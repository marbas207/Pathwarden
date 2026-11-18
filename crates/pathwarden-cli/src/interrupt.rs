//! Ctrl-C while a finding action runs. The action's program runs in a
//! process tree of its own (a process group on Unix, a Job Object on
//! Windows), so the signal doesn't reach it: without this, the command
//! would die and leave the program running. Here Ctrl-C (and SIGTERM on
//! Unix) cancels the run, which stops the whole tree, and the command
//! says "Cancelled.".
//!
//! Its `unsafe`: installing the handler (`signal` on Unix,
//! `SetConsoleCtrlHandler` on Windows). The handler only sets a flag.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use std::time::Duration;

use pathwarden_core::actions::CancelHandle;

/// Set by the handler.
static HIT: AtomicBool = AtomicBool::new(false);
static INSTALL: Once = Once::new();

/// How long the command may take to stop by itself after Ctrl-C (the run
/// returns within 50 ms of the cancel); past it, as when Ctrl-C comes
/// while it waits at a question, it exits.
const GRACE: Duration = Duration::from_secs(3);

/// The exit status after Ctrl-C, as shells give it (128 + SIGINT).
pub const EXIT_CANCELLED: i32 = 130;

/// Whether Ctrl-C was pressed.
pub fn hit() -> bool {
    HIT.load(Ordering::SeqCst)
}

/// A cancel handle that Ctrl-C (and SIGTERM) triggers from now on.
pub fn cancel_on_interrupt() -> CancelHandle {
    let cancel = CancelHandle::new();
    INSTALL.call_once(install);
    let c = cancel.clone();
    std::thread::spawn(move || {
        while !hit() {
            std::thread::sleep(Duration::from_millis(50));
        }
        c.cancel();
        std::thread::sleep(GRACE);
        eprintln!("Cancelled.");
        std::process::exit(EXIT_CANCELLED);
    });
    cancel
}

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    HIT.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn install() {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe, and lives for the whole process.
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

#[cfg(windows)]
unsafe extern "system" fn on_ctrl(kind: u32) -> windows_sys::core::BOOL {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT {
        HIT.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn install() {
    // SAFETY: the handler only stores to an atomic and lives for the whole
    // process; adding a handler has no other effect.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

#[cfg(not(any(unix, windows)))]
fn install() {}
