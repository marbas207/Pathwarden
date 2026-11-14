//! Where Pathwarden was started: whether there is a desktop to show a
//! window on, and whether the console is Pathwarden's own (opened for it by
//! Explorer) or a terminal the user is working in.

use windows_sys::Win32::System::Console::{
    FreeConsole, GetConsoleProcessList, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::SystemInformation::{
    VerSetConditionMask, VerifyVersionInfoW, OSVERSIONINFOEXW, VER_PRODUCT_TYPE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::WSF_VISIBLE;

/// `VER_EQUAL` and `VER_NT_WORKSTATION` (winnt.h).
const VER_EQUAL: u8 = 1;
const VER_NT_WORKSTATION: u8 = 1;

/// Whether `pathwarden ui` should open the window rather than the browser:
/// a Windows client edition (not Server), on a desktop the user can see,
/// not over SSH. Servers and remote shells keep the browser (with its
/// printed link); `--window` still opens the window there.
pub fn window_by_default() -> bool {
    is_workstation() && desktop_visible() && !over_ssh()
}

/// Windows 10 or 11 rather than Windows Server.
fn is_workstation() -> bool {
    // SAFETY: a zeroed OSVERSIONINFOEXW with its size set, as the call
    // expects; nothing is kept past it.
    unsafe {
        let mut info: OSVERSIONINFOEXW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        info.wProductType = VER_NT_WORKSTATION;
        let mask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
        VerifyVersionInfoW(&mut info, VER_PRODUCT_TYPE, mask) != 0
    }
}

/// Whether this process's window station is the visible, interactive one
/// (not a service's, or a scheduled task's that runs whether or not the
/// user is signed in).
fn desktop_visible() -> bool {
    // SAFETY: the station handle is the process's own (not to be closed);
    // the flags are read into a local of the size given.
    unsafe {
        let station = GetProcessWindowStation();
        if station.is_null() {
            return false;
        }
        let mut flags: USEROBJECTFLAGS = std::mem::zeroed();
        let mut needed = 0u32;
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&mut flags as *mut USEROBJECTFLAGS).cast(),
            std::mem::size_of::<USEROBJECTFLAGS>() as u32,
            &mut needed,
        ) != 0
            && flags.dwFlags & WSF_VISIBLE as u32 != 0
    }
}

/// Started from an SSH session (OpenSSH for Windows sets these).
fn over_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_CLIENT").is_some()
}

/// Whether the console is Pathwarden's alone: Windows opened it for this
/// process (a double-click in Explorer, a shortcut, Run), rather than
/// Pathwarden being started from a terminal that stays open.
pub fn own_console() -> bool {
    let mut ids = [0u32; 4];
    // SAFETY: the buffer and its length match.
    let n = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
    n == 1
}

/// Lets go of the console, which closes it when it is Pathwarden's own.
/// Standard handles are cleared, so later output goes nowhere (Rust's
/// standard streams treat a missing handle as a sink) instead of failing.
pub fn release_console() {
    // SAFETY: plain calls with no pointers; null handles are valid values.
    unsafe {
        FreeConsole();
        for h in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            SetStdHandle(h, std::ptr::null_mut());
        }
    }
}
