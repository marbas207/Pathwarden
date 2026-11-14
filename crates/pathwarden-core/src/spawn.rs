//! The one place Pathwarden makes a [`Command`]: every program it starts
//! (git, schtasks, powershell, icacls, SharpHound, RustHound-CE,
//! output plugins, xdg-open, ...) comes from [`quiet`], or, for the browser
//! it opens on purpose, from [`detached`].
//!
//! Why: started from Explorer (a double-click), Pathwarden lets go of its
//! console once the UI is up (`FreeConsole`, see docs/ui.md, "The
//! console"). A console program started by a process with no console gets
//! a new console window of its own, so each git pull, push or probe, each
//! `schtasks /Query`, each plugin run would flash a window on the desktop.
//! `CREATE_NO_WINDOW` gives the child a console with no window instead (the
//! programs it starts in turn, such as git's own git, ssh or a credential
//! helper, share that hidden console). It changes nothing for a program
//! started from a terminal: its output is piped or dropped either way, and
//! a GUI program (Git Credential Manager's sign-in) still shows its window.
//!
//! `tests/no_bare_spawns.rs` fails on a `Command::new(` anywhere else in
//! the workspace's sources, so a new spawn can't miss this.

use std::ffi::OsStr;
use std::process::Command;

/// `CreateProcess` flag: a console program gets a console with no window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A command for `program` that never opens a window of its own: for
/// everything Pathwarden runs and reads the output of, or waits for.
pub fn quiet(program: impl AsRef<OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// A command for a GUI program meant to be seen (the browser's app
/// window): not attached to this console, if there is one, so Ctrl+C here
/// doesn't reach it, and in its own process group. Its window shows as
/// usual (`DETACHED_PROCESS` gives a console program no console at all;
/// a browser has none to begin with).
pub fn detached(program: impl AsRef<OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd
}

/// A long-running child (an external collector) tied to Pathwarden's life.
///
/// Started [`quiet`], a console program has a hidden console of its own,
/// so Ctrl+C in Pathwarden's terminal no longer reaches it. On Windows it
/// is put in a kill-on-close Job Object (the one git and plugins run in):
/// when Pathwarden exits, Ctrl+C included, or this value is dropped, the
/// child and everything it started are stopped. Elsewhere `quiet` changes
/// nothing, the child stays in Pathwarden's process group, and the
/// terminal's Ctrl+C reaches it as before.
pub struct Contained {
    #[cfg(windows)]
    tree: crate::proc_tree::Tree,
}

impl Contained {
    /// Stops the child and every process it started (Windows); elsewhere
    /// the caller's own `Child::kill` does that part.
    pub fn kill(&self) {
        #[cfg(windows)]
        self.tree.kill();
    }
}

/// Ties `child` (just spawned) to Pathwarden's life: see [`Contained`].
pub fn contain(child: &std::process::Child) -> Contained {
    #[cfg(not(windows))]
    let _ = child;
    Contained {
        #[cfg(windows)]
        tree: crate::proc_tree::Tree::attach(child),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long-running quiet child (cmd running ping for ~30 s) dies when
    /// its `Contained` is dropped, as it does when Pathwarden exits.
    #[cfg(windows)]
    #[test]
    fn a_contained_child_dies_with_its_holder() {
        let mut child = quiet("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 >nul"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("cmd runs");
        let held = contain(&child);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(child.try_wait().unwrap().is_none(), "still running");
        drop(held);
        let started = std::time::Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the child outlived its job"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// `kill` stops it too, while the holder lives.
    #[cfg(windows)]
    #[test]
    fn a_contained_child_is_killed() {
        let mut child = quiet("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 >nul"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("cmd runs");
        let held = contain(&child);
        held.kill();
        let started = std::time::Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the child was not killed"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// A quiet command still runs a program and reads what it prints.
    #[test]
    fn a_quiet_command_runs_and_is_read() {
        let mut cmd = if cfg!(windows) {
            let mut c = quiet("cmd");
            c.args(["/C", "echo hi"]);
            c
        } else {
            let mut c = quiet("sh");
            c.args(["-c", "echo hi"]);
            c
        };
        let out = cmd.output().expect("the shell runs");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
    }
}
