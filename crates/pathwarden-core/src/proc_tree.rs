//! A plugin and every process it starts, so that a timeout (or the plugin
//! exiting) stops them all, not just the direct child: a Job Object on
//! Windows, a process group on Unix.
//!
//! Also what a process that left a lock is now ([`holder`]).
//!
//! Its `unsafe`: three Job Object calls, the process queries of [`holder`] and the process snapshot, queries and
//! `TerminateProcess` of [`end_descendants`] on Windows, and one `kill` on
//! Unix, each on a handle, buffer or id this module owns.

use std::process::{Child, Command};

#[cfg(windows)]
pub(crate) use windows::end_descendants;

/// The processes of `root` (created at `root_created`) and its children
/// (`procs`: process ID, parent ID), children first in no set order.
/// `open` opens a process and says when it was created; a process created
/// before its parent is not its child, only an orphan of an earlier
/// process that had the same ID, and is left alone with what it started.
/// A process created after `listed` (when `procs` was listed) got the ID
/// of one that stopped since, and is not on the list either.
/// What each `open` returned for a process kept is in the result, with its
/// ID and creation time, for the caller to stop by (a handle, so a process
/// ID reused meanwhile can't be hit).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn descendants<H>(
    root: u32,
    root_created: u64,
    listed: u64,
    procs: &[(u32, u32)],
    mut open: impl FnMut(u32) -> Option<(H, u64)>,
) -> Vec<(u32, u64, H)> {
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::from([root]);
    let mut queue = std::collections::VecDeque::from([(root, root_created)]);
    while let Some((parent, parent_created)) = queue.pop_front() {
        for &(pid, ppid) in procs {
            if ppid != parent || !seen.insert(pid) {
                continue;
            }
            if let Some((h, created)) = open(pid) {
                if created >= parent_created && created <= listed {
                    queue.push_back((pid, created));
                    found.push((pid, created, h));
                }
            }
        }
    }
    found
}

/// A Windows creation time (100 ns ticks since 1601) as a system time.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn from_ticks(ticks: u64) -> std::time::SystemTime {
    let unix = ticks.saturating_sub(116_444_736_000_000_000);
    std::time::UNIX_EPOCH + std::time::Duration::from_nanos(unix.saturating_mul(100))
}

/// Makes the program `cmd` starts the leader of its own process tree.
pub(crate) fn prepare(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = cmd;
}

/// The processes of one plugin run. Dropping it (Windows) or calling
/// [`Tree::kill`] stops any still running.
pub(crate) struct Tree {
    #[cfg(windows)]
    job: Option<windows::Job>,
    #[cfg(unix)]
    pgid: i32,
}

impl Tree {
    /// Tracks `child` and everything it starts from now on. On Windows a
    /// process the child starts in the moment before it joins the job is
    /// not tracked; on failure only the child itself is.
    pub(crate) fn attach(child: &Child) -> Tree {
        #[cfg(windows)]
        {
            Tree {
                job: windows::Job::for_child(child),
            }
        }
        #[cfg(unix)]
        {
            Tree {
                pgid: i32::try_from(child.id()).unwrap_or(0),
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = child;
            Tree {}
        }
    }

    /// Stops every process of the tree that is still running.
    pub(crate) fn kill(&self) {
        #[cfg(windows)]
        if let Some(job) = &self.job {
            job.terminate();
        }
        #[cfg(unix)]
        if self.pgid > 0 {
            // SAFETY: kill(2) takes no pointers; a negative id names the
            // process group the plugin leads (`process_group(0)`).
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// When the process `h` was created, in 100 ns ticks since 1601.
    pub(super) fn created(h: HANDLE) -> Option<u64> {
        use windows_sys::Win32::Foundation::FILETIME;
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: `h` is an open process handle the caller owns; four
        // FILETIMEs this frame owns.
        let ok = unsafe {
            windows_sys::Win32::System::Threading::GetProcessTimes(
                h,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } != 0;
        ok.then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    /// Every running process: its ID and its parent's.
    pub(super) fn process_list() -> Vec<(u32, u32)> {
        snapshot(|e| (e.th32ProcessID, e.th32ParentProcessID))
    }

    /// Every running process: its ID, its parent's and its file name (for
    /// a test to wait on a named one).
    #[cfg(test)]
    pub(super) fn process_names() -> Vec<(u32, u32, String)> {
        snapshot(|e| {
            let name = &e.szExeFile;
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            (
                e.th32ProcessID,
                e.th32ParentProcessID,
                String::from_utf16_lossy(&name[..len]),
            )
        })
    }

    /// `f` of each entry in a snapshot of the running processes.
    fn snapshot<T>(
        f: impl Fn(&windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W) -> T,
    ) -> Vec<T> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: no pointers; the handle is closed below, once.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return Vec::new();
        }
        let mut out = Vec::new();
        // SAFETY: zeroed is a valid PROCESSENTRY32W (plain integers and an
        // array); its size is set as the calls require.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: `snap` is open; `entry` is this frame's, its size set.
        let mut more = unsafe { Process32FirstW(snap, &mut entry) } != 0;
        while more {
            out.push(f(&entry));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut entry) } != 0;
        }
        // SAFETY: opened above, closed once.
        unsafe {
            CloseHandle(snap);
        }
        out
    }

    /// Ends every process `child` started, and those they started, while
    /// `child` still runs to be found by: what a Job Object can miss (one
    /// started in the moment before the child joined it). Only processes
    /// created after their parent are ended (see
    /// [`super::descendants`]); an orphan an earlier process with the same
    /// ID left is not, nor one that got a listed process's ID after the
    /// list was made.
    ///
    /// Returns each process ended: its ID and when it was created (for
    /// [`super::holder`] to tell later whether it still runs).
    pub(crate) fn end_descendants(child: &Child) -> Vec<(u32, std::time::SystemTime)> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        };
        let Some(root_created) = created(child.as_raw_handle() as HANDLE) else {
            return Vec::new();
        };
        let listed = now_ticks();
        let procs = process_list();
        let found = super::descendants(child.id(), root_created, listed, &procs, |pid| {
            // SAFETY: no pointers; the handle is owned (and closed) by the
            // OwnedHandle made at once.
            let h = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                    0,
                    pid,
                )
            };
            if h.is_null() {
                return None;
            }
            // SAFETY: `h` is a fresh handle nothing else owns.
            let owned = unsafe { OwnedHandle::from_raw_handle(h as _) };
            created(h).map(|t| (owned, t))
        });
        for (_, _, h) in &found {
            // SAFETY: the handle is open (owned by `found`) and was opened
            // with PROCESS_TERMINATE.
            unsafe {
                TerminateProcess(h.as_raw_handle() as HANDLE, 1);
            }
        }
        found
            .into_iter()
            .map(|(pid, t, _)| (pid, super::from_ticks(t)))
            .collect()
    }

    /// Now, in 100 ns ticks since 1601 (as [`created`] says it).
    pub(super) fn now_ticks() -> u64 {
        use windows_sys::Win32::Foundation::FILETIME;
        let mut t = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // Precise: the coarse clock can lag a process's creation time by a
        // tick (~16 ms), which would leave a just-started child out.
        // SAFETY: a FILETIME this frame owns.
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime(&mut t);
        }
        (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
    }

    /// An unnamed job whose processes die when its last handle closes.
    pub(super) struct Job(HANDLE);

    // SAFETY: a job handle may be used and closed from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub(super) fn for_child(child: &Child) -> Option<Job> {
            // SAFETY: null attributes and name are allowed; the handle is
            // owned by the returned `Job` and closed on drop.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return None;
            }
            let job = Job(handle);
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` is the structure this class expects, with its
            // exact size; the child's handle is valid while `child` lives.
            let ok = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) != 0
                    && AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) != 0
            };
            ok.then_some(job)
        }

        pub(super) fn terminate(&self) {
            // SAFETY: the handle is open until drop.
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: closed once, here. KILL_ON_JOB_CLOSE stops what is left.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// What process `pid` on this computer is now, for a lock it left
/// ([`crate::store`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Holder {
    /// No such process (it stopped).
    Gone,
    /// A running process: its program's file name (`pathwarden.exe`), and
    /// when it started, when that can be told.
    Running {
        program: String,
        started: Option<std::time::SystemTime>,
    },
    /// Can't be told (another account's process this one may not query,
    /// or a system with no way to look): taken for a running Pathwarden.
    Unknown,
}

/// [`Holder`] of process `pid`.
pub(crate) fn holder(pid: u32) -> Holder {
    #[cfg(windows)]
    {
        process::holder(pid)
    }
    #[cfg(not(windows))]
    {
        // Linux: /proc says. Elsewhere, unknown.
        let proc_dir = std::path::Path::new("/proc");
        if !proc_dir.join("self").exists() {
            return Holder::Unknown;
        }
        let dir = proc_dir.join(pid.to_string());
        if !dir.exists() {
            return Holder::Gone;
        }
        let program = std::fs::read_link(dir.join("exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .or_else(|| {
                std::fs::read_to_string(dir.join("comm"))
                    .ok()
                    .map(|s| s.trim().to_string())
            });
        match program {
            Some(program) => Holder::Running {
                program,
                started: None,
            },
            None => Holder::Unknown,
        }
    }
}

#[cfg(windows)]
mod process {
    use super::Holder;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub(super) fn holder(pid: u32) -> Holder {
        // SAFETY: OpenProcess takes no pointers; the handle it returns is
        // closed below, once.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            // SAFETY: no arguments.
            let e = unsafe { GetLastError() };
            return if e == ERROR_INVALID_PARAMETER {
                Holder::Gone
            } else {
                Holder::Unknown
            };
        }
        let mut code = 0u32;
        // SAFETY: `h` is open; `code` is a u32 this frame owns.
        let ok = unsafe { GetExitCodeProcess(h, &mut code) } != 0;
        let out = if ok && code != STILL_ACTIVE as u32 {
            Holder::Gone
        } else {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            // SAFETY: `buf` holds `len` u16s; `len` is set to the
            // characters written.
            let named = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
            let started = super::windows::created(h).map(super::from_ticks);
            if named != 0 {
                let path = String::from_utf16_lossy(&buf[..len as usize]);
                let program = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or(path);
                Holder::Running { program, started }
            } else {
                Holder::Unknown
            }
        };
        // SAFETY: `h` was opened above and is closed once.
        unsafe {
            CloseHandle(h);
        }
        out
    }
}

#[cfg(test)]
mod holder_tests {
    use super::*;

    #[test]
    fn this_process_is_running_and_a_stopped_one_is_gone() {
        match holder(std::process::id()) {
            Holder::Running { program, started } => {
                let me = std::env::current_exe().unwrap();
                assert_eq!(
                    program.to_ascii_lowercase(),
                    me.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_ascii_lowercase()
                );
                if cfg!(windows) {
                    let started = started.expect("Windows says when it started");
                    assert!(started <= std::time::SystemTime::now());
                    assert!(
                        started
                            > std::time::SystemTime::now()
                                - std::time::Duration::from_secs(24 * 3600)
                    );
                }
            }
            Holder::Unknown if cfg!(windows) => panic!("Windows can tell"),
            Holder::Unknown => {}
            Holder::Gone => panic!("this process is running"),
        }
        let mut cmd = crate::spawn::quiet(if cfg!(windows) { "cmd" } else { "true" });
        if cfg!(windows) {
            cmd.args(["/c", "exit"]);
        }
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        drop(child);
        // A stopped process whose handle is closed: gone (or, rarely, its
        // pid already reused by another program).
        match holder(pid) {
            Holder::Gone | Holder::Unknown => {}
            Holder::Running { program, .. } => {
                assert!(!program.eq_ignore_ascii_case("cmd.exe"), "{program}")
            }
        }
    }
}

#[cfg(test)]
mod descendant_tests {
    use super::*;

    /// A process created before its parent is an orphan of an earlier
    /// process with the parent's ID: it, and what it started, are left.
    #[test]
    fn an_orphan_older_than_its_parent_is_left_alone() {
        // Process ID and when it was created.
        let created = std::collections::HashMap::from([
            (11, 110), // the launcher's child
            (12, 120), // its child
            (20, 50),  // an orphan whose parent's ID (10) was reused later
            (21, 60),  // the orphan's own child
            (30, 130), // unrelated
        ]);
        let procs = [(11, 10), (12, 11), (20, 10), (21, 20), (30, 99)];
        let mut found: Vec<u32> = descendants(10, 100, 1000, &procs, |pid| {
            created.get(&pid).map(|&t| (pid, t))
        })
        .into_iter()
        .map(|(pid, _, h)| {
            assert_eq!(pid, h);
            pid
        })
        .collect();
        found.sort_unstable();
        assert_eq!(found, vec![11, 12]);
    }

    /// One that can't be opened (gone, or not ours to query) is skipped,
    /// and a loop in the parent IDs ends.
    #[test]
    fn an_unopened_process_is_skipped_and_loops_end() {
        let procs = [(11, 10), (12, 11), (10, 12)];
        let found = descendants(10, 100, 1000, &procs, |pid| {
            (pid != 12).then_some((pid, 200))
        });
        assert_eq!(found, vec![(11, 200, 11)]);
    }

    /// A process created after the list was made took the ID of a listed
    /// one that stopped since: it is not ended, nor what it started.
    #[test]
    fn an_id_reused_after_the_list_is_left_alone() {
        let created = std::collections::HashMap::from([(11, 500), (12, 900), (13, 950)]);
        let procs = [(11, 10), (12, 10), (13, 12)];
        let found: Vec<u32> = descendants(10, 100, 800, &procs, |pid| {
            created.get(&pid).map(|&t| (pid, t))
        })
        .into_iter()
        .map(|(pid, ..)| pid)
        .collect();
        assert_eq!(found, vec![11]);
    }

    #[test]
    fn windows_ticks_become_unix_time() {
        assert_eq!(from_ticks(116_444_736_000_000_000), std::time::UNIX_EPOCH);
        assert_eq!(
            from_ticks(116_444_736_000_000_000 + 10_000_000),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)
        );
    }

    /// The child's own children are ended, and it is not: cmd waiting on a
    /// 30-second ping goes on to its own exit as soon as the ping ends.
    #[cfg(windows)]
    #[test]
    fn a_childs_children_are_ended() {
        let mut child = crate::spawn::quiet("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 >nul & exit 7"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("cmd runs");
        let pid = child.id();
        let started = std::time::Instant::now();
        // cmd's first child can be the conhost it starts before the ping:
        // wait for the ping itself, so it is in the list that is ended.
        let ping = loop {
            let ping = windows::process_names()
                .into_iter()
                .find(|(_, p, name)| *p == pid && name.eq_ignore_ascii_case("PING.EXE"));
            if let Some((ping, ..)) = ping {
                break ping;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "cmd never started its ping"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let ended_procs = end_descendants(&child);
        assert!(
            ended_procs.iter().any(|&(p, _)| p == ping),
            "the ping is named"
        );
        for (_, created) in &ended_procs {
            assert!(*created <= std::time::SystemTime::now());
        }
        let ended = std::time::Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(
                ended.elapsed() < std::time::Duration::from_secs(10),
                "the ping was not ended"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert_eq!(status.code(), Some(7), "cmd itself ran on to its exit");
    }
}
