//! This process's memory, for the `[memory]` log lines: working set,
//! private bytes (commit) and their peaks. Numbers only.

use crate::progress::bytes;

/// This process's memory now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    /// Resident (Windows: working set; Linux: `VmRSS`).
    pub working_set: u64,
    /// Private bytes (Windows: commit charge, `PagefileUsage`; Linux:
    /// `RssAnon`).
    pub private: u64,
    pub peak_working_set: u64,
    /// Peak private bytes (Windows: `PeakPagefileUsage`; Linux: `VmHWM`,
    /// the peak resident set, as the closest it reports).
    pub peak_private: u64,
}

/// `[memory] <phase>: working set X, private Y, peak Z`, where the peak is
/// the peak private bytes. `None` where the OS doesn't say.
pub fn line(phase: &str) -> Option<String> {
    current().map(|m| m.line(phase))
}

impl Memory {
    /// The `[memory]` line for `phase`.
    pub fn line(&self, phase: &str) -> String {
        format!(
            "[memory] {phase}: working set {}, private {}, peak {}",
            bytes(self.working_set),
            bytes(self.private),
            bytes(self.peak_private)
        )
    }
}

/// This process's memory, when the OS says it cheaply.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn current() -> Option<Memory> {
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut Counters, cb: u32) -> i32;
    }
    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        ..Default::default()
    };
    // SAFETY: `c` is a PROCESS_MEMORY_COUNTERS-shaped buffer of the size
    // passed; the pseudo-handle from GetCurrentProcess needs no closing.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    (ok != 0).then_some(Memory {
        working_set: c.working_set_size as u64,
        private: c.pagefile_usage as u64,
        peak_working_set: c.peak_working_set_size as u64,
        peak_private: c.peak_pagefile_usage as u64,
    })
}

/// From `/proc/self/status`.
#[cfg(not(windows))]
pub fn current() -> Option<Memory> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = |key: &str| -> Option<u64> {
        let v: u64 = s
            .lines()
            .find_map(|l| l.strip_prefix(key))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        Some(v * 1024)
    };
    let peak = kb("VmHWM:")?;
    Some(Memory {
        working_set: kb("VmRSS:")?,
        private: kb("RssAnon:").unwrap_or(0),
        peak_working_set: peak,
        peak_private: peak,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_has_three_figures() {
        let m = Memory {
            working_set: 3 << 30,
            private: 2 << 30,
            peak_working_set: 4 << 30,
            peak_private: 5 << 30,
        };
        assert_eq!(
            m.line("read"),
            "[memory] read: working set 3.0 GB, private 2.0 GB, peak 5.0 GB"
        );
    }

    #[test]
    #[cfg(any(windows, target_os = "linux"))]
    fn memory_is_known_here() {
        let m = current().expect("known");
        assert!(m.working_set > 1 << 20 && m.peak_private >= m.private.min(m.peak_private));
        assert!(line("x").is_some_and(|l| l.starts_with("[memory] x: working set ")));
    }
}
