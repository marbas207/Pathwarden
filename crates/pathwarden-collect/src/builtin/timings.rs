//! Where a built-in collection spends its time (Phase 0 of the collection
//! work: measure before cutting). Always measured, since it costs a few
//! clock reads per entry. A one-line summary goes to the log at the end
//! (`-v` in the CLI, the job log in the UI); with `PATHWARDEN_TIMINGS=1` (as
//! for analysis, see `pathwarden_core::timing`) a `[timing]` block follows
//! with every naming context, page round trips, ranged retrieval, the sizing
//! count, each phase and peak memory. Counts and durations only: no names,
//! DNs or values.

use std::time::Duration;

use pathwarden_core::diagnostics::{
    CollectionTimings, HostSummary, NamingContextTime, PhaseMemory, PhaseTime, TIMINGS_VERSION,
};

use crate::progress::{bytes, thousands};

/// Whether `PATHWARDEN_TIMINGS` asks for the detailed block.
pub(crate) fn detailed() -> bool {
    std::env::var_os("PATHWARDEN_TIMINGS").is_some_and(|v| v != "0" && !v.is_empty())
}

/// One naming context's read.
#[derive(Debug, Default, Clone)]
pub(crate) struct NcTiming {
    /// `DC=contoso,DC=local` → "domain", "configuration", "schema", or
    /// "other partition": the kind, not the name.
    pub kind: &'static str,
    pub entries: u64,
    /// Entries whose object type the parser keeps (users, groups, ...).
    pub kept: u64,
    pub deleted: u64,
    pub dns: u64,
    pub schema: u64,
    /// Everything else the parser discards.
    pub other: u64,
    /// Attribute bytes received (values, including the security descriptor).
    pub bytes: u64,
    pub wall: Duration,
    pub first_entry: Option<Duration>,
    /// Wait for each page after the first (999 entries a page).
    pub pages: Vec<Duration>,
}

/// A whole collection.
#[derive(Debug, Default, Clone)]
pub(crate) struct Timings {
    pub connect: Duration,
    pub ncs: Vec<NcTiming>,
    /// Naming contexts not read (DNS application partitions).
    pub skipped_ncs: usize,
    /// Entries with ranged attributes (groups over 1,500 members), the extra
    /// searches and the time they took.
    pub ranged_entries: u64,
    pub ranged_searches: u64,
    pub ranged: Duration,
    /// The sizing count's duration, and whether it finished before the read.
    pub sizing: Option<(Duration, bool)>,
    pub read: Duration,
    pub parse: Duration,
    pub resolve: Duration,
    pub modules: Option<Duration>,
    /// Reading SYSVOL, part of `modules` (all of it as the current user).
    pub sysvol: Option<Duration>,
    pub write: Duration,
    /// Peak working set (bytes) at the end of each phase.
    pub peak_memory: Vec<(&'static str, u64)>,
    /// The computers a full collection contacted.
    pub hosts: Option<HostSummary>,
    /// The read on disk: entries and bytes.
    pub cache: Option<(u64, u64)>,
    /// Streams the read used at the start and at the end.
    pub streams: Option<(usize, usize)>,
    /// No sizing count: the last read's size was used.
    pub sized_from_last: bool,
    /// Entries read by type, for the next read's expected size.
    pub read_counts: std::collections::BTreeMap<String, u64>,
}

/// p50, p95 and max of `d`.
fn percentiles(d: &[Duration]) -> Option<(Duration, Duration, Duration)> {
    if d.is_empty() {
        return None;
    }
    let mut v = d.to_vec();
    v.sort();
    let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    Some((at(0.5), at(0.95), *v.last().unwrap()))
}

pub(crate) fn secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 60.0 {
        crate::progress::clock(s as u64)
    } else if s >= 10.0 {
        format!("{s:.1}s")
    } else {
        format!("{s:.2}s")
    }
}

impl Timings {
    pub(crate) fn note_memory(&mut self, phase: &'static str) {
        if let Some(b) = peak_memory() {
            self.peak_memory.push((phase, b));
        }
    }

    /// The one-line summary.
    pub(crate) fn summary(&self) -> String {
        let entries: u64 = self.ncs.iter().map(|n| n.entries).sum();
        let pages: usize = self.ncs.iter().map(|n| n.pages.len() + 1).sum();
        let bytes_in: u64 = self.ncs.iter().map(|n| n.bytes).sum();
        let mut parts = vec![
            format!("connect {}", secs(self.connect)),
            format!(
                "read {} ({} entries, {} pages, {})",
                secs(self.read),
                thousands(entries),
                thousands(pages as u64),
                bytes(bytes_in)
            ),
            format!("parse {}", secs(self.parse)),
            format!("resolve {}", secs(self.resolve)),
        ];
        if let Some(m) = self.modules {
            // As the current user SYSVOL is the whole step: said once.
            match self.sysvol.filter(|&s| s != m) {
                Some(s) => parts.push(format!("modules {} (sysvol {})", secs(m), secs(s))),
                None => parts.push(format!("modules {}", secs(m))),
            }
        }
        parts.push(format!("write {}", secs(self.write)));
        let mut line = format!("Timing: {}", parts.join(", "));
        if let Some(peak) = self.peak_memory.iter().map(|(_, b)| *b).max() {
            line.push_str(&format!("; peak memory {}", bytes(peak)));
        }
        line
    }

    /// What `timings.json` keeps of it: the numbers, the summary line and
    /// the `[timing]` block. `total` is the whole collection.
    pub(crate) fn to_saved(&self, total: Duration) -> CollectionTimings {
        let ms = |d: Duration| d.as_millis() as u64;
        let mut phases = vec![
            ("connect", Some(self.connect)),
            ("read", Some(self.read)),
            ("parse", Some(self.parse)),
            ("resolve", Some(self.resolve)),
            ("modules", self.modules),
            ("sysvol", self.sysvol),
            ("write", Some(self.write)),
        ];
        phases.retain(|(_, d)| d.is_some());
        CollectionTimings {
            version: TIMINGS_VERSION,
            collector: "built-in".into(),
            total_ms: ms(total),
            phases: phases
                .into_iter()
                .map(|(name, d)| PhaseTime {
                    name: name.into(),
                    ms: d.map_or(0, ms),
                })
                .collect(),
            entries: self.ncs.iter().map(|n| n.entries).sum(),
            pages: self.ncs.iter().map(|n| n.pages.len() as u64 + 1).sum(),
            bytes: self.ncs.iter().map(|n| n.bytes).sum(),
            naming_contexts: self
                .ncs
                .iter()
                .map(|n| {
                    let p = percentiles(&n.pages);
                    NamingContextTime {
                        kind: n.kind.into(),
                        entries: n.entries,
                        kept: n.kept,
                        deleted: n.deleted,
                        dns: n.dns,
                        schema: n.schema,
                        other: n.other,
                        bytes: n.bytes,
                        ms: ms(n.wall),
                        first_entry_ms: n.first_entry.map(ms),
                        pages: n.pages.len() as u64,
                        page_p50_ms: p.map(|p| ms(p.0)),
                        page_p95_ms: p.map(|p| ms(p.1)),
                        page_max_ms: p.map(|p| ms(p.2)),
                    }
                })
                .collect(),
            skipped_partitions: self.skipped_ncs,
            ranged_entries: self.ranged_entries,
            ranged_searches: self.ranged_searches,
            ranged_ms: ms(self.ranged),
            sizing_ms: self
                .sizing
                .filter(|(_, before)| *before)
                .map(|(d, _)| ms(d)),
            peak_memory: self
                .peak_memory
                .iter()
                .map(|(phase, b)| PhaseMemory {
                    phase: (*phase).into(),
                    bytes: *b,
                })
                .collect(),
            hosts: self.hosts.clone(),
            cache_entries: self.cache.map(|c| c.0),
            cache_bytes: self.cache.map(|c| c.1),
            read_counts: self.read_counts.clone(),
            read_streams: self.streams.map(|(a, b)| (a as u32, b as u32)),
            // Set by `collect`, which knows what was asked for.
            scope: None,
            summary: Some(self.summary()),
            details: self.details(),
        }
    }

    /// The `[timing]` block for `PATHWARDEN_TIMINGS=1`.
    pub(crate) fn details(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (i, n) in self.ncs.iter().enumerate() {
            out.push(format!(
                "[timing] naming context {} ({}): {} entries in {} (kept {}, deleted {}, DNS {}, schema {}, other {}), {}, first entry after {}",
                i + 1,
                n.kind,
                thousands(n.entries),
                secs(n.wall),
                thousands(n.kept),
                thousands(n.deleted),
                thousands(n.dns),
                thousands(n.schema),
                thousands(n.other),
                bytes(n.bytes),
                n.first_entry.map_or("-".into(), secs),
            ));
            if let Some((p50, p95, max)) = percentiles(&n.pages) {
                out.push(format!(
                    "[timing]   {} more pages: wait p50 {}, p95 {}, max {}",
                    n.pages.len(),
                    secs(p50),
                    secs(p95),
                    secs(max)
                ));
            }
        }
        if self.skipped_ncs > 0 {
            out.push(format!(
                "[timing] {} not read",
                pathwarden_core::text::count(
                    self.skipped_ncs,
                    "DNS application partition",
                    "DNS application partitions"
                )
            ));
        }
        out.push(format!(
            "[timing] ranged retrieval: {} entries, {} extra searches, {}",
            thousands(self.ranged_entries),
            thousands(self.ranged_searches),
            secs(self.ranged)
        ));
        if let Some((first, last)) = self.streams {
            out.push(if first == last {
                format!(
                    "[timing] read with {}",
                    pathwarden_core::text::count(first, "stream", "streams")
                )
            } else {
                format!(
                    "[timing] read with {first} streams, {last} at the end (the domain \
                     controller slowed down)"
                )
            });
        }
        match self.sizing {
            _ if self.sized_from_last => {
                out.push("[timing] sizing count: not made (the last read's size)".into())
            }
            Some((d, before)) => out.push(format!(
                "[timing] sizing count: {} ({} the read)",
                secs(d),
                if before {
                    "finished before"
                } else {
                    "cut off by the end of"
                }
            )),
            None => out.push("[timing] sizing count: did not finish".into()),
        }
        let mut phases = vec![
            ("connect", self.connect),
            ("read", self.read),
            ("parse", self.parse),
            ("resolve", self.resolve),
        ];
        if let Some(m) = self.modules {
            phases.push(("modules", m));
        }
        if let Some(s) = self.sysvol {
            phases.push(("  sysvol", s));
        }
        phases.push(("write", self.write));
        for (name, d) in phases {
            out.push(format!("[timing] {name:<10} {:>10}", secs(d)));
        }
        for (phase, b) in &self.peak_memory {
            out.push(format!("[timing] peak memory after {phase}: {}", bytes(*b)));
        }
        out
    }
}

/// Peak working set of this process, when the OS says it cheaply.
pub(crate) fn peak_memory() -> Option<u64> {
    crate::memory::current().map(|m| m.peak_working_set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_and_details() {
        let ms = Duration::from_millis;
        let t = Timings {
            connect: ms(400),
            ncs: vec![NcTiming {
                kind: "domain",
                entries: 2500,
                kept: 2000,
                deleted: 0,
                dns: 100,
                schema: 0,
                other: 400,
                bytes: 5_000_000,
                wall: ms(12_000),
                first_entry: Some(ms(150)),
                pages: vec![ms(900), ms(1100), ms(4000)],
            }],
            skipped_ncs: 2,
            ranged_entries: 1,
            ranged_searches: 3,
            ranged: ms(80),
            sizing: Some((ms(1500), true)),
            read: ms(12_100),
            parse: ms(2_300),
            resolve: ms(700),
            modules: Some(ms(3_000)),
            sysvol: Some(ms(2_500)),
            write: ms(900),
            peak_memory: vec![("read", 300 << 20), ("parse", 500 << 20)],
            hosts: None,
            cache: None,
            streams: Some((4, 3)),
            sized_from_last: false,
            read_counts: Default::default(),
        };
        let s = t.summary();
        assert!(
            s.starts_with("Timing: connect 0.40s, read 12.1s (2,500 entries, 4 pages,"),
            "{s}"
        );
        assert!(
            s.contains("modules 3.00s (sysvol 2.50s), write 0.90s; peak memory"),
            "{s}"
        );
        let d = t.details().join("\n");
        assert!(d.contains("naming context 1 (domain): 2,500 entries in 12.0s (kept 2,000, deleted 0, DNS 100, schema 0, other 400)"), "{d}");
        assert!(
            d.contains("3 more pages: wait p50 1.10s, p95 4.00s, max 4.00s"),
            "{d}"
        );
        assert!(d.contains("2 DNS application partitions not read"));
        assert!(d.contains("sizing count: 1.50s (finished before the read)"));
        assert!(
            d.contains("read with 4 streams, 3 at the end (the domain controller slowed down)"),
            "{d}"
        );
        let saved = t.to_saved(ms(20_000));
        assert_eq!(saved.read_streams, Some((4, 3)));
        let from_last = Timings {
            sized_from_last: true,
            streams: Some((1, 1)),
            ..t.clone()
        };
        let d = from_last.details().join("\n");
        assert!(
            d.contains("sizing count: not made (the last read's size)"),
            "{d}"
        );
        assert!(d.contains("[timing] read with 1 stream\n"), "{d}");
        assert!(d.contains("[timing]   sysvol        2.50s"), "{d}");
        // SYSVOL as the whole step (the current user): said once.
        let whole = Timings {
            sysvol: t.modules,
            ..t.clone()
        };
        let s = whole.summary();
        assert!(s.contains("modules 3.00s, write"), "{s}");
        assert!(d.lines().all(|l| l.starts_with("[timing]")));

        // What timings.json keeps.
        let saved = t.to_saved(ms(20_000));
        assert_eq!(saved.total_ms, 20_000);
        assert_eq!(saved.phase("read"), Some(12_100));
        assert_eq!(saved.phase("sysvol"), Some(2_500));
        assert_eq!((saved.entries, saved.pages), (2500, 4));
        assert_eq!(saved.naming_contexts[0].page_p95_ms, Some(4000));
        assert_eq!(saved.sizing_ms, Some(1500));
        assert_eq!(saved.peak(), Some(500 << 20));
        assert_eq!(saved.summary.as_deref(), Some(t.summary().as_str()));
        assert_eq!(saved.details, t.details());
    }

    #[test]
    fn peak_memory_is_known_here() {
        // Windows and Linux both report it; elsewhere it is simply absent.
        if cfg!(any(windows, target_os = "linux")) {
            assert!(peak_memory().is_some_and(|b| b > 1 << 20));
        }
    }
}
