//! Collection diagnostics: where a collection's time went, kept
//! with the run, compared with the environment's previous run, and a bundle
//! that is safe to share.
//!
//! - [`CollectionTimings`] is `timings.json` in a run's folder: the
//!   collector's steps, naming contexts, page waits, peak memory and the
//!   computers it contacted (reached, failed, timed out, errors by kind).
//!   Counts and durations only: no names, DNs or values.
//! - [`measures`] compares one run's timings with an earlier run's, one
//!   number per line with its change. `pathwarden diagnose` prints them and
//!   the run page's "Collection performance" panel shows the same.
//! - [`Bundle`] builds the zip `pathwarden diagnose --bundle` writes (and
//!   the run page downloads): version, system, timings, completeness, error
//!   counts, collection settings without credentials, posture and the plan's
//!   size. Every string that is not Pathwarden's own words is replaced by a
//!   placeholder ([`Placeholders`]), then every file is searched for the
//!   run's domain and object names ([`NameScan`]); one found and no zip is
//!   made ([`Refused`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::model::{EdgeKind, NodeKind};

/// The timings file in a run's folder.
pub const TIMINGS_FILE: &str = "timings.json";

/// The timings `pathwarden collect` (without `--save`) leaves in its output
/// folder, for the `pathwarden run -i` that reads it (a schedule's), with
/// the files they describe. Not a `.json` name, so the input readers pass
/// over it.
pub const SIDECAR_FILE: &str = ".pathwarden-timings";

/// [`SIDECAR_FILE`] once a run has recorded it: a later analysis of the
/// same folder is not that collection.
pub const RECORDED_SIDECAR_FILE: &str = ".pathwarden-timings.recorded";

/// [`CollectionTimings::version`] as written now.
pub const TIMINGS_VERSION: u32 = 1;

/// A step's change smaller than this share of the earlier time, or than
/// [`SAME_MS`], is "about the same": collections vary run to run.
pub const SAME_SHARE: f64 = 0.05;
pub const SAME_MS: u64 = 1000;

/// One step of a collection and how long it took.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTime {
    /// `connect`, `read`, `parse`, `resolve`, `modules`, `sysvol` (part of
    /// `modules`), `write`; `collector` for SharpHound's whole run.
    pub name: String,
    pub ms: u64,
}

/// One naming context's read, by kind (not its name).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NamingContextTime {
    /// "domain", "configuration", "schema", "other partition".
    pub kind: String,
    pub entries: u64,
    /// Entries the parser keeps, and those it discards by why.
    pub kept: u64,
    pub deleted: u64,
    pub dns: u64,
    pub schema: u64,
    pub other: u64,
    /// Attribute bytes received.
    pub bytes: u64,
    pub ms: u64,
    pub first_entry_ms: Option<u64>,
    /// Pages after the first, and the wait for them.
    pub pages: u64,
    pub page_p50_ms: Option<u64>,
    pub page_p95_ms: Option<u64>,
    pub page_max_ms: Option<u64>,
}

/// Peak memory at the end of a step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseMemory {
    pub phase: String,
    pub bytes: u64,
}

/// The computers a full collection contacted (sessions, local groups).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSummary {
    /// Computers in the directory.
    pub computers: usize,
    /// Computers the modules tried (the rest are disabled or stale).
    pub tried: usize,
    /// Of `tried`: at least one session list read.
    pub reached: usize,
    /// Of `tried`: nothing read, for another reason than the per-host
    /// timeout.
    pub failed: usize,
    /// Of `tried`: nothing read, the per-host timeout ran out.
    pub timed_out: usize,
    /// Computers whose local groups (SAMR) couldn't be read.
    pub local_groups_failed: usize,
    /// The errors the modules logged, by kind ("access denied",
    /// "unreachable", ...): counts, never the computers.
    pub errors: BTreeMap<String, usize>,
    /// The sessions pass (with the Remote Registry retry) and the local
    /// groups pass.
    pub sessions_ms: Option<u64>,
    pub local_groups_ms: Option<u64>,
    /// Per-computer time, when the collector measures it (RustHound-CE
    /// 2.5.27's modules don't say how long each computer took).
    pub p95_ms: Option<u64>,
    pub slowest_ms: Option<u64>,
}

/// `timings.json`: a collection's timings, as the collector measured them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionTimings {
    pub version: u32,
    /// "built-in" or "SharpHound".
    pub collector: String,
    /// The whole collection, wall clock.
    pub total_ms: u64,
    /// Each step, in order.
    pub phases: Vec<PhaseTime>,
    /// Directory entries read, LDAP pages and bytes received.
    pub entries: u64,
    pub pages: u64,
    pub bytes: u64,
    pub naming_contexts: Vec<NamingContextTime>,
    /// DNS application partitions not read.
    pub skipped_partitions: usize,
    /// Groups over 1,500 members: entries, extra searches, time.
    pub ranged_entries: u64,
    pub ranged_searches: u64,
    pub ranged_ms: u64,
    /// The sizing count, when it finished before the read.
    pub sizing_ms: Option<u64>,
    pub peak_memory: Vec<PhaseMemory>,
    pub hosts: Option<HostSummary>,
    /// The built-in collector's read on disk: entries and bytes, as the next
    /// collection's free-space estimate. Absent when it read into
    /// memory, and in timings saved before 0.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_entries: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_bytes: Option<u64>,
    /// The built-in collector's entries read, by type (`users`, ...): with
    /// `entries`, the next read's expected size, so it isn't counted again.
    /// Absent before 0.3.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub read_counts: BTreeMap<String, u64>,
    /// Connections the read used at the start, and at the end (fewer when
    /// the domain controller slowed down). Absent before 0.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_streams: Option<(u32, u32)>,
    /// "all" or "dc-only". Absent in timings saved before it was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The log's `Timing:` line and `[timing]` block, as written.
    pub summary: Option<String>,
    pub details: Vec<String>,
}

impl CollectionTimings {
    /// The time of step `name`, if it ran.
    pub fn phase(&self, name: &str) -> Option<u64> {
        self.phases.iter().find(|p| p.name == name).map(|p| p.ms)
    }

    pub fn peak(&self) -> Option<u64> {
        self.peak_memory.iter().map(|p| p.bytes).max()
    }

    /// Reads `timings.json` text; `None` when it isn't one, or when a
    /// newer Pathwarden wrote it ([`TIMINGS_VERSION`], docs/dev/formats.md):
    /// its numbers may not mean what this version reads them as.
    pub fn parse(text: &str) -> Option<Self> {
        serde_json::from_str::<Self>(text.trim_start_matches('\u{feff}'))
            .ok()
            .filter(|t| crate::formats::of_u32(t.version, TIMINGS_VERSION).is_known())
    }

    /// The scope, or for timings saved before it was recorded what the
    /// computers say: contacted means "all".
    pub fn scope(&self) -> Option<&str> {
        self.scope
            .as_deref()
            .or_else(|| self.hosts.as_ref().map(|_| "all"))
    }

    /// "built-in, all": how it was collected, to say why two runs aren't
    /// compared.
    pub fn kind_words(&self) -> String {
        match self.scope() {
            Some(s) => format!("{}, {s}", self.collector),
            None => self.collector.clone(),
        }
    }

    /// Whether `other` was collected the same way (collector and scope), so
    /// their times can be compared.
    pub fn same_collection(&self, other: &Self) -> bool {
        self.collector.eq_ignore_ascii_case(&other.collector)
            && match (self.scope(), other.scope()) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    /// Collections made one after another (a schedule's domains) as one:
    /// times and counts added, steps by name, peak memory the highest of
    /// each step. `None` for none.
    pub fn combine(mut parts: Vec<Self>) -> Option<Self> {
        if parts.len() <= 1 {
            return parts.pop();
        }
        let mut all = Self {
            version: TIMINGS_VERSION,
            collector: parts[0].collector.clone(),
            scope: parts[0].scope.clone(),
            ..Self::default()
        };
        let add = |x: Option<u64>, y: Option<u64>| match (x, y) {
            (Some(x), Some(y)) => Some(x + y),
            (x, y) => x.or(y),
        };
        for t in parts {
            all.total_ms += t.total_ms;
            for p in t.phases {
                match all.phases.iter_mut().find(|x| x.name == p.name) {
                    Some(x) => x.ms += p.ms,
                    None => all.phases.push(p),
                }
            }
            all.entries += t.entries;
            all.pages += t.pages;
            all.bytes += t.bytes;
            all.naming_contexts.extend(t.naming_contexts);
            all.skipped_partitions += t.skipped_partitions;
            all.ranged_entries += t.ranged_entries;
            all.ranged_searches += t.ranged_searches;
            all.ranged_ms += t.ranged_ms;
            all.sizing_ms = add(all.sizing_ms, t.sizing_ms);
            for m in t.peak_memory {
                match all.peak_memory.iter_mut().find(|x| x.phase == m.phase) {
                    Some(x) => x.bytes = x.bytes.max(m.bytes),
                    None => all.peak_memory.push(m),
                }
            }
            if let Some(h) = t.hosts {
                let a = all.hosts.get_or_insert_with(HostSummary::default);
                a.computers += h.computers;
                a.tried += h.tried;
                a.reached += h.reached;
                a.failed += h.failed;
                a.timed_out += h.timed_out;
                a.local_groups_failed += h.local_groups_failed;
                for (k, n) in h.errors {
                    *a.errors.entry(k).or_default() += n;
                }
                a.sessions_ms = add(a.sessions_ms, h.sessions_ms);
                a.local_groups_ms = add(a.local_groups_ms, h.local_groups_ms);
                a.p95_ms = a.p95_ms.max(h.p95_ms);
                a.slowest_ms = a.slowest_ms.max(h.slowest_ms);
            }
            all.details.extend(t.summary);
            all.details.extend(t.details);
        }
        Some(all)
    }
}

/// A collection file a [`SIDECAR_FILE`] describes: its path in the folder
/// (`/` between parts), size and last change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct CollectedFile {
    path: String,
    bytes: u64,
    modified_ms: u64,
}

/// [`SIDECAR_FILE`]: the timings, and the files of the collection they are
/// the timings of.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sidecar {
    files: Vec<CollectedFile>,
    timings: CollectionTimings,
}

/// `path` as the folder `dir` lists it, if it is a collection file there.
fn collected_file(dir: &Path, path: &Path) -> Option<CollectedFile> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let rel = path.strip_prefix(dir).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let modified_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64);
    Some(CollectedFile {
        path: parts.join("/"),
        bytes: meta.len(),
        modified_ms,
    })
}

/// The collection files `pathwarden run -i dir` reads: every `.json` and
/// `.zip` in it and its folders, links not followed (as the input readers).
fn collection_files(dir: &Path) -> Vec<CollectedFile> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<CollectedFile>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(root, &path, out);
            } else if kind.is_file() {
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase());
                if matches!(ext.as_deref(), Some("json" | "zip")) {
                    out.extend(collected_file(root, &path));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Leaves `t` in `dir` (a collection's output folder) as [`SIDECAR_FILE`],
/// with the `files` the collection wrote there.
pub fn write_sidecar(dir: &Path, t: &CollectionTimings, files: &[PathBuf]) -> std::io::Result<()> {
    let mut files: Vec<CollectedFile> = files
        .iter()
        .filter_map(|f| collected_file(dir, f))
        .collect();
    files.sort();
    let sidecar = Sidecar {
        files,
        timings: t.clone(),
    };
    let mut text = serde_json::to_string_pretty(&sidecar).map_err(std::io::Error::other)?;
    text.push('\n');
    std::fs::write(dir.join(SIDECAR_FILE), text)
}

/// The timings [`collected_timings`] found, and the sidecars they came
/// from.
#[derive(Debug, Clone, PartialEq)]
pub struct FolderTimings {
    pub timings: CollectionTimings,
    sidecars: Vec<PathBuf>,
}

impl FolderTimings {
    /// Once the run is recorded: each sidecar renamed
    /// [`RECORDED_SIDECAR_FILE`], so the next analysis of the folder (the
    /// same data, not a new collection) has no timings. A folder that can't
    /// be written keeps it.
    pub fn mark_recorded(&self) {
        for s in &self.sidecars {
            let _ = std::fs::rename(s, s.with_file_name(RECORDED_SIDECAR_FILE));
        }
    }
}

/// The timings `pathwarden collect` left in the folders of `inputs`, as one
/// ([`CollectionTimings::combine`]): each folder's, else those of the
/// folders in it (a schedule of several domains collects each into its
/// own). Only when they describe every file the run reads, unchanged since
/// the collection, and haven't been recorded: data added later, a file
/// given beside the folders or an old domain's folder, and none.
pub fn collected_timings(inputs: &[PathBuf]) -> Option<FolderTimings> {
    // The sidecar of `dir` and the files it describes.
    let read = |dir: &Path| -> Option<(PathBuf, Sidecar)> {
        let path = dir.join(SIDECAR_FILE);
        // Not through a link: the folder is the collector's own.
        if !std::fs::symlink_metadata(&path).ok()?.is_file() {
            return None;
        }
        let text = std::fs::read_to_string(&path).ok()?;
        let s: Sidecar = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
        Some((path, s))
    };
    let mut parts = Vec::new();
    let mut sidecars = Vec::new();
    for input in inputs {
        if !std::fs::symlink_metadata(input).ok()?.is_dir() {
            return None;
        }
        let files = collection_files(input);
        if let Some((path, s)) = read(input) {
            if s.files != files {
                return None;
            }
            parts.push(s.timings);
            sidecars.push(path);
            continue;
        }
        // Each file in a folder whose sidecar describes it.
        let mut covered = 0;
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(input)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect();
        dirs.sort();
        for d in dirs {
            let Some((path, s)) = read(&d) else {
                continue;
            };
            if s.files != collection_files(&d) {
                return None;
            }
            covered += s.files.len();
            parts.push(s.timings);
            sidecars.push(path);
        }
        if covered != files.len() {
            return None;
        }
    }
    Some(FolderTimings {
        timings: CollectionTimings::combine(parts)?,
        sidecars,
    })
}

/// `0.42s`, `12.1s`, `3:12`, `1:02:03`.
pub fn duration(ms: u64) -> String {
    let s = ms as f64 / 1000.0;
    if s >= 60.0 {
        let secs = ms / 1000;
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        if h > 0 {
            format!("{h}:{m:02}:{s:02}")
        } else {
            format!("{m}:{s:02}")
        }
    } else if s >= 10.0 {
        format!("{s:.1}s")
    } else {
        format!("{s:.2}s")
    }
}

/// `512 KB`, `1.9 GB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else if v < 10.0 {
        format!("{v:.1} {}", UNITS[u])
    } else {
        format!("{v:.0} {}", UNITS[u])
    }
}

// ------------------------------------------------------------ comparison

/// Which way a measure moved since the earlier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trend {
    /// Better: faster, less memory, more computers reached, fewer failed.
    Better,
    Worse,
    /// No change, or within what varies run to run.
    Same,
    /// More or fewer, neither better nor worse (entries read).
    Neutral,
}

/// One line of the comparison: a number and its change since the earlier
/// run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measure {
    /// Stable key (`total`, `read`, `hosts_reached`, ...).
    pub key: &'static str,
    pub label: &'static str,
    /// The number, in words ("3:12", "1.9 GB", "120 of 130").
    pub value: String,
    /// "0:31 slower", "6 more", "about the same"; `None` without an
    /// earlier run that measured it.
    pub change: Option<String>,
    pub trend: Option<Trend>,
    /// What it measures, for the (i).
    pub definition: &'static str,
}

/// A [`Measure::change`] as a phrase about the run it is compared with:
/// "0:31 slower than the last timed run", "about the same as the last
/// timed run".
pub fn against_last(change: &str) -> String {
    match change {
        "about the same" => "about the same as the last timed run".into(),
        "no change" => "no change since the last timed run".into(),
        c => format!("{c} than the last timed run"),
    }
}

/// The definitions of every [`Measure`], in order, for the list at the
/// bottom of the panel (and `diagnose --help`'s docs).
pub const DEFINITIONS: &[(&str, &str)] = &[
    ("Total", "The whole collection, from connecting to the domain controller to writing the zip."),
    ("Connect", "Opening the LDAP connection and signing in."),
    ("Read", "Reading the directory. Usually most of the time; a slow read with a fast network means the domain controller is slow to answer."),
    ("Processing", "Turning the entries into objects, then resolving memberships and permissions."),
    ("Computers and SYSVOL", "Contacting computers for sessions and local groups, and reading SYSVOL (Group Policy files)."),
    ("Write", "Writing the collection zip."),
    ("Peak memory", "The most memory the collector used at the end of any step."),
    ("Entries read", "Directory entries received, every naming context."),
    ("Computers reached", "Computers where sessions could be read, of those tried. Disabled and stale computers are skipped."),
    ("Computers failed", "Computers tried where nothing could be read: access denied, unreachable or a refused sign-in. The error kinds are counted below."),
    ("Computers timed out", "Computers tried that did not answer before the per-computer time limit."),
];

fn definition(label: &str) -> &'static str {
    DEFINITIONS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, d)| *d)
        .unwrap_or("")
}

/// A time's change: "0:31 slower" is worse, within [`SAME_SHARE`] or
/// [`SAME_MS`] is the same.
fn time_change(before: u64, after: u64) -> (String, Trend) {
    let diff = after.abs_diff(before);
    if diff < SAME_MS || (diff as f64) < before as f64 * SAME_SHARE {
        return ("about the same".into(), Trend::Same);
    }
    if after > before {
        (format!("{} slower", duration(diff)), Trend::Worse)
    } else {
        (format!("{} faster", duration(diff)), Trend::Better)
    }
}

/// A count's change in words ("1,000 more", "2 fewer"), so it doesn't take
/// the colour to tell which way it went.
fn count_change(before: usize, after: usize, more_is: Trend) -> (String, Trend) {
    use std::cmp::Ordering;
    let n = |d: usize| crate::report::num(d);
    match after.cmp(&before) {
        Ordering::Equal => ("no change".into(), Trend::Same),
        Ordering::Greater => (format!("{} more", n(after - before)), more_is),
        Ordering::Less => (
            format!("{} fewer", n(before - after)),
            match more_is {
                Trend::Better => Trend::Worse,
                Trend::Worse => Trend::Better,
                t => t,
            },
        ),
    }
}

/// `cur`'s measures, each with its change since `prev` when `prev` has it.
pub fn measures(cur: &CollectionTimings, prev: Option<&CollectionTimings>) -> Vec<Measure> {
    let mut out = Vec::new();
    let mut time = |key, label: &'static str, now: Option<u64>, then: Option<Option<u64>>| {
        let Some(now) = now else { return };
        let (change, trend) = match then.flatten() {
            Some(b) => {
                let (c, t) = time_change(b, now);
                (Some(c), Some(t))
            }
            None => (None, None),
        };
        out.push(Measure {
            key,
            label,
            value: duration(now),
            change,
            trend,
            definition: definition(label),
        });
    };
    let processing = |t: &CollectionTimings| match (t.phase("parse"), t.phase("resolve")) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    };
    time(
        "total",
        "Total",
        Some(cur.total_ms),
        prev.map(|p| Some(p.total_ms)),
    );
    time(
        "connect",
        "Connect",
        cur.phase("connect"),
        prev.map(|p| p.phase("connect")),
    );
    time(
        "read",
        "Read",
        cur.phase("read"),
        prev.map(|p| p.phase("read")),
    );
    time(
        "processing",
        "Processing",
        processing(cur),
        prev.map(processing),
    );
    time(
        "modules",
        "Computers and SYSVOL",
        cur.phase("modules"),
        prev.map(|p| p.phase("modules")),
    );
    time(
        "write",
        "Write",
        cur.phase("write"),
        prev.map(|p| p.phase("write")),
    );
    if let Some(peak) = cur.peak() {
        let (change, trend) = match prev.and_then(|p| p.peak()) {
            Some(b) => {
                let diff = peak.abs_diff(b);
                if (diff as f64) < b as f64 * SAME_SHARE {
                    (Some("about the same".to_string()), Some(Trend::Same))
                } else if peak > b {
                    (Some(format!("{} more", bytes(diff))), Some(Trend::Worse))
                } else {
                    (Some(format!("{} less", bytes(diff))), Some(Trend::Better))
                }
            }
            None => (None, None),
        };
        out.push(Measure {
            key: "peak_memory",
            label: "Peak memory",
            value: bytes(peak),
            change,
            trend,
            definition: definition("Peak memory"),
        });
    }
    if cur.entries > 0 {
        let (change, trend) = match prev.filter(|p| p.entries > 0) {
            Some(p) => {
                let (c, t) = count_change(p.entries as usize, cur.entries as usize, Trend::Neutral);
                (Some(c), Some(t))
            }
            None => (None, None),
        };
        out.push(Measure {
            key: "entries",
            label: "Entries read",
            value: crate::report::num(cur.entries as usize),
            change,
            trend,
            definition: definition("Entries read"),
        });
    }
    if let Some(h) = cur.hosts.as_ref().filter(|h| h.tried > 0) {
        let before = prev.and_then(|p| p.hosts.as_ref()).filter(|h| h.tried > 0);
        let mut host =
            |key, label: &'static str, value: String, now: usize, then: Option<usize>, more_is| {
                let (change, trend) = match then {
                    Some(b) => {
                        let (c, t) = count_change(b, now, more_is);
                        (Some(c), Some(t))
                    }
                    None => (None, None),
                };
                out.push(Measure {
                    key,
                    label,
                    value,
                    change,
                    trend,
                    definition: definition(label),
                });
            };
        host(
            "hosts_reached",
            "Computers reached",
            format!(
                "{} of {}",
                crate::report::num(h.reached),
                crate::report::num(h.tried)
            ),
            h.reached,
            before.map(|b| b.reached),
            Trend::Better,
        );
        host(
            "hosts_failed",
            "Computers failed",
            crate::report::num(h.failed),
            h.failed,
            before.map(|b| b.failed),
            Trend::Worse,
        );
        host(
            "hosts_timed_out",
            "Computers timed out",
            crate::report::num(h.timed_out),
            h.timed_out,
            before.map(|b| b.timed_out),
            Trend::Worse,
        );
    }
    out
}

/// "access denied 6, unreachable 2": the error kinds, most first.
pub fn error_line(h: &HostSummary) -> Option<String> {
    let mut kinds: Vec<(&String, &usize)> = h.errors.iter().filter(|(_, n)| **n > 0).collect();
    if kinds.is_empty() {
        return None;
    }
    kinds.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    Some(
        kinds
            .iter()
            .map(|(k, n)| format!("{k} {}", crate::report::num(**n)))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

// --------------------------------------------------------------- bundle

/// The machine the bundle is made on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemInfo {
    pub pathwarden: String,
    /// "Windows 11 Pro (build 26200)", "Ubuntu 24.04.1 LTS".
    pub os: String,
    pub arch: String,
    pub logical_processors: usize,
    pub memory_bytes: Option<u64>,
}

/// Strings Pathwarden writes itself (statuses, kinds, step names), by
/// their key: kept as they are. Every other string is a name.
const OWN_KEYS: &[&str] = &[
    "exposure_grade",
    "exposure_status",
    "status",
    "from_kind",
    "to_kind",
    "edges",
    "pathwarden",
    "collector",
    "method",
    "scope",
    "severity",
    "rule",
    "category",
];

/// Words Pathwarden itself writes into a bundle, and objects every domain
/// has: a run's object of one of these names identifies nothing.
const OWN_WORDS: &[&str] = &[
    "USERS",
    "USER",
    "COMPUTERS",
    "COMPUTER",
    "MACHINE",
    "MICROSOFT",
    "SYSTEM",
    "BUILTIN",
    "ADMINISTRATOR",
    "ADMINISTRATORS",
    "GUEST",
    "GUESTS",
    "KRBTGT",
    "SCHEMA",
    "SERVICES",
    "CONFIGURATION",
    "POLICIES",
    "DOMAIN",
    "CONNECT",
    "READ",
    "PARSE",
    "RESOLVE",
    "MODULES",
    "SYSVOL",
    "WRITE",
    "TOTAL",
    "COLLECTOR",
    "SHARPHOUND",
    "BUILT-IN",
    "BUILTIN",
    "TIER",
    "ZERO",
    "CRITICAL",
    "HIGH",
    "MODERATE",
    "MEDIUM",
    "LOW",
    "INFO",
    "NONE",
    "TRUE",
    "FALSE",
    "NULL",
    "PATHWARDEN",
    "TIMING",
    "ENTRIES",
    "PAGES",
    "OTHER",
    "PARTITION",
    "DELETED",
    "SESSIONS",
    "GROUPS",
    "LOCAL",
    "MEMORY",
    "PEAK",
    "WINDOWS",
    "LINUX",
    "MACOS",
    "BUILD",
    "README",
    "JSON",
    "TEXT",
    "RUN",
    "PLAN",
    "POSTURE",
    "SETTINGS",
    "TIMINGS",
    "PREVIOUS",
    "ERRORS",
    "DENIED",
    "ACCESS",
    "UNREACHABLE",
    "TIMEOUT",
    "SIGN-IN",
    "REGISTRY",
    "REMOTE",
    "STARTING",
    "DC-ONLY",
    "ALL",
    "LDAPS",
    "LDAP",
    "EVERYONE",
    "PUBLIC",
];

/// Whether `t` (upper-cased) is one of Pathwarden's own words: [`OWN_WORDS`]
/// or the name of an object kind or edge kind it knows (`GROUP`, `OWNS`,
/// `MEMBEROF`). The plan writes those words, so an OU or account of the same
/// name would refuse every bundle of its domain, and identifies nothing.
fn own_word(t: &str) -> bool {
    static KINDS: OnceLock<HashSet<String>> = OnceLock::new();
    OWN_WORDS.contains(&t)
        || KINDS
            .get_or_init(|| {
                NodeKind::ALL
                    .iter()
                    .map(|k| k.as_str())
                    .chain(EdgeKind::ALL.iter().map(|k| k.as_str()))
                    .chain([EXTERNAL_KIND])
                    .map(str::to_uppercase)
                    .collect()
            })
            .contains(t)
}

/// What the plan writes for an object or edge kind Pathwarden doesn't know
/// itself (an OpenGraph file's): the file named it, so it isn't written.
const EXTERNAL_KIND: &str = "External";

/// The keys whose values are fixed vocabulary: object kinds and edge kinds.
const KIND_KEYS: &[&str] = &["from_kind", "to_kind", "edges"];

/// `s` under `key`, a [`KIND_KEYS`] field, as Pathwarden writes it: a kind
/// it knows by its own name, [`EXTERNAL_KIND`] for any other.
fn known_kind(key: &str, s: &str) -> &'static str {
    let known = if key == "edges" {
        EdgeKind::from_name(s).map(EdgeKind::as_str)
    } else {
        NodeKind::ALL
            .iter()
            .find(|k| k.as_str().eq_ignore_ascii_case(s))
            .map(|k| k.as_str())
    };
    known.unwrap_or(EXTERNAL_KIND)
}

/// Whether `s` under `key` is a known kind, as [`known_kind`] writes it:
/// fixed vocabulary, so not searched.
fn is_known_kind(key: &str, s: &str) -> bool {
    KIND_KEYS.contains(&key) && known_kind(key, s) == s
}

/// Domain labels too common to mean anything (`corp` of `corp.local`).
const GENERIC_LABELS: &[&str] = &[
    "LOCAL", "COM", "NET", "ORG", "INT", "LAN", "CORP", "AD", "DOMAIN", "INTERNAL", "HOME",
];

/// Replaces names with placeholders named after their field (`domain-1`,
/// `zone-2`): the same name gets the same placeholder wherever it appears,
/// whatever its case.
#[derive(Debug, Default)]
pub struct Placeholders {
    map: HashMap<String, String>,
    next: HashMap<String, usize>,
}

impl Placeholders {
    /// The placeholder for `name` as a `kind` ("domain", "zone").
    pub fn of(&mut self, kind: &str, name: &str) -> String {
        let key = name.trim().to_uppercase();
        if let Some(p) = self.map.get(&key) {
            return p.clone();
        }
        let kind: String = kind
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let kind = if kind.is_empty() { "name".into() } else { kind };
        let n = self.next.entry(kind.clone()).or_default();
        *n += 1;
        let p = format!("{kind}-{n}");
        self.map.insert(key, p.clone());
        p
    }

    /// The placeholders written so far, upper-cased as the scan reads text.
    pub fn written(&self) -> HashSet<String> {
        self.map.values().map(|p| p.to_uppercase()).collect()
    }

    /// Every string in `v` replaced, except those under [`OWN_KEYS`] that
    /// look like Pathwarden's words and the name "Tier Zero".
    pub fn scrub(&mut self, v: &mut Value) {
        self.scrub_at(v, "");
    }

    fn scrub_at(&mut self, v: &mut Value, key: &str) {
        match v {
            Value::String(s) => {
                let own = OWN_KEYS.contains(&key) && is_vocabulary(s);
                if !(own || (key == "zone" && s == "Tier Zero")) {
                    *s = self.of(singular(key), s);
                }
            }
            Value::Array(a) => {
                for x in a {
                    self.scrub_at(x, key);
                }
            }
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    self.scrub_at(x, k);
                }
            }
            _ => {}
        }
    }
}

/// The placeholder's name for a value under `key`: `domain` for any list
/// or field of domains, `domains` → `domain`.
fn singular(key: &str) -> &str {
    match key {
        "" => "name",
        k if k.contains("domain") => "domain",
        k => k.strip_suffix('s').filter(|s| s.len() > 2).unwrap_or(k),
    }
}

/// Short words of letters, digits, spaces, `-`, `_` and `.`: what
/// Pathwarden writes as a status, kind or step name.
fn is_vocabulary(s: &str) -> bool {
    s.len() <= 40
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
}

/// The names a bundle must not contain: a run's domains, objects (names,
/// their parts, distinguished names' components) and domain SIDs.
#[derive(Debug, Default, Clone)]
pub struct NameScan {
    /// Upper-cased single words.
    words: HashSet<String>,
    /// Upper-cased text with spaces or other characters, found anywhere.
    phrases: HashSet<String>,
    /// Domain SIDs (`S-1-5-21-a-b-c`).
    sids: HashSet<String>,
    /// The phrases and SIDs as one automaton, built on the first search: a
    /// domain's names are hundreds of thousands, searched in one pass.
    matcher: OnceLock<(aho_corasick::AhoCorasick, Vec<usize>)>,
}

fn token_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.' | '$' | '-')
}

impl NameScan {
    /// How many names it looks for.
    pub fn len(&self) -> usize {
        self.words.len() + self.phrases.len() + self.sids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn add_text(&mut self, text: &str) {
        let t = text.trim().to_uppercase();
        if t.chars().count() < 4 || own_word(&t) {
            return;
        }
        if t.chars().all(token_char) {
            self.words.insert(t.trim_matches('.').to_string());
        } else {
            self.matcher = OnceLock::new();
            // As written, and as JSON writes it (quotes, backslashes and
            // control characters escaped).
            let esc = serde_json::to_string(&t).unwrap_or_default();
            let esc = esc[1..esc.len().saturating_sub(1).max(1)].to_string();
            if esc != t {
                self.phrases.insert(esc);
            }
            self.phrases.insert(t);
        }
    }

    /// A domain, and each of its labels that means something.
    pub fn add_domain(&mut self, domain: &str) {
        let d = domain.trim().to_uppercase();
        if d.is_empty() {
            return;
        }
        self.words.insert(d.clone());
        for label in d.split('.') {
            if label.chars().count() >= 3 && !GENERIC_LABELS.contains(&label) {
                self.words.insert(label.to_string());
            }
        }
    }

    /// An object's name: `NAME@DOMAIN` (both parts: the search splits text
    /// at `@`, so the whole is found through them), or a computer's host
    /// name (whole and short).
    pub fn add_name(&mut self, name: &str) {
        match name.rsplit_once('@') {
            Some((n, d)) => {
                self.add_text(n);
                self.add_domain(d);
            }
            None => {
                self.add_text(name);
                if let Some((short, _)) = name.split_once('.') {
                    self.add_text(short);
                }
            }
        }
    }

    /// A name as a finding lists it, searched for whole (`NAME@DOMAIN` as
    /// written, its domain as [`NameScan::add_domain`]) and not by its parts:
    /// what `evidence --redact` withholds. A pack's report and README are
    /// prose, where an account's first part ("Administrator") is a word.
    pub fn add_listed(&mut self, name: &str) {
        self.add_text(name);
        if let Some((_, d)) = name.rsplit_once('@') {
            self.add_domain(d);
        }
    }

    /// A distinguished name's values (`CN=Alice Smith,OU=Finance,...`).
    pub fn add_dn(&mut self, dn: &str) {
        for part in dn.split(',') {
            if let Some((_, value)) = part.split_once('=') {
                self.add_text(value);
            }
        }
    }

    /// An object ID: the domain SID of `S-1-5-21-a-b-c-RID`.
    pub fn add_sid(&mut self, id: &str) {
        let up = id.trim().to_uppercase();
        let Some(rest) = up.strip_prefix("S-1-5-21-") else {
            return;
        };
        let parts: Vec<&str> = rest.split('-').take(3).collect();
        if parts.len() == 3
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
            && self.sids.insert(format!("S-1-5-21-{}", parts.join("-")))
        {
            self.matcher = OnceLock::new();
        }
    }

    /// Every name `other` looks for, added to these.
    pub fn extend(&mut self, other: &NameScan) {
        self.words.extend(other.words.iter().cloned());
        self.phrases.extend(other.phrases.iter().cloned());
        self.sids.extend(other.sids.iter().cloned());
        self.matcher = OnceLock::new();
    }

    /// Every object of a saved object index.
    pub fn add_index(&mut self, index: &crate::object_index::ObjectIndex) {
        for d in &index.domains {
            self.add_domain(d);
        }
        for o in &index.objects {
            self.add_sid(&o.0);
            self.add_name(&o.1);
            self.add_dn(&o.4);
        }
    }

    /// The first name `text` holds: its length in characters (the name
    /// itself is never repeated).
    pub fn find(&self, text: &str) -> Option<usize> {
        self.find_except(text, &HashSet::new())
    }

    /// [`NameScan::find`], passing over the words in `written` (upper-cased):
    /// the placeholders a bundle wrote, which an object of the same name
    /// (`domain-1`) would otherwise match in every bundle.
    pub fn find_except(&self, text: &str, written: &HashSet<String>) -> Option<usize> {
        let up = text.to_uppercase();
        for token in up.split(|c: char| !token_char(c)) {
            let t = token.trim_matches('.');
            if t.is_empty() {
                continue;
            }
            // The token, and each part of a dotted one (a host name whose
            // domain labels were left out as generic).
            let parts = std::iter::once(t).chain(t.split('.'));
            for p in parts {
                // A computer's account name: `WS01$`.
                let q = p.trim_end_matches('$');
                if !q.is_empty()
                    && !own_word(q)
                    && !written.contains(q)
                    && (self.words.contains(p) || self.words.contains(q))
                {
                    return Some(q.chars().count());
                }
            }
        }
        let (ac, chars) = self.matcher.get_or_init(|| {
            let all: Vec<&String> = self.phrases.iter().chain(&self.sids).collect();
            let chars = all.iter().map(|p| p.chars().count()).collect();
            // Only fails past limits a domain's names don't reach; then
            // nothing matches, and the words above still do.
            let ac = aho_corasick::AhoCorasick::new(&all).unwrap_or_else(|_| {
                aho_corasick::AhoCorasick::new(std::iter::empty::<&str>()).expect("empty")
            });
            (ac, chars)
        });
        ac.find(&up).map(|m| chars[m.pattern().as_usize()])
    }
}

/// File name endings that make a dotted word a file, not a host.
const FILE_ENDINGS: &[&str] = &[
    "log", "txt", "json", "jsonl", "gz", "zip", "exe", "dll", "rs", "ps1", "psm1", "py", "sh",
    "toml", "html", "htm", "csv", "md", "xml", "pdf", "png", "svg", "js", "css", "age", "sig",
    "msi", "cmd", "bat", "yml", "yaml", "ini", "cfg", "conf", "tmp", "lock", "pem", "crt", "key",
    "pub", "db", "so", "dylib", "pdb", "git",
];

/// Whether a dotted word looks like a host or domain name
/// (`dc01.scale.local`), not a version (`1.0.0-rc.2`), a file
/// (`objects.json.gz`) or an abbreviation (`e.g.`).
fn looks_like_host(t: &str) -> bool {
    let labels: Vec<&str> = t.split('.').collect();
    let Some(last) = labels.last() else {
        return false;
    };
    labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty())
        && last.len() >= 2
        && last.chars().all(|c| c.is_ascii_alphabetic())
        && !FILE_ENDINGS.contains(&last.to_ascii_lowercase().as_str())
        && t.chars().any(|c| c.is_alphabetic())
}

/// The words of this computer that identify it or its user: its name and
/// the account's, upper-cased.
fn own_names() -> HashSet<String> {
    ["COMPUTERNAME", "HOSTNAME", "USERNAME", "USER", "USERDOMAIN"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|v| v.trim().to_uppercase())
        .filter(|v| v.chars().count() >= 3 && !own_word(v))
        .collect()
}

/// `text` (a log) with names replaced by placeholders `ph` gives, the
/// same as everywhere else in the bundle: every name `scan` knows (a
/// word, a phrase, a domain SID), and whatever looks like one without
/// being known: host and domain names, `name@domain`, the values of
/// distinguished names (`CN=`, `OU=`, `DC=`), domain SIDs, the folder
/// under `Users` or `home` of a path, and this computer's and account's
/// names.
pub fn replace_names(text: &str, scan: &NameScan, ph: &mut Placeholders) -> String {
    let own = own_names();
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&replace_line(line, scan, ph, &own));
    }
    out
}

fn replace_line(
    line: &str,
    scan: &NameScan,
    ph: &mut Placeholders,
    own: &HashSet<String>,
) -> String {
    let line = replace_phrases(line, scan, ph);
    let line = replace_dn_values(&line, ph);
    let line = replace_profile(&line, ph);
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    for c in line.chars().map(Some).chain([None]) {
        match c {
            Some(c) if token_char(c) => token.push(c),
            _ => {
                if !token.is_empty() {
                    out.push_str(&replace_token(&token, c, scan, ph, own));
                    token.clear();
                }
                if let Some(c) = c {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// One word of a log line (`after` is the character after it), replaced
/// when it is or holds a name.
fn replace_token(
    token: &str,
    after: Option<char>,
    scan: &NameScan,
    ph: &mut Placeholders,
    own: &HashSet<String>,
) -> String {
    // Dots around it are punctuation.
    let lead = token.len() - token.trim_start_matches('.').len();
    let core = token.trim_matches('.');
    if core.is_empty() {
        return token.to_string();
    }
    let trail = &token[lead + core.len()..];
    let up = core.to_uppercase();
    let wrap = |s: String| format!("{}{s}{trail}", &token[..lead]);
    if own_word(&up) || is_placeholder(core) {
        return token.to_string();
    }
    let known = |p: &str| scan.words.contains(p) || own.contains(p);
    let dotted = |t: &str| match t.matches('.').count() {
        0 => "name",
        1 => "domain",
        _ => "host",
    };
    // A computer's account name (`WS01$`): the computer's placeholder, `$`
    // kept.
    let bare = core.trim_end_matches('$');
    if known(&up) || (bare.len() < core.len() && !bare.is_empty() && known(&bare.to_uppercase())) {
        let dollar = &core[bare.len()..];
        return wrap(format!("{}{dollar}", ph.of(dotted(bare), bare)));
    }
    if let Some(sid) = domain_sid(&up) {
        let rest = &core[sid.len()..];
        return wrap(format!("{}{rest}", ph.of("sid", &sid)));
    }
    if core.contains('.') {
        if looks_like_host(core) {
            return wrap(ph.of(dotted(core), core));
        }
        // A file or a version: its known parts only.
        let parts: Vec<String> = core
            .split('.')
            .map(|p| {
                let u = p.to_uppercase();
                if !p.is_empty() && !own_word(&u) && known(&u) {
                    ph.of("name", p)
                } else {
                    p.to_string()
                }
            })
            .collect();
        return wrap(parts.join("."));
    }
    // `name@domain`: the account.
    if after == Some('@') && core.chars().any(|c| c.is_alphabetic()) {
        return wrap(ph.of("account", core));
    }
    token.to_string()
}

/// A placeholder this module writes: `domain-1`, `host-12`.
fn is_placeholder(t: &str) -> bool {
    t.rsplit_once('-').is_some_and(|(k, n)| {
        !n.is_empty()
            && n.chars().all(|c| c.is_ascii_digit())
            && matches!(
                k,
                "domain" | "host" | "name" | "account" | "sid" | "user" | "zone"
            )
    })
}

/// The domain SID a word starts with (`S-1-5-21-a-b-c`), upper-cased.
fn domain_sid(up: &str) -> Option<String> {
    let rest = up.strip_prefix("S-1-5-21-")?;
    let parts: Vec<&str> = rest.splitn(4, '-').take(3).collect();
    (parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
    .then(|| format!("S-1-5-21-{}", parts.join("-")))
}

/// `line` with every phrase and SID `scan` knows replaced. The search is
/// in upper case, mapped back character by character, so a letter whose
/// upper case is longer changes nothing else in the line.
fn replace_phrases(line: &str, scan: &NameScan, ph: &mut Placeholders) -> String {
    if scan.phrases.is_empty() && scan.sids.is_empty() {
        return line.to_string();
    }
    // Where each upper-case byte offset starts and ends in `line`.
    let mut up = String::with_capacity(line.len());
    let mut starts: HashMap<usize, usize> = HashMap::new();
    let mut ends: HashMap<usize, usize> = HashMap::new();
    for (i, c) in line.char_indices() {
        starts.insert(up.len(), i);
        up.extend(c.to_uppercase());
        ends.insert(up.len(), i + c.len_utf8());
    }
    // The same automaton as [`NameScan::find_except`]'s.
    let _ = scan.find("");
    let Some((ac, _)) = scan.matcher.get() else {
        return line.to_string();
    };
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    for m in ac.find_iter(&up) {
        let (Some(&a), Some(&b)) = (starts.get(&m.start()), ends.get(&m.end())) else {
            continue;
        };
        if a < at {
            continue;
        }
        out.push_str(&line[at..a]);
        let found = &line[a..b];
        let kind = if found.to_uppercase().starts_with("S-1-5-21-") {
            "sid"
        } else {
            "name"
        };
        out.push_str(&ph.of(kind, found));
        at = b;
    }
    out.push_str(&line[at..]);
    out
}

/// The values of a distinguished name's `CN=`, `OU=` and `DC=` parts.
fn replace_dn_values(line: &str, ph: &mut Placeholders) -> String {
    let up = line.to_ascii_uppercase();
    let b = up.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    let mut i = 0;
    while i + 3 <= b.len() {
        let starts = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        let key = up.get(i..i + 3).unwrap_or_default();
        if starts && matches!(key, "CN=" | "OU=" | "DC=") {
            let v = i + 3;
            let end = line[v..]
                .find([',', '"', '\'', ')', ']', ';'])
                .map_or(line.len(), |e| v + e);
            let value = line[v..end].trim();
            if !value.is_empty() && !own_word(&value.to_uppercase()) && !is_placeholder(value) {
                out.push_str(&line[at..v]);
                let kind = if key == "DC=" { "domain" } else { "name" };
                out.push_str(&ph.of(kind, value));
                at = end;
            }
            i = end.max(i + 1);
            continue;
        }
        i += 1;
    }
    out.push_str(&line[at..]);
    out
}

/// The account folder of a path (`C:\Users\<name>\`, `/home/<name>/`,
/// and `C:\\Users\\<name>` as JSON and Rust's `{:?}` write it).
fn replace_profile(line: &str, ph: &mut Placeholders) -> String {
    let mut out = line.to_string();
    for sep in ["\\\\", "\\", "/"] {
        for dir in ["Users", "users", "USERS", "home"] {
            let needle = format!("{sep}{dir}{sep}");
            let mut from = 0;
            while let Some(i) = out[from..].find(&needle).map(|i| from + i) {
                let v = i + needle.len();
                let end = out[v..]
                    .find(|c: char| {
                        c == '\\' || c == '/' || c.is_whitespace() || c == '"' || c == '\''
                    })
                    .map_or(out.len(), |e| v + e);
                let name = out[v..end].to_string();
                if name.is_empty() || is_placeholder(&name) || name.eq_ignore_ascii_case("public") {
                    from = end.max(v);
                    continue;
                }
                let p = ph.of("user", &name);
                out.replace_range(v..end, &p);
                from = v + p.len();
            }
        }
    }
    out
}

/// No bundle: `file` holds a name of the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub file: String,
    /// The name's length (the name is never shown).
    pub chars: usize,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not written: {} would contain a name from the run ({} characters), so no bundle \
             was made. Please report this as a bug (the file's name, not its contents).",
            self.file, self.chars
        )
    }
}

impl std::error::Error for Refused {}

/// The bundle's files, as its README lists those it holds.
const README_FILES: &[(&str, &str)] = &[
    ("system.json", "Pathwarden version, OS, CPU cores, memory"),
    (
        "run.json",
        "the run's posture numbers, findings and plan size",
    ),
    (
        "posture.json",
        "posture with collection completeness, per domain",
    ),
    (
        "plan.json",
        "the remediation plan's steps: costs and edge kinds",
    ),
    ("findings.json", "open findings by rule and severity"),
    (
        "collection.json",
        "how the data was collected (no credentials), the computers\r\n\
         \x20                      reached and error counts by kind",
    ),
    ("timings.json", "where the collection's time went"),
    (
        "timings-previous.json",
        "the same for the environment's previous run",
    ),
];

/// What a bundle is made of. Strings in `run`, `posture`, `plan` and
/// `collection` are replaced by placeholders when it is built.
#[derive(Debug, Default)]
pub struct Bundle {
    pub system: SystemInfo,
    /// The run's numbers (posture, findings, plan size, objects).
    pub run: Value,
    pub timings: Option<CollectionTimings>,
    /// The environment's previous run with timings, for the comparison.
    pub previous: Option<CollectionTimings>,
    /// The event document's posture (with completeness).
    pub posture: Option<Value>,
    /// The plan's numbers: steps, costs, edge kinds; no objects.
    pub plan: Option<Value>,
    /// Open findings by rule and severity.
    pub findings_by_rule: BTreeMap<String, BTreeMap<String, usize>>,
    /// How the data was collected, without credentials or names.
    pub collection: Option<Value>,
    /// Pathwarden's logs and crash reports ([`crate::logs::for_bundle`]):
    /// file name and text. Every name in them is replaced
    /// ([`replace_names`]) and they are searched like the rest.
    pub logs: Vec<(String, String)>,
}

/// What a bundle holds, as the run page lists it.
pub const CONTENTS: &[&str] = &[
    "This computer",
    "Run numbers",
    "Timings",
    "Completeness",
    "Posture",
    "Remediation path size",
    "Findings by rule",
    "Latest logs",
    "Crash reports",
];

/// What the list's (i) says.
pub const CONTENTS_TIP: &str = "This run's logs, and the app's session logs and crash reports of the last 7 days, at most 20 MB. Look through the zip before you send it.";

/// The plan's numbers from an event document's `plan`: per step its cost,
/// edge kinds and reach; never its objects or action text. The kinds are
/// checked against Pathwarden's own ([`known_kind`]): any other is written
/// as `External`.
pub fn plan_numbers(plan: &Value) -> Value {
    let kind = |key: &str, v: &Value| match v {
        Value::String(s) => json!(known_kind(key, s)),
        _ => Value::Null,
    };
    let fixes: Vec<Value> = plan["fixes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|f| {
                    let edges: Vec<Value> = f["edges"]
                        .as_array()
                        .map(|e| e.iter().map(|x| kind("edges", x)).collect())
                        .unwrap_or_default();
                    json!({
                        "from_kind": kind("from_kind", &f["from_kind"]),
                        "to_kind": kind("to_kind", &f["to_kind"]),
                        "edges": edges,
                        "cost": f["cost"],
                        "principals_through": f["principals_through"],
                        "shortest_paths_through": f["shortest_paths_through"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = json!({ "steps": fixes.len(), "fixes": fixes });
    for k in [
        "exposed_before",
        "exposed_after",
        "exposure_before",
        "exposure_after",
        "exposure_delta",
        "relevant_population",
        "relevant_population_after",
        "first_fix_exposure_after",
        "total_cost",
    ] {
        if let Some(v) = plan.get(k).filter(|v| v.is_number()) {
            out[k] = v.clone();
        }
    }
    out
}

impl Bundle {
    /// The bundle's files, names replaced, before the search.
    pub fn files(&self) -> Vec<(String, Vec<u8>)> {
        self.files_and_placeholders(&NameScan::default()).0
    }

    /// The files, and the placeholders written into them (upper-cased).
    /// `scan`'s names are replaced in the logs too.
    fn files_and_placeholders(&self, scan: &NameScan) -> (Vec<(String, Vec<u8>)>, HashSet<String>) {
        let mut ph = Placeholders::default();
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut json_file = |name: &str, mut v: Value, scrub: bool, ph: &mut Placeholders| {
            if scrub {
                ph.scrub(&mut v);
            }
            let mut b = serde_json::to_vec_pretty(&v).unwrap_or_default();
            b.push(b'\n');
            files.push((name.to_string(), b));
        };
        json_file(
            "system.json",
            serde_json::to_value(&self.system).unwrap_or(Value::Null),
            false,
            &mut ph,
        );
        json_file("run.json", self.run.clone(), true, &mut ph);
        if let Some(p) = &self.posture {
            json_file("posture.json", p.clone(), true, &mut ph);
        }
        if let Some(p) = &self.plan {
            json_file("plan.json", plan_numbers(p), true, &mut ph);
        }
        json_file(
            "findings.json",
            serde_json::to_value(&self.findings_by_rule).unwrap_or(Value::Null),
            false,
            &mut ph,
        );
        // A run of data `pathwarden collect` wrote, then analyzed, has no
        // settings: how it was collected is the timings'.
        let collection = self.collection.clone().or_else(|| {
            self.timings
                .as_ref()
                .map(|t| json!({ "collector": t.collector, "scope": t.scope() }))
        });
        if let Some(mut c) = collection {
            if let Some(h) = self.timings.as_ref().and_then(|t| t.hosts.as_ref()) {
                c["computers"] = serde_json::to_value(h).unwrap_or(Value::Null);
            }
            json_file("collection.json", c, true, &mut ph);
        }
        for (name, t) in [
            ("timings.json", &self.timings),
            ("timings-previous.json", &self.previous),
        ] {
            if let Some(t) = t {
                // Counts and durations by design; kinds and step names
                // are Pathwarden's. Not the log's lines: their numbers are
                // the fields', and their words would be searched for as
                // names (an OU called "Count").
                let t = CollectionTimings {
                    summary: None,
                    details: Vec::new(),
                    ..t.clone()
                };
                json_file(
                    name,
                    serde_json::to_value(&t).unwrap_or(Value::Null),
                    false,
                    &mut ph,
                );
            }
        }
        for (name, text) in &self.logs {
            let text = replace_names(text, scan, &mut ph);
            files.push((format!("logs/{name}"), text.into_bytes()));
        }
        let mut readme = format!(
            "Pathwarden diagnostics bundle\r\n\
             =============================\r\n\r\n\
             Made by `pathwarden diagnose --bundle` (or the run page's \"Download diagnostics\")\r\n\
             with Pathwarden {}. Counts, durations and logs: every domain, object, host,\r\n\
             account and zone name is replaced by a placeholder (domain-1, zone-1), and the bundle was\r\n\
             searched for the run's names before it was written.\r\n\r\n",
            self.system.pathwarden
        );
        for (name, what) in README_FILES {
            if files.iter().any(|(f, _)| f == name) {
                readme.push_str(&format!("{name:<23}{what}\r\n"));
            }
        }
        if !self.logs.is_empty() {
            readme.push_str(&format!(
                "{:<23}the logs of this run's jobs, and the app's session logs and\r\n\
                 \x20                      crash reports of the last {} days (at most {} in\r\n\
                 \x20                      all), every name replaced\r\n",
                "logs/",
                crate::logs::BUNDLE_DAYS,
                bytes(crate::logs::BUNDLE_BYTES)
            ));
        }
        files.insert(0, ("README.txt".into(), readme.into_bytes()));
        (files, ph.written())
    }

    /// The zip, or [`Refused`] when a file holds a name `scan` knows.
    pub fn zip(&self, scan: &NameScan) -> Result<Vec<u8>, Refused> {
        let (files, written) = self.files_and_placeholders(scan);
        check_except(&files, scan, &written)?;
        Ok(zip_files(&files))
    }
}

/// The error kinds the built-in collector counts computers' errors by
/// ([`HostSummary::errors`]' keys).
pub const ERROR_KINDS: &[&str] = &[
    "timeout",
    "remote registry starting",
    "access denied",
    "sign-in",
    "unreachable",
    "other",
];

/// Severities, as findings are counted by (`findings.json`).
const SEVERITY_WORDS: &[&str] = &["critical", "high", "medium", "low", "info", "accepted"];

/// Whether a JSON key is Pathwarden's own, so not searched: a field name
/// (lower-case letters, digits and `_`, as serde writes them), a rule ID
/// (`PW-012`), a severity or an error kind. Any other key is searched as a
/// value is: a map keyed by a name can't pass the check.
fn own_key(k: &str) -> bool {
    let field = k.starts_with(|c: char| c.is_ascii_lowercase())
        && k.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    let rule = k
        .strip_prefix("PW-")
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    field || rule || SEVERITY_WORDS.contains(&k) || ERROR_KINDS.contains(&k)
}

/// The text of a file to search: a JSON file's string values and the keys
/// that aren't Pathwarden's own ([`own_key`]), anything else whole. Known
/// object and edge kinds under their keys ([`is_known_kind`]) are fixed
/// vocabulary, not searched.
fn searched_text(data: &[u8]) -> String {
    fn strings(v: &Value, key: &str, out: &mut String) {
        match v {
            Value::String(s) => {
                if !is_known_kind(key, s) {
                    out.push_str(s);
                    out.push('\n');
                }
            }
            Value::Array(a) => a.iter().for_each(|x| strings(x, key, out)),
            Value::Object(o) => {
                for (k, x) in o {
                    if !own_key(k) {
                        out.push_str(k);
                        out.push('\n');
                    }
                    strings(x, k, out);
                }
            }
            _ => {}
        }
    }
    match serde_json::from_slice::<Value>(data) {
        Ok(v) => {
            let mut out = String::new();
            strings(&v, "", &mut out);
            out
        }
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    }
}

/// [`Refused`] for the first of `files` holding a name `scan` knows. The
/// README is Pathwarden's own text, the same in every bundle, and
/// `system.json` this computer's version, OS and memory (an OU named
/// "Datacenter" is not in "Windows Server 2022 Datacenter"): not searched.
pub fn check(files: &[(String, Vec<u8>)], scan: &NameScan) -> Result<(), Refused> {
    check_except(files, scan, &HashSet::new())
}

/// [`check`] of every file, README too: what `evidence --redact` checks
/// its pack with (its README names the run).
pub fn check_all(files: &[(String, Vec<u8>)], scan: &NameScan) -> Result<(), Refused> {
    for (file, data) in files {
        if let Some(chars) = scan.find(&searched_text(data)) {
            return Err(Refused {
                file: file.clone(),
                chars,
            });
        }
    }
    Ok(())
}

/// [`check`], passing over the placeholders the bundle wrote.
fn check_except(
    files: &[(String, Vec<u8>)],
    scan: &NameScan,
    written: &HashSet<String>,
) -> Result<(), Refused> {
    for (file, data) in files
        .iter()
        .filter(|(f, _)| f != "README.txt" && f != "system.json")
    {
        if let Some(chars) = scan.find_except(&searched_text(data), written) {
            return Err(Refused {
                file: file.clone(),
                chars,
            });
        }
    }
    Ok(())
}

fn zip_files(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in files {
        // Writing to memory can't fail.
        let _ = zip.start_file(name.as_str(), opts);
        let _ = zip.write_all(data);
    }
    zip.finish().map(|c| c.into_inner()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timings(total: u64, read: u64) -> CollectionTimings {
        CollectionTimings {
            version: TIMINGS_VERSION,
            collector: "built-in".into(),
            total_ms: total,
            phases: vec![
                PhaseTime {
                    name: "connect".into(),
                    ms: 400,
                },
                PhaseTime {
                    name: "read".into(),
                    ms: read,
                },
                PhaseTime {
                    name: "parse".into(),
                    ms: 2000,
                },
            ],
            entries: 2500,
            peak_memory: vec![PhaseMemory {
                phase: "read".into(),
                bytes: 300 << 20,
            }],
            hosts: Some(HostSummary {
                computers: 12,
                tried: 10,
                reached: 7,
                failed: 2,
                timed_out: 1,
                errors: [("access denied".to_string(), 2)].into(),
                ..HostSummary::default()
            }),
            ..CollectionTimings::default()
        }
    }

    #[test]
    fn durations_read_like_the_log() {
        assert_eq!(duration(420), "0.42s");
        assert_eq!(duration(12_100), "12.1s");
        assert_eq!(duration(192_000), "3:12");
        assert_eq!(duration(3_723_000), "1:02:03");
        assert_eq!(bytes(1 << 30), "1.0 GB");
    }

    #[test]
    fn measures_compare_with_the_earlier_run() {
        let now = timings(100_000, 60_000);
        let first = measures(&now, None);
        assert!(first.iter().all(|m| m.change.is_none()));
        assert_eq!(first[0].value, "1:40");
        let then = timings(70_000, 60_500);
        let m = measures(&now, Some(&then));
        let get = |k| m.iter().find(|x| x.key == k).unwrap();
        assert_eq!(get("total").change.as_deref(), Some("30.0s slower"));
        assert_eq!(get("total").trend, Some(Trend::Worse));
        // Half a second on a minute is noise.
        assert_eq!(get("read").trend, Some(Trend::Same));
        assert_eq!(get("hosts_reached").value, "7 of 10");
        assert_eq!(get("hosts_reached").change.as_deref(), Some("no change"));
        assert!(m.iter().all(|x| !x.definition.is_empty()), "{m:?}");
        let mut better = then.clone();
        better.hosts.as_mut().unwrap().reached = 5;
        let m = measures(&now, Some(&better));
        let r = m.iter().find(|x| x.key == "hosts_reached").unwrap();
        assert_eq!(
            (r.change.as_deref(), r.trend),
            (Some("2 more"), Some(Trend::Better))
        );
        assert_eq!(
            error_line(now.hosts.as_ref().unwrap()).as_deref(),
            Some("access denied 2")
        );
    }

    #[test]
    fn timings_round_trip_and_tolerate_missing_fields() {
        let t = timings(1, 1);
        let text = serde_json::to_string(&t).unwrap();
        assert_eq!(CollectionTimings::parse(&text), Some(t));
        let old = CollectionTimings::parse("\u{feff}{\"total_ms\": 5}").unwrap();
        assert_eq!(old.total_ms, 5);
        assert!(CollectionTimings::parse("not json").is_none());
    }

    #[test]
    fn placeholders_replace_names_and_keep_own_words() {
        let mut ph = Placeholders::default();
        let mut v = json!({
            "tier_zero": {"zone": "Tier Zero", "exposure_grade": "Critical", "reason": {"text": "ALICE can reach it"}},
            "zones": [{"zone": "Finance servers"}],
            "completeness": [{"domain": "CONTOSO.LOCAL", "sessions_percent": 50.0}],
            "activity_unknown_domains": ["contoso.local", "child.contoso.local"],
            "exposure_grade": "<b>x</b>"
        });
        ph.scrub(&mut v);
        assert_eq!(v["tier_zero"]["zone"], "Tier Zero");
        assert_eq!(v["tier_zero"]["exposure_grade"], "Critical");
        assert_eq!(v["tier_zero"]["reason"]["text"], "text-1");
        assert_eq!(v["zones"][0]["zone"], "zone-1");
        assert_eq!(v["completeness"][0]["domain"], "domain-1");
        // The same name, whatever its case, gets the same placeholder.
        assert_eq!(v["activity_unknown_domains"][0], "domain-1");
        assert_eq!(v["activity_unknown_domains"][1], "domain-2");
        // An own key with something that isn't a word is still replaced.
        assert_eq!(v["exposure_grade"], "exposure_grade-1");
    }

    #[test]
    fn the_scan_finds_names_parts_and_sids() {
        let mut s = NameScan::default();
        s.add_name("ALICE.SMITH@CONTOSO.LOCAL");
        s.add_name("WS-114.CONTOSO.LOCAL");
        s.add_name("ADMINISTRATOR@CONTOSO.LOCAL");
        s.add_name("Finance \"Team\"");
        s.add_dn("CN=Bob Jones,OU=Payroll,DC=contoso,DC=local");
        s.add_sid("S-1-5-21-1-2-3-1104");
        assert_eq!(s.find("{\"x\": \"alice.smith\"}"), Some(11));
        assert!(s.find("contoso").is_some());
        assert!(s.find("host ws-114 was slow").is_some());
        assert!(s.find("BOB JONES").is_some());
        assert!(s.find("payroll").is_some());
        assert!(s.find("\"name\": \"Finance \\\"Team\\\"\"").is_some());
        assert!(s.find("S-1-5-21-1-2-3-500").is_some());
        // Words every domain has, and Pathwarden's own, identify nothing.
        assert_eq!(s.find("administrator read write local"), None);
        assert_eq!(s.find("domain-1 zone-2 0.42s"), None);
    }

    #[test]
    fn listed_names_are_found_whole_in_any_case() {
        let mut scan = NameScan::default();
        scan.add_listed("Administrator@Contoso.Local");
        scan.add_sid("S-1-5-21-1-2-3-500");
        let file = |text: &str| vec![("README.txt".to_string(), text.as_bytes().to_vec())];
        assert!(check_all(&file("x administrator@contoso.local y"), &scan).is_err());
        assert!(check_all(&file("{\"d\":\"CONTOSO.local\"}"), &scan).is_err());
        assert!(check_all(&file("object S-1-5-21-1-2-3-1104"), &scan).is_err());
        // The account's first part alone is prose, not the name.
        assert!(check_all(&file("the built-in Administrator account"), &scan).is_ok());
        assert!(check_all(&file("fabrikam.local"), &scan).is_ok());
    }

    #[test]
    fn keys_are_searched_unless_they_are_pathwardens() {
        let mut scan = NameScan::default();
        scan.add_dn("CN=Computers,DC=contoso,DC=local");
        scan.add_name("FINANCE-SRV@CONTOSO.LOCAL");
        let json = |v: Value| vec![("x.json".to_string(), serde_json::to_vec(&v).unwrap())];
        // Field names, rule IDs, severities and error kinds.
        let own = json!({
            "computers": 3,
            "errors": {"access denied": 1, "remote registry starting": 2},
            "PW-012": {"high": 1, "accepted": 2},
        });
        assert!(check(&json(own), &scan).is_ok());
        // A map keyed by a name.
        assert!(check(&json(json!({"errors": {"FINANCE-SRV": 1}})), &scan).is_err());
        assert!(check(&json(json!({"by_domain": {"contoso.local": 1}})), &scan).is_err());
    }

    #[test]
    fn a_run_without_settings_gets_its_collection_from_the_timings() {
        let b = Bundle {
            timings: Some(timings(1000, 500)),
            ..Bundle::default()
        };
        let files = b.files();
        let get = |name: &str| files.iter().find(|(f, _)| f == name).map(|(_, d)| d);
        let c: Value = serde_json::from_slice(get("collection.json").unwrap()).unwrap();
        assert_eq!(c["collector"], "built-in");
        assert_eq!(c["scope"], "all");
        assert_eq!(c["computers"]["reached"], 7);
        // The README lists what the bundle holds, and only that.
        let readme = String::from_utf8_lossy(get("README.txt").unwrap()).into_owned();
        assert!(readme.contains("collection.json"));
        assert!(!readme.contains("posture.json") && !readme.contains("timings-previous.json"));
        let none = Bundle::default().files();
        let readme = String::from_utf8_lossy(&none[0].1).into_owned();
        assert!(!none.iter().any(|(f, _)| f == "collection.json"));
        assert!(!readme.contains("collection.json") && readme.contains("run.json"));
    }

    #[test]
    fn a_bundle_holds_no_names_and_refuses_one() {
        let mut scan = NameScan::default();
        scan.add_name("ALICE@CONTOSO.LOCAL");
        let b = Bundle {
            system: SystemInfo {
                pathwarden: "0.1.4".into(),
                os: "Windows".into(),
                ..SystemInfo::default()
            },
            run: json!({"domains": ["CONTOSO.LOCAL"], "exposed": 3, "next_step": "Remove ALICE@CONTOSO.LOCAL"}),
            timings: Some(timings(1000, 500)),
            plan: Some(
                json!({"fixes": [{"from": "ALICE@CONTOSO.LOCAL", "from_kind": "User", "edges": ["MemberOf"], "cost": 1, "action": "ALICE"}], "total_cost": 1}),
            ),
            collection: Some(
                json!({"method": "builtin", "scope": "all", "domain": "CONTOSO.LOCAL"}),
            ),
            ..Bundle::default()
        };
        let zip = b.zip(&scan).expect("no name left");
        assert!(zip.starts_with(b"PK"));
        let files = b.files();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"timings.json") && names.contains(&"collection.json"));
        let plan = &files.iter().find(|(n, _)| n == "plan.json").unwrap().1;
        assert!(!String::from_utf8_lossy(plan).contains("action"));
        // A name the placeholders can't catch (a collector that wrote one
        // into the timings) stops it.
        let mut leaky = b;
        leaky.timings.as_mut().unwrap().naming_contexts = vec![NamingContextTime {
            kind: "ALICE".into(),
            ..NamingContextTime::default()
        }];
        let err = leaky.zip(&scan).unwrap_err();
        assert_eq!(err.file, "timings.json");
        assert!(err.to_string().contains("5 characters"), "{err}");
    }

    /// What a real domain may well have: an OU named like a word of the
    /// timing lines or the OS, an account named like one, and an object
    /// named like a placeholder. None of them is in the bundle, so it is
    /// made.
    #[test]
    fn common_words_and_placeholder_names_dont_refuse_a_bundle() {
        let mut scan = NameScan::default();
        scan.add_dn("OU=DATACENTER,DC=contoso,DC=local");
        scan.add_name("COUNT@CONTOSO.LOCAL");
        scan.add_name("KEPT@CONTOSO.LOCAL");
        scan.add_name("DOMAIN-1@CONTOSO.LOCAL");
        let mut t = timings(1000, 500);
        t.summary = Some("Timing: 1.00s in all".into());
        t.details = vec![
            "[timing] naming context 1 (domain): 2,500 entries (kept 2,400)".into(),
            "[timing] sizing count: 0.20s (finished before the read)".into(),
        ];
        let b = Bundle {
            system: SystemInfo {
                pathwarden: "0.1.4".into(),
                os: "Windows Server 2022 Datacenter (build 20348)".into(),
                ..SystemInfo::default()
            },
            run: json!({"domains": ["CONTOSO.LOCAL"]}),
            timings: Some(t),
            ..Bundle::default()
        };
        let zip = b.zip(&scan).expect("nothing of the run in it");
        assert!(zip.starts_with(b"PK"));
        let files = b.files();
        let timings = &files.iter().find(|(n, _)| n == "timings.json").unwrap().1;
        let text = String::from_utf8_lossy(timings);
        assert!(
            !text.contains("[timing]") && !text.contains("Timing:"),
            "{text}"
        );
        // The placeholder the bundle wrote is passed over, the name itself
        // is not: a raw DOMAIN-1 anywhere else is still found.
        let run = &files.iter().find(|(n, _)| n == "run.json").unwrap().1;
        assert!(String::from_utf8_lossy(run).contains("domain-1"));
        assert!(scan.find("domain-1").is_some());
    }

    /// A domain with an OU named after an object kind (`Group`) and
    /// one named after an edge kind (`Owns`) still gets a bundle: the
    /// plan's kinds are fixed vocabulary. A kind the plan doesn't know is
    /// written as `External`, and a name in a free-text field still stops
    /// the bundle.
    #[test]
    fn ous_named_like_kinds_dont_refuse_a_bundle() {
        let mut scan = NameScan::default();
        scan.add_dn("OU=Group,DC=contoso,DC=local");
        scan.add_dn("OU=Owns,DC=contoso,DC=local");
        scan.add_dn("OU=Payroll,DC=contoso,DC=local");
        scan.add_name("ALICE@CONTOSO.LOCAL");
        let b = Bundle {
            run: json!({"domains": ["CONTOSO.LOCAL"]}),
            timings: Some(timings(1000, 500)),
            plan: Some(json!({"fixes": [
                {"from_kind": "Group", "to_kind": "OU", "edges": ["Owns", "GenericAll"], "cost": 1},
                {"from_kind": "ALICE", "to_kind": "TH_ScheduledTask", "edges": ["Payroll"], "cost": 2},
            ], "total_cost": 3})),
            ..Bundle::default()
        };
        assert!(b.zip(&scan).expect("kinds aren't names").starts_with(b"PK"));
        let files = b.files();
        let plan: Value =
            serde_json::from_slice(&files.iter().find(|(n, _)| n == "plan.json").unwrap().1)
                .unwrap();
        let f = &plan["fixes"];
        assert_eq!(f[0]["from_kind"], "Group");
        assert_eq!(f[0]["edges"], json!(["Owns", "GenericAll"]));
        assert_eq!(f[1]["from_kind"], "External");
        assert_eq!(f[1]["to_kind"], "External");
        assert_eq!(f[1]["edges"], json!(["External"]));
        // Kind words alone are Pathwarden's, wherever they are.
        assert_eq!(scan.find("group owns memberof"), None);
        // A real name in a free-text field is still found.
        let mut leaky = b;
        leaky.timings.as_mut().unwrap().naming_contexts = vec![NamingContextTime {
            kind: "Payroll".into(),
            ..NamingContextTime::default()
        }];
        let err = leaky.zip(&scan).unwrap_err();
        assert_eq!((err.file.as_str(), err.chars), ("timings.json", 7));
        // A kind field holding anything but a kind is searched.
        let file = |v: Value| vec![("plan.json".to_string(), serde_json::to_vec(&v).unwrap())];
        assert!(check(&file(json!({"from_kind": "Payroll"})), &scan).is_err());
        assert!(check(
            &file(json!({"from_kind": "Group", "edges": ["Owns"]})),
            &scan
        )
        .is_ok());
    }

    #[test]
    fn whole_account_names_are_found_through_their_parts() {
        let mut s = NameScan::default();
        s.add_name("ALICE SMITH@CONTOSO.LOCAL");
        assert!(s.find("alice smith@contoso.local").is_some());
        assert!(s.find("x alice smith y").is_some());
        assert!(s.find("x contoso y").is_some());
        // Not a phrase of its own: its parts are.
        assert!(
            !s.phrases.iter().any(|p| p.contains('@')),
            "{:?}",
            s.phrases
        );
    }

    #[test]
    fn timings_combine_and_compare_by_collection() {
        let a = timings(10_000, 6_000);
        let mut b = timings(5_000, 2_000);
        b.peak_memory[0].bytes = 900 << 20;
        let all = CollectionTimings::combine(vec![a.clone(), b]).unwrap();
        assert_eq!(all.total_ms, 15_000);
        assert_eq!(all.phase("read"), Some(8_000));
        assert_eq!(all.entries, 5000);
        assert_eq!(all.peak(), Some(900 << 20));
        let h = all.hosts.as_ref().unwrap();
        assert_eq!((h.tried, h.reached, h.errors["access denied"]), (20, 14, 4));
        assert_eq!(CollectionTimings::combine(vec![a.clone()]), Some(a.clone()));
        assert_eq!(CollectionTimings::combine(Vec::new()), None);

        // Built-in with computers is "all"; directory only isn't compared
        // with it, nor is SharpHound.
        assert_eq!(a.kind_words(), "built-in, all");
        let mut dc = a.clone();
        dc.hosts = None;
        dc.scope = Some("dc-only".into());
        assert!(!a.same_collection(&dc));
        let mut sh = a.clone();
        sh.collector = "SharpHound".into();
        assert!(!a.same_collection(&sh));
        let mut old = a.clone();
        old.scope = None;
        assert!(a.same_collection(&old));
    }

    #[test]
    fn collect_leaves_timings_that_run_finds() {
        let dir = std::env::temp_dir().join(format!("pw-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (one, two) = (dir.join("a.local"), dir.join("b.local"));
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let collect = |d: &Path, total: u64| {
            let f = d.join("collection.zip");
            std::fs::write(&f, b"zip").unwrap();
            write_sidecar(d, &timings(total, 500), &[f]).unwrap();
        };
        let found = |d: &Path| collected_timings(&[d.to_path_buf()]).map(|f| f.timings.total_ms);
        assert_eq!(found(&dir), None);
        collect(&one, 1000);
        // One folder: its own.
        assert_eq!(found(&one), Some(1000));
        // A folder of two domains, one not collected by Pathwarden: none.
        std::fs::write(two.join("other.zip"), b"zip").unwrap();
        assert_eq!(found(&dir), None);
        // A schedule of two domains: both, as one.
        std::fs::remove_file(two.join("other.zip")).unwrap();
        collect(&two, 2000);
        assert_eq!(found(&dir), Some(3000));
        // A zip added later, or a file changed: not that collection.
        std::fs::write(one.join("later.zip"), b"zip").unwrap();
        assert_eq!(found(&one), None);
        assert_eq!(found(&dir), None);
        std::fs::remove_file(one.join("later.zip")).unwrap();
        std::fs::write(two.join("collection.zip"), b"changed").unwrap();
        assert_eq!(found(&two), None);
        collect(&two, 2000);
        // Recorded once: analyzing the folder again finds none.
        let all = collected_timings(std::slice::from_ref(&dir)).unwrap();
        all.mark_recorded();
        assert_eq!(found(&dir), None);
        assert_eq!(found(&one), None);
        assert!(one.join(RECORDED_SIDECAR_FILE).is_file());
        // A file beside the folder isn't described.
        collect(&one, 1000);
        let zip = dir.join("x.zip");
        std::fs::write(&zip, b"zip").unwrap();
        assert_eq!(collected_timings(&[one.clone(), zip]), None);
        // The input readers take .json and .zip only.
        for name in [SIDECAR_FILE, RECORDED_SIDECAR_FILE] {
            assert!(!name.ends_with(".json") && !name.ends_with(".zip"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A domain of 500,000 objects: names with spaces, DNs, SIDs. Run with
    /// `cargo test -p pathwarden-core --release -- --ignored scan_of_a_large`.
    #[test]
    #[ignore = "a benchmark: 500,000 objects"]
    fn scan_of_a_large_domain_is_quick() {
        use crate::object_index::{IndexedObject, ObjectIndex};
        let objects = (0..500_000)
            .map(|i| {
                IndexedObject(
                    format!("S-1-5-21-1-2-3-{}", 1000 + i),
                    format!("FIRST{i} LAST{i}@CONTOSO.LOCAL"),
                    0,
                    0,
                    format!(
                        "CN=First{i} Last{i},OU=Team {},DC=contoso,DC=local",
                        i % 500
                    ),
                    0,
                )
            })
            .collect();
        let index = ObjectIndex {
            domains: vec!["CONTOSO.LOCAL".into()],
            objects,
            ..ObjectIndex::default()
        };
        let started = std::time::Instant::now();
        let mut scan = NameScan::default();
        scan.add_index(&index);
        let b = Bundle {
            run: json!({"domains": ["CONTOSO.LOCAL"], "objects": 500_000}),
            timings: Some(timings(1000, 500)),
            previous: Some(timings(900, 500)),
            plan: Some(json!({"fixes": [{"from_kind": "User", "edges": ["MemberOf"], "cost": 1}]})),
            collection: Some(
                json!({"method": "builtin", "scope": "all", "domain": "CONTOSO.LOCAL"}),
            ),
            ..Bundle::default()
        };
        b.zip(&scan).expect("no name in it");
        let took = started.elapsed();
        eprintln!("{} names, bundle in {took:?}", scan.len());
        assert!(took < std::time::Duration::from_secs(20), "{took:?}");
    }

    /// The logs in a bundle: every name of the run replaced as in the
    /// rest of it (the same placeholder for the same name), names that
    /// look like names replaced too, and the search covers them.
    #[test]
    fn logs_in_a_bundle_hold_no_names() {
        let mut scan = NameScan::default();
        scan.add_name("ALICE@CONTOSO.LOCAL");
        scan.add_name("WS01.CONTOSO.LOCAL");
        scan.add_text("Alice Smith");
        scan.add_sid("S-1-5-21-1-2-3-1104");
        let log = "# Collection CONTOSO.LOCAL | app | collect | Pathwarden 1.0\n\
            09:42:11.204 [collect, app] Collection CONTOSO.LOCAL started in the app\n\
            09:42:11.390 [collect, app] domain controller dc01.fabrikam.test (chosen)\n\
            09:42:12.018 [collect, app] LAPS: readable on ws01 and WS01.contoso.local, by Alice Smith\n\
            09:42:13.000 [collect, app] bob@fabrikam.test owns CN=Bob Jones,OU=Finance,DC=fabrikam,DC=test\n\
            09:42:14.000 [collect, app] S-1-5-21-1-2-3-1104 and S-1-5-21-9-8-7-500\n\
            09:42:15.000 [collect, app] kept in C:\\Users\\jdoe\\AppData\\Local\\Pathwarden\\uploads\\x.json\n\
            09:42:16.000 [collect, app] Pathwarden 1.0.0-rc.2 wrote objects.json.gz, e.g. 12.5 MB\n";
        let b = Bundle {
            run: json!({"domains": ["CONTOSO.LOCAL"]}),
            logs: vec![("job-20261119-094211-collect.log".into(), log.into())],
            ..Bundle::default()
        };
        let zip = b.zip(&scan).expect("no name left");
        assert!(zip.starts_with(b"PK"));
        let (files, _) = b.files_and_placeholders(&scan);
        let text = |n: &str| {
            String::from_utf8_lossy(&files.iter().find(|(f, _)| f == n).unwrap().1).into_owned()
        };
        let out = text("logs/job-20261119-094211-collect.log");
        for name in [
            "CONTOSO",
            "contoso",
            "ws01",
            "WS01",
            "Alice",
            "fabrikam",
            "bob",
            "Bob Jones",
            "Finance",
            "S-1-5-21-1-2-3",
            "S-1-5-21-9-8-7",
            "jdoe",
        ] {
            assert!(!out.contains(name), "{name} in:\n{out}");
        }
        let run = text("run.json");
        assert!(
            run.contains("domain-1") && out.contains("Collection domain-1 started"),
            "{out}"
        );
        assert!(
            out.contains("1.0.0-rc.2 wrote objects.json.gz, e.g. 12.5 MB"),
            "{out}"
        );
        assert!(out.contains("sid-1-1104"), "{out}");
        assert!(text("README.txt").contains("logs/"));
        // The search covers the logs: a name left in one refuses the bundle.
        let leaky = vec![("logs/x.log".to_string(), b"seen on ALICE today".to_vec())];
        assert_eq!(check(&leaky, &scan).unwrap_err().file, "logs/x.log");
    }

    /// A computer's account name (`WS01$`), and a path as JSON writes it,
    /// are replaced too; the check finds `WS01$` when it is left.
    #[test]
    fn account_names_and_escaped_paths_are_replaced() {
        let mut scan = NameScan::default();
        scan.add_name("WS01.CONTOSO.LOCAL");
        let mut ph = Placeholders::default();
        let out = replace_names(
            r#"machine WS01$ read; {"path":"C:\\Users\\jdoe\\x.json"} C:\Users\ann\y"#,
            &scan,
            &mut ph,
        );
        assert!(!out.contains("WS01") && out.contains("name-1$"), "{out}");
        assert!(!out.contains("jdoe") && !out.contains("ann"), "{out}");
        assert_eq!(scan.find("seen WS01$ today"), Some(4));
    }
}
