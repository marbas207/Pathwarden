//! Who reaches Tier Zero, account by account: the name-free keys
//! each run keeps in the history, and the lists each run keeps with itself.
//!
//! # The keys in the history
//!
//! Each run writes `exposed/<run>.json` into the history ([`DIR`]), beside
//! its point: the keys of the enabled users and computers outside Tier
//! Zero with an attack path to it. A key is the name-free object key the
//! findings state already keeps ([`key`], the same FNV-1a 64 of the
//! upper-cased object ID as [`crate::introduced::object_key`]), so the
//! file names nobody. It is encrypted and bound like every other history
//! file ([`crate::store`], [`crate::binding`]).
//!
//! ```json
//! {
//!   "version": 1,
//!   "run_id": "20261028T020000.000Z",
//!   "key": "object-id-fnv1a64",
//!   "basis": 2,
//!   "sets": {
//!     "Tier Zero": {
//!       "count": 3,
//!       "buckets": { "1f": "gIC4Bf8B", "a0": "AQ==" }
//!     }
//!   }
//! }
//! ```
//!
//! - `version` ([`VERSION`]): a newer one is not read ([`Why::NewerFormat`]).
//! - `key`: how the keys were made ([`KEY_KIND`]).
//! - `basis`: the run's exposure basis ([`crate::analysis::EXPOSURE_BASIS`]).
//! - `sets`: by what the accounts reach; only Tier Zero for now
//!   ([`TIER_ZERO`]). Privilege Zones can follow under their names.
//! - `count`: how many keys the set holds. It must match the keys decoded
//!   and the point's `tier_zero_exposed`, or the file is not used.
//! - `buckets`: the keys by their top byte (two hex digits). Each bucket
//!   holds the low 56 bits of its keys, sorted, as the differences from
//!   one to the next (the first from 0) in unsigned LEB128, in base64. A
//!   run that adds or drops a few accounts changes a few buckets, so a git
//!   history stores little for it (unencrypted).
//!
//! The keys are an unsalted FNV-1a hash of each object ID: name-free, but
//! pseudonymous. Anyone holding a list of the domain's SIDs or GUIDs can
//! hash them and tell which accounts a run counted (the threat model says
//! so; the findings state's object keys are the same).
//!
//! The history keeps the files of the latest [`KEPT`] runs of each
//! environment, and of its latest run of each kind (a Quick and a Full
//! run) and the runs those compare with, so the next run of either kind
//! has its previous run's keys
//! ([`crate::store::Store::prune_exposed`]).
//!
//! # The lists with each run
//!
//! [`ExposureLists`] (`exposed.json.gz` in the run's folder and its full
//! run, [`FILE`]) are made from the analysis while its graph is loaded:
//! for each remediation step, the accounts it cuts off with their paths;
//! and against the previous run's keys, the accounts that now reach Tier
//! Zero and those that no longer do. Each run keeps its own, so dropping
//! old keys never changes what an old run shows.
//!
//! # An earlier run without keys
//!
//! A previous run with no keys file (recorded before 0.2, or its keys
//! pruned) that has a full run in the history (`runs/<run>/`, with
//! `graph.bin.gz` and `objects.json.gz`) is read back from it
//! ([`EarlierRun`]): its graph says who reached Tier Zero then, and the set
//! is used only when its count matches the run's point. Whenever the
//! earlier graph is there, an account that no longer reaches Tier Zero also
//! gets its path from then, and one no longer in the directory its name.
//! The full run is read only while the lists are made (an analysis, never a
//! page), only when they need it, and the last one read is kept
//! ([`earlier_run`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use petgraph::graph::{EdgeIndex, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::graph::AdGraph;
use crate::history::ReportHistory;
use crate::model::NodeKind;
use crate::remediation::RemediationPlan;
use crate::state::{CompletenessPoint, HistoryPoint};

/// The history folder of the keys: `exposed/<run>.json`.
pub const DIR: &str = "exposed";

/// The lists' file in a run's folder and full run.
pub const FILE: &str = "exposed.json.gz";

/// The keys' file format this Pathwarden writes and reads.
pub const VERSION: u32 = 1;

/// How the keys are made: [`key`].
pub const KEY_KIND: &str = "object-id-fnv1a64";

/// The set of accounts with a path to Tier Zero.
pub const TIER_ZERO: &str = crate::introduced::TIER_ZERO;

/// The lists' file format.
pub const LISTS_VERSION: u32 = 1;

/// How many of each environment's latest runs keep their keys, besides its
/// latest run of each kind.
pub const KEPT: usize = 10;

/// Accounts the run page and the report list per step at most; `runs show
/// --json` lists every one.
pub const LISTED: usize = 1_000;

/// An account that now reaches Tier Zero through no step of the plan: what
/// the report, the app and `runs show` say in place of its step.
pub const NO_STEP: &str = "No step cuts it";

/// Accounts a report lists across all its steps at most: past it, later
/// steps list fewer, or none ([`ExposureLists::listed_per_step`]).
pub const LISTED_TOTAL: usize = 20_000;

/// What a step's list says when it is cut at [`LISTED`].
pub const LISTED_WORDS: &str = "The first 1,000 are listed: new ones first, then the closest.";

/// What a step's list says when it lists only its first `n` accounts
/// ([`LISTED_WORDS`] for 1,000).
pub fn listed_words(n: usize) -> String {
    if n == 0 {
        "None are listed.".to_string()
    } else {
        format!(
            "The first {} are listed: new ones first, then the closest.",
            crate::text::num(n)
        )
    }
}

/// The name-free key of an object (its SID or GUID): FNV-1a 64 of "o", a
/// zero byte, the upper-cased ID and a zero byte. The findings state keeps
/// the same key as 16 hex digits ([`crate::introduced::object_key`]).
pub fn key(id: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let id = id.trim().to_ascii_uppercase();
    for part in ["o", id.as_str()] {
        for b in part.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

// ------------------------------------------------------------- the keys

/// One run's keys file ([module docs](self)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedRecord {
    pub version: u32,
    pub run_id: String,
    /// [`KEY_KIND`].
    pub key: String,
    /// The run's exposure basis.
    pub basis: u8,
    /// By what the accounts reach ([`TIER_ZERO`]).
    pub sets: BTreeMap<String, KeySet>,
}

/// One set of keys, bucketed ([module docs](self)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySet {
    pub count: usize,
    pub buckets: BTreeMap<String, String>,
}

impl KeySet {
    /// The set of `keys` (duplicates count once).
    pub fn new(keys: impl IntoIterator<Item = u64>) -> Self {
        let mut keys: Vec<u64> = keys.into_iter().collect();
        keys.sort_unstable();
        keys.dedup();
        let mut buckets = BTreeMap::new();
        for chunk in keys.chunk_by(|a, b| a >> 56 == b >> 56) {
            let mut bytes = Vec::with_capacity(chunk.len() * 8);
            let mut last = 0u64;
            for &k in chunk {
                let low = k & LOW;
                leb128(&mut bytes, low - last);
                last = low;
            }
            buckets.insert(format!("{:02x}", chunk[0] >> 56), base64(&bytes));
        }
        KeySet {
            count: keys.len(),
            buckets,
        }
    }

    /// The keys, sorted; `None` when the set is damaged (a bucket that
    /// doesn't decode, keys out of order, or a count that doesn't match).
    pub fn keys(&self) -> Option<Vec<u64>> {
        let mut out = Vec::with_capacity(self.count.min(1 << 24));
        for (top, text) in &self.buckets {
            if top.len() != 2 || top.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            let top = u64::from_str_radix(top, 16).ok()? << 56;
            let bytes = unbase64(text)?;
            let mut at = 0;
            let mut low = 0u64;
            let mut first = true;
            while at < bytes.len() {
                let d = read_leb128(&bytes, &mut at)?;
                if !first && d == 0 {
                    return None;
                }
                first = false;
                low = low.checked_add(d)?;
                if low > LOW {
                    return None;
                }
                out.push(top | low);
                if out.len() > self.count {
                    return None;
                }
            }
        }
        (out.len() == self.count).then_some(out)
    }
}

/// The low 56 bits of a key.
const LOW: u64 = (1 << 56) - 1;

impl ExposedRecord {
    /// Run `run_id`'s record of `tier_zero` keys, on exposure basis `basis`.
    pub fn new(run_id: &str, basis: u8, tier_zero: impl IntoIterator<Item = u64>) -> Self {
        ExposedRecord {
            version: VERSION,
            run_id: run_id.to_string(),
            key: KEY_KIND.to_string(),
            basis,
            sets: BTreeMap::from([(TIER_ZERO.to_string(), KeySet::new(tier_zero))]),
        }
    }

    /// The record of the accounts the Tier Zero `plan` found exposed in
    /// `g`; `None` for a plan without its accounts.
    pub fn from_plan(run_id: &str, basis: u8, g: &AdGraph, plan: &RemediationPlan) -> Option<Self> {
        let detail = plan.detail.as_ref()?;
        Some(Self::new(
            run_id,
            basis,
            detail.exposed.iter().map(|&ix| key(&g.node(ix).id)),
        ))
    }

    /// The file's bytes: JSON, one bucket a line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = serde_json::to_string_pretty(self).expect("a record serializes");
        text.push('\n');
        text.into_bytes()
    }

    /// Reads a keys file: [`Why::NewerFormat`] for a newer version,
    /// [`Why::Unreadable`] for anything else that isn't one.
    pub fn parse(bytes: &[u8]) -> Result<Self, Why> {
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Why::Unreadable)?;
        if !crate::formats::of_json(&v, "version", VERSION).is_known() {
            return Err(Why::NewerFormat);
        }
        let r: ExposedRecord = serde_json::from_value(v).map_err(|_| Why::Unreadable)?;
        if r.version == 0 || r.key != KEY_KIND {
            return Err(Why::Unreadable);
        }
        Ok(r)
    }

    /// The Tier Zero keys, sorted, when they match `point` (the run, its
    /// basis and its count of exposed accounts); otherwise why not.
    pub fn tier_zero_for(&self, point: &HistoryPoint) -> Result<Vec<u64>, Why> {
        let set = self.sets.get(TIER_ZERO).ok_or(Why::Unreadable)?;
        if self.run_id != point.run_id
            || self.basis != point.basis()
            || set.count != point.tier_zero_exposed
        {
            return Err(Why::Unreadable);
        }
        set.keys().ok_or(Why::Unreadable)
    }
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn read_leb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *bytes.get(*at)?;
        *at += 1;
        let part = u64::from(b & 0x7f);
        if shift == 63 && part > 1 {
            return None;
        }
        v |= part << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, padded.
fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn unbase64(text: &str) -> Option<Vec<u8>> {
    let t = text.as_bytes();
    if !t.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 4 * 3);
    for (i, c) in t.chunks(4).enumerate() {
        let last = i + 1 == t.len() / 4;
        let pad = c.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &b in &c[..4 - pad] {
            let v = B64.iter().position(|&x| x == b)? as u32;
            n = n << 6 | v;
        }
        n <<= 6 * pad as u32;
        let got = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&got[..3 - pad]);
    }
    Some(out)
}

/// The runs of `points` whose keys the history keeps: in each environment
/// (its collected domains), the latest [`KEPT`], and the latest of each
/// kind (what it targeted, on which exposure basis): a Quick and a Full
/// run, and the run each of those compares with. By run ID.
pub fn kept_runs(points: &[HistoryPoint]) -> HashSet<String> {
    let mut envs: BTreeMap<&[String], Vec<&HistoryPoint>> = BTreeMap::new();
    for p in points {
        envs.entry(p.scopes.as_slice()).or_default().push(p);
    }
    let mut keep = HashSet::new();
    for (_, mut runs) in envs {
        runs.sort_by(|a, b| (b.at, &b.run_id).cmp(&(a.at, &a.run_id)));
        keep.extend(runs.iter().take(KEPT).map(|p| p.run_id.clone()));
        // Oldest first, as `since::previous` reads them.
        let oldest_first: Vec<HistoryPoint> = runs.iter().rev().map(|&p| p.clone()).collect();
        // A run added after a newer one is never compared with.
        let mut kinds = Vec::new();
        for p in runs.into_iter().filter(|p| !p.inserted) {
            let kind = (p.basis(), crate::since::targeting(p.completeness.as_ref()));
            if !kinds.contains(&kind) {
                kinds.push(kind);
                keep.insert(p.run_id.clone());
                // And the run it compares with: a weekly Full run keeps the
                // last Full run's keys past ten Quick runs between them.
                if let Some(before) = crate::since::previous(&oldest_first, p) {
                    keep.insert(before.run_id.clone());
                }
            }
        }
    }
    keep
}

// ------------------------------------------------ the previous run's keys

/// Why the accounts can't be compared with the previous run's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Why {
    /// The previous run kept no keys (recorded before 0.2, or imported):
    /// nothing is said about it.
    NoKeys,
    /// Its keys are no longer kept ([`KEPT`]).
    NotKept,
    /// It read other data: a Quick run beside a Full one, or another
    /// exposure basis.
    NotComparable,
    /// A newer Pathwarden wrote its keys.
    NewerFormat,
    /// Its keys can't be read, or don't match its point.
    Unreadable,
}

impl Why {
    pub fn key(self) -> &'static str {
        match self {
            Why::NoKeys => "no-keys",
            Why::NotKept => "not-kept",
            Why::NotComparable => "not-comparable",
            Why::NewerFormat => "newer-format",
            Why::Unreadable => "unreadable",
        }
    }

    /// One short sentence; `None` for [`Why::NoKeys`], which says
    /// nothing.
    pub fn sentence(self) -> Option<&'static str> {
        match self {
            Why::NoKeys => None,
            Why::NotKept => {
                Some("Which accounts are new isn't known: the last run's accounts are no longer kept.")
            }
            Why::NotComparable => {
                Some("Which accounts are new isn't known: the last run read other data.")
            }
            Why::NewerFormat => Some(
                "Which accounts are new isn't known: a newer Pathwarden recorded the last run's accounts.",
            ),
            Why::Unreadable => {
                Some("Which accounts are new isn't known: the last run's accounts can't be read.")
            }
        }
    }
}

/// The previous run's accounts, for "New" marks and what changed.
#[derive(Debug, Clone)]
pub struct PreviousExposed {
    pub run_id: String,
    pub at: i64,
    /// Its keys, sorted; or why they can't be used.
    pub keys: Result<Vec<u64>, Why>,
    /// The keys came from its full run's graph, not a keys file.
    pub from_full_run: bool,
    /// Its graph, from its full run in the history: read when first asked
    /// for ([`PreviousExposed::earlier`]).
    earlier: OnceLock<Option<Arc<EarlierRun>>>,
    /// The history folder its full run is read from, and what its point
    /// says the graph may hold.
    full_run_in: Option<(PathBuf, Limits)>,
}

/// How many objects a previous run's graph may hold, from its point: at
/// least its population (enabled users and computers outside Tier Zero),
/// at most [`Limits::PER_COUNTED`] times what it counted, and some; or, when
/// its full run's summary says how many objects it collected, what that
/// allows if more ([`Limits::with_collected`]: OpenGraph data and the
/// groups, OUs and disabled accounts the point doesn't count). Its edges
/// are bounded by its objects ([`crate::explore::edge_budget`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min_objects: usize,
    pub max_objects: usize,
}

impl Limits {
    /// Objects a graph may hold per user, computer and Tier Zero object the
    /// point counted: groups, OUs, GPOs, containers and the rest.
    pub const PER_COUNTED: usize = 16;
    /// And this many more, for a graph that counted few.
    pub const SLACK: usize = 100_000;

    /// The limits of run `point`'s graph.
    pub fn of(point: &HistoryPoint) -> Self {
        let counted = point
            .tier_zero_population
            .saturating_add(point.tier_zero_objects);
        Limits {
            min_objects: point.tier_zero_population,
            max_objects: counted
                .saturating_mul(Self::PER_COUNTED)
                .saturating_add(Self::SLACK),
        }
    }

    /// Widened to what a run that collected `objects` objects may hold
    /// ([`crate::explore::Bounds::of_collected`]), when that is more.
    pub fn with_collected(self, objects: usize) -> Self {
        Limits {
            max_objects: self
                .max_objects
                .max(crate::explore::Bounds::of_collected(objects).max_objects),
            ..self
        }
    }

    /// No limits but the files' own (a graph made here, in tests).
    pub const ANY: Limits = Limits {
        min_objects: crate::explore::Bounds::ANY.min_objects,
        max_objects: crate::explore::Bounds::ANY.max_objects,
    };

    fn bounds(self) -> crate::explore::Bounds {
        crate::explore::Bounds {
            min_objects: self.min_objects,
            max_objects: self.max_objects,
        }
    }
}

impl PreviousExposed {
    /// Run `run_id`'s accounts (recorded at `at`), without its graph.
    pub fn new(run_id: &str, at: i64, keys: Result<Vec<u64>, Why>) -> Self {
        PreviousExposed {
            run_id: run_id.to_string(),
            at,
            keys,
            from_full_run: false,
            earlier: OnceLock::new(),
            full_run_in: None,
        }
    }

    /// With its graph already read (`None`: it has none).
    pub fn with_earlier(mut self, earlier: Option<Arc<EarlierRun>>) -> Self {
        self.earlier = OnceLock::from(earlier);
        self
    }

    /// With its graph read, when first asked for, from its full run in the
    /// history in `state_dir`, within what its point says (`limits`).
    fn with_full_run_in(mut self, state_dir: &Path, limits: Limits) -> Self {
        self.full_run_in = Some((state_dir.to_path_buf(), limits));
        self
    }

    /// Its graph, from its full run, read the first time it is asked for;
    /// `None` without one, or when it can't be read.
    pub fn earlier(&self) -> Option<&Arc<EarlierRun>> {
        self.earlier
            .get_or_init(|| {
                let (dir, limits) = self.full_run_in.as_ref()?;
                earlier_run(dir, &self.run_id, *limits).ok().flatten()
            })
            .as_ref()
    }
}

/// The files of a full run its graph is read from.
const FULL_RUN_GRAPH: &str = "graph.bin.gz";
const FULL_RUN_OBJECTS: &str = "objects.json.gz";

/// The most a full run's file is inflated to here, whatever else allows.
const MAX_INFLATED: u64 = 1 << 30;

/// Real full-run files inflate 4 to 14 times (the demo's graph 7, its
/// object index 7): a file may inflate to this many times its size on
/// disk, ...
const INFLATE_RATIO: u64 = 32;
/// ... or this much, whichever is more, ...
const INFLATE_FLOOR: u64 = 8 << 20;
/// ... and to no more than this per object its point allows.
const INFLATE_PER_OBJECT: u64 = 1024;

/// The most a full-run file `on_disk` bytes long may inflate to, for a
/// graph within `limits`.
fn inflate_cap(on_disk: u64, limits: Limits) -> u64 {
    (on_disk.saturating_mul(INFLATE_RATIO))
        .max(INFLATE_FLOOR)
        .min((limits.max_objects as u64).saturating_mul(INFLATE_PER_OBJECT))
        .min(MAX_INFLATED)
}

/// The largest file any full run in the history holds, whatever its
/// manifest says ([`crate::config::MAX_FULL_RUN_FILE_MB`]; the app's
/// `shared_runs::MAX_FILE_BYTES`, held to it by a test).
pub const MAX_FULL_RUN_FILE: u64 = crate::config::MAX_FULL_RUN_FILE_MB * 1024 * 1024;

/// The limit a full run's files were held to before its `run.json`
/// recorded its own (`max_file_bytes`): 45 MB.
pub const LEGACY_FULL_RUN_FILE: u64 = 45 * 1024 * 1024;

/// The most a full run's `run.json` takes (the app's
/// `shared_runs::MAX_MANIFEST_BYTES`).
const MAX_FULL_RUN_MANIFEST: u64 = 1 << 20;

/// The most full run `run_id`'s graph and object index may each be, in
/// plain bytes: no more than the size its `run.json` lists, nor than the
/// limit it was written under (`max_file_bytes`, at most
/// [`MAX_FULL_RUN_FILE`]; [`LEGACY_FULL_RUN_FILE`] when it records none,
/// or has no `run.json` that can be read).
fn full_run_sizes(state_dir: &Path, run_id: &str) -> [u64; 2] {
    #[derive(Deserialize)]
    struct Entry {
        name: String,
        bytes: u64,
    }
    #[derive(Deserialize)]
    struct Manifest {
        #[serde(default)]
        max_file_bytes: Option<u64>,
        #[serde(default)]
        files: Vec<Entry>,
    }
    let rel = crate::store::bundle_rel(run_id, "run.json");
    let encrypted = crate::crypt::is_encrypted(state_dir);
    let manifest = std::fs::symlink_metadata(crate::store::on_disk(state_dir, &rel, encrypted))
        .ok()
        .filter(|m| m.is_file() && m.len() <= crate::store::max_on_disk(MAX_FULL_RUN_MANIFEST))
        .and_then(|_| {
            crate::store::read_state_file(state_dir, &rel)
                .ok()
                .flatten()
        })
        .filter(|b| b.len() as u64 <= MAX_FULL_RUN_MANIFEST)
        .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok());
    let limit = manifest
        .as_ref()
        .and_then(|m| m.max_file_bytes)
        .unwrap_or(LEGACY_FULL_RUN_FILE)
        .min(MAX_FULL_RUN_FILE);
    [FULL_RUN_GRAPH, FULL_RUN_OBJECTS].map(|name| {
        manifest
            .as_ref()
            .and_then(|m| m.files.iter().find(|e| e.name == name))
            .map_or(limit, |e| e.bytes.min(limit))
    })
}

/// A previous run's graph, read back from its full run: who reached Tier
/// Zero then (by key) and by which path, and the objects' names.
pub struct EarlierRun {
    pub run_id: String,
    /// The accounts with a path to Tier Zero then: key and object, sorted.
    exposed: Vec<(u64, u32)>,
    names: Vec<String>,
    kinds: Vec<NodeKind>,
    /// The shortest paths to Tier Zero then.
    tree: crate::explore::PathTree,
}

impl std::fmt::Debug for EarlierRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EarlierRun")
            .field("run_id", &self.run_id)
            .field("objects", &self.names.len())
            .field("exposed", &self.exposed.len())
            .finish()
    }
}

impl EarlierRun {
    /// The run's graph from its full run's files, inflated: the graph
    /// ([`crate::explore`]) and its object index.
    pub fn from_files(run_id: &str, graph: &[u8], objects: &[u8]) -> Result<Self, String> {
        Self::from_files_within(run_id, graph, objects, Limits::ANY)
    }

    /// [`EarlierRun::from_files`] for a graph within `limits`: a graph of
    /// more or fewer objects is refused before anything is made for them,
    /// and the object index is read no further than the graph's objects.
    pub fn from_files_within(
        run_id: &str,
        graph: &[u8],
        objects: &[u8],
        limits: Limits,
    ) -> Result<Self, String> {
        let x = crate::explore::ExploreGraph::decode_within(graph, limits.bounds())?;
        let objects = read_objects(objects, x.node_count())?;
        if objects.len() != x.node_count() {
            return Err("the run's object index and graph disagree".into());
        }
        // The population with a path, inactive accounts included: the
        // graph has no logon times. `previous` uses these keys only when
        // their count matches the point's, which counted active ones.
        let tree = x.tier_zero_tree();
        let mut exposed: Vec<(u64, u32)> = (0..x.node_count() as u32)
            .filter(|&v| x.is_population(v) && tree.reaches(v))
            .map(|v| (key(&objects[v as usize].0), v))
            .collect();
        exposed.sort_unstable();
        exposed.dedup_by_key(|e| e.0);
        let kinds = (0..x.node_count() as u32).map(|v| x.kind(v)).collect();
        Ok(EarlierRun {
            run_id: run_id.to_string(),
            exposed,
            names: objects.into_iter().map(|o| o.1).collect(),
            kinds,
            tree,
        })
    }
}

/// The IDs and names of a run's object index (`objects.json.gz`,
/// [`crate::object_index::ObjectIndex`]: `{"objects": [[id, name, kind,
/// domain, dn, flags], ...], ...}`), in order, refusing more than `limit`
/// objects as it reads.
fn read_objects(json: &[u8], limit: usize) -> Result<Vec<(String, String)>, String> {
    use serde::de::{DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};

    /// An object of the index: its ID and name; the rest unread.
    #[derive(Deserialize)]
    struct Obj(
        String,
        String,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
    );

    struct Index(usize);
    struct Objects(usize);

    impl<'de> DeserializeSeed<'de> for Index {
        type Value = Vec<(String, String)>;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Index {
        type Value = Vec<(String, String)>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object index")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let mut out = None;
            while let Some(k) = m.next_key::<String>()? {
                if k == "objects" && out.is_none() {
                    out = Some(m.next_value_seed(Objects(self.0))?);
                } else {
                    m.next_value::<IgnoredAny>()?;
                }
            }
            out.ok_or_else(|| A::Error::missing_field("objects"))
        }
    }
    impl<'de> DeserializeSeed<'de> for Objects {
        type Value = Vec<(String, String)>;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for Objects {
        type Value = Vec<(String, String)>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the objects")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(Obj(id, name, ..)) = s.next_element()? {
                if out.len() == self.0 {
                    return Err(A::Error::custom("more objects than the graph has"));
                }
                out.push((id, name));
            }
            Ok(out)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(json);
    let out = Index(limit)
        .deserialize(&mut de)
        .and_then(|v| de.end().map(|()| v))
        .map_err(|e| format!("the run's object index can't be read: {e}"))?;
    Ok(out)
}

impl EarlierRun {
    /// The keys of the accounts with a path to Tier Zero then, sorted.
    pub fn keys(&self) -> Vec<u64> {
        self.exposed.iter().map(|e| e.0).collect()
    }

    /// The account with key `k` among those with a path then.
    fn find(&self, k: u64) -> Option<u32> {
        let at = self.exposed.partition_point(|e| e.0 < k);
        self.exposed.get(at).filter(|e| e.0 == k).map(|e| e.1)
    }

    fn object(&self, v: u32) -> (&str, NodeKind) {
        (&self.names[v as usize], self.kinds[v as usize])
    }

    /// Object `v`'s path to Tier Zero then: edge kind and object, by hop.
    fn path(&self, v: u32) -> Vec<(&'static str, u32)> {
        self.tree
            .path(v)
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.kind.as_str(), e.to))
            .collect()
    }
}

/// `gz` inflated, refused past `cap` bytes.
fn inflate(gz: &[u8], cap: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("the run's files can't be read: {e}"))?;
    if out.len() as u64 > cap {
        return Err("the run's files inflate to more than a full run's do".into());
    }
    Ok(out)
}

/// Full run `run_id`'s graph in the history in `state_dir`, read (and
/// decrypted when the history is encrypted) within `limits`, its point's,
/// widened by what its summary says it collected; `None` when the history
/// has no full run of it with a graph.
pub fn read_full_run(
    state_dir: &Path,
    run_id: &str,
    limits: Limits,
) -> Result<Option<EarlierRun>, String> {
    read_full_run_or(state_dir, run_id, limits).map_err(Failed::why)
}

/// Why a full run couldn't be read.
enum Failed {
    /// Its files are not what a full run's are: no use reading them again.
    Files(String),
    /// They couldn't be read now (the history's passphrase not given yet, a
    /// file in use): read again next time.
    NotNow(String),
}

impl Failed {
    fn why(self) -> String {
        match self {
            Failed::Files(why) | Failed::NotNow(why) => why,
        }
    }
}

/// The most a full run's `summary.json` takes: a few KB in real runs.
/// Explore reads a run's summary within it too.
pub const MAX_SUMMARY: u64 = 1 << 20;

/// How many objects full run `run_id` collected, from its summary
/// (`summary.json`, the app's run summary); `None` without one, or with
/// one too large or not a summary. A summary there that can't be read now
/// (a file in use, a virus scanner's lock, the passphrase not given yet)
/// is [`Failed::NotNow`]: without its count a large run would be refused,
/// and remembered as refused until its files change.
fn collected_objects(state_dir: &Path, run_id: &str) -> Result<Option<usize>, Failed> {
    #[derive(Deserialize)]
    struct Summary {
        objects: usize,
    }
    let rel = crate::store::bundle_rel(run_id, "summary.json");
    let encrypted = crate::crypt::is_encrypted(state_dir);
    let m = match std::fs::symlink_metadata(crate::store::on_disk(state_dir, &rel, encrypted)) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Failed::NotNow(format!(
                "reading the full run's summary: {e}"
            )))
        }
    };
    if !m.is_file() || m.len() > crate::store::max_on_disk(MAX_SUMMARY) {
        return Ok(None);
    }
    let bytes = match crate::store::read_state_file(state_dir, &rel) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(Failed::NotNow(format!(
                "reading the full run's summary: {e:#}"
            )))
        }
    };
    Ok(serde_json::from_slice::<Summary>(&bytes)
        .ok()
        .map(|s| s.objects))
}

fn read_full_run_or(
    state_dir: &Path,
    run_id: &str,
    limits: Limits,
) -> Result<Option<EarlierRun>, Failed> {
    let files = crate::store::bundle_files(state_dir, run_id);
    if !files.contains(&FULL_RUN_GRAPH) || !files.contains(&FULL_RUN_OBJECTS) {
        return Ok(None);
    }
    // No larger than its manifest says, nor than the limit the full run
    // was written under: a planted file is never read whole.
    let held = full_run_sizes(state_dir, run_id);
    let stamp = full_run_stamp(state_dir, run_id);
    let mut sizes = [0u64; 2];
    for ((s, st), most) in sizes.iter_mut().zip(&stamp).zip(held) {
        match st {
            Some((n, _)) if *n <= crate::store::max_on_disk(most) => *s = *n,
            _ => {
                return Err(Failed::Files(
                    "the full run's files are larger than a full run takes".into(),
                ))
            }
        }
    }
    let limits = match collected_objects(state_dir, run_id)? {
        Some(n) => limits.with_collected(n),
        None => limits,
    };
    let read = |name: &str, on_disk: u64, most: u64| -> Result<Vec<u8>, Failed> {
        let gz = crate::store::read_state_file(state_dir, &crate::store::bundle_rel(run_id, name))
            .map_err(|e| Failed::NotNow(format!("{e:#}")))?
            .ok_or_else(|| Failed::NotNow(format!("the full run has no {name}")))?;
        if gz.len() as u64 > most {
            return Err(Failed::Files(
                "the full run's files are larger than a full run takes".into(),
            ));
        }
        inflate(&gz, inflate_cap(on_disk, limits)).map_err(Failed::Files)
    };
    // The graph first: its count of objects bounds the index's.
    let graph = read(FULL_RUN_GRAPH, sizes[0], held[0])?;
    let objects = read(FULL_RUN_OBJECTS, sizes[1], held[1])?;
    EarlierRun::from_files_within(run_id, &graph, &objects, limits)
        .map(Some)
        .map_err(Failed::Files)
}

/// What full run `run_id`'s graph and object index are on disk (as stored:
/// encrypted when the history is): size and time written; `None` for one
/// that isn't there or is a link. A file replaced since is read again.
type Stamp = [Option<(u64, Option<std::time::SystemTime>)>; 2];

fn full_run_stamp(state_dir: &Path, run_id: &str) -> Stamp {
    let encrypted = crate::crypt::is_encrypted(state_dir);
    [FULL_RUN_GRAPH, FULL_RUN_OBJECTS].map(|name| {
        let rel = crate::store::bundle_rel(run_id, name);
        std::fs::symlink_metadata(crate::store::on_disk(state_dir, &rel, encrypted))
            .ok()
            .filter(|m| m.is_file())
            .map(|m| (m.len(), m.modified().ok()))
    })
}

/// A full run read: its history folder, run ID and [`Stamp`].
type Read = (PathBuf, String, Stamp);

/// The last earlier run read, until [`release_earlier`].
static EARLIER: Mutex<Option<(Read, Arc<EarlierRun>)>> = Mutex::new(None);

/// Full runs whose files were refused, so a damaged or planted one costs
/// one read a process: the latest [`FAILED_KEPT`]. One that couldn't be
/// read for now (its history's passphrase not given yet) isn't kept here.
static FAILED: Mutex<Vec<Read>> = Mutex::new(Vec::new());
const FAILED_KEPT: usize = 32;

/// [`read_full_run`], keeping the last one read: the lists of one analysis
/// read it once (its keys and its paths), and a report made again reads it
/// no more. Only the last one read is kept here: it is let go before
/// another is read, and by [`release_earlier`] when the analysis is done.
/// A caller still holding an earlier one keeps it in memory, so two
/// callers (two analyses at once) can each hold one.
/// A full run whose files were refused is not read again while they stay
/// the same.
pub fn earlier_run(
    state_dir: &Path,
    run_id: &str,
    limits: Limits,
) -> Result<Option<Arc<EarlierRun>>, String> {
    if !crate::store::is_run_id(run_id) {
        return Ok(None);
    }
    let stamp = full_run_stamp(state_dir, run_id);
    if stamp.iter().any(Option::is_none) {
        return Ok(None);
    }
    let this: Read = (state_dir.to_path_buf(), run_id.to_string(), stamp);
    {
        let mut kept = EARLIER.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((read, e)) = kept.as_ref() {
            if *read == this {
                return Ok(Some(e.clone()));
            }
        }
        // The one kept is let go before another is read (two callers at
        // once may still each read one: the lock isn't held while reading).
        *kept = None;
    }
    if FAILED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&this)
    {
        return Err("the full run couldn't be read before".into());
    }
    // Read without holding the lock.
    match crate::timing::phase("earlier full run", || {
        read_full_run_or(state_dir, run_id, limits)
    }) {
        Ok(Some(e)) => {
            let e = Arc::new(e);
            *EARLIER.lock().unwrap_or_else(|e| e.into_inner()) = Some((this, e.clone()));
            Ok(Some(e))
        }
        Ok(None) => Ok(None),
        Err(Failed::NotNow(why)) => Err(why),
        Err(Failed::Files(why)) => {
            let mut failed = FAILED.lock().unwrap_or_else(|e| e.into_inner());
            if failed.len() >= FAILED_KEPT {
                failed.remove(0);
            }
            failed.push(this);
            Err(why)
        }
    }
}

/// Lets go of the earlier run [`earlier_run`] kept: an analysis calls it
/// when its lists are made.
pub fn release_earlier() {
    *EARLIER.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The keys run `run_id` kept in the history in `state_dir`: `None` when
/// it has none, and an error when they can't be read.
pub fn read_keys(state_dir: &Path, run_id: &str) -> Result<Option<ExposedRecord>, Why> {
    let rel = format!("{DIR}/{run_id}.json");
    match crate::store::read_state_file(state_dir, &rel) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => ExposedRecord::parse(&bytes).map(Some),
        Err(_) => Err(Why::Unreadable),
    }
}

/// What `history`'s report compares its accounts with: the previous run
/// ([`ReportHistory::before`]) and its keys, for a run that read what it
/// did (`completeness`, on exposure `basis`). `None` without an earlier
/// run.
pub fn previous(
    history: &ReportHistory,
    completeness: Option<&CompletenessPoint>,
    basis: u8,
) -> Option<PreviousExposed> {
    let before = history.before()?;
    let comparable = before.basis() == basis
        && crate::since::targeting(before.completeness.as_ref())
            == crate::since::targeting(completeness);
    let keys = (|| {
        if !before.exposed_keys {
            return Err(Why::NoKeys);
        }
        if !comparable {
            return Err(Why::NotComparable);
        }
        let dir = history.state_dir.as_deref().ok_or(Why::NotKept)?;
        read_keys(dir, &before.run_id)?
            .ok_or(Why::NotKept)?
            .tier_zero_for(before)
    })();
    let prev = PreviousExposed::new(&before.run_id, before.at, keys);
    let Some(dir) = history.state_dir.as_deref() else {
        return Some(prev);
    };
    let mut prev = prev.with_full_run_in(dir, Limits::of(before));
    // No keys to use: its full run's graph, when the history has one and
    // it counts the accounts the run did.
    if prev.keys.is_err() && comparable {
        if let Some(keys) = prev
            .earlier()
            .map(|e| e.keys())
            .filter(|k| k.len() == before.tier_zero_exposed)
        {
            prev.keys = Ok(keys);
            prev.from_full_run = true;
        }
    }
    Some(prev)
}

// --------------------------------------------------------- the lists

/// Which accounts each remediation step cuts off and what changed since
/// the previous run, with their paths (`exposed.json.gz`, [`FILE`]).
/// Objects are named once, in `nodes`; everything else refers to them by
/// index.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExposureLists {
    pub version: u32,
    /// The objects the lists name: name and kind.
    pub nodes: Vec<(String, NodeKind)>,
    /// The edge kinds the paths take, by name.
    pub edges: Vec<String>,
    /// Who reaches each step's `from`.
    pub sources: Vec<SourceList>,
    /// The plan's steps, in order.
    pub steps: Vec<StepList>,
    /// Against the previous run; `None` without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<Change>,
}

/// The accounts with a path to one object (a step's `from`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceList {
    pub from: u32,
    /// New ones first, then the fewest hops, then by name.
    pub accounts: Vec<u32>,
    /// The first `new` accounts are new since the previous run.
    pub new: usize,
    /// The paths to `from`: node, then the hop it takes (edge kind,
    /// next node), as `tail` and paths write hops; sorted by node.
    pub next: Vec<[u32; 3]>,
}

/// One remediation step's list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StepList {
    /// 1 for the first step.
    pub step: usize,
    /// Its `from`'s list ([`ExposureLists::sources`]).
    pub source: usize,
    /// Accounts it cuts off.
    pub exposed: usize,
    /// Of them, new since the previous run.
    pub new: usize,
    /// From `from` on to Tier Zero: edge kind, node.
    pub tail: Vec<[u32; 2]>,
}

/// What changed since the previous run, account by account.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub previous_run: String,
    pub previous_at: i64,
    /// Why the accounts were not compared; the lists are empty then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Why>,
    /// The previous run's accounts came from its full run's graph: it kept
    /// no keys, or they are no longer kept.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_full_run: bool,
    /// Now reach Tier Zero: the fewest hops first, then by name.
    pub now: Vec<NowRow>,
    /// No longer reach it, by name.
    pub gone: Vec<GoneRow>,
    /// No longer reach it and no longer in the directory.
    pub gone_unnamed: usize,
    /// How many now reach Tier Zero and how many named ones no longer do,
    /// when `now` and `gone` hold only the first ([`ExposureLists::change_only`]).
    /// Not in the file.
    #[serde(skip)]
    pub totals: Option<(usize, usize)>,
}

impl Change {
    /// How many accounts now reach Tier Zero.
    pub fn now_total(&self) -> usize {
        self.totals.map_or(self.now.len(), |t| t.0)
    }

    /// How many named accounts no longer reach it (besides
    /// [`Change::gone_unnamed`]).
    pub fn gone_total(&self) -> usize {
        self.totals.map_or(self.gone.len(), |t| t.1)
    }
}

/// An account that now reaches Tier Zero.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NowRow {
    pub node: u32,
    pub hops: u32,
    /// The first step that cuts it off (1 for the first); its path goes
    /// through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<usize>,
    /// Its path when no step cuts it off (or written out,
    /// [`ExposureLists::change_only`]): edge kind, node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<[u32; 2]>,
}

/// An account that no longer reaches Tier Zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoneRow {
    pub node: u32,
    pub why: Gone,
    /// Its path in the previous run, when its graph was read (its full
    /// run): edge kind, node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<[u32; 2]>,
}

/// Why an account no longer reaches Tier Zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Gone {
    NowTierZero,
    Disabled,
    NoPath,
    /// Named from the previous run's graph: not in this run's.
    NotInDirectory,
}

impl Gone {
    pub fn words(self) -> &'static str {
        match self {
            Gone::NowTierZero => "Now Tier Zero",
            Gone::Disabled => "Disabled",
            Gone::NoPath => "No path now",
            Gone::NotInDirectory => "No longer in the directory",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Gone::NowTierZero => "now-tier-zero",
            Gone::Disabled => "disabled",
            Gone::NoPath => "no-path",
            Gone::NotInDirectory => "not-in-directory",
        }
    }
}

/// An account that no longer reaches Tier Zero, as a list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoneAccount<'a> {
    pub name: &'a str,
    pub kind: NodeKind,
    pub why: Gone,
    /// Its path in the previous run; empty when its graph wasn't read.
    pub path: Vec<Hop<'a>>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One hop of a path: the edge taken and the object it reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop<'a> {
    pub edge: &'a str,
    pub name: &'a str,
    pub kind: NodeKind,
}

/// One account of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account<'a> {
    pub name: &'a str,
    pub kind: NodeKind,
    /// New since the previous run.
    pub new: bool,
    pub path: Vec<Hop<'a>>,
}

impl Account<'_> {
    pub fn hops(&self) -> usize {
        self.path.len()
    }
}

/// What a lists file a newer Pathwarden wrote says.
pub const NEWER_LISTS: &str = "A newer Pathwarden wrote this run's account lists.";

/// The most a lists file may inflate to.
pub const MAX_LISTS_BYTES: u64 = 1 << 30;

impl ExposureLists {
    /// Reads a lists file's JSON; an error in words for one that can't be
    /// read or comes from a newer Pathwarden.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        // The version first: a newer file may not have this one's shape.
        let v: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("The run's account lists can't be read ({e})."))?;
        if !crate::formats::of_json(&v, "version", LISTS_VERSION).is_known() {
            return Err(NEWER_LISTS.into());
        }
        let l: ExposureLists = serde_json::from_value(v)
            .map_err(|e| format!("The run's account lists can't be read ({e})."))?;
        l.check()
            .ok_or_else(|| "The run's account lists are damaged.".to_string())?;
        Ok(l)
    }

    /// Every index in range, so reading never panics.
    fn check(&self) -> Option<()> {
        let n = self.nodes.len() as u32;
        let k = self.edges.len() as u32;
        for s in &self.sources {
            (s.from < n
                && s.new <= s.accounts.len()
                && s.accounts.iter().all(|&a| a < n)
                && s.next.iter().all(|&[a, e, b]| a < n && b < n && e < k))
            .then_some(())?;
        }
        for st in &self.steps {
            (st.source < self.sources.len() && st.tail.iter().all(|&[e, b]| e < k && b < n))
                .then_some(())?;
        }
        if let Some(c) = &self.change {
            for r in &c.now {
                (r.node < n
                    && r.step.is_none_or(|s| s >= 1 && s <= self.steps.len())
                    && r.path.iter().all(|&[e, b]| e < k && b < n))
                .then_some(())?;
            }
            c.gone
                .iter()
                .all(|r| r.node < n && r.path.iter().all(|&[e, b]| e < k && b < n))
                .then_some(())?;
        }
        Some(())
    }

    fn hop(&self, [e, b]: [u32; 2]) -> Hop<'_> {
        let (name, kind) = &self.nodes[b as usize];
        Hop {
            edge: &self.edges[e as usize],
            name,
            kind: *kind,
        }
    }

    /// The path of `account` to step `step`'s `from` and on through it
    /// (`step` 1 for the first).
    fn path_through(&self, step: &StepList, account: u32) -> Vec<Hop<'_>> {
        self.hops_through(step, account)
            .into_iter()
            .map(|h| self.hop(h))
            .collect()
    }

    /// [`ExposureLists::path_through`] as hops by index (edge kind, node).
    fn hops_through(&self, step: &StepList, account: u32) -> Vec<[u32; 2]> {
        let src = &self.sources[step.source];
        let mut out = Vec::new();
        let mut cur = account;
        while cur != src.from && out.len() <= src.next.len() {
            let Ok(i) = src.next.binary_search_by_key(&cur, |x| x[0]) else {
                break;
            };
            let [_, e, next] = src.next[i];
            out.push([e, next]);
            cur = next;
        }
        out.extend(step.tail.iter().copied());
        out
    }

    /// What changed alone, each account's path written out, at most
    /// [`LISTED`] accounts a list (their totals kept, [`Change::totals`]),
    /// and nothing of the steps' lists: what Home keeps of a run's lists,
    /// which shows What changed only.
    pub fn change_only(&self) -> ExposureLists {
        let mut out = ExposureLists {
            version: LISTS_VERSION,
            edges: self.edges.clone(),
            ..Default::default()
        };
        let Some(c) = &self.change else {
            return out;
        };
        let mut index: HashMap<u32, u32> = HashMap::new();
        let mut node = |old: u32, nodes: &mut Vec<(String, NodeKind)>| -> u32 {
            *index.entry(old).or_insert_with(|| {
                nodes.push(self.nodes[old as usize].clone());
                (nodes.len() - 1) as u32
            })
        };
        let mut nodes = Vec::new();
        let now = c
            .now
            .iter()
            .take(LISTED)
            .map(|r| {
                let path = match r.step {
                    Some(s) if r.path.is_empty() => self.hops_through(&self.steps[s - 1], r.node),
                    _ => r.path.clone(),
                };
                NowRow {
                    node: node(r.node, &mut nodes),
                    hops: r.hops,
                    step: r.step,
                    path: path
                        .into_iter()
                        .map(|[e, b]| [e, node(b, &mut nodes)])
                        .collect(),
                }
            })
            .collect();
        let gone = c
            .gone
            .iter()
            .take(LISTED)
            .map(|r| GoneRow {
                node: node(r.node, &mut nodes),
                why: r.why,
                path: r
                    .path
                    .iter()
                    .map(|&[e, b]| [e, node(b, &mut nodes)])
                    .collect(),
            })
            .collect();
        out.nodes = nodes;
        out.change = Some(Change {
            previous_run: c.previous_run.clone(),
            previous_at: c.previous_at,
            unavailable: c.unavailable,
            from_full_run: c.from_full_run,
            now,
            gone,
            gone_unnamed: c.gone_unnamed,
            totals: Some((c.now_total(), c.gone_total())),
        });
        out
    }

    /// Step `step`'s accounts (1 for the first), in order: new ones first,
    /// then the closest. `None` for a step the lists don't have.
    pub fn step_accounts(&self, step: usize) -> Option<Vec<Account<'_>>> {
        self.step_accounts_first(step, usize::MAX)
    }

    /// How many accounts a page lists of each step, in order: at most
    /// [`LISTED`] a step and [`LISTED_TOTAL`] in all, the earlier steps
    /// first.
    pub fn listed_per_step(&self) -> Vec<usize> {
        let mut left = LISTED_TOTAL;
        self.steps
            .iter()
            .map(|st| {
                let n = st.exposed.min(LISTED).min(left);
                left -= n;
                n
            })
            .collect()
    }

    /// The first `limit` of [`ExposureLists::step_accounts`], as a page
    /// lists them ([`ExposureLists::listed_per_step`]).
    pub fn step_accounts_first(&self, step: usize, limit: usize) -> Option<Vec<Account<'_>>> {
        let st = self.steps.get(step.checked_sub(1)?)?;
        let src = &self.sources[st.source];
        Some(
            src.accounts
                .iter()
                .take(limit)
                .enumerate()
                .map(|(i, &a)| {
                    let (name, kind) = &self.nodes[a as usize];
                    Account {
                        name,
                        kind: *kind,
                        new: i < src.new,
                        path: self.path_through(st, a),
                    }
                })
                .collect(),
        )
    }

    /// The accounts that now reach Tier Zero, each with the step that cuts
    /// it off (`None`: none does); empty without a change.
    pub fn now_reach(&self) -> Vec<(Account<'_>, Option<usize>)> {
        let Some(c) = &self.change else {
            return Vec::new();
        };
        c.now
            .iter()
            .map(|r| {
                let (name, kind) = &self.nodes[r.node as usize];
                // Written out ([`ExposureLists::change_only`]), or through
                // the step that cuts it off.
                let path = match r.step {
                    Some(s) if r.path.is_empty() => self.path_through(&self.steps[s - 1], r.node),
                    _ => r.path.iter().map(|&h| self.hop(h)).collect(),
                };
                (
                    Account {
                        name,
                        kind: *kind,
                        new: true,
                        path,
                    },
                    r.step,
                )
            })
            .collect()
    }

    /// The accounts that no longer reach Tier Zero, by name, with why and
    /// their path in the previous run when its graph was read.
    pub fn no_longer(&self) -> Vec<GoneAccount<'_>> {
        let Some(c) = &self.change else {
            return Vec::new();
        };
        c.gone
            .iter()
            .map(|r| {
                let (name, kind) = &self.nodes[r.node as usize];
                GoneAccount {
                    name,
                    kind: *kind,
                    why: r.why,
                    path: r.path.iter().map(|&h| self.hop(h)).collect(),
                }
            })
            .collect()
    }

    /// Whether any account that no longer reaches Tier Zero has its path in
    /// the previous run.
    pub fn earlier_paths(&self) -> bool {
        self.change
            .as_ref()
            .is_some_and(|c| c.gone.iter().any(|r| !r.path.is_empty()))
    }

    /// The change, when the accounts were compared with the previous run's.
    pub fn compared(&self) -> Option<&Change> {
        self.change.as_ref().filter(|c| c.unavailable.is_none())
    }

    /// "5 new accounts reach Tier Zero, and 5 older accounts no longer
    /// do.": when as many came as went, so the count alone says nothing
    /// changed.
    pub fn same_total_sentence(&self) -> Option<String> {
        let c = self.compared()?;
        let gone = c.gone_total() + c.gone_unnamed;
        (gone > 0 && gone == c.now_total()).then(|| {
            format!(
                "{} {} Tier Zero, and {} no longer {}.",
                crate::text::count(gone, "new account", "new accounts"),
                if gone == 1 { "reaches" } else { "reach" },
                crate::text::count(gone, "older account", "older accounts"),
                if gone == 1 { "does" } else { "do" },
            )
        })
    }
}

/// "2 more are no longer in the directory."
pub fn unnamed_sentence(n: usize) -> String {
    format!(
        "{} more {} no longer in the directory.",
        crate::text::num(n),
        if n == 1 { "is" } else { "are" }
    )
}

/// An account that now reaches Tier Zero, while the lists are made: its
/// hops, name and node, the first step that cuts it off, and its path when
/// none does.
type NowEntry<'a> = (u32, &'a str, NodeIndex, Option<usize>, Vec<EdgeIndex>);

/// Names objects once, by index.
#[derive(Default)]
struct Table {
    index: HashMap<NodeIndex, u32>,
    /// The previous run's objects, by their number in its graph.
    earlier: HashMap<u32, u32>,
    nodes: Vec<(String, NodeKind)>,
    kinds: HashMap<String, u32>,
    edges: Vec<String>,
}

impl Table {
    /// Object `v` of the previous run's graph.
    fn earlier_node(&mut self, e: &EarlierRun, v: u32) -> u32 {
        let nodes = &mut self.nodes;
        *self.earlier.entry(v).or_insert_with(|| {
            let (name, kind) = e.object(v);
            nodes.push((name.to_string(), kind));
            (nodes.len() - 1) as u32
        })
    }

    /// Object `v`'s path in the previous run, as hops.
    fn earlier_path(&mut self, e: &EarlierRun, v: u32) -> Vec<[u32; 2]> {
        e.path(v)
            .into_iter()
            .map(|(kind, to)| [self.edge(kind), self.earlier_node(e, to)])
            .collect()
    }

    fn node(&mut self, g: &AdGraph, ix: NodeIndex) -> u32 {
        let nodes = &mut self.nodes;
        *self.index.entry(ix).or_insert_with(|| {
            let n = g.node(ix);
            nodes.push((n.name.clone(), n.kind));
            (nodes.len() - 1) as u32
        })
    }

    fn edge(&mut self, kind: &str) -> u32 {
        if let Some(&i) = self.kinds.get(kind) {
            return i;
        }
        self.edges.push(kind.to_string());
        let i = (self.edges.len() - 1) as u32;
        self.kinds.insert(kind.to_string(), i);
        i
    }

    /// An edge as a hop: its kind and where it goes.
    fn hop(&mut self, g: &AdGraph, e: EdgeIndex) -> [u32; 2] {
        let (_, b) = g.inner().edge_endpoints(e).expect("edge from this graph");
        [self.edge(g.inner()[e].as_str()), self.node(g, b)]
    }
}

/// The lists of the Tier Zero `plan` over `g`, against `previous` (the
/// previous run's keys, [`previous`]).
pub fn lists(
    g: &AdGraph,
    plan: &RemediationPlan,
    previous: Option<&PreviousExposed>,
) -> ExposureLists {
    let mut t = Table::default();
    let Some(detail) = plan.detail.as_ref() else {
        return ExposureLists {
            version: LISTS_VERSION,
            ..Default::default()
        };
    };
    // The current keys, and which accounts are new.
    let mut current: Vec<(u64, NodeIndex)> = detail
        .exposed
        .iter()
        .map(|&ix| (key(&g.node(ix).id), ix))
        .collect();
    current.sort_unstable();
    let prev_keys = previous.and_then(|p| p.keys.as_ref().ok());
    let new: HashSet<NodeIndex> = match prev_keys {
        Some(prev) => current
            .iter()
            .filter(|(k, _)| prev.binary_search(k).is_err())
            .map(|&(_, ix)| ix)
            .collect(),
        None => HashSet::new(),
    };
    let name = |ix: NodeIndex| g.node(ix).name.as_str();

    let mut sources = Vec::with_capacity(detail.sources.len());
    for s in &detail.sources {
        let mut accounts: Vec<(bool, u32, &str, NodeIndex)> = s
            .accounts
            .iter()
            .map(|&(ix, hops)| (!new.contains(&ix), hops, name(ix), ix))
            .collect();
        accounts.sort_unstable();
        let from = t.node(g, s.from);
        let mut next: Vec<[u32; 3]> = s
            .next
            .iter()
            .map(|&(a, b, e)| {
                let e = EdgeIndex::new(e as usize);
                [
                    t.node(g, NodeIndex::new(a as usize)),
                    t.edge(g.inner()[e].as_str()),
                    t.node(g, NodeIndex::new(b as usize)),
                ]
            })
            .collect();
        next.sort_unstable();
        sources.push(SourceList {
            from,
            new: accounts.iter().filter(|a| !a.0).count(),
            accounts: accounts.iter().map(|a| t.node(g, a.3)).collect(),
            next,
        });
    }
    let steps: Vec<StepList> = plan
        .fixes
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let source = detail.step_source[i];
            StepList {
                step: i + 1,
                source,
                exposed: f.principals_through,
                new: sources[source].new,
                tail: detail.step_tail[i].iter().map(|&e| t.hop(g, e)).collect(),
            }
        })
        .collect();

    let change = previous.map(|p| match prev_keys {
        None => Change {
            previous_run: p.run_id.clone(),
            previous_at: p.at,
            unavailable: Some(p.keys.clone().err().unwrap_or(Why::Unreadable)),
            ..Change::default()
        },
        Some(prev) => {
            let mut c = Change {
                previous_run: p.run_id.clone(),
                previous_at: p.at,
                from_full_run: p.from_full_run,
                ..Change::default()
            };
            // Now reach: the first step whose list has them.
            let mut first: HashMap<NodeIndex, (usize, u32)> = HashMap::new();
            let mut seen = HashSet::new();
            for (i, &si) in detail.step_source.iter().enumerate() {
                if !seen.insert(si) {
                    continue;
                }
                for &(ix, hops) in &detail.sources[si].accounts {
                    if new.contains(&ix) {
                        first.entry(ix).or_insert((i, hops));
                    }
                }
            }
            let unplanned = new.iter().any(|ix| !first.contains_key(ix));
            let tree = unplanned
                .then(|| crate::analysis::reach_targets(g, crate::analysis::tier_zero(g), None));
            let mut now: Vec<NowEntry> = Vec::new();
            for &ix in &new {
                match first.get(&ix) {
                    Some(&(i, hops)) => {
                        let hops = hops + detail.step_tail[i].len() as u32;
                        now.push((hops, name(ix), ix, Some(i + 1), Vec::new()));
                    }
                    None => {
                        let path = tree.as_ref().and_then(|t| t.path(ix)).unwrap_or_default();
                        now.push((path.len() as u32, name(ix), ix, None, path));
                    }
                }
            }
            now.sort_unstable_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
            c.now = now
                .into_iter()
                .map(|(hops, _, ix, step, path)| NowRow {
                    node: t.node(g, ix),
                    hops,
                    step,
                    path: path.into_iter().map(|e| t.hop(g, e)).collect(),
                })
                .collect();
            // No longer reach: named from this run's users and computers.
            let current_keys: Vec<u64> = current.iter().map(|c| c.0).collect();
            let gone_keys: Vec<u64> = prev
                .iter()
                .copied()
                .filter(|k| current_keys.binary_search(k).is_err())
                .collect();
            if !gone_keys.is_empty() {
                let mut known: Vec<(u64, NodeIndex)> = g
                    .nodes()
                    .filter(|(_, n)| {
                        matches!(n.kind, NodeKind::User | NodeKind::Computer) && !n.placeholder
                    })
                    .map(|(ix, n)| (key(&n.id), ix))
                    .collect();
                known.sort_unstable();
                // The previous run's graph, when its full run has one: each
                // account's path then, and the names of those gone since.
                let earlier = p.earlier().filter(|e| e.run_id == p.run_id);
                /// Who: in this run's graph, or only in the previous one's.
                enum Who {
                    Now(NodeIndex),
                    Then(u32),
                }
                let mut gone: Vec<(&str, u32, Who, Gone, Option<u32>)> = Vec::new();
                for k in gone_keys {
                    let then = earlier.and_then(|e| e.find(k));
                    let at = known.partition_point(|x| x.0 < k);
                    match (known.get(at).filter(|x| x.0 == k), then, earlier) {
                        (Some(&(_, ix)), _, _) => {
                            let n = g.node(ix);
                            let why = if n.tier_zero {
                                Gone::NowTierZero
                            } else if !n.is_enabled() {
                                Gone::Disabled
                            } else {
                                Gone::NoPath
                            };
                            gone.push((name(ix), 0, Who::Now(ix), why, then));
                        }
                        (None, Some(v), Some(e)) => {
                            gone.push((e.object(v).0, 1, Who::Then(v), Gone::NotInDirectory, then));
                        }
                        _ => c.gone_unnamed += 1,
                    }
                }
                gone.sort_unstable_by(|a, b| {
                    let at = |w: &Who| match *w {
                        Who::Now(ix) => ix.index(),
                        Who::Then(v) => v as usize,
                    };
                    (a.0, a.1, at(&a.2)).cmp(&(b.0, b.1, at(&b.2)))
                });
                c.gone = gone
                    .into_iter()
                    .map(|(_, _, who, why, then)| GoneRow {
                        node: match who {
                            Who::Now(ix) => t.node(g, ix),
                            Who::Then(v) => t.earlier_node(earlier.expect("named from it"), v),
                        },
                        why,
                        path: match (then, earlier) {
                            (Some(v), Some(e)) => t.earlier_path(e, v),
                            _ => Vec::new(),
                        },
                    })
                    .collect();
            }
            c
        }
    });

    ExposureLists {
        version: LISTS_VERSION,
        nodes: t.nodes,
        edges: t.edges,
        sources,
        steps,
        change,
    }
}

/// The lists of an analysis's Tier Zero plan, against the run `history`
/// compares with ([`previous`]).
pub fn lists_for(a: &crate::analyze::Analysis, history: &ReportHistory) -> ExposureLists {
    crate::timing::phase("exposed lists", || {
        let completeness = CompletenessPoint::new(&a.posture.completeness);
        let prev = previous(history, completeness.as_ref(), a.posture.exposure_basis);
        lists(&a.graph, &a.plan, prev.as_ref())
    })
}

#[cfg(test)]
#[path = "exposed_tests.rs"]
mod tests;
