//! Files saved with each run for the configuration screens, which need the
//! directory's objects after the collector files are gone:
//!
//! - `objects.json.gz`: a compact [`ObjectIndex`] (IDs, names, kinds,
//!   domains, distinguished names, Tier Zero flags, and the `MemberOf`,
//!   `Contains` and `GPLink` relations zones follow). Object search and the
//!   zone preview run on it.
//! - `graph.bin.gz`: the whole graph (every edge, with its kind) and each
//!   finding's path and entry points, for the explorer
//!   ([`crate::explore_ui`], [`pathwarden_core::explore`]).
//! - `opengraph.json`: what OpenGraph files added (sources, counts, packs,
//!   coverage), only for runs that had them ([`crate::opengraph_ui`]).
//! - `event.json.gz`: the run's event document (`pathwarden.event.v1`), as
//!   `pathwarden run` hands plugins, for "Test with the latest run" and for
//!   picking a finding to accept.
//! - `exposed.json.gz`: which accounts each remediation step cuts off and
//!   which reach Tier Zero now or no longer, with their paths
//!   ([`pathwarden_core::exposed::ExposureLists`]).
//!
//! All are as sensitive as the report (names, paths) and live beside it in
//! the run's folder, so deleting a run deletes them.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use pathwarden_core::analyze::Analysis;
use pathwarden_core::object_index::ObjectIndex;
use pathwarden_core::state::{self, FindingsState};
use pathwarden_core::{event, AdGraph};
use serde::{Deserialize, Serialize};

use crate::workspace::{RunSummary, Workspace};

pub const OBJECTS_FILE: &str = "objects.json.gz";
/// The run's objects' analysis fields, for Cypher queries on it
/// ([`pathwarden_core::cypher::RunProps`]).
pub const PROPS_FILE: &str = "props.json.gz";
pub const EVENT_FILE: &str = "event.json.gz";
/// What the run's data sources covered ([`run_sources`]).
pub const RUN_SOURCES_FILE: &str = "coverage.json.gz";
/// The run's account lists ([`pathwarden_core::exposed::ExposureLists`]).
pub const EXPOSED_FILE: &str = pathwarden_core::exposed::FILE;

/// Most search results returned.
pub const SEARCH_LIMIT: usize = 20;

fn gzip(write: impl FnOnce(&mut GzEncoder<Vec<u8>>) -> std::io::Result<()>) -> Option<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
    write(&mut enc).ok()?;
    enc.finish().ok()
}

/// The files to save with a finished run. A file that cannot be built is
/// left out (the run itself still saves). `run_id` is the run's history
/// run ID ([`RunSummary::run_id`]), which the event document carries;
/// `history` the runs it compares with, for its account lists
/// ([`EXPOSED_FILE`]).
pub fn files_for(
    run_id: &str,
    a: &Analysis,
    finished: i64,
    history: &pathwarden_core::history::ReportHistory,
) -> Vec<(&'static str, Vec<u8>)> {
    files_with(run_id, a, finished, &a.exposure_lists(history))
}

/// [`files_for`] with the run's account lists already made (as its report
/// shows them).
pub fn files_with(
    run_id: &str,
    a: &Analysis,
    finished: i64,
    lists: &pathwarden_core::exposed::ExposureLists,
) -> Vec<(&'static str, Vec<u8>)> {
    files(run_id, a, finished, lists, true)
}

/// [`files_with`] for a full run in a history only: without what a bundle
/// doesn't carry ([`PROPS_FILE`]), so it isn't made for nothing.
pub fn bundle_files(
    run_id: &str,
    a: &Analysis,
    finished: i64,
    lists: &pathwarden_core::exposed::ExposureLists,
) -> Vec<(&'static str, Vec<u8>)> {
    files(run_id, a, finished, lists, false)
}

fn files(
    run_id: &str,
    a: &Analysis,
    finished: i64,
    lists: &pathwarden_core::exposed::ExposureLists,
    with_props: bool,
) -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    // Which accounts each step cuts off, and which reach Tier Zero now or
    // no longer.
    if let Some(b) = gzip(|w| serde_json::to_writer(w, lists).map_err(std::io::Error::other)) {
        out.push((EXPOSED_FILE, b));
    }
    let index = ObjectIndex::from_graph(&a.graph);
    if let Some(b) = gzip(|w| serde_json::to_writer(w, &index).map_err(std::io::Error::other)) {
        out.push((OBJECTS_FILE, b));
    }
    drop(index);
    // The objects' analysis fields, for queries.
    if with_props {
        let props = pathwarden_core::cypher::RunProps::from_graph(&a.graph);
        if let Some(b) = gzip(|w| serde_json::to_writer(w, &props).map_err(std::io::Error::other)) {
            out.push((PROPS_FILE, b));
        }
    }
    // The whole graph and the findings' paths, for the explorer.
    if let Some(b) = gzip(|w| pathwarden_core::explore::encode_analysis_to(w, a)) {
        out.push((crate::explore_ui::GRAPH_FILE, b));
    }
    // What its sources covered, for retests against it.
    let sources = pathwarden_core::opengraph::coverage::RunSources::from_analysis_at(
        &a.graph,
        &a.stats,
        Some((a.settings.now, a.settings.stale_days)),
    );
    // As `pathwarden run` builds it on a first run: every finding is new.
    let r = state::reconcile(&FindingsState::default(), &a.findings, finished, false);
    let last = state::LastRun {
        version: state::STATE_VERSION,
        run_id: run_id.to_string(),
        started_at: finished,
        finished_at: finished,
        collected_at: a.stats.collected_at,
        pathwarden: env!("CARGO_PKG_VERSION").to_string(),
        collector_files: a.stats.files.len(),
        domains: a.domains.clone(),
        trusted_domains: Some(a.trusted_domains.clone()),
        objects: a.collected_objects(),
        changes: r.counts,
        sources: Vec::new(),
        sources_exact: true,
        settings_files: a.stats.settings_files(finished),
        hosts: Some(sources.host_keys()),
    };
    let doc = event::build(
        &last,
        &a.posture,
        &a.findings,
        &r.changes,
        &r.state.findings,
        &r.resolved,
        &a.plan,
    );
    if let Some(b) = gzip(|w| serde_json::to_writer(w, &doc).map_err(std::io::Error::other)) {
        out.push((EVENT_FILE, b));
    }
    if let Some(b) = gzip(|w| serde_json::to_writer(w, &sources).map_err(std::io::Error::other)) {
        out.push((RUN_SOURCES_FILE, b));
    }
    // OpenGraph sources, for Run details' "Other sources" row.
    if let Some(b) = crate::opengraph_ui::file_for(&a.stats.opengraph) {
        out.push((crate::opengraph_ui::SOURCES_FILE, b));
    }
    // What targeted retests need of the graph.
    if let Some(b) = crate::retest_ui::slice_bytes(a) {
        out.push((crate::retest_ui::SLICE_FILE, b));
    }
    out
}

/// The newest run that has `file`. It is kept loaded once loaded
/// ([`RunCache`]).
pub fn latest_with(ws: &Workspace, file: &str) -> Option<(RunSummary, PathBuf)> {
    let found = ws.runs().into_iter().find_map(|r| {
        let dir = ws.run_dir(&r.id)?;
        dir.join(file).is_file().then_some((r, dir))
    });
    if let Some((_, dir)) = &found {
        pin(dir);
    }
    found
}

/// One finding of a run, for the "accept a risk" picker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRef {
    pub fingerprint: String,
    pub rule: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub suppressed: Option<String>,
    #[serde(default)]
    pub category: Option<pathwarden_core::findings::Category>,
    /// OpenGraph sources (and SYSVOL parts) its evidence came from, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Coverage units those sources must cover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// What it rests on of sessions and local groups; absent in events
    /// saved before findings recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rests_on: Option<pathwarden_core::posture::Untargeted>,
}

#[derive(Deserialize)]
struct EventFindings {
    findings: Vec<FindingRef>,
}

/// The run [`latest_with`] found last, which [`RunCache`]s keep: Zones and
/// Tier Zero search the newest run, and Explore opens on it.
static PINNED: Mutex<Option<PathBuf>> = Mutex::new(None);

fn pin(dir: &Path) {
    let mut p = PINNED.lock().unwrap_or_else(|e| e.into_inner());
    if p.as_deref() != Some(dir) {
        *p = Some(dir.to_path_buf());
    }
}

fn pinned() -> Option<PathBuf> {
    PINNED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// What was loaded from a few runs, by run folder: the newest run's (see
/// [`latest_with`]) and the others used last, so going back and forth
/// between runs doesn't load them again. A large directory's graph takes
/// hundreds of MB, so few others are kept: at most `recent`, and past the
/// one used last only while they weigh at most [`OTHER_WEIGHT`] together
/// (`weight`, an estimate in bytes from their object and edge counts).
/// The caches of large values let go of a run, the newest too, once it has
/// gone [`IDLE`] without a request ([`release_when_idle`]).
///
/// A run is loaded once however many requests ask for it at the same time
/// (the others wait for it), and loading one doesn't hold up requests for
/// what is already loaded or for another run.
pub(crate) struct RunCache<T> {
    state: Mutex<CacheState<T>>,
    recent: usize,
    weight: fn(&T) -> usize,
    /// The run kept besides the others.
    pinned: fn() -> Option<PathBuf>,
    /// Runs between a load and its result going into the cache.
    #[cfg(test)]
    landing: fn(),
}

/// Estimated bytes the runs other than the newest may hold together in a
/// [`RunCache`] (the one used last is kept whatever its size): two
/// 500,000-object runs, with Explore's edges (about 530 MB each), or one
/// larger one.
pub(crate) const OTHER_WEIGHT: usize = 1200 << 20;

/// The most runs besides the newest the caches of large values keep, however
/// small: past [`OTHER_WEIGHT`], fewer.
pub(crate) const RECENT: usize = 8;

/// How long a run stays loaded without a request: then it is let go, and
/// the next request loads it again (about a second per 500,000 objects).
pub const IDLE: Duration = Duration::from_secs(10 * 60);

/// How often [`release_when_idle`] looks.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

struct Cached<T> {
    dir: PathBuf,
    value: Arc<T>,
    /// The last request for it.
    used: Instant,
}

struct CacheState<T> {
    /// Least recently used first.
    runs: Vec<Cached<T>>,
    /// Runs being loaded, each with the lock its loader holds.
    loading: Vec<(PathBuf, Arc<Mutex<()>>)>,
}

impl<T: Send + Sync + 'static> RunCache<T> {
    pub(crate) const fn new(recent: usize, weight: fn(&T) -> usize) -> Self {
        Self::pinning(recent, weight, pinned)
    }

    const fn pinning(
        recent: usize,
        weight: fn(&T) -> usize,
        pinned: fn() -> Option<PathBuf>,
    ) -> Self {
        RunCache {
            state: Mutex::new(CacheState {
                runs: Vec::new(),
                loading: Vec::new(),
            }),
            recent,
            weight,
            pinned,
            #[cfg(test)]
            landing: || {},
        }
    }

    #[cfg(test)]
    const fn landing(mut self, landing: fn()) -> Self {
        self.landing = landing;
        self
    }

    fn state(&self) -> std::sync::MutexGuard<'_, CacheState<T>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The run's entry, if loaded, now the most recently used.
    fn get(&self, dir: &Path) -> Option<Arc<T>> {
        let mut s = self.state();
        let i = s.runs.iter().position(|r| r.dir == dir)?;
        let mut run = s.runs.remove(i);
        run.used = Instant::now();
        let v = run.value.clone();
        s.runs.push(run);
        Some(v)
    }

    /// The run's entry, loaded with `load` when it isn't.
    pub(crate) fn get_or_load<E>(
        &self,
        dir: &Path,
        load: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        self.get_or_load_shared(dir, || load().map(Arc::new))
    }

    /// [`RunCache::get_or_load`], with `load` giving what may be shared
    /// already.
    fn get_or_load_shared<E>(
        &self,
        dir: &Path,
        load: impl FnOnce() -> Result<Arc<T>, E>,
    ) -> Result<Arc<T>, E> {
        if let Some(v) = self.get(dir) {
            return Ok(v);
        }
        let flight = {
            let mut s = self.state();
            match s.loading.iter().find(|(d, _)| d == dir) {
                Some((_, f)) => f.clone(),
                None => {
                    let f = Arc::new(Mutex::new(()));
                    s.loading.push((dir.to_path_buf(), f.clone()));
                    f
                }
            }
        };
        let _loading = flight.lock().unwrap_or_else(|e| e.into_inner());
        // Out of `loading` however this ends (a `load` that panics too), and
        // before `_loading` is let go: by then the run is in `runs`, so a
        // request that waited finds it.
        let _done = Landed {
            cache: self,
            flight: &flight,
        };
        // Loaded by the request this one waited for.
        if let Some(v) = self.get(dir) {
            return Ok(v);
        }
        let loaded = load();
        #[cfg(test)]
        (self.landing)();
        if let Ok(v) = &loaded {
            let mut s = self.state();
            s.runs.retain(|r| r.dir != dir);
            s.runs.push(Cached {
                dir: dir.to_path_buf(),
                value: v.clone(),
                used: Instant::now(),
            });
            let dropped = self.trim(&mut s.runs);
            drop(s);
            let_go(dropped);
        }
        loaded
    }

    /// Takes out the least recently used runs past the limits.
    fn trim(&self, runs: &mut Vec<Cached<T>>) -> Vec<Cached<T>> {
        let keep = (self.pinned)();
        let mut dropped = Vec::new();
        loop {
            let others: Vec<usize> = (0..runs.len())
                .filter(|&i| Some(&runs[i].dir) != keep.as_ref())
                .collect();
            let weight: usize = others.iter().map(|&i| (self.weight)(&runs[i].value)).sum();
            if others.len() > self.recent || (others.len() > 1 && weight > OTHER_WEIGHT) {
                dropped.push(runs.remove(others[0]));
            } else {
                return dropped;
            }
        }
    }

    /// Lets go of the runs without a request since `idle` before `now`.
    pub(crate) fn sweep(&self, idle: Duration, now: Instant) {
        let mut s = self.state();
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut s.runs)
            .into_iter()
            .partition(|r| now.saturating_duration_since(r.used) >= idle);
        s.runs = kept;
        drop(s);
        let_go(gone);
    }

    /// What it holds: runs, and their estimated bytes together.
    pub(crate) fn weighs(&self) -> (usize, usize) {
        self.weighs_by(self.weight)
    }

    /// [`RunCache::weighs`], with each run weighed by `weight`.
    pub(crate) fn weighs_by(&self, weight: impl Fn(&T) -> usize) -> (usize, usize) {
        let s = self.state();
        let bytes = s.runs.iter().map(|r| weight(&r.value)).sum();
        (s.runs.len(), bytes)
    }
}

/// Frees what a cache let go of. A large graph takes a moment to free: not
/// while a request waits.
fn let_go<T: Send + Sync + 'static>(runs: Vec<Cached<T>>) {
    if !runs.is_empty() {
        std::thread::spawn(move || drop(runs));
    }
}

/// Takes a run out of [`CacheState::loading`] when its loader is done.
struct Landed<'a, T: Send + Sync + 'static> {
    cache: &'a RunCache<T>,
    flight: &'a Arc<Mutex<()>>,
}

impl<T: Send + Sync + 'static> Drop for Landed<'_, T> {
    fn drop(&mut self) {
        self.cache
            .state()
            .loading
            .retain(|(_, f)| !Arc::ptr_eq(f, self.flight));
    }
}

/// Object graphs and finding lists: loading a large directory's index
/// takes a moment, and searches come per keystroke.
///
/// Explore keeps its own runs the same way, with their graphs from here
/// ([`crate::explore_ui`]), and the two drop runs on their own: at worst
/// the graphs of the newest run and of others for each are in memory, the
/// others of each at most [`OTHER_WEIGHT`] together past the one used last.
/// A graph one of them still holds is never read a second time
/// ([`SHARED`]).
static GRAPHS: RunCache<AdGraph> = RunCache::new(RECENT, graph_weight);
static PROPS: RunCache<pathwarden_core::cypher::RunProps> = RunCache::new(RECENT, |p| {
    p.columns.values().map(Vec::len).sum::<usize>() * PROP_CELL_BYTES
});
static FINDINGS: RunCache<Vec<FindingRef>> =
    RunCache::new(RECENT, |f| f.len() * std::mem::size_of::<FindingRef>());
/// Small: kept for many runs, so a Runs list reads each event once.
static COMPLETENESS: RunCache<Option<state::CompletenessPoint>> = RunCache::new(400, |_| 0);
static RUN_SOURCES: RunCache<Option<pathwarden_core::opengraph::coverage::RunSources>> =
    RunCache::new(8, |_| 0);

/// Every graph [`graph`] read that is still in memory, by run folder:
/// [`GRAPHS`] may let go of one Explore still holds, and it isn't read
/// again beside it.
static SHARED: Mutex<Vec<(PathBuf, Weak<AdGraph>)>> = Mutex::new(Vec::new());

/// Estimated bytes per object of a graph read from an object index (the
/// object, its strings, its place in the ID index), and per relation.
/// Measured on a synthetic 500,000-object domain.
pub(crate) const GRAPH_OBJECT_BYTES: usize = 800;
const GRAPH_EDGE_BYTES: usize = 32;
/// Estimated bytes per kept field of an object ([`PROPS`]).
const PROP_CELL_BYTES: usize = 40;

/// A graph's estimated bytes, from its object and edge counts.
pub(crate) fn graph_weight(g: &AdGraph) -> usize {
    g.node_count() * GRAPH_OBJECT_BYTES + g.edge_count() * GRAPH_EDGE_BYTES
}

/// From now on, lets go of every run that has had no request for [`IDLE`],
/// looking every [`SWEEP_EVERY`] on a thread of its own (the app calls it
/// once at start; again does nothing). What is let go is read again when
/// next asked for.
pub fn release_when_idle() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("release-idle-runs".into())
            .spawn(|| loop {
                std::thread::sleep(SWEEP_EVERY);
                sweep(IDLE, Instant::now());
            });
    });
}

/// Lets go of the runs without a request since `idle` before `now`, in
/// every cache of what a run's size makes large (the completeness and
/// sources caches keep a few bytes per run).
fn sweep(idle: Duration, now: Instant) {
    let logged = pathwarden_core::timing::enabled();
    let before = logged.then(cache_weights);
    GRAPHS.sweep(idle, now);
    PROPS.sweep(idle, now);
    FINDINGS.sweep(idle, now);
    crate::explore_ui::sweep(idle, now);
    crate::retest_ui::sweep(idle, now);
    if let Some(before) = before {
        let after = cache_weights();
        if after != before {
            print_weights("released idle runs", &after);
        }
    }
}

/// What each cache of runs holds: its name, its runs, and their estimated
/// bytes together. A graph Explore shares is counted under graphs only.
fn cache_weights() -> Vec<(&'static str, usize, usize)> {
    [
        ("graphs", GRAPHS.weighs()),
        ("explore edges", crate::explore_ui::edge_weights()),
        ("props", PROPS.weighs()),
        ("findings", FINDINGS.weighs()),
        ("retest slices", crate::retest_ui::weighs()),
        ("sources", RUN_SOURCES.weighs()),
        ("completeness", COMPLETENESS.weighs()),
    ]
    .into_iter()
    .map(|(name, (runs, bytes))| (name, runs, bytes))
    .collect()
}

/// With `PATHWARDEN_TIMINGS=1`, what each cache holds on stderr, after
/// `what`. Weighed only then.
pub(crate) fn log_weights(what: &str) {
    if pathwarden_core::timing::enabled() {
        print_weights(what, &cache_weights());
    }
}

fn print_weights(what: &str, w: &[(&'static str, usize, usize)]) {
    let held: Vec<String> = w
        .iter()
        .filter(|(_, runs, _)| *runs > 0)
        .map(|(name, runs, bytes)| format!("{name} {runs} run(s), {} MB", bytes >> 20))
        .collect();
    let held = if held.is_empty() {
        "nothing".to_string()
    } else {
        held.join("; ")
    };
    eprintln!("[cache] {what}; held: {held}");
}

/// The most a run's `.gz` file may inflate to. Pathwarden writes these files
/// itself (the largest, a 1.27-million-object forest's object index, is a few
/// hundred MB), so this only stops a damaged or planted file from taking all
/// memory.
pub const MAX_GZ_BYTES: u64 = 2 << 30;

/// A gzip file of the workspace, inflated, at most [`MAX_GZ_BYTES`].
pub fn read_gz(path: &Path) -> std::io::Result<Vec<u8>> {
    read_gz_capped(path, MAX_GZ_BYTES)
}

/// The event document of the run in `run_dir`, inflated: every reader of
/// one goes through here, so one of a schema this version doesn't read
/// (a newer Pathwarden's, docs/dev/formats.md) is never read as v1. An error
/// when it is missing, can't be read, or is of another schema.
pub fn read_event(run_dir: &Path) -> std::io::Result<Vec<u8>> {
    let bytes = read_gz(&run_dir.join(EVENT_FILE))?;
    if !pathwarden_core::event::readable(&bytes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            NEWER_EVENT_WORDS,
        ));
    }
    Ok(bytes)
}

/// [`read_event`]'s error in words: no findings saved, or a newer
/// Pathwarden's.
pub fn event_error(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::InvalidData && e.to_string() == NEWER_EVENT_WORDS {
        NEWER_EVENT_WORDS.into()
    } else {
        "This run has no saved findings.".into()
    }
}

/// What a run whose event document a newer Pathwarden wrote says.
pub const NEWER_EVENT_WORDS: &str =
    "A newer Pathwarden saved this run's findings. Update Pathwarden to read them.";

fn read_gz_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    GzDecoder::new(std::io::BufReader::new(f))
        .take(cap + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > cap {
        return Err(std::io::Error::other(format!(
            "{} inflates to more than {cap} bytes",
            path.display()
        )));
    }
    Ok(out)
}

/// Run object indexes being read into memory now: pages that wait
/// on one say so ([`loading_run`]).
static LOADING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether a run is being read into memory now (`/api/busy`).
pub fn loading_run() -> bool {
    LOADING.load(std::sync::atomic::Ordering::Relaxed) > 0
}

/// Counts a read in [`LOADING`] for as long as it lives.
struct Loading;

impl Loading {
    fn start() -> Self {
        LOADING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Loading
    }
}

impl Drop for Loading {
    fn drop(&mut self) {
        LOADING.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The run's objects as a graph (blocking: call from a blocking task).
pub fn graph(run_dir: &Path) -> Option<Arc<AdGraph>> {
    let mut read = false;
    let g = GRAPHS
        .get_or_load_shared(run_dir, || {
            if let Some(g) = shared(run_dir) {
                return Ok(g);
            }
            // One object index read at a time: each takes the index and the
            // graph at once, so loads of several runs would add those up. A
            // loaded graph never waits for this.
            static READING: Mutex<()> = Mutex::new(());
            let _loading = Loading::start();
            let _reading = READING.lock().unwrap_or_else(|e| e.into_inner());
            let started = Instant::now();
            let index = read_index(&run_dir.join(OBJECTS_FILE)).ok_or(())?;
            // A newer Pathwarden's index: not read as this one's.
            if !pathwarden_core::formats::of_u32(
                index.version,
                pathwarden_core::object_index::INDEX_VERSION,
            )
            .is_known()
            {
                return Err(());
            }
            let g = Arc::new(index.into_graph());
            pathwarden_core::timing::report("run object index read", started.elapsed());
            let mut live = SHARED.lock().unwrap_or_else(|e| e.into_inner());
            live.retain(|(d, w)| w.strong_count() > 0 && d != run_dir);
            live.push((run_dir.to_path_buf(), Arc::downgrade(&g)));
            read = true;
            Ok::<_, ()>(g)
        })
        .ok();
    if read {
        log_weights("graph read");
    }
    g
}

/// The graph of the run in `run_dir`, if one is still in memory.
fn shared(run_dir: &Path) -> Option<Arc<AdGraph>> {
    let live = SHARED.lock().unwrap_or_else(|e| e.into_inner());
    live.iter()
        .find(|(d, _)| d == run_dir)
        .and_then(|(_, w)| w.upgrade())
}

/// An object index file, read. Inflated first: parsing from a slice is
/// about twice as fast as from a reader, and the text is small beside the
/// graph made of it (60 MB for a 500,000-object directory's 450 MB graph),
/// let go before the graph is made.
fn read_index(path: &Path) -> Option<ObjectIndex> {
    let text = read_gz(path).ok()?;
    serde_json::from_slice(&text).ok()
}

/// The run's objects' analysis fields, for queries (blocking), or why
/// there are none: saved before runs kept them, by a newer Pathwarden, or
/// damaged.
pub fn props(
    run_dir: &Path,
) -> Result<Arc<pathwarden_core::cypher::RunProps>, pathwarden_core::cypher::NoProps> {
    use pathwarden_core::cypher::{NoProps, RunProps};
    PROPS.get_or_load(run_dir, || {
        let path = run_dir.join(PROPS_FILE);
        if !path.is_file() {
            return Err(NoProps::Absent);
        }
        let text = read_gz(&path).map_err(|_| NoProps::Unreadable)?;
        // The version first: a newer file may be shaped otherwise.
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let v: Version = serde_json::from_slice(&text).map_err(|_| NoProps::Unreadable)?;
        if v.version > pathwarden_core::cypher::PROPS_VERSION {
            return Err(NoProps::Newer);
        }
        serde_json::from_slice::<RunProps>(&text).map_err(|_| NoProps::Unreadable)
    })
}

/// [`props`] as [`pathwarden_core::cypher::RunView::new`] takes it.
pub fn props_ref(
    p: &Result<Arc<pathwarden_core::cypher::RunProps>, pathwarden_core::cypher::NoProps>,
) -> Result<&pathwarden_core::cypher::RunProps, pathwarden_core::cypher::NoProps> {
    match p {
        Ok(p) => Ok(p),
        Err(e) => Err(*e),
    }
}

/// The run's findings (blocking).
pub fn findings(run_dir: &Path) -> Option<Arc<Vec<FindingRef>>> {
    FINDINGS
        .get_or_load(run_dir, || {
            let text = read_event(run_dir).map_err(|_| ())?;
            let ev: EventFindings = serde_json::from_slice(&text).map_err(|_| ())?;
            Ok::<_, ()>(ev.findings)
        })
        .ok()
}

/// The run's collection completeness, from its summary when it has it
/// (runs saved since it was recorded), else read once from its event
/// document, findings skipped (blocking). `None` when neither says.
pub fn completeness(ws: &Workspace, r: &RunSummary) -> Option<state::CompletenessPoint> {
    completeness_in(&ws.runs_dir(), r)
}

/// [`completeness`] for a run under `runs_dir` (a workspace's `runs`).
pub fn completeness_in(runs_dir: &Path, r: &RunSummary) -> Option<state::CompletenessPoint> {
    if let Some(c) = &r.completeness {
        return Some(c.clone());
    }
    // The event may come from another computer (a run loaded from the
    // history): read as it inflates, up to Home's limit, with as many
    // domains as Home reads.
    #[derive(Deserialize)]
    struct Doc {
        /// [`pathwarden_core::event::schema_ok`].
        #[serde(default)]
        schema: Option<String>,
        #[serde(default)]
        posture: PostureDoc,
    }
    #[derive(Default, Deserialize)]
    struct PostureDoc {
        #[serde(
            default,
            deserialize_with = "crate::home_overview::at_most::<_, pathwarden_core::posture::Completeness, {crate::home_overview::MAX_DOMAINS}>"
        )]
        completeness: Vec<pathwarden_core::posture::Completeness>,
    }
    if !crate::workspace::valid_run_id(&r.id) {
        return None;
    }
    let dir = runs_dir.join(&r.id);
    // A run whose event can't be read is remembered as such (`None`), so
    // it isn't read again on every page.
    COMPLETENESS
        .get_or_load(&dir, || {
            let read = || -> Option<state::CompletenessPoint> {
                let f = std::fs::File::open(dir.join(EVENT_FILE)).ok()?;
                let gz = GzDecoder::new(std::io::BufReader::new(f))
                    .take(crate::home_overview::EVENT_LIMIT);
                let doc: Doc = serde_json::from_reader(std::io::BufReader::new(gz)).ok()?;
                if !pathwarden_core::event::schema_ok(doc.schema.as_deref()) {
                    return None;
                }
                state::CompletenessPoint::new(&doc.posture.completeness)
            };
            Ok::<_, ()>(read())
        })
        .ok()
        .and_then(|c| (*c).clone())
}

/// What a run's data sources covered (OpenGraph sources, SYSVOL parts,
/// other tools' reports), as saved with it ([`RUN_SOURCES_FILE`]); `None`
/// for runs saved before it was (blocking). A retest judges a finding that
/// rests on a source by it.
pub fn run_sources(run_dir: &Path) -> Option<pathwarden_core::opengraph::coverage::RunSources> {
    RUN_SOURCES
        .get_or_load(run_dir, || {
            let read = || {
                let text = read_gz_capped(
                    &run_dir.join(RUN_SOURCES_FILE),
                    crate::home_overview::EVENT_LIMIT,
                )
                .ok()?;
                serde_json::from_slice(&text).ok()
            };
            Ok::<_, ()>(read())
        })
        .ok()
        .and_then(|s| (*s).clone())
}

/// What a run targeted, domain by domain ([`pathwarden_core::since::targeting`]):
/// runs compare like with like by it.
pub fn targeting(
    ws: &Workspace,
    r: &RunSummary,
) -> (pathwarden_core::posture::Untargeted, Vec<String>) {
    pathwarden_core::since::targeting(completeness(ws, r).as_ref())
}

/// The run's event document as JSON text (blocking).
pub fn event_text(run_dir: &Path) -> Option<String> {
    String::from_utf8(read_event(run_dir).ok()?).ok()
}

/// The run's account lists ([`EXPOSED_FILE`]), blocking: `None` when the
/// run has none (saved before they were kept), an error in words when
/// they can't be read.
pub fn exposure_lists(
    run_dir: &Path,
) -> Option<Result<pathwarden_core::exposed::ExposureLists, String>> {
    let path = run_dir.join(EXPOSED_FILE);
    if !path.is_file() {
        return None;
    }
    Some(
        read_gz_capped(&path, pathwarden_core::exposed::MAX_LISTS_BYTES)
            .map_err(|e| {
                // The path and size go to the log, not the page.
                pathwarden_core::logs::note(&format!("The run's account lists: {e}"));
                if e.kind() == std::io::ErrorKind::Other {
                    "The run's account lists are too large to read.".to_string()
                } else {
                    "The run's account lists can't be read.".to_string()
                }
            })
            .and_then(|b| pathwarden_core::exposed::ExposureLists::parse(&b)),
    )
}

/// Writes `bytes` gzipped (tests build indexes this way).
pub fn write_gz(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
    enc.write_all(bytes)?;
    std::fs::write(path, enc.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run being read counts as loading for as long as its read lasts.
    /// Other tests may read runs at the same time, so only "while
    /// held" is certain.
    #[test]
    fn a_read_counts_as_loading_while_it_lasts() {
        let read = Loading::start();
        assert!(loading_run());
        drop(read);
    }

    #[test]
    fn gz_reads_are_bounded() {
        let p = std::env::temp_dir().join(format!("pathwarden-gz-{}.gz", std::process::id()));
        write_gz(&p, &[b' '; 4096]).unwrap();
        assert_eq!(read_gz_capped(&p, 4096).unwrap().len(), 4096);
        assert!(read_gz_capped(&p, 4095).is_err());
        assert_eq!(read_gz(&p).unwrap().len(), 4096);
        std::fs::remove_file(&p).unwrap();
    }

    /// A run's kept fields say why they are missing: never kept, a newer
    /// Pathwarden's, or damaged.
    #[test]
    fn run_props_say_why_they_are_missing() {
        use pathwarden_core::cypher::{NoProps, Value};
        let base = std::env::temp_dir().join(format!("pathwarden-props-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for (name, text, want) in [
            ("absent", None, Some(NoProps::Absent)),
            (
                "newer",
                Some(r#"{"version": 9, "rows": []}"#),
                Some(NoProps::Newer),
            ),
            ("damaged", Some("{"), Some(NoProps::Unreadable)),
            (
                "kept",
                Some(r#"{"version": 1, "columns": {"hasspn": [[0, true]]}}"#),
                None,
            ),
        ] {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(t) = text {
                write_gz(&dir.join(PROPS_FILE), t.as_bytes()).unwrap();
            }
            match (props(&dir), want) {
                (Err(got), Some(want)) => assert_eq!(got, want, "{name}"),
                (Ok(p), None) => assert_eq!(p.get(0, "hasspn"), Value::Bool(true)),
                (got, want) => panic!("{name}: {:?} for {want:?}", got.map(|_| ())),
            }
        }
        assert_ne!(NoProps::Newer.note(), NoProps::Absent.note());
        assert!(NoProps::Newer.note().contains("newer Pathwarden"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The object index a run keeps reads back as the graph it was made of.
    #[test]
    fn the_object_index_round_trips() {
        let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let (g, _) = pathwarden_core::load(&[forest], &Default::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("pathwarden-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = ObjectIndex::from_graph(&g);
        write_gz(
            &dir.join(OBJECTS_FILE),
            &serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
        let back = graph(&dir).unwrap();
        assert_eq!(back.node_count(), g.node_count());
        for (ix, n) in g.nodes() {
            let m = back.node(ix);
            assert_eq!(
                (&m.id, &m.name, m.tier_zero, m.is_dc),
                (&n.id, &n.name, n.tier_zero, n.is_dc)
            );
            // External kinds are kept as Base.
            if !n.kind.is_external() {
                assert_eq!(m.kind, n.kind, "{}", n.id);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn run(name: &str) -> PathBuf {
        PathBuf::from(format!("runs/{name}"))
    }

    fn newest() -> Option<PathBuf> {
        Some(run("newest"))
    }

    /// Loads `name` into `cache` (its value is its name) unless it is there;
    /// whether it was loaded.
    fn load(cache: &RunCache<String>, name: &str) -> bool {
        let mut loaded = false;
        cache
            .get_or_load(&run(name), || {
                loaded = true;
                Ok::<_, ()>(name.to_string())
            })
            .unwrap();
        loaded
    }

    #[test]
    fn the_newest_run_stays_and_the_least_recently_used_goes() {
        let cache = RunCache::pinning(2, |v: &String| v.len(), newest);
        for name in ["newest", "a", "b"] {
            assert!(load(&cache, name));
        }
        assert!(!load(&cache, "newest"));
        assert!(!load(&cache, "a"));
        // Two others besides the newest run: "b" was used longest ago.
        assert!(load(&cache, "c"));
        assert!(!load(&cache, "newest"));
        assert!(!load(&cache, "a"));
        assert!(!load(&cache, "c"));
        assert!(load(&cache, "b"));
        // "newest", however long ago it was used.
        for name in ["d", "e", "f"] {
            assert!(load(&cache, name));
        }
        assert!(!load(&cache, "newest"));
        // A load that fails keeps nothing and leaves the rest.
        assert!(cache.get_or_load(&run("bad"), || Err(())).is_err());
        assert!(!load(&cache, "f"));
        assert!(cache.state().loading.is_empty());
    }

    #[test]
    fn large_runs_keep_fewer_others() {
        // A MB per character.
        let cache = RunCache::pinning(RECENT, |v: &String| v.len() << 20, newest);
        let sized = |name: &str, mb: usize| {
            cache
                .get_or_load(&run(name), || Ok::<_, ()>("x".repeat(mb)))
                .unwrap();
        };
        let kept =
            || -> Vec<PathBuf> { cache.state().runs.iter().map(|r| r.dir.clone()).collect() };
        assert!(load(&cache, "newest"));
        // Two 500,000-object runs (about 530 MB each) stay besides it.
        sized("r1", 530);
        sized("r2", 530);
        assert_eq!(kept(), [run("newest"), run("r1"), run("r2")]);
        // "big", used last, stays whatever its size; the others go.
        sized("big", OTHER_WEIGHT >> 20);
        assert_eq!(kept(), [run("newest"), run("big")]);
        // With "a", "big" is past the limit.
        assert!(load(&cache, "a"));
        assert!(!load(&cache, "newest"));
        assert_eq!(kept(), [run("a"), run("newest")]);
        assert_eq!(cache.weighs(), (2, ("newest".len() + 1) << 20));
    }

    /// Runs without a request for a while are let go, the newest too, and
    /// read again when asked for.
    #[test]
    fn idle_runs_are_let_go() {
        let cache = RunCache::pinning(2, |v: &String| v.len(), newest);
        for name in ["newest", "a", "b"] {
            assert!(load(&cache, name));
        }
        let start = Instant::now();
        cache.sweep(IDLE, start + IDLE / 2);
        assert_eq!(cache.weighs().0, 3);
        // "a" asked for meanwhile.
        cache.state().runs[1].used = start + IDLE / 2;
        cache.sweep(IDLE, start + IDLE);
        let kept: Vec<PathBuf> = cache.state().runs.iter().map(|r| r.dir.clone()).collect();
        assert_eq!(kept, [run("a")]);
        assert!(load(&cache, "newest"));
        cache.sweep(IDLE, Instant::now() + IDLE * 2);
        assert_eq!(cache.weighs(), (0, 0));
    }

    /// A graph Explore still holds after the object cache let it go isn't
    /// read again.
    #[test]
    fn a_graph_held_elsewhere_is_shared() {
        let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let (g, _) = pathwarden_core::load(&[forest], &Default::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("pathwarden-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = ObjectIndex::from_graph(&g);
        write_gz(
            &dir.join(OBJECTS_FILE),
            &serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
        let held = graph(&dir).unwrap();
        GRAPHS.state().runs.retain(|r| r.dir != dir);
        let again = graph(&dir).unwrap();
        assert!(Arc::ptr_eq(&held, &again));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_run_loads_once_and_holds_up_no_other() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;
        // A while between the load and the cache, for a request that woke
        // too early to load the run again.
        static CACHE: RunCache<String> = RunCache::pinning(2, |v: &String| v.len(), newest)
            .landing(|| std::thread::sleep(Duration::from_millis(50)));
        static LOADS: AtomicUsize = AtomicUsize::new(0);
        assert!(load(&CACHE, "ready"));
        let (release, wait) = mpsc::channel::<()>();
        let slow = |wait: Option<mpsc::Receiver<()>>| {
            std::thread::spawn(move || {
                CACHE
                    .get_or_load(&run("slow"), || {
                        LOADS.fetch_add(1, Ordering::SeqCst);
                        if let Some(w) = wait {
                            w.recv().unwrap();
                        }
                        Ok::<_, ()>("slow".to_string())
                    })
                    .unwrap()
            })
        };
        let first = slow(Some(wait));
        while LOADS.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        // Several requests wait on the load (each holds its lock), so all of
        // them wake the moment it ends.
        let waiting: Vec<_> = (0..8).map(|_| slow(None)).collect();
        let lock_holders = || {
            let s = CACHE.state();
            s.loading
                .iter()
                .map(|(_, f)| Arc::strong_count(f))
                .sum::<usize>()
        };
        while lock_holders() < 2 + waiting.len() {
            std::thread::yield_now();
        }
        // Meanwhile another run loads, and a loaded one answers.
        let (done, other) = mpsc::channel();
        std::thread::spawn(move || {
            let loaded = load(&CACHE, "other");
            let cached = !load(&CACHE, "ready");
            done.send(loaded && cached).unwrap();
        });
        assert_eq!(other.recv_timeout(Duration::from_secs(30)), Ok(true));
        release.send(()).unwrap();
        assert_eq!(*first.join().unwrap(), "slow");
        for w in waiting {
            assert_eq!(*w.join().unwrap(), "slow");
        }
        assert_eq!(LOADS.load(Ordering::SeqCst), 1);
        assert!(CACHE.state().loading.is_empty());
    }

    #[test]
    fn a_load_that_panics_leaves_nothing_loading() {
        let cache = RunCache::pinning(2, |v: &String| v.len(), newest);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.get_or_load(&run("a"), || -> Result<String, ()> { panic!("damaged") })
        }));
        assert!(panicked.is_err());
        assert!(cache.state().loading.is_empty());
        assert!(load(&cache, "a"));
    }

    #[test]
    fn findings_dont_wait_for_a_graph_loading() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("pathwarden-run-data-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let event = r#"{"findings": [{"fingerprint": "PW-001-0", "rule": "PW-001", "title": "t", "severity": "high"}]}"#;
        write_gz(&dir.join(EVENT_FILE), event.as_bytes()).unwrap();
        // A large graph of the same run is loading.
        let (release, wait) = mpsc::channel::<()>();
        let (started, loading) = mpsc::channel();
        let graph_dir = dir.clone();
        let graph = std::thread::spawn(move || {
            GRAPHS.get_or_load(&graph_dir, || {
                started.send(()).unwrap();
                wait.recv().unwrap();
                Err::<AdGraph, ()>(())
            })
        });
        loading.recv().unwrap();
        let (done, found) = mpsc::channel();
        let findings_dir = dir.clone();
        std::thread::spawn(move || done.send(findings(&findings_dir).map(|f| f.len())).unwrap());
        assert_eq!(found.recv_timeout(Duration::from_secs(30)), Ok(Some(1)));
        release.send(()).unwrap();
        assert!(graph.join().unwrap().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
