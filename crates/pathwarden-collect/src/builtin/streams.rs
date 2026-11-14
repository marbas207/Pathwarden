//! The read in parallel: several streams, each on its own
//! LDAP connection, drain the chunks of the read's plan ([`cache::plan`]).
//!
//! - **Who reads what.** Stream 1 reads the small naming contexts and the
//!   domain head first, then joins the others on the 64 `uSNChanged`
//!   windows. The delta is read last, once every window is done: it holds
//!   what changed while they were read. Then the rest chunk: the domain
//!   listed by DN alone, and each object no range returned (one whose
//!   `uSNChanged` the account can't read) read on its own. With one stream
//!   the chunks are read in the plan's order, as before.
//! - **Order on disk.** Chunks finish in any order. [`cache::Reader`] reads
//!   them back in a fixed one (Schema, head, windows, delta, the rest), so
//!   the parser sees the same entries in the same order whatever the
//!   streams did.
//! - **The checkpoint.** One writer thread takes every stream's pages
//!   ([`cache::Writer`]); a stream has one chunk, so one `.part`, open at a
//!   time. A chunk is called done only after its `.seg` is renamed.
//! - **Slowing down.** [`Backoff`]: when a stream's recent page waits (p95)
//!   pass twice the first minute's, or the domain controller says busy or
//!   over a limit, one stream fewer reads (never under one). A chunk the DC
//!   refused that way is read again.
//! - **Failures.** A chunk that fails is read once more on a new
//!   connection; failing again stops the read, which can be resumed.
//!
//! The streams are futures polled together in one task ([`join_all`]): the
//! sources need not be `Send`, and shared state is a `RefCell` never held
//! across an `.await`. ldap3's connections each have their own driver
//! task, and ranged retrieval its own workers ([`super::ranged`]).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

use super::timings::{self, Timings};
use super::{
    cache, category, entry_bytes, kind_of, log_memory, nc_kind, static_kind, Category, Lookup, Msg,
    Page, PageSource, ReadOut, Sink, MEMORY_EVERY_PAGES,
};

/// Streams when `collect.read_streams` and `--read-streams` don't say.
pub(crate) const DEFAULT_STREAMS: usize = 4;
/// Never more than this many at once.
pub(crate) const MAX_STREAMS: usize = 8;

/// `asked` within 1 to [`MAX_STREAMS`]; [`DEFAULT_STREAMS`] when not set.
pub(crate) fn streams(asked: Option<usize>) -> usize {
    asked.unwrap_or(DEFAULT_STREAMS).clamp(1, MAX_STREAMS)
}

/// Where the streams get their pages: a source per stream, each on a
/// connection of its own.
pub(super) trait Streams {
    type Source: PageSource;
    /// A source for stream `stream` (from 0). `fresh`: the last one failed,
    /// so a new connection.
    async fn open(&self, stream: usize, fresh: bool) -> Result<Self::Source, String>;
    /// A stream is done with its source.
    async fn release(&self, source: Self::Source) {
        drop(source);
    }
}

/// One source, lent: one stream, no second connection to retry on.
pub(super) struct Single<'a, P>(RefCell<Option<&'a mut P>>);

impl<'a, P> Single<'a, P> {
    pub(super) fn new(pages: &'a mut P) -> Self {
        Self(RefCell::new(Some(pages)))
    }
}

impl<'a, P: PageSource> Streams for Single<'a, P> {
    type Source = &'a mut P;
    async fn open(&self, _stream: usize, _fresh: bool) -> Result<&'a mut P, String> {
        self.0
            .borrow_mut()
            .take()
            .ok_or_else(|| "there is no other connection to read it again on".to_string())
    }
}

impl<P: PageSource> PageSource for &mut P {
    async fn start(&mut self, chunk: &cache::Chunk, filter: &str) -> Result<(), String> {
        (**self).start(chunk, filter).await
    }
    async fn start_rest(
        &mut self,
        chunk: &cache::Chunk,
        filter: &str,
        lookup: Lookup<'_>,
    ) -> Result<(), String> {
        (**self).start_rest(chunk, filter, lookup).await
    }
    async fn next_page(&mut self) -> Result<Option<Page>, String> {
        (**self).next_page().await
    }
    async fn end(&mut self) -> Result<(), String> {
        (**self).end().await
    }
    fn take_gone(&mut self) -> Vec<String> {
        (**self).take_gone()
    }
}

/// A future polled in this task ([`join_all`]).
pub(super) type LocalFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Runs `futures` together in this task; their outputs in order.
pub(super) async fn join_all<'a, T>(futures: Vec<LocalFut<'a, T>>) -> Vec<T> {
    let mut futures: Vec<Option<LocalFut<'a, T>>> = futures.into_iter().map(Some).collect();
    let mut out: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (f, o) in futures.iter_mut().zip(out.iter_mut()) {
            if let Some(fut) = f {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(v) => {
                        *o = Some(v);
                        *f = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    out.into_iter().flatten().collect()
}

/// Whether the domain controller refused for load, not for a fault: busy
/// (51), an administrative limit (11) or a time limit (3).
pub(super) fn dc_overloaded(e: &str) -> bool {
    ["(busy)", "(adminLimitExceeded)", "(timeLimitExceeded)"]
        .iter()
        .any(|w| e.contains(w))
}

/// When the read slows down by itself: the page waits that are normal
/// (the baseline), and each stream's recent ones.
#[derive(Debug, Clone)]
pub(super) struct Backoff {
    /// Page waits before the baseline is set.
    first: Vec<Duration>,
    baseline: Option<Duration>,
    /// Each stream's last [`Backoff::WINDOW`] page waits.
    recent: Vec<VecDeque<Duration>>,
}

/// Why the read slowed down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Slower {
    pub p95: Duration,
    pub baseline: Duration,
}

impl Backoff {
    /// The longest the baseline is taken over.
    pub const FIRST: Duration = Duration::from_secs(60);
    /// Page waits a stream's p95 is taken over.
    pub const WINDOW: usize = 20;
    /// Waits needed before a p95 means anything.
    pub const MIN_SAMPLES: usize = 10;
    /// Slower by less than this is noise, whatever the ratio (a LAN's
    /// pages come in milliseconds).
    pub const MIN_SLOWER: Duration = Duration::from_millis(250);

    pub(super) fn new(streams: usize) -> Self {
        Self {
            first: Vec::new(),
            baseline: None,
            recent: vec![VecDeque::new(); streams.max(1)],
        }
    }

    /// The baseline, once known.
    pub(super) fn baseline(&self) -> Option<Duration> {
        self.baseline
    }

    /// Page waits taken toward the baseline so far.
    fn samples(&self) -> usize {
        self.first.len()
    }

    /// The page waits so far are the baseline, when there are enough: stream
    /// 1 reading alone, before the others start.
    pub(super) fn settle(&mut self) {
        if self.baseline.is_none() && self.first.len() >= Self::MIN_SAMPLES {
            self.baseline = p95(&self.first);
            self.first = Vec::new();
        }
    }

    /// A page's wait on `stream`, `at` after the read started, with `live`
    /// streams reading. Returns why the read should slow down when it
    /// should: then each stream's recent waits start again, one step at a
    /// time. Without a baseline yet, the first minute's waits make one.
    pub(super) fn page(
        &mut self,
        stream: usize,
        wait: Duration,
        at: Duration,
        live: usize,
    ) -> Option<Slower> {
        if self.baseline.is_none() {
            self.first.push(wait);
            if at >= Self::FIRST {
                self.settle();
            }
        }
        let recent = self.recent.get_mut(stream)?;
        recent.push_back(wait);
        while recent.len() > Self::WINDOW {
            recent.pop_front();
        }
        let baseline = self.baseline?;
        if live <= 1 || recent.len() < Self::MIN_SAMPLES {
            return None;
        }
        let now = p95(recent.make_contiguous())?;
        if now <= baseline * 2 || now < baseline + Self::MIN_SLOWER {
            return None;
        }
        for r in &mut self.recent {
            r.clear();
        }
        Some(Slower { p95: now, baseline })
    }
}

/// The 95th percentile of `d`.
pub(super) fn p95(d: &[Duration]) -> Option<Duration> {
    if d.is_empty() {
        return None;
    }
    let mut v = d.to_vec();
    v.sort();
    Some(v[((v.len() - 1) as f64 * 0.95).round() as usize])
}

/// How long a part the domain controller refused for load waits before it
/// is read again: this, then twice as long each time, at most
/// [`REFUSED_WAIT_MAX`] times it.
pub(crate) const REFUSED_WAIT: Duration = Duration::from_secs(5);
/// The longest wait is this many [`REFUSED_WAIT`]s (30 s).
const REFUSED_WAIT_MAX: u32 = 6;
/// With one stream left, refused parts wait at most this many
/// [`REFUSED_WAIT`]s in all (2 minutes) before the read stops.
const REFUSED_TOTAL: u32 = 24;
/// Stream 1 reads alone until it has read this many pages of the
/// domain's windows (or for [`Backoff::FIRST`]): their waits are the
/// baseline, taken before the others add to the DC's load.
pub(super) const ALONE_PAGES: usize = Backoff::MIN_SAMPLES;

/// What the read does with its chunks.
pub(super) struct Plan<'a> {
    pub filter: &'a str,
    pub chunks: &'a [cache::Chunk],
    pub domain_nc: &'a str,
    pub tx: &'a mpsc::Sender<Msg>,
    /// Streams asked for ([`streams`]).
    pub streams: usize,
    /// The first wait before a part refused for load is read again
    /// ([`REFUSED_WAIT`]; the tests' is shorter).
    pub refused_wait: Duration,
}

/// What [`read`] read.
pub(super) struct Read {
    pub out: ReadOut,
    /// The `scriptPath` of every entry read, as given: SYSVOL's logon
    /// scripts are read once the read ends ([`super::sysvol`]).
    pub scripts: BTreeSet<String>,
}

/// Why a chunk wasn't read.
enum ChunkError {
    /// The source failed: read it again, on a new connection.
    Read(String),
    /// Writing it failed: the read stops.
    Fatal(String),
    /// Another stream failed: this one stops too.
    Stopped,
}

/// A chunk to read, not before a time when the DC refused it for load.
type Queued = (cache::Chunk, Option<Instant>);

/// Chunks to read: stream 1's first ones, then everybody's.
struct Queue {
    first: VecDeque<Queued>,
    shared: VecDeque<Queued>,
}

impl Queue {
    /// Whether a window is still to be read.
    fn has_window(&self) -> bool {
        self.first
            .iter()
            .chain(&self.shared)
            .any(|(c, _)| c.kind == cache::Kind::Window)
    }

    fn is_empty(&self) -> bool {
        self.first.is_empty() && self.shared.is_empty()
    }
}

/// A naming context's timing, across its chunks and streams.
struct NcRead {
    timing: timings::NcTiming,
    /// When its first chunk started, and its last ended.
    started: Option<Instant>,
    ended: Option<Instant>,
    /// Its chunks not yet read.
    left: usize,
}

/// What the streams share. Borrows never cross an `.await`.
struct Shared<'a> {
    plan: &'a Plan<'a>,
    /// Streams at the start.
    n: usize,
    sink: RefCell<Sink>,
    queue: RefCell<Queue>,
    backoff: RefCell<Backoff>,
    /// The streams running now.
    live: RefCell<BTreeSet<usize>>,
    /// Those told to stop after their chunk (the read slowed down).
    stopping: RefCell<BTreeSet<usize>>,
    /// Streams lost: slowed down, or a connection that couldn't be opened.
    dropped: Cell<usize>,
    /// Stream 1 reads alone (for the baseline) while this is set.
    alone: Cell<bool>,
    /// Pages of the domain's windows stream 1 read alone.
    alone_pages: Cell<usize>,
    /// Parts refused for load so far: each waits longer.
    refusals: Cell<u32>,
    /// Waited in all, with one stream left, for refused parts.
    waited: Cell<Duration>,
    failed: RefCell<Option<String>>,
    started: Instant,
    counts: RefCell<BTreeMap<&'static str, u64>>,
    total: Cell<u64>,
    last_units: Cell<Instant>,
    pages: Cell<u64>,
    ncs: RefCell<BTreeMap<String, NcRead>>,
    ranged: Cell<(u64, u64, Duration)>,
    detail: RefCell<String>,
    parts: u64,
    parts_done: Cell<u64>,
    /// Streams shown: with a plan in parts.
    show_streams: bool,
    scripts: RefCell<BTreeSet<String>>,
    /// The [`cache::dn_key`]s of the domain's objects the head, the windows
    /// and the delta returned, while the rest chunk is still to read.
    seen: RefCell<Option<HashSet<u128>>>,
}

impl Shared<'_> {
    fn send(&self, m: Msg) {
        let _ = self.plan.tx.send(m);
    }

    fn log(&self, line: String) {
        self.send(Msg::Log(line));
    }

    fn fail(&self, why: String) {
        self.failed.borrow_mut().get_or_insert(why);
    }

    fn failed(&self) -> bool {
        self.failed.borrow().is_some()
    }

    /// Streams reading now, as shown: those at the start less those lost.
    fn active(&self) -> usize {
        self.n.saturating_sub(self.dropped.get()).max(1)
    }

    /// The streams still running and not told to stop.
    fn running(&self) -> usize {
        let stopping = self.stopping.borrow();
        self.live
            .borrow()
            .iter()
            .filter(|s| !stopping.contains(s))
            .count()
    }

    /// Tells the highest stream still running (never stream 1) to stop
    /// after its chunk. Returns the streams from now on, or `None` when
    /// only one runs.
    fn stop_one(&self) -> Option<usize> {
        let victim = {
            let stopping = self.stopping.borrow();
            self.live
                .borrow()
                .iter()
                .rev()
                .find(|s| **s != 0 && !stopping.contains(s))
                .copied()
        };
        let victim = victim.filter(|_| self.running() > 1)?;
        self.stopping.borrow_mut().insert(victim);
        self.dropped.set(self.dropped.get() + 1);
        self.report_streams();
        Some(self.active())
    }

    /// Stream 1 stops reading alone: the others start, and the waits so far
    /// are the baseline.
    fn end_alone(&self) {
        if self.alone.replace(false) {
            let mut b = self.backoff.borrow_mut();
            let samples = b.samples();
            b.settle();
            let line = match b.baseline() {
                Some(p) => format!(
                    "[read] page waits at first: p95 {} over {}; the other streams start",
                    timings::secs(p),
                    pathwarden_core::text::count(samples, "page", "pages")
                ),
                None => "[read] too few pages at first to say what is normal: the first \
                         minute's decide; the other streams start"
                    .to_string(),
            };
            drop(b);
            self.log(line);
        }
    }

    /// The next chunk for `stream`, if it still reads.
    fn take(&self, stream: usize) -> Option<Queued> {
        if self.failed() || self.stopping.borrow().contains(&stream) {
            return None;
        }
        let mut q = self.queue.borrow_mut();
        if stream == 0 {
            if let Some(c) = q.first.pop_front() {
                return Some(c);
            }
        }
        q.shared.pop_front()
    }

    /// `chunk` goes back to be read first, not before `at`.
    fn put_back(&self, chunk: cache::Chunk, first: bool, at: Option<Instant>) {
        let mut q = self.queue.borrow_mut();
        if first {
            q.first.push_front((chunk, at));
        } else {
            q.shared.push_front((chunk, at));
        }
    }

    fn report_streams(&self) {
        if self.show_streams {
            self.send(Msg::Streams {
                streams: self.active() as u32,
                parts: self.parts,
                done: self.parts_done.get(),
            });
        }
    }

    fn report_units(&self, force: bool) {
        if force || self.last_units.get().elapsed() >= Duration::from_millis(100) {
            self.send(Msg::Units {
                done: self.total.get(),
                total: None,
            });
            self.send(Msg::Counts(self.counts.borrow().clone()));
            self.last_units.set(Instant::now());
        }
    }

    /// The DC refused a part for load: one stream fewer, and the part waits
    /// before it is read again. `false` when only one stream runs (the
    /// refusal is then a failure like another).
    /// The next wait before a part refused for load is read again: 5 s,
    /// doubling, 30 s at most.
    fn refused_wait(&self) -> Duration {
        let k = self.refusals.get();
        self.refusals.set(k + 1);
        self.plan.refused_wait * 2u32.saturating_pow(k).min(REFUSED_WAIT_MAX)
    }

    /// With one stream left: how long to wait before reading a refused part
    /// again, or `None` once the waits would pass [`REFUSED_TOTAL`] in all
    /// (the refusal is then a failure: the read stops, to resume).
    fn busy_wait(&self) -> Option<Duration> {
        let wait = self.refused_wait();
        let total = self.waited.get() + wait;
        (total <= self.plan.refused_wait * REFUSED_TOTAL).then(|| {
            self.waited.set(total);
            wait
        })
    }

    fn overloaded(&self, stream: usize, chunk: cache::Chunk, first: bool, why: &str) -> bool {
        let Some(n) = self.stop_one() else {
            return false;
        };
        let wait = self.refused_wait();
        self.log(format!(
            "[read] stream {}: the domain controller refused for load ({}): reading with {}, \
             and that part again in {}",
            stream + 1,
            crate::one_line(why),
            pathwarden_core::text::count(n, "stream", "streams"),
            timings::secs(wait)
        ));
        self.put_back(chunk, first, Some(Instant::now() + wait));
        true
    }
}

/// Every chunk of `plan` not yet done, into `sink`, on up to
/// `plan.streams` streams from `streams`, counting and timing as it goes.
/// The chunks done before a resume count from the start. Into memory
/// (`--no-cache`), one stream reads each naming context whole in
/// RustHound-CE's order.
pub(super) async fn read<S: Streams>(
    streams: &S,
    plan: &Plan<'_>,
    timings: &mut Timings,
    sink: Sink,
) -> Result<Read, String> {
    let on_disk = matches!(sink, Sink::Disk(_));
    let windows = plan
        .chunks
        .iter()
        .any(|c| c.kind == cache::Kind::Window && !c.is_done());
    // In memory the order of arrival is the parser's: one stream.
    let n = if on_disk && windows {
        plan.streams.clamp(1, MAX_STREAMS)
    } else {
        1
    };
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut total: u64 = 0;
    // Read before the read resumed.
    for c in plan.chunks.iter().filter(|c| c.is_done()) {
        total += c.entries;
        for (kind, k) in &c.counts {
            *counts.entry(static_kind(kind)).or_default() += k;
        }
    }
    if total > 0 {
        let _ = plan.tx.send(Msg::ResumedUnits(total));
        let _ = plan.tx.send(Msg::Counts(counts.clone()));
    }
    let todo: Vec<&cache::Chunk> = plan.chunks.iter().filter(|c| !c.is_done()).collect();
    let mut first = VecDeque::new();
    let mut shared = VecDeque::new();
    let mut last = VecDeque::new();
    for c in &todo {
        let q = ((*c).clone(), None);
        match c.kind {
            cache::Kind::Delta | cache::Kind::Rest => last.push_back(q),
            cache::Kind::Window if n > 1 => shared.push_back(q),
            _ => first.push_back(q),
        }
    }
    let mut ncs = BTreeMap::new();
    for c in &todo {
        ncs.entry(c.nc.clone())
            .or_insert_with(|| NcRead {
                timing: timings::NcTiming {
                    kind: nc_kind(&c.nc, plan.domain_nc),
                    ..Default::default()
                },
                started: None,
                ended: None,
                left: 0,
            })
            .left += 1;
    }
    let sh = Shared {
        plan,
        n,
        sink: RefCell::new(sink),
        queue: RefCell::new(Queue { first, shared }),
        backoff: RefCell::new(Backoff::new(n)),
        live: RefCell::new(BTreeSet::new()),
        stopping: RefCell::new(BTreeSet::new()),
        dropped: Cell::new(0),
        alone: Cell::new(n > 1),
        alone_pages: Cell::new(0),
        refusals: Cell::new(0),
        waited: Cell::new(Duration::ZERO),
        failed: RefCell::new(None),
        started: Instant::now(),
        counts: RefCell::new(counts),
        total: Cell::new(total),
        last_units: Cell::new(Instant::now()),
        pages: Cell::new(0),
        ncs: RefCell::new(ncs),
        ranged: Cell::new((0, 0, Duration::ZERO)),
        detail: RefCell::new(String::new()),
        parts: plan.chunks.len() as u64,
        parts_done: Cell::new(plan.chunks.iter().filter(|c| c.is_done()).count() as u64),
        show_streams: windows && on_disk,
        scripts: RefCell::new(BTreeSet::new()),
        seen: RefCell::new(
            todo.iter()
                .any(|c| c.kind == cache::Kind::Rest)
                .then(HashSet::new),
        ),
    };
    if n > 1 {
        sh.log(format!(
            "[read] reading {} with {}",
            pathwarden_core::text::count(todo.len(), "part", "parts"),
            pathwarden_core::text::count(n, "stream", "streams")
        ));
    }
    sh.report_streams();
    let runs: Vec<LocalFut<'_, Option<S::Source>>> = (0..n)
        .map(|s| Box::pin(stream(&sh, streams, s, None)) as LocalFut<'_, _>)
        .collect();
    let mut sources = join_all(runs).await.into_iter();
    let mut lead = sources.next().flatten();
    for s in sources.flatten() {
        streams.release(s).await;
    }
    // A part put back once the others had stopped (refused for load, or a
    // stream that couldn't connect): stream 1 reads it, before the delta.
    if !sh.failed() && !sh.queue.borrow().is_empty() {
        lead = stream(&sh, streams, 0, lead).await;
    }
    // The delta, once every window is read: what changed meanwhile. A
    // window still to read would miss the changes made after it. Then the
    // rest chunk, which looks for what none of them returned.
    if !sh.failed() && !last.is_empty() {
        let left = sh.queue.borrow().has_window();
        debug_assert!(!left, "a window is left when the delta starts");
        if left {
            sh.fail("a part of the read was left unread before its changes were read".into());
        } else {
            sh.queue.borrow_mut().first.extend(last);
            lead = stream(&sh, streams, 0, lead).await;
        }
    }
    if let Some(s) = lead {
        streams.release(s).await;
    }
    let Shared {
        sink,
        failed,
        ncs,
        ranged,
        scripts,
        total,
        counts,
        n,
        dropped,
        ..
    } = sh;
    if let Some(why) = failed.into_inner() {
        return Err(why);
    }
    let mut ncs: Vec<NcRead> = ncs
        .into_inner()
        .into_values()
        .filter(|n| n.started.is_some())
        .collect();
    ncs.sort_by_key(|n| n.started);
    for mut nc in ncs {
        if let (Some(a), Some(b)) = (nc.started, nc.ended) {
            nc.timing.wall = b.saturating_duration_since(a);
        }
        timings.ncs.push(nc.timing);
    }
    let (entries, searches, took) = ranged.get();
    timings.ranged_entries += entries;
    timings.ranged_searches += searches;
    timings.ranged += took;
    timings.streams = Some((n, n.saturating_sub(dropped.get()).max(1)));
    let _ = plan.tx.send(Msg::Units {
        done: total.get(),
        total: None,
    });
    let counts = counts.into_inner();
    timings.read_counts = counts.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    let _ = plan.tx.send(Msg::Counts(counts));
    Ok(Read {
        out: sink.into_inner().finish()?,
        scripts: scripts.into_inner(),
    })
}

/// Sleeps until `at`, waking early when the read failed. `false` then.
async fn nap_until(sh: &Shared<'_>, at: Instant) -> bool {
    loop {
        if sh.failed() {
            return false;
        }
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        tokio::time::sleep(left.min(Duration::from_millis(50))).await;
    }
}

/// Stream `s`, counted as running while it runs.
async fn stream<S: Streams>(
    sh: &Shared<'_>,
    streams: &S,
    s: usize,
    source: Option<S::Source>,
) -> Option<S::Source> {
    // The others wait while stream 1 reads alone (for the baseline).
    while s > 0 && sh.alone.get() && !sh.failed() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sh.live.borrow_mut().insert(s);
    let source = stream_on(sh, streams, s, source).await;
    sh.live.borrow_mut().remove(&s);
    sh.stopping.borrow_mut().remove(&s);
    if s == 0 {
        // Nothing more to read alone.
        sh.end_alone();
    }
    source
}

/// Stream `s`: chunks until there are none for it, or the read failed.
/// Returns its source, for the next to use.
async fn stream_on<S: Streams>(
    sh: &Shared<'_>,
    streams: &S,
    s: usize,
    mut source: Option<S::Source>,
) -> Option<S::Source> {
    while let Some((chunk, not_before)) = sh.take(s) {
        // Where it goes back to when the DC refuses it for load.
        let first = chunk.kind != cache::Kind::Window || sh.n == 1;
        if let Some(at) = not_before {
            if !nap_until(sh, at).await {
                return source;
            }
        }
        let mut retried: Option<String> = None;
        loop {
            if source.is_none() {
                match streams.open(s, retried.is_some()).await {
                    Ok(src) => source = Some(src),
                    // An extra stream that can't connect leaves its part
                    // to the others (stream 1 always reads).
                    Err(e) if s > 0 && retried.is_none() => {
                        sh.log(format!(
                            "[read] stream {} could not connect ({}); the others read on",
                            s + 1,
                            crate::one_line(&e)
                        ));
                        // Told to stop meanwhile: counted then.
                        if !sh.stopping.borrow().contains(&s) {
                            sh.dropped.set(sh.dropped.get() + 1);
                        }
                        sh.put_back(chunk, first, not_before);
                        sh.report_streams();
                        return None;
                    }
                    Err(e) => {
                        sh.fail(match &retried {
                            // The chunk's own error says more.
                            Some(why) => why.clone(),
                            None => e,
                        });
                        return None;
                    }
                }
            }
            let src = source.as_mut()?;
            match read_chunk(sh, src, &chunk, s).await {
                Ok(()) => break,
                Err(ChunkError::Stopped) => return source,
                Err(ChunkError::Fatal(e)) => {
                    sh.fail(e);
                    return source;
                }
                Err(ChunkError::Read(e)) => {
                    if dc_overloaded(&e) {
                        if sh.overloaded(s, chunk.clone(), first, &e) {
                            break;
                        }
                        // The last stream: wait, then the same part again,
                        // a few times within a bounded total.
                        if let Some(wait) = sh.busy_wait() {
                            sh.log(format!(
                                "[read] the domain controller refused for load ({}): reading \
                                 that part again in {}",
                                crate::one_line(&e),
                                timings::secs(wait)
                            ));
                            if !nap_until(sh, Instant::now() + wait).await {
                                return source;
                            }
                            continue;
                        }
                    }
                    if retried.is_some() {
                        sh.fail(e);
                        return source;
                    }
                    sh.log(format!(
                        "[read] stream {}: a part failed ({}); reading it again on a new \
                         connection",
                        s + 1,
                        crate::one_line(&e)
                    ));
                    if let Some(old) = source.take() {
                        streams.release(old).await;
                    }
                    retried = Some(e);
                }
            }
        }
    }
    source
}

/// What one chunk read so far: added to its naming context once the chunk
/// is done, taken back when it fails.
#[derive(Default)]
struct Tally {
    mine: timings::NcTiming,
    /// When its first page came, and that page's wait.
    first_page: Option<(Instant, Duration)>,
    counts: BTreeMap<String, u64>,
    read: u64,
    ranged: (u64, u64, Duration),
}

/// One chunk, from `src` into the sink: done only once it is all there.
async fn read_chunk<P: PageSource>(
    sh: &Shared<'_>,
    src: &mut P,
    chunk: &cache::Chunk,
    s: usize,
) -> Result<(), ChunkError> {
    let cn = &chunk.nc;
    if *sh.detail.borrow() != *cn {
        *sh.detail.borrow_mut() = cn.clone();
        sh.send(Msg::Detail(cn.clone()));
    }
    if let Some(nc) = sh.ncs.borrow_mut().get_mut(cn) {
        nc.started.get_or_insert_with(Instant::now);
    }
    let rest = chunk.kind == cache::Kind::Rest;
    if !rest {
        src.start(chunk, sh.plan.filter)
            .await
            .map_err(ChunkError::Read)?;
    }
    sh.sink
        .borrow_mut()
        .begin(chunk.id, cn)
        .map_err(ChunkError::Fatal)?;
    let mut t = Tally::default();
    let outcome = if rest {
        read_rest(sh, src, chunk, s, &mut t).await
    } else {
        match drain(sh, src, chunk, s, &mut t).await {
            Ok(()) => end_search(src, cn).await,
            Err(e) => Err(e),
        }
    };
    if let Err(e) = outcome {
        // What this try counted is taken back: it is read again.
        {
            let mut counts = sh.counts.borrow_mut();
            for (kind, k) in &t.counts {
                if let Some(c) = counts.get_mut(static_kind(kind)) {
                    *c = c.saturating_sub(*k);
                }
            }
        }
        sh.total.set(sh.total.get().saturating_sub(t.read));
        let _ = sh.sink.borrow_mut().abort(chunk.id);
        sh.report_units(true);
        return Err(e);
    }
    let Tally {
        mine,
        first_page,
        counts: chunk_counts,
        ranged,
        ..
    } = t;
    sh.sink
        .borrow_mut()
        .end(chunk.id, chunk_counts)
        .map_err(ChunkError::Fatal)?;
    let (e, n, d) = sh.ranged.get();
    sh.ranged.set((e + ranged.0, n + ranged.1, d + ranged.2));
    let last_of_nc = {
        let mut ncs = sh.ncs.borrow_mut();
        let nc = ncs.get_mut(cn).ok_or(ChunkError::Stopped)?;
        match first_page {
            // The naming context's first entry: from when it started.
            Some((at, _)) if nc.timing.entries == 0 => {
                let started = nc.started.unwrap_or(at);
                nc.timing.first_entry = Some(at.saturating_duration_since(started));
            }
            // Not its first page: a page like the others.
            Some((_, wait)) => nc.timing.pages.push(wait),
            None => {}
        }
        let t = &mut nc.timing;
        t.entries += mine.entries;
        t.bytes += mine.bytes;
        t.kept += mine.kept;
        t.deleted += mine.deleted;
        t.dns += mine.dns;
        t.schema += mine.schema;
        t.other += mine.other;
        t.pages.extend(mine.pages);
        nc.ended = Some(Instant::now());
        nc.left = nc.left.saturating_sub(1);
        nc.left == 0
    };
    if last_of_nc {
        sh.log(format!("All data collected for naming context {cn}"));
    }
    sh.parts_done.set(sh.parts_done.get() + 1);
    sh.report_streams();
    sh.report_units(false);
    Ok(())
}

/// Ends the search `src` has going. One the domain controller didn't
/// return completely fails the chunk, on disk and in memory alike: it is
/// taken back out and read again, or the read stops (on disk it can be
/// resumed). Never a chunk marked done with entries missing, so a read cut
/// short can't make a collection or a retest look clean.
async fn end_search<P: PageSource>(src: &mut P, cn: &str) -> Result<(), ChunkError> {
    src.end().await.map_err(|e| {
        ChunkError::Read(format!(
            "the domain controller did not return all of {cn}: {e}"
        ))
    })
}

/// The rest chunk ([`cache::Kind::Rest`]): `chunk.nc` listed by DN alone,
/// then every object the head, the windows and the delta didn't return
/// (this read's, and those read before it resumed) read on its own, several
/// at once. An object gone by then (renamed or moved since it was listed,
/// or deleted) is counted, and the domain is listed once more for its new
/// name.
async fn read_rest<P: PageSource>(
    sh: &Shared<'_>,
    src: &mut P,
    chunk: &cache::Chunk,
    s: usize,
    t: &mut Tally,
) -> Result<(), ChunkError> {
    let mut seen = sh.seen.borrow_mut().take().unwrap_or_default();
    let read = rest_with(sh, src, chunk, s, t, &mut seen).await;
    if read.is_err() {
        // Read again: what was seen still counts.
        *sh.seen.borrow_mut() = Some(seen);
    }
    read
}

async fn rest_with<P: PageSource>(
    sh: &Shared<'_>,
    src: &mut P,
    chunk: &cache::Chunk,
    s: usize,
    t: &mut Tally,
    seen: &mut HashSet<u128>,
) -> Result<(), ChunkError> {
    let cn = &chunk.nc;
    let filter = sh.plan.filter;
    // Read before the read resumed: from their keys on disk.
    let before: Vec<&cache::Chunk> = sh
        .plan
        .chunks
        .iter()
        .filter(|c| c.is_done() && cache::sees_dns(c.kind) && c.nc == *cn)
        .collect();
    if !before.is_empty() {
        let dir = match &*sh.sink.borrow() {
            Sink::Disk(w) => Some(w.dir().to_path_buf()),
            Sink::Memory(..) => None,
        };
        if let Some(dir) = dir {
            cache::seen_in(&dir, &before, seen).map_err(ChunkError::Fatal)?;
        }
    }
    let mut again = false;
    loop {
        let missing = list_missing(sh, src, chunk, seen).await?;
        if missing.is_empty() {
            return Ok(());
        }
        sh.log(format!(
            "[read] {} of {cn} in no uSN range (this account can't read their uSNChanged){}: \
             reading each on its own",
            pathwarden_core::text::count(missing.len(), "object", "objects"),
            if again { ", listed again" } else { "" }
        ));
        src.start_rest(chunk, filter, Lookup::Objects(&missing))
            .await
            .map_err(ChunkError::Read)?;
        drain(sh, src, chunk, s, t).await?;
        end_search(src, cn).await?;
        let gone: HashSet<String> = src.take_gone().into_iter().collect();
        seen.extend(
            missing
                .iter()
                .filter(|dn| !gone.contains(*dn))
                .map(|dn| cache::dn_key(dn)),
        );
        if gone.is_empty() {
            return Ok(());
        }
        let n = pathwarden_core::text::count(gone.len(), "object was", "objects were");
        if again {
            sh.log(format!(
                "[read] {n} gone again when read (deleted, renamed or moved during the read): \
                 left out"
            ));
            return Ok(());
        }
        sh.log(format!(
            "[read] {n} gone when read (deleted, renamed or moved since the list): listing \
             {cn} again"
        ));
        again = true;
    }
}

/// `chunk.nc`'s objects, listed by DN, that `seen` doesn't hold: in the
/// order listed. The progress line says how far the list got.
async fn list_missing<P: PageSource>(
    sh: &Shared<'_>,
    src: &mut P,
    chunk: &cache::Chunk,
    seen: &HashSet<u128>,
) -> Result<Vec<String>, ChunkError> {
    let cn = &chunk.nc;
    src.start_rest(chunk, sh.plan.filter, Lookup::List)
        .await
        .map_err(ChunkError::Read)?;
    let mut missing: Vec<String> = Vec::new();
    let mut listed: u64 = 0;
    loop {
        if sh.failed() {
            return Err(ChunkError::Stopped);
        }
        let Some(page) = src.next_page().await.map_err(ChunkError::Read)? else {
            break;
        };
        for e in page.entries {
            listed += 1;
            if !seen.contains(&cache::dn_key(&e.dn)) {
                missing.push(e.dn);
            }
        }
        sh.send(Msg::Detail(format!(
            "Listing the objects of {cn}: {}",
            crate::progress::thousands(listed)
        )));
    }
    end_search(src, cn).await?;
    *sh.detail.borrow_mut() = cn.clone();
    sh.send(Msg::Detail(cn.clone()));
    Ok(missing)
}

/// The pages of the search `src` has going, into the sink as `chunk`'s:
/// counted, timed, and (for the head, the windows and the delta) their
/// DNs kept for the rest chunk.
async fn drain<P: PageSource>(
    sh: &Shared<'_>,
    src: &mut P,
    chunk: &cache::Chunk,
    s: usize,
    t: &mut Tally,
) -> Result<(), ChunkError> {
    let sees = cache::sees_dns(chunk.kind);
    loop {
        if sh.failed() {
            return Err(ChunkError::Stopped);
        }
        let Some(page) = src.next_page().await.map_err(ChunkError::Read)? else {
            return Ok(());
        };
        if t.first_page.is_none() {
            t.first_page = Some((page.first_at, page.wait));
        } else {
            t.mine.pages.push(page.wait);
        }
        let live = sh.running();
        let slower = sh
            .backoff
            .borrow_mut()
            .page(s, page.wait, sh.started.elapsed(), live);
        // Stream 1 alone: its waits (this page's counted above) are the
        // baseline.
        if s == 0 && sh.alone.get() {
            if chunk.kind == cache::Kind::Window {
                sh.alone_pages.set(sh.alone_pages.get() + 1);
            }
            if sh.alone_pages.get() >= ALONE_PAGES || sh.started.elapsed() >= Backoff::FIRST {
                sh.end_alone();
            }
        }
        if let Some(why) = slower {
            if let Some(n) = sh.stop_one() {
                sh.log(format!(
                    "[read] the domain controller answers slower (page wait p95 {}, \
                     against {} at first): reading with {}",
                    timings::secs(why.p95),
                    timings::secs(why.baseline),
                    pathwarden_core::text::count(n, "stream", "streams")
                ));
            }
        }
        t.ranged.0 += page.ranged_entries;
        t.ranged.1 += page.ranged_searches;
        t.ranged.2 += page.ranged;
        let mut out = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            if sees {
                if let Some(seen) = sh.seen.borrow_mut().as_mut() {
                    seen.insert(cache::dn_key(&entry.dn));
                }
            }
            let kind = kind_of(&entry);
            *sh.counts.borrow_mut().entry(kind).or_default() += 1;
            *t.counts.entry(kind.to_string()).or_default() += 1;
            t.mine.entries += 1;
            t.mine.bytes += entry_bytes(&entry);
            match category(&entry, kind) {
                Category::Kept => t.mine.kept += 1,
                Category::Deleted => t.mine.deleted += 1,
                Category::Dns => t.mine.dns += 1,
                Category::Schema => t.mine.schema += 1,
                Category::Other => t.mine.other += 1,
            }
            if let Some(script) = entry.attrs.get("scriptPath").and_then(|v| v.first()) {
                let script = script.trim();
                if !script.is_empty() {
                    sh.scripts.borrow_mut().insert(script.to_string());
                }
            }
            out.push(entry.into());
            t.read += 1;
            sh.total.set(sh.total.get() + 1);
            if sh.total.get().is_multiple_of(256) {
                sh.report_units(false);
            }
        }
        sh.sink
            .borrow_mut()
            .page(chunk.id, out)
            .map_err(ChunkError::Fatal)?;
        sh.pages.set(sh.pages.get() + 1);
        if sh.pages.get().is_multiple_of(MEMORY_EVERY_PAGES) {
            log_memory(
                sh.plan.tx,
                &format!("read, page {}", crate::progress::thousands(sh.pages.get())),
            );
        }
    }
}
