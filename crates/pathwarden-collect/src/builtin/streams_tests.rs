//! The read in parallel, on fake sources: the same output
//! whatever the number of streams and the order chunks finish in, slowing
//! down when the domain controller does, a failed chunk read again, a
//! stopped read resumed, and a checkpoint that never runs ahead of the
//! files. Then the ranged pool and SYSVOL's worker pools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use ldap3::SearchEntry;
use rusthound_ce::transport::ldap::LdapSearchEntry;

use super::cache_tests::{
    base_reads, contexts, highest, output_from, plenty, read_back, read_plan, returns, runtime,
    same, scratch, snapshot, synthetic, whole_of, BASE,
};
use super::streams::{self, Backoff, Streams};
use super::*;

type Dir = Arc<Mutex<Vec<(String, Vec<LdapSearchEntry>)>>>;

/// Where a fake source fails, and how.
#[derive(Clone, Debug)]
struct Fail {
    /// Only on this stream (from 0), else any.
    stream: Option<usize>,
    chunk: u32,
    /// At this page (from 1); 0: at the end of the search.
    page: usize,
    /// How many times, at most.
    times: usize,
    error: &'static str,
}

/// What the fake domain controller saw.
#[derive(Default)]
struct Seen {
    /// (stream, chunk) for each search started, in order.
    starts: Vec<(usize, u32)>,
    /// Connections opened, by stream (the first included).
    opens: BTreeMap<usize, usize>,
    /// Searches running at once, at most.
    most_at_once: usize,
    running: usize,
    /// Pages served, all streams.
    pages: u64,
}

/// Changes the directory as the read goes: called with how many searches
/// have started.
type Hook = Box<dyn FnMut(usize, &mut Vec<(String, Vec<LdapSearchEntry>)>) + Send>;

/// Fake streams over one directory: each source sleeps a random time
/// before each page (seeded, so a run is repeatable), and fails where
/// [`Fail`]s say.
#[derive(Clone)]
struct FakeStreams {
    dir: Dir,
    page_size: usize,
    /// Up to this long before each page.
    latency: Duration,
    fails: Arc<Mutex<Vec<Fail>>>,
    seen: Arc<Mutex<Seen>>,
    /// Page waits as reported: each page says it waited this long.
    reported_wait: Arc<Mutex<Option<Duration>>>,
    /// Streams whose connection is refused.
    refused: Arc<Mutex<BTreeSet<usize>>>,
    /// Pages served after this many say they waited this long.
    slower_after: Arc<Mutex<Option<(u64, Duration)>>>,
    /// This much longer before each page of these chunks.
    slow_chunks: Arc<Mutex<BTreeMap<u32, Duration>>>,
    hook: Arc<Mutex<Option<Hook>>>,
    /// Changes the directory as the rest chunk's Base searches start.
    before_objects: Arc<Mutex<Option<ObjectsHook>>>,
    /// The rest chunk's Base searches fail after serving this many
    /// objects, this many times.
    fail_objects: Arc<Mutex<Option<(usize, usize)>>>,
}

/// Changes the directory as the rest chunk's Base searches start.
type ObjectsHook = Box<dyn FnMut(&mut Vec<(String, Vec<LdapSearchEntry>)>) + Send>;

impl FakeStreams {
    fn new(ncs: Vec<(String, Vec<LdapSearchEntry>)>, page_size: usize, latency_ms: u64) -> Self {
        Self {
            dir: Arc::new(Mutex::new(ncs)),
            page_size,
            latency: Duration::from_millis(latency_ms),
            fails: Default::default(),
            seen: Default::default(),
            reported_wait: Default::default(),
            refused: Default::default(),
            slower_after: Default::default(),
            slow_chunks: Default::default(),
            hook: Default::default(),
            before_objects: Default::default(),
            fail_objects: Default::default(),
        }
    }

    fn fail(self, f: Fail) -> Self {
        self.fails.lock().unwrap().push(f);
        self
    }

    fn starts_of(&self, chunk: u32) -> usize {
        self.seen
            .lock()
            .unwrap()
            .starts
            .iter()
            .filter(|(_, c)| *c == chunk)
            .count()
    }

    fn streams_used(&self) -> BTreeSet<usize> {
        self.seen
            .lock()
            .unwrap()
            .starts
            .iter()
            .map(|(s, _)| *s)
            .collect()
    }
}

struct FakeSource {
    of: FakeStreams,
    stream: usize,
    chunk: Option<cache::Chunk>,
    /// A Base search of the rest chunk: this object alone.
    /// The rest chunk's Base searches: what they found, still to serve.
    queued: Option<std::collections::VecDeque<LdapSearchEntry>>,
    /// Objects they served.
    served: usize,
    gone: Vec<String>,
    page: usize,
    rng: u64,
}

impl FakeSource {
    fn failure(&self, at_page: usize) -> Option<String> {
        let id = self.chunk.as_ref()?.id;
        let mut fails = self.of.fails.lock().unwrap();
        let f = fails.iter_mut().find(|f| {
            f.chunk == id
                && f.page == at_page
                && f.times > 0
                && f.stream.is_none_or(|s| s == self.stream)
        })?;
        f.times -= 1;
        Some(f.error.to_string())
    }

    async fn nap(&mut self) {
        // xorshift: a different, repeatable wait each page.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let max = self.of.latency.as_micros() as u64;
        if max > 0 {
            tokio::time::sleep(Duration::from_micros(self.rng % max)).await;
        }
    }

    fn done(&mut self) {
        if self.chunk.take().is_some() {
            self.of.seen.lock().unwrap().running -= 1;
        }
    }
}

impl Drop for FakeSource {
    fn drop(&mut self) {
        self.done();
    }
}

impl PageSource for FakeSource {
    async fn start(&mut self, chunk: &cache::Chunk, _filter: &str) -> Result<(), String> {
        self.done();
        let mut seen = self.of.seen.lock().unwrap();
        seen.starts.push((self.stream, chunk.id));
        seen.running += 1;
        seen.most_at_once = seen.most_at_once.max(seen.running);
        let k = seen.starts.len();
        drop(seen);
        if let Some(hook) = self.of.hook.lock().unwrap().as_mut() {
            hook(k, &mut self.of.dir.lock().unwrap());
        }
        self.chunk = Some(chunk.clone());
        self.queued = None;
        self.page = 0;
        Ok(())
    }

    async fn start_rest(
        &mut self,
        chunk: &cache::Chunk,
        filter: &str,
        lookup: Lookup<'_>,
    ) -> Result<(), String> {
        match lookup {
            // The listing is the chunk's start; its Base searches aren't.
            Lookup::List => self.start(chunk, filter).await?,
            Lookup::Objects(dns) => {
                self.done();
                self.of.seen.lock().unwrap().running += 1;
                let mut dir = self.of.dir.lock().unwrap();
                if let Some(hook) = self.of.before_objects.lock().unwrap().as_mut() {
                    hook(&mut dir);
                }
                let all = dir
                    .iter()
                    .find(|(nc, _)| *nc == chunk.nc)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                drop(dir);
                let (found, gone) = base_reads(chunk, &all, dns);
                self.queued = Some(found.into());
                self.served = 0;
                self.gone = gone;
            }
        }
        self.chunk = Some(whole_of(chunk));
        self.page = 0;
        Ok(())
    }

    fn take_gone(&mut self) -> Vec<String> {
        std::mem::take(&mut self.gone)
    }

    async fn next_page(&mut self) -> Result<Option<Page>, String> {
        self.nap().await;
        let slow = self
            .chunk
            .as_ref()
            .and_then(|c| self.of.slow_chunks.lock().unwrap().get(&c.id).copied());
        if let Some(d) = slow {
            tokio::time::sleep(d).await;
        }
        self.page += 1;
        if let Some(e) = self.failure(self.page) {
            return Err(e);
        }
        let Some(chunk) = self.chunk.as_ref() else {
            return Ok(None);
        };
        let page: Vec<LdapSearchEntry> = match self.queued.as_mut() {
            Some(queued) => {
                let mut fail = self.of.fail_objects.lock().unwrap();
                if let Some((after, times)) = fail.as_mut() {
                    if *times > 0 && self.served >= *after {
                        *times -= 1;
                        return Err("LDAP search of an object no uSN range returned failed: \
                                    connection reset"
                            .into());
                    }
                }
                drop(fail);
                let page: Vec<_> = (0..self.of.page_size)
                    .map_while(|_| queued.pop_front())
                    .collect();
                self.served += page.len();
                page
            }
            None => {
                let dir = self.of.dir.lock().unwrap();
                let Some((_, all)) = dir.iter().find(|(nc, _)| *nc == chunk.nc) else {
                    return Ok(None);
                };
                all.iter()
                    .filter(|e| returns(chunk, e))
                    .skip((self.page - 1) * self.of.page_size)
                    .take(self.of.page_size)
                    .cloned()
                    .collect()
            }
        };
        if page.is_empty() {
            return Ok(None);
        }
        let mut p = Page::new(page.into_iter().map(SearchEntry::from).collect());
        if let Some(w) = *self.of.reported_wait.lock().unwrap() {
            p.wait = w;
        }
        let served = {
            let mut seen = self.of.seen.lock().unwrap();
            seen.pages += 1;
            seen.pages
        };
        if let Some((after, w)) = *self.of.slower_after.lock().unwrap() {
            if served > after {
                p.wait = w;
            }
        }
        Ok(Some(p))
    }

    async fn end(&mut self) -> Result<(), String> {
        let failed = self.failure(0);
        self.done();
        match failed {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Streams for FakeStreams {
    type Source = FakeSource;

    async fn open(&self, stream: usize, _fresh: bool) -> Result<FakeSource, String> {
        *self.seen.lock().unwrap().opens.entry(stream).or_default() += 1;
        if self.refused.lock().unwrap().contains(&stream) {
            return Err("cannot connect to ldaps://dc01.contoso.local:636: refused".into());
        }
        Ok(FakeSource {
            of: self.clone(),
            stream,
            chunk: None,
            queued: None,
            served: 0,
            gone: Vec::new(),
            page: 0,
            rng: 0x9e37_79b9_7f4a_7c15 ^ ((stream as u64 + 1) * 0x1000_0001),
        })
    }
}

/// A read of `contoso.local` in uSN windows into `root` on `n` streams of
/// `fake`, as a collection makes it.
struct Run {
    disk: DiskPlan,
    out: Result<streams::Read, String>,
    logs: Vec<String>,
    msgs: Vec<(u32, u64, u64)>,
    timings: Timings,
}

fn run(
    root: &Path,
    h: u64,
    n: usize,
    fake: &FakeStreams,
    resume: bool,
    crash_after: Option<u32>,
) -> Run {
    let c = crate::ReadCache {
        root: root.to_path_buf(),
        resume,
        ..crate::ReadCache::default()
    };
    let plan = read_plan(&c, plenty);
    let (tx, rx) = mpsc::channel::<Msg>();
    let disk = prepare_cache(
        &plan,
        &contexts(),
        BASE,
        "(objectClass=*)",
        &snapshot(h),
        &tx,
    )
    .unwrap()
    .expect("on disk");
    let writer = match crash_after {
        Some(id) => cache::Writer::crashing_after_for(&disk.folder, id, n),
        None => cache::Writer::for_streams(&disk.folder, n),
    }
    .unwrap();
    let mut timings = Timings::default();
    let read_plan = streams::Plan {
        filter: "(objectClass=*)",
        chunks: &disk.chunks,
        domain_nc: BASE,
        tx: &tx,
        streams: n,
        refused_wait: Duration::from_millis(20),
    };
    let out = runtime().block_on(streams::read(
        fake,
        &read_plan,
        &mut timings,
        Sink::Disk(writer),
    ));
    drop(tx);
    let (mut logs, mut msgs) = (Vec::new(), Vec::new());
    for m in rx {
        match m {
            Msg::Log(l) => logs.push(l),
            Msg::Streams {
                streams,
                parts,
                done,
            } => msgs.push((streams, parts, done)),
            _ => {}
        }
    }
    Run {
        disk,
        out,
        logs,
        msgs,
        timings,
    }
}

impl Run {
    fn ok(&self) -> &cache::Written {
        match &self.out {
            Ok(r) => match &r.out {
                ReadOut::Disk(w) => w,
                ReadOut::Memory(_) => panic!("in memory"),
            },
            Err(e) => panic!("{e}"),
        }
    }

    fn dir(&self) -> PathBuf {
        self.disk.folder.path().to_path_buf()
    }

    fn finish(mut self) {
        self.disk.folder.remove_on_drop();
    }
}

/// Entries in the fake directory. The read writes one more: the domain
/// head is in its window too (read back once).
fn all_entries(ncs: &[(String, Vec<LdapSearchEntry>)]) -> usize {
    ncs.iter().map(|(_, v)| v.len()).sum()
}

/// N=1 and N=4 over a source with random latencies: the same entries in
/// the same order on disk, and the same output, though the chunks finish
/// in another order.
#[test]
fn four_streams_give_what_one_gives() {
    let root = scratch("streams-same");
    let ncs = synthetic(1500);
    let h = highest(&ncs);

    let one = FakeStreams::new(ncs.clone(), 7, 3);
    let ran = run(&root.join("one"), h, 1, &one, false, None);
    let w = ran.ok();
    assert_eq!(w.entries as usize, all_entries(&ncs) + 1);
    let expected = read_back(&ran.dir());
    let expected_out = output_from(&ran.dir(), &root.join("out-one"));
    assert_eq!(one.streams_used(), BTreeSet::from([0]));
    assert_eq!(ran.timings.streams, Some((1, 1)));
    ran.finish();

    let four = FakeStreams::new(ncs.clone(), 7, 3);
    let ran = run(&root.join("four"), h, 4, &four, false, None);
    assert_eq!(ran.ok().entries as usize, all_entries(&ncs) + 1);
    // Every stream read, on its own connection, several at once.
    assert_eq!(four.streams_used(), BTreeSet::from([0, 1, 2, 3]));
    let seen = four.seen.lock().unwrap();
    assert!(seen.most_at_once > 1, "{}", seen.most_at_once);
    assert!(seen.opens.values().all(|&n| n == 1), "{:?}", seen.opens);
    // Stream 1 read the small naming contexts and the head first.
    let first: Vec<u32> = seen
        .starts
        .iter()
        .filter(|(s, _)| *s == 0)
        .map(|(_, c)| *c)
        .take(3)
        .collect();
    assert_eq!(first, [1, 2, 67]);
    // The delta, once every window was read, then the rest chunk.
    let last: Vec<u32> = seen.starts.iter().rev().take(2).map(|(_, c)| *c).collect();
    assert_eq!(last, [69, 68]);
    drop(seen);
    let back = read_back(&ran.dir());
    assert_eq!(dns(&back), dns(&expected));
    assert!(back.iter().zip(&expected).all(|(a, b)| same(a, b)));
    assert_eq!(
        output_from(&ran.dir(), &root.join("out-four")),
        expected_out
    );
    // The progress: 4 streams, then every part done.
    assert_eq!(ran.msgs.first(), Some(&(4, 69, 0)));
    assert_eq!(ran.msgs.last(), Some(&(4, 69, 69)));
    assert!(ran.msgs.windows(2).all(|w| w[0].2 <= w[1].2));
    assert_eq!(ran.timings.streams, Some((4, 4)));
    assert!(ran
        .logs
        .iter()
        .any(|l| l == "[read] reading 69 parts with 4 streams"));
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

fn dns(entries: &[LdapSearchEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.dn.as_str()).collect()
}

/// Stream 1's waits before the others start set the baseline (else the
/// first minute's); a stream whose recent waits (p95) pass twice that
/// says to slow down, once, then the waits start again.
#[test]
fn slower_pages_say_to_slow_down() {
    let s = Duration::from_secs;
    let ms = Duration::from_millis;
    let mut b = Backoff::new(4);
    // Stream 1 alone: about a second a page, one of 2 s.
    for i in 0..12u64 {
        let wait = if i == 7 { ms(2000) } else { ms(900 + i * 5) };
        assert_eq!(b.page(0, wait, s(i * 2), 1), None);
    }
    assert_eq!(b.baseline(), None);
    b.settle();
    // The p95 of its waits (the 2 s page above it).
    let base = b.baseline().unwrap();
    assert_eq!(base, ms(955));
    // Stream 2 keeps the pace: nothing.
    for i in 0..20u64 {
        assert_eq!(b.page(1, ms(1100), s(30 + i), 4), None);
    }
    // Stream 3 slows to 5 s a page: once its p95 passes twice the
    // baseline (enough samples for one), slow down.
    let mut slower = None;
    for i in 0..10u64 {
        if let Some(why) = b.page(2, s(5), s(60 + i), 4) {
            slower = Some((i, why));
            break;
        }
    }
    let (i, why) = slower.expect("slower");
    assert!(i < 10, "after {} pages", i + 1);
    assert_eq!(why.baseline, base);
    assert!(why.p95 >= s(5));
    // Its waits start again: not again at the next slow page.
    assert_eq!(b.page(2, s(5), s(71), 3), None);
    // One stream left: never.
    let mut b1 = b.clone();
    for i in 0..30u64 {
        assert_eq!(b1.page(2, s(9), s(80 + i), 1), None);
    }
    // A little slower, under twice the baseline: nothing.
    let mut b2 = Backoff::new(2);
    for i in 0..20u64 {
        b2.page(0, ms(1000), s(i * 4), 1);
    }
    for i in 0..30u64 {
        assert_eq!(b2.page(1, ms(1900), s(90 + i), 2), None);
    }
    // Fast pages (a LAN): twice as slow but under a quarter second more is
    // noise.
    let mut b3 = Backoff::new(4);
    for i in 0..20u64 {
        b3.page(0, ms(20), s(i * 4), 1);
    }
    for i in 0..30u64 {
        assert_eq!(b3.page(1, ms(200), s(90 + i), 4), None);
    }
    // Without settling, the first minute's waits are the baseline; none
    // before a minute, however slow.
    let mut b5 = Backoff::new(4);
    for i in 0..50u64 {
        assert_eq!(b5.page(0, s(i), ms(i * 100), 4), None);
    }
    assert_eq!(b5.baseline(), None);
    b5.page(0, s(1), s(61), 4);
    assert!(b5.baseline().is_some());
    // Too few to settle on: the first minute decides.
    let mut b6 = Backoff::new(2);
    b6.page(0, s(1), s(1), 1);
    b6.settle();
    assert_eq!(b6.baseline(), None);
}
#[test]
fn which_errors_mean_the_dc_is_overloaded() {
    for e in [
        "the domain controller did not return all of DC=x: rc=51 (busy), dn: \"\", text: \"\"",
        "LDAP search of DC=x failed: rc=11 (adminLimitExceeded), dn: \"\", text: \"\"",
        "rc=3 (timeLimitExceeded), dn: \"\", text: \"\"",
    ] {
        assert!(streams::dc_overloaded(e), "{e}");
    }
    for e in [
        "rc=4 (sizeLimitExceeded), dn: \"\", text: \"\"",
        "connection reset",
        "LDAP search of DC=x: connection stalled",
    ] {
        assert!(!streams::dc_overloaded(e), "{e}");
    }
    assert_eq!(streams::streams(None), 4);
    assert_eq!(streams::streams(Some(0)), 1);
    assert_eq!(streams::streams(Some(20)), 8);
    assert_eq!(streams::streams(Some(2)), 2);
}

/// The DC says busy at the end of a window, and over its limit within
/// another: one stream fewer each time, both read again, and the output
/// is the same.
#[test]
fn busy_and_over_limit_slow_the_read_down() {
    let root = scratch("streams-busy");
    let ncs = synthetic(900);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 5, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();

    let busy = FakeStreams::new(ncs.clone(), 5, 2)
        .fail(Fail {
            stream: None,
            chunk: 20,
            page: 0,
            times: 1,
            error: "rc=51 (busy), dn: \"\", text: \"\"",
        })
        .fail(Fail {
            stream: None,
            chunk: 40,
            page: 2,
            times: 1,
            error: "LDAP search of DC=contoso,DC=local failed: rc=11 (adminLimitExceeded), dn: \"\", text: \"\"",
        });
    let ran = run(&root.join("busy"), h, 4, &busy, false, None);
    assert_eq!(ran.ok().entries as usize, all_entries(&ncs) + 1);
    assert_eq!(busy.starts_of(20), 2);
    assert_eq!(busy.starts_of(40), 2);
    let refused: Vec<&String> = ran
        .logs
        .iter()
        .filter(|l| l.contains("refused for load"))
        .collect();
    assert_eq!(refused.len(), 2, "{:?}", ran.logs);
    assert!(
        refused[0].contains("reading with 3 streams"),
        "{}",
        refused[0]
    );
    assert!(
        refused[1].contains("reading with 2 streams"),
        "{}",
        refused[1]
    );
    // Not counted as a failure: no new connection for them.
    assert!(!ran.logs.iter().any(|l| l.contains("new connection")));
    assert_eq!(ran.msgs.last().map(|m| m.0), Some(2));
    assert_eq!(ran.timings.streams, Some((4, 2)));
    assert_eq!(output_from(&ran.dir(), &root.join("out-busy")), expected);
    ran.finish();

    // One stream and busy twice: it waits (doubling), then reads the same
    // part again on the same connection.
    let alone = FakeStreams::new(ncs.clone(), 5, 0).fail(Fail {
        stream: None,
        chunk: 20,
        page: 0,
        times: 2,
        error: "rc=51 (busy), dn: \"\", text: \"\"",
    });
    let ran = run(&root.join("alone"), h, 1, &alone, false, None);
    ran.ok();
    let waits: Vec<&String> = ran
        .logs
        .iter()
        .filter(|l| l.contains("reading that part again in"))
        .collect();
    assert_eq!(waits.len(), 2, "{:?}", ran.logs);
    assert!(waits[0].ends_with("in 0.02s"), "{}", waits[0]);
    assert!(waits[1].ends_with("in 0.04s"), "{}", waits[1]);
    assert!(!ran.logs.iter().any(|l| l.contains("new connection")));
    assert_eq!(alone.seen.lock().unwrap().opens.get(&0), Some(&1));
    assert_eq!(alone.starts_of(20), 3);
    assert_eq!(output_from(&ran.dir(), &root.join("out-alone")), expected);
    ran.finish();

    // Busy on and on: the waits stop at their total (24 times the first),
    // then it is a failure like another: once more on a new connection,
    // then the read stops, to resume.
    let stuck = FakeStreams::new(ncs.clone(), 5, 0).fail(Fail {
        stream: None,
        chunk: 20,
        page: 0,
        times: 100,
        error: "rc=51 (busy), dn: \"\", text: \"\"",
    });
    let ran = run(&root.join("stuck"), h, 1, &stuck, false, None);
    let e = ran.out.as_ref().err().expect("stops");
    assert!(e.contains("(busy)"), "{e}");
    let waited: usize = ran
        .logs
        .iter()
        .filter(|l| l.contains("reading that part again in"))
        .count();
    // 20, 40, 80, 120, 120 ms: 380 ms; one more would pass 480.
    assert_eq!(waited, 5, "{:?}", ran.logs);
    assert!(ran.logs.iter().any(|l| l.contains("new connection")));
    assert!(ran.disk.folder.resumable());
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// Stream 1 reads alone first, and its pages set the baseline; then the
/// DC answers slower (5 s a page against 1 s): the read goes on with one
/// stream fewer, says so, and the progress and timings show it. The output
/// is the same.
#[test]
fn slower_answers_slow_the_read_down() {
    let root = scratch("streams-slower");
    let ncs = synthetic(1500);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 7, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();

    let fake = FakeStreams::new(ncs.clone(), 7, 1);
    *fake.reported_wait.lock().unwrap() = Some(Duration::from_secs(1));
    *fake.slower_after.lock().unwrap() = Some((40, Duration::from_secs(5)));
    let ran = run(&root.join("slower"), h, 4, &fake, false, None);
    ran.ok();
    // Stream 1 alone for its first window pages: none of the others before.
    let seen = fake.seen.lock().unwrap();
    let others = seen.starts.iter().position(|(s, _)| *s != 0).unwrap();
    let alone_windows = seen.starts[..others]
        .iter()
        .filter(|(_, c)| (3..=66).contains(c))
        .count();
    assert!(alone_windows >= 2, "{:?}", &seen.starts[..others]);
    drop(seen);
    let slower: Vec<&String> = ran
        .logs
        .iter()
        .filter(|l| l.contains("answers slower"))
        .collect();
    assert!(!slower.is_empty(), "{:?}", ran.logs);
    assert!(
        slower[0].contains("page wait p95 5.00s, against 1.00s at first): reading with 3 streams"),
        "{}",
        slower[0]
    );
    let (first, last) = ran.timings.streams.unwrap();
    assert_eq!(first, 4);
    assert!(last < 4, "{last}");
    assert_eq!(ran.msgs.last().map(|m| m.0 as usize), Some(last));
    assert_eq!(output_from(&ran.dir(), &root.join("out-slower")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Only windows left (a resume): stream 1's first 10 window pages, this
/// one's wait counted too, are enough for the baseline.
#[test]
fn windows_alone_set_the_baseline() {
    let root = scratch("streams-windows");
    let ncs = synthetic(900);
    let h = highest(&ncs);
    let fake = FakeStreams::new(ncs.clone(), 3, 0);
    *fake.reported_wait.lock().unwrap() = Some(Duration::from_millis(700));
    let (folder, _) = cache::Folder::create(&root, "contoso.local").unwrap();
    let writer = cache::Writer::for_streams(&folder, 4).unwrap();
    let chunks: Vec<cache::Chunk> = cache::plan(&contexts(), BASE, Some(h))
        .into_iter()
        .filter(|c| c.kind == cache::Kind::Window)
        .collect();
    let (tx, rx) = mpsc::channel::<Msg>();
    let plan = streams::Plan {
        filter: "(objectClass=*)",
        chunks: &chunks,
        domain_nc: BASE,
        tx: &tx,
        streams: 4,
        refused_wait: Duration::from_millis(20),
    };
    let mut timings = Timings::default();
    let out = runtime().block_on(streams::read(
        &fake,
        &plan,
        &mut timings,
        Sink::Disk(writer),
    ));
    assert!(out.is_ok(), "{:?}", out.err());
    drop(tx);
    let logs: Vec<String> = rx
        .into_iter()
        .filter_map(|m| match m {
            Msg::Log(l) => Some(l),
            _ => None,
        })
        .collect();
    assert!(
        logs.iter()
            .any(|l| l
                == "[read] page waits at first: p95 0.70s over 10 pages; the other streams start"),
        "{logs:?}"
    );
    drop(folder);
    let _ = std::fs::remove_dir_all(&root);
}

/// B1: a part refused for load by the last stream reading, once the others
/// have stopped, is read again before the delta, never after it. The last
/// window is slow and busy at its end, so every other stream has nothing
/// left when it is refused.
#[test]
fn a_part_refused_last_is_read_before_the_delta() {
    let root = scratch("streams-last");
    let ncs = synthetic(900);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 5, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();

    let fake = FakeStreams::new(ncs.clone(), 5, 1).fail(Fail {
        stream: None,
        chunk: 66,
        page: 0,
        times: 1,
        error: "rc=51 (busy), dn: \"\", text: \"\"",
    });
    fake.slow_chunks
        .lock()
        .unwrap()
        .insert(66, Duration::from_millis(150));
    let ran = run(&root.join("last"), h, 4, &fake, false, None);
    ran.ok();
    let starts = fake.seen.lock().unwrap().starts.clone();
    let delta = starts.iter().position(|(_, c)| *c == 68).unwrap();
    let again = starts.iter().rposition(|(_, c)| *c == 66).unwrap();
    assert_eq!(fake.starts_of(66), 2, "{starts:?}");
    assert!(again < delta, "{starts:?}");
    assert_eq!(output_from(&ran.dir(), &root.join("out-last")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Objects change while four streams read: one already read moves to a
/// newer uSN (it is in the delta, and only its newer version is kept), and
/// one not yet read moves out of its window into the delta. Every object
/// once, the newest version.
#[test]
fn objects_changed_during_a_parallel_read_appear_once_newest() {
    let root = scratch("streams-changed");
    let ncs = synthetic(1500);
    let h = highest(&ncs);
    let early = format!("CN=User3,CN=Users,{BASE}");
    let late = format!("CN=User1490,CN=Users,{BASE}");
    let fake = FakeStreams::new(ncs.clone(), 7, 2);
    {
        let (early, late) = (early.clone(), late.clone());
        let mut done = false;
        *fake.hook.lock().unwrap() = Some(Box::new(move |k, dir| {
            if k < 30 || done {
                return;
            }
            done = true;
            let (_, domain) = dir.iter_mut().find(|(nc, _)| nc == BASE).unwrap();
            for (dn, u) in [(&early, h + 2), (&late, h + 3)] {
                let e = domain.iter_mut().find(|e| e.dn == *dn).unwrap();
                e.attrs
                    .insert("description".into(), vec![format!("changed at {u}")]);
                e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
            }
        }));
    }
    let ran = run(&root, h, 4, &fake, false, None);
    ran.ok();
    let back = read_back(&ran.dir());
    assert_eq!(back.len(), all_entries(&ncs));
    for (dn, u) in [(&early, h + 2), (&late, h + 3)] {
        let found: Vec<_> = back.iter().filter(|e| e.dn == *dn).collect();
        assert_eq!(found.len(), 1, "{dn}");
        assert_eq!(found[0].attrs["description"], [format!("changed at {u}")]);
    }
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Stopped on four streams, resumed on one; stopped on one, resumed on
/// four: the same output as a read that never stopped.
#[test]
fn a_read_resumes_with_another_number_of_streams() {
    let root = scratch("streams-41");
    let ncs = synthetic(900);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 5, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();
    for (i, (before, after)) in [(4, 1), (1, 4)].into_iter().enumerate() {
        let cache = root.join(format!("cache{i}"));
        // Window 30 fails twice: the read stops.
        let failing = FakeStreams::new(ncs.clone(), 5, 1).fail(Fail {
            stream: None,
            chunk: 30,
            page: 2,
            times: 2,
            error: "LDAP search of DC=contoso,DC=local failed: connection reset",
        });
        let ran = run(&cache, h, before, &failing, false, None);
        assert!(ran.out.is_err(), "{before}");
        let dir = ran.dir();
        drop(ran);
        let again = FakeStreams::new(ncs.clone(), 5, 1);
        let ran = run(&cache, h, after, &again, true, None);
        assert!(ran.ok().resumed_from.is_some());
        assert_eq!(
            output_from(&dir, &root.join(format!("out{i}"))),
            expected,
            "{before} then {after}"
        );
        ran.finish();
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A chunk that fails once is read again on a new connection and the read
/// goes on; failing again, the read stops, keeps what is done, and resumes
/// to the same output.
#[test]
fn a_failed_chunk_is_read_again_once() {
    let root = scratch("streams-retry");
    let ncs = synthetic(900);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 5, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();

    let once = FakeStreams::new(ncs.clone(), 5, 2).fail(Fail {
        stream: None,
        chunk: 30,
        page: 2,
        times: 1,
        error: "LDAP search of DC=contoso,DC=local failed: connection reset",
    });
    let ran = run(&root.join("once"), h, 4, &once, false, None);
    ran.ok();
    assert_eq!(once.starts_of(30), 2);
    assert!(ran
        .logs
        .iter()
        .any(|l| l.contains("a part failed (LDAP search of DC=contoso,DC=local failed: connection reset); reading it again on a new connection")));
    let opens: usize = once.seen.lock().unwrap().opens.values().sum();
    assert_eq!(opens, 5, "four streams and one new connection");
    assert_eq!(output_from(&ran.dir(), &root.join("out-once")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// A stream that can't connect leaves its share to the others, and the
/// read completes with the same output.
#[test]
fn a_stream_that_cannot_connect_leaves_its_share() {
    let root = scratch("streams-refused");
    let ncs = synthetic(600);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 5, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();
    let fake = FakeStreams::new(ncs.clone(), 5, 1);
    fake.refused.lock().unwrap().extend([1, 3]);
    let ran = run(&root.join("refused"), h, 4, &fake, false, None);
    ran.ok();
    assert_eq!(fake.streams_used(), BTreeSet::from([0, 2]));
    let lines: Vec<&String> = ran
        .logs
        .iter()
        .filter(|l| l.contains("could not connect"))
        .collect();
    assert_eq!(lines.len(), 2, "{:?}", ran.logs);
    // S4: the progress and timings count the streams that read.
    assert_eq!(ran.msgs.last().map(|m| m.0), Some(2));
    assert_eq!(ran.timings.streams, Some((4, 2)));
    assert_eq!(output_from(&ran.dir(), &root.join("out-refused")), expected);
    ran.finish();

    // S4: after stream 4 couldn't connect, a busy refusal still slows the
    // read down: the highest stream still reading (3) stops.
    let fake = FakeStreams::new(ncs.clone(), 5, 1).fail(Fail {
        stream: None,
        chunk: 40,
        page: 0,
        times: 1,
        error: "rc=51 (busy), dn: \"\", text: \"\"",
    });
    fake.refused.lock().unwrap().insert(3);
    let ran = run(&root.join("refused-busy"), h, 4, &fake, false, None);
    ran.ok();
    assert_eq!(fake.starts_of(40), 2);
    let refused: Vec<&String> = ran
        .logs
        .iter()
        .filter(|l| l.contains("refused for load"))
        .collect();
    assert_eq!(refused.len(), 1, "{:?}", ran.logs);
    assert!(
        refused[0].contains("reading with 2 streams"),
        "{}",
        refused[0]
    );
    assert_eq!(ran.timings.streams, Some((4, 2)));
    assert_eq!(
        output_from(&ran.dir(), &root.join("out-refused-busy")),
        expected
    );
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Fails mid-chunk on stream 3 (twice: the read stops), then resumes on
/// four streams: only what wasn't done is read, and the output is that of
/// a read that never stopped. At the stop, no `.part` is left and every
/// chunk the checkpoint calls done has its `.seg`.
#[test]
fn a_parallel_read_that_stopped_resumes_to_the_same_output() {
    let root = scratch("streams-resume");
    let ncs = synthetic(1500);
    let h = highest(&ncs);
    let clean = FakeStreams::new(ncs.clone(), 7, 0);
    let ran = run(&root.join("clean"), h, 1, &clean, false, None);
    let expected = read_back(&ran.dir());
    let expected_out = output_from(&ran.dir(), &root.join("out-clean"));
    ran.finish();

    let cache = root.join("cache");
    // The window stream 3 takes first fails at its third page, and again
    // on the new connection (still stream 3): the read stops. Which window
    // that is isn't known in advance, so every window fails so on stream 3.
    let failing = FakeStreams::new(ncs.clone(), 7, 3);
    for id in 3..=66 {
        failing.fails.lock().unwrap().push(Fail {
            stream: Some(2),
            chunk: id,
            page: 3,
            times: 2,
            error: "LDAP search of DC=contoso,DC=local failed: connection reset",
        });
    }
    let ran = run(&cache, h, 4, &failing, false, None);
    let e = ran.out.as_ref().err().expect("the read stops").clone();
    assert!(e.contains("connection reset"), "{e}");
    assert!(ran.disk.folder.resumable());
    let dir = ran.dir();
    let failed_chunk = failing
        .seen
        .lock()
        .unwrap()
        .starts
        .iter()
        .find(|(s, _)| *s == 2)
        .map(|(_, c)| *c)
        .unwrap();
    drop(ran);
    let cp = cache::Checkpoint::load(&dir).unwrap();
    assert!(!cp
        .chunks
        .iter()
        .find(|c| c.id == failed_chunk)
        .unwrap()
        .is_done());
    for c in &cp.chunks {
        let seg = dir.join(format!("chunk-{:04}.seg", c.id));
        assert_eq!(c.is_done(), seg.is_file(), "chunk {}", c.id);
    }
    let parts = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(parts, 0, "every stream's chunk was given up");
    let done_before: BTreeSet<u32> = cp
        .chunks
        .iter()
        .filter(|c| c.is_done())
        .map(|c| c.id)
        .collect();
    assert!(!done_before.is_empty());

    // Resumed on four streams.
    let again = FakeStreams::new(ncs.clone(), 7, 3);
    let ran = run(&cache, h, 4, &again, true, None);
    let w = ran.ok();
    assert!(w.resumed_from.is_some());
    assert_eq!(w.chunks, 69);
    let read_again: BTreeSet<u32> = again
        .seen
        .lock()
        .unwrap()
        .starts
        .iter()
        .map(|(_, c)| *c)
        .collect();
    // The head again (one Base search), and only what wasn't done.
    assert!(read_again.contains(&2));
    assert!(read_again.contains(&failed_chunk));
    assert!(
        read_again
            .iter()
            .all(|c| *c == 2 || !done_before.contains(c)),
        "{read_again:?}"
    );
    let back = read_back(&dir);
    assert_eq!(dns(&back), dns(&expected));
    assert!(back.iter().zip(&expected).all(|(a, b)| same(a, b)));
    assert_eq!(output_from(&dir, &root.join("out-resumed")), expected_out);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Lab item 42 on several streams: objects whose `uSNChanged` the account
/// can't read are in no uSN range, and the rest chunk reads them. With 1
/// and 4 streams, and resumed on 4 after a stop in the windows and after
/// one at the rest chunk, the output is the read into memory's.
#[test]
fn objects_without_a_readable_usn_on_any_number_of_streams() {
    let root = scratch("streams-hidden-usn");
    let (ncs, hidden) = super::cache_tests::hiding_usns(synthetic(1500), 9);
    let h = highest(&ncs);
    let expected = super::cache_tests::memory_output(&ncs, &root.join("out-memory"));
    let all = all_entries(&ncs);
    let said = format!(
        "[read] {} objects of {BASE} in no uSN range (this account can't read their \
         uSNChanged): reading each on its own",
        hidden.len()
    );
    for n in [1, 4] {
        let fake = FakeStreams::new(ncs.clone(), 7, 3);
        let ran = run(&root.join(format!("s{n}")), h, n, &fake, false, None);
        // Every entry once (the head is in its window too).
        assert_eq!(ran.ok().entries as usize, all + 1);
        assert!(ran.logs.contains(&said), "{n}: {:?}", ran.logs);
        // The rest chunk, last, once.
        assert_eq!(fake.starts_of(69), 1);
        assert_eq!(
            fake.seen.lock().unwrap().starts.last().map(|s| s.1),
            Some(69)
        );
        assert_eq!(read_back(&ran.dir()).len(), all);
        assert_eq!(
            output_from(&ran.dir(), &root.join(format!("out-s{n}"))),
            expected,
            "{n} streams"
        );
        ran.finish();
    }
    // Stopped after a window (some windows done, some not), or in the
    // rest chunk's list (only it left); resumed on four streams.
    for stop in [30, 69] {
        let cache = root.join(format!("stop{stop}"));
        let fake = FakeStreams::new(ncs.clone(), 7, 3);
        let ran = if stop == 69 {
            let fake = fake.fail(Fail {
                stream: None,
                chunk: 69,
                page: 1,
                times: 2,
                error: "LDAP search of DC=contoso,DC=local (DNs) failed: connection reset",
            });
            let ran = run(&cache, h, 4, &fake, false, None);
            let cp = cache::Checkpoint::load(&ran.dir()).unwrap();
            assert!(cp.chunks.iter().all(|c| c.is_done() == (c.id != 69)));
            ran
        } else {
            run(&cache, h, 4, &fake, false, Some(stop))
        };
        assert!(ran.out.is_err(), "{stop}");
        assert!(ran.disk.folder.resumable(), "{stop}");
        drop(ran);
        let again = FakeStreams::new(ncs.clone(), 7, 3);
        let ran = run(&cache, h, 4, &again, true, None);
        assert!(ran.ok().resumed_from.is_some());
        assert!(ran.logs.contains(&said), "{stop}: {:?}", ran.logs);
        assert_eq!(read_back(&ran.dir()).len(), all, "{stop}");
        assert_eq!(
            output_from(&ran.dir(), &root.join(format!("out-stop{stop}"))),
            expected,
            "stopped after chunk {stop}"
        );
        ran.finish();
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `ncs` with the object `dn` of the domain renamed (its GUID kept), as a
/// rename between two searches of the read leaves it.
fn renamed(ncs: &mut [(String, Vec<LdapSearchEntry>)], dn: &str) -> String {
    let to = dn.replacen(",CN=Users,", " moved,CN=Users,", 1);
    let e = ncs[1].1.iter_mut().find(|e| e.dn == dn).expect("there");
    e.dn = to.clone();
    to
}

/// The rest chunk's Base searches failing partway: read again on a new
/// connection in the same run, or, failing twice, the read stops and
/// resumes. Either way the output is the read into memory's.
#[test]
fn the_rest_chunk_failing_in_its_reads_is_read_again() {
    let root = scratch("streams-rest-fails");
    let (ncs, hidden) = super::cache_tests::hiding_usns(synthetic(400), 6);
    assert!(hidden.len() > 20);
    let h = highest(&ncs);
    let expected = super::cache_tests::memory_output(&ncs, &root.join("out-memory"));
    let all = all_entries(&ncs);

    // Once: read again at once.
    let fake = FakeStreams::new(ncs.clone(), 7, 1);
    *fake.fail_objects.lock().unwrap() = Some((10, 1));
    let ran = run(&root.join("once"), h, 4, &fake, false, None);
    assert_eq!(ran.ok().entries as usize, all + 1);
    assert_eq!(fake.starts_of(69), 2);
    assert!(
        ran.logs
            .iter()
            .any(|l| l.contains("a part failed") && l.contains("reading it again")),
        "{:?}",
        ran.logs
    );
    assert_eq!(read_back(&ran.dir()).len(), all);
    assert_eq!(output_from(&ran.dir(), &root.join("out-once")), expected);
    ran.finish();

    // Twice: the read stops in the rest chunk, then resumes.
    let cache = root.join("twice");
    let fake = FakeStreams::new(ncs.clone(), 7, 1);
    *fake.fail_objects.lock().unwrap() = Some((10, 2));
    let ran = run(&cache, h, 4, &fake, false, None);
    assert!(ran.out.is_err());
    assert!(ran.disk.folder.resumable());
    let cp = cache::Checkpoint::load(&ran.dir()).unwrap();
    assert!(cp.chunks.iter().all(|c| c.is_done() == (c.id != 69)));
    drop(ran);
    let again = FakeStreams::new(ncs.clone(), 7, 1);
    let ran = run(&cache, h, 4, &again, true, None);
    assert!(ran.ok().resumed_from.is_some());
    assert_eq!(read_back(&ran.dir()).len(), all);
    assert_eq!(output_from(&ran.dir(), &root.join("out-twice")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// An object renamed between the rest chunk's list and its Base search is
/// gone (noSuchObject) under its old DN: counted, the domain listed again,
/// and the object read under its new one.
#[test]
fn an_object_gone_when_read_is_listed_again() {
    let root = scratch("streams-rest-gone");
    let (ncs, hidden) = super::cache_tests::hiding_usns(synthetic(200), 9);
    let old = format!("CN=User0,CN=Users,{BASE}");
    assert!(hidden.contains(&old));
    let h = highest(&ncs);
    let mut after = ncs.clone();
    let new = renamed(&mut after, &old);
    let expected = super::cache_tests::memory_output(&after, &root.join("out-memory"));
    let fake = FakeStreams::new(ncs.clone(), 7, 0);
    let mut once = Some(old.clone());
    *fake.before_objects.lock().unwrap() = Some(Box::new(move |dir| {
        if let Some(dn) = once.take() {
            renamed(dir, &dn);
        }
    }));
    let ran = run(&root.join("cache"), h, 1, &fake, false, None);
    ran.ok();
    let n = hidden.len();
    let said = |l: &str| ran.logs.iter().any(|x| x == l);
    assert!(
        said(&format!(
            "[read] {n} objects of {BASE} in no uSN range (this account can't read their \
             uSNChanged): reading each on its own"
        )),
        "{:?}",
        ran.logs
    );
    assert!(said(&format!(
        "[read] 1 object was gone when read (deleted, renamed or moved since the list): \
         listing {BASE} again"
    )));
    assert!(said(&format!(
        "[read] 1 object of {BASE} in no uSN range (this account can't read their \
         uSNChanged), listed again: reading each on its own"
    )));
    let back = read_back(&ran.dir());
    assert_eq!(back.len(), all_entries(&after));
    assert!(back.iter().any(|e| e.dn == new));
    assert!(!back.iter().any(|e| e.dn == old));
    assert_eq!(output_from(&ran.dir(), &root.join("out-cache")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// An object read in its window, then renamed before the rest chunk's list
/// (its uSN unchanged, so not in the delta): the list finds its new DN,
/// the rest chunk reads it, and only that newer copy is read back.
#[test]
fn the_rest_chunk_drops_an_older_copy_from_the_windows() {
    let root = scratch("streams-rest-renamed");
    let (ncs, hidden) = super::cache_tests::hiding_usns(synthetic(200), 9);
    let old = format!("CN=User1,CN=Users,{BASE}");
    assert!(!hidden.contains(&old));
    let h = highest(&ncs);
    let mut after = ncs.clone();
    let new = renamed(&mut after, &old);
    let expected = super::cache_tests::memory_output(&after, &root.join("out-memory"));
    let fake = FakeStreams::new(ncs.clone(), 7, 0);
    // One stream: the 69th search is the rest chunk's list.
    let dn = old.clone();
    *fake.hook.lock().unwrap() = Some(Box::new(move |k, dir| {
        if k == 69 {
            renamed(dir, &dn);
        }
    }));
    let ran = run(&root.join("cache"), h, 1, &fake, false, None);
    // Both copies on disk; one read back.
    assert_eq!(ran.ok().entries as usize, all_entries(&ncs) + 1 + 1);
    let back = read_back(&ran.dir());
    assert_eq!(back.len(), all_entries(&after));
    assert!(back.iter().any(|e| e.dn == new));
    assert!(!back.iter().any(|e| e.dn == old));
    assert_eq!(output_from(&ran.dir(), &root.join("out-cache")), expected);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
}

/// Under four streams, a watcher reading the checkpoint as it changes never
/// sees a chunk done whose `.seg` isn't there, nor more `.part` files than
/// streams. A crash between a rename and the checkpoint redoes that chunk.
#[test]
fn the_checkpoint_never_runs_ahead_of_the_files() {
    let root = scratch("streams-watch");
    let ncs = synthetic(1500);
    let h = highest(&ncs);
    let dir = cache::domain_dir(&root, "contoso.local");
    let stop = Arc::new(AtomicBool::new(false));
    let looked = Arc::new(AtomicUsize::new(0));
    let watcher = {
        let (dir, stop, looked) = (dir.clone(), stop.clone(), looked.clone());
        std::thread::spawn(move || -> Result<(), String> {
            while !stop.load(Ordering::Relaxed) {
                let cp = match cache::Checkpoint::peek(&dir) {
                    cache::Peek::Ours(cp) => cp,
                    // Not there yet, or being replaced.
                    _ => continue,
                };
                let names: BTreeSet<String> = match std::fs::read_dir(&dir) {
                    Ok(r) => r
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect(),
                    Err(_) => continue,
                };
                for c in cp.chunks.iter().filter(|c| c.is_done()) {
                    let seg = format!("chunk-{:04}.seg", c.id);
                    if !names.contains(&seg) {
                        return Err(format!("chunk {} done without {seg}", c.id));
                    }
                }
                let parts = names.iter().filter(|n| n.ends_with(".part")).count();
                if parts > 4 {
                    return Err(format!("{parts} .part files for 4 streams"));
                }
                looked.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
    };
    let fake = FakeStreams::new(ncs.clone(), 7, 2);
    let ran = run(&root, h, 4, &fake, false, None);
    ran.ok();
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap().unwrap();
    assert!(looked.load(Ordering::Relaxed) > 10);
    ran.finish();

    // A crash right after chunk 30's rename, before the checkpoint says
    // it is done: the read stops; resumed, chunk 30 is read again.
    let root2 = scratch("streams-crash");
    let fake = FakeStreams::new(ncs.clone(), 7, 2);
    let ran = run(&root2, h, 4, &fake, false, Some(30));
    assert!(ran.out.is_err());
    let dir2 = ran.dir();
    drop(ran);
    assert!(dir2.join("chunk-0030.seg").is_file());
    let cp = cache::Checkpoint::load(&dir2).unwrap();
    assert!(!cp.chunks.iter().find(|c| c.id == 30).unwrap().is_done());
    let again = FakeStreams::new(ncs.clone(), 7, 2);
    let ran = run(&root2, h, 4, &again, true, None);
    assert_eq!(ran.ok().entries as usize, all_entries(&ncs) + 1);
    assert_eq!(again.starts_of(30), 1);
    ran.finish();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&root2);
}

// ----------------------------------------------------------------- ranged

/// A fake DC's group members, 1,500 a reply: a group's size is in its name
/// (`CN=G3500,...`); `CN=Broken,...` fails.
struct FakeRanged {
    searches: Arc<AtomicUsize>,
}

fn members(from: usize, to: usize) -> Vec<String> {
    (from..to).map(|i| format!("CN=U{i},DC=x")).collect()
}

fn size_of(dn: &str) -> usize {
    dn.trim_start_matches("CN=G")
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

impl ranged::RangedConn for FakeRanged {
    fn base_search<'a>(
        &'a mut self,
        dn: &'a str,
        attr: &'a str,
    ) -> ranged::BoxFut<'a, Result<Option<SearchEntry>, String>> {
        Box::pin(async move {
            self.searches.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(2)).await;
            if dn.starts_with("CN=Broken") {
                return Err("reading the members of CN=Broken failed: connection reset".into());
            }
            let n = size_of(dn);
            let from: usize = attr
                .split_once("range=")
                .and_then(|(_, r)| r.split_once('-'))
                .and_then(|(lo, _)| lo.parse().ok())
                .unwrap_or(0);
            let to = (from + 1500).min(n);
            let key = if to == n {
                format!("member;range={from}-*")
            } else {
                format!("member;range={from}-{}", to - 1)
            };
            Ok(Some(SearchEntry {
                dn: dn.to_string(),
                attrs: [(key, members(from, to))].into(),
                bin_attrs: Default::default(),
            }))
        })
    }

    fn close(self: Box<Self>) -> ranged::BoxFut<'static, ()> {
        Box::pin(async {})
    }
}

/// A group of `n` members as the first reply has it: all of them (`-*`)
/// up to 1,500, else the first 1,500.
fn group(dn: &str, n: usize) -> SearchEntry {
    let key = if n <= 1500 {
        "member;range=0-*".to_string()
    } else {
        "member;range=0-1499".to_string()
    };
    SearchEntry {
        dn: dn.into(),
        attrs: [
            (key, members(0, n.min(1500))),
            ("name".to_string(), vec![dn.to_string()]),
        ]
        .into(),
        bin_attrs: Default::default(),
    }
}

/// Groups of 1,500, 3,000 and 3,500 members (the last reply `-*`), and a
/// small one: completed by the pool's workers, in order, on at most four
/// connections, opened when needed. A failure comes back as an error, and
/// the worker opens a new connection for the next.
#[test]
fn the_ranged_pool_completes_members() {
    let searches = Arc::new(AtomicUsize::new(0));
    let opened = Arc::new(AtomicUsize::new(0));
    let opener: ranged::Opener = {
        let (searches, opened) = (searches.clone(), opened.clone());
        Arc::new(move || {
            opened.fetch_add(1, Ordering::SeqCst);
            let searches = searches.clone();
            Box::pin(
                async move { Ok(Box::new(FakeRanged { searches }) as Box<dyn ranged::RangedConn>) },
            )
        })
    };
    runtime().block_on(async {
        let pool = ranged::Pool::start(ranged::WORKERS, opener, None);
        let mut waits = Vec::new();
        for (dn, n) in [
            ("CN=G1500,DC=x", 1500),
            ("CN=G3000,DC=x", 3000),
            ("CN=G3500,DC=x", 3500),
            ("CN=G10,DC=x", 10),
            ("CN=G3500b,DC=x", 3500),
            ("CN=G3000b,DC=x", 3000),
            ("CN=G4501,DC=x", 4501),
        ] {
            waits.push((dn, n, pool.submit(group(dn, n)).await));
        }
        for (dn, n, rx) in waits {
            let (e, extra, _) = rx.await.unwrap().unwrap();
            assert_eq!(e.dn, dn);
            assert!(!ranged::is_ranged(&e), "{:?}", e.attrs.keys());
            assert_eq!(e.attrs["member"], members(0, n), "{dn}");
            assert_eq!(e.attrs["name"], [dn]);
            // 1,500 more a reply, the last one `-*`.
            assert_eq!(extra as usize, n.saturating_sub(1).div_euclid(1500), "{dn}");
        }
        let broken = pool.submit(group("CN=Broken,DC=x", 2000)).await;
        match broken.await.unwrap() {
            Err(ranged::Failed::Search(e)) => assert!(e.contains("connection reset"), "{e}"),
            other => panic!("{other:?}"),
        }
        // Still working, on a new connection.
        let after = pool.submit(group("CN=G3000c,DC=x", 3000)).await;
        assert_eq!(after.await.unwrap().unwrap().0.attrs["member"].len(), 3000);
        assert!(!pool.is_down());
        pool.close().await;
    });
    // 3,000: 1; 3,500: 2; 4,501: 3; the broken one and the one after: 1.
    assert_eq!(searches.load(Ordering::SeqCst), 1 + 2 + 2 + 1 + 3 + 1 + 1);
    let opened = opened.load(Ordering::SeqCst);
    assert!((1..=ranged::WORKERS + 1).contains(&opened), "{opened}");
}

/// S2: a pool that can't open a connection hands each entry back whole,
/// to be completed on the stream's own connection, and says so once.
#[test]
fn a_ranged_pool_without_connections_hands_entries_back() {
    let opener: ranged::Opener =
        Arc::new(|| Box::pin(async { Err("cannot connect: refused".to_string()) }));
    let (tx, rx) = mpsc::channel::<Msg>();
    runtime().block_on(async {
        let pool = ranged::Pool::start(2, opener, Some(tx));
        for dn in ["CN=G3000,DC=x", "CN=G3500,DC=x", "CN=G4000,DC=x"] {
            let rx = pool.submit(group(dn, 3000)).await;
            match rx.await.unwrap() {
                Err(ranged::Failed::NoConnection(mut e)) => {
                    assert_eq!(e.dn, dn);
                    // Completed inline, as the stream does.
                    let mut conn = FakeRanged {
                        searches: Default::default(),
                    };
                    ranged::complete(&mut conn, &mut e).await.unwrap();
                    assert_eq!(e.attrs["member"].len(), size_of(dn));
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(pool.is_down());
        pool.close().await;
    });
    let said: Vec<String> = rx
        .try_iter()
        .filter_map(|m| match m {
            Msg::Log(l) => Some(l),
            _ => None,
        })
        .collect();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("each stream's own connection"),
        "{}",
        said[0]
    );
}

/// Inline (a retest's read), the same completion on the stream's own
/// connection.
#[test]
fn ranged_attributes_complete_inline_too() {
    runtime().block_on(async {
        let mut conn = FakeRanged {
            searches: Default::default(),
        };
        let mut e = group("CN=G3500,DC=x", 3500);
        let n = ranged::complete(&mut conn, &mut e).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(e.attrs["member"], members(0, 3500));
        let mut small = group("CN=G10,DC=x", 10);
        assert_eq!(ranged::complete(&mut conn, &mut small).await.unwrap(), 0);
        assert_eq!(small.attrs["member"].len(), 10);
    });
}

#[test]
fn ranges_are_read_from_their_keys() {
    let e = group("CN=G2000,DC=x", 2000);
    assert!(ranged::is_ranged(&e));
    assert!(!ranged::is_ranged(&SearchEntry {
        dn: "CN=x".into(),
        attrs: [("member".to_string(), vec![])].into(),
        bin_attrs: Default::default(),
    }));
    assert_eq!(ranged::range_high("member;range=1500-2999"), Some(2999));
    assert_eq!(ranged::range_high("member;range=3000-*"), None);
    assert_eq!(
        ranged::range_bound("member;range=3000-*"),
        Some(ranged::Bound::Last)
    );
    assert_eq!(
        ranged::range_bound("member;Range=0-1499"),
        Some(ranged::Bound::Upto(1499))
    );
    for bad in [
        "member",
        "member;range=x-*",
        "member;range=0-",
        "member;foo=0-*",
    ] {
        assert_eq!(ranged::range_bound(bad), None, "{bad}");
    }
}

/// A ranged reply for an asked range: a key and how many values, or
/// nothing (the object not returned).
type Reply = fn(&str) -> Option<(String, usize)>;

/// Answers each ranged search with `reply(asked range)`.
struct OddRanged {
    reply: Reply,
    searches: usize,
}

impl ranged::RangedConn for OddRanged {
    fn base_search<'a>(
        &'a mut self,
        dn: &'a str,
        attr: &'a str,
    ) -> ranged::BoxFut<'a, Result<Option<SearchEntry>, String>> {
        Box::pin(async move {
            self.searches += 1;
            if self.searches > 50 {
                return Err("asked again and again".into());
            }
            Ok((self.reply)(attr).map(|(key, n)| SearchEntry {
                dn: dn.to_string(),
                attrs: [(key, members(0, n))].into(),
                bin_attrs: Default::default(),
            }))
        })
    }

    fn close(self: Box<Self>) -> ranged::BoxFut<'static, ()> {
        Box::pin(async {})
    }
}

/// A ranged reply that doesn't move on, has no `-*` end, can't
/// be read or doesn't come fails the entry at once: never values cut short
/// without a word, never the same range asked for again.
#[test]
fn odd_ranged_replies_fail_the_entry() {
    let cases: [(&str, Reply); 5] = [
        // The same range again.
        ("didn't move on", |_| {
            Some(("member;range=1500-2999".into(), 1500))
        }),
        // Backwards.
        ("didn't move on", |_| {
            Some(("member;range=0-1499".into(), 10))
        }),
        // No reply: the object gone between two searches.
        ("wasn't returned", |_| None),
        // The plain attribute, no range.
        ("has no range", |_| Some(("member".into(), 10))),
        ("can't be read", |_| {
            Some(("member;range=1500-x".into(), 10))
        }),
    ];
    runtime().block_on(async {
        for (why, reply) in cases {
            let mut conn = OddRanged { reply, searches: 0 };
            let mut e = group("CN=G4000,DC=x", 4000);
            let err = ranged::complete(&mut conn, &mut e).await.unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
            assert!(err.contains("incomplete"), "{err}");
            assert!(conn.searches <= 2, "{why}: {} searches", conn.searches);
        }
        // A first reply whose range can't be read fails too.
        let mut conn = OddRanged {
            reply: |_| None,
            searches: 0,
        };
        let mut e = group("CN=G10,DC=x", 10);
        let values = e.attrs.remove("member;range=0-*").unwrap();
        e.attrs.insert("member;range=0-x".into(), values);
        let err = ranged::complete(&mut conn, &mut e).await.unwrap_err();
        assert!(err.contains("can't be read"), "{err}");
        assert_eq!(conn.searches, 0);
    });
}

// ----------------------------------------------------------------- SYSVOL

/// K threads over 200 GPOs: each read once, the results in the GPOs'
/// order, the count of those done only going up.
#[test]
fn the_sysvol_pool_reads_each_gpo_once() {
    let gpos: Vec<String> = (0..200).map(|i| format!("{{GPO-{i:03}}}")).collect();
    for k in [1, 3, pool::SYSVOL_WORKERS] {
        let reads: Vec<AtomicUsize> = gpos.iter().map(|_| AtomicUsize::new(0)).collect();
        let progress = Mutex::new(Vec::new());
        let at_once = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let out = pool::blocking(
            &gpos,
            k,
            || false,
            |g| {
                let now = at_once.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                let i: usize = g[5..8].parse().unwrap();
                reads[i].fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_micros(300));
                at_once.fetch_sub(1, Ordering::SeqCst);
                format!("read {g}")
            },
            |n| progress.lock().unwrap().push(n),
        );
        assert!(!out.timed_out);
        assert!(reads.iter().all(|r| r.load(Ordering::SeqCst) == 1));
        assert!(out
            .results
            .iter()
            .zip(&gpos)
            .all(|(r, g)| r.as_deref() == Some(format!("read {g}").as_str())));
        let progress = progress.into_inner().unwrap();
        assert_eq!(progress, (1..=200).collect::<Vec<_>>(), "k = {k}");
        assert!(most.load(Ordering::SeqCst) <= k);
    }
}

/// The budget: once it is up no GPO is started; those left are not read,
/// and the pass says it ran out of time.
#[test]
fn the_sysvol_pool_keeps_to_its_budget() {
    let gpos: Vec<usize> = (0..400).collect();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(150);
    let starts = Mutex::new(Vec::new());
    let out = pool::blocking(
        &gpos,
        pool::SYSVOL_WORKERS,
        || Instant::now() > deadline,
        |_| {
            starts.lock().unwrap().push(Instant::now());
            std::thread::sleep(Duration::from_millis(20));
        },
        |_| {},
    );
    assert!(out.timed_out);
    let read = out.results.iter().filter(|r| r.is_some()).count();
    assert!(read > 0 && read < 400, "{read}");
    assert!(starts.lock().unwrap().iter().all(|t| *t <= deadline));
    // Nothing left: not out of time.
    let all = pool::blocking(&gpos[..5], 8, || false, |_| (), |_| {});
    assert!(!all.timed_out);
}

/// The SMB pool: workers on sessions of their own (the first given one),
/// each GPO once; a worker that can't connect leaves its share to the
/// others; the budget stops it.
#[test]
fn the_smb_pool_shares_the_gpos_out() {
    let rt = runtime();
    let gpos: Vec<String> = (0..60).map(|i| format!("G{i}")).collect();
    let opened = std::cell::Cell::new(0usize);
    let reads = std::cell::RefCell::new(BTreeMap::<String, usize>::new());
    let progress = std::cell::RefCell::new(Vec::new());
    let (out, lost) = rt.block_on(pool::concurrent(
        &gpos,
        pool::SYSVOL_WORKERS,
        || false,
        Some(100usize),
        async || {
            opened.set(opened.get() + 1);
            // The third session is refused.
            if opened.get() == 3 {
                Err("STATUS_LOGON_FAILURE".to_string())
            } else {
                Ok(opened.get())
            }
        },
        async |session: &mut usize, g: &String| {
            tokio::time::sleep(Duration::from_millis(1)).await;
            *reads.borrow_mut().entry(g.clone()).or_default() += 1;
            (*session, g.clone())
        },
        |n| progress.borrow_mut().push(n),
    ));
    assert_eq!(lost.as_deref(), Some("STATUS_LOGON_FAILURE"));
    assert_eq!(
        opened.get(),
        pool::SYSVOL_WORKERS - 1,
        "worker 1 had its session"
    );
    assert!(reads.borrow().values().all(|&n| n == 1));
    assert_eq!(reads.borrow().len(), 60);
    let sessions: BTreeSet<usize> = out.results.iter().map(|r| r.as_ref().unwrap().0).collect();
    assert!(sessions.contains(&100));
    assert!(!sessions.contains(&3));
    assert_eq!(*progress.borrow(), (1..=60).collect::<Vec<_>>());
    // Out of time from the start: nothing read.
    let (none, _) = rt.block_on(pool::concurrent(
        &gpos,
        2,
        || true,
        None,
        async || Ok(0usize),
        async |_: &mut usize, _: &String| (),
        |_| {},
    ));
    assert!(none.timed_out);
    assert!(none.results.iter().all(Option::is_none));
}
