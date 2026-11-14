//! Progress tracking for long jobs: numbered steps, counts by type, expected
//! totals, an overall percentage and a smoothed time to completion.
//!
//! A [`Tracker`] knows the steps of a job up front, each with a weight (its
//! rough share of the total time). A step is *measurable* while it knows how
//! many units it has to do (objects, bytes); otherwise it only counts.
//! [`Tracker::status`] turns that into a [`Status`] snapshot that a UI or a
//! terminal renders as is.
//!
//! The ETA comes from the observed rate of overall progress, smoothed with an
//! exponentially weighted moving average over about [`ETA_WINDOW_SECS`]. It
//! stays `None` ("estimating…") until the rate has been watched for
//! [`ETA_SETTLE_SECS`] of measurable work, and counts down on its own through
//! steps that cannot be measured.
//!
//! Nothing here is specific to collection: the CLI uses the same tracker for
//! analysis progress (bytes read, then the analysis steps).

use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;

/// Time constant of the rate smoothing, in seconds.
pub const ETA_WINDOW_SECS: f64 = 10.0;
/// Measurable progress watched before an ETA is shown, in seconds.
pub const ETA_SETTLE_SECS: f64 = 5.0;
/// A measurable step never reports more than this share of itself done until
/// the next step starts: expected totals are estimates.
const STEP_CAP: f64 = 0.99;
/// No progress for this long counts as a stall (the rate drops); shorter
/// gaps are taken as a collector that reports in bursts.
const STALL_SECS: f64 = 15.0;
/// An estimate longer than this says nothing useful: none is shown (a read
/// that stalled showed "98:59:12 left").
pub const ETA_MAX_SECS: f64 = 24.0 * 3600.0;

/// One step of a job.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    /// Stable identifier (`"read"`, `"parse"`, ...).
    pub key: &'static str,
    /// What the user sees ("Reading the directory").
    pub label: String,
    /// Relative share of the job's time. Only ratios matter.
    pub weight: f64,
}

impl Step {
    pub fn new(key: &'static str, label: impl Into<String>, weight: f64) -> Self {
        Self {
            key,
            label: label.into(),
            weight: weight.max(0.0),
        }
    }
}

/// A snapshot of a job's progress, ready to show.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Status {
    /// Key of the current step.
    pub key: String,
    /// The current step, 1-based ("2 of 5").
    pub step: usize,
    /// Number of steps.
    pub steps: usize,
    /// The current step's label.
    pub phase: String,
    /// Extra words about the current step, e.g. which naming context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Units done in the current step.
    pub done: u64,
    /// Units the current step expects, when known.
    pub total: Option<u64>,
    /// What a unit is ("objects", "bytes", "computers").
    pub unit: String,
    /// Units per second in the current step, smoothed.
    pub rate: Option<f64>,
    /// Objects so far, by BloodHound type (`users`, `computers`, ...).
    pub objects: BTreeMap<String, u64>,
    /// Objects expected, by type, when known.
    pub expected: BTreeMap<String, u64>,
    /// Whole job, 0 to 100.
    pub percent: f64,
    /// Current step, 0 to 100, when it is measurable.
    pub step_percent: Option<f64>,
    /// Seconds left, or `None` while estimating.
    pub eta_secs: Option<u64>,
    /// Seconds since the job started.
    pub elapsed_secs: u64,
    /// The job has finished.
    pub finished: bool,
    /// A read in parts: its streams and parts, while it reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<ReadParts>,
}

/// A read in parts on several streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct ReadParts {
    /// Streams reading now.
    pub streams: u32,
    /// Parts in all, and done (those read before a resume included).
    pub parts: u64,
    pub done: u64,
}

impl ReadParts {
    /// "4 streams".
    pub fn streams_words(&self) -> String {
        pathwarden_core::text::count(self.streams as usize, "stream", "streams")
    }

    /// "Read in 68 parts; 41 done."
    pub fn parts_words(&self) -> String {
        format!(
            "Read in {} parts; {} done.",
            thousands(self.parts),
            thousands(self.done.min(self.parts))
        )
    }
}

impl Status {
    /// "2 of 5".
    pub fn step_of(&self) -> String {
        format!("{} of {}", self.step, self.steps)
    }

    /// The ETA in words: "1:05 left", "estimating…" or "almost done".
    pub fn eta_words(&self) -> String {
        match self.eta_secs {
            _ if self.finished => "done".into(),
            None => "estimating\u{2026}".into(),
            Some(0) => "almost done".into(),
            Some(s) => format!("{} left", clock(s)),
        }
    }

    /// The current step's measurable progress, as `done of about total
    /// unit` (`done of total` for bytes).
    pub fn units_words(&self) -> Option<String> {
        if self.done == 0 && self.total.is_none() {
            return None;
        }
        let done = if self.unit == "bytes" {
            bytes(self.done)
        } else {
            thousands(self.done)
        };
        Some(match self.total {
            Some(t) if self.unit == "bytes" => format!("{done} of {}", bytes(t.max(self.done))),
            Some(t) => format!(
                "{done} of about {} {}",
                thousands(t.max(self.done)),
                self.unit
            ),
            None if self.unit == "bytes" => done,
            None => format!("{done} {}", self.unit),
        })
    }
}

/// Follows a job through its steps. Not thread-safe: wrap it in a mutex to
/// share it.
#[derive(Debug, Clone)]
pub struct Tracker {
    steps: Vec<Step>,
    current: usize,
    started: Instant,
    done: u64,
    total: Option<u64>,
    unit: String,
    detail: Option<String>,
    objects: BTreeMap<String, u64>,
    expected: BTreeMap<String, u64>,
    eta: Eta,
    step_rate: Rate,
    finished: bool,
    parts: Option<ReadParts>,
}

impl Tracker {
    /// A tracker at the start of the first step. `steps` must not be empty.
    pub fn new(steps: Vec<Step>) -> Self {
        Self::starting_at(steps, Instant::now())
    }

    /// A tracker whose clock started at `started` (for tests and replays).
    pub fn starting_at(mut steps: Vec<Step>, started: Instant) -> Self {
        if steps.is_empty() {
            steps.push(Step::new("work", "Working", 1.0));
        }
        Self {
            steps,
            current: 0,
            started,
            done: 0,
            total: None,
            unit: "objects".into(),
            detail: None,
            objects: BTreeMap::new(),
            expected: BTreeMap::new(),
            eta: Eta::default(),
            step_rate: Rate::default(),
            finished: false,
            parts: None,
        }
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Key of the current step.
    pub fn current(&self) -> &'static str {
        self.steps[self.current].key
    }

    /// Label of the current step.
    pub fn label(&self) -> &str {
        &self.steps[self.current].label
    }

    /// Moves to the step called `key`. Only moves forward: going back to a
    /// step already passed, or to an unknown one, does nothing. Returns
    /// whether the step changed.
    pub fn enter(&mut self, key: &str) -> bool {
        let Some(i) = self.steps.iter().position(|s| s.key == key) else {
            return false;
        };
        if i <= self.current {
            return false;
        }
        self.current = i;
        self.done = 0;
        self.total = None;
        self.unit = "objects".into();
        self.detail = None;
        self.parts = None;
        self.eta.step_changed();
        self.step_rate = Rate::default();
        true
    }

    /// The current step reads in `parts` parts, `done` of them done, on
    /// `streams` streams.
    pub fn streams(&mut self, streams: u32, parts: u64, done: u64) {
        self.parts = Some(ReadParts {
            streams,
            parts,
            done,
        });
    }

    /// Changes the current step's label (e.g. a collector names it better).
    pub fn relabel(&mut self, label: impl Into<String>) {
        self.steps[self.current].label = label.into();
    }

    /// Changes the weight of the current step or an upcoming one, once its
    /// size is known (e.g. the number of GPOs to read). The steps already
    /// done are scaled with it so that the percentage doesn't jump; only
    /// what is left is shared out again. A step already passed, or an
    /// unknown one, is left alone. Returns whether the weight changed.
    pub fn reweight(&mut self, key: &str, weight: f64) -> bool {
        let Some(i) = self.steps.iter().position(|s| s.key == key) else {
            return false;
        };
        if i < self.current || self.finished {
            return false;
        }
        let before = self.fraction();
        self.steps[i].weight = weight.max(0.0);
        // Keep the fraction done: scale the steps passed by `k` so that
        // (k * passed + here) / (k * passed + left) is what it was.
        let passed: f64 = self.steps[..self.current].iter().map(|s| s.weight).sum();
        let left: f64 = self.steps[self.current..].iter().map(|s| s.weight).sum();
        let here = self.steps[self.current].weight * self.step_fraction().unwrap_or(0.0);
        if passed > 0.0 && before < 1.0 {
            let k = (before * left - here) / (passed * (1.0 - before));
            if k.is_finite() && k > 0.0 {
                for s in &mut self.steps[..self.current] {
                    s.weight *= k;
                }
            }
        }
        true
    }

    /// Units done in the current step, of `total` when known.
    pub fn units(&mut self, done: u64, total: Option<u64>) {
        self.done = done;
        if total.is_some() {
            self.total = total;
        }
    }

    /// Units done in the current step before it went on from where an
    /// earlier run stopped: the rate and the ETA start afresh from
    /// here instead of counting them as read just now.
    pub fn resume_units(&mut self, done: u64) {
        self.done = done;
        self.step_rate = Rate::default();
        self.eta.step_changed();
    }

    /// Sets the expected units of the current step without changing `done`.
    pub fn expect_units(&mut self, total: u64) {
        self.total = Some(total);
    }

    /// What the current step's units are ("objects", "bytes", ...).
    pub fn unit(&mut self, unit: impl Into<String>) {
        self.unit = unit.into();
    }

    pub fn detail(&mut self, detail: Option<String>) {
        self.detail = detail;
    }

    /// Objects of one type so far.
    pub fn count(&mut self, kind: &str, n: u64) {
        self.objects.insert(kind.to_string(), n);
    }

    /// Objects of one type expected in the end.
    pub fn expect(&mut self, kind: &str, n: u64) {
        self.expected.insert(kind.to_string(), n);
    }

    /// The job finished: 100%, nothing left.
    pub fn finish(&mut self) {
        self.current = self.steps.len() - 1;
        self.finished = true;
    }

    /// Share of the current step done, when measurable.
    fn step_fraction(&self) -> Option<f64> {
        let total = self.total.filter(|&t| t > 0)?;
        Some((self.done as f64 / total as f64).clamp(0.0, STEP_CAP))
    }

    /// Share of the whole job done, 0 to 1.
    pub fn fraction(&self) -> f64 {
        if self.finished {
            return 1.0;
        }
        let all: f64 = self.steps.iter().map(|s| s.weight).sum();
        if all <= 0.0 {
            return 0.0;
        }
        let before: f64 = self.steps[..self.current].iter().map(|s| s.weight).sum();
        let here = self.steps[self.current].weight * self.step_fraction().unwrap_or(0.0);
        ((before + here) / all).clamp(0.0, 1.0)
    }

    /// The progress now.
    pub fn status(&mut self) -> Status {
        self.status_at(Instant::now())
    }

    /// The progress at `now` (for tests and replays). Each call feeds the
    /// ETA estimate, so call it at a steady pace (a few times a second).
    pub fn status_at(&mut self, now: Instant) -> Status {
        let t = now.saturating_duration_since(self.started).as_secs_f64();
        let fraction = self.fraction();
        let measurable = self.step_fraction().is_some();
        let eta = if self.finished {
            Some(0.0)
        } else {
            self.eta.sample(t, fraction, measurable)
        };
        let rate = self.step_rate.sample(t, self.done as f64);
        let step = &self.steps[self.current];
        Status {
            key: step.key.to_string(),
            step: self.current + 1,
            steps: self.steps.len(),
            phase: step.label.clone(),
            detail: self.detail.clone(),
            done: self.done,
            total: self.total,
            unit: self.unit.clone(),
            rate,
            objects: self.objects.clone(),
            expected: self.expected.clone(),
            percent: (fraction * 1000.0).round() / 10.0,
            step_percent: self.step_fraction().map(|f| (f * 1000.0).round() / 10.0),
            eta_secs: eta.map(|s| s.round().max(0.0) as u64),
            elapsed_secs: t as u64,
            finished: self.finished,
            parts: self.parts.filter(|_| !self.finished),
        }
    }
}

/// Smoothed rate of a growing quantity (units per second).
#[derive(Debug, Clone, Default)]
struct Rate {
    last: Option<(f64, f64)>,
    first: Option<f64>,
    rate: Option<f64>,
}

impl Rate {
    /// Feeds `value` at time `t`; returns the smoothed rate once it has been
    /// watched for a second.
    fn sample(&mut self, t: f64, value: f64) -> Option<f64> {
        let Some((t0, v0)) = self.last else {
            self.last = Some((t, value));
            self.first.get_or_insert(t);
            return None;
        };
        let dt = t - t0;
        if dt >= 0.25 && (value > v0 || dt >= STALL_SECS) {
            let inst = ((value - v0) / dt).max(0.0);
            let alpha = 1.0 - (-dt / ETA_WINDOW_SECS).exp();
            self.rate = Some(match self.rate {
                Some(r) => r + alpha * (inst - r),
                None => inst,
            });
            self.last = Some((t, value));
        }
        let watched = t - self.first.unwrap_or(t);
        self.rate.filter(|_| watched >= 1.0)
    }
}

/// ETA from the smoothed rate of overall progress.
#[derive(Debug, Clone, Default)]
struct Eta {
    /// Last sample: (time, fraction), within the current step.
    last: Option<(f64, f64)>,
    /// Smoothed fraction per second.
    rate: Option<f64>,
    /// Seconds of measurable progress watched.
    watched: f64,
    /// The last estimate made: (time, seconds left). Counted down through
    /// steps that cannot be measured.
    last_estimate: Option<(f64, f64)>,
}

impl Eta {
    /// A new step: the fraction jumps, so the next sample starts afresh
    /// (the smoothed rate is kept).
    fn step_changed(&mut self) {
        self.last = None;
    }

    fn countdown(&self, t: f64) -> Option<f64> {
        self.last_estimate
            .map(|(t0, left)| (left - (t - t0)).max(0.0))
    }

    fn sample(&mut self, t: f64, fraction: f64, measurable: bool) -> Option<f64> {
        if !measurable {
            self.last = None;
            return self.countdown(t);
        }
        let Some((t0, f0)) = self.last else {
            self.last = Some((t, fraction));
            return self.countdown(t);
        };
        let dt = t - t0;
        // Collectors that report in bursts (SharpHound every few seconds)
        // look stalled between reports: wait for the next one, unless it is
        // really stalled.
        if dt < 0.25 || (fraction <= f0 && dt < STALL_SECS) {
            return self.countdown(t);
        }
        let inst = ((fraction - f0) / dt).max(0.0);
        let alpha = 1.0 - (-dt / ETA_WINDOW_SECS).exp();
        self.rate = Some(match self.rate {
            Some(r) => r + alpha * (inst - r),
            None => inst,
        });
        self.watched += dt;
        self.last = Some((t, fraction));
        let rate = self.rate.unwrap_or(0.0);
        if self.watched < ETA_SETTLE_SECS || rate <= 1e-9 {
            return None;
        }
        let left = (1.0 - fraction) / rate;
        // Stalled (nothing for a while), or so slow the estimate means
        // nothing: no estimate, rather than one that only grows.
        if inst <= 0.0 || left > ETA_MAX_SECS {
            self.last_estimate = None;
            return None;
        }
        self.last_estimate = Some((t, left));
        Some(left)
    }
}

/// `m:ss` or `h:mm:ss`.
pub fn clock(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// `1,234,567`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn steps() -> Vec<Step> {
        vec![
            Step::new("connect", "Connecting", 5.0),
            Step::new("read", "Reading", 70.0),
            Step::new("parse", "Parsing", 20.0),
            Step::new("write", "Writing", 5.0),
        ]
    }

    #[test]
    fn steps_and_percent() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        let s = tr.status_at(t0);
        assert_eq!((s.step, s.steps, s.key.as_str()), (1, 4, "connect"));
        assert_eq!(s.percent, 0.0);
        assert!(tr.enter("read"));
        assert!(!tr.enter("connect"), "never goes back");
        assert!(!tr.enter("nope"));
        tr.units(500, Some(1000));
        let s = tr.status_at(t0 + Duration::from_secs(1));
        assert_eq!(s.step_of(), "2 of 4");
        // 5 + 70 * 0.5 = 40%
        assert_eq!(s.percent, 40.0);
        assert_eq!(s.step_percent, Some(50.0));
        // More than expected: capped below the next step.
        tr.units(2000, None);
        let s = tr.status_at(t0 + Duration::from_secs(2));
        assert!(s.percent < 75.0 && s.percent > 74.0, "{}", s.percent);
        assert_eq!(s.units_words().unwrap(), "2,000 of about 2,000 objects");
        tr.finish();
        let s = tr.status_at(t0 + Duration::from_secs(3));
        assert_eq!((s.percent, s.eta_secs, s.finished), (100.0, Some(0), true));
    }

    /// Lab: a read that stalls (the domain controller sends nothing) shows no
    /// time left, not one that climbs to "98:59:12 left"; it comes back once
    /// the read goes on.
    #[test]
    fn a_stalled_read_shows_no_time_left() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(vec![Step::new("read", "Reading", 1.0)], t0);
        let at =
            |tr: &mut Tracker, tenth: u64| tr.status_at(t0 + Duration::from_millis(tenth * 100));
        for tenth in 0..=300u64 {
            tr.units(tenth * 10, Some(100_000)); // 100/s for 30 s
            at(&mut tr, tenth);
        }
        assert!(at(&mut tr, 300).eta_secs.is_some());
        // Five minutes with nothing read.
        let mut shown = Vec::new();
        for tenth in 301..=3300u64 {
            shown.push(at(&mut tr, tenth).eta_secs);
        }
        assert!(shown.iter().flatten().all(|&s| s < ETA_MAX_SECS as u64));
        let s = at(&mut tr, 3300);
        assert_eq!(s.eta_secs, None);
        assert_eq!(s.eta_words(), "estimating\u{2026}");
        // Reading again: an estimate again.
        let mut back = None;
        for tenth in 3301..=3700u64 {
            tr.units(3000 + (tenth - 3300) * 10, Some(100_000));
            back = at(&mut tr, tenth).eta_secs;
        }
        assert!(back.is_some_and(|s| s < ETA_MAX_SECS as u64), "{back:?}");
    }

    /// A steady rate: "estimating…" for the first seconds, then an ETA that
    /// matches the true time left and counts down.
    #[test]
    fn eta_settles_on_a_steady_rate() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(vec![Step::new("read", "Reading", 1.0)], t0);
        // 100 objects/s of 10,000: 100 s in all.
        let mut etas = Vec::new();
        for tenth in 0..=600u64 {
            let t = tenth as f64 / 10.0;
            tr.units((t * 100.0) as u64, Some(10_000));
            let s = tr.status_at(t0 + Duration::from_millis(tenth * 100));
            etas.push((t, s.eta_secs));
        }
        assert!(etas
            .iter()
            .take_while(|(t, _)| *t < 4.9)
            .all(|(_, e)| e.is_none()));
        let (_, at_30) = etas.iter().find(|(t, _)| (*t - 30.0).abs() < 0.01).unwrap();
        let at_30 = at_30.expect("estimated by 30 s");
        assert!((65..=75).contains(&at_30), "70 s left at 30 s, got {at_30}");
        let (_, at_60) = etas.last().unwrap();
        let at_60 = at_60.unwrap();
        assert!((35..=45).contains(&at_60), "40 s left at 60 s, got {at_60}");
        assert_eq!(
            tr.status_at(t0 + Duration::from_secs(60)).eta_words(),
            format!("{} left", clock(at_60))
        );
    }

    /// The rate halves: the estimate follows within the smoothing window,
    /// without jumping on a single slow sample.
    #[test]
    fn eta_follows_a_slowdown_smoothly() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(vec![Step::new("read", "Reading", 1.0)], t0);
        let mut done = 0.0;
        let eta_at = |tr: &mut Tracker, tenth: u64| {
            tr.status_at(t0 + Duration::from_millis(tenth * 100))
                .eta_secs
        };
        let mut last = None;
        for tenth in 0..=1200u64 {
            done += if tenth < 300 { 10.0 } else { 5.0 }; // 100/s, then 50/s
            tr.units(done as u64, Some(20_000));
            let e = eta_at(&mut tr, tenth);
            if tenth == 300 {
                last = e;
            }
            if tenth == 301 {
                let (a, b) = (last.unwrap() as i64, e.unwrap() as i64);
                assert!((a - b).abs() < 5, "no jump on one sample: {a} -> {b}");
            }
        }
        // At 120 s: 3,000 + 4,500 = 7,500 done, 12,500 left at 50/s = 250 s.
        let e = eta_at(&mut tr, 1200).unwrap();
        assert!((235..=265).contains(&e), "about 250 s left, got {e}");
    }

    /// A step that can't be measured counts the last estimate down instead
    /// of inflating it; the next measurable step re-estimates.
    #[test]
    fn eta_counts_down_through_unmeasured_steps() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(
            vec![
                Step::new("read", "Reading", 50.0),
                Step::new("resolve", "Resolving", 10.0),
                Step::new("parse", "Parsing", 40.0),
            ],
            t0,
        );
        for tenth in 0..=200u64 {
            tr.units(tenth * 5, Some(1000)); // 50/s: 20 s for read
            tr.status_at(t0 + Duration::from_millis(tenth * 100));
        }
        tr.enter("resolve");
        let a = tr.status_at(t0 + Duration::from_secs(21)).eta_secs.unwrap();
        let b = tr.status_at(t0 + Duration::from_secs(24)).eta_secs.unwrap();
        assert_eq!(a.saturating_sub(b), 3, "{a} then {b}");
        assert!(tr
            .status_at(t0 + Duration::from_secs(24))
            .step_percent
            .is_none());
        let far = tr.status_at(t0 + Duration::from_secs(10_000));
        assert_eq!(far.eta_secs, Some(0));
        assert_eq!(far.eta_words(), "almost done");
    }

    /// SharpHound reports every few seconds: the estimate must not swing
    /// between reports.
    #[test]
    fn eta_is_steady_with_bursty_reports() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(vec![Step::new("enum", "Enumerating", 1.0)], t0);
        let mut seen = Vec::new();
        for tenth in 0..=1200u64 {
            // 100 objects/s of 20,000, reported every 5 s.
            let reported = (tenth / 50) * 50 * 10;
            tr.units(reported, Some(20_000));
            let s = tr.status_at(t0 + Duration::from_millis(tenth * 100));
            if tenth >= 600 {
                seen.push(s.eta_secs.expect("estimated") as i64);
            }
        }
        // True time left goes from 140 s (at 60 s) to 80 s (at 120 s).
        let first = seen[0];
        let last = *seen.last().unwrap();
        assert!((125..=155).contains(&first), "{first}");
        assert!((65..=95).contains(&last), "{last}");
        // It counts down smoothly: never up by more than a few seconds.
        for w in seen.windows(2) {
            assert!(w[1] - w[0] <= 3, "jumped from {} to {}", w[0], w[1]);
        }
    }

    /// A step that turns out to be large gets a larger share of what is
    /// left, without the bar jumping back.
    #[test]
    fn reweight_keeps_the_percentage() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        tr.enter("parse");
        tr.units(500, Some(1000));
        // 5 + 70 + 20 * 0.5 = 85%
        let s = tr.status_at(t0);
        assert_eq!(s.percent, 85.0);
        // The last step (writing) is 10 times as long as thought.
        assert!(tr.reweight("write", 50.0));
        assert_eq!(tr.status_at(t0).percent, 85.0);
        // Finishing parse is now a smaller step of the whole: what is left
        // is mostly writing.
        tr.units(1000, Some(1000));
        let at_end_of_parse = tr.status_at(t0).percent;
        assert!((85.0..90.0).contains(&at_end_of_parse), "{at_end_of_parse}");
        tr.enter("write");
        tr.units(500, Some(1000));
        let half = tr.status_at(t0).percent;
        assert!((90.0..96.0).contains(&half), "{half}");
        // The current step too, part done.
        assert!(tr.reweight("write", 5.0));
        assert_eq!(tr.status_at(t0).percent, half);
        // A step already passed, or an unknown one: nothing changes.
        assert!(!tr.reweight("read", 1.0));
        assert!(!tr.reweight("nope", 1.0));
        assert_eq!(tr.status_at(t0).percent, half);
    }

    /// Re-weighting before anything is done changes the shares only.
    #[test]
    fn reweight_at_the_start() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        assert!(tr.reweight("write", 105.0));
        assert_eq!(tr.status_at(t0).percent, 0.0);
        tr.enter("write");
        // 5 + 70 + 20 = 95 of 200.
        assert_eq!(tr.status_at(t0).percent, 47.5);
    }

    #[test]
    fn rate_is_per_step() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        tr.enter("read");
        for tenth in 0..=30u64 {
            tr.units(tenth * 20, Some(10_000)); // 200/s
            tr.status_at(t0 + Duration::from_millis(tenth * 100));
        }
        let r = tr.status_at(t0 + Duration::from_millis(3100)).rate.unwrap();
        assert!((150.0..=250.0).contains(&r), "{r}");
        tr.enter("parse");
        assert!(tr
            .status_at(t0 + Duration::from_millis(3200))
            .rate
            .is_none());
    }

    /// A read that resumes from 300,000 entries keeps today's rate:
    /// those entries are not counted as read in the first second.
    #[test]
    fn a_resumed_read_starts_its_rate_afresh() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        tr.enter("read");
        tr.status_at(t0);
        tr.resume_units(300_000);
        for tenth in 3..=30u64 {
            tr.units(300_000 + (tenth - 3) * 20, Some(1_000_000)); // 200/s
            tr.status_at(t0 + Duration::from_millis(tenth * 100));
        }
        let s = tr.status_at(t0 + Duration::from_millis(3100));
        assert_eq!(s.done, 300_540);
        let r = s.rate.unwrap();
        assert!((150.0..=250.0).contains(&r), "{r}");
    }

    /// A read in parts shows its streams and parts while it reads,
    /// not in the next step, and not once finished.
    #[test]
    fn a_read_in_parts_says_its_streams() {
        let t0 = Instant::now();
        let mut tr = Tracker::starting_at(steps(), t0);
        tr.enter("read");
        assert_eq!(tr.status_at(t0).parts, None);
        tr.streams(4, 68, 41);
        let p = tr.status_at(t0).parts.unwrap();
        assert_eq!(p.streams_words(), "4 streams");
        assert_eq!(p.parts_words(), "Read in 68 parts; 41 done.");
        let json = serde_json::to_value(tr.status_at(t0)).unwrap();
        assert_eq!(
            json["parts"],
            serde_json::json!({"streams": 4, "parts": 68, "done": 41})
        );
        tr.streams(1, 68, 70);
        let p = tr.status_at(t0).parts.unwrap();
        assert_eq!(p.streams_words(), "1 stream");
        assert_eq!(p.parts_words(), "Read in 68 parts; 68 done.");
        tr.enter("parse");
        assert_eq!(tr.status_at(t0).parts, None);
        assert!(serde_json::to_value(tr.status_at(t0)).unwrap()["parts"].is_null());
        tr.streams(2, 3, 1);
        tr.finish();
        assert_eq!(tr.status_at(t0).parts, None);
    }

    #[test]
    fn words() {
        assert_eq!(clock(5), "0:05");
        assert_eq!(clock(65), "1:05");
        assert_eq!(clock(3725), "1:02:05");
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(1_900_000_000), "1.8 GB");
        let s = Status {
            done: 1 << 30,
            total: Some(2 << 30),
            unit: "bytes".into(),
            ..Status::default()
        };
        assert_eq!(s.units_words().unwrap(), "1.0 GB of 2.0 GB");
        let s = Status {
            done: 42,
            unit: "objects".into(),
            ..Status::default()
        };
        assert_eq!(s.units_words().unwrap(), "42 objects");
        assert_eq!(s.eta_words(), "estimating\u{2026}");
    }
}
