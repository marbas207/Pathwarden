//! Progress over time, from the `history/<run>.json` points `pathwarden run`
//! writes into the state: what changed since the last run ([`crate::since`]),
//! a compact table and sparklines.

use std::borrow::Cow;
use std::path::Path;

use crate::state::{CompletenessPoint, FindingsState, HistoryPoint};
use crate::time::format_local;

/// Reads every history point under `<state>/history`, oldest first. Files
/// that are not history points are skipped and named in the second value.
/// Points come as written: those recorded before trusted domains were left
/// out keep their scopes (the UI regroups them with
/// [`crate::state::migrate_points`]).
///
/// An encrypted history ([`crate::crypt`]) is read with its passphrase;
/// without it, the error says how to give it.
pub fn load(state_dir: &Path) -> Result<(Vec<HistoryPoint>, Vec<String>), String> {
    crate::store::check_readable(state_dir).map_err(|e| format!("{e:#}"))?;
    let mut points = Vec::new();
    let mut skipped = Vec::new();
    // Every *.json file, as before: one that isn't a run's point (its name
    // isn't a run ID) is named in `skipped`.
    let dir = state_dir.join("history");
    if !crate::crypt::is_encrypted(state_dir) {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".json")
                    && !crate::store::has_state_file(state_dir, &format!("history/{name}"))
                {
                    skipped.push(e.path().display().to_string());
                }
            }
        }
    }
    // Plain files in an encrypted history: never read.
    for rel in crate::store::planted_files(state_dir) {
        if rel.starts_with("history/") {
            skipped.push(format!(
                "{} (a plain file in an encrypted history)",
                state_dir.join(&rel).display()
            ));
        }
    }
    let files = crate::store::list_state_files(state_dir, "history")
        .map_err(|e| format!("reading {}: {e:#}", dir.display()))?;
    for rel in files {
        let name = rel.trim_start_matches("history/").trim_end_matches(".json");
        let read = match crate::store::read_state_file(state_dir, &rel) {
            Ok(t) => t,
            Err(e) => {
                // Refused by its binding: say why.
                if let Some(b) = e
                    .chain()
                    .find_map(|c| c.downcast_ref::<crate::binding::BindingError>())
                {
                    skipped.push(format!(
                        "{} ({})",
                        state_dir.join(&rel).display(),
                        b.short()
                    ));
                    continue;
                }
                None
            }
        };
        match read.and_then(|t| crate::status_keys::from_slice::<HistoryPoint>(&t).ok()) {
            // A point copied over another's file (a swap, or the same
            // point twice) is not taken for the run its name says.
            Some(p) if p.run_id != name => skipped.push(format!(
                "{} (it holds run {}, not the run its name says)",
                state_dir.join(&rel).display(),
                p.run_id
            )),
            // A newer Pathwarden's point: named, never read as one of
            // ours (docs/dev/formats.md).
            Some(p)
                if !crate::formats::of_u32(p.version, crate::state::STATE_VERSION).is_known() =>
            {
                skipped.push(format!(
                    "{}: it was saved by a newer Pathwarden. Update Pathwarden to read it.",
                    state_dir.join(&rel).display()
                ))
            }
            Some(p) => points.push(p),
            None => skipped.push(state_dir.join(&rel).display().to_string()),
        }
    }
    points.sort_by(|a, b| a.at.cmp(&b.at).then(a.run_id.cmp(&b.run_id)));
    Ok((points, skipped))
}

/// What a report is of, for [`earlier`]: the run it was made for, or data
/// no run recorded.
#[derive(Debug, Clone, Copy)]
pub enum This<'a> {
    /// A recorded run (its run ID): `pathwarden run --report`, the app's
    /// analysis. The run itself is left out.
    Run(&'a str),
    /// A report of data (`pathwarden report --env`, the evidence pack's).
    /// The latest run of the same collection stands for it and is left
    /// out: the same data digest ([`crate::analyze::Analysis::data_digest`]),
    /// or for points without one, the same collection time. The usual
    /// nightly pattern, a run and then a report of its data, compares with
    /// the run before, as that run's own report does.
    Data {
        digest: &'a str,
        collected_at: Option<i64>,
    },
}

impl This<'_> {
    fn is(&self, p: &HistoryPoint) -> bool {
        match *self {
            This::Run(id) => p.run_id == id,
            This::Data {
                digest,
                collected_at,
            } => match &p.data {
                Some(d) => d == digest,
                None => p.collected_at.is_some() && p.collected_at == collected_at,
            },
        }
    }
}

/// The earlier runs a report of `domains` shows its trend and "since the
/// last run" against: points of the same environment (the same collected
/// domains; points without them count too), oldest first, leaving out the
/// run or data the report is of ([`This`]). Older points get today's
/// scopes first ([`crate::state::migrate_points`]).
pub fn earlier(points: &[HistoryPoint], domains: &[String], this: This) -> Vec<HistoryPoint> {
    for_report(points, domains, this).earlier
}

/// What a report's Overview compares with: the earlier runs of its
/// environment ([`earlier`]) and, when the report is of a run in the
/// history, that run's point and the findings state, which say which
/// findings opened and closed ([`ReportHistory::since`]).
#[derive(Debug, Clone, Default)]
pub struct ReportHistory<'s> {
    /// Oldest first, without the run the report is of; when the history
    /// has that run, only the runs before it.
    pub earlier: Vec<HistoryPoint>,
    /// The run the report is of, when the history has it.
    pub this_run: Option<HistoryPoint>,
    /// The findings state; it names findings only when `this_run` left it.
    /// Borrowed from a run just recorded ([`for_report_with`]), which keeps
    /// it anyway.
    pub state: Option<Cow<'s, FindingsState>>,
    /// The settings the commands under "What changed" take, as
    /// [`crate::since::SinceLast::render`] takes them (`["-c", "x.toml"]`,
    /// `["--env", "Prod"]`, `["-i", "demo:"]`); empty when not known.
    pub context: Vec<String>,
    /// The history folder the points come from, for the earlier run's
    /// exposed accounts ([`crate::exposed`]); `None` when not known.
    pub state_dir: Option<std::path::PathBuf>,
}

impl ReportHistory<'_> {
    /// The run this report compares with, as `pathwarden history` picks it
    /// ([`crate::since::previous`]): the latest earlier run of the same
    /// kind for a run in the history, else the latest earlier run. What
    /// changed ([`ReportHistory::since`]) and the account lists
    /// ([`crate::exposed`]) both compare with it. `None` without an
    /// earlier run.
    pub fn before(&self) -> Option<&HistoryPoint> {
        match &self.this_run {
            Some(p) => crate::since::previous(&self.earlier, p),
            None => crate::since::latest_point(&self.earlier),
        }
    }

    /// What changed since the last run, as `pathwarden history` compares
    /// it ([`crate::since::compare`]): the latest earlier run against this
    /// report's `posture`, with the finding changes `this_run` recorded.
    /// A report of data no run recorded has the counts but not which
    /// findings opened or closed. `None` without an earlier run.
    pub fn since(
        &self,
        posture: &crate::posture::Posture,
        generated_at: i64,
        collected_at: Option<i64>,
    ) -> Option<crate::since::SinceLast> {
        // The run before this one, as `pathwarden history` picks it.
        let before = self.before()?;
        let (run, at, changes) = match &self.this_run {
            Some(p) => (p.run_id.as_str(), p.at, p.changes),
            None => ("", generated_at, crate::state::ChangeCounts::default()),
        };
        let after = HistoryPoint::new(run, at, collected_at, posture, changes);
        let mut since = crate::since::compare(before, &after, self.state.as_deref());
        since.findings_unknown = self.this_run.is_none();
        Some(since)
    }
}

/// [`earlier`], with the run the report is of when the history has it.
/// A report of an older run compares with the runs before it only, never
/// with the ones recorded after it.
pub fn for_report(
    points: &[HistoryPoint],
    domains: &[String],
    this: This,
) -> ReportHistory<'static> {
    let mut points = points.to_vec();
    crate::state::migrate_points(&mut points);
    let scopes = crate::state::scopes_of(domains);
    points.retain(|p| p.scopes.is_empty() || scopes.is_empty() || p.scopes == scopes);
    let this_run = points
        .iter()
        .rposition(|p| this.is(p))
        .map(|i| points.remove(i));
    // The order `since::previous` goes by.
    if let Some(t) = &this_run {
        points.retain(|p| (p.at, &p.run_id) < (t.at, &t.run_id));
    }
    ReportHistory {
        earlier: points,
        this_run,
        ..ReportHistory::default()
    }
}

/// [`for_report`] from the history under `state_dir`, with its findings
/// state when the report is of the latest run (the one that left it);
/// empty when the history can't be read (the report then shows no trend).
pub fn for_report_in(state_dir: &Path, domains: &[String], this: This) -> ReportHistory<'static> {
    let Ok((points, _)) = load(state_dir) else {
        return ReportHistory::default();
    };
    let mut h = for_report(&points, domains, this);
    if h.this_run.as_ref().is_some_and(|t| is_latest(&points, t)) {
        h.state = read_state(state_dir).map(Cow::Owned);
    }
    h.state_dir = Some(state_dir.to_path_buf());
    h
}

/// [`for_report_in`] for a run just recorded, from the history in
/// `state_dir`, its `points` ([`load`]) and the findings state it left
/// (`state`, borrowed), so neither is read back.
pub fn for_report_with<'s>(
    state_dir: &Path,
    points: &[HistoryPoint],
    domains: &[String],
    this: This,
    state: &'s FindingsState,
) -> ReportHistory<'s> {
    let mut h = for_report(points, domains, this);
    if h.this_run.as_ref().is_some_and(|t| is_latest(points, t)) {
        h.state = Some(Cow::Borrowed(state));
    }
    h.state_dir = Some(state_dir.to_path_buf());
    h
}

/// `p` is the latest of `points` (oldest first): the run whose findings
/// state the folder keeps.
fn is_latest(points: &[HistoryPoint], p: &HistoryPoint) -> bool {
    crate::since::latest_point(points).is_some_and(|l| l.run_id == p.run_id)
}

/// The findings state under `state_dir`, when it can be read.
fn read_state(state_dir: &Path) -> Option<FindingsState> {
    findings_state_in(state_dir).ok().flatten()
}

/// The findings state under `state_dir` (`findings.json`, read through the
/// history's encryption): `None` when it has none yet.
pub fn findings_state_in(state_dir: &Path) -> Result<Option<FindingsState>, String> {
    let Some(bytes) =
        crate::store::read_state_file(state_dir, "findings.json").map_err(|e| format!("{e:#}"))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("findings.json can't be read: {e}"))
}

/// What changed in run `run_id` since the run before it in its environment,
/// from the history and findings state under `state_dir`: the comparison
/// `pathwarden history` prints for its latest run, and what `pathwarden
/// run` prints after its summary. `None` when the history can't be read,
/// hasn't the run, or has no earlier run of its environment.
pub fn since_run_in(state_dir: &Path, run_id: &str) -> Option<crate::since::SinceLast> {
    let (points, _) = load(state_dir).ok()?;
    since_run(&points, run_id, || read_state(state_dir).map(Cow::Owned))
}

/// [`since_run_in`] for a run just recorded, from the history `points` it
/// is in ([`load`]) and the findings state it left (`state`), so neither
/// is read back.
pub fn since_run_with(
    points: &[HistoryPoint],
    run_id: &str,
    state: &FindingsState,
) -> Option<crate::since::SinceLast> {
    since_run(points, run_id, || Some(Cow::Borrowed(state)))
}

fn since_run<'s>(
    points: &[HistoryPoint],
    run_id: &str,
    state: impl FnOnce() -> Option<Cow<'s, FindingsState>>,
) -> Option<crate::since::SinceLast> {
    let mut points = points.to_vec();
    crate::state::migrate_points(&mut points);
    let after = points.iter().find(|p| p.run_id == run_id)?;
    let before = crate::since::previous(&points, after)?;
    // The state names findings for the run that left it, the latest.
    let state = is_latest(&points, after).then(state).flatten();
    Some(crate::since::compare(before, after, state.as_deref()))
}

/// Open (unsuppressed) findings at a point.
pub fn open_findings(p: &HistoryPoint) -> usize {
    let c = &p.findings;
    c.critical + c.high + c.medium + c.low + c.info
}

/// Findings that appeared at a point: new ones and regressions.
pub fn opened(p: &HistoryPoint) -> usize {
    p.changes.new + p.changes.regressed
}

/// How far back the trend goes: the app's Progress switch and
/// `pathwarden history --range`. Measured back from the latest run, not
/// from now, so an environment that hasn't run for a while still shows
/// its last stretch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Week,
    Month,
    Quarter,
    All,
}

impl Range {
    pub const ALL: [Range; 4] = [Range::Week, Range::Month, Range::Quarter, Range::All];

    /// `1w`, `1m`, `3m` or `all` (also `week`, `month`, `quarter`).
    pub fn parse(s: &str) -> Option<Range> {
        match s.trim().to_ascii_lowercase().as_str() {
            "1w" | "week" => Some(Range::Week),
            "1m" | "month" => Some(Range::Month),
            "3m" | "quarter" => Some(Range::Quarter),
            "all" => Some(Range::All),
            _ => None,
        }
    }

    /// What [`Range::parse`] takes, for links and the command line.
    pub fn key(self) -> &'static str {
        match self {
            Range::Week => "1w",
            Range::Month => "1m",
            Range::Quarter => "3m",
            Range::All => "all",
        }
    }

    /// "1 week", for the switch.
    pub fn label(self) -> &'static str {
        match self {
            Range::Week => "1 week",
            Range::Month => "1 month",
            Range::Quarter => "3 months",
            Range::All => "All",
        }
    }

    /// "three months", in a sentence: "the three months up to the latest
    /// run".
    pub fn span(self) -> &'static str {
        match self {
            Range::Week => "week",
            Range::Month => "month",
            Range::Quarter => "three months",
            Range::All => "whole history",
        }
    }

    fn secs(self) -> Option<i64> {
        const DAY: i64 = 86_400;
        match self {
            Range::Week => Some(7 * DAY),
            Range::Month => Some(30 * DAY),
            Range::Quarter => Some(91 * DAY),
            Range::All => None,
        }
    }

    /// Where the range starts in `items` (oldest first, `at` their Unix
    /// time): the first one no older than the range before the latest.
    pub fn start<T>(self, items: &[T], at: impl Fn(&T) -> i64) -> usize {
        match (self.secs(), items.last()) {
            (Some(secs), Some(last)) => {
                let from = at(last) - secs;
                items.iter().position(|p| at(p) >= from).unwrap_or(0)
            }
            _ => 0,
        }
    }
}

/// Most runs the app's Progress page charts per environment: the latest
/// ones in the range. `pathwarden history` says when it prints more.
pub const MAX_CHARTED: usize = 40;

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// `▁▃▅█`: one bar per value, scaled between the series' minimum and
/// maximum (all the same: middle bars).
pub fn sparkline(values: &[f64]) -> String {
    let (lo, hi) = values
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    values
        .iter()
        .map(|&v| {
            if !(hi - lo).is_normal() {
                BARS[3]
            } else {
                let i = ((v - lo) / (hi - lo) * 7.0).round() as usize;
                BARS[i.min(7)]
            }
        })
        .collect()
}

fn pct(v: f64) -> String {
    crate::posture::share_percent(v)
}

/// Plan steps at a point: "5", or "-" when the plan was not recorded.
fn to_zero(p: &HistoryPoint) -> String {
    p.plan.map_or("-".into(), |s| s.steps.to_string())
}

/// Collection completeness at a point, sessions then local groups:
/// "92/88%", "92%" without member computers, "-" when not recorded,
/// "not targeted" when the run asked for neither (a Quick run), and "-"
/// for the one it did not ask for ("-/88%").
fn collected(c: Option<CompletenessPoint>) -> String {
    match c {
        None => "-".into(),
        Some(c) if c.untargeted().any() => {
            let u = c.untargeted();
            match c.local_groups_percent {
                _ if u.sessions && (u.local_groups || c.local_groups_percent.is_none()) => {
                    "not targeted".into()
                }
                Some(lg) if u.sessions => format!("-/{}%", crate::since::whole_percent(lg)),
                _ => format!("{}/-", crate::since::whole_percent(c.sessions_percent)),
            }
        }
        Some(c) => match c.local_groups_percent {
            Some(lg) => format!(
                "{}/{}%",
                crate::since::whole_percent(c.sessions_percent),
                crate::since::whole_percent(lg)
            ),
            None => format!("{}%", crate::since::whole_percent(c.sessions_percent)),
        },
    }
}

/// Most zones [`zone_trends`] gives a line each, as the app's chart of
/// accounts per tier draws them (Tier Zero and two zones).
pub const ZONE_TRENDS: usize = 2;

/// The zones of the latest point, as many as [`ZONE_TRENDS`]: the accounts
/// that can take each over, and its objects, from the first point that
/// recorded them (older points did not). The app's Progress charts draw
/// the same series.
fn zone_trends(points: &[HistoryPoint]) -> String {
    use std::fmt::Write;
    let Some(latest) = crate::since::latest_point(points) else {
        return String::new();
    };
    let mut out = String::new();
    let zones: Vec<&str> = latest
        .zones
        .iter()
        .filter(|z| z.exposed.is_some())
        .map(|z| z.zone.as_str())
        .collect();
    for name in zones.iter().take(ZONE_TRENDS) {
        let series: Vec<(usize, Option<usize>)> = points
            .iter()
            .filter_map(|p| {
                let z = p.zones.iter().find(|z| z.zone == *name)?;
                Some((z.exposed?, z.objects))
            })
            .collect();
        let (Some(a), Some(b)) = (series.first(), series.last()) else {
            continue;
        };
        let exposed: Vec<f64> = series.iter().map(|s| s.0 as f64).collect();
        let objects = match (a.1, b.1) {
            (Some(x), Some(y)) => format!(
                ", {} → {} objects",
                crate::text::num(x),
                crate::text::num(y)
            ),
            _ => String::new(),
        };
        // From settings that may come from a shared repository: no control
        // characters reach the terminal.
        let shown = crate::text::terminal_safe(name);
        let cut: String = shown.chars().take(17).collect();
        let cut = if cut.len() < shown.len() {
            format!("{}…", cut.chars().take(16).collect::<String>())
        } else {
            cut
        };
        let _ = writeln!(
            out,
            "  {cut:<18}  {}  {} → {} accounts{objects}",
            sparkline(&exposed),
            crate::text::num(a.0),
            crate::text::num(b.0),
        );
    }
    if zones.len() > ZONE_TRENDS {
        let _ = writeln!(
            out,
            "  and {} in the JSON (--json)",
            crate::text::count(zones.len() - ZONE_TRENDS, "more zone", "more zones")
        );
    }
    out
}

/// The history as text: what changed since the last run, sparklines for
/// the headline numbers, then one row per run. `last` limits the rows (and
/// sparklines) to the most recent runs; the latest run is compared with the
/// run before it in its environment whatever `last` is. `state` is the
/// findings state, to name the findings that changed
/// ([`crate::since::compare`]); `context` the settings `history` was given,
/// which the commands it points at take too ([`crate::since::SinceLast::render`]).
pub fn render(
    points: &[HistoryPoint],
    last: Option<usize>,
    state: Option<&FindingsState>,
    context: &[String],
) -> String {
    use std::fmt::Write;
    let since = crate::since::latest(points, state);
    let start = last.map_or(0, |n| points.len().saturating_sub(n));
    let points = &points[start..];
    let mut out = String::new();
    if points.is_empty() {
        out.push_str("No runs recorded yet. `pathwarden run` adds one per run.\n");
        return out;
    }
    if let Some(since) = &since {
        out.push_str(&since.render(context));
        out.push('\n');
    }
    let first = &points[0];
    let latest = &points[points.len() - 1];
    // Exposure trends only over the latest runs that share the latest run's
    // exposure basis: across a change of denominator a move is not a change
    // in the environment.
    let basis = latest.basis();
    let same = points
        .iter()
        .rposition(|p| p.basis() != basis)
        .map_or(0, |i| i + 1);
    let first_same = &points[same];
    let exposure: Vec<f64> = points[same..]
        .iter()
        .map(|p| p.tier_zero_exposure_percent)
        .collect();
    // Accounts that can reach Tier Zero: a count, so every run compares.
    let exposed: Vec<f64> = points.iter().map(|p| p.tier_zero_exposed as f64).collect();
    let open: Vec<f64> = points.iter().map(|p| open_findings(p) as f64).collect();
    let scores: Vec<f64> = points.iter().filter_map(|p| p.protection_score).collect();
    let _ = writeln!(
        out,
        "{}, {} to {}",
        crate::text::count(points.len(), "run", "runs"),
        format_local(first.at),
        format_local(latest.at)
    );
    let _ = writeln!(
        out,
        "  Exposed accounts    {}  {} → {}",
        sparkline(&exposed),
        crate::text::num(first.tier_zero_exposed),
        crate::text::num(latest.tier_zero_exposed)
    );
    let _ = writeln!(
        out,
        "  Tier Zero exposure  {}  {} → {}",
        sparkline(&exposure),
        pct(first_same.tier_zero_exposure_percent),
        pct(latest.tier_zero_exposure_percent)
    );
    if same > 0 {
        let _ = writeln!(
            out,
            "                      (from {}: {}; the {} before are marked *)",
            format_local(first_same.at),
            crate::state::BASIS_CHANGED,
            crate::text::count(same, "run", "runs")
        );
    }
    if !scores.is_empty() {
        let _ = writeln!(
            out,
            "  Tier Zero protected {}  {} → {}",
            sparkline(&scores),
            first.protection_score.map_or("n/a".into(), pct),
            latest.protection_score.map_or("n/a".into(), pct)
        );
    }
    let _ = writeln!(
        out,
        "  Open findings       {}  {} → {}",
        sparkline(&open),
        crate::text::num(open_findings(first)),
        crate::text::num(open_findings(latest))
    );
    let attack: Vec<f64> = points
        .iter()
        .map(|p| p.findings.attack_path as f64)
        .collect();
    let _ = writeln!(
        out,
        "    on attack paths   {}  {} → {}",
        sparkline(&attack),
        crate::text::num(first.findings.attack_path),
        crate::text::num(latest.findings.attack_path)
    );
    out.push_str(&zone_trends(points));
    if points.iter().any(|p| !crate::since::comparable(p, latest)) {
        let _ = writeln!(
            out,
            "  Not every run read sessions and local groups (see Collected), so these trends mix counts measured differently."
        );
    }
    // A point added after a newer run repeats changes that run counted.
    let fixed: usize = points
        .iter()
        .filter(|p| !p.inserted)
        .map(|p| p.changes.resolved)
        .sum();
    let opened_total: usize = points
        .iter()
        .skip(1)
        .filter(|p| !p.inserted)
        .map(opened)
        .sum();
    let _ = writeln!(
        out,
        "  Fixed {}, opened {} since the first run shown\n",
        crate::text::num(fixed),
        crate::text::num(opened_total)
    );
    let _ = writeln!(
        out,
        "{:<20} {:>8} {:>9} {:>9} {:>7} {:>13} {:>6} {:>5} {:>5} {:>10}  Critical/high",
        "Run (ID, UTC)",
        "Exposed",
        "Exposure",
        "Protected",
        "Steps",
        "Collected",
        "Open",
        "New",
        "Fixed",
        "Can't tell"
    );
    for p in points {
        let c = &p.findings;
        // The label last, as plain text (the history may come from a shared
        // repository: no control characters reach the terminal).
        let label: String = p
            .label
            .as_deref()
            .map(|l| {
                let l: String = l
                    .chars()
                    .filter(|c| !c.is_control() && !crate::text::is_bidi_control(*c))
                    .collect();
                format!("  {l}")
            })
            .unwrap_or_default();
        let _ = writeln!(
            out,
            // The run's ID (`label`, `history --forget` take it); it is
            // the run's time, UTC.
            "{:<20} {:>8} {:>9} {:>9} {:>7} {:>13} {:>6} {:>5} {:>5} {:>10}  {}/{}{label}",
            p.run_id,
            p.tier_zero_exposed,
            if p.basis() == basis {
                pct(p.tier_zero_exposure_percent)
            } else {
                format!("{}*", pct(p.tier_zero_exposure_percent))
            },
            p.protection_score.map_or("n/a".into(), pct),
            to_zero(p),
            collected(p.completeness.clone()),
            open_findings(p),
            opened(p),
            p.changes.resolved,
            p.changes.held,
            c.critical,
            c.high
        );
    }
    let _ = writeln!(
        out,
        "\nSteps: plan steps of the remediation path. -: not recorded then.\n\
         Protected: % of Tier Zero objects that no open attack path finding leads to.\n\
         Collected: % of computers with sessions / % of member computers with local groups{}.",
        if points.iter().any(|p| p
            .completeness
            .as_ref()
            .is_some_and(|c| c.untargeted().any()))
        {
            "; not targeted (or -): the run didn't ask for them"
        } else {
            ""
        }
    );
    if same > 0 {
        let _ = writeln!(
            out,
            "* Exposure on an older basis (a different denominator): not comparable with the runs after it."
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::FindingCounts;
    use crate::state::ChangeCounts;

    fn point(at: i64, exposure: f64, open: usize, new: usize, resolved: usize) -> HistoryPoint {
        HistoryPoint {
            version: 1,
            run_id: crate::state::run_id(at),
            at,
            collected_at: None,
            tier_zero_exposure_percent: exposure,
            tier_zero_exposed: (exposure * 4.0) as usize,
            tier_zero_population: 0,
            tier_zero_relevant_population: 0,
            exposure_basis: 0,
            tier_zero_objects: 0,
            protection_score: Some(100.0 - exposure / 2.0),
            tier_zero_grade: None,
            plan: None,
            findings: FindingCounts {
                high: open,
                ..FindingCounts::default()
            },
            changes: ChangeCounts {
                new,
                resolved,
                ..ChangeCounts::default()
            },
            zones: Vec::new(),
            completeness: None,
            scopes: Vec::new(),
            trusted_scopes: None,
            recorded_by: None,
            label: None,
            data: None,
            inserted: false,
            exposed_keys: false,
            severity_settings: None,
            rule_severities: Default::default(),
        }
    }

    /// A label another writer pushed (gap 22) reaches the terminal
    /// without its control or bidi characters: no escape sequence, no
    /// right-to-left override, no line of its own.
    #[test]
    fn hostile_labels_are_printed_as_plain_text() {
        let mut p = point(1_791_417_600, 1.0, 0, 0, 0);
        p.label = Some("fixed\u{1b}[2J\u{202e}gpj.exe\r\nPW-001 resolved\u{7}".into());
        let text = render(&[p], None, None, &[]);
        let line = text.lines().find(|l| l.contains("fixed")).unwrap();
        assert!(line.ends_with("fixed[2Jgpj.exePW-001 resolved"), "{line:?}");
        assert!(
            !text.contains(['\u{1b}', '\u{202e}', '\r', '\u{7}']),
            "{text:?}"
        );
    }

    /// A report compares with earlier runs of the same domains only, and
    /// never with itself; points from before domains were recorded count.
    #[test]
    fn earlier_runs_are_of_the_same_environment() {
        let domains = ["CONTOSO.LOCAL".to_string()];
        let mut same = point(10, 1.0, 0, 0, 0).with_domains(&domains);
        same.run_id = "same".into();
        let mut other = point(20, 1.0, 0, 0, 0).with_domains(&["FABRIKAM.LOCAL".to_string()]);
        other.run_id = "other".into();
        let mut old = point(5, 1.0, 0, 0, 0);
        old.run_id = "old".into();
        let mut this = point(30, 1.0, 0, 0, 0).with_domains(&domains);
        this.run_id = "this".into();
        this.data = Some("digest".into());
        let all = [old, same, other, this];
        let ids = |v: Vec<HistoryPoint>| v.into_iter().map(|p| p.run_id).collect::<Vec<_>>();
        assert_eq!(
            ids(earlier(&all, &domains, This::Run("this"))),
            ["old", "same"]
        );
        // A report of the data "this" recorded compares with the run before.
        let data = |digest, collected_at| This::Data {
            digest,
            collected_at,
        };
        assert_eq!(
            ids(earlier(&all, &domains, data("digest", None))),
            ["old", "same"]
        );
        assert_eq!(
            ids(earlier(&all, &domains, data("new data", None))),
            ["old", "same", "this"]
        );
        // Two runs of the same data: the report stands for the latest only.
        let mut twice = all.to_vec();
        twice[1].data = Some("digest".into());
        assert_eq!(
            ids(earlier(&twice, &domains, data("digest", None))),
            ["old", "same"]
        );
        // Points without a digest: the same collection time is the same
        // data; no time says nothing.
        let mut timed = all.to_vec();
        timed[1].collected_at = Some(7);
        // The runs after the one it stands for are left out.
        assert_eq!(ids(earlier(&timed, &domains, data("x", Some(7)))), ["old"]);
        assert_eq!(
            ids(earlier(&all, &domains, data("x", None))),
            ["old", "same", "this"]
        );
        let none = for_report_in(Path::new("no such state"), &domains, This::Run("x"));
        assert!(none.earlier.is_empty() && none.this_run.is_none());
        // The run the report is of comes apart, for what changed in it.
        let h = for_report(&all, &domains, data("digest", None));
        assert_eq!(h.this_run.map(|p| p.run_id).as_deref(), Some("this"));
    }

    /// An empty directory's posture, with a plan.
    fn test_posture() -> crate::posture::Posture {
        let g = crate::AdGraph::new();
        crate::posture::Posture {
            tier_zero: crate::posture::zone_posture(
                &g,
                "Tier Zero",
                &[],
                &[],
                &[],
                &crate::analysis::Relevance::new(&g, 0, 90),
                true,
            ),
            zones: Vec::new(),
            findings: Default::default(),
            completeness: Vec::new(),
            sysvol: Vec::new(),
            adcs: Vec::new(),
            dc_settings: Vec::new(),
            ca_settings: Vec::new(),
            host_agents: Default::default(),
            exposure_basis: crate::analysis::EXPOSURE_BASIS,
            activity_days: 90,
            activity_unknown_domains: Vec::new(),
            plan: Some(crate::posture::PlanSummary {
                steps: 2,
                exposed_after: 0,
            }),
            severities_set: Vec::new(),
            severity_settings: String::new(),
        }
    }

    /// What `pathwarden run` prints after its summary: the run against the
    /// one before it, as `history` compares its latest.
    #[test]
    fn since_a_run_in_a_state_folder() {
        let dir = std::env::temp_dir().join(format!("pw-since-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("history")).unwrap();
        let posture = test_posture();
        for (id, at, exposed) in [("r1", 100, 7), ("r2", 200, 3)] {
            let mut p = HistoryPoint::new(id, at, None, &posture, Default::default());
            p.tier_zero_exposed = exposed;
            std::fs::write(
                dir.join("history").join(format!("{id}.json")),
                serde_json::to_string(&p).unwrap(),
            )
            .unwrap();
        }
        let s = since_run_in(&dir, "r2").unwrap();
        assert_eq!(s.previous_run, "r1");
        assert_eq!(s.tier_zero.map(|d| (d.before, d.after)), Some((7, 3)));
        assert!(since_run_in(&dir, "r1").is_none());
        assert!(since_run_in(&dir, "nope").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A report of an older run's data compares with the run before it, as
    /// `pathwarden history` does, never with a run recorded after it; the
    /// findings state, which the latest run left, names nothing for it.
    #[test]
    fn a_report_of_an_older_run_compares_with_the_run_before() {
        let dir = std::env::temp_dir().join(format!("pw-older-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("history")).unwrap();
        let posture = test_posture();
        for (id, at, exposed) in [("r1", 100, 7), ("r2", 200, 3), ("r3", 300, 50)] {
            let mut p = HistoryPoint::new(id, at, None, &posture, Default::default());
            p.tier_zero_exposed = exposed;
            p.data = Some(format!("data of {id}"));
            std::fs::write(
                dir.join("history").join(format!("{id}.json")),
                serde_json::to_string(&p).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            dir.join("findings.json"),
            serde_json::to_string(&FindingsState::default()).unwrap(),
        )
        .unwrap();
        let this = |digest| This::Data {
            digest,
            collected_at: None,
        };
        let h = for_report_in(&dir, &[], this("data of r2"));
        let ids: Vec<&str> = h.earlier.iter().map(|p| p.run_id.as_str()).collect();
        assert_eq!(ids, ["r1"]);
        assert_eq!(h.this_run.as_ref().map(|p| p.run_id.as_str()), Some("r2"));
        assert!(h.state.is_none(), "the state is r3's");
        let mut posture = posture.clone();
        posture.tier_zero.exposed = 3;
        let s = h.since(&posture, 999, None).unwrap();
        assert_eq!(s.previous_run, "r1");
        assert_eq!(s.tier_zero.map(|d| (d.before, d.after)), Some((7, 3)));
        // The latest run has the state, and the runs before it.
        let h = for_report_in(&dir, &[], this("data of r3"));
        assert_eq!(h.earlier.len(), 2);
        assert!(h.state.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A range counts back from the latest run, not from now.
    #[test]
    fn ranges_count_back_from_the_latest_run() {
        const DAY: i64 = 86_400;
        let at = [0, 50 * DAY, 80 * DAY, 83 * DAY, 90 * DAY];
        assert_eq!(Range::Week.start(&at, |t| *t), 3);
        assert_eq!(Range::Month.start(&at, |t| *t), 2);
        assert_eq!(Range::Quarter.start(&at, |t| *t), 0);
        assert_eq!(Range::All.start(&at, |t| *t), 0);
        assert_eq!(Range::Week.start(&[] as &[i64], |t| *t), 0);
        for r in Range::ALL {
            assert_eq!(Range::parse(r.key()), Some(r));
        }
        assert_eq!(Range::parse("2w"), None);
        assert_eq!(Range::Quarter.span(), "three months");
    }

    #[test]
    fn sparklines_scale_to_the_series() {
        assert_eq!(sparkline(&[0.0, 50.0, 100.0]), "▁▅█");
        assert_eq!(sparkline(&[3.0, 3.0]), "▄▄");
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn renders_table_and_trend() {
        let mut latest = point(1_791_590_400, 12.5, 4, 0, 6);
        latest.plan = Some(crate::posture::PlanSummary {
            steps: 3,
            exposed_after: 0,
        });
        latest.completeness = Some(CompletenessPoint {
            computers: 50,
            sessions_collected: 46,
            sessions_percent: 92.0,
            member_computers: 48,
            local_groups_collected: 42,
            local_groups_percent: Some(87.5),
            low_domains: 0,
            sessions_targeted: true,
            local_groups_targeted: true,
            untargeted_domains: Vec::new(),
        });
        let pts = vec![
            point(1_791_417_600, 75.0, 15, 15, 0),
            point(1_791_504_000, 40.0, 10, 1, 6),
            latest,
        ];
        let text = render(&pts, None, None, &[]);
        // What changed comes first, then the trend.
        assert!(
            text.starts_with(
                "Since the last run (20261009T000000Z):\n  + 110 fewer accounts with an attack path to Tier Zero (160 → 50)\n  + 6 findings fixed\n\n3 runs"
            ),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "3 runs, {} to {}",
                crate::time::format_local(1_791_417_600),
                crate::time::format_local(pts[2].at)
            )),
            "{text}"
        );
        assert!(
            text.contains("Tier Zero exposure  █▄▁  75.00% → 12.50%"),
            "{text}"
        );
        assert!(text.contains("Exposed accounts    █▄▁  300 → 50"), "{text}");
        assert!(text.contains("Open findings       █▅▁  15 → 4"), "{text}");
        assert!(text.contains("Fixed 12, opened 1"), "{text}");
        // A point added after a newer run repeats changes that run
        // counted: not added up again, and never what a run is compared with.
        let mut inserted = point(1_791_460_800, 50.0, 12, 9, 9);
        inserted.inserted = true;
        let mut with = pts.clone();
        with.insert(1, inserted.clone());
        let text = render(&with, None, None, &[]);
        assert!(text.contains("Fixed 12, opened 1"), "{text}");
        assert_eq!(
            crate::since::previous(&with, &with[2]).map(|p| p.run_id.as_str()),
            Some(with[0].run_id.as_str())
        );
        // The latest run is never an inserted one.
        let mut last_inserted = pts.clone();
        inserted.at = 1_791_600_000;
        inserted.run_id = crate::state::run_id(inserted.at);
        last_inserted.push(inserted);
        assert_eq!(
            crate::since::latest_point(&last_inserted).map(|p| p.run_id.as_str()),
            Some(pts[2].run_id.as_str())
        );
        assert!(
            text.contains(
                "20261009T000000Z          160    40.00%    80.00%       -             -     10     1     6          0  0/10"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "20261010T000000Z           50    12.50%    93.75%       3  92.00/87.50%      4     0     6          0  0/4"
            ),
            "{text}"
        );
        // Readable in 120 columns (a label aside).
        assert!(text.lines().all(|l| l.chars().count() <= 120), "{text}");
        // The comparison stays with the latest run whatever is shown.
        let last = render(&pts, Some(1), None, &[]);
        assert!(
            last.starts_with("Since the last run (20261009T000000Z)"),
            "{last}"
        );
        assert!(last.contains("\n1 run,"), "{last}");
        assert!(render(&[], None, None, &[]).contains("No runs recorded yet"));
    }

    /// Across a change of exposure basis the trend starts again: no
    /// first-to-latest move spans two denominators, and the older runs are
    /// marked.
    #[test]
    fn exposure_trend_does_not_cross_a_basis_change() {
        let mut old = point(1_791_417_600, 14.8, 10, 10, 0);
        old.tier_zero_population = 41_714;
        let mut gated = point(1_791_504_000, 26.6, 10, 0, 0);
        gated.tier_zero_relevant_population = 28_000;
        let mut a = point(1_791_590_400, 40.0, 9, 0, 1);
        a.exposure_basis = 2;
        let mut b = point(1_791_676_800, 30.0, 8, 0, 1);
        b.exposure_basis = 2;
        let text = render(&[old, gated, a, b], None, None, &[]);
        assert!(
            text.contains("Tier Zero exposure  █▁  40.00% → 30.00%"),
            "{text}"
        );
        assert!(!text.contains("14.80% →"), "{text}");
        assert!(text.contains(crate::state::BASIS_CHANGED), "{text}");
        assert!(
            text.contains("14.80%*") && text.contains("26.60%*"),
            "{text}"
        );
        assert!(!text.contains("40.00%*"), "{text}");
        // One basis throughout: nothing marked.
        let same = render(
            &[point(1, 5.0, 1, 0, 0), point(2, 6.0, 1, 0, 0)],
            None,
            None,
            &[],
        );
        assert!(!same.contains('*') && !same.contains(crate::state::BASIS_CHANGED));
    }

    #[test]
    fn loads_sorted_and_skips_junk() {
        let dir = std::env::temp_dir().join(format!("pw-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("history")).unwrap();
        for p in [point(200, 1.0, 1, 0, 0), point(100, 2.0, 1, 0, 0)] {
            std::fs::write(
                dir.join("history").join(format!("{}.json", p.run_id)),
                serde_json::to_string(&p).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(dir.join("history").join("junk.json"), "{").unwrap();
        let (pts, skipped) = load(&dir).unwrap();
        assert_eq!(pts.iter().map(|p| p.at).collect::<Vec<_>>(), [100, 200]);
        assert_eq!(skipped.len(), 1);
        assert!(load(&dir.join("none")).unwrap().0.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
