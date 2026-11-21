//! The Runs list as data: every run of the environment, from this
//! computer and from the run history, with the words each row shows. The
//! Runs page renders it ([`row_html`]) and so does `pathwarden runs list`
//! ([`row_json`] and the text words here), so both say the same.
//!
//! A history point with no full run to open is a "numbers only" row. It
//! opens a small run page built from the point ([`point_page`]): when and
//! how it was recorded, its exposure and grade, and its findings from the
//! findings state ([`pathwarden_core::point_findings`]). It never opens
//! Progress in its place. `pathwarden runs show` prints the same.
//!
//! Rows say where they come from ([`Source`]): a full run loaded from the
//! history ([`crate::shared_runs::mirror`]) is a run of its own here, tagged
//! "From the repository".

use std::collections::HashSet;
use std::fmt::Write;

use pathwarden_core::config::Keep;
use pathwarden_core::point_findings::{self, PointChange, PointFindings};
use pathwarden_core::record::by;
use pathwarden_core::state::HistoryPoint;
use serde::Serialize;
use serde_json::{json, Value};

use crate::history_ui::{self, Snapshot, Vs};
use crate::pages::{self, esc, icon, num};
use crate::workspace::{RunSummary, Workspace};

/// Where a row's run comes from, and so what opening it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A run folder on this computer: report, Explore, findings, retest.
    Local,
    /// A history point whose report is the schedule's latest, next to the
    /// history folder (`reports/latest.html`).
    ScheduleReport,
    /// A history point with no full run: its numbers, and the findings the
    /// findings state dates ([`point_page`]).
    NumbersOnly,
    /// A full run loaded from the history ([`RunSummary::shared`]): opens
    /// as a run of this computer's does.
    Shared,
}

impl Source {
    pub fn key(self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::ScheduleReport => "schedule-report",
            Source::NumbersOnly => "numbers-only",
            Source::Shared => "shared",
        }
    }
}

/// A tag after a row's title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Demo,
    /// A run on this computer the history doesn't have.
    LocalOnly,
    Scheduled,
    /// Recorded from the command line or another run, not the schedule.
    Recorded,
    /// No full run: the history's numbers, finding titles and domain names.
    NumbersWithNames,
    /// Loaded from the history's full runs.
    FromRepository,
    /// Its full run was written by a newer Pathwarden.
    Newer,
}

impl Tag {
    pub fn words(self) -> &'static str {
        match self {
            Tag::Demo => "Demo",
            Tag::LocalOnly => "This computer only",
            Tag::Scheduled => "Scheduled",
            Tag::Recorded => "Recorded",
            Tag::NumbersWithNames => "Numbers with names",
            Tag::FromRepository => "From the run history",
            Tag::Newer => "Needs a newer Pathwarden",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Tag::Demo => "tag",
            Tag::LocalOnly | Tag::NumbersWithNames => "tag local",
            Tag::Scheduled | Tag::Recorded => "tag sched",
            Tag::FromRepository => "tag repo",
            Tag::Newer => "tag newer",
        }
    }
}

/// One row of the Runs list.
#[derive(Debug, Clone)]
pub struct RunRow {
    /// What opens it (`/runs/<id>`, `pathwarden runs show <id>`): the run
    /// folder's ID for a run on this computer, else the history's run ID.
    pub id: String,
    /// The history's run ID, when the history has the run.
    pub history_id: Option<String>,
    pub source: Source,
    /// Its numbers; for a history point, as `pathwarden history` prints them.
    pub summary: RunSummary,
    pub tags: Vec<Tag>,
    /// Against the run before it; `None` when it can't be compared.
    pub vs: Option<Vs>,
    /// The history has its collection timings.
    pub timed: bool,
    /// Said after where it came from: why there is no full run, or that it
    /// opens the schedule's report.
    pub note: Option<&'static str>,
    /// A numbers-only row: why it has no full run.
    pub no_full: Option<NoFull>,
}

impl RunRow {
    /// Where the row links to.
    pub fn href(&self) -> String {
        match self.source {
            Source::ScheduleReport => "/history/report".to_string(),
            _ => format!("/runs/{}", self.id),
        }
    }

    /// Where its change in accounts links to: What changed's accounts that
    /// now reach Tier Zero and those that no longer do, when its report
    /// opens to them ([`RunSummary::tier_zero_change`]).
    pub fn which_href(&self) -> Option<String> {
        (matches!(self.source, Source::Local | Source::Shared) && self.summary.tier_zero_change)
            .then(|| {
                format!(
                    "/runs/{}#{}",
                    self.id,
                    pathwarden_core::report::CHANGE_ANCHOR
                )
            })
    }

    /// Where its label form posts.
    fn label_action(&self) -> String {
        match self.source {
            Source::Local | Source::Shared => format!("/runs/{}/label", self.id),
            _ => format!("/history/{}/label", self.id),
        }
    }

    /// "Oct 20, 2026, 2:00 AM · Recorded by the schedule · …": the line under
    /// the title, with times as `when` writes them (HTML or text).
    pub fn sub(&self, when: impl Fn(i64) -> String) -> String {
        let r = &self.summary;
        let mut s = String::new();
        if r.label.is_some() {
            let _ = write!(s, "{} · ", r.environment());
        }
        let _ = write!(
            s,
            "{} · {}",
            when(r.created_at),
            crate::workspace::hide_profile(&r.source)
        );
        if let Some(n) = self.note {
            let _ = write!(s, " · {n}");
        }
        s
    }
}

/// Whether the history kept full runs when point `p` was recorded:
/// `Some(true)` when the history holds its full run, `Some(false)` when it
/// is older than every full run the history holds while it holds fewer
/// than it keeps (none was trimmed, so the history didn't keep them then),
/// `None` when that can't be told. The count kept is this computer's own
/// setting, which only says what the history keeps on a computer that
/// pushes: a reader makes no claim. A point at "Full runs and settings" may
/// lack its full run here for other reasons (trimmed to the latest N, not
/// shared, not loaded yet), so only a point known to come from before is
/// said to.
pub fn kept_full_runs(p: &HistoryPoint, f: &crate::shared_runs::BundleFacts) -> Option<bool> {
    if f.held.contains(&p.run_id) {
        return Some(true);
    }
    match &f.oldest {
        Some(oldest) if f.pushes && p.run_id < *oldest && f.held.len() < f.kept => Some(false),
        _ => None,
    }
}

/// Why a numbers-only row has no full run: what the history keeps now,
/// and whether it kept full runs when the run was recorded
/// ([`kept_full_runs`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoFull {
    /// The history keeps numbers with names.
    NumbersKept,
    /// Recorded before the history kept full runs.
    Before,
    /// Anything else, or not known.
    NotHere,
    /// Its full run is in the history, written by a newer Pathwarden.
    Newer,
}

impl NoFull {
    pub fn of(keep: Keep, kept_then: Option<bool>) -> NoFull {
        match (keep, kept_then) {
            (Keep::Names, _) => NoFull::NumbersKept,
            (Keep::Full, Some(false)) => NoFull::Before,
            (Keep::Full, _) => NoFull::NotHere,
        }
    }

    /// What its row says after where it came from.
    pub fn note(self) -> &'static str {
        match self {
            // The tag says it ([`Tag::NumbersWithNames`]).
            NoFull::NumbersKept => "",
            NoFull::Before => "recorded before reports were kept",
            NoFull::NotHere => "report not on this computer",
            NoFull::Newer => NEWER_NOTE,
        }
    }

    /// The small run page's one line on why there is nothing more to open.
    pub fn line(self) -> &'static str {
        match self {
            NoFull::NumbersKept => "Only its numbers are kept, so there's no report or graph.",
            NoFull::Before => "Recorded before reports were kept, so there's no report or graph.",
            NoFull::NotHere => "Its report and graph aren't on this computer.",
            NoFull::Newer => "Recorded by a newer Pathwarden. Update Pathwarden to open it.",
        }
    }
}

/// The ⓘ beside a numbers-only row's note.
const NO_FULL_TIP: &str =
    "The run history has its numbers, finding titles and domain names, but no report or graph to open.";

const SCHEDULE_REPORT_NOTE: &str = "opens the schedule's report";

/// A point whose full run a newer Pathwarden wrote.
const NEWER_NOTE: &str = "update Pathwarden to open it";

/// The history run IDs `runs` were recorded as.
fn recorded_ids(runs: &[RunSummary]) -> HashSet<&str> {
    runs.iter().filter_map(history_ui::recorded_id).collect()
}

/// Whether the history's run `id` is a row of its own on the Runs list:
/// none of this computer's runs (`recorded`, [`recorded_ids`]) is it.
fn own_row(recorded: &HashSet<&str>, id: &str) -> bool {
    !recorded.contains(id)
}

/// How many runs the Runs list (and `pathwarden runs list`) shows for
/// `runs` and a history whose points are the runs `points`, as
/// [`run_list`] makes its rows: each of `runs`, and each point none of
/// them is. The sidebar's count.
pub fn row_count<'a>(runs: &[RunSummary], points: impl IntoIterator<Item = &'a str>) -> usize {
    let recorded = recorded_ids(runs);
    let mut seen = HashSet::new();
    runs.len()
        + points
            .into_iter()
            .filter(|id| own_row(&recorded, id) && seen.insert(*id))
            .count()
}

/// Every run of the environment, newest first: the UI's runs (`runs`) and
/// every run the history (`snap`) has that none of them is. Each is
/// compared with the run before it ([`history_ui::vs_previous`]).
pub fn run_list(ws: &Workspace, runs: &[RunSummary], snap: &Snapshot) -> Vec<RunRow> {
    let keep = crate::settings::load_ws(ws).config.state.keep();
    run_list_with(ws, runs, snap, keep)
}

/// [`run_list`] for a history that keeps `keep`.
pub fn run_list_with(
    ws: &Workspace,
    runs: &[RunSummary],
    snap: &Snapshot,
    keep: Keep,
) -> Vec<RunRow> {
    let mut rows: Vec<RunRow> = Vec::new();
    let recorded = recorded_ids(runs);
    let facts = snap
        .location
        .as_ref()
        .ok()
        .map(|l| crate::shared_runs::bundle_facts(&l.store, ws, l.records()))
        .unwrap_or_default();
    // A history that holds full runs keeps them, whatever this computer
    // (a reader, say) is set to keep itself.
    let keep = if keeps_full_runs(keep, !facts.held.is_empty()) {
        Keep::Full
    } else {
        keep
    };
    let vs = history_ui::vs_previous(ws, runs, snap);
    // A history that can't be read (encrypted, no passphrase here) may well
    // hold a run, so no run is called local only then.
    let readable = snap.location.is_ok() && snap.history.problem.is_none();
    for r in runs {
        let in_history = snap.has(r);
        let tags = if r.demo {
            vec![Tag::Demo]
        } else if readable && !in_history {
            vec![Tag::LocalOnly]
        } else {
            Vec::new()
        };
        let history_id = history_ui::recorded_id(r)
            .filter(|_| in_history)
            .map(str::to_string);
        let key = history_id.as_deref().unwrap_or(&r.id);
        let mut summary = r.clone();
        let mut tags = tags;
        let (source, note) = match &r.shared {
            // Loaded from the history: who recorded it where, in place of
            // what it was analysed from.
            Some(s) => {
                if s.recorded_from == by::SCHEDULE {
                    tags.push(Tag::Scheduled);
                }
                tags.push(Tag::FromRepository);
                summary.source = crate::shared_runs::capitalized(&s.recorded_words());
                (Source::Shared, None)
            }
            None => {
                let shared = r
                    .history
                    .as_ref()
                    .and_then(|h| h.full_run.as_ref())
                    .is_some_and(|f| f.state == crate::shared_runs::FullRunState::Shared);
                // A shared one waits too when files it left out fit now.
                let waiting = if in_history {
                    crate::shared_runs::waiting(ws, r, &facts, keep == Keep::Full).words()
                } else {
                    None
                };
                let note = match (waiting, shared) {
                    (Some(w), _) => Some(w),
                    (None, true) => Some("shared"),
                    (None, false) => None,
                };
                (Source::Local, note)
            }
        };
        rows.push(RunRow {
            id: r.id.clone(),
            vs: vs.get(key).copied(),
            history_id,
            source,
            summary,
            tags,
            timed: false,
            note,
            no_full: None,
        });
    }
    let report = snap
        .location
        .as_ref()
        .ok()
        .and_then(|l| history_ui::scheduled_report(l, &snap.history))
        .map(|(_, id)| id);
    for p in &snap.history.points {
        if !own_row(&recorded, &p.run_id) {
            continue;
        }
        let mut tags = vec![match p.recorded_by.as_deref() {
            Some(by::SCHEDULE) => Tag::Scheduled,
            _ => Tag::Recorded,
        }];
        let (source, note, no_full) = if report.as_deref() == Some(p.run_id.as_str()) {
            (Source::ScheduleReport, SCHEDULE_REPORT_NOTE, None)
        } else if facts.newer.contains(&p.run_id) {
            tags.push(Tag::Newer);
            (Source::NumbersOnly, NEWER_NOTE, Some(NoFull::Newer))
        } else {
            tags.push(Tag::NumbersWithNames);
            let why = NoFull::of(keep, kept_full_runs(p, &facts));
            (Source::NumbersOnly, why.note(), Some(why))
        };
        rows.push(RunRow {
            id: p.run_id.clone(),
            history_id: Some(p.run_id.clone()),
            source,
            summary: point_summary(p, runs, snap),
            tags,
            vs: vs.get(&p.run_id).copied(),
            timed: snap
                .location
                .as_ref()
                .is_ok_and(|l| pathwarden_core::store::has_run_timings(&l.dir, &p.run_id)),
            // "Numbers only" is the tag: no note repeats it.
            note: (!note.is_empty()).then_some(note),
            no_full,
        });
    }
    rows.sort_by(|a, b| b.summary.order_key().cmp(&a.summary.order_key()));
    rows
}

/// A history point as a run summary, with the environment's domain names
/// when this computer knows them.
fn point_summary(p: &HistoryPoint, runs: &[RunSummary], snap: &Snapshot) -> RunSummary {
    let key = history_ui::point_scopes_key(p);
    let domains = history_ui::domains_for(&key, runs, snap.history.last.as_ref());
    history_ui::point_summary(p, &domains)
}

/// The row in the Runs page's list.
pub fn row_html(r: &RunRow) -> String {
    let mut tags = String::new();
    for t in &r.tags {
        let _ = write!(tags, r#" <span class="{}">{}</span>"#, t.class(), t.words());
    }
    if r.timed {
        tags.push_str(&history_ui::perf_link(&r.id));
    }
    let extra = match (r.source, r.note) {
        (Source::NumbersOnly, n) => {
            let tip = pages::tip(
                &format!(
                    "tip-nf-{}",
                    r.id.replace(|c: char| !c.is_ascii_alphanumeric(), "")
                ),
                "Numbers with names",
                NO_FULL_TIP,
            );
            match n {
                Some(n) => format!(" · {} {tip}", esc(n)),
                None => format!(" {tip}"),
            }
        }
        (_, Some(n)) => format!(" · {}", esc(n)),
        (_, None) => String::new(),
    };
    let mut b = String::new();
    pages::run_row_with(
        &mut b,
        &r.summary,
        &esc(&r.href()),
        &tags,
        &r.vs
            .map(|v| v.html_to(r.which_href().as_deref()))
            .unwrap_or_default(),
        Some(&r.label_action()),
        &extra,
        if r.source == Source::NumbersOnly {
            " numbers-only"
        } else {
            ""
        },
    );
    b
}

/// "16 accounts · 94.12% of 17 active accounts": a run's exposure, as the
/// list's column says it.
pub fn exposure_words(r: &RunSummary) -> String {
    format!(
        "{} {} · {}",
        num(r.exposed),
        if r.exposed == 1 {
            "account"
        } else {
            "accounts"
        },
        r.headline().share
    )
}

/// "8 critical, 11 high", or "None".
pub fn urgent_words(r: &RunSummary) -> String {
    let mut parts = Vec::new();
    if r.critical > 0 {
        parts.push(format!("{} critical", num(r.critical)));
    }
    if r.high > 0 {
        parts.push(format!("{} high", num(r.high)));
    }
    if parts.is_empty() {
        "None".to_string()
    } else {
        parts.join(", ")
    }
}

fn when_utc(t: i64) -> String {
    format!("{} UTC", pathwarden_core::time::format_unix(t))
}

/// A row as `pathwarden runs list --json` prints it.
pub fn row_json(r: &RunRow) -> Value {
    let s = &r.summary;
    json!({
        "id": r.id,
        "run_id": r.history_id,
        "source": r.source.key(),
        "title": s.title(),
        "environment": s.environment(),
        "label": s.label,
        "created_at": s.created_at,
        "collected_at": s.collected_at,
        "recorded_by_words": s.source,
        "tags": r.tags.iter().map(|t| t.words()).collect::<Vec<_>>(),
        "note": r.note,
        "sub": r.sub(when_utc),
        "exposed": s.exposed,
        "exposure_percent": s.exposure_percent,
        "exposure": exposure_words(s),
        "grade": s.grade().as_str(),
        "findings": {
            "critical": s.critical,
            "high": s.high,
            "medium": s.medium,
            "low": s.low,
            "info": s.info,
            "suppressed": s.suppressed,
        },
        "vs_previous": r.vs.map(|v| json!({
            "exposed": v.exposed,
            "new": v.opened_fixed.map(|x| x.0),
            "fixed": v.opened_fixed.map(|x| x.1),
            "words": v.text(),
        })),
        "timings": r.timed,
        // `runs show` lists the accounts that now reach Tier Zero or no
        // longer do, and those each step cuts off.
        "tier_zero_lists": s.tier_zero_lists,
        // Not `tier_zero_change`: `runs show --json` has that, the accounts.
        "tier_zero_change_opens": s.tier_zero_change,
    })
}

// ------------------------------------------- History storage's fact

/// How many of the history's runs open in full here: the "Full runs" fact
/// of History storage and `pathwarden history storage show`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FullRuns {
    /// Runs in the history with their full run on this computer.
    pub on_this_computer: usize,
    /// The run the schedule's report next to the history belongs to.
    pub schedule_report: usize,
    /// Runs with their numbers only.
    pub numbers_only: usize,
}

impl FullRuns {
    pub fn total(&self) -> usize {
        self.on_this_computer + self.schedule_report + self.numbers_only
    }
}

/// [`FullRuns`] of history `h` (at `loc`), as [`run_list`] sorts its
/// rows into sources (without comparing them, so without reading the runs).
pub fn full_runs(
    runs: &[RunSummary],
    h: &history_ui::History,
    loc: Option<&history_ui::Location>,
) -> FullRuns {
    let recorded = recorded_ids(runs);
    let report = loc
        .and_then(|l| history_ui::scheduled_report(l, h))
        .map(|(_, id)| id);
    let mut f = FullRuns::default();
    for p in &h.points {
        if !own_row(&recorded, &p.run_id) {
            f.on_this_computer += 1;
        } else if report.as_deref() == Some(p.run_id.as_str()) {
            f.schedule_report += 1;
        } else {
            f.numbers_only += 1;
        }
    }
    f
}

/// Whether History storage and `history storage show` state the Full runs
/// fact: only when the history keeps full runs (user decision):
/// this computer keeps "Full runs and settings", or the history in `store`
/// holds full runs (a reader loads them whatever it keeps itself). The
/// Runs list goes by the same rule ([`keeps_full_runs`]).
pub fn shows_full_runs(keep: Keep, store: &pathwarden_core::store::Store) -> bool {
    keeps_full_runs(keep, !store.bundles().is_empty())
}

/// [`shows_full_runs`] for a history that `holds` full runs or not.
pub fn keeps_full_runs(keep: Keep, holds: bool) -> bool {
    keep == Keep::Full || holds
}

/// What the Full runs fact says of an encrypted history this computer
/// can't open.
pub const FULL_RUNS_LOCKED: &str = "Can't be read without the passphrase.";

/// "2 of 5 runs open in full on this computer · 3 numbers only";
/// [`FULL_RUNS_LOCKED`] when the history is `locked`
/// ([`crate::encryption_ui::locked`]).
pub fn full_runs_words(f: &FullRuns, locked: bool) -> String {
    if locked {
        return FULL_RUNS_LOCKED.to_string();
    }
    let total = f.total();
    if total == 0 {
        return "None yet".to_string();
    }
    let mut s = format!(
        "{} of {} open in full on this computer",
        num(f.on_this_computer),
        pathwarden_core::text::count(total, "run", "runs")
    );
    if f.schedule_report > 0 {
        s.push_str(" · 1 opens the schedule's report");
    }
    if f.numbers_only > 0 {
        let _ = write!(s, " · {} numbers with names", num(f.numbers_only));
    }
    s
}

// ------------------------------------------------------------ the report

/// A run's stored report as the app serves and downloads it, and as
/// `pathwarden runs report` writes it: today's stylesheet and logo (a
/// report saved before a layout fix or the Crown W shows them), and the
/// run's label as it is now (reports are stored without one). The stored
/// file is not changed.
pub fn report_as_now(html: String, summary: Option<&RunSummary>) -> String {
    let mut html = pathwarden_core::report::with_current_style(&html);
    if let Some(label) = summary.and_then(|s| s.label.as_deref()) {
        html = pathwarden_core::report::with_label(&html, label);
    }
    if let Some(rebranded) = crate::brand::rebrand_old_report(&html) {
        html = rebranded;
    }
    html
}

/// The report of row `r` as "Download report" gives it (a run on this
/// computer), or the schedule's report it opens; else why there is none.
pub fn report_for(ws: &Workspace, snap: &Snapshot, r: &RunRow) -> Result<String, String> {
    match r.source {
        Source::Local | Source::Shared => {
            let dir = ws
                .run_dir(&r.id)
                .ok_or_else(|| format!("Run {} isn't on this computer. Reload the page.", r.id))?;
            let html = std::fs::read_to_string(dir.join(crate::workspace::REPORT_FILE))
                .map_err(|_| "This run has no saved report.".to_string())?;
            Ok(report_as_now(html, Some(&r.summary)))
        }
        Source::ScheduleReport => {
            let (path, _) = snap
                .location
                .as_ref()
                .ok()
                .and_then(|l| history_ui::scheduled_report(l, &snap.history))
                .ok_or_else(|| {
                    "The schedule's report isn't there any more. Wait for the next scheduled run."
                        .to_string()
                })?;
            std::fs::read_to_string(&path)
                .map_err(|_| "The schedule's report couldn't be read. Try again.".to_string())
        }
        Source::NumbersOnly => Err(r.no_full.unwrap_or(NoFull::NotHere).line().to_string()),
    }
}

// ------------------------------------------------- the small run page

/// A history point with no full run, as its small run page shows it.
pub struct PointPage {
    pub row: RunRow,
    /// Its findings by the findings state; why they can't be listed
    /// otherwise.
    pub findings: Result<PointFindings, String>,
    /// [`NoFull::line`].
    pub line: &'static str,
}

/// The small run page of history run `id`: `None` when the history hasn't
/// it as a numbers-only row (a run on this computer opens its own page).
pub fn point_page(
    ws: &Workspace,
    runs: &[RunSummary],
    snap: &Snapshot,
    id: &str,
) -> Option<PointPage> {
    let keep = crate::settings::load_ws(ws).config.state.keep();
    let p = snap.history.points.iter().find(|p| p.run_id == id)?;
    if runs
        .iter()
        .any(|r| history_ui::recorded_id(r) == Some(p.run_id.as_str()))
    {
        return None;
    }
    let row = run_list_with(ws, runs, snap, keep)
        .into_iter()
        .find(|r| r.id == id)?;
    let findings = match snap.location.as_ref() {
        Ok(loc) => match pathwarden_core::history::findings_state_in(&loc.dir) {
            Ok(Some(state)) => Ok(point_findings::point_findings(
                &snap.history.points,
                p,
                &state,
            )),
            Ok(None) => Ok(PointFindings::default()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e.clone()),
    };
    let line = row.no_full.unwrap_or(NoFull::NotHere).line();
    Some(PointPage {
        row,
        findings,
        line,
    })
}

/// Most findings of each part a page or `runs show` lists by name.
pub const MAX_LISTED: usize = 200;

/// What a list without the run's open findings says
/// ([`PointFindings::complete`] false).
pub const PARTIAL_WORDS: &str = "Open findings aren't listed for this run.";

/// The ⓘ of [`PARTIAL_WORDS`].
pub const PARTIAL_TIP: &str =
    "The run history keeps only each finding's latest dates, not every run in between.";

/// The ⓘ beside "Findings": where titles and severities come from.
pub const FINDINGS_TIP: &str =
    "Titles and severities are as the last run that saw each finding had them.";

/// What an empty list says: only when the run had no findings at all.
pub fn empty_words(f: &PointFindings) -> Option<&'static str> {
    (f.items.is_empty() && f.complete && f.new.count + f.back.count + f.fixed.count == 0)
        .then_some("No findings.")
}

/// A finding's title, else its rule's.
pub fn finding_title(f: &point_findings::PointFinding) -> String {
    f.title.clone().unwrap_or_else(|| {
        pathwarden_core::findings::rules()
            .iter()
            .find(|r| r.id == f.rule)
            .map_or_else(|| f.rule.clone(), |r| r.title.to_string())
    })
}

/// "Critical", "High", …
pub fn severity_words(s: pathwarden_core::findings::Severity) -> &'static str {
    use pathwarden_core::findings::Severity;
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// "3 new, 2 fixed (not listed)": the run's own counts, and which of them
/// the list names.
pub fn findings_counts_words(f: &PointFindings) -> String {
    let mut parts = Vec::new();
    for (k, w) in [(f.new, "new"), (f.back, "back"), (f.fixed, "fixed")] {
        if k.count > 0 {
            parts.push(format!(
                "{} {w}{}",
                num(k.count),
                if k.named { "" } else { " (not listed)" }
            ));
        }
    }
    parts.join(", ")
}

/// The small run page's body.
pub fn point_page_html(pg: &PointPage, env: (&str, &str)) -> String {
    let r = &pg.row.summary;
    let mut tags = String::new();
    for t in &pg.row.tags {
        let _ = write!(tags, r#" <span class="{}">{}</span>"#, t.class(), t.words());
    }
    let collected = r
        .collected_at
        .map(|t| format!(" · Collected {}", pages::collected_time(t)))
        .unwrap_or_default();
    let dom = if r.label.is_some() {
        format!(
            r#"<span class="rh-dom">{}</span> · "#,
            esc(&r.environment())
        )
    } else {
        String::new()
    };
    let vs = pg
        .row
        .vs
        .map(|v| format!(r#"<span class="nf-vs">{}</span>"#, esc(&v.text())))
        .unwrap_or_default();
    let mut b = format!(
        r#"<div class="page-head run-head nf-head">
  <div class="rh-text">
    <div class="eyebrow"><a class="rh-env" href="/environments#env-{env_id}" title="Open this environment">{i_layers}{env_name}</a></div>
    <div class="rh-title"><h1 class="panel-title">{title}</h1>{tags}</div>
    <p class="muted small">{dom}{when} · {source}{collected} · <span class="run-id" title="The run history's ID for this run.">Run <code>{run_id}</code></span></p>
    <p class="nf-line">{i_info}<span>{line}</span></p>
  </div>
</div>
<section class="card nf-numbers" aria-label="Exposure and findings">
  <div class="rr-expo {band}" title="{reason}"><span class="rr-pct">{exposed}</span><span class="rr-grade">{grade}</span><span class="rr-of">{expo_words}{mark}</span></div>
  {vs}<div class="rr-sev">{sev}</div>
</section>
"#,
        env_id = esc(env.0),
        env_name = esc(env.1),
        i_layers = icon("i-layers"),
        title = esc(&r.title()),
        when = pages::time(r.created_at),
        source = esc(&crate::workspace::hide_profile(&r.source)),
        run_id = esc(&pg.row.id),
        i_info = icon("i-info"),
        line = esc(pg.line),
        band = pages::grade_class(r),
        reason = esc(&r.status_reason()),
        exposed = num(r.exposed),
        grade = r.grade().as_str(),
        expo_words = esc(&format!(
            "{} · {}",
            if r.exposed == 1 {
                "account"
            } else {
                "accounts"
            },
            r.headline().share
        )),
        mark = pages::older_basis_mark(r.basis()),
        sev = pages::severity_pills(r),
    );
    let _ = write!(
        b,
        r#"<section class="card nf-findings"><header><h2 class="sub">Findings {}</h2>"#,
        pages::tip("tip-findings", "Titles and severities", FINDINGS_TIP)
    );
    match &pg.findings {
        Err(e) => {
            let _ = write!(
                b,
                r#"</header><p class="field-error" role="alert">The findings for this run couldn't be read: {}</p>"#,
                esc(e)
            );
        }
        Ok(f) => {
            let counts = findings_counts_words(f);
            if !counts.is_empty() {
                let _ = write!(b, r#"<p class="muted small">{}</p>"#, esc(&counts));
            }
            if !f.complete {
                let _ = write!(
                    b,
                    r#"<p class="muted small">{} {}</p>"#,
                    esc(PARTIAL_WORDS),
                    pages::tip("tip-partial", "Findings listed", PARTIAL_TIP)
                );
            }
            b.push_str("</header>");
            if f.items.is_empty() {
                if let Some(w) = empty_words(f) {
                    let _ = write!(b, r#"<p class="muted">{w}</p>"#);
                }
            } else {
                b.push_str(r#"<ul class="nf-list">"#);
                for x in f.items.iter().take(MAX_LISTED) {
                    let change = match x.change {
                        PointChange::Open => String::new(),
                        c => format!(
                            r#"<span class="tag nf-{}">{}</span>"#,
                            match c {
                                PointChange::New => "new",
                                PointChange::Back => "back",
                                _ => "fixed",
                            },
                            c.words()
                        ),
                    };
                    let _ = write!(
                        b,
                        r#"<li class="{fixed}"><span class="pill {sev}"><span class="dot" aria-hidden="true"></span>{sev_words}</span><span class="nf-title">{title}</span><span class="nf-meta">{change}<code title="Rule">{rule}</code></span></li>"#,
                        fixed = if x.change == PointChange::Fixed {
                            "nf-gone"
                        } else {
                            ""
                        },
                        sev = x.severity.as_str(),
                        sev_words = severity_words(x.severity),
                        title = esc(&finding_title(x)),
                        rule = esc(&x.rule),
                    );
                }
                b.push_str("</ul>");
                if f.items.len() > MAX_LISTED {
                    let _ = write!(
                        b,
                        r#"<p class="muted small">and {} more</p>"#,
                        num(f.items.len() - MAX_LISTED)
                    );
                }
            }
        }
    }
    b.push_str("</section>");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_follow_what_the_history_keeps() {
        // At "Full runs and settings" only a run known to come from before
        // full runs were kept says so.
        assert_eq!(
            NoFull::of(Keep::Full, Some(false)).line(),
            "Recorded before reports were kept, so there's no report or graph."
        );
        assert_eq!(
            NoFull::of(Keep::Full, None).line(),
            "Its report and graph aren't on this computer."
        );
        assert_eq!(
            NoFull::of(Keep::Full, Some(true)),
            NoFull::NotHere,
            "kept then, missing here: trimmed, not shared or not loaded"
        );
        assert_eq!(
            NoFull::of(Keep::Names, None).line(),
            "Only its numbers are kept, so there's no report or graph."
        );
        assert_eq!(Tag::NumbersWithNames.words(), "Numbers with names");
        assert_eq!(Source::NumbersOnly.key(), "numbers-only");
    }

    /// The change in accounts links to which accounts only when the
    /// run's report opens to them: not for a run whose accounts weren't
    /// compared, nor for one with its numbers only.
    #[test]
    fn the_change_links_only_when_the_report_opens_it() {
        let summary: RunSummary = serde_json::from_value(json!({
            "id": "20261028-020000-abcdef", "created_at": 0, "source": "x",
            "demo": false, "domains": [], "objects": 0, "files": 0,
            "exposure_percent": 0.0, "exposed": 3, "population": 0, "critical": 0,
            "high": 0, "medium": 0, "low": 0, "info": 0, "suppressed": 0,
            "plan_steps": 0, "pathwarden": "0", "tier_zero_lists": true,
        }))
        .unwrap();
        let row = |source: Source, change: bool| {
            let mut summary = summary.clone();
            summary.tier_zero_change = change;
            RunRow {
                id: "20261028-020000-abcdef".into(),
                history_id: None,
                source,
                summary,
                tags: Vec::new(),
                vs: Some(history_ui::Vs {
                    exposed: Some(2),
                    opened_fixed: None,
                    earlier: true,
                }),
                timed: false,
                note: None,
                no_full: None,
            }
        };
        let linked = row(Source::Local, true);
        assert_eq!(
            linked.which_href().as_deref(),
            Some("/runs/20261028-020000-abcdef#since-tier-zero")
        );
        assert!(row_html(&linked).contains(
            r#"<a class="vs-expo bad" href="/runs/20261028-020000-abcdef#since-tier-zero""#
        ));
        // Lists kept, but the accounts weren't compared: no link.
        let uncompared = row(Source::Local, false);
        assert_eq!(uncompared.which_href(), None);
        assert!(!row_html(&uncompared).contains("since-tier-zero"));
        assert_eq!(row(Source::NumbersOnly, true).which_href(), None);
        assert_eq!(row_json(&uncompared)["tier_zero_change_opens"], false);
    }

    /// The sidebar counts each run here and each history run none of
    /// them is, as the list makes its rows.
    #[test]
    fn the_count_is_the_list_s() {
        let run = |history: Option<&str>| -> RunSummary {
            let mut r: RunSummary = serde_json::from_value(json!({
                "id": "f", "created_at": 0, "source": "x", "demo": false,
                "domains": [], "objects": 0, "files": 0, "exposure_percent": 0.0,
                "exposed": 0, "population": 0, "critical": 0, "high": 0,
                "medium": 0, "low": 0, "info": 0, "suppressed": 0,
                "plan_steps": 0, "pathwarden": "0",
            }))
            .unwrap();
            r.history = history.map(|id| crate::workspace::HistoryLink {
                run_id: Some(id.to_string()),
                ..Default::default()
            });
            r
        };
        // Five here (four in the history, one not), and the history's
        // fifth run with its numbers only: six.
        let runs = vec![
            run(Some("a")),
            run(Some("b")),
            run(Some("c")),
            run(Some("d")),
            run(None),
        ];
        assert_eq!(row_count(&runs, ["a", "b", "c", "d", "e"]), 6);
        assert_eq!(row_count(&runs, []), 5);
        assert_eq!(row_count(&[], ["e", "e"]), 1);
    }
}
