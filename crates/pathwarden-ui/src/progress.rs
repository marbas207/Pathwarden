//! The Progress page: how an environment changed from run to run, read from
//! the run history (the state `pathwarden run` and the UI both record into,
//! [`crate::history_ui`]), so scheduled runs and analyses started here are
//! one series. Runs that are only in the workspace (the demo, analyses from
//! before the history was recorded) are charted on their own, marked local
//! only, from their saved events ([`pathwarden_core::record::import::point`]).
//!
//! Over a time range ([`Range`], as `pathwarden history --range`): four
//! cards (accounts with an attack path to Tier Zero with its status, changes to
//! zero, open findings, Tier Zero protected), each with its change since the
//! last run; what changed since the last run ([`pathwarden_core::since`],
//! the lines `pathwarden history` prints), or over a longer period
//! everything net new in it ([`pathwarden_core::introduced`], the lines
//! `pathwarden changes --since` prints); and five charts, drawn on the
//! server as inline SVG (no chart library):
//!
//! - the accounts with an attack path to each tier (Tier Zero and the first
//!   [`ZONE_TRENDS`] zones), linear or log;
//! - choke points (the length of the remediation plan);
//! - open findings by severity, stacked, with the attack path findings
//!   among them as a dashed line;
//! - objects per tier, one row per tier on its own scale;
//! - collection completeness (sessions, local groups), with dips below
//!   [`LOW_PERCENT`] marked.
//!
//! Runs are grouped by environment (their set of domains) and never mixed.
//! The numbers for history runs are the history point's, exactly as
//! `pathwarden history` prints them; figures older points lack are not
//! drawn as zero: their lines start at the first run that has them.
//! Every value is labeled or in the table under each chart; the hover layer
//! (`assets/progress.js`) only repeats them.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use pathwarden_core::history::{Range, ZONE_TRENDS};
use pathwarden_core::introduced::{self, Period};
use pathwarden_core::posture::LOW_PERCENT;
use pathwarden_core::record::import;
use pathwarden_core::since::{self, Tone};
use pathwarden_core::state::{ChangeCounts, FindingsState, HistoryPoint};
use serde::Deserialize;

use crate::history_ui::{self, Snapshot};
use crate::pages::{self, esc, icon, num, Ctx};
use crate::retest_ui::{env_key, open_fingerprints};
use crate::run_data;
use crate::server::Shared;
use crate::workspace::{RunSummary, Workspace};

const PROGRESS_CSS: &str = include_str!("assets/progress.css");
const PROGRESS_JS: &str = include_str!("assets/progress.js");

/// Most runs charted per environment (the latest ones in the range), as
/// `pathwarden history` says when it prints more.
const MAX_RUNS: usize = pathwarden_core::history::MAX_CHARTED;

/// The range shown when the page is opened without one.
pub const DEFAULT_RANGE: Range = Range::Quarter;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/progress", get(page))
        .route(
            "/static/progress.css",
            get(|| async { asset("text/css", PROGRESS_CSS) }),
        )
        .route(
            "/static/progress.js",
            get(|| async { asset("text/javascript", PROGRESS_JS) }),
        )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[derive(Deserialize)]
struct PageQuery {
    env: Option<String>,
    /// `1w`, `1m`, `3m` or `all` ([`Range::parse`]).
    range: Option<String>,
    /// What changed over: `last` (the default), `range` (the page's time
    /// range) or another period ([`Period::parse`]); or the days `from`
    /// and `to` (either alone: from or up to that day).
    changes: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

async fn page(State(st): State<Shared>, Query(q): Query<PageQuery>) -> Response {
    let ws = st.ws();
    let runs = ws.runs();
    let ctx_runs = runs.clone();
    let flag = st.state_dir();
    let range = q
        .range
        .as_deref()
        .and_then(Range::parse)
        .unwrap_or(DEFAULT_RANGE);
    let changes = changes_period(&q);
    let body = tokio::task::spawn_blocking(move || {
        let snap = history_ui::snapshot(&ws, flag.as_deref());
        body(&ws, &runs, &snap, q.env.as_deref(), range, changes)
    })
    .await
    .unwrap_or_default();
    Html(pages::shell(
        &Ctx::new(&st, &ctx_runs),
        Some(pages::Nav::Progress),
        "Progress",
        "",
        &body,
    ))
    .into_response()
}

/// One charted run.
pub struct Point {
    /// The run as the run list shows it: its status, reason and label.
    pub run: RunSummary,
    /// Its figures, as the history records them.
    pub hp: HistoryPoint,
    /// Whether the open attack path findings are known: not for a local
    /// run saved before the app kept its findings.
    pub attack_known: bool,
}

/// Open fingerprints per run, cached: runs never change once saved.
pub(crate) fn fingerprints(ws: &Workspace, id: &str) -> Option<Arc<HashSet<String>>> {
    static CACHE: Mutex<Option<HashMap<String, Arc<HashSet<String>>>>> = Mutex::new(None);
    if let Some(s) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .get(id)
    {
        return Some(s.clone());
    }
    let set = Arc::new(open_fingerprints(&ws.run_dir(id)?)?);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = c.get_or_insert_with(HashMap::new);
    if map.len() > 400 {
        map.clear();
    }
    map.insert(id.to_string(), set.clone());
    Some(set)
}

/// A local run as a history point, and whether its saved event had the
/// figures of its posture.
type Local = Arc<(HistoryPoint, bool)>;

/// What a run targeted, domain by domain ([`since::targeting`]).
type Targeting = (pathwarden_core::posture::Untargeted, Vec<String>);

/// A local run as a history point, from its saved event when it has one
/// (and whether it had), cached: runs never change once saved. Its
/// changes are left at zero; [`points`] fills them in.
fn local_point(ws: &Workspace, r: &RunSummary) -> Local {
    static CACHE: Mutex<Option<HashMap<String, Local>>> = Mutex::new(None);
    if let Some(p) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .get(&r.id)
    {
        return p.clone();
    }
    let event = ws
        .run_dir(&r.id)
        .and_then(|d| run_data::read_event(&d).ok())
        .and_then(|b| import::SavedEvent::parse(&b));
    let mut hp = import::point(
        &history_ui::analyzed(r),
        event.as_ref(),
        &r.domains,
        &r.id,
        ChangeCounts::default(),
    );
    hp.label = r.label.clone();
    let p = Arc::new((hp, event.is_some()));
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = c.get_or_insert_with(HashMap::new);
    if map.len() > 400 {
        map.clear();
    }
    map.insert(r.id.clone(), p.clone());
    p
}

/// An environment on the page: its runs in the history, or its UI runs
/// that are only in the workspace.
struct Env {
    /// The `env` parameter.
    key: String,
    /// Local-only environments: their runs' [`env_key`].
    runs_key: String,
    label: String,
    /// History environment: its scope key (else a local-only environment).
    scopes: Option<String>,
    /// Runs charted from the history, or local-only runs.
    count: usize,
    /// Local-only UI runs of a history environment (not charted).
    local_only: usize,
    /// Newest activity, to order the tabs.
    latest: i64,
    demo: bool,
}

/// The environments, newest activity first: every history environment, and
/// every environment of local-only UI runs that the history doesn't have.
/// Each is named after the workspace's environment (`env_name`), as
/// Environments shows it; when its runs collected more than one set of
/// domains, each set's default name follows ("Lab: SCALE.LOCAL +1").
fn environments(runs: &[RunSummary], snap: &Snapshot, env_name: &str) -> Vec<Env> {
    let mut out: Vec<Env> = Vec::new();
    for p in &snap.history.points {
        let scopes = history_ui::point_scopes_key(p);
        match out
            .iter_mut()
            .find(|e| e.scopes.as_deref() == Some(scopes.as_str()))
        {
            Some(e) => {
                e.count += 1;
                e.latest = e.latest.max(p.at);
            }
            None => {
                let domains = history_ui::domains_for(&scopes, runs, snap.history.last.as_ref());
                let label = if domains.is_empty() {
                    "Recorded environment".to_string()
                } else {
                    point_env(&domains)
                };
                out.push(Env {
                    runs_key: String::new(),
                    key: history_ui::env_param(&scopes, &domains),
                    label,
                    scopes: Some(scopes),
                    count: 1,
                    local_only: 0,
                    latest: p.at,
                    demo: false,
                });
            }
        }
    }
    for r in runs.iter().filter(|r| !snap.has(r)) {
        let scopes = history_ui::scopes_key(&r.domains);
        if !r.demo {
            if let Some(e) = out
                .iter_mut()
                .find(|e| e.scopes.as_deref() == Some(scopes.as_str()))
            {
                e.local_only += 1;
                continue;
            }
        }
        let runs_key = env_key(r);
        match out
            .iter_mut()
            .find(|e| e.scopes.is_none() && e.runs_key == runs_key)
        {
            Some(e) => {
                e.count += 1;
                e.latest = e.latest.max(r.created_at);
            }
            None => out.push(Env {
                // Distinct from a history environment of the same domains.
                key: if out.iter().any(|e| e.key == runs_key) {
                    format!("local-{runs_key}")
                } else {
                    runs_key.clone()
                },
                runs_key,
                label: if r.demo {
                    r.environment()
                } else {
                    point_env(&r.domains)
                },
                scopes: None,
                count: 1,
                local_only: 0,
                latest: r.created_at,
                demo: r.demo,
            }),
        }
    }
    let sets = out.iter().filter(|e| !e.demo).count();
    for e in out.iter_mut().filter(|e| !e.demo) {
        e.label = if sets == 1 {
            env_name.to_string()
        } else {
            format!("{env_name}: {}", e.label)
        };
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.latest));
    out
}

/// An environment's name from its domains, as [`RunSummary::environment`].
fn point_env(domains: &[String]) -> String {
    crate::workspace::environment_of(domains)
}

/// Every point of a history environment, oldest first, exactly as
/// `pathwarden history` reads them.
fn history_points(snap: &Snapshot, scopes: &str, domains: &[String]) -> Vec<Point> {
    snap.history
        .points
        .iter()
        .filter(|p| history_ui::point_scopes_key(p) == scopes)
        .map(|p| Point {
            run: history_ui::point_summary(p, domains),
            hp: p.clone(),
            attack_known: true,
        })
        .collect()
}

/// One environment of local runs on a range: the points charted (the
/// latest [`MAX_RUNS`] in the range) and the run before them, oldest
/// first, with how many runs there are in all and in the range. Opened
/// and fixed are against the environment's run before, by fingerprint.
/// Only those runs' events and fingerprints are read, so a workspace of
/// many local analyses pays for what the page shows.
pub fn points(
    ws: &Workspace,
    runs: &[RunSummary],
    key: &str,
    range: Range,
) -> (Vec<Point>, usize, usize) {
    let mut mine: Vec<&RunSummary> = runs.iter().filter(|r| env_key(r) == key).collect();
    mine.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    let total = mine.len();
    let in_range = total - range.start(&mine, |r| r.created_at);
    // The run before the charted ones, for the cards' change since the
    // last run, and the one before that for its own opened and fixed.
    let from = total - in_range.min(MAX_RUNS);
    let keep = from.saturating_sub(1);
    // Like with like: opened and fixed against the run before that
    // targeted the same (a Quick run against the last Quick run).
    let mut prev: HashMap<Targeting, Arc<HashSet<String>>> = HashMap::new();
    if let Some(i) = keep.checked_sub(1) {
        let before = local_point(ws, mine[i]);
        if let Some(f) = fingerprints(ws, &mine[i].id) {
            prev.insert(since::targeting(before.0.completeness.as_ref()), f);
        }
    }
    let mut out = Vec::new();
    for r in &mine[keep..] {
        let cur = fingerprints(ws, &r.id);
        let cached = local_point(ws, r);
        let mut hp = cached.0.clone();
        let key = since::targeting(hp.completeness.as_ref());
        if let (Some(p), Some(c)) = (prev.get(&key), &cur) {
            hp.changes = ChangeCounts {
                new: c.difference(p).count(),
                resolved: p.difference(c).count(),
                open: c.len(),
                ..ChangeCounts::default()
            };
        }
        if let Some(c) = cur {
            prev.insert(key, c);
        }
        out.push(Point {
            run: (*r).clone(),
            hp,
            attack_known: cached.1,
        });
    }
    (out, total, in_range)
}

/// `/progress` with an environment and a range.
fn href(env: &str, range: Range) -> String {
    format!("/progress?env={}&range={}", urlencode(env), range.key())
}

/// What What changed is over: since the last run, the page's time range,
/// or days picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Changes {
    LastRun,
    /// Everything net new over the page's range ([`Period::of_range`]).
    Range,
    /// Another period: days picked, or a link's `changes=7d`.
    Picked(Period),
    /// The To day is before the From day (the two days): said, and the
    /// last run shown.
    Backwards(i64, i64),
}

impl Changes {
    /// The period, with the page's range at `range`; `None`: since the
    /// last run.
    fn period(self, range: Range) -> Option<Period> {
        match self {
            Changes::LastRun | Changes::Backwards(..) => None,
            Changes::Range => Some(Period::of_range(range)),
            Changes::Picked(p) => (p != Period::LastRun).then_some(p),
        }
    }
}

/// [`href`] with what changed over: the range, or since the last run.
fn href_changes(env: &str, range: Range, changes: Changes) -> String {
    match changes {
        Changes::Range => format!("{}&changes=range", href(env, range)),
        _ => href(env, range),
    }
}

/// What What changed is over: the days `from` and `to` of the date fields
/// (either alone: from, or up to, that day), else `changes`; since the last
/// run when none reads.
fn changes_period(q: &PageQuery) -> Changes {
    let day = |d: &Option<String>| {
        d.as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .and_then(pathwarden_core::time::parse_date)
    };
    match (day(&q.from), day(&q.to)) {
        (Some(a), Some(b)) if b < a => return Changes::Backwards(a, b),
        (Some(a), Some(b)) => return Changes::Picked(Period::Between(a, b)),
        (Some(a), None) => return Changes::Picked(Period::From(a)),
        (None, Some(b)) => return Changes::Picked(Period::Until(b)),
        (None, None) => {}
    }
    match q.changes.as_deref().map(str::trim) {
        Some("range") => Changes::Range,
        Some(c) => Period::parse(c).map_or(Changes::LastRun, Changes::Picked),
        None => Changes::LastRun,
    }
}

/// What changed's own choice, under the page's time range (the one switch
/// for the page): since the last run, or everything net new over that
/// range; and two days, for another period.
fn changes_picker(env: &str, range: Range, changes: Changes) -> String {
    let over_range = changes == Changes::Range;
    let mut b = String::from(r#"<div class="pv-pick">"#);
    let _ = write!(
        b,
        r#"<span class="pv-over" role="group" aria-label="What changed over"><a href="{last}"{cur_last}>Since the last run</a><a href="{over}"{cur_over}>Over the {span}</a></span>"#,
        last = esc(&href_changes(env, range, Changes::LastRun)),
        over = esc(&href_changes(env, range, Changes::Range)),
        cur_last = if matches!(changes, Changes::LastRun | Changes::Backwards(..)) {
            r#" aria-current="true""#
        } else {
            ""
        },
        cur_over = if over_range {
            r#" aria-current="true""#
        } else {
            ""
        },
        span = range_words(range),
    );
    let (from, to) = match changes {
        Changes::Picked(Period::From(a)) => (day_value(a), String::new()),
        Changes::Picked(Period::Between(a, z)) => (day_value(a), day_value(z)),
        Changes::Picked(Period::Until(z)) => (String::new(), day_value(z)),
        Changes::Backwards(a, z) => (day_value(a), day_value(z)),
        _ => (String::new(), String::new()),
    };
    let _ = write!(
        b,
        r#"<form class="pv-dates" method="get" action="/progress"><input type="hidden" name="env" value="{env}"><input type="hidden" name="range" value="{range}"><label>From <input type="date" name="from" value="{from}"></label><label>To <input type="date" name="to" value="{to}"></label><span class="muted small">UTC days</span><button type="submit" class="btn small-btn">Show</button></form></div>"#,
        env = esc(env),
        range = range.key(),
    );
    if matches!(changes, Changes::Backwards(..)) {
        b.push_str(r#"<p class="muted small pv-note" role="status">The To day is before the From day: showing what changed since the last run.</p>"#);
    }
    b
}

/// "week", "month", "3 months", "whole history": the range in "Over the
/// month".
fn range_words(r: Range) -> &'static str {
    match r {
        Range::Week => "week",
        Range::Month => "month",
        Range::Quarter => "3 months",
        Range::All => "whole history",
    }
}

/// Where the report of `run` opens its Findings tab on `period`'s
/// Introduced filter: the report names the objects, members and paths the
/// card counts.
fn report_link(run: &str, period: Period, latest: i64) -> String {
    let place = match period {
        Period::LastRun => "last".to_string(),
        Period::Days(7) => "7".to_string(),
        Period::Days(30) => "30".to_string(),
        p => {
            let (from, to) = p.bounds(latest);
            let from = if from == i64::MIN {
                String::new()
            } else {
                day_value(from)
            };
            format!("{from}_{}", day_value(to))
        }
    };
    format!("/runs/{}#introduced-{place}", urlencode(run))
}

/// `YYYY-MM-DD` of a day's Unix time, for a date field.
fn day_value(t: i64) -> String {
    pathwarden_core::time::format_unix(t)
        .get(..10)
        .unwrap_or_default()
        .to_string()
}

fn body(
    ws: &Workspace,
    runs: &[RunSummary],
    snap: &Snapshot,
    env: Option<&str>,
    range: Range,
    changes: Changes,
) -> String {
    let mut b = String::from(r#"<link rel="stylesheet" href="/static/progress.css">"#);
    let envs = environments(runs, snap, &ws.env_name());
    let Some(chosen) = env
        .and_then(|e| envs.iter().find(|x| x.key == e))
        .or_else(|| envs.first())
    else {
        let _ = write!(
            b,
            r#"<div class="page-head"><div><h1 class="panel-title">Progress</h1><p class="lead">How exposure and findings change from run to run.</p></div></div>
{}"#,
            // The empty state Home and Explore have.
            pages::welcome_card(
                "Progress",
                "No runs yet.",
                "Analyze a collection, fix something, and analyze again. The change shows up here.",
            ),
        );
        return b;
    };
    // `all`: the points the page reads (every one of a history
    // environment; the charted ones and the run before for local runs),
    // with how many runs there are and how many are in the range.
    let (all, total, in_range, state): (Vec<Point>, usize, usize, Option<FindingsState>) =
        match &chosen.scopes {
            Some(scopes) => {
                let domains = history_ui::domains_for(scopes, runs, snap.history.last.as_ref());
                // The findings state names the findings that changed, as
                // `pathwarden history` does.
                let state = snap
                    .location
                    .as_ref()
                    .ok()
                    .and_then(|l| l.store.load().ok());
                let all = history_points(snap, scopes, &domains);
                let total = all.len();
                let in_range = total - range.start(&all, |p| p.hp.at);
                (all, total, in_range, state)
            }
            None => {
                // Only the runs that are not in the history.
                let local: Vec<RunSummary> =
                    runs.iter().filter(|r| !snap.has(r)).cloned().collect();
                let (all, total, in_range) = points(ws, &local, &chosen.runs_key, range);
                (all, total, in_range, None)
            }
        };
    let pts = &all[all.len() - in_range.min(MAX_RUNS).min(all.len())..];
    let _ = write!(
        b,
        r#"<div class="page-head pv-head"><div><h1 class="panel-title">Progress</h1><p class="lead">How {env} changed from run to run.{about}</p></div>"#,
        env = esc(&chosen.label),
        about = source_tip(snap, chosen),
    );
    if total > 1 {
        b.push_str(r#"<nav class="segmented pv-range" aria-label="Time range">"#);
        for r in Range::ALL {
            let _ = write!(
                b,
                r#"<a href="{h}"{cur}>{l}</a>"#,
                h = esc(&href_changes(&chosen.key, r, changes)),
                cur = if r == range {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                l = r.label(),
            );
        }
        b.push_str("</nav>");
    }
    b.push_str("</div>");
    if envs.len() > 1 {
        b.push_str(r#"<nav class="env-tabs" aria-label="Environment">"#);
        for e in &envs {
            let _ = write!(
                b,
                r#"<a href="{h}"{cur}><span>{l}</span><span class="count">{n}</span></a>"#,
                h = esc(&href(&e.key, range)),
                cur = if e.key == chosen.key {
                    r#" aria-current="page""#
                } else {
                    ""
                },
                l = esc(&e.label),
                n = num(e.count),
            );
        }
        b.push_str("</nav>");
    }
    b.push_str(&source_note(snap, chosen));
    kpis(&mut b, &all, pts);
    // What changed: since the last run, or with the history's findings
    // state, over the page's range or the days picked.
    let picker = state
        .as_ref()
        .filter(|_| total > 1)
        .map(|_| changes_picker(&chosen.key, range, changes))
        .unwrap_or_default();
    // The report that names them: the latest run's, when the app has it
    // (a history point names the run by the ID the history gave it).
    let report = latest_pair(&all)
        .0
        .filter(|_| state.is_some())
        .and_then(|p| {
            runs.iter()
                .find(|r| r.id == p.run.id || history_ui::recorded_id(r) == Some(p.run.id.as_str()))
        })
        .map(|r| r.id.as_str());
    match (changes.period(range), state.as_ref()) {
        (Some(p), Some(st)) if total > 1 => introduced_card(&mut b, &all, st, p, &picker, report),
        _ => {
            if let (Some(after), Some(before)) = latest_pair(&all) {
                since_card(&mut b, before, after, state.as_ref(), &picker, report);
            }
        }
    }
    if total < 2 {
        let _ = write!(
            b,
            r#"<div class="empty card pv-one">{}<p><strong>One run so far</strong>: {run}.<br><span class="muted">The charts need two runs. Fix something, then analyze this environment again (or let the schedule do it): the change shows up here.</span></p><p class="empty-actions"><a class="btn primary" href="/collect">{} Run an analysis</a></p></div>"#,
            icon("i-trend"),
            icon("i-upload"),
            run = all.last().map(|p| run_cell(&p.run)).unwrap_or_default(),
        );
    } else if pts.len() < 2 {
        let _ = write!(
            b,
            r#"<div class="empty card pv-one">{}<p><strong>One run in the {span} up to the latest.</strong><br><span class="muted">The charts need two runs in the range.</span></p><p class="empty-actions"><a class="btn primary" href="{h}">Show all {n} runs</a></p></div>"#,
            icon("i-trend"),
            span = range.span(),
            h = esc(&href(&chosen.key, Range::All)),
            n = num(total),
        );
    } else {
        // What the range leaves out, then what the cap leaves out of it.
        if in_range < total {
            let _ = write!(
                b,
                r#"<p class="note-line muted small">{n} of {total} runs: the {span} up to the latest. <a href="{h}">Show all</a></p>"#,
                n = num(in_range),
                total = num(total),
                span = range.span(),
                h = esc(&href(&chosen.key, Range::All)),
            );
        }
        if in_range > pts.len() {
            let _ = write!(
                b,
                r#"<p class="note-line muted small">The latest {n} of these {total} runs are charted.</p>"#,
                n = num(pts.len()),
                total = num(in_range),
            );
        }
        b.push_str(r#"<div class="pv-charts">"#);
        b.push_str(&tiers_chart(pts));
        b.push_str(&plan_chart(pts));
        b.push_str(&findings_chart(pts));
        b.push_str(&objects_chart(pts));
        b.push_str(&completeness_chart(pts));
        b.push_str("</div>");
    }
    b.push_str(&DEFINITIONS.replace("{info}", &icon("i-info")));
    b.push_str(r#"<div class="pv-tip" id="pv-tip" role="status" hidden></div><script src="/static/progress.js" defer></script>"#);
    b
}

pub(crate) fn urlencode(s: &str) -> String {
    history_ui::urlencode(s)
}

/// Where the charted runs come from, when they are the run history: an
/// (i) beside the title's line.
fn source_tip(snap: &Snapshot, e: &Env) -> String {
    match (&e.scopes, &snap.location) {
        (Some(_), Ok(loc)) => tip(
            "source",
            "Where these runs come from",
            &format!(
                "From the run history in {}{}: runs started here, from the command line and on a schedule.",
                crate::workspace::shown_path(&loc.dir),
                if loc.git.is_some() { " (a git repository)" } else { "" }
            ),
        ),
        _ => String::new(),
    }
}

/// Under the title, when some runs are not in the run history: which, and
/// the way to import them.
fn source_note(snap: &Snapshot, e: &Env) -> String {
    let mut parts = Vec::new();
    match (&e.scopes, &snap.location) {
        (Some(_), Ok(_)) => {}
        (None, _) if e.demo => parts.push(
            "Demo runs are kept on this computer only; they never enter the run history."
                .to_string(),
        ),
        (None, _) => parts.push(
            r#"These runs are local only: they are not in the run history. <a href="/automate/history#earlier">Import them</a>"#
                .to_string(),
        ),
        (Some(_), Err(_)) => {}
    }
    if e.local_only > 0 {
        parts.push(format!(
            r#"{} earlier {} of this environment {} local only and not charted. <a href="/automate/history#earlier">Import or keep them local</a>"#,
            num(e.local_only),
            if e.local_only == 1 { "run" } else { "runs" },
            if e.local_only == 1 { "is" } else { "are" },
        ));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!(
        r#"<p class="note-line muted small pv-source">{}</p>"#,
        parts.join(" ")
    )
}

fn open_of(p: &HistoryPoint) -> usize {
    pathwarden_core::history::open_findings(p)
}

/// A small (i) with a definition, as the report has them (`tip` in the
/// report's code; the same classes and behaviour).
fn tip(id: &str, term: &str, text: &str) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {term}" aria-describedby="tip-{id}">{icon}</button><span class="tip-text" role="tooltip" id="tip-{id}">{text}</span></span>"#,
        term = esc(term),
        text = esc(text),
        icon = icon("i-info"),
    )
}

/// How a figure moved since the last run: "▼ 120" in green when that is
/// better, "▲ 2" in red when worse, "no change" muted. The arrow is
/// decoration; the hidden word says which way. `unit` follows the number.
fn delta(before: f64, after: f64, lower_is_better: bool, fmt: impl Fn(f64) -> String) -> String {
    let d = after - before;
    if d.abs() < 0.005 {
        return r#"<span class="delta same">no change</span>"#.to_string();
    }
    let better = (d < 0.0) == lower_is_better;
    let (arrow, word) = if d < 0.0 {
        ("&#9660;", "down")
    } else {
        ("&#9650;", "up")
    };
    format!(
        r#"<span class="delta {}"><span aria-hidden="true">{arrow}</span><span class="vh">{word}</span> {}</span>"#,
        if better { "good" } else { "bad" },
        fmt(d.abs())
    )
}

fn count_fmt(v: f64) -> String {
    num(v.round() as usize)
}

/// How long a range of runs spans, for a card: "5 days", "7 weeks",
/// "3 months".
fn elapsed(secs: i64) -> String {
    let secs = secs.max(0);
    // Runs minutes apart: not "1 day".
    if secs < 3_600 {
        return "under an hour".to_string();
    }
    if secs < 86_400 {
        let hours = (secs as f64 / 3_600.0).round() as usize;
        return pathwarden_core::text::count(hours.clamp(1, 23), "hour", "hours");
    }
    let days = (secs as f64 / 86_400.0).round() as usize;
    if days < 14 {
        pathwarden_core::text::count(days.max(1), "day", "days")
    } else if days < 70 {
        pathwarden_core::text::count((days as f64 / 7.0).round() as usize, "week", "weeks")
    } else {
        pathwarden_core::text::count((days as f64 / 30.0).round() as usize, "month", "months")
    }
}

/// The latest run of `all` and the run it is compared with, as `pathwarden
/// history` and the Overview pick them ([`since::latest_point`],
/// [`since::previous`]): never a point added after a newer run.
pub fn latest_pair(all: &[Point]) -> (Option<&Point>, Option<&Point>) {
    let hps: Vec<HistoryPoint> = all.iter().map(|p| p.hp.clone()).collect();
    let (after, before) = latest_pair_of(&hps);
    (after.map(|i| &all[i]), before.map(|i| &all[i]))
}

/// [`latest_pair`] by position in `hps`.
fn latest_pair_of(hps: &[HistoryPoint]) -> (Option<usize>, Option<usize>) {
    let at = |p: &HistoryPoint| hps.iter().position(|h| h.run_id == p.run_id);
    let Some(after) = since::latest_point(hps) else {
        return (None, None);
    };
    (at(after), since::previous(hps, after).and_then(at))
}

/// The four cards: one number each, with its change since the last run
/// (over every run, `all`: the shared comparison, [`since::compare`], as
/// the report's Overview and `pathwarden history` have it) and over the
/// charted range (`pts`), when the range has more than the two runs.
fn kpis(b: &mut String, all: &[Point], pts: &[Point]) {
    let (Some(last), prev) = latest_pair(all) else {
        return;
    };
    let (l, r) = (&last.hp, &last.run);
    // The change over the range, from the first charted run that recorded
    // the figure, when that is not simply the run before.
    let over =
        |get: &dyn Fn(&HistoryPoint) -> Option<f64>, lower: bool, fmt: &dyn Fn(f64) -> String| {
            // From the first charted run that targeted what this one did.
            let first = pts
                .iter()
                .find(|p| get(&p.hp).is_some() && since::comparable(&p.hp, l))?;
            let (a, z) = (get(&first.hp)?, get(l)?);
            let before = prev.map(|p| p.hp.at);
            if pts.len() < 3 || Some(first.hp.at) >= before {
                return None;
            }
            Some(format!(
                r#"<span class="kpi-sub">{} in {}</span>"#,
                delta(a, z, lower, fmt),
                elapsed(l.at - first.hp.at)
            ))
        };
    let since_last = |d: Option<String>| match d {
        Some(d) => format!(r#"<span class="kpi-sub">{d} since the last run</span>"#),
        None => r#"<span class="kpi-sub">the first run</span>"#.to_string(),
    };
    let another_way =
        r#"<span class="kpi-sub">the last run counted these another way</span>"#.to_string();
    let changed = prev.map(|p| since::compare(&p.hp, l, None));
    let not_compared = r#"<span class="kpi-sub">not compared with the last run</span>"#.to_string();
    let counts = |d: since::Delta| delta(d.before as f64, d.after as f64, true, count_fmt);
    let exposed = match &changed {
        None => since_last(None),
        Some(c) if !c.comparable() => not_compared.clone(),
        Some(c) => match c.tier_zero {
            Some(d) => since_last(Some(counts(d))),
            None => another_way.clone(),
        },
    } + &over(&|p| Some(p.tier_zero_exposed as f64), true, &count_fmt)
        .unwrap_or_default();
    let steps = l.plan.map(|s| s.steps);
    let plan = match (steps, &changed) {
        (None, _) => r#"<span class="kpi-sub">not recorded for this run</span>"#.to_string(),
        (Some(_), None) => since_last(None),
        (Some(_), Some(c)) if !c.comparable() => not_compared.clone(),
        (Some(_), Some(c)) => match c.changes_to_zero {
            Some(p) => since_last(Some(counts(p.steps))),
            None if c.basis_changed => another_way.clone(),
            None => r#"<span class="kpi-sub">not recorded the run before</span>"#.to_string(),
        },
    } + &over(&|p| p.plan.map(|s| s.steps as f64), true, &count_fmt).unwrap_or_default();
    let open = match &changed {
        Some(c) if !c.comparable() => not_compared.clone(),
        _ => since_last(changed.as_ref().map(|c| counts(c.open.total))),
    } + &over(&|p| Some(open_of(p) as f64), true, &count_fmt).unwrap_or_default();
    let pts_fmt = pathwarden_core::posture::points;
    let mut score = match (l.protection_score, &changed) {
        (None, _) => r#"<span class="kpi-sub">no Tier Zero objects found</span>"#.to_string(),
        (Some(_), None) => since_last(None),
        (Some(_), Some(c)) if !c.comparable() => not_compared.clone(),
        (Some(_), Some(c)) => match c.protection_score {
            Some(sh) => since_last(Some(delta(sh.before, sh.after, false, pts_fmt))),
            None => r#"<span class="kpi-sub">not recorded the run before</span>"#.to_string(),
        },
    } + &over(&|p| p.protection_score, false, &pts_fmt).unwrap_or_default();
    // The objects behind the share, as context (the share is exact: the
    // protected objects over all of them).
    if let Some(s) = l.protection_score.filter(|_| l.tier_zero_objects > 0) {
        let protected = (s * l.tier_zero_objects as f64 / 100.0).round() as usize;
        score = format!(
            r#"<span class="kpi-sub">{}</span>{score}"#,
            pathwarden_core::posture::protected_count(protected, l.tier_zero_objects),
        );
    }
    let _ = write!(
        b,
        r#"<div class="kpis pv-kpis">
<div class="kpi {band}" title="{reason}"><span class="kpi-label">With an attack path to Tier Zero · {grade}{t1}</span><span class="kpi-value">{exposed_n}</span>{exposed}</div>
<div class="kpi"><span class="kpi-label">Plan steps{t2}</span><span class="kpi-value">{steps}</span>{plan}</div>
<div class="kpi"><span class="kpi-label">Open findings{t3}</span><span class="kpi-value">{open_n}</span>{open}</div>
<div class="kpi"><span class="kpi-label">Tier Zero protected{t4}</span><span class="kpi-value">{score_n}</span>{score}</div>
</div>"#,
        band = pages::grade_class(r),
        reason = esc(&r.status_reason()),
        grade = r.grade().as_str(),
        t1 = tip("k-exposed", "With an attack path to Tier Zero", "Enabled users and computers outside Tier Zero with a full path to it. The status comes from the paths and the open findings, never from a share."),
        exposed_n = num(l.tier_zero_exposed),
        t2 = tip("k-plan", "Plan steps", "The fewest changes that cut every attack path to Tier Zero, the one that cuts the most first."),
        steps = steps.map_or("–".to_string(), num),
        t3 = tip("k-open", "Open findings", "Findings not fixed or accepted as a risk, attack path and hygiene alike."),
        open_n = num(open_of(l)),
        t4 = tip("k-score", "Tier Zero protected", pathwarden_core::posture::PROTECTED_DEFINITION),
        score_n = l
            .protection_score
            .map_or("–".to_string(), pathwarden_core::posture::share_percent),
    );
}

/// What changed since the run before, as `pathwarden history` says it:
/// the same lines, from the same comparison.
fn since_card(
    b: &mut String,
    before: &Point,
    after: &Point,
    state: Option<&FindingsState>,
    picker: &str,
    report: Option<&str>,
) {
    let lines = since::compare(&before.hp, &after.hp, state).lines();
    let _ = write!(
        b,
        r#"<section class="card pv-since" aria-labelledby="pv-since-h"><div class="pv-since-head"><h2 class="sub" id="pv-since-h">What changed since {}{}</h2>{picker}</div>"#,
        pages::time_as(before.hp.at, "day"),
        tip(
            "since",
            "What changed",
            "The latest run compared with the last run that collected sessions and local groups the same way."
        ),
    );
    line_list(b, &lines);
    if let Some(run) = report {
        named_in(b, &report_link(run, Period::LastRun, after.hp.at));
    }
    b.push_str("</section>");
}

/// The link under a What changed card to the report's Findings tab, which
/// names what the lines count.
fn named_in(b: &mut String, href: &str) {
    let _ = write!(
        b,
        r#"<p class="small pv-named"><a href="{}">Name them in the report's Findings tab</a></p>"#,
        esc(href)
    );
}

/// What changed over a period: everything net new in it and what was
/// fixed, from the findings state, the lines `pathwarden changes --since`
/// prints; with the note when the period reaches back before objects and
/// paths were dated.
fn introduced_card(
    b: &mut String,
    all: &[Point],
    state: &FindingsState,
    period: Period,
    picker: &str,
    report: Option<&str>,
) {
    // The latest run as `pathwarden changes` picks it (never an inserted one).
    let Some(last) = latest_pair(all).0 else {
        return;
    };
    let latest = last.hp.at;
    let runs = introduced::Runs::new(all.iter().map(|p| p.hp.at).collect()).in_env_of(&last.hp);
    let points: Vec<HistoryPoint> = all.iter().map(|p| p.hp.clone()).collect();
    let intro = introduced::period(state, period, latest, &runs).with_exposure(&points, &runs);
    let _ = write!(
        b,
        r#"<section class="card pv-since" aria-labelledby="pv-since-h"><div class="pv-since-head"><h2 class="sub" id="pv-since-h">{}{}</h2>{picker}</div>"#,
        esc(&introduced::Introduced::heading(period, latest)),
        tip(
            "introduced",
            "Introduced",
            "First seen by Pathwarden: each finding, object and path carries the date of the run that found it, not when it changed in the directory. The report's Findings tab names the objects and paths."
        ),
    );
    line_list(b, &intro.lines());
    if let Some(note) = intro.note(&runs, latest) {
        let _ = write!(b, r#"<p class="muted small pv-note">{}</p>"#, esc(&note));
    }
    // The days and dates are those `pathwarden changes` and the report use:
    // UTC, not the local time the charts show.
    b.push_str(r#"<p class="muted small pv-utc">Days and dates here are UTC.</p>"#);
    if let Some(run) = report {
        named_in(b, &report_link(run, period, latest));
    }
    b.push_str("</section>");
}

/// The lines of a What changed card: each marked worse, better or neither,
/// with what it names (the terminal's commands are left out).
fn line_list(b: &mut String, lines: &[since::Line]) {
    b.push_str("<ul>");
    for l in lines {
        let (class, mark) = match l.tone {
            Tone::Worse => ("worse", "&#9650;"),
            Tone::Better => ("better", "&#9660;"),
            Tone::Same => ("same", "&#8226;"),
        };
        let word = match l.tone {
            Tone::Worse => "Worse: ",
            Tone::Better => "Better: ",
            Tone::Same => "",
        };
        let _ = write!(
            b,
            r#"<li class="{class}"><span class="mark" aria-hidden="true">{mark}</span><span><span class="vh">{word}</span>{}"#,
            esc(&l.text)
        );
        if !l.items.is_empty() {
            let items: Vec<String> = l.items.iter().map(|i| esc(i)).collect();
            let _ = write!(b, r#"<span class="items">{}</span>"#, items.join(" · "));
        }
        b.push_str("</span></li>");
    }
    b.push_str("</ul>");
}

// ---------------------------------------------------------------- charts

const W: f64 = 880.0;
const H: f64 = 260.0;
const ML: f64 = 54.0;
/// Room on the right for the last values' labels.
const MR: f64 = 46.0;
const MT: f64 = 26.0;
const MB: f64 = 50.0;

fn plot_w() -> f64 {
    W - ML - MR
}

fn plot_h() -> f64 {
    H - MT - MB
}

/// Center of slot `i` of `n`.
fn slot_x(i: usize, n: usize) -> f64 {
    ML + (i as f64 + 0.5) * plot_w() / n as f64
}

fn slot_w(n: usize) -> f64 {
    plot_w() / n.max(1) as f64
}

/// "Oct 9" and "2:05 PM" (UTC).
fn day_time(t: i64) -> (String, String) {
    (
        pathwarden_core::time::format_month_day(t),
        pathwarden_core::time::format_clock(t),
    )
}

/// A run in a chart's table: its time, and its label when it has one.
fn run_cell(r: &RunSummary) -> String {
    match &r.label {
        Some(l) => format!(
            r#"{} <span class="pv-label">{}</span>"#,
            pages::time(r.created_at),
            esc(l)
        ),
        None => pages::time(r.created_at),
    }
}

/// A run's time in a tooltip line, in UTC; `progress.js` shows it in local
/// time (the hit area carries `data-tip-unix`).
fn when(t: i64) -> String {
    pathwarden_core::time::format_utc(t)
}

/// X labels: every slot when few, else evenly thinned (the last always),
/// never closer than 60 units. A first label too near the y axis for its
/// width starts at the axis instead of centering on its run, clear of the
/// y ticks.
fn x_labels(b: &mut String, pts: &[Point], y0: f64) {
    let n = pts.len();
    let every = n.div_ceil(10).max(1);
    let mut last_x = f64::NEG_INFINITY;
    let last_slot = slot_x(n - 1, n);
    for (i, p) in pts.iter().enumerate() {
        if i % every != 0 && i != n - 1 {
            continue;
        }
        let x = slot_x(i, n);
        let lead = i == 0 && x - ML < 30.0;
        // Where the label's middle is, for the spacing.
        let mid = if lead { ML + 32.0 } else { x };
        // A thinned label too close to the last one gives way to it.
        if i != n - 1 && (mid - last_x < 60.0 || last_slot - mid < 60.0) {
            continue;
        }
        last_x = mid;
        let (x, lead) = if lead { (ML + 2.0, " lead") } else { (x, "") };
        let (d, h) = day_time(p.run.created_at);
        let _ = write!(
            b,
            r#"<text class="pv-x{lead}" x="{x:.1}" y="{y1:.1}" data-unix="{t}" data-fmt="day">{d}</text><text class="pv-x pv-x2{lead}" x="{x:.1}" y="{y2:.1}" data-unix="{t}" data-fmt="time">{h}</text>"#,
            t = p.run.created_at,
            y1 = y0 + 18.0,
            // Apart enough for the phone's larger type (in chart units).
            y2 = y0 + 38.0,
        );
    }
}

/// A rounded "nice" maximum for counts, and its tick step.
fn nice(max: usize) -> (usize, usize) {
    let max = max.max(1);
    let raw = max as f64 / 4.0;
    let mag = 10f64.powf(raw.log10().floor());
    let step = [1.0, 2.0, 2.5, 5.0, 10.0]
        .iter()
        .map(|m| m * mag)
        .find(|s| *s >= raw)
        .unwrap_or(10.0 * mag)
        .max(1.0)
        .round() as usize;
    (max.div_ceil(step) * step, step)
}

/// A count axis: linear from 0 to a nice maximum, or log in decades with
/// 0 on the baseline one step below 1.
#[derive(Clone, Copy)]
enum Scale {
    Linear { max: usize, step: usize },
    Log { decades: u32 },
}

impl Scale {
    fn linear(max: usize) -> Self {
        let (max, step) = nice(max);
        Scale::Linear { max, step }
    }

    fn log(max: usize) -> Self {
        // 10^(decades - 1) is the top tick, at or above `max`.
        let mut decades = 1;
        while 10usize.saturating_pow(decades - 1) < max {
            decades += 1;
        }
        Scale::Log { decades }
    }

    /// Where `v` sits, 0 (baseline) to 1 (top).
    fn frac(self, v: f64) -> f64 {
        match self {
            Scale::Linear { max, .. } => v / max.max(1) as f64,
            Scale::Log { decades } => {
                if v <= 0.0 {
                    0.0
                } else {
                    (1.0 + v.max(1.0).log10()) / decades as f64
                }
            }
        }
    }

    fn y(self, v: f64) -> f64 {
        MT + plot_h() * (1.0 - self.frac(v))
    }

    fn ticks(self) -> Vec<usize> {
        match self {
            Scale::Linear { max, step } => (0..=max).step_by(step.max(1)).collect(),
            Scale::Log { decades } => std::iter::once(0)
                .chain((0..decades).map(|d| 10usize.pow(d)))
                .collect(),
        }
    }

    /// Horizontal gridlines, and their labels into `axis` (the column
    /// that stays put when the chart scrolls, [`svg`]).
    fn grid(self, b: &mut String, axis: &mut String) {
        for v in self.ticks() {
            let y = self.y(v as f64);
            let _ = write!(
                b,
                r#"<line class="pv-grid{base}" x1="{ML}" x2="{x2}" y1="{y:.1}" y2="{y:.1}"/>"#,
                base = if v == 0 { " base" } else { "" },
                x2 = W - MR,
            );
            y_label(axis, y, &num(v));
        }
    }
}

/// A y tick's label, right-aligned against the plot.
fn y_label(axis: &mut String, y: f64, text: &str) {
    let _ = write!(
        axis,
        r#"<text class="pv-y" x="{tx}" y="{ty:.1}">{text}</text>"#,
        tx = ML - 8.0,
        ty = y + 4.0,
    );
}

/// A value label over a run at `x`: centered on it, or starting at it
/// when centering would reach into the y axis.
fn val_x(x: f64) -> (f64, &'static str) {
    if x - ML < 30.0 {
        (x - 3.0, " end")
    } else {
        (x, "")
    }
}

/// The hover/focus target for one run: the whole slot, with the tooltip
/// lines in `data-tip` (also as an SVG title for assistive tech).
/// The run's label, when it has one, is the second line.
fn hit(
    b: &mut String,
    i: usize,
    n: usize,
    top: f64,
    height: f64,
    run: &RunSummary,
    lines: &[String],
) {
    hit_at(
        b,
        (slot_x(i, n) - slot_w(n) / 2.0, slot_w(n)),
        (top, height),
        run,
        lines,
    );
}

/// [`hit`] over the slot from `x.0`, `x.1` wide, and from `y.0`, `y.1`
/// tall: for a chart with its own x positions.
fn hit_at(b: &mut String, x: (f64, f64), y: (f64, f64), run: &RunSummary, lines: &[String]) {
    let at = run.created_at;
    let mut lines = lines.to_vec();
    if let Some(l) = &run.label {
        lines.insert(1.min(lines.len()), l.clone());
    }
    let label = lines.join(". ");
    let _ = write!(
        b,
        r#"<rect class="pv-hit" x="{x:.1}" y="{top:.1}" width="{w:.1}" height="{height:.1}" tabindex="0" role="img" aria-label="{a}" data-tip="{t}" data-tip-unix="{at}"><title>{a}</title></rect>"#,
        x = x.0,
        w = x.1,
        top = y.0,
        height = y.1,
        a = esc(&label),
        t = esc(&lines.join("\n")),
    );
}

/// A chart's frame: title (with its definition), one-line subtitle,
/// legend, `extra` beside the title (the scale switch), the SVGs, a muted
/// note and the table behind it.
struct Figure<'a> {
    class: &'a str,
    title: &'a str,
    tip_id: &'a str,
    definition: &'a str,
    sub: &'a str,
    legend: &'a str,
    extra: &'a str,
    svg: &'a str,
    note: &'a str,
    table: &'a str,
}

impl Figure<'_> {
    fn render(&self) -> String {
        format!(
            r#"<figure class="pv card {class}"><figcaption><div class="pv-cap"><div><h2 class="sub">{title}{tip}</h2><p class="muted small">{sub}</p></div>{extra}</div>{legend}</figcaption>
{svg}{note}
<details class="pv-data"><summary>Show the numbers</summary><div class="pv-table-wrap"><table>{table}</table></div></details></figure>"#,
            class = self.class,
            title = esc(self.title),
            tip = tip(self.tip_id, self.title, self.definition),
            sub = self.sub,
            extra = self.extra,
            legend = self.legend,
            svg = self.svg,
            note = if self.note.is_empty() {
                String::new()
            } else {
                format!(r#"<p class="pv-note-line muted small">{}</p>"#, self.note)
            },
            table = self.table,
        )
    }
}

/// The column at the left of a chart that stays in view when the chart
/// scrolls sideways on a narrow screen: the y ticks, or the row names.
#[derive(Clone, Copy)]
enum Axis {
    Y,
    Rows,
}

impl Axis {
    fn width(self) -> f64 {
        match self {
            Axis::Y => ML,
            Axis::Rows => ROWS_LEFT,
        }
    }

    fn class(self) -> &'static str {
        match self {
            Axis::Y => "y",
            Axis::Rows => "rows",
        }
    }
}

/// A figure no run in the range recorded: its title, definition, subtitle
/// and note, and how to record it, instead of an empty chart.
fn empty_figure(
    class: &str,
    title: &str,
    tip_id: &str,
    definition: &str,
    sub: &str,
    note: &str,
) -> String {
    format!(
        r#"<figure class="pv card {class} pv-empty"><figcaption><div class="pv-cap"><div><h2 class="sub">{t}{tip}</h2><p class="muted small">{sub}</p></div></div></figcaption>
<p class="pv-note-line muted small">{note}</p><p class="empty-actions"><a class="btn" href="/collect">{icon} Run an analysis to record it</a></p></figure>"#,
        t = esc(title),
        tip = tip(tip_id, title, definition),
        icon = icon("i-upload"),
    )
}

/// An SVG of the standard size, or `h` tall, in its scroll box, with
/// `axis` drawn in a second SVG over its left edge that stays in view
/// when the box scrolls (`position: sticky`); both share the scale.
fn svg(title: &str, h: f64, body: &str, axis: &str, kind: Axis, class: &str) -> String {
    format!(
        r#"<div class="pv-scroll {class}"><div class="pv-canvas"><svg class="pv-svg" viewBox="0 0 {W} {h}" role="group" aria-label="{t}">{body}</svg><svg class="pv-svg pv-axis {k}" viewBox="0 0 {aw} {h}" aria-hidden="true"><rect class="pv-axis-bg" width="{aw}" height="{h}"/>{axis}</svg></div></div>"#,
        t = esc(title),
        k = kind.class(),
        aw = kind.width(),
    )
}

/// The legend: one swatch per series, `sw` its class.
fn legend(items: &[(&str, String)]) -> String {
    let mut s = String::from(r#"<ul class="pv-legend">"#);
    for (class, label) in items {
        let _ = write!(s, r#"<li><span class="sw {class}"></span>{label}</li>"#);
    }
    s.push_str("</ul>");
    s
}

/// A figure's note when older runs lack it: "Runs before Oct 5 didn't
/// record …: the line starts at the first run that did." Empty when every
/// run has it.
fn starts_note(pts: &[Point], has: impl Fn(&Point) -> bool, what: &str) -> String {
    match pts.iter().position(has) {
        Some(0) => String::new(),
        Some(i) => format!(
            "Runs before {} didn't record {what}: the line starts at the first run that did.",
            pages::time_as(pts[i].hp.at, "day")
        ),
        None => format!("No run in this range recorded {what}; runs from this version on do."),
    }
}

/// Moves labels apart vertically so none is closer than `gap` to the next,
/// keeping them between `lo` and `hi`. `ys` in any order; returns them in
/// the same order.
fn spread(ys: &[f64], gap: f64, lo: f64, hi: f64) -> Vec<f64> {
    let mut order: Vec<usize> = (0..ys.len()).collect();
    order.sort_by(|&a, &b| ys[a].total_cmp(&ys[b]));
    let mut placed: Vec<f64> = order.iter().map(|&i| ys[i].clamp(lo, hi)).collect();
    for k in 1..placed.len() {
        if placed[k] - placed[k - 1] < gap {
            placed[k] = placed[k - 1] + gap;
        }
    }
    // Pushed past the bottom: shift back up, keeping the gaps.
    if let Some(&last) = placed.last() {
        if last > hi {
            let over = last - hi;
            for p in &mut placed {
                *p -= over;
            }
            for k in (0..placed.len().saturating_sub(1)).rev() {
                if placed[k + 1] - placed[k] < gap {
                    placed[k] = placed[k + 1] - gap;
                }
            }
        }
    }
    let mut out = vec![0.0; ys.len()];
    for (k, &i) in order.iter().enumerate() {
        out[i] = placed[k];
    }
    out
}

/// One line series: its legend name, swatch class and values (`None`
/// where the run didn't record it).
struct Series {
    name: String,
    class: &'static str,
    values: Vec<Option<f64>>,
}

/// Series classes in their fixed order (`.s1` Tier Zero, then zones).
const SERIES: [&str; 3] = ["s1", "s2", "s3"];

/// How far apart, in chart units, two series are drawn where they
/// coincide, so the one underneath stays in view.
const OFFSET: f64 = 3.5;

/// The y of each series' value at each run on `scale`. A series that
/// would sit on an earlier one at a run (closer than [`OFFSET`]) is drawn
/// just beside it there, under it unless its value is higher, so a zone
/// with Tier Zero's counts still shows; the labels and the table keep the
/// exact values.
fn series_ys(series: &[Series], scale: Scale) -> Vec<Vec<Option<f64>>> {
    let mut ys: Vec<Vec<Option<f64>>> = Vec::new();
    for s in series {
        let row: Vec<Option<f64>> = s
            .values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let mut y = scale.y((*v)?);
                // Earlier series in order; one more pass catches a series
                // moved onto another.
                for _ in 0..ys.len() {
                    for earlier in &ys {
                        if let Some(e) = earlier[i] {
                            // On its side of the other: a higher value
                            // stays above it, an equal or lower one below.
                            if (y - e).abs() < OFFSET {
                                y = if y < e { e - OFFSET } else { e + OFFSET };
                            }
                        }
                    }
                }
                Some(y)
            })
            .collect();
        ys.push(row);
    }
    ys
}

/// A value label of a series, in the series' colour.
fn series_label(b: &mut String, class: &str, x: f64, y: f64, anchor: &str, text: &str) {
    let _ = write!(
        b,
        r#"<text class="pv-val{anchor} halo {class}" x="{x:.1}" y="{y:.1}">{text}</text>"#
    );
}

/// A leader line in a series' colour, from its dot to its moved label.
fn leader(b: &mut String, class: &str, dot: (f64, f64), end: (f64, f64)) {
    let _ = write!(
        b,
        r#"<line class="pv-lead {class}" x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}"/>"#,
        dot.0, dot.1, end.0, end.1
    );
}

/// Lines for `series` on `scale`, broken where a value is missing, with a
/// dot at each run and the first and last value of each line labeled in
/// its colour: the first above its dot, the last to its right, moved apart
/// so no two overlap, with a leader line to its dot when moved. `fmt`
/// writes a value.
fn lines(b: &mut String, series: &[Series], n: usize, scale: Scale, fmt: &dyn Fn(f64) -> String) {
    let ys = series_ys(series, scale);
    let mut firsts: Vec<(f64, f64, String, &str)> = Vec::new();
    let mut lasts: Vec<(f64, f64, String, &str)> = Vec::new();
    // The first series (Tier Zero) drawn last, on top where lines meet.
    for (s, sy) in series.iter().zip(&ys).rev() {
        let mut seg: Vec<String> = Vec::new();
        let flush = |b: &mut String, seg: &mut Vec<String>| {
            if seg.len() > 1 {
                let _ = write!(
                    b,
                    r#"<polyline class="pv-line {}" points="{}"/>"#,
                    s.class,
                    seg.join(" ")
                );
            }
            seg.clear();
        };
        for (i, y) in sy.iter().enumerate() {
            match y {
                Some(y) => seg.push(format!("{:.1},{:.1}", slot_x(i, n), y)),
                None => flush(b, &mut seg),
            }
        }
        flush(b, &mut seg);
        for (i, y) in sy.iter().enumerate() {
            if let Some(y) = y {
                let _ = write!(
                    b,
                    r#"<circle class="pv-dot {}" cx="{:.1}" cy="{:.1}" r="{}"/>"#,
                    s.class,
                    slot_x(i, n),
                    y,
                    if n > 24 { 3 } else { 4 }
                );
            }
        }
        let first = s.values.iter().position(|v| v.is_some());
        let last = s.values.iter().rposition(|v| v.is_some());
        if let (Some(f), Some(l)) = (first, last) {
            let (fv, lv) = (s.values[f].unwrap_or(0.0), s.values[l].unwrap_or(0.0));
            let (fy, ly) = (sy[f].unwrap_or(0.0), sy[l].unwrap_or(0.0));
            lasts.push((slot_x(l, n), ly, fmt(lv), s.class));
            if f != l {
                firsts.push((slot_x(f, n), fy, fmt(fv), s.class));
            }
        }
    }
    // Moved this far from its place, a label gets a leader line.
    const MOVED: f64 = 4.0;
    // First values above their dots, apart from each other when they share
    // a run; last values right of theirs.
    let want: Vec<f64> = firsts.iter().map(|f| f.1 - 10.0).collect();
    let placed = spread(&want, 19.0, MT - 6.0, MT + plot_h() - 4.0);
    for (((x, dy, t, class), y), w) in firsts.iter().zip(placed).zip(&want) {
        if (y - w).abs() > MOVED {
            // To the label's baseline from above its dot, or to its top
            // from under it.
            let (from, to) = if y < *dy {
                (dy - 5.0, y + 3.0)
            } else {
                (dy + 5.0, y - 13.0)
            };
            leader(b, class, (*x, from), (*x, to));
        }
        let (x, end) = val_x(*x);
        series_label(b, class, x, y, end, t);
    }
    let want: Vec<f64> = lasts.iter().map(|l| l.1 + 4.0).collect();
    let placed = spread(&want, 19.0, MT + 4.0, MT + plot_h() - 2.0);
    for (((x, dy, t, class), y), w) in lasts.iter().zip(placed).zip(&want) {
        if (y - w).abs() > MOVED {
            // From the dot's right edge to the label's start, at its middle.
            leader(b, class, (x + 4.0, *dy), (x + 7.0, y - 4.0));
        }
        series_label(b, class, x + 8.0, y, " end", t);
    }
}

/// The zones charted beside Tier Zero: the latest run's first
/// [`ZONE_TRENDS`] zones that recorded their accounts (as `pathwarden
/// history` lists them), and how many more there are.
fn charted_zones(pts: &[Point]) -> (Vec<String>, usize) {
    let Some(last) = latest_pair(pts).0 else {
        return (Vec::new(), 0);
    };
    let all: Vec<String> = last
        .hp
        .zones
        .iter()
        .filter(|z| z.exposed.is_some())
        .map(|z| z.zone.clone())
        .collect();
    let more = all.len().saturating_sub(ZONE_TRENDS);
    (all.into_iter().take(ZONE_TRENDS).collect(), more)
}

/// The legend item for the zones a chart leaves out, as `pathwarden
/// history` says it.
fn more_zones(more: usize) -> String {
    format!(
        "and {} not charted",
        pathwarden_core::text::count(more, "more zone", "more zones")
    )
}

fn zone_value(
    p: &Point,
    zone: &str,
    f: impl Fn(&pathwarden_core::state::ZonePoint) -> Option<usize>,
) -> Option<usize> {
    p.hp.zones.iter().find(|z| z.zone == zone).and_then(f)
}

fn tiers_chart(pts: &[Point]) -> String {
    let n = pts.len();
    let (zones, more) = charted_zones(pts);
    let mut series = vec![Series {
        name: "Tier Zero".into(),
        class: SERIES[0],
        values: pts
            .iter()
            .map(|p| Some(p.hp.tier_zero_exposed as f64))
            .collect(),
    }];
    for (k, z) in zones.iter().enumerate() {
        series.push(Series {
            name: z.clone(),
            class: SERIES[k + 1],
            values: pts
                .iter()
                .map(|p| zone_value(p, z, |z| z.exposed).map(|v| v as f64))
                .collect(),
        });
    }
    let values: Vec<f64> = series
        .iter()
        .flat_map(|s| s.values.iter().flatten().copied())
        .collect();
    let max = values.iter().cloned().fold(0.0, f64::max) as usize;
    let min_pos = values
        .iter()
        .map(|v| v.max(1.0))
        .fold(f64::INFINITY, f64::min);
    // Log by default when the range spans ten times or more.
    let log_default = max as f64 >= 10.0 * min_pos;
    let draw = |scale: Scale| {
        let (mut s, mut axis) = (String::new(), String::new());
        scale.grid(&mut s, &mut axis);
        x_labels(&mut s, pts, MT + plot_h());
        // A run that read the directory only counts fewer paths: marked,
        // so its drop doesn't read as progress.
        untargeted_labels(&mut s, pts, MT + plot_h() - 8.0);
        lines(&mut s, &series, n, scale, &count_fmt);
        for (i, p) in pts.iter().enumerate() {
            let mut tl = vec![
                when(p.hp.at),
                format!(
                    "Tier Zero: {} ({})",
                    num(p.hp.tier_zero_exposed),
                    p.run.grade().as_str()
                ),
            ];
            tl.extend(untargeted_tip(p));
            for z in &zones {
                tl.push(match zone_value(p, z, |z| z.exposed) {
                    Some(v) => format!("{z}: {}", num(v)),
                    None => format!("{z}: not recorded"),
                });
            }
            hit(&mut s, i, n, MT, plot_h(), &p.run, &tl);
        }
        (s, axis)
    };
    let title = "Accounts with an attack path to each tier";
    let (lin, lin_axis) = draw(Scale::linear(max));
    let (log, log_axis) = draw(Scale::log(max));
    let svgs = format!(
        "{}{}",
        svg(title, H, &lin, &lin_axis, Axis::Y, "pv-lin"),
        svg(title, H, &log, &log_axis, Axis::Y, "pv-log")
    );
    let extra = format!(
        r#"<span class="segmented pv-scale" role="radiogroup" aria-label="Scale"><label><input type="radio" name="pv-scale" value="lin"{}>Linear</label><label><input type="radio" name="pv-scale" value="log"{}>Log</label></span>"#,
        if log_default { "" } else { " checked" },
        if log_default { " checked" } else { "" },
    );
    let mut table = String::from("<thead><tr><th>Run</th><th>Status</th><th>Tier Zero</th>");
    for z in &zones {
        let _ = write!(table, "<th>{}</th>", esc(z));
    }
    table.push_str("<th>Share of active accounts</th></tr></thead><tbody>");
    for p in pts {
        let _ = write!(
            table,
            "<tr><td>{}</td><td>{}</td><td>{}</td>",
            run_cell(&p.run),
            p.run.grade().as_str(),
            num(p.hp.tier_zero_exposed)
        );
        for z in &zones {
            let _ = write!(
                table,
                "<td>{}</td>",
                zone_value(p, z, |z| z.exposed).map_or("–".to_string(), num)
            );
        }
        let _ = write!(
            table,
            "<td>{}{}</td></tr>",
            esc(&p.run.headline().share),
            pages::older_basis_mark(p.run.basis())
        );
    }
    table.push_str("</tbody>");
    let mut items: Vec<(&str, String)> = series.iter().map(|s| (s.class, esc(&s.name))).collect();
    if more > 0 {
        items.push(("none", more_zones(more)));
    }
    let mut notes: Vec<String> = Vec::new();
    for s in series.iter().skip(1) {
        if let Some(i) = s.values.iter().position(|v| v.is_some()).filter(|&i| i > 0) {
            notes.push(format!(
                "{} is charted from {}: runs before didn't record the accounts per zone.",
                esc(&s.name),
                pages::time_as(pts[i].hp.at, "day")
            ));
        }
    }
    Figure {
        class: "pv-tiers",
        title,
        tip_id: "c-tiers",
        definition: "For each tier, the enabled users and computers outside it (and outside Tier Zero) with a path into it. Log scale: each step up is ten times more, so a drop from thousands to tens stays visible. A run marked not targeted did not read sessions or local groups, so it counts fewer paths.",
        sub: "Enabled users and computers outside each tier with a path into it, per run. Lower is better.",
        legend: &legend(&items),
        extra: &extra,
        svg: &svgs,
        note: &notes.join(" "),
        table: &table,
    }
    .render()
}

const PLAN_DEF: &str =
    "The fewest changes that cut every attack path to Tier Zero, the one that cuts the most first.";
const PLAN_SUB: &str = "How many steps the remediation path needs to cut every attack path to Tier Zero: the size of the job left.";

fn plan_chart(pts: &[Point]) -> String {
    let n = pts.len();
    let note = starts_note(pts, |p| p.hp.plan.is_some(), "the remediation plan");
    if pts.iter().all(|p| p.hp.plan.is_none()) {
        return empty_figure("pv-plan", "Plan steps", "c-plan", PLAN_DEF, PLAN_SUB, &note);
    }
    let (mut s, mut axis) = (String::new(), String::new());
    let max = pts
        .iter()
        .filter_map(|p| p.hp.plan.map(|pl| pl.steps))
        .max()
        .unwrap_or(0);
    let scale = Scale::linear(max);
    scale.grid(&mut s, &mut axis);
    x_labels(&mut s, pts, MT + plot_h());
    let bw = (slot_w(n) * 0.56).min(46.0);
    let first = pts.iter().position(|p| p.hp.plan.is_some());
    let last = pts.iter().rposition(|p| p.hp.plan.is_some());
    let mut table = String::from(
        "<thead><tr><th>Run</th><th>Plan steps</th><th>Accounts left after them</th></tr></thead><tbody>",
    );
    for (i, p) in pts.iter().enumerate() {
        let cx = slot_x(i, n);
        match p.hp.plan {
            Some(pl) => {
                let y = scale.y(pl.steps as f64);
                let h = MT + plot_h() - y;
                if pl.steps > 0 {
                    let _ = write!(
                        s,
                        r#"<rect class="pv-bar plan" x="{x:.1}" y="{y:.1}" width="{bw:.1}" height="{h:.1}" rx="3"/>"#,
                        x = cx - bw / 2.0
                    );
                }
                if n <= 16 || Some(i) == first || Some(i) == last {
                    let (tx, end) = val_x(cx);
                    let _ = write!(
                        s,
                        r#"<text class="pv-val{end}" x="{tx:.1}" y="{ty:.1}">{}</text>"#,
                        num(pl.steps),
                        ty = y - 7.0
                    );
                }
                let mut tl = vec![when(p.hp.at), format!("{} plan steps", num(pl.steps))];
                if pl.exposed_after > 0 {
                    tl.push(format!(
                        "{} accounts still reach Tier Zero after them",
                        num(pl.exposed_after)
                    ));
                }
                hit(&mut s, i, n, MT, plot_h(), &p.run, &tl);
                let _ = write!(
                    table,
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    run_cell(&p.run),
                    num(pl.steps),
                    num(pl.exposed_after)
                );
            }
            None => {
                hit(
                    &mut s,
                    i,
                    n,
                    MT,
                    plot_h(),
                    &p.run,
                    &[when(p.hp.at), "Not recorded for this run".into()],
                );
                let _ = write!(
                    table,
                    "<tr><td>{}</td><td>–</td><td>–</td></tr>",
                    run_cell(&p.run)
                );
            }
        }
    }
    table.push_str("</tbody>");
    Figure {
        class: "pv-plan",
        title: "Plan steps",
        tip_id: "c-plan",
        definition: PLAN_DEF,
        sub: PLAN_SUB,
        legend: &legend(&[("plan", "Changes in the plan".into())]),
        extra: "",
        svg: &svg("Plan steps", H, &s, &axis, Axis::Y, ""),
        note: &note,
        table: &table,
    }
    .render()
}

const SEVS: [(&str, &str); 5] = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
];

fn sev_counts(p: &HistoryPoint) -> [usize; 5] {
    let c = &p.findings;
    [c.critical, c.high, c.medium, c.low, c.info]
}

fn findings_chart(pts: &[Point]) -> String {
    let n = pts.len();
    let (mut s, mut axis) = (String::new(), String::new());
    let show_info = pts.iter().any(|p| p.hp.findings.info > 0);
    let max_total = pts.iter().map(|p| open_of(&p.hp)).max().unwrap_or(0);
    let scale = Scale::linear(max_total);
    scale.grid(&mut s, &mut axis);
    x_labels(&mut s, pts, MT + plot_h());
    let bw = (slot_w(n) * 0.56).min(46.0);
    // The attack path findings among them, as a dashed line over the bars.
    let attack = Series {
        name: "Attack path findings".into(),
        class: "attack",
        values: pts
            .iter()
            .map(|p| p.attack_known.then_some(p.hp.findings.attack_path as f64))
            .collect(),
    };
    // The line's first value is labeled above its dot ([`attack_line`]):
    // that bar's total goes above the label.
    let first_attack = attack
        .values
        .iter()
        .enumerate()
        .find_map(|(i, v)| v.map(|v| (i, scale.y(v) - 10.0)));
    for (i, p) in pts.iter().enumerate() {
        let counts = sev_counts(&p.hp);
        let x = slot_x(i, n) - bw / 2.0;
        let mut acc = 0usize;
        // Most severe at the bottom, on the baseline.
        for (k, (class, _)) in SEVS.iter().enumerate() {
            let c = counts[k];
            if c == 0 {
                continue;
            }
            let y_top = scale.y((acc + c) as f64);
            let y_bot = scale.y(acc as f64);
            // A 2px surface gap between stacked segments.
            let h = (y_bot - y_top - if acc > 0 { 2.0 } else { 0.0 }).max(1.0);
            let _ = write!(
                s,
                r#"<rect class="pv-seg {class}" x="{x:.1}" y="{y_top:.1}" width="{bw:.1}" height="{h:.1}" rx="2"/>"#
            );
            acc += c;
        }
        if n <= 16 || i == 0 || i == n - 1 || first_attack.is_some_and(|(f, _)| f == i) {
            let mut ty = scale.y(acc as f64) - 7.0;
            if let Some((_, ay)) = first_attack.filter(|(f, _)| *f == i) {
                ty = ty.min(ay - 16.0).max(MT - 14.0);
            }
            let (cx, end) = val_x(slot_x(i, n));
            let _ = write!(
                s,
                r#"<text class="pv-val{end} halo" x="{cx:.1}" y="{ty:.1}">{acc}</text>"#
            );
        }
    }
    attack_line(&mut s, &attack, n, scale, bw);
    let mut table = String::from("<thead><tr><th>Run</th>");
    for (class, label) in SEVS.iter() {
        if *class == "info" && !show_info {
            continue;
        }
        let _ = write!(table, "<th>{label}</th>");
    }
    table.push_str("<th>Open</th><th>On attack paths</th></tr></thead><tbody>");
    for (i, p) in pts.iter().enumerate() {
        let counts = sev_counts(&p.hp);
        let ap = if p.attack_known {
            num(p.hp.findings.attack_path)
        } else {
            "–".into()
        };
        let mut tl = vec![
            when(p.hp.at),
            format!("{} open findings", num(open_of(&p.hp))),
            format!("{ap} on attack paths"),
        ];
        let _ = write!(table, "<tr><td>{}</td>", run_cell(&p.run));
        for (k, (class, label)) in SEVS.iter().enumerate() {
            if *class == "info" && !show_info {
                continue;
            }
            tl.push(format!("{label} {}", num(counts[k])));
            let _ = write!(table, "<td>{}</td>", num(counts[k]));
        }
        let _ = write!(table, "<td>{}</td><td>{ap}</td></tr>", num(open_of(&p.hp)));
        hit(&mut s, i, n, MT, plot_h(), &p.run, &tl);
    }
    table.push_str("</tbody>");
    let mut items: Vec<(&str, String)> = SEVS
        .iter()
        .filter(|(c, _)| *c != "info" || show_info)
        .map(|(c, l)| (*c, l.to_string()))
        .collect();
    items.push((
        "attack",
        "Attack path findings (dashed line; counted in the bars too)".into(),
    ));
    Figure {
        class: "pv-findings",
        title: "Open findings and attack paths",
        tip_id: "c-findings",
        definition: "Findings not fixed or accepted as a risk, by severity. Attack path findings are the ones on a path to Tier Zero; the rest are hygiene. The line is part of the bars, not added to them.",
        sub: "Open findings by severity (bars, total on top) and the attack path findings among them (dashed line).",
        legend: &legend(&items),
        extra: "",
        svg: &svg("Open findings and attack paths", H, &s, &axis, Axis::Y, ""),
        note: &starts_note(pts, |p| p.attack_known, "their attack path findings"),
        table: &table,
    }
    .render()
}

/// The attack path line over the bars: dashed, its dots ringed, the first
/// value labeled above its dot (off the line, which leaves it to the right;
/// the bar's total moves up for it) and the last right of the last bar,
/// where nothing follows.
fn attack_line(b: &mut String, s: &Series, n: usize, scale: Scale, bw: f64) {
    let mut seg: Vec<String> = Vec::new();
    let flush = |b: &mut String, seg: &mut Vec<String>| {
        if seg.len() > 1 {
            let _ = write!(
                b,
                r#"<polyline class="pv-line attack dashed" points="{}"/>"#,
                seg.join(" ")
            );
        }
        seg.clear();
    };
    for (i, v) in s.values.iter().enumerate() {
        match v {
            Some(v) => seg.push(format!("{:.1},{:.1}", slot_x(i, n), scale.y(*v))),
            None => flush(b, &mut seg),
        }
    }
    flush(b, &mut seg);
    let first = s.values.iter().position(|v| v.is_some());
    let last = s.values.iter().rposition(|v| v.is_some());
    for (i, v) in s.values.iter().enumerate() {
        let Some(v) = v else { continue };
        let (x, y) = (slot_x(i, n), scale.y(*v));
        let _ = write!(
            b,
            r#"<circle class="pv-dot attack" cx="{x:.1}" cy="{y:.1}" r="4"/>"#
        );
        if Some(i) == last && first != last {
            let _ = write!(
                b,
                r#"<text class="pv-val end halo" x="{:.1}" y="{:.1}">{}</text>"#,
                x + bw / 2.0 + 4.0,
                y + 4.0,
                count_fmt(*v)
            );
        } else if Some(i) == first {
            let (tx, end) = val_x(x);
            let _ = write!(
                b,
                r#"<text class="pv-val{end} halo" x="{tx:.1}" y="{:.1}">{}</text>"#,
                y - 10.0,
                count_fmt(*v)
            );
        }
    }
}

/// Objects per tier: the row names' column, in chart units.
const ROWS_LEFT: f64 = 190.0;

const OBJECTS_DEF: &str = "The objects each tier protects. Tier Zero objects are never counted in a zone: the highest tier wins.";
const OBJECTS_SUB: &str = "What each tier protects, per run, each row on its own scale. An object in Tier Zero counts there only.";

/// Objects per tier: one row per tier (Tier Zero and the zones the
/// accounts chart draws, [`charted_zones`]), each on its own scale, the
/// first and last count labeled. Rows no run recorded are left out.
fn objects_chart(pts: &[Point]) -> String {
    let n = pts.len();
    let (zones, more) = charted_zones(pts);
    let mut rows: Vec<Series> = vec![Series {
        name: "Tier Zero".into(),
        class: SERIES[0],
        // 0 objects: not recorded (a local run saved without its event).
        values: pts
            .iter()
            .map(|p| (p.hp.tier_zero_objects > 0).then_some(p.hp.tier_zero_objects as f64))
            .collect(),
    }];
    for (k, z) in zones.iter().enumerate() {
        rows.push(Series {
            name: z.clone(),
            class: SERIES[k + 1],
            values: pts
                .iter()
                .map(|p| zone_value(p, z, |z| z.objects).map(|v| v as f64))
                .collect(),
        });
    }
    rows.retain(|r| r.values.iter().any(Option::is_some));
    if rows.is_empty() {
        return empty_figure(
            "pv-objects",
            "Objects per tier",
            "c-objects",
            OBJECTS_DEF,
            OBJECTS_SUB,
            "No run in this range recorded the objects per tier; runs from this version on do.",
        );
    }
    const ROW: f64 = 64.0;
    let top = 12.0;
    let h = top + ROW * rows.len() as f64 + 40.0;
    // Room after the names for a first count, which sits left of its dot.
    let x0 = ROWS_LEFT + 56.0;
    let x1 = W - MR;
    let xs = |i: usize| x0 + (i as f64 + 0.5) * (x1 - x0) / n as f64;
    let (mut s, mut axis) = (String::new(), String::new());
    let mut table = String::from("<thead><tr><th>Run</th>");
    for r in &rows {
        let _ = write!(table, "<th>{}</th>", esc(&r.name));
    }
    table.push_str("</tr></thead><tbody>");
    for (k, r) in rows.iter().enumerate() {
        let y_top = top + ROW * k as f64;
        let (band_top, band_bot) = (y_top + 12.0, y_top + ROW - 16.0);
        let vals: Vec<f64> = r.values.iter().flatten().copied().collect();
        let lo = vals.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let y = |v: f64| {
            if hi > lo {
                band_bot - (v - lo) / (hi - lo) * (band_bot - band_top)
            } else {
                (band_top + band_bot) / 2.0
            }
        };
        let first = r.values.iter().position(|v| v.is_some());
        let lasti = r.values.iter().rposition(|v| v.is_some());
        let change = match (first, lasti) {
            (Some(f), Some(l)) if f != l => {
                let d = r.values[l].unwrap_or(0.0) - r.values[f].unwrap_or(0.0);
                // The day in the reader's zone, as the axis below shows it
                // (UTC until the script runs).
                let t = pts[f].hp.at;
                let day = format!(
                    r#"<tspan data-unix="{t}" data-fmt="day">{}</tspan>"#,
                    day_time(t).0
                );
                if d == 0.0 {
                    format!("no change since {day}")
                } else {
                    format!(
                        "{}{} since {day}",
                        if d > 0.0 { "+" } else { "−" },
                        num(d.abs() as usize),
                    )
                }
            }
            _ => "one run recorded".into(),
        };
        // Short enough for the column at the phone's larger type.
        let name: String = if r.name.chars().count() > 20 {
            format!("{}…", r.name.chars().take(19).collect::<String>())
        } else {
            r.name.clone()
        };
        let _ = write!(
            s,
            r#"<line class="pv-grid" x1="{x0}" x2="{x1}" y1="{gb:.1}" y2="{gb:.1}"/>"#,
            gb = y_top + ROW - 4.0,
        );
        let _ = write!(
            axis,
            r#"<text class="pv-row" x="8" y="{ny:.1}">{name}</text><text class="pv-row-sub" x="8" y="{sy:.1}">{change}</text>"#,
            ny = y_top + 24.0,
            sy = y_top + 44.0,
            name = esc(&name),
        );
        let mut seg: Vec<String> = Vec::new();
        let flush = |s: &mut String, seg: &mut Vec<String>| {
            if seg.len() > 1 {
                let _ = write!(
                    s,
                    r#"<polyline class="pv-line {}" points="{}"/>"#,
                    r.class,
                    seg.join(" ")
                );
            }
            seg.clear();
        };
        for (i, v) in r.values.iter().enumerate() {
            match v {
                Some(v) => seg.push(format!("{:.1},{:.1}", xs(i), y(*v))),
                None => flush(&mut s, &mut seg),
            }
        }
        flush(&mut s, &mut seg);
        for (i, v) in r.values.iter().enumerate() {
            let Some(v) = v else { continue };
            if Some(i) == first || Some(i) == lasti {
                let _ = write!(
                    s,
                    r#"<circle class="pv-dot {}" cx="{:.1}" cy="{:.1}" r="4"/>"#,
                    r.class,
                    xs(i),
                    y(*v)
                );
            }
        }
        if let Some(l) = lasti {
            let v = r.values[l].unwrap_or(0.0);
            let _ = write!(
                s,
                r#"<text class="pv-val end halo" x="{:.1}" y="{:.1}">{}</text>"#,
                xs(l) + 8.0,
                y(v) + 4.0,
                count_fmt(v)
            );
        }
        if let Some(f) = first.filter(|f| Some(*f) != lasti) {
            let v = r.values[f].unwrap_or(0.0);
            let _ = write!(
                s,
                r#"<text class="pv-val start halo" x="{:.1}" y="{:.1}">{}</text>"#,
                xs(f) - 8.0,
                y(v) + 4.0,
                count_fmt(v)
            );
        }
    }
    // The run axis under the rows, on the rows' own x positions.
    let every = n.div_ceil(8).max(1);
    let mut last_x = f64::NEG_INFINITY;
    for (i, p) in pts.iter().enumerate() {
        let x = xs(i);
        if (i % every != 0 && i != n - 1)
            || (i != n - 1 && (x - last_x < 60.0 || xs(n - 1) - x < 60.0))
        {
            continue;
        }
        last_x = x;
        let (d, _) = day_time(p.hp.at);
        let _ = write!(
            s,
            r#"<text class="pv-x" x="{x:.1}" y="{y:.1}" data-unix="{t}" data-fmt="day">{d}</text>"#,
            y = h - 16.0,
            t = p.hp.at,
        );
    }
    // One hover/focus target per run across the rows, with each row's count.
    let slot = (x1 - x0) / n as f64;
    for (i, p) in pts.iter().enumerate() {
        let _ = write!(table, "<tr><td>{}</td>", run_cell(&p.run));
        let mut tl = vec![when(p.hp.at)];
        for r in &rows {
            let v = r.values[i].map(|v| v as usize);
            let _ = write!(table, "<td>{}</td>", v.map_or("–".to_string(), num));
            tl.push(match v {
                Some(v) => format!(
                    "{}: {}",
                    r.name,
                    pathwarden_core::text::count(v, "object", "objects")
                ),
                None => format!("{}: not recorded", r.name),
            });
        }
        table.push_str("</tr>");
        hit_at(
            &mut s,
            (xs(i) - slot / 2.0, slot),
            (top, ROW * rows.len() as f64),
            &p.run,
            &tl,
        );
    }
    table.push_str("</tbody>");
    let mut items: Vec<(&str, String)> = rows.iter().map(|r| (r.class, esc(&r.name))).collect();
    if more > 0 {
        items.push(("none", more_zones(more)));
    }
    let note = if rows.len() > 1 {
        starts_note(
            pts,
            |p| p.hp.zones.iter().any(|z| z.objects.is_some()),
            "the objects per zone",
        )
    } else {
        String::new()
    };
    Figure {
        class: "pv-objects",
        title: "Objects per tier",
        tip_id: "c-objects",
        definition: OBJECTS_DEF,
        sub: OBJECTS_SUB,
        legend: &legend(&items),
        extra: "",
        svg: &svg("Objects per tier", h, &s, &axis, Axis::Rows, ""),
        note: &note,
        table: &table,
    }
    .render()
}

/// Collection completeness: sessions and local groups, 0 to 100%, with
/// the runs below [`LOW_PERCENT`] (or with a domain below it) shaded.
const COMPLETE_DEF: &str = "The share of computers whose sessions, and of member computers whose local groups, were collected. Paths through logged-on sessions and local administrator rights are only as complete as these; below 80% the counts above can read low. A run marked not targeted did not ask the collector to read them.";

/// What a point's run did not target (nothing, when it doesn't say).
fn untargeted(p: &Point) -> pathwarden_core::posture::Untargeted {
    since::untargeted(&p.hp)
}

/// The runs that did not target sessions (a Quick run), in contiguous
/// groups: the middle of each group's slots.
fn untargeted_groups(pts: &[Point]) -> Vec<f64> {
    let n = pts.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if !untargeted(&pts[i]).any() {
            i += 1;
            continue;
        }
        let j = (i..n).find(|&k| !untargeted(&pts[k]).any()).unwrap_or(n);
        out.push((slot_x(i, n) + slot_x(j - 1, n)) / 2.0);
        i = j;
    }
    out
}

/// A muted "not targeted" over each group of such runs, at `y`.
fn untargeted_labels(b: &mut String, pts: &[Point], y: f64) {
    for x in untargeted_groups(pts) {
        let _ = write!(
            b,
            r#"<text class="pv-nt" x="{x:.1}" y="{y:.1}">not targeted</text>"#
        );
    }
}

/// The tooltip line of a run that did not target sessions or local
/// groups: "Sessions and local groups not targeted".
fn untargeted_tip(p: &Point) -> Option<String> {
    let chip = untargeted(p).chip()?;
    let mut c = chip.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
}

const COMPLETE_SUB: &str = "Share of computers whose sessions and local groups were collected. Where it dips, paths may be missing and the counts above read low.";

fn completeness_chart(pts: &[Point]) -> String {
    let n = pts.len();
    let note = starts_note(
        pts,
        |p| p.hp.completeness.is_some(),
        "collection completeness",
    );
    if pts.iter().all(|p| p.hp.completeness.is_none()) {
        return empty_figure(
            "pv-complete",
            "Collection completeness",
            "c-complete",
            COMPLETE_DEF,
            COMPLETE_SUB,
            &note,
        );
    }
    let pct_scale = |v: f64| MT + plot_h() * (1.0 - v.clamp(0.0, 100.0) / 100.0);
    let (mut s, mut axis) = (String::new(), String::new());
    // Shaded runs first, under everything: contiguous runs as one band.
    // A part the run did not target is not low: it has no figure.
    let low: Vec<bool> = pts
        .iter()
        .map(|p| {
            p.hp.completeness.as_ref().is_some_and(|c| {
                let u = c.untargeted();
                !u.sessions && c.sessions_percent < LOW_PERCENT
                    || !u.local_groups && c.local_groups_percent.is_some_and(|g| g < LOW_PERCENT)
                    || c.low_domains > 0
            })
        })
        .collect();
    let mut bands: Vec<(f64, f64)> = Vec::new();
    let mut i = 0;
    while i < n {
        if !low[i] {
            i += 1;
            continue;
        }
        let j = (i..n).find(|&k| !low[k]).unwrap_or(n);
        let x = slot_x(i, n) - slot_w(n) / 2.0;
        let w = slot_w(n) * (j - i) as f64;
        let _ = write!(
            s,
            r#"<rect class="pv-low" x="{x:.1}" y="{MT}" width="{w:.1}" height="{h:.1}"/>"#,
            h = plot_h(),
        );
        bands.push((x, x + w));
        i = j;
    }
    // "counts may be low" at the top of the bands, centred on each and kept in the
    // chart; bands closer than a label's width share one, centred on them.
    // The width is the phone's, where the type is largest in chart units.
    const LOW_W: f64 = 170.0;
    let mut groups: Vec<(f64, f64)> = Vec::new();
    for (a, z) in bands {
        match groups.last_mut() {
            Some(g) if a - g.1 < LOW_W => g.1 = z,
            _ => groups.push((a, z)),
        }
    }
    // The first values sit up there too when they are high: clear of them.
    let first_high = pts
        .iter()
        .find_map(|p| p.hp.completeness.as_ref())
        .is_some_and(|c| {
            let u = c.untargeted();
            !u.sessions && c.sessions_percent >= 85.0
                || !u.local_groups && c.local_groups_percent.is_some_and(|g| g >= 85.0)
        });
    let left = if first_high {
        slot_x(0, n).max(ML + 30.0) + 50.0
    } else {
        ML
    };
    // Left to right, each after the one before and still over its band;
    // one with no room there goes without (the shading and the legend
    // say it), unless no band has a label yet.
    let mut from = left;
    let mut placed = Vec::new();
    for (a, z) in &groups {
        let cx = ((a + z) / 2.0)
            .max(from + LOW_W / 2.0)
            .min(W - MR - LOW_W / 2.0);
        if cx - LOW_W / 2.0 < from - 0.5 || cx - LOW_W / 2.0 > *z || cx + LOW_W / 2.0 < *a {
            continue;
        }
        placed.push(cx);
        from = cx + LOW_W / 2.0 + 8.0;
    }
    if placed.is_empty() {
        if let Some((a, z)) = groups.first() {
            placed.push(((a + z) / 2.0).clamp(left + LOW_W / 2.0, W - MR - LOW_W / 2.0));
        }
    }
    for cx in placed {
        let _ = write!(
            s,
            r#"<text class="pv-low-label" x="{cx:.1}" y="{ty:.1}">counts may be low</text>"#,
            // Inside the band, under the 100% line, so it never sits on it.
            ty = MT + 14.0,
        );
    }
    for v in [0.0, 25.0, 50.0, 75.0, 100.0] {
        let _ = write!(
            s,
            r#"<line class="pv-grid{base}" x1="{ML}" x2="{x2}" y1="{y:.1}" y2="{y:.1}"/>"#,
            base = if v == 0.0 { " base" } else { "" },
            x2 = W - MR,
            y = pct_scale(v),
        );
        y_label(&mut axis, pct_scale(v), &format!("{v}%"));
    }
    x_labels(&mut s, pts, MT + plot_h());
    // A run that did not target a part has no point for it: the line ends
    // at the last run that did, and the slot says "not targeted".
    untargeted_labels(&mut s, pts, MT + plot_h() * 0.5);
    let series = [
        Series {
            name: "Sessions".into(),
            class: "sess",
            values: pts
                .iter()
                .map(|p| {
                    p.hp.completeness
                        .as_ref()
                        .filter(|c| !c.untargeted().sessions)
                        .map(|c| c.sessions_percent)
                })
                .collect(),
        },
        Series {
            name: "Local groups".into(),
            class: "lg",
            values: pts
                .iter()
                .map(|p| {
                    p.hp.completeness
                        .as_ref()
                        .filter(|c| !c.untargeted().local_groups)
                        .and_then(|c| c.local_groups_percent)
                })
                .collect(),
        },
    ];
    // A linear 0-100 scale in the shared drawing: percent as a count.
    lines(
        &mut s,
        &series,
        n,
        Scale::Linear { max: 100, step: 25 },
        &|v| format!("{}%", since::whole_percent(v)),
    );
    let mut table = String::from(
        "<thead><tr><th>Run</th><th>Sessions</th><th>Local groups</th><th>Domains below 80%</th></tr></thead><tbody>",
    );
    for (i, p) in pts.iter().enumerate() {
        let c = p.hp.completeness.as_ref();
        let u = untargeted(p);
        let sess = match c {
            _ if u.sessions => None,
            None => Some("–".to_string()),
            Some(c) => Some(format!("{}%", since::whole_percent(c.sessions_percent))),
        };
        let lg = match c.and_then(|c| c.local_groups_percent) {
            _ if u.local_groups => None,
            None => Some("–".to_string()),
            Some(g) => Some(format!("{}%", since::whole_percent(g))),
        };
        let shown = |v: &Option<String>| v.clone().unwrap_or_else(|| "not targeted".into());
        let mut tl = vec![
            when(p.hp.at),
            format!("Sessions {}", shown(&sess)),
            format!("Local groups {}", shown(&lg)),
        ];
        if low[i] {
            tl.push("Counts may be low".into());
        }
        hit(&mut s, i, n, MT, plot_h(), &p.run, &tl);
        let cell = |v: Option<String>| match v {
            Some(v) => format!("<td>{v}</td>"),
            None => r#"<td class="muted">Not targeted</td>"#.to_string(),
        };
        let _ = write!(
            table,
            "<tr><td>{}</td>{}{}<td>{}</td></tr>",
            run_cell(&p.run),
            cell(sess),
            cell(lg),
            c.map_or("–".to_string(), |c| num(c.low_domains))
        );
    }
    table.push_str("</tbody>");
    Figure {
        class: "pv-complete",
        title: "Collection completeness",
        tip_id: "c-complete",
        definition: COMPLETE_DEF,
        sub: COMPLETE_SUB,
        legend: &legend(&[
            ("sess", "Sessions".into()),
            ("lg", "Local groups".into()),
            ("dip", "Below 80%: counts may be low".into()),
        ]),
        extra: "",
        svg: &svg("Collection completeness", H, &s, &axis, Axis::Y, ""),
        note: &note,
        table: &table,
    }
    .render()
}

/// Every definition on the page, collapsed at the bottom.
const DEFINITIONS: &str = r#"<details class="explain pv-defs"><summary>{info} All definitions</summary><dl>
<div><dt>With an attack path to Tier Zero</dt><dd>Enabled users and computers outside Tier Zero with a full path to it. Each is a way in.</dd></div>
<div><dt>Status</dt><dd>Critical, High, Moderate or Low, from the paths and the open findings, never from a share: any path into Tier Zero keeps it at High or above.</dd></div>
<div><dt>Plan steps</dt><dd>The fewest changes that cut every attack path to Tier Zero, the one that cuts the most first.</dd></div>
<div><dt>Open findings</dt><dd>Findings not fixed or accepted as a risk. Attack path findings are on a path to Tier Zero; hygiene findings are weaknesses not on an attack path.</dd></div>
<div><dt>Tier Zero protected</dt><dd>The share of Tier Zero objects that no open attack path finding leads to.</dd></div>
<div><dt>Accounts with an attack path to each tier</dt><dd>For Tier Zero and each Privilege Zone, the accounts outside it (and outside Tier Zero) with a path into it. Log scale: each step up is ten times more.</dd></div>
<div><dt>Objects per tier</dt><dd>The objects each tier protects. Tier Zero objects are never zone members, so an object counts in the highest tier only.</dd></div>
<div><dt>Collection completeness</dt><dd>The share of computers whose sessions, and of member computers whose local groups, were collected. Below 80% the counts can read low. A run marked not targeted did not ask the collector to read them, as in a Quick collection; its counts are compared only with runs that also didn't.</dd></div>
<div><dt>What changed</dt><dd>The latest run against the run before it in the same environment. Over the time range above, or two days picked: everything net new in it (new findings, findings back after a fix, findings that gained objects, new members of Tier Zero and the zones, new paths into them) and what was fixed. The report's Findings tab names them.</dd></div>
<div><dt>Introduced</dt><dd>First seen by Pathwarden: a change carries the date of the run that found it, not when it was made in the directory. Objects and paths are dated from the first run of this version on.</dd></div>
<div><dt>Time range</dt><dd>The week, month or three months up to the latest run (not up to today). At most the latest 40 runs are charted.</dd></div>
</dl><p class="muted small">More terms in the <a href="https://github.com/marbas207/Pathwarden/blob/main/docs/glossary.md">glossary</a>.</p></details>"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs seconds or hours apart are not "1 day" apart.
    #[test]
    fn elapsed_under_a_day() {
        assert_eq!(elapsed(3), "under an hour");
        assert_eq!(elapsed(5 * 3_600), "5 hours");
        assert_eq!(elapsed(86_400), "1 day");
        assert_eq!(elapsed(20 * 86_400), "3 weeks");
    }

    /// A point added after a newer run is neither the latest run nor
    /// the one the latest is compared with, as in `pathwarden history`.
    #[test]
    fn the_latest_pair_skips_inserted_points() {
        let p = |id: &str, at: i64, inserted: bool| -> HistoryPoint {
            serde_json::from_value(serde_json::json!({
                "version": 1, "run_id": id, "at": at, "collected_at": null,
                "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
                "tier_zero_population": 100, "tier_zero_objects": 1,
                "protection_score": null,
                "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                    "resolved": 0},
                "inserted": inserted,
            }))
            .unwrap()
        };
        let hps = [
            p("r1", 1, false),
            p("r2", 2, false),
            p("r3", 3, true),
            p("r4", 4, false),
        ];
        assert_eq!(latest_pair_of(&hps), (Some(3), Some(1)));
        let hps = [p("r1", 1, false), p("r2", 2, false), p("r3", 3, true)];
        assert_eq!(latest_pair_of(&hps), (Some(1), Some(0)));
    }

    #[test]
    fn nice_axes() {
        assert_eq!(nice(0), (1, 1));
        assert_eq!(nice(15), (15, 5));
        assert_eq!(nice(97), (100, 25));
        assert_eq!(nice(1234), (1500, 500));
    }

    #[test]
    fn labels_and_urls() {
        assert_eq!(
            day_time(1_791_417_600 + 3_600 * 14 + 300),
            ("Oct 8".into(), "2:05 PM".into())
        );
        assert_eq!(urlencode("A.LOCAL,B.LOCAL"), "A.LOCAL%2CB.LOCAL");
    }

    /// Log in decades: 0 on the baseline, 1 one step up, the maximum's
    /// decade at the top.
    #[test]
    fn log_scale_in_decades() {
        let s = Scale::log(8975);
        assert_eq!(s.ticks(), [0, 1, 10, 100, 1000, 10000]);
        assert_eq!(s.frac(0.0), 0.0);
        assert!((s.frac(1.0) - 0.2).abs() < 1e-9);
        assert!((s.frac(10000.0) - 1.0).abs() < 1e-9);
        assert_eq!(Scale::log(1).ticks(), [0, 1]);
    }

    /// Labels closer than the gap are moved apart and stay in the box.
    #[test]
    fn labels_are_spread() {
        let out = spread(&[100.0, 101.0, 50.0], 15.0, 0.0, 200.0);
        assert_eq!(out[2], 50.0);
        assert!(out[1] - out[0] >= 15.0 - 1e-9);
        let out = spread(&[199.0, 200.0], 15.0, 0.0, 200.0);
        assert!(out.iter().all(|y| *y <= 200.0) && (out[1] - out[0]).abs() >= 15.0 - 1e-9);
    }

    /// Spread labels keep the order of their dots: a label never passes
    /// another series' label, so each reads next to its own line. One case
    /// is the review's: two series at 31 and 30 and a third at 12.
    #[test]
    fn spread_labels_keep_the_order_of_their_dots() {
        let scale = Scale::log(120);
        let review: Vec<f64> = [31.0, 30.0, 12.0].iter().map(|v| scale.y(*v)).collect();
        for ys in [
            review,
            vec![60.0, 61.5, 70.0],
            vec![70.0, 61.5, 60.0],
            vec![10.0, 10.0 + OFFSET, 10.0 + 2.0 * OFFSET, 200.0],
            vec![195.0, 199.0, 198.0, 30.0],
            vec![5.0, 0.0, 3.0],
        ] {
            let out = spread(&ys, 19.0, 0.0, 200.0);
            for a in 0..ys.len() {
                for b in 0..ys.len() {
                    if ys[a] < ys[b] {
                        assert!(out[a] < out[b], "{ys:?} -> {out:?}");
                    }
                }
            }
        }
    }

    /// A series on Tier Zero's counts is drawn just under it, not hidden;
    /// apart, each sits on its own value.
    #[test]
    fn coinciding_series_stay_in_view() {
        let series = |values: Vec<Option<f64>>| Series {
            name: String::new(),
            class: "s1",
            values,
        };
        let scale = Scale::Linear { max: 200, step: 50 };
        let ys = series_ys(
            &[
                series(vec![Some(120.0), Some(31.0)]),
                series(vec![Some(118.0), Some(30.0)]),
                series(vec![Some(31.0), None]),
            ],
            scale,
        );
        for i in 0..2 {
            assert!(
                ys[1][i].unwrap() - ys[0][i].unwrap() >= OFFSET - 1e-9,
                "{ys:?}"
            );
        }
        assert_eq!(ys[2][1], None);
        // Not on anything at the first run: exactly on its value.
        assert!((ys[2][0].unwrap() - scale.y(31.0)).abs() < 1e-9, "{ys:?}");
        // A slightly higher value stays above.
        let ys = series_ys(
            &[series(vec![Some(100.0)]), series(vec![Some(101.0)])],
            scale,
        );
        assert!(
            ys[0][0].unwrap() - ys[1][0].unwrap() >= OFFSET - 1e-9,
            "{ys:?}"
        );
    }
}
