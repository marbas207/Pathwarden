//! One run history for the UI and the CLI.
//!
//! `pathwarden run` keeps its history in the state ([`Store`]): which
//! findings exist since when (`findings.json`), the last run, and one point
//! per run (`history/<run>.json`). The UI reads and writes the same state:
//!
//! - **Where**: `pathwarden ui --state DIR`, else `[state]` in the
//!   workspace's `pathwarden.toml` (a relative `path` is taken from the
//!   workspace folder, where that file lives, as the scheduled task takes it
//!   from its own folder), else `pathwarden-state` in the workspace.
//! - **Recording**: every analysis started here (the demo excepted) is
//!   compared with the state and recorded exactly as `pathwarden run` records
//!   one ([`pathwarden_core::record::prepare`]), under the same lock, with a
//!   pull before and a commit and push after when the state is a git
//!   repository. The UI run keeps its own folder (report, explore data); its
//!   summary names the history's run ID. When recording isn't possible (the
//!   lock is held, the repository can't be reached), the run is saved
//!   anyway, marked "local only" with the reason.
//! - **Reading**: Progress charts the history's points; Runs lists runs the
//!   CLI or a schedule recorded next to the UI's own. Reading never touches
//!   the network: a git-backed history is brought up to date by recording,
//!   by the app's pulls while it is open ([`crate::auto_pull`]), or by
//!   Sync now on the History storage page.
//! - **Earlier UI runs** (from before the UI recorded runs) are never
//!   rewritten silently: the History storage page offers to import them in
//!   order, or to keep them local only.

use std::collections::HashSet;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{self, HeaderValue};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::analyze::{Analysis, Evaluated};
use pathwarden_core::config::{Config, StateBackend};
use pathwarden_core::history::ReportHistory;
use pathwarden_core::posture::FindingCounts;
use pathwarden_core::record::{self, by, import, RecordProgress};
use pathwarden_core::state::{self, HistoryPoint, LastRun};
use pathwarden_core::store::{self, Store};
use serde::{Deserialize, Serialize};

use crate::pages::{self, esc, icon, num, Nav};
use crate::run_data;
use crate::server::AppState;
use crate::workspace::{HistoryLink, RunSummary, Workspace};

type Shared = Arc<AppState>;

/// The button that syncs a git history now (pushes what waits here, then
/// pulls), on History storage, and as the docs and the Schedule page name
/// it.
pub const SYNC_NOW: &str = "Sync now";

/// The history folder when nothing else is configured, in the workspace.
pub const DEFAULT_FOLDER: &str = "pathwarden-state";

/// UI runs the user chose to keep out of the history (in the workspace).
pub const KEPT_LOCAL_FILE: &str = "history-local.json";

/// The report the generated nightly scripts write, next to the state folder.
const SCHEDULED_REPORT: &str = "reports/latest.html";

/// A recorded run with no history of its own is at most this old before the
/// Schedule page warns that the schedule may have stopped.
pub const STALE_SCHEDULE_SECS: i64 = 36 * 3600;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/automate/history", get(page))
        .route("/history/report", get(scheduled_report_page))
        .route("/api/history/import", post(import_api))
        .route("/api/history/keep-local", post(keep_local_api))
        .route("/api/history/refresh", post(refresh_api))
        .route("/api/history/accept", post(accept_api))
        .route("/api/history/sign-in", post(crate::sign_in::api))
        .route("/api/history/since", get(since_api))
}

// ------------------------------------------------------------- location

/// Where the history location comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `pathwarden ui --state DIR`.
    Flag,
    /// `[state]` in the workspace's `pathwarden.toml`.
    Config,
    /// Nothing configured: `pathwarden-state` in the workspace.
    Default,
}

/// The history in use.
pub struct Location {
    pub store: Store,
    pub dir: PathBuf,
    pub origin: Origin,
    /// Remote (credentials hidden) and branch, for git.
    pub git: Option<(String, String)>,
    /// Git: commit and push recorded runs (`[state] push`).
    pub push: bool,
}

impl Location {
    /// Whether analyses started here are recorded. A git history with
    /// pushing off is only read: a run committed but not pushed would be
    /// thrown away by the next pull.
    pub fn records(&self) -> bool {
        self.git.is_none() || self.push
    }

    /// "a folder" or "a git repository", for sentences.
    pub fn kind(&self) -> &'static str {
        if self.git.is_some() {
            "a git repository"
        } else {
            "a folder"
        }
    }
}

/// The history the workspace's config (or `--state`) points at.
pub fn locate(ws: &Workspace, flag: Option<&Path>) -> Result<Location, String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    locate_with(ws, flag, &config)
}

pub fn locate_with(
    ws: &Workspace,
    flag: Option<&Path>,
    config: &Config,
) -> Result<Location, String> {
    let s = &config.state;
    let configured = s.path.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let (dir, origin) = match (flag, configured) {
        (Some(d), _) => (d.to_path_buf(), Origin::Flag),
        (None, Some(p)) => {
            let p = PathBuf::from(p);
            let dir = if p.is_absolute() {
                p
            } else {
                ws.env_dir().join(p)
            };
            (dir, Origin::Config)
        }
        (None, None) => (
            ws.env_dir().join(DEFAULT_FOLDER),
            if s.backend == StateBackend::Git {
                Origin::Config
            } else {
                Origin::Default
            },
        ),
    };
    // The config's own folder (not `ui --state`): its `[state] encrypted`
    // speaks for it.
    let store = if origin == Origin::Flag {
        Store::new(s, Some(&dir))
    } else {
        Store::new_configured(s, &dir)
    }
    .map_err(|e| format!("{e:#}"))?
    .with_config_file(ws.config_path());
    Ok(Location {
        git: store.remote(),
        push: s.pushes(),
        store,
        dir,
        origin,
    })
}

// ----------------------------------------------------------------- words

// What the History storage page and `pathwarden history storage show` say,
// in plain text with code in backticks (the page shows it as code).

/// The labels of the In use facts, on the page and in `pathwarden history
/// storage show`.
pub mod label {
    pub const WHERE: &str = "Where";
    pub const SET_BY: &str = "Set by";
    pub const RECORDED: &str = "Runs recorded";
    pub const RECORDS: &str = "Analyses started in the app";
    pub const ENCRYPTION: &str = "Encryption";
    /// What the history keeps (`[state] keep`).
    pub const KEEPS: &str = "What it keeps";
    /// How many full runs it keeps (the Full runs and settings card).
    pub const KEEP_LATEST: &str = "Keep the latest";
    /// The full runs' file limit (the same card).
    pub const FILE_LIMIT: &str = "Largest file";
    /// How many of its runs open in full here
    /// ([`crate::run_list::full_runs_words`]).
    pub const FULL_RUNS: &str = "Full runs";
    /// How often the app syncs a git history (`[state] refresh`).
    pub const SYNCS: &str = "Syncs";
    /// How the last sync went ([`crate::last_pull`]).
    pub const LAST_SYNC: &str = "Last sync";
}

/// Whether the history is encrypted, and whether this computer keeps its
/// passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    Off,
    /// On; where this computer has the passphrase from, if anywhere.
    On(Option<pathwarden_core::keystore::Source>),
    /// The marker can't be used (damaged, or from a newer version).
    Problem(String),
}

impl Encryption {
    pub fn of(loc: &Location) -> Encryption {
        use pathwarden_core::crypt;
        match crypt::marker(&loc.dir) {
            Ok(None) => Encryption::Off,
            Ok(Some(_)) => {
                // Given in this process (the app's Runs card), the
                // environment variable, or this computer's store.
                let here = crypt::passphrase_for(&loc.dir)
                    .ok()
                    .flatten()
                    .map(|(_, source)| source);
                Encryption::On(here)
            }
            Err(e) => Encryption::Problem(format!("{e:#}")),
        }
    }

    /// For JSON: "off", "on", "problem".
    pub fn key(&self) -> &'static str {
        match self {
            Encryption::Off => "off",
            Encryption::On(_) => "on",
            Encryption::Problem(_) => "problem",
        }
    }
}

/// "On (passphrase stored on this computer)", "Off", ...
pub fn encryption_words(e: &Encryption) -> String {
    use pathwarden_core::keystore::Source;
    match e {
        Encryption::Off => "Off: the files are plain JSON.".into(),
        Encryption::On(None) => "On (passphrase not stored here).".into(),
        Encryption::On(Some(Source::Env)) => format!(
            "On (passphrase from {}).",
            pathwarden_core::keystore::ENV_VAR
        ),
        Encryption::On(Some(_)) => "On (passphrase stored on this computer).".into(),
        Encryption::Problem(p) => format!("On, but it can't be used: {p}"),
    }
}

/// Where the history is, as text and code (`true`) in turn. A URL or folder
/// may hold a backtick, so the parts are kept apart rather than marked.
pub fn where_parts(loc: &Location) -> Vec<(String, bool)> {
    let dir = loc.dir.display().to_string();
    match &loc.git {
        Some((remote, branch)) => vec![
            ("A git repository: ".into(), false),
            (remote.clone(), true),
            (", branch ".into(), false),
            (branch.clone(), true),
            (", checked out in ".into(), false),
            (dir, true),
        ],
        None => vec![("A folder: ".into(), false), (dir, true)],
    }
}

/// [`where_parts`] as one line, code in backticks, for the terminal.
pub fn where_words(loc: &Location) -> String {
    where_parts(loc)
        .into_iter()
        .map(|(s, code)| if code { format!("`{s}`") } else { s })
        .collect()
}

/// After a pull of `loc` (its lock held): brings the shared settings of
/// `ws` and the repository's together, as on every pull
/// ([`pathwarden_core::settings_sync::after_pull`]), when the history
/// shares them. A note for the user, if there is something to say: in the
/// pages' words when `page`, else the command line's.
pub fn sync_settings(ws: &Workspace, loc: &Location, page: bool) -> Option<String> {
    sync_settings_of(&ws.config_path(), Some(&ws.env_name()), loc, page)
}

/// [`sync_settings`] for the `pathwarden.toml` at `config_path`.
pub fn sync_settings_of(
    config_path: &Path,
    env_name: Option<&str>,
    loc: &Location,
    page: bool,
) -> Option<String> {
    sync_settings_detail(config_path, env_name, loc, page).0
}

/// [`sync_settings_of`]: the note, the sections applied here (by key),
/// and whether some section waits for a choice.
pub fn sync_settings_detail(
    config_path: &Path,
    env_name: Option<&str>,
    loc: &Location,
    page: bool,
) -> (Option<String>, Vec<&'static str>, bool) {
    use pathwarden_core::settings_sync;
    let Some(config) = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|text| pathwarden_core::config_edit::check(&text).ok())
    else {
        return Default::default();
    };
    if settings_sync::inactive(&config.state).is_some() {
        return Default::default();
    }
    let place = settings_sync::Place {
        store: &loc.store,
        config_path,
        pushes: loc.push,
        env_name,
    };
    let d = settings_sync::after_pull_detail(&place);
    (
        d.note.map(|n| if page { n.page } else { n.text }),
        d.applied,
        d.conflict,
    )
}

/// Under "What it keeps" on History storage: what the level holds here.
fn keep_sub(keep: pathwarden_core::config::Keep, git: bool) -> &'static str {
    match (keep, git) {
        (pathwarden_core::config::Keep::Names, _) => {
            "IDs, rules, severities and dates, plus each finding's title (which names the accounts, groups and computers it is about) and its domain. No shared settings."
        }
        (pathwarden_core::config::Keep::Full, true) => {
            "Each run in full, with names, plus shared settings and accepted risks."
        }
        (pathwarden_core::config::Keep::Full, false) => {
            "Each run in full, with names. Settings are shared only through a git repository."
        }
    }
}

/// What the history keeps (`[state] keep`), in words.
pub fn keep_words(keep: pathwarden_core::config::Keep) -> &'static str {
    keep.description()
}

/// What set the location. `--state` is the UI's for the session, the
/// CLI's for the command.
pub fn origin_words(origin: Origin, cli: bool) -> &'static str {
    match (origin, cli) {
        (Origin::Flag, false) => "The folder this session was started with. The form below changes `pathwarden.toml`, which scheduled runs use; this session keeps using its folder.",
        (Origin::Flag, true) => "`--state`, for this command. `pathwarden history storage set` changes `pathwarden.toml`, which scheduled runs and the app use.",
        (Origin::Config, false) => "Set in this environment's settings. A relative folder is taken from Pathwarden's folder on this computer, and from the task's folder on a server.",
        (Origin::Config, true) => "`[state]` in `pathwarden.toml`. A relative folder is taken from the workspace here, and from the task's folder on a server.",
        (Origin::Default, false) => "The default: nothing is set, so the run history is kept in Pathwarden's folder on this computer.",
        (Origin::Default, true) => "The default: nothing is set in `pathwarden.toml`, so the history lives in the workspace.",
    }
}

/// Whether analyses started in the app are recorded.
pub fn records_words(loc: &Location) -> &'static str {
    if loc.records() {
        "Recorded in this run history, like scheduled runs. The demo never is."
    } else {
        "Kept on this computer only: syncing out is turned off, so this computer only reads the run history."
    }
}

/// How many runs the history has: "3 runs, the latest {when} · {by}";
/// `when` formats a time.
pub fn recorded_words(h: &History, when: impl Fn(i64) -> String) -> String {
    match h.latest() {
        Some(p) => format!(
            "{}, the latest {} · {}",
            pathwarden_core::text::count(h.points.len(), "run", "runs"),
            when(p.at),
            recorded_by_words(p)
        ),
        None => "None yet.".into(),
    }
}

/// Analyses too old to import, in words.
pub fn too_old_words(n: usize) -> String {
    let one = n == 1;
    format!(
        "{} older {} from before the history's latest run can't be added in order, so {} local only. {} still {} from Runs.",
        num(n),
        if one { "run" } else { "runs" },
        if one { "it stays" } else { "they stay" },
        if one { "It" } else { "They" },
        if one { "opens" } else { "open" },
    )
}

/// Refused by [`import`] when pushing is off.
pub const NO_PUSH_IMPORT: &str =
    "Pushing is turned off for this history, so nothing can be added to it from here.";

// --------------------------------------------------------------- reading

/// The history as it is on disk now (no pull).
#[derive(Default)]
pub struct History {
    /// Oldest first.
    pub points: Vec<HistoryPoint>,
    pub last: Option<LastRun>,
    /// Why the history couldn't be read.
    pub problem: Option<String>,
}

impl History {
    pub fn ids(&self) -> HashSet<&str> {
        self.points.iter().map(|p| p.run_id.as_str()).collect()
    }

    /// The latest run: never a point added after a newer run
    /// ([`pathwarden_core::since::latest_point`]).
    pub fn latest(&self) -> Option<&HistoryPoint> {
        pathwarden_core::since::latest_point(&self.points)
    }

    /// Runs the schedule recorded, oldest first.
    pub fn scheduled(&self) -> impl Iterator<Item = &HistoryPoint> {
        self.points
            .iter()
            .filter(|p| p.recorded_by.as_deref() == Some(by::SCHEDULE))
    }
}

/// Points recorded by 0.1.1 and earlier get the scopes a later point of the
/// same collection has ([`state::migrate_points`]), so they are charted and
/// compared with it. Only in memory: the files stay as they are.
pub fn read(loc: &Location) -> History {
    // What a run refuses, the pages refuse too.
    if let Err(e) = loc.store.check_expected() {
        return History {
            points: Vec::new(),
            last: None,
            problem: Some(format!("{e:#}")),
        };
    }
    let last = store::last_run(&loc.store);
    match pathwarden_core::history::load(&loc.dir) {
        Ok((mut points, _)) => {
            state::migrate_points(&mut points);
            History {
                points,
                last,
                problem: None,
            }
        }
        Err(e) => History {
            points: Vec::new(),
            last,
            problem: Some(e),
        },
    }
}

/// The run IDs of the points of `ws`'s history, by their file names
/// (nothing is read or decrypted), for the sidebar's count of runs
/// ([`crate::run_list::row_count`]): none when [`read`] would list none
/// (the history refused, or encrypted with no passphrase here).
///
/// Every page's sidebar asks, so the points aren't read: the Runs list's
/// [`read`] opens (and, encrypted, decrypts) every one, and nothing keeps
/// it between pages. So a point file it skips (one that can't be parsed or
/// decrypted, or holds another run than its name says) is counted here and
/// not listed there; with a history Pathwarden wrote there is none.
/// [`store::check_readable`] reads the key file and hashes it each time;
/// the key it opens is kept in this process ([`pathwarden_core::crypt`]),
/// so only a history this computer has no passphrase for looks for one
/// again on each page, as History storage's own checks do.
pub fn point_ids(ws: &Workspace, flag: Option<&Path>) -> Vec<String> {
    let Ok(loc) = locate(ws, flag) else {
        return Vec::new();
    };
    if loc.store.check_expected().is_err() || store::check_readable(&loc.dir).is_err() {
        return Vec::new();
    }
    store::list_state_files(&loc.dir, "history")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|rel| {
            rel.strip_prefix("history/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .collect()
}

/// The history in use and its contents, for a page (blocking).
pub struct Snapshot {
    pub location: Result<Location, String>,
    pub history: History,
}

/// Labels set later in the environment ([`crate::workspace::later_labels`])
/// replace the ones the points were recorded with, in memory.
pub fn snapshot(ws: &Workspace, flag: Option<&Path>) -> Snapshot {
    let location = locate(ws, flag);
    let mut history = location.as_ref().map(read).unwrap_or_default();
    let labels = crate::workspace::later_labels(ws);
    if !labels.is_empty() {
        for p in &mut history.points {
            p.label = crate::workspace::point_label(&labels, &p.run_id, p.label.as_deref());
        }
    }
    Snapshot { location, history }
}

impl Snapshot {
    pub fn ids(&self) -> HashSet<&str> {
        self.history.ids()
    }

    /// Whether a UI run is in this history.
    pub fn has(&self, r: &RunSummary) -> bool {
        recorded_id(r).is_some_and(|id| self.history.points.iter().any(|p| p.run_id == id))
    }
}

/// The history run ID a UI run was recorded as, if any.
pub fn recorded_id(r: &RunSummary) -> Option<&str> {
    r.history.as_ref().and_then(|h| h.run_id.as_deref())
}

/// What recorded a history point, in words: the recorded-from words of
/// the Runs page and Run details ([`crate::shared_runs::recorded_words`]),
/// "Recorded from the command line", "Recorded by the schedule", ...
pub fn recorded_by_words(p: &HistoryPoint) -> String {
    match p.recorded_by.as_deref() {
        Some(f @ (by::SCHEDULE | by::CLI | by::UI | by::IMPORT)) => {
            crate::shared_runs::capitalized(&crate::shared_runs::recorded_words(f, None, None))
        }
        _ => "Recorded by a run".into(),
    }
}

/// The environment key of a set of domains: their sorted scope keys.
pub fn scopes_key(domains: &[String]) -> String {
    state::scopes_of(domains).join(",")
}

pub fn point_scopes_key(p: &HistoryPoint) -> String {
    p.scopes.join(",")
}

/// A history point as a run summary, so the charts and the run list can
/// show it like a UI run. Counts come from the point exactly as
/// `pathwarden history` prints them.
pub fn point_summary(p: &HistoryPoint, domains: &[String]) -> RunSummary {
    let c: &FindingCounts = &p.findings;
    RunSummary {
        id: p.run_id.clone(),
        created_at: p.at,
        created_ms: pathwarden_core::state::run_id_to_millis(&p.run_id),
        collected_at: p.collected_at,
        source: recorded_by_words(p),
        demo: false,
        domains: domains.to_vec(),
        trusted_domains: None,
        not_collected: None,
        legacy_domains: false,
        objects: 0,
        files: 0,
        exposure_percent: p.tier_zero_exposure_percent,
        exposed: p.tier_zero_exposed,
        population: p.tier_zero_population,
        // As recorded: 0 in points from before risk scoring, whose denominator was the
        // population ([`RunSummary::relevant_pop`] falls back to it), so the
        // summary keeps the point's basis ([`RunSummary::basis`]).
        relevant_population: p.tier_zero_relevant_population,
        exposure_basis: p.basis(),
        protection_score: p.protection_score,
        critical: c.critical,
        high: c.high,
        medium: c.medium,
        low: c.low,
        info: c.info,
        suppressed: c.suppressed,
        plan_steps: p.plan.map_or(0, |pl| pl.steps),
        exposed_after: p.plan.map(|pl| pl.exposed_after),
        grade: p.tier_zero_grade,
        grade_reason: None,
        status_reason: None,
        exposure_delta: 0.0,
        next_step_delta: None,
        skipped_objects: 0,
        pathwarden: String::new(),
        collection: None,
        history: None,
        next_step: None,
        environment: None,
        env_name: None,
        assigned: None,
        label: p.label.clone(),
        shared: None,
        completeness: p.completeness.clone(),
        tier_zero_lists: false,
        tier_zero_change: false,
        settings_files: Vec::new(),
        settings_folders_unread: 0,
        incomplete_sources: Vec::new(),
        other_sources: None,
    }
}

/// Domain names for a history environment: from a UI run of the same
/// environment, else from the last run's record (which names them), else
/// none. The history itself holds no names by default. A list saved before
/// trusted domains were left out may name more domains than `key`
/// ([`state::migrate_points`]); the names `key` has are taken from it.
pub fn domains_for(key: &str, runs: &[RunSummary], last: Option<&LastRun>) -> Vec<String> {
    let lists = || {
        runs.iter()
            .map(|r| r.domains.as_slice())
            .chain(last.map(|l| l.domains.as_slice()))
    };
    if let Some(d) = lists().find(|d| scopes_key(d) == key) {
        return d.to_vec();
    }
    let wanted: HashSet<&str> = key.split(',').filter(|k| !k.is_empty()).collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    lists()
        .map(|d| {
            d.iter()
                .filter(|n| wanted.contains(state::scope_key(n).as_str()))
                .cloned()
                .collect::<Vec<String>>()
        })
        .find(|picked| state::scopes_of(picked).len() == wanted.len())
        .unwrap_or_default()
}

// ------------------------------------------------------------ recording

/// What [`record_analysis`] records besides the analysis.
pub struct Recording<'a> {
    pub started_ms: i64,
    /// [`by`]: `ui` for the UI, `cli` or `schedule` for `pathwarden
    /// collect --save` and `run --save`.
    pub recorded_by: &'a str,
    /// The run's label, for the history point.
    pub label: Option<&'a str>,
    /// When it finished, for a run dated in the past (the demo's earlier
    /// runs); `None`, now.
    pub finished_at: Option<i64>,
}

/// Records an evaluated analysis in the history, as `pathwarden run` would
/// (blocking: the analysis job's thread). Always returns the finished
/// analysis; the link says whether and where it was recorded. Once it is,
/// its environment's run history comes with it, for the report's trend and
/// "since the last run" ([`pathwarden_core::history::for_report`]).
pub fn record_analysis<P: RecordProgress>(
    ws: &Workspace,
    flag: Option<&Path>,
    config: &Config,
    ev: Evaluated,
    how: &Recording,
    p: &mut P,
) -> (Analysis, HistoryLink, ReportHistory<'static>) {
    let (a, link, earlier, _held) = record_analysis_held(ws, flag, config, ev, how, p);
    (a, link, earlier)
}

/// The history a run was just recorded in, still under the lock it was
/// recorded under: what comes after the point (its full run,
/// [`crate::shared_runs::share_saved`]) goes in before anything else can
/// take the history, as `pathwarden run` does. Dropped, the lock is
/// released.
pub struct Held {
    pub loc: Location,
    _lock: pathwarden_core::store::Lock,
}

/// [`record_analysis`], keeping the history's lock when the run was
/// recorded ([`Held`]).
pub fn record_analysis_held<P: RecordProgress>(
    ws: &Workspace,
    flag: Option<&Path>,
    config: &Config,
    ev: Evaluated,
    how: &Recording,
    p: &mut P,
) -> (Analysis, HistoryLink, ReportHistory<'static>, Option<Held>) {
    let (a, link, held) = record_only(ws, flag, config, ev, how, p);
    let earlier = match (&link.run_id, &held) {
        (Some(run), Some(h)) => pathwarden_core::history::for_report_in(
            &h.loc.store.dir,
            &a.domains,
            pathwarden_core::history::This::Run(run),
        ),
        _ => ReportHistory::default(),
    };
    (a, link, earlier, held)
}

fn record_only<P: RecordProgress>(
    ws: &Workspace,
    flag: Option<&Path>,
    config: &Config,
    ev: Evaluated,
    how: &Recording,
    p: &mut P,
) -> (Analysis, HistoryLink, Option<Held>) {
    let not = |why: String| HistoryLink {
        not_recorded: Some(why),
        ..HistoryLink::default()
    };
    let loc = match locate_with(ws, flag, config) {
        Ok(l) => l,
        Err(e) => {
            return (
                ev.finish(p),
                not(format!("The run history's settings can't be used: {e}")),
                None,
            )
        }
    };
    if !loc.records() {
        return (
            ev.finish(p),
            not("The run history is a git repository with syncing out turned off, so runs started here are only kept on this computer.".into()),
            None,
        );
    }
    // Kept until what follows the point is in ([`Held`]).
    let _lock = match loc.store.lock_waiting(pathwarden_core::settings_sync::lock_wait()) {
        Ok(l) => l,
        Err(e) => {
            return (
                ev.finish(p),
                not(format!(
                    "Another run was recording in the history at the same time ({e:#}). Import this run from History storage when it has finished."
                )),
                None,
            )
        }
    };
    match loc.store.pull() {
        Ok(Some(note)) => p.warn(note),
        Ok(None) => {}
        Err(e) => {
            let said = format!("{e:#}");
            let mut link = not(format!("Couldn't get the latest history: {said}"));
            if pathwarden_core::connect::is_sign_in(&said) {
                link.sign_in = true;
                link.no_helper = pathwarden_core::connect::no_helper(&said, Some(&loc.store.dir));
                link.refused = pathwarden_core::connect::refused(&said);
            }
            return (ev.finish(p), link, None);
        }
    }
    // Settings the repository changed apply from the next analysis.
    if let Some(note) = sync_settings(ws, &loc, true) {
        p.warn(note);
    }
    // Other machines' full runs, as on Pull now.
    let _ = crate::shared_runs::mirror(ws, &loc);
    let previous = match loc.store.load_for_run() {
        Ok((s, damaged)) => {
            if let Some(note) = damaged {
                p.warn(note);
            }
            s
        }
        Err(e) => {
            return (
                ev.finish(p),
                not(format!("Couldn't read the history: {e:#}")),
                None,
            )
        }
    };
    let prev_run = store::last_run(&loc.store);
    let opts = record::Options {
        started_ms: how.started_ms,
        accept_shrink: false,
        recorded_by: how.recorded_by,
        finished_at: how.finished_at,
    };
    let mut prep = record::prepare(prev_run.as_ref(), &previous, ev, config, &opts, p);
    prep.point.label = how.label.map(str::to_string);
    // Another run that pushed first is told in `p`'s warnings.
    let (prep, saved) =
        record::save_and_publish(&loc.store, prep, config, &opts, None, loc.git.is_some(), p);
    let saved = match saved {
        Err(e) => {
            return (
                prep.analysis,
                not(format!("Couldn't save to the history: {e:#}")),
                None,
            )
        }
        Ok(saved) => saved,
    };
    let run_id = prep.run_id().to_string();
    let sign_in = saved
        .unpushed
        .as_ref()
        .is_some_and(|k| pathwarden_core::connect::is_sign_in(&k.detail));
    let no_helper = sign_in
        && saved
            .unpushed
            .as_ref()
            .is_some_and(|k| pathwarden_core::connect::no_helper(&k.detail, Some(&loc.store.dir)));
    let saved_refused = saved
        .unpushed
        .as_ref()
        .is_some_and(|k| pathwarden_core::connect::refused(&k.detail));
    (
        prep.analysis,
        HistoryLink {
            run_id: Some(run_id),
            not_recorded: None,
            warnings: Vec::new(),
            // In the working copy's history, and pushed by the next run.
            unpushed: saved
                .unpushed
                .as_ref()
                .map(|k| k.sentence("This run is recorded")),
            unpushed_detail: saved.unpushed.map(|k| k.detail),
            full_run: None,
            sign_in,
            no_helper,
            refused: sign_in && saved_refused,
            settings_fewer: prep.settings_fewer,
        },
        Some(Held { loc, _lock }),
    )
}

// -------------------------------------------------------------- earlier runs

#[derive(Default, Serialize, Deserialize)]
struct KeptLocal {
    /// UI runs the user chose to keep out of the history.
    #[serde(default)]
    runs: Vec<String>,
}

fn kept_local(ws: &Workspace) -> HashSet<String> {
    std::fs::read_to_string(ws.env_dir().join(KEPT_LOCAL_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<KeptLocal>(&t).ok())
        .map(|k| k.runs.into_iter().collect())
        .unwrap_or_default()
}

/// Keeps UI runs `ids` out of the history for good: the History storage
/// page's "Keep them local only" and `pathwarden history keep-local`.
pub fn keep_local(ws: &Workspace, ids: &[String]) -> Result<(), String> {
    crate::environments::check_listed(ws)?;
    let mut all = kept_local(ws);
    all.extend(ids.iter().cloned());
    let mut runs: Vec<String> = all.into_iter().collect();
    runs.sort();
    let text = serde_json::to_string_pretty(&KeptLocal { runs }).map_err(|e| e.to_string())?;
    pathwarden_core::config_edit::write_atomic(&ws.env_dir().join(KEPT_LOCAL_FILE), &text)
        .map_err(|e| format!("Couldn't save the choice: {e}"))
}

/// UI runs that are not in the history, split into those that can be
/// imported in order (newer than everything in it) and those that can't.
pub struct LocalOnly {
    /// Oldest first.
    pub importable: Vec<RunSummary>,
    /// Older than the history's last run: importing them would replay the
    /// past over newer runs.
    pub too_old: Vec<RunSummary>,
    /// Kept out on purpose.
    pub kept: usize,
}

pub fn local_only(ws: &Workspace, runs: &[RunSummary], snap: &Snapshot) -> LocalOnly {
    let kept = kept_local(ws);
    let last_at = snap.history.latest().map(|p| p.at);
    let mut out = LocalOnly {
        importable: Vec::new(),
        too_old: Vec::new(),
        kept: 0,
    };
    let mut candidates: Vec<&RunSummary> =
        runs.iter().filter(|r| !r.demo && !snap.has(r)).collect();
    candidates.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    for r in candidates {
        if kept.contains(&r.id) {
            out.kept += 1;
        } else if last_at.is_some_and(|t| r.created_at <= t) {
            out.too_old.push(r.clone());
        } else {
            out.importable.push(r.clone());
        }
    }
    out
}

/// Removes run `run_id`'s point from the run history (and pushes, when the
/// history is in git), so Progress and `pathwarden history` stop showing it.
/// The findings state keeps what the run taught it. Returns whether there
/// was a point, and notes for the user (runs an earlier failed push left,
/// a push that failed with the removal committed here). Shared by the
/// app's Delete and `pathwarden history forget`.
pub fn forget(
    ws: &Workspace,
    flag: Option<&Path>,
    run_id: &str,
) -> Result<(bool, Vec<String>), String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    let loc = locate_with(ws, flag, &config)?;
    let _lock = loc
        .store
        .lock_waiting(pathwarden_core::settings_sync::lock_wait())
        .map_err(|e| format!("{e:#}"))?;
    let pulled = loc
        .store
        .pull()
        .map_err(|e| format!("Couldn't get the latest history: {e:#}"))?;
    let (removed, notes) = loc
        .store
        .forget_and_publish(run_id, loc.push)
        .map_err(|e| format!("{e:#}"))?;
    Ok((removed, pulled.into_iter().chain(notes).collect()))
}

/// What hiding a run from the history on a computer that only reads it
/// says.
pub const HIDDEN_WORDS: &str = "Hidden on this computer: this computer only reads the history, \
so the run stays there for everyone else.";

/// What deleting a run removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Deleted {
    /// Its folder in the workspace (report, graph, summary).
    pub folder: bool,
    /// Its point in the run history.
    pub history_point: bool,
    /// About the history, for the user ([`forget`]).
    pub notes: Vec<String>,
}

/// Deletes a run the way the app's Delete does: its point in its
/// environment's run history first (so a history that can't be changed
/// leaves everything in place), then its folder. `run` is the folder ID or
/// the history run ID; `flag` the `--state` override for the environment.
/// A run known only to the history (no folder) loses just its point.
pub fn delete_run(ws: &Workspace, flag: Option<&Path>, run: &str) -> Result<Deleted, String> {
    let folder = if crate::workspace::valid_run_id(run) && ws.summary(run).is_some() {
        Some(run.to_string())
    } else {
        ws.find_run(run)
    };
    let summary = folder.as_deref().and_then(|id| ws.summary(id));
    let run_id = match &summary {
        Some(r) => r.history.as_ref().and_then(|h| h.run_id.clone()),
        None => Some(run.to_string()),
    };
    let scoped = match &summary {
        Some(r) => ws.for_run(r),
        None => ws.clone(),
    };
    // A run loaded from the history, on a computer that doesn't write it:
    // hidden here, and left in the history for everyone else.
    if let (Some(r), Some(id)) = (&summary, &run_id) {
        let reads_only = locate(&scoped, flag).is_ok_and(|l| !l.records());
        if r.shared.is_some() && reads_only {
            crate::shared_runs::hide(&scoped, id)?;
            let folder = ws.delete_run(&r.id).map_err(|e| format!("{e:#}"))?;
            return Ok(Deleted {
                folder,
                history_point: false,
                notes: vec![HIDDEN_WORDS.to_string()],
            });
        }
    }
    let (history_point, notes) = match &run_id {
        Some(id) => forget(&scoped, flag, id).map_err(|e| {
            format!("Not deleted: the run couldn't be removed from the run history ({e}).")
        })?,
        None => (false, Vec::new()),
    };
    let folder = match folder {
        Some(id) => ws.delete_run(&id).map_err(|e| format!("{e:#}"))?,
        None => false,
    };
    Ok(Deleted {
        folder,
        history_point,
        notes,
    })
}

/// Imports the UI's local-only runs that are newer than the history, oldest
/// first, as if each had been recorded when it was analyzed
/// ([`pathwarden_core::record::import`]): the History storage page's
/// "Import them in order" and `pathwarden history import`. Returns how
/// many were imported, and notes for the user (runs an earlier failed push
/// left, a push that failed with the import committed here). Runs saved
/// before the UI kept their findings are skipped (named in the error if
/// nothing could be imported).
pub fn import(ws: &Workspace, flag: Option<&Path>) -> Result<(usize, Vec<String>), String> {
    let config = ws.config().map_err(|e| format!("{e:#}"))?;
    let loc = locate_with(ws, flag, &config)?;
    if !loc.records() {
        return Err(NO_PUSH_IMPORT.into());
    }
    let _lock = loc
        .store
        .lock_waiting(pathwarden_core::settings_sync::lock_wait())
        .map_err(|e| format!("{e:#}"))?;
    let mut notes: Vec<String> = loc
        .store
        .pull()
        .map_err(|e| format!("Couldn't get the latest history: {e:#}"))?
        .into_iter()
        .collect();
    let runs = ws.runs();
    let snap = Snapshot {
        history: read(&loc),
        location: Err(String::new()),
    };
    let lo = local_only(ws, &runs, &snap);
    // Runs whose folder is gone are left out.
    let (todo, items): (Vec<&RunSummary>, Vec<import::ToImport>) = lo
        .importable
        .iter()
        .filter_map(|r| {
            let dir = ws.run_dir(&r.id)?;
            let event = run_data::read_event(&dir)
                .ok()
                .and_then(|b| import::SavedEvent::parse(&b));
            Some((
                r,
                import::ToImport {
                    name: r.environment(),
                    analyzed: analyzed(r),
                    event,
                },
            ))
        })
        .unzip();
    let (ids, published) = import::import_runs(
        &loc.store,
        &config,
        snap.history.last.as_ref(),
        &items,
        loc.git.is_some(),
    )?;
    notes.extend(published);
    let done: Vec<(&RunSummary, String)> = todo
        .into_iter()
        .zip(ids)
        .filter_map(|(r, id)| Some((r, id?)))
        .collect();
    let n = done.len();
    let mut imported = Vec::new();
    for (r, run_id) in done {
        // The summary as saved, not as listed: the list gives runs saved by
        // 0.1.1 the domains of later runs, which must not be written back.
        let Some(mut r) = ws.summary(&r.id) else {
            continue;
        };
        r.history = Some(HistoryLink {
            run_id: Some(run_id.clone()),
            ..HistoryLink::default()
        });
        ws.update_summary(&r).map_err(|e| format!("{e:#}"))?;
        imported.push((r, run_id));
    }
    // With "Full runs and settings", each imported run goes in full too,
    // in one commit after the points'.
    if crate::shared_runs::wanted(&config) && !imported.is_empty() {
        notes.extend(share_imported(ws, &loc, &config, &mut imported));
    }
    Ok((n, notes))
}

/// The full runs of runs [`import`] just added, published under its lock;
/// each run's summary says how it went. Notes for the user.
fn share_imported(
    ws: &Workspace,
    loc: &Location,
    config: &Config,
    imported: &mut [(RunSummary, String)],
) -> Vec<String> {
    use crate::shared_runs::{self, Bundle, FullRunLink, FullRunState};
    // No settings.toml: the settings now may not be the ones an earlier
    // analysis was made with.
    let mut bundles = Vec::new();
    let mut failed: Vec<(usize, String)> = Vec::new();
    for (i, (r, run_id)) in imported.iter().enumerate() {
        match ws
            .run_dir(&r.id)
            .ok_or_else(|| "its folder is gone".to_string())
            .and_then(|dir| {
                Bundle::from_run_dir(
                    &dir,
                    r,
                    run_id,
                    None,
                    &shared_runs::recorded_from_point(&loc.store, run_id, by::IMPORT),
                    shared_runs::file_limit(&config.state, &loc.store),
                )
            }) {
            Ok(b) => bundles.push(b),
            Err(why) => failed.push((i, why)),
        }
    }
    let published = shared_runs::publish(
        &loc.store,
        &bundles,
        config.state.full_runs_kept(),
        loc.push,
    );
    let mut notes = Vec::new();
    for (i, (r, run_id)) in imported.iter_mut().enumerate() {
        let link = match failed.iter().find(|(j, _)| *j == i) {
            Some((_, why)) => FullRunLink {
                state: FullRunState::NotShared,
                why: Some(why.clone()),
                left_out: Vec::new(),
            },
            None => {
                let mut l = shared_runs::link_for(run_id, &published);
                if let Some(b) = bundles.iter().find(|b| b.run_id() == run_id) {
                    l.left_out = b
                        .manifest
                        .left_out
                        .iter()
                        .map(shared_runs::LeftOut::words)
                        .collect();
                }
                l
            }
        };
        if let Some(h) = r.history.as_mut() {
            h.full_run = Some(link);
        }
        let _ = ws.update_summary(r);
    }
    match &published {
        Ok(p) => {
            notes.extend(p.notes.iter().cloned());
            if let Some(k) = &p.unpushed {
                notes.push(k.sentence("The imported runs' full runs are committed"));
            }
        }
        Err(e) => notes.push(format!(
            "The imported runs' full runs weren't shared: {e:#}"
        )),
    }
    if !failed.is_empty() {
        notes.push(format!(
            "{} couldn't go in full: {}.",
            pathwarden_core::text::count(failed.len(), "imported run", "imported runs"),
            failed
                .iter()
                .map(|(_, w)| w.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    notes
}

/// What [`import`] takes from a UI run's summary.
pub(crate) fn analyzed(r: &RunSummary) -> import::Analyzed {
    import::Analyzed {
        at: r.created_at,
        collected_at: r.collected_at,
        pathwarden: r.pathwarden.clone(),
        skipped_objects: r.skipped_objects,
        exposure_percent: r.exposure_percent,
        exposed: r.exposed,
        population: r.population,
        // The run's own basis and denominator, as recorded: 0 for a run from
        // before risk scoring (its denominator was the population).
        relevant_population: if r.basis() == 0 {
            0
        } else {
            r.relevant_population
        },
        exposure_basis: r.basis(),
        protection_score: r.protection_score,
        grade: r.grade(),
        plan: r.plan_summary(),
        findings: FindingCounts {
            critical: r.critical,
            high: r.high,
            medium: r.medium,
            low: r.low,
            info: r.info,
            suppressed: r.suppressed,
            ..FindingCounts::default()
        },
        label: r.label.clone(),
    }
}

/// What changed in the latest run of the history since the run before it
/// in its environment, as `pathwarden history --changes --json` prints it
/// ([`pathwarden_core::since::view`]); `None` with no earlier run. The
/// findings state names the findings that changed; unreadable, they are
/// counted only. Blocking.
pub fn since(
    ws: &Workspace,
    flag: Option<&Path>,
) -> Result<Option<pathwarden_core::since::View>, String> {
    let loc = locate(ws, flag)?;
    let h = read(&loc);
    if let Some(e) = h.problem {
        return Err(e);
    }
    let findings = loc.store.load().ok();
    Ok(pathwarden_core::since::view(&h.points, findings.as_ref()))
}

/// Brings a git history up to date (blocking), and with it the shared
/// settings of `ws` ([`sync_settings`]). Returns a note when commits
/// earlier runs couldn't push were dropped ([`Store::pull`]), or about
/// the shared settings.
pub fn refresh(
    ws: Option<&Workspace>,
    loc: &Location,
    page: bool,
) -> Result<Option<String>, String> {
    let (notes, loaded) = refresh_all(ws, loc, page)?;
    let all: Vec<String> = loaded.into_iter().chain(notes).collect();
    Ok((!all.is_empty()).then(|| all.join(" ")))
}

/// [`refresh`], and with a workspace, the history's full runs loaded into
/// it ([`crate::shared_runs::mirror`]): the notes, and what loading said
/// ("2 full runs loaded from the history."), apart.
pub fn refresh_all(
    ws: Option<&Workspace>,
    loc: &Location,
    page: bool,
) -> Result<(Option<String>, Option<String>), String> {
    let by = if page { "pull now" } else { "command line" };
    refresh_detail(
        ws,
        loc,
        page,
        pathwarden_core::settings_sync::lock_wait(),
        by,
        &mut |_| {},
    )
    .map(|p| (p.notes, p.loaded))
    .map_err(PullError::into_message)
}

/// Why [`refresh_detail`] didn't pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullError {
    /// The history's lock is held (a run is recording): nothing was tried.
    Busy(String),
    /// The pull failed (recorded as the last pull).
    Failed(String),
}

impl PullError {
    pub fn into_message(self) -> String {
        match self {
            PullError::Busy(m) | PullError::Failed(m) => m,
        }
    }
}

/// What [`refresh_detail`] brought.
#[derive(Debug, Clone, Default)]
pub struct Pulled {
    /// [`refresh_all`]'s notes and loading words.
    pub notes: Option<String>,
    pub loaded: Option<String>,
    /// Runs the pull brought: new points in the history.
    pub runs: usize,
    /// Shared sections applied here, by key.
    pub sections: Vec<&'static str>,
    /// Runs loaded from the history earlier and removed here now, by
    /// folder ID.
    pub removed: Vec<String>,
    /// Some shared section waits for a choice.
    pub conflict: bool,
    /// Encrypted, with no passphrase here: pulled, nothing loaded.
    pub locked: bool,
    /// Runs recorded here that the sync pushed
    /// ([`crate::shared_runs::waiting_runs`] before and after).
    pub pushed: usize,
    /// It pushed something waiting here (runs, or a settings change).
    pub pushed_any: bool,
}

impl Pulled {
    /// What a sync someone asked for did, after "Synced: ": "pushed 1
    /// run, then pulled: up to date", "up to date", "2 new runs".
    pub fn synced_words(&self) -> String {
        let pulled = if self.runs > 0 {
            pathwarden_core::text::count(self.runs, "new run", "new runs")
        } else {
            "up to date".to_string()
        };
        let pushed = match (self.pushed, self.pushed_any) {
            (0, false) => return pulled,
            (0, true) => "pushed the changes recorded here".to_string(),
            (n, _) => format!("pushed {}", pathwarden_core::text::count(n, "run", "runs")),
        };
        format!("{pushed}, then pulled: {pulled}")
    }
}

/// The run points the history holds, by file.
fn point_files(store: &Store) -> HashSet<String> {
    store
        .list_state_files("history")
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// What a pull someone asked for says when it pushed what was kept here.
pub const KEPT_PUSHED: &str = "Changes recorded here earlier were pushed.";

/// [`refresh_all`], waiting up to `wait` for the history's lock, and what
/// the pull brought. `by` names who pulled in the record of the last pull
/// ([`crate::last_pull`]), which every pull writes, worked or not.
/// `settings_applied` is told the shared sections applied here as soon as
/// they are, before the full runs are loaded: a page loaded from then on
/// shows them, so the app counts them then ([`crate::auto_pull`]).
///
/// An encrypted history this computer has no passphrase for is pulled
/// (the files stay up to date, still encrypted: the pull needs no key) but
/// nothing is loaded from it: its settings and full runs can't be read, so
/// syncing and loading them load nothing and say why.
pub fn refresh_detail(
    ws: Option<&Workspace>,
    loc: &Location,
    page: bool,
    wait: std::time::Duration,
    by: &str,
    settings_applied: &mut dyn FnMut(&[&'static str]),
) -> Result<Pulled, PullError> {
    refresh_detail_busy(ws, loc, page, wait, by, settings_applied, &|| false)
}

/// [`refresh_detail`]; for the app's own pulls (`by` "app"), `busy` says an
/// analysis is running, so nothing waiting is pushed then
/// ([`crate::shared_runs::PullBy`]).
pub fn refresh_detail_busy(
    ws: Option<&Workspace>,
    loc: &Location,
    page: bool,
    wait: std::time::Duration,
    by: &str,
    settings_applied: &mut dyn FnMut(&[&'static str]),
    busy: &dyn Fn() -> bool,
) -> Result<Pulled, PullError> {
    let _lock = loc
        .store
        .lock_waiting(wait)
        .map_err(|e| PullError::Busy(format!("{e:#}")))?;
    let before = point_files(&loc.store);
    let now = pathwarden_core::analyze::now();
    let mut notes: Vec<String> = match loc.store.pull() {
        Ok(n) => n.into_iter().collect(),
        Err(e) => {
            let msg = format!("{e:#}");
            crate::last_pull::failed(&loc.store, by, now, &msg);
            return Err(PullError::Failed(msg));
        }
    };
    let locked = crate::encryption_ui::lock_reason(loc).is_some();
    let mut out = Pulled {
        locked,
        ..Pulled::default()
    };
    // Locked, the settings and full runs can't be read: each step loads
    // nothing and says why.
    {
        // The shared settings of the environment, or of the pathwarden.toml
        // the history was given with (`-c`, a server's).
        let synced = match ws {
            Some(ws) => sync_settings_detail(&ws.config_path(), Some(&ws.env_name()), loc, page),
            None => loc
                .store
                .flag_config()
                .map(|path| sync_settings_detail(path, None, loc, page))
                .unwrap_or_default(),
        };
        notes.extend(synced.0);
        out.sections = synced.1;
        out.conflict = synced.2;
        if !out.sections.is_empty() {
            settings_applied(&out.sections);
        }
        if !locked {
            out.runs = point_files(&loc.store).difference(&before).count();
        }
    }
    // A pull also pushes what was recorded here and is waiting: commits a
    // failed push left (a run's point, a full run, a settings change) and
    // full runs still to be made. Sync now and `history storage sync` push
    // all of it; the app's own pulls (`by` "app") nothing while an
    // analysis runs or for an hour after their push failed, and at most
    // one full run made again ([`crate::shared_runs::PullBy`]).
    let pull_by = if by == "app" {
        crate::shared_runs::PullBy::Background { busy }
    } else {
        crate::shared_runs::PullBy::Asked
    };
    // As noted with the last record: worked out on recordings and syncs.
    let waiting_before = crate::last_pull::read(&loc.store).map_or(0, |r| r.waiting.len());
    let pushed = match crate::shared_runs::push_waiting(ws, loc, pull_by) {
        Some(Ok(went)) => {
            out.pushed_any = true;
            Some(went)
        }
        Some(Err(still)) => {
            notes.push(still);
            None
        }
        None => None,
    };
    if loc.store.has_unpushed() {
        notes.push(
            "Changes recorded here earlier are not pushed yet; they go with the next push from \
             here."
                .to_string(),
        );
    }
    // What still waits, noted for the pages (once per sync), and the
    // history's checks made for its new commits now, so pages showing it
    // run no git.
    if let Some(ws) = ws {
        let after = crate::shared_runs::record_waiting(ws, loc).len();
        out.pushed = waiting_before.saturating_sub(after);
    }
    let _ = store::check_readable(&loc.dir);
    // The full runs the history holds open here like this computer's own.
    if let Some(ws) = ws {
        crate::shared_runs::signed_in(ws);
        let m = crate::shared_runs::mirror(ws, loc);
        crate::shared_runs::mark_shared(ws, &loc.store, "");
        out.removed = m.removed_ids.clone();
        out.loaded = m.words(loc.git.is_some());
    }
    // What went the other way, said with what came.
    out.loaded = match (pushed, out.loaded.take()) {
        (Some(p), Some(l)) => Some(format!("{p} {l}")),
        (p, l) => p.or(l),
    };
    out.notes = (!notes.is_empty()).then(|| notes.join(" "));
    crate::last_pull::succeeded(
        &loc.store,
        by,
        now,
        &crate::last_pull::Brought {
            loaded: out.loaded.clone(),
            sections: out.sections.iter().map(|s| s.to_string()).collect(),
            runs: out.runs,
            conflict: out.conflict,
            locked,
        },
    );
    Ok(out)
}

// ------------------------------------------------------- scheduled report

/// The report the schedule wrote last, if it sits in the known place next
/// to the history folder (`reports/latest.html`, as the generated scripts
/// write it), and the history run it belongs to: the newest run recorded at
/// or before the file was written.
pub fn scheduled_report(loc: &Location, h: &History) -> Option<(PathBuf, String)> {
    let path = loc.dir.parent()?.join(SCHEDULED_REPORT);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let written = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let p = h
        .points
        .iter()
        .rev()
        .find(|p| p.at <= written && p.recorded_by.as_deref() != Some(by::UI))?;
    Some((path, p.run_id.clone()))
}

/// The most a scheduled report may be to be served.
const MAX_REPORT_BYTES: u64 = 512 << 20;

async fn scheduled_report_file(st: &Shared) -> Option<String> {
    let ws = st.ws();
    let flag = st.state_dir();
    tokio::task::spawn_blocking(move || {
        let snap = snapshot(&ws, flag.as_deref());
        let loc = snap.location.as_ref().ok()?;
        let (path, _) = scheduled_report(loc, &snap.history)?;
        if std::fs::metadata(&path).ok()?.len() > MAX_REPORT_BYTES {
            return None;
        }
        std::fs::read_to_string(&path).ok()
    })
    .await
    .ok()
    .flatten()
}

/// The schedule's latest report, served like a run loaded from the
/// history: sandboxed, nothing loaded from anywhere, and only a report
/// script Pathwarden wrote may run ([`crate::retest_ui::report_csp_for`]).
/// The file sits beside the history folder, where whoever can change the
/// history's folder can change it too.
async fn scheduled_report_page(State(st): State<Shared>) -> Response {
    let Some(html) = scheduled_report_file(&st).await else {
        return (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response();
    };
    let Ok(csp) = HeaderValue::from_str(&crate::retest_ui::report_csp_for(&html, false)) else {
        return (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response();
    };
    let mut r = Html(html).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, csp);
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    r
}

// ------------------------------------------------------------- run pages

/// "Explore isn't available: graph.bin.gz was 120 MB, over the 75 MB
/// per-file limit.": what a run loaded from the history lacks, one
/// sentence per file.
pub fn shared_left_out_words(left: &[crate::shared_runs::LeftOut]) -> String {
    left.iter()
        .map(|l| {
            let what = match l.name.as_str() {
                "report.html.gz" => "The report isn't available",
                // Explore needs both.
                "graph.bin.gz" | "objects.json.gz" => "Explore isn't available",
                "event.json.gz" => "The findings list isn't available",
                "retest.json.gz" => "Targeted retests aren't available",
                _ => "Part of it isn't available",
            };
            format!(
                "{what}: {} was {}, {}.",
                l.name,
                pathwarden_core::diagnostics::bytes(l.bytes),
                l.why
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The Runs page's rows: every UI run, and every run recorded in the history
/// by the CLI or a schedule, newest first ([`crate::run_list::run_list`],
/// rendered by [`crate::run_list::row_html`]).
pub fn run_rows(ws: &Workspace, runs: &[RunSummary], snap: &Snapshot) -> Vec<String> {
    crate::run_list::run_list(ws, runs, snap)
        .iter()
        .map(crate::run_list::row_html)
        .collect()
}

/// The link to a recorded run's collection performance, as a tag on its
/// row.
pub(crate) fn perf_link(run_id: &str) -> String {
    format!(
        r#" <a class="tag rr-perf" href="/history/{}/performance" title="Collection performance of this run">Timings</a>"#,
        esc(run_id)
    )
}

/// A run against the run before it in the same series.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vs {
    /// Change in the accounts that can reach Tier Zero; `None` for a first
    /// run. A count, so it compares across a change of exposure basis.
    pub exposed: Option<i64>,
    /// Findings opened and fixed, when known.
    pub opened_fixed: Option<(usize, usize)>,
    /// With no `exposed`: the environment has earlier runs, none of which
    /// read what this one did (a Quick run after Full ones only).
    pub earlier: bool,
}

impl Vs {
    /// The cell's words as text ([`Vs::html`]): "No change", "↓ 2
    /// accounts, +1 new, −3 fixed", "↑ 1 account, +2 new", "First run"; a
    /// count of 0 is left out.
    pub fn text(&self) -> String {
        let Some(d) = self.exposed else {
            return self.uncompared().to_string();
        };
        let mut s = if d == 0 {
            "No change".to_string()
        } else {
            let n = d.unsigned_abs() as usize;
            format!(
                "{} {} {}",
                if d < 0 { "↓" } else { "↑" },
                num(n),
                if n == 1 { "account" } else { "accounts" }
            )
        };
        if let Some((o, f)) = self.opened_fixed {
            if o > 0 {
                let _ = write!(s, ", +{} new", num(o));
            }
            if f > 0 {
                let _ = write!(s, ", −{} fixed", num(f));
            }
        }
        s
    }

    /// The Runs list's "vs previous" cell.
    pub fn html(&self) -> String {
        self.html_to(None)
    }

    /// [`Vs::html`] with the change in accounts as a link to `which`: the
    /// run page's list of which accounts now reach Tier Zero and which no
    /// longer do.
    pub fn html_to(&self, which: Option<&str>) -> String {
        let mut words = Vec::new();
        let expo = match self.exposed {
            None => {
                return format!(
                    r#"<span class="vs-first muted">{}</span>"#,
                    self.uncompared()
                )
            }
            Some(d) => exposed_cell(d, which, &mut words),
        };
        let counts = match self.opened_fixed {
            Some((o, f)) => {
                words.push(format!("{} new, {} fixed", num(o), num(f)));
                format!(
                    r#"<span class="vs-counts"><span class="{}">+{} new</span><span class="{}">−{} fixed</span></span>"#,
                    if o > 0 { "vs-new" } else { "muted" },
                    num(o),
                    if f > 0 { "vs-fixed" } else { "muted" },
                    num(f)
                )
            }
            None => String::new(),
        };
        format!(
            r#"<span class="sr-only">Against the previous run: {}.</span><span aria-hidden="true" class="vs-cell">{expo}{counts}</span>"#,
            words.join(", ")
        )
    }
}

impl Vs {
    /// The words without a run to compare with, as Home says them.
    fn uncompared(&self) -> &'static str {
        if self.earlier {
            "Not compared with the last run"
        } else {
            "First run"
        }
    }
}

fn exposed_cell(d: i64, which: Option<&str>, words: &mut Vec<String>) -> String {
    if d == 0 {
        words.push("the same accounts can reach Tier Zero".to_string());
        return r#"<span class="vs-expo muted">No change</span>"#.to_string();
    }
    let n = d.unsigned_abs() as usize;
    let what = if n == 1 { "account" } else { "accounts" };
    let (cls, arrow, dir) = if d < 0 {
        ("good", "↓", "fewer")
    } else {
        ("bad", "↑", "more")
    };
    words.push(format!("{} {dir} {what} can reach Tier Zero", num(n)));
    match which {
        // The row's own link opens the run too: this one is for the mouse.
        Some(href) => format!(
            r#"<a class="vs-expo {cls}" href="{}" title="Which accounts" tabindex="-1">{arrow} {} {what}</a>"#,
            esc(href),
            num(n)
        ),
        None => format!(
            r#"<span class="vs-expo {cls}">{arrow} {} {what}</span>"#,
            num(n)
        ),
    }
}

/// Each run against the run before it, by ID (a UI run's folder ID, or a
/// history run ID). Two series, as Progress draws them: the history (by
/// environment; opened and fixed are the point's own, as `pathwarden
/// history` counts them), and UI runs not in the history (by environment;
/// opened and fixed from the runs' findings).
pub(crate) fn vs_previous(
    ws: &Workspace,
    runs: &[RunSummary],
    snap: &Snapshot,
) -> std::collections::HashMap<String, Vs> {
    let mut out = points_vs(&snap.history.points);
    let mut local: Vec<&RunSummary> = runs.iter().filter(|r| !snap.has(r)).collect();
    local.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    let mut prev: std::collections::HashMap<String, &RunSummary> = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for r in local {
        let earlier = !seen.insert(crate::retest_ui::env_key(r));
        // Like with like, as the history: a Quick run against the last
        // Quick run.
        let key = format!(
            "{}|{:?}",
            crate::retest_ui::env_key(r),
            crate::run_data::targeting(ws, r)
        );
        let before = prev.insert(key, r);
        let opened_fixed = before.and_then(|b| {
            let (old, new) = (
                crate::progress::fingerprints(ws, &b.id)?,
                crate::progress::fingerprints(ws, &r.id)?,
            );
            Some((new.difference(&old).count(), old.difference(&new).count()))
        });
        out.insert(
            r.id.clone(),
            Vs {
                exposed: before.map(|b| r.exposed as i64 - b.exposed as i64),
                opened_fixed,
                earlier,
            },
        );
    }
    out
}

/// [`vs_previous`] for history points: each against the point before it
/// in the same environment that targeted the same (sessions, local
/// groups). A point added after a newer run
/// ([`HistoryPoint::inserted`]) is compared with the one before it, but the
/// runs after it are not compared with it.
fn points_vs(points: &[HistoryPoint]) -> std::collections::HashMap<String, Vs> {
    let mut out = std::collections::HashMap::new();
    let mut last: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for p in points {
        let earlier = if p.inserted {
            seen.contains(&point_scopes_key(p))
        } else {
            !seen.insert(point_scopes_key(p))
        };
        // Like with like: a Quick run against the last Quick run, a Full
        // run against the last Full run (see `since::previous`).
        let key = format!(
            "{}|{:?}",
            point_scopes_key(p),
            pathwarden_core::since::targeting(p.completeness.as_ref())
        );
        let prev = if p.inserted {
            last.get(&key).copied()
        } else {
            last.insert(key, p.tier_zero_exposed)
        };
        out.insert(
            p.run_id.clone(),
            Vs {
                exposed: prev.map(|e| p.tier_zero_exposed as i64 - e as i64),
                opened_fixed: prev
                    .is_some()
                    .then(|| (pathwarden_core::history::opened(p), p.changes.resolved)),
                earlier,
            },
        );
    }
    out
}

/// The note above the Runs list: runs a newer Pathwarden saved here, and
/// earlier runs to import, or why the history can't be used.
pub fn runs_note(ws: &Workspace, runs: &[RunSummary], snap: &Snapshot) -> String {
    // As `pathwarden runs list` says it (docs/dev/formats.md).
    let newer = crate::workspace::newer_runs_words(ws.newer_run_folders())
        .map(|w| {
            format!(
                r#"<div class="note">{}<p>{}</p></div>"#,
                icon("i-alert"),
                esc(&w)
            )
        })
        .unwrap_or_default();
    newer + &history_note(ws, runs, snap)
}

fn history_note(ws: &Workspace, runs: &[RunSummary], snap: &Snapshot) -> String {
    match &snap.location {
        Err(e) => format!(
            r#"<div class="note">{}<p><strong>The run history can't be used:</strong> {} <a href="/automate/history">History storage</a></p></div>"#,
            icon("i-alert"),
            esc(e)
        ),
        // Encrypted and not opened here: the card asks for the passphrase,
        // and the history's runs can't be compared with yet.
        Ok(loc) if crate::encryption_ui::locked(loc, &snap.history) => String::new(),
        Ok(_) => {
            let lo = local_only(ws, runs, snap);
            let n = lo.importable.len();
            if n == 0 {
                return String::new();
            }
            format!(
                r#"<div class="note">{}<p><strong>{} {} made here {} in the run history.</strong> Progress and the command line don't see {}. <a href="/automate/history#earlier">Import or keep local only</a></p></div>"#,
                icon("i-history"),
                num(n),
                if n == 1 { "run" } else { "runs" },
                if n == 1 { "isn't" } else { "aren't" },
                if n == 1 { "it" } else { "them" },
            )
        }
    }
}

/// The `env` parameter for Progress: the domains when known (as Progress
/// names environments of UI runs), else a name-free key.
pub fn env_param(scopes: &str, domains: &[String]) -> String {
    if domains.is_empty() {
        pathwarden_core::findings::fingerprint("env", &[scopes])
    } else {
        let mut d: Vec<String> = domains.iter().map(|d| d.to_ascii_uppercase()).collect();
        d.sort();
        d.dedup();
        d.join(",")
    }
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|c| match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (c as char).to_string(),
            _ => format!("%{c:02X}"),
        })
        .collect()
}

// --------------------------------------------------- History storage page

/// History storage's query: from "Start a new run history" elsewhere
/// (New environment, an empty repository on the Connect page), the choice
/// made and the place filled in.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    origin: Option<String>,
    /// The place to fill in, by its token ([`crate::connect::keep_place`]):
    /// a URL never goes in the query.
    #[serde(default)]
    from: Option<String>,
    /// Filled in from `from`, never from the query.
    #[serde(skip)]
    remote: Option<String>,
    #[serde(skip)]
    branch: Option<String>,
    /// Runs of the environment's own ([`crate::connect::own_runs`]): set
    /// by the page, never from the query.
    #[serde(skip)]
    own: usize,
    /// The Sign in the page reloaded from, by its token
    /// ([`crate::sign_in::said`]).
    #[serde(default)]
    signin: Option<String>,
}

async fn page(
    State(st): State<Shared>,
    axum::extract::Query(mut q): axum::extract::Query<PageQuery>,
) -> Html<String> {
    if let Some(t) = q.from.take() {
        let root = st.workspace.root().to_path_buf();
        if let Ok(Some(m)) =
            tokio::task::spawn_blocking(move || crate::connect::take_place(&root, &t)).await
        {
            q.remote = m.url;
            q.branch = m.branch;
        }
    }
    let runs = st.ws().runs();
    let ctx_runs = runs.clone();
    let ws = st.ws();
    let flag = st.state_dir();
    let loaded = crate::settings::load(&st);
    let (snap, lo, full) = tokio::task::spawn_blocking(move || {
        let snap = snapshot(&ws, flag.as_deref());
        let lo = local_only(&ws, &runs, &snap);
        let full = crate::run_list::full_runs(&runs, &snap.history, snap.location.as_ref().ok());
        (snap, lo, full)
    })
    .await
    .unwrap_or_else(|_| {
        (
            Snapshot {
                location: Err("The history couldn't be read.".into()),
                history: History::default(),
            },
            LocalOnly {
                importable: Vec::new(),
                too_old: Vec::new(),
                kept: 0,
            },
            crate::run_list::FullRuns::default(),
        )
    });
    let sync = crate::sync_ui::view_for(&st, false).await;
    q.own = {
        let ws = st.ws();
        let flag = st.state_dir();
        tokio::task::spawn_blocking(move || crate::connect::own_runs(&ws, flag.as_deref()))
            .await
            .unwrap_or(0)
    };
    let body = render(&st, &loaded, &snap, &lo, &full, sync.as_ref(), &q);
    Html(pages::shell(
        &pages::Ctx::new(&st, &ctx_runs),
        Some(Nav::History),
        "History storage",
        "config",
        &body,
    ))
}

fn render(
    st: &AppState,
    loaded: &crate::settings::Loaded,
    snap: &Snapshot,
    lo: &LocalOnly,
    full: &crate::run_list::FullRuns,
    sync: Option<&crate::sync_ui::View>,
    q: &PageQuery,
) -> String {
    let own = q.own;
    let mut b = format!(
        r#"<div class="page-head"><div><p class="eyebrow">Automate</p><h1 class="panel-title">History storage</h1>
<p class="lead">Where each run's numbers and findings are kept, so Progress can show what is new, fixed or back.</p></div></div>
{file}"#,
        file = crate::settings::file_line_if_there(st, loaded),
    );

    // Once per page: it may look in this computer's credential store.
    let enc = snap.location.as_ref().ok().map(Encryption::of);

    // In use.
    b.push_str(r#"<section class="card setting hs-use" id="in-use"><header><h2 class="sub">In use</h2></header>"#);
    match &snap.location {
        Err(e) => {
            let _ = write!(
                b,
                r#"<div class="cfg-error card" role="alert">{}<div><strong>The history settings can't be used, so runs are kept on this computer only.</strong><pre>{}</pre></div></div>"#,
                icon("i-alert"),
                esc(e)
            );
        }
        Ok(loc) => {
            let h = &snap.history;
            // The folder last in both kinds, as pages show a path.
            let mut parts = where_parts(loc);
            if let Some(dir) = parts.last_mut() {
                dir.0 = crate::workspace::shown_path(&loc.dir);
            }
            let where_ = pages::parts_html(&parts);
            let origin = pages::code_html(origin_words(loc.origin, false));
            // Counts, fixed words and the time element: nothing to escape.
            let recorded = recorded_words(h, pages::time);
            let here = pages::code_html(records_words(loc));
            let keep = loaded.config.state.keep();
            let keeps = format!(
                r#"{} <span class="fact-sub">{}</span>"#,
                esc(keep.words()),
                esc(keep_sub(keep, loc.git.is_some()))
            );
            let settings_row = sync.map(crate::sync_ui::storage_row).unwrap_or_default();
            let _ = write!(
                b,
                r#"<dl class="hs-facts">
<div><dt>{}</dt><dd>{where_}</dd></div>
<div><dt>{}</dt><dd>{origin}</dd></div>
<div><dt>{}</dt><dd>{recorded}</dd></div>
<div><dt>{}</dt><dd>{keeps}</dd></div>{full_row}{settings_row}
<div><dt>{}</dt><dd>{here}</dd></div>
{enc_row}
</dl>"#,
                label::WHERE,
                label::SET_BY,
                label::RECORDED,
                label::KEEPS,
                label::RECORDS,
                full_row = if crate::run_list::shows_full_runs(keep, &loc.store) {
                    format!(
                        "\n<div><dt>{}</dt><dd>{}</dd></div>",
                        label::FULL_RUNS,
                        esc(&crate::run_list::full_runs_words(
                            full,
                            crate::encryption_ui::locked(loc, h)
                        ))
                    )
                } else {
                    String::new()
                },
                enc_row = enc
                    .as_ref()
                    .map(crate::encryption_ui::in_use_row)
                    .unwrap_or_default(),
            );
            if crate::encryption_ui::locked(loc, h) {
                // In the page's words: Runs asks for the passphrase.
                let _ = write!(
                    b,
                    r#"<p class="field-error" role="alert">The history is encrypted and can't be opened here yet. <a href="/runs">Enter the passphrase on Runs</a>.</p>"#
                );
            } else {
                // Older copies refused: what, and accepting them.
                let offer = accept_offer(loc, &st.env_id());
                if let Some(p) = &h.problem {
                    if !offer.as_ref().is_some_and(|o| o.contains(&*esc(p))) {
                        let _ = write!(b, r#"<p class="field-error" role="alert">{}</p>"#, esc(p));
                    }
                }
                b.push_str(&offer.unwrap_or_default());
            }
            if loc.git.is_some() {
                let line = crate::last_pull::status(
                    crate::last_pull::read(&loc.store),
                    loaded.config.state.refresh_minutes(),
                    pathwarden_core::analyze::now(),
                )
                .line_html();
                // How Sign in went, after the page reloaded from it.
                let (said, class) = match q.signin.as_deref().and_then(crate::sign_in::said) {
                    Some(o) => (o.words(), if o.good() { "good" } else { "bad" }),
                    None => ("", "muted"),
                };
                let _ = write!(
                    b,
                    r#"<div class="card-actions pull-line"><button type="button" class="btn" data-history-action="refresh">{} {}</button>{line}<span class="save-status small {class}" aria-live="polite">{said}</span></div>"#,
                    icon("i-sync"),
                    SYNC_NOW,
                    said = esc(said),
                );
            }
        }
    }
    b.push_str("</section>");

    // Earlier runs.
    if !lo.importable.is_empty() || !lo.too_old.is_empty() {
        b.push_str(r#"<section class="card setting" id="earlier"><header><h2 class="sub">Runs not in the run history</h2><p class="muted">These runs were made here before the app recorded them, or while the run history couldn't be reached, so Progress doesn't include them. Nothing changes until you choose.</p></header>"#);
        if !lo.importable.is_empty() {
            let _ = write!(
                b,
                r#"<p><strong>{n} can be added in order</strong>, oldest first, as if each had been recorded when it was analyzed:</p><ul class="hs-runs">"#,
                n = num(lo.importable.len())
            );
            for r in lo.importable.iter().take(12) {
                let _ = write!(
                    b,
                    r#"<li><a href="/runs/{id}">{env}</a> <span class="muted small">{when} · {src}</span></li>"#,
                    id = esc(&r.id),
                    env = esc(&r.environment()),
                    when = pages::time(r.created_at),
                    src = esc(&crate::workspace::hide_profile(&r.source)),
                );
            }
            if lo.importable.len() > 12 {
                let _ = write!(
                    b,
                    r#"<li class="muted small">and {} more</li>"#,
                    num(lo.importable.len() - 12)
                );
            }
            let ids: Vec<&str> = lo.importable.iter().map(|r| r.id.as_str()).collect();
            let _ = write!(
                b,
                r#"</ul><div class="card-actions"><button type="button" class="btn primary" data-history-action="import">{} Import them in order</button><button type="button" class="btn" data-history-action="keep-local" data-ids="{}">Keep them local only</button><span class="save-status muted small" aria-live="polite"></span></div>"#,
                icon("i-history"),
                esc(&ids.join(",")),
            );
        }
        if !lo.too_old.is_empty() {
            let _ = write!(
                b,
                r#"<p class="muted small">{}</p>"#,
                esc(&too_old_words(lo.too_old.len()))
            );
        }
        b.push_str("</section>");
    }

    // Where this environment's history lives: asked first, then the
    // form that was Settings, Scheduled runs.
    let s = &loaded.config.state;
    let starting = q.origin.as_deref() == Some("new-shared");
    let git = s.backend == StateBackend::Git || (starting && q.remote.is_some());
    // Shared already: a git repository, or a folder set in pathwarden.toml.
    let shared_now =
        s.backend == StateBackend::Git || s.path.as_deref().is_some_and(|p| !p.trim().is_empty());
    let origin = if starting || shared_now {
        "shared"
    } else {
        "local"
    };
    let env_name = st.ws().env_name();
    let connect_block = if own > 0 {
        let (lead, rest) = pathwarden_core::connect::own_runs(&env_name, own);
        format!(
            r#"<div class="note warn hs-origin-warn" role="status">{}<div><p><strong>{}</strong> {}</p><div class="enc-actions"><a class="btn small-btn primary" href="{}">Add an environment for it</a></div></div></div>"#,
            icon("i-alert"),
            esc(&lead),
            esc(&rest),
            crate::connect_ui::PATH
        )
    } else {
        format!(
            r#"<p class="muted">The next page looks at the repository or folder before anything changes here.</p><div class="card-actions"><a class="btn primary" href="{}?env={}">{} Continue</a></div>"#,
            crate::connect_ui::PATH,
            urlencode(&st.env_id()),
            icon("i-arrow"),
        )
    };
    let _ = write!(
        b,
        r#"<section class="card setting" id="state" data-section="state">
<header><h2 class="sub">Where this environment's history lives</h2></header>
<fieldset class="choice hs-origin" data-no-save><legend class="sr-only">Where the history lives</legend>
  <label class="option card"><input type="radio" name="hs-origin" value="local"{o_local}><span><strong>On this computer</strong><span class="muted">In this environment's folder. Nobody else sees it.</span></span></label>
  <label class="option card"><input type="radio" name="hs-origin" value="connect"><span><strong>Connect to a run history</strong><span class="muted">The runs and settings that teammates or a server record.</span></span></label>
  <label class="option card"><input type="radio" name="hs-origin" value="shared"{o_shared}><span><strong>{shared_title}</strong><span class="muted">{shared_sub}</span></span></label>
</fieldset>
<div data-when-origin="connect" hidden>{connect_block}</div>
<div data-when-origin="form">
<p class="muted hs-where-lead" data-when-origin="shared">One place for every run's history. For a schedule on a server, choose a place both the server and this computer reach (a shared folder or a git repository) and copy <code>pathwarden.toml</code> to the server, so its runs show up here too.</p>
<fieldset class="choice" data-when-origin="shared"><legend class="sr-only">Where to keep the history</legend>
  <label class="option card"><input type="radio" name="backend" value="local"{local_on}><span><strong>A folder</strong><span class="muted">On this computer or a network share. Use it when this computer and the scheduled runs reach the same folder.</span></span></label>
  <label class="option card"><input type="radio" name="backend" value="git"{git_on}><span><strong>A git repository</strong><span class="muted">Synced before and after each run, so runs on different computers share one run history. Use a private repository.</span></span></label>
</fieldset>
<div class="fields2" data-when-origin="shared">
  <div class="field"><label for="state-path" id="state-path-label">Folder</label><input class="input mono" id="state-path" value="{path}" placeholder="{DEFAULT_FOLDER}" autocomplete="off" spellcheck="false"><p class="hint" data-when-backend="local">A relative folder is taken from Pathwarden's folder on this computer, and from the folder a scheduled run starts in on a server. Default: <code>{DEFAULT_FOLDER}</code>.</p><p class="hint" data-when-backend="git">Where each computer checks the repository out. Pathwarden owns this folder. Default: <code>{DEFAULT_FOLDER}</code>.</p></div>
  <div class="field" data-when-backend="git"><label for="state-remote">Repository URL</label><input class="input mono" id="state-remote" value="{remote}" placeholder="https://github.com/you/pathwarden-state.git" autocomplete="off" spellcheck="false"><p class="hint">Sign-in comes from git's own credential helper; never put a password in the URL.</p>{remote_warning}</div>
  <div class="field" data-when-backend="git"><label for="state-branch">Branch</label><input class="input mono" id="state-branch" value="{branch}" placeholder="main" autocomplete="off" spellcheck="false"><p class="hint">Letters, digits and <code>. _ / -</code>.</p></div>
  <div class="field refresh-field" data-when-backend="git"><label for="state-refresh">Sync every</label><div class="unit"><input class="input" type="number" id="state-refresh" min="1" max="{max_refresh}" step="1" value="{refresh}" inputmode="numeric"><span>minutes</span></div><p class="hint">While the app is open, and when it opens. {refresh_tip}</p></div>
</div>
<label class="check-row" data-when-backend="git"><input type="checkbox" id="state-push"{push}><span><strong>Push recorded runs to the repository</strong><span class="muted">On: every run, here or on a server, is committed and pushed, so everyone sees it. Off: this computer only reads the run history (runs started here stay on this computer), and runs from the command line here don't push either.</span></span></label>
<fieldset class="choice keep-choice"><legend>What the history keeps</legend><label class="option card"><input type="radio" name="keep" value="names"{names_on}><span><strong>Numbers with names</strong><span class="muted">{names_words} The default.</span></span></label><label class="option card"><input type="radio" name="keep" value="full"{full_on}><span><strong>Full runs and settings</strong><span class="muted">Each run in full (report, Explore, findings, retest), plus shared settings and accepted risks with who accepted them.<span class="tip"><button type="button" class="tip-btn" aria-label="About: Full runs and settings" aria-describedby="tip-keep-full">{info}</button><span class="tip-text" role="tooltip" id="tip-keep-full">Each full run records the user and computer that recorded it. Each accepted risk records the computer it was accepted on, and when. Settings travel with a git repository.</span></span></span></span></label></fieldset><p class="hint keep-hint">The same for a folder or a git repository.</p>
<div class="note warn keep-warn" role="alert"{warn_hidden}>{alert}<div><p><strong>Full runs show how to attack your directory:</strong> every account, group and computer, and the paths between them. Anyone who can read this folder or repository can see them, and a repository's history keeps them after removal. <span class="tip"><button type="button" class="tip-btn" aria-label="About: What full runs hold" aria-describedby="tip-warn">{info}</button><span class="tip-text wide" role="tooltip" id="tip-warn"><strong>Kept:</strong> the report, the graph for Explore, the object list, the findings and their paths, the retest data and the settings each run was analysed with, with the user and computer that recorded it.<br><strong>Never kept:</strong> the raw collection, where it was kept, folders on this computer, passwords and tokens, plugin settings.<br><strong>Readers</strong> need read access to the repository.<br>Only keep full runs in a private place whose readers you would hand the reports to.</span></span></p><p class="small muted keep-confirm">You'll be asked to confirm. Switching back stops new full runs: earlier ones stay in the repository's history.</p></div></div>
{enc}
<div class="hs-found" id="hs-found" aria-live="polite"></div>
<div class="card-actions"><button type="button" class="btn primary" data-save><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save</button><span class="save-status muted small" aria-live="polite"></span></div>
</div>
</section>
"#,
        o_local = if origin == "local" { " checked" } else { "" },
        o_shared = if origin == "shared" { " checked" } else { "" },
        shared_title = if shared_now && !starting {
            "This run history"
        } else {
            "Start a new run history"
        },
        shared_sub = if shared_now && !starting {
            "Its repository or folder, and what it keeps."
        } else {
            "In a git repository or shared folder, for others to join."
        },
        names_words = esc(pathwarden_core::config::NAMES_WORDS
            .strip_prefix("Numbers with names: ")
            .unwrap_or(pathwarden_core::config::NAMES_WORDS)),
        names_on = if s.keep() == pathwarden_core::config::Keep::Names {
            " checked"
        } else {
            ""
        },
        full_on = if s.keep() == pathwarden_core::config::Keep::Full {
            " checked"
        } else {
            ""
        },
        warn_hidden = if s.keep() == pathwarden_core::config::Keep::Full {
            ""
        } else {
            " hidden"
        },
        info = icon("i-info"),
        alert = icon("i-alert"),
        local_on = if git { "" } else { " checked" },
        git_on = if git { " checked" } else { "" },
        path = crate::pages::attr(s.path.as_deref().unwrap_or_default()),
        // Credentials in the URL are never shown; saving the redacted form
        // back keeps them (config_edit::set_state).
        remote = esc(&pathwarden_core::config::redact_urls(
            match (starting, q.remote.as_deref()) {
                (true, Some(r)) => r,
                _ => s.remote.as_deref().unwrap_or_default(),
            }
        )),
        remote_warning = if s
            .remote
            .as_deref()
            .is_some_and(pathwarden_core::config::remote_has_password)
        {
            r#"<p class="hint"><strong>This URL contains a password or token, which git keeps in plain text in the working copy's <code>.git/config</code>.</strong> Remove it and sign in through a credential helper (Git Credential Manager on Windows) instead.</p>"#
        } else {
            ""
        },
        branch = crate::pages::attr(match (starting, q.branch.as_deref()) {
            (true, Some(b)) => b,
            _ => s.branch.as_deref().unwrap_or_default(),
        }),
        refresh = s.refresh_minutes(),
        max_refresh = pathwarden_core::config::MAX_REFRESH_MINUTES,
        refresh_tip = crate::sync_ui::tip(
            "refresh",
            "Sync every",
            &[
                (
                    "Syncs".into(),
                    "Brings runs, numbers, settings and accepted risks, and pushes what is waiting here.".into(),
                ),
                (
                    "Range".into(),
                    format!(
                        "1 to {} minutes. Default {}",
                        pathwarden_core::config::MAX_REFRESH_MINUTES,
                        pathwarden_core::config::DEFAULT_REFRESH_MINUTES
                    ),
                ),
                (
                    "Kept".into(),
                    "Each computer sets its own, including readers.".into(),
                ),
            ],
            false,
        ),
        push = if s.pushes() { " checked" } else { "" },
        enc = match &snap.location {
            Ok(_) => enc
                .as_ref()
                .map(crate::encryption_ui::where_block)
                .unwrap_or_default(),
            Err(_) => String::new(),
        },
    );

    // Full runs and settings: how many full runs the history keeps.
    if s.keep() == pathwarden_core::config::Keep::Full {
        let _ = write!(
            b,
            r#"<section class="card setting" id="full-runs" data-section="full-runs">
<header><h2 class="sub">Full runs and settings</h2><p class="muted">These apply while the history keeps full runs and settings. Every computer that reads it can open each run in full and analyze with the same settings.</p></header>
<div class="fr-grid">
  <div class="field"><label for="full-runs-kept">Keep the latest</label><input class="input fr-kept" id="full-runs-kept" type="number" min="1" max="{max}" step="1" value="{kept}" inputmode="numeric"><p class="hint">full runs; older ones keep their numbers.</p></div>
  <div class="field"><label for="full-run-file-mb">{limit_label}</label><input class="input fr-kept" id="full-run-file-mb" type="number" min="1" max="{max_mb}" step="1" value="{mb}" inputmode="numeric"><p class="hint">MB. {limit}</p>{held}</div>
</div>
<div class="card-actions"><button type="button" class="btn primary" data-save><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save</button><span class="save-status muted small" aria-live="polite"></span></div>
</section>
"#,
            max = pathwarden_core::config::MAX_FULL_RUNS_KEPT,
            limit_label = label::FILE_LIMIT,
            limit = esc(crate::shared_runs::FILE_LIMIT_WORDS),
            kept = s.full_runs_kept(),
            max_mb = pathwarden_core::config::MAX_FULL_RUN_FILE_MB,
            mb = s.full_run_file_mb(),
            // On GitHub: why a larger setting is held, shown while it is.
            held = match &snap.location {
                Ok(l) if crate::shared_runs::on_github(s, &l.store) => format!(
                    r#"<p class="hint" id="full-run-file-held" data-hold="{hold}"{hidden}>{words}</p>"#,
                    hold = pathwarden_core::config::GITHUB_FULL_RUN_FILE_MB,
                    hidden = if crate::shared_runs::file_limit_mb(s, &l.store).1 {
                        ""
                    } else {
                        " hidden"
                    },
                    words = esc(crate::shared_runs::GITHUB_HOLD_WORDS)
                ),
                _ => String::new(),
            },
        );
    }

    // Recent history.
    let pts = &snap.history.points;
    if !pts.is_empty() {
        b.push_str(r#"<section class="card setting" id="recent"><header><h2 class="sub">Latest runs in the history</h2><p class="muted">Each run's numbers, for every environment.</p></header><div class="hs-table-wrap"><table class="hs-table"><thead><tr><th scope="col">Run</th><th scope="col">Recorded by</th><th scope="col">Exposure</th><th scope="col">Open</th><th scope="col">New</th><th scope="col">Fixed</th><th scope="col">Can't tell</th></tr></thead><tbody>"#);
        let timed = |id: &str| {
            snap.location
                .as_ref()
                .is_ok_and(|l| pathwarden_core::store::has_run_timings(&l.dir, id))
        };
        for p in pts.iter().rev().take(10) {
            let _ = write!(
                b,
                "<tr><td>{}{}{}</td><td>{}</td><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                // Its label, so runs of one day can be told apart.
                p.label
                    .as_deref()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| format!("<strong>{}</strong> · ", esc(l)))
                    .unwrap_or_default(),
                pages::time(p.at),
                if timed(&p.run_id) {
                    perf_link(&p.run_id)
                } else {
                    String::new()
                },
                esc(&recorded_by_words(p)),
                pathwarden_core::posture::share_percent(p.tier_zero_exposure_percent),
                pages::older_basis_mark(p.basis()),
                num(pathwarden_core::history::open_findings(p)),
                num(pathwarden_core::history::opened(p)),
                num(p.changes.resolved),
                num(p.changes.held),
            );
        }
        b.push_str("</tbody></table></div></section>");
    }
    b.push_str(&crate::settings::after_save(st));
    b.push_str(r#"<script src="/static/config.js" defer></script><script src="/static/automate.js" defer></script><script src="/static/enc.js" defer></script>"#);
    b
}

// -------------------------------------------------------------------- API

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn import_api(State(st): State<Shared>) -> Response {
    if st.jobs.running().is_some() {
        return json_error(
            StatusCode::CONFLICT,
            "An analysis is running. Import when it has finished.",
        );
    }
    let ws = st.ws();
    let flag = st.state_dir();
    match tokio::task::spawn_blocking(move || import(&ws, flag.as_deref())).await {
        Ok(Ok((n, notes))) => Json(serde_json::json!({
            "imported": n,
            "note": (!notes.is_empty()).then(|| notes.join(" ")),
        }))
        .into_response(),
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "The import failed."),
    }
}

#[derive(Deserialize)]
struct KeepBody {
    ids: Vec<String>,
}

async fn keep_local_api(State(st): State<Shared>, Json(body): Json<KeepBody>) -> Response {
    let ids: Vec<String> = body
        .ids
        .into_iter()
        .filter(|id| crate::workspace::valid_run_id(id))
        .take(10_000)
        .collect();
    let ws = st.ws();
    match tokio::task::spawn_blocking(move || keep_local(&ws, &ids)).await {
        Ok(Ok(())) => Json(serde_json::json!({ "saved": true })).into_response(),
        Ok(Err(e)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Saving failed."),
    }
}

/// `POST /api/history/refresh`: Pull now. The app's next pull is a whole
/// interval on, and pages open on what it brought are told.
async fn refresh_api(State(st): State<Shared>) -> Response {
    let ws = st.ws();
    let env = st.env_id();
    let flag = st.state_dir();
    let (st2, env2) = (st.clone(), env.clone());
    let done = tokio::task::spawn_blocking(move || {
        let loc = locate(&ws, flag.as_deref())?;
        refresh_detail(
            Some(&ws),
            &loc,
            true,
            pathwarden_core::settings_sync::lock_wait(),
            "pull now",
            &mut |s| {
                st2.auto_pull.record_sections(&env2, s);
            },
        )
        .map_err(PullError::into_message)
    })
    .await;
    st.auto_pull.timer.reset();
    match done {
        Ok(Ok(p)) => {
            st.auto_pull.record_runs(&env, &p);
            let all: Vec<String> = p.loaded.into_iter().chain(p.notes).collect();
            let note = (!all.is_empty()).then(|| all.join(" "));
            Json(serde_json::json!({ "saved": true, "note": note })).into_response()
        }
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Refreshing failed."),
    }
}

/// What [`accept_api`] says when the page is of another environment than
/// the one in use (switched in another tab).
pub const ACCEPT_OTHER_ENV: &str =
    "Another environment is in use now. Reload the page to see its history.";

#[derive(Deserialize)]
struct AcceptBody {
    /// The environment the page was of.
    env: String,
}

/// The button that accepts an encrypted history as it is after a restore
/// made on purpose, where a refusal of older copies is shown.
pub const ACCEPT: &str = "Accept the history as it is";

/// The refusal of older copies in the history at `loc` that accepting it
/// gets past ([`pathwarden_core::binding::refused`], as reading it here
/// last met it), in the page's words, with the [`ACCEPT`] button and its
/// confirm dialog; `None` with no such refusal. Never offered for a file
/// without a binding where every file has one, or a newer binding:
/// accepting doesn't help there ([`pathwarden_core::binding::BindingError::acceptable`]).
/// `env`: the environment the page is of, posted back so a page left open
/// after a switch in another tab never accepts another history.
pub fn accept_offer(loc: &Location, env: &str) -> Option<String> {
    let e = store::refusal(&loc.dir)?;
    Some(format!(
        r#"<p class="field-error" role="alert">{said}</p><div class="card-actions"><button type="button" class="btn" data-accept-history="{env}">{i} {ACCEPT}</button><span class="save-status small" aria-live="polite"></span></div><dialog id="accept-history-dialog" class="card" aria-labelledby="accept-history-title"><form method="dialog"><h2 class="sub" id="accept-history-title">Accept the history as it is?</h2><p class="muted">{words}</p><div class="dialog-actions"><button class="btn" value="cancel">Cancel</button><button class="btn primary" value="accept" id="accept-history-go">{i} Accept the history</button></div></form></dialog>"#,
        said = esc(&e.to_string()),
        env = esc(env),
        words = esc(store::ACCEPT_WORDS),
        i = icon("i-check"),
    ))
}

/// [`accept_offer`] in a card of its own, for Runs and a run's page.
pub fn accept_card(loc: &Location, env: &str) -> Option<String> {
    accept_offer(loc, env)
        .map(|b| format!(r#"<section class="card setting" id="accept-history">{b}</section>"#))
}

/// `POST /api/history/accept`: accepts the history in use as it is on
/// this computer ([`store::accept_history`], as `pathwarden history
/// storage accept`), only for the environment the page was of (`env`),
/// and only past a refusal reading the history here met
/// ([`store::refusal`]): 409 otherwise, and nothing changes.
async fn accept_api(State(st): State<Shared>, Json(body): Json<AcceptBody>) -> Response {
    if body.env != st.env_id() {
        return json_error(StatusCode::CONFLICT, ACCEPT_OTHER_ENV);
    }
    let ws = st.ws();
    let flag = st.state_dir();
    let done = tokio::task::spawn_blocking(move || {
        let loc = locate(&ws, flag.as_deref()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        if store::refusal(&loc.dir).is_none() {
            return Err((StatusCode::CONFLICT, store::NOTHING_REFUSED.to_string()));
        }
        store::accept_history(&loc.dir)
            .map(|reset| reset.len())
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))
    })
    .await;
    match done {
        Ok(Ok(n)) => Json(serde_json::json!({ "saved": true, "reset": n })).into_response(),
        Ok(Err((status, e))) => json_error(status, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Accepting the history failed.",
        ),
    }
}

/// `GET /api/history/since`: [`since`], `null` with no earlier run.
async fn since_api(State(st): State<Shared>) -> Response {
    let ws = st.ws();
    let flag = st.state_dir();
    match tokio::task::spawn_blocking(move || since(&ws, flag.as_deref())).await {
        // The status keys' 1.0 names beside the old ones.
        Ok(Ok(v)) => match pathwarden_core::status_keys::to_value(&v) {
            Ok(v) => Json(v).into_response(),
            Err(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reading the history failed.",
            ),
        },
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Reading the history failed.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{domains_for, scopes_key, LastRun, Vs};

    /// A point added after a newer run is compared with the run
    /// before it, and the runs after it are not compared with it.
    #[test]
    fn an_inserted_point_is_not_compared_with() {
        let p = |id: &str, at: i64, exposed: usize, inserted: bool| {
            serde_json::from_value::<super::HistoryPoint>(serde_json::json!({
                "version": 1, "run_id": id, "at": at, "collected_at": null,
                "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": exposed,
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
        let vs = super::points_vs(&[
            p("a", 1, 10, false),
            p("i", 2, 50, true),
            p("b", 3, 20, false),
        ]);
        assert_eq!(vs["b"].exposed, Some(10));
        assert_eq!(vs["i"].exposed, Some(40));
    }

    /// A last run saved by 0.1.1 lists the trusted domain too; the names of
    /// an environment recorded since come from it all the same.
    #[test]
    fn names_from_a_list_with_trusted_domains() {
        let last: LastRun = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": "r", "started_at": 1, "finished_at": 1,
            "collected_at": null, "pathwarden": "0.1.1", "collector_files": 1,
            "domains": ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"],
            "changes": {"new": 0, "open": 0, "resolved": 0, "regressed": 0,
                "suppressed": 0, "held": 0},
        }))
        .unwrap();
        let essos = scopes_key(&["ESSOS.LOCAL".to_string()]);
        assert_eq!(domains_for(&essos, &[], Some(&last)), ["ESSOS.LOCAL"]);
        let both = scopes_key(&last.domains);
        assert_eq!(domains_for(&both, &[], Some(&last)), last.domains);
        let other = scopes_key(&["OTHER.LOCAL".to_string()]);
        assert!(domains_for(&other, &[], Some(&last)).is_empty());
    }

    #[test]
    fn vs_previous_cell() {
        let first = Vs {
            exposed: None,
            opened_fixed: None,
            earlier: false,
        };
        assert!(first.html().contains("First run"));
        let uncompared = Vs {
            earlier: true,
            ..first
        };
        assert!(uncompared.html().contains("Not compared with the last run"));
        assert_eq!(uncompared.text(), "Not compared with the last run");
        let better = Vs {
            exposed: Some(-12),
            opened_fixed: Some((1, 5)),
            earlier: true,
        };
        let h = better.html();
        assert!(h.contains(r#"vs-expo good">↓ 12 accounts"#), "{h}");
        assert!(h.contains("+1 new") && h.contains("−5 fixed"), "{h}");
        assert!(
            h.contains("12 fewer accounts can reach Tier Zero, 1 new, 5 fixed"),
            "{h}"
        );
        let worse = Vs {
            exposed: Some(1),
            opened_fixed: None,
            earlier: false,
        };
        assert!(worse.html().contains(r#"vs-expo bad">↑ 1 account<"#));
        let same = Vs {
            exposed: Some(0),
            opened_fixed: None,
            earlier: false,
        };
        assert!(same.html().contains("No change") && !same.html().contains("new"));
        // A run with its account lists: the change links to which accounts.
        let h = worse.html_to(Some("/runs/20261028-020000-abcdef#since-tier-zero"));
        assert!(
            h.contains(r#"<a class="vs-expo bad" href="/runs/20261028-020000-abcdef#since-tier-zero" title="Which accounts" tabindex="-1">↑ 1 account</a>"#),
            "{h}"
        );
        // No change, or no run to compare with: nothing to link.
        assert!(!same.html_to(Some("/x")).contains("<a "));
        assert!(!first.html_to(Some("/x")).contains("<a "));
    }

    /// Points compare by the accounts that can reach Tier Zero, a count, so
    /// across changes of exposure basis too (an old all-enabled point, a
    /// capability-gate point and an active-basis point).
    #[test]
    fn vs_previous_points_compare_counts_across_bases() {
        let point = |run: &str, at: i64, exposed: usize, relevant: usize, basis: u8| {
            serde_json::from_value::<pathwarden_core::state::HistoryPoint>(serde_json::json!({
                "version": 1, "run_id": run, "at": at, "collected_at": null,
                "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": exposed,
                "tier_zero_population": 10, "tier_zero_relevant_population": relevant,
                "exposure_basis": basis, "tier_zero_objects": 1, "protection_score": null,
                "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0, "critical": 0,
                    "high": 0, "medium": 0, "low": 0, "info": 0},
                "changes": {"new": 0, "open": 0, "resolved": 0, "regressed": 0,
                    "suppressed": 0, "held": 0},
            }))
            .unwrap()
        };
        let pts = [
            point("a", 1, 509, 0, 0),
            point("b", 2, 509, 8, 0),
            point("c", 3, 520, 9, 2),
            point("d", 4, 498, 9, 2),
        ];
        let vs = super::points_vs(&pts);
        assert_eq!(vs["a"].exposed, None);
        assert_eq!(vs["b"].exposed, Some(0));
        assert_eq!(vs["c"].exposed, Some(11));
        assert_eq!(vs["d"].exposed, Some(-22));
    }
}
