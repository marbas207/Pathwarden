//! Routes and handlers.
//!
//! Pages are rendered on the server ([`crate::pages`]); a small script
//! handles uploads, progress and the theme. Routes for the next screens
//! (Settings, Zones, Plugins) slot in next to the ones here: add a page in
//! `pages`, a route below and a [`pages::Nav`] entry. The Collect wizard's
//! routes live in [`crate::collect`].

use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, OnceLock};

use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::analyze;
use pathwarden_core::ingest::MAX_ENTRY_BYTES;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::environments::DEFAULT_ENV;
use crate::jobs::{self, JobSpec, Jobs};
use crate::pages;
use crate::security::{self, SessionPolicy, Sessions, Token};
use crate::workspace::{self, Workspace, REPORT_FILE};

/// The demo collection, built into the binary so it works with no files
/// (also `pathwarden demo` and `-i demo:` on the command line).
pub const DEMO_ZIP: &[u8] = include_bytes!("../../../demo/20261001020000_PathwardenDemo.zip");
pub const DEMO_NAME: &str = "20261001020000_PathwardenDemo.zip";

const APP_JS: &str = include_str!("assets/app.js");
const THEME_JS: &str = include_str!("assets/theme.js");
const UI_CSS: &str = include_str!("assets/ui.css");
const CONFIG_JS: &str = include_str!("assets/config.js");
const CONFIG_CSS: &str = include_str!("assets/config.css");

/// Upload limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest single file: the same cap core puts on one collector file.
    pub per_file: u64,
    /// All files in one analysis together.
    pub total: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_file: MAX_ENTRY_BYTES,
            total: 4 * MAX_ENTRY_BYTES,
        }
    }
}

pub struct AppState {
    /// The workspace, scoped to the Default environment; pages use
    /// [`AppState::ws`], scoped to the current one.
    pub workspace: Workspace,
    /// The current environment's ID ([`crate::environments`]).
    env: std::sync::RwLock<String>,
    /// The one-time link and the sessions it opened.
    pub sessions: Sessions,
    pub port: u16,
    pub cookie_name: String,
    pub jobs: Arc<Jobs>,
    pub limits: Limits,
    /// Keep uploaded collector files after analysis (off by default).
    pub keep_uploads: bool,
    /// Whether the pages may choose where findings and runs go
    /// (`--allow-destinations`): a plugin's program or destination, where the
    /// run history is kept, connecting to a shared history. Off by default: a
    /// UI session then cannot make Pathwarden run a program, or send data or
    /// sign in somewhere, of its choosing.
    pub allow_destinations: bool,
    /// Whether `Host: localhost:PORT` is accepted: not when another program
    /// holds `[::1]` on this port, where browsers try `localhost` first.
    pub localhost_host: bool,
    /// Notified when the user stops Pathwarden from the page.
    pub stop: tokio::sync::Notify,
    /// The browser launcher file while its link is unused.
    pub launch_file: crate::launch::Slot,
    /// How requests arrive: the loopback listener, or an embedded window.
    pub transport: security::Transport,
    /// Pulling a git history while pages are open ([`crate::auto_pull`]).
    pub auto_pull: crate::auto_pull::AutoPull,
}

impl AppState {
    /// `link` is the one-time token of the first link, valid from now.
    pub fn new(ws: Workspace, link: Token, port: u16) -> Self {
        // Demo runs from before the demo had its own environment move
        // there (in the registry only: no run is rewritten), so the demo
        // never mixes with real runs.
        if ws.registry().demo_id().is_none() && ws.all_runs().iter().any(|r| r.demo) {
            let _ = crate::environments::Registry::update(ws.root(), |r| Ok(r.ensure_demo()));
        }
        let env = ws.registry().current.unwrap_or_else(|| DEFAULT_ENV.into());
        Self {
            workspace: ws,
            env: std::sync::RwLock::new(env),
            sessions: Sessions::new(link, SessionPolicy::default()),
            port,
            cookie_name: security::cookie_name(port),
            jobs: Arc::default(),
            limits: Limits::default(),
            keep_uploads: false,
            allow_destinations: false,
            localhost_host: true,
            stop: tokio::sync::Notify::new(),
            launch_file: crate::launch::Slot::default(),
            transport: security::Transport::Loopback,
            auto_pull: crate::auto_pull::AutoPull::default(),
        }
    }

    /// State for an embedded window ([`security::Transport::Embedded`]):
    /// no port, and no link (one is made but retired at once, unseen).
    pub fn embedded(ws: Workspace, origin: impl Into<String>) -> anyhow::Result<Self> {
        let mut state = Self::new(ws, Token::generate()?, 0);
        state.sessions.end_all();
        state.transport = security::Transport::Embedded {
            origin: origin.into(),
        };
        Ok(state)
    }

    /// The workspace scoped to the current environment: what every page
    /// shows and changes.
    pub fn ws(&self) -> Workspace {
        self.workspace.in_env(&self.env_id())
    }

    /// The current environment's ID. If it was removed meanwhile (for
    /// example with `pathwarden env remove`), the one the removal made
    /// current, else Default.
    pub fn env_id(&self) -> String {
        let id = self.env.read().unwrap_or_else(|e| e.into_inner()).clone();
        let reg = self.workspace.registry();
        if id == DEFAULT_ENV || reg.get(&id).is_some() {
            id
        } else {
            reg.current
                .clone()
                .filter(|c| reg.get(c).is_some())
                .unwrap_or_else(|| DEFAULT_ENV.into())
        }
    }

    /// Makes environment `id` current (remembered in the registry for the
    /// next start). False if there is no such environment.
    pub fn set_env(&self, id: &str) -> bool {
        let root = self.workspace.root().to_path_buf();
        let ok = crate::environments::Registry::update(&root, |r| {
            if r.get(id).is_none() {
                return Err(String::new());
            }
            r.current = Some(id.to_string());
            Ok(())
        })
        .is_ok();
        if ok {
            let was = std::mem::replace(
                &mut *self.env.write().unwrap_or_else(|e| e.into_inner()),
                id.to_string(),
            );
            // Another environment: its history is pulled at once.
            if was != id {
                self.auto_pull.timer.kick();
            }
        }
        ok
    }

    /// `pathwarden ui --state DIR`: the run history folder, over the one
    /// `[state]` in the environment's `pathwarden.toml` names
    /// ([`crate::history_ui`]). It predates environments, so it is the
    /// Default environment's only.
    pub fn state_dir(&self) -> Option<PathBuf> {
        self.state_dir_for(&self.ws())
    }

    /// [`AppState::state_dir`] for the environment `ws` is scoped to.
    pub fn state_dir_for(&self, ws: &Workspace) -> Option<PathBuf> {
        self.jobs.state_dir_for(ws)
    }

    /// A `Cookie` header value for a new session, without a link (for tests
    /// and tools that drive the router directly).
    pub fn session_cookie(&self) -> String {
        let secret = self.sessions.start().expect("random numbers");
        format!("{}={}", self.cookie_name, secret.expose())
    }
}

pub(crate) type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/analyze", get(analyze_page))
        .route("/runs", get(runs_page))
        .route("/runs/{id}", get(run_page))
        .route("/runs/{id}/report", get(report))
        .route(
            "/api/analyze",
            post(start_analysis).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/demo", post(start_demo))
        .route("/api/jobs/{id}", get(job_status))
        // Whether a run is being read into memory (`app.js`).
        .route(
            "/api/busy",
            get(|| async {
                axum::Json(serde_json::json!({ "loading_run": crate::run_data::loading_run() }))
                    .into_response()
            }),
        )
        .route("/api/jobs/{id}/anyway", post(analyze_anyway))
        .route("/api/jobs/{id}/discard", post(discard_duplicate))
        .route("/api/jobs/{id}/place", post(place_job))
        .route("/api/runs/{id}", axum::routing::delete(delete_run))
        .route("/runs/{id}/label", post(label_run))
        .route("/history/{run}/label", post(label_history_run))
        // Where a run goes (Collect and Analyze).
        .merge(crate::env_where::routes())
        .route("/stop", post(stop))
        // The Collect wizard: its pages, API and script.
        .merge(crate::collect::routes())
        // The graph explorer: its page, read-only API and scripts.
        .merge(crate::explore_ui::routes())
        // A run's collection performance and diagnostics bundle.
        .merge(crate::diagnose::routes())
        .route("/static/app.css", get(css))
        .route(
            "/static/app.js",
            get(|| async { asset("text/javascript", APP_JS) }),
        )
        .route(
            "/static/theme.js",
            get(|| async { asset("text/javascript", THEME_JS) }),
        )
        // The report's account lists, for What changed on Home.
        .route(
            "/static/accounts.js",
            get(|| async { asset("text/javascript", pathwarden_core::report::ACCOUNTS_JS) }),
        )
        // Favicons, the web app manifest and its icons (public).
        .merge(crate::brand::routes())
        // Environments: the switcher and the Environments page.
        .merge(crate::environments::routes())
        .merge(crate::connect_ui::routes())
        .merge(crate::encryption_ui::routes())
        // Configuration: Settings, Privilege Zones, Plugins.
        .merge(crate::settings::routes())
        .merge(crate::zones_ui::routes())
        .merge(crate::opengraph_ui::routes())
        .merge(crate::plugins_ui::routes())
        // Retest and Progress.
        .merge(crate::retest_ui::routes())
        // Evidence packs, findings files and the signing key.
        .merge(crate::evidence_ui::routes())
        .merge(crate::progress::routes())
        // Automate: Schedule, Ticketing and alerts, History storage.
        .merge(crate::automate::routes())
        .merge(crate::history_ui::routes())
        .route(
            "/static/config.js",
            get(|| async { asset("text/javascript", CONFIG_JS) }),
        )
        .route("/api/history/pulled", get(crate::auto_pull::pulled_api))
        .fallback(|| async { not_found() })
        .layer(axum::middleware::from_fn(api_errors))
        // After the guard: only a signed-in page checks in.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auto_pull::touch,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::guard,
        ))
        .layer(axum::middleware::from_fn(time_request))
        .with_state(state)
}

/// With `PATHWARDEN_TIMINGS` set, prints each request's path (never its
/// query, which can hold names), status and time to stderr, next to the
/// `[cache]` lines that say when a run was loaded.
async fn time_request(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !pathwarden_core::timing::enabled() {
        return next.run(req).await;
    }
    let line = format!("{} {}", req.method(), req.uri().path());
    let started = std::time::Instant::now();
    let res = next.run(req).await;
    eprintln!(
        "[request] {line} {} {:.2}s",
        res.status().as_u16(),
        started.elapsed().as_secs_f64()
    );
    res
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn css() -> Response {
    static CSS: OnceLock<String> = OnceLock::new();
    let css = CSS.get_or_init(|| {
        format!(
            "{}\n/* ---- UI ---- */\n{UI_CSS}\n/* ---- Configuration ---- */\n{CONFIG_CSS}\n/* ---- Automate ---- */\n{}\n/* ---- Evidence packs ---- */\n{}",
            pathwarden_core::report::REPORT_CSS,
            crate::automate::AUTOMATE_CSS,
            crate::evidence_ui::EVIDENCE_CSS
        )
    });
    ([(header::CONTENT_TYPE, "text/css")], css.as_str()).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response()
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// Every error an `/api/` route answers is `{"error": "<a sentence>"}`,
/// which the pages show: also axum's own rejections of a request body
/// (plain text, 400, 415 or 422) and an unknown route (the HTML Not found
/// page). A body of the wrong shape is a 400.
async fn api_errors(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    let res = next.run(req).await;
    let status = res.status();
    if !path.starts_with("/api/") || !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if json {
        return res;
    }
    let text = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (status, message) = api_error_words(status, &path, &text);
    json_error(status, message)
}

/// [`api_errors`]'s status and sentence for an error answered as `text`.
fn api_error_words(status: StatusCode, path: &str, text: &str) -> (StatusCode, String) {
    let text = text.trim();
    let detail = |prefix: &str| {
        text.strip_prefix(prefix).map(|d| {
            d.trim_start_matches(':')
                .trim()
                .trim_end_matches('.')
                .to_string()
        })
    };
    let sentence = |s: String| {
        if s.ends_with('.') {
            s
        } else {
            format!("{s}.")
        }
    };
    if status == StatusCode::NOT_FOUND && text.starts_with('<') {
        return (status, format!("There is no {path} here."));
    }
    if let Some(d) = detail("Failed to deserialize the JSON body into the target type") {
        return (
            StatusCode::BAD_REQUEST,
            sentence(format!(
                "A value in the request is not of the right kind: {d}"
            )),
        );
    }
    if let Some(d) = detail("Failed to parse the request body as JSON") {
        return (
            StatusCode::BAD_REQUEST,
            sentence(format!("The request is not valid JSON: {d}")),
        );
    }
    if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
        return (
            StatusCode::BAD_REQUEST,
            "The request must be JSON (Content-Type: application/json).".into(),
        );
    }
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return (status, "The request is too large.".into());
    }
    if text.contains("multipart") || text.contains("boundary") {
        return (
            StatusCode::BAD_REQUEST,
            sentence(format!("The upload could not be read: {text}")),
        );
    }
    if text.is_empty() || text.starts_with('<') {
        let words = status.canonical_reason().unwrap_or("The request failed");
        return (status, sentence(words.to_string()));
    }
    let status = if status == StatusCode::UNPROCESSABLE_ENTITY {
        StatusCode::BAD_REQUEST
    } else {
        status
    };
    (status, sentence(text.to_string()))
}

// ------------------------------------------------------------------ pages

async fn home(State(st): State<Shared>) -> Html<String> {
    let runs = st.ws().runs();
    // Each environment card's latest run: its report's Overview, read once.
    // And what each run targeted, for the cards' like-with-like changes:
    // runs saved before their summaries said are read here, off the async
    // threads (once each: the read is cached, failures too).
    let (overviews, runs) = {
        let mut runs = runs;
        let ws = st.ws();
        let flag = st.state_dir_for(&ws);
        let latest: Vec<workspace::RunSummary> = pages::latest_runs(&runs)
            .into_iter()
            .filter_map(|id| runs.iter().find(|r| r.id == id).cloned())
            .collect();
        tokio::task::spawn_blocking(move || {
            // The run history, read once, when a loaded run is among them.
            let history = crate::home_overview::History::new(&ws, flag);
            let mut out = std::collections::HashMap::new();
            for (n, r) in latest.iter().enumerate() {
                let Some(dir) = ws.run_dir(&r.id) else {
                    continue;
                };
                let f = if crate::shared_runs::trusted_run_dir(&dir) {
                    crate::home_overview::of_run(&dir, &r.id, n)
                } else {
                    // A run loaded from the history: made from its data,
                    // never from the repository's HTML.
                    crate::home_overview::of_loaded_run(&dir, r, Some(&history), n)
                };
                if let Some(f) = f {
                    out.insert(r.id.clone(), f);
                }
            }
            for r in runs.iter_mut().filter(|r| r.completeness.is_none()) {
                r.completeness = crate::run_data::completeness(&ws, r);
            }
            (out, runs)
        })
        .await
        .unwrap_or_else(|_| (Default::default(), st.ws().runs()))
    };
    Html(pages::home(
        &pages::Ctx::new(&st, &runs),
        &runs,
        st.jobs.running(),
        analyze::now(),
        &overviews,
    ))
}

#[derive(Deserialize)]
struct AnalyzeQuery {
    job: Option<String>,
    /// A run whose kept collection the files go with.
    from: Option<String>,
}

async fn analyze_page(State(st): State<Shared>, Query(q): Query<AnalyzeQuery>) -> Response {
    let runs = st.ws().runs();
    // Resume a job's progress (from a link on Home), if it exists.
    let job = q
        .job
        .filter(|id| workspace::valid_run_id(id))
        .and_then(|id| st.jobs.get(&id))
        .or_else(|| st.jobs.running());
    // A job that finished before the page was opened: its run, not the
    // steps ticking off again.
    if let Some(crate::jobs::Job {
        status: crate::jobs::JobStatus::Done { run },
        ..
    }) = &job
    {
        if workspace::valid_run_id(run) {
            return axum::response::Redirect::to(&format!("/runs/{run}")).into_response();
        }
    }
    let applies = crate::settings::applies_line(&st, "Analyses here apply");
    let where_html = crate::env_where::render(&st, &[], &[], true).html;
    // Add files and analyze again: only a run whose collection is
    // kept, and still there; otherwise the page as it always is.
    let from = match q.from.filter(|id| workspace::valid_run_id(id)) {
        Some(id) => {
            let ws = st.ws();
            tokio::task::spawn_blocking(move || crate::add_data::find_kept(&ws, &id, true).ok())
                .await
                .ok()
                .flatten()
                .map(|(r, _)| r)
        }
        None => None,
    };
    Html(pages::analyze(
        &pages::Ctx::new(&st, &runs),
        job,
        &applies,
        &where_html,
        from.as_ref(),
    ))
    .into_response()
}

async fn runs_page(
    State(st): State<Shared>,
    Query(landing): Query<crate::connect_ui::LandingQuery>,
) -> Html<String> {
    let runs = st.ws().runs();
    // UI runs and the runs the CLI or a schedule recorded in the history.
    let (rows, note, gate) = {
        let ws = st.ws();
        let flag = st.state_dir();
        let runs = runs.clone();
        tokio::task::spawn_blocking(move || {
            let snap = crate::history_ui::snapshot(&ws, flag.as_deref());
            let loc = snap.location.as_ref().ok();
            let env = ws.env_id().to_string();
            (
                crate::history_ui::run_rows(&ws, &runs, &snap),
                crate::history_ui::runs_note(&ws, &runs, &snap),
                // The passphrase, or older copies refused: after
                // the history was read.
                loc.and_then(crate::encryption_ui::gate)
                    .or_else(|| loc.and_then(|l| crate::history_ui::accept_card(l, &env)))
                    .unwrap_or_default(),
            )
        })
        .await
        .unwrap_or_default()
    };
    // Just connected to a run history: what was loaded, once.
    let gate = match crate::connect_ui::landing_note(&landing) {
        Some(n) => format!("{n}{gate}"),
        None => gate,
    };
    Html(pages::runs(
        &pages::Ctx::new(&st, &runs),
        &runs,
        &rows,
        &note,
        &gate,
    ))
}

/// The small run page of a history run with no full run
/// ([`crate::run_list::point_page`]): never Progress in its place.
async fn point_page(st: &Shared, id: String) -> Response {
    let runs = st.ws().runs();
    let page = {
        let ws = st.ws();
        let flag = st.state_dir();
        let runs = runs.clone();
        tokio::task::spawn_blocking(move || {
            let snap = crate::history_ui::snapshot(&ws, flag.as_deref());
            match crate::run_list::point_page(&ws, &runs, &snap, &id) {
                Some(p) => Some(Ok(p)),
                // Encrypted and not opened here (a link kept from before):
                // the gate, as on Runs.
                None => snap
                    .location
                    .as_ref()
                    .ok()
                    .and_then(|l| {
                        crate::encryption_ui::gate_with(
                            l,
                            crate::encryption_ui::GATE_LEAD_RUN,
                            false,
                        )
                    })
                    .map(Err),
            }
        })
        .await
        .ok()
        .flatten()
    };
    let page = match page {
        Some(Ok(p)) => p,
        Some(Err(gate)) => {
            let body = format!(
                r#"<div class="page-head"><div><h1 class="panel-title">Run</h1></div></div>{gate}"#
            );
            return Html(pages::shell(
                &pages::Ctx::new(st, &runs),
                Some(pages::Nav::Runs),
                "Run",
                "",
                &body,
            ))
            .into_response();
        }
        None => return not_found(),
    };
    let ws = st.ws();
    let env_id = ws.env_id().to_string();
    let env_name = st.workspace.named_registry().name_of(&env_id);
    let body = crate::run_list::point_page_html(&page, (&env_id, &env_name));
    Html(pages::shell(
        &pages::Ctx::new(st, &runs),
        Some(pages::Nav::Runs),
        &page.row.summary.title(),
        "",
        &body,
    ))
    .into_response()
}

async fn run_page(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<RunPageQuery>,
) -> Response {
    let said = q.signin.as_deref().and_then(crate::sign_in::said);
    // Passed on to the report frame, which says it too.
    let signin = said.and(q.signin.clone());
    let Some(summary) = st.workspace.run(&id) else {
        // The history's run ID (what the command line prints) opens the
        // run's page too.
        return match st.workspace.find_run(&id) {
            Some(folder) => (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, format!("/runs/{folder}"))],
            )
                .into_response(),
            // A run the history has with no full run: its small page.
            None if workspace::looks_like_history_id(&id) => point_page(&st, id).await,
            None => not_found(),
        };
    };
    // A run's page is about its own environment (its runs, settings and
    // accepted risks), whichever is current.
    let run_ws = st.workspace.for_run(&summary);
    let runs = run_ws.runs();
    let env_note = crate::environments::run_note(&st, &run_ws);
    let env_id = run_ws.env_id().to_string();
    let env_name = st.workspace.named_registry().name_of(&env_id);
    // The dialogs read a few small files from the run and the config.
    // Collection performance and the settings the next analysis applies
    // are on the report's Run details tab ([`run_details_panel`]), or below
    // the report when it can't carry the tab.
    let (parts, details) = {
        let st = st.clone();
        let mut summary = summary.clone();
        let done = tokio::task::spawn_blocking(move || {
            crate::run_details::with_sources(&st.workspace, &mut summary);
            let (perf, applies, remove) = run_details_of(&st, &summary);
            // No nonce (no randomness): Run details below the report.
            let nonce = crate::run_details::try_nonce();
            let carries = nonce.is_some() && report_carries_details(&st, &summary);
            // Below the report when it can't carry the tab. A run loaded
            // from the history whose report carries it gets the same copy
            // hidden, shown only if the tab can't be seen (its report could
            // hide it): one Run details either way.
            let below = if !carries {
                Some(crate::run_details::below_html(
                    &summary, perf, &applies, remove, said,
                ))
            } else if summary.shared.is_some() {
                Some(crate::run_details::fallback_html(
                    &summary, perf, &applies, remove, said,
                ))
            } else {
                None
            };
            (
                crate::retest_ui::page_parts(&st, &summary),
                crate::run_details::PageDetails {
                    remove,
                    nonce: nonce.unwrap_or_default(),
                    carries,
                    below,
                    said,
                    signin,
                },
            )
        })
        .await;
        match done {
            Ok(v) => v,
            Err(_) => return not_found(),
        }
    };
    // Older copies refused in this environment's history, as the
    // run's files were read: accepting acts on the environment in use.
    let env_note = if run_ws.env_id() == st.env_id() {
        let flag = st.state_dir_for(&run_ws);
        let ws = run_ws.clone();
        let card = tokio::task::spawn_blocking(move || {
            crate::history_ui::locate(&ws, flag.as_deref())
                .ok()
                .and_then(|l| crate::history_ui::accept_card(&l, ws.env_id()))
        })
        .await
        .ok()
        .flatten();
        format!("{env_note}{}", card.unwrap_or_default())
    } else {
        env_note
    };
    Html(pages::run(
        &pages::Ctx::new(&st, &st.ws().runs()),
        &summary,
        &runs,
        &parts,
        &env_note,
        (&env_id, &env_name),
        &details,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct ReportQuery {
    download: Option<String>,
    theme: Option<String>,
    embed: Option<String>,
    /// The run page's nonce for the Run details tab
    /// ([`crate::run_details::try_nonce`]).
    rd: Option<String>,
    /// How Sign in went, after the run page loaded again from it
    /// ([`crate::sign_in::Outcome::key`]).
    signin: Option<String>,
}

/// The run page's query: how Sign in went, after it loaded again from it.
#[derive(Deserialize, Default)]
struct RunPageQuery {
    signin: Option<String>,
}

/// Inside the app the report drops its own rail (the app already shows the
/// logo, environment and theme) and puts its tabs in a bar across the top.
/// The app sizes the frame to the report, so nothing in it is at least a
/// screen tall, and the tab bar is pinned by the embed script
/// (`report-retest.js`) rather than by `position: sticky`. On a phone the
/// tabs wrap, so every one stays in view. The hero's glows are dropped: the
/// app's page already glows around the frame.
pub(crate) const EMBED_STYLE: &str = "<style>\
.shell{display:block;min-height:0}\
.rail{position:relative;top:0;z-index:3;height:auto;display:block;overflow:visible;\
padding:0 clamp(16px,4vw,52px);border-right:none;border-bottom:1px solid var(--line);background:var(--rail)}\
.rail::after,.brand,.meta,.rail-foot{display:none!important}\
.tabs{position:static;padding:0;border:none}\
.tablist{flex-direction:row;gap:2px;overflow-x:auto;scrollbar-width:none}\
.tablist a{padding:12px 12px 10px;white-space:nowrap;border-radius:0;background:transparent!important}\
.tablist a[aria-selected=\"true\"]::before{left:10px;right:10px;top:auto;bottom:0;width:auto;height:3px;border-radius:3px 3px 0 0}\
main{max-width:none;padding-top:26px}\
.panel-title{font-size:1.5rem}\
.hero::before,.hero::after{display:none}\
details.row{scroll-margin-top:60px}\
@media (max-width:640px){.tablist{flex-wrap:wrap;overflow-x:visible;row-gap:0}\
.tablist a{padding:10px 8px 9px;gap:7px}.tablist a .ic{width:16px;height:16px}main{padding-top:18px}}\
</style></head>";

/// What Run details shows of `summary`, in its own environment (blocking):
/// its collection performance (slower or not), the settings line, and how
/// it is removed. A run loaded from the history is hidden, not removed, on
/// a computer that only reads the history: the same state Delete reads.
fn run_details_of(
    st: &AppState,
    summary: &workspace::RunSummary,
) -> (
    Option<bool>,
    Result<String, String>,
    crate::run_details::Remove,
) {
    let run_ws = st.workspace.for_run(summary);
    let reads_only = summary.shared.is_some()
        && crate::history_ui::locate(&run_ws, st.state_dir_for(&run_ws).as_deref())
            .is_ok_and(|l| !l.records());
    let (perf, applies) = crate::run_details::perf_and_applies(&st.workspace, summary);
    (
        perf,
        applies,
        crate::run_details::Remove::of(summary, reads_only),
    )
}

/// The Run details tab's panel for `summary` ([`crate::run_details`]),
/// carrying the run page's `nonce`, and whether a row needs a look (the
/// tab's dot) (blocking).
fn run_details_panel(
    st: &AppState,
    summary: &workspace::RunSummary,
    nonce: &str,
    said: Option<crate::sign_in::Outcome>,
) -> (String, bool) {
    let (perf, applies, remove) = run_details_of(st, summary);
    let dot = crate::run_details::needs_a_look(&crate::run_details::rows(summary, perf, &applies));
    (
        crate::run_details::panel_html(summary, perf, &applies, remove, nonce, said),
        dot,
    )
}

/// Whether the embedded report of `summary` carries the Run details tab:
/// it has a report, as the frame gets it, that
/// [`crate::run_details::can_inject`] takes (blocking).
fn report_carries_details(st: &AppState, summary: &workspace::RunSummary) -> bool {
    let Some(dir) = st.ws().run_dir(&summary.id) else {
        return false;
    };
    match std::fs::read_to_string(dir.join(REPORT_FILE)) {
        Ok(html) => {
            crate::run_details::can_inject(&crate::run_list::report_as_now(html, Some(summary)))
        }
        Err(_) => false,
    }
}

/// The app's own origin as this request named it (the guard has already
/// checked `Host`): where an embedded report may send its retest requests.
fn app_origin(st: &AppState, headers: &HeaderMap) -> String {
    if let Some(origin) = st.transport.embedded_origin() {
        return origin.to_string();
    }
    let name = match headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("localhost:") => "localhost",
        _ => "127.0.0.1",
    };
    format!("http://{name}:{}", st.port)
}

/// The policy a downloaded report of a loaded run carries in its own
/// `<meta>`: no script, no frame, no form, nothing fetched but its own
/// inline styles and `data:` images and fonts.
pub const DOWNLOAD_POLICY: &str = "default-src 'none'; script-src 'none'; object-src 'none'; \
     style-src 'unsafe-inline'; img-src data:; font-src data:; form-action 'none'; base-uri 'none'";

/// `html` with [`DOWNLOAD_POLICY`] as its first element: right after the
/// doctype when it starts with one (so the page keeps its mode), else at
/// the very start. A policy in `<meta>` covers what comes after it, so
/// nothing in the file comes before it.
pub fn with_download_policy(html: &str) -> String {
    let meta =
        format!(r#"<meta http-equiv="Content-Security-Policy" content="{DOWNLOAD_POLICY}">"#);
    let body = html.strip_prefix('\u{feff}').unwrap_or(html);
    let lead = body.len() - body.trim_start().len();
    let rest = &body[lead..];
    let doctype = rest
        .get(..9)
        .is_some_and(|s| s.eq_ignore_ascii_case("<!doctype"))
        .then(|| rest.find('>'))
        .flatten();
    match doctype {
        Some(end) => {
            let at = lead + end + 1;
            format!("{}{meta}{}", &body[..at], &body[at..])
        }
        None => format!("{meta}{body}"),
    }
}

async fn report(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<ReportQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(dir) = st.ws().run_dir(&id) else {
        return not_found();
    };
    let Ok(html) = tokio::fs::read_to_string(dir.join(REPORT_FILE)).await else {
        return not_found();
    };
    let summary = st.workspace.summary(&id);
    // A run loaded from the history never runs a script of the repository's:
    // only the report script Pathwarden wrote, or none. Decided from the
    // folder, failing closed ([`crate::shared_runs::trusted_run_dir`]).
    let trusted = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || crate::shared_runs::trusted_run_dir(&dir))
            .await
            .unwrap_or(false)
    };
    let mut html = crate::run_list::report_as_now(html, summary.as_ref());
    // The report starts dark and remembers a choice in localStorage, which a
    // sandboxed frame cannot use: start it in the app's theme instead.
    if q.theme.as_deref() == Some("light") {
        html = html.replacen(
            r#"<html lang="en" data-theme="dark">"#,
            r#"<html lang="en" data-theme="light">"#,
            1,
        );
    }
    // Inside the app, each open finding gets a Retest button: the app adds
    // the script and its data here (see `retest_ui::embed_report`).
    let mut csp = None;
    if q.embed.is_some() {
        let nonce =
            q.rd.filter(|n| crate::run_details::valid_nonce(n))
                .unwrap_or_default();
        let said = q.signin.as_deref().and_then(crate::sign_in::said);
        let (meta, details) = match st.ws().run(&id) {
            Some(mut summary) => {
                let st = st.clone();
                let origin = app_origin(&st, &headers);
                let nonce = nonce.clone();
                tokio::task::spawn_blocking(move || {
                    crate::run_details::with_sources(&st.workspace, &mut summary);
                    let meta = crate::retest_ui::report_meta(&st, &summary, &origin);
                    (meta, Some(run_details_panel(&st, &summary, &nonce, said)))
                })
                .await
                .unwrap_or_default()
            }
            None => (String::new(), None),
        };
        // The Run details tab, only when the app's script comes with it (it
        // carries the tab's buttons to this page); else the run page shows
        // Run details below the report ([`report_carries_details`]).
        let carries = crate::run_details::can_inject(&html);
        let style = format!("{}{}", crate::run_details::CSS, EMBED_STYLE);
        let (page, policy) = crate::retest_ui::embed_report(&html, &meta, &style, trusted);
        html = match details {
            Some((panel, dot)) if carries => crate::run_details::inject(&page, &panel, dot, &nonce),
            _ => page,
        };
        csp = HeaderValue::from_str(&policy).ok();
    } else if !trusted {
        csp = HeaderValue::from_str(&crate::retest_ui::report_csp_for(&html, false)).ok();
    }
    // Saved to disk, a file has no response headers: a loaded run's report
    // carries its own policy, so no script of the repository's runs and
    // nothing is fetched when it is opened from there.
    if q.download.is_some() && !trusted {
        html = with_download_policy(&html);
    }
    let mut r = Html(html).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        csp.unwrap_or(HeaderValue::from_static(security::REPORT_CSP)),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    if q.download.is_some() {
        let name = match &summary {
            Some(s) => workspace::report_file_name(s, &st.workspace.for_run(s).env_name()),
            None => format!("pathwarden-report-{}.html", &id[..15]),
        };
        if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
            h.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    r
}

// -------------------------------------------------------------------- API

/// Stop (the rail's button): signs every browser out and stops the server.
/// Using Pathwarden again takes a new link from `pathwarden ui`.
async fn stop(State(st): State<Shared>) -> Response {
    st.sessions.end_all();
    crate::launch::discard(&st);
    st.stop.notify_one();
    let mut r = (
        StatusCode::OK,
        Html(pages::bare_page(
            "Pathwarden has stopped",
            "You are signed out and the server is stopping. You can close this tab. Start Pathwarden again to use it.",
        )),
    )
        .into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(security::BARE_CSP),
    );
    if let Ok(v) = HeaderValue::from_str(&security::clear_cookie(&st)) {
        h.insert(header::SET_COOKIE, v);
    }
    r
}

async fn job_status(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    match st.jobs.get(&id) {
        Some(job) => {
            if let jobs::JobStatus::Done { run } = &job.status {
                follow_first_run(&st, run);
            }
            Json(job).into_response()
        }
        None => json_error(StatusCode::NOT_FOUND, "No such job."),
    }
}

/// A real run finished while the demo (or nothing yet) was current: the
/// app switches to the run's environment, so the first collection's
/// environment is the one shown.
fn follow_first_run(st: &AppState, run: &str) {
    let Some(s) = st.workspace.summary(run) else {
        return;
    };
    if s.demo {
        return;
    }
    let reg = st.workspace.registry();
    let current = st.env_id();
    let target = crate::environments::run_env(&reg, &s);
    let idle = reg.demo_id() == Some(current.as_str())
        || (current == DEFAULT_ENV
            && reg.default_unused(
                st.workspace.root(),
                &crate::environments::run_domains(&reg, &st.workspace.all_runs()),
            ));
    if target != current && idle {
        st.set_env(&target);
    }
}

async fn delete_run(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    if !workspace::valid_run_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid run.");
    }
    // Its point in the run history goes too (history_ui::delete_run, the
    // same as `pathwarden history --forget`).
    let ws = st.ws();
    let flag = ws
        .summary(&id)
        .and_then(|r| st.state_dir_for(&ws.for_run(&r)));
    let result = tokio::task::spawn_blocking(move || {
        crate::history_ui::delete_run(&ws, flag.as_deref(), &id)
    })
    .await
    .unwrap_or_else(|_| Err("Deleting failed.".into()));
    match result {
        // Deleted, with something about the history the user should read.
        Ok(d) if d.folder && !d.notes.is_empty() => {
            axum::Json(serde_json::json!({ "note": d.notes.join(" ") })).into_response()
        }
        Ok(d) if d.folder => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => json_error(StatusCode::NOT_FOUND, "That run no longer exists."),
        Err(e) => json_error(StatusCode::CONFLICT, e),
    }
}

fn busy() -> Response {
    json_error(
        StatusCode::CONFLICT,
        "Pathwarden is already collecting or analyzing. Wait for it to finish, then try again.",
    )
}

/// Registers and starts a job; the response names it for polling. With
/// `check_duplicate`, a collection already analyzed stops for the user to
/// decide (see [`jobs::JobStatus::Duplicate`]).
fn begin(st: &AppState, spec: JobSpec, check_duplicate: bool) -> Response {
    if !st.jobs.try_begin(&spec) {
        spec.remove_uploads(false);
        return busy();
    }
    let id = spec.id.clone();
    jobs::spawn(
        st.jobs.clone(),
        st.ws(),
        spec,
        st.keep_uploads,
        check_duplicate,
    );
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "job": id }))).into_response()
}

/// "Analyze anyway" after a duplicate warning: the same inputs, unchecked.
async fn analyze_anyway(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    match st.jobs.take_pending(&id) {
        Some(mut spec) => {
            // Asked for: not checked again after an environment is picked.
            spec.force = true;
            begin(&st, spec, false)
        }
        None => json_error(StatusCode::NOT_FOUND, "That analysis is no longer waiting."),
    }
}

/// "Open that run" after a duplicate warning: the kept upload is deleted.
async fn discard_duplicate(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    if let Some(spec) = st.jobs.take_pending(&id) {
        let keep = st.keep_uploads;
        tokio::task::spawn_blocking(move || spec.remove_uploads(keep))
            .await
            .ok();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn start_demo(State(st): State<Shared>) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    // The demo has its own environment, and the app switches to it.
    let root = st.workspace.root().to_path_buf();
    let demo = match crate::environments::Registry::update(&root, |r| Ok(r.ensure_demo())) {
        Ok(id) => id,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Couldn't prepare the demo: {e}"),
            )
        }
    };
    st.set_env(&demo);
    let id = workspace::new_run_id(analyze::now());
    let scratch = st.ws().uploads_dir().join(&id);
    let file = scratch.join(DEMO_NAME);
    let written = async {
        tokio::fs::create_dir_all(&scratch).await?;
        tokio::fs::write(&file, DEMO_ZIP).await
    }
    .await;
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&scratch);
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't prepare the demo: {e}"),
        );
    }
    begin(
        &st,
        JobSpec {
            id,
            inputs: vec![file],
            scratch: Some(scratch),
            also_scratch: None,
            source: crate::jobs::DEMO_SOURCE.into(),
            demo: true,
            // Made-up data: always the demo's own environment.
            env: Some(demo),
            new_env: None,
            env_auto: false,
            label: None,
            collection: None,
            timings: None,
            force: true,
        },
        false,
    )
}

#[derive(Deserialize)]
struct PlaceBody {
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    new_env: Option<String>,
}

/// After [`jobs::JobStatus::Ask`]: the same inputs, analyzed into the
/// environment the user picked.
async fn place_job(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<PlaceBody>,
) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    let (env, new_env) =
        match check_choice(&st, body.env.as_deref(), body.new_env.as_deref(), false) {
            Ok(Some(c)) => c,
            Ok(None) => return json_error(StatusCode::BAD_REQUEST, "Choose an environment."),
            Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
        };
    match st.jobs.take_pending(&id) {
        Some(mut spec) => {
            spec.env = env;
            spec.new_env = new_env;
            spec.env_auto = false;
            // "Re-analyze" (or "Analyze anyway") still holds.
            let check = !spec.force;
            begin(&st, spec, check)
        }
        None => json_error(StatusCode::NOT_FOUND, "That analysis is no longer waiting."),
    }
}

/// A choice from a page: an existing environment (by ID; not the demo's),
/// or a new one by a valid name (one not taken, unless the page made the
/// choice by itself: a taken computed name then gets a number).
pub(crate) type EnvChoice = (Option<String>, Option<String>);

pub(crate) fn check_choice(
    st: &AppState,
    env: Option<&str>,
    new_env: Option<&str>,
    auto: bool,
) -> Result<Option<EnvChoice>, String> {
    let reg = st.workspace.registry();
    match (
        env.map(str::trim).filter(|v| !v.is_empty() && *v != "auto"),
        new_env.map(str::trim).filter(|v| !v.is_empty()),
    ) {
        (Some(id), _) => match reg.get(id) {
            Some(e) if !e.demo => Ok(Some((Some(id.to_string()), None))),
            _ => Err("That environment no longer exists. Reload the page.".into()),
        },
        (None, Some(name)) => {
            let name = crate::environments::clean_name(name)?;
            if !auto
                && reg
                    .find(&name)
                    .is_some_and(|e| e.name.eq_ignore_ascii_case(&name))
            {
                return Err(format!("There is already an environment named {name}."));
            }
            Ok(Some((None, Some(name))))
        }
        (None, None) => Ok(None),
    }
}

#[derive(Deserialize)]
struct LabelForm {
    #[serde(default)]
    label: String,
    #[serde(default)]
    back: String,
}

/// Where a label form goes back to: the Runs list or the run's page.
fn label_back(back: &str, run: &str) -> String {
    match back {
        "/runs" => "/runs".into(),
        _ => format!("/runs/{run}"),
    }
}

/// Sets or clears a UI run's label (the Runs list and the run page).
async fn label_run(
    State(st): State<Shared>,
    Path(id): Path<String>,
    axum::Form(f): axum::Form<LabelForm>,
) -> Response {
    let label = match workspace::clean_label(&f.label) {
        Ok(l) => l,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let Some(summary) = st.workspace.summary(&id) else {
        return json_error(StatusCode::NOT_FOUND, "That run no longer exists.");
    };
    let ws = st.workspace.for_run(&summary);
    match workspace::set_run_label(&ws, &id, label.as_deref()) {
        Ok(_) => axum::response::Redirect::to(&label_back(&f.back, &id)).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Sets or clears the label of a run the command line or a schedule
/// recorded in the current environment's history.
async fn label_history_run(
    State(st): State<Shared>,
    Path(run): Path<String>,
    axum::Form(f): axum::Form<LabelForm>,
) -> Response {
    if !workspace::looks_like_history_id(&run) {
        return json_error(StatusCode::BAD_REQUEST, "Invalid run.");
    }
    let label = match workspace::clean_label(&f.label) {
        Ok(l) => l,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    match workspace::set_later_label(&st.ws(), &run, label.as_deref()) {
        Ok(()) => axum::response::Redirect::to("/runs").into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// An upload's file name, reduced to safe characters. Only `.zip` and
/// `.json` are accepted. Digits are kept, since collectors put the collection
/// time in the name.
pub fn safe_file_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut name: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    name = name.trim_start_matches('.').to_string();
    if name.len() > 150 {
        name = name[name.len() - 150..].to_string();
    }
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".zip") || lower.ends_with(".json")).then_some(name)
}

/// A path typed or pasted by the user: surrounding quotes (as Windows'
/// "Copy as path" adds) and spaces removed.
fn clean_path(raw: &str) -> &str {
    raw.trim().trim_matches('"').trim()
}

/// Uploaded files (streamed to disk, never held in memory) and/or a local
/// path. Field `files` carries files; field `path` a file or folder.
async fn start_analysis(State(st): State<Shared>, mut form: Multipart) -> Response {
    if st.jobs.running().is_some() {
        return busy();
    }
    let id = workspace::new_run_id(analyze::now());
    let scratch = st.ws().uploads_dir().join(&id);
    match receive(&st, &scratch, &mut form).await {
        Ok(r) => {
            let uploaded = scratch.exists();
            // Added to a run's collection on purpose: never "already
            // analyzed", as the collection's directory data is the same.
            let force = r.force || r.from.is_some();
            begin(
                &st,
                JobSpec {
                    id,
                    inputs: r.inputs,
                    scratch: uploaded.then_some(scratch),
                    also_scratch: None,
                    source: r.source,
                    demo: false,
                    env: r.env,
                    new_env: r.new_env,
                    env_auto: r.env_auto,
                    label: r.label,
                    // Analyzed again from a run's kept collection:
                    // how it was collected, and where it is kept.
                    collection: r.from.and_then(|f| f.collection),
                    timings: None,
                    force,
                },
                !force,
            )
        }
        Err(message) => {
            let _ = tokio::fs::remove_dir_all(&scratch).await;
            json_error(StatusCode::BAD_REQUEST, message)
        }
    }
}

fn gb(bytes: u64) -> String {
    let g = bytes as f64 / (1u64 << 30) as f64;
    if g >= 1.0 {
        format!("{g:.0} GB")
    } else {
        format!("{} MB", bytes >> 20)
    }
}

/// The most the Analyze form's `path` field may hold (Windows paths reach
/// 32,767 characters with `\\?\`; anything longer is not a path).
pub const MAX_PATH_FIELD: usize = 32 * 1024;

/// What an Analyze form asked for.
pub(crate) struct Received {
    pub(crate) inputs: Vec<PathBuf>,
    /// Field `from`: the run whose kept collection is analyzed with the
    /// files.
    from: Option<workspace::RunSummary>,
    /// The source in words.
    source: String,
    /// Analyze even a collection already analyzed (field `force`, from
    /// "Re-analyze").
    force: bool,
    /// Field `env` (an environment's ID; empty or `auto` lets the data's
    /// domains decide) or field `new_env` (a new environment's name).
    env: Option<String>,
    new_env: Option<String>,
    /// Field `env_auto`: the page made the choice by itself.
    env_auto: bool,
    /// Field `label`.
    label: Option<String>,
}

/// Reads an Analyze form ([`Received`]): uploaded files are streamed into
/// `scratch`, a folder each; `path` fields are checked and read where they
/// are; `from` names a run whose kept collection goes first.
pub(crate) async fn receive(
    st: &AppState,
    scratch: &FsPath,
    form: &mut Multipart,
) -> Result<Received, String> {
    let mut inputs = Vec::new();
    let mut uploaded = Vec::new();
    let mut path_source = None;
    let mut total = 0u64;
    let mut force = false;
    let mut env = None;
    let mut new_env = None;
    let mut env_auto = false;
    let mut label = None;
    let mut declarations = Vec::new();
    let mut from = None;
    let mut typed = Vec::new();
    loop {
        let field = match form.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Err(format!("The upload was interrupted: {}", e.body_text())),
        };
        match field.name() {
            Some("force") => force = true,
            Some("env") => env = Some(short_text(field).await?),
            Some("new_env") => new_env = Some(short_text(field).await?),
            Some("env_auto") => env_auto = short_text(field).await? == "1",
            Some("label") => label = workspace::clean_label(&short_text(field).await?)?,
            Some("from") => {
                // A run's kept collection, found by the run's ID:
                // never a path the page sends.
                let id = short_text(field).await?.trim().to_string();
                if id.is_empty() || from.is_some() {
                    continue;
                }
                if !workspace::valid_run_id(&id) {
                    return Err("That run doesn't exist.".into());
                }
                let ws = st.ws();
                let (run, dir) =
                    tokio::task::spawn_blocking(move || crate::add_data::find_kept(&ws, &id, true))
                        .await
                        .map_err(|_| "Finding the collection failed.".to_string())??;
                inputs.insert(0, dir);
                from = Some(run);
            }
            Some("coverage") => {
                // Coverage declarations for uploaded OpenGraph files.
                let mut raw = Vec::new();
                let mut field = field;
                loop {
                    match field.chunk().await {
                        Ok(Some(c)) => {
                            if raw.len() + c.len() > crate::opengraph_ui::MAX_DECLARATION_BYTES {
                                return Err("The coverage declaration is too long.".into());
                            }
                            raw.extend_from_slice(&c);
                        }
                        Ok(None) => break,
                        Err(_) => return Err("The upload was interrupted.".into()),
                    }
                }
                if !raw.iter().all(u8::is_ascii_whitespace) {
                    let mut list: Vec<crate::opengraph_ui::DeclaredFile> =
                        serde_json::from_slice(&raw)
                            .map_err(|e| format!("The coverage declaration is not valid: {e}"))?;
                    declarations.append(&mut list);
                }
            }
            Some("path") => {
                // A path is short: read at most MAX_PATH_FIELD bytes of it
                // (this route has no overall body limit, for uploads).
                let mut raw = Vec::new();
                let mut field = field;
                loop {
                    match field.chunk().await {
                        Ok(Some(c)) => {
                            if raw.len() + c.len() > MAX_PATH_FIELD {
                                return Err("That path is too long.".into());
                            }
                            raw.extend_from_slice(&c);
                        }
                        Ok(None) => break,
                        Err(_) => return Err("The upload was interrupted.".into()),
                    }
                }
                let text = String::from_utf8(raw)
                    .map_err(|_| "That path is not valid text.".to_string())?;
                let p = clean_path(&text);
                if p.is_empty() {
                    continue;
                }
                // Before anything looks at it: checking that a network path
                // exists already signs in to that server as the user, and a
                // mapped network drive is read from it.
                if security::is_remote_path(p) {
                    return Err(format!(
                        "{p} is a network path. Copy the files to this computer first, or upload them."
                    ));
                }
                let path = PathBuf::from(p);
                if !path.exists() {
                    return Err(format!(
                        "Nothing found at {p}. Check the path and try again."
                    ));
                }
                path_source.get_or_insert_with(|| path.display().to_string());
                typed.push(path.display().to_string());
                inputs.push(path);
            }
            Some("files") => {
                let raw = field.file_name().unwrap_or_default().to_string();
                if raw.is_empty() {
                    continue;
                }
                let Some(name) = safe_file_name(&raw) else {
                    return Err(format!(
                        "{raw} is not a .zip or .json file. Use the output of SharpHound or RustHound-CE."
                    ));
                };
                // Each file in its own folder keeps names as they were.
                let dir = scratch.join(uploaded.len().to_string());
                tokio::fs::create_dir_all(&dir)
                    .await
                    .map_err(|e| format!("Couldn't save the upload: {e}"))?;
                let dest = dir.join(&name);
                let mut out = tokio::fs::File::create(&dest)
                    .await
                    .map_err(|e| format!("Couldn't save the upload: {e}"))?;
                let mut size = 0u64;
                let mut field = field;
                loop {
                    let chunk = match field.chunk().await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(_) => return Err("The upload was interrupted.".into()),
                    };
                    size += chunk.len() as u64;
                    total += chunk.len() as u64;
                    if size > st.limits.per_file {
                        return Err(format!(
                            "{name} is larger than {}, the most one file can be.",
                            gb(st.limits.per_file)
                        ));
                    }
                    if total > st.limits.total {
                        return Err(format!(
                            "These files add up to more than {}, the most one analysis can take.",
                            gb(st.limits.total)
                        ));
                    }
                    out.write_all(&chunk)
                        .await
                        .map_err(|e| format!("Couldn't save the upload: {e}"))?;
                }
                out.flush()
                    .await
                    .map_err(|e| format!("Couldn't save the upload: {e}"))?;
                uploaded.push(name);
                inputs.push(dest);
            }
            _ => {}
        }
    }
    if inputs.is_empty() {
        return Err("Choose collector files to upload, or enter a file or folder path.".into());
    }
    if !declarations.is_empty() {
        // Bound to the bytes received, by SHA-256 (blocking reads).
        let files: Vec<PathBuf> = inputs
            .iter()
            .filter(|p| p.starts_with(scratch))
            .cloned()
            .collect();
        let packs = crate::opengraph_ui::packs(st).0;
        let now = analyze::now();
        tokio::task::spawn_blocking(move || {
            crate::opengraph_ui::write_declarations(&declarations, &files, &packs, now)
        })
        .await
        .map_err(|_| "Writing the coverage file failed.".to_string())??;
    }
    // Several paths (picked or dropped in the desktop window): the first.
    let paths = typed.len();
    let path_source = path_source.map(|p| match paths {
        0 | 1 => p,
        n => format!("{p} and {} more", n - 1),
    });
    let source = match (&from, uploaded.as_slice(), path_source) {
        // A run's collection, with what was added to it.
        (Some(r), ..) => {
            let added: Vec<String> = typed.iter().chain(uploaded.iter()).cloned().collect();
            crate::add_data::source_with(&r.source, &added)
        }
        (None, [], Some(p)) => p,
        (None, [one], None) => one.clone(),
        (None, files, None) => format!("{} uploaded files", files.len()),
        (None, files, Some(p)) => format!("{p} and {} uploaded file(s)", files.len()),
    };
    let (env, new_env) =
        check_choice(st, env.as_deref(), new_env.as_deref(), env_auto)?.unwrap_or_default();
    Ok(Received {
        inputs,
        from,
        source,
        force,
        env,
        new_env,
        env_auto,
        label,
    })
}

/// A short text field (an ID, a name, a label), at most 1 KB.
async fn short_text(mut field: axum::extract::multipart::Field<'_>) -> Result<String, String> {
    let mut raw = Vec::new();
    loop {
        match field.chunk().await {
            Ok(Some(c)) => {
                if raw.len() + c.len() > 1024 {
                    return Err("A field of the form is too long.".into());
                }
                raw.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(_) => return Err("The upload was interrupted.".into()),
        }
    }
    String::from_utf8(raw).map_err(|_| "A field of the form is not valid text.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loaded run's report, downloaded, carries its own policy before
    /// anything else in it, after the doctype when it has one.
    #[test]
    fn a_downloaded_loaded_report_carries_its_policy_first() {
        let meta =
            format!(r#"<meta http-equiv="Content-Security-Policy" content="{DOWNLOAD_POLICY}">"#);
        assert!(DOWNLOAD_POLICY.contains("script-src 'none'"));
        assert_eq!(
            with_download_policy("<!DOCTYPE html>\n<html><script>x</script>"),
            format!("<!DOCTYPE html>{meta}\n<html><script>x</script>")
        );
        assert_eq!(
            with_download_policy("\u{feff}  <!doctype html><p>"),
            format!("  <!doctype html>{meta}<p>")
        );
        assert_eq!(
            with_download_policy("<script>x</script><!doctype html>"),
            format!("{meta}<script>x</script><!doctype html>")
        );
        assert_eq!(with_download_policy(""), meta);
    }

    #[test]
    fn file_names() {
        assert_eq!(
            safe_file_name("20240410083609_BloodHound.zip").as_deref(),
            Some("20240410083609_BloodHound.zip")
        );
        assert_eq!(
            safe_file_name(r"C:\x\..\evil name.JSON").as_deref(),
            Some("evil_name.JSON")
        );
        assert_eq!(safe_file_name("../../a.zip").as_deref(), Some("a.zip"));
        assert_eq!(safe_file_name("..zip"), None);
        assert_eq!(safe_file_name("report.exe"), None);
        assert_eq!(safe_file_name(""), None);
    }

    #[test]
    fn paths() {
        assert_eq!(clean_path("  \"C:\\data\\x.zip\" "), "C:\\data\\x.zip");
    }
}
