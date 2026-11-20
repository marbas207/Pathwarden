//! Finding actions in the app: the run page's action dialog and its
//! progress view, the actions API, and the Finding actions section of
//! Plugins and actions (add, remove, Test).
//!
//! **The channel from the report.** As for Retest and Accept risk
//! (`run.js`, `retest.js`): a click on an action's button in the embedded
//! report sends the run page one message, `{type: "pathwarden:action",
//! fingerprint, action, record}`. The page (`assets/actions.js`) accepts it
//! only from the report's frame, only with a well-formed fingerprint of a
//! finding the server listed on the dialog (`data-findings`), and only for
//! an action the server offered on it (or a follow-up on that record). It
//! only opens the dialog: nothing runs until the user clicks Run.
//!
//! **What the program says is text.** Progress lines, messages, records
//! and links are shown with `textContent`; links are `https://` only
//! ([`pathwarden_core::actions::parse_result`]).
//!
//! **One at a time.** An action runs as a job ([`crate::jobs`]), polled at
//! `/api/jobs/{id}`: a second while one runs is refused (429), as is one
//! during a collection or an analysis (409). The CLI's `pathwarden action`
//! runs the same shared functions ([`crate::actions_ui`]).

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use pathwarden_core::actions::{self, Ask, CancelHandle};
use pathwarden_core::config::ActionConfig;
use pathwarden_core::config_edit::{ActionEdit, Setting};
use pathwarden_core::plugin_form;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::actions_ui::{self, Ready};
use crate::jobs::ActionProgress;
use crate::pages::{self, esc, icon, Nav};
use crate::server::{AppState, Shared};
use crate::settings::{self, json_error};
use crate::workspace::{self, RunSummary, Workspace};

const ACTIONS_JS: &str = include_str!("assets/actions.js");
const ACTIONS_CSS: &str = include_str!("assets/actions.css");

/// What a page with finding actions loads: the dialog's look and script.
pub const SCRIPTS: &str = r#"<link rel="stylesheet" href="/static/retest.css"><link rel="stylesheet" href="/static/actions.css"><script src="/static/actions.js" defer></script>"#;

/// Refused while another action runs.
pub const BUSY_WORDS: &str = "Another action is running. Try again when it has finished.";
/// Refused during a collection or an analysis.
pub const ANALYZING_WORDS: &str =
    "A collection or analysis is running. Run the action when it has finished.";

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/runs/{id}/actions/request", post(request_api))
        .route("/api/runs/{id}/actions/run", post(run_api))
        .route("/api/actions/test", post(test_api))
        .route("/api/jobs/{id}/cancel", post(cancel_api))
        .route("/actions/new", get(new_page))
        .route("/actions/{index}/edit", get(edit_page))
        .route("/api/actions", post(save_api))
        .route("/api/actions/{index}", delete(remove_api))
        .route(
            "/static/actions.js",
            get(|| async { asset("text/javascript", ACTIONS_JS) }),
        )
        .route(
            "/static/actions.css",
            get(|| async { asset("text/css", ACTIONS_CSS) }),
        )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// The dialog's icons (24-unit strokes, as the run page's Retest icon).
pub const SPRITE: &str = r#"<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>
<symbol id="i-bolt" viewBox="0 0 24 24"><path d="M13 3 5.5 13.5H11l-1 7.5 7.5-10.5H12z"/></symbol>
<symbol id="i-ticket" viewBox="0 0 24 24"><path d="M4 7.5A1.5 1.5 0 0 1 5.5 6h13A1.5 1.5 0 0 1 20 7.5V10a2 2 0 0 0 0 4v2.5a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 16.5V14a2 2 0 0 0 0-4z"/></symbol>
<symbol id="i-out" viewBox="0 0 24 24"><path d="M12 15V4"/><path d="m7.5 8.5 4.5-4.5 4.5 4.5"/><path d="M5 14v4.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V14"/></symbol>
<symbol id="i-chev" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><path d="M10 8h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></symbol>
<symbol id="i-ext" viewBox="0 0 24 24"><path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/></symbol>
<symbol id="i-tick" viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7.5"/></symbol>
</defs></svg>"#;

// ------------------------------------------------------------ run page

/// What the run page adds for finding actions ([`crate::retest_ui::page_parts`]):
/// the dialog, carrying the run's findings with actions or records (title,
/// where each stands, its view) and the actions offered (label, what it
/// sends, its inputs), and one note when what actions did can't all be
/// read. Empty when no action is set up and no finding has a record.
pub fn run_parts(st: &AppState, r: &RunSummary) -> (String, String) {
    let ws = st.workspace.for_run(r);
    let config = ws.config().unwrap_or_default();
    let log = actions_ui::log(&ws);
    let any_records = log.as_ref().is_ok_and(|l| {
        l.findings
            .values()
            .any(|f| !f.records.is_empty() || !f.activity.is_empty())
    });
    if config.actions.is_empty() && !any_records {
        return (String::new(), String::new());
    }
    let blocks = actions_ui::described(&config.actions);
    let logs = st.jobs.logs_dir();
    let Some(data) = actions_ui::page_data(&ws, &blocks, r, logs.as_deref()) else {
        return (String::new(), String::new());
    };
    (dialog(r, &data), notes(&ws, log.err()))
}

/// The one note a page shows about what actions did: a plain
/// actions.json left in an encrypted history ([`actions_ui::plain_left`]),
/// or why the history's file can't be read.
fn notes(ws: &Workspace, unreadable: Option<String>) -> String {
    let words = match unreadable {
        Some(why) => why,
        None if actions_ui::plain_left(ws) => {
            pathwarden_core::action_log::PLAIN_LEFT_PAGE_WORDS.to_string()
        }
        None => return String::new(),
    };
    format!(
        r#"<div class="note ac-note">{}<p>{}</p></div>"#,
        icon("i-alert"),
        esc(&words)
    )
}

/// The run page's action dialog: empty until a finding's button asks for
/// it; `actions.js` fills it in as text.
fn dialog(r: &RunSummary, data: &Value) -> String {
    format!(
        r##"{SPRITE}<dialog id="ac-dialog" class="card rt-dialog ac-dialog" aria-labelledby="ac-title" data-run="{id}" data-acts="{acts}" data-findings="{findings}">{body}</dialog>
<link rel="stylesheet" href="/static/actions.css"><script src="/static/actions.js" defer></script>
"##,
        id = esc(&r.id),
        acts = pages::json_attr(&data["acts"].to_string()),
        findings = pages::json_attr(&data["f"].to_string()),
        body = dialog_body(),
    )
}

/// The dialog's parts: the action, its inputs and what leaves the
/// computer; the progress; the result; and the footer.
fn dialog_body() -> String {
    format!(
        r##"<form method="dialog" class="rt-close-form"><button class="rt-x" value="close" aria-label="Close">{i_x}</button></form>
<p class="ac-eyebrow" id="ac-eyebrow"></p>
<h2 class="sub" id="ac-title"></h2>
<p class="muted small ac-desc" id="ac-desc"></p>
<form id="ac-form" class="rt-form ac-form" autocomplete="off">
  <div class="ac-inputs" id="ac-inputs"></div>
  <div class="ac-sends" id="ac-sends"><svg class="ic" aria-hidden="true"><use href="#i-out"/></svg><div><p><strong>Leaves this computer:</strong> <span id="ac-sends-text"></span> <button type="button" class="ac-linkbtn" id="ac-see" aria-expanded="false" aria-controls="ac-json">See exactly what's sent <svg class="ic chev" aria-hidden="true"><use href="#i-chev"/></svg></button></p><pre class="ac-json" id="ac-json" hidden></pre><p class="muted small ac-json-note" id="ac-json-note" hidden></p></div></div>
</form>
<div class="ac-run" id="ac-run" aria-live="polite" hidden>
  <div class="ac-run-head"><span class="spinner" aria-hidden="true"></span><div><strong id="ac-run-title"></strong></div><span class="elapsed" id="ac-elapsed">0:00</span></div>
  <ol class="ac-lines" id="ac-lines"></ol>
</div>
<div class="rt-result ac-res" id="ac-result" aria-live="polite" hidden></div>
<div class="ac-foot">
  <label class="ac-switch" id="ac-test-wrap"><input type="checkbox" role="switch" id="ac-test"><span class="track" aria-hidden="true"></span>Test only</label>
  <span class="muted small ac-saved" id="ac-saved"></span>
  <span class="grow"></span>
  <button type="button" class="btn" id="ac-cancel">Cancel</button>
  <button type="submit" form="ac-form" class="btn primary" id="ac-go"><svg class="ic" aria-hidden="true"><use href="#i-bolt"/></svg> <span>Run</span></button>
</div>"##,
        i_x = icon("i-x"),
    )
}

// -------------------------------------------------------------------- API

/// What the dialog asks to run: the finding, the action (`<name>/<id>`),
/// the inputs by ID, Test only, and for a follow-up the record.
#[derive(Debug, Deserialize)]
struct RunBody {
    fingerprint: String,
    action: String,
    #[serde(default)]
    inputs: Map<String, Value>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    record: Option<String>,
}

impl RunBody {
    fn ask(&self) -> Ask {
        Ask {
            action: Some(self.action.clone()),
            inputs: self.inputs.clone(),
            dry_run: self.dry_run,
            record: self.record.clone().filter(|r| !r.trim().is_empty()),
        }
    }
}

/// The run `id` and its environment's workspace; `None` when there is no
/// such run.
fn run_of(st: &AppState, id: &str) -> Option<(RunSummary, Workspace)> {
    if !workspace::valid_run_id(id) {
        return None;
    }
    let r = st.workspace.summary(id)?;
    let ws = st.workspace.for_run(&r);
    Some((r, ws))
}

/// Why an action can't start now: another runs (429), or a collection or
/// an analysis does (409).
fn busy(st: &AppState) -> Option<Response> {
    if st.jobs.running().is_some() {
        return Some(json_error(StatusCode::CONFLICT, ANALYZING_WORDS));
    }
    if st.jobs.acting().is_some() {
        return Some(json_error(StatusCode::TOO_MANY_REQUESTS, BUSY_WORDS));
    }
    None
}

/// `POST /api/runs/{id}/actions/request`: the request the program would
/// get with these inputs (See exactly what's sent), as `pathwarden action
/// request` prints it.
async fn request_api(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<RunBody>,
) -> Response {
    let Some((r, ws)) = run_of(&st, &id) else {
        return json_error(StatusCode::NOT_FOUND, "There is no such run.");
    };
    let done = tokio::task::spawn_blocking(move || {
        let config = ws.config().map_err(|e| format!("{e:#}"))?;
        actions_ui::prepare(
            &ws,
            &config.actions,
            Some(&r.id),
            &body.fingerprint,
            &body.ask(),
        )
        .map(|ready| ready.prepared.request)
    })
    .await;
    match done {
        Ok(Ok(request)) => Json(json!({ "request": request })).into_response(),
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Try again."),
    }
}

/// `POST /api/runs/{id}/actions/run`: starts the action as a job; `{job}`
/// to poll at `/api/jobs/{job}`.
async fn run_api(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<RunBody>,
) -> Response {
    if let Some(r) = busy(&st) {
        return r;
    }
    let Some((r, ws)) = run_of(&st, &id) else {
        return json_error(StatusCode::NOT_FOUND, "There is no such run.");
    };
    let ws2 = ws.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let config = ws2.config().map_err(|e| format!("{e:#}"))?;
        actions_ui::prepare(
            &ws2,
            &config.actions,
            Some(&r.id),
            &body.fingerprint,
            &body.ask(),
        )
        .map(|ready| (ready, config.actions))
    })
    .await;
    match prepared {
        Ok(Ok((ready, blocks))) => start(&st, ws, ready, blocks),
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Try again."),
    }
}

#[derive(Debug, Deserialize)]
struct TestBody {
    /// The block's name.
    name: String,
    /// One of its actions (its ID); else the first that applies.
    #[serde(default)]
    action: Option<String>,
}

/// `POST /api/actions/test`: Test on Plugins and actions, as `pathwarden
/// action test` runs it ([`actions_ui::test_target`]): a dry run on the
/// first finding of the latest run it applies to. `{job}`, and which
/// finding.
async fn test_api(State(st): State<Shared>, Json(body): Json<TestBody>) -> Response {
    if let Some(r) = busy(&st) {
        return r;
    }
    let ws = st.ws();
    let ws2 = ws.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let config = ws2.config().map_err(|e| format!("{e:#}"))?;
        actions_ui::test_target(&ws2, &config.actions, &body.name, body.action.as_deref())
            .map(|ready| (ready, config.actions))
    })
    .await;
    match prepared {
        Ok(Ok((ready, blocks))) => start(&st, ws, ready, blocks),
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Try again."),
    }
}

/// Starts a prepared action on its own thread as a job: its lines go to
/// the job as they come; once it ends, what it did and was saved
/// ([`actions_ui::outcome_json`]), with the finding's view now, the
/// words the page says, and the job is done.
fn start(st: &Shared, ws: Workspace, ready: Ready, blocks: Vec<ActionConfig>) -> Response {
    let id = workspace::new_run_id(pathwarden_core::analyze::now());
    let stop = CancelHandle::new();
    let dry_run = ready.prepared.request["dry_run"].as_bool().unwrap_or(false);
    let label = ready.prepared.offered.def.label.clone();
    let progress = ActionProgress {
        label: label.clone(),
        dry_run,
        ..ActionProgress::default()
    };
    if !st.jobs.try_begin_action(&id, progress, stop.clone()) {
        return match busy(st) {
            Some(r) => r,
            None => json_error(StatusCode::TOO_MANY_REQUESTS, BUSY_WORDS),
        };
    }
    let answer = json!({
        "job": id,
        "label": label,
        "dry_run": dry_run,
        "fingerprint": ready.finding.fingerprint,
        "title": ready.finding.title,
        "run": ready.run.id,
    });
    let jobs = st.jobs.clone();
    let job = id.clone();
    let log = st.jobs.open_log(
        &id,
        pathwarden_core::logs::Kind::Action,
        &format!("{label} on {}", ready.finding.fingerprint),
    );
    if let (Some(l), Some(d)) = (&log, st.jobs.logs_dir()) {
        pathwarden_core::logs::note_run(&d, &ready.run.id, l.name());
    }
    if let Some(l) = &log {
        l.line(&format!(
            "{} ({}), run {}{}",
            ready.prepared.offered.address,
            ready.finding.title,
            ready.run.id,
            if dry_run { ", a test" } else { "" }
        ));
    }
    let logs_dir = st.jobs.logs_dir();
    std::thread::spawn(move || {
        let _in = log.as_ref().map(|l| l.enter());
        // Whatever happens in here (a panic too), the job ends: else it
        // would stay running and refuse every later action.
        let mut guard = Ended {
            jobs: jobs.clone(),
            job: job.clone(),
            done: false,
        };
        let lines = jobs.clone();
        let line_job = job.clone();
        let mut on_line = move |l: &str| lines.action_line(&line_job, l);
        let result = match actions_ui::run_and_save(&ws, &ready, &mut on_line, &stop) {
            Ok((out, saved)) => {
                // The activity entry's log, for its Open log.
                if let (Some(l), Some(dir), Some(Ok(s))) = (&log, &logs_dir, saved.as_ref()) {
                    if let Some(at) = &s.at {
                        pathwarden_core::logs::note_action(
                            dir,
                            &ready.finding.fingerprint,
                            at,
                            l.name(),
                        );
                    }
                }
                let mut v = actions_ui::outcome_json(&ready, &out, saved.as_ref());
                v["said"] = Value::from(said(&out, saved.as_ref()));
                if let Some(view) = actions_ui::view_now(
                    &ws,
                    &blocks,
                    &ready.run.id,
                    &ready.finding.fingerprint,
                    logs_dir.as_deref(),
                ) {
                    v["view"] = serde_json::to_value(view).unwrap_or_default();
                }
                v
            }
            Err(e) => json!({
                "ok": false,
                "message": e,
                "ended": "not_started",
                "label": ready.prepared.offered.def.label,
                "fingerprint": ready.finding.fingerprint,
                "saved": false,
                "pushed": false,
            }),
        };
        jobs.action_done(&job, result);
        guard.done = true;
    });
    (StatusCode::ACCEPTED, Json(answer)).into_response()
}

/// Ends an action's job that didn't end by itself (its thread panicked):
/// failed, so the next action can run.
struct Ended {
    jobs: Arc<crate::jobs::Jobs>,
    job: String,
    done: bool,
}

impl Drop for Ended {
    fn drop(&mut self) {
        if !self.done {
            self.jobs.action_done(
                &self.job,
                json!({
                    "ok": false,
                    "ended": "failed",
                    "message": "The action stopped unexpectedly. Try again.",
                    "saved": false,
                    "pushed": false,
                }),
            );
        }
    }
}

/// The result card's line under it: a dry run saved nothing; else saved
/// for everyone, saved on this computer only for now, kept in the
/// finding's activity (a failure), or why it wasn't saved.
fn said(
    out: &actions::Outcome,
    saved: Option<&Result<actions_ui::SavedOutcome, String>>,
) -> String {
    match saved {
        None => actions_ui::DRY_RUN_PAGE_WORDS.to_string(),
        Some(Err(why)) => format!("Not saved on the finding: {why}"),
        Some(Ok(s)) if !s.saved => String::new(),
        Some(Ok(s)) if !s.pushed => actions_ui::SAVED_HERE_PAGE_WORDS.to_string(),
        Some(Ok(_)) if out.ok => actions_ui::SAVED_PAGE_WORDS.to_string(),
        Some(Ok(_)) => "Kept in the finding's activity.".to_string(),
    }
}

/// `POST /api/jobs/{id}/cancel`: stops a running action (Cancel).
async fn cancel_api(State(st): State<Shared>, Path(id): Path<String>) -> Response {
    let acting = st
        .jobs
        .get(&id)
        .is_some_and(|j| matches!(j.status, crate::jobs::JobStatus::Acting));
    if acting && st.jobs.cancel(&id) {
        StatusCode::ACCEPTED.into_response()
    } else {
        json_error(StatusCode::CONFLICT, "This action has already finished.")
    }
}

// ------------------------------------------------- Plugins and actions

/// The Finding actions section of Plugins and actions: each block's
/// program, its actions with their inputs, what they send and which
/// findings they apply to, and Test; Add and Remove, or a lock
/// note with `--lock-destinations`.
pub fn settings_section(st: &AppState, blocks: &[ActionConfig]) -> String {
    let ws = st.ws();
    let locked = !st.allow_destinations;
    let mut b = format!(
        r#"{SPRITE}<section class="ac-section" id="finding-actions" aria-labelledby="finding-actions-h">
<div class="ac-sect"><div><h2 class="sub" id="finding-actions-h">Finding actions</h2><p class="muted">Buttons on a finding that run a program of yours when someone clicks them.</p></div>{add}</div>
{lock}{notes}"#,
        add = if locked {
            String::new()
        } else {
            format!(
                r#"<div class="rh-actions"><a class="btn" href="/actions/new">{} Add an action program</a></div>"#,
                icon("i-plus")
            )
        },
        lock = if locked {
            pages::lock_note("lock-actions", plugin_form::ACTIONS_LOCKED)
        } else {
            String::new()
        },
        notes = notes(&ws, actions_ui::log(&ws).err()),
    );
    // Test's progress view: the run page's dialog.
    let _ = write!(
        b,
        r#"<dialog id="ac-dialog" class="card rt-dialog ac-dialog" aria-labelledby="ac-title" data-acts="{{}}" data-findings="{{}}">{}</dialog>"#,
        dialog_body()
    );
    if blocks.is_empty() {
        let _ = write!(
            b,
            r#"<div class="empty card">{}<p><strong>No finding actions yet.</strong><br><span class="muted">Each is a button on the findings it applies to.</span></p></div></section>"#,
            icon("i-plug")
        );
        return b;
    }
    let described = actions_ui::described(blocks);
    let latest = actions_ui::latest_findings(&ws);
    let log = actions_ui::log(&ws).unwrap_or_default();
    b.push_str(r#"<div class="rows card pluglist ac-progs">"#);
    for (i, a) in blocks.iter().enumerate() {
        let (program, found) = plugin_form::action_program(a);
        let envs: Vec<String> = a
            .settings
            .iter()
            .filter(|(k, _)| k.ends_with("_env"))
            .filter_map(|(_, v)| v.as_str().map(str::to_string))
            .collect();
        let _ = write!(
            b,
            r##"<div class="ac-progwrap" id="action-{i}"><div class="ac-prog"><span class="zr-icon"><svg class="ic" aria-hidden="true"><use href="#i-bolt"/></svg></span><div class="zr-main"><a class="zr-name" href="/actions/{i}/edit">{name}</a><span class="prog {cls}">{ic}<code>{program}</code>{missing}</span>{env}</div>
<div class="zr-actions"><button type="button" class="btn small-btn danger" data-ac-remove="{i}" data-name="{name}" aria-label="Remove {name}"{disabled}>{trash} Remove</button></div></div><div class="ac-list">"##,
            name = esc(&a.name),
            cls = if found { "ok" } else { "missing" },
            ic = icon(if found { "i-check" } else { "i-alert" }),
            program = esc(&program),
            missing = if found { "" } else { " not found" },
            env = if envs.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="envs">{}</span>"#, env_chips(&envs))
            },
            disabled = if locked { " disabled" } else { "" },
            trash = icon("i-trash"),
        );
        match described.ok.iter().find(|(c, _)| c.name == a.name) {
            Some((_, d)) => {
                let program = actions::Program {
                    config: a,
                    describe: &d.describe,
                };
                let follow_ups: Vec<&str> = d
                    .describe
                    .actions
                    .iter()
                    .flat_map(|x| x.follow_ups.iter().map(String::as_str))
                    .collect();
                for def in &d.describe.actions {
                    // A follow-up shows under the action that makes its
                    // record.
                    if def.for_ == Some(actions::For::Record)
                        && follow_ups.contains(&def.id.as_str())
                    {
                        continue;
                    }
                    b.push_str(&action_row(a, def, &d.describe, program, &latest, &log));
                }
                for p in &d.problems {
                    let _ = write!(b, r#"<p class="muted small ac-problem">{}</p>"#, esc(p));
                }
            }
            None => {
                let why = described
                    .failed
                    .iter()
                    .find(|(n, _)| *n == a.name)
                    .map(|(_, w)| w.as_str())
                    .unwrap_or("It didn't say what it offers.");
                let _ = write!(
                    b,
                    r#"<p class="ac-problem">{} {}</p>"#,
                    icon("i-alert"),
                    esc(why)
                );
            }
        }
        b.push_str("</div></div>");
    }
    b.push_str("</div>");
    let _ = write!(
        b,
        r#"<p class="muted small after-list">{}</p></section>"#,
        match &latest {
            Some((r, _)) => format!(
                "<strong>Test</strong> runs the action as a dry run on the first matching finding of the latest analysis ({}, {}). Nothing is sent for real or saved.",
                esc(&r.environment()),
                pages::time(r.created_at)
            ),
            None => "Testing needs one analysis first: <a href=\"/analyze\">analyze a collection</a> or try the demo.".into(),
        }
    );
    b
}

fn env_chips(names: &[String]) -> String {
    let mut s = String::new();
    for n in names {
        let set = plugin_form::env_is_set(n);
        let _ = write!(
            s,
            r#"<span class="envchip {cls}" title="{title}"><span class="dot" aria-hidden="true"></span><code>{name}</code> {state}</span>"#,
            cls = if set { "set" } else { "unset" },
            title = if set {
                "Set in the environment Pathwarden was started from"
            } else {
                "Not set in the environment Pathwarden was started from"
            },
            name = esc(n),
            state = if set { "set" } else { "not set" },
        );
    }
    s
}

/// One action of a block on Plugins and actions: its name and
/// description, its inputs, what it sends, which findings it applies to
/// (and how many of the latest run's), its follow-ups, and Test.
fn action_row(
    a: &ActionConfig,
    def: &actions::ActionDef,
    describe: &actions::Describe,
    program: actions::Program,
    latest: &Option<(RunSummary, Vec<actions::FindingContext>)>,
    log: &pathwarden_core::action_log::ActionsFile,
) -> String {
    let mut rows: Vec<(&str, String)> = Vec::new();
    if !def.inputs.is_empty() {
        rows.push((
            "Inputs",
            def.inputs
                .iter()
                .map(|i| {
                    let mut s = esc(&i.label);
                    if !i.required {
                        s.push_str(r#" <span class="opt">(optional)</span>"#);
                    }
                    if !i.choices.is_empty() {
                        let _ = write!(s, ": {}", esc(&i.choices.join(", ")));
                    }
                    s
                })
                .collect::<Vec<_>>()
                .join(" · "),
        ));
    }
    if !def.sends.is_empty() {
        rows.push(("Sends", esc(&def.sends)));
    }
    let count = latest.as_ref().map(|(_, findings)| {
        findings
            .iter()
            .filter(|f| {
                actions::offered(
                    std::slice::from_ref(&program),
                    f,
                    &log.records(&f.fingerprint),
                )
                .iter()
                .any(|o| o.id == def.id)
            })
            .count()
    });
    let filters = applies_words(a, def);
    rows.push((
        "Applies to",
        match count {
            Some(n) if !filters.is_empty() || n > 0 => format!(
                "{}{}{} in the latest run",
                esc(&filters),
                if filters.is_empty() { "" } else { " · " },
                pathwarden_core::text::count(n, "finding", "findings")
            ),
            _ if filters.is_empty() => "All findings".to_string(),
            _ => esc(&filters),
        },
    ));
    let follow: Vec<String> = def
        .follow_ups
        .iter()
        .filter_map(|id| describe.actions.iter().find(|x| &x.id == id))
        .map(|x| {
            format!(
                r#"<span class="ac-fu">{}{}</span>"#,
                esc(&x.label),
                if actions_ui::for_fixed(x) {
                    r#" <span class="when">once fixed</span>"#
                } else {
                    ""
                }
            )
        })
        .collect();
    if !follow.is_empty() {
        rows.push(("Follow-ups", follow.join("")));
    }
    let mut dl = String::new();
    for (k, v) in rows {
        let _ = write!(dl, r#"<div class="ac-mrow"><dt>{k}</dt><dd>{v}</dd></div>"#);
    }
    format!(
        r#"<div class="ac-act"><div><strong>{label}</strong> <span class="ac-d">{desc}</span><dl class="ac-meta">{dl}</dl></div><button type="button" class="btn small-btn" data-ac-test="{name}" data-action="{id}"{disabled}>{play} Test</button></div>"#,
        label = esc(&def.label),
        desc = esc(&def.description),
        name = esc(&a.name),
        id = esc(&def.id),
        disabled = if latest.is_some() { "" } else { " disabled" },
        play = icon("i-play"),
    )
}

/// Which findings an action is for, in words: the block's filters and the
/// action's `applies_to` ("Medium and above", "rules PW-006",
/// "hygiene"); empty for every finding.
fn applies_words(a: &ActionConfig, def: &actions::ActionDef) -> String {
    let block = actions::Filters::of_config(a);
    let mut parts = Vec::new();
    let min = match (block.min_severity, def.applies_to.min_severity) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    };
    if let Some(s) = min {
        parts.push(if s == pathwarden_core::findings::Severity::Critical {
            "Critical only".to_string()
        } else {
            format!("{} and above", s.label())
        });
    }
    let rules: Vec<&str> = block
        .rules
        .iter()
        .chain(def.applies_to.rules.iter())
        .map(String::as_str)
        .collect();
    if !rules.is_empty() {
        parts.push(format!(
            "{} {}",
            if rules.len() == 1 { "rule" } else { "rules" },
            rules.join(", ")
        ));
    }
    let cats: Vec<&str> = block
        .categories
        .iter()
        .chain(def.applies_to.categories.iter())
        .map(|c| match c {
            pathwarden_core::findings::Category::AttackPath => "attack paths",
            _ => "hygiene",
        })
        .collect();
    if !cats.is_empty() {
        parts.push(cats.join(", "));
    }
    if def.offered_when(actions::FindingStatus::Fixed)
        && !def.offered_when(actions::FindingStatus::Open)
    {
        parts.push("once fixed".into());
    }
    let s = parts.join(" · ");
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => s,
    }
}

// ---------------------------------------------------------- the form

async fn new_page(State(st): State<Shared>) -> Response {
    form_page(&st, None).into_response()
}

async fn edit_page(State(st): State<Shared>, Path(index): Path<usize>) -> Response {
    let loaded = settings::load(&st);
    if loaded.config.actions.get(index).is_none() {
        return (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response();
    }
    form_page(&st, Some(index)).into_response()
}

/// Add an action program, or change one: its name, what it runs (a plugin
/// program `pathwarden-action-<name>`, or a script or program with its
/// arguments), its settings, its time limit and which findings it is
/// for. With `--lock-destinations` only the name, time limit and
/// filters can change ([`plugin_form::check_action`]), and nothing can be
/// added.
fn form_page(st: &AppState, index: Option<usize>) -> Html<String> {
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(st, &runs);
    let loaded = settings::load(st);
    let blank = ActionConfig {
        timeout_seconds: pathwarden_core::config::ACTION_TIMEOUT_DEFAULT,
        ..ActionConfig::default()
    };
    let a = index
        .and_then(|i| loaded.config.actions.get(i))
        .unwrap_or(&blank);
    let locked = !st.allow_destinations;
    let title = match index {
        None => "Add an action program".to_string(),
        Some(_) => format!("Edit {}", a.name),
    };
    let ro = if locked { " readonly" } else { "" };
    let dis = if locked { " disabled" } else { "" };
    let (program, args) = match &a.command {
        Some(argv) if !argv.is_empty() => (argv[0].clone(), argv[1..].join("\n")),
        _ => (String::new(), String::new()),
    };
    let by_plugin = a.command.is_none();
    let mut settings_rows = String::new();
    let mut rows: Vec<(String, String)> = a
        .settings
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), scalar_text(v)?)))
        .collect();
    let kept: Vec<String> = a
        .settings
        .iter()
        .filter(|(_, v)| scalar_text(v).is_none())
        .map(|(k, _)| format!("<code>{}</code>", esc(k)))
        .collect();
    if rows.is_empty() && !locked {
        rows.push((String::new(), String::new()));
    }
    for (k, v) in &rows {
        let _ = write!(
            settings_rows,
            r#"<div class="kv"><input class="input mono" data-k value="{k}" placeholder="name" aria-label="Name" autocomplete="off" spellcheck="false"{ro}><input class="input" data-v value="{v}" placeholder="value" aria-label="Value" autocomplete="off"{ro}><button type="button" class="fl-remove" data-remove-kv aria-label="Remove"{dis}>{x}</button></div>"#,
            k = pages::attr(k),
            v = pages::attr(v),
            x = icon("i-x"),
        );
    }
    let mut sevs = String::new();
    for (v, label) in [
        ("", "Every finding"),
        ("critical", "Critical only"),
        ("high", "High and above"),
        ("medium", "Medium and above"),
        ("low", "Low and above"),
    ] {
        let on = a.min_severity.map(|s| s.as_str()).unwrap_or("") == v;
        let _ = write!(
            sevs,
            r#"<option value="{v}"{}>{label}</option>"#,
            if on { " selected" } else { "" }
        );
    }
    let cat = |c: pathwarden_core::findings::Category| {
        if a.categories.contains(&c) {
            " checked"
        } else {
            ""
        }
    };
    let meta = json!({
        "index": index,
        "expect": index.map(|_| a.name.clone()),
    });
    let body = format!(
        r#"<div class="page-head"><div><p class="eyebrow"><a href="/automate/ticketing#finding-actions">{page}</a></p><h1 class="panel-title">{title}</h1></div></div>
<form class="card setting plugin-form ac-form-page" id="action-form" data-action-form="{meta}" novalidate>
{lock}<div class="field"><label for="af-name">Name</label><input class="input mono" id="af-name" value="{name}" placeholder="service-desk" maxlength="64" autocomplete="off" spellcheck="false"><p class="hint">Lowercase letters, digits and dashes. Its actions are called <code>name/action</code>.</p></div>
<fieldset class="choice"><legend>What to run</legend>
  <label class="option card"><input type="radio" name="af-how" value="plugin"{plugin_on}{dis}><span><strong>A plugin program</strong><span class="muted"><code>pathwarden-action-&lt;name&gt;</code> from the plugins folder.</span></span></label>
  <label class="option card"><input type="radio" name="af-how" value="command"{cmd_on}{dis}><span><strong>A script or program</strong><span class="muted">PowerShell, Python or any program, with its arguments.</span></span></label>
</fieldset>
<div class="field" data-when-how="plugin"><label for="af-plugin">Plugin</label><input class="input mono" id="af-plugin" value="{plugin}" placeholder="teams-alert" autocomplete="off" spellcheck="false"{ro}></div>
<div class="fields2" data-when-how="command">
  <div class="field"><label for="af-program">Program</label><input class="input mono" id="af-program" value="{program}" placeholder="python" autocomplete="off" spellcheck="false"{ro}><p class="hint">A full path, or one of: powershell, pwsh, python, python3, node, bash, sh, cmd. Not a network path.</p></div>
  <div class="field"><label for="af-args">Arguments, one per line</label><textarea class="input mono" id="af-args" rows="3" spellcheck="false"{ro}>{args}</textarea><p class="hint">Give scripts by their full path.</p></div>
</div>
<h3 class="form-title">Settings</h3>
<p class="hint">Passed to the program in its request. For a secret, add a setting ending in <code>_env</code> whose value is the <em>name</em> of an environment variable.</p>
<div class="kvs" id="af-settings">{settings_rows}</div>{kept}
<button type="button" class="btn small-btn" data-add-kv="af-settings"{dis}>{plus} Add a setting</button>
<h3 class="form-title">When it runs</h3>
<div class="fields2">
  <div class="field"><label for="af-timeout">Time limit (seconds)</label><input class="input" id="af-timeout" type="number" min="1" max="{max}" step="1" value="{timeout}" inputmode="numeric"><p class="hint">A run past it is stopped. Default {default}.</p></div>
  <div class="field"><label for="af-min">For</label><select class="input" id="af-min">{sevs}</select></div>
  <div class="field"><label for="af-rules">Only these rules <span class="muted">(optional)</span></label><input class="input mono" id="af-rules" value="{rules}" placeholder="PW-006, PW-002" autocomplete="off" spellcheck="false"></div>
  <div class="field"><span class="label">Only <span class="muted">(optional)</span></span><label class="check"><input type="checkbox" id="af-cat-attack"{c_attack}> Attack paths</label> <label class="check"><input type="checkbox" id="af-cat-hygiene"{c_hygiene}> Hygiene</label></div>
</div>
<div class="card-actions"><button type="submit" class="btn primary">{check} Save</button><a class="btn" href="/automate/ticketing#finding-actions">Cancel</a><span class="save-status muted small" aria-live="polite"></span></div>
</form>{saved}<script src="/static/config.js" defer></script>{scripts}"#,
        page = esc(crate::plugins_ui::PAGE_TITLE),
        title = esc(&title),
        meta = pages::json_attr(&meta.to_string()),
        lock = if locked {
            pages::lock_note("lock-actions", plugin_form::ACTIONS_LOCKED)
        } else {
            String::new()
        },
        name = pages::attr(if index.is_some() { &a.name } else { "" }),
        plugin_on = if by_plugin { " checked" } else { "" },
        cmd_on = if by_plugin { "" } else { " checked" },
        plugin = pages::attr(a.plugin.as_deref().unwrap_or_default()),
        program = pages::attr(&program),
        args = esc(&args),
        plus = icon("i-plus"),
        max = pathwarden_core::config::ACTION_TIMEOUT_MAX,
        default = pathwarden_core::config::ACTION_TIMEOUT_DEFAULT,
        timeout = a.timeout_seconds,
        rules = pages::attr(&a.rules.join(", ")),
        c_attack = cat(pathwarden_core::findings::Category::AttackPath),
        c_hygiene = cat(pathwarden_core::findings::Category::Hygiene),
        check = icon("i-check"),
        saved = settings::after_save(st),
        scripts = SCRIPTS,
        kept = if kept.is_empty() {
            String::new()
        } else {
            format!(
                r#"<p class="muted small kept">Also set in the file and kept as written: {}.</p>"#,
                kept.join(", ")
            )
        },
    );
    Html(pages::shell(
        &ctx,
        Some(Nav::Plugins),
        &title,
        "config",
        &body,
    ))
}

/// What the form saves.
#[derive(Debug, Deserialize)]
struct SaveBody {
    index: Option<usize>,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    name: String,
    /// `plugin` or `command`.
    #[serde(default)]
    how: String,
    #[serde(default)]
    plugin: String,
    #[serde(default)]
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    settings: Vec<(String, String)>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    min_severity: String,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
}

/// A setting as the form shows it: text, a number or true/false; `None`
/// for a list or a table, which the form keeps as the file has it.
fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A setting's text as the file keeps it: true/false and whole numbers
/// as such, as `pathwarden action add --setting` saves them.
pub fn setting_of(v: &str) -> Setting {
    match v {
        "true" => Setting::Bool(true),
        "false" => Setting::Bool(false),
        _ => match v.parse::<i64>() {
            Ok(n) if n.to_string() == v => Setting::Int(n),
            _ => Setting::Str(v.to_string()),
        },
    }
}

impl SaveBody {
    fn edit(&self, existing: Option<&ActionConfig>) -> Result<ActionEdit, String> {
        let mut set = Vec::new();
        let mut sent = Vec::new();
        for (k, v) in &self.settings {
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                continue;
            }
            sent.push(k.to_string());
            // As the file has it already (a decimal number too): no change.
            if existing
                .and_then(|a| a.settings.get(k))
                .and_then(scalar_text)
                .is_some_and(|t| t == v)
            {
                continue;
            }
            if plugin_form::looks_secret(k) {
                return Err(format!("Don't put secrets in the file. Instead of {k}, add {k}_env with the name of an environment variable that holds it."));
            }
            if k.ends_with("_env") && !pathwarden_core::plugins::valid_env_name(v) {
                return Err(format!(
                    "{k} must name an environment variable (letters, digits and _)."
                ));
            }
            set.push((k.to_string(), setting_of(v)));
        }
        // Only settings the form showed (text, numbers, true/false) can be
        // removed there; lists and tables are kept as the file has them.
        let remove = existing
            .map(|a| {
                a.settings
                    .iter()
                    .filter(|(k, v)| scalar_text(v).is_some() && !sent.contains(k))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        let command = (self.how == "command").then(|| {
            std::iter::once(self.program.trim().to_string())
                .chain(
                    self.args
                        .iter()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                )
                .collect::<Vec<_>>()
        });
        let plugin = (self.how != "command").then(|| self.plugin.trim().to_string());
        Ok(ActionEdit {
            name: self.name.trim().to_string(),
            plugin,
            command,
            timeout_seconds: Some(self.timeout_seconds.unwrap_or(0)),
            min_severity: Some(self.min_severity.trim().to_string()),
            rules: Some(
                self.rules
                    .iter()
                    .map(|r| r.trim().to_string())
                    .filter(|r| !r.is_empty())
                    .collect(),
            ),
            categories: Some(self.categories.clone()),
            set,
            remove,
        })
    }
}

/// `POST /api/actions`: adds or changes an `[[action]]` block, as
/// `pathwarden action add` does ([`plugin_form::check_action`]).
async fn save_api(State(st): State<Shared>, Json(body): Json<SaveBody>) -> Response {
    let loaded = settings::load(&st);
    let existing = body.index.and_then(|i| loaded.config.actions.get(i));
    if body.index.is_some() && existing.is_none() {
        return json_error(StatusCode::CONFLICT, pathwarden_core::config_edit::CHANGED);
    }
    let mut edit = match body.edit(existing) {
        Ok(e) => e,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    // The default timeout is no change when it was the default.
    if existing.is_some_and(|a| Some(a.timeout_seconds) == edit.timeout_seconds) {
        edit.timeout_seconds = None;
    }
    if let Err(e) = plugin_form::check_action(st.allow_destinations, &mut edit, existing) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    let at = body.index.zip(body.expect.clone());
    settings::edit(&st, move |d| {
        d.upsert_action(at.as_ref().map(|(i, n)| (*i, n.as_str())), &edit)
    })
    .await
}

#[derive(Debug, Deserialize)]
struct RemoveBody {
    expect: String,
}

/// `DELETE /api/actions/{index}`: removes an `[[action]]` block (not with
/// `--lock-destinations`, as adding one).
async fn remove_api(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    Json(body): Json<RemoveBody>,
) -> Response {
    if !st.allow_destinations {
        return json_error(StatusCode::BAD_REQUEST, plugin_form::ACTIONS_LOCKED);
    }
    settings::edit(&st, move |d| d.remove_action(index, &body.expect)).await
}

#[cfg(test)]
#[path = "actions_browser_tests.rs"]
mod browser_tests;
