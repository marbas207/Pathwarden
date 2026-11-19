//! Logs and crash reports in the app ([`pathwarden_core::logs`]): the
//! Logs card on Settings, with the latest crash not dismissed and its
//! Open crash report and Dismiss; the amber dot it puts by Settings in the
//! rail; and opening a log, a crash report or the logs folder in this
//! computer's default app (Open log on a failed collection and on a failed
//! action's Activity entry). Only a file of the logs folder is ever
//! opened, by its name ([`pathwarden_core::logs::file_in`]).

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use pathwarden_core::logs::{self, CrashReport};
use serde::Deserialize;

use crate::pages::{esc, icon};
use crate::server::{AppState, Shared};
use crate::settings::json_error;

/// What the rail's dot on Settings says after a crash.
pub const CRASH_DOT: &str = "Pathwarden stopped unexpectedly";

/// Opens a file or folder in this computer's default app; `true` when it
/// started. Tests put a recorder in its place ([`AppState::opener`]).
pub type Opener = Arc<dyn Fn(&Path) -> bool + Send + Sync>;

/// The real one: the system's default app for the file (a text editor
/// for a `.log` or `.txt`), the file manager for a folder. Debug builds
/// with `PATHWARDEN_TEST_OPENED` set write the path to that file instead.
pub fn open_path(path: &Path) -> bool {
    #[cfg(debug_assertions)]
    if let Some(record) = std::env::var_os("PATHWARDEN_TEST_OPENED").filter(|v| !v.is_empty()) {
        use std::io::Write;
        return std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(record)
            .and_then(|mut f| writeln!(f, "{}", path.display()))
            .is_ok();
    }
    crate::launch::open_file(path)
}

/// The default [`Opener`].
pub fn default_opener() -> Opener {
    Arc::new(open_path)
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/logs/open", post(open_api))
        .route("/api/logs/dismiss", post(dismiss_api))
}

#[derive(Deserialize, Default)]
struct DismissBody {
    /// The crash report the page showed.
    #[serde(default)]
    file: Option<String>,
}

#[derive(Deserialize)]
struct OpenBody {
    /// A log's or crash report's file name; none for the folder.
    #[serde(default)]
    file: Option<String>,
}

/// `POST /api/logs/open`: opens a log or crash report of the logs folder
/// by its name, or with none the folder.
async fn open_api(State(st): State<Shared>, Json(body): Json<OpenBody>) -> Response {
    let Some(dir) = st.jobs.logs_dir() else {
        return json_error(
            StatusCode::CONFLICT,
            "This computer has no logs folder: its account has no profile folder.",
        );
    };
    let target = match body.file.as_deref() {
        None => {
            if let Err(e) = logs::ensure(&dir) {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Couldn't create the logs folder: {e}"),
                );
            }
            dir
        }
        Some(name) => match logs::file_in(&dir, name) {
            Some(p) => p,
            None => return json_error(StatusCode::NOT_FOUND, "That log is no longer there."),
        },
    };
    let opener = st.opener.clone();
    let opened = tokio::task::spawn_blocking(move || opener(&target))
        .await
        .unwrap_or(false);
    if opened {
        StatusCode::NO_CONTENT.into_response()
    } else {
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't open it.")
    }
}

/// `POST /api/logs/dismiss`: the crash report the page showed (and any
/// earlier) goes, on this computer; one written since still shows.
async fn dismiss_api(State(st): State<Shared>, body: Option<Json<DismissBody>>) -> Response {
    let Some(dir) = st.jobs.logs_dir() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let body = body.map(|b| b.0).unwrap_or_default();
    match logs::dismiss(&dir, body.file.as_deref()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't save that: {e}"),
        ),
    }
}

/// The latest crash not dismissed, if any.
pub fn pending(st: &AppState) -> Option<CrashReport> {
    logs::pending_crash(&st.jobs.logs_dir()?)
}

/// The Logs card on Settings: what is kept, the latest crash not dismissed
/// with Open crash report and Dismiss, and Open logs folder.
pub fn card(st: &AppState) -> String {
    let about = if cfg!(windows) {
        "Logs of each collection, analysis, action and app session, and a report for each crash. Passwords, tokens and cookies are never written. A hard crash may only be in Windows Event Viewer."
    } else {
        "Logs of each collection, analysis, action and app session, and a report for each crash. Passwords, tokens and cookies are never written. A hard crash may only be in the system journal."
    };
    let line = match pending(st) {
        Some(c) => format!(
            r#"<p class="crash-line" data-crash>{i}<span>{text}</span><button type="button" class="linkish" data-crash-open="{name}">Open crash report</button><button type="button" class="linkish" data-crash-dismiss="{name}">Dismiss</button></p>"#,
            i = icon("i-alert"),
            text = esc(&c.line()),
            name = esc(&c.name),
        ),
        None => String::new(),
    };
    format!(
        r#"<section class="card setting" id="logs"><header><h2 class="sub">Logs</h2><p class="muted">Kept 30 days, at most 200 MB. {tip}</p></header>{line}<div class="card-actions"><button type="button" class="btn" data-logs-open>{i_folder} Open logs folder</button><span class="save-status muted small" aria-live="polite"></span></div></section>"#,
        tip = crate::pages::tip("logs", "logs", about),
        i_folder = icon("i-folder"),
    )
}

/// The Settings jump link to the card, with the dot after a crash.
pub fn jump_link(crash: bool) -> String {
    if crash {
        format!(
            r##"<a href="#logs" title="{CRASH_DOT}">Logs<span class="sr-only">: {}</span><span class="nav-dot jump-dot" aria-hidden="true"></span></a>"##,
            CRASH_DOT.to_lowercase()
        )
    } else {
        r##"<a href="#logs">Logs</a>"##.to_string()
    }
}

/// Opens this app session's log: the version, this computer's OS, and how
/// the app is reached (`how`: "the browser", "the desktop window").
pub fn start_session(state: &mut AppState, how: &str) {
    let Some(dir) = state.jobs.logs_dir() else {
        return;
    };
    let version = env!("CARGO_PKG_VERSION");
    if let Ok(log) = logs::JobLog::open_in(&dir, logs::Kind::Session, logs::By::App, version) {
        let sys = crate::diagnose::system_info();
        log.line(&format!(
            "Pathwarden {version} on {}, {}, in {how}",
            sys.os, sys.arch
        ));
        state.session = Some(log);
    }
}

/// Ends this app session's log.
pub fn end_session(state: &AppState) {
    if let Some(log) = &state.session {
        log.line("stopped");
        log.end(logs::Outcome::Ok, "");
    }
}
