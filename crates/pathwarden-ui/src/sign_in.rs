//! Sign in: when the git history wanted a sign-in git couldn't make
//! (the app's own syncs never open a sign-in window:
//! [`pathwarden_core::store::background`]), History storage, Run details
//! and the Connect page offer Sign in. It syncs with git's sign-in window
//! allowed (Git Credential Manager's: Pathwarden never sees the password),
//! then says how it went. `pathwarden history storage sign-in` does the
//! same.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pathwarden_core::connect::{SIGNED_IN, SIGN_IN_CANCELLED, SIGN_IN_FAILED};

use crate::history_ui::{self, Location, PullError, Pulled};
use crate::server::AppState;
use crate::workspace::Workspace;

/// Who signed in, in the record of the last sync ([`crate::last_pull`]).
pub const BY: &str = "sign in";

/// How a sign-in went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Signed in, and the sync after it worked.
    Ok,
    /// The repository still wanted a sign-in.
    Failed,
    /// The sign-in window was closed.
    Cancelled,
    /// It failed for something else: the repository couldn't be reached.
    Unreachable,
}

impl Outcome {
    /// Its key, in the page's address after a sign-in (`?signin=ok`).
    pub fn key(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Failed => "failed",
            Outcome::Cancelled => "cancelled",
            Outcome::Unreachable => "unreachable",
        }
    }

    pub fn from_key(key: &str) -> Option<Outcome> {
        Some(match key {
            "ok" => Outcome::Ok,
            "failed" => Outcome::Failed,
            "cancelled" => Outcome::Cancelled,
            "unreachable" => Outcome::Unreachable,
            _ => return None,
        })
    }

    /// What the page says of it.
    pub fn words(self) -> &'static str {
        match self {
            Outcome::Ok => SIGNED_IN,
            Outcome::Failed => SIGN_IN_FAILED,
            Outcome::Cancelled => SIGN_IN_CANCELLED,
            Outcome::Unreachable => "Couldn't sync with the repository.",
        }
    }

    /// Green, not red.
    pub fn good(self) -> bool {
        self == Outcome::Ok
    }

    /// The outcome of a sync that failed with git's `message`.
    pub fn of_error(message: &str) -> Outcome {
        if pathwarden_core::connect::cancelled(message) {
            Outcome::Cancelled
        } else if pathwarden_core::connect::is_sign_in(message) {
            Outcome::Failed
        } else {
            Outcome::Unreachable
        }
    }
}

/// How long a page may say how a Sign in went after it.
const SAID_FOR: std::time::Duration = std::time::Duration::from_secs(120);

/// Sign-ins of the last [`SAID_FOR`], by the short-lived token the page
/// loads again with (`?signin=<token>`): a page says how one went only
/// right after it, never from an address made up. The token is not used
/// up when read: the run page and its report frame both read it, and a
/// reload within the two minutes says it again. It only ever shows how a
/// Sign in went; it lets nothing be done.
fn recent() -> std::sync::MutexGuard<'static, Vec<(String, std::time::Instant, Outcome)>> {
    static RECENT: std::sync::OnceLock<
        std::sync::Mutex<Vec<(String, std::time::Instant, Outcome)>>,
    > = std::sync::OnceLock::new();
    RECENT
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Keeps how a Sign in went, for the page that loads again after it: its
/// token; none without randomness to make one (the page then says nothing).
pub fn remember(o: Outcome) -> Option<String> {
    let token = crate::run_details::try_nonce()?;
    let mut r = recent();
    r.retain(|(_, at, _)| at.elapsed() < SAID_FOR);
    r.push((token.clone(), std::time::Instant::now(), o));
    let n = r.len();
    if n > 16 {
        r.drain(..n - 16);
    }
    Some(token)
}

/// How the Sign in with `token` went, if it was just now.
pub fn said(token: &str) -> Option<Outcome> {
    if !crate::run_details::valid_nonce(token) {
        return None;
    }
    recent()
        .iter()
        .find(|(t, at, _)| t == token && at.elapsed() < SAID_FOR)
        .map(|(_, _, o)| *o)
}

/// Why [`sign_in`] didn't sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSignedIn {
    /// The history's lock is held (a run is recording): nothing was tried.
    Busy(String),
    /// Git tried, and it didn't work: how, and what git said.
    Failed(Outcome, String),
}

/// Signs in to the git history at `loc` and syncs (blocking): git runs with
/// its sign-in window allowed (not [`pathwarden_core::store::non_interactive`]),
/// pulls, and pushes what waits here, as Sync now does. The record of the
/// last sync says how it went, either way.
pub fn sign_in(ws: Option<&Workspace>, loc: &Location, page: bool) -> Result<Pulled, NotSignedIn> {
    // The sign-in itself first, without the history's lock: the window may
    // stay open for minutes, and runs and syncs must not wait for it.
    if let Err(e) = loc.store.check_access() {
        let said = format!("{e:#}");
        crate::last_pull::failed(&loc.store, BY, pathwarden_core::analyze::now(), &said);
        return Err(NotSignedIn::Failed(Outcome::of_error(&said), said));
    }
    history_ui::refresh_detail(
        ws,
        loc,
        page,
        pathwarden_core::settings_sync::lock_wait(),
        BY,
        &mut |_| {},
    )
    .map_err(|e| match e {
        PullError::Busy(m) => NotSignedIn::Busy(m),
        PullError::Failed(m) => NotSignedIn::Failed(Outcome::of_error(&m), m),
    })
}

/// `POST /api/history/sign-in`: Sign in. `{outcome}`, which the page shows
/// after loading again; a held lock is an error to show as it is.
pub async fn api(State(st): State<Arc<AppState>>) -> Response {
    let ws = st.ws();
    let env = st.env_id();
    let flag = st.state_dir();
    let done = tokio::task::spawn_blocking(move || {
        let loc = history_ui::locate(&ws, flag.as_deref()).map_err(NotSignedIn::Busy)?;
        if loc.git.is_none() {
            return Err(NotSignedIn::Busy(
                "The history is a folder: there is nothing to sign in to.".into(),
            ));
        }
        sign_in(Some(&ws), &loc, true)
    })
    .await;
    st.auto_pull.timer.reset();
    let outcome = match done {
        Ok(Ok(p)) => {
            st.auto_pull.record_runs(&env, &p);
            Outcome::Ok
        }
        Ok(Err(NotSignedIn::Failed(o, _))) => o,
        Ok(Err(NotSignedIn::Busy(m))) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Signing in failed." })),
            )
                .into_response()
        }
    };
    Json(serde_json::json!({
        "outcome": outcome.key(),
        "words": outcome.words(),
        "token": remember(outcome),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_by_what_git_said() {
        assert_eq!(
            Outcome::of_error(
                "git fetch failed: fatal: Authentication failed for 'https://h/x.git/'"
            ),
            Outcome::Failed
        );
        assert_eq!(
            Outcome::of_error("fatal: User cancelled the authentication prompt."),
            Outcome::Cancelled
        );
        assert_eq!(
            Outcome::of_error("fatal: unable to access 'https://h/': Could not resolve host: h"),
            Outcome::Unreachable
        );
        for o in [
            Outcome::Ok,
            Outcome::Failed,
            Outcome::Cancelled,
            Outcome::Unreachable,
        ] {
            assert_eq!(Outcome::from_key(o.key()), Some(o));
            assert!(o.words().ends_with('.'));
        }
        assert_eq!(Outcome::from_key("<script>"), None);
    }

    /// A page says how a Sign in went only with the token it just got, not
    /// from an address someone could make up.
    #[test]
    fn said_only_right_after() {
        let t = remember(Outcome::Failed).unwrap();
        assert_eq!(said(&t), Some(Outcome::Failed));
        assert_eq!(said(&t), Some(Outcome::Failed), "the frame reads it too");
        assert_eq!(said("ok"), None);
        assert_eq!(said("failed"), None);
        assert_eq!(said(&crate::run_details::new_nonce()), None);
    }
}
