//! The history's passphrase in the app (slice E): the Encryption row of
//! History storage's In use, the encryption part of Where to keep it (turn
//! on with a new passphrase, turn off, change, check), and the "This history
//! is encrypted" card on Runs for a computer that has no passphrase yet.
//! Every action is the CLI's (`pathwarden history storage passphrase ...`,
//! `set --encrypt`) from the same core code: [`pathwarden_core::store::Store`]
//! and [`pathwarden_core::keystore`].
//!
//! Passphrases arrive once, in a [`SecretJson`] body read into zeroing
//! [`Secret`]s, and go to the core and this account's credential store only:
//! never back to the browser, into a log, or to a file.

use std::fmt::Write;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_collect::Secret;
use pathwarden_core::crypt::{self, CryptError, SecretString};
use pathwarden_core::keystore::{self, Source};
use serde::Deserialize;

use crate::history_ui::{locate, Encryption, Location};
use crate::pages::{esc, icon};
use crate::secret_json::SecretJson;
use crate::server::AppState;

type Shared = Arc<AppState>;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/history/encryption", post(encryption_api))
        .route("/api/history/passphrase/change", post(change_api))
        .route("/api/history/passphrase/check", post(check_api))
        .route("/api/history/passphrase/open", post(open_api))
        .route(
            "/static/enc.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/javascript")],
                    ENC_JS,
                )
                    .into_response()
            }),
        )
}

const ENC_JS: &str = include_str!("assets/enc.js");

// ------------------------------------------------------------------ words

/// A small (i) with the details, as the other pages have them. `body` is
/// HTML (fixed text only).
fn tip(id: &str, about: &str, body: &str, wide: bool) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {about}" aria-describedby="{id}">{i}</button><span class="{cls}" role="tooltip" id="{id}">{body}</span></span>"#,
        i = icon("i-info"),
        cls = if wide { "tip-text wide" } else { "tip-text" },
    )
}

/// Where this computer's passphrase is, for the status line:
/// "passphrase stored on this computer (Windows Credential Manager)".
fn kept_words(source: &Option<Source>) -> String {
    match source {
        Some(Source::Store) => format!(
            "passphrase stored on this computer ({})",
            keystore::store_name()
        ),
        Some(Source::File(_)) => {
            "passphrase stored on this computer (a protected file for this account)".into()
        }
        Some(Source::Systemd) => "passphrase from the service's credential".into(),
        Some(Source::Another) => "passphrase kept on this computer for another history".into(),
        Some(Source::Env) => format!("passphrase from {}", keystore::ENV_VAR),
        Some(Source::Given) => "passphrase given for this session only".into(),
        None => "passphrase not stored on this computer".into(),
    }
}

/// The In use row: "On (passphrase)" with where it is kept, or "Off".
pub fn in_use_row(e: &Encryption) -> String {
    let dd = match e {
        Encryption::Off => "Off".to_string(),
        Encryption::On(source) => {
            let sub = match source {
                Some(Source::Store) => format!(
                    "Stored on this computer in {}, for this account.",
                    keystore::store_name()
                ),
                Some(Source::File(_)) => {
                    "Stored on this computer in a protected file, for this account.".into()
                }
                Some(Source::Systemd) => "From the service's credential.".into(),
                Some(Source::Another) => "Kept on this computer for another history.".into(),
                Some(Source::Env) => format!("From {}.", keystore::ENV_VAR),
                Some(Source::Given) => "Given for this session only.".into(),
                None => "Not stored on this computer.".into(),
            };
            format!(
                r#"On (passphrase) <span class="fact-sub">{}</span>"#,
                esc(&sub)
            )
        }
        Encryption::Problem(p) => format!(
            r#"On, but it can't be used <span class="fact-sub">{}</span>"#,
            esc(p)
        ),
    };
    format!(
        "<div><dt>{}</dt><dd>{dd}</dd></div>",
        crate::history_ui::label::ENCRYPTION
    )
}

/// The two notes, the rest behind the (i).
fn notes() -> String {
    format!(
        r#"<ul class="enc-notes"><li>Readers need repository access and the passphrase.</li><li>Give each history its own passphrase.</li><li>A lost passphrase can't be recovered. {}</li></ul>"#,
        tip(
            "tip-enc",
            "Encryption",
            "The contents of every file Pathwarden writes to the folder or repository are encrypted. File names, run times, sizes and commit times stay visible.<br>The workspace on this computer is never encrypted.<br>Keep a copy of the passphrase in your password manager.<br>The scheduled task's account needs the passphrase stored once; the setup script asks for it.<br>Changing the passphrase re-encrypts the latest files. Older versions in the git history stay readable with the old one.<br>Encrypted files don't shrink between versions, so the repository grows faster.",
            true
        )
    )
}

/// Two passphrase fields with the match hint and the strength bar (the
/// browser fills both in, `enc.js`).
fn new_fields(prefix: &str, first: &str) -> String {
    format!(
        r#"<div class="fields2"><div class="field"><label for="{prefix}-pass">{first}</label><input class="input mono" type="password" id="{prefix}-pass" autocomplete="new-password" spellcheck="false"></div><div class="field"><label for="{prefix}-pass2">Repeat it</label><input class="input mono" type="password" id="{prefix}-pass2" autocomplete="new-password" spellcheck="false"><p class="hint enc-match" id="{prefix}-match" hidden>{check} <span></span></p></div></div><div class="enc-strength" id="{prefix}-strength"><span class="bar"><span></span></span><span><strong>Too short.</strong> At least {min} characters.</span></div>"#,
        check = icon("i-check"),
        min = crypt::MIN_PASSPHRASE,
    )
}

/// The encryption part of Where to keep it.
pub fn where_block(e: &Encryption) -> String {
    let on = matches!(e, Encryption::On(_) | Encryption::Problem(_));
    let mut b = format!(
        r#"<div id="enc" data-on="{on}" data-no-save><label class="check-row enc-row"><input type="checkbox" id="state-encrypt"{checked}><span><strong>Encrypt the history with a passphrase</strong><span class="muted">{sub}</span></span></label>"#,
        checked = if on { " checked" } else { "" },
        sub = if on {
            "On by default for full runs."
        } else {
            "Available at this level too. Off: the history is kept as plain files."
        },
    );
    if let Encryption::On(source) = e {
        let _ = write!(
            b,
            r#"<div class="enc-body" id="enc-on"><p class="enc-status">{lock}<span><strong>Encrypted</strong> · {kept}</span></p><div class="enc-actions"><button type="button" class="btn small-btn" id="enc-change-open">Change passphrase</button><button type="button" class="btn small-btn" id="enc-check">Check the passphrase</button><span class="enc-msg small" id="enc-msg" aria-live="polite"></span></div>{notes}
<div class="enc-setup" id="enc-change" hidden><p class="enc-title">{lock}<strong>Change the passphrase</strong></p>{current}{fields}<p class="hint">Every file is encrypted again. Other computers need the new passphrase.</p><div class="enc-actions"><button type="button" class="btn primary" id="enc-change-go" disabled>{lock} Change passphrase</button><button type="button" class="btn" id="enc-change-cancel">Cancel</button><span class="enc-msg small" aria-live="polite"></span></div></div>
<div class="note warn enc-skip-warn" id="enc-off" hidden>{alert}<div><p><strong>Decrypt the history?</strong> Every file is written as plain text again, readable by anyone who can read this folder or repository. {tip_off}</p><div class="enc-actions"><button type="button" class="btn small-btn danger" id="enc-off-go">Decrypt and save</button><button type="button" class="btn small-btn" id="enc-off-cancel">Keep it encrypted</button><span class="enc-msg small" aria-live="polite"></span></div></div></div></div>"#,
            lock = icon("i-lock"),
            alert = icon("i-alert"),
            kept = esc(&kept_words(source)),
            notes = notes(),
            current = if source.is_none() {
                r#"<div class="field"><label for="enc-current">Current passphrase</label><input class="input mono" type="password" id="enc-current" autocomplete="current-password" spellcheck="false"></div>"#
            } else {
                ""
            },
            fields = new_fields("enc-new", "New passphrase"),
            tip_off = tip(
                "tip-enc-off",
                "Decrypting",
                "Older versions in the git history stay encrypted. The passphrase is removed from this computer.",
                false
            ),
        );
    } else if let Encryption::Problem(p) = e {
        let _ = write!(
            b,
            r#"<div class="enc-body"><p class="field-error" role="alert">{}</p></div>"#,
            esc(p)
        );
    } else {
        let _ = write!(
            b,
            r##"<div class="enc-body" id="enc-setup-wrap" hidden><div class="enc-setup"><p class="enc-title">{lock}<strong>Set the passphrase</strong></p>{fields}{notes}<label class="check-row"><input type="checkbox" id="enc-ack"><span><strong>I understand a lost passphrase can't be recovered</strong></span></label><div class="enc-actions"><button type="button" class="btn primary" id="enc-set" disabled>{lock} Set passphrase and save</button><a href="#enc-no" class="enc-skip" id="enc-skip">Don't encrypt</a><span class="enc-msg small" aria-live="polite"></span></div><div class="note warn enc-skip-warn" id="enc-no" hidden>{alert}<div><p><strong>Keep full runs unencrypted?</strong> Only if the repository is protected another way. Otherwise anyone who can read it can read <span class="nw">every full run. {tip_no}</span></p><div class="enc-actions"><button type="button" class="btn small-btn danger" id="enc-no-save">Save without encryption</button><button type="button" class="btn small-btn" id="enc-no-back">Encrypt after all</button></div></div></div></div></div>"##,
            lock = icon("i-lock"),
            alert = icon("i-alert"),
            fields = new_fields("enc", "Passphrase"),
            notes = notes(),
            tip_no = tip(
                "tip-noenc",
                "Protected another way",
                "For example, a server only your team can reach.",
                false
            ),
        );
    }
    b.push_str("</div>");
    b
}

/// Whether the history in use is encrypted and couldn't be read here (no
/// passphrase, or the wrong one): from what reading it found, without
/// trying again.
pub fn locked(loc: &Location, h: &crate::history_ui::History) -> bool {
    h.problem.is_some() && crypt::is_encrypted(&loc.dir)
}

/// The gate's heading: an encrypted history this computer can't open.
pub const GATE_TITLE: &str = "This history is encrypted";

/// What the gate says when this computer's passphrase doesn't open it.
pub const WRONG_PASSPHRASE: &str =
    "The passphrase stored on this computer doesn't open this history.";

/// Why this computer can't open the history: `None` when it isn't
/// encrypted or opens (or has a problem of its own, said elsewhere);
/// `Some(None)` with no passphrase here, `Some(Some(words))` with a wrong
/// one ([`WRONG_PASSPHRASE`]). What the Runs gate and `pathwarden runs`
/// say.
pub fn lock_reason(loc: &Location) -> Option<Option<&'static str>> {
    let encrypted = crypt::marker(&loc.dir).ok().flatten().is_some();
    if !encrypted {
        return None;
    }
    match pathwarden_core::store::check_readable(&loc.dir) {
        Ok(()) => None,
        Err(e) => match e.downcast_ref::<CryptError>() {
            Some(CryptError::NeedPassphrase) => Some(None),
            Some(CryptError::WrongPassphrase(_)) => Some(Some(WRONG_PASSPHRASE)),
            // Damaged or newer: the history's own problem, said elsewhere.
            _ => None,
        },
    }
}

/// The card on Runs when the history is encrypted and this computer can't
/// open it: `None` otherwise. `wrong`: a passphrase this computer has
/// doesn't open it.
pub fn gate(loc: &Location) -> Option<String> {
    gate_with(loc, GATE_LEAD, true)
}

/// The gate's line under its heading on Runs (and in `pathwarden runs
/// list`).
pub const GATE_LEAD: &str = "Enter the passphrase to open its runs. Runs analyzed here show below.";

/// The terminal's lead for the same (`pathwarden runs`): no "below" and
/// no field to type into; the command then says how to store it.
pub const CLI_LOCKED: &str =
    "This history is encrypted and this computer has no passphrase for it.";

/// The same on a run's page opened from a link to a run only the history
/// has.
pub const GATE_LEAD_RUN: &str = "Enter the passphrase to open this run.";

/// [`gate`] with its line `lead`; `local`: the "On this computer" heading
/// after it, for the runs listed below.
pub fn gate_with(loc: &Location, lead: &str, local: bool) -> Option<String> {
    let err = lock_reason(loc)?;
    Some(format!(
        r#"<section class="card enc-gate" id="enc-gate">{lock}<div><h2 class="sub">{GATE_TITLE}</h2><p class="muted">{lead}</p><div class="field enc-field"><label for="gate-pass">Passphrase {tip}</label><input class="input mono{bad}" type="password" id="gate-pass" autocomplete="current-password" spellcheck="false" aria-describedby="gate-err"><p class="enc-err" id="gate-err" role="alert"{hide}>{alert} <span>{err}</span></p></div><label class="check-row"><input type="checkbox" id="gate-remember" checked><span><strong>Remember on this computer</strong><span class="muted">Kept in {store} for your account, so you are asked once.</span></span></label><div class="enc-actions"><button type="button" class="btn primary" id="gate-open">{lock} Open the history</button>{access}</div></div></section>{local}<script src="/static/enc.js" defer></script>"#,
        lead = esc(lead),
        local = if local {
            r#"<h2 class="sub local-head">On this computer</h2>"#
        } else {
            ""
        },
        lock = icon("i-lock"),
        alert = icon("i-alert"),
        tip = tip(
            "tip-gate",
            "The passphrase",
            "Ask whoever set up the history. A lost passphrase can't be recovered.",
            false
        ),
        bad = if err.is_some() { " bad" } else { "" },
        hide = if err.is_some() { "" } else { " hidden" },
        err = esc(err.unwrap_or("That passphrase doesn't open this history.")),
        store = esc(keystore::store_name()),
        access = if loc.git.is_some() {
            r#"<span class="muted small">You also need read access to the repository.</span>"#
        } else {
            ""
        },
    ))
}

/// What the page says for an error of the core, in the page's words (no
/// commands: those are in the docs).
fn words(e: &anyhow::Error) -> String {
    match e.downcast_ref::<CryptError>() {
        Some(CryptError::NeedPassphrase) => {
            "No passphrase for this history is stored on this computer.".into()
        }
        Some(CryptError::WrongPassphrase(Source::Given)) => {
            "That passphrase doesn't open this history.".into()
        }
        Some(CryptError::WrongPassphrase(_)) => {
            "The passphrase this computer has doesn't open this history.".into()
        }
        _ => format!("{e:#}"),
    }
}

// -------------------------------------------------------------------- API

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

fn secret(s: &Secret) -> SecretString {
    crypt::secret_from(s.expose())
}

/// Runs `f` on the history in use, off the async threads; refused while an
/// analysis runs (it holds the history).
async fn with_location(
    st: &Shared,
    f: impl FnOnce(&Location) -> Result<serde_json::Value, (StatusCode, String)> + Send + 'static,
) -> Response {
    if st.jobs.running().is_some() {
        return error(
            StatusCode::CONFLICT,
            "An analysis is running. Try again when it has finished.",
        );
    }
    let ws = st.ws();
    let flag = st.state_dir();
    let done = tokio::task::spawn_blocking(move || {
        let loc = locate(&ws, flag.as_deref()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        f(&loc)
    })
    .await;
    match done {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err((status, message))) => error(status, message),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "That failed."),
    }
}

fn notes_json(notes: &[String]) -> serde_json::Value {
    serde_json::json!({
        "saved": true,
        "note": (!notes.is_empty()).then(|| notes.join(" ")),
    })
}

#[derive(Deserialize)]
struct EncryptionBody {
    on: bool,
    /// Turning it on: the new passphrase (stored on this computer).
    passphrase: Option<Secret>,
    /// Turning it on: the History storage form, saved with it ("Set
    /// passphrase and save"), in the order that shares nothing in plain
    /// text ([`crate::settings::update_state_encrypting`]).
    #[serde(default)]
    state: Option<crate::settings::StateBody>,
}

/// Turns encryption on for the history at `loc` with passphrase `p`
/// (stored here for this account), and records it in pathwarden.toml.
fn turn_on(loc: &Location, p: Option<&Secret>) -> Result<Vec<String>, (StatusCode, String)> {
    let bad = |e: anyhow::Error| (StatusCode::BAD_REQUEST, words(&e));
    let Some(p) = p.filter(|p| !p.is_empty()) else {
        return Err((StatusCode::BAD_REQUEST, "Enter a passphrase.".into()));
    };
    let pass = secret(p);
    crypt::check_passphrase(&pass).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let done = loc.store.encrypt(&pass, loc.push).map_err(bad)?;
    if let Some(path) = loc.store.flag_config() {
        crate::settings::apply(path.to_path_buf(), |d| d.set_state_encrypted(true))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    let mut notes = done.notes;
    if let Err(e) = keystore::store(&loc.dir, &pass) {
        // Encrypted; this session keeps it, the next one asks.
        crypt::give_passphrase(&loc.dir, pass);
        notes.push(format!(
            "The history is encrypted, but the passphrase couldn't be stored on this computer ({e:#}); you'll be asked for it again."
        ));
    }
    Ok(notes)
}

/// "Set passphrase and save": the History storage form saved and the
/// history encrypted, then the settings shared (encrypted).
async fn save_and_encrypt(
    st: &Shared,
    form: pathwarden_core::config_edit::StateEdit,
    passphrase: Option<Secret>,
) -> Response {
    if st.jobs.running().is_some() {
        return error(
            StatusCode::CONFLICT,
            "An analysis is running. Try again when it has finished.",
        );
    }
    // Not another place for the history from a page session.
    if let Some(refused) = crate::settings::history_lock_refusal(st, &form, false).await {
        return refused;
    }
    let ws = st.ws();
    let flag = st.state_dir();
    // A repository or folder that holds a history already: connect to it
    // instead; nothing is encrypted.
    {
        let (ws, form) = (ws.clone(), form.clone());
        let checked =
            tokio::task::spawn_blocking(move || crate::settings::check_new_place(&ws, &form, true))
                .await;
        if let Ok(Err(r)) = checked {
            return r.response();
        }
    }
    let done = tokio::task::spawn_blocking(move || {
        let mut status = StatusCode::BAD_REQUEST;
        let saved = crate::settings::update_state_encrypting(
            &ws,
            |_| Ok(form),
            || {
                let loc = locate(&ws, flag.as_deref())?;
                turn_on(&loc, passphrase.as_ref()).map_err(|(s, e)| {
                    status = s;
                    e
                })
            },
        );
        saved.map_err(|e| (status, e))
    })
    .await;
    match done {
        Ok(Ok((mut notes, shared))) => {
            // Shown when sharing needs attention; otherwise the page shows
            // the settings' state after it reloads.
            if let Some(n) = shared.filter(|n| n.problem) {
                notes.push(n.page);
            }
            Json(notes_json(&notes)).into_response()
        }
        Ok(Err((status, message))) => error(status, message),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "That failed."),
    }
}

/// `POST /api/history/encryption`: on with a new passphrase (stored here
/// for this account), or off. `history storage set --encrypt|--no-encrypt`.
async fn encryption_api(
    State(st): State<Shared>,
    SecretJson(body): SecretJson<EncryptionBody>,
) -> Response {
    let mut body = body;
    if body.on {
        if let Some(form) = body.state.take() {
            return save_and_encrypt(&st, form.edit, body.passphrase.take()).await;
        }
    }
    with_location(&st, move |loc| {
        let bad = |e: anyhow::Error| (StatusCode::BAD_REQUEST, words(&e));
        // `[state] encrypted` in the environment's pathwarden.toml, as
        // `history storage set --encrypt|--no-encrypt` records it (not for
        // `ui --state`, a folder the config doesn't name).
        let record = |on: bool| -> Result<(), (StatusCode, String)> {
            match loc.store.flag_config() {
                Some(path) => {
                    crate::settings::apply(path.to_path_buf(), |d| d.set_state_encrypted(on))
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
                }
                None => Ok(()),
            }
        };
        if !body.on {
            let done = loc.store.decrypt(loc.push).map_err(bad)?;
            record(false)?;
            let mut notes = done.notes;
            if let Some(by) = done.accepted {
                notes.insert(
                    0,
                    format!(
                        "Accepted the history as no longer encrypted ({by}). Nothing was written."
                    ),
                );
            }
            return Ok(notes_json(&notes));
        }
        let notes = turn_on(loc, body.passphrase.as_ref())?;
        Ok(notes_json(&notes))
    })
    .await
}

#[derive(Deserialize)]
struct ChangeBody {
    /// When this computer has none.
    current: Option<Secret>,
    new: Secret,
}

/// `POST /api/history/passphrase/change`: `passphrase change`.
async fn change_api(
    State(st): State<Shared>,
    SecretJson(body): SecretJson<ChangeBody>,
) -> Response {
    with_location(&st, move |loc| {
        let bad = |e: anyhow::Error| (StatusCode::BAD_REQUEST, words(&e));
        if let Some(c) = body.current.as_ref().filter(|c| !c.is_empty()) {
            let current = secret(c);
            if !crypt::opens(&loc.dir, &current).map_err(bad)? {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "The current passphrase doesn't open this history.".into(),
                ));
            }
            crypt::give_passphrase(&loc.dir, current);
        }
        let new = secret(&body.new);
        crypt::check_passphrase(&new).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let stored = keystore::stored_here(&loc.dir).map_err(bad)?;
        let done = loc.store.change_passphrase(&new, loc.push).map_err(bad)?;
        let mut notes = done.notes;
        match stored {
            Some(Source::Store) | Some(Source::File(_)) => {
                if let Err(e) = keystore::store(&loc.dir, &new) {
                    notes.push(format!(
                        "The new passphrase couldn't be stored on this computer ({e:#})."
                    ));
                }
            }
            _ => crypt::give_passphrase(&loc.dir, new),
        }
        Ok(notes_json(&notes))
    })
    .await
}

/// `POST /api/history/passphrase/check`: `passphrase check`.
async fn check_api(State(st): State<Shared>) -> Response {
    with_location(&st, |loc| {
        let bad = |e: anyhow::Error| (StatusCode::BAD_REQUEST, words(&e));
        let Some((pass, source)) = crypt::passphrase_for(&loc.dir).map_err(bad)? else {
            return Err(bad(CryptError::NeedPassphrase.into()));
        };
        if crypt::opens(&loc.dir, &pass).map_err(bad)? {
            Ok(serde_json::json!({ "message": "It opens this history." }))
        } else {
            Err(bad(CryptError::WrongPassphrase(source).into()))
        }
    })
    .await
}

#[derive(Deserialize)]
struct OpenBody {
    passphrase: Secret,
    remember: bool,
}

/// `POST /api/history/passphrase/open`: the card on Runs. `passphrase set`
/// when remembered; otherwise for this session only.
async fn open_api(State(st): State<Shared>, SecretJson(body): SecretJson<OpenBody>) -> Response {
    let r = with_location(&st, move |loc| {
        let bad = |e: anyhow::Error| (StatusCode::BAD_REQUEST, words(&e));
        let pass = secret(&body.passphrase);
        if !crypt::opens(&loc.dir, &pass).map_err(bad)? {
            return Err((
                StatusCode::BAD_REQUEST,
                "That passphrase doesn't open this history.".into(),
            ));
        }
        let mut notes = Vec::new();
        if body.remember {
            if let Err(e) = keystore::store(&loc.dir, &pass) {
                notes.push(format!(
                    "It opens the history, but couldn't be stored on this computer ({e:#}); it is kept for this session."
                ));
            }
        }
        crypt::give_passphrase(&loc.dir, pass);
        Ok(notes_json(&notes))
    })
    .await;
    // Opened: a pull starts at once, and loads what it couldn't before.
    if r.status().is_success() {
        st.auto_pull.timer.kick();
    }
    r
}
