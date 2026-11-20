//! The Connect to a run history page: where the run history
//! is, what it holds (before the passphrase), the passphrase to open it,
//! then this computer's name for it, how often it is pulled and whether it
//! pushes. Every step is [`crate::connect`]'s, as on the command line.

use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_collect::Secret;
use pathwarden_core::config::Keep;
use pathwarden_core::connect::{self, Access, Found, Where};
use pathwarden_core::keystore;
use serde::Deserialize;

use crate::connect::{self as shared, Refused, Session};
use crate::pages::{self, attr, esc, icon, Nav};
use crate::secret_json::SecretJson;
use crate::server::AppState;

type Shared = Arc<AppState>;

const CONNECT_JS: &str = include_str!("assets/connect.js");

/// The page's address.
pub const PATH: &str = "/environments/connect";

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(PATH, get(page))
        .route("/api/connect/probe", post(probe_api))
        .route("/api/connect/open", post(open_api))
        .route("/api/connect/go", post(go_api))
        .route("/api/connect/cancel", post(cancel_api))
        .route(
            "/static/connect.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/javascript")],
                    CONNECT_JS,
                )
                    .into_response()
            }),
        )
}

fn tip(id: &str, about: &str, body: &str, wide: bool) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {about}" aria-describedby="{id}">{i}</button><span class="{cls}" role="tooltip" id="{id}">{body}</span></span>"#,
        i = icon("i-info"),
        cls = if wide { "tip-text wide" } else { "tip-text" },
    )
}

#[derive(Deserialize, Default)]
struct PageQuery {
    /// A probe in progress.
    #[serde(default)]
    s: Option<String>,
    /// The environment to connect (else a new one).
    #[serde(default)]
    env: Option<String>,
    /// Filled in on step 1: "git" or "folder".
    #[serde(default)]
    kind: Option<String>,
    /// The place to fill in, by its token ([`shared::keep_place`], or a
    /// probe's for Change): a URL never goes in the query.
    #[serde(default)]
    from: Option<String>,
    /// Ask for the passphrase even though one here opens it ("Use a
    /// different passphrase").
    #[serde(default)]
    pass: Option<String>,
    /// Filled in from `from`, never from the query.
    #[serde(skip)]
    url: Option<String>,
    #[serde(skip)]
    branch: Option<String>,
    #[serde(skip)]
    folder: Option<String>,
}

const HEAD: &str = r#"<div class="page-head"><div><p class="eyebrow">Environments</p><h1 class="panel-title">Connect to a run history</h1>
<p class="lead">Open the runs and settings that teammates or a server record. Nothing changes on this computer until you connect.</p></div></div>"#;

/// The steps at the top: finished ones ticked.
fn steps(on: usize) -> String {
    let names = ["Where it is", "What it holds", "Open and sync"];
    let mut b = String::from(r#"<ol class="cx-steps" aria-label="Steps">"#);
    for (i, n) in names.iter().enumerate() {
        let k = i + 1;
        let (cls, mark, current) = if k < on {
            ("done", icon("i-check"), "")
        } else if k == on {
            ("on", k.to_string(), r#" aria-current="step""#)
        } else {
            ("", k.to_string(), "")
        };
        let _ = write!(
            b,
            r#"<li class="{cls}"{current}><span class="n">{mark}</span>{n}{done}</li>"#,
            done = if k < on {
                r#"<span class="sr-only"> (done)</span>"#
            } else {
                ""
            }
        );
    }
    b.push_str("</ol>");
    b
}

async fn page(State(st): State<Shared>, Query(mut q): Query<PageQuery>) -> Response {
    let st2 = st.clone();
    let body = tokio::task::spawn_blocking(move || {
        if let Some(t) = q.from.take() {
            if let Some(m) = shared::take_place(st2.workspace.root(), &t) {
                q.kind = Some(if m.is_git() { "git" } else { "folder" }.into());
                q.url = m.url;
                q.branch = m.branch;
                q.folder = m.folder;
                q.env = q.env.take().or(m.env);
            }
        }
        render(&st2, &q)
    })
    .await
    .unwrap_or_default();
    let runs = st.ws().runs();
    Html(pages::shell(
        &pages::Ctx::new(&st, &runs),
        Some(Nav::Environments),
        "Connect to a run history",
        "config",
        &body,
    ))
    .into_response()
}

fn render(st: &AppState, q: &PageQuery) -> String {
    let root = st.workspace.root();
    let session = q.s.as_deref().and_then(|t| shared::load(root, t));
    let mut b = String::from(HEAD);
    let Some(session) = session else {
        // Step 1, or a probe that is gone (connected, cancelled).
        b.push_str(&steps(1));
        if !st.allow_destinations {
            b.push_str(&crate::pages::lock_note("lock-connect", CONNECT_LOCKED));
        }
        b.push_str(&where_card(q));
        b.push_str(r#"<div class="cx-msg" id="cx-msg" aria-live="polite"></div>"#);
        b.push_str(r#"<script src="/static/connect.js" defer></script>"#);
        return b;
    };
    let found = match session.found() {
        Ok(f) => f,
        Err(p) => {
            b.push_str(&steps(1));
            b.push_str(&where_card(q));
            let _ = write!(
                b,
                r#"<div class="cx-msg" id="cx-msg" aria-live="polite">{}</div>"#,
                refused_html(st, &Refused::Problem(p), &session.meta)
            );
            b.push_str(r#"<script src="/static/connect.js" defer></script>"#);
            return b;
        }
    };
    let lock = session.lock(&found);
    // "Use a different passphrase": the passphrase card again.
    let opened = matches!(lock, shared::Lock::Open | shared::Lock::Kept { .. }) && q.pass.is_none();
    b.push_str(&steps(if opened { 3 } else { 2 }));
    b.push_str(&where_done(&session));
    if opened {
        b.push_str(&holds_open(&session, &found, lock));
        b.push_str(&this_computer(st, &session, &found, lock));
    } else {
        // Passphrases kept before 0.2 aren't tried any more: why it
        // asks.
        let old = lock == shared::Lock::Need && keystore::kept_without_key_file();
        b.push_str(&holds_locked(
            &session,
            &found,
            lock == shared::Lock::Wrong,
            old,
        ));
    }
    b.push_str(r#"<script src="/static/connect.js" defer></script>"#);
    b
}

/// Step 1: where the run history is.
fn where_card(q: &PageQuery) -> String {
    let folder = q.kind.as_deref() == Some("folder");
    format!(
        r#"<section class="card setting cx-card" id="cx-where" data-env="{env}">
<header><h2 class="sub">Where it is</h2></header>
<fieldset class="choice"><legend class="sr-only">Where the run history is</legend>
  <label class="option card"><input type="radio" name="cx-kind" value="git"{git_on}><span><strong>A git repository</strong><span class="muted">A private repository that teammates or a server share runs to.</span></span></label>
  <label class="option card"><input type="radio" name="cx-kind" value="folder"{folder_on}><span><strong>A shared folder</strong><span class="muted">A folder on a network share that teammates or a server record into.</span></span></label>
</fieldset>
<div class="fields2" data-when-kind="git"{git_hidden}>
  <div class="field"><label for="cx-url">Repository URL {tip_url}</label><input class="input mono" id="cx-url" value="{url}" placeholder="https://git.example.com/team/pathwarden-history.git" autocomplete="off" spellcheck="false"></div>
  <div class="field"><label for="cx-branch">Branch</label><input class="input mono" id="cx-branch" value="{branch}" placeholder="The repository's default branch" autocomplete="off" spellcheck="false"><p class="hint">Leave it empty unless your team uses another branch.</p></div>
</div>
<div class="field" data-when-kind="folder"{folder_hidden}><label for="cx-folder">Folder</label><input class="input mono" id="cx-folder" value="{folder_value}" placeholder="\\fileserver\security\pathwarden-history" autocomplete="off" spellcheck="false"><p class="hint">The folder that holds the history itself.</p></div>
<div class="card-actions"><button type="button" class="btn primary" id="cx-look">{search} Check it</button><span class="muted small cx-quiet">Pathwarden only reads it. Nothing changes.</span></div>
</section>"#,
        env = attr(q.env.as_deref().unwrap_or_default()),
        git_on = if folder { "" } else { " checked" },
        folder_on = if folder { " checked" } else { "" },
        git_hidden = if folder { " hidden" } else { "" },
        folder_hidden = if folder { "" } else { " hidden" },
        url = attr(q.url.as_deref().unwrap_or_default()),
        branch = attr(q.branch.as_deref().unwrap_or_default()),
        folder_value = attr(q.folder.as_deref().unwrap_or_default()),
        search = icon("i-search"),
        tip_url = tip(
            "tip-cx-signin",
            "Signing in",
            "Git on this computer signs you in, with its own sign-in window if it needs one. Never put a password in the URL.",
            false
        ),
    )
}

/// Where it is, once looked at: one plain sentence and Change.
fn where_done(s: &Session) -> String {
    let place = if s.meta.is_git() {
        format!(
            "A git repository: <code>{}</code>, branch <code>{}</code>.",
            esc(&pathwarden_core::store::redact_url(
                s.meta.url.as_deref().unwrap_or_default()
            )),
            esc(s.meta.branch.as_deref().unwrap_or_default())
        )
    } else {
        format!(
            "A shared folder: <code>{}</code>.",
            esc(s.meta.folder.as_deref().unwrap_or_default())
        )
    };
    let back = change_href(s);
    format!(
        r#"<section class="card setting cx-card"><header><h2 class="sub">Where it is</h2></header>
<p class="cx-found"><span>{place}</span> <button type="button" class="linkish small" data-cx-change="{back}" data-s="{token}">Change</button></p></section>"#,
        back = attr(&back),
        token = attr(&s.token),
    )
}

/// Step 1 again, filled in as this probe was: by its token (the page
/// reads the place back and removes the clone).
fn change_href(s: &Session) -> String {
    format!("{PATH}?from={}", s.token)
}

fn facts_html(rows: &[(String, String, Option<String>)]) -> String {
    let mut b = String::from(r#"<dl class="hs-facts">"#);
    for (dt, dd, sub) in rows {
        let _ = write!(
            b,
            r#"<div><dt>{}</dt><dd>{dd}{}</dd></div>"#,
            esc(dt),
            sub.as_deref()
                .map(|s| format!(r#" <span class="fact-sub">{}</span>"#, esc(s)))
                .unwrap_or_default()
        );
    }
    b.push_str("</dl>");
    b
}

/// Step 2, encrypted: what can be read before the passphrase, and the
/// passphrase to open it. `wrong`: the passphrase this computer has for it
/// doesn't open it (said under the field). `old`: this computer keeps
/// passphrases from before 0.2, which aren't tried on it
/// ([`connect::OLD_PASSPHRASES`] says so).
fn holds_locked(s: &Session, found: &Found, wrong: bool, old: bool) -> String {
    let mut rows: Vec<(String, String, Option<String>)> = found
        .facts(pages::time)
        .into_iter()
        .map(|(l, text, sub)| {
            // The time element is HTML already; the rest is text.
            let html = if l == "Runs" { text } else { esc(&text) };
            (l.to_string(), html, sub.map(str::to_string))
        })
        .collect();
    rows.push((
        "Environment".into(),
        r#"<span class="muted">Shown once the history is open.</span>"#.into(),
        None,
    ));
    format!(
        r#"<section class="card setting cx-card"><header><h2 class="sub">What it holds</h2></header>
<p class="cx-found">This is a Pathwarden history.</p>
{facts}
<div class="card enc-gate cx-gate" id="cx-gate" data-s="{token}">{lock}<div><h2 class="sub">Enter the passphrase to open it</h2><p class="muted">{why}</p>
<div class="field enc-field"><label for="cx-pass">Passphrase</label><input class="input mono{bad}" type="password" id="cx-pass" autocomplete="current-password" spellcheck="false" aria-describedby="cx-pass-err"{invalid}><p class="enc-err" id="cx-pass-err" role="alert"{err_hidden}>{alert} <span>{err}</span></p></div>
<label class="check-row"><input type="checkbox" id="cx-remember"{remember}><span><strong>Remember on this computer</strong><span class="muted">Kept in {store} for your account, so you are asked once.</span></span></label>
<div class="enc-actions"><button type="button" class="btn primary" id="cx-open">{lock} Open the history</button></div></div></div>
</section>"#,
        facts = facts_html(&rows),
        token = attr(&s.token),
        lock = icon("i-lock"),
        alert = icon("i-alert"),
        bad = if wrong { " bad" } else { "" },
        invalid = if wrong { r#" aria-invalid="true""# } else { "" },
        err_hidden = if wrong { "" } else { " hidden" },
        err = if wrong {
            esc(connect::WRONG_PASSPHRASE)
        } else {
            String::new()
        },
        remember = if s.meta.remember { " checked" } else { "" },
        store = esc(keystore::store_name()),
        why = if old {
            esc(connect::OLD_PASSPHRASES)
        } else {
            "Ask whoever set up the history. Pathwarden checks it here before anything is saved."
                .into()
        },
    )
}

/// Step 3: what it holds, now that it is open; with a passphrase kept for
/// another history, a sentence that says so and a way to type one instead.
fn holds_open(s: &Session, found: &Found, lock: shared::Lock) -> String {
    let c = connect::contents(&found.dir);
    let mut rows: Vec<(String, String, Option<String>)> = Vec::new();
    let name = c.name.clone().unwrap_or_else(|| "Not named.".into());
    let domains = if c.domains.is_empty() {
        None
    } else {
        Some(format!(
            "{}.",
            crate::environments::and_list(
                &c.domains
                    .iter()
                    .map(|d| d.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            )
        ))
    };
    rows.push(("Environment".into(), esc(&name), domains));
    rows.push((
        "Runs".into(),
        // Times are the page's own element; the rest is escaped.
        shared::runs_row(found, &c, |t| format!("\u{1}{t}\u{2}"))
            .split(['\u{1}', '\u{2}'])
            .enumerate()
            .map(|(i, part)| {
                if i % 2 == 1 {
                    part.parse::<i64>().map(pages::time).unwrap_or_default()
                } else {
                    esc(part)
                }
            })
            .collect(),
        None,
    ));
    rows.push((
        "What it keeps".into(),
        esc(&format!("{}.", found.keep.words())),
        Some(connect::keep_sub(found.keep).to_string()),
    ));
    if found.keep == Keep::Full && found.git.is_some() {
        rows.push((
            "Shared settings".into(),
            esc(c.settings.as_deref().unwrap_or("None shared yet.")),
            None,
        ));
    }
    let another = matches!(lock, shared::Lock::Kept { another: true, .. });
    rows.push((
        "Encryption".into(),
        if !found.encrypted {
            "Not encrypted.".into()
        } else if another {
            // Said below, with a way to type one instead.
            format!("{} Encrypted.", icon("i-lock"))
        } else {
            format!("{} Encrypted. Your passphrase opens it.", icon("i-lock"))
        },
        None,
    ));
    let kept = if another {
        format!(
            r#"<p class="cx-kept">{lock}{words} <a href="{href}">Use a different passphrase</a></p>"#,
            lock = icon("i-lock"),
            words = esc(connect::ANOTHER_PASSPHRASE),
            href = attr(&format!("{PATH}?s={}&pass=1", s.token)),
        )
    } else {
        String::new()
    };
    format!(
        r#"<section class="card setting cx-card"><header><h2 class="sub">What it holds</h2></header>
{}{kept}
</section>"#,
        facts_html(&rows)
    )
}

/// Step 3: this computer's name for it, how often it is pulled, push or
/// read only, and Connect.
fn this_computer(st: &AppState, s: &Session, found: &Found, lock: shared::Lock) -> String {
    let root = st.workspace.root();
    let c = connect::contents(&found.dir);
    let target = s.meta.env.as_deref();
    let name = shared::suggested_name(root, &c, target);
    let git = s.meta.is_git();
    let mut b = format!(
        r#"<section class="card setting cx-card" id="cx-go-card" data-s="{token}"><header><h2 class="sub">Open and sync</h2></header>
<div class="fields2">
  <div class="field"><label for="cx-name">Environment name</label><input class="input" id="cx-name" value="{name}" maxlength="{max}" autocomplete="off"><p class="hint">From the run history. The name is this computer's own.</p></div>"#,
        token = attr(&s.token),
        name = attr(&name),
        max = crate::environments::MAX_NAME,
    );
    if git {
        let _ = write!(
            b,
            r#"
  <div class="field refresh-field"><label for="cx-refresh">Sync every</label><div class="unit"><input class="input" type="number" id="cx-refresh" min="1" max="{max}" step="1" value="{def}" inputmode="numeric"><span>minutes</span></div><p class="hint">While the app is open, and when it opens.</p></div>"#,
            max = pathwarden_core::config::MAX_REFRESH_MINUTES,
            def = pathwarden_core::config::DEFAULT_REFRESH_MINUTES,
        );
    }
    b.push_str("\n</div>");
    if git {
        let access = s.meta.access().unwrap_or(Access::Unclear {
            detail: String::new(),
        });
        let detail_tip = |id: &str, d: &str| {
            if d.is_empty() {
                String::new()
            } else {
                tip(
                    id,
                    "What git said",
                    &format!("<code>{}</code>", esc(d)),
                    true,
                )
            }
        };
        match &access {
            Access::No { detail } => {
                let _ = write!(
                    b,
                    r#"<div class="cx-push" data-push="no"><p class="cx-found">{} {}</p><p class="muted small">{} {}</p></div>"#,
                    esc(access.sentence()),
                    detail_tip("tip-cx-git", detail),
                    esc(connect::READ_ONLY_WORDS),
                    tip(
                        "tip-cx-ro",
                        "Read only",
                        "Your changes stay on this computer. To share them, get write access and turn on Share runs from this computer in History storage.",
                        true
                    ),
                );
            }
            _ => {
                // Unclear: Read only is chosen, as on the command line.
                let yes = access.can_push();
                let detail = match &access {
                    Access::Unclear { detail } => detail_tip("tip-cx-git", detail),
                    _ => String::new(),
                };
                let _ = write!(
                    b,
                    r#"<div class="cx-push"><p class="cx-found">{sentence} {detail}</p>
<fieldset class="choice"><legend class="sr-only">Sharing</legend>
<label class="option card"><input type="radio" name="cx-push" value="push"{push_on}><span><strong>Share runs from this computer</strong><span class="muted">Runs you start here are added to the run history, for everyone.</span></span></label>
<label class="option card"><input type="radio" name="cx-push" value="read"{read_on}><span><strong>Read only</strong><span class="muted">This computer only reads the run history. Runs you start here stay on this computer.</span></span></label>
</fieldset></div>"#,
                    sentence = esc(access.sentence()),
                    push_on = if yes { " checked" } else { "" },
                    read_on = if yes { "" } else { " checked" },
                );
            }
        }
    }
    // A passphrase found here: kept for the new environment only if
    // Remember stays ticked.
    if let shared::Lock::Kept { remembered, .. } = lock {
        let _ = write!(
            b,
            r#"<label class="check-row cx-remember-kept"><input type="checkbox" id="cx-remember"{on}><span><strong>Remember on this computer</strong><span class="muted">Kept in {store} for your account, so you are asked once.</span></span></label>"#,
            on = if remembered { " checked" } else { "" },
            store = esc(keystore::store_name()),
        );
    }
    let target_name = target.map(|id| st.workspace.named_registry().name_of(id));
    let _ = write!(
        b,
        r#"<p class="cx-adopt">{adopt} {tip}</p>
<div class="card-actions"><button type="button" class="btn primary" id="cx-go">{i} {go}</button><button type="button" class="btn" id="cx-cancel">Cancel</button><span class="muted small cx-what" data-new="{is_new}">{what}</span><span class="save-status small" id="cx-go-msg" aria-live="polite"></span></div>
</section>"#,
        adopt = esc(connect::ADOPTED_WORDS),
        tip = tip(
            "tip-cx-adopt",
            "From the run history",
            connect::ADOPTED_WORDS,
            false
        ),
        i = icon(if git { "i-sync" } else { "i-download" }),
        go = if git { "Connect and sync" } else { "Connect" },
        is_new = target.is_none(),
        what = esc(&match &target_name {
            Some(n) => format!("Connects {n} and loads its runs."),
            None => format!("Adds the environment {name} and loads its runs."),
        }),
    );
    b
}

/// A refusal at step 1, as a note: the sentence, git's own words behind
/// an (i), and what can be done next.
fn refused_html(st: &AppState, r: &Refused, meta: &shared::Meta) -> String {
    refused_note(st, r, meta)
}

/// `meta`: what was looked at (for Start a new run history here, by a
/// token, never the URL in the link).
fn refused_note(st: &AppState, r: &Refused, meta: &shared::Meta) -> String {
    let rest = r.rest();
    let detail = r
        .detail()
        .map(|d| {
            format!(
                " {}",
                tip(
                    "tip-cx-err",
                    "What git said",
                    &format!("<code>{}</code>", esc(d)),
                    true
                )
            )
        })
        .unwrap_or_default();
    let (kind, ic, extra) = match r {
        Refused::Problem(connect::Problem::Empty { git }) => {
            let mut href = String::from("/automate/history?origin=new-shared");
            if *git {
                if let Some(t) = shared::keep_place(st.workspace.root(), meta) {
                    let _ = write!(href, "&from={t}");
                }
            }
            href.push_str("#state");
            (
                "tips",
                "i-info",
                format!(
                    r#"<div class="enc-actions"><a class="btn small-btn primary" href="{}">Start a new run history here</a></div>"#,
                    attr(&href)
                ),
            )
        }
        // The current one: its runs; another: switch to it.
        Refused::UsedBy { id, .. } if *id == st.env_id() => (
            "tips",
            "i-info",
            r#"<div class="enc-actions"><a class="btn small-btn" href="/runs">Open Runs</a></div>"#
                .to_string(),
        ),
        Refused::UsedBy { id, name } => (
            "tips",
            "i-info",
            format!(
                r#"<form class="enc-actions" method="post" action="/environments/switch?to={}&amp;then=/runs"><button type="submit" class="btn small-btn">Switch to {}</button></form>"#,
                attr(id),
                esc(name)
            ),
        ),
        // Look again with git's sign-in window allowed.
        Refused::Problem(connect::Problem::SignIn {
            no_helper: false, ..
        }) => (
            "warn",
            "i-alert",
            format!(
                r#"<div class="enc-actions">{}</div>"#,
                crate::last_pull::sign_in_button("data-cx-sign-in")
            ),
        ),
        _ => ("warn", "i-alert", String::new()),
    };
    format!(
        r#"<div class="note {kind}" role="alert" data-problem="{key}">{icon}<div><p><strong>{lead}</strong>{rest}{detail}</p>{extra}</div></div>"#,
        key = r.key(),
        icon = icon(ic),
        lead = esc(&r.lead()),
        rest = if rest.is_empty() {
            String::new()
        } else {
            format!(" {}", esc(&rest))
        },
    )
}

// -------------------------------------------------------------------- API

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// Why Connect refuses with `--lock-destinations`: looking at a history
/// makes Pathwarden reach (and maybe sign in to) the place the page named,
/// and connecting sends this computer's runs there.
pub const CONNECT_LOCKED: &str = "Safety locks are on, so connecting to a run history can't be done here. You can still open the runs on this computer.";

/// [`CONNECT_LOCKED`] unless the UI was started with the flag.
fn locked(st: &AppState) -> Option<Response> {
    (!st.allow_destinations).then(|| error(StatusCode::BAD_REQUEST, CONNECT_LOCKED))
}

#[derive(Deserialize)]
struct ProbeBody {
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    env: Option<String>,
}

/// `POST /api/connect/probe`: step 1's Connect. `{token}`, or the
/// refusal as a note to show.
async fn probe_api(State(st): State<Shared>, Json(body): Json<ProbeBody>) -> Response {
    if let Some(r) = locked(&st) {
        return r;
    }
    let root = st.workspace.root().to_path_buf();
    let env = body
        .env
        .clone()
        .filter(|e| !e.is_empty() && st.workspace.registry().get(e).is_some());
    let w = if body.kind == "folder" {
        let f = body.folder.clone().unwrap_or_default();
        if f.trim().is_empty() {
            return error(StatusCode::BAD_REQUEST, "Enter the folder.");
        }
        Where::Folder(PathBuf::from(f.trim()))
    } else {
        let url = body.url.clone().unwrap_or_default();
        if url.trim().is_empty() {
            return error(StatusCode::BAD_REQUEST, "Enter the repository's URL.");
        }
        Where::Git {
            url: url.trim().to_string(),
            branch: body.branch.clone().filter(|b| !b.trim().is_empty()),
        }
    };
    let looked = shared::Meta {
        kind: body.kind.clone(),
        url: body.url.clone().map(|u| u.trim().to_string()),
        branch: body.branch.clone().filter(|b| !b.trim().is_empty()),
        folder: body.folder.clone(),
        env: env.clone(),
        ..shared::Meta::default()
    };
    let st2 = st.clone();
    let done = tokio::task::spawn_blocking(move || {
        shared::start(&root, &w, env.as_deref()).map_err(|r| {
            let note = refused_note(&st2, &r, &looked);
            (r, note)
        })
    })
    .await;
    match done {
        Ok(Ok(s)) => Json(serde_json::json!({ "token": s.token })).into_response(),
        Ok(Err((r, note))) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": r.sentence(),
                "problem": r.key(),
                "note": note,
            })),
        )
            .into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't check the run history. Try again; if it keeps failing, see Settings › Logs.",
        ),
    }
}

#[derive(Deserialize)]
struct OpenBody {
    s: String,
    passphrase: Secret,
    #[serde(default)]
    remember: bool,
}

/// `POST /api/connect/open`: step 2's Open the history.
async fn open_api(State(st): State<Shared>, SecretJson(body): SecretJson<OpenBody>) -> Response {
    // The passphrase typed never reaches a log while this runs.
    let _masked = pathwarden_core::redact::mask_while(body.passphrase.expose());
    if let Some(r) = locked(&st) {
        return r;
    }
    let root = st.workspace.root().to_path_buf();
    let done = tokio::task::spawn_blocking(move || {
        let mut s = shared::load(&root, &body.s).ok_or(GONE)?;
        let pass = pathwarden_core::crypt::secret_from(body.passphrase.expose());
        shared::open(&mut s, pass, body.remember)
    })
    .await;
    match done {
        Ok(Ok(())) => Json(serde_json::json!({ "opened": true })).into_response(),
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't open the history. Try again; if it keeps failing, see Settings › Logs.",
        ),
    }
}

/// A probe that is gone (connected or cancelled meanwhile, or older than
/// a day).
const GONE: &str = "This page is out of date. Connect to the run history again.";

#[derive(Deserialize)]
struct GoBody {
    s: String,
    name: String,
    #[serde(default)]
    refresh: Option<u32>,
    #[serde(default)]
    push: Option<bool>,
    /// The Remember box, when the page showed one on this step.
    #[serde(default)]
    remember: Option<bool>,
}

/// `POST /api/connect/go`: Connect and pull. Answers where to go: Runs,
/// with the note that says what was loaded.
async fn go_api(State(st): State<Shared>, Json(body): Json<GoBody>) -> Response {
    if let Some(r) = locked(&st) {
        return r;
    }
    if st.jobs.running().is_some() {
        return error(
            StatusCode::CONFLICT,
            "A collection or analysis is running. Try again when it finishes.",
        );
    }
    let root = st.workspace.root().to_path_buf();
    let done = tokio::task::spawn_blocking(move || {
        let s = shared::load(&root, &body.s).ok_or_else(|| GONE.to_string())?;
        let can_push = s.meta.access().is_some_and(|a| a.can_push())
            || matches!(s.meta.access(), Some(Access::Unclear { .. }));
        let choices = shared::Choices {
            name: body.name.clone(),
            push: can_push && body.push.unwrap_or(false),
            refresh: body
                .refresh
                .unwrap_or(pathwarden_core::config::DEFAULT_REFRESH_MINUTES),
            remember: body.remember,
        };
        shared::connect(&root, &s, &choices, None, true)
    })
    .await;
    match done {
        Ok(Ok(c)) => {
            st.set_env(&c.env_id);
            st.auto_pull.timer.reset();
            let href = format!(
                "/runs?connected={}&keep={}&runs={}&every={}&kind={}",
                c.full_runs,
                c.keep.as_str(),
                c.runs,
                c.refresh,
                if c.git { "git" } else { "folder" }
            );
            Json(serde_json::json!({
                "redirect": href,
                "note": (!c.notes.is_empty()).then(|| c.notes.join(" ")),
            }))
            .into_response()
        }
        // The passphrase must be given (again): the page shows it.
        Ok(Err(e)) if e == shared::NEED_PASSPHRASE || e == connect::WRONG_PASSPHRASE => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e, "reload": true })),
        )
            .into_response(),
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't connect. Try again; if it keeps failing, see Settings › Logs.",
        ),
    }
}

#[derive(Deserialize)]
struct CancelBody {
    s: String,
}

/// `POST /api/connect/cancel`: removes the probe's clone.
async fn cancel_api(State(st): State<Shared>, Json(body): Json<CancelBody>) -> Response {
    let root = st.workspace.root().to_path_buf();
    let back = shared::load(&root, &body.s)
        .and_then(|s| s.meta.env)
        .map(|_| "/automate/history".to_string())
        .unwrap_or_else(|| "/environments".to_string());
    let _ = tokio::task::spawn_blocking(move || shared::discard(&root, &body.s)).await;
    Json(serde_json::json!({ "redirect": back })).into_response()
}

/// What this computer's first sync with the history took, and where its
/// earlier settings are ([`pathwarden_core::settings_sync::first_sync_words`]),
/// when the last sync was a first one not shown yet. Marked shown: the
/// pull note on Settings doesn't say it again.
pub fn first_sync_line(store: &pathwarden_core::store::Store) -> Option<String> {
    let a = pathwarden_core::settings_sync::unseen_applied(store, false)?;
    let first = a.first.as_ref().filter(|f| !f.is_empty())?;
    let names: Vec<&str> = first.iter().map(String::as_str).collect();
    let backups: Vec<&str> = a.backups.iter().map(String::as_str).collect();
    let line = pathwarden_core::settings_sync::first_sync_words(&names, &backups, a.folder_rights);
    let _ = pathwarden_core::settings_sync::unseen_applied(store, true);
    Some(line)
}

/// The note Runs shows right after connecting (`/runs?connected=N&...`):
/// `None` without those. `first`: what the first sync took
/// ([`first_sync_line`]), said after what was loaded.
pub fn landing_note(q: &LandingQuery, first: Option<&str>) -> Option<String> {
    let full_runs = q.connected?;
    let git = q.kind.as_deref() != Some("folder");
    let words = shared::landing_words(
        git,
        q.keep.as_deref() == Some("full"),
        full_runs,
        q.runs.unwrap_or(0),
        q.every
            .unwrap_or(pathwarden_core::config::DEFAULT_REFRESH_MINUTES)
            .clamp(1, pathwarden_core::config::MAX_REFRESH_MINUTES),
    );
    let (lead, rest) = words
        .split_once(". ")
        .map_or((words.as_str(), ""), |(a, b)| (a, b));
    let first = first
        .map(|f| format!(r#"<p class="cx-first">{}</p>"#, esc(f)))
        .unwrap_or_default();
    Some(format!(
        r#"<div class="note ok cx-landing" role="status">{}<div><p><strong>{}.</strong> {}</p>{first}</div></div>"#,
        icon("i-history"),
        esc(lead.trim_end_matches('.')),
        esc(rest)
    ))
}

/// Runs' query right after connecting.
#[derive(Debug, Default, Deserialize)]
pub struct LandingQuery {
    #[serde(default)]
    pub connected: Option<usize>,
    #[serde(default)]
    pub keep: Option<String>,
    #[serde(default)]
    pub runs: Option<usize>,
    #[serde(default)]
    pub every: Option<u32>,
    #[serde(default)]
    pub kind: Option<String>,
}
