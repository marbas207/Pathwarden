//! Settings: extra Tier Zero objects, rule settings and accepted risks, edited
//! in the workspace's `pathwarden.toml`. (Where the run history is kept is
//! edited on Automate › History storage, [`crate::history_ui`], through
//! `/api/settings/state` here.)
//!
//! Also the config plumbing the Zones and Plugins screens share: loading the
//! file for display, and [`edit`], which applies a change to the TOML
//! document (comments and unknown keys kept), validates the result the way
//! every command loads it, and writes it atomically. Nothing that core could
//! not load is ever written.

use std::fmt::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pathwarden_core::config::Config;
use pathwarden_core::config_edit::{self, ConfigDoc, RulesEdit, Stamp, StateEdit, SuppressionEdit};
use pathwarden_core::findings;
use pathwarden_core::time::parse_date;
use serde::Deserialize;

use crate::pages::{self, esc, icon, Nav};
use crate::run_data;
use crate::server::AppState;
use crate::workspace::{Workspace, CONFIG_FILE};

type Shared = Arc<AppState>;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/settings", get(page))
        .route("/api/settings/tier-zero", post(save_tier_zero))
        .route(
            "/api/settings/settings-folders",
            post(save_settings_folders),
        )
        .route(
            "/api/settings/settings-folders/use",
            post(use_settings_folder),
        )
        .route("/api/settings/rules", post(save_rules))
        .route("/api/settings/suppress", post(save_suppression))
        .route(
            "/api/settings/suppress/{index}",
            axum::routing::delete(delete_suppression),
        )
        .route(
            "/api/settings/suppress/{index}/note",
            post(add_suppression_note),
        )
        .route("/api/settings/state", post(save_state))
        .route("/api/settings/full-runs", post(save_full_runs))
        .route("/api/settings/sync", post(crate::sync_ui::sync_section))
        .route("/api/settings/dismiss", post(crate::sync_ui::dismiss))
        .route("/api/settings/sharing", get(crate::sync_ui::sharing))
        .route("/api/findings", get(search_findings))
}

// ------------------------------------------------------------ the config

/// The workspace config as the pages show it.
pub struct Loaded {
    pub config: Config,
    pub exists: bool,
    /// Why the file can't be loaded (it is then shown, and edits that leave
    /// the problem in place are refused with the same message).
    pub error: Option<String>,
}

pub(crate) fn load(st: &AppState) -> Loaded {
    load_ws(&st.ws())
}

/// [`load`] for the environment `ws` is scoped to.
pub fn load_ws(ws: &Workspace) -> Loaded {
    let path = ws.config_path();
    let exists = path.is_file();
    if !exists {
        return Loaded {
            config: Config::default(),
            exists,
            error: None,
        };
    }
    let checked = std::fs::read_to_string(&path)
        .map_err(|e| format!("Couldn't read {CONFIG_FILE}: {e}"))
        .and_then(|t| config_edit::check(&t));
    match checked {
        Ok(config) => Loaded {
            config,
            exists,
            error: None,
        },
        Err(e) => Loaded {
            config: Config::default(),
            exists,
            error: Some(e),
        },
    }
}

/// One writer at a time, so two quick saves cannot lose each other's change.
static WRITE: Mutex<()> = Mutex::new(());

/// Applies `change` to `pathwarden.toml` (created from the annotated example
/// when missing), validates the whole file and writes it atomically.
/// A change to the shared settings is shared ([`apply_sharing`]).
pub fn apply<T>(
    path: PathBuf,
    change: impl FnOnce(&mut ConfigDoc) -> Result<T, String>,
) -> Result<T, String> {
    apply_sharing(path, &Share::default(), change).map(|(out, _)| out)
}

/// Where a saved change to the shared settings goes
/// ([`pathwarden_core::settings_sync`]).
#[derive(Debug, Clone, Default)]
pub struct Share {
    /// Where a relative `[state] path` starts: the file's folder (an
    /// environment of the workspace) when `None`; the current folder for
    /// `pathwarden config -c FILE`, as `pathwarden run -c FILE` takes it.
    pub base: Option<PathBuf>,
    /// The environment's name, for the repository's `environment.json`.
    pub env_name: Option<String>,
}

/// [`apply`], then, when the history is a git repository that keeps full
/// runs and settings and the change touched the shared settings (or turned
/// sharing on), shares it: a machine that pushes commits and pushes it at
/// once. Returns what `change` returned, and a note for the user about the
/// sharing, if any; the save itself never fails over it.
pub fn apply_sharing<T>(
    path: PathBuf,
    share: &Share,
    change: impl FnOnce(&mut ConfigDoc) -> Result<T, String>,
) -> Result<(T, Option<String>), String> {
    let (out, pending) = apply_for_page(path, share, change)?;
    Ok((out, pending.run().map(|n| n.text)))
}

/// A saved change still to share ([`apply_for_page`]): the app shares it
/// after the page has its answer ([`crate::sync_ui::share_later`]).
pub struct PendingShare {
    path: PathBuf,
    share: Share,
    before: String,
    after: String,
}

impl PendingShare {
    /// The `pathwarden.toml` saved.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Whether there is anything to share: the history shares settings,
    /// this computer pushes, and the save changed the shared settings (or
    /// started sharing them).
    pub fn needed(&self) -> bool {
        use pathwarden_core::settings_sync;
        let Ok(now) = config_edit::check(&self.after) else {
            return false;
        };
        if settings_sync::inactive(&now.state).is_some() || !now.state.pushes() {
            return false;
        }
        let was = config_edit::check(&self.before)
            .ok()
            .is_some_and(|c| settings_sync::inactive(&c.state).is_none());
        !was || settings_sync::shared_changed(&self.before, &self.after, &self.path)
    }

    /// Shared whether or not the save changed the shared settings (when the
    /// history shares them, and this computer pushes): for a save whose
    /// sharing waited ([`update_state_encrypting`]).
    pub fn from_scratch(mut self) -> Self {
        self.before.clear();
        self
    }

    /// Shares it (blocking: it may reach the network), and says how it went.
    pub fn run(self) -> Option<pathwarden_core::settings_sync::Note> {
        if !self.needed() {
            return None;
        }
        let base = self
            .share
            .base
            .clone()
            .or_else(|| self.path.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_default();
        pathwarden_core::settings_sync::share_after_save(
            &self.path,
            &base,
            self.share.env_name.as_deref(),
        )
    }
}

/// [`apply`] without the sharing: the save, and what is left to share.
pub fn apply_for_page<T>(
    path: PathBuf,
    share: &Share,
    change: impl FnOnce(&mut ConfigDoc) -> Result<T, String>,
) -> Result<(T, PendingShare), String> {
    let _guard = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    // An environment's folder is made with it, but may have been removed.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
    }
    // Across processes too: the app and `pathwarden config` both come here.
    let (out, before, after) = config_edit::with_lock(&path, || {
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        let mut doc = ConfigDoc::load(&path)?;
        let out = change(&mut doc)?;
        let text = doc.text_for_file();
        config_edit::check(&text).map_err(|e| format!("Not saved: {e}"))?;
        config_edit::write_atomic(&path, &text)
            .map_err(|e| format!("Couldn't save {}: {e}", path.display()))?;
        Ok((out, before, text))
    })?;
    // Sharing reaches the network: other saves need not wait for it.
    Ok((
        out,
        PendingShare {
            path,
            share: share.clone(),
            before,
            after,
        },
    ))
}

/// [`apply`] on a blocking thread, answered as JSON.
pub(crate) async fn edit(
    st: &AppState,
    change: impl FnOnce(&mut ConfigDoc) -> Result<(), String> + Send + 'static,
) -> Response {
    edit_in(&st.ws(), change).await
}

/// [`edit_in`] whose change also returns what the page needs back: the
/// answer is `{"saved": true}` with its fields added.
pub(crate) async fn edit_answering(
    ws: &Workspace,
    change: impl FnOnce(&mut ConfigDoc) -> Result<serde_json::Value, String> + Send + 'static,
) -> Response {
    let path = ws.config_path();
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    match tokio::task::spawn_blocking(move || apply_for_page(path, &share, change)).await {
        Ok(Ok((extra, pending))) => {
            // `sharing`: the change goes to the repository now;
            // `/api/settings/sharing` says how it went.
            let sharing = crate::sync_ui::share_later(pending);
            let mut out = serde_json::json!({ "saved": true, "sharing": sharing });
            if let (Some(o), serde_json::Value::Object(e)) = (out.as_object_mut(), extra) {
                o.extend(e);
            }
            Json(out).into_response()
        }
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Saving failed."),
    }
}

/// The settings as the file holds them now, for a save that compares with
/// what its page loaded: refused when the file can't be read, since then
/// nobody can tell what the page would overwrite.
fn current(d: &ConfigDoc) -> Result<Config, String> {
    d.validate().map_err(|e| {
        format!("{CONFIG_FILE} can't be loaded, so this save can't tell what it would change: {e}. Fix the file in a text editor, then reload this page.")
    })
}

/// [`edit`] in the environment `ws` is scoped to.
pub(crate) async fn edit_in(
    ws: &Workspace,
    change: impl FnOnce(&mut ConfigDoc) -> Result<(), String> + Send + 'static,
) -> Response {
    let path = ws.config_path();
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    match tokio::task::spawn_blocking(move || apply_for_page(path, &share, change)).await {
        // `sharing`: the change goes to the repository now;
        // `/api/settings/sharing` says how it went.
        Ok(Ok(((), pending))) => {
            let sharing = crate::sync_ui::share_later(pending);
            Json(serde_json::json!({ "saved": true, "sharing": sharing })).into_response()
        }
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Saving failed."),
    }
}

pub(crate) fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// The note shown after a save: changes apply to the next analysis, and how
/// to run one now. The latest run can only be repeated when its inputs
/// still exist (the demo always does; uploads are deleted after analysis).
pub(crate) fn after_save(st: &AppState) -> String {
    let runs = st.ws().runs();
    let action = match runs.first() {
        _ if st.jobs.running().is_some() => {
            "An analysis is running now; it started before this change.".to_string()
        }
        None => r#"<a href="/analyze">Analyze a collection</a> or try the demo to see it."#.into(),
        Some(r) if r.demo => format!(
            r#"<button type="button" class="btn small-btn" data-demo data-demo-again>{} Re-analyze the demo</button>"#,
            icon("i-play")
        ),
        // A network path is not even looked at (that would sign in to it).
        Some(r)
            if !crate::security::is_network_path(&r.source)
                && std::path::Path::new(&r.source).exists() =>
        {
            format!(
            r#"<button type="button" class="btn small-btn" data-rerun-path="{}" data-rerun-env="{}">{} Re-analyze the latest run</button>"#,
            esc(&r.source),
            esc(&st.env_id()),
            icon("i-play")
        )
        }
        Some(_) => "The latest run's collector files were removed after it was analyzed, so <a href=\"/analyze\">analyze the collection again</a> to see the change.".into(),
    };
    format!(
        r#"<div class="saved-note card" id="saved" hidden role="status">{}<div><strong>Saved.</strong> Changes apply to the next analysis. <span class="saved-action">{action}</span></div><button type="button" class="fl-remove" id="saved-close" aria-label="Close">{}</button></div>"#,
        icon("i-check"),
        icon("i-x"),
    )
}

/// One line saying which workspace settings an analysis applies ("2 zones
/// · 1 accepted risk · 3 extra Tier Zero objects"), linking to Settings.
/// `lead` starts it ("This analysis applies", ...).
pub(crate) fn applies_line(st: &AppState, lead: &str) -> String {
    applies_line_in(&st.ws(), lead)
}

/// A settings line with fixed text (where the run goes isn't settled yet).
pub(crate) fn applies_note(text: &str) -> String {
    format!(
        r#"<p class="applies">{} <span>{}.</span> <a href="/settings">Settings</a></p>"#,
        icon("i-gear"),
        esc(text)
    )
}

/// [`applies_line`] for the environment `ws` is scoped to.
/// [`applies_line_in`] as words: "The next analysis applies: the default
/// settings (...)." `Err` with what to say when the file can't be loaded.
pub(crate) fn applies_words_in(ws: &Workspace, lead: &str) -> Result<String, String> {
    let loaded = load_ws(ws);
    if loaded.error.is_some() {
        return Err(format!(
            "{CONFIG_FILE} can't be loaded, so analyzing fails until it is fixed."
        ));
    }
    let what = applies_parts(&loaded.config).unwrap_or_else(|| {
        "the default settings (no zones, accepted risks or extra Tier Zero objects)".to_string()
    });
    let env = if ws.registry().several() {
        format!(" ({})", ws.env_name())
    } else {
        String::new()
    };
    Ok(format!("{lead}{env}: {what}."))
}

pub(crate) fn applies_line_in(ws: &Workspace, lead: &str) -> String {
    let loaded = load_ws(ws);
    if loaded.error.is_some() {
        return format!(
            r#"<p class="applies warn">{} <span>{CONFIG_FILE} can't be loaded, so analyzing fails until it is fixed.</span> <a href="/settings">Settings</a></p>"#,
            icon("i-alert")
        );
    }
    let c = &loaded.config;
    let what = applies_parts(c).unwrap_or_else(|| {
        "the default settings (no zones, accepted risks or extra Tier Zero objects)".to_string()
    });
    let env = if ws.registry().several() {
        format!(" ({})", ws.env_name())
    } else {
        String::new()
    };
    let lead = format!("{lead}{env}");
    format!(
        r#"<p class="applies">{} <span>{}: {}.</span> <a href="/settings">Settings</a></p>"#,
        icon("i-gear"),
        esc(&lead),
        esc(&what)
    )
}

/// What a config changes from the defaults ("2 Privilege Zones · 1
/// accepted risk"), or `None` for the defaults.
pub(crate) fn applies_parts(c: &Config) -> Option<String> {
    let count = |n: usize, one: &str, many: &str| {
        (n > 0).then(|| format!("{} {}", pages::num(n), if n == 1 { one } else { many }))
    };
    let d = pathwarden_core::config::RulesConfig::default();
    let r = &c.rules;
    let tuned = r.stale_days != d.stale_days
        || r.password_age_days != d.password_age_days
        || r.krbtgt_age_days != d.krbtgt_age_days
        || r.sso_key_age_days != d.sso_key_age_days
        || r.severity != d.severity;
    let parts: Vec<String> = [
        count(c.zones.len(), "Privilege Zone", "Privilege Zones"),
        count(c.suppress.len(), "accepted risk", "accepted risks"),
        count(
            c.tier_zero.len(),
            "extra Tier Zero object",
            "extra Tier Zero objects",
        ),
        count(r.disabled.len(), "check turned off", "checks turned off"),
        tuned.then(|| "custom rule thresholds".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Under a configuration page's title, only when `pathwarden.toml` can't
/// be loaded: what is wrong and how to fix it. (Where the file is, the
/// Environments page says.)
pub(crate) fn file_line_if_there(st: &AppState, loaded: &Loaded) -> String {
    file_line(st, loaded)
}

/// [`file_line_if_there`].
pub(crate) fn file_line(_st: &AppState, loaded: &Loaded) -> String {
    let Some(e) = &loaded.error else {
        return String::new();
    };
    format!(
        r#"<div class="cfg-error card" role="alert">{}<div><strong>{CONFIG_FILE} can't be loaded, so analyzing fails until it is fixed.</strong><pre>{}</pre><p class="muted small">Fix it in a text editor, or save a change here that fixes it. Pages show the defaults until then.</p></div></div>"#,
        icon("i-alert"),
        esc(e)
    )
}

// ------------------------------------------------------------------ page

fn rule_title(id: &str) -> &'static str {
    findings::rules()
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(id))
        .map(|r| r.title)
        .unwrap_or("")
}

async fn page(State(st): State<Shared>) -> Html<String> {
    let runs = st.ws().runs();
    let loaded = load(&st);
    let has_index = run_data::latest_with(&st.ws(), run_data::OBJECTS_FILE).is_some();
    let has_findings = run_data::latest_with(&st.ws(), run_data::EVENT_FILE).is_some();
    let sync = crate::sync_ui::view_for(&st, true).await;
    Html(render(
        &pages::Ctx::new(&st, &runs),
        &st,
        &loaded,
        has_index,
        has_findings,
        sync.as_ref(),
    ))
}

pub(crate) fn picker(id: &str, placeholder: &str, kinds: &str, enabled: bool) -> String {
    format!(
        r#"<div class="picker" data-picker="{id}" data-kinds="{kinds}">
  <div class="pathfield card">{i_search}<label class="sr-only" for="{id}-q">{placeholder}</label><input type="search" id="{id}-q" placeholder="{placeholder}" autocomplete="off" spellcheck="false"{search}><button type="button" class="btn small-btn" data-add-typed>{i_plus} Add</button></div>
  <ul class="results card" role="listbox" hidden></ul>
  {nosearch}
</div>"#,
        i_search = icon("i-search"),
        i_plus = icon("i-plus"),
        search = if enabled { " data-search" } else { "" },
        nosearch = if enabled {
            String::new()
        } else {
            r#"<p class="muted small">Searching needs one analysis first (<a href="/analyze">analyze a collection</a> or try the demo); you can still type a name or SID and add it.</p>"#.into()
        },
    )
}

fn render(
    ctx: &pages::Ctx,
    st: &AppState,
    loaded: &Loaded,
    has_index: bool,
    has_findings: bool,
    sync: Option<&crate::sync_ui::View>,
) -> String {
    let c = &loaded.config;
    let mut b = String::new();
    let tag = |key: &str| {
        sync.map(|v| crate::sync_ui::tag(v, key))
            .unwrap_or_default()
    };
    let conflict = |key: &str| sync.and_then(|v| crate::sync_ui::conflict(v, key));
    let reader = |key: &str| {
        sync.map(|v| crate::sync_ui::reader_action(v, key))
            .unwrap_or_default()
    };
    // The settings with two values of a section that have no field of
    // their own, at the top of its card.
    let clash_list = |key: &str, fields: &[&str]| {
        sync.map(|v| crate::sync_ui::clash_list(v, key, fields))
            .unwrap_or_default()
    };
    let mark = |key: &str, id: &str| {
        sync.map(|v| crate::sync_ui::merged_mark(v, key, id))
            .unwrap_or_default()
    };
    // The section links, each with the amber dot while its section has a
    // setting with two values.
    let mut jump = String::new();
    for (href, key, name) in [
        ("tier-zero", "tier_zero", "Tier Zero"),
        (
            "settings-folders",
            "settings_folders",
            "Tier Zero settings folders",
        ),
        ("rules", "rules", "Rules"),
        ("risks", "suppress", "Accepted risks"),
        ("evidence", "", "Evidence packs"),
    ] {
        let dot = !key.is_empty() && sync.is_some_and(|v| crate::sync_ui::jump_dot(v, key));
        let _ = write!(
            jump,
            r##"<a href="#{href}"{title}>{name}{dot}</a>"##,
            title = if dot {
                format!(r#" title="{}""#, pages::SETTINGS_DIFFER)
            } else {
                String::new()
            },
            dot = if dot {
                format!(
                    r#"<span class="sr-only">: {}</span><span class="nav-dot" aria-hidden="true"></span>"#,
                    pages::SETTINGS_DIFFER.to_lowercase()
                )
            } else {
                String::new()
            },
        );
    }
    let _ = write!(
        b,
        r##"<div class="page-head"><div><p class="eyebrow">Configure</p><h1 class="panel-title">Settings</h1>
<p class="lead">Set up how {env} is judged: extra Tier Zero objects, rules, accepted risks and evidence signing.</p></div></div>
{file}{line}
<nav class="jump" aria-label="Sections">{jump}{logs}</nav>
"##,
        logs = crate::logs_ui::jump_link(ctx.crash),
        file = file_line(st, loaded),
        env = if ctx.env_name.trim().is_empty() {
            "this environment".to_string()
        } else {
            esc(&ctx.env_name)
        },
        line = sync
            .map(|v| crate::sync_ui::sync_line(v, "settings"))
            .unwrap_or_default(),
    );

    // Tier Zero
    let here = sync
        .map(|v| crate::sync_ui::here_items(v, "tier_zero"))
        .unwrap_or_default();
    let mut chips = String::new();
    for t in &c.tier_zero {
        let from = mark("tier_zero", &t.trim().to_lowercase());
        if here.contains(t) {
            chip_here(&mut chips, t);
        } else {
            chip_marked(&mut chips, t, &from);
        }
    }
    let t0_editor = format!(
        r#"{picker}
<ul class="chiplist" id="t0-list" data-empty="No additions: only the built-in Tier Zero objects are used.">{chips}</ul>
<div class="card-actions"><button type="button" class="btn primary" data-save><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save Tier Zero</button>{reader}<span class="save-status muted small" aria-live="polite"></span></div>"#,
        picker = picker(
            "t0",
            "Search users, computers and groups, or type a name or SID",
            "User,Computer,Group",
            has_index
        ),
        reader = reader("tier_zero"),
    );
    // Changed on both sides: the choice instead of the editor (kept, hidden,
    // for the page's script).
    let t0_body = match conflict("tier_zero") {
        Some(block) => format!("{block}<div hidden>{t0_editor}</div>"),
        None => format!("{}{t0_editor}", clash_list("tier_zero", &[])),
    };
    let _ = write!(
        b,
        r#"<section class="card setting" id="tier-zero" data-section="tier-zero" data-loaded="{loaded}">
<header><h2 class="sub">Additional Tier Zero{tag}</h2>
<p class="muted">Pathwarden already treats domain controllers, Domain Admins, Enterprise Admins, CA servers and the other built-in control points as Tier Zero. Add what your organization also treats that way: Entra Connect servers and their sync accounts, PAM or password vaults, servers that back up domain controllers, and hypervisors that host them.</p></header>
{t0_body}
</section>
"#,
        loaded = pages::json_attr(&serde_json::to_string(&c.tier_zero).unwrap_or_default()),
        tag = tag("tier_zero"),
    );

    // Tier Zero settings folders.
    let here = sync
        .map(|v| crate::sync_ui::here_items(v, "settings_folders"))
        .unwrap_or_default();
    // Folders the run history brought: listed, not read here until
    // someone on this computer chooses Use (as a mapping pack's trust).
    let waiting = pathwarden_core::folder_origin::waiting(c, &st.ws().config_path());
    let repo = pathwarden_core::folder_origin::from_repo(c, &st.ws().config_path());
    let mut chips = String::new();
    for f in &c.settings_folders {
        if waiting.contains(f) {
            let _ = write!(
                chips,
                r#"<li class="chip-item waiting" data-value="{raw}"><span class="chip-text">{v}</span><span class="folder-waiting">{why}</span><button type="button" class="btn small-btn" data-use-folder="{raw}">Use</button><button type="button" class="fl-remove" data-remove aria-label="Remove {v}">{x}</button></li>"#,
                raw = pages::attr(f),
                v = esc(f),
                x = icon("i-x"),
                why = if repo.contains(f) {
                    FOLDER_WAITING
                } else {
                    FOLDER_WAITING_HERE
                },
            );
        } else if here.contains(f) {
            chip_here(&mut chips, f);
        } else {
            chip_marked(
                &mut chips,
                f,
                &mark("settings_folders", &pathwarden_core::folder_origin::key(f)),
            );
        }
    }
    let sf_editor = format!(
        r#"<div class="picker" data-folder-field>
  <div class="pathfield card">{i_folder}<label class="sr-only" for="sf-q">A folder or share</label><input type="text" id="sf-q" placeholder="{SETTINGS_FOLDERS_PLACEHOLDER}" autocomplete="off" spellcheck="false"><button type="button" class="btn small-btn" data-add-typed>{i_plus} Add</button></div>
</div>
<ul class="chiplist" id="sf-list">{chips}</ul>
<div class="card-actions"><button type="button" class="btn primary" data-save><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save folders</button>{reader}<span class="save-status muted small" aria-live="polite"></span></div>"#,
        i_folder = icon("i-folder"),
        i_plus = icon("i-plus"),
        reader = reader("settings_folders"),
    );
    let sf_body = match conflict("settings_folders") {
        Some(block) => format!("{block}<div hidden>{sf_editor}</div>"),
        None => format!("{}{sf_editor}", clash_list("settings_folders", &[])),
    };
    let _ = write!(
        b,
        r#"<section class="card setting" id="settings-folders" data-section="settings-folders" data-loaded="{loaded}">
<header><h2 class="sub">Tier Zero settings folders{tag}</h2>
<p class="muted">{SETTINGS_FOLDERS_INTRO}{tip}</p></header>
{sf_body}
</section>
"#,
        loaded = pages::json_attr(&serde_json::to_string(&c.settings_folders).unwrap_or_default()),
        tag = tag("settings_folders"),
        tip = pages::tip("tip-sf", "Tier Zero settings folders", SETTINGS_FOLDERS_TIP),
    );

    // Rules
    let r = &c.rules;
    let exposure = r.severity == pathwarden_core::config::SeverityMode::Exposure;
    let mut rule_rows = String::new();
    for row in r.rows() {
        let _ = write!(
            rule_rows,
            r#"<div class="rule-row{set_cls}" data-rule="{id}"><span class="rule-id">{id}</span><span class="rule-title"><label class="rule-name" for="chk-{id}">{title}</label>{who}</span>{select}<input type="checkbox" class="switch" name="rule" id="chk-{id}" value="{id}"{checked} aria-label="{id} {title}"></div>"#,
            id = row.id,
            title = esc(row.title),
            set_cls = if row.set.is_some() { " sev-set" } else { "" },
            who = row.set.as_ref().map(severity_who).unwrap_or_default(),
            select = severity_select(&row),
            checked = if row.on { " checked" } else { "" },
        );
    }
    let rules_body = conflict("rules");
    // A setting with two values: marked, with its choice under its field.
    let field = |id: &str| -> (&'static str, String) {
        match sync.and_then(|v| crate::sync_ui::clash_row(v, &format!("rules.{id}"))) {
            Some(row) => (" has-clash", row),
            None => ("", String::new()),
        }
    };
    let (c_stale, r_stale) = field("stale_days");
    let (c_pwd, r_pwd) = field("password_age_days");
    let (c_krb, r_krb) = field("krbtgt_age_days");
    let (c_sso, r_sso) = field("sso_key_age_days");
    let (c_sev, r_sev) = field("severity");
    let rules_list = clash_list(
        "rules",
        &[
            "rules.stale_days",
            "rules.password_age_days",
            "rules.krbtgt_age_days",
            "rules.sso_key_age_days",
            "rules.severity",
        ],
    );
    let _ = write!(
        b,
        r#"<section class="card setting" id="rules" data-section="rules" data-loaded="{loaded}">
<header><h2 class="sub">Rules{tag}</h2><p class="muted">When an account or password counts as old, how attack paths are rated, and which rules run.</p></header>
{conflict}{rules_list}<div class="fields3"{hidden}>
  <div class="field{c_stale}"><label for="stale_days">Stale Tier Zero account</label><div class="unit"><input class="input" type="number" id="stale_days" min="1" max="36500" step="1" value="{stale}" required><span>days</span></div>{r_stale}<p class="hint">Tier Zero accounts with no logon for this long are reported. It also sets which accounts count as active for exposure.</p></div>
  <div class="field{c_pwd}"><label for="password_age_days">Old Tier Zero password</label><div class="unit"><input class="input" type="number" id="password_age_days" min="1" max="36500" step="1" value="{pwd}" required><span>days</span></div>{r_pwd}<p class="hint">Tier Zero passwords older than this are reported.</p></div>
  <div class="field{c_krb}"><label for="krbtgt_age_days">Old krbtgt password</label><div class="unit"><input class="input" type="number" id="krbtgt_age_days" min="1" max="36500" step="1" value="{krbtgt}" required><span>days</span></div>{r_krb}<p class="hint">The krbtgt account signs every Kerberos ticket.</p></div>
  <div class="field{c_sso}"><label for="sso_key_age_days">Old Seamless SSO key</label><div class="unit"><input class="input" type="number" id="sso_key_age_days" min="1" max="36500" step="1" value="{sso}" required><span>days</span></div>{r_sso}<p class="hint">The Seamless SSO key signs in to Entra ID as any synced user.</p></div>
</div>
<fieldset class="choice{c_sev}"{hidden}><legend>How attack paths are rated</legend>{r_sev}
  <label class="option card"><input type="radio" name="severity" value="exposure"{exp_on}><span><span class="opt-title"><strong>By exposure</strong> <span class="tag">Default</span></span><span class="muted">A path many users and computers can use is critical; one only a few can reach is lower, as in BloodHound Enterprise.</span></span></label>
  <label class="option card"><input type="radio" name="severity" value="static"{static_on}><span><strong>By rule</strong><span class="muted">Each rule keeps its own severity, however many accounts can use the path.</span></span></label>
</fieldset>
<details class="rules-box"{hidden}><summary><span>Rules</span> <span class="muted small" id="rules-count"></span></summary>
<p class="muted small">Turn a rule off to skip it, or set its severity. To hide one finding or one rule's findings with a reason, add an accepted risk below instead: it stays on record and counts as open again after its review date.</p>
<div class="rules-tools"><div class="seg" role="group" aria-label="Show"><button type="button" class="seg-btn" data-show="all" aria-pressed="true">All <span class="n" id="rules-all-n"></span></button><button type="button" class="seg-btn" data-show="changed" aria-pressed="false">Changed <span class="n" id="rules-changed-n"></span></button></div><span class="sev-head">Severity{sev_tip}</span></div>
<div class="rule-list">{rule_rows}</div>
<p class="muted small rules-none" id="rules-none" hidden>Every rule is on, with its default severity.</p>
<div class="rules-reset" id="rules-reset-box" hidden><button type="button" class="btn" id="rules-reset">Reset to default</button></div></details>
<div class="card-actions"{hidden}><button type="button" class="btn primary" data-save><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save rules</button>{reader}<span class="save-status muted small" aria-live="polite"></span></div>
</section>
"#,
        tag = tag("rules"),
        hidden = if rules_body.is_some() { " hidden" } else { "" },
        conflict = rules_body.clone().unwrap_or_default(),
        reader = reader("rules"),
        loaded = pages::json_attr(&rules_view(r).to_string()),
        stale = r.stale_days,
        pwd = r.password_age_days,
        krbtgt = r.krbtgt_age_days,
        sso = r.sso_key_age_days,
        exp_on = if exposure { " checked" } else { "" },
        static_on = if exposure { "" } else { " checked" },
        sev_tip = pages::tip("tip-sev", "Severity", SEVERITY_TIP),
    );

    // Accepted risks
    let now = pathwarden_core::analyze::now();
    // This computer and account: whom a note is saved as.
    let me = pathwarden_core::identity::Actor::current();
    let mut rows = String::new();
    for (i, s) in c.suppress.iter().enumerate() {
        let target = match (&s.fingerprint, &s.rule) {
            (Some(fp), _) => format!(
                r#"<span class="risk-kind">Finding</span> <code>{}</code>"#,
                esc(fp)
            ),
            (_, Some(rule)) => format!(
                r#"<span class="risk-kind">Every finding of</span> <code>{}</code> <span class="muted">{}</span>"#,
                esc(rule),
                esc(rule_title(rule))
            ),
            _ => String::new(),
        };
        let expiry = match s.expires.as_deref() {
            None => r#"<span class="muted small">No review date</span>"#.to_string(),
            Some(d) => match parse_date(d) {
                Some(day) if now >= day + 86_400 => format!(
                    r#"<span class="pill expired"><span class="dot" aria-hidden="true"></span>Review by {}</span>"#,
                    esc(&pathwarden_core::time::day_of(d))
                ),
                Some(day) if now + 30 * 86_400 >= day => format!(
                    r#"<span class="pill soon-exp"><span class="dot" aria-hidden="true"></span>Review by {}</span>"#,
                    esc(&pathwarden_core::time::day_of(d))
                ),
                _ => format!(
                    r#"<span class="muted small">Review by {}</span>"#,
                    esc(&pathwarden_core::time::day_of(d))
                ),
            },
        };
        let data = serde_json::json!({
            "index": i,
            "fingerprint": s.fingerprint,
            "rule": s.rule,
            "reason": s.reason,
            "expires": s.expires,
        });
        let risk_id = s
            .fingerprint
            .as_deref()
            .or(s.rule.as_deref())
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let merged = mark("suppress", &risk_id);
        let tag = if !merged.is_empty() {
            merged
        } else if from_repository(s, &me.computer, shared_through_repository(c)) {
            format!(
                r#"<span class="risk-tag">{}From the repository</span>"#,
                icon("i-history")
            )
        } else {
            String::new()
        };
        let _ = write!(
            rows,
            r#"<div class="risk-row" data-risk="{data}"><div class="risk-main"><div>{target}{tag}</div><p class="risk-reason">{reason}</p>{who}{notes}</div><div class="risk-exp">{expiry}</div><div class="risk-actions"><button type="button" class="btn small-btn" data-note-risk aria-expanded="false" aria-controls="note-form">{i_plus} Add a note</button><button type="button" class="btn small-btn" data-edit-risk>{i_edit} Edit</button><button type="button" class="btn small-btn danger" data-remove-risk aria-label="Remove">{i_trash}</button></div></div>"#,
            data = pages::json_attr(&data.to_string()),
            reason = esc(&s.reason),
            who = risk_who(s),
            notes = risk_notes(s),
            i_plus = icon("i-plus"),
            i_edit = icon("i-edit"),
            i_trash = icon("i-trash"),
        );
    }
    let warnings = if c.warnings.is_empty() {
        String::new()
    } else {
        // Keys this version doesn't know, under their heading; notices that
        // name no key, each a sentence of its own after them.
        let keys: String = c
            .warnings
            .iter()
            .filter(|w| !w.key.is_empty())
            .map(|w| {
                let place = match (w.risk, w.note) {
                    (0, _) => w.place.clone().unwrap_or_default(),
                    (r, Some(n)) => format!("Accepted risk {r}, note {n}"),
                    (r, None) => format!("Accepted risk {r}"),
                };
                format!("<p>{}: <code>{}</code></p>", esc(&place), esc(&w.key))
            })
            .collect();
        let notices: String = c
            .warnings
            .iter()
            .filter(|w| w.key.is_empty())
            .map(|w| format!("<p>{}</p>", esc(&w.to_string())))
            .collect();
        let heading = if keys.is_empty() {
            String::new()
        } else {
            format!(
                "<p><strong>{CONFIG_FILE} has keys this version doesn't know, so they are \
                 ignored.</strong> A newer Pathwarden probably wrote them. They stay in the \
                 file.</p>"
            )
        };
        format!(
            r#"<div class="risk-warn" role="note">{}<div>{heading}{keys}{notices}</div></div>"#,
            icon("i-alert")
        )
    };
    let note_by = format!(
        "<strong>{}</strong>{}",
        esc(me.user.as_deref().unwrap_or("an unknown user")),
        me.computer
            .as_deref()
            .map(|c| format!(" on <strong>{}</strong>", esc(c)))
            .unwrap_or_default()
    );
    if c.suppress.is_empty() {
        rows.push_str(
            r#"<p class="muted empty-line">No accepted risks. Every finding is shown as open.</p>"#,
        );
    }
    let mut rule_options = String::new();
    for rule in sorted_rules() {
        let _ = write!(
            rule_options,
            r#"<option value="{id}">{id} · {title}</option>"#,
            id = rule.id,
            title = esc(rule.title)
        );
    }
    let finding_search = if has_findings {
        r##"<div class="picker" data-picker="fp" data-source="findings"><div class="pathfield card"><svg class="ic" aria-hidden="true"><use href="#i-search"/></svg><label class="sr-only" for="fp-q">Search the latest run's findings</label><input type="search" id="fp-q" placeholder="Search the latest run's findings by title, rule or ID" autocomplete="off" spellcheck="false" data-search></div><ul class="results card" role="listbox" hidden></ul></div>"##
    } else {
        r#"<p class="muted small">After an analysis you can search its findings here.</p>"#
    };
    let _ = write!(
        b,
        r#"<section class="card setting" id="risks" data-section="risks">
<header class="with-action"><div><h2 class="sub">Accepted risks{tag}</h2><p class="muted">Findings you keep, with a reason. Each counts as open again after its review date.{risks_tip}</p></div><button type="button" class="btn" id="add-risk">{i_plus} Accept a risk</button></header>
{risk_conflict}{warnings}<div class="risk-list">{rows}</div>
<form class="risk-note-form" id="note-form" hidden novalidate>
  <label for="note-text">Add a note</label>
  <textarea class="input" id="note-text" rows="2" maxlength="2000" placeholder="e.g. Checked with the CAB: still needed until the new jump host is in."></textarea>
  <p class="hint">Kept with this accepted risk, oldest first, with your name and this computer: {note_by}. A note doesn't change the reason or the review date.</p>
  <div class="card-actions"><button type="submit" class="btn primary">Add note</button><button type="button" class="btn" id="note-cancel">Cancel</button><span class="save-status muted small" aria-live="polite"></span></div>
</form>
<form class="risk-form" id="risk-form" hidden novalidate>
  <h3 class="form-title" id="risk-form-title">Accept a risk</h3>
  <fieldset class="seg"><legend class="sr-only">What to accept</legend>
    <label><input type="radio" name="target" value="fingerprint" checked><span>One finding</span></label>
    <label><input type="radio" name="target" value="rule"><span>Every finding of a rule</span></label>
  </fieldset>
  <div class="field" data-when="fingerprint">{finding_search}
    <label for="risk-fp">Finding ID</label><input class="input mono" id="risk-fp" placeholder="e.g. PW-004-13b0863341b2e306" autocomplete="off" spellcheck="false">
    <p class="hint">In a report, open a finding: its ID is listed under <strong>Finding ID</strong>. It stays the same from run to run while the problem exists.</p></div>
  <div class="field" data-when="rule" hidden><label for="risk-rule">Rule</label><select class="input" id="risk-rule">{rule_options}</select></div>
  <div class="field"><label for="risk-reason">Reason <span class="req">required</span></label><textarea class="input" id="risk-reason" rows="2" maxlength="2000" placeholder="e.g. Break-glass account, reviewed quarterly (CHG0012345)"></textarea><p class="hint">Why it is accepted and who decided. It is shown with the finding in every report.</p><p class="hint risk-bidi" id="risk-reason-bidi" hidden></p></div>
  <div class="field narrow"><label for="risk-expires">Review by <span class="muted">(optional)</span></label><input class="input" type="date" id="risk-expires"><p class="hint">After this day (UTC) the finding counts as open again.</p></div>
  <div class="card-actions"><button type="submit" class="btn primary"><svg class="ic" aria-hidden="true"><use href='#i-check'/></svg> Save accepted risk</button><button type="button" class="btn" id="risk-cancel">Cancel</button><span class="save-status muted small" aria-live="polite"></span></div>
</form>
</section>
"#,
        i_plus = icon("i-plus"),
        tag = tag("suppress"),
        risks_tip = pages::tip("tip-risks", "Accepted risks", RISKS_TIP),
        risk_conflict = conflict("suppress").unwrap_or_else(|| {
            let r = reader("suppress");
            let list = clash_list("suppress", &[]);
            if r.is_empty() {
                list
            } else {
                format!(r#"{list}<div class="card-actions">{r}<span class="save-status muted small" aria-live="polite"></span></div>"#)
            }
        }),
    );
    // This computer's evidence signing key, and checking a pack.
    b.push_str(&crate::evidence_ui::settings_sections(&st.workspace));
    // This computer's logs and crash reports.
    b.push_str(&crate::logs_ui::card(st));
    // Shared sections without a section of their own here: the choice for
    // one changed on both sides, or a reader's way back.
    for (key, title) in [
        ("management_planes", "Management planes"),
        ("mapping", "Mapping packs"),
    ] {
        let body = conflict(key).or_else(|| {
            let r = reader(key);
            let list = clash_list(key, &[]);
            (!r.is_empty() || !list.is_empty()).then(|| {
                if r.is_empty() {
                    list
                } else {
                    format!(r#"{list}<div class="card-actions">{r}<span class="save-status muted small" aria-live="polite"></span></div>"#)
                }
            })
        });
        if let Some(body) = body {
            let _ = write!(
                b,
                r#"<section class="card setting" id="sync-{key}"><header><h2 class="sub">{title}{tag}</h2></header>{body}</section>"#,
                tag = tag(key),
            );
        }
    }
    if let Some(v) = sync {
        b.push_str(&crate::sync_ui::pulled_note(v));
    }
    b.push_str(&after_save(st));
    b.push_str(r#"<script src="/static/config.js" defer></script>"#);
    pages::shell(ctx, Some(Nav::Settings), "Settings", "config", &b)
}

/// A time of an accepted risk as the page shows it: its local day ("Oct
/// 22, 2026"); one that isn't RFC 3339 as written.
fn risk_date(at: &str) -> String {
    match pathwarden_core::time::parse_rfc3339(at) {
        Some(t) => format!(
            r#"<time datetime="{}">{}</time>"#,
            pathwarden_core::time::format_rfc3339(t),
            pathwarden_core::time::format_local_date(t)
        ),
        None => esc(at),
    }
}

/// "by <b>NORTH\ned</b> on <b>WS02</b>, Oct 22, 2026": who, where and when,
/// with the parts that are known ("an unknown user" when only the computer
/// is). `None` when nothing is.
fn risk_stamp(by: &Option<String>, on: &Option<String>, at: &Option<String>) -> Option<String> {
    let mut out = String::new();
    match (by, on) {
        (Some(b), _) => {
            let _ = write!(out, "by <b>{}</b>", esc(b));
        }
        (None, Some(_)) => out.push_str("by an unknown user"),
        (None, None) => {}
    }
    if let Some(o) = on {
        let _ = write!(out, " on <b>{}</b>", esc(o));
    }
    if let Some(a) = at {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(&risk_date(a));
    }
    (!out.is_empty()).then_some(out)
}

/// Who accepted a risk and its last change, under its reason.
fn risk_who(s: &pathwarden_core::config::Suppression) -> String {
    match risk_stamp(&s.accepted_by, &s.accepted_on, &s.accepted_at) {
        None => r#"<p class="risk-who unknown">Who accepted it and when wasn't recorded: it was added by hand or by Pathwarden 0.1.6 or earlier.</p>"#.to_string(),
        Some(w) => {
            let changed = risk_stamp(&s.changed_by, &s.changed_on, &s.changed_at)
                .map(|c| format!(r#"<span class="sep">·</span>changed {c}"#))
                .unwrap_or_default();
            format!(r#"<p class="risk-who">Accepted {w}{changed}</p>"#)
        }
    }
}

/// A risk's notes, folded under it ("2 notes"); an empty, hidden fold when
/// there are none, for the first note added on the page.
fn risk_notes(s: &pathwarden_core::config::Suppression) -> String {
    let mut items = String::new();
    for n in &s.notes {
        let meta: Vec<String> = [
            n.at.as_deref().map(risk_date),
            risk_stamp(&n.by, &n.on, &None).map(|w| w.trim_start_matches("by ").to_string()),
        ]
        .into_iter()
        .flatten()
        .collect();
        let _ = write!(
            items,
            r#"<li>{}<span class="note-text">{}</span></li>"#,
            if meta.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="meta">{}</span>"#, meta.join(" · "))
            },
            esc(&n.text)
        );
    }
    let n = s.notes.len();
    format!(
        r#"<details class="risk-notes"{hidden}><summary>{count}</summary><ol>{items}</ol></details>"#,
        hidden = if n == 0 { " hidden" } else { "" },
        count = if n == 1 {
            "1 note".to_string()
        } else {
            format!("{} notes", pages::num(n))
        },
    )
}

/// Whether this environment's settings are shared with other machines
/// through the history repository ([`pathwarden_core::settings_sync`]).
fn shared_through_repository(c: &Config) -> bool {
    pathwarden_core::settings_sync::inactive(&c.state).is_none()
}

/// "From the repository": a risk accepted on another computer than this
/// one, in settings shared through the repository.
fn from_repository(
    s: &pathwarden_core::config::Suppression,
    here: &Option<String>,
    shared: bool,
) -> bool {
    shared
        && match (&s.accepted_on, here) {
            (Some(on), Some(here)) => !on.trim().eq_ignore_ascii_case(here.trim()),
            _ => false,
        }
}

/// The rules as the page loads them, to tell whether the file changed
/// before a save: thresholds, how paths are rated, and the checks off (in
/// upper case, sorted).
fn rules_view(r: &pathwarden_core::config::RulesConfig) -> serde_json::Value {
    let mut disabled: Vec<String> = r
        .disabled
        .iter()
        .map(|d| d.trim().to_ascii_uppercase())
        .collect();
    disabled.sort();
    disabled.dedup();
    let mut v = serde_json::json!({
        "stale_days": r.stale_days,
        "password_age_days": r.password_age_days,
        "krbtgt_age_days": r.krbtgt_age_days,
        "severity": if r.severity == pathwarden_core::config::SeverityMode::Exposure { "exposure" } else { "static" },
        "disabled": disabled,
    });
    // The Seamless SSO key age, when it isn't the default (so a page
    // loaded before it existed still matches).
    if r.sso_key_age_days != pathwarden_core::config::RulesConfig::default().sso_key_age_days {
        v["sso_key_age_days"] = serde_json::json!(r.sso_key_age_days);
    }
    // The severities set, by rule (left out when none is).
    let set = r.set_severities();
    if !set.is_empty() {
        v["severities"] = serde_json::json!(set
            .into_iter()
            .map(|(k, s)| (k, s.severity.as_str()))
            .collect::<std::collections::BTreeMap<_, _>>());
    }
    v
}

/// The Tier Zero settings folders card: its line, its ⓘ, and the
/// field's placeholder.
pub const SETTINGS_FOLDERS_INTRO: &str = "Shared folders where your servers save their Tier Zero settings files. Pathwarden reads them on every analysis, scheduled run and retest.";
pub const SETTINGS_FOLDERS_TIP: &str = "Pathwarden reads only the settings files in each folder, not other files or subfolders. If a folder can't be opened, the run goes ahead with a warning. Runs record file names, not folder paths. The folders are saved with your other settings, so teammates who share them read the same files.";
/// The mark on a folder from the repository no one here reviewed.
pub const FOLDER_WAITING: &str = "From the repository. Not used here yet.";
/// The same for a folder written into the file by other means (a hand
/// edit, a copied file).
pub const FOLDER_WAITING_HERE: &str = "Not used here yet.";
const SETTINGS_FOLDERS_PLACEHOLDER: &str =
    r"Folder or share path, for example \\fs01\pathwarden-t0";

/// The Accepted risks card's ⓘ.
const RISKS_TIP: &str = "They stay in the report, marked with your reason. Each one keeps who \
accepted it, on which computer and when, and the notes added since. The names are kept in this \
environment's settings, and in the run history when settings are shared.";

/// The Rules card's "Severity ⓘ".
const SEVERITY_TIP: &str = "A set severity rates every finding of the rule, whatever its \
exposure or the rule's own rating. It applies from the next analysis; earlier runs keep theirs. \
Zone status follows it, except that a broad group (one holding nearly every account) with a path \
to a zone keeps the zone Critical. Reports show it as set by your team, with the default beside \
it. Finding IDs and accepted risks stay the same.";

/// A rule's severity drop-down: its default first ("Default (exposure)"),
/// then the levels. Its default for each way attack paths are rated is on
/// it, for the page to switch with the choice.
fn severity_select(row: &pathwarden_core::config::RuleRow) -> String {
    let set = row.set.as_ref().map(|s| s.severity);
    let mut options = format!(
        r#"<option value=""{}>{}</option>"#,
        if set.is_none() { " selected" } else { "" },
        esc(&row.default_words())
    );
    for s in findings::Severity::SETTABLE {
        let _ = write!(
            options,
            r#"<option value="{}"{}>{}</option>"#,
            s.as_str(),
            if set == Some(s) { " selected" } else { "" },
            s.label()
        );
    }
    format!(
        r#"<span class="sev-wrap"><select class="input sev-pick{cls}" name="sev" data-rule="{id}" data-saved="{saved}" data-default-exposure="{dx}" data-default-static="{ds}" aria-label="Severity of {id}">{options}</select></span>"#,
        cls = set
            .map(|s| format!(" is-set sev-{}", s.as_str()))
            .unwrap_or_default(),
        id = row.id,
        saved = set.map(|s| s.as_str()).unwrap_or(""),
        dx = esc(&format!(
            "Default ({})",
            findings::default_label(row.id, true)
        )),
        ds = esc(&format!(
            "Default ({})",
            findings::default_label(row.id, false)
        )),
    )
}

/// "Set by NORTH\ned on Oct 24, 2026." under a rule whose severity is set,
/// with what was recorded (text).
fn severity_who_text(s: &findings::SetSeverity) -> String {
    let day = |a: &String| pathwarden_core::time::day_of(a);
    match (&s.by, &s.at) {
        (Some(b), Some(a)) => format!("Set by {b} on {}.", day(a)),
        (Some(b), None) => format!("Set by {b}."),
        (None, Some(a)) => format!("Set on {}.", day(a)),
        (None, None) => "Set in the settings file.".to_string(),
    }
}

fn severity_who(s: &findings::SetSeverity) -> String {
    format!(
        r#"<span class="rule-who">{}</span>"#,
        esc(&severity_who_text(s))
    )
}

/// The severities set, with who set them, for the page to show after a
/// save.
fn severities_who(r: &pathwarden_core::config::RulesConfig) -> serde_json::Value {
    serde_json::json!(r
        .set_severities()
        .iter()
        .map(|(k, s)| (k.clone(), severity_who_text(s)))
        .collect::<std::collections::BTreeMap<_, _>>())
}

/// Every rule, by ID.
fn sorted_rules() -> Vec<&'static findings::RuleInfo> {
    let mut r: Vec<_> = findings::rules().iter().collect();
    r.sort_by_key(|r| r.id);
    r
}

/// [`chip`] for an addition made here, not in the repository yet.
pub(crate) fn chip_here(b: &mut String, value: &str) {
    let _ = write!(
        b,
        r#"<li class="chip-item here" data-value="{raw}"><span class="chip-text">{v}</span><span class="here-mark">here</span><button type="button" class="fl-remove" data-remove aria-label="Remove {v}">{x}</button></li>"#,
        raw = pages::attr(value),
        v = esc(value),
        x = icon("i-x"),
    );
}

/// [`chip`] with `mark` after its text (an entry the last merge brought:
/// "shared · who, date"); a plain chip without one.
pub(crate) fn chip_marked(b: &mut String, value: &str, mark: &str) {
    if mark.is_empty() {
        return chip(b, value);
    }
    let _ = write!(
        b,
        r#"<li class="chip-item" data-value="{raw}"><span class="chip-text">{v}</span>{mark}<button type="button" class="fl-remove" data-remove aria-label="Remove {v}">{x}</button></li>"#,
        raw = pages::attr(value),
        v = esc(value),
        x = icon("i-x"),
    );
}

pub(crate) fn chip(b: &mut String, value: &str) {
    let _ = write!(
        b,
        r#"<li class="chip-item" data-value="{raw}"><span class="chip-text">{v}</span><button type="button" class="fl-remove" data-remove aria-label="Remove {v}">{x}</button></li>"#,
        raw = pages::attr(value),
        v = esc(value),
        x = icon("i-x"),
    );
}

// ------------------------------------------------------------------- API

#[derive(Deserialize)]
struct TierZeroBody {
    items: Vec<String>,
    /// The list as the page loaded it.
    #[serde(default)]
    loaded: Option<Vec<String>>,
}

/// Why a save of a section a pull changed since its page was loaded is
/// refused (409): "Rules changed in the shared settings since you opened this
/// page. Reload to see the changes."
pub fn stale_words(section: &str) -> String {
    format!(
        "{} changed in the shared settings since you opened this page. Reload to see the changes.",
        crate::last_pull::short_name(section)
    )
}

/// Why a save from a page of another environment is refused (409).
pub const ENV_SWITCHED: &str = "You switched environment in another tab. Reload this page.";

/// The environment a page was loaded in (`<body data-env>`), sent with its
/// saves and its news check.
pub const ENV_HEADER: &str = "x-pathwarden-env";

/// The pull counter a page was loaded at (`<body data-pulled>`), sent with
/// its saves.
pub const PULLED_HEADER: &str = "x-pathwarden-pulled";

/// A save of shared sections `keys` from a page that is out of date,
/// refused with 409: the page is of another environment than the current
/// one (switched in another tab), or a pull since the page was loaded
/// changed one of those sections ([`crate::auto_pull`]). `None` to go on;
/// a request without the page's stamps (not from a page) is not checked.
pub(crate) fn stale_page(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    keys: &[&str],
) -> Option<Response> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let env = st.env_id();
    if get(ENV_HEADER).is_some_and(|e| e != env) {
        return Some(json_error(StatusCode::CONFLICT, ENV_SWITCHED));
    }
    let pulled = get(PULLED_HEADER).and_then(|v| v.trim().parse::<u64>().ok())?;
    let since = st.auto_pull.since(&env, pulled);
    keys.iter()
        .find(|k| since.sections.iter().any(|s| s == *k))
        .map(|k| json_error(StatusCode::CONFLICT, stale_words(k)))
}

/// The same list, any case and spacing.
fn same_list(a: &[String], b: &[String]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.trim().eq_ignore_ascii_case(y.trim()))
}

/// `POST /api/settings/settings-folders`: the Tier Zero settings folders,
/// as the page lists them, refused when the file changed since the
/// page loaded it.
async fn save_settings_folders(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<TierZeroBody>,
) -> Response {
    if let Some(r) = stale_page(&st, &headers, &["settings_folders"]) {
        return r;
    }
    let Some(loaded) = body.loaded else {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    };
    use pathwarden_core::folder_origin::key;
    // Added on this page, on this computer: used here at once.
    let added: Vec<String> = body
        .items
        .iter()
        .filter(|i| !loaded.iter().any(|l| key(l) == key(i)))
        .cloned()
        .collect();
    let ws = st.ws();
    let r = edit_answering(&ws, move |d| {
        if !same_list(&current(d)?.settings_folders, &loaded) {
            return Err(OUT_OF_DATE.into());
        }
        d.set_settings_folders(&body.items)?;
        Ok(serde_json::json!({ "loaded": current(d)?.settings_folders }))
    })
    .await;
    if r.status().is_success() && !added.is_empty() {
        if let Err(e) = pathwarden_core::folder_origin::mark(&ws.config_path(), &added, true) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
    }
    r
}

#[derive(Deserialize)]
struct UseFolderBody {
    folder: String,
}

/// `POST /api/settings/settings-folders/use`: a folder the run history
/// brought, used on this computer from now on (the card's Use).
async fn use_settings_folder(
    State(st): State<Shared>,
    Json(body): Json<UseFolderBody>,
) -> Response {
    use pathwarden_core::folder_origin::key;
    let ws = st.ws();
    let config = load_ws(&ws).config;
    if !config
        .settings_folders
        .iter()
        .any(|f| key(f) == key(&body.folder))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "That folder isn't in the settings.",
        );
    }
    match pathwarden_core::folder_origin::mark(&ws.config_path(), &[body.folder], true) {
        Ok(()) => Json(serde_json::json!({ "used": true })).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn save_tier_zero(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<TierZeroBody>,
) -> Response {
    if let Some(r) = stale_page(&st, &headers, &["tier_zero"]) {
        return r;
    }
    let Some(loaded) = body.loaded else {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    };
    edit_answering(&st.ws(), move |d| {
        // Changed since the page was loaded (the command line, another
        // page): saving the page's list would undo that.
        if !same_list(&current(d)?.tier_zero, &loaded) {
            return Err(OUT_OF_DATE.into());
        }
        d.set_tier_zero(&body.items)?;
        // As the file now holds it (trimmed, without duplicates): what the
        // page compares its next save with.
        Ok(serde_json::json!({ "loaded": current(d)?.tier_zero }))
    })
    .await
}

#[derive(Deserialize)]
struct RulesBody {
    #[serde(flatten)]
    rules: RulesEdit,
    /// The rules as the page loaded them ([`rules_view`]).
    #[serde(default)]
    loaded: Option<serde_json::Value>,
}

async fn save_rules(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RulesBody>,
) -> Response {
    if let Some(r) = stale_page(&st, &headers, &["rules"]) {
        return r;
    }
    let Some(loaded) = body.loaded else {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    };
    edit_answering(&st.ws(), move |d| {
        if rules_view(&current(d)?.rules) != loaded {
            return Err(OUT_OF_DATE.into());
        }
        d.set_rules(&body.rules, &Stamp::now())?;
        let now = current(d)?.rules;
        Ok(serde_json::json!({ "loaded": rules_view(&now), "set": severities_who(&now) }))
    })
    .await
}

#[derive(Deserialize)]
struct SuppressBody {
    index: Option<usize>,
    /// The entry's reason as the page showed it (for edits).
    expect: Option<String>,
    /// Its finding ID or rule as the page showed it (for edits).
    #[serde(default)]
    expect_target: Option<String>,
    risk: SuppressionEdit,
    /// Accepting a risk from a run's page: the run (its environment's
    /// config is changed).
    #[serde(default)]
    run: Option<String>,
}

async fn save_suppression(
    State(st): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SuppressBody>,
) -> Response {
    // From Settings: the list the page shows. (A run's page saves into
    // that run's environment, whichever is current.)
    if body.run.is_none() {
        if let Some(r) = stale_page(&st, &headers, &["suppress"]) {
            return r;
        }
    }
    // From a run's page: that run's environment, whichever is current, so
    // a risk accepted for one environment's finding never applies to
    // another's runs.
    let ws = match body.run.as_deref() {
        Some(id) => match st.workspace.summary(id) {
            Some(r) => st.workspace.for_run(&r),
            None => return json_error(StatusCode::NOT_FOUND, "That run no longer exists."),
        },
        None => st.ws(),
    };
    if body.index.is_some() && body.expect_target.is_none() {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    }
    // Who accepted or changed it: the account the app runs as, on this
    // computer (what `pathwarden config risk` records too).
    let by = Stamp::now();
    edit_answering(&ws, move |d| {
        d.upsert_suppression(
            body.index,
            body.expect.as_deref(),
            body.expect_target.as_deref(),
            &body.risk,
            &by,
        )?;
        // The entry as saved, so the run page can offer Add a note at once.
        let c = current(d)?;
        let i = body.index.unwrap_or(c.suppress.len().saturating_sub(1));
        Ok(match c.suppress.get(i) {
            Some(s) => serde_json::json!({
                "index": i,
                "entry": crate::retest_ui::accepted_entry(i, s),
            }),
            None => serde_json::json!({}),
        })
    })
    .await
}

/// An edit of an accepted risk that doesn't say which finding or rule it
/// was made for comes from a page loaded before this version.
const OUT_OF_DATE: &str = "This page is out of date: reload it.";

#[derive(Deserialize)]
struct NoteBody {
    /// The entry's reason as the page showed it.
    expect: String,
    /// Its finding ID or rule as the page showed it.
    #[serde(default)]
    expect_target: Option<String>,
    text: String,
    /// From a run's page: the run (its environment's config is changed).
    #[serde(default)]
    run: Option<String>,
}

/// Adds a note to an accepted risk (`pathwarden config risk note`). Answers
/// with the note as saved (who, where, when), for the page to show.
async fn add_suppression_note(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    headers: axum::http::HeaderMap,
    Json(body): Json<NoteBody>,
) -> Response {
    if body.run.is_none() {
        if let Some(r) = stale_page(&st, &headers, &["suppress"]) {
            return r;
        }
    }
    if body.expect_target.is_none() {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    }
    let ws = match body.run.as_deref() {
        Some(id) => match st.workspace.summary(id) {
            Some(r) => st.workspace.for_run(&r),
            None => return json_error(StatusCode::NOT_FOUND, "That run no longer exists."),
        },
        None => st.ws(),
    };
    let by = Stamp::now();
    let note = serde_json::json!({
        "by": by.by,
        "on": by.on,
        "at": by.at,
        "text": body.text.trim(),
    });
    let path = ws.config_path();
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    let saved = tokio::task::spawn_blocking(move || {
        apply_for_page(path, &share, |d| {
            d.add_suppression_note(
                index,
                &body.expect,
                body.expect_target.as_deref(),
                &body.text,
                &by,
            )
        })
    })
    .await;
    match saved {
        Ok(Ok(((), pending))) => {
            let sharing = crate::sync_ui::share_later(pending);
            Json(serde_json::json!({ "saved": true, "note": note, "sharing": sharing }))
                .into_response()
        }
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "Saving failed."),
    }
}

#[derive(Deserialize)]
struct RemoveBody {
    expect: String,
    /// The finding ID or rule of an accepted risk as the page showed it.
    #[serde(default)]
    expect_target: Option<String>,
}

async fn delete_suppression(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RemoveBody>,
) -> Response {
    if let Some(r) = stale_page(&st, &headers, &["suppress"]) {
        return r;
    }
    if body.expect_target.is_none() {
        return json_error(StatusCode::BAD_REQUEST, OUT_OF_DATE);
    }
    edit(&st, move |d| {
        d.remove_suppression(index, &body.expect, body.expect_target.as_deref())
    })
    .await
}

/// The History storage form as the page sends it.
#[derive(Deserialize)]
pub(crate) struct StateBody {
    #[serde(flatten)]
    pub edit: StateEdit,
    /// Turning "Full runs and settings" on for a history that isn't
    /// encrypted: the user chose to keep it plain ("Don't encrypt").
    #[serde(default)]
    pub share_plain: bool,
}

/// Start a new run history, refused where one is already: before
/// a save that keeps full runs, or turns encryption on, for a repository or
/// folder other than the one in use, it is looked at; one that holds a
/// Pathwarden history is offered to connect to instead, and nothing is
/// saved or encrypted. (Only then: a plain save of a new place is what it
/// was, and never reaches the network before it is used.)
pub fn check_new_place(
    ws: &Workspace,
    s: &StateEdit,
    encrypting: bool,
) -> Result<(), NewPlaceRefused> {
    use pathwarden_core::config::StateBackend;
    use pathwarden_core::connect::Where;
    let full = s
        .keep
        .as_deref()
        .is_some_and(|k| k.trim().eq_ignore_ascii_case("full"));
    if !full && !encrypting {
        return Ok(());
    }
    let cur = ws.config().map(|c| c.state).unwrap_or_default();
    let git = s.backend.trim().eq_ignore_ascii_case("git");
    let branch = |b: &Option<String>| {
        b.as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .unwrap_or("main")
            .to_string()
    };
    let w = if git {
        let Some(url) = s.remote.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
            return Ok(());
        };
        // The remote as the page shows it (credentials hidden) is the saved one.
        let same = cur.backend == StateBackend::Git
            && cur.remote.as_deref().is_some_and(|r| {
                pathwarden_core::store::same_remote(r, url)
                    || pathwarden_core::config::redact_urls(r) == url
            })
            && branch(&cur.branch) == branch(&s.branch);
        if same {
            return Ok(());
        }
        Where::Git {
            url: url.to_string(),
            branch: Some(branch(&s.branch)),
        }
    } else {
        let dir = state_folder(&ws.env_dir(), s);
        let cur_dir = pathwarden_core::settings_sync::state_dir(&cur, &ws.env_dir());
        if cur.backend != StateBackend::Git && dir == cur_dir {
            return Ok(());
        }
        Where::Folder(dir)
    };
    crate::connect::check_new(ws.root(), &w).map_err(|(lead, rest)| {
        // Connect to it: this environment, when it has no runs of its own.
        // The place goes by a token, never in the link itself.
        let mut meta = crate::connect::Meta {
            env: (crate::connect::own_runs(ws, None) == 0).then(|| ws.env_id().to_string()),
            ..crate::connect::Meta::default()
        };
        match &w {
            Where::Git { url, branch } => {
                meta.kind = "git".into();
                meta.url = Some(url.clone());
                meta.branch = branch.clone();
            }
            Where::Folder(d) => {
                meta.kind = "folder".into();
                meta.folder = Some(d.display().to_string());
            }
        }
        let href = match crate::connect::keep_place(ws.root(), &meta) {
            Some(t) => format!("{}?from={t}", crate::connect_ui::PATH),
            None => crate::connect_ui::PATH.to_string(),
        };
        NewPlaceRefused {
            found: lead.contains("already holds a Pathwarden history"),
            lead,
            rest,
            connect: href,
        }
    })
}

/// [`check_new_place`]'s refusal: the sentence in two parts, and where
/// Connect to it goes when a history is there (`found`).
#[derive(Debug, Clone)]
pub struct NewPlaceRefused {
    pub lead: String,
    pub rest: String,
    pub found: bool,
    pub connect: String,
}

impl NewPlaceRefused {
    pub fn sentence(&self) -> String {
        if self.rest.is_empty() {
            self.lead.clone()
        } else {
            format!("{} {}", self.lead, self.rest)
        }
    }

    /// The JSON error the pages show: with Connect to it when a history is
    /// there.
    pub fn response(&self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": self.sentence(),
                "lead": self.lead,
                "rest": self.rest,
                "connect": self.found.then_some(&self.connect),
            })),
        )
            .into_response()
    }
}

/// The message for a page session that tries to change where the run
/// history is kept, or to start sharing full runs without encryption.
pub const HISTORY_LOCKED: &str = "Moving the run history, or sharing full runs and settings without encryption, is turned off in this app. You can still sync it and encrypt it.";

/// What a page session may save to `[state]` with
/// `--lock-destinations` ([`HISTORY_LOCKED`]): not another repository,
/// branch or folder, since every run would then go there (full runs with
/// their reports too), and a share is signed in to; nor full runs and
/// settings kept in a history that isn't encrypted. Everything else on the
/// History storage page stays editable.
pub(crate) fn check_history_lock(
    allow: bool,
    d: &ConfigDoc,
    env_dir: &std::path::Path,
    s: &StateEdit,
    share_plain: bool,
) -> Result<(), String> {
    use pathwarden_core::config::Keep;
    if allow {
        return Ok(());
    }
    if d.state_moves(s)? {
        return Err(HISTORY_LOCKED.into());
    }
    let full = s
        .keep
        .as_deref()
        .is_some_and(|k| k.trim().eq_ignore_ascii_case("full"));
    let was_full = d.validate().is_ok_and(|c| c.state.keep() == Keep::Full);
    if share_plain
        && full
        && !was_full
        && !pathwarden_core::crypt::is_encrypted(&state_folder(env_dir, s))
    {
        return Err(HISTORY_LOCKED.into());
    }
    Ok(())
}

/// [`check_history_lock`] against `pathwarden.toml` as it is now, before a
/// save looks at the new place (which may reach the network): the refusal,
/// as the page shows it.
pub(crate) async fn history_lock_refusal(
    st: &AppState,
    s: &StateEdit,
    share_plain: bool,
) -> Option<Response> {
    if st.allow_destinations {
        return None;
    }
    let ws = st.ws();
    let s = s.clone();
    let checked = tokio::task::spawn_blocking(move || {
        let d = ConfigDoc::load(&ws.config_path())?;
        check_history_lock(false, &d, &ws.env_dir(), &s, share_plain)
    })
    .await;
    match checked {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(json_error(StatusCode::BAD_REQUEST, e)),
        Err(_) => Some(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Saving failed.",
        )),
    }
}

async fn save_state(State(st): State<Shared>, Json(body): Json<StateBody>) -> Response {
    let allow = st.allow_destinations;
    if let Some(refused) = history_lock_refusal(&st, &body.edit, body.share_plain).await {
        return refused;
    }
    {
        let ws = st.ws();
        let edit = body.edit.clone();
        let checked = tokio::task::spawn_blocking(move || check_new_place(&ws, &edit, false)).await;
        if let Ok(Err(r)) = checked {
            return r.response();
        }
    }
    let env_dir = st.ws().env_dir();
    let r = edit(&st, move |d| {
        check_history_lock(allow, d, &env_dir, &body.edit, body.share_plain)?;
        set_state(d, &env_dir, &body.edit, body.share_plain).map_err(|e| {
            if e == CHOOSE_ENCRYPTION {
                CHOOSE_ENCRYPTION_PAGE.to_string()
            } else {
                e
            }
        })
    })
    .await;
    // Pull every may have changed: the next pull is a whole interval on.
    if r.status().is_success() {
        st.auto_pull.timer.reset();
    }
    r
}

/// What the page's "Full runs and settings" card and `pathwarden history
/// storage set --full-runs-kept N` say once it is saved.
pub fn full_runs_kept_words(n: usize) -> String {
    format!(
        "The history keeps the latest {}; older ones keep their numbers.",
        pathwarden_core::text::count(n, "full run", "full runs")
    )
}

/// Saves how many full runs the history keeps (`[state] full_runs_kept`)
/// in `ws`'s `pathwarden.toml`, as the History storage page does.
pub fn save_full_runs_kept(ws: &Workspace, n: usize) -> Result<(), String> {
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    apply_sharing(ws.config_path(), &share, |d| d.set_full_runs_kept(n)).map(|_| ())
}

/// What `pathwarden history storage set --full-run-file-mb N` says once it
/// is saved, for the history at `remote` (the GitHub hold, when it holds).
pub fn full_run_file_mb_words(mb: u64, remote: Option<&str>) -> String {
    let probe = pathwarden_core::config::StateConfig {
        full_run_file_mb: Some(mb),
        ..Default::default()
    };
    let applies = probe.full_run_file_mb_for(remote);
    let mut s = format!("A full run keeps files up to {applies} MB.");
    if applies < probe.full_run_file_mb() {
        s.push(' ');
        s.push_str(crate::shared_runs::GITHUB_HOLD_WORDS);
    }
    s
}

/// Saves the largest file a full run keeps (`[state] full_run_file_mb`)
/// in `ws`'s `pathwarden.toml`, as the History storage page does.
pub fn save_full_run_file_mb(ws: &Workspace, mb: u64) -> Result<(), String> {
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    apply_sharing(ws.config_path(), &share, |d| d.set_full_run_file_mb(mb)).map(|_| ())
}

#[derive(Deserialize)]
struct FullRunsBody {
    kept: usize,
    /// The largest file a full run keeps, in MB (the card's second field).
    #[serde(default)]
    file_mb: Option<u64>,
}

async fn save_full_runs(State(st): State<Shared>, Json(body): Json<FullRunsBody>) -> Response {
    edit(&st, move |d| {
        d.set_full_runs_kept(body.kept)?;
        match body.file_mb {
            Some(mb) => d.set_full_run_file_mb(mb),
            None => Ok(()),
        }
    })
    .await
}

/// Saves the History storage form: [`ConfigDoc::set_state`] in `ws`'s
/// `pathwarden.toml`, as the page does (`pathwarden history storage set`).
pub fn save_state_in(ws: &Workspace, s: &StateEdit) -> Result<(), String> {
    update_state_in(ws, false, |_| Ok(s.clone())).map(|_| ())
}

/// [`save_state_in`] with the form made from `[state]` as it is when the
/// save holds the lock (`pathwarden history storage set`, which changes only
/// what it is given): a change saved meanwhile isn't undone. `share_plain`:
/// as [`StateBody::share_plain`].
///
/// Returns a note when the save started sharing settings (`keep = "full"`
/// with a git history), as [`apply_sharing`].
pub fn update_state_in(
    ws: &Workspace,
    share_plain: bool,
    make: impl FnOnce(&pathwarden_core::config::StateConfig) -> Result<StateEdit, String>,
) -> Result<Option<String>, String> {
    let env_dir = ws.env_dir();
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    apply_sharing(ws.config_path(), &share, |d| {
        let current = d.validate()?.state;
        let s = make(&current)?;
        set_state(d, &env_dir, &s, share_plain)
    })
    .map(|((), shared)| shared)
}

/// [`update_state_in`] for a save that also turns encryption on, in the
/// order that never puts the shared settings in the repository in plain
/// text: `[state]` is saved first with its keep choice as it was and
/// nothing shared; then `encrypt` encrypts the history as now saved; only
/// then is the keep choice saved and the settings shared, encrypted. When
/// `encrypt` fails, the keep choice isn't saved and nothing is shared.
/// (`pathwarden history storage set --keep full --encrypt`, and the
/// passphrase panel's "Set passphrase and save".)
pub fn update_state_encrypting<E>(
    ws: &Workspace,
    make: impl FnOnce(&pathwarden_core::config::StateConfig) -> Result<StateEdit, String>,
    encrypt: impl FnOnce() -> Result<E, String>,
) -> Result<(E, Option<pathwarden_core::settings_sync::Note>), String> {
    use pathwarden_core::config::StateBackend;
    let env_dir = ws.env_dir();
    let share = Share {
        base: None,
        env_name: Some(ws.env_name()),
    };
    let path = ws.config_path();
    // Not shared: the history isn't encrypted yet.
    let (keep, _not_shared) = apply_for_page(path.clone(), &share, |d| {
        let current = d.validate()?.state;
        let mut s = make(&current)?;
        let keep = s.keep.take();
        set_state(d, &env_dir, &s, false)?;
        Ok(keep)
    })?;
    let out = encrypt()?;
    let ((), pending) = apply_for_page(path, &share, |d| {
        let Some(k) = keep else {
            return Ok(());
        };
        let cur = d.validate()?.state;
        let s = StateEdit {
            backend: if cur.backend == StateBackend::Git {
                "git"
            } else {
                "local"
            }
            .into(),
            path: cur.path.clone(),
            remote: cur.remote.clone(),
            branch: cur.branch.clone(),
            include_names: cur.include_names,
            push: None,
            keep: Some(k),
            refresh: None,
        };
        set_state(d, &env_dir, &s, false)
    })?;
    // Everything shared now goes encrypted, the first share included.
    Ok((out, pending.from_scratch().run()))
}

/// Why "Full runs and settings" isn't turned on for a history that isn't
/// encrypted, until the user chose.
pub const CHOOSE_ENCRYPTION: &str = "Choose whether to encrypt the history first: with \"Full \
runs and settings\", the shared settings and accepted risks, with who accepted them, go into \
it. Give --encrypt, or --no-encrypt to keep it in plain text on purpose. (If another computer \
encrypted it, run `pathwarden history storage sync` first.)";

/// [`CHOOSE_ENCRYPTION`] on the page.
pub const CHOOSE_ENCRYPTION_PAGE: &str = "Choose whether to encrypt the history first: with \
\"Full runs and settings\", the shared settings and accepted risks, with who accepted them, go \
into it. Set a passphrase, or choose Don't encrypt. (If another computer encrypted it, Sync now on \
History storage first.)";

/// The folder `s` keeps the history in.
fn state_folder(env_dir: &std::path::Path, s: &StateEdit) -> PathBuf {
    let folder = s
        .path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(crate::history_ui::DEFAULT_FOLDER);
    let folder = std::path::Path::new(folder);
    if folder.is_absolute() {
        folder.to_path_buf()
    } else {
        env_dir.join(folder)
    }
}

/// [`ConfigDoc::set_state`], refused when a git history would be checked out
/// in a folder that already holds something else, such as the folder history
/// it replaces: every pull would fail there. `env_dir` is where a relative
/// folder is taken from. Turning "Full runs and settings" on for a history
/// that isn't encrypted needs `share_plain`, the user's choice to keep it
/// plain ([`CHOOSE_ENCRYPTION`]).
fn set_state(
    d: &mut ConfigDoc,
    env_dir: &std::path::Path,
    s: &StateEdit,
    share_plain: bool,
) -> Result<(), String> {
    use pathwarden_core::config::Keep;
    let full = s
        .keep
        .as_deref()
        .is_some_and(|k| k.trim().eq_ignore_ascii_case("full"));
    let was_full = d.validate().is_ok_and(|c| c.state.keep() == Keep::Full);
    if full
        && !was_full
        && !share_plain
        && !pathwarden_core::crypt::is_encrypted(&state_folder(env_dir, s))
    {
        return Err(CHOOSE_ENCRYPTION.into());
    }
    d.set_state(s)?;
    if !s.backend.trim().eq_ignore_ascii_case("git") {
        return Ok(());
    }
    let dir = state_folder(env_dir, s);
    let taken =
        !dir.join(".git").exists() && std::fs::read_dir(&dir).is_ok_and(|mut r| r.next().is_some());
    if taken {
        return Err(format!(
            "{} already holds files and is not a git working copy (it may be the folder history this replaces), so the repository can't be checked out there. Choose an empty or new folder for the checkout.",
            dir.display()
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
}

/// The latest run's findings matching `q` (title, rule, domain or ID).
async fn search_findings(State(st): State<Shared>, Query(q): Query<SearchQuery>) -> Response {
    let query: String = q.q.chars().take(200).collect::<String>().to_lowercase();
    let ws = st.ws();
    let found = tokio::task::spawn_blocking(move || {
        let (_, dir) = run_data::latest_with(&ws, run_data::EVENT_FILE)?;
        let all = run_data::findings(&dir)?;
        let words: Vec<&str> = query.split_whitespace().collect();
        Some(
            all.iter()
                .filter(|f| {
                    let hay = format!(
                        "{} {} {} {}",
                        f.rule,
                        f.title,
                        f.domain.as_deref().unwrap_or_default(),
                        f.fingerprint
                    )
                    .to_lowercase();
                    words.iter().all(|w| hay.contains(w))
                })
                .take(run_data::SEARCH_LIMIT)
                .cloned()
                .collect::<Vec<_>>(),
        )
    })
    .await
    .ok()
    .flatten();
    match found {
        Some(list) => Json(serde_json::json!({ "results": list })).into_response(),
        None => json_error(
            StatusCode::NOT_FOUND,
            "No analysis to search yet. Analyze a collection or try the demo first.",
        ),
    }
}
