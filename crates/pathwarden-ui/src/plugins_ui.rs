//! Output plugins: the `[[output]]` list, ServiceNow and Jira forms, a form for any
//! other plugin or script, and "Test with the latest run", which runs the
//! plugin in dry-run mode on the latest run's event document.
//!
//! Secrets never pass through here. Plugins read them from environment
//! variables whose *names* the config holds; the pages only show whether a
//! named variable is set in this process, never its value.

use std::fmt::Write;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use pathwarden_core::config::OutputConfig;
use pathwarden_core::plugin_form::{
    self, describe, env_is_set, env_names, is_jira, is_servicenow, PluginForm, JIRA, JIRA_PAT,
    JIRA_TOKEN, JIRA_USER, SERVICENOW, SN_PASSWORD, SN_TOKEN, SN_USER,
};
use pathwarden_core::plugins;
use serde::Deserialize;
use serde_json::Value;

use crate::pages::{self, esc, icon, Nav};
use crate::run_data;
use crate::server::AppState;
use crate::settings::{self, json_error};

type Shared = Arc<AppState>;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/plugins/new", get(new_page))
        .route("/plugins/{index}/edit", get(edit_page))
        .route("/api/plugins", post(save))
        .route("/api/plugins/{index}", delete(remove))
        .route("/api/plugins/{index}/test", post(test))
        .route("/api/env", get(env_status))
}

fn env_chips(names: &[String]) -> String {
    let mut s = String::new();
    for n in names {
        let set = env_is_set(n);
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

/// The program the output runs, and whether it is there.
fn program_line(o: &OutputConfig) -> String {
    let (program, ok) = plugin_form::program(o);
    match (&o.command, ok) {
        (None, false) => format!(
            r#"<span class="prog missing">{}<code>{}</code> not found</span>"#,
            icon("i-alert"),
            esc(&program)
        ),
        _ => format!(
            r#"<span class="prog {cls}">{ic}<code>{cmd}</code></span>"#,
            cls = if ok { "ok" } else { "missing" },
            ic = icon(if ok { "i-check" } else { "i-alert" }),
            cmd = esc(&program),
        ),
    }
}

fn where_note() -> String {
    let dirs: Vec<String> = plugins::plugin_dirs()
        .iter()
        .map(|d| format!("<code>{}</code>", esc(&crate::workspace::shown_path(d))))
        .collect();
    let mut installed: Vec<String> = plugins::plugin_dirs()
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let stem = name
                .strip_suffix(std::env::consts::EXE_SUFFIX)
                .unwrap_or(&name)
                .strip_prefix("pathwarden-output-")?
                .to_string();
            (!stem.is_empty() && !stem.contains('.')).then_some(stem)
        })
        .collect();
    installed.sort();
    installed.dedup();
    let found = if installed.is_empty() {
        "None found yet.".to_string()
    } else {
        format!(
            "Found: {}.",
            installed
                .iter()
                .map(|n| format!("<strong>{}</strong>", esc(n)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let about = format!(
        "A plugin named x is the program pathwarden-output-x{} in {}. A script or program you choose must be given by its full path, or run through powershell, pwsh, python, node, bash, sh or cmd, which are only taken from system folders (System32, Program Files, or folders only root can change). Pathwarden never runs plugins from the current folder or from a PATH folder you can write to, so nobody can plant one there.",
        std::env::consts::EXE_SUFFIX,
        dirs.join(" or "),
    );
    format!(
        r#"<div class="note">{}<p><strong>Plugin programs.</strong> {found} {}</p></div>"#,
        icon("i-folder"),
        pages::tip("where-plugins", "Where plugins come from", &about),
    )
}

fn env_help() -> String {
    let example = if cfg!(windows) {
        r#"<pre class="code">setx PATHWARDEN_SN_USER "svc-pathwarden"
setx PATHWARDEN_SN_PASSWORD "••••••••"</pre>"#
    } else {
        r#"<pre class="code">export PATHWARDEN_SN_USER="svc-pathwarden"
export PATHWARDEN_SN_PASSWORD="••••••••"</pre>"#
    };
    format!(
        r#"<details class="help card"><summary>{} How to set an environment variable</summary><div class="help-body">
<p>Secrets never go in <code>pathwarden.toml</code> or on this page. The config only names the variable; set its value where the plugin runs.</p>
<p><strong>For the scheduled task</strong>: sign in as the account the task runs as and run, in a command prompt:</p>
{example}
<p class="muted small"><code>setx</code> stores the value in that account's profile, where every new process sees it. Running Pathwarden as a service account keeps it out of your own profile. A secret store your scheduler supports (a pipeline secret, a vault agent) works too, as long as it sets the variable.</p>
<p><strong>For "Test" on this page</strong>: this window only sees variables that were set before Pathwarden started. After <code>setx</code>, close Pathwarden and start it again from a new terminal.</p>
</div></details>"#,
        icon("i-lock")
    )
}

/// The page's title and rail entry: the output plugins (After each run)
/// and finding actions.
pub const PAGE_TITLE: &str = "Plugins and actions";

/// Plugins and actions (`/automate/ticketing`, in the Automate area): the
/// output plugins (After each run) and finding actions.
pub(crate) async fn list_page(State(st): State<Shared>) -> Html<String> {
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(&st, &runs);
    let loaded = settings::load(&st);
    let latest = run_data::latest_with(&st.ws(), run_data::EVENT_FILE);
    let mut b = format!(
        r#"<div class="page-head"><div><p class="eyebrow">Automate</p><h1 class="panel-title">{PAGE_TITLE}</h1>
<p class="lead">Hand each scheduled run's results to other systems (set up on <a href="/automate/schedule">Schedule</a>), and add your own buttons to findings.</p></div></div>
{file}
<div class="ac-sect" id="after-each-run"><div><h2 class="sub">After each run</h2><p class="muted">A ticket per finding in ServiceNow or Jira, or a plugin of your own.</p></div>
<div class="rh-actions"><a class="btn primary" href="/plugins/new?kind=servicenow">{plus} Add ServiceNow</a><a class="btn primary" href="/plugins/new?kind=jira">{plus} Add Jira</a><a class="btn" href="/plugins/new?kind=command">{plus} {other}</a></div></div>"#,
        plus = icon("i-plus"),
        other = esc(other_title(st.allow_destinations)),
        file = settings::file_line_if_there(&st, &loaded),
    );
    let outputs = &loaded.config.outputs;
    if outputs.is_empty() {
        let _ = write!(
            b,
            r#"<div class="empty card">{}<p><strong>No plugins yet.</strong><br><span class="muted">Scheduled runs keep their history either way; plugins only pass the results on.</span></p></div>"#,
            icon("i-plug")
        );
    } else {
        b.push_str(r#"<div class="rows card pluglist">"#);
        for (i, o) in outputs.iter().enumerate() {
            let kind = esc(&describe(o));
            let names = env_names(o);
            let _ = write!(
                b,
                r#"<div class="plugrow" id="plugin-{i}">
<span class="zr-icon">{ic}</span>
<div class="zr-main"><a class="zr-name" href="/plugins/{i}/edit">{name}</a><span class="zr-rules">{kind}</span>{program}{env}</div>
<div class="zr-actions"><button type="button" class="btn small-btn" data-test-plugin="{i}" data-name="{name}" data-custom="{custom}"{disabled}>{i_play} Test</button><a class="btn small-btn" href="/plugins/{i}/edit">{i_edit} Edit</a><button type="button" class="btn small-btn danger" data-delete-plugin="{i}" data-name="{name}" aria-label="Delete {name}">{i_trash}</button></div>
<div class="test-out" hidden><div class="test-head"><strong class="test-title"></strong><span class="muted small test-sub"></span></div><pre class="code test-log"></pre></div>
</div>"#,
                ic = icon("i-plug"),
                name = esc(&o.plugin),
                program = program_line(o),
                env = if names.is_empty() {
                    String::new()
                } else {
                    format!(r#"<span class="envs">{}</span>"#, env_chips(&names))
                },
                custom = plugin_form::test_needs_confirmation(o),
                disabled = if latest.is_some() { "" } else { " disabled" },
                i_play = icon("i-play"),
                i_edit = icon("i-edit"),
                i_trash = icon("i-trash"),
            );
        }
        b.push_str("</div>");
        let _ = write!(
            b,
            r#"<p class="muted small after-list">{}</p>"#,
            match &latest {
                Some((r, _)) => format!(
                    "<strong>Test</strong> runs the plugin as a dry run on the latest analysis ({}, {}): it reports what it would do and changes nothing. Every finding counts as new, as on a first scheduled run.",
                    esc(&r.environment()),
                    pages::time(r.created_at)
                ),
                None => "Testing needs one analysis first: <a href=\"/analyze\">analyze a collection</a> or try the demo.".into(),
            }
        );
    }
    b.push_str(&crate::actions_app::settings_section(
        &st,
        &loaded.config.actions,
    ));
    b.push_str(&where_note());
    b.push_str(&env_help());
    b.push_str(&settings::after_save(&st));
    b.push_str(r#"<script src="/static/config.js" defer></script>"#);
    b.push_str(crate::actions_app::SCRIPTS);
    Html(pages::shell(
        &ctx,
        Some(Nav::Plugins),
        PAGE_TITLE,
        "config",
        &b,
    ))
}

#[derive(Deserialize)]
struct NewQuery {
    #[serde(default)]
    kind: String,
}

/// Which form a plugin gets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    ServiceNow,
    Jira,
    Command,
}

impl Kind {
    fn of(o: &OutputConfig) -> Self {
        if is_servicenow(o) {
            Kind::ServiceNow
        } else if is_jira(o) {
            Kind::Jira
        } else {
            Kind::Command
        }
    }
    fn name(self) -> &'static str {
        match self {
            Kind::ServiceNow => "servicenow",
            Kind::Jira => "jira",
            Kind::Command => "command",
        }
    }
}

async fn new_page(State(st): State<Shared>, Query(q): Query<NewQuery>) -> Html<String> {
    let kind = match q.kind.as_str() {
        "command" => Kind::Command,
        "jira" => Kind::Jira,
        _ => Kind::ServiceNow,
    };
    let blank = OutputConfig {
        plugin: match kind {
            Kind::ServiceNow => SERVICENOW.into(),
            Kind::Jira => JIRA.into(),
            Kind::Command => String::new(),
        },
        command: (kind == Kind::Command).then(Vec::new),
        settings: serde_json::Map::new(),
    };
    form_page(&st, None, &blank, kind)
}

async fn edit_page(State(st): State<Shared>, Path(index): Path<usize>) -> Response {
    let loaded = settings::load(&st);
    match loaded.config.outputs.get(index) {
        Some(o) => form_page(&st, Some(index), o, Kind::of(o)).into_response(),
        None => (StatusCode::NOT_FOUND, Html(pages::not_found())).into_response(),
    }
}

fn setting_str<'a>(o: &'a OutputConfig, key: &str) -> &'a str {
    o.settings.get(key).and_then(Value::as_str).unwrap_or("")
}

fn kv_rows(rows: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in rows {
        let _ = write!(
            s,
            r#"<div class="kv"><input class="input mono" data-k value="{k}" placeholder="name" aria-label="Name" autocomplete="off" spellcheck="false"><input class="input" data-v value="{v}" placeholder="value" aria-label="Value" autocomplete="off"><button type="button" class="fl-remove" data-remove-kv aria-label="Remove">{x}</button></div>"#,
            k = crate::pages::attr(k),
            v = crate::pages::attr(v),
            x = icon("i-x"),
        );
    }
    s
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The button and form for a plugin other than ServiceNow and Jira: what
/// it can add. With `--lock-destinations` that is only a plugin
/// program (`pathwarden-output-<name>`), not a script.
fn other_title(allow_commands: bool) -> &'static str {
    if allow_commands {
        "Add a script or program"
    } else {
        "Add a plugin program"
    }
}

fn form_page(st: &AppState, index: Option<usize>, o: &OutputConfig, kind: Kind) -> Html<String> {
    let runs = st.ws().runs();
    let ctx = pages::Ctx::new(st, &runs);
    let title = match (index, kind) {
        (None, Kind::ServiceNow) => "Add ServiceNow".to_string(),
        (None, Kind::Jira) => "Add Jira".to_string(),
        (None, Kind::Command) => other_title(st.allow_destinations).to_string(),
        (Some(_), _) => format!("Edit {}", o.plugin),
    };
    let head = format!(
        r#"<div class="page-head"><div><p class="eyebrow"><a href="/automate/ticketing">{PAGE_TITLE}</a></p><h1 class="panel-title">{}</h1></div></div>"#,
        esc(&title)
    );
    let meta = serde_json::json!({ "index": index, "expect": o.plugin, "kind": kind.name() });
    let locked = !st.allow_destinations;
    let body = match kind {
        Kind::ServiceNow => servicenow_form(o, locked),
        Kind::Jira => jira_form(o, locked),
        Kind::Command => command_form(o, st.allow_destinations),
    };
    let page = format!(
        r#"{head}<form class="card setting plugin-form" id="plugin-form" data-plugin="{meta}" novalidate>{body}
<div class="card-actions"><button type="submit" class="btn primary">{check} Save plugin</button><a class="btn" href="/automate/ticketing">Cancel</a><span class="save-status muted small" aria-live="polite"></span></div>
</form>
{help}{saved}<script src="/static/config.js" defer></script>"#,
        meta = crate::pages::json_attr(&meta.to_string()),
        check = icon("i-check"),
        help = env_help(),
        saved = settings::after_save(st),
    );
    Html(pages::shell(
        &ctx,
        Some(Nav::Plugins),
        &title,
        "config",
        &page,
    ))
}

fn servicenow_form(o: &OutputConfig, locked: bool) -> String {
    let table = match setting_str(o, "table") {
        "" => "incident",
        t => t,
    };
    let mut tables = String::new();
    let mut known = vec![
        ("incident", "Incidents (incident)"),
        ("sc_req_item", "Requested items (sc_req_item)"),
    ];
    if !known.iter().any(|(t, _)| *t == table) {
        known.push((table, table));
    }
    for (t, label) in known {
        let _ = write!(
            tables,
            r#"<option value="{t}"{s}>{label}</option>"#,
            t = esc(t),
            label = esc(label),
            s = if t == table { " selected" } else { "" }
        );
    }
    let sevs = severity_options(o);
    let bearer = o.settings.contains_key("token_env");
    let env_or = |key: &str, default: &str| match setting_str(o, key) {
        "" => default.to_string(),
        v => v.to_string(),
    };
    let mut fields: Vec<(String, String)> = o
        .settings
        .get("fields")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| scalar_text(v).map(|v| (k.clone(), v)))
                .collect()
        })
        .unwrap_or_default();
    if fields.is_empty() {
        // One empty row to fill in; the hint names the usual fields.
        fields.push((String::new(), String::new()));
    }
    let shown = [
        "instance",
        "table",
        "min_severity",
        "username_env",
        "password_env",
        "token_env",
        "fields",
        "scope",
        "max_create",
        "max_resolve_percent",
    ];
    let other: Vec<&str> = o
        .settings
        .keys()
        .map(String::as_str)
        .filter(|k| !shown.contains(k))
        .collect();
    format!(
        r#"<input type="hidden" id="pl-name" value="servicenow">{lock}
<p class="muted">One ticket per finding: new findings get a ticket, fixed ones are resolved, and findings that come back reopen theirs. {docs} lists every option.</p>
<div class="fields2">
  <div class="field"><label for="sn-instance">Instance URL</label><input class="input mono" id="sn-instance" value="{instance}" placeholder="https://example.service-now.com" autocomplete="off" spellcheck="false" required><p class="hint">Must start with <code>https://</code>: credentials are sent to it.</p></div>
  <div class="field"><label for="sn-table">Create</label><select class="input" id="sn-table">{tables}</select></div>
  <div class="field"><label for="sn-min">Open tickets for</label><select class="input" id="sn-min">{sevs}</select><p class="hint">Findings below this get no ticket. Existing tickets are still kept up to date.</p></div>
  <div class="field"><label for="sn-scope">Scope <span class="muted">(optional)</span></label><input class="input mono" id="sn-scope" value="{scope}" placeholder="prod" maxlength="40" autocomplete="off" spellcheck="false"><p class="hint">Only when two deployments share one instance. Pick it once: changing it later orphans existing tickets.</p></div>
</div>
<fieldset class="choice"><legend>Sign-in</legend>
  <label class="option card"><input type="radio" name="sn-auth" value="basic"{basic_on}><span><strong>User name and password</strong><span class="muted">Basic authentication with an integration account.</span></span></label>
  <label class="option card"><input type="radio" name="sn-auth" value="bearer"{bearer_on}><span><strong>Bearer token</strong><span class="muted">An OAuth access token.</span></span></label>
</fieldset>
<div class="fields2">
  <div class="field" data-when-auth="basic"><label for="sn-user-env">User name: environment variable</label><input class="input mono" id="sn-user-env" data-env value="{user_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
  <div class="field" data-when-auth="basic"><label for="sn-pass-env">Password: environment variable</label><input class="input mono" id="sn-pass-env" data-env value="{pass_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
  <div class="field" data-when-auth="bearer"><label for="sn-token-env">Token: environment variable</label><input class="input mono" id="sn-token-env" data-env value="{token_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
</div>
<p class="hint">Only the <em>names</em> of the variables are saved. Whether each is set is checked in the environment Pathwarden was started from.</p>
<h3 class="form-title">Fields on new tickets</h3>
<p class="hint">For example <code>assignment_group</code>, <code>category</code>, <code>caller_id</code> or <code>cmdb_ci</code>, with the value as ServiceNow expects it.</p>
<div class="kvs" id="sn-fields">{fields}</div>
<button type="button" class="btn small-btn" data-add-kv="sn-fields">{plus} Add a field</button>
{limits}{other}"#,
        docs = crate::pages::repo_link(
            "crates/pathwarden-output-servicenow/README.md",
            "The ServiceNow plugin's guide"
        ),
        instance = esc(setting_str(o, "instance")),
        scope = crate::pages::attr(setting_str(o, "scope")),
        basic_on = if bearer { "" } else { " checked" },
        bearer_on = if bearer { " checked" } else { "" },
        user_env = crate::pages::attr(&env_or("username_env", SN_USER)),
        pass_env = crate::pages::attr(&env_or("password_env", SN_PASSWORD)),
        token_env = crate::pages::attr(&env_or("token_env", SN_TOKEN)),
        fields = kv_rows(&fields),
        plus = icon("i-plus"),
        limits = limits_html(o, "tickets", locked),
        other = kept_note(&other),
        lock = destination_lock(locked),
    )
}

/// The lock note on the ServiceNow and Jira forms with
/// `--lock-destinations`: where findings go can't be changed here.
fn destination_lock(locked: bool) -> String {
    if locked {
        pages::lock_note("lock-destinations", plugin_form::DESTINATION_LOCKED)
    } else {
        String::new()
    }
}

/// "Also set in the file and kept as written: ...", for settings the form
/// doesn't show.
fn kept_note(other: &[&str]) -> String {
    if other.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="muted small kept">Also set in the file and kept as written: {}.</p>"#,
            other
                .iter()
                .map(|k| format!("<code>{}</code>", esc(k)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// The "Open tickets for" options, with the plugin's `min_severity`
/// selected (medium by default).
fn severity_options(o: &OutputConfig) -> String {
    let min = match setting_str(o, "min_severity") {
        "" => "medium",
        m => m,
    };
    let mut sevs = String::new();
    for (v, label) in [
        ("critical", "Critical only"),
        ("high", "High and above"),
        ("medium", "Medium and above (default)"),
        ("low", "Low and above"),
        ("info", "Everything"),
    ] {
        let _ = write!(
            sevs,
            r#"<option value="{v}"{s}>{label}</option>"#,
            s = if v.eq_ignore_ascii_case(min) {
                " selected"
            } else {
                ""
            }
        );
    }
    sevs
}

/// A number setting as the form shows it, or `default`.
fn number_text(o: &OutputConfig, key: &str, default: &str) -> String {
    match o.settings.get(key) {
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 => format!("{f:.0}"),
            _ => n.to_string(),
        },
        Some(v) => scalar_text(v).unwrap_or_else(|| default.into()),
        None => default.into(),
    }
}

/// The ServiceNow and Jira plugins' safety limits (`max_create`,
/// `max_resolve_percent`); `noun` is "tickets" or "issues".
fn limits_html(o: &OutputConfig, noun: &str, locked: bool) -> String {
    format!(
        r#"<h3 class="form-title">Safety limits</h3>
<div class="fields2">
  <div class="field"><label for="pl-max-create">Most new {noun} in one run</label><input class="input" id="pl-max-create" type="number" min="1" max="100000" step="1" value="{create}" placeholder="100" inputmode="numeric"><p class="hint">A run that would open more opens none of them and says why, so a first run on a big domain can't flood the queue. Default 100.</p></div>
  <div class="field"><label for="pl-max-resolve">Most open {noun} closed in one run (%)</label><input class="input" id="pl-max-resolve" type="number" min="1" max="100" step="1" value="{resolve}" placeholder="50" inputmode="numeric"><p class="hint">A run that would close more closes none of them and says why, for example after a collection that missed a domain. Default 50; 100 turns this off.</p></div>
</div>{guard}"#,
        create = crate::pages::attr(&number_text(o, "max_create", "100")),
        resolve = crate::pages::attr(&number_text(o, "max_resolve_percent", "50")),
        guard = if locked {
            pages::lock_note("lock-close-limit", plugin_form::GUARD_LOCKED)
        } else {
            String::new()
        },
    )
}

fn jira_form(o: &OutputConfig, locked: bool) -> String {
    let data_center = matches!(setting_str(o, "deployment"), "data_center" | "server");
    let pat = o.settings.contains_key("pat_env");
    let or = |key: &str, default: &str| match setting_str(o, key) {
        "" => default.to_string(),
        v => v.to_string(),
    };
    // Jira fields may be JSON (components, custom select fields): shown as
    // JSON text, saved back as JSON.
    let mut fields: Vec<(String, String)> = o
        .settings
        .get("fields")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), scalar_text(v).unwrap_or_else(|| v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    if fields.is_empty() {
        fields.push((String::new(), String::new()));
    }
    let priority_off = o.settings.get("set_priority").and_then(Value::as_bool) == Some(false);
    let on_closed = match setting_str(o, "on_closed_but_present") {
        "" => "reopen",
        v => v,
    };
    let mut closed_opts = String::new();
    for (v, label) in [
        ("reopen", "Reopen it (default)"),
        ("comment", "Add a comment"),
        ("ignore", "Leave it"),
    ] {
        let _ = write!(
            closed_opts,
            r#"<option value="{v}"{s}>{label}</option>"#,
            s = if v.eq_ignore_ascii_case(on_closed) {
                " selected"
            } else {
                ""
            }
        );
    }
    let advanced = ["close_transition", "reopen_transition", "close_resolution"]
        .iter()
        .any(|k| !setting_str(o, k).is_empty());
    let shown = [
        "instance",
        "deployment",
        "project",
        "issue_type",
        "min_severity",
        "scope",
        "username_env",
        "token_env",
        "pat_env",
        "set_priority",
        "on_closed_but_present",
        "close_transition",
        "reopen_transition",
        "close_resolution",
        "fields",
        "max_create",
        "max_resolve_percent",
    ];
    let other: Vec<&str> = o
        .settings
        .keys()
        .map(String::as_str)
        .filter(|k| !shown.contains(k))
        .collect();
    let attr = |s: &str| crate::pages::attr(s);
    format!(
        r#"<input type="hidden" id="pl-name" value="jira">{lock}
<p class="muted">One issue per finding: new findings get an issue, fixed ones are closed, and findings that come back reopen theirs. {docs} lists every option.</p>
<div class="fields2">
  <div class="field"><label for="j-instance">Instance URL</label><input class="input mono" id="j-instance" value="{instance}" placeholder="https://example.atlassian.net" autocomplete="off" spellcheck="false" required><p class="hint">Must start with <code>https://</code>: credentials are sent to it.</p></div>
  <div class="field"><label for="j-deployment">Jira</label><select class="input" id="j-deployment"><option value="cloud"{cloud_sel}>Jira Cloud (default)</option><option value="data_center"{dc_sel}>Jira Data Center or Server</option></select></div>
  <div class="field"><label for="j-project">Project key</label><input class="input mono" id="j-project" value="{project}" placeholder="SEC" maxlength="30" autocomplete="off" spellcheck="false" required></div>
  <div class="field"><label for="j-type">Issue type</label><input class="input" id="j-type" value="{issue_type}" placeholder="Task" maxlength="100" autocomplete="off" spellcheck="false"><p class="hint">As it's named in the project, like Task, Bug or Story.</p></div>
  <div class="field"><label for="j-min">Open issues for</label><select class="input" id="j-min">{sevs}</select><p class="hint">Findings below this get no issue. Existing issues are still kept up to date.</p></div>
  <div class="field"><label for="j-scope">Scope <span class="muted">(optional)</span></label><input class="input mono" id="j-scope" value="{scope}" placeholder="prod" maxlength="40" autocomplete="off" spellcheck="false"><p class="hint">Only when two deployments share one project. Pick it once: changing it later orphans existing issues.</p></div>
</div>
<fieldset class="choice"><legend>Sign-in</legend>
  <label class="option card"><input type="radio" name="j-auth" value="basic"{basic_on}><span><strong>Email and API token</strong><span class="muted">Jira Cloud. On Data Center: a user name and password.</span></span></label>
  <label class="option card"><input type="radio" name="j-auth" value="pat"{pat_on}><span><strong>Personal access token</strong><span class="muted">Jira Data Center only.</span></span></label>
</fieldset>
<div class="fields2">
  <div class="field" data-when-auth="basic"><label for="j-user-env">Email or user name: environment variable</label><input class="input mono" id="j-user-env" data-env value="{user_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
  <div class="field" data-when-auth="basic"><label for="j-token-env">API token or password: environment variable</label><input class="input mono" id="j-token-env" data-env value="{token_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
  <div class="field" data-when-auth="pat"><label for="j-pat-env">Personal access token: environment variable</label><input class="input mono" id="j-pat-env" data-env value="{pat_env}" autocomplete="off" spellcheck="false"><span class="envstatus"></span></div>
</div>
<p class="hint">Only the <em>names</em> of the variables are saved. Whether each is set is checked in the environment Pathwarden was started from.</p>
<div class="fields2">
  <div class="field"><label for="j-priority">Priority</label><select class="input" id="j-priority"><option value="true"{prio_on}>Set from the severity (default)</option><option value="false"{prio_off}>Leave it to Jira</option></select><p class="hint">Critical is Highest, High is High, and so on. Leave it to Jira if Priority isn't on the project's create screen.</p></div>
  <div class="field"><label for="j-closed">When a closed issue's finding is still there</label><select class="input" id="j-closed">{closed_opts}</select><p class="hint">Issues closed as Won't Do, Won't Fix, Duplicate or Risk Accepted are never reopened.</p></div>
</div>
<h3 class="form-title">Fields on new issues</h3>
<p class="hint">For example <code>components</code> or a custom field like <code>customfield_10010</code>, with the value as Jira expects it: plain text, or JSON such as <code>[{{"name": "Active Directory"}}]</code>.</p>
<div class="kvs" id="j-fields">{fields}</div>
<button type="button" class="btn small-btn" data-add-kv="j-fields">{plus} Add a field</button>
{limits}
<details class="help card j-advanced"{adv_open}><summary>Closing and reopening <span class="muted">(optional)</span></summary><div class="help-body">
<p class="hint">Leave these empty and Pathwarden uses the first transition to a Done status to close, and to a To Do status to reopen. Fill them in when your workflow needs a particular one.</p>
<div class="fields2">
  <div class="field"><label for="j-close-tr">Close with transition</label><input class="input" id="j-close-tr" value="{close_tr}" placeholder="Done" maxlength="100" autocomplete="off"></div>
  <div class="field"><label for="j-reopen-tr">Reopen with transition</label><input class="input" id="j-reopen-tr" value="{reopen_tr}" placeholder="Reopen" maxlength="100" autocomplete="off"></div>
  <div class="field"><label for="j-resolution">Resolution when closing</label><input class="input" id="j-resolution" value="{resolution}" placeholder="Done" maxlength="100" autocomplete="off"><p class="hint">Only for workflows whose close screen asks for one.</p></div>
</div></div></details>
{other}"#,
        docs = crate::pages::repo_link(
            "crates/pathwarden-output-jira/README.md",
            "The Jira plugin's guide"
        ),
        instance = attr(setting_str(o, "instance")),
        cloud_sel = if data_center { "" } else { " selected" },
        dc_sel = if data_center { " selected" } else { "" },
        project = attr(setting_str(o, "project")),
        issue_type = attr(&or("issue_type", "Task")),
        sevs = severity_options(o),
        scope = attr(setting_str(o, "scope")),
        basic_on = if pat { "" } else { " checked" },
        pat_on = if pat { " checked" } else { "" },
        user_env = attr(&or("username_env", JIRA_USER)),
        token_env = attr(&or("token_env", JIRA_TOKEN)),
        pat_env = attr(&or("pat_env", JIRA_PAT)),
        prio_on = if priority_off { "" } else { " selected" },
        prio_off = if priority_off { " selected" } else { "" },
        fields = kv_rows(&fields),
        plus = icon("i-plus"),
        limits = limits_html(o, "issues", locked),
        lock = destination_lock(locked),
        adv_open = if advanced { " open" } else { "" },
        close_tr = attr(setting_str(o, "close_transition")),
        reopen_tr = attr(setting_str(o, "reopen_transition")),
        resolution = attr(setting_str(o, "close_resolution")),
        other = kept_note(&other),
    )
}

/// Why the page can't change a plugin's program.
fn commands_locked_note() -> String {
    pages::lock_note("lock-programs", plugin_form::COMMANDS_LOCKED)
}

fn command_form(o: &OutputConfig, allow_commands: bool) -> String {
    let (program, args) = match &o.command {
        Some(argv) if !argv.is_empty() => (argv[0].clone(), argv[1..].join("\n")),
        _ => (String::new(), String::new()),
    };
    // With --lock-destinations a new plugin can only be a plugin
    // program, and an existing command is shown but can't be edited.
    let has_command = o.command.as_ref().is_some_and(|c| !c.is_empty());
    let by_name = o.command.is_none() || (!allow_commands && !has_command);
    let locked = !allow_commands;
    let readonly = if locked { " readonly" } else { "" };
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut kept = Vec::new();
    for (k, v) in &o.settings {
        match scalar_text(v) {
            Some(t) => rows.push((k.clone(), t)),
            None => kept.push(format!("<code>{}</code>", esc(k))),
        }
    }
    let example = if cfg!(windows) {
        r"C:\Pathwarden\plugins\teams.ps1"
    } else {
        "/opt/pathwarden/plugins/teams.sh"
    };
    format!(
        r#"<div class="field"><label for="pl-name">Name</label><input class="input mono" id="pl-name" value="{name}" placeholder="teams" maxlength="64" autocomplete="off" spellcheck="false" required><p class="hint">Lowercase letters, digits and dashes. Shown in run output as <code>[name]</code>.</p></div>
{locked_note}<fieldset class="choice"><legend>What to run</legend>
  <label class="option card{cmd_off}"><input type="radio" name="pl-how" value="command"{cmd_on}{cmd_disabled}><span><strong>A script or program</strong><span class="muted">PowerShell, Python or any program, with its arguments.</span></span></label>
  <label class="option card"><input type="radio" name="pl-how" value="named"{named_on}><span><strong>A plugin program</strong><span class="muted"><code>pathwarden-output-&lt;name&gt;</code> from the plugins folder.</span></span></label>
</fieldset>
<div class="fields2" data-when-how="command">
  <div class="field"><label for="pl-program">Program</label><input class="input mono" id="pl-program" value="{program}" placeholder="powershell" autocomplete="off" spellcheck="false"{readonly}><p class="hint">A full path, or one of: powershell, pwsh, python, python3, node, bash, sh, cmd (found only in system folders such as System32 or Program Files, never on a PATH folder you can write to). Not a network path.</p></div>
  <div class="field"><label for="pl-args">Arguments, one per line</label><textarea class="input mono" id="pl-args" rows="4" placeholder="-NoProfile&#10;-File&#10;{example}" spellcheck="false"{readonly}>{args}</textarea><p class="hint">Give scripts by their full path.</p></div>
</div>
<h3 class="form-title">Settings</h3>
<p class="hint">Passed to the plugin as JSON in <code>PATHWARDEN_OUTPUT_SETTINGS</code>. For a secret, add a setting ending in <code>_env</code> whose value is the <em>name</em> of an environment variable, such as <code>webhook_env = PATHWARDEN_TEAMS_WEBHOOK</code>; only those variables reach the plugin. Whole numbers and true/false are saved as such. <code>timeout_seconds</code> limits how long it may run (default 600).</p>
<div class="kvs" id="pl-settings">{rows}</div>
<button type="button" class="btn small-btn" data-add-kv="pl-settings">{plus} Add a setting</button>
<div class="envs" id="pl-envs"></div>
{kept}"#,
        name = crate::pages::attr(&o.plugin),
        cmd_on = if by_name { "" } else { " checked" },
        named_on = if by_name { " checked" } else { "" },
        locked_note = if locked {
            commands_locked_note()
        } else {
            String::new()
        },
        cmd_off = if locked && !has_command { " off" } else { "" },
        cmd_disabled = if locked && !has_command {
            " disabled"
        } else {
            ""
        },
        program = crate::pages::attr(&program),
        args = esc(&args),
        rows = kv_rows(&rows),
        plus = icon("i-plus"),
        kept = if kept.is_empty() {
            String::new()
        } else {
            format!(
                r#"<p class="muted small kept">Also set in the file and kept as written: {}.</p>"#,
                kept.join(", ")
            )
        },
    )
}

// ------------------------------------------------------------------- API

#[derive(Deserialize)]
struct SaveBody {
    index: Option<usize>,
    expect: Option<String>,
    #[serde(flatten)]
    form: PluginForm,
}

async fn save(State(st): State<Shared>, Json(body): Json<SaveBody>) -> Response {
    let loaded = settings::load(&st);
    let existing = body.index.and_then(|i| loaded.config.outputs.get(i));
    let mut edit = match body.form.edit(existing) {
        Ok(e) => e,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if let Err(e) = plugin_form::check_command(st.allow_destinations, &mut edit, existing) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    settings::edit(&st, move |d| {
        d.upsert_output(body.index, body.expect.as_deref(), &edit)
    })
    .await
}

#[derive(Deserialize)]
struct NameBody {
    expect: String,
}

async fn remove(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    Json(body): Json<NameBody>,
) -> Response {
    settings::edit(&st, move |d| d.remove_output(index, &body.expect)).await
}

/// Runs the plugin as a dry run on the latest run's event.
async fn test(
    State(st): State<Shared>,
    Path(index): Path<usize>,
    Json(body): Json<NameBody>,
) -> Response {
    let loaded = settings::load(&st);
    if let Some(e) = loaded.error {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    let Some(output) = loaded.config.outputs.get(index).cloned() else {
        return json_error(
            StatusCode::NOT_FOUND,
            format!("No plugin {index}: reload the page, pathwarden.toml may have changed."),
        );
    };
    if output.plugin != body.expect {
        return json_error(StatusCode::CONFLICT, settings_changed());
    }
    let Some((run, dir)) = run_data::latest_with(&st.ws(), run_data::EVENT_FILE) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "Testing needs one analysis first. Analyze a collection or try the demo.",
        );
    };
    let result = tokio::task::spawn_blocking(move || {
        let event = run_data::event_text(&dir).ok_or("The latest run's event couldn't be read.")?;
        plugin_form::dry_run(&output, &event)
    })
    .await;
    let ran = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return json_error(StatusCode::BAD_REQUEST, e),
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The test stopped. Try again.",
            )
        }
    };
    Json(serde_json::json!({
        "ok": ran.ok,
        "status": ran.status,
        "output": ran.output,
        "run": format!("{}, analyzed {}", run.environment(), pathwarden_core::time::format_local(run.created_at)),
        "run_env": run.environment(),
        "run_at": run.created_at,
    }))
    .into_response()
}

fn settings_changed() -> &'static str {
    pathwarden_core::config_edit::CHANGED
}

#[derive(Deserialize)]
struct EnvQuery {
    #[serde(default)]
    names: String,
}

/// Whether each named environment variable is set in this process. Values
/// are never returned.
async fn env_status(Query(q): Query<EnvQuery>) -> Response {
    let mut out = serde_json::Map::new();
    for name in q
        .names
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .take(20)
    {
        if plugins::valid_env_name(name) {
            out.insert(name.to_string(), Value::Bool(env_is_set(name)));
        }
    }
    Json(Value::Object(out)).into_response()
}
