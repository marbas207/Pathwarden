//! The plugin forms' rules, shared by the app's Ticketing and alerts page
//! and `pathwarden plugins`: what a ServiceNow, Jira or script plugin may be set
//! to ([`PluginForm::edit`], turned into a [`ConfigDoc`] edit), which
//! environment variables a plugin reads, and "Test", a dry run of the
//! plugin on an event document ([`dry_run`]).
//!
//! Secrets never pass through here. Plugins read them from environment
//! variables whose *names* the config holds; only whether a named variable
//! is set is ever shown, never its value.
//!
//! [`ConfigDoc`]: crate::config_edit::ConfigDoc

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::config::OutputConfig;
use crate::config_edit::{OutputEdit, Setting};
use crate::plugins;

/// The plugin shipped with Pathwarden, which gets its own form.
pub const SERVICENOW: &str = "servicenow";
pub const SN_USER: &str = "PATHWARDEN_SN_USER";
pub const SN_PASSWORD: &str = "PATHWARDEN_SN_PASSWORD";
pub const SN_TOKEN: &str = "PATHWARDEN_SN_TOKEN";

/// The longest a test may run: the plugin's own `timeout_seconds` is capped
/// at this, since someone is waiting for the answer.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(120);
/// The most plugin output a test shows.
pub const MAX_TEST_OUTPUT: usize = 64 * 1024;

/// The message for a page session that tries to choose a program.
pub const COMMANDS_LOCKED: &str = "This page can't add or change the program a plugin runs. Edit pathwarden.toml, or start the UI with pathwarden ui --allow-destinations.";

/// The message for a page session that tries to change where a plugin
/// sends findings or its credentials, or which secrets it reads.
pub const DESTINATION_LOCKED: &str = "This page can't change where a plugin sends findings: its instance, project, table, allow_insecure_http or the environment variables it reads. Edit pathwarden.toml, or start the UI with pathwarden ui --allow-destinations.";

/// The message for a page session that tries to turn off the ticketing
/// plugins' check on how many open tickets one run may close.
pub const GUARD_LOCKED: &str = "This page can't turn off the limit on how many open tickets one run may close (max_resolve_percent 100). Edit pathwarden.toml, or start the UI with pathwarden ui --allow-destinations.";

/// The Jira plugin shipped with Pathwarden, which gets its own form too.
pub const JIRA: &str = "jira";
pub const JIRA_USER: &str = "PATHWARDEN_JIRA_USER";
pub const JIRA_TOKEN: &str = "PATHWARDEN_JIRA_TOKEN";
pub const JIRA_PAT: &str = "PATHWARDEN_JIRA_PAT";

/// Fields the Jira plugin sets itself, so `fields` may not.
pub const JIRA_RESERVED_FIELDS: [&str; 5] =
    ["project", "issuetype", "summary", "description", "labels"];

/// Why the script form refuses `servicenow` with no program of its own.
pub const SERVICENOW_FORM: &str =
    "Use the ServiceNow form (`pathwarden plugins add servicenow`) for the ServiceNow plugin.";

/// What "Test" asks before running a plugin that isn't shipped with
/// Pathwarden: only those are known to honor `dry_run`.
pub const TEST_CUSTOM: &str = "Pathwarden asks the plugin for a dry run by adding dry_run = true to its settings. A script that ignores that setting would really send its alert or create its tickets. Run it only if yours honors dry_run.";

/// Whether "Test" must ask first ([`TEST_CUSTOM`]): every plugin but the
/// shipped ServiceNow and Jira ones.
pub fn test_needs_confirmation(o: &OutputConfig) -> bool {
    !is_servicenow(o) && !is_jira(o)
}

/// The ServiceNow plugin, configured by its form (not run as a command).
pub fn is_servicenow(o: &OutputConfig) -> bool {
    o.plugin == SERVICENOW && o.command.is_none()
}

/// The Jira plugin, configured by its form (not run as a command).
pub fn is_jira(o: &OutputConfig) -> bool {
    o.plugin == JIRA && o.command.is_none()
}

/// What a plugin is, as the Ticketing page and `pathwarden plugins list`
/// say it: "ServiceNow · incident at https://…", "Script or program",
/// "Plugin program". Unescaped.
pub fn describe(o: &OutputConfig) -> String {
    if is_servicenow(o) {
        let get = |k: &str, default: &'static str| {
            o.settings
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_string()
        };
        let table = get("table", "incident");
        format!(
            "ServiceNow · {} at {}",
            if table == "sc_req_item" {
                "requested items".to_string()
            } else {
                table
            },
            get("instance", "")
        )
    } else if is_jira(o) {
        let get = |k: &str| o.settings.get(k).and_then(Value::as_str).unwrap_or("");
        format!("Jira · {} at {}", get("project"), get("instance"))
    } else if o.command.is_some() {
        "Script or program".into()
    } else {
        "Plugin program".into()
    }
}

/// Whether the environment variable is set (and not empty) in this process.
pub fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// The environment variables an output reads, with ServiceNow's defaults.
pub fn env_names(o: &OutputConfig) -> Vec<String> {
    let mut names = plugins::named_env(o);
    if is_servicenow(o) && !o.settings.contains_key("token_env") {
        for (key, default) in [("username_env", SN_USER), ("password_env", SN_PASSWORD)] {
            if !o.settings.contains_key(key) {
                names.push(default.to_string());
            }
        }
    }
    if is_jira(o) && !o.settings.contains_key("pat_env") {
        for (key, default) in [("username_env", JIRA_USER), ("token_env", JIRA_TOKEN)] {
            if !o.settings.contains_key(key) {
                names.push(default.to_string());
            }
        }
    }
    names
}

fn severity(min: &str, what: &str) -> Result<String, String> {
    let min = min.trim().to_ascii_lowercase();
    if matches!(
        min.as_str(),
        "critical" | "high" | "medium" | "low" | "info"
    ) {
        Ok(min)
    } else {
        Err(format!("Choose which findings get {what}."))
    }
}

fn check_scope(scope: &str) -> Result<(), String> {
    if !scope.is_empty()
        && !(scope.len() <= 40
            && scope
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')))
    {
        return Err("Scope: up to 40 letters, digits, '.', '_' or '-'.".into());
    }
    Ok(())
}

/// A Jira name (issue type, transition, resolution), as the plugin checks
/// it: no quotes, backslashes or control characters, at most 100.
fn jira_name(label: &str, v: &str) -> Result<(), String> {
    if (1..=100).contains(&v.len())
        && !v
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '\''))
    {
        Ok(())
    } else {
        Err(format!(
            "{label}: up to 100 characters, without quotes or backslashes."
        ))
    }
}

/// An optional setting: set when given, removed when empty.
fn optional(set: &mut Vec<(String, Setting)>, remove: &mut Vec<String>, key: &str, v: &str) {
    if v.is_empty() {
        remove.push(key.into());
    } else {
        set.push((key.into(), Setting::Str(v.into())));
    }
}

impl PluginForm {
    /// The ticketing plugins' safety limits: `max_create` (1 to 100000,
    /// default 100) and `max_resolve_percent` (1 to 100, default 50; 100
    /// turns the check off). The default itself is written as no setting.
    fn limits(
        &self,
        set: &mut Vec<(String, Setting)>,
        remove: &mut Vec<String>,
    ) -> Result<(), String> {
        for (key, given, range, default, msg) in [
            (
                "max_create",
                &self.max_create,
                1..=100_000,
                100,
                "Most new tickets in one run: a whole number from 1 to 100000.",
            ),
            (
                "max_resolve_percent",
                &self.max_resolve_percent,
                1..=100,
                50,
                "Most open tickets closed in one run: a whole percentage from 1 to 100.",
            ),
        ] {
            match given.as_deref().map(str::trim) {
                None => {}
                Some("") => remove.push(key.into()),
                Some(v) => match v.trim_end_matches('%').trim().parse::<i64>() {
                    Ok(n) if n == default => remove.push(key.into()),
                    Ok(n) if range.contains(&n) => set.push((key.into(), Setting::Int(n))),
                    _ => return Err(msg.into()),
                },
            }
        }
        Ok(())
    }

    /// The Jira form's change to the `[[output]]` entry.
    fn jira_edit(&self, existing: Option<&OutputConfig>) -> Result<OutputEdit, String> {
        let b = self;
        let allow_insecure = existing
            .and_then(|o| o.settings.get("allow_insecure_http"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if b.instance.trim().is_empty() {
            return Err("Enter the Jira address, like https://contoso.atlassian.net".into());
        }
        check_instance(&b.instance, allow_insecure)?;
        let data_center = match b.deployment.trim() {
            "" | "cloud" => false,
            "data_center" | "server" => true,
            _ => return Err("Choose Jira Cloud or Jira Data Center.".into()),
        };
        let project = b.project.trim();
        if !((1..=30).contains(&project.len())
            && project.as_bytes()[0].is_ascii_uppercase()
            && project
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'))
        {
            return Err(
                "Project key: capital letters, digits and _, starting with a letter, like SEC."
                    .into(),
            );
        }
        let issue_type = match b.issue_type.trim() {
            "" => "Task",
            t => t,
        };
        jira_name("Issue type", issue_type)?;
        let min = severity(&b.min_severity, "issues")?;
        let scope = b.scope.trim();
        check_scope(scope)?;
        let mut set = vec![
            (
                "instance".to_string(),
                Setting::Str(b.instance.trim().into()),
            ),
            ("project".to_string(), Setting::Str(project.into())),
            ("issue_type".to_string(), Setting::Str(issue_type.into())),
            ("min_severity".to_string(), Setting::Str(min)),
        ];
        let mut remove = Vec::new();
        if data_center {
            set.push(("deployment".into(), Setting::Str("data_center".into())));
        } else {
            remove.push("deployment".into());
        }
        optional(&mut set, &mut remove, "scope", scope);
        match b.auth.as_str() {
            "pat" => {
                if !data_center {
                    return Err("Personal access tokens are for Jira Data Center. Jira Cloud signs in with an e-mail and an API token.".into());
                }
                set.push(env_setting("pat_env", &b.pat_env)?);
                remove.extend(["username_env".to_string(), "token_env".to_string()]);
            }
            "basic" => {
                set.push(env_setting("username_env", &b.username_env)?);
                set.push(env_setting("token_env", &b.token_env)?);
                remove.push("pat_env".into());
            }
            _ => return Err("Choose how the plugin signs in.".into()),
        }
        match b.set_priority {
            Some(false) => set.push(("set_priority".into(), Setting::Bool(false))),
            Some(true) => remove.push("set_priority".into()),
            None => {}
        }
        match b.on_closed_but_present.trim() {
            "" | "reopen" => remove.push("on_closed_but_present".into()),
            v @ ("comment" | "ignore") => {
                set.push(("on_closed_but_present".into(), Setting::Str(v.into())))
            }
            _ => {
                return Err(
                    "Choose what happens when a closed issue's finding is still there.".into(),
                )
            }
        }
        for (key, label, v) in [
            (
                "close_transition",
                "Close with transition",
                &b.close_transition,
            ),
            (
                "reopen_transition",
                "Reopen with transition",
                &b.reopen_transition,
            ),
            (
                "close_resolution",
                "Resolution when closing",
                &b.close_resolution,
            ),
        ] {
            let v = v.trim();
            if !v.is_empty() {
                jira_name(label, v)?;
            }
            optional(&mut set, &mut remove, key, v);
        }
        b.limits(&mut set, &mut remove)?;
        for (k, v) in &b.fields {
            let k = k.trim();
            if looks_secret(k) {
                return Err(format!("{k}: don't put secrets in issue fields."));
            }
            if JIRA_RESERVED_FIELDS.contains(&k) {
                return Err(format!("{k}: the plugin sets this field itself."));
            }
            let v = v.trim();
            if (v.starts_with('[') || v.starts_with('{'))
                && serde_json::from_str::<Value>(v).is_err()
            {
                return Err(format!(
                    "{k}: the value starts like JSON but isn't valid JSON, like [{{\"name\": \"Active Directory\"}}]."
                ));
            }
        }
        Ok(OutputEdit {
            plugin: JIRA.into(),
            command: None,
            set,
            remove,
            replace_scalars: false,
            fields: Some(b.fields.clone()),
            json_fields: true,
        })
    }
}

/// What a plugin form sends: the ServiceNow form (`kind` `servicenow`), the
/// Jira form (`jira`) or the script or program form (`command`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PluginForm {
    pub kind: String,
    #[serde(default)]
    pub plugin: String,
    /// ServiceNow
    #[serde(default)]
    pub instance: String,
    #[serde(default)]
    pub table: String,
    #[serde(default)]
    pub min_severity: String,
    #[serde(default)]
    pub scope: String,
    /// `basic` or `bearer`.
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub username_env: String,
    #[serde(default)]
    pub password_env: String,
    #[serde(default)]
    pub token_env: String,
    #[serde(default)]
    pub fields: Vec<(String, String)>,
    /// ServiceNow and Jira: the safety limits, as typed. `None` leaves the
    /// file's value alone; empty removes it (the plugin's default).
    #[serde(default)]
    pub max_create: Option<String>,
    #[serde(default)]
    pub max_resolve_percent: Option<String>,
    /// Jira: `cloud` (default) or `data_center`.
    #[serde(default)]
    pub deployment: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub issue_type: String,
    /// Jira Data Center: a personal access token (`auth` `pat`).
    #[serde(default)]
    pub pat_env: String,
    /// Jira: set the priority from the severity (default true).
    #[serde(default)]
    pub set_priority: Option<bool>,
    /// Jira: `reopen` (default), `comment` or `ignore`.
    #[serde(default)]
    pub on_closed_but_present: String,
    #[serde(default)]
    pub close_transition: String,
    #[serde(default)]
    pub reopen_transition: String,
    #[serde(default)]
    pub close_resolution: String,
    /// Script or program: `None` runs the plugin program by its name.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub settings: Vec<(String, String)>,
}

/// The ServiceNow and Jira plugins' instance check: https, or http only to
/// this machine. Credentials in the URL are refused too.
pub fn check_instance(url: &str, allow_insecure: bool) -> Result<(), String> {
    let u = url.trim();
    if u.is_empty() {
        return Err("Enter the instance URL, like https://contoso.service-now.com".into());
    }
    if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("The instance URL can't contain spaces.".into());
    }
    if u.contains('\\') {
        return Err("The instance URL can't contain a backslash.".into());
    }
    let rest = if let Some(r) = u.strip_prefix("https://") {
        r
    } else if let Some(r) = u.strip_prefix("http://") {
        let host = r.split(['/', ':', '?', '#']).next().unwrap_or_default();
        if !allow_insecure
            && !matches!(
                host.to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1"
            )
        {
            return Err(
                "The instance URL must use https://: the plugin sends credentials to it.".into(),
            );
        }
        r
    } else {
        return Err(
            "The instance URL must use https://: the plugin sends credentials to it.".into(),
        );
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(
            "Don't put a user name or password in the URL: use the environment variables below."
                .into(),
        );
    }
    if authority.split(':').next().unwrap_or_default().is_empty() {
        return Err("The instance URL has no host name.".into());
    }
    Ok(())
}

/// Setting names that would hold a secret: those go in an environment
/// variable, named by a `<key>_env` setting.
pub fn looks_secret(key: &str) -> bool {
    !key.ends_with("_env")
        && [
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "webhook",
            "credential",
        ]
        .iter()
        .any(|w| key.contains(w))
}

fn env_setting(key: &str, name: &str) -> Result<(String, Setting), String> {
    let n = name.trim();
    if !plugins::valid_env_name(n) {
        return Err(format!(
            "{n:?} is not an environment variable name (letters, digits and _, not starting with a digit)"
        ));
    }
    Ok((key.to_string(), Setting::Str(n.to_string())))
}

impl PluginForm {
    /// The change to the `[[output]]` entry (`existing`, when editing one).
    pub fn edit(&self, existing: Option<&OutputConfig>) -> Result<OutputEdit, String> {
        let b = self;
        if b.kind == "servicenow" {
            let allow_insecure = existing
                .and_then(|o| o.settings.get("allow_insecure_http"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            check_instance(&b.instance, allow_insecure)?;
            let table = b.table.trim();
            if table.is_empty()
                || !table
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            {
                return Err(
                    "Table: lowercase letters, digits and _ (incident or sc_req_item).".into(),
                );
            }
            let min = severity(&b.min_severity, "tickets")?;
            let scope = b.scope.trim();
            check_scope(scope)?;
            let mut set = vec![
                (
                    "instance".to_string(),
                    Setting::Str(b.instance.trim().into()),
                ),
                ("table".to_string(), Setting::Str(table.into())),
                ("min_severity".to_string(), Setting::Str(min)),
            ];
            let mut remove = Vec::new();
            if scope.is_empty() {
                remove.push("scope".to_string());
            } else {
                set.push(("scope".into(), Setting::Str(scope.into())));
            }
            match b.auth.as_str() {
                "bearer" => {
                    set.push(env_setting("token_env", &b.token_env)?);
                    remove.extend(["username_env".to_string(), "password_env".to_string()]);
                }
                "basic" => {
                    set.push(env_setting("username_env", &b.username_env)?);
                    set.push(env_setting("password_env", &b.password_env)?);
                    remove.push("token_env".into());
                }
                _ => return Err("Choose how the plugin signs in.".into()),
            }
            b.limits(&mut set, &mut remove)?;
            for (k, _) in &b.fields {
                if looks_secret(k) {
                    return Err(format!("{k}: don't put secrets in ticket fields."));
                }
            }
            Ok(OutputEdit {
                plugin: SERVICENOW.into(),
                command: None,
                set,
                remove,
                replace_scalars: false,
                fields: Some(b.fields.clone()),
                json_fields: false,
            })
        } else if b.kind == "jira" {
            b.jira_edit(existing)
        } else {
            // Without a program of its own this entry is the ServiceNow
            // plugin, so it needs that form's checks (instance, table, auth).
            if b.plugin.trim().eq_ignore_ascii_case(SERVICENOW)
                && b.command.as_ref().is_none_or(|c| c.is_empty())
            {
                return Err(SERVICENOW_FORM.into());
            }
            let jira = b.plugin.trim().eq_ignore_ascii_case(JIRA)
                && b.command.as_ref().is_none_or(|c| c.is_empty());
            if jira {
                let get = |key: &str| {
                    b.settings
                        .iter()
                        .find(|(k, _)| k.trim() == key)
                        .map(|(_, v)| v.trim())
                };
                let instance = get("instance").unwrap_or_default();
                if instance.is_empty() {
                    return Err(
                        "Add the instance setting: the Jira address, like https://contoso.atlassian.net"
                            .into(),
                    );
                }
                check_instance(instance, get("allow_insecure_http") == Some("true"))?;
            }
            let mut set = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for (k, v) in &b.settings {
                let k = k.trim();
                if k.is_empty() && v.trim().is_empty() {
                    continue;
                }
                if !seen.insert(k.to_string()) {
                    return Err(format!("{k} is listed twice."));
                }
                if looks_secret(k) {
                    return Err(format!(
                        "Don't put secrets in the file. Instead of {k}, add {k}_env with the name of an environment variable that holds it."
                    ));
                }
                let v = v.trim();
                if k.ends_with("_env") {
                    set.push(env_setting(k, v)?);
                    continue;
                }
                let value = if let Ok(n) = v.parse::<i64>() {
                    Setting::Int(n)
                } else if v == "true" || v == "false" {
                    Setting::Bool(v == "true")
                } else {
                    Setting::Str(v.to_string())
                };
                set.push((k.to_string(), value));
            }
            Ok(OutputEdit {
                plugin: b.plugin.trim().to_string(),
                command: b.command.clone(),
                set,
                remove: Vec::new(),
                replace_scalars: true,
                fields: None,
                json_fields: false,
            })
        }
    }
}

/// Settings that say where a plugin sends what it knows: its `instance`,
/// the Jira `project` and ServiceNow `table` its tickets go in, whether
/// plain http is allowed, and every `*_env` (which secrets it reads). A
/// page session may not change them ([`check_command`]).
fn is_destination(key: &str) -> bool {
    matches!(
        key,
        "instance" | "project" | "table" | "allow_insecure_http"
    ) || key.ends_with("_env")
}

/// `max_resolve_percent` at 100: the ticketing plugins' resolve check off.
const RESOLVE_GUARD: &str = "max_resolve_percent";
const RESOLVE_GUARD_OFF: i64 = 100;

/// Whether `edit` turns the resolve check off where `existing` has it on.
fn turns_resolve_guard_off(edit: &OutputEdit, existing: Option<&OutputConfig>) -> bool {
    let off_now = existing
        .filter(|o| o.plugin == edit.plugin)
        .and_then(|o| o.settings.get(RESOLVE_GUARD))
        .and_then(Value::as_i64)
        .is_some_and(|n| n >= RESOLVE_GUARD_OFF);
    let off_after = edit.set.iter().any(|(k, v)| {
        k == RESOLVE_GUARD
            && match v {
                Setting::Int(n) => *n >= RESOLVE_GUARD_OFF,
                Setting::Str(s) => s
                    .trim()
                    .trim_end_matches('%')
                    .trim()
                    .parse::<i64>()
                    .is_ok_and(|n| n >= RESOLVE_GUARD_OFF),
                Setting::Bool(_) => false,
            }
    });
    off_after && !off_now
}

/// The [`is_destination`] settings an edit leaves, by name, as JSON
/// values: those of `existing` (when the edit is for the same plugin)
/// with the edit's changes applied.
fn destinations_after(
    edit: &OutputEdit,
    existing: Option<&OutputConfig>,
) -> std::collections::BTreeMap<String, Value> {
    let mut out: std::collections::BTreeMap<String, Value> = existing
        .filter(|o| o.plugin == edit.plugin)
        .map(|o| {
            o.settings
                .iter()
                .filter(|(k, v)| is_destination(k) && !v.is_array() && !v.is_object())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    if edit.replace_scalars {
        out.retain(|k, _| edit.set.iter().any(|(s, _)| s == k));
    }
    for k in &edit.remove {
        out.remove(k);
    }
    for (k, v) in &edit.set {
        if is_destination(k) {
            let v = match v {
                Setting::Str(s) => Value::from(s.as_str()),
                Setting::Int(n) => Value::from(*n),
                Setting::Bool(b) => Value::from(*b),
            };
            out.insert(k.clone(), v);
        }
    }
    out
}

/// The [`is_destination`] settings `existing` has now.
fn destinations_of(
    edit: &OutputEdit,
    existing: Option<&OutputConfig>,
) -> std::collections::BTreeMap<String, Value> {
    existing
        .filter(|o| o.plugin == edit.plugin)
        .map(|o| {
            o.settings
                .iter()
                .filter(|(k, v)| is_destination(k) && !v.is_array() && !v.is_object())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// What a save may change. Without `allow` (the app without
/// `--allow-destinations`) a save may keep a command the file already
/// has, but not add or change one: a page session must not be able to make
/// Pathwarden run a program of its choosing. Nor may it change where a
/// plugin sends findings or its credentials, or which secrets it reads (its
/// `instance`, `project`, `table`, `allow_insecure_http` and `*_env`
/// settings, [`DESTINATION_LOCKED`]): otherwise a page could point a
/// ticketing plugin's token at a server of its choosing and press Test, or
/// file every finding where it can read them. Nor may it turn the resolve
/// check off (`max_resolve_percent` 100, [`GUARD_LOCKED`]); other limits and
/// ticket fields stay editable. With `allow` (and always from the
/// terminal, where the file can be edited anyway), network paths and
/// relative script paths are still refused ([`plugins::check_args`]).
pub fn check_command(
    allow: bool,
    edit: &mut OutputEdit,
    existing: Option<&OutputConfig>,
) -> Result<(), String> {
    if allow {
        return match &edit.command {
            Some(new) => plugins::check_args(new),
            None => Ok(()),
        };
    }
    if let Some(new) = &edit.command {
        let norm = |c: &[String]| -> Vec<String> {
            c.iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        match existing.and_then(|o| o.command.as_ref()) {
            // Written back exactly as the file has it.
            Some(old) if norm(old) == norm(new) => edit.command = Some(old.clone()),
            _ => return Err(COMMANDS_LOCKED.into()),
        }
    }
    if destinations_after(edit, existing) != destinations_of(edit, existing) {
        return Err(DESTINATION_LOCKED.into());
    }
    if turns_resolve_guard_off(edit, existing) {
        return Err(GUARD_LOCKED.into());
    }
    Ok(())
}

/// Whether the program an output runs is there: a plugin program in the
/// plugins folder, an interpreter in a system folder, or a local file (a
/// network path is never looked at: that alone would sign in to the
/// server). The program as shown, and whether it was found.
pub fn program(o: &OutputConfig) -> (String, bool) {
    match &o.command {
        Some(argv) => {
            let program = argv.first().map(String::as_str).unwrap_or_default();
            let ok = if plugins::is_interpreter(program) {
                plugins::resolve_interpreter(program).is_some()
            } else {
                !plugins::is_remote_path(program) && std::path::Path::new(program).is_file()
            };
            (argv.join(" "), ok)
        }
        None => match plugins::locate(&o.plugin) {
            Some(p) => (p.display().to_string(), true),
            None => (plugins::program_name(&o.plugin), false),
        },
    }
}

/// What a test run printed and how it exited.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestRun {
    pub ok: bool,
    /// "exit code 0", or how it stopped.
    pub status: String,
    /// Its lines, at most [`MAX_TEST_OUTPUT`] bytes.
    pub output: String,
}

/// "Test": runs the plugin as a dry run (`dry_run = true` in its settings;
/// the plugins shipped with Pathwarden then change nothing) on `event`, for
/// at most [`TEST_TIMEOUT`].
pub fn dry_run(output: &OutputConfig, event: &str) -> Result<TestRun, String> {
    let mut dry = output.clone();
    dry.settings.insert("dry_run".into(), Value::Bool(true));
    let ran = plugins::run(&dry, event, Some(TEST_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut text = ran.lines().join("\n");
    if text.len() > MAX_TEST_OUTPUT {
        let mut cut = MAX_TEST_OUTPUT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n[output cut short]");
    }
    Ok(TestRun {
        ok: ran.status.success(),
        status: match ran.status.code() {
            Some(c) => format!("exit code {c}"),
            None => ran.status.to_string(),
        },
        output: text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instances_need_https_and_no_credentials() {
        assert!(check_instance("https://contoso.service-now.com", false).is_ok());
        assert!(check_instance("http://contoso.service-now.com", false).is_err());
        assert!(check_instance("http://contoso.service-now.com", true).is_ok());
        assert!(check_instance("http://localhost:8080", false).is_ok());
        assert!(check_instance("https://u:p@contoso.service-now.com", false).is_err());
        assert!(check_instance("ftp://x", false).is_err());
        assert!(check_instance("https://", false).is_err());
        assert!(check_instance("https://a b", false).is_err());
    }

    #[test]
    fn secret_looking_settings() {
        assert!(looks_secret("webhook"));
        assert!(looks_secret("api_token"));
        assert!(!looks_secret("webhook_env"));
        assert!(!looks_secret("min_change"));
    }

    #[test]
    fn forms_become_edits() {
        let sn = PluginForm {
            kind: "servicenow".into(),
            instance: "https://contoso.service-now.com".into(),
            table: "incident".into(),
            min_severity: "High".into(),
            auth: "bearer".into(),
            token_env: "SN_TOKEN".into(),
            fields: vec![("assignment_group".into(), "IAM".into())],
            ..Default::default()
        };
        let e = sn.edit(None).unwrap();
        assert_eq!(e.plugin, "servicenow");
        assert!(e
            .set
            .contains(&("min_severity".into(), Setting::Str("high".into()))));
        assert!(e.remove.contains(&"password_env".to_string()));
        let mut bad = sn.clone();
        bad.fields = vec![("password".into(), "x".into())];
        assert!(bad.edit(None).is_err());

        let script = PluginForm {
            kind: "command".into(),
            plugin: "teams".into(),
            command: Some(vec!["pwsh".into()]),
            settings: vec![
                ("webhook_env".into(), "TEAMS_HOOK".into()),
                ("timeout_seconds".into(), "30".into()),
            ],
            ..Default::default()
        };
        let mut e = script.edit(None).unwrap();
        assert!(e
            .set
            .contains(&("timeout_seconds".into(), Setting::Int(30))));
        // A page without --allow-destinations may not add a program; the
        // terminal may, but not from a network path.
        assert_eq!(
            check_command(false, &mut e.clone(), None),
            Err(COMMANDS_LOCKED.into())
        );
        assert!(check_command(true, &mut e, None).is_ok());
        e.command = Some(vec![r"\\server\share\x.exe".into()]);
        assert!(check_command(true, &mut e, None)
            .unwrap_err()
            .contains("network path"));
        // Nor as an argument's value.
        for arg in [
            r"-File=\\srv\s\x.ps1",
            r"-File:\\srv\s\x.ps1",
            "--script=//srv/s/x.ps1",
            "--x=file://srv/s",
        ] {
            e.command = Some(vec!["pwsh".into(), "-File".into(), arg.into()]);
            assert!(
                check_command(true, &mut e, None)
                    .unwrap_err()
                    .contains("network path"),
                "{arg}"
            );
        }
        e.command = Some(vec![
            "pwsh".into(),
            r"-File=C:\x\teams.ps1".into(),
            "--url=https://hooks.example.com/x".into(),
        ]);
        assert!(check_command(true, &mut e, None).is_ok());
        let mut webhook = script.clone();
        webhook.settings = vec![("webhook".into(), "https://x".into())];
        assert!(webhook.edit(None).unwrap_err().contains("webhook_env"));
        // With no program of its own, "servicenow" is the ServiceNow plugin:
        // its form, with its checks.
        let sn_script = PluginForm {
            kind: "command".into(),
            plugin: "servicenow".into(),
            settings: vec![("instance".into(), "http://x".into())],
            ..Default::default()
        };
        assert_eq!(sn_script.edit(None).unwrap_err(), SERVICENOW_FORM);
        let own = PluginForm {
            command: Some(vec!["pwsh".into()]),
            ..sn_script
        };
        assert!(own.edit(None).is_ok());
    }

    /// Without the flag, a page can't change where a plugin sends its
    /// credentials or which secrets it reads; other settings it can.
    #[test]
    fn destinations_need_the_flag() {
        let existing: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "servicenow",
            "instance": "https://contoso.service-now.com",
            "table": "incident",
            "min_severity": "high",
            "token_env": "SN_TOKEN",
        }))
        .unwrap();
        let form = PluginForm {
            kind: "servicenow".into(),
            instance: "https://contoso.service-now.com".into(),
            table: "incident".into(),
            min_severity: "critical".into(),
            auth: "bearer".into(),
            token_env: "SN_TOKEN".into(),
            ..Default::default()
        };
        // The severity changes: fine.
        let mut e = form.edit(Some(&existing)).unwrap();
        assert!(check_command(false, &mut e, Some(&existing)).is_ok());
        // The instance, the table, the token's variable, or the way it
        // signs in: not.
        for changed in [
            PluginForm {
                instance: "https://evil.example".into(),
                ..form.clone()
            },
            PluginForm {
                table: "sc_req_item".into(),
                ..form.clone()
            },
            PluginForm {
                token_env: "PATHWARDEN_JIRA_TOKEN".into(),
                ..form.clone()
            },
            PluginForm {
                auth: "basic".into(),
                username_env: "U".into(),
                password_env: "P".into(),
                ..form.clone()
            },
        ] {
            let mut e = changed.edit(Some(&existing)).unwrap();
            assert_eq!(
                check_command(false, &mut e, Some(&existing)),
                Err(DESTINATION_LOCKED.into())
            );
            assert!(check_command(true, &mut e, Some(&existing)).is_ok());
        }
        // Nor can it add one.
        let mut e = form.edit(None).unwrap();
        assert_eq!(
            check_command(false, &mut e, None),
            Err(DESTINATION_LOCKED.into())
        );
        // A plugin by name: its *_env and allow_insecure_http too.
        let jira: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "jira", "instance": "https://contoso.atlassian.net", "project": "SEC",
            "token_env": "PATHWARDEN_JIRA_TOKEN",
        }))
        .unwrap();
        let script = |settings: &[(&str, &str)]| PluginForm {
            kind: "command".into(),
            plugin: "jira".into(),
            settings: settings
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        };
        let same = [
            ("instance", "https://contoso.atlassian.net"),
            ("project", "SEC"),
            ("token_env", "PATHWARDEN_JIRA_TOKEN"),
        ];
        let mut e = script(&same).edit(Some(&jira)).unwrap();
        assert!(check_command(false, &mut e, Some(&jira)).is_ok());
        let mut more = same.to_vec();
        more.push(("allow_insecure_http", "true"));
        let mut e = script(&more).edit(Some(&jira)).unwrap();
        assert_eq!(
            check_command(false, &mut e, Some(&jira)),
            Err(DESTINATION_LOCKED.into())
        );
        let mut e = script(&same[..2]).edit(Some(&jira)).unwrap();
        assert_eq!(
            check_command(false, &mut e, Some(&jira)),
            Err(DESTINATION_LOCKED.into()),
            "removing token_env changes the variable it reads"
        );
        // The project its tickets go in.
        let mut moved = same.to_vec();
        moved[1] = ("project", "LEAK");
        let mut e = script(&moved).edit(Some(&jira)).unwrap();
        assert_eq!(
            check_command(false, &mut e, Some(&jira)),
            Err(DESTINATION_LOCKED.into())
        );
        assert!(check_command(true, &mut e, Some(&jira)).is_ok());
    }

    /// Without the flag, a page may change the ticketing limits and fields
    /// but not turn the resolve check off (`max_resolve_percent` 100); one
    /// already off in the file may stay off.
    #[test]
    fn the_resolve_check_stays_on_without_the_flag() {
        let existing: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "servicenow",
            "instance": "https://contoso.service-now.com",
            "table": "incident",
            "token_env": "SN_TOKEN",
        }))
        .unwrap();
        let form = |max_resolve: &str, max_create: &str| PluginForm {
            kind: "servicenow".into(),
            instance: "https://contoso.service-now.com".into(),
            table: "incident".into(),
            auth: "bearer".into(),
            token_env: "SN_TOKEN".into(),
            min_severity: "high".into(),
            max_resolve_percent: Some(max_resolve.into()),
            max_create: Some(max_create.into()),
            ..Default::default()
        };
        for fine in [("80", "500"), ("1", "1"), ("", "")] {
            let mut e = form(fine.0, fine.1).edit(Some(&existing)).unwrap();
            assert!(
                check_command(false, &mut e, Some(&existing)).is_ok(),
                "{fine:?}"
            );
        }
        for off in ["100", "100%"] {
            let mut e = form(off, "").edit(Some(&existing)).unwrap();
            assert_eq!(
                check_command(false, &mut e, Some(&existing)),
                Err(GUARD_LOCKED.into())
            );
            assert!(check_command(true, &mut e, Some(&existing)).is_ok());
        }
        // Already off in the file: kept, or turned back on.
        let off: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "servicenow",
            "instance": "https://contoso.service-now.com",
            "table": "incident",
            "token_env": "SN_TOKEN",
            "max_resolve_percent": 100,
        }))
        .unwrap();
        for v in ["100", "50"] {
            let mut e = form(v, "").edit(Some(&off)).unwrap();
            assert!(check_command(false, &mut e, Some(&off)).is_ok(), "{v}");
        }
        // Through the script form too.
        let jira: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "jira", "instance": "https://contoso.atlassian.net", "project": "SEC",
            "token_env": "PATHWARDEN_JIRA_TOKEN",
        }))
        .unwrap();
        let script = PluginForm {
            kind: "command".into(),
            plugin: "jira".into(),
            settings: vec![
                ("instance".into(), "https://contoso.atlassian.net".into()),
                ("project".into(), "SEC".into()),
                ("token_env".into(), "PATHWARDEN_JIRA_TOKEN".into()),
                ("max_resolve_percent".into(), "100".into()),
            ],
            ..Default::default()
        };
        let mut e = script.edit(Some(&jira)).unwrap();
        assert_eq!(
            check_command(false, &mut e, Some(&jira)),
            Err(GUARD_LOCKED.into())
        );
    }

    /// The Jira plugin's instance is checked by the script form too.
    #[test]
    fn the_jira_instance_is_checked() {
        let jira = |instance: &str, insecure: bool| {
            let mut settings = vec![("project".to_string(), "SEC".to_string())];
            if !instance.is_empty() {
                settings.push(("instance".into(), instance.into()));
            }
            if insecure {
                settings.push(("allow_insecure_http".into(), "true".into()));
            }
            PluginForm {
                kind: "command".into(),
                plugin: "jira".into(),
                settings,
                ..Default::default()
            }
            .edit(None)
        };
        assert!(jira("https://contoso.atlassian.net", false).is_ok());
        assert!(jira("http://localhost:8080", false).is_ok());
        assert!(jira("http://jira.contoso.com", true).is_ok());
        for bad in [
            "http://jira.contoso.com",
            "https://u:p@contoso.atlassian.net",
            r"https://contoso.atlassian.net\x",
            "ftp://x",
        ] {
            assert!(jira(bad, false).is_err(), "{bad}");
        }
        assert!(jira("", false).unwrap_err().contains("instance"));
        // A script of its own named jira is not the shipped plugin.
        let own = PluginForm {
            kind: "command".into(),
            plugin: "jira".into(),
            command: Some(vec!["pwsh".into()]),
            settings: vec![("instance".into(), "http://x".into())],
            ..Default::default()
        };
        assert!(own.edit(None).is_ok());
    }

    fn jira_form() -> PluginForm {
        PluginForm {
            kind: "jira".into(),
            instance: "https://contoso.atlassian.net".into(),
            project: "SEC".into(),
            min_severity: "High".into(),
            auth: "basic".into(),
            username_env: JIRA_USER.into(),
            token_env: JIRA_TOKEN.into(),
            set_priority: Some(true),
            fields: vec![(
                "components".into(),
                r#"[{"name": "Active Directory"}]"#.into(),
            )],
            ..Default::default()
        }
    }

    #[test]
    fn the_jira_form_becomes_an_edit() {
        let e = jira_form().edit(None).unwrap();
        assert_eq!(e.plugin, JIRA);
        assert!(e.json_fields);
        for (k, v) in [
            ("instance", "https://contoso.atlassian.net"),
            ("project", "SEC"),
            ("issue_type", "Task"),
            ("min_severity", "high"),
            ("username_env", JIRA_USER),
            ("token_env", JIRA_TOKEN),
        ] {
            assert!(e.set.contains(&(k.into(), Setting::Str(v.into()))), "{k}");
        }
        // Defaults are written as no setting.
        for k in [
            "deployment",
            "pat_env",
            "set_priority",
            "on_closed_but_present",
            "scope",
        ] {
            assert!(e.remove.contains(&k.to_string()), "{k}");
        }

        // Data Center with a personal access token, and the other choices.
        let dc = PluginForm {
            deployment: "data_center".into(),
            auth: "pat".into(),
            pat_env: JIRA_PAT.into(),
            set_priority: Some(false),
            on_closed_but_present: "comment".into(),
            close_transition: "Close Issue".into(),
            ..jira_form()
        };
        let e = dc.edit(None).unwrap();
        assert!(e
            .set
            .contains(&("deployment".into(), Setting::Str("data_center".into()))));
        assert!(e
            .set
            .contains(&("pat_env".into(), Setting::Str(JIRA_PAT.into()))));
        assert!(e
            .set
            .contains(&("set_priority".into(), Setting::Bool(false))));
        assert!(e.set.contains(&(
            "close_transition".into(),
            Setting::Str("Close Issue".into())
        )));
        assert!(e.remove.contains(&"token_env".to_string()));

        // Refused: a personal access token on Cloud, a bad project key, a
        // reserved or secret field, broken JSON, a quote in a transition.
        for (bad, why) in [
            (
                PluginForm {
                    auth: "pat".into(),
                    pat_env: JIRA_PAT.into(),
                    ..jira_form()
                },
                "Data Center",
            ),
            (
                PluginForm {
                    project: "sec".into(),
                    ..jira_form()
                },
                "Project key",
            ),
            (
                PluginForm {
                    fields: vec![("labels".into(), "x".into())],
                    ..jira_form()
                },
                "itself",
            ),
            (
                PluginForm {
                    fields: vec![("api_token".into(), "x".into())],
                    ..jira_form()
                },
                "secrets",
            ),
            (
                PluginForm {
                    fields: vec![("components".into(), "[{".into())],
                    ..jira_form()
                },
                "JSON",
            ),
            (
                PluginForm {
                    close_transition: "Do\"ne".into(),
                    ..jira_form()
                },
                "quotes",
            ),
            (
                PluginForm {
                    instance: "http://jira.contoso.com".into(),
                    ..jira_form()
                },
                "https",
            ),
            (
                PluginForm {
                    instance: String::new(),
                    ..jira_form()
                },
                "Jira address",
            ),
        ] {
            let err = bad.edit(None).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn safety_limits_on_both_ticketing_forms() {
        let sn = PluginForm {
            kind: "servicenow".into(),
            instance: "https://contoso.service-now.com".into(),
            table: "incident".into(),
            min_severity: "high".into(),
            auth: "basic".into(),
            username_env: SN_USER.into(),
            password_env: SN_PASSWORD.into(),
            ..Default::default()
        };
        for form in [sn, jira_form()] {
            let with = |c: &str, r: &str| PluginForm {
                max_create: Some(c.into()),
                max_resolve_percent: Some(r.into()),
                ..form.clone()
            };
            let e = with("25", "80%").edit(None).unwrap();
            assert!(e.set.contains(&("max_create".into(), Setting::Int(25))));
            assert!(e
                .set
                .contains(&("max_resolve_percent".into(), Setting::Int(80))));
            // The defaults, or nothing: the plugin's default.
            let e = with("100", "").edit(None).unwrap();
            assert!(e.remove.contains(&"max_create".to_string()));
            assert!(e.remove.contains(&"max_resolve_percent".to_string()));
            // Not given (an older page): the file's value stays.
            let e = form.edit(None).unwrap();
            assert!(!e.remove.iter().any(|k| k.starts_with("max_")));
            assert!(!e.set.iter().any(|(k, _)| k.starts_with("max_")));
            for (c, r) in [("0", "50"), ("ten", "50"), ("100", "101"), ("100", "0")] {
                assert!(with(c, r).edit(None).is_err(), "{c} {r}");
            }
        }
    }

    /// Jira's JSON field values are written as TOML arrays and tables, so
    /// the plugin gets them as JSON again.
    #[test]
    fn jira_fields_are_written_as_json() {
        let mut d = crate::config_edit::ConfigDoc::template();
        let mut e = jira_form().edit(None).unwrap();
        e.fields
            .as_mut()
            .unwrap()
            .push(("customfield_10010".into(), "Identity team".into()));
        d.upsert_output(None, None, &e).unwrap();
        let config = crate::config::Config::parse(&d.text()).unwrap();
        let o = &config.outputs[0];
        assert!(is_jira(o));
        assert_eq!(
            o.settings["fields"]["components"],
            serde_json::json!([{ "name": "Active Directory" }])
        );
        assert_eq!(o.settings["fields"]["customfield_10010"], "Identity team");
        assert_eq!(describe(o), "Jira · SEC at https://contoso.atlassian.net");
        assert!(!test_needs_confirmation(o));
        // (In file order or sorted, depending on serde_json's features.)
        let mut names = env_names(o);
        names.sort();
        assert_eq!(names, vec![JIRA_TOKEN.to_string(), JIRA_USER.to_string()]);
    }

    #[test]
    fn only_the_shipped_plugin_tests_without_asking() {
        let sn = OutputConfig {
            plugin: SERVICENOW.into(),
            command: None,
            settings: Default::default(),
        };
        assert!(!test_needs_confirmation(&sn));
        let script = OutputConfig {
            plugin: SERVICENOW.into(),
            command: Some(vec!["pwsh".into()]),
            settings: Default::default(),
        };
        assert!(test_needs_confirmation(&script));
    }
}
