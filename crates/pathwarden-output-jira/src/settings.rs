//! Plugin settings: the `[[output]]` table from pathwarden.toml, passed as JSON
//! in `PATHWARDEN_OUTPUT_SETTINGS` (or a file with `--settings`). Secrets are
//! never in settings, only the names of the environment variables holding
//! them. Every value that ends up in a JQL query or a URL path is checked
//! against a strict character set first.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::{Map, Value};

/// Jira Cloud (REST v3, Atlassian Document Format) or Data Center / Server
/// (REST v2, plain text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    #[default]
    Cloud,
    #[serde(alias = "server", alias = "data-center", alias = "dc")]
    DataCenter,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// e.g. `https://contoso.atlassian.net` or `https://jira.contoso.com`
    pub instance: String,
    pub deployment: Deployment,
    /// Project key, e.g. `SEC`.
    pub project: String,
    /// Issue type name for new issues.
    pub issue_type: String,
    /// Cloud: the Atlassian account e-mail. Basic auth with `token_env`.
    pub username_env: String,
    /// Cloud: an API token. Data Center: a password (basic auth).
    pub token_env: String,
    /// Data Center: a personal access token (bearer auth); when set,
    /// `username_env` / `token_env` are not used.
    pub pat_env: Option<String>,
    /// Lowest severity that gets a new issue.
    pub min_severity: String,
    /// Only create issues for these categories (`attack_path`, `hygiene`).
    pub categories: Option<Vec<String>>,
    /// Extra fields set on every created issue (`components`, custom fields).
    pub fields: Map<String, Value>,
    /// Set the priority from the severity (the field must be on the
    /// project's create screen).
    pub set_priority: bool,
    /// Severity -> priority name; merged over the defaults.
    pub priority_map: BTreeMap<String, String>,
    /// Transition (by name) that closes an issue; default: the first one
    /// leading to a "done" status.
    pub close_transition: Option<String>,
    /// Transition (by name) that reopens an issue; default: the first one
    /// leading to a "to do" status, else an "in progress" one.
    pub reopen_transition: Option<String>,
    /// Resolution set when closing, for workflows whose close screen asks
    /// for one (e.g. "Done").
    pub close_resolution: Option<String>,
    /// `reopen` (default), `comment` or `ignore`.
    pub on_closed_but_present: String,
    /// Close issues for findings that became accepted risks.
    pub resolve_suppressed: bool,
    /// Leave out findings that already have an open record from a finding
    /// action (an "Open a ticket" button): no new ticket, no reopened one.
    pub skip_action_tickets: bool,
    pub dry_run: bool,
    /// Separates deployments sharing one project: issues are labelled
    /// `pathwarden-<scope>` instead of `pathwarden`.
    pub scope: Option<String>,
    pub max_resolve_percent: f64,
    pub max_create: usize,
    pub allow_insecure_http: bool,
    /// Resolutions that mean "decided, leave it": such issues are never
    /// reopened or commented on.
    pub respect_resolutions: Vec<String>,
    /// Only issues created by this account (Cloud: account ID; Data Center:
    /// user name) are read or changed. Matched on Jira's `creator`, which
    /// unlike `reporter` can't be edited.
    pub created_by: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            instance: String::new(),
            deployment: Deployment::Cloud,
            project: String::new(),
            issue_type: "Task".into(),
            username_env: "PATHWARDEN_JIRA_USER".into(),
            token_env: "PATHWARDEN_JIRA_TOKEN".into(),
            pat_env: None,
            min_severity: "medium".into(),
            categories: None,
            fields: Map::new(),
            set_priority: true,
            priority_map: BTreeMap::new(),
            close_transition: None,
            reopen_transition: None,
            close_resolution: None,
            on_closed_but_present: "reopen".into(),
            resolve_suppressed: true,
            skip_action_tickets: true,
            dry_run: false,
            scope: None,
            max_resolve_percent: 50.0,
            max_create: 100,
            allow_insecure_http: false,
            respect_resolutions: [
                "Won't Do",
                "Won't Fix",
                "Duplicate",
                "Cannot Reproduce",
                "Declined",
                "Risk Accepted",
            ]
            .map(String::from)
            .to_vec(),
            created_by: None,
        }
    }
}

/// What to do with a closed issue whose finding is still present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnClosed {
    Reopen,
    Comment,
    Ignore,
}

pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Checks the instance URL the way the HTTP client will read it: https only
/// (plain http only for loopback or with `allow_insecure_http`), no
/// credentials, no backslash, no query or fragment. Errors never quote it.
fn check_instance(instance: &str, allow_insecure_http: bool) -> Result<()> {
    if instance.is_empty() {
        bail!("settings: `instance` is required (e.g. \"https://contoso.atlassian.net\")");
    }
    if instance.contains('\\') {
        bail!("settings: `instance` must not contain a backslash");
    }
    if instance
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("settings: `instance` must not contain spaces or control characters");
    }
    let Ok(url) = url::Url::parse(instance) else {
        bail!("settings: `instance` must be a URL starting with https://");
    };
    if !url.username().is_empty() || url.password().is_some() {
        bail!(
            "settings: `instance` must not contain a user name or password; put the credentials \
             in the environment variables named by username_env and token_env (or pat_env)"
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("settings: `instance` must not have a query (?) or fragment (#)");
    }
    let Some(host) = url.host() else {
        bail!("settings: `instance` has no host name");
    };
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&host) || allow_insecure_http => {}
        "http" => bail!(
            "settings: `instance` must use https:// (credentials would be sent unencrypted); \
             set allow_insecure_http = true only for a test instance you control"
        ),
        _ => bail!("settings: `instance` must be a URL starting with https://"),
    }
    Ok(())
}

/// A Jira project key: an uppercase letter, then uppercase letters, digits
/// or `_`; at most 30 characters (Jira's own limits are narrower).
pub fn valid_project(s: &str) -> bool {
    (1..=30).contains(&s.len())
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// An issue key: `PROJECT-123`.
pub fn valid_issue_key(s: &str) -> bool {
    match s.rsplit_once('-') {
        Some((project, number)) => {
            valid_project(project)
                && (1..=12).contains(&number.len())
                && number.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// A Cloud account ID (`5b10a2844c20165700ede21g`, `712020:1a2b...`) or a
/// Data Center user name: safe inside a quoted JQL string.
pub fn valid_account(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b':'))
}

/// 1-40 characters of `[A-Za-z0-9._-]`.
pub fn valid_scope(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A name (issue type, transition, resolution, priority): no quotes,
/// backslashes or control characters.
fn valid_name(s: &str) -> bool {
    (1..=100).contains(&s.trim().len())
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '\''))
}

impl Settings {
    pub fn parse(json: &str) -> Result<Self> {
        let mut s: Settings = serde_json::from_str(json)?;
        s.instance = s.instance.trim().to_string();
        s.project = s.project.trim().to_string();
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<()> {
        check_instance(&self.instance, self.allow_insecure_http)?;
        if !valid_project(&self.project) {
            bail!(
                "settings: `project` must be a Jira project key (uppercase letters, digits, '_'), got {:?}",
                self.project
            );
        }
        if !valid_name(&self.issue_type) {
            bail!(
                "settings: `issue_type` must be an issue type name, got {:?}",
                self.issue_type
            );
        }
        for (key, value) in [
            ("close_transition", &self.close_transition),
            ("reopen_transition", &self.reopen_transition),
            ("close_resolution", &self.close_resolution),
        ] {
            if let Some(v) = value {
                if !valid_name(v) {
                    bail!("settings: `{key}` must be a name without quotes or backslashes");
                }
            }
        }
        if self.priority_map.values().any(|p| !valid_name(p)) {
            bail!("settings: `priority_map` values must be priority names");
        }
        if let Some(user) = &self.created_by {
            if !valid_account(user) {
                bail!(
                    "settings: `created_by` must be a Jira account ID or user name (letters, digits, '.', '_', '-', '@', ':')"
                );
            }
        }
        if let Some(scope) = &self.scope {
            if !valid_scope(scope) {
                bail!(
                    "settings: `scope` must be 1-40 characters of letters, digits, '.', '_' or '-', got {scope:?}"
                );
            }
        }
        if !(0.0..=100.0).contains(&self.max_resolve_percent) {
            bail!("settings: `max_resolve_percent` must be between 0 and 100");
        }
        if !matches!(
            self.min_severity.to_ascii_lowercase().as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ) {
            bail!("settings: `min_severity` must be one of critical, high, medium, low, info");
        }
        for reserved in ["project", "issuetype", "summary", "description", "labels"] {
            if self.fields.contains_key(reserved) {
                bail!("settings: `fields` must not set `{reserved}`; the plugin sets it");
            }
        }
        self.on_closed()?;
        Ok(())
    }

    pub fn on_closed(&self) -> Result<OnClosed> {
        Ok(match self.on_closed_but_present.to_ascii_lowercase().as_str() {
            "reopen" => OnClosed::Reopen,
            "comment" => OnClosed::Comment,
            "ignore" => OnClosed::Ignore,
            other => bail!("settings: `on_closed_but_present` must be reopen, comment or ignore (got {other:?})"),
        })
    }

    /// The label on every issue of this deployment.
    pub fn marker(&self) -> String {
        match &self.scope {
            Some(scope) => format!("pathwarden-{scope}"),
            None => "pathwarden".to_string(),
        }
    }

    /// `https://host/rest/api/3` (Cloud) or `.../rest/api/2` (Data Center).
    pub fn api_base(&self) -> String {
        let version = match self.deployment {
            Deployment::Cloud => 3,
            Deployment::DataCenter => 2,
        };
        format!("{}/rest/api/{version}", self.instance.trim_end_matches('/'))
    }

    /// Whether a closed issue with this resolution was deliberately closed.
    pub fn respects(&self, resolution: Option<&str>) -> bool {
        resolution.is_some_and(|r| {
            let r = r.trim();
            !r.is_empty()
                && self
                    .respect_resolutions
                    .iter()
                    .any(|x| x.trim().eq_ignore_ascii_case(r))
        })
    }

    /// The priority name for a severity: configured, else Jira's defaults.
    pub fn priority_for(&self, severity: &str) -> String {
        let sev = severity.to_ascii_lowercase();
        if let Some(p) = self.priority_map.get(&sev) {
            return p.clone();
        }
        match sev.as_str() {
            "critical" => "Highest",
            "high" => "High",
            "medium" => "Medium",
            "low" => "Low",
            _ => "Lowest",
        }
        .to_string()
    }

    /// Whether a new finding of this severity and category gets an issue.
    pub fn wants(&self, severity: &str, category: &str) -> bool {
        severity_rank(severity) >= severity_rank(&self.min_severity)
            && self
                .categories
                .as_ref()
                .is_none_or(|c| c.iter().any(|x| x.eq_ignore_ascii_case(category)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid settings with `extra` (JSON members) merged over them.
    fn parse(extra: &str) -> Result<Settings> {
        let mut base = serde_json::json!({
            "instance": "https://contoso.atlassian.net",
            "project": "SEC",
        });
        let extra: Value = serde_json::from_str(&format!("{{{extra}}}")).unwrap();
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        Settings::parse(&base.to_string())
    }

    #[test]
    fn defaults() {
        let s = parse("").unwrap();
        assert_eq!(s.deployment, Deployment::Cloud);
        assert_eq!(s.issue_type, "Task");
        assert_eq!(s.username_env, "PATHWARDEN_JIRA_USER");
        assert_eq!(s.token_env, "PATHWARDEN_JIRA_TOKEN");
        assert_eq!(s.marker(), "pathwarden");
        assert_eq!(s.api_base(), "https://contoso.atlassian.net/rest/api/3");
        assert_eq!(s.priority_for("critical"), "Highest");
        assert_eq!(s.priority_for("info"), "Lowest");
        assert!(s.set_priority && s.resolve_suppressed && !s.dry_run);
        assert_eq!(s.on_closed().unwrap(), OnClosed::Reopen);
        assert!(s.respects(Some("won't do")));
        assert!(!s.respects(Some("Done")));
    }

    #[test]
    fn data_center_and_overrides() {
        let s = parse(
            r#""deployment":"data_center","scope":"lab","priority_map":{"critical":"Blocker"}"#,
        )
        .unwrap();
        assert_eq!(s.deployment, Deployment::DataCenter);
        assert!(s.api_base().ends_with("/rest/api/2"));
        assert_eq!(s.marker(), "pathwarden-lab");
        assert_eq!(s.priority_for("Critical"), "Blocker");
        assert_eq!(s.priority_for("high"), "High");
        assert!(parse(r#""deployment":"server""#).is_ok());
    }

    #[test]
    fn validation() {
        for bad in [
            r#""project":"sec""#,
            r#""project":"SEC\" OR project = \"X""#,
            r#""issue_type":"Task\" OR 1=1""#,
            r#""created_by":"a\" OR creator is not EMPTY""#,
            r#""scope":"a b""#,
            r#""min_severity":"urgent""#,
            r#""on_closed_but_present":"panic""#,
            r#""max_resolve_percent":150"#,
            r#""fields":{"labels":["x"]}"#,
            r#""close_transition":"Done\"""#,
        ] {
            assert!(parse(bad).is_err(), "accepted {bad}");
        }
        assert!(Settings::parse(r#"{"project":"SEC"}"#).is_err());
        assert!(Settings::parse(r#"{"instance":"https://x"}"#).is_err());
        assert!(parse(r#""created_by":"712020:1a2b-3c4d""#).is_ok());
    }

    #[test]
    fn https_required_and_no_credentials_in_the_url() {
        for bad in [
            "http://contoso.atlassian.net",
            "http://example.invalid\\@localhost",
            "https://x/?a=1",
            "ftp://localhost",
        ] {
            let json = format!(
                r#"{{"instance":{},"project":"SEC"}}"#,
                serde_json::json!(bad)
            );
            assert!(Settings::parse(&json).is_err(), "accepted {bad}");
        }
        for ok in [
            "http://127.0.0.1:8080",
            "http://localhost/",
            "https://jira.contoso.com/jira",
        ] {
            let json = format!(
                r#"{{"instance":{},"project":"SEC"}}"#,
                serde_json::json!(ok)
            );
            assert!(Settings::parse(&json).is_ok(), "rejected {ok}");
        }
        let e = format!(
            "{:#}",
            Settings::parse(r#"{"instance":"https://me:hunter2@x.atlassian.net","project":"SEC"}"#)
                .unwrap_err()
        );
        assert!(
            e.contains("user name or password") && !e.contains("hunter2"),
            "{e}"
        );
    }

    #[test]
    fn issue_keys() {
        assert!(valid_issue_key("SEC-1"));
        assert!(valid_issue_key("AB_2-12345"));
        for bad in ["SEC", "sec-1", "SEC-", "SEC-1/../x", "-1", "SEC-1a"] {
            assert!(!valid_issue_key(bad), "accepted {bad}");
        }
    }
}
