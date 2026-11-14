//! Plugin settings: the `[[output]]` table from pathwarden.toml, passed as JSON
//! in `PATHWARDEN_OUTPUT_SETTINGS` (or a file with `--settings`). Secrets are
//! never in settings, only the names of the environment variables holding them.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::reconcile::CORRELATION_DISPLAY;

#[derive(Debug, Clone, Deserialize)]
pub struct Impact {
    pub urgency: String,
    pub impact: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// e.g. `https://contoso.service-now.com`
    pub instance: String,
    /// `incident` (default) or `sc_req_item`.
    pub table: String,
    pub username_env: String,
    pub password_env: String,
    /// When set, bearer token auth is used instead of basic auth.
    pub token_env: Option<String>,
    /// Lowest severity that gets a new ticket.
    pub min_severity: String,
    /// Only create tickets for these categories (`attack_path`, `hygiene`).
    pub categories: Option<Vec<String>>,
    /// Extra fields set on every created ticket.
    pub fields: Map<String, Value>,
    /// Severity -> urgency / impact; merged over the defaults.
    pub severity_map: BTreeMap<String, Impact>,
    /// Fields set when resolving; `{message}` is replaced. Per-table default.
    pub resolve_fields: Option<Map<String, Value>>,
    /// Fields set when reopening; per-table default.
    pub reopen_fields: Option<Map<String, Value>>,
    /// `reopen` (default), `comment` or `ignore`.
    pub on_closed_but_present: String,
    /// Resolve tickets for findings that became accepted risks.
    pub resolve_suppressed: bool,
    pub dry_run: bool,
    /// Separates deployments sharing one instance and table: tickets are
    /// marked `Pathwarden:<scope>`, and only tickets with exactly this marker
    /// are ever read or changed.
    pub scope: Option<String>,
    /// Refuse to resolve anything when a run would resolve more than this
    /// percentage of the active tickets (100 disables the guard).
    pub max_resolve_percent: f64,
    /// Refuse to create anything when a run would create more tickets than this.
    pub max_create: usize,
    /// Allow a plain `http://` instance (credentials would travel unencrypted).
    pub allow_insecure_http: bool,
    /// Close codes that mean "decided, leave it": such tickets are never
    /// reopened or commented on.
    pub respect_close_codes: Vec<String>,
    /// Only tickets created by this ServiceNow account (`sys_created_by`,
    /// normally the integration user) are read or changed. Without it, any
    /// ticket carrying this deployment's correlation marker is trusted, and
    /// tickets someone else created are only warned about.
    pub created_by: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            instance: String::new(),
            table: "incident".into(),
            username_env: "PATHWARDEN_SN_USER".into(),
            password_env: "PATHWARDEN_SN_PASSWORD".into(),
            token_env: None,
            min_severity: "medium".into(),
            categories: None,
            fields: Map::new(),
            severity_map: BTreeMap::new(),
            resolve_fields: None,
            reopen_fields: None,
            on_closed_but_present: "reopen".into(),
            resolve_suppressed: true,
            dry_run: false,
            scope: None,
            max_resolve_percent: 50.0,
            max_create: 100,
            allow_insecure_http: false,
            respect_close_codes: [
                "Won't Fix",
                "Not Solved (Not Reproducible)",
                "Duplicate",
                "Accepted Risk",
                "Risk Accepted",
            ]
            .map(String::from)
            .to_vec(),
            created_by: None,
        }
    }
}

/// What to do with a closed ticket whose finding is still present.
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

fn obj(pairs: &[(&str, &str)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
        .collect()
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Checks the instance URL the way the HTTP client will read it: parsed by
/// the `url` crate (as ureq does), https only (plain http only for loopback
/// or with `allow_insecure_http`), no credentials in it, no backslashes
/// (which some parsers read as `/` and others don't).
fn check_instance(instance: &str, allow_insecure_http: bool) -> Result<()> {
    if instance.is_empty() {
        bail!("settings: `instance` is required (e.g. \"https://contoso.service-now.com\")");
    }
    // Errors below never quote the URL: it may hold a password.
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
             in the environment variables named by username_env and password_env (or token_env)"
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

/// A ServiceNow user name, safe inside an encoded query.
pub fn valid_user_name(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
}

/// `^[a-z0-9_]+$`
pub fn valid_table(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// 1-40 characters of `[A-Za-z0-9._-]`.
pub fn valid_scope(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Settings {
    pub fn parse(json: &str) -> Result<Self> {
        let mut s: Settings = serde_json::from_str(json)?;
        s.table = s.table.trim().to_string();
        s.instance = s.instance.trim().to_string();
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<()> {
        check_instance(self.instance.trim(), self.allow_insecure_http)?;
        if let Some(user) = &self.created_by {
            if !valid_user_name(user) {
                bail!(
                    "settings: `created_by` must be a ServiceNow user name (letters, digits, '.', '_', '-', '@')"
                );
            }
        }
        if !valid_table(self.table.trim()) {
            bail!(
                "settings: `table` must be a table name of lowercase letters, digits and underscores \
                 (e.g. incident, sc_req_item), got {:?}",
                self.table
            );
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

    /// The `correlation_display` marker on this deployment's tickets.
    pub fn correlation_display(&self) -> String {
        match &self.scope {
            Some(scope) => format!("{CORRELATION_DISPLAY}:{scope}"),
            None => CORRELATION_DISPLAY.to_string(),
        }
    }

    pub fn base_url(&self) -> String {
        format!(
            "{}/api/now/table/{}",
            self.instance.trim().trim_end_matches('/'),
            self.table.trim()
        )
    }

    /// Whether a closed ticket with this close code was deliberately closed.
    pub fn respects(&self, close_code: Option<&str>) -> bool {
        close_code.is_some_and(|c| {
            let c = c.trim();
            !c.is_empty()
                && self
                    .respect_close_codes
                    .iter()
                    .any(|r| r.trim().eq_ignore_ascii_case(c))
        })
    }

    /// Urgency and impact for a severity: configured value, else the default.
    pub fn impact_for(&self, severity: &str) -> (String, String) {
        let sev = severity.to_ascii_lowercase();
        if let Some(i) = self.severity_map.get(&sev) {
            return (i.urgency.clone(), i.impact.clone());
        }
        let (u, i) = match sev.as_str() {
            "critical" => ("1", "1"),
            "high" => ("2", "1"),
            "medium" => ("2", "2"),
            _ => ("3", "3"),
        };
        (u.into(), i.into())
    }

    pub fn resolve_fields(&self) -> Map<String, Value> {
        self.resolve_fields
            .clone()
            .unwrap_or_else(|| match self.table.trim() {
                "incident" => obj(&[
                    ("state", "6"),
                    ("close_code", "Resolution provided"),
                    ("close_notes", "{message}"),
                ]),
                _ => obj(&[("state", "3"), ("close_notes", "{message}")]),
            })
    }

    pub fn reopen_fields(&self) -> Map<String, Value> {
        self.reopen_fields
            .clone()
            .unwrap_or_else(|| match self.table.trim() {
                "incident" => obj(&[("state", "2")]),
                _ => obj(&[("state", "1")]),
            })
    }

    /// Whether a new finding of this severity and category gets a ticket.
    pub fn wants(&self, severity: &str, category: &str) -> bool {
        severity_rank(severity) >= severity_rank(&self.min_severity)
            && self
                .categories
                .as_ref()
                .is_none_or(|c| c.iter().any(|x| x.eq_ignore_ascii_case(category)))
    }
}

/// Replaces `{message}` in every string value.
pub fn fill(fields: &Map<String, Value>, message: &str) -> Map<String, Value> {
    fields
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) => Value::String(s.replace("{message}", message)),
                other => other.clone(),
            };
            (k.clone(), v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let s = Settings::parse(
            r#"{"instance":"https://contoso.service-now.com/","plugin":"servicenow"}"#,
        )
        .unwrap();
        assert_eq!(s.table, "incident");
        assert_eq!(s.min_severity, "medium");
        assert_eq!(s.username_env, "PATHWARDEN_SN_USER");
        assert_eq!(s.password_env, "PATHWARDEN_SN_PASSWORD");
        assert!(s.resolve_suppressed);
        assert!(!s.dry_run);
        assert_eq!(s.max_resolve_percent, 50.0);
        assert_eq!(s.max_create, 100);
        assert_eq!(s.correlation_display(), "Pathwarden");
        assert_eq!(s.on_closed().unwrap(), OnClosed::Reopen);
        assert_eq!(
            s.base_url(),
            "https://contoso.service-now.com/api/now/table/incident"
        );
        assert_eq!(s.impact_for("Critical"), ("1".into(), "1".into()));
        assert_eq!(s.impact_for("high"), ("2".into(), "1".into()));
        assert_eq!(s.impact_for("medium"), ("2".into(), "2".into()));
        assert_eq!(s.impact_for("low"), ("3".into(), "3".into()));
        assert_eq!(s.resolve_fields()["state"], "6");
        assert_eq!(s.resolve_fields()["close_code"], "Resolution provided");
        assert_eq!(s.reopen_fields()["state"], "2");
    }

    #[test]
    fn ritm_defaults_and_overrides() {
        let s = Settings::parse(
            r#"{"instance":"https://x.service-now.com","table":"sc_req_item",
                "severity_map":{"high":{"urgency":"1","impact":"2"}},
                "reopen_fields":{"state":"2","stage":"fulfillment"}}"#,
        )
        .unwrap();
        assert_eq!(s.resolve_fields()["state"], "3");
        assert_eq!(s.reopen_fields()["stage"], "fulfillment");
        assert_eq!(s.impact_for("high"), ("1".into(), "2".into()));
        assert_eq!(s.impact_for("critical"), ("1".into(), "1".into()));
    }

    #[test]
    fn validation() {
        assert!(Settings::parse("{}").is_err());
        assert!(Settings::parse(r#"{"instance":"contoso.service-now.com"}"#).is_err());
        assert!(Settings::parse(r#"{"instance":"https://x","min_severity":"urgent"}"#).is_err());
        assert!(
            Settings::parse(r#"{"instance":"https://x","on_closed_but_present":"panic"}"#).is_err()
        );
        assert!(Settings::parse(r#"{"instance":"https://x","max_resolve_percent":150}"#).is_err());
    }

    #[test]
    fn https_required_except_loopback_or_explicit_opt_in() {
        assert!(Settings::parse(r#"{"instance":"http://contoso.service-now.com"}"#).is_err());
        assert!(
            Settings::parse(r#"{"instance":"http://user@evil.com@127.0.0.1.evil.com"}"#).is_err()
        );
        // L3: a backslash made the check see `localhost` while the HTTP
        // client sent the request, with credentials, to example.invalid.
        for bad in [
            r#"{"instance":"http://example.invalid\\@localhost"}"#,
            r#"{"instance":"https://example.invalid\\@localhost"}"#,
            r#"{"instance":"http://localhost.example.invalid"}"#,
            r#"{"instance":"http://127.0.0.2.nip.io"}"#,
            r#"{"instance":"ftp://localhost"}"#,
            r#"{"instance":"https://"}"#,
            r#"{"instance":"https://x/?a=1"}"#,
            r#"{"instance":"https://x y"}"#,
        ] {
            assert!(Settings::parse(bad).is_err(), "accepted {bad}");
        }
        for ok in [
            r#"{"instance":"http://127.0.0.1:8765"}"#,
            r#"{"instance":"http://127.0.0.3:8765"}"#,
            r#"{"instance":"http://localhost/"}"#,
            r#"{"instance":"http://[::1]:8080"}"#,
            r#"{"instance":"http://sn.lab.local","allow_insecure_http":true}"#,
        ] {
            assert!(Settings::parse(ok).is_ok(), "rejected {ok}");
        }
    }

    /// L4: credentials in the URL are refused, and the error never repeats them.
    #[test]
    fn credentials_in_the_instance_are_refused() {
        for bad in [
            r#"{"instance":"https://user:hunter2@contoso.service-now.com"}"#,
            r#"{"instance":"https://user@contoso.service-now.com"}"#,
            r#"{"instance":"http://user:hunter2@127.0.0.1:9"}"#,
        ] {
            let e = format!("{:#}", Settings::parse(bad).unwrap_err());
            assert!(e.contains("user name or password"), "{e}");
            assert!(!e.contains("hunter2") && !e.contains("user@"), "{e}");
        }
    }

    #[test]
    fn created_by_is_validated() {
        let s =
            Settings::parse(r#"{"instance":"https://x","created_by":"svc.pathwarden"}"#).unwrap();
        assert_eq!(s.created_by.as_deref(), Some("svc.pathwarden"));
        assert!(
            Settings::parse(r#"{"instance":"https://x","created_by":"a^ORactive=true"}"#).is_err()
        );
    }

    #[test]
    fn table_names_are_validated_and_trimmed() {
        let s = Settings::parse(r#"{"instance":"https://x","table":" incident "}"#).unwrap();
        assert_eq!(s.table, "incident");
        assert_eq!(
            s.resolve_fields()["state"],
            "6",
            "trimmed table keeps incident defaults"
        );
        for bad in [
            "incident/../../v1/x?q=#",
            "Incident",
            "inc ident",
            "",
            "sc-req-item",
        ] {
            let json = format!(
                r#"{{"instance":"https://x","table":{}}}"#,
                serde_json::json!(bad)
            );
            assert!(Settings::parse(&json).is_err(), "accepted table {bad:?}");
        }
    }

    #[test]
    fn scope_marks_and_validates() {
        let s = Settings::parse(r#"{"instance":"https://x","scope":"prod-forest"}"#).unwrap();
        assert_eq!(s.correlation_display(), "Pathwarden:prod-forest");
        for bad in [
            "",
            "has space",
            "a^b",
            "x".repeat(41).as_str(),
            "sémantique",
        ] {
            let json = format!(
                r#"{{"instance":"https://x","scope":{}}}"#,
                serde_json::json!(bad)
            );
            assert!(Settings::parse(&json).is_err(), "accepted scope {bad:?}");
        }
    }

    #[test]
    fn respected_close_codes() {
        let s = Settings::parse(r#"{"instance":"https://x"}"#).unwrap();
        assert!(s.respects(Some("won't fix")));
        assert!(s.respects(Some(" Duplicate ")));
        assert!(!s.respects(Some("Resolution provided")));
        assert!(!s.respects(Some("")));
        assert!(!s.respects(None));
    }

    #[test]
    fn severity_and_category_filter() {
        let mut s = Settings::parse(r#"{"instance":"https://x"}"#).unwrap();
        assert!(s.wants("critical", "hygiene"));
        assert!(s.wants("medium", "attack_path"));
        assert!(!s.wants("low", "attack_path"));
        s.categories = Some(vec!["attack_path".into()]);
        assert!(!s.wants("critical", "hygiene"));
        assert!(s.wants("high", "attack_path"));
    }

    #[test]
    fn placeholder() {
        let f = obj(&[("close_notes", "Done: {message}"), ("state", "6")]);
        let out = fill(&f, "gone");
        assert_eq!(out["close_notes"], "Done: gone");
        assert_eq!(out["state"], "6");
    }
}
