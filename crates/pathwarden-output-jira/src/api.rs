//! The Jira REST API, through `ureq` (rustls with the operating system's
//! certificate store, proxy from HTTPS_PROXY / HTTP_PROXY).
//!
//! - Cloud: REST v3. Search with `POST /rest/api/3/search/jql` (paged by
//!   `nextPageToken`), text as Atlassian Document Format, basic auth with
//!   an account e-mail and API token.
//! - Data Center / Server: REST v2. Search with `POST /rest/api/2/search`
//!   (paged by `startAt`), plain text, basic auth or a personal access
//!   token (bearer).

use std::io::Read;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::reconcile::{fingerprint_of, Issue, NewIssue};
use crate::settings::{valid_issue_key, Deployment, Settings};

const PAGE: usize = 100;
/// More pages than this means something is wrong (a server that never says
/// it is done); stop rather than loop.
const MAX_PAGES: usize = 1000;
/// Jira Cloud refuses descriptions over 32,767 characters.
const TEXT_MAX: usize = 30_000;
/// The most of an answer read: a page of 100 issues is far smaller.
const MAX_RESPONSE: u64 = 32 << 20;
/// The most of an error answer read, for its messages.
const MAX_ERROR_BODY: u64 = 64 << 10;

pub struct Client {
    agent: ureq::Agent,
    base: String,
    auth: Zeroizing<String>,
    deployment: Deployment,
    project: String,
    marker: String,
    created_by: Option<String>,
}

/// Which way a transition goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Done,
    Open,
}

impl Client {
    pub fn new(settings: &Settings) -> Result<Self> {
        // The secrets and every copy made here are zeroed when dropped; ureq's
        // own copy of the header, and the environment, are out of reach.
        let auth = match &settings.pat_env {
            Some(var) => {
                let token = Zeroizing::new(secret(var)?);
                Zeroizing::new(format!("Bearer {}", *token))
            }
            None => {
                let user = Zeroizing::new(secret(&settings.username_env)?);
                let pass = Zeroizing::new(secret(&settings.token_env)?);
                let pair = Zeroizing::new(format!("{}:{}", *user, *pass));
                let encoded = Zeroizing::new(base64(pair.as_bytes()));
                Zeroizing::new(format!("Basic {}", *encoded))
            }
        };
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
            .timeout(Duration::from_secs(90))
            .try_proxy_from_env(env_proxy_for(&settings.instance))
            // Never follow a redirect: it could carry the Authorization
            // header to another host.
            .redirects(0)
            .build();
        Ok(Client {
            agent,
            base: settings.api_base(),
            auth,
            deployment: settings.deployment,
            project: settings.project.clone(),
            marker: settings.marker(),
            created_by: settings.created_by.clone(),
        })
    }
}

/// Whether the proxy from the environment (`HTTPS_PROXY`, `HTTP_PROXY`,
/// `ALL_PROXY`) is used for `instance`: never for a loopback address or a
/// plain `http://` instance, whose Authorization header the proxy would get
/// in clear, nor for a host `NO_PROXY` names (ureq doesn't read it).
pub(crate) fn env_proxy_for(instance: &str) -> bool {
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    env_proxy_with(instance, &no_proxy)
}

fn env_proxy_with(instance: &str, no_proxy: &str) -> bool {
    let Ok(url) = url::Url::parse(instance.trim()) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(url::Host::Ipv4(a)) if !a.is_loopback() => a.to_string(),
        Some(url::Host::Ipv6(a)) if !a.is_loopback() => a.to_string(),
        _ => return false,
    };
    if host == "localhost" || host.ends_with(".localhost") {
        return false;
    }
    !no_proxy
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| {
            if e == "*" {
                return true;
            }
            // A port on the entry is ignored; an IPv6 entry is kept whole.
            let e = match e.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => {
                    h.to_string()
                }
                _ => e.trim_start_matches('[').trim_end_matches(']').to_string(),
            };
            let e = e.trim_start_matches("*.").trim_start_matches('.');
            host == e || host.ends_with(&format!(".{e}"))
        })
}

#[cfg(test)]
mod proxy_tests {
    use super::env_proxy_with;

    /// The environment's proxy: for an https instance NO_PROXY doesn't
    /// name; never for loopback or plain http.
    #[test]
    fn the_proxy_skips_loopback_http_and_no_proxy() {
        let cloud = "https://contoso.atlassian.net";
        assert!(env_proxy_with(cloud, ""));
        assert!(env_proxy_with(cloud, "example.com, 10.0.0.1"));
        for no in [
            "atlassian.net",
            ".atlassian.net",
            "*.atlassian.net",
            "contoso.atlassian.net:443",
            "*",
            "x, CONTOSO.atlassian.net",
        ] {
            assert!(!env_proxy_with(cloud, no), "{no}");
        }
        assert!(env_proxy_with(cloud, "notatlassian.net"));
        for direct in [
            "http://jira.example.com",
            "https://127.0.0.1:8443",
            "https://[::1]:8443",
            "https://localhost:8443",
            "not a url",
        ] {
            assert!(!env_proxy_with(direct, ""), "{direct}");
        }
        assert!(!env_proxy_with("https://10.1.2.3", "10.1.2.3"));
        assert!(!env_proxy_with("https://[2001:db8::1]", "2001:db8::1"));
    }
}

impl Client {
    fn get(&self, url: &str) -> ureq::Request {
        self.agent
            .get(url)
            .set("Accept", "application/json")
            .set("Authorization", &self.auth)
    }

    fn post(&self, url: &str) -> ureq::Request {
        self.agent
            .post(url)
            .set("Accept", "application/json")
            .set("Authorization", &self.auth)
    }

    /// The authenticated account: account ID (Cloud) or user name (Data
    /// Center), to notice issues someone else created.
    pub fn myself(&self) -> Result<Option<String>> {
        let body = read(
            self.get(&format!("{}/myself", self.base)).call(),
            "reading the current user",
        )?;
        let field = match self.deployment {
            Deployment::Cloud => "accountId",
            Deployment::DataCenter => "name",
        };
        Ok(body[field].as_str().map(str::to_string))
    }

    /// The JQL for this deployment's issues. Every value in it was checked
    /// against a strict character set (settings), and is quoted.
    pub fn jql(&self) -> String {
        let mut q = format!(
            "project = \"{}\" AND labels = \"{}\"",
            self.project, self.marker
        );
        if let Some(c) = &self.created_by {
            q.push_str(&format!(" AND creator = \"{c}\""));
        }
        q.push_str(" ORDER BY key ASC");
        q
    }

    /// Every Pathwarden issue of this deployment (any status).
    pub fn issues(&self) -> Result<Vec<Issue>> {
        let fields = json!(["labels", "status", "resolution", "creator"]);
        let jql = self.jql();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        let mut start = 0usize;
        for _ in 0..MAX_PAGES {
            let (url, body) = match self.deployment {
                Deployment::Cloud => {
                    let mut b = json!({ "jql": jql, "fields": fields, "maxResults": PAGE });
                    if let Some(t) = &token {
                        b["nextPageToken"] = t.clone().into();
                    }
                    (format!("{}/search/jql", self.base), b)
                }
                Deployment::DataCenter => (
                    format!("{}/search", self.base),
                    json!({ "jql": jql, "fields": fields, "maxResults": PAGE, "startAt": start }),
                ),
            };
            let page = read(self.post(&url).send_json(body), "searching issues")?;
            let rows = page["issues"].as_array().cloned().unwrap_or_default();
            for row in &rows {
                if let Some(i) = self.issue(row) {
                    out.push(i);
                }
            }
            match self.deployment {
                Deployment::Cloud => {
                    token = page["nextPageToken"].as_str().map(str::to_string);
                    if page["isLast"].as_bool().unwrap_or(token.is_none()) || token.is_none() {
                        return Ok(out);
                    }
                }
                Deployment::DataCenter => {
                    start += rows.len();
                    let total = page["total"].as_u64().unwrap_or(0) as usize;
                    if rows.is_empty() || start >= total {
                        return Ok(out);
                    }
                }
            }
        }
        bail!("searching issues: more than {MAX_PAGES} pages; refusing to continue")
    }

    /// One search row, or `None` (with a warning) when it can't be trusted.
    fn issue(&self, row: &Value) -> Option<Issue> {
        let key = row["key"].as_str().unwrap_or_default();
        if !valid_issue_key(key) {
            eprintln!(
                "jira: warning: skipping an issue with an unexpected key {}",
                row["key"]
            );
            return None;
        }
        let f = &row["fields"];
        let labels: Vec<String> = f["labels"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|l| l.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // The search asked for the marker; check it anyway.
        if !labels.contains(&self.marker) {
            return None;
        }
        let Some(fingerprint) = fingerprint_of(&labels) else {
            eprintln!("jira: warning: {key} has no single valid pwfp- label; left alone");
            return None;
        };
        let creator = match self.deployment {
            Deployment::Cloud => f["creator"]["accountId"].as_str(),
            Deployment::DataCenter => f["creator"]["name"].as_str(),
        }
        .map(str::to_string);
        if let Some(want) = &self.created_by {
            if creator.as_deref() != Some(want.as_str()) {
                return None;
            }
        }
        Some(Issue {
            key: key.to_string(),
            fingerprint,
            active: f["status"]["statusCategory"]["key"].as_str() != Some("done"),
            status: f["status"]["name"].as_str().map(str::to_string),
            resolution: f["resolution"]["name"].as_str().map(str::to_string),
            creator,
        })
    }

    /// Creates an issue; returns its key.
    pub fn create(&self, issue: &NewIssue, settings: &Settings) -> Result<String> {
        let mut fields = settings.fields.clone();
        fields.insert("project".into(), json!({ "key": self.project }));
        fields.insert("issuetype".into(), json!({ "name": settings.issue_type }));
        fields.insert("summary".into(), issue.summary.clone().into());
        fields.insert("description".into(), self.text(&issue.description));
        fields.insert("labels".into(), json!(issue.labels));
        if let Some(p) = &issue.priority {
            fields.insert("priority".into(), json!({ "name": p }));
        }
        let body = read(
            self.post(&format!("{}/issue", self.base))
                .send_json(json!({ "fields": Value::Object(fields) })),
            "creating an issue",
        )?;
        Ok(body["key"].as_str().unwrap_or("(unknown key)").to_string())
    }

    pub fn comment(&self, key: &str, note: &str) -> Result<()> {
        check_key(key)?;
        read(
            self.post(&format!("{}/issue/{key}/comment", self.base))
                .send_json(json!({ "body": self.text(note) })),
            "commenting",
        )
        .map(|_| ())
    }

    /// Moves an issue to a done (or open) status: the transition named
    /// `name`, else the first whose target status is in the right category.
    /// Returns the transition's name.
    pub fn transition(
        &self,
        key: &str,
        target: Target,
        name: Option<&str>,
        resolution: Option<&str>,
    ) -> Result<String> {
        check_key(key)?;
        let url = format!("{}/issue/{key}/transitions", self.base);
        let list = read(self.get(&url).call(), "listing transitions")?;
        let transitions = list["transitions"].as_array().cloned().unwrap_or_default();
        let category = |t: &Value| {
            t["to"]["statusCategory"]["key"]
                .as_str()
                .map(str::to_string)
        };
        let pick = match name {
            Some(n) => transitions.iter().find(|t| {
                t["name"]
                    .as_str()
                    .is_some_and(|x| x.trim().eq_ignore_ascii_case(n.trim()))
            }),
            None => match target {
                Target::Done => transitions
                    .iter()
                    .find(|t| category(t).as_deref() == Some("done")),
                Target::Open => transitions
                    .iter()
                    .find(|t| category(t).as_deref() == Some("new"))
                    .or_else(|| {
                        transitions
                            .iter()
                            .find(|t| category(t).as_deref() == Some("indeterminate"))
                    }),
            },
        };
        let Some(t) = pick else {
            let names: Vec<&str> = transitions
                .iter()
                .filter_map(|t| t["name"].as_str())
                .collect();
            bail!(
                "{key}: no transition to {} (available: {}); set {} in the settings",
                match target {
                    Target::Done => "a done status",
                    Target::Open => "an open status",
                },
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                },
                match target {
                    Target::Done => "close_transition",
                    Target::Open => "reopen_transition",
                }
            );
        };
        let id = t["id"].as_str().unwrap_or_default();
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{key}: transition with an unexpected id {}", t["id"]);
        }
        let mut body = json!({ "transition": { "id": id } });
        if let (Target::Done, Some(r)) = (target, resolution) {
            body["fields"] = json!({ "resolution": { "name": r } });
        }
        read(self.post(&url).send_json(body), "transitioning")?;
        Ok(t["name"].as_str().unwrap_or(id).to_string())
    }

    /// Text in the form this deployment takes: ADF (Cloud) or wiki markup
    /// with every special character escaped (Data Center renders
    /// descriptions and comments as wiki markup).
    fn text(&self, s: &str) -> Value {
        match self.deployment {
            Deployment::Cloud => adf(&clip(s, TEXT_MAX)),
            Deployment::DataCenter => Value::String(wiki_within(s, TEXT_MAX)),
        }
    }
}

/// [`wiki_escape`] of `s`, clipped so the escaped text is at most `max`
/// characters: escaping can make text several times longer, and Jira
/// refuses a field over its limit.
fn wiki_within(s: &str, max: usize) -> String {
    let mut n = max;
    loop {
        let e = wiki_escape(&clip(s, n));
        let len = e.chars().count();
        if len <= max || n <= 100 {
            return e;
        }
        n = (n * max / len).min(n - 1).max(100);
    }
}

/// Plain text as Jira wiki markup that shows exactly that text:
/// AD names can't add links, images, macros, mentions, tables or
/// formatting. Every character the renderer treats specially is escaped
/// with a backslash; a backslash itself, which would escape the next
/// character or (doubled) break the line, becomes `&#92;`; a line that
/// would start a heading or quote (`h1.`, `bq.`) has its first letter as
/// an entity. A plain web address (`https://...` with none of the special
/// characters that make a link or macro) stays as it is, so references
/// stay links. Line breaks stay; other control characters go.
pub fn wiki_escape(text: &str) -> String {
    const SPECIAL: &[char] = &[
        '*', '_', '?', '-', '+', '^', '~', '|', '!', '#', '{', '}', '[', ']', '(', ')',
    ];
    let plain_url = |word: &str| {
        let lower = word.to_ascii_lowercase();
        (lower.starts_with("https://") || lower.starts_with("http://"))
            && word.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '/' | ':' | '.' | '-' | '_' | '?' | '=' | '#' | '%' | '~' | '+' | ',' | ';'
                    )
            })
    };
    let mut out = String::with_capacity(text.len() + text.len() / 4);
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let lead = line.trim_start().as_bytes();
        let block = lead.len() > 3
            && (lead.starts_with(b"bq.")
                || (lead[0] == b'h' && lead[1].is_ascii_digit() && lead[2] == b'.'));
        let mut first = block;
        for (j, word) in line.split(' ').enumerate() {
            if j > 0 {
                out.push(' ');
            }
            if !first && plain_url(word) {
                out.push_str(word);
                continue;
            }
            for c in word.chars() {
                match c {
                    '\\' => out.push_str("&#92;"),
                    '&' => out.push_str("&amp;"),
                    c if first && !c.is_whitespace() => {
                        out.push_str(&format!("&#{};", u32::from(c)));
                        first = false;
                    }
                    c if SPECIAL.contains(&c) => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c.is_control() && c != '\t' => {}
                    c => out.push(c),
                }
            }
        }
    }
    out
}

/// At most `max` bytes of an answer; more is an error, never a cut answer
/// read as whole.
fn body(r: ureq::Response, max: u64, what: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.into_reader()
        .take(max + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("{what}: reading the response"))?;
    if buf.len() as u64 > max {
        bail!(
            "{what}: the response is larger than {} KiB; refusing to read it",
            max >> 10
        );
    }
    Ok(buf)
}

fn check_key(key: &str) -> Result<()> {
    if !valid_issue_key(key) {
        bail!("refusing to use an unexpected issue key {key:?}");
    }
    Ok(())
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 20).collect();
    out.push_str("\n\n[truncated]");
    out
}

/// Plain text as an Atlassian Document Format document: a paragraph per
/// blank-line-separated block, hard breaks between its lines. Text is
/// never interpreted, so names can't add links or formatting.
pub fn adf(text: &str) -> Value {
    let mut paragraphs = Vec::new();
    for block in text.split("\n\n") {
        let mut content = Vec::new();
        for (i, line) in block.lines().enumerate() {
            if i > 0 {
                content.push(json!({ "type": "hardBreak" }));
            }
            let line: String = line
                .chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .collect();
            if !line.is_empty() {
                content.push(json!({ "type": "text", "text": line }));
            }
        }
        if content.iter().any(|c| c["type"] == "text") {
            paragraphs.push(json!({ "type": "paragraph", "content": content }));
        }
    }
    json!({ "type": "doc", "version": 1, "content": paragraphs })
}

fn secret(var: &str) -> Result<String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .with_context(|| format!("environment variable {var} is not set"))
}

/// Turns a response into JSON, or an error with the status and Jira's own
/// messages (never the request, which carries credentials).
fn read(resp: Result<ureq::Response, ureq::Error>, what: &str) -> Result<Value> {
    match resp {
        // Redirects are never followed (the agent's `redirects(0)`).
        Ok(r) if (300..400).contains(&r.status()) => bail!(
            "{what}: Jira answered with a redirect (HTTP {}), which Pathwarden doesn't follow; \
             check the site address",
            r.status()
        ),
        Ok(r) => {
            let text = String::from_utf8(body(r, MAX_RESPONSE, what)?)
                .with_context(|| format!("{what}: reading the response"))?;
            if text.trim().is_empty() {
                // 204 No Content (transitions).
                return Ok(Value::Null);
            }
            serde_json::from_str(&text).with_context(|| format!("{what}: response is not JSON"))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = body(r, MAX_ERROR_BODY, what)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .map(|v| {
                    let mut parts: Vec<String> = v["errorMessages"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|m| m.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(errors) = v["errors"].as_object() {
                        for (k, m) in errors {
                            parts.push(format!("{k}: {}", m.as_str().unwrap_or_default()));
                        }
                    }
                    parts.join("; ")
                })
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| body.chars().take(300).collect());
            bail!(
                "{what}: Jira returned HTTP {code}: {}",
                redact_userinfo(&detail)
            )
        }
        Err(ureq::Error::Transport(t)) => {
            let url = t.url().map(redacted).unwrap_or_default();
            let mut detail = match t.message() {
                Some(m) => format!("{}: {}", t.kind(), redact_userinfo(m)),
                None => t.kind().to_string(),
            };
            // Why, such as a certificate this computer doesn't trust.
            if let Some(cause) = std::error::Error::source(&t) {
                detail.push_str(&format!(" ({})", redact_userinfo(&cause.to_string())));
            }
            bail!("{what}: {url}: {detail}")
        }
    }
}

/// A URL without its user name and password.
fn redacted(url: &url::Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

/// Removes `user:password@` from every URL in a message.
pub fn redact_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        out.push_str(&rest[..at + 3]);
        rest = &rest[at + 3..];
        let end = rest
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(rest.len());
        if let Some(userinfo) = rest[..end].rfind('@') {
            out.push_str("***@");
            rest = &rest[userinfo + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// Standard base64 (for the basic auth header), to avoid a dependency.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want);
        }
    }

    #[test]
    fn auth_headers_are_zeroizing() {
        std::env::set_var("PW_JIRA_TEST_USER", "me@contoso.com");
        std::env::set_var("PW_JIRA_TEST_TOKEN", "tok");
        std::env::set_var("PW_JIRA_TEST_PAT", "pat");
        let mut s =
            Settings::parse(r#"{"instance":"https://x.atlassian.net","project":"SEC"}"#).unwrap();
        s.username_env = "PW_JIRA_TEST_USER".into();
        s.token_env = "PW_JIRA_TEST_TOKEN".into();
        let c = Client::new(&s).unwrap();
        let auth: &Zeroizing<String> = &c.auth;
        assert_eq!(
            auth.as_str(),
            format!("Basic {}", base64(b"me@contoso.com:tok"))
        );
        s.pat_env = Some("PW_JIRA_TEST_PAT".into());
        assert_eq!(Client::new(&s).unwrap().auth.as_str(), "Bearer pat");
    }

    #[test]
    fn jql_is_built_from_checked_values() {
        let mut s = Settings::parse(r#"{"instance":"https://x.atlassian.net","project":"SEC","scope":"prod","created_by":"712020:abc"}"#).unwrap();
        s.username_env = "PATH".into();
        s.token_env = "PATH".into();
        let c = Client::new(&s).unwrap();
        assert_eq!(
            c.jql(),
            "project = \"SEC\" AND labels = \"pathwarden-prod\" AND creator = \"712020:abc\" ORDER BY key ASC"
        );
    }

    #[test]
    fn adf_paragraphs_and_breaks() {
        let d = adf("Title\n\nline one\nline two\n\n\n");
        assert_eq!(d["type"], "doc");
        let paras = d["content"].as_array().unwrap();
        assert_eq!(paras.len(), 2);
        assert_eq!(paras[1]["content"][0]["text"], "line one");
        assert_eq!(paras[1]["content"][1]["type"], "hardBreak");
        assert_eq!(paras[1]["content"][2]["text"], "line two");
        // Markdown in a name stays text.
        let d = adf("[click](https://evil)");
        assert_eq!(
            d["content"][0]["content"][0]["text"],
            "[click](https://evil)"
        );
        assert!(d["content"][0]["content"][0].get("marks").is_none());
    }

    /// Data Center renders text as wiki markup: a hostile AD name stays
    /// text. No link, image, macro, mention, table, list, heading
    /// or formatting survives unescaped; backslashes and line breaks are
    /// kept as text; our own reference links stay links.
    /// Data Center text is clipped after escaping, so a path-heavy finding
    /// whose escaped text is several times longer still fits.
    #[test]
    fn escaped_text_fits_the_limit() {
        let path = "\\\\srv\\share\\[x](y)-z ".repeat(4000);
        assert!(wiki_escape(&path).chars().count() > 3 * TEXT_MAX);
        let e = wiki_within(&path, TEXT_MAX);
        assert!(e.chars().count() <= TEXT_MAX, "{}", e.chars().count());
        assert!(e.ends_with("\\[truncated\\]"), "{}", &e[e.len() - 40..]);
        assert_eq!(wiki_within("short", TEXT_MAX), "short");
    }

    #[test]
    fn wiki_markup_in_names_stays_text() {
        let e = wiki_escape;
        assert_eq!(e("CONTOSO\\svc-sql"), "CONTOSO&#92;svc\\-sql");
        assert_eq!(e("a\\\\b"), "a&#92;&#92;b");
        assert_eq!(
            e("[click|javascript:alert(1)]"),
            "\\[click\\|javascript:alert\\(1\\)\\]"
        );
        assert_eq!(
            e("!https://contoso.com/x.png!"),
            "\\!https://contoso.com/x.png\\!"
        );
        assert_eq!(
            e("[~admin] {color:red}x{color}"),
            "\\[\\~admin\\] \\{color:red\\}x\\{color\\}"
        );
        assert_eq!(
            e("*bold* _it_ ||a||b||"),
            "\\*bold\\* \\_it\\_ \\|\\|a\\|\\|b\\|\\|"
        );
        assert_eq!(e("- item\n# one\n----"), "\\- item\n\\# one\n\\-\\-\\-\\-");
        assert_eq!(e("h1. Fake\nbq. quote"), "&#104;1. Fake\n&#98;q. quote");
        assert_eq!(
            e("(!) (x) &#92; & ok"),
            "\\(\\!\\) \\(x\\) &amp;\\#92; &amp; ok"
        );
        assert_eq!(e("one\ntwo\u{7}\tthree"), "one\ntwo\tthree");
        assert_eq!(
            e("- https://learn.microsoft.com/en-us/x_y?a=1#b"),
            "\\- https://learn.microsoft.com/en-us/x_y?a=1#b"
        );
        // An address that carries markup is escaped like any other text.
        assert_eq!(e("https://x/[y]"), "https://x/\\[y\\]");
        for (c, raw) in [
            "*", "_", "?", "+", "^", "~", "|", "!", "#", "{", "}", "[", "]",
        ]
        .iter()
        .map(|c| (c, format!("a{c}b")))
        {
            assert_eq!(e(&raw), format!("a\\{c}b"));
        }
    }

    #[test]
    fn errors_hide_credentials() {
        assert_eq!(
            redact_userinfo("GET https://u:pw@h/x"),
            "GET https://***@h/x"
        );
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();
        let resp = agent.get("http://user:hunter2@127.0.0.1:9/rest").call();
        let e = format!("{:#}", read(resp, "searching issues").unwrap_err());
        assert!(
            e.starts_with("searching issues: ") && !e.contains("hunter2"),
            "{e}"
        );
    }
}
