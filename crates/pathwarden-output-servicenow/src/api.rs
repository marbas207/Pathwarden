//! The ServiceNow Table API, through `ureq` (rustls with the operating
//! system's certificate store, proxy from HTTPS_PROXY / HTTP_PROXY).

use std::io::Read;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::reconcile::Ticket;
use crate::settings::Settings;

const PAGE: usize = 500;
/// More pages than this (500,000 tickets) means something is wrong (a
/// server that never says it is done): stop rather than loop.
const MAX_PAGES: usize = 1000;
/// The most of an answer read: a page of 500 tickets is far smaller.
pub const MAX_RESPONSE: u64 = 32 << 20;
/// The most of an error answer read, for its message.
const MAX_ERROR_BODY: u64 = 64 << 10;

pub struct Client {
    agent: ureq::Agent,
    base: String,
    /// The instance's address, without a trailing `/`.
    instance: String,
    auth: Zeroizing<String>,
    /// This deployment's `correlation_display` marker.
    display: String,
    /// Only tickets created by this account are read (validated setting).
    created_by: Option<String>,
    /// The basic-auth user, to notice tickets someone else created.
    pub user: Option<String>,
}

impl Client {
    pub fn new(settings: &Settings) -> Result<Self> {
        // The secrets and every copy made here are zeroed when dropped; ureq's
        // own copy of the header, and the environment, are out of reach.
        let (auth, user) = match &settings.token_env {
            Some(var) => {
                let token = Zeroizing::new(secret(var)?);
                (Zeroizing::new(format!("Bearer {}", *token)), None)
            }
            None => {
                let user = secret(&settings.username_env)?;
                let pass = Zeroizing::new(secret(&settings.password_env)?);
                let pair = Zeroizing::new(format!("{user}:{}", *pass));
                let encoded = Zeroizing::new(base64(pair.as_bytes()));
                (Zeroizing::new(format!("Basic {}", *encoded)), Some(user))
            }
        };
        Ok(Client {
            agent: agent(&settings.instance),
            base: settings.base_url(),
            instance: settings.instance.trim().trim_end_matches('/').to_string(),
            auth,
            display: settings.correlation_display(),
            created_by: settings.created_by.clone(),
            user,
        })
    }

    /// The user name of the account the plugin signs in as (what
    /// `sys_created_by` holds): the basic-auth user, or, with a token, the
    /// one ServiceNow names for the session.
    pub fn me(&self) -> Result<Option<String>> {
        if let Some(u) = &self.user {
            return Ok(Some(u.clone()));
        }
        let body = read(
            self.agent
                .get(&format!("{}/api/now/ui/user/current_user", self.instance))
                .set("Accept", "application/json")
                .set("Authorization", &self.auth)
                .call(),
            "reading the current user",
        )?;
        Ok(text(&body["result"]["user_name"]).filter(|u| !u.is_empty()))
    }

    /// Every ticket this plugin created (any state), paging through results.
    pub fn tickets(&self) -> Result<Vec<Ticket>> {
        self.tickets_upto(MAX_PAGES)
    }

    fn tickets_upto(&self, max_pages: usize) -> Result<Vec<Ticket>> {
        let mut out = Vec::new();
        let mut offset = 0;
        for _ in 0..max_pages {
            let resp = self
                .agent
                .get(&self.base)
                .set("Accept", "application/json")
                .set("Authorization", &self.auth)
                .query(
                    "sysparm_query",
                    // Exactly this deployment's marker (and creator, when
                    // configured), in a stable order so paging never skips
                    // or repeats rows.
                    &format!(
                        "correlation_display={}{}^ORDERBYsys_created_on^ORDERBYsys_id",
                        self.display,
                        self.created_by
                            .as_deref()
                            .map(|u| format!("^sys_created_by={u}"))
                            .unwrap_or_default()
                    ),
                )
                .query(
                    "sysparm_fields",
                    "sys_id,number,active,correlation_id,state,close_code,sys_created_by",
                )
                .query("sysparm_limit", &PAGE.to_string())
                .query("sysparm_offset", &offset.to_string())
                .call();
            let body = read(resp, "listing tickets")?;
            let rows = body["result"].as_array().cloned().unwrap_or_default();
            let n = rows.len();
            for row in &rows {
                match ticket(row) {
                    Some(t) => out.push(t),
                    None if row.get("sys_id").is_some() => eprintln!(
                        "servicenow: warning: skipping a ticket with an unexpected sys_id {}",
                        row["sys_id"]
                    ),
                    None => {}
                }
            }
            if n < PAGE {
                return Ok(out);
            }
            offset += PAGE;
        }
        bail!("listing tickets: more than {max_pages} pages; refusing to continue")
    }

    /// Creates a ticket; returns its number and, when ServiceNow gave a
    /// valid one, its sys_id.
    pub fn create(&self, fields: &Map<String, Value>) -> Result<(String, Option<String>)> {
        let resp = self
            .agent
            .post(&self.base)
            .set("Accept", "application/json")
            .set("Authorization", &self.auth)
            .send_json(Value::Object(fields.clone()));
        let body = read(resp, "creating a ticket")?;
        let number = text(&body["result"]["number"]).unwrap_or_else(|| "(unknown number)".into());
        let sys_id = text(&body["result"]["sys_id"]).filter(|s| valid_sys_id(s));
        Ok((number, sys_id))
    }

    pub fn update(&self, sys_id: &str, fields: &Map<String, Value>) -> Result<()> {
        if !valid_sys_id(sys_id) {
            bail!("refusing to update a ticket with an unexpected sys_id {sys_id:?}");
        }
        let resp = self
            .agent
            .request("PATCH", &format!("{}/{sys_id}", self.base))
            .set("Accept", "application/json")
            .set("Authorization", &self.auth)
            .send_json(Value::Object(fields.clone()));
        read(resp, "updating a ticket").map(|_| ()).map_err(|e| {
            let text = format!("{e:#}");
            if text.contains("mandatory") && text.contains("Resolution code") {
                e.context(
                    "ServiceNow refused the resolution code: set resolve_fields.close_code to one of \
                     this instance's codes (System Definition > Choice Lists, incident, close_code)",
                )
            } else {
                e
            }
        })
    }
}

/// The HTTP client for `instance`: the operating system's certificates, a
/// proxy from the environment where it applies ([`env_proxy_for`]), time
/// limits, and no redirects: one could carry the Authorization header to
/// another host.
fn agent(instance: &str) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(20))
        .timeout(Duration::from_secs(90))
        .try_proxy_from_env(env_proxy_for(instance))
        .redirects(0)
        .build()
}

/// Whether the proxy from the environment (`HTTPS_PROXY`, `HTTP_PROXY`,
/// `ALL_PROXY`) is used for `instance`: never for a loopback address or a
/// plain `http://` instance, whose Authorization header the proxy would get
/// in clear, nor for a host `NO_PROXY` names (ureq doesn't read it).
fn env_proxy_for(instance: &str) -> bool {
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

fn secret(var: &str) -> Result<String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .with_context(|| format!("environment variable {var} is not set"))
}

/// Turns a response into JSON, or an error with the status and ServiceNow's
/// own message (never the request, which carries credentials).
fn read(resp: Result<ureq::Response, ureq::Error>, what: &str) -> Result<Value> {
    match resp {
        // Redirects are never followed ([`agent`]).
        Ok(r) if (300..400).contains(&r.status()) => bail!(
            "{what}: ServiceNow answered with a redirect (HTTP {}), which Pathwarden doesn't \
             follow; check the instance address",
            r.status()
        ),
        Ok(r) => serde_json::from_slice(&body(r, MAX_RESPONSE, what)?)
            .with_context(|| format!("{what}: response is not JSON")),
        Err(ureq::Error::Status(code, r)) => {
            let body = body(r, MAX_ERROR_BODY, what)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    let e = &v["error"];
                    let msg = text(&e["message"])?;
                    Some(match text(&e["detail"]) {
                        Some(d) if !d.is_empty() => format!("{msg} ({d})"),
                        _ => msg,
                    })
                })
                .unwrap_or_else(|| body.chars().take(300).collect());
            bail!("{what}: ServiceNow returned HTTP {code}: {detail}")
        }
        // Credentials are in a header, and settings refuse them in the URL;
        // still, never print a URL's user name or password.
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

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// A ServiceNow sys_id: 32 lowercase hex characters.
pub fn valid_sys_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ticket(row: &Value) -> Option<Ticket> {
    let correlation_id = text(&row["correlation_id"]).filter(|c| !c.is_empty())?;
    let sys_id = text(&row["sys_id"]).filter(|s| valid_sys_id(s))?;
    let active = match &row["active"] {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    Some(Ticket {
        sys_id,
        number: text(&row["number"]).unwrap_or_default(),
        correlation_id,
        active,
        state: text(&row["state"]).filter(|c| !c.is_empty()),
        close_code: text(&row["close_code"]).filter(|c| !c.is_empty()),
        created_by: text(&row["sys_created_by"]).filter(|c| !c.is_empty()),
    })
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
        assert_eq!(base64(b"admin:p@ss"), "YWRtaW46cEBzcw==");
    }

    #[test]
    fn auth_header_is_built_in_zeroizing_memory() {
        std::env::set_var("PW_SN_TEST_USER", "admin");
        std::env::set_var("PW_SN_TEST_PASS", "p@ss");
        let settings = Settings {
            username_env: "PW_SN_TEST_USER".into(),
            password_env: "PW_SN_TEST_PASS".into(),
            ..Settings::default()
        };
        let client = Client::new(&settings).unwrap();
        // The type is the point: the header is zeroed when the client drops.
        let auth: &Zeroizing<String> = &client.auth;
        assert_eq!(auth.as_str(), "Basic YWRtaW46cEBzcw==");
        assert_eq!(client.user.as_deref(), Some("admin"));
    }

    const SYS: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn sys_id_validation() {
        assert!(valid_sys_id(SYS));
        for bad in [
            "",
            "abc",
            "0123456789ABCDEF0123456789ABCDEF",
            "../../../v1/x#0123456789abcdef01",
        ] {
            assert!(!valid_sys_id(bad), "accepted {bad}");
        }
        let row = serde_json::json!({"sys_id":"../x","correlation_id":"PW-1","active":true});
        assert!(ticket(&row).is_none(), "rows with a bad sys_id are skipped");
    }

    #[test]
    fn ticket_rows() {
        let row = serde_json::json!({"sys_id":SYS,"number":"INC1","active":"false","correlation_id":"PW-1","close_code":"Won't Fix"});
        let t = ticket(&row).unwrap();
        assert!(!t.active);
        assert_eq!(
            (t.number.as_str(), t.correlation_id.as_str()),
            ("INC1", "PW-1")
        );
        assert_eq!(t.close_code.as_deref(), Some("Won't Fix"));
        assert!(ticket(&serde_json::json!({"sys_id":SYS,"correlation_id":""})).is_none());
        let t = ticket(
            &serde_json::json!({"sys_id":SYS,"correlation_id":"P","active":true,"close_code":""}),
        )
        .unwrap();
        assert!(t.active && t.close_code.is_none());
        let row = serde_json::json!({"sys_id":SYS,"correlation_id":"P","sys_created_by":"bob"});
        assert_eq!(ticket(&row).unwrap().created_by.as_deref(), Some("bob"));
    }

    /// L4: transport errors never print credentials from a URL.
    #[test]
    fn transport_errors_hide_credentials() {
        assert_eq!(
            redact_userinfo("GET https://u:pw@h:9/api and http://x@y/z, ok"),
            "GET https://***@h:9/api and http://***@y/z, ok"
        );
        assert_eq!(redact_userinfo("no url here"), "no url here");
        // Port 9 (discard) is closed on test machines: a connection error.
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();
        let resp = agent.get("http://user:hunter2@127.0.0.1:9/api").call();
        let e = format!("{:#}", read(resp, "listing tickets").unwrap_err());
        assert!(e.starts_with("listing tickets: "), "{e}");
        assert!(!e.contains("hunter2") && !e.contains("user:"), "{e}");
    }

    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    /// A local HTTP server that answers every request with `answer(n)`
    /// (the n-th request, from 0) until the test ends. Returns its port.
    fn serve(answer: impl Fn(usize) -> Vec<u8> + Send + 'static) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for (n, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { return };
                read_request(&mut conn);
                let _ = conn.write_all(&answer(n));
            }
        });
        port
    }

    /// Reads one request's head (the tests send no body).
    fn read_request(conn: &mut TcpStream) {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && conn.read(&mut byte).is_ok_and(|n| n == 1) {
            head.push(byte[0]);
        }
    }

    fn http(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn client(port: u16) -> Client {
        Client {
            agent: agent("http://127.0.0.1"),
            base: format!("http://127.0.0.1:{port}/api/now/table/incident"),
            instance: format!("http://127.0.0.1:{port}"),
            auth: Zeroizing::new("Basic c2VjcmV0".into()),
            display: "pathwarden".into(),
            created_by: None,
            user: None,
        }
    }

    /// A redirect is never followed: it could carry the
    /// Authorization header to another host.
    #[test]
    fn redirects_are_not_followed() {
        let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = elsewhere.local_addr().unwrap().port();
        elsewhere.set_nonblocking(true).unwrap();
        let port = serve(move |_| {
            http(
                "302 Found",
                &format!("Location: http://127.0.0.1:{to}/steal\r\n"),
                b"",
            )
        });
        let e = format!("{:#}", client(port).tickets().unwrap_err());
        assert!(e.contains("redirect (HTTP 302)"), "{e}");
        std::thread::sleep(Duration::from_millis(200));
        assert!(elsewhere.accept().is_err(), "the redirect was followed");
    }

    /// Who the plugin signs in as: the basic-auth user as given, or
    /// with a token the session's user name; an error when ServiceNow
    /// doesn't say.
    #[test]
    fn the_account_is_known() {
        let mut c = client(1);
        c.user = Some("svc.pw".into());
        assert_eq!(c.me().unwrap().as_deref(), Some("svc.pw"));
        let port = serve(|_| {
            http(
                "200 OK",
                "",
                br#"{"result":{"user_name":"svc.token","user_sys_id":"x"}}"#,
            )
        });
        assert_eq!(client(port).me().unwrap().as_deref(), Some("svc.token"));
        let port = serve(|_| http("404 Not Found", "", br#"{"error":{"message":"no"}}"#));
        assert!(client(port).me().is_err());
    }

    /// A server that never says it is done is stopped after the page cap
    ///.
    #[test]
    fn paging_stops_at_the_cap() {
        let row = |i: usize| {
            serde_json::json!({
                "sys_id": format!("{i:032x}"),
                "number": format!("INC{i}"),
                "active": true,
                "correlation_id": format!("PW-{i}"),
            })
        };
        let port = serve(move |n| {
            let rows: Vec<Value> = (0..PAGE).map(|i| row(n * PAGE + i)).collect();
            http(
                "200 OK",
                "",
                &serde_json::to_vec(&serde_json::json!({ "result": rows })).unwrap(),
            )
        });
        let e = format!("{:#}", client(port).tickets_upto(3).unwrap_err());
        assert!(e.contains("more than 3 pages"), "{e}");
    }

    /// Answers have explicit size caps: a larger one is refused,
    /// not read in full or cut short and parsed.
    #[test]
    fn answers_are_capped() {
        let big = vec![b' '; 4096];
        let port = serve(move |_| http("200 OK", "", &big));
        let resp = agent("http://127.0.0.1")
            .get(&format!("http://127.0.0.1:{port}/"))
            .call()
            .unwrap();
        let e = format!("{:#}", body(resp, 1024, "listing tickets").unwrap_err());
        assert!(e.contains("larger than 1 KiB"), "{e}");
        let port = serve(|_| http("200 OK", "", b"{\"result\":[]}"));
        let resp = agent("http://127.0.0.1")
            .get(&format!("http://127.0.0.1:{port}/"))
            .call()
            .unwrap();
        assert_eq!(body(resp, 1024, "x").unwrap(), b"{\"result\":[]}");
    }

    /// The environment's proxy: for an https instance NO_PROXY doesn't
    /// name; never for loopback or plain http.
    #[test]
    fn the_proxy_skips_loopback_http_and_no_proxy() {
        let sn = "https://contoso.service-now.com";
        assert!(env_proxy_with(sn, ""));
        assert!(env_proxy_with(sn, "example.com"));
        for no in [
            "service-now.com",
            ".service-now.com",
            "*.service-now.com",
            "contoso.service-now.com:443",
            "*",
        ] {
            assert!(!env_proxy_with(sn, no), "{no}");
        }
        for direct in [
            "http://sn.example.com",
            "https://127.0.0.1:8443",
            "https://[::1]",
            "https://localhost",
        ] {
            assert!(!env_proxy_with(direct, ""), "{direct}");
        }
    }

    /// A server whose certificate this computer doesn't trust (self-signed,
    /// for 127.0.0.1) is refused before anything is sent. The
    /// certificate and key in `testdata` were made for this test only.
    #[test]
    fn an_untrusted_certificate_is_refused() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let cert =
            CertificateDer::from(include_bytes!("../testdata/self-signed-cert.der").to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../testdata/self-signed-key.der").to_vec(),
        ));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let got_request = Arc::new(AtomicBool::new(false));
        let seen = got_request.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let mut tls = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(config.clone()).unwrap(),
                    conn,
                );
                let mut buf = [0u8; 64];
                // The handshake fails on the client's side; any request
                // that got through would be read here.
                if tls.read(&mut buf).is_ok_and(|n| n > 0) {
                    seen.store(true, Ordering::SeqCst);
                    let _ = tls.write_all(&http("200 OK", "", b"{\"result\":[]}"));
                }
            }
        });
        let resp = agent("https://127.0.0.1")
            .get(&format!("https://127.0.0.1:{port}/api/now/table/incident"))
            .set("Authorization", "Basic c2VjcmV0")
            .call();
        let e = format!("{:#}", read(resp, "listing tickets").unwrap_err());
        assert!(
            e.contains("certificate") || e.contains("Certificate"),
            "{e}"
        );
        assert!(!got_request.load(Ordering::SeqCst), "a request got through");
    }
}
