//! Who may talk to the server. It listens on 127.0.0.1 only, and every
//! request must:
//!
//! - name this server in `Host` (`127.0.0.1:PORT` or `localhost:PORT`), which
//!   stops DNS rebinding: a web page on another name cannot reach it;
//! - carry a session cookie, which the browser gets by opening the
//!   `?token=` link printed at startup. The link's token works **once**, and
//!   only for a short time ([`SessionPolicy::link_ttl`]); it is exchanged for
//!   a *separate* random session secret in an `HttpOnly; SameSite=Strict`
//!   cookie, and the link is replaced by one without it. Sessions end after
//!   a while unused ([`SessionPolicy::idle`]), after a fixed time in any case
//!   ([`SessionPolicy::absolute`]), and when the user stops Pathwarden;
//! - for anything that changes state (POST, PUT, DELETE), say it comes from
//!   this server's own pages: an `Origin` naming this server, or, without
//!   one, `Sec-Fetch-Site: same-origin`. A change that says neither is
//!   refused.
//!
//! Every response is also marked not to be cached, sniffed or framed by
//! other sites, with a strict Content Security Policy.
//!
//! In the experimental desktop window ([`Transport::Embedded`]) there is no
//! socket: the window's webview hands each request to the router inside
//! this process, so only that webview can make one. The link, cookie and
//! sessions are skipped there; `Host` and `Origin` must name the webview's
//! own origin, and the same headers and CSP apply.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::pages;
use crate::server::AppState;

/// A secret: 32 random bytes, as hex. Used both for the one-time link and
/// (a different value) for each session's cookie.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    pub fn generate() -> anyhow::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow::anyhow!("no random numbers available: {e}"))?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }

    /// The value as it appears in the link or the cookie.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison, so response timing reveals nothing about
    /// how much of a guess was right.
    pub fn matches(&self, candidate: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), candidate.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// How long links and sessions last.
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    /// A link must be opened within this time of being printed.
    pub link_ttl: Duration,
    /// A session ends after this long without a request.
    pub idle: Duration,
    /// A session ends this long after it started, used or not.
    pub absolute: Duration,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            link_ttl: Duration::from_secs(120),
            idle: Duration::from_secs(8 * 3600),
            absolute: Duration::from_secs(24 * 3600),
        }
    }
}

/// The most sessions kept at once (each browser that opened a link is one);
/// the oldest goes first.
const MAX_SESSIONS: usize = 32;

struct Link {
    token: Token,
    issued: Instant,
}

struct Session {
    secret: Token,
    started: Instant,
    seen: Instant,
}

/// What a cookie turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Valid,
    /// It was a session, which has timed out or was ended.
    Expired,
    Unknown,
}

/// What exchanging a link's token gave.
#[derive(Debug)]
pub enum Exchange {
    /// A new session: its secret goes in the cookie.
    Session(Token),
    /// The right token, but too late.
    Expired,
    /// Already used, replaced by a newer link, or never valid.
    Refused,
}

/// The one-time link and the live sessions.
pub struct Sessions {
    pub policy: SessionPolicy,
    link: Mutex<Option<Link>>,
    live: Mutex<Vec<Session>>,
    /// Secrets of sessions that ended, so the page can say so (bounded).
    ended: Mutex<Vec<Token>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Sessions {
    /// Starts with `link` as the one-time link, issued now.
    pub fn new(link: Token, policy: SessionPolicy) -> Self {
        Self {
            policy,
            link: Mutex::new(Some(Link {
                token: link,
                issued: Instant::now(),
            })),
            live: Mutex::default(),
            ended: Mutex::default(),
        }
    }

    /// A fresh one-time link token. The previous link, if unused, stops
    /// working.
    pub fn new_link(&self) -> anyhow::Result<Token> {
        let token = Token::generate()?;
        *lock(&self.link) = Some(Link {
            token: token.clone(),
            issued: Instant::now(),
        });
        Ok(token)
    }

    /// Whether the current link has been used or has run out (so a launcher
    /// file holding it can go).
    pub fn link_spent(&self) -> bool {
        lock(&self.link)
            .as_ref()
            .is_none_or(|l| l.issued.elapsed() > self.policy.link_ttl)
    }

    /// Exchanges a link's token for a new session. The token works once: it
    /// is gone after a successful exchange, and after it expires.
    pub fn exchange(&self, candidate: &str) -> Exchange {
        let mut link = lock(&self.link);
        let Some(current) = link.as_ref() else {
            return Exchange::Refused;
        };
        if !current.token.matches(candidate) {
            return Exchange::Refused;
        }
        let expired = current.issued.elapsed() > self.policy.link_ttl;
        *link = None;
        drop(link);
        if expired {
            return Exchange::Expired;
        }
        match self.start() {
            Ok(secret) => Exchange::Session(secret),
            Err(_) => Exchange::Refused,
        }
    }

    /// Starts a session and returns its secret. The guard calls this for a
    /// valid link; tests use it directly.
    pub fn start(&self) -> anyhow::Result<Token> {
        let secret = Token::generate()?;
        let now = Instant::now();
        let mut live = lock(&self.live);
        self.prune(&mut live, now);
        if live.len() >= MAX_SESSIONS {
            let gone = live.remove(0);
            self.remember_ended(gone.secret);
        }
        live.push(Session {
            secret: secret.clone(),
            started: now,
            seen: now,
        });
        Ok(secret)
    }

    fn remember_ended(&self, secret: Token) {
        let mut ended = lock(&self.ended);
        if ended.len() >= 4 * MAX_SESSIONS {
            ended.remove(0);
        }
        ended.push(secret);
    }

    fn prune(&self, live: &mut Vec<Session>, now: Instant) {
        let p = self.policy;
        let (keep, gone): (Vec<_>, Vec<_>) = std::mem::take(live).into_iter().partition(|s| {
            now.duration_since(s.seen) <= p.idle && now.duration_since(s.started) <= p.absolute
        });
        *live = keep;
        let ended = !gone.is_empty();
        for s in gone {
            self.remember_ended(s.secret);
        }
        if ended && live.is_empty() {
            // A history passphrase given "for this session only" (and the
            // keys it opened) ends with the last session.
            pathwarden_core::crypt::forget_all_in_process();
        }
    }

    /// Checks a cookie value, and counts the request as activity.
    pub fn check(&self, cookie: &str) -> Check {
        self.check_with(cookie, true)
    }

    /// [`Sessions::check`] for a page asking on its own, in the background
    /// (the history's news every 30 seconds): it never keeps an idle
    /// session alive.
    pub fn check_quietly(&self, cookie: &str) -> Check {
        self.check_with(cookie, false)
    }

    fn check_with(&self, cookie: &str, used: bool) -> Check {
        let now = Instant::now();
        let mut live = lock(&self.live);
        self.prune(&mut live, now);
        // Every entry is compared, in constant time each.
        let mut found = None;
        for (i, s) in live.iter().enumerate() {
            if s.secret.matches(cookie) {
                found = Some(i);
            }
        }
        if let Some(i) = found {
            if used {
                live[i].seen = now;
            }
            return Check::Valid;
        }
        drop(live);
        if lock(&self.ended).iter().any(|t| t.matches(cookie)) {
            Check::Expired
        } else {
            Check::Unknown
        }
    }

    /// Ends every session and the unused link (Stop).
    pub fn end_all(&self) {
        *lock(&self.link) = None;
        let gone = std::mem::take(&mut *lock(&self.live));
        for s in gone {
            self.remember_ended(s.secret);
        }
        pathwarden_core::crypt::forget_all_in_process();
    }
}

/// How requests reach the router.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Transport {
    /// A TCP listener on 127.0.0.1 (`pathwarden ui`): the one-time link,
    /// session cookie, `Host` and `Origin` checks.
    #[default]
    Loopback,
    /// Handed over in-process by an embedded webview's custom protocol
    /// (`pathwarden ui --window`): no socket exists, so nothing but that
    /// webview can send a request, and no link or cookie is needed.
    /// `origin` is the app's origin in that webview, such as
    /// `https://pathwarden.localhost` (WebView2) or `pathwarden://localhost`.
    Embedded { origin: String },
}

impl Transport {
    /// The embedded origin, if this is the embedded transport.
    pub fn embedded_origin(&self) -> Option<&str> {
        match self {
            Transport::Embedded { origin } => Some(origin),
            Transport::Loopback => None,
        }
    }
}

/// The `Host` that goes with an embedded origin: `pathwarden.localhost` for
/// `https://pathwarden.localhost`.
pub fn origin_host(origin: &str) -> &str {
    origin.split_once("://").map_or(origin, |(_, h)| h)
}

/// The app's own pages: scripts, styles and frames from this server only.
pub const APP_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; manifest-src 'self'; connect-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// A stored report: its own inline script and styles, nothing loaded from
/// anywhere, and sandboxed (an opaque origin), so even a name in the data that
/// slipped past escaping couldn't reach the app or its cookie.
pub const REPORT_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox";

/// The run page's frame for a report this computer recorded: links it
/// opens (Microsoft's documentation, references) leave the sandbox.
pub const REPORT_SANDBOX: &str = "allow-scripts allow-popups allow-popups-to-escape-sandbox";

/// The frame for a run loaded from the history: what the report
/// opens stays sandboxed (an opaque origin), so another computer's report
/// can't open a page with this app's origin or anything else unsandboxed.
pub const LOADED_REPORT_SANDBOX: &str = "allow-scripts allow-popups";

/// [`REPORT_CSP`] (or a policy made from it) for a run loaded from the
/// history: the same, with popups kept in the sandbox
/// ([`LOADED_REPORT_SANDBOX`]).
pub fn loaded_report_csp(csp: &str) -> String {
    csp.replace(" allow-popups-to-escape-sandbox", "")
}

/// Pages shown before the session is established (they cannot load the
/// stylesheet, which needs the cookie).
pub const BARE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Cookie names are not separated by port, so each server gets its own.
pub fn cookie_name(port: u16) -> String {
    format!("pathwarden_session_{port}")
}

fn allowed_host(state: &AppState, host: &str) -> bool {
    let port = state.port.to_string();
    host.strip_prefix("127.0.0.1:")
        .or_else(|| {
            state
                .localhost_host
                .then(|| host.strip_prefix("localhost:"))
                .flatten()
        })
        .is_some_and(|p| p == port)
}

fn allowed_origin(state: &AppState, origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .is_some_and(|h| allowed_host(state, h))
}

fn session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// A network or device path ([`is_network_path`]), or one on a drive
/// letter mapped to a network share ([`is_network_drive`]: reading it
/// waits on, and signs in to, that server).
pub use pathwarden_core::plugins::{is_network_drive, is_network_path, is_remote_path};

/// A duration for people: "2 minutes", "8 hours".
pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = if s >= 86_400 && s.is_multiple_of(86_400) {
        (s / 86_400, "day")
    } else if s >= 3600 && s.is_multiple_of(3600) {
        (s / 3600, "hour")
    } else if s >= 60 {
        (s / 60, "minute")
    } else {
        (s, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// The `token` parameter of a query string, if any.
fn query_token(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "token")
        .map(|(_, v)| v)
}

fn bare(status: StatusCode, title: &str, text: &str) -> Response {
    let mut r = (status, axum::response::Html(pages::bare_page(title, text))).into_response();
    r.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(BARE_CSP),
    );
    r
}

/// Where to send the browser after the token exchange: the same path
/// without the token (other parameters kept). Anything that is not a plain
/// local path (`//host`, `/\host`) becomes `/`.
fn clean_target(uri: &axum::http::Uri) -> String {
    let path = uri.path();
    let path = if path.starts_with('/') && !path.starts_with("//") && !path.contains('\\') {
        path
    } else {
        "/"
    };
    let rest: Vec<&str> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|kv| !kv.is_empty() && !kv.starts_with("token="))
        .collect();
    if rest.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", rest.join("&"))
    }
}

fn redirect(target: &str, cookie: Option<&str>) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::SEE_OTHER;
    let h = r.headers_mut();
    h.insert(
        header::LOCATION,
        HeaderValue::from_str(target).unwrap_or(HeaderValue::from_static("/")),
    );
    if let Some(v) = cookie.and_then(|c| HeaderValue::from_str(c).ok()) {
        h.insert(header::SET_COOKIE, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}

/// The browser says the request was started by another site (or a file).
fn cross_site(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"cross-site"))
}

/// Sets the cookie and moves on to `target` from this page, so the next
/// request is same-site and carries the `SameSite=Strict` cookie.
/// `target` is a local path from [`clean_target`].
fn refresh(target: &str, cookie: &str) -> Response {
    let mut r = bare(
        StatusCode::OK,
        "Opening Pathwarden",
        "If nothing happens, reload this page.",
    );
    let h = r.headers_mut();
    h.insert(
        header::REFRESH,
        HeaderValue::from_str(&format!("0;url={target}"))
            .unwrap_or(HeaderValue::from_static("0;url=/")),
    );
    if let Ok(v) = HeaderValue::from_str(cookie) {
        h.insert(header::SET_COOKIE, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}

/// The `Set-Cookie` value for a session.
fn session_set_cookie(state: &AppState, secret: &Token) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        state.cookie_name,
        secret.expose(),
        state.sessions.policy.absolute.as_secs()
    )
}

/// The `Set-Cookie` value that removes the session cookie.
pub fn clear_cookie(state: &AppState) -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        state.cookie_name
    )
}

const NEW_LINK: &str = "Press Enter in the window where Pathwarden is running to get a new link, or start Pathwarden again.";

/// What pages ask in the background ([`crate::auto_pull::pulled_api`]).
const BACKGROUND_PATH: &str = "/api/history/pulled";

/// The guard in front of every route.
pub async fn guard(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if let Some(origin) = state.transport.embedded_origin() {
        return embedded_guard(origin, req, next).await;
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if !allowed_host(&state, host) {
        return bare(
            StatusCode::MISDIRECTED_REQUEST,
            "Wrong address",
            "Pathwarden only answers on 127.0.0.1. Open the link printed in the terminal.",
        );
    }

    // The favicons and the manifest are public: a browser fetches the
    // manifest without cookies, and the pages shown before a session (link
    // expired, session ended) carry the icons too. They are the brand's
    // images and nothing else.
    if matches!(*req.method(), Method::GET | Method::HEAD)
        && crate::brand::is_public(req.uri().path())
    {
        return harden(next.run(req).await);
    }

    // The pages' background check for the history's news is no use of the
    // app: it doesn't keep an idle session alive.
    let background = req.uri().path() == BACKGROUND_PATH;
    let session = session_cookie(req.headers(), &state.cookie_name)
        .map(|v| {
            if background {
                state.sessions.check_quietly(v)
            } else {
                state.sessions.check(v)
            }
        })
        .unwrap_or(Check::Unknown);

    // The token exchange: ?token= becomes a new session, and the link
    // without the token.
    if let Some(candidate) = query_token(req.uri().query()) {
        let target = clean_target(req.uri());
        if req.method() != Method::GET {
            return bare(StatusCode::UNAUTHORIZED, "This link has expired", NEW_LINK);
        }
        return match state.sessions.exchange(candidate) {
            Exchange::Session(secret) => {
                crate::launch::discard(&state);
                let cookie = session_set_cookie(&state, &secret);
                if cross_site(req.headers()) {
                    // Opened from the launcher file (or another site): a
                    // redirect would keep that initiator, and the browser
                    // would not send the SameSite=Strict cookie with it.
                    // A refresh from this page is same-site.
                    refresh(&target, &cookie)
                } else {
                    redirect(&target, Some(&cookie))
                }
            }
            // Opening a used link again (from history, say) in a browser
            // that is signed in just goes on.
            _ if session == Check::Valid => redirect(&target, None),
            Exchange::Expired => bare(
                StatusCode::UNAUTHORIZED,
                "This link has expired",
                &format!(
                    "Each link works once, within {} of being printed. {NEW_LINK}",
                    human(state.sessions.policy.link_ttl)
                ),
            ),
            Exchange::Refused => bare(
                StatusCode::UNAUTHORIZED,
                "This link has expired",
                &format!("Each link works once: this one was already used or replaced. {NEW_LINK}"),
            ),
        };
    }

    match session {
        Check::Valid => {}
        Check::Expired => {
            let p = state.sessions.policy;
            let mut r = bare(
                StatusCode::UNAUTHORIZED,
                "Your session has ended",
                &format!(
                    "Pathwarden signs you out after {} without use, after {} in any case, and when it is stopped. {NEW_LINK}",
                    human(p.idle),
                    human(p.absolute)
                ),
            );
            if let Ok(v) = HeaderValue::from_str(&clear_cookie(&state)) {
                r.headers_mut().insert(header::SET_COOKIE, v);
            }
            return r;
        }
        Check::Unknown => {
            return bare(
                StatusCode::UNAUTHORIZED,
                "Open Pathwarden from the terminal",
                "For your safety this page only opens from the link Pathwarden printed when it started. Copy that link into this browser, or press Enter in the Pathwarden window for a new one.",
            );
        }
    }

    if !matches!(*req.method(), Method::GET | Method::HEAD) && !own_page(&state, req.headers()) {
        return (StatusCode::FORBIDDEN, "Request from another site refused").into_response();
    }

    harden(next.run(req).await)
}

/// Whether a change (POST, PUT, DELETE) says it came from this server's
/// own pages: `Origin` names this server, or, with no `Origin`, the
/// browser says `Sec-Fetch-Site: same-origin`. A request that says
/// neither is refused: CSRF never rests on `SameSite` alone.
fn own_page(state: &AppState, headers: &HeaderMap) -> bool {
    match headers.get(header::ORIGIN) {
        Some(o) => o.to_str().is_ok_and(|o| allowed_origin(state, o)),
        None => headers
            .get("sec-fetch-site")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"same-origin")),
    }
}

/// The guard for [`Transport::Embedded`]: no link or session (the transport
/// is the authentication), but `Host` must be the embedded origin's, and a
/// change must not say it came from anywhere else. A change without
/// `Origin` is let through here, unlike on the loopback server: no other
/// site can reach a custom protocol, and the webview is not relied on to
/// hand its fetches' `Origin` to the protocol handler.
async fn embedded_guard(origin: &str, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if host != origin_host(origin) {
        return bare(
            StatusCode::MISDIRECTED_REQUEST,
            "Wrong address",
            "Pathwarden's window only answers its own pages.",
        );
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        if let Some(o) = req.headers().get(header::ORIGIN) {
            if o.to_str().ok() != Some(origin) {
                return (StatusCode::FORBIDDEN, "Request from another site refused")
                    .into_response();
            }
        }
    }
    harden(next.run(req).await)
}

/// The headers every answer gets.
fn harden(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(APP_CSP));
    h.entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    h.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asking_in_the_background_keeps_no_session_alive() {
        let s = Sessions::new(Token::generate().unwrap(), SessionPolicy::default());
        let secret = s.start().unwrap();
        let earlier = Instant::now() - Duration::from_secs(600);
        lock(&s.live)[0].seen = earlier;
        assert_eq!(s.check_quietly(secret.expose()), Check::Valid);
        assert_eq!(lock(&s.live)[0].seen, earlier, "not counted as use");
        assert_eq!(s.check(secret.expose()), Check::Valid);
        assert!(lock(&s.live)[0].seen > earlier, "a page is use");
    }

    /// At most [`MAX_SESSIONS`] sessions live at once (gap 14): the
    /// next one ends the oldest, whose page then says its session ended;
    /// the list of ended ones stays bounded too.
    #[test]
    fn the_oldest_session_makes_room() {
        let s = Sessions::new(Token::generate().unwrap(), SessionPolicy::default());
        let first: Vec<Token> = (0..MAX_SESSIONS).map(|_| s.start().unwrap()).collect();
        assert!(first.iter().all(|t| s.check(t.expose()) == Check::Valid));
        let newer = s.start().unwrap();
        assert_eq!(lock(&s.live).len(), MAX_SESSIONS);
        assert_eq!(s.check(first[0].expose()), Check::Expired);
        assert_eq!(s.check(first[1].expose()), Check::Valid);
        assert_eq!(s.check(newer.expose()), Check::Valid);
        let more: Vec<Token> = (0..8 * MAX_SESSIONS).map(|_| s.start().unwrap()).collect();
        assert_eq!(lock(&s.live).len(), MAX_SESSIONS);
        assert_eq!(lock(&s.ended).len(), 4 * MAX_SESSIONS);
        assert_eq!(s.check(first[0].expose()), Check::Unknown, "forgotten");
        let last_ended = &more[more.len() - MAX_SESSIONS - 1];
        assert_eq!(s.check(last_ended.expose()), Check::Expired);
        assert_eq!(s.check(more[more.len() - 1].expose()), Check::Valid);
    }

    #[test]
    fn token() {
        let t = Token::generate().unwrap();
        assert_eq!(t.expose().len(), 64);
        assert!(t.matches(t.expose()));
        assert!(!t.matches(""));
        assert!(!t.matches(&t.expose()[..63]));
        let mut wrong = t.expose().to_string();
        wrong.replace_range(0..1, if wrong.starts_with('0') { "1" } else { "0" });
        assert!(!t.matches(&wrong));
        assert_ne!(Token::generate().unwrap().expose(), t.expose());
        assert_eq!(format!("{t:?}"), "Token(..)");
    }

    #[test]
    fn network_paths() {
        for p in [
            r"\\server\share\SharpHound.exe",
            "//server/share/x.exe",
            r"\/server\x",
            r"\\?\C:\x.exe",
            r"\\.\pipe\x",
            r"\??\UNC\server\x",
            r#" "\\server\x" "#,
            "file://server/x",
            "FILE:///C:/x",
        ] {
            assert!(is_network_path(p), "{p}");
        }
        for p in [r"C:\Tools\SharpHound.exe", "/opt/x", "powershell", ""] {
            assert!(!is_network_path(p), "{p}");
        }
    }

    /// A mapped drive is skipped by the domains peek; a local drive,
    /// an unused letter or a relative path is not one.
    #[test]
    fn network_drives() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        for p in [
            format!(r"{system}\x.zip"),
            r"1:\x".into(),
            "x.zip".into(),
            "/opt/x".into(),
            String::new(),
            ":".into(),
        ] {
            assert!(!is_network_drive(&p), "{p}");
        }
    }

    #[test]
    fn query_and_cookie_parsing() {
        assert_eq!(query_token(Some("a=1&token=abc")), Some("abc"));
        assert_eq!(query_token(Some("tokenx=abc")), None);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("x=1; s_1=abc; y=2"),
        );
        assert_eq!(session_cookie(&h, "s_1"), Some("abc"));
        assert_eq!(session_cookie(&h, "s_2"), None);
    }
}
