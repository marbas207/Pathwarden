//! The UI server end to end, through its router: the security checks, an
//! analysis from a path and from uploads, and run management.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState, Limits};
use pathwarden_ui::workspace::Workspace;
use tower::ServiceExt;

const PORT: u16 = 4242;
const HOST: &str = "127.0.0.1:4242";

struct App {
    router: Router,
    state: Arc<AppState>,
    /// The first one-time link's token.
    link: Token,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app(name: &str) -> App {
    app_with(name, |_| {})
}

fn app_with(name: &str, tweak: impl FnOnce(&mut AppState)) -> App {
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let link = Token::generate().unwrap();
    let mut state = AppState::new(ws, link.clone(), PORT);
    tweak(&mut state);
    let state = Arc::new(state);
    App {
        router: router(state.clone()),
        state,
        link,
        dir,
    }
}

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

impl App {
    fn cookie(&self) -> String {
        self.state.session_cookie()
    }

    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    /// Posts a multipart form: (field, file name or None, content).
    async fn post_form(
        &self,
        uri: &str,
        parts: &[(&str, Option<&str>, Vec<u8>)],
    ) -> (StatusCode, String) {
        let boundary = "pathwardenTestBoundary7d1f";
        let mut body = Vec::new();
        for (field, file, content) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match file {
                Some(f) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{field}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{field}\"\r\n\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = self
            .request(Method::POST, uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, b)
    }

    /// Waits for a job to finish (two minutes at most: the demo's first
    /// run analyzes its earlier runs too); returns its final status document.
    async fn wait(&self, job: &str) -> serde_json::Value {
        for _ in 0..2400 {
            let (s, _, body) = self.get(&format!("/api/jobs/{job}")).await;
            assert_eq!(s, StatusCode::OK, "{body}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            if v["status"] != "running" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("job {job} did not finish");
    }

    fn uploads_empty(&self) -> bool {
        std::fs::read_dir(self.state.ws().uploads_dir())
            .unwrap()
            .next()
            .is_none()
    }
}

fn job_id(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["job"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn requests_without_the_cookie_are_rejected() {
    let a = app("nocookie");
    for uri in [
        "/",
        "/runs",
        "/analyze",
        "/static/app.css",
        "/static/app.js",
        "/api/jobs/x",
        "/api/busy",
        "/api/history/since",
        "/nope",
    ] {
        let req = Request::get(uri)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let (s, h, body) = a.send(req).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri}");
        assert!(body.contains("Open Pathwarden from the terminal"), "{uri}");
        assert!(h.get(header::SET_COOKIE).is_none());
    }
    // A wrong cookie value is no better.
    let req = Request::get("/")
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("{}=00", a.state.cookie_name))
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
    // Another port's cookie is not this server's.
    let req = Request::get("/")
        .header(header::HOST, HOST)
        .header(
            header::COOKIE,
            a.cookie()
                .replace(&a.state.cookie_name, "pathwarden_session_1"),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
    // With it, the page loads.
    let (s, h, body) = a.get("/").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Try the demo") && body.contains(r#"<body class="app" data-pulled="0""#));
    assert!(h[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("script-src 'self'"));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn wrong_host_is_rejected() {
    let a = app("host");
    for host in [
        Some("evil.example:4242"),
        Some("127.0.0.1:4243"),
        Some("127.0.0.1"),
        Some("localhost.evil.example:4242"),
        Some("0.0.0.0:4242"),
        None,
    ] {
        let mut req = Request::get("/").header(header::COOKIE, a.cookie());
        if let Some(h) = host {
            req = req.header(header::HOST, h);
        }
        let (s, _, _) = a.send(req.body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::MISDIRECTED_REQUEST, "{host:?}");
    }
    // The token exchange checks the host first, too.
    let req = Request::get(format!("/?token={}", a.link.expose()))
        .header(header::HOST, "evil.example:4242")
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = a.send(req).await;
    assert_eq!(s, StatusCode::MISDIRECTED_REQUEST);
    assert!(h.get(header::SET_COOKIE).is_none());
    // localhost is fine.
    let req = Request::get("/")
        .header(header::HOST, "localhost:4242")
        .header(header::COOKIE, a.cookie())
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::OK);
}

impl App {
    /// Opens a one-time link without a cookie.
    async fn open_link(&self, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let req = Request::get(uri)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn get_with(
        &self,
        uri: &str,
        cookie: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let req = Request::get(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }
}

/// `name=value` from a `Set-Cookie` header.
fn cookie_pair(h: &axum::http::HeaderMap) -> String {
    let set = h[header::SET_COOKIE].to_str().unwrap();
    set.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn token_exchange_sets_a_separate_session_cookie() {
    let a = app("token");
    let (s, h, _) = a.open_link(&format!("/?token={}", a.link.expose())).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/");
    let set = h[header::SET_COOKIE].to_str().unwrap();
    assert!(
        set.starts_with(&format!("{}=", a.state.cookie_name)),
        "{set}"
    );
    assert!(set.contains("HttpOnly"));
    assert!(set.contains("SameSite=Strict"));
    assert!(set.contains("Path=/"));
    assert!(set.contains("Max-Age=86400"), "{set}");
    // The cookie is a new random secret, not the link's token.
    let cookie = cookie_pair(&h);
    let value = cookie.split_once('=').unwrap().1;
    assert_eq!(value.len(), 64);
    assert_ne!(value, a.link.expose());
    assert!(!set.contains(a.link.expose()));
    // It opens the app; the token used as a cookie does not.
    assert_eq!(a.get_with("/", &cookie).await.0, StatusCode::OK);
    let as_cookie = format!("{}={}", a.state.cookie_name, a.link.expose());
    assert_eq!(
        a.get_with("/", &as_cookie).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_link_opened_from_the_launcher_file_moves_on_from_the_page() {
    // A link opened from the launcher file (a file:// page) is a cross-site
    // navigation: a redirect would not carry the SameSite=Strict cookie, so
    // the page sets it and refreshes itself instead.
    let a = app("launcher");
    let req = Request::get(format!("/analyze?job=1&token={}", a.link.expose()))
        .header(header::HOST, HOST)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let (s, h, body) = a.send(req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::REFRESH], "0;url=/analyze?job=1");
    assert!(h.get(header::LOCATION).is_none());
    let set = h[header::SET_COOKIE].to_str().unwrap();
    assert!(set.contains("SameSite=Strict") && set.contains("HttpOnly"));
    assert!(!body.contains(a.link.expose()));
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert_eq!(a.get_with("/", &cookie_pair(&h)).await.0, StatusCode::OK);
    // Spent: a second use is refused.
    let req = Request::get(format!("/?token={}", a.link.expose()))
        .header(header::HOST, HOST)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_link_works_once() {
    let a = app("once");
    let link = format!("/?token={}", a.link.expose());
    let (s, h, _) = a.open_link(&link).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let cookie = cookie_pair(&h);
    // A second browser (no cookie) gets nothing from the same link.
    let (s, h, body) = a.open_link(&link).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.contains("already used"), "{body}");
    assert!(h.get(header::SET_COOKIE).is_none());
    assert!(!body.contains(a.link.expose()));
    // The signed-in browser opening it again (from history) just goes on.
    let (s, h, _) = a.get_with(&link, &cookie).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/");
    assert!(h.get(header::SET_COOKIE).is_none());

    // A new link (Enter in the console) works, once; other parameters
    // survive the redirect, the token does not.
    let fresh = a.state.sessions.new_link().unwrap();
    let (s, h, _) = a
        .open_link(&format!(
            "/analyze?job=20261001-020000-abcdef&token={}",
            fresh.expose()
        ))
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/analyze?job=20261001-020000-abcdef");
    assert_ne!(cookie_pair(&h), cookie);
    // Issuing a link retires the unused one before it.
    let older = a.state.sessions.new_link().unwrap();
    let _newer = a.state.sessions.new_link().unwrap();
    let (s, _, _) = a.open_link(&format!("/?token={}", older.expose())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A wrong token gets nothing, and does not burn the real one.
    let real = a.state.sessions.new_link().unwrap();
    let (s, h, _) = a.open_link(&format!("/?token={}", "ab".repeat(32))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h.get(header::SET_COOKIE).is_none());
    let (s, _, _) = a.open_link(&format!("/?token={}", real.expose())).await;
    assert_eq!(s, StatusCode::SEE_OTHER);

    // Only GET exchanges a token.
    let next = a.state.sessions.new_link().unwrap();
    let req = Request::post(format!("/?token={}", next.expose()))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_link_expires() {
    let a = app_with("linkttl", |s| {
        s.sessions.policy.link_ttl = Duration::from_millis(50);
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(a.state.sessions.link_spent());
    let (s, h, body) = a.open_link(&format!("/?token={}", a.link.expose())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.contains("expired"), "{body}");
    assert!(h.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn the_crown_w_brand() {
    let a = app("brand");
    // The rail: the lockup (mark and wordmark, once: its gradient and glow
    // filter IDs are fixed) with the tagline under it, the environment right
    // under that, every page in its group, and the one-line footer.
    let (s, _, body) = a.get("/").await;
    assert_eq!(s, StatusCode::OK);
    let rail = &body[body.find(r#"<aside class="rail">"#).unwrap()..body.find("</aside>").unwrap()];
    assert_eq!(rail.matches(r#"class="cw""#).count(), 1);
    assert!(rail.contains(r#"class="cw-word""#));
    assert!(rail.contains(r#"filter="url(#pwcw-g)""#));
    let lockup = rail.find(r#"class="lockup home-link""#).unwrap();
    let tagline = rail
        .find(r#"<p class="tagline">Defend every path to privilege.</p>"#)
        .unwrap();
    assert!(lockup < tagline);
    let switcher = rail.find(r#"id="env-switch""#).unwrap();
    let nav = rail.find(r#"<nav class="tabs""#).unwrap();
    assert!(lockup < switcher && switcher < nav);
    let mut at = nav;
    for href in [
        "/",
        "/collect",
        "/runs",
        "/explore",
        "/progress",
        "/automate/schedule",
        "/automate/ticketing",
        "/automate/history",
        "/zones",
        "/mappings",
        "/environments",
        "/settings",
    ] {
        let i = rail[at..]
            .find(&format!(r#"<a href="{href}""#))
            .unwrap_or_else(|| panic!("{href} missing or out of order"));
        at += i + 1;
    }
    // One Analyze entry, opening on Collect from Active Directory.
    assert!(!rail.contains(r#"<a href="/analyze""#));
    assert_eq!(rail.matches(r#"<a href="/collect""#).count(), 1);
    assert!(rail.contains(r#"<span class="tl-group" aria-hidden="true">Configure</span>"#));
    // About Pathwarden: the version, the website and the coffee page.
    assert!(rail.contains(&format!("Pathwarden {}", env!("CARGO_PKG_VERSION"))));
    assert!(rail.contains(r#"href="https://pathwarden.org""#));
    assert!(rail.contains(r#"href="https://buymeacoffee.com/marbasec""#));
    assert!(rail.contains(r#"href="https://github.com/marbas207/Pathwarden/issues/new""#));
    assert!(rail.contains(r#"href="https://github.com/marbas207/Pathwarden/releases""#));
    assert!(!rail.contains("Reports saved in"));
    assert!(rail.contains(r#"id="theme-toggle""#) && rail.contains(r#"action="/stop""#));
    let (_, _, envs) = a.get("/environments").await;
    assert!(envs.contains(r#"href="/environments" aria-current="page""#));
    // Favicons and the web app manifest, under /static/brand/ (a profile
    // that cached the old lighthouse at /static/favicon.svg fetches them
    // anew): the adaptive SVG, PNGs from 16 to 64 px on the navy tile, the
    // Apple touch icon, and the manifest with its 192 and 512 px icons (an
    // Edge or Chrome app window's title bar and taskbar).
    for link in [
        r#"<link rel="icon" href="/static/brand/favicon.svg" type="image/svg+xml">"#,
        r#"href="/static/brand/favicon-16.png" sizes="16x16""#,
        r#"href="/static/brand/favicon-32.png" sizes="32x32""#,
        r#"href="/static/brand/favicon-48.png" sizes="48x48""#,
        r#"href="/static/brand/favicon-64.png" sizes="64x64""#,
        r#"<link rel="apple-touch-icon" href="/static/brand/apple-touch-icon.png">"#,
        r#"<link rel="manifest" href="/static/brand/site.webmanifest">"#,
    ] {
        assert!(body.contains(link), "{link}");
    }
    let (_, h, _) = a.get("/").await;
    assert!(h[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("manifest-src 'self'"));
    // All public: a browser fetches the manifest without cookies, and the
    // pages shown before a session link them too. Nothing else is.
    for uri in ["/static/brand/favicon.svg", "/static/favicon.svg"] {
        let (s, h, svg) = a.open_link(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert_eq!(h[header::CONTENT_TYPE], "image/svg+xml");
        assert!(svg.contains("prefers-color-scheme: light"));
        assert!(h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("style-src 'unsafe-inline'"));
    }
    let (s, h, manifest) = a.open_link("/static/brand/site.webmanifest").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "application/manifest+json");
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["name"], "Pathwarden");
    let icons = manifest["icons"].as_array().unwrap();
    let srcs: Vec<&str> = icons.iter().map(|i| i["src"].as_str().unwrap()).collect();
    assert_eq!(
        srcs,
        [
            "/static/brand/icon-192.png",
            "/static/brand/icon-512.png",
            "/static/brand/icon-maskable-512.png"
        ]
    );
    assert!(icons.iter().any(|i| i["purpose"] == "maskable"));
    for (uri, px) in [
        ("/static/brand/favicon-16.png", 16),
        ("/static/brand/favicon-32.png", 32),
        ("/static/brand/favicon-48.png", 48),
        ("/static/brand/favicon-64.png", 64),
        ("/static/favicon-32.png", 32),
        ("/static/brand/apple-touch-icon.png", 180),
        ("/static/brand/icon-192.png", 192),
        ("/static/brand/icon-512.png", 512),
        ("/static/brand/icon-maskable-512.png", 512),
    ] {
        let req = Request::get(uri)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        let res = a.router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        assert_eq!(res.headers()[header::CONTENT_TYPE], "image/png", "{uri}");
        let png = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&png[1..4], b"PNG", "{uri}");
        let w = u32::from_be_bytes(png[16..20].try_into().unwrap());
        assert_eq!(w, px, "{uri}");
    }
    let (s, h, _) = a.open_link("/favicon.ico").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "image/x-icon");
    for uri in ["/static/app.css", "/static/brand/", "/static/brand/x.png"] {
        assert_eq!(a.open_link(uri).await.0, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // Not found and bare pages link the icons too.
    let (_, _, missing) = a.get("/no-such-page").await;
    assert!(missing.contains(r#"<link rel="manifest" href="/static/brand/site.webmanifest">"#));
    // A bare page (no session, no stylesheet) carries the small mark.
    let (s, _, bare) = a.open_link("/?token=0000").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(bare.contains(r#"class="cw""#), "{bare}");
    assert!(bare.contains(r#"<link rel="icon" href="/static/brand/favicon.svg""#));
}

#[tokio::test]
async fn sessions_end_when_idle_and_after_the_limit() {
    let a = app_with("idle", |s| {
        s.sessions.policy.idle = Duration::from_millis(150);
        s.sessions.policy.absolute = Duration::from_secs(60);
    });
    let cookie = a.cookie();
    assert_eq!(a.get_with("/", &cookie).await.0, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (s, h, body) = a.get_with("/", &cookie).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.contains("Your session has ended"), "{body}");
    assert!(h[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));

    // Being busy does not stretch a session past its absolute limit.
    let a = app_with("absolute", |s| {
        s.sessions.policy.idle = Duration::from_secs(60);
        s.sessions.policy.absolute = Duration::from_millis(300);
    });
    let cookie = a.cookie();
    for _ in 0..3 {
        assert_eq!(a.get_with("/", &cookie).await.0, StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a.get_with("/", &cookie).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stop_signs_out_and_stops_the_server() {
    let a = app("stop");
    let cookie = a.cookie();
    let other = a.cookie();
    // The rail offers it on every page, with a confirmation.
    let (_, _, body) = a.get_with("/", &cookie).await;
    assert!(body.contains(r#"action="/stop""#));
    assert!(body.contains("data-confirm="));
    // Like every change, it needs this server's origin when one is given.
    let req = Request::post("/stop")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    let req = Request::post("/stop")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::empty())
        .unwrap();
    let (s, h, body) = a.send(req).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Pathwarden has stopped"));
    assert!(h[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    // The server was told to stop (the permit is waiting).
    tokio::time::timeout(Duration::from_secs(1), a.state.stop.notified())
        .await
        .expect("stop notified");
    // Every session, and the unused link, is gone.
    for c in [&cookie, &other] {
        let (s, _, body) = a.get_with("/", c).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(body.contains("Your session has ended"));
    }
    let (s, _, _) = a.open_link(&format!("/?token={}", a.link.expose())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_exchange_redirects_only_to_local_paths() {
    let a = app("redirect");
    for (path, want) in [
        // Browsers read `/\host` as `//host`, another site.
        ("/\\evil.example", "/"),
        ("/\\\\evil.example", "/"),
        ("//evil.example", "/"),
        // Encoded, it is only a path on this server.
        ("/%5Cevil.example", "/%5Cevil.example"),
        ("/runs", "/runs"),
    ] {
        let link = a.state.sessions.new_link().unwrap();
        let (s, h, _) = a
            .open_link(&format!("{path}?token={}", link.expose()))
            .await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(h[header::LOCATION], want, "{path}");
    }
}

#[tokio::test]
async fn state_changes_from_other_origins_are_refused() {
    let a = app("origin");
    let req = a
        .request(Method::POST, "/api/demo")
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    let req = a
        .request(Method::DELETE, "/api/runs/20261001-020000-abcdef")
        .header(header::ORIGIN, "http://127.0.0.1:9999")
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    let req = a
        .request(Method::DELETE, "/api/runs/20261001-020000-abcdef")
        .header(header::ORIGIN, "null")
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
}

/// A change must say it comes from this server's pages (gap 13):
/// `Origin` naming it (127.0.0.1 or localhost), or, without `Origin`,
/// `Sec-Fetch-Site: same-origin`. One that says neither, or says another
/// site, is refused on POST, PUT and DELETE; reading needs neither.
#[tokio::test]
async fn changes_must_say_they_come_from_this_server() {
    let a = app("same-origin");
    let run = "/api/runs/20261001-020000-abcdef";
    let refused = |method: Method, extra: &[(&str, &str)]| {
        let mut r = a.request(method, run);
        for (k, v) in extra {
            r = r.header(*k, *v);
        }
        r.body(Body::empty()).unwrap()
    };
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        for extra in [
            &[][..],
            &[("sec-fetch-site", "same-site")][..],
            &[("sec-fetch-site", "cross-site")][..],
            &[("sec-fetch-site", "none")][..],
            // Origin wins: a wrong one is refused whatever else is said.
            &[
                ("origin", "http://evil.example"),
                ("sec-fetch-site", "same-origin"),
            ][..],
            &[("origin", "https://127.0.0.1:4242")][..],
        ] {
            let (s, _, body) = a.send(refused(method.clone(), extra)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{method} {extra:?}: {body}");
            assert!(body.contains("another site refused"), "{body}");
        }
    }
    // This server's own pages get through the guard (the route then says
    // the run doesn't exist, or the method isn't allowed).
    for extra in [
        &[("origin", "http://127.0.0.1:4242")][..],
        &[("origin", "http://localhost:4242")][..],
        &[("sec-fetch-site", "same-origin")][..],
        &[("sec-fetch-site", "Same-Origin")][..],
    ] {
        let (s, _, body) = a.send(refused(Method::DELETE, extra)).await;
        assert_ne!(s, StatusCode::FORBIDDEN, "{extra:?}: {body}");
        assert!(!body.contains("another site refused"), "{body}");
    }
    let (s, _, _) = a.get("/").await;
    assert_eq!(s, StatusCode::OK);
}

/// "Since the last run" for the app: `null` until there is an earlier run,
/// then the shared comparison (`pathwarden history --since --json` prints
/// the same; `tests/history.rs` in the CLI checks that side).
#[tokio::test]
async fn the_since_route_serves_the_shared_comparison() {
    let a = app("since");
    let (s, _, body) = a.get("/api/history/since").await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "null"));
    let forest = testdata("forest");
    for i in 0..2 {
        if i > 0 {
            // A second later, so the history orders the two runs.
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        let (s, body) = a
            .post_form(
                "/api/analyze",
                &[(
                    "path",
                    None,
                    format!("\"{}\"", forest.display()).into_bytes(),
                )],
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{body}");
        assert_eq!(a.wait(&job_id(&body)).await["status"], "done");
    }
    let (s, _, body) = a.get("/api/history/since").await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let got: serde_json::Value = serde_json::from_str(&body).unwrap();
    // With the status keys' 1.0 names beside the old ones.
    let want = pathwarden_core::status_keys::to_value(
        &pathwarden_ui::history_ui::since(&a.state.ws(), None)
            .unwrap()
            .expect("an earlier run"),
    )
    .unwrap();
    assert_eq!(got, want);
    // The same data twice: one line, saying nothing changed.
    assert_eq!(got["lines"][0]["tone"], "same", "{got}");
    assert!(
        got["previous_run"].as_str().unwrap().ends_with('Z'),
        "{got}"
    );
}

#[tokio::test]
async fn a_path_produces_a_run_and_a_report() {
    let a = app("path");
    let forest = testdata("forest");
    // First launch: the welcome and its three ways in.
    let (_, _, first) = a.get("/").await;
    assert!(first.contains(r#"class="welcome card""#) && !first.contains("env-card"));
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[(
                "path",
                None,
                format!("\"{}\"", forest.display()).into_bytes(),
            )],
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let id = job_id(&body);
    let done = a.wait(&id).await;
    assert_eq!(done["status"], "done", "{done}");
    assert_eq!(done["run"], id.as_str());
    // No demo, no step for its earlier runs.
    assert!(done.get("earlier").is_none(), "{done}");

    let summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(a.state.ws().runs_dir().join(&id).join("summary.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(summary["domains"][1], "CONTOSO.LOCAL");
    assert_eq!(summary["source"], forest.display().to_string().as_str());

    let (s, _, page) = a.get(&format!("/runs/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("CONTOSO.LOCAL"));
    // The frame's address carries the page's nonce for Run details.
    assert!(page.contains(&format!(r#"src="/runs/{id}/report?embed=1&amp;rd="#)));
    assert!(!page.contains("rd-below"), "the report carries Run details");
    // One run ID for users: the history's, which also opens the page.
    let run_id = summary["history"]["run_id"].as_str().unwrap().to_string();
    assert!(run_id.contains('T') && run_id.ends_with('Z'), "{run_id}");
    // Its Run details tab (in the embedded report) names it.
    let (_, _, details) = a.get(&format!("/runs/{id}/report?embed=1")).await;
    assert!(
        details.contains(&format!("<dt>Run ID</dt><dd><code>{run_id}</code>")),
        "{details}"
    );
    assert!(!details.contains(&format!("<code>{id}</code>")));
    assert!(details.contains("<dt>Recorded</dt><dd>On this computer</dd>"));
    assert!(details.contains(r#"data-pw-run="remove""#) && details.contains("Delete run"));
    // Not in the report itself, and the page has no Delete button of its
    // own: only the trigger the tab's button asks for.
    let (_, _, full) = a.get(&format!("/runs/{id}/report")).await;
    assert!(!full.contains("Run details"));
    assert!(
        !page.contains(r#"class="btn danger""#),
        "no Delete in the header"
    );
    assert!(page.contains(&format!(r#"class="rd-delete" data-delete="{id}""#)));
    assert!(
        !page.contains(&format!("<code>{run_id}</code>")),
        "not in the header"
    );
    let (s, h, _) = a.get(&format!("/runs/{run_id}")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], format!("/runs/{id}").as_str());
    assert_eq!(
        a.get("/runs/20200101T000000.000Z").await.0,
        StatusCode::NOT_FOUND
    );
    let event: serde_json::Value = serde_json::from_slice(
        &pathwarden_ui::run_data::read_gz(&a.state.ws().runs_dir().join(&id).join("event.json.gz"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(event["run"]["run_id"], run_id.as_str());

    let (s, h, report) = a.get(&format!("/runs/{id}/report")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(report.starts_with("<!doctype html>"));
    assert!(report.contains("Remediation path"));
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("sandbox allow-scripts"), "{csp}");
    assert_eq!(h[header::X_FRAME_OPTIONS], "SAMEORIGIN");
    assert!(h.get(header::CONTENT_DISPOSITION).is_none());

    assert!(!report.contains(".brand,.meta,.rail-foot"));
    let (_, _, light) = a
        .get(&format!("/runs/{id}/report?embed=1&theme=light"))
        .await;
    assert!(light.contains(r#"<html lang="en" data-theme="light">"#));
    assert!(light.contains(".brand,.meta,.rail-foot{display:none"));
    let (_, h, _) = a.get(&format!("/runs/{id}/report?download=1")).await;
    assert!(h[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("attachment;"));

    // With a run, Home is a dashboard: the latest report's Overview per
    // environment (its links to the run page), the ways in as a menu, times
    // local in the browser (UTC until then).
    let (_, _, home) = a.get("/").await;
    assert!(home.contains(&format!("/runs/{id}")));
    assert!(home.contains(r#"<section class="env-ov">"#) && home.contains(" Analyze <svg"));
    assert!(home.contains(r#"<div class="hero card"#), "{home}");
    assert!(home.contains(r#"class="ov-cards""#), "{home}");
    assert!(!home.contains(r##"<a href="#"##), "{home}");
    assert!(!home.contains(r#"class="welcome card""#));
    assert!(home.contains(r#"data-fmt="full""#));
    let (_, _, runs) = a.get("/runs").await;
    assert!(runs.contains("CONTOSO.LOCAL"));
    // Each row against the run before; this is the first.
    assert!(runs.contains("Since the previous run") && runs.contains("First run"));

    // Delete it.
    let req = a
        .request(Method::DELETE, &format!("/api/runs/{id}"))
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::NO_CONTENT);
    assert_eq!(a.get(&format!("/runs/{id}")).await.0, StatusCode::NOT_FOUND);
    assert!(!a.state.ws().runs_dir().join(&id).exists());
    // The input folder is the user's own: never deleted.
    assert!(forest.join("contoso_users.json").exists());
}

#[tokio::test]
async fn uploads_produce_a_run_and_are_deleted() {
    let a = app("upload");
    let files: Vec<(String, Vec<u8>)> = std::fs::read_dir(testdata("forest"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    let parts: Vec<(&str, Option<&str>, Vec<u8>)> = files
        .iter()
        .map(|(n, c)| ("files", Some(n.as_str()), c.clone()))
        .collect();
    let (s, body) = a.post_form("/api/analyze", &parts).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let id = job_id(&body);
    let done = a.wait(&id).await;
    assert_eq!(done["status"], "done", "{done}");
    assert!(
        a.uploads_empty(),
        "uploads should be deleted after analysis"
    );
    let summary = a.state.ws().summary(&id).unwrap();
    assert_eq!(summary.source, format!("{} uploaded files", files.len()));
    assert_eq!(summary.domains, ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"]);
    let (s, _, report) = a.get(&format!("/runs/{id}/report")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(report.contains("CONTOSO.LOCAL"));
}

#[tokio::test]
async fn bad_input_fails_plainly() {
    let a = app("bad");
    // Not a collector file type.
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[("files", Some("notes.txt"), b"hi".to_vec())],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("isn't a .zip or .json file"), "{body}");
    assert!(a.uploads_empty());

    // Nothing chosen.
    let (s, body) = a
        .post_form("/api/analyze", &[("path", None, Vec::new())])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("Choose collector files"), "{body}");

    // A path that does not exist (on this computer: a drive letter could
    // be a mapped network drive, refused before it is looked at).
    let missing = std::env::temp_dir()
        .join(format!("pw-missing-{}", std::process::id()))
        .join("exist.zip");
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[("path", None, missing.to_string_lossy().as_bytes().to_vec())],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("Nothing found at"), "{body}");

    // A path field is short: a huge one is refused without reading it all.
    let (s, body) = a
        .post_form("/api/analyze", &[("path", None, vec![b'a'; 64 * 1024])])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("too long"), "{body}");

    // Network paths are refused before anything looks at them.
    for p in [
        r"\\pathwarden-unc-test.invalid\share\x.zip",
        "//pathwarden-unc-test.invalid/share/x.zip",
        r#""\\?\UNC\pathwarden-unc-test.invalid\share""#,
    ] {
        let (s, body) = a
            .post_form("/api/analyze", &[("path", None, p.as_bytes().to_vec())])
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{p}");
        assert!(body.contains("network path"), "{body}");
    }

    // A folder without collector files.
    let empty = a.dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[("path", None, empty.display().to_string().into_bytes())],
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let done = a.wait(&job_id(&body)).await;
    assert_eq!(done["status"], "failed");
    assert!(
        done["error"]
            .as_str()
            .unwrap()
            .starts_with("No collector files found"),
        "{done}"
    );

    // A file that is not collector data fails plainly, and its upload goes.
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[(
                "files",
                Some("20240410083609_users.json"),
                b"{not json".to_vec(),
            )],
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let done = a.wait(&job_id(&body)).await;
    assert_eq!(done["status"], "failed");
    let error = done["error"].as_str().unwrap();
    assert!(error.starts_with("No collector files found"), "{error}");
    assert!(a.uploads_empty());
    assert!(a.state.ws().runs().is_empty());
}

#[tokio::test]
async fn upload_limits_are_enforced() {
    let a = app_with("limits", |s| {
        s.limits = Limits {
            per_file: 1000,
            total: 1500,
        }
    });
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[("files", Some("a.json"), vec![b' '; 1001])],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("the most one file can be"), "{body}");
    let (s, body) = a
        .post_form(
            "/api/analyze",
            &[
                ("files", Some("a.json"), vec![b' '; 900]),
                ("files", Some("b.json"), vec![b' '; 900]),
            ],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("the most one analysis can take"), "{body}");
    assert!(a.uploads_empty());
}

#[tokio::test]
async fn run_id_traversal_is_rejected() {
    let a = app("traversal");
    // Something that must stay out of reach.
    std::fs::write(a.dir.join("secret.html"), "secret").unwrap();
    std::fs::create_dir_all(a.state.ws().runs_dir().join("x")).unwrap();
    std::fs::write(a.state.ws().runs_dir().join("x").join("summary.json"), "{}").unwrap();
    for uri in [
        "/runs/..%2Fsecret.html",
        "/runs/..%2F..%2Fsecret.html/report",
        "/runs/../secret.html",
        "/runs/%2E%2E/report",
        "/runs/x",
        "/runs/x/report",
        "/runs/20261001-020000-abcdef",
        "/runs/20261001-020000-abcdef/report",
    ] {
        let (s, _, body) = a.get(uri).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
        assert!(!body.contains("secret"), "{uri}");
    }
    for uri in ["/api/runs/..%2F..", "/api/runs/x", "/api/runs/%2E%2E"] {
        let req = a
            .request(Method::DELETE, uri)
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(a.send(req).await.0, StatusCode::BAD_REQUEST, "{uri}");
    }
    assert!(a.state.ws().runs_dir().join("x").exists());
    assert!(a.dir.join("secret.html").exists());
    let (s, _, _) = a.get("/api/jobs/..%2F..").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_demo_is_built_in() {
    let a = app("demo");
    let req = a
        .request(Method::POST, "/api/demo")
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, body) = a.send(req).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let id = job_id(&body);
    // Only one analysis at a time.
    let req = a
        .request(Method::POST, "/api/demo")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let (s, _, body) = a.send(req).await;
    if s != StatusCode::ACCEPTED {
        assert_eq!(s, StatusCode::CONFLICT, "{body}");
    } else {
        a.wait(&job_id(&body)).await;
    }
    // Its progress only goes forward, though its earlier runs and
    // its own data are read again before it is saved.
    const PHASES: [&str; 5] = ["reading", "graph", "rules", "remediation", "report"];
    let mut seen: Vec<String> = Vec::new();
    // Its earlier runs have a step of their own, after Checking for
    // weaknesses, counting up while they are built.
    let total = pathwarden_ui::demo_runs::EARLIER.len();
    let mut counts: Vec<u64> = Vec::new();
    let done = loop {
        let (s, _, body) = a.get(&format!("/api/jobs/{id}")).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        if v["status"] != "running" {
            break v;
        }
        let phase = v["phase"].as_str().unwrap_or_default().to_string();
        if seen.last() != Some(&phase) {
            seen.push(phase.clone());
        }
        assert!(
            v["reading"].is_null() || seen.len() == 1,
            "read again after {seen:?}: {v}"
        );
        if let Some(n) = v["earlier"]["done"].as_u64() {
            assert_eq!(v["earlier"]["total"], total, "{v}");
            if (n as usize) < total {
                assert_eq!(phase, "rules", "built after {seen:?}: {v}");
            }
            if counts.last() != Some(&n) {
                counts.push(n);
            }
        } else {
            assert!(counts.is_empty(), "the count went away: {v}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(done["status"], "done", "{done}");
    assert_eq!(done["earlier"]["done"], total, "{done}");
    assert!(counts.windows(2).all(|w| w[0] < w[1]), "{counts:?}");
    assert!(counts.len() >= 2 && counts[0] < total as u64, "{counts:?}");
    let at: Vec<usize> = seen
        .iter()
        .map(|p| PHASES.iter().position(|q| q == p).expect("a known phase"))
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{seen:?}");
    let summary = a.state.ws().summary(&id).unwrap();
    assert!(summary.demo);
    assert_eq!(summary.domains, ["SCALE.LOCAL"]);
    assert!(summary.collected_at.is_some());
    assert!(a.uploads_empty());
    // The first demo brings its earlier runs, eight days apart before it,
    // recorded in the demo environment's own history, and the demo's zone.
    let ws = a.state.ws();
    let demo_ws = ws.in_env(ws.registry().demo_id().expect("the demo environment"));
    let mut runs = demo_ws.runs();
    runs.sort_by_key(|r| r.created_at);
    assert!(runs.len() >= 5, "{}", runs.len());
    let gap = pathwarden_ui::demo_runs::GAP;
    for w in runs[..4].windows(2) {
        assert_eq!(
            w[1].created_at - w[0].created_at,
            gap,
            "{:?}",
            (&w[0].id, &w[1].id)
        );
    }
    // The demo's own run is dated when it finished, a little after.
    assert!(runs[4].created_at - runs[3].created_at >= gap);
    assert!(runs.iter().all(|r| r.demo && r.history.is_some()));
    // Now there is a demo environment, the pages hide Try the demo.
    let (_, _, home) = a.get("/").await;
    assert!(home.contains(r#"<body class="app has-demo" data-pulled="0""#));
    let config = std::fs::read_to_string(demo_ws.config_path()).unwrap();
    assert!(config.contains("R01 servers"), "{config}");
    let (points, _) = pathwarden_core::history::load(
        &pathwarden_ui::history_ui::locate(&demo_ws, None)
            .unwrap()
            .dir,
    )
    .unwrap();
    assert!(points.len() >= 5, "{}", points.len());
    let (_, _, page) = a.get("/analyze").await;
    assert!(page.contains("Where does the data come from?"), "{page}");
    // The earlier runs' step is there, hidden until they are built.
    assert!(page.contains(r#"<li data-step="earlier" hidden><span class="st"></span><span class="sl">Building the demo's earlier runs <span class="muted" id="earlier-n"></span></span></li>"#), "{page}");
    // Analyze asks where the data comes from: a previous collection here,
    // with one box to drop, browse or paste; the wizard a link away. The
    // menu has no Collect of its own.
    assert!(page.contains(r#"<a class="src-choice on" href="/analyze" aria-current="page">"#));
    assert!(page.contains(r#"<a class="src-choice" href="/collect">"#));
    assert!(page.contains(r#"<div class="source-box">"#));
    assert!(!page.contains(r#"<span class="tl">Collect</span>"#));
}

#[test]
fn workspace_reopens_clean() {
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-reopen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    std::fs::create_dir_all(ws.uploads_dir().join("leftover")).unwrap();
    std::fs::create_dir_all(ws.runs_dir().join(".20261001-020000-abcdef")).unwrap();
    let ws = Workspace::open(&dir).unwrap();
    assert!(std::fs::read_dir(ws.uploads_dir())
        .unwrap()
        .next()
        .is_none());
    assert!(!Path::new(&ws.runs_dir().join(".20261001-020000-abcdef")).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A page's wait asks whether a run is being read into memory: no
/// run is, here; every page carries the script that asks.
#[tokio::test]
async fn a_wait_asks_whether_a_run_is_loading() {
    let a = app("busy");
    let (s, h, body) = a.get("/api/busy").await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(h[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v, serde_json::json!({ "loading_run": false }));
    let (_, _, js) = a.get("/static/app.js").await;
    assert!(js.contains("fetch(\"/api/busy\""), "app.js asks /api/busy");
    assert!(js.contains("Loading this run into memory"));
}
