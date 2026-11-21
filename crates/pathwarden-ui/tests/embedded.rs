//! The embedded transport (experimental `pathwarden ui --window`): requests
//! handed to the router in-process need no link or cookie, but must name the
//! window's own origin, and get the same headers.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::security::{Transport, APP_CSP};
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use tower::ServiceExt;

const ORIGIN: &str = "https://pathwarden.localhost";

struct App {
    router: Router,
    dir: std::path::PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app(name: &str) -> App {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-ui-embedded-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let state = AppState::embedded(ws, ORIGIN).unwrap();
    assert_eq!(
        state.transport,
        Transport::Embedded {
            origin: ORIGIN.into()
        }
    );
    App {
        router: router(Arc::new(state)),
        dir,
    }
}

async fn send(app: &App, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let res = app.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn get(uri: &str, host: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn pages_need_no_link_or_cookie() {
    let app = app("pages");
    let (status, headers, body) = send(&app, get("/", "pathwarden.localhost")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Pathwarden"));
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], APP_CSP);
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    // So the app's own form posts carry its origin rather than `null`.
    assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
    let (status, _, _) = send(&app, get("/static/app.js", "pathwarden.localhost")).await;
    assert_eq!(status, StatusCode::OK);
    // A token in the address is not a login here: it is just ignored.
    let (status, headers, _) = send(&app, get("/?token=abc", "pathwarden.localhost")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn other_hosts_are_refused() {
    let app = app("hosts");
    for host in ["127.0.0.1:0", "localhost", "attacker.example", ""] {
        let (status, _, _) = send(&app, get("/", host)).await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "{host}");
    }
}

#[tokio::test]
async fn changes_from_other_origins_are_refused() {
    let app = app("origin");
    let delete = |origin: Option<&str>| {
        let mut b = Request::builder()
            .method(Method::DELETE)
            .uri("/api/runs/not-a-run")
            .header(header::HOST, "pathwarden.localhost");
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(Body::empty()).unwrap()
    };
    for bad in ["http://127.0.0.1:1234", "null", "https://evil.example"] {
        let (status, _, _) = send(&app, delete(Some(bad))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{bad}");
    }
    // Its own origin, or none, reaches the handler (which rejects the ID).
    for ok in [Some(ORIGIN), None] {
        let (status, _, _) = send(&app, delete(ok)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ok:?}");
    }
}

#[tokio::test]
async fn analyze_says_files_stay_where_they_are() {
    let app = app("analyze-page");
    let (status, _, body) = send(&app, get("/analyze", "pathwarden.localhost")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Files are read where they are"), "{body}");
    assert!(!body.contains("Uploaded copies are deleted"));
}

/// Files and folders picked or dropped in the window arrive as several
/// `path` fields, and are analyzed together.
#[tokio::test]
async fn several_paths_are_analyzed_together() {
    let app = app("paths");
    let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let boundary = "embeddedPaths";
    let mut body = String::new();
    for name in ["forest", "broad"] {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n",
            data.join(name).display()
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    let req = Request::post("/api/analyze")
        .header(header::HOST, "pathwarden.localhost")
        .header(header::ORIGIN, ORIGIN)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let (status, _, b) = send(&app, req).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{b}");
    let job = serde_json::from_str::<serde_json::Value>(&b).unwrap()["job"]
        .as_str()
        .unwrap()
        .to_string();
    for _ in 0..600 {
        let uri = format!("/api/jobs/{job}");
        let (_, _, body) = send(&app, get(&uri, "pathwarden.localhost")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let source = v["source"].as_str().unwrap_or_default();
        assert!(source.ends_with("forest and 1 more"), "{v}");
        if v["status"] == "done" {
            return;
        }
        assert_ne!(v["status"], "failed", "{v}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("analysis did not finish");
}
