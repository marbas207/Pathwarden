//! "Accept the history as it is", through the router: an older copy
//! put back in an encrypted history is refused, History storage, Runs and
//! the run's page say so with the button and its confirm dialog, and the
//! POST (a session and this server's own pages only) resets this
//! computer's records for that history, as `pathwarden history storage
//! accept` does. This computer's store is a test folder
//! (`PATHWARDEN_TEST_KEYSTORE`, set once for this test binary).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::keystore;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4246";
const PASS: &str = "correct horse battery staple";

struct App {
    router: Router,
    state: Arc<AppState>,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl App {
    fn new(name: &str) -> App {
        let dir = std::env::temp_dir().join(format!(
            "pathwarden-ui-accept-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(dir.join("ws")).unwrap();
        let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), 4246));
        App {
            router: router(state.clone()),
            state,
            dir,
        }
    }

    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> String {
        let (s, b) = self
            .send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, String) {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(req).await
    }

    async fn analyze(&self, path: &Path) {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let boundary = "acceptBoundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"env\"\r\n\r\ndefault\r\n--{boundary}--\r\n",
            path.display()
        );
        let req = self
            .request(Method::POST, "/api/analyze")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        let (s, body) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{body}");
        let job = serde_json::from_str::<Value>(&body).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..2400 {
            let v: Value =
                serde_json::from_str(&self.get(&format!("/api/jobs/{job}")).await).unwrap();
            if !matches!(v["status"].as_str(), Some("running" | "collecting")) {
                assert_eq!(v["status"], "done", "{v}");
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.join("ws").join("pathwarden-state")
    }
}

/// This computer's records of sequences seen, in the test store.
fn records(a: &App) -> usize {
    std::fs::read_dir(a.dir.join("keystore").join("pins").join("sequences"))
        .map(|d| d.flatten().count())
        .unwrap_or(0)
}

const REFUSED: &str = "last-run.json in the history was replaced with an older copy.";
const BUTTON: &str = "Accept the history as it is";
const SAYS: &str =
    "This computer will trust the history&#39;s files as they are now. Do this only \
                    if you restored an older copy on purpose. You can&#39;t undo it.";

#[tokio::test]
async fn an_older_copy_is_accepted_from_the_pages() {
    let a = App::new("flow");
    // The only test in this binary: the variable is set before anything
    // reads it.
    std::env::set_var(keystore::TEST_STORE_ENV, a.dir.join("keystore"));
    std::env::remove_var(keystore::ENV_VAR);
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    a.analyze(&forest).await;
    let state = a.state_dir();
    let (s, b) = a
        .post(
            "/api/history/encryption",
            json!({"on": true, "passphrase": PASS}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    // Nothing refused: no button anywhere.
    let page = a.get("/automate/history").await;
    assert!(!page.contains(BUTTON), "{page}");
    let old = std::fs::read(state.join("last-run.json.age")).unwrap();
    a.analyze(&forest).await;
    assert!(!a.get("/runs").await.contains(BUTTON));
    assert!(records(&a) > 0);
    let env = a.state.env_id();
    // Nothing refused: a POST (a page left open) changes nothing.
    let before = records(&a);
    let (s, b) = a.post("/api/history/accept", json!({ "env": env })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert!(
        b.contains("Nothing needs accepting: the history is fine. Reload the page."),
        "{b}"
    );
    assert_eq!(records(&a), before);

    // Restored from a backup.
    std::fs::write(state.join("last-run.json.age"), &old).unwrap();
    let page = a.get("/automate/history").await;
    assert!(page.contains(REFUSED), "{page}");
    assert!(page.contains(BUTTON), "{page}");
    assert!(
        page.contains(&format!(r#"data-accept-history="{env}""#)),
        "{page}"
    );
    assert!(page.contains(r#"id="accept-history-dialog""#), "{page}");
    assert!(page.contains(SAYS), "{page}");
    assert!(
        !page.contains("pathwarden history storage"),
        "no command hints"
    );
    let runs = a.get("/runs").await;
    assert!(runs.contains(REFUSED) && runs.contains(BUTTON), "{runs}");
    let id = a.state.ws().runs()[0].id.clone();
    let run = a.get(&format!("/runs/{id}")).await;
    assert!(run.contains(REFUSED) && run.contains(BUTTON), "{run}");

    // Only with a session, and from this server's own pages.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/history/accept")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "env": env }).to_string()))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
    let req = a
        .request(Method::POST, "/api/history/accept")
        .header(header::ORIGIN, "http://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "env": env }).to_string()))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    // A page of another environment (switched in another tab).
    let (s, b) = a
        .post("/api/history/accept", json!({ "env": "another" }))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert!(b.contains("Another environment is in use now."), "{b}");
    assert!(a.get("/automate/history").await.contains(REFUSED));
    assert_eq!(records(&a), before);

    // Accepted: the records reset, and nothing is refused any more.
    let (s, b) = a.post("/api/history/accept", json!({ "env": env })).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(records(&a), 0);
    let (s, b) = a.post("/api/history/accept", json!({ "env": env })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert!(
        b.contains("Nothing needs accepting: the history is fine. Reload the page."),
        "{b}"
    );
    let page = a.get("/automate/history").await;
    assert!(!page.contains(REFUSED) && !page.contains(BUTTON), "{page}");
    assert!(!a.get("/runs").await.contains(BUTTON));
    // The next analysis records on top of it.
    a.analyze(&forest).await;
    assert!(!a.get("/automate/history").await.contains(BUTTON));
}
