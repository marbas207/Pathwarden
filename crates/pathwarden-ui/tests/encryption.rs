//! The history's passphrase in the app (slice E), through the router: History
//! storage turns encryption on with a new passphrase, checks and changes it
//! and turns it off; Runs asks for it on a computer without it. The
//! passphrase is never sent back. This computer's store is a test folder
//! (`PATHWARDEN_TEST_KEYSTORE`, set once for this test binary), so no real
//! credential is touched.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::crypt::{self, SecretString};
use pathwarden_core::keystore;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4245";
const PASS: &str = "correct horse battery staple";
const NEW: &str = "a brand new passphrase here";

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
        let dir =
            std::env::temp_dir().join(format!("pathwarden-ui-enc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ws = Workspace::open(dir.join("ws")).unwrap();
        let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), 4245));
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
        let body = String::from_utf8_lossy(&body).into_owned();
        for p in [PASS, NEW, "short pass"] {
            assert!(!body.contains(p), "a passphrase came back: {body}");
        }
        (status, body)
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
        let boundary = "encBoundary";
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

#[tokio::test]
async fn the_passphrase_from_the_pages() {
    let a = App::new("flow");
    // The only test in this binary: the variable is set before anything
    // reads it.
    std::env::set_var(keystore::TEST_STORE_ENV, a.dir.join("keystore"));
    std::env::remove_var(keystore::ENV_VAR);
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    a.analyze(&forest).await;
    let state = a.state_dir();

    // Off: the checkbox, and the setup panel to fill in.
    let page = a.get("/automate/history").await;
    assert!(
        page.contains("Encrypt the history with a passphrase"),
        "{page}"
    );
    assert!(page.contains("Off: the history is kept as plain files."));
    assert!(page.contains("Set passphrase"));
    assert!(
        page.contains("I understand a lost passphrase can&#39;t be recovered")
            || page.contains("I understand a lost passphrase can't be recovered")
    );
    assert!(page.contains("<dt>Encryption</dt><dd>Off</dd>"), "{page}");
    assert!(
        !page.contains("pathwarden history storage"),
        "no command hints"
    );

    // On: refused when short, then with a passphrase stored here.
    let (s, b) = a
        .post(
            "/api/history/encryption",
            json!({"on": true, "passphrase": "short pass"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b.contains("at least 12 characters"), "{b}");
    assert!(!crypt::is_encrypted(&state));
    let (s, b) = a
        .post(
            "/api/history/encryption",
            json!({"on": true, "passphrase": PASS}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(crypt::is_encrypted(&state));
    assert!(keystore::stored_here(&state).unwrap().is_some());
    let page = a.get("/automate/history").await;
    assert!(
        page.contains(
            "<strong>Encrypted</strong> · passphrase stored on this computer (the test keystore)"
        ),
        "{page}"
    );
    assert!(page.contains("On (passphrase)"));
    assert!(page.contains("Change passphrase") && page.contains("Check passphrase"));
    assert!(page.contains("Readers need repository access and the passphrase."));
    // Against reusing one passphrase for several histories.
    assert!(page.contains("Give each history its own passphrase."));
    assert!(page.contains("1 run, the latest"), "{page}");
    let (s, b) = a.post("/api/history/passphrase/check", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.contains("The passphrase works."), "{b}");

    // Another session on a computer without it: Runs asks.
    keystore::forget(&state).unwrap();
    let runs = a.get("/runs").await;
    assert!(runs.contains("This history is encrypted"), "{runs}");
    assert!(runs.contains("Remember on this computer"));
    assert!(runs.contains("Open the history"));
    assert!(runs.contains("On this computer"));
    let page = a.get("/automate/history").await;
    assert!(
        page.contains("passphrase not stored on this computer"),
        "{page}"
    );
    assert!(page.contains("Enter the passphrase on Runs"), "{page}");
    // "Numbers with names": no Full runs fact (the CLI test checks its
    // words for a locked history at "Full runs and settings").
    assert!(!page.contains("<dt>Full runs</dt>"), "{page}");
    // A link kept to a run only the history has: the gate, not "not found".
    let run = a.get("/runs/20261020T060000.455Z").await;
    assert!(run.contains(r#"id="enc-gate""#), "{run}");
    assert!(
        run.contains("Enter the passphrase to open this run."),
        "{run}"
    );
    assert!(!run.contains("On this computer</h2>"), "{run}");
    let (s, b) = a.post("/api/history/passphrase/check", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        b.contains("No passphrase for this history is stored on this computer."),
        "{b}"
    );
    let (s, b) = a
        .post(
            "/api/history/passphrase/open",
            json!({"passphrase": "not the passphrase", "remember": true}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        b.contains("That passphrase doesn't open this history."),
        "{b}"
    );
    assert!(
        keystore::stored_here(&state).unwrap().is_none(),
        "a wrong one is never stored"
    );
    // For this session only.
    let (s, b) = a
        .post(
            "/api/history/passphrase/open",
            json!({"passphrase": PASS, "remember": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(!a.get("/runs").await.contains("This history is encrypted"));
    assert!(keystore::stored_here(&state).unwrap().is_none());
    assert!(a
        .get("/automate/history")
        .await
        .contains("passphrase given for this session only"));
    // Remembered.
    crypt::forget_in_process(&state);
    assert!(a.get("/runs").await.contains("This history is encrypted"));
    let (s, b) = a
        .post(
            "/api/history/passphrase/open",
            json!({"passphrase": PASS, "remember": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(keystore::stored_here(&state).unwrap().is_some());

    // Change: every file again; the stored copy follows.
    let (s, b) = a
        .post("/api/history/passphrase/change", json!({"new": NEW}))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(crypt::opens(&state, &SecretString::from(NEW.to_string())).unwrap());
    assert!(!crypt::opens(&state, &SecretString::from(PASS.to_string())).unwrap());
    crypt::forget_in_process(&state);
    let (s, b) = a.post("/api/history/passphrase/check", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");

    // Off.
    let (s, b) = a
        .post("/api/history/encryption", json!({"on": false}))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(!crypt::is_encrypted(&state));
    let page = a.get("/automate/history").await;
    assert!(page.contains("<dt>Encryption</dt><dd>Off</dd>"));
    keystore::forget(&state).unwrap();
}
