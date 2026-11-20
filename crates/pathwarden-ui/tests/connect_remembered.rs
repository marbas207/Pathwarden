//! Connect to a run history whose passphrase this computer already
//! keeps: an environment remembered it, was removed, and a new one
//! connects to the same history. The page opens it without the passphrase
//! and Connect uses that one; a passphrase here that doesn't open it shows
//! the passphrase again, with why. Its own test binary: the test keystore
//! and the passphrase variable are this process's.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::config::{StateBackend, StateConfig};
use pathwarden_core::crypt::SecretString;
use pathwarden_core::store::Store;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4262";
const PASS: &str = "correct horse battery staple";

fn git() -> Command {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    c
}

fn git_ok() -> bool {
    let ok = git()
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
    }
    ok
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

struct App {
    router: Router,
    state: Arc<AppState>,
}

impl App {
    fn new(ws: Workspace) -> Self {
        // Connect sets where the history is kept: as `pathwarden ui --allow-destinations`.
        let mut state = AppState::new(ws, Token::generate().unwrap(), 4262);
        state.allow_destinations = true;
        let state = Arc::new(state);
        App {
            router: router(state.clone()),
            state,
        }
    }

    async fn get(&self, uri: &str) -> String {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&b).into_owned()
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let s = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// Looks at `remote`: the probe's token.
    async fn probe(&self, remote: &Path) -> String {
        let (s, r) = self
            .post(
                "/api/connect/probe",
                json!({"kind": "git", "url": slash(remote)}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{r}");
        r["token"].as_str().unwrap().to_string()
    }
}

/// A run history on `remote`, encrypted with [`PASS`] by another
/// computer (its working copy in `work`); this process knows no key after.
fn encrypted_history(remote: &Path, work: &Path) {
    assert!(git()
        .args(["init", "-q", "--bare"])
        .arg(remote)
        .status()
        .unwrap()
        .success());
    let cfg = StateConfig {
        backend: StateBackend::Git,
        remote: Some(slash(remote)),
        branch: Some("main".into()),
        ..StateConfig::default()
    };
    Store::new(&cfg, Some(work))
        .unwrap()
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    pathwarden_core::crypt::forget_all_in_process();
}

/// Removes environment `id` as the Remove environment page does.
fn remove_env(ws: &Workspace, id: &str) {
    let plan = pathwarden_ui::env_remove::plan(ws.root(), id, None).unwrap();
    pathwarden_ui::env_remove::remove(ws.root(), id, None, Some(plan.runs_key.as_str())).unwrap();
}

/// The history folder of environment `id`.
fn history_dir(ws: &Workspace, id: &str) -> PathBuf {
    pathwarden_ui::history_ui::locate(&ws.in_env(id), None)
        .unwrap()
        .dir
}

#[tokio::test]
async fn a_passphrase_kept_here_opens_and_connects() {
    if !git_ok() {
        return;
    }
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "pathwarden-ui-connect-remembered-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    pathwarden_core::keystore::use_test_store(&dir.join("keystore"));
    let remote = dir.join("shared.git");
    encrypted_history(&remote, &dir.join("a-work"));
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let a = App::new(ws.clone());

    // Environment Lab connects, with its passphrase remembered here.
    let token = a.probe(&remote).await;
    let page = a.get(&format!("/environments/connect?s={token}")).await;
    assert!(page.contains("Enter the passphrase to open it"), "{page}");
    let (s, r) = a
        .post(
            "/api/connect/open",
            json!({"s": token, "passphrase": PASS, "remember": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (s, r) = a
        .post("/api/connect/go", json!({"s": token, "name": "Lab"}))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let lab = history_dir(&ws, "lab");
    assert!(pathwarden_core::keystore::stored_here(&lab)
        .unwrap()
        .is_some());

    // Lab is removed; its passphrase stays in this computer's store.
    remove_env(&ws, "lab");
    assert!(!lab.exists());

    // 1. In the same app session (the key still open in this process),
    // then 2. after the app starts again (only the store has it).
    // Round 2 says it opens with another history's passphrase, offers to
    // type one instead, and its Remember is ticked: left ticked in round 2,
    // unticked in round 3 (then it isn't kept for the new folder).
    const ANOTHER: &str =
        "This history opens with the passphrase kept on this computer for another history.";
    for (round, name) in [(1, "Lab again"), (2, "Lab once more"), (3, "Not kept")] {
        if round > 1 {
            pathwarden_core::crypt::forget_all_in_process();
        }
        let token = a.probe(&remote).await;
        let page = a.get(&format!("/environments/connect?s={token}")).await;
        assert!(
            !page.contains("Enter the passphrase to open it"),
            "round {round}: no passphrase asked: {page}"
        );
        for want in ["Encrypted.", "Connect and sync"] {
            assert!(page.contains(want), "round {round}: {want}");
        }
        // Remember is offered; ticked for one kept on this computer (in
        // round 1 the key was opened here with the passphrase as typed).
        assert!(
            page.contains(r#"<input type="checkbox" id="cx-remember"#),
            "round {round}: Remember: {page}"
        );
        if round > 1 {
            assert!(
                page.contains(r#"<input type="checkbox" id="cx-remember" checked>"#),
                "round {round}: Remember, ticked: {page}"
            );
        }
        assert_eq!(page.contains(ANOTHER), round > 1, "round {round}: {page}");
        if round > 1 {
            assert!(page.contains("Use a different passphrase"), "{page}");
            let typed = a
                .get(&format!("/environments/connect?s={token}&pass=1"))
                .await;
            assert!(typed.contains("Enter the passphrase to open it"), "{typed}");
        }
        let remember = round != 3;
        let (s, r) = a
            .post(
                "/api/connect/go",
                json!({"s": token, "name": name, "remember": remember}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "round {round}: {r}");
        let id = a.state.env_id();
        let here = history_dir(&ws, &id);
        // Kept for the new folder as Remember says: it opens after the
        // next start only then.
        assert_eq!(
            pathwarden_core::keystore::stored_here(&here)
                .unwrap()
                .is_some(),
            remember,
            "round {round}"
        );
        if remember {
            pathwarden_core::crypt::forget_all_in_process();
            assert!(pathwarden_core::store::check_readable(&here).is_ok());
        }
        remove_env(&ws, &id);
    }

    // Another history's passphrase is tried only for the key file it was
    // kept for: one recorded for another key is passed over, and so is one
    // kept before the key was recorded with it (before 0.2), with
    // the reason on the page.
    const OLD: &str = "Enter this history&#39;s passphrase once.";
    let keys: Vec<PathBuf> = std::fs::read_dir(dir.join("keystore"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "key"))
        .collect();
    assert!(!keys.is_empty());
    for k in &keys {
        std::fs::write(k, "0".repeat(64)).unwrap();
    }
    pathwarden_core::crypt::forget_all_in_process();
    let token = a.probe(&remote).await;
    let page = a.get(&format!("/environments/connect?s={token}")).await;
    assert!(page.contains("Enter the passphrase to open it"), "{page}");
    assert!(!page.contains(OLD), "{page}");
    for k in &keys {
        std::fs::remove_file(k).unwrap();
    }
    pathwarden_core::crypt::forget_all_in_process();
    let page = a.get(&format!("/environments/connect?s={token}")).await;
    assert!(!page.contains(ANOTHER), "{page}");
    assert!(page.contains("Enter the passphrase to open it"), "{page}");
    assert!(page.contains(OLD), "{page}");
    a.post("/api/connect/cancel", json!({"s": token})).await;

    // A passphrase here that doesn't open it: the passphrase is asked
    // for, with why, and Connect refuses and asks the page to show it.
    pathwarden_core::crypt::forget_all_in_process();
    std::fs::remove_dir_all(dir.join("keystore")).unwrap();
    pathwarden_core::keystore::use_test_store(&dir.join("keystore"));
    std::env::set_var(
        pathwarden_core::keystore::ENV_VAR,
        "not the passphrase of this history",
    );
    let token = a.probe(&remote).await;
    let page = a.get(&format!("/environments/connect?s={token}")).await;
    assert!(page.contains("Enter the passphrase to open it"), "{page}");
    assert!(
        page.contains("That passphrase doesn&#39;t open this history.")
            || page.contains("That passphrase doesn't open this history."),
        "{page}"
    );
    assert!(!page.contains(r#"id="cx-pass-err" role="alert" hidden"#));
    let (s, r) = a
        .post("/api/connect/go", json!({"s": token, "name": "Wrong"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert_eq!(r["reload"], true, "{r}");
    std::env::remove_var(pathwarden_core::keystore::ENV_VAR);

    // Nothing here at all: Connect refuses before changing anything, and
    // the page asks for it.
    pathwarden_core::crypt::forget_all_in_process();
    let page = a.get(&format!("/environments/connect?s={token}")).await;
    assert!(page.contains("Enter the passphrase to open it"), "{page}");
    assert!(page.contains(r#"id="cx-pass-err" role="alert" hidden"#));
    let (s, r) = a
        .post("/api/connect/go", json!({"s": token, "name": "Nothing"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert_eq!(
        r["error"],
        "Enter the passphrase to open the history first."
    );
    assert_eq!(r["reload"], true, "{r}");
    let _ = std::fs::remove_dir_all(&dir);
}
