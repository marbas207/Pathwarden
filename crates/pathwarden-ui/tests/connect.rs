//! Connect to a run history in the app: the page's steps through
//! its API (connect, the passphrase, use this history), the note on Runs, the
//! New environment choice, and Start a new run history refusing a
//! repository that holds one. A local bare repository; no network.

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

const HOST: &str = "127.0.0.1:4261";
const PASS: &str = "correct horse battery staple";

fn git_ok() -> bool {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    let ok = c
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
        Self::with(ws, true)
    }

    /// `allow`: as `pathwarden ui --allow-destinations`, which Connect needs.
    fn with(ws: Workspace, allow: bool) -> Self {
        let mut state = AppState::new(ws, Token::generate().unwrap(), 4261);
        state.allow_destinations = allow;
        let state = Arc::new(state);
        App {
            router: router(state.clone()),
            state,
        }
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Option<String>, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let s = res.status();
        let loc = res
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string());
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (s, loc, String::from_utf8_lossy(&b).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, b)
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
        let (s, _, b) = self.send(req).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn form(&self, uri: &str, body: &str) -> (StatusCode, Option<String>) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, l, _) = self.send(req).await;
        (s, l)
    }
}

/// A run history on `remote`, encrypted with [`PASS`] by another
/// computer (its working copy in `work`).
fn encrypted_history(remote: &Path, work: &Path) {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    assert!(c
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
    let store = Store::new(&cfg, Some(work)).unwrap();
    store
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    // This process is the new computer from here on: it knows no key.
    pathwarden_core::crypt::forget_all_in_process();
}

/// Without `--allow-destinations` Connect reaches nowhere: looking at a
/// history (which may sign in to the place the page named), opening it and
/// connecting are all refused before anything is contacted.
#[tokio::test]
async fn connect_needs_the_flag() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("pathwarden-ui-connect-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let a = App::with(ws, false);
    let locked = pathwarden_ui::connect_ui::CONNECT_LOCKED;
    for (uri, body) in [
        (
            "/api/connect/probe",
            json!({"kind": "git", "url": "https://git.example.com/h.git"}),
        ),
        (
            "/api/connect/probe",
            json!({"kind": "folder", "folder": r"\\attacker\share"}),
        ),
        ("/api/connect/open", json!({"s": "x", "passphrase": "p"})),
        ("/api/connect/go", json!({"s": "x", "name": "x"})),
    ] {
        let (s, v) = a.post(uri, body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri} {body}: {v}");
        assert_eq!(v["error"], locked, "{uri}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_page_looks_opens_and_connects() {
    if !git_ok() {
        return;
    }
    let dir: PathBuf =
        std::env::temp_dir().join(format!("pathwarden-ui-connect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    pathwarden_core::keystore::use_test_store(&dir.join("keystore"));
    let remote = dir.join("shared.git");
    encrypted_history(&remote, &dir.join("a-work"));
    let ws = Workspace::open(dir.join("wsB")).unwrap();
    let a = App::new(ws.clone());

    // Home and New environment lead here.
    let (_, home) = a.get("/").await;
    assert!(home.contains(r#"href="/environments/connect""#), "{home}");
    assert!(home.contains("Connect to a run history"));
    let (_, envs) = a.get("/environments").await;
    for want in ["Run history", "On this computer", "Start a new run history"] {
        assert!(envs.contains(want), "{want}");
    }
    let (s, loc) = a
        .form("/environments", "origin=connect&name=&domains=")
        .await;
    assert!(s.is_redirection(), "{s}");
    assert_eq!(loc.as_deref(), Some("/environments/connect"));

    // Step 1.
    let (s, page) = a.get("/environments/connect").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("Where it is") && page.contains("Pathwarden only reads it. Nothing changes.")
    );
    let (s, r) = a
        .post(
            "/api/connect/probe",
            json!({"kind": "git", "url": slash(&dir.join("nothing-here.git"))}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert_eq!(r["problem"], "unreachable");
    assert!(r["note"]
        .as_str()
        .unwrap()
        .contains("reach the repository."));
    let (s, r) = a
        .post(
            "/api/connect/probe",
            json!({"kind": "git", "url": slash(&remote)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let token = r["token"].as_str().unwrap().to_string();

    // Step 2: before the passphrase.
    let (_, page) = a.get(&format!("/environments/connect?s={token}")).await;
    for want in [
        "This is a Pathwarden history.",
        "Encrypted with a passphrase.",
        "Enter the passphrase to open it",
        "Shown once the history is open.",
    ] {
        assert!(page.contains(want), "{want}");
    }
    assert!(!page.contains("and it is open"), "{page}");
    let (s, r) = a
        .post(
            "/api/connect/open",
            json!({"s": token, "passphrase": "not the passphrase", "remember": true}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(r["error"], "That passphrase doesn't open this history.");
    let (s, r) = a
        .post(
            "/api/connect/open",
            json!({"s": token, "passphrase": PASS, "remember": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // Step 3.
    let (_, page) = a.get(&format!("/environments/connect?s={token}")).await;
    for want in [
        "Open and sync",
        "Your account can push to this repository.",
        "Share runs from this computer",
        "What it keeps and its encryption come from the run history.",
        "Encrypted. Your passphrase opens it.",
        "Connect and sync",
    ] {
        assert!(page.contains(want), "{want}");
    }
    // Plain sentences: no checkmarks in the text (the steps keep theirs).
    assert!(!page.contains('\u{2713}'));
    let (s, r) = a
        .post(
            "/api/connect/go",
            json!({"s": token, "name": "Lab", "refresh": 15, "push": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let href = r["redirect"].as_str().unwrap();
    assert!(href.starts_with("/runs?connected="), "{href}");
    assert!(href.contains("every=15"), "{href}");
    let (_, runs) = a.get(href).await;
    assert!(
        runs.contains("Connected to the run history.")
            && runs.contains("It is synced again every 15 minutes."),
        "{runs}"
    );
    // The new environment is current, with the history's choices.
    assert_eq!(a.state.env_id(), "lab");
    let env = ws.in_env("lab");
    let state = env.config().unwrap().state;
    assert_eq!(state.backend, StateBackend::Git);
    assert!(state.encrypted);
    assert!(!state.pushes());
    assert_eq!(state.refresh_minutes(), 15);
    // Remembered: in this computer's store.
    let loc = pathwarden_ui::history_ui::locate(&env, None).unwrap();
    assert!(pathwarden_core::keystore::stored_here(&loc.dir)
        .unwrap()
        .is_some());
    // No probe left behind.
    assert!(!ws.root().join(".pathwarden-connect").exists());

    // The same history again.
    let (s, r) = a
        .post(
            "/api/connect/probe",
            json!({"kind": "git", "url": slash(&remote)}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(r["problem"], "used");
    assert!(r["error"]
        .as_str()
        .unwrap()
        .contains("The environment Lab already uses this history."));
    // Lab is the current one: its runs, not a switch to it.
    let note = r["note"].as_str().unwrap();
    assert!(
        note.contains("Open Runs") && !note.contains("Switch to"),
        "{note}"
    );

    // A token in the URL is refused before anything is looked at.
    let (s, r) = a
        .post(
            "/api/connect/probe",
            json!({"kind": "git", "url": "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@git.example.com/team/history.git"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(r["problem"], "bad_url", "{r}");

    // An empty repository: Start a new run history here names it by a
    // token, never by its URL.
    let empty = dir.join("empty.git");
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    assert!(c
        .args(["init", "-q", "--bare"])
        .arg(&empty)
        .status()
        .unwrap()
        .success());
    let (s, r) = a
        .post(
            "/api/connect/probe",
            json!({"kind": "git", "url": slash(&empty)}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let note = r["note"].as_str().unwrap();
    assert!(
        note.contains("/automate/history?origin=new-shared&amp;from="),
        "{note}"
    );
    assert!(!note.contains("empty.git"), "{note}");
    let from = note
        .split("from=")
        .nth(1)
        .unwrap()
        .split(['#', '"'])
        .next()
        .unwrap()
        .to_string();
    let (_, hs) = a
        .get(&format!("/automate/history?origin=new-shared&from={from}"))
        .await;
    assert!(hs.contains(&slash(&empty)), "the place is filled in");

    // Start a new run history there, from another workspace: refused,
    // with Connect to it, and nothing encrypted or saved.
    let wsc = Workspace::open(dir.join("wsC")).unwrap();
    let c = App::new(wsc.clone());
    let (_, hs) = c.get("/automate/history").await;
    for want in [
        "Where this environment&#39;s history lives",
        "On this computer",
        "Connect to a run history",
        "Start a new run history",
    ] {
        assert!(
            hs.contains(want) || hs.contains(&want.replace("&#39;", "'")),
            "{want}"
        );
    }
    let form = json!({"backend": "git", "remote": slash(&remote), "keep": "full"});
    let (s, r) = c
        .post(
            "/api/history/encryption",
            json!({"on": true, "passphrase": "another long passphrase", "state": form}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert_eq!(
        r["error"],
        "This repository already holds a Pathwarden history. It is encrypted and has 0 runs. Connect to it instead, or choose an empty repository."
    );
    let href = r["connect"].as_str().unwrap();
    assert!(href.starts_with("/environments/connect?from="), "{href}");
    assert!(!href.contains("shared"), "no URL in the link: {href}");
    let (_, page) = c.get(href).await;
    assert!(page.contains(&slash(&remote)), "the place is filled in");
    assert!(!wsc.config_path().exists());
    let mut plain = form.clone();
    plain["share_plain"] = true.into();
    let (s, r) = c.post("/api/settings/state", plain).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert!(r["connect"].is_string(), "{r}");
    assert!(!wsc.config_path().exists());

    // URLs on History storage's form: a user name is fine (Azure DevOps'
    // own form), a password or token is not. (Numbers with names: nothing
    // is looked at, no network.)
    let azure = "https://org@dev.azure.com/org/p/_git/r";
    let pat = format!(
        "https://{}@dev.azure.com/org/p/_git/r",
        "a1b2c3d4e5".repeat(5) + "zz"
    );
    for (url, ok) in [
        ("https://user:pw@git.example.com/x.git", false),
        (
            "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/s.git",
            false,
        ),
        (pat.as_str(), false),
        ("git@github.com:o/s.git", true),
        ("ssh://git@git.example.com/x.git", true),
        (azure, true),
    ] {
        let (s, r) = c
            .post(
                "/api/settings/state",
                json!({"backend": "git", "remote": url, "path": "state"}),
            )
            .await;
        if ok {
            assert_eq!(s, StatusCode::OK, "{url}: {r}");
        } else {
            assert_eq!(s, StatusCode::BAD_REQUEST, "{url}: {r}");
            assert!(
                r["error"].as_str().unwrap().contains("password or token"),
                "{r}"
            );
        }
    }
    // Saved with a user name: it loads and saves again as it is, and the
    // page never shows the user name.
    let state = wsc.config().unwrap().state;
    assert_eq!(state.remote.as_deref(), Some(azure));
    let (s, hs) = c.get("/automate/history").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!hs.contains("org@dev.azure.com"), "redacted on the page");
    let (s, r) = c
        .post(
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://***@dev.azure.com/org/p/_git/r", "path": "state", "push": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(wsc.config().unwrap().state.remote.as_deref(), Some(azure));
    let _ = std::fs::remove_dir_all(&dir);
}
