//! Pulling a git history while the app is open: what a pull
//! tells the open pages (`/api/history/pulled`), a save refused when a pull
//! changed its section since the page was loaded (409), the ticks that are
//! skipped, the footer and History storage's Pull now and Pull every, and
//! the last-pull record that is never committed. Two `pathwarden.toml`
//! files on one local bare repository.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::auto_pull::{self, Skip};
use pathwarden_ui::jobs::JobSpec;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::settings::{apply_sharing, Share};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4252";

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

struct App {
    router: Router,
    state: Arc<AppState>,
}

impl App {
    fn new(ws: &Workspace) -> App {
        let st = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), 4252));
        App {
            router: router(st.clone()),
            state: st,
        }
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let s = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (s, String::from_utf8_lossy(&b).into_owned())
    }

    async fn json(&self, uri: &str) -> Value {
        let (s, body) = self.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.send(Method::POST, uri, body, None, None).await
    }

    /// A save as a page sends it: with the page's environment and the pull
    /// counter it was loaded at (`config.js`).
    async fn save(
        &self,
        method: Method,
        uri: &str,
        body: Value,
        env: &str,
        pulled: u64,
    ) -> (StatusCode, Value) {
        self.send(method, uri, body, Some(env), Some(pulled)).await
    }

    async fn send(
        &self,
        method: Method,
        uri: &str,
        body: Value,
        env: Option<&str>,
        pulled: Option<u64>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(e) = env {
            req = req.header("X-Pathwarden-Env", e);
        }
        if let Some(n) = pulled {
            req = req.header("X-Pathwarden-Pulled", n.to_string());
        }
        let req = req
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let s = res.status();
        let b = res.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        // A save shares in the background: wait for it, so it can't take
        // the lock (and pull) after the test has checked the lock is free.
        if let Some(id) = v["sharing"].as_u64() {
            let start = std::time::Instant::now();
            while self.json(&format!("/api/settings/sharing?id={id}")).await["running"] == true {
                assert!(
                    start.elapsed().as_secs() < 60,
                    "sharing {id} never finished"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        (s, v)
    }
}

/// Waits until no save of this process is still sharing in the background.
async fn wait_for_shares() {
    let start = std::time::Instant::now();
    while pathwarden_ui::sync_ui::shares_running() {
        assert!(start.elapsed().as_secs() < 60, "a share never finished");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn pull(ws: &Workspace) -> Result<pathwarden_ui::history_ui::Pulled, Skip> {
    let ws = ws.clone();
    tokio::task::spawn_blocking(move || auto_pull::pull_env(&ws, None))
        .await
        .unwrap()
}

#[tokio::test]
async fn a_pull_tells_the_pages_it_changes_and_refuses_stale_saves() {
    if !git_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-autopull-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _clean = Dir(dir.clone());
    let remote = dir.join("state.git");
    assert!(git()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let state = |at: &Path| {
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\nkeep = \"full\"\n",
            slash(&remote),
            slash(&at.join("state"))
        )
    };
    // Another machine shares Tier Zero.
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let other_toml = other.join("pathwarden.toml");
    std::fs::write(
        &other_toml,
        format!("tier_zero = [\"VAULT01$\"]\n\n{}", state(&other)),
    )
    .unwrap();
    let (_, note) = apply_sharing(other_toml.clone(), &Share::default(), |d| {
        d.set_tier_zero(&["VAULT01$".into(), "SRV-ADSYNC$".into()])
    })
    .unwrap();
    assert!(
        note.unwrap().contains("Shared with this history"),
        "the other machine shares"
    );

    let ws = Workspace::open(dir.join("ws")).unwrap();
    std::fs::write(ws.config_path(), state(&ws.env_dir())).unwrap();
    let a = App::new(&ws);
    let env = a.state.env_id();

    // Not pulled yet: the footer says so, and nothing is new.
    let v = a.json("/api/history/pulled?since=0&page=settings").await;
    assert_eq!(v["n"], 0, "{v}");
    assert!(v["note"].is_null(), "{v}");
    assert!(
        v["foot"].as_str().unwrap().contains("Not synced yet"),
        "{v}"
    );

    // The app's first pull takes the repository's Tier Zero.
    let p = pull(&ws).await.unwrap();
    assert_eq!(p.sections, vec!["tier_zero"], "{p:?}");
    assert_eq!(a.state.auto_pull.record(&env, &p), 1);
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains(&format!(
            r#"data-pulled="1" data-env="{env}" data-page="settings""#
        )),
        "the shell stamps the counter"
    );
    assert!(
        page.contains("Tier Zero updated · just now"),
        "the footer: {page}"
    );
    assert!(
        page.contains("About Pathwarden") && !page.contains(">This computer only<"),
        "the footer's (i) alone"
    );
    assert!(
        !page.contains("run pathwarden ui"),
        "no command on the page"
    );
    let tier_zero: Vec<String> = ws.config().unwrap().tier_zero;
    assert_eq!(tier_zero, ["VAULT01$", "SRV-ADSYNC$"]);

    // The other machine changes it again while Settings is open (loaded
    // at counter 1); the next pull brings it.
    let (_, note) = apply_sharing(other_toml.clone(), &Share::default(), |d| {
        d.set_tier_zero(&["VAULT01$".into(), "CASTELBLACK$".into()])
    })
    .unwrap();
    assert!(note.unwrap().contains("Shared with this history"));
    let p = pull(&ws).await.unwrap();
    assert_eq!(a.state.auto_pull.record(&env, &p), 2);

    let v = a.json("/api/history/pulled?since=1&page=settings").await;
    assert_eq!(v["n"], 2);
    let note = v["note"].as_str().unwrap();
    assert!(
        note.contains("<strong>Tier Zero</strong> changed in the shared settings"),
        "{note}"
    );
    assert!(note.contains("From the next run"), "{note}");
    assert!(note.contains("data-repo-reload"), "{note}");
    let v = a
        .json("/api/history/pulled?since=1&page=settings&editing=true")
        .await;
    let note = v["note"].as_str().unwrap();
    assert!(
        note.contains("changed in the shared settings while you were editing.")
            && note.contains("Your unsaved changes here will be lost."),
        "{note}"
    );
    // Pages it doesn't change show nothing; nor does a page loaded since.
    for q in [
        "since=1&page=runs",
        "since=1&page=zones",
        "since=1&page=mappings",
        "since=2&page=settings",
        "since=1&page=run&run=20261025-042200-abcdef",
    ] {
        let v = a.json(&format!("/api/history/pulled?{q}")).await;
        assert!(v["note"].is_null(), "{q}: {v}");
    }

    // A save from the page loaded at 1 is refused: a pull changed it.
    let t0 = json!({ "items": ["WINTERFELL$"], "loaded": ["VAULT01$", "SRV-ADSYNC$"] });
    let (s, r) = a
        .save(Method::POST, "/api/settings/tier-zero", t0.clone(), &env, 1)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{r}");
    assert_eq!(
        r["error"],
        "Tier Zero changed in the shared settings since you opened this page. Reload to see the changes."
    );
    // From a page loaded after the pull, a stale list is the old refusal.
    let (s, r) = a
        .save(Method::POST, "/api/settings/tier-zero", t0.clone(), &env, 2)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    // A page of another environment (switched in another tab): refused,
    // and its news shows no note.
    let (s, r) = a
        .save(Method::POST, "/api/settings/tier-zero", t0, "another", 2)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{r}");
    assert_eq!(
        r["error"],
        "You switched environment in another tab. Reload this page."
    );
    let v = a
        .json("/api/history/pulled?since=1&page=settings&env=another")
        .await;
    assert!(v["note"].is_null(), "{v}");
    let v = a
        .json(&format!(
            "/api/history/pulled?since=1&page=settings&env={env}"
        ))
        .await;
    assert!(v["note"].is_string(), "its own environment's page: {v}");
    assert_eq!(
        ws.config().unwrap().tier_zero,
        ["VAULT01$", "CASTELBLACK$"],
        "nothing saved"
    );

    // Rules, zones and accepted risks the same: the other machine changes
    // them, and every save of theirs from a page loaded before is refused.
    let (_, note) = apply_sharing(other_toml.clone(), &Share::default(), |d| {
        d.set_rules(
            &pathwarden_core::config_edit::RulesEdit {
                stale_days: 90,
                password_age_days: 365,
                krbtgt_age_days: 120,
                sso_key_age_days: None,
                severity: "exposure".into(),
                disabled: Vec::new(),
                severities: Default::default(),
            },
            &pathwarden_core::config_edit::Stamp::now(),
        )?;
        d.upsert_zone(
            None,
            None,
            &pathwarden_core::config_edit::ZoneEdit {
                name: "Tier 1 servers".into(),
                members: vec!["SRV01$".into()],
                ..Default::default()
            },
        )?;
        d.upsert_suppression(
            None,
            None,
            None,
            &pathwarden_core::config_edit::SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: "LAPS rollout".into(),
                expires: None,
            },
            &pathwarden_core::config_edit::Stamp::now(),
        )
    })
    .unwrap();
    assert!(note.unwrap().contains("Shared with this history"));
    let p = pull(&ws).await.unwrap();
    for k in ["rules", "zone", "suppress"] {
        assert!(p.sections.contains(&k), "{k}: {p:?}");
    }
    assert_eq!(a.state.auto_pull.record(&env, &p), 3);
    let zone = json!({ "zone": { "name": "Mine" } });
    let risk = json!({ "risk": { "rule": "PW-004", "reason": "r" } });
    let entry = json!({ "expect": "LAPS rollout", "expect_target": "PW-011", "text": "n" });
    for (method, uri, body, says) in [
        (
            Method::POST,
            "/api/settings/rules",
            json!({ "stale_days": 30, "password_age_days": 30, "krbtgt_age_days": 30, "severity": "exposure", "disabled": [], "loaded": {} }),
            "Rules",
        ),
        (Method::POST, "/api/zones", zone, "Zones"),
        (
            Method::DELETE,
            "/api/zones/0",
            json!({ "expect": "Tier 1 servers" }),
            "Zones",
        ),
        (
            Method::POST,
            "/api/settings/suppress",
            risk,
            "Accepted risks",
        ),
        (
            Method::POST,
            "/api/settings/suppress/0/note",
            entry.clone(),
            "Accepted risks",
        ),
        (
            Method::DELETE,
            "/api/settings/suppress/0",
            entry,
            "Accepted risks",
        ),
    ] {
        let (s, r) = a.save(method.clone(), uri, body.clone(), &env, 2).await;
        assert_eq!(s, StatusCode::CONFLICT, "{method} {uri}: {r}");
        assert_eq!(
            r["error"],
            format!(
                "{says} changed in the shared settings since you opened this page. Reload to see the changes."
            ),
            "{uri}"
        );
        // From a page loaded after that pull, the save goes on.
        let (s, r) = a.save(method.clone(), uri, body, &env, 3).await;
        assert_ne!(s, StatusCode::CONFLICT, "{method} {uri}: {r}");
    }

    // History storage: Pull now with the last pull after it, and Pull
    // every beside Branch.
    let (_, page) = a.get("/automate/history").await;
    assert!(page.contains("Sync now</button>"), "{page}");
    assert!(
        page.contains("<strong>Up to date</strong><span> · synced just now · every 5 min</span>"),
        "{page}"
    );
    assert!(page.contains(r#"id="state-refresh" min="1" max="1440" step="1" value="5""#));
    assert!(page.contains("While the app is open, and when it opens."));
    // Saved with the form's Save, written only when it isn't 5.
    let save = |refresh: Value| {
        json!({
            "backend": "git",
            "path": slash(&ws.env_dir().join("state")),
            "remote": slash(&remote),
            "keep": "full",
            "refresh": refresh,
        })
    };
    let (s, r) = a.post("/api/settings/state", save(json!(15))).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let toml = std::fs::read_to_string(ws.config_path()).unwrap();
    assert!(toml.contains("refresh = 15"), "{toml}");
    let (_, page) = a.get("/automate/history").await;
    assert!(page.contains(r#"value="15""#) && page.contains("every 15 min"));
    let (s, r) = a.post("/api/settings/state", save(json!(0))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    let (s, _) = a.post("/api/settings/state", save(json!(5))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!std::fs::read_to_string(ws.config_path())
        .unwrap()
        .contains("refresh"));

    // Skipped ticks: the lock held (never waited for), an analysis running.
    {
        wait_for_shares().await;
        let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
        let _held = loc
            .store
            .lock_waiting(std::time::Duration::from_secs(60))
            .unwrap();
        assert_eq!(pull(&ws).await.unwrap_err(), Skip::Busy);
    }
    let spec = JobSpec {
        id: "job1".into(),
        inputs: Vec::new(),
        scratch: None,
        also_scratch: None,
        source: "test".into(),
        demo: false,
        env: None,
        new_env: None,
        env_auto: false,
        label: None,
        collection: None,
        timings: None,
        force: false,
    };
    assert!(a.state.jobs.try_begin(&spec));
    assert_eq!(
        auto_pull::tick(a.state.clone()).await.unwrap_err(),
        Skip::Analysis
    );

    // The sections a pull applies are counted as soon as they are applied,
    // before the full runs load: a page loaded meanwhile shows the pulled
    // values and carries that counter, so its save isn't refused for them.
    let (_, note) = apply_sharing(other_toml.clone(), &Share::default(), |d| {
        d.set_tier_zero(&["VAULT01$".into(), "N1$".into()])
    })
    .unwrap();
    assert!(note.unwrap().contains("Shared with this history"));
    // No save of this app is still sharing: one would pull the change
    // first and leave this pull nothing to apply. Taking and dropping the
    // lock doesn't prove it (a share may not have taken it yet).
    wait_for_shares().await;
    let (st, w, e) = (a.state.clone(), ws.clone(), env.clone());
    let (p, mid, seen) = tokio::task::spawn_blocking(move || {
        let (mut mid, mut seen) = (0, Vec::new());
        let p = auto_pull::pull_env_with(&w, None, &mut |s| {
            mid = st.auto_pull.record_sections(&e, s);
            seen = w.config().unwrap().tier_zero;
        })
        .unwrap();
        (p, mid, seen)
    })
    .await
    .unwrap();
    assert_eq!(seen, ["VAULT01$", "N1$"], "applied before it is counted");
    let end = a.state.auto_pull.record_runs(&env, &p);
    assert!(end > mid, "the runs are counted after");
    let t0 = json!({ "items": ["VAULT01$", "N1$", "MINE$"], "loaded": ["VAULT01$", "N1$"] });
    let (s, r) = a
        .save(
            Method::POST,
            "/api/settings/tier-zero",
            t0.clone(),
            &env,
            mid,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "a page loaded during the pull: {r}");
    let (s, _) = a
        .save(Method::POST, "/api/settings/tier-zero", t0, &env, mid - 1)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "one loaded before it");

    // The record of the last pull, beside the lock: never in a commit.
    let work = ws.env_dir().join("state");
    assert!(work.join(".pathwarden-last-pull.json").exists());
    let out = git()
        .arg("-C")
        .arg(&remote)
        .args(["log", "--all", "--name-only", "--format="])
        .output()
        .unwrap();
    let names = String::from_utf8_lossy(&out.stdout);
    assert!(!names.is_empty() && !names.contains("last-pull"), "{names}");

    // A folder history: no status, and the tick is skipped.
    let f = Workspace::open(dir.join("folder")).unwrap();
    let b = App::new(&f);
    let v = b.json("/api/history/pulled?since=0&page=runs").await;
    assert_eq!(v["foot"], "", "{v}");
    assert_eq!(pull(&f).await.unwrap_err(), Skip::Folder);
    let (_, page) = b.get("/runs").await;
    assert!(!page.contains("pull-foot"), "just the icons");
}

/// A first clone that fails (the repository can't be reached) is recorded
/// all the same, before any working copy exists: History storage and the
/// footer say so in amber, with git's message, and the next pull still
/// clones into the folder.
#[tokio::test]
async fn a_first_clone_that_fails_is_shown() {
    if !git_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-ui-autopull-clone-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _clean = Dir(dir.clone());
    let remote = dir.join("nowhere.git");
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let work = ws.env_dir().join("state");
    std::fs::write(
        ws.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\n",
            slash(&remote),
            slash(&work)
        ),
    )
    .unwrap();
    let a = App::new(&ws);
    assert_eq!(pull(&ws).await.unwrap_err(), Skip::Failed);
    assert!(!work.join(".git").exists(), "nothing cloned");
    assert!(work.join(".pathwarden-last-pull.json").exists());
    let (_, page) = a.get("/automate/history").await;
    assert!(
        page.contains("<strong>Couldn&#39;t reach the run history.</strong>"),
        "{page}"
    );
    assert!(
        page.contains("What git said") && page.contains("nowhere.git"),
        "{page}"
    );
    assert!(page.contains("Not synced yet."), "{page}");
    let v = a.json("/api/history/pulled?since=0&page=runs").await;
    let foot = v["foot"].as_str().unwrap();
    assert!(
        foot.contains("pull-foot warn") && foot.contains("Couldn&#39;t reach the run history"),
        "{foot}"
    );
    // Once it can be reached, the record doesn't stand in the clone's way.
    assert!(git()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    pull(&ws).await.unwrap();
    assert!(work.join(".git").exists(), "cloned");
    let exclude = std::fs::read_to_string(work.join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("/.pathwarden-last-pull.json"), "{exclude}");
    let v = a.json("/api/history/pulled?since=0&page=runs").await;
    assert!(!v["foot"].as_str().unwrap().contains("warn"), "{v}");
}
