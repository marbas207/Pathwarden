//! Shared settings on the app's pages: the line under Settings'
//! title, the choice for a section that differs from the shared settings and
//! its buttons, the note after a pull, a save's sharing in the background,
//! packs from the repository on Mappings, and History storage's rows. Two
//! `pathwarden.toml` files on one local bare repository.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::settings::{apply, apply_sharing, Share};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4251";

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
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Pulls and syncs `ws`, as Pull now does.
async fn refresh(ws: Workspace) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
        pathwarden_ui::history_ui::refresh(Some(&ws), &loc, true).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn settings_pages_show_and_settle_the_shared_settings() {
    if !git_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-sync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let remote = dir.join("state.git");
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    assert!(c
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
    // Another machine shares Tier Zero, an accepted risk and a pack.
    let other = dir.join("other");
    std::fs::create_dir_all(other.join("packs")).unwrap();
    std::fs::write(
        other.join("packs/acme.toml"),
        "[pack]\nname = \"acme\"\nversion = 1\nsource_kinds = [\"AcmeHound\"]\nkind_prefix = \"AC_\"\ntrusted = true\n\n[[node]]\nkind = \"AC_Thing\"\nicon = \"clock\"\ncolor = \"#abc\"\n",
    )
    .unwrap();
    let other_toml = other.join("pathwarden.toml");
    std::fs::write(
        &other_toml,
        format!(
            "tier_zero = [\"VAULT01$\"]\n\n{}\n[[mapping]]\npath = \"packs/acme.toml\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"LAPS rollout\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"PW-SCHED01\"\n",
            state(&other)
        ),
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

    // This workspace joins: the first Pull now takes the repository's. It
    // had none of its own, so nothing is saved beside pathwarden.toml.
    let ws_dir = dir.join("ws");
    let ws = Workspace::open(&ws_dir).unwrap();
    std::fs::write(ws.config_path(), state(&ws.env_dir())).unwrap();
    let note = refresh(ws.clone()).await.unwrap();
    assert!(
        note.contains(
            "Tier Zero additions, accepted risks and mapping packs were taken from the run \
             history."
        ),
        "{note}"
    );
    assert!(!note.contains("saved in"), "nothing of its own: {note}");
    // These pages set where the history is kept: as `pathwarden ui --allow-destinations`.
    let mut st = AppState::new(ws.clone(), Token::generate().unwrap(), 4251);
    st.allow_destinations = true;
    let st = Arc::new(st);
    let a = App {
        router: router(st.clone()),
        state: st,
        dir: dir.clone(),
    };
    let (s, page) = a.get("/settings").await;
    assert_eq!(s, StatusCode::OK);
    // Nothing to act on: nothing about sharing, nor the file, at the top.
    assert!(
        !page.contains("Shared through")
            && !page.contains("sync-conflict")
            && !page.contains("cfg-file")
            && !page.contains("Changes are written to this file"),
        "{page}"
    );
    assert!(
        page.contains("Set up how ") && page.contains(" is judged: extra Tier Zero objects"),
        "the description: {page}"
    );
    assert!(!page.contains("nav-dot"), "nothing differs: no dot");
    assert!(
        page.contains("mapping packs were taken from the run history."),
        "the note after a pull: {page}"
    );
    let (_, page) = a.get("/settings").await;
    assert!(
        !page.contains("were taken from the run history"),
        "shown once"
    );
    assert!(
        page.contains("From the run history"),
        "a risk from another computer"
    );

    // Mappings: the pack came, untrusted here whatever it says.
    let (_, page) = a.get("/mappings").await;
    assert!(
        page.contains("From the repository · not trusted here"),
        "{page}"
    );
    assert!(page.contains("Never travels."), "{page}");

    // Two saves from the page, one right after the other: each answered at
    // once with its own sharing, shared in order.
    let mut ids = Vec::new();
    for (items, loaded) in [
        (
            json!(["VAULT01$", "SRV-ADSYNC$", "BACKUP01$"]),
            json!(["VAULT01$", "SRV-ADSYNC$"]),
        ),
        (
            json!(["VAULT01$", "SRV-ADSYNC$", "BACKUP01$", "DRAGONSTONE$"]),
            json!(["VAULT01$", "SRV-ADSYNC$", "BACKUP01$"]),
        ),
    ] {
        let (s, r) = a
            .post(
                "/api/settings/tier-zero",
                json!({ "items": items, "loaded": loaded }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{r}");
        ids.push(r["sharing"].as_u64().unwrap_or_else(|| panic!("{r}")));
    }
    assert_ne!(ids[0], ids[1]);
    let mut notes = Vec::new();
    for id in &ids {
        let mut shared = Value::Null;
        for _ in 0..600 {
            let (_, body) = a.get(&format!("/api/settings/sharing?id={id}")).await;
            shared = serde_json::from_str(&body).unwrap();
            if shared["running"] == false {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(shared["running"], false, "{shared}");
        assert_ne!(shared["problem"], true, "{shared}");
        notes.push(shared["note"].as_str().unwrap_or_default().to_string());
    }
    assert!(notes[0].contains("Shared with this history"), "{notes:?}");
    assert!(
        !notes.iter().any(|n| n.contains("pathwarden config")),
        "no commands on pages: {notes:?}"
    );
    let (_, page) = a.get("/settings").await;
    assert!(
        !page.contains("sync-conflict") && !page.contains("Differs from"),
        "both saves arrived: {page}"
    );

    // Both change Tier Zero: the page asks for a choice. (The other machine
    // takes this one's change first.)
    {
        let text = std::fs::read_to_string(&other_toml).unwrap();
        let cfg = pathwarden_core::config_edit::check(&text).unwrap();
        let store =
            pathwarden_core::store::Store::new(&cfg.state, Some(&other.join("state"))).unwrap();
        let _l = store.lock().unwrap();
        store.pull().unwrap();
        let place = pathwarden_core::settings_sync::Place {
            store: &store,
            config_path: &other_toml,
            pushes: true,
            env_name: None,
        };
        let o = pathwarden_core::settings_sync::sync(
            &place,
            pathwarden_core::settings_sync::Resolve::Auto,
        )
        .unwrap();
        assert!(o.applied(), "{:?}", o.done);
    }
    // Both add Tier Zero, and both set the stale days: Tier Zero merges,
    // the one setting asks.
    let rules = |days: i64| pathwarden_core::config_edit::RulesEdit {
        disabled: Vec::new(),
        stale_days: days,
        password_age_days: 365,
        krbtgt_age_days: 180,
        sso_key_age_days: None,
        severity: "exposure".into(),
        severities: Default::default(),
    };
    let by = pathwarden_core::config_edit::Stamp {
        by: Some(r"CORP\a.admin".into()),
        on: Some("ADMIN-WS01".into()),
        at: "2026-11-18T17:55:00Z".into(),
    };
    let with = |path: &Path, extra: &str| {
        let text = std::fs::read_to_string(path).unwrap();
        let mut list = pathwarden_core::config_edit::check(&text)
            .unwrap()
            .tier_zero;
        list.push(extra.into());
        list
    };
    let theirs = with(&other_toml, "APP01$");
    apply_sharing(other_toml.clone(), &Share::default(), |d| {
        d.set_tier_zero(&theirs)?;
        d.set_rules(&rules(60), &by)
    })
    .unwrap();
    let mine = with(&ws.config_path(), "VAULT02$");
    apply(ws.config_path(), |d| {
        d.set_tier_zero(&mine)?;
        d.set_rules(&rules(30), &by)
    })
    .unwrap();
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains("<strong>Stale Tier Zero account has two values.</strong>"),
        "the note names it: {page}"
    );
    assert!(
        page.contains(
            "Merged from the shared settings: <strong>APP01$</strong> added to Tier Zero."
        ),
        "what merged: {page}"
    );
    assert!(
        page.contains("Runs here use 30 days. Everything else is merged."),
        "what happens meanwhile: {page}"
    );
    assert!(
        page.contains(r#"<span class="stag clash">1 setting has two values</span>"#)
            && page.contains(r#"class="field has-clash""#)
            && page.contains(r#"data-sync-section="rules.stale_days">Use 60</button>"#)
            && page.contains(r#"data-sync-section="rules.stale_days">Keep 30</button>"#)
            && page.contains("Shared: <strong>60 days</strong>"),
        "the choice next to the setting: {page}"
    );
    assert!(
        page.contains(
            r##"<a href="#rules" title="Settings differ from the shared settings">Rules<span class="sr-only">"##
        ),
        "the jump link's dot: {page}"
    );
    assert!(
        !page.contains(r##"<a href="#tier-zero" title"##),
        "Tier Zero merged, no dot: {page}"
    );
    assert!(
        page.contains(r#"<span class="chip-text">APP01$</span><span class="chip-from">shared · "#),
        "the merged entry's mark: {page}"
    );
    assert!(
        page.contains("VAULT02$") && !page.contains("Differs from the shared settings"),
        "{page}"
    );
    assert!(
        !page.contains("pathwarden config") && !page.contains("stag both"),
        "plain words, amber only: {page}"
    );
    let (_, page) = a.get("/automate/history").await;
    assert!(
        page.contains("What it keeps")
            && page.contains("Stale Tier Zero account has two values")
            && page.contains(">Review</a>"),
        "{page}"
    );

    // The rail's dot on Settings, on every page; the footer says only how
    // the sync went.
    let dot = |page: &str| page.contains(r#"class="nav-dot""#);
    let (_, page) = a.get("/runs").await;
    assert!(dot(&page), "{page}");
    assert!(
        page.contains(r#"<span class="sr-only">: a setting has two values</span>"#),
        "a name for screen readers: {page}"
    );
    let foot = page
        .split(r#"<div class="rail-foot">"#)
        .nth(1)
        .unwrap_or_default();
    assert!(
        !foot.contains("two values") && !foot.contains("choice"),
        "the footer: {foot}"
    );
    // Dismiss: no dot, the note on one line without the merged line, the
    // choice stays.
    let (_, page) = a.get("/settings").await;
    let key = page
        .split(r#"data-sync-dismiss=""#)
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or_else(|| panic!("a Dismiss button: {page}"))
        .to_string();
    let (s, r) = a
        .post("/api/settings/dismiss", json!({ "key": "stale" }))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{r}");
    let merged_at: i64 = page
        .split(r#"data-merged-at=""#)
        .nth(1)
        .and_then(|r| r.split('"').next())
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| panic!("the merge's record goes with Dismiss: {page}"));
    let (s, r) = a
        .post(
            "/api/settings/dismiss",
            json!({ "key": key, "merged_at": merged_at }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (_, page) = a.get("/runs").await;
    assert!(!dot(&page), "dismissed: {page}");
    let (_, page) = a.get("/settings").await;
    assert!(!dot(&page), "no dot on the rail nor the links: {page}");
    assert!(
        page.contains(r#"<p class="sync-quiet" role="status">"#)
            && page.contains("<span>Stale Tier Zero account has two values.</span>"),
        "the note on one line: {page}"
    );
    assert!(
        !page.contains("data-sync-dismiss") && !page.contains("Merged from the shared settings"),
        "{page}"
    );
    assert!(
        page.contains("Use 60") && page.contains(r#"<span class="chip-from">shared · "#),
        "the choice and the mark stay: {page}"
    );
    // The same clash after a restart: still dismissed.
    {
        let st2 = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), 4251));
        let b = App {
            router: router(st2.clone()),
            state: st2,
            dir: std::env::temp_dir().join("pathwarden-ui-sync-unused"),
        };
        let (_, page) = b.get("/runs").await;
        assert!(!dot(&page), "after a restart: {page}");
    }
    // A new value on either side is a new clash: the dot is back.
    apply(ws.config_path(), |d| d.set_rules(&rules(31), &by)).unwrap();
    let (_, page) = a.get("/runs").await;
    assert!(dot(&page), "a changed clash: {page}");
    // Keep 31: shared, up to date again.
    let (s, r) = a
        .post(
            "/api/settings/sync",
            json!({ "action": "keep_local", "section": "rules.stale_days" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert!(
        r["note"]
            .as_str()
            .is_some_and(|n| n.contains("Stale Tier Zero account: kept 31 days")),
        "{r}"
    );
    let (_, page) = a.get("/settings").await;
    assert!(
        !page.contains("sync-conflict") && !page.contains("sync-quiet"),
        "{page}"
    );
    assert!(!page.contains("Keep 31"));
    assert!(!dot(&page), "resolved: {page}");
    // Resolved: the dismissal is gone, so the next clash shows.
    {
        let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
        assert_eq!(
            pathwarden_core::settings_sync::dismissed_key(&loc.store),
            None
        );
    }
    let (s, r) = a
        .post(
            "/api/settings/sync",
            json!({ "action": "x", "section": "tier_zero" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
}

/// `git ARGS` in `dir`, its output.
fn git_out(dir: &Path, args: &[&str]) -> String {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    let out = c.arg("-C").arg(dir).args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every object of the repository at `remote`, as text.
fn all_objects(remote: &Path) -> String {
    git_out(remote, &["cat-file", "--batch-all-objects", "--batch"])
}

/// What only the settings say: never in the repository in plain text.
const SECRETS: [&str; 4] = [
    "Break-glass, reviewed quarterly",
    "eddard.stark",
    "accepted_by",
    "Changed-by",
];

/// "Set passphrase and save" with "Full runs and settings": the history is
/// encrypted before anything is shared, so no object of the repository ever
/// holds a setting in plain text. Without a passphrase, full runs and
/// settings waits for the choice to keep it plain ("Don't encrypt"), and
/// shares only then.
#[tokio::test]
async fn full_runs_and_settings_shares_nothing_plain() {
    if !git_ok() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-fullenc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    pathwarden_core::keystore::use_test_store(&dir.join("keystore"));
    let setup = |name: &str| {
        let remote = dir.join(format!("{name}.git"));
        let mut c = Command::new("git");
        for v in pathwarden_core::store::GIT_LOCAL_ENV {
            c.env_remove(v);
        }
        assert!(c
            .args(["init", "-q", "--bare"])
            .arg(&remote)
            .status()
            .unwrap()
            .success());
        let ws = Workspace::open(dir.join(name)).unwrap();
        std::fs::write(
            ws.config_path(),
            format!(
                "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"state\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"Break-glass, reviewed quarterly\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"PW-SCHED01\"\n",
                slash(&remote)
            ),
        )
        .unwrap();
        let form = json!({
            "backend": "git",
            "remote": slash(&remote),
            "path": "state",
            "keep": "full",
            "push": true,
        });
        // These pages set where the history is kept: as `pathwarden ui --allow-destinations`.
        let mut st = AppState::new(ws.clone(), Token::generate().unwrap(), 4251);
        st.allow_destinations = true;
        let st = Arc::new(st);
        let app = App {
            router: router(st.clone()),
            state: st,
            dir: dir.join(format!("{name}-gone")),
        };
        (remote, ws, form, app)
    };

    // Full runs and settings on a history that isn't encrypted: refused
    // until the user chooses.
    let (remote, ws, form, a) = setup("enc");
    let (s, r) = a.post("/api/settings/state", form.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert!(
        r["error"]
            .as_str()
            .unwrap()
            .contains("Choose whether to encrypt"),
        "{r}"
    );
    assert!(!r["error"].as_str().unwrap().contains("--"), "{r}");
    let text = std::fs::read_to_string(ws.config_path()).unwrap();
    assert!(!text.contains("keep"), "{text}");

    // "Set passphrase and save": encrypted first, then shared.
    let (s, r) = a
        .post(
            "/api/history/encryption",
            json!({ "on": true, "passphrase": "correct horse battery staple", "state": form }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let text = std::fs::read_to_string(ws.config_path()).unwrap();
    assert!(
        text.contains("keep = \"full\"") && text.contains("encrypted = true"),
        "{text}"
    );
    let files = git_out(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(files.contains("settings/pathwarden.toml.age"), "{files}");
    assert!(!files.contains("settings/pathwarden.toml\n"), "{files}");
    let objects = all_objects(&remote);
    for s in SECRETS {
        assert!(
            !objects.contains(s),
            "an object of the repository holds {s}"
        );
    }
    let log = git_out(&remote, &["log", "--format=%an <%ae> %B", "main"]);
    assert!(log.contains("pathwarden settings"), "{log}");
    // Without the passphrase here, Settings says so: never "up to date".
    pathwarden_core::crypt::forget_all_in_process();
    pathwarden_core::keystore::use_test_store(&dir.join("keystore-none"));
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains("t be read here: this history is encrypted"),
        "{page}"
    );
    assert!(
        !page.contains("passphrase set"),
        "no commands on pages: {page}"
    );
    assert!(!page.contains("up to date"), "{page}");

    // Kept plain on purpose ("Don't encrypt", then Save): shared then, and
    // not before.
    let (remote, plain_ws, form, a) = setup("plain");
    let (s, r) = a.post("/api/settings/state", form.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{r}");
    assert!(all_objects(&remote).trim().is_empty());
    let mut plain = form;
    plain["share_plain"] = true.into();
    let (s, r) = a.post("/api/settings/state", plain).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let id = r["sharing"].as_u64().unwrap_or_else(|| panic!("{r}"));
    let mut shared = Value::Null;
    for _ in 0..600 {
        let (_, body) = a.get(&format!("/api/settings/sharing?id={id}")).await;
        shared = serde_json::from_str(&body).unwrap();
        if shared["running"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(shared["running"], false, "{shared}");
    assert!(
        all_objects(&remote).contains("Break-glass, reviewed quarterly"),
        "shared in plain text, as chosen"
    );
    // ... and said so on History storage, the one place that says where
    // the history lives and whether it is encrypted; not atop Settings.
    let (_, page) = a.get("/settings").await;
    assert!(!page.contains("Shared through"), "{page}");
    let (_, page) = a.get("/automate/history").await;
    assert!(page.contains("in plain text (not encrypted)"), "{page}");

    // A history decrypted elsewhere, which this computer expects
    // encrypted: refused, in the page's words, no commands.
    apply(plain_ws.config_path(), |d| d.set_state_encrypted(true)).unwrap();
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains("expects the history encrypted") && page.contains("see History storage"),
        "{page}"
    );
    assert!(
        !page.contains("--no-encrypt") && !page.contains("pathwarden history"),
        "no commands on pages: {page}"
    );
    assert!(!page.contains("up to date"), "{page}");
    let _ = std::fs::remove_dir_all(&dir);
}
