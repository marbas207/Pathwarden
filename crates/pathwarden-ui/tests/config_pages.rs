//! Settings, Privilege Zones and Plugins through the router: config
//! write-back, the zone preview against core, search limits and escaping,
//! and a plugin dry run.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::object_index::{IndexedObject, ObjectIndex};
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const PORT: u16 = 4243;
const HOST: &str = "127.0.0.1:4243";
const MARKUP: &str = "<IMG SRC=X ONERROR=ALERT(1)>@EVIL.LOCAL";

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

fn app(name: &str) -> App {
    app_with(name, false)
}

/// `allow_commands`: as `pathwarden ui --allow-destinations`.
fn app_with(name: &str, allow_commands: bool) -> App {
    let dir = std::env::temp_dir().join(format!("pathwarden-cfg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let mut state = AppState::new(ws, Token::generate().unwrap(), PORT);
    state.allow_destinations = allow_commands;
    let state = Arc::new(state);
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

impl App {
    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let (s, _, b) = self
            .send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await;
        (s, b)
    }

    async fn json(&self, method: Method, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = self
            .request(method, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    /// What the Settings page says a section loaded (`data-loaded`).
    async fn loaded(&self, section: &str) -> Value {
        let (_, body) = self.get("/settings").await;
        let key = format!("data-section=\"{section}\" data-loaded=\"");
        let start = body.find(&key).unwrap_or_else(|| panic!("no {key}")) + key.len();
        let raw = &body[start..start + body[start..].find('"').unwrap()];
        serde_json::from_str(&raw.replace("&quot;", "\"").replace("&amp;", "&")).unwrap()
    }

    fn config(&self) -> Option<String> {
        std::fs::read_to_string(self.state.ws().config_path()).ok()
    }

    /// Analyzes a folder by path and waits for the run.
    async fn analyze(&self, path: PathBuf) -> String {
        let boundary = "cfgTestBoundary";
        // Into the workspace's own environment, whose settings these pages
        // edit (it has a pathwarden.toml, so a run wouldn't take it over).
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
        let (s, _, b) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..600 {
            let (_, body) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{v}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }
}

#[tokio::test]
async fn pages_render_without_a_config_or_a_run() {
    let a = app("pages");
    for uri in [
        "/settings",
        "/zones",
        "/zones/new",
        "/automate/ticketing",
        "/automate/history",
        "/plugins/new?kind=servicenow",
        "/plugins/new?kind=jira",
        "/plugins/new?kind=command",
        "/plugins/add",
        "/plugins/add?what=servicenow",
        "/plugins/add?what=servicenow&when=scheduled",
    ] {
        let (s, body) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert!(body.contains("/static/config.js"), "{uri}");
        assert!(!body.contains("<script>"), "{uri}: no inline scripts");
        assert!(!body.contains(" style=\""), "{uri}: no inline styles");
    }
    // Plugins moved to Automate › Plugins and actions.
    let (s, _) = a.get("/plugins").await;
    assert_eq!(s, StatusCode::PERMANENT_REDIRECT);
    let (s, _) = a.get("/zones/0/edit").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, body) = a.get("/zones/new").await;
    assert!(body.contains("need one run first"));
    assert!(body.contains("Search works after the first run"));
    let (s, v) = a
        .json(
            Method::POST,
            "/api/zones/preview",
            json!({"name": "x", "members": ["A"]}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
}

#[tokio::test]
async fn saves_keep_the_file_and_refuse_invalid_values() {
    let a = app("save");
    assert!(a.config().is_none());
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": ["BACKUP01.CONTOSO.LOCAL"], "loaded": []}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap();
    assert!(text.contains("# Systems and accounts your organization treats as Tier Zero"));
    assert!(text.contains("\"BACKUP01.CONTOSO.LOCAL\""));

    // A hand edit survives later saves.
    let edited = text.replace("[rules]\n", "[rules]\n# Agreed with the SOC, 2026-10.\n");
    std::fs::write(a.state.ws().config_path(), &edited).unwrap();
    let mut rules = json!({"stale_days": 30, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "static", "disabled": ["PW-011"]});
    rules["loaded"] = a.loaded("rules").await;
    let (s, v) = a.json(Method::POST, "/api/settings/rules", rules).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap();
    assert!(text.contains("# Agreed with the SOC, 2026-10.\n"));
    assert!(text.contains("stale_days = 30"));
    assert!(text.contains("disabled = [\"PW-011\"]"));

    // The Seamless SSO key age (PW-037): saved, shown in the field, and in
    // what the page's next save compares with.
    let mut rules = json!({"stale_days": 30, "password_age_days": 365, "krbtgt_age_days": 180, "sso_key_age_days": 45, "severity": "static", "disabled": ["PW-011"]});
    rules["loaded"] = a.loaded("rules").await;
    let (s, v) = a.json(Method::POST, "/api/settings/rules", rules).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["loaded"]["sso_key_age_days"], 45);
    assert!(a.config().unwrap().contains("sso_key_age_days = 45"));
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains(r#"id="sso_key_age_days" min="1" max="36500" step="1" value="45""#),
        "the field shows the saved value"
    );

    // Invalid values: an error, and the file is untouched.
    for (uri, body) in [
        (
            "/api/settings/rules",
            json!({"stale_days": 0, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "static", "disabled": [], "loaded": a.loaded("rules").await}),
        ),
        (
            // A fraction: the same message, not an unreadable request.
            "/api/settings/rules",
            json!({"stale_days": 1.5, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "static", "disabled": [], "loaded": a.loaded("rules").await}),
        ),
        (
            "/api/settings/suppress",
            json!({"risk": {"rule": "PW-004", "reason": " "}}),
        ),
        (
            "/api/settings/suppress",
            json!({"risk": {"fingerprint": "PW-004-zz", "reason": "x"}}),
        ),
        (
            "/api/settings/state",
            json!({"backend": "git", "remote": "--upload-pack=evil"}),
        ),
        (
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://x/y.git", "branch": "-f"}),
        ),
        ("/api/zones", json!({"zone": {"name": "Empty"}})),
        (
            "/api/zones",
            json!({"zone": {"name": "Tier Zero", "members": ["A"]}}),
        ),
        (
            "/api/plugins",
            json!({"kind": "command", "plugin": "teams", "command": ["teams.exe"]}),
        ),
        (
            "/api/plugins",
            json!({"kind": "command", "plugin": "teams", "command": ["pwsh"], "settings": [["webhook", "https://hooks/secret"]]}),
        ),
        (
            "/api/plugins",
            json!({"kind": "servicenow", "instance": "http://sn.example.com", "table": "incident", "min_severity": "high", "auth": "basic", "username_env": "U", "password_env": "P"}),
        ),
        (
            "/api/plugins",
            json!({"kind": "servicenow", "instance": "https://u:p@sn.example.com", "table": "incident", "min_severity": "high", "auth": "basic", "username_env": "U", "password_env": "P"}),
        ),
    ] {
        let before = a.config();
        let (s, v) = a.json(Method::POST, uri, body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri} {body}: {v}");
        assert!(v["error"].as_str().is_some_and(|e| !e.is_empty()), "{v}");
        assert_eq!(a.config(), before, "{uri} changed the file");
    }

    // A file that core can't load is shown, and not made worse.
    std::fs::write(a.state.ws().config_path(), "tier_zero = [\n").unwrap();
    let (s, body) = a.get("/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Settings can't be read"));
    let (s, _) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": [], "loaded": []}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(a.config().unwrap(), "tier_zero = [\n");
}

#[tokio::test]
async fn changes_from_other_origins_are_refused() {
    let a = app("origin");
    let req = a
        .request(Method::POST, "/api/settings/tier-zero")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::from(r#"{"items":["X"]}"#))
        .unwrap();
    let (s, _, _) = a.send(req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(a.config().is_none());
}

#[tokio::test]
async fn zone_preview_matches_the_analysis() {
    use pathwarden_core::zones::{self, ZoneConfig};
    let a = app("zones");
    let run = a.analyze(testdata("forest")).await;
    let dir = a.state.ws().run_dir(&run).unwrap();
    assert!(dir.join("objects.json.gz").is_file());
    assert!(dir.join("event.json.gz").is_file());

    // Core's own resolution on the collected data, as `exposure --zone` uses.
    let (g, _) = pathwarden_core::load(&[testdata("forest")], &Default::default()).unwrap();
    let defs = [
        json!({"name": "App servers", "members": ["SRV01.CONTOSO.LOCAL", "APP01.CONTOSO.LOCAL", "NOPE.CONTOSO.LOCAL"]}),
        json!({"name": "Helpdesk", "groups": ["HELPDESK@CONTOSO.LOCAL"]}),
        json!({"name": "Workstations", "ous": ["WORKSTATIONS@CONTOSO.LOCAL"]}),
        json!({"name": "Mixed", "groups": ["DOMAIN ADMINS@CONTOSO.LOCAL"], "ous": ["OU=SERVERS,DC=CONTOSO,DC=LOCAL"]}),
    ];
    for def in defs {
        let (s, v) = a
            .json(Method::POST, "/api/zones/preview", def.clone())
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let config: ZoneConfig = serde_json::from_value(def.clone()).unwrap();
        let expected = &zones::resolve(&g, std::slice::from_ref(&config))[0];
        let p = &v["preview"];
        assert_eq!(p["total"], expected.members.len(), "{def}: {v}");
        assert_eq!(p["unresolved"], json!(expected.unresolved), "{def}");
        let mut sample: Vec<String> = serde_json::from_value(p["sample"].clone()).unwrap();
        let mut names: Vec<String> = expected
            .members
            .iter()
            .map(|&ix| g.node(ix).name.clone())
            .collect();
        sample.sort();
        names.sort();
        names.truncate(12);
        if expected.members.len() <= 12 {
            assert_eq!(sample, names, "{def}");
        }
    }
    let (_, v) = a
        .json(
            Method::POST,
            "/api/zones/preview",
            json!({"name": "T0", "groups": ["DOMAIN ADMINS@CONTOSO.LOCAL"]}),
        )
        .await;
    // The warnings are core's words, as `pathwarden zones preview` prints them.
    assert_eq!(
        v["warnings"],
        json!(["DOMAIN ADMINS@CONTOSO.LOCAL is Tier Zero, so it is left out."])
    );
    assert_eq!(
        v["preview"]["tier_zero"],
        json!(["DOMAIN ADMINS@CONTOSO.LOCAL"])
    );

    // Save, edit, and delete a zone.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/zones",
            json!({"zone": {"name": "Helpdesk", "groups": ["HELPDESK@CONTOSO.LOCAL"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, body) = a.get("/zones").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Helpdesk") && body.contains("1 group"));
    let (s, _) = a
        .json(
            Method::POST,
            "/api/zones",
            json!({"index": 0, "expect": "Payroll", "zone": {"name": "X", "members": ["A"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a stale edit is refused");
    let (s, _) = a
        .json(
            Method::DELETE,
            "/api/zones/0",
            json!({"expect": "Helpdesk"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let config = pathwarden_core::config::Config::parse(&a.config().unwrap()).unwrap();
    assert!(config.zones.is_empty());

    // Findings of the latest run are searchable for accepting a risk.
    let (s, body) = a.get("/api/findings?q=pw-").await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    let first = &v["results"][0];
    let fp = first["fingerprint"].as_str().unwrap();
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"risk": {"fingerprint": fp, "reason": "Reviewed", "expires": "2020-01-01"}}),
        )
        .await;
    // A day already over would accept nothing.
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("Jan 1, 2020 has passed."),
        "{v}"
    );
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"risk": {"fingerprint": fp, "reason": "Reviewed", "expires": "2099-01-01"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // One that has expired since shows so, and saves unchanged.
    let config = a.config().unwrap().replace("2099-01-01", "2020-01-01");
    std::fs::write(a.state.ws().config_path(), config).unwrap();
    let (_, body) = a.get("/settings").await;
    assert!(
        body.contains("pill expired") && body.contains("Review by Jan 1, 2020"),
        "{body}"
    );
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"index": 0, "expect": "Reviewed", "expect_target": fp, "risk": {"fingerprint": fp, "reason": "Reviewed again", "expires": "2020-01-01"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// Accepting, changing and annotating a risk in the app records who did it,
/// on which computer and when, and keeps the file's comments and entries.
#[tokio::test]
async fn accepted_risks_record_who_and_when() {
    let a = app("risk-attribution");
    std::fs::write(
        a.state.ws().config_path(),
        "# Our settings.\n[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\" # CAB 12\n",
    )
    .unwrap();
    let me = pathwarden_core::identity::Actor::current();
    let load = || pathwarden_core::config::Config::parse(&a.config().unwrap()).unwrap();

    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"risk": {"fingerprint": "PW-004-13b0863341b2e306", "reason": "Break-glass"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = load();
    // The old entry is untouched and reads as not recorded.
    assert!(c.suppress[0].accepted_by.is_none());
    assert!(a.config().unwrap().contains("# Our settings.\n"));
    assert!(a.config().unwrap().contains("reason = \"Kiosks\" # CAB 12"));
    let new = &c.suppress[1];
    assert_eq!(new.accepted_by, me.user);
    assert_eq!(new.accepted_on, me.computer);
    let at = new.accepted_at.clone().unwrap();
    assert!(pathwarden_core::time::parse_rfc3339(&at).is_some(), "{at}");
    assert!(new.changed_at.is_none());

    // Edit: a new review date is a change.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"index": 1, "expect": "Break-glass", "expect_target": "PW-004-13b0863341b2e306", "risk": {"fingerprint": "PW-004-13b0863341b2e306", "reason": "Break-glass", "expires": "2099-01-31"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = load();
    assert_eq!(c.suppress[1].changed_by, me.user);
    assert!(c.suppress[1].changed_at.is_some());
    assert_eq!(c.suppress[1].accepted_at.as_deref(), Some(at.as_str()));
    // And an old entry edited records the change, not who accepted it.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"index": 0, "expect": "Kiosks", "expect_target": "PW-011", "risk": {"rule": "PW-011", "reason": "Kiosks, CAB 13"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = load();
    assert!(c.suppress[0].accepted_by.is_none());
    assert_eq!(c.suppress[0].changed_on, me.computer);

    // Notes are appended, with who wrote them.
    for text in ["Checked with the CAB.", "Renewed for Q1."] {
        let (s, v) = a
            .json(
                Method::POST,
                "/api/settings/suppress/1/note",
                json!({"expect": "Break-glass", "expect_target": "PW-004-13b0863341b2e306", "text": text}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let c = load();
    let notes = &c.suppress[1].notes;
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0].text, "Checked with the CAB.");
    assert_eq!(notes[1].text, "Renewed for Q1.");
    assert_eq!(notes[1].by, me.user);
    assert!(notes[1].at.is_some());
    // A page from before this version (no target): reload it.
    let before = a.config().unwrap();
    for (method, uri, body) in [
        (
            Method::POST,
            "/api/settings/suppress/1/note",
            json!({"expect": "Break-glass", "text": "x"}),
        ),
        (
            Method::DELETE,
            "/api/settings/suppress/1",
            json!({"expect": "Break-glass"}),
        ),
        (
            Method::POST,
            "/api/settings/suppress",
            json!({"index": 1, "expect": "Break-glass", "risk": {"fingerprint": "PW-004-13b0863341b2e306", "reason": "x"}}),
        ),
    ] {
        let (s, v) = a.json(method, uri, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert_eq!(v["error"], "This page is out of date. Reload it.", "{uri}");
    }
    assert_eq!(a.config().unwrap(), before);
    // A stale page, an empty note: refused, nothing written.
    for body in [
        json!({"expect": "Something else", "expect_target": "PW-004-13b0863341b2e306", "text": "x"}),
        json!({"expect": "Break-glass", "expect_target": "PW-004-13b0863341b2e306", "text": "  "}),
    ] {
        let (s, _) = a
            .json(Method::POST, "/api/settings/suppress/1/note", body)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (s, _) = a
        .json(
            Method::POST,
            "/api/settings/suppress/9/note",
            json!({"expect": "x", "expect_target": "x", "text": "x"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // A note over the length limit, or for an entry that now covers
    // something else (its reason matches, its target doesn't): refused.
    for body in [
        json!({"expect": "Break-glass", "expect_target": "PW-004-13b0863341b2e306", "text": "x".repeat(2049)}),
        json!({"expect": "Break-glass", "expect_target": "PW-011", "text": "x"}),
    ] {
        let (s, v) = a
            .json(Method::POST, "/api/settings/suppress/1/note", body)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    }
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            json!({"index": 1, "expect": "Break-glass", "expect_target": "PW-011", "risk": {"rule": "PW-011", "reason": "x"}}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = a
        .json(
            Method::DELETE,
            "/api/settings/suppress/1",
            json!({"expect": "Break-glass", "expect_target": "PW-011"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(a.config().unwrap(), before);
    // With its own target it goes through.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress/1/note",
            json!({"expect": "Break-glass", "expect_target": "PW-004-13b0863341b2e306", "text": "x".repeat(2048)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The lock next to the file is free after every save.
    let lock = a
        .state
        .ws()
        .config_path()
        .with_file_name(".pathwarden.toml.lock");
    let f = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
    f.try_lock().unwrap();
}

/// A page loaded before the file changed (the command line, another page)
/// can't undo that change: Tier Zero and rule saves send what the page
/// loaded, and are refused when it no longer matches.
#[tokio::test]
async fn stale_settings_pages_are_refused() {
    let a = app("stale");
    std::fs::write(a.state.ws().config_path(), "tier_zero = [\"A@X.LOCAL\"]\n").unwrap();
    let t0 = a.loaded("tier-zero").await;
    assert_eq!(t0, json!(["A@X.LOCAL"]));
    let rules = a.loaded("rules").await;
    // The command line adds one, and changes a threshold.
    std::fs::write(
        a.state.ws().config_path(),
        "tier_zero = [\"A@X.LOCAL\", \"B@X.LOCAL\"]\n[rules]\nstale_days = 30\n",
    )
    .unwrap();
    let before = a.config();
    for (uri, body) in [
        (
            "/api/settings/tier-zero",
            json!({"items": ["A@X.LOCAL", "C@X.LOCAL"], "loaded": t0}),
        ),
        ("/api/settings/tier-zero", json!({"items": ["A@X.LOCAL"]})),
        (
            "/api/settings/rules",
            json!({"stale_days": 90, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": ["PW-011"], "loaded": rules}),
        ),
        (
            "/api/settings/rules",
            json!({"stale_days": 90, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": []}),
        ),
    ] {
        let (s, v) = a.json(Method::POST, uri, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {v}");
        assert_eq!(v["error"], "This page is out of date. Reload it.", "{uri}");
    }
    assert_eq!(a.config(), before);
    // Reloaded, the same saves go through.
    let t0 = a.loaded("tier-zero").await;
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": ["A@X.LOCAL", "B@X.LOCAL", "C@X.LOCAL"], "loaded": t0}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let rules = a.loaded("rules").await;
    assert_eq!(rules["stale_days"], 30);
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            json!({"stale_days": 30, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": ["pw-011"], "loaded": rules}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The page's own next save (what config.js keeps as loaded) matches.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            json!({"stale_days": 31, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": ["PW-011"],
                   "loaded": {"stale_days": 30, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": ["PW-011"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// The saves answer with the list or rules as the file now holds them (the
/// page's next save compares with that); a second tab that loaded the same
/// page is refused; a file that can't be read is refused with why.
#[tokio::test]
async fn saves_answer_with_what_the_file_holds() {
    let a = app("canonical");
    let t0 = a.loaded("tier-zero").await;
    // Duplicates and spaces: the file keeps one, trimmed.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": [" A@X.LOCAL ", "a@x.local", "B@X.LOCAL"], "loaded": t0}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["loaded"], json!(["A@X.LOCAL", "B@X.LOCAL"]));
    // The page's next save, with what came back: accepted.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": ["A@X.LOCAL"], "loaded": v["loaded"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Rules from two tabs that loaded the same page: the second is refused.
    let page = a.loaded("rules").await;
    let tab = |stale: i64| {
        json!({"stale_days": stale, "password_age_days": 365, "krbtgt_age_days": 180,
               "severity": "exposure", "disabled": [], "loaded": page.clone()})
    };
    let (s, v) = a.json(Method::POST, "/api/settings/rules", tab(45)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["loaded"]["stale_days"], 45);
    let (s, v) = a.json(Method::POST, "/api/settings/rules", tab(60)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "This page is out of date. Reload it.");
    assert!(a.config().unwrap().contains("stale_days = 45"));

    // A file that parses but doesn't load: refused, saying why.
    std::fs::write(
        a.state.ws().config_path(),
        "[[suppress]]\nreason = \"no target\"\n",
    )
    .unwrap();
    for (uri, body) in [
        (
            "/api/settings/tier-zero",
            json!({"items": ["X"], "loaded": []}),
        ),
        ("/api/settings/rules", tab(30)),
    ] {
        let (s, v) = a.json(Method::POST, uri, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {v}");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("Settings can't be read"),
            "{v}"
        );
    }
    assert_eq!(
        a.config().unwrap(),
        "[[suppress]]\nreason = \"no target\"\n"
    );
}

/// A note of several lines is kept as written (one escaped string in the
/// file) and shown line by line; a CRLF file stays CRLF.
#[tokio::test]
async fn notes_of_several_lines_and_crlf_files() {
    let a = app("multiline");
    std::fs::write(
        a.state.ws().config_path(),
        "# Ours.\r\n[[suppress]]\r\nrule = \"PW-011\"\r\nreason = \"Kiosks\"\r\n",
    )
    .unwrap();
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress/0/note",
            json!({"expect": "Kiosks", "expect_target": "PW-011", "text": "First line\r\nsecond line"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap();
    assert!(text.starts_with("# Ours.\r\n[[suppress]]\r\n"), "{text:?}");
    assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
    assert!(
        text.contains("text = \"First line\\nsecond line\"\r\n"),
        "{text:?}"
    );
    let (_, body) = a.get("/settings").await;
    assert!(
        body.contains("<span class=\"note-text\">First line\nsecond line</span>"),
        "{body}"
    );
    // A bidi control is refused, as are other control characters.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress/0/note",
            json!({"expect": "Kiosks", "expect_target": "PW-011", "text": "a\u{202e}b"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

/// A Tier Zero name holding a bidi control, saved unchanged from the page
/// (what the chips send back), leaves the file byte for byte as it was:
/// the chips carry the name itself, not how the page shows it.
#[tokio::test]
async fn names_with_bidi_controls_survive_a_save() {
    let a = app("bidi-names");
    let original = "tier_zero = [\"A@X.LOCAL\", \"EVIL\\u202Egpj.exe@X.LOCAL\"]\n";
    std::fs::write(a.state.ws().config_path(), original).unwrap();
    let (_, body) = a.get("/settings").await;
    // What config.js sends: every chip's data-value.
    let items: Vec<String> = body
        .split(r#"<li class="chip-item" data-value=""#)
        .skip(1)
        .map(|p| {
            p[..p.find('"').unwrap()]
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
        })
        .collect();
    assert_eq!(items, ["A@X.LOCAL", "EVIL\u{202e}gpj.exe@X.LOCAL"]);
    // Shown, not obeyed, where it is text.
    assert!(body.contains(r#"<span class="chip-text">EVIL\u{202e}gpj.exe@X.LOCAL</span>"#));
    let loaded = a.loaded("tier-zero").await;
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": items, "loaded": loaded}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let after = std::fs::read(a.state.ws().config_path()).unwrap();
    assert_eq!(String::from_utf8(after).unwrap(), original);
}

/// Settings shows who accepted each risk, where and when, the last change,
/// the notes folded under it, old entries as not recorded, an unknown user
/// as such, and keys a newer version wrote as ignored. No command hints.
#[tokio::test]
async fn settings_show_who_accepted_each_risk() {
    let a = app("risk-page");
    std::fs::write(
        a.state.ws().config_path(),
        r#"tier_zero = ["SVC\u202E@X.LOCAL"]

[[suppress]]
fingerprint = "PW-004-13b0863341b2e306"
reason = "Break-glass <admin>"
expires = "2099-03-31"
accepted_by = 'NORTH\eddard.stark'
accepted_on = "SECOPS-WS02"
accepted_at = "2026-10-22T14:03:11Z"
changed_by = 'NORTH\robb.stark'
changed_on = "SECOPS-WS03"
changed_at = "2026-10-29T10:12:40Z"
ticket = "CHG7"

[[suppress.notes]]
by = 'NORTH\robb.stark'
on = "SECOPS-WS03"
at = "2026-10-29T10:11:02Z"
text = "Checked with the <CAB>."

[[suppress]]
rule = "PW-011"
reason = "LAPS rollout"
accepted_on = "PW-SCHED01"
accepted_at = "2026-10-22T14:03:11Z"

[[suppress]]
fingerprint = "PW-012-dae8c94b3afae522"
reason = "Trust \u202Ekept open"
"#,
    )
    .unwrap();
    let (s, body) = a.get("/settings").await;
    assert_eq!(s, StatusCode::OK);
    let risks = &body[body.find(r#"id="risks""#).unwrap()..];
    let risks = &risks[..risks.find("</section>").unwrap()];
    // The local day of when it was accepted; review dates as typed.
    assert!(risks.contains("Accepted by <b>NORTH\\eddard.stark</b> on <b>SECOPS-WS02</b>, <time datetime=\"2026-10-22T14:03:11Z\">Oct 22, 2026</time>"), "{risks}");
    assert!(risks.contains("Review by Mar 31, 2099"), "{risks}");
    assert!(
        risks.contains("changed by <b>NORTH\\robb.stark</b> on <b>SECOPS-WS03</b>"),
        "{risks}"
    );
    assert!(risks.contains("<summary>1 note</summary>"), "{risks}");
    assert!(risks.contains("Checked with the &lt;CAB&gt;."));
    assert!(risks.contains("Break-glass &lt;admin&gt;"));
    assert!(
        risks.contains("Accepted by an unknown user on <b>PW-SCHED01</b>"),
        "{risks}"
    );
    assert!(risks.contains("Who accepted it wasn't recorded"));
    assert!(
        risks.contains("Some settings come from a newer Pathwarden and are ignored here.")
            && risks.contains("<p>Accepted risk 1: <code>ticket</code></p>")
            && !risks.contains("[[suppress]]"),
        "{risks}"
    );
    assert!(risks.contains("data-note-risk") && risks.contains(r#"id="note-form""#));
    // Settings aren't shared through a repository yet (A3): no tag.
    assert!(!risks.contains("From the run history"));
    // Plain words only: no commands on the page.
    assert!(!risks.contains("pathwarden config"), "{risks}");
    // Every risk's data reads as JSON, a bidi control in a reason included
    // (one such reason used to leave the page's script without its data).
    let mut rows = 0;
    for part in risks.split(r#"data-risk=""#).skip(1) {
        let raw = &part[..part.find('"').unwrap()];
        let text = raw
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&#39;", "'")
            .replace("&amp;", "&");
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
        assert!(v["reason"].is_string());
        rows += 1;
    }
    assert_eq!(rows, 3);
    assert!(
        risks.contains(r"Trust \u{202e}kept open"),
        "shown, not obeyed"
    );
    // And the Tier Zero list the page compares its next save with.
    assert_eq!(a.loaded("tier-zero").await, json!(["SVC\u{202e}@X.LOCAL"]));
    // A note through the page's endpoint comes back as saved.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress/2/note",
            json!({"expect": "Trust \u{202e}kept open", "expect_target": "PW-012-dae8c94b3afae522", "text": "Still needed."}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let me = pathwarden_core::identity::Actor::current();
    assert_eq!(v["note"]["text"], "Still needed.");
    assert_eq!(v["note"]["on"], json!(me.computer));
    let (_, body) = a.get("/settings").await;
    assert!(body.contains("<summary>1 note</summary>") && body.contains("Still needed."));
}

/// Credentials in a hand-edited `[state] remote` are never shown, survive a
/// save of the page's redacted form, and new ones are refused.
#[tokio::test]
async fn state_remote_credentials_are_hidden_and_kept() {
    let a = app("remote-creds");
    std::fs::write(
        a.state.ws().config_path(),
        "[state]\nbackend = \"git\"\nremote = \"https://u:ghp_SECRET@example.com/s.git\"\n",
    )
    .unwrap();
    // The [state] form lives on Automate › History storage.
    let (s, body) = a.get("/automate/history").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.contains("ghp_SECRET"));
    assert!(body.contains("https://***@example.com/s.git"));
    assert!(body.contains("contains a password or token"));

    let save = |remote: &str| json!({"backend": "git", "remote": remote});
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/state",
            save("https://***@example.com/s.git"),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(a.config().unwrap().contains("ghp_SECRET"), "kept");

    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/state",
            save("https://u:other@example.com/t.git"),
        )
        .await;
    assert_ne!(s, StatusCode::OK, "{v}");
    assert!(!v.to_string().contains("other@"), "{v}");
}

/// A run with a made-up object index, for search tests.
fn fake_run(a: &App, objects: Vec<IndexedObject>) {
    let id = "20261009-120000-abcdef";
    let dir = a.state.ws().runs_dir().join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let summary = json!({
        "id": id, "created_at": 1791547200, "collected_at": null, "source": "test", "demo": false,
        "domains": ["EVIL.LOCAL"], "objects": objects.len(), "files": 1, "exposure_percent": 0.0,
        "exposed": 0, "population": 0, "protection_score": null, "critical": 0, "high": 0, "medium": 0,
        "low": 0, "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "test"
    });
    std::fs::write(dir.join("summary.json"), summary.to_string()).unwrap();
    std::fs::write(dir.join("report.html"), "<html></html>").unwrap();
    let index = ObjectIndex {
        version: 1,
        domains: vec!["EVIL.LOCAL".into()],
        objects,
        ..Default::default()
    };
    pathwarden_ui::run_data::write_gz(
        &dir.join("objects.json.gz"),
        serde_json::to_string(&index).unwrap().as_bytes(),
    )
    .unwrap();
}

#[tokio::test]
async fn search_is_capped_and_names_are_escaped() {
    let a = app("search");
    let mut objects: Vec<IndexedObject> = (0..60)
        .map(|i| {
            IndexedObject(
                format!("S-1-5-21-9-9-9-{}", 1000 + i),
                format!("USER{i:02}@EVIL.LOCAL"),
                0,
                0,
                String::new(),
                0,
            )
        })
        .collect();
    objects.push(IndexedObject(
        "S-1-5-21-9-9-9-666".into(),
        MARKUP.into(),
        2,
        0,
        String::new(),
        0,
    ));
    fake_run(&a, objects);

    let (s, body) = a.get("/api/objects?q=user").await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["results"].as_array().unwrap().len(), 20);
    assert_eq!(v["results"][0]["name"], "USER00@EVIL.LOCAL");
    let (_, body) = a.get("/api/objects?q=user&kinds=Group").await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["results"],
        json!([])
    );
    let (_, body) = a.get(&format!("/api/objects?q={}", "x".repeat(5000))).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["results"],
        json!([])
    );

    // The hostile name comes back as JSON data (served as JSON, never HTML).
    let req = a
        .request(Method::GET, "/api/objects?q=onerror")
        .body(Body::empty())
        .unwrap();
    let (_, headers, body) = a.send(req).await;
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["results"][0]["name"],
        MARKUP
    );

    // On pages it is escaped wherever it shows up.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/zones",
            json!({"zone": {"name": MARKUP, "groups": [MARKUP]}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/tier-zero",
            json!({"items": [MARKUP], "loaded": []}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for uri in ["/zones", "/zones/0/edit", "/settings"] {
        let (s, body) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert!(!body.contains("<IMG"), "{uri} has raw markup");
        assert!(body.contains("&lt;IMG SRC=X ONERROR=ALERT(1)&gt;"), "{uri}");
    }
    let (_, v) = a
        .json(
            Method::POST,
            "/api/zones/preview",
            json!({"name": "z", "groups": [MARKUP]}),
        )
        .await;
    assert_eq!(v["preview"]["sample"], json!([MARKUP]));
}

#[tokio::test]
async fn plugins_dry_run_on_the_latest_run_and_secrets_stay_out() {
    let a = app_with("plugins", true);
    // Before any run there is nothing to test against.
    let command: Vec<&str> = if cfg!(windows) {
        vec![
            "cmd",
            "/C",
            "echo",
            "settings=%PATHWARDEN_OUTPUT_SETTINGS%",
            "&",
            "findstr",
            "pathwarden.event.v1",
        ]
    } else {
        vec![
            "sh",
            "-c",
            "echo \"settings=$PATHWARDEN_OUTPUT_SETTINGS\"; grep -o pathwarden.event.v1",
        ]
    };
    let settings = json!([
        ["webhook_env", "PW_UI_TEST_HOOK"],
        ["min_change", "new"],
        ["timeout_seconds", "30"]
    ]);
    let (s, v) = a
        .json(Method::POST, "/api/plugins", json!({"kind": "command", "plugin": "stand-in", "command": command, "settings": settings}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap();
    assert!(text.contains("timeout_seconds = 30"), "{text}");
    let (s, _) = a
        .json(
            Method::POST,
            "/api/plugins/0/test",
            json!({"expect": "stand-in"}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    a.analyze(testdata("forest")).await;
    let (s, v) = a
        .json(
            Method::POST,
            "/api/plugins/0/test",
            json!({"expect": "stand-in"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    let out = v["output"].as_str().unwrap();
    assert!(out.contains("\"dry_run\":true"), "{out}");
    assert!(out.contains("pathwarden.event.v1"), "{out}");
    let (s, _) = a
        .json(
            Method::POST,
            "/api/plugins/0/test",
            json!({"expect": "other"}),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // The list shows whether named variables are set, never their values.
    std::env::set_var("PW_UI_TEST_HOOK", "https://hooks.example/very-secret");
    let (_, body) = a.get("/automate/ticketing").await;
    assert!(body.contains("PW_UI_TEST_HOOK</code> set"));
    assert!(!body.contains("very-secret"));
    let (_, body) = a
        .get("/api/env?names=PW_UI_TEST_HOOK,NOT_SET_X,bad-name")
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"PW_UI_TEST_HOOK": true, "NOT_SET_X": false})
    );

    // ServiceNow: names of variables only; other keys in the file are kept.
    let sn = json!({"kind": "servicenow", "instance": "https://contoso.service-now.com", "table": "sc_req_item",
        "min_severity": "high", "auth": "bearer", "token_env": "PW_SN_TOKEN", "fields": [["assignment_group", "IAM"]]});
    let (s, v) = a.json(Method::POST, "/api/plugins", sn.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap() + "max_create = 5\n";
    std::fs::write(a.state.ws().config_path(), &text).unwrap();
    let mut edit = sn;
    edit["index"] = json!(1);
    edit["expect"] = json!("servicenow");
    edit["auth"] = json!("basic");
    edit["username_env"] = json!("PW_SN_USER");
    edit["password_env"] = json!("PW_SN_PASSWORD");
    let edit_sn = edit.clone();
    let (s, v) = a.json(Method::POST, "/api/plugins", edit).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = pathwarden_core::config::Config::parse(&a.config().unwrap()).unwrap();
    let o = &config.outputs[1].settings;
    assert_eq!(o["max_create"], 5);
    assert_eq!(o["password_env"], "PW_SN_PASSWORD");
    assert!(!o.contains_key("token_env"));
    assert_eq!(o["fields"]["assignment_group"], "IAM");
    let (s, body) = a.get("/plugins/1/edit").await;
    assert_eq!(s, StatusCode::OK);
    // The safety limits are on the form now, with the file's value.
    assert!(
        body.contains(
            r#"id="pl-max-create" type="number" min="1" max="100000" step="1" value="5""#
        ),
        "{body}"
    );
    assert!(!body.contains("<code>max_create</code>"));
    // Saved from the form: a limit, and a default that leaves the file.
    let mut limits = edit_sn.clone();
    limits["max_create"] = json!("25");
    limits["max_resolve_percent"] = json!("50");
    let (s, v) = a.json(Method::POST, "/api/plugins", limits).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = pathwarden_core::config::Config::parse(&a.config().unwrap()).unwrap();
    assert_eq!(config.outputs[1].settings["max_create"], 25);
    assert!(!config.outputs[1]
        .settings
        .contains_key("max_resolve_percent"));
    let mut bad = edit_sn;
    bad["max_resolve_percent"] = json!("150");
    let (s, _) = a.json(Method::POST, "/api/plugins", bad).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Jira gets its own form: the list offers it, a save writes the
    // plugin's settings (fields as JSON), and the edit page shows them.
    let (_, body) = a.get("/automate/ticketing").await;
    assert!(body.contains(r#"href="/plugins/add""#));
    assert!(body.contains("Run on scheduled runs, not when you use Analyze in the app."));
    let (_, body) = a.get("/plugins/new?kind=jira").await;
    assert!(body.contains("Add Jira") && body.contains("PATHWARDEN_JIRA_TOKEN"));
    assert!(body.contains("Safety limits"));
    let jira = json!({"kind": "jira", "instance": "https://contoso.atlassian.net", "deployment": "cloud",
        "project": "SEC", "issue_type": "Bug", "min_severity": "high", "scope": "", "auth": "basic",
        "username_env": "PATHWARDEN_JIRA_USER", "token_env": "PATHWARDEN_JIRA_TOKEN", "pat_env": "PATHWARDEN_JIRA_PAT",
        "set_priority": false, "on_closed_but_present": "comment", "close_transition": "", "reopen_transition": "",
        "close_resolution": "Done", "fields": [["components", "[{\"name\": \"Active Directory\"}]"]],
        "max_create": "40", "max_resolve_percent": "50"});
    let (s, v) = a.json(Method::POST, "/api/plugins", jira.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = pathwarden_core::config::Config::parse(&a.config().unwrap()).unwrap();
    let j = &config.outputs[2].settings;
    assert_eq!(config.outputs[2].plugin, "jira");
    assert_eq!(j["issue_type"], "Bug");
    assert_eq!(j["set_priority"], false);
    assert_eq!(j["on_closed_but_present"], "comment");
    assert_eq!(j["close_resolution"], "Done");
    assert_eq!(j["max_create"], 40);
    assert_eq!(
        j["fields"]["components"],
        json!([{"name": "Active Directory"}])
    );
    assert!(!j.contains_key("deployment") && !j.contains_key("pat_env"));
    let (s, body) = a.get("/plugins/2/edit").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"id="j-project" value="SEC""#), "{body}");
    assert!(body.contains(r#"<option value="false" selected>Leave it to Jira"#));
    assert!(body.contains(r#"<option value="comment" selected>"#));
    assert!(
        body.contains("j-advanced\" open"),
        "a set resolution opens Closing and reopening"
    );
    assert!(body.contains("&quot;Active Directory&quot;"), "{body}");
    let (_, body) = a.get("/automate/ticketing").await;
    assert!(body.contains("Jira · SEC at https://contoso.atlassian.net"));
    // Refused: a personal access token on Cloud.
    let mut bad = jira;
    bad["auth"] = json!("pat");
    let (s, v) = a.json(Method::POST, "/api/plugins", bad).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

/// Without `--allow-destinations` the page can't make Pathwarden run a
/// program of its choosing: no new command plugin, no changed command. It
/// can still keep (and test) what the file has, change names and settings,
/// and use plugin programs from the plugins folder.
#[tokio::test]
async fn plugin_commands_need_the_flag() {
    let a = app("cmdlock");
    let program = if cfg!(windows) { "cmd" } else { "sh" };

    // Adding one is refused, and the file is untouched.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/plugins",
            json!({"kind": "command", "plugin": "teams", "command": [program, "-c", "x"]}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("Safety locks are on, so plugin programs"),
        "{v}"
    );
    assert!(a.config().is_none());
    // The form says why in plain words (an (i) links to the docs), and
    // offers only a plugin program.
    let (s, body) = a.get("/plugins/new?kind=command").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Safety locks are on, so plugin programs"));
    assert!(body.contains("pathwarden.org/docs/ui.html#safety-locks"));
    assert!(!body.contains("--allow-destinations"));
    assert!(body.contains(r#"value="command" disabled"#), "{body}");
    assert!(body.contains(r#"value="named" checked"#), "{body}");
    // A plugin program by name is fine.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/plugins",
            json!({"kind": "command", "plugin": "teams", "command": null}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // A command written in the file can be kept while its settings change.
    std::fs::write(
        a.state.ws().config_path(),
        format!("[[output]]\nplugin = \"stand-in\"\ncommand = [\"{program}\", \"  -c\", \"x\"]\n"),
    )
    .unwrap();
    let (s, body) = a.get("/plugins/0/edit").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#"id="pl-program""#) && body.contains(" readonly"));
    let keep = json!({"index": 0, "expect": "stand-in", "kind": "command", "plugin": "stand-in",
        "command": [program, "-c", "x"], "settings": [["min_change", "new"]]});
    let (s, v) = a.json(Method::POST, "/api/plugins", keep.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = a.config().unwrap();
    assert!(
        text.contains(&format!(r#"command = ["{program}", "-c", "x"]"#)),
        "{text}"
    );
    assert!(text.contains("min_change"), "{text}");
    // Changing it is refused.
    for command in [json!([program, "-c", "y"]), json!([r"C:\other.exe"])] {
        let mut change = keep.clone();
        change["command"] = command;
        let before = a.config();
        let (s, v) = a.json(Method::POST, "/api/plugins", change).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert_eq!(a.config(), before);
    }

    // Nor where a ticketing plugin sends its credentials, or which
    // variables a plugin reads: adding ServiceNow, or changing its
    // instance, table or token variable, is refused; its severity is not.
    let sn = json!({"kind": "servicenow", "instance": "https://contoso.service-now.com", "table": "incident",
        "min_severity": "high", "auth": "bearer", "token_env": "PW_SN_TOKEN"});
    let before = a.config();
    let (s, v) = a.json(Method::POST, "/api/plugins", sn.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("Safety locks are on"),
        "{v}"
    );
    assert_eq!(a.config(), before);
    std::fs::write(
        a.state.ws().config_path(),
        "[[output]]\nplugin = \"servicenow\"\ninstance = \"https://contoso.service-now.com\"\ntable = \"incident\"\nmin_severity = \"high\"\ntoken_env = \"PW_SN_TOKEN\"\n",
    )
    .unwrap();
    let mut edit = sn;
    edit["index"] = json!(0);
    edit["expect"] = json!("servicenow");
    edit["min_severity"] = json!("critical");
    let (s, v) = a.json(Method::POST, "/api/plugins", edit.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(a.config().unwrap().contains("critical"));
    for (key, value) in [
        ("instance", "https://evil.example"),
        ("token_env", "PATHWARDEN_JIRA_TOKEN"),
        ("table", "sc_req_item"),
    ] {
        let mut change = edit.clone();
        change[key] = json!(value);
        let before = a.config();
        let (s, v) = a.json(Method::POST, "/api/plugins", change).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{key}: {v}");
        assert_eq!(a.config(), before);
    }
}

/// With the flag, commands can be added, but never from a network path.
#[tokio::test]
async fn plugin_commands_refuse_network_paths() {
    let a = app_with("cmdunc", true);
    for command in [
        json!([r"\\pathwarden-unc-test.invalid\share\alert.exe"]),
        json!(["//pathwarden-unc-test.invalid/share/alert.exe"]),
        json!([
            "powershell",
            "-File",
            r"\\pathwarden-unc-test.invalid\share\alert.ps1"
        ]),
    ] {
        let (s, v) = a
            .json(
                Method::POST,
                "/api/plugins",
                json!({"kind": "command", "plugin": "alert", "command": command}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(v["error"].as_str().unwrap().contains("network path"), "{v}");
    }
    assert!(a.config().is_none());
    // The form has no lock note.
    let (_, body) = a.get("/plugins/new?kind=command").await;
    assert!(!body.contains("pathwarden.org/docs/ui.html#safety-locks"));
    assert!(body.contains(r#"value="command" checked"#));
}

/// Settings › Rules › Checks: a severity drop-down beside each
/// rule's switch, its default named; a rule set is marked with who set it;
/// the Changed filter and its reset; a save records who set each severity,
/// Default takes one off, and unknown rules and levels are refused.
#[tokio::test]
async fn rule_severities_are_set_from_the_settings_page() {
    let a = app("severities");
    std::fs::write(
        a.state.ws().config_path(),
        "[rules]\nseverity = \"exposure\"\n\n[rules.severities]\n\"PW-011\" = { severity = \"low\", by = 'NORTH\\eddard.stark', at = \"2026-10-24T09:00:00Z\" }\n",
    )
    .unwrap();
    let (s, body) = a.get("/settings").await;
    assert_eq!(s, StatusCode::OK);
    let rules = &body[body.find(r#"id="rules""#).unwrap()..];
    let rules = &rules[..rules.find("</section>").unwrap()];
    let n = pathwarden_core::findings::rules().len();
    assert_eq!(rules.matches(r#"<select class="input sev-pick"#).count(), n);
    assert_eq!(
        rules
            .matches(r#"<input type="checkbox" class="switch""#)
            .count(),
        n
    );
    // Rows are not labels: a click on the drop-down never flips the switch.
    assert!(!rules.contains(r#"<label class="rule-row""#));
    assert!(rules.contains(r#"aria-label="PW-011 Computers without LAPS""#));
    assert!(rules.contains(r#"aria-label="Severity of PW-011""#));
    // The title still flips the switch.
    assert!(rules.contains(r#"<label class="rule-name" for="chk-PW-011">"#));
    assert!(rules.contains(r#"id="chk-PW-011""#));
    // The Changed filter hides rows with a class: controls under [hidden]
    // don't count for "Unsaved changes", so [hidden] would mark the card
    // changed by a mere click on the filter.
    let (_, js) = a.get("/static/config.js").await;
    assert!(js.contains(r#"classList.toggle("filtered-out""#));
    assert!(!js.contains("row.hidden ="));
    // Each default as the drop-down's first choice, in both ways of rating.
    assert!(rules.contains(r#"<option value="" selected>Default (exposure)</option>"#));
    assert!(rules.contains(r#"<option value="" selected>Default (Medium)</option>"#));
    assert!(rules.contains(r#"<option value="" selected>Default (High or Low)</option>"#));
    assert!(rules.contains(r#"data-default-static="Default (Critical)""#));
    // No Info.
    assert!(!rules.contains(r#"<option value="info""#));
    // PW-011 set: marked, with who set it.
    assert!(rules.contains(r#"<div class="rule-row sev-set" data-rule="PW-011">"#));
    assert!(rules.contains(r#"<option value="low" selected>Low</option>"#));
    assert!(
        rules.contains(
            r#"<span class="rule-who">Set by NORTH\eddard.stark on Oct 24, 2026.</span>"#
        ),
        "{rules}"
    );
    // The filter, the reset, and the words.
    assert!(rules.contains(r#"data-show="all" aria-pressed="true""#));
    assert!(rules.contains(r#"data-show="changed" aria-pressed="false""#));
    assert!(rules.contains(r#"id="rules-reset""#));
    assert!(rules.contains("Turn a rule off or set its severity."));
    assert!(rules.contains("About: Severity"));
    assert!(
        !rules.contains("pathwarden config"),
        "no commands on the page"
    );
    let loaded = a.loaded("rules").await;
    assert_eq!(loaded["severities"], json!({"PW-011": "low"}));

    // Save: PW-002 set, PW-011 back to its default.
    let body = |sev: Value, loaded: Value| json!({"stale_days": 90, "password_age_days": 365, "krbtgt_age_days": 180, "severity": "exposure", "disabled": [], "severities": sev, "loaded": loaded});
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            body(
                json!({"PW-002": "critical", "PW-011": "default", "PW-003": "default"}),
                loaded,
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["loaded"]["severities"], json!({"PW-002": "critical"}));
    assert!(
        v["set"]["PW-002"].as_str().unwrap().starts_with("Set "),
        "{v}"
    );
    assert!(v["set"].get("PW-011").is_none());
    let text = a.config().unwrap();
    assert!(text.contains("[rules.severities]"), "{text}");
    assert!(
        text.contains("PW-002 = { severity = \"critical\""),
        "{text}"
    );
    assert!(!text.contains("PW-011"), "{text}");

    // Unknown rules and levels: refused, the file untouched.
    for bad in [
        json!({"PW-999": "low"}),
        json!({"PW-002": "info"}),
        json!({"PW-002": "urgent"}),
    ] {
        let before = a.config();
        let (s, v) = a
            .json(
                Method::POST,
                "/api/settings/rules",
                body(bad.clone(), a.loaded("rules").await),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
        assert!(v["error"].as_str().is_some_and(|e| e.ends_with('.')), "{v}");
        assert_eq!(a.config(), before);
    }
    let (_, v) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            body(json!({"PW-999": "low"}), a.loaded("rules").await),
        )
        .await;
    assert_eq!(v["error"], "PW-999 is not a rule Pathwarden has.");

    // Reset: the table goes with the last one.
    let (s, _) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            body(json!({"PW-002": "default"}), a.loaded("rules").await),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!a.config().unwrap().contains("[rules.severities]"));
    let (_, page) = a.get("/settings").await;
    assert!(!page.contains("rule-row sev-set"));
}

/// The Tier Zero settings folders card, after Additional Tier Zero
/// with its own jump chip: saved in pathwarden.toml (a shared section), a
/// relative path refused, and an analysis reads the files in the folder.
#[tokio::test]
async fn tier_zero_settings_folders_are_saved_and_read() {
    let a = app("t0folders");
    let (_, page) = a.get("/settings").await;
    let t0 = page.find(r#"id="tier-zero""#).unwrap();
    let sf = page.find(r#"id="settings-folders""#).unwrap();
    let rules = page.find(r#"id="rules""#).unwrap();
    assert!(t0 < sf && sf < rules);
    assert!(page.contains(r##"<a href="#tier-zero">Tier Zero</a><a href="#settings-folders">Tier Zero settings folders</a><a href="#rules">Rules</a>"##));
    assert!(page.contains("<h2 class=\"sub\">Tier Zero settings folders</h2>"));
    assert!(page.contains("Shared folders where your servers save Tier Zero settings files."));
    assert!(page.contains("Runs record file names, not folder paths."));
    assert!(
        page.contains(r#"placeholder="Folder or share path, for example \\fs01\pathwarden-t0""#)
    );
    assert!(page.contains(r#"<ul class="chiplist" id="sf-list"></ul>"#));
    assert!(page.contains("Save folders"));
    // No command hints on the page.
    assert!(!page.contains("config settings-folders"));
    assert_eq!(a.loaded("settings-folders").await, json!([]));

    // A relative path is refused, and nothing is written.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/settings-folders",
            json!({"items": ["t0"], "loaded": []}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("is not a full folder path"),
        "{v}"
    );
    assert!(a.config().is_none());

    // The AD CS fixture, and a folder with one CA's settings file.
    let base = std::env::temp_dir().join(format!("pathwarden-cfg-t0data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let data = base.join("data");
    let folder = base.join("t0");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&folder).unwrap();
    for entry in std::fs::read_dir(testdata("adcs")).unwrap() {
        let p = entry.unwrap().path();
        std::fs::copy(&p, data.join(p.file_name().unwrap())).unwrap();
    }
    // The fixture's file without its certificate hash (the AD CS fixture's
    // CA has a made-up one): matched by CA name and host.
    let file = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../pathwarden-core/tests/fixtures/tierzero/pathwarden-tierzero-CA01.pki.local.json",
    ))
    .unwrap()
    .replace("\"3F2504E04F8911D39A0C0305E82C3301AABBCCDD\"", "");
    std::fs::write(folder.join("pathwarden-tierzero-CA01.pki.local.json"), file).unwrap();

    let path = folder.display().to_string();
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/settings-folders",
            json!({"items": [path, path.to_uppercase()], "loaded": []}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["loaded"], json!([path]));
    assert!(a.config().unwrap().contains("settings_folders = ["));
    assert_eq!(a.loaded("settings-folders").await, json!([path]));

    let run = a.analyze(data).await;
    let r = a.state.ws().summary(&run).unwrap();
    let dir = a.state.ws().run_dir(&run).unwrap();
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(r.settings_files.len(), 1, "{:?}", r.settings_files);
    let f = &r.settings_files[0];
    assert_eq!(f.file_name, "pathwarden-tierzero-CA01.pki.local.json");
    assert_eq!(f.server, "PKI-CA");
    // The run's files name the file, never the folder.
    let mut saved = String::new();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        if e.path().extension().is_some_and(|x| x == "json") {
            saved.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
        }
    }
    assert!(saved.contains("pathwarden-tierzero-CA01.pki.local.json"));
    let escaped = path.replace('\\', "\\\\");
    assert!(!saved.contains(&escaped), "a folder path in the run");
}

/// Without `--allow-destinations`, the History storage page can't send
/// the history somewhere else (every run, full reports too, would go
/// there) nor keep full runs in a history that isn't encrypted; its other
/// settings it can change. With the flag it can.
#[tokio::test]
async fn the_history_place_needs_the_flag() {
    let locked = pathwarden_ui::settings::HISTORY_LOCKED;
    let a = app("histlock");
    let elsewhere = [
        json!({"backend": "git", "remote": "https://git.example.com/h.git"}),
        json!({"backend": "local", "path": "D:\\elsewhere"}),
        json!({"backend": "local", "path": "\\\\attacker\\share"}),
    ];
    for body in &elsewhere {
        let (s, v) = a
            .json(Method::POST, "/api/settings/state", body.clone())
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
        assert_eq!(v["error"], locked, "{body}");
        assert!(a.config().is_none(), "nothing saved for {body}");
    }
    // Full runs in a plain history, by choice ("Don't encrypt"): refused.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/state",
            json!({"backend": "local", "keep": "full", "share_plain": true}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], locked);
    // The same place with other settings: saved.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/state",
            json!({"backend": "local", "include_names": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(a.config().unwrap().contains("include_names = true"));
    // With the flag, the history can move.
    let b = app_with("histlock-flag", true);
    let (s, v) = b
        .json(Method::POST, "/api/settings/state", elsewhere[0].clone())
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(b
        .config()
        .unwrap()
        .contains("https://git.example.com/h.git"));
    // A history set in the file stays editable in place without it.
    let c = app("histlock-kept");
    std::fs::write(
        c.state.ws().config_path(),
        "[state]\nbackend = \"git\"\nremote = \"https://git.example.com/h.git\"\n",
    )
    .unwrap();
    let (s, v) = c
        .json(
            Method::POST,
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://git.example.com/h.git", "push": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = c
        .json(
            Method::POST,
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://git.example.com/other.git"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], locked);
}

/// A body of the wrong shape, a body that isn't JSON and an unknown API
/// route each get `{"error": "<a sentence>"}`, which the pages show.
#[tokio::test]
async fn api_errors_are_json_sentences() {
    let a = app("api-errors");
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/rules",
            json!({"stale_days": 30, "password_age_days": 365, "krbtgt_age_days": "x", "severity": "static", "disabled": []}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // Plain words on the page; the detail goes to the log.
    assert_eq!(v["error"], pathwarden_ui::server::UNREADABLE_REQUEST, "{v}");

    let req = a
        .request(Method::POST, "/api/settings/rules")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::from("not json"))
        .unwrap();
    let (s, _, b) = a.send(req).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["error"], pathwarden_ui::server::UNREADABLE_REQUEST, "{v}");

    let (s, b) = a.get("/api/no-such-thing").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["error"], "That page doesn't exist.");

    // Pages keep the HTML Not found page.
    let (s, b) = a.get("/no-such-page").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        b.contains("<html") || b.contains("<!doctype") || b.contains("<!DOCTYPE"),
        "{b}"
    );
}

/// Plugins and actions has one Add, which starts from what should happen:
/// tickets and your own program ask when (each scheduled run is a plugin,
/// a button is an action), Alert a team and Look up an owner go straight
/// to the action form with a line to the guide. The old addresses still
/// open their forms.
#[tokio::test]
async fn add_starts_from_what_should_happen() {
    let a = app_with("add-flow", true);
    let (_, list) = a.get("/automate/ticketing").await;
    assert!(list.contains(r#"id="add-btn" href="/plugins/add""#));
    for gone in [
        "Add ServiceNow",
        "Add Jira",
        "Add a script or program",
        "Add a finding action",
        "Send scheduled run results",
        r#"class="lead""#,
    ] {
        assert!(!list.contains(gone), "{gone}");
    }
    assert!(list.contains(">Plugins</h2>"));
    assert!(list.contains("Run on scheduled runs, not when you use Analyze in the app."));
    assert!(list.contains("No plugins yet."));
    assert!(list.contains("No actions yet."));

    // Step 1: five choices, each tagged plugin, action or both.
    let (s, what) = a.get("/plugins/add").await;
    assert_eq!(s, StatusCode::OK);
    assert!(what.contains("What should happen?"));
    assert!(what.contains(r#"id="add-what" method="get" action="/plugins/add""#));
    for (key, title, tags) in [
        (
            "servicenow",
            "ServiceNow tickets",
            r#"<span class="tag">Plugin</span><span class="tag act">Action</span>"#,
        ),
        (
            "jira",
            "Jira tickets",
            r#"<span class="tag">Plugin</span><span class="tag act">Action</span>"#,
        ),
        (
            "alert",
            "Alert a team",
            r#"<span class="tag act">Action</span>"#,
        ),
        (
            "owner",
            "Look up an owner",
            r#"<span class="tag act">Action</span>"#,
        ),
        (
            "own",
            "Your own program",
            r#"<span class="tag">Plugin</span><span class="tag act">Action</span>"#,
        ),
    ] {
        assert!(
            what.contains(&format!(r#"name="what" value="{key}""#)),
            "{key}"
        );
        assert!(what.contains(&format!("{title}{tags}</strong>")), "{key}");
    }
    assert!(what.contains(r#"value="servicenow" checked"#));
    assert!(what.contains("Next"));
    assert!(!what.contains('\u{2014}'), "no em dashes");
    // Change comes back with the choice kept.
    let (_, again) = a.get("/plugins/add?picked=owner").await;
    assert!(again.contains(r#"value="owner" checked"#));
    assert!(!again.contains(r#"value="servicenow" checked"#));

    // Step 2 for tickets and your own program: when?
    for key in ["servicenow", "jira", "own"] {
        let (s, when) = a.get(&format!("/plugins/add?what={key}")).await;
        assert_eq!(s, StatusCode::OK, "{key}");
        assert!(when.contains("When?"), "{key}");
        assert!(when.contains(&format!(
            r#"<input type="hidden" name="what" value="{key}">"#
        )));
        assert!(when.contains(r#"value="scheduled" checked"#), "{key}");
        assert!(when.contains("Every finding, on each scheduled run"));
        assert!(when.contains("Only when someone clicks a button on a finding"));
        assert!(when.contains(&format!(r#"href="/plugins/add?picked={key}">Change</a>"#)));
        assert!(!when.contains(r#"id="plugin-form""#) && !when.contains(r#"id="action-form""#));
    }

    // Each scheduled run: today's plugin forms, under the choice.
    for (key, form, title) in [
        ("servicenow", "sn-instance", "Add ServiceNow"),
        ("jira", "j-project", "Add Jira"),
        ("own", "pl-program", "Add a script or program"),
    ] {
        let (s, page) = a
            .get(&format!("/plugins/add?what={key}&when=scheduled"))
            .await;
        assert_eq!(s, StatusCode::OK, "{key}");
        assert!(page.contains(r#"id="plugin-form""#), "{key}");
        assert!(page.contains(&format!(r#"id="{form}""#)), "{key}");
        assert!(page.contains(&format!(">{title}</h1>")), "{key}");
        assert!(page.contains(r#"id="add-picked""#), "{key}");
        assert!(
            !page.contains(r#"<span class="tag act">"#),
            "{key}: the plugin only"
        );
    }

    // A button: the action form. Tickets point to the guide's REST
    // example; your own program has no line.
    for (key, section, how) in [
        ("servicenow", "open-a-ticket", r#"value="command" checked"#),
        ("jira", "open-a-ticket", r#"value="command" checked"#),
        ("own", "", r#"value="plugin" checked"#),
    ] {
        let (s, page) = a.get(&format!("/plugins/add?what={key}&when=button")).await;
        assert_eq!(s, StatusCode::OK, "{key}");
        assert!(page.contains(r#"id="action-form""#), "{key}");
        assert!(page.contains(">Add an action</h1>"), "{key}");
        assert!(page.contains(r#"id="add-picked""#), "{key}");
        assert!(page.contains(how), "{key}");
        if section.is_empty() {
            assert!(!page.contains("guide-line"), "{key}");
        } else {
            assert!(
                page.contains(&format!(
                    "pathwarden.org/docs/finding-actions.html#{section}"
                )),
                "{key}"
            );
        }
    }

    // Alert a team and Look up an owner: straight to the action form,
    // with a script or program picked, the guide and a name to start from.
    for (key, line, link, ph) in [
        (
            "alert",
            "Alert a team runs a script of yours.",
            "#alert-a-team",
            "team-chat",
        ),
        (
            "owner",
            "Look up an owner runs a script of yours.",
            "#look-up-an-owner",
            "owners",
        ),
    ] {
        let (s, page) = a.get(&format!("/plugins/add?what={key}")).await;
        assert_eq!(s, StatusCode::OK, "{key}");
        assert!(page.contains(r#"id="action-form""#), "{key}");
        assert!(page.contains(line), "{key}");
        assert!(page.contains("The guide has one to copy, with its setup."));
        assert!(
            page.contains(&format!("finding-actions.html{link}")),
            "{key}"
        );
        assert!(page.contains(&format!(r#"placeholder="{ph}""#)), "{key}");
        assert!(
            page.contains(r#"name="af-how" value="command" checked"#),
            "{key}"
        );
        assert!(page.contains(r#"data-when-how="plugin" hidden"#), "{key}");
        assert!(!page.contains("When?"), "{key}");
        assert!(!page.contains("pathwarden action"), "{key}: no commands");
    }

    // Anything else starts again at step 1.
    let (s, page) = a.get("/plugins/add?what=nope&when=button").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("What should happen?"));

    // The old addresses still open their forms.
    for (uri, id) in [
        ("/plugins/new?kind=servicenow", "sn-instance"),
        ("/plugins/new?kind=jira", "j-project"),
        ("/plugins/new?kind=command", "pl-program"),
        ("/actions/new", "af-program"),
    ] {
        let (s, page) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert!(page.contains(&format!(r#"id="{id}""#)), "{uri}");
        assert!(!page.contains(r#"id="add-picked""#), "{uri}");
    }
}
