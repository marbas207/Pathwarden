//! Finding actions in the app, through the router, with the fake action
//! program in testdata/actions (PowerShell on Windows, sh elsewhere): the
//! run page's dialog data and the report's buttons, See exactly what's
//! sent, a run as a job with its result saved on the finding, a follow-up,
//! Cancel, one action at a time, and Plugins and actions (its sections,
//! Test, the lock without --allow-destinations).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::actions::CancelHandle;
use pathwarden_ui::jobs::ActionProgress;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4251";

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

fn app(name: &str, allow: bool) -> App {
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-ac-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let mut state = AppState::new(ws, Token::generate().unwrap(), 4251);
    state.allow_destinations = allow;
    // Logs in the test's folder; Open log opens nothing.
    state.jobs.set_logs_dir(Some(dir.join("logs")));
    state.opener = Arc::new(|_| true);
    let state = Arc::new(state);
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// The `[[action]]` block that runs the fake program, as TOML.
fn fake_block(name: &str) -> String {
    let ext = if cfg!(windows) { "ps1" } else { "sh" };
    let script = std::path::absolute(repo(&format!("testdata/actions/fake-action.{ext}"))).unwrap();
    let s = script.display().to_string();
    let argv: Vec<String> = if cfg!(windows) {
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|a| a.to_string())
        .chain([s])
        .collect()
    } else {
        vec!["sh".into(), s]
    };
    format!(
        "\n[[action]]\nname = \"{name}\"\ncommand = {}\n",
        serde_json::to_string(&argv).unwrap()
    )
}

impl App {
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

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn json(&self, method: Method, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = self
            .request(method, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, text) = self.send(req).await;
        (s, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Analyzes a folder and returns the new run's ID.
    async fn analyze(&self, path: &Path) -> String {
        let boundary = "acBoundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}--\r\n",
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
        for _ in 0..600 {
            let (_, b) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&b).unwrap();
            if v["status"] == "done" {
                return v["run"].as_str().unwrap().to_string();
            }
            assert_ne!(v["status"], "failed", "{b}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    /// The job's result once the action ended.
    async fn result(&self, job: &str) -> Value {
        for _ in 0..1200 {
            let (_, b) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&b).unwrap();
            if v["status"] == "acted" {
                return v["action"]["result"].clone();
            }
            assert_eq!(v["status"], "acting", "{b}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the action did not finish");
    }

    fn add_actions(&self) {
        let path = self.state.ws().config_path();
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str(&fake_block("fake"));
        std::fs::write(&path, text).unwrap();
    }
}

/// The JSON in attribute `attr` of the first element that has it,
/// unescaped as a browser would.
fn attr_json(html: &str, attr: &str) -> Value {
    // The action dialog's own attributes, not the Retest dialog's.
    let html = html
        .find(r#"id="ac-dialog""#)
        .filter(|_| attr.starts_with("data-"))
        .map_or(html, |i| &html[i..]);
    let key = format!("{attr}=\"");
    let start = html
        .find(&key)
        .map(|i| i + key.len())
        .unwrap_or_else(|| panic!("no {attr}"));
    let raw = &html[start..start + html[start..].find('"').unwrap()];
    let text = raw
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&text).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_runs_from_the_run_page_and_is_saved_on_the_finding() {
    let a = app("run", false);
    let run = a.analyze(&repo("testdata/forest")).await;
    a.add_actions();

    // The run page's dialog lists the findings the action applies to, and
    // the report gets the buttons' data.
    let (s, page) = a.get(&format!("/runs/{run}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains(r#"id="ac-dialog""#), "no dialog");
    assert!(page.contains(r#"src="/static/actions.js""#));
    let acts = attr_json(&page, "data-acts");
    assert_eq!(acts["fake/open"]["label"], "Open a ticket", "{acts}");
    assert_eq!(acts["fake/open"]["once"], true);
    assert_eq!(acts["fake/close"]["fixed"], true);
    let findings = attr_json(&page, "data-findings");
    let (fp, f) = findings
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, f)| {
            f["view"]["offered"]
                .as_array()
                .unwrap()
                .contains(&json!("fake/open"))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .expect("a finding offered the action");
    assert!(f["title"].as_str().is_some_and(|t| !t.is_empty()));
    let (_, report) = a.get(&format!("/runs/{run}/report?embed=1")).await;
    let meta = attr_json(&report, r#"<meta name="pathwarden-retest" content"#);
    assert_eq!(meta["ac"]["on"], true);
    assert!(meta["ac"]["f"][&fp]["view"]["offered"]
        .as_array()
        .unwrap()
        .contains(&json!("fake/open")));
    // The report holds the titles already.
    assert!(meta["ac"]["f"][&fp].get("title").is_none());

    // See exactly what's sent: the request, as `pathwarden action request`.
    let ask =
        json!({ "fingerprint": fp, "action": "fake/open", "inputs": { "note": "Please look" } });
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/request"),
            ask.clone(),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["request"]["schema"], "pathwarden.action-request.v1");
    assert_eq!(v["request"]["inputs"]["note"], "Please look");
    assert_eq!(v["request"]["inputs"]["urgency"], "Medium");
    assert_eq!(v["request"]["finding"]["fingerprint"], json!(fp));

    // Run: a job, its lines, then what it did, saved on the finding.
    let (s, v) = a
        .json(Method::POST, &format!("/api/runs/{run}/actions/run"), ask)
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["label"], "Open a ticket");
    let r = a.result(v["job"].as_str().unwrap()).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["message"], "Opened FAKE0001.");
    assert_eq!(r["records"][0]["number"], "FAKE0001");
    assert_eq!(r["saved"], true);
    assert_eq!(r["pushed"], true);
    assert_eq!(r["said"], pathwarden_ui::actions_ui::SAVED_PAGE_WORDS);
    assert!(r["progress"]
        .as_array()
        .unwrap()
        .contains(&json!("Opening a ticket")));
    // The finding's view now: its chip, and no second Open (once).
    assert_eq!(r["view"]["records"][0]["chip"], "FAKE0001 · Open", "{r}");
    assert_eq!(
        r["view"]["records"][0]["follow_ups"],
        json!(["fake/status"])
    );
    assert!(!r["view"]["offered"]
        .as_array()
        .unwrap()
        .contains(&json!("fake/open")));
    assert_eq!(r["view"]["activity"][0]["summary"], "Opened FAKE0001");

    // It is on the page after a reload too.
    let (_, page) = a.get(&format!("/runs/{run}")).await;
    let findings = attr_json(&page, "data-findings");
    assert_eq!(
        findings[&fp]["view"]["records"][0]["chip"],
        "FAKE0001 · Open"
    );
    assert_eq!(findings[&fp]["view"]["activity_count"], 1);

    // Open again while its record is open (once) is refused, before anything runs.
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fp, "action": "fake/open" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = a
        .json(
            Method::POST,
            "/api/runs/not-a-run/actions/run",
            json!({ "fingerprint": fp, "action": "fake/open" }),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A follow-up on the record: the chip says Closed.
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fp, "action": "fake/status", "record": "fake-1" }),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let r = a.result(v["job"].as_str().unwrap()).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["record"], "fake-1");
    assert_eq!(r["view"]["records"][0]["chip"], "FAKE0001 · Closed", "{r}");

    // A failure: kept in the activity, with the program's error output.
    let other = findings
        .as_object()
        .unwrap()
        .iter()
        .find(|(k, f)| {
            **k != fp
                && f["view"]["offered"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("fake/open"))
        })
        .map(|(k, _)| k.clone())
        .unwrap();
    let (_, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": other, "action": "fake/open", "inputs": { "note": "fail" } }),
        )
        .await;
    let r = a.result(v["job"].as_str().unwrap()).await;
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["message"], "The fake desk said no.");
    assert!(r["details"].as_str().unwrap().contains("HTTP 403"), "{r}");
    assert_eq!(r["said"], "Kept in the finding's activity.");
    assert_eq!(r["view"]["activity"][0]["ok"], false);
    // Its log, for Open log on its Activity entry: the action's result is
    // in it.
    let log = r["view"]["activity"][0]["log"]
        .as_str()
        .expect("a failed entry has its log")
        .to_string();
    assert!(log.contains("-action") && log.ends_with(".log"), "{log}");
    let text = std::fs::read_to_string(a.dir.join("logs").join(&log)).unwrap();
    assert!(
        text.contains("[action, app] result: failed: The fake desk said no."),
        "{text}"
    );
    let (s, _) = a
        .json(Method::POST, "/api/logs/open", json!({ "file": log }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // The run page has it too, on that entry only.
    let (_, page) = a.get(&format!("/runs/{run}")).await;
    let again = attr_json(&page, "data-findings");
    assert_eq!(again[&other]["view"]["activity"][0]["log"], log.as_str());
    assert!(again[&fp]["view"]["activity"][0]["log"].is_null());

    // Test only: nothing saved.
    let (_, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": other, "action": "fake/open", "dry_run": true }),
        )
        .await;
    let r = a.result(v["job"].as_str().unwrap()).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["saved"], false);
    assert_eq!(r["said"], pathwarden_ui::actions_ui::DRY_RUN_PAGE_WORDS);
    assert_eq!(r["view"]["activity_count"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_action_runs_at_a_time_and_cancel_stops_it() {
    let a = app("busy", false);
    let run = a.analyze(&repo("testdata/forest")).await;
    a.add_actions();
    let (_, page) = a.get(&format!("/runs/{run}")).await;
    let findings = attr_json(&page, "data-findings");
    let fps: Vec<String> = findings
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, f)| {
            f["view"]["offered"]
                .as_array()
                .unwrap()
                .contains(&json!("fake/open"))
        })
        .map(|(k, _)| k.clone())
        .collect();
    // A slow one runs; a second is refused (429).
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fps[0], "action": "fake/open", "inputs": { "note": "slow" } }),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let job = v["job"].as_str().unwrap().to_string();
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fps[1], "action": "fake/open" }),
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"], pathwarden_ui::actions_app::BUSY_WORDS);
    let (s, v) = a
        .json(Method::POST, "/api/actions/test", json!({ "name": "fake" }))
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    // Its lines come as they are written.
    let mut seen = false;
    for _ in 0..400 {
        let (_, b) = a.get(&format!("/api/jobs/{job}")).await;
        let v: Value = serde_json::from_str(&b).unwrap();
        if v["action"]["lines"]
            .as_array()
            .is_some_and(|l| l.contains(&json!("Waiting for the fake desk")))
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "no progress line");
    // Cancel: stopped, and saved as cancelled.
    let (s, _) = a
        .json(Method::POST, &format!("/api/jobs/{job}/cancel"), json!({}))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let r = a.result(&job).await;
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["ended"], "cancelled");
    assert_eq!(r["saved"], true, "{r}");
    assert_eq!(r["view"]["activity"][0]["outcome"], "cancelled", "{r}");
    let (s, _) = a
        .json(Method::POST, &format!("/api/jobs/{job}/cancel"), json!({}))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // An action registered as running holds up another (429).
    assert!(a.state.jobs.try_begin_action(
        "20261119-000001-abcdef",
        ActionProgress::default(),
        CancelHandle::new()
    ));
    let (s, _) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fps[1], "action": "fake/open" }),
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    a.state
        .jobs
        .action_done("20261119-000001-abcdef", json!({}));

    // During an analysis or a collection: 409.
    let spec = pathwarden_ui::jobs::JobSpec {
        id: "20261119-000000-abcdef".into(),
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
    let (s, v) = a
        .json(
            Method::POST,
            &format!("/api/runs/{run}/actions/run"),
            json!({ "fingerprint": fps[1], "action": "fake/open" }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"], pathwarden_ui::actions_app::ANALYZING_WORDS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugins_and_actions_shows_programs_tests_them_and_locks_changes() {
    let a = app("settings", false);
    a.analyze(&repo("testdata/forest")).await;
    a.add_actions();
    let (s, page) = a.get("/automate/ticketing").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains(r#"<h1 class="panel-title">Plugins and actions</h1>"#));
    assert!(page.contains("<title>Plugins and actions"), "the title");
    assert!(
        page.contains(r#"<span class="tl">Plugins and actions</span>"#),
        "the rail"
    );
    assert!(!page.contains("Ticketing and alerts"));
    assert!(page.contains(">Plugins</h2>"));
    assert!(page.contains(">Actions</h2>"));
    assert!(page.contains("Buttons to trigger actions on a finding."));
    assert!(page.contains("pathwarden.org/docs/finding-actions.html"));
    // One Add for the page, even locked: plugin programs can still be added.
    assert!(page.contains(r#"id="add-btn" href="/plugins/add""#));
    assert!(!page.contains("Add a finding action"));
    // The program, its action with inputs, what it sends, what it
    // applies to, its follow-ups and Test.
    assert!(page.contains("<strong>Open a ticket</strong>"));
    assert!(page.contains(r#"Urgency <span class="opt">(optional)</span>: Low, Medium, High"#));
    assert!(
        page.contains("The finding&#39;s title and the note.")
            || page.contains("The finding's title and the note.")
    );
    assert!(page.contains(r#"data-ac-test="fake" data-action="open""#));
    assert!(page.contains(
        r#"<span class="ac-fu">Close the ticket <span class="when">after the fix</span></span>"#
    ));
    assert!(page.contains("Critical only"), "Ping the team's filter");
    // Locked with --lock-destinations: plain words, an (i) with the
    // docs, no command, no Add, Remove off.
    assert!(page.contains(&pathwarden_core::plugin_form::ACTIONS_LOCKED.replace('\'', "&#39;")));
    assert!(page.contains("pathwarden.org/docs/ui.html#safety-locks"));
    assert!(!page.contains("--allow-destinations"));
    assert!(!page.contains("pathwarden ui"));
    assert!(!page.contains(r#"href="/actions/new""#));
    // Add: the choices that are only actions are off, and so is a button.
    let (s, add) = a.get("/plugins/add").await;
    assert_eq!(s, StatusCode::OK);
    assert!(add.contains(r#"value="alert" disabled"#), "{add}");
    assert!(add.contains(r#"value="owner" disabled"#));
    assert!(add.contains(r#"value="servicenow" checked"#));
    assert!(!add.contains(r#"value="own" disabled"#));
    assert!(add.contains(&pathwarden_core::plugin_form::ACTIONS_LOCKED.replace('\'', "&#39;")));
    let (_, when) = a.get("/plugins/add?what=jira").await;
    assert!(when.contains(r#"value="button" disabled"#), "{when}");
    assert!(when.contains(r#"value="scheduled" checked"#));
    assert!(
        page.contains(r#"data-ac-remove="0" data-name="fake" aria-label="Remove fake" disabled"#)
    );
    let (s, v) = a
        .json(
            Method::DELETE,
            "/api/actions/0",
            json!({ "expect": "fake" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], pathwarden_core::plugin_form::ACTIONS_LOCKED);
    let (s, v) = a
        .json(
            Method::POST,
            "/api/actions",
            json!({ "index": null, "name": "more", "how": "plugin", "plugin": "more" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], pathwarden_core::plugin_form::ACTIONS_LOCKED);
    // Its name, time limit and filters can still change.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/actions",
            json!({
                "index": 0, "expect": "fake", "name": "fake",
                "how": "command",
                "program": if cfg!(windows) { "powershell" } else { "sh" },
                "args": fake_args(),
                "timeout_seconds": 60, "min_severity": "high"
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = a.state.ws().config().unwrap();
    assert_eq!(c.actions[0].timeout_seconds, 60);
    assert_eq!(
        c.actions[0].min_severity,
        Some(pathwarden_core::findings::Severity::High)
    );

    // Test: a dry run on the first matching finding of the latest run, in
    // the same progress view; nothing is saved.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/actions/test",
            json!({ "name": "fake", "action": "open" }),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert!(v["title"].as_str().is_some_and(|t| !t.is_empty()));
    let r = a.result(v["job"].as_str().unwrap()).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["message"], "Would open a ticket (dry run).");
    assert_eq!(r["saved"], false);
    let (s, v) = a
        .json(Method::POST, "/api/actions/test", json!({ "name": "nope" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "There is no finding action nope.");

    // The other lock notes say the same kind of words, without a command.
    for (uri, words) in [
        (
            "/plugins/new?kind=servicenow",
            pathwarden_core::plugin_form::DESTINATION_LOCKED,
        ),
        (
            "/plugins/new?kind=jira",
            pathwarden_core::plugin_form::GUARD_LOCKED,
        ),
        (
            "/plugins/new?kind=command",
            pathwarden_core::plugin_form::COMMANDS_LOCKED,
        ),
        (
            "/environments/connect",
            pathwarden_ui::connect_ui::CONNECT_LOCKED,
        ),
        (
            "/actions/0/edit",
            pathwarden_core::plugin_form::ACTIONS_LOCKED,
        ),
    ] {
        let (s, page) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        let html_words = words.replace('\'', "&#39;");
        assert!(
            page.contains(words) || page.contains(&html_words),
            "{uri}: {words}"
        );
        assert!(
            page.contains("pathwarden.org/docs/ui.html#safety-locks"),
            "{uri}"
        );
        assert!(!page.contains("--allow-destinations"), "{uri}");
    }
}

/// The fake program's arguments after the interpreter.
fn fake_args() -> Vec<String> {
    let ext = if cfg!(windows) { "ps1" } else { "sh" };
    let script = std::path::absolute(repo(&format!("testdata/actions/fake-action.{ext}")))
        .unwrap()
        .display()
        .to_string();
    if cfg!(windows) {
        [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|a| a.to_string())
        .chain([script])
        .collect()
    } else {
        vec![script]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_allow_destinations_a_program_is_added_and_removed() {
    let a = app("allow", true);
    a.analyze(&repo("testdata/forest")).await;
    let (_, page) = a.get("/automate/ticketing").await;
    assert!(page.contains(r#"href="/plugins/add""#));
    assert!(!page.contains(pathwarden_core::plugin_form::ACTIONS_LOCKED));
    // The old address still opens the form, under its new words.
    let (s, page) = a.get("/actions/new").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains(r#"id="action-form""#));
    assert!(page.contains(">Add an action</h1>"));
    assert!(page.contains("<strong>From the plugins folder</strong>"));
    assert!(page.contains(r#"<label for="af-plugin">Name in the folder</label>"#));
    assert!(!page.contains("A plugin program"));
    assert!(!page.contains(r#"id="add-picked""#));
    // From Add: nothing is off without the lock.
    let (_, add) = a.get("/plugins/add").await;
    assert!(!add.contains(r#"value="alert" disabled"#), "{add}");
    assert!(!add.contains("lock-actions"));
    let (s, v) = a
        .json(
            Method::POST,
            "/api/actions",
            json!({
                "index": null, "name": "fake", "how": "command",
                "program": if cfg!(windows) { "powershell" } else { "sh" },
                "args": fake_args(),
                "settings": [["queue", "Identity"], ["webhook_env", "PW_FAKE_HOOK"]],
                "categories": ["attack_path"]
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = a.state.ws().config().unwrap();
    assert_eq!(c.actions.len(), 1);
    assert_eq!(c.actions[0].settings["queue"], "Identity");
    // A secret goes in an environment variable, never the file.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/actions",
            json!({ "index": null, "name": "x", "how": "plugin", "plugin": "x", "settings": [["password", "hunter2"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"].as_str().unwrap().contains("password_env"), "{v}");
    let (_, page) = a.get("/automate/ticketing").await;
    assert!(page.contains("<strong>Open a ticket</strong>"));
    assert!(page.contains("PW_FAKE_HOOK"));
    let (s, v) = a
        .json(
            Method::DELETE,
            "/api/actions/0",
            json!({ "expect": "fake" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(a.state.ws().config().unwrap().actions.is_empty());
}

/// The forest fixture in `dir/name`: with `fixed`, CAROL's GenericAll on
/// CHILD_DA removed and BOB requiring pre-authentication again; each copy
/// with its own description on BOB, so no two are the same collection.
fn forest(dir: &Path, name: &str, fixed: bool) -> PathBuf {
    let out = dir.join(name);
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(repo("testdata/forest"))
        .unwrap()
        .flatten()
    {
        let mut text = std::fs::read_to_string(e.path()).unwrap();
        if e.file_name().to_string_lossy() == "contoso_users.json" {
            let mut doc: Value = serde_json::from_str(&text).unwrap();
            for o in doc["data"].as_array_mut().unwrap() {
                match o["ObjectIdentifier"].as_str().unwrap() {
                    "S-1-5-21-2000-2000-2000-1201" if fixed => o["Aces"] = json!([]),
                    "S-1-5-21-1000-1000-1000-1104" => {
                        if fixed {
                            o["Properties"]["dontreqpreauth"] = false.into();
                        }
                        o["Properties"]["description"] = name.into();
                    }
                    _ => {}
                }
            }
            text = doc.to_string();
        }
        std::fs::write(out.join(e.file_name()), text).unwrap();
    }
    out
}

/// A finding fixed in a later run counts as fixed on an earlier run's page
/// even when the newest run no longer lists it at all (it was fixed in the
/// run between): what an action is offered on, and what it is told. The
/// CLI reads it from the same shared code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finding_fixed_two_runs_ago_still_counts_as_fixed() {
    let a = app("three", false);
    let first = a.analyze(&forest(&a.dir, "one", false)).await;
    a.analyze(&forest(&a.dir, "two", true)).await;
    let newest = a.analyze(&forest(&a.dir, "three", true)).await;
    let ws = a.state.ws();
    let fps = |run: &str| -> Vec<(String, pathwarden_core::actions::FindingStatus)> {
        let text = pathwarden_ui::run_data::event_text(&ws.run_dir(run).unwrap()).unwrap();
        let event: Value = serde_json::from_str(&text).unwrap();
        pathwarden_core::actions::findings_in_event(&event)
            .into_iter()
            .map(|f| (f.fingerprint, f.status))
            .collect()
    };
    let before = fps(&first);
    let after = fps(&newest);
    let open_now: Vec<&str> = after
        .iter()
        .filter(|(_, s)| *s != pathwarden_core::actions::FindingStatus::Fixed)
        .map(|(f, _)| f.as_str())
        .collect();
    let gone: Vec<&str> = before
        .iter()
        .map(|(f, _)| f.as_str())
        .filter(|f| !open_now.contains(f))
        .collect();
    assert!(!gone.is_empty(), "nothing was fixed");
    // The newest run doesn't list them (they were fixed the run before).
    assert!(
        gone.iter().all(|f| !after.iter().any(|(x, _)| x == f)),
        "{gone:?} / {after:?}"
    );
    for (fp, _) in &before {
        let (_, f) = pathwarden_ui::actions_ui::find_finding(&ws, Some(&first), fp).unwrap();
        let fixed = f.status == pathwarden_core::actions::FindingStatus::Fixed;
        assert_eq!(fixed, gone.contains(&fp.as_str()), "{fp}");
        if fixed {
            assert_eq!(f.finding["status"], "fixed");
        }
    }
}
