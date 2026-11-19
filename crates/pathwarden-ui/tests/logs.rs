//! Logs and crash reports in the app, through the router: the Logs card on
//! Settings, a crash's line with Open crash report and Dismiss, the amber
//! dot by Settings (and nothing on Home), Open log (only a file of the logs
//! folder), and a failed analysis's and collection's logs.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::logs::{By, Crash, JobRef, Kind};
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4271";

struct App {
    router: Router,
    state: Arc<AppState>,
    dir: PathBuf,
    opened: Arc<Mutex<Vec<PathBuf>>>,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app(name: &str) -> App {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-ui-logs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let mut state = AppState::new(ws, Token::generate().unwrap(), 4271);
    state.jobs.set_logs_dir(Some(dir.join("logs")));
    let opened = Arc::new(Mutex::new(Vec::new()));
    let rec = opened.clone();
    state.opener = Arc::new(move |p: &std::path::Path| {
        rec.lock().unwrap().push(p.to_path_buf());
        true
    });
    let state = Arc::new(state);
    App {
        router: router(state.clone()),
        state,
        dir,
        opened,
    }
}

impl App {
    fn logs(&self) -> PathBuf {
        self.dir.join("logs")
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, text) = self.send(req).await;
        (s, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Analyzes `path` as the Analyze page does; the finished job.
    async fn analyze(&self, path: &std::path::Path) -> Value {
        let boundary = "lgBoundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            path.display()
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/analyze")
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let (s, text) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{text}");
        let job = serde_json::from_str::<Value>(&text).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        self.wait(&job).await
    }

    async fn wait(&self, job: &str) -> Value {
        for _ in 0..2400 {
            let (_, body) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            if v["status"] != "running" && v["status"] != "collecting" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("job {job} did not finish");
    }
}

fn crash(job: Option<JobRef>) -> Crash {
    Crash {
        message: "index out of bounds".into(),
        location: "src/x.rs:1:2".into(),
        thread: "main".into(),
        backtrace: String::new(),
        system: "Test OS".into(),
        job,
    }
}

#[tokio::test]
async fn a_crash_shows_on_settings_until_dismissed() {
    let a = app("crash");
    let (s, page) = a.get("/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains(r#"<section class="card setting" id="logs">"#),
        "{page}"
    );
    assert!(page.contains("Kept 30 days, at most 200 MB."));
    assert!(page.contains("Open logs folder"));
    assert!(page.contains(r##"<a href="#logs">Logs</a>"##));
    assert!(!page.contains("crash-line") && !page.contains("nav-dot"));

    // A crash during a collection.
    let log =
        pathwarden_core::logs::JobLog::open_in(&a.logs(), Kind::Collect, By::App, "SCALE.LOCAL")
            .unwrap();
    let name = crash(Some(JobRef {
        kind: Kind::Collect,
        by: By::App,
        subject: "SCALE.LOCAL".into(),
        name: log.name().into(),
        path: log.path().into(),
    }))
    .write_in(&a.logs())
    .unwrap();
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains("Stopped unexpectedly during a collection, "),
        "{page}"
    );
    assert!(page.contains(&format!(
        r#"data-crash-open="{name}">Open crash report</button>"#
    )));
    assert!(page.contains(&format!(r#"data-crash-dismiss="{name}">Dismiss</button>"#)));
    assert!(
        page.contains(r#"class="nav-dot jump-dot""#),
        "the jump link's dot"
    );
    assert!(
        page.contains(r#"<a href="/settings" title="Pathwarden stopped unexpectedly" data-crash"#),
        "the rail's dot: {page}"
    );
    // Nothing on Home but the rail's dot.
    let (_, home) = a.get("/").await;
    assert!(!home.contains("Stopped unexpectedly"), "{home}");
    assert!(home.contains(r#"class="nav-dot""#));
    // The pages' poll keeps the dot.
    let (_, polled) = a.get("/api/history/pulled?since=0&page=home").await;
    let polled: Value = serde_json::from_str(&polled).unwrap();
    assert_eq!(polled["crash"], true, "{polled}");

    // Open crash report: that file of the logs folder.
    let (s, _) = a.post("/api/logs/open", json!({ "file": name })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(a.opened.lock().unwrap().last(), Some(&a.logs().join(&name)));

    // Dismiss: the line and the dot go, on this computer. A crash written
    // after the page was shown still shows.
    let later = crash(None).write_in(&a.logs()).unwrap();
    let (s, _) = a.post("/api/logs/dismiss", json!({ "file": name })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, page) = a.get("/settings").await;
    assert!(
        page.contains(&format!(r#"data-crash-open="{later}""#)),
        "{page}"
    );
    let (s, _) = a.post("/api/logs/dismiss", json!({ "file": later })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, page) = a.get("/settings").await;
    assert!(
        !page.contains("crash-line") && !page.contains("nav-dot"),
        "{page}"
    );
    let (_, polled) = a.get("/api/history/pulled?since=0&page=home").await;
    assert_eq!(
        serde_json::from_str::<Value>(&polled).unwrap()["crash"],
        false
    );
    // A later crash shows again.
    crash(None).write_in(&a.logs()).unwrap();
    let (_, page) = a.get("/settings").await;
    assert!(page.contains("Stopped unexpectedly, "), "no job: {page}");
}

#[tokio::test]
async fn only_files_of_the_logs_folder_open() {
    let a = app("open");
    // The folder, made when missing.
    let (s, _) = a.post("/api/logs/open", json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(a.opened.lock().unwrap().last(), Some(&a.logs()));
    assert!(a.logs().is_dir());
    std::fs::write(a.dir.join("secret.txt"), "x").unwrap();
    std::fs::write(a.logs().join("notes.txt"), "x").unwrap();
    for bad in [
        "../secret.txt",
        "..\\secret.txt",
        "notes.txt",
        "job-20261119-094211-collect.log",
        "crash-20261119-094702.txt/../../secret.txt",
    ] {
        let (s, v) = a.post("/api/logs/open", json!({ "file": bad })).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}: {v}");
    }
    assert_eq!(a.opened.lock().unwrap().len(), 1, "nothing else opened");
}

/// A failed analysis names its log, which says what happened and how it
/// ended; Open log opens it.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_analysis_has_its_log() {
    let a = app("failed");
    let data = a.dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("20261001020000_users.json"), "{ not json").unwrap();
    let job = a.analyze(&data).await;
    assert_eq!(job["status"], "failed", "{job}");
    let log = job["log"].as_str().expect("the job names its log");
    assert!(
        log.starts_with("job-") && log.ends_with("-analyze.log"),
        "{log}"
    );
    let text = std::fs::read_to_string(a.logs().join(log)).unwrap();
    assert!(
        text.lines().next().unwrap().starts_with("# Analysis "),
        "{text}"
    );
    assert!(text.contains("[analyze, app] analysis: reading"), "{text}");
    let last = text.lines().last().unwrap();
    assert!(last.contains("[analyze, app] result: failed: "), "{text}");
    let (s, _) = a.post("/api/logs/open", json!({ "file": log })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

/// A collection that fails: its log has the collector's output and exit
/// code, and how it ended; the job names it for Open log.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_collection_has_its_log() {
    let a = app("collect");
    let tools = a.dir.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let fake = tools.join("FailingSharpHound.cmd");
    std::fs::write(
        &fake,
        "@echo off\r\necho Fake SharpHound: collecting\r\necho token=Tk-0123456789abc\r\nexit /b 3\r\n",
    )
    .unwrap();
    let form = json!({
        "domain": "pathwarden.demo", "auth": "current", "depth": "quick",
        "collector": "sharphound", "sharphound": fake.display().to_string(),
    });
    let (s, v) = a.post("/api/collect/start", form).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let job = a.wait(v["job"].as_str().unwrap()).await;
    assert_eq!(job["status"], "failed", "{job}");
    let log = job["log"].as_str().expect("the job names its log");
    assert!(log.ends_with("-collect.log"), "{log}");
    let text = std::fs::read_to_string(a.logs().join(log)).unwrap();
    assert!(
        text.starts_with("# Collection PATHWARDEN.DEMO | app | collect"),
        "{text}"
    );
    assert!(
        text.contains("[collect, app] Fake SharpHound: collecting"),
        "{text}"
    );
    assert!(
        text.contains("SharpHound exited with exit code: 3"),
        "{text}"
    );
    assert!(!text.contains("Tk-0123456789abc"), "{text}");
    assert!(
        text.lines().last().unwrap().contains("result: failed: "),
        "{text}"
    );
}
