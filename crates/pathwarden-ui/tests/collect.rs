//! The Collect wizard through the router: validation and step routing, the
//! rule that a password never comes back out, one job at a time, cancel,
//! and (on Windows) a collection with a stand-in SharpHound that copies the
//! demo collection, through analysis to the run page and the schedule.
//!
//! No domain controller is reachable here: connection checks against a real
//! DC are not covered.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::collect::BUILTIN;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const PORT: u16 = 4343;
const HOST: &str = "127.0.0.1:4343";

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
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-ui-collect-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(&dir).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), PORT));
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

impl App {
    fn cookie(&self) -> String {
        self.state.session_cookie()
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let req = Request::builder()
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.cookie())
            .body(Body::empty())
            .unwrap();
        self.send(req).await
    }

    async fn post(&self, uri: &str, body: Option<Value>) -> (StatusCode, Value, String) {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.cookie())
            .header(header::ORIGIN, format!("http://{HOST}"));
        let body = match body {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let (s, _, text) = self.send(req.body(body).unwrap()).await;
        let v = serde_json::from_str(&text).unwrap_or(Value::Null);
        (s, v, text)
    }

    /// Polls a job until it is no longer collecting or analyzing, returning
    /// every status document seen (raw), the last one parsed.
    async fn wait(&self, job: &str) -> (Value, Vec<String>) {
        let mut seen = Vec::new();
        for _ in 0..2400 {
            let (s, _, body) = self.get(&format!("/api/jobs/{job}")).await;
            assert_eq!(s, StatusCode::OK, "{body}");
            let v: Value = serde_json::from_str(&body).unwrap();
            seen.push(body);
            if v["status"] != "running" && v["status"] != "collecting" {
                return (v, seen);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("job {job} did not finish");
    }

    /// Analyzes the files in `data` as the Analyze page does, and waits:
    /// the job's ID.
    async fn analyze(&self, data: &std::path::Path) -> String {
        let boundary = "tdBoundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            data.display()
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/analyze")
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.cookie())
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let (s, _, text) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{text}");
        let job = serde_json::from_str::<Value>(&text).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        let (done, _) = self.wait(&job).await;
        assert_eq!(done["status"], "done", "{done}");
        job
    }

    /// Posts a multipart form, as the pages send files: `fields` as text,
    /// `files` as (name, bytes) in fields named `files`.
    // Only the Windows-only tests below post forms.
    #[cfg_attr(not(windows), allow(dead_code))]
    async fn post_form(
        &self,
        uri: &str,
        fields: &[(&str, &str)],
        files: &[(&str, &[u8])],
    ) -> (StatusCode, Value, String) {
        let boundary = "pwFormBoundary";
        let mut body = Vec::new();
        for (k, v) in fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        for (name, bytes) in files {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/json\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.cookie())
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let (s, _, text) = self.send(req).await;
        let v = serde_json::from_str(&text).unwrap_or(Value::Null);
        (s, v, text)
    }

    fn uploads_empty(&self) -> bool {
        std::fs::read_dir(self.state.ws().uploads_dir())
            .unwrap()
            .next()
            .is_none()
    }
}

fn demo_zip() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../demo/20261001020000_PathwardenDemo.zip")
        .canonicalize()
        .unwrap()
}

/// A stand-in SharpHound: a batch file that finds `--outputdirectory` among
/// its arguments and copies the demo collection there.
#[cfg(windows)]
fn fake_sharphound(dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let script = dir.join("FakeSharpHound.cmd");
    let demo = demo_zip().display().to_string();
    let demo = demo.trim_start_matches(r"\\?\");
    std::fs::write(
        &script,
        format!(
            "@echo off\r\nsetlocal\r\nset \"OUT=\"\r\n:loop\r\nif \"%~1\"==\"\" goto run\r\n\
             if /i \"%~1\"==\"--outputdirectory\" set \"OUT=%~2\"\r\nshift\r\ngoto loop\r\n:run\r\n\
             echo Fake SharpHound: collecting\r\n\
             copy /y \"{demo}\" \"%OUT%\\20261001020000_PathwardenDemo.zip\" >nul\r\n\
             echo Fake SharpHound: done\r\n"
        ),
    )
    .unwrap();
    script
}

/// A stand-in collector that takes 30 seconds and writes nothing.
#[cfg(windows)]
fn slow_sharphound(dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let script = dir.join("SlowSharpHound.cmd");
    std::fs::write(
        &script,
        "@echo off\r\necho started\r\nping -n 30 127.0.0.1 >nul\r\n",
    )
    .unwrap();
    script
}

#[tokio::test]
async fn the_wizard_page_and_its_assets() {
    let a = app("page");
    let (s, h, body) = a.get("/collect").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Collect from Active Directory"));
    // One Analyze in the menu, current here too; the page's question has
    // the wizard chosen and links the other source.
    assert!(body.contains(r#"<a href="/collect" aria-current="page">"#));
    assert!(body.contains(r#"<a class="src-choice on" href="/collect" aria-current="page">"#));
    assert!(body.contains(r#"<a class="src-choice" href="/analyze">"#));
    // Collecting first, a previous collection second.
    assert!(
        body.find(r#"href="/collect" aria-current"#).unwrap()
            < body
                .find(r#"<a class="src-choice" href="/analyze">"#)
                .unwrap()
    );
    assert!(body.contains(r#"<script src="/static/collect.js" defer></script>"#));
    assert!(!body.contains("<script>"), "no inline scripts");
    assert!(h[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("script-src 'self'"));
    // The build decides whether the built-in collector is offered.
    let offered = body.contains(r#"value="builtin" checked>"#);
    assert_eq!(offered, BUILTIN, "built-in offered iff the build has it");
    assert_eq!(
        body.contains("Not included in this version of Pathwarden"),
        !BUILTIN
    );
    assert!(body.contains(&format!(r#"data-builtin="{}""#, u8::from(BUILTIN))));
    // SharpHound is offered on Windows, in every build.
    assert_eq!(body.contains("Runs on Windows only."), !cfg!(windows));
    // Other collectors' files: under Keep the raw collection, a
    // one-row drop area and their list; while collecting, one row above
    // Stop collecting, hidden until there are some.
    let keep = body.find("Keep the raw collection").unwrap();
    let also = body.find(r#"<div class="also" id="also">"#).unwrap();
    assert!(keep < also && also < body.find(r#"id="ew""#).unwrap());
    assert!(body.contains(
        "<h3>Analyze other data with it <span class=\"muted small\">(optional)</span></h3>"
    ));
    assert!(body.contains("AzureHound, OpenGraph or SharpHound files. They are read with the collection when it finishes."));
    assert!(body.contains(r#"<input type="file" id="also-files" multiple accept=".zip,.json""#));
    assert!(body.contains(r#"<span class="dz-hint">.zip, .json or a folder</span>"#));
    let row = body
        .find(r#"<div class="also-row" id="run-also" hidden>"#)
        .unwrap();
    assert!(row < body.find(r#"id="run-actions""#).unwrap());
    assert!(body.contains("<strong>Analyzed with it:</strong>"));

    for (uri, ty) in [
        ("/static/collect.js", "text/javascript"),
        ("/static/collect.css", "text/css"),
    ] {
        let (s, h, _) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert_eq!(h[header::CONTENT_TYPE], ty);
    }
    // Home links to the wizard; the rail entry is no longer "Soon".
    let (_, _, home) = a.get("/").await;
    assert!(home.contains("Collect from Active Directory"));
    assert!(!home.contains("coming soon"));
}

/// "Read service accounts": ticked unless the environment's
/// pathwarden.toml turns the reads off, as the command line reads it.
#[tokio::test]
async fn read_service_accounts_follows_the_environment() {
    let a = app("svc");
    let (_, _, body) = a.get("/collect").await;
    assert!(body.contains(r#"<input type="checkbox" id="service-reads" checked>"#));
    assert!(body.contains(
        "Service accounts won't be read, so passwords stored on computers aren't checked."
    ));
    let ws = a.state.ws();
    std::fs::write(ws.config_path(), "[collect]\nservice_reads = false\n").unwrap();
    let (_, _, body) = a.get("/collect").await;
    assert!(body.contains(r#"<input type="checkbox" id="service-reads">"#));
    assert!(!pathwarden_ui::collect::service_reads_of(&ws, true));
    assert!(pathwarden_ui::collect::service_reads_of(
        &Workspace::open(a.dir.join("other")).unwrap(),
        true
    ));
}

/// "Read scheduled tasks": its own switch, ticked unless the
/// environment's pathwarden.toml turns the task reads off; the service
/// reads' setting doesn't touch it, nor it theirs.
#[tokio::test]
async fn read_scheduled_tasks_follows_the_environment() {
    let a = app("task");
    let (_, _, body) = a.get("/collect").await;
    assert!(body.contains(r#"<input type="checkbox" id="task-reads" checked>"#));
    assert!(
        body.contains("Finds domain passwords saved in scheduled tasks. Reads account names only.")
    );
    assert!(
        body.contains("Scheduled tasks won't be read, so passwords saved in them aren't checked.")
    );
    let ws = a.state.ws();
    std::fs::write(ws.config_path(), "[collect]\ntask_reads = false\n").unwrap();
    let (_, _, body) = a.get("/collect").await;
    assert!(body.contains(r#"<input type="checkbox" id="task-reads">"#));
    assert!(body.contains(r#"<input type="checkbox" id="service-reads" checked>"#));
    assert!(!pathwarden_ui::collect::task_reads_of(&ws, true));
    assert!(pathwarden_ui::collect::service_reads_of(&ws, true));
    std::fs::write(ws.config_path(), "[collect]\nservice_reads = false\n").unwrap();
    assert!(pathwarden_ui::collect::task_reads_of(&ws, true));
    assert!(
        !pathwarden_ui::collect::task_reads_of(&ws, false),
        "unticked"
    );
}

#[tokio::test]
async fn the_api_needs_the_session_and_same_origin() {
    let a = app("guard");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/collect/start")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::UNAUTHORIZED);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/collect/test")
        .header(header::HOST, HOST)
        .header(header::COOKIE, a.cookie())
        .header(header::ORIGIN, "http://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(a.send(req).await.0, StatusCode::FORBIDDEN);
    // A form post (no JSON) is not accepted either.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/collect/start")
        .header(header::HOST, HOST)
        .header(header::COOKIE, a.cookie())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("domain=contoso.local"))
        .unwrap();
    assert!(a.send(req).await.0.is_client_error());
    assert!(a.state.jobs.running().is_none());
    // Files for the collection: the session, and this origin.
    let upload = |cookie: Option<String>, origin: &str| {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/collect/also")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=b");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        req.body(Body::from(
            "--b\r\nContent-Disposition: form-data; name=\"files\"; filename=\"x.json\"\r\n\r\n{}\r\n--b--\r\n",
        ))
        .unwrap()
    };
    let here = format!("http://{HOST}");
    assert_eq!(
        a.send(upload(None, &here)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        a.send(upload(Some(a.cookie()), "http://evil.example"))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(a.uploads_empty());
}

#[tokio::test]
async fn answers_are_checked_and_name_their_step() {
    let a = app("validate");
    for (body, step, field) in [
        (json!({ "domain": "" }), 1, "domain"),
        (json!({ "domain": "CONTOSO" }), 1, "domain"),
        (
            json!({ "domain": "contoso.local", "server": "dc01 --evil" }),
            1,
            "server",
        ),
        (
            json!({ "domain": "contoso.local", "auth": "password", "user": "" }),
            2,
            "user",
        ),
        (
            json!({ "domain": "contoso.local", "auth": "password", "user": "svc" }),
            2,
            "password",
        ),
    ] {
        for uri in ["/api/collect/test", "/api/collect/start"] {
            let (s, v, text) = a.post(uri, Some(body.clone())).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{uri} {body}: {text}");
            assert_eq!(v["step"], step, "{body}");
            assert_eq!(v["field"], field, "{body}");
            assert!(v["error"].as_str().is_some_and(|e| !e.is_empty()));
        }
    }
    if cfg!(windows) {
        let (s, v, _) = a
            .post(
                "/api/collect/test",
                Some(json!({
                    "domain": "contoso.local", "collector": "sharphound",
                    "sharphound": r"C:\definitely\not\here\SharpHound.exe"
                })),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["field"], "sharphound");
        assert!(v["error"].as_str().unwrap().starts_with("Nothing found"));
        // Network paths are refused before anything looks at them (which
        // would sign in to that server). The host does not exist anyway.
        for path in [
            r"\\pathwarden-unc-test.invalid\share\SharpHound.exe",
            "//pathwarden-unc-test.invalid/share/SharpHound.exe",
            r"\\?\UNC\pathwarden-unc-test.invalid\share\SharpHound.exe",
        ] {
            for uri in ["/api/collect/test", "/api/collect/start"] {
                let (s, v, _) = a
                    .post(
                        uri,
                        Some(json!({
                            "domain": "contoso.local", "collector": "sharphound",
                            "sharphound": path
                        })),
                    )
                    .await;
                assert_eq!(s, StatusCode::BAD_REQUEST, "{uri} {path}");
                assert_eq!(v["field"], "sharphound");
                assert!(v["error"].as_str().unwrap().contains("network path"), "{v}");
            }
        }
    }
    if !BUILTIN {
        // The lean build says plainly that the built-in collector is absent.
        let (s, v, _) = a
            .post(
                "/api/collect/start",
                Some(json!({ "domain": "contoso.local", "collector": "builtin" })),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["field"], "collector");
        assert!(v["error"]
            .as_str()
            .unwrap()
            .contains("doesn't include the built-in collector"));
    }
    assert!(a.state.jobs.running().is_none());
    assert!(a.uploads_empty());
}

/// The password goes in, and never comes back out: not in an error, not in
/// the job's status at any point, not in the page, not on disk.
#[tokio::test]
async fn the_password_never_leaks() {
    const PW: &str = "Leak-Canary-7Q!x";
    let a = app("noleak");
    let form = json!({
        "domain": "contoso.local", "server": "127.0.0.1",
        "auth": "password", "user": "svc-test", "password": PW,
        "ldaps": true, "depth": "quick", "collector": "builtin",
    });

    // The connection check: nothing listens on 127.0.0.1:636.
    let (s, _, text) = a.post("/api/collect/test", Some(form.clone())).await;
    assert!(!text.contains(PW), "{text}");
    if BUILTIN {
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
        let v: Value = serde_json::from_str(&text).unwrap();
        assert!(
            v["error"].as_str().unwrap().contains("refused")
                || v["error"].as_str().unwrap().contains("in time"),
            "{text}"
        );
        assert_eq!(v["step"], 1);
    } else {
        assert_eq!(s, StatusCode::BAD_REQUEST, "{text}");
    }

    // A collection with the same answers fails at the connection, and
    // nothing it reports holds the password.
    let (s, v, text) = a.post("/api/collect/start", Some(form)).await;
    assert!(!text.contains(PW));
    if !BUILTIN {
        assert_eq!(s, StatusCode::BAD_REQUEST);
        return;
    }
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (_, _, page) = a.get(&format!("/collect?job={job}")).await;
    assert!(!page.contains(PW));
    let (done, seen) = a.wait(&job).await;
    assert_eq!(done["status"], "failed", "{done}");
    for body in &seen {
        assert!(!body.contains(PW), "status leaked the password: {body}");
    }
    let (_, _, page) = a.get(&format!("/collect?job={job}")).await;
    assert!(!page.contains(PW));
    // Nothing in the workspace holds it either, and the attempt left nothing.
    assert!(a.uploads_empty());
    for entry in walk(&a.dir) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(PW),
            "{}",
            entry.display()
        );
    }
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[tokio::test]
async fn the_schedule_page_and_files() {
    let a = app("schedule");
    // The old addresses redirect, keeping the query.
    let (s, h, _) = a.get("/collect/schedule?os=linux&at=03%3A00").await;
    assert_eq!(s, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        h[header::LOCATION],
        "/automate/schedule?os=linux&at=03%3A00"
    );
    let (s, h, _) = a.get("/collect/schedule/run.ps1?os=windows").await;
    assert_eq!(s, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(h[header::LOCATION], "/automate/schedule/run.ps1?os=windows");
    let (s, _, body) = a.get("/automate/schedule?os=windows").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Register-ScheduledTask"));
    assert!(body.contains("New-ScheduledTaskPrincipal"));
    assert!(body.contains("-LogonType Password"));
    assert!(body.contains("/automate/schedule/run.ps1?"));
    assert!(body.contains("data-copy=\"code-run\""));
    let (s, _, body) = a.get("/automate/schedule?os=linux").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("pathwarden.timer"));
    assert!(body.contains("LoadCredential=collect-password"));
    // Bad values are refused, never pasted into a script: the form shows
    // them again to correct, and there are no files until they work.
    let bad = "os=windows&folder=C%3A%5Cx%27%3B%20calc&at=99%3A00";
    let (_, _, body) = a.get(&format!("/automate/schedule?{bad}")).await;
    assert!(body.contains("The folder must be a full path"));
    assert!(body.contains("Enter the time as HH:MM"));
    assert!(body.contains(r#"value="C:\x&#39;; calc""#), "{body}");
    assert!(body.contains(r#"value="99:00""#));
    // Each refused field is marked and points at its own message; the time
    // is plain text, which can show 99:00; the OS links keep what was typed.
    assert!(body.contains(
        r#"<input type="text" id="at" name="at" value="99:00" aria-invalid="true" aria-describedby="sf-err-at">"#
    ), "{body}");
    assert!(body.contains(r#"aria-invalid="true" aria-describedby="sf-err-folder""#));
    assert!(body.contains(r#"<li id="sf-err-folder">The folder must be a full path"#));
    assert!(body.contains(r#"<li id="sf-err-at">Enter the time"#));
    assert!(!body.contains("sf-err-account"));
    assert!(
        body.contains("at=99%3A00") && !body.contains("at=02%3A00"),
        "{body}"
    );
    assert!(
        !body.contains("Register-ScheduledTask") && !body.contains("/automate/schedule/run.ps1?")
    );
    let (s, _, text) = a.get(&format!("/automate/schedule/run.ps1?{bad}")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(!text.contains("calc"), "{text}");
    // Downloads: a fixed set of names.
    let (s, h, script) = a.get("/automate/schedule/run.ps1?os=windows").await;
    assert_eq!(s, StatusCode::OK);
    assert!(h[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("filename=\"run.ps1\""));
    assert!(script.contains("pathwarden.exe run -i $collect"));
    // Scheduled runs are marked as such in the history.
    assert!(script.contains("$env:PATHWARDEN_SCHEDULED = '1'"));
    assert!(script.contains("Remove-Item -LiteralPath $collect"));
    for bad in [
        "/automate/schedule/run.sh?os=windows",
        "/automate/schedule/..%2Fsummary.json",
        "/automate/schedule/x.ps1",
    ] {
        assert_eq!(a.get(bad).await.0, StatusCode::NOT_FOUND, "{bad}");
    }
}

#[cfg(windows)]
#[tokio::test]
async fn sharphound_collects_then_the_analysis_runs() {
    let a = app("e2e");
    let tools = a.dir.join("tools");
    let fake = fake_sharphound(&tools);
    let form = json!({
        "domain": "pathwarden.demo", "auth": "current", "depth": "quick",
        "collector": "sharphound", "sharphound": fake.display().to_string(),
    });
    // The check finds the program.
    let (s, v, text) = a.post("/api/collect/test", Some(form.clone())).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert!(v["lines"][0]
        .as_str()
        .unwrap()
        .starts_with("Found SharpHound at"));
    // Not signed by SpecterOps: one warning, first, and it still runs.
    assert_eq!(
        v["warnings"][0].as_str().unwrap(),
        format!(
            "{} isn't signed by SpecterOps. Run it only if you trust where it came from.",
            fake.display()
        ),
        "{v}"
    );

    let (s, v, text) = a.post("/api/collect/start", Some(form)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (done, seen) = a.wait(&job).await;
    assert_eq!(done["status"], "done", "{done}");
    assert_eq!(done["run"], job.as_str());
    assert_eq!(done["collect"]["method"], "SharpHound");
    assert_eq!(done["collect"]["depth"], "Quick");
    let log = done["collect"]["log"].as_array().unwrap();
    assert!(
        log.iter().any(|l| l == "Fake SharpHound: collecting"),
        "{log:?}"
    );
    assert!(done["collect"]["objects"]["users"].as_u64().unwrap() > 0);
    assert!(done["collect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w
            .as_str()
            .unwrap()
            .contains("so it has no sessions or local groups.")));
    assert!(seen
        .iter()
        .any(|b| b.contains("\"status\":\"collecting\"") || b.contains("\"status\":\"running\"")));
    // The raw collection is gone; the run records how it was collected.
    assert!(a.uploads_empty());
    assert!(!a.state.ws().collections_dir().exists());
    let summary = a.state.ws().summary(&job).expect("run saved");
    let c = summary.collection.expect("collection recorded");
    assert_eq!(
        (c.method.as_str(), c.scope.as_str()),
        ("sharphound", "dc-only")
    );
    assert_eq!(c.domain, "pathwarden.demo");
    assert!(c.current_user && c.kept.is_none());
    assert!(summary.source.starts_with("Collected from pathwarden.demo"));
    let raw =
        std::fs::read_to_string(a.state.ws().run_dir(&job).unwrap().join("summary.json")).unwrap();
    assert!(raw.contains("\"collection\""));

    // Its Run details tab says how, with what a Quick collection leaves
    // out as information (not a warning: the row isn't amber), and links
    // to the nightly schedule; the run page has no card for it above the
    // report.
    let (s, _, page) = a.get(&format!("/runs/{job}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!page.contains("This run was collected with"), "{page}");
    let (_, _, tab) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(
        tab.contains("This run was collected with SharpHound, Quick (directory only)."),
        "{tab}"
    );
    assert!(
        tab.contains("<p>This collection read only the domain controllers, so it has no sessions or local groups."),
        "{tab}"
    );
    assert!(
        tab.contains(r#"<span class="aside">Quick (directory only)</span>"#),
        "{tab}"
    );
    assert!(!tab.contains("collector warning"), "{tab}");
    assert!(
        tab.contains(r##"<a href="#" data-pw-run="schedule">Schedule this collection</a>"##),
        "{tab}"
    );
    let (_, _, sched) = a
        .get(&format!("/automate/schedule?os=windows&run={job}"))
        .await;
    assert!(
        sched.contains("&#39;--domain&#39;, &#39;pathwarden.demo&#39;"),
        "domain from the run"
    );
    assert!(sched.contains(
        "&#39;--sharphound&#39;, (Join-Path $folder &#39;SharpHound.exe&#39;)\n        &#39;--scope&#39;, &#39;dc-only&#39;"
    ));
    assert!(sched.contains("SharpHound.exe</code> into"));
}

#[cfg(windows)]
#[tokio::test]
async fn keeping_the_raw_collection() {
    let a = app("keep");
    let fake = fake_sharphound(&a.dir.join("tools"));
    let (s, v, text) = a
        .post(
            "/api/collect/start",
            Some(json!({
                "domain": "pathwarden.demo", "collector": "sharphound",
                "sharphound": fake.display().to_string(), "keep": true,
            })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (done, _) = a.wait(&job).await;
    assert_eq!(done["status"], "done", "{done}");
    let kept = a.state.ws().collections_dir().join(&job);
    assert!(kept.join("20261001020000_PathwardenDemo.zip").is_file());
    assert_eq!(done["collect"]["kept"], kept.display().to_string());
    assert!(a.uploads_empty());
    let c = a.state.ws().summary(&job).unwrap().collection.unwrap();
    assert_eq!(c.kept.as_deref(), Some(kept.display().to_string().as_str()));
    // Its Run details tab says where.
    let (_, _, page) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(page.contains("The raw collection was kept in"), "{page}");
    // Kept collections survive a restart; uploads do not.
    Workspace::open(&a.dir).unwrap();
    assert!(kept.is_dir());
}

#[cfg_attr(not(windows), allow(dead_code))]
fn testdata(rel: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(rel),
    )
    .unwrap()
}

/// Other collectors' files go with a collection (uploaded before it
/// starts, read in its analysis, deleted after), and a run whose
/// collection was kept is analyzed again with more files, as a new run.
#[cfg(windows)]
#[tokio::test]
async fn other_files_go_with_a_collection_before_and_after() {
    let a = app("also");
    let fake = fake_sharphound(&a.dir.join("tools"));
    let azure = testdata("entra/azurehound/azurehound_hybrid.json");
    let taskhound = testdata("opengraph/taskhound/taskhound.json");

    // What each file is, for its row.
    let (s, v, text) = a
        .post(
            "/api/opengraph/sniff",
            Some(json!({ "files": [
                { "name": "contoso-azurehound.json", "size": azure.len(),
                  "head": String::from_utf8_lossy(&azure), "tail": String::from_utf8_lossy(&azure) },
                { "name": "collection.zip", "size": 10 },
            ]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(v["kinds"], json!(["AzureHound: Entra ID", "Archive"]));

    // Before: uploaded, then named by Start collecting.
    let (s, v, text) = a
        .post_form(
            "/api/collect/also",
            &[],
            &[("contoso-azurehound.json", &azure)],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{text}");
    let also = v["also"].as_str().unwrap().to_string();
    assert_eq!(v["names"], json!(["contoso-azurehound.json"]));
    let form = |also: &str| {
        json!({
            "domain": "pathwarden.demo", "collector": "sharphound",
            "sharphound": fake.display().to_string(), "keep": true, "also": also,
        })
    };
    // Files no longer waiting: nothing starts.
    let (s, v, _) = a
        .post("/api/collect/start", Some(form("20990101-000000-000000")))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        v["error"],
        "The files to analyze with the collection are no longer waiting. Add them again."
    );
    let (s, v, text) = a.post("/api/collect/start", Some(form(&also))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (done, seen) = a.wait(&job).await;
    assert_eq!(done["status"], "done", "{done}");
    // While collecting, the page names them.
    assert!(
        seen.iter().any(|b| b.contains("\"status\":\"collecting\"")
            && b.contains("\"also\":[\"contoso-azurehound.json\"]")),
        "{seen:?}"
    );
    let first = a.state.ws().summary(&job).unwrap();
    assert!(
        first.source.starts_with("Collected from pathwarden.demo")
            && first.source.ends_with(", with contoso-azurehound.json"),
        "{}",
        first.source
    );
    // Read in the same analysis: the run has their sources.
    let sources = |id: &str| {
        pathwarden_ui::opengraph_ui::read_stats(&a.state.ws().run_dir(id).unwrap())
            .map(|s| format!("{s:?}"))
            .unwrap_or_default()
    };
    assert!(sources(&job).contains("azurehound"), "{}", sources(&job));
    // The upload is gone; the kept collection is the collection alone.
    assert!(a.uploads_empty());
    let kept = a.state.ws().collections_dir().join(&job);
    let kept_files: Vec<_> = walk(&kept);
    assert!(
        kept_files
            .iter()
            .all(|f| !f.to_string_lossy().contains("azurehound")),
        "{kept_files:?}"
    );

    // After: Run details offers to add other data.
    let (_, _, tab) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(
        tab.contains(r#"<div class="rd-add"><h3>Add other data</h3><div class="rd-row"><button type="button" class="rd-btn" data-pw-run="add-data"><span>Add files and analyze again</span></button><span class="why">Analyzes this run&#39;s collection again with AzureHound, OpenGraph or SharpHound files, as a new run.</span></div></div><div class="rd-remove">"#),
        "{tab}"
    );
    // Analyze, with the collection first.
    let (s, _, page) = a.get(&format!("/analyze?from={job}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains(&format!(r#"id="from-list" data-from="{job}""#)),
        "{page}"
    );
    assert!(page.contains("They are analyzed with this collection, as a new run."));
    // The files and the collection: a new run, collected as the first.
    let (s, v, text) = a
        .post_form(
            "/api/analyze",
            &[("from", &job)],
            &[("taskhound_opengraph.json", &taskhound)],
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let again = v["job"].as_str().unwrap().to_string();
    let (done, _) = a.wait(&again).await;
    assert_eq!(done["status"], "done", "{done}");
    assert_ne!(again, job);
    let second = a.state.ws().summary(&again).unwrap();
    // The collection, with the files added this time.
    assert_eq!(
        second.source,
        first
            .source
            .replace("contoso-azurehound.json", "taskhound_opengraph.json")
    );
    assert_eq!(second.collection, first.collection);
    assert!(sources(&again).contains("TaskHound"), "{}", sources(&again));
    assert!(a.uploads_empty());
    assert!(kept.is_dir(), "the kept collection stays");

    // Moved or deleted: greyed out, with why; Analyze is as it always is.
    std::fs::remove_dir_all(&kept).unwrap();
    let (_, _, tab) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(
        tab.contains(r#"<button type="button" class="rd-btn" disabled><span>Add files and analyze again</span></button><span class="why">The kept collection was moved or deleted, so there is nothing to add to.</span>"#),
        "{tab}"
    );
    assert!(!tab.contains(r#"data-pw-run="add-data""#));
    let (_, _, page) = a.get(&format!("/analyze?from={job}")).await;
    assert!(!page.contains(r#"id="from-list""#));
    let (s, v, _) = a
        .post_form(
            "/api/analyze",
            &[("from", &job)],
            &[("taskhound_opengraph.json", &taskhound)],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v["error"],
        "The kept collection was moved or deleted, so there is nothing to add to."
    );
    assert!(a.uploads_empty());
}

/// A collection that wasn't kept has nothing to add to; files
/// uploaded for a collection that stops are deleted.
#[cfg(windows)]
#[tokio::test]
async fn nothing_to_add_to_without_the_kept_collection() {
    let a = app("also-not-kept");
    let fake = fake_sharphound(&a.dir.join("tools"));
    let (s, v, text) = a
        .post(
            "/api/collect/start",
            Some(json!({
                "domain": "pathwarden.demo", "collector": "sharphound",
                "sharphound": fake.display().to_string(),
            })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (done, _) = a.wait(&job).await;
    assert_eq!(done["status"], "done", "{done}");
    assert!(done["collect"].get("also").is_none(), "{done}");
    let dir = a.state.ws().run_dir(&job).unwrap();
    assert!(pathwarden_ui::opengraph_ui::read_stats(&dir).is_none());
    let (_, _, tab) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(
        tab.contains(r#"<button type="button" class="rd-btn" disabled><span>Add files and analyze again</span></button><span class="why">The collection wasn&#39;t kept, so there is nothing to add to. Keep the raw collection when you collect.</span>"#),
        "{tab}"
    );
    let (s, v, _) = a
        .post_form("/api/analyze", &[("from", &job)], &[("x.json", b"{}")])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"]
        .as_str()
        .unwrap()
        .starts_with("The collection wasn't kept"));

    // Staged for a collection that stops: deleted with it.
    let slow = slow_sharphound(&a.dir.join("tools"));
    let (s, v, _) = a
        .post_form(
            "/api/collect/also",
            &[],
            &[("contoso-azurehound.json", b"{}")],
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let also = v["also"].as_str().unwrap().to_string();
    assert!(!a.uploads_empty());
    let (s, v, text) = a
        .post(
            "/api/collect/start",
            Some(json!({
                "domain": "pathwarden.demo", "collector": "sharphound",
                "sharphound": slow.display().to_string(), "also": also,
            })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (s, _, _) = a.post(&format!("/api/collect/{job}/cancel"), None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (done, _) = a.wait(&job).await;
    assert_eq!(done["status"], "stopped", "{done}");
    assert!(a.uploads_empty());
}

#[cfg(windows)]
#[tokio::test]
async fn cancel_stops_the_collector_and_one_job_runs_at_a_time() {
    let a = app("cancel");
    let slow = slow_sharphound(&a.dir.join("tools"));
    let (s, v, text) = a
        .post(
            "/api/collect/start",
            Some(json!({
                "domain": "contoso.local", "collector": "sharphound",
                "sharphound": slow.display().to_string(), "depth": "full",
            })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();

    // Wait until the collector is running.
    for _ in 0..200 {
        let (_, _, body) = a.get(&format!("/api/jobs/{job}")).await;
        if body.contains("started") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (_, _, body) = a.get(&format!("/api/jobs/{job}")).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "collecting", "{body}");
    assert_eq!(v["collect"]["depth"], "Full");

    // Nothing else starts meanwhile: not a demo, not another collection.
    let (s, _, _) = a.post("/api/demo", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = a
        .post(
            "/api/collect/start",
            Some(json!({ "domain": "contoso.local", "collector": "sharphound", "sharphound": slow.display().to_string() })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // The Collect page resumes the running job.
    let (_, _, page) = a.get("/collect").await;
    assert!(page.contains(&format!(r#"data-job="{job}""#)));

    let (s, _, _) = a.post(&format!("/api/collect/{job}/cancel"), None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let started = std::time::Instant::now();
    let (done, _) = a.wait(&job).await;
    assert_eq!(done["status"], "stopped", "{done}");
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(a.uploads_empty());
    assert!(a.state.ws().summary(&job).is_none());
    // A stopped job can't be stopped again; nonsense IDs are refused.
    let (s, _, _) = a.post(&format!("/api/collect/{job}/cancel"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = a.post("/api/collect/..%2F..%2Fx/cancel", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// A stand-in SharpHound for a run of several domains: copies the
/// demo collection for any domain but `broken.invalid`, for which it writes
/// nothing.
#[cfg(windows)]
fn fake_sharphound_domains(dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let script = dir.join("FakeSharpHound2.cmd");
    let demo = demo_zip().display().to_string();
    let demo = demo.trim_start_matches(r"\\?\");
    std::fs::write(
        &script,
        format!(
            "@echo off\r\nsetlocal\r\nset \"OUT=\"\r\nset \"DOM=\"\r\n:loop\r\nif \"%~1\"==\"\" goto run\r\n\
             if /i \"%~1\"==\"--outputdirectory\" set \"OUT=%~2\"\r\n\
             if /i \"%~1\"==\"--domain\" set \"DOM=%~2\"\r\nshift\r\ngoto loop\r\n:run\r\n\
             echo Fake SharpHound: collecting %DOM%\r\n\
             if /i \"%DOM%\"==\"broken.invalid\" exit /b 1\r\n\
             copy /y \"{demo}\" \"%OUT%\\20261001020000_PathwardenDemo.zip\" >nul\r\n\
             echo Fake SharpHound: done\r\n"
        ),
    )
    .unwrap();
    script
}

/// A run of several domains, one of which fails: the others are
/// analyzed, each domain's outcome is recorded, Run details says what's
/// missing and links to collect it, and the link opens the Collect page
/// with it ticked.
#[cfg(windows)]
#[tokio::test]
async fn several_domains_one_fails_and_the_rest_are_analyzed() {
    let a = app("several");
    let fake = fake_sharphound_domains(&a.dir.join("tools"));
    // A run of pathwarden.demo whose trusts list BROKEN.INVALID: the page
    // offers only those.
    let trusts = a.dir.join("trusts");
    std::fs::create_dir_all(&trusts).unwrap();
    for kind in ["domains", "users", "computers", "groups"] {
        let text = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../testdata/trusts/contoso_{kind}.json")),
        )
        .unwrap()
        .replace("CHILD.CONTOSO.LOCAL", "BROKEN.INVALID")
        .replace("CONTOSO.LOCAL", "PATHWARDEN.DEMO");
        std::fs::write(trusts.join(format!("demo_{kind}.json")), text).unwrap();
    }
    a.analyze(&trusts).await;
    let form = json!({
        "domain": "pathwarden.demo", "auth": "current", "depth": "quick",
        "collector": "sharphound", "sharphound": fake.display().to_string(),
        "trusted": ["broken.invalid"],
    });
    let (s, v, text) = a.post("/api/collect/start", Some(form)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{text}");
    let job = v["job"].as_str().unwrap().to_string();
    let (done, seen) = a.wait(&job).await;
    assert_eq!(done["status"], "done", "{done}");
    // Each domain had its line while it ran.
    assert!(
        seen.iter()
            .any(|b| b.contains(r#""name":"PATHWARDEN.DEMO","state":"active""#)),
        "{seen:?}"
    );
    // The run's domain, for the page's title.
    assert_eq!(done["collect"]["domain"], "PATHWARDEN.DEMO", "{done}");
    let doms = done["collect"]["domains"].as_array().unwrap();
    assert_eq!(doms[0]["state"], "done", "{doms:?}");
    assert_eq!(doms[1]["name"], "BROKEN.INVALID");
    assert_eq!(doms[1]["state"], "failed");
    let summary = a.state.ws().summary(&job).expect("run saved");
    assert!(summary
        .source
        .starts_with("Collected from pathwarden.demo and 1 trusted domain"));
    let c = summary.collection.expect("collection recorded");
    assert_eq!(c.domains.len(), 2);
    assert!(c.domains[0].collected && c.domains[0].objects.unwrap() > 0);
    assert!(!c.domains[1].collected);
    assert!(c.domains[1].reason.is_some());
    // Run details: the Domains row, amber, with the link.
    let (_, _, tab) = a.get(&format!("/runs/{job}/report?embed=1")).await;
    assert!(tab.contains("1 of 2 collected"), "{tab}");
    assert!(
        tab.contains(
            "Attack paths through BROKEN.INVALID are missing. PATHWARDEN.DEMO was analyzed on its own."
        ),
        "{tab}"
    );
    assert!(
        tab.contains(r##"<a href="#" data-pw-run="collect">Collect BROKEN.INVALID</a>"##),
        "{tab}"
    );
    let (s, h, _) = a.get(&format!("/runs/{job}/collect")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let to = h[header::LOCATION].to_str().unwrap().to_string();
    assert_eq!(to, "/collect?domain=pathwarden.demo&pick=BROKEN.INVALID");
    let (_, _, page) = a.get(&to).await;
    assert!(
        page.contains(r#"data-pick="[&quot;broken.invalid&quot;]""#),
        "{page}"
    );
    assert!(page.contains(r#"value="pathwarden.demo""#));
    assert!(page.contains("&#39;s last run.") || page.contains("'s last run."));
}

/// The Collect page lists a domain's trusted domains from the last
/// run that collected it, ticked when they can probably be read, and with
/// the reason when they can't.
#[tokio::test]
async fn the_trusted_domains_of_the_last_run() {
    let a = app("trusted");
    // No run yet: nothing to list.
    let (s, _, body) = a.get("/api/collect/trusted?domain=contoso.local").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({ "domains": [] })
    );
    // A run of the synthetic data with a trust of each kind.
    let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/trusts");
    let job = a.analyze(&data).await;

    let (s, _, body) = a.get("/api/collect/trusted?domain=Contoso.Local").await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["from"], "CONTOSO.LOCAL");
    let doms = v["domains"].as_array().unwrap();
    assert_eq!(doms.len(), 7, "{v}");
    let pick = |n: &str| {
        doms.iter()
            .find(|d| d["name"] == n)
            .unwrap_or_else(|| panic!("{n} in {v}"))
            .clone()
    };
    assert_eq!(pick("CHILD.CONTOSO.LOCAL")["pick"], "on");
    // Their own trust records aren't in the run: selective authentication
    // unknown, so offered unticked (lab item 53).
    assert_eq!(pick("FABRIKAM.COM")["pick"], "maybe");
    assert_eq!(
        pick("FABRIKAM.COM")["why"],
        "Your account may not be allowed to sign in there."
    );
    assert_eq!(pick("TAILSPIN.COM")["pick"], "maybe");
    assert_eq!(pick("WINGTIP.COM")["pick"], "maybe");
    assert_eq!(pick("NORTHWIND.COM")["pick"], "off");
    assert_eq!(
        pick("NORTHWIND.COM")["why"],
        "This trust doesn't let accounts from your domain in."
    );
    // The run saved what it didn't collect, for Run details.
    let summary = a.state.ws().summary(&job).unwrap();
    assert_eq!(summary.not_collected.as_ref().map(Vec::len), Some(7));
    // A request keeps only the domains the page offers: a domain the
    // trusts don't list, or one that can't be collected, is dropped, with
    // its domain controller. The ticked one's is checked as typed (step 1);
    // without it, the next problem is the user (step 2), not the domains.
    let form = |servers: Value| {
        json!({
            "domain": "contoso.local", "auth": "password", "user": "",
            "trusted": ["child.contoso.local", "evil.example", "NORTHWIND.COM"],
            "trusted_servers": servers,
        })
    };
    for uri in ["/api/collect/test", "/api/collect/start"] {
        let (s, v, text) = a
            .post(
                uri,
                Some(form(json!({ "CHILD.CONTOSO.LOCAL": "dc01 --evil" }))),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{text}");
        assert_eq!(
            (v["step"].clone(), v["field"].clone()),
            (json!(1), json!("trusted"))
        );
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .starts_with("CHILD.CONTOSO.LOCAL's domain controller"),
            "{text}"
        );
        let (s, v, text) = a
            .post(
                uri,
                Some(form(
                    json!({ "evil.example": "x y", "northwind.com": "x y" }),
                )),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{text}");
        assert_eq!(v["field"], "user", "{text}");
    }
    // Another domain: nothing.
    let (_, _, body) = a.get("/api/collect/trusted?domain=elsewhere.local").await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["domains"],
        json!([])
    );
    // The page has the list's place on step 1, and the confirmation says
    // the authorization line.
    let (_, _, page) = a.get("/collect").await;
    assert!(page.contains(r#"<fieldset class="field" id="trusted" hidden>"#));
    assert!(page.contains(r#"<dialog id="doms-dialog""#));
    assert!(page.contains("Only collect from domains you are authorized to assess."));
}

/// One progress view. The panel is the current domain's row of the
/// domains list, the only one; done, skipped and waiting domains fold into
/// a row each that opens with a button; the counts are one line with All
/// counts opening the tiles; the skipped-domain note is behind an ⓘ.
#[tokio::test]
async fn the_progress_view_is_one_panel_in_the_domain_list() {
    let a = app("one-view");
    let (_, _, page) = a.get("/collect").await;
    let list = &page[page.find(r#"<ol class="doms" id="run-doms""#).unwrap()..];
    let list = &list[..list.find(r#"<ol class="steps" id="run-steps">"#).unwrap()];
    // The list is not hidden: with one domain it holds the panel alone.
    assert!(list.starts_with(r#"<ol class="doms" id="run-doms" aria-label="Domains">"#));
    let (done, cur, waiting) = (
        list.find(r#"id="run-done""#).unwrap(),
        list.find(r#"<li class="cur" id="run-cur"><div class="cprog" id="cprog">"#)
            .unwrap(),
        list.find(r#"id="run-waiting""#).unwrap(),
    );
    let skipped = list.find(r#"id="run-skipped""#).unwrap();
    assert!(done < skipped && skipped < cur && cur < waiting, "{list}");
    assert_eq!(page.matches(r#"class="cprog""#).count(), 1);
    // The notes fold into one line before their list, with the collector's
    // output a link on it.
    let notes = page
        .find(r#"<div class="notes-row" id="run-notes" hidden>"#)
        .unwrap();
    let warnings = page
        .find(r#"<ul class="warn-list" id="run-warnings" hidden>"#)
        .unwrap();
    assert!(notes < warnings);
    assert!(page[notes..warnings].contains(r#"aria-controls="run-warnings">Show</button>"#));
    assert!(page[notes..warnings].contains(r#"id="run-output" aria-expanded="false" aria-controls="run-log-box" hidden>Collector output</button>"#));
    assert_eq!(page.matches(r#"role="progressbar""#).count(), 1);
    for k in ["done", "skipped", "waiting"] {
        assert!(
            list.contains(&format!(
                r#"<button type="button" class="linkish dg-show" aria-expanded="false" aria-controls="run-{k}-list">Show</button></div><ol class="dg-list" id="run-{k}-list" hidden></ol>"#
            )),
            "{k}"
        );
    }
    // The bar, the numbers, the counts line, the tiles and their note
    // are all in the panel.
    let panel = &list[cur..waiting];
    for id in [
        "cp-st",
        "cp-dom",
        "cp-phase",
        "cp-step",
        "verb",
        "cp-bar",
        "cp-pct",
        "cp-eta",
        "run-kinds",
        "run-counts",
        "run-counts-note",
    ] {
        assert!(panel.contains(&format!(r#"id="{id}""#)), "{id}");
    }
    assert!(panel.contains(r#"<button type="button" class="linkish cp-all" id="run-counts-all" aria-expanded="false" aria-controls="run-counts" hidden>All counts</button>"#));
    // The note is the skipped row's ⓘ, not a paragraph of its own.
    assert!(!page.contains("run-doms-note"));
    assert!(list[skipped..cur].contains(
        r#"<span class="tip-text" role="tooltip" id="run-skipped-tip">A domain that fails is skipped. The others are still analyzed.</span>"#
    ));
}

#[test]
fn demo_zip_exists() {
    assert!(demo_zip().is_file());
}
