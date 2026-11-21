//! Where runs go and what they are called, through the router: the "Saving
//! to" block on Collect and Analyze (match, new, ask, unknown), run labels
//! (set, edited, escaped, in the report and its file name), the sidebar
//! switcher's states, Default shown as its domains, and the demo's own
//! environment.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_ui::environments::{Registry, DEFAULT_ENV, REGISTRY_FILE};
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::Value;
use tower::ServiceExt;

const PORT: u16 = 4248;
const HOST: &str = "127.0.0.1:4248";

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

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-labels-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn app_in(dir: PathBuf) -> App {
    let ws = Workspace::open(&dir).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), PORT));
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

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
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

    async fn form(&self, uri: &str, fields: &[(&str, &str)]) -> (StatusCode, String, String) {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, format!("http://{HOST}"));
        let (s, h, b) = self.send(req.body(Body::from(body)).unwrap()).await;
        let loc = h
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (s, loc, b)
    }

    /// A multipart POST of text fields, and (name, file name, bytes) files.
    async fn multipart(
        &self,
        uri: &str,
        fields: &[(&str, &str)],
        files: &[(&str, &str, &[u8])],
    ) -> (StatusCode, String) {
        let boundary = "labelsTestBoundary";
        let mut body: Vec<u8> = Vec::new();
        for (k, v) in fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        for (k, name, bytes) in files {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = self
            .request(Method::POST, uri)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, b)
    }

    /// Two minutes at most: the demo's first run analyzes its earlier runs
    /// too.
    async fn wait(&self, job: &str) -> Value {
        for _ in 0..2400 {
            let (_, body) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            if !matches!(v["status"].as_str(), Some("running" | "collecting")) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    /// Analyzes a path with the Analyze form's other fields; the run.
    async fn analyze(&self, path: PathBuf, fields: &[(&str, &str)]) -> String {
        let p = path.display().to_string();
        let mut all = vec![("path", p.as_str()), ("force", "1")];
        all.extend_from_slice(fields);
        let (s, b) = self.multipart("/api/analyze", &all, &[]).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        let v = self.wait(&job).await;
        assert_eq!(v["status"], "done", "{v}");
        v["run"].as_str().unwrap().to_string()
    }

    async fn demo(&self) -> String {
        let req = self
            .request(Method::POST, "/api/demo")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::empty())
            .unwrap();
        let (s, _, b) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        let v = self.wait(&job).await;
        assert_eq!(v["status"], "done", "{v}");
        v["run"].as_str().unwrap().to_string()
    }

    /// The "where" block for these fields.
    async fn place(&self, fields: &[(&str, &str)], files: &[(&str, &str, &[u8])]) -> Value {
        let (s, b) = self.multipart("/api/analyze/where", fields, files).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        serde_json::from_str(&b).unwrap()
    }

    fn summary(&self, run: &str) -> pathwarden_ui::workspace::RunSummary {
        self.state.workspace.summary(run).unwrap()
    }
}

/// The switcher before anything, with only the demo, and after the first
/// real run; the demo has its own environment and never mixes with real
/// runs; Default shows as its domains.
#[tokio::test]
async fn switcher_states_and_the_demo() {
    let a = app_in(fresh("switcher"));
    let (_, home) = a.get("/").await;
    assert!(home.contains(r#"<span class="es-name es-none">No environment yet</span>"#));
    assert!(home.contains("Your first collection creates one, named after its domain."));
    assert!(home.contains(">Manage environments<"));
    assert!(!home.contains(">Default<"));

    // The demo: its own environment, current.
    let demo = a.demo().await;
    let reg = Registry::load(a.state.workspace.root());
    let demo_env = reg.demo_id().unwrap().to_string();
    assert_eq!(a.state.env_id(), demo_env);
    assert_eq!(
        a.summary(&demo).environment.as_deref(),
        Some(demo_env.as_str())
    );
    let (_, home) = a.get("/").await;
    assert!(
        home.contains(r#"<span class="es-name">Demo</span>"#),
        "{home}"
    );
    assert!(home.contains("it never mixes with the demo"));
    assert!(home.contains(r#"<span class="tag demo">Demo</span>"#));

    // The first real run: its own environment, named after its domains
    // (Default takes the name), and the app switches to it.
    let real = a.analyze(repo("testdata/forest"), &[]).await;
    let (_, _) = a.get(&format!("/api/jobs/{real}")).await;
    assert_eq!(a.state.env_id(), DEFAULT_ENV);
    let (_, runs) = a.get("/runs").await;
    assert!(runs.contains(r#"<span class="es-name">CONTOSO.LOCAL +1</span>"#));
    assert!(runs.contains(">Switch to<"));
    assert!(
        !runs.contains(&demo),
        "the demo run is not listed with real runs"
    );
    // The demo's domain never matches the demo's environment.
    let v = a.place(&[("domain", "SCALE.LOCAL")], &[]).await;
    assert_eq!(v["state"], "new", "{v}");
    let _ = std::fs::remove_dir_all(a.dir.join("unused"));
}

/// A workspace with a demo run from before the demo had its own
/// environment: the run moves there (in the registry only), its file
/// untouched.
#[tokio::test]
async fn an_old_demo_run_moves_to_the_demo_environment() {
    let dir = fresh("olddemo");
    let rdir = dir.join("runs").join("20261002-055320-abcdef");
    std::fs::create_dir_all(&rdir).unwrap();
    let summary = r#"{"id":"20261002-055320-abcdef","created_at":1791000000,"collected_at":null,
        "source":"Demo data","demo":true,"domains":["SCALE.LOCAL"],"objects":1,"files":1,
        "exposure_percent":12.5,"exposed":1,"population":8,"protection_score":null,
        "critical":0,"high":1,"medium":0,"low":0,"info":0,"suppressed":0,
        "plan_steps":0,"pathwarden":"0.1.0"}"#;
    std::fs::write(rdir.join("summary.json"), summary).unwrap();
    std::fs::write(rdir.join("report.html"), "<html></html>").unwrap();
    let a = app_in(dir.clone());
    let reg = Registry::load(&dir);
    let demo = reg.demo_id().expect("a Demo environment").to_string();
    assert_eq!(reg.get(&demo).unwrap().name, "Demo");
    assert!(a.state.ws().runs().is_empty(), "not Default's any more");
    assert_eq!(a.state.workspace.in_env(&demo).runs().len(), 1);
    assert_eq!(
        std::fs::read_to_string(rdir.join("summary.json")).unwrap(),
        summary
    );
    // Without demo runs, nothing is written by starting.
    let plain = fresh("nodemo");
    let _b = app_in(plain.clone());
    assert!(!plain.join(REGISTRY_FILE).exists());
}

/// The block on Collect and Analyze, for each case; Analyze reads the
/// domains from domains files (sent by the browser) or a path.
#[tokio::test]
async fn where_a_run_goes_before_it_starts() {
    let a = app_in(fresh("where"));
    // Nothing yet: a new environment, named after the domain.
    let v = a.place(&[("domain", "contoso.com")], &[]).await;
    assert_eq!(v["state"], "new");
    assert!(
        v["html"]
            .as_str()
            .unwrap()
            .contains("Saving to a new environment <strong>CONTOSO.COM</strong>"),
        "{v}"
    );
    assert_eq!(v["computed"], "CONTOSO.COM");
    a.analyze(repo("testdata/forest"), &[]).await;
    // A match: one line, the cards hidden until "change".
    let v = a
        .place(
            &[
                ("domain", "CONTOSO.LOCAL"),
                ("domain", "child.contoso.local"),
            ],
            &[],
        )
        .await;
    assert_eq!(v["state"], "match");
    let html = v["html"].as_str().unwrap();
    assert!(
        html.contains("Saving to <strong>CONTOSO.LOCAL +1</strong>"),
        "{html}"
    );
    assert!(
        html.contains("it lists CHILD.CONTOSO.LOCAL and CONTOSO.LOCAL"),
        "{html}"
    );
    assert!(html.contains(r#"<fieldset class="env-pick" id="ew-cards" hidden>"#));
    assert!(html.contains(r#"value="env:default" checked"#));
    // One more domain, which no environment has: it joins the one that
    // has the other.
    let v = a
        .place(
            &[("domain", "CONTOSO.LOCAL"), ("domain", "BRAAVOS.LOCAL")],
            &[],
        )
        .await;
    assert_eq!(v["state"], "match");
    let html = v["html"].as_str().unwrap();
    assert!(
        html.contains("Saving to <strong>CONTOSO.LOCAL +1</strong>"),
        "{html}"
    );
    assert!(
        html.contains("it has the other domains; the new ones join it"),
        "{html}"
    );
    // Analyze: the domains file of an upload, as the browser sends it.
    let domains = std::fs::read(repo(
        "testdata/rusthound/20261011195626_essos-local_domains.json",
    ))
    .unwrap();
    let v = a
        .place(&[("files", "1")], &[("domains", "domains.json", &domains)])
        .await;
    assert_eq!(v["state"], "new");
    assert!(v["found"]
        .as_str()
        .unwrap()
        .contains("Found in these files"));
    assert!(v["found"]
        .as_str()
        .unwrap()
        .contains(r#"<span class="dom-chip is-collected">ESSOS.LOCAL</span>"#));
    // Or a path on this computer.
    let p = repo("testdata/forest").display().to_string();
    let v = a.place(&[("path", &p)], &[]).await;
    assert_eq!(v["state"], "match");
    // Files without a domains file: decided from the data, later.
    let v = a.place(&[("files", "1")], &[]).await;
    assert_eq!(v["state"], "unknown");
    assert!(v["found"]
        .as_str()
        .unwrap()
        .contains("Domains not read yet"));
    // The pages: no Automatic dropdown, the block and the label field.
    let (_, page) = a.get("/analyze").await;
    assert!(page.contains(r#"<div class="env-where" id="ew" data-state="unknown">"#));
    assert!(page.contains(r#"<input type="text" id="run-label" name="label" maxlength="60""#));
    let (_, page) = a.get("/collect").await;
    assert!(page.contains(r#"<div class="env-where" id="ew" data-state="loading"></div>"#));
    assert!(page.contains(r#"id="run-label""#));
    // A new environment by the name typed; a name taken is refused.
    let run = a
        .analyze(repo("testdata/sdprop"), &[("new_env", "Lab <1>")])
        .await;
    let s = a.summary(&run);
    let reg = Registry::load(a.state.workspace.root());
    assert_eq!(reg.name_of(s.environment.as_deref().unwrap()), "Lab <1>");
    assert_eq!(s.assigned.as_deref(), Some("chosen"));
    let p = repo("testdata/sdprop").display().to_string();
    let (st, b) = a
        .multipart("/api/analyze", &[("path", &p), ("new_env", "lab <1>")], &[])
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(b.contains("already an environment named"), "{b}");
    // The page's own choice yields to the data's domains (env_auto).
    let run = a
        .analyze(
            repo("testdata/forest"),
            &[("new_env", "Something else"), ("env_auto", "1")],
        )
        .await;
    let s = a.summary(&run);
    assert_eq!(s.environment, None);
    assert_eq!(s.assigned.as_deref(), Some("domains"));
}

/// The page's own choice (closed cards: `env_auto`) never settles
/// something that's off: the data asks; Discard deletes what waits.
#[tokio::test]
async fn a_page_choice_never_settles_something_off() {
    let dir = fresh("auto");
    let a = app_in(dir.clone());
    // ESSOS.LOCAL is GOAD lab's and SEVENKINGDOMS.LOCAL is Kings's: the
    // data has both, so something is off.
    let essos = repo("testdata/rusthound/20261011195626_essos-local_domains.json");
    let essos_users = repo("testdata/rusthound/20261011195626_essos-local_users.json");
    let p = essos.display().to_string();
    let pu = essos_users.display().to_string();
    let (s, b) = a
        .multipart(
            "/api/analyze",
            &[
                ("path", &p),
                ("path", &pu),
                ("new_env", "GOAD lab"),
                ("force", "1"),
            ],
            &[],
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(a.wait(&job).await["status"], "done");
    Registry::update(&dir, |r| {
        r.create("Kings", &["SEVENKINGDOMS.LOCAL".to_string()])
    })
    .unwrap();
    let both = repo("testdata/rusthound").display().to_string();
    for (field, value) in [("env", "default"), ("new_env", "Somewhere")] {
        let runs_before = a.state.workspace.all_runs().len();
        let (s, b) = a
            .multipart(
                "/api/analyze",
                &[
                    ("path", &both),
                    (field, value),
                    ("env_auto", "1"),
                    ("force", "1"),
                ],
                &[],
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string();
        let v = a.wait(&job).await;
        assert_eq!(v["status"], "ask", "{field}: {v}");
        assert_eq!(
            a.state.workspace.all_runs().len(),
            runs_before,
            "nothing saved"
        );
        // Discard: the waiting analysis is gone.
        let req = a
            .request(Method::POST, &format!("/api/jobs/{job}/discard"))
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::empty())
            .unwrap();
        let (s, _, _) = a.send(req).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = a.get(&format!("/api/jobs/{job}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    let (_, page) = a.get("/analyze").await;
    assert!(page.contains(r#"id="ask-discard""#));
}

/// A Default with settings (or history) of its own is never hidden or
/// taken over; a registry that can't be read is shown as an error and never
/// written over.
#[tokio::test]
async fn a_default_with_settings_and_a_broken_registry() {
    let dir = fresh("used");
    std::fs::write(dir.join("pathwarden.toml"), "tier_zero = []\n").unwrap();
    let a = app_in(dir.clone());
    a.analyze(repo("testdata/forest"), &[]).await;
    let reg = Registry::load(&dir);
    let new = reg.environments.iter().find(|e| !e.is_default()).unwrap();
    assert_eq!(new.name, "CONTOSO.LOCAL +1", "a new one, not Default");
    assert_eq!(reg.get(DEFAULT_ENV).unwrap().name, "Default");
    let (_, page) = a.get("/environments").await;
    assert!(page.contains(r#"id="env-default""#), "Default is listed");
    // Rename it to the name it shows as: it stays unrenamed.
    let (st, _, _) = a
        .form(
            "/environments/default/rename",
            &[("name", "No environment yet")],
        )
        .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(
        Registry::load(&dir).get(DEFAULT_ENV).unwrap().name,
        "Default"
    );
    // A taken name, asked for as JSON (the page's script): the reason.
    let req = a
        .request(Method::POST, "/environments/default/rename")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::ORIGIN, format!("http://{HOST}"))
        .body(Body::from("name=CONTOSO.LOCAL+%2B1"))
        .unwrap();
    let (st, _, b) = a.send(req).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(b.contains("already an environment named"), "{b}");
    // Broken registry: the page says so, changes fail, the file stays.
    std::fs::write(dir.join(REGISTRY_FILE), "{broken").unwrap();
    let (_, page) = a.get("/environments").await;
    assert!(page.contains("can&#39;t be read"), "{page}");
    let (st, _, _) = a
        .form("/environments", &[("name", "Lab"), ("domains", "")])
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let p = repo("testdata/sdprop").display().to_string();
    let (s, b) = a
        .multipart("/api/analyze", &[("path", &p), ("force", "1")], &[])
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let job = serde_json::from_str::<Value>(&b).unwrap()["job"]
        .as_str()
        .unwrap()
        .to_string();
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "failed", "{v}");
    assert_eq!(
        std::fs::read_to_string(dir.join(REGISTRY_FILE)).unwrap(),
        "{broken"
    );
}

/// Labels: set on Analyze, edited in the list and on the run page,
/// escaped everywhere, in the report's title and its file name.
#[tokio::test]
async fn run_labels_are_set_edited_and_shown() {
    let a = app_in(fresh("label"));
    let run = a
        .analyze(
            repo("testdata/forest"),
            &[("label", " <b>before</b> & after ")],
        )
        .await;
    let s = a.summary(&run);
    assert_eq!(s.label.as_deref(), Some("<b>before</b> & after"));
    let (_, runs) = a.get("/runs").await;
    assert!(runs.contains(r#"<a class="rr-link" href="/runs/"#));
    assert!(
        runs.contains("&lt;b&gt;before&lt;/b&gt; &amp; after</a>"),
        "{runs}"
    );
    assert!(runs.contains(r#"<span class="rr-dom">CONTOSO.LOCAL +1</span>"#));
    assert!(!runs.contains("<b>before</b>"));
    assert!(runs.contains(&format!(r#"action="/runs/{run}/label""#)));
    let (_, page) = a.get(&format!("/runs/{run}")).await;
    assert!(page.contains(r#"<h1 class="panel-title">&lt;b&gt;before&lt;/b&gt; &amp; after</h1>"#));
    assert!(page.contains("Empty shows CONTOSO.LOCAL +1."));
    // The report: the label in its title and rail, and the file name.
    let (_, h, report) = a
        .send(
            a.request(Method::GET, &format!("/runs/{run}/report?download=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(report.contains(
        "<title>Pathwarden report: &lt;b&gt;before&lt;/b&gt; &amp; after (CHILD.CONTOSO.LOCAL, CONTOSO.LOCAL)</title>"
    ));
    assert!(report.contains("<dt>Run</dt><dd>&lt;b&gt;before&lt;/b&gt; &amp; after</dd>"));
    let cd = h
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        cd,
        r#"attachment; filename="pathwarden-CONTOSO.LOCAL-1-b-before-b-after.html""#
    );
    // Edited from the list: back to the list; the history gets it too.
    let (st, loc, _) = a
        .form(
            &format!("/runs/{run}/label"),
            &[("label", "after GPO fix"), ("back", "/runs")],
        )
        .await;
    assert_eq!((st, loc.as_str()), (StatusCode::SEE_OTHER, "/runs"));
    assert_eq!(a.summary(&run).label.as_deref(), Some("after GPO fix"));
    let (_, h, _) = a
        .send(
            a.request(Method::GET, &format!("/runs/{run}/report?download=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(h
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("pathwarden-CONTOSO.LOCAL-1-after-gpo-fix.html"));
    let (_, progress) = a.get("/progress").await;
    assert!(
        progress.contains(r#"<span class="pv-label">after GPO fix</span>"#),
        "{progress}"
    );
    // Too long, or a control character: refused, nothing changed.
    for bad in ["x".repeat(61), "a\u{1b}b".to_string()] {
        let (st, _, _) = a
            .form(&format!("/runs/{run}/label"), &[("label", &bad)])
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    assert_eq!(a.summary(&run).label.as_deref(), Some("after GPO fix"));
    // Cleared: the computed name again; the run page is where it goes back.
    let (st, loc, _) = a
        .form(&format!("/runs/{run}/label"), &[("label", "")])
        .await;
    assert_eq!((st, loc), (StatusCode::SEE_OTHER, format!("/runs/{run}")));
    assert_eq!(a.summary(&run).label, None);
    let (_, h, _) = a
        .send(
            a.request(Method::GET, &format!("/runs/{run}/report?download=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(h
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("pathwarden-CONTOSO.LOCAL-1-2026-"));
    // A label for a run the history has (a CLI or scheduled run).
    let history_id = a.summary(&run).history.unwrap().run_id.unwrap();
    let (st, loc, _) = a
        .form(
            &format!("/history/{history_id}/label"),
            &[("label", "nightly")],
        )
        .await;
    assert_eq!((st, loc.as_str()), (StatusCode::SEE_OTHER, "/runs"));
    let labels = pathwarden_ui::workspace::later_labels(&a.state.ws());
    assert_eq!(labels.get(&history_id).map(String::as_str), Some("nightly"));
    let (st, _, _) = a.form("/history/..%2Fx/label", &[("label", "x")]).await;
    assert_ne!(st, StatusCode::SEE_OTHER);
}

/// Environments page: Default never shows by that name, and renames in
/// place.
#[tokio::test]
async fn environments_rename_in_place() {
    let a = app_in(fresh("rename"));
    a.analyze(repo("testdata/forest"), &[]).await;
    let (_, page) = a.get("/environments").await;
    assert!(page.contains("<h2>CONTOSO.LOCAL +1</h2>"), "{page}");
    assert!(page.contains(r#"action="/environments/default/rename""#));
    assert!(!page.contains(r#"<span class="tag">Default</span>"#));
    let (st, loc, _) = a
        .form("/environments/default/rename", &[("name", "GOAD lab")])
        .await;
    assert_eq!(
        (st, loc.as_str()),
        (StatusCode::SEE_OTHER, "/environments#env-default")
    );
    let reg = Registry::load(a.state.workspace.root());
    assert_eq!(reg.get(DEFAULT_ENV).unwrap().name, "GOAD lab");
    assert_eq!(
        reg.get(DEFAULT_ENV).unwrap().domains,
        ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"],
        "the domains stay"
    );
    let (st, _, body) = a
        .form("/environments/default/rename", &[("name", "")])
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(body.contains("Enter a name"));
}
