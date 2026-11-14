//! Environments end to end, through the router: a workspace from before
//! environments migrates as Default with nothing changed, the switcher
//! scopes every page, analyses are assigned by domain or by choice, and one
//! environment's accepted risks and ticketing never reach another's runs.

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

const PORT: u16 = 4246;
const HOST: &str = "127.0.0.1:4246";

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
    let dir = std::env::temp_dir().join(format!("pathwarden-envs-{name}-{}", std::process::id()));
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

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else if b == b' ' {
                "+".into()
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

    /// Posts an HTML form (as the Environments page and the switcher do).
    /// Returns the status, the `Location` and the body.
    async fn form(
        &self,
        uri: &str,
        fields: &[(&str, &str)],
        referer: Option<&str>,
    ) -> (StatusCode, String, String) {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, format!("http://{HOST}"));
        if let Some(r) = referer {
            req = req.header(header::REFERER, format!("http://{HOST}{r}"));
        }
        let (s, h, b) = self.send(req.body(Body::from(body)).unwrap()).await;
        let loc = h
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (s, loc, b)
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

    /// Creates an environment (and switches to it, as the page does).
    async fn create(&self, name: &str, domains: &str) -> String {
        let (s, loc, b) = self
            .form(
                "/environments",
                &[("name", name), ("domains", domains), ("copy", "")],
                None,
            )
            .await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{b}");
        assert!(loc.starts_with("/environments#env-"), "{loc}");
        loc.trim_start_matches("/environments#env-").to_string()
    }

    async fn switch(&self, id: &str) {
        let (s, _, b) = self
            .form(
                &format!("/environments/switch?to={id}"),
                &[],
                Some("/settings"),
            )
            .await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{b}");
        assert_eq!(self.state.env_id(), id);
    }

    /// Posts a multipart form; returns the status and the body.
    async fn multipart(&self, uri: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
        let boundary = "envTestBoundary";
        let mut body = String::new();
        for (k, v) in fields {
            body += &format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
            );
        }
        body += &format!("--{boundary}--\r\n");
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

    /// Starts an analysis of a folder by path, with the Analyze form's
    /// other fields (`env`, `new_env`, `env_auto`, `label`).
    async fn start(&self, path: PathBuf, fields: &[(&str, &str)]) -> String {
        let p = path.display().to_string();
        let mut all = vec![("path", p.as_str())];
        all.extend_from_slice(fields);
        // Each analysis is new data, not "already analyzed".
        all.push(("force", "1"));
        let (s, b) = self.multipart("/api/analyze", &all).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Waits until a job is done, stopped or failed; its status.
    async fn wait(&self, job: &str) -> Value {
        for _ in 0..600 {
            let (_, body) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            if !matches!(v["status"].as_str(), Some("running" | "collecting")) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    /// Analyzes a folder by path (`env`: the Analyze page's choice) and
    /// waits for the run.
    async fn analyze(&self, path: PathBuf, env: Option<&str>) -> String {
        let fields: Vec<(&str, &str)> = env.map(|e| ("env", e)).into_iter().collect();
        let job = self.start(path, &fields).await;
        let v = self.wait(&job).await;
        assert_eq!(v["status"], "done", "{v}");
        v["run"].as_str().unwrap().to_string()
    }

    fn summary(&self, run: &str) -> pathwarden_ui::workspace::RunSummary {
        self.state.workspace.summary(run).unwrap()
    }
}

const OLD_CONFIG: &str = "# my settings\n[[suppress]]\nfingerprint = \"PW-003-39f2ede7c479090b\"\nreason = \"Reviewed (CHG1)\"\n";

/// A workspace from before environments: its config, history and runs are
/// the Default environment's, untouched, and every address still works.
#[tokio::test]
async fn an_existing_workspace_is_the_default_environment() {
    let dir = fresh("migrate");
    std::fs::write(dir.join("pathwarden.toml"), OLD_CONFIG).unwrap();
    // A run saved by an earlier version (no `environment`).
    let run = "20261002-055320-abcdef";
    let rdir = dir.join("runs").join(run);
    std::fs::create_dir_all(&rdir).unwrap();
    let summary = r#"{"id":"20261002-055320-abcdef","created_at":1791000000,"collected_at":null,
        "source":"x.zip","demo":false,"domains":["CHILD.CONTOSO.LOCAL","CONTOSO.LOCAL"],"objects":1,"files":1,
        "exposure_percent":12.5,"exposed":1,"population":8,"protection_score":null,
        "critical":0,"high":1,"medium":0,"low":0,"info":0,"suppressed":1,
        "plan_steps":0,"pathwarden":"0.1.0"}"#;
    std::fs::write(rdir.join("summary.json"), summary).unwrap();
    std::fs::write(rdir.join("report.html"), "<html><body>old</body></html>").unwrap();
    let a = app_in(dir.clone());

    assert_eq!(a.state.env_id(), DEFAULT_ENV);
    assert_eq!(a.state.ws().config_path(), dir.join("pathwarden.toml"));
    assert_eq!(a.state.ws().runs().len(), 1);
    for uri in [
        "/",
        "/runs",
        &format!("/runs/{run}"),
        &format!("/runs/{run}/report"),
        "/settings",
        "/progress",
        "/automate/history",
        "/environments",
    ] {
        let (s, body) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {body}");
    }
    let (_, settings) = a.get("/settings").await;
    assert!(
        settings.contains("Reviewed (CHG1)"),
        "the old accepted risk shows"
    );
    // Default is never shown by that name: it shows as its domains.
    assert!(
        settings.contains("Environment</span><span class=\"es-name\">CONTOSO.LOCAL +1"),
        "{settings}"
    );
    assert!(!settings.contains(r#"es-name">Default"#));
    let (_, history) = a.get("/automate/history").await;
    assert!(history.contains(&pathwarden_ui::workspace::shown_path(
        &dir.join("pathwarden-state")
    )));
    // Nothing was rewritten or added by looking.
    assert_eq!(
        std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap(),
        OLD_CONFIG
    );
    assert_eq!(
        std::fs::read_to_string(rdir.join("summary.json")).unwrap(),
        summary
    );
    assert!(!dir.join(REGISTRY_FILE).exists());
    assert!(!dir.join("environments").exists());

    // A new analysis of the same collection in the migrated workspace
    // gives the same result as before environments: Default's settings
    // apply, matched by its run's domains.
    let new = a.analyze(testdata("forest"), None).await;
    let s = a.summary(&new);
    assert_eq!(s.environment, None, "Default is not written into summaries");
    assert_eq!(s.assigned.as_deref(), Some("runs"));
    assert_eq!(s.suppressed, 1, "the old accepted risk applied");
    // The old run's files are as they were.
    assert_eq!(
        std::fs::read_to_string(rdir.join("summary.json")).unwrap(),
        summary
    );
}

/// The switcher scopes the pages; creating, renaming and removing
/// environments works from the Environments page.
#[tokio::test]
async fn the_switcher_scopes_every_page() {
    let a = app_in(fresh("switch"));
    let (_, home) = a.get("/").await;
    assert!(home.contains(r#"<span class="es-name es-none">No environment yet</span>"#));
    assert!(home.contains("Your first collection creates one, named after its domain."));
    // The first run's domains name the (until then unused) Default.
    let default_run = a.analyze(testdata("forest"), None).await;
    assert_eq!(a.summary(&default_run).assigned.as_deref(), Some("new"));
    let reg = Registry::load(a.state.workspace.root());
    assert_eq!(reg.get(DEFAULT_ENV).unwrap().name, "CONTOSO.LOCAL +1");
    assert_eq!(
        reg.get(DEFAULT_ENV).unwrap().domains,
        ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"]
    );

    let lab = a.create("Lab", "").await;
    assert_eq!(lab, "lab");
    assert_eq!(a.state.env_id(), "lab", "a new environment becomes current");
    assert!(a.state.workspace.root().join("environments/lab").is_dir());

    // Lab has no runs, settings of its own, and its own history folder.
    let (_, home) = a.get("/").await;
    assert!(
        home.contains("<strong>Lab</strong> has no runs yet"),
        "{home}"
    );
    assert!(home.contains(r#"<span class="es-name">Lab</span>"#));
    assert!(home.contains(r#"formaction="/environments/switch?to=default""#));
    let (_, runs) = a.get("/runs").await;
    assert!(
        !runs.contains(&default_run),
        "Default's run is not listed in Lab"
    );
    let (_, settings) = a.get("/settings").await;
    let lab_dir = a.state.workspace.root().join("environments").join("lab");
    assert!(settings.contains(&pathwarden_ui::workspace::shown_path(
        &lab_dir.join("pathwarden.toml")
    )));
    let (_, history) = a.get("/automate/history").await;
    assert!(history.contains(&pathwarden_ui::workspace::shown_path(
        &lab_dir.join("pathwarden-state")
    )));
    let (_, schedule) = a.get("/automate/schedule?os=windows").await;
    assert!(
        schedule.contains("Pathwarden-lab"),
        "its own scheduled task"
    );
    assert!(schedule.contains(r"C:\Pathwarden\lab"));
    let (_, analyze) = a.get("/analyze").await;
    assert!(analyze.contains(r#"<div class="env-where" id="ew" data-state="unknown">"#));
    assert!(!analyze.contains("env-choice"), "no Automatic dropdown");

    // Its run page is still reachable, and says which environment it is in.
    let (s, page) = a.get(&format!("/runs/{default_run}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains("This run is in <strong>CONTOSO.LOCAL +1</strong>"),
        "{page}"
    );
    assert!(page.contains(r#"<a class="rh-env" href="/environments#env-default""#));

    // Switching goes back to the page it came from; a run of another
    // environment goes to the run list.
    let (s, loc, _) = a
        .form(
            "/environments/switch?to=default",
            &[],
            Some("/settings?x=1"),
        )
        .await;
    assert_eq!((s, loc.as_str()), (StatusCode::SEE_OTHER, "/settings"));
    // Explore's menu keeps its Forest view, and only that query.
    for (then, to) in [
        ("%2Fexplore%3Fview%3Dforest", "/explore?view=forest"),
        ("/explore?view=forest", "/explore?view=forest"),
        ("%2Fexplore%3Fnext%3D%2F%2Fevil", "/"),
    ] {
        let (_, loc, _) = a
            .form(
                &format!("/environments/switch?to=default&then={then}"),
                &[],
                None,
            )
            .await;
        assert_eq!(loc, to, "{then}");
    }
    let (_, loc, _) = a
        .form(
            "/environments/switch?to=lab",
            &[],
            Some(&format!("/runs/{default_run}")),
        )
        .await;
    assert_eq!(loc, "/runs");
    let (_, loc, _) = a
        .form(
            "/environments/switch?to=default",
            &[],
            Some(&format!("/runs/{default_run}/explore")),
        )
        .await;
    assert_eq!(loc, format!("/runs/{default_run}/explore"));
    // Never anywhere else.
    let (_, loc, _) = a
        .form(
            "/environments/switch?to=default",
            &[],
            Some("//evil.example/x"),
        )
        .await;
    assert_eq!(loc, "/");
    // Explore's environment menu says where to go after: a path on this
    // site only, else back as usual.
    let (_, loc, _) = a
        .form(
            "/environments/switch?to=lab&then=/explore",
            &[],
            Some(&format!("/runs/{default_run}/explore")),
        )
        .await;
    assert_eq!(loc, "/explore");
    for bad in [
        "//evil.example/x",
        "https://evil.example/",
        "/\\evil",
        "explore",
    ] {
        let (_, loc, _) = a
            .form(
                &format!("/environments/switch?to=default&then={}", urlencode(bad)),
                &[],
                Some("/settings"),
            )
            .await;
        assert_eq!(loc, "/settings", "{bad}");
    }
    let (s, _, _) = a.form("/environments/switch?to=nope", &[], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // The choice is remembered for the next start.
    assert_eq!(
        Registry::load(a.state.workspace.root()).current.as_deref(),
        Some(DEFAULT_ENV)
    );

    // Rename, a duplicate name, and remove.
    let (s, _, _) = a
        .form(
            "/environments/lab/edit",
            &[("name", "Lab 2"), ("domains", "lab.local, x.lab.local")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let reg = Registry::load(a.state.workspace.root());
    assert_eq!(reg.get("lab").unwrap().name, "Lab 2");
    assert_eq!(
        reg.get("lab").unwrap().domains,
        ["LAB.LOCAL", "X.LAB.LOCAL"]
    );
    let (s, _, body) = a
        .form("/environments", &[("name", "lab 2"), ("domains", "")], None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("already an environment named"), "{body}");
    // Removing asks first: the page says what goes, and the name must be
    // typed. Lab's files are kept in environments/removed.
    std::fs::write(lab_dir.join("pathwarden.toml"), "tier_zero = []\n").unwrap();
    let (s, page) = a.get("/environments/lab/remove").await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Remove Lab 2?"), "{page}");
    assert!(
        page.contains("Goes: no runs and its settings, run history and labels ("),
        "{page}"
    );
    assert!(page.contains("Type Lab 2 to confirm"), "{page}");
    let key = runs_key(&page);
    for typed in ["", "Lab 3"] {
        let (s, _, b) = a
            .form(
                "/environments/lab/remove",
                &[("confirm", typed), ("runs_key", &key)],
                None,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(
            b.contains("the name typed doesn&#39;t match")
                || b.contains("the name typed doesn't match"),
            "{b}"
        );
        assert!(lab_dir.exists());
    }
    let (s, loc, b) = a
        .form(
            "/environments/lab/remove",
            &[("confirm", "lab 2"), ("runs_key", &key)],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{b}");
    assert!(loc.starts_with("/environments?removed=lab-"), "{loc}");
    let (_, page) = a.get(&loc).await;
    assert!(page.contains("Removed Lab 2: its files"), "{page}");
    assert!(Registry::load(a.state.workspace.root())
        .get("lab")
        .is_none());
    assert!(!lab_dir.exists());
    let removed = a.state.workspace.root().join("environments/removed");
    assert_eq!(std::fs::read_dir(removed).unwrap().count(), 1);
    let (s, _, _) = a
        .form("/environments/lab/remove", &[("confirm", "lab")], None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "gone");
}

/// The runs key a confirmation page carries.
fn runs_key(page: &str) -> String {
    let at = page.find(r#"name="runs_key" value=""#).expect("a runs key") + 23;
    page[at..].split('"').next().unwrap().to_string()
}

/// The first environment, with its run, and while current: it goes like
/// any other (its files out of the workspace folder) and the app switches
/// to the one left; removing that one too leaves "No environment yet".
#[tokio::test]
async fn the_first_and_the_last_environment_can_be_removed() {
    let a = app_in(fresh("remove-first"));
    let first = a.analyze(testdata("forest"), None).await;
    let lab = a.create("Lab", "").await;
    let lab_run = a.analyze(testdata("forest"), Some(&lab)).await;
    a.switch(DEFAULT_ENV).await;
    let root = a.state.workspace.root().to_path_buf();
    assert!(root.join("pathwarden-state").is_dir());
    let (_, page) = a.get("/environments/default/remove").await;
    assert!(
        page.contains("Remove CONTOSO.LOCAL +1 and its run"),
        "{page}"
    );
    assert!(
        page.contains("It is the first environment")
            || page.contains("It is the first environment:"),
        "{page}"
    );
    assert!(page.contains("the app switches to Lab"), "{page}");
    assert!(page.contains("task Pathwarden,"), "{page}");
    // The runs changed since the page was shown: not removed.
    let (s, _, b) = a
        .form(
            "/environments/default/remove",
            &[("confirm", "default"), ("runs_key", "stale")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(b.contains("changed since you confirmed"), "{b}");
    let (s, _, b) = a
        .form(
            "/environments/default/remove",
            &[("confirm", "default"), ("runs_key", &runs_key(&page))],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{b}");
    assert_eq!(a.state.env_id(), lab);
    assert!(a.state.workspace.summary(&first).is_none());
    assert!(!root.join("pathwarden-state").exists());
    assert!(a.state.workspace.summary(&lab_run).is_some());
    let (_, page) = a.get("/environments").await;
    assert!(
        !page.contains(r#"id="env-default""#),
        "the first environment starts over, unlisted"
    );
    // The last one.
    let (_, page) = a.get(&format!("/environments/{lab}/remove")).await;
    assert!(
        page.contains("the app then shows No environment yet"),
        "{page}"
    );
    let (s, _, _) = a
        .form(
            &format!("/environments/{lab}/remove"),
            &[("confirm", "Lab"), ("runs_key", &runs_key(&page))],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(a.state.env_id(), DEFAULT_ENV);
    let (_, home) = a.get("/").await;
    assert!(home.contains(r#"<span class="es-name es-none">No environment yet</span>"#));
    assert!(a.state.workspace.all_runs().is_empty());
    // A new run starts a fresh environment again.
    a.analyze(testdata("forest"), None).await;
    assert_eq!(a.state.workspace.all_runs().len(), 1);
}

/// One environment's accepted risks and ticketing never apply to another's
/// runs, whichever is current; analyses go to the environment chosen, or
/// to the one their domains belong to.
#[tokio::test]
async fn settings_never_cross_environments() {
    let dir = fresh("isolation");
    // Default accepts a risk and has a ticketing plugin.
    std::fs::write(
        dir.join("pathwarden.toml"),
        format!(
            "{OLD_CONFIG}\n[[output]]\nplugin = \"servicenow\"\ninstance = \"https://contoso.service-now.com\"\n"
        ),
    )
    .unwrap();
    let a = app_in(dir.clone());
    // Default has settings of its own: a run goes there only when picked
    // (by domain, it would get an environment of its own).
    let default_run = a.analyze(testdata("forest"), Some("default")).await;
    assert_eq!(a.summary(&default_run).suppressed, 1);

    // Client A: same data, chosen explicitly, from Default.
    let client = a.create("Client A", "").await;
    a.switch(DEFAULT_ENV).await;
    let client_run = a.analyze(testdata("forest"), Some(&client)).await;
    let s = a.summary(&client_run);
    assert_eq!(s.environment.as_deref(), Some(client.as_str()));
    assert_eq!(s.assigned.as_deref(), Some("chosen"));
    assert_eq!(s.suppressed, 0, "Default's accepted risk did not apply");
    assert_eq!(a.state.env_id(), DEFAULT_ENV, "analyzing doesn't switch");
    // Recorded in Client A's own history, not Default's.
    let client_state = dir
        .join("environments")
        .join(&client)
        .join("pathwarden-state");
    assert!(client_state.join("history").is_dir());
    let default_points = std::fs::read_dir(dir.join("pathwarden-state/history"))
        .unwrap()
        .count();
    assert_eq!(default_points, 1);

    // The run page (viewed from Default) shows Client A's settings: the
    // finding is not "already accepted" there.
    let (_, page) = a.get(&format!("/runs/{client_run}")).await;
    assert!(page.contains(
        "This run is in <strong>Client A</strong>, so its retests and accepted risks use the settings of Client A."
    ));
    // What the next analysis applies is on its Run details tab.
    let (_, details) = a.get(&format!("/runs/{client_run}/report?embed=1")).await;
    assert!(details.contains("The next analysis applies (Client A): the default settings"));
    let (_, page) = a.get(&format!("/runs/{default_run}/report?embed=1")).await;
    assert!(page.contains("1 accepted risk"), "{page}");
    // Accepting a risk on Client A's run page writes Client A's config,
    // even with Default current.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress",
            serde_json::json!({
                "index": null,
                "run": client_run,
                "risk": {"fingerprint": "PW-006-8ae0b31a46eacada", "reason": "Client A only", "expires": null}
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let client_cfg = std::fs::read_to_string(
        dir.join("environments")
            .join(&client)
            .join("pathwarden.toml"),
    )
    .unwrap();
    assert!(client_cfg.contains("Client A only"));
    // Accepted from a run page: who accepted it, where and when, as in Settings.
    let parsed = pathwarden_core::config::Config::parse(&client_cfg).unwrap();
    let me = pathwarden_core::identity::Actor::current();
    assert_eq!(parsed.suppress[0].accepted_by, me.user);
    assert_eq!(parsed.suppress[0].accepted_on, me.computer);
    assert!(parsed.suppress[0].accepted_at.is_some());
    // A note from Client A's run page goes to Client A's risk, with Default
    // current.
    let (s, v) = a
        .json(
            Method::POST,
            "/api/settings/suppress/0/note",
            serde_json::json!({
                "run": client_run,
                "expect": "Client A only",
                "expect_target": "PW-006-8ae0b31a46eacada",
                "text": "Noted from the run page."
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let client_cfg = std::fs::read_to_string(
        dir.join("environments")
            .join(&client)
            .join("pathwarden.toml"),
    )
    .unwrap();
    assert!(client_cfg.contains("Noted from the run page."));
    assert!(!std::fs::read_to_string(dir.join("pathwarden.toml"))
        .unwrap()
        .contains("Noted from the run page."));
    let default_cfg = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(!default_cfg.contains("Client A only"));
    assert!(!client_cfg.contains("Reviewed (CHG1)"));

    // Ticketing: Client A has no plugins; Default's stays Default's.
    a.switch(&client).await;
    let (_, ticketing) = a.get("/automate/ticketing").await;
    assert!(
        !ticketing.contains("contoso.service-now.com"),
        "{ticketing}"
    );
    a.switch(DEFAULT_ENV).await;
    let (_, ticketing) = a.get("/automate/ticketing").await;
    assert!(ticketing.contains("contoso.service-now.com"));

    // Automatic: Default lists both domains (its first run named it), and
    // Client A now lists CONTOSO.LOCAL too: something's off, so the
    // analysis asks, and saves nothing.
    let (s, _, _) = a
        .form(
            &format!("/environments/{client}/edit"),
            &[("name", "Client A"), ("domains", "contoso.local")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let runs_before = a.state.workspace.all_runs().len();
    let job = a.start(testdata("forest"), &[]).await;
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "ask", "{v}");
    assert_eq!(
        v["reason"],
        "CHILD.CONTOSO.LOCAL and CONTOSO.LOCAL match CONTOSO.LOCAL +1; CONTOSO.LOCAL matches Client A."
    );
    assert_eq!(
        a.state.workspace.all_runs().len(),
        runs_before,
        "nothing saved"
    );
    // The Analyze page resumes it with the question.
    let (_, page) = a.get(&format!("/analyze?job={job}")).await;
    assert!(page.contains(r#"id="ask-env""#) && page.contains("&quot;ask&quot;"));
    // Picking Client A analyzes the same files into it.
    let (s, b) = a
        .json(
            Method::POST,
            &format!("/api/jobs/{job}/place"),
            serde_json::json!({"env": client}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "done", "{v}");
    let s = a.summary(v["run"].as_str().unwrap());
    assert_eq!(s.environment.as_deref(), Some(client.as_str()));
    assert_eq!(s.assigned.as_deref(), Some("chosen"));
    assert_eq!(s.suppressed, 1, "Client A's own accepted risk applied");
    // Listed for Client A alone, the next one goes there by itself.
    let (s, _, _) = a
        .form(
            "/environments/default/edit",
            &[("name", "Lab"), ("domains", "")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _, _) = a
        .form(
            &format!("/environments/{client}/edit"),
            &[
                ("name", "Client A"),
                ("domains", "contoso.local child.contoso.local"),
            ],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let auto = a.analyze(testdata("forest"), None).await;
    let s = a.summary(&auto);
    assert_eq!(s.environment.as_deref(), Some(client.as_str()));
    assert_eq!(s.assigned.as_deref(), Some("domains"));
    // Default keeps exactly its own runs.
    let ids: Vec<String> = a.state.ws().runs().into_iter().map(|r| r.id).collect();
    assert_eq!(ids, [default_run]);
}

/// An environment stuck with the reserved ID `removed` (its folder
/// holds removals) is said on the Environments page, with why the start
/// couldn't give it another ID.
#[tokio::test]
async fn the_environments_page_says_when_an_old_removed_id_is_stuck() {
    let dir = fresh("stuck-removed");
    std::fs::write(
        dir.join(REGISTRY_FILE),
        r#"{"environments":[{"id":"default","name":"Default"},{"id":"removed","name":"Old removed"}]}"#,
    )
    .unwrap();
    let rec = dir.join("environments/removed/lab-20261001-000000");
    std::fs::create_dir_all(&rec).unwrap();
    std::fs::write(
        rec.join("removal.json"),
        r#"{"id":"lab","name":"Lab","entry":{"id":"lab","name":"Lab"},"started_at":1,"done":true}"#,
    )
    .unwrap();
    // Worked out by the page itself, not only at the start.
    let a = app_in(dir);
    let (s, page) = a.get("/environments").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        page.contains(r#"role="status"><p><strong>Old removed still has the reserved ID"#),
        "{page}"
    );
    assert!(page.contains("<summary>What to do</summary>"), "{page}");
    assert!(page.contains("tries again at each start"), "{page}");
    assert!(page.contains("also holds earlier removals"), "{page}");
    assert!(!page.contains("Nothing was removed"), "{page}");
}

/// Percent-encodes everything but letters, digits and `-_.~`, for a query
/// value.
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
