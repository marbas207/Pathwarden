//! The Automate area and the shared run history through the router: the
//! pages, the schedule from any run, the "already analyzed" warning, runs
//! recorded by a schedule on Runs and Progress, the schedule's report, and
//! earlier runs kept local only.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::analyze::{self, Phase};
use pathwarden_core::config::Config;
use pathwarden_core::record::{self, RecordProgress};
use pathwarden_core::store::Store;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::{json, Value};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4245";

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
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-au-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    // These pages set where the history is kept: as `pathwarden ui --allow-destinations`.
    let mut state = AppState::new(ws, Token::generate().unwrap(), 4245);
    state.allow_destinations = true;
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

impl App {
    fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(&self, uri: &str) -> (StatusCode, HeaderMap, String) {
        self.send(self.request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, String) {
        let req = self
            .request(Method::POST, uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let (s, _, b) = self.send(req).await;
        (s, b)
    }

    /// Starts an analysis of a path; returns the job ID.
    async fn start(&self, path: &Path, force: bool) -> String {
        let boundary = "auBoundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{}\r\n",
            path.display()
        );
        if force {
            body.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"force\"\r\n\r\n1\r\n"
            ));
        }
        // Into the workspace's own environment, whose history these tests
        // watch (with history files of its own, a run wouldn't take it over).
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"env\"\r\n\r\ndefault\r\n"
        ));
        body.push_str(&format!("--{boundary}--\r\n"));
        let req = self
            .request(Method::POST, "/api/analyze")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::from(body))
            .unwrap();
        let (s, _, body) = self.send(req).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{body}");
        serde_json::from_str::<Value>(&body).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Waits for a job to end; returns its status document.
    async fn wait(&self, job: &str) -> Value {
        for _ in 0..2400 {
            let (_, _, b) = self.get(&format!("/api/jobs/{job}")).await;
            let v: Value = serde_json::from_str(&b).unwrap();
            if !matches!(v["status"].as_str(), Some("running" | "collecting")) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("analysis did not finish");
    }

    async fn analyze(&self, path: &Path) -> String {
        // Run IDs carry the second they were made in.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let job = self.start(path, false).await;
        let v = self.wait(&job).await;
        assert_eq!(v["status"], "done", "{v}");
        v["run"].as_str().unwrap().to_string()
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.join("ws").join("pathwarden-state")
    }
}

struct Quiet;
impl analyze::Progress for Quiet {
    fn phase(&mut self, _: Phase) {}
}
impl RecordProgress for Quiet {
    fn warn(&mut self, _: String) {}
}

/// Records a run in the history the way a scheduled `pathwarden run` does.
fn scheduled_run(state: &Path, input: &Path) {
    let config = Config::default();
    let store = Store::new(&config.state, Some(state)).unwrap();
    let _lock = store.lock().unwrap();
    store.pull().unwrap();
    let previous = store.load().unwrap();
    let ev = analyze::evaluate(&[input], &config, &[], &mut Quiet).unwrap();
    let prep = record::prepare(
        pathwarden_core::store::last_run(&store).as_ref(),
        &previous,
        ev,
        &config,
        &record::Options {
            started_ms: analyze::now() * 1000,
            accept_shrink: false,
            recorded_by: record::by::SCHEDULE,
            finished_at: None,
        },
        &mut Quiet,
    );
    store
        .save(&prep.reconciled.state, &prep.last, &prep.point)
        .unwrap();
}

#[tokio::test]
async fn automate_pages_and_the_rail() {
    let a = app("pages");
    for uri in [
        "/automate/schedule",
        "/automate/ticketing",
        "/automate/history",
    ] {
        let (s, _, body) = a.get(uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert!(body.contains(r#"<span class="tl-group" aria-hidden="true">Automate</span>"#));
        assert!(
            body.contains(&format!(r#"href="{uri}" aria-current="page""#)),
            "{uri}"
        );
        assert!(!body.contains("<script>"), "{uri}: no inline scripts");
        assert!(!body.contains(" style=\""), "{uri}: no inline styles");
    }
    let (_, _, body) = a.get("/automate/schedule").await;
    assert!(body.contains("No run of your own yet"), "{body}");
    assert!(body.contains("Next steps"));
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains("The default: nothing is set"), "{body}");
    assert!(body.contains(&pathwarden_ui::workspace::shown_path(&a.state_dir())));
    assert!(body.contains(r#"id="state-push""#));
    // The labels `pathwarden history storage show` uses too.
    use pathwarden_ui::history_ui::label;
    for l in [label::WHERE, label::SET_BY, label::RECORDED, label::RECORDS] {
        assert!(body.contains(&format!("<dt>{l}</dt>")), "{l}");
    }
    // Settings points to the new place.
    let (_, _, body) = a.get("/settings").await;
    assert!(body.contains(r#"href="/automate/history""#));
    assert!(!body.contains(r#"data-section="state""#));
    let (s, h, _) = a.get("/automate").await;
    assert!(s.is_redirection());
    assert_eq!(h[header::LOCATION], "/automate/schedule");
    assert_eq!(a.get("/static/automate.js").await.0, StatusCode::OK);

    // A git checkout can't take over a folder holding something else (such
    // as the folder history it replaces); nothing is saved.
    std::fs::create_dir_all(a.state_dir()).unwrap();
    std::fs::write(a.state_dir().join("history.json"), "[]").unwrap();
    let before = std::fs::read_to_string(a.state.ws().config_path()).ok();
    let (s, b) = a
        .post(
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://example.com/s.git"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(b.contains("not a git working copy"), "{b}");
    assert_eq!(
        std::fs::read_to_string(a.state.ws().config_path()).ok(),
        before
    );
    std::fs::remove_file(a.state_dir().join("history.json")).unwrap();

    // Pushing off for a git history: the page says this computer only reads.
    let (s, b) = a
        .post(
            "/api/settings/state",
            json!({"backend": "git", "remote": "https://example.com/s.git", "push": false}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let toml = std::fs::read_to_string(a.state.ws().config_path()).unwrap();
    assert!(toml.contains("push = false"), "{toml}");
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains("only reads the run history"), "{body}");
    assert!(body.contains("Sync now</button>"));
    assert!(!body.contains("Get the latest"));
}

/// With "Full runs and settings", History storage has a card for how many
/// full runs the history keeps; its save writes `[state] full_runs_kept`
/// (the default removes it). Without it, there is no card.
#[tokio::test]
async fn history_storage_sets_how_many_full_runs_are_kept() {
    let a = app("fullruns");
    let (_, _, body) = a.get("/automate/history").await;
    assert!(!body.contains(r#"data-section="full-runs""#));
    std::fs::write(a.state.ws().config_path(), "[state]\nkeep = \"full\"\n").unwrap();
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains(r#"data-section="full-runs""#), "{body}");
    assert!(body
        .contains(r#"id="full-runs-kept" type="number" min="1" max="1000" step="1" value="50""#));
    // And the largest file a full run keeps.
    assert!(body.contains(r#"<label for="full-run-file-mb">Largest file</label>"#));
    assert!(body
        .contains(r#"id="full-run-file-mb" type="number" min="1" max="2048" step="1" value="75""#));
    assert!(!body.contains("full-run-file-held"), "not on GitHub");
    assert!(!body.contains("in a later version"));
    let (s, b) = a.post("/api/settings/full-runs", json!({"kept": 20})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let toml = std::fs::read_to_string(a.state.ws().config_path()).unwrap();
    assert!(toml.contains("full_runs_kept = 20"), "{toml}");
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains(r#"value="20""#));
    for bad in [0, 1001] {
        let (s, b) = a
            .post("/api/settings/full-runs", json!({"kept": bad}))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {b}");
        assert!(b.contains("Keep between 1 and 1000 full runs."), "{b}");
    }
    let (s, _) = a.post("/api/settings/full-runs", json!({"kept": 50})).await;
    assert_eq!(s, StatusCode::OK);
    let toml = std::fs::read_to_string(a.state.ws().config_path()).unwrap();
    assert!(!toml.contains("full_runs_kept"), "{toml}");
}

/// The card's Largest file saves `[state] full_run_file_mb` (the
/// default, 75, removes it); on a GitHub remote, a setting over 95 says
/// why it is held to 95.
#[tokio::test]
async fn history_storage_sets_the_largest_file_of_a_full_run() {
    let a = app("filemb");
    std::fs::write(a.state.ws().config_path(), "[state]\nkeep = \"full\"\n").unwrap();
    let (s, b) = a
        .post(
            "/api/settings/full-runs",
            json!({"kept": 50, "file_mb": 200}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let toml = std::fs::read_to_string(a.state.ws().config_path()).unwrap();
    assert!(toml.contains("full_run_file_mb = 200"), "{toml}");
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains(
        r#"id="full-run-file-mb" type="number" min="1" max="2048" step="1" value="200""#
    ));
    // A folder history: no hold.
    assert!(!body.contains("full-run-file-held"), "{body}");
    for bad in [0, 2049] {
        let (s, b) = a
            .post(
                "/api/settings/full-runs",
                json!({"kept": 50, "file_mb": bad}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {b}");
        assert!(b.contains("Choose between 1 and 2048 MB."), "{b}");
    }
    // On GitHub: held to 95, and the card says why while it is.
    let gh = "[state]\nbackend = \"git\"\nremote = \"https://github.com/contoso/history.git\"\npush = false\nkeep = \"full\"\nfull_run_file_mb = 200\n";
    std::fs::write(a.state.ws().config_path(), gh).unwrap();
    let (_, _, body) = a.get("/automate/history").await;
    assert!(
        body.contains(r#"<p class="hint" id="full-run-file-held" data-hold="95">GitHub refuses files over 100 MB, so a larger setting is held to 95 MB.</p>"#),
        "{body}"
    );
    std::fs::write(a.state.ws().config_path(), gh.replace("200", "90")).unwrap();
    let (_, _, body) = a.get("/automate/history").await;
    assert!(
        body.contains(r#"id="full-run-file-held" data-hold="95" hidden>"#),
        "{body}"
    );
    let (s, _) = a
        .post(
            "/api/settings/full-runs",
            json!({"kept": 50, "file_mb": 75}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let toml = std::fs::read_to_string(a.state.ws().config_path()).unwrap();
    assert!(!toml.contains("full_run_file_mb"), "{toml}");
}

#[tokio::test]
async fn schedule_from_a_path_run_not_the_demo() {
    let a = app("sched");
    let run = a.analyze(&repo("testdata/forest")).await;
    let (_, _, body) = a.get("/automate/schedule?os=windows").await;
    assert!(
        body.contains(&format!(r#"<option value="{run}" selected>"#)),
        "the latest run by default: {body}"
    );
    // Both of the run's domains are collected.
    assert!(body.contains("&#39;--domain&#39;, &#39;contoso.local&#39;"));
    assert!(body.contains("child.contoso.local"));
    assert!(body.contains("None recorded in the history in use"));
    // The demo is not offered, and asking for it falls back to your run.
    let demo_job = {
        let req = a
            .request(Method::POST, "/api/demo")
            .header(header::ORIGIN, format!("http://{HOST}"))
            .body(Body::empty())
            .unwrap();
        let (_, _, b) = a.send(req).await;
        serde_json::from_str::<Value>(&b).unwrap()["job"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let demo = a.wait(&demo_job).await["run"].as_str().unwrap().to_string();
    let (_, _, body) = a.get(&format!("/automate/schedule?run={demo}")).await;
    assert!(
        body.contains("can&#39;t be collected on a schedule")
            || body.contains("can't be collected on a schedule"),
        "{body}"
    );
    assert!(!body.contains(&format!(r#"value="{demo}""#)));
    let (s, _, file) = a
        .get(&format!("/automate/schedule/run.ps1?os=windows&run={run}"))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(file.contains("PATHWARDEN_SCHEDULED"));
    // The demo switched to its own environment; back to the run's.
    assert!(a.state.set_env("default"));
    // A scheduled run arrives: the status says when.
    scheduled_run(&a.state_dir(), &repo("testdata/forest"));
    let (_, _, body) = a.get("/automate/schedule").await;
    assert!(body.contains("Running since"), "{body}");
    assert!(body.contains("with an attack path to Tier Zero"), "{body}");
}

#[tokio::test]
async fn the_same_collection_warns_before_a_run_is_made() {
    let a = app("dup");
    // A collection whose file name carries its time.
    let data = a.dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let zip = data.join("20260901020000_BloodHound.zip");
    std::fs::copy(repo("demo/20261001020000_PathwardenDemo.zip"), &zip).unwrap();
    let first = a.analyze(&zip).await;

    let job = a.start(&zip, false).await;
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "duplicate", "{v}");
    assert_eq!(v["run"], first.as_str());
    assert!(v["what"].as_str().unwrap().starts_with("the run of"));
    assert_eq!(a.state.ws().runs().len(), 1, "nothing saved");
    // The analyze page can resume it.
    let (_, _, page) = a.get(&format!("/analyze?job={job}")).await;
    assert!(page.contains(r#"id="duplicate""#) && page.contains("&quot;duplicate&quot;"));

    // Analyze anyway: the same inputs, a second run.
    let (s, b) = a.post(&format!("/api/jobs/{job}/anyway"), json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "done", "{v}");
    assert_eq!(a.state.ws().runs().len(), 2);
    // Opened again once it is done: the page goes to its run.
    let (s, h, _) = a.get(&format!("/analyze?job={job}")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(
        h[header::LOCATION],
        format!("/runs/{}", v["run"].as_str().unwrap()).as_str()
    );
    let (s, _) = a.post(&format!("/api/jobs/{job}/anyway"), json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "only once");

    // "Re-analyze" (force) skips the check; discarding forgets the job.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let job = a.start(&zip, true).await;
    assert_eq!(a.wait(&job).await["status"], "done");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let job = a.start(&zip, false).await;
    assert_eq!(a.wait(&job).await["status"], "duplicate");
    let (s, _) = a.post(&format!("/api/jobs/{job}/discard"), json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, b) = a.get(&format!("/api/jobs/{job}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["error"],
        "That analysis or collection is no longer running. Reload the page."
    );
    assert_eq!(a.state.ws().runs().len(), 3);
}

#[tokio::test]
async fn scheduled_runs_show_on_runs_and_progress_with_their_report() {
    let a = app("sched-runs");
    let first = a.analyze(&repo("testdata/forest")).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    scheduled_run(&a.state_dir(), &repo("testdata/forest"));
    // The schedule's report, next to the history folder.
    let reports = a.dir.join("ws").join("reports");
    std::fs::create_dir_all(&reports).unwrap();
    std::fs::write(
        reports.join("latest.html"),
        "<!doctype html><title>Scheduled report</title>",
    )
    .unwrap();

    let (s, _, body) = a.get("/runs").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains(r#"<span class="tag sched">Scheduled</span>"#),
        "{body}"
    );
    assert!(body.contains(r#"href="/history/report""#), "{body}");
    assert!(body.contains(&format!(r#"href="/runs/{first}""#)));
    assert!(!body.contains("This computer only"), "{body}");
    let (s, h, report) = a.get("/history/report").await;
    assert_eq!(s, StatusCode::OK);
    assert!(report.contains("Scheduled report"));
    // Served as a run loaded from the history: a script that isn't
    // one Pathwarden wrote doesn't run, and popups stay sandboxed.
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("sandbox allow-scripts allow-popups"), "{csp}");
    assert!(csp.contains("script-src 'none'"), "{csp}");
    assert!(!csp.contains("script-src 'unsafe-inline'"), "{csp}");
    assert!(!csp.contains("allow-popups-to-escape-sandbox"), "{csp}");

    // Progress charts both runs of the environment from the history, and
    // the scheduled one found nothing new.
    let (_, _, body) = a.get("/progress").await;
    // Where the runs come from, in the (i) beside the title's line.
    assert!(
        body.contains(r#"id="tip-source">From the run history in "#),
        "{body}"
    );
    assert!(body.contains("What changed since"), "{body}");
    assert!(body.contains("No change: as many accounts"), "{body}");
    assert!(
        !body.contains(r#"class="env-tabs""#),
        "one environment: {body}"
    );
}

#[tokio::test]
async fn earlier_runs_stay_local_until_the_user_chooses() {
    let a = app("earlier");
    // A run made while another run held the history's lock is local only
    // (at once: no wait for the lock in these tests).
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let lock = a
        .dir
        .join("ws")
        .join("pathwarden-state")
        .join(".pathwarden.lock");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let run = a.analyze(&repo("testdata/forest")).await;
    std::fs::remove_file(&lock).unwrap();
    // Its Run details tab says so, amber.
    let (_, _, page) = a.get(&format!("/runs/{run}/report?embed=1")).await;
    assert!(
        page.contains("This run is not in the run history."),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="aside warn">Not recorded</span>"#),
        "{page}"
    );
    let (_, _, body) = a.get("/runs").await;
    assert!(body.contains("This computer only"), "{body}");
    assert!(
        body.contains("Import or keep on this computer only"),
        "{body}"
    );
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains("Import them in order"), "{body}");
    let (_, _, body) = a.get("/progress").await;
    assert!(body.contains("These runs are local only"), "{body}");

    // Keep them local only: the offer goes away, nothing is rewritten.
    let before =
        std::fs::read_to_string(a.state.ws().run_dir(&run).unwrap().join("summary.json")).unwrap();
    let (s, b) = a
        .post("/api/history/keep-local", json!({"ids": [run, "../x"]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (_, _, body) = a.get("/runs").await;
    assert!(
        !body.contains("Import or keep on this computer only"),
        "{body}"
    );
    let after =
        std::fs::read_to_string(a.state.ws().run_dir(&run).unwrap().join("summary.json")).unwrap();
    assert_eq!(before, after);
    assert!(!a.state_dir().join("history").exists());
}

/// essos from `testdata/rusthound` as RustHound-CE writes it: the domains
/// file also holds a not-collected object for the trusted sevenkingdoms.
fn essos_with_trust(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for entry in std::fs::read_dir(repo("testdata/rusthound")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.contains("sevenkingdoms") {
            continue;
        }
        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if name.ends_with("_domains.json") {
            let data = doc["data"].as_array_mut().unwrap();
            data.push(json!({
                "Properties": {"domain": "SEVENKINGDOMS.LOCAL", "name": "SEVENKINGDOMS.LOCAL",
                    "domainsid": "", "highvalue": true, "collected": false},
                "Aces": [], "ChildObjects": [], "Trusts": [], "Links": [],
                "ObjectIdentifier": "S-1-5-21-1821261621-2407627684-1290984713",
                "IsDeleted": false, "IsACLProtected": false,
            }));
            doc["meta"]["count"] = data.len().into();
        }
        std::fs::write(dir.join(&name), serde_json::to_vec(&doc).unwrap()).unwrap();
    }
}

/// Rewrites a JSON file with `edit`.
fn edit_json(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    edit(&mut v);
    std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// A trusted domain's object doesn't make it a collected domain.
/// A run 0.1.1 saved (which counted it) is still the same environment as
/// the runs after it: the same collection is recognised, the trusted domain
/// is not "missing", and runs and history points are listed together.
#[tokio::test]
async fn trusted_domains_are_not_collected_and_earlier_runs_follow() {
    let a = app("trusts");
    let data = a.dir.join("data");
    essos_with_trust(&data);
    let first = a.analyze(&data).await;
    let s = a.state.ws().summary(&first).unwrap();
    assert_eq!(s.domains, ["ESSOS.LOCAL"]);
    assert_eq!(
        s.trusted_domains,
        Some(vec!["SEVENKINGDOMS.LOCAL".to_string()])
    );
    assert_eq!(s.environment(), "ESSOS.LOCAL");

    // As 0.1.1 saved it: the trusted domain among the collected ones.
    let both = json!(["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]);
    let summary = a.state.ws().run_dir(&first).unwrap().join("summary.json");
    edit_json(&summary, |v| {
        v["domains"] = both.clone();
        v.as_object_mut().unwrap().remove("trusted_domains");
    });
    edit_json(&a.state_dir().join("last-run.json"), |v| {
        v["domains"] = both.clone();
        v.as_object_mut().unwrap().remove("trusted_domains");
    });
    let scopes = pathwarden_core::state::scopes_of(&[
        "ESSOS.LOCAL".to_string(),
        "SEVENKINGDOMS.LOCAL".to_string(),
    ]);
    for e in std::fs::read_dir(a.state_dir().join("history")).unwrap() {
        edit_json(&e.unwrap().path(), |v| {
            v["scopes"] = json!(scopes);
            v.as_object_mut().unwrap().remove("trusted_scopes");
        });
    }
    let runs = a.state.ws().runs();
    assert_eq!(
        runs[0].domains,
        both.as_array().unwrap().clone(),
        "nothing to learn from yet"
    );

    // The same collection again: recognised although the lists differ.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let job = a.start(&data, false).await;
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "duplicate", "{v}");
    assert_eq!(v["run"], first.as_str());

    // Analyzed anyway: one environment, and sevenkingdoms isn't missing.
    let (s, b) = a.post(&format!("/api/jobs/{job}/anyway"), json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let v = a.wait(&job).await;
    assert_eq!(v["status"], "done", "{v}");
    let runs = a.state.ws().runs();
    assert_eq!(runs.len(), 2);
    for r in &runs {
        assert_eq!(r.domains, ["ESSOS.LOCAL"], "{}", r.id);
        assert_eq!(r.environment(), "ESSOS.LOCAL");
    }
    let warnings = &runs[0].history.as_ref().unwrap().warnings;
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("not in this collection")),
        "{warnings:?}"
    );
    // On disk the old point keeps its scopes; the UI groups it with the new.
    let (mut points, _) = pathwarden_core::history::load(&a.state_dir()).unwrap();
    assert_eq!(points.len(), 2);
    assert_ne!(points[0].scopes, points[1].scopes);
    pathwarden_core::state::migrate_points(&mut points);
    assert_eq!(points[0].scopes, points[1].scopes);
    let (_, _, page) = a.get("/progress").await;
    assert!(page.contains("ESSOS.LOCAL"), "{page}");
    assert!(
        !page.contains("SEVENKINGDOMS"),
        "one environment, named after essos"
    );
}

/// Runs 0.1.1 saved are listed with later runs' domains, but their files
/// keep what was saved: importing one into the history writes only its
/// history link. Its own page uses the listed domains, as the lists do.
#[tokio::test]
async fn earlier_runs_keep_their_files_and_their_pages_follow() {
    let a = app("trusts-import");
    let data = a.dir.join("data");
    essos_with_trust(&data);
    // Both runs local only: made while another run held the history's lock.
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let lock = a.state_dir().join(".pathwarden.lock");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let old = a.analyze(&data).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let job = a.start(&data, true).await;
    assert_eq!(a.wait(&job).await["status"], "done");
    std::fs::remove_file(&lock).unwrap();

    // The first as 0.1.1 saved it.
    let summary = a.state.ws().run_dir(&old).unwrap().join("summary.json");
    edit_json(&summary, |v| {
        v["domains"] = json!(["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]);
        v.as_object_mut().unwrap().remove("trusted_domains");
    });
    assert_eq!(a.state.ws().run(&old).unwrap().domains, ["ESSOS.LOCAL"]);
    let (_, _, page) = a.get(&format!("/runs/{old}")).await;
    assert!(page.contains("ESSOS.LOCAL"), "{page}");
    assert!(
        !page.contains("ESSOS.LOCAL and SEVENKINGDOMS.LOCAL"),
        "named as the lists name it"
    );

    let (s, b) = a.post("/api/history/import", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["imported"], 2);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&summary).unwrap()).unwrap();
    assert_eq!(
        saved["domains"],
        json!(["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"])
    );
    assert!(saved.get("trusted_domains").is_none(), "{saved}");
    assert!(saved["history"]["run_id"].is_string(), "{saved}");
}

/// A run the history has with no full run opens its small run page, built
/// from the history point, never Progress; History storage counts
/// the runs that open in full.
#[tokio::test]
async fn numbers_only_runs_open_their_small_page() {
    let a = app("numbers-only");
    let first = a.analyze(&repo("testdata/forest")).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    scheduled_run(&a.state_dir(), &repo("testdata/forest"));
    let snap = pathwarden_ui::history_ui::snapshot(&a.state.ws(), None);
    let point = snap.history.points.last().unwrap().run_id.clone();

    let (s, _, body) = a.get("/runs").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(&format!(r#"href="/runs/{point}""#)), "{body}");
    assert!(body.contains(&format!(r#"href="/runs/{first}""#)), "{body}");
    assert!(!body.contains("/progress?env="), "{body}");
    assert!(body.contains("Numbers with names"), "{body}");
    assert!(!body.contains("no full run"), "the tag says it: {body}");
    assert!(body.contains(r#"class="runrow numbers-only""#), "{body}");

    let (s, _, page) = a.get(&format!("/runs/{point}")).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert!(
        page.contains("Only its numbers are kept, so there"),
        "{page}"
    );
    assert!(page.contains("no report or graph."), "{page}");
    assert!(page.contains("Recorded by the schedule"), "{page}");
    assert!(page.contains(r#"class="nf-list""#), "{page}");
    // The open findings are named: the state's dates add up to the point.
    assert!(!page.contains("Only new, back and fixed"), "{page}");
    assert!(!page.contains("report-frame"), "{page}");
    // A run on this computer still opens its own page.
    let (s, _, page) = a.get(&format!("/runs/{first}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("report-frame"));
    let (s, _, _) = a.get("/runs/20200101T000000.000Z").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The Full runs fact only at "Full runs and settings".
    let (_, _, body) = a.get("/automate/history").await;
    assert!(!body.contains("<dt>Full runs</dt>"), "{body}");
    std::fs::write(a.state.ws().config_path(), "[state]\nkeep = \"full\"\n").unwrap();
    let (_, _, body) = a.get("/automate/history").await;
    assert!(body.contains("<dt>Full runs</dt>"), "{body}");
    assert!(
        body.contains("1 of 2 runs open in full on this computer · 1 numbers with names"),
        "{body}"
    );
    // And the run's line no longer says only its numbers are kept.
    let (_, _, page) = a.get(&format!("/runs/{point}")).await;
    assert!(
        page.contains("Its report and graph aren&#39;t on this computer."),
        "{page}"
    );
}
