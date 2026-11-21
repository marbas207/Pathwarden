//! Collection performance and the diagnostics bundle, through the
//! router: a collection's timings are saved as the run's `timings.json`,
//! the run page compares them with the environment's previous run, the API
//! serves what `pathwarden diagnose --json` prints, and the bundle holds
//! none of the run's names (a fixture of hostile ones), or is refused.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::diagnostics::{
    CollectionTimings, HostSummary, PhaseMemory, PhaseTime, TIMINGS_FILE, TIMINGS_VERSION,
};
use pathwarden_ui::jobs::{self, JobSpec, JobStatus};
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::{new_run_id, CollectionInfo, Workspace};
use serde_json::Value;
use tower::ServiceExt;

const PORT: u16 = 4261;
const HOST: &str = "127.0.0.1:4261";

/// Names in `testdata/hostile` no bundle may hold: quotes, markup,
/// accents, a name that looks like a placeholder.
const HOSTILE: &[&str] = &[
    "KESTRELÜBER",
    "ALICE \"<IMG SRC=X>\" NOVÁK",
    "SRV-ÆTHER01",
    "DOMAIN-1 ZØNE",
];

/// `testdata/hostile`: the forest fixture with those names.
fn hostile_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/hostile")
}

/// Timings as a built-in full collection reports them.
fn timings(total_ms: u64, reached: usize) -> CollectionTimings {
    CollectionTimings {
        version: TIMINGS_VERSION,
        collector: "built-in".into(),
        total_ms,
        phases: [
            ("connect", 400),
            ("read", total_ms / 2),
            ("parse", 3000),
            ("resolve", 700),
            ("modules", total_ms / 4),
            ("write", 900),
        ]
        .iter()
        .map(|(n, ms)| PhaseTime {
            name: (*n).into(),
            ms: *ms,
        })
        .collect(),
        entries: 41_000,
        pages: 42,
        bytes: 90 << 20,
        peak_memory: vec![PhaseMemory {
            phase: "parse".into(),
            bytes: 700 << 20,
        }],
        hosts: Some(HostSummary {
            computers: 12,
            tried: 10,
            reached,
            failed: 10 - reached - 1,
            timed_out: 1,
            errors: [("access denied".to_string(), 3), ("timeout".to_string(), 1)].into(),
            ..HostSummary::default()
        }),
        summary: Some("Timing: connect 0.40s, read 50.0s".into()),
        details: vec!["[timing] naming context 1 (domain): 41,000 entries".into()],
        ..CollectionTimings::default()
    }
}

/// Analyzes `input` as the Collect wizard does after a collection (with
/// its collection info and timings), into the Default environment.
fn collect_run(ws: &Workspace, input: &Path, t: CollectionTimings) -> String {
    save_run(ws, input, Some(t))
}

/// A run of `input` saved by the UI's job, with timings `t` if any.
fn save_run(ws: &Workspace, input: &Path, t: Option<CollectionTimings>) -> String {
    std::thread::sleep(Duration::from_millis(1100));
    let jobs = Arc::new(jobs::Jobs::default());
    let id = new_run_id(pathwarden_core::analyze::now());
    let spec = JobSpec {
        id: id.clone(),
        inputs: vec![input.to_path_buf()],
        scratch: None,
        also_scratch: None,
        source: "Collected from kestrelüber.local".into(),
        demo: false,
        env: Some("default".into()),
        new_env: None,
        env_auto: false,
        label: None,
        collection: Some(CollectionInfo {
            read_started: None,
            plain_allowed: false,
            plain_fallback: false,
            method: "builtin".into(),
            scope: "all".into(),
            domain: "kestrelüber.local".into(),
            server: Some("dc01.kestrelüber.local".into()),
            ldaps: true,
            current_user: false,
            warnings: vec!["Contacting computers: sessions not fully read on SRV-ÆTHER01".into()],
            kept: None,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
        }),
        timings: t,
        force: true,
    };
    assert!(jobs.try_begin(&spec));
    jobs::spawn(jobs.clone(), ws.clone(), spec, false, true);
    let start = Instant::now();
    loop {
        match jobs.get(&id).map(|j| j.status) {
            Some(JobStatus::Done { .. }) => return id,
            Some(JobStatus::Failed { error }) => panic!("{error}"),
            Some(s) if !s.is_active() => panic!("{s:?}"),
            _ if start.elapsed() > Duration::from_secs(120) => panic!("timed out"),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
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
    async fn get(&self, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body.to_vec())
    }
}

fn unzip(bytes: &[u8]) -> Vec<(String, String)> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            (f.name().unwrap().into_owned(), s)
        })
        .collect()
}

/// The end of the Environments page's (one) panel tag after its ID:
/// `" open>` when open, `">` when closed.
fn env_panel_tag(page: &str) -> &str {
    let start = r#"<details class="perf card" id="perf-"#;
    assert_eq!(page.matches(start).count(), 1, "{page}");
    let rest = &page[page.find(start).unwrap() + start.len()..];
    let quote = rest.find('"').unwrap();
    &rest[quote..=quote + rest[quote..].find('>').unwrap()]
}

/// Every hostile name, its parts and the way JSON writes them, absent.
fn assert_no_names(files: &[(String, String)]) {
    for (name, text) in files {
        let up = text.to_uppercase();
        for n in HOSTILE {
            let json = serde_json::to_string(n).unwrap();
            for form in [n.to_string(), json.trim_matches('"').to_string()] {
                assert!(!up.contains(&form), "{name} holds {form}:\n{text}");
            }
            for part in ["KESTRELÜBER", "NOVÁK", "<IMG", "ÆTHER", "ZØNE"] {
                assert!(!up.contains(part), "{name} holds {part}:\n{text}");
            }
        }
        // No domain SID either.
        assert!(!up.contains("S-1-5-21-"), "{name}:\n{text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timings_are_saved_compared_and_bundled_without_names() {
    let dir = std::env::temp_dir().join(format!("pathwarden-diagnose-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input = hostile_fixture();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let first = collect_run(&ws, &input, timings(100_000, 6));
    let second = collect_run(&ws, &input, timings(130_000, 8));

    // Saved with the run, as written.
    let saved = std::fs::read_to_string(ws.run_dir(&second).unwrap().join(TIMINGS_FILE)).unwrap();
    assert_eq!(
        CollectionTimings::parse(&saved),
        Some(timings(130_000, 8)),
        "{saved}"
    );

    let state = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), PORT));
    let app = App {
        router: router(state.clone()),
        state,
        dir: dir.clone(),
    };

    // The run page's Run details tab (in the report it embeds) links its
    // performance page, and says when the collection got slower; the
    // panel isn't on it.
    let (s, _, page) = app.get(&format!("/runs/{second}/report?embed=1")).await;
    assert_eq!(s, StatusCode::OK);
    let page = String::from_utf8(page).unwrap();
    assert!(
        page.contains(r#"data-pw-run="performance">Collection slower</a>"#),
        "{page}"
    );
    assert!(!page.contains(r#"class="perf card""#), "{page}");
    let (_, _, page) = app.get(&format!("/runs/{first}/report?embed=1")).await;
    let page = String::from_utf8(page).unwrap();
    assert!(
        page.contains(r#"data-pw-run="performance">Collection performance</a>"#),
        "{page}"
    );

    // The Environments page: the environment's latest timed collection,
    // open because it got slower, naming its run.
    let (s, _, page) = app.get("/environments").await;
    assert_eq!(s, StatusCode::OK);
    let page = String::from_utf8(page).unwrap();
    assert_eq!(env_panel_tag(&page), r#"" open>"#, "{page}");
    assert!(page.contains(r#"-title" role="heading" aria-level="3""#));
    assert!(page.contains(&format!(r#"Run <a href="/runs/{second}">"#)));
    assert!(page.contains("2:10 in all, 30.0s slower than the last timed run"));

    // The run's performance page: one number per card, the change since
    // the earlier run.
    let (s, _, page) = app.get(&format!("/runs/{second}/performance")).await;
    assert_eq!(s, StatusCode::OK);
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("Collection performance"), "{page}");
    assert!(page.contains(r#"data-measure="total""#));
    assert!(page.contains("30.0s slower"), "{page}");
    assert!(
        page.contains("2:10 in all, 30.0s slower than the last timed run"),
        "{page}"
    );
    assert!(page.contains(r#"<span class="perf-num">8 of 10</span>"#));
    assert!(page.contains("Errors by kind: access denied 3, timeout 1."));
    assert!(page.contains(&format!("/runs/{second}/diagnostics.zip")));
    // A heading for heading navigation, and which way a count went in
    // words, not only its colour.
    assert!(page.contains(r#"id="perf-title" role="heading" aria-level="2""#));
    assert!(
        page.contains(r#"2 more<span class="sr-only"> (better)</span>"#),
        "{page}"
    );
    assert!(page.contains(r#"</span> than the last timed run</span>"#));
    // Alone on its page: open.
    assert!(
        page.contains(r#"<details class="perf card" id="perf" open>"#),
        "{page}"
    );
    // The first run has nothing to compare with.
    let (_, _, page) = app.get(&format!("/runs/{first}/performance")).await;
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("No earlier run of this environment has timings"));
    assert!(!page.contains("than the last timed run"));
    // A faster run is the latest: closed on the Environments page, and
    // the run page links it unmarked.
    let third = collect_run(&ws, &input, timings(90_000, 8));
    let (_, _, page) = app.get("/environments").await;
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("40.0s faster"), "{page}");
    assert_eq!(env_panel_tag(&page), r#"">"#, "{page}");
    assert!(page.contains(&format!(r#"Run <a href="/runs/{third}">"#)));
    let (_, _, page) = app.get(&format!("/runs/{third}")).await;
    let page = String::from_utf8(page).unwrap();
    assert!(!page.contains("Collection slower"), "{page}");

    // The API is what `pathwarden diagnose --json` prints.
    let (s, _, api) = app.get(&format!("/api/runs/{second}/performance")).await;
    assert_eq!(s, StatusCode::OK);
    let api: Value = serde_json::from_slice(&api).unwrap();
    let run = ws.run(&second).unwrap();
    assert_eq!(
        api,
        pathwarden_ui::diagnose::Performance::of(&ws, &run).to_json()
    );
    assert_eq!(api["measures"][0]["change"], "30.0s slower");
    assert_eq!(api["slower"], true);

    // The bundle: a zip with every part, and none of the names.
    let (s, h, zip) = app.get(&format!("/runs/{second}/diagnostics.zip")).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(h[header::CONTENT_TYPE], "application/zip");
    assert!(h[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("attachment; filename=\"pathwarden-diagnostics-"));
    let files = unzip(&zip);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    for want in [
        "README.txt",
        "system.json",
        "run.json",
        "posture.json",
        "plan.json",
        "findings.json",
        "collection.json",
        "timings.json",
        "timings-previous.json",
    ] {
        assert!(names.contains(&want), "{names:?}");
    }
    assert_no_names(&files);
    let collection: Value = serde_json::from_str(
        &files
            .iter()
            .find(|(n, _)| n == "collection.json")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(collection["method"], "builtin");
    // The same placeholder as the run's own list of domains.
    let run_json: Value =
        serde_json::from_str(&files.iter().find(|(n, _)| n == "run.json").unwrap().1).unwrap();
    let domains = run_json["domains"].as_array().unwrap();
    assert!(domains.contains(&collection["domain"]), "{collection}");
    assert!(collection["domain"]
        .as_str()
        .unwrap()
        .starts_with("domain-"));
    assert_eq!(collection["computers"]["reached"], 8);
    assert_eq!(collection["warnings"], 1);

    // A name where the placeholders don't reach (here planted in the
    // timings): refused, with the file named and the name not shown.
    let path = ws.run_dir(&second).unwrap().join(TIMINGS_FILE);
    let mut t = timings(130_000, 8);
    t.phases.push(PhaseTime {
        name: "SRV-ÆTHER01".into(),
        ms: 1,
    });
    std::fs::write(&path, serde_json::to_vec(&t).unwrap()).unwrap();
    let (s, h, body) = app.get(&format!("/runs/{second}/diagnostics.zip")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(h.get(header::CONTENT_DISPOSITION).is_none());
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("timings.json would contain a name"), "{body}");
    assert!(!body.to_uppercase().contains("ÆTHER"), "{body}");
}

/// A directory-only collection between two full ones: the second full one
/// is compared with the first, and the directory-only one with none. The
/// environment's zone names are searched for in the bundle.
#[tokio::test(flavor = "multi_thread")]
async fn only_runs_collected_the_same_way_are_compared() {
    let dir = std::env::temp_dir().join(format!("pathwarden-diagnose-kind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input = hostile_fixture();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let full = |total, reached| CollectionTimings {
        scope: Some("all".into()),
        ..timings(total, reached)
    };
    let first = collect_run(&ws, &input, full(100_000, 6));
    let dc_only = collect_run(
        &ws,
        &input,
        CollectionTimings {
            scope: Some("dc-only".into()),
            hosts: None,
            ..timings(20_000, 0)
        },
    );
    let third = collect_run(&ws, &input, full(130_000, 8));

    let state = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), PORT));
    let app = App {
        router: router(state.clone()),
        state,
        dir: dir.clone(),
    };
    let api = |v: Vec<u8>| serde_json::from_slice::<Value>(&v).unwrap();
    let (_, _, third_api) = app.get(&format!("/api/runs/{third}/performance")).await;
    let third_api = api(third_api);
    let first_id = ws.run(&first).unwrap().run_id();
    assert_eq!(third_api["previous_run"], first_id.as_str(), "{third_api}");
    assert_eq!(third_api["measures"][0]["change"], "30.0s slower");

    // The directory-only run: not compared, and it says why.
    let (_, _, dc_api) = app.get(&format!("/api/runs/{dc_only}/performance")).await;
    let dc_api = api(dc_api);
    assert!(dc_api["previous_run"].is_null(), "{dc_api}");
    assert_eq!(dc_api["not_compared"]["last_timed_run"], "built-in, all");
    assert_eq!(dc_api["not_compared"]["this_run"], "built-in, dc-only");
    let (_, _, page) = app.get(&format!("/runs/{dc_only}/performance")).await;
    let page = String::from_utf8(page).unwrap();
    assert!(
        page.contains("Not compared: the last timed run of this environment was collected another way (built-in, all; this one built-in, dc-only)."),
        "{page}"
    );
    assert!(!page.contains("than the last timed run"));

    // A zone's name, planted where the placeholders don't reach: refused.
    std::fs::write(
        ws.config_path(),
        "[[zone]]\nname = \"Ledger Vault \u{d8}stby\"\ngroups = [\"Ledger Admins\"]\n",
    )
    .unwrap();
    let path = ws.run_dir(&third).unwrap().join(TIMINGS_FILE);
    let mut t = full(130_000, 8);
    t.phases.push(PhaseTime {
        name: "ledger vault østby".into(),
        ms: 1,
    });
    std::fs::write(&path, serde_json::to_vec(&t).unwrap()).unwrap();
    let (s, _, body) = app.get(&format!("/runs/{third}/diagnostics.zip")).await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "{}",
        String::from_utf8_lossy(&body)
    );
}

/// A run recorded in the history has its timings in the state folder
/// (`timings/<run>.json`, as `pathwarden run` keeps a schedule's), and a
/// page of its own with the panel open.
#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_run_has_its_own_performance_page() {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-diagnose-point-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    // An earlier run saved with its timings in its folder only.
    let earlier = collect_run(&ws, &hostile_fixture(), timings(60_000, 5));
    let earlier_id = ws.run(&earlier).unwrap().run_id();
    let run = collect_run(&ws, &hostile_fixture(), timings(90_000, 7));
    let run_id = ws.run(&run).unwrap().run_id();
    let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
    let store_dir = loc.dir.join(pathwarden_core::store::TIMINGS_DIR);
    std::fs::create_dir_all(&store_dir).unwrap();
    std::fs::write(
        store_dir.join(format!("{run_id}.json")),
        serde_json::to_vec(&timings(90_000, 7)).unwrap(),
    )
    .unwrap();
    // And one without timings (an upload).
    let upload = save_run(&ws, &hostile_fixture(), None);

    let state = Arc::new(AppState::new(ws.clone(), Token::generate().unwrap(), PORT));
    let app = App {
        router: router(state.clone()),
        state,
        dir: dir.clone(),
    };
    let (s, _, page) = app.get(&format!("/history/{run_id}/performance")).await;
    assert_eq!(s, StatusCode::OK);
    let page = String::from_utf8(page).unwrap();
    assert!(
        page.contains(r#"<details class="perf card" id="perf" open>"#),
        "{page}"
    );
    assert!(page.contains(r#"<span class="perf-num">7 of 10</span>"#));
    let p = pathwarden_ui::diagnose::point_performance(&ws, None, &run_id).unwrap();
    assert!(p.recorded && p.timings.is_some());
    // Compared with the earlier run, whose timings are in its folder.
    assert_eq!(
        p.previous.as_ref().map(|(r, _)| r.run_id()),
        Some(earlier_id.clone())
    );
    assert!(
        page.contains("30.0s slower than the last timed run"),
        "{page}"
    );

    // The history storage page links the run's performance.
    let (_, _, page) = app.get("/automate/history").await;
    let page = String::from_utf8(page).unwrap();
    assert!(
        page.contains(&format!(r#"href="/history/{run_id}/performance""#)),
        "{page}"
    );

    // A run without timings: its page says why, the download inside.
    let (_, _, page) = app.get(&format!("/runs/{upload}/performance")).await;
    let page = String::from_utf8(page).unwrap();
    let at = page
        .find(r#"<details class="perf card" id="perf" open>"#)
        .expect(&page);
    let panel = &page[at..at + page[at..].find("</details>").unwrap()];
    assert!(panel.contains("not timed"), "{panel}");
    assert!(panel.contains("No collection timings"), "{panel}");
    assert!(panel.contains(&format!("/runs/{upload}/diagnostics.zip")));
    let zip = pathwarden_ui::diagnose::bundle_point(&ws, &p, None).expect("no names");
    let files = unzip(&zip);
    assert!(files.iter().any(|(n, _)| n == "timings.json"));
    assert_no_names(&files);
    // An unknown run: not found.
    let (s, _, _) = app.get("/history/20200101T000000.000Z/performance").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// The bundle's logs: this computer's logs and crash reports, every name
/// in them replaced like the rest of the zip, and searched; the page lists
/// them among what the zip holds.
#[tokio::test(flavor = "multi_thread")]
async fn the_bundle_takes_the_logs_without_names() {
    use pathwarden_core::logs::{By, Crash, JobLog, Kind, Outcome};
    let dir = std::env::temp_dir().join(format!("pathwarden-diagnose-logs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let run = collect_run(&ws, &hostile_fixture(), timings(100_000, 6));
    let logs = dir.join("logs");
    let log = JobLog::open_in(&logs, Kind::Collect, By::App, "kestrelüber.local").unwrap();
    log.line("domain controller dc01.kestrelüber.local (chosen)");
    log.line("Contacting computers: sessions not fully read on SRV-ÆTHER01");
    log.line("owner: ALICE \"<IMG SRC=X>\" NOVÁK@KESTRELÜBER.LOCAL");
    log.line(r"kept in C:\Users\someone\AppData\Local\Pathwarden\uploads");
    log.end(
        Outcome::Failed,
        "the LDAP connection to dc01.kestrelüber.local was reset",
    );
    // This run's job; another job's log stays out.
    pathwarden_core::logs::note_run(&logs, &run, log.name());
    let other = JobLog::open_in(&logs, Kind::Run, By::App, "elsewhere").unwrap();
    other.line("another environment's run of FABRIKAM.TEST");
    other.end(Outcome::Ok, "");
    let crash = Crash {
        message: "index out of bounds on SRV-ÆTHER01".into(),
        location: "src/x.rs:1:2".into(),
        thread: "main".into(),
        backtrace: String::new(),
        system: "Test OS".into(),
        job: None,
    }
    .write_in(&logs)
    .unwrap();
    let state = AppState::new(ws, Token::generate().unwrap(), PORT);
    state.jobs.set_logs_dir(Some(logs.clone()));
    let state = Arc::new(state);
    let app = App {
        router: router(state.clone()),
        state,
        dir: dir.clone(),
    };
    let (_, _, page) = app.get(&format!("/runs/{run}/performance")).await;
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("In the zip, every name replaced:"), "{page}");
    assert!(
        page.contains("<li>Latest logs</li><li>Crash reports</li>"),
        "{page}"
    );
    let (s, _, zip) = app.get(&format!("/runs/{run}/diagnostics.zip")).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    let files = unzip(&zip);
    let get = |n: &str| {
        files
            .iter()
            .find(|(f, _)| f == n)
            .map(|(_, t)| t.clone())
            .unwrap_or_else(|| {
                panic!(
                    "no {n} in {:?}",
                    files.iter().map(|f| &f.0).collect::<Vec<_>>()
                )
            })
    };
    let text = get(&format!("logs/{}", log.name()));
    assert!(
        text.contains("result: failed: the LDAP connection to host-"),
        "{text}"
    );
    assert!(!text.contains("someone"), "{text}");
    assert!(get(&format!("logs/{crash}")).contains("Message: index out of bounds on "));
    assert!(get("README.txt").contains("logs/"));
    assert!(
        !files
            .iter()
            .any(|(f, _)| f == &format!("logs/{}", other.name())),
        "another job's log is never in it"
    );
    assert_no_names(&files);
}
