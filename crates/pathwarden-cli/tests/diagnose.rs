//! `pathwarden diagnose`: what the run page's Collection performance panel
//! shows, from the same code (`--json` is the app's API), and `--bundle`,
//! which writes a zip holding none of the run's names (the hostile-names
//! fixture) or refuses, writing nothing.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pathwarden_core::diagnostics::{
    CollectionTimings, HostSummary, PhaseTime, TIMINGS_FILE, TIMINGS_VERSION,
};
use pathwarden_ui::jobs::{self, JobSpec, JobStatus, Jobs};
use pathwarden_ui::workspace::{new_run_id, CollectionInfo, Workspace};

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pathwarden"))
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn timings(total_ms: u64, reached: usize) -> CollectionTimings {
    CollectionTimings {
        version: TIMINGS_VERSION,
        collector: "built-in".into(),
        total_ms,
        phases: [("connect", 400), ("read", total_ms / 2), ("write", 900)]
            .iter()
            .map(|(n, ms)| PhaseTime {
                name: (*n).into(),
                ms: *ms,
            })
            .collect(),
        entries: 41_000,
        hosts: Some(HostSummary {
            computers: 12,
            tried: 10,
            reached,
            failed: 10 - reached,
            errors: [("unreachable".to_string(), 2)].into(),
            ..HostSummary::default()
        }),
        summary: Some("Timing: connect 0.40s".into()),
        details: vec!["[timing] naming context 1 (domain): 41,000 entries".into()],
        ..CollectionTimings::default()
    }
}

/// A run saved as the Collect wizard saves one (`timings` given), or as an
/// upload (`None`).
fn save(ws: &Workspace, timings: Option<CollectionTimings>) -> String {
    save_with(ws, timings, None)
}

/// [`save`], the read resumed when `read_started` says it started.
fn save_with(
    ws: &Workspace,
    timings: Option<CollectionTimings>,
    read_started: Option<i64>,
) -> String {
    std::thread::sleep(Duration::from_millis(1100));
    let jobs = Arc::new(Jobs::default());
    let id = new_run_id(pathwarden_core::analyze::now());
    let collected = timings.is_some();
    let spec = JobSpec {
        id: id.clone(),
        inputs: vec![repo("testdata/hostile")],
        scratch: None,
        also_scratch: None,
        source: "test".into(),
        demo: false,
        env: Some("default".into()),
        new_env: None,
        env_auto: false,
        label: None,
        collection: collected.then(|| CollectionInfo {
            read_started,
            method: "builtin".into(),
            scope: "all".into(),
            domain: "kestrelüber.local".into(),
            server: None,
            ldaps: false,
            current_user: true,
            warnings: Vec::new(),
            kept: None,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
        }),
        timings,
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

#[test]
fn diagnose_prints_the_panel_and_writes_a_bundle_without_names() {
    let dir = std::env::temp_dir().join(format!("pathwarden-diagnose-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("ws");
    let ws = Workspace::open(&root).unwrap();
    let wsarg = root.to_string_lossy().into_owned();
    let upload = save(&ws, None);
    save(&ws, Some(timings(100_000, 6)));
    let latest = save(&ws, Some(timings(130_000, 8)));
    let run = ws.run(&latest).unwrap();
    let run_id = run.run_id();

    // The latest run by default, compared with the one before it that has
    // timings (the upload in between has none).
    let text = ok(&pw(&dir, &["diagnose", "--workspace", &wsarg]));
    assert!(
        text.contains(&format!("Collection performance of run {run_id}")),
        "{text}"
    );
    assert!(text.contains("Compared with run"), "{text}");
    assert!(text.contains("30.0s slower"), "{text}");
    assert!(text.contains("8 of 10  2 more"), "{text}");
    assert!(text.contains("Errors by kind: unreachable 2"), "{text}");
    assert!(!text.contains("[timing]"), "{text}");
    let details = ok(&pw(
        &dir,
        &["diagnose", &run_id, "--details", "--workspace", &wsarg],
    ));
    assert!(
        details.contains("[timing] naming context 1 (domain)"),
        "{details}"
    );

    // --json is the app's /api/runs/<run>/performance.
    let json = ok(&pw(
        &dir,
        &["diagnose", &run_id, "--json", "--workspace", &wsarg],
    ));
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        json,
        pathwarden_ui::diagnose::Performance::of(&ws, &run).to_json()
    );

    // `runs show` says what the run page's Run details says: the slower
    // collection and the settings line, in text and JSON. Its hints name
    // the run by the ID its header prints.
    let shown = ok(&pw(&dir, &["runs", "show", &latest, "--workspace", &wsarg]));
    assert!(
        shown.contains(&format!(
            "  Collection slower · `pathwarden diagnose {run_id}` shows it."
        )),
        "{shown}"
    );
    assert!(
        shown.contains("  The next analysis applies: the default settings"),
        "{shown}"
    );
    let shown: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["runs", "show", &latest, "--json", "--workspace", &wsarg],
    )))
    .unwrap();
    assert_eq!(shown["performance"]["slower"], true, "{shown}");
    assert_eq!(
        shown["performance"]["words"], "Collection slower",
        "{shown}"
    );
    assert_eq!(shown["settings"]["loaded"], true, "{shown}");
    assert!(
        shown["settings"]["applies"]
            .as_str()
            .unwrap()
            .starts_with("The next analysis applies: the default settings"),
        "{shown}"
    );
    // The upload, with no timings: the plain words, as the run page has.
    let up = ok(&pw(&dir, &["runs", "show", &upload, "--workspace", &wsarg]));
    assert!(
        up.contains(&format!(
            "  Collection performance · `pathwarden diagnose {}` shows it.",
            ws.run(&upload).unwrap().run_id()
        )),
        "{up}"
    );

    // An upload has no timings, and says why.
    let none = ok(&pw(&dir, &["diagnose", &upload, "--workspace", &wsarg]));
    assert!(
        none.contains("only collections Pathwarden runs itself are timed"),
        "{none}"
    );

    // The bundle: written, none of the names in it.
    let zip = dir.join("bundle.zip");
    let zarg = zip.to_string_lossy().into_owned();
    let said = ok(&pw(
        &dir,
        &[
            "diagnose",
            "--bundle",
            "--output",
            &zarg,
            "--workspace",
            &wsarg,
        ],
    ));
    assert!(said.contains("Wrote"), "{said}");
    let mut z = zip::ZipArchive::new(std::fs::File::open(&zip).unwrap()).unwrap();
    let mut all = String::new();
    for i in 0..z.len() {
        z.by_index(i).unwrap().read_to_string(&mut all).unwrap();
    }
    assert!(all.contains("\"total_ms\": 130000"), "{all}");
    let up = all.to_uppercase();
    for name in ["KESTRELÜBER", "NOVÁK", "<IMG", "ÆTHER", "ZØNE", "S-1-5-21-"] {
        assert!(!up.contains(name), "{name} in the bundle:\n{all}");
    }
    // Never over a file already there.
    let again = pw(
        &dir,
        &[
            "diagnose",
            "--bundle",
            "--out",
            &zarg,
            "--workspace",
            &wsarg,
        ],
    );
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));

    // A name the placeholders can't reach: refused, nothing written, the
    // name not repeated.
    let mut planted = timings(130_000, 8);
    planted.phases.push(PhaseTime {
        name: "SRV-ÆTHER01".into(),
        ms: 1,
    });
    std::fs::write(
        ws.run_dir(&latest).unwrap().join(TIMINGS_FILE),
        serde_json::to_vec(&planted).unwrap(),
    )
    .unwrap();
    let refused_zip = dir.join("refused.zip");
    let refused = pw(
        &dir,
        &[
            "diagnose",
            "--bundle",
            "--out",
            &refused_zip.to_string_lossy(),
            "--workspace",
            &wsarg,
        ],
    );
    assert_eq!(refused.status.code(), Some(2));
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(err.contains("timings.json would contain a name"), "{err}");
    assert!(!err.to_uppercase().contains("ÆTHER"), "{err}");
    assert!(!refused_zip.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

/// `pathwarden run -i` as the scheduled scripts run it, on a folder
/// `pathwarden collect` wrote: one with forest data and the timings collect
/// leaves with it.
fn scheduled_run(dir: &Path, data: &Path, state: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_pathwarden"))
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_SCHEDULED", "1")
        .args(["run", "-i"])
        .arg(data)
        .arg("--state")
        .arg(state)
        .output()
        .unwrap();
    ok(&out)
}

/// Collect then run, as a schedule does: the run's timings are kept in the
/// history's state folder, `diagnose` reads them by the run's ID (as the
/// app's API does), and the bundle holds them. Analyzing the folder again
/// isn't that collection: no timings. `run -i ... --save` on a collected
/// folder keeps them with the saved run.
#[test]
fn a_scheduled_collect_then_run_keeps_its_timings() {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-diagnose-sched-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("ws");
    let ws = Workspace::open(&root).unwrap();
    let wsarg = root.to_string_lossy().into_owned();
    let data = dir.join("collect");
    std::fs::create_dir_all(&data).unwrap();
    for f in std::fs::read_dir(repo("testdata/forest")).unwrap() {
        let f = f.unwrap().path();
        std::fs::copy(&f, data.join(f.file_name().unwrap())).unwrap();
    }
    let state = dir.join("state");
    let ids = |state: &Path| -> Vec<String> {
        let mut ids: Vec<String> = std::fs::read_dir(state.join("history"))
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        ids.sort();
        ids
    };

    // What `pathwarden collect` leaves: the timings and the files written.
    let collected = |t: &CollectionTimings| {
        let files: Vec<PathBuf> = std::fs::read_dir(&data)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        pathwarden_core::diagnostics::write_sidecar(&data, t, &files).unwrap();
    };
    collected(&timings(100_000, 6));
    scheduled_run(&dir, &data, &state);
    std::thread::sleep(Duration::from_millis(1100));
    collected(&timings(130_000, 8));
    scheduled_run(&dir, &data, &state);
    // The same folder again, not collected again.
    std::thread::sleep(Duration::from_millis(1100));
    scheduled_run(&dir, &data, &state);
    let ids = ids(&state);
    assert_eq!(ids.len(), 3, "{ids:?}");
    for id in &ids[..2] {
        assert!(
            pathwarden_core::store::run_timings(&state, id).is_some(),
            "{id}"
        );
    }
    assert!(pathwarden_core::store::run_timings(&state, &ids[2]).is_none());
    let latest = &ids[1];

    let sarg = state.to_string_lossy().into_owned();
    let text = ok(&pw(
        &dir,
        &["diagnose", latest, "--state", &sarg, "--workspace", &wsarg],
    ));
    assert!(
        text.contains(&format!("Collection performance of run {latest}")),
        "{text}"
    );
    assert!(
        text.contains(&format!("Compared with run {}", ids[0])),
        "{text}"
    );
    assert!(text.contains("30.0s slower"), "{text}");

    // --json is the app's /api/runs/<run>/performance.
    let json = ok(&pw(
        &dir,
        &[
            "diagnose",
            latest,
            "--json",
            "--state",
            &sarg,
            "--workspace",
            &wsarg,
        ],
    ));
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let app = pathwarden_ui::diagnose::point_performance(&ws, Some(&state), latest).unwrap();
    assert_eq!(json, app.to_json());
    assert_eq!(json["recorded"], true);

    // The bundle holds the timings, and none of the forest's names.
    let zip = dir.join("sched.zip");
    ok(&pw(
        &dir,
        &[
            "diagnose",
            latest,
            "--bundle",
            "--out",
            &zip.to_string_lossy(),
            "--state",
            &sarg,
            "--workspace",
            &wsarg,
        ],
    ));
    let mut z = zip::ZipArchive::new(std::fs::File::open(&zip).unwrap()).unwrap();
    let mut all = String::new();
    for i in 0..z.len() {
        z.by_index(i).unwrap().read_to_string(&mut all).unwrap();
    }
    assert!(all.contains("\"total_ms\": 130000"), "{all}");
    assert!(!all.to_uppercase().contains("CONTOSO"), "{all}");

    // Saved instead: the run's timings.json.
    collected(&timings(130_000, 8));
    let saved = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &data.to_string_lossy(),
            "--save",
            "--workspace",
            &wsarg,
        ],
    ));
    let run = ws.all_runs().into_iter().next().expect(&saved);
    let t = std::fs::read_to_string(ws.run_dir(&run.id).unwrap().join(TIMINGS_FILE)).unwrap();
    assert_eq!(
        CollectionTimings::parse(&t).map(|t| t.total_ms),
        Some(130_000)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `diagnose --compare-output A B`: two collections, zips or the
/// folders `collect --out` wrote them to, compared as normalized JSON.
#[test]
fn compare_output_says_whether_two_collections_are_the_same() {
    let dir = std::env::temp_dir().join(format!("pathwarden-compare-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    let demo = repo("demo/20261001020000_PathwardenDemo.zip");
    std::fs::copy(&demo, dir.join("b/20261031090000_PathwardenDemo.zip")).unwrap();
    let a = demo.to_string_lossy().into_owned();
    let text = ok(&pw(&dir, &["diagnose", "--compare-output", &a, "b"]));
    assert!(text.starts_with("Same output: "), "{text}");
    assert!(
        text.contains(" files, ") && text.trim_end().ends_with(" objects."),
        "{text}"
    );

    // An error: status 2, as `diff`.
    let out = pw(&dir, &["diagnose", "--compare-output", &a, "empty"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("holds no collection zip"), "{err}");

    // Different: status 1, the lines, a secret's value hidden.
    let one = |name: &str, password: &str| {
        use std::io::Write;
        let path = dir.join(name);
        let mut z = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        z.start_file("1_users.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        let users = serde_json::json!({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1104",
            "Properties": {"name": "ALICE@CONTOSO.LOCAL", "userpassword": password}}]});
        z.write_all(users.to_string().as_bytes()).unwrap();
        z.finish().unwrap();
        path.to_string_lossy().into_owned()
    };
    let (x, y) = (one("x.zip", "Summer2024"), one("y.zip", "Winter2025"));
    let out = pw(&dir, &["diagnose", "--compare-output", &x, &y]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Different output: 1 difference.")
            && text.contains(
                "users.json: S-1-5-21-1-2-3-1104: Properties.userpassword: (hidden) / (hidden)"
            ),
        "{text}"
    );
    assert!(
        !text.contains("Summer2024") && !text.contains("Winter2025"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The text of every `summary.json` under `dir` whose folder is `id`.
fn summaries_of(dir: &Path, id: &str) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(summaries_of(&p, id));
        } else if p.file_name().is_some_and(|n| n == "summary.json")
            && p.parent()
                .and_then(|d| d.file_name())
                .is_some_and(|n| n == id)
        {
            out.push(std::fs::read_to_string(&p).unwrap());
        }
    }
    out
}

/// Lab item 70: a run whose read was resumed keeps when the read started
/// (`read_started` in its saved summary), and its Run details say it: in
/// the app and in `runs show`, US style in local time.
#[test]
fn a_resumed_read_says_when_it_started() {
    let dir = std::env::temp_dir().join(format!("pathwarden-resumed-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("ws");
    let ws = Workspace::open(&root).unwrap();
    let id = save_with(&ws, Some(timings(100_000, 6)), Some(1_793_000_000));
    let saved = summaries_of(&root, &id);
    assert_eq!(saved.len(), 1);
    assert!(
        saved[0].contains("\"read_started\": 1793000000"),
        "{}",
        saved[0]
    );
    let run = ws.run(&id).unwrap();
    assert_eq!(
        run.collection.as_ref().and_then(|c| c.read_started),
        Some(1_793_000_000)
    );
    let (perf, applies) = pathwarden_ui::run_details::perf_and_applies(&ws, &run);
    let html = pathwarden_ui::run_details::panel_html(
        &run,
        perf,
        &applies,
        pathwarden_ui::run_details::Remove::Delete { recorded: false },
        "n",
        None,
    );
    assert!(
        html.contains(
            r#"<p>The read was resumed. It started <time data-unix="1793000000" data-fmt="full""#
        ),
        "{html}"
    );
    let wsarg = root.to_string_lossy().into_owned();
    let text = ok(&pw(&dir, &["runs", "show", &run.id, "--workspace", &wsarg]));
    assert!(
        text.contains(&format!(
            "The read was resumed. It started {}.",
            pathwarden_core::time::format_local(1_793_000_000)
        )),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
