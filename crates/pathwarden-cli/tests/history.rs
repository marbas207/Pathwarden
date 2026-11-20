//! One history for the UI and the CLI: an analysis started in the UI is
//! recorded in the state `pathwarden history` reads, and a `pathwarden run`
//! (here marked as scheduled) continues that state and shows up in the UI.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pathwarden_ui::jobs::{self, JobSpec, JobStatus, Jobs};
use pathwarden_ui::workspace::{new_run_id, Workspace};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-hist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        .args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Runs an analysis the way the UI's Analyze page does, and waits for it.
fn ui_analyze(jobs: &Arc<Jobs>, ws: &Workspace, input: PathBuf, demo: bool) -> String {
    // The workspace's own environment, whose history these tests watch.
    ui_analyze_in(jobs, ws, input, demo, Some("default"))
}

/// [`ui_analyze`] into environment `env` (as picked on the page).
fn ui_analyze_in(
    jobs: &Arc<Jobs>,
    ws: &Workspace,
    input: PathBuf,
    demo: bool,
    env: Option<&str>,
) -> String {
    // Run IDs carry the second they were made in.
    std::thread::sleep(Duration::from_millis(1100));
    let id = new_run_id(pathwarden_core::analyze::now());
    let spec = JobSpec {
        id: id.clone(),
        inputs: vec![input],
        scratch: None,
        also_scratch: None,
        source: "test".into(),
        demo,
        env: env.map(str::to_string),
        new_env: None,
        env_auto: false,
        label: None,
        collection: None,
        timings: None,
        force: false,
    };
    assert!(jobs.try_begin(&spec));
    jobs::spawn(jobs.clone(), ws.clone(), spec, false, true);
    let start = Instant::now();
    loop {
        match jobs.get(&id).map(|j| j.status) {
            Some(JobStatus::Done { .. }) => return id,
            Some(JobStatus::Failed { error }) => panic!("{error}"),
            Some(s) if !s.is_active() => panic!("{s:?}"),
            // The demo's analysis alone takes 90-120 s in a debug build
            // while another build runs: room for that.
            _ if start.elapsed() > Duration::from_secs(300) => panic!("timed out"),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn points(dir: &Path, state: &str) -> Vec<serde_json::Value> {
    let text = pw(dir, &["history", "--state", state, "--json"], &[]);
    serde_json::from_str::<serde_json::Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn ui_and_cli_share_one_history() {
    let dir = scratch("shared");
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let jobs = Arc::new(Jobs::default());
    let state = dir.join("ws").join("pathwarden-state");
    let state_arg = state.to_string_lossy().into_owned();

    // An analysis started in the UI is recorded in the default history (in
    // the workspace), and `pathwarden history` shows it.
    let first = ui_analyze(&jobs, &ws, repo("testdata/forest"), false);
    let summary = ws.summary(&first).unwrap();
    let link = summary.history.clone().expect("recorded");
    assert!(link.not_recorded.is_none(), "{link:?}");
    let pts = points(&dir, &state_arg);
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0]["run_id"], link.run_id.clone().unwrap().as_str());
    assert_eq!(pts[0]["recorded_by"], "ui");
    assert_eq!(pts[0]["changes"]["new"], 15);
    // The same counts on both sides.
    assert_eq!(pts[0]["findings"]["critical"], summary.critical);
    assert_eq!(pts[0]["findings"]["high"], summary.high);
    let text = pw(&dir, &["history", "--state", &state_arg], &[]);
    assert!(text.contains("1 run,"), "{text}");
    // Its report has nothing earlier to compare with.
    let report = |id: &str| {
        std::fs::read_to_string(
            ws.run_dir(id)
                .unwrap()
                .join(pathwarden_ui::workspace::REPORT_FILE),
        )
        .unwrap()
    };
    assert!(report(&first).contains(r#"<div class="hero card solo">"#));

    // A scheduled `pathwarden run` continues the same state: the UI's
    // fingerprints match, so nothing is new. (A second later, so the run
    // list orders the two by time.)
    std::thread::sleep(Duration::from_millis(1100));
    let run = pw(
        &dir,
        &[
            "run",
            "-i",
            &repo("testdata/forest").to_string_lossy(),
            "--state",
            &state_arg,
            "--report",
            "scheduled.html",
        ],
        &[("PATHWARDEN_SCHEDULED", "1")],
    );
    assert!(
        run.contains("0 new, 0 back, 0 fixed, 15 still open"),
        "{run}"
    );
    let pts = points(&dir, &state_arg);
    assert_eq!(pts.len(), 2);
    assert_eq!(pts[1]["recorded_by"], "schedule");
    // Its report compares with the UI's run.
    let html = std::fs::read_to_string(dir.join("scheduled.html")).unwrap();
    assert!(html.contains("last 2 runs"), "the trend");
    assert!(html.contains(r#"<span class="since">"#));

    // "Since the last run": the app's comparison is the command line's.
    let cli: serde_json::Value = serde_json::from_str(&pw(
        &dir,
        &["history", "--state", &state_arg, "--since", "--json"],
        &[],
    ))
    .unwrap();
    // Both with the status keys' 1.0 names beside the old ones.
    let ui = pathwarden_core::status_keys::to_value(
        &pathwarden_ui::history_ui::since(&ws, None).unwrap(),
    )
    .unwrap();
    assert!(cli["lines"].is_array(), "{cli}");
    assert_eq!(ui, cli);

    // The UI shows the scheduled run next to its own.
    let snap = pathwarden_ui::history_ui::snapshot(&ws, None);
    assert_eq!(snap.history.points.len(), 2);
    let rows = pathwarden_ui::history_ui::run_rows(&ws, &ws.runs(), &snap);
    assert_eq!(rows.len(), 2);
    assert!(rows[0].contains("Scheduled"), "{}", rows[0]);
    // Compared with the run before it in the history.
    assert!(rows[0].contains("vs-expo"), "{}", rows[0]);
    assert!(rows[1].contains(&format!("/runs/{first}")), "{}", rows[1]);

    // The next UI analysis (other domains, picked for this environment)
    // compares with the scheduled run.
    let third = ui_analyze_in(&jobs, &ws, repo("testdata/sdprop"), false, Some("default"));
    let link = ws.summary(&third).unwrap().history.unwrap();
    assert!(link.run_id.is_some());
    assert!(
        link.warnings
            .iter()
            .any(|w| w.contains("not in this collection")),
        "{link:?}"
    );
    let pts = points(&dir, &state_arg);
    assert_eq!(pts.len(), 3);
    // Other domains: its report has no earlier run of the same ones.
    assert!(report(&third).contains(r#"<div class="hero card solo">"#));
    // CONTOSO's findings are held, not resolved, as on the command line.
    assert_eq!(pts[2]["changes"]["resolved"], 0);
    assert!(pts[2]["changes"]["held"].as_u64().unwrap() > 0);

    // The same domains again: the UI's report has the trend of the two
    // earlier runs of them and this one.
    let fourth = ui_analyze(&jobs, &ws, repo("testdata/forest"), false);
    let html = report(&fourth);
    assert!(html.contains("last 3 runs"), "the trend");
    assert!(html.contains(r#"<span class="since">"#));

    // The demo never enters this history: it has its own, in the demo
    // environment's folder (with its earlier runs), never `--state`'s.
    let demo = ui_analyze(
        &jobs,
        &ws,
        repo("demo/20261001020000_PathwardenDemo.zip"),
        true,
    );
    let link = ws.summary(&demo).unwrap().history.unwrap();
    let demo_ws = ws.in_env(ws.registry().demo_id().unwrap());
    assert_eq!(
        link.run_id.as_deref(),
        pathwarden_core::history::load(
            &pathwarden_ui::history_ui::locate(&demo_ws, None)
                .unwrap()
                .dir
        )
        .unwrap()
        .0
        .last()
        .map(|p| p.run_id.as_str())
    );
    assert_eq!(points(&dir, &state_arg).len(), 4);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A run in progress on the command line holds the lock: the UI saves its
/// run anyway, marked local only with the reason, and can import it later.
#[test]
fn a_held_lock_keeps_the_ui_run_local_until_imported() {
    // At once, not after the usual wait for the lock.
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let dir = scratch("lock");
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let jobs = Arc::new(Jobs::default());
    let lock = dir
        .join("ws")
        .join("pathwarden-state")
        .join(".pathwarden.lock");
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let id = ui_analyze(&jobs, &ws, repo("testdata/forest"), false);
    let link = ws.summary(&id).unwrap().history.unwrap();
    assert!(link.run_id.is_none());
    assert!(
        link.not_recorded
            .as_deref()
            .is_some_and(|w| w.contains("Another run")),
        "{link:?}"
    );
    std::fs::remove_file(&lock).unwrap();
    assert_eq!(
        pathwarden_ui::history_ui::import(&ws, None).unwrap().0,
        1,
        "imported"
    );
    let pts = points(&dir, &dir.join("ws/pathwarden-state").to_string_lossy());
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0]["recorded_by"], "import");
    assert_eq!(pts[0]["changes"]["new"], 15);
    // An imported run records completeness from its saved posture too.
    assert!(
        pts[0]["completeness"]["computers"].as_u64().unwrap() > 0,
        "{}",
        pts[0]
    );
    assert!(ws.summary(&id).unwrap().history.unwrap().run_id.is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `pathwarden history` opens with what changed since the last run, names
/// the findings that changed, and its table and JSON carry choke points,
/// collection completeness and the zones' figures. (Rules turned on in the
/// second run give it new findings; a fixed finding is named in
/// [`history_over_an_older_point`], from a written state, since turning a
/// rule off is not a fix.)
#[test]
fn history_says_what_changed_since_the_last_run() {
    let dir = scratch("since");
    let state = dir.join("state");
    let state_arg = state.to_string_lossy().into_owned();
    let config = |name: &str, disabled: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "[rules]\ndisabled = [{disabled}]\n\n[[zone]]\nname = \"Servers\"\ngroups = [\"R00S00-SERVERADMINS@SCALE.LOCAL\"]\n\n[state]\ninclude_names = true\n"
            ),
        )
        .unwrap();
        path.to_string_lossy().into_owned()
    };
    let first = config("first.toml", "\"PW-002\", \"PW-010\"");
    let second = config("second.toml", "");
    let mut out = Vec::new();
    for c in [&first, &second] {
        out.push(pw(
            &dir,
            &[
                "run",
                "-i",
                "demo:",
                "-c",
                c,
                "--state",
                &state_arg,
                "--no-push",
            ],
            &[],
        ));
    }
    // `run` says what changed after its summary, as `history` does.
    assert!(!out[0].contains("Since the last run"), "{}", out[0]);
    let after = out[1]
        .split("\nSince the last run (")
        .nth(1)
        .expect(&out[1]);
    assert!(
        after.contains("  ! 2 new findings\n      High PW-002 "),
        "{after}"
    );
    assert!(
        after.contains("  The commands take the collection (-i) and these settings: -c "),
        "{after}"
    );
    let text = pw(
        &dir,
        &["history", "-c", &second, "--state", &state_arg],
        &[],
    );
    assert!(text.starts_with("Since the last run ("), "{text}");
    assert!(
        text.contains("  ! 2 new findings\n      High PW-002 "),
        "{text}"
    );
    assert!(text.contains("      see: pathwarden findings\n"), "{text}");
    // The commands take the settings given here.
    assert!(
        text.contains("  The commands take the collection (-i) and these settings: -c "),
        "{text}"
    );
    assert!(!text.contains("finding fixed"), "{text}");
    assert!(text.contains("  Steps     Collected"), "{text}");
    // Every line stays within 120 columns (the settings line names a
    // scratch path).
    assert!(
        text.lines()
            .filter(|l| !l.contains("these settings"))
            .all(|l| l.chars().count() <= 120),
        "{text}"
    );

    let pts = points(&dir, &state_arg);
    assert_eq!(pts.len(), 2);
    // --with-since: the runs as --json prints them, and the comparison as
    // --since --json prints it.
    let both: serde_json::Value = serde_json::from_str(&pw(
        &dir,
        &["history", "--state", &state_arg, "--json", "--with-since"],
        &[],
    ))
    .unwrap();
    assert_eq!(both["runs"], serde_json::Value::Array(pts.clone()));
    let since: serde_json::Value = serde_json::from_str(&pw(
        &dir,
        &["history", "--state", &state_arg, "--since", "--json"],
        &[],
    ))
    .unwrap();
    assert_eq!(both["since"], since);
    assert_eq!(since["findings"]["new"], 2);

    // `report --state`: the report of the second run's data compares with
    // the first, the same lines in its "What changed".
    pw(
        &dir,
        &[
            "report", "-i", "demo:", "-c", &second, "--state", &state_arg, "-o", "r.html",
        ],
        &[],
    );
    let html = std::fs::read_to_string(dir.join("r.html")).unwrap();
    assert!(html.contains("last 2 runs &middot;"), "the trend");
    for l in since["lines"].as_array().unwrap() {
        // As the report escapes it.
        let text = l["text"].as_str().unwrap().replace('\'', "&#39;");
        assert!(rows(&html).iter().any(|r| row_says(r, &text)), "{text}");
    }
    assert!(html.contains("2 new findings"));
    // The terminal's commands, and what they take, stay in the terminal.
    assert!(!html.contains("The commands take the collection"));
    let heading = |html: &str| {
        let s = html.split(r#"id="ov-since-h">"#).nth(1).unwrap();
        s[..s.find("</h3>").unwrap()].to_string()
    };
    let before = heading(&html);
    // A run recorded after it changes nothing: the report of the second
    // run's data still compares with the first, never with a later run.
    write_point(&state, "20991231T000000Z", 4_102_358_400, 9_999, true);
    pw(
        &dir,
        &[
            "report", "-i", "demo:", "-c", &second, "--state", &state_arg, "-o", "r.html",
        ],
        &[],
    );
    let html = std::fs::read_to_string(dir.join("r.html")).unwrap();
    assert!(html.contains("last 2 runs &middot;"), "the trend");
    assert!(!html.contains("9,999"), "the later run");
    assert_eq!(heading(&html), before);
    for l in since["lines"].as_array().unwrap() {
        let text = l["text"].as_str().unwrap().replace('\'', "&#39;");
        assert!(rows(&html).iter().any(|r| row_says(r, &text)), "{text}");
    }
    std::fs::remove_file(state.join("history/20991231T000000Z.json")).unwrap();
    // A --state with no history says so.
    let out = Command::new(bin())
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .args([
            "report",
            "-i",
            "demo:",
            "--state",
            "nosuchdir",
            "-o",
            "n.html",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("No run history in nosuchdir: the report shows this run alone"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A history of other domains says that, not that it is empty.
    let forest = repo("testdata/forest");
    let out = Command::new(bin())
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .args(["report", "--state", &state_arg, "-o", "f.html", "-i"])
        .arg(&forest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("has no runs of these domains (")
            && err.contains("CONTOSO.LOCAL")
            && err.contains("): the report shows this run alone"),
        "{err}"
    );
    assert!(!err.contains("no run history"), "{err}");
    let p = &pts[1];
    assert!(p["plan"]["steps"].as_u64().unwrap() > 0, "{p}");
    let c = &p["completeness"];
    assert!(c["computers"].as_u64().unwrap() > 0, "{p}");
    assert!(
        c["sessions_percent"].is_number() && c["local_groups_percent"].is_number(),
        "{p}"
    );
    let z = &p["zones"][0];
    assert_eq!(z["zone"], "Servers");
    assert!(z["objects"].as_u64().unwrap() > 0, "{p}");
    assert!(z["exposed"].is_u64() && z["grade"].is_string(), "{p}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// One history point as `pathwarden run` writes it, with or without the
/// risk-scoring figures (completeness, zone counts and status, the plan).
fn write_point(state: &Path, run: &str, at: i64, exposed: usize, newer: bool) {
    let mut p = serde_json::json!({
        "version": 1, "run_id": run, "at": at, "collected_at": null,
        "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": exposed,
        "tier_zero_population": 100, "tier_zero_relevant_population": 100,
        "exposure_basis": 2, "tier_zero_objects": 5, "protection_score": 80.0,
        "findings": {"attack_path": 1, "hygiene": 0, "suppressed": 0, "critical": 0,
            "high": 1, "medium": 0, "low": 0, "info": 0},
        "changes": {"new": 0, "open": 1, "regressed": 0, "suppressed": 0, "resolved": 0},
        "zones": [{"zone": "Finance", "exposure_percent": 1.0, "protection_score": null}],
    });
    if newer {
        p["tier_zero_grade"] = "High".into();
        p["plan"] = serde_json::json!({"steps": 3, "exposed_after": 0});
        p["changes"]["resolved"] = 1.into();
        p["completeness"] = serde_json::json!({
            "computers": 50, "sessions_collected": 6, "sessions_percent": 12.0,
            "member_computers": 50, "local_groups_collected": 6,
            "local_groups_percent": 12.0, "low_domains": 1,
        });
        p["zones"] = serde_json::json!([
            {"zone": "Finance", "exposure_percent": 1.0, "protection_score": null,
                "objects": 4, "exposed": 2, "grade": "High"},
            {"zone": "Payments and treasury servers of the European subsidiaries",
                "exposure_percent": 1.0, "protection_score": null,
                "objects": 3, "exposed": 9, "grade": "Critical"},
        ]);
    }
    let dir = state.join("history");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{run}.json")), p.to_string()).unwrap();
}

/// A point written before the risk-scoring figures next to one with them: the table
/// shows "-" for what the older one lacks, "since the last run" compares
/// only what both have (and the zone new in the later one), names the
/// finding the state says was fixed, and every line fits in 120 columns.
/// `--since --json` carries the same comparison as the app's API.
#[test]
fn history_over_an_older_point() {
    let dir = scratch("older");
    let state = dir.join("state");
    write_point(&state, "20261009T000000Z", 1_791_504_000, 40, false);
    write_point(&state, "20261010T000000Z", 1_791_590_400, 52, true);
    std::fs::write(
        state.join("findings.json"),
        serde_json::json!({"version": 1, "findings": {"f1": {
            "rule": "PW-003", "severity": "high", "category": "attack_path",
            "status": "resolved", "first_seen": 1_791_504_000, "last_seen": 1_791_504_000,
            "resolved_at": 1_791_590_400, "times_seen": 1,
            "title": "DEMO-USER has GenericAll on DEMO-DC01"}}})
        .to_string(),
    )
    .unwrap();
    let state_arg = state.to_string_lossy().into_owned();
    let text = pw(&dir, &["history", "--state", &state_arg], &[]);
    assert!(
        text.starts_with(
            "Since the last run (20261009T000000Z):\n  ! 12 more accounts with an attack path to Tier Zero (40 → 52)\n      see: pathwarden plan\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  ! New zone Payments and treasury servers of the Eu…: 9 accounts with an attack path to it\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "      see: pathwarden plan '--zone=Payments and treasury servers of the European subsidiaries'\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  + 1 finding fixed\n      High PW-003 DEMO-USER has GenericAll on DEMO-DC01\n"
        ),
        "{text}"
    );
    // The older point has no status, plan, completeness or zone counts:
    // nothing is compared on them.
    let block = text
        .split(
            "

",
        )
        .next()
        .unwrap();
    for missing in ["status:", "Choke points", "Sessions:", "Finance"] {
        assert!(!block.contains(missing), "{missing}: {text}");
    }
    // Nor anywhere else: only the zone's trend line names it.
    for missing in ["status:", "Choke points", "Sessions:"] {
        assert!(!text.contains(missing), "{missing}: {text}");
    }
    assert!(
        text.contains("  The commands take the collection (-i) and your settings (-c or --env).\n"),
        "{text}"
    );
    assert!(
        text.contains("20261009T000000Z           40     1.00%    80.00%       -             -"),
        "{text}"
    );
    assert!(
        text.contains("20261010T000000Z           52     1.00%    80.00%       3  12.00/12.00%"),
        "{text}"
    );
    assert!(text.lines().all(|l| l.chars().count() <= 120), "{text}");

    // The points as JSON: the older one simply lacks the new figures.
    let pts = points(&dir, &state_arg);
    assert!(pts[0].get("completeness").is_none() && pts[0].get("plan").is_none());
    assert!(pts[0]["zones"][0].get("exposed").is_none());
    assert_eq!(pts[1]["completeness"]["low_domains"], 1);
    assert_eq!(pts[1]["zones"][1]["grade"], "Critical");

    // Only the comparison, as text and as the app's JSON.
    let since = pw(&dir, &["history", "--state", &state_arg, "--changes"], &[]);
    assert!(
        since.starts_with("Since the last run (") && !since.contains("Run (ID"),
        "{since}"
    );
    let v: serde_json::Value = serde_json::from_str(&pw(
        &dir,
        &["history", "--state", &state_arg, "--since", "--json"],
        &[],
    ))
    .unwrap();
    assert_eq!(v["previous_run"], "20261009T000000Z");
    assert_eq!(v["tier_zero"]["after"], 52);
    assert_eq!(v["new_zones"][0]["exposed"], 9);
    assert_eq!(v["findings"]["top_fixed"][0]["rule"], "PW-003");
    assert_eq!(v["lines"][0]["next"], serde_json::json!(["plan"]));
    assert!(v.get("completeness").is_none(), "{v}");

    // One run only: nothing to compare with.
    std::fs::remove_file(state.join("history").join("20261009T000000Z.json")).unwrap();
    let v = pw(
        &dir,
        &["history", "--state", &state_arg, "--since", "--json"],
        &[],
    );
    assert_eq!(v.trim(), "null");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--range` keeps the runs of the last week, month or three months up to
/// the latest run, as the app's Progress switch does; the trend lines
/// include the attack path findings and the zones, from the first run that
/// recorded them.
#[test]
fn history_over_a_range_with_tier_trends() {
    let dir = scratch("range");
    let state = dir.join("state");
    let day = 86_400;
    let latest = 1_791_590_400;
    write_point(&state, "20260801T000000Z", latest - 70 * day, 60, false);
    write_point(&state, "20261005T000000Z", latest - 5 * day, 40, true);
    write_point(&state, "20261010T000000Z", latest, 52, true);
    let state_arg = state.to_string_lossy().into_owned();
    let rows = |text: &str| text.lines().filter(|l| l.starts_with("2026")).count();

    let all = pw(
        &dir,
        &["history", "--state", &state_arg, "--range", "all"],
        &[],
    );
    assert_eq!(rows(&all), 3, "{all}");
    let week = pw(
        &dir,
        &["history", "--state", &state_arg, "--range", "1w"],
        &[],
    );
    assert_eq!(rows(&week), 2, "{week}");
    assert!(week.contains("2 runs, "), "{week}");
    // It says what it left out, as the app's note does; All says nothing.
    assert!(
        week.contains(
            "
The week up to the latest run: 2 of 3 runs. `--range all` shows every run.
"
        ),
        "{week}"
    );
    assert!(!all.contains("up to the latest run"), "{all}");
    // The comparison stays with the latest run.
    assert!(
        week.starts_with("Since the last run (20261005T000000Z):"),
        "{week}"
    );
    let quarter = pw(
        &dir,
        &["history", "--state", &state_arg, "--range", "3m"],
        &[],
    );
    assert_eq!(rows(&quarter), 3, "{quarter}");
    let v: serde_json::Value = serde_json::from_str(&pw(
        &dir,
        &["history", "--state", &state_arg, "--range", "1m", "--json"],
        &[],
    ))
    .unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
    // With --last, the fewer of the two.
    let one = pw(
        &dir,
        &[
            "history", "--state", &state_arg, "--range", "1m", "--last", "1",
        ],
        &[],
    );
    assert_eq!(rows(&one), 1, "{one}");
    // The note counts the rows printed, and names the range's.
    assert!(
        one.contains(
            "
The latest 1 of the 2 runs in the month up to the latest run (3 in all). `--range all` shows every run.
"
        ),
        "{one}"
    );
    assert!(!one.contains("Progress page"), "{one}");

    // The trends: attack path findings, and each zone from the first run
    // that counted it (the oldest did not).
    assert!(all.contains("    on attack paths   "), "{all}");
    assert!(
        all.contains("  Finance             ▄▄  2 → 2 accounts, 4 → 4 objects\n"),
        "{all}"
    );
    assert!(
        all.contains("  Payments and tre…   ▄▄  9 → 9 accounts, 3 → 3 objects\n"),
        "{all}"
    );
    assert!(all.lines().all(|l| l.chars().count() <= 120), "{all}");
    assert!(!all.contains("Progress page"), "{all}");

    // Past the app's cap, it says which view charts fewer: All without a
    // range, and the same range with one.
    for k in 0..40 {
        let run = format!("20261001T00{k:02}00Z");
        write_point(&state, &run, latest - 9 * day + k * 60, 50, true);
    }
    let all = pw(&dir, &["history", "--state", &state_arg], &[]);
    assert!(
        all.contains(
            "With All, the app's Progress page charts the latest 40 of these 43 runs.
"
        ),
        "{all}"
    );
    let month = pw(
        &dir,
        &["history", "--state", &state_arg, "--range", "1m"],
        &[],
    );
    assert!(
        month.contains(
            "
The month up to the latest run: 42 of 43 runs. `--range all` shows every run.
On the same range, the app's Progress page charts the latest 40 of these 42 runs.
"
        ),
        "{month}"
    );
    let few = pw(
        &dir,
        &["history", "--state", &state_arg, "--last", "40"],
        &[],
    );
    assert!(!few.contains("Progress page"), "{few}");

    // Anything else is refused, naming the choices.
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["history", "--state", &state_arg, "--range", "2w"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("use 1w, 1m, 3m or all"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A report with What changed's count markup taken out: the lines' text.
/// The report's What changed rows as text, a cell each ("5", "fewer
/// accounts with an attack path to Tier Zero", "11 → 6").
fn rows(html: &str) -> Vec<Vec<String>> {
    let Some(table) = html.split(r#"<table class="wc-table">"#).nth(1) else {
        return Vec::new();
    };
    let table = table.split("</table>").next().unwrap();
    table
        .split("<tr ")
        .skip(1)
        .map(|r| {
            let r = r.split("</tr>").next().unwrap();
            // After the row's own tag.
            r[r.find('>').unwrap() + 1..]
                .split("</td>")
                .map(|c| {
                    // The hidden word, the mark and the brief are not the
                    // cell's text.
                    let c = c
                        .replace(r#"<span class="vh">Worse: </span>"#, "")
                        .replace(r#"<span class="vh">Better: </span>"#, "");
                    let c = match c.find(r#"<span class="wc-brief">"#) {
                        Some(at) => c[..at].to_string(),
                        None => c,
                    };
                    let mut out = String::new();
                    let mut tag = false;
                    for ch in c.chars() {
                        match ch {
                            '<' => tag = true,
                            '>' => tag = false,
                            _ if !tag => out.push(ch),
                            _ => {}
                        }
                    }
                    out.replace("&#9650;", "")
                        .replace("&#9660;", "")
                        .replace("&#8226;", "")
                        .trim()
                        .to_string()
                })
                .collect()
        })
        .collect()
}

/// A row says a line of `pathwarden history`: its count, its words, and
/// the before and after in a cell of their own.
fn row_says(row: &[String], text: &str) -> bool {
    let (count, rest) = match text.split_once(' ') {
        Some((n, r)) if n.chars().all(|c| c.is_ascii_digit() || c == ',') => (n, r),
        _ => ("", text),
    };
    let (what, ba) = match (rest.find(" ("), rest.find(')')) {
        (Some(o), Some(c)) if rest[o..c].contains('→') => {
            (format!("{}{}", &rest[..o], &rest[c + 1..]), &rest[o + 2..c])
        }
        _ => (rest.to_string(), ""),
    };
    row.len() >= 3 && row[0] == count && row[1] == what && row[2] == ba
}

/// A copy of `testdata/forest` as a Quick (DC only) collection writes it:
/// every session list not collected for the built-in collector's reason,
/// no local groups.
fn quick_copy(dir: &Path) -> PathBuf {
    let out = dir.join("quick");
    std::fs::create_dir_all(&out).unwrap();
    for entry in std::fs::read_dir(repo("testdata/forest")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": pathwarden_core::ingest::NOT_CONTACTED});
                }
                c["LocalGroups"] = serde_json::json!([]);
                c.as_object_mut().unwrap().remove("LocalAdmins");
            }
        }
        std::fs::write(
            out.join(path.file_name().unwrap()),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
    }
    out
}

/// Full, then Quick, then Full: the Quick run says "not targeted" and is
/// not compared with the Full one, fixes no attack path it can't see, and
/// the second Full run compares with the first.
#[test]
fn a_quick_run_is_not_targeted_and_never_a_false_win() {
    let dir = scratch("quick");
    let state = dir.join("state");
    let state_arg = state.to_string_lossy().into_owned();
    let full = repo("testdata/forest").to_string_lossy().into_owned();
    let quick = quick_copy(&dir).to_string_lossy().into_owned();
    let run = |input: &str| {
        // Run IDs carry the second they were made in.
        std::thread::sleep(Duration::from_millis(1100));
        pw(
            &dir,
            &["run", "-i", input, "--state", &state_arg, "--no-push"],
            &[],
        )
    };
    let first = run(&full);
    assert!(!first.contains("not collected"), "{first}");
    let second = run(&quick);
    let since = second
        .split("\nSince the last run (")
        .nth(1)
        .expect(&second);
    assert!(
        since.contains(
            "Sessions and local groups weren't collected in this run, so this run's counts aren't compared with the last run."
        ),
        "{since}"
    );
    assert!(!since.contains("fewer accounts"), "{since}");
    assert!(!since.contains("Sessions: 0%"), "{since}");
    // The summary says it once, without the incomplete-collection warning.
    assert!(
        second.contains(
            "Note: Sessions and local groups weren't collected in this run. Paths through \
             sessions and local administrator rights are not in this run."
        ),
        "{second}"
    );
    assert!(!second.contains("incomplete collection"), "{second}");
    // No attack path is fixed by a run that can't see sessions.
    let pts = points(&dir, &state_arg);
    assert_eq!(pts.len(), 2);
    assert_eq!(pts[1]["changes"]["resolved"], 0, "{}", pts[1]);
    assert!(
        pts[1]["changes"]["held"].as_u64().unwrap() > 0,
        "{}",
        pts[1]
    );
    assert_eq!(pts[1]["completeness"]["sessions_targeted"], false);
    assert_eq!(pts[1]["completeness"]["local_groups_targeted"], false);
    assert_eq!(pts[0]["completeness"]["sessions_targeted"], true);

    // The posture and the history table say "not targeted".
    let posture = pw(&dir, &["posture", "-i", &quick], &[]);
    assert!(
        posture.contains("sessions not collected   local groups not collected"),
        "{posture}"
    );
    assert!(
        posture.contains(
            "  Not collected: this collection read the directory only, so paths through \
             sessions and local administrator rights are not in this run."
        ),
        "{posture}"
    );
    assert!(!posture.contains("Below 80%"), "{posture}");
    let json: serde_json::Value =
        serde_json::from_str(&pw(&dir, &["posture", "-i", &quick, "--json"], &[])).unwrap();
    assert_eq!(json["completeness"][0]["sessions_targeted"], false);
    assert_eq!(json["completeness"][0]["sessions_percent"], 0.0);

    // The second Full run compares with the first, not the Quick one.
    let third = run(&full);
    let since = third.split("\nSince the last run (").nth(1).expect(&third);
    assert!(
        since.starts_with(pts[0]["run_id"].as_str().unwrap()),
        "{since}"
    );
    assert!(!since.contains("not collected"), "{since}");
    let history = pw(&dir, &["history", "--state", &state_arg], &[]);
    assert!(history.contains(" not collected"), "{history}");
    assert!(
        history.contains("  Not every run read sessions and local groups (see Collected)"),
        "{history}"
    );
    assert!(
        history.contains("; not collected (or -): the run didn't ask for them."),
        "{history}"
    );
}
