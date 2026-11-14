//! `--env NAME`: an environment of the UI workspace stands in for
//! `--config` and `--state`, so a scheduled CLI run and the app share one
//! environment's settings and history, and never another's.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn testdata(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

/// A workspace with Default (which accepts a risk) and Lab (which doesn't).
fn workspace(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-cli-envs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("environments/lab")).unwrap();
    std::fs::write(
        dir.join("environments.json"),
        r#"{"environments":[{"id":"default","name":"Default"},{"id":"lab","name":"Lab"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[[suppress]]\nfingerprint = \"PW-003-39f2ede7c479090b\"\nreason = \"Default only\"\n",
    )
    .unwrap();
    dir
}

/// The accepted-risk reason of PW-003-39f2ede7c479090b, if it is accepted.
fn accepted(out: &std::process::Output) -> Option<String> {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = v
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["fingerprint"] == "PW-003-39f2ede7c479090b")
        .unwrap();
    f["suppressed"].as_str().map(str::to_string)
}

/// `findings` says who accepted a risk, in text and in `--json`.
#[test]
fn findings_say_who_accepted_a_risk() {
    let ws = workspace("who");
    std::fs::write(
        ws.join("pathwarden.toml"),
        "[[suppress]]\nfingerprint = \"PW-003-39f2ede7c479090b\"\nreason = \"Default only\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"PW-SCHED01\"\naccepted_at = \"2026-10-22T14:03:11Z\"\n[[suppress.notes]]\ntext = \"Checked.\"\n",
    )
    .unwrap();
    let w = ws.to_string_lossy().into_owned();
    let forest = testdata("forest");
    let out = run(
        &ws,
        &[
            "findings",
            "-i",
            &forest,
            "--json",
            "--show-suppressed",
            "--env",
            "default",
            "--workspace",
            &w,
        ],
    );
    assert_eq!(accepted(&out).as_deref(), Some("Default only"));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = v
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["fingerprint"] == "PW-003-39f2ede7c479090b")
        .unwrap();
    assert_eq!(f["accepted"]["accepted_by"], "NORTH\\eddard.stark");
    assert_eq!(f["accepted"]["accepted_on"], "PW-SCHED01");
    assert_eq!(f["accepted"]["notes"][0]["text"], "Checked.");
    let out = run(
        &ws,
        &[
            "findings",
            "-i",
            &forest,
            "--show-suppressed",
            "--env",
            "default",
            "--workspace",
            &w,
        ],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("  ACCEPTED RISK: Default only\n    accepted by NORTH\\eddard.stark on PW-SCHED01, Oct 22, 2026; 1 note\n"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn env_picks_the_environments_config_and_history() {
    let ws = workspace("config");
    let w = ws.to_string_lossy().into_owned();
    let forest = testdata("forest");
    let findings = |env: &str| {
        run(
            &ws,
            &[
                "findings",
                "-i",
                &forest,
                "--json",
                "--show-suppressed",
                "--env",
                env,
                "--workspace",
                &w,
            ],
        )
    };
    // By name or ID, any case.
    assert_eq!(
        accepted(&findings("default")).as_deref(),
        Some("Default only")
    );
    assert_eq!(
        accepted(&findings("LAB")),
        None,
        "Default's risk is not Lab's"
    );

    // `run --env Lab` records into Lab's history only.
    let out = run(
        &ws,
        &[
            "run",
            "-i",
            &forest,
            "--env",
            "Lab",
            "--workspace",
            &w,
            "--no-push",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ws
        .join("environments/lab/pathwarden-state/history")
        .is_dir());
    assert!(!ws.join("pathwarden-state").exists());
    let out = run(
        &ws,
        &["history", "--env", "lab", "--workspace", &w, "--json"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v.as_array().map(Vec::len), Some(1), "{v}");

    // An unknown name is an error that lists the environments.
    let out = findings("Prod");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("No environment named") && err.contains("(there is: default, Lab)"),
        "{err}"
    );
    // --env and --config don't go together.
    let out = run(
        &ws,
        &[
            "findings",
            "-i",
            &forest,
            "--env",
            "Lab",
            "-c",
            "x.toml",
            "--workspace",
            &w,
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&ws);
}

/// `report --env` after a run of the same data, the nightly pattern: the
/// report is of that run, so it compares with the run before it, never
/// with itself.
#[test]
fn a_report_of_the_last_runs_data_compares_with_the_run_before() {
    let ws = workspace("report");
    let w = ws.to_string_lossy().into_owned();
    let forest = testdata("forest");
    let pingcastle = testdata("pingcastle/ad_hc_contoso.local.xml");
    let ok = |out: std::process::Output| {
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let run_on = |inputs: &[&str]| {
        let mut args = vec!["run"];
        for i in inputs {
            args.extend(["-i", i]);
        }
        args.extend(["--env", "Default", "--workspace", &w, "--no-push"]);
        ok(run(&ws, &args));
    };
    let report = || {
        ok(run(
            &ws,
            &[
                "report",
                "-i",
                &forest,
                "--env",
                "Default",
                "--workspace",
                &w,
                "-o",
                "r.html",
            ],
        ));
        std::fs::read_to_string(ws.join("r.html")).unwrap()
    };
    // One run of this data: nothing before it to compare with.
    run_on(&[&forest]);
    let html = report();
    assert!(html.contains(r#"<div class="hero card solo">"#));
    assert!(!html.contains(r#"<span class="since">"#));
    assert!(!html.contains("last 2 runs"));
    // Other data (a PingCastle report too), then this data again: the
    // report stands for the last run and compares with the one before.
    let _ = std::fs::remove_dir_all(ws.join("pathwarden-state"));
    run_on(&[&forest, &pingcastle]);
    run_on(&[&forest]);
    let html = report();
    assert!(
        html.contains("last 2 runs"),
        "the report is not a third point"
    );
    assert!(html.contains(r#"<span class="since">"#));
    let _ = std::fs::remove_dir_all(&ws);
}

/// An environment still holding the reserved ID `removed` (its
/// folder holds removals, so it can't get another by itself) is said by
/// `pathwarden env list`, as on the Environments page.
/// A first environment whose history is only in a folder given with
/// `pathwarden ui --state` is recorded as used in the registry, so
/// `env list` shows it too (not only the app that was given the folder).
#[test]
fn env_list_shows_a_default_used_through_a_state_folder() {
    let ws = workspace("state-used");
    let w = ws.to_string_lossy().into_owned();
    std::fs::remove_file(ws.join("pathwarden.toml")).unwrap();
    let ids = |ws: &Path| -> Vec<String> {
        let out = run(ws, &["env", "list", "--json", "--workspace", &w]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(ids(&ws), ["lab"], "an unused Default is left out");
    std::fs::write(
        ws.join("environments.json"),
        r#"{"environments":[{"id":"default","name":"Default"},{"id":"lab","name":"Lab"}],"default_used":true}"#,
    )
    .unwrap();
    assert_eq!(ids(&ws), ["default", "lab"]);
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn env_list_says_when_an_old_removed_id_is_stuck() {
    let ws = workspace("stuck");
    let w = ws.to_string_lossy().into_owned();
    std::fs::write(
        ws.join("environments.json"),
        r#"{"environments":[{"id":"default","name":"Default"},{"id":"removed","name":"Old removed"}]}"#,
    )
    .unwrap();
    let rec = ws.join("environments/removed/lab-20261001-000000");
    std::fs::create_dir_all(&rec).unwrap();
    std::fs::write(
        rec.join("removal.json"),
        r#"{"id":"lab","name":"Lab","entry":{"id":"lab","name":"Lab"},"started_at":1,"done":true}"#,
    )
    .unwrap();
    let out = run(&ws, &["env", "list", "--workspace", &w]);
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Warning:")
            && err.contains("Old removed still has the reserved ID")
            && err.contains("also holds earlier removals")
            && err.contains("summary.json")
            && !err.contains("Nothing was removed"),
        "{err}"
    );
    // The app's start got as far as the rename and then failed (a locked
    // summary.json): what it kept in the workspace is said here too, not
    // "the next start gives it another".
    std::fs::remove_dir_all(ws.join("environments/removed")).unwrap();
    let moved = ws.join("environments/removed-2");
    std::fs::create_dir_all(&moved).unwrap();
    std::fs::write(moved.join("renamed-from-removed.txt"), "x").unwrap();
    std::fs::write(
        ws.join("reserved-id-problem.json"),
        r#"{"name":"Old removed","why":"a run summary could not be changed (locked)","steps":["its folder is removed-2 already: change its \"id\" in environments.json to \"removed-2\"","in each of its runs' summary.json, change \"environment\": \"removed\" to \"removed-2\""]}"#,
    )
    .unwrap();
    let out = run(&ws, &["env", "list", "--workspace", &w]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Old removed still has the reserved ID")
            && err.contains("a run summary could not be changed (locked)")
            && err.contains("tries again")
            && !err.contains("gives it another"),
        "{err}"
    );
    // Once it has another ID, nothing is said.
    std::fs::write(
        ws.join("environments.json"),
        r#"{"environments":[{"id":"default","name":"Default"},{"id":"removed-2","name":"Old removed"}]}"#,
    )
    .unwrap();
    let out = run(&ws, &["env", "list", "--workspace", &w]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("Warning:"));
    let _ = std::fs::remove_dir_all(&ws);
}
