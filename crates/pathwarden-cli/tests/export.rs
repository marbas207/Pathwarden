//! `pathwarden export` from collector data and from a run's event document.

use std::path::PathBuf;
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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-export-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn sarif_from_collector_data_and_defectdojo_from_an_event() {
    let dir = scratch("both");
    let forest = testdata("forest");

    let out = run(&dir, &["export", "sarif", "-i", &forest]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(log["version"], "2.1.0");
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    assert!(
        results[0]["partialFingerprints"]["pathwardenFingerprint/v1"]
            .as_str()
            .unwrap()
            .starts_with("PW-")
    );

    let out = run(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--state",
            "st",
            "--event",
            "ev.json",
            "--no-push",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(
        &dir,
        &[
            "export",
            "defectdojo",
            "--event",
            "ev.json",
            "-o",
            "dd.json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dd: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("dd.json")).unwrap()).unwrap();
    let findings = dd["findings"].as_array().unwrap();
    assert_eq!(findings.len(), results.len(), "same findings both ways");
    assert!(findings.iter().all(|f| f["unique_id_from_tool"]
        .as_str()
        .is_some_and(|s| s.starts_with("PW-"))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn needs_an_event_or_input_but_not_both() {
    let dir = scratch("args");
    let out = run(&dir, &["export", "sarif"]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(
        &dir,
        &[
            "export",
            "sarif",
            "--event",
            "x.json",
            "-i",
            &testdata("forest"),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    // An event document without findings is refused, not read as "all fixed".
    std::fs::write(dir.join("bad.json"), r#"{"schema":"pathwarden.event.v1"}"#).unwrap();
    let out = run(&dir, &["export", "defectdojo", "--event", "bad.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("findings"));
    let _ = std::fs::remove_dir_all(&dir);
}
