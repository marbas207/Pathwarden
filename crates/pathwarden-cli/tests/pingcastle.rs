//! A PingCastle report imported with the collection: its findings open,
//! stay open, are held (not resolved) by a run without a report, resolve
//! when the rule stops triggering, and come back as regressions.

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

fn run(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn pingcastle_findings_follow_the_lifecycle() {
    let dir = std::env::temp_dir().join(format!("pathwarden-pc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = testdata("forest");
    let report = testdata("pingcastle/ad_hc_contoso.local.xml");
    let full = std::fs::read_to_string(&report).unwrap();
    // The same domain later, with the password policy fixed.
    let start = full.find("<HealthcheckRiskRule>").unwrap();
    let end = full.find("</HealthcheckRiskRule>").unwrap() + "</HealthcheckRiskRule>".len();
    let fixed = format!("{}{}", &full[..start], &full[end..]);
    assert!(!fixed.contains("A-MinPwdLen"));
    std::fs::write(dir.join("fixed.xml"), fixed).unwrap();

    // 1: 15 findings from the collection plus 2 from PingCastle.
    let first = run(
        &dir,
        &[
            "run", "-i", &forest, "-i", &report, "--state", "st", "--event", "ev.json",
        ],
    );
    assert!(first.contains("17 new, 0 back, 0 fixed"), "{first}");
    let ev: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("ev.json")).unwrap()).unwrap();
    let pc: Vec<&serde_json::Value> = ev["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"].as_str().unwrap().starts_with("PC-"))
        .collect();
    assert_eq!(pc.len(), 2);
    let minpwd = pc.iter().find(|f| f["rule"] == "PC-A-MinPwdLen").unwrap();
    assert_eq!(minpwd["category"], "hygiene");
    assert_eq!(minpwd["severity"], "medium");
    assert_eq!(minpwd["domain"], "CONTOSO.LOCAL");
    assert_eq!(minpwd["sources"][0], "PingCastle");
    let kerb = pc
        .iter()
        .find(|f| f["rule"] == "PC-P-Kerberoasting")
        .unwrap();
    assert_eq!(kerb["severity"], "critical");

    // 2: same inputs, nothing changes.
    let second = run(
        &dir,
        &["run", "-i", &forest, "-i", &report, "--state", "st"],
    );
    assert!(
        second.contains("0 new, 0 back, 0 fixed, 17 still open"),
        "{second}"
    );

    // 3: no report this time: the PingCastle findings are held, not fixed.
    let third = run(
        &dir,
        &["run", "-i", &forest, "--state", "st", "--event", "ev3.json"],
    );
    assert!(
        third.contains("0 fixed")
            && third.contains(" 2 can't tell")
            && third.contains("15 still open"),
        "{third}"
    );
    // The event says so, so ticketing plugins keep their tickets open.
    let ev3: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("ev3.json")).unwrap()).unwrap();
    let held: Vec<&str> = ev3["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["rule"].as_str().unwrap())
        .collect();
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|r| r.starts_with("PC-")), "{held:?}");

    // 4: a new report without the rule: that finding resolves.
    let fourth = run(
        &dir,
        &["run", "-i", &forest, "-i", "fixed.xml", "--state", "st"],
    );
    assert!(fourth.contains("1 fixed"), "{fourth}");

    // 5: it triggers again: a regression.
    let fifth = run(
        &dir,
        &["run", "-i", &forest, "-i", &report, "--state", "st"],
    );
    assert!(fifth.contains("1 back"), "{fifth}");

    // A folder with the collection and the report (by its PingCastle name)
    // reads both, and exports carry the PingCastle findings too.
    let both = dir.join("both");
    std::fs::create_dir_all(&both).unwrap();
    for e in std::fs::read_dir(&forest).unwrap() {
        let e = e.unwrap().path();
        std::fs::copy(&e, both.join(e.file_name().unwrap())).unwrap();
    }
    std::fs::copy(&report, both.join("ad_hc_contoso.local.xml")).unwrap();
    let out = run(&dir, &["export", "defectdojo", "-i", "both"]);
    let dd: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ids: Vec<&str> = dd["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["vuln_id_from_tool"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"PC-A-MinPwdLen"), "{ids:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_report_is_an_error() {
    let dir = std::env::temp_dir().join(format!("pathwarden-pc-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bad.xml"), "<Other/>").unwrap();
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["findings", "-i", &testdata("forest"), "-i", "bad.xml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("bad.xml") && err.contains("HealthcheckData"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
