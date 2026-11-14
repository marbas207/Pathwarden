//! What is net new over a period: `pathwarden changes` and
//! `pathwarden findings --introduced`, over two runs of the demo whose
//! settings differ (a group added to Tier Zero, a group added to a zone), so
//! the second run has new findings, findings that gained objects and new
//! paths into Tier Zero and the zone.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-chg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let (good, out, err) = pw(dir, args);
    assert!(good, "{args:?}: {err}");
    out
}

/// Two runs of the demo into `state`: the second with a server admins group
/// added to Tier Zero and a second one to the zone. Returns the second
/// run's settings.
fn two_runs(dir: &Path) -> String {
    let first = dir.join("first.toml");
    std::fs::write(
        &first,
        "[rules]\ndisabled = [\"PW-002\"]\n\n[[zone]]\nname = \"Servers\"\ngroups = [\"R00S00-SERVERADMINS@SCALE.LOCAL\"]\n",
    )
    .unwrap();
    let second = dir.join("second.toml");
    std::fs::write(
        &second,
        "tier_zero = [\"R01S00-SERVERADMINS@SCALE.LOCAL\"]\n\n[[zone]]\nname = \"Servers\"\ngroups = [\"R00S00-SERVERADMINS@SCALE.LOCAL\", \"R02S00-SERVERADMINS@SCALE.LOCAL\"]\n",
    )
    .unwrap();
    for c in [&first, &second] {
        ok(
            dir,
            &[
                "run",
                "-i",
                "demo:",
                "-c",
                &c.to_string_lossy(),
                "--state",
                "state",
            ],
        );
        // Each run its own second.
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    second.to_string_lossy().into_owned()
}

#[test]
fn changes_and_findings_introduced_say_what_is_net_new() {
    let dir = scratch("net-new");
    let second = two_runs(&dir);

    // The text: the same lines the app's Progress page lists.
    let text = ok(&dir, &["changes", "--state", "state"]);
    assert!(
        text.starts_with("Introduced since the last run (first seen by Pathwarden):\n"),
        "{text}"
    );
    assert!(text.contains("  ! 27 new findings\n"), "{text}");
    assert!(text.contains("older findings gained"), "{text}");
    assert!(text.contains("new paths into Tier Zero\n"), "{text}");
    assert!(text.contains("new paths into Servers\n"), "{text}");
    // The server admins added to Tier Zero are new members of it: no edge
    // from outside shows them.
    assert!(text.contains("new members of Tier Zero\n"), "{text}");
    assert!(text.contains("      see: pathwarden tier-zero\n"), "{text}");
    assert!(
        text.contains("      see: pathwarden findings --introduced last\n"),
        "{text}"
    );
    assert!(
        text.contains("      see: pathwarden plan --zone=Servers\n"),
        "{text}"
    );
    // Without the collection, objects and paths are counted, not named.
    assert!(
        text.contains("With -i (the collection), the objects and paths are named."),
        "{text}"
    );

    // JSON, name-free: the period, the lines, everything in `introduced`.
    let v: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["changes", "--state", "state", "--json"])).unwrap();
    assert_eq!(v["period"], "last");
    assert_eq!(v["latest_run"], 2);
    assert_eq!(v["named"], false);
    assert!(v["note"].is_null(), "the last run is after tracking began");
    let paths = v["introduced"]["paths"].as_array().unwrap();
    assert_eq!(paths[0]["zone"], "Tier Zero");
    let t0 = paths[0]["new"].as_array().unwrap();
    assert!(!t0.is_empty());
    assert!(t0[0]["from"].is_null(), "no names without -i");
    assert_eq!(t0[0]["run"], 2);
    // Finding titles and domain names are kept (0.1.7); what was
    // introduced on paths is not named without -i.
    let text_json = serde_json::to_string(&v["introduced"]["paths"]).unwrap();
    assert!(
        !text_json.contains("SCALE.LOCAL"),
        "paths are not named without -i: {text_json}"
    );

    // With -i, named: each path's ends and the step that cuts it, each
    // gained object's name.
    let v: serde_json::Value = serde_json::from_str(&ok(
        &dir,
        &[
            "changes", "--state", "state", "-i", "demo:", "-c", &second, "--json",
        ],
    ))
    .unwrap();
    assert_eq!(v["named"], true);
    let p = &v["introduced"]["paths"][0]["new"][0];
    assert!(p["from"].as_str().unwrap().ends_with("SCALE.LOCAL"), "{p}");
    assert!(p["edge"].is_string() && p["from_id"].is_string(), "{p}");
    assert!(p["cut"]["by"].is_string(), "the plan cuts every path: {p}");
    let gained: Vec<&serde_json::Value> = v["introduced"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["badge"].is_object())
        .collect();
    assert!(!gained.is_empty());
    let o = &gained[0]["objects"][0];
    assert!(o["name"].as_str().unwrap().ends_with("@SCALE.LOCAL"), "{o}");
    assert!(
        o["label"].as_str().unwrap().starts_with("first seen "),
        "{o}"
    );
    assert!(o["label"].as_str().unwrap().ends_with("(run 2)"), "{o}");
    let joined = v["introduced"]["paths"][0]["joined"].as_array().unwrap();
    assert!(
        joined
            .iter()
            .any(|m| m["via"] == "R01S00-SERVERADMINS@SCALE.LOCAL"),
        "{joined:?}"
    );

    // --paths lists every new member and path, not only the first three,
    // each path with the step that cuts it.
    let listed = ok(
        &dir,
        &[
            "changes", "--state", "state", "-i", "demo:", "-c", &second, "--paths",
        ],
    );
    let t0_paths = t0.len();
    assert!(t0_paths > 3, "more than a line names: {t0_paths}");
    let rest = listed
        .split("New in Tier Zero and the zones:\n")
        .nth(1)
        .expect("the listing");
    let tier_zero = rest.split("\n  Servers\n").next().unwrap();
    assert_eq!(
        tier_zero.matches("\n    path    ").count(),
        t0_paths,
        "{tier_zero}"
    );
    assert!(
        tier_zero.contains(" · step ") || tier_zero.contains(" · no single step; see the plan"),
        "{tier_zero}"
    );
    assert!(tier_zero.contains("\n    member  "), "{tier_zero}");
    assert!(!tier_zero.contains(" more\n"), "{tier_zero}");
    let (good, _, err) = pw(&dir, &["changes", "--state", "state", "--paths"]);
    assert!(!good && err.contains("--input"), "--paths needs -i: {err}");

    // The whole history reaches back to the run tracking began in.
    let all = ok(&dir, &["changes", "--state", "state", "--since", "all"]);
    assert!(
        all.contains("Objects and paths are dated from ") && all.contains(" (run 1) on;"),
        "{all}"
    );

    // findings --introduced: only those, each with its badge, the gained
    // objects first.
    let listed: Vec<serde_json::Value> = serde_json::from_str(&ok(
        &dir,
        &[
            "findings",
            "-i",
            "demo:",
            "-c",
            &second,
            "--state",
            "state",
            "--introduced",
            "last",
            "--json",
        ],
    ))
    .unwrap();
    let new = listed
        .iter()
        .filter(|f| f["introduced"]["badge"] == "new")
        .count();
    assert_eq!(new, 27);
    assert!(listed.iter().all(|f| f["introduced"]["label"].is_string()));
    let text = ok(
        &dir,
        &[
            "findings",
            "-i",
            "demo:",
            "-c",
            &second,
            "--state",
            "state",
            "--introduced",
            "last",
            "--rule",
            "PW-008",
        ],
    );
    assert!(
        text.contains("Introduced since the last run (first seen by Pathwarden): 1 finding"),
        "{text}"
    );
    assert!(text.contains("  introduced: +"), "{text}");
    let all_new = ok(
        &dir,
        &[
            "findings",
            "-i",
            "demo:",
            "-c",
            &second,
            "--state",
            "state",
            "--introduced",
            "last",
        ],
    );
    assert!(
        all_new.contains("  introduced: New, first seen "),
        "{all_new}"
    );
    let affected = text.split("  affected (").nth(1).expect(&text);
    let first = affected.lines().nth(1).unwrap();
    assert!(first.contains("  first seen "), "gained first: {affected}");

    // --since takes a day; a period goes to --introduced.
    let (good, _, err) = pw(
        &dir,
        &[
            "findings", "-i", "demo:", "--state", "state", "--since", "7d",
        ],
    );
    assert!(!good && err.contains("is not a day"), "{err}");
    // Junk, and periods that end in a character of more than one byte:
    // an error, never a panic.
    for bad in ["soon", "7\u{e9}", "7\u{65e5}", "\u{e9}"] {
        let out = Command::new(bin())
            .current_dir(&dir)
            .args(["changes", "--state", "state", "--since", bad])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{bad}: {err}");
        assert!(
            err.contains("is not a period") && !err.contains("panicked"),
            "{err}"
        );
    }
    // --state goes with a period.
    let (good, _, err) = pw(&dir, &["findings", "-i", "demo:", "--state", "state"]);
    assert!(!good && err.contains("--introduced"), "{err}");
    let old = ok(
        &dir,
        &[
            "findings",
            "-i",
            "demo:",
            "-c",
            &second,
            "--state",
            "state",
            "--since",
            "2020-01-01",
            "--json",
        ],
    );
    let old: Vec<serde_json::Value> = serde_json::from_str(&old).unwrap();
    assert!(old.len() > 27, "everything is new since 2020");
    // --fail-on counts only the findings introduced in the period.
    let code = |since: &str| {
        Command::new(bin())
            .current_dir(&dir)
            .args([
                "findings",
                "-i",
                "demo:",
                "-c",
                &second,
                "--state",
                "state",
                "--since",
                since,
                "--fail-on",
                "high",
            ])
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(code("2020-01-01"), Some(1), "new high findings");
    assert_eq!(code("2099-01-01"), Some(0), "nothing introduced");
    // changes --fail-on: anything new, or a severity.
    let changes_code = |args: &[&str]| {
        Command::new(bin())
            .current_dir(&dir)
            .args(["changes", "--state", "state"])
            .args(args)
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(changes_code(&["--fail-on", "new"]), Some(1));
    assert_eq!(changes_code(&["--fail-on", "info", "--json"]), Some(1));
    assert_eq!(
        changes_code(&["--fail-on", "new", "--since", "2099-01-01"]),
        Some(0)
    );
    assert_eq!(changes_code(&["--fail-on", "soon"]), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// With one run there is no run before to compare with: `changes` says so,
/// as the report and Progress offer no "since the last run" then.
#[test]
fn one_run_has_nothing_to_compare_with() {
    let dir = scratch("one");
    ok(&dir, &["run", "-i", "demo:", "--state", "state"]);
    let text = ok(&dir, &["changes", "--state", "state"]);
    assert!(
        text.contains("No run before this one to compare with."),
        "{text}"
    );
    assert!(!text.contains("new findings"), "{text}");
    let v: serde_json::Value =
        serde_json::from_str(&ok(&dir, &["changes", "--state", "state", "--json"])).unwrap();
    assert_eq!(v["reason"], "No run before this one to compare with.");
    assert!(v["introduced"].is_null() && v["lines"].as_array().unwrap().is_empty());
    let listed: Vec<serde_json::Value> = serde_json::from_str(&ok(
        &dir,
        &[
            "findings",
            "-i",
            "demo:",
            "--state",
            "state",
            "--introduced",
            "last",
            "--json",
        ],
    ))
    .unwrap();
    assert!(listed.is_empty(), "{listed:?}");
    // A longer period still lists the first run's findings as new.
    let all = ok(&dir, &["changes", "--state", "state", "--since", "all"]);
    assert!(all.contains("new findings"), "{all}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// One state folder holding two environments (two collections of other
/// domains, run in turn): each environment's period lists only its own
/// findings, members and paths, and the other's runs neither make its
/// Tier Zero new nor hold its edges open.
#[test]
fn environments_sharing_a_state_keep_apart() {
    let dir = scratch("two-envs");
    let data = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(name)
            .to_string_lossy()
            .into_owned()
    };
    let (forest, adcs) = (data("forest"), data("adcs"));
    for input in [&forest, &adcs, &forest, &adcs] {
        ok(&dir, &["run", "-i", input, "--state", "state"]);
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    let period = |input: &str, since: &str| -> serde_json::Value {
        serde_json::from_str(&ok(
            &dir,
            &[
                "changes", "--state", "state", "-i", input, "--since", since, "--json",
            ],
        ))
        .unwrap()
    };
    for (input, other) in [(&forest, "PKI.LOCAL"), (&adcs, "CONTOSO.LOCAL")] {
        // Since the last run: the environment's run before it was two runs
        // ago, the other's in between. Nothing changed in either.
        let last = period(input, "last");
        assert_eq!(
            last["lines"][0]["text"], "Nothing new, and nothing fixed",
            "{input}: {last}"
        );
        assert_eq!(last["latest_run"], 2, "{input}");
        // Over the week: its own first run's findings, members and paths
        // are the baseline, and none of the other's.
        let week = period(input, "7d");
        let text = serde_json::to_string(&week["lines"]).unwrap();
        assert!(!text.contains("new member"), "{input}: {text}");
        assert!(!text.contains("new path"), "{input}: {text}");
        assert!(!text.contains(" gone"), "{input}: {text}");
        assert!(!text.contains(" left "), "{input}: {text}");
        let named = serde_json::to_string(&week["introduced"]).unwrap();
        assert!(!named.contains(other), "{input}: {named}");
        // Its findings only: the analysis of its own collection names
        // each (the state keeps no names), so one of the other's would
        // have no title.
        let findings = week["introduced"]["findings"].as_array().unwrap();
        assert!(
            !findings.is_empty(),
            "{input}: its first run is in the week"
        );
        assert!(
            findings.iter().all(|f| f["title"].is_string()),
            "{input}: {findings:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn changes_needs_a_history() {
    let dir = scratch("none");
    let (good, _, err) = pw(&dir, &["changes", "--state", "nothing-here"]);
    assert!(!good && err.contains("No run history at"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
