//! `pathwarden config` and `env create/domains/use`: the Settings and
//! Environments pages from the terminal, through the app's own code, with
//! its checks and messages.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn err(out: &std::process::Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A workspace with Default (current) and Lab.
fn workspace(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-config-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("environments/lab")).unwrap();
    std::fs::write(
        dir.join("environments.json"),
        r#"{"current":"default","environments":[{"id":"default","name":"Default"},{"id":"lab","name":"Lab","domains":["LAB.LOCAL"]}]}"#,
    )
    .unwrap();
    dir
}

#[test]
fn rules_and_risks_go_through_the_settings_checks() {
    let dir = workspace("rules");
    let ws = dir.to_str().unwrap();
    // Partial set: the rest keep their defaults.
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "rules",
            "set",
            "--stale-days",
            "60",
            "--disable",
            "pw-011",
        ],
    ));
    let show: serde_json::Value = serde_json::from_str(&ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "rules",
            "show",
            "--json",
        ],
    )))
    .unwrap();
    assert_eq!(show["stale_days"], 60);
    assert_eq!(show["password_age_days"], 365);
    assert_eq!(show["sso_key_age_days"], 30);
    assert_eq!(show["disabled"], serde_json::json!(["PW-011"]));
    // The Seamless SSO key age (PW-037), as the Settings page sets it.
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "rules",
            "set",
            "--sso-key-age-days",
            "45",
        ],
    ));
    let text = std::fs::read_to_string(dir.join("environments/lab/pathwarden.toml")).unwrap();
    assert!(text.contains("sso_key_age_days = 45"), "{text}");
    assert!(text.contains("stale_days = 60"), "{text}");
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "rules",
            "set",
            "--sso-key-age-days",
            "0",
        ],
    ));
    assert!(
        e.contains("Seamless SSO key age days must be a whole number from 1 to 36500"),
        "{e}"
    );
    // Lab's file, not Default's.
    assert!(dir.join("environments/lab/pathwarden.toml").is_file());
    assert!(!dir.join("pathwarden.toml").exists());
    // The app's messages.
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "rules",
            "set",
            "--stale-days",
            "0",
        ],
    ));
    assert!(
        e.contains("Stale account days must be a whole number from 1 to 36500"),
        "{e}"
    );
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "accept",
            "--finding",
            "PW-999-x",
            "--reason",
            "r",
        ],
    ));
    assert!(e.contains("is not a finding ID"), "{e}");
    // A review date already over is refused, as in the Settings page (one
    // check in core).
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "accept",
            "--rule",
            "pw-011",
            "--reason",
            "Kiosks",
            "--review-by",
            "2020-01-01",
        ],
    ));
    assert!(
        e.contains("Jan 1, 2020 has passed. Choose a later date, or none."),
        "{e}"
    );
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "accept",
            "--rule",
            "pw-011",
            "--reason",
            "Kiosks",
            "--review-by",
            "2099-01-01",
        ],
    ));
    let list: serde_json::Value = serde_json::from_str(&ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "list",
            "--json",
        ],
    )))
    .unwrap();
    assert_eq!(list[0]["rule"], "PW-011");
    assert_eq!(list[0]["review_by"], "2099-01-01");
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "remove",
            "1",
        ],
    ));
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "--env",
            "Lab",
            "risk",
            "remove",
            "1",
        ],
    ));
    assert!(e.contains("no accepted risk 1"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `run` as `NORTH\user` on `computer` (Windows' variables; elsewhere the
/// login name alone).
fn run_as(dir: &Path, user: &str, computer: &str, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("USERDOMAIN", "NORTH")
        .env("USERNAME", user)
        .env("USER", user)
        .env("COMPUTERNAME", computer)
        .env("HOSTNAME", computer)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn accepted_risks_say_who_accepted_and_changed_them() {
    let dir = workspace("risk-who");
    let ws = dir.to_str().unwrap();
    let who = |u: &str| {
        if cfg!(windows) {
            format!("NORTH\\{u}")
        } else {
            u.to_string()
        }
    };
    // An entry from before attribution, with a comment.
    std::fs::write(
        dir.join("pathwarden.toml"),
        "# Ours.\n[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\"\n",
    )
    .unwrap();
    let cfg = |args: &[&str]| {
        let mut all = vec!["config", "--workspace", ws, "risk"];
        all.extend_from_slice(args);
        all.iter().map(|s| s.to_string()).collect::<Vec<_>>()
    };
    let call = |user: &str, computer: &str, args: &[&str]| {
        let a = cfg(args);
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        run_as(&dir, user, computer, &a)
    };
    ok(&call(
        "eddard.stark",
        "SECOPS-WS02",
        &[
            "accept",
            "--finding",
            "PW-004-13b0863341b2e306",
            "--reason",
            "Break-glass",
        ],
    ));
    let list = ok(&call("x", "Y", &["list"]));
    assert!(
        list.contains(&format!(
            "     accepted by {} on SECOPS-WS02, ",
            who("eddard.stark")
        )),
        "{list}"
    );
    assert!(
        list.contains("     who accepted it and when wasn't recorded"),
        "{list}"
    );

    // Edit (the page's Edit) and a note, by someone else elsewhere.
    ok(&call(
        "robb.stark",
        "PW-SCHED01",
        &["edit", "2", "--review-by", "2099-01-31"],
    ));
    ok(&call(
        "robb.stark",
        "PW-SCHED01",
        &["note", "2", "--text", "Renewed for Q1."],
    ));
    let list = ok(&call("x", "Y", &["list"]));
    assert!(
        list.contains("2. finding PW-004-13b0863341b2e306, review by Jan 31, 2099"),
        "{list}"
    );
    assert!(
        list.contains(&format!(
            "     changed by {} on PW-SCHED01, ",
            who("robb.stark")
        )),
        "{list}"
    );
    assert!(
        list.contains(&format!(
            "     note by {} on PW-SCHED01, ",
            who("robb.stark")
        )) && list.contains(": Renewed for Q1."),
        "{list}"
    );
    // Who accepted it stays.
    assert!(list.contains(&format!("accepted by {}", who("eddard.stark"))));

    let v: serde_json::Value =
        serde_json::from_str(&ok(&call("x", "Y", &["list", "--json"]))).unwrap();
    assert!(v[0]["accepted_by"].is_null());
    assert_eq!(v[1]["accepted_by"], who("eddard.stark"));
    assert_eq!(v[1]["accepted_on"], "SECOPS-WS02");
    assert!(v[1]["accepted_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(v[1]["changed_by"], who("robb.stark"));
    assert_eq!(v[1]["notes"][0]["text"], "Renewed for Q1.");
    assert_eq!(v[1]["notes"][0]["on"], "PW-SCHED01");

    // The file keeps its comment and its old entry as written.
    let text = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(
        text.starts_with("# Ours.\n[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\"\n"),
        "{text}"
    );

    // Nothing to change, or no such risk: refused.
    assert!(err(&call("x", "Y", &["edit", "2"])).contains("Say what to change"));
    assert!(err(&call("x", "Y", &["note", "3", "--text", "x"])).contains("no accepted risk 3"));
    assert!(err(&call("x", "Y", &["note", "2", "--text", " "])).contains("Write the note"));
    // Edit can drop the review date and change the reason.
    ok(&call(
        "x",
        "Y",
        &[
            "edit",
            "2",
            "--no-review-by",
            "--reason",
            "Break-glass, CHG2",
        ],
    ));
    let v: serde_json::Value =
        serde_json::from_str(&ok(&call("x", "Y", &["list", "--json"]))).unwrap();
    assert!(v[1]["review_by"].is_null());
    assert_eq!(v[1]["reason"], "Break-glass, CHG2");
    // The old reason stays on record as a note, by whoever changed it.
    let notes = v[1]["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[1]["text"], "Reason changed from: Break-glass");
    assert_eq!(notes[1]["on"], "Y");
    assert_eq!(v[1]["changed_on"], "Y");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two risks with one reason: after the first is removed, a note meant for
/// it (by what it covers) is refused instead of landing on the other, and
/// confirmations name what each risk covers.
#[test]
fn risks_are_picked_by_what_they_cover() {
    let dir = workspace("risk-pick");
    let ws = dir.to_str().unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[[suppress]]\nrule = \"PW-011\"\nreason = \"CAB approved\"\n\n[[suppress]]\nfingerprint = \"PW-004-13b0863341b2e306\"\nreason = \"CAB approved\"\nticket = \"CHG7\"\n",
    )
    .unwrap();
    let risk = |args: &[&str]| {
        let mut all = vec!["config", "--workspace", ws, "risk"];
        all.extend_from_slice(args);
        run(&dir, &all)
    };
    // A key from a newer version: a warning, and the rest works.
    let out = risk(&["list"]);
    let warn = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        warn.contains("Warning: pathwarden.toml: Accepted risk 2") && warn.contains("`ticket`"),
        "{warn}"
    );
    ok(&out);
    let out = ok(&risk(&["remove", "--rule", "PW-011"]));
    assert!(
        out.contains("Removed accepted risk 1 (every PW-011 finding)"),
        "{out}"
    );
    // The number from the old list now names the finding: refused.
    let e = err(&risk(&["note", "1", "--rule", "PW-011", "--text", "x"]));
    assert!(
        e.contains("Accepted risk 1 in")
            && e.contains("accepts finding PW-004-13b0863341b2e306, not every PW-011 finding"),
        "{e}"
    );
    let e = err(&risk(&["note", "--rule", "PW-011", "--text", "x"]));
    assert!(
        e.contains("No accepted risk in") && e.contains("accepts every PW-011 finding"),
        "{e}"
    );
    let e = err(&risk(&["note", "--text", "x"]));
    assert!(e.contains("Say which accepted risk"), "{e}");
    let out = ok(&risk(&[
        "note",
        "--finding",
        "pw-004-13B0863341B2E306",
        "--text",
        "Checked.",
    ]));
    assert!(
        out.contains("Added the note to accepted risk 1 (finding PW-004-13b0863341b2e306)"),
        "{out}"
    );
    let out = ok(&risk(&["edit", "1", "--review-by", "2099-01-01"]));
    assert!(
        out.contains("Saved accepted risk 1 (finding PW-004-13b0863341b2e306)"),
        "{out}"
    );
    // A new target through edit is a new acceptance, with a note saying so.
    ok(&risk(&["edit", "1", "--new-rule", "PW-004"]));
    let v: serde_json::Value = serde_json::from_str(&ok(&risk(&["list", "--json"]))).unwrap();
    assert_eq!(v[0]["rule"], "PW-004");
    assert!(v[0]["accepted_at"].is_string());
    let notes = v[0]["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 2);
    assert!(notes[1]["text"]
        .as_str()
        .unwrap()
        .starts_with("Changed from finding PW-004-13b0863341b2e306 to every PW-004 finding"));
    // Every key is there in --json, null when not recorded, notes too.
    assert!(v[0].as_object().unwrap().contains_key("changed_by") && v[0]["changed_by"].is_null());
    for k in ["by", "on", "at", "text"] {
        assert!(notes[0].as_object().unwrap().contains_key(k), "{k}");
    }
    // Duplicates need the number.
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[[suppress]]\nrule = \"PW-011\"\nreason = \"a\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"b\"\n",
    )
    .unwrap();
    let e = err(&risk(&["remove", "--rule", "PW-011"]));
    assert!(
        e.contains("Accepted risks 1, 2 in") && e.contains("give the number too"),
        "{e}"
    );
    ok(&risk(&["remove", "2", "--rule", "PW-011"]));
    // A typo of a known key stops it, saying which.
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[[suppress]]\nrule = \"PW-011\"\nreason = \"a\"\nexpire = \"2099-01-01\"\n",
    )
    .unwrap();
    let e = err(&risk(&["list"]));
    assert!(e.contains("did you mean `expires`?"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Commands run at the same moment each apply their change to the file as
/// it is under the lock: none is lost.
#[test]
fn concurrent_saves_all_stay() {
    let dir = workspace("concurrent");
    let ws = dir.to_str().unwrap().to_string();
    let spawn = |args: Vec<String>| {
        Command::new(bin())
            .current_dir(&dir)
            .env("NO_COLOR", "1")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let rules = ["PW-008", "PW-009", "PW-010", "PW-011", "PW-012", "PW-020"];
    let mut children = Vec::new();
    for i in 0..12 {
        children.push(spawn(
            [
                "config",
                "--workspace",
                &ws,
                "tier-zero",
                "add",
                &format!("OBJ{i}@CORP.LOCAL"),
            ]
            .map(String::from)
            .to_vec(),
        ));
    }
    for r in rules {
        children.push(spawn(
            ["config", "--workspace", &ws, "rules", "set", "--disable", r]
                .map(String::from)
                .to_vec(),
        ));
    }
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let list: Vec<String> = serde_json::from_str(&ok(&run(
        &dir,
        &["config", "--workspace", &ws, "tier-zero", "list", "--json"],
    )))
    .unwrap();
    assert_eq!(list.len(), 12, "{list:?}");
    let v: serde_json::Value = serde_json::from_str(&ok(&run(
        &dir,
        &["config", "--workspace", &ws, "rules", "show", "--json"],
    )))
    .unwrap();
    let disabled = v["disabled"].as_array().unwrap();
    for r in rules {
        assert!(disabled.iter().any(|d| d == r), "{r}: {v}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `config rules set --severity`: the Settings page's severities
/// from the terminal, through the same checks; `show` lists them, `--json`
/// and `--rules` too; `pathwarden rules` names each rule's default.
#[test]
fn rule_severities_from_the_command_line() {
    let dir = workspace("severities");
    let ws = dir.to_str().unwrap();
    let config = |args: &[&str]| {
        let mut all = vec!["config", "--workspace", ws, "rules"];
        all.extend_from_slice(args);
        run(&dir, &all)
    };
    ok(&config(&[
        "set",
        "--severity",
        "PW-002=critical",
        "--severity",
        "pw-011=Low",
    ]));
    let text = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(text.contains("[rules.severities]"), "{text}");
    let show = ok(&config(&["show"]));
    assert!(show.contains("Severities set:            2"), "{show}");
    assert!(
        show.contains("PW-002  Critical  default by exposure"),
        "{show}"
    );
    assert!(show.contains("PW-011  Low       default Medium"), "{show}");
    let v: serde_json::Value = serde_json::from_str(&ok(&config(&["show", "--json"]))).unwrap();
    assert_eq!(v["severities"]["PW-002"]["severity"], "critical");
    assert_eq!(v["severities"]["PW-011"]["severity"], "low");
    assert!(v.get("rules").is_none());
    // Every rule, as the Settings page lists them.
    let v: serde_json::Value =
        serde_json::from_str(&ok(&config(&["show", "--json", "--rules"]))).unwrap();
    let rows = v["rules"].as_array().unwrap();
    assert_eq!(rows.len(), pathwarden_core::findings::rules().len());
    let row = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap().clone();
    assert_eq!(row("PW-001")["default"], "exposure");
    assert!(row("PW-001").get("set").is_none());
    assert_eq!(row("PW-011")["set"]["severity"], "low");
    assert_eq!(row("PW-013")["default"], "High or Low");
    let list = ok(&config(&["show", "--rules"]));
    assert!(list.contains("PW-001  on   Default (exposure)"), "{list}");
    assert!(list.contains("PW-002  on   Critical (set)"), "{list}");
    // Default takes one off; the rest stay.
    ok(&config(&["set", "--severity", "PW-002=default"]));
    let v: serde_json::Value = serde_json::from_str(&ok(&config(&["show", "--json"]))).unwrap();
    assert!(v["severities"].get("PW-002").is_none());
    assert_eq!(v["severities"]["PW-011"]["severity"], "low");
    // The app's checks and messages.
    let before = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    let e = err(&config(&["set", "--severity", "PW-999=low"]));
    assert!(e.contains("PW-999 is not a rule Pathwarden has."), "{e}");
    let e = err(&config(&["set", "--severity", "PW-002=info"]));
    assert!(e.contains("use critical, high, medium or low."), "{e}");
    let e = err(&config(&["set", "--severity", "PW-002"]));
    assert!(e.contains("such as PW-011=low"), "{e}");
    assert_eq!(
        std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap(),
        before
    );
    // `pathwarden rules`: each rule's severity by the environment's settings.
    let rules = ok(&run(&dir, &["rules", "--workspace", ws]));
    assert!(rules.contains("PW-011  on   Low (set)"), "{rules}");
    assert!(rules.contains("PW-002  on   Default (exposure)"), "{rules}");
    ok(&config(&["set", "--rating", "rule"]));
    let rules = ok(&run(&dir, &["rules", "--workspace", ws]));
    assert!(rules.contains("PW-002  on   Default (Critical)"), "{rules}");
    // A file outside the workspace, or none at all.
    let rules = ok(&run(&dir, &["rules", "-c", "no-such.toml"]));
    assert!(rules.contains("PW-011  on   Default (Medium)"), "{rules}");
    // --reset-severities: all back to their defaults, as Settings' reset.
    ok(&config(&["set", "--severity", "PW-002=high"]));
    ok(&config(&[
        "set",
        "--reset-severities",
        "--severity",
        "PW-013=low",
    ]));
    let v: serde_json::Value = serde_json::from_str(&ok(&config(&["show", "--json"]))).unwrap();
    assert_eq!(
        v["severities"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["PW-013"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hand-written reason with spaces around it, given a new review date:
/// the date changed, the reason didn't (no "Reason changed" note).
#[test]
fn spaces_around_a_reason_are_the_same_reason() {
    let dir = workspace("risk-spaces");
    let ws = dir.to_str().unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks  \"\n",
    )
    .unwrap();
    let risk = |args: &[&str]| {
        let mut all = vec!["config", "--workspace", ws, "risk"];
        all.extend_from_slice(args);
        run_as(&dir, "ned", "WS1", &all)
    };
    ok(&risk(&["edit", "1", "--review-by", "2099-01-01"]));
    let v: serde_json::Value = serde_json::from_str(&ok(&risk(&["list", "--json"]))).unwrap();
    assert_eq!(v[0]["review_by"], "2099-01-01");
    assert_eq!(v[0]["changed_on"], "WS1");
    assert_eq!(v[0]["notes"], serde_json::json!([]));
    let text = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(text.contains("reason = \"Kiosks  \""), "{text}");
    // A note of several lines: the rest indented under its first.
    ok(&risk(&[
        "note",
        "1",
        "--text",
        "First line\nsecond line\n\nafter a gap",
    ]));
    let list = ok(&risk(&["list"]));
    // A blank line inside the note is blank: no trailing spaces.
    assert!(
        list.contains(": First line\n       second line\n\n       after a gap\n"),
        "{list:?}"
    );
    assert!(!list.lines().any(|l| l.ends_with(' ')), "{list:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier_zero_edits_default_to_the_current_environment() {
    let dir = workspace("t0");
    let ws = dir.to_str().unwrap();
    // No analysis to check names against: saved as given, with a note.
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "tier-zero",
            "add",
            "BACKUP@CORP.LOCAL",
        ],
    ));
    let list = ok(&run(
        &dir,
        &["config", "--workspace", ws, "tier-zero", "list", "--json"],
    ));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&list).unwrap(),
        serde_json::json!(["BACKUP@CORP.LOCAL"])
    );
    assert!(
        dir.join("pathwarden.toml").is_file(),
        "the current environment is Default"
    );
    let e = err(&run(
        &dir,
        &["config", "--workspace", ws, "tier-zero", "remove", "NOPE"],
    ));
    assert!(e.contains("Not a Tier Zero addition"), "{e}");
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "tier-zero",
            "remove",
            "backup@corp.local",
        ],
    ));
    let list = ok(&run(
        &dir,
        &["config", "--workspace", ws, "tier-zero", "list", "--json"],
    ));
    assert_eq!(list.trim(), "[]");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn environments_are_created_changed_and_made_current() {
    let dir = workspace("env");
    let ws = dir.to_str().unwrap();
    let e = err(&run(
        &dir,
        &[
            "env",
            "create",
            "Prod",
            "--domains",
            "corp, not a domain!!",
            "--workspace",
            ws,
        ],
    ));
    assert!(e.contains("are not domain names"), "{e}");
    ok(&run(
        &dir,
        &[
            "env",
            "create",
            "Prod",
            "--domains",
            "corp.example.com",
            "--copy-from",
            "Lab",
            "--use",
            "--workspace",
            ws,
        ],
    ));
    ok(&run(
        &dir,
        &[
            "env",
            "domains",
            "Prod",
            "corp.example.com emea.example.com",
            "--workspace",
            ws,
        ],
    ));
    let list: serde_json::Value = serde_json::from_str(&ok(&run(
        &dir,
        &["env", "list", "--json", "--workspace", ws],
    )))
    .unwrap();
    let prod = list
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "Prod")
        .unwrap();
    assert_eq!(
        prod["listed_domains"],
        serde_json::json!(["CORP.EXAMPLE.COM", "EMEA.EXAMPLE.COM"])
    );
    assert_eq!(prod["current"], true);
    // Back to Lab (an unused Default isn't listed); Prod is no longer current.
    ok(&run(&dir, &["env", "use", "Lab", "--workspace", ws]));
    let list: serde_json::Value = serde_json::from_str(&ok(&run(
        &dir,
        &["env", "list", "--json", "--workspace", ws],
    )))
    .unwrap();
    let current: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["current"] == true)
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(current, ["lab"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `config settings-folders` is the Settings page's Tier Zero settings
/// folders card: the same checks, written to the same key.
#[test]
fn settings_folders_are_listed_added_and_removed() {
    let dir = workspace("t0folders");
    let ws = dir.to_str().unwrap();
    let list = |dir: &Path| -> Vec<String> {
        let rows: Vec<serde_json::Value> = serde_json::from_str(&ok(&run(
            dir,
            &[
                "config",
                "--workspace",
                ws,
                "settings-folders",
                "list",
                "--json",
            ],
        )))
        .unwrap();
        // Added here: used here.
        assert!(rows.iter().all(|r| r["used"] == true), "{rows:?}");
        rows.iter()
            .map(|r| r["path"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(list(&dir).is_empty());
    let text = ok(&run(
        &dir,
        &["config", "--workspace", ws, "settings-folders", "list"],
    ));
    assert!(text.contains("No Tier Zero settings folders"), "{text}");
    let out = ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "settings-folders",
            "add",
            r"\\fs01\pathwarden-t0",
            r"D:\t0",
            r"\\FS01\pathwarden-t0",
        ],
    ));
    assert!(out.contains("Saved: 2 Tier Zero settings folders"), "{out}");
    // A plain `run` doesn't read the app's environment: say what does.
    assert!(
        out.contains("`pathwarden run` reads them with -c "),
        "{out}"
    );
    assert_eq!(list(&dir), [r"\\fs01\pathwarden-t0", r"D:\t0"]);
    let toml = std::fs::read_to_string(dir.join("environments/default/pathwarden.toml"))
        .or_else(|_| std::fs::read_to_string(dir.join("pathwarden.toml")))
        .unwrap();
    assert!(toml.contains("settings_folders = ["), "{toml}");
    // A relative path, and removing one that isn't there, are refused.
    let e = err(&run(
        &dir,
        &["config", "--workspace", ws, "settings-folders", "add", "t0"],
    ));
    assert!(e.contains("is not a full folder path"), "{e}");
    let e = err(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "settings-folders",
            "remove",
            r"E:\x",
        ],
    ));
    assert!(e.contains("Not a Tier Zero settings folder"), "{e}");
    ok(&run(
        &dir,
        &[
            "config",
            "--workspace",
            ws,
            "settings-folders",
            "remove",
            r"\\FS01\PATHWARDEN-T0",
        ],
    ));
    assert_eq!(list(&dir), [r"D:\t0"]);
    let _ = std::fs::remove_dir_all(&dir);
}
