//! `pathwarden runs list|show|report`: the app's Runs list and run
//! pages from the terminal, from the page's own code. A saved run opens in
//! full; a run only the history has ("numbers only") shows its numbers and
//! findings, and has no report to write.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-runs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw_out(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        .env("LOCALAPPDATA", dir.join("lad"))
        .env("PATHWARDEN_TEST_KEYSTORE", dir.join("keystore"))
        .args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn pw(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let out = pw_out(dir, args, env);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn runs_list_show_and_report() {
    let dir = scratch("cli");
    let ws = dir.join("ws");
    let ws_arg = ws.to_string_lossy().into_owned();
    let input = repo("testdata/forest").to_string_lossy().into_owned();
    let common = ["--workspace", ws_arg.as_str()];

    // A run saved in the workspace (full), then one the schedule records
    // in the same environment's history only.
    pw(
        &dir,
        &[
            "run",
            "-i",
            &input,
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            &ws_arg,
        ],
        &[],
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    pw(
        &dir,
        &[
            "run",
            "-i",
            &input,
            "--env",
            "Lab",
            "--workspace",
            &ws_arg,
            "--no-outputs",
        ],
        &[("PATHWARDEN_SCHEDULED", "1")],
    );

    let list = |extra: &[&str]| {
        let mut a = vec!["runs", "list", "--env", "Lab"];
        a.extend(common);
        a.extend(extra);
        pw(&dir, &a, &[])
    };
    let v: Value = serde_json::from_str(&list(&["--json"])).unwrap();
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2, "{v}");
    assert!(v["problem"].is_null(), "{v}");
    // Newest first: the scheduled run, numbers only.
    let (point, saved) = (&runs[0], &runs[1]);
    assert_eq!(point["source"], "numbers-only", "{v}");
    assert_eq!(point["tags"][0], "Scheduled");
    assert_eq!(point["tags"][1], "Numbers with names");
    assert_eq!(point["note"], "no full run");
    assert_eq!(point["id"], point["run_id"]);
    assert_eq!(saved["source"], "local", "{v}");
    assert!(saved["run_id"].is_string(), "recorded too: {v}");
    assert_eq!(point["vs_previous"]["exposed"], 0, "{v}");
    assert_eq!(saved["vs_previous"]["words"], "First run", "{v}");
    let (pid, sid) = (
        point["id"].as_str().unwrap().to_string(),
        saved["id"].as_str().unwrap().to_string(),
    );

    // The text says the same words.
    let text = list(&[]);
    assert!(text.contains("[Scheduled]  [Numbers with names]"), "{text}");
    assert!(
        text.contains("Recorded by the schedule · no full run"),
        "{text}"
    );
    assert!(text.contains("With an attack path to Tier Zero:"), "{text}");

    // `runs show` of the numbers-only run: its small page's facts.
    let show = |id: &str, extra: &[&str]| {
        let mut a = vec!["runs", "show", id, "--env", "Lab"];
        a.extend(common);
        a.extend(extra);
        pw(&dir, &a, &[])
    };
    let s: Value = serde_json::from_str(&show(&pid, &["--json"])).unwrap();
    assert_eq!(
        s["line"],
        "Only its numbers are kept, so there's no report or graph."
    );
    assert_eq!(s["findings"]["complete"], true, "{s}");
    let items = s["findings"]["items"].as_array().unwrap();
    // Every finding of the run, as many as it counted.
    let counts = &point["findings"];
    let total: u64 = ["critical", "high", "medium", "low", "info", "suppressed"]
        .iter()
        .map(|k| counts[k].as_u64().unwrap())
        .sum();
    assert_eq!(items.len() as u64, total, "{s}");
    assert!(items.iter().all(|i| i["change"] == "open"), "{s}");
    assert!(items.iter().all(|i| i["title"].is_string()), "{s}");
    let text = show(&pid, &[]);
    assert!(text.contains("no report or graph."), "{text}");
    assert!(text.contains("Findings"), "{text}");
    // The saved run's first sighting: everything new.
    let text = show(&sid, &[]);
    assert!(text.contains("runs report"), "{text}");

    // Its report, as Download report gives it; none for numbers only.
    let report = |id: &str, out: &str| {
        let mut a = vec!["runs", "report", id, "-o", out, "--env", "Lab"];
        a.extend(common);
        pw_out(&dir, &a, &[])
    };
    let out = report(&sid, "saved.html");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let html = std::fs::read_to_string(dir.join("saved.html")).unwrap();
    assert!(
        html.starts_with("<!doctype html>") || html.contains("<html"),
        "a report"
    );
    let out = report(&pid, "none.html");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no report or graph"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.join("none.html").exists());
    // An unknown run says how to list them.
    let mut a = vec!["runs", "show", "20200101T000000.000Z", "--env", "Lab"];
    a.extend(common);
    let out = pw_out(&dir, &a, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pathwarden runs list"));

    // History storage counts the runs that open in full here, only when
    // the history keeps "Full runs and settings".
    let storage = |extra: &[&str]| {
        let mut a = vec!["history", "storage", "show", "--env", "Lab"];
        a.extend(common);
        a.extend(extra);
        pw(&dir, &a, &[])
    };
    // The facts wrap: compare the words.
    let words = |t: String| t.split_whitespace().collect::<Vec<_>>().join(" ");
    let v: Value = serde_json::from_str(&storage(&["--json"])).unwrap();
    assert!(v["open_in_full"].is_null(), "{v}");
    let text = words(storage(&[]));
    assert!(!text.contains("Full runs "), "{text}");
    pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--keep",
            "full",
            "--no-encrypt",
            "--yes",
            "--env",
            "Lab",
            "--workspace",
            &ws_arg,
        ],
        &[],
    );
    let v: Value = serde_json::from_str(&storage(&["--json"])).unwrap();
    assert_eq!(v["open_in_full"]["on_this_computer"], 1, "{v}");
    assert_eq!(v["open_in_full"]["numbers_only"], 1, "{v}");
    let text = words(storage(&[]));
    assert!(
        text.contains("Full runs 1 of 2 runs open in full on this computer · 1 numbers only"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `runs show` says which accounts reach Tier Zero now and no longer, and
/// `--step N` which a plan step cuts off: every one in the JSON,
/// the first ones in the text. A numbers-only run shows its counts only.
#[test]
fn runs_show_lists_the_accounts() {
    let dir = scratch("lists");
    let ws = dir.join("ws");
    let ws_arg = ws.to_string_lossy().into_owned();
    let zip = |name: &str| repo(name).to_string_lossy().into_owned();
    let common = ["--env", "D", "--workspace", ws_arg.as_str()];
    let run = |input: &str, extra: &[&str], env: &[(&str, &str)]| {
        let mut a = vec!["run", "-i", input, "--workspace", &ws_arg];
        a.extend(extra);
        pw(&dir, &a, env);
        std::thread::sleep(std::time::Duration::from_millis(1100));
    };
    run(
        &zip("demo-history/20260917020000_PathwardenDemo.zip"),
        &["--save", "--new-env", "D"],
        &[],
    );
    run(
        &zip("demo-history/20260924020000_PathwardenDemo.zip"),
        &["--save", "--env", "D"],
        &[],
    );
    run(
        &zip("demo/20261001020000_PathwardenDemo.zip"),
        &["--env", "D", "--no-outputs"],
        &[("PATHWARDEN_SCHEDULED", "1")],
    );
    let mut a = vec!["runs", "list", "--json"];
    a.extend(common);
    let v: Value = serde_json::from_str(&pw(&dir, &a, &[])).unwrap();
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 3, "{v}");
    let (r3, r2, r1) = (&runs[0], &runs[1], &runs[2]);
    assert_eq!(r3["source"], "numbers-only");
    assert_eq!(r3["tier_zero_lists"], false);
    assert_eq!(r2["tier_zero_lists"], true);
    assert_eq!(r1["tier_zero_lists"], true);
    let id = |r: &Value| r["id"].as_str().unwrap().to_string();
    let show_out = |id: &str, extra: &[&str]| {
        let mut a = vec!["runs", "show", id];
        a.extend(common);
        a.extend(extra);
        pw_out(&dir, &a, &[])
    };
    let show = |id: &str, extra: &[&str]| {
        let out = show_out(id, extra);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    // The first run: no earlier one, so nothing changed; its steps.
    let s: Value = serde_json::from_str(&show(&id(r1), &["--json"])).unwrap();
    assert!(s["tier_zero_change"].is_null(), "{s}");
    assert!(!s["steps"].as_array().unwrap().is_empty(), "{s}");

    // The second against the first: every account in the JSON, as many
    // more and fewer as the counts moved.
    let s: Value = serde_json::from_str(&show(&id(r2), &["--json"])).unwrap();
    let c = &s["tier_zero_change"];
    assert_eq!(c["available"], true, "{c}");
    assert_eq!(c["previous_run"], r1["run_id"]);
    let now = c["now_reach"].as_array().unwrap();
    let gone = c["no_longer"].as_array().unwrap();
    let unnamed = c["no_longer_unnamed"].as_i64().unwrap();
    assert_eq!(
        now.len() as i64 - gone.len() as i64 - unnamed,
        r2["exposed"].as_i64().unwrap() - r1["exposed"].as_i64().unwrap()
    );
    assert!(gone.len() > 200, "{}", gone.len());
    for a in now {
        assert_eq!(
            a["hops"].as_u64().unwrap() as usize,
            a["path"].as_array().unwrap().len()
        );
        assert_eq!(a["new"], true);
    }
    for g in gone {
        assert!(
            ["Now Tier Zero", "Disabled", "No path now"].contains(&g["words"].as_str().unwrap()),
            "{g}"
        );
    }
    let steps = s["steps"].as_array().unwrap();
    assert!(s["step"].is_null());
    // The text: the first 200, then a count.
    let text = show(&id(r2), &[]);
    assert!(
        text.contains(&format!(
            "No longer reach Tier Zero ({})",
            pathwarden_core::text::num(gone.len() + unnamed as usize)
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "  and {} more (--json lists every one)",
            pathwarden_core::text::num(gone.len() - 200)
        )),
        "{text}"
    );
    assert!(text.contains("--step N` lists the accounts"), "{text}");

    // One step's accounts, every one in the JSON, new ones first.
    let s: Value = serde_json::from_str(&show(&id(r2), &["--step", "1", "--json"])).unwrap();
    let accounts = s["step"]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len() as u64, steps[0]["exposed"].as_u64().unwrap());
    let new = accounts.iter().take_while(|a| a["new"] == true).count();
    assert_eq!(new as u64, steps[0]["new"].as_u64().unwrap());
    assert!(accounts[new..].iter().all(|a| a["new"] == false));
    let text = show(&id(r2), &["--step", "1"]);
    assert!(
        text.contains(&format!(
            "Plan step 1 cuts off {}.",
            pathwarden_core::text::count(accounts.len(), "account", "accounts")
        )),
        "{text}"
    );
    assert!(!text.contains("Run details"), "{text}");
    let out = show_out(&id(r2), &["--step", "999"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("The remediation path of run"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Numbers only: its counts, no lists and nothing about why.
    let s: Value = serde_json::from_str(&show(&id(r3), &["--json"])).unwrap();
    assert!(s.get("tier_zero_change").is_none(), "{s}");
    let text = show(&id(r3), &[]);
    assert!(!text.contains("reach Tier Zero ("), "{text}");
    assert!(!text.contains("isn't known"), "{text}");
    let out = show_out(&id(r3), &["--step", "1"]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `runs show` prints Run details' "Other sources" row as the run page has
/// it (right after "Where it came from"): each OpenGraph source's facts,
/// the retest sentence and where the mappings are. A run without
/// OpenGraph data has no such row.
#[test]
fn runs_show_has_the_other_sources() {
    let dir = scratch("og");
    let ws = dir.join("ws");
    let ws_arg = ws.to_string_lossy().into_owned();
    let input = dir.join("input");
    std::fs::create_dir_all(&input).unwrap();
    for sub in ["testdata/opengraph/ad", "testdata/opengraph/taskhound"] {
        for e in std::fs::read_dir(repo(sub)).unwrap() {
            let p = e.unwrap().path();
            std::fs::copy(&p, input.join(p.file_name().unwrap())).unwrap();
        }
    }
    let input_arg = input.to_string_lossy().into_owned();
    pw(
        &dir,
        &[
            "run",
            "-i",
            &input_arg,
            "--save",
            "--new-env",
            "Contoso",
            "--workspace",
            &ws_arg,
        ],
        &[],
    );
    let common = ["--env", "Contoso", "--workspace", ws_arg.as_str()];
    let mut a = vec!["runs", "list", "--json"];
    a.extend(common);
    let v: Value = serde_json::from_str(&pw(&dir, &a, &[])).unwrap();
    let id = v["runs"][0]["id"].as_str().unwrap().to_string();
    let mut a = vec!["runs", "show", id.as_str()];
    a.extend(common);
    let text = pw(&dir, &a, &[]);
    let from = text.find("  Where it came from · ").expect(&text);
    let at = text
        .find("  Other sources · TaskHound · trusted mapping !")
        .expect(&text);
    assert!(from < at, "{text}");
    // No other row between them.
    assert!(
        text[from..at]
            .lines()
            .skip(1)
            .all(|l| l.is_empty() || l.starts_with("    ")),
        "{text}"
    );
    for want in [
        "    Source             TaskHound, OpenGraph · 1 file: taskhound.json",
        "    Relationships kept ",
        "    Mapping            Trusted, ",
        "    Coverage           No coverage file.",
        "    For retests: Findings that rest on TaskHound can't be marked Fixed",
        "    Mappings lists what each pack means. `pathwarden mappings list` shows them.",
    ] {
        assert!(text.contains(want), "{want} in {text}");
    }
    a.push("--json");
    let v: Value = serde_json::from_str(&pw(&dir, &a, &[])).unwrap();
    assert_eq!(v["other_sources"]["sources"][0]["name"], "TaskHound", "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
