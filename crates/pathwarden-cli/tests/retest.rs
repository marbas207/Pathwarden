//! `pathwarden retest` and `pathwarden history` end to end, on the forest
//! fixture and a "fixed" copy of it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-retest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// A copy of the forest fixture with `edit` applied to each user object.
fn forest_variant(dir: &Path, name: &str, edit: impl Fn(&mut serde_json::Value)) -> String {
    let out = dir.join(name);
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let name = e.file_name();
        let text = if name.to_string_lossy() == "contoso_users.json" {
            let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
            for o in doc["data"].as_array_mut().unwrap() {
                edit(o);
            }
            doc.to_string()
        } else {
            text
        };
        std::fs::write(out.join(name), text).unwrap();
    }
    out.to_string_lossy().into_owned()
}

const CHILD_DA: &str = "S-1-5-21-2000-2000-2000-1201";
const BOB: &str = "S-1-5-21-1000-1000-1000-1104";
const JDOE: &str = "S-1-5-21-1000-1000-1000-1102";
const PW003: &str = "PW-003-39f2ede7c479090b";
const PW007: &str = "PW-007-9330011c83e2d77e";

/// CAROL's GenericAll on CHILD_DA removed, BOB requires pre-authentication
/// again, and JDOE newly doesn't.
fn fixed(o: &mut serde_json::Value) {
    match o["ObjectIdentifier"].as_str().unwrap() {
        CHILD_DA => o["Aces"] = serde_json::json!([]),
        BOB => o["Properties"]["dontreqpreauth"] = false.into(),
        JDOE => o["Properties"]["dontreqpreauth"] = true.into(),
        _ => {}
    }
}

fn listing(dir: &Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for e in walk(dir) {
        let m = std::fs::metadata(&e).unwrap();
        out.push((e.display().to_string(), m.len()));
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn retest_against_the_state() {
    let dir = scratch("state");
    let forest = testdata("forest");
    let forest = forest.to_str().unwrap();
    let fixed = forest_variant(&dir, "fixed", fixed);
    assert!(pw(&dir, &["run", "-i", forest, "--state", "st"])
        .status
        .success());
    let before = listing(&dir.join("st"));

    // Text: two fixed, the rest still open, one new; exit 1.
    let o = pw(&dir, &["retest", "-i", &fixed, "--state", "st"]);
    let text = stdout(&o);
    assert_eq!(o.status.code(), Some(1), "{text}");
    assert!(text.contains(&format!("FIXED       {PW003}")), "{text}");
    assert!(text.contains(&format!("FIXED       {PW007}")), "{text}");
    assert!(
        text.contains("STILL OPEN  PW-011-efa423e3a818ec8b"),
        "{text}"
    );
    assert!(text.contains("New since the baseline"), "{text}");
    assert!(
        text.contains("JDOE@CONTOSO.LOCAL does not require"),
        "{text}"
    );
    assert!(
        text.contains("2 fixed, 13 still open, 0 can't tell, 1 new."),
        "{text}"
    );
    // Ad hoc: nothing written.
    assert_eq!(
        listing(&dir.join("st")),
        before,
        "retest wrote to the state"
    );

    // JSON.
    let o = pw(&dir, &["retest", "-i", &fixed, "--state", "st", "--json"]);
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["counts"]["fixed"], 2);
    assert_eq!(j["counts"]["still_open"], 13);
    assert_eq!(j["counts"]["new"], 1);
    let r = j["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["fingerprint"] == PW003)
        .unwrap();
    assert_eq!(r["verdict"], "fixed");
    assert_eq!(j["new"][0]["rule"], "PW-007");
    assert_eq!(j["new"][0]["regressed"], false);

    // Only the fixed findings: exit 0, and no "new" list.
    let o = pw(
        &dir,
        &[
            "retest",
            "-i",
            &fixed,
            "--state",
            "st",
            "--finding",
            PW003,
            "--finding",
            PW007,
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    assert!(!stdout(&o).contains("New since"), "{}", stdout(&o));
    // A rule filter.
    let o = pw(
        &dir,
        &["retest", "-i", &fixed, "--state", "st", "--rule", "pw-011"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stdout(&o).contains("0 fixed, 1 still open"),
        "{}",
        stdout(&o)
    );
    // Unknown fingerprint: an error, exit 2.
    let o = pw(
        &dir,
        &[
            "retest",
            "-i",
            &fixed,
            "--state",
            "st",
            "--finding",
            "PW-003-0",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("PW-003-0"));

    // Another domain entirely: nothing can be told; exit 3.
    let sdprop = testdata("sdprop");
    let o = pw(
        &dir,
        &[
            "retest",
            "-i",
            sdprop.to_str().unwrap(),
            "--state",
            "st",
            "--rule",
            "PW-003",
        ],
    );
    assert_eq!(o.status.code(), Some(3), "{}", stdout(&o));
    assert!(stdout(&o).contains("CAN'T TELL"), "{}", stdout(&o));
    assert!(
        stdout(&o).contains("CHILD.CONTOSO.LOCAL was not in this collection")
            || stdout(&o).contains("its domain was not in this collection"),
        "{}",
        stdout(&o)
    );

    // --record records the run, as `run` would.
    let o = pw(&dir, &["retest", "-i", &fixed, "--state", "st", "--record"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("Recorded run"), "{}", stdout(&o));
    assert_eq!(
        std::fs::read_dir(dir.join("st/history")).unwrap().count(),
        2
    );
    // ...so the next retest against the state finds nothing fixed or new.
    let o = pw(&dir, &["retest", "-i", &fixed, "--state", "st"]);
    assert!(
        stdout(&o).contains("0 fixed, 14 still open, 0 can't tell, 0 new."),
        "{}",
        stdout(&o)
    );

    // History: what changed since the last run, two runs, the trend and
    // the table.
    let o = pw(&dir, &["history", "--state", "st"]);
    let h = stdout(&o);
    assert!(o.status.success(), "{h}");
    assert!(h.starts_with("Since the last run ("), "{h}");
    assert!(h.contains("  + 2 findings fixed\n"), "{h}");
    assert!(h.contains("\n2 runs,"), "{h}");
    assert!(h.contains("Open findings       █▁  15 → 14"), "{h}");
    assert!(h.contains("Fixed 2, opened 1"), "{h}");
    let o = pw(&dir, &["history", "--state", "st", "--json", "--last", "1"]);
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j.as_array().unwrap().len(), 1);
    assert_eq!(j[0]["changes"]["resolved"], 2);

    // No state at all: a clear error.
    let o = pw(&dir, &["retest", "-i", &fixed, "--state", "nowhere"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("No run history at"));
    assert!(!dir.join("nowhere").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn retest_against_an_earlier_collection_or_event() {
    let dir = scratch("baseline");
    let forest = testdata("forest");
    let forest = forest.to_str().unwrap();
    let fixed = forest_variant(&dir, "fixed", fixed);

    let o = pw(
        &dir,
        &["retest", "-i", &fixed, "--baseline", forest, "--json"],
    );
    assert_eq!(o.status.code(), Some(1));
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["counts"]["fixed"], 2);
    // The collection baseline names things.
    let r = j["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["fingerprint"] == PW003)
        .unwrap();
    assert!(r["title"].as_str().unwrap().contains("CAROL"), "{r}");

    // From an event document: details such as "all 2 affected objects remain".
    let o = pw(
        &dir,
        &["run", "-i", forest, "--state", "st", "--event", "ev.json"],
    );
    assert!(
        o.status.success(),
        "run --event: {:?}\n{}\n{}",
        o.status.code(),
        stdout(&o),
        String::from_utf8_lossy(&o.stderr)
    );
    let o = pw(&dir, &["retest", "-i", &fixed, "--baseline", "ev.json"]);
    let text = stdout(&o);
    assert!(
        text.contains("Retest against event ev.json"),
        "retest --baseline ev.json: {:?}\n{text}\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(text.contains("all 2 affected objects remain"), "{text}");
    assert!(text.contains("exposure unchanged"), "{text}");

    // --baseline and --record don't mix.
    let o = pw(
        &dir,
        &["retest", "-i", &fixed, "--baseline", "ev.json", "--record"],
    );
    assert!(!o.status.success());
    std::fs::remove_dir_all(&dir).ok();
}

/// The forest fixture as a Quick collection writes it: no session list
/// collected, no local groups.
fn quick_forest(dir: &Path) -> String {
    let out = dir.join("quick");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": "not collected: this collection does not contact computers (DC only)"});
                }
                c["LocalGroups"] = serde_json::json!([]);
                c.as_object_mut().unwrap().remove("LocalAdmins");
            }
        }
        std::fs::write(out.join(e.file_name()), doc.to_string()).unwrap();
    }
    out.to_string_lossy().into_owned()
}

/// A Quick collection holds the findings that may rest on sessions or
/// local groups; `retest` says, for those only, what the run page says, and
/// the command that checks the computers on their path.
#[test]
fn held_findings_point_at_the_targeted_retest() {
    let dir = scratch("held");
    let quick = quick_forest(&dir);
    let forest = testdata("forest").to_string_lossy().into_owned();
    let o = pw(
        &dir,
        &["retest", "-i", &quick, "--baseline", &forest, "--json"],
    );
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let held: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["held"] == true)
        .map(|r| r["fingerprint"].as_str().unwrap())
        .collect();
    assert!(held.contains(&"PW-006-8ae0b31a46eacada"), "{v}");
    assert!(!held.contains(&"PW-003-39f2ede7c479090b"));
    for r in v["results"].as_array().unwrap() {
        if r["held"] == true {
            assert_eq!(r["verdict"], "cant_tell");
        }
    }
    let o = pw(&dir, &["retest", "-i", &quick, "--baseline", &forest]);
    let text = stdout(&o);
    let line = "Retest it to check the computers on its path.";
    assert_eq!(text.matches(line).count(), held.len(), "{text}");
    assert!(
        text.contains(&format!(
            "{line} `pathwarden retest targeted --finding PW-006-8ae0b31a46eacada`"
        )),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `retest targeted` with no terminal asks for the password's variable (it
/// prompts only at a terminal, as `collect -u` does), and names a finding
/// no saved run has open.
#[test]
fn retest_targeted_needs_a_password() {
    let dir = scratch("targeted");
    let ws = dir.join("ws").to_string_lossy().into_owned();
    let forest = testdata("forest").to_string_lossy().into_owned();
    let o = pw(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            &ws,
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = Command::new(bin())
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .env_remove("PATHWARDEN_COLLECT_PASSWORD")
        .args([
            "retest",
            "targeted",
            "--finding",
            "PW-006-8ae0b31a46eacada",
            "--env",
            "Lab",
            "--workspace",
            &ws,
            "--user",
            "svc",
            "--ldaps",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    if err.contains("no built-in collector") {
        // A build without the collector offers no targeted retest.
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    assert!(err.contains("run interactively to be prompted"), "{err}");
    let o = pw(
        &dir,
        &[
            "retest",
            "targeted",
            "--finding",
            "PW-999-0",
            "--env",
            "Lab",
            "--workspace",
            &ws,
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("has PW-999-0 open"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `run` and `retest` read the config's Tier Zero settings folders,
/// say how many settings files they used, and name the servers the last
/// run had a file for and this one has not.
#[test]
fn run_and_retest_read_the_settings_folders() {
    let dir = scratch("t0folders");
    let folder = dir.join("t0");
    std::fs::create_dir_all(&folder).unwrap();
    let file = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../pathwarden-core/tests/fixtures/tierzero/pathwarden-tierzero-CA01.pki.local.json",
    ))
    .unwrap()
    // The AD CS fixture's CA has a made-up certificate hash: matched by
    // CA name and host.
    .replace("\"3F2504E04F8911D39A0C0305E82C3301AABBCCDD\"", "");
    std::fs::write(folder.join("pathwarden-tierzero-CA01.pki.local.json"), file).unwrap();
    // Written by hand: listed, not read until added or reviewed here.
    std::fs::write(
        dir.join("pathwarden.toml"),
        format!("settings_folders = ['{}']\n", folder.display()),
    )
    .unwrap();
    let o = pw(
        &dir,
        &[
            "config",
            "-c",
            "pathwarden.toml",
            "settings-folders",
            "list",
        ],
    );
    assert!(
        stdout(&o).contains("not used here until you review it"),
        "{}",
        stdout(&o)
    );
    // Added with the command: used here.
    let (f, m) = (
        folder.display().to_string(),
        dir.join("missing").display().to_string(),
    );
    let o = pw(
        &dir,
        &[
            "config",
            "-c",
            "pathwarden.toml",
            "settings-folders",
            "add",
            &f,
            &m,
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let adcs = testdata("adcs");
    let adcs = adcs.to_str().unwrap();
    let args = ["-i", adcs, "--state", "st", "-c", "pathwarden.toml"];
    let o = pw(&dir, &[&["run"][..], &args].concat());
    let text = stdout(&o);
    assert!(o.status.success(), "{text}");
    assert!(
        text.contains("Tier Zero settings files: 1 file\n"),
        "{text}"
    );
    assert!(
        text.contains("A settings folder couldn't be opened"),
        "{text}"
    );
    // The terminal names the folder that couldn't be opened; the record
    // names only the file.
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("missing") && err.contains("couldn't be opened"),
        "{err}"
    );
    let last = std::fs::read_to_string(dir.join("st").join("last-run.json")).unwrap();
    assert!(
        last.contains("\"file_name\": \"pathwarden-tierzero-CA01.pki.local.json\""),
        "{last}"
    );
    assert!(
        !last.contains("t0\\\\") && !last.contains("missing"),
        "{last}"
    );

    // The file is gone: retest says so, and run records fewer files.
    std::fs::remove_file(folder.join("pathwarden-tierzero-CA01.pki.local.json")).unwrap();
    let o = pw(&dir, &[&["retest"][..], &args].concat());
    let text = stdout(&o);
    assert!(
        text.contains("Tier Zero settings files: 0 files, 1 fewer than the last run"),
        "{text}"
    );
    assert!(
        text.contains("The last run also had files for PKI-CA. Findings that relied on them are marked unverified until the files are back. They don't count as fixed."),
        "{text}"
    );
    let o = pw(&dir, &[&["retest"][..], &args, &["--json"]].concat());
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["settings_fewer"], serde_json::json!(["PKI-CA"]));
    let o = pw(&dir, &[&["run"][..], &args].concat());
    let text = stdout(&o);
    assert!(
        text.contains("Tier Zero settings files: 0 files, 1 fewer than the last run"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
