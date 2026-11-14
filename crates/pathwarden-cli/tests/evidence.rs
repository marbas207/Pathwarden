//! `pathwarden evidence`: keygen, packs, verify, tampering, the wrong key,
//! and redaction, end to end on the forest fixture and a "fixed" copy.

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
    let dir =
        std::env::temp_dir().join(format!("pathwarden-evidence-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("PATHWARDEN_EVIDENCE_KEY")
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const PW003: &str = "PW-003-39f2ede7c479090b";
const CHILD_DA: &str = "S-1-5-21-2000-2000-2000-1201";

/// The forest fixture with CAROL's GenericAll on CHILD_DA removed (PW-003
/// fixed).
fn fixed_forest(dir: &Path) -> String {
    let out = dir.join("fixed");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(testdata("forest")).unwrap().flatten() {
        let mut text = std::fs::read_to_string(e.path()).unwrap();
        if e.file_name().to_string_lossy() == "contoso_users.json" {
            let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
            for o in doc["data"].as_array_mut().unwrap() {
                if o["ObjectIdentifier"] == CHILD_DA {
                    o["Aces"] = serde_json::json!([]);
                }
            }
            text = doc.to_string();
        }
        std::fs::write(out.join(e.file_name()), text).unwrap();
    }
    out.to_string_lossy().into_owned()
}

/// A key, a state from the forest fixture, and the fixed collection.
struct Lab {
    dir: PathBuf,
    fixed: String,
}

fn lab(name: &str) -> Lab {
    let dir = scratch(name);
    let o = pw(&dir, &["evidence", "keygen", "--output", "key"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("Fingerprint  SHA256:"), "{}", text(&o));
    let forest = testdata("forest");
    // A label that names the domain: a redacted pack leaves it out.
    let o = pw(
        &dir,
        &[
            "run",
            "-i",
            forest.to_str().unwrap(),
            "--state",
            "st",
            "--label",
            "CONTOSO baseline",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    let fixed = fixed_forest(&dir);
    Lab { dir, fixed }
}

fn fingerprint(dir: &Path, key_dir: &str) -> String {
    let text = std::fs::read_to_string(dir.join(key_dir).join("evidence.pub")).unwrap();
    text.split_whitespace()
        .find(|w| w.starts_with("SHA256:"))
        .unwrap()
        .to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

#[test]
fn round_trip_zip() {
    let lab = lab("round-trip");
    let d = &lab.dir;
    let o = pw(
        d,
        &[
            "evidence",
            "-i",
            &lab.fixed,
            "--state",
            "st",
            "--key",
            "key/evidence.key",
            "-o",
            "pack.zip",
        ],
    );
    // Some findings are still open: retest's exit status.
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("Wrote pack.zip."), "{}", text(&o));
    assert!(text(&o).contains("1 fixed, 14 still open"), "{}", text(&o));

    let fp = fingerprint(d, "key");
    let o = pw(
        d,
        &[
            "evidence",
            "verify",
            "pack.zip",
            "--key",
            "key/evidence.pub",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("VERIFIED"), "{}", text(&o));
    assert!(text(&o).contains("6 of 6 match"), "{}", text(&o));
    let o = pw(d, &["evidence", "verify", "pack.zip", "--fingerprint", &fp]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    // Without a key: intact, but whose signature is not checked.
    let o = pw(d, &["evidence", "verify", "pack.zip"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("SIGNER NOT CHECKED"), "{}", text(&o));

    // JSON.
    let o = pw(
        d,
        &[
            "evidence",
            "verify",
            "pack.zip",
            "--fingerprint",
            &fp,
            "--json",
        ],
    );
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["outcome"], "verified");
    assert_eq!(j["manifest"]["summary"]["counts"]["fixed"], 1);
    let files: Vec<&str> = j["manifest"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    for f in [
        "README.txt",
        "metadata.json",
        "retest.json",
        "findings.json",
        "history.json",
        "report.html",
    ] {
        assert!(files.contains(&f), "{files:?}");
    }

    // A changed byte in the zip: not verified.
    let mut bytes = std::fs::read(d.join("pack.zip")).unwrap();
    let mid = bytes.len() / 3;
    bytes[mid] ^= 0x55;
    std::fs::write(d.join("bad.zip"), bytes).unwrap();
    let o = pw(d, &["evidence", "verify", "bad.zip", "--fingerprint", &fp]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("NOT VERIFIED"), "{}", text(&o));

    // Never overwritten.
    let o = pw(
        d,
        &[
            "evidence", "-i", &lab.fixed, "--state", "st", "--key", "key", "-o", "pack.zip",
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("never overwritten"), "{}", text(&o));
    std::fs::remove_dir_all(d).ok();
}

#[test]
fn the_pack_shows_the_fix_with_both_sides() {
    let lab = lab("contents");
    let d = &lab.dir;
    // One finding, the key from the environment, a folder pack.
    let key = std::fs::read_to_string(d.join("key/evidence.key")).unwrap();
    let line = key.lines().last().unwrap();
    let o = Command::new(bin())
        .current_dir(d)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_EVIDENCE_KEY", line)
        .args([
            "evidence",
            "-i",
            &lab.fixed,
            "--state",
            "st",
            "--finding",
            PW003,
            "-o",
            "pack",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let read = |f: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(d.join("pack").join(f)).unwrap()).unwrap()
    };
    let retest = read("retest.json");
    assert_eq!(retest["results"][0]["fingerprint"], PW003);
    assert_eq!(retest["results"][0]["verdict"], "fixed");
    assert_eq!(retest["counts"]["fixed"], 1);
    let last: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("st/last-run.json")).unwrap())
            .unwrap();
    assert_eq!(retest["before"]["run_id"], last["run_id"]);
    assert!(retest["after"]["run_id"].is_string());
    assert!(retest["after"]["analyzed_at"]["utc"].is_string());

    let meta = read("metadata.json");
    assert_eq!(meta["pathwarden"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        meta["pathwarden"]["binary_sha256"].as_str().unwrap().len(),
        64
    );
    let files = meta["after"]["collection"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 6);
    assert!(files[0]["name"].is_string());
    assert_eq!(
        meta["after"]["collection"]["combined_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let findings = read("findings.json");
    assert_eq!(findings["retested"][0]["tracked"]["status"], "open");
    assert!(findings["retested"][0]["after"].is_null(), "fixed: gone");
    assert!(read("history.json")["points"].as_array().unwrap().len() == 1);
    // Its report compares with the run in --state: the trend and what
    // changed since that run.
    let report = std::fs::read_to_string(d.join("pack/report.html")).unwrap();
    assert!(report.contains("last 2 runs &middot;"), "the trend");
    assert!(report.contains(r#"id="ov-since-h">What changed since "#));
    let readme = std::fs::read_to_string(d.join("pack/README.txt")).unwrap();
    assert!(readme.contains(&fingerprint(d, "key")), "{readme}");
    assert!(readme.contains("Result: 1 fixed, 0 still open"), "{readme}");

    let fp = fingerprint(d, "key");
    let o = pw(d, &["evidence", "verify", "pack", "--fingerprint", &fp]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    std::fs::remove_dir_all(d).ok();
}

#[test]
fn any_change_fails_verification() {
    let lab = lab("tamper");
    let d = &lab.dir;
    let o = pw(
        d,
        &[
            "evidence", "-i", &lab.fixed, "--state", "st", "--key", "key", "-o", "pack",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let fp = fingerprint(d, "key");
    let verify = |pack: &str| pw(d, &["evidence", "verify", pack, "--fingerprint", &fp]);
    assert_eq!(verify("pack").status.code(), Some(0));

    let names: Vec<String> = std::fs::read_dir(d.join("pack"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 8, "{names:?}"); // 6 listed, the manifest and its signature
    for (i, name) in names.iter().enumerate() {
        // One changed byte in each file, the manifest and signature included.
        let copy = format!("changed-{i}");
        copy_dir(&d.join("pack"), &d.join(&copy));
        let path = d.join(&copy).join(name);
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.iter().position(|b| b.is_ascii_digit()).unwrap_or(0);
        bytes[at] = if bytes[at] == b'1' { b'2' } else { b'1' };
        std::fs::write(&path, bytes).unwrap();
        let o = verify(&copy);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", text(&o));
        assert!(text(&o).contains("NOT VERIFIED"), "{name}: {}", text(&o));

        // The file removed.
        let copy = format!("removed-{i}");
        copy_dir(&d.join("pack"), &d.join(&copy));
        std::fs::remove_file(d.join(&copy).join(name)).unwrap();
        let o = verify(&copy);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", text(&o));
    }
    // A file added.
    copy_dir(&d.join("pack"), &d.join("added"));
    std::fs::write(d.join("added/extra.txt"), "hello").unwrap();
    let o = verify("added");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("extra.txt is in the pack but not in the manifest"));

    // The manifest re-hashed after an edit: the signature no longer matches.
    copy_dir(&d.join("pack"), &d.join("rehashed"));
    let retest = d.join("rehashed/retest.json");
    let edited = std::fs::read_to_string(&retest)
        .unwrap()
        .replace("\"still_open\"", "\"fixed\"");
    std::fs::write(&retest, &edited).unwrap();
    let manifest_path = d.join("rehashed/manifest.json");
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    for f in m["files"].as_array_mut().unwrap() {
        if f["path"] == "retest.json" {
            f["sha256"] = sha256_hex(edited.as_bytes()).into();
            f["bytes"] = edited.len().into();
        }
    }
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let o = verify("rehashed");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("signature is not valid"), "{}", text(&o));
    std::fs::remove_dir_all(d).ok();
}

#[test]
fn another_key_fails_verification() {
    let lab = lab("wrong-key");
    let d = &lab.dir;
    assert!(pw(d, &["evidence", "keygen", "--out", "other"])
        .status
        .success());
    let o = pw(
        d,
        &[
            "evidence", "-i", &lab.fixed, "--state", "st", "--key", "key", "-o", "pack.zip",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let o = pw(
        d,
        &[
            "evidence",
            "verify",
            "pack.zip",
            "--key",
            "other/evidence.pub",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("not signed by the key you gave"),
        "{}",
        text(&o)
    );
    let other = fingerprint(d, "other");
    let o = pw(
        d,
        &["evidence", "verify", "pack.zip", "--fingerprint", &other],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("not by the expected"), "{}", text(&o));
    // A secret key where the public key belongs, and no key at all.
    let o = pw(
        d,
        &[
            "evidence",
            "verify",
            "pack.zip",
            "--key",
            "key/evidence.key",
        ],
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let o = pw(d, &["evidence", "-i", &lab.fixed, "--state", "st"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("No signing key"), "{}", text(&o));
    // keygen never reuses a folder.
    let o = pw(d, &["evidence", "keygen", "--out", "key"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    std::fs::remove_dir_all(d).ok();
}

#[test]
fn a_redacted_pack_holds_no_names() {
    let lab = lab("redact");
    let d = &lab.dir;
    // Against the state, and against the original collection (which names
    // everything) with the state's history.
    let forest = testdata("forest");
    for (out, extra) in [
        ("redacted", vec!["--state", "st"]),
        (
            "redacted-baseline",
            vec!["--baseline", forest.to_str().unwrap(), "--state", "st"],
        ),
    ] {
        let mut args = vec![
            "evidence", "-i", &lab.fixed, "--key", "key", "--redact", "-o", out,
        ];
        args.extend(extra);
        let o = pw(d, &args);
        assert_eq!(o.status.code(), Some(1), "{}", text(&o));
        assert!(!d.join(out).join("report.html").exists());
        let mut all = String::new();
        for e in std::fs::read_dir(d.join(out)).unwrap().flatten() {
            all.push_str(&std::fs::read_to_string(e.path()).unwrap().to_lowercase());
        }
        for name in [
            "contoso", "fabrikam", "carol@", "bob@", "jdoe@", "child_da", "svc_sql", "svc_sync",
            "app01.", "da_alice", "krbtgt@",
        ] {
            assert!(!all.contains(name), "{out} contains {name}");
        }
        // Still proves the fix: fingerprints, verdicts, counts.
        assert!(all.contains(&PW003.to_lowercase()), "{out}");
        assert!(all.contains("\"fixed\": 1"), "{out}");
        let fp = fingerprint(d, "key");
        let o = pw(d, &["evidence", "verify", out, "--fingerprint", &fp]);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        assert!(text(&o).contains("redacted"), "{}", text(&o));
    }
    std::fs::remove_dir_all(d).ok();
}

/// SHA-256 in hex.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `pw` in a scratch app data folder: the UI workspace commands never touch
/// the real one.
fn pw_ws(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        .env("LOCALAPPDATA", dir.join("lad"))
        .env("PATHWARDEN_TEST_KEYSTORE", dir.join("keystore"))
        .env_remove("PATHWARDEN_EVIDENCE_KEY")
        .args(args)
        .output()
        .unwrap()
}

/// `evidence --run`, `evidence key` and `export --run`: the app's run page
/// and Settings from the terminal, from the same code.
#[test]
fn a_run_of_the_app_makes_the_same_pack_and_findings_file() {
    let dir = scratch("run");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let forest = testdata("forest").to_string_lossy().into_owned();
    let fixed = fixed_forest(&dir);
    let ok = |args: &[&str]| {
        let o = pw_ws(&dir, args);
        assert!(o.status.success(), "{args:?}: {}", text(&o));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    ok(&[
        "run",
        "-i",
        &forest,
        "--save",
        "--new-env",
        "Lab",
        "--workspace",
        &w,
    ]);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    ok(&["run", "-i", &fixed, "--save", "--workspace", &w]);
    let list: serde_json::Value = serde_json::from_str(&ok(&[
        "runs",
        "list",
        "--env",
        "Lab",
        "--workspace",
        &w,
        "--json",
    ]))
    .unwrap();
    let runs = list["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2, "{list}");
    let (newer, older) = (
        runs[0]["id"].as_str().unwrap().to_string(),
        runs[1]["id"].as_str().unwrap().to_string(),
    );
    let env = ["--env", "Lab", "--workspace", w.as_str()];
    let with_env = |args: &[&str]| -> Vec<String> {
        args.iter()
            .chain(env.iter())
            .map(|s| s.to_string())
            .collect()
    };
    let run_env = |args: &[&str]| {
        let a = with_env(args);
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        pw_ws(&dir, &a)
    };

    // No key yet.
    let o = run_env(&["evidence", "--run", &newer]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("evidence key new"), "{}", text(&o));
    let o = pw_ws(&dir, &["evidence", "key", "--workspace", &w]);
    assert!(text(&o).contains("No signing key yet."), "{}", text(&o));

    // The app's key: created, shown, its public key written.
    let made: serde_json::Value = serde_json::from_str(&ok(&[
        "evidence",
        "key",
        "new",
        "--workspace",
        &w,
        "--json",
    ]))
    .unwrap();
    let fp = made["fingerprint"].as_str().unwrap().to_string();
    assert!(ws.join("evidence-key").join("evidence.key").is_file());
    let o = pw_ws(&dir, &["evidence", "key", "new", "--workspace", &w]);
    assert!(!o.status.success(), "a second key needs --replace");
    let shown = ok(&["evidence", "key", "--workspace", &w]);
    assert!(shown.contains(&fp), "{shown}");
    ok(&[
        "evidence",
        "key",
        "public",
        "--workspace",
        &w,
        "-o",
        "org.pub",
    ]);
    assert!(std::fs::read_to_string(dir.join("org.pub"))
        .unwrap()
        .contains(&fp));

    // The pack: against the run before, as the run page makes it.
    let o = run_env(&["evidence", "--run", &newer, "--json"]);
    assert!(o.status.code().is_some_and(|c| c != 2), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["signed_by"], fp.as_str(), "{v}");
    assert!(v["counts"]["fixed"].as_u64().unwrap() >= 1, "{v}");
    let pack = v["pack"].as_str().unwrap().to_string();
    assert!(
        pack.starts_with("pathwarden-evidence-") && pack.ends_with(".zip"),
        "{pack}"
    );
    let o = pw(
        &dir,
        &["evidence", "verify", &pack, "--key", "org.pub", "--json"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let ver: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(ver["outcome"], "verified");
    assert_eq!(ver["manifest"]["summary"]["baseline"]["kind"], "run");
    assert_eq!(
        ver["manifest"]["summary"]["baseline"]["run_id"],
        runs[1]["run_id"]
    );
    // Never overwritten.
    let o = run_env(&["evidence", "--run", &newer]);
    assert!(text(&o).contains("never overwritten"), "{}", text(&o));
    // The oldest run has nothing to compare with; --against names one.
    let o = run_env(&["evidence", "--run", &older]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let o = run_env(&[
        "evidence",
        "--run",
        &newer,
        "--against",
        &older,
        "--redact",
        "-o",
        "r.zip",
    ]);
    assert!(o.status.code().is_some_and(|c| c != 2), "{}", text(&o));
    assert!(
        text(&o).contains("Redacted: no object or domain names"),
        "{}",
        text(&o)
    );
    // -i or --run, not both, and one of them.
    let o = pw_ws(&dir, &["evidence", "--run", &newer, "-i", &forest]);
    assert_eq!(o.status.code(), Some(2));
    let o = pw_ws(&dir, &["evidence"]);
    assert_eq!(o.status.code(), Some(2));

    // The findings file, as the run page gives it.
    let o = run_env(&["export", "sarif", "--run", &newer]);
    assert!(o.status.success(), "{}", text(&o));
    let s: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(s["version"], "2.1.0");
    let o = run_env(&["export", "defectdojo", "--run", &newer]);
    assert!(o.status.success(), "{}", text(&o));
    let d: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(!d["findings"].as_array().unwrap().is_empty());
    let o = pw_ws(&dir, &["export", "sarif", "-i", &forest, "--env", "Lab"]);
    assert_eq!(o.status.code(), Some(2), "--env goes with --run");
    // The same text the app's run page gives, from the same history the
    // app reads (the environment's own), and with --state naming it.
    let sarif = run_env(&["export", "sarif", "--run", &newer]).stdout;
    let lab = pathwarden_ui::environments::cli_workspace(Some(&ws), "Lab").unwrap();
    let r = pathwarden_ui::evidence_ui::find_run(&lab, &newer).unwrap();
    let doc = pathwarden_ui::evidence_ui::findings_doc(&lab, None, &r).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&sarif),
        pathwarden_export::text(&doc, pathwarden_export::Format::Sarif).unwrap()
    );
    let history = pathwarden_ui::environments::cli_paths(Some(&ws), "Lab")
        .unwrap()
        .state;
    let h = history.to_string_lossy().into_owned();
    let o = run_env(&["export", "sarif", "--run", &newer, "--state", &h]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(o.stdout, sarif);
    let o = run_env(&[
        "evidence", "--run", &newer, "--state", &h, "-o", "s.zip", "--json",
    ]);
    assert!(o.status.code().is_some_and(|c| c != 2), "{}", text(&o));

    // The key: --key, else PATHWARDEN_EVIDENCE_KEY, else this computer's.
    let o = pw(&dir, &["evidence", "keygen", "--out", "own"]);
    assert!(o.status.success(), "{}", text(&o));
    let own = fingerprint(&dir, "own");
    let line = std::fs::read_to_string(dir.join("own").join("evidence.key"))
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .to_string();
    let with_var = |args: &[&str]| {
        let a = with_env(args);
        Command::new(bin())
            .current_dir(&dir)
            .env("NO_COLOR", "1")
            .env("PATHWARDEN_LOCK_WAIT", "0")
            .env("LOCALAPPDATA", dir.join("lad"))
            .env("PATHWARDEN_TEST_KEYSTORE", dir.join("keystore"))
            .env("PATHWARDEN_EVIDENCE_KEY", &line)
            .args(&a)
            .output()
            .unwrap()
    };
    let signer = |o: &Output| -> String {
        assert!(o.status.code().is_some_and(|c| c != 2), "{}", text(o));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        v["signed_by"].as_str().unwrap().to_string()
    };
    assert_eq!(
        signer(&with_var(&[
            "evidence", "--run", &newer, "-o", "v.zip", "--json"
        ])),
        own,
        "the variable wins over this computer's key"
    );
    let o = pw(&dir, &["evidence", "keygen", "--out", "third"]);
    assert!(o.status.success(), "{}", text(&o));
    let third = fingerprint(&dir, "third");
    assert_eq!(
        signer(&with_var(&[
            "evidence", "--run", &newer, "-o", "k.zip", "--key", "third", "--json",
        ])),
        third,
        "--key wins over the variable"
    );

    // Replacing the key, then using the old one again.
    let old = ws.join("evidence-key").join("evidence.key");
    std::fs::copy(&old, dir.join("old.key")).unwrap();
    let r: serde_json::Value = serde_json::from_str(&ok(&[
        "evidence",
        "key",
        "new",
        "--replace",
        "--workspace",
        &w,
        "--json",
    ]))
    .unwrap();
    assert_ne!(r["fingerprint"], fp.as_str());
    let r: serde_json::Value = serde_json::from_str(&ok(&[
        "evidence",
        "key",
        "use",
        "old.key",
        "--workspace",
        &w,
        "--json",
    ]))
    .unwrap();
    assert_eq!(r["fingerprint"], fp.as_str());
    let _ = std::fs::remove_dir_all(&dir);
}
