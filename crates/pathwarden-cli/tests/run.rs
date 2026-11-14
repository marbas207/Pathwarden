//! `pathwarden run` end to end, with local and git state.

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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-run-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn local_state_tracks_changes() {
    let dir = scratch("local");
    let (forest, sdprop) = (testdata("forest"), testdata("sdprop"));

    let first = run(
        &dir,
        &["run", "-i", &forest, "--state", "st", "--event", "ev.json"],
    );
    assert!(first.contains("15 new, 0 back, 0 fixed"), "{first}");
    let second = run(&dir, &["run", "-i", &forest, "--state", "st"]);
    assert!(
        second.contains("0 new, 0 back, 0 fixed, 15 still open"),
        "{second}"
    );
    // A different domain: CONTOSO's findings are held, never resolved.
    let third = run(&dir, &["run", "-i", &sdprop, "--state", "st"]);
    assert!(
        third.contains("0 fixed") && third.contains("15 can't tell"),
        "{third}"
    );
    // Same domains, one rule turned off: its finding is no longer
    // checked, not fixed...
    std::fs::write(
        dir.join("nolaps.toml"),
        "[rules]
disabled = [\"PW-011\"]
",
    )
    .unwrap();
    let fourth = run(
        &dir,
        &["run", "-i", &forest, "--state", "st", "-c", "nolaps.toml"],
    );
    assert!(
        fourth.contains("0 fixed") && fourth.contains("1 no longer checked (rule turned off)"),
        "{fourth}"
    );
    // ...and with the rule on again it is open, not back after a fix.
    let back = run(&dir, &["run", "-i", &forest, "--state", "st"]);
    assert!(
        back.contains("0 new, 0 back, 0 fixed, 15 still open"),
        "{back}"
    );

    let state = std::fs::read_to_string(dir.join("st/findings.json")).unwrap();
    // Numbers with names (0.1.7, the only level without full runs): finding
    // titles and domain names are kept in the state.
    assert!(state.contains("\"title\""), "titles are kept");
    assert!(state.contains("\"domain\""), "domains are kept");
    assert_eq!(
        std::fs::read_dir(dir.join("st/history")).unwrap().count(),
        5
    );

    let event = read_json(&dir.join("ev.json"));
    assert_eq!(event["schema"], "pathwarden.event.v1");
    assert_eq!(event["findings"].as_array().unwrap().len(), 15);
    assert_eq!(event["findings"][0]["change"], "new");
    assert!(
        event["findings"][0]["title"].is_string(),
        "events carry details"
    );
    assert!(event["guides"]["PW-002"]
        .as_str()
        .unwrap()
        .starts_with("# PW-002"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn git_state_survives_a_fresh_clone() {
    if git_command().arg("--version").output().is_err() {
        eprintln!("git not installed; skipping");
        return;
    }
    let dir = scratch("git");
    let remote = dir.join("remote.git");
    assert!(git_command()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let config = format!(
        "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"work\"\n",
        remote.to_string_lossy().replace('\\', "/")
    );
    std::fs::write(dir.join("git.toml"), config).unwrap();
    let forest = testdata("forest");

    let first = run(&dir, &["run", "-i", &forest, "-c", "git.toml"]);
    assert!(
        first.contains("15 new") && first.contains("pushed"),
        "{first}"
    );
    // Another machine (no working copy) continues from the remote.
    std::fs::remove_dir_all(dir.join("work")).unwrap();
    let second = run(&dir, &["run", "-i", &forest, "-c", "git.toml"]);
    assert!(
        second.contains("0 new, 0 back, 0 fixed, 15 still open"),
        "{second}"
    );

    let log = git_command()
        .arg("-C")
        .arg(&remote)
        .args(["log", "--oneline", "main"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&log.stdout).lines().count(), 2);
    let state = read_json(&dir.join("work/findings.json"));
    assert_eq!(state["findings"].as_object().unwrap().len(), 15);
    assert!(!dir.join("work.lock").exists(), "lock released");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn output_plugins_get_the_event_and_failures_fail_the_run() {
    let dir = scratch("outputs");
    let forest = testdata("forest");
    let exe = bin().replace('\\', "/");
    // Stand-in plugins: `pathwarden rules` succeeds (and ignores stdin),
    // `pathwarden guide PW-999` fails.
    let config = format!(
        "[[output]]\nplugin = \"ok\"\ncommand = [\"{exe}\", \"rules\"]\ncolor = \"green\"\n\n\
         [[output]]\nplugin = \"broken\"\ncommand = [\"{exe}\", \"guide\", \"PW-999\"]\n"
    );
    std::fs::write(dir.join("p.toml"), config).unwrap();
    let out = Command::new(bin())
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .args(["run", "-i", &forest, "-c", "p.toml", "--state", "st"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("[ok] PW-001"),
        "plugin output is relayed: {stdout}"
    );
    assert!(stderr.contains("Plugin broken failed"), "{stderr}");
    assert!(!out.status.success(), "a failed plugin fails the run");
    assert!(
        dir.join("st/findings.json").exists(),
        "state is saved regardless"
    );

    // --no-outputs skips them.
    let skipped = run(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "-c",
            "p.toml",
            "--state",
            "st",
            "--no-outputs",
        ],
    );
    assert!(!skipped.contains("[ok]"));
    std::fs::remove_dir_all(&dir).ok();
}

/// The lab's castelblack check: a computer with a Tier Zero
/// session is read once, then not reached in two runs. Nothing that rests
/// on it is marked fixed in either, and its findings are fixed once it is
/// read again with the session gone.
#[test]
fn a_computer_not_reached_twice_holds_what_rests_on_it() {
    let dir = scratch("unreached");
    let srv01 = "S-1-5-21-1000-1000-1000-1001";
    // The forest, and the same with SRV01 (DA_ALICE's session, SVC_SQL's
    // admin right) not reached, or read with neither.
    let copy = |name: &str, edit: &dyn Fn(&mut serde_json::Value)| {
        let to = dir.join(name);
        std::fs::create_dir_all(&to).unwrap();
        for e in std::fs::read_dir(testdata("forest")).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
        let file = to.join("contoso_computers.json");
        let mut doc = read_json(&file);
        for c in doc["data"].as_array_mut().unwrap() {
            if c["ObjectIdentifier"] == srv01 {
                edit(c);
            }
        }
        std::fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
        to.to_string_lossy().into_owned()
    };
    let full = copy("full", &|_| {});
    let down = copy("down", &|c| {
        for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
            c[k] = serde_json::json!({"Results": [], "Collected": false,
                "FailureReason": "not reachable"});
        }
        for g in c["LocalGroups"].as_array_mut().unwrap() {
            g["Results"] = serde_json::json!([]);
            g["Collected"] = serde_json::json!(false);
        }
    });
    let clean = copy("clean", &|c| {
        c["Sessions"]["Results"] = serde_json::json!([]);
        for g in c["LocalGroups"].as_array_mut().unwrap() {
            g["Results"] = serde_json::json!([]);
        }
    });
    let appdata = dir.join("appdata");
    std::fs::create_dir_all(&appdata).unwrap();
    let pw = |input: &str| {
        let out = Command::new(bin())
            .current_dir(&dir)
            .env("NO_COLOR", "1")
            .env("LOCALAPPDATA", &appdata)
            .args(["run", "-i", input, "--state", "st"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (first, _) = pw(&full);
    assert!(first.contains("0 fixed"), "{first}");
    for n in [2, 3] {
        let (out, err) = pw(&down);
        assert!(
            out.contains("0 fixed") && out.contains("can't tell"),
            "run {n}: {out}"
        );
        assert!(
            err.contains("Sessions weren't read on 1 computer that had one."),
            "run {n}: {err}"
        );
    }
    let last = read_json(&dir.join("st/last-run.json"));
    assert!(
        last["hosts"].as_str().is_some_and(|h| h.contains("s:")),
        "SRV01 carried forward: {last}"
    );
    let (fourth, _) = pw(&clean);
    assert!(!fourth.contains(" 0 fixed"), "{fourth}");
    assert!(!fourth.contains("can't tell"), "{fourth}");
    std::fs::remove_dir_all(&dir).ok();
}

/// An AzureHound read stopped by a limit: `run` warns, naming the
/// source, why and the setting; `summary --json` carries it.
#[test]
fn an_azurehound_read_that_stops_is_said() {
    let dir = scratch("og-incomplete");
    let local = dir.join("localappdata");
    std::fs::create_dir_all(&local).unwrap();
    let pw = |args: &[&str]| {
        let out = Command::new(bin())
            .current_dir(&dir)
            .env("NO_COLOR", "1")
            .env("LOCALAPPDATA", &local)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (ad, azure) = (testdata("entra/ad"), testdata("entra/azurehound"));
    // A whole read says nothing.
    let (_, err) = pw(&["run", "-i", &ad, &azure, "--state", "st"]);
    assert!(!err.contains("read only part way"), "{err}");

    // The kept-properties limit.
    std::fs::write(dir.join("kept.toml"), "[opengraph]\nmax_kept_mib = 0\n").unwrap();
    let (_, err) = pw(&["run", "-i", &ad, &azure, "--state", "st", "-c", "kept.toml"]);
    assert!(
        err.contains(
            "Warning: AzureHound was read only part way (the limit on kept properties). \
             Raise the limit with max_kept_mib under [opengraph] in pathwarden.toml. \
             Findings that rest on it aren't marked fixed."
        ),
        "{err}"
    );
    let (out, _) = pw(&["summary", "-i", &ad, &azure, "-c", "kept.toml", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let s = &v["incomplete_sources"][0];
    assert_eq!(s["source"], "AzureHound", "{s}");
    assert_eq!(s["limits"], serde_json::json!(["kept properties"]), "{s}");
    assert!(s["warning"]
        .as_str()
        .unwrap()
        .contains("Raise the limit with max_kept_mib"));

    // A record too large to load.
    let big_dir = dir.join("big");
    std::fs::create_dir_all(&big_dir).unwrap();
    let text = std::fs::read_to_string(Path::new(&azure).join("azurehound_hybrid.json")).unwrap();
    let big = "x".repeat(3 << 19);
    std::fs::write(
        big_dir.join("azurehound_hybrid.json"),
        text.replace(
            "\"displayName\": \"Partner\"",
            &format!("\"displayName\": \"{big}\""),
        ),
    )
    .unwrap();
    std::fs::write(dir.join("record.toml"), "[opengraph]\nmax_record_mib = 1\n").unwrap();
    let big_dir = big_dir.to_string_lossy().into_owned();
    let (_, err) = pw(&[
        "run",
        "-i",
        &ad,
        &big_dir,
        "--state",
        "st",
        "-c",
        "record.toml",
    ]);
    assert!(
        err.contains(
            "Warning: AzureHound was read only part way (1 record too large to load). \
             Raise the limit with max_record_mib under [opengraph] in pathwarden.toml."
        ),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// git, without the variables that would point it at another repository
/// (set when the tests run from a git hook).
fn git_command() -> Command {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    c
}
