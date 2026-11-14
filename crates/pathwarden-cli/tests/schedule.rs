//! `pathwarden schedule`: the files it writes are the ones the UI's
//! Schedule page generates for a run collected the same way, byte for byte.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pathwarden_ui::collect::{Detected, ScheduleParams, Target};
use pathwarden_ui::workspace::RunSummary;

const OK: i32 = 0;
const ERROR: i32 = 2;

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-schedule-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pathwarden"))
        .current_dir(dir)
        .env("NO_COLOR", "1")
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

/// A run of `domains` collected with `method` from dc01.contoso.local over
/// LDAPS, as the Collect wizard records it.
fn run(domains: &[&str], method: &str) -> RunSummary {
    serde_json::from_value(serde_json::json!({
        "id": "20261009-020000-abcdef", "created_at": 0, "collected_at": null,
        "source": "x", "demo": false, "domains": domains, "objects": 0,
        "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
        "protection_score": null, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "0.1.0",
        "collection": {
            "method": method, "scope": "dc-only", "domain": "contoso.local",
            "server": "dc01.contoso.local", "ldaps": true, "current_user": true,
        },
    }))
    .unwrap()
}

/// The files in `dir`, sorted by name.
fn written(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

fn same_as_the_page(os: &str, method: &str, params: ScheduleParams, args: &[&str]) {
    let dir = scratch(os);
    let out = dir.join("out");
    let mut all = vec!["schedule", "--os", os, "--output", out.to_str().unwrap()];
    all.extend_from_slice(args);
    let o = pw(&dir, &all);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));

    let summary = run(&["CONTOSO.LOCAL", "FABRIKAM.LOCAL"], method);
    let params = ScheduleParams {
        os: Some(os.into()),
        ..params
    };
    let (page, errors) = Target::resolve(&params, Some(&summary), &Detected::default());
    assert!(errors.is_empty(), "{errors:?}");
    let mut expected: Vec<(String, Vec<u8>)> = page
        .files()
        .into_iter()
        .map(|(n, t)| (n, t.into_bytes()))
        .collect();
    expected.sort();
    let got = written(&out);
    assert_eq!(
        got.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        expected.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    for ((name, got), (_, want)) in got.iter().zip(&expected) {
        assert!(got == want, "{os} {name} differs");
        // What the page offers as a download is the same file.
        if let Some(served) = page.file(name) {
            assert_eq!(*got, served.into_bytes(), "{name}");
        }
    }

    // The steps are printed in order, as the page shows them.
    let t = text(&o);
    let mut at = 0;
    for (n, step) in page.steps().iter().enumerate() {
        let heading = format!("{}. {}", n + 1, step.title);
        let found = t[at..]
            .find(&heading)
            .unwrap_or_else(|| panic!("{heading} missing or out of order:\n{t}"));
        at += found;
        for b in &step.blocks {
            assert!(t[at..].contains(&format!("→ {}", b.file)), "{t}");
        }
        if os == "linux" && step.blocks.iter().any(|b| b.file == "setup.sh") {
            assert!(t[at..].contains("sudo sh setup.sh"), "{t}");
        }
    }
    assert!(!t.contains("<code>"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn windows_files_match_the_page() {
    // A SharpHound run: a build without the built-in collector schedules
    // SharpHound on the page whatever the run used, so only this compares
    // in both builds (the library's tests compare a built-in run).
    same_as_the_page(
        "windows",
        "sharphound",
        ScheduleParams {
            folder: Some(r"D:\Tools\Pathwarden".into()),
            account: Some(r"CONTOSO\gmsa-pw$".into()),
            at: Some("23:30".into()),
            ..ScheduleParams::default()
        },
        &[
            "--domain",
            "contoso.local,fabrikam.local",
            "--server",
            "dc01.contoso.local",
            "--ldaps",
            "--sharphound",
            "--folder",
            r"D:\Tools\Pathwarden",
            "--account",
            r"CONTOSO\gmsa-pw$",
            "--at",
            "23:30",
        ],
    );
}

#[test]
fn linux_files_match_the_page() {
    same_as_the_page(
        "linux",
        "builtin",
        ScheduleParams {
            folder: Some("/srv/pathwarden".into()),
            user: Some("svc-pw".into()),
            ..ScheduleParams::default()
        },
        &[
            "--domain",
            "contoso.local",
            "--domain",
            "fabrikam.local",
            "--server",
            "dc01.contoso.local",
            "--folder",
            "/srv/pathwarden",
            "--user",
            "svc-pw",
        ],
    );
}

#[test]
fn existing_files_are_kept_unless_forced() {
    let dir = scratch("force");
    let args = [
        "schedule",
        "--os",
        "linux",
        "--domain",
        "contoso.local",
        "--out",
        "out",
    ];
    assert_eq!(pw(&dir, &args).status.code(), Some(OK));
    std::fs::write(dir.join("out").join("run.sh"), "mine").unwrap();
    let o = pw(&dir, &args);
    assert_eq!(o.status.code(), Some(ERROR), "{}", text(&o));
    assert!(text(&o).contains("run.sh"), "{}", text(&o));
    assert!(text(&o).contains("--force"), "{}", text(&o));
    assert_eq!(
        std::fs::read_to_string(dir.join("out").join("run.sh")).unwrap(),
        "mine"
    );
    let mut forced = args.to_vec();
    forced.push("--force");
    assert_eq!(pw(&dir, &forced).status.code(), Some(OK));
    assert!(std::fs::read_to_string(dir.join("out").join("run.sh"))
        .unwrap()
        .starts_with("#!/bin/sh\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_arguments_exit_2_and_write_nothing() {
    let dir = scratch("bad");
    for (args, says) in [
        (&["--os", "windows"][..], "--domain"),
        (
            &["--os", "windows", "--domain", "bad domain"],
            "isn't a domain name",
        ),
        (
            &[
                "--os",
                "windows",
                "--domain",
                "contoso.local",
                "--at",
                "25:00",
            ],
            "HH:MM",
        ),
        (
            &[
                "--os",
                "windows",
                "--domain",
                "contoso.local",
                "--account",
                "CONTOSO\\user",
            ],
            "gMSA",
        ),
        (
            &[
                "--os",
                "windows",
                "--domain",
                "contoso.local",
                "--folder",
                "relative",
            ],
            "full path",
        ),
        (
            &[
                "--os",
                "linux",
                "--domain",
                "contoso.local",
                "--account",
                "CONTOSO\\g$",
            ],
            "--account",
        ),
        (
            &[
                "--os",
                "windows",
                "--domain",
                "contoso.local",
                "--user",
                "svc",
            ],
            "--user",
        ),
        (
            &["--os", "linux", "--domain", "contoso.local", "--sharphound"],
            "SharpHound",
        ),
        (
            &["--os", "linux", "--domain", "contoso.local", "--ldaps"],
            "--ldaps",
        ),
        (
            &["--os", "linux", "--domain", "contoso.local", "--server=-x"],
            "domain controller",
        ),
        (&["--os", "macos", "--domain", "contoso.local"], "macos"),
    ] {
        let mut all = vec!["schedule", "--out", "out"];
        all.extend_from_slice(args);
        let o = pw(&dir, &all);
        assert_eq!(o.status.code(), Some(ERROR), "{args:?}: {}", text(&o));
        assert!(text(&o).contains(says), "{args:?}: {}", text(&o));
        assert!(!dir.join("out").exists(), "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn help_lists_the_options() {
    let dir = scratch("help");
    let o = pw(&dir, &["schedule", "--help"]);
    assert_eq!(o.status.code(), Some(OK));
    let t = text(&o);
    for opt in [
        "--os",
        "--domain",
        "--server",
        "--ldaps",
        "--scope",
        "--sharphound",
        "--folder",
        "--account",
        "--user",
        "--at",
        "--env",
        "--out",
        "--force",
    ] {
        assert!(t.contains(opt), "{opt}: {t}");
    }
    assert!(t.contains("never registers a task"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}
