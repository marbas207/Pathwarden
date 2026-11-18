//! The finding action examples in examples/actions pass `pathwarden action
//! check`: their describe and a dry run of every action they offer, on the
//! sample finding, with no problem. scripts/check-action-examples.py checks
//! the rest of the developer kit (schemas, helpers, the stub ticket system)
//! and runs this same check when given a binary.
//!
//! The Python examples need a Python 3.9 or later on PATH, and the
//! PowerShell one PowerShell (Windows PowerShell, or pwsh elsewhere); an
//! example whose interpreter isn't there is skipped with a note.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn example(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/actions")
        .join(name);
    std::path::absolute(p).unwrap().display().to_string()
}

/// The first `names` program on PATH that runs, by its full path: `python`
/// from a user install isn't in a folder only administrators can change,
/// so `action check` is given the full path, as the docs say.
fn on_path(names: &[&str], probe: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for n in names {
            let file = dir.join(format!("{n}{}", std::env::consts::EXE_SUFFIX));
            if !file.is_file() || file.to_string_lossy().contains("WindowsApps") {
                continue;
            }
            let runs = Command::new(&file)
                .args(probe)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if runs {
                return Some(file.display().to_string());
            }
        }
    }
    None
}

fn check(dir: &Path, args: &[String]) -> (bool, String) {
    let out = Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("LOCALAPPDATA", dir.join("lad"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env(
            "PW_EXAMPLE_WEBHOOK",
            "https://hooks.example.com/workflows/sample",
        )
        .env("PW_EXAMPLE_TOKEN", "sample-token")
        .env_remove("PATHWARDEN_SCHEDULED")
        .stdin(Stdio::null())
        .arg("action")
        .arg("check")
        .args(args)
        .output()
        .unwrap();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn strings(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_examples_pass_action_check() {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-action-examples-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut checked = 0;

    let python = on_path(
        &["python3", "python"],
        &["-c", "import sys; sys.exit(sys.version_info < (3, 9))"],
    );
    match &python {
        Some(py) => {
            for (name, settings) in [
                (
                    "rest-ticket.py",
                    &[
                        "base_url=https://desk.example.com/api",
                        "token_env=PW_EXAMPLE_TOKEN",
                        "queue=Identity",
                    ][..],
                ),
                ("owner-lookup.py", &[][..]),
            ] {
                let mut args = vec![py.clone()];
                for s in settings {
                    args.extend(strings(&["--setting", s]));
                }
                args.extend(["--".to_string(), example(name)]);
                let (ok, out) = check(&dir, &args);
                assert!(ok, "{name}: {out}");
                assert!(out.contains("No problems"), "{name}: {out}");
                checked += 1;
            }
        }
        None => eprintln!("skipped the Python examples: no Python 3.9 or later on PATH"),
    }

    let settings = strings(&[
        "--setting",
        "webhook_env=PW_EXAMPLE_WEBHOOK",
        "--setting",
        "format=teams",
    ]);
    let script = example("post-to-webhook.ps1");
    let args = if cfg!(windows) {
        Some([vec![script], settings].concat())
    } else if on_path(&["pwsh"], &["-NoProfile", "-Command", "exit 0"]).is_some() {
        // `pwsh` from a folder only administrators can change (/usr/bin).
        Some(
            [
                strings(&["pwsh"]),
                settings,
                strings(&["--", "-NoProfile", "-NonInteractive", "-File"]),
                vec![script],
            ]
            .concat(),
        )
    } else {
        eprintln!("skipped post-to-webhook.ps1: no pwsh on PATH");
        None
    };
    if let Some(args) = args {
        let (ok, out) = check(&dir, &args);
        assert!(ok, "post-to-webhook.ps1: {out}");
        checked += 1;
    }

    eprintln!("{checked} examples checked");
    let _ = std::fs::remove_dir_all(&dir);
}
