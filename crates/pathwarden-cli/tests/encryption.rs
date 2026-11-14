//! `pathwarden history storage set --encrypt` and `history storage
//! passphrase set|change|check|forget` (slice E), end to end: the
//! environment variable, this computer's store (a test folder in its place,
//! `PATHWARDEN_TEST_KEYSTORE`, so no real credential is touched), a server's
//! `-c pathwarden.toml`, and runs recorded into an encrypted history.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PASS: &str = "correct horse battery staple";
const NEW: &str = "a brand new passphrase";
const ENV: &str = "PATHWARDEN_HISTORY_PASSPHRASE";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn forest() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/forest")
        .to_string_lossy()
        .into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-cli-enc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs pathwarden in `dir` with the test keystore, no passphrase in the
/// environment unless `env` gives one, and `stdin` piped in.
fn pw(dir: &Path, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_TEST_KEYSTORE", dir.join("keystore"))
        .env_remove(ENV)
        .env_remove("PATHWARDEN_HISTORY_NEW_PASSPHRASE")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Lines are wrapped to the terminal: compared with the spaces collapsed.
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn err(out: &Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every file of a history folder, by path, with its contents.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

fn plain_json(state: &Path) -> Vec<PathBuf> {
    snapshot(state)
        .into_iter()
        .map(|(p, _)| p)
        .filter(|p| {
            p.extension().is_some_and(|x| x == "json")
                && p.file_name().is_some_and(|n| n != "findings.json")
        })
        .collect()
}

/// The environment variable, and runs recorded into an encrypted folder
/// history from the app's workspace.
#[test]
fn the_environment_variable_encrypts_and_opens_the_history() {
    let dir = scratch("env");
    let input = forest();
    let state = dir.join("ws").join("pathwarden-state");
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", &input],
        &[],
        None,
    ));
    let before = snapshot(&state);

    // Not without --yes: the warning, and nothing changed.
    let e = err(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--encrypt",
            "--from-env",
            "--workspace",
            "ws",
        ],
        &[(ENV, PASS)],
        None,
    ));
    assert!(e.contains("A lost passphrase can't be recovered"), "{e}");
    assert!(e.contains("--yes"), "{e}");
    assert_eq!(snapshot(&state), before);

    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--encrypt",
            "--from-env",
            "--yes",
            "--workspace",
            "ws",
        ],
        &[(ENV, PASS)],
        None,
    ));
    assert!(text.contains("files of the history."), "{text}");
    assert!(plain_json(&state).is_empty(), "{:?}", plain_json(&state));
    assert!(state.join(".pathwarden-encryption").is_file());
    // --from-env doesn't store it.
    let stored = std::fs::read_dir(dir.join("keystore"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "txt"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(stored, 0, "nothing stored");

    // show: from the environment, or not stored here.
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[(ENV, PASS)],
        None,
    ));
    assert!(
        text.contains("Encryption On (passphrase from PATHWARDEN_HISTORY_PASSPHRASE)."),
        "{text}"
    );
    assert!(text.contains("1 run, the latest"), "{text}");
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
        None,
    ));
    assert!(text.contains("On (passphrase not stored here)."), "{text}");
    assert!(
        text.contains("this computer has no passphrase for it"),
        "{text}"
    );
    let v: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
        &[],
        None,
    )))
    .unwrap();
    assert_eq!(v["encryption"]["state"], "on");
    assert_eq!(v["encryption"]["passphrase"], "not stored");

    // A run without the passphrase is refused and writes nothing.
    let before = snapshot(&state);
    let e = err(&pw(
        &dir,
        &["run", "--state", state.to_str().unwrap(), "-i", &input],
        &[],
        None,
    ));
    assert!(e.contains("this computer has no passphrase for it"), "{e}");
    let e = err(&pw(
        &dir,
        &["run", "--state", state.to_str().unwrap(), "-i", &input],
        &[(ENV, "not the passphrase")],
        None,
    ));
    assert!(
        e.contains(
            "That passphrase doesn't open this history (from PATHWARDEN_HISTORY_PASSPHRASE)"
        ),
        "{e}"
    );
    assert_eq!(snapshot(&state), before, "nothing written");
    let e = err(&pw(
        &dir,
        &["history", "--state", state.to_str().unwrap()],
        &[],
        None,
    ));
    assert!(e.contains("this computer has no passphrase for it"), "{e}");

    // With it: recorded, encrypted, and readable.
    ok(&pw(
        &dir,
        &["run", "--state", state.to_str().unwrap(), "-i", &input],
        &[(ENV, PASS)],
        None,
    ));
    assert!(plain_json(&state).is_empty());
    let text = ok(&pw(
        &dir,
        &["history", "--state", state.to_str().unwrap()],
        &[(ENV, PASS)],
        None,
    ));
    assert!(
        text.contains("2 runs") || text.matches("T").count() >= 2,
        "{text}"
    );

    // Off, with the warning first.
    let e = err(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--no-encrypt",
            "--workspace",
            "ws",
        ],
        &[(ENV, PASS)],
        None,
    ));
    assert!(e.contains("plain text again"), "{e}");
    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--no-encrypt",
            "--yes",
            "--workspace",
            "ws",
        ],
        &[(ENV, PASS)],
        None,
    ));
    assert!(
        text.contains("Decrypted ") && text.contains("plain text from now on"),
        "{text}"
    );
    assert!(!state.join(".pathwarden-encryption").exists());
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
        None,
    ));
    assert!(text.contains("Off: the files are plain JSON."), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `passphrase set|check|change|forget` against this computer's store.
#[test]
fn the_passphrase_is_stored_checked_changed_and_forgotten() {
    let dir = scratch("store");
    let input = forest();
    let state = dir.join("ws").join("pathwarden-state");
    let state_arg = state.to_str().unwrap().to_string();
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", &input],
        &[],
        None,
    ));
    let storage = |args: &[&str]| {
        let mut v = vec!["history", "storage"];
        v.extend(args);
        v.extend(["--workspace", "ws"]);
        v.into_iter().map(String::from).collect::<Vec<_>>()
    };
    let call = |args: &[String], env: &[(&str, &str)], stdin: Option<&str>| {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        pw(&dir, &a, env, stdin)
    };

    // No passphrase for a plain history: it would make this computer
    // refuse the history.
    let e = err(&call(
        &storage(&["passphrase", "set"]),
        &[],
        Some(&format!("{PASS}\n")),
    ));
    assert!(
        e.contains("isn't encrypted, so there is no passphrase to store"),
        "{e}"
    );
    // Too short, piped in: refused.
    let e = err(&call(
        &storage(&["set", "--encrypt", "--yes"]),
        &[],
        Some("short\n"),
    ));
    assert!(e.contains("at least 12 characters"), "{e}");
    // Encrypted with the passphrase piped in, which is then stored.
    let text = ok(&call(
        &storage(&["set", "--encrypt", "--yes"]),
        &[],
        Some(&format!("{PASS}\n")),
    ));
    assert!(text.contains("files of the history"), "{text}");
    assert!(
        text.contains("The passphrase is stored on this computer"),
        "{text}"
    );
    let text = ok(&call(
        &storage(&["passphrase", "set"]),
        &[],
        Some(&format!("{PASS}\n")),
    ));
    assert!(
        text.contains("Stored on this computer for this account"),
        "{text}"
    );
    let text = ok(&call(&storage(&["show"]), &[], None));
    assert!(
        text.contains("On (passphrase stored on this computer)."),
        "{text}"
    );
    let text = ok(&call(&storage(&["passphrase", "check"]), &[], None));
    assert!(text.contains("opens this history"), "{text}");
    // A run needs nothing more.
    ok(&pw(
        &dir,
        &["run", "--state", &state_arg, "-i", &input],
        &[],
        None,
    ));

    // A wrong one is never stored.
    let e = err(&call(
        &storage(&["passphrase", "set"]),
        &[],
        Some("not the right passphrase\n"),
    ));
    assert!(
        e.contains("That passphrase doesn't open this history"),
        "{e}"
    );
    ok(&call(&storage(&["passphrase", "check"]), &[], None));

    // Change: every file again, the stored copy updated; the old one no
    // longer opens it.
    let before = snapshot(&state);
    let text = ok(&call(
        &storage(&["passphrase", "change", "--from-env"]),
        &[("PATHWARDEN_HISTORY_NEW_PASSPHRASE", NEW)],
        None,
    ));
    assert!(
        text.contains("files again with the new passphrase."),
        "{text}"
    );
    assert!(
        text.contains("The new passphrase is stored on this computer"),
        "{text}"
    );
    let after = snapshot(&state);
    for (path, bytes) in &before {
        if path.to_string_lossy().ends_with(".age") {
            let now = after.iter().find(|(p, _)| p == path).map(|(_, b)| b);
            assert!(
                now.is_some_and(|b| b != bytes),
                "{} not re-encrypted",
                path.display()
            );
        }
    }
    ok(&call(&storage(&["passphrase", "check"]), &[], None));
    let e = err(&call(
        &storage(&["passphrase", "check"]),
        &[(ENV, PASS)],
        None,
    ));
    assert!(
        e.contains(
            "That passphrase doesn't open this history (from PATHWARDEN_HISTORY_PASSPHRASE)"
        ),
        "{e}"
    );
    let text = ok(&pw(&dir, &["history", "--state", &state_arg], &[], None));
    assert!(!text.is_empty());

    // Forget: gone from this computer.
    let text = ok(&call(&storage(&["passphrase", "forget"]), &[], None));
    assert!(
        text.contains("Removed the entry in the test keystore."),
        "{text}"
    );
    let text = ok(&call(&storage(&["passphrase", "forget"]), &[], None));
    assert!(text.contains("Nothing was stored"), "{text}");
    let text = ok(&call(&storage(&["show"]), &[], None));
    assert!(text.contains("On (passphrase not stored here)."), "{text}");
    let e = err(&call(&storage(&["passphrase", "check"]), &[], None));
    assert!(e.contains("this computer has no passphrase for it"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A server's `-c pathwarden.toml`, without the app's workspace.
#[test]
fn a_servers_config_is_encrypted_with_dash_c() {
    let dir = scratch("server");
    let input = forest();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[state]\nbackend = \"local\"\npath = \"pathwarden-state\"\n",
    )
    .unwrap();
    ok(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[],
        None,
    ));
    let state = dir.join("pathwarden-state");
    // --config goes with --encrypt only.
    let e = err(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "pathwarden.toml",
            "--names",
        ],
        &[],
        None,
    ));
    assert!(e.contains("cannot be used with"), "{e}");
    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "pathwarden.toml",
            "--encrypt",
            "--yes",
        ],
        &[],
        Some(&format!("{PASS}\n")),
    ));
    assert!(text.contains("files of the history"), "{text}");
    assert!(
        text.contains("The passphrase is stored on this computer"),
        "{text}"
    );
    assert!(plain_json(&state).is_empty());
    ok(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[],
        None,
    ));
    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "passphrase",
            "check",
            "-c",
            "pathwarden.toml",
        ],
        &[],
        None,
    ));
    assert!(text.contains("opens this history"), "{text}");
    assert!(plain_json(&state).is_empty());

    // The config records it: a history found plain there (its files
    // replaced behind Pathwarden's back) is refused.
    let toml = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(toml.contains("encrypted = true"), "{toml}");
    // It speaks for that history only: another folder given with --state
    // is not refused.
    ok(&pw(
        &dir,
        &[
            "run",
            "-c",
            "pathwarden.toml",
            "--state",
            "other-state",
            "-i",
            &input,
        ],
        &[],
        None,
    ));
    std::fs::remove_dir_all(&state).unwrap();
    let e = err(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[],
        None,
    ));
    assert!(e.contains("[state] encrypted = true"), "{e}");
    // `pathwarden history` refuses it too, naming the file that says so.
    std::fs::copy(dir.join("pathwarden.toml"), dir.join("s.toml")).unwrap();
    let e = err(&pw(&dir, &["history", "-c", "s.toml"], &[], None));
    assert!(e.contains("s.toml says the history"), "{e}");
    std::fs::remove_file(dir.join("s.toml")).unwrap();
    // --no-encrypt accepts it, writing nothing, and clears the setting.
    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "pathwarden.toml",
            "--no-encrypt",
            "--yes",
        ],
        &[],
        None,
    ));
    assert!(
        text.contains("Accepted the history as no longer encrypted"),
        "{text}"
    );
    assert!(text.contains("Nothing was written"), "{text}");
    let toml = std::fs::read_to_string(dir.join("pathwarden.toml")).unwrap();
    assert!(!toml.contains("encrypted = true"), "{toml}");
    ok(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[],
        None,
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Git for Windows' default `core.autocrlf=true` (here from a global
/// config file) must not make a second computer's checkout of the stub
/// look like a planted plain file; and the environment variable, set for
/// the account, doesn't make another, plain history of it refused.
#[test]
fn autocrlf_and_a_second_plain_history_with_the_variable_set() {
    let have_git = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_git {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    let dir = scratch("crlf");
    let input = forest();
    let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let remote = dir.join("state.git");
    let gitconfig = dir.join("gitconfig");
    std::fs::write(&gitconfig, "[core]\n\tautocrlf = true\n").unwrap();
    let global = gitconfig.to_str().unwrap().to_string();
    let out = Command::new("git")
        .args(["init", "-q", "--bare", &slash(&remote)])
        .output()
        .unwrap();
    assert!(out.status.success());
    for (name, work) in [("a.toml", "work-a"), ("b.toml", "work-b")] {
        std::fs::write(
            dir.join(name),
            format!(
                "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{work}\"\n",
                slash(&remote)
            ),
        )
        .unwrap();
    }
    let env = [(ENV, PASS), ("GIT_CONFIG_GLOBAL", global.as_str())];
    ok(&pw(
        &dir,
        &["run", "-c", "a.toml", "-i", &input],
        &env[1..],
        None,
    ));
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "a.toml",
            "--encrypt",
            "--yes",
            "--from-env",
        ],
        &env,
        None,
    ));
    // The second computer clones under autocrlf=true.
    let out = pw(&dir, &["run", "-c", "b.toml", "-i", &input], &env, None);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    ok(&out);
    assert!(!stderr.contains("in plain text"), "{stderr}");
    let stub = std::fs::read(dir.join("work-b").join("findings.json")).unwrap();
    assert!(!stub.contains(&b'\r'), "checked out byte for byte");

    // Another environment of the same account, plain, with the variable
    // set: not refused.
    std::fs::write(
        dir.join("plain.toml"),
        "[state]\nbackend = \"local\"\npath = \"plain-state\"\n",
    )
    .unwrap();
    ok(&pw(
        &dir,
        &["run", "-c", "plain.toml", "-i", &input],
        &env,
        None,
    ));
    ok(&pw(&dir, &["history", "-c", "plain.toml"], &env, None));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A history folder that is a git repository, with git missing from PATH:
/// its commits can't be checked for a removed encryption marker, so the
/// run is refused, never taken for a repository with nothing to check.
#[test]
fn git_missing_from_path_fails_closed() {
    let have_git = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_git {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    let dir = scratch("nogit");
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    for args in [
        vec!["init", "-q"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "x",
        ],
    ] {
        let out = Command::new("git")
            .arg("-C")
            .arg(&state)
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    let state_arg = state.to_str().unwrap().to_string();
    let e = err(&pw(
        &dir,
        &["run", "--state", &state_arg, "-i", &forest()],
        &[("PATH", "")],
        None,
    ));
    assert!(e.contains("Checking the history's git commits"), "{e}");
    assert!(!state.join("last-run.json").exists(), "nothing written");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Programs Pathwarden starts never see the passphrase variables: here a
/// commit hook in the git working copy records what it was given.
#[test]
fn git_children_never_see_the_passphrase() {
    let have_git = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_git {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    let dir = scratch("children");
    let input = forest();
    let remote = dir.join("state.git");
    let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let out = Command::new("git")
        .args(["init", "-q", "--bare", &slash(&remote)])
        .output()
        .unwrap();
    assert!(out.status.success());
    std::fs::write(
        dir.join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"work\"\n",
            slash(&remote)
        ),
    )
    .unwrap();
    ok(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[],
        None,
    ));
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "pathwarden.toml",
            "--encrypt",
            "--yes",
            "--from-env",
        ],
        &[(ENV, PASS)],
        None,
    ));
    let seen = dir.join("seen.txt");
    let hook = dir
        .join("work")
        .join(".git")
        .join("hooks")
        .join("post-commit");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf '[%s][%s]' \"$PATHWARDEN_HISTORY_PASSPHRASE\" \"$PATHWARDEN_HISTORY_NEW_PASSPHRASE\" > '{}'\n",
            slash(&seen)
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    ok(&pw(
        &dir,
        &["run", "-c", "pathwarden.toml", "-i", &input],
        &[(ENV, PASS), ("PATHWARDEN_HISTORY_NEW_PASSPHRASE", NEW)],
        None,
    ));
    assert_eq!(
        std::fs::read_to_string(&seen).expect("the hook ran"),
        "[][]",
        "the commit hook saw a passphrase"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--keep full --encrypt` in one step: the history is encrypted before the
/// shared settings go into it, so no object of the repository ever holds
/// an accepted risk's reason or who accepted it, and the commits after it
/// name nobody.
#[test]
fn full_runs_and_settings_with_encrypt_shares_nothing_plain() {
    let have_git = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_git {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    let dir = scratch("fullenc");
    let input = forest();
    let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let remote = dir.join("state.git");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&remote)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let out = Command::new("git")
        .args(["init", "-q", "--bare", &slash(&remote)])
        .output()
        .unwrap();
    assert!(out.status.success());
    let ws = dir.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let config = ws.join("pathwarden.toml");
    std::fs::write(
        &config,
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\n",
            slash(&remote)
        ),
    )
    .unwrap();
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", &input],
        &[],
        None,
    ));
    // An accepted risk, after the run (which keeps names only).
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(
        "\n[[suppress]]\nrule = \"PW-011\"\nreason = \"Break-glass, reviewed quarterly\"\naccepted_by = 'NORTH\\eddard.stark'\naccepted_on = \"PW-SCHED01\"\n",
    );
    std::fs::write(&config, text).unwrap();
    let out = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--keep",
            "full",
            "--encrypt",
            "--from-env",
            "--yes",
            "--workspace",
            "ws",
        ],
        &[(ENV, PASS)],
        None,
    ));
    let encrypted = out.find("Encrypted").unwrap_or_else(|| panic!("{out}"));
    let shared = out
        .find("Shared settings pushed")
        .unwrap_or_else(|| panic!("{out}"));
    assert!(encrypted < shared, "encrypted first: {out}");
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains("keep = \"full\"") && text.contains("encrypted = true"),
        "{text}"
    );
    let files = git(&["ls-tree", "-r", "--name-only", "main"]);
    assert!(files.contains("settings/pathwarden.toml.age"), "{files}");
    let objects = git(&["cat-file", "--batch-all-objects", "--batch"]);
    for s in [
        "Break-glass, reviewed quarterly",
        "eddard.stark",
        "accepted_by",
        "Changed-by",
    ] {
        assert!(
            !objects.contains(s),
            "an object of the repository holds {s}"
        );
    }
    let sealed = git(&[
        "log",
        "-1",
        "--format=%H",
        "--grep=encrypt the history",
        "main",
    ]);
    // The encrypting commit and every one after it.
    let format = "--format=%an <%ae>|%cn <%ce>";
    let who = git(&["log", "-1", format, sealed.trim()])
        + &git(&["log", format, &format!("{}..main", sealed.trim())]);
    assert!(who.lines().count() >= 2, "{who}");
    for line in who.lines() {
        assert_eq!(
            line, "Pathwarden <pathwarden@invalid>|Pathwarden <pathwarden@invalid>",
            "{who}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `pathwarden runs` on a computer without the passphrase says so, as the
/// Runs page's card does, and lists the runs analysed here.
#[test]
fn runs_list_without_the_passphrase_says_so() {
    let dir = scratch("runs");
    let input = forest();
    let state = dir.join("ws").join("pathwarden-state");
    let state_arg = state.to_str().unwrap().to_string();
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", &input],
        &[],
        None,
    ));
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--encrypt",
            "--yes",
            "--workspace",
            "ws",
        ],
        &[],
        Some(&format!("{PASS}\n")),
    ));
    // A run only the history has.
    ok(&pw(
        &dir,
        &["run", "--state", &state_arg, "-i", &input, "--no-outputs"],
        &[],
        None,
    ));
    let list = |env: &[(&str, &str)]| {
        let out = pw(
            &dir,
            &["runs", "list", "--workspace", "ws", "--json"],
            env,
            None,
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let v = list(&[]);
    assert!(v["problem"].is_null(), "{v}");
    assert_eq!(v["runs"].as_array().unwrap().len(), 2, "{v}");
    // "Full runs and settings", so History storage states its Full runs.
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--keep",
            "full",
            "--yes",
            "--workspace",
            "ws",
        ],
        &[],
        None,
    ));

    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "passphrase",
            "forget",
            "--workspace",
            "ws",
        ],
        &[],
        None,
    ));
    let v = list(&[]);
    let problem = v["problem"].as_str().unwrap_or_default();
    // The terminal's own lead, then how to store the passphrase.
    assert!(
        problem
            .starts_with("This history is encrypted and this computer has no passphrase for it."),
        "{v}"
    );
    assert!(!problem.contains("show below"), "{v}");
    assert!(
        problem.contains("pathwarden history storage passphrase set"),
        "{v}"
    );
    // History storage says the same about its full runs.
    let out = pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
        None,
    );
    assert!(
        ok(&out).contains("Full runs Can't be read without the passphrase."),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1, "only the run analysed here: {v}");
    assert_eq!(runs[0]["source"], "local");
    // Never called local only: the history may well hold it.
    assert!(runs[0]["tags"].as_array().unwrap().is_empty(), "{v}");
    // With the passphrase in the environment, both again.
    let v = list(&[(ENV, PASS)]);
    assert_eq!(v["runs"].as_array().unwrap().len(), 2, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `history storage accept` after a restore made on purpose: what
/// it does, nothing without --yes off a terminal, then this computer's
/// records reset and the history read as it is. Refused with nothing to
/// accept.
#[test]
fn accept_takes_a_restored_history_as_it_is() {
    let dir = scratch("accept");
    let input = forest();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "[state]\nbackend = \"local\"\npath = \"pathwarden-state\"\n",
    )
    .unwrap();
    let env = [(ENV, PASS)];
    let run = || {
        pw(
            &dir,
            &["run", "-c", "pathwarden.toml", "-i", &input],
            &env,
            None,
        )
    };
    let accept = |yes: bool| {
        let mut args = vec!["history", "storage", "accept", "-c", "pathwarden.toml"];
        if yes {
            args.push("--yes");
        }
        pw(&dir, &args, &env, None)
    };
    ok(&run());
    // A plain history: nothing refused.
    let text = ok(&accept(true));
    assert_eq!(text, "Nothing in this history is refused.");
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "-c",
            "pathwarden.toml",
            "--encrypt",
            "--from-env",
            "--yes",
        ],
        &env,
        None,
    ));
    let state = dir.join("pathwarden-state");
    ok(&run());
    let old = std::fs::read(state.join("findings.json.age")).unwrap();
    ok(&run());
    // Records kept, but nothing refused: nothing changes.
    let records = dir.join("keystore").join("pins").join("sequences");
    let kept = || std::fs::read_dir(&records).unwrap().count();
    let before = kept();
    assert!(before > 0);
    let text = ok(&accept(true));
    assert_eq!(text, "Nothing in this history is refused.");
    assert_eq!(kept(), before);
    // Restored from a backup: refused as an older copy, with the command.
    std::fs::write(state.join("findings.json.age"), &old).unwrap();
    let e = err(&run());
    assert!(
        e.contains("findings.json in the history was replaced with an older copy."),
        "{e}"
    );
    assert!(e.contains("pathwarden history storage accept"), "{e}");
    // Without --yes and no terminal: what it does, and nothing changed.
    let out = accept(false);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let e = err(&out);
    assert!(
        said.contains("findings.json in the history was replaced with an older copy."),
        "{said}"
    );
    assert!(
        said.contains("This computer will trust the history's files as they are now."),
        "{said}"
    );
    assert!(e.contains("Nothing was changed"), "{e}");
    assert!(e.contains("--yes"), "{e}");
    let e = err(&run());
    assert!(e.contains("older copy"), "{e}");
    // With --yes: reset, named, and the history reads as it is.
    let text = ok(&accept(true));
    assert!(text.contains("Accepted the history in"), "{text}");
    assert!(text.contains("records:"), "{text}");
    assert!(text.contains(&records.display().to_string()), "{text}");
    // Nothing refused any more.
    let text = ok(&accept(true));
    assert_eq!(text, "Nothing in this history is refused.");
    ok(&run());
    let _ = std::fs::remove_dir_all(&dir);
}
