//! Opening a shared history on a new computer from the command line:
//! `pathwarden history storage probe`, `pathwarden env create --from-git`
//! and `pathwarden history storage connect`, on local bare repositories
//! (file paths; no network). The passphrase comes from the environment
//! variable, and this computer's store is a test folder
//! (`PATHWARDEN_TEST_KEYSTORE`), so no real credential is touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PASS: &str = "correct horse battery staple";
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

fn git_command() -> Command {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    c
}

fn have_git() -> bool {
    let ok = git_command()
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        eprintln!("git is not installed: skipping this test");
    }
    ok
}

fn remove_all(dir: &Path) {
    fn writable(dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                writable(&p);
            } else if let Ok(m) = p.metadata() {
                let mut perms = m.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(&p, perms);
            }
        }
    }
    writable(dir);
    let _ = std::fs::remove_dir_all(dir);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-cx-{name}-{}", std::process::id()));
    remove_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_command()
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn bare(dir: &Path, name: &str) -> PathBuf {
    let remote = dir.join(format!("{name}.git"));
    git(dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    remote
}

/// Runs pathwarden in `dir`, never with this account's app data, store or
/// git settings, and with no terminal.
fn pw(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(bin());
    c.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        .env("LOCALAPPDATA", dir.join("appdata"))
        .env("PATHWARDEN_TEST_KEYSTORE", dir.join("keystore"))
        .env("GIT_CONFIG_GLOBAL", dir.join("gitconfig"))
        .env("GCM_INTERACTIVE", "never")
        .env_remove(ENV)
        .args(args)
        .stdin(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
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

/// Computer A: environment Lab keeping full runs, encrypted (`encrypt`)
/// or plain, with two runs recorded, in the bare repository `remote`.
fn computer_a(dir: &Path, remote: &Path, encrypt: bool) {
    let ws = dir.join("wsA");
    std::fs::create_dir_all(&ws).unwrap();
    let ws = ws.to_string_lossy().into_owned();
    let env = [(ENV, PASS)];
    ok(&pw(
        dir,
        &[
            "env",
            "create",
            "Lab",
            "--domains",
            "north.example",
            "--workspace",
            &ws,
        ],
        &[],
    ));
    let url = slash(remote);
    let mut set = vec![
        "history",
        "storage",
        "set",
        "--git",
        &url,
        "--keep",
        "full",
        "--yes",
        "--env",
        "Lab",
        "--workspace",
        &ws,
    ];
    if encrypt {
        set.extend(["--encrypt", "--from-env"]);
    } else {
        set.push("--no-encrypt");
    }
    ok(&pw(dir, &set, &env));
    for label in ["baseline", "after the fix"] {
        ok(&pw(
            dir,
            &[
                "run",
                "-i",
                &forest(),
                "--save",
                "--env",
                "Lab",
                "--workspace",
                &ws,
                "--label",
                label,
            ],
            &env,
        ));
    }
}

/// `[state]` of a `pathwarden.toml`.
fn state_of(path: &Path) -> pathwarden_core::config::StateConfig {
    pathwarden_core::config::Config::from_file(path)
        .unwrap()
        .state
}

/// What `history storage probe --json` says.
fn probe_json(dir: &Path, args: &[&str]) -> serde_json::Value {
    let ws = dir.join("wsP").to_string_lossy().into_owned();
    let mut a = vec!["history", "storage", "probe", "--json", "--workspace", &ws];
    a.extend(args);
    let out = pw(dir, &a, &[]);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Probe folders left behind in a workspace (there should be none).
fn leftovers(ws: &Path) -> Vec<String> {
    std::fs::read_dir(ws.join(".pathwarden-connect"))
        .map(|r| {
            r.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn probe_says_what_a_repository_holds_before_anything_is_saved() {
    if !have_git() {
        return;
    }
    let dir = scratch("probe");
    let enc = bare(&dir, "enc");
    computer_a(&dir, &enc, true);
    let plain = bare(&dir, "plain");
    computer_a(&dir.join("plainA"), &plain, false);
    let empty = bare(&dir, "empty");
    // A project's repository, not a history.
    let other = bare(&dir, "other");
    let seed = dir.join("seed");
    git(&dir, &["init", "-q", "-b", "main", &seed.to_string_lossy()]);
    std::fs::create_dir_all(seed.join("src")).unwrap();
    std::fs::write(seed.join("src/main.c"), "int main(void) { return 0; }\n").unwrap();
    std::fs::write(seed.join("README.md"), "# A project\n").unwrap();
    git(&seed, &["add", "-A"]);
    git(&seed, &["commit", "-q", "-m", "seed"]);
    git(&seed, &["push", "-q", &other.to_string_lossy(), "main"]);

    // Encrypted: what can be read without the passphrase.
    let j = probe_json(&dir, &["--git", &slash(&enc)]);
    assert_eq!(j["history"], true, "{j}");
    assert_eq!(j["encrypted"], true);
    assert_eq!(j["keep"], "full");
    assert_eq!(j["runs"], 2);
    assert_eq!(j["branch"], "main");
    assert!(j["latest"].as_i64().is_some(), "{j}");
    assert_eq!(j["push_access"], "yes");
    let ws = dir.join("wsP");
    assert!(leftovers(&ws).is_empty(), "{:?}", leftovers(&ws));
    // Nothing was configured: no environment, no state.
    assert!(!ws.join("pathwarden.toml").exists());

    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "probe",
            "--git",
            &slash(&enc),
            "--workspace",
            &ws.to_string_lossy(),
        ],
        &[],
    ));
    for want in [
        "This is a Pathwarden history.",
        "Encrypted with a passphrase.",
        "Full runs and settings.",
        "2 runs. The latest was recorded on",
        "Your account can push to this repository.",
    ] {
        assert!(text.contains(want), "{want}: {text}");
    }
    assert!(!text.contains('\u{2713}'), "no checkmarks: {text}");

    // Plain.
    let j = probe_json(&dir, &["--git", &slash(&plain)]);
    assert_eq!(j["encrypted"], false, "{j}");
    assert_eq!(j["keep"], "full");

    // The refusals, each a sentence.
    let probe_err = |args: &[&str]| {
        let mut a = vec!["history", "storage", "probe", "--workspace"];
        let w = ws.to_string_lossy().into_owned();
        a.push(&w);
        a.extend(args);
        err(&pw(&dir, &a, &[]))
    };
    let e = probe_err(&["--git", &slash(&empty)]);
    assert!(
        e.contains("This repository is empty. You can start a new shared history in it."),
        "{e}"
    );
    let e = probe_err(&["--git", &slash(&other)]);
    assert!(
        e.contains("This repository isn't a Pathwarden history. It holds other files."),
        "{e}"
    );
    let e = probe_err(&["--git", &slash(&enc), "--branch", "lab"]);
    assert!(
        e.contains("The repository has no branch named lab. Its only branch is main."),
        "{e}"
    );
    let e = probe_err(&["--git", &slash(&dir.join("nothing-here.git"))]);
    assert!(
        e.contains("Pathwarden couldn't reach the repository."),
        "{e}"
    );
    let e = probe_err(&[
        "--git",
        "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@git.example.com/team/history.git",
    ]);
    assert!(e.contains("The URL holds a password or token."), "{e}");
    // A default branch Pathwarden can't use: a sentence, not the raw check.
    let odd = bare(&dir, "odd");
    git(
        &seed,
        &[
            "push",
            "-q",
            &odd.to_string_lossy(),
            "main:refs/heads/lab+x",
        ],
    );
    git(&odd, &["symbolic-ref", "HEAD", "refs/heads/lab+x"]);
    let e = probe_err(&["--git", &slash(&odd)]);
    assert!(
        e.contains(
            "The repository's default branch has a name Pathwarden can't use. Enter a branch."
        ),
        "{e}"
    );
    let j = probe_json(&dir, &["--git", &slash(&empty)]);
    assert_eq!(j["history"], false);
    assert_eq!(j["problem"], "empty");
    assert!(leftovers(&ws).is_empty(), "{:?}", leftovers(&ws));
    remove_all(&dir);
}

#[test]
fn a_new_environment_opens_the_shared_history_and_adopts_it() {
    if !have_git() {
        return;
    }
    let dir = scratch("create");
    let remote = bare(&dir, "shared");
    computer_a(&dir, &remote, true);
    let wsb = dir.join("wsB");
    std::fs::create_dir_all(&wsb).unwrap();
    let w = wsb.to_string_lossy().into_owned();
    let url = slash(&remote);
    // A local environment already has the history's name: "Lab 2".
    ok(&pw(&dir, &["env", "create", "Lab", "--workspace", &w], &[]));

    // Encrypted, and no passphrase without a terminal: refused, nothing made.
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[],
    ));
    assert!(
        e.contains("This history is encrypted. Give its passphrase in PATHWARDEN_HISTORY_PASSPHRASE, or run this at a terminal to type it."),
        "{e}"
    );
    // The wrong one.
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[(ENV, "not the passphrase at all")],
    ));
    assert!(
        e.contains("That passphrase doesn't open this history."),
        "{e}"
    );
    assert!(leftovers(&wsb).is_empty(), "{:?}", leftovers(&wsb));
    let listed = ok(&pw(&dir, &["env", "list", "--workspace", &w], &[]));
    assert!(!listed.contains("Lab 2"), "{listed}");

    // Connecting fails once the environment is made (its folder can't be):
    // the environment goes again.
    std::fs::create_dir_all(wsb.join("environments")).unwrap();
    std::fs::write(wsb.join("environments/lab-2"), "in the way").unwrap();
    let out = pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[(ENV, PASS)],
    );
    assert_eq!(out.status.code(), Some(2));
    let listed = ok(&pw(&dir, &["env", "list", "--workspace", &w], &[]));
    assert!(!listed.contains("Lab 2"), "{listed}");
    assert!(leftovers(&wsb).is_empty(), "{:?}", leftovers(&wsb));
    std::fs::remove_file(wsb.join("environments/lab-2")).unwrap();

    // The right one: connected, pulled and its full runs loaded.
    let text = ok(&pw(
        &dir,
        &[
            "env",
            "create",
            "--from-git",
            &url,
            "--workspace",
            &w,
            "--use",
        ],
        &[(ENV, PASS)],
    ));
    assert!(text.contains("Connected environment Lab 2"), "{text}");
    assert!(
        text.contains("Connected to the run history. 2 full runs were loaded from the repository. It is synced again every 5 minutes."),
        "{text}"
    );
    assert!(leftovers(&wsb).is_empty(), "{:?}", leftovers(&wsb));
    let state = state_of(&wsb.join("environments/lab-2/pathwarden.toml"));
    // What it keeps and its encryption come from the shared history.
    assert_eq!(state.keep(), pathwarden_core::config::Keep::Full);
    assert!(state.encrypted);
    assert!(state.pushes());
    let shown: serde_json::Value = serde_json::from_slice(
        &pw(
            &dir,
            &[
                "history",
                "storage",
                "show",
                "--env",
                "Lab 2",
                "--workspace",
                &w,
                "--json",
            ],
            &[(ENV, PASS)],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(shown["keep"], "full", "{shown}");
    assert_eq!(shown["runs"], 2, "{shown}");
    assert_eq!(shown["encryption"]["state"], "on");
    assert_eq!(shown["open_in_full"]["on_this_computer"], 2, "{shown}");
    // The passphrase was given in the environment: not stored here.
    let checked = pw(
        &dir,
        &[
            "history",
            "storage",
            "passphrase",
            "check",
            "--env",
            "Lab 2",
            "--workspace",
            &w,
        ],
        &[],
    );
    assert_eq!(checked.status.code(), Some(2));

    // The same history again: the environment that uses it.
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[(ENV, PASS)],
    ));
    assert!(
        e.contains("The environment Lab 2 already uses this history."),
        "{e}"
    );
    remove_all(&dir);
}

#[test]
fn an_account_that_cannot_push_connects_read_only() {
    if !have_git() {
        return;
    }
    let dir = scratch("ro");
    let remote = bare(&dir, "shared");
    computer_a(&dir, &remote, false);
    // This account's git refuses every push to origin (as a server that
    // gives it read access only).
    std::fs::write(
        dir.join("gitconfig"),
        "[remote \"origin\"]\n\treceivepack = \"sh -c 'echo remote: Permission to the repository denied >&2; exit 1' --\"\n",
    )
    .unwrap();
    let wsb = dir.join("wsB");
    std::fs::create_dir_all(&wsb).unwrap();
    let w = wsb.to_string_lossy().into_owned();
    let url = slash(&remote);
    let j = probe_json(&dir, &["--git", &url]);
    assert_eq!(j["push_access"], "no", "{j}");
    let e = err(&pw(
        &dir,
        &[
            "env",
            "create",
            "--from-git",
            &url,
            "--workspace",
            &w,
            "--push",
        ],
        &[],
    ));
    assert!(
        e.contains("Your account can read this repository but can't push to it."),
        "{e}"
    );
    let text = ok(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[],
    ));
    assert!(text.contains("can't push to it."), "{text}");
    assert!(
        text.contains("This computer will only read the shared history. Analyses you start here stay on this computer."),
        "{text}"
    );
    let state = state_of(&wsb.join("environments/lab/pathwarden.toml"));
    assert!(!state.pushes());
    // Plain full runs: adopted as they are, no encryption recorded.
    assert_eq!(state.keep(), pathwarden_core::config::Keep::Full);
    assert!(!state.encrypted);
    remove_all(&dir);
}

#[test]
fn an_environment_with_runs_of_its_own_is_never_connected() {
    if !have_git() {
        return;
    }
    let dir = scratch("own");
    let remote = bare(&dir, "shared");
    computer_a(&dir, &remote, true);
    let wsb = dir.join("wsB");
    std::fs::create_dir_all(&wsb).unwrap();
    let w = wsb.to_string_lossy().into_owned();
    ok(&pw(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &w],
        &[],
    ));
    let before = std::fs::read_to_string(wsb.join("pathwarden.toml")).ok();
    let e = err(&pw(
        &dir,
        &[
            "history",
            "storage",
            "connect",
            "--git",
            &slash(&remote),
            "--workspace",
            &w,
        ],
        &[(ENV, PASS)],
    ));
    assert!(e.contains("has 1 run of its own."), "{e}");
    assert!(e.contains("pathwarden env create --from-git"), "{e}");
    assert_eq!(
        std::fs::read_to_string(wsb.join("pathwarden.toml")).ok(),
        before
    );
    assert!(leftovers(&wsb).is_empty());

    // Start a new shared history where one is: refused, nothing encrypted
    // or saved.
    let e = err(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            &slash(&remote),
            "--keep",
            "full",
            "--encrypt",
            "--from-env",
            "--yes",
            "--workspace",
            &w,
        ],
        &[(ENV, "another passphrase for it")],
    ));
    assert!(
        e.contains("This repository already holds a Pathwarden history. It is encrypted and has 2 runs. Connect to it instead, or choose an empty repository."),
        "{e}"
    );
    assert!(
        e.contains("pathwarden history storage connect --git"),
        "{e}"
    );
    assert_eq!(
        std::fs::read_to_string(wsb.join("pathwarden.toml")).ok(),
        before
    );
    remove_all(&dir);
}

/// The passphrase kept on this computer for an environment since removed
/// opens the same history for a new one: nothing typed, and kept for the
/// new environment too. Another history's passphrase doesn't open it:
/// without a terminal, nothing is connected.
#[test]
fn a_passphrase_kept_here_connects_a_new_environment() {
    if !have_git() {
        return;
    }
    let dir = scratch("remembered");
    let remote = bare(&dir, "shared");
    computer_a(&dir, &remote, true);
    let ws = dir.join("wsA").to_string_lossy().into_owned();
    let url = slash(&remote);
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "passphrase",
            "set",
            "--from-env",
            "--env",
            "Lab",
            "--workspace",
            &ws,
        ],
        &[(ENV, PASS)],
    ));
    ok(&pw(
        &dir,
        &["env", "remove", "Lab", "--yes", "--workspace", &ws],
        &[],
    ));
    // Kept with the key file it opens: one recorded for another key file
    // is never tried.
    let keys: Vec<PathBuf> = std::fs::read_dir(dir.join("keystore"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "key"))
        .collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    let recorded = std::fs::read_to_string(&keys[0]).unwrap();
    std::fs::write(&keys[0], "0".repeat(64)).unwrap();
    let wsb = dir.join("wsB");
    std::fs::create_dir_all(&wsb).unwrap();
    let w = wsb.to_string_lossy().into_owned();
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[],
    ));
    assert!(e.contains("This history is encrypted."), "{e}");
    std::fs::write(&keys[0], recorded).unwrap();
    let text = ok(&pw(
        &dir,
        &[
            "env",
            "create",
            "--from-git",
            &url,
            "--name",
            "Lab again",
            "--workspace",
            &ws,
        ],
        &[],
    ));
    assert!(
        text.contains(
            "This history opens with the passphrase kept on this computer for another history."
        ),
        "{text}"
    );
    assert!(text.contains("Connected environment Lab again"), "{text}");
    // Kept for the new environment: it opens without the variable.
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "passphrase",
            "check",
            "--env",
            "Lab again",
            "--workspace",
            &ws,
        ],
        &[],
    ));

    // Only another history's passphrase here: nothing connected.
    remove_all(&dir.join("keystore"));
    std::fs::create_dir_all(dir.join("keystore")).unwrap();
    std::fs::write(dir.join("keystore/other.txt"), "another history's phrase").unwrap();
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[],
    ));
    assert!(
        e.contains(
            "This history is encrypted. Give its passphrase in PATHWARDEN_HISTORY_PASSPHRASE"
        ),
        "{e}"
    );
    assert!(leftovers(&wsb).is_empty(), "{:?}", leftovers(&wsb));

    // Kept before 0.2 (no key file recorded with it): never tried on
    // another history, even when it is the right one, and the
    // terminal says why it is asked.
    std::fs::write(dir.join("keystore/other.txt"), PASS).unwrap();
    let e = err(&pw(
        &dir,
        &["env", "create", "--from-git", &url, "--workspace", &w],
        &[],
    ));
    assert!(
        e.contains(
            "Passphrases saved on this computer before Pathwarden 0.2 are no longer tried on \
             other histories. Enter this history's passphrase once."
        ),
        "{e}"
    );
    assert!(e.contains("This history is encrypted."), "{e}");
    assert!(leftovers(&wsb).is_empty(), "{:?}", leftovers(&wsb));
    remove_all(&dir);
}
