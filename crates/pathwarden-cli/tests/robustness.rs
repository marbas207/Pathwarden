//! Safety of unattended runs: the git state backend never takes over someone
//! else's repository and recovers from half-done git operations; plugins
//! cannot deadlock or hang the run, must be explicitly located, and only see
//! the environment they are meant to.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

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
    let dir = std::env::temp_dir().join(format!("pathwarden-robust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> Output {
    let out = git_command()
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .output()
        .unwrap();
    out
}

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn pathwarden(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .envs(env.iter().copied())
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

fn git_config(dir: &Path, remote: &Path, path: &str) {
    let config = format!(
        "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{path}\"\n",
        remote.to_string_lossy().replace('\\', "/")
    );
    std::fs::write(dir.join("git.toml"), config).unwrap();
}

#[test]
fn git_backend_refuses_to_take_over_an_existing_repository() {
    if !have("git", &["--version"]) {
        return;
    }
    let dir = scratch("takeover");
    let state_remote = dir.join("state.git");
    git_ok(
        &dir,
        &["init", "-q", "--bare", &state_remote.to_string_lossy()],
    );
    // Someone's project, with its own origin and uncommitted work.
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    git_ok(&project, &["init", "-q"]);
    std::fs::write(project.join("code.txt"), "v1").unwrap();
    git_ok(&project, &["add", "code.txt"]);
    git_ok(&project, &["commit", "-q", "-m", "project"]);
    git_ok(
        &project,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/project.git",
        ],
    );
    std::fs::write(project.join("code.txt"), "uncommitted work").unwrap();
    git_config(&dir, &state_remote, "project");

    let out = pathwarden(&dir, &["run", "-i", &forest(), "-c", "git.toml"], &[]);
    assert!(!out.status.success(), "must refuse: {}", text(&out));
    assert!(
        text(&out).contains("not the configured state remote"),
        "{}",
        text(&out)
    );
    assert_eq!(
        git_ok(&project, &["remote", "get-url", "origin"]).trim(),
        "https://example.invalid/project.git",
        "origin untouched"
    );
    assert_eq!(
        std::fs::read_to_string(project.join("code.txt")).unwrap(),
        "uncommitted work"
    );
    assert!(
        git_ok(&state_remote, &["branch", "--list"])
            .trim()
            .is_empty(),
        "nothing pushed"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fresh_clone_is_marked_and_a_stuck_rebase_is_recovered() {
    if !have("git", &["--version"]) {
        return;
    }
    let dir = scratch("marker");
    let remote = dir.join("state.git");
    git_ok(&dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    git_config(&dir, &remote, "work");
    let run = |d: &Path| pathwarden(d, &["run", "-i", &forest(), "-c", "git.toml"], &[]);

    let first = run(&dir);
    assert!(first.status.success(), "{}", text(&first));
    let work = dir.join("work");
    assert!(work.join(".pathwarden-state").exists());
    assert!(
        git_ok(&remote, &["ls-tree", "--name-only", "main"]).contains(".pathwarden-state"),
        "marker is committed"
    );

    // Leave the working copy in the middle of a conflicting rebase.
    let other = dir.join("other");
    git_ok(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &other.to_string_lossy(),
        ],
    );
    std::fs::write(other.join("last-run.json"), "{\"other\": true}\n").unwrap();
    git_ok(&other, &["commit", "-q", "-am", "other"]);
    git_ok(&other, &["push", "-q", "origin", "main"]);
    std::fs::write(work.join("last-run.json"), "{\"mine\": true}\n").unwrap();
    git_ok(&work, &["commit", "-q", "-am", "mine"]);
    let rebase = git(&work, &["pull", "-q", "--rebase", "origin", "main"]);
    assert!(!rebase.status.success(), "the rebase conflicts");
    assert!(work.join(".git/rebase-merge").exists() || work.join(".git/rebase-apply").exists());

    let again = run(&dir);
    assert!(again.status.success(), "recovers: {}", text(&again));
    assert!(!work.join(".git/rebase-merge").exists() && !work.join(".git/rebase-apply").exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// L7: a symlink committed to the state repository must not redirect the
/// run's writes.
#[test]
fn committed_symlinks_in_the_state_repo_are_refused() {
    if !have("git", &["--version"]) {
        return;
    }
    let dir = scratch("symlink");
    let remote = dir.join("state.git");
    git_ok(&dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    let outside = dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    // Push a commit whose `history` is a symlink to `outside`.
    let seed = dir.join("seed");
    git_ok(
        &dir,
        &[
            "clone",
            "-q",
            &remote.to_string_lossy(),
            &seed.to_string_lossy(),
        ],
    );
    std::fs::write(seed.join("target"), outside.to_string_lossy().as_bytes()).unwrap();
    let blob = git_ok(&seed, &["hash-object", "-w", "target"]);
    std::fs::remove_file(seed.join("target")).unwrap();
    let info = format!("120000,{},history", blob.trim());
    git_ok(&seed, &["update-index", "--add", "--cacheinfo", &info]);
    git_ok(&seed, &["commit", "-q", "-m", "evil"]);
    git_ok(&seed, &["push", "-q", "origin", "HEAD:refs/heads/main"]);

    git_config(&dir, &remote, "work");
    let out = pathwarden(&dir, &["run", "-i", &forest(), "-c", "git.toml"], &[]);
    let t = text(&out);
    assert!(!out.status.success(), "must refuse: {t}");
    assert!(t.contains("symbolic links (history)"), "{t}");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    // core.symlinks=false: the link was checked out as a plain file.
    let history = dir.join("work/history");
    assert!(!std::fs::symlink_metadata(&history)
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::remove_dir_all(&dir).ok();
}

/// A config inside the git state working copy is controlled by whoever can
/// push to the state repository: the run says so.
#[test]
fn config_inside_the_state_working_copy_is_warned_about() {
    if !have("git", &["--version"]) {
        return;
    }
    let dir = scratch("cfg-in-state");
    let remote = dir.join("state.git");
    git_ok(&dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    git_config(&dir, &remote, "work");
    let run = |cfg: &str| pathwarden(&dir, &["run", "-i", &forest(), "-c", cfg], &[]);
    let first = run("git.toml");
    assert!(first.status.success(), "{}", text(&first));
    assert!(!text(&first).contains("inside the run history's git working"));
    std::fs::copy(dir.join("git.toml"), dir.join("work").join("p.toml")).unwrap();
    let inside = run("work/p.toml");
    assert!(inside.status.success(), "{}", text(&inside));
    assert!(
        text(&inside).contains("inside the run history's git working"),
        "{}",
        text(&inside)
    );
    std::fs::remove_dir_all(&dir).ok();
}

fn plugin_config(dir: &Path, blocks: &str) {
    std::fs::write(dir.join("p.toml"), blocks).unwrap();
}

fn powershell() -> bool {
    have("powershell", &["-NoProfile", "-Command", "exit 0"])
}

#[test]
fn plugin_that_writes_before_reading_does_not_deadlock() {
    if !powershell() {
        return;
    }
    let dir = scratch("deadlock");
    plugin_config(
        &dir,
        "[[output]]\nplugin = \"chatty\"\ntimeout_seconds = 60\n\
         command = [\"powershell\", \"-NoProfile\", \"-Command\", \
         \"[Console]::Out.WriteLine('x' * 2000000); $null = [Console]::In.ReadToEnd(); 'done'\"]\n",
    );
    let started = Instant::now();
    let out = pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "p.toml", "--state", "st"],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(started.elapsed() < Duration::from_secs(55));
    assert!(out.stdout.len() > 1_000_000);
    assert!(text(&out).contains("[chatty] done"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hung_plugin_is_stopped_at_its_timeout() {
    if !powershell() {
        return;
    }
    let dir = scratch("timeout");
    plugin_config(
        &dir,
        "[[output]]\nplugin = \"sleepy\"\ntimeout_seconds = 2\n\
         command = [\"powershell\", \"-NoProfile\", \"-Command\", \"Start-Sleep -Seconds 60\"]\n",
    );
    let started = Instant::now();
    let out = pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "p.toml", "--state", "st"],
        &[],
    );
    assert!(!out.status.success());
    assert!(text(&out).contains("timed out after 2 s"), "{}", text(&out));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "killed, not waited for"
    );
    assert!(
        dir.join("st/findings.json").exists(),
        "state saved regardless"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn relative_plugin_commands_are_rejected() {
    let dir = scratch("relative");
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    plugin_config(
        &dir,
        "[[output]]\nplugin = \"planted\"\ncommand = [\"plugins/evil.exe\"]\n\n\
         [[output]]\nplugin = \"teams\"\n",
    );
    let out = pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "p.toml", "--state", "st"],
        &[],
    );
    let t = text(&out);
    assert!(!out.status.success());
    assert!(t.contains("must be an absolute path"), "{t}");
    // pathwarden-output-teams is not beside the test binary, and ./plugins is
    // never searched.
    assert!(t.contains("pathwarden-output-teams not found"), "{t}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn plugins_only_see_the_environment_they_name() {
    if !powershell() {
        return;
    }
    let dir = scratch("env");
    plugin_config(
        &dir,
        "[[output]]\nplugin = \"envcheck\"\ntoken_env = \"PW_TEST_ALLOWED\"\n\
         key_env = \"PATHWARDEN_EVIDENCE_KEY\"\npassword_env = \"PATHWARDEN_COLLECT_PASSWORD\"\n\
         command = [\"powershell\", \"-NoProfile\", \"-Command\", \
         \"'secret=[' + $env:PW_TEST_SECRET + '] allowed=[' + $env:PW_TEST_ALLOWED + '] key=[' + $env:PATHWARDEN_EVIDENCE_KEY + '] pw=[' + $env:PATHWARDEN_COLLECT_PASSWORD + ']'\"]\n",
    );
    let out = pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "p.toml", "--state", "st"],
        &[
            ("PW_TEST_SECRET", "leak"),
            ("PW_TEST_ALLOWED", "ok"),
            // Pathwarden's own secrets, even named.
            ("PATHWARDEN_EVIDENCE_KEY", "leak-key"),
            ("PATHWARDEN_COLLECT_PASSWORD", "leak-pw"),
        ],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("secret=[] allowed=[ok] key=[] pw=[]"), "{t}");
    std::fs::remove_dir_all(&dir).ok();
}

/// L1/L13: an AD name holding terminal escapes, `\r` and a bidi override
/// reaches a real terminal (color forced on) only in escaped, visible form.
#[test]
fn hostile_names_are_escaped_on_the_terminal() {
    let dir = scratch("names");
    let data = dir.join("in");
    std::fs::create_dir_all(&data).unwrap();
    for entry in std::fs::read_dir(forest()).unwrap() {
        let path = entry.unwrap().path();
        // JSON escapes, so the collector file itself stays valid.
        let text = std::fs::read_to_string(&path).unwrap().replace(
            "\"name\": \"CAROL@CHILD.CONTOSO.LOCAL\"",
            "\"name\": \"JDOE\\u001b]0;pwned\\u0007\\u001b[2K\\rX\\u009b31m\\u202eLACOL.OSOTNOC@\"",
        );
        std::fs::write(data.join(path.file_name().unwrap()), text).unwrap();
    }
    let input = data.to_string_lossy().into_owned();
    for cmd in ["findings", "exposure", "plan", "tier-zero", "choke-points"] {
        let out = Command::new(bin())
            .current_dir(&dir)
            .env("CLICOLOR_FORCE", "1")
            .env_remove("NO_COLOR")
            .args([cmd, "-i", &input])
            .output()
            .unwrap();
        let shown = text(&out);
        assert!(out.status.success(), "{cmd}: {shown}");
        for bad in ["\u{1b}]", "\u{1b}[2K", "\r", "\u{9b}", "\u{202e}", "\u{7}"] {
            assert!(!shown.contains(bad), "{cmd} printed {bad:?}");
        }
        if cmd == "findings" {
            assert!(shown.contains("JDOE\\u{1b}]0;PWNED"), "{shown}");
        }
    }
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
