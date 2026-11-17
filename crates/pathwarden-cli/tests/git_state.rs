//! Run history in a git repository, end to end: `pathwarden run`, a
//! scheduled run and the app's saves commit and push; two machines racing
//! on one remote both get their run recorded; and an unreachable or
//! refusing remote, a foreign repository, a stale lock and a dirty working
//! copy are each handled. Every remote is a local bare repository.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn forest() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/forest")
        .to_string_lossy()
        .into_owned()
}

fn have_git() -> bool {
    let ok = git_command()
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        // CI must have it: a skipped test there would pass unseen.
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        eprintln!("git is not installed: skipping this test");
    }
    ok
}

/// A hook script git runs (executable where that matters).
fn write_hook(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-git-{name}-{}", std::process::id()));
    remove_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A path as git and `sh` on Windows take it.
fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
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

fn bare(dir: &Path) -> PathBuf {
    let remote = dir.join("state.git");
    git(dir, &["init", "-q", "--bare", &slash(&remote)]);
    remote
}

/// `git.toml` in `dir`: the state in `remote`, checked out in `dir/work`.
fn config(dir: &Path, remote: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let text = format!(
        "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"work\"\n",
        slash(remote)
    );
    std::fs::write(dir.join("git.toml"), text).unwrap();
}

fn pathwarden(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        // A held lock is a failure at once, not after a wait.
        .env("PATHWARDEN_LOCK_WAIT", "0")
        .env_remove("PATHWARDEN_SCHEDULED")
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

fn ok(o: Output) -> String {
    assert!(o.status.success(), "{}", text(&o));
    text(&o)
}

fn run(dir: &Path) -> Output {
    pathwarden(dir, &["run", "-i", &forest(), "-c", "git.toml"], &[])
}

/// Commit subjects on the remote's `main`, newest first.
fn log(remote: &Path) -> Vec<String> {
    git(remote, &["log", "--format=%s", "main"])
        .lines()
        .map(str::to_string)
        .collect()
}

/// Files on the remote's `main` under `folder`.
fn files(remote: &Path, folder: &str) -> Vec<String> {
    git(
        remote,
        &["ls-tree", "--name-only", "main", &format!("{folder}/")],
    )
    .lines()
    .map(str::to_string)
    .collect()
}

fn remote_json(remote: &Path, path: &str) -> serde_json::Value {
    serde_json::from_str(&git(remote, &["show", &format!("main:{path}")])).unwrap()
}

/// Every saved run's summary under `dir`, a line each: what a failure
/// shows.
fn summaries(dir: &Path) -> String {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("summary"))
            {
                let v: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_default())
                        .unwrap_or_default();
                out.push(format!(
                    "{}: created_at {} created_ms {} environment {} history {}",
                    p.display(),
                    v["created_at"],
                    v["created_ms"],
                    v["environment"],
                    v["history"]
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.join("\n")
}

/// Runs by hand, by a schedule and by the app (`run --save`, the app's own
/// recording) all commit and push with a message naming the run, and the
/// History storage commands (set, pull, import, keep-local, forget) work
/// against a git history.
#[test]
fn every_way_of_recording_commits_and_pushes() {
    if !have_git() {
        return;
    }
    let dir = scratch("record");
    let remote = bare(&dir);
    config(&dir, &remote);

    let first = ok(run(&dir));
    assert!(first.contains("pushed"), "{first}");
    let scheduled = ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "git.toml"],
        &[("PATHWARDEN_SCHEDULED", "1")],
    ));
    assert!(scheduled.contains("pushed"), "{scheduled}");
    let subjects = log(&remote);
    assert_eq!(subjects.len(), 2, "{subjects:?}");
    for s in &subjects {
        assert!(s.starts_with("pathwarden run 20"), "{s}");
        assert!(s.contains(" new, ") && s.ends_with(" open"), "{s}");
    }
    assert!(subjects[1].contains(": 15 new, 0 regressed, 0 resolved, 15 open"));
    let last = remote_json(&remote, "last-run.json");
    let id = last["run_id"].as_str().unwrap();
    let point = remote_json(&remote, &format!("history/{id}.json"));
    assert_eq!(point["recorded_by"], "schedule");
    // No identity configured: commits are Pathwarden's.
    let author = git(&remote, &["log", "-1", "--format=%an <%ae>", "main"]);
    if git(&dir.join("work"), &["config", "--get-all", "user.email"]).is_empty() {
        assert_eq!(author.trim(), "Pathwarden <pathwarden@localhost>");
    }

    // The app's history, set to the same repository from the terminal.
    let w = slash(&dir.join("ws"));
    let r = slash(&remote);
    // The first save makes the workspace (its history a folder).
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &w],
        &[],
    ));
    let set = ok(pathwarden(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            &r,
            "--folder",
            "appstate",
            "--workspace",
            &w,
        ],
        &[],
    ));
    assert!(set.contains("branch `main`"), "{set}");
    let saved = ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &w],
        &[],
    ));
    assert!(!saved.contains("not in the run history"), "{saved}");
    assert_eq!(log(&remote).len(), 3);
    let last = remote_json(&remote, "last-run.json");
    let point = remote_json(
        &remote,
        &format!("history/{}.json", last["run_id"].as_str().unwrap()),
    );
    assert_eq!(point["recorded_by"], "cli");
    // The terminal's working copy gets it.
    ok(pathwarden(
        &dir,
        &["history", "storage", "pull", "--workspace", &w],
        &[],
    ));

    // An analysis saved while the history's lock was held stays local; it
    // is imported, and pushed, afterwards.
    let show: serde_json::Value = serde_json::from_str(&ok(pathwarden(
        &dir,
        &["history", "storage", "show", "--workspace", &w, "--json"],
        &[],
    )))
    .unwrap();
    let checkout = PathBuf::from(show["dir"].as_str().unwrap());
    let lock = checkout.join(".pathwarden.lock");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let locked = ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &w],
        &[],
    ));
    std::fs::remove_file(&lock).unwrap();
    assert_eq!(log(&remote).len(), 3, "nothing pushed while locked");
    let imported = ok(pathwarden(
        &dir,
        &["history", "import", "--workspace", &w],
        &[],
    ));
    assert!(
        imported.contains("Imported 1 run"),
        "{imported}\n--- the run saved while locked said:\n{locked}\n--- saved runs:\n{}\n--- the remote's commits:\n{}",
        summaries(&dir.join("ws")),
        git(&remote, &["log", "--format=%s %ad", "--date=unix", "main"])
    );
    assert_eq!(
        log(&remote)[0],
        "pathwarden: import 1 run(s) analyzed in the UI"
    );
    let kept = ok(pathwarden(
        &dir,
        &["history", "keep-local", "--workspace", &w],
        &[],
    ));
    assert!(kept.starts_with("Nothing"), "{kept}");

    // Forgetting a run from the terminal is a commit too.
    let forget = files(&remote, "history")[0]
        .trim_start_matches("history/")
        .trim_end_matches(".json")
        .to_string();
    ok(pathwarden(
        &dir,
        &["history", "--forget", &forget, "-c", "git.toml"],
        &[],
    ));
    assert_eq!(
        log(&remote)[0],
        format!("pathwarden: remove run {forget} from the history")
    );
    assert_eq!(files(&remote, "history").len(), 3);
    remove_all(&dir);
}

/// Machine B's push is rejected because machine A pushed a newer run
/// while B was pushing (A's whole run happens in B's pre-push hook): B's
/// run is still recorded, as an earlier point, and B says so.
#[test]
fn a_run_that_loses_the_race_is_still_recorded() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let (a, b) = (dir.join("a"), dir.join("b"));
    config(&a, &remote);
    config(&b, &remote);
    ok(run(&a));
    ok(run(&b));

    let marker = dir.join("raced");
    let hook = format!(
        "#!/bin/sh\n[ -f '{m}' ] && exit 0\n: > '{m}'\n\
         unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX\n\
         cd '{a}' && '{bin}' run -i '{forest}' -c git.toml > '{a}/raced.log' 2>&1\nexit 0\n",
        m = slash(&marker),
        a = slash(&a),
        bin = slash(Path::new(bin())),
        forest = slash(Path::new(&forest())),
    );
    write_hook(&b.join("work/.git/hooks/pre-push"), &hook);
    // B's output plugin fails if it is run: B's event is older than the
    // history's state, so it must not be.
    let failing = format!(
        "\n[[output]]\nplugin = \"broken\"\ncommand = [\"{}\", \"guide\", \"PW-999\"]\n",
        slash(Path::new(bin()))
    );
    let mut cfg = std::fs::read_to_string(b.join("git.toml")).unwrap();
    cfg.push_str(&failing);
    std::fs::write(b.join("git.toml"), cfg).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = ok(pathwarden(
        &b,
        &[
            "run",
            "-i",
            &forest(),
            "-c",
            "git.toml",
            "--event",
            "ev.json",
        ],
        &[],
    ));
    let event: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(b.join("ev.json")).unwrap()).unwrap();
    assert_eq!(event["superseded"], true);
    assert!(marker.exists(), "the hook ran");
    let a_log = std::fs::read_to_string(a.join("raced.log")).unwrap();
    assert!(a_log.contains("pushed"), "{a_log}");
    assert!(out.contains("a newer run ("), "{out}");
    assert!(out.contains("pushed"), "{out}");
    assert!(out.contains("output plugins weren't run"), "{out}");

    // Four runs, four points, four commits; the newest (A's) is the last.
    assert_eq!(log(&remote).len(), 4, "{:?}", log(&remote));
    let points = files(&remote, "history");
    assert_eq!(points.len(), 4, "{points:?}");
    let last = remote_json(&remote, "last-run.json");
    assert_eq!(
        format!("history/{}.json", last["run_id"].as_str().unwrap()),
        points[3]
    );
    remove_all(&dir);
}

#[test]
fn an_unreachable_remote_fails_the_run_and_keeps_the_working_copy() {
    if !have_git() {
        return;
    }
    let dir = scratch("offline");
    let remote = bare(&dir);
    config(&dir, &remote);
    ok(run(&dir));
    let away = dir.join("moved.git");
    std::fs::rename(&remote, &away).unwrap();
    let out = run(&dir);
    assert!(!out.status.success());
    let t = text(&out);
    assert!(t.contains("Syncing the run history"), "{t}");
    assert!(t.contains("git fetch failed"), "{t}");
    assert!(dir.join("work/findings.json").exists());
    assert!(!dir.join("work/.pathwarden.lock").exists(), "lock released");
    std::fs::rename(&away, &remote).unwrap();
    ok(run(&dir));
    assert_eq!(log(&remote).len(), 2);
    remove_all(&dir);
}

#[test]
fn a_refused_push_keeps_the_run_for_the_next_one() {
    if !have_git() {
        return;
    }
    let dir = scratch("refused");
    let remote = bare(&dir);
    config(&dir, &remote);
    ok(run(&dir));
    let hook = remote.join("hooks/pre-receive");
    write_hook(&hook, "#!/bin/sh\necho 'branch is protected' >&2\nexit 1\n");
    let out = pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "git.toml", "--verbose"],
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let t = text(&out);
    // Recorded here: the summary is printed, then the warning; git's own
    // words only with --verbose.
    assert!(t.contains("committed here, not pushed"), "{t}");
    assert!(t.contains("still open"), "{t}");
    assert!(
        t.contains("Warning: This run is recorded here, but the change couldn't be pushed"),
        "{t}"
    );
    assert!(
        t.contains("refused it: can this account write there"),
        "{t}"
    );
    assert!(
        t.contains("git: ") && t.contains("branch is protected"),
        "{t}"
    );
    assert_eq!(log(&remote).len(), 1);

    // A failing output plugin doesn't hide it: the error names both.
    let mut cfg = std::fs::read_to_string(dir.join("git.toml")).unwrap();
    cfg.push_str(&format!(
        "\n[[output]]\nplugin = \"broken\"\ncommand = [\"{}\", \"guide\", \"PW-999\"]\n",
        slash(Path::new(bin()))
    ));
    std::fs::write(dir.join("plugin.toml"), cfg).unwrap();
    let out = pathwarden(&dir, &["run", "-i", &forest(), "-c", "plugin.toml"], &[]);
    assert_eq!(out.status.code(), Some(2));
    let t = text(&out);
    assert!(t.contains("1 output plugin failed: broken"), "{t}");
    assert!(t.contains("couldn't be pushed"), "{t}");

    std::fs::remove_file(&hook).unwrap();
    ok(run(&dir));
    assert_eq!(log(&remote).len(), 4, "all three runs pushed");
    remove_all(&dir);
}

/// A remote that holds something else (a mistyped URL, someone's project)
/// is refused before anything is checked out or pushed; one a host made
/// with a README is fine.
#[test]
fn a_foreign_repository_is_refused() {
    if !have_git() {
        return;
    }
    let dir = scratch("foreign");
    let remote = bare(&dir);
    let seed = dir.join("seed");
    git(&dir, &["clone", "-q", &slash(&remote), &slash(&seed)]);
    std::fs::write(seed.join("main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(seed.join("README.md"), "# project\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-q", "-m", "project"]);
    git(&seed, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
    config(&dir, &remote);

    for _ in 0..2 {
        let out = run(&dir);
        assert!(!out.status.success());
        let t = text(&out);
        assert!(
            t.contains("is not Pathwarden state (it holds main.rs)"),
            "{t}"
        );
    }
    assert_eq!(log(&remote), ["project"]);
    assert!(!dir.join("work/main.rs").exists(), "nothing checked out");

    // A new repository with only a README (as a host creates it) is used.
    git(&seed, &["rm", "-q", "main.rs"]);
    git(&seed, &["commit", "-q", "-m", "readme only"]);
    git(&seed, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
    ok(run(&dir));
    assert_eq!(log(&remote).len(), 3);
    remove_all(&dir);
}

#[test]
fn a_stale_lock_is_replaced_and_a_live_one_is_not() {
    if !have_git() {
        return;
    }
    let dir = scratch("lock");
    let remote = bare(&dir);
    config(&dir, &remote);
    let stale = |lock: &Path| {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 3600);
        std::fs::File::options()
            .write(true)
            .open(lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
    };
    // The lock is inside the state folder; a folder holding only it is
    // cloned into.
    std::fs::create_dir_all(dir.join("work")).unwrap();
    let lock = dir.join("work/.pathwarden.lock");
    std::fs::write(&lock, "host other pid 1 token x\n").unwrap();
    let out = run(&dir);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("Another pathwarden run is using"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("host other pid 1"), "{}", text(&out));
    stale(&lock);
    ok(run(&dir));
    assert!(!lock.exists());

    // One an older version keeps beside the folder: respected while
    // fresh, ignored once stale, and never removed.
    let old = dir.join("work.lock");
    std::fs::write(&old, "host older pid 2 token y\n").unwrap();
    let out = run(&dir);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("An older pathwarden run is using"),
        "{}",
        text(&out)
    );
    assert!(!lock.exists(), "this run's own lock released");
    stale(&old);
    ok(run(&dir));
    assert!(old.exists());
    assert_eq!(log(&remote).len(), 2);
    remove_all(&dir);
}

/// Edits and stray files in the working copy never reach the remote: the
/// state is reset to the remote's, and files no commit holds in `history`
/// (a --no-push run's point, say) are removed.
#[test]
fn a_dirty_working_copy_is_reset() {
    if !have_git() {
        return;
    }
    let dir = scratch("dirty");
    let remote = bare(&dir);
    config(&dir, &remote);
    ok(run(&dir));
    let work = dir.join("work");
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "git.toml", "--no-push"],
        &[],
    ));
    let local_only = std::fs::read_dir(work.join("history")).unwrap().count();
    assert_eq!(local_only, 2, "the --no-push run's point is local");
    std::fs::write(work.join("findings.json"), "not json").unwrap();
    std::fs::write(work.join("history/stray.json"), "{}").unwrap();
    std::fs::write(work.join("notes.txt"), "mine").unwrap();

    let out = ok(run(&dir));
    assert!(out.contains("15 still open"), "{out}");
    assert_eq!(
        files(&remote, "history").len(),
        2,
        "{:?}",
        files(&remote, "history")
    );
    assert!(!git(&remote, &["ls-tree", "--name-only", "main"]).contains("notes.txt"));
    assert!(!work.join("history/stray.json").exists());
    remove_all(&dir);
}

/// Run from a git hook or `git rebase -x` (GIT_DIR and GIT_WORK_TREE set
/// for another repository), Pathwarden still works in its own working copy
/// only.
#[test]
fn git_variables_of_another_repository_are_ignored() {
    if !have_git() {
        return;
    }
    let dir = scratch("env");
    let remote = bare(&dir);
    config(&dir, &remote);
    ok(run(&dir));
    let victim = dir.join("victim");
    std::fs::create_dir_all(victim.join("history")).unwrap();
    git(&victim, &["init", "-q"]);
    std::fs::write(victim.join("findings.json"), "mine").unwrap();
    git(&victim, &["add", "findings.json"]);
    git(&victim, &["commit", "-q", "-m", "victim"]);
    std::fs::write(victim.join("history/untracked.json"), "{}").unwrap();
    let (gd, wt) = (slash(&victim.join(".git")), slash(&victim));
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "-c", "git.toml"],
        &[
            ("GIT_DIR", &gd),
            ("GIT_WORK_TREE", &wt),
            ("GIT_INDEX_FILE", ""),
        ],
    ));
    assert_eq!(
        std::fs::read_to_string(victim.join("findings.json")).unwrap(),
        "mine"
    );
    assert!(victim.join("history/untracked.json").exists());
    assert_eq!(git(&victim, &["log", "--format=%s"]).trim(), "victim");
    assert_eq!(log(&remote).len(), 2);
    remove_all(&dir);
}

/// A state that can't be saved writes no event or report: they would tell
/// of a run the state doesn't have.
#[test]
fn a_failed_save_writes_no_event_or_report() {
    let dir = scratch("save-fails");
    std::fs::create_dir_all(dir.join("st/last-run.json")).unwrap();
    let out = pathwarden(
        &dir,
        &[
            "run",
            "-i",
            &forest(),
            "--state",
            "st",
            "--event",
            "ev.json",
            "--report",
            "r.html",
        ],
        &[],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!dir.join("ev.json").exists());
    assert!(!dir.join("r.html").exists());
    remove_all(&dir);
}

/// The app's history in git: a save whose push fails is still recorded
/// (and pushed later); runs a failed push left that another machine's push
/// came before are added back, and `history storage pull` says so; an
/// import is made again on top of another machine's change, or refused
/// when that change made it out of order.
#[test]
fn the_apps_history_in_git_keeps_every_run() {
    if !have_git() {
        return;
    }
    let dir = scratch("app");
    let remote = bare(&dir);
    let other = dir.join("other");
    config(&other, &remote);
    ok(run(&other));
    let w = slash(&dir.join("ws"));
    let save = || {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        pathwarden(
            &dir,
            &["run", "-i", &forest(), "--save", "--workspace", &w],
            &[],
        )
    };
    ok(save());
    ok(pathwarden(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            &slash(&remote),
            "--folder",
            "appstate",
            "--workspace",
            &w,
        ],
        &[],
    ));
    ok(save());
    assert_eq!(log(&remote).len(), 2);

    // A refused push: the save is in the history here; the command says so
    // after its summary and fails, as `pathwarden run` does.
    let pre_receive = remote.join("hooks/pre-receive");
    write_hook(&pre_receive, "#!/bin/sh\nexit 1\n");
    let out = save();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let saved = text(&out);
    assert!(
        saved.contains("Warning: This run is recorded here, but the change couldn't be pushed"),
        "{saved}"
    );
    assert!(saved.contains("refused it"), "{saved}");
    assert!(!saved.contains("not in the run history"), "{saved}");
    // Getting the latest says it is kept, and pushes nothing.
    let pulled = ok(pathwarden(
        &dir,
        &["history", "storage", "pull", "--workspace", &w],
        &[],
    ));
    assert!(pulled.contains("are not pushed yet"), "{pulled}");
    assert_eq!(log(&remote).len(), 2);
    std::fs::remove_file(&pre_receive).unwrap();

    // Another machine pushes first: the pull adds the kept run back.
    ok(run(&other));
    let pulled = ok(pathwarden(
        &dir,
        &["history", "storage", "pull", "--workspace", &w],
        &[],
    ));
    assert!(
        pulled.contains("1 run recorded here but not pushed before another machine pushed"),
        "{pulled}"
    );
    ok(save());
    assert_eq!(files(&remote, "history").len(), 5);

    // Import, while another machine removes a run: imported on top.
    let show: serde_json::Value = serde_json::from_str(&ok(pathwarden(
        &dir,
        &["history", "storage", "show", "--workspace", &w, "--json"],
        &[],
    )))
    .unwrap();
    let checkout = PathBuf::from(show["dir"].as_str().unwrap());
    let lock = checkout.join(".pathwarden.lock");
    let local_only = || {
        std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
        ok(save());
        std::fs::remove_file(&lock).unwrap();
    };
    local_only();
    let oldest = files(&remote, "history")[0]
        .trim_start_matches("history/")
        .trim_end_matches(".json")
        .to_string();
    let racing = |n: u32, command: String| {
        let marker = dir.join(format!("raced-{n}"));
        let script = format!(
            "#!/bin/sh\n[ -f '{m}' ] && exit 0\n: > '{m}'\n\
             unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX\n\
             cd '{o}' && '{bin}' {command} -c git.toml > '{o}/raced-{n}.log' 2>&1\nexit 0\n",
            m = slash(&marker),
            o = slash(&other),
            bin = slash(Path::new(bin())),
        );
        write_hook(&checkout.join(".git/hooks/pre-push"), &script);
        marker
    };
    let marker = racing(1, format!("history --forget {oldest}"));
    let imported = ok(pathwarden(
        &dir,
        &["history", "import", "--workspace", &w],
        &[],
    ));
    assert!(marker.exists(), "the hook ran");
    assert!(imported.contains("Imported 1 run"), "{imported}");
    let h = files(&remote, "history");
    assert_eq!(h.len(), 5, "{h:?}");
    assert!(!h.contains(&format!("history/{oldest}.json")));

    // Import, while another machine records a newer run: refused.
    local_only();
    let marker = racing(2, format!("run -i '{}'", slash(Path::new(&forest()))));
    let out = pathwarden(&dir, &["history", "import", "--workspace", &w], &[]);
    assert!(marker.exists(), "the hook ran");
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("can't be imported in order"), "{t}");
    remove_all(&dir);
}

/// `history storage show --json` of workspace `w`.
fn show_json(dir: &Path, w: &str, env: &[(&str, &str)]) -> serde_json::Value {
    let out = ok(pathwarden(
        dir,
        &["history", "storage", "show", "--json", "--workspace", w],
        env,
    ));
    serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("{e}: {out}"))
}

/// The `pathwarden.toml` under `ws` that keeps the history in `appstate`.
fn env_toml(ws: &Path) -> String {
    fn walk(p: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() && !path.ends_with(".git") {
                walk(&path, out);
            } else if path.file_name().is_some_and(|n| n == "pathwarden.toml") {
                out.extend(std::fs::read_to_string(&path).ok());
            }
        }
    }
    let mut all = Vec::new();
    walk(ws, &mut all);
    all.into_iter()
        .find(|t| t.contains("appstate"))
        .expect("the environment's pathwarden.toml")
}

/// Files any commit on the remote ever held.
fn every_file(remote: &Path) -> String {
    git(remote, &["log", "--all", "--name-only", "--format="])
}

/// Pull every: `set --refresh`, `show`'s rows and JSON, and the
/// record every `pull` writes, worked or not, never committed.
#[test]
fn pull_every_and_the_last_pull() {
    if !have_git() {
        return;
    }
    let dir = scratch("refresh");
    let remote = bare(&dir);
    let w = slash(&dir.join("ws"));
    let f = slash(&dir.join("folder"));
    let storage = |args: &[&str], ws: &str| {
        let mut a = vec!["history", "storage"];
        a.extend_from_slice(args);
        a.extend_from_slice(&["--workspace", ws]);
        pathwarden(&dir, &a, &[])
    };
    // Each workspace starts with a run of its own.
    for ws in [&w, &f] {
        ok(pathwarden(
            &dir,
            &["run", "-i", &forest(), "--save", "--workspace", ws],
            &[],
        ));
    }
    ok(storage(
        &["set", "--git", &slash(&remote), "--folder", "appstate"],
        &w,
    ));
    ok(storage(&["pull"], &w));
    std::fs::remove_file(dir.join("ws/appstate/.pathwarden-last-pull.json")).unwrap();
    // Not pulled by the app yet: the defaults.
    let v = show_json(&dir, &w, &[]);
    assert_eq!(v["refresh_minutes"], 5, "{v}");
    assert_eq!(v["last_pull"]["status"], "not_yet", "{v}");
    let text = ok(storage(&["show"], &w));
    assert!(
        text.contains("Every 5 minutes while the app is open"),
        "{text}"
    );
    assert!(text.contains("Not synced yet on this computer"), "{text}");

    // 1 to 1440 minutes, written only when it isn't 5.
    for bad in ["0", "1441"] {
        let out = storage(&["set", "--refresh", bad], &w);
        assert!(!out.status.success(), "{}", text_of(&out));
    }
    let said = ok(storage(&["set", "--refresh", "15"], &w));
    assert!(said.contains("The app pulls every 15 minutes"), "{said}");
    let toml = env_toml(&dir.join("ws"));
    assert!(toml.contains("refresh = 15"), "{toml}");
    assert_eq!(show_json(&dir, &w, &[])["refresh_minutes"], 15);
    ok(storage(&["set", "--refresh", "5"], &w));
    let toml = env_toml(&dir.join("ws"));
    assert!(!toml.lines().any(|l| l.starts_with("refresh")), "{toml}");

    // `pull` writes the record.
    ok(storage(&["pull"], &w));
    let v = show_json(&dir, &w, &[]);
    assert_eq!(v["last_pull"]["status"], "up_to_date", "{v}");
    assert_eq!(v["last_pull"]["record"]["ok"], true, "{v}");
    assert_eq!(v["last_pull"]["record"]["by"], "command line", "{v}");
    let text = ok(storage(&["show"], &w));
    assert!(text.contains("Up to date · synced just now"), "{text}");

    // The repository out of reach: recorded, counted, and kept as it was.
    let away = dir.join("away.git");
    std::fs::rename(&remote, &away).unwrap();
    for n in 1..=2 {
        let out = storage(&["pull"], &w);
        assert!(!out.status.success(), "{}", text_of(&out));
        let v = show_json(&dir, &w, &[]);
        let last = &v["last_pull"];
        assert_eq!(last["status"], "failed", "{v}");
        assert_eq!(last["record"]["tries"], n, "{v}");
        assert!(!last["record"]["error"].as_str().unwrap().is_empty());
        assert!(last["record"]["last_ok"].is_number(), "{v}");
    }
    let text = ok(storage(&["show"], &w));
    assert!(
        text.contains("Couldn't sync with the repository") && text.contains("2 times in a"),
        "{text}"
    );
    std::fs::rename(&away, &remote).unwrap();
    ok(storage(&["pull"], &w));
    assert_eq!(show_json(&dir, &w, &[])["last_pull"]["record"]["tries"], 0);

    // A run after the pulls commits; the record never goes with it.
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &w],
        &[],
    ));
    assert!(dir.join("ws/appstate/.pathwarden-last-pull.json").exists());
    let all = every_file(&remote);
    assert!(
        all.contains("history/") && !all.contains("last-pull"),
        "{all}"
    );

    // A first clone that fails is recorded too, with git's message.
    let fresh = slash(&dir.join("fresh"));
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &fresh],
        &[],
    ));
    let nowhere = slash(&dir.join("nowhere.git"));
    let set = storage(&["set", "--git", &nowhere, "--folder", "fstate"], &fresh);
    assert!(set.status.success(), "{}", text_of(&set));
    let out = storage(&["pull"], &fresh);
    assert!(!out.status.success(), "{}", text_of(&out));
    let v = show_json(&dir, &fresh, &[]);
    assert_eq!(v["last_pull"]["status"], "failed", "{v}");
    assert!(
        v["last_pull"]["record"]["error"]
            .as_str()
            .unwrap()
            .contains("nowhere.git"),
        "{v}"
    );
    assert!(v["last_pull"]["record"]["last_ok"].is_null(), "{v}");
    let text = ok(storage(&["show"], &fresh));
    assert!(
        text.contains("Couldn't sync with the repository") && text.contains("not synced yet"),
        "{text}"
    );

    // A folder: nothing to pull, and Pull every isn't for it.
    let out = storage(&["set", "--refresh", "10"], &f);
    assert!(!out.status.success());
    assert!(
        text_of(&out).contains("--refresh go with --git"),
        "{}",
        text_of(&out)
    );
    let v = show_json(&dir, &f, &[]);
    assert!(
        v["refresh_minutes"].is_null() && v["last_pull"].is_null(),
        "{v}"
    );
    let text = ok(storage(&["show"], &f));
    assert!(!text.contains("Last sync"), "{text}");
    remove_all(&dir);
}

/// An encrypted history on a computer with no passphrase for it:
/// the pull goes on (it needs no key) and loads nothing; the record says
/// so, and is never committed, encrypted or not.
#[test]
fn an_encrypted_history_pulls_without_the_passphrase_and_loads_nothing() {
    if !have_git() {
        return;
    }
    let dir = scratch("refresh-enc");
    let remote = bare(&dir);
    let keys = slash(&dir.join("keystore"));
    let pass = [
        ("PATHWARDEN_TEST_KEYSTORE", keys.as_str()),
        (
            "PATHWARDEN_HISTORY_PASSPHRASE",
            "correct horse battery staple",
        ),
    ];
    let none = [("PATHWARDEN_TEST_KEYSTORE", keys.as_str())];
    let a = slash(&dir.join("a"));
    let b = slash(&dir.join("b"));
    let storage = |args: &[&str], ws: &str, env: &[(&str, &str)]| {
        let mut v = vec!["history", "storage"];
        v.extend_from_slice(args);
        v.extend_from_slice(&["--workspace", ws]);
        pathwarden(&dir, &v, env)
    };
    for (ws, env) in [(&a, &pass[..]), (&b, &none[..])] {
        ok(pathwarden(
            &dir,
            &["run", "-i", &forest(), "--save", "--workspace", ws],
            env,
        ));
    }
    ok(storage(
        &["set", "--git", &slash(&remote), "--folder", "astate"],
        &a,
        &pass,
    ));
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &a],
        &pass,
    ));
    ok(storage(
        &["set", "--encrypt", "--yes", "--from-env"],
        &a,
        &pass,
    ));
    ok(storage(&["pull"], &a, &pass));
    assert_eq!(
        show_json(&dir, &a, &pass)["last_pull"]["status"],
        "up_to_date"
    );

    // Another computer, no passphrase: it pulls, and loads nothing.
    ok(storage(
        &["set", "--git", &slash(&remote), "--folder", "bstate"],
        &b,
        &none,
    ));
    let out = ok(storage(&["pull"], &b, &none));
    assert!(out.contains("Synced: up to date."), "{out}");
    let v = show_json(&dir, &b, &none);
    assert_eq!(v["last_pull"]["status"], "locked", "{v}");
    assert_eq!(v["last_pull"]["record"]["ok"], true, "{v}");
    assert_eq!(v["last_pull"]["record"]["runs"], 0, "{v}");
    let text = ok(storage(&["show"], &b, &none));
    assert!(text.contains("nothing loaded until the"), "{text}");
    assert!(dir.join("b/bstate/.pathwarden-last-pull.json").exists());
    // The files came, still encrypted.
    assert!(std::fs::read_dir(dir.join("b/bstate/history"))
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().ends_with(".age")));
    // A's next run commits encrypted files; the record never goes with them.
    ok(pathwarden(
        &dir,
        &["run", "-i", &forest(), "--save", "--workspace", &a],
        &pass,
    ));
    let all = every_file(&remote);
    assert!(all.contains(".age") && !all.contains("last-pull"), "{all}");
    remove_all(&dir);
}

fn text_of(o: &Output) -> String {
    text(o)
}

/// How the state repository grows: 20 runs of the demo collection.
/// Prints the repository's size and each commit's size; run with
/// `cargo test -p pathwarden --test git_state -- --ignored --nocapture`.
#[test]
#[ignore]
fn growth_over_twenty_runs() {
    if !have_git() {
        return;
    }
    let dir = scratch("growth");
    let remote = bare(&dir);
    config(&dir, &remote);
    let mut before = 0u64;
    for i in 1..=20 {
        ok(pathwarden(
            &dir,
            &["run", "-i", "demo:", "-c", "git.toml"],
            &[],
        ));
        let size = dir_size(&remote);
        let stat = git(&remote, &["show", "--stat=200", "--format=", "main"]);
        println!(
            "run {i:2}: repository {size:>9} bytes (+{:>7}); {}",
            size - before,
            stat.lines().last().unwrap_or("").trim()
        );
        before = size;
    }
    let work = dir.join("work");
    for f in ["findings.json", "last-run.json"] {
        println!(
            "{f}: {} bytes",
            std::fs::metadata(work.join(f)).unwrap().len()
        );
    }
    let point = std::fs::read_dir(work.join("history"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    println!("a history point: {} bytes", point.metadata().unwrap().len());
    git(&remote, &["gc", "-q"]);
    println!("after git gc: {} bytes", dir_size(&remote));
    remove_all(&dir);
}

fn dir_size(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                dir_size(&e.path())
            } else {
                m.len()
            }
        })
        .sum()
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

/// Removes a test's folder, git's read-only object files included (Windows
/// won't delete a read-only file).
fn remove_all(dir: &Path) {
    fn writable(p: &Path) {
        let Ok(entries) = std::fs::read_dir(p) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            if let Ok(m) = std::fs::symlink_metadata(&path) {
                if m.is_dir() {
                    writable(&path);
                } else {
                    let mut perms = m.permissions();
                    #[allow(clippy::permissions_set_readonly_false)]
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&path, perms);
                }
            }
        }
    }
    writable(dir);
    let _ = std::fs::remove_dir_all(dir);
}
