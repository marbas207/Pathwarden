//! Full runs in the history from every recorder: the app,
//! a schedule's `pathwarden run`, `history import`, and the backlog a crash
//! leaves; and `history storage set --full-runs-kept`. The remote is a
//! local bare repository.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pathwarden_ui::jobs::{self, JobSpec, JobStatus, Jobs};
use pathwarden_ui::shared_runs::{FullRunState, Manifest};
use pathwarden_ui::workspace::{new_run_id, Workspace};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
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
    let dir = std::env::temp_dir().join(format!("pathwarden-fr-{name}-{}", std::process::id()));
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

fn bare(dir: &Path) -> PathBuf {
    let remote = dir.join("state.git");
    git(dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    remote
}

fn pw(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        // Never this account's own app data.
        .env("LOCALAPPDATA", dir.join("appdata"))
        .args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn ok(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Runs an analysis the way the app's Analyze page does, and waits for it.
fn ui_analyze(jobs: &Arc<Jobs>, ws: &Workspace, input: PathBuf) -> String {
    std::thread::sleep(Duration::from_millis(1100));
    let id = new_run_id(pathwarden_core::analyze::now());
    let spec = JobSpec {
        id: id.clone(),
        inputs: vec![input],
        scratch: None,
        also_scratch: None,
        source: r"C:\Users\ann.smith\goad.zip".into(),
        demo: false,
        env: Some("default".into()),
        new_env: None,
        env_auto: false,
        label: None,
        collection: None,
        timings: None,
        force: true,
    };
    assert!(jobs.try_begin(&spec));
    jobs::spawn(jobs.clone(), ws.clone(), spec, false, true);
    let start = Instant::now();
    loop {
        match jobs.get(&id).map(|j| j.status) {
            Some(JobStatus::Done { .. }) => return id,
            Some(JobStatus::Failed { error }) => panic!("{error}"),
            Some(s) if !s.is_active() => panic!("{s:?}"),
            _ if start.elapsed() > Duration::from_secs(180) => panic!("timed out"),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn remote_bundles(remote: &Path) -> Vec<String> {
    git(remote, &["ls-tree", "--name-only", "main", "runs/"])
        .lines()
        .map(|l| l.trim_start_matches("runs/").to_string())
        .collect()
}

fn manifest(remote: &Path, id: &str) -> Manifest {
    serde_json::from_str(&git(remote, &["show", &format!("main:runs/{id}/run.json")])).unwrap()
}

fn state_toml(remote: &Path, work: &Path) -> String {
    format!(
        "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\nkeep = \"full\"\n",
        remote.to_string_lossy().replace('\\', "/"),
        work.to_string_lossy().replace('\\', "/"),
    )
}

#[test]
fn the_app_shares_its_runs_in_full_and_catches_up_after_a_crash() {
    if !have_git() {
        return;
    }
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let dir = scratch("app");
    let remote = bare(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    std::fs::write(
        ws.config_path(),
        state_toml(&remote, &dir.join("ws").join("state")),
    )
    .unwrap();
    let jobs = Arc::new(Jobs::default());

    let first = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    let link = ws.summary(&first).unwrap().history.unwrap();
    let run_id = link.run_id.clone().unwrap();
    let full = link.full_run.expect("a full run");
    assert_eq!(full.state, FullRunState::Shared, "{full:?}");
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&run_id));
    let m = manifest(&remote, &run_id);
    assert_eq!(m.recorded_from, "ui");
    assert_eq!(m.folder.as_deref(), Some(first.as_str()));
    let summary = git(
        &remote,
        &["show", &format!("main:runs/{run_id}/summary.json")],
    );
    assert!(!summary.contains("ann.smith"), "{summary}");
    assert!(summary.contains("goad.zip"), "{summary}");

    // A crash after the point but before the full run: the run says
    // pending, and the remote lacks its full run (taken out by hand here).
    let other = dir.join("other");
    git(
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
    git(&other, &["rm", "-q", "-r", &format!("runs/{run_id}")]);
    git(&other, &["commit", "-q", "-m", "lost"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let mut s = ws.summary(&first).unwrap();
    s.history.as_mut().unwrap().full_run.as_mut().unwrap().state = FullRunState::Pending;
    ws.update_summary(&s).unwrap();

    // The next run from the app brings it in, with its own.
    let second = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    let second_id = ws.summary(&second).unwrap().run_id();
    let mut want = vec![run_id.clone(), second_id];
    want.sort();
    assert_eq!(remote_bundles(&remote), want);
    let caught_up = ws
        .summary(&first)
        .unwrap()
        .history
        .unwrap()
        .full_run
        .unwrap();
    assert_eq!(caught_up.state, FullRunState::Shared);

    // A run that said "not pushed" while a later push took its full run
    // along: the next full run from here marks it shared.
    let mut s = ws.summary(&first).unwrap();
    let f = s.history.as_mut().unwrap().full_run.as_mut().unwrap();
    f.state = FullRunState::Unpushed;
    f.why = Some("not pushed".into());
    ws.update_summary(&s).unwrap();
    ui_analyze(&jobs, &ws, repo("testdata/forest"));
    let now = ws
        .summary(&first)
        .unwrap()
        .history
        .unwrap()
        .full_run
        .unwrap();
    assert_eq!(now.state, FullRunState::Shared);
    assert_eq!(now.why, None);
    remove_all(&dir);
}

#[test]
fn a_schedules_run_goes_in_full_without_a_run_folder() {
    if !have_git() {
        return;
    }
    let dir = scratch("sched");
    let remote = bare(&dir);
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, state_toml(&remote, &dir.join("state"))).unwrap();
    let out = pw(
        &dir,
        &[
            "run",
            "-c",
            &config.to_string_lossy(),
            "-i",
            &repo("testdata/forest").to_string_lossy(),
        ],
        &[("PATHWARDEN_SCHEDULED", "1")],
    );
    let text = ok(&out);
    assert!(text.contains("Full run in the history ("), "{text}");
    let ids = remote_bundles(&remote);
    assert_eq!(ids.len(), 1);
    let m = manifest(&remote, &ids[0]);
    assert_eq!(m.recorded_from, "schedule");
    assert_eq!(m.folder, None);
    assert!(m.files.iter().any(|f| f.name == "report.html.gz"));
    assert!(m.files.iter().any(|f| f.name == "graph.bin.gz"));
    // The source is the input's folder name, not its path.
    let summary = git(
        &remote,
        &["show", &format!("main:runs/{}/summary.json", ids[0])],
    );
    let s: serde_json::Value = serde_json::from_str(&summary).unwrap();
    assert_eq!(s["source"], "forest");

    // --no-push: neither the point nor the full run goes anywhere.
    let out = pw(
        &dir,
        &[
            "run",
            "-c",
            &config.to_string_lossy(),
            "-i",
            &repo("testdata/forest").to_string_lossy(),
            "--no-push",
        ],
        &[],
    );
    let text = ok(&out);
    assert!(!text.contains("Full run"), "{text}");
    assert_eq!(remote_bundles(&remote).len(), 1);
    remove_all(&dir);
}

#[test]
fn imported_runs_go_in_full() {
    if !have_git() {
        return;
    }
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let dir = scratch("import");
    let remote = bare(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let work = dir.join("ws").join("state");
    std::fs::write(ws.config_path(), state_toml(&remote, &work)).unwrap();
    let jobs = Arc::new(Jobs::default());
    // A run made while another held the history: local only.
    std::fs::create_dir_all(&work).unwrap();
    let lock = work.join(".pathwarden.lock");
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let id = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    assert!(ws.summary(&id).unwrap().history.unwrap().run_id.is_none());
    std::fs::remove_file(&lock).unwrap();
    // The lock made the folder: no clone there yet, and it must be empty.
    let _ = std::fs::remove_dir(&work);
    let (n, notes) = pathwarden_ui::history_ui::import(&ws, None).unwrap();
    assert_eq!(n, 1, "{notes:?}");
    let link = ws.summary(&id).unwrap().history.unwrap();
    let run_id = link.run_id.unwrap();
    assert_eq!(link.full_run.unwrap().state, FullRunState::Shared);
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&run_id));
    assert_eq!(manifest(&remote, &run_id).recorded_from, "import");
    remove_all(&dir);
}

#[test]
fn how_many_full_runs_are_kept_is_set_from_the_command_line() {
    let dir = scratch("kept");
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    let text = ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--full-runs-kept",
            "12",
            "--workspace",
            "ws",
        ],
        &[],
    ));
    assert!(
        text.contains("The history keeps the latest 12 full runs; older ones keep their numbers."),
        "{text}"
    );
    let toml = std::fs::read_to_string(dir.join("ws").join("pathwarden.toml")).unwrap();
    assert!(toml.contains("full_runs_kept = 12"), "{toml}");
    // The default writes nothing (a file 0.1.7 still reads).
    ok(&pw(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--full-runs-kept",
            "50",
            "--workspace",
            "ws",
        ],
        &[],
    ));
    let toml = std::fs::read_to_string(dir.join("ws").join("pathwarden.toml")).unwrap();
    assert!(!toml.contains("full_runs_kept"), "{toml}");
    for bad in ["0", "1001", "x"] {
        let out = pw(
            &dir,
            &[
                "history",
                "storage",
                "set",
                "--full-runs-kept",
                bad,
                "--workspace",
                "ws",
            ],
            &[],
        );
        assert!(!out.status.success(), "{bad}");
    }
    remove_all(&dir);
}

/// A pre-receive hook on `remote` that refuses any push changing runs/
/// (a new branch passes).
fn refuse_full_runs(remote: &Path) -> PathBuf {
    let hook = remote.join("hooks").join("pre-receive");
    std::fs::write(
        &hook,
        "#!/bin/sh\nwhile read old new ref; do\n  case $old in 0000000000000000000000000000000000000000) exit 0;; esac\n  if git diff --name-only \"$old\" \"$new\" | grep -q '^runs/'; then echo 'no full runs' >&2; exit 1; fi\ndone\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    hook
}

/// `pathwarden run`, `run --save` and `retest --record` whose point is
/// pushed but whose full run the remote refuses: each warns and exits with
/// status 2, so a schedule notices.
#[test]
fn a_full_run_the_remote_refuses_fails_every_recording_command() {
    if !have_git() {
        return;
    }
    let dir = scratch("refused");
    let remote = bare(&dir);
    let forest = repo("testdata/forest").to_string_lossy().into_owned();
    // The first push (a new branch) passes, with a first run and its full
    // run; then the hook refuses full runs.
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, state_toml(&remote, &dir.join("state"))).unwrap();
    let c = config.to_string_lossy().into_owned();
    ok(&pw(&dir, &["run", "-c", &c, "-i", &forest], &[]));
    refuse_full_runs(&remote);
    let refused = |out: &std::process::Output, what: &str| {
        assert_eq!(out.status.code(), Some(2), "{what}: {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("Full run not shared"), "{what}: {err}");
        assert!(
            err.contains("The run was recorded, but its full run is committed here, not pushed"),
            "{what}: {err}"
        );
    };
    std::thread::sleep(Duration::from_millis(1100));
    let out = pw(
        &dir,
        &["run", "-c", &c, "-i", &forest],
        &[("PATHWARDEN_SCHEDULED", "1")],
    );
    refused(&out, "run");
    // A schedule's run says it can't make it again.
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("If this run's upload is lost before it is shared"),
        "{out:?}"
    );
    // Each from a working copy of its own: one that holds the refused
    // commit would push it with its point, and the point would be refused.
    let config2 = dir.join("retest.toml");
    std::fs::write(&config2, state_toml(&remote, &dir.join("state2"))).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    refused(
        &pw(
            &dir,
            &[
                "retest",
                "--record",
                "-c",
                &config2.to_string_lossy(),
                "-i",
                &forest,
            ],
            &[],
        ),
        "retest --record",
    );
    // run --save: a first one makes the environment, which then gets the
    // same history settings.
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", &forest],
        &[],
    ));
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let env = ws.for_run(&ws.all_runs()[0]);
    std::fs::write(
        env.config_path(),
        state_toml(&remote, &dir.join("ws-state")),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    refused(
        &pw(
            &dir,
            &["run", "--save", "--workspace", "ws", "-i", &forest],
            &[],
        ),
        "run --save",
    );
    remove_all(&dir);
}

/// `history storage show` says how many full runs are kept and the file
/// limit, as the page's card does.
#[test]
fn history_storage_show_names_the_full_run_settings() {
    let dir = scratch("show");
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    std::fs::write(
        dir.join("ws").join("pathwarden.toml"),
        "[state]\nkeep = \"full\"\nfull_runs_kept = 7\n",
    )
    .unwrap();
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
    ));
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(text.contains("Keep the latest"), "{text}");
    assert!(
        text.contains("The history keeps the latest 7 full runs; older ones keep their numbers."),
        "{text}"
    );
    assert!(
        text.contains(
            "Largest file 75 MB. Larger files are left out of the full run and named on its page."
        ),
        "{text}"
    );
    assert!(text.contains("Its numbers are always kept."), "{text}");
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
        &[],
    )))
    .unwrap();
    assert_eq!(json["full_runs"]["kept"], 7);
    assert_eq!(json["full_runs"]["max_file_bytes"], 75 * 1024 * 1024);
    assert_eq!(json["full_runs"]["held_by_github"], false);
    // Without full runs, neither.
    std::fs::write(dir.join("ws").join("pathwarden.toml"), "[state]\n").unwrap();
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
    ));
    assert!(!text.contains("Keep the latest"), "{text}");
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
        &[],
    )))
    .unwrap();
    assert!(json["full_runs"].is_null());
    remove_all(&dir);
}

/// What an encrypted history's objects must never hold in plain text.
fn assert_nothing_plain(objects: &[u8]) {
    let text = String::from_utf8_lossy(objects).to_ascii_lowercase();
    let me = pathwarden_core::identity::Actor::current();
    let mut secrets: Vec<String> = [
        "contoso",
        "s-1-5-21",
        "<html",
        "pathwarden.run-bundle",
        "full run (",
        "full runs (",
        "goad.zip",
        "ann.smith",
        "run(s)",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    secrets.extend(me.user.iter().map(|u| u.to_ascii_lowercase()));
    secrets.extend(me.computer.iter().map(|c| c.to_ascii_lowercase()));
    for s in &secrets {
        assert!(
            !text.contains(s.as_str()),
            "the git objects hold {s:?} in plain text"
        );
    }
    assert!(
        // The whole header our gzip files start with (magic, deflate, no
        // flags, no time): 3 bytes alone turn up in ciphertext by chance.
        !objects
            .windows(8)
            .any(|w| w == [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]),
        "a gzip file is in the git objects in plain form"
    );
}

/// An encrypted history's commit messages: a run's own, a removal's, a few
/// fixed ones, or the neutral one; never a count or a size.
fn assert_neutral_messages(remote: &Path) {
    let log = git(remote, &["log", "--format=%B%x1e", "main"]);
    for m in log.split('\u{1e}').map(str::trim).filter(|m| !m.is_empty()) {
        let ok = m == "pathwarden: update the history"
            || m == "pathwarden: encrypt the history"
            || m == "pathwarden settings"
            || m.strip_prefix("pathwarden run ")
                .is_some_and(|id| !id.contains([' ', ':', '(']))
            || (m.starts_with("pathwarden: remove run ") && m.ends_with(" from the history"));
        assert!(ok, "an encrypted history's commit says {m:?}");
    }
}

/// On an encrypted history, the app's import of several runs and its
/// catch-up of pending full runs commit several full runs at once: their
/// messages say no count or size, and no object holds anything plain.
#[test]
fn an_encrypted_history_s_import_and_catch_up_say_nothing() {
    if !have_git() {
        return;
    }
    std::env::set_var("PATHWARDEN_LOCK_WAIT", "0");
    let dir = scratch("enc");
    pathwarden_core::keystore::use_test_store(&dir.join("keystore"));
    let remote = bare(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let work = dir.join("ws").join("state");
    std::fs::write(ws.config_path(), state_toml(&remote, &work)).unwrap();
    let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
    let pass =
        || pathwarden_core::crypt::SecretString::from("correct horse battery staple".to_string());
    loc.store.encrypt(&pass(), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&loc.dir, pass());
    let jobs = Arc::new(Jobs::default());

    // Two runs made while another held the history, then imported: their
    // full runs go in one commit.
    let lock = work.join(".pathwarden.lock");
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    let r1 = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    let r2 = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    std::fs::remove_file(&lock).unwrap();
    let (n, notes) = pathwarden_ui::history_ui::import(&ws, None).unwrap();
    assert_eq!(n, 2, "{notes:?}");
    let ids: Vec<String> = [&r1, &r2]
        .iter()
        .map(|r| {
            let h = ws.summary(r).unwrap().history.unwrap();
            assert_eq!(h.full_run.unwrap().state, FullRunState::Shared);
            h.run_id.unwrap()
        })
        .collect();
    assert_eq!(remote_bundles(&remote), ids);

    // Both full runs lost from the remote and pending here: the next run
    // from the app brings them in with its own, in one commit.
    let other = dir.join("other");
    git(
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
    git(&other, &["rm", "-q", "-r", "runs"]);
    git(
        &other,
        &["commit", "-q", "-m", "pathwarden: update the history"],
    );
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    for r in [&r1, &r2] {
        let mut s = ws.summary(r).unwrap();
        s.history.as_mut().unwrap().full_run.as_mut().unwrap().state = FullRunState::Pending;
        ws.update_summary(&s).unwrap();
    }
    let r3 = ui_analyze(&jobs, &ws, repo("testdata/forest"));
    assert_eq!(remote_bundles(&remote).len(), 3);
    for r in [&r1, &r2, &r3] {
        let h = ws.summary(r).unwrap().history.unwrap();
        assert_eq!(h.full_run.unwrap().state, FullRunState::Shared, "{r}");
    }
    // The catch-up's manifests say how each run was recorded.
    for id in &ids {
        let m: Manifest =
            serde_json::from_slice(&loc.store.read_bundle_file(id, "run.json").unwrap().unwrap())
                .unwrap();
        assert_eq!(m.recorded_from, "import", "{id}");
        assert!(m.files.iter().all(|f| f.name != "settings.toml"), "{id}");
    }
    assert_neutral_messages(&remote);
    let objects = {
        let out = git_command()
            .arg("-C")
            .arg(&remote)
            .args(["cat-file", "--batch-all-objects", "--batch"])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        out.stdout
    };
    assert_nothing_plain(&objects);
    remove_all(&dir);
}

/// `history storage pull` loads the history's full runs into the
/// workspace, as the app's Pull now does.
#[test]
fn history_storage_pull_loads_full_runs() {
    if !have_git() {
        return;
    }
    let dir = scratch("pull");
    let remote = bare(&dir);
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, state_toml(&remote, &dir.join("state"))).unwrap();
    let forest = repo("testdata/forest").to_string_lossy().into_owned();
    ok(&pw(
        &dir,
        &["run", "-c", &config.to_string_lossy(), "-i", &forest],
        &[],
    ));
    // A reader: pushing off, and keeping numbers with names itself.
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    std::fs::write(
        dir.join("ws").join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\npush = false\n",
            remote.to_string_lossy().replace('\\', "/"),
            dir.join("reader-state")
                .to_string_lossy()
                .replace('\\', "/"),
        ),
    )
    .unwrap();
    let text = ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
        &[],
    ));
    assert!(
        text.contains("1 full run loaded from the repository."),
        "{text}"
    );
    // Who recorded it, in the words the Runs page and Run details use.
    assert!(
        text.contains(" · Recorded from the command line."),
        "{text}"
    );
    assert!(!text.contains("by the command line"), "{text}");
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let runs = ws.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].shared.as_ref().unwrap().recorded_from, "cli");
    assert!(ws
        .run_dir(&runs[0].id)
        .unwrap()
        .join("report.html")
        .is_file());
    // A reader keeping numbers with names itself, on a history that holds
    // full runs: History storage states the Full runs fact all the same,
    // as Runs lists them.
    let shown: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
        &[],
    )))
    .unwrap();
    assert_eq!(shown["keep"], "names");
    assert_eq!(shown["open_in_full"]["on_this_computer"], 1, "{shown}");
    let text = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
    ));
    assert!(text.contains("open in full on this computer"), "{text}");
    // `runs show` says what the run page's Run details tab says.
    let shown = ok(&pw(
        &dir,
        &["runs", "show", &runs[0].id, "--workspace", "ws"],
        &[],
    ));
    for want in [
        "Run details",
        "Run ID",
        &runs[0].run_id(),
        "From the command line by",
        "Repository",
        "Loaded here",
        // Its collection performance and the settings line, as the tab.
        &format!(
            "  Collection performance · `pathwarden diagnose {}` shows it.",
            runs[0].run_id()
        ),
        "  The next analysis applies: ",
    ] {
        assert!(shown.contains(want), "{want} in {shown}");
    }
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["runs", "show", &runs[0].id, "--workspace", "ws", "--json"],
        &[],
    )))
    .unwrap();
    assert_eq!(json["performance"]["slower"], false, "{json}");
    assert_eq!(json["performance"]["words"], "Collection performance");
    assert_eq!(json["settings"]["loaded"], true, "{json}");
    assert!(
        json["settings"]["applies"]
            .as_str()
            .unwrap()
            .starts_with("The next analysis applies: "),
        "{json}"
    );
    // Who recorded it, as a hostile writer would say it: no terminal
    // escape reaches the terminal.
    // A loaded run's summary is run folder format 2 (docs/dev/formats.md).
    let path = ws.run_dir(&runs[0].id).unwrap().join("summary.v2.json");
    let mut s: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    s["shared"]["recorded_by"] = "<b>x</b>\u{1b}[31mmallory".into();
    s["shared"]["recorded_on"] = "\u{1b}]0;owned\u{7}PC\u{1b}[2J".into();
    std::fs::write(&path, serde_json::to_vec(&s).unwrap()).unwrap();
    for args in [
        &["runs", "show", &runs[0].id, "--workspace", "ws"][..],
        &["runs", "list", "--workspace", "ws"][..],
    ] {
        let shown = ok(&pw(&dir, args, &[]));
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
            "{args:?}: {shown:?}"
        );
        if args[1] == "show" {
            assert!(shown.contains("mallory"), "{shown}");
        }
    }
    // Again: nothing new.
    let text = ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
        &[],
    ));
    assert!(!text.contains("loaded"), "{text}");
    remove_all(&dir);
}

// ------------------------------- A full run that didn't follow its point

/// Progress that does `then` once, when the report starts: after the run's
/// point is recorded and pushed, before its full run goes in.
struct AfterPoint<F: FnMut()> {
    then: Option<F>,
}

impl<F: FnMut()> pathwarden_core::analyze::Progress for AfterPoint<F> {
    fn phase(&mut self, phase: pathwarden_core::analyze::Phase) {
        if phase == pathwarden_core::analyze::Phase::Report {
            if let Some(mut f) = self.then.take() {
                f();
            }
        }
    }
}

impl<F: FnMut()> pathwarden_core::record::RecordProgress for AfterPoint<F> {
    fn warn(&mut self, _: String) {}
}

/// An app workspace recording into `remote` with "Full runs and
/// settings": the workspace and its history's folder.
fn app_workspace(dir: &Path, remote: &Path) -> (Workspace, PathBuf) {
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let state = dir.join("ws").join("state");
    std::fs::write(ws.config_path(), state_toml(remote, &state)).unwrap();
    (ws, state)
}

/// Analyzes and saves a run as the app does ([`jobs::save_analysis`]),
/// telling `p` how it goes.
fn app_save<P: pathwarden_core::record::RecordProgress>(
    ws: &Workspace,
    p: &mut P,
) -> pathwarden_ui::workspace::RunSummary {
    std::thread::sleep(Duration::from_millis(1100));
    let config = ws.config().unwrap();
    let mut quiet = AfterPoint::<fn()> { then: None };
    let ev =
        pathwarden_core::analyze::evaluate(&[repo("testdata/forest")], &config, &[], &mut quiet)
            .unwrap();
    let now = pathwarden_core::analyze::now();
    let id = new_run_id(now);
    jobs::save_analysis(
        ws,
        &config,
        ev,
        jobs::SaveRun {
            id: &id,
            source: "goad.zip".into(),
            demo: false,
            label: None,
            collection: None,
            timings: None,
            how: pathwarden_ui::environments::Assigned::Chosen,
            state_dir: None,
            started_ms: now * 1000,
            recorded_by: pathwarden_core::record::by::UI,
            finished_at: None,
            inputs: &[],
        },
        p,
    )
    .unwrap()
}

fn remote_points(remote: &Path) -> String {
    git(remote, &["ls-tree", "--name-only", "main", "history/"])
}

/// The app recorded a run's point, then took the history's lock again for
/// its full run: anything that took the history in between (the app's own
/// pull, Pull now, a settings save, another run) kept the full run out.
/// Now the full run goes in under the lock its point was recorded under,
/// and another task of the app is told the history is in use by this
/// Pathwarden, never by "another pathwarden run".
#[test]
fn the_app_s_full_run_follows_its_point_with_nothing_in_between() {
    if !have_git() {
        return;
    }
    let dir = scratch("between");
    let remote = bare(&dir);
    let (ws, state) = app_workspace(&dir, &remote);
    let config = ws.config().unwrap();
    // The app's pull, say, between the point and the full run: kept, if
    // it got the lock, until the run is saved.
    let other = pathwarden_core::store::Store::new(&config.state, Some(&state)).unwrap();
    let mut tried: Option<Result<pathwarden_core::store::Lock, String>> = None;
    let s = app_save(
        &ws,
        &mut AfterPoint {
            then: Some(|| {
                assert!(remote_points(&remote).contains(".json"), "the point first");
                tried = Some(other.lock().map_err(|e| format!("{e:#}")));
            }),
        },
    );
    let e = match tried {
        Some(Err(e)) => e,
        Some(Ok(_)) => panic!("the history was free between the point and its full run"),
        None => panic!("no report was made"),
    };
    assert!(e.contains("this Pathwarden is already using"), "{e}");
    assert!(!e.contains("another pathwarden run"), "{e}");
    let link = s.history.unwrap();
    let id = link.run_id.unwrap();
    assert_eq!(link.full_run.unwrap().state, FullRunState::Shared);
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&id));
    let log = git(&remote, &["log", "--format=%s", "main"]);
    assert!(
        log.lines()
            .next()
            .unwrap()
            .starts_with(&format!("pathwarden run {id}")),
        "{log}"
    );
    assert!(!state.join(".pathwarden.lock").exists(), "released");
    remove_all(&dir);
}

/// The repository out of reach (or refusing the sign-in) once the point is
/// pushed: the full run is committed here and the run says it is waiting
/// to be pushed, on Runs and in `runs list`, never "Numbers with names".
/// The app's next pull pushes it.
#[test]
fn a_full_run_a_failed_push_kept_goes_with_the_next_pull() {
    if !have_git() {
        return;
    }
    let dir = scratch("kept-push");
    let remote = bare(&dir);
    let (ws, _) = app_workspace(&dir, &remote);
    let away = dir.join("away.git");
    let s = app_save(
        &ws,
        &mut AfterPoint {
            then: Some(|| std::fs::rename(&remote, &away).unwrap()),
        },
    );
    std::fs::rename(&away, &remote).unwrap();
    let link = s.history.clone().unwrap();
    let id = link.run_id.clone().unwrap();
    assert!(remote_points(&remote).contains(&id), "the point is pushed");
    let full = link.full_run.unwrap();
    assert_eq!(full.state, FullRunState::Unpushed, "{full:?}");
    assert!(remote_bundles(&remote).is_empty());

    // Runs and `runs list` say so, from the same rows.
    let snap = pathwarden_ui::history_ui::snapshot(&ws, None);
    let rows = pathwarden_ui::run_list::run_list(&ws, &ws.runs(), &snap);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].note,
        Some(pathwarden_ui::shared_runs::WAITING_WORDS)
    );
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"], &[]));
    assert!(
        text.contains("Its full run is waiting to be shared."),
        "{text}"
    );
    assert!(!text.contains("Numbers with names"), "{text}");

    // The app's next pull (no sign-in prompt) pushes it.
    let pulled = pathwarden_ui::auto_pull::pull_env(&ws, None).unwrap();
    assert!(
        pulled
            .loaded
            .as_deref()
            .unwrap_or_default()
            .contains("1 full run recorded here went into the history."),
        "{:?}",
        pulled.loaded
    );
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&id));
    let now = ws
        .summary(&s.id)
        .unwrap()
        .history
        .unwrap()
        .full_run
        .unwrap();
    assert_eq!(now.state, FullRunState::Shared, "{now:?}");
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"], &[]));
    assert!(!text.contains("waiting to be shared"), "{text}");
    assert!(text.contains("shared"), "{text}");
    remove_all(&dir);
}

/// A pre-receive hook on `remote` that refuses every push to an existing
/// branch.
fn refuse_pushes(remote: &Path) -> PathBuf {
    let hook = remote.join("hooks").join("pre-receive");
    std::fs::write(
        &hook,
        "#!/bin/sh\nwhile read old new ref; do\n  case $old in 0000000000000000000000000000000000000000) exit 0;; esac\n  echo 'not now' >&2; exit 1\ndone\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    hook
}

/// What a failed push kept here (a run's point) goes with the next pull:
/// Pull now and `history storage pull` at once; the app's own pulls not
/// while an analysis runs, nor for an hour after their own push failed.
#[test]
fn a_point_kept_here_goes_with_the_next_pull() {
    if !have_git() {
        return;
    }
    let dir = scratch("kept-point");
    let remote = bare(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    // Numbers with names: points only.
    std::fs::write(
        ws.config_path(),
        state_toml(&remote, &dir.join("ws").join("state")).replace("keep = \"full\"\n", ""),
    )
    .unwrap();
    app_save(&ws, &mut AfterPoint::<fn()> { then: None });
    let hook = refuse_pushes(&remote);
    let s = app_save(&ws, &mut AfterPoint::<fn()> { then: None });
    let id = s.run_id();
    assert!(s.history.unwrap().unpushed.is_some(), "kept here");
    assert!(!remote_points(&remote).contains(&id));
    std::fs::remove_file(&hook).unwrap();
    use pathwarden_ui::auto_pull::{pull_env, pull_env_busy};
    // An analysis running: the app's pull pushes nothing.
    pull_env_busy(&ws, None, &mut |_| {}, &|| true).unwrap();
    assert!(!remote_points(&remote).contains(&id));
    // One that starts while the pull gets ready to push: asked again just
    // before the push, which is left for later.
    let asked = std::cell::Cell::new(0);
    pull_env_busy(&ws, None, &mut |_| {}, &|| {
        asked.set(asked.get() + 1);
        asked.get() > 1
    })
    .unwrap();
    assert_eq!(asked.get(), 2);
    assert!(!remote_points(&remote).contains(&id));
    // Its push refused: it says so once, then waits.
    let hook = refuse_pushes(&remote);
    let p = pull_env(&ws, None).unwrap();
    assert!(p.loaded.is_none(), "{:?}", p.loaded);
    std::fs::remove_file(&hook).unwrap();
    let p = pull_env(&ws, None).unwrap();
    assert!(p.loaded.is_none(), "{:?}", p.loaded);
    assert!(!remote_points(&remote).contains(&id), "an hour first");
    // Waiting: History storage and `show` say so.
    let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
    let waiting = pathwarden_ui::shared_runs::waiting_runs(&ws, &loc);
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert!(!waiting[0].full);
    let show = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
    ));
    assert!(show.contains("1 run is waiting to be shared."), "{show}");
    // Sync now's command, at once: it says what it pushed.
    let text = ok(&pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &[],
    ));
    assert!(
        text.contains(pathwarden_ui::history_ui::KEPT_PUSHED),
        "{text}"
    );
    assert!(
        text.contains("Synced: pushed 1 run, then pulled: up to date."),
        "{text}"
    );
    assert!(remote_points(&remote).contains(&id));
    // The run says it is in the history now, and nothing waits.
    assert!(
        ws.summary(&s.id)
            .unwrap()
            .history
            .unwrap()
            .unpushed
            .is_none(),
        "no longer said to be waiting"
    );
    assert!(pathwarden_ui::shared_runs::waiting_runs(&ws, &loc).is_empty());
    let text = ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
        &[],
    ));
    assert!(text.contains("Synced: up to date."), "{text}");
    remove_all(&dir);
}

/// A repository that wants a sign-in: an HTTP server that answers
/// every request with 401, so git, with no account to give and prompts off,
/// says it could not read a user name. `sync` and `show` say this computer
/// isn't signed in, and whether git here has a credential helper at all.
#[test]
fn a_repository_that_wants_a_sign_in() {
    if !have_git() {
        return;
    }
    use std::io::{Read, Write};
    let dir = scratch("sign-in");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut buf = Vec::new();
                        let mut b = [0u8; 1024];
                        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            match s.read(&mut b) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => buf.extend_from_slice(&b[..n]),
                            }
                        }
                        let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"history\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        })
    };
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let url = format!("http://127.0.0.1:{port}/team/history.git");
    std::fs::write(
        ws.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{url}\"\npath = \"{}\"\n",
            dir.join("ws")
                .join("state")
                .to_string_lossy()
                .replace('\\', "/")
        ),
    )
    .unwrap();
    // Git with no settings but these: no helper at all.
    let empty = dir.join("gitconfig-empty");
    std::fs::write(&empty, "").unwrap();
    let empty = empty.to_string_lossy().into_owned();
    let bare_git = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", empty.as_str()),
    ];
    let out = pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &bare_git,
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("This computer isn't signed in to the repository, and git on this computer has no credential helper"),
        "{err}"
    );
    let show = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &bare_git,
    ));
    assert!(show.contains("Last sync"), "{show}");
    assert!(
        show.contains("Not signed in to the repository") && show.contains("no credential helper"),
        "{show}"
    );
    let v: serde_json::Value = serde_json::from_slice(
        &pw(
            &dir,
            &["history", "storage", "show", "--workspace", "ws", "--json"],
            &bare_git,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(v["last_pull"]["status"], "no_helper", "{v}");
    assert_eq!(v["last_pull"]["sign_in"], true, "{v}");
    assert_eq!(v["last_pull"]["waiting"], 0, "{v}");

    // A helper that gives no account: not signed in, and how to sign in.
    let helper = dir.join("gitconfig-helper");
    std::fs::write(
        &helper,
        "[credential]\n\thelper = \"!f() { cat >/dev/null; }; f\"\n",
    )
    .unwrap();
    let helper = helper.to_string_lossy().into_owned();
    let with_helper = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", helper.as_str()),
    ];
    let out = pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &with_helper,
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("This computer isn't signed in to the repository. Run `pathwarden history storage sign-in`"),
        "{err}"
    );
    let v: serde_json::Value = serde_json::from_slice(
        &pw(
            &dir,
            &["history", "storage", "show", "--workspace", "ws", "--json"],
            &with_helper,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(v["last_pull"]["status"], "not_signed_in", "{v}");
    assert_eq!(v["last_pull"]["record"]["tries"], 2, "{v}");
    // Sign in can't sign in either: it says so.
    let out = pw(
        &dir,
        &["history", "storage", "sign-in", "--workspace", "ws"],
        &with_helper,
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Sign-in didn't work. Check that the account can read the repository, then run `pathwarden history storage sign-in` again."),
        "{err}"
    );

    // A helper that gives an account the repository refuses: refused.
    let giver = dir.join("gitconfig-giver");
    std::fs::write(
        &giver,
        "[credential]\n\thelper = \"!f() { cat >/dev/null; echo username=someone; echo password=wrong; }; f\"\n",
    )
    .unwrap();
    let giver = giver.to_string_lossy().into_owned();
    let gives = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", giver.as_str()),
    ];
    let out = pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &gives,
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("The repository refused this computer's sign-in. Run `pathwarden history storage sign-in`"),
        "{err}"
    );
    let v: serde_json::Value = serde_json::from_slice(
        &pw(
            &dir,
            &["history", "storage", "show", "--workspace", "ws", "--json"],
            &gives,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(v["last_pull"]["status"], "not_signed_in", "{v}");
    assert_eq!(v["last_pull"]["record"]["refused"], true, "{v}");
    assert_eq!(v["last_pull"]["sign_in"], true, "{v}");
    let show = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &gives,
    ));
    assert!(show.contains("Sign-in refused by the repository"), "{show}");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = server.join();
    remove_all(&dir);
}

/// Takes run `s`'s full run out of the repository (through another clone),
/// and has the run say it wasn't shared.
fn lose_full_run(
    dir: &Path,
    remote: &Path,
    ws: &Workspace,
    s: &pathwarden_ui::workspace::RunSummary,
) {
    let other = dir.join("other");
    if !other.exists() {
        git(
            dir,
            &[
                "clone",
                "-q",
                "-b",
                "main",
                &remote.to_string_lossy(),
                &other.to_string_lossy(),
            ],
        );
    }
    git(&other, &["pull", "-q", "origin", "main"]);
    git(&other, &["rm", "-q", "-r", &format!("runs/{}", s.run_id())]);
    git(&other, &["commit", "-q", "-m", "lost"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let mut sum = ws.summary(&s.id).unwrap();
    let f = sum.history.as_mut().unwrap().full_run.as_mut().unwrap();
    f.state = FullRunState::NotShared;
    f.why = Some("the history was in use".into());
    ws.update_summary(&sum).unwrap();
}

/// Full runs that never went in (the history was in use, say) go in with
/// the next `history storage pull`, all at once, and with the app's own
/// pulls one at a time. One whose report is gone here says it can't be
/// shared, on Runs and in `runs list`.
#[test]
fn a_full_run_the_history_never_got_goes_with_the_next_pull() {
    if !have_git() {
        return;
    }
    let dir = scratch("never");
    let remote = bare(&dir);
    let (ws, _) = app_workspace(&dir, &remote);
    let s1 = app_save(&ws, &mut AfterPoint::<fn()> { then: None });
    let s2 = app_save(&ws, &mut AfterPoint::<fn()> { then: None });
    let (id1, id2) = (s1.run_id(), s2.run_id());
    lose_full_run(&dir, &remote, &ws, &s1);
    lose_full_run(&dir, &remote, &ws, &s2);
    // The first one's report is gone here: it can't be made again.
    let report = ws.run_dir(&s1.id).unwrap().join("report.html");
    let aside = dir.join("report.html");
    std::fs::rename(&report, &aside).unwrap();

    let text = ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
        &[],
    ));
    assert!(
        text.contains("1 full run recorded here went into the history."),
        "{text}"
    );
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&id2));
    let now = ws
        .summary(&s2.id)
        .unwrap()
        .history
        .unwrap()
        .full_run
        .unwrap();
    assert_eq!(now.state, FullRunState::Shared, "{now:?}");
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"], &[]));
    assert!(
        text.contains(pathwarden_ui::shared_runs::CANT_SHARE_WORDS),
        "{text}"
    );
    assert!(!text.contains("waiting to be shared"), "{text}");
    // Nothing more to do: the next pull says nothing of it.
    let text = ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
        &[],
    ));
    assert!(!text.contains("full run recorded here"), "{text}");

    // Both waiting again, the report back: the app's pulls bring in one
    // at a time.
    std::fs::rename(&aside, &report).unwrap();
    lose_full_run(&dir, &remote, &ws, &s2);
    let mut want = vec![id1, id2];
    want.sort();
    for n in 1..=2 {
        let p = pathwarden_ui::auto_pull::pull_env(&ws, None).unwrap();
        assert!(
            p.loaded
                .as_deref()
                .unwrap_or_default()
                .contains("1 full run recorded here went into the history."),
            "{:?}",
            p.loaded
        );
        assert_eq!(remote_bundles(&remote).len(), n);
    }
    assert_eq!(remote_bundles(&remote), want);
    remove_all(&dir);
}

// ------------------------------------- The full-run file limit

/// `history storage set --full-run-file-mb` writes `[state]
/// full_run_file_mb` (the default removes it) and says what applies; on a
/// GitHub remote, more than 95 is held to 95, and `show` says why.
#[test]
fn the_largest_file_of_a_full_run_is_set_from_the_command_line() {
    let dir = scratch("file-mb");
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    let toml = dir.join("ws").join("pathwarden.toml");
    std::fs::write(&toml, "[state]\nkeep = \"full\"\n").unwrap();
    let set = |mb: &str| {
        pw(
            &dir,
            &[
                "history",
                "storage",
                "set",
                "--full-run-file-mb",
                mb,
                "--workspace",
                "ws",
            ],
            &[],
        )
    };
    let text = ok(&set("200"));
    assert!(
        text.contains("A full run keeps files up to 200 MB."),
        "{text}"
    );
    assert!(!text.contains("GitHub"), "{text}");
    assert!(std::fs::read_to_string(&toml)
        .unwrap()
        .contains("full_run_file_mb = 200"));
    // On GitHub: held to 95.
    std::fs::write(
        &toml,
        "[state]\nbackend = \"git\"\nremote = \"https://github.com/contoso/history.git\"\npush = false\nkeep = \"full\"\n",
    )
    .unwrap();
    let text = ok(&set("200"));
    assert!(
        text.contains(
            "A full run keeps files up to 95 MB. GitHub refuses files over 100 MB, so a larger setting is held to 95 MB."
        ),
        "{text}"
    );
    let shown = ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
        &[],
    ));
    let shown = shown.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        shown.contains("Largest file 95 MB. GitHub refuses files over 100 MB, so a larger setting is held to 95 MB."),
        "{shown}"
    );
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
        &[],
    )))
    .unwrap();
    assert_eq!(json["full_runs"]["max_file_bytes"], 95 * 1024 * 1024);
    assert_eq!(json["full_runs"]["file_mb_set"], 200);
    assert_eq!(json["full_runs"]["held_by_github"], true);
    ok(&set("75"));
    assert!(!std::fs::read_to_string(&toml)
        .unwrap()
        .contains("full_run_file_mb"));
    for bad in ["0", "2049", "x"] {
        assert!(!set(bad).status.success(), "{bad}");
    }
    remove_all(&dir);
}

/// `runs/<id>/run.json` and `objects.json.gz` of the history in working
/// copy `other`, changed by `change`, committed and pushed.
fn change_full_run(other: &Path, id: &str, change: impl FnOnce(&Path, &mut serde_json::Value)) {
    let folder = other.join("runs").join(id);
    let path = folder.join("run.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    change(&folder, &mut m);
    std::fs::write(&path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    git(other, &["add", "-A"]);
    git(other, &["commit", "-q", "-m", "change"]);
    git(other, &["push", "-q", "origin", "HEAD:main"]);
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A full run whose object index is 60 MB answers `query --run` on the
/// computer that reads the history; one without its index says so, and
/// `search --env` answers from the earlier run, saying why.
#[test]
fn a_large_object_index_answers_queries_on_another_computer() {
    if !have_git() {
        return;
    }
    let dir = scratch("large-index");
    let remote = bare(&dir);
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, state_toml(&remote, &dir.join("state"))).unwrap();
    let forest = repo("testdata/forest").to_string_lossy().into_owned();
    let record = || {
        ok(&pw(
            &dir,
            &["run", "-c", &config.to_string_lossy(), "-i", &forest],
            &[],
        ))
    };
    record();
    let first = remote_bundles(&remote).remove(0);
    assert_eq!(
        manifest(&remote, &first).max_file_bytes,
        Some(75 * 1024 * 1024)
    );
    // Its index padded to 60 MB (spaces after it, stored without
    // compression), as the largest forests' are.
    let other = dir.join("other");
    git(
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
    change_full_run(&other, &first, |folder, m| {
        use std::io::{Read as _, Write as _};
        let path = folder.join("objects.json.gz");
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap())
            .read_to_end(&mut json)
            .unwrap();
        json.resize(60 << 20, b' ');
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        enc.write_all(&json).unwrap();
        let gz = enc.finish().unwrap();
        for f in m["files"].as_array_mut().unwrap() {
            if f["name"] == "objects.json.gz" {
                f["bytes"] = gz.len().into();
                f["sha256"] = sha256_hex(&gz).into();
            }
        }
        std::fs::write(&path, gz).unwrap();
    });
    // A reader.
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    std::fs::write(
        dir.join("ws").join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\npush = false\n",
            remote.to_string_lossy().replace('\\', "/"),
            dir.join("reader-state")
                .to_string_lossy()
                .replace('\\', "/"),
        ),
    )
    .unwrap();
    let pull = || {
        ok(&pw(
            &dir,
            &["history", "storage", "pull", "--workspace", "ws"],
            &[],
        ))
    };
    let text = pull();
    assert!(
        text.contains("1 full run loaded from the repository."),
        "{text}"
    );
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let env = ws.for_run(&ws.runs()[0]).env_name();
    let query = |run: &str| {
        pw(
            &dir,
            &[
                "query",
                "MATCH (u:User) RETURN u LIMIT 5",
                "--run",
                run,
                "--env",
                &env,
                "--workspace",
                "ws",
                "--json",
            ],
            &[],
        )
    };
    let answer: serde_json::Value = serde_json::from_str(&ok(&query(&first))).unwrap();
    assert_eq!(answer["run"]["id"], first.as_str(), "{answer}");

    // A later run without its object index (over the limit it was
    // recorded under).
    std::thread::sleep(Duration::from_millis(1100));
    record();
    git(&other, &["pull", "-q", "origin", "main"]);
    let second = remote_bundles(&remote)
        .into_iter()
        .find(|r| *r != first)
        .unwrap();
    change_full_run(&other, &second, |folder, m| {
        let path = folder.join("objects.json.gz");
        let n = std::fs::metadata(&path).unwrap().len();
        std::fs::remove_file(&path).unwrap();
        m["files"]
            .as_array_mut()
            .unwrap()
            .retain(|f| f["name"] != "objects.json.gz");
        m["left_out"] = serde_json::json!([{
            "name": "objects.json.gz",
            "bytes": n,
            "why": "over the 45 MB per-file limit",
        }]);
    });
    let text = pull();
    assert!(
        text.contains("1 full run loaded from the repository."),
        "{text}"
    );
    let out = query(&second);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(
            "This run's object index wasn't shared, so it can't be explored on this computer"
        ),
        "{err}"
    );
    assert!(!err.contains("analyzed before"), "{err}");
    let out = pw(
        &dir,
        &["search", "alice", "--env", &env, "--workspace", "ws"],
        &[],
    );
    ok(&out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "The latest run of {env}, {second}, can't be explored (its object index wasn't shared): an older run answers."
        )),
        "{err}"
    );
    remove_all(&dir);
}

/// A run whose full run left files out
/// is waiting again once they fit the limit, on the computer that recorded
/// it and still has them; the next push adds just those files (its
/// settings snapshot stays) and updates the manifest. Never from a
/// computer that only reads the history.
#[test]
fn files_a_full_run_left_out_go_in_once_they_fit() {
    if !have_git() {
        return;
    }
    let dir = scratch("refill");
    let remote = bare(&dir);
    let (ws, _) = app_workspace(&dir, &remote);
    let s = app_save(&ws, &mut AfterPoint::<fn()> { then: None });
    let id = s.history.as_ref().unwrap().run_id.clone().unwrap();
    assert_eq!(
        s.history.as_ref().unwrap().full_run.as_ref().unwrap().state,
        FullRunState::Shared
    );
    let before = manifest(&remote, &id);
    assert!(before.settings_sha256.is_some(), "{before:?}");

    // As a run shared under the 45 MB limit was: its index left out and
    // named, and the run here saying so.
    let other = dir.join("other");
    git(
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
    let mut n = 0;
    change_full_run(&other, &id, |folder, m| {
        let path = folder.join("objects.json.gz");
        n = std::fs::metadata(&path).unwrap().len();
        std::fs::remove_file(&path).unwrap();
        m["files"]
            .as_array_mut()
            .unwrap()
            .retain(|f| f["name"] != "objects.json.gz");
        m["left_out"] = serde_json::json!([{
            "name": "objects.json.gz",
            "bytes": n,
            "why": "over the 45 MB per-file limit",
        }]);
        m.as_object_mut().unwrap().remove("max_file_bytes");
    });
    let mut summary = ws.summary(&s.id).unwrap();
    summary
        .history
        .as_mut()
        .unwrap()
        .full_run
        .as_mut()
        .unwrap()
        .left_out = vec![format!(
        "objects.json.gz ({})",
        pathwarden_core::diagnostics::bytes(n)
    )];
    ws.update_summary(&summary).unwrap();
    let files = |id: &str| {
        git(
            &remote,
            &["ls-tree", "--name-only", "main", &format!("runs/{id}/")],
        )
    };
    assert!(!files(&id).contains("objects.json.gz"));

    // Its row says it waits.
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"], &[]));
    assert!(
        text.contains("Its full run is waiting to be shared."),
        "{text}"
    );

    // A computer that only reads the history never fills it in.
    std::fs::create_dir_all(dir.join("reader")).unwrap();
    std::fs::write(
        dir.join("reader").join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\npush = false\nkeep = \"full\"\n",
            remote.to_string_lossy().replace('\\', "/"),
            dir.join("reader-state")
                .to_string_lossy()
                .replace('\\', "/"),
        ),
    )
    .unwrap();
    ok(&pw(
        &dir,
        &["history", "storage", "pull", "--workspace", "reader"],
        &[],
    ));
    assert!(!files(&id).contains("objects.json.gz"));

    // The recording computer's next sync adds just the index.
    let commits = || git(&remote, &["rev-list", "--count", "main"]);
    let was = commits();
    let text = ok(&pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &[],
    ));
    assert!(
        text.contains("1 full run recorded here went into the history."),
        "{text}"
    );
    let now = files(&id);
    assert!(now.contains("objects.json.gz"), "{now}");
    assert!(now.contains("settings.toml"), "{now}");
    let changed = git(
        &remote,
        &["diff", "--name-only", "main~1", "main", "--", "runs/"],
    );
    let mut changed: Vec<&str> = changed.lines().collect();
    changed.sort();
    assert_eq!(
        changed,
        [
            format!("runs/{id}/objects.json.gz"),
            format!("runs/{id}/run.json")
        ]
    );
    let after = manifest(&remote, &id);
    assert!(after.left_out.is_empty(), "{after:?}");
    assert_eq!(after.max_file_bytes, Some(75 * 1024 * 1024));
    assert_eq!(after.settings_sha256, before.settings_sha256);
    let link = ws
        .summary(&s.id)
        .unwrap()
        .history
        .unwrap()
        .full_run
        .unwrap();
    assert_eq!(link.state, FullRunState::Shared, "{link:?}");
    assert!(link.left_out.is_empty(), "{link:?}");
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"], &[]));
    assert!(!text.contains("waiting to be shared"), "{text}");
    // Nothing more to add.
    let pushed = commits();
    assert_ne!(pushed, was);
    ok(&pw(
        &dir,
        &["history", "storage", "sync", "--workspace", "ws"],
        &[],
    ));
    assert_eq!(commits(), pushed);
    remove_all(&dir);
}
