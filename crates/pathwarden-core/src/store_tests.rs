use super::*;

/// A scheduled run doesn't follow a key it hasn't pinned: the
/// pin stays, and nothing says it was followed. By hand it is followed,
/// and told once; the key already pinned is fine either way.
#[test]
fn a_scheduled_run_refuses_a_replaced_key() {
    let dir = std::env::temp_dir().join(format!("pw-follow-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".git")).unwrap();
    let old = "a".repeat(64);
    let new = "b".repeat(64);
    pin_key(&dir, &old).unwrap();
    follow_key_as(&dir, &old, true).unwrap();
    let e = follow_key_as(&dir, &new, true).unwrap_err().to_string();
    assert!(
        e.contains("a scheduled run doesn't follow a new key"),
        "{e}"
    );
    assert_eq!(pinned_key(&dir).as_deref(), Some(old.as_str()));
    assert!(take_key_note(&dir).is_none());
    follow_key_as(&dir, &new, false).unwrap();
    assert_eq!(pinned_key(&dir).as_deref(), Some(new.as_str()));
    assert!(take_key_note(&dir).is_some_and(|n| n.contains("was replaced")));
    // Nothing pinned yet: the first key is pinned, scheduled or not.
    fs::remove_file(pin_path(&dir).unwrap()).unwrap();
    follow_key_as(&dir, &old, true).unwrap();
    assert_eq!(pinned_key(&dir).as_deref(), Some(old.as_str()));
    fs::remove_dir_all(&dir).unwrap();
}

/// A small file of the repository (the marker, a `.gitattributes`) is
/// read only when git says it is small.
#[test]
fn large_blobs_are_not_read() {
    let dir = std::env::temp_dir().join(format!("pw-small-blob-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    if run_git(Some(&dir), &["init", "-q"]).is_err() {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    fs::write(dir.join("small"), "text=auto\n").unwrap();
    fs::write(dir.join("big"), vec![b'x'; 4096]).unwrap();
    let id = |f: &str| {
        run_git(Some(&dir), &["hash-object", "-w", f])
            .unwrap()
            .trim()
            .to_string()
    };
    let (small, big) = (id("small"), id("big"));
    assert_eq!(small_blob(&dir, &small, 1024).unwrap(), b"text=auto\n");
    let e = small_blob(&dir, &big, 1024).unwrap_err().to_string();
    assert!(
        e.contains("is 4096 bytes") && e.contains("wasn't read"),
        "{e}"
    );
    remove_tree(&dir).unwrap();
}

#[test]
fn forget_removes_one_point_and_refuses_paths() {
    let dir = std::env::temp_dir().join(format!("pw-forget-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("history")).unwrap();
    for id in ["20261018T120000.000Z", "20261018T130000.000Z"] {
        fs::write(dir.join("history").join(format!("{id}.json")), "{}").unwrap();
    }
    fs::write(dir.join("findings.json"), "{}").unwrap();
    let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
    assert!(store.forget("20261018T120000.000Z").unwrap());
    assert!(!dir.join("history/20261018T120000.000Z.json").exists());
    assert!(dir.join("history/20261018T130000.000Z.json").exists());
    // The findings state is untouched; a second forget finds nothing.
    assert!(dir.join("findings.json").exists());
    assert!(!store.forget("20261018T120000.000Z").unwrap());
    for bad in ["", "../findings", "..", "a/b", r"a\b", ".hidden"] {
        assert!(store.forget(bad).is_err(), "{bad}");
    }
    assert!(dir.join("findings.json").exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// A run's exposed accounts are a file of the history: written
/// through the seam, removed with the run, and kept for the latest
/// runs only.
#[test]
fn exposed_accounts_are_kept_with_their_runs() {
    use crate::exposed::{ExposedRecord, DIR};
    assert!(is_state_rel("exposed/20261018T120000.000Z.json"));
    assert!(!is_state_rel("exposed/x/y.json"));
    assert!(!is_state_rel("exposed/../findings.json"));
    assert!(!is_state_rel("exposed/a.txt"));
    assert!(state_entry("exposed"));
    let dir = std::env::temp_dir().join(format!("pw-exposed-store-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("history")).unwrap();
    let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
    // Twelve runs of one environment, all Full; and keys of a run the
    // history has no point for.
    let ids: Vec<String> = (0..12)
        .map(|i| format!("20261018T12{i:02}00.000Z"))
        .collect();
    for (i, id) in ids.iter().enumerate() {
        let point = serde_json::json!({
            "version": 1, "run_id": id, "at": 1000 + i, "collected_at": null,
            "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
            "tier_zero_population": 1, "tier_zero_objects": 1, "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0, "critical": 0,
                "high": 0, "medium": 0, "low": 0, "info": 0},
            "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                "resolved": 0},
        });
        fs::write(
            dir.join("history").join(format!("{id}.json")),
            point.to_string(),
        )
        .unwrap();
        store
            .save_exposed(&ExposedRecord::new(id, 0, [i as u64]))
            .unwrap();
    }
    store
        .save_exposed(&ExposedRecord::new("20261018T000000.000Z", 0, [7]))
        .unwrap();
    assert!(store
        .save_exposed(&ExposedRecord::new("../x", 0, [7]))
        .is_err());
    // A point the history has but can't read (damaged, or of a newer
    // shape): its keys stay, whatever it is.
    let unread = "20261018T000100.000Z";
    fs::write(dir.join("history").join(format!("{unread}.json")), "{").unwrap();
    store
        .save_exposed(&ExposedRecord::new(unread, 0, [8]))
        .unwrap();
    assert_eq!(store.list_state_files(DIR).unwrap().len(), 14);
    // The orphan and the two oldest go.
    assert_eq!(store.prune_exposed().unwrap(), 3);
    let left = store.list_state_files(DIR).unwrap();
    assert_eq!(left.first().unwrap(), &format!("{DIR}/{unread}.json"));
    assert_eq!(left[1], format!("{DIR}/{}.json", ids[2]));
    assert_eq!(left.len(), 11);
    assert_eq!(store.prune_exposed().unwrap(), 0);
    // Forgetting a run removes its keys.
    assert!(store.forget(&ids[5]).unwrap());
    assert!(!dir.join(format!("{DIR}/{}.json", ids[5])).exists());
    assert_eq!(store.list_state_files(DIR).unwrap().len(), 10);
    // A newer Pathwarden's keys, even an orphan's, stay
    // (docs/dev/formats.md); one of ours goes.
    let newer = dir.join(DIR).join("20261017T000000.000Z.json");
    fs::write(&newer, r#"{"version":2,"run_id":"20261017T000000.000Z"}"#).unwrap();
    fs::write(
        dir.join(DIR).join("20261016T000000.000Z.json"),
        r#"{"version":1,"run_id":"20261016T000000.000Z"}"#,
    )
    .unwrap();
    assert_eq!(store.prune_exposed().unwrap(), 1);
    assert!(newer.is_file());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn encrypted_histories_get_neutral_commit_messages() {
    let id = "20261023T015208.222Z";
    for (given, want) in [
        (
            format!("pathwarden run {id}: 3 new, 0 regressed, 1 resolved, 9 open"),
            format!("pathwarden run {id}"),
        ),
        (
            format!("pathwarden run {id}: full run (2.1 MB)"),
            format!("pathwarden run {id}"),
        ),
        (
            format!("pathwarden run {id}: full run (2.1 MB); 1 older full run removed"),
            format!("pathwarden run {id}"),
        ),
        (
            format!("pathwarden: remove run {id} from the history"),
            format!("pathwarden: remove run {id} from the history"),
        ),
        ("pathwarden settings".into(), "pathwarden settings".into()),
        (
            "pathwarden: encrypt the history".into(),
            "pathwarden: encrypt the history".into(),
        ),
        (
            "pathwarden: 2 full runs (2.0 KB); 1 older full run removed".into(),
            "pathwarden: update the history".into(),
        ),
        (
            "pathwarden: import 3 run(s) analyzed in the UI".into(),
            "pathwarden: update the history".into(),
        ),
        (
            "pathwarden: add 1 earlier run(s) another run's push came before".into(),
            "pathwarden: update the history".into(),
        ),
        (
            "pathwarden settings: 1 Tier Zero addition\n\nChanged-by: NORTH\\x".into(),
            "pathwarden: update the history".into(),
        ),
        (
            "pathwarden settings\n\nChanged-by: NORTH\\x".into(),
            "pathwarden: update the history".into(),
        ),
        (
            "pathwarden run ../x: y".into(),
            "pathwarden: update the history".into(),
        ),
    ] {
        assert_eq!(neutral_message(&given), want, "{given}");
    }
}

#[test]
fn redacts_credentials() {
    assert_eq!(
        redact_url("https://user:ghp_secret@github.com/org/state.git"),
        "https://***@github.com/org/state.git"
    );
    assert_eq!(
        redact_url("https://token@dev.azure.com/org/p/_git/state"),
        "https://***@dev.azure.com/org/p/_git/state"
    );
    assert_eq!(
        redact_url("https://github.com/org/state.git"),
        "https://github.com/org/state.git"
    );
    assert_eq!(redact_url("C:/state/remote.git"), "C:/state/remote.git");
    // The @ in a path is not userinfo.
    assert_eq!(
        redact_url("https://host/a@b/state.git"),
        "https://host/a@b/state.git"
    );
}

#[test]
fn remote_comparison_is_loose_about_form_only() {
    assert!(same_remote(
        "https://GitHub.com/org/state.git/",
        "https://github.com/org/state"
    ));
    assert!(same_remote(
        "https://user:tok@github.com/org/state.git",
        "https://github.com/org/state.git"
    ));
    assert!(!same_remote(
        "https://github.com/org/project.git",
        "https://github.com/org/state.git"
    ));
    assert!(!same_remote("", "https://github.com/org/state.git"));
}

#[test]
fn validates_git_inputs() {
    assert!(validate_branch("main").is_ok());
    assert!(validate_branch("pathwarden/state-1.0").is_ok());
    for bad in [
        "",
        "--upload-pack=/x.sh",
        "-x",
        "a..b",
        "x.lock",
        "x/",
        "a b",
        "a;b",
    ] {
        assert!(validate_branch(bad).is_err(), "{bad:?} accepted");
    }
    assert!(validate_remote("--upload-pack=evil").is_err());
    assert!(validate_remote("https://github.com/org/state.git").is_ok());
}

/// A directory link: a junction on Windows (no privilege needed), a
/// symlink elsewhere.
fn link_dir(target: &Path, link: &Path) -> bool {
    #[cfg(windows)]
    {
        crate::spawn::quiet("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
}

#[test]
fn state_is_not_written_through_links() {
    let dir = std::env::temp_dir().join(format!("pw-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let (state, outside) = (dir.join("state"), dir.join("outside"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&outside).unwrap();
    if !link_dir(&outside, &state.join("history")) {
        eprintln!("cannot create a directory link here; skipping");
        return;
    }
    let cfg = StateConfig::default();
    let store = Store::new(&cfg, Some(&state)).unwrap();
    // save() runs this check before writing anything.
    let err = store.check_no_links().unwrap_err();
    assert!(err.to_string().contains("symbolic link"), "{err:#}");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    // Without the link, the state folder passes.
    // A Unix symlink is removed as a file, a Windows junction as a folder.
    let link = state.join("history");
    fs::remove_file(&link)
        .or_else(|_| fs::remove_dir(&link))
        .unwrap();
    fs::create_dir(&link).unwrap();
    store.check_no_links().unwrap();
    fs::remove_dir_all(&dir).ok();
}

/// The app's background pull stops a silent git after 45 seconds, well
/// before a run or a save waiting for the lock gives up; elsewhere the
/// limit stays 10 minutes, and it ends with the pull.
#[test]
fn a_background_pull_gives_up_on_a_silent_git_early() {
    assert_eq!(git_idle(), GIT_IDLE);
    let inside = background(|| (git_idle(), NON_INTERACTIVE.with(std::cell::Cell::get)));
    assert_eq!(inside, (BACKGROUND_GIT_IDLE, true));
    assert!(BACKGROUND_GIT_IDLE < crate::settings_sync::lock_wait());
    assert_eq!(git_idle(), GIT_IDLE);
    assert!(!NON_INTERACTIVE.with(std::cell::Cell::get));
    assert_eq!(idle_words(BACKGROUND_GIT_IDLE), "45 seconds");
    assert_eq!(idle_words(GIT_IDLE), "10 minutes");
    // A panic inside puts them back too.
    let caught = std::panic::catch_unwind(|| background(|| panic!("in a pull")));
    assert!(caught.is_err());
    assert_eq!(git_idle(), GIT_IDLE);
    assert!(!NON_INTERACTIVE.with(std::cell::Cell::get));
    // The record of the last pull is Pathwarden's own: a working copy
    // from before the mark that holds it is still taken over.
    assert!(state_entry(LAST_PULL_FILE));
}

/// A git that says nothing for too long is stopped, with every process
/// it started (on Windows `git` is a launcher; here an alias's shell
/// and its `sleep`): the alias never gets to write its file.
#[test]
fn a_silent_git_is_stopped_with_everything_it_started() {
    if crate::spawn::quiet("git")
        .arg("--version")
        .output()
        .is_err()
    {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        eprintln!("git is not installed: skipping this test");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pw-git-idle-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let late = dir.join("late.txt");
    let alias = format!(
        "alias.zz=!sleep 4; echo late > '{}'",
        late.to_string_lossy().replace('\\', "/")
    );
    // A ref lock an earlier stopped fetch left goes with the stop.
    run_git(Some(&dir), &["init", "-q"]).unwrap();
    let lock = dir.join(".git/refs/heads/main.lock");
    fs::write(&lock, "x").unwrap();
    let started = std::time::Instant::now();
    let e = run_git_idle(Some(&dir), &["-c", &alias, "zz"], Duration::from_secs(1)).unwrap_err();
    assert!(
        format!("{e:#}").contains("gave no sign of progress"),
        "{e:#}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "stopped, not waited for"
    );
    std::thread::sleep(Duration::from_secs(6));
    assert!(
        !late.exists(),
        "the alias's shell and sleep were stopped too"
    );
    assert!(!lock.exists(), "a stale ref lock is removed");
    // Output is a sign of life; a git that finishes is not stopped.
    let out = run_git_idle(None, &["--version"], Duration::from_secs(1)).unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("git version"));
    remove_tree(&dir).ok();
}

/// A process git started that outlives the stop (here one that left
/// the process group; on Windows a real git that started before the
/// launcher joined its job) may still be writing: the locks are kept.
#[cfg(target_os = "linux")]
#[test]
fn locks_are_kept_while_a_process_git_started_lives() {
    if crate::spawn::quiet("git")
        .arg("--version")
        .output()
        .is_err()
        || crate::spawn::quiet("setsid")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("git or setsid is not installed: skipping this test");
        return;
    }
    let dir = std::env::temp_dir().join(format!("pw-git-escaped-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    run_git(Some(&dir), &["init", "-q"]).unwrap();
    let lock = dir.join(".git/index.lock");
    fs::write(&lock, "x").unwrap();
    let e = run_git_idle(
        Some(&dir),
        &["-c", "alias.zz=!setsid sleep 9", "zz"],
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(
        format!("{e:#}").contains("gave no sign of progress"),
        "{e:#}"
    );
    assert!(lock.exists(), "a lock a live git may hold is kept");
    let words = format!("{e:#}");
    assert!(
        words.contains(&lock.display().to_string()) && words.contains("safe to remove"),
        "the kept lock is named: {words}"
    );
    // While the escaped process holds the pipes, git counts as running
    // there: the next pull leaves the lock alone.
    assert!(running_git().contains_key(&running_key(&dir)));
    fs::remove_dir_all(&dir).ok();
}

/// Lock files a stopped fetch left are removed; ones made after the
/// stop, and anything else, are not.
#[test]
fn locks_a_stopped_git_left_are_removed() {
    let dir = std::env::temp_dir().join(format!("pw-stale-locks-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let git = dir.join(".git");
    let origin = git.join("refs/remotes/origin");
    fs::create_dir_all(&origin).unwrap();
    for f in [
        origin.join("main.lock"),
        git.join("index.lock"),
        origin.join("main"),
    ] {
        fs::write(&f, "x").unwrap();
    }
    let stopped = std::time::SystemTime::now();
    let later = origin.join("other.lock");
    let f = fs::File::create(&later).unwrap();
    f.set_modified(stopped + Duration::from_secs(60)).unwrap();
    drop(f);
    assert_eq!(remove_stale_locks(&git, stopped), 2);
    assert!(!origin.join("main.lock").exists());
    assert!(!git.join("index.lock").exists());
    assert!(origin.join("main").exists());
    assert!(later.exists(), "made after the stop");
    fs::remove_dir_all(&dir).ok();
}

fn git_store(dir: &Path) -> Store {
    let cfg = StateConfig {
        backend: StateBackend::Git,
        remote: Some("https://example.invalid/state.git".into()),
        ..StateConfig::default()
    };
    Store::new(&cfg, Some(dir)).unwrap()
}

/// Git locks an earlier idle stop kept go before the next fetch, once
/// older than the idle limit, only while this process holds the
/// history's lock and runs no git there.
#[test]
fn locks_kept_by_an_earlier_stop_go_once_stale() {
    let dir = std::env::temp_dir().join(format!("pw-left-locks-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let git = dir.join(".git");
    let origin = git.join("refs/remotes/origin");
    fs::create_dir_all(&origin).unwrap();
    let old = std::time::SystemTime::now() - GIT_IDLE - Duration::from_secs(60);
    let (index, reflock, fresh) = (
        git.join("index.lock"),
        origin.join("main.lock"),
        origin.join("other.lock"),
    );
    for f in [&index, &reflock, &fresh] {
        let file = fs::File::create(f).unwrap();
        if *f != fresh {
            file.set_modified(old).unwrap();
        }
    }
    let store = git_store(&dir);
    // No history lock held here: nothing is touched.
    assert_eq!(remove_left_locks(&dir), 0);
    assert!(index.exists());
    let lock = store.lock().unwrap();
    // A git of this process still running there: kept.
    {
        let _running = RunningGit::new(&dir);
        assert_eq!(remove_left_locks(&dir), 0);
        assert!(index.exists() && reflock.exists());
    }
    // A process an earlier stop recorded as still running (here this
    // one): kept, whichever Pathwarden asks.
    let me = std::process::id();
    let my_start = match crate::proc_tree::holder(me) {
        crate::proc_tree::Holder::Running {
            started: Some(s), ..
        } => s,
        _ => std::time::SystemTime::now(),
    };
    record_survivors(&git, &[(me, my_start)]);
    assert_eq!(read_survivors(&git).len(), 1, "recorded while it runs");
    assert_eq!(remove_left_locks(&dir), 0);
    assert!(index.exists() && reflock.exists());
    // Once every recorded process has stopped, the record goes too.
    let mut cmd = crate::spawn::quiet(if cfg!(windows) { "cmd" } else { "true" });
    if cfg!(windows) {
        cmd.args(["/c", "exit"]);
    }
    let mut gone = cmd.spawn().unwrap();
    let gone_pid = gone.id();
    gone.wait().unwrap();
    drop(gone);
    fs::write(
        git.join(SURVIVORS_FILE),
        format!("pid {gone_pid} created 1\n"),
    )
    .unwrap();
    assert_eq!(remove_left_locks(&dir), 2);
    assert!(!git.join(SURVIVORS_FILE).exists());
    assert!(!index.exists() && !reflock.exists());
    assert!(fresh.exists(), "younger than the idle limit");
    drop(lock);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn kept_locks_are_named_with_what_to_do() {
    assert_eq!(kept_locks_words(&[]), "");
    let one = kept_locks_words(&[PathBuf::from("w/.git/index.lock")]);
    assert!(one.contains("this git lock file was kept:"), "{one}");
    assert!(one.contains("index.lock. It is safe to remove"), "{one}");
    assert!(one.ends_with("once no git is running there."), "{one}");
    let two = kept_locks_words(&[
        PathBuf::from("w/.git/index.lock"),
        PathBuf::from("w/.git/HEAD.lock"),
    ]);
    assert!(two.contains("index.lock, w"), "{two}");
    assert!(two.contains("They are safe to remove"), "{two}");
}

/// Lines of `.git/info/exclude` compare as git reads them: a leading
/// space is part of the pattern, trailing ones are not.
#[test]
fn exclude_lines_compare_as_git_reads_them() {
    assert_eq!(git_pattern("/.pathwarden.lock"), "/.pathwarden.lock");
    assert_eq!(git_pattern("/.pathwarden.lock   "), "/.pathwarden.lock");
    assert_eq!(git_pattern("  /.pathwarden.lock"), "  /.pathwarden.lock");
    assert_eq!(git_pattern("/a\\  "), "/a\\ ");

    let dir = std::env::temp_dir().join(format!("pw-exclude-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let info = dir.join(".git/info");
    fs::create_dir_all(&info).unwrap();
    // A byte order mark before the first line, as Notepad may write.
    let mine = format!("\u{feff}/{TAKING_FILE}\r\n  /{LOCK_FILE}\r\n/{CLONING_DIR}  \r\n");
    fs::write(info.join("exclude"), &mine).unwrap();
    git_store(&dir).exclude_own_files().unwrap();
    let text = fs::read_to_string(info.join("exclude")).unwrap();
    assert!(text.starts_with(&mine), "the user's lines stay: {text:?}");
    let added: Vec<&str> = text[mine.len()..].lines().collect();
    assert!(
        added.contains(&format!("/{LOCK_FILE}").as_str()),
        "{text:?}"
    );
    for present in [CLONING_DIR, TAKING_FILE] {
        assert!(
            !added.contains(&format!("/{present}").as_str()),
            "present already: {text:?}"
        );
    }
    // Once listed, nothing more is added.
    git_store(&dir).exclude_own_files().unwrap();
    assert_eq!(fs::read_to_string(info.join("exclude")).unwrap(), text);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn git_messages_leave_progress_out() {
    let err = b"Enumerating objects: 5, done.\nCounting objects:  20% (1/5)\rCounting objects: 100% (5/5), done.\nremote: Resolving deltas: 100% (1/1)\nTo C:/x.git\n ! [remote rejected] main -> main (pre-receive hook declined)\nerror: failed to push some refs\n";
    assert_eq!(
            git_message(err),
            "To C:/x.git\n! [remote rejected] main -> main (pre-receive hook declined)\nerror: failed to push some refs"
        );
}

/// A scheduled task may write only inside its state folder, not next to
/// it (the folder above holds the programs it runs).
#[test]
fn a_local_lock_stays_inside_the_state_folder() {
    let dir = std::env::temp_dir().join(format!("pw-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let state = dir.join("pathwarden-state");
    let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    assert_eq!(store.lock_path(), state.join(LOCK_FILE));
    let lock = store.lock().unwrap();
    assert!(state.join(LOCK_FILE).exists());
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        1,
        "nothing beside the state folder"
    );
    assert!(store.lock().is_err(), "a second run is refused");
    drop(lock);
    assert!(!state.join(LOCK_FILE).exists(), "released");
    fs::remove_dir_all(&dir).ok();
}

/// Run by [`Store::lock`] just after it made the lock file of `path`,
/// before it returns the lock: what a test set for that path.
type AfterCreate = Option<(PathBuf, Box<dyn FnOnce() + Send>)>;
static AFTER_CREATE: std::sync::Mutex<AfterCreate> = std::sync::Mutex::new(None);

pub(super) fn after_create(path: &Path) {
    let f = {
        let mut g = AFTER_CREATE.lock().unwrap_or_else(|e| e.into_inner());
        match g.take() {
            Some((p, f)) if p == path => Some(f),
            other => {
                *g = other;
                None
            }
        }
    };
    if let Some(f) = f {
        f();
    }
}

/// Another task of this process that finds the lock file in the moment
/// between its making and the lock being returned sees it held here:
/// it never takes it over as left.
#[test]
fn a_lock_being_taken_is_held_here_already() {
    let dir = std::env::temp_dir().join(format!("pw-taking-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let state = dir.join("pathwarden-state");
    fs::create_dir_all(&state).unwrap();
    let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (state2, ran2) = (state.clone(), ran.clone());
    *AFTER_CREATE.lock().unwrap() = Some((
        store.lock_path(),
        Box::new(move || {
            let other = Store::new(&StateConfig::default(), Some(&state2)).unwrap();
            let e = std::thread::spawn(move || other.lock().map(drop))
                .join()
                .unwrap()
                .expect_err("the lock is being taken");
            let e = format!("{e:#}");
            assert!(e.contains(HELD_HERE), "{e}");
            ran2.store(true, std::sync::atomic::Ordering::SeqCst);
        }),
    ));
    let lock = store.lock().unwrap();
    assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
    assert!(fs::read_to_string(store.lock_path())
        .unwrap()
        .contains(&lock.token));
    drop(lock);
    fs::remove_dir_all(&dir).ok();
}

/// A take-over guard a stopped run left is old, or dated in the
/// future; a fresh one isn't, nor one that isn't there.
#[test]
fn a_left_take_over_guard_is_old_or_from_the_future() {
    let dir = std::env::temp_dir().join(format!("pw-guard-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let guard = dir.join(TAKING_FILE);
    assert!(!guard_left(&guard));
    let f = fs::File::create(&guard).unwrap();
    assert!(!guard_left(&guard), "fresh");
    let now = std::time::SystemTime::now();
    f.set_modified(now - Duration::from_secs(120)).unwrap();
    assert!(guard_left(&guard), "old");
    f.set_modified(now + Duration::from_secs(3600)).unwrap();
    assert!(guard_left(&guard), "from the future");
    drop(f);
    // A left one doesn't keep a take-over out.
    let state = dir.join("state");
    fs::create_dir_all(&state).unwrap();
    let g = fs::File::create(state.join(TAKING_FILE)).unwrap();
    g.set_modified(now + Duration::from_secs(3600)).unwrap();
    drop(g);
    fs::write(
        state.join(LOCK_FILE),
        format!("host {} pid {} token gone\n", this_host(), stopped_pid()),
    )
    .unwrap();
    let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    drop(store.lock().unwrap());
    assert!(!state.join(TAKING_FILE).exists());
    fs::remove_dir_all(&dir).ok();
}

/// Runs taking over the same left lock at once: one gets it.
#[test]
fn one_run_takes_over_a_left_lock() {
    let dir = std::env::temp_dir().join(format!("pw-race-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let state = dir.join("pathwarden-state");
    fs::create_dir_all(&state).unwrap();
    let left = format!("host {} pid {} token gone\n", this_host(), stopped_pid());
    for _ in 0..5 {
        fs::write(state.join(LOCK_FILE), &left).unwrap();
        let n = 8;
        let gate = std::sync::Barrier::new(n);
        let done = std::sync::Barrier::new(n);
        let got = std::thread::scope(|s| {
            let handles: Vec<_> = (0..n)
                .map(|_| {
                    s.spawn(|| {
                        let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
                        gate.wait();
                        let l = store.lock();
                        done.wait();
                        l.is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(got, 1);
        assert!(!state.join(LOCK_FILE).exists(), "released");
        let others: Vec<_> = fs::read_dir(&state).unwrap().flatten().collect();
        assert!(others.is_empty(), "nothing moved aside is left: {others:?}");
    }
    fs::remove_dir_all(&dir).ok();
}

fn holder_of(host: &str, pid: u32, token: &str) -> LockHolder {
    LockHolder::parse(&format!("host {host} pid {pid} token {token}\n"))
}

#[test]
fn lock_files_are_read() {
    assert_eq!(
        LockHolder::parse("host HQ01 pid 43108 token 00ab\n"),
        LockHolder {
            host: Some("HQ01".into()),
            pid: Some(43108),
            token: Some("00ab".into()),
            started: None,
        }
    );
    assert_eq!(
        LockHolder::parse("host HQ01 pid 1 token t started 1800000000").started,
        Some(1_800_000_000)
    );
    assert_eq!(LockHolder::parse("x"), LockHolder::default());
    assert_eq!(LockHolder::parse("host a pid nope").pid, None);
}

/// A lock this computer's stopped Pathwarden left is taken over at
/// once; one of another computer, or of a Pathwarden still running
/// here, is not; one naming this process is never another run's.
#[test]
fn whose_lock_it_is() {
    use crate::proc_tree::Holder;
    let here = this_host();
    let fresh = Duration::from_secs(60);
    let then = std::time::SystemTime::now() - Duration::from_secs(3600);
    let running = |program: &str, started: std::time::SystemTime| {
        let program = program.to_string();
        move |_| Holder::Running {
            program: program.clone(),
            started: Some(started),
        }
    };
    let never = |_| -> Holder { panic!("another computer's process isn't looked up") };
    // Another computer's: held until stale.
    let other = holder_of("SOMEWHERE-ELSE", 4, "t");
    assert_eq!(
        lock_verdict(&other, fresh, never),
        LockVerdict::HeldElsewhere
    );
    assert_eq!(
        lock_verdict(&other, STALE_LOCK + fresh, never),
        LockVerdict::Left
    );
    // This computer's, its process stopped: at once.
    let mine = holder_of(&here.to_ascii_lowercase(), 43108, "t");
    assert_eq!(
        lock_verdict(&mine, fresh, |_| Holder::Gone),
        LockVerdict::Left
    );
    // Its ID now another program's.
    assert_eq!(
        lock_verdict(&mine, fresh, running("notepad.exe", then)),
        LockVerdict::Left
    );
    // A Pathwarden running: held, unless the lock says it was written
    // by a process that started at another time (the ID used again).
    assert_eq!(
        lock_verdict(&mine, fresh, running("Pathwarden.exe", then)),
        LockVerdict::HeldElsewhere
    );
    let wrote = LockHolder {
        started: unix_secs(then),
        ..holder_of(&here, 43108, "t")
    };
    assert_eq!(
        lock_verdict(&wrote, fresh, running("pathwarden.exe", then)),
        LockVerdict::HeldElsewhere
    );
    assert_eq!(
        lock_verdict(
            &wrote,
            fresh,
            running("pathwarden.exe", then + Duration::from_secs(600))
        ),
        LockVerdict::Left
    );
    // Can't be told: held.
    assert_eq!(
        lock_verdict(&mine, fresh, |_| Holder::Unknown),
        LockVerdict::HeldElsewhere
    );
    // This process: held here while one of its locks has the token,
    // else nothing holds it.
    let me = std::process::id();
    assert_eq!(
        lock_verdict(&holder_of(&here, me, "not-held"), fresh, never),
        LockVerdict::Left
    );
    held_here().insert("held-token".into());
    assert_eq!(
        lock_verdict(&holder_of(&here, me, "held-token"), fresh, never),
        LockVerdict::HeldHere
    );
    held_here().remove("held-token");
    assert!(is_pathwarden("pathwarden.exe"));
    assert!(is_pathwarden("Pathwarden Desktop.exe"));
    assert!(!is_pathwarden("git.exe"));
}

/// A stopped process's ID, which nothing may hold now.
fn stopped_pid() -> u32 {
    let mut cmd = crate::spawn::quiet(if cfg!(windows) { "cmd" } else { "true" });
    if cfg!(windows) {
        cmd.args(["/c", "exit"]);
    }
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

/// The lock files a stopped Pathwarden of this computer leaves, and the
/// one a lock this process failed to remove leaves, are taken over at
/// once; a lock another task of this process holds is waited for, and
/// never called another run's.
#[test]
fn this_computer_s_left_locks_are_taken_over_at_once() {
    let dir = std::env::temp_dir().join(format!("pw-left-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let state = dir.join("pathwarden-state");
    let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    fs::create_dir_all(&state).unwrap();
    let here = this_host();
    for left in [
        format!("host {here} pid {} token gone\n", stopped_pid()),
        format!("host {here} pid {} token nobody\n", std::process::id()),
    ] {
        fs::write(store.lock_path(), &left).unwrap();
        let lock = store.lock().unwrap_or_else(|e| panic!("{left}: {e:#}"));
        let now = fs::read_to_string(store.lock_path()).unwrap();
        assert!(!now.contains(&left), "{now}");
        // When it started, so a later process with its ID is told apart.
        if cfg!(windows) {
            assert!(now.contains(" started "), "{now}");
        }
        drop(lock);
        assert!(!store.lock_path().exists());
    }
    // A program that isn't Pathwarden, running under the ID.
    let mut cmd = crate::spawn::quiet(if cfg!(windows) { "ping" } else { "sleep" });
    if cfg!(windows) {
        cmd.args(["-n", "30", "127.0.0.1"]);
    } else {
        cmd.arg("30");
    }
    cmd.stdout(std::process::Stdio::null());
    let mut other = cmd.spawn().unwrap();
    fs::write(
        store.lock_path(),
        format!("host {here} pid {} token ping\n", other.id()),
    )
    .unwrap();
    let taken = store.lock();
    let _ = other.kill();
    let _ = other.wait();
    drop(taken.unwrap());

    // Held by another task here (the app's pull, say): waited for, and
    // said so.
    let lock = store.lock().unwrap();
    let other = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    let e = std::thread::scope(|s| s.spawn(|| other.lock().err()).join().unwrap()).expect("held");
    let e = format!("{e:#}");
    assert!(e.contains(HELD_HERE), "{e}");
    assert!(!e.contains("another pathwarden run"), "{e}");
    let waited = std::thread::scope(|s| {
        let t = s.spawn(|| other.lock_waiting(Duration::from_secs(20)).map(|_| ()));
        std::thread::sleep(Duration::from_millis(600));
        drop(lock);
        t.join().unwrap()
    });
    waited.unwrap();
    // Another computer's fresh lock still holds.
    fs::write(store.lock_path(), "host SOMEWHERE-ELSE pid 1 token x\n").unwrap();
    let e = format!("{:#}", store.lock().err().unwrap());
    assert!(e.contains("another pathwarden run is using"), "{e}");
    fs::remove_dir_all(&dir).ok();
}

/// Run by [`a_running_pathwarden_s_lock_holds`] as the other Pathwarden.
#[test]
#[ignore = "a helper process"]
fn a_pathwarden_that_keeps_running() {
    if std::env::var_os("PW_LOCK_HOLDER").is_some() {
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// A lock of another Pathwarden running on this computer holds.
#[test]
fn a_running_pathwarden_s_lock_holds() {
    let dir = std::env::temp_dir().join(format!("pw-live-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let state = dir.join("pathwarden-state");
    fs::create_dir_all(&state).unwrap();
    let store = Store::new(&StateConfig::default(), Some(&state)).unwrap();
    let mut cmd = crate::spawn::quiet(std::env::current_exe().unwrap());
    cmd.args([
        "--ignored",
        "--exact",
        "store::tests::a_pathwarden_that_keeps_running",
    ])
    .env("PW_LOCK_HOLDER", "1")
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());
    let mut other = cmd.spawn().unwrap();
    // Made after it started.
    std::thread::sleep(Duration::from_millis(1500));
    fs::write(
        store.lock_path(),
        format!("host {} pid {} token other\n", this_host(), other.id()),
    )
    .unwrap();
    let held = store.lock().err();
    // The same ID, written by a process that started long before: not
    // this one's, so taken over.
    fs::write(
        store.lock_path(),
        format!(
            "host {} pid {} token older started 1000000000\n",
            this_host(),
            other.id()
        ),
    )
    .unwrap();
    let reused = store.lock().map(drop);
    let _ = other.kill();
    let _ = other.wait();
    let e = format!("{:#}", held.expect("held by the other Pathwarden"));
    assert!(e.contains("another pathwarden run is using"), "{e}");
    if cfg!(windows) {
        reused.unwrap();
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn atomic_write_replaces_and_leaves_no_temp_files() {
    let dir = std::env::temp_dir().join(format!("pw-atomic-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let path = dir.join("findings.json");
    write_atomic(&path, b"{\"a\": 1}").unwrap();
    write_atomic(&path, b"{\"a\": 2}").unwrap();
    assert!(fs::read_to_string(&path).unwrap().contains('2'));
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(&dir).ok();
}

/// The marker and kept-commit checks answer from what `.git`'s files
/// say only when they say it for sure: a branch's loose ref or packed
/// line, or "unborn" when neither file is there. A detached HEAD, the
/// reftable format, a ref that can't be read or a packed-refs without
/// the branch: no answer, so git is asked (and nothing is kept).
#[test]
fn refs_are_read_from_files_only_when_they_say_for_sure() {
    let dir = std::env::temp_dir().join(format!("pw-refs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let git = dir.join(".git");
    let id = "0123456789abcdef0123456789abcdef01234567";
    let fresh = || {
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(git.join("refs").join("heads")).unwrap();
        fs::write(git.join("config"), "[core]\n\tbare = false\n").unwrap();
        fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    };
    // A branch with no commit yet, then with one, loose or packed.
    fresh();
    assert_eq!(head_commit(&dir).as_deref(), Some("unborn refs/heads/main"));
    fs::write(git.join("refs/heads/main"), format!("{id}\n")).unwrap();
    assert_eq!(head_commit(&dir).as_deref(), Some(id));
    fs::remove_file(git.join("refs/heads/main")).unwrap();
    fs::write(
        git.join("packed-refs"),
        format!("# pack-refs\n{id} refs/heads/main\n"),
    )
    .unwrap();
    assert_eq!(head_commit(&dir).as_deref(), Some(id));
    // packed-refs without the branch: not "unborn".
    fs::write(git.join("packed-refs"), format!("{id} refs/heads/other\n")).unwrap();
    assert_eq!(head_commit(&dir), None);
    // Detached.
    fresh();
    fs::write(git.join("HEAD"), format!("{id}\n")).unwrap();
    assert_eq!(head_commit(&dir), None);
    // Reftable: its stub HEAD, its folder, or the config's extension.
    fresh();
    fs::write(git.join("HEAD"), "ref: refs/heads/.invalid\n").unwrap();
    assert_eq!(head_commit(&dir), None);
    fresh();
    fs::create_dir_all(git.join("reftable")).unwrap();
    assert_eq!(head_commit(&dir), None);
    fresh();
    fs::write(
        git.join("config"),
        "[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefStorage = reftable\n",
    )
    .unwrap();
    assert_eq!(head_commit(&dir), None);
    // A ref that can't be read (here a folder where the file goes).
    fresh();
    fs::create_dir_all(git.join("refs/heads/main")).unwrap();
    assert_eq!(head_commit(&dir), None);
    // `.git` a file (a linked work tree).
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(&git, "gitdir: elsewhere\n").unwrap();
    assert_eq!(head_commit(&dir), None);
    let _ = fs::remove_dir_all(&dir);
}

/// With a reftable repository (when this git makes them) and a
/// detached HEAD, the encryption-marker check asks git every time and
/// keeps nothing.
#[test]
fn the_marker_check_keeps_nothing_it_cant_key() {
    if crate::spawn::quiet("git")
        .arg("--version")
        .output()
        .is_err()
    {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    let base = std::env::temp_dir().join(format!("pw-marker-cache-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let kept = |dir: &Path| removed_by_cache().contains_key(dir);
    let commit = |dir: &Path| {
        fs::write(dir.join("x.txt"), "x").unwrap();
        run_git(Some(dir), &["add", "x.txt"]).unwrap();
        run_git(
            Some(dir),
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "-m",
                "x",
            ],
        )
        .unwrap();
    };
    // Reftable, if this git can.
    let table = base.join("table");
    fs::create_dir_all(&table).unwrap();
    if run_git(Some(&table), &["init", "-q", "--ref-format=reftable"]).is_ok() {
        commit(&table);
        assert_eq!(head_commit(&table), None);
        let before = git_runs();
        assert_eq!(marker_removed_by(&table).unwrap(), None);
        assert_eq!(marker_removed_by(&table).unwrap(), None);
        assert!(git_runs() >= before + 2, "asked git each time");
        assert!(!kept(&table));
    }
    // Plain refs: kept by HEAD's commit; detached: never.
    let plain = base.join("plain");
    fs::create_dir_all(&plain).unwrap();
    run_git(Some(&plain), &["init", "-q"]).unwrap();
    commit(&plain);
    assert_eq!(marker_removed_by(&plain).unwrap(), None);
    assert!(kept(&plain));
    // Answered from what was kept (other tests run git at the same
    // time, so the count can't tell): a marked answer comes back.
    let head = head_commit(&plain).expect("a branch's commit");
    removed_by_cache().insert(plain.clone(), (head.clone(), Some("kept".into())));
    assert_eq!(marker_removed_by(&plain).unwrap().as_deref(), Some("kept"));
    assert_eq!(
        removed_by_cache().get(&plain),
        Some(&(head, Some("kept".to_string())))
    );
    removed_by_cache().remove(&plain);
    run_git(Some(&plain), &["checkout", "-q", "--detach"]).unwrap();
    // Detached: git is asked, and refuses (fails closed).
    assert!(marker_removed_by(&plain).is_err());
    assert!(!kept(&plain));
    let _ = fs::remove_dir_all(&base);
}

/// Every git command runs unable to prompt (gap 15): no terminal
/// prompt, SSH in batch mode, nothing on standard input, Git Credential
/// Manager's window off in work nobody watches; without the variables
/// that point git at another repository, and without the passphrase.
#[test]
fn git_never_prompts() {
    let env_of = |cmd: &std::process::Command| -> Vec<(String, Option<String>)> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    };
    let has = |env: &[(String, Option<String>)], k: &str, v: Option<&str>| {
        env.iter().any(|(ek, ev)| ek == k && ev.as_deref() == v)
    };
    let cmd = git_command(Some(Path::new("C:/contoso")), &["fetch"], &[]);
    let env = env_of(&cmd);
    assert!(has(&env, "GIT_TERMINAL_PROMPT", Some("0")), "{env:?}");
    if std::env::var_os("GIT_SSH_COMMAND").is_none() && std::env::var_os("GIT_SSH").is_none() {
        assert!(
            has(&env, "GIT_SSH_COMMAND", Some("ssh -o BatchMode=yes")),
            "{env:?}"
        );
    }
    for var in GIT_LOCAL_ENV
        .iter()
        .chain(&[keystore::ENV_VAR, keystore::NEW_ENV_VAR])
    {
        assert!(has(&env, var, None), "{var} is not removed: {env:?}");
    }
    assert!(!env.iter().any(|(k, _)| k == "GCM_INTERACTIVE"), "{env:?}");
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(
        args.contains(&"core.symlinks=false".to_string()),
        "{args:?}"
    );
    assert_eq!(args.last().map(String::as_str), Some("fetch"));
    let env = non_interactive(|| env_of(&git_command(None, &["fetch"], &[])));
    assert!(has(&env, "GCM_INTERACTIVE", Some("never")), "{env:?}");
    // Back as it was after the background work.
    let env = env_of(&git_command(None, &["fetch"], &[]));
    assert!(!env.iter().any(|(k, _)| k == "GCM_INTERACTIVE"), "{env:?}");
    // And git really gets nothing to read a password from.
    if run_git(None, &["--version"]).is_ok() {
        let dir = std::env::temp_dir().join(format!("pw-noprompt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let e = run_git(
            Some(&dir),
            &["ls-remote", "https://127.0.0.1:9/contoso/state.git"],
        );
        assert!(e.is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}

/// A held lock's time is renewed while its run goes on (gap 22),
/// so a run longer than [`STALE_LOCK`] keeps it; a lock another run
/// took over is left alone, and renewing stops with the lock.
#[test]
fn a_held_lock_is_kept_fresh() {
    let dir = std::env::temp_dir().join(format!("pw-renew-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("lock");
    fs::write(&path, "host H pid 1 token mine").unwrap();
    let old = std::time::SystemTime::now() - STALE_LOCK - Duration::from_secs(60);
    let age = |p: &Path| {
        fs::metadata(p)
            .unwrap()
            .modified()
            .unwrap()
            .elapsed()
            .unwrap_or_default()
    };
    let set_old = |p: &Path| {
        fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(old)
            .unwrap()
    };
    set_old(&path);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let p = path.clone();
    let worker = std::thread::spawn(move || renew_lock(&p, "mine", &rx, Duration::from_millis(20)));
    let start = std::time::Instant::now();
    while age(&path) > STALE_LOCK {
        assert!(start.elapsed() < Duration::from_secs(10), "never renewed");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(age(&path) < Duration::from_secs(60));
    // Taken over by another run: its time is not this run's to renew.
    fs::write(&path, "host H pid 2 token theirs").unwrap();
    // (A renewal that read the file before it was replaced is done.)
    std::thread::sleep(Duration::from_millis(50));
    set_old(&path);
    std::thread::sleep(Duration::from_millis(150));
    assert!(age(&path) > STALE_LOCK);
    // Dropping the lock's sender stops the renewing.
    drop(tx);
    worker.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// A history's `.gitattributes` may set line endings and "binary"
/// only (gap 15).
#[test]
fn only_line_ending_attributes_are_allowed() {
    for ok in [
        "",
        "# comment\n\n* text=auto\n",
        "* text=auto eol=lf\n*.age binary\n*.json -diff -merge !filter\n",
        "*.txt text eol=crlf\n*.sln merge=union\n\"a b\" -text\n",
    ] {
        assert_eq!(unsafe_attribute(ok), None, "{ok}");
    }
    for (bad, attr) in [
        ("*.json filter=lfs\n", "filter=lfs"),
        ("* text\n*.json diff=contoso\n", "diff=contoso"),
        ("*.json merge=fabrikam\n", "merge=fabrikam"),
        ("*.json ident\n", "ident"),
        (
            "*.json working-tree-encoding=UTF-16\n",
            "working-tree-encoding=UTF-16",
        ),
        ("\"a \\\" b\" filter=x\n", "filter=x"),
        ("*.json text=crlf\n", "text=crlf"),
        ("*.json -diff=x\n", "-diff=x"),
    ] {
        assert_eq!(unsafe_attribute(bad).as_deref(), Some(attr), "{bad}");
    }
    assert!(unsafe_attribute("[attr]plain filter=x\n").is_some());
    assert!(unsafe_attribute("\"unclosed filter=x\n").is_some());
}

/// A repository URL with a password or token is refused, as the app
/// refuses it (gap 15); a user name alone is fine.
#[test]
fn a_remote_with_a_password_or_token_is_refused() {
    let dir = std::env::temp_dir().join(format!("pw-token-url-{}", std::process::id()));
    let new = |remote: &str| {
        Store::new(
            &StateConfig {
                backend: StateBackend::Git,
                remote: Some(remote.into()),
                ..StateConfig::default()
            },
            Some(&dir),
        )
    };
    for bad in [
        "https://someone:secret@git.contoso.com/state.git",
        "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@git.contoso.com/state.git",
        "https://abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP@dev.azure.com/x",
    ] {
        let e = format!("{:#}", new(bad).err().expect(bad));
        assert!(e.contains("password or token"), "{e}");
        assert!(!e.contains("secret") && !e.contains("ghp_"), "{e}");
    }
    for ok in [
        "https://git.contoso.com/state.git",
        "https://contoso@dev.azure.com/contoso/p/_git/state",
        "git@git.contoso.com:team/state.git",
        "C:/contoso/state.git",
    ] {
        new(ok).expect(ok);
    }
}

/// The history's findings state, latest run, points and timings are
/// read only up to their caps (gap 9): a point too large is
/// skipped and named, a findings state too large counts as damaged.
#[test]
fn history_files_have_size_caps() {
    let dir = std::env::temp_dir().join(format!("pw-caps-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("history")).unwrap();
    fs::create_dir_all(dir.join("timings")).unwrap();
    let big = |rel: &str, plain: u64| {
        let f = fs::File::create(dir.join(rel)).unwrap();
        f.set_len(max_on_disk(plain) + 1).unwrap();
    };
    let store = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
    // Not written: a GiB on disk for a test.
    assert_eq!(max_state_bytes("findings.json"), Some(1 << 30));
    assert_eq!(max_state_bytes(crate::exposed::FILE), None);
    big("last-run.json", 64 << 20);
    let e = format!("{:#}", store.read_state_file("last-run.json").unwrap_err());
    assert!(e.contains("larger than 64 MiB"), "{e}");
    assert!(last_run(&store).is_none());
    let id = "20261018T120000.000Z";
    big(&format!("history/{id}.json"), 16 << 20);
    let (points, skipped) = crate::history::load(&dir).unwrap();
    assert!(points.is_empty());
    assert!(skipped.iter().any(|s| s.contains(id)), "{skipped:?}");
    big(&format!("timings/{id}.json"), 16 << 20);
    assert!(run_timings(&dir, id).is_none());
    // A findings state that isn't one counts as damaged: a run starts
    // afresh, with a note.
    fs::write(dir.join("findings.json"), "not json").unwrap();
    let e = store.load().unwrap_err();
    assert!(e.downcast_ref::<DamagedFindings>().is_some(), "{e:#}");
    assert!(format!("{e:#}").contains("can't be read"), "{e:#}");
    let (state, note) = store.load_for_run().unwrap();
    assert!(state.findings.is_empty());
    let note = note.unwrap();
    assert!(note.contains("no earlier findings"), "{note}");
    assert!(!note.contains("earlier commits"), "a folder: {note}");
    let _ = fs::remove_dir_all(&dir);
}

thread_local! {
    /// Run by [`Store::rewrite`] once it has staged every file, before
    /// it takes the pending lock: what a test of this thread set.
    static DURING_REWRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn during_rewrite() {
    if let Some(f) = DURING_REWRITE.with(|h| h.borrow_mut().take()) {
        f();
    }
}

/// A rewrite that runs past the pending lock's stale age (here: an age
/// of nothing, as if 30 seconds went by) keeps a save another process
/// made meanwhile: it is sealed again with the new key, not lost.
#[test]
fn a_save_made_during_a_long_rewrite_is_kept() {
    use crate::action_log::{self, Activity, Change};
    let dir = std::env::temp_dir().join(format!("pw-rewrite-pending-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let work = dir.join("work");
    fs::create_dir_all(&work).unwrap();
    if run_git(Some(&work), &["init", "-q"]).is_err() {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    crate::keystore::use_test_store(&dir.join("ks"));
    let store = git_store(&work);
    store.write_state_file("last-run.json", b"{}").unwrap();
    let first = crypt::SecretString::from("first passphrase here".to_string());
    let second = crypt::SecretString::from("second passphrase here".to_string());
    store.rewrite(Some(&first)).unwrap();
    crypt::give_passphrase(&work, first);
    let change = |at: &str| Change {
        fingerprint: "PW-001-aaaa".into(),
        activity: Activity {
            at: at.into(),
            action: "service-desk/open".into(),
            ..Activity::default()
        },
        records: Vec::new(),
        removed: Vec::new(),
    };
    action_log::add_pending(&store, &change("2026-11-18T14:00:00.000Z")).unwrap();
    assert_eq!(action_log::pending_count(&store), 1);
    let other = git_store(&work);
    DURING_REWRITE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            action_log::TEST_STALE_AFTER.with(|s| s.set(Some(std::time::Duration::ZERO)));
            action_log::add_pending(&other, &change("2026-11-18T15:00:00.000Z")).unwrap();
            action_log::TEST_STALE_AFTER.with(|s| s.set(None));
        }))
    });
    store.rewrite(Some(&second)).unwrap();
    assert!(
        DURING_REWRITE.with(|h| h.borrow().is_none()),
        "the hook ran"
    );
    crypt::give_passphrase(&work, second);
    let bytes = fs::read(work.join(".git").join(action_log::PENDING_FILE)).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/"));
    assert_eq!(action_log::pending_count(&store), 2, "both saves kept");
    assert!(!work
        .join(".git")
        .join(format!("{}.lock", action_log::PENDING_FILE))
        .exists());
    let _ = fs::remove_dir_all(&dir);
}

/// The same while decrypting: a save made during the rewrite (sealed
/// with the old key) is kept, and the file ends up plain.
#[test]
fn a_save_made_during_a_long_decrypt_is_kept() {
    use crate::action_log::{self, Activity, Change};
    let dir = std::env::temp_dir().join(format!("pw-decrypt-pending-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let work = dir.join("work");
    fs::create_dir_all(&work).unwrap();
    if run_git(Some(&work), &["init", "-q"]).is_err() {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        return;
    }
    crate::keystore::use_test_store(&dir.join("ks"));
    let store = git_store(&work);
    store.write_state_file("last-run.json", b"{}").unwrap();
    let first = crypt::SecretString::from("first passphrase here".to_string());
    store.rewrite(Some(&first)).unwrap();
    crypt::give_passphrase(&work, first);
    let change = |at: &str| Change {
        fingerprint: "PW-001-aaaa".into(),
        activity: Activity {
            at: at.into(),
            action: "service-desk/open".into(),
            ..Activity::default()
        },
        records: Vec::new(),
        removed: Vec::new(),
    };
    action_log::add_pending(&store, &change("2026-11-18T14:00:00.000Z")).unwrap();
    let pending = work.join(".git").join(action_log::PENDING_FILE);
    assert!(fs::read(&pending)
        .unwrap()
        .starts_with(b"age-encryption.org/"));
    let other = git_store(&work);
    DURING_REWRITE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            action_log::TEST_STALE_AFTER.with(|s| s.set(Some(std::time::Duration::ZERO)));
            action_log::add_pending(&other, &change("2026-11-18T15:00:00.000Z")).unwrap();
            action_log::TEST_STALE_AFTER.with(|s| s.set(None));
        }))
    });
    store.rewrite(None).unwrap();
    assert!(
        DURING_REWRITE.with(|h| h.borrow().is_none()),
        "the hook ran"
    );
    assert!(!crypt::is_encrypted(&work));
    let bytes = fs::read(&pending).unwrap();
    assert!(bytes.starts_with(b"{"), "plain");
    assert_eq!(action_log::pending_count(&store), 2, "both saves kept");
    let _ = fs::remove_dir_all(&dir);
}
