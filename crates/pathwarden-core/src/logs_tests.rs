use super::*;

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    let d = std::env::temp_dir().join(format!("pathwarden-logs-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    Tmp(d)
}

fn set_age(path: &Path, days: i64) {
    let t = std::time::SystemTime::now() - std::time::Duration::from_secs((days * 86_400) as u64);
    let f = OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(t).unwrap();
}

#[test]
fn the_folder_follows_the_workspace_conventions() {
    let win = |n: &str| (n == "LOCALAPPDATA").then(|| r"C:\Users\x\AppData\Local".into());
    if cfg!(windows) {
        assert_eq!(
            dir_from(win, true).unwrap(),
            PathBuf::from(r"C:\Users\x\AppData\Local\Pathwarden\logs")
        );
    }
    let xdg = |n: &str| match n {
        "XDG_STATE_HOME" => Some("/srv/state".into()),
        "HOME" => Some("/home/x".into()),
        _ => None,
    };
    let home = |n: &str| match n {
        "XDG_STATE_HOME" => Some("relative".into()),
        "HOME" => Some("/home/x".into()),
        _ => None,
    };
    if cfg!(unix) {
        assert_eq!(
            dir_from(xdg, false).unwrap(),
            PathBuf::from("/srv/state/pathwarden/logs")
        );
        assert_eq!(
            dir_from(home, false).unwrap(),
            PathBuf::from("/home/x/.local/state/pathwarden/logs")
        );
    }
    assert!(dir_from(|_| None, true).is_none());
    assert!(dir_from(|_| None, false).is_none());
}

#[test]
fn a_job_log_is_stamped_redacted_and_flushed() {
    let t = tmp("job");
    let log = JobLog::open_in(&t.0, Kind::Collect, By::App, "SCALE.LOCAL").unwrap();
    assert!(log.name().starts_with("job-") && log.name().ends_with("-collect.log"));
    assert!(crate::perms::is_private_dir(&t.0), "the folder is private");
    log.line("collector RustHound-CE started");
    log.line("pushing to https://ci:Tk-0123456789@git.example.test/x\nsecond line");
    // Written and flushed while the log is still open.
    let text = fs::read_to_string(log.path()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        format!(
            "# Collection SCALE.LOCAL | app | collect | Pathwarden {}",
            env!("CARGO_PKG_VERSION")
        )
    );
    assert!(lines[1].ends_with("[collect, app] Collection SCALE.LOCAL started in the app"));
    assert!(lines[2].ends_with("[collect, app] collector RustHound-CE started"));
    assert!(!text.contains("Tk-0123456789"), "{text}");
    assert!(lines[4].ends_with("[collect, app] second line"));
    // `HH:MM:SS.mmm`.
    let stamp = &lines[2][..12];
    assert!(
        stamp.as_bytes()[2] == b':' && stamp.as_bytes()[8] == b'.',
        "{stamp}"
    );
    log.end(Outcome::Failed, "the LDAP connection was reset");
    log.end(Outcome::Ok, "");
    log.line("after the end");
    let text = fs::read_to_string(log.path()).unwrap();
    assert!(text
        .lines()
        .last()
        .unwrap()
        .ends_with("result: failed: the LDAP connection was reset"));
    assert!(!text.contains("after the end"));
    assert!(!text.contains("result: ok"));
}

#[test]
fn the_list_says_what_each_file_is() {
    let t = tmp("list");
    let a = JobLog::open_in(&t.0, Kind::Run, By::Schedule, "SCALE.LOCAL").unwrap();
    a.end(Outcome::Ok, "");
    let s = JobLog::open_in(&t.0, Kind::Session, By::App, "1.0").unwrap();
    let c = JobLog::open_in(&t.0, Kind::Collect, By::App, "SCALE.LOCAL").unwrap();
    let crash = Crash {
        message: "index out of bounds".into(),
        location: "src/x.rs:1:2".into(),
        thread: "main".into(),
        backtrace: String::new(),
        system: "Test OS".into(),
        job: Some(JobRef {
            kind: c.kind(),
            by: c.by(),
            subject: "SCALE.LOCAL".into(),
            name: c.name().into(),
            path: c.path().into(),
        }),
    };
    let name = crash.write_in(&t.0).unwrap();
    let all = list(&t.0);
    assert_eq!(all.len(), 4);
    let get = |n: &str| all.iter().find(|e| e.name == n).unwrap();
    let run = get(a.name());
    assert_eq!(
        (run.title.as_str(), run.by.as_str(), run.result.as_str()),
        ("Run SCALE.LOCAL", "schedule", "ok")
    );
    assert_eq!(get(c.name()).result, "crashed");
    assert_eq!(get(s.name()).kind, Some(Kind::Session));
    assert!(get(&name).crash);
    assert_eq!(last_job(&t.0).unwrap().name, c.name());
    let r = last_crash(&t.0).unwrap();
    assert_eq!(r.during, Some(Kind::Collect));
    assert_eq!(r.job_log.as_deref(), Some(c.name()));
    assert_eq!(r.message, "index out of bounds");
    assert!(
        r.line()
            .starts_with("Stopped unexpectedly during a collection, "),
        "{}",
        r.line()
    );
    assert!(
        r.sentence()
            .ends_with(", during a collection of SCALE.LOCAL."),
        "{}",
        r.sentence()
    );
    let text = fs::read_to_string(t.0.join(&name)).unwrap();
    assert!(
        text.contains("Collection SCALE.LOCAL started in the app"),
        "the job's lines: {text}"
    );
}

#[test]
fn a_crash_shows_until_dismissed() {
    let t = tmp("dismiss");
    fs::create_dir_all(&t.0).unwrap();
    assert!(pending_crash(&t.0).is_none());
    dismiss(&t.0).unwrap();
    let c = Crash {
        message: "x".into(),
        location: String::new(),
        thread: "t".into(),
        backtrace: String::new(),
        system: String::new(),
        job: None,
    };
    let first = c.write_in(&t.0).unwrap();
    assert_eq!(pending_crash(&t.0).unwrap().name, first);
    assert!(pending_crash(&t.0)
        .unwrap()
        .line()
        .starts_with("Stopped unexpectedly, "));
    dismiss(&t.0).unwrap();
    assert!(pending_crash(&t.0).is_none());
    let second = c.write_in(&t.0).unwrap();
    assert_eq!(
        pending_crash(&t.0).unwrap().name,
        second,
        "a later crash shows again"
    );
}

#[test]
fn old_and_extra_files_go_and_others_stay() {
    let t = tmp("prune");
    // Opened first: its open prunes the folder once.
    let open = JobLog::open_in(&t.0, Kind::Run, By::App, "").unwrap();
    let old = t.0.join("job-20200101-000000-run.log");
    let mid = t.0.join("job-20200102-000000-run.log");
    let other = t.0.join("notes.txt");
    for p in [&old, &mid, &other] {
        fs::write(p, vec![b'x'; 1000]).unwrap();
    }
    set_age(&old, 31);
    set_age(&mid, 3);
    set_age(&other, 90);
    set_age(open.path(), 40);
    assert_eq!(prune(&t.0, now()), 1);
    assert!(!old.exists() && mid.exists() && other.exists());
    assert!(open.path().exists(), "a log being written is never deleted");
    // Over the size: the oldest goes first.
    let new = t.0.join("job-20200103-000000-run.log");
    fs::write(&new, vec![b'x'; 1000]).unwrap();
    assert_eq!(prune_to(&t.0, now(), KEEP_DAYS, 1500), 1);
    assert!(!mid.exists() && new.exists());
}

#[test]
fn only_its_own_files_open() {
    let t = tmp("open");
    fs::create_dir_all(&t.0).unwrap();
    let good = "crash-20261119-094702.txt";
    fs::write(t.0.join(good), "x").unwrap();
    fs::write(t.0.join("notes.txt"), "x").unwrap();
    assert_eq!(file_in(&t.0, good), Some(t.0.join(good)));
    for bad in [
        "notes.txt",
        "../crash-20261119-094702.txt",
        "..\\crash-20261119-094702.txt",
        "job-20261119-094211-collect.log",
        "crash-20261119-094702.exe",
        "",
    ] {
        assert!(file_in(&t.0, bad).is_none(), "{bad}");
    }
    #[cfg(unix)]
    {
        let link = "job-20261119-094211-collect.log";
        std::os::unix::fs::symlink(t.0.join("notes.txt"), t.0.join(link)).unwrap();
        assert!(file_in(&t.0, link).is_none(), "a link is not opened");
    }
}

#[test]
fn the_bundle_takes_crashes_and_a_week_of_logs() {
    let t = tmp("bundle");
    fs::create_dir_all(&t.0).unwrap();
    let recent = t.0.join("job-20261118-100000-run.log");
    let old = t.0.join("job-20261101-100000-run.log");
    let crash = t.0.join("crash-20261001-100000.txt");
    fs::write(&recent, "recent").unwrap();
    fs::write(&old, "old").unwrap();
    fs::write(&crash, "crash").unwrap();
    set_age(&old, 8);
    set_age(&crash, 20);
    let got = for_bundle(&t.0, now());
    let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["crash-20261001-100000.txt", "job-20261118-100000-run.log"]
    );
}

#[test]
fn action_logs_are_found_by_entry() {
    let t = tmp("actions");
    fs::create_dir_all(&t.0).unwrap();
    let f = "job-20261119-101200-action.log";
    fs::write(t.0.join(f), "x").unwrap();
    note_action(&t.0, "PW-006-5ca8fbd0a56628a3", "2026-11-19T10:12:00Z", f);
    note_action(
        &t.0,
        "PW-006-gone",
        "2026-11-19T10:13:00Z",
        "job-20261119-101300-action.log",
    );
    note_action(&t.0, "PW-bad\tx", "t", f);
    let m = action_logs(&t.0);
    assert_eq!(m.len(), 1);
    assert_eq!(
        m[&(
            "PW-006-5ca8fbd0a56628a3".to_string(),
            "2026-11-19T10:12:00Z".to_string()
        )],
        f
    );
}

#[test]
fn names_and_times() {
    assert!(is_log_name("job-20261119-094211-collect.log"));
    assert!(is_log_name("job-20261119-094211-collect-2.log"));
    assert!(is_log_name("session-20261117-142955.log"));
    assert!(is_log_name("crash-20261119-094702.txt"));
    assert!(!is_log_name("job-2026111-094211-collect.log"));
    assert!(!is_log_name("session-20261117-142955.txt"));
    assert_eq!(
        when_words("job-20261119-094211-collect.log"),
        "Nov 19 09:42"
    );
    assert_eq!(when_page("crash-20261119-094702.txt"), "Nov 19, 9:47 AM");
    assert_eq!(when_page("crash-20261119-004702.txt"), "Nov 19, 12:47 AM");
}

/// The panic hook, in a child process (a panic here would end the test
/// run's other tests): the child opens a job log, then panics; the crash
/// report names the job and holds its last lines, and the job's log points
/// at the report. Nothing in it is a secret.
#[test]
fn a_panic_writes_a_crash_report() {
    if std::env::var_os("PATHWARDEN_PANIC_CHILD").is_some() {
        return panic_child();
    }
    let t = tmp("panic");
    let exe = std::env::current_exe().unwrap();
    let out = crate::spawn::quiet(exe)
        .args([
            "logs::tests::a_panic_writes_a_crash_report",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PATHWARDEN_PANIC_CHILD", "1")
        .env(TEST_DIR_ENV, &t.0)
        .output()
        .unwrap();
    assert!(!out.status.success(), "the child panics");
    let crash = last_crash(&t.0).expect("a crash report");
    assert_eq!(crash.during, Some(Kind::Collect));
    assert_eq!(crash.subject, "SCALE.LOCAL");
    assert!(crash.message.starts_with("boom"), "{crash:?}");
    assert!(crash.location.contains("logs_tests.rs"), "{crash:?}");
    assert_eq!(crash.version, env!("CARGO_PKG_VERSION"));
    assert!(crash.system.starts_with("Test OS"));
    let text = fs::read_to_string(&crash.path).unwrap();
    assert!(text.contains("Backtrace:"), "{text}");
    assert!(
        text.contains("reading ACLs: 61%"),
        "the job log's last lines: {text}"
    );
    assert!(!text.contains("Zq-secret-1234"), "{text}");
    let job = t.0.join(crash.job_log.as_deref().unwrap());
    let log = fs::read_to_string(job).unwrap();
    assert!(
        log.contains(&format!("internal error: see {}", crash.name)),
        "{log}"
    );
    assert_eq!(pending_crash(&t.0).unwrap().name, crash.name);
}

fn panic_child() {
    install_crash_hook("Test OS".into());
    let log = JobLog::open(Kind::Collect, By::App, "SCALE.LOCAL").expect("the test folder");
    let _in = log.enter();
    log.line("reading ACLs: 61%");
    panic!("boom with token=Zq-secret-1234");
}
