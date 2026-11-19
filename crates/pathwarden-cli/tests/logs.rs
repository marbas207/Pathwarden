//! `pathwarden logs`: the latest jobs, the latest job's last lines, the
//! latest crash report and opening them, as the app's Settings › Logs; and
//! a command-line job writing its log. Every test uses its own logs folder
//! (`PATHWARDEN_TEST_LOGS`), never this account's.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pathwarden_core::logs::{By, Crash, JobLog, JobRef, Kind, Outcome};

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    let d = std::env::temp_dir().join(format!("pathwarden-cli-logs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

fn pw(logs: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_pathwarden"));
    c.env("NO_COLOR", "1")
        .env("PATHWARDEN_TEST_LOGS", logs)
        .env_remove("PATHWARDEN_SCHEDULED")
        .env_remove("PATHWARDEN_TEST_OPENED")
        .args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn logs_lists_shows_and_opens() {
    let t = tmp("list");
    let logs = t.0.join("logs");
    let run = JobLog::open_in(&logs, Kind::Run, By::Schedule, "SCALE.LOCAL").unwrap();
    run.end(Outcome::Ok, "");
    let session = JobLog::open_in(&logs, Kind::Session, By::App, "1.0").unwrap();
    session.end(Outcome::Ok, "");
    let collect = JobLog::open_in(&logs, Kind::Collect, By::App, "SCALE.LOCAL").unwrap();
    collect.line("reading ACLs: 61%");
    let crash = Crash {
        message: "index out of bounds".into(),
        location: "crates/x/src/acl.rs:412:31".into(),
        thread: "collect".into(),
        backtrace: String::new(),
        system: "Test OS".into(),
        job: Some(JobRef {
            kind: Kind::Collect,
            by: By::App,
            subject: "SCALE.LOCAL".into(),
            name: collect.name().into(),
            path: collect.path().into(),
        }),
    }
    .write_in(&logs)
    .unwrap();

    let out = ok(&pw(&logs, &["logs"], &[]));
    assert!(
        out.starts_with(&format!("Logs: {}  (4 files, ", logs.display())),
        "{out}"
    );
    assert!(out.contains("kept 30 days, at most 200 MB)"), "{out}");
    assert!(out.contains("When") && out.contains("Started by") && out.contains("Result"));
    let row = |name: &str| {
        out.lines()
            .find(|l| l.ends_with(name))
            .unwrap_or_else(|| panic!("no {name}: {out}"))
            .to_string()
    };
    assert!(row(collect.name()).contains("Collection SCALE.LOCAL"));
    assert!(row(collect.name()).contains(" crashed "), "{out}");
    assert!(row(run.name()).contains(" schedule ") && row(run.name()).contains(" ok "));
    assert!(row(&crash).contains("Pathwarden crashed"));
    assert!(row(session.name()).contains("App session 1.0"));
    assert!(!out.contains("more."), "{out}");

    let out = ok(&pw(&logs, &["logs", "--last"], &[]));
    assert!(
        out.starts_with(&format!(
            "{}  (Collection SCALE.LOCAL, started in the app, crashed)\n",
            collect.name()
        )),
        "{out}"
    );
    assert!(out.contains("[collect, app] reading ACLs: 61%"), "{out}");
    assert!(out.contains(&format!("Full log: {}", collect.path().display())));

    let out = ok(&pw(&logs, &["logs", "--crash"], &[]));
    assert!(out.starts_with(&format!("{crash}  (Pathwarden ")), "{out}");
    assert!(
        out.contains(", during a collection of SCALE.LOCAL."),
        "{out}"
    );
    assert!(out.contains("  Message: index out of bounds"));
    assert!(out.contains("  Where:   crates/x/src/acl.rs:412:31"));
    assert!(out.contains(&format!(
        "  Job log: {} (its last 200 lines are in the report)",
        collect.name()
    )));
    assert!(out.contains("No crash report? A hard crash may only be in "));

    // Opening: the folder, the latest job's log, the crash report.
    let record = t.0.join("opened.txt");
    let rec = [("PATHWARDEN_TEST_OPENED", record.to_str().unwrap())];
    let out = ok(&pw(&logs, &["logs", "--open"], &rec));
    assert_eq!(out.trim(), format!("Opened {}.", logs.display()));
    let out = ok(&pw(&logs, &["logs", "--last", "--open"], &rec));
    assert_eq!(out.trim(), format!("Opened {}.", collect.name()));
    ok(&pw(&logs, &["logs", "--crash", "--open"], &rec));
    let opened = std::fs::read_to_string(&record).unwrap();
    let opened: Vec<&str> = opened.lines().collect();
    assert_eq!(
        opened,
        [
            logs.display().to_string(),
            collect.path().display().to_string(),
            logs.join(&crash).display().to_string()
        ]
    );

    // Six jobs (with a session log and a crash report among them): all
    // shown, as the list counts jobs only.
    for _ in 0..4 {
        JobLog::open_in(
            &logs,
            Kind::Retest,
            By::CommandLine,
            "PW-001-0123456789abcdef",
        )
        .unwrap()
        .end(Outcome::Ok, "");
    }
    let out = ok(&pw(&logs, &["logs"], &[]));
    assert!(!out.contains("more."), "{out}");
    assert!(
        out.contains(run.name()) && out.contains(session.name()),
        "{out}"
    );
    // A seventh: the latest six jobs, then how many more.
    std::thread::sleep(std::time::Duration::from_millis(20));
    JobLog::open_in(
        &logs,
        Kind::Retest,
        By::CommandLine,
        "PW-001-0123456789abcdef",
    )
    .unwrap()
    .end(Outcome::Ok, "");
    let out = ok(&pw(&logs, &["logs"], &[]));
    assert!(
        out.contains("  ... 2 more. All of them: pathwarden logs --all"),
        "{out}"
    );
    assert!(
        !out.contains(run.name()),
        "the oldest job is left out: {out}"
    );
    let all = ok(&pw(&logs, &["logs", "--all"], &[]));
    assert!(!all.contains("more.") && all.contains(run.name()), "{all}");

    // --dismiss: the crash report --crash showed, as Dismiss in the app.
    let out = ok(&pw(&logs, &["logs", "--dismiss"], &[]));
    assert_eq!(out.trim(), format!("Dismissed {crash}."));
    assert!(pathwarden_core::logs::pending_crash(&logs).is_none());
}

#[test]
fn an_empty_folder_says_so() {
    let t = tmp("empty");
    let logs = t.0.join("logs");
    let out = ok(&pw(&logs, &["logs", "--crash"], &[]));
    assert_eq!(
        out.trim(),
        format!("No crash reports. Logs: {}", logs.display())
    );
    let out = ok(&pw(&logs, &["logs"], &[]));
    assert_eq!(out.trim(), format!("No logs yet. Logs: {}", logs.display()));
    assert!(!logs.exists(), "listing makes nothing");
}

/// A command-line job writes its log: the command, and how it ended; a
/// scheduled one says so on every line.
#[test]
fn a_command_line_job_writes_its_log() {
    let t = tmp("job");
    let logs = t.0.join("logs");
    let missing = t.0.join("missing.zip");
    let state = t.0.join("state");
    let args = [
        "run",
        "-i",
        missing.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--no-push",
    ];
    let out = pw(&logs, &args, &[]);
    assert!(!out.status.success());
    let out = pw(&logs, &args, &[("PATHWARDEN_SCHEDULED", "1")]);
    assert!(!out.status.success());
    let names: Vec<String> = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    let mut seen = Vec::new();
    for name in &names {
        assert!(name.ends_with(".log") && name.contains("-run"), "{name}");
        let text = std::fs::read_to_string(logs.join(name)).unwrap();
        let by = if text.contains("| schedule |") {
            "schedule"
        } else {
            "command line"
        };
        seen.push(by);
        assert!(
            text.starts_with(&format!("# Run | {by} | run | Pathwarden ")),
            "{text}"
        );
        assert!(
            text.contains(&format!("[run, {by}] pathwarden run -i ")),
            "{text}"
        );
        let last = text.lines().last().unwrap();
        assert!(
            last.contains(&format!("[run, {by}] result: failed: ")),
            "{text}"
        );
    }
    seen.sort();
    assert_eq!(seen, ["command line", "schedule"]);
}
