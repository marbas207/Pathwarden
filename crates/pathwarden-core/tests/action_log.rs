//! What finding actions did, in the history (`actions.json`): saved at
//! once, merged when two computers save at the same time, refused when a
//! newer Pathwarden wrote it, and left alone by what doesn't know it.
//! Two working copies of one local bare repository stand in for two
//! computers, as in git_state.rs.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::action_log::{self, ActionsFile, Change};
use pathwarden_core::actions::{Ended, Outcome, Record};
use pathwarden_core::analyze::{self, Phase, Progress};
use pathwarden_core::config::{Config, StateBackend, StateConfig};
use pathwarden_core::identity::Actor;
use pathwarden_core::record::{self, RecordProgress};
use pathwarden_core::store::{self, Store};

fn git_command() -> Command {
    let mut c = Command::new("git");
    for v in store::GIT_LOCAL_ENV {
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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-actionlog-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
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

fn git_store(remote: &Path, work: &Path) -> (Store, Config) {
    let state = StateConfig {
        backend: StateBackend::Git,
        remote: Some(remote.to_string_lossy().replace('\\', "/")),
        ..StateConfig::default()
    };
    let config = Config {
        state: state.clone(),
        ..Config::default()
    };
    (Store::new(&state, Some(work)).unwrap(), config)
}

fn remote_log(remote: &Path) -> ActionsFile {
    action_log::parse(git(remote, &["show", "main:actions.json"]).as_bytes()).unwrap()
}

fn who(user: &str) -> Actor {
    Actor {
        user: Some(user.into()),
        computer: Some("WS".into()),
    }
}

/// A run of desk/open on `fp` at `at`, by `user`, that opened `id`.
fn opened(fp: &str, id: &str, at: &str, user: &str) -> Change {
    let outcome = Outcome {
        ok: true,
        message: format!("Opened {id}."),
        links: Vec::new(),
        records: vec![Record {
            id: id.into(),
            number: Some(id.to_uppercase()),
            status: Some("Open".into()),
            open: true,
            ..Record::default()
        }],
        progress: Vec::new(),
        details: String::new(),
        problems: Vec::new(),
        ended: Ended::Exited,
        status: "exit code 0".into(),
        dry_run: false,
    };
    action_log::run_change(
        None,
        fp,
        "desk/open",
        "Open a ticket",
        None,
        &outcome,
        Some("20261118T140200.000Z"),
        &who(user),
        at,
    )
    .unwrap()
}

#[derive(Default)]
struct Quiet(Vec<String>);

impl Progress for Quiet {
    fn phase(&mut self, _: Phase) {}
}

impl RecordProgress for Quiet {
    fn warn(&mut self, message: String) {
        self.0.push(message);
    }
}

/// Two computers save at the same time: the second one's push is refused,
/// so its change is made again on what the first left. Every entry of both
/// survives, on different findings and on the same one.
#[test]
fn two_computers_saving_at_once_keep_both() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    let (b, _) = git_store(&remote, &dir.join("b"));
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    a.pull().unwrap();
    b.pull().unwrap();
    // Both work from the same state now; A pushes first.
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    action_log::save(
        &a,
        &opened("PW-011-bbbb", "t-3", "2026-11-18T15:01:00.000Z", "ned"),
        true,
    )
    .unwrap();
    let notes = action_log::save(
        &b,
        &opened("PW-001-aaaa", "t-4", "2026-11-18T15:00:30.000Z", "arya"),
        true,
    )
    .unwrap();
    action_log::save(
        &b,
        &opened("PW-012-cccc", "t-5", "2026-11-18T15:02:00.000Z", "arya"),
        true,
    )
    .unwrap();
    let log = remote_log(&remote);
    assert_eq!(
        log.findings.keys().collect::<Vec<_>>(),
        ["PW-001-aaaa", "PW-011-bbbb", "PW-012-cccc"],
        "{notes:?}"
    );
    let same = &log.findings["PW-001-aaaa"];
    let ids: Vec<&str> = same.records.iter().map(|r| r.record.id.as_str()).collect();
    assert_eq!(ids, ["t-1", "t-2", "t-4"]);
    let by: Vec<&str> = same
        .activity
        .iter()
        .map(|a| a.by.as_deref().unwrap())
        .collect();
    assert_eq!(by, ["ned", "ned", "arya"], "oldest first");
    // A's working copy gets B's on its next pull.
    a.pull().unwrap();
    assert_eq!(action_log::load(&a).unwrap(), log);
    // The commits name nobody and no finding.
    let messages = git(&remote, &["log", "--format=%s", "main"]);
    assert!(
        messages.lines().all(|m| m == action_log::MESSAGE),
        "{messages}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file a newer Pathwarden saved is neither read nor written over.
#[test]
fn a_newer_file_is_never_written_over() {
    let dir = scratch("newer");
    let state = StateConfig::default();
    let s = Store::new(&state, Some(&dir)).unwrap();
    let newer = b"{\"version\":2,\"findings\":{},\"what\":\"next\"}\n";
    s.write_state_file(action_log::FILE, newer).unwrap();
    let e = action_log::save(
        &s,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap_err();
    assert_eq!(format!("{e:#}"), action_log::NEWER_WORDS);
    assert_eq!(s.read_state_file(action_log::FILE).unwrap().unwrap(), newer);
    assert!(action_log::load(&s).is_err());
    // A folder history: saved at once, nothing to push.
    let dir2 = scratch("folder");
    let s = Store::new(&state, Some(&dir2)).unwrap();
    action_log::save(
        &s,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(
        action_log::load(&s).unwrap().records("PW-001-aaaa").len(),
        1
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// What older releases do with `actions.json`: they commit only the files
/// they know, and clean only files no commit holds, so a file they don't
/// know stays as the repository has it. A file this version doesn't know
/// stands in for it, through a run's recording and an action's save.
#[test]
fn a_file_the_writer_doesnt_know_stays_in_the_history() {
    if !have_git() {
        return;
    }
    let dir = scratch("unknown");
    let remote = bare(&dir);
    let (a, config) = git_store(&remote, &dir.join("a"));
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    // Another release commits a file of its own next to the state.
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
    let text = "{\"version\":1,\"from\":\"a newer release\"}\n";
    std::fs::write(other.join("notes-of-a-newer-release.json"), text).unwrap();
    git(&other, &["add", "notes-of-a-newer-release.json"]);
    git(&other, &["commit", "-q", "-m", "newer"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);

    // A run is recorded here, and an action saved.
    let mut w = Quiet::default();
    a.pull().unwrap();
    let previous = a.load().unwrap();
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let ev = analyze::evaluate(&[forest], &config, &[], &mut w).unwrap();
    let opts = record::Options {
        started_ms: 1_800_000_000_000,
        accept_shrink: false,
        recorded_by: record::by::CLI,
        finished_at: Some(1_800_000_030),
    };
    let prev_run = store::last_run(&a);
    let prep = record::prepare(prev_run.as_ref(), &previous, ev, &config, &opts, &mut w);
    let (prep, saved) = record::save_and_publish(&a, prep, &config, &opts, None, true, &mut w);
    assert!(saved.unwrap().pushed);
    // The run carries what actions did on its findings (none of them
    // here: the action ran on a made-up one).
    assert!(prep.analysis.findings.iter().all(|f| f.actions.is_none()));
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    a.pull().unwrap();
    assert_eq!(
        git(&remote, &["show", "main:notes-of-a-newer-release.json"]),
        text
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("a").join("notes-of-a-newer-release.json")).unwrap(),
        text
    );
    assert_eq!(
        remote_log(&remote).records("PW-001-aaaa").len(),
        2,
        "the actions file stays too"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run's findings carry what actions did on them, from the history: in
/// the event, the report and `findings --json`.
#[test]
fn a_run_carries_what_actions_did() {
    let dir = scratch("carry");
    let state = StateConfig::default();
    let s = Store::new(&state, Some(&dir)).unwrap();
    let config = Config::default();
    let mut w = Quiet::default();
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let ev = analyze::evaluate(&[forest], &config, &[], &mut w).unwrap();
    let fp = ev.findings[0].fingerprint.clone();
    action_log::save(
        &s,
        &opened(&fp, "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    let opts = record::Options {
        started_ms: 1_800_000_000_000,
        accept_shrink: false,
        recorded_by: record::by::CLI,
        finished_at: Some(1_800_000_030),
    };
    let prep = record::prepare(None, &s.load().unwrap(), ev, &config, &opts, &mut w);
    let (prep, saved) = record::save_and_publish(&s, prep, &config, &opts, None, false, &mut w);
    saved.unwrap();
    let f = prep
        .analysis
        .findings
        .iter()
        .find(|f| f.fingerprint == fp)
        .unwrap();
    let a = f.actions.as_ref().expect("the finding carries its record");
    assert_eq!(a.records[0].record.id, "t-1");
    assert_eq!(a.activity_count, 1);
    // The event: on the finding, as `findings --json` has it.
    let event = pathwarden_core::event::build(
        &prep.last,
        &prep.analysis.posture,
        &prep.analysis.findings,
        &prep.reconciled.changes,
        &prep.reconciled.state.findings,
        &prep.reconciled.resolved,
        &prep.analysis.plan,
    );
    let v = serde_json::to_value(&event).unwrap();
    let e = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["fingerprint"] == fp.as_str())
        .unwrap();
    assert_eq!(e["actions"]["records"][0]["number"], "T-1");
    assert_eq!(e["actions"]["activity_count"], 1);
    // The report shows the chip and the activity as text.
    let html = prep.analysis.report_html(1_800_000_030, &mut w);
    assert!(
        html.contains(r#"<span class="ac-chip">T-1 · Open</span>"#),
        "no chip"
    );
    assert!(html.contains("<h4>Activity</h4>"), "no activity");
    assert!(html.contains("Opened t-1 <span class=\"ac-who\">— ned, WS, "));
    assert!(html.contains(r#"data-records="1""#));
    let _ = std::fs::remove_dir_all(&dir);
}
