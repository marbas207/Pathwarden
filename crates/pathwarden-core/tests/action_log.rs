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

// ------------------------------------------------ older releases' storage

const PASS: &str = "correct horse battery staple";
const OTHER: &str = "a different passphrase";

fn pass(s: &str) -> pathwarden_core::crypt::SecretString {
    pathwarden_core::crypt::SecretString::from(s.to_string())
}

/// A folder history with one action saved, keys kept in a test store.
fn folder_with_a_record(name: &str) -> (PathBuf, Store) {
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch(name);
    let s = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
    action_log::save(
        &s,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    s.write_state_file("last-run.json", b"{}").unwrap();
    (dir, s)
}

fn encrypt(s: &Store) {
    s.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&s.dir, pass(PASS));
}

/// An older release turned encryption off: it rewrote only its own files,
/// so actions.json stays encrypted with the key gone. Only what actions
/// did is unavailable, said plainly, and never written over.
#[test]
fn encryption_turned_off_by_an_older_release() {
    let (dir, s) = folder_with_a_record("rc2-decrypt");
    encrypt(&s);
    let sealed = dir.join("actions.json.age");
    let kept = std::fs::read(&sealed).unwrap();
    s.decrypt(true).unwrap();
    // As the older release leaves it.
    std::fs::write(&sealed, &kept).unwrap();
    std::fs::remove_file(dir.join("actions.json")).unwrap();
    // The rest of the history works.
    assert_eq!(s.read_state_file("last-run.json").unwrap().unwrap(), b"{}");
    s.write_state_file("last-run.json", b"{\"a\":1}").unwrap();
    let e = action_log::load(&s).unwrap_err();
    assert_eq!(format!("{e:#}"), action_log::LEFT_SEALED_WORDS);
    let e = action_log::save(
        &s,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("older Pathwarden turned encryption off"));
    assert_eq!(std::fs::read(&sealed).unwrap(), kept);
    assert!(!dir.join("actions.json").exists());
    // Encrypting again (here) keeps it as it was, with a note.
    let done = s.encrypt(&pass(PASS), true).unwrap();
    assert!(
        done.notes.iter().any(|n| n.contains("was left as it is")),
        "{:?}",
        done.notes
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An older release changed the passphrase: actions.json stays under the
/// old key. It can't be read, the rest works, nothing writes over it, and
/// this version's own rewrite keeps it with a note.
#[test]
fn a_passphrase_changed_by_an_older_release() {
    let (dir, s) = folder_with_a_record("rc2-rekey");
    encrypt(&s);
    let sealed = dir.join("actions.json.age");
    let kept = std::fs::read(&sealed).unwrap();
    s.change_passphrase(&pass(OTHER), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&s.dir, pass(OTHER));
    std::fs::write(&sealed, &kept).unwrap();
    assert_eq!(s.read_state_file("last-run.json").unwrap().unwrap(), b"{}");
    let e = action_log::load(&s).unwrap_err();
    assert!(
        format!("{e:#}").contains(action_log::UNREADABLE_WORDS),
        "{e:#}"
    );
    assert!(action_log::save(
        &s,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .is_err());
    assert_eq!(std::fs::read(&sealed).unwrap(), kept);
    // A rewrite here works, and leaves it.
    let done = s.change_passphrase(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&s.dir, pass(PASS));
    assert!(
        done.notes.iter().any(|n| n.contains("was left as it is")),
        "{:?}",
        done.notes
    );
    assert_eq!(std::fs::read(&sealed).unwrap(), kept);
    assert_eq!(s.read_state_file("last-run.json").unwrap().unwrap(), b"{}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain actions.json in an encrypted history (an older release left it
/// when it turned encryption on, or anyone who can push put it there) is
/// never read, merged, encrypted or removed by itself; the readers say
/// so, and importing it takes it in on purpose, as untrusted.
#[test]
fn a_plain_file_in_an_encrypted_history_is_only_imported_on_purpose() {
    let (dir, s) = folder_with_a_record("rc2-encrypt");
    let plain = dir.join("actions.json");
    // A record with a link that isn't https, as anyone could push.
    let text = std::fs::read_to_string(&plain)
        .unwrap()
        .replace(
            "\"open\": true",
            "\"open\": true,\n          \"url\": \"javascript:alert(1)\"",
        )
        .replace("PW-001-aaaa", "PW-003-cccc")
        .replace("t-1", "t-p");
    assert!(text.contains("javascript:"));
    encrypt(&s);
    let sealed = dir.join("actions.json.age");
    // The real log holds another record; the planted file sits beside it.
    action_log::save(
        &s,
        &opened("PW-002-bbbb", "t-9", "2026-11-18T14:30:00.000Z", "ned"),
        true,
    )
    .unwrap();
    std::fs::write(&plain, &text).unwrap();
    assert!(store::planted_files(&dir).is_empty());
    assert!(action_log::plain_left(&s));
    // Not read, not merged.
    let log = action_log::load(&s).unwrap();
    assert!(log.records("PW-003-cccc").is_empty());
    assert_eq!(log.records("PW-002-bbbb").len(), 1);
    // A save leaves it as it is.
    action_log::save(
        &s,
        &opened("PW-002-bbbb", "t-10", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(&plain).unwrap(), text);
    assert!(action_log::load(&s)
        .unwrap()
        .records("PW-003-cccc")
        .is_empty());
    // What it holds, for whoever decides.
    let (shown, hash) = action_log::read_plain(&s).unwrap().unwrap();
    let summary = shown.summary(5);
    // Every record, with its number, status and the link's host (none
    // here: the javascript: link is dropped).
    assert_eq!(
        summary.record_lines,
        [("PW-003-cccc".to_string(), "T-1 · Open".to_string())]
    );
    assert_eq!(
        (summary.findings, summary.records, summary.activity),
        (1, 1, 1)
    );
    assert_eq!(summary.newest[0].0, "PW-003-cccc");
    assert!(
        summary.newest[0].1.starts_with("Opened t-p — ned"),
        "{:?}",
        summary.newest
    );
    // Only what was shown is imported.
    let e = action_log::import_plain(&s, true, "0000").unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "The file changed since you were shown it; run the command again."
    );
    assert!(plain.exists());
    // Imported on purpose: merged as untrusted, encrypted, plain removed.
    action_log::import_plain(&s, true, &hash).unwrap();
    assert!(!plain.exists());
    assert!(sealed.exists());
    assert!(!action_log::plain_left(&s));
    let log = action_log::load(&s).unwrap();
    let r = &log.records("PW-003-cccc")[0];
    assert_eq!(r.record.id, "t-p");
    assert_eq!(r.record.url, None, "the javascript: link is dropped");
    assert_eq!(log.records("PW-002-bbbb").len(), 2);
    assert!(
        action_log::import_plain(&s, true, &hash).is_err(),
        "nothing left"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// In git, a planted plain file isn't removed by a pull either, and the
/// import's commit removes it from the repository.
#[test]
fn a_planted_file_stays_in_git_until_imported() {
    if !have_git() {
        return;
    }
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("planted-git");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    a.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(PASS));
    // Someone without the passphrase pushes a plain file.
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
    let forged = "{\"version\":1,\"findings\":{\"PW-001-aaaa\":{\"records\":[{\"action\":\"desk/open\",\"id\":\"x\",\"open\":true,\"at\":\"2026-11-18T13:00:00.000Z\"}]}}}\n";
    std::fs::write(other.join("actions.json"), forged).unwrap();
    git(&other, &["add", "actions.json"]);
    git(&other, &["commit", "-q", "-m", "forged"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    a.pull().unwrap();
    assert!(action_log::plain_left(&a));
    let ids: Vec<String> = action_log::load(&a)
        .unwrap()
        .records("PW-001-aaaa")
        .into_iter()
        .map(|r| r.record.id)
        .collect();
    assert_eq!(ids, ["t-1"], "the forged record isn't read");
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(git(&remote, &["show", "main:actions.json"]), forged);
    let (_, hash) = action_log::read_plain(&a).unwrap().unwrap();
    action_log::import_plain(&a, true, &hash).unwrap();
    assert!(git_command()
        .arg("-C")
        .arg(&remote)
        .args(["cat-file", "-e", "main:actions.json"])
        .status()
        .is_ok_and(|s| !s.success()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save to a log that can't take it is refused and kept nowhere: not
/// written, and not in the saves waiting for a push.
#[test]
fn a_refused_save_is_not_kept_for_later() {
    if !have_git() {
        return;
    }
    let dir = scratch("refused");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    std::fs::write(
        dir.join("a").join("actions.json"),
        "{\"version\":2,\"findings\":{}}\n",
    )
    .unwrap();
    let change = opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned");
    assert!(action_log::save(&a, &change, true).is_err());
    assert_eq!(action_log::pending_count(&a), 0);
    for locked in [true, false] {
        assert!(action_log::save_here(&a, &change, locked).is_err());
        assert_eq!(action_log::pending_count(&a), 0, "locked: {locked}");
    }
    // Nothing to prune with a log that can't be read, and nothing grows.
    action_log::prune_pending(&a);
    assert_eq!(action_log::pending_count(&a), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// In an encrypted history, the saves waiting for a push are encrypted
/// with its key, as its files are.
#[test]
fn saves_waiting_for_a_push_are_encrypted() {
    if !have_git() {
        return;
    }
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("pending-sealed");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(PASS));
    hook(
        &remote.join("hooks").join("pre-receive"),
        "#!/bin/sh\nexit 1\n",
    );
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(action_log::pending_count(&a), 1);
    let raw = std::fs::read(
        dir.join("a")
            .join(".git")
            .join("pathwarden-actions-pending.json"),
    )
    .unwrap();
    assert!(raw.starts_with(b"age-encryption.org/"));
    assert!(!String::from_utf8_lossy(&raw).contains("PW-001-aaaa"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hook script git runs (executable where that matters).
fn hook(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// A save whose push failed is kept here: another computer pushes first,
/// the pull takes the remote's state, and the save is made again on it,
/// then pushed with the next save, and no longer kept.
#[test]
fn a_save_whose_push_failed_survives_another_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("pending");
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
    assert_eq!(action_log::pending_count(&a), 0, "pushed, so not kept");
    b.pull().unwrap();
    // A's next push is refused.
    let refuse = remote.join("hooks").join("pre-receive");
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    let notes = action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert!(
        notes.iter().any(|n| n.contains("couldn't be pushed")),
        "{notes:?}"
    );
    assert_eq!(action_log::pending_count(&a), 1);
    std::fs::remove_file(&refuse).unwrap();
    // B pushes first.
    action_log::save(
        &b,
        &opened("PW-011-bbbb", "t-3", "2026-11-18T15:30:00.000Z", "arya"),
        true,
    )
    .unwrap();
    // A pulls: the remote's state, with A's save made again on it.
    a.pull().unwrap();
    let here = action_log::load(&a).unwrap();
    assert_eq!(here.records("PW-001-aaaa").len(), 2, "A's record survives");
    assert_eq!(here.records("PW-011-bbbb").len(), 1, "B's is there");
    assert_eq!(action_log::pending_count(&a), 1);
    // A's next save pushes it.
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-4", "2026-11-18T16:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    let log = remote_log(&remote);
    let ids: Vec<String> = log
        .records("PW-001-aaaa")
        .into_iter()
        .map(|r| r.record.id)
        .collect();
    assert_eq!(ids, ["t-1", "t-2", "t-4"]);
    assert_eq!(log.activity("PW-001-aaaa").len(), 3);
    assert_eq!(log.records("PW-011-bbbb").len(), 1);
    assert_eq!(action_log::pending_count(&a), 0, "no longer kept");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cancelled run's quick save: written here without the network, kept
/// for the next pull and push, which carries it.
#[test]
fn a_quick_save_goes_with_the_next_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("quick");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    {
        let _lock = a.lock().unwrap();
        action_log::save_here(
            &a,
            &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
            true,
        )
        .unwrap();
    }
    assert_eq!(
        action_log::load(&a).unwrap().records("PW-001-aaaa").len(),
        2
    );
    assert_eq!(remote_log(&remote).records("PW-001-aaaa").len(), 1);
    assert_eq!(action_log::pending_count(&a), 1);
    // Without the lock: only kept, and still carried.
    action_log::save_here(
        &a,
        &opened("PW-001-aaaa", "t-3", "2026-11-18T15:30:00.000Z", "ned"),
        false,
    )
    .unwrap();
    assert_eq!(action_log::pending_count(&a), 2);
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-4", "2026-11-18T16:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(remote_log(&remote).records("PW-001-aaaa").len(), 4);
    assert_eq!(action_log::pending_count(&a), 0);
    // A folder history without the lock: not saved, and it says so.
    let folder = scratch("quick-folder");
    let f = Store::new(&StateConfig::default(), Some(&folder)).unwrap();
    assert!(action_log::save_here(
        &f,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        false,
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&folder);
}

/// A file of the saves waiting for a push, as raw bytes.
fn pending_bytes(work: &Path) -> Option<Vec<u8>> {
    std::fs::read(work.join(".git").join("pathwarden-actions-pending.json")).ok()
}

/// The saves waiting for a push survive a change of passphrase and a
/// decrypt (written again in the history's new form), and are pushed by
/// the next save; an empty list leaves no file behind.
#[test]
fn waiting_saves_survive_a_storage_change() {
    if !have_git() {
        return;
    }
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("pending-rekey");
    let remote = bare(&dir);
    let work = dir.join("a");
    let (a, _) = git_store(&remote, &work);
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(PASS));
    // A save whose push is refused: kept, sealed.
    let refuse = remote.join("hooks").join("pre-receive");
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    std::fs::remove_file(&refuse).unwrap();
    assert_eq!(action_log::pending_count(&a), 1);
    let sealed_before = pending_bytes(&work).unwrap();
    // A new passphrase: the waiting save is sealed with the new key.
    a.change_passphrase(&pass(OTHER), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(OTHER));
    let sealed_after = pending_bytes(&work).unwrap();
    assert!(sealed_after.starts_with(b"age-encryption.org/"));
    assert_ne!(sealed_before, sealed_after);
    assert_eq!(action_log::pending_count(&a), 1, "still readable");
    // Hold the push again, then decrypt: written plain.
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    std::fs::remove_file(&refuse).unwrap();
    a.decrypt(true).unwrap();
    let plain = pending_bytes(&work).unwrap();
    assert!(plain.starts_with(b"{"));
    assert_eq!(action_log::pending_count(&a), 2);
    // The next save pushes them all, and the list is gone.
    a.pull().unwrap();
    action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-3", "2026-11-18T16:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert_eq!(remote_log(&remote).records("PW-001-aaaa").len(), 3);
    assert_eq!(pending_bytes(&work), None, "no empty file left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file of waiting saves that can't be opened is moved aside, said so,
/// and saves go on.
#[test]
fn unreadable_waiting_saves_are_moved_aside() {
    if !have_git() {
        return;
    }
    let dir = scratch("pending-bad");
    let remote = bare(&dir);
    let work = dir.join("a");
    let (a, _) = git_store(&remote, &work);
    a.pull().unwrap();
    let file = work.join(".git").join("pathwarden-actions-pending.json");
    std::fs::write(&file, b"not json at all").unwrap();
    let notes = action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert!(
        notes.iter().any(|n| n.contains("were moved aside to")),
        "{notes:?}"
    );
    let aside: Vec<String> = std::fs::read_dir(work.join(".git"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("pathwarden-actions-pending.json.unreadable-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(
        std::fs::read(work.join(".git").join(&aside[0])).unwrap(),
        b"not json at all"
    );
    assert_eq!(remote_log(&remote).records("PW-001-aaaa").len(), 1);
    // Again, found by a count (which says nothing): moved aside under a
    // name of its own, and the next save says so.
    std::fs::write(&file, b"still not json").unwrap();
    assert_eq!(action_log::pending_count(&a), 0);
    let notes = action_log::save(
        &a,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "ned"),
        true,
    )
    .unwrap();
    assert!(
        notes.iter().any(|n| n.contains("were moved aside to")),
        "{notes:?}"
    );
    let aside = std::fs::read_dir(work.join(".git"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("pathwarden-actions-pending.json.unreadable-")
        })
        .count();
    assert_eq!(aside, 2, "never over the first");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Decrypting leaves a plain actions.json that sat, never read, beside the
/// encrypted history out of it: moved aside, with a note.
#[test]
fn decrypting_leaves_a_planted_plain_file_out() {
    let (dir, s) = folder_with_a_record("decrypt-planted");
    encrypt(&s);
    std::fs::remove_file(dir.join("actions.json.age")).unwrap();
    let forged = "{\"version\":1,\"findings\":{\"PW-009-x\":{\"records\":[{\"action\":\"a/b\",\"id\":\"x\",\"open\":true}]}}}\n";
    std::fs::write(dir.join("actions.json"), forged).unwrap();
    let done = s.decrypt(true).unwrap();
    assert!(
        done.notes.iter().any(|n| n.contains("moved aside to")),
        "{:?}",
        done.notes
    );
    let moved = s.leftovers();
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert!(moved[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with(action_log::LEFTOVER_PREFIX));
    assert_eq!(std::fs::read_to_string(&moved[0]).unwrap(), forged);
    assert!(action_log::load(&s).unwrap().findings.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// What the import shows: every record, at most 20 lines.
#[test]
fn the_import_summary_lists_the_records() {
    let mut f = ActionsFile::default();
    for i in 0..25 {
        let mut c = opened(
            &format!("PW-001-{i:04}"),
            &format!("t-{i}"),
            &format!("2026-11-18T14:{i:02}:00.000Z"),
            "ned",
        );
        c.records[0].record.url = Some(format!("https://desk{i}.example.com/x"));
        c.apply(&mut f);
    }
    let s = f.summary(3);
    assert_eq!(s.records, 25);
    assert_eq!(s.record_lines.len(), action_log::SUMMARY_RECORDS);
    assert_eq!(s.more_records, 5);
    assert_eq!(
        s.record_lines[0],
        (
            "PW-001-0000".to_string(),
            "T-0 · Open · desk0.example.com".to_string()
        )
    );
    assert_eq!(s.newest.len(), 3);
}

/// In git, decrypting moves a plain actions.json it leaves out into the
/// working copy's `.git`, where no commit picks it up.
#[test]
fn a_leftover_from_a_decrypt_stays_out_of_git() {
    if !have_git() {
        return;
    }
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("leftover-git");
    let remote = bare(&dir);
    let work = dir.join("a");
    let (a, _) = git_store(&remote, &work);
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(PASS));
    std::fs::write(work.join("actions.json"), "{\"version\":1}\n").unwrap();
    let done = a.decrypt(true).unwrap();
    assert!(
        done.notes.iter().any(|n| n.contains("moved aside to")),
        "{:?}",
        done.notes
    );
    let moved = a.leftovers();
    assert_eq!(moved.len(), 1);
    assert!(moved[0].starts_with(work.join(".git")), "{moved:?}");
    assert!(!work.join("actions.json").exists());
    assert!(git_command()
        .arg("-C")
        .arg(&remote)
        .args(["cat-file", "-e", "main:actions.json"])
        .status()
        .is_ok_and(|s| !s.success()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// B keeps a save sealed while it waits; A decrypts the history and
/// pushes; B pulls: the sealed file can't be opened any more, so it is
/// moved aside, the pull says so, and B's saves go on.
#[test]
fn a_decrypt_elsewhere_sets_sealed_waiting_saves_aside() {
    if !have_git() {
        return;
    }
    let ks = std::env::temp_dir().join(format!("pathwarden-actionlog-ks-{}", std::process::id()));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("pending-decrypted");
    let remote = bare(&dir);
    let (a, _) = git_store(&remote, &dir.join("a"));
    let (b, _) = git_store(&remote, &dir.join("b"));
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.encrypt(&pass(PASS), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&a.dir, pass(PASS));
    b.pull().unwrap();
    pathwarden_core::crypt::give_passphrase(&b.dir, pass(PASS));
    let refuse = remote.join("hooks").join("pre-receive");
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    action_log::save(
        &b,
        &opened("PW-001-aaaa", "t-1", "2026-11-18T14:00:00.000Z", "arya"),
        true,
    )
    .unwrap();
    std::fs::remove_file(&refuse).unwrap();
    assert!(pending_bytes(&dir.join("b"))
        .unwrap()
        .starts_with(b"age-encryption.org/"));
    a.pull().unwrap();
    a.decrypt(true).unwrap();
    // B follows the decrypt (as `history storage set --no-encrypt` here).
    let done = b.decrypt(true).unwrap();
    let said = done.notes.join(" ");
    assert!(said.contains("were moved aside to"), "{said}");
    assert_eq!(action_log::pending_count(&b), 0);
    let saved = action_log::save_reporting(
        &b,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "arya"),
        true,
    )
    .unwrap();
    assert!(saved.pushed, "{:?}", saved.notes);
    assert_eq!(remote_log(&remote).records("PW-001-aaaa").len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save the remote's log refuses on the retry (a newer file pushed
/// meanwhile) is the error, and isn't kept; one whose push fails for a
/// reason that can go away is kept, not pushed.
#[test]
fn a_refused_retry_drops_the_save_and_a_failed_push_keeps_it() {
    if !have_git() {
        return;
    }
    let dir = scratch("retry");
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
    b.pull().unwrap();
    // A failed push: kept here, not pushed.
    let refuse = remote.join("hooks").join("pre-receive");
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    let saved = action_log::save_reporting(
        &b,
        &opened("PW-001-aaaa", "t-2", "2026-11-18T15:00:00.000Z", "arya"),
        true,
    )
    .unwrap();
    assert!(!saved.pushed);
    assert_eq!(action_log::pending_count(&b), 1);
    std::fs::remove_file(&refuse).unwrap();
    // Meanwhile another computer pushes a newer log.
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
    std::fs::write(
        other.join("actions.json"),
        "{\"version\":2,\"findings\":{}}\n",
    )
    .unwrap();
    git(&other, &["commit", "-q", "-am", "newer"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    // B's next save is refused on the retry, and nothing is kept for it.
    let change = opened("PW-001-aaaa", "t-3", "2026-11-18T16:00:00.000Z", "arya");
    let e = action_log::save_reporting(&b, &change, true).unwrap_err();
    assert!(
        format!("{e:#}").contains("saved by a newer Pathwarden"),
        "{e:#}"
    );
    let left = action_log::pending_count(&b);
    assert_eq!(
        left, 1,
        "only the earlier save is kept, not the refused one"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
