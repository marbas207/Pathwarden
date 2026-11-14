//! The history encrypted with a passphrase (slice E): every file through
//! `Store::read_state_file` / `write_state_file`, turned on and off, the
//! passphrase changed, a wrong or missing passphrase, two machines racing,
//! and nothing in plain text in the folder or the git objects. Remotes are
//! local bare repositories; passphrases are given in-process
//! (`crypt::give_passphrase`), so no credential store is touched.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::analyze::{self, Phase, Progress};
use pathwarden_core::binding;
use pathwarden_core::config::{Config, StateBackend, StateConfig};
use pathwarden_core::crypt::{self, SecretString};
use pathwarden_core::history;
use pathwarden_core::keystore;
use pathwarden_core::record::{self, RecordProgress};
use pathwarden_core::state::{FindingsState, STATE_VERSION};
use pathwarden_core::store::{self, Store};

const PASS: &str = "correct horse battery staple";
const OTHER: &str = "a different passphrase";

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn git_command() -> Command {
    let mut c = Command::new("git");
    for var in store::GIT_LOCAL_ENV {
        c.env_remove(var);
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
    let dir = std::env::temp_dir().join(format!("pathwarden-enc-{name}-{}", std::process::id()));
    remove_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Removes a folder these tests made (git's object files are read-only).
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

fn git_bytes(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = git_command()
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
    out.stdout
}

fn bare(dir: &Path) -> PathBuf {
    let remote = dir.join("state.git");
    git(dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    remote
}

#[derive(Default)]
struct Warnings(Vec<String>);

impl Progress for Warnings {
    fn phase(&mut self, _: Phase) {}
}

impl RecordProgress for Warnings {
    fn warn(&mut self, message: String) {
        self.0.push(message);
    }
}

struct Machine {
    store: Store,
    config: Config,
}

impl Machine {
    fn git(remote: &Path, work: &Path) -> Self {
        Machine::with(
            StateConfig {
                backend: StateBackend::Git,
                remote: Some(remote.to_string_lossy().replace('\\', "/")),
                ..StateConfig::default()
            },
            work,
        )
    }

    fn folder(dir: &Path) -> Self {
        Machine::with(StateConfig::default(), dir)
    }

    /// Encrypts with [`PASS`], and keeps it given here: keys opened in this
    /// process are shared by the tests, and one may forget them all.
    fn encrypt(&self) -> store::Converted {
        let done = self.store.encrypt(&pass(PASS), true).unwrap();
        crypt::give_passphrase(&self.store.dir, pass(PASS));
        done
    }

    /// No passphrase given: a plain history with one here is refused. The
    /// keystore is a test folder, for every test of this binary.
    fn with(state: StateConfig, dir: &Path) -> Self {
        // Emptied once per run: a folder left by an earlier run with the
        // same process ID holds pins that would refuse these histories.
        static FRESH: std::sync::Once = std::sync::Once::new();
        let store =
            std::env::temp_dir().join(format!("pathwarden-enc-keystore-{}", std::process::id()));
        FRESH.call_once(|| remove_all(&store));
        keystore::use_test_store(&store);
        let config = Config {
            state: state.clone(),
            ..Config::default()
        };
        Machine {
            store: Store::new(&state, Some(dir)).unwrap(),
            config,
        }
    }

    fn prepare(&self, at: i64, w: &mut Warnings) -> (record::Prepared, record::Options<'static>) {
        self.store.pull().unwrap();
        let previous = self.store.load().unwrap();
        let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let ev = analyze::evaluate(&[forest], &self.config, &[], w).unwrap();
        let opts = record::Options {
            started_ms: at * 1000,
            accept_shrink: false,
            recorded_by: record::by::CLI,
            finished_at: Some(at + 30),
        };
        let prev_run = store::last_run(&self.store);
        let prep = record::prepare(prev_run.as_ref(), &previous, ev, &self.config, &opts, w);
        (prep, opts)
    }

    /// Records a run started at `at` (with timings), pushed when git.
    fn record(&self, at: i64) -> String {
        self.record_warned(at).0
    }

    /// [`Machine::record`], with the run's warnings.
    fn record_warned(&self, at: i64) -> (String, Vec<String>) {
        let mut w = Warnings::default();
        let (prep, opts) = self.prepare(at, &mut w);
        let id = prep.run_id().to_string();
        let timings = pathwarden_core::diagnostics::CollectionTimings::default();
        let saved = record::save_and_publish(
            &self.store,
            prep,
            &self.config,
            &opts,
            Some(&timings),
            true,
            &mut w,
        )
        .1
        .unwrap();
        if self.store.is_git() {
            assert!(saved.pushed, "{saved:?}");
        }
        (id, w.0)
    }

    fn ids(&self) -> Vec<String> {
        history::load(&self.store.dir)
            .unwrap()
            .0
            .into_iter()
            .map(|p| p.run_id)
            .collect()
    }
}

/// Removes this account's sticky record for `m`'s history: what another
/// computer, which never saw it encrypted, has. Tests share one account.
fn forget_records(m: &Machine) {
    if let Some(r) = m.store.location_record() {
        std::fs::remove_file(r).unwrap();
    }
}

/// Every file under `dir` but `.git`, with its contents.
fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if e.file_name() == ".git" {
                continue;
            }
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

/// What the history holds that must never be readable without the
/// passphrase: run records, the domain, finding counts.
const SECRETS: &[&str] = &["run_id", "contoso", " regressed, "];

fn assert_no_plaintext(what: &str, bytes: &[u8]) {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for s in SECRETS {
        assert!(!lower.contains(s), "{what} holds {s:?} in plain text");
    }
}

fn assert_encrypted_folder(dir: &Path) {
    for (path, bytes) in files(dir) {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".age") {
            assert!(
                bytes.starts_with(b"age-encryption.org/v1\n"),
                "{} is not an age file",
                path.display()
            );
        } else {
            assert!(
                matches!(
                    name.as_str(),
                    ".pathwarden-state" | ".pathwarden-encryption" | "findings.json"
                ),
                "{} is plain",
                path.display()
            );
        }
        assert_no_plaintext(&path.display().to_string(), &bytes);
    }
    assert_eq!(
        std::fs::read(dir.join("findings.json")).unwrap(),
        crypt::stub()
    );
}

/// Every object in the repository, decompressed.
fn all_objects(repo: &Path) -> Vec<u8> {
    let out = git_command()
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
}

#[test]
fn a_folder_history_is_encrypted_and_decrypted_in_place() {
    let dir = scratch("folder");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    let first = m.record(1_760_000_000);
    let before = m.store.load().unwrap();
    let last_before = store::last_run(&m.store).unwrap();

    // On: every file encrypted, the plain ones gone.
    let keys_before = pathwarden_core::exposed::read_keys(&state, &first)
        .unwrap()
        .unwrap();
    let done = m.encrypt();
    // findings, last-run, a point, its timings, its exposed accounts
    assert_eq!(done.files, 5, "{done:?}");
    assert!(!done.pushed);
    assert!(crypt::is_encrypted(&state));
    assert_encrypted_folder(&state);
    // The exposed accounts too, bound like the rest.
    assert!(state.join(format!("exposed/{first}.json.age")).is_file());
    assert!(!state.join(format!("exposed/{first}.json")).exists());
    assert_eq!(
        pathwarden_core::exposed::read_keys(&state, &first).unwrap(),
        Some(keys_before)
    );
    // Read back the same, through the seam.
    assert_eq!(
        serde_json::to_value(m.store.load().unwrap()).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    assert_eq!(
        store::last_run(&m.store).unwrap().run_id,
        last_before.run_id
    );
    assert_eq!(m.ids(), vec![first.clone()]);
    assert!(store::has_run_timings(&state, &first));
    assert!(store::run_timings(&state, &first).is_some());
    // Turning it on again is refused.
    let e = m.store.encrypt(&pass(PASS), true).unwrap_err();
    assert!(format!("{e:#}").contains("encrypted already"), "{e:#}");

    // A run recorded while encrypted is encrypted.
    let second = m.record(1_760_000_100);
    assert_encrypted_folder(&state);
    assert_eq!(m.ids(), vec![first.clone(), second.clone()]);
    // Forgetting a run removes its encrypted files.
    assert!(m.store.forget(&first).unwrap());
    assert!(!state.join(format!("history/{first}.json.age")).exists());
    assert!(!store::has_run_timings(&state, &first));
    assert!(!state.join(format!("exposed/{first}.json.age")).exists());
    assert!(state.join(format!("exposed/{second}.json.age")).is_file());

    // Off: plain again, the markers gone.
    let done = m.store.decrypt(true).unwrap();
    assert_eq!(done.files, 5);
    assert!(state.join(format!("exposed/{second}.json")).is_file());
    assert!(!crypt::is_encrypted(&state));
    for (path, _) in files(&state) {
        assert!(
            !path.to_string_lossy().ends_with(".age"),
            "{} left",
            path.display()
        );
    }
    assert!(!state.join(crypt::MARKER).exists());
    assert_eq!(m.ids(), vec![second.clone()]);
    assert_eq!(m.store.load().unwrap().version, STATE_VERSION);
    let text = std::fs::read_to_string(state.join("last-run.json")).unwrap();
    assert!(text.contains(&second), "{text}");
    remove_all(&dir);
}

#[test]
fn an_empty_history_can_be_encrypted_and_decrypted() {
    let dir = scratch("empty");
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let m = Machine::folder(&state);
    assert_eq!(m.encrypt().files, 0);
    // Only the stub: no findings yet.
    assert!(!m.store.has_state_file("findings.json"));
    assert_eq!(m.store.load().unwrap().findings.len(), 0);
    assert_eq!(m.store.decrypt(true).unwrap().files, 0);
    assert!(!state.join("findings.json").exists(), "the stub is removed");
    assert!(m.store.load().is_ok());
    remove_all(&dir);
}

#[test]
fn short_passphrases_are_refused_before_anything_changes() {
    let dir = scratch("short");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    let before = files(&state);
    let e = m.store.encrypt(&pass("short"), true).unwrap_err();
    assert!(format!("{e:#}").contains("at least 12 characters"), "{e:#}");
    assert_eq!(files(&state), before);
    remove_all(&dir);
}

/// A wrong passphrase gives the message and changes nothing; a reader
/// without one is told how to give it.
#[test]
fn a_wrong_or_missing_passphrase_is_refused_and_changes_nothing() {
    let dir = scratch("wrong");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    m.encrypt();
    let before = files(&state);

    // Another process: nothing opened yet, no passphrase.
    crypt::forget_in_process(&state);
    let e = m.store.load().unwrap_err();
    assert!(
        format!("{e:#}").contains("this computer has no passphrase for it"),
        "{e:#}"
    );
    let e = history::load(&state).unwrap_err();
    assert!(e.contains("PATHWARDEN_HISTORY_PASSPHRASE"), "{e}");
    assert!(store::last_run(&m.store).is_none());
    assert!(store::read_state_file(&state, "findings.json").is_err());

    // A wrong one.
    crypt::give_passphrase(&state, pass(OTHER));
    let e = m.store.load().unwrap_err();
    assert!(
        format!("{e:#}").contains("That passphrase doesn't open this history"),
        "{e:#}"
    );
    assert!(!crypt::opens(&state, &pass(OTHER)).unwrap());
    // Writing is refused before anything is written.
    assert!(m
        .store
        .write_state_file("history/20261018T120000.000Z.json", b"{}")
        .is_err());
    assert!(m.store.decrypt(true).is_err());
    assert!(m.store.change_passphrase(&pass(OTHER), true).is_err());
    assert_eq!(files(&state), before, "nothing changed");

    // The right one opens it.
    crypt::give_passphrase(&state, pass(PASS));
    assert!(m.store.load().is_ok());
    assert!(crypt::opens(&state, &pass(PASS)).unwrap());
    remove_all(&dir);
}

/// Pathwarden 0.1.6 and earlier read `findings.json` and stop at a state
/// version above theirs; their history list takes `history/*.json` only.
/// An encrypted history gives them neither ciphertext nor a run to show.
#[test]
fn older_versions_refuse_an_encrypted_history() {
    let dir = scratch("older");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    m.encrypt();

    // `Store::load` of 0.1.6: parse, then refuse a newer state version.
    let text = std::fs::read_to_string(state.join("findings.json")).unwrap();
    let old: FindingsState = serde_json::from_str(&text).unwrap();
    assert!(old.version > STATE_VERSION);
    assert!(old.findings.is_empty());
    // Its `last_run` reads last-run.json; its history list *.json.
    assert!(!state.join("last-run.json").exists());
    let plain_points = std::fs::read_dir(state.join("history"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .count();
    assert_eq!(plain_points, 0);
    // This version, with the marker gone: refused, not misread.
    std::fs::remove_file(state.join(crypt::MARKER)).unwrap();
    let e = m.store.load().unwrap_err();
    assert!(format!("{e:#}").contains("marker"), "{e:#}");
    remove_all(&dir);
}

/// The marker is plain and holds no secret; one from a newer format is
/// refused.
#[test]
fn the_marker_says_how_and_a_newer_one_is_refused() {
    let dir = scratch("marker");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    m.encrypt();
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join(crypt::MARKER)).unwrap()).unwrap();
    assert_eq!(marker["format"], crypt::FORMAT);
    assert_eq!(marker["cipher"], "age");
    assert_eq!(marker["scrypt_log_n"], crypt::WORK_FACTOR);
    let mut newer = marker.clone();
    newer["format"] = (crypt::FORMAT + 1).into();
    std::fs::write(state.join(crypt::MARKER), newer.to_string()).unwrap();
    let e = m.store.load().unwrap_err();
    assert!(format!("{e:#}").contains("newer Pathwarden"), "{e:#}");
    remove_all(&dir);
}

/// On in one commit, runs recorded encrypted, the passphrase changed in
/// one commit (the old one opens only older commits), off in one commit;
/// no git object written while on holds plain text.
#[test]
fn a_git_history_through_on_change_and_off() {
    if !have_git() {
        return;
    }
    let dir = scratch("git");
    let remote = bare(&dir);
    let work = dir.join("a");
    // Encrypted from the start: nothing plain ever reaches the repository.
    let a = Machine::git(&remote, &work);
    a.store.pull().unwrap();
    let on = a.encrypt();
    assert!(on.pushed, "{on:?}");
    let first = a.record(1_760_000_000);
    let second = a.record(1_760_000_100);
    assert_encrypted_folder(&work);
    let objects = all_objects(&remote);
    assert_no_plaintext("a git object", &objects);
    assert!(
        git(&remote, &["log", "--format=%s", "main"])
            .contains(&format!("pathwarden run {second}\n")),
        "a run's commit message carries no counts"
    );

    // Another machine, with the passphrase: reads both runs.
    let b = Machine::git(&remote, &dir.join("b"));
    b.store.pull().unwrap();
    crypt::give_passphrase(&b.store.dir, pass(PASS));
    assert_eq!(b.ids(), vec![first.clone(), second.clone()]);

    // Change: one commit, every file new, the key new.
    let head = git(&remote, &["rev-parse", "main"]).trim().to_string();
    let changed = a.store.change_passphrase(&pass(OTHER), true).unwrap();
    crypt::give_passphrase(&a.store.dir, pass(OTHER));
    assert!(changed.pushed);
    assert_eq!(changed.files, 8, "{changed:?}");
    assert_eq!(
        git(&remote, &["rev-parse", "main~1"]).trim(),
        head,
        "one commit"
    );
    let diff = git(&remote, &["diff", "--name-only", &head, "main"]);
    for f in [
        ".pathwarden-key.age",
        "findings.json.age",
        "last-run.json.age",
        &format!("history/{first}.json.age"),
        &format!("timings/{second}.json.age"),
        &format!("exposed/{first}.json.age"),
    ] {
        assert!(diff.lines().any(|l| l == f), "{f} not re-encrypted: {diff}");
    }
    // The old passphrase opens the older commit's key, not the tip's.
    let key_at = |rev: &str| git_bytes(&remote, &["show", &format!("{rev}:.pathwarden-key.age")]);
    let src = pathwarden_core::keystore::Source::Given;
    let old_key = crypt::open_key(&key_at(&head), &pass(PASS), src.clone()).unwrap();
    let old_findings = git_bytes(&remote, &["show", &format!("{head}:findings.json.age")]);
    assert!(crypt::open(&old_key, &old_findings, "old").is_ok());
    assert!(crypt::open_key(&key_at("main"), &pass(PASS), src.clone()).is_err());
    let new_key = crypt::open_key(&key_at("main"), &pass(OTHER), src).unwrap();
    let new_findings = git_bytes(&remote, &["show", "main:findings.json.age"]);
    assert!(crypt::open(&new_key, &new_findings, "new").is_ok());
    assert!(crypt::open(&old_key, &new_findings, "new").is_err());

    // B still has the old passphrase: told, after pulling.
    crypt::forget_in_process(&b.store.dir);
    crypt::give_passphrase(&b.store.dir, pass(PASS));
    b.store.pull().unwrap();
    let e = b.store.load().unwrap_err();
    assert!(
        format!("{e:#}").contains("That passphrase doesn't open this history"),
        "{e:#}"
    );
    assert!(
        format!("{e:#}").contains("the history's key was replaced"),
        "{e:#}"
    );
    crypt::give_passphrase(&b.store.dir, pass(OTHER));
    assert_eq!(b.ids(), vec![first.clone(), second.clone()]);
    assert_no_plaintext("a git object", &all_objects(&remote));

    // Off: one commit, plain files, no markers.
    let off = a.store.decrypt(true).unwrap();
    assert!(off.pushed);
    // A accepted its own decrypt: it records plain from here on.
    a.store
        .write_state_file(
            "last-run.json",
            &git_bytes(&remote, &["show", "main:last-run.json"]),
        )
        .unwrap();
    let tip = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tip.contains(".age"), "{tip}");
    assert!(!tip.contains(crypt::MARKER), "{tip}");
    assert!(
        tip.lines().any(|l| l == format!("history/{first}.json")),
        "{tip}"
    );
    let last: serde_json::Value =
        serde_json::from_str(&git(&remote, &["show", "main:last-run.json"])).unwrap();
    assert_eq!(last["run_id"], second.as_str());
    // B had it encrypted: refused until B says so here (and B's
    // passphrase goes).
    b.store.pull().unwrap();
    assert!(!crypt::is_encrypted(&b.store.dir));
    let e = history::load(&b.store.dir).unwrap_err();
    assert!(e.contains("was encrypted when this computer last"), "{e}");
    b.store.decrypt(true).unwrap();
    assert_eq!(b.ids(), vec![first, second]);
    remove_all(&dir);
}

/// Two machines record into one encrypted repository at once: the one
/// that pushes second records on top of the first, both encrypted.
#[test]
fn two_machines_race_on_an_encrypted_repository() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    let b = Machine::git(&remote, &dir.join("b"));
    crypt::give_passphrase(&dir.join("b"), pass(PASS));

    // Both start from the same state; A pushes first.
    let mut wa = Warnings::default();
    let mut wb = Warnings::default();
    let (pa, oa) = a.prepare(1_760_000_000, &mut wa);
    let (pb, ob) = b.prepare(1_760_000_100, &mut wb);
    let ida = pa.run_id().to_string();
    let idb = pb.run_id().to_string();
    let sa = record::save_and_publish(&a.store, pa, &a.config, &oa, None, true, &mut wa)
        .1
        .unwrap();
    assert!(sa.pushed);
    let sb = record::save_and_publish(&b.store, pb, &b.config, &ob, None, true, &mut wb)
        .1
        .unwrap();
    assert!(sb.pushed);
    assert!(
        wb.0.iter().any(|m| m.contains("pushed")),
        "B was told: {:?}",
        wb.0
    );
    // Both runs, both encrypted, in the remote.
    let tip = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    for id in [&ida, &idb] {
        assert!(
            tip.lines().any(|l| l == format!("history/{id}.json.age")),
            "{id}: {tip}"
        );
    }
    assert!(!tip
        .lines()
        .any(|l| l.ends_with(".json") && l != "findings.json"));
    a.store.pull().unwrap();
    assert_eq!(a.ids(), vec![ida, idb.clone()]);
    assert_eq!(store::last_run(&a.store).unwrap().run_id, idb);
    assert_no_plaintext("a git object", &all_objects(&remote));
    remove_all(&dir);
}

/// Encryption turned on at one machine while another, without the
/// passphrase, records plain: its push is rejected, and its run can't be
/// added to the encrypted history, so it isn't; nothing plain lands.
#[test]
fn a_plain_run_racing_the_switch_never_lands_plain() {
    if !have_git() {
        return;
    }
    let dir = scratch("switch");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.record(1_760_000_000);
    let b = Machine::git(&remote, &dir.join("b"));
    let mut wb = Warnings::default();
    let (pb, ob) = b.prepare(1_760_000_100, &mut wb);
    let idb = pb.run_id().to_string();
    // A encrypts while B's run is in progress.
    a.encrypt();
    // Refused (in this one test process, A's record of seeing it
    // encrypted counts for B too; on another computer, B's reapply finds
    // no passphrase): either way, nothing lands.
    record::save_and_publish(&b.store, pb, &b.config, &ob, None, true, &mut wb)
        .1
        .unwrap_err();
    let tip = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tip.contains(&idb), "{tip}");
    assert!(!tip.lines().any(|l| l == "last-run.json"), "{tip}");
    assert_no_plaintext("a git object", &all_objects_since_encryption(&remote));
    remove_all(&dir);
}

/// The objects of every commit from the one that turned encryption on.
fn all_objects_since_encryption(remote: &Path) -> Vec<u8> {
    let first = git(
        remote,
        &["log", "--format=%H", "--grep=encrypt the history", "main"],
    );
    let first = first.lines().last().unwrap().to_string();
    let mut out = Vec::new();
    for rev in git(remote, &["rev-list", &format!("{first}^..main")]).lines() {
        for line in git(remote, &["ls-tree", "-r", rev]).lines() {
            let object = line.split_whitespace().nth(2).unwrap();
            out.extend(git_bytes(remote, &["cat-file", "-p", object]));
        }
        out.extend(git_bytes(remote, &["cat-file", "-p", rev]));
    }
    out
}

/// The repro: someone who can push removes the marker (and the plain
/// stub); the next run on a computer with the passphrase must not write
/// and push the history in plain text.
#[test]
fn a_removed_marker_is_refused_not_written_plain() {
    if !have_git() {
        return;
    }
    let dir = scratch("strip");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let before = git(&remote, &["rev-parse", "main"]);

    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    git(&attacker, &["rm", "-q", crypt::MARKER, "findings.json"]);
    git(&attacker, &["commit", "-q", "-m", "tidy up"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    let stripped = git(&remote, &["rev-parse", "main"]);
    assert_ne!(before, stripped);

    a.store.pull().unwrap();
    // A run starts by reading the state: refused.
    let e = a.store.load().unwrap_err();
    let e = format!("{e:#}");
    assert!(
        e.contains("encryption marker .pathwarden-encryption is missing"),
        "{e}"
    );
    assert!(e.contains("by t"), "names who removed it: {e}");
    // Writing is refused too, and nothing is pushed.
    assert!(a.store.write_state_file("last-run.json", b"{}").is_err());
    assert!(
        store::write_state_file(&a.store.dir, "history/20261018T120000.000Z.json", b"{}").is_err()
    );
    assert!(history::load(&a.store.dir).is_err());
    assert_eq!(
        git(&remote, &["rev-parse", "main"]),
        stripped,
        "nothing pushed"
    );
    let tip = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tip.lines().any(|l| l.ends_with(".json")), "{tip}");
    remove_all(&dir);
}

/// Every encrypted file removed too (marker, key, all `.age`): the pin in
/// this computer's working copy refuses the plain history, until
/// `--no-encrypt` here.
#[test]
fn a_fully_stripped_history_is_refused_by_the_pin() {
    if !have_git() {
        return;
    }
    let dir = scratch("strip-all");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    git(&attacker, &["rm", "-q", "-r", "--", "."]);
    git(&attacker, &["checkout", "HEAD", "--", ".pathwarden-state"]);
    git(&attacker, &["commit", "-q", "-m", "start over"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    // Even without any passphrase at hand here.
    crypt::forget_in_process(&a.store.dir);
    a.store.pull().unwrap();
    let e = format!(
        "{:#}",
        a.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("was encrypted when this computer last"), "{e}");
    assert!(e.contains("set --no-encrypt"), "{e}");
    // --no-encrypt here accepts it.
    a.store.decrypt(true).unwrap();
    a.store.write_state_file("last-run.json", b"{}").unwrap();
    remove_all(&dir);
}

/// A folder history that isn't encrypted, on a computer that has a
/// passphrase for it: refused (someone turned the encryption off).
#[test]
fn a_plain_history_with_a_passphrase_here_is_refused() {
    let dir = scratch("plain-pass");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    crypt::give_passphrase(&state, pass(PASS));
    let e = format!(
        "{:#}",
        m.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("has a passphrase for the history"), "{e}");
    assert!(history::load(&state).is_err());
    crypt::forget_in_process(&state);
    m.store.write_state_file("last-run.json", b"{}").unwrap();
    remove_all(&dir);
}

/// A key file replaced in the repository (by someone without the
/// passphrase) is named as replaced, not just "wrong passphrase".
#[test]
fn a_replaced_key_is_named() {
    if !have_git() {
        return;
    }
    let dir = scratch("rekey");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    let (_, key_file) = crypt::new_key(&pass(OTHER)).unwrap();
    std::fs::write(attacker.join(crypt::KEY_FILE), key_file).unwrap();
    git(&attacker, &["commit", "-q", "-am", "new key"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    crypt::forget_in_process(&a.store.dir);
    crypt::give_passphrase(&a.store.dir, pass(PASS));
    a.store.pull().unwrap();
    let e = format!("{:#}", a.store.load().unwrap_err());
    assert!(e.contains("the history's key was replaced"), "{e}");
    assert!(e.contains("by t"), "{e}");
    remove_all(&dir);
}

/// A key replaced in the repository with one the passphrase here still
/// opens (someone who knows it, or who planted a passphrase source this
/// account reads) is followed, and the pull says so once, naming the
/// commit.
#[test]
fn a_followed_key_change_is_told_once() {
    if !have_git() {
        return;
    }
    let dir = scratch("rekey-same");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    assert_eq!(a.store.pull().unwrap(), None);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    let (_, key_file) = crypt::new_key(&pass(PASS)).unwrap();
    std::fs::write(attacker.join(crypt::KEY_FILE), key_file).unwrap();
    git(
        &attacker,
        &["commit", "-q", "-am", "same passphrase, new key"],
    );
    git(&attacker, &["push", "-q", "origin", "main"]);
    let commit = git(&attacker, &["log", "-1", "--format=%h"])
        .trim()
        .to_string();
    let note = a
        .store
        .pull()
        .unwrap()
        .expect("the pull says the key changed");
    assert!(note.contains("The history's key was replaced"), "{note}");
    assert!(note.contains(&format!("commit {}", &commit[..7])), "{note}");
    assert!(note.contains(" by t)"), "{note}");
    assert!(note.contains("If nobody changed the passphrase"), "{note}");
    // Once: the next pull is quiet.
    assert_eq!(a.store.pull().unwrap(), None);
    remove_all(&dir);
}

/// A point copied over another's file is not taken for that run: the
/// history doesn't show one run twice and lose the other silently. The
/// binding refuses it before its content is read.
#[test]
fn a_swapped_point_is_left_out_and_named() {
    let dir = scratch("swap");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    let first = m.record(1_760_000_000);
    let second = m.record(1_760_000_100);
    m.encrypt();
    std::fs::copy(
        state.join(format!("history/{first}.json.age")),
        state.join(format!("history/{second}.json.age")),
    )
    .unwrap();
    let (points, skipped) = history::load(&state).unwrap();
    assert_eq!(
        points.iter().map(|p| p.run_id.clone()).collect::<Vec<_>>(),
        vec![first.clone()]
    );
    assert!(
        skipped.iter().any(|s| s.contains(&second)
            && s.contains("another file of the history was put in its place")),
        "{skipped:?}"
    );
    remove_all(&dir);
}

/// The decrypted content of an encrypted file of the history in `dir`.
fn decrypted(dir: &Path, file: &str) -> Vec<u8> {
    let key = crypt::key_for(dir).unwrap();
    crypt::open(&key, &std::fs::read(dir.join(file)).unwrap(), file).unwrap()
}

/// The binding refusal behind `e`, if any.
fn binding_problem(e: &anyhow::Error) -> Option<binding::Problem> {
    e.chain()
        .find_map(|c| c.downcast_ref::<binding::BindingError>())
        .map(|b| b.problem)
}

/// One single file copied over another (last-run.json over findings.json)
/// and a full run's file moved to another run: each decrypts, and each is
/// refused, with words fit for a page.
#[test]
fn a_file_moved_into_another_place_is_refused() {
    let dir = scratch("moved");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    let first = m.record(1_760_000_000);
    let second = m.record(1_760_000_100);
    m.encrypt();
    for id in [&first, &second] {
        m.store
            .write_bundle_file(
                id,
                "summary.json",
                format!("{{\"run\":\"{id}\"}}").as_bytes(),
            )
            .unwrap();
    }
    let body = decrypted(&state, "findings.json.age");
    assert!(body.starts_with(b"pathwarden-binding/1 {\"path\":\"findings.json\""));

    std::fs::copy(
        state.join(format!("runs/{first}/summary.json.age")),
        state.join(format!("runs/{second}/summary.json.age")),
    )
    .unwrap();
    let e = m
        .store
        .read_bundle_file(&second, "summary.json")
        .unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Moved), "{e:#}");
    assert!(m.store.read_bundle_file(&first, "summary.json").is_ok());
    // A run ID in another case is no run here, on any file system (one
    // that ignores case finds the file; its binding says it isn't this).
    let other_case = first.to_lowercase();
    assert_ne!(other_case, first);
    assert!(m
        .store
        .read_bundle_file(&other_case, "summary.json")
        .unwrap()
        .is_none());

    std::fs::copy(
        state.join("last-run.json.age"),
        state.join("findings.json.age"),
    )
    .unwrap();
    let e = m.store.load().unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Moved), "{e:#}");
    assert_eq!(
        format!("{e}"),
        "findings.json in the history was replaced with another file of the history."
    );
    remove_all(&dir);
}

/// An older encrypted copy of findings.json put back: refused on the
/// computer that saw the newer one, in a folder history and in git. A
/// computer that never read the history accepts it (trust on first use).
#[test]
fn an_older_copy_put_back_is_refused() {
    // A folder: everything written is what everyone reads.
    let dir = scratch("rollback-folder");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.encrypt();
    m.record(1_760_000_000);
    let old = std::fs::read(state.join("findings.json.age")).unwrap();
    m.record(1_760_000_100);
    m.store.load().unwrap();
    std::fs::write(state.join("findings.json.age"), &old).unwrap();
    let e = m.store.load().unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Older), "{e:#}");
    assert_eq!(
        format!("{e}"),
        "findings.json in the history was replaced with an older copy."
    );
    let b = e
        .chain()
        .find_map(|c| c.downcast_ref::<binding::BindingError>())
        .unwrap();
    let record = b
        .records
        .first()
        .cloned()
        .expect("a record in the test store");
    assert!(b.acceptable());
    assert!(
        b.hint()
            .unwrap()
            .contains("run `pathwarden history storage accept`"),
        "{:?}",
        b.hint()
    );
    // The app offers to accept it where it shows the history.
    let history = keystore::history_key(&state);
    let shown = binding::refused(&history).expect("kept for the pages");
    assert_eq!(shown.rel, "findings.json");
    // Accepting resets the record: the history is read as it is.
    assert!(store::acceptable_records(&state).unwrap().contains(&record));
    let reset = store::accept_history(&state).unwrap();
    assert!(reset.contains(&record), "{reset:?}");
    assert!(!record.exists());
    assert!(binding::refused(&history).is_none());
    m.store.load().unwrap();
    remove_all(&dir);

    if !have_git() {
        return;
    }
    let dir = scratch("rollback-git");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = attacker_clone(&dir, &remote);
    a.record(1_760_000_100);
    a.store.load().unwrap();
    // The attacker's clone has the first run's findings.json.age: put it
    // back on top of the second run.
    let old = std::fs::read(attacker.join("findings.json.age")).unwrap();
    git(&attacker, &["pull", "-q", "origin", "main"]);
    std::fs::write(attacker.join("findings.json.age"), &old).unwrap();
    git(&attacker, &["commit", "-q", "-am", "pathwarden run"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    a.store.pull().unwrap();
    let e = a.store.load().unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Older), "{e:#}");
    // A computer that never read this history has nothing to compare.
    let c = Machine::git(&remote, &dir.join("c"));
    crypt::give_passphrase(&dir.join("c"), pass(PASS));
    c.store.pull().unwrap();
    c.store.load().unwrap();
    remove_all(&dir);
}

/// Two computers write the same history: one's writes that never reach
/// the remote (its push lost a race, or pushing is off) are not
/// remembered, so the remote's file, with a lower sequence, is no
/// rollback.
#[test]
fn writes_that_never_reach_the_remote_are_no_rollback() {
    if !have_git() {
        return;
    }
    let dir = scratch("two-writers");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let b = Machine::git(&remote, &dir.join("b"));
    crypt::give_passphrase(&dir.join("b"), pass(PASS));
    b.store.pull().unwrap();
    b.store.load().unwrap();
    // B writes findings.json twice here and reads it, never pushing.
    let state = b.store.load().unwrap();
    for _ in 0..2 {
        b.store
            .write_state_file("findings.json", &serde_json::to_vec(&state).unwrap())
            .unwrap();
        b.store.load().unwrap();
    }
    // A records again; B's writes give way to A's.
    a.record(1_760_000_100);
    b.store.pull().unwrap();
    b.store.load().unwrap();
    // B records on top: one more than A's.
    b.record(1_760_000_200);
    a.store.pull().unwrap();
    a.store.load().unwrap();
    assert_eq!(a.ids().len(), 3);
    remove_all(&dir);
}

/// A history encrypted before the binding (marker format 1, no binding in
/// its files) is read as it is; the first write binds every file and sets
/// format 2; then an unbound copy put back, or the marker set back to
/// format 1, is refused.
#[test]
fn a_history_encrypted_before_the_binding_is_read_then_bound() {
    let dir = scratch("upgrade");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    m.encrypt();
    m.store
        .write_bundle_file(&m.ids()[0], "summary.json", b"{}")
        .unwrap();
    // As 0.1.9 left it: every file unbound, the marker at format 1.
    let key = crypt::key_for(&state).unwrap();
    assert!(unbind(&state) >= 5);
    let marker = std::fs::read(state.join(crypt::MARKER)).unwrap();
    let unbound = std::fs::read(state.join("findings.json.age")).unwrap();
    // This computer never saw it otherwise.
    forget_bindings(&state);

    // Read as it is, and not changed by reading.
    m.store.load().unwrap();
    assert_eq!(m.ids().len(), 1);
    assert_eq!(
        m.store.encryption().unwrap().unwrap().format,
        crypt::UNBOUND_FORMAT
    );
    // The first write binds everything.
    m.record(1_760_000_100);
    assert_eq!(m.store.encryption().unwrap().unwrap().format, crypt::FORMAT);
    for (path, bytes) in files(&state) {
        if path.extension().is_some_and(|e| e == "age") && !path.ends_with(crypt::KEY_FILE) {
            let plain = crypt::open(&key, &bytes, "x").unwrap();
            assert!(
                plain.starts_with(b"pathwarden-binding/1 "),
                "{} is not bound",
                path.display()
            );
        }
    }
    assert_eq!(m.ids().len(), 2);
    assert!(m
        .store
        .read_bundle_file(&m.ids()[0], "summary.json")
        .unwrap()
        .is_some());

    // An unbound copy put back.
    let bound = std::fs::read(state.join("findings.json.age")).unwrap();
    std::fs::write(state.join("findings.json.age"), &unbound).unwrap();
    let e = m.store.load().unwrap_err();
    assert_eq!(
        binding_problem(&e),
        Some(binding::Problem::Unbound),
        "{e:#}"
    );
    // And the marker set back, so it would be read.
    std::fs::write(state.join(crypt::MARKER), &marker).unwrap();
    let e = m.store.load().unwrap_err();
    assert_eq!(
        binding_problem(&e),
        Some(binding::Problem::MarkerOlder),
        "{e:#}"
    );
    assert_eq!(
        format!("{e}"),
        "The history's encryption marker was replaced with an older one."
    );
    std::fs::write(state.join("findings.json.age"), &bound).unwrap();
    assert!(m.store.load().is_err(), "the marker alone is refused");
    // A write doesn't bind what was put back with it.
    std::fs::write(state.join("findings.json.age"), &unbound).unwrap();
    let e = m
        .store
        .write_state_file("last-run.json", b"{}")
        .unwrap_err();
    assert_eq!(
        binding_problem(&e),
        Some(binding::Problem::MarkerOlder),
        "{e:#}"
    );
    let plain = decrypted(&state, "findings.json.age");
    assert!(!plain.starts_with(b"pathwarden-binding/"), "not laundered");
    remove_all(&dir);
}

/// Turning encryption off and on again, and changing the passphrase,
/// each start a new key and a new record of sequences: nothing older is
/// compared with what the new key wrote.
#[test]
fn off_on_and_a_new_passphrase_start_the_sequences_again() {
    let dir = scratch("sequences-restart");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    m.encrypt();
    for at in 0..3 {
        m.record(1_760_000_000 + at * 100);
    }
    m.store.load().unwrap();
    // Turned off here: this computer's marks go with the encryption, so a
    // later encryption by any version (format 1 too) isn't refused.
    let history = keystore::history_key(&state);
    let mark = binding::format2_mark_for(&history).unwrap();
    let key = crypt::key_for(&state).unwrap();
    let record = binding::record_for(&history, &key.to_public().to_string()).unwrap();
    assert!(mark.is_file() && record.is_file());
    m.store.decrypt(false).unwrap();
    assert!(!mark.exists() && !record.exists());
    m.encrypt();
    m.store.load().unwrap();
    m.record(1_760_001_000);
    assert!(mark.is_file());
    // A new passphrase keeps the mark.
    m.store.change_passphrase(&pass(OTHER), false).unwrap();
    crypt::give_passphrase(&state, pass(OTHER));
    assert!(mark.is_file());
    m.store.load().unwrap();
    m.record(1_760_002_000);
    assert_eq!(m.ids().len(), 5);
    remove_all(&dir);
}

/// A plain file someone added to an encrypted history is never read, is
/// named, and the next commit removes it.
#[test]
fn a_planted_plain_file_is_named_and_removed() {
    if !have_git() {
        return;
    }
    let dir = scratch("planted");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    let planted = "history/20261018T120000.000Z.json";
    std::fs::write(attacker.join(planted), "{}\n").unwrap();
    git(&attacker, &["add", planted]);
    git(&attacker, &["commit", "-q", "-m", "a point"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    let note = a.store.pull().unwrap().unwrap_or_default();
    assert!(note.contains("in plain text"), "{note}");
    assert!(note.contains(planted), "{note}");
    assert!(!a.store.dir.join(planted).exists());
    a.record(1_760_000_100);
    let tip = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tip.lines().any(|l| l == planted), "{tip}");
    remove_all(&dir);
}

/// A computer that only reads (pushing off) can't change the shared
/// history.
#[test]
fn a_reader_cannot_turn_encryption_on() {
    if !have_git() {
        return;
    }
    let dir = scratch("reader");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.record(1_760_000_000);
    let e = a.store.encrypt(&pass(PASS), false).unwrap_err();
    assert!(format!("{e:#}").contains("only reads"), "{e:#}");
    assert!(!crypt::is_encrypted(&dir.join("a")));
    remove_all(&dir);
}

/// A computer that only reads (pushing off), with the passphrase and a
/// pin, accepts a decrypt made elsewhere: `--no-encrypt` here commits
/// nothing, so it needs no push.
#[test]
fn a_reader_accepts_a_decrypt_made_elsewhere() {
    if !have_git() {
        return;
    }
    let dir = scratch("reader-decrypt");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    let first = a.record(1_760_000_000);
    let d = Machine::with(
        StateConfig {
            backend: StateBackend::Git,
            remote: Some(remote.to_string_lossy().replace('\\', "/")),
            push: Some(false),
            ..StateConfig::default()
        },
        &dir.join("d"),
    );
    d.store.pull().unwrap();
    crypt::give_passphrase(&d.store.dir, pass(PASS));
    assert_eq!(d.ids(), vec![first.clone()]);
    a.store.decrypt(true).unwrap();
    d.store.pull().unwrap();
    let e = history::load(&d.store.dir).unwrap_err();
    assert!(e.contains("set --no-encrypt --yes"), "{e}");
    assert!(e.contains("revert commit"), "{e}");
    let done = d.store.decrypt(false).unwrap();
    assert!(!done.pushed);
    assert_eq!(d.ids(), vec![first]);
    remove_all(&dir);
}

/// A working copy that never opened the history (a fresh clone, no pin, no
/// passphrase) still refuses it after a full strip: the repository's own
/// history had the marker. `--no-encrypt` here accepts that commit.
#[test]
fn a_fresh_clone_refuses_a_stripped_history_until_accepted() {
    if !have_git() {
        return;
    }
    let dir = scratch("strip-fresh");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    git(&attacker, &["rm", "-q", "-r", "--", "."]);
    git(&attacker, &["checkout", "HEAD", "--", ".pathwarden-state"]);
    git(&attacker, &["commit", "-q", "-m", "start over"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    let stripped = git(&remote, &["rev-parse", "main"]);

    let c = Machine::git(&remote, &dir.join("c"));
    // Another computer: none of this one's records of the history.
    c.store.pull().unwrap();
    forget_records(&c);
    let e = format!(
        "{:#}",
        c.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("was encrypted before"), "{e}");
    assert!(e.contains("by t"), "{e}");
    assert!(e.contains("set --encrypt --yes"), "{e}");
    assert!(history::load(&c.store.dir).is_err());
    assert_eq!(git(&remote, &["rev-parse", "main"]), stripped);
    // Accepted here, naming who removed it: it proceeds.
    let done = c.store.decrypt(true).unwrap();
    assert!(
        done.accepted.as_deref().is_some_and(|a| a.contains("by t")),
        "{done:?}"
    );
    assert_eq!(done.files, 0);
    c.store.write_state_file("last-run.json", b"{}").unwrap();
    assert!(history::load(&c.store.dir).is_ok());
    remove_all(&dir);
}

/// The merge bypass: a fast-forward push of a merge between the encrypted
/// tip and an orphan commit holding only `.pathwarden-state`. Git's default
/// history simplification follows the orphan side; `--full-history` finds
/// the merge, so a fresh clone still refuses.
#[test]
fn a_fresh_clone_refuses_a_marker_dropped_by_a_merge() {
    if !have_git() {
        return;
    }
    let dir = scratch("strip-merge");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = dir.join("attacker");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    git(&attacker, &["checkout", "-q", "--orphan", "strip"]);
    git(&attacker, &["rm", "-q", "-r", "--cached", "."]);
    git(&attacker, &["add", ".pathwarden-state"]);
    git(&attacker, &["commit", "-q", "-m", "s"]);
    let merge = git(
        &attacker,
        &[
            "commit-tree",
            "strip^{tree}",
            "-p",
            "main",
            "-p",
            "strip",
            "-m",
            "merge",
        ],
    );
    let merge = merge.trim();
    // A fast-forward: no force push needed.
    git(
        &attacker,
        &["push", "-q", "origin", &format!("{merge}:refs/heads/main")],
    );
    assert_eq!(git(&remote, &["rev-parse", "main"]).trim(), merge);
    // Git's default simplification would miss it.
    assert!(git(
        &remote,
        &["log", "-1", "--format=%H", "main", "--", crypt::MARKER]
    )
    .trim()
    .is_empty());

    let c = Machine::git(&remote, &dir.join("c"));
    // Another computer: none of this one's records of the history.
    c.store.pull().unwrap();
    forget_records(&c);
    let e = format!(
        "{:#}",
        c.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("was encrypted before"), "{e}");
    let done = c.store.decrypt(true).unwrap();
    assert!(done.accepted.is_some());
    c.store.write_state_file("last-run.json", b"{}").unwrap();
    remove_all(&dir);
}

/// `[state] encrypted = true` refuses any plain history at its location,
/// whatever the repository holds (here a folder whose encryption was
/// removed by hand), until `--no-encrypt` accepts it.
#[test]
fn the_encrypted_setting_refuses_a_plain_history() {
    let dir = scratch("setting");
    let state = dir.join("state");
    let plain = Machine::folder(&state);
    plain.record(1_760_000_000);
    let cfg = StateConfig {
        encrypted: true,
        ..StateConfig::default()
    };
    let mut m = Machine::with(cfg.clone(), &state);
    // The config's own folder (the app resolves it; the CLI uses it
    // without --state); a --state folder it doesn't name isn't affected.
    assert!(
        m.store.load().is_ok(),
        "--state elsewhere: not this config's"
    );
    m.store = Store::new_configured(&cfg, &state).unwrap();
    let e = format!("{:#}", m.store.load().unwrap_err());
    assert!(e.contains("[state] encrypted = true"), "{e}");
    assert!(e.contains("set --encrypt --yes"), "{e}");
    assert!(m.store.write_state_file("last-run.json", b"{}").is_err());
    // Encrypting it again satisfies the setting.
    m.encrypt();
    assert!(m.store.load().is_ok());
    remove_all(&dir);
}

/// A clone of `remote`'s main for an attacker, in `dir/attacker`.
fn attacker_clone(dir: &Path, remote: &Path) -> PathBuf {
    let attacker = dir.join("attacker");
    git(
        dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &attacker.to_string_lossy(),
        ],
    );
    attacker
}

/// A history encrypted by A, then seen (pulled, never opened: no
/// passphrase) by D, whose sighting alone records it.
fn seen_encrypted(dir: &Path, remote: &Path) -> Machine {
    let a = Machine::git(remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let d = Machine::git(remote, &dir.join("d"));
    d.store.pull().unwrap();
    forget_records(&d);
    // The sighting: a pull, without the passphrase.
    d.store.pull().unwrap();
    assert!(crypt::is_encrypted(&d.store.dir));
    assert!(
        d.store.location_record().is_some(),
        "seeing it encrypted records it, passphrase or not"
    );
    d
}

/// A force push of an orphan plain history, fetched on its own first (a
/// pull a crash cut short after its fetch): a computer that saw the
/// history encrypted refuses it, until `--no-encrypt` here.
#[test]
fn a_force_push_after_an_interrupted_pull_is_refused() {
    if !have_git() {
        return;
    }
    let dir = scratch("rewrite");
    let remote = bare(&dir);
    let d = seen_encrypted(&dir, &remote);
    let attacker = attacker_clone(&dir, &remote);
    git(&attacker, &["checkout", "-q", "--orphan", "fresh"]);
    git(&attacker, &["rm", "-q", "-r", "--cached", "."]);
    git(&attacker, &["add", ".pathwarden-state"]);
    git(&attacker, &["commit", "-q", "-m", "fresh start"]);
    git(
        &attacker,
        &["push", "-q", "--force", "origin", "fresh:main"],
    );
    let pushed = git(&remote, &["rev-parse", "main"]);

    // The fetch alone, then a run's pull.
    git(&d.store.dir, &["fetch", "-q", "origin"]);
    d.store.pull().unwrap();
    assert!(!crypt::is_encrypted(&d.store.dir));
    let e = format!(
        "{:#}",
        d.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("when this computer last saw it"), "{e}");
    assert!(e.contains("this computer's record"), "{e}");
    assert!(history::load(&d.store.dir).is_err());
    assert_eq!(
        git(&remote, &["rev-parse", "main"]),
        pushed,
        "nothing pushed"
    );
    let done = d.store.decrypt(true).unwrap();
    assert!(done.accepted.is_some(), "{done:?}");
    assert!(d.store.location_record().is_none());
    d.store.write_state_file("last-run.json", b"{}").unwrap();
    remove_all(&dir);
}

/// The branch deleted on the remote (`git push origin :main`): the next
/// pull finds an empty repository, and a computer that saw the history
/// encrypted refuses to start it again in plain text.
#[test]
fn a_deleted_branch_is_refused_not_started_plain() {
    if !have_git() {
        return;
    }
    let dir = scratch("deleted");
    let remote = bare(&dir);
    let d = seen_encrypted(&dir, &remote);
    let attacker = attacker_clone(&dir, &remote);
    git(&attacker, &["push", "-q", "origin", ":main"]);
    assert!(git(&remote, &["branch", "--list", "main"])
        .trim()
        .is_empty());

    d.store.pull().unwrap();
    assert!(!crypt::is_encrypted(&d.store.dir));
    let e = format!(
        "{:#}",
        d.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("when this computer last saw it"), "{e}");
    assert!(
        git(&remote, &["branch", "--list", "main"])
            .trim()
            .is_empty(),
        "nothing pushed"
    );
    remove_all(&dir);
}

/// A damaged `.git` (here HEAD) can't be read for the marker's history:
/// refused, never taken for a new, empty repository.
#[test]
fn a_damaged_git_folder_fails_closed() {
    if !have_git() {
        return;
    }
    let dir = scratch("bad-head");
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    git(&state, &["init", "-q"]);
    std::fs::write(state.join(".git").join("HEAD"), "not a ref\n").unwrap();
    let m = Machine::folder(&state);
    let e = format!(
        "{:#}",
        m.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("checking the history's git commits"), "{e}");
    // A new repository with no commit yet is fine.
    let fresh = dir.join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    git(&fresh, &["init", "-q"]);
    Machine::folder(&fresh)
        .store
        .write_state_file("last-run.json", b"{}")
        .unwrap();
    remove_all(&dir);
}

/// A directory link: a junction on Windows (no privilege needed), a
/// symlink elsewhere. Paths are passed as they are, never joined as text.
fn link_dir(target: &Path, link: &Path) -> bool {
    #[cfg(windows)]
    {
        Command::new("cmd")
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

/// A folder history encrypted here, renamed away and replaced by a link to
/// a plain folder: the record of its path as given still refuses it.
#[test]
fn a_link_swapped_in_for_an_encrypted_folder_is_refused() {
    let dir = scratch("junction");
    let state = dir.join("hist");
    let m = Machine::folder(&state);
    m.record(1_760_000_000);
    m.encrypt();
    assert!(m.store.location_record().is_some());
    std::fs::rename(&state, dir.join("hist-away")).unwrap();
    let plain = dir.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    if !link_dir(&plain, &state) {
        eprintln!("cannot create a directory link here; skipping");
        remove_all(&dir);
        return;
    }
    crypt::forget_in_process(&state);
    let e = format!(
        "{:#}",
        m.store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err()
    );
    assert!(e.contains("when this computer last saw it"), "{e}");
    assert!(
        std::fs::read_dir(&plain).unwrap().next().is_none(),
        "nothing written"
    );
    // The link itself (a junction is removed as a folder).
    std::fs::remove_dir(&state)
        .or_else(|_| std::fs::remove_file(&state))
        .unwrap();
    remove_all(&dir);
}

/// The app runs for days: a working copy whose remote is changed at the
/// same folder is another history, with its own record (or none).
#[test]
fn a_new_remote_at_the_same_folder_is_another_history() {
    if !have_git() {
        return;
    }
    let dir = scratch("same-folder");
    let remote = bare(&dir);
    let d = seen_encrypted(&dir, &remote);
    assert!(d.store.location_record().is_some());
    let other = dir.join("other.git");
    git(&dir, &["init", "-q", "--bare", &other.to_string_lossy()]);
    // A moment, so the config's change shows in its time.
    std::thread::sleep(std::time::Duration::from_millis(50));
    git(
        &d.store.dir,
        &["remote", "set-url", "origin", &other.to_string_lossy()],
    );
    assert!(
        d.store.location_record().is_none(),
        "the old record isn't this one's"
    );
    remove_all(&dir);
}

/// An empty `.pathwarden-encryption` someone committed (no key) is no
/// encrypted history: nothing is recorded, so removing it again locks no
/// account out.
#[test]
fn an_empty_marker_records_nothing() {
    if !have_git() {
        return;
    }
    let dir = scratch("empty-marker");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.record(1_760_000_000);
    let attacker = attacker_clone(&dir, &remote);
    std::fs::write(attacker.join(crypt::MARKER), "").unwrap();
    git(&attacker, &["add", crypt::MARKER]);
    git(&attacker, &["commit", "-q", "-m", "marker"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    let d = Machine::git(&remote, &dir.join("d"));
    d.store.pull().unwrap();
    assert!(crypt::is_encrypted(&d.store.dir));
    assert!(d.store.location_record().is_none(), "nothing recorded");
    remove_all(&dir);
}

/// Makes the encrypted history folder `dir` as Pathwarden 0.1.9 left it:
/// every file without a binding, the marker at format 1. How many files
/// were bound.
fn unbind(dir: &Path) -> usize {
    let key = crypt::key_for(dir).unwrap();
    let mut n = 0;
    for (path, bytes) in files(dir) {
        if path.extension().is_some_and(|e| e == "age") && !path.ends_with(crypt::KEY_FILE) {
            let plain = crypt::open(&key, &bytes, "x").unwrap();
            if let binding::Parsed::Bound(_, body) = binding::parse(plain).unwrap() {
                std::fs::write(&path, crypt::seal(&key, &body).unwrap()).unwrap();
                n += 1;
            }
        }
    }
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(crypt::MARKER)).unwrap()).unwrap();
    marker["format"] = crypt::UNBOUND_FORMAT.into();
    let mut text = serde_json::to_string_pretty(&marker).unwrap();
    text.push('\n');
    std::fs::write(dir.join(crypt::MARKER), text).unwrap();
    n
}

/// Forgets what this computer saw of the bindings of the history in
/// `dir`: its record of sequences and its format-2 mark.
fn forget_bindings(dir: &Path) {
    let key = crypt::key_for(dir).unwrap();
    let history = keystore::history_key(dir);
    for f in [
        binding::record_for(&history, &key.to_public().to_string()),
        binding::format2_mark_for(&history),
    ]
    .into_iter()
    .flatten()
    {
        let _ = std::fs::remove_file(f);
    }
}

/// Whether every encrypted file under `dir` is bound.
fn all_bound(dir: &Path) -> bool {
    let key = crypt::key_for(dir).unwrap();
    files(dir).into_iter().all(|(path, bytes)| {
        !path.extension().is_some_and(|e| e == "age")
            || path.ends_with(crypt::KEY_FILE)
            || crypt::open(&key, &bytes, "x")
                .unwrap()
                .starts_with(b"pathwarden-binding/1 ")
    })
}

/// A git history from before the binding, upgraded by a run; then the
/// 0.1.9 marker and findings.json pushed back. A computer that read it at
/// format 2 refuses both the read and a write (which would bind the old
/// copy), even with a line-ending rule that makes its marker's bytes
/// differ from the repository's.
#[test]
fn a_marker_set_back_in_git_is_refused_whatever_its_line_endings() {
    if !have_git() {
        return;
    }
    let dir = scratch("marker-back-git");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = attacker_clone(&dir, &remote);
    crypt::give_passphrase(&attacker, pass(PASS));
    unbind(&attacker);
    std::fs::write(
        attacker.join(".gitattributes"),
        ".pathwarden-encryption text eol=crlf\n",
    )
    .unwrap();
    git(&attacker, &["add", "-A"]);
    git(&attacker, &["commit", "-q", "-m", "as 0.1.9 left it"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    let legacy = git(&attacker, &["rev-parse", "HEAD"]).trim().to_string();
    forget_bindings(&a.store.dir);
    a.store.pull().unwrap();
    a.store.load().unwrap();
    a.record(1_760_000_100);
    assert_eq!(a.store.encryption().unwrap().unwrap().format, crypt::FORMAT);

    // C clones it at format 2: its marker has CRLF, the repository's LF.
    let c = Machine::git(&remote, &dir.join("c"));
    crypt::give_passphrase(&dir.join("c"), pass(PASS));
    c.store.pull().unwrap();
    let here = std::fs::read(c.store.dir.join(crypt::MARKER)).unwrap();
    assert!(here.windows(2).any(|w| w == b"\r\n"), "CRLF on disk");
    c.store.load().unwrap();
    assert_eq!(c.ids().len(), 2);

    git(&attacker, &["pull", "-q", "origin", "main"]);
    git(
        &attacker,
        &[
            "checkout",
            &legacy,
            "--",
            crypt::MARKER,
            "findings.json.age",
        ],
    );
    git(&attacker, &["commit", "-q", "-m", "pathwarden run"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    for m in [&a, &c] {
        m.store.pull().unwrap();
        let e = m.store.load().unwrap_err();
        assert_eq!(
            binding_problem(&e),
            Some(binding::Problem::MarkerOlder),
            "{e:#}"
        );
        let e = m
            .store
            .write_state_file("last-run.json", b"{}")
            .unwrap_err();
        assert_eq!(
            binding_problem(&e),
            Some(binding::Problem::MarkerOlder),
            "{e:#}"
        );
        let plain = decrypted(&m.store.dir, "findings.json.age");
        assert!(!plain.starts_with(b"pathwarden-binding/"), "not laundered");
    }
    remove_all(&dir);
}

/// Whether file permissions stop this process: not for root on Unix, which
/// reads and writes whatever the permissions say.
fn permissions_bind() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and can't fail.
        (unsafe { libc::geteuid() }) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Makes `file` impossible to replace; undone by the returned closure.
fn unwritable(file: &Path) -> Box<dyn FnOnce()> {
    #[cfg(windows)]
    {
        let mut p = std::fs::metadata(file).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(file, p).unwrap();
        let file = file.to_path_buf();
        Box::new(move || {
            let mut p = std::fs::metadata(&file).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            std::fs::set_permissions(&file, p).unwrap();
        })
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let folder = file.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555)).unwrap();
        Box::new(move || {
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
        })
    }
}

/// Makes `file` impossible to read (on Windows, held open by nobody else
/// sharing it); undone by the returned closure.
fn unreadable(file: &Path) -> Box<dyn FnOnce()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(file)
            .unwrap();
        Box::new(move || drop(held))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let file = file.to_path_buf();
        Box::new(move || {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        })
    }
}

/// An upgrade that can't write one file and can't read another: the
/// run's own write goes on, the marker stays at format 1 (nothing is left
/// unbound for good), and the next write finishes it.
#[test]
fn an_upgrade_that_fails_partway_goes_on_and_tries_again() {
    if !permissions_bind() {
        eprintln!("running as root: permissions stop nothing; skipping this test");
        return;
    }
    let dir = scratch("upgrade-partway");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    let id = m.record(1_760_000_000);
    m.encrypt();
    for name in ["summary.json", "opengraph.json"] {
        m.store.write_bundle_file(&id, name, b"{}").unwrap();
    }
    unbind(&state);
    forget_bindings(&state);
    let key = crypt::key_for(&state).unwrap();
    let unbound = |file: &Path| {
        let plain = crypt::open(&key, &std::fs::read(file).unwrap(), "x").unwrap();
        !plain.starts_with(b"pathwarden-binding/")
    };
    let stuck = state.join(format!("runs/{id}/summary.json.age"));
    let hidden = state.join(format!("runs/{id}/opengraph.json.age"));
    // Each on its own, then both.
    for (write_fails, read_fails) in [(true, false), (false, true), (true, true)] {
        let undo_write = write_fails.then(|| unwritable(&stuck));
        let undo_read = read_fails.then(|| unreadable(&hidden));
        let notes = m
            .store
            .write_state_file(
                "last-run.json",
                &decrypted_body(&state, "last-run.json.age"),
            )
            .unwrap();
        // Said once, for the run or the sync to show.
        let n = usize::from(write_fails) + usize::from(read_fails);
        assert_eq!(notes, vec![store::upgrade_note(n)]);
        if let Some(u) = undo_read {
            u();
        }
        if let Some(u) = undo_write {
            u();
        }
        assert_eq!(
            m.store.encryption().unwrap().unwrap().format,
            crypt::UNBOUND_FORMAT,
            "write fails: {write_fails}, read fails: {read_fails}"
        );
        assert!(decrypted(&state, "findings.json.age").starts_with(b"pathwarden-binding/1 "));
        if write_fails {
            assert!(unbound(&stuck));
        }
        if read_fails {
            assert!(unbound(&hidden));
        }
        // Back as it was for the next round: unbound, at format 1.
        unbind(&state);
        forget_bindings(&state);
    }
    assert_eq!(m.ids().len(), 1);
    m.record(1_760_000_200);
    assert_eq!(m.store.encryption().unwrap().unwrap().format, crypt::FORMAT);
    assert!(all_bound(&state));
    assert_eq!(m.ids().len(), 2);
    remove_all(&dir);
}

/// The same upgrade during a run: the run goes on, and says so in its
/// warnings (Run details, the command line). The next run finishes it,
/// and says nothing.
#[test]
fn a_partial_upgrade_is_a_note_on_the_run() {
    if !permissions_bind() {
        eprintln!("running as root: permissions stop nothing; skipping this test");
        return;
    }
    assert_eq!(
        store::upgrade_note(1),
        "1 file in the history couldn't be upgraded. Pathwarden tries again on the next run."
    );
    assert_eq!(
        store::upgrade_note(3),
        "3 files in the history couldn't be upgraded. Pathwarden tries again on the next run."
    );
    // Each write tries again: only the latest says how it stands.
    assert_eq!(
        store::once_each(vec![
            store::upgrade_note(3),
            "other".into(),
            store::upgrade_note(1),
            "other".into(),
        ]),
        vec!["other".to_string(), store::upgrade_note(1)]
    );
    let dir = scratch("upgrade-note");
    let state = dir.join("state");
    let m = Machine::folder(&state);
    let id = m.record(1_760_000_000);
    m.encrypt();
    m.store
        .write_bundle_file(&id, "summary.json", b"{}")
        .unwrap();
    unbind(&state);
    forget_bindings(&state);
    let stuck = state.join(format!("runs/{id}/summary.json.age"));
    let undo = unwritable(&stuck);
    let (_, warnings) = m.record_warned(1_760_000_100);
    undo();
    let said: Vec<&String> = warnings
        .iter()
        .filter(|w| w.contains("couldn't be upgraded"))
        .collect();
    assert_eq!(said, vec![&store::upgrade_note(1)], "{warnings:?}");
    assert_eq!(
        m.store.encryption().unwrap().unwrap().format,
        crypt::UNBOUND_FORMAT
    );
    let (_, warnings) = m.record_warned(1_760_000_200);
    assert!(
        !warnings.iter().any(|w| w.contains("couldn't be upgraded")),
        "{warnings:?}"
    );
    assert_eq!(m.store.encryption().unwrap().unwrap().format, crypt::FORMAT);
    assert!(all_bound(&state));
    remove_all(&dir);
}

/// Accepting the history as it is, after a restore made on purpose,
/// resets this computer's records for that history only: another
/// history's stay, and still refuse its older copies. A marker set back
/// is accepted the same way; a file without a binding where every file
/// has one is never offered (accepting doesn't help there).
#[test]
fn accepting_a_history_resets_its_records_only() {
    let dir = scratch("accept");
    let (sa, sb) = (dir.join("a"), dir.join("b"));
    let a = Machine::folder(&sa);
    let b = Machine::folder(&sb);
    for m in [&a, &b] {
        m.encrypt();
        m.record(1_760_000_000);
    }
    let old_a = std::fs::read(sa.join("findings.json.age")).unwrap();
    let old_b = std::fs::read(sb.join("findings.json.age")).unwrap();
    for m in [&a, &b] {
        m.record(1_760_000_100);
        m.store.load().unwrap();
    }
    let records_b = store::acceptable_records(&sb).unwrap();
    assert_eq!(records_b.len(), 2, "the sequences and the format-2 mark");
    std::fs::write(sa.join("findings.json.age"), &old_a).unwrap();
    let e = a.store.load().unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Older), "{e:#}");
    let ha = keystore::history_key(&sa);
    assert!(binding::refused(&ha).is_some());
    let reset = store::accept_history(&sa).unwrap();
    assert_eq!(reset.len(), 2, "{reset:?}");
    assert!(reset.iter().all(|r| !r.exists()));
    assert!(binding::refused(&ha).is_none());
    // Nothing left to accept until the history is read again.
    // Nothing refused any more: accepting again changes nothing.
    let e = store::accept_history(&sa).unwrap_err();
    assert_eq!(format!("{e}"), store::NOTHING_REFUSED);
    a.store.load().unwrap();
    assert!(store::find_refusal(&sa).unwrap().is_none());
    assert!(store::accept_history(&sa).is_err());
    assert!(!store::acceptable_records(&sa).unwrap().is_empty());
    // The other history's records are as they were, and still refuse.
    assert!(records_b.iter().all(|r| r.is_file()));
    std::fs::write(sb.join("findings.json.age"), &old_b).unwrap();
    let e = b.store.load().unwrap_err();
    assert_eq!(binding_problem(&e), Some(binding::Problem::Older), "{e:#}");
    // Removing a refused file forgets its refusal.
    let hb = keystore::history_key(&sb);
    assert!(binding::refused(&hb).is_some());
    store::remove_state_file(&sb, "findings.json").unwrap();
    assert!(binding::refused(&hb).is_none());
    std::fs::write(sb.join("findings.json.age"), &old_b).unwrap();
    // The command line's read of the whole history finds it.
    let found = store::find_refusal(&sb).unwrap().expect("refused");
    assert_eq!(found.rel, "findings.json");

    // The marker set back to format 1, with every file as before the
    // binding: refused, then accepted, and bound again by the next run.
    a.record(1_760_000_200);
    unbind(&sa);
    let e = a.store.load().unwrap_err();
    assert_eq!(
        binding_problem(&e),
        Some(binding::Problem::MarkerOlder),
        "{e:#}"
    );
    assert_eq!(binding::refused(&ha).unwrap().rel, crypt::MARKER);
    store::accept_history(&sa).unwrap();
    a.store.load().unwrap();
    a.record(1_760_000_300);
    assert_eq!(a.store.encryption().unwrap().unwrap().format, crypt::FORMAT);

    // A file without a binding at format 2: refused, never offered.
    let key = crypt::key_for(&sa).unwrap();
    let body = decrypted_body(&sa, "findings.json.age");
    std::fs::write(
        sa.join("findings.json.age"),
        crypt::seal(&key, &body).unwrap(),
    )
    .unwrap();
    let e = a.store.load().unwrap_err();
    assert_eq!(
        binding_problem(&e),
        Some(binding::Problem::Unbound),
        "{e:#}"
    );
    assert!(binding::refused(&ha).is_none());
    remove_all(&dir);
}

/// The file in a decrypted file of the history in `dir`, after its
/// binding, if it has one.
fn decrypted_body(dir: &Path, file: &str) -> Vec<u8> {
    match binding::parse(decrypted(dir, file)).unwrap() {
        binding::Parsed::Bound(_, body) | binding::Parsed::Unbound(body) => body,
    }
}

/// Two computers upgrade a history from before the binding at once: the
/// second's push is rejected, it starts again from the first's (bound
/// already) and records on top; every file ends up bound once.
#[test]
fn two_computers_upgrading_at_once_bind_once() {
    if !have_git() {
        return;
    }
    let dir = scratch("upgrade-race");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"));
    a.store.pull().unwrap();
    a.encrypt();
    a.record(1_760_000_000);
    let attacker = attacker_clone(&dir, &remote);
    crypt::give_passphrase(&attacker, pass(PASS));
    unbind(&attacker);
    git(&attacker, &["commit", "-q", "-am", "as 0.1.9 left it"]);
    git(&attacker, &["push", "-q", "origin", "main"]);
    forget_bindings(&a.store.dir);
    let b = Machine::git(&remote, &dir.join("b"));
    crypt::give_passphrase(&dir.join("b"), pass(PASS));

    let mut wa = Warnings::default();
    let mut wb = Warnings::default();
    let (pa, oa) = a.prepare(1_760_000_100, &mut wa);
    let (pb, ob) = b.prepare(1_760_000_200, &mut wb);
    assert_eq!(
        b.store.encryption().unwrap().unwrap().format,
        crypt::UNBOUND_FORMAT
    );
    let sa = record::save_and_publish(&a.store, pa, &a.config, &oa, None, true, &mut wa)
        .1
        .unwrap();
    assert!(sa.pushed);
    let sb = record::save_and_publish(&b.store, pb, &b.config, &ob, None, true, &mut wb)
        .1
        .unwrap();
    assert!(sb.pushed);
    assert!(
        wb.0.iter().any(|m| m.contains("pushed")),
        "B's push was rejected first: {:?}",
        wb.0
    );
    for m in [&a, &b] {
        m.store.pull().unwrap();
        m.store.load().unwrap();
        assert_eq!(m.ids().len(), 3);
        assert_eq!(m.store.encryption().unwrap().unwrap().format, crypt::FORMAT);
        assert!(all_bound(&m.store.dir));
    }
    remove_all(&dir);
}
