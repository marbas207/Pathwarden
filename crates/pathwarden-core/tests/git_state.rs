//! Git-backed run state shared by two machines: a run whose push is
//! rejected because another run pushed first is recorded on top of it,
//! never discarded; a push that fails for another reason keeps the run for
//! the next one, and runs kept that way survive another machine's push.
//! Two working copies of one local bare repository stand in for the two
//! machines; the runs' start times are chosen, so which one is newer is
//! known.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::analyze::{self, Phase, Progress};
use pathwarden_core::config::{Config, StateBackend, StateConfig};
use pathwarden_core::history;
use pathwarden_core::record::{self, RecordProgress};
use pathwarden_core::store::{self, Store};

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

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-gitstate-{name}-{}", std::process::id()));
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

/// A hook script git runs (executable where that matters).
fn hook(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Warnings a recording gives, kept.
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

impl Warnings {
    fn has(&self, text: &str) -> bool {
        self.0.iter().any(|m| m.contains(text))
    }
}

struct Machine {
    store: Store,
    config: Config,
}

impl Machine {
    fn new(remote: &Path, work: &Path) -> Self {
        let state = StateConfig {
            backend: StateBackend::Git,
            remote: Some(remote.to_string_lossy().replace('\\', "/")),
            ..StateConfig::default()
        };
        let config = Config {
            state: state.clone(),
            ..Config::default()
        };
        Machine {
            store: Store::new(&state, Some(work)).unwrap(),
            config,
        }
    }

    /// Pulls and analyzes `testdata/forest` as a run started at `at`
    /// (seconds), ready to save: what a run does before it records. The
    /// pull has nothing to say.
    fn prepare(&self, at: i64, w: &mut Warnings) -> (record::Prepared, record::Options<'static>) {
        let (prep, opts, note) = self.prepare_noting(at, w);
        assert_eq!(note, None);
        (prep, opts)
    }

    /// [`Machine::prepare`], with what the pull said.
    fn prepare_noting(
        &self,
        at: i64,
        w: &mut Warnings,
    ) -> (record::Prepared, record::Options<'static>, Option<String>) {
        let note = self.store.pull().unwrap();
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
        (prep, opts, note)
    }

    fn save(
        &self,
        prep: record::Prepared,
        opts: &record::Options,
        w: &mut Warnings,
    ) -> anyhow::Result<record::Saved> {
        record::save_and_publish(&self.store, prep, &self.config, opts, None, true, w).1
    }

    fn record(&self, prep: record::Prepared, opts: &record::Options, w: &mut Warnings) -> String {
        let id = prep.run_id().to_string();
        let saved = self.save(prep, opts, w).unwrap();
        assert!(saved.pushed, "pushed: {saved:?}");
        id
    }
}

fn history_ids(remote: &Path) -> Vec<String> {
    git(remote, &["ls-tree", "--name-only", "main", "history/"])
        .lines()
        .map(|l| {
            l.trim_start_matches("history/")
                .trim_end_matches(".json")
                .to_string()
        })
        .collect()
}

fn remote_json(remote: &Path, path: &str) -> serde_json::Value {
    serde_json::from_str(&git(remote, &["show", &format!("main:{path}")])).unwrap()
}

fn last_run_id(remote: &Path) -> String {
    remote_json(remote, "last-run.json")["run_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn inserted(remote: &Path, run: &str) -> bool {
    remote_json(remote, &format!("history/{run}.json"))["inserted"] == true
}

/// Another clone of the remote that commits and pushes by hand (a stand-in
/// for a machine whose push lands first).
fn push_other(dir: &Path, remote: &Path, file: &str) {
    push_other_text(dir, remote, file, "{}\n");
}

/// [`push_other`] with `text` in `file`.
fn push_other_text(dir: &Path, remote: &Path, file: &str, text: &str) {
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
    if let Some(parent) = other.join(file).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(other.join(file), text).unwrap();
    git(&other, &["add", file]);
    git(&other, &["commit", "-q", "-m", file]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
}

#[test]
fn a_run_another_run_pushed_before_is_recorded_on_top_of_it() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();

    // A first run, from A.
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);

    // A newer run from B pushes while an older one from A is still being
    // recorded: A's run is added to the history before B's, marked so, and
    // the findings state stays B's.
    let (older, older_opts) = a.prepare(1_800_001_000, &mut w);
    let (newer, newer_opts) = b.prepare(1_800_002_000, &mut w);
    let newer = b.record(newer, &newer_opts, &mut w);
    w.0.clear();
    let older_id = older.run_id().to_string();
    let saved = a.save(older, &older_opts, &mut w).unwrap();
    assert!(saved.pushed && saved.inserted, "{saved:?}");
    assert!(w.has(&format!("a newer run ({newer})")), "{:?}", w.0);
    assert_eq!(
        w.0.iter().filter(|m| m.contains("a newer run")).count(),
        1,
        "said once: {:?}",
        w.0
    );
    assert_eq!(
        history_ids(&remote),
        [first.clone(), older_id.clone(), newer.clone()]
    );
    assert_eq!(last_run_id(&remote), newer, "the newest run stays the last");
    assert!(inserted(&remote, &older_id));
    assert!(!inserted(&remote, &newer));
    // Each run's exposed accounts go in with its point, the inserted one's
    // too.
    for run in [&first, &older_id, &newer] {
        let keys = remote_json(&remote, &format!("exposed/{run}.json"));
        assert_eq!(keys["run_id"], run.as_str());
        let point = remote_json(&remote, &format!("history/{run}.json"));
        assert_eq!(point["exposed_keys"], true);
        assert_eq!(
            keys["sets"]["Tier Zero"]["count"],
            point["tier_zero_exposed"]
        );
    }

    // B's run is still compared with the first, not with the run added
    // before it; the history's totals don't count both.
    git(&dir.join("b"), &["pull", "-q", "origin", "main"]);
    let (points, _) = history::load(&dir.join("b")).unwrap();
    let b_point = points.iter().find(|p| p.run_id == newer).unwrap();
    assert_eq!(
        pathwarden_core::since::previous(&points, b_point).map(|p| p.run_id.as_str()),
        Some(first.as_str())
    );
    let a_point = points.iter().find(|p| p.run_id == older_id).unwrap();
    assert_eq!(
        pathwarden_core::since::previous(&points, a_point).map(|p| p.run_id.as_str()),
        Some(first.as_str())
    );

    // The other way round: B's newer run is compared again with the state
    // A's older one left, and recorded after it.
    let (newer, newer_opts) = b.prepare(1_800_004_000, &mut w);
    let (older, older_opts) = a.prepare(1_800_003_000, &mut w);
    let older = a.record(older, &older_opts, &mut w);
    w.0.clear();
    let newer = b.record(newer, &newer_opts, &mut w);
    assert_eq!(
        w.0.iter()
            .filter(
                |m| m.contains(&format!("another run ({older})")) && m.contains("compared again")
            )
            .count(),
        1,
        "said once: {:?}",
        w.0
    );
    let h = history_ids(&remote);
    assert_eq!(h.len(), 5, "{h:?}");
    assert_eq!(h[3..], [older.clone(), newer.clone()]);
    assert_eq!(last_run_id(&remote), newer);
    // Compared with A's run, which saw the same: nothing new.
    let log = git(&remote, &["log", "--format=%s", "main"]);
    assert!(
        log.lines().next().unwrap().starts_with(&format!(
            "pathwarden run {newer}: 0 new, 0 regressed, 0 resolved"
        )),
        "{log}"
    );
    assert_eq!(log.lines().count(), 5, "one commit per run: {log}");
    remove_all(&dir);
}

/// A racing commit that leaves the last run as it was (a removal) is not
/// named as a newer run.
#[test]
fn a_race_with_a_removal_says_the_history_changed() {
    if !have_git() {
        return;
    }
    let dir = scratch("race-forget");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let second = a.record(prep, &opts, &mut w);
    let (prep, opts) = a.prepare(1_800_002_000, &mut w);
    b.store.pull().unwrap();
    assert!(b.store.forget_and_publish(&first, true).unwrap().0);
    w.0.clear();
    let third = a.record(prep, &opts, &mut w);
    assert!(w.has("the history changed while this run ran"), "{:?}", w.0);
    assert!(!w.has(&format!("({second})")), "{:?}", w.0);
    assert_eq!(history_ids(&remote), [second, third]);
    remove_all(&dir);
}

#[test]
fn forgetting_a_run_survives_another_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("forget");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);

    // B removes the first run while A records a second one.
    assert_eq!(b.store.pull().unwrap(), None);
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let second = a.record(prep, &opts, &mut w);
    let (removed, notes) = b.store.forget_and_publish(&first, true).unwrap();
    assert!(removed && notes.is_empty(), "{notes:?}");
    assert_eq!(history_ids(&remote), [second]);
    let log = git(&remote, &["log", "--format=%s", "main"]);
    assert!(
        log.starts_with(&format!("pathwarden: remove run {first} from the history")),
        "{log}"
    );
    remove_all(&dir);
}

/// A push that fails for another reason than a race keeps the run's commit:
/// the next pull keeps it while the remote has not moved on, and the next
/// publish pushes it.
#[test]
fn an_unpushed_run_is_pushed_by_the_next_one() {
    if !have_git() {
        return;
    }
    let dir = scratch("unpushed");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);

    // The remote is out of reach when the run pushes: recorded here, not an
    // error.
    let (prep, opts) = a.prepare(1_800_000_500, &mut w);
    let away = dir.join("away.git");
    std::fs::rename(&remote, &away).unwrap();
    let saved = a.save(prep, &opts, &mut w).unwrap();
    let kept = saved.unpushed.expect("not pushed");
    assert!(!saved.pushed);
    assert!(
        kept.reason
            .ends_with("can't be reached, or refused the sign-in"),
        "{kept:?}"
    );
    assert_eq!(
        kept.sentence("This run is recorded"),
        format!(
            "This run is recorded here, but the change couldn't be pushed ({}); it goes with \
             the next run that pushes.",
            kept.reason
        )
    );
    std::fs::rename(&away, &remote).unwrap();
    assert_eq!(history_ids(&remote), std::slice::from_ref(&first));

    // The remote refuses the next push (a protected branch, no access).
    let pre_receive = remote.join("hooks").join("pre-receive");
    hook(
        &pre_receive,
        "#!/bin/sh\necho 'protected branch' >&2\nexit 1\n",
    );
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let kept = a
        .save(prep, &opts, &mut w)
        .unwrap()
        .unpushed
        .expect("refused");
    assert!(kept.reason.contains("refused it"), "{kept:?}");
    assert!(
        kept.reason.contains("is branch main protected?"),
        "{kept:?}"
    );
    assert!(kept.detail.contains("protected branch"), "{kept:?}");
    assert_eq!(history_ids(&remote), std::slice::from_ref(&first));

    // Allowed again: the next run pushes all three.
    std::fs::remove_file(&pre_receive).unwrap();
    let (prep, opts) = a.prepare(1_800_002_000, &mut w);
    let fourth = a.record(prep, &opts, &mut w);
    let h = history_ids(&remote);
    assert_eq!(h.len(), 4, "{h:?}");
    assert_eq!(h[3], fourth);
    remove_all(&dir);
}

/// Runs a failed push left, when another machine pushed before them: their
/// points are added back (marked inserted) by the next pull, and pushed by
/// the next run.
#[test]
fn unpushed_runs_survive_another_machines_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("salvage");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);

    let pre_receive = remote.join("hooks").join("pre-receive");
    hook(&pre_receive, "#!/bin/sh\nexit 1\n");
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let kept = prep.run_id().to_string();
    assert!(a.save(prep, &opts, &mut w).unwrap().unpushed.is_some());
    std::fs::remove_file(&pre_receive).unwrap();
    let (prep, opts) = b.prepare(1_800_002_000, &mut w);
    let newer = b.record(prep, &opts, &mut w);

    // A's next run: the pull adds the kept run back and says so.
    let (prep, opts, note) = a.prepare_noting(1_800_003_000, &mut w);
    let note = note.expect("a note");
    assert!(
        note.starts_with(
            "1 run recorded here but not pushed before another machine pushed was added to the \
             history as earlier points"
        ),
        "{note}"
    );
    let third = a.record(prep, &opts, &mut w);
    let h = history_ids(&remote);
    assert_eq!(h.len(), 4, "{h:?}");
    assert!(h.contains(&kept) && h.contains(&newer) && h.contains(&third));
    assert!(inserted(&remote, &kept));
    assert_eq!(last_run_id(&remote), third);
    remove_all(&dir);
}

/// The same while publishing: A keeps an unpushed run (C1), records a
/// second on top (C2), and B pushes first. Both of A's runs are recorded,
/// and A is told.
#[test]
fn a_kept_run_and_a_lost_race_lose_nothing() {
    if !have_git() {
        return;
    }
    let dir = scratch("kept-race");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    let pre_receive = remote.join("hooks").join("pre-receive");
    hook(&pre_receive, "#!/bin/sh\nexit 1\n");
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let c1 = prep.run_id().to_string();
    assert!(a.save(prep, &opts, &mut w).unwrap().unpushed.is_some());
    std::fs::remove_file(&pre_receive).unwrap();

    // A's next run pulls (C1 kept), then B pushes before A does.
    let (prep, opts) = a.prepare(1_800_003_000, &mut w);
    let c2 = prep.run_id().to_string();
    let (bp, bopts) = b.prepare(1_800_002_000, &mut w);
    let newer = b.record(bp, &bopts, &mut w);
    w.0.clear();
    let saved = a.save(prep, &opts, &mut w).unwrap();
    assert!(saved.pushed, "{saved:?}");
    assert_eq!(
        w.0.iter()
            .filter(|m| m.starts_with("1 run recorded here"))
            .count(),
        1,
        "{:?}",
        w.0
    );
    let h = history_ids(&remote);
    assert_eq!(h.len(), 4, "{h:?}");
    assert!(h.contains(&c1) && h.contains(&c2) && h.contains(&newer));
    assert!(inserted(&remote, &c1));
    assert_eq!(last_run_id(&remote), c2);
    remove_all(&dir);
}

/// A remote moved back on purpose is followed: the working copy's newer
/// commits (pushed, not left by a failed push) are not pushed again.
#[test]
fn a_remote_rolled_back_stays_rolled_back() {
    if !have_git() {
        return;
    }
    let dir = scratch("rollback");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    a.record(prep, &opts, &mut w);
    git(&remote, &["update-ref", "refs/heads/main", "main~1"]);
    assert_eq!(a.store.pull().unwrap(), None);
    let (prep, opts) = a.prepare(1_800_002_000, &mut w);
    let third = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first, third]);
    remove_all(&dir);
}

/// Git locks an earlier idle stop had to keep, long stale, are removed by
/// the next pull that holds the history's lock: the fetch they would make
/// fail ("cannot lock ref") goes through.
#[test]
fn a_pull_removes_stale_git_locks_an_idle_stop_kept() {
    if !have_git() {
        return;
    }
    let dir = scratch("kept-locks");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    push_other(&dir, &remote, "other-0");
    let git_dir = dir.join("a/.git");
    let locks = [
        git_dir.join("refs/remotes/origin/main.lock"),
        git_dir.join("index.lock"),
    ];
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 60);
    for l in &locks {
        std::fs::File::create(l).unwrap().set_modified(old).unwrap();
    }
    // Without the history's lock, nothing is removed and the fetch fails.
    assert!(a.store.pull().is_err());
    assert!(locks.iter().all(|l| l.exists()));
    let lock = a.store.lock().unwrap();
    a.store.pull().unwrap();
    drop(lock);
    assert!(locks.iter().all(|l| !l.exists()));
    assert!(git(&dir.join("a"), &["log", "--oneline", "-1"]).contains("other-0"));
}

/// Other runs pushing first every time: the run gives up after four
/// rejections, with the working copy at the remote's state.
#[test]
fn a_run_gives_up_after_four_rejected_pushes() {
    if !have_git() {
        return;
    }
    let dir = scratch("give-up");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    a.store.pull().unwrap();
    std::fs::write(dir.join("a/history/x.json"), "{}\n").unwrap();
    push_other(&dir, &remote, "other-0");
    let mut n = 0;
    let e = a
        .store
        .publish_with("mine", || {
            n += 1;
            std::fs::write(dir.join("a/history/x.json"), "{}\n").unwrap();
            push_other(&dir, &remote, &format!("other-{n}"));
            Ok(Some("mine".into()))
        })
        .unwrap_err();
    assert!(format!("{e:#}").contains("first 4 times in a row"), "{e:#}");
    assert_eq!(n, 3, "applied again three times");
    let work = dir.join("a");
    assert_eq!(
        git(&work, &["rev-parse", "HEAD"]),
        git(&work, &["rev-parse", "origin/main"])
    );
    assert!(git(&work, &["status", "--porcelain"]).trim().is_empty());
    remove_all(&dir);
}

/// A change that can't be applied again leaves the working copy at the
/// remote's state, and says why.
#[test]
fn a_change_that_cant_be_applied_again_is_not_recorded() {
    if !have_git() {
        return;
    }
    let dir = scratch("reapply-err");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    a.store.pull().unwrap();
    std::fs::write(dir.join("a/history/x.json"), "{}\n").unwrap();
    push_other(&dir, &remote, "other");
    let e = a
        .store
        .publish_with("mine", || {
            std::fs::write(dir.join("a/history/x.json"), "{}\n").unwrap();
            anyhow::bail!("out of order")
        })
        .unwrap_err();
    let text = format!("{e:#}");
    assert!(text.contains("could not be applied on top of it"), "{text}");
    assert!(text.contains("out of order"), "{text}");
    let work = dir.join("a");
    assert_eq!(
        git(&work, &["rev-parse", "HEAD"]),
        git(&work, &["rev-parse", "origin/main"])
    );
    assert!(!work.join("history/x.json").exists());
    remove_all(&dir);
}

#[test]
fn two_runs_with_one_id_never_overwrite_each_other() {
    if !have_git() {
        return;
    }
    let dir = scratch("same-id");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    // Both prepared before either is recorded (a run after a recorded one
    // starts a second later, so only a race gives two runs one ID).
    let (first, first_opts) = a.prepare(1_800_000_000, &mut w);
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(first, &first_opts, &mut w);
    let e = a.save(prep, &opts, &mut w).unwrap_err();
    assert!(
        format!("{e:#}").contains("is in the history already"),
        "{e:#}"
    );
    remove_all(&dir);
}

#[test]
fn nothing_to_commit_publishes_nothing() {
    if !have_git() {
        return;
    }
    let dir = scratch("nothing");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    assert_eq!(a.store.pull().unwrap(), None);
    let called = std::cell::Cell::new(false);
    let done = a
        .store
        .publish_with("nothing", || {
            called.set(true);
            Ok(None)
        })
        .unwrap();
    assert!(!done.pushed);
    assert!(!called.get());
    remove_all(&dir);
}

/// A branch is state when it has the marker (whatever else it holds), or
/// only state files and what a host puts in a new repository.
#[test]
fn only_a_state_branch_is_used() {
    if !have_git() {
        return;
    }
    let cases: &[(&[&str], bool)] = &[
        (
            &["README.md", "LICENSE", ".gitattributes", ".gitignore"],
            true,
        ),
        (
            &["readme", "LICENCE.txt", "history/20261018T120000.000Z.json"],
            true,
        ),
        (&[".pathwarden-state", "notes/anything.txt"], true),
        (&["READMEtools/build.sh"], false),
        (&["LICENSE-src/lib.rs"], false),
        (&[".gitattributes.bak"], false),
        (&["LICENSES/MIT.txt"], false),
        (&["history/notes.txt"], false),
        (&["history/deep/20261018T120000.000Z.json"], false),
        (&["src/main.rs", "README.md"], false),
    ];
    for (i, (files, ok)) in cases.iter().enumerate() {
        let dir = scratch(&format!("branch-{i}"));
        let remote = bare(&dir);
        let seed = dir.join("seed");
        git(
            &dir,
            &[
                "clone",
                "-q",
                &remote.to_string_lossy(),
                &seed.to_string_lossy(),
            ],
        );
        for f in *files {
            let path = seed.join(f);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{}\n").unwrap();
        }
        git(&seed, &["add", "-A"]);
        git(&seed, &["commit", "-q", "-m", "seed"]);
        git(&seed, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let a = Machine::new(&remote, &dir.join("a"));
        let pulled = a.store.pull();
        assert_eq!(pulled.is_ok(), *ok, "{files:?}: {pulled:?}");
        if !ok {
            let e = format!("{:#}", pulled.unwrap_err());
            assert!(e.contains("is not Pathwarden state"), "{e}");
        }
        remove_all(&dir);
    }
}

/// A working copy cloned by hand (on another branch, or with files of its
/// own) is never reset; one Pathwarden cloned before it marked them is
/// taken over once.
#[test]
fn only_a_working_copy_pathwarden_cloned_is_reset() {
    if !have_git() {
        return;
    }
    let dir = scratch("owned");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);

    // By hand, on another branch, with work of its own.
    let manual = dir.join("manual");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &manual.to_string_lossy(),
        ],
    );
    git(&manual, &["checkout", "-q", "-b", "mine"]);
    std::fs::write(manual.join("findings.json"), "edited").unwrap();
    std::fs::write(manual.join("history/mine.json"), "{}").unwrap();
    let m = Machine::new(&remote, &manual);
    let e = format!("{:#}", m.store.pull().unwrap_err());
    assert!(e.contains("Pathwarden did not clone"), "{e}");
    assert_eq!(
        std::fs::read_to_string(manual.join("findings.json")).unwrap(),
        "edited"
    );
    assert!(manual.join("history/mine.json").exists());

    // Pathwarden's own, from before the mark: taken over, and marked, with
    // a README a host made and a temporary file a crash left.
    let work = dir.join("a");
    git(&work, &["config", "--unset", "pathwarden.workingcopy"]);
    std::fs::write(work.join("README.md"), "# state\n").unwrap();
    std::fs::write(work.join(".findings.json.4242.tmp"), "{").unwrap();
    // And the app's record of the last pull, which this version writes.
    std::fs::write(work.join(".pathwarden-last-pull.json"), "{}").unwrap();
    a.store.pull().unwrap();
    assert_eq!(
        git(&work, &["config", "--get", "pathwarden.workingcopy"]).trim(),
        "true"
    );
    remove_all(&dir);
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

/// A `.gitignore` in the state repository that leaves out the state files
/// never keeps a run out of the commit.
#[test]
fn a_gitignore_never_keeps_state_out() {
    if !have_git() {
        return;
    }
    let dir = scratch("ignored");
    let remote = bare(&dir);
    let seed = dir.join("seed");
    git(
        &dir,
        &[
            "clone",
            "-q",
            &remote.to_string_lossy(),
            &seed.to_string_lossy(),
        ],
    );
    std::fs::write(
        seed.join(".gitignore"),
        "history/*.json\ntimings/\nfindings.json\n",
    )
    .unwrap();
    git(&seed, &["add", ".gitignore"]);
    git(&seed, &["commit", "-q", "-m", "ignore"]);
    git(&seed, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    // Only the state's own files go in, ignored or not.
    std::fs::create_dir_all(dir.join("a/history")).unwrap();
    std::fs::write(dir.join("a/history/Thumbs.db"), "x").unwrap();
    std::fs::write(dir.join("a/history/desktop.ini"), "x").unwrap();
    let first = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first]);
    assert!(git(&remote, &["ls-tree", "--name-only", "main"]).contains("findings.json"));
    remove_all(&dir);
}

/// A `.gitattributes` pushed to the history that would make git run a
/// filter, diff or merge program (gap 15) stops the pull before
/// anything is checked out; line-ending attributes are fine.
#[test]
fn a_gitattributes_that_runs_programs_is_refused() {
    if !have_git() {
        return;
    }
    let dir = scratch("attributes");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    push_other_text(
        &dir,
        &remote,
        ".gitattributes",
        "# line endings\n* text=auto eol=lf\n*.age binary -diff\n",
    );
    a.store.pull().unwrap();
    for (file, text) in [
        (".gitattributes", "*.json filter=contoso\n"),
        (".gitattributes", "[attr]plain filter=contoso\n"),
        ("history/.gitattributes", "*.json diff=fabrikam\n"),
        ("history/.gitattributes", "\"a b\" merge=fabrikam\n"),
    ] {
        push_other_text(&dir, &remote, file, text);
        let e = format!("{:#}", a.store.pull().unwrap_err());
        assert!(
            e.contains(file) && e.contains("nothing was checked out"),
            "{e}"
        );
        // Removed again: the pull goes on.
        let other = dir.join("other");
        git(&other, &["rm", "-q", file]);
        git(&other, &["commit", "-q", "-m", "remove"]);
        git(&other, &["push", "-q", "origin", "HEAD:main"]);
        a.store.pull().unwrap();
    }
    remove_all(&dir);
}

/// A `findings.json` a writer pushed that can't be read (gap 9) is
/// reported, and the next run is compared with no earlier findings and
/// recorded, which repairs the file; a newer version is still refused.
#[test]
fn a_malformed_pushed_findings_state_is_reported_not_fatal() {
    if !have_git() {
        return;
    }
    let dir = scratch("malformed");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    push_other_text(
        &dir,
        &remote,
        "findings.json",
        "{\"version\": 3, \"findings\": {\"PW-0",
    );
    a.store.pull().unwrap();
    let e = format!("{:#}", a.store.load().unwrap_err());
    assert!(e.contains("findings.json can't be read"), "{e}");
    let (previous, note) = a.store.load_for_run().unwrap();
    assert!(previous.findings.is_empty());
    let note = note.unwrap();
    assert!(
        note.contains("compared with no earlier findings") && note.contains("earlier commits"),
        "{note}"
    );
    // The run goes on and is recorded.
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let ev = analyze::evaluate(&[forest], &a.config, &[], &mut w).unwrap();
    let opts = record::Options {
        started_ms: 1_800_000_100_000,
        accept_shrink: false,
        recorded_by: record::by::CLI,
        finished_at: Some(1_800_000_130),
    };
    let prev_run = store::last_run(&a.store);
    let prep = record::prepare(prev_run.as_ref(), &previous, ev, &a.config, &opts, &mut w);
    let id = a.record(prep, &opts, &mut w);
    assert_eq!(last_run_id(&remote), id);
    a.store.pull().unwrap();
    assert!(!a.store.load().unwrap().findings.is_empty());
    // A newer version is not damage: it still stops the run.
    push_other_text(
        &dir,
        &remote,
        "findings.json",
        "{\"version\": 999, \"findings\": {}}",
    );
    a.store.pull().unwrap();
    let e = format!("{:#}", a.store.load_for_run().unwrap_err());
    assert!(e.contains("newer Pathwarden"), "{e}");
    remove_all(&dir);
}

/// Kept runs newer than everything the remote has are added back as
/// inserted points, so the latest run stays the remote's (its findings
/// state is); a removal made here that was never pushed is undone, and the
/// note says so.
#[test]
fn kept_runs_newer_than_the_remote_stay_earlier_points() {
    if !have_git() {
        return;
    }
    let dir = scratch("newer-kept");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let r1 = a.record(prep, &opts, &mut w);
    let (prep, opts) = b.prepare(1_800_001_000, &mut w);
    let r2 = b.record(prep, &opts, &mut w);
    let pre_receive = remote.join("hooks").join("pre-receive");
    hook(&pre_receive, "#!/bin/sh\nexit 1\n");
    let (prep, opts) = a.prepare(1_800_002_000, &mut w);
    let r3 = prep.run_id().to_string();
    assert!(a.save(prep, &opts, &mut w).unwrap().unpushed.is_some());
    let (prep, opts) = a.prepare(1_800_003_000, &mut w);
    let r4 = prep.run_id().to_string();
    assert!(a.save(prep, &opts, &mut w).unwrap().unpushed.is_some());
    // A removes r2 here too, unpushed.
    let (removed, notes) = a.store.forget_and_publish(&r2, true).unwrap();
    assert!(removed);
    assert!(
        notes.iter().any(|n| n.starts_with(
            "The run was removed from the history here, but the change couldn't be pushed"
        )),
        "{notes:?}"
    );
    std::fs::remove_file(&pre_receive).unwrap();
    b.store.pull().unwrap();
    assert!(b.store.forget_and_publish(&r1, true).unwrap().0);

    let note = a.store.pull().unwrap().expect("a note");
    assert!(
        note.contains("2 runs recorded here but not pushed"),
        "{note}"
    );
    assert!(note.contains("as earlier points"), "{note}");
    assert!(
        note.contains("1 removal of a run made here was not pushed"),
        "{note}"
    );
    let (points, _) = history::load(&dir.join("a")).unwrap();
    let ids: Vec<&str> = points.iter().map(|p| p.run_id.as_str()).collect();
    assert_eq!(ids, [r2.as_str(), r3.as_str(), r4.as_str()]);
    assert_eq!(
        pathwarden_core::since::latest_point(&points).map(|p| p.run_id.as_str()),
        Some(r2.as_str())
    );
    assert!(
        pathwarden_core::since::latest(&points, None).is_none(),
        "r2 has no run before it"
    );
    remove_all(&dir);
}

/// A kept commit that reached the remote another way is not kept any
/// more: a later rollback of the remote is followed.
#[test]
fn a_kept_commit_pushed_another_way_is_not_pushed_again() {
    if !have_git() {
        return;
    }
    let dir = scratch("pushed-elsewhere");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    let pre_receive = remote.join("hooks").join("pre-receive");
    hook(&pre_receive, "#!/bin/sh\nexit 1\n");
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    assert!(a.save(prep, &opts, &mut w).unwrap().unpushed.is_some());
    std::fs::remove_file(&pre_receive).unwrap();
    // Pushed by hand, then pulled; then the remote is moved back.
    git(&dir.join("a"), &["push", "-q", "origin", "HEAD:main"]);
    assert_eq!(a.store.pull().unwrap(), None);
    git(&remote, &["update-ref", "refs/heads/main", "main~1"]);
    assert_eq!(a.store.pull().unwrap(), None);
    assert_eq!(history_ids(&remote), std::slice::from_ref(&first));
    let (prep, opts) = a.prepare(1_800_002_000, &mut w);
    let third = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first, third]);
    remove_all(&dir);
}

/// A clone stopped halfway by an older version (the idle limit, Ctrl+C, a
/// power cut) left a marked working copy with origin's URL but no fetch
/// refspec: the next run fetches the state's branch anyway and records.
/// A clone that fails now leaves nothing behind, and an unfinished one
/// in the folder is cleared.
#[test]
fn a_clone_stopped_halfway_never_blocks_the_next_run() {
    if !have_git() {
        return;
    }
    let dir = scratch("half-clone");
    let remote = bare(&dir);
    let b = Machine::new(&remote, &dir.join("b"));
    let mut w = Warnings::default();
    let (prep, opts) = b.prepare(1_800_000_000, &mut w);
    let first = b.record(prep, &opts, &mut w);

    let work = dir.join("a");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    git(&work, &["config", "pathwarden.workingcopy", "true"]);
    git(
        &work,
        &[
            "config",
            "remote.origin.url",
            &remote.to_string_lossy().replace('\\', "/"),
        ],
    );
    let a = Machine::new(&remote, &work);
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let second = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first.clone(), second.clone()]);
    assert!(git(&work, &["config", "--get", "remote.origin.fetch"]).contains("refs/heads/*"));

    // A remote that isn't there: the clone fails and leaves nothing; a
    // folder the run made is removed again, one made beforehand is kept,
    // emptied of the unfinished clone a run before left in it.
    let missing = Machine::new(&dir.join("missing.git"), &dir.join("c"));
    assert!(missing.store.pull().is_err());
    assert!(!dir.join("c").exists());
    // The same with the run's lock held, which made the folder.
    let lock = missing.store.lock().unwrap();
    assert!(missing.store.pull().is_err());
    drop(lock);
    assert!(!dir.join("c").exists());
    // Parent folders it made on the way go too, with the lock held or
    // not; one that was there already stays.
    std::fs::create_dir_all(dir.join("p")).unwrap();
    let nested = Machine::new(&dir.join("missing.git"), &dir.join("p/q/r/state"));
    assert!(nested.store.pull().is_err());
    assert!(!dir.join("p/q").exists());
    let lock = nested.store.lock().unwrap();
    assert!(nested.store.pull().is_err());
    drop(lock);
    assert!(!dir.join("p/q").exists());
    assert!(dir.join("p").is_dir());
    // A parent that holds something else meanwhile is kept.
    let lock = nested.store.lock().unwrap();
    std::fs::write(dir.join("p/q/mine.txt"), "x").unwrap();
    assert!(nested.store.pull().is_err());
    drop(lock);
    assert!(!dir.join("p/q/r").exists());
    assert!(dir.join("p/q/mine.txt").is_file());
    let leftover = dir.join("e/.pathwarden-cloning");
    std::fs::create_dir_all(leftover.join(".git/objects")).unwrap();
    let missing = Machine::new(&dir.join("missing.git"), &dir.join("e"));
    assert!(missing.store.pull().is_err());
    assert!(dir.join("e").is_dir());
    assert!(!leftover.exists());
    assert_eq!(std::fs::read_dir(dir.join("e")).unwrap().count(), 0);
    // An unfinished clone left in the folder is cleared and the next run
    // records; a good clone leaves no clone folder behind.
    let leftover = dir.join("d/.pathwarden-cloning");
    std::fs::create_dir_all(leftover.join(".git/objects")).unwrap();
    std::fs::write(
        leftover.join(".git/HEAD"),
        "ref: refs/heads/main
",
    )
    .unwrap();
    let d = Machine::new(&remote, &dir.join("d"));
    let (prep, opts) = d.prepare(1_800_002_000, &mut w);
    let third = d.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first, second, third]);
    assert!(dir.join("d/.git").exists());
    assert!(!leftover.exists());
    remove_all(&dir);
}

/// A state folder the operator set up beforehand is used as it is, never
/// replaced: an account given write access to it alone (what
/// setup-folder.ps1 does for the scheduled task's gMSA) keeps it after the
/// first clone.
#[test]
fn a_state_folder_set_up_beforehand_keeps_its_permissions() {
    if !have_git() {
        return;
    }
    let dir = scratch("acl");
    let remote = bare(&dir);
    let work = dir.join("wa");
    std::fs::create_dir_all(&work).unwrap();
    #[cfg(windows)]
    {
        // LOCAL SERVICE (S-1-5-19, "LS" in SDDL) given Modify.
        let ok = Command::new("icacls")
            .arg(&work)
            .args(["/grant", "*S-1-5-19:(OI)(CI)M", "/Q"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "icacls /grant");
        let has_grant = |p: &Path| sddl(p).contains("(A;OICI;0x1301bf;;;LS)");
        assert!(has_grant(&work), "{}", sddl(&work));
        assert!(!has_grant(&dir), "the parent has no such grant");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    let a = Machine::new(&remote, &work);
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first]);
    #[cfg(windows)]
    assert!(
        sddl(&work).contains("(A;OICI;0x1301bf;;;LS)"),
        "{}",
        sddl(&work)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&work).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o750);
    }
    remove_all(&dir);
}

/// A folder's security descriptor, in SDDL.
#[cfg(windows)]
fn sddl(path: &Path) -> String {
    // A PowerShell 7 parent (as on CI runners) leaves its module path
    // behind, and Windows PowerShell then can't load Get-Acl.
    let out = Command::new("powershell")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "(Get-Acl -LiteralPath '{}').Sddl",
            path.to_string_lossy().replace('\'', "''")
        ))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "Get-Acl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A state folder that is a link (a junction on Windows, a symbolic link
/// elsewhere) the operator set up to an empty folder: the state goes into
/// its target, and the link stays a link.
#[test]
fn a_linked_state_folder_gets_the_state_in_its_target() {
    if !have_git() {
        return;
    }
    let dir = scratch("linked");
    let remote = bare(&dir);
    let target = dir.join("jt");
    let link = dir.join("wj");
    std::fs::create_dir_all(&target).unwrap();
    #[cfg(windows)]
    {
        let ok = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "mklink /J");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let a = Machine::new(&remote, &link);
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), std::slice::from_ref(&first));
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "still a link"
    );
    assert!(target.join(".git").is_dir());
    assert!(target.join(format!("history/{first}.json")).is_file());
    // The next run uses it as it is.
    let (prep, opts) = a.prepare(1_800_001_000, &mut w);
    let second = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first, second]);
    remove_all(&dir);
}

/// A run point git can't stage (a file an antivirus or indexer holds open)
/// stops the commit: the rest of the state never goes in without it.
#[test]
fn a_point_that_cant_be_staged_stops_the_commit() {
    if !have_git() {
        return;
    }
    let dir = scratch("unstageable");
    let remote = bare(&dir);
    let a = Machine::new(&remote, &dir.join("a"));
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    let before = git(&remote, &["rev-parse", "main"]);

    let point = dir.join("a/history/20261022T120000.000Z.json");
    std::fs::write(&point, "{}\n").unwrap();
    std::fs::write(dir.join("a/last-run.json"), "{}\n").unwrap();
    let Some(_held) = hold(&point) else {
        eprintln!("cannot make a file unreadable here; skipping");
        remove_all(&dir);
        return;
    };
    let e = a.store.publish_with("held", || Ok(None)).unwrap_err();
    let e = format!("{e:#}");
    assert!(
        e.contains("staging ") && e.contains("history/*.json"),
        "{e}"
    );
    assert_eq!(git(&remote, &["rev-parse", "main"]), before);
    assert_eq!(history_ids(&remote), [first]);
    drop(_held);
    remove_all(&dir);
}

/// Keeps `path` from being read while the result lives: opened with no
/// sharing on Windows, made unreadable on Unix (None as root, who reads
/// it anyway).
fn hold(path: &Path) -> Option<impl Drop> {
    struct Held(PathBuf, #[allow(dead_code)] Option<std::fs::File>);
    impl Drop for Held {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644));
            }
            let _ = &self.0;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .ok()?;
        Some(Held(path.to_path_buf(), Some(f)))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).ok()?;
        let held = Held(path.to_path_buf(), None);
        if std::fs::read(path).is_ok() {
            return None;
        }
        Some(held)
    }
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

/// A state folder set up beforehand in a folder the run may not write to
/// (setup-folder.ps1 gives the scheduled task's gMSA Read & Execute on
/// `C:\Pathwarden` and Modify on `pathwarden-state` only): the first clone
/// and the next run both record. Nothing, the lock included, is written
/// beside the state folder.
#[test]
fn a_state_folder_in_a_read_only_folder_is_used() {
    if !have_git() {
        return;
    }
    let dir = scratch("ro-parent");
    let remote = bare(&dir);
    let parent = dir.join("program");
    let work = parent.join("pathwarden-state");
    std::fs::create_dir_all(&work).unwrap();
    let Some(read_only) = ReadOnlyDir::new(&parent) else {
        eprintln!("cannot make a folder read-only here; skipping");
        remove_all(&dir);
        return;
    };
    assert!(
        std::fs::write(parent.join("probe"), "x").is_err(),
        "the parent is read-only"
    );
    let a = Machine::new(&remote, &work);
    let mut w = Warnings::default();
    let mut runs = Vec::new();
    for at in [1_800_000_000, 1_800_001_000] {
        let lock = a.store.lock().unwrap();
        let (prep, opts) = a.prepare(at, &mut w);
        runs.push(a.record(prep, &opts, &mut w));
        drop(lock);
    }
    assert_eq!(history_ids(&remote), runs);
    assert!(!work.join(".pathwarden.lock").exists(), "released");
    let beside: Vec<_> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(beside, ["pathwarden-state"], "nothing beside the folder");
    drop(read_only);
    remove_all(&dir);
}

/// The run's lock, inside the state folder, is never committed or listed
/// by `git status`, and the reset of a dirty working copy keeps it. A
/// remote branch that holds a file of that name is refused, and the lock
/// is left as it was.
#[test]
fn the_lock_inside_the_state_folder_is_never_committed_or_reset() {
    if !have_git() {
        return;
    }
    let dir = scratch("lock-inside");
    let remote = bare(&dir);
    let work = dir.join("a");
    let a = Machine::new(&remote, &work);
    let mut w = Warnings::default();
    let lock = a.store.lock().unwrap();
    let file = work.join(".pathwarden.lock");
    let held = std::fs::read_to_string(&file).unwrap();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    let first = a.record(prep, &opts, &mut w);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), held);
    assert_eq!(
        git(&work, &["status", "--porcelain", "--untracked-files=all"]),
        ""
    );

    // A dirty working copy is reset to the remote; the lock stays.
    std::fs::write(work.join("findings.json"), "not json").unwrap();
    std::fs::write(work.join("history/stray.json"), "{}").unwrap();
    let (prep, opts, note) = a.prepare_noting(1_800_001_000, &mut w);
    assert!(note.is_some_and(|n| n.contains("1 run point")));
    assert!(!work.join("history/stray.json").exists());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), held);
    let second = a.record(prep, &opts, &mut w);
    assert_eq!(history_ids(&remote), [first, second]);
    let tree = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tree.contains(".pathwarden.lock"), "{tree}");

    // The take-over's guard beside it is never listed either.
    std::fs::write(work.join(".pathwarden.lock.taking"), "").unwrap();
    assert_eq!(
        git(&work, &["status", "--porcelain", "--untracked-files=all"]),
        ""
    );
    std::fs::remove_file(work.join(".pathwarden.lock.taking")).unwrap();

    // A remote that commits a file of the lock's name, or the guard's, is
    // refused.
    push_other(&dir, &remote, ".pathwarden.lock.taking");
    let e = a.store.pull().unwrap_err();
    assert!(
        format!("{e:#}").contains(".pathwarden.lock.taking"),
        "{e:#}"
    );
    git(&dir.join("other"), &["rm", "-q", ".pathwarden.lock.taking"]);
    git(&dir.join("other"), &["commit", "-q", "-m", "undo"]);
    git(&dir.join("other"), &["push", "-q", "origin", "HEAD:main"]);
    push_other(&dir, &remote, ".pathwarden.lock");
    let e = a.store.pull().unwrap_err();
    assert!(format!("{e:#}").contains(".pathwarden.lock"), "{e:#}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), held);
    drop(lock);
    assert!(!file.exists(), "released");
    remove_all(&dir);
}

/// An older Pathwarden kept a git state folder's lock beside the folder
/// (`<folder>.lock`). One that is fresh (an older version still running)
/// refuses the run, and is never removed; a stale one is ignored, and left.
#[test]
fn a_lock_an_older_version_holds_beside_the_folder_is_respected() {
    if !have_git() {
        return;
    }
    let dir = scratch("old-lock");
    let remote = bare(&dir);
    let work = dir.join("a");
    let old = dir.join("a.lock");
    std::fs::write(&old, "host other pid 1 token x\n").unwrap();
    let a = Machine::new(&remote, &work);
    let e = a
        .store
        .lock()
        .err()
        .expect("refused while an older run holds it");
    assert!(format!("{e:#}").contains("host other pid 1"), "{e:#}");
    assert!(old.exists(), "never removed");
    assert!(!work.exists(), "nothing left inside");
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 3600);
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(stale)
        .unwrap();
    let lock = a.store.lock().unwrap();
    let mut w = Warnings::default();
    let (prep, opts) = a.prepare(1_800_000_000, &mut w);
    a.record(prep, &opts, &mut w);
    drop(lock);
    assert!(old.exists(), "a lock this run didn't take is left");
    remove_all(&dir);
}

/// Keeps this user from making files or folders in a folder while it lives
/// (a deny entry on Windows, mode 555 on Unix; None as root, who may write
/// anyway). Restored on drop, a failed test's too.
struct ReadOnlyDir {
    path: PathBuf,
    #[cfg(windows)]
    sid: String,
}

impl ReadOnlyDir {
    fn new(path: &Path) -> Option<Self> {
        #[cfg(windows)]
        {
            let out = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let sid = text
                .trim()
                .rsplit(',')
                .next()?
                .trim_matches('"')
                .to_string();
            if !sid.starts_with("S-1-") {
                return None;
            }
            let ok = Command::new("icacls")
                .arg(path)
                .args(["/deny", &format!("*{sid}:(WD,AD)"), "/Q"])
                .stdout(std::process::Stdio::null())
                .status()
                .ok()?
                .success();
            assert!(ok, "icacls /deny");
            Some(ReadOnlyDir {
                path: path.to_path_buf(),
                sid,
            })
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let uid = Command::new("id").arg("-u").output().ok()?;
            if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
                return None;
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).ok()?;
            Some(ReadOnlyDir {
                path: path.to_path_buf(),
            })
        }
    }
}

impl Drop for ReadOnlyDir {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let _ = Command::new("icacls")
                .arg(&self.path)
                .args(["/remove:d", &format!("*{}", self.sid), "/Q"])
                .stdout(std::process::Stdio::null())
                .status();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o755));
        }
    }
}
