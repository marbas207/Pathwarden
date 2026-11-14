//! Full runs in the history: with "Full runs and
//! settings", each recorded run also goes into the history in full
//! (`runs/<run ID>/`), in a commit of its own after its point's. Two
//! machines racing on one bare repository, forgetting a run, a file over
//! the limit, the latest N kept, an encrypted history (nothing about a run
//! in plain text in any git object), and what an older Pathwarden does on
//! the same branch. Remotes are local bare repositories; passphrases are
//! given in-process and the keystore is a test folder.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::analyze::{self, Phase, Progress};
use pathwarden_core::config::{Config, Keep, StateBackend, StateConfig};
use pathwarden_core::crypt::{self, SecretString};
use pathwarden_core::keystore;
use pathwarden_core::record::{self, RecordProgress};
use pathwarden_core::store::{self, Store};
use pathwarden_ui::shared_runs::{self, Bundle, Manifest, Parts, Published};
use pathwarden_ui::workspace::{HistoryLink, RunSummary};

const PASS: &str = "correct horse battery staple";

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

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-fullruns-{name}-{}", std::process::id()));
    remove_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Never this account's own credential store or records.
    keystore::use_test_store(&std::env::temp_dir().join(format!(
        "pathwarden-fullruns-keystore-{}",
        std::process::id()
    )));
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
    fn git(remote: &Path, work: &Path, kept: Option<usize>) -> Self {
        Machine::with(
            StateConfig {
                backend: StateBackend::Git,
                remote: Some(remote.to_string_lossy().replace('\\', "/")),
                keep: Some(Keep::Full),
                full_runs_kept: kept,
                ..StateConfig::default()
            },
            work,
        )
    }

    fn folder(dir: &Path) -> Self {
        Machine::with(
            StateConfig {
                keep: Some(Keep::Full),
                ..StateConfig::default()
            },
            dir,
        )
    }

    fn with(state: StateConfig, dir: &Path) -> Self {
        let config = Config {
            state: state.clone(),
            ..Config::default()
        };
        Machine {
            store: Store::new(&state, Some(dir)).unwrap(),
            config,
        }
    }

    /// Records a run started at `at` (seconds) as `pathwarden run` does:
    /// its point, pushed; and returns the run ready for its full run.
    fn record_point(&self, at: i64) -> record::Prepared {
        let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        self.record_point_from(at, &forest)
    }

    /// [`Machine::record_point`] of the collection at `input`.
    fn record_point_from(&self, at: i64, input: &Path) -> record::Prepared {
        let mut w = Warnings::default();
        self.store.pull().unwrap();
        let previous = self.store.load().unwrap();
        let ev = analyze::evaluate(&[input], &self.config, &[], &mut w).unwrap();
        let opts = record::Options {
            started_ms: at * 1000,
            accept_shrink: false,
            recorded_by: record::by::SCHEDULE,
            finished_at: Some(at + 30),
        };
        let prev_run = store::last_run(&self.store);
        let prep = record::prepare(
            prev_run.as_ref(),
            &previous,
            ev,
            &self.config,
            &opts,
            &mut w,
        );
        let (prep, saved) =
            record::save_and_publish(&self.store, prep, &self.config, &opts, None, true, &mut w);
        let saved = saved.unwrap();
        if self.store.is_git() {
            assert!(saved.pushed, "{saved:?}");
        }
        prep
    }

    fn bundle(&self, prep: &record::Prepared, limit: u64) -> Bundle {
        bundle_of(prep, limit)
    }

    fn publish(&self, bundles: &[Bundle]) -> Published {
        shared_runs::publish(
            &self.store,
            bundles,
            self.config.state.full_runs_kept(),
            true,
        )
        .unwrap()
    }

    /// A run and its full run, both pushed: its run ID.
    fn record(&self, at: i64) -> String {
        let prep = self.record_point(at);
        let p = self.publish(&[self.bundle(&prep, shared_runs::MAX_FILE_BYTES)]);
        assert_eq!(p.shared, [prep.run_id().to_string()], "{p:?}");
        if self.store.is_git() {
            assert!(p.pushed, "{p:?}");
        }
        prep.run_id().to_string()
    }
}

/// The full run of a recorded run, as `pathwarden run` builds it.
fn bundle_of(prep: &record::Prepared, limit: u64) -> Bundle {
    bundle_with(prep, limit, |_, _| {})
}

/// [`bundle_of`], its summary and report changed by `change` first (what a
/// writer who controls them could put in).
fn bundle_with(
    prep: &record::Prepared,
    limit: u64,
    change: impl FnOnce(&mut RunSummary, &mut String),
) -> Bundle {
    bundle_changed(prep, limit, change, |_| {})
}

/// [`bundle_with`], its event document changed by `change_event` too.
fn bundle_changed(
    prep: &record::Prepared,
    limit: u64,
    change: impl FnOnce(&mut RunSummary, &mut String),
    change_event: impl FnOnce(&mut serde_json::Value),
) -> Bundle {
    bundle_files(prep, limit, change, change_event, |_| {})
}

/// The object index of `extra` padded to `bytes` or more on disk: the same
/// index, gzipped without compression, with spaces after it (a large
/// forest's index without its objects).
fn pad_objects(extra: &mut [(&str, Vec<u8>)], bytes: usize) {
    use std::io::Write as _;
    let (_, gz) = extra
        .iter_mut()
        .find(|(n, _)| *n == pathwarden_ui::run_data::OBJECTS_FILE)
        .unwrap();
    let mut json = gunzip(gz);
    json.resize(json.len().max(bytes), b' ');
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    enc.write_all(&json).unwrap();
    *gz = enc.finish().unwrap();
    assert!(gz.len() >= bytes);
}

/// [`bundle_changed`], the run's files changed by `change_extra` too.
fn bundle_files(
    prep: &record::Prepared,
    limit: u64,
    change: impl FnOnce(&mut RunSummary, &mut String),
    change_event: impl FnOnce(&mut serde_json::Value),
    change_extra: impl FnOnce(&mut Vec<(&'static str, Vec<u8>)>),
) -> Bundle {
    use std::io::Write as _;
    let a = &prep.analysis;
    let run_id = prep.run_id();
    let mut html = a.report_html(prep.finished, &mut Warnings::default());
    let mut summary = RunSummary::new(
        "20261009-021000-1a2b3c",
        prep.finished,
        r"C:\Users\ann.smith\collections\contoso.zip".into(),
        false,
        a,
    );
    summary.history = Some(HistoryLink {
        run_id: Some(run_id.to_string()),
        warnings: vec![r"removed from C:\Users\ann.smith\state".into()],
        ..HistoryLink::default()
    });
    summary.environment = Some("env-local-id".into());
    change(&mut summary, &mut html);
    let mut extra =
        pathwarden_ui::run_data::files_for(run_id, a, prep.finished, &Default::default());
    if let Some((_, bytes)) = extra
        .iter_mut()
        .find(|(name, _)| *name == pathwarden_ui::run_data::EVENT_FILE)
    {
        let mut event: serde_json::Value = serde_json::from_slice(&gunzip(bytes)).unwrap();
        change_event(&mut event);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&serde_json::to_vec(&event).unwrap()).unwrap();
        *bytes = gz.finish().unwrap();
    }
    change_extra(&mut extra);
    Bundle::build(
        Parts {
            run_id,
            summary: &summary,
            report_html: &html,
            extra,
            config_text: Some(
                "tier_zero = [\"S-1-5-21-1-2-3-1105\"]\n\n[state]\nbackend = \"git\"\nremote = \"C:/secret/remote.git\"\n\n[[output]]\nplugin = \"jira\"\ntoken_env = \"X\"\n",
            ),
            recorded_from: record::by::SCHEDULE,
            folder: None,
        },
        limit,
    )
}

/// The files of `runs/<id>/` on the remote's branch.
fn remote_bundle(remote: &Path, id: &str) -> Vec<String> {
    git(
        remote,
        &["ls-tree", "--name-only", "main", &format!("runs/{id}/")],
    )
    .lines()
    .map(|l| l.rsplit('/').next().unwrap().to_string())
    .collect()
}

fn remote_bundles(remote: &Path) -> Vec<String> {
    let mut out: Vec<String> = git(remote, &["ls-tree", "--name-only", "main", "runs/"])
        .lines()
        .map(|l| l.trim_start_matches("runs/").to_string())
        .collect();
    out.sort();
    out
}

fn remote_points(remote: &Path) -> Vec<String> {
    git(remote, &["ls-tree", "--name-only", "main", "history/"])
        .lines()
        .map(|l| {
            l.trim_start_matches("history/")
                .trim_end_matches(".json")
                .to_string()
        })
        .collect()
}

fn remote_file(remote: &Path, path: &str) -> Vec<u8> {
    let out = git_command()
        .arg("-C")
        .arg(remote)
        .args(["show", &format!("main:{path}")])
        .output()
        .unwrap();
    assert!(out.status.success(), "{path}");
    out.stdout
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_full_run_follows_its_point_in_a_commit_of_its_own() {
    if !have_git() {
        return;
    }
    let dir = scratch("first");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let id = a.record(1_800_000_000);

    let files = remote_bundle(&remote, &id);
    for f in [
        "run.json",
        "summary.json",
        "report.html.gz",
        "graph.bin.gz",
        "objects.json.gz",
        "event.json.gz",
        "retest.json.gz",
        "settings.toml",
    ] {
        assert!(files.contains(&f.to_string()), "{f} in {files:?}");
    }
    // The point first, then the full run, each a commit.
    let log = git(&remote, &["log", "--format=%s", "main"]);
    let subjects: Vec<&str> = log.lines().collect();
    assert!(
        subjects[0].starts_with(&format!("pathwarden run {id}: full run (")),
        "{subjects:?}"
    );
    assert!(
        subjects[1].starts_with(&format!("pathwarden run {id}: ")) && subjects[1].contains(" new"),
        "{subjects:?}"
    );

    // The manifest: who, where, how, with which Pathwarden; every file with
    // its size and hash.
    let m: Manifest =
        serde_json::from_slice(&remote_file(&remote, &format!("runs/{id}/run.json"))).unwrap();
    let me = pathwarden_core::identity::Actor::current();
    assert_eq!(m.schema, shared_runs::SCHEMA);
    assert_eq!(m.format, shared_runs::FORMAT);
    assert_eq!(m.run_id, id);
    assert_eq!(m.recorded_by, me.user);
    assert_eq!(m.recorded_on, me.computer);
    assert_eq!(m.recorded_from, "schedule");
    assert_eq!(m.pathwarden, env!("CARGO_PKG_VERSION"));
    assert!(m.left_out.is_empty());
    for f in &m.files {
        let bytes = remote_file(&remote, &format!("runs/{id}/{}", f.name));
        assert_eq!(bytes.len() as u64, f.bytes, "{}", f.name);
        assert_eq!(sha256(&bytes), f.sha256, "{}", f.name);
    }
    // The report is the run's. (Its gzip header is the one the encrypted
    // history's scan looks for.)
    let gz = remote_file(&remote, &format!("runs/{id}/report.html.gz"));
    assert!(gz.starts_with(&[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]));
    let report = gunzip(&gz);
    assert!(String::from_utf8_lossy(&report).contains("CONTOSO"));

    // Nothing of the recording computer's own: no folders, no local
    // environment ID, no history notes; settings without [state] or
    // plugins.
    let summary =
        String::from_utf8(remote_file(&remote, &format!("runs/{id}/summary.json"))).unwrap();
    assert!(!summary.contains("ann.smith"), "{summary}");
    assert!(!summary.contains("env-local-id"), "{summary}");
    let s: RunSummary = serde_json::from_str(&summary).unwrap();
    assert_eq!(s.source, "contoso.zip");
    assert_eq!(s.history.unwrap().run_id.as_deref(), Some(id.as_str()));
    let settings =
        String::from_utf8(remote_file(&remote, &format!("runs/{id}/settings.toml"))).unwrap();
    assert!(settings.contains("S-1-5-21-1-2-3-1105"), "{settings}");
    for never in ["[state]", "secret", "[[output]]", "jira"] {
        assert!(!settings.contains(never), "{never} in {settings}");
    }
    assert_eq!(
        m.settings_sha256.as_deref(),
        Some(sha256(settings.as_bytes()).as_str())
    );
    remove_all(&dir);
}

#[test]
fn two_machines_race_and_both_full_runs_are_kept() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let b = Machine::git(&remote, &dir.join("b"), None);
    // A records its point; B records a newer point on top of it; then A's
    // full run meets B's push and is written again on top of it.
    let a_run = a.record_point(1_800_000_000);
    let b_run = b.record_point(1_800_001_000);
    let pa = a.publish(&[a.bundle(&a_run, shared_runs::MAX_FILE_BYTES)]);
    assert!(pa.pushed, "{pa:?}");
    assert_eq!(pa.shared, [a_run.run_id().to_string()]);
    let pb = b.publish(&[b.bundle(&b_run, shared_runs::MAX_FILE_BYTES)]);
    assert!(pb.pushed, "{pb:?}");

    let (ida, idb) = (a_run.run_id().to_string(), b_run.run_id().to_string());
    assert_eq!(remote_points(&remote), [ida.clone(), idb.clone()]);
    assert_eq!(remote_bundles(&remote), [ida.clone(), idb.clone()]);
    for id in [&ida, &idb] {
        assert!(remote_bundle(&remote, id).contains(&"run.json".to_string()));
    }
    // A's full run went in after B's point: nothing was lost or merged.
    let log = git(&remote, &["log", "--format=%s", "main"]);
    let subjects: Vec<&str> = log.lines().collect();
    assert!(subjects[0].starts_with(&format!("pathwarden run {idb}: full run")));
    assert!(subjects[1].starts_with(&format!("pathwarden run {ida}: full run")));
    assert!(subjects[2].starts_with(&format!("pathwarden run {idb}: ")));
    remove_all(&dir);
}

#[test]
fn forgetting_a_run_removes_its_full_run() {
    if !have_git() {
        return;
    }
    let dir = scratch("forget");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let first = a.record(1_800_000_000);
    let second = a.record(1_800_001_000);
    let _lock = a.store.lock().unwrap();
    a.store.pull().unwrap();
    let (removed, notes) = a.store.forget_and_publish(&first, true).unwrap();
    assert!(removed && notes.is_empty(), "{notes:?}");
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&second));
    assert_eq!(remote_points(&remote), [second]);
    assert!(!dir.join("a").join("runs").join(&first).exists());
    remove_all(&dir);
}

#[test]
fn a_file_over_the_limit_is_left_out_and_named() {
    if !have_git() {
        return;
    }
    let dir = scratch("limit");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let prep = a.record_point(1_800_000_000);
    let id = prep.run_id().to_string();
    // A limit the report and event are over, the smaller files under.
    let limit = 4 * 1024;
    let bundle = a.bundle(&prep, limit);
    let left: Vec<String> = bundle
        .manifest
        .left_out
        .iter()
        .map(|l| l.name.clone())
        .collect();
    assert!(left.iter().any(|l| l == "report.html.gz"), "{left:?}");
    assert!(left.iter().any(|l| l == "event.json.gz"), "{left:?}");
    for l in &bundle.manifest.left_out {
        assert!(l.bytes > limit, "{l:?}");
        assert!(l.why.contains("per-file limit"), "{l:?}");
    }
    let p = a.publish(&[bundle]);
    assert!(p.pushed && p.shared == [id.clone()], "{p:?}");
    let files = remote_bundle(&remote, &id);
    assert!(files.contains(&"run.json".to_string()));
    assert!(files.contains(&"summary.json".to_string()));
    assert!(!files.contains(&"report.html.gz".to_string()), "{files:?}");
    assert!(!files.contains(&"event.json.gz".to_string()), "{files:?}");
    assert!(files.contains(&"graph.bin.gz".to_string()), "{files:?}");
    let m: Manifest =
        serde_json::from_slice(&remote_file(&remote, &format!("runs/{id}/run.json"))).unwrap();
    assert_eq!(
        m.left_out
            .iter()
            .map(|l| l.name.clone())
            .collect::<Vec<_>>(),
        left
    );
    // The point is there whatever the full run holds.
    assert_eq!(remote_points(&remote), std::slice::from_ref(&id));

    // Published again with room for everything: the files come in, and
    // nothing is named as left out.
    let _lock = a.store.lock().unwrap();
    let again = shared_runs::publish(
        &a.store,
        &[a.bundle(&prep, shared_runs::MAX_FILE_BYTES)],
        50,
        true,
    )
    .unwrap();
    assert!(again.pushed, "{again:?}");
    assert!(remote_bundle(&remote, &id).contains(&"report.html.gz".to_string()));
    // And with a small limit again, the file it now leaves out is removed.
    let shrunk = shared_runs::publish(&a.store, &[a.bundle(&prep, limit)], 50, true).unwrap();
    assert!(shrunk.pushed, "{shrunk:?}");
    assert!(!remote_bundle(&remote, &id).contains(&"report.html.gz".to_string()));
    remove_all(&dir);
}

#[test]
fn the_latest_full_runs_are_kept_and_orphans_removed() {
    if !have_git() {
        return;
    }
    let dir = scratch("keep");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), Some(2));
    let r1 = a.record(1_800_000_000);
    let r2 = a.record(1_800_001_000);
    let r3 = a.record(1_800_002_000);
    // The two latest in full; every point stays.
    assert_eq!(remote_bundles(&remote), [r2.clone(), r3.clone()]);
    assert_eq!(remote_points(&remote), [r1.clone(), r2.clone(), r3.clone()]);
    let log = git(&remote, &["log", "-1", "--format=%s", "main"]);
    assert!(log.contains("1 older full run removed"), "{log}");

    // An older run recorded late (another machine's, kept unpushed): its
    // point goes in, its full run doesn't, and the publish says why.
    let late = a.record_point(1_799_000_000);
    let p = a.publish(&[a.bundle(&late, shared_runs::MAX_FILE_BYTES)]);
    assert!(p.shared.is_empty(), "{p:?}");
    assert!(p.skipped[0].1.contains("older than the latest 2"), "{p:?}");
    assert_eq!(remote_bundles(&remote), [r2.clone(), r3.clone()]);

    // An older Pathwarden forgets r3: only its point goes (it doesn't know
    // full runs). The next full run removes the orphan.
    let other = dir.join("old");
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
    git(&other, &["rm", "-q", &format!("history/{r3}.json")]);
    git(&other, &["commit", "-q", "-m", "pathwarden: remove run"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    assert_eq!(remote_bundles(&remote), [r2.clone(), r3.clone()]);
    let r4 = a.record(1_800_003_000);
    assert_eq!(remote_bundles(&remote), [r2, r4]);
    remove_all(&dir);
}

#[test]
fn a_folder_history_keeps_full_runs_too() {
    let dir = scratch("folder");
    let state = dir.join("state");
    let a = Machine::folder(&state);
    let id = a.record(1_800_000_000);
    let m: Manifest = serde_json::from_slice(
        &std::fs::read(state.join("runs").join(&id).join("run.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(m.run_id, id);
    assert!(state.join("runs").join(&id).join("graph.bin.gz").is_file());
    // Forgotten, it goes with its point.
    assert!(a.store.forget(&id).unwrap());
    assert!(!state.join("runs").join(&id).exists());
    remove_all(&dir);
}

#[test]
fn a_pull_drops_a_full_run_no_commit_holds() {
    if !have_git() {
        return;
    }
    let dir = scratch("crash");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let prep = a.record_point(1_800_000_000);
    // A crash between writing the full run and committing it.
    let id = prep.run_id();
    a.store.write_bundle_file(id, "run.json", b"{}").unwrap();
    assert!(dir.join("a/runs").join(id).join("run.json").is_file());
    a.store.pull().unwrap();
    assert!(!dir.join("a/runs").join(id).exists());
    // Only the names a full run may hold go through the seam.
    for bad in ["notes.txt", "../x.json", "sub/run.json"] {
        assert!(a.store.write_bundle_file(id, bad, b"x").is_err(), "{bad}");
    }
    assert!(a.store.write_bundle_file("../x", "run.json", b"x").is_err());
    remove_all(&dir);
}

/// What must never be readable in an encrypted history's git objects: the
/// domain and its objects, the report, the manifest, the recorder, the
/// full run's size in a commit message, and the gzip files themselves.
fn assert_nothing_plain(objects: &[u8]) {
    let text = String::from_utf8_lossy(objects).to_ascii_lowercase();
    let me = pathwarden_core::identity::Actor::current();
    let mut secrets: Vec<String> = [
        "contoso",
        "s-1-5-21",
        "<html",
        "<!doctype",
        "pathwarden.run-bundle",
        "recorded_by",
        "full run (",
        "schedule",
        "tier_zero",
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
    // No gzip member in the clear (a plain report.html.gz or graph).
    assert!(
        // The whole header our gzip files start with (magic, deflate, no
        // flags, no time): 3 bytes alone turn up in ciphertext by chance.
        !objects
            .windows(8)
            .any(|w| w == [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]),
        "a gzip file is in the git objects in plain form"
    );
}

#[test]
fn an_encrypted_history_keeps_every_full_run_file_encrypted() {
    if !have_git() {
        return;
    }
    let dir = scratch("enc");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    // Encrypted from the first commit.
    a.store
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    crypt::give_passphrase(&a.store.dir, SecretString::from(PASS.to_string()));
    let id = a.record(1_800_000_000);

    let files = remote_bundle(&remote, &id);
    assert!(!files.is_empty());
    for f in &files {
        assert!(f.ends_with(".age"), "{f} is plain");
        let bytes = remote_file(&remote, &format!("runs/{id}/{f}"));
        assert!(bytes.starts_with(b"age-encryption.org/v1\n"), "{f}");
    }
    // Read back through the seam.
    let m: Manifest =
        serde_json::from_slice(&a.store.read_bundle_file(&id, "run.json").unwrap().unwrap())
            .unwrap();
    assert_eq!(m.run_id, id);
    // Every commit names nobody and says only the run ID.
    let log = git(
        &remote,
        &["log", "--format=%an <%ae>|%cn <%ce>|%B%x1e", "main"],
    );
    for entry in log.split('\u{1e}').filter(|e| !e.trim().is_empty()) {
        assert!(
            entry
                .trim_start()
                .starts_with("Pathwarden <pathwarden@invalid>|Pathwarden <pathwarden@invalid>|"),
            "{entry}"
        );
    }
    assert!(log.contains(&format!("pathwarden run {id}\n")), "{log}");
    assert_nothing_plain(&all_objects(&remote));

    // Forgotten in an encrypted history, it goes too.
    let _lock = a.store.lock().unwrap();
    a.store.pull().unwrap();
    a.store.forget_and_publish(&id, true).unwrap();
    assert!(remote_bundles(&remote).is_empty());

    // Turning encryption off rewrites full runs plain, and on again
    // encrypts them: the full run's files are state files like the rest.
    drop(_lock);
    let id2 = a.record(1_800_001_000);
    a.store.decrypt(true).unwrap();
    assert!(remote_bundle(&remote, &id2).contains(&"run.json".to_string()));
    a.store
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    crypt::give_passphrase(&a.store.dir, SecretString::from(PASS.to_string()));
    assert!(remote_bundle(&remote, &id2).contains(&"run.json.age".to_string()));
    assert!(!remote_bundle(&remote, &id2).contains(&"run.json".to_string()));
    remove_all(&dir);
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
fn an_older_pathwarden_on_the_same_branch_leaves_full_runs_alone() {
    if !have_git() {
        return;
    }
    let dir = scratch("older");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let first = a.record(1_800_000_000);

    // An older version records a run: it stages only its own files, so
    // the full run already there stays in the tree.
    let old = dir.join("old");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &old.to_string_lossy(),
        ],
    );
    let mut point: serde_json::Value = serde_json::from_slice(
        &std::fs::read(old.join("history").join(format!("{first}.json"))).unwrap(),
    )
    .unwrap();
    point["run_id"] = "20270101T000000.000Z".into();
    std::fs::write(
        old.join("history/20270101T000000.000Z.json"),
        serde_json::to_vec_pretty(&point).unwrap(),
    )
    .unwrap();
    git(&old, &["add", "--", "history/20270101T000000.000Z.json"]);
    git(
        &old,
        &[
            "commit",
            "-q",
            "-m",
            "pathwarden run 20270101T000000.000Z: older version",
        ],
    );
    git(&old, &["push", "-q", "origin", "HEAD:main"]);
    assert_eq!(remote_bundles(&remote), std::slice::from_ref(&first));

    // A working copy an older version cloned by hand, never marked as
    // Pathwarden's (0.1.6), holding runs/: taken over, runs/ and all.
    let unmarked = dir.join("unmarked");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            &unmarked.to_string_lossy(),
        ],
    );
    assert!(unmarked
        .join("runs")
        .join(&first)
        .join("run.json")
        .is_file());
    let b = Machine::git(&remote, &unmarked, None);
    b.store.pull().unwrap();
    assert!(unmarked
        .join("runs")
        .join(&first)
        .join("run.json")
        .is_file());
    let next = b.record(1_800_001_000);
    assert_eq!(remote_bundles(&remote), [first, next]);
    remove_all(&dir);
}

/// Every commit message on the remote's branch.
fn messages(remote: &Path) -> Vec<String> {
    git(remote, &["log", "--format=%B%x1e", "main"])
        .split('\u{1e}')
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// An encrypted history's commit messages: a run's own, a removal's, a
/// few fixed ones, or the neutral one; never a count or a size.
fn assert_neutral_messages(remote: &Path) {
    for m in messages(remote) {
        let ok = m == "pathwarden: update the history"
            || m == "pathwarden: encrypt the history"
            || m == "pathwarden settings"
            || m.strip_prefix("pathwarden run ")
                .is_some_and(|id| !id.contains([' ', ':', '(']))
            || (m.starts_with("pathwarden: remove run ") && m.ends_with(" from the history"));
        assert!(ok, "an encrypted history's commit says {m:?}");
        assert!(!m.contains('\n'), "{m:?}");
    }
}

/// Several full runs in one commit (as the app's catch-up and an import of
/// several runs make), and a commit that only removes older full runs: on
/// an encrypted history, their messages say no count or size, and no
/// object holds anything in plain text.
#[test]
fn an_encrypted_history_s_multi_run_and_trim_commits_say_nothing() {
    if !have_git() {
        return;
    }
    let dir = scratch("enc-multi");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    a.store
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    crypt::give_passphrase(&a.store.dir, SecretString::from(PASS.to_string()));
    // Three points, then their full runs together.
    let runs: Vec<record::Prepared> = (0..3)
        .map(|i| a.record_point(1_800_000_000 + i * 1000))
        .collect();
    let bundles: Vec<Bundle> = runs
        .iter()
        .map(|p| bundle_of(p, shared_runs::MAX_FILE_BYTES))
        .collect();
    let _lock = a.store.lock().unwrap();
    let p = shared_runs::publish(&a.store, &bundles, 50, true).unwrap();
    assert!(p.pushed && p.shared.len() == 3, "{p:?}");
    // Only the latest one kept: a commit that only removes.
    let t = shared_runs::publish(&a.store, &[], 1, true).unwrap();
    assert!(t.pushed && t.removed == 2 && t.shared.is_empty(), "{t:?}");
    assert_eq!(remote_bundles(&remote).len(), 1);
    let log = messages(&remote);
    assert_eq!(log[0], "pathwarden: update the history", "{log:?}");
    assert_eq!(log[1], "pathwarden: update the history", "{log:?}");
    assert_neutral_messages(&remote);
    assert_nothing_plain(&all_objects(&remote));
    drop(_lock);
    remove_all(&dir);
}

/// A full run whose push was refused stays committed here; when another
/// machine pushes first, the next pull adds it back on top and commits it,
/// so a second pull never cleans it away, and the next push takes it.
#[test]
fn a_full_run_refused_at_the_push_survives_another_machines_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("refused");
    let remote = bare(&dir);
    // Refuses any push that changes runs/.
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
    let a = Machine::git(&remote, &dir.join("a"), None);
    let b = Machine::git(&remote, &dir.join("b"), None);
    let a_run = a.record_point(1_800_000_000);
    let p = a.publish(&[a.bundle(&a_run, shared_runs::MAX_FILE_BYTES)]);
    let kept = p.unpushed.as_ref().expect("the push was refused");
    assert!(kept.reason.contains("refused"), "{kept:?}");
    let ida = a_run.run_id().to_string();
    assert!(remote_bundles(&remote).is_empty());

    // B pushes a point (no full run: allowed), then A gets the latest.
    let b_run = b.record_point(1_800_001_000);
    let note = a.store.pull().unwrap().unwrap_or_default();
    assert!(note.contains("1 full run committed here"), "{note}");
    let tracked = |m: &Machine| git(&m.store.dir, &["ls-files", "runs/"]);
    assert!(
        tracked(&a).contains(&format!("runs/{ida}/run.json")),
        "{}",
        tracked(&a)
    );
    assert!(a.store.has_unpushed());
    // A second pull keeps it: it is committed, not left to the clean.
    a.store.pull().unwrap();
    assert!(dir.join("a/runs").join(&ida).join("run.json").is_file());
    assert!(tracked(&a).contains(&format!("runs/{ida}/run.json")));

    // Once the remote takes full runs, A's next publish pushes it along.
    std::fs::remove_file(&hook).unwrap();
    let c_run = a.record_point(1_800_002_000);
    let p = a.publish(&[a.bundle(&c_run, shared_runs::MAX_FILE_BYTES)]);
    assert!(p.pushed, "{p:?}");
    let mut want = vec![ida, c_run.run_id().to_string()];
    want.sort();
    assert_eq!(remote_bundles(&remote), want);
    assert!(remote_points(&remote).contains(&b_run.run_id().to_string()));
    remove_all(&dir);
}

// ------------------------------------------------- B2: loading full runs

/// A workspace of another computer that uses the same history: `push`
/// false for one that only reads it. What it keeps is left at the default
/// (numbers with names): loading full runs follows the history, not this
/// computer's own setting.
fn other_computer(
    dir: &Path,
    remote: &Path,
    name: &str,
    push: bool,
) -> pathwarden_ui::workspace::Workspace {
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join(name)).unwrap();
    std::fs::write(
        ws.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\n{}",
            remote.to_string_lossy().replace('\\', "/"),
            dir.join(format!("{name}-state"))
                .to_string_lossy()
                .replace('\\', "/"),
            if push { "" } else { "push = false\n" }
        ),
    )
    .unwrap();
    ws
}

/// Gets the latest on `ws`'s history: what loading full runs said.
fn get_latest(ws: &pathwarden_ui::workspace::Workspace) -> Option<String> {
    let loc = pathwarden_ui::history_ui::locate(ws, None).unwrap();
    pathwarden_ui::history_ui::refresh_all(Some(ws), &loc, true)
        .unwrap()
        .1
}

/// A page of the app on `ws`, as the browser gets it: (status, location,
/// body).
fn page(ws: &pathwarden_ui::workspace::Workspace, uri: &str) -> (u16, String, String) {
    let (status, location, _, body) = request(&app(ws), uri);
    (status, location, body)
}

fn app(
    ws: &pathwarden_ui::workspace::Workspace,
) -> std::sync::Arc<pathwarden_ui::server::AppState> {
    std::sync::Arc::new(pathwarden_ui::server::AppState::new(
        ws.clone(),
        pathwarden_ui::security::Token::generate().unwrap(),
        4246,
    ))
}

/// A page of app `state`: (status, location, Content-Security-Policy, body).
fn request(
    state: &std::sync::Arc<pathwarden_ui::server::AppState>,
    uri: &str,
) -> (u16, String, String, String) {
    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let router = pathwarden_ui::server::router(state.clone());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let req = Request::builder()
            .uri(uri)
            .header(header::HOST, "127.0.0.1:4246")
            .header(header::COOKIE, state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        let status = res.status().as_u16();
        let get = |h: header::HeaderName| {
            res.headers()
                .get(h)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default()
        };
        let location = get(header::LOCATION);
        let csp = get(header::CONTENT_SECURITY_POLICY);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            location,
            csp,
            String::from_utf8_lossy(&body).into_owned(),
        )
    })
}

/// The user's report: runs recorded on one computer, shared through the
/// repository, open on another as full runs (report, Explore, findings),
/// not as numbers that take you to Progress.
#[test]
fn a_reader_opens_the_full_runs_another_computer_recorded() {
    if !have_git() {
        return;
    }
    let dir = scratch("reader");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let r1 = a.record(1_800_000_000);
    let r2 = a.record(1_800_001_000);

    let reader = other_computer(&dir, &remote, "reader", false);
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("2 full runs loaded from the repository.")
    );
    let runs = reader.runs();
    assert_eq!(runs.len(), 2);
    let source = remote.to_string_lossy().replace('\\', "/");
    for (r, id) in runs.iter().zip([&r2, &r1]) {
        assert_eq!(r.run_id(), *id);
        assert_eq!(
            Some(r.id.clone()),
            shared_runs::mirror_folder_id(&pathwarden_core::store::redact_url(&source), id)
        );
        let s = r.shared.as_ref().expect("loaded from the history");
        let me = pathwarden_core::identity::Actor::current();
        assert_eq!(s.recorded_by, me.user);
        assert_eq!(s.recorded_on, me.computer);
        assert_eq!(s.recorded_from, "schedule");
        let folder = reader.run_dir(&r.id).unwrap();
        for f in [
            "report.html",
            "graph.bin.gz",
            "objects.json.gz",
            "event.json.gz",
        ] {
            assert!(folder.join(f).is_file(), "{f}");
        }
        assert!(std::fs::read_to_string(folder.join("report.html"))
            .unwrap()
            .contains("CONTOSO"));
    }
    // Nothing changed: nothing loaded again.
    assert_eq!(get_latest(&reader), None);

    // On Runs: tagged, saying who recorded them where; they open their run
    // pages, not Progress.
    let (status, _, list) = page(&reader, "/runs");
    assert_eq!(status, 200);
    assert_eq!(list.matches("From the repository").count(), 2, "{list}");
    assert!(list.contains("Recorded by the schedule"), "{list}");
    for r in &runs {
        assert!(
            list.contains(&format!(r#"href="/runs/{}""#, r.id)),
            "{list}"
        );
    }
    assert!(!list.contains("Numbers with names"), "{list}");
    let loc = pathwarden_ui::history_ui::locate(&reader, None).unwrap();
    let snap = pathwarden_ui::history_ui::Snapshot {
        history: pathwarden_ui::history_ui::read(&loc),
        location: Ok(loc),
    };
    let rows = pathwarden_ui::run_list::run_list(&reader, &reader.runs(), &snap);
    assert!(rows
        .iter()
        .all(|r| r.source == pathwarden_ui::run_list::Source::Shared));

    // Its page is a full run page, saying where it came from; the history's
    // run ID opens it too.
    let folder = runs[0].id.clone();
    let (status, _, body) = page(&reader, &format!("/runs/{folder}"));
    assert_eq!(status, 200, "{body}");
    // The header: tagged, nothing more about where it came from (the
    // owner's choice). What the report opens stays sandboxed.
    assert!(body.contains("From the repository"), "{body}");
    assert!(!body.contains("ecorded by the schedule"), "{body}");
    assert!(
        body.contains(r#"sandbox="allow-scripts allow-popups">"#),
        "{body}"
    );
    assert!(!body.contains("allow-popups-to-escape-sandbox"), "{body}");
    assert!(body.contains(&format!("/runs/{folder}/explore")));
    assert!(!body.contains("Remove from the history"));
    // The Run details tab, in the report as the run page embeds it: where
    // it came from and, on a computer that only reads, Hide.
    let (status, _, embed) = page(&reader, &format!("/runs/{folder}/report?embed=1"));
    assert_eq!(status, 200);
    assert!(embed.contains(r#"id="tab-details""#), "the tab");
    assert!(embed.contains("Run details"));
    assert!(
        embed.contains("<dt>Recorded</dt><dd>By the schedule as"),
        "{embed}"
    );
    assert!(embed.contains(&format!("<code>{r2}</code>")), "the run ID");
    assert!(embed.contains("Hide on this computer"));
    assert!(embed.contains("It stays in the repository for everyone else."));
    assert!(!embed.contains("Remove from the history"));
    assert!(
        embed.contains(r#"id="i-trash""#),
        "the report's icons have the trash"
    );
    // Never in the report itself: the full page and the download.
    for q in ["", "?download=1"] {
        let (_, _, report) = page(&reader, &format!("/runs/{folder}/report{q}"));
        assert!(!report.contains(r#"id="tab-details""#), "{q}");
        assert!(!report.contains("Hide on this computer"), "{q}");
    }
    let (status, location, _) = page(&reader, &format!("/runs/{r2}"));
    assert_eq!(
        (status, location.as_str()),
        (303, format!("/runs/{folder}").as_str())
    );
    let (status, _, report) = page(&reader, &format!("/runs/{folder}/report"));
    assert_eq!(status, 200);
    assert!(report.contains("CONTOSO"));
    let (status, _, _) = page(&reader, &format!("/runs/{folder}/explore"));
    assert_eq!(status, 200);

    // Removed from the history: removed here on the next pull.
    {
        let _lock = a.store.lock().unwrap();
        a.store.pull().unwrap();
        a.store.forget_and_publish(&r1, true).unwrap();
    }
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("1 run no longer in the repository was removed here.")
    );
    assert_eq!(reader.runs().len(), 1);

    // A reader hides a run: gone here, not from the history, and not
    // loaded again.
    let gone = pathwarden_ui::history_ui::delete_run(&reader, None, &folder).unwrap();
    assert_eq!(gone.notes, [pathwarden_ui::history_ui::HIDDEN_WORDS]);
    assert!(remote_bundles(&remote).contains(&r2));
    assert_eq!(get_latest(&reader), None);
    assert!(reader.runs().is_empty());

    // A computer that pushes removes it from the history for everyone.
    let writer = other_computer(&dir, &remote, "writer", true);
    assert!(get_latest(&writer).is_some());
    let w = writer.runs();
    assert_eq!(w.len(), 1);
    let (status, _, embed) = page(&writer, &format!("/runs/{}/report?embed=1", w[0].id));
    assert_eq!(status, 200);
    assert!(embed.contains("Remove from the history"), "{embed}");
    assert!(embed.contains("This removes it on every computer."));
    assert!(!embed.contains("Hide on this computer"));
    // The page's dialog asks to remove it from the history.
    let (_, _, body) = page(&writer, &format!("/runs/{}", w[0].id));
    assert!(body.contains("Remove this run from the history?"), "{body}");
    pathwarden_ui::history_ui::delete_run(&writer, None, &w[0].id).unwrap();
    assert!(remote_bundles(&remote).is_empty());
    assert!(!remote_points(&remote).contains(&r2));
    assert!(writer.runs().is_empty());
    remove_all(&dir);
}

/// A full run published again with a file left out is loaded again, and
/// its page says what is missing; one whose file doesn't match its
/// manifest, or of a newer format, isn't loaded.
#[test]
fn changed_damaged_and_newer_full_runs() {
    if !have_git() {
        return;
    }
    let dir = scratch("changed");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    // A run from before full runs were kept: its point only.
    a.record_point(1_799_000_000);
    let prep = a.record_point(1_800_000_000);
    a.publish(&[a.bundle(&prep, shared_runs::MAX_FILE_BYTES)]);
    let id = prep.run_id().to_string();
    let reader = other_computer(&dir, &remote, "reader", false);
    assert!(get_latest(&reader).is_some());
    // What was done with it here: a label and a retest.
    let first = reader.runs()[0].id.clone();
    pathwarden_ui::workspace::set_run_label(&reader, &first, Some("Before the fix")).unwrap();
    let retests = reader
        .run_dir(&first)
        .unwrap()
        .join(pathwarden_ui::retest_ui::RETESTS_FILE);
    std::fs::write(&retests, br#"{"kept":"here"}"#).unwrap();

    // Published again without its report.
    a.publish(&[a.bundle(&prep, 4 * 1024)]);
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("1 full run loaded from the repository.")
    );
    let r = &reader.runs()[0];
    // Loaded again, it keeps its label and retests.
    assert_eq!(r.id, first);
    assert_eq!(r.label.as_deref(), Some("Before the fix"));
    assert_eq!(std::fs::read(&retests).unwrap(), br#"{"kept":"here"}"#);
    let s = r.shared.as_ref().unwrap();
    assert!(s.left_out.iter().any(|l| l.name == "report.html.gz"));
    let report =
        std::fs::read_to_string(reader.run_dir(&r.id).unwrap().join("report.html")).unwrap();
    assert!(report.contains("The report isn't available"), "{report}");
    let (_, _, body) = page(&reader, &format!("/runs/{}", r.id));
    // What was left out is a fact of Run details, its row amber; no note
    // above the report repeats it.
    assert!(!body.contains("Not all of this run was shared"), "{body}");
    assert!(body.contains("<dt>Left out</dt>"), "{body}");
    assert!(body.contains("The report isn"), "{body}");
    // What was left out, and that Explore can't open it when it
    // needed one of them.
    let status = plain(&body)
        .split(r#"<span class="rd-s">From the repository · "#)
        .nth(1)
        .and_then(|s| s.split("</span>").next())
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        status.starts_with("report") && status.contains(" left out"),
        "{status}"
    );
    assert_eq!(
        status.ends_with(", so Explore can't open it"),
        s.left_out
            .iter()
            .any(|l| shared_runs::explore_needs(&l.name)),
        "{status}"
    );
    // The report can't carry Run details: the page shows them below it,
    // with Hide on a computer that only reads.
    assert!(body.contains(r#"class="card rd-below""#), "{body}");
    assert!(body.contains(&format!("<code>{id}</code>")), "{body}");
    assert!(body.contains("Hide on this computer"), "{body}");
    assert!(body.contains(&format!(r#"data-delete="{}""#, r.id)));

    // A file that doesn't match its manifest: not loaded; the run loaded
    // before stays.
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
    let prep2 = a.record_point(1_800_001_000);
    a.publish(&[a.bundle(&prep2, shared_runs::MAX_FILE_BYTES)]);
    let id2 = prep2.run_id().to_string();
    git(&other, &["pull", "-q", "origin", "main"]);
    std::fs::write(
        other.join("runs").join(&id2).join("graph.bin.gz"),
        b"not the graph",
    )
    .unwrap();
    git(&other, &["commit", "-q", "-am", "x"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!(
            "Couldn't load the full run of {id2}: graph.bin.gz doesn't match its manifest"
        )),
        "{said}"
    );
    assert_eq!(reader.runs().len(), 1);
    assert_eq!(reader.runs()[0].run_id(), id);

    // A newer format: named, not loaded.
    let mut m: serde_json::Value = serde_json::from_slice(
        &std::fs::read(other.join("runs").join(&id2).join("run.json")).unwrap(),
    )
    .unwrap();
    m["format"] = (pathwarden_ui::shared_runs::FORMAT + 1).into();
    m["pathwarden"] = "0.1.9".into();
    std::fs::write(
        other.join("runs").join(&id2).join("run.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    git(&other, &["commit", "-q", "-am", "y"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!(
            "Run {id2} was recorded by Pathwarden 0.1.9: update Pathwarden to open it."
        )),
        "{said}"
    );
    assert_eq!(reader.runs().len(), 1);
    // On Runs: the newer one says so. The one recorded before full runs
    // were kept says that only on a computer that pushes: how many the
    // history keeps is its setting, which a reader doesn't share.
    let (_, _, list) = page(&reader, "/runs");
    assert!(list.contains("Needs a newer Pathwarden"), "{list}");
    assert!(list.contains("update Pathwarden to open it"), "{list}");
    assert!(
        !list.contains("recorded before full runs were kept"),
        "{list}"
    );
    let writer = other_computer(&dir, &remote, "writer", true);
    get_latest(&writer);
    let (_, _, list) = page(&writer, "/runs");
    assert!(
        list.contains("recorded before full runs were kept"),
        "{list}"
    );

    // Another schema: not a full run of ours, so not "update Pathwarden".
    m["schema"] = "someone.else.v7".into();
    m["format"] = pathwarden_ui::shared_runs::FORMAT.into();
    std::fs::write(
        other.join("runs").join(&id2).join("run.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    git(&other, &["commit", "-q", "-am", "z"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!(
            "Couldn't load the full run of {id2}: its run.json isn't a Pathwarden full run"
        )),
        "{said}"
    );
    assert!(!said.contains("update Pathwarden"), "{said}");
    let (_, _, list) = page(&reader, "/runs");
    assert!(!list.contains("Needs a newer Pathwarden"), "{list}");

    // A run.json over 1 MB isn't read.
    std::fs::write(
        other.join("runs").join(&id2).join("run.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    git(&other, &["commit", "-q", "-am", "big"]);
    git(&other, &["push", "-q", "origin", "HEAD:main"]);
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!(
            "Couldn't load the full run of {id2}: its run.json is too large"
        )),
        "{said}"
    );
    let (status, _, _) = page(&reader, "/runs");
    assert_eq!(status, 200);
    remove_all(&dir);
}

/// A reader of an encrypted history needs its passphrase to load the full
/// runs; with it, they load.
#[test]
fn a_reader_of_an_encrypted_history_needs_the_passphrase() {
    if !have_git() {
        return;
    }
    let dir = scratch("enc-reader");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    a.store
        .encrypt(&SecretString::from(PASS.to_string()), true)
        .unwrap();
    crypt::give_passphrase(&a.store.dir, SecretString::from(PASS.to_string()));
    let id = a.record(1_800_000_000);
    // The reader's computer has neither the passphrase nor the key opened.
    crypt::forget_in_process(&a.store.dir);
    let reader = other_computer(&dir, &remote, "reader", false);
    let said = get_latest(&reader).unwrap_or_default();
    assert!(said.contains("can't be read here"), "{said}");
    assert!(reader.runs().is_empty());
    let loc = pathwarden_ui::history_ui::locate(&reader, None).unwrap();
    crypt::give_passphrase(&loc.dir, SecretString::from(PASS.to_string()));
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("1 full run loaded from the repository.")
    );
    assert_eq!(reader.runs()[0].run_id(), id);
    remove_all(&dir);
}

/// The sidebar counted the runs on this computer (5) while Runs
/// listed the history's numbers-only runs too (6). Both count the same
/// runs now.
#[test]
fn the_sidebar_counts_the_runs_the_runs_list_shows() {
    if !have_git() {
        return;
    }
    let dir = scratch("count");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    // One run in full, one with its numbers only.
    a.record_point(1_800_000_000);
    a.record(1_800_001_000);
    let ws = other_computer(&dir, &remote, "b", true);
    get_latest(&ws);
    let runs = ws.runs();
    assert_eq!(runs.len(), 1, "the full run, loaded");
    let snap = pathwarden_ui::history_ui::snapshot(&ws, None);
    let rows = pathwarden_ui::run_list::run_list(&ws, &runs, &snap);
    assert_eq!(rows.len(), 2);
    let ids = pathwarden_ui::history_ui::point_ids(&ws, None);
    assert_eq!(
        pathwarden_ui::run_list::row_count(&runs, ids.iter().map(String::as_str)),
        rows.len()
    );
    for uri in ["/runs", "/"] {
        let (status, _, body) = page(&ws, uri);
        assert_eq!(status, 200, "{uri}");
        assert!(
            body.contains(r#"<span class="tl">Runs</span><span class="count">2</span>"#),
            "{uri}: {body}"
        );
    }
    remove_all(&dir);
}

/// The `run.json` of full run `id` in working copy `other`, changed by
/// `change`, committed and pushed: what anyone who can push can do.
fn tamper_manifest(other: &Path, id: &str, change: impl FnOnce(&mut serde_json::Value)) {
    let path = other.join("runs").join(id).join("run.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    change(&mut m);
    std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    git(other, &["commit", "-q", "-am", "tamper"]);
    git(other, &["push", "-q", "origin", "HEAD:main"]);
}

/// The `script-src` directive of policy `csp`.
fn script_src(csp: &str) -> &str {
    csp.split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src"))
        .unwrap_or_default()
}

/// A report Overview's hero as a hostile writer would put it.
const HOSTILE_HERO: &str = r#"<div class="hero card"><meta http-equiv="refresh" content="0;url=https://evil.example/"><form id="pw-evil-form" method="post" action="/environments/default/remove"><button>Go</button></form><a href="/runs" data-delete="pw-evil-del">x</a></div>"#;

/// Who recorded a run, as a hostile writer would put it: markup, and
/// terminal escapes for the command line.
const HOSTILE_BY: &str = "<img src=x onerror=alert(1)>\u{1b}[31mmallory";
const HOSTILE_ON: &str = "<script>alert(2)</script>\u{1b}]0;owned\u{7}PC";

/// A run loaded from the history is someone else's: nothing in it picks
/// where this computer signs in for a retest, no script of its own runs,
/// and what it says of who recorded it is shown as text. A report that
/// can't carry Run details (an unknown script, left out) gets them below
/// it on the run page.
#[test]
fn a_loaded_run_is_shown_not_trusted() {
    if !have_git() {
        return;
    }
    let dir = scratch("untrusted");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    // A summary that names a domain controller of the writer's choosing,
    // over plain LDAP.
    let p1 = a.record_point(1_800_000_000);
    a.publish(&[bundle_with(&p1, shared_runs::MAX_FILE_BYTES, |s, _| {
        s.collection = Some(pathwarden_ui::workspace::CollectionInfo {
            read_started: None,
            method: "builtin".into(),
            scope: "all".into(),
            domain: "evil.example".into(),
            server: Some("dc.evil.example".into()),
            ldaps: false,
            current_user: true,
            warnings: Vec::new(),
            kept: None,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
        });
    })]);
    // A report whose script isn't one Pathwarden wrote.
    let p2 = a.record_point(1_800_001_000);
    a.publish(&[bundle_with(&p2, shared_runs::MAX_FILE_BYTES, |_, html| {
        let i = html.rfind("<script>").unwrap() + "<script>".len();
        html.insert_str(i, "window.evil=1;");
    })]);
    // A report left out.
    let p3 = a.record_point(1_800_002_000);
    a.publish(&[a.bundle(&p3, 4 * 1024)]);
    // The latest, Home's: a hero that refreshes the page, posts a form and
    // carries a Delete of the app's.
    let p4 = a.record_point(1_800_003_000);
    a.publish(&[bundle_with(&p4, shared_runs::MAX_FILE_BYTES, |_, html| {
        let i = html.find(r#"<div class="hero card"#).unwrap();
        html.insert_str(i, HOSTILE_HERO);
    })]);
    let (id1, id2, id3, id4) = (p1.run_id(), p2.run_id(), p3.run_id(), p4.run_id());
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
    for id in [id1, id3] {
        tamper_manifest(&other, id, |m| {
            m["recorded_by"] = HOSTILE_BY.into();
            m["recorded_on"] = HOSTILE_ON.into();
        });
    }

    let reader = other_computer(&dir, &remote, "reader", false);
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("4 full runs loaded from the repository.")
    );
    let folder = |id: &str| {
        reader
            .runs()
            .into_iter()
            .find(|r| r.run_id() == id)
            .unwrap()
            .id
    };
    let (f1, f2, f3, f4) = (folder(id1), folder(id2), folder(id3), folder(id4));
    let st = app(&reader);

    // Nothing of a loaded report's HTML reaches an app page: Home shows its
    // own card; Runs, Progress and the run page don't carry it either.
    assert!(
        std::fs::read_to_string(reader.run_dir(&f4).unwrap().join("report.html"))
            .unwrap()
            .contains("pw-evil-form")
    );
    for uri in [
        "/".to_string(),
        "/runs".into(),
        "/progress".into(),
        format!("/runs/{f4}"),
    ] {
        let (status, _, _, page) = request(&st, &uri);
        assert_eq!(status, 200, "{uri}");
        for bad in ["pw-evil-form", "pw-evil-del", "http-equiv", "evil.example/"] {
            assert!(!page.contains(bad), "{bad} on {uri}");
        }
    }

    // The retest dialog starts empty: no domain, no domain controller.
    let (_, _, _, body) = request(&st, &format!("/runs/{f1}"));
    // (How it was collected is still said, as a fact.)
    assert!(!body.contains(r#"value="evil.example""#), "{body}");
    assert!(!body.contains(r#"value="dc.evil.example""#), "{body}");
    assert!(body.contains(r#"placeholder="scale.local" value="""#));
    assert!(body.contains(r#"placeholder="dc01.scale.local" value="""#));
    // Nor does the Schedule page follow it, asked for or not.
    for uri in [
        "/automate/schedule".to_string(),
        format!("/automate/schedule?run={f1}"),
    ] {
        let (status, _, _, page) = request(&st, &uri);
        assert_eq!(status, 200, "{uri}");
        assert!(!page.contains("evil.example"), "{uri}: {page}");
    }
    // The report carries Run details: one Run details, the tab. The page's
    // own copy (with its Hide) is there only hidden, for when the frame
    // says the tab can't be seen (the report is the repository's file).
    assert!(
        body.contains(r#"<section class="card rd-below" id="run-details" data-rd-fallback hidden"#),
        "{body}"
    );
    assert_eq!(body.matches(r#"class="card rd-below""#).count(), 1);
    assert!(
        body.contains(r#"<details class="rd-more"><summary>"#),
        "{body}"
    );
    assert!(!body.contains(r#"<details class="rd-more" open"#), "{body}");
    assert!(
        body.contains(&format!(
            r#"<button type="button" class="btn" data-delete="{f1}"><span>Hide on this computer</span>"#
        )),
        "{body}"
    );
    let nonce = body
        .split(r#"data-rd=""#)
        .nth(1)
        .and_then(|s| s.get(..32))
        .unwrap()
        .to_string();
    assert!(body.contains(&format!("report?embed=1&amp;rd={nonce}")));
    let (_, _, csp, embed) = request(&st, &format!("/runs/{f1}/report?embed=1&rd={nonce}"));
    assert!(embed.contains(r#"id="tab-details""#));
    assert!(embed.contains(&format!(r#"data-pw-nonce="{nonce}""#)));
    assert!(embed.contains(&format!(r#"data-pw-tab="{nonce}""#)));
    // The tab holds Remove: the panel the app put in, with its button.
    assert!(embed.contains(r#"<h3>Remove this run</h3>"#), "{embed}");
    assert!(embed.contains(r#"data-pw-run="remove""#), "{embed}");
    assert!(!script_src(&csp).contains("unsafe-inline"), "{csp}");
    // Hostile words are text.
    for page in [&body, &embed] {
        assert!(!page.contains("<img src=x"), "{page}");
        assert!(!page.contains("<script>alert(2)"), "{page}");
    }
    assert!(
        embed.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{embed}"
    );
    // A nonce that isn't one is not carried.
    let (_, _, _, embed) = request(&st, &format!("/runs/{f1}/report?embed=1&rd=%22%3E%3Cb%3E"));
    assert!(embed.contains(r#"data-pw-nonce="""#));
    // The full page runs only the report's own script.
    let (_, _, csp, _) = request(&st, &format!("/runs/{f1}/report"));
    assert!(csp.contains("script-src 'sha256-"), "{csp}");
    assert!(!script_src(&csp).contains("unsafe-inline"), "{csp}");
    // Embedded or not, what it opens stays sandboxed.
    for q in ["?embed=1", ""] {
        let (_, _, csp, _) = request(&st, &format!("/runs/{f1}/report{q}"));
        assert!(
            csp.ends_with("sandbox allow-scripts allow-popups"),
            "{q}: {csp}"
        );
    }
    // Trust is the folder's: a loaded folder whose summary says nothing of
    // the history, or has none, is still the repository's.
    // (A loaded run's summary is run folder format 2; put back at the
    // format 1 name, as 0.1.9 kept it, it is still the repository's.)
    let dir = reader.run_dir(&f1).unwrap();
    let loaded = dir.join("summary.v2.json");
    let mut s: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&loaded).unwrap()).unwrap();
    s.as_object_mut().unwrap().remove("shared");
    std::fs::write(dir.join("summary.json"), serde_json::to_vec(&s).unwrap()).unwrap();
    std::fs::remove_file(&loaded).unwrap();
    let (_, _, csp, _) = request(&st, &format!("/runs/{f1}/report"));
    assert!(!script_src(&csp).contains("unsafe-inline"), "{csp}");
    for f in ["summary.json", "summary.v2.json"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    let (_, _, csp, _) = request(&st, &format!("/runs/{f1}/report"));
    assert!(!script_src(&csp).contains("unsafe-inline"), "{csp}");

    // An unknown script: no script at all, embedded or not; Run details
    // below the report instead.
    for q in ["?embed=1", ""] {
        let (status, _, csp, report) = request(&st, &format!("/runs/{f2}/report{q}"));
        assert_eq!(status, 200);
        assert!(csp.contains("script-src 'none'"), "{q}: {csp}");
        assert!(!script_src(&csp).contains("unsafe-inline"), "{q}: {csp}");
        assert!(!report.contains(r#"id="tab-details""#), "{q}");
        assert!(!report.contains("pathwarden:run-action"), "{q}");
    }
    for f in [&f2, &f3] {
        let (_, _, _, body) = request(&st, &format!("/runs/{f}"));
        assert!(body.contains(r#"class="card rd-below""#), "{f}: {body}");
        // No tab, so no nonce for it.
        assert!(!body.contains("data-rd="), "{body}");
        assert!(!body.contains("&amp;rd="), "{body}");
        assert!(body.contains("<dt>Run ID</dt>"), "{body}");
        assert!(body.contains("Hide on this computer"), "{body}");
        assert!(
            body.contains(&format!(r#"class="btn" data-delete="{f}""#)),
            "{body}"
        );
        assert!(!body.contains("<img src=x"), "{body}");
        assert!(!body.contains("<script>alert(2)"), "{body}");
    }
    let (_, _, _, body) = request(&st, &format!("/runs/{f3}"));
    assert!(
        body.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{body}"
    );
    // On Runs too.
    let (_, _, _, list) = request(&st, "/runs");
    assert!(!list.contains("<img src=x"), "{list}");
    assert!(!list.contains("<script>alert(2)"), "{list}");
    assert!(list.contains("&lt;img src=x"), "{list}");

    // A computer that pushes removes it from the history, from the page.
    let writer = other_computer(&dir, &remote, "writer", true);
    get_latest(&writer);
    let wf = writer
        .runs()
        .into_iter()
        .find(|r| r.run_id() == id3)
        .unwrap()
        .id;
    let (_, _, body) = page(&writer, &format!("/runs/{wf}"));
    // Its report can't carry the tab: Run details below it, shown.
    assert!(
        body.contains(r#"class="card rd-below" id="run-details" aria-label"#),
        "{body}"
    );
    assert!(body.contains("Remove from the history"), "{body}");
    assert!(
        body.contains("This removes it on every computer."),
        "{body}"
    );
    remove_all(&dir);
}

/// Home shows a run loaded from the history with the report's Overview,
/// made here from its data (never from its report's HTML) with every name
/// escaped; a full run without its event document keeps Home's card.
#[test]
fn home_shows_a_loaded_run_s_overview_from_its_data() {
    if !have_git() {
        return;
    }
    let dir = scratch("home-overview");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    a.record(1_800_000_000);
    let r2 = a.record(1_800_001_000);
    let reader = other_computer(&dir, &remote, "reader", false);
    get_latest(&reader);
    let latest = &reader.runs()[0];
    assert_eq!(latest.run_id(), r2);
    let folder = latest.id.clone();
    let (status, _, home) = page(&reader, "/");
    assert_eq!(status, 200);
    assert!(home.contains(r#"<section class="env-ov">"#), "{home}");
    assert!(home.contains(r#"<div class="hero card"#), "{home}");
    assert!(home.contains("have an attack path to Tier"), "{home}");
    assert!(home.contains(r#"<div class="ov-cards">"#), "{home}");
    assert!(home.contains("Plan steps"), "{home}");
    // The trend and What changed, from the history.
    assert!(home.contains(r#"<div class="hero-trend">"#), "{home}");
    assert!(home.contains("What changed since"), "{home}");
    // Its links go to the run page, its IDs are Home's.
    assert!(
        home.contains(&format!(r##"href="/runs/{folder}#step-1""##)),
        "{home}"
    );
    assert!(home.contains(r#"id="h0-tip-takeover""#), "{home}");
    assert!(!home.contains(r##"<a href="#"##), "{home}");
    // Not the older card.
    assert!(!home.contains(r#"class="env-card card""#), "{home}");
    assert!(!home.contains("Next fix"), "{home}");

    // Names the writer chose are text, and a kind this computer doesn't
    // know reads as a plain permission.
    let p3 = a.record_point(1_800_002_000);
    a.publish(&[bundle_changed(
        &p3,
        shared_runs::MAX_FILE_BYTES,
        |_, _| {},
        |e| {
            e["posture"]["tier_zero"]["reason"]["text"] =
                "<script>alert(2)</script> can take over the domain.".into();
            let fix = &mut e["plan"]["fixes"][0];
            assert!(fix.is_object(), "{e}");
            fix["from"] = "<img src=x onerror=alert(3)>@CONTOSO.LOCAL".into();
            fix["edges"] = serde_json::json!(["NotAKindAnyoneKnows"]);
        },
    )]);
    get_latest(&reader);
    assert_eq!(reader.runs()[0].run_id(), p3.run_id());
    let (_, _, home) = page(&reader, "/");
    assert!(home.contains(r#"<div class="hero card"#), "{home}");
    assert!(!home.contains("<img src=x"), "{home}");
    assert!(!home.contains("<script>alert(2)"), "{home}");
    assert!(
        home.contains("&lt;img src=x onerror=alert(3)&gt;"),
        "{home}"
    );
    assert!(
        home.contains("&lt;script&gt;alert(2)&lt;/script&gt;"),
        "{home}"
    );
    assert!(home.contains("Start: remove the permissions"), "{home}");

    // A full run without its event document: Home's card.
    let p4 = a.record_point(1_800_003_000);
    a.publish(&[a.bundle(&p4, 4 * 1024)]);
    get_latest(&reader);
    let latest = &reader.runs()[0];
    assert_eq!(latest.run_id(), p4.run_id());
    assert!(!reader
        .run_dir(&latest.id)
        .unwrap()
        .join(pathwarden_ui::run_data::EVENT_FILE)
        .exists());
    let (_, _, home) = page(&reader, "/");
    assert!(
        home.contains(r#"<section class="env-card card">"#),
        "{home}"
    );
    assert!(!home.contains(r#"<div class="hero card"#), "{home}");
    remove_all(&dir);
}

/// The forest fixture as a Quick (DC only) collection writes it, under
/// `dir`: no session list collected, no local groups.
fn quick_forest(dir: &Path) -> PathBuf {
    let out = dir.join("quick-forest");
    std::fs::create_dir_all(&out).unwrap();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": pathwarden_core::ingest::NOT_CONTACTED});
                }
                c["LocalGroups"] = serde_json::json!([]);
                c.as_object_mut().unwrap().remove("LocalAdmins");
            }
        }
        std::fs::write(out.join(e.file_name()), doc.to_string()).unwrap();
    }
    out
}

/// A repository Quick run after a Full run: Home's Overview of it says
/// "Not targeted" and compares no count with the Full run.
#[test]
fn home_shows_a_loaded_quick_run_as_not_targeted() {
    if !have_git() {
        return;
    }
    let dir = scratch("home-quick");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    a.record(1_800_000_000);
    let quick = a.record_point_from(1_800_001_000, &quick_forest(&dir));
    a.publish(&[a.bundle(&quick, shared_runs::MAX_FILE_BYTES)]);
    let reader = other_computer(&dir, &remote, "reader", false);
    get_latest(&reader);
    assert_eq!(reader.runs()[0].run_id(), quick.run_id());
    let (_, _, home) = page(&reader, "/");
    assert!(home.contains(r#"<div class="hero card"#), "{home}");
    assert!(
        home.contains(r#"<span class="ov-num">Not targeted</span>"#),
        "{home}"
    );
    assert!(
        home.contains("Sessions and local groups were not targeted this run, so its counts are not compared with the last run."),
        "{home}"
    );
    assert!(!home.contains("hero-change"), "{home}");
    assert!(!home.contains("since the last run"), "{home}");
    assert!(!home.contains(r#"<div class="hero-trend">"#), "{home}");
    remove_all(&dir);
}

/// With `ui --state`, a run of another environment is removed as that
/// environment's history says (`--state` is the Default environment's
/// only): the run page offers what Delete does.
#[test]
fn another_environment_s_run_follows_its_own_history_under_state() {
    if !have_git() {
        return;
    }
    let dir = scratch("other-env");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let id = a.record(1_800_000_000);
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join("multi")).unwrap();
    let env = pathwarden_ui::environments::create_environment(&ws, "Other", "", "").unwrap();
    let oth = ws.in_env(&env);
    std::fs::write(
        oth.config_path(),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\npush = false\n",
            remote.to_string_lossy().replace('\\', "/"),
            dir.join("oth-state").to_string_lossy().replace('\\', "/"),
        ),
    )
    .unwrap();
    assert!(get_latest(&oth).is_some());
    let f = oth.runs()[0].id.clone();
    assert_eq!(oth.runs()[0].run_id(), id);
    // The app on the Default environment, with a folder history of its own.
    let st = app(&ws);
    let flag = dir.join("flag-history");
    std::fs::create_dir_all(&flag).unwrap();
    st.jobs.set_state_dir(Some(flag.clone()));
    assert_eq!(st.state_dir_for(&oth), None);
    let (status, _, _, body) = request(&st, &format!("/runs/{f}"));
    assert_eq!(status, 200, "{body}");
    let nonce = body
        .split(r#"data-rd=""#)
        .nth(1)
        .and_then(|s| s.get(..32))
        .unwrap()
        .to_string();
    let (_, _, _, embed) = request(&st, &format!("/runs/{f}/report?embed=1&rd={nonce}"));
    assert!(embed.contains("Hide on this computer"), "{embed}");
    assert!(!embed.contains("Remove from the history"), "{embed}");
    assert!(body.contains("Hide this run on this computer?"), "{body}");
    // And Delete hides it: the repository keeps it, the flag's folder is
    // left alone.
    let gone =
        pathwarden_ui::history_ui::delete_run(&oth, st.state_dir_for(&oth).as_deref(), &f).unwrap();
    assert_eq!(gone.notes, [pathwarden_ui::history_ui::HIDDEN_WORDS]);
    assert!(remote_bundles(&remote).contains(&id));
    assert_eq!(std::fs::read_dir(&flag).unwrap().count(), 0);
    remove_all(&dir);
}

/// A loaded run dated next year is dated when it was loaded: it can't stay
/// the latest. And the Schedule page never offers a loaded run to repeat.
#[test]
fn a_loaded_run_from_the_future_and_the_schedule_picker() {
    if !have_git() {
        return;
    }
    let dir = scratch("future");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let p = a.record_point(1_800_000_000);
    let next_year = pathwarden_core::analyze::now() + 365 * 24 * 3600;
    a.publish(&[bundle_with(&p, shared_runs::MAX_FILE_BYTES, |s, _| {
        s.created_at = next_year;
        s.collected_at = Some(next_year);
    })]);
    let reader = other_computer(&dir, &remote, "reader", false);
    let before = pathwarden_core::analyze::now();
    assert!(get_latest(&reader).is_some());
    let after = pathwarden_core::analyze::now();
    let r = &reader.runs()[0];
    assert!(
        r.created_at >= before && r.created_at <= after,
        "{}",
        r.created_at
    );
    let c = r.collected_at.unwrap();
    assert!(c >= before && c <= after, "{c}");
    assert!(r.shared.as_ref().unwrap().mirrored_at >= r.created_at);

    let (status, _, page) = page(&reader, "/automate/schedule");
    assert_eq!(status, 200);
    assert!(
        !page.contains(&format!(r#"<option value="{}""#, r.id)),
        "{page}"
    );
    assert!(page.contains("No analysis of your own data yet"), "{page}");
    remove_all(&dir);
}

// ------------------------------------- The full-run file limit

/// `body` with its apostrophes unescaped.
fn plain(body: &str) -> String {
    body.replace("&#39;", "'").replace("&#x27;", "'")
}

/// A full run whose object index is 60 MB: kept under the default limit
/// (75 MB), its manifest says so, and another computer explores it.
#[test]
fn a_large_object_index_is_kept_and_explored_on_another_computer() {
    if !have_git() {
        return;
    }
    let dir = scratch("large-index");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let prep = a.record_point(1_800_000_000);
    let limit = shared_runs::file_limit(&a.config.state, &a.store);
    assert_eq!(limit, 75 << 20);
    let b = bundle_files(
        &prep,
        limit,
        |_, _| {},
        |_| {},
        |e| pad_objects(e, 60 << 20),
    );
    assert!(b.manifest.left_out.is_empty(), "{:?}", b.manifest.left_out);
    assert_eq!(b.manifest.max_file_bytes, Some(75 << 20));
    let p = a.publish(&[b]);
    assert!(p.pushed, "{p:?}");

    let reader = other_computer(&dir, &remote, "reader", false);
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("1 full run loaded from the repository.")
    );
    let r = reader.runs().remove(0);
    let folder = reader.run_dir(&r.id).unwrap();
    let index = std::fs::metadata(folder.join("objects.json.gz")).unwrap();
    assert!(index.len() >= 60 << 20);
    pathwarden_ui::explore_ui::read_run(&folder).unwrap();
    let (status, _, body) = page(&reader, &format!("/runs/{}/explore", r.id));
    assert_eq!(status, 200);
    assert!(body.contains(r#"id="xp-cy""#), "{body}");
    remove_all(&dir);
}

/// A setting of 200 MB keeps a 150 MB file on Azure DevOps (or any host
/// but GitHub); GitHub holds the setting to 95 MB, so there the file is
/// left out and named. A reader takes the file within the limit the run
/// recorded.
#[test]
fn the_limit_follows_the_setting_and_github_holds_it() {
    let dir = scratch("limit-setting");
    let big = vec![7u8; 150 << 20];
    let ado = "https://contoso@dev.azure.com/contoso/pw/_git/history";
    let gh = "https://github.com/contoso/history.git";
    let state = |remote: &str| StateConfig {
        backend: StateBackend::Git,
        remote: Some(remote.into()),
        keep: Some(Keep::Full),
        full_run_file_mb: Some(200),
        ..StateConfig::default()
    };
    // Each host's limit, as a full run recorded there is written under.
    assert_eq!(state(ado).full_run_file_bytes_for(Some(ado)), 200 << 20);
    assert_eq!(state(gh).full_run_file_bytes_for(Some(gh)), 95 << 20);

    let history = dir.join("history");
    let a = Machine::folder(&history);
    let prep = a.record_point(1_800_000_000);
    let with_big = |limit: u64| {
        bundle_files(
            &prep,
            limit,
            |_, _| {},
            |_| {},
            |e| {
                e.retain(|(n, _)| *n != "retest.json.gz");
                e.push(("retest.json.gz", big.clone()));
            },
        )
    };
    let on_github = with_big(state(gh).full_run_file_bytes_for(Some(gh)));
    let left: Vec<&str> = on_github
        .manifest
        .left_out
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    assert_eq!(left, ["retest.json.gz"]);
    assert!(
        on_github.manifest.left_out[0].why.contains("95 MB"),
        "{:?}",
        on_github.manifest.left_out
    );
    drop(on_github);
    let on_ado = with_big(state(ado).full_run_file_bytes_for(Some(ado)));
    assert!(on_ado.manifest.left_out.is_empty());
    assert_eq!(on_ado.manifest.max_file_bytes, Some(200 << 20));
    let p = a.publish(&[on_ado]);
    assert_eq!(p.shared.len(), 1, "{p:?}");

    // A reader of the folder takes it: within the 200 MB it recorded.
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join("reader")).unwrap();
    std::fs::write(
        ws.config_path(),
        format!(
            "[state]\npath = \"{}\"\n",
            history.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    assert_eq!(
        get_latest(&ws).as_deref(),
        Some("1 full run loaded from the history folder.")
    );
    let r = ws.runs().remove(0);
    let kept = std::fs::metadata(ws.run_dir(&r.id).unwrap().join("retest.json.gz")).unwrap();
    assert_eq!(kept.len(), 150 << 20);
    remove_all(&dir);
}

/// A full run without its object index: named in the manifest; on the
/// other computer, Run details say what is missing, Explore and the API
/// say the index wasn't shared, and Explore's entry opens the earlier run
/// saying which run it shows and why. A file larger than its manifest
/// says, or over the limit it recorded, is refused unread.
#[test]
fn a_run_without_its_object_index_says_so() {
    if !have_git() {
        return;
    }
    let dir = scratch("no-index");
    let remote = bare(&dir);
    let a = Machine::git(&remote, &dir.join("a"), None);
    let r1 = a.record(1_800_000_000);
    let prep = a.record_point(1_800_001_000);
    let id = prep.run_id().to_string();
    // The index over the limit, everything else under it.
    let limit = 4 << 20;
    let b = bundle_files(&prep, limit, |_, _| {}, |_| {}, |e| pad_objects(e, 5 << 20));
    let left: Vec<&str> = b
        .manifest
        .left_out
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    assert_eq!(left, ["objects.json.gz"]);
    assert!(a.publish(&[b]).pushed);
    let m: Manifest =
        serde_json::from_slice(&remote_file(&remote, &format!("runs/{id}/run.json"))).unwrap();
    assert_eq!(m.left_out[0].name, "objects.json.gz");
    assert_eq!(m.max_file_bytes, Some(limit));

    let reader = other_computer(&dir, &remote, "reader", false);
    assert_eq!(
        get_latest(&reader).as_deref(),
        Some("2 full runs loaded from the repository.")
    );
    let runs = reader.runs();
    let (newer, older) = (&runs[0], &runs[1]);
    assert_eq!((newer.run_id(), older.run_id()), (id.clone(), r1.clone()));
    let (_, _, body) = page(&reader, &format!("/runs/{}", newer.id));
    let body = plain(&body);
    assert!(
        body.contains(
            r#"<span class="rd-s">From the repository · object index left out, so Explore can't open it</span>"#
        ),
        "{body}"
    );
    assert!(
        body.contains("Explore isn't available: objects.json.gz was"),
        "{body}"
    );
    // Explore: the run's own page, the API and the command line's reader.
    let (status, _, body) = page(&reader, &format!("/runs/{}/explore", newer.id));
    assert_eq!(status, 200);
    let body = plain(&body);
    assert!(
        body.contains("This run's object index wasn't shared."),
        "{body}"
    );
    assert!(!body.contains("analyzed before"), "{body}");
    let (status, _, body) = page(&reader, &format!("/api/runs/{}/explore", newer.id));
    assert_eq!(status, 404);
    assert!(
        body.contains("This run's object index wasn't shared."),
        "{body}"
    );
    let err = pathwarden_ui::explore_ui::read_run(&reader.run_dir(&newer.id).unwrap())
        .err()
        .unwrap();
    assert_eq!(
        err,
        "this run's object index wasn't shared, so it can't be explored on this computer"
    );
    // Explore's entry opens the earlier run, and says which and why.
    let (status, location, _) = page(&reader, "/explore");
    assert_eq!(status, 303);
    assert_eq!(location, format!("/runs/{}/explore?from=latest", older.id));
    let (_, _, body) = page(&reader, &location);
    let line = format!(
        "Showing the run of {}. The latest run, {}, can't be explored: its object index wasn't shared.",
        pathwarden_core::time::format_local(older.created_at),
        pathwarden_core::time::format_local(newer.created_at),
    );
    assert!(plain(&body).contains(&line), "{line} in {body}");
    // Opened directly, it says nothing of the sort.
    let (_, _, body) = page(&reader, &format!("/runs/{}/explore", older.id));
    assert!(!body.contains("Showing the run of"), "{body}");

    // A file larger than its manifest says, or over the limit it
    // recorded: refused before it is read; what was loaded stays.
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
    let graph = other.join("runs").join(&id).join("graph.bin.gz");
    let mut grown = std::fs::read(&graph).unwrap();
    grown.resize(grown.len() + (1 << 20), 0);
    std::fs::write(&graph, grown).unwrap();
    // Its manifest changed too, so the reader loads it again.
    tamper_manifest(&other, &id, |m| m["recorded_on"] = "FABRIKAM-PC".into());
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!(
            "Couldn't load the full run of {id}: graph.bin.gz doesn't match its manifest"
        )),
        "{said}"
    );
    let rel = format!("runs/{id}/graph.bin.gz");
    git(&other, &["checkout", "HEAD~1", "--", &rel]);
    tamper_manifest(&other, &id, |m| m["max_file_bytes"] = 16.into());
    let said = get_latest(&reader).unwrap_or_default();
    assert!(
        said.contains(&format!("Couldn't load the full run of {id}: "))
            && said.contains("is too large"),
        "{said}"
    );
    assert_eq!(reader.runs().len(), 2);
    remove_all(&dir);
}
