//! Data each published release wrote, read by this one
//! (docs/dev/formats.md), and data a newer Pathwarden wrote, which this one
//! never takes for its own or writes over.
//!
//! The fixtures are in `crates/pathwarden-core/tests/fixtures/compat/
//! <version>/`: each release's own `pathwarden.exe` (0.1.5, 0.1.6, 0.1.7
//! and 0.1.9; 0.1.8 was never published) ran `pathwarden run` twice on the
//! synthetic MGMT.LOCAL test data (`testdata/mgmt`) with a folder history,
//! then `run --save` once into an app workspace. Kept: `pathwarden.toml`,
//! the history (`findings.json`, `last-run.json`, both points), the first
//! run's event document, and the workspace's registry and run folder; for
//! 0.1.9, which was the first to keep full runs, one full run as well.
//! Trimmed: paths, user and computer names replaced; the event documents
//! cut to three findings with each guide's first line; the app's report
//! replaced by a stub page, and the full run's report listed as left out
//! (its manifest's sizes and hashes made again to match). Everything else
//! is byte for byte what the release wrote.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::config::{Config, Keep};
use pathwarden_ui::workspace::Workspace;

/// The published releases, oldest first.
const RELEASES: &[&str] = &["0.1.5", "0.1.6", "0.1.7", "0.1.9"];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn fixture(version: &str) -> PathBuf {
    repo("crates/pathwarden-core/tests/fixtures/compat").join(version)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-compat-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn pw(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("PATHWARDEN_LOCK_WAIT", "0")
        // Never this account's own app data.
        .env("LOCALAPPDATA", dir.join("appdata"))
        .args(args)
        .output()
        .unwrap()
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

fn failed(out: &std::process::Output) -> String {
    assert!(
        !out.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A release's `pathwarden.toml`, its state folder at `state`.
fn config_text(version: &str, state: &Path) -> String {
    std::fs::read_to_string(fixture(version).join("pathwarden.toml"))
        .unwrap()
        .replace(
            "path = \"pathwarden-state\"",
            &format!("path = \"{}\"", state.to_string_lossy().replace('\\', "/")),
        )
}

/// A copy of release `version`'s history in `dir/state`, and its config
/// at `dir/pathwarden.toml`, pointing there.
fn old_history(version: &str, dir: &Path) -> (PathBuf, PathBuf) {
    let state = dir.join("state");
    copy_dir(&fixture(version).join("state"), &state);
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, config_text(version, &state)).unwrap();
    (state, config)
}

fn keys(v: &serde_json::Value) -> std::collections::BTreeSet<String> {
    v.as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

#[test]
fn each_release_s_config_reads() {
    for v in RELEASES {
        let c = Config::from_file(&fixture(v).join("pathwarden.toml"))
            .unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(c.tier_zero, ["VEEAM01.MGMT.LOCAL"], "{v}");
        assert_eq!(c.suppress.len(), 1, "{v}");
        assert_eq!(c.suppress[0].rule.as_deref(), Some("PW-028"), "{v}");
        assert_eq!(c.zones.len(), 1, "{v}");
        assert_eq!(c.zones[0].name, "Servers", "{v}");
        assert_eq!(c.format, None, "{v}");
        let keep = if *v == "0.1.9" {
            Keep::Full
        } else {
            Keep::Names
        };
        assert_eq!(c.state.keep(), keep, "{v}");
    }
}

/// A history each release kept goes on under this one: every finding it
/// tracked keeps its first sighting, its points stay, and the event
/// document still has every field that release's had.
#[test]
fn each_release_s_history_goes_on() {
    let mgmt = repo("testdata/mgmt").to_string_lossy().into_owned();
    for v in RELEASES {
        let dir = scratch(&format!("history-{v}"));
        let (state, config) = old_history(v, &dir);
        let before = json(&state.join("findings.json"));
        let old_points: Vec<String> = std::fs::read_dir(state.join("history"))
            .unwrap()
            .flatten()
            .map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .trim_end_matches(".json")
                    .to_string()
            })
            .collect();
        assert_eq!(old_points.len(), 2, "{v}");
        let old_last = json(&state.join("last-run.json"));
        assert_eq!(old_last["pathwarden"], *v, "{v}");
        // Read as it is.
        let (points, skipped) = pathwarden_core::history::load(&state).unwrap();
        assert_eq!(points.len(), 2, "{v}");
        assert!(skipped.is_empty(), "{v}: {skipped:?}");
        let store =
            pathwarden_core::store::Store::new(&Config::from_file(&config).unwrap().state, None)
                .unwrap();
        let tracked = store.load().unwrap_or_else(|e| panic!("{v}: {e:#}"));
        assert_eq!(
            tracked.findings.len(),
            before["findings"].as_object().unwrap().len(),
            "{v}"
        );
        assert!(pathwarden_core::store::last_run(&store).is_some(), "{v}");

        // A run of this version on top.
        let event = dir.join("event.json");
        ok(&pw(
            &dir,
            &[
                "run",
                "-c",
                &config.to_string_lossy(),
                "-i",
                &mgmt,
                "--event",
                &event.to_string_lossy(),
                "--no-outputs",
            ],
        ));
        let after = json(&state.join("findings.json"));
        assert_eq!(after["version"], 1, "{v}");
        for (fp, f) in before["findings"].as_object().unwrap() {
            let now = &after["findings"][fp];
            assert_eq!(now["first_seen"], f["first_seen"], "{v} {fp}");
            assert_eq!(now["rule"], f["rule"], "{v} {fp}");
        }
        let (points, skipped) = pathwarden_core::history::load(&state).unwrap();
        assert_eq!(points.len(), 3, "{v}");
        assert!(skipped.is_empty(), "{v}: {skipped:?}");
        for id in &old_points {
            assert!(points.iter().any(|p| &p.run_id == id), "{v} {id}");
        }

        // The event document only grows: what a plugin read from that
        // release's is still there.
        let old = json(&fixture(v).join("event.json"));
        let new = json(&event);
        assert_eq!(old["schema"], pathwarden_core::event::SCHEMA, "{v}");
        assert_eq!(new["schema"], pathwarden_core::event::SCHEMA, "{v}");
        let missing: Vec<_> = keys(&old).difference(&keys(&new)).cloned().collect();
        assert!(missing.is_empty(), "{v}: the event lost {missing:?}");
        for part in ["run", "posture", "plan"] {
            let missing: Vec<_> = keys(&old[part])
                .difference(&keys(&new[part]))
                .cloned()
                .collect();
            assert!(missing.is_empty(), "{v}: {part} lost {missing:?}");
        }
        let finding_keys = |e: &serde_json::Value| {
            e["findings"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(keys)
                .collect::<std::collections::BTreeSet<_>>()
        };
        let missing: Vec<_> = finding_keys(&old)
            .difference(&finding_keys(&new))
            .cloned()
            .collect();
        assert!(missing.is_empty(), "{v}: findings lost {missing:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The app's runs each release saved open here: listed, with their
/// findings, graph and retest data.
#[test]
fn each_release_s_app_runs_open() {
    for v in RELEASES {
        let dir = scratch(&format!("ws-{v}"));
        let root = dir.join("ws");
        copy_dir(&fixture(v).join("workspace"), &root);
        let ws = Workspace::open(&root).unwrap();
        let runs = ws.runs();
        assert_eq!(runs.len(), 1, "{v}");
        let run = &runs[0];
        assert_eq!(run.pathwarden, *v, "{v}");
        assert_eq!(run.domains, ["MGMT.LOCAL"], "{v}");
        assert!(run.shared.is_none(), "{v}");
        let rdir = ws.run_dir(&run.id).unwrap();
        assert!(pathwarden_ui::shared_runs::trusted_run_dir(&rdir), "{v}");
        assert!(
            pathwarden_ui::run_data::findings(&rdir).is_some_and(|f| !f.is_empty()),
            "{v}"
        );
        assert!(pathwarden_ui::run_data::graph(&rdir).is_some(), "{v}");
        assert!(pathwarden_ui::retest_ui::slice(&rdir).is_some(), "{v}");
        assert_eq!(ws.newer_run_folders(), 0, "{v}");
        let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"]));
        assert!(
            text.contains(&run.run_id()) || text.contains(&run.id),
            "{v}: {text}"
        );
        assert!(!text.contains("newer Pathwarden"), "{v}: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A reader of a history folder that holds a full run, `dir/ws` its
/// workspace; the history is a copy of `version`'s.
fn reader(version: &str, dir: &Path) -> PathBuf {
    let state = dir.join("state");
    copy_dir(&fixture(version).join("state"), &state);
    let root = dir.join("ws");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"local\"\npath = \"{}\"\n",
            state.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    state
}

/// What loading the history's full runs into `dir/ws` says, as a sync
/// does (a folder history has no sync of its own; the app loads them as
/// it records a run).
fn load_full_runs(dir: &Path) -> Option<String> {
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
    pathwarden_ui::shared_runs::mirror(&ws, &loc).words(false)
}

/// 0.1.9's full run loads, as a run of the history's (run folder format
/// 2): its summary is where Pathwarden 0.1.7 and earlier never look, so
/// they can't take it for one of their own.
#[test]
fn a_full_run_from_0_1_9_loads_out_of_older_versions_sight() {
    let dir = scratch("full-019");
    reader("0.1.9", &dir);
    let text = load_full_runs(&dir).unwrap_or_default();
    assert_eq!(text, "1 full run loaded from the folder.");
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let runs = ws.runs();
    assert_eq!(runs.len(), 1);
    let shared = runs[0].shared.as_ref().unwrap();
    assert_eq!(shared.pathwarden, "0.1.9");
    assert_eq!(shared.recorded_from, "cli");
    // The report was left out of the fixture: the run says so.
    assert_eq!(shared.left_out.len(), 1);
    let rdir = ws.run_dir(&runs[0].id).unwrap();
    assert!(rdir.join("summary.v2.json").is_file());
    assert!(!rdir.join("summary.json").exists());
    assert!(!pathwarden_ui::shared_runs::trusted_run_dir(&rdir));
    assert!(pathwarden_ui::run_data::graph(&rdir).is_some());
    let text = ok(&pw(
        &dir,
        &["runs", "show", &runs[0].id, "--workspace", "ws"],
    ));
    assert!(text.contains("Run details"), "{text}");

    // A run 0.1.9 loaded kept its summary at the format 1 name: the first
    // look from this version moves it.
    std::fs::rename(rdir.join("summary.v2.json"), rdir.join("summary.json")).unwrap();
    assert_eq!(ws.runs().len(), 1);
    assert!(rdir.join("summary.v2.json").is_file());
    assert!(!rdir.join("summary.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------- newer than this

/// A findings state a newer Pathwarden saved: the run stops before it
/// writes anything, and says to update.
#[test]
fn a_newer_findings_state_is_refused_and_left_alone() {
    let dir = scratch("newer-state");
    let (state, config) = old_history("0.1.9", &dir);
    let path = state.join("findings.json");
    let mut v = json(&path);
    v["version"] = 2.into();
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let before = snapshot(&state);
    let mgmt = repo("testdata/mgmt").to_string_lossy().into_owned();
    let text = failed(&pw(
        &dir,
        &[
            "run",
            "-c",
            &config.to_string_lossy(),
            "-i",
            &mgmt,
            "--no-outputs",
        ],
    ));
    assert!(
        text.contains("was saved by a newer Pathwarden (state version 2). Update Pathwarden"),
        "{text}"
    );
    assert_eq!(snapshot(&state), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `pathwarden.toml` of a newer format: refused by every command, and
/// never rewritten.
#[test]
fn a_newer_config_is_refused_and_left_alone() {
    let dir = scratch("newer-config");
    let (_, config) = old_history("0.1.9", &dir);
    let text = format!("format = 2\n{}", std::fs::read_to_string(&config).unwrap());
    std::fs::write(&config, &text).unwrap();
    let cfg = config.to_string_lossy().into_owned();
    let mgmt = repo("testdata/mgmt").to_string_lossy().into_owned();
    let words = "This pathwarden.toml was saved by a newer Pathwarden (format 2). Update \
                 Pathwarden to read it.";
    for args in [
        &["run", "-c", &cfg, "-i", &mgmt, "--no-outputs"][..],
        &["config", "rules", "set", "--stale-days", "60", "-c", &cfg][..],
    ] {
        let said = failed(&pw(&dir, args));
        assert!(said.contains(words), "{args:?}: {said}");
        assert_eq!(std::fs::read_to_string(&config).unwrap(), text, "{args:?}");
    }
    // Format 1, said or not, is this version's.
    let one = text.replacen("format = 2", "format = 1", 1);
    assert_eq!(
        Config::parse(&one).unwrap().format,
        Some(1),
        "an explicit format 1 reads"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A history point or `last-run.json` a newer Pathwarden saved is named,
/// never counted, and left in the history.
#[test]
fn newer_points_and_last_run_are_not_taken() {
    let dir = scratch("newer-point");
    let (state, config) = old_history("0.1.9", &dir);
    let id = "20261031T000000.000Z";
    let mut p = json(&state.join("history/20261030T151733.262Z.json"));
    p["version"] = 2.into();
    p["run_id"] = id.into();
    let newer = state.join(format!("history/{id}.json"));
    std::fs::write(&newer, serde_json::to_vec_pretty(&p).unwrap()).unwrap();
    let (points, skipped) = pathwarden_core::history::load(&state).unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(
        skipped[0].contains("saved by a newer Pathwarden"),
        "{skipped:?}"
    );
    let last = state.join("last-run.json");
    let mut l = json(&last);
    l["version"] = 2.into();
    std::fs::write(&last, serde_json::to_vec_pretty(&l).unwrap()).unwrap();
    let store =
        pathwarden_core::store::Store::new(&Config::from_file(&config).unwrap().state, None)
            .unwrap();
    assert!(pathwarden_core::store::last_run(&store).is_none());
    // A run of this version leaves the newer point and last run as they
    // are, and says so.
    let kept = std::fs::read(&newer).unwrap();
    let kept_last = std::fs::read(&last).unwrap();
    let mgmt = repo("testdata/mgmt").to_string_lossy().into_owned();
    let out = pw(
        &dir,
        &[
            "run",
            "-c",
            &config.to_string_lossy(),
            "-i",
            &mgmt,
            "--no-outputs",
        ],
    );
    ok(&out);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("last-run.json was saved by a newer Pathwarden, so it is left as it is."),
        "{said}"
    );
    assert_eq!(std::fs::read(&newer).unwrap(), kept);
    assert_eq!(std::fs::read(&last).unwrap(), kept_last);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full run whose folder here a newer Pathwarden saved isn't loaded
/// into it: no raw error, no half-made folder, said once.
#[test]
fn a_full_run_is_not_loaded_into_a_newer_folder() {
    let dir = scratch("into-newer");
    let state = reader("0.1.9", &dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let loc = pathwarden_ui::history_ui::locate(&ws, None).unwrap();
    let source = loc.dir.display().to_string();
    let id = "20261030T151733.132Z";
    let folder = pathwarden_ui::shared_runs::mirror_folder_id(&source, id).unwrap();
    let fdir = ws.runs_dir().join(&folder);
    std::fs::create_dir_all(&fdir).unwrap();
    std::fs::write(fdir.join("summary.v99999999999.json"), "{}").unwrap();
    let before = snapshot(&ws.runs_dir());
    let text = load_full_runs(&dir).unwrap_or_default();
    assert_eq!(
        text,
        "1 run on this computer was saved by a newer Pathwarden. Update Pathwarden to open it."
    );
    assert_eq!(snapshot(&ws.runs_dir()), before);
    assert!(state.join("runs").join(id).is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Editing a loaded run (its label) keeps it a loaded run's folder; a
/// summary at the format 1 name that says `shared` is moved too.
#[test]
fn a_loaded_run_stays_format_2_when_edited() {
    let dir = scratch("edit-loaded");
    reader("0.1.9", &dir);
    load_full_runs(&dir).unwrap();
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let id = ws.runs()[0].id.clone();
    let rdir = ws.run_dir(&id).unwrap();
    ok(&pw(
        &dir,
        &["label", &id, "after GPO fix", "--workspace", "ws"],
    ));
    assert!(rdir.join("summary.v2.json").is_file());
    assert!(!rdir.join("summary.json").exists());
    assert_eq!(ws.runs()[0].label.as_deref(), Some("after GPO fix"));
    // A summary that lost `shared` is still written at the folder's name.
    let loaded = std::fs::read(rdir.join("summary.v2.json")).unwrap();
    let mut s = ws.summary(&id).unwrap();
    s.shared = None;
    ws.update_summary(&s).unwrap();
    assert!(rdir.join("summary.v2.json").is_file());
    assert!(!rdir.join("summary.json").exists());
    // Marker gone, but a format 1 summary says it was loaded: moved all
    // the same.
    std::fs::remove_file(rdir.join(pathwarden_ui::shared_runs::LOADED_MARKER)).unwrap();
    std::fs::remove_file(rdir.join("summary.v2.json")).unwrap();
    std::fs::write(rdir.join("summary.json"), loaded).unwrap();
    assert_eq!(ws.runs().len(), 1);
    assert!(rdir.join("summary.v2.json").is_file());
    assert!(!rdir.join("summary.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Runs page and `pathwarden runs list` say the same sentence of run
/// folders a newer Pathwarden saved.
#[test]
fn the_newer_runs_note_is_the_same_on_the_page_and_the_command_line() {
    let dir = scratch("note-parity");
    let root = dir.join("ws");
    copy_dir(&fixture("0.1.9").join("workspace"), &root);
    let ws = Workspace::open(&root).unwrap();
    for run in ["20261030-151733-aaaaaa", "20261030-151733-bbbbbb"] {
        let d = root.join("runs").join(run);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("summary.v3.json"), "{}").unwrap();
    }
    let words = "2 runs on this computer were saved by a newer Pathwarden. Update Pathwarden to \
                 open them.";
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"]));
    assert!(text.contains(words), "{text}");
    let snap = pathwarden_ui::history_ui::snapshot(&ws, None);
    let page = pathwarden_ui::history_ui::runs_note(&ws, &ws.runs(), &snap);
    assert!(page.contains(words), "{page}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full run of a newer format isn't loaded: the pull says to update,
/// and the history's files stay as they are.
#[test]
fn a_newer_full_run_is_not_loaded() {
    let dir = scratch("newer-full");
    let state = reader("0.1.9", &dir);
    let manifest = state.join("runs/20261030T151733.132Z/run.json");
    let mut m = json(&manifest);
    m["format"] = 99.into();
    m["pathwarden"] = "9.0.0".into();
    std::fs::write(&manifest, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let before = snapshot(&state);
    let text = load_full_runs(&dir).unwrap_or_default();
    assert_eq!(
        text,
        "Run 20261030T151733.132Z was saved by Pathwarden 9.0.0. Update Pathwarden to open it."
    );
    let ws = Workspace::open(dir.join("ws")).unwrap();
    assert!(ws.runs().iter().all(|r| r.shared.is_none()));
    assert_eq!(snapshot(&state), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run folder a newer Pathwarden saved (a summary of a format after 2)
/// is never listed or opened: the run list says how many there are.
#[test]
fn a_newer_run_folder_is_skipped_and_counted() {
    let dir = scratch("newer-folder");
    let root = dir.join("ws");
    copy_dir(&fixture("0.1.9").join("workspace"), &root);
    let ws = Workspace::open(&root).unwrap();
    let id = ws.runs()[0].id.clone();
    let rdir = root.join("runs").join(&id);
    std::fs::rename(rdir.join("summary.json"), rdir.join("summary.v3.json")).unwrap();
    let before = snapshot(&rdir);
    assert!(ws.runs().is_empty());
    assert!(ws.run_dir(&id).is_none());
    assert_eq!(ws.newer_run_folders(), 1);
    let text = ok(&pw(&dir, &["runs", "list", "--workspace", "ws"]));
    assert!(
        text.contains(
            "1 run on this computer was saved by a newer Pathwarden. Update Pathwarden to open it."
        ),
        "{text}"
    );
    let shown: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["runs", "list", "--workspace", "ws", "--json"],
    )))
    .unwrap();
    assert_eq!(shown["newer_runs"], 1, "{shown}");
    // Even with a format 1 summary beside it, the folder is the newer
    // version's.
    std::fs::copy(rdir.join("summary.v3.json"), rdir.join("summary.json")).unwrap();
    assert!(ws.runs().is_empty());
    std::fs::remove_file(rdir.join("summary.json")).unwrap();
    assert_eq!(snapshot(&rdir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A newer version's folder is left untouched even when it looks like a
/// run 0.1.9 loaded: run_dir doesn't move its summary.
#[test]
fn a_newer_folder_is_never_migrated() {
    let dir = scratch("newer-migrate");
    let root = dir.join("ws");
    copy_dir(&fixture("0.1.9").join("workspace"), &root);
    let ws = Workspace::open(&root).unwrap();
    let id = ws.runs()[0].id.clone();
    let rdir = root.join("runs").join(&id);
    std::fs::write(rdir.join(pathwarden_ui::shared_runs::LOADED_MARKER), "x").unwrap();
    std::fs::write(rdir.join("summary.v3.json"), "{}").unwrap();
    let before = snapshot(&rdir);
    assert!(ws.run_dir(&id).is_none());
    assert!(ws.runs().is_empty());
    assert!(rdir.join("summary.json").is_file());
    assert!(!rdir.join("summary.v2.json").exists());
    assert_eq!(snapshot(&rdir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The files of a run folder that carry their own version or schema: one
/// a newer Pathwarden wrote isn't read as this one's.
#[test]
fn newer_run_files_are_not_read() {
    use std::io::Write as _;
    let gz = |v: &serde_json::Value| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&serde_json::to_vec(v).unwrap()).unwrap();
        e.finish().unwrap()
    };
    let ungz = |p: &Path| -> serde_json::Value {
        use std::io::Read as _;
        let mut s = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(p).unwrap())
            .read_to_end(&mut s)
            .unwrap();
        serde_json::from_slice(&s).unwrap()
    };
    let dir = scratch("newer-files");
    let root = dir.join("ws");
    copy_dir(&fixture("0.1.9").join("workspace"), &root);
    let ws = Workspace::open(&root).unwrap();
    let rdir = ws.run_dir(&ws.runs()[0].id).unwrap();
    for (file, key, value) in [
        ("objects.json.gz", "version", serde_json::json!(2)),
        ("retest.json.gz", "version", serde_json::json!(2)),
        (
            "event.json.gz",
            "schema",
            serde_json::json!("pathwarden.event.v2"),
        ),
    ] {
        let mut v = ungz(&rdir.join(file));
        v[key] = value;
        std::fs::write(rdir.join(file), gz(&v)).unwrap();
    }
    assert!(pathwarden_ui::run_data::graph(&rdir).is_none());
    assert!(pathwarden_ui::retest_ui::slice(&rdir).is_none());
    assert!(pathwarden_ui::run_data::findings(&rdir).is_none());
    // retests.json: not read, never recorded into or rewritten.
    let rec: pathwarden_ui::retest_ui::RetestRecord = serde_json::from_value(serde_json::json!({
        "fingerprint": "PW-003-1", "at": 1, "method": "targeted", "verdict": "fixed"
    }))
    .unwrap();
    let newer = serde_json::json!({"version": 2, "results": [rec]}).to_string();
    let log = rdir.join(pathwarden_ui::retest_ui::RETESTS_FILE);
    std::fs::write(&log, &newer).unwrap();
    assert!(pathwarden_ui::retest_ui::load_log(&rdir).results.is_empty());
    let e = pathwarden_ui::retest_ui::record(&rdir, rec.clone()).unwrap_err();
    assert_eq!(e.to_string(), pathwarden_ui::retest_ui::NEWER_RETESTS_WORDS);
    assert_eq!(std::fs::read_to_string(&log).unwrap(), newer);
    // One of this version's reads and records.
    std::fs::write(&log, newer.replace("\"version\":2", "\"version\":1")).unwrap();
    assert_eq!(pathwarden_ui::retest_ui::load_log(&rdir).results.len(), 1);
    pathwarden_ui::retest_ui::record(&rdir, rec).unwrap();
    assert_eq!(pathwarden_ui::retest_ui::load_log(&rdir).results.len(), 2);
    // Timings: the same.
    let t = r#"{"version":2,"collector":"built-in","total_ms":1,"phases":[]}"#;
    assert!(pathwarden_core::diagnostics::CollectionTimings::parse(t).is_none());
    assert!(pathwarden_core::diagnostics::CollectionTimings::parse(
        &t.replace("\"version\":2", "\"version\":1")
    )
    .is_some());
    let _ = std::fs::remove_dir_all(&dir);
}
