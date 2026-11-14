//! The demo's earlier runs: SCALE.LOCAL one to four weeks before the demo's
//! collection (`demo-history/`, made by `scripts/gen_scale_fixture.py
//! --stage 1..4`), recorded in the demo environment's own run history the
//! first time the demo runs, eight days apart, so Progress, What changed and
//! the report's Introduced filter have real changes to show: a finding fixed and
//! back again, objects gained and lost, a completeness drop, a member into
//! and out of Tier Zero, new paths into Tier Zero and into a zone, a new
//! finding. The demo's own run, dated now, follows them.
//!
//! The demo environment also gets a zone, "R01 servers", so the paths into
//! it show; it's written only when the environment has no settings yet.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use pathwarden_core::analyze;
use pathwarden_core::config::Config;
use pathwarden_core::record::RecordProgress;

use crate::environments::Assigned;
use crate::jobs::{save_analysis, SaveRun};
use crate::workspace::{new_run_id, Workspace};

/// The earlier collections, oldest first: (file name, zip).
pub const EARLIER: [(&str, &[u8]); 4] = [
    (
        "20260903020000_PathwardenDemo.zip",
        include_bytes!("../../../demo-history/20260903020000_PathwardenDemo.zip"),
    ),
    (
        "20260910020000_PathwardenDemo.zip",
        include_bytes!("../../../demo-history/20260910020000_PathwardenDemo.zip"),
    ),
    (
        "20260917020000_PathwardenDemo.zip",
        include_bytes!("../../../demo-history/20260917020000_PathwardenDemo.zip"),
    ),
    (
        "20260924020000_PathwardenDemo.zip",
        include_bytes!("../../../demo-history/20260924020000_PathwardenDemo.zip"),
    ),
];

/// The progress line while the earlier runs are recorded (Analyze, and
/// `pathwarden demo`).
pub const BUILDING: &str = "Building the demo's earlier runs";

/// "2 of 4": the earlier runs recorded so far, of [`EARLIER`].
pub fn count_words(done: usize) -> String {
    format!("{done} of {}", EARLIER.len())
}

/// Days between the analyses (the collections are a week apart): eight, so
/// the first run, whose findings are all new, falls outside "Last 30 days",
/// and "Last 7 days" is the demo's own run alone.
pub const GAP: i64 = 8 * 86_400;

/// The demo environment's zone: the messy region's server admin groups,
/// which the later runs give new paths into.
pub const ZONE_CONFIG: &str = "# The demo's settings: one Privilege Zone, so the demo shows paths into it.\n\
[[zone]]\n\
name = \"R01 servers\"\n\
groups = [\"R01S00-SERVERADMINS@SCALE.LOCAL\", \"R01S01-SERVERADMINS@SCALE.LOCAL\", \"R01S02-SERVERADMINS@SCALE.LOCAL\", \"R01S03-SERVERADMINS@SCALE.LOCAL\"]\n";

/// Whether the demo environment `ws` still needs its earlier runs: it has
/// no run yet.
pub fn needed(ws: &Workspace) -> bool {
    ws.runs().is_empty()
}

/// Writes the demo's zone when the environment `ws` has no settings yet.
pub fn ensure_zone(ws: &Workspace) -> Result<(), String> {
    let path = ws.config_path();
    if path.exists() {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{e}"))?;
    }
    std::fs::write(&path, ZONE_CONFIG)
        .map_err(|e| format!("Couldn't write the demo's settings: {e}"))
}

/// Records the earlier runs in the demo environment `ws`, the last [`GAP`]
/// before `now`, with `config` (the environment's). Each zip is written to a
/// folder of this recording's own under `scratch` while it is read, so two
/// recordings at once (the app and `pathwarden demo`, or two test runs
/// sharing the system temp folder) never read each other's half-written zip.
/// `progress` gets every step, and `recorded` the number recorded so far
/// after each one.
pub fn record<P: RecordProgress>(
    ws: &Workspace,
    config: &Config,
    state_dir: Option<&Path>,
    scratch: &Path,
    now: i64,
    progress: &mut P,
    recorded: &mut dyn FnMut(usize),
) -> Result<(), String> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let own = scratch.join(format!(
        "pathwarden-demo-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&own).map_err(|e| format!("Couldn't prepare the demo: {e}"))?;
    let done = record_in(ws, config, state_dir, &own, now, progress, recorded);
    let _ = std::fs::remove_dir_all(&own);
    done
}

fn record_in<P: RecordProgress>(
    ws: &Workspace,
    config: &Config,
    state_dir: Option<&Path>,
    own: &Path,
    now: i64,
    progress: &mut P,
    recorded: &mut dyn FnMut(usize),
) -> Result<(), String> {
    let n = EARLIER.len() as i64;
    for (i, (name, zip)) in EARLIER.iter().enumerate() {
        let file = own.join(name);
        std::fs::write(&file, zip).map_err(|e| format!("Couldn't prepare the demo: {e}"))?;
        let ev = analyze::evaluate(std::slice::from_ref(&file), config, &[], progress)
            .map_err(|e| format!("{e:#}"))?;
        let _ = std::fs::remove_file(&file);
        let at = now - (n - i as i64) * GAP;
        let id = new_run_id(at);
        save_analysis(
            ws,
            config,
            ev,
            SaveRun {
                id: &id,
                source: "Demo data".into(),
                demo: true,
                label: None,
                collection: None,
                timings: None,
                how: Assigned::Current,
                state_dir,
                started_ms: (at - 60) * 1000,
                recorded_by: pathwarden_core::record::by::UI,
                finished_at: Some(at),
                inputs: &[],
            },
            progress,
        )?;
        recorded(i + 1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathwarden_core::analyze::{Phase, Progress};

    struct Quiet;
    impl Progress for Quiet {
        fn phase(&mut self, _: Phase) {}
    }
    impl RecordProgress for Quiet {
        fn warn(&mut self, _: String) {}
    }

    /// Two recordings at once with the same scratch folder (the system temp
    /// folder, when nothing else is given) each read their own zips, and
    /// leave nothing behind.
    #[test]
    fn two_recordings_at_once_share_a_scratch_folder() {
        let root = std::env::temp_dir().join(format!("pw-demo-twice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let scratch = root.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let runs: Vec<_> = (0..2)
            .map(|i| {
                let (root, scratch) = (root.clone(), scratch.clone());
                std::thread::spawn(move || {
                    let ws = Workspace::open(root.join(format!("ws{i}"))).unwrap();
                    record(
                        &ws,
                        &Config::default(),
                        None,
                        &scratch,
                        analyze::now(),
                        &mut Quiet,
                        &mut |_| {},
                    )
                })
            })
            .collect();
        for r in runs {
            r.join().unwrap().unwrap();
        }
        assert!(
            std::fs::read_dir(&scratch).unwrap().next().is_none(),
            "left in the scratch folder"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
