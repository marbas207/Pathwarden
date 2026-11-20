//! Other collectors' files analyzed with a collection: AzureHound,
//! OpenGraph or SharpHound files read in the same analysis as a built-in
//! collection, before it starts (the Collect page) or afterwards, from a
//! run whose raw collection was kept (Run details' "Add other data").
//!
//! Afterwards is the Analyze page with the run's kept collection as its
//! first input (`/analyze?from=<run>`); the command line names the same
//! collection with `-i run:<ID>` ([`resolve_inputs`]). Both find it here
//! ([`kept_collection`], [`find_kept`]), so they agree on which runs can
//! be added to and say why not in the same words.

use std::path::{Path, PathBuf};

use crate::workspace::{RunSummary, Workspace};

/// The section's heading in Run details.
pub const TITLE: &str = "Add other data";
/// Its button.
pub const BUTTON: &str = "Add files and analyze again";
/// The line beside the button, when the collection is there.
pub const READY: &str = "Analyzes this run's collection again with AzureHound, OpenGraph or \
SharpHound files, as a new run.";
/// The line when the raw collection wasn't kept.
pub const NOT_KEPT: &str =
    "The raw collection wasn't kept. Tick Keep the raw collection next time.";
/// The line when it was kept, but is no longer where it was.
pub const GONE: &str = "The kept collection was moved or deleted, so there is nothing to add to.";

/// The input prefix that names a run's kept collection on the command line.
pub const INPUT_PREFIX: &str = "run:";

/// What a run's raw collection is to "Add other data".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// Kept, and still there.
    Here(PathBuf),
    /// Collected here, but not kept.
    NotKept,
    /// Kept, but no longer where it was kept.
    Gone,
}

impl Kept {
    /// The line Run details shows beside the button.
    pub fn line(&self) -> &'static str {
        match self {
            Kept::Here(_) => READY,
            Kept::NotKept => NOT_KEPT,
            Kept::Gone => GONE,
        }
    }
}

/// Whether `r`'s collection can be analyzed again with other files: `None`
/// for a run that didn't come from a collection on this computer (an
/// upload, the demo, a run loaded from the run history), which has
/// nothing to say about it.
pub fn kept_collection(r: &RunSummary) -> Option<Kept> {
    if r.shared.is_some() || r.demo {
        return None;
    }
    let c = r.collection.as_ref()?;
    let Some(kept) = c.kept.as_deref().map(str::trim).filter(|k| !k.is_empty()) else {
        return Some(Kept::NotKept);
    };
    // Looking at a network path signs in to its server: never here.
    if crate::security::is_network_path(kept) {
        return Some(Kept::Gone);
    }
    let path = PathBuf::from(kept);
    Some(if path.exists() {
        Kept::Here(path)
    } else {
        Kept::Gone
    })
}

/// The run `id` (its folder ID, or the history's run ID) among `runs`.
fn find<'a>(runs: &'a [RunSummary], id: &str) -> Option<&'a RunSummary> {
    runs.iter().find(|r| r.id == id).or_else(|| {
        crate::workspace::looks_like_history_id(id)
            .then(|| runs.iter().find(|r| r.run_id() == id))
            .flatten()
    })
}

/// The kept collection of run `id` in `ws`'s environment, or with
/// `every_env` in any environment of the workspace: the run and the
/// folder, or why there is none, in words.
pub fn find_kept(
    ws: &Workspace,
    id: &str,
    every_env: bool,
) -> Result<(RunSummary, PathBuf), String> {
    let runs = if every_env { ws.all_runs() } else { ws.runs() };
    let Some(r) = find(&runs, id) else {
        return Err(format!("There is no run {id}."));
    };
    match kept_collection(r) {
        Some(Kept::Here(p)) => Ok((r.clone(), p)),
        Some(other) => Err(other.line().to_string()),
        None => Err("That run wasn't collected here, so there is nothing to add to.".into()),
    }
}

/// The run ID an input names with [`INPUT_PREFIX`] (`run:ID`), if it does.
pub fn input_run(p: &Path) -> Option<&str> {
    let s = p.to_str()?;
    let (head, id) = s.split_at_checked(INPUT_PREFIX.len())?;
    (head.eq_ignore_ascii_case(INPUT_PREFIX) && !id.trim().is_empty()).then(|| id.trim())
}

/// Replaces every `run:ID` among `inputs` with that run's kept collection,
/// found in `ws` (its environment, or with `every_env` any): the runs, and
/// the other inputs' names (for [`source_with`]). An input that names no
/// run, or a run whose collection is not kept, is an error.
pub fn resolve_inputs(
    inputs: &mut [PathBuf],
    ws: &Workspace,
    every_env: bool,
) -> Result<Resolved, String> {
    let mut out = Resolved::default();
    for p in inputs.iter_mut() {
        // Not a run's (or a file or folder that is really named so): read
        // as it is.
        let Some(id) = input_run(p).filter(|_| !p.exists()).map(str::to_string) else {
            out.added.push(
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| p.display().to_string()),
            );
            continue;
        };
        let runs = if every_env { ws.all_runs() } else { ws.runs() };
        let Some(run) = find(&runs, &id) else {
            return Err(format!("{INPUT_PREFIX}{id}: there is no run {id}."));
        };
        // Said for any command `-i` goes with, not only for adding files.
        let why = match kept_collection(run) {
            Some(Kept::Here(dir)) => {
                *p = dir;
                out.runs.push(run.clone());
                continue;
            }
            Some(Kept::NotKept) => "its raw collection wasn't kept",
            Some(Kept::Gone) => "its kept collection was moved or deleted",
            None => "it has no raw collection on this computer (it wasn't collected here)",
        };
        return Err(format!(
            "{INPUT_PREFIX}{id}: {why}, so -i can't read it. {SAVED_RUN_HINT}"
        ));
    }
    Ok(out)
}

/// What `-i run:ID` says when the run has no collection to read.
pub const SAVED_RUN_HINT: &str = "A saved run is read with --run ID by summary, reach, search, \
query, path, zones suggest and zones preview; `runs show ID` shows its exposure, findings and \
plan steps, as its page does.";

/// What [`resolve_inputs`] found.
#[derive(Debug, Default)]
pub struct Resolved {
    /// The runs whose kept collections are read, in order.
    pub runs: Vec<RunSummary>,
    /// The names of the other inputs.
    pub added: Vec<String>,
}

impl Resolved {
    /// The source a saved run says it came from, and how it was collected,
    /// as the app saves a run analyzed again with other files: the first
    /// run's. `None` when no input named a run.
    pub fn saved_as(&self) -> Option<(String, Option<crate::workspace::CollectionInfo>)> {
        let r = self.runs.first()?;
        Some((source_with(&r.source, &self.added), r.collection.clone()))
    }
}

/// Whether any of `inputs` names a run's kept collection.
pub fn names_a_run(inputs: &[PathBuf]) -> bool {
    inputs.iter().any(|p| input_run(p).is_some())
}

/// The source of a run analyzed with other files: what was analyzed first
/// (the collection, without the files an earlier run added to it), then
/// the files.
pub fn source_with(source: &str, files: &[String]) -> String {
    let source = source.split_once(WITH).map_or(source, |(base, _)| base);
    match files {
        [] => source.to_string(),
        [one] => format!("{source}{WITH}{one}"),
        many => format!("{source}{WITH}{} other files", many.len()),
    }
}

/// What [`source_with`] puts between the collection and the files.
const WITH: &str = ", with ";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::CollectionInfo;

    /// A fresh, empty folder for one test.
    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pathwarden-add-data-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn collected(kept: Option<String>) -> RunSummary {
        let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
            "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
            "tier_zero_population": 100, "tier_zero_objects": 1,
            "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                "resolved": 0},
            "recorded_by": "app",
        }))
        .unwrap();
        let mut r = crate::history_ui::point_summary(&p, &[]);
        r.id = "20261105-101500-abcdef".into();
        r.source = "Collected from contoso.local (Full, built-in)".into();
        r.domains = vec!["CONTOSO.LOCAL".into()];
        r.collection = Some(CollectionInfo {
            method: "builtin".into(),
            scope: "all".into(),
            domain: "contoso.local".into(),
            server: None,
            ldaps: false,
            current_user: true,
            warnings: Vec::new(),
            kept,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
            read_started: None,
        });
        r
    }

    #[test]
    fn what_a_run_can_add_to() {
        let dir = temp("what");
        let here = collected(Some(dir.display().to_string()));
        assert_eq!(kept_collection(&here), Some(Kept::Here(dir.clone())));
        assert_eq!(kept_collection(&here).unwrap().line(), READY);
        let gone = collected(Some(dir.join("moved").display().to_string()));
        assert_eq!(kept_collection(&gone), Some(Kept::Gone));
        let not_kept = collected(None);
        assert_eq!(kept_collection(&not_kept), Some(Kept::NotKept));
        assert!(NOT_KEPT.contains("Tick Keep the raw collection next time."));
        // Never looked at: a network path.
        let unc = collected(Some(r"\\fileserver\share\collection".into()));
        assert_eq!(kept_collection(&unc), Some(Kept::Gone));
        // An upload, the demo: nothing to say.
        let mut upload = collected(None);
        upload.collection = None;
        assert_eq!(kept_collection(&upload), None);
        let mut demo = collected(Some(dir.display().to_string()));
        demo.demo = true;
        assert_eq!(kept_collection(&demo), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inputs_name_runs() {
        assert_eq!(
            input_run(Path::new("run:20261105-101500-abcdef")),
            Some("20261105-101500-abcdef")
        );
        assert_eq!(input_run(Path::new("RUN:x")), Some("x"));
        assert_eq!(input_run(Path::new("run:")), None);
        assert_eq!(input_run(Path::new("runs/x.json")), None);
        assert_eq!(input_run(Path::new("demo:")), None);
        assert!(names_a_run(&["a.zip".into(), "run:x".into()]));
        assert!(!names_a_run(&["a.zip".into()]));
    }

    #[test]
    fn sources_say_what_was_added() {
        let s = "Collected from contoso.local (Full, built-in)";
        assert_eq!(source_with(s, &[]), s);
        assert_eq!(
            source_with(s, &["contoso-azurehound.json".into()]),
            "Collected from contoso.local (Full, built-in), with contoso-azurehound.json"
        );
        assert_eq!(
            source_with(s, &["a.json".into(), "b.json".into()]),
            "Collected from contoso.local (Full, built-in), with 2 other files"
        );
        // Added to again: the collection, with the files added now.
        assert_eq!(
            source_with(
                "Collected from contoso.local (Full, built-in), with a.json",
                &["b.json".into()]
            ),
            "Collected from contoso.local (Full, built-in), with b.json"
        );
    }

    #[test]
    fn runs_are_found_in_the_workspace() {
        let root = temp("find");
        let ws = Workspace::open(&root).unwrap();
        let kept = root.join("collections").join("x");
        std::fs::create_dir_all(&kept).unwrap();
        let r = collected(Some(kept.display().to_string()));
        ws.save_run(&r, "<html></html>").unwrap();
        let mut not_kept = collected(None);
        not_kept.id = "20261105-111500-fedcba".into();
        ws.save_run(&not_kept, "<html></html>").unwrap();

        let (found, dir) = find_kept(&ws, &r.id, true).unwrap();
        assert_eq!(
            (found.id.as_str(), dir.as_path()),
            (r.id.as_str(), kept.as_path())
        );
        assert_eq!(find_kept(&ws, &not_kept.id, true).unwrap_err(), NOT_KEPT);
        assert_eq!(
            find_kept(&ws, "20990101-000000-000000", true).unwrap_err(),
            "There is no run 20990101-000000-000000."
        );

        let mut inputs = vec![
            PathBuf::from("contoso-azurehound.json"),
            PathBuf::from(format!("run:{}", r.id)),
        ];
        let found = resolve_inputs(&mut inputs, &ws, true).unwrap();
        assert_eq!(inputs[1], kept);
        assert_eq!(found.added, ["contoso-azurehound.json"]);
        let (source, collection) = found.saved_as().unwrap();
        assert_eq!(
            source,
            "Collected from contoso.local (Full, built-in), with contoso-azurehound.json"
        );
        assert_eq!(collection, r.collection);
        let mut bad = vec![PathBuf::from(format!("run:{}", not_kept.id))];
        let e = resolve_inputs(&mut bad, &ws, true).unwrap_err();
        assert!(
            e.starts_with("run:20261105-111500-fedcba: its raw collection wasn't kept"),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
