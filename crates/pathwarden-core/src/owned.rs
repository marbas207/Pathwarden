//! Objects marked as owned, kept per environment.
//!
//! BloodHound CE's `Tag_Owned`: the objects an assessor has taken, to ask
//! what they lead to (`MATCH p=shortestPath((s:Tag_Owned)-[...]->(t))`).
//! The app's Explore page marks them on the Object tab and `pathwarden
//! owned` from the terminal, both through this module, into `owned.json`
//! in the environment's folder; Cypher queries on that environment's runs
//! see them as `Tag_Owned`.
//!
//! Marks are object IDs (upper-cased), so they hold from run to run. They
//! are local to this computer: not settings, and not shared with a
//! history's repository.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file in an environment's folder.
pub const FILE: &str = "owned.json";

/// The most objects one environment keeps marked.
pub const MAX_OWNED: usize = 10_000;

const VERSION: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Doc {
    version: u32,
    /// Object IDs, upper-cased, sorted.
    objects: Vec<String>,
}

fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// What a newer `owned.json` makes every page and command say.
pub const NEWER: &str =
    "owned.json was saved by a newer Pathwarden. Update Pathwarden to change the owned marks.";

/// Why an environment's marks can't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// A newer Pathwarden wrote the file: it is not read, nor written over.
    Newer,
    /// The file is damaged or can't be opened (why, without its path).
    Unreadable(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Newer => f.write_str(NEWER),
            LoadError::Unreadable(why) => write!(f, "owned.json can't be read ({why})."),
        }
    }
}

/// The object IDs marked as owned in the environment at `dir`, sorted and
/// each once (none when nothing was ever marked).
pub fn load(dir: &Path) -> Result<Vec<String>, LoadError> {
    let text = match std::fs::read_to_string(path(dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(LoadError::Unreadable(e.to_string())),
    };
    // The version first: a newer file may be shaped otherwise.
    #[derive(Deserialize)]
    struct Version {
        version: u32,
    }
    let v: Version =
        serde_json::from_str(&text).map_err(|e| LoadError::Unreadable(e.to_string()))?;
    if v.version > VERSION {
        return Err(LoadError::Newer);
    }
    let doc: Doc = serde_json::from_str(&text).map_err(|e| LoadError::Unreadable(e.to_string()))?;
    let mut ids: Vec<String> = doc.objects.iter().map(|id| normal(id)).collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// The marks a query uses: the environment's, or none and a note saying
/// why (the app and the CLI add it to the answer's notes).
pub fn for_query(dir: &Path) -> (Vec<String>, Option<String>) {
    match load(dir) {
        Ok(ids) => (ids, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    }
}

fn normal(id: &str) -> String {
    id.trim().to_ascii_uppercase()
}

/// Marks `ids` as owned (`true`) or not (`false`), under the environment's
/// settings lock so the app and the terminal never lose a change. Returns
/// how many objects are marked after it.
pub fn set(dir: &Path, ids: &[String], owned: bool) -> Result<usize, String> {
    let p = path(dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    crate::config_edit::with_lock(&p, || {
        let mut all = load(dir).map_err(|e| e.to_string())?;
        for id in ids.iter().map(|i| normal(i)).filter(|i| !i.is_empty()) {
            match all.binary_search(&id) {
                Ok(i) if !owned => {
                    all.remove(i);
                }
                Err(i) if owned => {
                    if all.len() >= MAX_OWNED {
                        return Err(format!(
                            "at most {} objects can be marked as owned",
                            crate::text::num(MAX_OWNED)
                        ));
                    }
                    all.insert(i, id);
                }
                _ => {}
            }
        }
        let doc = Doc {
            version: VERSION,
            objects: all,
        };
        let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
        crate::config_edit::write_atomic(&p, &text)
            .map_err(|e| format!("writing {}: {e}", p.display()))?;
        Ok(doc.objects.len())
    })
}

/// How many objects are marked, in a sentence: what the app and
/// `pathwarden owned` both say.
pub fn summary(n: usize) -> String {
    match n {
        0 => "No object is marked as owned.".to_string(),
        n => format!(
            "{} marked as owned.",
            crate::text::count(n, "object is", "objects are")
        ),
    }
}

/// The marked objects that are in `g`, as its nodes.
pub fn in_graph(g: &crate::graph::AdGraph, ids: &[String]) -> Vec<crate::NodeIndex> {
    ids.iter().filter_map(|id| g.lookup(id)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_kept_sorted_and_once() {
        let dir = std::env::temp_dir().join(format!("pathwarden-owned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&dir).unwrap().is_empty());
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            set(
                &dir,
                &ids(&["s-1-5-21-1-1-1102", "S-1-5-21-1-1-1101"]),
                true
            ),
            Ok(2)
        );
        assert_eq!(set(&dir, &ids(&[" S-1-5-21-1-1-1101 "]), true), Ok(2));
        assert_eq!(
            load(&dir).unwrap(),
            ids(&["S-1-5-21-1-1-1101", "S-1-5-21-1-1-1102"])
        );
        assert_eq!(set(&dir, &ids(&["S-1-5-21-1-1-1101"]), false), Ok(1));
        assert_eq!(set(&dir, &ids(&["S-1-5-21-9-9-9"]), false), Ok(1));
        assert_eq!(load(&dir).unwrap(), ids(&["S-1-5-21-1-1-1102"]));
        // A newer file is not read as this one's, nor written over, and a
        // query runs without marks and says why.
        std::fs::write(dir.join(FILE), r#"{"version": 9, "marks": {}}"#).unwrap();
        assert_eq!(load(&dir), Err(LoadError::Newer));
        assert_eq!(
            set(&dir, &ids(&["S-1-5-21-1-1-1101"]), true),
            Err(NEWER.to_string())
        );
        assert_eq!(for_query(&dir), (Vec::new(), Some(NEWER.to_string())));
        // A damaged one says so, without its path.
        std::fs::write(dir.join(FILE), "{").unwrap();
        let err = load(&dir).unwrap_err().to_string();
        assert!(err.starts_with("owned.json can't be read ("), "{err}");
        assert!(!err.contains(&dir.display().to_string()), "{err}");
        // Read sorted and once, whoever wrote it.
        std::fs::write(
            dir.join(FILE),
            r#"{"version": 1, "objects": ["S-2", "s-1", "S-2"]}"#,
        )
        .unwrap();
        assert_eq!(load(&dir).unwrap(), ids(&["S-1", "S-2"]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
