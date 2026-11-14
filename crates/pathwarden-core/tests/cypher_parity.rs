//! Cypher result-parity harness (design §4).
//!
//! Runs each committed golden's query through Pathwarden's Cypher engine over
//! the shared `data/goad` capture, normalises the result, and asserts set
//! equality against the golden BHE captured. The Pathwarden side needs no BHE —
//! the goldens are snapshots taken once from a pinned BHE (a separate manual lab
//! step; see `tests/parity/README.md`).
//!
//! The test is **gated** on two things being present, mirroring how the
//! object-index tests gate on `testdata/`:
//!   - the git-ignored `data/goad` capture, and
//!   - at least one golden file under `tests/parity/golden/`.
//!
//! When either is absent the test skips, so the harness wiring is always
//! compiled and exercised even before the first BHE capture. The skip is
//! visible: a `SKIPPED` line past the output capture, a warning annotation
//! on GitHub Actions, and a failure under `PATHWARDEN_REQUIRE_PARITY=1`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pathwarden_core::cypher::{self, AdGraphView, EvalLimits};
use pathwarden_core::graph::AdGraph;
use pathwarden_core::{load, LoadOptions};
use serde::Deserialize;

/// One golden snapshot: the query plus the normalised result BHE returned.
#[derive(Debug, Deserialize)]
struct Golden {
    id: String,
    query: String,
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    relationships: Vec<(String, String, String)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/parity")
}

fn goad_dir() -> PathBuf {
    // crates/pathwarden-core -> workspace root -> data/goad
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/goad")
}

/// Golden files under `tests/parity/golden/`, excluding the `.gitkeep` marker.
fn goldens() -> Vec<PathBuf> {
    let dir = parity_dir().join("golden");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect()
}

fn load_goad() -> AdGraph {
    let dir = goad_dir();
    // As `pathwarden query` loads: every collector property kept.
    let opts = LoadOptions {
        all_properties: true,
        ..LoadOptions::default()
    };
    load(&[dir], &opts)
        .expect("loading data/goad for the parity harness")
        .0
}

/// The normal form (design §4.1): a set of upper-cased objectids, and a set of
/// `(src, TYPE, tgt)` relationship triples.
fn normalise(
    result: &cypher::QueryResult,
) -> (BTreeSet<String>, BTreeSet<(String, String, String)>) {
    let nodes = result.node_ids();
    let rels = result.relationships.iter().cloned().collect();
    (nodes, rels)
}

/// Reports that a check on the capture did not run, so a skip never reads as a
/// pass: written past the test harness's output capture (which only takes
/// `print!` and friends), so it shows in every log; a warning annotation on
/// GitHub Actions; and a failure when `PATHWARDEN_REQUIRE_PARITY` is `1` or `true`
/// (for the job that has the capture and the goldens).
fn skip(why: &str) {
    use std::io::Write;
    if std::env::var("PATHWARDEN_REQUIRE_PARITY").is_ok_and(|v| v == "1" || v == "true") {
        panic!("cypher parity required but skipped: {why}");
    }
    // A workflow command counts only at the start of a line, and the test
    // harness may have left its own line unfinished.
    let line = if std::env::var_os("GITHUB_ACTIONS").is_some() {
        format!("\n::warning title=Cypher parity skipped::{why}\n")
    } else {
        format!("SKIPPED cypher parity: {why}\n")
    };
    let _ = std::io::stdout().lock().write_all(line.as_bytes());
}

fn run(view: &AdGraphView, query: &str) -> cypher::QueryResult {
    cypher::run(view, query, &EvalLimits::default()).expect("query should parse and evaluate")
}

/// The kept properties answer queries on the real capture, and what they
/// cost per object (run with `--nocapture` to see it).
#[test]
fn goad_keeps_bloodhound_properties() {
    if !Path::new(&goad_dir()).exists() {
        return skip(&format!("{} not present", goad_dir().display()));
    }
    let graph = load_goad();
    let view = AdGraphView::new(&graph);
    let named = run(
        &view,
        r#"MATCH (n:User) WHERE n.samaccountname = "jon.snow" RETURN n"#,
    );
    assert_eq!(named.node_ids().len(), 1);
    let mut per_kind = std::collections::BTreeMap::<&str, (usize, usize, usize)>::new();
    for (_, n) in graph.nodes().filter(|(_, n)| !n.placeholder) {
        let e = per_kind.entry(n.kind.as_str()).or_default();
        e.0 += 1;
        e.1 += n.props.extra.len();
        e.2 += n.props.extra.heap_bytes();
    }
    for (kind, (objects, entries, bytes)) in per_kind {
        eprintln!(
            "goad {kind}: {objects} objects, {entries} kept properties, {} heap bytes per object",
            bytes / objects.max(1)
        );
    }
}

#[test]
fn cypher_matches_bhe_goldens() {
    let golden_files = goldens();
    if golden_files.is_empty() {
        return skip(&format!(
            "no goldens in {} yet (capture them from a pinned BHE, see tests/parity/README.md)",
            parity_dir().join("golden").display()
        ));
    }
    if !Path::new(&goad_dir()).exists() {
        return skip(&format!(
            "{} not present (the GOAD capture is git-ignored)",
            goad_dir().display()
        ));
    }

    let graph = load_goad();
    let view = AdGraphView::new(&graph);

    let mut failures = Vec::new();
    for path in &golden_files {
        let text = std::fs::read_to_string(path).expect("reading golden file");
        let golden: Golden = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parsing golden {}: {e}", path.display()));

        let result = run(&view, &golden.query);
        let (got_nodes, got_rels) = normalise(&result);
        let want_nodes: BTreeSet<String> = golden.nodes.iter().cloned().collect();
        let want_rels: BTreeSet<(String, String, String)> =
            golden.relationships.iter().cloned().collect();

        if got_nodes != want_nodes {
            failures.push(format!(
                "[{}] node id-set differs: {} only in Pathwarden, {} only in BHE golden",
                golden.id,
                got_nodes.difference(&want_nodes).count(),
                want_nodes.difference(&got_nodes).count(),
            ));
        }
        if got_rels != want_rels {
            failures.push(format!(
                "[{}] relationship set differs: {} only in Pathwarden, {} only in BHE golden",
                golden.id,
                got_rels.difference(&want_rels).count(),
                want_rels.difference(&got_rels).count(),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "cypher parity mismatches:\n{}",
        failures.join("\n")
    );
}
