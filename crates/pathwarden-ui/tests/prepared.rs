//! Prepared queries: the pinned BloodHound Query Library's queries
//! that Pathwarden offers run, and answer the same in the app (a saved run)
//! and the CLI (`pathwarden query -i`, every collector property kept).
//!
//! - Every offered query runs without error on the demo and a small fixture,
//!   and both ways of loading give the same rows.
//! - `queries/unsupported.toml` is what this build finds from each query's
//!   text alone: each query left out is still refused, or still reads a
//!   field saved runs don't keep, and nothing else is left out. With `PATHWARDEN_WRITE_PREPARED=1` the test
//!   rewrites the file instead of failing.
//! - Every offered query reads only fields saved runs keep.
//! - `queries/findings.toml` names real queries and real rules.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use pathwarden_core::analyze;
use pathwarden_core::config::Config;
use pathwarden_core::cypher::{self, AdGraphView, Cell, EvalLimits, QueryResult};
use pathwarden_core::graph::AdGraph;
use pathwarden_core::prepared::{self, Unsupported};

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_as(input: &str, all_properties: bool) -> AdGraph {
    let opts = pathwarden_core::LoadOptions {
        all_properties,
        ..analyze::load_options(&Config::default(), &[])
    };
    pathwarden_core::load(&[repo(input)], &opts).unwrap().0
}

/// The rows, in an order that doesn't depend on how the graph lists edges.
fn rows(r: &QueryResult) -> Vec<String> {
    let mut v: Vec<String> = r
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|c| match c {
                    Cell::Path {
                        nodes,
                        relationships,
                        ..
                    } => format!("{nodes:?} {relationships:?}"),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect();
    v.sort();
    v
}

const DEMO: &str = "demo/20261001020000_PathwardenDemo.zip";
const FIXTURE: &str = "testdata/adcs";

/// One input as the CLI (`-i`, every collector property) and the app (a
/// saved run: its explore graph, object index and kept fields) read it.
struct Data {
    full: AdGraph,
    index: AdGraph,
    x: pathwarden_core::explore::ExploreGraph,
    props: cypher::RunProps,
}

fn data(input: &'static str) -> &'static Data {
    static DEMO_DATA: OnceLock<Data> = OnceLock::new();
    static FIXTURE_DATA: OnceLock<Data> = OnceLock::new();
    let cell = if input == DEMO {
        &DEMO_DATA
    } else {
        &FIXTURE_DATA
    };
    cell.get_or_init(|| {
        let g = load_as(input, false);
        let props = cypher::RunProps::from_graph(&g);
        Data {
            full: load_as(input, true),
            x: pathwarden_core::explore::build(&g, &[], &[]).unwrap(),
            index: pathwarden_core::object_index::ObjectIndex::from_graph(&g).into_graph(),
            // As a saved run's file gives them back.
            props: serde_json::from_str(&serde_json::to_string(&props).unwrap()).unwrap(),
        }
    })
}

/// Runs every offered query on `input` as the CLI (`-i`) and the app (a
/// saved run) do; returns how many came back with rows.
fn run_all(input: &'static str) -> usize {
    let d = data(input);
    let cli = AdGraphView::new(&d.full);
    let app = cypher::RunView::new(&d.index, &d.x, Ok(&d.props));
    // The app's row cap, and room to finish in a debug build.
    let limits = EvalLimits {
        max_rows: pathwarden_ui::explore_ui::QUERY_ROWS,
        timeout: std::time::Duration::from_secs(300),
        ..EvalLimits::default()
    };
    let mut answered = 0;
    let mut differ = Vec::new();
    for q in prepared::library().offered() {
        let a = cypher::run(&cli, &q.query, &limits)
            .unwrap_or_else(|e| panic!("{input}: {} ({}) fails in the CLI: {e}", q.name, q.guid));
        let b = cypher::run(&app, &q.query, &limits)
            .unwrap_or_else(|e| panic!("{input}: {} ({}) fails in the app: {e}", q.name, q.guid));
        assert!(
            !a.timed_out && !b.timed_out,
            "{input}: {} timed out",
            q.name
        );
        // A row cap cuts the two answers at different rows; the counts agree.
        let same = if a.truncated || b.truncated {
            a.rows.len() == b.rows.len()
        } else {
            rows(&a) == rows(&b)
        };
        if !same {
            differ.push(format!(
                "{} ({}): {} rows in the CLI, {} in the app",
                q.name,
                q.guid,
                a.rows.len(),
                b.rows.len()
            ));
        }
        if !a.rows.is_empty() {
            answered += 1;
        }
    }
    assert!(
        differ.is_empty(),
        "{input}: answers differ:\n{}",
        differ.join("\n")
    );
    answered
}

#[test]
fn offered_queries_run_and_answer_alike_on_the_demo() {
    let n = run_all(DEMO);
    assert!(n >= 10, "only {n} offered queries return rows on the demo");
}

#[test]
fn offered_queries_run_and_answer_alike_on_a_small_fixture() {
    run_all(FIXTURE);
}

#[test]
fn the_unsupported_list_is_current() {
    let lib = prepared::library();
    let found: Vec<(&str, &str, Option<Unsupported>)> = lib
        .all
        .iter()
        .map(|q| (q.guid.as_str(), q.name.as_str(), prepared::check(&q.query)))
        .collect();
    let shipped = prepared::shipped_unsupported();
    let mut stale = Vec::new();
    for (guid, name, now) in &found {
        if shipped.get(*guid) != now.as_ref() {
            stale.push(format!(
                "{name} ({guid}): listed {:?}, finds {:?}",
                shipped.get(*guid),
                now
            ));
        }
    }
    let known: BTreeSet<&str> = found.iter().map(|f| f.0).collect();
    for guid in shipped.keys() {
        if !known.contains(guid.as_str()) {
            stale.push(format!("{guid}: listed, but not in the library"));
        }
    }
    if stale.is_empty() {
        return;
    }
    let toml = prepared::unsupported_toml(&found);
    if std::env::var_os("PATHWARDEN_WRITE_PREPARED").is_some() {
        let path = repo("crates/pathwarden-core/queries/unsupported.toml");
        std::fs::write(&path, toml).unwrap();
        eprintln!("wrote {}", path.display());
        return;
    }
    panic!(
        "queries/unsupported.toml is out of date:\n{}\n\nRun with PATHWARDEN_WRITE_PREPARED=1 to rewrite it, or write:\n{toml}",
        stale.join("\n")
    );
}

#[test]
fn offered_queries_read_only_kept_fields() {
    for q in prepared::library().offered() {
        let shape = cypher::shape(&q.query).unwrap();
        for key in &shape.properties {
            assert!(prepared::kept(key), "{} reads {key}", q.name);
        }
        assert_eq!(q.returns == "paths", shape.returns_paths, "{}", q.name);
    }
}

#[test]
fn findings_and_names_are_sound() {
    let lib = prepared::library();
    for (guid, rule) in prepared::shipped_findings() {
        let q = lib
            .by_guid(&guid)
            .unwrap_or_else(|| panic!("findings.toml: {guid} is not in the library"));
        let o = q.finding.as_ref().unwrap();
        assert_eq!(&o.rule, &rule);
        assert!(!o.title.is_empty(), "findings.toml: {rule} is not a rule");
    }
    let mut guids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for q in &lib.all {
        assert!(guids.insert(q.guid.to_ascii_lowercase()), "{}", q.guid);
        assert!(
            names.insert(q.name.to_lowercase()),
            "two queries named {}",
            q.name
        );
    }
    // Every offered query is found by its name, its GUID and a GUID prefix.
    for q in lib.offered() {
        for key in [
            q.name.to_uppercase(),
            q.guid.clone(),
            q.guid[..8].to_string(),
        ] {
            match lib.find(&key) {
                Ok(f) => assert_eq!(f.guid, q.guid, "{key}"),
                Err(_) => panic!("{key} finds no one query"),
            }
        }
    }
    // The library's placeholders: they open in the editor, never run.
    let edit: Vec<&str> = lib
        .all
        .iter()
        .filter(|q| q.edit_first)
        .map(|q| &q.guid[..8])
        .collect();
    assert_eq!(edit.len(), 4, "{edit:?}");
}
