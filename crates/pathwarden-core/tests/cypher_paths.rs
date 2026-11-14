//! Cypher path queries give the paths `pathwarden path` gives.
//!
//! A corpus of BloodHound CE path queries (most of them as BloodHound's
//! query library writes them) runs over the synthetic demo and test data.
//! Every `shortestPath` row must be the path the analysis finds between its
//! two ends (`analysis::shortest_path`, which `pathwarden path --from s --to
//! t` prints), and, where no LIMIT cut the answer, every pair of ends with
//! such a path must have a row. An attack path ends at the first Tier Zero
//! object it meets, as the analysis's paths do, so no path runs on from one.
//!
//! The query side loads as `pathwarden query` does (every property kept),
//! the analysis side as `pathwarden path` does; the two are compared by
//! object ID.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use pathwarden_core::analysis;
use pathwarden_core::analyze;
use pathwarden_core::config::Config;
use pathwarden_core::cypher::{self, AdGraphView, Cell, EvalLimits, QueryResult};
use pathwarden_core::graph::AdGraph;
use pathwarden_core::model::EdgeKind;
use pathwarden_core::{load, NodeIndex};
use petgraph::visit::EdgeRef;

type Hop = (String, String, String);

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// The data loaded as `pathwarden query` (`.0`) and `pathwarden path`
/// (`.1`) load it.
struct Data {
    query: AdGraph,
    path: AdGraph,
}

fn load_as(inputs: &[PathBuf], all_properties: bool) -> AdGraph {
    let opts = pathwarden_core::LoadOptions {
        all_properties,
        ..analyze::load_options(&Config::default(), &[])
    };
    load(inputs, &opts).unwrap().0
}

fn data(inputs: &[&str]) -> Data {
    let inputs: Vec<PathBuf> = inputs.iter().map(|i| repo(i)).collect();
    Data {
        query: load_as(&inputs, true),
        path: load_as(&inputs, false),
    }
}

fn demo() -> &'static Data {
    static D: OnceLock<Data> = OnceLock::new();
    D.get_or_init(|| data(&["demo/20261001020000_PathwardenDemo.zip"]))
}

/// Runs a query with room to finish in a debug build on a loaded machine:
/// a row or time cap would make a check pass on part of the answer.
fn run(view: &dyn cypher::GraphView, q: &str) -> QueryResult {
    let limits = EvalLimits {
        timeout: std::time::Duration::from_secs(300),
        ..EvalLimits::default()
    };
    let r = cypher::run(view, q, &limits).unwrap_or_else(|e| panic!("{q}: {e}"));
    assert!(!r.truncated, "{q}: {:?}", r.stopped);
    r
}

/// A returned path: its two ends and hops, turned to run with its
/// relationships (`(t)<-[]-(s)` reads from t).
fn forward(cell: &Cell) -> (String, String, Vec<Hop>) {
    let Cell::Path {
        nodes,
        relationships,
        ..
    } = cell
    else {
        panic!("not a path: {cell:?}")
    };
    let mut nodes = nodes.clone();
    let mut hops: Vec<Hop> = relationships
        .iter()
        .map(|h| (h.src.clone(), h.kind.clone(), h.tgt.clone()))
        .collect();
    if hops.first().is_some_and(|h| h.0 != nodes[0]) {
        nodes.reverse();
        hops.reverse();
    }
    for (i, h) in hops.iter().enumerate() {
        assert_eq!(
            (&h.0, &h.2),
            (&nodes[i], &nodes[i + 1]),
            "a path that runs with its edges"
        );
    }
    (nodes[0].clone(), nodes[nodes.len() - 1].clone(), hops)
}

/// The analysis's shortest path from each node to `to` (by object ID),
/// one search for all of them, as `shortest_path` runs it, without passing
/// through a Tier Zero object.
struct Toward {
    g: &'static AdGraph,
    tree: analysis::ReachTree,
}

impl Toward {
    fn new(g: &'static AdGraph, to: &str) -> Self {
        let t = g.lookup(to).unwrap();
        Toward {
            g,
            tree: analysis::search(
                g,
                [t],
                &[petgraph::Direction::Incoming],
                |e| g.traversable(*e.weight(), e.target()),
                |_| true,
                |ix| !g.node(ix).tier_zero,
                None,
                |_| false,
            ),
        }
    }

    fn hops(&self, from: &str) -> Option<Vec<Hop>> {
        let s = self.g.lookup(from).unwrap();
        let edges = self.tree.path(s)?;
        Some(edges.iter().map(|&e| hop(self.g, e)).collect())
    }
}

fn hop(g: &AdGraph, e: petgraph::graph::EdgeIndex) -> Hop {
    let (a, b) = g.inner().edge_endpoints(e).unwrap();
    (
        g.node(a).id.clone(),
        g.inner()[e].as_str().to_string(),
        g.node(b).id.clone(),
    )
}

/// Checks every row of a `shortestPath` result against the analysis, and
/// returns the (source, target) pairs it found.
fn check_rows(d: &'static Data, r: &QueryResult) -> BTreeSet<(String, String)> {
    let mut by_target: BTreeMap<String, Toward> = BTreeMap::new();
    let mut pairs = BTreeSet::new();
    for cell in r.paths() {
        let (s, t, hops) = forward(cell);
        let toward = by_target
            .entry(t.clone())
            .or_insert_with(|| Toward::new(&d.path, &t));
        assert_eq!(
            Some(&hops),
            toward.hops(&s).as_ref(),
            "the query's path from {s} to {t} is not pathwarden path's"
        );
        assert!(pairs.insert((s, t)), "one row per pair of ends");
    }
    pairs
}

/// The pairs the analysis joins: each source to each target it has a
/// path to (itself excluded).
fn analysis_pairs(
    d: &'static Data,
    sources: &BTreeSet<String>,
    targets: &BTreeSet<String>,
) -> BTreeSet<(String, String)> {
    let mut want = BTreeSet::new();
    for t in targets {
        let toward = Toward::new(&d.path, t);
        for s in sources {
            if s != t && toward.hops(s).is_some() {
                want.insert((s.clone(), t.clone()));
            }
        }
    }
    want
}

/// The objects a node query returns.
fn ids(view: &AdGraphView, q: &str) -> BTreeSet<String> {
    run(view, q).node_ids()
}

#[test]
fn domain_users_to_tier_zero() {
    // As BloodHound's query library writes it.
    let q = "MATCH p=shortestPath((s:Group)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero))\n\
             WHERE s.objectid ENDS WITH '-513' AND s<>t\nRETURN p\nLIMIT 1000";
    let mut found = 0;
    for input in [
        "demo/20261001020000_PathwardenDemo.zip",
        "testdata/broad",
        "testdata/adcs",
    ] {
        let d: &'static Data = Box::leak(Box::new(data(&[input])));
        let view = AdGraphView::new(&d.query);
        let r = run(&view, q);
        assert!(!r.truncated && r.rows.len() < 1000, "{input}");
        let got = check_rows(d, &r);
        let sources = ids(
            &view,
            "MATCH (s:Group) WHERE s.objectid ENDS WITH '-513' RETURN s",
        );
        let targets = ids(&view, "MATCH (t:Tag_Tier_Zero) RETURN t");
        assert_eq!(got, analysis_pairs(d, &sources, &targets), "{input}");
        found += got.len();
    }
    assert!(found > 0, "some data has a path from Domain Users");
}

#[test]
fn kerberoastable_users_to_domain_admins() {
    let d = demo();
    let view = AdGraphView::new(&d.query);
    let filter = "s.hasspn=true\n\
                  AND s.enabled = true\n\
                  AND NOT s.objectid ENDS WITH '-502'\n\
                  AND NOT COALESCE(s.gmsa, false) = true\n\
                  AND NOT COALESCE(s.msa, false) = true";
    let q = format!(
        "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Group))\n\
         WHERE {filter}\nAND t.objectid ENDS WITH '-512'\nRETURN p\nLIMIT 1000"
    );
    let r = run(&view, &q);
    let got = check_rows(d, &r);
    let sources = ids(&view, &format!("MATCH (s:User) WHERE {filter} RETURN s"));
    let targets = ids(
        &view,
        "MATCH (t:Group) WHERE t.objectid ENDS WITH '-512' RETURN t",
    );
    assert!(!sources.is_empty());
    assert_eq!(got, analysis_pairs(d, &sources, &targets));
    assert!(
        !got.is_empty(),
        "a Kerberoastable account reaches Domain Admins"
    );
}

/// Two users with a path to Tier Zero and one without, marked owned.
fn owned(d: &Data) -> Vec<NodeIndex> {
    let g = &d.query;
    let users = g
        .nodes()
        .filter(|(_, n)| n.kind.as_str() == "User" && !n.tier_zero && !n.placeholder)
        .map(|(ix, _)| ix);
    let (mut with, mut without) = (Vec::new(), Vec::new());
    for ix in users {
        match analysis::path_to_tier_zero(g, ix) {
            Some(_) if with.len() < 2 => with.push(ix),
            None if without.is_empty() => without.push(ix),
            _ => {}
        }
        if with.len() == 2 && !without.is_empty() {
            break;
        }
    }
    with.into_iter().chain(without).collect()
}

#[test]
fn shortest_paths_from_owned_objects() {
    let d = demo();
    let owned = owned(d);
    assert_eq!(owned.len(), 3);
    let view = AdGraphView::new(&d.query).with_owned(owned.iter().copied());
    let q = "// MANY TO MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE\n\
             MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero))\n\
             WHERE s<>t\nRETURN p\nLIMIT 1000";
    let r = run(&view, q);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let got = check_rows(d, &r);
    let sources: BTreeSet<String> = owned
        .iter()
        .map(|&ix| d.query.node(ix).id.clone())
        .collect();
    let targets = ids(&view, "MATCH (t:Tag_Tier_Zero) RETURN t");
    assert_eq!(got, analysis_pairs(d, &sources, &targets));
    // `pathwarden path --from s`: the nearest Tier Zero object is the
    // shortest of s's rows.
    for &s in &owned {
        let id = &d.query.node(s).id;
        let nearest = analysis::path_to_tier_zero(&d.path, d.path.lookup(id).unwrap());
        let shortest = r
            .paths()
            .map(forward)
            .filter(|(from, _, _)| from == id)
            .map(|(_, _, hops)| hops.len())
            .min();
        assert_eq!(nearest.map(|p| p.steps.len()), shortest, "{id}");
    }
    // Every object, not only Tier Zero, as the library's other owned query.
    let r = run(
        &view,
        "MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base))\n\
         WHERE (s:Tag_Owned)\nAND s<>t\nRETURN p\nLIMIT 1000",
    );
    assert_eq!(r.rows.len(), 1000, "LIMIT stops it");
    check_rows(d, &r);
    // allShortestPaths: each one as short as the analysis's, the analysis's
    // among them.
    let r = run(
        &view,
        "MATCH p=allShortestPaths((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p",
    );
    let mut per_pair: BTreeMap<(String, String), Vec<Vec<Hop>>> = BTreeMap::new();
    for cell in r.paths() {
        let (s, t, hops) = forward(cell);
        per_pair.entry((s, t)).or_default().push(hops);
    }
    assert_eq!(
        per_pair.keys().cloned().collect::<BTreeSet<_>>(),
        analysis_pairs(d, &sources, &targets)
    );
    for ((s, t), all) in &per_pair {
        let want = Toward::new(&d.path, t).hops(s).unwrap();
        assert!(all.iter().all(|h| h.len() == want.len()), "{s} -> {t}");
        assert!(all.contains(&want), "{s} -> {t}");
        let distinct: BTreeSet<_> = all.iter().collect();
        assert_eq!(distinct.len(), all.len(), "each shortest path once");
    }
    // Nothing marked: the note says why nothing matched.
    let r = run(&AdGraphView::new(&d.query), q);
    assert!(r.rows.is_empty());
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
}

#[test]
fn paths_to_a_named_group() {
    let d = demo();
    let view = AdGraphView::new(&d.query);
    let da_name = "DOMAIN ADMINS@SCALE.LOCAL";
    let da = d.query.find_principal(da_name);
    assert_eq!(da.len(), 1);
    let da_id = d.query.node(da[0]).id.clone();

    // Every user's shortest path to the group, by name.
    let r = run(
        &view,
        &format!(
            "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(g:Group {{name: '{da_name}'}})) WHERE s<>g RETURN p"
        ),
    );
    assert!(!r.truncated);
    let got = check_rows(d, &r);
    let users = ids(&view, "MATCH (s:User) RETURN s");
    assert_eq!(
        got,
        analysis_pairs(d, &users, &BTreeSet::from([da_id.clone()]))
    );
    // Paths stop at Tier Zero: only users with a path that meets no other
    // Tier Zero object first.
    assert!(got.len() > 20, "{}", got.len());

    // The library's form, read from the group.
    let r = run(
        &view,
        "MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base))\n\
         WHERE t.objectid ENDS WITH '-512' AND s<>t\nRETURN p\nLIMIT 1000",
    );
    // Fewer than the LIMIT: the paths meet no other Tier Zero object.
    assert_eq!(r.rows.len(), 45);
    for cell in r.paths() {
        let Cell::Path { nodes, .. } = cell else {
            unreachable!()
        };
        assert_eq!(nodes[0], da_id, "the path reads from the group");
    }
    check_rows(d, &r);

    // Membership, nested: every MemberOf chain into the group.
    let r = run(
        &view,
        &format!("MATCH p=(n:Base)-[:MemberOf*1..]->(g:Group) WHERE g.name = '{da_name}' RETURN p"),
    );
    assert!(!r.truncated && r.hop_cap.is_none());
    let mut starts = BTreeSet::new();
    for cell in r.paths() {
        let (s, t, hops) = forward(cell);
        assert_eq!(t, da_id);
        assert!(hops.iter().all(|h| h.1 == "MemberOf"));
        starts.insert(s);
    }
    // ... from each object that is a member, directly or not.
    let g = &d.path;
    let tree = analysis::search(
        g,
        [g.lookup(&da_id).unwrap()],
        &[petgraph::Direction::Incoming],
        |e| *e.weight() == EdgeKind::MemberOf,
        |_| true,
        |_| true,
        None,
        |_| false,
    );
    let members: BTreeSet<String> = g
        .nodes()
        .filter(|(ix, n)| tree.depth(*ix).is_some_and(|d| d > 0) && !n.kind.is_external())
        .map(|(_, n)| n.id.clone())
        .collect();
    assert_eq!(starts, members);
}

#[test]
fn shortest_paths_to_tier_zero_and_unconstrained_delegation() {
    let d = demo();
    let view = AdGraphView::new(&d.query);
    for q in [
        "MATCH p=shortestPath((s)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero))\nWHERE s<>t\nRETURN p\nLIMIT 1000",
        "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Base))\nWHERE s<>t\nAND NOT (s:Tag_Tier_Zero)\nAND (t:Tag_Tier_Zero)\nRETURN p\nLIMIT 1000",
        "MATCH p=shortestPath((s)-[:AD_ATTACK_PATHS*1..]->(t:Computer))\nWHERE t.unconstraineddelegation = true AND s<>t\nRETURN p\nLIMIT 1000",
    ] {
        let r = run(&view, q);
        // Paths stop at Tier Zero, so to computers that are not Tier Zero
        // there are fewer than the LIMIT.
        let want = if q.contains("unconstraineddelegation") { 70 } else { 1000 };
        assert_eq!(r.rows.len(), want, "{q}");
        check_rows(d, &r);
    }
}

/// OpenGraph edges the mapping packs make traversable are attack edges:
/// TaskHound's stored task credential is on the path.
#[test]
fn opengraph_path_kinds_are_attack_edges() {
    let d: &'static Data = Box::leak(Box::new(data(&[
        "testdata/opengraph/ad",
        "testdata/opengraph/taskhound",
    ])));
    let view = AdGraphView::new(&d.query);
    let r = run(
        &view,
        "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p",
    );
    let got = check_rows(d, &r);
    let users = ids(&view, "MATCH (s:User) RETURN s");
    let targets = ids(&view, "MATCH (t:Tag_Tier_Zero) RETURN t");
    assert_eq!(got, analysis_pairs(d, &users, &targets));
    let kinds: BTreeSet<String> = r.paths().flat_map(|c| forward(c).2).map(|h| h.1).collect();
    assert!(kinds.contains("TH_HasTaskWithStoredCreds"), "{kinds:?}");
    assert!(kinds.contains("TH_RunsAs"), "{kinds:?}");
    // A context-only kind is no attack edge, but a query can name it.
    let named = run(&view, "MATCH p=(c:Computer)-[:TH_HasTask]->(t) RETURN p");
    assert!(!named.rows.is_empty());
    let attack = run(
        &view,
        "MATCH p=(c:Computer)-[:AD_ATTACK_PATHS]->(t:TH_ScheduledTask) RETURN p",
    );
    let attack_kinds: BTreeSet<String> = attack
        .paths()
        .flat_map(|c| forward(c).2)
        .map(|h| h.1)
        .collect();
    assert!(!attack_kinds.contains("TH_HasTask"), "{attack_kinds:?}");
}

/// Expansion on a big graph is bounded: an unbounded `*` stops at the hop
/// cap, rows at the row cap, and the result says which.
#[test]
fn expansion_is_bounded_and_says_so() {
    let d = demo();
    let view = AdGraphView::new(&d.query);
    let limits = EvalLimits {
        max_rows: 5_000,
        ..EvalLimits::default()
    };
    let r = cypher::run(
        &view,
        "MATCH p=(s:User)-[:AD_ATTACK_PATHS*]->(t) RETURN p",
        &limits,
    )
    .unwrap();
    assert!(r.truncated && !r.timed_out, "5,000 rows is not all of them");
    assert_eq!(r.rows.len(), 5_000);
    assert_eq!(
        r.stopped[0],
        "Stopped at the 5,000-row cap: there are more rows."
    );
    for cell in r.paths() {
        let Cell::Path { relationships, .. } = cell else {
            unreachable!()
        };
        assert!(relationships.len() <= cypher::DEFAULT_MAX_HOPS as usize);
    }
    // Attack paths into Tier Zero run longer than 10 relationships: the hop
    // cap cuts them, and says so.
    let r = run(
        &view,
        "MATCH p=(s:User)-[:AD_ATTACK_PATHS*]->(t:Tag_Tier_Zero) RETURN p LIMIT 1000",
    );
    assert_eq!(r.hop_cap, Some(cypher::DEFAULT_MAX_HOPS));
    assert!(
        r.stopped.contains(
            &"Paths longer than 10 relationships were not followed: a variable-length relationship without an upper bound stops there."
                .to_string()
        ),
        "{:?}",
        r.stopped
    );
}

/// A saved run (its explore graph, object index and kept fields) answers
/// as the analysis's graph does, row for row: the app's Query tab and
/// `pathwarden query --run` give the paths `pathwarden path` gives.
#[test]
fn a_saved_run_answers_as_the_full_graph() {
    let d = demo();
    let g = &d.path;
    let x = pathwarden_core::explore::build(g, &[], &[]).unwrap();
    let index = pathwarden_core::object_index::ObjectIndex::from_graph(g).into_graph();
    let props = cypher::RunProps::from_graph(g);
    // The fields survive the file.
    let props: cypher::RunProps =
        serde_json::from_str(&serde_json::to_string(&props).unwrap()).unwrap();
    let marked: Vec<String> = owned(d)
        .iter()
        .map(|&ix| d.query.node(ix).id.clone())
        .collect();
    let full = AdGraphView::new(g).with_owned(marked.iter().map(|id| g.lookup(id).unwrap()));
    let saved = cypher::RunView::new(&index, &x, Ok(&props)).with_owned(&marked);
    // Sorted: a run lists the edges out of an object by target, the
    // analysis's graph as they were added, so allShortestPaths and
    // variable-length rows come in another order (the same rows; the
    // edges into an object, which shortestPath follows, keep the order).
    let rows = |r: &QueryResult| -> Vec<String> {
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
    };
    for q in [
        "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Group)) WHERE s.hasspn = true AND s.enabled = true AND t.objectid ENDS WITH '-512' RETURN p",
        "MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p",
        "MATCH p=allShortestPaths((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p",
        "MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base)) WHERE t.objectid ENDS WITH '-512' AND s<>t RETURN p LIMIT 500",
        "MATCH p=(n:Base)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN p",
        "MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true RETURN n",
        "MATCH (n:Base) WHERE n.admincount = true AND n.name STARTS WITH 'DA-' RETURN n",
    ] {
        let a = run(&full, q);
        let b = run(&saved, q);
        assert!(!a.rows.is_empty(), "{q}");
        assert_eq!(rows(&a), rows(&b), "{q}");
        assert_eq!(a.relationships, b.relationships, "{q}");
        // Drawn hop by hop the same way.
        let steps = |view: &dyn cypher::GraphView, r: &QueryResult| -> Vec<String> {
            let mut v: Vec<String> = r
                .paths()
                .filter_map(|c| cypher::attack_path(view, c))
                .map(|p| serde_json::to_string(&p.steps).unwrap())
                .collect();
            v.sort();
            v
        };
        assert_eq!(steps(&full, &a), steps(&saved, &b), "{q}");
    }
    // No fields: they read as null, and a note says why (never kept, or a
    // newer Pathwarden's).
    let limits = EvalLimits::default();
    let newer = cypher::RunProps {
        version: cypher::PROPS_VERSION + 1,
        ..props.clone()
    };
    for (kept, why) in [
        (Err(cypher::NoProps::Absent), cypher::NoProps::Absent),
        (Err(cypher::NoProps::Newer), cypher::NoProps::Newer),
        (Ok(&newer), cypher::NoProps::Newer),
    ] {
        let bare = cypher::RunView::new(&index, &x, kept);
        let r = cypher::run(
            &bare,
            "MATCH (n:User) WHERE n.hasspn = true RETURN n",
            &limits,
        )
        .unwrap();
        assert!(r.rows.is_empty());
        assert_eq!(r.warnings, vec![why.note().to_string()]);
    }
}
