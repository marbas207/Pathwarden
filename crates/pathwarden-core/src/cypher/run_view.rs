//! Cypher over a saved run: what the app's Explore page and
//! `pathwarden query --run/--env` query, from the files a run keeps.
//!
//! A run keeps its whole graph for exploring ([`ExploreGraph`]: every
//! object's kind and flags, every relationship, which kinds attack paths
//! follow), its objects' names and IDs ([`crate::object_index`]), and since
//! Cypher path queries the analysis fields of each object ([`RunProps`]). Together they
//! answer the same queries as the full graph, with two differences:
//!
//! - properties are Pathwarden's analysis fields (the list in
//!   [`PROP_KEYS`], normalised as the analysis reads them), not every
//!   property the collector wrote, which only `pathwarden query -i` keeps;
//! - a run saved before Cypher path queries has no properties: they read as null, and a
//!   note says so.
//!
//! The incoming lists of the run's graph keep the order of the analysis's
//! own graph, so [`RunView::shortest_tree`] finds the tree
//! [`crate::analysis::search`] finds, and `shortestPath` over
//! `AD_ATTACK_PATHS` the path `pathwarden path` prints.

use std::collections::{BTreeMap, VecDeque};

use petgraph::graph::EdgeIndex;
use serde::{Deserialize, Serialize};

use super::ast::Direction;
use super::value::Value;
use super::view::{self, EdgeId, GraphView, NodeRef, TypeSel, HIDDEN, TAG_OWNED};
use crate::analysis::ReachTree;
use crate::explore::{Edge, ExploreGraph};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::NodeIndex;

/// The properties a run keeps for queries: the analysis's fields.
pub const PROP_KEYS: &[&str] = &[
    "name",
    "domain",
    "domainsid",
    "distinguishedname",
    "description",
    "operatingsystem",
    "logonscript",
    "enabled",
    "hasspn",
    "dontreqpreauth",
    "admincount",
    "unconstraineddelegation",
    "trustedtoauth",
    "sensitive",
    "pwdneverexpires",
    "passwordnotreqd",
    "haslaps",
    "isdc",
    "pwdlastset",
    "lastlogontimestamp",
    "whencreated",
    "serviceprincipalnames",
];

/// The version of [`RunProps`] this build writes and reads.
pub const PROPS_VERSION: u32 = 1;

/// One kept value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropCell {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<String>),
}

/// A run's objects' analysis fields, by property: `[object, value]` pairs
/// in object order, only where the object has a value. Saved with each run
/// (`props.json.gz`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunProps {
    pub version: u32,
    pub columns: BTreeMap<String, Vec<(u32, PropCell)>>,
}

impl RunProps {
    /// The fields of every object of `g`, the analysis's graph.
    pub fn from_graph(g: &AdGraph) -> Self {
        let mut columns: BTreeMap<String, Vec<(u32, PropCell)>> = BTreeMap::new();
        for (ix, node) in g.nodes() {
            for key in PROP_KEYS {
                let cell = match view::typed_prop(node, key) {
                    Some(Value::Bool(b)) => PropCell::Bool(b),
                    Some(Value::Int(i)) => PropCell::Int(i),
                    Some(Value::Str(s)) => PropCell::Str(s),
                    Some(Value::List(l)) => PropCell::List(
                        l.into_iter()
                            .filter_map(|v| match v {
                                Value::Str(s) => Some(s),
                                _ => None,
                            })
                            .collect(),
                    ),
                    _ => continue,
                };
                columns
                    .entry((*key).to_string())
                    .or_default()
                    .push((ix.index() as u32, cell));
            }
        }
        RunProps {
            version: PROPS_VERSION,
            columns,
        }
    }

    /// `key` of object `n`, null when it has none.
    pub fn get(&self, n: NodeRef, key: &str) -> Value {
        let Some(col) = self.columns.get(key) else {
            return Value::Null;
        };
        match col.binary_search_by_key(&n, |(i, _)| *i) {
            Ok(i) => match &col[i].1 {
                PropCell::Bool(b) => Value::Bool(*b),
                PropCell::Int(v) => Value::Int(*v),
                PropCell::Str(s) => Value::Str(s.clone()),
                PropCell::List(l) => Value::List(l.iter().cloned().map(Value::Str).collect()),
            },
            Err(_) => Value::Null,
        }
    }

    /// Whether this build reads it as written (a newer one's is not).
    pub fn is_known(&self) -> bool {
        self.version <= PROPS_VERSION
    }
}

/// Why a saved run's properties aren't there: queries read them as null,
/// and a note says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoProps {
    /// Saved before runs kept them.
    Absent,
    /// Saved by a newer Pathwarden.
    Newer,
    /// Damaged.
    Unreadable,
}

impl NoProps {
    /// What a query on the run says.
    pub fn note(self) -> &'static str {
        match self {
            NoProps::Absent => "This run was saved without its objects' properties, so they read as null. Analyze its data again to query them.",
            NoProps::Newer => "This run's properties were saved by a newer Pathwarden, so they read as null. Update Pathwarden to query them.",
            NoProps::Unreadable => "This run's properties can't be read, so they read as null. Analyze its data again to query them.",
        }
    }
}

/// A [`GraphView`] over a saved run: its explore graph `x`, its object
/// index's graph `g` (names and IDs, the same indexes as `x`), and its kept
/// properties when it has them.
pub struct RunView<'a> {
    g: &'a AdGraph,
    x: &'a ExploreGraph,
    props: Result<&'a RunProps, NoProps>,
    owned: Vec<NodeRef>,
}

impl<'a> RunView<'a> {
    /// `g` and `x` must be the same run's (the same objects, in the same
    /// order), as the Explore page checks when it loads them.
    pub fn new(g: &'a AdGraph, x: &'a ExploreGraph, props: Result<&'a RunProps, NoProps>) -> Self {
        RunView {
            g,
            x,
            props: props.and_then(|p| {
                if p.is_known() {
                    Ok(p)
                } else {
                    Err(NoProps::Newer)
                }
            }),
            owned: Vec::new(),
        }
    }

    /// Marks the objects with these IDs as owned (those not in the run are
    /// left out).
    pub fn with_owned(mut self, ids: &[String]) -> Self {
        self.owned = crate::owned::in_graph(self.g, ids)
            .into_iter()
            .map(|ix| ix.index() as NodeRef)
            .collect();
        self.owned.sort_unstable();
        self.owned.dedup();
        self
    }

    /// How many objects of the run are marked as owned.
    pub fn owned_count(&self) -> usize {
        self.owned.len()
    }

    fn is_owned(&self, n: NodeRef) -> bool {
        self.owned.binary_search(&n).is_ok()
    }

    fn selects(&self, sel: &TypeSel, kind: EdgeKind, to: u32) -> bool {
        if sel.kinds.contains(&kind) {
            return true;
        }
        if !(sel.attack || sel.azure_attack) || !self.x.traversable(kind, to) {
            return false;
        }
        sel.attack
            || self.x.edge_kind_info(kind).and_then(|i| i.pack.as_deref())
                == Some(crate::entra::PACK)
    }

    fn edge(&self, e: EdgeId) -> Edge {
        self.x.edge_at(e).expect("an edge of this run")
    }
}

impl GraphView for RunView<'_> {
    fn node_handles(&self) -> Vec<NodeRef> {
        (0..self.x.node_count() as NodeRef).collect()
    }

    fn objectid(&self, n: NodeRef) -> String {
        self.g.node(NodeIndex::new(n as usize)).id.clone()
    }

    fn matches_label(&self, n: NodeRef, label: &str) -> bool {
        match label {
            "Tag_Tier_Zero" => self.g.node(NodeIndex::new(n as usize)).tier_zero,
            TAG_OWNED => self.is_owned(n),
            "Base" => !self.x.kind(n).is_external(),
            other => self.x.kind(n).as_str() == other,
        }
    }

    fn prop(&self, n: NodeRef, key: &str) -> Value {
        let node = self.g.node(NodeIndex::new(n as usize));
        if let Some(v) = view::virtual_prop(node, key, self.is_owned(n)) {
            return v;
        }
        let v = match self.props {
            Ok(p) => p.get(n, key),
            Err(_) => Value::Null,
        };
        if view::is_secret_prop(key) && !v.is_null() {
            return Value::Str(HIDDEN.into());
        }
        v
    }

    fn canonical_rel_type(&self, type_name: &str) -> Option<String> {
        view::canonical_rel_type(type_name)
    }

    fn suggest_rel_type(&self, type_name: &str) -> Option<String> {
        view::suggest_rel_type(type_name)
    }

    fn suggest_label(&self, label: &str) -> Option<String> {
        view::suggest_label(label)
    }

    fn label_note(&self, label: &str) -> Option<String> {
        view::owned_note(label, self.owned.is_empty())
    }

    fn notes(&self) -> Vec<String> {
        match self.props {
            Ok(_) => Vec::new(),
            Err(why) => vec![why.note().to_string()],
        }
    }

    fn type_sel(&self, types: &[String]) -> TypeSel {
        view::type_sel(types)
    }

    fn edges(&self, n: NodeRef, dir: Direction, sel: &TypeSel) -> Vec<(EdgeId, NodeRef)> {
        let mut out = Vec::new();
        if matches!(dir, Direction::Right | Direction::Both) {
            for (id, e) in self.x.out_edges_with_ids(n) {
                if self.selects(sel, e.kind, e.to) {
                    out.push((id, e.to));
                }
            }
        }
        if matches!(dir, Direction::Left | Direction::Both) {
            for (id, e) in self.x.in_edges_with_ids(n) {
                // Undirected, a self-loop came already as an outgoing edge.
                if dir == Direction::Both && e.from == n {
                    continue;
                }
                if self.selects(sel, e.kind, e.to) {
                    out.push((id, e.from));
                }
            }
        }
        out
    }

    fn edge_kind(&self, e: EdgeId) -> EdgeKind {
        self.edge(e).kind
    }

    fn edge_ends(&self, e: EdgeId) -> (NodeRef, NodeRef) {
        let e = self.edge(e);
        (e.from, e.to)
    }

    fn name(&self, n: NodeRef) -> String {
        self.g.node(NodeIndex::new(n as usize)).name.clone()
    }

    fn kind(&self, n: NodeRef) -> NodeKind {
        self.x.kind(n)
    }

    /// The search of [`crate::analysis::search`], over the run's lists.
    fn shortest_tree(
        &self,
        root: NodeRef,
        dir: Direction,
        sel: &TypeSel,
        max_depth: Option<u32>,
        stop: &dyn Fn(NodeRef) -> bool,
        visit: &mut dyn FnMut(NodeRef) -> bool,
    ) -> ReachTree {
        let n = self.x.node_count();
        let mut tree = ReachTree::empty(n);
        let ix = |v: NodeRef| NodeIndex::new(v as usize);
        tree.reach(ix(root), None, 0);
        if visit(root) {
            return tree;
        }
        // Toward the root: `(a)-[]->(root)` steps back along edges into it.
        let (back, forth) = match dir {
            Direction::Right => (true, false),
            Direction::Left => (false, true),
            Direction::Both => (true, true),
        };
        let mut queue = VecDeque::from([root]);
        let mut found = Vec::new();
        'bfs: while let Some(v) = queue.pop_front() {
            let d = tree.depth(ix(v)).unwrap_or(0);
            if max_depth.is_some_and(|m| d >= m) {
                continue;
            }
            found.clear();
            if back {
                for (id, e) in self.x.in_edges_with_ids(v) {
                    if self.selects(sel, e.kind, e.to) {
                        found.push((e.from, id));
                    }
                }
            }
            if forth {
                for (id, e) in self.x.out_edges_with_ids(v) {
                    if self.selects(sel, e.kind, e.to) {
                        found.push((e.to, id));
                    }
                }
            }
            for &(u, id) in &found {
                if tree.reaches(ix(u)) {
                    continue;
                }
                tree.reach(ix(u), Some((ix(v), EdgeIndex::new(id as usize))), d + 1);
                if !stop(u) {
                    queue.push_back(u);
                }
                if visit(u) {
                    break 'bfs;
                }
            }
        }
        tree
    }
}
