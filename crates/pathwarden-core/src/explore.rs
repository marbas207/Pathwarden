//! Graph exploration for the local UI: a compact copy of a run's whole graph
//! (every edge, with its kind and whether the right was inherited), each
//! finding's path, entry points and affected objects, and the queries the
//! explorer runs on it: neighbors, shortest and k-shortest paths, "who can
//! reach this" and zone suggestions.
//!
//! [`encode_to`] writes it at the end of an analysis and
//! [`ExploreGraph::decode`] reads it back. Objects are numbered by their
//! index in the analysis graph, which is also their position in the run's
//! object index ([`crate::object_index::ObjectIndex`]), so names, search and
//! distinguished names come from there and are not stored twice.
//!
//! Format (the UI gzips it). Version 1:
//!
//! - `PWEXPL` and a version byte;
//! - a varint object count, then two bytes per object: its kind and flags
//!   ([`flag`]);
//! - per object, its incoming edges in the analysis graph's own order: a
//!   varint count, then per edge the zigzag varint difference from the
//!   previous edge's source and a byte holding the edge kind (bit 7 set when
//!   inherited);
//! - a varint length and a JSON [`Meta`]: Tier Zero reasons, zone members and
//!   findings, in report order.
//!
//! Version 2, written only when the graph has external (OpenGraph) kinds,
//! so graphs without them stay byte for byte as before:
//!
//! - `PWEXPL`, the version byte, then a varint length and a JSON
//!   [`KindsInfo`]: every node and edge kind the codes below refer to, by
//!   name, with what the mapping packs say about external ones;
//! - objects as in version 1, but each kind is a varint index into the
//!   node kinds;
//! - edges as in version 1, but each kind is a varint: the index into the
//!   edge kinds shifted left once, bit 0 set when inherited;
//! - the [`Meta`] as in version 1.
//!
//! Both versions are read.
//!
//! Keeping the incoming order means a breadth-first search here finds exactly
//! the path [`crate::analysis`] finds.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{self, Write};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::analysis::AttackPath;
use crate::findings::{EntryPoints, Finding, Severity};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, Node, NodeKind};
use crate::sid;
use crate::zones::Zone;

pub mod answers;

const MAGIC: &[u8; 6] = b"PWEXPL";
/// The version written for graphs without external kinds.
pub const FORMAT_VERSION: u8 = 1;
/// The version written for graphs with external (OpenGraph) kinds.
pub const FORMAT_VERSION_KINDS: u8 = 2;

/// Per-object flags.
pub mod flag {
    pub const TIER_ZERO: u8 = 1;
    /// Referenced but never collected.
    pub const PLACEHOLDER: u8 = 2;
    pub const DC: u8 = 4;
    pub const DISABLED: u8 = 8;
    /// A computer running a server operating system.
    pub const SERVER: u8 = 16;
    /// `adminCount=1`: protected by AdminSDHolder, so once privileged.
    pub const ADMIN_COUNT: u8 = 32;
    /// Everyone, Authenticated Users, Domain Users, Domain Computers, Users.
    pub const BROAD: u8 = 64;
}

const INHERITED: u8 = 0x80;
/// Inherited, in the in-memory edge codes.
const INH: u16 = 0x8000;
const NONE: u32 = u32::MAX;

/// Objects kept per finding for each list (entry points, affected, Tier Zero
/// objects reached); the totals are kept as well.
pub const FINDING_LIST_CAP: usize = 200;

fn node_kind_code(k: NodeKind) -> u8 {
    NodeKind::ALL.iter().position(|&x| x == k).unwrap_or(0) as u8
}

fn edge_code(k: EdgeKind) -> u8 {
    EdgeKind::ALL.iter().position(|&x| x == k).unwrap_or(0) as u8
}

/// The kinds a version 2 file names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KindsInfo {
    pub nodes: Vec<NodeKindInfo>,
    pub edges: Vec<EdgeKindInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeKindInfo {
    pub name: String,
    /// Display label from a mapping pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// An icon name from [`crate::opengraph::pack::ICONS`]; absent means the
    /// generic shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// `#RGB` or `#RRGGBB`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeKindInfo {
    pub name: String,
    #[serde(default)]
    pub traversable: bool,
    /// The mapping pack that describes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The OpenGraph sources whose files had edges of this kind (for the
    /// explorer's source filter); empty for AD kinds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

/// Version 2 is written when OpenGraph data (or SYSVOL, which uses the same
/// source mechanism) added anything: its kind table names each edge kind's
/// sources, for Explore's source filter.
fn has_external(g: &AdGraph) -> bool {
    !g.og_sources().is_empty()
        || g.nodes().any(|(_, n)| n.kind.is_external())
        || g.inner().edge_weights().any(|k| k.is_external())
}

/// Every kind of the graph, natives first in their usual order (so their
/// codes are the version 1 codes), then external ones by name.
fn kinds_of(g: &AdGraph) -> (Vec<NodeKind>, Vec<EdgeKind>, KindsInfo) {
    let mut node_ext: Vec<NodeKind> = g
        .nodes()
        .map(|(_, n)| n.kind)
        .filter(|k| k.is_external())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    node_ext.sort_by_key(|k| k.as_str());
    let mut edge_ext: Vec<EdgeKind> = g
        .inner()
        .edge_weights()
        .copied()
        .filter(|k| k.is_external())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    edge_ext.sort_by_key(|k| k.as_str());
    let nodes: Vec<NodeKind> = NodeKind::ALL.iter().copied().chain(node_ext).collect();
    let edges: Vec<EdgeKind> = EdgeKind::ALL.iter().copied().chain(edge_ext).collect();
    let table = g.kind_table();
    let mut sources: HashMap<EdgeKind, std::collections::BTreeSet<String>> = HashMap::new();
    // Every edge an OpenGraph source added, external kinds and native ones
    // alike (SYSVOL's WriteGPOFiles and WriteLogonScript).
    for e in g.inner().edge_references() {
        if let Some(o) = g.edge_origin(e.id()) {
            sources
                .entry(*e.weight())
                .or_default()
                .insert(g.source_name(o.source).to_string());
        }
    }
    let info = KindsInfo {
        nodes: nodes
            .iter()
            .map(|&k| {
                let sem = match k {
                    NodeKind::External(x) => table.node(x),
                    _ => None,
                };
                NodeKindInfo {
                    name: k.as_str().to_string(),
                    label: sem.and_then(|s| s.label.clone()),
                    icon: sem.and_then(|s| s.icon.clone()),
                    color: sem.and_then(|s| s.color.clone()),
                }
            })
            .collect(),
        edges: edges
            .iter()
            .map(|&k| {
                let sem = g.edge_sem(k);
                EdgeKindInfo {
                    name: k.as_str().to_string(),
                    traversable: match k {
                        EdgeKind::External(_) => sem.is_some_and(|s| s.traversable),
                        _ => k.is_traversable(),
                    },
                    pack: sem.map(|s| s.pack.clone()),
                    description: sem.and_then(|s| s.description.clone()),
                    sources: sources
                        .remove(&k)
                        .map(|s| s.into_iter().collect())
                        .unwrap_or_default(),
                }
            })
            .collect(),
    };
    (nodes, edges, info)
}

/// The kind a version 2 file names: native, or external (interned; past
/// the cap, `OG_Other`).
fn node_kind_named(name: &str) -> Option<NodeKind> {
    if let Some(k) = NodeKind::ALL.iter().copied().find(|k| k.as_str() == name) {
        return Some(k);
    }
    valid_external(name).then(|| NodeKind::External(crate::kinds::intern(name)))
}

fn edge_kind_named(name: &str) -> Option<EdgeKind> {
    if let Some(k) = EdgeKind::ALL.iter().copied().find(|k| k.as_str() == name) {
        return Some(k);
    }
    valid_external(name).then(|| EdgeKind::External(crate::kinds::intern(name)))
}

fn valid_external(name: &str) -> bool {
    let base = name.strip_suffix(" (context)").unwrap_or(name);
    crate::kinds::valid_name(base) || base == crate::kinds::OTHER_NAME
}

pub(crate) fn node_flags(n: &Node) -> u8 {
    let mut f = 0;
    if n.tier_zero {
        f |= flag::TIER_ZERO;
    }
    if n.placeholder {
        f |= flag::PLACEHOLDER;
    }
    if n.is_dc {
        f |= flag::DC;
    }
    if !n.is_enabled() {
        f |= flag::DISABLED;
    }
    if n.kind == NodeKind::Computer
        && n.props
            .operatingsystem
            .as_deref()
            .is_some_and(|os| os.to_ascii_lowercase().contains("server"))
    {
        f |= flag::SERVER;
    }
    if n.props.admincount == Some(true) {
        f |= flag::ADMIN_COUNT;
    }
    if sid::is_broad_group(&n.id) {
        f |= flag::BROAD;
    }
    f
}

// ------------------------------------------------------------ varints

fn put_varint(w: &mut impl Write, mut v: u64) -> io::Result<()> {
    let mut buf = [0u8; 10];
    let mut i = 0;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf[i] = b;
            i += 1;
            break;
        }
        buf[i] = b | 0x80;
        i += 1;
    }
    w.write_all(&buf[..i])
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.b.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.left() {
            return Err("the explorer data is cut short".into());
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("the explorer data is damaged".into())
    }
}

// ------------------------------------------------------------- meta

/// Everything besides the edges, as JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// `(object, why it is Tier Zero)`.
    #[serde(default)]
    pub tier_zero_reasons: Vec<(u32, String)>,
    #[serde(default)]
    pub zones: Vec<ZoneData>,
    /// In the report's order.
    #[serde(default)]
    pub findings: Vec<FindingData>,
    /// The domains and trusts ([`crate::forest::forest_map`]); `None` for
    /// runs saved before it was kept, and for graphs encoded without their
    /// analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forest: Option<crate::forest::ForestMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneData {
    pub name: String,
    /// Sorted.
    pub members: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingData {
    pub fingerprint: String,
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    pub attack_path: bool,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub suppressed: bool,
    /// Percent of the population exposed.
    #[serde(default)]
    pub exposure: Option<f64>,
    #[serde(default)]
    pub exposed: Option<usize>,
    /// Any authenticated principal can abuse it.
    #[serde(default)]
    pub everyone: bool,
    #[serde(default)]
    pub entry: Vec<u32>,
    #[serde(default)]
    pub entry_total: usize,
    /// Tier Zero (or zone) objects it leads to.
    #[serde(default)]
    pub hits: Vec<u32>,
    #[serde(default)]
    pub hits_total: usize,
    /// The example attack path's objects, start first (empty when there is
    /// none), and the edge kinds between them.
    #[serde(default)]
    pub path: Vec<u32>,
    #[serde(default)]
    pub path_edges: Vec<String>,
    #[serde(default)]
    pub affected: Vec<u32>,
    #[serde(default)]
    pub affected_total: usize,
}

/// The order the report lists findings in: grouped by rule, groups with the
/// most severe finding first, then larger groups, then by rule ID (as
/// `report::findings_panel` does).
pub fn report_order(findings: &[Finding]) -> Vec<usize> {
    let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, f) in findings.iter().enumerate() {
        groups.entry(f.rule).or_default().push(i);
    }
    let mut groups: Vec<(&str, Vec<usize>)> = groups.into_iter().collect();
    let worst = |ix: &[usize]| {
        ix.iter()
            .map(|&i| findings[i].severity)
            .max()
            .unwrap_or(Severity::Info)
    };
    groups.sort_by(|a, b| {
        worst(&b.1)
            .cmp(&worst(&a.1))
            .then(b.1.len().cmp(&a.1.len()))
            .then(a.0.cmp(b.0))
    });
    groups.into_iter().flat_map(|(_, ix)| ix).collect()
}

/// The objects and edge kinds of an attack path, found by walking the
/// graph from its start (names alone can repeat across domains).
fn resolve_path(
    g: &AdGraph,
    starts: &HashMap<&str, Vec<NodeIndex>>,
    p: &AttackPath,
) -> Option<(Vec<u32>, Vec<String>)> {
    let first = p.steps.first()?;
    let all = starts.get(first.from.as_str())?;
    let same_kind: Vec<NodeIndex> = all
        .iter()
        .copied()
        .filter(|&ix| g.node(ix).kind == first.from_kind)
        .collect();
    let candidates = if same_kind.is_empty() {
        all.clone()
    } else {
        same_kind
    };
    'start: for s in candidates {
        let mut nodes = vec![s.index() as u32];
        let mut cur = s;
        for step in &p.steps {
            let next = g
                .inner()
                .edges_directed(cur, Direction::Outgoing)
                .find(|e| *e.weight() == step.edge && g.node(e.target()).name == step.to)
                .map(|e| e.target());
            match next {
                Some(nx) => {
                    nodes.push(nx.index() as u32);
                    cur = nx;
                }
                None => continue 'start,
            }
        }
        let edges = p
            .steps
            .iter()
            .map(|s| s.edge.as_str().to_string())
            .collect();
        return Some((nodes, edges));
    }
    None
}

fn build_meta(g: &AdGraph, findings: &[Finding], zones: &[Zone]) -> Meta {
    let tier_zero_reasons = g
        .nodes()
        .filter(|(_, n)| n.tier_zero)
        .map(|(ix, n)| {
            (
                ix.index() as u32,
                n.tier_zero_reason
                    .clone()
                    .unwrap_or_else(|| "Tier Zero".into()),
            )
        })
        .collect();
    let zones = zones
        .iter()
        .map(|z| {
            let mut members: Vec<u32> = z.members.iter().map(|ix| ix.index() as u32).collect();
            members.sort_unstable();
            ZoneData {
                name: z.name.clone(),
                members,
            }
        })
        .collect();

    // Start objects of every example path, found in one pass.
    let wanted: HashSet<&str> = findings
        .iter()
        .filter_map(|f| Some(f.path.as_ref()?.steps.first()?.from.as_str()))
        .collect();
    let mut starts: HashMap<&str, Vec<NodeIndex>> = HashMap::new();
    if !wanted.is_empty() {
        for (ix, n) in g.nodes() {
            if let Some(&name) = wanted.get(n.name.as_str()) {
                starts.entry(name).or_default().push(ix);
            }
        }
    }

    let capped = |ixs: &mut dyn Iterator<Item = u32>| -> (Vec<u32>, usize) {
        let mut out = Vec::new();
        let mut total = 0;
        for ix in ixs {
            total += 1;
            if out.len() < FINDING_LIST_CAP {
                out.push(ix);
            }
        }
        (out, total)
    };

    let findings = report_order(findings)
        .into_iter()
        .map(|i| {
            let f = &findings[i];
            let (everyone, (entry, entry_total)) = match f.entry_points() {
                EntryPoints::None => (false, (Vec::new(), 0)),
                EntryPoints::Everyone => (true, (Vec::new(), 0)),
                EntryPoints::Principals(p) => {
                    (false, capped(&mut p.iter().map(|ix| ix.index() as u32)))
                }
            };
            let (hits, hits_total) =
                capped(&mut f.hit_objects().iter().map(|ix| ix.index() as u32));
            let (affected, affected_total) = capped(
                &mut f
                    .affected
                    .iter()
                    .filter_map(|a| g.lookup(&a.id))
                    .map(|ix| ix.index() as u32),
            );
            let (path, path_edges) = f
                .path
                .as_ref()
                .and_then(|p| resolve_path(g, &starts, p))
                .unwrap_or_default();
            FindingData {
                fingerprint: f.fingerprint.clone(),
                rule: f.rule.to_string(),
                title: f.title.clone(),
                severity: f.severity,
                attack_path: f.category == crate::findings::Category::AttackPath,
                summary: f.summary.clone(),
                domain: f.domain.clone(),
                suppressed: f.suppressed.is_some(),
                exposure: f.exposure.as_ref().map(|e| e.percent),
                exposed: f.exposure.as_ref().map(|e| e.principals),
                everyone,
                entry,
                entry_total,
                hits,
                hits_total,
                path,
                path_edges,
                affected,
                affected_total,
            }
        })
        .collect();
    Meta {
        tier_zero_reasons,
        zones,
        findings,
        forest: None,
    }
}

/// Writes the explorer data for a graph and its findings.
pub fn encode_to<W: Write>(
    w: W,
    g: &AdGraph,
    findings: &[Finding],
    zones: &[Zone],
) -> io::Result<()> {
    write_to(w, g, &build_meta(g, findings, zones))
}

/// Writes the explorer data for an analysis, with its forest map: what a
/// saved run keeps.
pub fn encode_analysis_to<W: Write>(w: W, a: &crate::analyze::Analysis) -> io::Result<()> {
    encode_with_forest_to(w, a, &a.forest_map())
}

/// [`encode_analysis_to`] with a given forest map (one as an older version
/// saved it, in tests).
pub fn encode_with_forest_to<W: Write>(
    w: W,
    a: &crate::analyze::Analysis,
    forest: &crate::forest::ForestMap,
) -> io::Result<()> {
    let mut meta = build_meta(&a.graph, &a.findings, &a.zones);
    meta.forest = Some(forest.clone());
    write_to(w, &a.graph, &meta)
}

fn write_to<W: Write>(w: W, g: &AdGraph, meta: &Meta) -> io::Result<()> {
    let mut w = io::BufWriter::with_capacity(1 << 16, w);
    w.write_all(MAGIC)?;
    if has_external(g) {
        return encode_v2(w, g, meta);
    }
    w.write_all(&[FORMAT_VERSION])?;
    put_varint(&mut w, g.node_count() as u64)?;
    for (_, n) in g.nodes() {
        w.write_all(&[node_kind_code(n.kind), node_flags(n)])?;
    }
    for v in g.inner().node_indices() {
        let count = g.inner().edges_directed(v, Direction::Incoming).count();
        put_varint(&mut w, count as u64)?;
        let mut prev = 0i64;
        for e in g.inner().edges_directed(v, Direction::Incoming) {
            let s = e.source().index() as i64;
            put_varint(&mut w, zigzag(s - prev))?;
            prev = s;
            let mut code = edge_code(*e.weight());
            if g.is_inherited(e.id()) {
                code |= INHERITED;
            }
            w.write_all(&[code])?;
        }
    }
    let json = serde_json::to_vec(meta).map_err(io::Error::other)?;
    put_varint(&mut w, json.len() as u64)?;
    w.write_all(&json)?;
    w.flush()
}

/// Version 2 (see the module documentation), after the magic.
fn encode_v2<W: Write>(mut w: io::BufWriter<W>, g: &AdGraph, meta: &Meta) -> io::Result<()> {
    w.write_all(&[FORMAT_VERSION_KINDS])?;
    let (nodes, edges, info) = kinds_of(g);
    let node_code: HashMap<NodeKind, u64> = nodes
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i as u64))
        .collect();
    let edge_code: HashMap<EdgeKind, u64> = edges
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i as u64))
        .collect();
    let json = serde_json::to_vec(&info).map_err(io::Error::other)?;
    put_varint(&mut w, json.len() as u64)?;
    w.write_all(&json)?;
    put_varint(&mut w, g.node_count() as u64)?;
    for (_, n) in g.nodes() {
        put_varint(&mut w, node_code[&n.kind])?;
        w.write_all(&[node_flags(n)])?;
    }
    for v in g.inner().node_indices() {
        let count = g.inner().edges_directed(v, Direction::Incoming).count();
        put_varint(&mut w, count as u64)?;
        let mut prev = 0i64;
        for e in g.inner().edges_directed(v, Direction::Incoming) {
            let s = e.source().index() as i64;
            put_varint(&mut w, zigzag(s - prev))?;
            prev = s;
            let code = (edge_code[e.weight()] << 1) | u64::from(g.is_inherited(e.id()));
            put_varint(&mut w, code)?;
        }
    }
    let json = serde_json::to_vec(meta).map_err(io::Error::other)?;
    put_varint(&mut w, json.len() as u64)?;
    w.write_all(&json)?;
    w.flush()
}

/// [`encode_to`] into memory.
pub fn encode(g: &AdGraph, findings: &[Finding], zones: &[Zone]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_to(&mut out, g, findings, zones).expect("writing to memory");
    out
}

/// The explore graph of an analysis in memory, exactly as a saved run's
/// reads back: what the CLI explores (`pathwarden reach`, `zones suggest`).
pub fn build(g: &AdGraph, findings: &[Finding], zones: &[Zone]) -> Result<ExploreGraph, String> {
    ExploreGraph::decode(&encode(g, findings, zones))
}

// ------------------------------------------------------------ graph

/// One edge: `from` holds `kind` over `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub from: u32,
    pub to: u32,
    pub kind: EdgeKind,
    pub inherited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
    Both,
}

/// A run's graph for exploring: both directions as compressed adjacency
/// lists (about ten bytes per edge).
pub struct ExploreGraph {
    /// Per object, an index into `node_table`.
    kinds: Vec<u16>,
    node_table: Vec<NodeKind>,
    flags: Vec<u8>,
    in_off: Vec<u32>,
    in_src: Vec<u32>,
    /// Per edge, an index into `edge_table`, with [`INH`] when inherited.
    in_kind: Vec<u16>,
    out_off: Vec<u32>,
    out_dst: Vec<u32>,
    out_kind: Vec<u16>,
    /// Per outgoing edge, its place in the incoming lists: its ID
    /// ([`ExploreGraph::edge_at`]).
    out_in: Vec<u32>,
    edge_table: Vec<EdgeKind>,
    /// External kinds the mapping packs made traversable.
    ext_traversable: HashSet<EdgeKind>,
    /// The kinds the file names (version 2), for display.
    pub kinds_info: KindsInfo,
    pub meta: Meta,
    reasons: HashMap<u32, usize>,
}

/// Neighbors of one object, capped.
#[derive(Debug, Clone)]
pub struct Neighbors {
    pub edges: Vec<Edge>,
    /// Edges matching the kinds filter.
    pub total: usize,
    /// Every edge in the direction asked, per kind (ignoring the filter).
    pub by_kind: Vec<(EdgeKind, usize)>,
}

/// A breadth-first search backwards from a set of targets: for every object
/// reached, the next object toward the targets and the edge to it.
pub struct PathTree {
    next: Vec<u32>,
    kind: Vec<EdgeKind>,
    inherited: Vec<bool>,
    hops: Vec<u32>,
    /// Objects in the order they were reached, targets first.
    order: Vec<u32>,
}

impl PathTree {
    pub fn reaches(&self, v: u32) -> bool {
        self.hops.get(v as usize).is_some_and(|&h| h != NONE)
    }

    /// Edges from `v` to the target set.
    pub fn hops(&self, v: u32) -> Option<u32> {
        self.hops.get(v as usize).copied().filter(|&h| h != NONE)
    }

    /// The first edge of `v`'s path: `(next object, kind, inherited)`.
    pub fn step(&self, v: u32) -> Option<Edge> {
        let next = *self.next.get(v as usize)?;
        (next != NONE).then(|| Edge {
            from: v,
            to: next,
            kind: self.kind[v as usize],
            inherited: self.inherited[v as usize],
        })
    }

    pub fn path(&self, from: u32) -> Option<Vec<Edge>> {
        if !self.reaches(from) {
            return None;
        }
        let mut out = Vec::new();
        let mut cur = from;
        while let Some(e) = self.step(cur) {
            out.push(e);
            cur = e.to;
        }
        Some(out)
    }

    /// The target `v`'s path ends at.
    pub fn target(&self, v: u32) -> Option<u32> {
        if !self.reaches(v) {
            return None;
        }
        let mut cur = v;
        while let Some(e) = self.step(cur) {
            cur = e.to;
        }
        Some(cur)
    }
}

#[derive(Default)]
struct Search<'a> {
    /// Stop as soon as this object is reached.
    stop: Option<u32>,
    banned_nodes: Option<&'a HashSet<u32>>,
    banned_edges: Option<&'a HashSet<(u32, u32, EdgeKind)>>,
    /// List Tier Zero objects but go no further through them.
    stop_at_tier_zero: bool,
}

/// One object that can reach the object asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reacher {
    pub node: u32,
    pub hops: u32,
    /// The first edge of its shortest route.
    pub first: Edge,
    /// [`ExploreGraph::reach_class`].
    pub class: u8,
}

/// Why an object is suggested for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Heuristic {
    /// Many exposed principals' shortest paths to Tier Zero run through it.
    ChokePoint,
    /// It controls many other objects.
    Control,
    /// Privileged accounts log on to it.
    PrivilegedSessions,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub node: u32,
    pub heuristic: Heuristic,
    /// The tier it most likely belongs in: 1 (servers, and anything close to
    /// Tier Zero) or 2 (workstations).
    pub tier: u8,
    /// Choke point: exposed principals whose shortest path runs through it.
    /// Control: objects it controls. Sessions: privileged accounts seen
    /// logged on to it.
    pub count: usize,
    pub servers: usize,
    pub workstations: usize,
    pub users: usize,
    pub groups: usize,
    pub other: usize,
    pub tier_zero_sessions: usize,
    pub admin_sessions: usize,
    /// Groups: members, nested included.
    pub members: Option<usize>,
    /// A Tier Zero object the paths lead to, or a privileged account seen.
    pub example: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestions {
    /// Exposed principals (enabled users and computers outside Tier Zero
    /// that can reach it).
    pub exposed: usize,
    pub population: usize,
    pub items: Vec<Suggestion>,
}

/// Edges that grant control of the target, as opposed to structure
/// (membership, containment, links), sessions and trusts.
pub fn is_control(kind: EdgeKind) -> bool {
    kind.is_traversable()
        && !kind.is_adcs_abuse()
        && !matches!(
            kind,
            EdgeKind::MemberOf
                | EdgeKind::Contains
                | EdgeKind::GpLink
                | EdgeKind::HasSession
                | EdgeKind::SameForestTrust
                | EdgeKind::HasSidHistory
                | EdgeKind::CoerceToTgt
                | EdgeKind::DcSync
                | EdgeKind::GoldenCert
                | EdgeKind::HostsCaService
        )
}

/// How many objects a graph read back may hold: one written here, or one
/// whose run says how large it is (a saved run's summary, an earlier run's
/// point). Its edges are bounded by its objects ([`edge_budget`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub min_objects: usize,
    pub max_objects: usize,
}

impl Bounds {
    /// No bounds but the bytes' own.
    pub const ANY: Bounds = Bounds {
        min_objects: 0,
        max_objects: NONE as usize - 1,
    };
    /// Objects a graph may hold per object its run collected: the rest are
    /// placeholders, referenced but not collected (5 to 25% in real runs).
    pub const PER_COLLECTED: usize = 2;
    /// And this many more, for a run that collected few.
    pub const SLACK: usize = 100_000;

    /// The bounds of a run that collected `objects` objects (its summary's
    /// count, which leaves out placeholders).
    pub fn of_collected(objects: usize) -> Bounds {
        Bounds {
            min_objects: 0,
            max_objects: objects
                .saturating_mul(Self::PER_COLLECTED)
                .saturating_add(Self::SLACK)
                .min(Self::ANY.max_objects),
        }
    }
}

/// Edges a graph may hold per object, on average: real runs have 7 to 32
/// (a 685,000-object domain, 32).
pub const EDGES_PER_OBJECT: usize = 256;
/// And this many more, for a small graph dense with edges.
pub const EDGE_SLACK: usize = 1 << 20;

/// The most edges a graph of `objects` objects may hold. Checked before
/// anything is made for them: an edge takes two bytes in the file, six in
/// memory.
pub fn edge_budget(objects: usize) -> usize {
    objects
        .saturating_mul(EDGES_PER_OBJECT)
        .saturating_add(EDGE_SLACK)
}

/// A graph of `n` objects whose first holds `edges` edges from itself, two
/// bytes each, and no meta: what a planted file can say in few bytes.
#[cfg(test)]
pub(crate) fn edge_bomb(n: usize, edges: usize) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.push(FORMAT_VERSION);
    put_varint(&mut b, n as u64).unwrap();
    b.resize(b.len() + 2 * n, 0);
    put_varint(&mut b, edges as u64).unwrap();
    b.resize(b.len() + 2 * edges, 0);
    b.resize(b.len() + n, 0);
    b
}

/// The forest map kept in explorer data ([`Meta::forest`]), read past the
/// graph without building it: what the Collect page lists a domain's
/// trusted domains from. `None` for data saved before the map was
/// kept.
pub fn read_forest(bytes: &[u8]) -> Result<Option<crate::forest::ForestMap>, String> {
    #[derive(Deserialize)]
    struct OnlyForest {
        #[serde(default)]
        forest: Option<crate::forest::ForestMap>,
    }
    let damaged = || "the explorer data is damaged".to_string();
    let mut r = Reader { b: bytes, pos: 0 };
    if r.take(MAGIC.len())? != MAGIC {
        return Err("not explorer data".into());
    }
    let v2 = match r.byte()? {
        FORMAT_VERSION => false,
        FORMAT_VERSION_KINDS => true,
        v => return Err(format!("explorer data version {v} is not supported")),
    };
    if v2 {
        let len = r.varint()? as usize;
        r.take(len)?;
    }
    let n = r.varint()? as usize;
    if n > r.left() / 3 {
        return Err(damaged());
    }
    for _ in 0..n {
        if v2 {
            r.varint()?;
        } else {
            r.byte()?;
        }
        r.byte()?;
    }
    for _ in 0..n {
        let count = r.varint()? as usize;
        if count > r.left() / 2 {
            return Err(damaged());
        }
        for _ in 0..count {
            r.varint()?;
            if v2 {
                r.varint()?;
            } else {
                r.byte()?;
            }
        }
    }
    let len = r.varint()? as usize;
    let meta: OnlyForest = serde_json::from_slice(r.take(len)?)
        .map_err(|e| format!("the explorer data is damaged: {e}"))?;
    Ok(meta.forest)
}

impl ExploreGraph {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        Self::decode_within(bytes, Bounds::ANY)
    }

    /// [`ExploreGraph::decode`], refusing a graph of more or fewer objects
    /// than `bounds`, or of more edges than its objects may have
    /// ([`edge_budget`]), before anything is made for them.
    pub fn decode_within(bytes: &[u8], bounds: Bounds) -> Result<Self, String> {
        let mut r = Reader { b: bytes, pos: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err("not explorer data".into());
        }
        let version = r.byte()?;
        let v2 = match version {
            FORMAT_VERSION => false,
            FORMAT_VERSION_KINDS => true,
            _ => return Err(format!("explorer data version {version} is not supported")),
        };
        let damaged = || "the explorer data is damaged".to_string();
        let mut kinds_info = KindsInfo::default();
        let (node_table, edge_table): (Vec<NodeKind>, Vec<EdgeKind>) = if v2 {
            let len = r.varint()? as usize;
            kinds_info = serde_json::from_slice(r.take(len)?)
                .map_err(|e| format!("the explorer data is damaged: {e}"))?;
            if kinds_info.nodes.len() >= INH as usize || kinds_info.edges.len() >= INH as usize {
                return Err(damaged());
            }
            let nodes = kinds_info
                .nodes
                .iter()
                .map(|k| node_kind_named(&k.name).ok_or_else(damaged))
                .collect::<Result<Vec<_>, _>>()?;
            let edges = kinds_info
                .edges
                .iter()
                .map(|k| edge_kind_named(&k.name).ok_or_else(damaged))
                .collect::<Result<Vec<_>, _>>()?;
            (nodes, edges)
        } else {
            (NodeKind::ALL.to_vec(), EdgeKind::ALL.to_vec())
        };
        let ext_traversable: HashSet<EdgeKind> = kinds_info
            .edges
            .iter()
            .zip(&edge_table)
            .filter(|(info, k)| info.traversable && k.is_external())
            .map(|(_, k)| *k)
            .collect();
        let n = r.varint()? as usize;
        // Each object takes at least three bytes.
        if n > r.left() / 3 || n >= NONE as usize {
            return Err(damaged());
        }
        if n > bounds.max_objects {
            return Err("the explorer data has more objects than its run counted".into());
        }
        if n < bounds.min_objects {
            return Err("the explorer data has fewer objects than its run counted".into());
        }
        let budget = edge_budget(n);
        let mut kinds = Vec::with_capacity(n);
        let mut flags = Vec::with_capacity(n);
        for _ in 0..n {
            let k = if v2 {
                r.varint()?
            } else {
                u64::from(r.byte()?)
            };
            if k as usize >= node_table.len() {
                return Err(damaged());
            }
            kinds.push(k as u16);
            flags.push(r.byte()?);
        }
        let mut in_off = Vec::with_capacity(n + 1);
        in_off.push(0u32);
        let mut in_src: Vec<u32> = Vec::new();
        let mut in_kind: Vec<u16> = Vec::new();
        for _ in 0..n {
            let count = r.varint()? as usize;
            if count > r.left() / 2 {
                return Err("the explorer data is damaged".into());
            }
            // Checked before reserving: past `budget`, nothing more is made.
            if count > budget - in_src.len() {
                return Err("the explorer data has more edges than its objects can have".into());
            }
            in_src.reserve(count);
            in_kind.reserve(count);
            let mut prev = 0i64;
            for _ in 0..count {
                let s = prev.checked_add(unzigzag(r.varint()?));
                let Some(s) = s.filter(|&s| s >= 0 && (s as u64) < n as u64) else {
                    return Err("the explorer data is damaged".into());
                };
                prev = s;
                let (index, inherited) = if v2 {
                    let c = r.varint()?;
                    (c >> 1, c & 1 == 1)
                } else {
                    let c = r.byte()?;
                    (u64::from(c & !INHERITED), c & INHERITED != 0)
                };
                if index as usize >= edge_table.len() {
                    return Err(damaged());
                }
                in_src.push(s as u32);
                in_kind.push(index as u16 | if inherited { INH } else { 0 });
            }
            if in_src.len() >= NONE as usize {
                return Err("the explorer data is too large".into());
            }
            in_off.push(in_src.len() as u32);
        }
        let len = r.varint()? as usize;
        let mut meta: Meta = serde_json::from_slice(r.take(len)?)
            .map_err(|e| format!("the explorer data is damaged: {e}"))?;
        // Drop anything that points outside the graph.
        let ok = |v: &u32| (*v as usize) < n;
        meta.tier_zero_reasons.retain(|(v, _)| ok(v));
        for z in &mut meta.zones {
            z.members.retain(ok);
        }
        for f in &mut meta.findings {
            f.entry.retain(ok);
            f.hits.retain(ok);
            f.affected.retain(ok);
            if !f.path.iter().all(ok) || f.path.len() != f.path_edges.len() + 1 {
                f.path.clear();
                f.path_edges.clear();
            }
        }

        // Grown as read: up to twice their length until shrunk, and kept as
        // long as the run.
        in_src.shrink_to_fit();
        in_kind.shrink_to_fit();
        // The outgoing lists, by counting sort on the source.
        let m = in_src.len();
        let mut out_off = vec![0u32; n + 1];
        for &s in &in_src {
            out_off[s as usize + 1] += 1;
        }
        for i in 0..n {
            out_off[i + 1] += out_off[i];
        }
        let mut pos = out_off.clone();
        let mut out_dst = vec![0u32; m];
        let mut out_kind = vec![0u16; m];
        let mut out_in = vec![0u32; m];
        for v in 0..n {
            for i in in_off[v] as usize..in_off[v + 1] as usize {
                let s = in_src[i] as usize;
                let p = pos[s] as usize;
                out_dst[p] = v as u32;
                out_kind[p] = in_kind[i];
                out_in[p] = i as u32;
                pos[s] += 1;
            }
        }
        let reasons = meta
            .tier_zero_reasons
            .iter()
            .enumerate()
            .map(|(i, (v, _))| (*v, i))
            .collect();
        Ok(ExploreGraph {
            kinds,
            node_table,
            flags,
            in_off,
            in_src,
            in_kind,
            out_off,
            out_dst,
            out_kind,
            out_in,
            edge_table,
            ext_traversable,
            kinds_info,
            meta,
            reasons,
        })
    }

    pub fn node_count(&self) -> usize {
        self.kinds.len()
    }

    pub fn edge_count(&self) -> usize {
        self.in_src.len()
    }

    /// Bytes held in memory, roughly.
    pub fn memory(&self) -> usize {
        self.kinds.len() * 3 + (self.in_off.len() + self.out_off.len()) * 4 + self.in_src.len() * 16
    }

    pub fn contains(&self, v: u32) -> bool {
        (v as usize) < self.kinds.len()
    }

    pub fn kind(&self, v: u32) -> NodeKind {
        self.node_table[self.kinds[v as usize] as usize]
    }

    fn edge_of(&self, code: u16) -> EdgeKind {
        // Codes are checked when the file is read.
        self.edge_table[(code & !INH) as usize]
    }

    /// The source collector of an external edge kind (its mapping pack),
    /// for display; `None` for AD kinds.
    pub fn edge_kind_info(&self, kind: EdgeKind) -> Option<&EdgeKindInfo> {
        if !kind.is_external() {
            return None;
        }
        self.kinds_info
            .edges
            .iter()
            .find(|i| i.name == kind.as_str())
    }

    /// What the mapping packs say about an external node kind.
    pub fn node_kind_info(&self, kind: NodeKind) -> Option<&NodeKindInfo> {
        if !kind.is_external() {
            return None;
        }
        self.kinds_info
            .nodes
            .iter()
            .find(|i| i.name == kind.as_str())
    }

    pub fn has(&self, v: u32, f: u8) -> bool {
        self.flags[v as usize] & f != 0
    }

    pub fn flags(&self, v: u32) -> u8 {
        self.flags[v as usize]
    }

    pub fn tier_zero_reason(&self, v: u32) -> Option<&str> {
        self.reasons
            .get(&v)
            .map(|&i| self.meta.tier_zero_reasons[i].1.as_str())
    }

    /// Names of the zones `v` is in.
    pub fn zones_of(&self, v: u32) -> Vec<&str> {
        self.meta
            .zones
            .iter()
            .filter(|z| z.members.binary_search(&v).is_ok())
            .map(|z| z.name.as_str())
            .collect()
    }

    pub fn finding(&self, fingerprint: &str) -> Option<(usize, &FindingData)> {
        self.meta
            .findings
            .iter()
            .enumerate()
            .find(|(_, f)| f.fingerprint.eq_ignore_ascii_case(fingerprint))
    }

    pub fn out_edges(&self, v: u32) -> impl Iterator<Item = Edge> + '_ {
        let (a, b) = (
            self.out_off[v as usize] as usize,
            self.out_off[v as usize + 1] as usize,
        );
        (a..b).map(move |i| Edge {
            from: v,
            to: self.out_dst[i],
            kind: self.edge_of(self.out_kind[i]),
            inherited: self.out_kind[i] & INH != 0,
        })
    }

    pub fn in_edges(&self, v: u32) -> impl Iterator<Item = Edge> + '_ {
        let (a, b) = (
            self.in_off[v as usize] as usize,
            self.in_off[v as usize + 1] as usize,
        );
        (a..b).map(move |i| Edge {
            from: self.in_src[i],
            to: v,
            kind: self.edge_of(self.in_kind[i]),
            inherited: self.in_kind[i] & INH != 0,
        })
    }

    /// The edges into `v` with their IDs, in the order the analysis's
    /// graph lists them (so a search over them meets them as the
    /// analysis's own search does).
    pub fn in_edges_with_ids(&self, v: u32) -> impl Iterator<Item = (u32, Edge)> + '_ {
        let a = self.in_off[v as usize] as usize;
        self.in_edges(v)
            .enumerate()
            .map(move |(k, e)| ((a + k) as u32, e))
    }

    /// The edges out of `v` with their IDs, by target.
    pub fn out_edges_with_ids(&self, v: u32) -> impl Iterator<Item = (u32, Edge)> + '_ {
        let a = self.out_off[v as usize] as usize;
        self.out_edges(v)
            .enumerate()
            .map(move |(k, e)| (self.out_in[a + k], e))
    }

    /// The edge with ID `id` (its place among the incoming edges).
    pub fn edge_at(&self, id: u32) -> Option<Edge> {
        let i = id as usize;
        if i >= self.in_src.len() {
            return None;
        }
        // The target: the last node whose incoming list starts at or
        // before `i`.
        let v = self.in_off.partition_point(|&o| o as usize <= i) - 1;
        Some(Edge {
            from: self.in_src[i],
            to: v as u32,
            kind: self.edge_of(self.in_kind[i]),
            inherited: self.in_kind[i] & INH != 0,
        })
    }

    /// The edge `from -kind-> to`, if it exists.
    pub fn edge(&self, from: u32, to: u32, kind: EdgeKind) -> Option<Edge> {
        if !self.contains(from) || !self.contains(to) {
            return None;
        }
        self.out_edges(from).find(|e| e.to == to && e.kind == kind)
    }

    /// As [`AdGraph::traversable`]: remote logon into a domain controller is
    /// not a path.
    pub fn traversable(&self, kind: EdgeKind, to: u32) -> bool {
        match kind {
            EdgeKind::External(_) => self.ext_traversable.contains(&kind),
            _ => kind.is_traversable() && !(kind.is_remote_logon() && self.has(to, flag::DC)),
        }
    }

    pub fn tier_zero(&self) -> Vec<u32> {
        (0..self.node_count() as u32)
            .filter(|&v| self.has(v, flag::TIER_ZERO))
            .collect()
    }

    /// Principals an attacker could start from (as
    /// [`crate::analysis::population`]): enabled, collected users and
    /// computers outside Tier Zero.
    pub fn is_population(&self, v: u32) -> bool {
        matches!(self.kind(v), NodeKind::User | NodeKind::Computer)
            && !self.has(v, flag::PLACEHOLDER | flag::TIER_ZERO | flag::DISABLED)
    }

    /// The edges of `v` in `dir` whose kind is in `kinds` (all when empty):
    /// at most `limit`, Tier Zero neighbors and traversable edges first.
    pub fn neighbors(&self, v: u32, dir: Dir, kinds: &[EdgeKind], limit: usize) -> Neighbors {
        let edges: Box<dyn Iterator<Item = Edge> + '_> = match dir {
            Dir::Out => Box::new(self.out_edges(v)),
            Dir::In => Box::new(self.in_edges(v)),
            Dir::Both => Box::new(self.out_edges(v).chain(self.in_edges(v))),
        };
        let mut by_kind: BTreeMap<EdgeKind, usize> = BTreeMap::new();
        let mut hits = Vec::new();
        for e in edges {
            *by_kind.entry(e.kind).or_default() += 1;
            if kinds.is_empty() || kinds.contains(&e.kind) {
                hits.push(e);
            }
        }
        let total = hits.len();
        let key = |e: &Edge| {
            let other = if e.from == v { e.to } else { e.from };
            (
                !self.has(other, flag::TIER_ZERO),
                self.has(other, flag::PLACEHOLDER),
                !self.traversable(e.kind, e.to),
                e.kind,
                other,
            )
        };
        if hits.len() > limit && limit > 0 {
            hits.select_nth_unstable_by_key(limit - 1, key);
        }
        hits.truncate(limit);
        hits.sort_unstable_by_key(key);
        let mut by_kind: Vec<(EdgeKind, usize)> = by_kind.into_iter().collect();
        by_kind.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Neighbors {
            edges: hits,
            total,
            by_kind,
        }
    }

    fn search(&self, targets: &[u32], opts: &Search) -> PathTree {
        let n = self.node_count();
        let mut t = PathTree {
            next: vec![NONE; n],
            kind: vec![EdgeKind::MemberOf; n],
            inherited: vec![false; n],
            hops: vec![NONE; n],
            order: Vec::new(),
        };
        let mut queue = VecDeque::new();
        for &v in targets {
            if (v as usize) < n && t.hops[v as usize] == NONE {
                t.hops[v as usize] = 0;
                t.order.push(v);
                queue.push_back(v);
                if opts.stop == Some(v) {
                    return t;
                }
            }
        }
        while let Some(v) = queue.pop_front() {
            let (a, b) = (
                self.in_off[v as usize] as usize,
                self.in_off[v as usize + 1] as usize,
            );
            for i in a..b {
                let u = self.in_src[i];
                if t.hops[u as usize] != NONE {
                    continue;
                }
                let code = self.in_kind[i];
                let kind = self.edge_of(code);
                if !self.traversable(kind, v) {
                    continue;
                }
                if opts.banned_nodes.is_some_and(|b| b.contains(&u))
                    || opts.banned_edges.is_some_and(|b| b.contains(&(u, v, kind)))
                {
                    continue;
                }
                t.hops[u as usize] = t.hops[v as usize] + 1;
                t.next[u as usize] = v;
                t.kind[u as usize] = kind;
                t.inherited[u as usize] = code & INH != 0;
                t.order.push(u);
                if opts.stop == Some(u) {
                    return t;
                }
                if !(opts.stop_at_tier_zero && self.has(u, flag::TIER_ZERO)) {
                    queue.push_back(u);
                }
            }
        }
        t
    }

    /// Shortest paths from everything to Tier Zero, as
    /// [`crate::analysis::reach_targets`] builds them.
    pub fn tier_zero_tree(&self) -> PathTree {
        self.search(&self.tier_zero(), &Search::default())
    }

    /// The shortest path from `from` to any of `targets` (the same path
    /// [`crate::analysis::shortest_path`] finds). It ends at the first Tier
    /// Zero object it meets: none goes on through one.
    pub fn shortest_path(&self, from: u32, targets: &[u32]) -> Option<Vec<Edge>> {
        let t = self.search(
            targets,
            &Search {
                stop: Some(from),
                stop_at_tier_zero: true,
                ..Search::default()
            },
        );
        t.path(from)
    }

    /// When [`Self::shortest_path`] finds none because every path to `to`
    /// passes through Tier Zero: the shortest one, up to the first Tier
    /// Zero object on it (as [`crate::analysis::path_through_tier_zero`]).
    pub fn path_through_tier_zero(&self, from: u32, to: u32) -> Option<Vec<Edge>> {
        let mut p = self
            .search(
                &[to],
                &Search {
                    stop: Some(from),
                    ..Search::default()
                },
            )
            .path(from)?;
        let cut = p
            .iter()
            .position(|e| e.to != to && self.has(e.to, flag::TIER_ZERO))?;
        p.truncate(cut + 1);
        Some(p)
    }

    /// Up to `k` shortest loop-free paths from `from` to any of `targets`,
    /// shortest first (Yen's algorithm).
    pub fn k_shortest_paths(&self, from: u32, targets: &[u32], k: usize) -> Vec<Vec<Edge>> {
        let Some(first) = self.shortest_path(from, targets) else {
            return Vec::new();
        };
        let nodes_of = |p: &[Edge]| -> Vec<u32> {
            std::iter::once(from)
                .chain(p.iter().map(|e| e.to))
                .collect()
        };
        let mut found: Vec<Vec<Edge>> = vec![first];
        let mut candidates: Vec<Vec<Edge>> = Vec::new();
        while found.len() < k {
            let prev = found.last().expect("one path").clone();
            let prev_nodes = nodes_of(&prev);
            for i in 0..prev.len() {
                let spur = prev_nodes[i];
                let root = &prev[..i];
                let mut banned_edges = HashSet::new();
                for p in &found {
                    if p.len() > i && p[..i] == *root {
                        banned_edges.insert((p[i].from, p[i].to, p[i].kind));
                    }
                }
                let banned_nodes: HashSet<u32> = prev_nodes[..i].iter().copied().collect();
                let t = self.search(
                    targets,
                    &Search {
                        stop: Some(spur),
                        banned_nodes: Some(&banned_nodes),
                        banned_edges: Some(&banned_edges),
                        stop_at_tier_zero: true,
                    },
                );
                if let Some(spur_path) = t.path(spur) {
                    let mut total = root.to_vec();
                    total.extend(spur_path);
                    if !found.contains(&total) && !candidates.contains(&total) {
                        candidates.push(total);
                    }
                }
            }
            if candidates.is_empty() {
                break;
            }
            // Shortest first; among equals, the one found first.
            let best = (0..candidates.len())
                .min_by_key(|&i| (candidates[i].len(), i))
                .expect("a candidate");
            found.push(candidates.remove(best));
        }
        found
    }

    /// How early in an attack chain an object sits, for ordering "who can
    /// reach this": 0 for enabled users and computers outside Tier Zero (the
    /// unprivileged accounts an attacker starts from), 1 for other objects
    /// outside Tier Zero (groups, OUs, GPOs ...), 2 for disabled or
    /// uncollected objects, 3 for Tier Zero.
    pub fn reach_class(&self, v: u32) -> u8 {
        if self.has(v, flag::TIER_ZERO) {
            3
        } else if self.has(v, flag::DISABLED | flag::PLACEHOLDER) {
            2
        } else if matches!(self.kind(v), NodeKind::User | NodeKind::Computer) {
            0
        } else {
            1
        }
    }

    /// Everything that can reach `target` along attack edges, with its hop
    /// count and the first edge of its shortest route. Routes do not go on
    /// through Tier Zero objects (whoever holds one has already won), but
    /// those objects are listed. Unsorted; see [`ExploreGraph::sort_reach`].
    pub fn reach(&self, target: u32) -> Vec<Reacher> {
        if !self.contains(target) {
            return Vec::new();
        }
        let t = self.search(
            &[target],
            &Search {
                stop_at_tier_zero: true,
                ..Search::default()
            },
        );
        t.order
            .iter()
            .filter(|&&v| v != target)
            .filter_map(|&v| {
                Some(Reacher {
                    node: v,
                    hops: t.hops(v)?,
                    first: t.step(v)?,
                    class: self.reach_class(v),
                })
            })
            .collect()
    }

    /// Earliest in the chain first: unprivileged users and computers, then
    /// other objects, disabled ones and Tier Zero; within each, the fewest
    /// hops, then by name.
    pub fn sort_reach<'a>(&self, list: &mut [Reacher], name: impl Fn(u32) -> &'a str) {
        list.sort_by(|a, b| {
            (a.class, a.hops)
                .cmp(&(b.class, b.hops))
                .then_with(|| name(a.node).cmp(name(b.node)))
                .then(a.node.cmp(&b.node))
        });
    }

    /// Members of group `g`, nested included, counted up to `cap`.
    fn member_count(&self, g: u32, cap: usize) -> usize {
        let mut seen = HashSet::from([g]);
        let mut queue = VecDeque::from([g]);
        let mut count = 0;
        while let Some(v) = queue.pop_front() {
            for e in self.in_edges(v) {
                if e.kind == EdgeKind::MemberOf && seen.insert(e.from) {
                    count += 1;
                    if count >= cap {
                        return count;
                    }
                    queue.push_back(e.from);
                }
            }
        }
        count
    }

    /// Objects outside Tier Zero worth putting in a Tier 1 or Tier 2 zone,
    /// `per` for each [`Heuristic`]. `tree` is [`ExploreGraph::tier_zero_tree`].
    pub fn suggestions(&self, tree: &PathTree, per: usize) -> Suggestions {
        let n = self.node_count();
        let candidate = |v: u32| !self.has(v, flag::TIER_ZERO | flag::PLACEHOLDER | flag::BROAD);
        let population = (0..n as u32).filter(|&v| self.is_population(v)).count();
        let mut items = Vec::new();

        // Choke points: how many exposed principals' shortest paths pass
        // through each object, summed up the shortest-path tree.
        let mut below = vec![0u32; n];
        let mut exposed = 0;
        for &v in tree.order.iter().rev() {
            if self.is_population(v) {
                below[v as usize] += 1;
                exposed += 1;
            }
            let next = tree.next[v as usize];
            if next != NONE {
                below[next as usize] += below[v as usize];
            }
        }
        let mut chokes: Vec<(u32, usize)> = (0..n as u32)
            .filter(|&v| candidate(v) && tree.reaches(v))
            .map(|v| {
                let own = usize::from(self.is_population(v));
                (v, below[v as usize] as usize - own)
            })
            .filter(|&(_, through)| through >= 2)
            .collect();
        chokes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        // A group holding a large share of everyone is not a zone.
        let too_big = (population / 5).max(50);
        let mut taken = 0;
        for (v, through) in chokes {
            if taken >= per {
                break;
            }
            let members =
                (self.kind(v) == NodeKind::Group).then(|| self.member_count(v, too_big + 1));
            if members.is_some_and(|m| m > too_big) {
                continue;
            }
            taken += 1;
            items.push(Suggestion {
                node: v,
                heuristic: Heuristic::ChokePoint,
                tier: 1,
                count: through,
                servers: 0,
                workstations: 0,
                users: 0,
                groups: 0,
                other: 0,
                tier_zero_sessions: 0,
                admin_sessions: 0,
                members,
                example: tree.target(v),
            });
        }

        // Control: distinct objects each one holds a control edge over.
        let mut mark = vec![NONE; n];
        let mut control: Vec<Suggestion> = Vec::new();
        for v in 0..n as u32 {
            if !candidate(v) {
                continue;
            }
            let mut s = Suggestion {
                node: v,
                heuristic: Heuristic::Control,
                tier: 1,
                count: 0,
                servers: 0,
                workstations: 0,
                users: 0,
                groups: 0,
                other: 0,
                tier_zero_sessions: 0,
                admin_sessions: 0,
                members: None,
                example: None,
            };
            for e in self.out_edges(v) {
                if !is_control(e.kind)
                    || !self.traversable(e.kind, e.to)
                    || mark[e.to as usize] == v
                {
                    continue;
                }
                mark[e.to as usize] = v;
                s.count += 1;
                match self.kind(e.to) {
                    NodeKind::Computer if self.has(e.to, flag::SERVER) => s.servers += 1,
                    NodeKind::Computer => s.workstations += 1,
                    NodeKind::User => s.users += 1,
                    NodeKind::Group => s.groups += 1,
                    _ => s.other += 1,
                }
                if s.example.is_none() || self.has(e.to, flag::SERVER) {
                    s.example.get_or_insert(e.to);
                }
            }
            if s.count >= 3 {
                if s.workstations > s.servers + s.users + s.groups + s.other {
                    s.tier = 2;
                }
                control.push(s);
            }
        }
        control.sort_by(|a, b| b.count.cmp(&a.count).then(a.node.cmp(&b.node)));
        for mut s in control.into_iter().take(per) {
            if self.kind(s.node) == NodeKind::Group {
                s.members = Some(self.member_count(s.node, 1_000_000));
            }
            items.push(s);
        }

        // Computers privileged accounts log on to.
        let mut sessions: Vec<Suggestion> = Vec::new();
        for c in 0..n as u32 {
            if self.kind(c) != NodeKind::Computer || !candidate(c) {
                continue;
            }
            let (mut t0, mut admin, mut example) = (0, 0, None);
            for e in self.out_edges(c) {
                if e.kind != EdgeKind::HasSession {
                    continue;
                }
                if self.has(e.to, flag::TIER_ZERO) {
                    t0 += 1;
                    example.get_or_insert(e.to);
                } else if self.has(e.to, flag::ADMIN_COUNT) {
                    admin += 1;
                }
            }
            if t0 + admin == 0 {
                continue;
            }
            sessions.push(Suggestion {
                node: c,
                heuristic: Heuristic::PrivilegedSessions,
                tier: 1,
                count: t0 + admin,
                servers: 0,
                workstations: 0,
                users: 0,
                groups: 0,
                other: 0,
                tier_zero_sessions: t0,
                admin_sessions: admin,
                members: None,
                example: example.or_else(|| {
                    self.out_edges(c)
                        .find(|e| {
                            e.kind == EdgeKind::HasSession && self.has(e.to, flag::ADMIN_COUNT)
                        })
                        .map(|e| e.to)
                }),
            });
        }
        sessions.sort_by(|a, b| {
            (b.tier_zero_sessions, b.admin_sessions)
                .cmp(&(a.tier_zero_sessions, a.admin_sessions))
                .then(a.node.cmp(&b.node))
        });
        items.extend(sessions.into_iter().take(per));

        Suggestions {
            exposed,
            population,
            items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::{load, LoadOptions};
    use std::path::PathBuf;

    fn forest() -> AdGraph {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        load(&[dir], &LoadOptions::default()).unwrap().0
    }

    fn explore(g: &AdGraph) -> ExploreGraph {
        ExploreGraph::decode(&encode(g, &[], &[])).unwrap()
    }

    fn ix(g: &AdGraph, name: &str) -> u32 {
        g.find(name)[0].index() as u32
    }

    #[test]
    fn varints_round_trip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v).unwrap();
            assert_eq!(Reader { b: &b, pos: 0 }.varint().unwrap(), v);
        }
        for v in [0i64, -1, 1, -1000, 1 << 40] {
            assert_eq!(unzigzag(zigzag(v)), v);
        }
    }

    #[test]
    fn keeps_every_edge() {
        let g = forest();
        let x = explore(&g);
        assert_eq!(x.node_count(), g.node_count());
        assert_eq!(x.edge_count(), g.edge_count());
        for e in g.inner().edge_references() {
            let found = x
                .edge(
                    e.source().index() as u32,
                    e.target().index() as u32,
                    *e.weight(),
                )
                .expect("edge kept");
            assert_eq!(found.inherited, g.is_inherited(e.id()));
        }
        for (v, n) in g.nodes() {
            let v = v.index() as u32;
            assert_eq!(x.kind(v), n.kind);
            assert_eq!(x.has(v, flag::TIER_ZERO), n.tier_zero);
            assert_eq!(x.tier_zero_reason(v).is_some(), n.tier_zero);
        }
    }

    #[test]
    fn rejects_damaged_data() {
        let g = forest();
        let b = encode(&g, &[], &[]);
        assert!(ExploreGraph::decode(&b[..b.len() / 2]).is_err());
        assert!(ExploreGraph::decode(b"PWEXPL\x09").is_err());
        assert!(ExploreGraph::decode(b"nonsense").is_err());
        let mut bad = b.clone();
        bad[6] = 0xff; // version
        assert!(ExploreGraph::decode(&bad).is_err());
    }

    /// Delta-coded sources that overflow are damage, not a panic.
    #[test]
    fn rejects_overflowing_deltas() {
        let mut b = MAGIC.to_vec();
        b.push(FORMAT_VERSION);
        put_varint(&mut b, 2).unwrap();
        b.extend_from_slice(&[0, 0, 0, 0]);
        put_varint(&mut b, 2).unwrap();
        put_varint(&mut b, zigzag(1)).unwrap();
        b.push(0);
        put_varint(&mut b, zigzag(i64::MAX)).unwrap();
        b.push(0);
        b.extend_from_slice(&[0; 32]);
        assert!(ExploreGraph::decode(&b).is_err());
    }

    /// Edges past what a graph's objects may have are refused before
    /// anything is made for them, whatever the bytes allow; objects past
    /// its bounds too.
    #[test]
    fn an_edge_bomb_is_refused_before_it_is_made() {
        let n = 1_000;
        let budget = edge_budget(n);
        assert_eq!(budget, 256_000 + (1 << 20));
        let err = ExploreGraph::decode(&edge_bomb(n, budget + 1))
            .err()
            .unwrap();
        assert!(err.contains("more edges"), "{err}");
        // Within the budget, only the missing meta is wrong.
        let err = ExploreGraph::decode(&edge_bomb(n, 10)).err().unwrap();
        assert!(!err.contains("more edges"), "{err}");
        let within = |min, max| Bounds {
            min_objects: min,
            max_objects: max,
        };
        let b = edge_bomb(n, 10);
        let more = ExploreGraph::decode_within(&b, within(0, n - 1))
            .err()
            .unwrap();
        assert!(more.contains("more objects"), "{more}");
        let fewer = ExploreGraph::decode_within(&b, within(n + 1, n * 2))
            .err()
            .unwrap();
        assert!(fewer.contains("fewer objects"), "{fewer}");
        assert_eq!(Bounds::of_collected(650_000).max_objects, 1_400_000);
    }

    /// A real graph dense with edges, but within its budget, decodes:
    /// every object an edge to every other, nine tenths of what its
    /// objects may have.
    #[test]
    fn a_dense_graph_within_its_budget_decodes() {
        use crate::model::{EdgeKind, Node, NodeKind};
        let n = 1_100;
        let mut g = AdGraph::new();
        let ix: Vec<NodeIndex> = (0..n)
            .map(|i| {
                let mut node =
                    Node::placeholder(format!("S-1-5-21-7-7-{}", 1000 + i), NodeKind::User);
                node.placeholder = false;
                node.name = format!("U{i}@CONTOSO.LOCAL");
                g.upsert(node)
            })
            .collect();
        g.add_distinct_edges(ix.iter().flat_map(|&a| {
            ix.iter()
                .filter(move |&&b| b != a)
                .map(move |&b| (a, b, EdgeKind::GenericAll))
        }));
        let edges = n * (n - 1);
        assert!(edges > edge_budget(n) * 9 / 10 && edges <= edge_budget(n));
        let bytes = encode(&g, &[], &[]);
        let x = ExploreGraph::decode_within(&bytes, Bounds::of_collected(n)).unwrap();
        assert_eq!(x.node_count(), n);
        assert_eq!(x.edge_count(), edges);
        let (a, b) = (ix[0].index() as u32, ix[n - 1].index() as u32);
        assert_eq!(x.shortest_path(a, &[b]).map(|p| p.len()), Some(1));
    }

    #[test]
    fn shortest_paths_match_the_analysis() {
        let g = forest();
        let x = explore(&g);
        let t0: Vec<u32> = x.tier_zero();
        let tree = x.tier_zero_tree();
        let mut checked = 0;
        for (v, _) in g.nodes() {
            let ours = x.shortest_path(v.index() as u32, &t0);
            let theirs = analysis::path_to_tier_zero(&g, v);
            assert_eq!(ours.is_some(), theirs.is_some(), "{}", g.node(v).name);
            let (Some(ours), Some(theirs)) = (ours, theirs) else {
                continue;
            };
            let names: Vec<(&str, EdgeKind, &str)> = ours
                .iter()
                .map(|e| {
                    (
                        g.node(NodeIndex::new(e.from as usize)).name.as_str(),
                        e.kind,
                        g.node(NodeIndex::new(e.to as usize)).name.as_str(),
                    )
                })
                .collect();
            let want: Vec<(&str, EdgeKind, &str)> = theirs
                .steps
                .iter()
                .map(|s| (s.from.as_str(), s.edge, s.to.as_str()))
                .collect();
            assert_eq!(names, want);
            assert_eq!(tree.path(v.index() as u32).unwrap(), ours);
            checked += 1;
        }
        assert!(checked > 3);
        // Between two objects.
        let (a, b) = (
            ix(&g, "JDOE@CONTOSO.LOCAL"),
            ix(&g, "DOMAIN ADMINS@CONTOSO.LOCAL"),
        );
        let p = x.shortest_path(a, &[b]);
        let q = analysis::shortest_path(&g, NodeIndex::new(a as usize), NodeIndex::new(b as usize));
        assert_eq!(p.map(|p| p.len()), q.map(|q| q.steps.len()));
    }

    /// User -> group -> Tier Zero domain -> another user: the path between
    /// the users ends at the domain, said as "only through Tier Zero".
    #[test]
    fn a_path_between_objects_ends_at_the_first_tier_zero_object() {
        use crate::model::{EdgeKind, Node, NodeKind};
        let mut g = AdGraph::new();
        let mut add = |id: &str, kind: NodeKind, t0: bool| {
            let mut n = Node::placeholder(id.into(), kind);
            n.placeholder = false;
            n.name = format!("{id}@EXAMPLE.LOCAL");
            n.tier_zero = t0;
            g.upsert(n)
        };
        let u = add("S-1-5-21-9-9-1101", NodeKind::User, false);
        let grp = add("S-1-5-21-9-9-1201", NodeKind::Group, false);
        let dom = add("S-1-5-21-9-9", NodeKind::Domain, true);
        let other = add("S-1-5-21-9-9-1102", NodeKind::User, false);
        g.add_edge(u, grp, EdgeKind::MemberOf);
        g.add_edge(grp, dom, EdgeKind::GenericAll);
        g.add_edge(dom, other, EdgeKind::GenericAll);
        let x = explore(&g);
        let i = |n: NodeIndex| n.index() as u32;
        // To the domain: a path. To the user past it: none of its own.
        assert_eq!(x.shortest_path(i(u), &[i(dom)]).map(|p| p.len()), Some(2));
        assert!(x.shortest_path(i(u), &[i(other)]).is_none());
        assert!(x.k_shortest_paths(i(u), &[i(other)], 3).is_empty());
        assert!(analysis::shortest_path(&g, u, other).is_none());
        // Only through Tier Zero: up to the domain, the same both ways.
        let p = x.path_through_tier_zero(i(u), i(other)).unwrap();
        assert_eq!(
            p.iter().map(|e| e.to).collect::<Vec<_>>(),
            vec![i(grp), i(dom)]
        );
        let q = analysis::path_through_tier_zero(&g, u, other).unwrap();
        assert_eq!(q.target, "S-1-5-21-9-9@EXAMPLE.LOCAL");
        assert_eq!(q.steps.len(), 2);
        assert!(x.path_through_tier_zero(i(u), i(dom)).is_none());
        assert_eq!(
            analysis::through_tier_zero_line("C"),
            "C is reached only through Tier Zero."
        );
    }

    #[test]
    fn k_shortest_paths_are_distinct_and_ordered() {
        let g = forest();
        let x = explore(&g);
        let t0 = x.tier_zero();
        let from = ix(&g, "JDOE@CONTOSO.LOCAL");
        let paths = x.k_shortest_paths(from, &t0, 5);
        assert!(!paths.is_empty());
        assert_eq!(paths[0], x.shortest_path(from, &t0).unwrap());
        for w in paths.windows(2) {
            assert!(w[0].len() <= w[1].len());
            assert_ne!(w[0], w[1]);
        }
        for p in &paths {
            assert_eq!(p[0].from, from);
            assert!(x.has(p.last().unwrap().to, flag::TIER_ZERO));
            for pair in p.windows(2) {
                assert_eq!(pair[0].to, pair[1].from);
            }
            // Loop-free.
            let mut seen: Vec<u32> = p.iter().map(|e| e.from).collect();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), p.len());
        }
    }

    #[test]
    fn neighbors_filter_and_cap() {
        let g = forest();
        let x = explore(&g);
        let du = ix(&g, "DOMAIN USERS@CONTOSO.LOCAL");
        let all = x.neighbors(du, Dir::In, &[], 1000);
        assert_eq!(
            all.total,
            g.inner()
                .edges_directed(NodeIndex::new(du as usize), Direction::Incoming)
                .count()
        );
        let members = x.neighbors(du, Dir::In, &[EdgeKind::MemberOf], 1000);
        assert!(members
            .edges
            .iter()
            .all(|e| e.kind == EdgeKind::MemberOf && e.to == du));
        let capped = x.neighbors(du, Dir::In, &[], 2);
        assert_eq!(capped.edges.len(), 2.min(all.total));
        assert_eq!(capped.total, all.total);
        let both = x.neighbors(du, Dir::Both, &[], 10_000);
        assert_eq!(
            both.total,
            all.total + x.neighbors(du, Dir::Out, &[], 10_000).total
        );
    }

    #[test]
    fn reach_lists_unprivileged_first() {
        let g = forest();
        let x = explore(&g);
        // A Tier Zero account with a session on a server.
        let da = ix(&g, "DA_ALICE@CONTOSO.LOCAL");
        let mut list = x.reach(da);
        assert!(!list.is_empty());
        x.sort_reach(&mut list, |v| {
            g.node(NodeIndex::new(v as usize)).name.as_str()
        });
        for w in list.windows(2) {
            assert!((w[0].class, w[0].hops) <= (w[1].class, w[1].hops));
        }
        // Hop counts agree with a direct search, and every first edge is real.
        for r in &list {
            assert_eq!(r.first.from, r.node);
            assert!(x.edge(r.first.from, r.first.to, r.first.kind).is_some());
            if r.class != 3 {
                assert_eq!(
                    x.shortest_path(r.node, &[da]).map(|p| p.len() as u32),
                    Some(r.hops)
                );
            }
        }
        assert!(list.iter().any(|r| r.class == 0));
        assert!(!list.iter().any(|r| r.node == da));
    }

    #[test]
    fn suggestions_are_outside_tier_zero() {
        let g = forest();
        let x = explore(&g);
        let tree = x.tier_zero_tree();
        let s = x.suggestions(&tree, 10);
        assert!(s.exposed > 0 && s.exposed <= s.population);
        assert!(!s.items.is_empty());
        for item in &s.items {
            assert!(!x.has(item.node, flag::TIER_ZERO | flag::BROAD | flag::PLACEHOLDER));
            assert!(item.count > 0);
            assert!(matches!(item.tier, 1 | 2));
        }
        // SRV01 holds a session of a Tier Zero account in the test forest.
        let srv = ix(&g, "SRV01.CONTOSO.LOCAL");
        let sessions: Vec<_> = s
            .items
            .iter()
            .filter(|i| i.heuristic == Heuristic::PrivilegedSessions)
            .collect();
        if x.out_edges(srv)
            .any(|e| e.kind == EdgeKind::HasSession && x.has(e.to, flag::TIER_ZERO))
        {
            assert!(sessions.iter().any(|i| i.node == srv));
        }
    }

    #[test]
    fn findings_keep_their_paths() {
        let opts = LoadOptions::default();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let config = crate::config::Config::default();
        let a = crate::analyze::run(&[dir], &config, &opts.extra_tier_zero, &mut |_| {}).unwrap();
        let x = ExploreGraph::decode(&encode(&a.graph, &a.findings, &a.zones)).unwrap();
        assert_eq!(x.meta.findings.len(), a.findings.len());
        let order = report_order(&a.findings);
        for (f, &i) in x.meta.findings.iter().zip(&order) {
            let orig = &a.findings[i];
            assert_eq!(f.fingerprint, orig.fingerprint);
            if let Some(p) = &orig.path {
                if p.steps.is_empty() {
                    continue;
                }
                assert_eq!(f.path.len(), p.steps.len() + 1, "{}", f.title);
                for (w, step) in f.path.windows(2).zip(&p.steps) {
                    assert!(x.edge(w[0], w[1], step.edge).is_some());
                    assert_eq!(a.graph.node(NodeIndex::new(w[1] as usize)).name, step.to);
                }
            }
            assert!(f.affected.len() <= FINDING_LIST_CAP);
        }
        assert!(x.meta.findings.iter().any(|f| !f.path.is_empty()));
    }

    /// A saved run keeps its forest map; a bare graph has none.
    #[test]
    fn analyses_keep_their_forest_map() {
        let opts = LoadOptions::default();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let config = crate::config::Config::default();
        let a = crate::analyze::run(&[dir], &config, &opts.extra_tier_zero, &mut |_| {}).unwrap();
        let mut bytes = Vec::new();
        encode_analysis_to(&mut bytes, &a).unwrap();
        let x = ExploreGraph::decode(&bytes).unwrap();
        assert_eq!(x.meta.forest, Some(a.forest_map()));
        assert_eq!(x.meta.forest.as_ref().unwrap().trusts.len(), 2);
        // Read past the graph alone, for the Collect page.
        assert_eq!(read_forest(&bytes).unwrap(), Some(a.forest_map()));
        assert!(read_forest(&bytes[..bytes.len() - 3]).is_err());
        assert!(read_forest(b"PWEXPL\x09").is_err());
        let bare_bytes = encode(&a.graph, &a.findings, &a.zones);
        assert_eq!(read_forest(&bare_bytes).unwrap(), None);
        let bare = ExploreGraph::decode(&bare_bytes).unwrap();
        assert_eq!(bare.meta.forest, None);
        // Runs saved before the map was kept still read.
        let old: Meta =
            serde_json::from_str(r#"{"tier_zero_reasons":[],"zones":[],"findings":[]}"#).unwrap();
        assert!(old.forest.is_none());
    }
}
