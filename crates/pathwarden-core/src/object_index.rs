//! A compact copy of a run's objects: what the local UI needs to search for
//! objects and preview Privilege Zones after the collector files are gone.
//!
//! It keeps every object's ID, name, kind, domain, distinguished name and
//! Tier Zero flag, plus the three relations zone resolution follows
//! (`MemberOf`, `Contains`, `GPLink`). [`ObjectIndex::to_graph`] turns it back
//! into an [`AdGraph`] so previews run the real [`crate::zones::resolve`],
//! not a copy of it.
//!
//! As JSON, objects are arrays (`[id, name, kind, domain, dn, flags]`) and
//! relations flat lists of index pairs, so a large directory stays small.

use serde::{Deserialize, Serialize};

use crate::graph::AdGraph;
use crate::model::{EdgeKind, Node, NodeKind, Props};
use crate::{sid, NodeIndex};

pub const INDEX_VERSION: u32 = 1;

const TIER_ZERO: u8 = 1;
const PLACEHOLDER: u8 = 2;
const DC: u8 = 4;
const DISABLED: u8 = 8;

/// One object: `(id, name, kind, domain, distinguished name, flags)`.
/// `kind` indexes [`NodeKind::ALL`]; `domain` indexes
/// [`ObjectIndex::domains`] (-1 for none); `dn` is empty when unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedObject(pub String, pub String, pub u8, pub i32, pub String, pub u8);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectIndex {
    pub version: u32,
    pub domains: Vec<String>,
    pub objects: Vec<IndexedObject>,
    /// `[member, group, member, group, ...]`
    pub member_of: Vec<u32>,
    /// `[parent, child, ...]`
    pub contains: Vec<u32>,
    /// `[gpo, linked OU or domain, ...]`
    pub gp_link: Vec<u32>,
}

fn kind_code(k: NodeKind) -> u8 {
    // External (OpenGraph) kinds are kept as Base here: the index serves
    // search and zone previews, which only need AD kinds.
    let k = if k.is_external() { NodeKind::Base } else { k };
    NodeKind::ALL.iter().position(|&x| x == k).unwrap_or(0) as u8
}

fn kind_of(code: u8) -> NodeKind {
    NodeKind::ALL
        .get(code as usize)
        .copied()
        .unwrap_or(NodeKind::Base)
}

impl ObjectIndex {
    pub fn from_graph(g: &AdGraph) -> Self {
        let mut domains: Vec<String> = g.nodes().filter_map(|(_, n)| n.domain.clone()).collect();
        domains.sort();
        domains.dedup();
        let objects = g
            .nodes()
            .map(|(_, n)| {
                let domain = n
                    .domain
                    .as_ref()
                    .and_then(|d| domains.binary_search(d).ok())
                    .map_or(-1, |i| i as i32);
                let mut flags = 0;
                if n.tier_zero {
                    flags |= TIER_ZERO;
                }
                if n.placeholder {
                    flags |= PLACEHOLDER;
                }
                if n.is_dc {
                    flags |= DC;
                }
                if !n.is_enabled() {
                    flags |= DISABLED;
                }
                IndexedObject(
                    n.id.clone(),
                    n.name.clone(),
                    kind_code(n.kind),
                    domain,
                    n.props.distinguishedname.clone().unwrap_or_default(),
                    flags,
                )
            })
            .collect();
        let mut index = ObjectIndex {
            version: INDEX_VERSION,
            domains,
            objects,
            ..Default::default()
        };
        for e in g.inner().edge_indices() {
            let Some((a, b)) = g.inner().edge_endpoints(e) else {
                continue;
            };
            let list = match g.inner()[e] {
                EdgeKind::MemberOf => &mut index.member_of,
                EdgeKind::Contains => &mut index.contains,
                EdgeKind::GpLink => &mut index.gp_link,
                _ => continue,
            };
            list.extend([a.index() as u32, b.index() as u32]);
        }
        index
    }

    /// The objects and relations as a graph, with node indexes equal to
    /// positions in [`ObjectIndex::objects`].
    pub fn to_graph(&self) -> AdGraph {
        self.clone().into_graph()
    }

    /// [`ObjectIndex::to_graph`], moving the strings instead of copying
    /// them. A large directory's index has millions of them: the graph is
    /// built at its final size, and each object becomes its node directly.
    pub fn into_graph(self) -> AdGraph {
        let edges = (self.member_of.len() + self.contains.len() + self.gp_link.len()) / 2;
        let mut g = AdGraph::with_capacity(self.objects.len(), edges);
        for IndexedObject(id, name, kind, domain, dn, flags) in self.objects {
            // As `Node::placeholder` makes it, with what the index kept.
            g.upsert(Node {
                domain_sid: sid::domain_sid_of(&id),
                id,
                kind: kind_of(kind),
                name,
                domain: usize::try_from(domain)
                    .ok()
                    .and_then(|d| self.domains.get(d).cloned()),
                is_dc: flags & DC != 0,
                placeholder: flags & PLACEHOLDER != 0,
                tier_zero: flags & TIER_ZERO != 0,
                tier_zero_reason: None,
                props: Props {
                    enabled: (flags & DISABLED != 0).then_some(false),
                    distinguishedname: (!dn.is_empty()).then_some(dn),
                    ..Props::default()
                },
                adcs: None,
                ext: None,
            });
        }
        // Positions past the objects are left out (an object listed twice
        // has one node).
        let n = g.node_count() as u32;
        let lists = [
            (&self.member_of, EdgeKind::MemberOf),
            (&self.contains, EdgeKind::Contains),
            (&self.gp_link, EdgeKind::GpLink),
        ];
        // The index of a graph has each edge once: then no edge needs the
        // check `add_edge` makes, which is most of the time edges take.
        if lists.iter().all(|(list, _)| distinct(list, n)) {
            for (list, kind) in lists {
                g.add_distinct_edges(pairs(list, n).map(|(a, b)| (a, b, kind)));
            }
        } else {
            for (list, kind) in lists {
                for (a, b) in pairs(list, n) {
                    g.add_edge(a, b, kind);
                }
            }
        }
        g
    }
}

/// The pairs in `list` of objects below `n`.
fn pairs(list: &[u32], n: u32) -> impl Iterator<Item = (NodeIndex, NodeIndex)> + '_ {
    list.as_chunks::<2>()
        .0
        .iter()
        .filter(move |p| p[0] < n && p[1] < n)
        .map(|p| (NodeIndex::new(p[0] as usize), NodeIndex::new(p[1] as usize)))
}

/// Whether the pairs in `list` are each two objects below `n`, different,
/// and none is there twice.
fn distinct(list: &[u32], n: u32) -> bool {
    let mut keys = Vec::with_capacity(list.len() / 2);
    for p in list.as_chunks::<2>().0 {
        if p[0] >= n || p[1] >= n || p[0] == p[1] {
            return false;
        }
        keys.push(u64::from(p[0]) << 32 | u64::from(p[1]));
    }
    keys.sort_unstable();
    keys.windows(2).all(|w| w[0] != w[1])
}

/// Collected objects whose name, distinguished name or ID matches `query`
/// (case-insensitive), best first: exact matches, then names starting with
/// it, then names containing it, then distinguished names containing it.
/// Only `kinds` are searched when given. At most `limit` results.
pub fn search(g: &AdGraph, query: &str, kinds: &[NodeKind], limit: usize) -> Vec<NodeIndex> {
    let q = query.trim().to_ascii_uppercase();
    if q.is_empty() || limit == 0 {
        return Vec::new();
    }
    let mut hits: Vec<(u8, usize, NodeIndex)> = g
        .nodes()
        .filter(|(_, n)| !n.placeholder && (kinds.is_empty() || kinds.contains(&n.kind)))
        .filter_map(|(ix, n)| {
            let dn = n.props.distinguishedname.as_deref().unwrap_or_default();
            let rank = if n.name == q || n.id == q || dn == q {
                0
            } else if n.name.starts_with(&q) {
                1
            } else if n.name.contains(&q) {
                2
            } else if dn.contains(&q) {
                3
            } else {
                return None;
            };
            Some((rank, n.name.len(), ix))
        })
        .collect();
    let order = |a: &(u8, usize, NodeIndex), b: &(u8, usize, NodeIndex)| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then_with(|| g.node(a.2).name.cmp(&g.node(b.2).name))
    };
    if hits.len() > limit {
        hits.select_nth_unstable_by(limit - 1, order);
        hits.truncate(limit);
    }
    hits.sort_unstable_by(order);
    hits.into_iter().map(|(_, _, ix)| ix).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load, LoadOptions};
    use std::path::PathBuf;

    fn forest() -> AdGraph {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        load(&[dir], &LoadOptions::default()).unwrap().0
    }

    #[test]
    fn round_trips_through_json() {
        let g = forest();
        let index = ObjectIndex::from_graph(&g);
        let json = serde_json::to_string(&index).unwrap();
        let back: ObjectIndex = serde_json::from_str(&json).unwrap();
        let h = back.to_graph();
        assert_eq!(h.node_count(), g.node_count());
        for (ix, n) in g.nodes() {
            let m = h.node(ix);
            assert_eq!(
                (
                    &m.id,
                    &m.name,
                    m.kind,
                    m.tier_zero,
                    &m.props.distinguishedname
                ),
                (
                    &n.id,
                    &n.name,
                    n.kind,
                    n.tier_zero,
                    &n.props.distinguishedname
                )
            );
        }
        let count =
            |g: &AdGraph, k: EdgeKind| g.inner().edge_weights().filter(|&&e| e == k).count();
        for k in [EdgeKind::MemberOf, EdgeKind::Contains, EdgeKind::GpLink] {
            assert_eq!(count(&h, k), count(&g, k), "{k:?}");
        }
    }

    /// The graph as `to_graph` built it before it was made fast: each
    /// object upserted onto a placeholder, each edge through `add_edge`.
    fn upserted(index: &ObjectIndex) -> AdGraph {
        let mut g = AdGraph::new();
        for IndexedObject(id, name, kind, domain, dn, flags) in &index.objects {
            let mut node = Node::placeholder(id.clone(), kind_of(*kind));
            node.name = name.clone();
            node.domain = usize::try_from(*domain)
                .ok()
                .and_then(|d| index.domains.get(d).cloned());
            node.placeholder = flags & PLACEHOLDER != 0;
            node.tier_zero = flags & TIER_ZERO != 0;
            node.is_dc = flags & DC != 0;
            node.props.enabled = (flags & DISABLED != 0).then_some(false);
            node.props.distinguishedname = (!dn.is_empty()).then(|| dn.clone());
            g.upsert(node);
        }
        let n = index.objects.len() as u32;
        for (list, kind) in [
            (&index.member_of, EdgeKind::MemberOf),
            (&index.contains, EdgeKind::Contains),
            (&index.gp_link, EdgeKind::GpLink),
        ] {
            for pair in list.as_chunks::<2>().0 {
                if pair[0] < n && pair[1] < n {
                    g.add_edge(
                        NodeIndex::new(pair[0] as usize),
                        NodeIndex::new(pair[1] as usize),
                        kind,
                    );
                }
            }
        }
        g
    }

    /// Every node (all its fields) and every edge, in order.
    fn dump(g: &AdGraph) -> (Vec<String>, Vec<(usize, usize, EdgeKind)>) {
        let nodes = g.nodes().map(|(_, n)| format!("{n:?}")).collect();
        let edges = g
            .inner()
            .edge_indices()
            .map(|e| {
                let (a, b) = g.inner().edge_endpoints(e).unwrap();
                (a.index(), b.index(), g.inner()[e])
            })
            .collect();
        (nodes, edges)
    }

    #[test]
    fn fast_graph_equals_upserting_one() {
        let index = ObjectIndex::from_graph(&forest());
        let reference = upserted(&index);
        assert_eq!(dump(&index.to_graph()), dump(&reference));
        let mut fast = index.into_graph();
        assert_eq!(dump(&fast), dump(&reference));
        // The ID index and the edge check work as on a graph built one by one.
        let b = NodeIndex::new(1);
        assert_eq!(fast.lookup(&reference.node(b).id), Some(b));
        let first = reference.inner().edge_indices().next().unwrap();
        let (x, y) = reference.inner().edge_endpoints(first).unwrap();
        assert!(!fast.add_edge(x, y, reference.inner()[first]));
        assert!(!fast.add_edge(x, x, EdgeKind::MemberOf));
        assert!(fast.add_edge(y, x, EdgeKind::GenericAll));
        assert!(!fast.add_edge(y, x, EdgeKind::GenericAll));
        assert_eq!(fast.edge_count(), reference.edge_count() + 1);
    }

    #[test]
    fn a_damaged_index_makes_the_same_graph_too() {
        let mut index = ObjectIndex::from_graph(&forest());
        // What Pathwarden never writes: repeated and self edges, positions
        // past the end, and an object listed twice (the first copy is kept).
        let m = index.member_of.clone();
        index.member_of.extend_from_slice(&m[..m.len().min(8)]);
        index.member_of.extend([0, 0, 1, 1]);
        index
            .contains
            .extend([3, 1, 3, 1, u32::MAX, 0, 0, 1_000_000]);
        index.gp_link.extend([2, 3, 2, 3]);
        let mut twice = index.objects[0].clone();
        twice.1 = "SECOND COPY".into();
        index.objects.push(twice);
        let reference = upserted(&index);
        assert_eq!(dump(&index.to_graph()), dump(&reference));
        assert_eq!(dump(&index.into_graph()), dump(&reference));
        // Each check on its own, too.
        assert!(distinct(&[0, 1, 1, 0, 2, 1], 3));
        assert!(!distinct(&[0, 1, 2, 1, 0, 1], 3));
        assert!(!distinct(&[0, 1, 2, 2], 3));
        assert!(!distinct(&[0, 1, 2, 3], 3));
    }

    #[test]
    fn search_ranks_and_caps() {
        let g = forest();
        let hits = search(&g, "jdoe", &[], 20);
        assert_eq!(g.node(hits[0]).name, "JDOE@CONTOSO.LOCAL");
        let all = search(&g, "contoso", &[], 3);
        assert_eq!(all.len(), 3);
        let groups = search(&g, "contoso", &[NodeKind::Group], 1000);
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|&ix| g.node(ix).kind == NodeKind::Group));
        assert!(search(&g, "   ", &[], 20).is_empty());
    }
}
