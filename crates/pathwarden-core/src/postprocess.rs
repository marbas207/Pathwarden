//! Edges that collectors do not emit directly but that the analysis depends on.

use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::sid;

pub fn run(g: &mut AdGraph) {
    use crate::timing::phase;
    phase("  name placeholders", || name_placeholders(g));
    phase("  implicit memberships", || implicit_memberships(g));
    phase("  dcsync", || dcsync(g));
    phase("  coerce to tgt", || coerce_to_tgt(g));
    phase("  ad cs", || crate::adcs::run(g));
    phase("  management planes", || crate::mgmt::add_edges(g));
    // Last: the hybrid links need the AD edges above (DCSync, for the
    // Entra Connect account).
    phase("  entra", || crate::entra::derive(g));
}

/// A non-DC with unconstrained delegation caches the TGT of anything that
/// authenticates to it. Coercing a DC to authenticate (PrinterBug, PetitPotam)
/// hands over the DC's TGT, so controlling that host means controlling the domain.
fn coerce_to_tgt(g: &mut AdGraph) {
    let domains: HashMap<String, NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain)
        .map(|(ix, n)| (n.id.clone(), ix))
        .collect();
    let edges: Vec<(NodeIndex, NodeIndex)> = g
        .nodes()
        .filter(|(_, n)| {
            matches!(n.kind, NodeKind::Computer | NodeKind::User)
                && !n.is_dc
                && n.is_enabled()
                && n.props.unconstraineddelegation == Some(true)
        })
        .filter_map(|(ix, n)| Some((ix, *domains.get(n.domain_sid.as_ref()?)?)))
        .collect();
    for (from, domain) in edges {
        g.add_edge(from, domain, EdgeKind::CoerceToTgt);
    }
}

/// `DOMAIN COMPUTERS@S-1-5-21-...` reads better as `DOMAIN COMPUTERS@CONTOSO.LOCAL`.
fn name_placeholders(g: &mut AdGraph) {
    let domains: HashMap<String, String> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain && !n.placeholder)
        .map(|(_, n)| (n.id.clone(), n.name.clone()))
        .collect();
    let renames: Vec<(NodeIndex, String, String)> = g
        .nodes()
        .filter(|(_, n)| n.placeholder && sid::split_prefixed(&n.id).0.is_none())
        .filter_map(|(ix, n)| {
            let wk = sid::well_known_name(&n.id)?;
            let domain = domains.get(n.domain_sid.as_ref()?)?;
            Some((ix, format!("{wk}@{domain}"), domain.clone()))
        })
        .collect();
    for (ix, name, domain) in renames {
        let n = g.node_mut(ix);
        n.name = name;
        n.domain = Some(domain);
    }
}

/// Everyone and Authenticated Users contain every principal in the forest, but
/// collectors never list those members. Without these edges, ACEs granted to
/// them (a very common misconfiguration) would be invisible.
fn implicit_memberships(g: &mut AdGraph) {
    let forest_of = forest_components(g);
    let key = |domain: &str| match forest_of.get(domain) {
        Some(forest) => format!("forest:{forest}"),
        None => format!("domain:{domain}"),
    };

    let mut principals: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    for (ix, n) in g.nodes() {
        if matches!(n.kind, NodeKind::User | NodeKind::Computer) && !n.placeholder {
            if let Some(d) = &n.domain {
                principals.entry(key(d)).or_default().push(ix);
            }
        }
    }
    let groups: Vec<(NodeIndex, String)> = g
        .nodes()
        .filter(|(_, n)| sid::is_implicit_group(&n.id))
        .filter_map(|(ix, n)| Some((ix, key(sid::split_prefixed(&n.id).0?))))
        .collect();
    for (group, k) in groups {
        for &member in principals.get(&k).into_iter().flatten() {
            g.add_edge(member, group, EdgeKind::MemberOf);
        }
    }
}

/// Maps each domain name to a forest id, using same-forest trusts.
pub(crate) fn forest_components(g: &AdGraph) -> HashMap<String, usize> {
    let mut comp: HashMap<NodeIndex, usize> = HashMap::new();
    let domains: Vec<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain)
        .map(|(ix, _)| ix)
        .collect();
    for (forest, &start) in domains.iter().enumerate() {
        if comp.contains_key(&start) {
            continue;
        }
        let mut stack = vec![start];
        comp.insert(start, forest);
        while let Some(v) = stack.pop() {
            for e in g.inner().edges_directed(v, Direction::Outgoing) {
                if *e.weight() == EdgeKind::SameForestTrust && !comp.contains_key(&e.target()) {
                    comp.insert(e.target(), forest);
                    stack.push(e.target());
                }
            }
        }
    }
    comp.into_iter()
        .map(|(ix, f)| (g.node(ix).name.clone(), f))
        .collect()
}

/// DCSync needs both GetChanges and GetChangesAll; either can arrive through
/// (nested) group membership, so a split grant is still a full DCSync.
fn dcsync(g: &mut AdGraph) {
    let domains: Vec<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain)
        .map(|(ix, _)| ix)
        .collect();
    let mut edges = Vec::new();
    for d in domains {
        let changes = effective_holders(g, d, EdgeKind::GetChanges);
        let changes_all = effective_holders(g, d, EdgeKind::GetChangesAll);
        let both: HashSet<NodeIndex> = changes.intersection(&changes_all).copied().collect();
        // Only the outermost holders get the edge: when a group can DCSync,
        // its members reach the domain through MemberOf. One edge per member
        // would turn one fix (the group's grant) into one per member.
        edges.extend(
            both.iter()
                .copied()
                .filter(|&p| {
                    !g.inner()
                        .edges_directed(p, Direction::Outgoing)
                        .any(|e| *e.weight() == EdgeKind::MemberOf && both.contains(&e.target()))
                })
                .map(|p| (p, d)),
        );
    }
    for (p, d) in edges {
        g.add_edge(p, d, EdgeKind::DcSync);
    }
}

fn effective_holders(g: &AdGraph, target: NodeIndex, right: EdgeKind) -> HashSet<NodeIndex> {
    let mut out = HashSet::new();
    for e in g.inner().edges_directed(target, Direction::Incoming) {
        if *e.weight() == right {
            out.insert(e.source());
            out.extend(g.transitive_members(e.source()));
        }
    }
    out
}
