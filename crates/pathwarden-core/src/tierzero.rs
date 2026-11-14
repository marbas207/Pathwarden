//! Tier Zero: objects whose compromise means compromise of the domain or forest.
//! Every attack path analysis is "who outside Tier Zero can reach it".

use std::collections::VecDeque;

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::AdGraph;
use crate::model::{EdgeKind, Node, NodeKind};
use crate::{mgmt, sid};

/// Marks Tier Zero objects. `extra` holds object IDs or names the organization
/// also treats as Tier Zero (PAM servers, backup systems, Entra Connect, ...).
///
/// OpenGraph data never makes anything Tier Zero (the one exception is the
/// Entra side of AzureHound data, see [`crate::entra`]): objects only an OpenGraph
/// file has are Tier Zero only when configured, and edges an OpenGraph file
/// added (even native kinds a pack accepts) don't propagate it.
pub fn mark(g: &mut AdGraph, extra: &[String]) {
    mark_with(g, extra, &[]);
}

/// The configured Tier Zero entries (IDs or names, as [`mark`] matches them)
/// that match no object in the graph: usually a typo, which would otherwise
/// leave Tier Zero silently unchanged.
pub fn unmatched(g: &AdGraph, extra: &[String]) -> Vec<String> {
    extra
        .iter()
        .filter(|e| {
            let e = e.trim().to_ascii_uppercase();
            !g.nodes().any(|(_, n)| n.id == e || n.name == e)
        })
        .cloned()
        .collect()
}

/// [`mark`], except that the management planes named in `not_planes` (IDs
/// or names) are not made Tier Zero: systems the organization has checked
/// and found not to manage Tier Zero after all.
pub fn mark_with(g: &mut AdGraph, extra: &[String], not_planes: &[String]) {
    let upper = |list: &[String]| -> Vec<String> {
        list.iter().map(|e| e.trim().to_ascii_uppercase()).collect()
    };
    let extra = upper(extra);
    let not_planes = upper(not_planes);
    let seeds: Vec<(NodeIndex, String)> = g
        .nodes()
        .filter_map(|(ix, n)| Some((ix, seed_reason(n, &extra)?)))
        .collect();
    for (ix, reason) in seeds {
        set(g, ix, reason);
    }

    // Whoever controls a CA's server holds its private key and can forge any
    // certificate (golden certificate).
    let ca_hosts: Vec<(NodeIndex, String)> = g
        .inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::HostsCaService && !g.node(e.source()).tier_zero)
        .filter(|e| g.edge_origin(e.id()).is_none())
        .map(|e| {
            (
                e.source(),
                format!("Hosts Enterprise CA {}", g.node(e.target()).name),
            )
        })
        .collect();
    for (ix, reason) in ca_hosts {
        set(g, ix, reason);
    }

    // Management planes: systems that control Tier Zero from outside the
    // directory's permissions (Entra Connect, Seamless SSO, the SCOM server
    // of a DC, ...), then anything else that manages a Tier Zero host.
    let excluded = |n: &Node| not_planes.iter().any(|e| *e == n.id || *e == n.name);
    // A group that administers management servers (ADSyncAdmins) is Tier
    // Zero only while one of those servers is, so it waits for them.
    let (groups, detections): (Vec<mgmt::Detection>, Vec<mgmt::Detection>) = mgmt::detect(g)
        .into_iter()
        .filter(|d| d.tier_zero.is_some())
        .partition(|d| d.role == mgmt::Role::Group && !d.manages.is_empty());
    let mut planes: Vec<(NodeIndex, String)> = detections
        .into_iter()
        .filter_map(|d| Some((d.object, d.tier_zero?)))
        .collect();
    planes.extend(
        g.inner()
            .edge_references()
            .filter(|e| *e.weight() == EdgeKind::ManagesHost && g.node(e.target()).tier_zero)
            .filter(|e| g.edge_origin(e.id()).is_none())
            .map(|e| {
                (
                    e.source(),
                    format!("manages Tier Zero host {}", g.node(e.target()).name),
                )
            }),
    );
    for (ix, reason) in planes {
        let n = g.node(ix);
        if !n.tier_zero && !n.og_created() && !excluded(n) {
            set(g, ix, format!("{}{reason}", mgmt::REASON_PREFIX));
        }
    }
    for d in groups {
        let n = g.node(d.object);
        if n.tier_zero || n.og_created() || excluded(n) {
            continue;
        }
        if d.manages.iter().any(|&s| g.node(s).tier_zero) {
            let reason = d.tier_zero.unwrap_or_default();
            set(g, d.object, format!("{}{reason}", mgmt::REASON_PREFIX));
        }
    }

    // Group Policy linked to a Tier Zero domain or OU applies code to Tier Zero.
    let gpos: Vec<(NodeIndex, String)> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Gpo && !n.tier_zero)
        .filter_map(|(ix, _)| {
            g.inner()
                .edges_directed(ix, Direction::Outgoing)
                .find(|e| {
                    *e.weight() == EdgeKind::GpLink
                        && g.node(e.target()).tier_zero
                        && g.edge_origin(e.id()).is_none()
                })
                .map(|e| {
                    (
                        ix,
                        format!("GPO linked to Tier Zero {}", g.node(e.target()).name),
                    )
                })
        })
        .collect();
    for (ix, reason) in gpos {
        set(g, ix, reason);
    }

    // Entra ID: the tenant, the Tier Zero roles and their holders (AzureHound
    // data; never an AD object).
    crate::entra::mark_tier_zero(g);

    // Members of Tier Zero groups are Tier Zero, however deeply nested. Broad
    // groups (Domain Users, Authenticated Users, ...) are the exception: if one is
    // nested into Tier Zero, that is the finding, not a reason to call every user
    // Tier Zero and hide the exposure.
    let mut queue: VecDeque<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.tier_zero)
        .map(|(ix, _)| ix)
        .collect();
    while let Some(v) = queue.pop_front() {
        let group = g.node(v).name.clone();
        let members: Vec<NodeIndex> = g
            .inner()
            .edges_directed(v, Direction::Incoming)
            .filter(|e| *e.weight() == EdgeKind::MemberOf && !g.node(e.source()).tier_zero)
            .filter(|e| g.edge_origin(e.id()).is_none())
            .filter(|e| !sid::is_broad_group(&g.node(e.source()).id))
            .map(|e| e.source())
            .collect();
        for m in members {
            if !g.node(m).tier_zero {
                set(g, m, format!("Member of {group}"));
                queue.push_back(m);
            }
        }
    }
}

fn seed_reason(n: &Node, extra: &[String]) -> Option<String> {
    let configured = || {
        extra
            .iter()
            .any(|e| *e == n.id || *e == n.name)
            .then(|| "Configured as Tier Zero".to_string())
    };
    if n.og_created() {
        return configured();
    }
    let reason = match n.kind {
        NodeKind::Domain => Some("Domain object".to_string()),
        NodeKind::EnterpriseCa | NodeKind::RootCa | NodeKind::AiaCa | NodeKind::NtAuthStore => {
            Some("AD CS trust anchor".to_string())
        }
        NodeKind::Computer if n.is_dc => Some("Domain controller".to_string()),
        NodeKind::Ou if n.name.starts_with("DOMAIN CONTROLLERS@") => {
            Some("Domain Controllers OU".to_string())
        }
        NodeKind::Container
            if n.props
                .distinguishedname
                .as_deref()
                .is_some_and(|dn| dn.starts_with("CN=ADMINSDHOLDER,CN=SYSTEM,")) =>
        {
            Some("AdminSDHolder".to_string())
        }
        _ => sid::tier_zero_reason(&n.id).map(str::to_string),
    };
    reason.or_else(configured)
}

fn set(g: &mut AdGraph, ix: NodeIndex, reason: String) {
    let n = g.node_mut(ix);
    n.tier_zero = true;
    n.tier_zero_reason = Some(reason);
}
