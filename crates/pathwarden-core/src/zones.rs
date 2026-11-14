//! Privilege Zones: named sets of objects to protect besides Tier Zero, such as
//! Tier 1 servers or the systems holding sensitive data. A zone is defined by
//! explicit objects, groups (with nested members) and OUs (with everything
//! below them, and the GPOs linked to them). Tier Zero objects are never zone members: they already sit
//! above every zone.

use std::collections::{BTreeSet, HashSet, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::analysis;
use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ZoneConfig {
    pub name: String,
    /// Object IDs or names.
    pub members: Vec<String>,
    /// Groups whose (nested) members belong to the zone, as do the groups.
    pub groups: Vec<String>,
    /// OUs (distinguished name or name) whose contents belong to the zone.
    pub ous: Vec<String>,
    /// Keys this version doesn't know (a newer one wrote them): such a zone
    /// is listed but not applied ([`resolve`] leaves it out).
    #[serde(skip)]
    pub unknown_keys: Vec<String>,
}

/// Whether two zone names name the same zone (`--zone`, saves, loading a
/// file): trimmed, in any case, accents included.
pub fn same_name(a: &str, b: &str) -> bool {
    name_key(a) == name_key(b)
}

/// A zone name as [`same_name`] compares it.
pub fn name_key(name: &str) -> String {
    name.trim().to_lowercase()
}

#[derive(Debug, Clone, Serialize)]
pub struct Zone {
    pub name: String,
    #[serde(skip)]
    pub members: Vec<NodeIndex>,
    /// Config entries that matched nothing in the data.
    pub unresolved: Vec<String>,
}

impl Zone {
    pub fn contains(&self, ix: NodeIndex) -> bool {
        self.members.binary_search(&ix).is_ok()
    }

    /// What reaching this zone means: the zone itself, or Tier Zero, which
    /// controls every zone.
    pub fn targets(&self, g: &AdGraph) -> Vec<NodeIndex> {
        let mut t = self.members.clone();
        t.extend(analysis::tier_zero(g));
        t.sort_unstable();
        t.dedup();
        t
    }
}

fn lookup(g: &AdGraph, query: &str) -> Vec<NodeIndex> {
    if let Some(ix) = g.lookup(query) {
        return vec![ix];
    }
    let q = query.trim().to_ascii_uppercase();
    g.nodes()
        .filter(|(_, n)| n.name == q || n.props.distinguishedname.as_deref() == Some(q.as_str()))
        .map(|(ix, _)| ix)
        .collect()
}

fn contents(g: &AdGraph, ou: NodeIndex) -> Vec<NodeIndex> {
    let mut seen = HashSet::from([ou]);
    let mut queue = VecDeque::from([ou]);
    while let Some(v) = queue.pop_front() {
        for e in g.inner().edges_directed(v, Direction::Outgoing) {
            if *e.weight() == EdgeKind::Contains && seen.insert(e.target()) {
                queue.push_back(e.target());
            }
        }
    }
    seen.into_iter().collect()
}

pub fn resolve(g: &AdGraph, configs: &[ZoneConfig]) -> Vec<Zone> {
    configs
        .iter()
        // A newer version's zone: a key this one doesn't know could narrow it.
        .filter(|c| c.unknown_keys.is_empty())
        .map(|c| {
            let mut members = BTreeSet::new();
            let mut unresolved = Vec::new();
            for m in &c.members {
                let found = lookup(g, m);
                if found.is_empty() {
                    unresolved.push(format!("member {m}"));
                }
                members.extend(found);
            }
            for grp in &c.groups {
                let found: Vec<NodeIndex> = lookup(g, grp)
                    .into_iter()
                    .filter(|&ix| g.node(ix).kind == NodeKind::Group)
                    .collect();
                if found.is_empty() {
                    unresolved.push(format!("group {grp}"));
                }
                for ix in found {
                    members.insert(ix);
                    members.extend(g.transitive_members(ix));
                }
            }
            for ou in &c.ous {
                let found: Vec<NodeIndex> = lookup(g, ou)
                    .into_iter()
                    .filter(|&ix| matches!(g.node(ix).kind, NodeKind::Ou | NodeKind::Container))
                    .collect();
                if found.is_empty() {
                    unresolved.push(format!("ou {ou}"));
                }
                for ix in found {
                    members.extend(contents(g, ix));
                }
            }
            // GPOs linked to a zone OU run code on everything below it.
            let linked: Vec<NodeIndex> = members
                .iter()
                .filter(|&&ix| matches!(g.node(ix).kind, NodeKind::Ou | NodeKind::Domain))
                .flat_map(|&ix| {
                    g.inner()
                        .edges_directed(ix, Direction::Incoming)
                        .filter(|e| *e.weight() == EdgeKind::GpLink)
                        .map(|e| e.source())
                        .collect::<Vec<_>>()
                })
                .collect();
            members.extend(linked);
            Zone {
                name: c.name.clone(),
                members: members
                    .into_iter()
                    .filter(|&ix| !g.node(ix).tier_zero)
                    .collect(),
                unresolved,
            }
        })
        .collect()
}

/// What a zone definition resolves to, for checking it while editing.
#[derive(Debug, Clone, Serialize)]
pub struct ZonePreview {
    /// Objects in the zone (Tier Zero excluded, as in the analysis).
    pub total: usize,
    /// Objects per kind, most common first.
    pub kinds: Vec<(&'static str, usize)>,
    /// A sample of member names: groups and OUs first, then the rest.
    pub sample: Vec<String>,
    /// Entries that matched nothing in the data.
    pub unresolved: Vec<String>,
    /// Entries that matched only Tier Zero objects, which are never zone members.
    pub tier_zero: Vec<String>,
    /// Share of all enabled users and computers that are in the zone.
    pub population_percent: f64,
}

/// Members named in a preview: the app's live preview and `pathwarden
/// zones preview` show this many.
pub const PREVIEW_SAMPLE: usize = 12;

impl ZonePreview {
    /// What to check before saving, in words: entries that match nothing
    /// in `source` ("the latest analysis"), entries left out because they
    /// are Tier Zero, and a zone holding most of the domain.
    pub fn warnings(&self, source: &str) -> Vec<String> {
        let mut out = Vec::new();
        for u in &self.unresolved {
            let entry = ["member ", "group ", "ou "]
                .iter()
                .find_map(|p| u.strip_prefix(p))
                .unwrap_or(u);
            out.push(format!(
                "No object in {source} matches {entry}. Check the spelling, or that it was collected."
            ));
        }
        for t in &self.tier_zero {
            out.push(format!(
                "{t} is Tier Zero, so it is left out: Tier Zero already sits above every zone."
            ));
        }
        if self.population_percent > 50.0 {
            out.push(format!(
                "This zone holds {}% of all users and computers. A group in it may nest Domain Users or Domain Computers.",
                self.population_percent.round()
            ));
        }
        out
    }
}

/// Resolves one zone exactly as the analysis does ([`resolve`]) and
/// summarizes the result.
pub fn preview(g: &AdGraph, config: &ZoneConfig, sample: usize) -> ZonePreview {
    let zone = resolve(g, std::slice::from_ref(config))
        .pop()
        .unwrap_or_else(|| Zone {
            name: config.name.clone(),
            members: Vec::new(),
            unresolved: Vec::new(),
        });
    let mut kinds: Vec<(&'static str, usize)> = Vec::new();
    for &ix in &zone.members {
        let k = g.node(ix).kind.as_str();
        match kinds.iter_mut().find(|(n, _)| *n == k) {
            Some((_, c)) => *c += 1,
            None => kinds.push((k, 1)),
        }
    }
    kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let rank = |k: NodeKind| -> u8 {
        match k {
            NodeKind::Group => 0,
            NodeKind::Ou | NodeKind::Container => 1,
            NodeKind::Gpo => 2,
            NodeKind::Computer => 3,
            NodeKind::User => 4,
            _ => 5,
        }
    };
    let mut named: Vec<(u8, &str)> = zone
        .members
        .iter()
        .map(|&ix| (rank(g.node(ix).kind), g.node(ix).name.as_str()))
        .collect();
    named.sort_unstable();
    let tier_zero = config
        .members
        .iter()
        .chain(&config.groups)
        .chain(&config.ous)
        .filter(|q| {
            let found = lookup(g, q);
            !found.is_empty() && found.iter().all(|&ix| g.node(ix).tier_zero)
        })
        .cloned()
        .collect();
    let people = |ix: NodeIndex| {
        let n = g.node(ix);
        matches!(n.kind, NodeKind::User | NodeKind::Computer) && !n.placeholder && n.is_enabled()
    };
    let population = g.nodes().filter(|&(ix, _)| people(ix)).count();
    let inside = zone.members.iter().filter(|&&ix| people(ix)).count();
    ZonePreview {
        total: zone.members.len(),
        kinds,
        sample: named
            .into_iter()
            .take(sample)
            .map(|(_, n)| n.to_string())
            .collect(),
        unresolved: zone.unresolved,
        tier_zero,
        population_percent: if population == 0 {
            0.0
        } else {
            100.0 * inside as f64 / population as f64
        },
    }
}
