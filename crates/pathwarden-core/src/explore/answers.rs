//! What Explore answers, shared by the app's Explore page and the CLI
//! (`pathwarden reach`, `pathwarden search`, `pathwarden zones suggest`):
//! the same objects, in the same order, in the same words.
//!
//! [`Explorer`] pairs a run's graph ([`AdGraph`], for names) with its
//! [`ExploreGraph`] (for edges and flags); both number objects alike. The
//! answers serialize to the JSON the app's API returns, so `--json` prints
//! the same document.

use serde::Serialize;

use super::{flag, Edge, ExploreGraph, Heuristic, PathTree, Reacher, Suggestion};
use crate::graph::AdGraph;
use crate::model::{Node, NodeKind};
use crate::text::{count, num};
use crate::zones::Zone;
use petgraph::graph::NodeIndex;

/// Plain-words names of [`ExploreGraph::reach_class`], by class.
pub const REACH_CLASSES: [&str; 4] = [
    "Unprivileged users and computers",
    "Groups and other objects",
    "Disabled or not collected",
    "Tier Zero",
];

/// Suggestions listed for each [`Heuristic`].
pub const SUGGESTIONS_PER_KIND: usize = 12;

fn is_false(b: &bool) -> bool {
    !*b
}

/// One object, as Explore lists it.
#[derive(Debug, Clone, Serialize)]
pub struct NodeOut<'a> {
    pub ix: u32,
    pub id: &'a str,
    pub name: &'a str,
    pub kind: &'static str,
    pub domain: Option<&'a str>,
    #[serde(skip_serializing_if = "is_false")]
    pub t0: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub dc: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub ph: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub server: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub zone: bool,
}

impl<'a> NodeOut<'a> {
    fn new(ix: u32, n: &'a Node, kind: NodeKind, f: u8, zone: bool) -> Self {
        NodeOut {
            ix,
            id: &n.id,
            name: &n.name,
            kind: kind.as_str(),
            domain: n.domain.as_deref(),
            t0: f & flag::TIER_ZERO != 0,
            dc: f & flag::DC != 0,
            disabled: f & flag::DISABLED != 0,
            ph: f & flag::PLACEHOLDER != 0,
            server: f & flag::SERVER != 0,
            zone,
        }
    }
}

/// [`Explorer::search`] on the data's graph alone, without building its
/// explore graph: the flags come from the objects themselves, as the
/// explore graph takes them. For `pathwarden search`.
pub fn search_graph<'a>(
    g: &'a AdGraph,
    zones: &[Zone],
    query: &str,
    kinds: &[NodeKind],
    limit: usize,
) -> Vec<NodeOut<'a>> {
    let mut seen = std::collections::HashSet::new();
    crate::object_index::search(g, query, kinds, limit)
        .into_iter()
        .filter(|ix| seen.insert(*ix))
        .map(|ix| {
            let n = g.node(ix);
            let zone = zones.iter().any(|z| z.members.contains(&ix));
            NodeOut::new(ix.index() as u32, n, n.kind, super::node_flags(n), zone)
        })
        .collect()
}

/// One edge, as Explore draws it.
#[derive(Debug, Clone, Serialize)]
pub struct EdgeOut {
    pub s: u32,
    pub t: u32,
    pub k: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    pub inh: bool,
    /// Not an attack step (kept for context, e.g. Enroll).
    #[serde(skip_serializing_if = "is_false")]
    pub weak: bool,
}

/// One object that can reach the object asked about.
#[derive(Debug, Clone, Serialize)]
pub struct ReachItem<'a> {
    pub node: NodeOut<'a>,
    pub hops: u32,
    /// [`ExploreGraph::reach_class`]; its name is [`REACH_CLASSES`].
    pub class: u8,
    /// The first edge of its shortest route.
    pub first: EdgeOut,
    /// Where that edge leads.
    pub via: NodeOut<'a>,
}

/// "Who can reach this": one page of the sorted list.
#[derive(Debug, Clone, Serialize)]
pub struct ReachAnswer<'a> {
    pub target: NodeOut<'a>,
    /// Everything that can reach it.
    pub total: usize,
    /// Of those, in the class asked for (all without one).
    pub filtered: usize,
    /// How many of each class ([`REACH_CLASSES`]).
    pub classes: [usize; 4],
    pub class_names: [&'static str; 4],
    pub offset: usize,
    pub items: Vec<ReachItem<'a>>,
    /// [`reach_summary`].
    pub summary: String,
}

/// The line under "Who can reach ...".
pub fn reach_summary(total: usize) -> String {
    if total == 0 {
        return "Nothing has an attack path to it.".into();
    }
    format!(
        "{} an attack path to it. Unprivileged users and computers come first: they are where an attacker starts. Attack paths stop at Tier Zero objects.",
        count(total, "object has", "objects have")
    )
}

/// A [`Heuristic`] with its heading and what it means.
#[derive(Debug, Clone, Serialize)]
pub struct HeuristicOut {
    pub key: Heuristic,
    pub title: &'static str,
    pub about: &'static str,
}

impl Heuristic {
    /// In the order the suggestions are listed.
    pub const ALL: [Heuristic; 3] = [
        Heuristic::ChokePoint,
        Heuristic::Control,
        Heuristic::PrivilegedSessions,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Heuristic::ChokePoint => "Objects many paths cross",
            Heuristic::Control => "Control over many objects",
            Heuristic::PrivilegedSessions => "Privileged logons",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Heuristic::ChokePoint => "Objects outside Tier Zero that many exposed users' and computers' paths run through. Protecting them like Tier 1 cuts the most routes.",
            Heuristic::Control => "Admin or control rights over many computers, groups or users. Whoever holds this holds all of them.",
            Heuristic::PrivilegedSessions => "Computers where Tier Zero or other privileged accounts log on. Their credentials can be taken from there.",
        }
    }
}

/// One suggested zone member.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionOut<'a> {
    pub node: NodeOut<'a>,
    pub heuristic: Heuristic,
    /// 1 or 2 ([`Suggestion::tier`]).
    pub tier: u8,
    pub count: usize,
    /// Why, in plain words ([`Explorer::reason`]).
    pub reason: String,
    /// How a zone takes it: `group`, `ou` or `member` ([`adds_as`]).
    pub adds_as: &'static str,
    /// Zones it is in already.
    pub zones: Vec<&'a str>,
}

/// Suggested zones.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionsAnswer<'a> {
    /// Users and computers that can reach Tier Zero.
    pub exposed: usize,
    pub population: usize,
    /// The exposure denominator ([`crate::posture::ZonePosture`]).
    pub relevant_population: usize,
    /// [`suggestions_intro`].
    pub intro: String,
    pub heuristics: Vec<HeuristicOut>,
    pub items: Vec<SuggestionOut<'a>>,
    /// The zones the run has.
    pub zones: Vec<&'a str>,
}

/// The line under "Suggested zones".
pub fn suggestions_intro(exposed: usize, relevant_population: usize) -> String {
    format!(
        "Candidates for Tier 1 (servers and anything close to Tier Zero) or Tier 2 (workstations) zones, from the data's graph. {} of {} active users and computers can reach Tier Zero.",
        num(exposed),
        num(relevant_population)
    )
}

/// How a zone takes an object of `kind`: as a group (with its members), an
/// OU (with what it contains) or a single member.
pub fn adds_as(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Group => "group",
        NodeKind::Ou | NodeKind::Container => "ou",
        _ => "member",
    }
}

/// A share to two decimals: "0%", "0.42%", "33.33%".
pub fn pct(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "0%".into();
    }
    crate::posture::share_percent(100.0 * part as f64 / whole as f64)
}

/// A run's graph for answering: names from `g`, edges from `x`.
#[derive(Clone, Copy)]
pub struct Explorer<'a> {
    pub g: &'a AdGraph,
    pub x: &'a ExploreGraph,
}

impl<'a> Explorer<'a> {
    pub fn new(g: &'a AdGraph, x: &'a ExploreGraph) -> Self {
        Explorer { g, x }
    }

    pub fn node(&self, v: u32) -> &'a Node {
        self.g.node(NodeIndex::new(v as usize))
    }

    pub fn out(&self, v: u32) -> NodeOut<'a> {
        let zone = self
            .x
            .meta
            .zones
            .iter()
            .any(|z| z.members.binary_search(&v).is_ok());
        NodeOut::new(v, self.node(v), self.x.kind(v), self.x.flags(v), zone)
    }

    /// Each object once, in the order given.
    pub fn outs(&self, ixs: impl IntoIterator<Item = u32>) -> Vec<NodeOut<'a>> {
        let mut seen = std::collections::HashSet::new();
        ixs.into_iter()
            .filter(|v| seen.insert(*v))
            .map(|v| self.out(v))
            .collect()
    }

    pub fn edge_out(&self, e: &Edge) -> EdgeOut {
        EdgeOut {
            s: e.from,
            t: e.to,
            k: e.kind.as_str(),
            inh: e.inherited,
            weak: !self.x.traversable(e.kind, e.to),
        }
    }

    /// Everything that can reach `v`, sorted as listed
    /// ([`ExploreGraph::sort_reach`]).
    pub fn reach_list(&self, v: u32) -> Vec<Reacher> {
        let mut l = self.x.reach(v);
        self.x.sort_reach(&mut l, |u| self.node(u).name.as_str());
        l
    }

    /// One page of `list` ([`Explorer::reach_list`] of `v`): at most `limit`
    /// from `offset`, of class `class` only when given.
    pub fn reach_page(
        &self,
        v: u32,
        list: &[Reacher],
        class: Option<u8>,
        offset: usize,
        limit: usize,
    ) -> ReachAnswer<'a> {
        let mut classes = [0usize; 4];
        for r in list {
            classes[r.class as usize] += 1;
        }
        // The list is sorted by class first, so each class is one slice.
        let slice: &[Reacher] = match class.filter(|&c| c < 4) {
            Some(c) => {
                let start: usize = classes[..c as usize].iter().sum();
                &list[start..start + classes[c as usize]]
            }
            None => list,
        };
        let offset = offset.min(slice.len());
        let page = &slice[offset..offset.saturating_add(limit).min(slice.len())];
        ReachAnswer {
            target: self.out(v),
            total: list.len(),
            filtered: slice.len(),
            classes,
            class_names: REACH_CLASSES,
            offset,
            items: page
                .iter()
                .map(|r| ReachItem {
                    node: self.out(r.node),
                    hops: r.hops,
                    class: r.class,
                    first: self.edge_out(&r.first),
                    via: self.out(r.first.to),
                })
                .collect(),
            summary: reach_summary(list.len()),
        }
    }

    /// Objects matching `query` ([`crate::object_index::search`]).
    pub fn search(&self, query: &str, kinds: &[NodeKind], limit: usize) -> Vec<NodeOut<'a>> {
        let hits = crate::object_index::search(self.g, query, kinds, limit);
        self.outs(hits.into_iter().map(|ix| ix.index() as u32))
    }

    /// Why `s` is suggested, in plain words. `exposed`: everyone exposed,
    /// for the choke point's share.
    pub fn reason(&self, s: &Suggestion, exposed: usize) -> String {
        let example = s.example.map(|e| self.node(e).name.clone());
        match s.heuristic {
            Heuristic::ChokePoint => {
                let mut r = format!(
                    "The shortest paths to Tier Zero of {} ({} of everyone exposed) run through it",
                    count(
                        s.count,
                        "exposed user or computer",
                        "exposed users and computers"
                    ),
                    pct(s.count, exposed),
                );
                if let Some(e) = example {
                    r.push_str(&format!(", toward {e}"));
                }
                r.push('.');
                if let Some(m) = s.members {
                    r.push_str(&format!(" It has {}.", count(m, "member", "members")));
                }
                r
            }
            Heuristic::Control => {
                let mut parts = Vec::new();
                let computers =
                    |n: usize, what: &str| format!("{} {what}", count(n, "computer", "computers"));
                if s.servers > 0 {
                    parts.push(computers(s.servers, "running a server OS"));
                }
                if s.workstations > 0 {
                    parts.push(computers(s.workstations, "running a workstation OS"));
                }
                if s.groups > 0 {
                    parts.push(count(s.groups, "group", "groups"));
                }
                if s.users > 0 {
                    parts.push(count(s.users, "user", "users"));
                }
                if s.other > 0 {
                    parts.push(count(s.other, "other object", "other objects"));
                }
                let mut r = format!(
                    "Holds admin or control rights over {}: {}.",
                    count(s.count, "object", "objects"),
                    parts.join(", ")
                );
                if let Some(m) = s.members {
                    r.push_str(&format!(
                        " Its {} inherit them.",
                        count(m, "member", "members")
                    ));
                }
                r
            }
            Heuristic::PrivilegedSessions => {
                let mut who = Vec::new();
                if s.tier_zero_sessions > 0 {
                    who.push(count(
                        s.tier_zero_sessions,
                        "Tier Zero account",
                        "Tier Zero accounts",
                    ));
                }
                if s.admin_sessions > 0 {
                    who.push(count(
                        s.admin_sessions,
                        "other privileged (adminCount) account",
                        "other privileged (adminCount) accounts",
                    ));
                }
                let verb = if s.count == 1 { "was" } else { "were" };
                let mut r = format!("{} {verb} seen logged on to it", who.join(" and "));
                if let Some(e) = example {
                    r.push_str(&format!(" ({e})"));
                }
                r.push_str(": whoever controls it can take their credentials.");
                r
            }
        }
    }

    /// Suggested zones, [`SUGGESTIONS_PER_KIND`] per heuristic. `tree` is
    /// [`ExploreGraph::tier_zero_tree`]. `headline`: the run's own exposed
    /// count and denominator, from its posture, so the line shows the
    /// numbers the report and `pathwarden posture` show; without, the
    /// graph's own counts.
    pub fn suggestions(
        &self,
        tree: &PathTree,
        headline: Option<(usize, usize)>,
    ) -> SuggestionsAnswer<'a> {
        let s = self.x.suggestions(tree, SUGGESTIONS_PER_KIND);
        let items = s
            .items
            .iter()
            .map(|item| SuggestionOut {
                node: self.out(item.node),
                heuristic: item.heuristic,
                tier: item.tier,
                count: item.count,
                reason: self.reason(item, s.exposed),
                adds_as: adds_as(self.x.kind(item.node)),
                zones: self.x.zones_of(item.node),
            })
            .collect();
        let (exposed, relevant) = headline.unwrap_or((s.exposed, s.population));
        SuggestionsAnswer {
            exposed,
            population: s.population,
            relevant_population: relevant,
            intro: suggestions_intro(exposed, relevant),
            heuristics: Heuristic::ALL
                .iter()
                .map(|&h| HeuristicOut {
                    key: h,
                    title: h.title(),
                    about: h.about(),
                })
                .collect(),
            items,
            zones: self.x.meta.zones.iter().map(|z| z.name.as_str()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentages_read_well() {
        assert_eq!(pct(0, 0), "0%");
        assert_eq!(pct(1, 1000), "0.10%");
        assert_eq!(pct(1, 3), "33.33%");
    }

    #[test]
    fn reach_lines() {
        assert_eq!(reach_summary(0), "Nothing has an attack path to it.");
        assert!(reach_summary(1).starts_with("1 object has an attack path to it."));
        assert!(reach_summary(1200).starts_with("1,200 objects have an attack path"));
    }
}
