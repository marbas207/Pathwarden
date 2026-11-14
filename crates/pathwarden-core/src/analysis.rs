//! Attack path analysis: who can reach Tier Zero, by which route, and which
//! single edges cut off the most principals when removed.

use std::collections::{BTreeMap, HashMap, VecDeque};

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::Serialize;

use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};

/// Shortest-path tree toward a target set, built by a multi-source BFS over
/// reversed traversable edges. One O(V+E) pass answers "can X reach a target,
/// and how" for every X at once.
pub struct ReachTree {
    next: Vec<Option<(NodeIndex, EdgeIndex)>>,
    reached: Vec<bool>,
    /// Steps from the nearest root, for reached nodes.
    depth: Vec<u32>,
}

impl ReachTree {
    pub fn reaches(&self, ix: NodeIndex) -> bool {
        self.reached[ix.index()]
    }

    /// A tree over `n` nodes that reaches none yet, for a search over
    /// another copy of the graph (a saved run's) to fill with [`Self::reach`].
    pub(crate) fn empty(n: usize) -> Self {
        ReachTree {
            next: vec![None; n],
            reached: vec![false; n],
            depth: vec![0; n],
        }
    }

    /// Marks `ix` reached, `depth` steps from a root, through `via` (the
    /// next node toward the root and the edge to it; `None` at a root).
    pub(crate) fn reach(&mut self, ix: NodeIndex, via: Option<(NodeIndex, EdgeIndex)>, depth: u32) {
        let i = ix.index();
        self.reached[i] = true;
        self.next[i] = via;
        self.depth[i] = depth;
    }

    /// How many steps `ix` is from the nearest root, if reached.
    pub fn depth(&self, ix: NodeIndex) -> Option<u32> {
        self.reaches(ix).then(|| self.depth[ix.index()])
    }

    /// The target that `from`'s shortest path ends at.
    pub fn target(&self, from: NodeIndex) -> Option<NodeIndex> {
        if !self.reaches(from) {
            return None;
        }
        let mut cur = from;
        while let Some((next, _)) = self.next[cur.index()] {
            cur = next;
        }
        Some(cur)
    }

    /// The next node and edge on `from`'s shortest path; `None` at a
    /// target, and for a node that doesn't reach one.
    pub fn next(&self, from: NodeIndex) -> Option<(NodeIndex, EdgeIndex)> {
        self.next[from.index()]
    }

    /// Edges of the shortest path from `from` to the target set.
    pub fn path(&self, from: NodeIndex) -> Option<Vec<EdgeIndex>> {
        if !self.reaches(from) {
            return None;
        }
        let mut edges = Vec::new();
        let mut cur = from;
        while let Some((next, e)) = self.next[cur.index()] {
            edges.push(e);
            cur = next;
        }
        Some(edges)
    }
}

pub fn reach_targets(
    g: &AdGraph,
    targets: impl IntoIterator<Item = NodeIndex>,
    skip: Option<EdgeIndex>,
) -> ReachTree {
    reach_targets_where(g, targets, |e| Some(e) != skip)
}

/// Like [`reach_targets`], following only traversable edges that `allow` accepts.
pub fn reach_targets_where(
    g: &AdGraph,
    targets: impl IntoIterator<Item = NodeIndex>,
    allow: impl Fn(EdgeIndex) -> bool,
) -> ReachTree {
    reach_filtered(g, targets, allow, |_| true)
}

/// Like [`reach_targets_where`], also refusing to pass through nodes that
/// `through` rejects (they can still be targets).
pub fn reach_filtered(
    g: &AdGraph,
    targets: impl IntoIterator<Item = NodeIndex>,
    allow: impl Fn(EdgeIndex) -> bool,
    through: impl Fn(NodeIndex) -> bool,
) -> ReachTree {
    search(
        g,
        targets,
        &[Direction::Incoming],
        |e| g.traversable(*e.weight(), e.target()) && allow(e.id()),
        through,
        |_| true,
        None,
        |_| false,
    )
}

/// The breadth-first search behind every attack path: out from `roots`,
/// one step at a time, along the edges `allow` accepts. `Incoming` walks
/// edges backwards (from a node to whoever has an edge into it, as
/// [`reach_filtered`] does toward a target), `Outgoing` forwards; both
/// together ignore direction. A node `through` rejects is skipped: it is
/// neither reached nor passed through (a root always is reached). A node
/// `expand` rejects is reached, but the search goes no further from it (a
/// root always is passed through). Stops after `max_depth` steps, and as soon as `visit`,
/// called on each node as it is reached, says to.
///
/// Neighbours are taken in the graph's storage order, so the same search
/// finds the same tree, and the Cypher engine's `shortestPath` the same
/// path as `pathwarden path`.
#[allow(clippy::too_many_arguments)]
pub fn search<'g>(
    g: &'g AdGraph,
    roots: impl IntoIterator<Item = NodeIndex>,
    dirs: &[Direction],
    allow: impl Fn(petgraph::graph::EdgeReference<'g, EdgeKind>) -> bool,
    through: impl Fn(NodeIndex) -> bool,
    expand: impl Fn(NodeIndex) -> bool,
    max_depth: Option<u32>,
    mut visit: impl FnMut(NodeIndex) -> bool,
) -> ReachTree {
    let n = g.node_count();
    let mut next = vec![None; n];
    let mut reached = vec![false; n];
    let mut depth = vec![0u32; n];
    let mut queue = VecDeque::new();
    for t in roots {
        if !reached[t.index()] {
            reached[t.index()] = true;
            queue.push_back(t);
            if visit(t) {
                return ReachTree {
                    next,
                    reached,
                    depth,
                };
            }
        }
    }
    'bfs: while let Some(v) = queue.pop_front() {
        let d = depth[v.index()];
        if max_depth.is_some_and(|m| d >= m) {
            continue;
        }
        for &dir in dirs {
            for e in g.inner().edges_directed(v, dir) {
                let u = match dir {
                    Direction::Incoming => e.source(),
                    Direction::Outgoing => e.target(),
                };
                if reached[u.index()] || !allow(e) || !through(u) {
                    continue;
                }
                reached[u.index()] = true;
                depth[u.index()] = d + 1;
                next[u.index()] = Some((v, e.id()));
                if expand(u) {
                    queue.push_back(u);
                }
                if visit(u) {
                    break 'bfs;
                }
            }
        }
    }
    ReachTree {
        next,
        reached,
        depth,
    }
}

pub fn tier_zero(g: &AdGraph) -> Vec<NodeIndex> {
    g.nodes()
        .filter(|(_, n)| n.tier_zero)
        .map(|(ix, _)| ix)
        .collect()
}

/// Principals an attacker could start from: enabled, collected, non-Tier Zero
/// users and computers.
pub fn population(g: &AdGraph) -> Vec<NodeIndex> {
    g.nodes()
        .filter(|(_, n)| {
            matches!(n.kind, NodeKind::User | NodeKind::Computer)
                && !n.placeholder
                && !n.tier_zero
                && n.is_enabled()
        })
        .map(|(ix, _)| ix)
        .collect()
}

/// Which [`population`] members count toward the exposure denominator.
///
/// Only **active** population members count, in the exposure percentage
/// and in every count of accounts: those that
/// logged on within the stale window before the collection time
/// ([`crate::findings::RuleSettings::stale_days`] days before
/// [`crate::findings::RuleSettings::now`], the same window PW-009 calls an
/// account stale after). An account that never logged on (no logon time,
/// `0` or `-1`) is not active. An inactive account with a path is not
/// counted as exposed either (the owner's decision, 11-14).
///
/// Edges do not decide relevance: adding inactive objects, rightless groups
/// or sessions leaves the denominator alone, and no change of rights ever
/// moves it.
///
/// Whether a domain's data has logon times is decided per kind: for its
/// users from its users, for its computers from its computers. A
/// kind has them when the collector wrote the field for at least half of
/// that kind's population members there ("never", `-1` or `0`, is a
/// collected answer). Where a kind has none, activity can't be told for it,
/// and every enabled member of that kind there counts as active: data with
/// logon times for users and none for computers doesn't make every computer
/// inactive. A domain where no kind has logon times is listed in
/// [`Relevance::activity_unknown_domains`] so the surfaces can say so.
#[derive(Debug, Clone)]
pub struct Relevance {
    active: Vec<bool>,
    /// The activity window, in days before the collection time.
    pub stale_days: i64,
    /// Domains without logon times, where every enabled account counts as
    /// active, sorted.
    pub activity_unknown_domains: Vec<String>,
}

/// The exposure basis this build computes: 0 was every enabled user and
/// computer, 1 the capability gate, 2 the active accounts plus the inactive
/// ones with a path, 3 the active accounts only ([`Relevance`]).
/// Recorded with every run so trends never compare across bases.
pub const EXPOSURE_BASIS: u8 = 3;

/// The domain a population member counts under for [`Relevance`].
fn activity_domain(n: &crate::model::Node) -> String {
    n.domain
        .as_deref()
        .map(str::to_ascii_uppercase)
        .unwrap_or_else(|| "UNKNOWN".into())
}

/// Which domains "have logon times" among `members` (all of one kind):
/// the collector wrote the field for at least half of those there. -1 / 0
/// is SharpHound's "never logged on", a collected answer, not missing data.
/// Names every domain `members` has one in.
fn domains_with_logons(
    g: &AdGraph,
    members: &[NodeIndex],
) -> std::collections::BTreeMap<String, bool> {
    let mut counts: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for &ix in members {
        let c = counts.entry(activity_domain(g.node(ix))).or_default();
        c.1 += 1;
        if g.node(ix).props.lastlogontimestamp.is_some() {
            c.0 += 1;
        }
    }
    counts
        .into_iter()
        .map(|(d, (with, all))| (d, with > 0 && with * 2 >= all))
        .collect()
}

/// Which of `members` are active, judged at `now` with a window of
/// `stale_days`: a logon within the window; never logged on (no logon
/// time, `0` or `-1`) is inactive, unless the member's domain has no logon
/// times (`with_logons` says false or doesn't name it: activity can't be
/// told there, so every member counts as active). Shared by [`Relevance`]
/// and the computers a run holds findings on ([`computer_gone`]).
fn activity(
    g: &AdGraph,
    members: &[NodeIndex],
    with_logons: &std::collections::BTreeMap<String, bool>,
    now: i64,
    stale_days: i64,
) -> Vec<bool> {
    let logon = |ix: NodeIndex| g.node(ix).props.lastlogontimestamp.filter(|&t| t > 0);
    let mut active = vec![false; g.node_count()];
    for &ix in members {
        active[ix.index()] = match logon(ix) {
            Some(t) => (now - t) / 86_400 <= stale_days,
            None => !with_logons
                .get(&activity_domain(g.node(ix)))
                .copied()
                .unwrap_or(false),
        };
    }
    active
}

/// Which computers count as gone for the findings a run holds on
/// computers ([`crate::opengraph::coverage::RunSources`]), by node index:
/// disabled, or not active as [`Relevance`] judges activity (no logon in
/// `stale_days` before `now`, or never logged on). A computer switched off
/// for good, or pre-staged and never joined, doesn't hold findings forever.
///
/// A domain has logon times here when at least half of its computers
/// (enabled or not) carry the field, as [`Relevance`] decides for its
/// computers. Data with logon times for users and none (or almost none) for
/// computers would otherwise make every computer gone, and its findings
/// fixed.
pub fn computer_gone(g: &AdGraph, now: i64, stale_days: i64) -> Vec<bool> {
    let computers: Vec<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Computer && !n.placeholder)
        .map(|(ix, _)| ix)
        .collect();
    let with_logons = domains_with_logons(g, &computers);
    let active = activity(g, &computers, &with_logons, now, stale_days);
    let mut gone = vec![false; g.node_count()];
    for ix in computers {
        gone[ix.index()] = !g.node(ix).is_enabled() || !active[ix.index()];
    }
    gone
}

impl Relevance {
    /// Activity of every population member, judged at `now` (the collection
    /// time) with a window of `stale_days`.
    pub fn new(g: &AdGraph, now: i64, stale_days: i64) -> Self {
        let pop = population(g);
        let mut active = vec![false; g.node_count()];
        // Per domain: whether any kind there has logon times.
        let mut known: std::collections::BTreeMap<String, bool> = Default::default();
        for kind in [NodeKind::User, NodeKind::Computer] {
            let members: Vec<NodeIndex> = pop
                .iter()
                .copied()
                .filter(|&ix| g.node(ix).kind == kind)
                .collect();
            let with_logons = domains_with_logons(g, &members);
            let of_kind = activity(g, &members, &with_logons, now, stale_days);
            for &ix in &members {
                active[ix.index()] = of_kind[ix.index()];
            }
            for (d, with) in with_logons {
                *known.entry(d).or_default() |= with;
            }
        }
        let activity_unknown_domains = known
            .into_iter()
            .filter(|(_, any)| !any)
            .map(|(d, _)| d)
            .collect();
        Relevance {
            active,
            stale_days,
            activity_unknown_domains,
        }
    }

    /// [`Relevance::new`] with the rule settings' collection time and stale
    /// window.
    pub fn from_settings(g: &AdGraph, settings: &crate::findings::RuleSettings) -> Self {
        Self::new(g, settings.now, settings.stale_days)
    }

    /// Whether the population member `ix` counts as active.
    pub fn is_active(&self, ix: NodeIndex) -> bool {
        self.active.get(ix.index()).copied().unwrap_or(false)
    }

    /// Of `pop`, how many count: the active ones.
    pub fn relevant(&self, pop: &[NodeIndex]) -> usize {
        pop.iter().filter(|&&ix| self.is_active(ix)).count()
    }

    /// Of `pop`, how many count as exposed: active, and `exposed` says so.
    pub fn exposed(&self, pop: &[NodeIndex], exposed: impl Fn(NodeIndex) -> bool) -> usize {
        pop.iter()
            .filter(|&&ix| self.is_active(ix) && exposed(ix))
            .count()
    }
}

/// The Tier-Zero-relevant principals, the denominator of the exposure
/// percentage: the active population members ([`Relevance`]).
pub fn relevant_population_for(g: &AdGraph, rel: &Relevance) -> Vec<NodeIndex> {
    population(g)
        .into_iter()
        .filter(|&ix| rel.is_active(ix))
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub from: String,
    pub from_kind: NodeKind,
    pub edge: EdgeKind,
    pub to: String,
    pub to_kind: NodeKind,
    /// The OpenGraph source that says this step exists ("TaskHound");
    /// absent for steps from AD data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The edge runs from `to` to `from`: a Cypher path can walk an edge
    /// against its direction. Never set on an attack path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub backward: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackPath {
    pub source: String,
    pub target: String,
    pub steps: Vec<PathStep>,
    /// The graph edges of the steps (for provenance; not serialized). For
    /// a Cypher path ([`crate::cypher::attack_path`]) they are the view's
    /// edge handles: petgraph indexes of the [`AdGraph`] under
    /// [`crate::cypher::AdGraphView`], positions in the run's explore graph
    /// ([`crate::explore::ExploreGraph::edge_at`]) under
    /// [`crate::cypher::RunView`].
    #[serde(skip)]
    pub edges: Vec<EdgeIndex>,
}

pub fn render_path(g: &AdGraph, from: NodeIndex, edges: &[EdgeIndex]) -> AttackPath {
    let steps: Vec<PathStep> = edges
        .iter()
        .map(|&e| {
            let (a, b) = g.inner().edge_endpoints(e).expect("edge from this graph");
            let (a, b) = (g.node(a), g.node(b));
            PathStep {
                from: a.name.clone(),
                from_kind: a.kind,
                edge: g.inner()[e],
                to: b.name.clone(),
                to_kind: b.kind,
                source: g.edge_source_name(e).map(str::to_owned),
                backward: false,
            }
        })
        .collect();
    AttackPath {
        source: g.node(from).name.clone(),
        target: steps
            .last()
            .map(|s| s.to.clone())
            .unwrap_or_else(|| g.node(from).name.clone()),
        steps,
        edges: edges.to_vec(),
    }
}

/// Shortest attack path between two objects. It ends at the first Tier
/// Zero object it meets: none goes on through one (see
/// [`path_through_tier_zero`]).
pub fn shortest_path(g: &AdGraph, from: NodeIndex, to: NodeIndex) -> Option<AttackPath> {
    toward(g, to, true)
        .path(from)
        .map(|edges| render_path(g, from, &edges))
}

/// Shortest attack paths to `to`; with `stop_at_tier_zero`, none goes on
/// through a Tier Zero object (`to` itself aside): whoever holds one has
/// already won, so an attack path ends at the first.
fn toward(g: &AdGraph, to: NodeIndex, stop_at_tier_zero: bool) -> ReachTree {
    search(
        g,
        [to],
        &[Direction::Incoming],
        |e| g.traversable(*e.weight(), e.target()),
        |_| true,
        |ix| !(stop_at_tier_zero && g.node(ix).tier_zero),
        None,
        |_| false,
    )
}

/// What Path between and `pathwarden path --to` say over a path from
/// [`path_through_tier_zero`], which ends before `to`.
pub fn through_tier_zero_line(to: &str) -> String {
    format!("{to} is reached only through Tier Zero.")
}

/// When [`shortest_path`] finds none because every path to `to` passes
/// through Tier Zero: the shortest one, up to the first Tier Zero object on
/// it (which controls `to`).
pub fn path_through_tier_zero(g: &AdGraph, from: NodeIndex, to: NodeIndex) -> Option<AttackPath> {
    let edges = toward(g, to, false).path(from)?;
    let cut = edges.iter().position(|&e| {
        let b = g
            .inner()
            .edge_endpoints(e)
            .expect("an edge of this graph")
            .1;
        b != to && g.node(b).tier_zero
    })?;
    Some(render_path(g, from, &edges[..=cut]))
}

/// Shortest attack path from an object to any Tier Zero object.
pub fn path_to_tier_zero(g: &AdGraph, from: NodeIndex) -> Option<AttackPath> {
    reach_targets(g, tier_zero(g), None)
        .path(from)
        .map(|edges| render_path(g, from, &edges))
}

/// Exposure counts for a set of principals. `*_total` is the relevant
/// population (the active, see [`Relevance`]) and `*_exposed` the active
/// ones with a path, the
/// denominator the Posture page uses; `*_enabled` is every enabled user or
/// computer, for context.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Exposure {
    pub users_total: usize,
    pub users_exposed: usize,
    pub computers_total: usize,
    pub computers_exposed: usize,
    pub users_enabled: usize,
    pub computers_enabled: usize,
}

impl Exposure {
    pub fn users_pct(&self) -> f64 {
        pct(self.users_exposed, self.users_total)
    }

    pub fn computers_pct(&self) -> f64 {
        pct(self.computers_exposed, self.computers_total)
    }

    /// Users and computers together: exposed, relevant, percent.
    pub fn exposed(&self) -> usize {
        self.users_exposed + self.computers_exposed
    }

    pub fn relevant(&self) -> usize {
        self.users_total + self.computers_total
    }

    pub fn percent(&self) -> f64 {
        pct(self.exposed(), self.relevant())
    }

    fn add(&mut self, kind: NodeKind, exposed: bool, relevant: bool) {
        let (total, hit, enabled) = match kind {
            NodeKind::User => (
                &mut self.users_total,
                &mut self.users_exposed,
                &mut self.users_enabled,
            ),
            _ => (
                &mut self.computers_total,
                &mut self.computers_exposed,
                &mut self.computers_enabled,
            ),
        };
        *enabled += 1;
        *total += usize::from(relevant);
        *hit += usize::from(relevant && exposed);
    }
}

pub(crate) fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

#[derive(Debug, Serialize)]
pub struct ExposureReport {
    /// Objects being protected (Tier Zero, or a zone plus Tier Zero).
    pub target_objects: usize,
    pub total: Exposure,
    pub per_domain: BTreeMap<String, Exposure>,
    /// Shortest paths first: the quickest routes an attacker would find.
    pub sample_paths: Vec<AttackPath>,
    /// The exposure basis of the counts ([`EXPOSURE_BASIS`]).
    pub exposure_basis: u8,
    /// The activity window the relevant counts use, in days.
    pub stale_days: i64,
    /// Domains without logon times, where every enabled account counts.
    pub activity_unknown_domains: Vec<String>,
}

pub fn exposure(g: &AdGraph, sample_limit: usize, rel: &Relevance) -> ExposureReport {
    exposure_to(g, &tier_zero(g), sample_limit, rel)
}

/// Exposure to an arbitrary set of targets; principals in the set are not
/// counted. Totals are over the relevant population ([`Relevance`]), so the
/// totals match the Posture page.
pub fn exposure_to(
    g: &AdGraph,
    targets: &[NodeIndex],
    sample_limit: usize,
    rel: &Relevance,
) -> ExposureReport {
    let t0 = targets;
    let target_set: std::collections::HashSet<NodeIndex> = targets.iter().copied().collect();
    let tree = reach_targets(g, t0.iter().copied(), None);
    let mut total = Exposure::default();
    let mut per_domain: BTreeMap<String, Exposure> = BTreeMap::new();
    let mut exposed = Vec::new();
    for ix in population(g)
        .into_iter()
        .filter(|ix| !target_set.contains(ix))
    {
        let n = g.node(ix);
        let hit = tree.reaches(ix);
        let active = rel.is_active(ix);
        total.add(n.kind, hit, active);
        per_domain
            .entry(n.domain.clone().unwrap_or_else(|| "UNKNOWN".into()))
            .or_default()
            .add(n.kind, hit, active);
        if !active {
            continue;
        }
        if let Some(edges) = tree.path(ix) {
            exposed.push((edges.len(), n.name.as_str(), ix, edges));
        }
    }
    exposed.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let sample_paths = exposed
        .into_iter()
        .take(sample_limit)
        .map(|(_, _, ix, edges)| render_path(g, ix, &edges))
        .collect();
    ExposureReport {
        target_objects: t0.len(),
        total,
        per_domain,
        sample_paths,
        exposure_basis: EXPOSURE_BASIS,
        stale_days: rel.stale_days,
        activity_unknown_domains: rel.activity_unknown_domains.clone(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChokePoint {
    pub from: String,
    pub from_kind: NodeKind,
    pub edge: EdgeKind,
    pub to: String,
    pub to_kind: NodeKind,
    /// Exposed active principals whose shortest path uses this edge.
    pub shortest_paths_through: usize,
    /// Active principals that lose every path to Tier Zero if this edge is
    /// removed.
    pub principals_cut_off: usize,
    /// Tier Zero exposure percentage before removing this edge: the run's
    /// baseline `exposed / relevant_population`, the same hero figure the
    /// Posture page shows (see [`crate::posture::ZonePosture::exposure_percent`]).
    pub exposure_before: f64,
    /// Exposure percentage with this one edge removed, as a fresh run would
    /// read it: the principals still exposed over
    /// [`ChokePoint::relevant_population_after`].
    pub exposure_after: f64,
    /// Points of exposure this single removal buys back
    /// (`exposure_before - exposure_after`).
    pub exposure_delta: f64,
    /// The denominator of `exposure_before`: the run's Tier-Zero-relevant
    /// population (the active, see [`Relevance`]).
    pub relevant_population: usize,
    /// The denominator of `exposure_after`. Only active accounts count, so
    /// it is `relevant_population`: removing an edge never moves it. Kept
    /// so the JSON doesn't lose a key.
    pub relevant_population_after: usize,
}

/// Ranks edges by how many principals lose all access to Tier Zero when the edge
/// is removed. Candidates come from shortest-path usage; each is then verified
/// exactly by recomputing reachability without it.
pub fn choke_points(g: &AdGraph, top: usize, rel: &Relevance) -> Vec<ChokePoint> {
    let t0 = tier_zero(g);
    let tree = reach_targets(g, t0.iter().copied(), None);
    // Inactive accounts don't count, here or in the cut-off counts.
    let pop: Vec<NodeIndex> = population(g)
        .into_iter()
        .filter(|&ix| rel.is_active(ix))
        .collect();
    let baseline = pop.iter().filter(|&&ix| tree.reaches(ix)).count();
    let relevant = pop.len();
    let exposure_before = pct(baseline, relevant);

    let mut usage: HashMap<EdgeIndex, usize> = HashMap::new();
    for &ix in &pop {
        for e in tree.path(ix).unwrap_or_default() {
            *usage.entry(e).or_default() += 1;
        }
    }
    let mut candidates: Vec<(EdgeIndex, usize)> = usage.into_iter().collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    candidates.truncate((top * 3).min(60).max(top));

    let mut out: Vec<ChokePoint> = candidates
        .into_iter()
        .map(|(e, through)| {
            let without = reach_targets(g, t0.iter().copied(), Some(e));
            let still = pop.iter().filter(|&&ix| without.reaches(ix)).count();
            let relevant_after = relevant;
            let exposure_after = pct(still, relevant_after);
            let (a, b) = g.inner().edge_endpoints(e).expect("edge from this graph");
            let (a, b) = (g.node(a), g.node(b));
            ChokePoint {
                from: a.name.clone(),
                from_kind: a.kind,
                edge: g.inner()[e],
                to: b.name.clone(),
                to_kind: b.kind,
                shortest_paths_through: through,
                principals_cut_off: baseline - still,
                exposure_before,
                exposure_after,
                exposure_delta: exposure_before - exposure_after,
                relevant_population: relevant,
                relevant_population_after: relevant_after,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.principals_cut_off
            .cmp(&a.principals_cut_off)
            .then(b.shortest_paths_through.cmp(&a.shortest_paths_through))
            .then(a.from.cmp(&b.from))
    });
    out.truncate(top);
    out
}

#[cfg(test)]
mod choke_point_tests {
    use super::*;
    use crate::model::Node;

    fn node(g: &mut AdGraph, id: &str, kind: NodeKind) -> NodeIndex {
        let mut n = Node::placeholder(id.to_string(), kind);
        n.placeholder = false;
        n.name = format!("{id}@CORP.LOCAL");
        g.upsert(n)
    }

    const NOW: i64 = 1_791_417_600;

    fn logged_on(g: &mut AdGraph, ix: NodeIndex, days_ago: i64) {
        g.node_mut(ix).props.lastlogontimestamp = Some(NOW - days_ago * 86_400);
    }

    /// A synthetic graph where three exposed users all reach a Tier Zero
    /// computer only through one AdminTo edge (GROUP -> T0); one of them has
    /// not logged on for a year. A fourth user is active with no path, a
    /// fifth inactive. Removing the shared edge cuts all three, but only the
    /// two active ones count.
    #[test]
    fn choke_point_reports_before_after_exposure_and_cut() {
        let mut g = AdGraph::new();
        let t0 = node(&mut g, "S-1-5-21-1-2-3-516", NodeKind::Computer);
        g.node_mut(t0).tier_zero = true;
        let group = node(&mut g, "S-1-5-21-1-2-3-1100", NodeKind::Group);
        g.add_edge(group, t0, EdgeKind::AdminTo);
        for i in 0..3 {
            let u = node(
                &mut g,
                &format!("S-1-5-21-1-2-3-{}", 1200 + i),
                NodeKind::User,
            );
            g.add_edge(u, group, EdgeKind::MemberOf);
            logged_on(&mut g, u, if i == 2 { 365 } else { 1 });
        }
        // Active, not exposed.
        let active = node(&mut g, "S-1-5-21-1-2-3-1300", NodeKind::User);
        logged_on(&mut g, active, 3);
        // Inactive, not exposed.
        let idle = node(&mut g, "S-1-5-21-1-2-3-1500", NodeKind::User);
        logged_on(&mut g, idle, 200);

        let rel = Relevance::new(&g, NOW, 90);
        let points = choke_points(&g, 5, &rel);
        let top = &points[0];
        assert_eq!(top.edge, EdgeKind::AdminTo);
        assert_eq!(top.from, "S-1-5-21-1-2-3-1100@CORP.LOCAL");
        assert_eq!(top.to, "S-1-5-21-1-2-3-516@CORP.LOCAL");
        // Inactive accounts don't count: two of the three are cut off.
        assert_eq!(top.principals_cut_off, 2);
        // The two active exposed and the active one with no path.
        assert_eq!(top.relevant_population, 3);
        assert!((top.exposure_before - 200.0 / 3.0).abs() < 1e-9);
        assert_eq!(top.relevant_population_after, 3);
        assert_eq!(top.exposure_after, 0.0);
        assert!((top.exposure_delta - 200.0 / 3.0).abs() < 1e-9);
    }
}
