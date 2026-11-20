//! The forest map: the domains of a collection, grouped into forests, and
//! the trusts between them, each once. What `pathwarden summary` shows and
//! the app's API returns (`/api/runs/<id>/explore/forest`), from one
//! function ([`forest_map`]).
//!
//! The map is plain data. A saved run keeps it in its explorer data
//! ([`crate::explore::Meta::forest`]), since the per-trust details
//! (direction, SID filtering, selective authentication) are not in the
//! graph, which has only "same forest" and "other forest" trust edges.
//!
//! A trust is used one way or both. Each way is principals of one domain
//! (`from`) authenticating into a domain that trusts them (`to`), and what
//! applies to that way (SID filtering, selective authentication) is set on
//! the trusting side's record of the trust, so it is unknown when that
//! side was not collected.

use std::collections::{BTreeMap, HashMap};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use crate::analysis::{self, Relevance};
use crate::graph::AdGraph;
use crate::ingest::{IngestStats, TrustInfo};
use crate::model::{EdgeKind, NodeKind};
use crate::sid;

/// What a run saved before the map was kept says, in the app and the CLI.
pub const NOT_KEPT: &str = "This run was analyzed before Pathwarden kept its domains and trusts. \
Analyze the collection again to see its forest.";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ForestMap {
    /// Sorted by forest, its root first, then tree roots, then by name.
    pub domains: Vec<DomainNode>,
    /// Sorted by name.
    pub forests: Vec<Forest>,
    /// Each trust once, though both of its domains record it; within a
    /// forest first, then by name.
    pub trusts: Vec<TrustEdge>,
    /// Rights between domains of one forest that no trust joins directly
    /// (they cross the forest's transitive trusts), or between forests no
    /// trust in the data joins.
    #[serde(default)]
    pub indirect: Vec<Crossing>,
}

/// Domains joined by same-forest trusts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Forest {
    /// Its forest root domain's name.
    pub name: String,
    /// Sorted.
    pub domains: Vec<String>,
}

/// Where a domain sits in its forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainRole {
    /// The forest root: the domain of Enterprise Admins (RID 519) or Schema
    /// Admins (518); without either, the first domain by name with no
    /// parent in the forest.
    ForestRoot,
    /// The root of another tree of the forest: no parent in the forest by
    /// DNS name.
    TreeRoot,
    /// Under a parent domain of the forest (by DNS name).
    Child,
    /// Not collected and known only from trusts that do not say (external
    /// ones): only the far end of a forest trust is known to be a root.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainNode {
    /// The DNS name, or the SID when the data has no name for it.
    pub name: String,
    pub sid: String,
    /// Index into [`ForestMap::forests`].
    pub forest: usize,
    /// Its data was collected; otherwise it is only known from a trust.
    pub collected: bool,
    pub role: DomainRole,
    /// Collected objects of each kind (not ones only referenced).
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    /// Collected Tier Zero objects of any kind.
    pub tier_zero: usize,
    /// Its enabled users and computers outside Tier Zero, active or not.
    #[serde(default)]
    pub population: usize,
    /// Its enabled users and computers outside Tier Zero with an attack path
    /// to Tier Zero (any domain's).
    pub exposed: usize,
    /// Its active accounts and the exposed ([`Relevance`]), as the Tier Zero
    /// headline counts them.
    pub relevant_population: usize,
    /// `exposed / relevant_population`; `None` when no account counts.
    pub exposure_percent: Option<f64>,
    /// In words ([`ForestMap::derive`]): "forest root", ...
    #[serde(default)]
    pub role_text: String,
    /// Its attack paths in words, when an account counts.
    #[serde(default)]
    pub paths: Option<PathWords>,
    /// Otherwise why not: [`NOT_COLLECTED`], or no accounts outside Tier
    /// Zero.
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustEdge {
    /// The domain whose record comes first, and the other one.
    pub source: String,
    pub target: String,
    /// `ParentChild`, `CrossLink`, `Forest`, `External`, ...
    pub trust_type: String,
    /// Relative to `source`, from every record of the trust:
    /// `Bidirectional`, `Outbound` (`source` trusts `target`), `Inbound`
    /// (`target` trusts `source`) or `Disabled` (neither).
    pub direction: String,
    pub transitive: bool,
    /// Inside one forest, where the forest, not the domain, is the security
    /// boundary.
    pub intra_forest: bool,
    /// The ways the trust is used.
    pub ways: Vec<TrustWay>,
    /// Every way filters SIDs (`Some(true)`); one does not (`Some(false)`);
    /// otherwise unknown, a trusting side not collected.
    pub sid_filtering: Option<bool>,
    /// Every way needs selective authentication (`Some(true)`); one does not
    /// (`Some(false)`); otherwise unknown.
    pub selective_auth: Option<bool>,
    /// Taking either domain takes the forest: an intra-forest trust in use.
    pub enables_forest_takeover: bool,
    /// SID history can be forged along some way ([`TrustWay::sid_history_abuse`]).
    pub abusable_sid_history: bool,
    /// The two domains' records say different things (one way against two,
    /// or one disabled).
    pub records_disagree: bool,
    /// The PW-012 findings its records fire, by fingerprint.
    pub findings: Vec<String>,
    /// What each domain records: one entry, or two when both were collected.
    pub records: Vec<TrustInfo>,
    /// What the data shows crossing the trust: for a trust between forests,
    /// between any domains of the two forests no trust joins directly.
    pub crossing: Vec<Crossing>,
    /// In words ([`ForestMap::derive`]): what its label calls out.
    #[serde(default)]
    pub flags: Vec<TrustFlag>,
    /// Why PW-012 fires though SID history abuse is not shown.
    #[serde(default)]
    pub pw012_note: Option<String>,
    /// What its crossings leave out ([`TIER_ZERO_NOT_LISTED`] inside a
    /// forest).
    #[serde(default)]
    pub crossing_note: Option<String>,
    /// "two-way", "one-way" or "disabled".
    #[serde(default)]
    pub way_word: String,
}

/// One way of a trust: principals of `from` authenticating into `to`,
/// which trusts `from`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustWay {
    pub from: String,
    pub to: String,
    /// As `to` records it; `None` when `to` has no record trusting `from`
    /// (not collected, or its record is inbound only).
    pub sid_filtering: Option<bool>,
    pub selective_auth: Option<bool>,
    /// `to`'s record has its trust attributes, so `sid_filtering` is read
    /// from them; otherwise it is the collector's `SidFilteringEnabled`
    /// flag.
    #[serde(default)]
    pub attributes_known: bool,
    /// Why `sid_filtering` is unknown though `to` recorded the trust: a
    /// forest trust without its attributes, whose `SidFilteringEnabled`
    /// flag only reports quarantine, which forest trusts don't use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid_filtering_unknown: Option<String>,
    /// Whoever controls `from` can forge SID history that `to` accepts: a
    /// forest or external trust whose trusting side filters only RIDs under
    /// 1000 and the built-in SIDs from the other side.
    pub sid_history_abuse: bool,
    /// Of those SIDs, only RIDs 1000 and above can pass. Always so where
    /// `sid_history_abuse` is: every trust between forests, forest (with
    /// TREAT_AS_EXTERNAL) or external (not quarantined), filters RIDs under
    /// 1000 and the built-in SIDs (MS-PAC 4.1.2.2). Kept for the JSON shape.
    pub rid_1000_and_up: bool,
    /// In words ([`ForestMap::derive`]): "SID filtering on", "off" or
    /// "unknown", and its note: the collector's flag ([`FLAG_ONLY`]) or
    /// why it is unknown.
    #[serde(default)]
    pub filtering: String,
    #[serde(default)]
    pub filtering_note: Option<String>,
    /// "selective authentication", "no ...", "... not in the data".
    #[serde(default)]
    pub selective: String,
    /// What the abuse lets whoever controls `from` do.
    #[serde(default)]
    pub abuse_text: Option<String>,
}

/// Why a forest trust's SID filtering is unknown without its attributes.
pub const FOREST_FLAG_UNKNOWN: &str = "the collector didn't record this trust's attributes, and \
its summary flag doesn't apply to forest trusts";

/// Rights principals of one domain hold over objects of another. Within a
/// forest, those held by Tier Zero are left out: Enterprise Admins control
/// every domain of the forest by design.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crossing {
    /// The principals' domain.
    pub from: String,
    /// The objects' domain.
    pub to: String,
    /// Group memberships (foreign group members), not counting the groups
    /// everyone is in (Authenticated Users, Everyone).
    pub memberships: usize,
    /// Local administrator rights on computers.
    pub admin_rights: usize,
    /// Directory permissions that grant control (ACEs).
    pub aces: usize,
    /// Accounts carrying a SID of the other domain in their SID history.
    pub sid_history: usize,
    /// The rights counted, one per relationship: up to
    /// [`RIGHTS_LISTED`], shared out between the kinds in turn so each kind
    /// counted is listed; memberships first, then admin rights, ACEs and
    /// SID history, each by name. Empty for a run saved before they were
    /// listed.
    #[serde(default)]
    pub rights: Vec<CrossingRight>,
    /// The counts in words ([`Crossing::counts_text`]).
    #[serde(default)]
    pub counts: String,
}

/// One right a [`Crossing`] counts: `from` holds `kind` over `to`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossingRight {
    /// The principal's object ID (a SID) and name.
    pub from: String,
    pub from_name: String,
    /// The object's ID and name.
    pub to: String,
    pub to_name: String,
    /// The relationship: `MemberOf`, `AdminTo`, `GenericAll`, ...,
    /// `HasSidHistory`.
    pub kind: String,
}

/// How many rights a crossing lists ([`Crossing::rights`]); its counts
/// are of all of them.
pub const RIGHTS_LISTED: usize = 100;

impl Crossing {
    fn is_empty(&self) -> bool {
        self.memberships + self.admin_rights + self.aces + self.sid_history == 0
    }

    /// Every right counted.
    pub fn counted(&self) -> usize {
        self.memberships + self.admin_rights + self.aces + self.sid_history
    }
}

impl TrustEdge {
    /// PW-012 fires on its records, but whether SID history can be forged
    /// across it is not in the data: a forest trust without its attributes,
    /// or only an inbound record (the trusting side's own not collected).
    pub fn sid_filtering_unknown(&self) -> bool {
        !self.abusable_sid_history && !self.findings.is_empty()
    }
}

/// The line above the map: how many domains, forests and trusts, and what
/// stands out.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Headline {
    pub domains: usize,
    pub forests: usize,
    pub trusts: usize,
    pub between_forests: usize,
    pub not_collected: usize,
    /// Trusts with SID history abuse ([`TrustEdge::abusable_sid_history`]).
    pub sid_history_abuse: usize,
    /// Trusts PW-012 fires on whose SID filtering is unknown
    /// ([`TrustEdge::sid_filtering_unknown`]).
    pub sid_filtering_unknown: usize,
    /// "3 domains in 2 forests"
    pub lead: String,
    /// "2 trusts, 1 between forests · all collected"
    pub detail: String,
    /// What stands out, worst first; "No SID history abuse" when nothing
    /// does. Forest takeover is not here: every trust inside a forest has
    /// it, so it is shown on each such trust instead.
    pub status: Vec<Status>,
    /// The trust to open on ([`ForestMap::focus`]).
    pub focus: Option<usize>,
}

/// One thing the [`Headline`] calls out.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Status {
    /// `abuse`, `unknown` or `none`.
    pub kind: &'static str,
    pub text: String,
}

/// A forest map as the app's API and `pathwarden summary --json` give it:
/// the map, its words filled in ([`ForestMap::derive`]), with its
/// [`Headline`].
#[derive(Debug, Serialize)]
pub struct Document {
    #[serde(flatten)]
    pub map: ForestMap,
    pub headline: Headline,
}

impl ForestMap {
    /// Whether there is more than one domain to map.
    pub fn is_multi_domain(&self) -> bool {
        self.domains.len() > 1
    }

    pub fn domain(&self, name: &str) -> Option<&DomainNode> {
        self.domains
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
    }

    /// The map with its words and headline, as the API and `summary
    /// --json` give it; a map saved before its words existed gets them.
    pub fn document(&self) -> Document {
        let mut map = self.clone();
        map.derive();
        Document {
            headline: map.headline(),
            map,
        }
    }

    pub fn headline(&self) -> Headline {
        use crate::text::count;
        let between_forests = self.trusts.iter().filter(|t| !t.intra_forest).count();
        let not_collected = self.domains.iter().filter(|d| !d.collected).count();
        let sid_history_abuse = self
            .trusts
            .iter()
            .filter(|t| t.abusable_sid_history)
            .count();
        let sid_filtering_unknown = self
            .trusts
            .iter()
            .filter(|t| t.sid_filtering_unknown())
            .count();
        let mut detail = count(self.trusts.len(), "trust", "trusts");
        if !self.trusts.is_empty() {
            detail.push_str(&format!(", {between_forests} between forests"));
        }
        detail.push_str(&if not_collected == 0 {
            " · all collected".to_string()
        } else {
            format!(" · {not_collected} not collected")
        });
        let mut status = Vec::new();
        if sid_history_abuse > 0 {
            status.push(Status {
                kind: "abuse",
                text: format!(
                    "{} with SID history abuse",
                    count(sid_history_abuse, "trust", "trusts")
                ),
            });
        }
        if sid_filtering_unknown > 0 {
            status.push(Status {
                kind: "unknown",
                text: format!(
                    "{}: SID filtering unknown",
                    count(sid_filtering_unknown, "trust", "trusts")
                ),
            });
        }
        if status.is_empty() {
            status.push(Status {
                kind: "none",
                text: "No SID history abuse".into(),
            });
        }
        Headline {
            domains: self.domains.len(),
            forests: self.forests.len(),
            trusts: self.trusts.len(),
            between_forests,
            not_collected,
            sid_history_abuse,
            sid_filtering_unknown,
            lead: format!(
                "{} in {}",
                count(self.domains.len(), "domain", "domains"),
                count(self.forests.len(), "forest", "forests")
            ),
            detail,
            status,
            focus: self.focus(),
        }
    }
}

/// The first `cap` of `sorted` (grouped by `kind`, in order), shared out
/// between the kinds in turn: a crossing with hundreds of memberships
/// still lists its admin rights and ACEs.
fn share_out<T, K: PartialEq + Copy>(sorted: Vec<T>, cap: usize, kind: impl Fn(&T) -> K) -> Vec<T> {
    if sorted.len() <= cap {
        return sorted;
    }
    let mut groups: Vec<(K, Vec<T>)> = Vec::new();
    for x in sorted {
        let k = kind(&x);
        match groups.last_mut() {
            Some((g, list)) if *g == k => list.push(x),
            _ => groups.push((k, vec![x])),
        }
    }
    let mut take = vec![0; groups.len()];
    let mut left = cap;
    while left > 0 {
        let mut gave = false;
        for (i, (_, list)) in groups.iter().enumerate() {
            if left > 0 && take[i] < list.len() {
                take[i] += 1;
                left -= 1;
                gave = true;
            }
        }
        if !gave {
            break;
        }
    }
    groups
        .into_iter()
        .zip(take)
        .flat_map(|((_, list), n)| list.into_iter().take(n))
        .collect()
}

/// What a right across domains is, in the order they are listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Right {
    Membership,
    Admin,
    Ace,
    SidHistory,
}

/// ACEs that grant control of their object.
fn is_ace(kind: EdgeKind) -> bool {
    use EdgeKind::*;
    matches!(
        kind,
        GenericAll
            | GenericWrite
            | WriteOwner
            | WriteDacl
            | Owns
            | AddMember
            | AddSelf
            | ForceChangePassword
            | AllExtendedRights
            | AddKeyCredentialLink
            | AddAllowedToAct
            | ReadLapsPassword
            | ReadGmsaPassword
            | SyncLapsPassword
            | WriteSpn
            | WriteAccountRestrictions
            | WriteGpLink
            | DcSync
    )
}

/// Who `r`'s domain trusts and who trusts it, as ways `(from, to)` between
/// the record's ends (0 = its source, 1 = its target).
fn ways_of(r: &TrustInfo) -> Vec<(usize, usize)> {
    match r.direction.as_str() {
        // The source trusts the target: the target's principals come in.
        "Outbound" => vec![(1, 0)],
        "Inbound" => vec![(0, 1)],
        "Bidirectional" => vec![(1, 0), (0, 1)],
        _ => Vec::new(),
    }
}

/// The key a trust's end is known by: its SID, else its name.
fn end_key(name: &str, sid: &str) -> String {
    if sid.is_empty() {
        format!("name:{}", name.to_ascii_uppercase())
    } else {
        sid.to_ascii_uppercase()
    }
}

/// The map of `g`'s domains and `stats`' trusts. `rel` says which accounts
/// are active, for the per-domain exposure ([`Relevance::from_settings`] at
/// the collection time, as the analysis uses).
pub fn forest_map(g: &AdGraph, stats: &IngestStats, rel: &Relevance) -> ForestMap {
    crate::timing::phase("forest map", || build(g, stats, rel))
}

fn build(g: &AdGraph, stats: &IngestStats, rel: &Relevance) -> ForestMap {
    let collected = crate::analyze::domain_names(g);

    // The domains, by graph node; keyed by SID, so two domains without a
    // name stay apart.
    let domain_ix: Vec<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain)
        .map(|(ix, _)| ix)
        .collect();
    let names: Vec<String> = domain_ix
        .iter()
        .map(|&ix| {
            let n = g.node(ix);
            if n.name.trim().is_empty() {
                n.id.clone()
            } else {
                n.name.clone()
            }
        })
        .collect();
    let by_name = |name: &str| {
        (!name.is_empty())
            .then(|| names.iter().position(|n| n.eq_ignore_ascii_case(name)))
            .flatten()
    };
    let by_sid: HashMap<String, usize> = domain_ix
        .iter()
        .enumerate()
        .map(|(i, &ix)| (g.node(ix).id.to_ascii_uppercase(), i))
        .collect();
    let by_end = |name: &str, sid: &str| {
        by_sid
            .get(&sid.to_ascii_uppercase())
            .copied()
            .or_else(|| sid.is_empty().then(|| by_name(name)).flatten())
    };

    // Which domain each object belongs to: its domain SID, else the SID it
    // is prefixed with or carries, else its domain name.
    let of = |n: &crate::model::Node| -> Option<usize> {
        if n.kind == NodeKind::Domain {
            return by_sid.get(&n.id.to_ascii_uppercase()).copied();
        }
        n.domain_sid
            .as_deref()
            .map(str::to_ascii_uppercase)
            .or_else(|| sid::domain_sid_of(&n.id))
            .and_then(|s| by_sid.get(&s.to_ascii_uppercase()).copied())
            .or_else(|| sid::split_prefixed(&n.id).0.and_then(by_name))
            .or_else(|| n.domain.as_deref().and_then(by_name))
    };
    let owner: Vec<Option<usize>> = g.nodes().map(|(_, n)| of(n)).collect();

    // Forests: domains joined by same-forest trusts.
    let mut comp: Vec<usize> = (0..domain_ix.len()).collect();
    let at: HashMap<NodeIndex, usize> = domain_ix
        .iter()
        .enumerate()
        .map(|(i, &ix)| (ix, i))
        .collect();
    for start in 0..domain_ix.len() {
        if comp[start] != start {
            continue;
        }
        let mut stack = vec![start];
        while let Some(v) = stack.pop() {
            for e in g.inner().edges(domain_ix[v]) {
                if *e.weight() != EdgeKind::SameForestTrust {
                    continue;
                }
                if let Some(&w) = at.get(&e.target()) {
                    if w != start && comp[w] == w && w > start {
                        comp[w] = start;
                        stack.push(w);
                    }
                }
            }
        }
    }

    // Counts and exposure, and who holds Enterprise or Schema Admins.
    #[derive(Default)]
    struct Counts {
        users: usize,
        computers: usize,
        groups: usize,
        tier_zero: usize,
        enterprise: bool,
        population: Vec<NodeIndex>,
    }
    let mut counts: Vec<Counts> = domain_ix.iter().map(|_| Counts::default()).collect();
    for (ix, n) in g.nodes() {
        let Some(d) = owner[ix.index()] else { continue };
        if n.placeholder {
            continue;
        }
        let c = &mut counts[d];
        match n.kind {
            NodeKind::User => c.users += 1,
            NodeKind::Computer => c.computers += 1,
            NodeKind::Group => {
                c.groups += 1;
                c.enterprise |= matches!(sid::domain_rid(&n.id), Some(518 | 519));
            }
            _ => {}
        }
        if n.tier_zero {
            c.tier_zero += 1;
        }
    }
    for ix in analysis::population(g) {
        if let Some(d) = owner[ix.index()] {
            counts[d].population.push(ix);
        }
    }
    let tree = analysis::reach_targets(g, analysis::tier_zero(g), None);

    // Roles: the forest root holds Enterprise Admins; other domains with no
    // parent in the forest are tree roots.
    let has_parent = |i: usize| {
        let name = names[i].to_ascii_uppercase();
        (0..names.len()).any(|j| {
            j != i
                && comp[j] == comp[i]
                && name.ends_with(&format!(".{}", names[j].to_ascii_uppercase()))
        })
    };
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, &c) in comp.iter().enumerate() {
        members.entry(c).or_default().push(i);
    }
    // Domains at an end of a forest trust: each is its forest's root.
    let mut forest_trust_end = vec![false; names.len()];
    for t in stats
        .trusts
        .iter()
        .filter(|t| t.trust_type.eq_ignore_ascii_case("forest"))
    {
        for i in [
            by_end(&t.source, &t.source_sid),
            by_end(&t.target, &t.target_sid),
        ]
        .into_iter()
        .flatten()
        {
            forest_trust_end[i] = true;
        }
    }
    let is_collected = |i: usize| collected.iter().any(|d| d == &names[i]);
    let mut role = vec![DomainRole::Child; names.len()];
    let mut forests: Vec<(String, Vec<usize>)> = Vec::new();
    for (_, mut list) in members {
        list.sort_by(|&a, &b| names[a].cmp(&names[b]));
        let root = list
            .iter()
            .copied()
            .find(|&i| counts[i].enterprise)
            .or_else(|| list.iter().copied().find(|&i| !has_parent(i)))
            .unwrap_or(list[0]);
        for &i in &list {
            role[i] = if list.len() == 1 && !is_collected(i) && !forest_trust_end[i] {
                DomainRole::Unknown
            } else if i == root {
                DomainRole::ForestRoot
            } else if has_parent(i) {
                DomainRole::Child
            } else {
                DomainRole::TreeRoot
            };
        }
        forests.push((names[root].clone(), list));
    }
    forests.sort_by(|a, b| a.0.cmp(&b.0));
    let mut forest_of = vec![0; names.len()];
    for (f, (_, list)) in forests.iter().enumerate() {
        for &i in list {
            forest_of[i] = f;
        }
    }

    let mut order: Vec<usize> = (0..names.len()).collect();
    order.sort_by(|&a, &b| {
        (forest_of[a], role[a], &names[a]).cmp(&(forest_of[b], role[b], &names[b]))
    });
    let domains: Vec<DomainNode> = order
        .iter()
        .map(|&i| {
            let c = &counts[i];
            let exposed = rel.exposed(&c.population, |ix| tree.reaches(ix));
            let relevant = rel.relevant(&c.population);
            DomainNode {
                name: names[i].clone(),
                sid: g.node(domain_ix[i]).id.clone(),
                forest: forest_of[i],
                collected: is_collected(i),
                role: role[i],
                users: c.users,
                computers: c.computers,
                groups: c.groups,
                tier_zero: c.tier_zero,
                population: c.population.len(),
                exposed,
                relevant_population: relevant,
                exposure_percent: (relevant > 0).then(|| analysis::pct(exposed, relevant)),
                role_text: String::new(),
                paths: None,
                note: None,
            }
        })
        .collect();

    // The trusts: records grouped by their two ends.
    let mut grouped: Vec<(String, String, Vec<&TrustInfo>)> = Vec::new();
    for t in &stats.trusts {
        let (a, b) = (
            end_key(&t.source, &t.source_sid),
            end_key(&t.target, &t.target_sid),
        );
        match grouped
            .iter_mut()
            .find(|(x, y, _)| (x == &a && y == &b) || (x == &b && y == &a))
        {
            Some((_, _, list)) => {
                if !list.contains(&t) {
                    list.push(t)
                }
            }
            None => grouped.push((a, b, vec![t])),
        }
    }
    let mut trusts: Vec<(TrustEdge, Option<(usize, usize)>)> = grouped
        .into_iter()
        .map(|(a_key, _, records)| {
            let r = records[0];
            let (a, b) = (
                by_end(&r.source, &r.source_sid),
                by_end(&r.target, &r.target_sid),
            );
            // Named as the domains are: a record written before its
            // domain's own file was read may carry its SID.
            let name = |i: Option<usize>, fallback: &str| {
                i.map_or_else(|| fallback.to_string(), |i| names[i].clone())
            };
            let ends = [name(a, &r.source), name(b, &r.target)];
            (trust_edge(&a_key, &records, ends), a.zip(b))
        })
        .collect();
    trusts.sort_by(|(a, _), (b, _)| {
        (!a.intra_forest, &a.source, &a.target).cmp(&(!b.intra_forest, &b.source, &b.target))
    });

    // Rights across domains, in one pass over the edges.
    let mut across: BTreeMap<(usize, usize), Crossing> = BTreeMap::new();
    type Listed = Vec<(Right, NodeIndex, NodeIndex, EdgeKind)>;
    let mut listed: BTreeMap<(usize, usize), Listed> = BTreeMap::new();
    for e in g.inner().edge_references() {
        let (a, b) = (e.source(), e.target());
        let (Some(from), Some(to)) = (owner[a.index()], owner[b.index()]) else {
            continue;
        };
        if from == to {
            continue;
        }
        // Within a forest, Tier Zero holds rights everywhere by design.
        let wiring = g.node(a).tier_zero && comp[from] == comp[to];
        let c = across.entry((from, to)).or_default();
        let right = match *e.weight() {
            EdgeKind::HasSidHistory => Right::SidHistory,
            _ if wiring => continue,
            EdgeKind::MemberOf if !sid::is_implicit_group(&g.node(b).id) => Right::Membership,
            EdgeKind::AdminTo => Right::Admin,
            k if is_ace(k) => Right::Ace,
            _ => continue,
        };
        match right {
            Right::Membership => c.memberships += 1,
            Right::Admin => c.admin_rights += 1,
            Right::Ace => c.aces += 1,
            Right::SidHistory => c.sid_history += 1,
        }
        listed
            .entry((from, to))
            .or_default()
            .push((right, a, b, *e.weight()));
    }
    // Each pair of domains goes to the trust between them, else (between
    // forests) to a trust between their forests, else to `indirect`.
    let mut indirect = Vec::new();
    for ((from, to), c) in across {
        if c.is_empty() {
            continue;
        }
        type Placed = (TrustEdge, Option<(usize, usize)>);
        let joins = |t: &Placed| {
            t.1.is_some_and(|(x, y)| (x, y) == (from, to) || (y, x) == (from, to))
        };
        let joins_forests = |t: &Placed| {
            !t.0.intra_forest
                && t.1.is_some_and(|(x, y)| {
                    let (fx, fy) = (comp[x], comp[y]);
                    (fx, fy) == (comp[from], comp[to]) || (fy, fx) == (comp[from], comp[to])
                })
        };
        let at = trusts.iter().position(joins).or_else(|| {
            (comp[from] != comp[to])
                .then(|| {
                    // A forest trust before an external one.
                    trusts
                        .iter()
                        .position(|t| {
                            joins_forests(t) && t.0.trust_type.eq_ignore_ascii_case("forest")
                        })
                        .or_else(|| trusts.iter().position(joins_forests))
                })
                .flatten()
        });
        let mut rights = listed.remove(&(from, to)).unwrap_or_default();
        let key = |r: &(Right, NodeIndex, NodeIndex, EdgeKind)| {
            (
                r.0,
                g.node(r.1).name.clone(),
                g.node(r.2).name.clone(),
                r.3.as_str(),
            )
        };
        rights.sort_by_cached_key(key);
        let rights = share_out(rights, RIGHTS_LISTED, |r| r.0);
        let c = Crossing {
            from: names[from].clone(),
            to: names[to].clone(),
            rights: rights
                .into_iter()
                .map(|(_, a, b, kind)| {
                    let (x, y) = (g.node(a), g.node(b));
                    CrossingRight {
                        from: x.id.clone(),
                        from_name: x.name.clone(),
                        to: y.id.clone(),
                        to_name: y.name.clone(),
                        kind: kind.as_str().to_string(),
                    }
                })
                .collect(),
            ..c
        };
        match at {
            Some(i) => trusts[i].0.crossing.push(c),
            None => indirect.push(c),
        }
    }

    for (t, _) in &mut trusts {
        t.crossing
            .sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    }
    indirect.sort_by(|a: &Crossing, b: &Crossing| (&a.from, &a.to).cmp(&(&b.from, &b.to)));

    let mut map = ForestMap {
        forests: forests
            .into_iter()
            .map(|(name, list)| {
                let mut domains: Vec<String> = list.iter().map(|&i| names[i].clone()).collect();
                domains.sort();
                Forest { name, domains }
            })
            .collect(),
        domains,
        trusts: trusts.into_iter().map(|(t, _)| t).collect(),
        indirect,
    };
    map.derive();
    map
}

/// One trust from its records (one per domain that recorded it), its ends
/// the first record's source and target, named `names`; `a_key` is the
/// [`end_key`] of its source.
fn trust_edge(a_key: &str, records: &[&TrustInfo], names: [String; 2]) -> TrustEdge {
    let first = records[0];
    // Each record, as ways between ends 0 (the first record's source) and 1.
    let side = |r: &TrustInfo| usize::from(end_key(&r.source, &r.source_sid) != a_key);
    let mut ways_by_side: [Vec<(usize, usize)>; 2] = [Vec::new(), Vec::new()];
    let mut seen = [false; 2];
    for r in records {
        let s = side(r);
        seen[s] = true;
        for (f, t) in ways_of(r) {
            // Record ends 0/1 are its source/target; on side 1 they swap.
            let (f, t) = if s == 0 { (f, t) } else { (1 - f, 1 - t) };
            if !ways_by_side[s].contains(&(f, t)) {
                ways_by_side[s].push((f, t));
            }
        }
    }
    let records_disagree = seen[0] && seen[1] && {
        let (mut x, mut y) = (ways_by_side[0].clone(), ways_by_side[1].clone());
        x.sort_unstable();
        y.sort_unstable();
        x != y
    };
    let mut ways: Vec<(usize, usize)> = ways_by_side.concat();
    ways.sort_unstable();
    ways.dedup();

    let ways: Vec<TrustWay> = ways
        .into_iter()
        .map(|(f, t)| {
            // The trusting side's record of a way it trusts.
            let governing = records.iter().copied().find(|r| {
                side(r) == t && matches!(r.direction.as_str(), "Outbound" | "Bidirectional")
            });
            // A forest trust's flag can't tell default filtering from SID
            // history enabled: without its attributes, filtering is unknown.
            let flag_only = governing.is_some_and(TrustInfo::sid_filtering_flag_only);
            let abuse = !flag_only && governing.is_some_and(TrustInfo::sid_history_abusable);
            TrustWay {
                from: names[f].clone(),
                to: names[t].clone(),
                sid_filtering: governing.filter(|_| !flag_only).map(|r| r.sid_filtering),
                selective_auth: governing.and_then(|r| r.selective_auth),
                attributes_known: governing.is_some_and(|r| r.trust_attributes.is_some()),
                sid_filtering_unknown: flag_only.then(|| FOREST_FLAG_UNKNOWN.to_string()),
                sid_history_abuse: abuse,
                rid_1000_and_up: abuse,
                filtering: String::new(),
                filtering_note: None,
                selective: String::new(),
                abuse_text: None,
            }
        })
        .collect();
    let all = |get: fn(&TrustWay) -> Option<bool>| {
        if ways.iter().any(|w| get(w) == Some(false)) {
            Some(false)
        } else if !ways.is_empty() && ways.iter().all(|w| get(w) == Some(true)) {
            Some(true)
        } else {
            None
        }
    };
    let direction = match (
        ways.iter().any(|w| w.to == names[0]),
        ways.iter().any(|w| w.to == names[1]),
    ) {
        (true, true) => "Bidirectional",
        (true, false) => "Outbound",
        (false, true) => "Inbound",
        (false, false) => "Disabled",
    };
    let intra_forest = records.iter().any(|r| r.is_same_forest());
    TrustEdge {
        source: names[0].clone(),
        target: names[1].clone(),
        trust_type: first.trust_type.clone(),
        direction: direction.into(),
        transitive: first.transitive,
        intra_forest,
        sid_filtering: all(|w| w.sid_filtering),
        selective_auth: all(|w| w.selective_auth),
        enables_forest_takeover: intra_forest && !ways.is_empty(),
        abusable_sid_history: ways.iter().any(|w| w.sid_history_abuse),
        ways,
        records_disagree,
        findings: records
            .iter()
            .filter(|r| r.sid_history_abusable())
            .map(|r| crate::findings::fingerprint("PW-012", &[&r.source, &r.target]))
            .collect(),
        records: records.iter().map(|&r| r.clone()).collect(),
        crossing: Vec::new(),
        flags: Vec::new(),
        pw012_note: None,
        crossing_note: None,
        way_word: String::new(),
    }
}

mod words;
pub use words::*;

mod trusted;
pub use trusted::{
    off_other_domain, readable, trusted_domains, Pick, TrustedDomain, MAYBE_SELECTIVE,
    OFF_BEYOND_FOREST, OFF_DISABLED, OFF_ONE_WAY, OFF_SID_ONLY,
};

#[cfg(test)]
mod tests;
