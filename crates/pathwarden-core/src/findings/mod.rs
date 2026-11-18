//! Findings: concrete, ticketable problems. Each carries a fingerprint that
//! stays the same across runs for as long as the same problem exists, so a
//! ticketing integration can update or close tickets instead of duplicating them.

mod adcs;
mod entra;
mod opengraph;
mod planes;
mod rules;
mod sysvol;

pub use rules::PW012_FLAG_ONLY_SEVERITY;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use petgraph::graph::{EdgeIndex, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::analysis::{self, AttackPath, ReachTree};
use crate::graph::AdGraph;
use crate::ingest::TrustInfo;
use crate::model::{EdgeKind, NodeKind};
use crate::zones::Zone;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// BloodHound Enterprise's bands for the share of principals that can
    /// abuse an attack path.
    pub fn from_exposure(percent: f64) -> Self {
        match percent {
            p if p >= 95.0 => Severity::Critical,
            p if p >= 80.0 => Severity::High,
            p if p >= 40.0 => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// "Critical", as pages and reports show it.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// The levels a team can set a rule's severity to ([`SetSeverity`]),
    /// most severe first: not Info.
    pub const SETTABLE: [Severity; 4] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    /// A level a rule's severity can be set to ("critical", any case);
    /// the error is a sentence.
    pub fn parse_settable(s: &str) -> Result<Self, String> {
        match s.trim().parse::<Severity>() {
            Ok(Severity::Info) | Err(_) => Err(format!(
                "\"{}\" is not a severity a rule can be set to: use critical, high, medium or low.",
                s.trim()
            )),
            Ok(v) => Ok(v),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "unknown severity '{s}' (info, low, medium, high, critical)"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Affected {
    pub id: String,
    pub name: String,
    pub kind: NodeKind,
    /// Why this object is listed, when it differs per object ("last logon
    /// 412 days ago").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Exploitable relationships leading to a protected zone.
    AttackPath,
    /// Weaknesses that are not (yet) part of a path: list-based checks.
    Hygiene,
}

impl FromStr for Category {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_', ' '], "").as_str() {
            "attackpath" | "attackpaths" => Ok(Category::AttackPath),
            "hygiene" => Ok(Category::Hygiene),
            _ => Err(format!("unknown category '{s}' (attack-path, hygiene)")),
        }
    }
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::AttackPath => "attack path",
            Category::Hygiene => "hygiene",
        }
    }
}

/// How many principals (enabled users and computers outside Tier Zero) can
/// abuse a finding: those that can reach one of its entry points.
#[derive(Debug, Clone, Serialize)]
pub struct Exposure {
    /// The domain whose population was measured (the finding's own domain),
    /// or `None` when measured across every collected domain.
    pub scope: Option<String>,
    pub principals: usize,
    /// The denominator, on the same basis as the Posture page
    /// ([`crate::analysis::Relevance`]): the scope's active users and
    /// computers. Inactive ones don't count, in `principals` either.
    pub population: usize,
    pub percent: f64,
}

/// Who has to be controlled to abuse a finding.
#[derive(Debug, Clone, Default)]
pub(crate) enum Entry {
    #[default]
    None,
    Principals(Vec<NodeIndex>),
    /// Any authenticated principal (Kerberoasting, coercion, ...).
    Everyone,
}

/// [`Finding::entry_points`]: who has to be controlled to abuse a finding.
#[derive(Debug, Clone, Copy)]
pub enum EntryPoints<'a> {
    /// Not an attack path (hygiene).
    None,
    /// Controlling any of these objects.
    Principals(&'a [NodeIndex]),
    /// Any authenticated principal.
    Everyone,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub category: Category,
    /// Severity used for sorting and filtering: from exposure for attack paths
    /// (unless configured otherwise), from the rule for hygiene.
    pub severity: Severity,
    /// The rule's own assessment, independent of exposure.
    pub rule_severity: Severity,
    /// When the team set the rule's severity in the settings
    /// (`[rules.severities]`), the severity the finding would have had
    /// without it: from exposure or the rule. `severity` is then the set
    /// one. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_default: Option<Severity>,
    pub exposure: Option<Exposure>,
    pub fingerprint: String,
    pub title: String,
    /// The change that fixes it, as one sentence ("Remove the Group Policy
    /// security permissions EVERYONE holds on DEFAULT DOMAIN POLICY."),
    /// worded as the report's plan steps. Only for findings about one
    /// relationship between two objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headline: Option<String>,
    pub domain: Option<String>,
    pub summary: String,
    pub remediation: String,
    pub affected: Vec<Affected>,
    /// An example attack path showing why this matters.
    pub path: Option<AttackPath>,
    pub references: Vec<&'static str>,
    /// Set when a configured suppression matched; holds its reason.
    pub suppressed: Option<String>,
    /// With `suppressed`: who accepted it, where, when, and its notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<crate::config::Acceptance>,
    /// What finding actions did on it, from the history's `actions.json`
    /// ([`crate::action_log::annotate`]): its records and how many runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<crate::action_log::FindingActions>,
    /// OpenGraph sources whose data this finding's evidence uses
    /// ("TaskHound"). Empty when it rests on AD data alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Name-free keys of the coverage units (hosts, instances) those
    /// sources must cover before the finding can be marked fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// What of the data only contacting computers reads the finding rests
    /// on: sessions, local groups ([`crate::posture::Untargeted::of_edge`]
    /// over its sample path and evidence, and the rule's own
    /// [`crate::posture::Untargeted::of_rule`]). A run that did not read
    /// it can't tell the finding fixed.
    #[serde(default)]
    pub rests_on: crate::posture::Untargeted,
    /// Edges the finding is about besides its path (for provenance).
    #[serde(skip)]
    pub(crate) evidence: Vec<EdgeIndex>,
    #[serde(skip)]
    pub(crate) entry: Entry,
    /// Severity never drops below this, whatever the exposure: a few accounts
    /// with direct control of Tier Zero are still a domain compromise.
    #[serde(skip)]
    pub(crate) floor: Option<Severity>,
    /// Protected (Tier Zero) objects this finding leads to.
    #[serde(skip)]
    pub(crate) hits: Vec<NodeIndex>,
    /// Days since the account's password was set, for findings about a
    /// crackable password (Kerberoastable, AS-REP roastable): the report
    /// ranks them by it.
    #[serde(skip)]
    pub(crate) password_age_days: Option<i64>,
    /// What the fingerprint is made of (object IDs, a domain, a zone).
    #[serde(skip)]
    pub(crate) key: Vec<String>,
}

/// Rules whose findings always list just the objects their fingerprint is
/// made of (a right of one object over another, a zone's boundary crossed).
/// A rule that lists more than its key (an account and the hosts it is
/// logged on to) is not one: its objects can grow, and are dated. On a large
/// domain these are nearly all the findings, so the state stays small.
pub const KEYED_RULES: &[&str] = &["PW-002", "PW-022", "PW-031", "PW-032"];

/// The sentence a fix ends with that points at the report's plan.
pub const PLAN_TAB_SENTENCE: &str = "The Remediation path tab lists the smallest set of changes.";

/// A finding's text as the terminal says it: what points at a tab of the
/// report points at the command instead.
pub fn for_terminal(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains(PLAN_TAB_SENTENCE) {
        text.replace(
            PLAN_TAB_SENTENCE,
            "`pathwarden plan` lists the smallest set of changes.",
        )
        .into()
    } else {
        text.into()
    }
}

impl Finding {
    pub(crate) fn new(
        rule: &'static str,
        severity: Severity,
        key: &[&str],
        title: impl Into<String>,
    ) -> Self {
        Finding {
            rule,
            category: Category::Hygiene,
            severity,
            rule_severity: severity,
            severity_default: None,
            exposure: None,
            fingerprint: fingerprint(rule, key),
            title: title.into(),
            headline: None,
            domain: None,
            summary: String::new(),
            remediation: String::new(),
            affected: Vec::new(),
            path: None,
            references: Vec::new(),
            suppressed: None,
            accepted: None,
            actions: None,
            sources: Vec::new(),
            requires: Vec::new(),
            rests_on: Default::default(),
            evidence: Vec::new(),
            entry: Entry::None,
            floor: None,
            hits: Vec::new(),
            password_age_days: None,
            key: key.iter().map(|k| k.to_string()).collect(),
        }
    }

    /// It is of a rule whose findings list only what their fingerprint is
    /// made of ([`KEYED_RULES`]: one account's right over another), and
    /// this one does: its objects can't change without it becoming another
    /// finding, so the findings state doesn't date them.
    pub fn objects_are_its_key(&self) -> bool {
        KEYED_RULES.contains(&self.rule)
            && !self.affected.is_empty()
            && self
                .affected
                .iter()
                .all(|a| self.key.iter().any(|k| k.eq_ignore_ascii_case(&a.id)))
    }

    /// [`Finding::headline`] for the `kinds` of relationship `from` has to
    /// `to`, worded as a plan step ([`crate::report::step_headline_text`]).
    pub(crate) fn headline_for(
        mut self,
        g: &AdGraph,
        from: NodeIndex,
        to: NodeIndex,
        kinds: &[EdgeKind],
    ) -> Self {
        let (a, b) = (g.node(from), g.node(to));
        let text = crate::report::step_headline_text(&crate::report::StepWords {
            from: &a.name,
            from_kind: a.kind,
            edges: kinds,
            to: &b.name,
            to_kind: b.kind,
            to_managed: b.props.managedpassword == Some(true),
        });
        self.headline = Some(format!("{text}."));
        self
    }

    /// The age in days of the password the finding is about.
    pub(crate) fn password_age(mut self, days: Option<i64>) -> Self {
        self.password_age_days = days;
        self
    }

    /// Keeps severity at `floor` or above when it is derived from exposure.
    pub(crate) fn floor(mut self, floor: Severity) -> Self {
        self.floor = Some(floor);
        self
    }

    /// Marks this an attack path that is abused by controlling any of `ixs`.
    pub(crate) fn entry(mut self, ixs: impl IntoIterator<Item = NodeIndex>) -> Self {
        self.category = Category::AttackPath;
        self.entry = Entry::Principals(ixs.into_iter().collect());
        self
    }

    /// Marks this an attack path that any authenticated principal can abuse.
    pub(crate) fn entry_everyone(mut self) -> Self {
        self.category = Category::AttackPath;
        self.entry = Entry::Everyone;
        self
    }

    pub(crate) fn entry_everyone_if(self, cond: bool) -> Self {
        if cond {
            self.entry_everyone()
        } else {
            self
        }
    }

    /// Entry is `who`, or everyone when the abuse needs no prior foothold.
    pub(crate) fn entry_principals_or_everyone(self, who: &[NodeIndex], everyone: bool) -> Self {
        if everyone {
            self.entry_everyone()
        } else {
            self.entry(who.iter().copied())
        }
    }

    /// Protected objects this finding leads to (for the protected share).
    pub(crate) fn hits(mut self, ixs: impl IntoIterator<Item = NodeIndex>) -> Self {
        self.hits.extend(ixs);
        self
    }

    /// Protected objects this finding leads to.
    pub fn hit_objects(&self) -> &[NodeIndex] {
        &self.hits
    }

    /// Who has to be controlled to abuse this finding.
    pub fn entry_points(&self) -> EntryPoints<'_> {
        match &self.entry {
            Entry::None => EntryPoints::None,
            Entry::Principals(p) => EntryPoints::Principals(p),
            Entry::Everyone => EntryPoints::Everyone,
        }
    }

    pub(crate) fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }

    pub(crate) fn remediation(mut self, s: impl Into<String>) -> Self {
        self.remediation = s.into();
        self
    }

    pub(crate) fn domain(mut self, d: Option<&String>) -> Self {
        self.domain = d.cloned();
        self
    }

    pub(crate) fn affect(self, g: &AdGraph, ixs: impl IntoIterator<Item = NodeIndex>) -> Self {
        self.affect_with(g, ixs.into_iter().map(|ix| (ix, None)))
    }

    /// [`Finding::affect`] with a per-object detail.
    pub(crate) fn affect_with(
        mut self,
        g: &AdGraph,
        items: impl IntoIterator<Item = (NodeIndex, Option<String>)>,
    ) -> Self {
        self.affected.extend(items.into_iter().map(|(ix, detail)| {
            let n = g.node(ix);
            Affected {
                id: n.id.clone(),
                name: n.name.clone(),
                kind: n.kind,
                detail,
            }
        }));
        self
    }

    pub(crate) fn path(mut self, p: Option<AttackPath>) -> Self {
        self.path = p;
        self
    }

    pub(crate) fn refs(mut self, r: &[&'static str]) -> Self {
        self.references.extend_from_slice(r);
        self
    }

    /// Edges this finding is about, besides its path.
    pub(crate) fn evidence(mut self, edges: impl IntoIterator<Item = EdgeIndex>) -> Self {
        self.evidence.extend(edges);
        self
    }
}

/// Most coverage units one finding records; past that it depends on its
/// sources' whole coverage (see [`crate::opengraph::coverage`]).
pub const MAX_REQUIRES: usize = 32;

/// Fills in each finding's OpenGraph `sources` and `requires` from the
/// external edges in its evidence and sample path (and the SYSVOL edges,
/// whose parts are sources too).
fn attach_sources(g: &AdGraph, findings: &mut [Finding]) {
    // The domains whose sidecar recorded the GPO local groups part: a
    // right a linked GPO grants there rests on it.
    let gpo_local: HashSet<String> = g
        .sysvol_domains()
        .iter()
        .filter(|d| d.checks.gpo_local_groups.is_some())
        .map(|d| d.domain.trim().to_ascii_uppercase())
        .collect();
    if !g.has_og_edges() && gpo_local.is_empty() {
        return;
    }
    let planes = plane_sources(g);
    for f in findings.iter_mut() {
        let edges = f
            .evidence
            .iter()
            .chain(f.path.iter().flat_map(|p| p.edges.iter()));
        // Sources a rule set itself (SYSVOL data with no edge) are kept.
        let mut sources: BTreeSet<String> = f.sources.iter().cloned().collect();
        let mut units: BTreeSet<String> = f.requires.iter().cloned().collect();
        // A path to a system that is Tier Zero only because the built-in
        // collector's sidecar shows it manages Tier Zero rests on it.
        // So does a path that runs through one.
        let through = f
            .path
            .iter()
            .flat_map(|p| p.edges.iter())
            .filter_map(|&e| g.inner().edge_endpoints(e))
            .flat_map(|(a, b)| [a, b]);
        for h in f.hits.iter().copied().chain(through) {
            if let Some(s) = planes.get(&h) {
                sources.extend(s.iter().cloned());
            }
        }
        for &e in edges {
            if !gpo_local.is_empty() && !g.gpo_grants(e).is_empty() {
                let domain = g
                    .inner()
                    .edge_endpoints(e)
                    .and_then(|(_, to)| g.node(to).domain.as_deref())
                    .map(str::to_ascii_uppercase);
                if let Some(d) = domain.filter(|d| gpo_local.contains(d)) {
                    sources.insert(crate::sysvol::Part::GpoLocalGroups.source(&d));
                }
            }
            let Some(origin) = g.edge_origin(e) else {
                continue;
            };
            let name = g.source_name(origin.source).to_string();
            if crate::storedcreds::is_source(&name) {
                // A computer's services, its scheduled tasks, or both.
                for (source, u) in crate::storedcreds::edge_units(g, e) {
                    units.insert(crate::opengraph::host_unit_key(&source, &u));
                    sources.insert(source);
                }
                sources.insert(name);
                continue;
            }
            if let Some(u) = &origin.unit {
                units.insert(crate::opengraph::unit_key(&name, u));
            }
            sources.insert(name);
        }
        if units.len() > MAX_REQUIRES {
            units = sources
                .iter()
                .map(|s| crate::opengraph::unit_key(s, crate::opengraph::coverage::ALL_UNITS))
                .collect();
        }
        f.sources = sources.into_iter().collect();
        f.requires = units.into_iter().collect();
    }
}

/// The management servers made Tier Zero because of what the built-in
/// collector's sidecar shows (WSUS from the registry policy, SCCM narrowed
/// by the site objects), with the sources each rests on. Empty without
/// that data.
fn plane_sources(g: &AdGraph) -> HashMap<NodeIndex, Vec<String>> {
    let any = !g.host_probes().is_empty()
        || g.sysvol_domains()
            .iter()
            .any(|d| !d.policy.is_empty() || !d.sccm.sites.is_empty());
    if !any {
        return HashMap::new();
    }
    let mut out: HashMap<NodeIndex, Vec<String>> = HashMap::new();
    for d in crate::mgmt::detect(g) {
        if d.tier_zero.is_none() || d.sources.is_empty() {
            continue;
        }
        if !crate::mgmt::is_plane_reason(g.node(d.object)) {
            continue;
        }
        let e = out.entry(d.object).or_default();
        for s in d.sources {
            if !e.contains(&s) {
                e.push(s);
            }
        }
    }
    out
}

/// Most computers one finding records for its sessions, and for its local
/// groups; past that it rests on every computer of that kind
/// ([`crate::opengraph::hosts::ANY_HOST`]).
pub const MAX_HOST_REQUIRES: usize = 256;

/// Keeps a finding's session and local group units within
/// [`MAX_HOST_REQUIRES`] computers of each kind: past that, the kind's
/// units become its [`crate::opengraph::hosts::ANY_HOST`] unit.
pub(crate) fn cap_host_units(units: &mut BTreeSet<String>) {
    use crate::opengraph::hosts::{computers, ANY_HOST, LOCAL_GROUP_HOST, SESSION_HOST};
    for mark in [SESSION_HOST, LOCAL_GROUP_HOST] {
        let any = format!("{mark}{ANY_HOST}");
        let n = computers(units.iter().filter(|h| h.starts_with(mark)));
        if n > MAX_HOST_REQUIRES {
            units.retain(|h| !h.starts_with(mark));
            units.insert(any);
        }
    }
}

/// Fills in what each finding rests on of the data only contacting
/// computers reads ([`Finding::rests_on`]), and the computers it reads
/// it from in its `requires`: those its sample path and evidence have a
/// session or a local group right on, and the hosts a rule that reads
/// sessions lists (PW-004). It resolves only when they were read again
/// ([`crate::opengraph::coverage::RunSources::hold_reason`]).
fn attach_rests_on(g: &AdGraph, findings: &mut [Finding]) {
    use crate::opengraph::{hosts as units, SESSION_HOST};
    use crate::posture::Untargeted;
    for f in findings.iter_mut() {
        let edges: Vec<EdgeIndex> = f
            .evidence
            .iter()
            .chain(f.path.iter().flat_map(|p| p.edges.iter()))
            .copied()
            .collect();
        f.rests_on = edges
            .iter()
            .map(|&e| Untargeted::of_edge(g.inner()[e]))
            .fold(Untargeted::of_rule(f.rule), Untargeted::or);
        let mut hosts: BTreeSet<String> = edges
            .iter()
            .flat_map(|&e| units::edge_units(g, e))
            .collect();
        let reads_sessions = crate::posture::HOST_DATA_RULES
            .iter()
            .any(|(r, part)| *r == f.rule && *part == crate::posture::SESSIONS);
        if reads_sessions {
            for a in f.affected.iter().filter(|a| a.kind == NodeKind::Computer) {
                let bits = g.lookup(&a.id).map_or(0, |ix| g.node(ix).props.host_lists);
                hosts.extend(units::units(&a.id, SESSION_HOST, bits));
            }
        }
        cap_host_units(&mut hosts);
        if !hosts.is_empty() {
            let mut all: BTreeSet<String> = std::mem::take(&mut f.requires).into_iter().collect();
            all.extend(hosts);
            f.requires = all.into_iter().collect();
        }
    }
}

/// `RULE-<fnv1a64 of rule and key parts>`. FNV-1a is used instead of std's
/// hasher because it is specified and stable across Rust releases; ticket
/// de-duplication depends on fingerprints never changing.
pub fn fingerprint(rule: &str, key: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in std::iter::once(rule).chain(key.iter().copied()) {
        for b in part.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{rule}-{h:016x}")
}

#[derive(Debug, Clone)]
pub struct RuleSettings {
    /// Unix time the analysis treats as "now".
    pub now: i64,
    /// Tier Zero accounts without a logon for this long are stale.
    pub stale_days: i64,
    /// Tier Zero passwords older than this are flagged.
    pub password_age_days: i64,
    /// krbtgt passwords older than this are flagged.
    pub krbtgt_age_days: i64,
    /// Seamless SSO keys older than this are flagged (PW-037; Microsoft
    /// recommends 30 days).
    pub sso_key_age_days: i64,
    /// Attack path severity from exposure (BloodHound Enterprise style) rather
    /// than from the rule.
    pub severity_from_exposure: bool,
    /// Severities the team set per rule (`[rules.severities]`), by rule ID
    /// in upper case: they rate every finding of the rule, whatever its
    /// exposure, its own rating or its floor.
    pub severities: BTreeMap<String, SetSeverity>,
}

/// A severity the team set for one rule, and who set it when Pathwarden
/// recorded that (the app and `pathwarden config rules set` do; a line
/// written by hand has none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSeverity {
    pub severity: Severity,
    /// [`crate::identity::Actor::user`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// [`crate::identity::Actor::computer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    /// RFC 3339, UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

impl RuleSettings {
    /// The severity set for `rule`, if any.
    pub fn set_severity(&self, rule: &str) -> Option<Severity> {
        self.severities
            .get(&rule.to_ascii_uppercase())
            .map(|s| s.severity)
    }

    /// The severities set, by rule.
    pub fn set_levels(&self) -> BTreeMap<String, Severity> {
        self.severities
            .iter()
            .map(|(k, v)| (k.clone(), v.severity))
            .collect()
    }

    /// What rated the findings ([`severity_settings_key`]): how attack
    /// paths are rated and the severities set.
    pub fn severity_key(&self) -> String {
        severity_settings_key(self.severity_from_exposure, &self.set_levels())
    }
}

/// A digest of how findings were rated: by exposure or by rule, and the
/// severities set per rule. A run records it
/// ([`crate::state::HistoryPoint::severity_settings`]), so a comparison
/// with an earlier run can tell a change of these settings from a change
/// in the environment.
pub fn severity_settings_key(by_exposure: bool, set: &BTreeMap<String, Severity>) -> String {
    let mut text = String::from(if by_exposure { "exposure" } else { "rule" });
    // A rule set to the one level it has anyway rates nothing differently.
    for (rule, s) in set
        .iter()
        .filter(|(r, s)| !is_default_level(r, **s, by_exposure))
    {
        text.push_str(&format!(";{}={}", rule.to_ascii_uppercase(), s.as_str()));
    }
    fingerprint("severities", &[&text])["severities-".len()..].to_string()
}

/// How a rule's findings are rated when no severity is set for it:
/// whether they are attack paths (rated by exposure when that is on), and
/// the levels the rule gives them itself.
pub fn default_levels(rule: &str) -> Option<(bool, &'static [Severity])> {
    rules::DEFAULT_LEVELS
        .iter()
        .find(|(id, _, _)| id.eq_ignore_ascii_case(rule))
        .map(|(_, exposure, levels)| (*exposure, *levels))
}

/// Whether setting `rule` to `s` changes nothing: without it, its findings
/// have that one level anyway (not rated by exposure, `by_exposure`, and
/// a single level of its own).
pub fn is_default_level(rule: &str, s: Severity, by_exposure: bool) -> bool {
    matches!(default_levels(rule), Some((exposure, [one])) if *one == s && !(exposure && by_exposure))
}

/// What rates a rule's findings when no severity is set for it, in a few
/// words: "exposure" for attack paths rated by exposure (`by_exposure`),
/// otherwise the rule's own level ("High"), or its levels when they
/// depend on the case ("High or Low", "Medium to Critical").
pub fn default_label(rule: &str, by_exposure: bool) -> String {
    let Some((exposure, levels)) = default_levels(rule) else {
        return if by_exposure { "exposure" } else { "the rule" }.to_string();
    };
    if exposure && by_exposure {
        return "exposure".into();
    }
    let mut v: Vec<Severity> = levels.to_vec();
    v.sort_unstable_by(|a, b| b.cmp(a));
    v.dedup();
    match v.as_slice() {
        [] => "the rule".into(),
        [one] => one.label().into(),
        [a, b] => format!("{} or {}", a.label(), b.label()),
        [high, .., low] => format!("{} to {}", low.label(), high.label()),
    }
}

/// Rates every finding of a rule whose severity is set with the set
/// severity, keeping the one it would have had as
/// [`Finding::severity_default`].
pub fn apply_set_severities(settings: &RuleSettings, findings: &mut [Finding]) {
    if settings.severities.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        if let Some(s) = settings.set_severity(f.rule) {
            f.severity_default = Some(f.severity_default.unwrap_or(f.severity));
            f.severity = s;
        }
    }
}

impl Default for RuleSettings {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        RuleSettings {
            now,
            stale_days: 90,
            password_age_days: 365,
            krbtgt_age_days: 180,
            sso_key_age_days: 30,
            severity_from_exposure: true,
            severities: BTreeMap::new(),
        }
    }
}

/// Shared, precomputed state for rules.
pub struct Context<'a> {
    pub graph: &'a AdGraph,
    pub trusts: &'a [TrustInfo],
    pub settings: &'a RuleSettings,
    pub zones: &'a [Zone],
    to_tier_zero: ReachTree,
    /// Which principals are active: the denominator of per-finding exposure.
    pub relevance: analysis::Relevance,
}

impl<'a> Context<'a> {
    pub fn new(graph: &'a AdGraph, trusts: &'a [TrustInfo], settings: &'a RuleSettings) -> Self {
        let to_tier_zero = crate::timing::phase("reach to tier zero", || {
            analysis::reach_targets(graph, analysis::tier_zero(graph), None)
        });
        Context {
            graph,
            trusts,
            settings,
            zones: &[],
            to_tier_zero,
            relevance: analysis::Relevance::from_settings(graph, settings),
        }
    }

    /// Also evaluate zone rules for these Privilege Zones.
    pub fn with_zones(mut self, zones: &'a [Zone]) -> Self {
        self.zones = zones;
        self
    }

    pub fn reaches_tier_zero(&self, ix: NodeIndex) -> bool {
        self.to_tier_zero.reaches(ix)
    }

    pub fn path_to_tier_zero(&self, ix: NodeIndex) -> Option<AttackPath> {
        let edges = self.to_tier_zero.path(ix)?;
        Some(analysis::render_path(self.graph, ix, &edges))
    }

    /// The Tier Zero object `ix`'s shortest path ends at.
    pub fn tier_zero_end(&self, ix: NodeIndex) -> Option<NodeIndex> {
        self.to_tier_zero.target(ix)
    }

    pub fn edge_path(&self, from: NodeIndex, e: EdgeIndex) -> AttackPath {
        analysis::render_path(self.graph, from, &[e])
    }

    fn days_since(&self, unix: i64) -> i64 {
        (self.settings.now - unix) / 86_400
    }
}

pub struct RuleInfo {
    pub id: &'static str,
    pub title: &'static str,
    run: fn(&Context) -> Vec<Finding>,
}

pub fn rules() -> &'static [RuleInfo] {
    rules::ALL
}

/// Runs every enabled rule, most severe findings first.
pub fn evaluate(ctx: &Context, disabled: &[String]) -> Vec<Finding> {
    let mut out: Vec<Finding> = rules::ALL
        .iter()
        .filter(|r| !disabled.iter().any(|d| d.eq_ignore_ascii_case(r.id)))
        .flat_map(|r| crate::timing::phase(&format!("rule {}", r.id), || (r.run)(ctx)))
        .collect();
    crate::timing::phase("exposure per finding", || measure_exposure(ctx, &mut out));
    // A set severity wins over exposure, the rule's own level and floors.
    apply_set_severities(ctx.settings, &mut out);
    attach_sources(ctx.graph, &mut out);
    attach_rests_on(ctx.graph, &mut out);
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.rule.cmp(b.rule))
            .then(a.title.cmp(&b.title))
    });
    out
}

/// Fills in exposure for attack path findings and, unless configured
/// otherwise, derives their severity from it.
fn measure_exposure(ctx: &Context, findings: &mut [Finding]) {
    let g = ctx.graph;
    let rel = &ctx.relevance;
    // Inactive accounts don't count, as exposed or in the denominator.
    let everywhere: Vec<NodeIndex> = analysis::population(g)
        .into_iter()
        .filter(|&p| rel.is_active(p))
        .collect();
    // Exposure is measured against the finding's own domain, so a small
    // domain's findings aren't diluted by a large one next to it.
    let mut by_domain: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    for &p in &everywhere {
        if let Some(d) = &g.node(p).domain {
            by_domain.entry(d.to_ascii_uppercase()).or_default().push(p);
        }
    }
    let scope_of = |f: &Finding| -> Option<String> {
        f.domain
            .as_ref()
            .map(|d| d.to_ascii_uppercase())
            .filter(|d| by_domain.contains_key(d))
    };
    let population = |scope: &Option<String>| -> &Vec<NodeIndex> {
        scope
            .as_ref()
            .and_then(|d| by_domain.get(d))
            .unwrap_or(&everywhere)
    };
    let key_of = |entry: &[NodeIndex]| {
        let mut key = entry.to_vec();
        key.sort_unstable();
        key.dedup();
        key
    };

    // One search per distinct set of entry points, in parallel, counting
    // every population it is needed for; the search itself is not kept
    // (at scale each one is tens of megabytes).
    let mut wanted: BTreeMap<Vec<NodeIndex>, BTreeSet<Option<String>>> = BTreeMap::new();
    for f in findings.iter() {
        if let Entry::Principals(entry) = &f.entry {
            wanted.entry(key_of(entry)).or_default().insert(scope_of(f));
        }
    }
    let jobs: Vec<(Vec<NodeIndex>, Vec<Option<String>>)> = wanted
        .into_iter()
        .map(|(k, scopes)| (k, scopes.into_iter().collect()))
        .collect();
    let counts = crate::par::map(&jobs, |(key, scopes)| {
        // A route through Tier Zero is not exposure to this finding: whoever
        // gets there has already won.
        let tree =
            analysis::reach_filtered(g, key.iter().copied(), |_| true, |n| !g.node(n).tier_zero);
        // How many of the scope's active principals it reaches.
        scopes
            .iter()
            .map(|s| population(s).iter().filter(|&&p| tree.reaches(p)).count())
            .collect::<Vec<usize>>()
    });
    let mut reached: HashMap<(Vec<NodeIndex>, Option<String>), usize> = HashMap::new();
    for ((key, scopes), counts) in jobs.into_iter().zip(counts) {
        for (scope, n) in scopes.into_iter().zip(counts) {
            reached.insert((key.clone(), scope), n);
        }
    }

    let mut active_count: HashMap<Option<String>, usize> = HashMap::new();
    for f in findings.iter_mut() {
        let scope = scope_of(f);
        let active = *active_count
            .entry(scope.clone())
            .or_insert_with(|| population(&scope).len());
        let (principals, total) = match &f.entry {
            Entry::None => continue,
            // Everyone can: the whole population is exposed, so all count.
            Entry::Everyone => {
                let n = population(&scope).len();
                (n, n)
            }
            Entry::Principals(entry) => (reached[&(key_of(entry), scope.clone())], active),
        };
        let percent = if total == 0 {
            0.0
        } else {
            100.0 * principals as f64 / total as f64
        };
        f.exposure = Some(Exposure {
            scope,
            principals,
            population: total,
            percent,
        });
        if ctx.settings.severity_from_exposure {
            f.severity = Severity::from_exposure(percent).max(f.floor.unwrap_or(Severity::Info));
        }
    }
}
