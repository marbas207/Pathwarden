//! Run-to-run state: which findings exist, since when, and what changed.
//!
//! State is a handful of small, deterministic JSON files, meant to live in a
//! local folder or a git repository:
//!
//! - `findings.json`: every finding ever seen, keyed by fingerprint, with its
//!   status (open, suppressed, resolved) and first / last seen times; and
//!   when each object a finding lists, and each edge into Tier Zero or a
//!   zone, first appeared ([`crate::introduced`])
//! - `last-run.json`: when the last run happened and what it found
//! - `history/<run>.json`: posture numbers per run, for trends
//!
//! The state holds numbers with names ([`crate::config::NAMES_WORDS`]):
//! fingerprints, rules, severities and dates, plus each finding's title,
//! which names the accounts, groups and computers it is about, and its
//! domain. (Before 0.1.7 the titles could be left out; the code that
//! reconciles still takes that switch for older callers.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::findings::{Category, Finding, Severity};
use crate::opengraph::coverage::RunSources;
use crate::opengraph::source_key;
use crate::posture::{FindingCounts, Posture};

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Suppressed,
    Resolved,
}

/// How a finding in this run relates to the previous run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Never seen before.
    New,
    /// Seen before and still present.
    Open,
    /// Was resolved and is back.
    Regressed,
    /// Present but covered by an unexpired suppression.
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedFinding {
    pub rule: String,
    pub severity: Severity,
    /// The severity it would have had with no severity set for its rule
    /// ([`Finding::severity_default`]), when the one set differs: so a
    /// later run can re-rate it under its own settings ([`crate::since`]).
    /// Absent otherwise, and in state written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<Severity>,
    pub category: Category,
    pub status: Status,
    pub first_seen: i64,
    pub last_seen: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<i64>,
    /// When it last came back after being resolved (a regression). Absent
    /// when it never did, and in state written before this was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regressed_at: Option<i64>,
    /// Resolved because its rule was turned off in the settings, not
    /// because it was fixed: not counted as fixed, and open again (not back
    /// after a fix) when the rule is on again and finds it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rule_off: bool,
    pub times_seen: u32,
    /// Only kept when the state is configured to include names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Hash of the finding's domain (no name), so a run that did not collect
    /// that domain never marks its findings resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Hashes of the OpenGraph sources its evidence came from: it resolves
    /// only in a run where they are present, whole, and with coverage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Hashes of the coverage units those sources must have covered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// When each object it lists appeared ([`crate::introduced`]). Absent
    /// in state written before objects were tracked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<crate::introduced::ObjectTrack>,
    /// What the run that last saw it did not target in its domain
    /// ([`crate::posture::SESSIONS`], [`crate::posture::LOCAL_GROUPS`]).
    /// An attack-path finding seen when sessions were read is held, not
    /// fixed, by a run that doesn't read them. Empty when that run
    /// targeted both, and in state written before this was recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_targeted: Vec<String>,
    /// What of sessions and local groups it rests on
    /// ([`crate::findings::Finding::rests_on`]), as its last sighting
    /// said. `None` in state written before this was recorded: then
    /// [`crate::posture::Untargeted::rested_on`] (both for an attack path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rests_on: Option<Vec<String>>,
}

impl TrackedFinding {
    /// What it rests on of sessions and local groups.
    pub fn rested_on(&self) -> crate::posture::Untargeted {
        match &self.rests_on {
            Some(parts) => crate::posture::Untargeted::from_parts(parts),
            None => crate::posture::Untargeted::rested_on(
                &self.rule,
                self.category == Category::AttackPath,
            ),
        }
    }
}

/// Which previously open findings this run may resolve.
#[derive(Debug, Clone)]
pub struct ResolveScope {
    /// Scope keys of the domains present in this run's collection; `None`
    /// means everything was collected.
    pub collected: Option<std::collections::HashSet<String>>,
    /// False when the collection looks incomplete (for example much smaller
    /// than the last one): nothing is resolved, everything is held.
    pub allow_resolve: bool,
    /// The OpenGraph sources of this run and what they covered.
    pub sources: RunSources,
    /// OpenGraph sources the last run had and this one lacks (or read only
    /// partly): attack-path findings are held, since a path may have run
    /// through their edges without its sample path showing it.
    pub missing_sources: Vec<String>,
    /// Computers the last run had a session, a local group right or a
    /// stored credential on that this run didn't read again in full
    /// ([`RunSources::missing_hosts_since`]): findings that exist because
    /// an account reaches Tier Zero by any path
    /// ([`crate::posture::REACH_RULES`]) are held. Others are held by their
    /// own `requires`.
    pub missing_hosts: Vec<String>,
    /// The last run didn't record its computers (`LastRun::hosts` absent):
    /// [`ResolveScope::with_legacy_hosts`].
    pub legacy_hosts: bool,
    /// Rules turned off in this run's settings: their open findings are
    /// set aside as no longer checked ([`TrackedFinding::rule_off`]), not
    /// fixed.
    pub rules_off: std::collections::HashSet<String>,
    /// What this run did not target, by the scope key of each domain that
    /// lacks something (sessions, local groups). An attack-path finding
    /// last seen in a run that targeted what its domain lacks now is held:
    /// its path may have run through a session or an admin right this run
    /// did not read.
    pub not_targeted: std::collections::HashMap<String, crate::posture::Untargeted>,
}

impl ResolveScope {
    pub fn everything() -> Self {
        ResolveScope {
            collected: None,
            allow_resolve: true,
            sources: RunSources::default(),
            missing_sources: Vec::new(),
            missing_hosts: Vec::new(),
            legacy_hosts: false,
            rules_off: Default::default(),
            not_targeted: Default::default(),
        }
    }

    pub fn domains(domains: &[String], allow_resolve: bool) -> Self {
        ResolveScope {
            collected: Some(domains.iter().map(|d| scope_key(d)).collect()),
            ..ResolveScope::everything()
        }
        .allowing(allow_resolve)
    }

    fn allowing(mut self, allow_resolve: bool) -> Self {
        self.allow_resolve = allow_resolve;
        self
    }

    /// Adds what this run did not target, per domain by name
    /// ([`crate::posture::untargeted_domains`]).
    pub fn with_untargeted(mut self, domains: &[(String, crate::posture::Untargeted)]) -> Self {
        self.not_targeted = domains.iter().map(|(d, u)| (scope_key(d), *u)).collect();
        self
    }

    /// What this run did not target where `domain` (a scope key) is: every
    /// domain's gaps together when the finding has none.
    fn untargeted_at(&self, scope: Option<&str>) -> crate::posture::Untargeted {
        match scope {
            Some(s) => self.not_targeted.get(s).copied().unwrap_or_default(),
            None => self
                .not_targeted
                .values()
                .fold(Default::default(), |a, b| a.or(*b)),
        }
    }

    /// What this run didn't target for a finding seen now, as recorded.
    fn not_targeted_for(&self, domain: Option<&str>) -> Vec<String> {
        self.untargeted_at(domain.map(scope_key).as_deref()).parts()
    }

    /// A finding that may have rested on a session or an admin right its
    /// sightings read and this run did not ([`TrackedFinding::rested_on`]).
    fn lost_targeting(&self, t: &TrackedFinding) -> bool {
        use crate::posture::Untargeted;
        self.untargeted_at(t.scope.as_deref())
            .lost_since(Untargeted::from_parts(&t.not_targeted))
            .and(t.rested_on())
            .any()
    }

    /// Adds the rules turned off in the settings (`[rules] disabled`).
    pub fn with_rules_off(mut self, rules: &[String]) -> Self {
        self.rules_off = rules
            .iter()
            .map(|r| r.trim().to_ascii_uppercase())
            .collect();
        self
    }

    /// Adds this run's OpenGraph sources, and notes those of `previous`
    /// (the last run's source keys and hosts) that are missing now.
    pub fn with_sources(mut self, mut sources: RunSources, previous: &[String]) -> Self {
        self.missing_sources = sources
            .missing_since(previous)
            .into_iter()
            .cloned()
            .collect();
        sources.note_missing(previous);
        let mut missing: Vec<String> = sources.missing_hosts.iter().cloned().collect();
        missing.sort_unstable();
        self.missing_hosts = missing;
        self.sources = sources;
        self
    }

    /// Marks the last run as recorded before runs recorded their computers
    /// (`LastRun::hosts` absent): a finding that rests on sessions or local
    /// groups without saying on which computers is held while any computer
    /// of that kind isn't read ([`Self::legacy_hold`]).
    pub fn with_legacy_hosts(mut self, legacy: bool) -> Self {
        self.legacy_hosts = legacy;
        self
    }

    /// What of sessions and local groups `t` rests on without listing its
    /// computers, when the last run didn't record them and a computer of
    /// that kind isn't read this run: the kinds to hold it for.
    fn legacy_hold(&self, t: &TrackedFinding) -> crate::posture::Untargeted {
        use crate::opengraph::{LOCAL_GROUP_HOST, SESSION_HOST};
        // Reach findings are held by the computers runs record, from the
        // next run on ([`crate::opengraph::hosts::SEEDED`]).
        if !self.legacy_hosts || crate::posture::is_reach_rule(&t.rule) {
            return Default::default();
        }
        let lists = |mark: &str| t.requires.iter().any(|u| u.starts_with(mark));
        let rested = t.rested_on();
        crate::posture::Untargeted {
            sessions: rested.sessions
                && !lists(SESSION_HOST)
                && self.sources.any_unread(SESSION_HOST),
            local_groups: rested.local_groups
                && !lists(LOCAL_GROUP_HOST)
                && self.sources.any_unread(LOCAL_GROUP_HOST),
        }
    }

    fn rule_off(&self, t: &TrackedFinding) -> bool {
        self.rules_off.contains(&t.rule.to_ascii_uppercase())
    }

    fn may_resolve(&self, t: &TrackedFinding) -> bool {
        self.allow_resolve
            && match (&self.collected, &t.scope) {
                (Some(collected), Some(scope)) => collected.contains(scope),
                _ => true,
            }
            && !(t.category == Category::AttackPath && !self.missing_sources.is_empty())
            && self.sources.hold_reason(&t.sources, &t.requires).is_none()
            && !(crate::posture::is_reach_rule(&t.rule) && self.sources.missing_reach_hosts())
            && self.legacy_hold(t).none()
            && !self.lost_targeting(t)
    }

    /// `t`'s units from its last sighting that this run still didn't read
    /// again (a computer down twice): a sighting keeps them, so a finding
    /// seen through another computer doesn't forget them.
    fn still_unread(&self, t: &TrackedFinding) -> Vec<String> {
        t.requires
            .iter()
            .filter(|u| self.sources.still_unread(u))
            .cloned()
            .collect()
    }
}

/// What reconciling needs of a finding: a full [`Finding`] from an analysis,
/// or an [`ObservedFinding`] read back from a saved event document (to
/// import an earlier analysis into the state).
pub trait Observed {
    fn fingerprint(&self) -> &str;
    fn rule(&self) -> &str;
    fn severity(&self) -> Severity;
    /// The severity without the one set for its rule, when one was set.
    fn default_severity(&self) -> Option<Severity> {
        None
    }
    fn category(&self) -> Category;
    fn title(&self) -> &str;
    fn domain(&self) -> Option<&str>;
    /// Covered by an unexpired suppression.
    fn suppressed(&self) -> bool;
    /// OpenGraph sources the evidence came from.
    fn sources(&self) -> &[String];
    /// Coverage units those sources must cover.
    fn requires(&self) -> &[String];
    /// What it rests on of sessions and local groups, when it says
    /// ([`Finding::rests_on`]).
    fn rests_on(&self) -> Option<crate::posture::Untargeted>;
    /// The IDs of the objects it lists; `None` when not known (an event
    /// saved before it listed them), which keeps what the state had.
    fn objects(&self) -> Option<Vec<&str>>;
    /// Its objects are what it is ([`Finding::objects_are_its_key`]):
    /// nothing to date. Not known of an event document, whose objects are
    /// dated.
    fn objects_are_its_key(&self) -> bool {
        false
    }
}

impl Observed for Finding {
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn rule(&self) -> &str {
        self.rule
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn default_severity(&self) -> Option<Severity> {
        self.severity_default
    }
    fn category(&self) -> Category {
        self.category
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
    fn suppressed(&self) -> bool {
        self.suppressed.is_some()
    }
    fn sources(&self) -> &[String] {
        &self.sources
    }
    fn requires(&self) -> &[String] {
        &self.requires
    }
    fn rests_on(&self) -> Option<crate::posture::Untargeted> {
        Some(self.rests_on)
    }
    fn objects(&self) -> Option<Vec<&str>> {
        Some(self.affected.iter().map(|a| a.id.as_str()).collect())
    }
    fn objects_are_its_key(&self) -> bool {
        Finding::objects_are_its_key(self)
    }
}

/// A finding as an event document (`pathwarden.event.v1`) lists it: the
/// fields reconciling needs, read back from a saved run.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservedFinding {
    pub fingerprint: String,
    pub rule: String,
    pub severity: Severity,
    #[serde(default)]
    pub severity_default: Option<Severity>,
    pub category: Category,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub suppressed: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub affected: Option<Vec<ObservedObject>>,
    /// Absent in events written before findings recorded it.
    #[serde(default)]
    pub rests_on: Option<crate::posture::Untargeted>,
}

/// An object an [`ObservedFinding`] lists: its ID is all reconciling needs.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservedObject {
    pub id: String,
}

impl Observed for ObservedFinding {
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn rule(&self) -> &str {
        &self.rule
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn default_severity(&self) -> Option<Severity> {
        self.severity_default
    }
    fn category(&self) -> Category {
        self.category
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
    fn suppressed(&self) -> bool {
        self.suppressed.is_some()
    }
    fn sources(&self) -> &[String] {
        &self.sources
    }
    fn requires(&self) -> &[String] {
        &self.requires
    }
    fn rests_on(&self) -> Option<crate::posture::Untargeted> {
        self.rests_on
    }
    fn objects(&self) -> Option<Vec<&str>> {
        self.affected
            .as_ref()
            .map(|a| a.iter().map(|o| o.id.as_str()).collect())
    }
}

/// The name-free key for a domain in the state.
pub fn scope_key(domain: &str) -> String {
    crate::findings::fingerprint("scope", &[&domain.trim().to_ascii_uppercase()])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsState {
    pub version: u32,
    pub findings: BTreeMap<String, TrackedFinding>,
    /// When objects and paths began to be tracked
    /// ([`TrackedFinding::objects`], `paths`): the first run after
    /// upgrading. Absent in state written before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked_since: Option<i64>,
    /// Edges into Tier Zero and each zone, and when each appeared
    /// ([`crate::introduced::PathsTrack`]). Recorded by runs of an analysis
    /// ([`crate::record::prepare`]); absent in state written before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<crate::introduced::PathsTrack>,
}

impl FindingsState {
    /// Keys of the sources any tracked finding's evidence came from.
    pub fn cited_sources(&self) -> std::collections::HashSet<String> {
        self.findings
            .values()
            .flat_map(|t| t.sources.iter().cloned())
            .collect()
    }
}

impl Default for FindingsState {
    fn default() -> Self {
        FindingsState {
            version: STATE_VERSION,
            findings: BTreeMap::new(),
            tracked_since: None,
            paths: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ChangeCounts {
    pub new: usize,
    pub open: usize,
    pub regressed: usize,
    pub suppressed: usize,
    pub resolved: usize,
    /// Previously open findings neither seen nor resolved, because their
    /// domain was not collected or the collection looked incomplete.
    #[serde(default)]
    pub held: usize,
    /// Previously open findings of a rule turned off in the settings: no
    /// longer checked, and not counted as resolved.
    #[serde(default)]
    pub unchecked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastRun {
    pub version: u32,
    pub run_id: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub collected_at: Option<i64>,
    pub pathwarden: String,
    pub collector_files: usize,
    /// The domains whose data was collected ([`crate::analyze::domain_names`]).
    pub domains: Vec<String>,
    /// Domains the data had an object for but did not collect: trusted
    /// domains RustHound-CE writes beside the collected one. `None` in runs
    /// recorded before `domains` left them out ([`LegacyDomains`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_domains: Option<Vec<String>>,
    /// Collected objects, to notice a collection much smaller than the last.
    #[serde(default)]
    pub objects: usize,
    pub changes: ChangeCounts,
    /// Hashes of the sources this run had data from: OpenGraph sources and
    /// SYSVOL parts that added edges ([`RunSources::keys`], see
    /// [`ResolveScope::missing_sources`]), and the computers that stored a
    /// credential, this run or unread since ([`RunSources::recorded`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Set when `sources` is as [`RunSources::keys`] writes it now. Runs
    /// recorded before listed every SYSVOL part, read or not
    /// ([`LastRun::baseline_sources`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sources_exact: bool,
    /// Units of the computers whose session, local group right or stored
    /// credential led to Tier Zero this run, and of those an earlier run had
    /// that weren't read again since ([`RunSources::recorded`]). Written as
    /// one string, the units sorted and separated by spaces. `None` in runs
    /// recorded before it was ([`ResolveScope::with_legacy_hosts`]).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "packed_hosts"
    )]
    pub hosts: Option<Vec<String>>,
    /// The Tier Zero settings files the run used, by file name only:
    /// the next run says when it has fewer. Absent in runs recorded before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings_files: Vec<crate::dcsettings::SettingsFileUse>,
}

/// [`LastRun::hosts`] as one string of units separated by spaces; also read
/// back as a list.
pub(crate) mod packed_hosts {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<String>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&v.join(" ")),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Packed(String),
            List(Vec<String>),
        }
        Ok(Option::<Form>::deserialize(d)?.map(|f| match f {
            Form::Packed(s) => s.split_whitespace().map(str::to_string).collect(),
            Form::List(v) => v,
        }))
    }
}

impl LastRun {
    /// The sources and hosts this run had data from, for comparing a later
    /// run with it (`now`); `findings` is the state this run left.
    pub fn baseline_sources(&self, now: &RunSources, findings: &FindingsState) -> Vec<String> {
        let cited = (!self.sources_exact).then(|| findings.cited_sources());
        let mut keys = now.baseline_keys(&self.sources, cited.as_ref());
        keys.extend(self.hosts.iter().flatten().cloned());
        keys
    }
}

/// The exposure basis of a record that stores `recorded` (0 when it has no
/// basis field) and a relevant population of `relevant` (0 when it has none):
/// records written by the capability-gate builds carry a relevant
/// population but no basis, so they are basis 1. See
/// [`crate::analysis::EXPOSURE_BASIS`].
pub fn exposure_basis(recorded: u8, relevant: usize) -> u8 {
    match recorded {
        0 if relevant > 0 => 1,
        b => b,
    }
}

/// What a change of exposure basis is called wherever a trend crosses one.
pub const BASIS_CHANGED: &str = "new exposure basis · not comparable";

/// One point of trend data. Small on purpose: it is written every run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPoint {
    pub version: u32,
    pub run_id: String,
    pub at: i64,
    pub collected_at: Option<i64>,
    pub tier_zero_exposure_percent: f64,
    pub tier_zero_exposed: usize,
    pub tier_zero_population: usize,
    /// The denominator of `tier_zero_exposure_percent` on the point's
    /// [`HistoryPoint::basis`]: for basis 3, the active users and computers;
    /// for basis 2, those unioned with the exposed. 0 in points written before it was recorded
    /// (basis 0), where `tier_zero_population` is the denominator.
    #[serde(default)]
    pub tier_zero_relevant_population: usize,
    /// What the exposure figures are a share of, as written
    /// ([`crate::analysis::EXPOSURE_BASIS`]); read it with
    /// [`HistoryPoint::basis`]. 0 in points written before it was recorded.
    /// The zone points share it.
    #[serde(default)]
    pub exposure_basis: u8,
    pub tier_zero_objects: usize,
    pub protection_score: Option<f64>,
    /// Tier Zero's grade ([`crate::posture::ExposureGrade`]). Absent in
    /// points written before the grade came from paths and findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_zero_grade: Option<crate::posture::ExposureGrade>,
    /// Changes in the Tier Zero remediation plan, and accounts that still
    /// reach Tier Zero after all of them. Absent in older points and when
    /// the plan was not computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<crate::posture::PlanSummary>,
    pub findings: FindingCounts,
    pub changes: ChangeCounts,
    #[serde(default)]
    pub zones: Vec<ZonePoint>,
    /// How much of the session and local group data was collected, over
    /// every domain of the run. Absent in points written before it was
    /// recorded, and when the run had no computers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<CompletenessPoint>,
    /// Scope keys ([`scope_key`]) of the domains collected, sorted: which
    /// environment the point belongs to, without naming it. Empty in points
    /// written before this was recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Scope keys of the domains the data had an object for but did not
    /// collect (trusted domains), sorted. `None` in points written before
    /// `scopes` left them out: there they are in `scopes`
    /// ([`migrate_points`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_scopes: Option<Vec<String>>,
    /// What recorded the run: `schedule` (the generated nightly scripts),
    /// `cli` (`pathwarden run` by hand or in a pipeline), `ui` (an analysis
    /// started in `pathwarden ui`) or `import` (an earlier UI analysis
    /// imported). Absent in points written before this was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by: Option<String>,
    /// The run's label ("after GPO fix"), when it was given one
    /// (`pathwarden run --label`). Absent otherwise, and in points written
    /// before labels existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// A digest of the collection the run read
    /// ([`crate::analyze::Analysis::data_digest`]), so a report of the same
    /// data is not compared with this run. Absent in points written before
    /// it was recorded, and in imported UI runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Added to a git history after a newer run was pushed first
    /// ([`crate::record::save_and_publish`], [`crate::store::Store::pull`]):
    /// its `changes` are against the run before it, while the newer run's
    /// skip it. So it is never the run a later one is compared with
    /// ([`crate::since::previous`]), and its changes are not added up with
    /// theirs. Absent (false) otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inserted: bool,
    /// The run kept the name-free keys of its accounts with a path to Tier
    /// Zero (`exposed/<run>.json`, [`crate::exposed`]). A later run's
    /// "now reach" and "no longer reach" lists compare with them. Absent
    /// (false) in points written before 0.2 and in imported runs: there is
    /// nothing to compare with, and nothing is said about it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exposed_keys: bool,
    /// How the run rated its findings, as a digest of how attack paths are
    /// rated and the severities set per rule
    /// ([`crate::findings::severity_settings_key`]), like
    /// [`HistoryPoint::basis`] for exposure: runs rated otherwise are
    /// compared like for like ([`crate::since`]). Absent in points written
    /// before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_settings: Option<String>,
    /// The severities the team set per rule for the run. Empty when none
    /// were set.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_severities: BTreeMap<String, Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePoint {
    pub zone: String,
    pub exposure_percent: f64,
    pub protection_score: Option<f64>,
    /// Objects in the zone. Absent in points written before it was recorded
    /// (as are `exposed` and `grade`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<usize>,
    /// Accounts outside the zone (and Tier Zero) with an attack path to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposed: Option<usize>,
    /// The zone's status ([`crate::posture::ExposureGrade`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<crate::posture::ExposureGrade>,
}

impl ZonePoint {
    pub fn new(z: &crate::posture::ZonePosture) -> Self {
        ZonePoint {
            zone: z.zone.clone(),
            exposure_percent: z.exposure_percent,
            protection_score: z.protection_score,
            objects: Some(z.objects),
            exposed: Some(z.exposed),
            grade: Some(z.exposure_grade),
        }
    }
}

/// Collection completeness at a point: the per-domain figures of
/// [`crate::posture::Completeness`] summed over the run's domains, with the
/// percentages worked out the same way (sessions over every computer, local
/// groups over member computers only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "CompletenessRecord")]
pub struct CompletenessPoint {
    /// Computers sessions are read from, domain controllers included.
    pub computers: usize,
    pub sessions_collected: usize,
    pub sessions_percent: f64,
    /// Member computers, the base of the local groups figures.
    pub member_computers: usize,
    pub local_groups_collected: usize,
    /// `None` when the run had no member computers (local groups don't
    /// apply).
    pub local_groups_percent: Option<f64>,
    /// Domains below [`crate::posture::LOW_PERCENT`] on either figure, of
    /// those the collection targeted.
    pub low_domains: usize,
    /// The run asked for sessions in at least one domain. The figures above
    /// count only the domains it asked: a Quick run (DC only) asks none,
    /// and its sessions are "not targeted", not 0%. In points written
    /// before it was recorded, whether the run collected any.
    pub sessions_targeted: bool,
    /// The run asked for local groups in at least one domain with member
    /// computers (`true` when none has any). In points written before it
    /// was recorded, whether the run collected any.
    pub local_groups_targeted: bool,
    /// Each domain that lacked something, as its scope key ([`scope_key`])
    /// and what it did not target ("<key>:sessions,local_groups"), sorted.
    /// Two runs compare only when these match: one domain read the
    /// directory only while another was read in full is not the same as
    /// both read in full. Empty when every domain targeted both, and in
    /// points written before it was recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untargeted_domains: Vec<String>,
}

/// A [`CompletenessPoint`] as written. Points written before the run
/// recorded what it targeted say what it collected: a run that read no
/// sessions is compared with a Quick run, which reads none either, rather
/// than taken for a Full run (its sessions would read as all removed).
#[derive(Deserialize)]
struct CompletenessRecord {
    computers: usize,
    sessions_collected: usize,
    sessions_percent: f64,
    member_computers: usize,
    local_groups_collected: usize,
    local_groups_percent: Option<f64>,
    low_domains: usize,
    sessions_targeted: Option<bool>,
    local_groups_targeted: Option<bool>,
    #[serde(default)]
    untargeted_domains: Vec<String>,
}

impl From<CompletenessRecord> for CompletenessPoint {
    fn from(r: CompletenessRecord) -> Self {
        CompletenessPoint {
            sessions_targeted: r.sessions_targeted.unwrap_or(r.sessions_collected > 0),
            local_groups_targeted: r
                .local_groups_targeted
                .unwrap_or(r.local_groups_percent.is_none() || r.local_groups_collected > 0),
            computers: r.computers,
            sessions_collected: r.sessions_collected,
            sessions_percent: r.sessions_percent,
            member_computers: r.member_computers,
            local_groups_collected: r.local_groups_collected,
            local_groups_percent: r.local_groups_percent,
            low_domains: r.low_domains,
            untargeted_domains: r.untargeted_domains,
        }
    }
}

impl CompletenessPoint {
    /// What each domain did not target, by scope key ([`scope_key`]):
    /// from [`CompletenessPoint::untargeted_domains`], or for a point
    /// written before it, what the run as a whole did not target in each of
    /// `domains`. Domains that targeted both are left out.
    pub fn untargeted_by_scope(
        &self,
        domains: &[String],
    ) -> Vec<(String, crate::posture::Untargeted)> {
        if !self.untargeted_domains.is_empty() {
            return self
                .untargeted_domains
                .iter()
                .filter_map(|d| d.split_once(':'))
                .map(|(key, parts)| {
                    let parts: Vec<String> = parts.split(',').map(str::to_string).collect();
                    (
                        key.to_string(),
                        crate::posture::Untargeted::from_parts(&parts),
                    )
                })
                .collect();
        }
        let u = self.untargeted();
        if !u.any() {
            return Vec::new();
        }
        domains.iter().map(|d| (scope_key(d), u)).collect()
    }

    /// What any of the run's domains did not target (more than
    /// [`CompletenessPoint::untargeted`] when one domain was read in full
    /// and another not).
    pub fn lacking(&self) -> crate::posture::Untargeted {
        self.untargeted_domains
            .iter()
            .filter_map(|d| d.split_once(':'))
            .map(|(_, parts)| {
                let parts: Vec<String> = parts.split(',').map(str::to_string).collect();
                crate::posture::Untargeted::from_parts(&parts)
            })
            .fold(self.untargeted(), crate::posture::Untargeted::or)
    }

    /// Nothing targeted anywhere, for the views that show the run as a
    /// whole.
    pub fn untargeted(&self) -> crate::posture::Untargeted {
        crate::posture::Untargeted {
            sessions: !self.sessions_targeted,
            local_groups: self.local_groups_percent.is_some() && !self.local_groups_targeted,
        }
    }

    /// The run's completeness, `None` when it had no computers.
    pub fn new(domains: &[crate::posture::Completeness]) -> Option<Self> {
        let sum =
            |f: fn(&crate::posture::Completeness) -> usize| domains.iter().map(f).sum::<usize>();
        if sum(|d| d.computers) == 0 {
            return None;
        }
        let any_members = domains.iter().any(|d| d.local_groups_apply());
        // Only the domains the run asked count toward each figure.
        let of = |keep: fn(&crate::posture::Completeness) -> bool,
                  f: fn(&crate::posture::Completeness) -> usize| {
            domains.iter().filter(|d| keep(d)).map(f).sum::<usize>()
        };
        let sessions = |d: &crate::posture::Completeness| d.sessions_targeted;
        let groups = |d: &crate::posture::Completeness| d.local_groups_targeted;
        let computers = of(sessions, |d| d.computers);
        let sessions_collected = of(sessions, |d| d.sessions_collected);
        let member_computers = of(groups, |d| d.member_computers);
        let local_groups_collected = of(groups, |d| d.local_groups_collected);
        let pct = |n: usize, of: usize| {
            if of == 0 {
                0.0
            } else {
                100.0 * n as f64 / of as f64
            }
        };
        Some(CompletenessPoint {
            computers,
            sessions_collected,
            sessions_percent: pct(sessions_collected, computers),
            member_computers,
            local_groups_collected,
            local_groups_percent: any_members
                .then(|| pct(local_groups_collected, member_computers)),
            low_domains: domains.iter().filter(|d| d.is_low()).count(),
            sessions_targeted: domains
                .iter()
                .any(|d| d.computers > 0 && d.sessions_targeted),
            local_groups_targeted: !any_members
                || domains
                    .iter()
                    .any(|d| d.local_groups_apply() && d.local_groups_targeted),
            untargeted_domains: {
                let mut v: Vec<String> = crate::posture::untargeted_domains(domains)
                    .into_iter()
                    .map(|(d, u)| format!("{}:{}", scope_key(&d), u.parts().join(",")))
                    .collect();
                v.sort();
                v
            },
        })
    }
}

impl HistoryPoint {
    pub fn new(
        run_id: &str,
        at: i64,
        collected_at: Option<i64>,
        posture: &Posture,
        changes: ChangeCounts,
    ) -> Self {
        let t0 = &posture.tier_zero;
        HistoryPoint {
            version: STATE_VERSION,
            run_id: run_id.to_string(),
            at,
            collected_at,
            tier_zero_exposure_percent: t0.exposure_percent,
            tier_zero_exposed: t0.exposed,
            tier_zero_population: t0.population,
            tier_zero_relevant_population: t0.relevant_population,
            exposure_basis: posture.exposure_basis,
            tier_zero_objects: t0.objects,
            protection_score: t0.protection_score,
            tier_zero_grade: Some(t0.exposure_grade),
            plan: posture.plan,
            findings: posture.findings.clone(),
            changes,
            zones: posture.zones.iter().map(ZonePoint::new).collect(),
            completeness: CompletenessPoint::new(&posture.completeness),
            scopes: Vec::new(),
            trusted_scopes: None,
            recorded_by: None,
            label: None,
            data: None,
            inserted: false,
            exposed_keys: false,
            severity_settings: (!posture.severity_settings.is_empty())
                .then(|| posture.severity_settings.clone()),
            rule_severities: posture
                .severities_set
                .iter()
                .map(|s| (s.rule.clone(), s.severity))
                .collect(),
        }
    }

    /// The exposure basis of the point's figures: 0, every enabled user and
    /// computer (points from before risk scoring); 1, the capability gate (points
    /// that recorded a relevant population but no basis); 2 and up, as
    /// recorded. Trends compare only points of the same basis.
    pub fn basis(&self) -> u8 {
        exposure_basis(self.exposure_basis, self.tier_zero_relevant_population)
    }

    /// Sets the environment from the collected domains.
    pub fn with_domains(mut self, domains: &[String]) -> Self {
        self.scopes = scopes_of(domains);
        self
    }

    /// Records the domains the data had an object for but did not collect
    /// ([`HistoryPoint::trusted_scopes`]).
    pub fn with_trusted(mut self, trusted: &[String]) -> Self {
        self.trusted_scopes = Some(scopes_of(trusted));
        self
    }

    pub fn with_recorded_by(mut self, by: &str) -> Self {
        self.recorded_by = Some(by.to_string());
        self
    }
}

/// The sorted, de-duplicated scope keys of `domains`.
pub fn scopes_of(domains: &[String]) -> Vec<String> {
    let mut s: Vec<String> = domains.iter().map(|d| scope_key(d)).collect();
    s.sort();
    s.dedup();
    s
}

/// Pathwarden 0.1.1 and earlier counted every domain object as collected,
/// trusted domains included, so a run recorded then lists more domains
/// than the same collection does now, and would look like another
/// environment. This maps such a list to the one recorded now, learned from
/// runs recorded since: one that collected `C` and saw trusted domains `T`
/// would have been recorded as `C` and `T` together.
///
/// Lists are compared ignoring case and order. Works on domain names and on
/// scope keys alike.
#[derive(Debug, Default)]
pub struct LegacyDomains {
    /// Old list (normalized) to the list recorded now; `None` when runs
    /// recorded now map it to different lists.
    map: std::collections::HashMap<Vec<String>, Option<Vec<String>>>,
    /// Lists recorded now (normalized).
    current: std::collections::HashSet<Vec<String>>,
}

impl LegacyDomains {
    /// Learns from a run recorded now.
    ///
    /// Two domains that trust each other and are collected separately (a
    /// parent and its child) were both recorded as the pair by 0.1.1. Runs
    /// recorded since map the pair to one domain or the other, so an old
    /// list mapped to two different lists is not mapped at all: those old
    /// runs stay a series of their own.
    pub fn learn(&mut self, collected: &[String], trusted: &[String]) {
        let now = normalized_set(collected.iter());
        self.current.insert(now.clone());
        if trusted.is_empty() {
            return;
        }
        let old = normalized_set(collected.iter().chain(trusted));
        match self.map.entry(old) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(Some(collected.to_vec()));
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let same = e
                    .get()
                    .as_ref()
                    .is_some_and(|c| normalized_set(c.iter()) == now);
                if !same {
                    e.insert(None);
                }
            }
        }
    }

    /// What a list recorded by an earlier version means now, when it
    /// differs and only one meaning is known. A list some run recorded now
    /// as it is stays as it is.
    pub fn map(&self, recorded: &[String]) -> Option<&[String]> {
        let key = normalized_set(recorded.iter());
        if self.current.contains(&key) {
            return None;
        }
        self.map.get(&key)?.as_deref()
    }
}

fn normalized_set<'a>(items: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut v: Vec<String> = items.map(|d| d.trim().to_ascii_uppercase()).collect();
    v.sort();
    v.dedup();
    v
}

/// Gives points written before [`HistoryPoint::trusted_scopes`] existed the
/// scopes a point of the same collection gets now ([`LegacyDomains`]), so
/// they stay in the same environment as the points recorded since.
pub fn migrate_points(points: &mut [HistoryPoint]) {
    let mut legacy = LegacyDomains::default();
    for p in points.iter() {
        if let Some(t) = &p.trusted_scopes {
            legacy.learn(&p.scopes, t);
        }
    }
    for p in points.iter_mut().filter(|p| p.trusted_scopes.is_none()) {
        if let Some(now) = legacy.map(&p.scopes) {
            p.scopes = now.to_vec();
        }
    }
}

/// A finding that disappeared in this run.
#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    pub fingerprint: String,
    pub rule: String,
    pub severity: Severity,
    pub first_seen: i64,
    pub resolved_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What finding actions did on it ([`crate::action_log::annotate`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<crate::action_log::FindingActions>,
}

pub struct Reconciled {
    pub state: FindingsState,
    /// Parallel to the current findings.
    pub changes: Vec<Change>,
    pub resolved: Vec<Resolved>,
    pub counts: ChangeCounts,
}

/// Compares this run's findings with the previous state and returns the new
/// state. `now` stamps first/last seen; `include_names` keeps titles and
/// domains in the state.
pub fn reconcile<F: Observed>(
    prev: &FindingsState,
    current: &[F],
    now: i64,
    include_names: bool,
) -> Reconciled {
    reconcile_scoped(
        prev,
        current,
        now,
        include_names,
        &ResolveScope::everything(),
    )
}

/// [`reconcile`], resolving only findings within `scope`.
pub fn reconcile_scoped<F: Observed>(
    prev: &FindingsState,
    current: &[F],
    now: i64,
    include_names: bool,
    scope: &ResolveScope,
) -> Reconciled {
    let mut state = FindingsState {
        // Paths are recorded from the analysis graph, after this.
        paths: prev.paths.clone(),
        tracked_since: prev.tracked_since,
        ..FindingsState::default()
    };
    let mut changes = Vec::with_capacity(current.len());
    let mut counts = ChangeCounts::default();

    for f in current {
        let before = prev.findings.get(f.fingerprint());
        let suppressed = f.suppressed();
        let change = match (before.map(|t| t.status), suppressed) {
            (_, true) => Change::Suppressed,
            (None, false) => Change::New,
            // Set aside while its rule was off: open all along, as far as
            // anyone checked.
            (Some(Status::Resolved), false) if before.is_some_and(|t| t.rule_off) => Change::Open,
            (Some(Status::Resolved), false) => Change::Regressed,
            (Some(_), false) => Change::Open,
        };
        match change {
            Change::New => counts.new += 1,
            Change::Open => counts.open += 1,
            Change::Regressed => counts.regressed += 1,
            Change::Suppressed => counts.suppressed += 1,
        }
        changes.push(change);
        // When each object appeared: kept as it was when this run doesn't
        // say which objects it lists.
        let objects = match f.objects() {
            // Its objects are what it is: nothing to date. (Most findings
            // of a large domain are such: one per account, or per right.)
            Some(_) if f.objects_are_its_key() => {
                state.tracked_since.get_or_insert(now);
                None
            }
            Some(ids) => {
                state.tracked_since.get_or_insert(now);
                // A finding set aside while its rule was off was open all
                // along; one that was fixed took its objects with it.
                let left = before
                    .filter(|t| t.status == Status::Resolved && !t.rule_off)
                    .map(|t| t.resolved_at.unwrap_or(now));
                // A run that couldn't resolve the finding can't tell that
                // an object left it either: those it lacks are held.
                let hold = before.is_some_and(|t| !scope.may_resolve(t));
                Some(crate::introduced::ObjectTrack::update(
                    before.and_then(|t| t.objects.as_ref()),
                    &ids,
                    now,
                    left,
                    hold,
                ))
            }
            None => before.and_then(|t| t.objects.clone()),
        };
        state.findings.insert(
            f.fingerprint().to_string(),
            TrackedFinding {
                rule: f.rule().to_string(),
                severity: f.severity(),
                default_severity: f.default_severity().filter(|d| *d != f.severity()),
                category: f.category(),
                status: if suppressed {
                    Status::Suppressed
                } else {
                    Status::Open
                },
                first_seen: before.map_or(now, |t| t.first_seen),
                last_seen: now,
                resolved_at: None,
                regressed_at: if change == Change::Regressed {
                    Some(now)
                } else {
                    before.and_then(|t| t.regressed_at)
                },
                rule_off: false,
                times_seen: before.map_or(1, |t| t.times_seen.saturating_add(1)),
                title: include_names.then(|| f.title().to_string()),
                domain: if include_names {
                    f.domain().map(str::to_string)
                } else {
                    None
                },
                scope: f.domain().map(scope_key),
                sources: f.sources().iter().map(|s| source_key(s)).collect(),
                // This sighting's units, and the last sighting's computers
                // this run still didn't read: a session on another
                // computer seen now doesn't make the unread one fixed.
                requires: {
                    let mut all: std::collections::BTreeSet<String> =
                        f.requires().iter().cloned().collect();
                    if let Some(t) = before.filter(|t| t.status != Status::Resolved) {
                        all.extend(scope.still_unread(t));
                    }
                    crate::findings::cap_host_units(&mut all);
                    all.into_iter().collect()
                },
                objects,
                // A sighting that read sessions or local groups is
                // remembered while the finding stays open: a later run
                // without them can't tell it fixed.
                not_targeted: {
                    let now =
                        crate::posture::Untargeted::from_parts(&scope.not_targeted_for(f.domain()));
                    match before.filter(|t| t.status != Status::Resolved) {
                        Some(t) => crate::posture::Untargeted::from_parts(&t.not_targeted).and(now),
                        None => now,
                    }
                    .parts()
                },
                // What it rests on, over every sighting while it stays
                // open: a Quick sighting sees no session or admin right,
                // which a Full one may have shown. Fixed, it starts again.
                rests_on: {
                    let open = before.filter(|t| t.status != Status::Resolved);
                    let now_lacks =
                        crate::posture::Untargeted::from_parts(&scope.not_targeted_for(f.domain()));
                    match (f.rests_on(), open) {
                        (None, Some(t)) => t.rests_on.clone(),
                        (None, None) => None,
                        (Some(now), None) => Some(now.parts()),
                        (Some(now), Some(t)) => Some(
                            match &t.rests_on {
                                Some(p) => crate::posture::Untargeted::from_parts(p).or(now),
                                // Recorded before it was kept: what its rule
                                // and category say, unless this sighting
                                // read everything and says itself.
                                None if now_lacks.any() => t.rested_on().or(now),
                                None => now,
                            }
                            .parts(),
                        ),
                    }
                },
            },
        );
    }

    let mut resolved = Vec::new();
    for (fp, t) in &prev.findings {
        if state.findings.contains_key(fp) {
            continue;
        }
        let mut t = t.clone();
        if t.status != Status::Resolved && scope.rule_off(&t) {
            // Not looked for this run: resolved so it leaves the open
            // list, but never counted or listed as fixed.
            t.status = Status::Resolved;
            t.resolved_at = Some(now);
            t.rule_off = true;
            counts.unchecked += 1;
        } else if t.status != Status::Resolved && !scope.may_resolve(&t) {
            // Held for computers it doesn't list (recorded before findings
            // listed them): it now rests on every computer of the kind the
            // run records, until they are read.
            let legacy = scope.legacy_hold(&t);
            for (lost, mark) in [
                (legacy.sessions, crate::opengraph::SESSION_HOST),
                (legacy.local_groups, crate::opengraph::LOCAL_GROUP_HOST),
            ] {
                if lost {
                    let any = format!("{mark}{}", crate::opengraph::hosts::ANY_HOST);
                    if !t.requires.contains(&any) {
                        t.requires.push(any);
                        t.requires.sort_unstable();
                    }
                }
            }
            counts.held += 1;
        } else if t.status != Status::Resolved {
            t.status = Status::Resolved;
            t.resolved_at = Some(now);
            counts.resolved += 1;
            resolved.push(Resolved {
                fingerprint: fp.clone(),
                rule: t.rule.clone(),
                severity: t.severity,
                first_seen: t.first_seen,
                resolved_at: now,
                title: t.title.clone(),
                actions: None,
            });
        }
        if !include_names {
            t.title = None;
            t.domain = None;
        }
        // Fixed long ago: its objects are forgotten, as departed ones are
        // ([`crate::introduced::GONE_DAYS`]). Should it come back, what it
        // lists then is its new baseline (and it is Back).
        if t.status == Status::Resolved
            && t.resolved_at
                .is_some_and(|at| at < now - crate::introduced::GONE_DAYS * 86_400)
        {
            t.objects = None;
        }
        state.findings.insert(fp.clone(), t);
    }

    Reconciled {
        state,
        changes,
        resolved,
        counts,
    }
}

/// A run identifier that sorts by time and is safe in file names:
/// `20261009T021000Z`.
pub fn run_id(at: i64) -> String {
    let s = crate::time::format_unix(at); // "YYYY-MM-DD HH:MM"
    let secs = at.rem_euclid(60);
    format!(
        "{}{}{}T{}{}{secs:02}Z",
        &s[0..4],
        &s[5..7],
        &s[8..10],
        &s[11..13],
        &s[14..16]
    )
}

/// [`run_id`] with milliseconds (`20261009T021000.042Z`), so runs started
/// within one second still get distinct history files.
pub fn run_id_millis(at_millis: i64) -> String {
    let id = run_id(at_millis.div_euclid(1000));
    format!(
        "{}.{:03}Z",
        id.trim_end_matches('Z'),
        at_millis.rem_euclid(1000)
    )
}

/// The time a history run ID ([`run_id`] or [`run_id_millis`]) names, in
/// Unix milliseconds: `None` for anything else.
pub fn run_id_to_millis(id: &str) -> Option<i64> {
    let id = id.strip_suffix('Z')?;
    let (date, ms) = match id.split_once('.') {
        Some((d, ms)) if ms.len() == 3 && ms.bytes().all(|b| b.is_ascii_digit()) => {
            (d, ms.parse::<i64>().ok()?)
        }
        Some(_) => return None,
        None => (id, 0),
    };
    let (day, clock) = date.split_once('T')?;
    if day.len() != 8
        || clock.len() != 6
        || !(day.bytes().chain(clock.bytes())).all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let n = |s: &str| s.parse::<i64>().ok();
    let secs = crate::time::unix_from_civil(
        n(&day[0..4])?,
        n(&day[4..6])?,
        n(&day[6..8])?,
        n(&clock[0..2])?,
        n(&clock[2..4])?,
        n(&clock[4..6])?,
    )?;
    Some(secs * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::fingerprint;

    fn finding(id: &str, suppressed: bool) -> Finding {
        let mut f = test_finding(id);
        if suppressed {
            f.suppressed = Some("accepted".into());
        }
        f
    }

    fn test_finding(id: &str) -> Finding {
        Finding {
            rule: "PW-003",
            category: Category::AttackPath,
            severity: Severity::High,
            rule_severity: Severity::High,
            severity_default: None,
            exposure: None,
            fingerprint: fingerprint("PW-003", &[id]),
            title: format!("{id} has GenericAll on DC01"),
            headline: None,
            domain: Some("CONTOSO.LOCAL".into()),
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
            entry: Default::default(),
            floor: None,
            hits: Vec::new(),
            password_age_days: None,
            key: Vec::new(),
        }
    }

    /// A finding read back from an event document reconciles exactly like
    /// the analysis's own finding (UI runs are imported this way).
    #[test]
    fn observed_findings_reconcile_like_findings() {
        let mut a = finding("A", false);
        a.domain = Some("CONTOSO.LOCAL".into());
        let b = finding("B", true);
        let json = serde_json::to_string(&[&a, &b]).unwrap();
        let read: Vec<ObservedFinding> = serde_json::from_str(&json).unwrap();
        let prev = reconcile(&FindingsState::default(), &[finding("C", false)], 50, true);
        let x = reconcile(&prev.state, &[a, b], 100, true);
        let y = reconcile(&prev.state, &read, 100, true);
        assert_eq!(x.changes, y.changes);
        assert_eq!(
            serde_json::to_string(&x.state).unwrap(),
            serde_json::to_string(&y.state).unwrap()
        );
        assert_eq!(x.counts.resolved, 1);
    }

    #[test]
    fn history_points_carry_the_environment_without_names() {
        let p = HistoryPoint {
            version: STATE_VERSION,
            run_id: "r".into(),
            at: 1,
            collected_at: None,
            tier_zero_exposure_percent: 0.0,
            tier_zero_exposed: 0,
            tier_zero_population: 0,
            tier_zero_relevant_population: 0,
            exposure_basis: 0,
            tier_zero_objects: 0,
            protection_score: None,
            tier_zero_grade: None,
            plan: None,
            findings: FindingCounts::default(),
            changes: ChangeCounts::default(),
            zones: Vec::new(),
            completeness: None,
            scopes: Vec::new(),
            trusted_scopes: None,
            recorded_by: None,
            label: None,
            data: None,
            inserted: false,
            exposed_keys: false,
            severity_settings: None,
            rule_severities: Default::default(),
        }
        .with_domains(&["b.local".into(), "A.LOCAL".into(), "B.LOCAL".into()])
        .with_recorded_by("ui");
        assert_eq!(p.scopes.len(), 2);
        let text = serde_json::to_string(&p).unwrap();
        assert!(!text.to_ascii_uppercase().contains("LOCAL"), "{text}");
        assert!(text.contains(r#""recorded_by":"ui""#));
        // Points written before these fields existed still load.
        let old = text.replace(r#","recorded_by":"ui""#, "").replace(
            &format!(r#","scopes":{}"#, serde_json::to_string(&p.scopes).unwrap()),
            "",
        );
        let back: HistoryPoint = serde_json::from_str(&old).unwrap();
        assert!(
            back.scopes.is_empty() && back.recorded_by.is_none(),
            "{old}"
        );
        assert!(back.trusted_scopes.is_none());
    }

    /// Points from before the basis was recorded read with the basis they
    /// were computed on: 0 without a relevant population, 1 (the
    /// capability gate) with one; a recorded basis reads as written.
    #[test]
    fn old_history_points_read_with_their_exposure_basis() {
        let p = HistoryPoint::new(
            "r",
            1,
            None,
            &crate::posture::Posture {
                tier_zero: crate::posture::zone_posture(
                    &crate::AdGraph::new(),
                    "Tier Zero",
                    &[],
                    &[],
                    &[],
                    &crate::analysis::Relevance::new(&crate::AdGraph::new(), 0, 90),
                    true,
                ),
                zones: Vec::new(),
                findings: FindingCounts::default(),
                completeness: Vec::new(),
                sysvol: Vec::new(),
                adcs: Vec::new(),
                dc_settings: Vec::new(),
                ca_settings: Vec::new(),
                host_agents: Default::default(),
                exposure_basis: crate::analysis::EXPOSURE_BASIS,
                activity_days: 90,
                activity_unknown_domains: Vec::new(),
                plan: None,
                severities_set: Vec::new(),
                severity_settings: String::new(),
            },
            ChangeCounts::default(),
        );
        assert_eq!(p.basis(), crate::analysis::EXPOSURE_BASIS);
        let mut v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["exposure_basis"], crate::analysis::EXPOSURE_BASIS);
        v.as_object_mut().unwrap().remove("exposure_basis");
        let original: HistoryPoint = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(original.basis(), 0, "no relevant population: basis 0");
        v["tier_zero_relevant_population"] = 24.into();
        let gated: HistoryPoint = serde_json::from_value(v).unwrap();
        assert_eq!(gated.basis(), 1, "relevant population, no basis: #80 gate");
    }

    fn names(d: &[&str]) -> Vec<String> {
        d.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn legacy_domain_lists_map_to_the_collected_ones() {
        let mut l = LegacyDomains::default();
        l.learn(&names(&["ESSOS.LOCAL"]), &names(&["SEVENKINGDOMS.LOCAL"]));
        l.learn(&names(&["NORTH.SEVENKINGDOMS.LOCAL"]), &[]);
        // Case and order don't matter.
        assert_eq!(
            l.map(&names(&["sevenkingdoms.local", "ESSOS.LOCAL"])),
            Some(names(&["ESSOS.LOCAL"]).as_slice())
        );
        // Not a list a trust explains, or already a list recorded now.
        assert_eq!(l.map(&names(&["ESSOS.LOCAL", "OTHER.LOCAL"])), None);
        assert_eq!(l.map(&names(&["ESSOS.LOCAL"])), None);
        assert_eq!(l.map(&names(&["NORTH.SEVENKINGDOMS.LOCAL"])), None);
        // A run that collected both: its list stays as it is.
        l.learn(
            &names(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]),
            &names(&["NORTH.SEVENKINGDOMS.LOCAL"]),
        );
        assert_eq!(l.map(&names(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"])), None);
    }

    /// A point recorded by 0.1.1 (trusted domains in its scopes) and one
    /// recorded now of the same collection end up in one environment.
    #[test]
    fn legacy_points_join_the_points_recorded_since() {
        let point = |run: &str| HistoryPoint {
            version: STATE_VERSION,
            run_id: run.into(),
            at: 1,
            collected_at: None,
            tier_zero_exposure_percent: 0.0,
            tier_zero_exposed: 0,
            tier_zero_population: 0,
            tier_zero_relevant_population: 0,
            exposure_basis: 0,
            tier_zero_objects: 0,
            protection_score: None,
            tier_zero_grade: None,
            plan: None,
            findings: FindingCounts::default(),
            changes: ChangeCounts::default(),
            zones: Vec::new(),
            completeness: None,
            scopes: Vec::new(),
            trusted_scopes: None,
            recorded_by: None,
            label: None,
            data: None,
            inserted: false,
            exposed_keys: false,
            severity_settings: None,
            rule_severities: Default::default(),
        };
        let old = point("old").with_domains(&names(&["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]));
        let other = point("other").with_domains(&names(&["CONTOSO.LOCAL", "FABRIKAM.LOCAL"]));
        let new = point("new")
            .with_domains(&names(&["ESSOS.LOCAL"]))
            .with_trusted(&names(&["SEVENKINGDOMS.LOCAL"]));
        let mut points = vec![old, other.clone(), new.clone()];
        migrate_points(&mut points);
        assert_eq!(points[0].scopes, new.scopes);
        assert!(points[0].trusted_scopes.is_none(), "still a legacy point");
        assert_eq!(points[1].scopes, other.scopes, "nothing explains it");
        // A parent and its child collected separately: 0.1.1 recorded both
        // as the pair; runs since map the pair to one or the other, so the
        // old points stay a series of their own.
        let pair = names(&["NORTH.SEVENKINGDOMS.LOCAL", "SEVENKINGDOMS.LOCAL"]);
        let old_pair = point("old-pair").with_domains(&pair);
        let parent = point("parent")
            .with_domains(&pair[1..])
            .with_trusted(&pair[..1]);
        let child = point("child")
            .with_domains(&pair[..1])
            .with_trusted(&pair[1..]);
        let mut points = vec![old_pair.clone(), parent, child];
        migrate_points(&mut points);
        assert_eq!(points[0].scopes, old_pair.scopes);
        // The new point's field round-trips; no names in it.
        let text = serde_json::to_string(&new).unwrap();
        assert!(text.contains(r#""trusted_scopes":["#), "{text}");
        assert!(!text.to_ascii_uppercase().contains("LOCAL"), "{text}");
    }

    #[test]
    fn lifecycle_new_open_resolved_regressed() {
        let a = finding("A", false);
        let b = finding("B", false);

        let r1 = reconcile(
            &FindingsState::default(),
            &[a.clone(), b.clone()],
            100,
            false,
        );
        assert_eq!(r1.changes, [Change::New, Change::New]);
        assert_eq!(r1.counts.new, 2);
        assert!(
            r1.state.findings.values().all(|t| t.title.is_none()),
            "hash-only by default"
        );

        // B disappears.
        let r2 = reconcile(&r1.state, std::slice::from_ref(&a), 200, false);
        assert_eq!(r2.changes, [Change::Open]);
        assert_eq!(r2.resolved.len(), 1);
        assert_eq!(r2.resolved[0].fingerprint, b.fingerprint);
        let ta = &r2.state.findings[&a.fingerprint];
        assert_eq!((ta.first_seen, ta.last_seen, ta.times_seen), (100, 200, 2));
        assert_eq!(r2.state.findings[&b.fingerprint].status, Status::Resolved);

        // Still gone: not resolved again.
        let r3 = reconcile(&r2.state, std::slice::from_ref(&a), 300, false);
        assert_eq!(r3.counts.resolved, 0);

        // B comes back.
        let r4 = reconcile(&r3.state, &[a.clone(), b.clone()], 400, false);
        assert_eq!(r4.changes, [Change::Open, Change::Regressed]);
        let tb = &r4.state.findings[&b.fingerprint];
        assert_eq!(
            (tb.status, tb.first_seen, tb.resolved_at),
            (Status::Open, 100, None)
        );
        // The regression is stamped, and the stamp stays while it is open.
        assert_eq!(tb.regressed_at, Some(400));
        assert_eq!(r4.state.findings[&a.fingerprint].regressed_at, None);
        let r5 = reconcile(&r4.state, &[a.clone(), b.clone()], 500, false);
        assert_eq!(r5.state.findings[&b.fingerprint].regressed_at, Some(400));
    }

    /// A finding of a rule turned off is not fixed: it leaves the open list
    /// as no longer checked, and is open again (not back after a fix) when
    /// the rule is on again and finds it.
    #[test]
    fn findings_of_a_rule_turned_off_are_not_fixed() {
        let a = finding("A", false);
        let r1 = reconcile(
            &FindingsState::default(),
            std::slice::from_ref(&a),
            100,
            true,
        );
        let off = ResolveScope::everything().with_rules_off(&[" pw-003 ".to_string()]);
        let r2 = reconcile_scoped(&r1.state, &[] as &[Finding], 200, true, &off);
        assert_eq!((r2.counts.resolved, r2.counts.unchecked), (0, 1));
        assert!(r2.resolved.is_empty());
        let t = &r2.state.findings[&a.fingerprint];
        assert_eq!(
            (t.status, t.resolved_at, t.rule_off),
            (Status::Resolved, Some(200), true)
        );
        // The flag is saved, and absent from findings never set aside.
        let v = serde_json::to_value(&r2.state).unwrap();
        assert_eq!(v["findings"][&a.fingerprint]["rule_off"], true);
        assert!(
            serde_json::to_value(&r1.state).unwrap()["findings"][&a.fingerprint]
                .get("rule_off")
                .is_none()
        );
        // Still off: counted once.
        let r3 = reconcile_scoped(&r2.state, &[] as &[Finding], 300, true, &off);
        assert_eq!(r3.counts.unchecked, 0);
        // On again and found: open, not a regression.
        let r4 = reconcile(&r3.state, std::slice::from_ref(&a), 400, true);
        assert_eq!(r4.changes, [Change::Open]);
        assert_eq!(r4.counts.regressed, 0);
        let t = &r4.state.findings[&a.fingerprint];
        assert_eq!(
            (t.status, t.rule_off, t.regressed_at),
            (Status::Open, false, None)
        );
    }

    /// The risk-scoring figures of history points (completeness, per-zone
    /// counts and status) and the regression stamp are optional: files
    /// written before them load, and simply lack them.
    #[test]
    fn history_from_before_the_new_figures_still_loads() {
        let old_point = r#"{"version":1,"run_id":"r","at":1,"collected_at":null,
            "tier_zero_exposure_percent":0.0,"tier_zero_exposed":3,"tier_zero_population":9,
            "tier_zero_objects":4,"protection_score":null,
            "findings":{"attack_path":0,"hygiene":0,"suppressed":0,"critical":0,"high":0,"medium":0,"low":0,"info":0},
            "changes":{"new":0,"open":0,"regressed":0,"suppressed":0,"resolved":0},
            "zones":[{"zone":"Finance","exposure_percent":5.0,"protection_score":null}]}"#;
        let p: HistoryPoint = serde_json::from_str(old_point).unwrap();
        assert!(p.completeness.is_none());
        let z = &p.zones[0];
        assert!(z.objects.is_none() && z.exposed.is_none() && z.grade.is_none());
        // Written back, the missing figures stay missing (not zero).
        let text = serde_json::to_string(&p).unwrap();
        assert!(
            !text.contains("completeness") && !text.contains(r#""exposed":"#),
            "{text}"
        );

        let old_finding = r#"{"rule":"PW-003","severity":"high","category":"attack_path",
            "status":"open","first_seen":1,"last_seen":2,"times_seen":2}"#;
        let t: TrackedFinding = serde_json::from_str(old_finding).unwrap();
        assert!(t.regressed_at.is_none());
    }

    /// Completeness sums the domains, and works the shares out as the
    /// report does: sessions over every computer, local groups over member
    /// computers only.
    #[test]
    fn completeness_points_sum_the_domains() {
        let domain = |computers, members, sessions, groups| crate::posture::Completeness {
            domain: "D".into(),
            computers,
            member_computers: members,
            enabled_member_computers: members,
            active_only: true,
            sessions_collected: sessions,
            local_groups_collected: groups,
            sessions_percent: 100.0 * sessions as f64 / computers as f64,
            local_groups_percent: if members == 0 {
                0.0
            } else {
                100.0 * groups as f64 / members as f64
            },
            gpo_local_groups: None,
            sessions_targeted: true,
            local_groups_targeted: true,
            skipped_no_kerberos: 0,
            skipped_unsigned: 0,
            skipped_bad_reply: 0,
            skipped_rc4_trust: 0,
            skipped_not_counted: 0,
            stored_credentials_collected: None,
            stored_credentials_off: false,
            task_credentials_collected: None,
            task_credentials_off: false,
        };
        let c = CompletenessPoint::new(&[domain(10, 8, 10, 8), domain(10, 8, 2, 0)]).unwrap();
        assert_eq!((c.computers, c.sessions_collected), (20, 12));
        assert_eq!(c.sessions_percent, 60.0);
        assert_eq!(c.local_groups_percent, Some(50.0));
        assert_eq!(c.low_domains, 1);
        // Domain controllers only: local groups don't apply.
        let dc = CompletenessPoint::new(&[domain(2, 0, 2, 0)]).unwrap();
        assert_eq!(dc.local_groups_percent, None);
        assert_eq!(dc.low_domains, 0);
        // No computers: nothing to record.
        assert!(CompletenessPoint::new(&[]).is_none());
    }

    #[test]
    fn suppression_and_names() {
        let a = finding("A", true);
        let r = reconcile(
            &FindingsState::default(),
            std::slice::from_ref(&a),
            100,
            true,
        );
        assert_eq!(r.changes, [Change::Suppressed]);
        let t = &r.state.findings[&a.fingerprint];
        assert_eq!(t.status, Status::Suppressed);
        assert_eq!(t.title.as_deref(), Some("A has GenericAll on DC01"));
    }

    #[test]
    fn run_ids_sort_and_are_file_safe() {
        assert_eq!(run_id(1_791_417_600), "20261008T000000Z");
        assert_eq!(run_id(1_791_417_600 + 3_725), "20261008T010205Z");
        assert_eq!(run_id_millis(1_791_417_600_042), "20261008T000000.042Z");
        assert_eq!(
            run_id_to_millis("20261008T000000.042Z"),
            Some(1_791_417_600_042)
        );
        assert_eq!(
            run_id_to_millis(&run_id(1_791_417_601)),
            Some(1_791_417_601_000)
        );
        assert_eq!(run_id_to_millis("20261008-000000-ab12cd"), None);
        assert_eq!(run_id_to_millis("20261008T000000.42Z"), None);
    }

    /// An OpenGraph source the last run had and this one lacks holds every
    /// attack-path finding (a path may have run through its edges without
    /// its sample path showing it); hygiene findings resolve as usual.
    #[test]
    fn a_missing_source_holds_attack_paths_only() {
        let path = finding("P", false);
        let mut hygiene = finding("H", false);
        hygiene.category = Category::Hygiene;
        let r1 = reconcile(
            &FindingsState::default(),
            &[path.clone(), hygiene.clone()],
            100,
            false,
        );
        let previous = vec![crate::opengraph::source_key("TaskHound")];
        let scope = ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], true)
            .with_sources(RunSources::default(), &previous);
        assert_eq!(scope.missing_sources.len(), 1);
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &scope);
        assert_eq!(r2.state.findings[&path.fingerprint].status, Status::Open);
        assert_eq!(
            r2.state.findings[&hygiene.fingerprint].status,
            Status::Resolved
        );

        // A finding that rests on a source with no coverage at all is held.
        let mut og = finding("OG", false);
        og.sources = vec!["TaskHound".into()];
        let r1 = reconcile(&FindingsState::default(), &[og.clone()], 100, false);
        let t = &r1.state.findings[&og.fingerprint];
        assert_eq!(t.sources, previous, "sources are stored as hashes");
        let scope = ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], true);
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &scope);
        assert_eq!(r2.counts.held, 1);
    }

    /// A Quick run (sessions and local groups not read) can't tell an
    /// attack path a Full run saw is gone: it is held. One the Quick runs
    /// saw themselves is theirs to fix.
    #[test]
    fn a_quick_run_holds_attack_paths_a_full_run_saw() {
        use crate::posture::Untargeted;
        let quick = || {
            ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], true).with_untargeted(&[(
                "contoso.local".to_string(),
                Untargeted {
                    sessions: true,
                    local_groups: true,
                },
            )])
        };
        let full = || ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], true);
        // A path that may run through a session or an admin right.
        let mut path = finding("P", false);
        path.rests_on = Untargeted::BOTH;
        let mut hygiene = finding("H", false);
        hygiene.category = Category::Hygiene;
        // Run 1, Full: both seen.
        let r1 = reconcile_scoped(
            &FindingsState::default(),
            &[path.clone(), hygiene.clone()],
            100,
            false,
            &full(),
        );
        assert!(r1.state.findings[&path.fingerprint].not_targeted.is_empty());
        // Run 2, Quick: both gone. The path is held, the hygiene fixed.
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &quick());
        assert_eq!((r2.counts.resolved, r2.counts.held), (1, 1));
        assert_eq!(r2.state.findings[&path.fingerprint].status, Status::Open);
        // Run 3, Quick again: still held, never fixed by a Quick run.
        let r3 = reconcile_scoped::<Finding>(&r2.state, &[], 300, false, &quick());
        assert_eq!((r3.counts.resolved, r3.counts.held), (0, 1));
        // Run 4, Full: gone, so fixed.
        let r4 = reconcile_scoped::<Finding>(&r3.state, &[], 400, false, &full());
        assert_eq!((r4.counts.resolved, r4.counts.held), (1, 0));

        // Seen by a Full run, then by a Quick run, then gone in a Quick
        // run: the Full sighting read sessions, so it stays held.
        let r1 = reconcile_scoped(
            &FindingsState::default(),
            std::slice::from_ref(&path),
            100,
            false,
            &full(),
        );
        let r2 = reconcile_scoped(&r1.state, std::slice::from_ref(&path), 200, false, &quick());
        assert!(r2.state.findings[&path.fingerprint].not_targeted.is_empty());
        let r3 = reconcile_scoped::<Finding>(&r2.state, &[], 300, false, &quick());
        assert_eq!((r3.counts.resolved, r3.counts.held), (0, 1));

        // An ACL and an admin right seen by a Full run, the ACL alone by a
        // Quick run, then gone in a Quick run: the admin right may still
        // be there, so it stays held.
        let mut both = finding("B", false);
        both.rests_on = Untargeted {
            sessions: false,
            local_groups: true,
        };
        let mut acl_only = both.clone();
        acl_only.rests_on = Untargeted::default();
        let r1 = reconcile_scoped(
            &FindingsState::default(),
            &[both.clone()],
            100,
            false,
            &full(),
        );
        let r2 = reconcile_scoped(&r1.state, &[acl_only], 200, false, &quick());
        assert_eq!(
            r2.state.findings[&both.fingerprint].rests_on.as_deref(),
            Some(&["local_groups".to_string()][..])
        );
        let r3 = reconcile_scoped::<Finding>(&r2.state, &[], 300, false, &quick());
        assert_eq!((r3.counts.resolved, r3.counts.held), (0, 1));

        // An attack path that rests on neither (an ACL, DCSync): a Quick
        // run tells it fixed.
        let acl = finding("A", false);
        assert!(acl.rests_on.none());
        let r1 = reconcile_scoped(
            &FindingsState::default(),
            std::slice::from_ref(&acl),
            100,
            false,
            &full(),
        );
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &quick());
        assert_eq!((r2.counts.resolved, r2.counts.held), (1, 0));

        // A hygiene rule that reads local groups (logon rights on domain
        // controllers) is held too.
        let mut rdp = finding("R", false);
        rdp.rule = "PW-023";
        rdp.category = Category::Hygiene;
        rdp.rests_on = Untargeted::of_rule("PW-023");
        let r1 = reconcile_scoped(&FindingsState::default(), &[rdp], 100, false, &full());
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &quick());
        assert_eq!((r2.counts.resolved, r2.counts.held), (0, 1));

        // A path a Quick run found, gone in the next Quick run: fixed.
        let mut q = finding("Q", false);
        q.rests_on = Untargeted::BOTH;
        let r1 = reconcile_scoped(
            &FindingsState::default(),
            std::slice::from_ref(&q),
            100,
            false,
            &quick(),
        );
        assert_eq!(
            r1.state.findings[&q.fingerprint].not_targeted,
            ["sessions", "local_groups"]
        );
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &quick());
        assert_eq!((r2.counts.resolved, r2.counts.held), (1, 0));
        // A state written before this was recorded: held by a Quick run.
        let text = r#"{"version":1,"findings":{"PW-003-1":{"rule":"PW-003","severity":"high",
            "category":"attack_path","status":"open","first_seen":1,"last_seen":2,"times_seen":2}}}"#;
        let old: FindingsState = serde_json::from_str(text).unwrap();
        assert!(old.findings["PW-003-1"].not_targeted.is_empty());
        let mut everywhere = quick();
        everywhere.collected = None;
        let r = reconcile_scoped::<Finding>(&old, &[], 300, false, &everywhere);
        assert_eq!((r.counts.resolved, r.counts.held), (0, 1));
    }

    #[test]
    fn state_from_before_opengraph_loads() {
        let text = r#"{"version":1,"findings":{"PW-003-1":{"rule":"PW-003","severity":"high",
            "category":"attack_path","status":"open","first_seen":1,"last_seen":2,"times_seen":2}}}"#;
        let st: FindingsState = serde_json::from_str(text).unwrap();
        let t = &st.findings["PW-003-1"];
        assert!(t.sources.is_empty() && t.requires.is_empty());
        let last = r#"{"version":1,"run_id":"x","started_at":1,"finished_at":2,"collected_at":null,
            "pathwarden":"0.1.0","collector_files":1,"domains":[],"changes":{"new":0,"open":0,
            "regressed":0,"suppressed":0,"resolved":0}}"#;
        let last: LastRun = serde_json::from_str(last).unwrap();
        assert!(last.sources.is_empty());
    }

    #[test]
    fn findings_in_uncollected_domains_are_held_not_resolved() {
        let mut a = finding("A", false);
        a.domain = Some("CONTOSO.LOCAL".into());
        let mut b = finding("B", false);
        b.domain = Some("FABRIKAM.LOCAL".into());
        let r1 = reconcile(
            &FindingsState::default(),
            &[a.clone(), b.clone()],
            100,
            false,
        );

        // Only CONTOSO collected this time: B is held, not resolved.
        let only = ResolveScope::domains(&["CONTOSO.LOCAL".to_string()], true);
        let r2 = reconcile_scoped(&r1.state, std::slice::from_ref(&a), 200, false, &only);
        assert_eq!((r2.counts.resolved, r2.counts.held), (0, 1));
        assert_eq!(r2.state.findings[&b.fingerprint].status, Status::Open);

        // A collection that looks incomplete resolves nothing.
        let shrunk = ResolveScope::domains(
            &["CONTOSO.LOCAL".to_string(), "FABRIKAM.LOCAL".to_string()],
            false,
        );
        let r3 = reconcile_scoped::<Finding>(&r1.state, &[], 300, false, &shrunk);
        assert_eq!((r3.counts.resolved, r3.counts.held), (0, 2));

        // Both collected and B gone: B resolves.
        let both = ResolveScope::domains(
            &["contoso.local".to_string(), "FABRIKAM.LOCAL".to_string()],
            true,
        );
        let r4 = reconcile_scoped(&r1.state, std::slice::from_ref(&a), 400, false, &both);
        assert_eq!(r4.counts.resolved, 1);
        assert!(r1
            .state
            .findings
            .values()
            .all(|t| t.scope.as_deref().is_some_and(|s| !s.contains("CONTOSO"))));
    }

    /// SRV01 in `testdata/forest`: DA_ALICE has a session there (PW-004),
    /// and SVC_SQL, Kerberoastable, is its admin (PW-006 through both).
    const SRV01: &str = "S-1-5-21-1000-1000-1000-1001";
    /// APP01: no session, no admin right.
    const APP01: &str = "S-1-5-21-1000-1000-1000-1003";

    /// `testdata/forest` with each computer `edit` changes (`None` removes
    /// it from the directory), analyzed.
    fn forest_with(
        edit: impl Fn(&str, &mut serde_json::Value) -> Option<()>,
    ) -> (crate::analyze::Analysis, RunSources) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let src =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
        let dir = std::env::temp_dir().join(format!(
            "pathwarden-state-hosts-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for e in std::fs::read_dir(&src).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dir.join(e.file_name())).unwrap();
        }
        let file = dir.join("contoso_computers.json");
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let data = doc["data"].as_array_mut().unwrap();
        data.retain_mut(|c| {
            let id = c["ObjectIdentifier"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            edit(&id, c).is_some()
        });
        let count = data.len();
        doc["meta"]["count"] = serde_json::json!(count);
        std::fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
        let a = crate::analyze::run(
            std::slice::from_ref(&dir),
            &crate::config::Config::default(),
            &[],
            &mut crate::analyze::Quiet,
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let s = RunSources::from_analysis_at(
            &a.graph,
            &a.stats,
            Some((a.settings.now, a.settings.stale_days)),
        );
        (a, s)
    }

    /// `host`'s sessions not read (not reachable).
    fn sessions_unread(host: &'static str) -> impl Fn(&str, &mut serde_json::Value) -> Option<()> {
        move |id, c| {
            if id == host {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": "not reachable"});
                }
            }
            Some(())
        }
    }

    /// `host`'s local groups not read (not reachable).
    fn groups_unread(host: &'static str) -> impl Fn(&str, &mut serde_json::Value) -> Option<()> {
        move |id, c| {
            if id == host {
                for g in c["LocalGroups"].as_array_mut().into_iter().flatten() {
                    g["Results"] = serde_json::json!([]);
                    g["Collected"] = serde_json::json!(false);
                }
            }
            Some(())
        }
    }

    /// SRV01 read, with no session and no admin.
    fn srv01_clean(id: &str, c: &mut serde_json::Value) -> Option<()> {
        if id == SRV01 {
            c["Sessions"]["Results"] = serde_json::json!([]);
            for g in c["LocalGroups"].as_array_mut().into_iter().flatten() {
                g["Results"] = serde_json::json!([]);
            }
        }
        Some(())
    }

    /// SRV01 deleted from the directory.
    fn srv01_gone(id: &str, _: &mut serde_json::Value) -> Option<()> {
        (id != SRV01).then_some(())
    }

    /// Runs one after another, recorded as `pathwarden run` records them:
    /// each compared with the last run's sources and hosts.
    #[derive(Default)]
    struct Runs {
        state: FindingsState,
        prev: Vec<String>,
        at: i64,
        /// The last run recorded no computers (an upgrade): the next run only.
        legacy: bool,
    }

    impl Runs {
        fn run(&mut self, (a, s): &(crate::analyze::Analysis, RunSources)) -> &Self {
            self.at += 100;
            let scope = ResolveScope::domains(&a.domains, true)
                .with_sources(s.clone(), &self.prev)
                .with_legacy_hosts(self.legacy);
            let r = reconcile_scoped(&self.state, &a.findings, self.at, false, &scope);
            let (sources, hosts) = s.recorded(&self.prev, self.legacy);
            self.prev = sources.into_iter().chain(hosts).collect();
            self.state = r.state;
            self.legacy = false;
            self
        }

        fn status(&self, fp: &str) -> Status {
            self.state.findings[fp].status
        }
    }

    /// The fingerprint of the finding of `rule` that lists `id`.
    fn listing(a: &crate::analyze::Analysis, rule: &str, id: &str) -> String {
        a.findings
            .iter()
            .find(|f| f.rule == rule && f.affected.iter().any(|x| x.id == id))
            .unwrap_or_else(|| panic!("no {rule} listing {id}"))
            .fingerprint
            .clone()
    }

    /// A session on SRV01 a full run read: held while SRV01's sessions
    /// aren't read again, run after run, and fixed once they are with no
    /// session there, or once SRV01 is deleted. PW-004 lists SRV01; PW-006
    /// reaches Tier Zero through its session.
    #[test]
    fn an_unread_session_host_holds_what_rests_on_it() {
        use crate::opengraph::hosts::units;
        let full = forest_with(|_, _| Some(()));
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let pw006 = listing(&full.0, "PW-006", "S-1-5-21-1000-1000-1000-1103");
        for fp in [&pw004, &pw006] {
            let f = full
                .0
                .findings
                .iter()
                .find(|f| f.fingerprint == **fp)
                .unwrap();
            assert!(
                units(SRV01, crate::opengraph::SESSION_HOST, 1 | 2)
                    .iter()
                    .all(|u| f.requires.contains(u)),
                "{}",
                f.title
            );
        }
        let unread = forest_with(sessions_unread(SRV01));
        assert!(!unread.0.findings.iter().any(|f| f.fingerprint == pw004));
        let clean = forest_with(srv01_clean);
        let gone = forest_with(srv01_gone);
        for (last, what) in [(&clean, "read, no session"), (&gone, "deleted")] {
            let mut runs = Runs::default();
            runs.run(&full);
            for n in 2..4 {
                runs.run(&unread);
                for fp in [&pw004, &pw006] {
                    assert_eq!(runs.status(fp), Status::Open, "{fp} held in run {n}");
                }
            }
            runs.run(last);
            for fp in [&pw004, &pw006] {
                assert_eq!(runs.status(fp), Status::Resolved, "{fp}: {what}");
            }
            assert!(
                !runs
                    .prev
                    .iter()
                    .any(|k| k.contains(&crate::opengraph::hosts::host_hash(SRV01))),
                "{what}"
            );
        }
        // The reason, in words.
        let f = full
            .0
            .findings
            .iter()
            .find(|f| f.fingerprint == pw004)
            .unwrap();
        assert_eq!(
            unread.1.hold_reason(&f.sources, &f.requires).as_deref(),
            Some("Sessions weren't read on 1 computer this finding rests on, so it can't be confirmed fixed.")
        );
    }

    /// A computer that never had a session or an admin right holds nothing
    /// when it isn't read.
    #[test]
    fn an_unread_host_without_edges_holds_nothing() {
        let full = forest_with(|_, _| Some(()));
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let pw006 = listing(&full.0, "PW-006", "S-1-5-21-1000-1000-1000-1103");
        let app01_down = forest_with(|id, c| {
            sessions_unread(APP01)(id, c)?;
            groups_unread(APP01)(id, c)?;
            srv01_clean(id, c)
        });
        let mut runs = Runs::default();
        runs.run(&full);
        let scope = ResolveScope::domains(&app01_down.0.domains, true)
            .with_sources(app01_down.1.clone(), &runs.prev);
        assert!(scope.missing_hosts.is_empty());
        runs.run(&app01_down);
        for fp in [&pw004, &pw006] {
            assert_eq!(runs.status(fp), Status::Resolved, "{fp}");
        }
    }

    /// The same for local groups: SVC_SQL's admin right on SRV01 holds its
    /// path (PW-006) while SRV01's local groups aren't read.
    #[test]
    fn an_unread_local_groups_host_holds_what_rests_on_it() {
        use crate::opengraph::hosts::units;
        let full = forest_with(|_, _| Some(()));
        let pw006 = listing(&full.0, "PW-006", "S-1-5-21-1000-1000-1000-1103");
        let f = full
            .0
            .findings
            .iter()
            .find(|f| f.fingerprint == pw006)
            .unwrap();
        assert!(f
            .requires
            .contains(&units(SRV01, crate::opengraph::LOCAL_GROUP_HOST, 8)[0]));
        let unread = forest_with(groups_unread(SRV01));
        assert!(!unread.0.findings.iter().any(|f| f.fingerprint == pw006));
        assert_eq!(
            unread.1.hold_reason(&f.sources, &f.requires).as_deref(),
            Some("Local groups weren't read on 1 computer this finding rests on, so it can't be confirmed fixed.")
        );
        let clean = forest_with(srv01_clean);
        let gone = forest_with(srv01_gone);
        for last in [&clean, &gone] {
            let mut runs = Runs::default();
            runs.run(&full);
            runs.run(&unread);
            assert_eq!(runs.status(&pw006), Status::Open);
            runs.run(&unread);
            assert_eq!(runs.status(&pw006), Status::Open);
            runs.run(last);
            assert_eq!(runs.status(&pw006), Status::Resolved);
        }
    }

    /// A reach finding (PW-006) is held by any computer the last run had an
    /// edge on and this one didn't read, even one not on its sample path;
    /// other findings only by their own.
    #[test]
    fn reach_findings_are_held_by_any_unread_host() {
        use crate::opengraph::hosts::units;
        let mut reach = finding("R", false);
        reach.rule = "PW-006";
        let other = finding("O", false);
        let r1 = reconcile(
            &FindingsState::default(),
            &[reach.clone(), other.clone()],
            100,
            false,
        );
        let had = units(SRV01, crate::opengraph::SESSION_HOST, 1);
        let unread = forest_with(sessions_unread(SRV01));
        let scope =
            ResolveScope::domains(&unread.0.domains, true).with_sources(unread.1.clone(), &had);
        assert_eq!(scope.missing_hosts, had);
        assert!(scope.missing_sources.is_empty());
        let r2 = reconcile_scoped::<Finding>(&r1.state, &[], 200, false, &scope);
        assert_eq!(r2.state.findings[&reach.fingerprint].status, Status::Open);
        assert_eq!(
            r2.state.findings[&other.fingerprint].status,
            Status::Resolved
        );
    }

    /// The lab's run 3: a computer that stored a credential, then not
    /// reached twice, holds the findings that may rest on it both times
    /// (before, the second run had forgotten it). An attack path that
    /// doesn't rest on it is not held by it.
    #[test]
    fn stored_credentials_stay_held_while_unread() {
        use crate::opengraph::coverage::{HostsPart, SourceCoverage};
        use crate::sysvol::CheckStatus;
        let name = crate::storedcreds::source("CONTOSO.LOCAL");
        let unit = crate::opengraph::host_unit_key(&name, APP01);
        let run = |read: bool| {
            let mut s = RunSources {
                present_hosts: Some([unit.clone()].into_iter().collect()),
                host_edges: if read {
                    [unit.clone()].into_iter().collect()
                } else {
                    Default::default()
                },
                ..RunSources::default()
            };
            s.sources.insert(
                crate::opengraph::source_key(&name),
                SourceCoverage {
                    name: name.clone(),
                    has_coverage: true,
                    complete: true,
                    read_complete: true,
                    ok: if read {
                        [unit.clone()].into_iter().collect()
                    } else {
                        Default::default()
                    },
                    sysvol: None,
                    hosts: Some(HostsPart {
                        status: if read {
                            CheckStatus::Complete
                        } else {
                            CheckStatus::Partial
                        },
                        edges: usize::from(read),
                        turned_off: false,
                    }),
                    edge_units: if read { vec![unit.clone()] } else { Vec::new() },
                },
            );
            s
        };
        let mut reach = finding("R", false);
        reach.rule = "PW-006";
        let mut through = finding("T", false);
        through.requires = vec![unit.clone()];
        let elsewhere = finding("E", false);
        let all = [reach.clone(), through.clone(), elsewhere.clone()];
        let domains = ["CONTOSO.LOCAL".to_string()];
        let mut state = reconcile(&FindingsState::default(), &all, 100, false).state;
        let (s, h) = run(true).recorded(&[], false);
        let mut prev: Vec<String> = s.into_iter().chain(h).collect();
        assert_eq!(prev, std::slice::from_ref(&unit));
        for at in [200, 300] {
            let now = run(false);
            let scope = ResolveScope::domains(&domains, true).with_sources(now.clone(), &prev);
            assert!(
                scope.missing_sources.is_empty(),
                "a computer isn't a source"
            );
            let r = reconcile_scoped::<Finding>(&state, &[], at, false, &scope);
            assert_eq!(
                r.state.findings[&reach.fingerprint].status,
                Status::Open,
                "run {at}"
            );
            assert_eq!(
                r.state.findings[&through.fingerprint].status,
                Status::Open,
                "run {at}"
            );
            assert_eq!(
                r.state.findings[&elsewhere.fingerprint].status,
                Status::Resolved,
                "run {at}"
            );
            let (s, h) = now.recorded(&prev, false);
            prev = s.into_iter().chain(h).collect();
            assert_eq!(prev, std::slice::from_ref(&unit), "kept while unread");
            state = r.state;
        }
        // Read again, clean: both fixed, and the computer drops off.
        let mut clean = run(true);
        clean
            .sources
            .values_mut()
            .for_each(|c| c.edge_units.clear());
        clean.host_edges.clear();
        let scope = ResolveScope::domains(&domains, true).with_sources(clean.clone(), &prev);
        let r = reconcile_scoped::<Finding>(&state, &[], 400, false, &scope);
        assert_eq!(r.counts.resolved, 2);
        assert_eq!(clean.recorded(&prev, false), (Vec::new(), Vec::new()));
    }

    /// WS01: BOB's session (no path to Tier Zero).
    const WS01: &str = "S-1-5-21-1000-1000-1000-1002";

    /// DA_ALICE's session on WS01 too.
    fn alice_on_ws01(id: &str, c: &mut serde_json::Value) -> Option<()> {
        if id == WS01 {
            c["Sessions"]["Results"].as_array_mut()?.push(
                serde_json::json!({"UserSID": "S-1-5-21-1000-1000-1000-1101",
                    "ComputerSID": WS01}),
            );
        }
        Some(())
    }

    /// A finding seen again through another computer keeps the one still
    /// not read: PW-004 with sessions on SRV01 and WS01; SRV01 down while
    /// WS01's session stays (seen, SRV01 kept); then SRV01 still down and
    /// WS01's session gone: held, not fixed.
    #[test]
    fn a_sighting_keeps_the_computers_still_unread() {
        use crate::opengraph::hosts::host_hash;
        let both = forest_with(alice_on_ws01);
        let pw004 = listing(&both.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let srv01_down = forest_with(|id, c| {
            alice_on_ws01(id, c)?;
            sessions_unread(SRV01)(id, c)
        });
        let neither = forest_with(sessions_unread(SRV01));
        assert!(srv01_down.0.findings.iter().any(|f| f.fingerprint == pw004));
        assert!(!neither.0.findings.iter().any(|f| f.fingerprint == pw004));
        let mut runs = Runs::default();
        runs.run(&both);
        runs.run(&srv01_down);
        let t = &runs.state.findings[&pw004];
        assert!(
            t.requires.iter().any(|u| u.contains(&host_hash(SRV01))),
            "SRV01 kept: {:?}",
            t.requires
        );
        runs.run(&neither);
        assert_eq!(runs.status(&pw004), Status::Open, "SRV01 still down");
        runs.run(&forest_with(srv01_clean));
        assert_eq!(runs.status(&pw004), Status::Resolved);
    }

    /// Only a computer whose edge led to Tier Zero holds the reach
    /// findings: WS01 (BOB's session, no path) down for good holds no
    /// PW-006; SRV01 (DA_ALICE's session) does.
    #[test]
    fn only_computers_on_a_path_to_tier_zero_hold_reach_findings() {
        use crate::opengraph::hosts::host_hash;

        let full = forest_with(|_, _| Some(()));
        assert!(full
            .1
            .host_edges
            .iter()
            .any(|k| k.contains(&host_hash(SRV01))));
        assert!(
            !full
                .1
                .host_edges
                .iter()
                .any(|k| k.contains(&host_hash(WS01))),
            "{:?}",
            full.1.host_edges
        );
        let mut reach = finding("R", false);
        reach.rule = "PW-001";
        let state = reconcile(&FindingsState::default(), &[reach.clone()], 100, false).state;
        let (_, had) = full.1.recorded(&[], false);
        for (down, held) in [(WS01, false), (SRV01, true)] {
            let run = forest_with(|id, c| {
                sessions_unread(down)(id, c)?;
                groups_unread(down)(id, c)
            });
            let scope =
                ResolveScope::domains(&run.0.domains, true).with_sources(run.1.clone(), &had);
            let r = reconcile_scoped::<Finding>(&state, &[], 200, false, &scope);
            let status = r.state.findings[&reach.fingerprint].status;
            assert_eq!(status == Status::Open, held, "{down}");
        }
    }

    /// Read in full means every list read before: SRV01's sessions read
    /// with none, but its privileged sessions not: PW-004 held.
    #[test]
    fn privileged_sessions_failing_alone_hold_pw004() {
        let full = forest_with(|_, _| Some(()));
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let privileged_down = forest_with(|id, c| {
            if id == SRV01 {
                c["Sessions"]["Results"] = serde_json::json!([]);
                c["PrivilegedSessions"] = serde_json::json!({"Results": [], "Collected": false,
                    "FailureReason": "access denied"});
            }
            Some(())
        });
        let mut runs = Runs::default();
        runs.run(&full);
        runs.run(&privileged_down);
        assert_eq!(runs.status(&pw004), Status::Open);
        runs.run(&forest_with(srv01_clean));
        assert_eq!(runs.status(&pw004), Status::Resolved);
    }

    /// The first run after an upgrade from a version that recorded no
    /// computers: a finding that doesn't list its computers is held while a
    /// computer of its kind isn't read, and the run after too, until they
    /// are.
    #[test]
    fn the_run_after_an_upgrade_holds_what_it_cant_place() {
        let full = forest_with(|_, _| Some(()));
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let mut runs = Runs::default();
        runs.run(&full);
        // As 0.2 left it: no computers on the finding, none recorded.
        for t in runs.state.findings.values_mut() {
            t.requires.clear();
        }
        runs.prev.clear();
        runs.legacy = true;
        let unread = forest_with(sessions_unread(SRV01));
        runs.run(&unread);
        assert_eq!(runs.status(&pw004), Status::Open, "upgrade run");
        assert!(
            runs.prev
                .iter()
                .any(|k| k.ends_with(crate::opengraph::hosts::SEEDED)),
            "{:?}",
            runs.prev
        );
        runs.run(&unread);
        assert_eq!(runs.status(&pw004), Status::Open, "the run after");
        runs.run(&forest_with(srv01_clean));
        assert_eq!(runs.status(&pw004), Status::Resolved);
    }

    /// APP01 pre-staged: never logged on, its lists never read. On an
    /// upgrade it counts as gone, not as a computer to wait for: the
    /// finding resolves once SRV01 is read again. A reach finding isn't
    /// held by the upgrade at all.
    #[test]
    fn a_pre_staged_computer_doesnt_hold_an_upgrade() {
        // The other computers logged on today, as they do in a real
        // domain; APP01 never did.
        let today = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let prestaged = move |id: &str, c: &mut serde_json::Value| {
            c["Properties"]["lastlogontimestamp"] = serde_json::json!(today);
            if id == APP01 {
                c["Properties"]["lastlogontimestamp"] = serde_json::json!(-1);
                c["Sessions"] = serde_json::json!({"Results": [], "Collected": false,
                    "FailureReason": "not reachable"});
            }
            Some(())
        };
        let full = forest_with(|id, c| {
            prestaged(id, c)?;
            if id == APP01 {
                c["Sessions"] = serde_json::json!({"Results": [], "Collected": true});
            }
            Some(())
        });
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let mut reach = finding("R", false);
        reach.rule = "PW-006";
        reach.rests_on = crate::posture::Untargeted::BOTH;
        let mut runs = Runs::default();
        let mut seen = full.0.findings.clone();
        seen.push(reach.clone());
        runs.state = reconcile(&FindingsState::default(), &seen, 100, false).state;
        runs.at = 100;
        for t in runs.state.findings.values_mut() {
            t.requires.clear();
        }
        runs.legacy = true;
        runs.run(&forest_with(|id, c| {
            prestaged(id, c)?;
            sessions_unread(SRV01)(id, c)
        }));
        assert_eq!(runs.status(&pw004), Status::Open, "SRV01 down");
        assert_eq!(
            runs.status(&reach.fingerprint),
            Status::Resolved,
            "reach findings wait for recorded computers, not the upgrade"
        );
        assert!(
            !runs
                .prev
                .iter()
                .any(|k| k.contains(&crate::opengraph::hosts::host_hash(APP01))),
            "APP01 is gone, not seeded: {:?}",
            runs.prev
        );
        runs.run(&forest_with(|id, c| {
            prestaged(id, c)?;
            srv01_clean(id, c)
        }));
        assert_eq!(runs.status(&pw004), Status::Resolved);
    }

    /// `testdata/forest` has logon times for users and none for computers:
    /// no computer counts as gone for never having logged on, so SRV01 down
    /// still holds PW-004 (counting them gone would mark it fixed).
    #[test]
    fn computers_without_logon_times_are_not_gone() {
        let full = forest_with(|_, _| Some(()));
        let a = &full.0;
        assert!(a
            .graph
            .nodes()
            .any(|(_, n)| n.kind == crate::model::NodeKind::User
                && n.props.lastlogontimestamp.is_some()));
        assert!(!a
            .graph
            .nodes()
            .any(|(_, n)| n.kind == crate::model::NodeKind::Computer
                && n.props.lastlogontimestamp.is_some()));
        let gone = crate::analysis::computer_gone(&a.graph, a.settings.now, a.settings.stale_days);
        assert!(!gone.iter().any(|g| *g));
        let pw004 = listing(a, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let mut runs = Runs::default();
        runs.run(&full);
        runs.run(&forest_with(sessions_unread(SRV01)));
        assert_eq!(runs.status(&pw004), Status::Open);
    }

    /// An All collection read SRV01's privileged sessions; a Default one
    /// doesn't ask for them. PW-004 is held as not targeted (never "weren't
    /// read"), the list isn't carried to the next run, and an All run with
    /// no session fixes it.
    #[test]
    fn a_list_not_asked_for_is_not_targeted() {
        use crate::opengraph::hosts::units;
        let full = forest_with(|_, _| Some(()));
        let pw004 = listing(&full.0, "PW-004", "S-1-5-21-1000-1000-1000-1101");
        let f = full
            .0
            .findings
            .iter()
            .find(|f| f.fingerprint == pw004)
            .unwrap()
            .clone();
        let privileged = units(SRV01, crate::opengraph::SESSION_HOST, 2).remove(0);
        assert!(f.requires.contains(&privileged));
        let default = forest_with(|id, c| {
            if id == SRV01 {
                c["Sessions"]["Results"] = serde_json::json!([]);
                c["PrivilegedSessions"] = serde_json::json!({"Results": [], "Collected": false});
            }
            Some(())
        });
        assert_eq!(
            default.1.hold_reason(&f.sources, &f.requires).as_deref(),
            Some("sessions were not targeted in this collection, and the finding may rest on them")
        );
        let mut runs = Runs::default();
        runs.run(&full);
        runs.run(&default);
        assert_eq!(runs.status(&pw004), Status::Open);
        assert!(!runs.prev.contains(&privileged), "not carried");
        runs.run(&forest_with(srv01_clean));
        assert_eq!(runs.status(&pw004), Status::Resolved);
    }

    /// A sighting's units and the ones it keeps stay within the cap: past
    /// it, the kind's any-computer unit.
    #[test]
    fn kept_units_stay_within_the_cap() {
        use crate::opengraph::hosts::{host_hash, units, ANY_HOST};
        use crate::opengraph::SESSION_HOST;
        let ids: Vec<String> = (0..300).map(|i| format!("S-1-5-21-9-9-9-{i}")).collect();
        let unit = |id: &String| units(id, SESSION_HOST, 1).remove(0);
        let mut f = finding("C", false);
        f.requires = ids[..200].iter().map(unit).collect();
        let r1 = reconcile(
            &FindingsState::default(),
            std::slice::from_ref(&f),
            100,
            false,
        );
        // The first 200 down, the other 100 seen now.
        let sources = RunSources {
            host_reads: ids
                .iter()
                .enumerate()
                .map(|(i, id)| (host_hash(id), if i < 200 { 0 } else { 1 }))
                .collect(),
            ..RunSources::default()
        };
        f.requires = ids[200..].iter().map(unit).collect();
        let scope = ResolveScope::everything().with_sources(sources, &[]);
        let r2 = reconcile_scoped(&r1.state, std::slice::from_ref(&f), 200, false, &scope);
        assert_eq!(
            r2.state.findings[&f.fingerprint].requires,
            [format!("{SESSION_HOST}{ANY_HOST}")]
        );
    }
}
