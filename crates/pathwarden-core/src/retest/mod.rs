//! Retesting: after remediation, did the findings of an earlier analysis go
//! away?
//!
//! A retest compares a **baseline** (the findings of an earlier analysis: the
//! run state, an event document, or the findings of an earlier collection)
//! with the findings of a fresh collection, by fingerprint. Each baseline
//! finding is then:
//!
//! - **Fixed**: its domain was collected and the fingerprint is gone;
//! - **Still open**: the fingerprint is still there, with what changed
//!   ("exposure 61.0% → 12.0%", "2 of 5 affected objects remain");
//! - **Can't tell**: its domain was not collected, or the collection looks
//!   incomplete, so its absence proves nothing. A finding that rests on
//!   OpenGraph data (TaskHound, ...) is also "can't tell" unless that source
//!   is present with a coverage file that lists the affected host
//!   ([`crate::opengraph::coverage`]).
//!
//! Findings in the fresh collection that the baseline never had are **new**
//! (or **regressed** when the baseline knew them as resolved).
//!
//! [`targeted`] retests one finding by re-reading only its objects.

pub mod targeted;

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::findings::{self, Category, Finding, Severity};
use crate::opengraph::coverage::RunSources;
use crate::opengraph::source_key;
use crate::posture::Untargeted;
use crate::state::{scope_key, FindingsState, Status};

/// What a retest knows about one finding, from whichever source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingView {
    pub fingerprint: String,
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The name-free domain key ([`scope_key`]); state baselines carry only
    /// this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Covered by a suppression (accepted risk).
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureView>,
    /// Affected objects, when the source lists them (not the state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected: Option<Vec<AffectedView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
    /// Keys ([`source_key`]) of the OpenGraph sources it rests on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Keys of the coverage units those sources must cover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// What the baseline's run did not target in the finding's domain
    /// ([`crate::state::TrackedFinding::not_targeted`]). Empty when it
    /// targeted both, or doesn't say: a fresh collection that lacks
    /// sessions or local groups then can't tell an attack-path finding
    /// fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_targeted: Vec<String>,
    /// What it rests on of sessions and local groups
    /// ([`crate::findings::Finding::rests_on`]); `None` when the source
    /// doesn't say ([`Untargeted::rested_on`] then).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rests_on: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ExposureView {
    pub principals: usize,
    pub population: usize,
    pub percent: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedView {
    pub id: String,
    pub name: String,
}

impl From<&Finding> for FindingView {
    fn from(f: &Finding) -> Self {
        FindingView {
            fingerprint: f.fingerprint.clone(),
            rule: f.rule.to_string(),
            severity: Some(f.severity),
            title: Some(f.title.clone()),
            domain: f.domain.clone(),
            scope: f.domain.as_deref().map(scope_key),
            suppressed: f.suppressed.is_some(),
            exposure: f.exposure.as_ref().map(|e| ExposureView {
                principals: e.principals,
                population: e.population,
                percent: e.percent,
            }),
            affected: Some(
                f.affected
                    .iter()
                    .map(|a| AffectedView {
                        id: a.id.clone(),
                        name: a.name.clone(),
                    })
                    .collect(),
            ),
            category: Some(f.category),
            sources: f.sources.iter().map(|s| source_key(s)).collect(),
            requires: f.requires.clone(),
            not_targeted: Vec::new(),
            rests_on: Some(f.rests_on.parts()),
        }
    }
}

impl FindingView {
    /// Records what the run these views are of did not target, by domain
    /// ([`crate::posture::untargeted_domains`]): for a baseline read from
    /// an earlier collection.
    pub fn mark_untargeted(views: &mut [FindingView], domains: &[(String, Untargeted)]) {
        let by_scope: HashMap<String, Untargeted> =
            domains.iter().map(|(d, u)| (scope_key(d), *u)).collect();
        let all = domains
            .iter()
            .fold(Untargeted::default(), |a, (_, u)| a.or(*u));
        for v in views {
            let u = match &v.scope {
                Some(s) => by_scope.get(s).copied().unwrap_or_default(),
                None => all,
            };
            v.not_targeted = u.parts();
        }
    }
}

/// A finding as the event document (`pathwarden.event.v1`) writes it; only
/// the fields a retest reads.
#[derive(Deserialize)]
struct EventFinding {
    fingerprint: String,
    rule: String,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    suppressed: Option<String>,
    #[serde(default)]
    exposure: Option<ExposureView>,
    #[serde(default)]
    affected: Option<Vec<AffectedView>>,
    #[serde(default)]
    category: Option<Category>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    rests_on: Option<Untargeted>,
}

#[derive(Deserialize)]
struct EventDoc {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    run: Option<EventRun>,
    findings: Vec<EventFinding>,
}

#[derive(Deserialize)]
struct EventRun {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    collected_at: Option<i64>,
    #[serde(default)]
    objects: usize,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    sources_exact: bool,
    #[serde(default, with = "crate::state::packed_hosts")]
    hosts: Option<Vec<String>>,
}

/// The findings of an event document, with the domains and collection time
/// of its run.
pub struct EventFindings {
    pub findings: Vec<FindingView>,
    pub domains: Vec<String>,
    pub collected_at: Option<i64>,
    /// Collected objects (0 when unknown).
    pub objects: usize,
    /// Keys of the run's sources (OpenGraph, and SYSVOL parts), as its
    /// `LastRun::sources` recorded them, then its `LastRun::hosts`.
    pub sources: Vec<String>,
    /// `LastRun::sources_exact` of the run.
    pub sources_exact: bool,
    /// The run didn't record its computers (`LastRun::hosts` absent: 0.2 or
    /// earlier): [`Coverage::legacy_hosts`].
    pub legacy_hosts: bool,
}

/// Reads an event document (`pathwarden run --event`). Errors when the text
/// is not one.
pub fn parse_event(text: &str) -> Result<EventFindings, String> {
    let doc: EventDoc =
        serde_json::from_str(text).map_err(|e| format!("not an event document: {e}"))?;
    if !doc.schema.starts_with("pathwarden.event.") {
        return Err("not a Pathwarden event document (no pathwarden.event schema)".into());
    }
    let legacy_hosts = doc.run.as_ref().is_some_and(|r| r.hosts.is_none());
    let run = doc.run.unwrap_or(EventRun {
        domains: Vec::new(),
        collected_at: None,
        objects: 0,
        sources: Vec::new(),
        sources_exact: true,
        hosts: None,
    });
    Ok(EventFindings {
        findings: doc
            .findings
            .into_iter()
            .map(|f| FindingView {
                scope: f.domain.as_deref().map(scope_key),
                fingerprint: f.fingerprint,
                rule: f.rule,
                severity: f.severity,
                title: f.title,
                domain: f.domain,
                suppressed: f.suppressed.is_some(),
                exposure: f.exposure,
                affected: f.affected,
                category: f.category,
                sources: f.sources.iter().map(|s| source_key(s)).collect(),
                requires: f.requires,
                // Events don't say: read as targeted.
                not_targeted: Vec::new(),
                rests_on: f.rests_on.map(Untargeted::parts),
            })
            .collect(),
        domains: run.domains,
        collected_at: run.collected_at,
        objects: run.objects,
        sources: run
            .sources
            .into_iter()
            .chain(run.hosts.into_iter().flatten())
            .collect(),
        sources_exact: run.sources_exact,
        legacy_hosts,
    })
}

/// Whether `text` is an event document. A cheap check on the start first;
/// a lean build of 0.1.6 or earlier wrote the keys sorted, so `schema` can
/// also come late, and then the top-level key decides.
pub fn looks_like_event(text: &str) -> bool {
    let head: String = text.chars().take(4096).collect();
    if head.contains("\"pathwarden.event.") {
        return true;
    }
    #[derive(Deserialize)]
    struct Schema {
        schema: Option<String>,
    }
    text.contains("\"pathwarden.event.")
        && serde_json::from_str::<Schema>(text)
            .ok()
            .and_then(|d| d.schema)
            .is_some_and(|s| s.starts_with("pathwarden.event."))
}

/// What a fresh collection is compared against.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// In words, for output: "state pathwarden-state", "event ev.json".
    pub label: String,
    /// Findings that were open (not suppressed, not resolved): what gets
    /// retested.
    pub open: Vec<FindingView>,
    /// Every fingerprint the baseline knows, in any status.
    pub known: HashSet<String>,
    /// Fingerprints the baseline knows as resolved (back now = regressed).
    pub resolved: HashSet<String>,
}

impl Baseline {
    /// From the run state. The state keeps no names by default, so titles
    /// and affected objects are absent unless `include_names` was on.
    pub fn from_state(state: &FindingsState, label: impl Into<String>) -> Self {
        let mut b = Baseline {
            label: label.into(),
            ..Baseline::default()
        };
        for (fp, t) in &state.findings {
            b.known.insert(fp.clone());
            match t.status {
                // Set aside while its rule was off, not fixed: back is
                // not a regression.
                Status::Resolved if t.rule_off => {}
                Status::Resolved => {
                    b.resolved.insert(fp.clone());
                }
                Status::Suppressed => {}
                Status::Open => b.open.push(FindingView {
                    fingerprint: fp.clone(),
                    rule: t.rule.clone(),
                    severity: Some(t.severity),
                    title: t.title.clone(),
                    domain: t.domain.clone(),
                    scope: t
                        .scope
                        .clone()
                        .or_else(|| t.domain.as_deref().map(scope_key)),
                    suppressed: false,
                    exposure: None,
                    affected: None,
                    category: Some(t.category),
                    sources: t.sources.clone(),
                    requires: t.requires.clone(),
                    not_targeted: t.not_targeted.clone(),
                    rests_on: t.rests_on.clone(),
                }),
            }
        }
        b
    }

    /// From the findings of an earlier analysis (an earlier collection, or an
    /// event document).
    pub fn from_views(views: Vec<FindingView>, label: impl Into<String>) -> Self {
        let mut b = Baseline {
            label: label.into(),
            ..Baseline::default()
        };
        for v in views {
            b.known.insert(v.fingerprint.clone());
            if !v.suppressed {
                b.open.push(v);
            }
        }
        b
    }
}

/// Which baseline findings to retest. Empty means all of them.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub fingerprints: Vec<String>,
    pub rules: Vec<String>,
}

impl Selection {
    fn is_targeted(&self) -> bool {
        !self.fingerprints.is_empty()
    }

    fn rule_matches(&self, rule: &str) -> bool {
        self.rules.is_empty() || self.rules.iter().any(|r| r.eq_ignore_ascii_case(rule))
    }
}

/// What the fresh collection covered.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    /// Domains present in the fresh collection.
    pub domains: Vec<String>,
    /// False when the collection looks incomplete (much smaller than the
    /// baseline's): nothing missing from it counts as fixed.
    pub complete: bool,
    /// The OpenGraph sources of the fresh collection and what they covered.
    pub sources: RunSources,
    /// Keys of sources (OpenGraph, SYSVOL parts) the baseline run had data
    /// from that the fresh collection lacks (or read only partly):
    /// attack-path findings missing from it can't be told.
    pub missing_sources: Vec<String>,
    /// Computers the baseline had a session, a local group right or a
    /// stored credential on that the fresh collection didn't read again in
    /// full ([`RunSources::missing_hosts_since`]): findings that exist
    /// because an account reaches Tier Zero by any path can't be told.
    pub missing_hosts: Vec<String>,
    /// What the fresh collection did not target, by the scope key of each
    /// domain that lacks something: an attack-path finding the baseline saw
    /// with sessions or local groups read can't be told fixed without them.
    pub not_targeted: HashMap<String, Untargeted>,
    /// The baseline didn't record its computers (0.2 or earlier): a finding
    /// that rests on sessions or local groups without listing its computers
    /// can't be told fixed while any computer of the kind isn't read
    /// ([`crate::state::ResolveScope::with_legacy_hosts`]).
    pub legacy_hosts: bool,
}

impl Coverage {
    /// Notes what of `had` (the baseline's sources and hosts) the fresh
    /// collection's [`Coverage::sources`] lack.
    pub fn compared_with(mut self, had: &[String]) -> Self {
        self.missing_sources = self
            .sources
            .missing_since(had)
            .into_iter()
            .cloned()
            .collect();
        self.sources.note_missing(had);
        let mut missing: Vec<String> = self.sources.missing_hosts.iter().cloned().collect();
        missing.sort_unstable();
        self.missing_hosts = missing;
        self
    }

    /// The kinds a baseline finding that doesn't list its computers rests
    /// on, of which a computer isn't read ([`Coverage::legacy_hosts`]).
    fn legacy_for(&self, b: &FindingView, rested: Untargeted) -> Untargeted {
        use crate::opengraph::{LOCAL_GROUP_HOST, SESSION_HOST};
        // Reach findings: held by the computers runs record, not this.
        if !self.legacy_hosts || crate::posture::is_reach_rule(&b.rule) {
            return Untargeted::default();
        }
        let lists = |mark: &str| b.requires.iter().any(|u| u.starts_with(mark));
        Untargeted {
            sessions: rested.sessions
                && !lists(SESSION_HOST)
                && self.sources.any_unread(SESSION_HOST),
            local_groups: rested.local_groups
                && !lists(LOCAL_GROUP_HOST)
                && self.sources.any_unread(LOCAL_GROUP_HOST),
        }
    }

    /// [`Coverage::with_untargeted`] by scope key
    /// ([`crate::state::CompletenessPoint::untargeted_by_scope`]).
    pub fn with_untargeted_scopes(mut self, scopes: Vec<(String, Untargeted)>) -> Self {
        self.not_targeted = scopes.into_iter().collect();
        self
    }

    /// Adds what the fresh collection did not target, per domain by name
    /// ([`crate::posture::untargeted_domains`]).
    pub fn with_untargeted(mut self, domains: &[(String, Untargeted)]) -> Self {
        self.not_targeted = domains.iter().map(|(d, u)| (scope_key(d), *u)).collect();
        self
    }

    /// What the fresh collection lacks for `b` that its baseline had.
    fn lost_for(&self, b: &FindingView) -> Untargeted {
        let here = match &b.scope {
            Some(s) => self.not_targeted.get(s).copied().unwrap_or_default(),
            None => self
                .not_targeted
                .values()
                .fold(Untargeted::default(), |a, u| a.or(*u)),
        };
        here.lost_since(Untargeted::from_parts(&b.not_targeted))
            .and(rested_of(b))
    }
}

/// What a baseline finding rests on, when it says; else by its rule and
/// category (a baseline that doesn't say the category reads as an attack
/// path).
fn rested_of(b: &FindingView) -> Untargeted {
    match &b.rests_on {
        Some(parts) => Untargeted::from_parts(parts),
        None => Untargeted::rested_on(&b.rule, b.category != Some(Category::Hygiene)),
    }
}

/// `words` with a capital first letter.
fn capitalized(words: &str) -> String {
    let mut c = words.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Fixed,
    StillOpen,
    CantTell,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Fixed => "Fixed",
            Verdict::StillOpen => "Still open",
            Verdict::CantTell => "Can't tell",
        }
    }
}

/// One retested finding.
#[derive(Debug, Clone, Serialize)]
pub struct Retested {
    pub fingerprint: String,
    pub rule: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// The finding's title (from the fresh data when still open), or the
    /// rule's title when the baseline keeps no names.
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// What changed, in words ("exposure 61.0% → 12.0%"), or why the verdict
    /// can't be given.
    pub details: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_before: Option<ExposureView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_after: Option<ExposureView>,
    /// Affected objects in the baseline, and how many of them remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_before: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_remaining: Option<usize>,
    /// "Can't tell" only because the fresh collection didn't read sessions
    /// or local groups it may rest on ([`held`]): a targeted retest that
    /// reads the computers on its path can tell.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
}

/// The line a held finding shows next to its retest action, in the app and
/// on the command line ([`held`]).
pub const HELD_LINE: &str = "Retest it to check the computers on its path.";

/// Whether a baseline finding the fresh collection lacks is held for what
/// that collection didn't target: [`absent`] says "can't tell" for that
/// reason alone.
pub fn held(b: &FindingView, coverage: &Coverage) -> bool {
    let (verdict, _) = absent(b, coverage);
    verdict == Verdict::CantTell && {
        // As if targeted: the computers of what wasn't targeted read too.
        let lost = coverage.lost_for(b);
        let mut targeted = Coverage {
            not_targeted: HashMap::new(),
            ..coverage.clone()
        };
        if lost.any() {
            targeted.missing_hosts.clear();
            targeted.sources.missing_hosts.clear();
            targeted.legacy_hosts = false;
        }
        // Lists this collection didn't ask for are targeted then too.
        targeted.sources.unasked_hosts.clear();
        let mut requires = without_hosts(&b.requires, lost);
        requires.retain(|u| !coverage.sources.not_asked(u));
        let b = FindingView {
            requires,
            ..b.clone()
        };
        absent(&b, &targeted).0 == Verdict::Fixed
    }
}

/// `requires` without the session or local group computers of `lost`
/// (what the collection didn't target), which the not-targeted reason
/// covers.
fn without_hosts(requires: &[String], lost: Untargeted) -> Vec<String> {
    use crate::opengraph::{LOCAL_GROUP_HOST, SESSION_HOST};
    requires
        .iter()
        .filter(|u| {
            !(lost.sessions && u.starts_with(SESSION_HOST)
                || lost.local_groups && u.starts_with(LOCAL_GROUP_HOST))
        })
        .cloned()
        .collect()
}

/// A finding the baseline did not have open.
#[derive(Debug, Clone, Serialize)]
pub struct NewFinding {
    pub fingerprint: String,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The baseline knew it as resolved: it came back.
    pub regressed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RetestCounts {
    pub fixed: usize,
    pub still_open: usize,
    pub cant_tell: usize,
    pub new: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetestReport {
    pub baseline: String,
    pub results: Vec<Retested>,
    pub new: Vec<NewFinding>,
    pub counts: RetestCounts,
}

impl RetestReport {
    /// 0: every retested finding is fixed (or there was nothing to retest);
    /// 1: some are still open; 3: none open, but some can't be told.
    pub fn exit_code(&self) -> u8 {
        if self.counts.still_open > 0 {
            1
        } else if self.counts.cant_tell > 0 {
            3
        } else {
            0
        }
    }
}

fn rule_title(rule: &str) -> String {
    findings::rules()
        .iter()
        .find(|r| r.id == rule)
        .map(|r| r.title.to_string())
        .unwrap_or_else(|| rule.to_string())
}

fn pct(v: f64) -> String {
    crate::posture::share_percent(v)
}

/// What changed between a baseline finding and the same finding now.
pub fn describe_changes(before: &FindingView, after: &FindingView) -> Vec<String> {
    let mut out = Vec::new();
    match (&before.exposure, &after.exposure) {
        (Some(b), Some(a)) if (b.percent - a.percent).abs() >= 0.05 => out.push(format!(
            "exposure {} → {} ({} → {} of {})",
            pct(b.percent),
            pct(a.percent),
            b.principals,
            a.principals,
            a.population
        )),
        (Some(b), Some(_)) => out.push(format!("exposure unchanged at {}", pct(b.percent))),
        _ => {}
    }
    if let (Some(b), Some(a)) = (before.severity, after.severity) {
        if b != a {
            out.push(format!("severity {} → {}", b.as_str(), a.as_str()));
        }
    }
    if let (Some(b), Some(a)) = (&before.affected, &after.affected) {
        let now: HashSet<&str> = a.iter().map(|x| x.id.as_str()).collect();
        let was: HashSet<&str> = b.iter().map(|x| x.id.as_str()).collect();
        let remaining = b.iter().filter(|x| now.contains(x.id.as_str())).count();
        let added = a.iter().filter(|x| !was.contains(x.id.as_str())).count();
        if b.len() > 1 || remaining < b.len() {
            if remaining == b.len() {
                out.push(format!("all {} affected objects remain", b.len()));
            } else {
                out.push(format!(
                    "{remaining} of {} affected objects remain",
                    b.len()
                ));
            }
        }
        if added > 0 {
            out.push(format!(
                "{added} newly affected object{}",
                if added == 1 { "" } else { "s" }
            ));
        }
    }
    if after.suppressed {
        out.push("now an accepted risk".into());
    }
    out
}

/// The verdict on a baseline finding the fresh collection doesn't have:
/// fixed, or "can't tell" and why (its domain not collected, the
/// collection incomplete, a source missing, or sessions and local groups
/// it may rest on not targeted). The app's retest column says the same.
pub fn absent(b: &FindingView, coverage: &Coverage) -> (Verdict, Vec<String>) {
    let collected: HashSet<String> = coverage.domains.iter().map(|d| scope_key(d)).collect();
    let in_scope = match &b.scope {
        Some(scope) => collected.contains(scope),
        None => !coverage.domains.is_empty(),
    };
    // Sessions or local groups the collection didn't target are said as
    // such below, not computer by computer.
    let lost = coverage.lost_for(b);
    let requires = without_hosts(&b.requires, lost);
    if !in_scope {
        (
            Verdict::CantTell,
            vec![match &b.domain {
                Some(d) => format!("{d} was not in this collection"),
                None => "its domain was not in this collection".to_string(),
            }],
        )
    } else if !coverage.complete {
        (
            Verdict::CantTell,
            vec!["this collection looks incomplete (much smaller than the last one)".to_string()],
        )
    } else if let Some(why) = coverage.sources.hold_reason(&b.sources, &requires) {
        (Verdict::CantTell, vec![why])
    } else if b.category != Some(Category::Hygiene) && !coverage.missing_sources.is_empty() {
        (
            Verdict::CantTell,
            vec![format!(
                "data the baseline had is missing or incomplete in this collection, \
                     and a path may have run through it: {}",
                coverage.sources.describe(&coverage.missing_sources)
            )],
        )
    } else if crate::posture::is_reach_rule(&b.rule)
        && coverage.sources.missing_reach_hosts()
        && lost.none()
    {
        // The computers the run's warning names too (not those recorded
        // on an upgrade); those only not asked for are not targeted.
        let (unasked, unread): (Vec<String>, Vec<String>) = coverage
            .sources
            .reach_keys()
            .cloned()
            .partition(|k| coverage.sources.not_asked(k));
        let why = if unread.is_empty() {
            let kind = |m: &str| unasked.iter().any(|k| k.starts_with(m));
            let words = Untargeted {
                sessions: kind(crate::opengraph::SESSION_HOST),
                local_groups: kind(crate::opengraph::LOCAL_GROUP_HOST),
            }
            .words()
            .unwrap_or("sessions and local groups");
            format!("{words} weren't collected in this run, and the finding may depend on them")
        } else {
            format!(
                "computers the baseline had data from weren't read again, \
                     and a path may have run through them: {}",
                coverage.sources.describe(&unread)
            )
        };
        (Verdict::CantTell, vec![why])
    } else if let (true, Some(words)) = (lost.none(), coverage.legacy_for(b, rested_of(b)).words())
    {
        (
            Verdict::CantTell,
            vec![format!(
                "{} weren't read on every computer, and the baseline doesn't say which \
                     it rests on, so it can't be confirmed fixed.",
                capitalized(words)
            )],
        )
    } else if let Some(words) = lost.words() {
        (
            Verdict::CantTell,
            vec![format!(
                "{words} weren't collected in this run, and the finding may depend \
                     on them"
            )],
        )
    } else {
        (Verdict::Fixed, Vec::new())
    }
}

/// Compares the baseline with the findings of a fresh collection.
///
/// Errors when the selection names a fingerprint the baseline does not have
/// open.
pub fn compare(
    baseline: &Baseline,
    current: &[FindingView],
    coverage: &Coverage,
    selection: &Selection,
) -> Result<RetestReport, String> {
    let by_fp: HashMap<&str, &FindingView> = current
        .iter()
        .map(|f| (f.fingerprint.as_str(), f))
        .collect();

    let wanted: BTreeSet<String> = selection
        .fingerprints
        .iter()
        .map(|f| f.trim().to_string())
        .collect();
    if selection.is_targeted() {
        let open: HashSet<String> = baseline
            .open
            .iter()
            .map(|f| f.fingerprint.to_ascii_lowercase())
            .collect();
        let missing: Vec<&String> = wanted
            .iter()
            .filter(|f| !open.contains(&f.to_ascii_lowercase()))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "not an open finding in the baseline ({}): {}",
                baseline.label,
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let selected = |f: &FindingView| {
        selection.rule_matches(&f.rule)
            && (!selection.is_targeted()
                || wanted
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(&f.fingerprint)))
    };

    let mut counts = RetestCounts::default();
    let mut results = Vec::new();
    for b in baseline.open.iter().filter(|f| selected(f)) {
        let fallback_title = || b.title.clone().unwrap_or_else(|| rule_title(&b.rule));
        let r = match by_fp.get(b.fingerprint.as_str()) {
            Some(now) => {
                let affected_remaining = match (&b.affected, &now.affected) {
                    (Some(before), Some(after)) => {
                        let ids: HashSet<&str> = after.iter().map(|a| a.id.as_str()).collect();
                        Some(
                            before
                                .iter()
                                .filter(|a| ids.contains(a.id.as_str()))
                                .count(),
                        )
                    }
                    _ => None,
                };
                Retested {
                    fingerprint: b.fingerprint.clone(),
                    rule: b.rule.clone(),
                    verdict: Verdict::StillOpen,
                    severity: now.severity.or(b.severity),
                    title: now.title.clone().unwrap_or_else(fallback_title),
                    domain: now.domain.clone().or_else(|| b.domain.clone()),
                    details: describe_changes(b, now),
                    exposure_before: b.exposure,
                    exposure_after: now.exposure,
                    affected_before: b.affected.as_ref().map(Vec::len),
                    affected_remaining,
                    held: false,
                }
            }
            None => {
                let (verdict, details) = absent(b, coverage);
                let held = held(b, coverage);
                Retested {
                    fingerprint: b.fingerprint.clone(),
                    rule: b.rule.clone(),
                    verdict,
                    severity: b.severity,
                    title: fallback_title(),
                    domain: b.domain.clone(),
                    details,
                    exposure_before: b.exposure,
                    exposure_after: None,
                    affected_before: b.affected.as_ref().map(Vec::len),
                    affected_remaining: (verdict == Verdict::Fixed)
                        .then_some(0)
                        .filter(|_| b.affected.is_some()),
                    held,
                }
            }
        };
        match r.verdict {
            Verdict::Fixed => counts.fixed += 1,
            Verdict::StillOpen => counts.still_open += 1,
            Verdict::CantTell => counts.cant_tell += 1,
        }
        results.push(r);
    }
    // Most urgent first: still open, can't tell, fixed; then by severity.
    results.sort_by(|a, b| {
        let rank = |v: Verdict| match v {
            Verdict::StillOpen => 0,
            Verdict::CantTell => 1,
            Verdict::Fixed => 2,
        };
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then(b.severity.cmp(&a.severity))
            .then(a.rule.cmp(&b.rule))
            .then(a.title.cmp(&b.title))
    });

    let open_before: HashSet<&str> = baseline
        .open
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    let mut new: Vec<NewFinding> = if selection.is_targeted() {
        Vec::new()
    } else {
        current
            .iter()
            .filter(|f| !f.suppressed && selection.rule_matches(&f.rule))
            .filter(|f| !open_before.contains(f.fingerprint.as_str()))
            // A finding the baseline knows as suppressed is not new.
            .filter(|f| {
                !baseline.known.contains(&f.fingerprint)
                    || baseline.resolved.contains(&f.fingerprint)
            })
            .map(|f| NewFinding {
                fingerprint: f.fingerprint.clone(),
                rule: f.rule.clone(),
                severity: f.severity,
                title: f.title.clone().unwrap_or_else(|| rule_title(&f.rule)),
                domain: f.domain.clone(),
                regressed: baseline.resolved.contains(&f.fingerprint),
            })
            .collect()
    };
    new.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.rule.cmp(&b.rule))
            .then(a.title.cmp(&b.title))
    });
    counts.new = new.len();
    Ok(RetestReport {
        baseline: baseline.label.clone(),
        results,
        new,
        counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(fp: &str, rule: &str, domain: &str) -> FindingView {
        FindingView {
            fingerprint: fp.into(),
            rule: rule.into(),
            severity: Some(Severity::High),
            title: Some(format!("{fp} title")),
            domain: Some(domain.into()),
            scope: Some(scope_key(domain)),
            ..FindingView::default()
        }
    }

    fn affected(ids: &[&str]) -> Option<Vec<AffectedView>> {
        Some(
            ids.iter()
                .map(|i| AffectedView {
                    id: i.to_string(),
                    name: i.to_string(),
                })
                .collect(),
        )
    }

    fn coverage(domains: &[&str]) -> Coverage {
        Coverage {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            complete: true,
            ..Coverage::default()
        }
    }

    /// A fresh collection that read no sessions or local groups (Quick)
    /// can't tell an attack path the baseline saw with them is fixed; one
    /// the baseline also saw without them, and hygiene, it can.
    #[test]
    fn a_quick_retest_cant_tell_attack_paths_a_full_run_saw() {
        let mut path = view("PW-003-a", "PW-003", "A.LOCAL");
        path.category = Some(Category::AttackPath);
        let mut seen_quick = view("PW-003-q", "PW-003", "A.LOCAL");
        seen_quick.category = Some(Category::AttackPath);
        let mut hygiene = view("PW-011-h", "PW-011", "A.LOCAL");
        hygiene.category = Some(Category::Hygiene);
        let both = Untargeted {
            sessions: true,
            local_groups: true,
        };
        FindingView::mark_untargeted(
            std::slice::from_mut(&mut seen_quick),
            &[("A.LOCAL".to_string(), both)],
        );
        assert_eq!(seen_quick.not_targeted, ["sessions", "local_groups"]);
        let base = Baseline::from_views(vec![path, seen_quick, hygiene], "test");
        let quick = coverage(&["A.LOCAL"]).with_untargeted(&[("a.local".to_string(), both)]);
        let r = compare(&base, &[], &quick, &Selection::default()).unwrap();
        let get = |fp: &str| r.results.iter().find(|x| x.fingerprint == fp).unwrap();
        assert_eq!(get("PW-003-a").verdict, Verdict::CantTell);
        assert_eq!(
            get("PW-003-a").details,
            ["sessions and local groups weren't collected in this run, and the finding may depend on them"]
        );
        assert_eq!(get("PW-003-q").verdict, Verdict::Fixed);
        assert_eq!(get("PW-011-h").verdict, Verdict::Fixed);
        // A Full collection tells.
        let r = compare(&base, &[], &coverage(&["A.LOCAL"]), &Selection::default()).unwrap();
        assert_eq!(r.counts.fixed, 3);
    }

    #[test]
    fn fixed_open_cant_tell_and_new() {
        let mut a = view("PW-003-a", "PW-003", "A.LOCAL");
        a.exposure = Some(ExposureView {
            principals: 61,
            population: 100,
            percent: 61.0,
        });
        let mut b = view("PW-011-b", "PW-011", "A.LOCAL");
        b.affected = affected(&["1", "2", "3", "4", "5"]);
        let c = view("PW-007-c", "PW-007", "B.LOCAL");
        let d = view("PW-005-d", "PW-005", "A.LOCAL");
        let base = Baseline::from_views(vec![a.clone(), b.clone(), c, d], "test");

        let mut a2 = a.clone();
        a2.exposure = Some(ExposureView {
            principals: 12,
            population: 100,
            percent: 12.0,
        });
        let mut b2 = b.clone();
        b2.affected = affected(&["1", "2", "9"]);
        let e = view("PW-002-e", "PW-002", "A.LOCAL");
        let r = compare(
            &base,
            &[a2, b2, e],
            &coverage(&["A.LOCAL"]),
            &Selection::default(),
        )
        .unwrap();
        assert_eq!(
            r.counts,
            RetestCounts {
                fixed: 1,
                still_open: 2,
                cant_tell: 1,
                new: 1
            }
        );
        let get = |fp: &str| r.results.iter().find(|x| x.fingerprint == fp).unwrap();
        assert_eq!(get("PW-005-d").verdict, Verdict::Fixed);
        assert_eq!(get("PW-007-c").verdict, Verdict::CantTell);
        assert!(get("PW-007-c").details[0].contains("B.LOCAL"));
        assert!(
            get("PW-003-a").details[0].starts_with("exposure 61.00% → 12.00%"),
            "{:?}",
            get("PW-003-a").details
        );
        let bd = &get("PW-011-b").details;
        assert!(
            bd.contains(&"2 of 5 affected objects remain".to_string()),
            "{bd:?}"
        );
        assert!(
            bd.contains(&"1 newly affected object".to_string()),
            "{bd:?}"
        );
        assert_eq!(get("PW-011-b").affected_remaining, Some(2));
        assert_eq!(r.new[0].fingerprint, "PW-002-e");
        assert_eq!(r.exit_code(), 1);
        // Still open first.
        assert_eq!(r.results[0].verdict, Verdict::StillOpen);
    }

    #[test]
    fn selection_and_exit_codes() {
        let base = Baseline::from_views(
            vec![
                view("PW-003-a", "PW-003", "A.LOCAL"),
                view("PW-007-c", "PW-007", "B.LOCAL"),
            ],
            "test",
        );
        let cov = coverage(&["A.LOCAL"]);
        let one = Selection {
            fingerprints: vec!["pw-003-A".into()],
            rules: vec![],
        };
        let r = compare(&base, &[], &cov, &one).unwrap();
        assert_eq!(r.results.len(), 1);
        assert_eq!(r.exit_code(), 0);
        assert!(r.new.is_empty());
        let rule = Selection {
            fingerprints: vec![],
            rules: vec!["pw-007".into()],
        };
        let r = compare(&base, &[], &cov, &rule).unwrap();
        assert_eq!((r.results.len(), r.exit_code()), (1, 3));
        let bad = Selection {
            fingerprints: vec!["PW-999-x".into()],
            rules: vec![],
        };
        assert!(compare(&base, &[], &cov, &bad)
            .unwrap_err()
            .contains("PW-999-x"));
        // An incomplete collection proves nothing.
        let partial = Coverage {
            domains: vec!["A.LOCAL".into()],
            complete: false,
            ..Coverage::default()
        };
        let r = compare(&base, &[], &partial, &Selection::default()).unwrap();
        assert_eq!(r.counts.cant_tell, 2);
    }

    #[test]
    fn state_baselines_have_no_names_but_know_regressions() {
        use crate::findings::{Category, Severity};
        use crate::state::TrackedFinding;
        let mut st = FindingsState::default();
        let t = |status| TrackedFinding {
            rule: "PW-003".into(),
            severity: Severity::High,
            default_severity: None,
            category: Category::AttackPath,
            status,
            first_seen: 1,
            last_seen: 1,
            resolved_at: None,
            regressed_at: None,
            rule_off: false,
            times_seen: 1,
            title: None,
            domain: None,
            scope: Some(scope_key("A.LOCAL")),
            sources: Vec::new(),
            requires: Vec::new(),
            objects: None,
            not_targeted: Vec::new(),
            rests_on: None,
        };
        st.findings.insert("PW-003-open".into(), t(Status::Open));
        st.findings
            .insert("PW-003-gone".into(), t(Status::Resolved));
        st.findings
            .insert("PW-003-ok".into(), t(Status::Suppressed));
        let base = Baseline::from_state(&st, "state");
        assert_eq!(base.open.len(), 1);
        let back = view("PW-003-gone", "PW-003", "A.LOCAL");
        let accepted = view("PW-003-ok", "PW-003", "A.LOCAL");
        let r = compare(
            &base,
            &[back, accepted],
            &coverage(&["a.local"]),
            &Selection::default(),
        )
        .unwrap();
        assert_eq!(r.results[0].verdict, Verdict::Fixed);
        assert_eq!(
            r.results[0].title,
            "Account or group outside Tier Zero controls a Tier Zero object"
        );
        assert_eq!(r.new.len(), 1);
        assert!(r.new[0].regressed);
    }

    /// A lean build of 0.1.6 or earlier sorted the keys: `schema` after a
    /// long `findings`. Collector data mentioning the schema is not one.
    #[test]
    fn an_event_with_the_schema_late_is_still_one() {
        let pad = "x".repeat(5000);
        let late =
            format!(r#"{{"findings":[{{"title":"{pad}"}}],"schema":"pathwarden.event.v1"}}"#);
        assert!(looks_like_event(&late));
        let data = format!(r#"{{"data":[{{"name":"{pad} pathwarden.event.v1"}}],"meta":{{}}}}"#);
        assert!(!looks_like_event(&data));
    }

    #[test]
    fn event_documents_parse() {
        let text = r#"{"schema":"pathwarden.event.v1","run":{"domains":["A.LOCAL"],"collected_at":5},
          "findings":[{"fingerprint":"PW-003-a","rule":"PW-003","severity":"high","title":"x",
          "domain":"A.LOCAL","suppressed":"accepted","exposure":{"scope":"A.LOCAL","principals":1,"population":2,"percent":50.0},
          "affected":[{"id":"S-1","name":"N","kind":"User"}],"change":"new"}]}"#;
        assert!(looks_like_event(text));
        let ev = parse_event(text).unwrap();
        assert_eq!(ev.domains, ["A.LOCAL"]);
        let f = &ev.findings[0];
        assert!(f.suppressed);
        assert_eq!(f.exposure.unwrap().principals, 1);
        assert_eq!(f.affected.as_ref().unwrap()[0].id, "S-1");
        assert!(parse_event(r#"{"findings":[]}"#).is_err());
    }
}
