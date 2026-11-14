//! Posture: the numbers BloodHound Enterprise puts on its Posture page, for one
//! run. Exposure and the protected share per protected zone (Tier Zero plus any
//! Privilege Zones), findings by category and severity, and how complete the
//! collection was, since missing session or local group data hides paths.

use std::collections::{BTreeMap, HashMap, HashSet};

use petgraph::graph::NodeIndex;
use serde::Serialize;

use crate::analysis;
use crate::findings::{Category, Finding, Severity};
use crate::graph::AdGraph;
use crate::model::NodeKind;
use crate::report::num as thousands;
use crate::zones::Zone;

/// Computers that logged on within this many days count as active (the same
/// window BloodHound Enterprise uses for completeness).
pub const ACTIVE_DAYS: i64 = 14;

/// A domain whose sessions or local groups were collected for fewer than this
/// share of computers is flagged as incomplete.
pub const LOW_PERCENT: f64 = 80.0;

/// How bad a zone's exposure is, at a glance (the status colour of the hero,
/// the Home cards and the trend). Higher is worse:
///
/// - `Critical`: a group that holds (nearly) every account (Domain Users,
///   Authenticated Users, Everyone...) can reach the zone, or a critical
///   finding is open;
/// - `High`: at least one account outside the zone can reach it;
/// - `Moderate`: no account can, but findings at medium or above are open;
/// - `Low`: no account can, and nothing at medium or above is open.
///
/// Any path into Tier Zero is a way to take over the domain, so a run is
/// never green while one is open, whatever share of the domain it is: 509
/// accounts are 0.1% of a 400,000-account domain and still 509 ways in.
/// [`assess`](ExposureGrade::assess) decides; [`GradeInputs`] says from what.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize,
)]
pub enum ExposureGrade {
    Low,
    Moderate,
    High,
    Critical,
}

/// What [`ExposureGrade::assess`] looks at. For Tier Zero every open finding
/// counts; for a Privilege Zone, those that lead into it.
#[derive(Debug, Clone, Default)]
pub struct GradeInputs {
    /// Accounts outside the zone with a path into it.
    pub exposed: usize,
    /// Groups that hold (nearly) every account and reach the zone, by name.
    pub broad_groups: Vec<String>,
    /// Open (not accepted) critical findings.
    pub critical: usize,
    /// Open findings rated high or medium.
    pub high_or_medium: usize,
    /// Open Kerberoastable accounts (PW-006) on a path into the zone: any
    /// account can ask for a ticket to crack.
    pub kerberoastable: usize,
    /// Open accounts without Kerberos pre-authentication (PW-007) on a path
    /// into the zone: anyone on the network can ask for data to crack.
    pub asrep: usize,
    /// Of `critical`, those about such accounts.
    pub critical_roastable: usize,
    /// Of `kerberoastable` and `asrep`, the accounts that are in the zone
    /// themselves rather than on a path to it.
    pub roastable_in_zone: usize,
}

/// The one line under the status saying why it is what it is, as counts
/// ("10 Kerberoastable service accounts are in or on a path to Tier
/// Zero."). The report's hero, `pathwarden
/// posture` and `pathwarden run` print the same line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReason {
    pub text: String,
    /// The words of `text` that name findings, and their rule: the report
    /// links them to that rule's findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<ReasonLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonLink {
    /// Found in [`StatusReason::text`] as written ("10 service accounts").
    pub words: String,
    pub rule: String,
}

impl ExposureGrade {
    /// The grade of a zone from what the run found (see [`ExposureGrade`]).
    pub fn assess(i: &GradeInputs) -> Self {
        if !i.broad_groups.is_empty() || i.critical > 0 {
            ExposureGrade::Critical
        } else if i.exposed > 0 {
            ExposureGrade::High
        } else if i.high_or_medium > 0 {
            ExposureGrade::Moderate
        } else {
            ExposureGrade::Low
        }
    }

    /// Why the zone has its grade, in one sentence ("2 critical findings
    /// are open"), for the line under the hero.
    pub fn reason(i: &GradeInputs, zone: &str) -> String {
        let s = |n: usize| if n == 1 { "" } else { "s" };
        let are = |n: usize| if n == 1 { "is" } else { "are" };
        let mut why = Vec::new();
        match i.broad_groups.as_slice() {
            [] => {}
            [one] => why.push(format!(
                "{one}, which holds nearly every account, can reach {zone}"
            )),
            [one, rest @ ..] => why.push(format!(
                "{one} and {} other group{} that hold nearly every account can reach {zone}",
                rest.len(),
                s(rest.len())
            )),
        }
        if i.critical > 0 {
            why.push(format!(
                "{} critical finding{} {} open",
                thousands(i.critical),
                s(i.critical),
                are(i.critical)
            ));
        }
        if !why.is_empty() {
            return capitalize(&why.join("; "));
        }
        if i.exposed > 0 {
            format!(
                "{} account{} outside {zone} can reach it",
                thousands(i.exposed),
                s(i.exposed)
            )
        } else if i.high_or_medium > 0 {
            format!(
                "No account outside {zone} can reach it; {} finding{} at medium or above {} open",
                thousands(i.high_or_medium),
                s(i.high_or_medium),
                are(i.high_or_medium)
            )
        } else {
            format!(
                "No account outside {zone} can reach it, and nothing at medium or above is open"
            )
        }
    }

    /// Why the zone has its grade, as what an attacker can do (see
    /// [`StatusReason`]). A group that holds nearly every account reaching
    /// the zone comes first: every account is a way in. Then accounts
    /// whose passwords can be cracked offline, when they are what made the
    /// grade (they are the critical findings, or there are none). Otherwise
    /// the plain [`reason`](ExposureGrade::reason).
    pub fn status_reason(i: &GradeInputs, zone: &str) -> StatusReason {
        let s = |n: usize| if n == 1 { "" } else { "s" };
        let count = |n: usize, one: &str, many: &str| {
            format!("{} {}", thousands(n), if n == 1 { one } else { many })
        };
        if let [one, rest @ ..] = i.broad_groups.as_slice() {
            let text = if rest.is_empty() {
                format!("Every account has an attack path to {zone} through {one}, which holds nearly every account.")
            } else {
                format!(
                    "Every account has an attack path to {zone} through {one} and {} other group{} that hold nearly every account.",
                    rest.len(),
                    s(rest.len())
                )
            };
            return StatusReason {
                text,
                link: Some(ReasonLink {
                    words: one.clone(),
                    rule: "PW-001".into(),
                }),
            };
        }
        let roastable = i.kerberoastable + i.asrep;
        if roastable > 0 && i.critical == i.critical_roastable {
            let (words, rule, detail) = match (i.kerberoastable, i.asrep) {
                (k, 0) => (
                    count(
                        k,
                        "Kerberoastable service account",
                        "Kerberoastable service accounts",
                    ),
                    "PW-006",
                    String::new(),
                ),
                (0, a) => (
                    format!(
                        "{} without Kerberos pre-authentication",
                        count(a, "account", "accounts")
                    ),
                    "PW-007",
                    String::new(),
                ),
                (k, a) => (
                    count(k + a, "crackable account", "crackable accounts"),
                    if k >= a { "PW-006" } else { "PW-007" },
                    format!(
                        " ({} Kerberoastable, {} without Kerberos pre-authentication)",
                        thousands(k),
                        thousands(a)
                    ),
                ),
            };
            // Accounts in the zone are worse than "on a path to" it.
            let place = if i.roastable_in_zone == 0 {
                "on a path to"
            } else if i.roastable_in_zone >= roastable {
                "in"
            } else {
                "in or on a path to"
            };
            return StatusReason {
                text: format!(
                    "{words} {} {place} {zone}{detail}.",
                    if roastable == 1 { "is" } else { "are" }
                ),
                link: Some(ReasonLink {
                    words,
                    rule: rule.into(),
                }),
            };
        }
        StatusReason {
            text: format!("{}.", Self::reason(i, zone)),
            link: None,
        }
    }

    /// The colour class the report and the UI give this grade (`low`,
    /// `medium`, `high`, `critical`), so red always means Critical.
    pub fn css_class(self) -> &'static str {
        match self {
            ExposureGrade::Low => "low",
            ExposureGrade::Moderate => "medium",
            ExposureGrade::High => "high",
            ExposureGrade::Critical => "critical",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExposureGrade::Low => "Low",
            ExposureGrade::Moderate => "Moderate",
            ExposureGrade::High => "High",
            ExposureGrade::Critical => "Critical",
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// What the remediation plan does for Tier Zero, for the headline: how many
/// changes it has and how many accounts still reach Tier Zero after all of
/// them (0 when it closes every path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct PlanSummary {
    pub steps: usize,
    pub exposed_after: usize,
}

/// The hero of the report, the run page, Home and `pathwarden posture`: the
/// count first, then the work, then the share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Headline {
    /// "509 accounts have an attack path to Tier Zero".
    pub title: String,
    /// "7 plan steps cut every attack path", when there is a path and a plan.
    pub fixes: Option<String>,
    /// "0.13% of 398,161 active accounts".
    pub share: String,
}

/// The Tier Zero headline from its numbers, shared by every view so they
/// say the same thing.
pub fn headline(
    exposed: usize,
    relevant_population: usize,
    exposure_percent: f64,
    plan: Option<PlanSummary>,
) -> Headline {
    let title = match exposed {
        0 => "No account outside Tier Zero has an attack path to it".to_string(),
        1 => "1 account has an attack path to Tier Zero".to_string(),
        n => format!("{} accounts have an attack path to Tier Zero", thousands(n)),
    };
    let fixes = match plan {
        _ if exposed == 0 => None,
        None => None,
        Some(p) if p.steps == 0 => Some("No plan step cuts these paths".to_string()),
        Some(p) => {
            let changes = if p.steps == 1 {
                "1 plan step".to_string()
            } else {
                format!("{} plan steps", thousands(p.steps))
            };
            Some(if p.exposed_after == 0 {
                format!(
                    "{changes} {} every attack path",
                    if p.steps == 1 { "cuts" } else { "cut" }
                )
            } else {
                format!(
                    "{changes} cut off {} of them",
                    thousands(exposed.saturating_sub(p.exposed_after))
                )
            })
        }
    };
    let share = format!(
        "{} of {} active account{}",
        share_percent(exposure_percent),
        thousands(relevant_population),
        if relevant_population == 1 { "" } else { "s" }
    );
    Headline {
        title,
        fixes,
        share,
    }
}

/// A percentage to two decimals, so a small move reads: "39.91%",
/// "0.13%", "<0.01%". Never rounded to all or none: "100%" and "0%" mean
/// exactly that.
pub fn share_percent(p: f64) -> String {
    format!("{}%", percent_number(p))
}

/// [`share_percent`] without the sign: "39.91", "<0.01", "100".
pub fn percent_number(p: f64) -> String {
    if p <= 0.0 {
        "0".to_string()
    } else if p < 0.01 {
        "<0.01".to_string()
    } else if p >= 100.0 {
        "100".to_string()
    } else if p > 99.99 {
        "99.99".to_string()
    } else {
        format!("{p:.2}")
    }
}

/// A change in percentage points to two decimals: "2.93 pts".
pub fn points(d: f64) -> String {
    format!("{d:.2} pts")
}

/// What "Tier Zero protected" means, for a glossary or an ⓘ. It is a
/// count of objects, never a score.
pub const PROTECTED_DEFINITION: &str =
    "The share of Tier Zero objects that no open attack path finding leads to.";

/// A protected share in words: "58 of 59 objects (98.31%)", or "n/a"
/// with no objects. The same words in the CLI, the report and the app.
pub fn protected_words(objects: usize, with_findings: usize) -> String {
    if objects == 0 {
        return "n/a".to_string();
    }
    let protected = objects.saturating_sub(with_findings);
    format!(
        "{} ({})",
        protected_count(protected, objects),
        share_percent(pct(protected, objects))
    )
}

/// The count part of [`protected_words`]: "58 of 59 objects", "1 of 1
/// object".
pub fn protected_count(protected: usize, objects: usize) -> String {
    format!(
        "{} of {}",
        crate::text::num(protected),
        crate::text::count(objects, "object", "objects")
    )
}

/// Written with each status key under its 1.0 name too
/// ([`crate::status_keys`]): `exposure_status`, `status_reason` and
/// `protected_percent` beside `exposure_grade`, `grade_reason` and
/// `protection_score`, which are written until 2.0.
#[derive(Debug, Clone)]
pub struct ZonePosture {
    pub zone: String,
    pub objects: usize,
    /// Enabled users and computers outside the zone (and outside Tier Zero).
    /// Context for `relevant_population`, not the exposure denominator.
    pub population: usize,
    /// Of `population`, the denominator of `exposure_percent`: the active
    /// users and computers (logged on within the stale window before the
    /// collection time). Accounts nobody uses don't count, exposed or not,
    /// so onboarding many of them does not move the percentage, and edges
    /// never decide who counts. See
    /// [`analysis::Relevance`].
    pub relevant_population: usize,
    /// Of the relevant population, how many have a path into the zone. The
    /// exposed are unioned into `relevant_population`, so this is always a
    /// subset of it (`exposed ≤ relevant_population`) and the same count as
    /// over the whole population.
    pub exposed: usize,
    /// `exposed / relevant_population`, as a percentage. Higher is worse.
    pub exposure_percent: f64,
    /// How bad it is, from the paths and the open findings. See
    /// [`ExposureGrade`].
    pub exposure_grade: ExposureGrade,
    /// Why it has that grade, in one sentence ([`ExposureGrade::reason`]).
    pub grade_reason: String,
    /// The same as what an attacker can do, for the line under the status
    /// ([`ExposureGrade::status_reason`]).
    pub reason: StatusReason,
    /// Groups that hold (nearly) every account and can reach the zone, by
    /// name: one of them makes the grade Critical (not written when there
    /// is none).
    pub broad_groups: Vec<String>,
    /// Zone objects that unsuppressed attack path findings lead to.
    pub objects_with_findings: usize,
    /// Share of zone objects with no attack path findings.
    pub protection_score: Option<f64>,
}

impl Serialize for ZonePosture {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The fields in their order, then the 1.0 names of the status keys
        // (a struct, not a map, so the order holds in every build).
        #[derive(Serialize)]
        struct Out<'a> {
            zone: &'a str,
            objects: usize,
            population: usize,
            relevant_population: usize,
            exposed: usize,
            exposure_percent: f64,
            exposure_grade: ExposureGrade,
            grade_reason: &'a str,
            reason: &'a StatusReason,
            #[serde(skip_serializing_if = "<[String]>::is_empty")]
            broad_groups: &'a [String],
            objects_with_findings: usize,
            protection_score: Option<f64>,
            exposure_status: ExposureGrade,
            status_reason: &'a str,
            protected_percent: Option<f64>,
        }
        Out {
            zone: &self.zone,
            objects: self.objects,
            population: self.population,
            relevant_population: self.relevant_population,
            exposed: self.exposed,
            exposure_percent: self.exposure_percent,
            exposure_grade: self.exposure_grade,
            grade_reason: &self.grade_reason,
            reason: &self.reason,
            broad_groups: &self.broad_groups,
            objects_with_findings: self.objects_with_findings,
            protection_score: self.protection_score,
            exposure_status: self.exposure_grade,
            status_reason: &self.grade_reason,
            protected_percent: self.protection_score,
        }
        .serialize(s)
    }
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct FindingCounts {
    pub attack_path: usize,
    pub hygiene: usize,
    pub suppressed: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Open findings per rule by the severity they would have had with no
    /// severity set ([`crate::findings::Finding::severity_default`]), so a
    /// later run that set other severities can re-rate them and compare
    /// like for like ([`crate::since`]). Absent in older points.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub open_by_rule: BTreeMap<String, BTreeMap<Severity, usize>>,
}

impl FindingCounts {
    /// The open counts by severity re-rated with the severities `set` per
    /// rule (each rule's default otherwise), from [`Self::open_by_rule`];
    /// `None` when it isn't recorded and there are open findings.
    pub fn rerated(&self, set: &BTreeMap<String, Severity>) -> Option<FindingCounts> {
        let open = self.critical + self.high + self.medium + self.low + self.info;
        let recorded: usize = self.open_by_rule.values().flat_map(|m| m.values()).sum();
        if recorded != open {
            return None;
        }
        let mut c = FindingCounts {
            open_by_rule: self.open_by_rule.clone(),
            attack_path: self.attack_path,
            hygiene: self.hygiene,
            suppressed: self.suppressed,
            ..FindingCounts::default()
        };
        for (rule, by) in &self.open_by_rule {
            for (&default, &n) in by {
                *c.slot(set.get(rule).copied().unwrap_or(default)) += n;
            }
        }
        Some(c)
    }

    fn slot(&mut self, s: Severity) -> &mut usize {
        match s {
            Severity::Critical => &mut self.critical,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Low => &mut self.low,
            Severity::Info => &mut self.info,
        }
    }
}

/// A rule whose severity the team set, as the run used it: the report's
/// Environment tab lists them, and its Overview names them.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SeveritySetting {
    pub rule: String,
    #[serde(default)]
    pub title: String,
    pub severity: Severity,
    /// What would rate its findings otherwise
    /// ([`crate::findings::default_label`]): "exposure", "Medium".
    #[serde(default)]
    pub default: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// [`SeveritySetting`] for each rule `settings` sets a severity for.
pub fn severity_settings(settings: &crate::findings::RuleSettings) -> Vec<SeveritySetting> {
    settings
        .severities
        .iter()
        .map(|(rule, s)| SeveritySetting {
            rule: rule.clone(),
            title: crate::findings::rules()
                .iter()
                .find(|r| r.id == rule)
                .map(|r| r.title.to_string())
                .unwrap_or_default(),
            severity: s.severity,
            default: crate::findings::default_label(rule, settings.severity_from_exposure),
            by: s.by.clone(),
            at: s.at.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Completeness {
    pub domain: String,
    /// Computers the sessions percentage is based on, domain controllers
    /// included (sessions are read from them).
    pub computers: usize,
    /// Of those, the member computers (not domain controllers, read-only
    /// ones included): the denominator of `local_groups_collected` and
    /// `local_groups_percent`. Local groups are not read from domain
    /// controllers, whose local groups are the domain's BUILTIN groups,
    /// already in the directory. 0 when there are none, and local groups
    /// don't apply. Defaults (as the next two) to 0 in postures saved
    /// before it was recorded, where local groups then read as not applying.
    #[serde(default)]
    pub member_computers: usize,
    /// Enabled member computers in the domain, active or not. More than
    /// `member_computers` when `active_only` leaves some out.
    #[serde(default)]
    pub enabled_member_computers: usize,
    /// `true` when based on computers active in the last [`ACTIVE_DAYS`] days;
    /// `false` when logon times were unavailable and all enabled computers count.
    #[serde(default)]
    pub active_only: bool,
    pub sessions_collected: usize,
    /// Member computers whose local groups were collected.
    pub local_groups_collected: usize,
    pub sessions_percent: f64,
    /// Share of member computers whose local groups were collected (0 when
    /// there are none; see [`Completeness::local_groups_apply`]).
    pub local_groups_percent: f64,
    /// Local groups set by GPOs were read (`None`: the collection doesn't
    /// say, as with RustHound-CE run on its own). Without them, admin rights
    /// granted by Group Policy are missing.
    #[serde(default)]
    pub gpo_local_groups: Option<bool>,
    /// The collection asked for the domain's sessions: it did for at least
    /// one of its computers. A Quick (DC only) collection reads the
    /// directory only and asks for none; its 0% is "not targeted", not a
    /// shortfall. `true` in postures saved before it was recorded.
    #[serde(default = "yes")]
    pub sessions_targeted: bool,
    /// The collection asked for the local groups of at least one member
    /// computer, as [`Completeness::sessions_targeted`]. `true` when the
    /// domain has no member computers.
    #[serde(default = "yes")]
    pub local_groups_targeted: bool,
    /// Enabled computers, active or not, the built-in collector skipped
    /// because the domain has no Kerberos name for them (Kerberos only),
    /// as many as the collection's warning says. Those among
    /// `computers` count as not collected.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_no_kerberos: usize,
    /// Enabled computers skipped because their SMB replies weren't signed,
    /// as [`Completeness::skipped_no_kerberos`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_unsigned: usize,
    /// Enabled computers skipped because a reply answered another request
    /// (a replayed or misdirected signed reply).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_bad_reply: usize,
    /// Enabled computers in another domain skipped because the trust on
    /// the way allows only RC4 (Pathwarden uses AES).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_rc4_trust: usize,
    /// Of the skipped ones, those not among `computers` (not active in the
    /// 14 days before collection): they aren't in the percentages.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_not_counted: usize,
    /// Of `computers`, those whose services the built-in collector read in
    /// full, for credentials they store. `None` when the collection
    /// has no such data for the domain (not a Full collection by the
    /// built-in collector, SharpHound, older Pathwarden).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_credentials_collected: Option<usize>,
    /// The service reads were turned off for this collection
    /// (`--no-service-reads`, `[collect] service_reads = false`):
    /// `stored_credentials_collected` is then `None`, and the report says
    /// "off" rather than 0%.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stored_credentials_off: bool,
    /// Of `computers`, those whose scheduled tasks the built-in collector
    /// read in full, for credentials they store. `None` when
    /// the collection has no such data for the domain, as
    /// [`Completeness::stored_credentials_collected`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_credentials_collected: Option<usize>,
    /// The task reads were turned off for this collection
    /// (`--no-task-reads`, `[collect] task_reads = false`), as
    /// [`Completeness::stored_credentials_off`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub task_credentials_off: bool,
}

/// What the services count of [`Completeness::stored_credentials_collected`]
/// means, for the CLI and the report.
pub const STORED_CREDENTIALS_DEF: &str = "Services read: computers whose services were read in \
     full for the accounts they run as; one not read holds the findings that rest on it.";

/// What the report's services cell says when the reads were turned off.
pub const STORED_CREDENTIALS_OFF: &str = "Off for this collection";

/// The sentence the CLI and the report add when they were.
pub const STORED_CREDENTIALS_OFF_DEF: &str = "Service reads were turned off for this collection, \
     so stored credentials in services were not checked.";

/// What the tasks count of [`Completeness::task_credentials_collected`]
/// means, for the CLI and the report.
pub const TASK_CREDENTIALS_DEF: &str = "Tasks read: computers whose scheduled tasks were read in \
     full for the accounts whose passwords they store; one not read holds the findings that rest \
     on it.";

/// The sentence the CLI and the report add when the task reads were
/// turned off. The cell says [`STORED_CREDENTIALS_OFF`].
pub const TASK_CREDENTIALS_OFF_DEF: &str = "Task reads were turned off for this collection, so \
     stored credentials in scheduled tasks were not checked.";

impl Completeness {
    /// The services cell in words, for the CLI: "2/3", "off", or `None`
    /// when the collection has no such data.
    pub fn services_words(&self) -> Option<String> {
        if self.stored_credentials_off {
            return Some("off".into());
        }
        self.stored_credentials_collected
            .map(|n| format!("{n}/{}", self.computers))
    }

    /// The tasks cell in words, as [`Completeness::services_words`].
    pub fn tasks_words(&self) -> Option<String> {
        if self.task_credentials_off {
            return Some("off".into());
        }
        self.task_credentials_collected
            .map(|n| format!("{n}/{}", self.computers))
    }
}

fn yes() -> bool {
    true
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Completeness {
    /// The line under the completeness table for the computers the
    /// collector skipped, if it skipped any: "16 computers were
    /// skipped and count as not collected: 14 have no Kerberos name, 2
    /// didn't sign their replies."
    pub fn skipped_words(&self) -> Option<String> {
        let total = self.skipped_no_kerberos
            + self.skipped_unsigned
            + self.skipped_bad_reply
            + self.skipped_rc4_trust;
        if total == 0 {
            return None;
        }
        let one = total == 1;
        /// How many, the words for one alone, the words for n of several.
        type Reason = (usize, &'static str, fn(usize) -> String);
        let reasons: [Reason; 4] = [
            (self.skipped_no_kerberos, "it has no Kerberos name", |n| {
                format!(
                    "{n} {} no Kerberos name",
                    if n == 1 { "has" } else { "have" }
                )
            }),
            (self.skipped_unsigned, "it didn't sign its replies", |n| {
                format!(
                    "{n} didn't sign {} replies",
                    if n == 1 { "its" } else { "their" }
                )
            }),
            (
                self.skipped_bad_reply,
                "its replies didn't answer Pathwarden's requests",
                |n| format!("{n} answered with replies to other requests"),
            ),
            (
                self.skipped_rc4_trust,
                "the trust to its domain allows only RC4",
                |n| {
                    format!(
                        "{n} {} behind a trust that allows only RC4",
                        if n == 1 { "is" } else { "are" }
                    )
                },
            ),
        ];
        let why: Vec<String> = reasons
            .iter()
            .filter(|(n, _, _)| *n > 0)
            .map(
                |(n, alone, many)| {
                    if one {
                        alone.to_string()
                    } else {
                        many(*n)
                    }
                },
            )
            .collect();
        let n = crate::text::count(total, "computer", "computers");
        let was = if one { "was" } else { "were" };
        let why = why.join(", ");
        let outside = self.skipped_not_counted.min(total);
        Some(if outside == 0 {
            format!(
                "{n} {was} skipped and {} as not collected: {why}.",
                if one { "counts" } else { "count" }
            )
        } else if outside == total {
            format!(
                "{n} {was} skipped: {why}. {} active, so {} in the numbers above.",
                if one { "It isn't" } else { "They aren't" },
                if one { "it isn't" } else { "they aren't" }
            )
        } else if outside == 1 {
            format!(
                "{n} {was} skipped: {why}. {} as not collected; the other one isn't active, so \
                 it isn't in the numbers above.",
                count_word(total - outside),
            )
        } else {
            format!(
                "{n} {was} skipped: {why}. {} as not collected; the other {outside} aren't \
                 active, so they aren't in the numbers above.",
                count_word(total - outside),
            )
        })
    }
}

/// "1 counts" / "3 count".
fn count_word(n: usize) -> String {
    if n == 1 {
        "1 counts".into()
    } else {
        format!("{n} count")
    }
}

impl Completeness {
    /// The domain has member computers, so local groups apply. A domain with
    /// only domain controllers has none to read.
    pub fn local_groups_apply(&self) -> bool {
        self.member_computers > 0
    }

    /// Why local groups don't apply, when they don't: the domain has only
    /// domain controllers, or none of its member computers is active.
    pub fn local_groups_na(&self) -> Option<&'static str> {
        if self.local_groups_apply() {
            None
        } else if self.enabled_member_computers > 0 {
            Some("no active member computers")
        } else {
            Some("domain controllers only")
        }
    }

    /// Sessions or local groups were collected for fewer than
    /// [`LOW_PERCENT`] of the computers they apply to.
    /// A part the collection did not ask for is not short, and doesn't
    /// count.
    pub fn is_low(&self) -> bool {
        self.computers > 0
            && (self.sessions_targeted && self.sessions_percent < LOW_PERCENT
                || self.local_groups_apply()
                    && self.local_groups_targeted
                    && self.local_groups_percent < LOW_PERCENT)
    }

    /// Local groups apply and were not asked for.
    pub fn local_groups_untargeted(&self) -> bool {
        self.local_groups_apply() && !self.local_groups_targeted
    }
}

/// What a collection did not target: sessions, local groups, or both. The
/// words every surface uses for it come from here, so the report, the app
/// and the command line say the same.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct Untargeted {
    pub sessions: bool,
    pub local_groups: bool,
}

/// The names of the parts in [`Untargeted::parts`]: what a tracked finding
/// records ([`crate::state::TrackedFinding::not_targeted`]).
pub const SESSIONS: &str = "sessions";
pub const LOCAL_GROUPS: &str = "local_groups";

/// Rules that read sessions or local groups straight from the data,
/// whatever their category: Tier Zero sessions (PW-004) and the logon
/// rights local groups grant on domain controllers (PW-023).
pub const HOST_DATA_RULES: &[(&str, &str)] = &[("PW-004", SESSIONS), ("PW-023", LOCAL_GROUPS)];

/// Rules whose findings exist because their entry reaches Tier Zero (or
/// the object a rule guards) by any path, which may run through any
/// session or admin right: a Kerberoastable account with a path to Tier
/// Zero (PW-006), a broad group with one (PW-001), an Entra ID role that
/// reaches on-premises Tier Zero (PW-032). They rest on both, whatever
/// their sample path shows. Every other rule rests on the edges of its
/// sample path and evidence ([`Untargeted::of_edge`]).
pub const REACH_RULES: &[&str] = &["PW-001", "PW-006", "PW-032"];

/// Whether `rule` is one of [`REACH_RULES`].
pub fn is_reach_rule(rule: &str) -> bool {
    REACH_RULES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(rule.trim()))
}

/// The definition the completeness views add.
pub const NOT_TARGETED_DEF: &str = "Not targeted means the collector was not asked to read them.";

impl Untargeted {
    /// Of one domain.
    pub fn of(c: &Completeness) -> Self {
        Untargeted {
            sessions: c.computers > 0 && !c.sessions_targeted,
            local_groups: c.local_groups_untargeted(),
        }
    }

    pub fn any(self) -> bool {
        self.sessions || self.local_groups
    }

    /// Both were targeted.
    pub fn none(&self) -> bool {
        !self.any()
    }

    /// Both together, or either.
    pub fn or(self, other: Untargeted) -> Untargeted {
        Untargeted {
            sessions: self.sessions || other.sessions,
            local_groups: self.local_groups || other.local_groups,
        }
    }

    /// "sessions and local groups", "sessions" or "local groups"; `None`
    /// when both were targeted.
    pub fn words(self) -> Option<&'static str> {
        match (self.sessions, self.local_groups) {
            (true, true) => Some("sessions and local groups"),
            (true, false) => Some("sessions"),
            (false, true) => Some("local groups"),
            (false, false) => None,
        }
    }

    /// The paths a run without them lacks.
    pub fn paths(self) -> Option<&'static str> {
        match (self.sessions, self.local_groups) {
            (true, true) => Some("logged-on sessions and local administrator rights"),
            (true, false) => Some("logged-on sessions"),
            (false, true) => Some("local administrator rights"),
            (false, false) => None,
        }
    }

    /// [`SESSIONS`] and [`LOCAL_GROUPS`], those not targeted.
    pub fn parts(self) -> Vec<String> {
        let mut v = Vec::new();
        if self.sessions {
            v.push(SESSIONS.to_string());
        }
        if self.local_groups {
            v.push(LOCAL_GROUPS.to_string());
        }
        v
    }

    /// From [`Untargeted::parts`].
    pub fn from_parts(parts: &[String]) -> Self {
        Untargeted {
            sessions: parts.iter().any(|p| p == SESSIONS),
            local_groups: parts.iter().any(|p| p == LOCAL_GROUPS),
        }
    }

    /// What both lack.
    pub fn and(self, other: Untargeted) -> Untargeted {
        Untargeted {
            sessions: self.sessions && other.sessions,
            local_groups: self.local_groups && other.local_groups,
        }
    }

    /// Both.
    pub const BOTH: Untargeted = Untargeted {
        sessions: true,
        local_groups: true,
    };

    /// What a finding of `rule` rests on when it doesn't say (state and
    /// event documents written before findings recorded it): both for an
    /// attack path, the part a rule reads for [`HOST_DATA_RULES`],
    /// nothing for the rest.
    pub fn rested_on(rule: &str, attack_path: bool) -> Untargeted {
        if attack_path {
            return Untargeted::BOTH;
        }
        Untargeted::of_rule(rule)
    }

    /// The part [`HOST_DATA_RULES`] (and both for [`REACH_RULES`]) say
    /// `rule` reads, whatever its edges.
    pub fn of_rule(rule: &str) -> Untargeted {
        let rule = rule.trim();
        if is_reach_rule(rule) {
            return Untargeted::BOTH;
        }
        HOST_DATA_RULES
            .iter()
            .filter(|(r, _)| r.eq_ignore_ascii_case(rule))
            .fold(Untargeted::default(), |a, (_, part)| {
                a.or(Untargeted::from_parts(&[part.to_string()]))
            })
    }

    /// What an edge of `kind` rests on: a session (HasSession) or a local
    /// group membership (AdminTo, CanRDP, CanPSRemote, ExecuteDCOM).
    pub fn of_edge(kind: crate::model::EdgeKind) -> Untargeted {
        use crate::model::EdgeKind::*;
        match kind {
            HasSession => Untargeted {
                sessions: true,
                local_groups: false,
            },
            AdminTo | CanRdp | CanPsRemote | ExecuteDcom => Untargeted {
                sessions: false,
                local_groups: true,
            },
            _ => Untargeted::default(),
        }
    }

    /// Not targeted here and targeted in `before`: what a comparison with
    /// `before` can't check.
    pub fn lost_since(self, before: Untargeted) -> Untargeted {
        Untargeted {
            sessions: self.sessions && !before.sessions,
            local_groups: self.local_groups && !before.local_groups,
        }
    }

    /// The line under the command line's completeness table.
    pub fn posture_line(self) -> Option<String> {
        let what = match (self.sessions, self.local_groups) {
            (true, true) => "this collection read the directory only",
            (true, false) => "this collection did not read sessions",
            (false, true) => "this collection did not read local groups",
            (false, false) => return None,
        };
        Some(format!(
            "Not targeted: {what}, so paths through {} are not in this run.",
            self.paths()?
        ))
    }

    /// "Paths through logged-on sessions are not in this run."
    pub fn paths_sentence(self) -> Option<String> {
        Some(format!(
            "Paths through {} are not in this run.",
            self.paths()?
        ))
    }

    /// The run summary's note, once for the run.
    pub fn summary_note(self) -> Option<String> {
        let words = self.words()?;
        let mut chars = words.chars();
        let first = chars.next()?.to_uppercase().collect::<String>();
        Some(format!(
            "Note: {first}{} were not targeted in this collection. {}",
            chars.as_str(),
            self.paths_sentence()?
        ))
    }

    /// "Sessions and local groups not targeted": a chip or an aside.
    pub fn chip(self) -> Option<String> {
        Some(format!("{} not targeted", self.words()?))
    }
}

/// What a run did not target in any of its domains.
pub fn untargeted(completeness: &[Completeness]) -> Untargeted {
    completeness
        .iter()
        .map(Untargeted::of)
        .fold(Untargeted::default(), Untargeted::or)
}

/// What each domain of a run did not target, by name: the domains that
/// targeted everything are left out.
pub fn untargeted_domains(completeness: &[Completeness]) -> Vec<(String, Untargeted)> {
    completeness
        .iter()
        .map(|c| (c.domain.clone(), Untargeted::of(c)))
        .filter(|(_, u)| u.any())
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Posture {
    pub tier_zero: ZonePosture,
    pub zones: Vec<ZonePosture>,
    pub findings: FindingCounts,
    pub completeness: Vec<Completeness>,
    /// What the built-in collector read from SYSVOL, per domain. Empty for
    /// collections without SYSVOL data (SharpHound, older Pathwarden).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sysvol: Vec<crate::sysvol::Completeness>,
    /// What the collection says about each Enterprise CA, for the AD CS
    /// checks that need more than LDAP. Empty without Enterprise CAs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adcs: Vec<AdcsCompleteness>,
    /// Per domain, how many domain controllers' ESC9/ESC10 registry settings
    /// the data holds (from the collector or Tier Zero settings files).
    /// Empty without Enterprise CAs or settings files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dc_settings: Vec<crate::dcsettings::Completeness>,
    /// Per Enterprise CA, its Tier Zero settings file. Empty without
    /// Enterprise CAs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_settings: Vec<crate::dcsettings::CaCompleteness>,
    /// Per Tier Zero host, whether its management agents were read:
    /// "Management agents read on Tier Zero hosts: n of m". Empty when the
    /// run read no Tier Zero settings file.
    #[serde(skip_serializing_if = "crate::hostprobe::Completeness::is_empty")]
    pub host_agents: crate::hostprobe::Completeness,
    /// What the exposure denominators mean ([`analysis::EXPOSURE_BASIS`]):
    /// 3, active users and computers only (2 also counted the inactive
    /// ones with a path). Consumers of
    /// the event JSON compare exposure only between equal bases.
    pub exposure_basis: u8,
    /// The activity window of the denominator: accounts that logged on
    /// within this many days before the collection time count.
    pub activity_days: i64,
    /// Domains whose data has no logon times: every enabled user and
    /// computer there counts as active.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activity_unknown_domains: Vec<String>,
    /// What the Tier Zero remediation plan does, once it was computed
    /// ([`crate::analyze::Evaluated::finish`]); `None` from the rules alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanSummary>,
    /// The rules whose severity the team set ([`severity_settings`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severities_set: Vec<SeveritySetting>,
    /// How the findings were rated
    /// ([`crate::findings::RuleSettings::severity_key`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub severity_settings: String,
}

impl Posture {
    /// The Tier Zero headline ([`headline`]).
    pub fn headline(&self) -> Headline {
        let t0 = &self.tier_zero;
        headline(
            t0.exposed,
            t0.relevant_population,
            t0.exposure_percent,
            self.plan,
        )
    }
}

/// Which AD CS checks the collection let Pathwarden make for one Enterprise
/// CA. A check that could not be made is "not checked", not "not vulnerable".
#[derive(Debug, Clone, Serialize)]
pub struct AdcsCompleteness {
    pub ca: String,
    /// The CA's own name ("CONTOSO-CA", its `caname`), as the report and
    /// the command line show it; `ca` stays the object's name in the JSON.
    #[serde(skip)]
    pub ca_name: String,
    /// Which templates the CA publishes was collected. When not (RustHound-CE
    /// up to 2.5.23), every template of the forest counts as published.
    pub published_templates: bool,
    /// ESC6: the CA's EDITF_ATTRIBUTESUBJECTALTNAME2 flag was read from its
    /// registry (SharpHound, or Pathwarden's built-in Full collection; never
    /// RustHound-CE on its own).
    pub esc6: bool,
    /// ESC11: the CA's InterfaceFlags were read from its registry
    /// (Pathwarden's built-in Full collection only).
    #[serde(default)]
    pub esc11: bool,
    /// Where ESC6's and ESC11's values came from when a Tier Zero settings
    /// file is involved: a current file, or one over 90 days old.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esc6_file: Option<crate::dcsettings::FileAge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esc11_file: Option<crate::dcsettings::FileAge>,
    /// ESC13: the certificate policies of the templates it publishes were
    /// collected (RustHound-CE does not read them).
    pub esc13: bool,
}

/// [`AdcsCompleteness`] for every collected Enterprise CA, by name.
pub fn adcs_completeness(g: &AdGraph) -> Vec<AdcsCompleteness> {
    let ages = crate::dcsettings::ca_file_ages(g);
    let mut out: Vec<AdcsCompleteness> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::EnterpriseCa && !n.placeholder)
        .map(|(ix, n)| {
            let adcs = n.adcs.as_deref();
            let templates: Vec<NodeIndex> = g
                .inner()
                .edges_directed(ix, petgraph::Direction::Incoming)
                .filter(|e| *e.weight() == crate::model::EdgeKind::PublishedTo)
                .map(|e| petgraph::visit::EdgeRef::source(&e))
                .collect();
            AdcsCompleteness {
                ca: n.name.clone(),
                ca_name: adcs
                    .and_then(|a| a.caname.clone())
                    .unwrap_or_else(|| n.name.clone()),
                published_templates: !adcs.is_some_and(|a| a.publishedtemplatesunresolved),
                esc6: adcs.is_some_and(|a| a.isuserspecifiessanenabled.is_some()),
                esc11: adcs.is_some_and(|a| a.enforceencryptionforrequests.is_some()),
                esc6_file: ages.get(&ix).and_then(|a| a.0),
                esc11_file: ages.get(&ix).and_then(|a| a.1),
                esc13: !templates.is_empty()
                    && templates.iter().all(|&t| {
                        g.node(t)
                            .adcs
                            .as_deref()
                            .is_some_and(|a| a.certificatepolicycollected)
                    }),
            }
        })
        .collect();
    out.sort_by(|a, b| a.ca.cmp(&b.ca));
    out
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

/// Posture of one protected set of objects. `reach` is what counts as reaching
/// the zone: the zone itself plus Tier Zero, which controls every zone.
/// Principals inside the zone, or in Tier Zero, are not counted as exposed.
/// `rel` says which principals are active: the denominator has the same
/// meaning for every zone. The grade counts every open finding when
/// `every_finding` (Tier Zero, which every finding is about), else only
/// those that lead into the zone.
pub fn zone_posture(
    g: &AdGraph,
    zone: &str,
    members: &[NodeIndex],
    reach: &[NodeIndex],
    findings: &[Finding],
    rel: &analysis::Relevance,
    every_finding: bool,
) -> ZonePosture {
    let member_set: HashSet<NodeIndex> = members.iter().copied().collect();
    let population: Vec<NodeIndex> = analysis::population(g)
        .into_iter()
        .filter(|ix| !member_set.contains(ix))
        .collect();
    let tree = analysis::reach_targets(g, reach.iter().copied(), None);
    // Only active accounts count, as exposed and in the denominator.
    let relevant = rel.relevant(&population);
    let exposed = rel.exposed(&population, |ix| tree.reaches(ix));
    let exposure_percent = pct(exposed, relevant);
    let hit: HashSet<NodeIndex> = findings
        .iter()
        .filter(|f| f.category == Category::AttackPath && f.suppressed.is_none())
        .flat_map(|f| f.hit_objects().iter().copied())
        .filter(|ix| member_set.contains(ix))
        .collect();
    let objects = member_set.len();
    let mut broad_groups: Vec<String> = g
        .nodes()
        .filter(|(ix, n)| {
            crate::sid::is_broad_group(&n.id) && !member_set.contains(ix) && tree.reaches(*ix)
        })
        .map(|(_, n)| n.name.clone())
        .collect();
    broad_groups.sort();
    broad_groups.dedup();
    let mut inputs = GradeInputs {
        exposed,
        broad_groups,
        ..GradeInputs::default()
    };
    for f in findings.iter().filter(|f| f.suppressed.is_none()) {
        if !every_finding && !f.hit_objects().iter().any(|ix| member_set.contains(ix)) {
            continue;
        }
        use crate::findings::Severity::*;
        match f.severity {
            Critical => inputs.critical += 1,
            High | Medium => inputs.high_or_medium += 1,
            Low | Info => {}
        }
        // Weak accounts count when they lead into the zone (Tier Zero
        // included), not when they are merely in the data.
        let roastable = matches!(f.rule, "PW-006" | "PW-007")
            && f.hit_objects().iter().any(|ix| member_set.contains(ix));
        if roastable {
            if f.rule == "PW-006" {
                inputs.kerberoastable += 1;
            } else {
                inputs.asrep += 1;
            }
            if f.severity == Critical {
                inputs.critical_roastable += 1;
            }
            let account = f.affected.first().and_then(|a| g.lookup(&a.id));
            if account.is_some_and(|ix| member_set.contains(&ix)) {
                inputs.roastable_in_zone += 1;
            }
        }
    }
    let exposure_grade = ExposureGrade::assess(&inputs);
    let grade_reason = ExposureGrade::reason(&inputs, zone);
    let reason = ExposureGrade::status_reason(&inputs, zone);
    ZonePosture {
        zone: zone.to_string(),
        objects,
        population: population.len(),
        relevant_population: relevant,
        exposed,
        exposure_percent,
        exposure_grade,
        grade_reason,
        reason,
        broad_groups: inputs.broad_groups,
        objects_with_findings: hit.len(),
        protection_score: (objects > 0).then(|| pct(objects - hit.len(), objects)),
    }
}

pub fn finding_counts(findings: &[Finding]) -> FindingCounts {
    let mut c = FindingCounts::default();
    for f in findings {
        if f.suppressed.is_some() {
            c.suppressed += 1;
            continue;
        }
        match f.category {
            Category::AttackPath => c.attack_path += 1,
            Category::Hygiene => c.hygiene += 1,
        }
        *c.slot(f.severity) += 1;
        *c.open_by_rule
            .entry(f.rule.to_string())
            .or_default()
            .entry(f.severity_default.unwrap_or(f.severity))
            .or_default() += 1;
    }
    c
}

/// Share of computers per domain whose sessions and local groups were
/// collected. Paths through sessions and local admin rights are only as
/// complete as these numbers. Sessions count every computer; local groups
/// count member computers only, since they are not read from domain
/// controllers.
pub fn completeness(g: &AdGraph, now: i64) -> Vec<Completeness> {
    // GPO local groups, per domain: the built-in collector's SYSVOL sidecar,
    // else what SharpHound's methods say on the domain object.
    let mut gpo_local: BTreeMap<String, bool> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain && !n.placeholder)
        .filter_map(|(_, n)| Some((n.name.clone(), n.props.gpo_local_groups_collected?)))
        .collect();
    for d in g.sysvol_domains() {
        if let Some(c) = &d.checks.gpo_local_groups {
            gpo_local.insert(
                d.domain.clone(),
                c.status != crate::sysvol::CheckStatus::NotCollected,
            );
        }
    }
    let computers: Vec<_> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Computer && !n.placeholder && n.is_enabled())
        .collect();
    let mut by_domain: BTreeMap<String, Vec<&crate::model::Node>> = BTreeMap::new();
    let mut dcs: HashSet<&str> = HashSet::new();
    for (ix, n) in computers {
        if n.is_dc || is_rodc(g, ix) {
            dcs.insert(n.id.as_str());
        }
        let domain = n.domain.clone().unwrap_or_else(|| "UNKNOWN".into());
        by_domain.entry(domain).or_default().push(n);
    }
    let is_member = |n: &crate::model::Node| !dcs.contains(n.id.as_str());
    by_domain
        .into_iter()
        .map(|(domain, all)| {
            let enabled_members = all.iter().filter(|n| is_member(n)).count();
            // Targeted when the collection asked any of the domain's
            // computers, active or not.
            let sessions_targeted = all.iter().any(|n| n.props.sessions_targeted != Some(false));
            let mut all_members = all.iter().filter(|n| is_member(n)).peekable();
            let local_groups_targeted = all_members.peek().is_none()
                || all_members.any(|n| n.props.local_groups_targeted != Some(false));
            let cutoff = now - ACTIVE_DAYS * 86_400;
            let active: Vec<_> = all
                .iter()
                .copied()
                .filter(|n| n.props.lastlogontimestamp.is_some_and(|t| t >= cutoff))
                .collect();
            let have_logons = all
                .iter()
                .any(|n| n.props.lastlogontimestamp.is_some_and(|t| t > 0));
            // No recent logons at all usually means the data is older than the
            // analysis time; count every enabled computer rather than none.
            // Skipped computers, every enabled one, active or not, so
            // the line agrees with the collection's warning; those outside
            // the basis are counted apart, as they aren't in the numbers.
            let skipped_in = |set: &[&crate::model::Node], why| {
                set.iter()
                    .filter(|n| n.props.host_skipped == Some(why))
                    .count()
            };
            let skipped_all = [
                skipped_in(&all, crate::model::HostSkip::NoKerberosName),
                skipped_in(&all, crate::model::HostSkip::Unsigned),
                skipped_in(&all, crate::model::HostSkip::BadReply),
                skipped_in(&all, crate::model::HostSkip::Rc4Trust),
            ];
            let (basis, active_only) = if have_logons && !active.is_empty() {
                (active, true)
            } else {
                (all, false)
            };
            let sessions = basis
                .iter()
                .filter(|n| n.props.sessions_collected == Some(true))
                .count();
            let members: Vec<_> = basis.iter().filter(|n| is_member(n)).collect();
            let groups = members
                .iter()
                .filter(|n| n.props.local_groups_collected == Some(true))
                .count();
            // The computers read in full, of the basis.
            let read_of = |m: HashMap<NodeIndex, crate::sysvol::CheckStatus>| {
                let read: HashSet<&str> = m
                    .iter()
                    .filter(|(_, s)| **s == crate::sysvol::CheckStatus::Complete)
                    .map(|(&ix, _)| g.node(ix).id.as_str())
                    .collect();
                basis
                    .iter()
                    .filter(|n| read.contains(n.id.as_str()))
                    .count()
            };
            let stored_off = crate::storedcreds::turned_off(g, &domain);
            let stored = crate::storedcreds::complete_hosts(g, &domain)
                .filter(|_| !stored_off)
                .map(read_of);
            let tasks_off = crate::storedcreds::tasks_turned_off(g, &domain);
            let tasks = crate::storedcreds::complete_task_hosts(g, &domain)
                .filter(|_| !tasks_off)
                .map(read_of);
            let in_basis = skipped_in(&basis, crate::model::HostSkip::NoKerberosName)
                + skipped_in(&basis, crate::model::HostSkip::Unsigned)
                + skipped_in(&basis, crate::model::HostSkip::BadReply)
                + skipped_in(&basis, crate::model::HostSkip::Rc4Trust);
            Completeness {
                skipped_no_kerberos: skipped_all[0],
                skipped_unsigned: skipped_all[1],
                skipped_bad_reply: skipped_all[2],
                skipped_rc4_trust: skipped_all[3],
                skipped_not_counted: skipped_all.iter().sum::<usize>() - in_basis,
                computers: basis.len(),
                member_computers: members.len(),
                enabled_member_computers: enabled_members,
                active_only,
                sessions_collected: sessions,
                local_groups_collected: groups,
                sessions_percent: pct(sessions, basis.len()),
                local_groups_percent: pct(groups, members.len()),
                gpo_local_groups: gpo_local.get(&domain).copied(),
                sessions_targeted,
                local_groups_targeted,
                stored_credentials_collected: stored,
                stored_credentials_off: stored_off,
                task_credentials_collected: tasks,
                task_credentials_off: tasks_off,
                domain,
            }
        })
        .collect()
}

/// A read-only domain controller: a direct member of Read-only Domain
/// Controllers (RID 521, its primary group). Collectors mark only writable
/// DCs as `IsDC` (SERVER_TRUST_ACCOUNT), but a RODC's local groups are not
/// read either.
pub(crate) fn is_rodc(g: &AdGraph, ix: NodeIndex) -> bool {
    use petgraph::visit::EdgeRef;
    g.inner().edges(ix).any(|e| {
        *e.weight() == crate::model::EdgeKind::MemberOf
            && crate::sid::domain_rid(&g.node(e.target()).id) == Some(521)
    })
}

/// Whether a computer's local groups are read from the computer itself: a
/// member, not a domain controller (whose built-in groups are the
/// domain's, read from the directory).
pub(crate) fn local_groups_on_host(g: &AdGraph, ix: NodeIndex) -> bool {
    let n = g.node(ix);
    n.kind == NodeKind::Computer && !n.placeholder && !n.is_dc && !is_rodc(g, ix)
}

/// Posture against Tier Zero and every zone. `settings` gives the collection
/// time (`now`, which ages are measured from) and the activity window of the
/// exposure denominator (`stale_days`, see [`analysis::Relevance`]).
pub fn compute(
    g: &AdGraph,
    findings: &[Finding],
    zones: &[Zone],
    settings: &crate::findings::RuleSettings,
) -> Posture {
    let now = settings.now;
    let t0 = analysis::tier_zero(g);
    let rel = analysis::Relevance::from_settings(g, settings);
    Posture {
        tier_zero: zone_posture(g, "Tier Zero", &t0, &t0, findings, &rel, true),
        zones: zones
            .iter()
            .map(|z| zone_posture(g, &z.name, &z.members, &z.targets(g), findings, &rel, false))
            .collect(),
        findings: finding_counts(findings),
        completeness: completeness(g, now),
        sysvol: crate::sysvol::completeness(g),
        adcs: adcs_completeness(g),
        dc_settings: crate::dcsettings::completeness(g, now),
        ca_settings: crate::dcsettings::ca_completeness(g),
        host_agents: crate::hostprobe::completeness(g),
        exposure_basis: analysis::EXPOSURE_BASIS,
        activity_days: rel.stale_days,
        activity_unknown_domains: rel.activity_unknown_domains,
        plan: None,
        severities_set: severity_settings(settings),
        severity_settings: settings.severity_key(),
    }
}
