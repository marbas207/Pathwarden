//! What changed since the last run: two history points of one environment
//! (and the findings state the later run left) compared into a short list of
//! changes, each one line a person can act on. `pathwarden history` prints
//! it above its table; the app shows the same lines.
//!
//! Compared: accounts with an attack path to Tier Zero and each Privilege Zone,
//! and their status; zones added or removed; choke points (the
//! remediation plan's length, and who still reaches Tier Zero after it);
//! findings new, fixed, back again, held and no longer checked; drops in
//! collection completeness. Figures a point does not have (points written
//! before they were recorded) are left out, never read as zero, and so are
//! counts measured on another exposure basis.
//!
//! Takeover changes are counts: five accounts replaced by five others is
//! no change here. The findings that changed are named.

use serde::Serialize;

use crate::findings::Severity;
use crate::posture::{ExposureGrade, Untargeted, LOW_PERCENT};
use crate::report::num as thousands;
use crate::state::{CompletenessPoint, FindingsState, HistoryPoint, Status, BASIS_CHANGED};

/// How many findings of each kind a line names; the rest are counted.
pub const NAMED: usize = 3;

/// A completeness figure that falls by at least this many points (or below
/// [`LOW_PERCENT`]) is a drop worth a line.
pub const DROP_POINTS: f64 = 5.0;

/// Zone names in a line are cut to this many characters.
pub const ZONE_CHARS: usize = 40;

/// At most this many lines about zones, the worst first; the rest are
/// counted in one line.
pub const ZONE_LINES: usize = 3;

/// Lines of [`SinceLast::render`] fit in this many columns (a long config
/// path or zone name in a command aside).
pub const WIDTH: usize = 120;

/// A count before and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Delta {
    pub before: usize,
    pub after: usize,
}

impl Delta {
    pub fn changed(&self) -> bool {
        self.before != self.after
    }
}

/// A status before and after, when it changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GradeChange {
    pub before: ExposureGrade,
    pub after: ExposureGrade,
}

fn grade_change(
    before: Option<ExposureGrade>,
    after: Option<ExposureGrade>,
) -> Option<GradeChange> {
    match (before, after) {
        (Some(before), Some(after)) if before != after => Some(GradeChange { before, after }),
        _ => None,
    }
}

/// A Privilege Zone that changed. Figures one of the runs lacks are left
/// out; zones only one of them had are [`NewZone`]s or removed zones.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ZoneChange {
    pub zone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed: Option<Delta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<GradeChange>,
}

/// A Privilege Zone only the later run has (added to the settings), with
/// the accounts with an attack path to it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NewZone {
    pub zone: String,
    pub exposed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<ExposureGrade>,
}

/// The remediation plan before and after: its changes, and the accounts
/// that still reach Tier Zero after all of them (0 when it closes every
/// path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlanChange {
    pub steps: Delta,
    pub exposed_after: Delta,
}

/// A finding a line names: its rule, severity and, when the state keeps
/// names, its title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingRef {
    pub rule: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// A rule whose severity was set, changed or taken off in the settings
/// between the two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeverityChange {
    pub rule: String,
    /// The severity set for the earlier run; `None`: none was set.
    pub before: Option<Severity>,
    /// The severity set for the later run; `None`: none is set.
    pub after: Option<Severity>,
    /// What rates the rule's findings when none is set
    /// ([`crate::findings::default_label`]), for the line.
    #[serde(skip)]
    pub default: String,
}

impl SeverityChange {
    fn side(&self, s: Option<Severity>) -> String {
        match s {
            Some(s) => s.label().to_string(),
            None if self.default == "exposure" => "by exposure".into(),
            // "High or Low": which one depends on the case.
            None if self.default.contains(' ') => format!("default ({})", self.default),
            None => self.default.clone(),
        }
    }

    /// "PW-002 by exposure → Critical".
    pub fn words(&self) -> String {
        format!(
            "{} {} → {}",
            self.rule,
            self.side(self.before),
            self.side(self.after)
        )
    }
}

/// How the later run's settings rate the earlier run (see
/// [`HistoryPoint::severity_settings`]): the severities set that changed,
/// whether the settings changed at all, and the earlier run's open counts
/// re-rated with the later run's severities (`None` when they can't be:
/// attack paths are rated another way, or the earlier run didn't record
/// its counts per rule).
struct Rerating {
    changes: Vec<SeverityChange>,
    settings_changed: bool,
    before_counts: Option<crate::posture::FindingCounts>,
}

fn rerating(before: &HistoryPoint, after: &HistoryPoint) -> Rerating {
    use crate::findings::severity_settings_key as key;
    let same = Rerating {
        changes: Vec::new(),
        settings_changed: false,
        before_counts: None,
    };
    // A later run that didn't record them: compared as before.
    let Some(after_key) = &after.severity_settings else {
        return same;
    };
    let none = std::collections::BTreeMap::new();
    let after_mode = [true, false]
        .into_iter()
        .find(|&m| key(m, &after.rule_severities) == *after_key);
    // An earlier run that didn't record them had no severity set, and is
    // taken to have rated attack paths the same way.
    let before_key = before
        .severity_settings
        .clone()
        .unwrap_or_else(|| after_mode.map_or(after_key.clone(), |m| key(m, &none)));
    if before_key == *after_key {
        return same;
    }
    let same_mode = after_mode.is_some_and(|m| key(m, &before.rule_severities) == before_key);
    let mut rules: Vec<&String> = before
        .rule_severities
        .keys()
        .chain(after.rule_severities.keys())
        .collect();
    rules.sort();
    rules.dedup();
    let changes = rules
        .into_iter()
        .filter_map(|r| {
            // A rule set to the one level it has anyway is as good as unset.
            let by_exposure = after_mode.unwrap_or(true);
            let set = |s: Option<Severity>| {
                s.filter(|s| !crate::findings::is_default_level(r, *s, by_exposure))
            };
            let (b, a) = (
                set(before.rule_severities.get(r).copied()),
                set(after.rule_severities.get(r).copied()),
            );
            (b != a).then(|| SeverityChange {
                rule: r.clone(),
                before: b,
                after: a,
                default: crate::findings::default_label(r, after_mode.unwrap_or(true)),
            })
        })
        .collect();
    Rerating {
        changes,
        settings_changed: true,
        before_counts: same_mode
            .then(|| before.findings.rerated(&after.rule_severities))
            .flatten(),
    }
}

/// Findings that changed in the later run: the counts it recorded, and the
/// most severe few of each kind from the findings state (only when the
/// state is the one that run left).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct FindingChanges {
    pub new: usize,
    /// Fixed: gone in a run that could see them. Findings of a rule turned
    /// off are `unchecked` instead.
    pub fixed: usize,
    /// Fixed before, open again.
    pub regressed: usize,
    /// Open before, neither seen nor resolved: their domain was not
    /// collected, or the collection looked incomplete.
    pub held: usize,
    /// Open before, of a rule turned off in the settings.
    pub unchecked: usize,
    pub top_new: Vec<FindingRef>,
    pub top_fixed: Vec<FindingRef>,
    pub top_regressed: Vec<FindingRef>,
    pub top_unchecked: Vec<FindingRef>,
}

/// A completeness figure that fell, in percent of the computers it applies
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Drop {
    pub before: f64,
    pub after: f64,
}

/// Collection completeness that got worse.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CompletenessDrop {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Drop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_groups: Option<Drop>,
    /// Domains below [`LOW_PERCENT`], when there are more than before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_domains: Option<Delta>,
}

impl CompletenessDrop {
    fn is_empty(&self) -> bool {
        self.sessions.is_none() && self.local_groups.is_none() && self.low_domains.is_none()
    }
}

/// Sessions or local groups one run targeted and the other did not (a
/// Quick run beside a Full one): the counts measure different things, so
/// they are not compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TargetingChange {
    /// What the earlier run did not target.
    pub before: Untargeted,
    /// What the later run did not target.
    pub after: Untargeted,
}

impl TargetingChange {
    /// The neutral line What changed shows in place of the comparisons.
    pub fn sentence(&self) -> String {
        let cap = |words: &str| {
            let mut w = words.chars();
            w.next()
                .map(|c| c.to_uppercase().collect::<String>() + w.as_str())
                .unwrap_or_default()
        };
        match (self.after.words(), self.before.words()) {
            (Some(w), b) if b.is_none() || self.after != self.before => format!(
                "{} weren't collected in this run, so this run's counts aren't compared with the last run.",
                cap(w)
            ),
            (None, Some(w)) => format!(
                "{} weren't collected in the last run, so this run's counts aren't compared with it.",
                cap(w)
            ),
            // The same parts, not in the same domains.
            (w, _) => format!(
                "{} weren't collected in the same domains as the last run, so this run's counts aren't compared with it.",
                cap(w.unwrap_or("sessions and local groups"))
            ),
        }
    }
}

/// What a run did not target anywhere, from its point (nothing, when the
/// point doesn't say): a run shown as "not targeted".
pub fn untargeted(p: &HistoryPoint) -> Untargeted {
    p.completeness
        .as_ref()
        .map(|c| c.untargeted())
        .unwrap_or_default()
}

/// What any domain of a run did not target.
pub fn lacking(p: &HistoryPoint) -> Untargeted {
    p.completeness
        .as_ref()
        .map(|c| c.lacking())
        .unwrap_or_default()
}

/// What a run targeted, domain by domain: equal for two runs whose counts
/// can be compared.
pub fn targeting(c: Option<&CompletenessPoint>) -> (Untargeted, Vec<String>) {
    let Some(c) = c else {
        return Default::default();
    };
    let u = c.untargeted();
    // Every domain lacked the same, which the run as a whole says: a point
    // written before the domains were listed reads the same.
    let parts = u.parts().join(",");
    let uniform = u.any()
        && c.untargeted_domains
            .iter()
            .all(|d| d.split_once(':').is_some_and(|(_, p)| p == parts));
    let domains = if uniform {
        Vec::new()
    } else {
        c.untargeted_domains.clone()
    };
    (u, domains)
}

/// Two runs targeted the same things, in every domain: their counts can
/// be compared.
pub fn comparable(a: &HistoryPoint, b: &HistoryPoint) -> bool {
    targeting(a.completeness.as_ref()) == targeting(b.completeness.as_ref())
}

/// A share before and after, in percent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Share {
    pub before: f64,
    pub after: f64,
}

/// Open findings (accepted risks left out) before and after, in all and by
/// severity: what the report's Overview shows beside its counts. No line
/// of their own: the findings that opened and closed say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OpenCounts {
    pub total: Delta,
    pub critical: Delta,
    pub high: Delta,
    pub medium: Delta,
    pub low: Delta,
    pub info: Delta,
}

impl OpenCounts {
    /// `b`: the earlier run's counts, re-rated with the later run's
    /// severities when they were.
    fn new(before: &HistoryPoint, after: &HistoryPoint, b: &crate::posture::FindingCounts) -> Self {
        let a = &after.findings;
        let d = |before, after| Delta { before, after };
        OpenCounts {
            total: d(
                crate::history::open_findings(before),
                crate::history::open_findings(after),
            ),
            critical: d(b.critical, a.critical),
            high: d(b.high, a.high),
            medium: d(b.medium, a.medium),
            low: d(b.low, a.low),
            info: d(b.info, a.info),
        }
    }

    /// The severities, most severe first, with their counts.
    pub fn by_severity(&self) -> [(Severity, Delta); 5] {
        [
            (Severity::Critical, self.critical),
            (Severity::High, self.high),
            (Severity::Medium, self.medium),
            (Severity::Low, self.low),
            (Severity::Info, self.info),
        ]
    }
}

/// What changed between two runs of one environment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SinceLast {
    /// The earlier run's ID.
    pub previous_run: String,
    /// The later run's ID.
    pub run: String,
    /// The runs measured exposure on different bases
    /// ([`HistoryPoint::basis`]): takeover counts, statuses and the plan
    /// are not compared.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub basis_changed: bool,
    /// Accounts with an attack path to Tier Zero; `None` when the basis
    /// changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_zero: Option<Delta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_zero_grade: Option<GradeChange>,
    /// Privilege Zones whose exposed count or status changed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<ZoneChange>,
    /// Privilege Zones only the later run has.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub new_zones: Vec<NewZone>,
    /// Privilege Zones only the earlier run had, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed_zones: Vec<String>,
    /// Privilege Zones whose takeover counts were compared and are the
    /// same (the report's Tiers table says "no change" for them).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones_unchanged: Vec<String>,
    /// The remediation plan, when both runs recorded one on the same basis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes_to_zero: Option<PlanChange>,
    pub findings: FindingChanges,
    /// The later one is a report of data no run recorded: which findings
    /// opened and closed is not known, so `findings` counts none and no
    /// line says that none did.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub findings_unknown: bool,
    /// Open findings in all and by severity. When the severities set in the
    /// settings changed, the earlier run's are re-rated with the later
    /// run's, so the change of settings reads as neither better nor worse.
    pub open: OpenCounts,
    /// Rules whose severity was set, changed or taken off in the settings
    /// between the runs: one line of neither better nor worse.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub severities_changed: Vec<SeverityChange>,
    /// The runs rated findings another way, and the earlier one can't be
    /// re-rated (attack paths rated another way, or a run from before the
    /// counts per rule were recorded): findings by severity and the
    /// statuses are not compared.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rating_changed: bool,
    /// The severity settings changed between the runs: a status that moved
    /// may have moved with them, so its line is neither better nor worse.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub severity_settings_changed: bool,
    /// Tier Zero's protected share, when both runs had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_score: Option<Share>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness: Option<CompletenessDrop>,
    /// Set when the runs targeted different things (sessions, local
    /// groups): no count is compared (accounts, zones, choke points, open
    /// findings, Tier Zero protected, completeness), and the findings that
    /// rest on what the later run lacks are held, not fixed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeting: Option<TargetingChange>,
    /// What the later run did not target (findings held for it are among
    /// `findings.held`).
    #[serde(skip_serializing_if = "Untargeted::none")]
    pub not_targeted: Untargeted,
    /// What the counts don't say, from the findings state the later run
    /// left ([`crate::introduced`]): findings that gained or lost objects,
    /// paths into Tier Zero and the zones that appeared or went. `None`
    /// without that state, or when there is none of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced: Option<crate::introduced::Introduced>,
}

/// Whether a line is a change for the worse, for the better, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tone {
    Worse,
    Better,
    Same,
}

/// One change, as one line: what happened, and where to act on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    pub tone: Tone,
    pub text: String,
    /// What the line is about, one per entry, when it names things: the
    /// most severe findings, then "and 3 more".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
    /// The command to look at next, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<Next>,
    /// About something new since the last run (findings new or back,
    /// objects gained, new members and paths): the report links it to the
    /// Findings tab's Introduced filter. Not in the JSON.
    #[serde(skip)]
    pub introduced: bool,
    /// The count of accounts with an attack path to Tier Zero changed:
    /// the report opens this line to which accounts. Not in the JSON.
    #[serde(skip)]
    pub tier_zero: bool,
}

/// A pathwarden command to look at next, as its arguments after
/// `pathwarden` (`["plan", "--zone=Finance"]`). Kept apart so the
/// arguments, which can come from a shared state, are quoted where they are
/// shown ([`Next::command_line`]). It points: the command still needs the
/// collection (`-i`) and the settings (`-c` or `--env`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Next(pub Vec<String>);

impl Next {
    fn new(args: &[&str]) -> Self {
        Next(args.iter().map(|a| a.to_string()).collect())
    }

    /// `plan`, or `plan --zone=<zone>`: one argument, so a zone name that
    /// starts with `-` is never read as an option.
    fn plan(zone: Option<&str>) -> Self {
        match zone {
            None => Next::new(&["plan"]),
            Some(z) => Next(vec!["plan".into(), format!("--zone={z}")]),
        }
    }

    /// "pathwarden plan '--zone=Tier 1 servers'", each argument quoted for
    /// PowerShell and sh alike when it needs it. `None` when an argument
    /// has a quote or control character, which no quoting makes safe to
    /// paste in both.
    pub fn command_line(&self) -> Option<String> {
        let mut out = String::from("pathwarden");
        for a in &self.0 {
            out.push(' ');
            out.push_str(&quote(a)?);
        }
        Some(out)
    }

    /// [`Next::command_line`], or when no quoting makes it safe (a zone
    /// name), what to type: "pathwarden plan --zone, with the zone's name"
    /// (the zone is the one the line names).
    pub fn shown(&self) -> String {
        self.command_line().unwrap_or_else(|| {
            format!(
                "pathwarden {} --zone, with the zone's name",
                self.0.first().map_or("plan", String::as_str)
            )
        })
    }
}

/// `a` as one shell argument: bare when it is only letters, digits and
/// `-_./:=@+` and does not start with `@` (PowerShell splats `@name`);
/// otherwise in single quotes, inside which PowerShell and sh both take
/// everything literally. `None` when it holds a quote (straight or
/// typographic: PowerShell ends a string at either) or a control character.
pub fn quote(a: &str) -> Option<String> {
    const QUOTES: &[char] = &[
        '\'', '"', '`', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}',
        '\u{201E}',
    ];
    if a.chars()
        .any(|c| QUOTES.contains(&c) || c.is_control() || crate::text::is_bidi_control(c))
    {
        return None;
    }
    if !a.is_empty()
        && !a.starts_with('@')
        && a.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@+".contains(c))
    {
        Some(a.to_string())
    } else {
        Some(format!("'{a}'"))
    }
}

/// A completeness share without its sign, to two decimals and never
/// rounded up to 100 or down to 0: "100" means every computer, "0" none.
pub fn whole_percent(p: f64) -> String {
    crate::posture::percent_number(p)
}

/// The latest run of `points` (oldest first): the last one not added after
/// a newer run ([`HistoryPoint::inserted`]), whose findings state the
/// folder keeps; the last point when all were.
pub fn latest_point(points: &[HistoryPoint]) -> Option<&HistoryPoint> {
    points
        .iter()
        .rev()
        .find(|p| !p.inserted)
        .or_else(|| points.last())
}

/// The point `latest` is compared with: the latest earlier point of the
/// same environment (the same collected domains) that targeted the same
/// things ([`comparable`]: a Quick run with the last Quick run, a Full run
/// with the last Full run), else the latest earlier point of the
/// environment, whose counts [`compare`] then leaves out. Never one added
/// after a newer run ([`HistoryPoint::inserted`]: the runs after it were
/// compared with the one before it). `points` are oldest first, as
/// [`crate::history::load`] returns them.
pub fn previous<'a>(points: &'a [HistoryPoint], latest: &HistoryPoint) -> Option<&'a HistoryPoint> {
    let mut earlier = points
        .iter()
        .rev()
        .filter(|p| !p.inserted)
        .filter(|p| (p.at, &p.run_id) < (latest.at, &latest.run_id))
        .filter(|p| p.scopes.is_empty() || latest.scopes.is_empty() || p.scopes == latest.scopes)
        .peekable();
    let last = *earlier.peek()?;
    Some(earlier.find(|p| comparable(p, latest)).unwrap_or(last))
}

/// Compares `before` with `after`, a later run of the same environment.
/// `state` is the findings state; it names the findings that changed only
/// when it is the one `after` left (its time stamps say so), otherwise the
/// findings are counted only.
pub fn compare(
    before: &HistoryPoint,
    after: &HistoryPoint,
    state: Option<&FindingsState>,
) -> SinceLast {
    // Counts measured on another basis differ by how they were measured,
    // not by what changed (as the history's trend says); so do counts of
    // runs that read different things (a Quick run beside a Full one).
    let targeting = (!comparable(before, after)).then(|| TargetingChange {
        before: lacking(before),
        after: lacking(after),
    });
    let same_basis = before.basis() == after.basis();
    let counted = same_basis && targeting.is_none();
    // Severities set another way in the settings: the counts are re-rated,
    // and a status that moved may have moved with them, so it is shown
    // as neither better nor worse.
    let rerate = rerating(before, after);
    let zones = after
        .zones
        .iter()
        .filter(|_| counted)
        .filter_map(|z| {
            let b = before.zones.iter().find(|b| b.zone == z.zone)?;
            let exposed = match (b.exposed, z.exposed) {
                (Some(before), Some(after)) if before != after => Some(Delta { before, after }),
                _ => None,
            };
            let grade = grade_change(b.grade, z.grade);
            (exposed.is_some() || grade.is_some()).then(|| ZoneChange {
                zone: z.zone.clone(),
                exposed,
                grade,
            })
        })
        .collect();
    // Points have listed their zones from the start, so a zone missing from
    // one was not in its settings. A new zone nobody can take over (or one
    // from a point without the counts) needs no line.
    let new_zones = after
        .zones
        .iter()
        .filter(|z| !before.zones.iter().any(|b| b.zone == z.zone))
        .filter_map(|z| {
            Some(NewZone {
                zone: z.zone.clone(),
                exposed: z.exposed.filter(|&n| n > 0)?,
                grade: z.grade,
            })
        })
        .collect();
    let removed_zones = before
        .zones
        .iter()
        .filter(|b| !after.zones.iter().any(|z| z.zone == b.zone))
        .map(|b| b.zone.clone())
        .collect();
    let zones_unchanged = after
        .zones
        .iter()
        .filter(|_| counted)
        .filter(|z| {
            z.exposed.is_some()
                && before
                    .zones
                    .iter()
                    .any(|b| b.zone == z.zone && b.exposed == z.exposed)
        })
        .map(|z| z.zone.clone())
        .collect();
    let changes_to_zero = match (before.plan, after.plan) {
        (Some(b), Some(a)) if counted => Some(PlanChange {
            steps: Delta {
                before: b.steps,
                after: a.steps,
            },
            exposed_after: Delta {
                before: b.exposed_after,
                after: a.exposed_after,
            },
        }),
        _ => None,
    };
    let mut findings = FindingChanges {
        new: after.changes.new,
        fixed: after.changes.resolved,
        regressed: after.changes.regressed,
        held: after.changes.held,
        unchecked: after.changes.unchecked,
        ..FindingChanges::default()
    };
    if let Some(state) = state {
        let at = after.at;
        // Each as the later run's settings rate it: a finding fixed in an
        // earlier run was rated with that run's.
        let rate = |t: &crate::state::TrackedFinding| {
            if after.severity_settings.is_none() {
                return t.severity;
            }
            after
                .rule_severities
                .get(&t.rule.to_ascii_uppercase())
                .copied()
                .unwrap_or(t.default_severity.unwrap_or(t.severity))
        };
        let pick = |keep: &dyn Fn(&crate::state::TrackedFinding) -> bool| {
            let mut v: Vec<&crate::state::TrackedFinding> =
                state.findings.values().filter(|t| keep(t)).collect();
            // Most severe first, then by rule, so the list is stable.
            v.sort_by(|a, b| {
                rate(b)
                    .cmp(&rate(a))
                    .then(a.rule.cmp(&b.rule))
                    .then(a.title.cmp(&b.title))
            });
            v.into_iter()
                .take(NAMED)
                .map(|t| FindingRef {
                    rule: t.rule.clone(),
                    severity: rate(t),
                    title: t.title.clone(),
                })
                .collect::<Vec<_>>()
        };
        findings.top_new =
            pick(&|t| t.status == Status::Open && t.first_seen == at && t.last_seen == at);
        findings.top_regressed =
            pick(&|t| t.status == Status::Open && t.regressed_at == Some(at) && t.first_seen != at);
        let resolved_now = |t: &crate::state::TrackedFinding| {
            t.status == Status::Resolved && t.resolved_at == Some(at)
        };
        findings.top_fixed = pick(&|t| resolved_now(t) && !t.rule_off);
        findings.top_unchecked = pick(&|t| resolved_now(t) && t.rule_off);
    }
    let completeness = match (before.completeness.clone(), after.completeness.clone()) {
        (Some(b), Some(a)) if targeting.is_none() => {
            let fell = |before: f64, after: f64| {
                (before - after >= DROP_POINTS || (before >= LOW_PERCENT && after < LOW_PERCENT))
                    .then_some(Drop { before, after })
            };
            // A part either run did not target has nothing to compare.
            let skip = b.untargeted().or(a.untargeted());
            let d = CompletenessDrop {
                sessions: fell(b.sessions_percent, a.sessions_percent).filter(|_| !skip.sessions),
                local_groups: match (b.local_groups_percent, a.local_groups_percent) {
                    (Some(b), Some(a)) if !skip.local_groups => fell(b, a),
                    _ => None,
                },
                low_domains: (a.low_domains > b.low_domains).then_some(Delta {
                    before: b.low_domains,
                    after: a.low_domains,
                }),
            };
            (!d.is_empty()).then_some(d)
        }
        _ => None,
    };
    // Runs that read different things: only the findings the later run
    // could check and found fixed are said, in the lines and here alike.
    if targeting.is_some() {
        findings = FindingChanges {
            fixed: findings.fixed,
            top_fixed: std::mem::take(&mut findings.top_fixed),
            ..FindingChanges::default()
        };
    }
    // Objects and paths: only the state the later run left dates them.
    let introduced = state
        .filter(|_| targeting.is_none())
        .filter(|s| s.tracked_since.is_some())
        .map(|s| {
            crate::introduced::period(
                s,
                crate::introduced::Period::LastRun,
                after.at,
                &crate::introduced::Runs::default().in_env_of(after),
            )
        })
        .filter(|i| !i.extra_lines().is_empty());
    SinceLast {
        previous_run: before.run_id.clone(),
        run: after.run_id.clone(),
        basis_changed: !same_basis,
        tier_zero: counted.then_some(Delta {
            before: before.tier_zero_exposed,
            after: after.tier_zero_exposed,
        }),
        tier_zero_grade: grade_change(before.tier_zero_grade, after.tier_zero_grade)
            .filter(|_| counted),
        zones,
        new_zones,
        removed_zones,
        zones_unchanged,
        changes_to_zero,
        findings,
        findings_unknown: false,
        open: OpenCounts::new(
            before,
            after,
            rerate.before_counts.as_ref().unwrap_or(&before.findings),
        ),
        rating_changed: rerate.settings_changed && rerate.before_counts.is_none(),
        severity_settings_changed: rerate.settings_changed,
        severities_changed: rerate.changes,
        protection_score: match (before.protection_score, after.protection_score) {
            (Some(before), Some(after)) if targeting.is_none() => Some(Share { before, after }),
            _ => None,
        },
        completeness,
        targeting,
        not_targeted: lacking(after),
        introduced,
    }
}

/// What changed in the latest of `points` since the run before it in the
/// same environment; `None` when there is no such run.
pub fn latest(points: &[HistoryPoint], state: Option<&FindingsState>) -> Option<SinceLast> {
    let after = latest_point(points)?;
    Some(compare(previous(points, after)?, after, state))
}

/// The comparison with its lines, as `pathwarden history --changes --json`
/// prints it and the app's `/api/history/since` returns it.
///
/// Zone names and finding titles in it (`lines[].text`, `lines[].items`,
/// `zones`, `top_*`) come from settings and a state others can write: a
/// page shows them as text (`textContent`), never as markup.
#[derive(Debug, Clone, Serialize)]
pub struct View {
    #[serde(flatten)]
    pub since: SinceLast,
    pub lines: Vec<Line>,
}

/// [`latest`] with its lines; `None` when there is no earlier run.
pub fn view(points: &[HistoryPoint], state: Option<&FindingsState>) -> Option<View> {
    let since = latest(points, state)?;
    let lines = since.lines();
    Some(View { since, lines })
}

fn s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// "12 more accounts with an attack path to Tier Zero (40 → 52)" and its kin.
fn takeover(d: Delta, zone: &str) -> (Tone, String) {
    if d.before == 0 {
        (
            Tone::Worse,
            format!(
                "{} account{} now {} an attack path to {zone} (none had before)",
                thousands(d.after),
                s(d.after),
                if d.after == 1 { "has" } else { "have" }
            ),
        )
    } else if d.after == 0 {
        (
            Tone::Better,
            format!(
                "No account has an attack path to {zone} anymore ({} had before)",
                thousands(d.before)
            ),
        )
    } else if d.after > d.before {
        let n = d.after - d.before;
        (
            Tone::Worse,
            format!(
                "{} more account{} with an attack path to {zone} ({} → {})",
                thousands(n),
                s(n),
                thousands(d.before),
                thousands(d.after)
            ),
        )
    } else {
        let n = d.before - d.after;
        (
            Tone::Better,
            format!(
                "{} fewer account{} with an attack path to {zone} ({} → {})",
                thousands(n),
                s(n),
                thousands(d.before),
                thousands(d.after)
            ),
        )
    }
}

/// One line for Tier Zero or a zone: the takeover count and the status,
/// "3 more accounts with an attack path to Finance (2 → 5); status Low → High", or
/// "Finance status: Low → High" alone. Worse when either got worse, and
/// then it points at `plan`.
fn zone_line(
    exposed: Option<Delta>,
    grade: Option<GradeChange>,
    zone: &str,
    plan: Next,
    settings_changed: bool,
) -> Line {
    let status = grade.map(|g| {
        // The severities set in Settings changed: the status may have moved
        // with them, so it is shown as neither better nor worse.
        if settings_changed {
            return (
                Tone::Same,
                format!(
                    "{} → {} (rule severities changed in Settings)",
                    g.before.as_str(),
                    g.after.as_str()
                ),
            );
        }
        let tone = if g.after > g.before {
            Tone::Worse
        } else {
            Tone::Better
        };
        (
            tone,
            format!("{} → {}", g.before.as_str(), g.after.as_str()),
        )
    });
    let (tone, text) = match (exposed.map(|d| takeover(d, zone)), status) {
        (Some((t, text)), None) => (t, text),
        (None, Some((t, g))) => (t, format!("{zone} status: {g}")),
        (Some((t1, text)), Some((t2, g))) => (t1.min(t2), format!("{text}; status {g}")),
        (None, None) => (Tone::Same, String::new()),
    };
    Line {
        introduced: false,
        tier_zero: false,
        items: Vec::new(),
        tone,
        text,
        next: (tone == Tone::Worse).then_some(plan),
    }
}

/// A finding named in a line: "Critical PW-003 JDOE has GenericAll on DC01",
/// or the rule's own title when the state keeps no names. With `cut`, the
/// title is cut to 70 characters.
fn finding_name(f: &FindingRef, cut: bool) -> String {
    let title = f.title.clone().or_else(|| {
        crate::findings::rules()
            .iter()
            .find(|r| r.id == f.rule)
            .map(|r| r.title.to_string())
    });
    let sev = f.severity.label();
    match title {
        Some(t) if cut => format!("{sev} {} {}", f.rule, short(&t, 70)),
        Some(t) => format!("{sev} {} {t}", f.rule),
        None => format!("{sev} {}", f.rule),
    }
}

/// `t` cut to `max` characters, with an ellipsis when cut.
fn short(t: &str, max: usize) -> String {
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let mut s: String = t.chars().take(max - 1).collect();
        s.push('…');
        s
    }
}

/// "3 new findings", naming the most severe ("Critical PW-003 …") and
/// counting the rest ("and 1 more").
fn findings_line(
    n: usize,
    what: &str,
    named: &[FindingRef],
    tone: Tone,
    next: Option<Next>,
    cut: bool,
    introduced: bool,
) -> Line {
    let mut items: Vec<String> = named.iter().map(|f| finding_name(f, cut)).collect();
    if !items.is_empty() && n > named.len() {
        items.push(format!("and {} more", thousands(n - named.len())));
    }
    Line {
        introduced,
        tier_zero: false,
        tone,
        text: format!("{} {what}", thousands(n)),
        items,
        next,
    }
}

/// "2 fewer choke points (5 → 3)" while the
/// plan closes every path;
/// once it no longer does, the accounts still left, as the headline says
/// it. Worse when more accounts are left after it, or (as many left) when
/// it got longer.
fn plan_line(p: PlanChange) -> Option<Line> {
    let (steps, left) = (p.steps, p.exposed_after);
    if !steps.changed() && !left.changed() {
        return None;
    }
    let tone = match left.after.cmp(&left.before) {
        std::cmp::Ordering::Greater => Tone::Worse,
        std::cmp::Ordering::Less => Tone::Better,
        std::cmp::Ordering::Equal if steps.after > steps.before => Tone::Worse,
        std::cmp::Ordering::Equal => Tone::Better,
    };
    let text = if left.after == 0 {
        let (word, n) = if steps.after > steps.before {
            ("more", steps.after - steps.before)
        } else {
            ("fewer", steps.before - steps.after)
        };
        format!(
            "{} {word} step{} on the remediation path ({} → {})",
            thousands(n),
            if n == 1 { "" } else { "s" },
            thousands(steps.before),
            thousands(steps.after),
        )
    } else {
        format!(
            "Remediation path steps: {} → {}; {} account{} still reach{} Tier Zero after them ({} before)",
            thousands(steps.before),
            thousands(steps.after),
            thousands(left.after),
            s(left.after),
            if left.after == 1 { "es" } else { "" },
            thousands(left.before)
        )
    };
    Some(Line {
        introduced: false,
        tier_zero: false,
        items: Vec::new(),
        tone,
        text,
        next: (tone == Tone::Worse).then(|| Next::plan(None)),
    })
}

impl SinceLast {
    /// The line for severities set another way in the settings: "Rule
    /// severities set in Settings: PW-002 by exposure → Critical, PW-011
    /// Medium → Low." Neither better nor worse.
    pub fn rating_line(&self) -> Option<String> {
        self.rating_text(true)
    }

    /// [`SinceLast::rating_line`]; `say_not_compared`: with "Findings by
    /// severity are not compared" when they aren't (a line that already
    /// says the counts are not compared leaves it out).
    fn rating_text(&self, say_not_compared: bool) -> Option<String> {
        let not_compared = "Findings by severity are not compared with the last run.";
        if self.severities_changed.is_empty() {
            if !say_not_compared {
                return self.rating_changed.then(|| {
                    "Attack path severities were changed in Settings since the last run."
                        .to_string()
                });
            }
            return self.rating_changed.then(|| {
                format!("Attack path severities were changed in Settings since the last run. {not_compared}")
            });
        }
        let what: Vec<String> = self
            .severities_changed
            .iter()
            .map(SeverityChange::words)
            .collect();
        let mut text = format!("Rule severities set in Settings: {}.", what.join(", "));
        if self.rating_changed && say_not_compared {
            text.push(' ');
            text.push_str(not_compared);
        }
        Some(text)
    }

    /// The runs targeted the same things, so their counts are compared
    /// (open findings and the severities included, which [`SinceLast::open`]
    /// always carries).
    pub fn comparable(&self) -> bool {
        self.targeting.is_none()
    }

    /// Nothing worth a line changed.
    pub fn is_empty(&self) -> bool {
        self.lines().iter().all(|l| l.tone == Tone::Same)
    }

    /// The changes, one line each: Tier Zero first, then the zones (at
    /// most [`ZONE_LINES`], the worst first), the plan, the findings and
    /// the collection. With no change for the better or the worse, a line
    /// saying so comes first. Zone names are cut to [`ZONE_CHARS`] in the
    /// text, never in `next`, and the findings' titles to 70 characters,
    /// for the terminal.
    pub fn lines(&self) -> Vec<Line> {
        self.lines_cut(true)
    }

    /// [`SinceLast::lines`] with zone names and titles whole, for a page
    /// that wraps them (the report's What changed).
    pub fn full_lines(&self) -> Vec<Line> {
        self.lines_cut(false)
    }

    fn lines_cut(&self, cut: bool) -> Vec<Line> {
        let mut out = Vec::new();
        if let Some(t) = &self.targeting {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                // Severities set another way too: one line, saying "not
                // compared" once.
                text: match self.rating_text(false) {
                    Some(r) => format!("{} {r}", t.sentence()),
                    None => t.sentence(),
                },
                next: None,
            });
            // Runs that read different things: nothing is compared but the
            // findings the later run could check and found fixed (those
            // that may rest on what it did not read are held, not fixed).
            let f = &self.findings;
            if f.fixed > 0 {
                out.push(findings_line(
                    f.fixed,
                    if f.fixed == 1 {
                        "finding fixed"
                    } else {
                        "findings fixed"
                    },
                    &f.top_fixed,
                    Tone::Better,
                    None,
                    cut,
                    false,
                ));
            }
            return out;
        }
        if self.basis_changed {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                text: format!(
                    "Accounts with an attack path to Tier Zero and the zones: {BASIS_CHANGED}"
                ),
                next: None,
            });
        }
        if self.tier_zero.is_some_and(|d| d.changed()) || self.tier_zero_grade.is_some() {
            let mut line = zone_line(
                self.tier_zero.filter(Delta::changed),
                self.tier_zero_grade,
                "Tier Zero",
                Next::plan(None),
                self.severity_settings_changed,
            );
            line.tier_zero = self.tier_zero.is_some_and(|d| d.changed());
            out.push(line);
        }
        out.extend(self.zone_lines(cut));
        out.extend(self.changes_to_zero.and_then(plan_line));
        let f = &self.findings;
        if f.new > 0 {
            out.push(findings_line(
                f.new,
                if f.new == 1 {
                    "new finding"
                } else {
                    "new findings"
                },
                &f.top_new,
                Tone::Worse,
                Some(Next::new(&["findings"])),
                cut,
                true,
            ));
        }
        if f.regressed > 0 {
            out.push(findings_line(
                f.regressed,
                if f.regressed == 1 {
                    "finding is back after it was fixed"
                } else {
                    "findings are back after they were fixed"
                },
                &f.top_regressed,
                Tone::Worse,
                Some(Next::new(&["findings"])),
                cut,
                true,
            ));
        }
        if f.fixed > 0 {
            out.push(findings_line(
                f.fixed,
                if f.fixed == 1 {
                    "finding fixed"
                } else {
                    "findings fixed"
                },
                &f.top_fixed,
                Tone::Better,
                None,
                cut,
                false,
            ));
        }
        if f.unchecked > 0 {
            out.push(findings_line(
                f.unchecked,
                if f.unchecked == 1 {
                    "finding no longer checked (rule turned off)"
                } else {
                    "findings no longer checked (rule turned off)"
                },
                &f.top_unchecked,
                Tone::Same,
                None,
                cut,
                false,
            ));
        }
        if let Some(i) = &self.introduced {
            for mut l in i.extra_lines() {
                if cut {
                    l.items = l.items.iter().map(|t| short(t, 100)).collect();
                }
                out.push(l);
            }
        }
        if let Some(text) = self.rating_line() {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                text,
                next: None,
            });
        }
        if f.held > 0 {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                text: match self.not_targeted.words() {
                    Some(w) => format!(
                        "{} finding{} can't be checked this run: {w} weren't collected",
                        thousands(f.held),
                        s(f.held)
                    ),
                    None => format!(
                        "{} finding{} can't be checked this run: the data behind them wasn't collected",
                        thousands(f.held),
                        s(f.held)
                    ),
                },
                next: Some(Next::new(&["posture"])),
            });
        }
        if let Some(c) = &self.completeness {
            let next = Some(Next::new(&["posture"]));
            if let Some(d) = c.sessions {
                out.push(Line {
                    introduced: false,
                    tier_zero: false,
                    items: Vec::new(),
                    tone: Tone::Worse,
                    text: format!(
                        "Sessions: {}% of computers, was {}%; paths through sessions may be missing",
                        whole_percent(d.after),
                        whole_percent(d.before)
                    ),
                    next: next.clone(),
                });
            }
            if let Some(d) = c.local_groups {
                out.push(Line {
                    introduced: false,
                    tier_zero: false,
                    items: Vec::new(),
                    tone: Tone::Worse,
                    text: format!(
                        "Local groups: {}% of member computers, was {}%; local admin paths may be missing",
                        whole_percent(d.after),
                        whole_percent(d.before)
                    ),
                    next: next.clone(),
                });
            }
            // The totals can hold while one domain falls behind.
            if let Some(d) = c
                .low_domains
                .filter(|_| c.sessions.is_none() && c.local_groups.is_none())
            {
                out.push(Line {
                    introduced: false,
                    tier_zero: false,
                    items: Vec::new(),
                    tone: Tone::Worse,
                    text: format!(
                        "{} domain{} now below {LOW_PERCENT:.0}% collection completeness ({} before)",
                        thousands(d.after),
                        s(d.after),
                        thousands(d.before)
                    ),
                    next,
                });
            }
        }
        // Only counts are compared: five accounts replaced by five others
        // is no change here. Runs not compared say no "no change".
        if self.targeting.is_none() && out.iter().all(|l| l.tone == Tone::Same) {
            let text = if out.is_empty() && self.findings_unknown {
                "No change: as many accounts as before have an attack path to Tier Zero"
            } else if out.is_empty() {
                "No change: as many accounts as before have an attack path to Tier Zero, and no finding opened or closed"
            } else {
                "No change"
            };
            out.insert(
                0,
                Line {
                    introduced: false,
                    tier_zero: false,
                    items: Vec::new(),
                    tone: Tone::Same,
                    text: text.to_string(),
                    next: None,
                },
            );
        }
        out
    }

    /// The zones' lines: changed, new and removed zones, the worst first
    /// (worse before better before neither, then the higher status, then
    /// the larger change), at most [`ZONE_LINES`] and a line counting the
    /// rest.
    fn zone_lines(&self, cut: bool) -> Vec<Line> {
        let name = |z: &str| {
            if cut {
                short(z, ZONE_CHARS)
            } else {
                z.to_string()
            }
        };
        // (line, status after, size of the change)
        let mut all: Vec<(Line, Option<ExposureGrade>, usize)> = Vec::new();
        for z in &self.zones {
            let line = zone_line(
                z.exposed,
                z.grade,
                &name(&z.zone),
                Next::plan(Some(&z.zone)),
                self.severity_settings_changed,
            );
            let size = z.exposed.map_or(0, |d| d.before.abs_diff(d.after));
            all.push((line, z.grade.map(|g| g.after), size));
        }
        for z in &self.new_zones {
            let line = Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Worse,
                text: format!(
                    "New zone {}: {} account{} with an attack path to it",
                    name(&z.zone),
                    thousands(z.exposed),
                    s(z.exposed)
                ),
                next: Some(Next::plan(Some(&z.zone))),
            };
            all.push((line, z.grade, z.exposed));
        }
        for z in &self.removed_zones {
            let line = Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                text: format!("Zone {} is no longer in the settings", name(z)),
                next: None,
            };
            all.push((line, None, 0));
        }
        // A stable sort keeps the settings' order among equals.
        all.sort_by(|a, b| {
            a.0.tone
                .cmp(&b.0.tone)
                .then(b.1.cmp(&a.1))
                .then(b.2.cmp(&a.2))
        });
        let more = all.len().saturating_sub(ZONE_LINES);
        let mut out: Vec<Line> = all.into_iter().take(ZONE_LINES).map(|(l, ..)| l).collect();
        if more > 0 {
            out.push(Line {
                introduced: false,
                tier_zero: false,
                items: Vec::new(),
                tone: Tone::Same,
                text: format!("and {} more zone{} changed", thousands(more), s(more)),
                next: Some(Next::new(&["history", "--changes", "--json"])),
            });
        }
        out
    }

    /// The lines as text for the terminal, under "Since the last run":
    /// `!` marks a change for the worse, `+` one for the better; under a
    /// line, what it names and the command to look at. Text from the state
    /// (titles, zone names) is shown with control characters escaped, and
    /// every line fits in [`WIDTH`] columns but a command with a long zone
    /// name, which is never cut. `context` is the settings the commands
    /// take, as given to `history` (`["-c", "pathwarden.toml"]` or
    /// `["--env", "Prod"]`), named once at the end.
    pub fn render(&self, context: &[String]) -> String {
        render_lines(
            &format!("Since the last run ({}):", self.previous_run),
            &self.lines(),
            None,
            context,
        )
    }
}

/// Lines as text for the terminal under `heading`, as
/// [`SinceLast::render`] prints them, with a `note` after them when given
/// (`pathwarden changes` prints [`crate::introduced::Introduced`] so).
pub fn render_lines(
    heading: &str,
    lines: &[Line],
    note: Option<&str>,
    context: &[String],
) -> String {
    let fit = |indent: &str, t: &str| {
        let t = crate::text::terminal_safe(t);
        format!("{indent}{}\n", short(&t, WIDTH - indent.chars().count()))
    };
    let mut out = fit("", heading);
    let mut commands = false;
    for l in lines {
        let mark = match l.tone {
            Tone::Worse => '!',
            Tone::Better => '+',
            Tone::Same => ' ',
        };
        out.push_str(&fit(&format!("  {mark} "), &l.text));
        // One per line under it, so a long title never runs past the
        // width of the table below.
        for item in &l.items {
            out.push_str(&fit("      ", item));
        }
        if let Some(n) = &l.next {
            commands = true;
            out.push_str(&format!("      see: {}\n", n.shown()));
        }
    }
    if let Some(n) = note {
        out.push_str(&fit("  ", n));
    }
    if commands {
        out.push_str(&format!(
            "  {}\n",
            crate::text::terminal_safe(&commands_note(context))
        ));
    }
    out
}

/// The sentence under the commands: what they still take. `context` is the
/// settings they were given (`["-c", "x.toml"]`, `["--env", "Prod"]`), or
/// for the demo its collection (`["-i", "demo:"]`).
pub fn commands_note(context: &[String]) -> String {
    let given: Option<Vec<String>> = context.iter().map(|a| quote(a)).collect();
    match given.filter(|g| !g.is_empty()) {
        Some(g) if context[0] == "-i" => {
            format!("The commands take these arguments: {}", g.join(" "))
        }
        Some(g) => format!(
            "The commands take the collection (-i) and these settings: {}",
            g.join(" ")
        ),
        None => {
            "The commands take the collection (-i) and your settings (-c or --env).".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Category;
    use crate::posture::{FindingCounts, PlanSummary};
    use crate::state::{ChangeCounts, CompletenessPoint, TrackedFinding, ZonePoint};

    fn point(run: &str, at: i64, exposed: usize) -> HistoryPoint {
        HistoryPoint {
            version: 1,
            run_id: run.into(),
            at,
            collected_at: None,
            tier_zero_exposure_percent: 0.0,
            tier_zero_exposed: exposed,
            tier_zero_population: 0,
            tier_zero_relevant_population: 0,
            exposure_basis: 2,
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
    }

    fn zone(name: &str, exposed: Option<usize>, grade: Option<ExposureGrade>) -> ZonePoint {
        ZonePoint {
            zone: name.into(),
            exposure_percent: 0.0,
            protection_score: None,
            objects: exposed.map(|_| 4),
            exposed,
            grade,
        }
    }

    /// A point written before runs recorded what they targeted says what
    /// it collected: one that read no sessions or local groups compares
    /// with a Quick run of the same domain, one that read them with a Full
    /// run.
    #[test]
    fn older_points_compare_by_what_they_collected() {
        let quick_now: CompletenessPoint = serde_json::from_value(serde_json::json!({
            "computers": 0, "sessions_collected": 0, "sessions_percent": 0.0,
            "member_computers": 0, "local_groups_collected": 0, "local_groups_percent": 0.0,
            "low_domains": 0, "sessions_targeted": false, "local_groups_targeted": false,
            "untargeted_domains": [format!("{}:sessions,local_groups", crate::state::scope_key("A.LOCAL"))],
        }))
        .unwrap();
        let older = |sessions: usize, groups: usize| -> CompletenessPoint {
            serde_json::from_value(serde_json::json!({
                "computers": 40, "sessions_collected": sessions, "sessions_percent": 0.0,
                "member_computers": 38, "local_groups_collected": groups,
                "local_groups_percent": 0.0, "low_domains": 1,
            }))
            .unwrap()
        };
        let read_nothing = older(0, 0);
        assert!(!read_nothing.sessions_targeted && !read_nothing.local_groups_targeted);
        assert_eq!(targeting(Some(&read_nothing)), targeting(Some(&quick_now)));
        let full = older(31, 30);
        assert!(full.sessions_targeted && full.local_groups_targeted);
        assert_ne!(targeting(Some(&full)), targeting(Some(&quick_now)));
        assert_eq!(targeting(Some(&full)), targeting(None));
        // Written again, it says what was inferred.
        let again: CompletenessPoint =
            serde_json::from_value(serde_json::to_value(&read_nothing).unwrap()).unwrap();
        assert_eq!(again, read_nothing);
        // One domain read in full beside one that wasn't still differs
        // from both read the same way.
        let mixed = CompletenessPoint {
            sessions_targeted: true,
            local_groups_targeted: true,
            untargeted_domains: vec![format!(
                "{}:sessions,local_groups",
                crate::state::scope_key("B.LOCAL")
            )],
            ..full.clone()
        };
        assert_ne!(targeting(Some(&mixed)), targeting(Some(&full)));
        assert_ne!(targeting(Some(&mixed)), targeting(Some(&quick_now)));
    }

    fn completeness(sessions: f64, groups: Option<f64>, low: usize) -> CompletenessPoint {
        CompletenessPoint {
            computers: 100,
            sessions_collected: sessions as usize,
            sessions_percent: sessions,
            member_computers: 90,
            local_groups_collected: 0,
            local_groups_percent: groups,
            low_domains: low,
            sessions_targeted: true,
            local_groups_targeted: true,
            untargeted_domains: Vec::new(),
        }
    }

    fn tracked(rule: &str, severity: Severity, title: Option<&str>) -> TrackedFinding {
        TrackedFinding {
            rule: rule.into(),
            severity,
            default_severity: None,
            category: Category::AttackPath,
            status: Status::Open,
            first_seen: 100,
            last_seen: 200,
            resolved_at: None,
            regressed_at: None,
            rule_off: false,
            times_seen: 2,
            title: title.map(str::to_string),
            domain: None,
            scope: None,
            sources: Vec::new(),
            requires: Vec::new(),
            objects: None,
            not_targeted: Vec::new(),
            rests_on: None,
        }
    }

    fn texts(s: &SinceLast) -> Vec<String> {
        s.lines().into_iter().map(|l| l.text).collect()
    }

    #[test]
    fn takeover_counts_status_and_changes_to_zero() {
        let mut a = point("a", 100, 40);
        a.tier_zero_grade = Some(ExposureGrade::High);
        a.plan = Some(PlanSummary {
            steps: 5,
            exposed_after: 0,
        });
        a.zones = vec![
            zone("Finance", Some(0), Some(ExposureGrade::Low)),
            zone("Same", Some(3), Some(ExposureGrade::High)),
            zone("Old", None, None),
        ];
        let mut b = point("b", 200, 52);
        b.tier_zero_grade = Some(ExposureGrade::Critical);
        b.plan = Some(PlanSummary {
            steps: 7,
            exposed_after: 0,
        });
        b.zones = vec![
            zone("Finance", Some(3), Some(ExposureGrade::High)),
            zone("Same", Some(3), Some(ExposureGrade::High)),
            zone("Old", Some(9), Some(ExposureGrade::High)),
            zone("New", Some(9), Some(ExposureGrade::High)),
        ];
        let s = compare(&a, &b, None);
        assert_eq!(
            s.tier_zero,
            Some(Delta {
                before: 40,
                after: 52
            })
        );
        // Only Finance changed in figures both runs have.
        assert_eq!(s.zones.len(), 1, "{:?}", s.zones);
        let lines = s.lines();
        // The count and the status in one line; the zones worst first (the
        // larger change first among equal statuses).
        assert_eq!(
            texts(&s),
            [
                "12 more accounts with an attack path to Tier Zero (40 → 52); status High → Critical",
                "New zone New: 9 accounts with an attack path to it",
                "3 accounts now have an attack path to Finance (none had before); status Low → High",
                "2 more steps on the remediation path (5 → 7)",
            ]
        );
        assert!(lines.iter().all(|l| l.tone == Tone::Worse));
        // Every change for the worse names the command to look at.
        assert!(lines.iter().all(|l| l.next.is_some()), "{lines:?}");
        assert_eq!(lines[0].next, Some(Next::new(&["plan"])));
        assert_eq!(lines[1].next, Some(Next::new(&["plan", "--zone=New"])));
        assert_eq!(lines[2].next, Some(Next::new(&["plan", "--zone=Finance"])));

        // The other way round, everything is better.
        let back = compare(&b, &a, None);
        assert_eq!(
            texts(&back)[..2],
            [
                "12 fewer accounts with an attack path to Tier Zero (52 → 40); status Critical → High",
                "No account has an attack path to Finance anymore (3 had before); status High → Low",
            ]
        );
        // A zone the later run no longer has is said, neither better nor
        // worse.
        assert_eq!(back.removed_zones, ["New"]);
        let lines = back.lines();
        let removed: Vec<&Line> = lines.iter().filter(|l| l.tone == Tone::Same).collect();
        assert_eq!(removed.len(), 1, "{lines:?}");
        assert_eq!(removed[0].text, "Zone New is no longer in the settings");
        assert!(lines
            .iter()
            .filter(|l| l.tone != Tone::Same)
            .all(|l| l.tone == Tone::Better && l.next.is_none()));
        // Fewer accounts but a worse status is worse.
        let mut c = b.clone();
        c.zones[0] = zone("Finance", Some(1), Some(ExposureGrade::Critical));
        let l = &compare(&b, &c, None).lines()[0];
        assert_eq!(
            l.text,
            "2 fewer accounts with an attack path to Finance (3 → 1); status High → Critical"
        );
        assert_eq!(l.tone, Tone::Worse);
        // A new zone nobody can take over needs no line.
        let mut c = b.clone();
        c.zones
            .push(zone("Empty", Some(0), Some(ExposureGrade::Low)));
        assert_eq!(compare(&b, &c, None).new_zones, []);
    }

    /// Points from before the figures were recorded compare on what they
    /// have; nothing missing reads as zero.
    #[test]
    fn missing_figures_are_left_out() {
        let a = point("a", 100, 10);
        let mut b = point("b", 200, 10);
        b.tier_zero_grade = Some(ExposureGrade::High);
        b.plan = Some(PlanSummary {
            steps: 3,
            exposed_after: 0,
        });
        b.completeness = Some(completeness(10.0, Some(10.0), 1));
        let s = compare(&a, &b, None);
        assert!(s.tier_zero_grade.is_none() && s.changes_to_zero.is_none());
        assert!(s.completeness.is_none());
        assert!(s.is_empty());
        assert_eq!(
            texts(&s),
            ["No change: as many accounts as before have an attack path to Tier Zero, and no finding opened or closed"]
        );
    }

    #[test]
    fn findings_are_counted_and_the_most_severe_named() {
        let a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        b.changes = ChangeCounts {
            new: 4,
            resolved: 1,
            regressed: 1,
            ..ChangeCounts::default()
        };
        // Without the state: counts only.
        assert_eq!(
            texts(&compare(&a, &b, None)),
            [
                "4 new findings",
                "1 finding is back after it was fixed",
                "1 finding fixed"
            ]
        );
        let mut state = FindingsState::default();
        let mut add = |fp: &str, t: TrackedFinding| {
            state.findings.insert(fp.into(), t);
        };
        for (fp, sev, title) in [
            ("n1", Severity::Low, Some("low one")),
            (
                "n2",
                Severity::Critical,
                Some("JDOE has GenericAll on DC01"),
            ),
            ("n3", Severity::High, None),
            ("n4", Severity::Medium, Some("medium one")),
        ] {
            let mut t = tracked("PW-003", sev, title);
            t.first_seen = 200;
            add(fp, t);
        }
        let mut back = tracked("PW-010", Severity::High, Some("back again"));
        back.regressed_at = Some(200);
        add("r1", back);
        let mut fixed = tracked("PW-001", Severity::Medium, Some("gone"));
        fixed.status = Status::Resolved;
        fixed.last_seen = 100;
        fixed.resolved_at = Some(200);
        add("f1", fixed);
        // Open all along, and fixed in an earlier run: not named.
        add(
            "o1",
            tracked("PW-003", Severity::Critical, Some("still open")),
        );
        let mut old = tracked("PW-003", Severity::Critical, Some("fixed long ago"));
        old.status = Status::Resolved;
        old.resolved_at = Some(100);
        add("f0", old);

        let s = compare(&a, &b, Some(&state));
        let pw003 = crate::findings::rules()
            .iter()
            .find(|r| r.id == "PW-003")
            .unwrap()
            .title;
        let lines = s.lines();
        assert_eq!(
            texts(&s),
            [
                "4 new findings",
                "1 finding is back after it was fixed",
                "1 finding fixed"
            ]
        );
        // The most severe first; without a title in the state, the rule's.
        assert_eq!(
            lines[0].items,
            [
                "Critical PW-003 JDOE has GenericAll on DC01".to_string(),
                format!("High PW-003 {pw003}"),
                "Medium PW-003 medium one".to_string(),
                "and 1 more".to_string(),
            ]
        );
        assert_eq!(lines[1].items, ["High PW-010 back again"]);
        assert_eq!(lines[2].items, ["Medium PW-001 gone"]);
        assert_eq!(lines[2].tone, Tone::Better);
        let text = s.render(&[]);
        assert!(
            text.contains(
                "  ! 4 new findings\n      Critical PW-003 JDOE has GenericAll on DC01\n"
            ),
            "{text}"
        );

        // A state another run left (other time stamps) names nothing.
        let mut c = b.clone();
        c.at = 300;
        assert!(compare(&a, &c, Some(&state)).findings.top_new.is_empty());
    }

    #[test]
    fn completeness_drops_get_a_line() {
        let mut a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        a.completeness = Some(completeness(92.0, Some(88.0), 0));
        b.completeness = Some(completeness(61.0, Some(85.0), 1));
        let s = compare(&a, &b, None);
        assert_eq!(
            texts(&s),
            ["Sessions: 61.00% of computers, was 92.00%; paths through sessions may be missing"]
        );
        // Falling below 80% counts even when small; a rise never does.
        b.completeness = Some(completeness(92.0, Some(79.0), 1));
        assert!(texts(&compare(&a, &b, None))[0]
            .starts_with("Local groups: 79.00% of member computers, was 88.00%"));
        assert!(compare(&b, &a, None).completeness.is_none());
        // The totals hold while a domain falls behind.
        b.completeness = Some(completeness(92.0, Some(88.0), 1));
        assert_eq!(
            texts(&compare(&a, &b, None)),
            ["1 domain now below 80% collection completeness (0 before)"]
        );
    }

    /// The latest run is compared with the run before it in its own
    /// environment.
    #[test]
    fn previous_is_the_run_before_in_the_same_environment() {
        let mut a = point("a", 100, 1).with_domains(&["A.LOCAL".into()]);
        let b = point("b", 200, 2).with_domains(&["B.LOCAL".into()]);
        let c = point("c", 300, 3).with_domains(&["A.LOCAL".into()]);
        let pts = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(previous(&pts, &c).unwrap().run_id, "a");
        assert!(previous(&pts, &b).is_none());
        let s = latest(&pts, None).unwrap();
        assert_eq!((s.previous_run.as_str(), s.run.as_str()), ("a", "c"));
        assert!(latest(&pts[..1], None).is_none());
        // Runs in the same second order by ID.
        a.at = 300;
        a.run_id = "0".into();
        assert_eq!(previous(&[a, c.clone()], &c).unwrap().run_id, "0");
    }

    /// A Full run: sessions and local groups read for most computers.
    fn full(run: &str, at: i64, exposed: usize) -> HistoryPoint {
        let mut p = point(run, at, exposed);
        p.completeness = Some(completeness(88.0, Some(88.0), 0));
        p.protection_score = Some(80.0);
        p
    }

    /// A Quick run: the directory only, sessions and local groups not
    /// targeted (as [`CompletenessPoint::new`] records it).
    fn quick(run: &str, at: i64, exposed: usize) -> HistoryPoint {
        let mut p = point(run, at, exposed);
        p.completeness = Some(CompletenessPoint {
            computers: 0,
            sessions_collected: 0,
            sessions_percent: 0.0,
            member_computers: 0,
            local_groups_collected: 0,
            local_groups_percent: Some(0.0),
            low_domains: 0,
            sessions_targeted: false,
            local_groups_targeted: false,
            untargeted_domains: Vec::new(),
        });
        p.protection_score = Some(96.0);
        p
    }

    const NOT_COMPARED: &str = "Sessions and local groups weren't collected in this run, so this run's counts aren't compared with the last run.";

    /// A Quick run after a Full one is no progress: no count is compared,
    /// one neutral line says why, and only the findings it could check and
    /// found fixed are said (in the lines and the JSON alike).
    #[test]
    fn a_quick_run_after_a_full_one_is_not_compared() {
        let a = full("a", 100, 8975);
        let mut b = quick("b", 200, 1);
        b.changes.resolved = 2;
        b.changes.new = 1;
        b.changes.held = 5;
        let s = compare(&a, &b, None);
        assert!(!s.comparable());
        assert!(s.tier_zero.is_none() && s.tier_zero_grade.is_none());
        assert!(s.protection_score.is_none() && s.completeness.is_none());
        assert!(s.changes_to_zero.is_none());
        assert_eq!(texts(&s), [NOT_COMPARED, "2 findings fixed"]);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(
            (
                &json["findings"]["fixed"],
                &json["findings"]["new"],
                &json["findings"]["held"]
            ),
            (&2.into(), &0.into(), &0.into())
        );
        assert_eq!(json["targeting"]["after"]["sessions"], true);
        assert_eq!(json["not_targeted"]["local_groups"], true);
        // The other way round: this run is not compared with the Quick one.
        let c = full("c", 300, 9000);
        assert_eq!(
            texts(&compare(&b, &c, None))[0],
            "Sessions and local groups weren't collected in the last run, so this run's counts aren't compared with it."
        );
        // Sessions only.
        let mut s_only = quick("s", 300, 1);
        if let Some(c) = s_only.completeness.as_mut() {
            c.local_groups_targeted = true;
        }
        assert_eq!(
            texts(&compare(&a, &s_only, None))[0],
            "Sessions weren't collected in this run, so this run's counts aren't compared with the last run."
        );
        // Quick after Quick: compared, and held findings say why.
        let mut d = quick("d", 400, 1);
        d.changes.held = 3;
        assert!(texts(&compare(&b, &d, None)).contains(
            &"3 findings can't be checked this run: sessions and local groups weren't collected"
                .to_string()
        ));
    }

    /// A run of two domains, one read in full and one Quick, is not
    /// compared with one where both were read in full; a domain that was
    /// targeted and reached nobody still warns.
    #[test]
    fn domains_compare_one_by_one() {
        use crate::posture::Completeness;
        let domain = |name: &str, sessions: usize, targeted: bool| Completeness {
            domain: name.into(),
            computers: 10,
            member_computers: 9,
            enabled_member_computers: 9,
            active_only: true,
            sessions_collected: sessions,
            local_groups_collected: sessions.min(9),
            sessions_percent: sessions as f64 * 10.0,
            local_groups_percent: sessions.min(9) as f64 * 100.0 / 9.0,
            gpo_local_groups: None,
            sessions_targeted: targeted,
            local_groups_targeted: targeted,
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
        let with = |run: &str, at: i64, b: Completeness| {
            let mut p = point(run, at, 10);
            p.completeness = CompletenessPoint::new(&[domain("A.LOCAL", 9, true), b]);
            p
        };
        let both = with("a", 100, domain("B.LOCAL", 9, true));
        let mixed = with("b", 200, domain("B.LOCAL", 0, false));
        assert!(mixed.completeness.as_ref().unwrap().sessions_targeted);
        assert!(!comparable(&both, &mixed));
        assert_eq!(texts(&compare(&both, &mixed, None)), [NOT_COMPARED]);
        // B targeted, reached nobody: compared, and it says so.
        let unreached = with("c", 300, domain("B.LOCAL", 0, true));
        assert!(comparable(&both, &unreached));
        assert!(texts(&compare(&both, &unreached, None)).iter().any(|l| l
            .contains("1 domain now below 80% collection completeness")
            || l.starts_with("Sessions: ")));
    }

    /// Like with like: a run compares with the last run that targeted the
    /// same things, and with the run before when there is none.
    #[test]
    fn runs_compare_with_the_last_run_that_targeted_the_same() {
        // Full, Quick, Full: the two Full runs.
        let pts = vec![full("a", 100, 10), quick("b", 200, 1), full("c", 300, 8)];
        assert_eq!(previous(&pts, &pts[2]).unwrap().run_id, "a");
        let s = latest(&pts, None).unwrap();
        assert!(s.comparable());
        assert_eq!(
            s.tier_zero,
            Some(Delta {
                before: 10,
                after: 8
            })
        );
        // Quick, Full, Quick: the two Quick runs.
        let pts = vec![quick("a", 100, 2), full("b", 200, 10), quick("c", 300, 1)];
        assert_eq!(previous(&pts, &pts[2]).unwrap().run_id, "a");
        let s = latest(&pts, None).unwrap();
        assert!(s.comparable());
        assert_eq!(
            s.tier_zero,
            Some(Delta {
                before: 2,
                after: 1
            })
        );
        assert!(!texts(&s).contains(&NOT_COMPARED.to_string()));
        // Full, Quick: no earlier Quick run, so the Full one, not compared.
        let pts = vec![full("a", 100, 10), quick("b", 200, 1)];
        let s = latest(&pts, None).unwrap();
        assert_eq!(s.previous_run, "a");
        assert!(!s.comparable());
        assert_eq!(texts(&s), [NOT_COMPARED]);
        // Points written before targeting was recorded read as targeted.
        let old: CompletenessPoint = serde_json::from_value(serde_json::json!({
            "computers": 10, "sessions_collected": 9, "sessions_percent": 90.0,
            "member_computers": 8, "local_groups_collected": 8,
            "local_groups_percent": 100.0, "low_domains": 0
        }))
        .unwrap();
        assert!(old.sessions_targeted && old.local_groups_targeted);
        let mut legacy = point("l", 50, 12);
        legacy.completeness = Some(old);
        assert!(comparable(&legacy, &full("a", 100, 10)));
    }

    #[test]
    fn render_marks_and_escapes() {
        let mut a = point("20261009T000000Z", 100, 4);
        let mut b = point("b", 200, 2);
        a.zones = vec![zone("Fin\u{1b}[31mance", Some(0), None)];
        b.zones = vec![zone("Fin\u{1b}[31mance", Some(1), None)];
        let text = compare(&a, &b, None).render(&[]);
        assert!(
            text.starts_with("Since the last run (20261009T000000Z):\n"),
            "{text}"
        );
        assert!(
            text.contains("  + 2 fewer accounts with an attack path to Tier Zero (4 → 2)\n"),
            "{text}"
        );
        assert!(
            text.contains("  ! 1 account now has an attack path to Fin\\u{1b}[31mance"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
        // No command with a control character in it: the zone is the one
        // the line names.
        assert!(
            text.contains("      see: pathwarden plan --zone, with the zone's name\n"),
            "{text}"
        );
    }

    /// Zone names come from a state others can write: the command a line
    /// points at quotes them, and leaves out a name no quoting makes safe.
    #[test]
    fn commands_quote_zone_names() {
        let cmd = |z: &str| Next::plan(Some(z)).command_line();
        assert_eq!(
            cmd("Finance").as_deref(),
            Some("pathwarden plan --zone=Finance")
        );
        assert_eq!(
            cmd("Tier 1 servers; $x & y").as_deref(),
            Some("pathwarden plan '--zone=Tier 1 servers; $x & y'")
        );
        // A name that starts with "-" stays the option's value, and "@"
        // (a PowerShell splat at the start of an argument) is inside it.
        assert_eq!(cmd("-rf").as_deref(), Some("pathwarden plan --zone=-rf"));
        assert_eq!(
            cmd("@splat").as_deref(),
            Some("pathwarden plan --zone=@splat")
        );
        assert_eq!(quote("@splat").as_deref(), Some("'@splat'"));
        // "," is PowerShell's array operator in an argument.
        assert_eq!(quote("a,b").as_deref(), Some("'a,b'"));
        for hostile in [
            "x\"; calc; \"",
            "x'; calc; '",
            "x\u{2019}; calc; \u{2018}",
            "x`; calc",
            "x\ncalc",
        ] {
            assert_eq!(cmd(hostile), None, "{hostile}");
        }
        assert_eq!(quote(""), Some("''".into()));

        let mut a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        a.zones = vec![zone("x'; calc; '", Some(0), None)];
        b.zones = vec![zone("x'; calc; '", Some(2), None)];
        let text = compare(&a, &b, None).render(&[]);
        assert!(!text.contains("--zone='x"), "{text}");
        assert!(text.contains("--zone, with the zone's name"), "{text}");
    }

    /// Every line of the block fits in 120 columns: completeness drops, a
    /// long zone name (cut in the text, and its command left out when too
    /// long), findings, the settings line.
    #[test]
    fn render_fits_in_120_columns() {
        let long = "Payments and treasury servers of the European subsidiaries (production)";
        let mut a = point("20261009T000000Z", 100, 40);
        let mut b = point("20261010T000000Z", 200, 1_234_567);
        a.tier_zero_grade = Some(ExposureGrade::Low);
        b.tier_zero_grade = Some(ExposureGrade::Critical);
        a.completeness = Some(completeness(92.0, Some(88.0), 0));
        b.completeness = Some(completeness(12.0, Some(12.0), 3));
        a.zones = vec![zone(long, Some(0), Some(ExposureGrade::Low))];
        b.zones = vec![
            zone(long, Some(9_999), Some(ExposureGrade::Critical)),
            zone(&format!("{long} 2"), Some(5), Some(ExposureGrade::High)),
        ];
        b.changes = ChangeCounts {
            new: 12_345,
            ..ChangeCounts::default()
        };
        let s = compare(&a, &b, None);
        let text = s.render(&["-c".into(), "C:\\pathwarden\\pathwarden.toml".into()]);
        assert!(text.lines().all(|l| l.chars().count() <= WIDTH), "{text}");
        assert!(
            text.contains("Sessions: 12.00% of computers, was 92.00%"),
            "{text}"
        );
        assert!(
            text.contains("Local groups: 12.00% of member computers, was 88.00%"),
            "{text}"
        );
        assert!(
            text.contains(
                "accounts now have an attack path to Payments and treasury servers of the Eu… (none had before)"
            ),
            "{text}"
        );
        assert!(
            text.ends_with(
                "  The commands take the collection (-i) and these settings: -c 'C:\\pathwarden\\pathwarden.toml'\n"
            ),
            "{text}"
        );
        // In the lines (for the app), the zone keeps its whole name.
        assert!(s
            .lines()
            .iter()
            .any(|l| l.next == Some(Next::plan(Some(long)))));
    }

    /// A zone name too long for the line is cut in the text, and its
    /// command keeps it whole (past the width) so it can be pasted.
    #[test]
    fn a_long_zone_name_stays_whole_in_its_command() {
        let long = "Z".repeat(130);
        let mut a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        a.zones = vec![zone(&long, Some(0), None)];
        b.zones = vec![zone(&long, Some(2), None)];
        let text = compare(&a, &b, None).render(&[]);
        assert!(
            text.contains(&format!(
                "      see: pathwarden plan --zone={long}
"
            )),
            "{text}"
        );
        assert!(!text.contains("with the zone's name"), "{text}");
    }

    /// The figures the report's Overview shows beside its counts: open
    /// findings by severity, Tier Zero protected, and zones compared
    /// with no change. A report of data no run recorded doesn't say no
    /// finding opened or closed.
    #[test]
    fn open_findings_score_and_unchanged_zones_for_the_report() {
        let mut a = point("a", 100, 10);
        a.findings.critical = 3;
        a.findings.high = 2;
        a.protection_score = Some(80.0);
        a.zones = vec![
            zone("Finance", Some(4), None),
            zone("Old", None, None),
            zone("HR", Some(1), None),
        ];
        let mut b = point("b", 200, 10);
        b.findings.critical = 1;
        b.findings.medium = 4;
        b.protection_score = Some(85.5);
        b.zones = vec![
            zone("Finance", Some(4), None),
            zone("Old", Some(2), None),
            zone("HR", Some(3), None),
        ];
        let mut s = compare(&a, &b, None);
        assert_eq!(
            s.open.total,
            Delta {
                before: 5,
                after: 5
            }
        );
        assert_eq!(
            s.open.critical,
            Delta {
                before: 3,
                after: 1
            }
        );
        assert_eq!(
            s.open.by_severity()[2].1,
            Delta {
                before: 0,
                after: 4
            }
        );
        assert_eq!(
            s.protection_score,
            Some(Share {
                before: 80.0,
                after: 85.5
            })
        );
        // Old wasn't counted before: neither changed nor unchanged.
        assert_eq!(s.zones_unchanged, ["Finance"]);
        assert_eq!(s.zones.len(), 1);
        b.zones.clear();
        b.findings = a.findings.clone();
        s = compare(&a, &b, None);
        s.removed_zones.clear();
        s.findings_unknown = true;
        assert_eq!(
            texts(&s),
            ["No change: as many accounts as before have an attack path to Tier Zero"]
        );
        // Another basis: no zone is compared.
        b.exposure_basis = 0;
        b.zones = a.zones.clone();
        assert!(compare(&a, &b, None).zones_unchanged.is_empty());
    }

    /// The JSON the CLI and the app share: the comparison and its lines,
    /// commands as their arguments.
    #[test]
    fn view_serializes_the_lines() {
        let pts = vec![point("a", 100, 1), point("b", 200, 3)];
        let v = serde_json::to_value(view(&pts, None).unwrap()).unwrap();
        assert_eq!(v["previous_run"], "a");
        assert_eq!(v["tier_zero"]["after"], 3);
        assert_eq!(v["lines"][0]["tone"], "worse");
        assert_eq!(v["lines"][0]["next"], serde_json::json!(["plan"]));
        assert!(view(&pts[..1], None).is_none());
    }

    /// A run measured on another exposure basis (an older build) is not
    /// compared on takeover counts: the change is in how they were
    /// counted. The rest still is.
    #[test]
    fn counts_on_another_basis_are_not_compared() {
        let mut a = point("a", 100, 900);
        a.exposure_basis = 0;
        a.tier_zero_grade = Some(ExposureGrade::Critical);
        a.plan = Some(PlanSummary {
            steps: 9,
            exposed_after: 0,
        });
        a.zones = vec![zone("Finance", Some(50), Some(ExposureGrade::High))];
        let mut b = point("b", 200, 40);
        b.tier_zero_grade = Some(ExposureGrade::High);
        b.plan = Some(PlanSummary {
            steps: 3,
            exposed_after: 0,
        });
        b.zones = vec![zone("Finance", Some(2), Some(ExposureGrade::Low))];
        b.changes = ChangeCounts {
            new: 1,
            ..ChangeCounts::default()
        };
        assert_ne!(a.basis(), b.basis());
        let s = compare(&a, &b, None);
        assert!(s.basis_changed);
        assert_eq!(s.tier_zero, None);
        assert_eq!(s.tier_zero_grade, None);
        assert!(s.zones.is_empty() && s.changes_to_zero.is_none());
        let lines = s.lines();
        assert_eq!(
            texts(&s),
            [
                format!("Accounts with an attack path to Tier Zero and the zones: {BASIS_CHANGED}"),
                "1 new finding".to_string(),
            ]
        );
        assert_eq!(lines[0].tone, Tone::Same);
        assert!(!lines.iter().any(|l| l.tone == Tone::Better), "{lines:?}");
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["basis_changed"], true);
        assert!(v.get("tier_zero").is_none(), "{v}");
        // Alone, the line says nothing got better or worse.
        b.changes = ChangeCounts::default();
        assert_eq!(
            texts(&compare(&a, &b, None)),
            [
                "No change".to_string(),
                format!("Accounts with an attack path to Tier Zero and the zones: {BASIS_CHANGED}"),
            ]
        );
    }

    /// A plan that no longer closes every path says who is left, and is not
    /// better for being shorter.
    #[test]
    fn a_plan_that_no_longer_reaches_zero_says_so() {
        let mut a = point("a", 100, 10);
        let mut b = point("b", 200, 10);
        a.plan = Some(PlanSummary {
            steps: 5,
            exposed_after: 0,
        });
        b.plan = Some(PlanSummary {
            steps: 3,
            exposed_after: 4,
        });
        let l = &compare(&a, &b, None).lines()[0];
        assert_eq!(
            l.text,
            "Remediation path steps: 5 → 3; 4 accounts still reach Tier Zero after them (0 before)"
        );
        assert_eq!(l.tone, Tone::Worse);
        assert_eq!(l.next, Some(Next::new(&["plan"])));
        // Back to zero is better, even with more changes.
        let l = &compare(&b, &a, None).lines()[0];
        assert_eq!(l.text, "2 more steps on the remediation path (3 → 5)");
        assert_eq!(l.tone, Tone::Better);
        // As many left after a shorter plan: better, and still says so.
        let mut c = b.clone();
        c.plan = Some(PlanSummary {
            steps: 2,
            exposed_after: 4,
        });
        let l = &compare(&b, &c, None).lines()[0];
        assert_eq!(
            l.text,
            "Remediation path steps: 3 → 2; 4 accounts still reach Tier Zero after them (4 before)"
        );
        assert_eq!(l.tone, Tone::Better);
    }

    /// Many zones changed: the worst few get a line, the rest one line
    /// that counts them.
    #[test]
    fn zone_lines_are_capped_worst_first() {
        let mut a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        for i in 0..8 {
            a.zones
                .push(zone(&format!("Z{i}"), Some(1), Some(ExposureGrade::Low)));
            b.zones.push(zone(
                &format!("Z{i}"),
                Some(1 + i),
                Some(if i == 2 {
                    ExposureGrade::Critical
                } else {
                    ExposureGrade::Low
                }),
            ));
        }
        a.zones.push(zone("Gone", Some(1), None));
        let lines = compare(&a, &b, None).lines();
        assert_eq!(lines.len(), ZONE_LINES + 1, "{lines:?}");
        assert_eq!(
            lines[0].text,
            "2 more accounts with an attack path to Z2 (1 → 3); status Low → Critical"
        );
        assert!(lines[1].text.contains("Z7 (1 → 8)"), "{lines:?}");
        assert!(lines[2].text.contains("Z6 (1 → 7)"), "{lines:?}");
        // Z1, Z3, Z4, Z5 and the removed zone.
        assert_eq!(lines[3].text, "and 5 more zones changed");
        assert_eq!(
            lines[3].next,
            Some(Next::new(&["history", "--changes", "--json"]))
        );
    }

    /// Only a removed zone: the first line does not say "no change".
    #[test]
    fn a_removed_zone_alone_is_neither_better_nor_worse() {
        let mut a = point("a", 100, 0);
        let b = point("b", 200, 0);
        a.zones = vec![zone("Old", Some(1), None)];
        assert_eq!(
            texts(&compare(&a, &b, None)),
            ["No change", "Zone Old is no longer in the settings",]
        );
    }

    /// Findings of a rule turned off are not fixed; held findings are said.
    #[test]
    fn unchecked_and_held_findings_are_not_fixed() {
        let a = point("a", 100, 0);
        let mut b = point("b", 200, 0);
        b.changes = ChangeCounts {
            resolved: 1,
            unchecked: 2,
            held: 3,
            ..ChangeCounts::default()
        };
        let mut state = FindingsState::default();
        let mut fixed = tracked("PW-001", Severity::Medium, Some("gone"));
        fixed.status = Status::Resolved;
        fixed.resolved_at = Some(200);
        state.findings.insert("f".into(), fixed);
        for (fp, title) in [("u1", "off one"), ("u2", "off two")] {
            let mut t = tracked("PW-011", Severity::High, Some(title));
            t.status = Status::Resolved;
            t.resolved_at = Some(200);
            t.rule_off = true;
            state.findings.insert(fp.into(), t);
        }
        let s = compare(&a, &b, Some(&state));
        let lines = s.lines();
        assert_eq!(
            texts(&s),
            [
                "1 finding fixed",
                "2 findings no longer checked (rule turned off)",
                "3 findings can't be checked this run: the data behind them wasn't collected",
            ]
        );
        assert_eq!(lines[0].items, ["Medium PW-001 gone"]);
        assert_eq!(
            lines[1].items,
            ["High PW-011 off one", "High PW-011 off two"]
        );
        assert_eq!((lines[1].tone, lines[2].tone), (Tone::Same, Tone::Same));
        assert_eq!(lines[2].next, Some(Next::new(&["posture"])));
    }

    /// 100% means every computer, 0% none.
    #[test]
    fn whole_percent_never_rounds_to_all_or_none() {
        assert_eq!(whole_percent(100.0), "100");
        assert_eq!(whole_percent(99.999), "99.99");
        assert_eq!(whole_percent(99.6), "99.60");
        assert_eq!(whole_percent(88.5), "88.50");
        assert_eq!(whole_percent(0.004), "<0.01");
        assert_eq!(whole_percent(0.0), "0");
    }
}
