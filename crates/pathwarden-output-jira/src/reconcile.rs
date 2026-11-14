//! Deciding what to do in Jira, without talking to it: the current findings
//! and the existing Pathwarden issues in, a list of actions out. Issues are
//! matched by the label `pwfp-<fingerprint>`, so the plugin is idempotent:
//! running it twice, or after lost state, converges.

use std::collections::{HashMap, HashSet};

use crate::event::{Event, Finding};
use crate::settings::{OnClosed, Settings};

/// Prefix of the label that carries a finding's fingerprint.
pub const FINGERPRINT_LABEL: &str = "pwfp-";
const SUMMARY_MAX: usize = 255;
const AFFECTED_MAX: usize = 25;

/// An existing Pathwarden issue.
#[derive(Debug, Clone)]
pub struct Issue {
    pub key: String,
    pub fingerprint: String,
    /// Not in a "done" status category.
    pub active: bool,
    pub resolution: Option<String>,
    /// Account ID (Cloud) or user name (Data Center) of the creator.
    pub creator: Option<String>,
}

/// What a new issue says; the API layer turns it into Jira fields.
#[derive(Debug, Clone, PartialEq)]
pub struct NewIssue {
    pub summary: String,
    pub description: String,
    pub labels: Vec<String>,
    pub priority: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Create {
        fingerprint: String,
        issue: NewIssue,
    },
    Comment {
        key: String,
        fingerprint: String,
        note: String,
    },
    Reopen {
        key: String,
        fingerprint: String,
        note: String,
    },
    Resolve {
        key: String,
        fingerprint: String,
        note: String,
    },
    /// Nothing to change; tell the operator why (no API call).
    Info {
        key: String,
        fingerprint: String,
        message: String,
    },
}

/// A fingerprint usable inside a label (labels can't hold spaces) and a
/// JQL string: `[A-Za-z0-9._-]`, at most 200 characters.
pub fn valid_fingerprint(s: &str) -> bool {
    (1..=200).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The fingerprint in an issue's labels: exactly one `pwfp-` label, or none.
pub fn fingerprint_of(labels: &[String]) -> Option<String> {
    let mut found = labels
        .iter()
        .filter_map(|l| l.strip_prefix(FINGERPRINT_LABEL))
        .filter(|f| valid_fingerprint(f));
    let first = found.next()?;
    if found.next().is_some() {
        return None;
    }
    Some(first.to_string())
}

/// Issues are trusted by their labels, which anyone who can edit an issue
/// can set: one labelled as a finding's could stand in for its issue, be
/// closed or reopened in its place. So only issues this account (`me`, the
/// integration account) created are used: the others are left out, and
/// named in a warning. Without `me` (Jira didn't say who it is), every
/// issue is used, as before `created_by` defaulted to the account.
pub fn own_issues(issues: Vec<Issue>, me: &str) -> (Vec<Issue>, Option<String>) {
    let (mine, foreign): (Vec<Issue>, Vec<Issue>) = issues
        .into_iter()
        .partition(|i| i.creator.as_deref() == Some(me));
    if foreign.is_empty() {
        return (mine, None);
    }
    let shown = foreign
        .iter()
        .take(10)
        .map(|i| {
            format!(
                "{} (by {})",
                i.key,
                i.creator.as_deref().unwrap_or("an unknown account")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let w = format!(
        "{} issue(s) carry Pathwarden's labels but were created by another account, not this \
         one ({me}): {shown}{}. They are left alone: never closed or reopened. If they are \
         Pathwarden's from an earlier integration account, set created_by to that account",
        foreign.len(),
        if foreign.len() > 10 { ", ..." } else { "" }
    );
    (mine, Some(w))
}

pub fn plan(
    event: &Event,
    issues: &[Issue],
    settings: &Settings,
    on_closed: OnClosed,
) -> Vec<Action> {
    let run_id = event.run.run_id.as_str();
    // Several issues can share a fingerprint (someone cloned one): prefer
    // the active one.
    let mut by_fp: HashMap<&str, &Issue> = HashMap::new();
    for i in issues {
        match by_fp.get(i.fingerprint.as_str()) {
            Some(existing) if existing.active || !i.active => {}
            _ => {
                by_fp.insert(i.fingerprint.as_str(), i);
            }
        }
    }
    let mut actions = Vec::new();
    // Held findings were not checked this run: never close their issues.
    let mut present: HashSet<&str> = event.held.iter().map(|h| h.fingerprint.as_str()).collect();

    for f in &event.findings {
        present.insert(&f.fingerprint);
        if !valid_fingerprint(&f.fingerprint) {
            actions.push(Action::Info {
                key: "-".into(),
                fingerprint: f.fingerprint.chars().take(80).collect(),
                message: "skipped: the fingerprint can't be used as a Jira label".into(),
            });
            continue;
        }
        let issue = by_fp.get(f.fingerprint.as_str()).copied();
        if !f.is_active() {
            if let Some(i) = issue.filter(|i| i.active && settings.resolve_suppressed) {
                let reason = f
                    .suppressed
                    .as_deref()
                    .unwrap_or("suppressed in Pathwarden");
                // Whoever accepted the risk wrote the reason: one line.
                actions.push(resolve(i, format!("Accepted risk: {}", one_line(reason))));
            }
            continue;
        }
        match issue {
            None => {
                if settings.wants(&f.severity, &f.category) {
                    actions.push(Action::Create {
                        fingerprint: f.fingerprint.clone(),
                        issue: new_issue(f, event, settings),
                    });
                }
            }
            Some(i) if i.active => {
                if f.change == "regressed" {
                    actions.push(Action::Comment {
                        key: i.key.clone(),
                        fingerprint: i.fingerprint.clone(),
                        note: format!(
                            "Pathwarden run {run_id}: this finding was resolved earlier and is present again."
                        ),
                    });
                }
            }
            Some(i) if settings.respects(i.resolution.as_deref()) => {
                actions.push(Action::Info {
                    key: i.key.clone(),
                    fingerprint: i.fingerprint.clone(),
                    message: format!(
                        "closed as {:?} and left closed; to stop tracking it, add a [[suppress]] entry \
                         with fingerprint = \"{}\"",
                        i.resolution.as_deref().unwrap_or_default(),
                        i.fingerprint
                    ),
                });
            }
            Some(i) => {
                let note = format!("Closed in Jira but still present in Pathwarden run {run_id}.");
                match on_closed {
                    OnClosed::Reopen => actions.push(Action::Reopen {
                        key: i.key.clone(),
                        fingerprint: i.fingerprint.clone(),
                        note,
                    }),
                    OnClosed::Comment => actions.push(Action::Comment {
                        key: i.key.clone(),
                        fingerprint: i.fingerprint.clone(),
                        note,
                    }),
                    OnClosed::Ignore => {}
                }
            }
        }
    }

    let note = format!("No longer present in Pathwarden run {run_id}.");
    let mut stale: Vec<&Issue> = issues
        .iter()
        .filter(|i| i.active && !present.contains(i.fingerprint.as_str()))
        .collect();
    stale.sort_by(|a, b| a.key.cmp(&b.key));
    for i in stale {
        actions.push(resolve(i, note.clone()));
    }
    actions
}

fn resolve(i: &Issue, note: String) -> Action {
    Action::Resolve {
        key: i.key.clone(),
        fingerprint: i.fingerprint.clone(),
        note,
    }
}

/// What the guards decided: actions to perform, warnings to print, and
/// whether the run must be flagged (non-zero exit).
pub struct Guarded {
    pub actions: Vec<Action>,
    pub warnings: Vec<String>,
    pub flagged: bool,
}

/// Never close a large share of the open issues at once (a partial
/// collection looks like "everything was fixed"), and never open a flood.
pub fn guard(actions: Vec<Action>, issues: &[Issue], settings: &Settings) -> Guarded {
    let mut warnings = Vec::new();
    let mut flagged = false;
    let active = issues.iter().filter(|i| i.active).count();
    let resolves = actions
        .iter()
        .filter(|a| matches!(a, Action::Resolve { .. }))
        .count();
    let creates = actions
        .iter()
        .filter(|a| matches!(a, Action::Create { .. }))
        .count();
    let block_resolves = settings.max_resolve_percent < 100.0
        && active >= 5
        && resolves as f64 * 100.0 > settings.max_resolve_percent * active as f64;
    if block_resolves {
        flagged = true;
        warnings.push(format!(
            "refusing to close {resolves} of {active} open issues ({:.0}%, above max_resolve_percent = {}). \
             This usually means an incomplete collection or input. Check the run; if it is right, raise \
             max_resolve_percent for one run (100 disables the guard).",
            resolves as f64 * 100.0 / active as f64,
            settings.max_resolve_percent
        ));
    }
    let block_creates = creates > settings.max_create;
    if block_creates {
        flagged = true;
        warnings.push(format!(
            "refusing to create {creates} issues (above max_create = {}). Preview them with --dry-run, \
             narrow min_severity or categories, or raise max_create.",
            settings.max_create
        ));
    }
    let actions = actions
        .into_iter()
        .filter(|a| match a {
            Action::Resolve { .. } => !block_resolves,
            Action::Create { .. } => !block_creates,
            _ => true,
        })
        .collect();
    Guarded {
        actions,
        warnings,
        flagged,
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &c.as_str().to_ascii_lowercase(),
        None => String::new(),
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep: String = s.chars().take(max.saturating_sub(3)).collect();
    format!("{keep}...")
}

/// The subject: the rule's title alone, on one line with no control
/// characters (Jira refuses a newline in a summary). Severity is in the
/// priority, and issues are matched by their labels, never by this text.
pub fn summary(f: &Finding) -> String {
    truncate(&one_line(subject(f)), SUMMARY_MAX)
}

/// "2,764".
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The subject: the rule's title, or the finding's own title when the
/// event (an older Pathwarden's) doesn't carry it.
fn subject(f: &Finding) -> &str {
    if f.rule_title.trim().is_empty() {
        &f.title
    } else {
        &f.rule_title
    }
}

/// "EVERYONE@SCALE.LOCAL (Group)".
/// Characters that change how the text around them shows without being
/// seen themselves: bidirectional overrides, isolates and marks, and
/// zero-width characters. A directory name holding one could make a
/// ticket read differently from what it says.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Text from the directory (a name, a domain) on one line: line breaks
/// and other control characters become spaces, invisible characters
/// ([`is_invisible`]) go. A name can't add a line of its own to a ticket.
pub fn one_line(s: &str) -> String {
    s.chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if breaks_line(c) { ' ' } else { c })
        .collect()
}

/// A control character, or a Unicode line or paragraph separator (which
/// Jira Data Center starts a line at).
fn breaks_line(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Text of several lines (the remediation): its own line breaks kept,
/// every other control character and separator a space, invisible
/// characters gone. Pathwarden puts every name in it on one line as it
/// reads the directory; this keeps a carriage return or separator from
/// starting a line too.
pub fn lines(s: &str) -> String {
    s.chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if c != '\n' && breaks_line(c) { ' ' } else { c })
        .collect()
}

fn with_kind(name: &str, kind: &str) -> String {
    if kind.is_empty() {
        one_line(name)
    } else {
        format!("{} ({})", one_line(name), one_line(kind))
    }
}

/// Plain-text issue body: everything an administrator needs to act.
pub fn description(f: &Finding, event: &Event) -> String {
    let mut d = String::new();
    d.push_str(&one_line(f.headline.as_deref().unwrap_or(&f.title)));
    d.push_str("\n\n");
    if let Some(domain) = &f.domain {
        d.push_str(&format!("Domain: {}\n", one_line(domain)));
    }
    d.push_str(&format!("Finding ID: {}\n", f.fingerprint));
    if let Some(e) = &f.exposure {
        let scope = e
            .scope
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| format!(" in {}", one_line(s)))
            .unwrap_or_default();
        d.push_str(&format!(
            "User exposure: {:.2}% ({} of {} active users and computers{scope})\n",
            e.percent,
            thousands(e.principals),
            thousands(e.population)
        ));
    }
    // The deny-entry note gets its own line.
    let why = one_line(&f.summary).replacen(" Deny entries: ", "\nDeny entries: ", 1);
    d.push_str(&format!("\nWHY IT MATTERS\n{why}\n"));
    d.push_str(&format!("\nHOW TO FIX IT\n{}\n", lines(&f.remediation)));
    d.push_str("\nOr: define why this is required, so it can be accepted as a risk.\n");
    if let Some(p) = f.path.as_ref().filter(|p| !p.steps.is_empty()) {
        let mut line = with_kind(&p.steps[0].from, &p.steps[0].from_kind);
        for s in &p.steps {
            line.push_str(&format!(
                " ---> {} {}",
                one_line(&s.edge),
                with_kind(&s.to, &s.to_kind)
            ));
        }
        d.push_str(&format!("\nPATH AS TEXT\n{line}\n"));
    }
    d.push_str(&format!(
        "\nSeverity: {} ({}, {})\n",
        capitalize(&f.severity),
        f.rule,
        f.category.replace('_', " ")
    ));
    if let Some(dflt) = f.severity_default.as_deref() {
        d.push_str(&format!(
            "Severity set by your team. The default is {}.\n",
            capitalize(dflt)
        ));
    }
    if !f.affected.is_empty() {
        d.push_str(&format!("\nAFFECTED OBJECTS ({})\n", f.affected.len()));
        for a in f.affected.iter().take(AFFECTED_MAX) {
            d.push_str(&format!(
                "- {} ({})\n",
                one_line(&a.name),
                one_line(&a.kind)
            ));
        }
        if f.affected.len() > AFFECTED_MAX {
            d.push_str(&format!("- and {} more\n", f.affected.len() - AFFECTED_MAX));
        }
    }
    if !f.references.is_empty() {
        d.push_str("\nREFERENCES\n");
        for r in &f.references {
            d.push_str(&format!("- {}\n", one_line(r)));
        }
    }
    if let Some(guide) = event.guides.get(&f.rule) {
        d.push_str("\nSTEP-BY-STEP GUIDE\n");
        d.push_str(guide.trim_end());
        d.push('\n');
    }
    // Nor anywhere else: Pathwarden's own text never needs one.
    d.retain(|c| !is_invisible(c));
    d
}

fn new_issue(f: &Finding, event: &Event, settings: &Settings) -> NewIssue {
    NewIssue {
        summary: summary(f),
        description: description(f, event),
        labels: vec![
            settings.marker(),
            format!("{FINGERPRINT_LABEL}{}", f.fingerprint),
        ],
        priority: settings
            .set_priority
            .then(|| settings.priority_for(&f.severity)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Affected, Path, Run, Step};

    fn settings() -> Settings {
        Settings::parse(r#"{"instance":"https://x.atlassian.net","project":"SEC"}"#).unwrap()
    }

    fn finding(fp: &str, change: &str, severity: &str) -> Finding {
        Finding {
            change: change.into(),
            rule: "PW-003".into(),
            category: "attack_path".into(),
            severity: severity.into(),
            fingerprint: fp.into(),
            title: format!("{fp} title"),
            rule_title: "Account or group outside Tier Zero controls a Tier Zero object".into(),
            domain: Some("CONTOSO.LOCAL".into()),
            summary: "why".into(),
            remediation: "fix".into(),
            ..Default::default()
        }
    }

    fn event(findings: Vec<Finding>) -> Event {
        Event {
            schema: "pathwarden.event.v1".into(),
            run: Run {
                run_id: "R1".into(),
            },
            findings,
            guides: [("PW-003".to_string(), "# PW-003: guide\n\nsteps".to_string())].into(),
            held: Vec::new(),
        }
    }

    #[test]
    fn held_findings_keep_their_issues_open() {
        let mut e = event(vec![]);
        e.held.push(crate::event::Held {
            fingerprint: "H".into(),
        });
        let a = plan(
            &e,
            &[issue("H", "SEC-1", true), issue("G", "SEC-2", true)],
            &settings(),
            OnClosed::Reopen,
        );
        assert_eq!(kinds(&a), ["resolve SEC-2"]);
    }

    fn issue(fp: &str, key: &str, active: bool) -> Issue {
        Issue {
            key: key.into(),
            fingerprint: fp.into(),
            active,
            resolution: None,
            creator: None,
        }
    }

    fn kinds(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .map(|a| match a {
                Action::Create { fingerprint, .. } => format!("create {fingerprint}"),
                Action::Comment { key, .. } => format!("comment {key}"),
                Action::Reopen { key, .. } => format!("reopen {key}"),
                Action::Resolve { key, .. } => format!("resolve {key}"),
                Action::Info { key, .. } => format!("info {key}"),
            })
            .collect()
    }

    #[test]
    fn fingerprint_labels() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            fingerprint_of(&l(&["pathwarden", "pwfp-PW-003-ab"])).as_deref(),
            Some("PW-003-ab")
        );
        assert_eq!(fingerprint_of(&l(&["pathwarden"])), None);
        // Two fingerprints on one issue: someone tampered; trust neither.
        assert_eq!(fingerprint_of(&l(&["pwfp-A", "pwfp-B"])), None);
        assert_eq!(fingerprint_of(&l(&["pwfp-a\"b"])), None);
    }

    #[test]
    fn creates_for_new_findings_above_min_severity() {
        let e = event(vec![
            finding("A", "new", "high"),
            finding("B", "new", "low"),
        ]);
        let a = plan(&e, &[], &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["create A"]);
        let Action::Create { issue, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(issue.labels, ["pathwarden", "pwfp-A"]);
        assert_eq!(
            issue.summary,
            "Account or group outside Tier Zero controls a Tier Zero object"
        );
        assert_eq!(issue.priority.as_deref(), Some("High"));
        assert!(issue
            .description
            .contains("STEP-BY-STEP GUIDE\n# PW-003: guide"));
    }

    #[test]
    fn lifecycle() {
        let e = event(vec![
            finding("A", "open", "high"),
            finding("R", "regressed", "high"),
            finding("C", "open", "high"),
        ]);
        let issues = [
            issue("A", "SEC-1", true),
            issue("R", "SEC-2", true),
            issue("C", "SEC-3", false),
            issue("OLD", "SEC-4", true),
            issue("DONE", "SEC-5", false),
        ];
        let a = plan(&e, &issues, &settings(), OnClosed::Reopen);
        assert_eq!(
            kinds(&a),
            ["comment SEC-2", "reopen SEC-3", "resolve SEC-4"]
        );
        assert_eq!(
            kinds(&plan(&e, &issues, &settings(), OnClosed::Comment)),
            ["comment SEC-2", "comment SEC-3", "resolve SEC-4"]
        );
        assert_eq!(
            kinds(&plan(&e, &issues, &settings(), OnClosed::Ignore)),
            ["comment SEC-2", "resolve SEC-4"]
        );
    }

    #[test]
    fn suppressed_and_respected_resolutions() {
        let mut f = finding("A", "suppressed", "high");
        f.suppressed = Some("Entra Connect".into());
        let e = event(vec![f, finding("B", "open", "high")]);
        let mut b = issue("B", "SEC-2", false);
        b.resolution = Some("Won't Do".into());
        let a = plan(
            &e,
            &[issue("A", "SEC-1", true), b],
            &settings(),
            OnClosed::Reopen,
        );
        assert_eq!(kinds(&a), ["resolve SEC-1", "info SEC-2"]);
        let Action::Resolve { note, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(note, "Accepted risk: Entra Connect");
    }

    /// An accepted-risk reason and the remediation can't add lines of their
    /// own: a reason is one line, and the remediation keeps only its own
    /// line breaks (a carriage return or separator is a space).
    #[test]
    fn reasons_and_remediation_add_no_lines() {
        let mut f = finding("A", "suppressed", "high");
        f.suppressed = Some("ok\nStatus: approved\u{2028}x\u{202E}".into());
        let e = event(vec![f]);
        let a = plan(
            &e,
            &[issue("A", "SEC-1", true)],
            &settings(),
            OnClosed::Reopen,
        );
        let Action::Resolve { note, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(note, "Accepted risk: ok Status: approved x");
        let mut f = finding("B", "open", "high");
        f.remediation =
            "1. Remove HOST\r\nStatus: approved\u{2028}Resolution: Done\n2. Check".into();
        let d = description(&f, &event(vec![f.clone()]));
        assert!(
            d.contains(
                "HOW TO FIX IT\n1. Remove HOST \nStatus: approved Resolution: Done\n2. Check\n"
            ),
            "{d}"
        );
        assert!(!d.contains('\r') && !d.contains('\u{2028}'), "{d:?}");
        assert_eq!(one_line("a\u{2029}b\u{85}c"), "a b c");
    }

    #[test]
    fn guards() {
        let issues: Vec<Issue> = (0..10)
            .map(|i| issue(&format!("F{i}"), &format!("SEC-{i}"), true))
            .collect();
        let e = event(
            (6..10)
                .map(|i| finding(&format!("F{i}"), "open", "high"))
                .collect(),
        );
        let g = guard(
            plan(&e, &issues, &settings(), OnClosed::Reopen),
            &issues,
            &settings(),
        );
        assert!(g.flagged && g.actions.is_empty());
        let mut s = settings();
        s.max_create = 1;
        let e = event(vec![
            finding("N1", "new", "high"),
            finding("N2", "new", "high"),
        ]);
        let g = guard(plan(&e, &[], &s, OnClosed::Reopen), &[], &s);
        assert!(g.flagged && g.actions.is_empty());
    }

    /// Only this account's issues are used; the others, and one
    /// whose creator Jira didn't give, are named and left alone.
    #[test]
    fn issues_of_other_accounts_are_left_out_and_named() {
        let mut mine = issue("A", "SEC-1", true);
        mine.creator = Some("me".into());
        let mut theirs = issue("B", "SEC-2", true);
        theirs.creator = Some("mallory".into());
        let unknown = issue("C", "SEC-3", true);
        let (kept, w) = own_issues(vec![mine.clone(), theirs, unknown], "me");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].key, "SEC-1");
        let w = w.unwrap();
        assert!(
            w.contains("SEC-2 (by mallory)") && !w.contains("SEC-1"),
            "{w}"
        );
        assert!(w.contains("SEC-3 (by an unknown account)"), "{w}");
        assert!(w.contains("never closed or reopened"), "{w}");
        let (kept, w) = own_issues(vec![mine], "me");
        assert_eq!(kept.len(), 1);
        assert!(w.is_none());
    }

    /// max_resolve_percent counts this account's open issues only: issues
    /// someone else labelled can't widen the share that may close.
    #[test]
    fn the_resolve_guard_counts_own_issues() {
        let mut issues: Vec<Issue> = (0..10)
            .map(|n| {
                let mut i = issue(&format!("F{n}"), &format!("SEC-{n}"), true);
                i.creator = Some(if n < 5 { "me" } else { "mallory" }.into());
                i
            })
            .collect();
        // Four of this account's five issues are gone: 80% of its own,
        // though only 40% of all ten.
        let e = event(vec![finding("F0", "open", "high")]);
        let (mine, _) = own_issues(std::mem::take(&mut issues), "me");
        let g = guard(
            plan(&e, &mine, &settings(), OnClosed::Reopen),
            &mine,
            &settings(),
        );
        assert!(g.flagged, "{:?}", g.warnings);
        assert!(
            g.warnings[0].contains("4 of 5 open issues"),
            "{:?}",
            g.warnings
        );
    }

    #[test]
    fn summary_is_one_line_and_short() {
        let mut f = finding("A", "new", "medium");
        f.rule_title = format!("evil\nname{}", "x".repeat(300));
        let s = summary(&f);
        assert!(!s.contains('\n'));
        assert_eq!(s.chars().count(), 255);
    }

    /// A directory name can't add a line of its own to a ticket, nor
    /// reorder or hide what is shown with invisible characters.
    #[test]
    fn names_stay_on_their_line_and_visible() {
        let mut f = finding("PW-003-abc", "new", "critical");
        f.title = "Owner of \u{202E}AD\u{202C} admins".into();
        f.rule_title = String::new();
        f.headline = None;
        f.domain = Some("CONTOSO\nStatus: fixed".into());
        f.affected = vec![Affected {
            name: "EVIL\r\nResolution: done\u{200B}".into(),
            kind: "User\u{2066}".into(),
        }];
        let d = description(&f, &event(vec![]));
        for c in ['\u{202E}', '\u{202C}', '\u{200B}', '\u{2066}', '\r'] {
            assert!(!d.contains(c), "{c:?} in {d}");
        }
        assert!(d.contains("Domain: CONTOSO Status: fixed\n"), "{d}");
        assert!(d.contains("- EVIL  Resolution: done (User)\n"), "{d}");
        assert!(!d
            .lines()
            .any(|l| l.starts_with("Status:") || l.starts_with("Resolution:")));
        assert!(d.starts_with("Owner of AD admins"), "{d}");
        assert_eq!(summary(&f), "Owner of AD admins");
    }

    #[test]
    fn description_has_everything_an_admin_needs() {
        let mut f = finding("PW-003-abc", "new", "critical");
        f.headline = Some(
            "Remove the Active Directory security permission HELPDESK holds on the group DA."
                .into(),
        );
        f.summary =
            "why it matters. Deny entries: not checked. Pathwarden reads allowed permissions only."
                .into();
        f.exposure = Some(crate::event::Exposure {
            scope: Some("CONTOSO.LOCAL".into()),
            principals: 1234,
            population: 5678,
            percent: 21.733_004,
        });
        f.path = Some(Path {
            steps: vec![
                Step {
                    from: "JDOE".into(),
                    from_kind: "User".into(),
                    edge: "MemberOf".into(),
                    to: "HELPDESK".into(),
                    to_kind: "Group".into(),
                },
                Step {
                    from: "HELPDESK".into(),
                    from_kind: "Group".into(),
                    edge: "GenericAll".into(),
                    to: "DA".into(),
                    to_kind: "Group".into(),
                },
            ],
        });
        f.affected = (0..30)
            .map(|i| Affected {
                name: format!("OBJ{i}"),
                kind: "User".into(),
            })
            .collect();
        f.references = vec!["https://attack.mitre.org/".into()];
        let e = event(vec![f.clone()]);
        let d = description(&f, &e);
        assert!(d.starts_with(
            "Remove the Active Directory security permission HELPDESK holds on the group DA.\n\n\
             Domain: CONTOSO.LOCAL\nFinding ID: PW-003-abc\n\
             User exposure: 21.73% (1,234 of 5,678 active users and computers in CONTOSO.LOCAL)\n"
        ), "{d}");
        for want in [
            "Severity: Critical (PW-003, attack path)",
            "WHY IT MATTERS\nwhy it matters.\nDeny entries: not checked. Pathwarden reads allowed permissions only.\n",
            "HOW TO FIX IT\nfix\n\nOr: define why this is required, so it can be accepted as a risk.\n",
            "PATH AS TEXT\nJDOE (User) ---> MemberOf HELPDESK (Group) ---> GenericAll DA (Group)\n",
            "AFFECTED OBJECTS (30)",
            "- OBJ24 (User)",
            "- and 5 more",
            "Finding ID: PW-003-abc",
            "- https://attack.mitre.org/",
            "STEP-BY-STEP GUIDE\n# PW-003: guide",
        ] {
            assert!(d.contains(want), "missing {want:?} in\n{d}");
        }
        assert!(!d.contains("OBJ25"));
    }
}
