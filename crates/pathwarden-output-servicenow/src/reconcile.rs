//! Deciding what to do in ServiceNow, without talking to it: the current
//! findings and the existing Pathwarden tickets in, a list of actions out.
//! Tickets are matched on `correlation_id` (the finding fingerprint), so the
//! plugin is idempotent: running it twice, or after lost state, converges.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::event::{Event, Finding};
use crate::settings::{fill, OnClosed, Settings};

/// Marks every ticket this plugin creates (with `:<scope>` when a scope is
/// set); only tickets with this deployment's exact marker are ever touched.
pub const CORRELATION_DISPLAY: &str = "Pathwarden";
const SHORT_MAX: usize = 160;
const AFFECTED_MAX: usize = 25;

/// An existing Pathwarden ticket.
#[derive(Debug, Clone)]
pub struct Ticket {
    pub sys_id: String,
    pub number: String,
    pub correlation_id: String,
    pub active: bool,
    /// The ticket's `state` value, when ServiceNow reports one.
    pub state: Option<String>,
    /// Close code of a closed ticket, when ServiceNow reports one.
    pub close_code: Option<String>,
    /// The ServiceNow account that created it (`sys_created_by`).
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Create {
        fingerprint: String,
        fields: Map<String, Value>,
    },
    Comment {
        ticket: String,
        sys_id: String,
        fingerprint: String,
        note: String,
    },
    Reopen {
        ticket: String,
        sys_id: String,
        fingerprint: String,
        fields: Map<String, Value>,
    },
    Resolve {
        ticket: String,
        sys_id: String,
        fingerprint: String,
        fields: Map<String, Value>,
    },
    /// Nothing to change; tell the operator why (no API call).
    Info {
        ticket: String,
        fingerprint: String,
        message: String,
    },
}

/// Tickets are trusted by their correlation fields, which any ServiceNow
/// user who can edit a ticket can set: such a ticket could stand in for a
/// real finding's ticket (and, closed as "Won't Fix", keep it from ever
/// being raised). So only tickets this account (`user`, the integration
/// account's user name, which `sys_created_by` holds) created are used:
/// the others are left out, and named in a warning. Without `user`
/// (ServiceNow didn't say who it is), every ticket is used.
pub fn own_tickets(tickets: Vec<Ticket>, user: &str) -> (Vec<Ticket>, Option<String>) {
    let (mine, foreign): (Vec<Ticket>, Vec<Ticket>) = tickets.into_iter().partition(|t| {
        t.created_by
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(user))
    });
    if foreign.is_empty() {
        return (mine, None);
    }
    let shown = foreign
        .iter()
        .take(10)
        .map(|t| {
            format!(
                "{} (by {})",
                t.number,
                t.created_by.as_deref().unwrap_or("an unknown account")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let w = format!(
        "{} ticket(s) carry Pathwarden's correlation fields but were created by another account, \
         not {user}: {shown}{}. They are left alone: never resolved or reopened. If they are \
         Pathwarden's from an earlier integration account, set created_by to that account",
        foreign.len(),
        if foreign.len() > 10 { ", ..." } else { "" }
    );
    (mine, Some(w))
}

/// A ticket in the state this plugin resolves to counts as closed: an
/// incident stays `active` in ServiceNow while Resolved (state 6), and
/// treated as open it would be resolved again on every run and never
/// reopened when its finding comes back.
pub fn settle(tickets: &mut [Ticket], settings: &Settings) {
    let resolved = settings.resolve_fields();
    let Some(state) = resolved.get("state").and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }) else {
        return;
    };
    for t in tickets {
        if t.state.as_deref() == Some(state.as_str()) {
            t.active = false;
        }
    }
}

pub fn plan(
    event: &Event,
    tickets: &[Ticket],
    settings: &Settings,
    on_closed: OnClosed,
) -> Vec<Action> {
    let run_id = event.run.run_id.as_str();
    // Several tickets can share a fingerprint (e.g. someone duplicated one):
    // prefer the active one.
    let mut by_fp: HashMap<&str, &Ticket> = HashMap::new();
    for t in tickets {
        match by_fp.get(t.correlation_id.as_str()) {
            Some(existing) if existing.active || !t.active => {}
            _ => {
                by_fp.insert(t.correlation_id.as_str(), t);
            }
        }
    }
    let mut actions = Vec::new();
    // Held findings were not checked this run (domain or source not
    // collected): never resolve their tickets as gone.
    let mut present: HashSet<&str> = event.held.iter().map(|h| h.fingerprint.as_str()).collect();

    for f in &event.findings {
        let ticket = by_fp.get(f.fingerprint.as_str()).copied();
        if !f.is_active() {
            if let Some(t) = ticket.filter(|t| t.active && settings.resolve_suppressed) {
                let reason = f
                    .suppressed
                    .as_deref()
                    .unwrap_or("suppressed in Pathwarden");
                // Whoever accepted the risk wrote the reason: one line.
                actions.push(resolve(
                    t,
                    settings,
                    &format!("Accepted risk: {}", one_line(reason)),
                ));
            }
            // Handled here; never resolve it again below as "no longer present".
            present.insert(&f.fingerprint);
            continue;
        }
        present.insert(&f.fingerprint);
        match ticket {
            None => {
                if settings.wants(&f.severity, &f.category) {
                    actions.push(Action::Create {
                        fingerprint: f.fingerprint.clone(),
                        fields: create_fields(f, event, settings),
                    });
                }
            }
            Some(t) if t.active => {
                if f.change == "regressed" {
                    actions.push(comment(
                        t,
                        format!("Pathwarden run {run_id}: this finding was resolved earlier and is present again."),
                    ));
                }
            }
            Some(t) if settings.respects(t.close_code.as_deref()) => {
                actions.push(Action::Info {
                    ticket: t.number.clone(),
                    fingerprint: t.correlation_id.clone(),
                    message: format!(
                        "closed as {:?} and left closed; to stop tracking it, add a [[suppress]] entry \
                         with fingerprint = \"{}\"",
                        t.close_code.as_deref().unwrap_or_default(),
                        t.correlation_id
                    ),
                });
            }
            Some(t) => {
                let note =
                    format!("Closed in ServiceNow but still present in Pathwarden run {run_id}.");
                match on_closed {
                    OnClosed::Reopen => {
                        let mut fields = fill(&settings.reopen_fields(), &note);
                        fields.insert("work_notes".into(), Value::String(note));
                        actions.push(Action::Reopen {
                            ticket: t.number.clone(),
                            sys_id: t.sys_id.clone(),
                            fingerprint: t.correlation_id.clone(),
                            fields,
                        });
                    }
                    OnClosed::Comment => actions.push(comment(t, note)),
                    OnClosed::Ignore => {}
                }
            }
        }
    }

    let message = format!("No longer present in Pathwarden run {run_id}.");
    let mut stale: Vec<&Ticket> = tickets
        .iter()
        .filter(|t| t.active && !present.contains(t.correlation_id.as_str()))
        .collect();
    stale.sort_by(|a, b| a.number.cmp(&b.number));
    for t in stale {
        actions.push(resolve(t, settings, &message));
    }
    actions
}

/// What the guards decided: actions to perform, warnings to print, and
/// whether the run must be flagged (non-zero exit).
pub struct Guarded {
    pub actions: Vec<Action>,
    pub warnings: Vec<String>,
    pub flagged: bool,
}

/// Safety limits on top of the plan: never resolve a large share of the
/// active tickets at once (a partial collection or a broken input looks like
/// "everything was fixed"), and never open a flood of tickets in one run.
pub fn guard(actions: Vec<Action>, tickets: &[Ticket], settings: &Settings) -> Guarded {
    let mut warnings = Vec::new();
    let mut flagged = false;
    let active = tickets.iter().filter(|t| t.active).count();
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
            "refusing to resolve {resolves} of {active} active tickets ({:.0}%, above max_resolve_percent = {}). \
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
            "refusing to create {creates} tickets (above max_create = {}). Preview them with --dry-run, \
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

fn comment(t: &Ticket, note: String) -> Action {
    Action::Comment {
        ticket: t.number.clone(),
        sys_id: t.sys_id.clone(),
        fingerprint: t.correlation_id.clone(),
        note,
    }
}

fn resolve(t: &Ticket, settings: &Settings, message: &str) -> Action {
    Action::Resolve {
        ticket: t.number.clone(),
        sys_id: t.sys_id.clone(),
        fingerprint: t.correlation_id.clone(),
        fields: fill(&settings.resolve_fields(), message),
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

/// The subject: the rule's title alone. Severity is in urgency and impact,
/// and tickets are matched by `correlation_id`, never by this text.
pub fn short_description(f: &Finding) -> String {
    truncate(&one_line(subject(f)), SHORT_MAX)
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
    no_code_tag(
        s.chars()
            .filter(|c| !is_invisible(*c))
            .map(|c| if breaks_line(c) { ' ' } else { c })
            .collect(),
    )
}

/// A control character, or a Unicode line or paragraph separator.
fn breaks_line(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Text of several lines (the remediation): its own line breaks kept,
/// every other control character and separator a space, invisible
/// characters gone. Pathwarden puts every name in it on one line as it
/// reads the directory; this keeps a carriage return or separator from
/// starting a line too.
pub fn lines(s: &str) -> String {
    no_code_tag(
        s.chars()
            .filter(|c| !is_invisible(*c))
            .map(|c| if c != '\n' && breaks_line(c) { ' ' } else { c })
            .collect(),
    )
}

/// `s` with every `[code]` and `[/code]` (any case) broken up as `[ code]`:
/// where ServiceNow allows code tags, a journal field shows what is
/// between them as HTML, and names and accepted-risk reasons come from
/// others.
fn no_code_tag(s: String) -> String {
    let lower = s.to_ascii_lowercase();
    if !lower.contains("code]") {
        return s;
    }
    let mut out = String::with_capacity(s.len() + 4);
    let mut i = 0;
    while i < s.len() {
        let rest = &lower[i..];
        if rest.starts_with("[code]") || rest.starts_with("[/code]") {
            out.push_str("[ ");
            i += 1;
            continue;
        }
        let c = s[i..].chars().next().expect("in bounds");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn with_kind(name: &str, kind: &str) -> String {
    if kind.is_empty() {
        one_line(name)
    } else {
        format!("{} ({})", one_line(name), one_line(kind))
    }
}

/// Plain-text ticket body: everything an administrator needs to act.
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

fn create_fields(f: &Finding, event: &Event, settings: &Settings) -> Map<String, Value> {
    let mut fields = settings.fields.clone();
    let (urgency, impact) = settings.impact_for(&f.severity);
    let mut set = |k: &str, v: String| {
        fields.insert(k.to_string(), Value::String(v));
    };
    set("short_description", short_description(f));
    set("description", description(f, event));
    set("correlation_id", f.fingerprint.clone());
    set("correlation_display", settings.correlation_display());
    set("urgency", urgency);
    set("impact", impact);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Affected, Path, Run, Step};

    fn settings() -> Settings {
        Settings::parse(r#"{"instance":"https://x.service-now.com"}"#).unwrap()
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
    fn held_findings_keep_their_tickets_open() {
        let mut e = event(vec![]);
        e.held.push(crate::event::Held {
            fingerprint: "H".into(),
        });
        let t = [ticket("H", "INC1", true), ticket("G", "INC2", true)];
        let a = plan(&e, &t, &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["resolve INC2"]);
    }

    fn ticket(fp: &str, number: &str, active: bool) -> Ticket {
        Ticket {
            sys_id: format!("sys-{number}"),
            number: number.into(),
            correlation_id: fp.into(),
            active,
            state: None,
            close_code: None,
            created_by: None,
        }
    }

    fn kinds(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .map(|a| match a {
                Action::Create { fingerprint, .. } => format!("create {fingerprint}"),
                Action::Comment { ticket, .. } => format!("comment {ticket}"),
                Action::Reopen { ticket, .. } => format!("reopen {ticket}"),
                Action::Resolve { ticket, .. } => format!("resolve {ticket}"),
                Action::Info { ticket, .. } => format!("info {ticket}"),
            })
            .collect()
    }

    /// L5: tickets with Pathwarden's correlation fields that another
    /// account created are pointed out.
    #[test]
    fn foreign_tickets_are_left_out_and_named() {
        let mut ours = ticket("PW-1", "INC1", true);
        ours.created_by = Some("svc.pw".into());
        let mut theirs = ticket("PW-2", "INC2", false);
        theirs.created_by = Some("mallory".into());
        let unknown = ticket("PW-3", "INC3", true);
        let (kept, w) = own_tickets(vec![ours.clone(), theirs, unknown], "SVC.PW");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].number, "INC1");
        let w = w.unwrap();
        assert!(
            w.contains("INC2 (by mallory)") && !w.contains("INC1"),
            "{w}"
        );
        assert!(w.contains("INC3 (by an unknown account)"), "{w}");
        assert!(w.contains("never resolved or reopened"), "{w}");
        let (kept, w) = own_tickets(vec![ours], "svc.pw");
        assert_eq!(kept.len(), 1);
        assert!(w.is_none());
    }

    /// max_resolve_percent counts this account's active tickets only
    ///: tickets someone else labelled can't widen the share that
    /// may be resolved.
    #[test]
    fn the_resolve_guard_counts_own_tickets() {
        let tickets: Vec<Ticket> = (0..10)
            .map(|n| {
                let mut t = ticket(&format!("F{n}"), &format!("INC{n}"), true);
                t.created_by = Some(if n < 5 { "svc.pw" } else { "mallory" }.into());
                t
            })
            .collect();
        let e = event(vec![finding("F0", "open", "high")]);
        let (mine, _) = own_tickets(tickets, "svc.pw");
        let g = guard(
            plan(&e, &mine, &settings(), OnClosed::Reopen),
            &mine,
            &settings(),
        );
        assert!(g.flagged, "{:?}", g.warnings);
        assert!(
            g.warnings[0].contains("4 of 5 active tickets"),
            "{:?}",
            g.warnings
        );
    }

    #[test]
    fn creates_for_new_findings_above_min_severity() {
        let e = event(vec![
            finding("A", "new", "high"),
            finding("B", "new", "low"),
        ]);
        let a = plan(&e, &[], &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["create A"]);
        let Action::Create { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(fields["correlation_id"], "A");
        assert_eq!(fields["correlation_display"], "Pathwarden");
        assert_eq!(
            fields["short_description"],
            "Account or group outside Tier Zero controls a Tier Zero object"
        );
        assert_eq!(
            (fields["urgency"].as_str(), fields["impact"].as_str()),
            (Some("2"), Some("1"))
        );
    }

    #[test]
    fn extra_fields_and_category_filter() {
        let mut s = settings();
        s.fields
            .insert("assignment_group".into(), Value::String("AD Team".into()));
        s.categories = Some(vec!["hygiene".into()]);
        let mut h = finding("H", "new", "medium");
        h.category = "hygiene".into();
        let e = event(vec![finding("A", "new", "critical"), h]);
        let a = plan(&e, &[], &s, OnClosed::Reopen);
        assert_eq!(kinds(&a), ["create H"]);
        let Action::Create { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(fields["assignment_group"], "AD Team");
    }

    #[test]
    fn open_active_ticket_is_left_alone() {
        let e = event(vec![
            finding("A", "open", "high"),
            finding("B", "new", "high"),
        ]);
        let t = [ticket("A", "INC1", true), ticket("B", "INC2", true)];
        assert!(plan(&e, &t, &settings(), OnClosed::Reopen).is_empty());
    }

    /// An incident Pathwarden resolved stays `active` in ServiceNow (state
    /// 6): it is not resolved again while its finding is gone, and is
    /// reopened when the finding comes back. Found on a live instance.
    #[test]
    fn resolved_incidents_count_as_closed() {
        let resolved = |fp: &str, n: &str| Ticket {
            state: Some("6".into()),
            ..ticket(fp, n, true)
        };
        let s = settings();
        let mut t = [resolved("A", "INC1"), ticket("B", "INC2", true)];
        settle(&mut t, &s);
        assert!(!t[0].active && t[1].active);
        let gone = event(vec![]);
        assert_eq!(
            kinds(&plan(&gone, &t, &s, OnClosed::Reopen)),
            ["resolve INC2"]
        );
        let back = event(vec![
            finding("A", "regressed", "high"),
            finding("B", "open", "high"),
        ]);
        assert_eq!(
            kinds(&plan(&back, &t, &s, OnClosed::Reopen)),
            ["reopen INC1"]
        );
    }

    #[test]
    fn regressed_with_active_ticket_gets_a_note() {
        let e = event(vec![finding("A", "regressed", "high")]);
        let a = plan(
            &e,
            &[ticket("A", "INC1", true)],
            &settings(),
            OnClosed::Reopen,
        );
        assert_eq!(kinds(&a), ["comment INC1"]);
        let Action::Comment { note, .. } = &a[0] else {
            panic!()
        };
        assert!(note.contains("run R1") && note.contains("present again"));
    }

    #[test]
    fn closed_but_present_reopen_comment_or_ignore() {
        let e = event(vec![finding("A", "open", "low")]);
        let t = [ticket("A", "INC1", false)];
        let a = plan(&e, &t, &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["reopen INC1"]);
        let Action::Reopen { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(fields["state"], "2");
        assert!(fields["work_notes"]
            .as_str()
            .unwrap()
            .contains("still present"));
        assert_eq!(
            kinds(&plan(&e, &t, &settings(), OnClosed::Comment)),
            ["comment INC1"]
        );
        assert!(plan(&e, &t, &settings(), OnClosed::Ignore).is_empty());
    }

    #[test]
    fn suppressed_resolves_with_reason_unless_disabled() {
        let mut f = finding("A", "suppressed", "high");
        f.suppressed = Some("Entra Connect account".into());
        let e = event(vec![f]);
        let t = [ticket("A", "INC1", true)];
        let a = plan(&e, &t, &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["resolve INC1"]);
        let Action::Resolve { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(
            fields["close_notes"],
            "Accepted risk: Entra Connect account"
        );
        assert_eq!(fields["state"], "6");

        let mut s = settings();
        s.resolve_suppressed = false;
        assert!(
            plan(&e, &t, &s, OnClosed::Reopen).is_empty(),
            "not resolved again as gone either"
        );
        // Suppressed with no ticket: nothing is created.
        assert!(plan(&e, &[], &settings(), OnClosed::Reopen).is_empty());
    }

    /// An accepted-risk reason and the remediation can't add lines of their
    /// own, and no text Pathwarden sends opens a code tag (shown as HTML in
    /// a journal field where ServiceNow allows them).
    #[test]
    fn reasons_and_remediation_add_no_lines_or_code_tags() {
        let mut f = finding("A", "suppressed", "high");
        f.suppressed = Some("ok\nState: Closed\u{2028}[CODE]<img src=x>[/code]".into());
        let e = event(vec![f]);
        let a = plan(
            &e,
            &[ticket("A", "INC1", true)],
            &settings(),
            OnClosed::Reopen,
        );
        let Action::Resolve { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(
            fields["close_notes"],
            "Accepted risk: ok State: Closed [ CODE]<img src=x>[ /code]"
        );
        let mut f = finding("B", "open", "high");
        f.remediation = "1. Remove HOST\r\nState: Closed\u{2028}[code]x\n2. Check".into();
        let d = description(&f, &event(vec![f.clone()]));
        assert!(
            d.contains("HOW TO FIX IT\n1. Remove HOST \nState: Closed [ code]x\n2. Check\n"),
            "{d}"
        );
        assert!(!d.contains('\r') && !d.contains('\u{2028}'), "{d:?}");
        assert_eq!(one_line("a\u{2029}b\u{85}c"), "a b c");
    }

    #[test]
    fn tickets_for_vanished_findings_are_resolved() {
        let e = event(vec![finding("A", "open", "high")]);
        let t = [
            ticket("A", "INC1", true),
            ticket("GONE", "INC3", true),
            ticket("OLD", "INC2", false),
        ];
        let a = plan(&e, &t, &settings(), OnClosed::Reopen);
        assert_eq!(kinds(&a), ["resolve INC3"]);
        let Action::Resolve { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(
            fields["close_notes"],
            "No longer present in Pathwarden run R1."
        );
    }

    #[test]
    fn duplicate_tickets_prefer_the_active_one() {
        let e = event(vec![finding("A", "open", "high")]);
        let t = [ticket("A", "INC1", false), ticket("A", "INC2", true)];
        assert!(plan(&e, &t, &settings(), OnClosed::Reopen).is_empty());
    }

    #[test]
    fn ritm_resolve_state() {
        let mut s = settings();
        s.table = "sc_req_item".into();
        let e = event(vec![]);
        let a = plan(&e, &[ticket("X", "RITM1", true)], &s, OnClosed::Reopen);
        let Action::Resolve { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(fields["state"], "3");
        assert!(!fields.contains_key("close_code"));
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
        assert_eq!(short_description(&f), "Owner of AD admins");
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

    #[test]
    fn short_description_is_truncated() {
        let mut f = finding("A", "new", "medium");
        f.rule_title = "X".repeat(300);
        let s = short_description(&f);
        assert_eq!(s.chars().count(), 160);
        assert!(s.starts_with("XXX") && s.ends_with("..."));
        // An older event without the rule's title: the finding's title.
        f.rule_title = String::new();
        assert_eq!(short_description(&f), "A title");
        assert_eq!(truncate("short", 160), "short");
    }

    #[test]
    fn scope_marks_created_tickets() {
        let mut s = settings();
        s.scope = Some("prod".into());
        let e = event(vec![finding("A", "new", "high")]);
        let a = plan(&e, &[], &s, OnClosed::Reopen);
        let Action::Create { fields, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(fields["correlation_display"], "Pathwarden:prod");
    }

    #[test]
    fn respected_close_code_is_never_reopened() {
        let e = event(vec![finding("A", "open", "high")]);
        let mut t = ticket("A", "INC1", false);
        t.close_code = Some("Won't Fix".into());
        for mode in [OnClosed::Reopen, OnClosed::Comment] {
            let a = plan(&e, std::slice::from_ref(&t), &settings(), mode);
            assert_eq!(kinds(&a), ["info INC1"]);
            let Action::Info { message, .. } = &a[0] else {
                panic!()
            };
            assert!(message.contains("[[suppress]]") && message.contains("fingerprint = \"A\""));
        }
        // Any other close code is still reopened.
        t.close_code = Some("Resolution provided".into());
        assert_eq!(
            kinds(&plan(&e, &[t], &settings(), OnClosed::Reopen)),
            ["reopen INC1"]
        );
    }

    fn active_tickets(n: usize) -> Vec<Ticket> {
        (0..n)
            .map(|i| ticket(&format!("F{i}"), &format!("INC{i}"), true))
            .collect()
    }

    #[test]
    fn mass_resolve_guard() {
        let tickets = active_tickets(10);
        // 6 of 10 vanish: above 50%, so no resolves, and the run is flagged.
        let e = event(
            (6..10)
                .map(|i| finding(&format!("F{i}"), "open", "high"))
                .collect(),
        );
        let a = plan(&e, &tickets, &settings(), OnClosed::Reopen);
        assert_eq!(a.len(), 6);
        let g = guard(a.clone(), &tickets, &settings());
        assert!(g.flagged && g.actions.is_empty());
        assert!(g.warnings[0].contains("refusing to resolve 6 of 10"));
        // Exactly at the threshold is allowed.
        let e5 = event(
            (5..10)
                .map(|i| finding(&format!("F{i}"), "open", "high"))
                .collect(),
        );
        let g5 = guard(
            plan(&e5, &tickets, &settings(), OnClosed::Reopen),
            &tickets,
            &settings(),
        );
        assert!(!g5.flagged && g5.actions.len() == 5);
        // 100 disables the guard.
        let mut s = settings();
        s.max_resolve_percent = 100.0;
        let g = guard(a.clone(), &tickets, &s);
        assert!(!g.flagged && g.actions.len() == 6);
        // Fewer than 5 active tickets: never blocked.
        let few = active_tickets(4);
        let g = guard(
            plan(&event(vec![]), &few, &settings(), OnClosed::Reopen),
            &few,
            &settings(),
        );
        assert!(!g.flagged && g.actions.len() == 4);
        // Creates are not blocked by the resolve guard.
        let mut mixed = a;
        mixed.push(Action::Create {
            fingerprint: "NEW".into(),
            fields: Map::new(),
        });
        let g = guard(mixed, &tickets, &settings());
        assert_eq!(kinds(&g.actions), ["create NEW"]);
    }

    #[test]
    fn create_cap() {
        let e = event(
            (0..5)
                .map(|i| finding(&format!("N{i}"), "new", "high"))
                .collect(),
        );
        let mut s = settings();
        s.max_create = 4;
        let g = guard(plan(&e, &[], &s, OnClosed::Reopen), &[], &s);
        assert!(g.flagged && g.actions.is_empty());
        assert!(g.warnings[0].contains("refusing to create 5"));
        s.max_create = 5;
        let g = guard(plan(&e, &[], &s, OnClosed::Reopen), &[], &s);
        assert!(!g.flagged && g.actions.len() == 5);
    }
}
