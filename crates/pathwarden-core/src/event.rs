//! The event document: everything an output plugin needs about one run, as a
//! single versioned JSON document (`pathwarden.event.v1`). Plugins receive it
//! on stdin; the schema only grows, so plugins written against v1 keep working.
//!
//! Unlike the stored state, the event carries names and details (a ticket
//! needs them), so it is written to a file or pipe for the run and not
//! committed.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::findings::Finding;
use crate::guides;
use crate::posture::Posture;
use crate::remediation::RemediationPlan;
use crate::state::{Change, LastRun, Resolved, Status, TrackedFinding};

pub const SCHEMA: &str = "pathwarden.event.v1";

/// Whether event document `bytes` is one this version reads: its schema
/// is [`SCHEMA`], or it names none (docs/dev/formats.md). Every reader of a
/// kept event document asks this first, so a newer Pathwarden's breaking
/// schema is never read as v1. Pathwarden writes `schema` first, so the
/// start of the document usually answers; otherwise the whole document
/// is read for it.
pub fn readable(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if let Some(s) = schema_at_start(&bytes[..bytes.len().min(256)]) {
        return s == SCHEMA.as_bytes();
    }
    #[derive(serde::Deserialize)]
    struct Head {
        #[serde(default)]
        schema: Option<serde_json::Value>,
    }
    match serde_json::from_slice::<Head>(bytes) {
        Ok(Head { schema: None }) => true,
        Ok(Head { schema: Some(s) }) => s.as_str() == Some(SCHEMA),
        // Not a document at all: its reader says so.
        Err(_) => true,
    }
}

/// For a reader that parses the document in one go: whether the `schema`
/// it read is one this version reads ([`readable`]).
pub fn schema_ok(schema: Option<&str>) -> bool {
    schema.is_none_or(|s| s == SCHEMA)
}

/// The schema string when the document opens with it: `{"schema": "..."`.
fn schema_at_start(head: &[u8]) -> Option<&[u8]> {
    fn trim(b: &[u8]) -> &[u8] {
        let n = b.iter().take_while(|c| c.is_ascii_whitespace()).count();
        &b[n..]
    }
    let rest = trim(head).strip_prefix(b"{")?;
    let rest = trim(rest).strip_prefix(b"\"schema\"")?;
    let rest = trim(rest).strip_prefix(b":")?;
    let rest = trim(rest).strip_prefix(b"\"")?;
    let end = rest.iter().position(|&c| c == b'"' || c == b'\\')?;
    (rest[end] == b'"').then(|| &rest[..end])
}

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub schema: &'static str,
    pub run: &'a LastRun,
    pub posture: &'a Posture,
    /// Every finding present in this run, with how it changed.
    pub findings: Vec<EventFinding<'a>>,
    /// Findings that were open (or suppressed) last run and are gone now.
    pub resolved: &'a [Resolved],
    /// Findings this run could not check (their domain or source was not
    /// collected): still open as far as anyone knows. Plugins that close
    /// tickets for findings missing from `findings` should leave these.
    pub held: Vec<Held<'a>>,
    pub plan: &'a RemediationPlan,
    /// Step-by-step guide (Markdown) for every rule with findings in this run.
    pub guides: BTreeMap<&'static str, &'static str>,
    /// A newer run was recorded first, so what this says changed is older
    /// than the history's state (docs/running.md). Only written when true.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub superseded: bool,
}

#[derive(Debug, Serialize)]
pub struct EventFinding<'a> {
    pub change: Change,
    pub first_seen: i64,
    pub times_seen: u32,
    /// The rule's title ("Account or group outside Tier Zero controls a
    /// Tier Zero object"): a ticket's subject.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub rule_title: &'static str,
    #[serde(flatten)]
    pub finding: &'a Finding,
}

/// A finding this run could not check.
#[derive(Debug, Serialize)]
pub struct Held<'a> {
    pub fingerprint: &'a str,
    pub rule: &'a str,
}

/// The title of the rule `id`, or "" for an unknown one.
fn rule_title(id: &str) -> &'static str {
    crate::findings::rules()
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(id))
        .map_or("", |r| r.title)
}

pub fn build<'a>(
    run: &'a LastRun,
    posture: &'a Posture,
    findings: &'a [Finding],
    changes: &[Change],
    tracked: &'a BTreeMap<String, TrackedFinding>,
    resolved: &'a [Resolved],
    plan: &'a RemediationPlan,
) -> Event<'a> {
    let present: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.fingerprint.as_str()).collect();
    let mut guide_map = BTreeMap::new();
    for f in findings {
        if let Some(g) = guides::guide(f.rule) {
            guide_map.insert(f.rule, g);
        }
    }
    Event {
        schema: SCHEMA,
        run,
        posture,
        findings: findings
            .iter()
            .zip(changes)
            .map(|(f, &change)| {
                let t = tracked.get(&f.fingerprint);
                EventFinding {
                    change,
                    first_seen: t.map_or(run.started_at, |t| t.first_seen),
                    times_seen: t.map_or(1, |t| t.times_seen),
                    rule_title: rule_title(f.rule),
                    finding: f,
                }
            })
            .collect(),
        resolved,
        held: tracked
            .iter()
            .filter(|(fp, t)| t.status != Status::Resolved && !present.contains(fp.as_str()))
            .map(|(fp, t)| Held {
                fingerprint: fp,
                rule: &t.rule,
            })
            .collect(),
        plan,
        guides: guide_map,
        superseded: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::findings::Severity;

    /// docs/dev/formats.md: v1, or no schema at all, reads; anything else
    /// doesn't, wherever in the document it is.
    #[test]
    fn only_v1_is_readable() {
        assert!(readable(br#"{"schema":"pathwarden.event.v1","run":{}}"#));
        assert!(readable(
            b"\xef\xbb\xbf{\n  \"schema\": \"pathwarden.event.v1\"\n}"
        ));
        assert!(readable(br#"{"run":{}}"#));
        assert!(!readable(br#"{"schema":"pathwarden.event.v2"}"#));
        assert!(!readable(br#"{"run":{},"schema":"pathwarden.event.v2"}"#));
        // An escape (here `v`, a "v") sends the check to the full
        // parse, which reads it as JSON does.
        let escaped = "{\"schema\":\"pathwarden.event.\\u00761\"}";
        assert!(escaped.contains("\\u0076"));
        assert!(readable(escaped.as_bytes()));
        assert!(!readable(
            "{\"schema\":\"pathwarden.event.\\u00762\"}".as_bytes()
        ));
        assert!(!readable(br#"{"schema":2}"#));
        assert!(schema_ok(None) && schema_ok(Some(SCHEMA)) && !schema_ok(Some("x")));
    }

    /// Plugins get who accepted a risk: user and computer names travel in
    /// the event with the finding (`accepted`), as in `findings --json`.
    #[test]
    fn an_accepted_finding_names_who_accepted_it() {
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\"\naccepted_by = 'NORTH\\ned'\naccepted_on = \"SECOPS-WS02\"\naccepted_at = \"2026-10-22T14:03:11Z\"\n[[suppress.notes]]\ntext = \"Checked.\"\n",
        )
        .unwrap();
        let mut f = vec![Finding::new("PW-011", Severity::Medium, &["a"], "x")];
        c.apply_suppressions(&mut f, 0);
        let e = EventFinding {
            change: Change::Suppressed,
            first_seen: 0,
            times_seen: 1,
            rule_title: "",
            finding: &f[0],
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["suppressed"], "Kiosks");
        assert_eq!(v["accepted"]["accepted_by"], "NORTH\\ned");
        assert_eq!(v["accepted"]["accepted_on"], "SECOPS-WS02");
        assert_eq!(v["accepted"]["notes"][0]["text"], "Checked.");
    }
}
