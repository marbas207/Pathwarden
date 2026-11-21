//! The parts of the Pathwarden event document (`pathwarden.event.v1`) this
//! plugin uses. Everything is optional and unknown fields are ignored, so the
//! plugin keeps working as the schema grows.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

/// The start of a record's `action` when an output plugin reported it.
pub const PLUGIN_SOURCE: &str = "plugin:";

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Event {
    pub schema: String,
    pub run: Run,
    pub findings: Vec<Finding>,
    pub guides: BTreeMap<String, String>,
    /// Findings the run could not check (domain or source not collected):
    /// still present as far as anyone knows, so their tickets stay open.
    pub held: Vec<Held>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Held {
    pub fingerprint: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Run {
    pub run_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Finding {
    /// `new`, `open`, `regressed` or `suppressed`.
    pub change: String,
    pub rule: String,
    pub category: String,
    pub severity: String,
    /// The severity it would have had when the team set its rule's
    /// severity (`severity` is then the set one).
    pub severity_default: Option<String>,
    pub fingerprint: String,
    pub title: String,
    /// The rule's title: the ticket's subject.
    pub rule_title: String,
    /// The change that fixes it, as one sentence, when the finding is
    /// about one relationship.
    pub headline: Option<String>,
    pub domain: Option<String>,
    pub summary: String,
    pub remediation: String,
    pub affected: Vec<Affected>,
    pub path: Option<Path>,
    pub exposure: Option<Exposure>,
    pub references: Vec<String>,
    pub suppressed: Option<String>,
    /// What finding actions did on it (from 1.0.0-rc.3): `records` and
    /// `activity_count`. Kept as plain JSON and read leniently
    /// ([`Finding::open_action_record`]), so an odd shape never stops the
    /// plugin.
    pub actions: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Affected {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Path {
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Step {
    pub from: String,
    pub from_kind: String,
    pub edge: String,
    pub to: String,
    pub to_kind: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Exposure {
    /// The domain measured, or none when measured across every domain.
    pub scope: Option<String>,
    pub principals: usize,
    pub population: usize,
    pub percent: f64,
}

impl Event {
    /// Parses and checks an event document. A document without `findings` (or
    /// without a run ID) is rejected: read as "no findings", it would resolve
    /// every ticket.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .context("parsing the event")?;
        let schema = raw
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !schema.starts_with("pathwarden.event.v1") {
            bail!("unsupported event schema {schema:?} (expected pathwarden.event.v1)");
        }
        if !raw.get("findings").is_some_and(Value::is_array) {
            bail!("the event has no `findings` list; refusing to act on it");
        }
        let run_id = raw
            .get("run")
            .and_then(|r| r.get("run_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if run_id.trim().is_empty() {
            bail!("the event has no `run.run_id`; refusing to act on it");
        }
        serde_json::from_value(raw).context("reading the event")
    }
}

impl Finding {
    /// Present and not covered by an accepted-risk suppression.
    pub fn is_active(&self) -> bool {
        self.change != "suppressed" && self.suppressed.is_none()
    }

    /// The first record a finding action made for this finding that is
    /// still open in the other system (as Pathwarden last heard), named by
    /// its number, label or ID. Any kind counts (`ticket`, `request`, ...):
    /// the kind is free text an action chooses, and an open record means
    /// someone is already tracking the finding there. Records an output
    /// plugin reported (their `action` is `plugin:<name>`, this plugin's
    /// own tickets among them) don't count: they aren't a finding
    /// action's, and counting its own would make the plugin skip every
    /// finding it keeps a ticket for.
    pub fn open_action_record(&self) -> Option<String> {
        let records = self.actions.as_ref()?.get("records")?.as_array()?;
        records
            .iter()
            .filter(|r| r.get("open").and_then(Value::as_bool) == Some(true))
            .filter(|r| {
                !r.get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|a| a.starts_with(PLUGIN_SOURCE))
            })
            .map(|r| {
                ["number", "label", "id"]
                    .iter()
                    .filter_map(|k| r.get(*k).and_then(Value::as_str))
                    .map(str::trim)
                    .find(|v| !v.is_empty())
                    .map(|v| v.chars().take(80).collect::<String>())
                    .unwrap_or_else(|| "a record".into())
            })
            .next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_events() {
        let ok = r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R1"},"findings":[]}"#;
        assert!(Event::parse(ok).is_ok());
        for bad in [
            r#"{"schema":"pathwarden.event.v1"}"#,
            r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R1"}}"#,
            r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R1"},"findings":null}"#,
            r#"{"schema":"pathwarden.event.v1","findings":[]}"#,
            r#"{"schema":"other.v1","run":{"run_id":"R1"},"findings":[]}"#,
            r#"{"run":{"run_id":"R1"},"findings":[]}"#,
        ] {
            assert!(Event::parse(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn reads_open_action_records_leniently() {
        let text = r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R1"},"findings":[
            {"fingerprint":"A","actions":{"records":[
                {"id":"1","number":"RITM1","open":false},
                {"id":"2","kind":"request","number":"RITM2","open":true}],"activity_count":2}},
            {"fingerprint":"B","actions":{"records":[{"id":"x9","open":true,"number":null}]}},
            {"fingerprint":"C","actions":{"records":[{"id":"1","open":"yes"}]}},
            {"fingerprint":"D","actions":{"records":"odd"}},
            {"fingerprint":"E"}]}"#;
        let e = Event::parse(text).unwrap();
        let got: Vec<_> = e.findings.iter().map(Finding::open_action_record).collect();
        assert_eq!(
            got,
            [Some("RITM2".into()), Some("x9".into()), None, None, None]
        );
    }

    /// This plugin's own tickets come back on the findings in `actions`
    /// (Pathwarden saves what the result file said): they never count as
    /// a finding action's ticket, or the plugin would skip every finding
    /// it keeps a ticket for. Another plugin's don't either.
    #[test]
    fn own_and_other_plugin_records_are_not_action_tickets() {
        let text = r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R1"},"findings":[
            {"fingerprint":"A","actions":{"records":[
                {"action":"plugin:servicenow","id":"s1","number":"INC1","open":true}]}},
            {"fingerprint":"B","actions":{"records":[
                {"action":"plugin:jira","id":"SEC-1","number":"SEC-1","open":true},
                {"action":"service-desk/open","id":"r","number":"RITM9","open":true}]}}]}"#;
        let e = Event::parse(text).unwrap();
        let got: Vec<_> = e.findings.iter().map(Finding::open_action_record).collect();
        assert_eq!(got, [None, Some("RITM9".into())]);
    }
}
