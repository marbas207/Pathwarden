//! The parts of the Pathwarden event document (`pathwarden.event.v1`) this
//! plugin uses. Everything is optional and unknown fields are ignored, so the
//! plugin keeps working as the schema grows.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

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
}
