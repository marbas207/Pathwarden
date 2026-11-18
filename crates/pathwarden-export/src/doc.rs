//! The findings of one run, as the exporters read them: the parts of the
//! event document (`pathwarden.event.v1`) they use. Unknown fields are
//! ignored, so newer event documents keep working.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

/// One run's findings, ready to export.
#[derive(Debug, Clone, Default)]
pub struct Doc {
    /// The run (`run.run_id`); empty for an analysis that was not a run.
    pub run_id: String,
    /// The Pathwarden version that produced the findings.
    pub tool_version: String,
    /// When the data was collected (or the run started), Unix time.
    pub when: Option<i64>,
    pub findings: Vec<Finding>,
    /// Step-by-step guide (Markdown) per rule ID.
    pub guides: BTreeMap<String, String>,
    /// Rule titles per rule ID; a rule without one takes its guide's first
    /// heading, then its ID.
    pub rule_titles: BTreeMap<String, String>,
    /// Fingerprints of findings the run could not check (domain or source
    /// not collected). They are not in `findings`, but are not fixed either.
    pub held: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Finding {
    /// `new`, `open`, `regressed` or `suppressed`; `None` outside a run.
    pub change: Option<String>,
    pub rule: String,
    pub category: String,
    pub severity: String,
    /// The severity it would have had when the team set its rule's
    /// severity (`severity` is then the set one); `None` otherwise.
    pub severity_default: Option<String>,
    pub fingerprint: String,
    pub title: String,
    pub domain: Option<String>,
    pub summary: String,
    pub remediation: String,
    pub affected: Vec<Affected>,
    pub path: Option<Path>,
    pub exposure: Option<Exposure>,
    pub references: Vec<String>,
    /// The accepted-risk reason, when a suppression matched.
    pub suppressed: Option<String>,
    pub first_seen: Option<i64>,
    pub times_seen: Option<u32>,
    /// External sources the evidence rests on (OpenGraph, PingCastle).
    pub sources: Vec<String>,
    /// What finding actions did on it: its records (a ticket) and how
    /// many times an action ran. `None` when none did.
    pub actions: Option<Actions>,
}

/// The event's `actions` on a finding.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Actions {
    pub records: Vec<ActionRecord>,
    pub activity_count: usize,
}

/// A record an action keeps on a finding, as the event has it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ActionRecord {
    /// The action that made it, `<name>/<id>`.
    pub action: String,
    pub id: String,
    pub kind: Option<String>,
    pub label: Option<String>,
    pub number: Option<String>,
    pub url: Option<String>,
    pub status: Option<String>,
    pub open: bool,
    pub fields: BTreeMap<String, String>,
}

impl ActionRecord {
    /// "RITM10816190 · Open": its number (else label, else ID) and status.
    pub fn line(&self) -> String {
        let name = self
            .number
            .as_deref()
            .or(self.label.as_deref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.id);
        let status = self
            .status
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(if self.open { "Open" } else { "Closed" });
        format!("{name} · {status}")
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Affected {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Path {
    pub source: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Step {
    pub from: String,
    pub edge: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Exposure {
    pub scope: Option<String>,
    pub principals: usize,
    pub population: usize,
    pub percent: f64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawEvent {
    run: RawRun,
    findings: Vec<Finding>,
    guides: BTreeMap<String, String>,
    held: Vec<RawHeld>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawHeld {
    fingerprint: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawRun {
    run_id: String,
    started_at: Option<i64>,
    collected_at: Option<i64>,
    pathwarden: String,
}

impl Doc {
    /// Reads an event document. One without a `findings` list is refused:
    /// read as "no findings", a reimport would close every finding.
    pub fn from_event(text: &str) -> Result<Doc> {
        let raw: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .context("parsing the event document")?;
        let schema = raw
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !schema.starts_with("pathwarden.event.v1") {
            bail!("Unsupported event schema {schema:?} (expected pathwarden.event.v1).");
        }
        if !raw.get("findings").is_some_and(Value::is_array) {
            bail!("The event document has no `findings` list.");
        }
        let ev: RawEvent = serde_json::from_value(raw).context("reading the event document")?;
        let doc = Doc {
            run_id: ev.run.run_id,
            tool_version: ev.run.pathwarden,
            when: ev.run.collected_at.or(ev.run.started_at),
            findings: ev.findings,
            guides: ev.guides,
            rule_titles: BTreeMap::new(),
            held: ev.held.into_iter().map(|h| h.fingerprint).collect(),
        };
        doc.check()?;
        Ok(doc)
    }

    /// Every finding needs a rule and a fingerprint: the fingerprint is what
    /// the importing system matches on, and a blank one would merge findings.
    pub fn check(&self) -> Result<()> {
        for (i, f) in self.findings.iter().enumerate() {
            if f.fingerprint.trim().is_empty() || f.rule.trim().is_empty() {
                bail!("Finding {} has no rule or fingerprint.", i + 1);
            }
        }
        Ok(())
    }

    /// The rule's title: configured, else the guide's `# ID: Title` heading,
    /// else the ID itself.
    pub fn rule_title(&self, rule: &str) -> String {
        if let Some(t) = self.rule_titles.get(rule) {
            return t.clone();
        }
        self.guides
            .get(rule)
            .and_then(|g| g.lines().next())
            .and_then(|l| l.strip_prefix('#'))
            .map(|l| l.trim())
            .map(|l| {
                l.strip_prefix(rule)
                    .map(|r| r.trim_start_matches(':').trim())
                    .unwrap_or(l)
            })
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| rule.to_string())
    }
}

impl Finding {
    /// Covered by an accepted-risk suppression.
    pub fn is_suppressed(&self) -> bool {
        self.suppressed.is_some() || self.change.as_deref() == Some("suppressed")
    }

    /// The accepted-risk reason, or a generic one.
    pub fn suppression_reason(&self) -> &str {
        self.suppressed
            .as_deref()
            .unwrap_or("accepted risk in Pathwarden")
    }

    /// `critical` ... `info`, lowercased; anything unknown is `info`.
    pub fn severity_key(&self) -> &'static str {
        match self.severity.trim().to_ascii_lowercase().as_str() {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "info",
        }
    }

    /// "Severity set by your team. The default is High." when it was.
    pub fn severity_set_line(&self) -> Option<String> {
        let d = self.severity_default.as_deref()?.trim();
        let mut c = d.chars();
        let first = c.next()?;
        Some(format!(
            "Severity set by your team. The default is {}{}.",
            first.to_ascii_uppercase(),
            c.as_str().to_ascii_lowercase()
        ))
    }

    /// `A -[Edge]-> B -[Edge]-> C`, when there is a path.
    pub fn path_line(&self) -> Option<String> {
        let p = self.path.as_ref().filter(|p| !p.steps.is_empty())?;
        let mut line = if p.source.is_empty() {
            p.steps[0].from.clone()
        } else {
            p.source.clone()
        };
        for s in &p.steps {
            line.push_str(&format!(" -[{}]-> {}", s.edge, s.to));
        }
        Some(line)
    }

    /// "51 of 80 active users and computers in X can abuse this (63.8%)".
    pub fn exposure_line(&self) -> Option<String> {
        let e = self.exposure.as_ref()?;
        let scope = e
            .scope
            .as_deref()
            .map(|s| format!(" in {s}"))
            .unwrap_or_default();
        Some(format!(
            "{} of {} active users and computers{scope} can abuse this ({:.2}%)",
            e.principals, e.population, e.percent
        ))
    }
}

pub(crate) fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_incomplete_events() {
        assert!(
            Doc::from_event(r#"{"schema":"pathwarden.event.v1","run":{},"findings":[]}"#).is_ok()
        );
        for bad in [
            r#"{"schema":"pathwarden.event.v1"}"#,
            r#"{"schema":"other","findings":[]}"#,
            r#"{"schema":"pathwarden.event.v1","findings":[{"rule":"PW-1"}]}"#,
            "not json",
        ] {
            assert!(Doc::from_event(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn rule_titles_come_from_guides() {
        let mut d = Doc::default();
        d.guides
            .insert("PW-003".into(), "# PW-003: Dangerous rights\n\ntext".into());
        d.guides.insert("PW-009".into(), "no heading".into());
        assert_eq!(d.rule_title("PW-003"), "Dangerous rights");
        assert_eq!(d.rule_title("PW-009"), "PW-009");
        assert_eq!(d.rule_title("PC-A-X"), "PC-A-X");
        d.rule_titles.insert("PW-003".into(), "Set".into());
        assert_eq!(d.rule_title("PW-003"), "Set");
    }
}
