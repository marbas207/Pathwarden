//! SARIF 2.1.0 (OASIS Standard, Errata 01).
//!
//! | Pathwarden | SARIF |
//! |---|---|
//! | rule (with its guide) | `tool.driver.rules[]`: `shortDescription`, `help.text` / `help.markdown`, `helpUri` |
//! | finding | `results[]`, `kind: "fail"` |
//! | fingerprint | `partialFingerprints["pathwardenFingerprint/v1"]` |
//! | severity | `level`: critical and high `error`, medium `warning`, low and info `note`; also `properties.security-severity` on the rule |
//! | accepted risk | `suppressions: [{kind: "external", status: "accepted", justification}]` |
//! | change since the last run | `baselineState`: new and regressed `new`, open and suppressed `unchanged` |
//! | affected objects | `locations[].logicalLocations[]` (no files: AD objects have none) |
//!
//! Results carry no physical location, which SARIF allows. Tools that need
//! one (GitHub code scanning) are not a target; see docs/integrations.md.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::doc::{severity_rank, Doc, Finding};
use crate::HOMEPAGE;

pub const SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
/// The `partialFingerprints` key holding the finding fingerprint.
pub const FINGERPRINT_KEY: &str = "pathwardenFingerprint/v1";
/// Affected objects listed as logical locations per result.
const LOCATIONS_MAX: usize = 25;

/// SARIF level for a severity.
pub fn level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// The `security-severity` score (0.0-10.0) vulnerability platforms read
/// from a rule's properties: the CVSS bands (critical 9.0+, high 7.0-8.9,
/// medium 4.0-6.9, low 0.1-3.9).
fn security_severity(severity: &str) -> &'static str {
    match severity {
        "critical" => "9.5",
        "high" => "8.0",
        "medium" => "5.5",
        "low" => "3.0",
        _ => "0.0",
    }
}

fn baseline_state(change: Option<&str>) -> Option<&'static str> {
    match change? {
        "new" | "regressed" => Some("new"),
        "open" | "suppressed" => Some("unchanged"),
        _ => None,
    }
}

/// The SARIF log for a run's findings.
pub fn sarif(doc: &Doc) -> Value {
    // Rules in ID order, each with the worst severity among its findings.
    let mut worst: BTreeMap<&str, &'static str> = BTreeMap::new();
    for f in &doc.findings {
        let s = f.severity_key();
        let e = worst.entry(f.rule.as_str()).or_insert(s);
        if severity_rank(s) > severity_rank(e) {
            *e = s;
        }
    }
    let index: BTreeMap<&str, usize> = worst.keys().enumerate().map(|(i, r)| (*r, i)).collect();
    let rules: Vec<Value> = worst
        .iter()
        .map(|(rule, sev)| rule_object(doc, rule, sev))
        .collect();
    let results: Vec<Value> = doc
        .findings
        .iter()
        .map(|f| result_object(f, index[f.rule.as_str()]))
        .collect();

    let mut driver = Map::new();
    driver.insert("name".into(), "Pathwarden".into());
    driver.insert("informationUri".into(), HOMEPAGE.into());
    if !doc.tool_version.is_empty() {
        driver.insert("version".into(), doc.tool_version.clone().into());
    }
    driver.insert("rules".into(), rules.into());

    let mut run = Map::new();
    run.insert("tool".into(), json!({ "driver": driver }));
    if !doc.run_id.is_empty() {
        // `category/runId`: one category, so successive runs compare.
        run.insert(
            "automationDetails".into(),
            json!({ "id": format!("pathwarden/{}", doc.run_id) }),
        );
    }
    run.insert("results".into(), results.into());
    let mut props = Map::new();
    if let Some(when) = doc.when {
        props.insert("collectedAt".into(), crate::timestamp(when).into());
    }
    if !doc.held.is_empty() {
        // Not results (nothing was checked), but not fixed either.
        props.insert("heldFingerprints".into(), json!(doc.held));
    }
    if !props.is_empty() {
        run.insert("properties".into(), Value::Object(props));
    }
    json!({
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [run],
    })
}

fn rule_object(doc: &Doc, rule: &str, worst: &str) -> Value {
    let title = doc.rule_title(rule);
    let mut r = Map::new();
    r.insert("id".into(), rule.into());
    r.insert("shortDescription".into(), json!({ "text": title }));
    match doc.guides.get(rule) {
        Some(guide) => {
            r.insert("help".into(), json!({ "text": guide, "markdown": guide }));
        }
        None => {
            r.insert(
                "help".into(),
                json!({ "text": format!("{title}. See the finding's remediation text.") }),
            );
        }
    }
    if rule.starts_with("PW-") {
        r.insert(
            "helpUri".into(),
            format!("{HOMEPAGE}/blob/main/crates/pathwarden-core/guides/{rule}.md").into(),
        );
    }
    r.insert(
        "defaultConfiguration".into(),
        json!({ "level": level(worst) }),
    );
    let mut tags = vec!["security".to_string(), "active-directory".to_string()];
    if let Some(cat) = doc
        .findings
        .iter()
        .find(|f| f.rule == rule)
        .map(|f| f.category.replace('_', "-"))
        .filter(|c| !c.is_empty())
    {
        tags.push(cat);
    }
    if rule.starts_with("PC-") {
        tags.push("pingcastle".into());
    }
    r.insert(
        "properties".into(),
        json!({ "tags": tags, "security-severity": security_severity(worst) }),
    );
    Value::Object(r)
}

fn result_object(f: &Finding, rule_index: usize) -> Value {
    let sev = f.severity_key();
    let mut text = f.title.clone();
    if !f.summary.trim().is_empty() {
        text.push_str("\n\n");
        text.push_str(f.summary.trim());
    }
    let mut r = Map::new();
    r.insert("ruleId".into(), f.rule.clone().into());
    r.insert("ruleIndex".into(), rule_index.into());
    r.insert("kind".into(), "fail".into());
    r.insert("level".into(), level(sev).into());
    r.insert("message".into(), json!({ "text": text }));
    let locations: Vec<Value> = f
        .affected
        .iter()
        .take(LOCATIONS_MAX)
        .map(|a| {
            let mut l = Map::new();
            l.insert("name".into(), a.name.clone().into());
            if !a.id.is_empty() {
                l.insert("fullyQualifiedName".into(), a.id.clone().into());
            }
            if !a.kind.is_empty() {
                l.insert("kind".into(), a.kind.to_ascii_lowercase().into());
            }
            json!({ "logicalLocations": [l] })
        })
        .collect();
    if !locations.is_empty() {
        r.insert("locations".into(), locations.into());
    }
    r.insert(
        "partialFingerprints".into(),
        json!({ FINGERPRINT_KEY: f.fingerprint }),
    );
    if let Some(b) = baseline_state(f.change.as_deref()) {
        r.insert("baselineState".into(), b.into());
    }
    // An empty array says "not suppressed"; absent would mean "unknown".
    let suppressions = if f.is_suppressed() {
        json!([{
            "kind": "external",
            "status": "accepted",
            "justification": f.suppression_reason(),
        }])
    } else {
        json!([])
    };
    r.insert("suppressions".into(), suppressions);

    let mut p = Map::new();
    p.insert("severity".into(), sev.into());
    if let Some(d) = &f.severity_default {
        p.insert(
            "severityDefault".into(),
            d.trim().to_ascii_lowercase().into(),
        );
    }
    if !f.category.is_empty() {
        p.insert("category".into(), f.category.clone().into());
    }
    if let Some(d) = &f.domain {
        p.insert("domain".into(), d.clone().into());
    }
    if let Some(c) = &f.change {
        p.insert("change".into(), c.clone().into());
    }
    if let Some(t) = f.first_seen {
        p.insert("firstSeen".into(), crate::timestamp(t).into());
    }
    if let Some(n) = f.times_seen {
        p.insert("timesSeen".into(), n.into());
    }
    if let Some(e) = &f.exposure {
        p.insert(
            "exposure".into(),
            json!({ "principals": e.principals, "population": e.population, "percent": e.percent }),
        );
    }
    if let Some(line) = f.path_line() {
        p.insert("attackPath".into(), line.into());
    }
    p.insert("affectedCount".into(), f.affected.len().into());
    if !f.remediation.is_empty() {
        p.insert("remediation".into(), f.remediation.clone().into());
    }
    if !f.references.is_empty() {
        p.insert("references".into(), f.references.clone().into());
    }
    if !f.sources.is_empty() {
        p.insert("sources".into(), f.sources.clone().into());
    }
    r.insert("properties".into(), Value::Object(p));
    Value::Object(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(level("critical"), "error");
        assert_eq!(level("high"), "error");
        assert_eq!(level("medium"), "warning");
        assert_eq!(level("low"), "note");
        assert_eq!(level("info"), "note");
        assert_eq!(baseline_state(Some("regressed")), Some("new"));
        assert_eq!(baseline_state(Some("open")), Some("unchanged"));
        assert_eq!(baseline_state(None), None);
    }
}
