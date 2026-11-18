//! The exports of a real event document (`pathwarden run -i testdata/forest
//! --event`): SARIF validated against the official OASIS schema, DefectDojo
//! checked against the generic JSON parser's rules.

use std::collections::HashSet;
use std::path::PathBuf;

use pathwarden_export::{defectdojo, sarif, Doc};
use serde_json::Value;

fn event_text() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/event.json"))
        .unwrap()
}

/// The fixture, with the first finding turned into an accepted risk.
fn doc() -> Doc {
    let mut ev: Value = serde_json::from_str(&event_text()).unwrap();
    let f = &mut ev["findings"][0];
    f["change"] = "suppressed".into();
    f["suppressed"] = "Entra Connect sync account, reviewed 2026-09".into();
    Doc::from_event(&ev.to_string()).unwrap()
}

fn schema_validate(instance: &Value) -> Result<(), String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sarif/sarif-schema-2.1.0.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler.enable_format_assertions();
    compiler
        .add_resource(sarif::SCHEMA_URI, schema)
        .map_err(|e| e.to_string())?;
    let idx = compiler
        .compile(sarif::SCHEMA_URI, &mut schemas)
        .map_err(|e| format!("{e:#}"))?;
    schemas
        .validate(instance, idx)
        .map_err(|e| format!("{e:#}"))
}

#[test]
fn sarif_validates_against_the_official_schema() {
    let log = sarif::sarif(&doc());
    schema_validate(&log).unwrap();
    // The schema itself is strict enough to catch a broken log.
    let mut broken = log.clone();
    broken["runs"][0]["results"][0]["level"] = "fatal".into();
    assert!(schema_validate(&broken).is_err());
    let mut broken = log;
    broken["runs"][0]["results"][0]["suppressions"][0]["kind"] = "ignored".into();
    assert!(schema_validate(&broken).is_err());
}

#[test]
fn sarif_maps_rules_results_fingerprints_and_suppressions() {
    let d = doc();
    let log = sarif::sarif(&d);
    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "Pathwarden");
    assert_eq!(
        run["automationDetails"]["id"],
        format!("pathwarden/{}", d.run_id)
    );
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let distinct: HashSet<&str> = d.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rule_ids.len(), distinct.len(), "one rule per rule ID");
    for r in rules {
        let id = r["id"].as_str().unwrap();
        // Help text is the step-by-step guide.
        assert_eq!(r["help"]["markdown"], d.guides[id].as_str(), "{id}");
        assert!(r["help"]["text"].as_str().unwrap().contains("## Fix"));
        assert!(!r["shortDescription"]["text"]
            .as_str()
            .unwrap()
            .starts_with("PW-"));
        assert!(r["helpUri"]
            .as_str()
            .unwrap()
            .ends_with(&format!("{id}.md")));
    }

    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), d.findings.len());
    for (res, f) in results.iter().zip(&d.findings) {
        assert_eq!(
            res["partialFingerprints"][sarif::FINGERPRINT_KEY],
            f.fingerprint.as_str()
        );
        let idx = res["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], f.rule.as_str());
        assert_eq!(res["level"], sarif::level(f.severity_key()));
        assert!(res["message"]["text"]
            .as_str()
            .unwrap()
            .starts_with(&f.title));
    }
    // The accepted risk is a suppression; the rest say "not suppressed".
    assert_eq!(results[0]["suppressions"][0]["kind"], "external");
    assert_eq!(results[0]["suppressions"][0]["status"], "accepted");
    assert_eq!(
        results[0]["suppressions"][0]["justification"],
        "Entra Connect sync account, reviewed 2026-09"
    );
    assert_eq!(results[0]["baselineState"], "unchanged");
    assert_eq!(results[1]["suppressions"], Value::Array(vec![]));
    assert_eq!(results[1]["baselineState"], "new");
    // Severity bands: the critical finding is an error.
    assert!(results
        .iter()
        .any(|r| r["level"] == "error" && r["properties"]["severity"] == "critical"));
}

#[test]
fn defectdojo_report_fits_the_generic_parser() {
    let d = doc();
    let report = defectdojo::defectdojo(&d);
    assert_eq!(report["type"], defectdojo::TEST_TYPE);
    let allowed: HashSet<&str> = defectdojo::ALLOWED_KEYS.iter().copied().collect();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), d.findings.len());
    let mut ids = HashSet::new();
    for (out, f) in findings.iter().zip(&d.findings) {
        let obj = out.as_object().unwrap();
        for key in obj.keys() {
            assert!(allowed.contains(key.as_str()), "not allowed: {key}");
        }
        for key in ["title", "severity", "description"] {
            assert!(obj[key].as_str().is_some_and(|s| !s.is_empty()), "{key}");
        }
        assert!(["Critical", "High", "Medium", "Low", "Info"]
            .contains(&obj["severity"].as_str().unwrap()));
        assert!(obj["title"].as_str().unwrap().chars().count() <= 511);
        assert_eq!(obj["unique_id_from_tool"], f.fingerprint.as_str());
        assert_eq!(obj["vuln_id_from_tool"], f.rule.as_str());
        // Booleans must be JSON booleans; tags a list.
        for key in ["active", "static_finding", "dynamic_finding"] {
            assert!(obj[key].is_boolean(), "{key}");
        }
        assert!(obj["tags"].is_array());
        assert!(ids.insert(f.fingerprint.clone()), "unique IDs repeat");
        // `date` is a plain day (first seen).
        let date = obj["date"].as_str().unwrap();
        assert_eq!(date.len(), 10, "{date}");
    }
    assert_eq!(findings[0]["risk_accepted"], true);
    assert_eq!(findings[0]["active"], false);
    assert_eq!(findings[1]["active"], true);
    assert!(findings[1].get("risk_accepted").is_none());
    // The guide is part of the mitigation.
    assert!(findings[1]["mitigation"]
        .as_str()
        .unwrap()
        .contains("## Verify"));
}

/// DefectDojo's default deduplication for this format hashes the title and
/// the description: the description must not change while the finding
/// stays (exposure and object lists move to other fields).
#[test]
fn defectdojo_description_is_stable_across_runs() {
    let d1 = doc();
    let mut ev: Value = serde_json::from_str(&event_text()).unwrap();
    for f in ev["findings"].as_array_mut().unwrap() {
        f["change"] = "open".into();
        f["times_seen"] = 7.into();
        if f["exposure"].is_object() {
            f["exposure"]["principals"] = 999.into();
            f["exposure"]["percent"] = 99.9.into();
        }
        f["affected"].as_array_mut().unwrap().truncate(1);
        f["summary"] = "changed summary".into();
    }
    let d2 = Doc::from_event(&ev.to_string()).unwrap();
    let (r1, r2) = (defectdojo::defectdojo(&d1), defectdojo::defectdojo(&d2));
    for (a, b) in r1["findings"]
        .as_array()
        .unwrap()
        .iter()
        .zip(r2["findings"].as_array().unwrap())
    {
        assert_eq!(a["description"], b["description"]);
        assert_eq!(a["unique_id_from_tool"], b["unique_id_from_tool"]);
        assert_eq!(a["date"], b["date"]);
    }
}

/// A finding whose rule's severity the team set: `severity` is the
/// set one; the default is added beside it, and only then.
#[test]
fn a_set_severity_carries_its_default() {
    let mut ev: Value = serde_json::from_str(&event_text()).unwrap();
    ev["findings"][0]["severity"] = "low".into();
    ev["findings"][0]["severity_default"] = "high".into();
    let d = Doc::from_event(&ev.to_string()).unwrap();
    let log = sarif::sarif(&d);
    schema_validate(&log).unwrap();
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results[0]["properties"]["severity"], "low");
    assert_eq!(results[0]["properties"]["severityDefault"], "high");
    assert!(results[1]["properties"].get("severityDefault").is_none());
    let dd = defectdojo::defectdojo(&d);
    let f = dd["findings"].as_array().unwrap();
    assert_eq!(f[0]["severity"], "Low");
    assert!(f[0]["severity_justification"]
        .as_str()
        .unwrap()
        .starts_with("Severity set by your team. The default is High."));
    assert!(!f[1]["severity_justification"]
        .as_str()
        .unwrap_or_default()
        .contains("set by your team"));
}

/// The fixture, with records finding actions keep on its first finding.
fn doc_with_records() -> Doc {
    let mut ev: Value = serde_json::from_str(&event_text()).unwrap();
    ev["findings"][0]["actions"] = serde_json::json!({
        "records": [{
            "action": "service-desk/open", "id": "sys-1", "kind": "ticket",
            "number": "RITM10816190", "status": "Open", "open": true,
            "url": "https://desk.example.com/RITM10816190",
            "fields": { "Queue": "Identity" },
            "by": "NORTH\\eddard.stark", "on": "SECOPS-WS02",
            "at": "2026-11-18T14:02:11.000Z", "updated_at": "2026-11-18T14:02:11.000Z"
        }],
        "activity_count": 2
    });
    Doc::from_event(&ev.to_string()).unwrap()
}

/// Records finding actions keep travel as SARIF properties and DefectDojo
/// references; a finding without any has neither.
#[test]
fn action_records_travel_in_both_exports() {
    let d = doc_with_records();
    let log = sarif::sarif(&d);
    schema_validate(&log).unwrap();
    let results = log["runs"][0]["results"].as_array().unwrap();
    let p = &results[0]["properties"];
    assert_eq!(p["actionRuns"], 2);
    assert_eq!(
        p["actionRecords"],
        serde_json::json!([{
            "action": "service-desk/open", "id": "sys-1", "kind": "ticket",
            "number": "RITM10816190", "status": "Open",
            "url": "https://desk.example.com/RITM10816190", "open": true
        }])
    );
    assert!(results[1]["properties"].get("actionRecords").is_none());
    let dojo = defectdojo::defectdojo(&d);
    let refs = dojo["findings"][0]["references"].as_str().unwrap();
    assert!(
        refs.ends_with("Record RITM10816190 · Open: https://desk.example.com/RITM10816190"),
        "{refs}"
    );
}
