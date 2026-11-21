use super::*;
use pathwarden_core::action_log::{ActionsFile, Change};
use pathwarden_core::actions::{parse_describe, Record};
use pathwarden_core::config::Config;
use serde_json::json;

/// What a page reads for a fixed finding with an open ticket: no action
/// but the follow-ups on its record, the "Fixed — … still Open" chip,
/// and the Activity lines.
#[test]
fn a_fixed_findings_view_offers_its_follow_ups() {
    let c = Config::parse("[[action]]\nplugin = \"desk\"\n").unwrap();
    let (d, problems) = parse_describe(
        br#"{"schema":"pathwarden.action-describe.v1","actions":[
          {"id":"open","label":"Open","sends":"x","once":true,"follow_ups":["status","close"]},
          {"id":"status","label":"Status","sends":"x","for":"record"},
          {"id":"close","label":"Close","sends":"x","for":"record","when":"fixed"}]}"#,
    )
    .unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    let programs = [Program {
        config: &c.actions[0],
        describe: &d,
    }];
    let event = json!({
        "schema": "pathwarden.event.v1",
        "run": { "run_id": "R2" },
        "findings": [ { "rule": "PW-001", "fingerprint": "PW-001-aaaa", "title": "Open one",
                        "severity": "high", "category": "attack_path" } ],
        "resolved": [ { "fingerprint": "PW-003-cccc", "rule": "PW-003", "severity": "high",
                        "first_seen": 1, "resolved_at": 2 } ],
    });
    let all = actions::findings_in_event(&event);
    let (open, fixed) = (&all[0], &all[1]);
    let mut file = ActionsFile::default();
    let ticket = ActionRecord {
        action: "desk/open".into(),
        record: Record {
            id: "t-1".into(),
            number: Some("RITM10816190".into()),
            status: Some("Open".into()),
            open: true,
            ..Record::default()
        },
        by: Some(r"NORTH\eddard.stark".into()),
        on: Some("SECOPS-WS02".into()),
        at: "2026-11-18T14:02:11.000Z".into(),
        updated_at: "2026-11-18T14:02:11.000Z".into(),
    };
    Change {
        fingerprint: "PW-003-cccc".into(),
        activity: Activity {
            at: "2026-11-18T14:02:11.000Z".into(),
            by: Some(r"NORTH\eddard.stark".into()),
            on: Some("SECOPS-WS02".into()),
            action: "desk/open".into(),
            label: "Open".into(),
            ok: true,
            message: "Opened RITM10816190.".into(),
            record_ids: vec!["t-1".into()],
            ..Activity::default()
        },
        records: vec![ticket],
        removed: Vec::new(),
    }
    .apply(&mut file);

    let v = view(&file, &programs, fixed);
    assert!(v.offered.is_empty(), "{:?}", v.offered);
    assert_eq!(v.records.len(), 1);
    assert_eq!(v.records[0].chip, "Fixed · RITM10816190 still Open");
    // The follow-up meant for a fixed finding comes first.
    assert_eq!(v.records[0].follow_ups, ["desk/close", "desk/status"]);
    assert_eq!(v.activity_count, 1);
    assert!(
        v.activity[0]
            .line
            .starts_with(r"Opened RITM10816190 · NORTH\eddard.stark, SECOPS-WS02, "),
        "{}",
        v.activity[0].line
    );
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["records"][0]["number"], "RITM10816190");
    assert_eq!(j["records"][0]["chip"], "Fixed · RITM10816190 still Open");
    assert_eq!(j["activity"][0]["action"], "desk/open");
    // An open finding without records: its action, nothing else.
    let v = view(&file, &programs, open);
    assert_eq!(v.offered, ["desk/open"]);
    assert!(v.records.is_empty() && v.activity.is_empty());
}
