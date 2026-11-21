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

/// A ticket an output plugin reported: a chip like an action's record,
/// no follow-ups (no `[[action]]` block made it), its activity named by
/// the plugin, and while it is open the `once` action isn't offered.
#[test]
fn a_plugins_ticket_shows_without_follow_ups_and_hides_once() {
    let c = Config::parse("[[action]]\nplugin = \"desk\"\n").unwrap();
    let (d, _) = parse_describe(
        br#"{"schema":"pathwarden.action-describe.v1","actions":[
          {"id":"open","label":"Open","sends":"x","once":true,"follow_ups":["status"]},
          {"id":"status","label":"Status","sends":"x","for":"record"},
          {"id":"note","label":"Note","sends":"x"}]}"#,
    )
    .unwrap();
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
    let reported = |fp: &str, open: bool| pathwarden_core::output_result::OutputRecord {
        fingerprint: fp.into(),
        record: Record {
            id: format!("sys-{fp}"),
            kind: Some("ticket".into()),
            number: Some("INC0012345".into()),
            url: Some("https://contoso.service-now.com/incident.do?sys_id=1".into()),
            status: Some(if open { "Open" } else { "Resolved" }.into()),
            open,
            ..Record::default()
        },
    };
    for c in action_log::plugin_changes(
        &file,
        "plugin:servicenow",
        "ServiceNow plugin",
        &[reported("PW-001-aaaa", true), reported("PW-003-cccc", true)],
        &|_| true,
        &Actor {
            user: Some(r"CORP\svc-pathwarden".into()),
            computer: Some("PW01".into()),
        },
        "2026-11-21T10:00:00.000Z",
        Some("R2"),
    ) {
        c.apply(&mut file);
    }
    let v = view(&file, &programs, open);
    assert_eq!(
        v.offered,
        ["desk/note"],
        "once is hidden by the open ticket"
    );
    assert_eq!(v.records[0].chip, "INC0012345 · Open");
    assert!(v.records[0].follow_ups.is_empty());
    assert!(
        v.activity[0]
            .line
            .starts_with(r"ServiceNow plugin: INC0012345 · Open · CORP\svc-pathwarden, PW01, "),
        "{}",
        v.activity[0].line
    );
    let v = view(&file, &programs, fixed);
    assert_eq!(v.records[0].chip, "Fixed · INC0012345 still Open");
    assert!(v.records[0].follow_ups.is_empty());
}
