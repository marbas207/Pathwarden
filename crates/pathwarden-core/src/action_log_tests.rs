use super::*;
use crate::actions::Ended;

fn who(user: &str, computer: &str) -> Actor {
    Actor {
        user: Some(user.into()),
        computer: Some(computer.into()),
    }
}

fn ticket(id: &str, status: &str, open: bool) -> Record {
    Record {
        id: id.into(),
        kind: Some("ticket".into()),
        number: Some("RITM10816190".into()),
        status: Some(status.into()),
        open,
        url: Some("https://desk.example.com/RITM10816190".into()),
        ..Record::default()
    }
}

fn outcome(ok: bool, message: &str, records: Vec<Record>, dry_run: bool) -> Outcome {
    Outcome {
        ok,
        message: message.into(),
        links: Vec::new(),
        records,
        progress: Vec::new(),
        details: String::new(),
        problems: Vec::new(),
        ended: Ended::Exited,
        status: "exit code 0".into(),
        dry_run,
    }
}

const FP: &str = "PW-001-8ae0b31a46eacada";

/// A run of `service-desk/open` on [`FP`] at `at` that opened a ticket.
fn opened(file: &ActionsFile, at: &str, by: &Actor) -> Change {
    run_change(
        file.findings.get(FP),
        FP,
        "service-desk/open",
        "Open a service request",
        None,
        &outcome(
            true,
            "Opened RITM10816190.",
            vec![ticket("sys-1", "Open", true)],
            false,
        ),
        Some("20261118T140200.000Z"),
        by,
        at,
    )
    .unwrap()
}

#[test]
fn the_file_reads_back_the_same() {
    let mut f = ActionsFile::default();
    opened(
        &f,
        "2026-11-18T14:02:11.000Z",
        &who(r"NORTH\eddard.stark", "SECOPS-WS02"),
    )
    .apply(&mut f);
    let bytes = f.to_bytes();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.starts_with("{\n  \"version\": 1,"), "{text}");
    assert!(text.contains("\"action\": \"service-desk/open\""), "{text}");
    // A run's entry has no `kind`; dry_run is always there, false.
    assert!(!text.contains("\"kind\": \"run\""), "{text}");
    assert!(text.contains("\"dry_run\": false"), "{text}");
    assert_eq!(parse(&bytes).unwrap(), f);
    // Fields a later release of version 1 adds are kept as they are.
    let later = br#"{"version":1,"soon":{"a":1},"findings":{"PW-001-x":{"activity":[{"at":"2026-11-18T14:02:11.000Z","action":"a/b","colour":"red"}],"records":[],"pinned":true}}}"#;
    let f = parse(later).unwrap();
    let again: Value = serde_json::from_slice(&f.to_bytes()).unwrap();
    assert_eq!(again["soon"]["a"], 1);
    assert_eq!(again["findings"]["PW-001-x"]["pinned"], true);
    assert_eq!(
        again["findings"]["PW-001-x"]["activity"][0]["colour"],
        "red"
    );
    // Without a version it is version 1; a BOM is fine.
    let f = parse(b"\xef\xbb\xbf{\"findings\":{}}").unwrap();
    assert_eq!(f.version, 1);
}

#[test]
fn a_newer_or_damaged_file_is_refused() {
    assert_eq!(
        parse(br#"{"version":2,"findings":{}}"#),
        Err(LogError::Newer(2))
    );
    assert_eq!(LogError::Newer(2).to_string(), NEWER_WORDS);
    for bad in [
        &b"not json"[..],
        b"[]",
        br#"{"version":0}"#,
        br#"{"version":"1"}"#,
    ] {
        assert!(
            matches!(parse(bad), Err(LogError::Damaged(_))),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// The latest 100 runs of a finding are kept, oldest first.
#[test]
fn a_finding_keeps_its_latest_activity() {
    let mut f = ActionsFile::default();
    let me = who("NORTH\\ed", "WS");
    for i in 0..(MAX_ACTIVITY + 5) {
        let at = at_of_ms(1_795_010_520_000 + i as i64 * 1000);
        opened(&f, &at, &me).apply(&mut f);
    }
    let log = &f.findings[FP];
    assert_eq!(log.activity.len(), MAX_ACTIVITY);
    assert_eq!(log.activity[0].at, at_of_ms(1_795_010_520_000 + 5_000));
    assert!(log.activity.windows(2).all(|w| w[0].at < w[1].at));
    // One record, made by the first run, changed by the last.
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].at, at_of_ms(1_795_010_520_000));
    assert_eq!(
        log.records[0].updated_at,
        at_of_ms(1_795_010_520_000 + (MAX_ACTIVITY as i64 + 4) * 1000)
    );
    // What a finding carries: every record, the count, the latest 20.
    let a = f.for_finding(FP).unwrap();
    assert_eq!(a.activity_count, MAX_ACTIVITY);
    assert_eq!(a.activity.len(), REPORT_ACTIVITY);
    assert_eq!(a.activity[0].at, log.activity.last().unwrap().at);
    assert!(f.for_finding("PW-002-none").is_none());
    let v = serde_json::to_value(&a).unwrap();
    assert!(v.get("activity").is_none(), "{v}");
    assert_eq!(v["activity_count"], MAX_ACTIVITY);
    assert_eq!(v["records"][0]["number"], "RITM10816190");
}

#[test]
fn milliseconds_keep_runs_of_one_second_apart() {
    assert_eq!(at_of_ms(1_795_010_531_007), "2026-11-18T14:02:11.007Z");
    assert_eq!(
        crate::time::parse_rfc3339(&at_of_ms(1_795_010_531_007)),
        Some(1_795_010_531)
    );
    assert!(now_at().ends_with('Z') && now_at().len() == 24);
}

#[test]
fn a_dry_run_is_not_kept() {
    let o = outcome(
        true,
        "Would open one.",
        vec![ticket("sys-1", "Open", true)],
        true,
    );
    assert!(run_change(None, FP, "a/b", "B", None, &o, None, &Actor::default(), "x").is_none());
}

/// A follow-up's result updates the record it ran on (same block, same
/// ID): its status changes, who first made it stays, the entry names it.
#[test]
fn a_follow_up_updates_its_record() {
    let mut f = ActionsFile::default();
    let ned = who(r"NORTH\eddard.stark", "SECOPS-WS02");
    let arya = who(r"NORTH\arya.stark", "SECOPS-WS07");
    opened(&f, "2026-11-18T14:02:11.000Z", &ned).apply(&mut f);
    let parent = f.findings[FP].records[0].clone();
    let c = run_change(
        f.findings.get(FP),
        FP,
        "service-desk/status",
        "Check status",
        Some(&parent),
        &outcome(
            true,
            "Closed.",
            vec![ticket("sys-1", "Closed", false)],
            false,
        ),
        None,
        &arya,
        "2026-11-19T09:00:00.000Z",
    )
    .unwrap();
    c.apply(&mut f);
    let log = &f.findings[FP];
    assert_eq!(log.records.len(), 1, "{:?}", log.records);
    let r = &log.records[0];
    assert_eq!(r.action, "service-desk/open");
    assert_eq!(r.record.status.as_deref(), Some("Closed"));
    assert!(!r.record.open);
    assert_eq!(r.by.as_deref(), Some(r"NORTH\eddard.stark"));
    assert_eq!(r.at, "2026-11-18T14:02:11.000Z");
    assert_eq!(r.updated_at, "2026-11-19T09:00:00.000Z");
    let last = log.activity.last().unwrap();
    assert_eq!(last.action, "service-desk/status");
    assert_eq!(last.record_ids, ["sys-1"]);
    assert_eq!(last.by.as_deref(), Some(r"NORTH\arya.stark"));
    // A follow-up that returns a new record files it under its parent's
    // action; a failed one keeps the record as it was.
    let c = run_change(
        f.findings.get(FP),
        FP,
        "service-desk/status",
        "Check status",
        Some(&parent),
        &outcome(false, "HTTP 500", Vec::new(), false),
        None,
        &arya,
        "2026-11-19T10:00:00.000Z",
    )
    .unwrap();
    assert_eq!(c.activity.record_ids, ["sys-1"]);
    c.apply(&mut f);
    assert_eq!(
        f.findings[FP].records[0].record.status.as_deref(),
        Some("Closed")
    );
    // Another block's record of the same ID is a record of its own.
    let c = run_change(
        f.findings.get(FP),
        FP,
        "teams/alert",
        "Alert",
        None,
        &outcome(true, "Sent.", vec![ticket("sys-1", "Sent", false)], false),
        None,
        &arya,
        "2026-11-19T11:00:00.000Z",
    )
    .unwrap();
    c.apply(&mut f);
    let actions: Vec<&str> = f.findings[FP]
        .records
        .iter()
        .map(|r| r.action.as_str())
        .collect();
    assert_eq!(actions, ["service-desk/open", "teams/alert"]);
}

/// A removal takes the record out and is itself activity.
#[test]
fn a_removal_is_logged() {
    let mut f = ActionsFile::default();
    let ned = who(r"NORTH\eddard.stark", "SECOPS-WS02");
    opened(&f, "2026-11-18T14:02:11.000Z", &ned).apply(&mut f);
    let r = f.findings[FP].records[0].clone();
    let c = remove_change(FP, &r, &ned, "2026-11-20T08:00:00.000Z");
    c.apply(&mut f);
    c.apply(&mut f);
    let log = &f.findings[FP];
    assert!(log.records.is_empty());
    assert_eq!(log.activity.len(), 2);
    let e = &log.activity[1];
    assert_eq!(e.kind, Kind::Remove);
    assert_eq!(e.record_ids, ["sys-1"]);
    assert_eq!(e.summary(), "Removed RITM10816190");
    let v = serde_json::to_value(e).unwrap();
    assert_eq!(v["kind"], "remove");
    // The finding still carries its activity.
    let a = f.for_finding(FP).unwrap();
    assert!(a.records.is_empty());
    assert_eq!(a.activity_count, 2);
}

/// Two histories that both changed: finding by finding, the union of the
/// activity, and per record the newer update.
#[test]
fn two_sides_merge_finding_by_finding() {
    let ned = who(r"NORTH\eddard.stark", "SECOPS-WS02");
    let arya = who(r"NORTH\arya.stark", "SECOPS-WS07");
    let mut base = ActionsFile::default();
    opened(&base, "2026-11-18T14:00:00.000Z", &ned).apply(&mut base);
    // Each side adds a run on the same finding, and one on a finding of
    // its own; one side changed the record later.
    let (mut a, mut b) = (base.clone(), base.clone());
    opened(&a, "2026-11-18T15:00:00.000Z", &ned).apply(&mut a);
    let mut other = opened(&b, "2026-11-18T15:00:00.000Z", &arya);
    other.records[0].record.status = Some("In progress".into());
    other.records[0].updated_at = "2026-11-18T16:00:00.000Z".into();
    other.apply(&mut b);
    let elsewhere = |file: &ActionsFile, fp: &str, at: &str, by: &Actor| Change {
        fingerprint: fp.into(),
        ..opened(file, at, by)
    };
    elsewhere(&a, "PW-011-aaaa", "2026-11-18T15:30:00.000Z", &ned).apply(&mut a);
    elsewhere(&b, "PW-011-bbbb", "2026-11-18T15:30:00.000Z", &arya).apply(&mut b);
    let mut merged = a.clone();
    merge(&mut merged, &b);
    assert_eq!(
        merged.findings.keys().collect::<Vec<_>>(),
        [FP, "PW-011-aaaa", "PW-011-bbbb"]
    );
    let log = &merged.findings[FP];
    // The shared first entry once; both 15:00 entries (by differs).
    assert_eq!(log.activity.len(), 3, "{:?}", log.activity);
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].record.status.as_deref(), Some("In progress"));
    assert_eq!(log.records[0].at, "2026-11-18T14:00:00.000Z");
    // The same the other way round.
    let mut back = b.clone();
    merge(&mut back, &a);
    assert_eq!(back.findings[FP].records, log.records);
    assert_eq!(back.findings[FP].activity.len(), 3);
    // Merging twice is merging once.
    let again = merged.clone();
    merge(&mut merged, &again);
    assert_eq!(merged, again);
}

#[test]
fn chips_and_lines_read_as_the_mock_up() {
    let open = ticket("sys-1", "Open", true);
    assert_eq!(chip(&open, false), "RITM10816190 · Open");
    assert_eq!(chip(&open, true), "Fixed — RITM10816190 still Open");
    let closed = ticket("sys-1", "Closed", false);
    assert_eq!(chip(&closed, true), "RITM10816190 · Closed");
    let bare = Record {
        id: "x-1".into(),
        open: true,
        ..Record::default()
    };
    assert_eq!(chip(&bare, false), "x-1 · Open");
    let e = Activity {
        at: "2026-11-18T14:02:11.000Z".into(),
        by: Some(r"NORTH\eddard.stark".into()),
        on: Some("SECOPS-WS02".into()),
        action: "service-desk/open".into(),
        label: "Open a service request".into(),
        ok: true,
        message: "Opened RITM10816190.\nIt goes to the review team.".into(),
        ..Activity::default()
    };
    let when = crate::time::format_local(1_795_010_531);
    assert_eq!(
        e.line(),
        format!(r"Opened RITM10816190 — NORTH\eddard.stark, SECOPS-WS02, {when}")
    );
    let failed = Activity {
        ok: false,
        message: "The desk said no.".into(),
        ..e.clone()
    };
    assert_eq!(
        failed.summary(),
        "Open a service request failed: The desk said no"
    );
    let quiet = Activity {
        message: String::new(),
        by: None,
        ..e
    };
    assert_eq!(quiet.summary(), "Open a service request");
    assert_eq!(quiet.who_when(), format!("SECOPS-WS02, {when}"));
}

#[test]
fn findings_and_fixed_ones_carry_what_actions_did() {
    let mut f = ActionsFile::default();
    opened(&f, "2026-11-18T14:02:11.000Z", &who("a", "b")).apply(&mut f);
    let mut findings = vec![
        crate::findings::Finding::new("PW-001", crate::findings::Severity::High, &["a"], "x"),
        crate::findings::Finding::new("PW-001", crate::findings::Severity::High, &["b"], "y"),
    ];
    findings[0].fingerprint = FP.into();
    let mut resolved = vec![crate::state::Resolved {
        fingerprint: FP.into(),
        rule: "PW-001".into(),
        severity: crate::findings::Severity::High,
        first_seen: 0,
        resolved_at: 1,
        title: None,
        actions: None,
    }];
    annotate(&f, &mut findings, &mut resolved);
    assert_eq!(findings[0].actions.as_ref().unwrap().records.len(), 1);
    assert!(findings[1].actions.is_none());
    let v = serde_json::to_value(&findings[0]).unwrap();
    assert_eq!(v["actions"]["activity_count"], 1);
    assert_eq!(v["actions"]["records"][0]["action"], "service-desk/open");
    assert!(serde_json::to_value(&findings[1])
        .unwrap()
        .get("actions")
        .is_none());
    let v = serde_json::to_value(&resolved[0]).unwrap();
    assert_eq!(v["actions"]["records"][0]["id"], "sys-1");
}

/// Fields a later release of v1 adds to a record or an activity entry,
/// and a `kind` this version doesn't know, are kept as they are: the
/// file stays readable, and is written back the same.
#[test]
fn a_later_v1s_fields_and_kinds_are_kept() {
    let later = br#"{"version":1,"findings":{"PW-001-x":{
        "activity":[{"at":"2026-11-18T14:02:11.000Z","action":"a/b","label":"Escalate","ok":true,
                     "message":"Escalated.","kind":"escalate","priority":2}],
        "records":[{"action":"a/b","id":"t-1","open":true,"sla":"4h","by":"ned",
                    "at":"2026-11-18T14:02:11.000Z","updated_at":"2026-11-18T14:02:11.000Z"}]}}}"#;
    let f = parse(later).unwrap();
    let log = &f.findings["PW-001-x"];
    assert_eq!(log.activity[0].kind, Kind::Other("escalate".into()));
    assert_eq!(log.activity[0].summary(), "Escalate: Escalated");
    assert_eq!(log.records[0].record.other["sla"], "4h");
    assert_eq!(log.records[0].by.as_deref(), Some("ned"));
    let again: Value = serde_json::from_slice(&f.to_bytes()).unwrap();
    let a = &again["findings"]["PW-001-x"];
    assert_eq!(a["activity"][0]["kind"], "escalate");
    assert_eq!(a["activity"][0]["priority"], 2);
    assert_eq!(a["records"][0]["sla"], "4h");
    assert_eq!(a["records"][0]["action"], "a/b");
    assert!(a["records"][0].get("other").is_none(), "{a}");
    // Merging keeps them too.
    let mut base = ActionsFile::default();
    merge(&mut base, &f);
    assert_eq!(base, f);
}

/// The file is untrusted: links that aren't https are dropped, texts cut
/// to the result's caps, and a file past the cap isn't read.
#[test]
fn the_file_is_read_as_untrusted() {
    let long = "x".repeat(crate::actions::MAX_MESSAGE + 50);
    let text = format!(
        r#"{{"version":1,"findings":{{"PW-001-x":{{
        "activity":[{{"at":"2026-11-18T14:02:11.000Z","action":"a/b","ok":true,"message":"{long}"}}],
        "records":[{{"action":"a/b","id":"t-1","url":"javascript:alert(1)","number":"N\u202e1"}},
                   {{"action":"a/b","id":"t-2","url":"https://desk.example.com/2"}},
                   {{"action":"a/b","id":"t-3","url":"http://desk.example.com/3"}}]}}}}}}"#
    );
    let f = parse(text.as_bytes()).unwrap();
    let log = &f.findings["PW-001-x"];
    assert_eq!(
        log.activity[0].message.chars().count(),
        crate::actions::MAX_MESSAGE
    );
    assert_eq!(log.records[0].record.url, None);
    assert_eq!(log.records[0].record.number.as_deref(), Some("N1"));
    assert_eq!(
        log.records[1].record.url.as_deref(),
        Some("https://desk.example.com/2")
    );
    assert_eq!(log.records[2].record.url, None);
    // What findings carry has no such link either.
    let a = f.for_finding("PW-001-x").unwrap();
    assert!(a.records.iter().all(|r| r
        .record
        .url
        .as_deref()
        .is_none_or(|u| u.starts_with("https://"))));
    let big = vec![b' '; MAX_BYTES as usize + 1];
    match parse(&big) {
        Err(LogError::Damaged(why)) => assert!(why.contains("larger than 16 MiB"), "{why}"),
        other => panic!("{other:?}"),
    }
}

/// A removal wins over any update of the record that started before it,
/// whichever side is merged into which; a record a later run makes anew
/// with the same ID is kept.
#[test]
fn a_removed_record_never_comes_back() {
    let ned = who(r"NORTH\eddard.stark", "SECOPS-WS02");
    let arya = who(r"NORTH\arya.stark", "SECOPS-WS07");
    let mut base = ActionsFile::default();
    opened(&base, "2026-11-18T14:00:00.000Z", &ned).apply(&mut base);
    let r = base.findings[FP].records[0].clone();
    // One computer removes it; another, from the view before that, checks
    // its status a little later.
    let removal = remove_change(FP, &r, &ned, "2026-11-18T15:00:00.000Z");
    let status = run_change(
        base.findings.get(FP),
        FP,
        "service-desk/status",
        "Check status",
        Some(&r),
        &outcome(
            true,
            "Closed.",
            vec![ticket("sys-1", "Closed", false)],
            false,
        ),
        None,
        &arya,
        "2026-11-18T15:05:00.000Z",
    )
    .unwrap();
    let (mut a, mut b) = (base.clone(), base.clone());
    removal.apply(&mut a);
    status.apply(&mut b);
    for (into, from) in [(a.clone(), &b), (b.clone(), &a)] {
        let mut m = into;
        merge(&mut m, from);
        let log = &m.findings[FP];
        assert!(log.records.is_empty(), "{:?}", log.records);
        assert_eq!(log.removed.len(), 1);
        assert_eq!(log.activity.len(), 3);
    }
    // The stale update made on top of the removal (a late save) too.
    let mut late = a.clone();
    status.apply(&mut late);
    assert!(late.findings[FP].records.is_empty());
    // A new run after the removal makes the record anew.
    let anew = opened(&late, "2026-11-19T09:00:00.000Z", &arya);
    anew.apply(&mut late);
    let log = &late.findings[FP];
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].at, "2026-11-19T09:00:00.000Z");
    // And it survives a merge with the side that removed the old one.
    let mut m = a.clone();
    merge(&mut m, &late);
    assert_eq!(m.findings[FP].records.len(), 1);
    // The removal is kept in the file, and reads back.
    let v: Value = serde_json::from_slice(&a.to_bytes()).unwrap();
    assert_eq!(v["findings"][FP]["removed"][0]["id"], "sys-1");
    assert_eq!(
        v["findings"][FP]["removed"][0]["at"],
        "2026-11-18T15:00:00.000Z"
    );
    assert_eq!(parse(&a.to_bytes()).unwrap(), a);
}

/// A run someone stopped is saved as cancelled: not ok, "Cancelled", and
/// `outcome: cancelled`; a cancelled dry run isn't saved.
#[test]
fn a_cancelled_run_is_saved_as_cancelled() {
    let mut o = outcome(
        false,
        "Cancelled: it was stopped before it finished.",
        Vec::new(),
        false,
    );
    o.ended = Ended::Cancelled;
    let c = run_change(
        None,
        FP,
        "a/b",
        "B",
        None,
        &o,
        None,
        &who("a", "b"),
        "2026-11-18T14:00:00.000Z",
    )
    .unwrap();
    assert!(!c.activity.ok);
    assert_eq!(c.activity.message, "Cancelled");
    assert_eq!(c.activity.outcome.as_deref(), Some(CANCELLED));
    assert_eq!(c.activity.summary(), "B failed: Cancelled");
    let v = serde_json::to_value(&c.activity).unwrap();
    assert_eq!(v["outcome"], "cancelled");
    let done = run_change(
        None,
        FP,
        "a/b",
        "B",
        None,
        &outcome(true, "Done.", Vec::new(), false),
        None,
        &who("a", "b"),
        "x",
    )
    .unwrap();
    assert!(serde_json::to_value(&done.activity)
        .unwrap()
        .get("outcome")
        .is_none());
    o.dry_run = true;
    assert!(run_change(None, FP, "a/b", "B", None, &o, None, &who("a", "b"), "x").is_none());
}
