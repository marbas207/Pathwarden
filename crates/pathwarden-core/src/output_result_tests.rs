use super::*;
use crate::action_log::{self, ActionsFile};
use crate::identity::Actor;
use serde_json::json;

fn output(plugin: &str) -> OutputConfig {
    serde_json::from_value(json!({ "plugin": plugin })).unwrap()
}

fn doc(records: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "schema": SCHEMA, "records": records })).unwrap()
}

fn ticket(fp: &str, id: &str, status: &str, open: bool) -> Value {
    json!({
        "fingerprint": fp, "id": id, "kind": "ticket", "number": id.to_uppercase(),
        "url": format!("https://desk.example.com/{id}"), "status": status, "open": open
    })
}

#[test]
fn a_good_result_is_read_as_an_actions_records() {
    let r = parse(&doc(json!([
        ticket("PW-001-aaaa", "inc1", "Open", true),
        ticket("PW-002-bbbb", "inc2", "Resolved", false),
    ])))
    .unwrap();
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.records.len(), 2);
    assert_eq!(r.records[0].fingerprint, "PW-001-aaaa");
    let rec = &r.records[0].record;
    assert_eq!(rec.number.as_deref(), Some("INC1"));
    assert_eq!(rec.url.as_deref(), Some("https://desk.example.com/inc1"));
    assert!(rec.open);
    assert!(!r.records[1].record.open);
}

#[test]
fn a_broken_result_is_refused_whole() {
    for (bytes, says) in [
        (b"{\"schema\": tru".to_vec(), "isn't JSON"),
        (b"[]".to_vec(), "JSON object"),
        (
            br#"{"schema":"pathwarden.output-result.v2","records":[]}"#.to_vec(),
            "isn't \"pathwarden.output-result.v1\"",
        ),
        (
            br#"{"schema":"pathwarden.output-result.v1"}"#.to_vec(),
            "no records list",
        ),
        (
            br#"{"schema":"pathwarden.output-result.v1","records":{}}"#.to_vec(),
            "must be a list",
        ),
    ] {
        let e = parse(&bytes).unwrap_err();
        assert!(e.contains(says), "{e}");
    }
}

/// What can't be kept is left out, never read as HTML, and said.
#[test]
fn bad_records_are_left_out_and_texts_capped() {
    let long = "x".repeat(MAX_RECORD_TEXT + 50);
    let r = parse(&doc(json!([
        { "id": "no-fingerprint", "open": true },
        { "fingerprint": "PW-001-aaaa", "open": true },
        { "fingerprint": "PW-001-aaaa", "id": "a", "url": "http://desk/a", "open": true },
        { "fingerprint": "PW-001-aaaa", "id": "a", "open": false },
        { "fingerprint": "PW-001-aaaa", "id": "b", "status": long, "number": "<b>INC</b>" },
        "a string",
    ])))
    .unwrap();
    assert_eq!(r.records.len(), 2, "{:?}", r.problems);
    assert_eq!(r.records[0].record.url, None, "only https links");
    assert!(r.records[0].record.open, "the first of two with one id");
    let b = &r.records[1].record;
    assert_eq!(b.status.as_ref().unwrap().chars().count(), MAX_RECORD_TEXT);
    // Text stays text: Pathwarden escapes it wherever it shows it.
    assert_eq!(b.number.as_deref(), Some("<b>INC</b>"));
    let all = r.problems.join("\n");
    for says in [
        "records[0].fingerprint is missing",
        "records[1].id is missing",
        "records[2].url",
        "records[3] is there twice",
        "records[4].status is longer",
        "records[5] must be an object",
    ] {
        assert!(all.contains(says), "{says}: {all}");
    }
}

#[test]
fn the_caps_hold() {
    let many: Vec<Value> = (0..MAX_RECORDS + 3)
        .map(|i| ticket(&format!("PW-{i}"), "t", "Open", true))
        .collect();
    let r = parse(&doc(Value::Array(many))).unwrap();
    assert_eq!(r.records.len(), MAX_RECORDS);
    assert!(
        r.problems[0].contains("more than 10000 records"),
        "{:?}",
        r.problems
    );

    let one: Vec<Value> = (0..MAX_PER_FINDING + 2)
        .map(|i| ticket("PW-001-aaaa", &format!("t{i}"), "Open", true))
        .collect();
    let r = parse(&doc(Value::Array(one))).unwrap();
    assert_eq!(r.records.len(), MAX_PER_FINDING);
    assert_eq!(r.problems.len(), 2);

    let big = vec![b' '; MAX_BYTES as usize + 1];
    assert!(parse(&big).unwrap_err().contains("larger than 8 MiB"));

    let problems: Vec<String> = (0..MAX_PROBLEMS + 4).map(|i| format!("p{i}")).collect();
    let line = problems_line(&problems);
    assert!(line.ends_with("; and 4 more"), "{line}");
}

/// No file: nothing, no warning. A broken one: a warning, nothing saved.
/// A good one with problems: its records and a warning.
#[test]
fn the_run_log_says_what_was_wrong() {
    let o = output("servicenow");
    assert_eq!(read_result(&o, None), (None, None));
    let (r, w) = read_result(&o, Some(Ok(b"nope".to_vec())));
    assert!(r.is_none());
    assert!(w.unwrap().contains("wasn't read"));
    let (r, w) = read_result(&o, Some(Err("The result file isn't a plain file.".into())));
    assert!(r.is_none());
    assert!(w.unwrap().contains("isn't a plain file"));
    let (r, w) = read_result(
        &o,
        Some(Ok(doc(json!([
            ticket("PW-1", "inc1", "Open", true),
            { "fingerprint": "PW-2" }
        ])))),
    );
    let r = r.unwrap();
    assert_eq!(r.source, "plugin:servicenow");
    assert_eq!(r.label, "ServiceNow plugin");
    assert_eq!(r.records.len(), 1);
    assert!(w.unwrap().contains("records[1].id is missing"));
}

#[test]
fn sources_and_their_words() {
    assert_eq!(source(&output("jira")), "plugin:jira");
    assert!(is_plugin_source("plugin:jira"));
    assert!(!is_plugin_source("service-desk/open"));
    assert_eq!(source_label("plugin:jira").as_deref(), Some("Jira plugin"));
    assert_eq!(
        source_label("plugin:teams").as_deref(),
        Some("teams plugin")
    );
    assert_eq!(source_label("service-desk/open"), None);
    // No [[action]] block can be named like a plugin's source.
    assert!(!crate::config::valid_plugin_name("plugin:jira"));
    let mut dry = output("jira");
    dry.settings.insert("dry_run".into(), Value::Bool(true));
    assert!(is_dry_run(&dry));
    assert!(!is_dry_run(&output("jira")));
}

#[test]
fn an_events_fingerprints() {
    let fps = event_fingerprints(
        r#"{"findings":[{"fingerprint":"A"}],"resolved":[{"fingerprint":"B"}],"held":[{"fingerprint":"C"}]}"#,
    );
    let mut fps: Vec<String> = fps.into_iter().collect();
    fps.sort();
    assert_eq!(fps, ["A", "B", "C"]);
    assert!(event_fingerprints("not json").is_empty());
}

fn who() -> Actor {
    Actor {
        user: Some("CORP\\svc-pathwarden".into()),
        computer: Some("PW01".into()),
    }
}

fn reported(records: Value) -> Vec<OutputRecord> {
    parse(&doc(records)).unwrap().records
}

fn changes_at(file: &ActionsFile, records: Value, at: &str) -> Vec<action_log::RecordsChange> {
    action_log::plugin_changes(
        file,
        "plugin:servicenow",
        "ServiceNow plugin",
        &reported(records),
        &|fp: &str| fp != "UNKNOWN",
        &who(),
        at,
        Some("R1"),
    )
}

fn apply(file: &mut ActionsFile, changes: &[action_log::RecordsChange]) {
    for c in changes {
        c.apply(file);
    }
}

/// Upserted by source and ID: a new ticket is added with one entry of
/// activity; seen again unchanged, nothing changes (no write, no
/// activity); a new status is an update without activity; closing and
/// reopening are activity.
#[test]
fn plugin_records_are_upserted_without_flooding_activity() {
    let mut file = ActionsFile::default();
    let t1 = "2026-11-21T10:00:00.000Z";
    let c = changes_at(
        &file,
        json!([
            ticket("PW-1", "inc1", "Open", true),
            ticket("UNKNOWN", "inc9", "Open", true)
        ]),
        t1,
    );
    assert_eq!(c.len(), 1, "unknown fingerprints are left out");
    apply(&mut file, &c);
    let log = &file.findings["PW-1"];
    assert_eq!(log.records.len(), 1);
    let r = &log.records[0];
    assert_eq!(r.action, "plugin:servicenow");
    assert_eq!((r.at.as_str(), r.updated_at.as_str()), (t1, t1));
    assert_eq!(r.by.as_deref(), Some("CORP\\svc-pathwarden"));
    assert_eq!(log.activity.len(), 1);
    assert_eq!(log.activity[0].summary(), "ServiceNow plugin: INC1 · Open");
    assert_eq!(log.activity[0].label, "ServiceNow plugin");

    // The next run sees it again: nothing to save.
    let t2 = "2026-11-22T10:00:00.000Z";
    assert!(changes_at(&file, json!([ticket("PW-1", "inc1", "Open", true)]), t2).is_empty());

    // In progress: updated, no activity.
    let c = changes_at(
        &file,
        json!([ticket("PW-1", "inc1", "In Progress", true)]),
        t2,
    );
    assert!(c[0].activity.is_empty());
    apply(&mut file, &c);
    let r = &file.findings["PW-1"].records[0];
    assert_eq!(r.record.status.as_deref(), Some("In Progress"));
    assert_eq!(
        (r.at.as_str(), r.updated_at.as_str()),
        (t1, t2),
        "first made kept"
    );
    assert_eq!(file.findings["PW-1"].activity.len(), 1);

    // Closed, then reopened: one entry each.
    let t3 = "2026-11-23T10:00:00.000Z";
    let c = changes_at(
        &file,
        json!([ticket("PW-1", "inc1", "Resolved", false)]),
        t3,
    );
    apply(&mut file, &c);
    let t4 = "2026-11-24T10:00:00.000Z";
    let c = changes_at(&file, json!([ticket("PW-1", "inc1", "Open", true)]), t4);
    apply(&mut file, &c);
    let summaries: Vec<String> = file.activity("PW-1").iter().map(|a| a.summary()).collect();
    assert_eq!(
        summaries,
        [
            "ServiceNow plugin: Reopened INC1 · Open",
            "ServiceNow plugin: Closed INC1 · Resolved",
            "ServiceNow plugin: INC1 · Open"
        ]
    );
    assert_eq!(file.records("PW-1").len(), 1, "still one record");
}

/// An action's record and a plugin's with the same ID are two records:
/// they are told apart by their source.
#[test]
fn a_plugin_never_overwrites_an_actions_record() {
    let mut file = ActionsFile::default();
    let log = file.findings.entry("PW-1".into()).or_default();
    log.records.push(crate::actions::ActionRecord {
        action: "service-desk/open".into(),
        record: Record {
            id: "inc1".into(),
            open: true,
            ..Record::default()
        },
        by: None,
        on: None,
        at: "2026-11-01T00:00:00.000Z".into(),
        updated_at: "2026-11-01T00:00:00.000Z".into(),
    });
    let c = changes_at(
        &file,
        json!([ticket("PW-1", "inc1", "Closed", false)]),
        "2026-11-21T10:00:00.000Z",
    );
    apply(&mut file, &c);
    let recs = file.records("PW-1");
    assert_eq!(recs.len(), 2);
    assert!(recs[0].record.open, "the action's record is untouched");
    assert_eq!(recs[1].action, "plugin:servicenow");
}

/// Two computers' saves merge as action records do: the newer
/// `updated_at` wins, activity is the union.
#[test]
fn plugin_records_merge_by_source_and_id() {
    let base = {
        let mut f = ActionsFile::default();
        let c = changes_at(
            &f,
            json!([ticket("PW-1", "inc1", "Open", true)]),
            "2026-11-21T10:00:00.000Z",
        );
        apply(&mut f, &c);
        f
    };
    let mut a = base.clone();
    let ca = changes_at(
        &a,
        json!([ticket("PW-1", "inc1", "Resolved", false)]),
        "2026-11-22T10:00:00.000Z",
    );
    apply(&mut a, &ca);
    let mut b = base.clone();
    let cb = changes_at(
        &b,
        json!([ticket("PW-1", "inc1", "In Progress", true)]),
        "2026-11-21T12:00:00.000Z",
    );
    apply(&mut b, &cb);
    // B's change made again on A's file: A's is newer and stays.
    let mut merged = a.clone();
    apply(&mut merged, &cb);
    assert_eq!(
        merged.records("PW-1")[0].record.status.as_deref(),
        Some("Resolved")
    );
    let mut other = b.clone();
    action_log::merge(&mut other, &a);
    assert_eq!(
        other.records("PW-1")[0].record.status.as_deref(),
        Some("Resolved")
    );
    // Making a change twice is making it once.
    let before = merged.clone();
    apply(&mut merged, &ca);
    assert_eq!(merged, before);
}

/// What an older release reads: the plugin's record is an ordinary
/// record of an action it doesn't know, its `action` a plain string.
#[test]
fn an_older_reader_takes_a_plugins_record() {
    let mut file = ActionsFile::default();
    let c = changes_at(
        &file,
        json!([ticket("PW-1", "inc1", "Open", true)]),
        "2026-11-21T10:00:00.000Z",
    );
    apply(&mut file, &c);
    let text = String::from_utf8(file.to_bytes()).unwrap();
    assert!(text.contains("\"action\": \"plugin:servicenow\""), "{text}");
    assert!(text.contains("\"version\": 1"), "{text}");
    let back = action_log::parse(text.as_bytes()).unwrap();
    assert_eq!(back, file);
}

/// An output plugin as a script: writes `doc` to the result file when it
/// is given one, and says whether it was.
fn script_plugin(dir: &std::path::Path, doc: &str) -> OutputConfig {
    let command: Vec<String> = if cfg!(windows) {
        let p = dir.join("plugin.ps1");
        std::fs::write(
            &p,
            format!(
                "$p = $env:PATHWARDEN_OUTPUT_RESULT\n\
                 if ($p) {{ if ('{doc}') {{ [IO.File]::WriteAllText($p, '{doc}') }}; Write-Output \"asked\" }} else {{ Write-Output \"not asked\" }}\n"
            ),
        )
        .unwrap();
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain([p.display().to_string()])
        .collect()
    } else {
        let p = dir.join("plugin.sh");
        std::fs::write(
            &p,
            format!(
                "if [ -n \"$PATHWARDEN_OUTPUT_RESULT\" ]; then\n\
                 [ -n '{doc}' ] && printf '%s' '{doc}' > \"$PATHWARDEN_OUTPUT_RESULT\"\n\
                 echo asked\nelse echo 'not asked'; fi\n"
            ),
        )
        .unwrap();
        vec!["sh".into(), p.display().to_string()]
    };
    serde_json::from_value(json!({ "plugin": "fake", "command": command })).unwrap()
}

fn plugin_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pathwarden-output-result-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A real run gives the plugin a result file and reads what it wrote;
/// one that writes none runs as before; a dry run isn't given one.
#[test]
fn a_real_run_reads_the_result_file_a_dry_run_asks_for_none() {
    let dir = plugin_dir("run");
    let body = r#"{"schema":"pathwarden.output-result.v1","records":[{"fingerprint":"PW-1","id":"i1","open":true}]}"#;
    let o = script_plugin(&dir, body);
    let ran = crate::plugins::run_reporting(&o, "{}").unwrap();
    assert!(ran.ran.status.success(), "{:?}", ran.ran.lines());
    assert_eq!(ran.ran.lines(), ["asked"]);
    let bytes = ran.result.unwrap().unwrap();
    let (r, w) = read_result(&o, Some(Ok(bytes)));
    assert_eq!(w, None);
    assert_eq!(r.unwrap().records[0].record.id, "i1");
    // The file is gone once read.
    let work = crate::plugins::work_dir().unwrap();
    assert!(std::fs::read_dir(&work).unwrap().flatten().all(|e| !e
        .file_name()
        .to_string_lossy()
        .starts_with("output-result-")));

    let mut dry = o.clone();
    dry.settings.insert("dry_run".into(), Value::Bool(true));
    let ran = crate::plugins::run_reporting(&dry, "{}").unwrap();
    assert_eq!(ran.ran.lines(), ["not asked"]);
    assert!(ran.result.is_none());

    let silent = script_plugin(&dir, "");
    let ran = crate::plugins::run_reporting(&silent, "{}").unwrap();
    assert_eq!(ran.ran.lines(), ["asked"]);
    assert!(ran.result.is_none(), "no file, nothing read");
    let _ = std::fs::remove_dir_all(&dir);
}
