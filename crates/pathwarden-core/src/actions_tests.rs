use super::*;
use crate::config::Config;

/// The plan's example: one program, three actions.
const DESCRIBE: &str = r#"{
  "schema": "pathwarden.action-describe.v1",
  "actions": [ {
      "id": "open", "label": "Open a service request",
      "description": "Opens a request for the team that reviews findings.",
      "sends": "The finding's title, summary, affected objects, path and remediation.",
      "applies_to": { "min_severity": "medium" },
      "inputs": [
        { "id": "note", "label": "Note for the team", "type": "textarea", "max": 2000 },
        { "id": "urgency", "label": "Urgency", "type": "choice",
          "choices": ["Low", "Medium", "High"], "default": "Medium" } ],
      "once": true,
      "follow_ups": ["status", "close"],
      "colour": "a field this version doesn't know" },
    { "id": "status", "label": "Check status", "for": "record", "sends": "The record's ID." },
    { "id": "close", "label": "Close request", "for": "record", "when": "fixed", "sends": "The record's ID." } ] }"#;

fn described(text: &str) -> Describe {
    let (d, problems) = parse_describe(text.as_bytes()).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    d
}

/// One action of its own, from JSON.
fn one(action: Value) -> Result<(Describe, Vec<String>), Vec<String>> {
    parse_describe(
        json!({ "schema": DESCRIBE_SCHEMA, "actions": [action] })
            .to_string()
            .as_bytes(),
    )
}

#[test]
fn the_example_describe_reads() {
    let d = described(DESCRIBE);
    assert_eq!(d.actions.len(), 3);
    let open = &d.actions[0];
    assert_eq!(open.id, "open");
    assert_eq!(open.applies_to.min_severity, Some(Severity::Medium));
    assert_eq!(open.inputs[0].kind, InputType::Textarea);
    assert_eq!(open.inputs[0].max_chars(), 2000);
    assert_eq!(open.inputs[1].choices, ["Low", "Medium", "High"]);
    assert!(open.once);
    assert_eq!(open.follow_ups, ["status", "close"]);
    assert_eq!(d.actions[1].for_, Some(For::Record));
    assert_eq!(d.actions[2].when, Some(vec![FindingStatus::Fixed]));
    // A BOM is fine.
    let bom = [b"\xef\xbb\xbf".as_slice(), DESCRIBE.as_bytes()].concat();
    assert_eq!(parse_describe(&bom).unwrap().0, d);
}

#[test]
fn a_describe_that_cant_be_used_is_refused() {
    assert!(parse_describe(b"not json").unwrap_err()[0].contains("isn't JSON"));
    assert!(parse_describe(b"[]").unwrap_err()[0].contains("must be a JSON object"));
    let e =
        parse_describe(br#"{"schema":"pathwarden.action-describe.v2","actions":[]}"#).unwrap_err();
    assert!(
        e[0].contains("isn't \"pathwarden.action-describe.v1\""),
        "{e:?}"
    );
    let e = parse_describe(br#"{"schema":"pathwarden.action-describe.v1"}"#).unwrap_err();
    assert_eq!(
        e,
        ["actions must be a list of the actions the program offers"]
    );
    // No schema: used, and named.
    let (d, p) = parse_describe(br#"{"actions":[{"id":"a","label":"A","sends":"x"}]}"#).unwrap();
    assert_eq!(d.actions.len(), 1);
    assert_eq!(
        p,
        ["schema is missing: use \"pathwarden.action-describe.v1\""]
    );
    let (d, p) =
        parse_describe(br#"{"schema":"pathwarden.action-describe.v1","actions":[]}"#).unwrap();
    assert!(d.actions.is_empty());
    assert_eq!(p, ["actions is empty: the program offers no action"]);
}

/// Every check on an action, worded with where it is.
#[test]
fn bad_actions_are_left_out_with_why() {
    let base = || json!({ "id": "a", "label": "A", "sends": "x" });
    let with = |k: &str, v: Value| {
        let mut a = base();
        a[k] = v;
        a
    };
    let input = |v: Value| with("inputs", v);
    let cases: Vec<(Value, &str)> = vec![
        (
            with("id", json!("Open Ticket")),
            "actions[0].id 'Open Ticket' must be lowercase letters, digits, - and _",
        ),
        (
            with("id", json!(7)),
            "actions[0].id must be text, not a number",
        ),
        (
            json!({ "label": "A", "sends": "x" }),
            "actions[0].id is missing",
        ),
        (
            json!({ "id": "a", "sends": "x" }),
            "actions[0].label is missing",
        ),
        (
            with("for", json!("finding")),
            "actions[0].for \"finding\" isn't \"record\", the only value v1 knows",
        ),
        (
            with("when", json!("later")),
            "actions[0].when \"later\" isn't one of open, held, accepted, fixed",
        ),
        (
            with("once", json!("yes")),
            "actions[0].once must be true or false, not text",
        ),
        (
            with("applies_to", json!({ "min_severity": "severe" })),
            "actions[0].applies_to.min_severity 'severe' isn't one of critical, high, medium, low, info",
        ),
        (
            with("applies_to", json!({ "categories": ["paths"] })),
            "actions[0].applies_to.categories[0] 'paths' isn't one of attack_path, hygiene",
        ),
        (
            with("applies_to", json!({ "rules": ["PW 1"] })),
            "actions[0].applies_to.rules[0] 'PW 1' is not a rule ID such as PW-001",
        ),
        (
            input(json!([
                { "id": "n", "label": "N", "type": "text" },
                { "id": "c", "label": "C", "type": "number" }
            ])),
            "actions[0].inputs[1].type 'number' isn't one of text, textarea, choice, bool",
        ),
        (
            input(json!([{ "id": "n", "label": "N" }])),
            "actions[0].inputs[0].type is missing: use one of text, textarea, choice, bool",
        ),
        (
            input(json!([{ "id": "n", "label": "N", "type": "text", "max": 5000 }])),
            "actions[0].inputs[0].max must be a whole number from 1 to 1000",
        ),
        (
            input(json!([{ "id": "n", "label": "N", "type": "bool", "max": 5 }])),
            "actions[0].inputs[0].max is only for text and textarea inputs",
        ),
        (
            input(json!([{ "id": "n", "label": "N", "type": "choice" }])),
            "actions[0].inputs[0].choices must be a list of at least one choice",
        ),
        (
            input(json!([{ "id": "n", "label": "N", "type": "choice", "choices": ["a", "a"] }])),
            "actions[0].inputs[0].choices[1] 'a' is there twice",
        ),
        (
            input(json!([
                { "id": "n", "label": "N", "type": "choice", "choices": ["a"], "default": "b" }
            ])),
            "actions[0].inputs[0].default must be one of the choices",
        ),
        (
            input(json!([{ "id": "n", "label": "N", "type": "bool", "default": "yes" }])),
            "actions[0].inputs[0].default must be true or false",
        ),
        (
            input(json!([
                { "id": "n", "label": "N", "type": "text", "max": 3, "default": "abcd" }
            ])),
            "actions[0].inputs[0].default must be text no longer than max, without control characters",
        ),
        (
            input(json!([
                { "id": "n", "label": "N", "type": "text" },
                { "id": "n", "label": "M", "type": "text" }
            ])),
            "actions[0].inputs[1].id 'n' is there twice",
        ),
        (
            input(json!("note")),
            "actions[0].inputs must be a list, not text",
        ),
    ];
    for (action, why) in cases {
        let (d, problems) = one(action.clone()).unwrap();
        assert!(d.actions.is_empty(), "{action}: kept");
        assert!(problems.iter().any(|p| p == why), "{action}: {problems:?}");
    }
}

#[test]
fn small_problems_keep_the_action() {
    let long = "x".repeat(400);
    let (d, p) =
        one(json!({ "id": "a", "label": "A", "description": long, "follow_ups": ["nope"] }))
            .unwrap();
    assert_eq!(d.actions.len(), 1, "{p:?}");
    assert_eq!(d.actions[0].description.chars().count(), MAX_DESCRIPTION);
    assert!(d.actions[0].description.ends_with('…'));
    assert!(d.actions[0].follow_ups.is_empty());
    assert_eq!(
        p,
        [
            "actions[0].description is longer than 300 characters; it was cut",
            "actions[0].sends is missing: say in plain words what leaves the computer",
            "Action 'a': follow-up 'nope' isn't an action of this program with for: \"record\"",
        ]
    );
    // Control and bidi characters never reach a label.
    let (d, _) = one(json!({ "id": "a", "label": "Open\u{202e}\n\u{7}it", "sends": "x" })).unwrap();
    assert_eq!(d.actions[0].label, "Openit");
    // Twice the same ID: the first counts.
    let (d, p) = parse_describe(
        json!({ "schema": DESCRIBE_SCHEMA, "actions": [
            { "id": "a", "label": "First", "sends": "x" },
            { "id": "a", "label": "Second", "sends": "x" } ] })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(d.actions.len(), 1);
    assert_eq!(d.actions[0].label, "First");
    assert_eq!(p, ["actions[1].id 'a' is there twice"]);
    // At most 20.
    let many: Vec<Value> = (0..25)
        .map(|i| json!({ "id": format!("a{i}"), "label": "A", "sends": "x" }))
        .collect();
    let (d, p) = parse_describe(
        json!({ "schema": DESCRIBE_SCHEMA, "actions": many })
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(d.actions.len(), MAX_ACTIONS);
    assert_eq!(
        p,
        ["actions has more than 20 actions; the rest are left out"]
    );
}

fn object(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn inputs_are_checked_against_their_types() {
    let d = described(DESCRIBE);
    let open = &d.actions[0];
    // Defaults: an empty note, the default choice.
    let got = check_inputs(open, &Map::new()).unwrap();
    assert_eq!(
        Value::Object(got),
        json!({ "note": "", "urgency": "Medium" })
    );
    // A choice in any case is the choice as written; lines in a textarea.
    let got = check_inputs(
        open,
        &object(json!({ "note": " a\r\nb ", "urgency": "high" })),
    )
    .unwrap();
    assert_eq!(
        Value::Object(got),
        json!({ "note": "a\nb", "urgency": "High" })
    );
    let e = check_inputs(open, &object(json!({ "urgency": "Now", "colour": "red" }))).unwrap_err();
    assert_eq!(
        e,
        [
            "There is no input 'colour': Open a service request takes note, urgency.",
            "Urgency: 'Now' isn't one of Low, Medium, High.",
        ]
    );
    let e = check_inputs(open, &object(json!({ "note": "x".repeat(2001) }))).unwrap_err();
    assert_eq!(
        e,
        ["Note for the team is 2001 characters long; it takes at most 2000."]
    );

    let (d, _) = one(json!({ "id": "a", "label": "A", "sends": "x", "inputs": [
        { "id": "who", "label": "Who", "type": "text", "required": true },
        { "id": "page", "label": "Page them", "type": "bool" } ] }))
    .unwrap();
    let a = &d.actions[0];
    let e = check_inputs(a, &Map::new()).unwrap_err();
    assert_eq!(e, ["Who is needed."]);
    let e = check_inputs(a, &object(json!({ "who": "a\nb", "page": "maybe" }))).unwrap_err();
    assert_eq!(
        e,
        [
            "Who holds a control character or a line break.",
            "Page them must be true or false, not 'maybe'.",
        ]
    );
    let got = check_inputs(a, &object(json!({ "who": "Ned", "page": "yes" }))).unwrap();
    assert_eq!(Value::Object(got), json!({ "who": "Ned", "page": true }));
    let got = check_inputs(a, &object(json!({ "who": "Ned" }))).unwrap();
    assert_eq!(got["page"], false);
    let e = check_inputs(a, &object(json!({ "who": "Ned", "page": [true] }))).unwrap_err();
    assert_eq!(e, ["Page them must be true or false, not a list."]);
    // No inputs at all.
    let (d, _) = one(json!({ "id": "a", "label": "Ping", "sends": "x" })).unwrap();
    let e = check_inputs(&d.actions[0], &object(json!({ "x": "1" }))).unwrap_err();
    assert_eq!(e, ["Ping takes no inputs, so 'x' can't be given."]);
    assert_eq!(
        Value::Object(sample_inputs(&described(DESCRIBE).actions[0])),
        json!({ "note": "Test from Pathwarden", "urgency": "Medium" })
    );
}

#[test]
fn links_must_be_https() {
    assert!(https_url("https://sn.example.com/x?a=b#c").is_ok());
    assert!(https_url("HTTPS://sn.example.com:8443").is_ok());
    for (bad, why) in [
        ("http://sn.example.com", "must start with https://"),
        ("javascript:alert(1)", "must start with https://"),
        ("https://", "has no host"),
        ("https://:443/x", "has no host"),
        (
            "https://u:p@sn.example.com",
            "must not hold a user name or password",
        ),
        (
            "https://sn.example.com/a b",
            "holds a space or a control character",
        ),
        (
            "https://sn.example.com/\u{202e}",
            "holds a space or a control character",
        ),
    ] {
        assert_eq!(https_url(bad), Err(why), "{bad}");
    }
    assert!(https_url(&format!("https://x.example/{}", "a".repeat(MAX_URL))).is_err());
}

#[test]
fn results_are_read_strictly_and_capped() {
    let r = |v: Value| parse_result(v.to_string().as_bytes());
    let (res, p) = r(json!({
        "schema": RESULT_SCHEMA, "ok": true, "message": "Opened <b>RITM0010</b>",
        "links": [{ "label": "Open in ServiceNow", "url": "https://sn.example.com/x" }],
        "records": [{ "id": "abc", "kind": "ticket", "number": "RITM0010", "status": "Open",
                      "open": true, "url": "https://sn.example.com/r",
                      "fields": { "Request": "REQ1", "Item": 7 } }],
        "later": "a field this version doesn't know"
    }))
    .unwrap();
    assert!(p.is_empty(), "{p:?}");
    assert!(res.ok);
    // Kept as text: never read as HTML.
    assert_eq!(res.message, "Opened <b>RITM0010</b>");
    assert_eq!(res.links[0].url, "https://sn.example.com/x");
    assert_eq!(res.records[0].number.as_deref(), Some("RITM0010"));
    assert!(res.records[0].open);
    assert_eq!(res.records[0].fields["Item"], "7");

    // What can't be used at all fails the run.
    assert!(parse_result(b"").unwrap_err()[0].starts_with("The result isn't JSON"));
    assert!(parse_result(b"\"ok\"").unwrap_err()[0].contains("must be a JSON object"));
    assert_eq!(
        r(json!({ "schema": RESULT_SCHEMA })).unwrap_err(),
        ["ok is missing: say whether the action worked"]
    );
    assert_eq!(
        r(json!({ "schema": RESULT_SCHEMA, "ok": "yes" })).unwrap_err(),
        ["ok must be true or false, not text"]
    );
    assert!(
        r(json!({ "schema": "pathwarden.action-result.v2", "ok": true })).unwrap_err()[0]
            .contains("isn't \"pathwarden.action-result.v1\"")
    );

    // The caps: cut or left out, and named.
    let many_fields: Map<String, Value> =
        (0..25).map(|i| (format!("f{i:02}"), json!("v"))).collect();
    let records: Vec<Value> = (0..7)
        .map(|i| json!({ "id": format!("r{i}"), "url": "http://sn.example.com", "fields": many_fields }))
        .collect();
    let (res, p) = r(json!({
        "ok": false,
        "message": "m".repeat(2500),
        "links": [{ "label": "Bad", "url": "http://x.example" },
                  { "label": "Good", "url": "https://x.example" }],
        "records": records,
    }))
    .unwrap();
    assert!(!res.ok);
    assert_eq!(res.message.chars().count(), MAX_MESSAGE);
    assert_eq!(
        res.links,
        [Link {
            label: "Good".into(),
            url: "https://x.example".into()
        }]
    );
    assert_eq!(res.records.len(), MAX_RECORDS);
    assert!(res
        .records
        .iter()
        .all(|r| r.url.is_none() && r.fields.len() == MAX_FIELDS));
    for want in [
        "schema is missing: use \"pathwarden.action-result.v1\"",
        "message is longer than 2000 characters; it was cut",
        "links[0].url must start with https://; the link was left out",
        "records has more than 5 records; the rest were left out",
        "records[0].url must start with https://; it was left out",
        "records[0].fields has more than 20 fields; the rest were left out",
    ] {
        assert!(p.iter().any(|x| x == want), "{want}: {p:?}");
    }
    let (res, p) = r(json!({ "schema": RESULT_SCHEMA, "ok": true, "records": [
        { "id": "a", "fields": { "Long": "x".repeat(250), "List": [1] } },
        { "id": "a" }, { "kind": "no id" } ] }))
    .unwrap();
    assert_eq!(res.records.len(), 1);
    assert_eq!(res.records[0].fields["Long"].chars().count(), MAX_FIELD);
    assert!(!res.records[0].fields.contains_key("List"));
    let mut p = p;
    p.sort();
    assert_eq!(
        p,
        [
            "records[0].fields.List must be text, not a list; it was left out",
            "records[0].fields.Long is longer than 200 characters; it was cut",
            "records[1].id 'a' is there twice; the second was left out",
            "records[2].id is missing",
        ]
    );
    // A message keeps its lines but no other control character.
    let (res, _) =
        r(json!({ "schema": RESULT_SCHEMA, "ok": true, "message": "a\r\nb\u{1b}[2J\u{202e}" }))
            .unwrap();
    assert_eq!(res.message, "a\nb[2J");
}

/// An event with an open, an accepted, a fixed and a held finding.
fn event() -> Value {
    json!({
        "schema": "pathwarden.event.v1",
        "run": { "run_id": "R1", "domains": ["SCALE.LOCAL"], "pathwarden": "1.0.0", "objects": 9 },
        "findings": [
            { "change": "new", "rule": "PW-001", "category": "attack_path", "severity": "critical",
              "fingerprint": "PW-001-aaaa", "title": "Critical path", "suppressed": null },
            { "change": "suppressed", "rule": "PW-011", "category": "hygiene", "severity": "low",
              "fingerprint": "PW-011-bbbb", "title": "Kiosk", "suppressed": "Kiosks" },
        ],
        "resolved": [ { "fingerprint": "PW-003-cccc", "rule": "PW-003", "severity": "high",
                        "first_seen": 1, "resolved_at": 2 } ],
        "held": [ { "fingerprint": "PW-004-dddd", "rule": "PW-004" } ],
        "guides": { "PW-001": "# Guide one" }
    })
}

#[test]
fn findings_come_from_the_event_as_they_are() {
    let e = event();
    let all = findings_in_event(&e);
    assert_eq!(
        all.iter()
            .map(|f| (f.fingerprint.as_str(), f.status))
            .collect::<Vec<_>>(),
        [
            ("PW-001-aaaa", FindingStatus::Open),
            ("PW-011-bbbb", FindingStatus::Accepted),
            ("PW-003-cccc", FindingStatus::Fixed),
            ("PW-004-dddd", FindingStatus::Held),
        ]
    );
    let f = finding_in_event(&e, "pw-001-AAAA").unwrap();
    // The event's object as it is, plus guide and status.
    let mut want = e["findings"][0].clone();
    want["guide"] = json!("# Guide one");
    want["status"] = json!("open");
    assert_eq!(f.finding, want);
    assert_eq!(
        f.run,
        json!({ "run_id": "R1", "domains": ["SCALE.LOCAL"], "pathwarden": "1.0.0" })
    );
    assert_eq!(f.category, Some(Category::AttackPath));
    // Fixed and held findings get the rule's own guide.
    let fixed = finding_in_event(&e, "PW-003-cccc").unwrap();
    assert_eq!(
        fixed.finding["guide"],
        json!(crate::guides::guide("PW-003"))
    );
    assert_eq!(fixed.severity, Some(Severity::High));
    // What their event entry lacks comes from the rule catalog.
    assert_eq!(fixed.category, Some(Category::AttackPath));
    let held = finding_in_event(&e, "PW-004-dddd").unwrap();
    assert_eq!(held.severity, Some(Severity::High));
    assert_eq!(held.category, Some(Category::AttackPath));
    assert_eq!(rule_category("PW-011"), Some(Category::Hygiene));
    assert_eq!(rule_severity("PW-003"), Some(Severity::Critical));
    assert_eq!(rule_category("PW-999"), None);
    assert!(finding_in_event(&e, "PW-999-x").is_none());
    let s = sample_finding();
    assert_eq!(s.status, FindingStatus::Open);
    assert_eq!(s.finding["guide"], json!(crate::guides::guide("PW-001")));
}

/// Two `[[action]]` blocks, the first a program offering several actions.
fn config() -> Config {
    Config::parse(
        r#"
[[action]]
name = "service-desk"
command = ["python", "/opt/actions/desk.py"]
group = "Identity"

[[action]]
plugin = "teams-alert"
min_severity = "High"
webhook_env = "TEAMS_HOOK"
"#,
    )
    .unwrap()
}

fn desk() -> Describe {
    described(DESCRIBE)
}

fn alert() -> Describe {
    described(
        r#"{"schema":"pathwarden.action-describe.v1","actions":[
          {"id":"alert","label":"Alert the team","sends":"The title."},
          {"id":"page","label":"Page on-call","sends":"The title.",
           "applies_to":{"categories":["hygiene"]}}]}"#,
    )
}

fn addresses(o: &[Offered]) -> Vec<&str> {
    o.iter().map(|o| o.address.as_str()).collect()
}

fn rec(action: &str, open: bool) -> ActionRecord {
    ActionRecord {
        action: action.into(),
        record: Record {
            id: "r1".into(),
            open,
            ..Record::default()
        },
        by: None,
        on: None,
        at: String::new(),
        updated_at: String::new(),
    }
}

#[test]
fn the_right_actions_in_config_order() {
    let c = config();
    assert_eq!(c.actions[0].name, "service-desk");
    assert_eq!(c.actions[1].name, "teams-alert");
    // Settings are the other keys.
    assert_eq!(
        Value::Object(c.actions[0].settings.clone()),
        json!({ "group": "Identity" })
    );
    assert_eq!(
        c.actions[1].timeout_seconds,
        crate::config::ACTION_TIMEOUT_DEFAULT
    );
    let (d, a) = (desk(), alert());
    let programs = [
        Program {
            config: &c.actions[0],
            describe: &d,
        },
        Program {
            config: &c.actions[1],
            describe: &a,
        },
    ];
    let e = event();
    let open = finding_in_event(&e, "PW-001-aaaa").unwrap();
    // Not the record actions; not `page` (hygiene only).
    assert_eq!(
        addresses(&offered(&programs, &open, &[])),
        ["service-desk/open", "teams-alert/alert"]
    );
    // Low and hygiene: below both minimums.
    let low = finding_in_event(&e, "PW-011-bbbb").unwrap();
    assert!(offered(&programs, &low, &[]).is_empty());
    // A held finding is rated as its rule is (PW-004: High).
    let held = finding_in_event(&e, "PW-004-dddd").unwrap();
    assert_eq!(
        addresses(&offered(&programs, &held, &[])),
        ["service-desk/open", "teams-alert/alert"]
    );

    // `once`: hidden while an open record from it is there.
    assert_eq!(
        addresses(&offered(
            &programs,
            &open,
            &[rec("service-desk/open", true)]
        )),
        ["teams-alert/alert"]
    );
    assert_eq!(
        addresses(&offered(
            &programs,
            &open,
            &[
                rec("service-desk/open", false),
                rec("teams-alert/alert", true)
            ]
        )),
        ["service-desk/open", "teams-alert/alert"]
    );

    // Follow-ups: in the order the action lists them; `close` only once
    // fixed.
    let r = rec("service-desk/open", true);
    assert_eq!(
        addresses(&follow_ups(&programs, &open, &r)),
        ["service-desk/status"]
    );
    let fixed = finding_in_event(&e, "PW-003-cccc").unwrap();
    assert_eq!(
        addresses(&follow_ups(&programs, &fixed, &r)),
        ["service-desk/status", "service-desk/close"]
    );
    assert!(follow_ups(&programs, &open, &rec("teams-alert/alert", true)).is_empty());
    assert!(follow_ups(&programs, &open, &rec("gone/open", true)).is_empty());
}

/// `when: "fixed"` behind a categories filter: a fixed finding takes its
/// category from the rule, so it shows.
#[test]
fn a_fixed_finding_passes_a_category_filter() {
    let c = Config::parse(
        "[[action]]\nplugin = \"desk\"\ncategories = [\"attack_path\"]\nmin_severity = \"high\"\n",
    )
    .unwrap();
    let d = described(
        r#"{"schema":"pathwarden.action-describe.v1","actions":[
          {"id":"done","label":"Say it's fixed","sends":"x","when":"fixed"}]}"#,
    );
    let programs = [Program {
        config: &c.actions[0],
        describe: &d,
    }];
    let e = event();
    let fixed = finding_in_event(&e, "PW-003-cccc").unwrap();
    assert_eq!(addresses(&offered(&programs, &fixed, &[])), ["desk/done"]);
    let open = finding_in_event(&e, "PW-001-aaaa").unwrap();
    assert!(offered(&programs, &open, &[]).is_empty());
}

#[test]
fn block_filters_narrow_what_a_program_offers() {
    let c = Config::parse(
        "[[action]]\nplugin = \"x\"\nrules = [\"pw-011\"]\ncategories = [\"hygiene\"]\n",
    )
    .unwrap();
    let a = alert();
    let programs = [Program {
        config: &c.actions[0],
        describe: &a,
    }];
    let e = event();
    let low = finding_in_event(&e, "PW-011-bbbb").unwrap();
    assert_eq!(
        addresses(&offered(&programs, &low, &[])),
        ["x/alert", "x/page"]
    );
    let open = finding_in_event(&e, "PW-001-aaaa").unwrap();
    assert!(offered(&programs, &open, &[]).is_empty());
}

#[test]
fn an_action_is_picked_and_its_request_built() {
    let c = config();
    let (d, a) = (desk(), alert());
    let programs = [
        Program {
            config: &c.actions[0],
            describe: &d,
        },
        Program {
            config: &c.actions[1],
            describe: &a,
        },
    ];
    let e = event();
    let open = finding_in_event(&e, "PW-001-aaaa").unwrap();
    let o = offered(&programs, &open, &[]);
    assert_eq!(
        pick(&o, Some("SERVICE-DESK/open")).unwrap().address,
        "service-desk/open"
    );
    assert_eq!(
        pick(&o, Some("teams-alert")).unwrap().address,
        "teams-alert/alert"
    );
    assert_eq!(
        pick(&o, Some("alert")).unwrap().address,
        "teams-alert/alert"
    );
    assert_eq!(
        pick(&o, None).unwrap_err(),
        "Several actions apply to this finding: choose one of service-desk/open, teams-alert/alert."
    );
    assert_eq!(
        pick(&o, Some("teams-alert/page")).unwrap_err(),
        "teams-alert/page doesn't apply to this finding. These do: service-desk/open, teams-alert/alert."
    );
    assert_eq!(
        pick(&[], None).unwrap_err(),
        "No action applies to this finding."
    );
    assert_eq!(pick(&o[..1], None).unwrap().address, "service-desk/open");
    // A bare word that is one block's name and another's action ID.
    let c2 =
        Config::parse("[[action]]\nplugin = \"alert\"\n[[action]]\nplugin = \"pager\"\n").unwrap();
    let one = described(
        r#"{"schema":"pathwarden.action-describe.v1","actions":[{"id":"send","label":"Send","sends":"x"}]}"#,
    );
    let two = described(
        r#"{"schema":"pathwarden.action-describe.v1","actions":[{"id":"alert","label":"Alert","sends":"x"}]}"#,
    );
    let both = [
        Program {
            config: &c2.actions[0],
            describe: &one,
        },
        Program {
            config: &c2.actions[1],
            describe: &two,
        },
    ];
    let o2 = offered(&both, &open, &[]);
    assert_eq!(
        pick(&o2, Some("alert")).unwrap_err(),
        "alert could be alert/send, pager/alert: give the action as name/id."
    );
    assert_eq!(pick(&o2, Some("send")).unwrap().address, "alert/send");

    // `prepare`: the request, with checked inputs and who asked.
    let ask = Ask {
        action: Some("service-desk/open".into()),
        inputs: object(json!({ "urgency": "low" })),
        dry_run: true,
        ..Ask::default()
    };
    let p = prepare(&programs, &open, &[], &ask).unwrap();
    let r = &p.request;
    assert_eq!(r["schema"], REQUEST_SCHEMA);
    assert_eq!(r["kind"], "run");
    assert_eq!(r["action"], "open");
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["inputs"], json!({ "note": "", "urgency": "Low" }));
    assert_eq!(r["settings"], json!({ "group": "Identity" }));
    assert_eq!(r["run"]["run_id"], "R1");
    assert_eq!(r["finding"]["fingerprint"], "PW-001-aaaa");
    assert_eq!(r["finding"]["status"], "open");
    assert_eq!(r["finding"]["guide"], "# Guide one");
    assert_eq!(r["record"], Value::Null);
    assert_eq!(
        r["requested_by"]["on"],
        json!(crate::identity::Actor::current().computer)
    );
    assert_eq!(p.offered.address, "service-desk/open");
    assert_eq!(p.config.name, "service-desk");
    // A follow-up isn't run on a finding without a record.
    let ask = Ask {
        action: Some("service-desk/status".into()),
        ..Ask::default()
    };
    assert_eq!(
        prepare(&programs, &open, &[], &ask).unwrap_err(),
        "Check status runs on a record of this finding, and it has none."
    );
    let ask = Ask {
        action: Some("service-desk/open".into()),
        inputs: object(json!({ "x": 1 })),
        dry_run: false,
        ..Ask::default()
    };
    assert_eq!(
        prepare(&programs, &open, &[], &ask).unwrap_err(),
        "There is no input 'x': Open a service request takes note, urgency."
    );
    assert_eq!(
        describe_request(&c.actions[0]),
        json!({ "schema": REQUEST_SCHEMA, "kind": "describe", "settings": { "group": "Identity" } })
    );
}

#[test]
fn action_blocks_are_checked() {
    let e = |text: &str| Config::parse(text).unwrap_err().to_string();
    assert!(
        e("[[action]]\nplugin = \"a\"\n[[action]]\nname = \"a\"\ncommand = [\"pwsh\"]\n")
            .contains("Two [[action]] blocks are named a: give one of them another name"),
    );
    // Default names: plugin, else action-N (by place: noted where blocks
    // are listed).
    let c = Config::parse(
        "[[action]]\ncommand = [\"pwsh\"]\n[[action]]\nplugin = \"b\"\n[[action]]\ncommand = [\"sh\"]\n",
    )
    .unwrap();
    assert_eq!(
        c.actions
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>(),
        ["action-1", "b", "action-3"]
    );
    assert_eq!(
        c.actions
            .iter()
            .map(|a| a.positional_name)
            .collect::<Vec<_>>(),
        [true, false, true]
    );
    assert!(e(
        "[[action]]\ncommand = [\"pwsh\"]\nname = \"action-2\"\n[[action]]\ncommand = [\"sh\"]\n"
    )
    .contains("named action-2"));
    for (text, why) in [
        (
            "[[action]]\nname = \"x\"\n",
            "[[action]] 1: name the program with plugin or command",
        ),
        (
            "[[action]]\nplugin = \"x\"\ncommand = [\"sh\"]\n",
            "give plugin or command, not both",
        ),
        (
            "[[action]]\ncommand = []\n",
            "[[action]] 1: command is empty",
        ),
        (
            "[[action]]\nplugin = \"Teams\"\n",
            "use lowercase letters, digits and dashes",
        ),
        (
            "[[action]]\nplugin = \"t\"\nname = \"a b\"\n",
            "use lowercase letters, digits and dashes",
        ),
        (
            "[[action]]\nplugin = \"t\"\ntimeout_seconds = 1801\n",
            "timeout_seconds must be from 1 to 1800",
        ),
        (
            "[[action]]\nplugin = \"t\"\ntimeout_seconds = 0\n",
            "timeout_seconds must be from 1 to 1800",
        ),
        (
            "[[action]]\nplugin = \"t\"\nmin_severity = \"severe\"\n",
            "unknown severity 'severe'",
        ),
        (
            "[[action]]\nplugin = \"t\"\ncategories = [\"paths\"]\n",
            "'paths' isn't one of attack_path, hygiene",
        ),
        (
            "[[action]]\nplugin = \"t\"\nrules = [\"PW 1\"]\n",
            "is not a rule ID",
        ),
    ] {
        let msg = e(text);
        assert!(msg.contains(why), "{text}: {msg}");
    }
    // A singular or plural of a block key stays a setting, with a note;
    // any other key is a setting, as programs may need any name.
    for (key, block_key) in [
        ("rule", "rules"),
        ("category", "categories"),
        ("names", "name"),
        ("commands", "command"),
        ("timeout_second", "timeout_seconds"),
    ] {
        let c = Config::parse(&format!("[[action]]\nplugin = \"t\"\n{key} = \"x\"\n")).unwrap();
        assert_eq!(c.actions[0].settings[key], "x");
        let notes: Vec<String> = c.warnings.iter().filter_map(|w| w.place.clone()).collect();
        assert_eq!(
            notes,
            [format!(
                "[[action]] 1: `{key}` is passed to the program as a setting; the block's own key is `{block_key}`."
            )],
            "{key}"
        );
    }
    for key in ["comand", "role", "group", "timeout"] {
        let c = Config::parse(&format!("[[action]]\nplugin = \"t\"\n{key} = \"x\"\n")).unwrap();
        assert_eq!(c.actions[0].settings[key], "x");
        assert!(c.warnings.is_empty(), "{key}: {:?}", c.warnings);
    }
    // Any other key is a setting.
    let c = Config::parse(
        "[[action]]\nplugin = \"t\"\ntimeout_seconds = 900\ngroup = \"x\"\nurgency_default = 2\n",
    )
    .unwrap();
    assert_eq!(c.actions[0].timeout_seconds, 900);
    assert_eq!(
        Value::Object(c.actions[0].settings.clone()),
        json!({ "group": "x", "urgency_default": 2 })
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    // The program and *_env, as for outputs.
    let msg = crate::config_edit::check("[[action]]\ncommand = [\"teams.exe\"]\n").unwrap_err();
    assert!(
        msg.contains("[[action]] action-1: command \"teams.exe\" must be an absolute path"),
        "{msg}"
    );
    let msg =
        crate::config_edit::check("[[action]]\nplugin = \"t\"\ntoken_env = \"A-B\"\n").unwrap_err();
    assert!(
        msg.contains("token_env must name an environment variable"),
        "{msg}"
    );
}

#[test]
fn actions_are_added_changed_and_removed_in_the_file() {
    use crate::config_edit::{ActionEdit, ConfigDoc, Setting};
    let mut d = ConfigDoc::parse("# mine\n[[output]]\nplugin = \"x\"\n").unwrap();
    let script = if cfg!(windows) {
        r"C:\actions\desk.py"
    } else {
        "/opt/actions/desk.py"
    };
    let add = ActionEdit {
        name: "service-desk".into(),
        command: Some(vec!["python".into(), script.into()]),
        timeout_seconds: Some(900),
        min_severity: Some("Medium".into()),
        categories: Some(vec!["attack_path".into()]),
        set: vec![
            ("group".into(), Setting::Str("Identity".into())),
            ("token_env".into(), Setting::Str("DESK_TOKEN".into())),
        ],
        ..ActionEdit::default()
    };
    d.upsert_action(None, &add).unwrap();
    d.upsert_action(
        None,
        &ActionEdit {
            plugin: Some("teams-alert".into()),
            ..ActionEdit::default()
        },
    )
    .unwrap();
    let c = d.validate().unwrap();
    assert_eq!(c.actions.len(), 2);
    let a = &c.actions[0];
    assert_eq!(a.name, "service-desk");
    assert_eq!(a.timeout_seconds, 900);
    assert_eq!(a.min_severity, Some(Severity::Medium));
    assert_eq!(a.categories, [Category::AttackPath]);
    assert_eq!(
        Value::Object(a.settings.clone()),
        json!({ "group": "Identity", "token_env": "DESK_TOKEN" })
    );
    assert!(d.text().starts_with("# mine\n"), "{}", d.text());
    assert!(
        d.text().contains("min_severity = \"medium\""),
        "{}",
        d.text()
    );
    // A name another block has is refused, and so is a stale edit.
    let e = d
        .upsert_action(
            None,
            &ActionEdit {
                name: "teams-alert".into(),
                command: Some(vec!["sh".into()]),
                ..ActionEdit::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        e,
        "There is already an action named teams-alert: give this one another name."
    );
    assert_eq!(
        d.upsert_action(Some((1, "service-desk")), &add)
            .unwrap_err(),
        crate::config_edit::CHANGED
    );
    let e = d
        .upsert_action(
            None,
            &ActionEdit {
                set: vec![("rules".into(), Setting::Int(1))],
                plugin: Some("z".into()),
                ..ActionEdit::default()
            },
        )
        .unwrap_err();
    assert!(e.starts_with("Setting name \"rules\""), "{e}");
    assert_eq!(
        d.upsert_action(None, &ActionEdit::default()).unwrap_err(),
        "Name the program: a plugin or a command."
    );
    // Changed: a filter taken off, a setting removed.
    let change = ActionEdit {
        min_severity: Some(String::new()),
        remove: vec!["group".into()],
        set: Vec::new(),
        ..add.clone()
    };
    d.upsert_action(Some((0, "service-desk")), &change).unwrap();
    let c = d.validate().unwrap();
    assert_eq!(c.actions[0].min_severity, None);
    assert!(!c.actions[0].settings.contains_key("group"));
    assert_eq!(d.action_index("TEAMS-ALERT"), Some(1));
    assert_eq!(
        d.remove_action(1, "service-desk").unwrap_err(),
        crate::config_edit::CHANGED
    );
    d.remove_action(1, "teams-alert").unwrap();
    d.remove_action(0, "service-desk").unwrap();
    assert!(d.validate().unwrap().actions.is_empty());
    assert!(!d.text().contains("[[action]]"), "{}", d.text());
    // Never shared through the history.
    assert!(crate::config_edit::NEVER_SHARED.contains(&"action"));
}

/// Every block the editor writes has a name: given, kept, the plugin's, or
/// the script's, made unique.
#[test]
fn blocks_always_get_a_name() {
    use crate::config::action_name_for;
    use crate::config_edit::{ActionEdit, ConfigDoc};
    let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(action_name_for(Some("teams"), None), "teams");
    assert_eq!(
        action_name_for(
            None,
            Some(&argv(&["python", r"C:\Actions\Service_Desk.py"]))
        ),
        "service-desk"
    );
    assert_eq!(
        action_name_for(
            None,
            Some(&argv(&["pwsh", "-File=/opt/a/Post To Teams.ps1", "-x"]))
        ),
        "post-to-teams"
    );
    assert_eq!(
        action_name_for(None, Some(&argv(&["/opt/bin/alert"]))),
        "alert"
    );
    assert_eq!(
        action_name_for(None, Some(&argv(&["/opt/bin/.."]))),
        "action"
    );

    let mut d = ConfigDoc::parse("[[action]]\ncommand = [\"sh\"]\n").unwrap();
    let script = if cfg!(windows) {
        r"C:\actions\desk.py"
    } else {
        "/opt/actions/desk.py"
    };
    let desk = ActionEdit {
        command: Some(vec!["python".into(), script.into()]),
        ..ActionEdit::default()
    };
    d.upsert_action(None, &desk).unwrap();
    d.upsert_action(None, &desk).unwrap();
    // An unnamed block keeps the name it had when changed.
    d.upsert_action(
        Some((0, "action-1")),
        &ActionEdit {
            command: Some(vec!["sh".into()]),
            timeout_seconds: Some(60),
            ..ActionEdit::default()
        },
    )
    .unwrap();
    let c = d.validate().unwrap();
    assert_eq!(
        c.actions
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>(),
        ["action-1", "desk", "desk-2"]
    );
    assert!(c.actions.iter().all(|a| !a.positional_name));
    // An explicit name a block has by its place is taken too.
    let mut d = ConfigDoc::parse("[[action]]\ncommand = [\"sh\"]\n").unwrap();
    let e = d
        .upsert_action(
            None,
            &ActionEdit {
                name: "action-1".into(),
                command: Some(vec!["sh".into()]),
                ..ActionEdit::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        e,
        "There is already an action named action-1: give this one another name."
    );
}

/// With --lock-destinations a page may change only a block's name,
/// time limit and filters: not add one, its program or any setting.
#[test]
fn programs_and_secrets_of_actions_need_the_flag() {
    use crate::config_edit::{ActionEdit, Setting};
    use crate::plugin_form::{check_action, ACTIONS_LOCKED};
    let c = Config::parse(
        "[[action]]\nname = \"desk\"\ncommand = [\"sh\", \" -c\"]\ntoken_env = \"T\"\n",
    )
    .unwrap();
    let old = &c.actions[0];
    let same = || ActionEdit {
        name: "desk".into(),
        command: Some(vec!["sh".into(), "-c".into()]),
        ..ActionEdit::default()
    };
    assert_eq!(
        check_action(false, &mut same(), None).unwrap_err(),
        ACTIONS_LOCKED
    );
    let mut e = same();
    check_action(false, &mut e, Some(old)).unwrap();
    // Written back exactly as the file has it.
    assert_eq!(e.command, old.command);
    // The filters, the time limit and the name; a setting set to what it
    // is now is no change.
    let mut e = ActionEdit {
        name: "front-desk".into(),
        set: vec![("token_env".into(), Setting::Str("T".into()))],
        min_severity: Some("high".into()),
        rules: Some(vec!["PW-001".into()]),
        categories: Some(vec!["hygiene".into()]),
        timeout_seconds: Some(900),
        ..same()
    };
    check_action(false, &mut e, Some(old)).unwrap();
    for mut bad in [
        ActionEdit {
            command: Some(vec!["pwsh".into()]),
            ..same()
        },
        ActionEdit {
            command: None,
            plugin: Some("desk".into()),
            ..same()
        },
        ActionEdit {
            set: vec![("token_env".into(), Setting::Str("OTHER".into()))],
            ..same()
        },
        ActionEdit {
            set: vec![("new_env".into(), Setting::Str("X".into()))],
            ..same()
        },
        ActionEdit {
            remove: vec!["token_env".into()],
            ..same()
        },
        // Where it sends: any program setting.
        ActionEdit {
            set: vec![(
                "instance".into(),
                Setting::Str("https://evil.example".into()),
            )],
            ..same()
        },
        ActionEdit {
            set: vec![("group".into(), Setting::Str("x".into()))],
            ..same()
        },
        ActionEdit {
            set: vec![("dry_run".into(), Setting::Bool(false))],
            ..same()
        },
    ] {
        assert_eq!(
            check_action(false, &mut bad, Some(old)).unwrap_err(),
            ACTIONS_LOCKED,
            "{bad:?}"
        );
        check_action(true, &mut bad, Some(old)).unwrap();
    }
    // With the flag, network paths are still refused.
    let mut net = ActionEdit {
        command: Some(vec![
            "powershell".into(),
            "-File".into(),
            r"\\srv\s\a.ps1".into(),
        ]),
        ..same()
    };
    assert!(check_action(true, &mut net, None)
        .unwrap_err()
        .contains("network path"));
}

// --------------------------------------------------- running a program

/// A scratch folder for one test's scripts.
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pw-actions-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An `[[action]]` block running a script: PowerShell on Windows, sh
/// elsewhere.
fn script(dir: &Path, ps: &str, sh: &str, timeout: u64) -> ActionConfig {
    let command = if cfg!(windows) {
        let p = dir.join("action.ps1");
        std::fs::write(&p, ps).unwrap();
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
        let p = dir.join("action.sh");
        std::fs::write(&p, sh).unwrap();
        vec!["sh".into(), p.display().to_string()]
    };
    ActionConfig {
        name: "test".into(),
        command: Some(command),
        timeout_seconds: timeout,
        ..ActionConfig::default()
    }
}

fn run_it(a: &ActionConfig) -> (Outcome, Vec<String>) {
    let mut lines = Vec::new();
    let req = json!({ "schema": REQUEST_SCHEMA, "kind": "run", "dry_run": true });
    let out = run(
        a,
        &req,
        &mut |l| lines.push(l.to_string()),
        &CancelHandle::new(),
    )
    .unwrap();
    (out, lines)
}

#[test]
fn a_missing_or_broken_result_is_a_failed_run_with_its_output() {
    let dir = scratch("missing");
    let a = script(
        &dir,
        "[Console]::Out.WriteLine('Signing in'); [Console]::Error.WriteLine('no token'); exit 0\n",
        "echo 'Signing in'; echo 'no token' >&2; exit 0\n",
        60,
    );
    let (out, lines) = run_it(&a);
    assert!(!out.ok);
    assert_eq!(out.message, "It ended without a result (exit code 0).");
    assert_eq!(lines, ["Signing in"]);
    assert_eq!(out.progress, ["Signing in"]);
    assert_eq!(out.details, "no token");
    assert_eq!(out.ended, Ended::Exited);
    assert!(out.dry_run);

    let a = script(
        &dir,
        "[IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{\"ok\": tru'); exit 0\n",
        "printf '{\"ok\": tru' > \"$PATHWARDEN_ACTION_RESULT\"\n",
        60,
    );
    let (out, _) = run_it(&a);
    assert!(!out.ok);
    assert!(
        out.message
            .starts_with("Its result couldn't be read: The result isn't JSON"),
        "{}",
        out.message
    );

    // A result that says it worked, from a program that failed.
    let a = script(
        &dir,
        "[IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{\"schema\":\"pathwarden.action-result.v1\",\"ok\":true,\"message\":\"Sent\"}'); exit 3\n",
        "printf '{\"schema\":\"pathwarden.action-result.v1\",\"ok\":true,\"message\":\"Sent\"}' > \"$PATHWARDEN_ACTION_RESULT\"; exit 3\n",
        60,
    );
    let (out, _) = run_it(&a);
    assert!(!out.ok);
    assert_eq!(out.message, "Sent");
    assert_eq!(out.status, "exit code 3");
    assert_eq!(
        out.problems,
        ["It said it worked, but ended with exit code 3."]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The request arrives on stdin with its kind in the environment, and the
/// answer file is removed afterwards.
#[test]
fn a_program_gets_the_request_and_its_result_is_read() {
    let dir = scratch("roundtrip");
    let seen = dir.join("seen.txt");
    let s = seen.display().to_string();
    let result = r#"{"schema":"pathwarden.action-result.v1","ok":true,"message":"Opened","records":[{"id":"1","open":true}]}"#;
    let a = script(
        &dir,
        &format!(
            "$req = [Console]::In.ReadToEnd() | ConvertFrom-Json\n\
             [IO.File]::WriteAllText('{s}', \"$env:PATHWARDEN_ACTION_REQUEST $($req.kind) $env:PATHWARDEN_ACTION_RESULT\")\n\
             [Console]::Out.WriteLine('one'); [Console]::Out.WriteLine(''); [Console]::Out.WriteLine('two')\n\
             [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{result}')\n"
        ),
        &format!(
            "req=$(cat)\n\
             case \"$req\" in *'\"kind\":\"run\"'*) kind=run;; *) kind=other;; esac\n\
             printf '%s %s %s' \"$PATHWARDEN_ACTION_REQUEST\" \"$kind\" \"$PATHWARDEN_ACTION_RESULT\" > '{s}'\n\
             echo one; echo; echo two\n\
             printf '%s' '{result}' > \"$PATHWARDEN_ACTION_RESULT\"\n"
        ),
        60,
    );
    let (out, lines) = run_it(&a);
    assert!(out.ok, "{out:?}");
    assert_eq!(out.message, "Opened");
    assert_eq!(out.records[0].id, "1");
    assert_eq!(lines, ["one", "two"]);
    let seen = std::fs::read_to_string(&seen).unwrap();
    let mut parts = seen.splitn(3, ' ');
    assert_eq!(parts.next(), Some("run"));
    assert_eq!(parts.next(), Some("run"));
    let answer = PathBuf::from(parts.next().unwrap().trim());
    assert!(
        answer.starts_with(plugins::work_dir().unwrap()),
        "{}",
        answer.display()
    );
    assert!(!answer.exists(), "the answer file is removed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancel stops the program and every process it started.
#[test]
fn cancel_kills_the_whole_tree() {
    let dir = scratch("cancel");
    // The grandchild writes `alive` at once and `marker` 8 s later: the
    // cancel comes only once it is running, so a slow start can't make
    // this pass.
    let alive = dir.join("grandchild-is-running");
    let marker = dir.join("grandchild-was-here");
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let (al, m) = (q(&alive), q(&marker));
    let a = script(
        &dir,
        &format!(
            "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Set-Content -LiteralPath ''{al}'' x; Start-Sleep -Seconds 8; Set-Content -LiteralPath ''{m}'' x'\n\
             [Console]::Error.WriteLine('working on it')\n\
             [Console]::Out.WriteLine('started'); [Console]::Out.Flush()\nStart-Sleep -Seconds 120\n"
        ),
        &format!(
            "(touch '{al}'; sleep 8; touch '{m}') &\necho 'working on it' >&2\necho started\nsleep 120\n"
        ),
        300,
    );
    let cancel = CancelHandle::new();
    let c = cancel.clone();
    let watched = alive.clone();
    std::thread::spawn(move || {
        // Busy Windows runners can take over a minute to start PowerShell;
        // the program itself sleeps 120 s.
        let until = std::time::Instant::now() + Duration::from_secs(100);
        while !watched.exists() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        c.cancel();
    });
    let req = json!({ "schema": REQUEST_SCHEMA, "kind": "run", "dry_run": false });
    let out = run(&a, &req, &mut |_| {}, &cancel).unwrap();
    let stopped = std::time::Instant::now();
    assert!(alive.exists(), "the grandchild never started");
    assert_eq!(out.ended, Ended::Cancelled);
    assert!(!out.ok);
    assert_eq!(out.message, "Canceled before it finished.");
    assert_eq!(out.progress, ["started"]);
    // What it wrote to stderr before the cancel is kept.
    assert_eq!(out.details, "working on it");
    std::thread::sleep(Duration::from_secs(12).saturating_sub(stopped.elapsed()));
    assert!(!marker.exists(), "the grandchild outlived the cancel");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_slow_program_is_stopped_at_its_time_limit() {
    let dir = scratch("slow");
    let a = script(
        &dir,
        "[Console]::Error.WriteLine('still signing in'); Start-Sleep -Seconds 60\n",
        "echo 'still signing in' >&2; sleep 60\n",
        2,
    );
    let (out, _) = run_it(&a);
    assert_eq!(out.ended, Ended::TimedOut);
    assert_eq!(out.details, "still signing in");
    assert_eq!(
        out.message,
        "It took longer than 2 seconds, its time limit, and was stopped."
    );
    assert_eq!(out.status, "stopped after 2 s");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `describe` is asked once and kept until the script changes; a broken
/// one is an error with every problem.
#[test]
fn describe_is_kept_until_the_script_changes() {
    let dir = scratch("describe");
    let count = dir.join("count.txt");
    let c = count.display().to_string();
    let body = |label: &str| {
        let doc = format!(
            r#"{{"schema":"pathwarden.action-describe.v1","actions":[{{"id":"a","label":"{label}","sends":"x"}}]}}"#
        );
        (
            format!(
                "Add-Content -LiteralPath '{c}' x\n\
                 [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{doc}')\n"
            ),
            format!(
                "echo x >> '{c}'\n\
                 printf '%s' '{doc}' > \"$PATHWARDEN_ACTION_RESULT\"\n"
            ),
        )
    };
    let (ps, sh) = body("First");
    let a = script(&dir, &ps, &sh, 60);
    let runs = || {
        std::fs::read_to_string(&count)
            .unwrap_or_default()
            .lines()
            .count()
    };
    assert_eq!(describe(&a).unwrap().describe.actions[0].label, "First");
    assert_eq!(describe(&a).unwrap().describe.actions[0].label, "First");
    assert_eq!(runs(), 1);
    let (ps, sh) = body("Second");
    let a = script(&dir, &ps, &sh, 60);
    assert_eq!(describe(&a).unwrap().describe.actions[0].label, "Second");
    assert_eq!(runs(), 2);
    // Other settings: asked again.
    let mut b = a.clone();
    b.settings.insert("group".into(), json!("x"));
    describe(&b).unwrap();
    assert_eq!(runs(), 3);

    let a = script(
        &dir,
        "[IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{\"schema\":\"pathwarden.action-describe.v1\"}')\n",
        "printf '{\"schema\":\"pathwarden.action-describe.v1\"}' > \"$PATHWARDEN_ACTION_RESULT\"\n",
        60,
    );
    let e = describe(&a).unwrap_err().to_string();
    assert_eq!(
        e,
        "test sent a list of actions Pathwarden can't read: actions must be a list of the actions the program offers"
    );
    let a = script(&dir, "exit 0\n", "exit 0\n", 60);
    let e = describe_fresh(&a, &mut |_| {}, &CancelHandle::new())
        .unwrap_err()
        .to_string();
    assert_eq!(
        e,
        "test sent a list of actions Pathwarden can't read: it wrote nothing to the file named in PATHWARDEN_ACTION_RESULT"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn streamed_lines_are_cleaned_and_capped() {
    let dir = scratch("lines");
    let a = script(
        &dir,
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         1..250 | ForEach-Object { [Console]::Out.WriteLine(\"line $_\") }\n\
         [Console]::Out.WriteLine('x' * 600)\n\
         [Console]::Out.WriteLine(\"bad$([char]27)[2J$([char]0x202e)end\")\n",
        "i=1; while [ $i -le 250 ]; do echo \"line $i\"; i=$((i+1)); done\n\
         printf 'x%.0s' $(seq 1 600); echo\n\
         printf 'bad\\033[2J\\342\\200\\256end\\n'\n",
        60,
    );
    let (out, lines) = run_it(&a);
    assert_eq!(lines.len(), 252);
    assert_eq!(out.progress.len(), plugins::MAX_PROGRESS_LINES);
    assert_eq!(out.progress[0], "line 53");
    assert_eq!(out.progress[198].chars().count(), plugins::MAX_LINE_CHARS);
    assert_eq!(out.progress[199], "bad[2Jend");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A broken describe isn't asked again for every finding shown.
#[test]
fn a_failed_describe_is_kept_a_while() {
    let dir = scratch("failed-describe");
    let count = dir.join("count.txt");
    let c = count.display().to_string();
    let a = script(
        &dir,
        &format!("Add-Content -LiteralPath '{c}' x\nexit 1\n"),
        &format!("echo x >> '{c}'\nexit 1\n"),
        60,
    );
    let e = describe(&a).unwrap_err().to_string();
    assert_eq!(
        e,
        "test sent a list of actions Pathwarden can't read: it stopped with exit code 1"
    );
    assert_eq!(describe(&a).unwrap_err().to_string(), e);
    let runs = std::fs::read_to_string(&count).unwrap_or_default();
    assert_eq!(runs.lines().count(), 1);
    assert_eq!(FAILED_DESCRIBE_KEPT, Duration::from_secs(30));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hidden_characters_in_defaults_and_field_names_are_refused() {
    for default in ["a\u{7}b", "a\u{202e}b", "a\nb"] {
        let (d, p) = one(json!({ "id": "a", "label": "A", "sends": "x",
            "inputs": [{ "id": "n", "label": "N", "type": "text", "default": default }] }))
        .unwrap();
        assert!(d.actions.is_empty(), "{default:?}");
        assert_eq!(
            p,
            ["actions[0].inputs[0].default must be text no longer than max, without control characters"]
        );
    }
    // A textarea's default may have lines.
    let (d, _) = one(json!({ "id": "a", "label": "A", "sends": "x",
        "inputs": [{ "id": "n", "label": "N", "type": "textarea", "default": "a\nb" }] }))
    .unwrap();
    assert_eq!(d.actions.len(), 1);
    let (res, p) = parse_result(
        json!({ "schema": RESULT_SCHEMA, "ok": true, "records": [
            { "id": "r", "fields": { "Queue": "a", "Queue\u{7}": "b" } } ] })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(res.records[0].fields.len(), 1);
    assert_eq!(
        p,
        ["records[0].fields name 'Queue' is there twice once cleaned; the second was left out"]
    );
}

/// A pipe in place of the result file is refused, not waited on.
#[cfg(unix)]
#[test]
fn a_result_that_isnt_a_file_is_refused() {
    let dir = scratch("fifo");
    let a = script(&dir, "", "mkfifo \"$PATHWARDEN_ACTION_RESULT\"\n", 60);
    let started = std::time::Instant::now();
    let (out, _) = run_it(&a);
    assert!(!out.ok);
    assert_eq!(out.message, "The result file isn't a plain file.");
    assert!(started.elapsed() < Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `when`: without one, open, held and accepted findings; a fixed finding
/// only the actions that list `fixed`, and the follow-ups on its records.
/// A string is a list of one, as #4's `"when": "fixed"` was.
#[test]
fn when_says_where_a_finding_must_stand() {
    let c = Config::parse("[[action]]\nplugin = \"desk\"\n").unwrap();
    let d = described(
        r#"{"schema":"pathwarden.action-describe.v1","actions":[
          {"id":"open","label":"Open","sends":"x","follow_ups":["status","close"]},
          {"id":"any","label":"Any","sends":"x","when":["open","held","accepted","fixed"]},
          {"id":"done","label":"Done","sends":"x","when":"fixed"},
          {"id":"open-only","label":"Open only","sends":"x","when":["open"]},
          {"id":"status","label":"Status","sends":"x","for":"record"},
          {"id":"close","label":"Close","sends":"x","for":"record","when":["fixed"]}]}"#,
    );
    assert_eq!(d.actions[0].when, None);
    assert_eq!(d.actions[2].when, Some(vec![FindingStatus::Fixed]));
    let programs = [Program {
        config: &c.actions[0],
        describe: &d,
    }];
    let e = event();
    let at = |fp: &str| {
        addresses(&offered(&programs, &finding_in_event(&e, fp).unwrap(), &[]))
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        at("PW-001-aaaa"),
        ["desk/open", "desk/any", "desk/open-only"]
    );
    assert_eq!(at("PW-011-bbbb"), ["desk/open", "desk/any"]);
    assert_eq!(at("PW-004-dddd"), ["desk/open", "desk/any"]);
    assert_eq!(at("PW-003-cccc"), ["desk/any", "desk/done"]);
    // Follow-ups on a record: without `when`, however the finding stands.
    let r = rec("desk/open", true);
    let fixed = finding_in_event(&e, "PW-003-cccc").unwrap();
    assert_eq!(
        addresses(&follow_ups(&programs, &fixed, &r)),
        ["desk/status", "desk/close"]
    );
    let held = finding_in_event(&e, "PW-004-dddd").unwrap();
    assert_eq!(
        addresses(&follow_ups(&programs, &held, &r)),
        ["desk/status"]
    );
    // Every value in words; a list must say something.
    let bad = |when: Value| {
        one(json!({ "id": "a", "label": "A", "sends": "x", "when": when }))
            .unwrap()
            .1
    };
    assert_eq!(
        bad(json!([])),
        ["actions[0].when must list at least one of open, held, accepted, fixed"]
    );
    assert_eq!(
        bad(json!(["open", "soon"])),
        ["actions[0].when[1] \"soon\" isn't one of open, held, accepted, fixed"]
    );
    assert_eq!(
        bad(json!(3)),
        ["actions[0].when 3 isn't one of open, held, accepted, fixed"]
    );
    let (d, p) =
        one(json!({ "id": "a", "label": "A", "sends": "x", "when": ["fixed", "fixed", "open"] }))
            .unwrap();
    assert!(p.is_empty(), "{p:?}");
    assert_eq!(
        d.actions[0].when,
        Some(vec![FindingStatus::Fixed, FindingStatus::Open])
    );
    // It reads back as a list.
    assert_eq!(
        serde_json::to_value(&d.actions[0]).unwrap()["when"],
        json!(["fixed", "open"])
    );
}

/// With a record, the action is one of that record's follow-ups, and the
/// request carries the record.
#[test]
fn a_follow_up_is_prepared_on_a_record() {
    let c = config();
    let d = desk();
    let programs = [Program {
        config: &c.actions[0],
        describe: &d,
    }];
    let e = event();
    let open = finding_in_event(&e, "PW-001-aaaa").unwrap();
    let records = [rec("service-desk/open", true)];
    let ask = Ask {
        action: Some("service-desk/status".into()),
        record: Some("R1".into()),
        ..Ask::default()
    };
    let p = prepare(&programs, &open, &records, &ask).unwrap();
    assert_eq!(p.offered.address, "service-desk/status");
    assert_eq!(p.request["record"]["id"], "r1");
    assert_eq!(p.record.as_ref().unwrap().action, "service-desk/open");
    // The one follow-up that applies needs no name.
    let only = Ask {
        record: Some("r1".into()),
        ..Ask::default()
    };
    assert_eq!(
        prepare(&programs, &open, &records, &only)
            .unwrap()
            .offered
            .address,
        "service-desk/status"
    );
    // Named without its record; a record that isn't there.
    let bare = Ask {
        action: Some("service-desk/status".into()),
        ..Ask::default()
    };
    assert_eq!(
        prepare(&programs, &open, &records, &bare).unwrap_err(),
        "Check status runs on a record of this finding: name one of r1."
    );
    let gone = Ask {
        record: Some("r9".into()),
        ..Ask::default()
    };
    assert_eq!(
        prepare(&programs, &open, &records, &gone).unwrap_err(),
        "This finding has no record r9. Its records: r1."
    );
    // Close waits for a fix; on an open finding it isn't offered.
    let close = Ask {
        action: Some("service-desk/close".into()),
        record: Some("r1".into()),
        ..Ask::default()
    };
    assert!(prepare(&programs, &open, &records, &close)
        .unwrap_err()
        .contains("doesn't apply to this record"));
}

/// A record ID as given is matched first; another case only when it means
/// one record; two of one action are told apart in words.
#[test]
fn records_are_found_by_their_id() {
    let mut a = rec("desk/open", true);
    a.record.id = "ab".into();
    let mut b = rec("desk/open", true);
    b.record.id = "AB".into();
    let both = [a.clone(), b.clone()];
    assert_eq!(find_record(&both, "AB").unwrap().record.id, "AB");
    assert_eq!(find_record(&both, "ab").unwrap().record.id, "ab");
    assert_eq!(
        find_record(&both, "Ab").unwrap_err(),
        "This finding has 2 records Ab from desk/open (their IDs differ only in case), so it can't be told which: give its ID exactly."
    );
    let mut c = rec("alert/send", true);
    c.record.id = "ab".into();
    let two = [a.clone(), c];
    assert_eq!(
        find_record(&two, "ab").unwrap_err(),
        "Several actions made a record ab on this finding (desk/open, alert/send), so it can't be told which."
    );
    assert_eq!(find_record(&[a], "AB").unwrap().record.id, "ab");
}
