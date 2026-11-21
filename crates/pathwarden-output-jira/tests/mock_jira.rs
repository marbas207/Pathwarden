//! The plugin end to end against a small fake Jira Cloud (REST v3) on
//! loopback: issues open, stay quiet, close by retest, reopen on
//! regression, and issues another account created are never touched.
//!
//! The fake implements only what the plugin calls, the way Atlassian's
//! documentation describes it; it is not a substitute for a live instance.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

#[derive(Clone, Debug)]
struct FakeIssue {
    key: String,
    labels: Vec<String>,
    category: &'static str,
    resolution: Option<String>,
    creator: String,
    summary: String,
    priority: Option<String>,
    comments: Vec<Value>,
}

#[derive(Default)]
struct Fake {
    issues: Vec<FakeIssue>,
    next: u32,
    /// `/myself` fails (a Jira that doesn't say who the account is).
    no_myself: bool,
    /// (method, path, authorization, body)
    log: Vec<(String, String, String, Value)>,
}

type Shared = Arc<Mutex<Fake>>;

const ME: &str = "acc-svc";

fn start() -> (String, Shared) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fake: Shared = Arc::new(Mutex::new(Fake {
        next: 1,
        ..Default::default()
    }));
    let f = fake.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream, &f);
        }
    });
    (url, fake)
}

fn serve(mut stream: TcpStream, fake: &Shared) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let (mut len, mut auth) = (0usize, String::new());
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (name, value) = h.split_once(':').unwrap();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => len = value.trim().parse().unwrap(),
            "authorization" => auth = value.trim().to_string(),
            _ => {}
        }
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let (status, reply) = handle(fake, &method, &path, &auth, body);
    let text = if reply.is_null() {
        String::new()
    } else {
        reply.to_string()
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
}

fn issue_json(i: &FakeIssue) -> Value {
    json!({
        "id": "1", "key": i.key,
        "fields": {
            "labels": i.labels,
            "status": { "statusCategory": { "key": i.category } },
            "resolution": i.resolution.as_ref().map(|r| json!({ "name": r })),
            "creator": { "accountId": i.creator },
        }
    })
}

fn handle(fake: &Shared, method: &str, path: &str, auth: &str, body: Value) -> (u16, Value) {
    let mut f = fake.lock().unwrap();
    f.log
        .push((method.into(), path.into(), auth.into(), body.clone()));
    if auth != format!("Basic {}", b64("svc@contoso.com:s3cret-token")) {
        return (401, json!({ "errorMessages": ["unauthorized"] }));
    }
    let segs: Vec<&str> = path.trim_start_matches("/rest/api/3/").split('/').collect();
    match (method, segs.as_slice()) {
        ("GET", ["myself"]) if f.no_myself => (404, json!({ "errorMessages": ["no"] })),
        ("GET", ["myself"]) => (200, json!({ "accountId": ME })),
        ("POST", ["search", "jql"]) => {
            let jql = body["jql"].as_str().unwrap();
            assert!(
                jql.starts_with("project = \"SEC\" AND labels = \"pathwarden\""),
                "{jql}"
            );
            // One per page, to exercise nextPageToken. The creator clause is
            // ignored on purpose: the plugin must filter on its own too.
            let start: usize = body["nextPageToken"]
                .as_str()
                .map_or(0, |t| t.parse().unwrap());
            let matching: Vec<&FakeIssue> = f
                .issues
                .iter()
                .filter(|i| i.labels.iter().any(|l| l == "pathwarden"))
                .collect();
            let page: Vec<Value> = matching
                .iter()
                .skip(start)
                .take(1)
                .map(|i| issue_json(i))
                .collect();
            let last = start + 1 >= matching.len();
            let mut reply = json!({ "issues": page, "isLast": last });
            if !last {
                reply["nextPageToken"] = (start + 1).to_string().into();
            }
            (200, reply)
        }
        ("POST", ["issue"]) => {
            let fields = &body["fields"];
            assert_eq!(fields["project"]["key"], "SEC");
            assert_eq!(fields["issuetype"]["name"], "Task");
            assert_eq!(fields["description"]["type"], "doc", "ADF on Cloud");
            let key = format!("SEC-{}", f.next);
            f.next += 1;
            f.issues.push(FakeIssue {
                key: key.clone(),
                labels: serde_json::from_value(fields["labels"].clone()).unwrap(),
                category: "new",
                resolution: None,
                creator: ME.into(),
                summary: fields["summary"].as_str().unwrap().into(),
                priority: fields["priority"]["name"].as_str().map(str::to_string),
                comments: vec![],
            });
            (201, json!({ "id": "10000", "key": key }))
        }
        ("POST", ["issue", key, "comment"]) => {
            let Some(i) = f.issues.iter_mut().find(|i| i.key == *key) else {
                return (404, json!({ "errorMessages": ["Issue does not exist"] }));
            };
            assert_eq!(body["body"]["type"], "doc");
            i.comments.push(body["body"].clone());
            (201, json!({ "id": "1" }))
        }
        ("GET", ["issue", key, "transitions"]) => {
            let Some(i) = f.issues.iter().find(|i| i.key == *key) else {
                return (404, json!({ "errorMessages": ["Issue does not exist"] }));
            };
            let t = if i.category == "done" {
                json!([{ "id": "11", "name": "Reopen", "to": { "statusCategory": { "key": "new" } } }])
            } else {
                json!([
                    { "id": "21", "name": "Start", "to": { "statusCategory": { "key": "indeterminate" } } },
                    { "id": "31", "name": "Done", "to": { "statusCategory": { "key": "done" } } }
                ])
            };
            (200, json!({ "transitions": t }))
        }
        ("POST", ["issue", key, "transitions"]) => {
            let Some(i) = f.issues.iter_mut().find(|i| i.key == *key) else {
                return (404, json!({ "errorMessages": ["Issue does not exist"] }));
            };
            match body["transition"]["id"].as_str() {
                Some("31") => {
                    i.category = "done";
                    i.resolution = Some("Done".into());
                }
                Some("11") => {
                    i.category = "new";
                    i.resolution = None;
                }
                other => {
                    return (
                        400,
                        json!({ "errorMessages": [format!("bad transition {other:?}")] }),
                    )
                }
            }
            (204, Value::Null)
        }
        _ => (
            404,
            json!({ "errorMessages": [format!("no route {method} {path}")] }),
        ),
    }
}

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].iter().enumerate() {
            out.push(if i <= c.len() {
                T[(n >> shift) as usize & 63] as char
            } else {
                '='
            });
        }
    }
    out
}

fn finding(fp: &str, change: &str, severity: &str) -> Value {
    json!({
        "change": change, "rule": "PW-003", "category": "attack_path", "severity": severity,
        "fingerprint": fp, "title": format!("{fp}: [evil](https://x) has GenericAll on DA"),
        "rule_title": "Account or group outside Tier Zero controls a Tier Zero object",
        "domain": "CONTOSO.LOCAL", "summary": "why", "remediation": "fix",
        "affected": [{ "name": "ALICE@CONTOSO.LOCAL", "kind": "User" }],
        "suppressed": null
    })
}

fn event(run: &str, findings: Vec<Value>) -> String {
    json!({
        "schema": "pathwarden.event.v1",
        "run": { "run_id": run },
        "findings": findings,
        "guides": { "PW-003": "# PW-003: Guide\n\n## Fix\nDo it." }
    })
    .to_string()
}

fn plugin(url: &str, extra: Value, event: &str) -> (bool, String, String) {
    let mut settings = json!({ "instance": url, "project": "SEC" });
    for (k, v) in extra.as_object().unwrap() {
        settings[k] = v.clone();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_pathwarden-output-jira"))
        .env("PATHWARDEN_OUTPUT_SETTINGS", settings.to_string())
        .env("PATHWARDEN_JIRA_USER", "svc@contoso.com")
        .env("PATHWARDEN_JIRA_TOKEN", "s3cret-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn issues_follow_the_findings() {
    let (url, fake) = start();
    let fps = [
        "PW-003-aaaaaaaaaaaaaaaa",
        "PW-003-bbbbbbbbbbbbbbbb",
        "PW-003-cccccccccccccccc",
    ];

    // Run 1: three new findings (one below min_severity).
    let ev = event(
        "R1",
        vec![
            finding(fps[0], "new", "critical"),
            finding(fps[1], "new", "high"),
            finding(fps[2], "new", "low"),
        ],
    );
    let (ok, out, err) = plugin(&url, json!({}), &ev);
    assert!(ok, "{out}\n{err}");
    assert!(
        out.contains("2 created, 0 commented, 0 reopened, 0 closed"),
        "{out}"
    );
    {
        let f = fake.lock().unwrap();
        assert_eq!(f.issues.len(), 2);
        let a = &f.issues[0];
        assert_eq!(a.labels, ["pathwarden", &format!("pwfp-{}", fps[0])]);
        assert_eq!(a.priority.as_deref(), Some("Highest"));
        assert_eq!(
            a.summary,
            "Account or group outside Tier Zero controls a Tier Zero object"
        );
        // The secret only ever travels in the Authorization header.
        assert!(f
            .log
            .iter()
            .all(|(_, p, _, b)| !p.contains("s3cret") && !b.to_string().contains("s3cret")));
    }

    // Run 2, same findings: nothing changes (idempotent).
    let (ok, out, _) = plugin(&url, json!({}), &ev.replace("\"new\"", "\"open\""));
    assert!(ok);
    assert!(
        out.contains("0 created, 0 commented, 0 reopened, 0 closed"),
        "{out}"
    );

    // Run 3: the first finding is fixed; its issue closes with a note.
    let ev3 = event("R3", vec![finding(fps[1], "open", "high")]);
    let (ok, out, err) = plugin(&url, json!({}), &ev3);
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("closed SEC-1"), "{out}");
    {
        let f = fake.lock().unwrap();
        assert_eq!(f.issues[0].category, "done");
        assert_eq!(f.issues[0].comments.len(), 1);
        assert!(f.issues[0].comments[0]
            .to_string()
            .contains("No longer present in Pathwarden run R3"));
    }

    // Run 4: it is back (regressed): the closed issue reopens.
    let ev4 = event(
        "R4",
        vec![
            finding(fps[0], "regressed", "critical"),
            finding(fps[1], "open", "high"),
        ],
    );
    let (ok, out, err) = plugin(&url, json!({}), &ev4);
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("reopened SEC-1"), "{out}");
    assert_eq!(fake.lock().unwrap().issues[0].category, "new");
}

#[test]
fn issues_created_by_others_are_ignored_with_created_by() {
    let (url, fake) = start();
    {
        // Mallory labelled her own issue as a Pathwarden finding that is gone.
        let mut f = fake.lock().unwrap();
        for (n, creator) in [(90, "mallory"), (91, ME)] {
            f.issues.push(FakeIssue {
                key: format!("SEC-{n}"),
                labels: vec!["pathwarden".into(), format!("pwfp-PW-001-{n}")],
                category: "new",
                resolution: None,
                creator: creator.into(),
                summary: "x".into(),
                priority: None,
                comments: vec![],
            });
        }
    }
    let ev = event("R1", vec![]);
    // Without created_by, it defaults to the account the plugin signs in
    // as: her issue is named and left alone.
    let (_, out, err) = plugin(&url, json!({ "dry_run": true }), &ev);
    assert!(err.contains("SEC-90 (by mallory)"), "{err}");
    assert!(err.contains("never closed or reopened"), "{err}");
    assert!(
        out.contains("would close SEC-91") && !out.contains("SEC-90"),
        "{out}"
    );
    // When Jira doesn't say who the account is: matched by labels, as
    // before, with a warning.
    fake.lock().unwrap().no_myself = true;
    let (_, out, err) = plugin(&url, json!({ "dry_run": true }), &ev);
    assert!(
        err.contains("could not tell which account this is"),
        "{err}"
    );
    assert!(
        out.contains("would close SEC-90") && out.contains("would close SEC-91"),
        "{out}"
    );
    fake.lock().unwrap().no_myself = false;
    // With created_by, it is invisible: only our own issue is closed.
    let (ok, out, err) = plugin(&url, json!({ "created_by": ME }), &ev);
    assert!(ok, "{out}\n{err}");
    assert!(
        out.contains("closed SEC-91") && !out.contains("SEC-90"),
        "{out}"
    );
    let f = fake.lock().unwrap();
    assert_eq!(f.issues[0].category, "new", "mallory's issue untouched");
    assert!(f.log.iter().any(|(_, _, _, b)| b["jql"]
        .as_str()
        .is_some_and(|q| q.contains("creator = \"acc-svc\""))));
}

#[test]
fn http_errors_are_reported_without_secrets() {
    let (url, _fake) = start();
    let mut child_env_wrong = Command::new(env!("CARGO_BIN_EXE_pathwarden-output-jira"))
        .env(
            "PATHWARDEN_OUTPUT_SETTINGS",
            json!({ "instance": url, "project": "SEC" }).to_string(),
        )
        .env("PATHWARDEN_JIRA_USER", "svc@contoso.com")
        .env("PATHWARDEN_JIRA_TOKEN", "wrong-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_env_wrong
        .stdin
        .take()
        .unwrap()
        .write_all(event("R1", vec![]).as_bytes())
        .unwrap();
    let out = child_env_wrong.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("HTTP 401") && err.contains("unauthorized"),
        "{err}"
    );
    assert!(!err.contains("wrong-secret"), "{err}");
}

#[test]
fn offline_dry_run_and_refusals() {
    // No credentials: a dry run previews creates without touching Jira.
    let mut child = Command::new(env!("CARGO_BIN_EXE_pathwarden-output-jira"))
        .args(["--dry-run"])
        .env(
            "PATHWARDEN_OUTPUT_SETTINGS",
            json!({ "instance": "https://contoso.atlassian.net", "project": "SEC", "username_env": "PW_NOPE_1", "token_env": "PW_NOPE_2" }).to_string(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            event(
                "R1",
                vec![finding("PW-003-dddddddddddddddd", "new", "high")],
            )
            .as_bytes(),
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("offline preview") && stdout.contains("would create"),
        "{stdout}"
    );

    // An event without findings is refused before any call.
    let (url, fake) = start();
    let (ok, _, err) = plugin(
        &url,
        json!({}),
        r#"{"schema":"pathwarden.event.v1","run":{"run_id":"R"}}"#,
    );
    assert!(!ok && err.contains("findings"), "{err}");
    assert!(fake.lock().unwrap().log.is_empty());
}

/// [`plugin`] with Pathwarden's result file named: what it wrote there,
/// `None` when it wrote nothing.
fn plugin_reporting(url: &str, extra: Value, event: &str) -> (bool, Option<Value>) {
    let dir = std::env::temp_dir().join(format!(
        "pw-jira-result-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("output-result.json");
    let mut settings = json!({ "instance": url, "project": "SEC" });
    for (k, v) in extra.as_object().unwrap() {
        settings[k] = v.clone();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_pathwarden-output-jira"))
        .env("PATHWARDEN_OUTPUT_SETTINGS", settings.to_string())
        .env("PATHWARDEN_JIRA_USER", "svc@contoso.com")
        .env("PATHWARDEN_JIRA_TOKEN", "s3cret-token")
        .env("PATHWARDEN_OUTPUT_RESULT", &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.as_bytes())
        .unwrap();
    let ok = child.wait().unwrap().success();
    let got = std::fs::read(&path)
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    (ok, got)
}

/// A real run hands Pathwarden the issues it keeps (created, closed);
/// a dry run writes nothing.
#[test]
fn the_result_file_lists_the_issues_on_real_runs_only() {
    let (url, _fake) = start();
    let (a, b) = ("PW-003-aaaaaaaaaaaaaaaa", "PW-003-bbbbbbbbbbbbbbbb");
    let ev = event(
        "R1",
        vec![finding(a, "new", "critical"), finding(b, "new", "high")],
    );
    let (ok, got) = plugin_reporting(&url, json!({ "dry_run": true }), &ev);
    assert!(ok);
    assert_eq!(got, None, "a dry run writes no result");

    let (ok, got) = plugin_reporting(&url, json!({}), &ev);
    assert!(ok);
    let got = got.expect("a real run writes its result");
    assert_eq!(got["schema"], "pathwarden.output-result.v1");
    let recs = got["records"].as_array().unwrap();
    assert_eq!(recs.len(), 2, "{got}");
    assert_eq!(recs[0]["fingerprint"], a);
    assert_eq!(recs[0]["number"], "SEC-1");
    assert_eq!(recs[0]["open"], true);
    // A plain-http (loopback) instance gets no link.
    assert!(recs[0].get("url").is_none(), "{got}");

    // The first finding is fixed: its issue is closed, and said so.
    let ev2 = event("R2", vec![finding(b, "open", "high")]);
    let (ok, got) = plugin_reporting(&url, json!({}), &ev2);
    assert!(ok);
    let got = got.unwrap();
    let recs = got["records"].as_array().unwrap();
    let closed = recs.iter().find(|r| r["fingerprint"] == a).unwrap();
    assert_eq!(closed["open"], false);
    assert_eq!(closed["status"], "Done");
    let open = recs.iter().find(|r| r["fingerprint"] == b).unwrap();
    assert_eq!(
        (open["number"].as_str(), open["open"].as_bool()),
        (Some("SEC-2"), Some(true))
    );
}
