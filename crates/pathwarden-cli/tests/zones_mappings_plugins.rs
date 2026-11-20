//! `pathwarden zones`, `mappings` and `plugins`: the Privilege Zones,
//! Mappings and Ticketing pages from the terminal, through the app's own
//! code, with its checks and messages.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn err(out: &std::process::Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_str(&ok(out)).unwrap()
}

/// A scratch folder with a UI workspace `ws` holding one saved analysis of
/// the forest fixture (CONTOSO.LOCAL).
fn workspace(name: &str) -> (PathBuf, String) {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-cli-zmp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    ok(&run(
        &dir,
        &[
            "run",
            "--save",
            "--workspace",
            "ws",
            "-i",
            forest.to_str().unwrap(),
        ],
    ));
    let ws = dir.join("ws").to_str().unwrap().to_string();
    (dir, ws)
}

#[test]
fn zones_are_added_changed_previewed_and_removed() {
    let (dir, ws) = workspace("zones");
    let ws = ws.as_str();
    let forest = repo("testdata/forest");
    let input = forest.to_str().unwrap();

    let out = ok(&run(
        &dir,
        &[
            "zones",
            "add",
            "Helpdesk",
            "--group",
            "HELPDESK@CONTOSO.LOCAL",
            "--member",
            "NOPE.CONTOSO.LOCAL",
            "--workspace",
            ws,
        ],
    ));
    assert!(out.contains("Saved: zone Helpdesk"), "{out}");
    // Checked against the latest analysis, as the wizard's preview is.
    let o = run(&dir, &["zones", "list", "--workspace", ws]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Helpdesk  1 group · 1 named object"));

    // The app's refusals: Tier Zero, a name taken, nothing in it.
    for (name, why) in [
        (
            "Tier Zero",
            "Tier Zero is built in and protected above every zone",
        ),
        ("helpdesk", "There is already a zone named helpdesk."),
    ] {
        let e = err(&run(
            &dir,
            &["zones", "add", name, "--member", "A", "--workspace", ws],
        ));
        assert!(e.contains(why), "{e}");
    }
    let e = err(&run(&dir, &["zones", "add", "Empty", "--workspace", ws]));
    assert!(e.contains("Add at least one object, group or OU"), "{e}");

    // Edit: rename, add and remove entries; a missing entry is refused.
    let e = err(&run(
        &dir,
        &[
            "zones",
            "edit",
            "helpdesk",
            "--remove-ou",
            "OU=X",
            "--workspace",
            ws,
        ],
    ));
    assert!(e.contains("Not an OU of zone Helpdesk"), "{e}");
    let e = err(&run(
        &dir,
        &[
            "zones",
            "edit",
            "Helpdesk",
            "--rename",
            "tier 0",
            "--workspace",
            ws,
        ],
    ));
    assert!(e.contains("Tier Zero is built in"), "{e}");
    ok(&run(
        &dir,
        &[
            "zones",
            "edit",
            "helpdesk",
            "--rename",
            "Support",
            "--remove-member",
            "nope.contoso.local",
            "--add-ou",
            "OU=SERVERS,DC=CONTOSO,DC=LOCAL",
            "--workspace",
            ws,
        ],
    ));
    let z = json(&run(
        &dir,
        &["zones", "show", "support", "--json", "--workspace", ws],
    ));
    assert_eq!(z["name"], "Support");
    assert_eq!(z["groups"], serde_json::json!(["HELPDESK@CONTOSO.LOCAL"]));
    assert_eq!(
        z["ous"],
        serde_json::json!(["OU=SERVERS,DC=CONTOSO,DC=LOCAL"])
    );
    assert_eq!(z["members"], serde_json::json!([]));

    // Preview: core's resolution on the data, with the app's warnings. The
    // zone comes from the environment the app has current, or --env.
    let config = dir.join("ws").join("pathwarden.toml");
    let p = json(&run(
        &dir,
        &[
            "zones",
            "preview",
            "Support",
            "-c",
            config.to_str().unwrap(),
            "-i",
            input,
            "--json",
        ],
    ));
    let (g, _) = pathwarden_core::load(std::slice::from_ref(&forest), &Default::default()).unwrap();
    let def = pathwarden_core::zones::ZoneConfig {
        name: "Support".into(),
        groups: vec!["HELPDESK@CONTOSO.LOCAL".into()],
        ous: vec!["OU=SERVERS,DC=CONTOSO,DC=LOCAL".into()],
        ..Default::default()
    };
    let expected = pathwarden_core::zones::preview(&g, &def, 12);
    assert_eq!(p["preview"]["total"], expected.total, "{p}");
    assert_eq!(
        p["warnings"],
        serde_json::json!(expected.warnings("the data"))
    );
    let e = err(&run(
        &dir,
        &[
            "zones",
            "preview",
            "Nope",
            "-c",
            config.to_str().unwrap(),
            "-i",
            input,
        ],
    ));
    assert!(e.contains("No zone named 'Nope'"), "{e}");
    // --zone anywhere; a name after -i is read as an input, and said so.
    let p2 = json(&run(
        &dir,
        &[
            "zones",
            "preview",
            "-c",
            config.to_str().unwrap(),
            "-i",
            input,
            "--zone",
            "support",
            "--json",
        ],
    ));
    assert_eq!(p2["preview"]["total"], expected.total, "{p2}");
    let e = err(&run(
        &dir,
        &[
            "zones",
            "preview",
            "-c",
            config.to_str().unwrap(),
            "-i",
            input,
            "Support",
        ],
    ));
    assert!(e.contains("--zone NAME"), "{e}");
    // --workspace alone: that workspace's current environment, no -c.
    let p3 = json(&run(
        &dir,
        &[
            "zones",
            "preview",
            "Support",
            "--workspace",
            ws,
            "-i",
            input,
            "--json",
        ],
    ));
    assert_eq!(p3["preview"]["total"], expected.total, "{p3}");

    // An edit that changes nothing says so and writes nothing.
    let before = std::fs::read_to_string(&config).unwrap();
    let e = err(&run(&dir, &["zones", "edit", "Support", "--workspace", ws]));
    assert!(e.contains("Nothing to change: give --rename"), "{e}");
    let out = ok(&run(
        &dir,
        &[
            "zones",
            "edit",
            "Support",
            "--add-group",
            "helpdesk@contoso.local",
            "--workspace",
            ws,
        ],
    ));
    assert!(out.contains("Nothing to change"), "{out}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);

    ok(&run(
        &dir,
        &["zones", "remove", "SUPPORT", "--workspace", ws],
    ));
    assert_eq!(
        json(&run(&dir, &["zones", "list", "--json", "--workspace", ws])),
        serde_json::json!([])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mapping_packs_are_trusted_only_after_a_review() {
    let dir = std::env::temp_dir().join(format!("pathwarden-cli-zmp-maps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pathwarden.toml");
    let c = config.to_str().unwrap();

    let list = json(&run(&dir, &["mappings", "-c", c, "list", "--json"]));
    let packs = list["packs"].as_array().unwrap();
    let untrusted = packs
        .iter()
        .find(|p| p["trusted"] == false)
        .expect("a built-in pack that ships untrusted");
    let name = untrusted["name"].as_str().unwrap();

    // Show: what the review is of, the pack card opened.
    let show = json(&run(&dir, &["mappings", "-c", c, "show", name, "--json"]));
    assert_eq!(show["name"], name);
    assert_eq!(show["trust"], "Untrusted mapping: context only");
    let edges = show["relationship_kinds"].as_array().unwrap();
    assert_eq!(
        edges.len() as u64,
        untrusted["relationship_kinds"].as_u64().unwrap()
    );
    let traversable = edges.iter().find(|e| e["traversable"] == true);
    if let Some(t) = traversable {
        assert_eq!(t["role"], "Path once trusted");
        assert_eq!(t["attack_path"], false);
    }
    let text = ok(&run(&dir, &["mappings", "-c", c, "show", name]));
    assert!(text.contains("[Untrusted mapping: context only]"), "{text}");
    if let Some(t) = traversable {
        let kind = t["kind"].as_str().unwrap();
        assert!(
            text.contains(&format!("{kind}  [Path once trusted]")),
            "{text}"
        );
    }
    let e = err(&run(&dir, &["mappings", "-c", c, "show", "no-such"]));
    assert!(e.contains("There is no mapping pack by that name."), "{e}");

    // An unknown pack is named as such, not sent for a review.
    let e = err(&run(&dir, &["mappings", "-c", c, "trust", "no-such"]));
    assert!(e.contains("There is no mapping pack by that name."), "{e}");
    assert!(!e.contains("--reviewed"), "{e}");
    let e = err(&run(&dir, &["mappings", "-c", c, "trust", name]));
    assert!(
        e.contains("Confirm that you reviewed the pack before trusting it."),
        "{e}"
    );
    assert!(
        e.contains(&format!("pathwarden mappings show {name}")),
        "{e}"
    );
    assert!(!config.exists(), "nothing written");
    let e = err(&run(
        &dir,
        &["mappings", "-c", c, "trust", "no-such", "--reviewed"],
    ));
    assert!(e.contains("There is no mapping pack by that name."), "{e}");

    ok(&run(
        &dir,
        &[
            "mappings",
            "-c",
            c,
            "trust",
            &name.to_ascii_uppercase(),
            "--reviewed",
        ],
    ));
    let list = json(&run(&dir, &["mappings", "-c", c, "list", "--json"]));
    let p = list["packs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap()
        .clone();
    assert_eq!(p["trusted"], true);
    assert_eq!(p["trusted_by_config"], true);
    let text =
        String::from_utf8_lossy(&run(&dir, &["mappings", "-c", c, "list"]).stdout).into_owned();
    assert!(text.contains("[Trusted by you]"), "{text}");

    ok(&run(&dir, &["mappings", "-c", c, "untrust", name]));
    let e = err(&run(&dir, &["mappings", "-c", c, "untrust", name]));
    assert!(e.contains("isn't trusted"), "{e}");
    if let Some(own) = packs.iter().find(|p| p["trusted"] == true) {
        let e = err(&run(
            &dir,
            &[
                "mappings",
                "-c",
                c,
                "untrust",
                own["name"].as_str().unwrap(),
            ],
        ));
        assert!(e.contains("trusted by its own file"), "{e}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plugins_are_added_tested_and_removed() {
    let (dir, ws) = workspace("plugins");
    let ws = ws.as_str();

    // The page's refusals, word for word.
    for (args, why) in [
        (
            vec!["add", "servicenow", "--instance", "http://sn.example.com"],
            "The instance URL must use https://",
        ),
        (
            vec![
                "add",
                "servicenow",
                "--instance",
                "https://u:p@sn.example.com",
            ],
            "Don't put a user name or password in the URL",
        ),
        (
            vec![
                "add",
                "servicenow",
                "--instance",
                "https://sn.example.com",
                "--field",
                "password=x",
            ],
            "secrets can't go in ticket fields",
        ),
        (
            vec![
                "add",
                "command",
                "teams",
                "--setting",
                "webhook=https://x",
                "--",
                "pwsh",
            ],
            "Instead of webhook, add webhook_env",
        ),
        (
            vec!["add", "command", "teams", "--", r"\\server\share\t.exe"],
            "is a network path",
        ),
        (
            vec!["add", "command", "Teams"],
            "Plugin name: use lowercase letters, digits and dashes.",
        ),
        (
            vec![
                "add",
                "command",
                "servicenow",
                "--setting",
                "instance=http://sn.example.com",
            ],
            "The ServiceNow plugin has its own form",
        ),
    ] {
        let mut full = vec!["plugins", "--workspace", ws];
        full.extend(args.iter().copied());
        let e = err(&run(&dir, &full));
        assert!(e.contains(why), "{args:?}: {e}");
    }

    let out = ok(&run(
        &dir,
        &[
            "plugins",
            "--workspace",
            ws,
            "add",
            "servicenow",
            "--instance",
            "https://sn.example.com",
            "--min-severity",
            "high",
            "--token-env",
            "SN_TOKEN_FOR_TEST",
            "--field",
            "assignment_group=Identity",
        ],
    ));
    assert!(out.contains("Saved: plugin 1, servicenow"), "{out}");
    // A plugin that prints a line, so a test shows its output.
    let echo: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/c", "echo", "hello-from-the-plugin"]
    } else {
        vec!["sh", "-c", "echo hello-from-the-plugin"]
    };
    let mut add = vec![
        "plugins",
        "--workspace",
        ws,
        "add",
        "command",
        "echo",
        "--setting",
        "timeout_seconds=30",
        "--",
    ];
    add.extend(echo.iter().copied());
    ok(&run(&dir, &add));

    let list = json(&run(
        &dir,
        &["plugins", "--workspace", ws, "list", "--json"],
    ));
    assert_eq!(list[0]["plugin"], "servicenow");
    assert_eq!(
        list[0]["kind"],
        "ServiceNow · incident at https://sn.example.com"
    );
    assert_eq!(
        list[0]["env"],
        serde_json::json!([{ "name": "SN_TOKEN_FOR_TEST", "set": false }])
    );
    assert_eq!(list[1]["plugin"], "echo");
    assert_eq!(list[1]["found"], true, "{list}");
    let text = std::fs::read_to_string(dir.join("ws").join("pathwarden.toml")).unwrap();
    assert!(text.contains("min_severity = \"high\""), "{text}");
    assert!(text.contains("assignment_group = \"Identity\""), "{text}");

    // Test: a dry run on the latest analysis, as the page's Test. A script
    // of your own needs --yes, where the page asks first.
    let e = err(&run(&dir, &["plugins", "--workspace", ws, "test", "2"]));
    assert!(e.contains("isn't shipped with Pathwarden"), "{e}");
    assert!(
        e.contains("Test it only if your script supports test runs."),
        "{e}"
    );
    assert!(e.contains("--yes"), "{e}");
    let out = ok(&run(
        &dir,
        &["plugins", "--workspace", ws, "test", "2", "--yes"],
    ));
    assert!(out.contains("[echo] hello-from-the-plugin"), "{out}");
    assert!(out.contains("a dry run, which changes nothing"), "{out}");
    let e = err(&run(&dir, &["plugins", "--workspace", ws, "test", "3"]));
    assert!(e.contains("There is no plugin 3"), "{e}");

    ok(&run(&dir, &["plugins", "--workspace", ws, "remove", "1"]));
    let list = json(&run(
        &dir,
        &["plugins", "--workspace", ws, "list", "--json"],
    ));
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["plugin"], "echo");

    // Jira, as the page's Add Jira form: its settings, fields as JSON and
    // the safety limits; a personal access token only on Data Center.
    let e = err(&run(
        &dir,
        &[
            "plugins",
            "--workspace",
            ws,
            "add",
            "jira",
            "--instance",
            "https://contoso.atlassian.net",
            "--project",
            "SEC",
            "--pat-env",
            "JIRA_PAT_FOR_TEST",
        ],
    ));
    assert!(e.contains("Jira Data Center"), "{e}");
    let out = ok(&run(
        &dir,
        &[
            "plugins",
            "--workspace",
            ws,
            "add",
            "jira",
            "--instance",
            "https://contoso.atlassian.net",
            "--project",
            "SEC",
            "--min-severity",
            "high",
            "--no-priority",
            "--field",
            r#"components=[{"name": "Active Directory"}]"#,
            "--max-create",
            "40",
            "--max-resolve-percent",
            "50",
        ],
    ));
    assert!(out.contains("Saved: plugin 2, jira"), "{out}");
    let list = json(&run(
        &dir,
        &["plugins", "--workspace", ws, "list", "--json"],
    ));
    assert_eq!(
        list[1]["kind"],
        "Jira · SEC at https://contoso.atlassian.net"
    );
    // (In file order or sorted, depending on serde_json's features.)
    let mut env: Vec<String> = list[1]["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{}={}", e["name"].as_str().unwrap(), e["set"]))
        .collect();
    env.sort();
    assert_eq!(
        env,
        ["PATHWARDEN_JIRA_TOKEN=false", "PATHWARDEN_JIRA_USER=false"]
    );
    let config = pathwarden_core::config::Config::parse(
        &std::fs::read_to_string(dir.join("ws").join("pathwarden.toml")).unwrap(),
    )
    .unwrap();
    let j = &config.outputs[1].settings;
    assert_eq!(j["set_priority"], false);
    assert_eq!(j["max_create"], 40);
    assert!(!j.contains_key("max_resolve_percent"), "50 is the default");
    assert_eq!(
        j["fields"]["components"],
        serde_json::json!([{ "name": "Active Directory" }])
    );
    ok(&run(&dir, &["plugins", "--workspace", ws, "remove", "2"]));

    // Outside a workspace there is no latest analysis: --event instead.
    let c = dir.join("ws").join("pathwarden.toml");
    let e = err(&run(
        &dir,
        &["plugins", "-c", c.to_str().unwrap(), "test", "1", "--yes"],
    ));
    assert!(e.contains("Testing needs one analysis first"), "{e}");
    let event = dir.join("event.json");
    std::fs::write(&event, "{}").unwrap();
    let out = ok(&run(
        &dir,
        &[
            "plugins",
            "-c",
            c.to_str().unwrap(),
            "test",
            "1",
            "--yes",
            "--event",
            event.to_str().unwrap(),
        ],
    ));
    assert!(out.contains("hello-from-the-plugin"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zones_from_an_older_file_are_flagged() {
    // Saves refuse a zone called Tier Zero, but a hand-written file can
    // hold one.
    let dir = std::env::temp_dir().join(format!("pathwarden-cli-zmp-old-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pathwarden.toml");
    std::fs::write(
        &config,
        r#"[[zone]]
name = "Tier Zero"
members = ["A"]

[[zone]]
name = "T0"
members = ["B"]

[[zone]]
name = "Apps"
members = ["D"]
"#,
    )
    .unwrap();
    let c = config.to_str().unwrap();
    let text = ok(&run(&dir, &["zones", "list", "-c", c]));
    assert_eq!(
        text.matches("! Rename this zone: Tier Zero is built in")
            .count(),
        2,
        "{text}"
    );
    let list = json(&run(&dir, &["zones", "list", "-c", c, "--json"]));
    assert!(list[0]["name_problem"].is_string(), "{list}");
    assert!(list[2]["name_problem"].is_null(), "{list}");
    let z = json(&run(&dir, &["zones", "show", "t0", "-c", c, "--json"]));
    assert!(z["name_problem"].is_string(), "{z}");
    let z = json(&run(&dir, &["zones", "show", "apps", "-c", c, "--json"]));
    assert!(z["name_problem"].is_null(), "{z}");

    // Two zones one name (any case, spaces at either end) don't load, so no
    // command can pick the wrong one.
    let text = "[[zone]]\nname = \"Ops\"\nmembers = [\"A\"]\n\n[[zone]]\nname = \" ops \"\nmembers = [\"B\"]\n";
    std::fs::write(&config, text).unwrap();
    for args in [
        &["zones", "remove", "ops", "-c", c][..],
        &["zones", "edit", "ops", "--add-member", "C", "-c", c],
        &["zones", "list", "-c", c],
    ] {
        let e = err(&run(&dir, args));
        assert!(e.contains("zone 'ops' is defined twice"), "{e}");
    }
    assert_eq!(std::fs::read_to_string(&config).unwrap(), text);
    let _ = std::fs::remove_dir_all(&dir);
}
