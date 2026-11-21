//! `pathwarden action`: finding actions end to end, with the fake action
//! program in testdata/actions (PowerShell on Windows, sh elsewhere): add,
//! list, run, request, check, test and remove.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// Runs pathwarden in `dir`, with this account's app data kept in `dir`.
fn run_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(bin());
    c.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("LOCALAPPDATA", dir.join("lad"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env_remove("PATHWARDEN_SCHEDULED")
        .stdin(Stdio::null())
        .args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    run_with(dir, args, &[])
}

fn text(out: &std::process::Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn ok(out: &std::process::Output) -> String {
    assert!(out.status.success(), "{}", text(out));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// stdout and stderr of a run that failed with exit status 2.
fn err(out: &std::process::Output) -> (String, String) {
    assert_eq!(out.status.code(), Some(2), "{}", text(out));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_str(&ok(out)).unwrap()
}

/// The command that runs `script` (testdata/actions/NAME.ps1 or .sh).
fn command_of(script: &Path) -> Vec<String> {
    let s = script.display().to_string();
    if cfg!(windows) {
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]
        .iter()
        .map(|a| a.to_string())
        .chain([s])
        .collect()
    } else {
        vec!["sh".into(), s]
    }
}

fn fake_action() -> PathBuf {
    let ext = if cfg!(windows) { "ps1" } else { "sh" };
    std::path::absolute(repo(&format!("testdata/actions/fake-action.{ext}"))).unwrap()
}

/// A scratch folder with a workspace `ws` holding one saved analysis of
/// the forest fixture, and the IDs of a critical and a high finding.
fn workspace() -> (PathBuf, String, String, String) {
    workspace_named("")
}

/// [`workspace`] in a folder of its own, for tests that run beside it.
fn workspace_named(name: &str) -> (PathBuf, String, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-actions{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    let forest = forest.to_str().unwrap();
    ok(&run(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", forest],
    ));
    let findings = json(&run(&dir, &["findings", "-i", forest, "--json"]));
    let list = findings
        .as_array()
        .or_else(|| findings["findings"].as_array())
        .unwrap()
        .clone();
    let of = |severity: &str| {
        list.iter()
            .find(|f| f["severity"] == severity && f["category"] == "attack_path")
            .unwrap_or_else(|| panic!("no {severity} attack path"))["fingerprint"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let ws = dir.join("ws").display().to_string();
    let (critical, high) = (of("critical"), of("high"));
    (dir, ws, critical, high)
}

#[test]
fn actions_are_added_run_checked_and_removed() {
    let (dir, ws, critical, high) = workspace();
    let ws = ws.as_str();
    let at = |args: &[&str]| -> Vec<String> {
        ["action", "--workspace", ws]
            .iter()
            .chain(args)
            .map(|s| s.to_string())
            .collect()
    };
    let call = |args: &[&str], env: &[(&str, &str)]| {
        let full = at(args);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        run_with(&dir, &refs, env)
    };

    // Added from the terminal, as the app would with --allow-destinations.
    let command = command_of(&fake_action());
    let mut add = vec![
        "add",
        "--name",
        "desk",
        "--setting",
        "out_env=PW_FAKE_ACTION_OUT",
        "--",
    ];
    add.extend(command.iter().map(String::as_str));
    let out = ok(&call(&add, &[]));
    assert!(out.contains("Saved: finding action desk"), "{out}");
    let (_, e) = err(&call(&add, &[]));
    assert!(e.contains("There is already an action named desk"), "{e}");
    let (_, e) = err(&call(
        &["add", "--plugin", "teams", "--setting", "webhook=x"],
        &[],
    ));
    assert!(e.contains("Instead of webhook, add webhook_env"), "{e}");
    let (_, e) = err(&call(
        &["add", "--name", "net", "--", r"\\srv\share\a.exe"],
        &[],
    ));
    assert!(e.contains("is a network path"), "{e}");

    // What the program offers, and what applies to a finding.
    let list = json(&call(&["list", "--json"], &[]));
    assert_eq!(list[0]["name"], "desk");
    assert_eq!(list[0]["found"], true, "{list}");
    let ids: Vec<&str> = list[0]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["open", "status", "ping", "close"]);
    let on = json(&call(&["list", "--fingerprint", &critical, "--json"], &[]));
    let offered: Vec<&str> = on["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["address"].as_str().unwrap())
        .collect();
    assert_eq!(offered, ["desk/open", "desk/ping"]);
    // `ping` is for critical findings only.
    let on = json(&call(&["list", "--fingerprint", &high, "--json"], &[]));
    assert_eq!(on["actions"].as_array().unwrap().len(), 1, "{on}");

    // Several apply: one must be named. And it always asks first.
    let (_, e) = err(&call(&["run", &critical], &[]));
    assert!(
        e.contains("Several actions apply to this finding: choose one of desk/open, desk/ping."),
        "{e}"
    );
    let (_, e) = err(&call(&["run", &high], &[]));
    assert!(e.contains("pass --yes to run it without asking"), "{e}");
    let (_, e) = err(&call(&["run", &high, "--input", "urgency=Now", "-y"], &[]));
    assert!(
        e.contains("Urgency: 'Now' isn't one of Low, Medium, High."),
        "{e}"
    );

    // `request` prints the request a run sends (before the run: `open` is
    // `once`, so its record hides it afterwards).
    let printed = json(&call(
        &[
            "request",
            &critical,
            "--action",
            "desk/open",
            "--input",
            "note=Please review",
        ],
        &[],
    ));
    // A run: progress lines, then the result; the program got the request.
    let seen = dir.join("request.json");
    let seen_s = seen.display().to_string();
    let env = [("PW_FAKE_ACTION_OUT", seen_s.as_str())];
    let out = ok(&call(
        &[
            "run",
            &critical,
            "--action",
            "desk/open",
            "--input",
            "note=Please review",
            "-y",
        ],
        &env,
    ));
    for want in [
        "Open a ticket (desk/open) on ",
        "It sends: The finding's title and the note.",
        "  [desk] Opening a ticket\n  [desk] Ticket created\n",
        "Done: Opened FAKE0001.",
        "  Record: FAKE0001 · Open  https://desk.example.com/FAKE0001",
        "    Queue: Identity",
        "  Open in the fake desk: https://desk.example.com/FAKE0001",
        "Saved on this finding in the run history.",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
    let got: serde_json::Value = serde_json::from_slice(&std::fs::read(&seen).unwrap()).unwrap();
    assert_eq!(got["schema"], "pathwarden.action-request.v1");
    assert_eq!(got["kind"], "run");
    assert_eq!(got["action"], "open");
    assert_eq!(got["dry_run"], false);
    assert_eq!(
        got["inputs"],
        serde_json::json!({ "note": "Please review", "urgency": "Medium" })
    );
    assert_eq!(
        got["settings"],
        serde_json::json!({ "out_env": "PW_FAKE_ACTION_OUT" })
    );
    assert_eq!(got["finding"]["fingerprint"], critical.as_str());
    assert_eq!(got["finding"]["status"], "open");
    assert!(
        got["finding"]["guide"]
            .as_str()
            .is_some_and(|g| g.starts_with('#')),
        "{got}"
    );
    assert!(got["finding"]["remediation"].is_string());
    assert!(got["run"]["run_id"].is_string());
    assert!(got["requested_by"].is_object());
    assert_eq!(got["record"], serde_json::Value::Null);

    // `request` printed that same request.
    assert_eq!(printed, got);

    // A dry run, as JSON; a failure, with the program's error output.
    let r = json(&call(&["run", &high, "--dry-run", "-y", "--json"], &[]));
    assert_eq!(r["ok"], true);
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["message"], "Would open a ticket (dry run).");
    assert_eq!(r["action"], "desk/open");
    assert_eq!(r["progress"], serde_json::json!(["Opening a ticket"]));
    assert_eq!(r["saved"], false, "a dry run saves nothing");
    let (out, e) = err(&call(&["run", &high, "--input", "note=fail", "-y"], &[]));
    assert!(e.contains("The fake desk said no."), "{e}");
    assert!(out.contains("Details (exit code 1):"), "{out}");
    assert!(out.contains("HTTP 403 from the fake desk"), "{out}");

    // What was saved: the record on the critical finding, and every run
    // but the dry one, newest first.
    let recs = json(&call(&["records", &critical, "--json"], &[]));
    assert_eq!(recs.as_array().unwrap().len(), 1, "{recs}");
    assert_eq!(recs[0]["id"], "fake-1");
    assert_eq!(recs[0]["action"], "desk/open");
    assert_eq!(recs[0]["number"], "FAKE0001");
    assert_eq!(recs[0]["open"], true);
    assert_eq!(recs[0]["fingerprint"], critical.as_str());
    let all = json(&call(&["records", "--json"], &[]));
    assert_eq!(all, recs);
    let out = ok(&call(&["records", &critical], &[]));
    assert!(
        out.contains("fake-1  FAKE0001 · Open  https://desk.example.com/FAKE0001"),
        "{out}"
    );
    assert!(out.contains("    Queue: Identity"), "{out}");
    let out = ok(&call(&["records", &high], &[]));
    assert!(out.contains("has no records."), "{out}");
    let act = json(&call(&["activity", "--json"], &[]));
    let act = act.as_array().unwrap();
    assert_eq!(act.len(), 2, "{act:?}");
    assert_eq!(act[0]["fingerprint"], high.as_str());
    assert_eq!(act[0]["ok"], false);
    assert_eq!(act[0]["message"], "The fake desk said no.");
    assert_eq!(act[1]["action"], "desk/open");
    assert_eq!(act[1]["record_ids"], serde_json::json!(["fake-1"]));
    assert_eq!(act[1]["dry_run"], false);
    let out = ok(&call(&["activity", &critical], &[]));
    assert!(out.contains("  Opened FAKE0001 — "), "{out}");
    let out = ok(&call(&["activity"], &[]));
    assert!(
        out.contains("! Open a ticket failed: The fake desk said no"),
        "{out}"
    );
    // `findings --json` carries it on the finding.
    let forest = repo("testdata/forest");
    let fj = json(&run(
        &dir,
        &[
            "findings",
            "-i",
            forest.to_str().unwrap(),
            "--workspace",
            ws,
            "--json",
        ],
    ));
    let f = fj
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["fingerprint"] == critical.as_str())
        .unwrap();
    assert_eq!(f["actions"]["records"][0]["id"], "fake-1", "{f}");
    assert_eq!(f["actions"]["activity_count"], 1);

    // `once`: open is hidden while its record is open; the follow-up runs
    // on the record and updates it.
    let on = json(&call(&["list", "--fingerprint", &critical, "--json"], &[]));
    assert_eq!(on["actions"].as_array().unwrap().len(), 1, "{on}");
    let (_, e) = err(&call(
        &["run", &critical, "--action", "desk/status", "-y"],
        &[],
    ));
    assert!(
        e.contains("Check status runs on a record of this finding: name one of fake-1."),
        "{e}"
    );
    let out = ok(&call(&["run", &critical, "--record", "fake-1", "-y"], &[]));
    assert!(out.contains("Check status (desk/status) on "), "{out}");
    assert!(out.contains(", record FAKE0001 · Open: "), "{out}");
    assert!(out.contains("Done: FAKE0001 is Closed."), "{out}");
    assert!(
        out.contains("Saved on this finding in the run history."),
        "{out}"
    );
    let recs = json(&call(&["records", &critical, "--json"], &[]));
    assert_eq!(recs.as_array().unwrap().len(), 1, "{recs}");
    assert_eq!(recs[0]["action"], "desk/open");
    assert_eq!(recs[0]["status"], "Closed");
    assert_eq!(recs[0]["open"], false);
    let on = json(&call(&["list", "--fingerprint", &critical, "--json"], &[]));
    assert_eq!(on["actions"].as_array().unwrap().len(), 2, "{on}");

    // A record is removed only when asked, and the removal is activity.
    let (_, e) = err(&call(&["records", "remove", &critical, "fake-1"], &[]));
    assert!(e.contains("pass --yes"), "{e}");
    let (_, e) = err(&call(
        &["records", "remove", &critical, "fake-9", "-y"],
        &[],
    ));
    assert!(
        e.contains("This finding has no record fake-9. Its records: fake-1."),
        "{e}"
    );
    let out = ok(&call(
        &["records", "remove", &critical, "FAKE-1", "-y"],
        &[],
    ));
    assert!(
        out.contains("Removed record fake-1 (FAKE0001 · Closed) from "),
        "{out}"
    );
    let recs = json(&call(&["records", &critical, "--json"], &[]));
    assert!(recs.as_array().unwrap().is_empty(), "{recs}");
    let act = json(&call(&["activity", &critical, "--json"], &[]));
    assert_eq!(act[0]["kind"], "remove");
    assert_eq!(act[0]["record_ids"], serde_json::json!(["fake-1"]));
    assert_eq!(act[1]["action"], "desk/status");
    assert_eq!(act.as_array().unwrap().len(), 3);

    // Test: a dry run on the latest run's first finding it applies to.
    let out = ok(&call(&["test", "desk", "-y"], &[]));
    assert!(
        out.contains("A dry run: the program is asked to change nothing."),
        "{out}"
    );
    assert!(
        out.contains("Done: Would open a ticket (dry run)."),
        "{out}"
    );

    // Check: the program, and a block by name.
    let script = fake_action().display().to_string();
    let out = ok(&run(&dir, &["action", "check", &script]));
    assert!(out.contains("a sample finding"), "{out}");
    assert!(
        out.contains("No problems: its describe and every dry run passed the checks."),
        "{out}"
    );
    let out = ok(&call(&["check", "desk", "-y"], &[]));
    assert!(out.contains("No problems"), "{out}");
    // A real finding could leave the computer: it asks first.
    let (_, e) = err(&call(&["check", "desk"], &[]));
    assert!(e.contains("pass --yes"), "{e}");
    let (_, e) = err(&call(&["check", &script, "--fingerprint", &high], &[]));
    assert!(e.contains("pass --yes"), "{e}");
    let out = ok(&call(
        &["check", &script, "--fingerprint", &high, "-y"],
        &[],
    ));
    assert!(
        out.contains(&format!("Checking fake-action on {high}.")),
        "{out}"
    );
    // Nothing to import in a plain history.
    let (_, e) = err(&call(&["log", "import", "-y"], &[]));
    assert!(e.contains("There is no plain actions.json"), "{e}");
    // Check and test are dry runs: nothing more was saved.
    let act = json(&call(&["activity", "--json"], &[]));
    assert_eq!(act.as_array().unwrap().len(), 4, "{act}");

    // Never from a scheduled task.
    let (_, e) = err(&call(
        &["run", &high, "--action", "desk/open", "-y"],
        &[("PATHWARDEN_SCHEDULED", "1")],
    ));
    assert!(e.contains("never from a scheduled task"), "{e}");

    // Without --name, the block is named after its script, made unique.
    let mut unnamed = vec!["add", "--"];
    unnamed.extend(command.iter().map(String::as_str));
    let out = ok(&call(&unnamed, &[]));
    assert!(out.contains("Saved: finding action fake-action "), "{out}");
    let out = ok(&call(&unnamed, &[]));
    assert!(
        out.contains("Saved: finding action fake-action-2 "),
        "{out}"
    );
    ok(&call(&["remove", "fake-action"], &[]));
    ok(&call(&["remove", "fake-action-2"], &[]));
    // A block written by hand without a name: named by its place, noted.
    let toml = dir.join("ws").join("pathwarden.toml");
    let mut text = std::fs::read_to_string(&toml).unwrap();
    text.push_str("\n[[action]]\ncommand = [\"sh\"]\n");
    std::fs::write(&toml, &text).unwrap();
    let out = call(&["list", "--json"], &[]);
    let note = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        note.contains(
            "an [[action]] block has no name, so it is called action-2 by its place in the file"
        ),
        "{note}"
    );
    assert!(note.contains("Add name = \"sh\" to it."), "{note}");
    ok(&call(&["remove", "action-2"], &[]));

    ok(&call(&["remove", "desk"], &[]));
    let out = ok(&call(&["list"], &[]));
    assert!(out.contains("No finding actions in"), "{out}");
    // With none set up, `request` prints the finding's request anyway.
    let r = json(&call(&["request", &high], &[]));
    assert_eq!(r["action"], "");
    assert_eq!(r["finding"]["fingerprint"], high.as_str());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `check` names every problem with a program's answers and exits 2.
#[test]
fn check_names_the_problems() {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-action-check-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let describe = r#"{"schema":"pathwarden.action-describe.v1","actions":[{"id":"a","label":"A","sends":"x","inputs":[{"id":"n","label":"N","type":"number"}]},{"id":"b","label":"B"}]}"#;
    let result = r#"{"schema":"pathwarden.action-result.v1","ok":true,"links":[{"label":"L","url":"http://x.example"}]}"#;
    let script = if cfg!(windows) {
        let p = dir.join("broken.ps1");
        std::fs::write(
            &p,
            format!(
                "$null = [Console]::In.ReadToEnd()\n\
                 if ($env:PATHWARDEN_ACTION_REQUEST -eq 'describe') {{ [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{describe}'); exit 0 }}\n\
                 [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, '{result}')\n"
            ),
        )
        .unwrap();
        p
    } else {
        let p = dir.join("broken.sh");
        std::fs::write(
            &p,
            format!(
                "cat > /dev/null\n\
                 if [ \"$PATHWARDEN_ACTION_REQUEST\" = describe ]; then printf '%s' '{describe}' > \"$PATHWARDEN_ACTION_RESULT\"; exit 0; fi\n\
                 printf '%s' '{result}' > \"$PATHWARDEN_ACTION_RESULT\"\n"
            ),
        )
        .unwrap();
        p
    };
    let (out, _) = err(&run(
        &dir,
        &["action", "check", &script.display().to_string()],
    ));
    for want in [
        "3 problems:",
        "  - describe: actions[1].sends is missing: say in plain words what leaves the computer",
        "  - describe: actions[0].inputs[0].type 'number' isn't one of text, textarea, choice, bool",
        "  - broken/b: dry run: links[0].url must start with https://; the link was left out",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
    let (out, _) = err(&run(
        &dir,
        &[
            "action",
            "check",
            &dir.join("none.ps1").display().to_string(),
        ],
    ));
    assert!(out.is_empty(), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ctrl-C (SIGINT) while an action runs stops it and its processes, and
/// the command says so. The program runs in a process group of its own,
/// which the signal doesn't reach.
#[cfg(unix)]
#[test]
fn interrupting_a_run_cancels_it() {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-cli-action-int-{}", std::process::id()));
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
    let ws = dir.join("ws").display().to_string();
    let script = fake_action().display().to_string();
    ok(&run(
        &dir,
        &[
            "action",
            "--workspace",
            &ws,
            "add",
            "--name",
            "desk",
            "--setting",
            "mark_env=PW_FAKE_ACTION_MARK",
            "--",
            "sh",
            &script,
        ],
    ));
    let findings = json(&run(
        &dir,
        &["findings", "-i", forest.to_str().unwrap(), "--json"],
    ));
    let list = findings
        .as_array()
        .or_else(|| findings["findings"].as_array())
        .unwrap()
        .clone();
    let high = list
        .iter()
        .find(|f| f["severity"] == "high" && f["category"] == "attack_path")
        .unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let mark = dir.join("still-running");
    let mut child = Command::new(bin())
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .env("LOCALAPPDATA", dir.join("lad"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("PW_FAKE_ACTION_MARK", &mark)
        .env_remove("PATHWARDEN_SCHEDULED")
        .args([
            "action",
            "--workspace",
            &ws,
            "run",
            &high,
            "--action",
            "desk/open",
            "--input",
            "note=slow",
            "-y",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Until the program says it waits.
    let mut out = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    while !String::from_utf8_lossy(&seen).contains("Waiting for the fake desk") {
        let n = std::io::Read::read(&mut out, &mut buf).unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&seen));
        seen.extend_from_slice(&buf[..n]);
    }
    let started = std::time::Instant::now();
    assert!(Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let status = child.wait().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(err.contains("Cancelled."), "{err}");
    // Saved on the finding, as cancelled.
    let act = json(&run(
        &dir,
        &["action", "--workspace", &ws, "activity", &high, "--json"],
    ));
    assert_eq!(act[0]["outcome"], "cancelled", "{act}");
    assert_eq!(act[0]["ok"], false);
    assert_eq!(act[0]["message"], "Cancelled");
    std::thread::sleep(std::time::Duration::from_secs(10));
    assert!(!mark.exists(), "the action's process outlived the cancel");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The app and `pathwarden action` give the same results (CLI/UI parity):
/// what applies to a finding (the run page's buttons and `list
/// --fingerprint`), what a run returns (the app's result card and `run
/// --json`), and which finding Test runs on (Plugins and actions and
/// `action test`). The app's side is the shared code its pages call.
#[test]
fn the_app_and_the_command_line_give_the_same_results() {
    let (dir, ws_path, critical, _) = workspace_named("-parity");
    let ws_arg = ws_path.as_str();
    let call = |args: &[&str]| {
        let full: Vec<&str> = ["action", "--workspace", ws_arg]
            .iter()
            .copied()
            .chain(args.iter().copied())
            .collect();
        run(&dir, &full)
    };
    let command = command_of(&fake_action());
    let mut add = vec!["add", "--name", "desk", "--"];
    add.extend(command.iter().map(String::as_str));
    ok(&call(&add));
    let ws = pathwarden_ui::workspace::Workspace::open(&ws_path).unwrap();
    let config = ws.config().unwrap();

    // What applies to the finding.
    let on = json(&call(&["list", "--fingerprint", &critical, "--json"]));
    let cli: Vec<String> = on["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["address"].as_str().unwrap().to_string())
        .collect();
    let blocks = pathwarden_ui::actions_ui::described(&config.actions);
    let run_id = on["run"].as_str().unwrap();
    let summary = ws.summary(run_id).unwrap();
    let page = pathwarden_ui::actions_ui::page_data(&ws, &blocks, &summary, None).unwrap();
    let app: Vec<String> = page["f"][&critical]["view"]["offered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    assert_eq!(cli, app);
    assert_eq!(cli, ["desk/open", "desk/ping"]);

    // What a run returns (a dry run, so the history is the same for both).
    let cli = json(&call(&[
        "run",
        &critical,
        "--action",
        "desk/open",
        "--input",
        "note=Please look",
        "--dry-run",
        "--json",
        "--yes",
    ]));
    let ask = pathwarden_core::actions::Ask {
        action: Some("desk/open".into()),
        inputs: [("note".to_string(), serde_json::json!("Please look"))]
            .into_iter()
            .collect(),
        dry_run: true,
        record: None,
    };
    let ready =
        pathwarden_ui::actions_ui::prepare(&ws, &config.actions, None, &critical, &ask).unwrap();
    let (out, saved) = pathwarden_ui::actions_ui::run_and_save(
        &ws,
        &ready,
        &mut |_| {},
        &pathwarden_core::actions::CancelHandle::new(),
    )
    .unwrap();
    let app = pathwarden_ui::actions_ui::outcome_json(&ready, &out, saved.as_ref());
    for key in [
        "ok",
        "message",
        "records",
        "links",
        "dry_run",
        "action",
        "label",
        "fingerprint",
        "run",
        "record",
        "saved",
        "pushed",
        "ended",
        "status",
        "problems",
    ] {
        assert_eq!(cli[key], app[key], "{key}: {cli} / {app}");
    }
    assert_eq!(app["message"], "Would open a ticket (dry run).");

    // Which finding Test runs on.
    let text = ok(&call(&["test", "desk", "--action", "open", "--yes"]));
    let ready =
        pathwarden_ui::actions_ui::test_target(&ws, &config.actions, "desk", Some("open")).unwrap();
    assert!(
        text.contains(&format!("on {}", ready.finding.fingerprint)),
        "{text}"
    );
    assert!(text.contains("Would open a ticket (dry run)."), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed `action run` ends its log as failed, with `--json` (which
/// exits 2 without an error) and without.
#[test]
fn a_failed_action_run_logs_a_failure() {
    let (dir, ws, _, high) = workspace_named("-log");
    let logs = dir.join("logs");
    let logs_env = logs.display().to_string();
    let env = [("PATHWARDEN_TEST_LOGS", logs_env.as_str())];
    let command = command_of(&fake_action());
    let mut add = vec!["action", "--workspace", &ws, "add", "--name", "desk", "--"];
    add.extend(command.iter().map(String::as_str));
    ok(&run_with(&dir, &add, &[]));
    for extra in [None, Some("--json")] {
        let mut args = vec![
            "action",
            "--workspace",
            &ws,
            "run",
            &high,
            "--input",
            "note=fail",
            "-y",
        ];
        args.extend(extra);
        let out = run_with(&dir, &args, &env);
        assert!(!out.status.success());
    }
    let mut seen = 0;
    for e in std::fs::read_dir(&logs).unwrap() {
        let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
        if !text.starts_with("# Action ") {
            continue;
        }
        seen += 1;
        let last = text.lines().last().unwrap();
        assert!(
            last.contains("[action, command line] result: failed: "),
            "{text}"
        );
    }
    assert_eq!(seen, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `records --fixed` and `--open`: the findings the latest run left fixed
/// that have records, newest fix first; `--open --fixed` is the report's
/// "Fixed, ticket still open" list.
#[test]
fn records_of_fixed_findings_whose_ticket_is_still_open() {
    let (dir, ws, critical, high) = workspace_named("-fixed");
    let ws = ws.as_str();
    let call = |args: &[&str]| {
        let full: Vec<&str> = ["action", "--workspace", ws]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        run(&dir, &full)
    };
    // Nothing has records yet.
    let out = ok(&call(&["records", "--open", "--fixed"]));
    assert!(
        out.contains("No fixed finding has an open record in "),
        "{out}"
    );
    assert_eq!(
        json(&call(&["records", "--open", "--fixed", "--json"])),
        serde_json::json!([])
    );

    // The latest run's state, with the critical finding fixed.
    fn find(dir: &Path) -> Option<PathBuf> {
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(f) = find(&p) {
                    return Some(f);
                }
            } else if p.file_name().is_some_and(|n| n == "findings.json") {
                return Some(p);
            }
        }
        None
    }
    let path = find(&dir.join("ws")).expect("the history's findings.json");
    let state_dir = path.parent().unwrap().to_path_buf();
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let t = &mut state["findings"][critical.as_str()];
    assert!(t.is_object(), "{state}");
    t["status"] = "resolved".into();
    t["resolved_at"] = 1_795_000_000_i64.into();
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    // A closed and an open ticket on it; an open one on the high finding,
    // which isn't fixed.
    let rec = |id: &str, status: &str, open: bool| {
        serde_json::json!({"action": "desk/open", "id": id, "number": id.to_uppercase(),
            "status": status, "open": open, "at": "2026-11-18T14:02:11.000Z",
            "updated_at": "2026-11-18T14:02:11.000Z"})
    };
    let actions = serde_json::json!({"version": 1, "findings": {
        critical.as_str(): {"records": [rec("fake-1", "Closed", false), rec("fake-2", "Open", true)]},
        high.as_str(): {"records": [rec("fake-3", "Open", true)]},
    }});
    std::fs::write(
        state_dir.join("actions.json"),
        serde_json::to_vec(&actions).unwrap(),
    )
    .unwrap();

    let out = ok(&call(&["records", "--open", "--fixed"]));
    assert!(out.contains(&format!("{critical}  PW-")), "{out}");
    assert!(out.contains("fixed Nov 18"), "{out}");
    assert!(out.contains("fake-2  FAKE-2 · Open"), "{out}");
    assert!(!out.contains("fake-1"), "{out}");
    assert!(!out.contains(&high), "{out}");
    let j = json(&call(&["records", "--open", "--fixed", "--json"]));
    let list = j.as_array().unwrap();
    assert_eq!(list.len(), 1, "{j}");
    assert_eq!(list[0]["id"], "fake-2");
    assert_eq!(list[0]["fingerprint"], critical.as_str());
    assert_eq!(list[0]["fixed_at"], 1_795_000_000_i64);
    assert_eq!(list[0]["open"], true);
    assert!(list[0]["rule"].as_str().unwrap().starts_with("PW-"), "{j}");
    assert!(!list[0]["title"].as_str().unwrap().is_empty(), "{j}");

    // `--fixed`: every record of the fixed findings.
    let j = json(&call(&["records", "--fixed", "--json"]));
    let ids: Vec<&str> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["fake-1", "fake-2"]);
    // `--open`: open records, fixed or not.
    let j = json(&call(&["records", "--open", "--json"]));
    let mut ids: Vec<&str> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, ["fake-2", "fake-3"]);
    let out = ok(&call(&["records", "--open", "--fixed", &high]));
    assert!(
        out.contains("isn't a fixed finding with an open record."),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
