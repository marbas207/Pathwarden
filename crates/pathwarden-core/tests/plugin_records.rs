//! The tickets output plugins report (their result file), saved on the
//! findings in the history's `actions.json`: two computers saving at once
//! keep both, a save whose push failed goes with the next one, and an
//! encrypted history keeps them encrypted. Two working copies of one local
//! bare repository stand in for two computers, as in action_log.rs.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::action_log::{self, ActionsFile};
use pathwarden_core::actions::Record;
use pathwarden_core::config::{StateBackend, StateConfig};
use pathwarden_core::output_result::{self, OutputRecord, Reported};
use pathwarden_core::store::{self, Store};

fn git_command() -> Command {
    let mut c = Command::new("git");
    for v in store::GIT_LOCAL_ENV {
        c.env_remove(v);
    }
    c
}

fn have_git() -> bool {
    let ok = git_command()
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        eprintln!("git is not installed: skipping this test");
    }
    ok
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-pluginrecords-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_command()
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn bare(dir: &Path) -> PathBuf {
    let remote = dir.join("state.git");
    git(dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    remote
}

fn git_store(remote: &Path, work: &Path) -> Store {
    let state = StateConfig {
        backend: StateBackend::Git,
        remote: Some(remote.to_string_lossy().replace('\\', "/")),
        ..StateConfig::default()
    };
    Store::new(&state, Some(work)).unwrap()
}

fn remote_log(remote: &Path) -> ActionsFile {
    action_log::parse(git(remote, &["show", "main:actions.json"]).as_bytes()).unwrap()
}

fn hook(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// What a plugin reported: `(fingerprint, id, status, open)`.
fn reported(plugin: &str, tickets: &[(&str, &str, &str, bool)]) -> Reported {
    let source = format!("plugin:{plugin}");
    Reported {
        label: output_result::source_label(&source).unwrap(),
        source,
        records: tickets
            .iter()
            .map(|(fp, id, status, open)| OutputRecord {
                fingerprint: fp.to_string(),
                record: Record {
                    id: id.to_string(),
                    kind: Some("ticket".into()),
                    number: Some(id.to_uppercase()),
                    url: Some(format!("https://desk.example.com/{id}")),
                    status: Some(status.to_string()),
                    open: *open,
                    ..Record::default()
                },
            })
            .collect(),
    }
}

fn any(_: &str) -> bool {
    true
}

fn status(log: &ActionsFile, fp: &str) -> Vec<(String, String)> {
    log.records(fp)
        .into_iter()
        .map(|r| (r.action, r.record.status.unwrap_or_default()))
        .collect()
}

/// Two computers' scheduled runs save at the same time: the second push
/// is refused, its change is made again on what the first left, and both
/// plugins' tickets are on the findings. Seen again, nothing is saved.
#[test]
fn two_computers_saving_plugin_tickets_at_once_keep_both() {
    if !have_git() {
        return;
    }
    let dir = scratch("race");
    let remote = bare(&dir);
    let a = git_store(&remote, &dir.join("a"));
    let b = git_store(&remote, &dir.join("b"));
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.publish_with("first", || Ok(None)).unwrap();
    b.pull().unwrap();
    let sn = reported("servicenow", &[("PW-001-aaaa", "inc1", "Open", true)]);
    let s = output_result::save_all(&a, std::slice::from_ref(&sn), &any, Some("R1"), true).unwrap();
    assert_eq!(s.findings, 1);
    assert!(s.saved.pushed, "{:?}", s.saved.notes);
    // B worked from the state before A's save.
    let jira = reported(
        "jira",
        &[
            ("PW-001-aaaa", "sec-1", "To Do", true),
            ("PW-002-bbbb", "sec-2", "Done", false),
        ],
    );
    let s = output_result::save_all(&b, &[jira], &any, Some("R1"), true).unwrap();
    assert!(s.saved.pushed, "{:?}", s.saved.notes);
    let log = remote_log(&remote);
    assert_eq!(
        status(&log, "PW-001-aaaa"),
        [
            ("plugin:servicenow".to_string(), "Open".to_string()),
            ("plugin:jira".to_string(), "To Do".to_string())
        ]
    );
    assert_eq!(status(&log, "PW-002-bbbb").len(), 1);
    // A sees B's on its next pull, and the same report again saves nothing.
    a.pull().unwrap();
    let before = git(&remote, &["rev-parse", "main"]);
    let s = output_result::save_all(&a, &[sn], &any, Some("R2"), true).unwrap();
    assert_eq!(s.findings, 0);
    assert_eq!(git(&remote, &["rev-parse", "main"]), before, "no commit");
    let messages = git(&remote, &["log", "--format=%s", "main"]);
    assert!(
        messages
            .lines()
            .filter(|m| *m != "first")
            .all(|m| m == action_log::PLUGIN_MESSAGE),
        "{messages}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save whose push failed is kept on this computer: another computer
/// pushes first, the pull makes it again on the remote's state, and the
/// next push carries it.
#[test]
fn plugin_tickets_whose_push_failed_go_with_the_next_push() {
    if !have_git() {
        return;
    }
    let dir = scratch("pending");
    let remote = bare(&dir);
    let a = git_store(&remote, &dir.join("a"));
    let b = git_store(&remote, &dir.join("b"));
    a.pull().unwrap();
    a.write_state_file("last-run.json", b"{}").unwrap();
    a.publish_with("first", || Ok(None)).unwrap();
    b.pull().unwrap();
    let refuse = remote.join("hooks").join("pre-receive");
    hook(&refuse, "#!/bin/sh\nexit 1\n");
    let sn = reported("servicenow", &[("PW-001-aaaa", "inc1", "Open", true)]);
    let s = output_result::save_all(&a, &[sn], &any, Some("R1"), true).unwrap();
    assert!(!s.saved.pushed);
    assert_eq!(action_log::pending_count(&a), 1);
    // The next run on A, still offline: kept as one entry for the finding.
    let sn = reported("servicenow", &[("PW-001-aaaa", "inc1", "Resolved", false)]);
    output_result::save_all(&a, &[sn], &any, Some("R2"), true).unwrap();
    assert_eq!(action_log::pending_count(&a), 1, "merged, not piled up");
    std::fs::remove_file(&refuse).unwrap();
    // B pushes first.
    let jira = reported("jira", &[("PW-002-bbbb", "sec-2", "To Do", true)]);
    output_result::save_all(&b, &[jira], &any, Some("R1"), true).unwrap();
    a.pull().unwrap();
    let here = action_log::load(&a).unwrap();
    assert_eq!(
        status(&here, "PW-001-aaaa"),
        [("plugin:servicenow".to_string(), "Resolved".to_string())]
    );
    assert_eq!(status(&here, "PW-002-bbbb").len(), 1);
    // A's next commit pushes it.
    a.write_state_file("last-run.json", b"{\"n\":2}").unwrap();
    a.publish_with("second", || Ok(None)).unwrap();
    let log = remote_log(&remote);
    assert_eq!(
        status(&log, "PW-001-aaaa"),
        [("plugin:servicenow".to_string(), "Resolved".to_string())]
    );
    let summaries: Vec<String> = log
        .activity("PW-001-aaaa")
        .iter()
        .map(|a| a.summary())
        .collect();
    assert_eq!(
        summaries,
        [
            "ServiceNow plugin: Closed INC1 · Resolved",
            "ServiceNow plugin: INC1 · Open"
        ]
    );
    assert_eq!(action_log::pending_count(&a), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

const PASS: &str = "correct horse battery staple";

/// In an encrypted history the tickets are saved encrypted, as the rest
/// of `actions.json`, and read back with its key.
#[test]
fn plugin_tickets_in_an_encrypted_history_stay_encrypted() {
    let ks = std::env::temp_dir().join(format!(
        "pathwarden-pluginrecords-ks-{}",
        std::process::id()
    ));
    pathwarden_core::keystore::use_test_store(&ks);
    let dir = scratch("sealed");
    let s = Store::new(&StateConfig::default(), Some(&dir)).unwrap();
    s.write_state_file("last-run.json", b"{}").unwrap();
    let pass = || pathwarden_core::crypt::SecretString::from(PASS.to_string());
    s.encrypt(&pass(), true).unwrap();
    pathwarden_core::crypt::give_passphrase(&s.dir, pass());
    let sn = reported("servicenow", &[("PW-001-aaaa", "inc1", "Open", true)]);
    let saved = output_result::save_all(&s, &[sn], &any, Some("R1"), true).unwrap();
    assert_eq!(saved.findings, 1);
    assert!(!dir.join("actions.json").exists());
    let raw = std::fs::read(dir.join("actions.json.age")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("PW-001-aaaa"));
    let log = action_log::load(&s).unwrap();
    assert_eq!(log.records("PW-001-aaaa")[0].record.id, "inc1");
    let _ = std::fs::remove_dir_all(&dir);
}
