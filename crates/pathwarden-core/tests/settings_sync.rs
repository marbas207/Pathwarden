//! Shared settings through the history repository: two or
//! three environments on one local bare repository stand in for machines.
//! Each keeps its `pathwarden.toml` in its own folder, with the history's
//! working copy beside it.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::config::Config;
use pathwarden_core::config_edit::{self, ConfigDoc, Stamp, SuppressionEdit};
use pathwarden_core::settings_sync::{self, Changed, Place, Resolve};
use pathwarden_core::store::{Store, ENVIRONMENT_FILE, SETTINGS_FILE};

fn git_command() -> Command {
    let mut c = Command::new("git");
    for v in pathwarden_core::store::GIT_LOCAL_ENV {
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

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pathwarden-settings-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bare(dir: &Path) -> PathBuf {
    let remote = dir.join("state.git");
    git(dir, &["init", "-q", "--bare", &remote.to_string_lossy()]);
    remote
}

/// One machine: an environment folder with `pathwarden.toml` and the
/// history's working copy in `state/`.
struct Machine {
    dir: PathBuf,
}

impl Machine {
    fn new(root: &Path, name: &str, remote: &Path, push: bool, rest: &str) -> Self {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let m = Machine { dir };
        m.write(&format!(
            "# {name}'s settings\n[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"state\"\nkeep = \"full\"\n{}\n{rest}",
            remote.to_string_lossy().replace('\\', "/"),
            if push { "" } else { "push = false\n" },
        ));
        m
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("pathwarden.toml")
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap()
    }

    fn write(&self, text: &str) {
        std::fs::write(self.config_path(), text).unwrap();
    }

    fn config(&self) -> Config {
        config_edit::check(&self.text()).unwrap()
    }

    /// Edits `pathwarden.toml` as the app and `pathwarden config` do.
    fn edit(&self, change: impl FnOnce(&mut ConfigDoc)) {
        let mut d = ConfigDoc::parse(&self.text()).unwrap();
        change(&mut d);
        self.write(&d.validate().map(|_| d.text()).unwrap());
    }

    fn store(&self) -> Store {
        let state = self.config().state;
        Store::new(&state, Some(&settings_sync::state_dir(&state, &self.dir))).unwrap()
    }

    /// Takes the lock, pulls and syncs, as `pathwarden config sync` does.
    fn sync(&self, resolve: Resolve) -> anyhow::Result<settings_sync::Outcome> {
        let store = self.store();
        let _lock = store.lock()?;
        store.pull()?;
        let pushes = self.config().state.pushes();
        settings_sync::sync(
            &Place {
                store: &store,
                config_path: &self.config_path(),
                pushes,
                env_name: Some("North"),
            },
            resolve,
        )
    }

    fn status(&self) -> settings_sync::Status {
        let store = self.store();
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        settings_sync::status(&Place {
            store: &store,
            config_path: &self.config_path(),
            pushes: self.config().state.pushes(),
            env_name: None,
        })
        .unwrap()
    }
}

fn stamp(by: &str, on: &str) -> Stamp {
    Stamp {
        by: Some(by.into()),
        on: Some(on.into()),
        at: "2026-10-22T14:03:11Z".into(),
    }
}

fn accept(d: &mut ConfigDoc, rule: &str, reason: &str, by: &Stamp) {
    d.upsert_suppression(
        None,
        None,
        None,
        &SuppressionEdit {
            fingerprint: None,
            rule: Some(rule.into()),
            reason: reason.into(),
            expires: None,
        },
        by,
    )
    .unwrap();
}

fn remote_file(remote: &Path, path: &str) -> String {
    git(remote, &["show", &format!("main:{path}")])
}

fn section(s: &settings_sync::Status, key: &str) -> Changed {
    s.sections.iter().find(|x| x.key == key).unwrap().state
}

fn pushed(o: &settings_sync::Outcome) -> &str {
    assert!(
        o.done.published.as_ref().is_some_and(|p| p.pushed),
        "{:?}",
        o.done
    );
    o.done.summary.as_deref().unwrap_or_default()
}

/// A writer shares its accepted risks with who accepted them; a new
/// machine gets them on its first sync, attribution and all; a change on
/// either side reaches the other; the other sections stay each machine's.
#[test]
fn accepted_risks_travel_with_who_accepted_them() {
    if !have_git() {
        return;
    }
    let root = scratch("travel");
    let remote = bare(&root);
    let sched = Machine::new(
        &root,
        "sched",
        &remote,
        true,
        "[[output]]\nplugin = \"jira\"\n",
    );
    sched.edit(|d| {
        accept(
            d,
            "PW-011",
            "Break-glass, reviewed quarterly",
            &stamp(r"NORTH\eddard.stark", "PW-SCHED01"),
        )
    });
    let o = sched.sync(Resolve::Auto).unwrap();
    // The first share: nothing in the repository to compare with.
    assert_eq!(
        pushed(&o),
        "pathwarden settings: shared from this environment"
    );
    assert_eq!(o.status.state, Changed::InStep);
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(
        shared.contains(r"NORTH\\eddard.stark") || shared.contains(r"'NORTH\eddard.stark'"),
        "{shared}"
    );
    assert!(
        !shared.contains("[state]") && !shared.contains("jira"),
        "{shared}"
    );
    let env: serde_json::Value =
        serde_json::from_str(&remote_file(&remote, ENVIRONMENT_FILE)).unwrap();
    assert_eq!(env["name"], "North");
    assert_eq!(env["written_by_version"], settings_sync::VERSION);
    let log = git(&remote, &["log", "-1", "--format=%an%n%B", "main"]);
    assert!(
        log.contains("pathwarden settings: shared from this environment"),
        "{log}"
    );
    assert!(
        log.contains("Pathwarden: ") && log.contains("Sections: "),
        "{log}"
    );

    // A new machine, with no settings of its own, takes the repository's.
    let ws = Machine::new(
        &root,
        "ws",
        &remote,
        true,
        "[[output]]\nplugin = \"teams\"\n",
    );
    let o = ws.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Accepted risks"], "{:?}", o.done);
    assert!(o.sentence().unwrap().contains("Accepted risks"));
    let c = ws.config();
    let a = c.suppress[0].acceptance();
    assert_eq!(
        a.accepted_line(),
        r"accepted by NORTH\eddard.stark on PW-SCHED01, Oct 22, 2026"
    );
    assert_eq!(c.outputs[0].plugin, "teams", "its own plugins stay");
    assert!(ws.text().contains("# ws's settings"), "comments stay");
    assert_eq!(c.state.path.as_deref(), Some("state"));
    assert_eq!(ws.status().state, Changed::InStep);
    let last = ws.status().last_change.unwrap();
    assert_eq!(
        last.summary,
        "pathwarden settings: shared from this environment"
    );
    assert_eq!(last.sections, ["Accepted risks"]);
    // The app is told once.
    let store = ws.store();
    let seen = settings_sync::unseen_applied(&store, true).unwrap();
    assert_eq!(seen.sections, ["Accepted risks"]);
    assert!(seen.by.is_some(), "who pushed it: {seen:?}");
    assert!(settings_sync::unseen_applied(&store, false).is_none());

    // The workstation adds Tier Zero; the scheduler gets it on its next pull.
    ws.edit(|d| d.set_tier_zero(&["SVC_SYNC@NORTH.LOCAL".into()]).unwrap());
    let o = ws.sync(Resolve::Auto).unwrap();
    assert_eq!(pushed(&o), "pathwarden settings: 1 Tier Zero addition");
    let o = sched.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    assert_eq!(sched.config().tier_zero, ["SVC_SYNC@NORTH.LOCAL"]);
    assert_eq!(sched.config().outputs[0].plugin, "jira");
    // Nothing more to do on either side.
    for m in [&sched, &ws] {
        let o = m.sync(Resolve::Auto).unwrap();
        assert!(o.sentence().is_none(), "{:?}", o.done);
        assert_eq!(o.status.state, Changed::InStep);
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Each section is settled on its own: two machines that change different
/// sections both arrive; one changed on both sides stops alone, until
/// --use-repo or --keep-local settles it, and --keep-local never takes a
/// section the other side changed alone.
#[test]
fn each_section_is_settled_on_its_own() {
    if !have_git() {
        return;
    }
    let root = scratch("sections");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.edit(|d| accept(d, "PW-011", "r", &stamp("ned", "A")));
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    let rules = |days| config_edit::RulesEdit {
        disabled: vec!["PW-002".into()],
        stale_days: days,
        password_age_days: 365,
        krbtgt_age_days: 180,
        sso_key_age_days: None,
        severity: "exposure".into(),
        severities: [("PW-011".to_string(), "low".to_string())].into(),
    };
    let reason = |d: &mut ConfigDoc, text: &str| {
        d.upsert_suppression(
            Some(0),
            None,
            Some("PW-011"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-011".into()),
                reason: text.into(),
                expires: None,
            },
            &stamp("arya", "B"),
        )
        .unwrap()
    };

    // Offline, A changes the rules; B changes the accepted risk and pushes.
    a.edit(|d| d.set_rules(&rules(30), &stamp("ned", "A")).unwrap());
    b.edit(|d| reason(d, "reviewed again"));
    assert!(!pushed(&b.sync(Resolve::Auto).unwrap()).is_empty());
    // A takes B's risk and pushes its rules: nothing to choose.
    let o = a.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Accepted risks"], "{:?}", o.done);
    assert_eq!(o.done.pushed, ["Rule settings"], "{:?}", o.done);
    assert!(!o.conflict());
    assert_eq!(a.config().suppress[0].reason, "reviewed again");
    let o = b.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Rule settings"], "{:?}", o.done);
    assert_eq!(b.config().rules.stale_days, 30);
    // A severity set travels with who set it.
    let set = b.config().rules.set_severities();
    assert_eq!(
        set["PW-011"].severity,
        pathwarden_core::findings::Severity::Low
    );
    assert_eq!(set["PW-011"].by.as_deref(), Some("ned"));
    assert_eq!(set["PW-011"].at.as_deref(), Some("2026-10-22T14:03:11Z"));
    assert_eq!(a.status().state, Changed::InStep);

    // Both change one rule setting, and B also adds Tier Zero: only that
    // setting waits.
    a.edit(|d| d.set_rules(&rules(40), &stamp("ned", "A")).unwrap());
    b.edit(|d| {
        d.set_rules(&rules(50), &stamp("ned", "A")).unwrap();
        d.set_tier_zero(&["T".into()]).unwrap();
    });
    b.sync(Resolve::Auto).unwrap();
    let before_rules = a.config().rules.stale_days;
    let o = a.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Rule settings"], "{:?}", o.done);
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    assert_eq!(a.config().rules.stale_days, before_rules, "left as it is");
    assert_eq!(a.config().tier_zero, ["T"]);
    let s = o.sentence().unwrap();
    assert!(
        s.contains("Stale Tier Zero account has two values. Stale Tier Zero account: 40 days here, 50 days shared."),
        "{s}"
    );
    assert!(s.contains("--section` rules.stale_days"), "{s}");
    assert_eq!(o.status.clashes.len(), 1, "{:?}", o.status.clashes);
    assert_eq!(o.status.clashes[0].id, "rules.stale_days");
    assert_eq!(section(&a.status(), "rules"), Changed::Both);
    assert_eq!(a.status().state, Changed::Both);
    // Still stopped on the next pull.
    assert!(a.sync(Resolve::Auto).unwrap().conflict());

    // Meanwhile B removes the Tier Zero addition. A keeps its rules: the
    // removal still arrives, not undone by --keep-local.
    b.edit(|d| d.set_tier_zero(&[]).unwrap());
    b.sync(Resolve::Auto).unwrap();
    let o = a.sync(Resolve::KeepLocal(vec![])).unwrap();
    assert_eq!(
        o.done.settled,
        ["Stale Tier Zero account: kept 40 days and pushed it to the shared settings."],
        "{:?}",
        o.done
    );
    assert!(!pushed(&o).is_empty());
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    assert_eq!(o.status.state, Changed::InStep);
    assert!(a.config().tier_zero.is_empty());
    let o = b.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Rule settings"], "{:?}", o.done);
    assert_eq!(b.config().rules.stale_days, 40);
    assert!(b.config().tier_zero.is_empty());

    // Both add Tier Zero: both are kept, with nothing to choose.
    a.edit(|d| d.set_tier_zero(&["X".into()]).unwrap());
    b.edit(|d| d.set_tier_zero(&["Y".into()]).unwrap());
    b.sync(Resolve::Auto).unwrap();
    let o = a.sync(Resolve::Auto).unwrap();
    assert!(!o.conflict(), "{:?}", o.done);
    assert_eq!(o.done.merged, ["Y added to Tier Zero"], "{:?}", o.done);
    assert_eq!(o.done.shared, ["X added to Tier Zero"], "{:?}", o.done);
    assert_eq!(a.config().tier_zero, ["X", "Y"]);
    b.sync(Resolve::Auto).unwrap();
    assert_eq!(b.config().tier_zero, ["Y", "X"]);

    // One setting with two values; A takes the repository's, for that
    // entry only.
    a.edit(|d| {
        d.set_rules(&rules(60), &stamp(r"CORP\a.admin", "A"))
            .unwrap()
    });
    b.edit(|d| {
        d.set_rules(&rules(70), &stamp(r"CORP\a.admin", "A"))
            .unwrap()
    });
    b.sync(Resolve::Auto).unwrap();
    assert!(a.sync(Resolve::Auto).unwrap().conflict());
    let e = a
        .sync(Resolve::UseRepo(vec!["tierzero".into()]))
        .unwrap_err();
    assert!(e.to_string().contains("not a shared section"), "{e}");
    let e = a
        .sync(Resolve::UseRepo(vec!["rules.krbtgt_age_days".into()]))
        .unwrap_err();
    assert!(e.to_string().contains("nothing to choose"), "{e}");
    let o = a
        .sync(Resolve::UseRepo(vec!["RULES.stale_days".into()]))
        .unwrap();
    assert_eq!(
        o.done.settled,
        ["Stale Tier Zero account: now 70 days, from the shared settings."],
        "{:?}",
        o.done
    );
    assert_eq!(a.config().rules.stale_days, 70);
    assert_eq!(a.status().state, Changed::InStep);
    let _ = std::fs::remove_dir_all(&root);
}

/// A machine that doesn't push may change shared settings here; they are
/// reported as changed here and stay, while the other sections follow the
/// repository; they can't be kept over the repository's, and --use-repo
/// drops them.
#[test]
fn a_reader_changes_settings_only_here() {
    if !have_git() {
        return;
    }
    let root = scratch("reader");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_tier_zero(&["A".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let r = Machine::new(&root, "r", &remote, false, "");
    assert!(r.sync(Resolve::Auto).unwrap().applied());
    r.edit(|d| d.set_tier_zero(&["A".into(), "B".into()]).unwrap());
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.here_only, ["Tier Zero additions"], "{:?}", o.done);
    let s = o.sentence().unwrap();
    assert!(
        s.contains("Only on this computer: Tier Zero additions"),
        "{s}"
    );
    assert!(s.contains("replaces them with the shared settings"), "{s}");
    assert_eq!(
        remote_file(&remote, SETTINGS_FILE).matches("\"B\"").count(),
        0
    );
    assert_eq!(section(&r.status(), "tier_zero"), Changed::Here);
    // The writer accepts a risk: the reader receives it, its own Tier Zero
    // change stays.
    w.edit(|d| accept(d, "PW-011", "r", &stamp("ned", "W")));
    w.sync(Resolve::Auto).unwrap();
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Accepted risks"], "{:?}", o.done);
    assert_eq!(r.config().suppress.len(), 1);
    assert_eq!(r.config().tier_zero, ["A", "B"]);
    let e = r.sync(Resolve::KeepLocal(vec![])).unwrap_err().to_string();
    assert!(e.contains("doesn't push"), "{e}");
    let o = r.sync(Resolve::UseRepo(vec![])).unwrap();
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    assert_eq!(r.config().tier_zero, ["A"]);
    // The writer's next change reaches the reader.
    w.edit(|d| d.set_tier_zero(&["A".into(), "C".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    assert!(r.sync(Resolve::Auto).unwrap().applied());
    assert_eq!(r.config().tier_zero, ["A", "C"]);
    let _ = std::fs::remove_dir_all(&root);
}

/// Settings a newer Pathwarden wrote: keys this version doesn't know are
/// kept, and an accepted risk or zone with one is not applied; a section it
/// doesn't know stays in the repository, and the status names the writer's
/// version. A typo is refused, and a section never shared is dropped.
#[test]
fn a_newer_writers_settings_are_read() {
    if !have_git() {
        return;
    }
    let root = scratch("newer");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_tier_zero(&["A".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    // As 9.9.9 would write it, pushed by hand.
    let store = w.store();
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        store
            .write_state_file(
                SETTINGS_FILE,
                b"tier_zero = [\"A\"]\n\n[[zone]]\nname = \"Servers\"\ngroups = [\"G\"]\ncriticality = \"high\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nreview_board = \"CAB\"\n\n[risk_owners]\nPW-011 = \"secops\"\n\n[state]\nbackend = \"local\"\n",
            )
            .unwrap();
        store
            .write_state_file(
                ENVIRONMENT_FILE,
                br#"{"name": "North", "written_by_version": "9.9.9", "colour": "blue"}"#,
            )
            .unwrap();
        assert!(store.publish_with("newer", || Ok(None)).unwrap().pushed);
    }
    let r = Machine::new(&root, "r", &remote, true, "");
    let o = r.sync(Resolve::Auto).unwrap();
    assert!(o.applied(), "{:?}", o.done);
    let c = r.config();
    assert_eq!(c.zones[0].name, "Servers");
    let w_text: Vec<String> = c.warnings.iter().map(|w| w.to_string()).collect();
    assert!(
        w_text
            .iter()
            .any(|w| w.contains("criticality") && w.contains("zone is not applied")),
        "{w_text:?}"
    );
    assert!(
        w_text
            .iter()
            .any(|w| w.contains("review_board") && w.contains("accepted risk is not applied")),
        "{w_text:?}"
    );
    // Neither is applied on this version.
    assert_eq!(c.active_suppression("PW-011-1", "PW-011", 0), None);
    assert!(!r.text().contains("risk_owners"));
    assert!(
        r.text().contains("backend = \"git\""),
        "[state] stays its own"
    );
    let s = r.status();
    assert_eq!(s.state, Changed::InStep);
    assert!(s.newer_writer);
    assert_eq!(s.written_by_version.as_deref(), Some("9.9.9"));
    assert!(
        s.notes.iter().any(|n| n.contains("Pathwarden 9.9.9")),
        "{:?}",
        s.notes
    );
    assert!(
        s.notes.iter().any(|n| n.contains("risk_owners")),
        "{:?}",
        s.notes
    );
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("`state`") && n.contains("never shared")),
        "{:?}",
        s.notes
    );
    // Its own change keeps the section it doesn't know in the repository,
    // and drops the one never shared.
    r.edit(|d| d.set_tier_zero(&["A".into(), "B".into()]).unwrap());
    assert!(!pushed(&r.sync(Resolve::Auto).unwrap()).is_empty());
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(
        shared.contains("risk_owners") && shared.contains("criticality"),
        "{shared}"
    );
    assert!(!shared.contains("[state]"), "{shared}");

    // A typo of a known key is not applied: the settings here stay.
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        store
            .write_state_file(
                SETTINGS_FILE,
                b"[[suppress]]\nrule = \"PW-011\"\nreasn = \"r\"\n",
            )
            .unwrap();
        assert!(store.publish_with("typo", || Ok(None)).unwrap().pushed);
    }
    let before = r.text();
    let e = r.sync(Resolve::Auto).unwrap_err().to_string();
    assert!(
        e.contains("can't be used here") && e.contains("reason"),
        "{e}"
    );
    assert_eq!(r.text(), before);
    let _ = std::fs::remove_dir_all(&root);
}

/// A change saved while another machine pushes first: sections that didn't
/// change there are pushed on top; a section that did is left to settle.
#[test]
fn a_push_after_another_machines_push() {
    if !have_git() {
        return;
    }
    let root = scratch("race");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    // A pulls, then B pushes a run point before A pushes.
    let store = a.store();
    let lock = store.lock().unwrap();
    store.pull().unwrap();
    {
        let bs = b.store();
        let _l = bs.lock().unwrap();
        bs.pull().unwrap();
        bs.write_state_file("history/20261018T120000.000Z.json", b"{}\n")
            .unwrap();
        assert!(bs.publish_with("run", || Ok(None)).unwrap().pushed);
    }
    a.edit(|d| d.set_tier_zero(&["A".into()]).unwrap());
    let place = Place {
        store: &store,
        config_path: &a.config_path(),
        pushes: true,
        env_name: None,
    };
    let o = settings_sync::sync(&place, Resolve::Auto).unwrap();
    assert_eq!(o.done.published.as_ref().unwrap().retries, 1);
    assert!(remote_file(&remote, SETTINGS_FILE).contains("\"A\""));
    assert!(!git(&remote, &["ls-tree", "-r", "main", "history/"]).is_empty());
    drop(lock);

    // Now B changes Tier Zero meanwhile: A's Tier Zero is left to settle,
    // its rules go.
    let lock = store.lock().unwrap();
    store.pull().unwrap();
    b.sync(Resolve::Auto).unwrap();
    b.edit(|d| d.set_tier_zero(&["B".into()]).unwrap());
    b.sync(Resolve::Auto).unwrap();
    a.edit(|d| {
        d.set_tier_zero(&["A".into(), "C".into()]).unwrap();
        d.set_rules(
            &config_edit::RulesEdit {
                disabled: vec![],
                stale_days: 33,
                password_age_days: 365,
                krbtgt_age_days: 180,
                sso_key_age_days: None,
                severity: "exposure".into(),
                severities: Default::default(),
            },
            &stamp("ned", "A"),
        )
        .unwrap();
    });
    let o = settings_sync::sync(&place, Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Tier Zero additions"], "{:?}", o.done);
    assert_eq!(o.done.pushed, ["Rule settings"], "{:?}", o.done);
    drop(lock);
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(
        shared.contains("\"B\"") && shared.contains("33"),
        "{shared}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

const PACK: &str = "[pack]\nname = \"acme\"\nversion = 1\nsource_kinds = [\"AcmeHound\"]\nkind_prefix = \"AC_\"\ntrusted = true\n\n[[node]]\nkind = \"AC_Thing\"\nicon = \"clock\"\ncolor = \"#abc\"\n";

fn acme_trusted(m: &Machine) -> bool {
    Config::from_file(&m.config_path())
        .unwrap()
        .packs()
        .unwrap()
        .iter()
        .find(|p| p.name() == "acme")
        .unwrap()
        .trusted()
}

/// A mapping pack in the environment's packs folder travels with the
/// settings; one elsewhere stays and is named. Trust never travels: a
/// pushed pack is untrusted on the reader whatever it says, until someone
/// there reviews it; a new text from the repository is untrusted again;
/// trust by name never reaches it.
#[test]
fn mapping_packs_travel_but_trust_does_not() {
    if !have_git() {
        return;
    }
    pathwarden_core::config::check_pack_text(PACK).unwrap();
    let root = scratch("packs");
    let remote = bare(&root);
    let outside = root.join("outside.toml");
    std::fs::write(&outside, PACK.replace("acme", "other")).unwrap();
    let w = Machine::new(
        &root,
        "w",
        &remote,
        true,
        &format!(
            "[[mapping]]\npath = \"packs/acme.toml\"\n\n[[mapping]]\npath = \"{}\"\n",
            outside.to_string_lossy().replace('\\', "/")
        ),
    );
    std::fs::create_dir_all(w.dir.join("packs")).unwrap();
    std::fs::write(w.dir.join("packs/acme.toml"), PACK).unwrap();
    assert!(acme_trusted(&w), "the writer's own pack trusts itself");
    let o = w.sync(Resolve::Auto).unwrap();
    assert!(!pushed(&o).is_empty());
    assert!(
        o.status
            .notes
            .iter()
            .any(|n| n.contains("outside.toml") && n.contains("not shared")),
        "{:?}",
        o.status.notes
    );
    // The reader trusts `acme` by name for a pack of its own: that never
    // reaches the pushed one.
    let r = Machine::new(
        &root,
        "r",
        &remote,
        true,
        "[opengraph]\ntrust = [\"acme\"]\n",
    );
    assert!(r.sync(Resolve::Auto).unwrap().applied());
    assert_eq!(
        std::fs::read_to_string(r.dir.join("packs/acme.toml")).unwrap(),
        PACK
    );
    let c = Config::from_file(&r.config_path()).unwrap();
    assert_eq!((c.mappings.len(), c.user_packs.len()), (1, 1));
    assert!(c.user_packs[0].from_repo.is_some());
    assert!(
        !acme_trusted(&r),
        "trusted = true in the pack doesn't travel"
    );
    assert_eq!(r.status().state, Changed::InStep);
    // Reviewed here: trusted, at the text reviewed only.
    let review = |m: &Machine, digest: Option<&str>| {
        pathwarden_core::pack_origin::mark_reviewed(
            &m.config_path(),
            "packs/acme.toml",
            true,
            digest,
        )
    };
    let shown = pathwarden_core::pack_origin::text_digest(PACK);
    let e = review(&r, Some("not-the-digest")).unwrap_err();
    assert_eq!(e, pathwarden_core::pack_origin::CHANGED_SINCE_REVIEW);
    assert!(!acme_trusted(&r));
    review(&r, Some(&shown)).unwrap();
    assert!(acme_trusted(&r));
    // The record next to pathwarden.toml lost: the pack is still from the
    // repository (the sync's own data says so), untrusted, and name trust
    // doesn't come back.
    let origins = r.dir.join(pathwarden_core::pack_origin::FILE);
    std::fs::remove_file(&origins).unwrap();
    assert!(!acme_trusted(&r), "a lost record trusts nothing");
    let c = Config::from_file(&r.config_path()).unwrap();
    assert!(c.user_packs[0].from_repo.is_some());
    review(&r, Some(&shown)).unwrap();
    assert!(acme_trusted(&r), "reviewed again, the record is made again");
    // The record broken: every pack in packs/ is untrusted, and says why.
    std::fs::write(&origins, "{ not json").unwrap();
    assert!(!acme_trusted(&r), "a broken record trusts nothing");
    let c = Config::from_file(&r.config_path()).unwrap();
    assert!(c.user_packs[0].from_repo.as_ref().unwrap().unreadable);
    review(&r, Some(&shown)).unwrap();
    assert!(acme_trusted(&r));
    // The writer changes the pack: untrusted again on the reader.
    std::fs::write(
        w.dir.join("packs/acme.toml"),
        PACK.replace("color = \"#abc\"", "color = \"#def\""),
    )
    .unwrap();
    assert!(!pushed(&w.sync(Resolve::Auto).unwrap()).is_empty());
    assert!(r.sync(Resolve::Auto).unwrap().applied());
    assert!(!acme_trusted(&r), "a new text needs a new review");
    let _ = std::fs::remove_dir_all(&root);
}

/// A bad pack in the repository is left out, with its [[mapping]] entry;
/// the rest of the settings still arrive. A pack path that only looks like
/// the history folder's (`packs/state.toml` beside `packs/state`) is fine.
#[test]
fn one_bad_entry_stops_nothing_else() {
    if !have_git() {
        return;
    }
    let root = scratch("badpack");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.sync(Resolve::Auto).unwrap();
    let store = w.store();
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        let text = format!(
            "tier_zero = [\"T\"]\n\n[[mapping]]\npath = \"packs/state.toml\"\n\n[[mapping]]\npath = \"../evil.toml\"\n\n[[mapping_files]]\npath = \"packs/state.toml\"\ntext = {}\n\n[[mapping_files]]\npath = \"../evil.toml\"\ntext = {}\n",
            toml_string(PACK),
            toml_string(PACK)
        );
        store
            .write_state_file(SETTINGS_FILE, text.as_bytes())
            .unwrap();
        assert!(store.publish_with("bad", || Ok(None)).unwrap().pushed);
    }
    let dir = root.join("r");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"packs/state\"\nkeep = \"full\"\n",
            remote.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let r = Machine { dir };
    let o = r.sync(Resolve::Auto).unwrap();
    assert!(o.applied(), "{:?}", o.done);
    let s = o.sentence().unwrap();
    assert!(s.contains("../evil.toml") && s.contains("left out"), "{s}");
    let c = Config::from_file(&r.config_path()).unwrap();
    assert_eq!(c.tier_zero, ["T"]);
    assert_eq!(c.mappings.len(), 1, "only the good pack");
    assert!(r.dir.join("packs/state.toml").exists());
    assert!(!root.join("evil.toml").exists());

    // A repository file that can't be read stops nothing here, and
    // --keep-local replaces it.
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        store
            .write_state_file(SETTINGS_FILE, b"this is [not toml")
            .unwrap();
        assert!(store.publish_with("broken", || Ok(None)).unwrap().pushed);
    }
    let o = r.sync(Resolve::Auto).unwrap();
    assert!(o.done.unreadable.is_some() && o.problem(), "{:?}", o.done);
    assert!(o.status.damaged);
    assert!(o.sentence().unwrap().contains("--keep-local"));
    assert!(o.page_sentence().unwrap().contains("can't be read"));
    assert!(!o.page_sentence().unwrap().contains("pathwarden config"));
    assert_eq!(
        Config::from_file(&r.config_path()).unwrap().tier_zero,
        ["T"]
    );
    let o = r.sync(Resolve::KeepLocal(vec![])).unwrap();
    assert!(!pushed(&o).is_empty(), "{:?}", o.done);
    assert!(remote_file(&remote, SETTINGS_FILE).contains("\"T\""));
    let _ = std::fs::remove_dir_all(&root);
}

/// Keeping the settings here only takes sections changed here: never one
/// the repository changed alone, which keeping would undo.
#[test]
fn keep_local_never_undoes_the_repositorys_change() {
    if !have_git() {
        return;
    }
    let root = scratch("keepsect");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    a.edit(|d| accept(d, "PW-013", "r", &stamp("ned", "A")));
    a.sync(Resolve::Auto).unwrap();
    let e = b
        .sync(Resolve::KeepLocal(vec!["suppress".into()]))
        .unwrap_err()
        .to_string();
    assert!(e.contains("has only a shared update"), "{e}");
    assert!(remote_file(&remote, SETTINGS_FILE).contains("PW-013"));
    let _ = std::fs::remove_dir_all(&root);
}

/// A pack path that would reach the history folder (in any case) or go
/// through a link is refused, and nothing is written.
#[test]
fn packs_never_land_in_the_history_folder() {
    if !have_git() {
        return;
    }
    let root = scratch("packpath");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.sync(Resolve::Auto).unwrap();
    let store = w.store();
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        let text = format!(
            "[[mapping]]\npath = \"Packs/State/evil.toml\"\n[[mapping_files]]\npath = \"Packs/State/evil.toml\"\ntext = {}\n",
            toml_string(PACK)
        );
        store
            .write_state_file(SETTINGS_FILE, text.as_bytes())
            .unwrap();
        assert!(store.publish_with("evil", || Ok(None)).unwrap().pushed);
    }
    let dir = root.join("r");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        format!(
            "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"packs/state\"\nkeep = \"full\"\n",
            remote.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let r = Machine { dir };
    let o = r.sync(Resolve::Auto).unwrap();
    let s = o.sentence().unwrap();
    assert!(
        s.contains("history folder") && s.contains("left out"),
        "{s}"
    );
    assert!(
        !r.text().contains("evil.toml"),
        "its [[mapping]] stays out too"
    );
    assert!(!r.dir.join("packs/state/evil.toml").exists());
    let _ = std::fs::remove_dir_all(&root);
}

fn toml_string(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    )
}

/// Settings travel only with a git history that keeps full runs and
/// settings.
#[test]
fn only_full_git_histories_share_settings() {
    let mut c = Config::parse("[state]\nbackend = \"git\"\nremote = \"r\"\n").unwrap();
    assert!(settings_sync::inactive(&c.state).is_some());
    c = Config::parse("[state]\nbackend = \"git\"\nremote = \"r\"\nkeep = \"full\"\n").unwrap();
    assert!(settings_sync::inactive(&c.state).is_none());
    c = Config::parse("[state]\nkeep = \"full\"\n").unwrap();
    assert!(settings_sync::inactive(&c.state).is_some());
    assert!(Config::parse("[state]\nkeep = \"everything\"\n").is_err());
    // The old names switch: false is ignored, with a warning.
    let c = Config::parse("[state]\ninclude_names = false\n").unwrap();
    assert!(c.state.keeps_names());
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
    assert!(Config::parse("[state]\ninclude_names = true\n")
        .unwrap()
        .warnings
        .is_empty());
    // Listing Tier Zero among management planes reads as the opposite.
    let e = Config::parse("[management_planes]\ntier_zero = [\"X\"]\n").unwrap_err();
    assert!(e.to_string().contains("not_tier_zero"), "{e}");
    // A key it doesn't know: the section isn't applied (it could narrow it).
    let c = Config::parse(
        "[management_planes]\nnot_tier_zero = [\"SYNC01\"]\nonly_for_scope = \"x\"\n",
    )
    .unwrap();
    assert!(c.management_planes.applied().is_empty());
    assert!(c.warnings[0].to_string().contains("section is not applied"));
    let c = Config::parse("[management_planes]\nnot_tier_zero = [\"SYNC01\"]\n").unwrap();
    assert_eq!(c.management_planes.applied(), ["SYNC01"]);
}

/// Settings in an encrypted history: two machines with the passphrase
/// share an accepted risk, who accepted it included; nothing of it is
/// plain in the working copies or the repository's objects, and the
/// commit messages say only "pathwarden settings". A machine without the
/// passphrase can't sync them, says why, and changes nothing here.
#[test]
fn settings_travel_encrypted() {
    use pathwarden_core::crypt::{self, SecretString};
    if !have_git() {
        return;
    }
    let root = scratch("encrypted");
    pathwarden_core::keystore::use_test_store(&root.join("keystore"));
    let remote = bare(&root);
    let pass = || SecretString::from("a passphrase long enough".to_string());
    let a = Machine::new(&root, "a", &remote, true, "");
    a.sync(Resolve::Auto).unwrap();
    {
        // It takes the history's lock and pulls itself.
        let s = a.store();
        s.encrypt(&pass(), true).unwrap();
        crypt::give_passphrase(&s.dir, pass());
    }
    a.edit(|d| {
        accept(
            d,
            "PW-011",
            "Break-glass vault, reviewed quarterly",
            &stamp(r"NORTH\eddard.stark", "PW-SCHED01"),
        )
    });
    let o = a.sync(Resolve::Auto).unwrap();
    assert!(
        o.done.published.as_ref().is_some_and(|p| p.pushed),
        "{:?}",
        o.done
    );
    // A second machine with the passphrase takes it, who and all.
    let b = Machine::new(&root, "b", &remote, true, "");
    crypt::give_passphrase(&b.store().dir, pass());
    let o = b.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Accepted risks"], "{:?}", o.done);
    assert_eq!(
        b.config().suppress[0].acceptance().accepted_line(),
        r"accepted by NORTH\eddard.stark on PW-SCHED01, Oct 22, 2026"
    );
    let last = b.status().last_change.unwrap();
    assert!(last.summary.contains("accepted risk"), "{last:?}");
    // Nothing plain: the working copies' files, every object in the
    // repository, and the commit messages.
    let secrets = ["Break-glass", "eddard", "PW-SCHED01"];
    for m in [&a, &b] {
        let mut stack = vec![m.store().dir];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let text = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
                    for s in secrets {
                        assert!(!text.contains(s), "{} holds {s}", p.display());
                    }
                }
            }
        }
    }
    let objects = git(&remote, &["cat-file", "--batch-all-objects", "--batch"]);
    for s in secrets {
        assert!(!objects.contains(s), "an object holds {s}");
    }
    // Since the history was encrypted (the commit before held no secret).
    let sealed = git(
        &remote,
        &[
            "log",
            "-1",
            "--format=%H",
            "--grep=encrypt the history",
            "main",
        ],
    );
    let log = git(
        &remote,
        &["log", "--format=%B", &format!("{}..main", sealed.trim())],
    );
    assert!(log.contains("pathwarden settings"), "{log}");
    for s in ["Changed-by", "accepted risk", "Sections"] {
        assert!(!log.contains(s), "the log says {s}: {log}");
    }
    // Nor do their authors and committers say who: the encrypting commit
    // and every one after it.
    let who = git(
        &remote,
        &[
            "log",
            "--format=%an <%ae>|%cn <%ce>",
            &format!("{}^..main", sealed.trim()),
        ],
    );
    assert!(who.lines().count() >= 2, "{who}");
    for line in who.lines() {
        assert_eq!(
            line, "Pathwarden <pathwarden@invalid>|Pathwarden <pathwarden@invalid>",
            "{who}"
        );
    }
    // Without the passphrase (another account's store, nothing given in
    // this process): nothing synced, and it says why.
    for m in [&a, &b] {
        crypt::forget_in_process(&m.store().dir);
    }
    pathwarden_core::keystore::use_test_store(&root.join("keystore-c"));
    let c = Machine::new(&root, "c", &remote, true, "");
    let before = c.text();
    match c.sync(Resolve::Auto) {
        Ok(o) => {
            assert!(o.done.unreadable.is_some(), "{:?}", o.done);
            assert!(!o.status.damaged);
            let s = o.sentence().unwrap();
            assert!(
                s.contains("passphrase")
                    && s.contains("can't be read here")
                    && !s.contains("--keep-local"),
                "{s}"
            );
            // Keeping the settings here would overwrite what it can't read.
            let e = c.sync(Resolve::KeepLocal(vec![])).unwrap_err();
            assert!(format!("{e:#}").contains("can't be replaced"), "{e:#}");
        }
        Err(e) => assert!(format!("{e:#}").contains("passphrase"), "{e:#}"),
    }
    assert_eq!(c.text(), before);
    for m in [&a, &b] {
        crypt::forget_in_process(&m.store().dir);
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A history refused here (pathwarden.toml says it is encrypted, the
/// repository is plain) is refused for settings too: nothing is read from
/// it or written to it.
#[test]
fn a_refused_history_syncs_no_settings() {
    if !have_git() {
        return;
    }
    let root = scratch("refused");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_tier_zero(&["T".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let r = Machine::new(&root, "r", &remote, true, "encrypted = true\n");
    let before = r.text();
    let e = r.sync(Resolve::Auto).unwrap_err();
    assert!(format!("{e:#}").contains("encrypted"), "{e:#}");
    assert_eq!(r.text(), before);
    let _ = std::fs::remove_dir_all(&root);
}

/// Sections that are never shared (gap 3): `[[output]]`, `[ingest]`,
/// `[opengraph]` and `[collect]` pushed into the repository's settings by a
/// writer reach no reader. An output there would run a program on every
/// reader; an ingest or OpenGraph limit would change what it reads; a
/// trusted pack would turn on its paths. The shared section beside them is
/// applied, and the reader's own copies stay as they were.
#[test]
fn sections_never_shared_are_ignored_on_pull() {
    if !have_git() {
        return;
    }
    let root = scratch("never-shared");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_tier_zero(&["A".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let r = Machine::new(
        &root,
        "r",
        &remote,
        true,
        "\n[ingest]\nmax_zip_entries = 500\n\n[opengraph]\nmax_nodes = 1000\n",
    );
    assert!(r.sync(Resolve::Auto).unwrap().applied());
    // Pushed by hand, as a hostile writer could.
    let store = w.store();
    {
        let _lock = store.lock().unwrap();
        store.pull().unwrap();
        store
            .write_state_file(
                SETTINGS_FILE,
                b"tier_zero = [\"A\", \"B\"]\n\n\
                  [[output]]\nplugin = \"evil\"\ncommand = [\"C:/contoso/evil.exe\"]\n\n\
                  [ingest]\nmax_zip_entries = 999999\nmax_archive_gib = 9999\n\n\
                  [opengraph]\nmax_nodes = 99999999\ntrust = [\"fabrikam-pack\"]\n\n\
                  [collect]\nsharphound = \"C:/contoso/SharpHound.exe\"\n",
            )
            .unwrap();
        assert!(store.publish_with("hostile", || Ok(None)).unwrap().pushed);
    }
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    let c = r.config();
    assert_eq!(c.tier_zero, ["A", "B"]);
    assert!(c.outputs.is_empty(), "{:?}", c.outputs);
    assert_eq!(c.ingest.max_zip_entries, Some(500));
    assert_eq!(c.ingest.max_archive_gib, None);
    assert_eq!(c.opengraph.max_nodes, Some(1000));
    assert!(c.opengraph.trust.is_empty(), "{:?}", c.opengraph.trust);
    let text = r.text();
    for word in ["evil", "999999", "fabrikam-pack", "SharpHound", "[collect]"] {
        assert!(!text.contains(word), "{word} reached the reader:\n{text}");
    }
    // The status says they were left out.
    let s = r.status();
    for key in ["output", "ingest", "opengraph", "collect"] {
        assert!(
            s.notes
                .iter()
                .any(|n| n.contains(&format!("`{key}`")) && n.contains("never shared")),
            "{key}: {:?}",
            s.notes
        );
    }
    // The reader's next push drops them from the repository.
    r.edit(|d| {
        d.set_tier_zero(&["A".into(), "B".into(), "C".into()])
            .unwrap()
    });
    assert!(!pushed(&r.sync(Resolve::Auto).unwrap()).is_empty());
    let shared = remote_file(&remote, SETTINGS_FILE);
    for word in ["evil", "[ingest]", "[opengraph]", "[collect]"] {
        assert!(!shared.contains(word), "{word}:\n{shared}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A new install's rules, as `pathwarden.toml` starts from the example.
const DEFAULT_RULES: &str =
    "[rules]\ndisabled = []\nstale_days = 90\npassword_age_days = 365\nkrbtgt_age_days = 180\n";

fn before_connect_copies(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pathwarden.toml.before-connect-")
        })
        .collect();
    v.sort();
    v
}

/// A computer's first sync takes the history's settings: a fresh install
/// with default rules gets the history's customized rules and zones, its
/// own pathwarden.toml saved beside it first, and one line says so; a
/// section only it has is pushed. After that a change here is pushed, and
/// only edits on two computers differ from the shared ones. A computer that only
/// reads gets the history's settings on its first sync as well.
#[test]
fn a_new_computer_takes_the_historys_settings() {
    if !have_git() {
        return;
    }
    let root = scratch("first");
    let remote = bare(&root);
    let rules = |days, disabled: &[&str]| config_edit::RulesEdit {
        disabled: disabled.iter().map(|s| s.to_string()).collect(),
        stale_days: days,
        password_age_days: 365,
        krbtgt_age_days: 180,
        sso_key_age_days: None,
        severity: "exposure".into(),
        severities: Default::default(),
    };
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| {
        d.set_rules(&rules(30, &["PW-002"]), &stamp("ned", "W"))
            .unwrap();
        d.upsert_zone(
            None,
            None,
            &config_edit::ZoneEdit {
                name: "Tier 1 servers".into(),
                groups: vec!["SERVER ADMINS@NORTH.LOCAL".into()],
                ..Default::default()
            },
        )
        .unwrap();
    });
    assert!(!pushed(&w.sync(Resolve::Auto).unwrap()).is_empty());

    // A fresh install, its default rules and a Tier Zero addition of its own.
    let n = Machine::new(&root, "n", &remote, true, DEFAULT_RULES);
    n.edit(|d| d.set_tier_zero(&["SVC_N@NORTH.LOCAL".into()]).unwrap());
    let before = std::fs::read(n.config_path()).unwrap();
    let s = n.status();
    assert!(s.first_sync);
    assert_eq!(section(&s, "rules"), Changed::Repository, "never Both");
    assert_eq!(section(&s, "tier_zero"), Changed::Here);
    let o = n.sync(Resolve::Auto).unwrap();
    assert!(!o.conflict(), "{:?}", o.done);
    // Its own rules are replaced; it had no zones, so those are only taken.
    assert_eq!(o.done.first, ["Rule settings"], "{:?}", o.done);
    assert_eq!(o.done.taken, ["Rule settings", "Zones"], "{:?}", o.done);
    assert_eq!(o.done.applied, ["Rule settings", "Zones"], "{:?}", o.done);
    assert_eq!(o.done.pushed, ["Tier Zero additions"], "{:?}", o.done);
    let c = n.config();
    assert_eq!(c.rules.stale_days, 30);
    assert_eq!(c.rules.disabled, ["PW-002"]);
    assert_eq!(c.zones.len(), 1);
    assert_eq!(c.tier_zero, ["SVC_N@NORTH.LOCAL"]);
    // The copy: beside it, as it was.
    let copies = before_connect_copies(&n.dir);
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(o.done.backups, [copies[0].clone()]);
    assert_eq!(std::fs::read(&copies[0]).unwrap(), before);
    let name = copies[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let line = format!(
        "Rule settings and zones were taken from the run history. This computer's earlier \
         settings are saved in {name}."
    );
    for s in [o.sentence().unwrap(), o.page_sentence().unwrap()] {
        assert!(s.contains(&line), "{s}");
        assert!(!s.contains("differ"), "{s}");
    }
    let a = settings_sync::unseen_applied(&n.store(), false).unwrap();
    assert_eq!(
        a.first.as_deref(),
        Some(&["Rule settings".to_string(), "Zones".to_string()][..])
    );
    assert_eq!(a.backups, [name.as_str()]);
    assert_eq!(n.status().state, Changed::InStep);

    // The writer gets the section only the new computer had.
    let o = w.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Tier Zero additions"], "{:?}", o.done);
    assert!(o.done.taken.is_empty() && o.done.backups.is_empty());
    assert!(before_connect_copies(&w.dir).is_empty());

    // A second sync after an edit here pushes it: no copy, no first line.
    n.edit(|d| {
        d.set_rules(&rules(45, &["PW-002"]), &stamp("arya", "N"))
            .unwrap()
    });
    let o = n.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.pushed, ["Rule settings"], "{:?}", o.done);
    assert!(o.done.taken.is_empty() && o.done.backups.is_empty());
    assert_eq!(before_connect_copies(&n.dir).len(), 1);
    w.sync(Resolve::Auto).unwrap();
    assert_eq!(w.config().rules.stale_days, 45);

    // The same setting edited on two computers after the first sync has
    // two values.
    w.edit(|d| d.set_rules(&rules(50, &[]), &stamp("ned", "W")).unwrap());
    w.sync(Resolve::Auto).unwrap();
    n.edit(|d| d.set_rules(&rules(60, &[]), &stamp("arya", "N")).unwrap());
    let o = n.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Rule settings"], "{:?}", o.done);
    assert_eq!(n.config().rules.stale_days, 60, "left as it is");
    assert_eq!(section(&n.status(), "rules"), Changed::Both);
    let s = o.page_sentence().unwrap();
    assert!(
        s.contains("Stale Tier Zero account has two values. Choose on Settings."),
        "{s}"
    );
    assert!(
        !s.contains("pathwarden config"),
        "no commands on pages: {s}"
    );
    assert_eq!(before_connect_copies(&n.dir).len(), 1);

    // A computer that only reads: the history's settings on its first sync.
    let r = Machine::new(&root, "r", &remote, false, DEFAULT_RULES);
    let head = git(&remote, &["rev-parse", "main"]);
    let o = r.sync(Resolve::Auto).unwrap();
    assert!(!o.conflict(), "{:?}", o.done);
    assert_eq!(o.done.first, ["Rule settings"], "{:?}", o.done);
    assert_eq!(
        o.done.taken,
        ["Tier Zero additions", "Rule settings", "Zones"],
        "{:?}",
        o.done
    );
    assert_eq!(r.config().rules.stale_days, 50);
    assert_eq!(r.config().zones.len(), 1);
    assert_eq!(before_connect_copies(&r.dir).len(), 1);
    assert!(o
        .sentence()
        .unwrap()
        .contains("Tier Zero additions, rule settings and zones were taken from the run history."));
    assert_eq!(
        git(&remote, &["rev-parse", "main"]),
        head,
        "a reader pushes nothing"
    );
    assert_eq!(r.status().state, Changed::InStep);
    let _ = std::fs::remove_dir_all(&root);
}

fn rules_with(days: i64) -> config_edit::RulesEdit {
    config_edit::RulesEdit {
        disabled: Vec::new(),
        stale_days: days,
        password_age_days: 365,
        krbtgt_age_days: 180,
        sso_key_age_days: None,
        severity: "exposure".into(),
        severities: Default::default(),
    }
}

fn zone(name: &str) -> config_edit::ZoneEdit {
    config_edit::ZoneEdit {
        name: name.into(),
        groups: vec!["SERVER ADMINS@NORTH.LOCAL".into()],
        ..Default::default()
    }
}

/// A reader's section kept only on this computer is a section synced as
/// absent: a shared version that arrives later is merged with it entry by
/// entry, never replacing it as a first sync would; an entry of the same
/// name with other contents has two values.
#[test]
fn a_readers_own_section_is_not_replaced_later() {
    if !have_git() {
        return;
    }
    let root = scratch("reader-own");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_tier_zero(&["A".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let r = Machine::new(&root, "r", &remote, false, "");
    r.edit(|d| d.upsert_zone(None, None, &zone("Mine")).unwrap());
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.here_only, ["Zones"], "{:?}", o.done);
    // The writer shares a zone of its own.
    w.edit(|d| d.upsert_zone(None, None, &zone("Theirs")).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let o = r.sync(Resolve::Auto).unwrap();
    assert!(o.done.conflict.is_empty(), "{:?}", o.done);
    assert!(o.done.taken.is_empty(), "{:?}", o.done);
    assert_eq!(o.done.merged, ["Zone Theirs added"], "{:?}", o.done);
    assert_eq!(o.done.here_only, ["Zones"], "{:?}", o.done);
    let names: Vec<String> = r.config().zones.iter().map(|z| z.name.clone()).collect();
    assert_eq!(names, ["Mine", "Theirs"]);
    assert_eq!(section(&r.status(), "zone"), Changed::Here);
    // The writer shares a "Mine" of its own: two values for it.
    w.edit(|d| {
        let mut z = zone("Mine");
        z.groups = vec!["OTHER ADMINS@CORP.LOCAL".into()];
        d.upsert_zone(None, None, &z).unwrap()
    });
    w.sync(Resolve::Auto).unwrap();
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Zones"], "{:?}", o.done);
    assert_eq!(
        o.status.clashes[0].id, "zone.mine",
        "{:?}",
        o.status.clashes
    );
    let mine = r
        .config()
        .zones
        .into_iter()
        .find(|z| z.name == "Mine")
        .unwrap();
    assert_eq!(
        mine.groups,
        zone("Mine").groups,
        "this computer's, until chosen"
    );
    assert_eq!(section(&r.status(), "zone"), Changed::Both);
    let _ = std::fs::remove_dir_all(&root);
}

/// A base file that is there but can't be read is not a first sync: a
/// section that differs is shown as differing; the history's are never taken
/// silently.
#[test]
fn a_damaged_base_is_not_a_first_sync() {
    if !have_git() {
        return;
    }
    let root = scratch("damaged-base");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_rules(&rules_with(30), &stamp("ned", "W")).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let n = Machine::new(&root, "n", &remote, true, DEFAULT_RULES);
    n.sync(Resolve::Auto).unwrap();
    assert!(!n.status().first_sync);
    let base = n
        .dir
        .join("state")
        .join(".git")
        .join("pathwarden-settings-base.json");
    assert!(base.is_file());
    std::fs::write(&base, "{ not json").unwrap();
    w.edit(|d| d.set_rules(&rules_with(40), &stamp("ned", "W")).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let s = n.status();
    assert!(!s.first_sync, "a damaged base is not a first sync");
    assert_eq!(section(&s, "rules"), Changed::Both);
    let o = n.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Rule settings"], "{:?}", o.done);
    assert!(o.done.taken.is_empty() && o.done.backups.is_empty());
    assert_eq!(n.config().rules.stale_days, 30, "left as it is");
    // Still a choice on the next pull, from the base written meanwhile.
    assert!(n.sync(Resolve::Auto).unwrap().conflict());
    let o = n.sync(Resolve::UseRepo(vec![])).unwrap();
    assert_eq!(o.done.applied, ["Rule settings"], "{:?}", o.done);
    assert_eq!(n.config().rules.stale_days, 40);
    assert_eq!(n.status().state, Changed::InStep);
    let _ = std::fs::remove_dir_all(&root);
}

/// `config sync --keep-local` with no section on a first sync keeps this
/// computer's versions and shares them; on a computer that only reads it
/// is refused.
#[test]
fn keep_local_on_a_first_sync_keeps_this_computers() {
    if !have_git() {
        return;
    }
    let root = scratch("keep-first");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| {
        d.set_rules(&rules_with(30), &stamp("ned", "W")).unwrap();
        d.upsert_zone(None, None, &zone("Theirs")).unwrap();
    });
    w.sync(Resolve::Auto).unwrap();
    let n = Machine::new(&root, "n", &remote, true, DEFAULT_RULES);
    let before = n.text();
    let o = n.sync(Resolve::KeepLocal(vec![])).unwrap();
    assert_eq!(o.done.pushed, ["Rule settings"], "{:?}", o.done);
    // What it had nothing of still comes from the history.
    assert_eq!(o.done.applied, ["Zones"], "{:?}", o.done);
    assert!(o.done.first.is_empty() && o.done.backups.is_empty());
    assert_eq!(n.config().rules.stale_days, 90);
    assert!(n.text().contains("stale_days = 90"), "{before}");
    assert_eq!(n.status().state, Changed::InStep);
    w.sync(Resolve::Auto).unwrap();
    assert_eq!(w.config().rules.stale_days, 90);
    let r = Machine::new(&root, "r", &remote, false, DEFAULT_RULES);
    let e = r.sync(Resolve::KeepLocal(vec![])).unwrap_err().to_string();
    assert!(e.contains("doesn't push"), "{e}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The first sync's notice survives a later pull that applies more, until
/// the app shows it.
#[test]
fn the_first_sync_notice_waits_until_shown() {
    if !have_git() {
        return;
    }
    let root = scratch("notice");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| d.set_rules(&rules_with(30), &stamp("ned", "W")).unwrap());
    w.sync(Resolve::Auto).unwrap();
    let n = Machine::new(&root, "n", &remote, true, DEFAULT_RULES);
    let o = n.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.first, ["Rule settings"], "{:?}", o.done);
    w.edit(|d| accept(d, "PW-011", "r", &stamp("ned", "W")));
    w.sync(Resolve::Auto).unwrap();
    let o = n.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.applied, ["Accepted risks"], "{:?}", o.done);
    assert!(o.done.taken.is_empty(), "an update: {:?}", o.done);
    let a = settings_sync::unseen_applied(&n.store(), true).unwrap();
    assert_eq!(a.first.as_deref(), Some(&["Rule settings".to_string()][..]));
    assert_eq!(a.backups.len(), 1, "{a:?}");
    assert!(
        a.backups[0].starts_with("pathwarden.toml.before-connect-"),
        "{a:?}"
    );
    assert_eq!(a.sections, ["Rule settings", "Accepted risks"]);
    // Shown: the next update's record says only what it applied.
    w.edit(|d| d.set_tier_zero(&["T".into()]).unwrap());
    w.sync(Resolve::Auto).unwrap();
    n.sync(Resolve::Auto).unwrap();
    let a = settings_sync::unseen_applied(&n.store(), false).unwrap();
    assert!(a.first.is_none() && a.backups.is_empty(), "{a:?}");
    assert_eq!(a.sections, ["Tier Zero additions"]);
    let _ = std::fs::remove_dir_all(&root);
}

/// Writes machine `m`'s `pathwarden.toml` whole: `top` (top-level keys),
/// its [state], then `tables`.
fn write_whole(m: &Machine, remote: &Path, push: bool, top: &str, tables: &str) {
    m.write(&format!(
        "# hand-written\n{top}\n[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"state\"\nkeep = \"full\"\n{}\n{tables}",
        remote.to_string_lossy().replace('\\', "/"),
        if push { "" } else { "push = false\n" },
    ));
}

fn pack(name: &str, color: &str) -> String {
    PACK.replace("acme", name).replace("#abc", color)
}

fn lower_sorted(v: &[String]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|s| s.to_lowercase()).collect();
    v.sort();
    v
}

fn risk(rule: &str, reason: &str) -> String {
    format!("[[suppress]]\nrule = \"{rule}\"\nreason = \"{reason}\"\n\n")
}

fn zone_t(name: &str, groups: &str) -> String {
    format!("[[zone]]\nname = \"{name}\"\ngroups = [{groups}]\n\n")
}

/// The tables of a test's `pathwarden.toml`.
fn tables(
    stale: u32,
    pwd: u32,
    disabled: &str,
    risks: &str,
    zones: &str,
    planes: &str,
    packs: &[&str],
) -> String {
    let mut t = format!(
        "[rules]\nstale_days = {stale} # stale\npassword_age_days = {pwd}\ndisabled = [{disabled}]\n\n{risks}\n{zones}\n[management_planes]\nnot_tier_zero = [{planes}]\n"
    );
    for p in packs {
        t.push_str(&format!("\n[[mapping]]\npath = \"packs/{p}.toml\"\n"));
    }
    t
}

/// Every section merges entry by entry: additions on both sides are both
/// kept, a removal on one side goes, and edits to different entries both
/// apply, without asking. The merged result is pushed, a third computer
/// gets it, comments in pathwarden.toml stay, and the repository's file
/// stays one an older release reads.
#[test]
fn every_section_merges_entry_by_entry() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-all");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    let b = Machine::new(&root, "b", &remote, true, "");
    for m in [&a, &b] {
        std::fs::create_dir_all(m.dir.join("packs")).unwrap();
    }
    std::fs::write(a.dir.join("packs/a.toml"), pack("pa", "#aaa")).unwrap();
    std::fs::write(a.dir.join("packs/b.toml"), pack("pb", "#bbb")).unwrap();
    let folders = |list: &[&str]| -> String {
        let quoted: Vec<String> = list.iter().map(|f| format!("'\\\\fs01\\{f}'")).collect();
        format!("settings_folders = [{}]", quoted.join(", "))
    };
    write_whole(
        &a,
        &remote,
        true,
        &format!(
            "tier_zero = [\n  \"T1\", # the first\n  \"T2\", # the second\n]\n{}",
            folders(&["t0a", "t0b"])
        ),
        &tables(
            30,
            365,
            "\"PW-002\", \"PW-003\"",
            &(risk("PW-011", "eleven") + &risk("PW-012", "twelve")),
            &(zone_t("Z1", "\"G1@CORP.LOCAL\"") + &zone_t("Z2", "\"G2@CORP.LOCAL\"")),
            "\"M1.CORP.LOCAL\", \"M2.CORP.LOCAL\"",
            &["a", "b"],
        ),
    );
    assert!(!pushed(&a.sync(Resolve::Auto).unwrap()).is_empty());
    b.sync(Resolve::Auto).unwrap();
    assert_eq!(b.status().state, Changed::InStep);

    // A: adds T3, removes T1, adds a folder, changes stale days, turns
    // PW-004 off, accepts PW-013 and drops PW-011, adds Z3, M3 and pack c.
    std::fs::write(a.dir.join("packs/c.toml"), pack("pc", "#ccc")).unwrap();
    write_whole(
        &a,
        &remote,
        true,
        &format!(
            "tier_zero = [\"T2\", \"T3\"]\n{}",
            folders(&["t0a", "t0b", "t0c"])
        ),
        &tables(
            40,
            365,
            "\"PW-002\", \"PW-003\", \"PW-004\"",
            &(risk("PW-012", "twelve") + &risk("PW-013", "thirteen")),
            &(zone_t("Z1", "\"G1@CORP.LOCAL\"")
                + &zone_t("Z2", "\"G2@CORP.LOCAL\"")
                + &zone_t("Z3", "\"G3@CORP.LOCAL\"")),
            "\"M1.CORP.LOCAL\", \"M2.CORP.LOCAL\", \"M3.CORP.LOCAL\"",
            &["a", "b", "c"],
        ),
    );
    // B, offline: adds T4, drops folder a, changes the password age, turns
    // PW-003 on, edits PW-012, edits Z2 and drops Z1, drops M1, edits pack b.
    std::fs::write(b.dir.join("packs/b.toml"), pack("pb", "#b0b")).unwrap();
    write_whole(
        &b,
        &remote,
        true,
        &format!(
            "tier_zero = [\n  \"T1\", # the first\n  \"T2\", # the second\n  \"T4\",\n]\n{}",
            folders(&["t0b"])
        ),
        &tables(
            30,
            400,
            "\"PW-002\"",
            &(risk("PW-011", "eleven") + &risk("PW-012", "twelve, reviewed")),
            &zone_t("Z2", "\"G2@CORP.LOCAL\", \"G9@CORP.LOCAL\""),
            "\"M2.CORP.LOCAL\"",
            &["a", "b"],
        ),
    );
    assert!(!pushed(&a.sync(Resolve::Auto).unwrap()).is_empty());
    let s = b.status();
    for x in &s.sections {
        assert_eq!(x.state, Changed::Merge, "{}", x.key);
    }
    let o = b.sync(Resolve::Auto).unwrap();
    assert!(!o.conflict(), "{:?}", o.done);
    assert!(o.status.clashes.is_empty(), "{:?}", o.status.clashes);
    for m in [
        "T3 added to Tier Zero",
        "T1 removed from Tier Zero",
        "Stale Tier Zero account: 40 days",
        "PW-004 turned off",
        "Zone Z3 added",
        "Accepted risk for every PW-011 finding removed",
    ] {
        assert!(
            o.done.merged.iter().any(|x| x == m),
            "{m}: {:?}",
            o.done.merged
        );
    }
    for m in [
        "T4 added to Tier Zero",
        "PW-003 turned on",
        "Zone Z1 removed",
        "Zone Z2 changed",
    ] {
        assert!(
            o.done.shared.iter().any(|x| x == m),
            "{m}: {:?}",
            o.done.shared
        );
    }
    assert!(!pushed(&o).is_empty());
    let s = o.sentence().unwrap();
    assert!(s.contains("Merged from the shared settings: "), "{s}");
    assert!(
        s.contains("Shared from this computer, in plain text (not encrypted): "),
        "{s}"
    );
    assert_eq!(o.status.state, Changed::InStep);
    // The comments on entries kept stay.
    let text = b.text();
    for c in ["# hand-written", "# the second", "# stale"] {
        assert!(text.contains(c), "{c}: {text}");
    }
    // The repository's file reads as before: the sections, format and keys
    // an older release knows.
    let shared = remote_file(&remote, SETTINGS_FILE);
    let raw: toml::Table = shared.parse().unwrap();
    for k in raw.keys() {
        assert!(
            config_edit::is_shared_key(k) || k == "mapping_files",
            "{k}: {shared}"
        );
    }
    assert!(raw.get("format").is_none_or(|f| f.as_integer() == Some(1)));
    assert_eq!(
        raw["mapping_files"].as_array().unwrap().len(),
        3,
        "{shared}"
    );
    assert!(
        shared.contains("#b0b") && shared.contains("#ccc"),
        "{shared}"
    );

    // A gets B's side; a third computer gets the merged result.
    a.sync(Resolve::Auto).unwrap();
    let c = Machine::new(&root, "c", &remote, true, "");
    c.sync(Resolve::Auto).unwrap();
    for m in [&a, &b, &c] {
        let cfg = m.config();
        assert_eq!(
            lower_sorted(&cfg.tier_zero),
            ["t2", "t3", "t4"],
            "{}",
            m.text()
        );
        assert_eq!(cfg.settings_folders.len(), 2, "{}", m.text());
        assert_eq!(cfg.rules.stale_days, 40);
        assert_eq!(cfg.rules.password_age_days, 400);
        assert_eq!(lower_sorted(&cfg.rules.disabled), ["pw-002", "pw-004"]);
        let risks: Vec<(String, String)> = cfg
            .suppress
            .iter()
            .map(|s| (s.rule.clone().unwrap_or_default(), s.reason.clone()))
            .collect();
        assert_eq!(risks.len(), 2, "{risks:?}");
        assert!(
            risks.contains(&("PW-012".into(), "twelve, reviewed".into())),
            "{risks:?}"
        );
        assert!(risks.iter().any(|r| r.0 == "PW-013"), "{risks:?}");
        let mut zones: Vec<(String, usize)> = cfg
            .zones
            .iter()
            .map(|z| (z.name.clone(), z.groups.len()))
            .collect();
        zones.sort();
        assert_eq!(zones, [("Z2".to_string(), 2), ("Z3".to_string(), 1)]);
        assert_eq!(
            lower_sorted(&cfg.management_planes.not_tier_zero),
            ["m2.corp.local", "m3.corp.local"]
        );
        assert_eq!(cfg.mappings.len(), 3);
        assert!(std::fs::read_to_string(m.dir.join("packs/b.toml"))
            .unwrap()
            .contains("#b0b"));
        assert!(m.dir.join("packs/c.toml").exists());
        assert_eq!(m.status().state, Changed::InStep);
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Only a real clash waits: the same entry edited to different values on
/// both sides, or edited on one and removed on the other. Everything else
/// merges, the clash keeps this computer's value here, and a choice
/// without a section settles every clash.
#[test]
fn only_real_clashes_wait() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-clash");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.edit(|d| {
        accept(d, "PW-011", "eleven", &stamp(r"CORP\a.admin", "A"));
        accept(d, "PW-012", "twelve", &stamp(r"CORP\a.admin", "A"));
        d.upsert_zone(None, None, &zone("Z1")).unwrap();
        d.set_tier_zero(&["T1".into()]).unwrap();
    });
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    let reason = |d: &mut ConfigDoc, i: usize, rule: &str, text: &str| {
        d.upsert_suppression(
            Some(i),
            None,
            Some(rule),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some(rule.into()),
                reason: text.into(),
                expires: None,
            },
            &stamp(r"CORP\b.admin", "B"),
        )
        .unwrap()
    };
    // A edits PW-011, removes Z1, adds T2; B edits PW-011 too, edits Z1,
    // and edits PW-012 alone.
    a.edit(|d| {
        reason(d, 0, "PW-011", "eleven, by A");
        d.remove_zone(0, "Z1").unwrap();
        d.set_tier_zero(&["T1".into(), "T2".into()]).unwrap();
    });
    a.sync(Resolve::Auto).unwrap();
    b.edit(|d| {
        reason(d, 0, "PW-011", "eleven, by B");
        reason(d, 1, "PW-012", "twelve, by B");
        let mut z = zone("Z1");
        z.groups.push("MORE@CORP.LOCAL".into());
        d.upsert_zone(Some(0), Some("Z1"), &z).unwrap();
    });
    let o = b.sync(Resolve::Auto).unwrap();
    let ids: Vec<&str> = o.status.clashes.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        ["suppress.pw-011", "zone.z1"],
        "{:?}",
        o.status.clashes
    );
    assert_eq!(o.done.conflict, ["Accepted risks", "Zones"], "{:?}", o.done);
    let z1 = &o.status.clashes[1];
    assert_eq!(
        (z1.here.as_str(), z1.shared.as_str()),
        ("Z1: 2 members, groups and OUs", "removed")
    );
    assert_eq!(
        settings_sync::clash_words(&o.status.clashes),
        "Accepted risk for every PW-011 finding and 1 more have two values."
    );
    // Everything else merged: B has T2, its PW-012 went to the repository.
    assert_eq!(b.config().tier_zero, ["T1", "T2"]);
    let cfg = b.config();
    assert_eq!(
        cfg.suppress[0].reason, "eleven, by B",
        "this computer's, until chosen"
    );
    assert_eq!(cfg.zones.len(), 1);
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(
        shared.contains("twelve, by B") && shared.contains("eleven, by A"),
        "{shared}"
    );
    assert!(
        !shared.contains("eleven, by B") && !shared.contains("[[zone]]"),
        "{shared}"
    );
    // The same clashes on the next pull, with the same key for a dismissal.
    let key = o.status.differs_key.clone().unwrap();
    let o = b.sync(Resolve::Auto).unwrap();
    assert_eq!(o.status.differs_key.as_deref(), Some(key.as_str()));
    assert!(
        o.done.merged.is_empty() && o.done.summary.is_none(),
        "{:?}",
        o.done
    );
    // A has nothing to choose: the repository still holds its values, and
    // B's PW-012 is a shared update for it.
    let s = a.status();
    assert!(s.clashes.is_empty(), "{:?}", s.clashes);
    assert_eq!(section(&s, "suppress"), Changed::Repository);
    assert_eq!(a.config().suppress[0].reason, "eleven, by A");
    // B keeps its values for every clash at once.
    let o = b.sync(Resolve::KeepLocal(vec![])).unwrap();
    assert_eq!(o.done.settled.len(), 2, "{:?}", o.done);
    assert!(o.status.clashes.is_empty());
    a.sync(Resolve::Auto).unwrap();
    let cfg = a.config();
    assert_eq!(cfg.suppress[0].reason, "eleven, by B");
    assert_eq!(cfg.zones.len(), 1);
    assert_eq!(cfg.zones[0].groups.len(), 2);
    assert_eq!(a.status().state, Changed::InStep);
    let _ = std::fs::remove_dir_all(&root);
}

/// A computer that only reads merges too: the repository's entries arrive,
/// its own stay here unpushed, and a clash keeps its value until it takes
/// the shared one.
#[test]
fn a_reader_merges_too() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-reader");
    let remote = bare(&root);
    let w = Machine::new(&root, "w", &remote, true, "");
    w.edit(|d| {
        d.set_tier_zero(&["T1".into()]).unwrap();
        d.set_rules(&rules_with(30), &stamp(r"CORP\a.admin", "W"))
            .unwrap();
    });
    w.sync(Resolve::Auto).unwrap();
    let r = Machine::new(&root, "r", &remote, false, "");
    r.sync(Resolve::Auto).unwrap();
    r.edit(|d| {
        d.set_tier_zero(&["T1".into(), "R1".into()]).unwrap();
        d.set_rules(&rules_with(33), &stamp(r"CORP\b.admin", "R"))
            .unwrap();
    });
    w.edit(|d| {
        d.set_tier_zero(&["T1".into(), "W1".into()]).unwrap();
        d.set_rules(&rules_with(44), &stamp(r"CORP\a.admin", "W"))
            .unwrap();
    });
    w.sync(Resolve::Auto).unwrap();
    let head = git(&remote, &["rev-parse", "main"]);
    let o = r.sync(Resolve::Auto).unwrap();
    assert_eq!(o.done.merged, ["W1 added to Tier Zero"], "{:?}", o.done);
    assert_eq!(r.config().tier_zero, ["T1", "R1", "W1"]);
    assert_eq!(
        r.config().rules.stale_days,
        33,
        "this computer's, until chosen"
    );
    assert_eq!(o.status.clashes.len(), 1);
    assert_eq!(o.status.clashes[0].id, "rules.stale_days");
    assert_eq!(
        git(&remote, &["rev-parse", "main"]),
        head,
        "a reader pushes nothing"
    );
    let e = r.sync(Resolve::KeepLocal(vec![])).unwrap_err();
    assert!(e.to_string().contains("doesn't push"), "{e}");
    // Taking the shared value for that setting keeps R1 here.
    let o = r
        .sync(Resolve::UseRepo(vec!["rules.stale_days".into()]))
        .unwrap();
    assert!(o.status.clashes.is_empty(), "{:?}", o.status.clashes);
    assert_eq!(r.config().rules.stale_days, 44);
    assert_eq!(r.config().tier_zero, ["T1", "R1", "W1"]);
    assert_eq!(section(&r.status(), "tier_zero"), Changed::Here);
    assert_eq!(section(&r.status(), "rules"), Changed::InStep);
    let _ = std::fs::remove_dir_all(&root);
}

fn place_of<'a>(m: &Machine, store: &'a Store, config_path: &'a Path) -> Place<'a> {
    Place {
        store,
        config_path,
        pushes: m.config().state.pushes(),
        env_name: None,
    }
}

/// An entry the merge brought is marked until it is edited here.
#[test]
fn a_merged_entry_is_marked_until_edited_here() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-mark");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.edit(|d| d.set_tier_zero(&["T1".into()]).unwrap());
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    a.edit(|d| accept(d, "PW-013", "thirteen", &stamp(r"CORP\a.admin", "A")));
    a.sync(Resolve::Auto).unwrap();
    b.edit(|d| accept(d, "PW-014", "fourteen", &stamp(r"CORP\b.admin", "B")));
    let o = b.sync(Resolve::Auto).unwrap();
    assert_eq!(
        o.done.merged,
        ["Accepted risk for every PW-013 finding added"],
        "{:?}",
        o.done
    );
    let store = b.store();
    let path = b.config_path();
    let m = settings_sync::merged_here(&store).unwrap();
    let marks = settings_sync::merged_marks(&place_of(&b, &store, &path), &m);
    assert_eq!(marks, [("suppress".to_string(), "pw-013".to_string())]);
    b.edit(|d| {
        d.upsert_suppression(
            Some(1),
            None,
            Some("PW-013"),
            &SuppressionEdit {
                fingerprint: None,
                rule: Some("PW-013".into()),
                reason: "thirteen, reviewed".into(),
                expires: None,
            },
            &stamp(r"CORP\b.admin", "B"),
        )
        .unwrap()
    });
    assert!(settings_sync::merged_marks(&place_of(&b, &store, &path), &m).is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

/// What came from the repository is recorded as the repository's even when
/// the push of this computer's entries races another: a third computer's
/// revert that lands meanwhile is taken, never undone.
#[test]
fn what_came_stays_the_repositorys_when_the_push_races() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-race");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.edit(|d| {
        d.set_rules(&rules_with(30), &stamp(r"CORP\a.admin", "A"))
            .unwrap()
    });
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    let c = Machine::new(&root, "c", &remote, true, "");
    c.sync(Resolve::Auto).unwrap();
    // A shares 60 stale days.
    a.edit(|d| {
        d.set_rules(&rules_with(60), &stamp(r"CORP\a.admin", "A"))
            .unwrap()
    });
    a.sync(Resolve::Auto).unwrap();
    // B pulls (60), then edits its password age offline.
    let store = b.store();
    let lock = store.lock().unwrap();
    store.pull().unwrap();
    b.edit(|d| {
        let mut r = rules_with(30);
        r.password_age_days = 400;
        d.set_rules(&r, &stamp(r"CORP\b.admin", "B")).unwrap()
    });
    // Meanwhile C takes 60 and reverts it to 30.
    c.sync(Resolve::Auto).unwrap();
    c.edit(|d| {
        d.set_rules(&rules_with(30), &stamp(r"CORP\c.admin", "C"))
            .unwrap()
    });
    c.sync(Resolve::Auto).unwrap();
    // B merges what it pulled (60 here) and pushes its password age: the
    // push meets C's revert.
    let path = b.config_path();
    let o = settings_sync::sync(&place_of(&b, &store, &path), Resolve::Auto).unwrap();
    assert_eq!(o.done.conflict, ["Rule settings"], "raced: {:?}", o.done);
    assert_eq!(b.config().rules.stale_days, 60);
    drop(lock);
    // The next sync takes C's 30, and shares the password age.
    let o = b.sync(Resolve::Auto).unwrap();
    assert!(o.status.clashes.is_empty(), "{:?}", o.status.clashes);
    assert_eq!(b.config().rules.stale_days, 30);
    assert_eq!(b.config().rules.password_age_days, 400);
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(
        shared.contains("stale_days = 30") && shared.contains("password_age_days = 400"),
        "{shared}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A merge whose push is kept unpushed records only what came: when the
/// kept commit is dropped (the repository moved on), this computer's entry
/// is still its own, kept and pushed on the next sync.
#[test]
fn a_kept_push_never_records_this_computers_entries() {
    if !have_git() {
        return;
    }
    let root = scratch("merge-kept");
    let remote = bare(&root);
    let a = Machine::new(&root, "a", &remote, true, "");
    a.edit(|d| d.set_tier_zero(&["T1".into()]).unwrap());
    a.sync(Resolve::Auto).unwrap();
    let b = Machine::new(&root, "b", &remote, true, "");
    b.sync(Resolve::Auto).unwrap();
    a.edit(|d| d.set_tier_zero(&["T1".into(), "A1".into()]).unwrap());
    a.sync(Resolve::Auto).unwrap();
    b.edit(|d| d.set_tier_zero(&["T1".into(), "X".into()]).unwrap());
    // B's push is refused: kept here.
    let hook = remote.join("hooks").join("pre-receive");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let o = b.sync(Resolve::Auto).unwrap();
    assert!(o.done.kept.is_some(), "{:?}", o.done);
    assert_eq!(o.done.merged, ["A1 added to Tier Zero"], "{:?}", o.done);
    std::fs::remove_file(&hook).unwrap();
    // The repository moves on: B's kept commit is dropped on its next pull.
    a.edit(|d| {
        d.set_tier_zero(&["T1".into(), "A1".into(), "A2".into()])
            .unwrap()
    });
    a.sync(Resolve::Auto).unwrap();
    b.sync(Resolve::Auto).unwrap();
    assert_eq!(lower_sorted(&b.config().tier_zero), ["a1", "a2", "t1", "x"]);
    let shared = remote_file(&remote, SETTINGS_FILE);
    assert!(shared.contains("\"X\""), "X kept and pushed: {shared}");
    let _ = std::fs::remove_dir_all(&root);
}
