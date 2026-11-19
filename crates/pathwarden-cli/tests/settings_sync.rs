//! `pathwarden config sync` and the settings commands on a history that
//! shares settings: two `pathwarden.toml` files on one
//! local bare repository stand in for two machines.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

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

/// One machine: its folder, its config and who runs Pathwarden there.
struct Machine {
    dir: PathBuf,
    user: &'static str,
    computer: &'static str,
}

impl Machine {
    fn new(
        root: &Path,
        name: &str,
        remote: &Path,
        user: &'static str,
        computer: &'static str,
    ) -> Self {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
        std::fs::write(
            dir.join("pathwarden.toml"),
            format!(
                "[state]\nbackend = \"git\"\nremote = \"{}\"\npath = \"{}\"\nkeep = \"full\"\n",
                slash(remote),
                slash(&dir.join("state"))
            ),
        )
        .unwrap();
        Machine {
            dir,
            user,
            computer,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut all = vec!["config"];
        all.extend(args);
        self.pw(&all)
    }

    /// `pathwarden ARGS -c <its pathwarden.toml>`.
    fn pw(&self, args: &[&str]) -> Output {
        let config = self.dir.join("pathwarden.toml");
        let (domain, name) = self.user.split_once('\\').unwrap_or(("", self.user));
        Command::new(bin())
            .current_dir(&self.dir)
            .env("NO_COLOR", "1")
            .env("USERDOMAIN", domain)
            .env("USERNAME", name)
            .env("USER", self.user)
            .env("COMPUTERNAME", self.computer)
            .env("HOSTNAME", self.computer)
            .args(args)
            .arg("-c")
            .arg(&config)
            .output()
            .unwrap()
    }
}

/// A pack from the repository is trusted only at the text reviewed
/// (`--digest`, as `mappings show` gives it), and untrusting it also takes
/// its name out of `[opengraph] trust`, so trust by name can't come back.
#[test]
fn packs_from_the_repository_are_trusted_at_the_reviewed_text() {
    if !have_git() {
        return;
    }
    let root = std::env::temp_dir().join(format!("pathwarden-cli-packs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let remote = root.join("state.git");
    assert!(git_command()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let w = Machine::new(&root, "w", &remote, r"NORTH\eddard.stark", "PW-SCHED01");
    std::fs::create_dir_all(w.dir.join("packs")).unwrap();
    std::fs::write(
        w.dir.join("packs/acme.toml"),
        "[pack]\nname = \"acme\"\nversion = 1\nsource_kinds = [\"AcmeHound\"]\nkind_prefix = \"AC_\"\ntrusted = true\n\n[[node]]\nkind = \"AC_Thing\"\nicon = \"clock\"\ncolor = \"#abc\"\n",
    )
    .unwrap();
    let mut text = std::fs::read_to_string(w.dir.join("pathwarden.toml")).unwrap();
    text.push_str("\n[[mapping]]\npath = \"packs/acme.toml\"\n");
    std::fs::write(w.dir.join("pathwarden.toml"), text).unwrap();
    ok(&w.run(&["sync"]));
    let r = Machine::new(&root, "r", &remote, r"NORTH\arya.stark", "SECOPS-WS02");
    let mut text = std::fs::read_to_string(r.dir.join("pathwarden.toml")).unwrap();
    text.push_str("\n[opengraph]\ntrust = [\"acme\"]\n");
    std::fs::write(r.dir.join("pathwarden.toml"), text).unwrap();
    ok(&r.run(&["sync"]));
    let show: serde_json::Value =
        serde_json::from_str(&ok(&r.pw(&["mappings", "show", "acme", "--json"])).0).unwrap();
    assert_eq!(show["trusted"], false, "{show}");
    let digest = show["from_repository"]["digest"]
        .as_str()
        .unwrap()
        .to_string();
    let out = r.pw(&["mappings", "trust", "acme", "--reviewed"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--digest"));
    let out = r.pw(&[
        "mappings",
        "trust",
        "acme",
        "--reviewed",
        "--digest",
        "0000",
    ]);
    assert!(!out.status.success());
    ok(&r.pw(&[
        "mappings",
        "trust",
        "acme",
        "--reviewed",
        "--digest",
        &digest,
    ]));
    let show: serde_json::Value =
        serde_json::from_str(&ok(&r.pw(&["mappings", "show", "acme", "--json"])).0).unwrap();
    assert_eq!(show["trusted"], true, "{show}");
    // Untrusted: the old name trust goes too, and losing the record trusts
    // nothing.
    ok(&r.pw(&["mappings", "untrust", "acme"]));
    let text = std::fs::read_to_string(r.dir.join("pathwarden.toml")).unwrap();
    assert!(!text.contains("\"acme\""), "{text}");
    std::fs::remove_file(r.dir.join(pathwarden_core::pack_origin::FILE)).unwrap();
    let show: serde_json::Value =
        serde_json::from_str(&ok(&r.pw(&["mappings", "show", "acme", "--json"])).0).unwrap();
    assert_eq!(show["trusted"], false, "{show}");
    let _ = std::fs::remove_dir_all(&root);
}

fn ok(out: &Output) -> (String, String) {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn status(m: &Machine) -> serde_json::Value {
    serde_json::from_str(&ok(&m.run(&["sync", "--status", "--json"])).0).unwrap()
}

fn section<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == key)
        .unwrap()["state"]
        .as_str()
        .unwrap()
}

#[test]
fn settings_go_through_the_repository_from_the_terminal() {
    if !have_git() {
        return;
    }
    let root = std::env::temp_dir().join(format!("pathwarden-cli-settings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let remote = root.join("state.git");
    assert!(git_command()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let sched = Machine::new(&root, "sched", &remote, r"NORTH\eddard.stark", "PW-SCHED01");
    let ws = Machine::new(&root, "ws", &remote, r"NORTH\arya.stark", "SECOPS-WS02");

    // A writer's saves are pushed at once.
    let (_, e) = ok(&sched.run(&["tier-zero", "add", "SVC_SYNC@NORTH.LOCAL", "--force"]));
    assert!(
        e.contains("Shared with this history, in plain text (not encrypted)."),
        "{e}"
    );
    let (_, e) = ok(&sched.run(&[
        "risk",
        "accept",
        "--rule",
        "PW-011",
        "--reason",
        "Break-glass, reviewed quarterly",
    ]));
    assert!(
        e.contains(
            "Shared with this history, in plain text (not encrypted): 1 accepted risk added."
        ),
        "{e}"
    );

    // The other machine sees them as shared updates, and takes them.
    let v = status(&ws);
    assert_eq!(v["active"], true);
    assert_eq!(v["state"], "repository");
    assert_eq!(section(&v, "suppress"), "repository");
    assert_eq!(section(&v, "rules"), "in_step");
    assert_eq!(v["written_by_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["last_change"]["by"], r"NORTH\eddard.stark");
    let (text, _) = ok(&ws.run(&["sync", "--status"]));
    assert!(
        text.contains("Accepted risks") && text.contains("shared update"),
        "{text}"
    );
    assert!(text.contains("in plain text (not encrypted)"), "{text}");
    assert_eq!(v["encrypted"], false);
    // Its first sync: the history's settings are taken. It had none of
    // its own, so nothing is saved beside pathwarden.toml.
    let (text, _) = ok(&ws.run(&["sync"]));
    assert!(
        text.contains("Tier Zero additions and accepted risks were taken from the run history."),
        "{text}"
    );
    assert!(!text.contains("saved in"), "{text}");
    let copies: Vec<_> = std::fs::read_dir(&ws.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("pathwarden.toml.before-connect-")
        })
        .collect();
    assert!(copies.is_empty(), "{copies:?}");
    let (text, _) = ok(&ws.run(&["risk", "list"]));
    assert!(
        text.contains(r"accepted by NORTH\eddard.stark on PW-SCHED01"),
        "{text}"
    );
    assert_eq!(status(&ws)["state"], "in_step");

    // Both add Tier Zero: both are kept, without asking.
    ok(&ws.run(&["tier-zero", "add", "SVC_BACKUP@NORTH.LOCAL", "--force"]));
    let (_, e) = ok(&sched.run(&["tier-zero", "add", "SVC_OTHER@NORTH.LOCAL", "--force"]));
    assert!(
        e.contains("Merged from the shared settings: SVC_BACKUP@NORTH.LOCAL added to Tier Zero.")
            && e.contains("Shared from this computer"),
        "{e}"
    );
    // Both set the stale days: that one setting has two values.
    ok(&ws.run(&["rules", "set", "--stale-days", "60"]));
    let (_, e) = ok(&sched.run(&["rules", "set", "--stale-days", "30"]));
    assert!(e.contains("Stale Tier Zero account has two values."), "{e}");
    let v = status(&sched);
    assert_eq!(v["state"], "both");
    assert_eq!(section(&v, "rules"), "both");
    assert_eq!(section(&v, "tier_zero"), "in_step");
    assert_eq!(v["clashes"][0]["id"], "rules.stale_days", "{v}");
    let (text, _) = ok(&sched.run(&["sync", "--status"]));
    assert!(
        text.contains("1 setting has two values: stale_days (here 30, shared 60)"),
        "{text}"
    );
    let out = sched.run(&["sync"]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    for line in [
        "1 setting has two values:",
        "Stale Tier Zero account (rules.stale_days)",
        "This computer   30 days",
        "Shared          60 days",
        r"NORTH\arya.stark on SECOPS-WS02",
        "Until you choose, runs here use 30 days. Everything else is up to date.",
        "pathwarden config sync --use-repo --section rules.stale_days   use 60 days here",
        "pathwarden config sync --keep-local --section rules.stale_days   keep 30 days and share it",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    // Keep the scheduler's for every setting with two values: the
    // workstation follows.
    let (text, _) = ok(&sched.run(&["sync", "--keep-local"]));
    assert!(
        text.contains(
            "Stale Tier Zero account: kept 30 days and pushed it to the shared settings."
        ) && text.contains("Everything is up to date."),
        "{text}"
    );
    let (text, _) = ok(&ws.run(&["sync"]));
    assert!(text.contains("applied here"), "{text}");
    let (text, _) = ok(&ws.run(&["tier-zero", "list"]));
    assert!(
        text.contains("SVC_BACKUP") && text.contains("SVC_OTHER"),
        "{text}"
    );
    let (text, _) = ok(&ws.run(&["rules", "show"]));
    assert!(text.contains("30"), "{text}");
    // Up to date: nothing to do.
    let (text, _) = ok(&sched.run(&["sync"]));
    assert!(text.contains("up to date"), "{text}");

    // A computer told the history is encrypted, which it isn't: refused,
    // and said so, never "up to date"; keeping its settings isn't offered.
    let refused = Machine::new(&root, "refused", &remote, r"NORTH\jon.snow", "SECOPS-WS03");
    let mut text = std::fs::read_to_string(refused.dir.join("pathwarden.toml")).unwrap();
    text.push_str("encrypted = true\n");
    std::fs::write(refused.dir.join("pathwarden.toml"), text).unwrap();
    let (text, _) = ok(&refused.run(&["sync", "--status"]));
    assert!(
        text.contains("can't be read here") && text.contains("encrypted"),
        "{text}"
    );
    assert!(
        !text.contains("up to date")
            && !text.contains("Up to date")
            && !text.contains("--keep-local"),
        "{text}"
    );
    let v = status(&refused);
    assert_eq!(v["state"], "unreadable", "{v}");
    assert_eq!(section(&v, "tier_zero"), "unreadable");
    let out = refused.run(&["sync"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("encrypted"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sync_says_when_settings_are_not_shared() {
    let dir = std::env::temp_dir().join(format!("pathwarden-cli-nosync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pathwarden.toml");
    std::fs::write(&config, "[state]\nbackend = \"local\"\n").unwrap();
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["config", "sync", "--status", "--json", "-c"])
        .arg(&config)
        .output()
        .unwrap();
    let (text, _) = ok(&out);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["active"], false);
    assert!(v["why"].as_str().unwrap().contains("git"), "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Commits `change` to file `rel` of the bare repository `remote` from a
/// clone of its own, as a newer Pathwarden elsewhere would.
fn commit_to(remote: &Path, scratch: &Path, rel: &str, change: impl Fn(String) -> String) {
    let clone = scratch.join("elsewhere");
    let _ = std::fs::remove_dir_all(&clone);
    let git = |dir: &Path, args: &[&str]| {
        let out = git_command()
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(
        scratch,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            &remote.to_string_lossy(),
            "elsewhere",
        ],
    );
    let path = clone.join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    std::fs::write(&path, change(text)).unwrap();
    git(&clone, &["add", "-A"]);
    git(&clone, &["commit", "-q", "-m", "a newer Pathwarden"]);
    git(&clone, &["push", "-q", "origin", "HEAD:main"]);
}

/// The file `rel` at the tip of the bare repository `remote`.
fn at_tip(remote: &Path, rel: &str) -> Vec<u8> {
    let out = git_command()
        .arg("--git-dir")
        .arg(remote)
        .args(["show", &format!("main:{rel}")])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Shared settings a newer Pathwarden saved (docs/dev/formats.md): never
/// applied, never replaced, not even with `--keep-local`, and said in one
/// sentence of their own. A newer `environment.json` is never written
/// over either.
#[test]
fn newer_shared_settings_are_never_replaced() {
    if !have_git() {
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "pathwarden-cli-newer-settings-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let remote = root.join("state.git");
    assert!(git_command()
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .status()
        .unwrap()
        .success());
    let a = Machine::new(&root, "a", &remote, r"NORTH\eddard.stark", "PW-SCHED01");
    ok(&a.run(&["tier-zero", "add", "SVC_SYNC@NORTH.LOCAL", "--force"]));

    // environment.json first: a save that would push is refused.
    commit_to(&remote, &root, "settings/environment.json", |_| {
        "{\"format\": 2, \"name\": \"Lab\"}\n".into()
    });
    let env_before = at_tip(&remote, "settings/environment.json");
    let settings_before = at_tip(&remote, "settings/pathwarden.toml");
    let out = a.run(&["tier-zero", "add", "SVC_OTHER@NORTH.LOCAL", "--force"]);
    let text = said(&out);
    assert!(
        text.contains("settings/environment.json was saved by a newer Pathwarden"),
        "{text}"
    );
    assert_eq!(at_tip(&remote, "settings/environment.json"), env_before);
    assert_eq!(at_tip(&remote, "settings/pathwarden.toml"), settings_before);

    // Then the settings file itself.
    commit_to(&remote, &root, "settings/pathwarden.toml", |t| {
        format!("format = 2\n{t}")
    });
    let before = at_tip(&remote, "settings/pathwarden.toml");
    let b = Machine::new(&root, "b", &remote, r"NORTH\arya.stark", "SECOPS-WS02");
    let words = pathwarden_core::settings_sync::NEWER_SETTINGS_WORDS;
    let (text, _) = ok(&b.run(&["sync", "--status"]));
    assert!(text.contains(words), "{text}");
    assert!(!text.contains("--keep-local"), "{text}");
    assert!(!text.contains("can't be read here: The"), "{text}");
    let v = status(&b);
    assert_eq!(v["damaged"], false, "{v}");
    assert_eq!(v["newer_format"], true, "{v}");
    for args in [
        &["sync", "--keep-local"][..],
        &["sync", "--keep-local", "--section", "tier_zero"][..],
    ] {
        let out = b.run(args);
        assert!(!out.status.success(), "{args:?}");
        let text = said(&out);
        assert!(text.contains(words), "{args:?}: {text}");
        assert!(!text.contains("--keep-local` replaces"), "{args:?}: {text}");
        assert_eq!(
            at_tip(&remote, "settings/pathwarden.toml"),
            before,
            "{args:?}"
        );
    }
    // A save here doesn't replace it either.
    let _ = b.run(&["tier-zero", "add", "SVC_B@NORTH.LOCAL", "--force"]);
    assert_eq!(at_tip(&remote, "settings/pathwarden.toml"), before);
    let _ = std::fs::remove_dir_all(&root);
}
