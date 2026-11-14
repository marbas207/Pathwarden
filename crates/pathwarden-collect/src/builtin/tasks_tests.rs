//! The scheduled tasks walk against a fake `C$`.

use super::*;
use std::collections::BTreeMap;

use pathwarden_core::storedcreds::{NetbiosName, SCHEMA};

/// A computer's `C$`: folders and files by path (lower case), recording
/// every call.
#[derive(Default)]
struct FakeShare {
    dirs: BTreeMap<String, Vec<DirEntry>>,
    files: BTreeMap<String, Vec<u8>>,
    /// Folders whose listing fails.
    deny: Vec<String>,
    listed: Vec<String>,
    read: Vec<String>,
    /// What Task Scheduler registered: every entry added with
    /// [`FakeShare::entry`], not those [`FakeShare::plant`] adds.
    registered: Registered,
}

impl FakeShare {
    fn dir(&mut self, path: &str) {
        self.dirs.entry(path.to_ascii_lowercase()).or_default();
    }

    /// Adds a registered entry to `parent`, creating it.
    fn entry(&mut self, parent: &str, name: &str, is_dir: bool, size: u64) {
        let rel = parent
            .get(TASKS_DIR.len()..)
            .unwrap_or_default()
            .trim_start_matches('\\');
        let rel = if rel.is_empty() {
            name.to_string()
        } else {
            format!(r"{rel}\{name}")
        };
        // A folder, or a task whose file is checked against a hash
        // (`task` sets the real one).
        let expect = if is_dir {
            Expect::Folder
        } else {
            Expect::Hash(vec![0; 32])
        };
        self.registered.insert(&rel, expect);
        self.plant(parent, name, is_dir, size);
    }

    /// Adds an entry to `parent` that Task Scheduler doesn't know (any
    /// user can write files into the tasks folder).
    fn plant(&mut self, parent: &str, name: &str, is_dir: bool, size: u64) {
        self.dirs
            .entry(parent.to_ascii_lowercase())
            .or_default()
            .push(DirEntry {
                name: name.into(),
                is_dir,
                size,
                attributes: if is_dir { 0x10 } else { 0x20 },
            });
    }

    /// A task file at `rel` under the tasks folder (folders created).
    fn task(&mut self, rel: &str, bytes: Vec<u8>) {
        let full = format!(r"{TASKS_DIR}\{rel}");
        let (parent, name) = full.rsplit_once('\\').unwrap();
        let mut at = TASKS_DIR.to_string();
        for part in rel.split('\\').collect::<Vec<_>>().split_last().unwrap().1 {
            let next = format!(r"{at}\{part}");
            if !self.dirs.contains_key(&next.to_ascii_lowercase()) {
                self.entry(&at, part, true, 0);
                self.dir(&next);
            }
            at = next;
        }
        self.entry(parent, name, false, bytes.len() as u64);
        // Registered as written: its registration records its hash.
        self.registered.insert(rel, Expect::Hash(sha(&bytes)));
        self.files.insert(full.to_ascii_lowercase(), bytes);
    }
}

impl Share for FakeShare {
    async fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String> {
        self.listed.push(path.to_string());
        if self.deny.iter().any(|d| d.eq_ignore_ascii_case(path)) {
            return Err("SMB2 status 0xc0000022 for command 5".into());
        }
        let all = self
            .dirs
            .get(&path.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| "SMB2 status 0xc0000034 for command 5".to_string())?;
        let more = all.len() > max;
        Ok((all.into_iter().take(max).collect(), more))
    }
    async fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        self.read.push(path.to_string());
        let b = self
            .files
            .get(&path.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| "SMB2 status 0xc0000034 for command 5".to_string())?;
        let more = b.len() > max;
        Ok((b.into_iter().take(max).collect(), more))
    }
}

/// The SHA-256 Task Scheduler records for a task file (without its BOM).
fn sha(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes)).to_vec()
}

/// [`read_tasks`] over `share`, with what it registered.
async fn walk(share: &mut FakeShare, deadline: Instant) -> (Check, Vec<Stored>) {
    let registered = share.registered.clone();
    read_tasks(share, HOST, deadline, &registered).await
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A task file in UTF-16 with its BOM, as Windows writes them.
fn task_file(user: &str, logon: &str, enabled: bool) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Copies the backups</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>{logon}</LogonType></Principal></Principals>
  <Settings><Enabled>{enabled}</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>robocopy.exe</Command><Arguments>/user:x /p Hunter2!</Arguments></Exec></Actions>
</Task>"#
    );
    let mut b = vec![0xFF, 0xFE];
    b.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    b
}

const HOST: &str = "APP01.NORTH.CONTOSO.LOCAL";

fn later() -> Instant {
    Instant::now() + PER_HOST
}

/// The usual mix: only tasks that store a domain account's password are
/// kept, a disabled one too, in nested folders; only the tasks folder is
/// ever listed or read; no argument reaches the result.
#[test]
fn only_the_tasks_tree_and_only_stored_passwords() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task(
        "Nightly sync",
        task_file(r"NORTH\svc_sync", "Password", true),
    );
    share.task(
        r"Backups\Copy",
        task_file("S-1-5-21-1-2-3-1201", "InteractiveTokenOrPassword", true),
    );
    share.task(
        r"Backups\Old\Archive",
        task_file("svc_old@north.contoso.local", "Password", false),
    );
    share.task(
        r"Microsoft\Windows\Defrag\ScheduledDefrag",
        task_file("S-1-5-18", "ServiceAccount", true),
    );
    share.task("S4U job", task_file(r"NORTH\svc_s4u", "S4U", true));
    share.task(
        "Interactive",
        task_file(r"NORTH\alice", "InteractiveToken", true),
    );
    share.task("Local", task_file(r"APP01\admin", "Password", true));
    share.task("Dot local", task_file(r".\admin", "Password", true));
    share.task("Bare", task_file("admin", "Password", true));
    // Files outside the tasks folder that must never be touched.
    share
        .files
        .insert(r"windows\system32\config\sam".into(), b"secret".to_vec());
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Complete, "{check:?}");
    assert_eq!(check.read, 9);
    let mut got: Vec<(&str, &str, Option<bool>, Option<&str>)> = stored
        .iter()
        .map(|s| {
            assert_eq!(s.via, Via::Task);
            (
                s.name.as_str(),
                s.account.as_str(),
                s.enabled,
                s.logon_type.as_deref(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            (
                r"\Backups\Copy",
                "S-1-5-21-1-2-3-1201",
                Some(true),
                Some("InteractiveTokenOrPassword")
            ),
            (
                r"\Backups\Old\Archive",
                "svc_old@north.contoso.local",
                Some(false),
                Some("Password")
            ),
            (
                r"\Nightly sync",
                r"NORTH\svc_sync",
                Some(true),
                Some("Password")
            ),
        ]
    );
    for p in share.listed.iter().chain(share.read.iter()) {
        assert!(
            p.to_ascii_lowercase()
                .starts_with(&TASKS_DIR.to_ascii_lowercase()),
            "{p}"
        );
    }
    assert!(!share.read.iter().any(|p| p.contains("config")));
    let json = serde_json::to_string(&stored).unwrap();
    assert!(!json.contains("Hunter2"), "{json}");
    assert!(!json.contains("robocopy"), "{json}");
    assert!(!json.contains("Copies the backups"), "{json}");
}

/// The tasks folder denied (a plain user): not collected, access denied.
/// Missing, likewise not collected.
#[test]
fn a_denied_tasks_folder_is_not_collected() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.deny = vec![TASKS_DIR.into()];
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::NotCollected);
    assert_eq!(check.reason.as_deref(), Some("access denied"));
    assert!(stored.is_empty());
    let (check, _) = run(walk(&mut FakeShare::default(), later()));
    assert_eq!(check.status, CheckStatus::NotCollected);
}

/// A hostile computer: a billion-laughs file, a file larger than it says,
/// one that says it is huge, a deep folder chain, bad names, a folder that
/// can't be listed, a file that can't be read. Each leaves the computer
/// partly read, nothing panics, and what could be read still counts.
#[test]
fn hostile_answers_are_bounded_and_partial() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Good", task_file(r"NORTH\svc_sync", "Password", true));
    let laughs = br#"<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><Task><Principals><Principal><UserId>&b;</UserId><LogonType>Password</LogonType></Principal></Principals></Task>"#;
    share.task("Laughs", laughs.to_vec());
    share.task("Not xml", vec![0x4D, 0x5A, 0x90, 0x00]);
    // Says it is small, sends more than the limit.
    share.task(
        "Liar",
        vec![b' '; pathwarden_core::taskxml::MAX_TASK_FILE + 10],
    );
    if let Some(e) = share
        .dirs
        .get_mut(&TASKS_DIR.to_ascii_lowercase())
        .and_then(|d| d.iter_mut().find(|e| e.name == "Liar"))
    {
        e.size = 10;
    }
    // Says it is huge: never read.
    share.entry(TASKS_DIR, "Huge", false, u64::MAX);
    // A folder chain deeper than the limit.
    let mut rel = String::new();
    for i in 0..MAX_DEPTH + 2 {
        rel = if rel.is_empty() {
            format!("d{i}")
        } else {
            format!(r"{rel}\d{i}")
        };
    }
    share.task(
        &format!(r"{rel}\Deep"),
        task_file(r"NORTH\deep", "Password", true),
    );
    // Names that would leave the folder, or carry control characters.
    for bad in ["..", r"..\..\config", "a/b", "x\u{1}y", "c:evil", ""] {
        share.entry(TASKS_DIR, bad, true, 0);
    }
    share.entry(TASKS_DIR, &"n".repeat(300), false, 10);
    // A folder that can't be listed, a file that can't be read.
    share.entry(TASKS_DIR, "Locked", true, 0);
    share.deny = vec![format!(r"{TASKS_DIR}\Locked")];
    share.entry(TASKS_DIR, "Gone", false, 10);
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial, "{check:?}");
    let why = check.reason.clone().unwrap();
    for part in [
        "1 folder deeper than 8 levels not read",
        "1 folder could not be listed",
        "1 task file could not be read",
        "2 task files over the 1024 KiB limit",
        "2 files were not readable as a task",
        "7 names were not usable",
    ] {
        assert!(why.contains(part), "{part} in {why}");
    }
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0].account, r"NORTH\svc_sync");
    assert!(!share.read.iter().any(|p| p.ends_with("Huge")));
    assert!(!share.read.iter().any(|p| p.contains("..")));
    let deepest = share
        .listed
        .iter()
        .map(|p| p.matches('\\').count())
        .max()
        .unwrap();
    assert_eq!(deepest, TASKS_DIR.matches('\\').count() + MAX_DEPTH);
}

/// More files than the limit, a listing longer than the limit, and the
/// time running out each leave the computer partly read.
#[test]
fn limits_are_partial() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    for i in 0..MAX_FILES + 3 {
        share.entry(TASKS_DIR, &format!("t{i}"), false, 10);
        share.files.insert(
            format!(r"{TASKS_DIR}\t{i}").to_ascii_lowercase(),
            Vec::new(),
        );
    }
    let (check, _) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert!(check.reason.unwrap().contains("more than 5000 task files"));
    assert_eq!(share.read.len(), MAX_FILES);

    let mut share = FakeShare::default();
    for i in 0..MAX_LISTED + 1 {
        share.entry(TASKS_DIR, &format!("d{i}"), true, 0);
    }
    let (check, _) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert!(check.reason.unwrap().contains("entries listed"));

    let mut share = FakeShare::default();
    share.task("Good", task_file(r"NORTH\svc_sync", "Password", true));
    let (check, stored) = run(walk(&mut share, Instant::now()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert_eq!(check.reason.as_deref(), Some("ran out of time"));
    assert!(stored.is_empty());
}

/// An empty tasks folder is read in full.
#[test]
fn an_empty_folder_is_complete() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Complete);
    assert!(stored.is_empty());
}

#[test]
fn task_accounts() {
    assert!(is_task_account(r"NORTH\svc", HOST));
    assert!(is_task_account("svc@north.local", HOST));
    assert!(is_task_account("S-1-5-21-1-2-3-1201", HOST));
    assert!(!is_task_account("S-1-5-18", HOST));
    assert!(!is_task_account(r"APP01\admin", HOST));
    assert!(!is_task_account(r"NT AUTHORITY\SYSTEM", HOST));
    assert!(!is_task_account("admin", HOST));
}

fn computer(name: &str, sid: &str, active: bool) -> Computer {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut v = serde_json::to_value(Computer::default()).unwrap();
    v["Properties"]["name"] = name.into();
    v["Properties"]["enabled"] = active.into();
    v["Properties"]["is_dc"] = false.into();
    v["Properties"]["pwdlastset"] = (now - 86_400).into();
    v["ObjectIdentifier"] = sid.into();
    serde_json::from_value::<Computer>(v).unwrap()
}

/// Skipped and unreached computers are not collected, with why, and never
/// contacted; inactive ones aren't listed. The step warns.
#[test]
fn skipped_and_unreached_computers_say_why() {
    let mut computers = vec![
        computer("WS1.NORTH.LOCAL", "S-1-5-21-1-2-3-1101", true),
        computer("WS2.NORTH.LOCAL", "S-1-5-21-1-2-3-1102", true),
        computer("OLD.NORTH.LOCAL", "S-1-5-21-1-2-3-1103", false),
    ];
    let skipped: Skipped = [(
        "S-1-5-21-1-2-3-1101".to_string(),
        super::super::hostauth::Skip::Unsigned,
    )]
    .into();
    let k = KerberosSignIn {
        // Never used: no computer here is contacted.
        ccache: "FILE:nowhere".into(),
        kdc: "127.0.0.1:1".into(),
    };
    let (tx, rx) = mpsc::channel();
    let plan = Plan {
        k: &k,
        smb_domain: "north.local",
        user: "collector",
        until: Instant::now() + STEP_BUDGET,
        registry_down: Default::default(),
    };
    let reads = run(collect(plan, &mut computers, &skipped, &tx));
    assert_eq!(reads.len(), 2);
    assert_eq!(
        reads[0].tasks.reason.as_deref(),
        Some("skipped: its replies weren't signed")
    );
    assert_eq!(reads[1].tasks.reason.as_deref(), Some("not reached"));
    let warned: Vec<String> = rx
        .try_iter()
        .filter_map(|m| match m {
            Msg::Warning(w) => Some(w),
            _ => None,
        })
        .collect();
    assert_eq!(warned.len(), 1);
    assert!(warned[0].starts_with("Scheduled tasks weren't read on 2 of 2 computers"));
}

fn sidecar() -> Sidecar {
    Sidecar {
        schema: SCHEMA.into(),
        domain: "north.local".into(),
        netbios: vec![NetbiosName {
            dns: "north.local".into(),
            netbios: "NORTH".into(),
        }],
        ..Sidecar::default()
    }
}

fn read_of(id: &str, status: CheckStatus, stored: Vec<Stored>) -> HostTasks {
    HostTasks {
        id: id.into(),
        name: "WS1.NORTH.LOCAL".into(),
        tasks: Check {
            status,
            ..Check::default()
        },
        stored,
    }
}

/// The switches: services and tasks each on or off. The file says for
/// each what was read, and a computer gets one record whatever was read.
#[test]
fn switch_combinations() {
    let task = Stored {
        via: Via::Task,
        name: r"\Sync".into(),
        account: r"NORTH\svc".into(),
        logon_type: Some("Password".into()),
        ..Stored::default()
    };
    let service = Stored {
        name: "SqlAgent".into(),
        account: r"NORTH\sql".into(),
        ..Stored::default()
    };
    let id = "S-1-5-21-1-2-3-1101";
    // Both on: one record with both.
    let mut s = sidecar();
    s.services = Check {
        status: CheckStatus::Complete,
        ..Check::default()
    };
    s.hosts.push(HostRecord {
        id: id.into(),
        name: "WS1.NORTH.LOCAL".into(),
        services: s.services.clone(),
        tasks: None,
        stored: vec![service.clone()],
    });
    merge(
        &mut s,
        vec![read_of(id, CheckStatus::Complete, vec![task.clone()])],
    );
    assert_eq!(s.hosts.len(), 1);
    assert_eq!(s.hosts[0].stored, [service.clone(), task.clone()]);
    assert_eq!(s.tasks.as_ref().unwrap().status, CheckStatus::Complete);
    assert!(!s.tasks_turned_off && !s.turned_off);

    // Services off, tasks on: the computer is added, its services not
    // collected for the switch's reason.
    let mut s = super::super::storedcreds::turned_off("north.local", Vec::new());
    merge(
        &mut s,
        vec![read_of(id, CheckStatus::Partial, vec![task.clone()])],
    );
    assert!(s.turned_off);
    assert_eq!(s.hosts.len(), 1);
    assert_eq!(s.hosts[0].services.status, CheckStatus::NotCollected);
    assert_eq!(
        s.hosts[0].services.reason.as_deref(),
        Some(super::super::storedcreds::TURNED_OFF)
    );
    assert_eq!(s.tasks.as_ref().unwrap().status, CheckStatus::Partial);

    // Services on, tasks off; and both off: the tasks step says so.
    for mut s in [
        sidecar(),
        super::super::storedcreds::turned_off("north.local", Vec::new()),
    ] {
        not_read(&mut s, TURNED_OFF, true);
        assert!(s.tasks_turned_off);
        let t = s.tasks.as_ref().unwrap();
        assert_eq!(t.status, CheckStatus::NotCollected);
        assert_eq!(t.reason.as_deref(), Some(TURNED_OFF));
        // Written and read back as the analysis reads it.
        let back = Sidecar::parse(&serde_json::to_vec(&s).unwrap(), &mut Vec::new()).unwrap();
        assert!(back.tasks_turned_off);
    }
    // NTLM: not read, not by choice.
    let mut s = super::super::storedcreds::not_read(
        "north.local",
        Vec::new(),
        super::super::storedcreds::NO_KERBEROS,
    );
    not_read(&mut s, NO_KERBEROS, false);
    assert!(!s.tasks_turned_off);
    assert_eq!(
        s.tasks.as_ref().unwrap().reason.as_deref(),
        Some(NO_KERBEROS)
    );

    // The flags reach the request; on by default, each on its own.
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: crate::CollectArgs,
    }
    let req = |extra: &[&str]| {
        let mut argv = vec!["x", "--domain", "contoso.local", "--out", "o"];
        argv.extend_from_slice(extra);
        Cli::parse_from(argv).args.into_request().unwrap()
    };
    let r = req(&[]);
    assert!(r.service_reads && r.task_reads);
    let r = req(&["--no-task-reads"]);
    assert!(r.service_reads && !r.task_reads);
    let r = req(&["--no-service-reads"]);
    assert!(!r.service_reads && r.task_reads);
    let r = req(&["--no-service-reads", "--no-task-reads"]);
    assert!(!r.service_reads && !r.task_reads);
    assert!(Cli::try_parse_from([
        "x",
        "--domain",
        "contoso.local",
        "--out",
        "o",
        "--task-reads",
        "--no-task-reads"
    ])
    .is_err());
}

/// A file any user planted in the tasks folder, and a planted folder, are
/// ignored: only what Task Scheduler registered is read, so a fake Tier
/// Zero principal can't make a finding.
#[test]
fn a_file_task_scheduler_never_registered_is_ignored() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Real", task_file(r"NORTH\svc_sync", "Password", true));
    share.plant(TASKS_DIR, "x", false, 100);
    share.files.insert(
        format!(r"{TASKS_DIR}\x").to_ascii_lowercase(),
        task_file(r"NORTH\Administrator", "Password", true),
    );
    share.plant(TASKS_DIR, "Planted", true, 0);
    share.dir(&format!(r"{TASKS_DIR}\Planted"));
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Complete, "{check:?}");
    assert_eq!(check.skipped, 2);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].account, r"NORTH\svc_sync");
    assert!(!share.read.iter().any(|p| p.ends_with(r"\x")));
    assert!(!share.listed.iter().any(|p| p.ends_with("Planted")));
}

/// A link (symbolic link or junction) in the tasks folder is never
/// followed, even when registered: the read is partial.
#[test]
fn links_are_not_followed() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Real", task_file(r"NORTH\svc_sync", "Password", true));
    for (name, is_dir) in [("ToSam", false), ("ToConfig", true)] {
        share.entry(TASKS_DIR, name, is_dir, 10);
        let e = share
            .dirs
            .get_mut(&TASKS_DIR.to_ascii_lowercase())
            .and_then(|d| d.iter_mut().find(|e| e.name == name))
            .unwrap();
        e.attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
    }
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert_eq!(check.reason.as_deref(), Some("2 links were not followed"));
    assert_eq!(stored.len(), 1);
    assert!(!share.read.iter().any(|p| p.contains("ToSam")));
    assert!(!share.listed.iter().any(|p| p.contains("ToConfig")));
}

/// The review's namespace bomb as a registered task file: refused before
/// the parser, quickly; the computer is partly read.
#[test]
fn a_parser_bomb_costs_nothing() {
    let decls: String = (0..256)
        .map(|n| format!(" xmlns:p{n}=\"urn:{n}\""))
        .collect();
    let bomb = format!(
        "<Task>{}{}{}</Task>",
        format!("<a{decls}>").repeat(63),
        "<b xmlns:q=\"urn:q\"/>".repeat(19_900),
        "</a>".repeat(63)
    );
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Bomb", bomb.into_bytes());
    let started = Instant::now();
    let (check, stored) = run(walk(&mut share, later()));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(check.status, CheckStatus::Partial);
    assert!(check.reason.unwrap().contains("not readable as a task"));
    assert!(stored.is_empty());
}

/// A computer's registry, as far as Task Scheduler's cache: Tree subkey
/// names by path (lower case), each task's `Id`, and each cache entry's
/// `Hash`. Records every open and query.
#[derive(Default)]
struct FakeTree {
    keys: BTreeMap<String, Vec<String>>,
    /// Tree path (lower case) → Id.
    ids: BTreeMap<String, RegValue>,
    /// Id → the cache entry's Hash (`None`: the entry has no Hash).
    hashes: BTreeMap<String, Option<RegValue>>,
    deny_root: bool,
    deny: Vec<String>,
    access: Vec<(String, u32)>,
    queried: Vec<(String, String)>,
    open_handles: i64,
}

fn reg_sz(s: &str) -> RegValue {
    let mut data: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&[0, 0]);
    RegValue { ty: 1, data }
}

fn reg_binary(b: &[u8]) -> RegValue {
    RegValue {
        ty: 3,
        data: b.to_vec(),
    }
}

impl FakeTree {
    /// A registered folder or task at `rel` (its parents as folders).
    fn add(&mut self, rel: &str) {
        let mut at = String::new();
        for part in rel.split('\\') {
            let next = if at.is_empty() {
                part.to_string()
            } else {
                format!(r"{at}\{part}")
            };
            let list = self.keys.entry(at.to_ascii_lowercase()).or_default();
            if !list.iter().any(|n| n == part) {
                list.push(part.to_string());
            }
            self.keys.entry(next.to_ascii_lowercase()).or_default();
            at = next;
        }
    }

    /// A registered task at `rel` with Id `id`, whose cache entry has
    /// `hash` (`None`: no cache entry at all).
    fn task(&mut self, rel: &str, id: &str, hash: Option<Option<RegValue>>) {
        self.add(rel);
        self.ids.insert(rel.to_ascii_lowercase(), reg_sz(id));
        if let Some(h) = hash {
            self.hashes.insert(id.to_string(), h);
        }
    }
}

impl super::super::storedcreds::Registry for FakeTree {
    type Key = Option<String>;
    async fn hklm(&mut self) -> Result<Option<String>, String> {
        self.open_handles += 1;
        Ok(None)
    }
    async fn open_key(
        &mut self,
        parent: &Option<String>,
        subkey: &str,
        access: u32,
    ) -> Result<Option<String>, String> {
        let path = match parent {
            None if subkey == TREE_KEY => String::new(),
            None => {
                let id = subkey
                    .strip_prefix(&format!(r"{TASKS_KEY}\"))
                    .expect("only the Tree key and cache entries under HKLM");
                self.access.push((format!("cache:{id}"), access));
                if !self.hashes.contains_key(id) {
                    return Err(format!("BaseRegOpenKey('{subkey}') failed (rc=2)"));
                }
                self.open_handles += 1;
                return Ok(Some(format!("cache:{id}")));
            }
            Some(p) if p.is_empty() => subkey.to_string(),
            Some(p) => format!(r"{p}\{subkey}"),
        };
        self.access.push((path.clone(), access));
        if (parent.is_none() && self.deny_root) || self.deny.contains(&path) {
            return Err(format!("BaseRegOpenKey('{subkey}') failed (rc=5)"));
        }
        self.open_handles += 1;
        Ok(Some(path))
    }
    async fn enum_key(
        &mut self,
        key: &Option<String>,
        index: u32,
    ) -> Result<Option<String>, String> {
        let k = key.as_deref().unwrap_or_default().to_ascii_lowercase();
        Ok(self
            .keys
            .get(&k)
            .and_then(|l| l.get(index as usize))
            .cloned())
    }
    async fn query(&mut self, key: &Option<String>, value: &str) -> Result<RegValue, String> {
        let k = key.clone().unwrap_or_default();
        self.queried.push((k.clone(), value.to_string()));
        let missing = || Err("BaseRegQueryValue failed (win32 2)".to_string());
        if let Some(id) = k.strip_prefix("cache:") {
            assert_eq!(value, "Hash", "only Hash from a cache entry");
            return match self.hashes.get(id).cloned().flatten() {
                Some(v) => Ok(v),
                None => missing(),
            };
        }
        assert_eq!(value, "Id", "only Id from a Tree key");
        match self.ids.get(&k.to_ascii_lowercase()) {
            Some(v) => Ok(v.clone()),
            None => missing(),
        }
    }
    async fn close(&mut self, _key: &Option<String>) {
        self.open_handles -= 1;
    }
}

use dcerpc::rrp::RegValue;

const ID1: &str = "{11111111-1111-1111-1111-111111111111}";
const ID2: &str = "{22222222-2222-2222-2222-222222222222}";
const ID3: &str = "{33333333-3333-3333-3333-333333333333}";

/// The registered tasks come from the Tree key with each task's hash from
/// its cache entry: only `Id` and `Hash` are queried, with the least
/// access, every key closed. A denied Tree is an error (nothing parsed); a
/// subkey that can't be opened or a chain too deep leave it incomplete; a
/// leftover entry, a bad Id and a missing Hash are told apart.
#[test]
fn the_tree_lists_the_registered_tasks() {
    use super::super::storedcreds::{KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE};
    let hash = [7u8; 32];
    let mut tree = FakeTree::default();
    tree.task("Nightly sync", ID1, Some(Some(reg_binary(&hash))));
    tree.task(r"Backups\Copy", ID2, Some(None));
    tree.task(r"Microsoft\Windows\SyncCenter\Leftover", ID3, None);
    tree.task("BadId", "not-a-guid", None);
    tree.task(
        "Crc",
        "{44444444-4444-4444-4444-444444444444}",
        Some(Some(reg_binary(&[1, 2, 3, 4]))),
    );
    let (reg, left) = run(registered_tasks(&mut tree, later())).unwrap();
    assert_eq!(left, None);
    assert_eq!(reg.get("nightly SYNC"), Some(&Expect::Hash(hash.to_vec())));
    assert_eq!(reg.get(r"backups\copy"), Some(&Expect::NoHash));
    assert_eq!(reg.get("Backups"), Some(&Expect::Folder));
    assert_eq!(
        reg.get(r"Microsoft\Windows\SyncCenter"),
        Some(&Expect::Folder)
    );
    assert_eq!(
        reg.get(r"Microsoft\Windows\SyncCenter\Leftover"),
        Some(&Expect::Unmatched)
    );
    assert_eq!(reg.get("BadId"), Some(&Expect::Unmatched));
    assert_eq!(
        reg.get("Crc"),
        Some(&Expect::NoHash),
        "a CRC32 is not trusted"
    );
    assert_eq!(reg.get("x"), None);
    for (path, access) in &tree.access {
        let want = if path.is_empty() {
            KEY_ENUMERATE_SUB_KEYS
        } else if path.starts_with("cache:") {
            KEY_QUERY_VALUE
        } else {
            KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
        };
        assert_eq!(*access, want, "{path}");
    }
    assert!(tree.queried.iter().all(|(_, v)| v == "Id" || v == "Hash"));
    assert_eq!(tree.open_handles, 0, "every key closed");

    let mut tree = FakeTree {
        deny_root: true,
        ..FakeTree::default()
    };
    let e = run(registered_tasks(&mut tree, later())).unwrap_err();
    assert_eq!(e, "access denied");
    assert_eq!(tree_unread(&e).status, CheckStatus::NotCollected);
    let other = tree_unread("Remote Registry: pipe not available");
    assert_eq!(other.status, CheckStatus::Partial);
    assert!(other.reason.unwrap().contains("no task file was read"));
    assert_eq!(tree.open_handles, 0);

    let mut tree = FakeTree::default();
    tree.add(r"Locked\Task");
    tree.deny = vec!["Locked".into()];
    let mut deep = String::from("d0");
    for i in 1..MAX_DEPTH + 2 {
        deep = format!(r"{deep}\d{i}");
    }
    tree.add(&deep);
    let (reg, left) = run(registered_tasks(&mut tree, later())).unwrap();
    let left = left.unwrap();
    assert!(
        left.contains("1 key of registered tasks could not be listed"),
        "{left}"
    );
    assert!(left.contains("deeper than 8"), "{left}");
    assert_eq!(reg.get("Locked"), Some(&Expect::Unmatched));
    assert_eq!(tree.open_handles, 0);
}

/// A user's own task whose file they rewrote (the hash no longer
/// matches), and a file under a leftover Tree entry, are skipped as not
/// matching their registration; a matching file is kept, and the read
/// stays complete.
#[test]
fn a_file_that_doesnt_match_its_registration_is_ignored() {
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Real", task_file(r"NORTH\svc_sync", "Password", true));
    // Registered as bob, rewritten to name the Administrator.
    share.task("Bob", task_file(r"NORTH\Administrator", "Password", true));
    share.registered.insert(
        "Bob",
        Expect::Hash(sha(&task_file(r"NORTH\bob", "Password", true))),
    );
    // A leftover Tree entry in a folder users can write to.
    share.task(
        r"SyncCenter\Leftover",
        task_file(r"NORTH\Administrator", "Password", true),
    );
    share
        .registered
        .insert(r"SyncCenter\Leftover", Expect::Unmatched);
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Complete, "{check:?}");
    assert_eq!(check.skipped, 2);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].account, r"NORTH\svc_sync");

    // Nothing matched at all (or the hash isn't what Pathwarden expects):
    // partial, never a clean "complete".
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Bob", task_file(r"NORTH\Administrator", "Password", true));
    share.registered.insert("Bob", Expect::Hash(vec![0; 32]));
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert!(check
        .reason
        .unwrap()
        .contains("no task file matched its registration"));
    assert!(stored.is_empty());

    // No SHA-256 in the registration (an older Windows): not trusted,
    // partial, nothing read.
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    share.task("Old", task_file(r"NORTH\svc_old", "Password", true));
    share.registered.insert("Old", Expect::NoHash);
    let (check, stored) = run(walk(&mut share, later()));
    assert_eq!(check.status, CheckStatus::Partial);
    assert!(check.reason.unwrap().contains("1 task has no SHA-256"));
    assert!(stored.is_empty());
    assert!(share.read.is_empty());
}

/// What listing the registered tasks left out goes in front of the
/// computer's status: partial with both reasons; not collected stays so.
#[test]
fn the_tree_left_out_is_merged() {
    let complete = Check {
        status: CheckStatus::Complete,
        read: 3,
        ..Check::default()
    };
    assert_eq!(with_tree_left(complete.clone(), None), complete);
    let c = with_tree_left(
        complete,
        Some("ran out of time listing the registered tasks".into()),
    );
    assert_eq!(c.status, CheckStatus::Partial);
    assert_eq!(
        c.reason.as_deref(),
        Some("ran out of time listing the registered tasks")
    );
    let partial = Check {
        status: CheckStatus::Partial,
        reason: Some("1 link was not followed".into()),
        ..Check::default()
    };
    let c = with_tree_left(
        partial,
        Some("1 key of registered tasks could not be listed".into()),
    );
    assert_eq!(
        c.reason.as_deref(),
        Some("1 key of registered tasks could not be listed; 1 link was not followed")
    );
    let c = with_tree_left(not_collected("access denied"), Some("x".into()));
    assert_eq!(c.status, CheckStatus::NotCollected);

    // And end to end with the fakes: a Tree read that left a folder out,
    // then the walk.
    let mut tree = FakeTree::default();
    tree.add(r"Locked\Task");
    tree.deny = vec!["Locked".into()];
    let (registered, left) = run(registered_tasks(&mut tree, later())).unwrap();
    let mut share = FakeShare::default();
    share.dir(TASKS_DIR);
    let (check, _) = run(read_tasks(&mut share, HOST, later(), &registered));
    let c = with_tree_left(check, left);
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(c.reason.unwrap().starts_with("1 key of registered tasks"));
}
