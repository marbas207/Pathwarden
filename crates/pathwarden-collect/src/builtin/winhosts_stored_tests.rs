//! The services and scheduled tasks of a computer read as the Windows
//! account, through a fake `HostApi`: a computer's registry
//! (its services keys and Task Scheduler's registrations) and its `C$`,
//! with the cases of the Kerberos walks' tests (slices 1 and 2), each read
//! through [`read_hosts`] and [`apply`].

use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

use pathwarden_core::storedcreds::{Via, MAX_TEXT};
use pathwarden_core::sysvol::CheckStatus;

use super::super::storedcreds::{
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, MAX_SERVICES, SERVICES_KEY, VALUES,
};
use super::super::tasks::{TASKS_DIR, TASKS_KEY, TREE_KEY};

const HOST: &str = "APP01.NORTH.CONTOSO.LOCAL";
const APP01: &str = "S-1-5-21-1000-2000-3000-1104";
const OWN: u32 = 0x10;

fn sz(s: &str) -> RegValue {
    let mut data: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&[0, 0]);
    RegValue { ty: 1, data }
}

fn dword(v: u32) -> RegValue {
    RegValue {
        ty: 4,
        data: v.to_le_bytes().to_vec(),
    }
}

fn binary(b: Vec<u8>) -> RegValue {
    RegValue { ty: 3, data: b }
}

/// The SHA-256 Task Scheduler records for a task file (without its BOM).
fn sha(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes)).to_vec()
}

/// A task file in UTF-16 with its BOM, as Windows writes them, with a
/// password on its command line that must never come back.
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

/// What the fake recorded.
#[derive(Default)]
struct Log {
    /// Keys opened, with the access asked.
    opened: Vec<(String, u32)>,
    /// (key, value) queried.
    queried: Vec<(String, String)>,
    /// Keys open now.
    open: i64,
    /// Folders listed and files read on `C$`.
    listed: Vec<String>,
    read: Vec<String>,
}

/// One computer: its registry by key path (lower case), each key's
/// subkeys in order and values; its `C$` folders and files. Every call is
/// recorded.
#[derive(Default)]
struct Computer {
    subkeys: BTreeMap<String, Vec<String>>,
    values: BTreeMap<String, Vec<(String, RegValue)>>,
    /// Keys whose opening is denied (rc=5).
    deny_keys: Vec<String>,
    dirs: BTreeMap<String, Vec<DirEntry>>,
    files: BTreeMap<String, Vec<u8>>,
    /// Folders whose listing is denied.
    deny_dirs: Vec<String>,
    /// Remote Registry can't be had: this code.
    no_registry: Option<Code>,
    log: Mutex<Log>,
}

fn lower(p: &str) -> String {
    p.to_ascii_lowercase()
}

impl Computer {
    fn key(&mut self, path: &str) {
        let mut at = String::new();
        for part in path.split('\\') {
            let next = if at.is_empty() {
                part.to_string()
            } else {
                format!(r"{at}\{part}")
            };
            let kids = self.subkeys.entry(lower(&at)).or_default();
            if !kids.iter().any(|k| k.eq_ignore_ascii_case(part)) {
                kids.push(part.to_string());
            }
            self.subkeys.entry(lower(&next)).or_default();
            at = next;
        }
    }

    fn value(&mut self, path: &str, name: &str, v: RegValue) {
        self.key(path);
        self.values
            .entry(lower(path))
            .or_default()
            .push((name.to_string(), v));
    }

    fn service(&mut self, name: &str, values: &[(&str, RegValue)]) {
        let path = format!(r"{SERVICES_KEY}\{name}");
        self.key(&path);
        for (k, v) in values {
            self.value(&path, k, v.clone());
        }
    }

    fn dir_entry(&mut self, parent: &str, name: &str, is_dir: bool, size: u64) {
        self.dirs.entry(lower(parent)).or_default().push(DirEntry {
            name: name.into(),
            is_dir,
            size,
            attributes: if is_dir { 0x10 } else { 0x20 },
        });
    }

    /// A task file at `rel` under the tasks folder, registered with Task
    /// Scheduler (folders and their Tree keys created) under `id` with the
    /// hash of `registered` (its own bytes unless told otherwise).
    fn task(&mut self, rel: &str, id: &str, bytes: Vec<u8>, registered: Option<&[u8]>) {
        let parts: Vec<&str> = rel.split('\\').collect();
        let mut at = TASKS_DIR.to_string();
        let mut tree = TREE_KEY.to_string();
        self.dirs.entry(lower(&at)).or_default();
        for p in &parts[..parts.len() - 1] {
            let next = format!(r"{at}\{p}");
            if !self.dirs.contains_key(&lower(&next)) {
                self.dir_entry(&at, p, true, 0);
                self.dirs.entry(lower(&next)).or_default();
            }
            tree = format!(r"{tree}\{p}");
            self.key(&tree);
            at = next;
        }
        let name = parts[parts.len() - 1];
        self.dir_entry(&at, name, false, bytes.len() as u64);
        self.value(&format!(r"{tree}\{name}"), "Id", sz(id));
        let hash = sha(registered.unwrap_or(&bytes));
        self.value(&format!(r"{TASKS_KEY}\{id}"), "Hash", binary(hash));
        self.files.insert(lower(&format!(r"{at}\{name}")), bytes);
    }

    /// A file in the tasks folder Task Scheduler doesn't know.
    fn plant(&mut self, name: &str, bytes: Vec<u8>) {
        self.dirs.entry(lower(TASKS_DIR)).or_default();
        self.dir_entry(TASKS_DIR, name, false, bytes.len() as u64);
        self.files
            .insert(lower(&format!(r"{TASKS_DIR}\{name}")), bytes);
    }
}

/// HKLM of a fake computer: keys by number, 0 the root.
struct Reg {
    c: Arc<Computer>,
    keys: Vec<Option<String>>,
}

impl HostRegistry for Reg {
    fn open_key(&mut self, parent: usize, subkey: &str, access: u32) -> Result<usize, String> {
        let Some(Some(p)) = self.keys.get(parent).cloned() else {
            return Err("not an open key (rc=6)".into());
        };
        let path = if p.is_empty() {
            subkey.to_string()
        } else {
            format!(r"{p}\{subkey}")
        };
        let mut log = self.c.log.lock().unwrap();
        log.opened.push((path.clone(), access));
        if self
            .c
            .deny_keys
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&path))
        {
            return Err(format!("RegOpenKeyExW('{subkey}') failed (rc=5)"));
        }
        if !self.c.subkeys.contains_key(&lower(&path)) {
            return Err(format!("RegOpenKeyExW('{subkey}') failed (rc=2)"));
        }
        log.open += 1;
        self.keys.push(Some(path));
        Ok(self.keys.len() - 1)
    }
    fn enum_key(&mut self, key: usize, index: u32) -> Result<Option<String>, String> {
        let path = self.keys[key].clone().expect("an open key");
        Ok(self
            .c
            .subkeys
            .get(&lower(&path))
            .and_then(|k| k.get(index as usize))
            .cloned())
    }
    fn query(&mut self, key: usize, value: &str) -> Result<RegValue, String> {
        let path = self.keys[key].clone().expect("an open key");
        self.c
            .log
            .lock()
            .unwrap()
            .queried
            .push((path.clone(), value.to_string()));
        self.c
            .values
            .get(&lower(&path))
            .and_then(|vs| vs.iter().find(|(n, _)| n.eq_ignore_ascii_case(value)))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| format!("RegQueryValueExW('{value}') failed (rc=2)"))
    }
    fn close(&mut self, key: usize) {
        if key == HKLM {
            return;
        }
        if self.keys[key].take().is_some() {
            self.c.log.lock().unwrap().open -= 1;
        }
    }
}

/// `C$` of a fake computer.
struct Share(Arc<Computer>);

impl HostShare for Share {
    fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String> {
        self.0.log.lock().unwrap().listed.push(path.to_string());
        if self
            .0
            .deny_dirs
            .iter()
            .any(|d| d.eq_ignore_ascii_case(path))
        {
            return Err("rc=5 (access denied)".into());
        }
        let all = self
            .0
            .dirs
            .get(&lower(path))
            .cloned()
            .ok_or_else(|| "rc=3 (error)".to_string())?;
        let more = all.len() > max;
        Ok((all.into_iter().take(max).collect(), more))
    }
    fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        self.0.log.lock().unwrap().read.push(path.to_string());
        let b = self
            .0
            .files
            .get(&lower(path))
            .cloned()
            .ok_or_else(|| "rc=2 (error)".to_string())?;
        let more = b.len() > max;
        Ok((b.into_iter().take(max).collect(), more))
    }
}

/// The fake `HostApi`: one computer, which answers on port 445 unless
/// `down`. Its sessions and local groups aren't asked here.
struct Api {
    c: Arc<Computer>,
    down: bool,
    /// Windows gets no `cifs/` ticket for it.
    no_ticket: bool,
    /// `services` (Remote Registry) was asked for.
    registry_asked: AtomicUsize,
    /// `tasks` (C$) was asked for.
    share_asked: AtomicUsize,
}

impl HostApi for Api {
    fn reachable(&self, _: &str, _: Duration) -> bool {
        !self.down
    }
    fn net_sessions(&self, _: &str) -> Result<Vec<String>, Code> {
        unreachable!("not asked")
    }
    fn logged_on(&self, _: &str) -> Result<Vec<(String, String)>, Code> {
        unreachable!("not asked")
    }
    fn registry_users(&self, _: &str) -> Result<Vec<String>, Code> {
        unreachable!("not asked")
    }
    fn account_domain(&self, _: &str) -> Result<(String, String), Code> {
        unreachable!("not asked")
    }
    fn alias_members(&self, _: &str, _: u32) -> Result<Vec<String>, Code> {
        unreachable!("not asked")
    }
    fn cifs_ticket(&self, host: &str) -> Result<(), String> {
        if self.no_ticket {
            return Err(format!(
                "{host}: skipped: the domain has no Kerberos name for it"
            ));
        }
        Ok(())
    }
    fn services(&self, _: &str) -> Result<Box<dyn HostRegistry>, Code> {
        self.registry_asked.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = self.c.no_registry {
            return Err(code);
        }
        Ok(Box::new(Reg {
            c: self.c.clone(),
            keys: vec![Some(String::new())],
        }))
    }
    fn tasks(&self, _: &str) -> Result<Box<dyn HostShare>, Code> {
        self.share_asked.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Share(self.c.clone())))
    }
}

/// Reads `c`'s services and tasks (as asked) through [`read_hosts`] and
/// writes them as [`apply`] does: the computer's record, and the fake.
fn read(c: Computer, services: bool, tasks: bool, down: bool) -> (HostRecord, Arc<Api>) {
    read_with(c, services, tasks, down, false)
}

/// [`read`], with or without the computer's Kerberos ticket.
fn read_with(
    c: Computer,
    services: bool,
    tasks: bool,
    down: bool,
    no_ticket: bool,
) -> (HostRecord, Arc<Api>) {
    let api = Arc::new(Api {
        c: Arc::new(c),
        down,
        no_ticket,
        registry_asked: AtomicUsize::new(0),
        share_asked: AtomicUsize::new(0),
    });
    let ask = HostAsk {
        name: HOST.into(),
        services,
        tasks,
        ..HostAsk::default()
    };
    let limits = Limits {
        port: PORT_TIMEOUT,
        per_host: HOST_TIMEOUT,
        at_once: AT_ONCE,
        deadline: Instant::now() + Duration::from_secs(60),
    };
    let found = read_hosts(
        api.clone(),
        &[ask],
        limits,
        Box::leak(Box::new(AtomicUsize::new(0))),
    )
    .unwrap()
    .remove(0);
    let mut computer = {
        let mut v =
            serde_json::to_value(rusthound_ce::objects::computer::Computer::default()).unwrap();
        v["Properties"]["name"] = HOST.into();
        v["Properties"]["is_dc"] = false.into();
        v["ObjectIdentifier"] = APP01.into();
        v["IsDC"] = false.into();
        serde_json::from_value(v).unwrap()
    };
    let record = apply(
        &mut computer,
        &found,
        &SidIndex::new(&[], "north.contoso.local"),
        &HashMap::new(),
        "north.contoso.local",
    )
    .expect("a record when services or tasks are asked");
    (record, api)
}

/// The usual computer of slices 1 and 2: services that run as built-in,
/// virtual, local and domain accounts, a gMSA, a disabled one, a driver, a
/// key with `ImagePath` and `Password` values; and scheduled tasks of each
/// logon type, nested, one disabled, plus a file Task Scheduler doesn't
/// know and one rewritten after it was registered.
fn usual() -> Computer {
    let mut c = Computer::default();
    c.service(
        "Spooler",
        &[("ObjectName", sz("LocalSystem")), ("Type", dword(OWN))],
    );
    c.service(
        "MSSQL$SQLEXPRESS",
        &[
            ("ObjectName", sz("NT Service\\MSSQL$SQLEXPRESS")),
            ("Type", dword(OWN)),
        ],
    );
    c.service(
        "LocalBackup",
        &[("ObjectName", sz(".\\backup")), ("Type", dword(OWN))],
    );
    c.service(
        "OwnName",
        &[
            ("ObjectName", sz("APP01\\localadmin")),
            ("Type", dword(OWN)),
        ],
    );
    c.service(
        "SqlAgent",
        &[
            ("ObjectName", sz("NORTH\\sql_svc")),
            ("Start", dword(2)),
            ("Type", dword(OWN)),
            ("ImagePath", sz("C:\\sql\\agent.exe -p Hunter2!")),
            ("Password", sz("Hunter2!")),
        ],
    );
    c.service(
        "Reports",
        &[
            ("ObjectName", sz("svc@north.contoso.local")),
            ("Start", dword(3)),
            ("Type", dword(0x20)),
        ],
    );
    c.service(
        "Backup",
        &[
            ("ObjectName", sz("NORTH\\gmsa01$")),
            ("Start", dword(2)),
            ("Type", dword(OWN)),
        ],
    );
    c.service(
        "OldJob",
        &[
            ("ObjectName", sz("NORTH\\old_svc")),
            ("Start", dword(4)),
            ("Type", dword(OWN)),
        ],
    );
    c.service("Drv", &[("ObjectName", sz("NORTH\\x")), ("Type", dword(1))]);
    c.service("NoAccount", &[("Type", dword(OWN))]);
    // A Parameters key below a service: never opened.
    c.value(
        &format!(r"{SERVICES_KEY}\SqlAgent\Parameters"),
        "Secret",
        sz("Hunter2!"),
    );

    let id = |n: u32| format!("{{0000000{n}-0000-0000-0000-000000000000}}");
    c.task(
        "Nightly sync",
        &id(1),
        task_file(r"NORTH\svc_sync", "Password", true),
        None,
    );
    c.task(
        r"Backups\Copy",
        &id(2),
        task_file("S-1-5-21-1-2-3-1201", "InteractiveTokenOrPassword", true),
        None,
    );
    c.task(
        r"Backups\Old\Archive",
        &id(3),
        task_file("svc_old@north.contoso.local", "Password", false),
        None,
    );
    c.task(
        r"Microsoft\Windows\Defrag\ScheduledDefrag",
        &id(4),
        task_file("S-1-5-18", "ServiceAccount", true),
        None,
    );
    c.task(
        "S4U job",
        &id(5),
        task_file(r"NORTH\svc_s4u", "S4U", true),
        None,
    );
    c.task(
        "Interactive",
        &id(6),
        task_file(r"NORTH\alice", "InteractiveToken", true),
        None,
    );
    c.task(
        "Local",
        &id(7),
        task_file(r"APP01\admin", "Password", true),
        None,
    );
    // Registered as a harmless task, then rewritten by its owner.
    c.task(
        "Rewritten",
        &id(8),
        task_file(r"NORTH\da_admin", "Password", true),
        Some(&task_file(r"NORTH\alice", "InteractiveToken", true)),
    );
    // Written into the folder by a user; Task Scheduler doesn't know it.
    c.plant("Planted", task_file(r"NORTH\da_admin", "Password", true));
    // Never read: outside the tasks folder.
    c.files
        .insert(r"windows\system32\config\sam".into(), b"secret".to_vec());
    c
}

/// The usual mix, as the Windows account: only domain accounts' services
/// (a disabled one too, a gMSA kept for the analysis to drop) and the
/// registered tasks that store a domain account's password; only
/// `ObjectName`, `Start` and `Type` of a service's own key, only `Id` and
/// `Hash` of Task Scheduler's keys, only the tasks folder; each key opened
/// for the least access and closed; nothing secret comes back.
#[test]
fn services_and_tasks_are_read_as_a_full_collection_reads_them() {
    let (r, api) = read(usual(), true, true, false);
    assert_eq!(r.id, APP01);
    assert_eq!(r.services.status, CheckStatus::Complete, "{:?}", r.services);
    assert_eq!(r.services.read, 10);
    let tasks = r.tasks.clone().unwrap();
    // The rewritten file is skipped; the read stays complete.
    assert_eq!(tasks.status, CheckStatus::Complete, "{tasks:?}");
    let got: Vec<(Via, &str, &str)> = r
        .stored
        .iter()
        .map(|s| (s.via, s.name.as_str(), s.account.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (Via::Service, "SqlAgent", "NORTH\\sql_svc"),
            (Via::Service, "Reports", "svc@north.contoso.local"),
            (Via::Service, "Backup", "NORTH\\gmsa01$"),
            (Via::Service, "OldJob", "NORTH\\old_svc"),
            (Via::Task, r"\Nightly sync", r"NORTH\svc_sync"),
            (Via::Task, r"\Backups\Copy", "S-1-5-21-1-2-3-1201"),
            (
                Via::Task,
                r"\Backups\Old\Archive",
                "svc_old@north.contoso.local"
            ),
        ],
        "{got:?}"
    );
    let old = r.stored.iter().find(|s| s.name == "OldJob").unwrap();
    assert!(old.disabled());
    let archive = r
        .stored
        .iter()
        .find(|s| s.name.ends_with("Archive"))
        .unwrap();
    assert!(archive.disabled());

    let log = api.c.log.lock().unwrap();
    let services = lower(SERVICES_KEY);
    let tree = lower(TREE_KEY);
    let cache = lower(TASKS_KEY);
    for (path, access) in &log.opened {
        let p = lower(path);
        assert!(!p.contains("parameters"), "{path}");
        let want = if p == services {
            KEY_ENUMERATE_SUB_KEYS
        } else if p.starts_with(&services) {
            KEY_QUERY_VALUE
        } else if p.starts_with(&tree) {
            if p == tree {
                KEY_ENUMERATE_SUB_KEYS
            } else {
                KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
            }
        } else if p.starts_with(&cache) {
            KEY_QUERY_VALUE
        } else {
            panic!("opened {path}");
        };
        assert_eq!(*access, want, "{path}");
    }
    for (key, value) in &log.queried {
        let k = lower(key);
        if k.starts_with(&services) {
            assert!(VALUES.contains(&value.as_str()), "{key} {value}");
            // A service's own key, never one below it.
            assert_eq!(k.matches('\\').count(), 3, "{key}");
        } else if k.starts_with(&tree) {
            assert_eq!(value, "Id");
        } else {
            assert!(k.starts_with(&cache), "{key}");
            assert_eq!(value, "Hash");
        }
    }
    assert_eq!(log.open, 0, "every key closed");
    let tasks_dir = lower(TASKS_DIR);
    for p in log.listed.iter().chain(&log.read) {
        assert!(lower(p).starts_with(&tasks_dir), "{p}");
    }
    // Neither the planted file nor the rewritten one was parsed into the
    // result; the planted one was never even read.
    assert!(!log.read.iter().any(|p| p.ends_with("Planted")));
    drop(log);
    let json = serde_json::to_string(&r).unwrap();
    for secret in [
        "Hunter2",
        "agent.exe",
        "robocopy",
        "Copies the backups",
        "da_admin",
    ] {
        assert!(!json.contains(secret), "{secret} in {json}");
    }
}

/// Remote Registry or `C$` denied (a plain user): not collected, access
/// denied; nothing else is tried.
#[test]
fn access_denied_is_not_collected() {
    let c = Computer {
        no_registry: Some(5),
        ..usual()
    };
    let (r, api) = read(c, true, true, false);
    assert_eq!(r.services.status, CheckStatus::NotCollected);
    assert_eq!(
        r.services.reason.as_deref(),
        Some("Remote Registry: access denied")
    );
    let tasks = r.tasks.unwrap();
    assert_eq!(tasks.status, CheckStatus::NotCollected);
    assert!(tasks.reason.as_deref().unwrap().ends_with("access denied"));
    // Without the registrations no task file is read.
    assert_eq!(api.share_asked.load(Ordering::SeqCst), 0);
    assert!(r.stored.is_empty());

    // The services key denied.
    let mut c = usual();
    c.deny_keys = vec![SERVICES_KEY.into()];
    let (r, _) = read(c, true, false, false);
    assert_eq!(r.services.status, CheckStatus::NotCollected);
    assert_eq!(r.services.reason.as_deref(), Some("access denied"));

    // The tasks folder denied.
    let mut c = usual();
    c.deny_dirs = vec![TASKS_DIR.into()];
    let (r, _) = read(c, false, true, false);
    let tasks = r.tasks.unwrap();
    assert_eq!(tasks.status, CheckStatus::NotCollected);
    assert_eq!(tasks.reason.as_deref(), Some("access denied"));
    assert!(r.stored.is_empty());
}

/// Each part has its own switch: a part not asked isn't read and says so;
/// with neither asked there is no record.
#[test]
fn only_the_parts_asked_are_read() {
    let (r, api) = read(usual(), true, false, false);
    assert_eq!(r.services.status, CheckStatus::Complete);
    let tasks = r.tasks.unwrap();
    assert_eq!(tasks.status, CheckStatus::NotCollected);
    assert_eq!(
        tasks.reason.as_deref(),
        Some(super::super::tasks::TURNED_OFF)
    );
    assert!(r.stored.iter().all(|s| s.via == Via::Service));
    assert_eq!(api.share_asked.load(Ordering::SeqCst), 0);
    assert!(api.c.log.lock().unwrap().listed.is_empty());

    let (r, api) = read(usual(), false, true, false);
    assert_eq!(
        r.services.reason.as_deref(),
        Some(super::super::storedcreds::TURNED_OFF)
    );
    assert!(r.stored.iter().all(|s| s.via == Via::Task));
    assert!(!api
        .c
        .log
        .lock()
        .unwrap()
        .opened
        .iter()
        .any(|(p, _)| lower(p).starts_with(&lower(SERVICES_KEY))));

    let found = HostFound::new(&HostAsk {
        name: HOST.into(),
        sessions: true,
        ..HostAsk::default()
    });
    let c = rusthound_ce::objects::computer::Computer::default();
    assert!(stored_record(&c, &found).is_none());
}

/// Without the computer's `cifs/` Kerberos ticket neither Remote Registry
/// nor `C$` is asked for: both parts not collected, with the skip reason.
#[test]
fn no_kerberos_ticket_reads_nothing() {
    let (r, api) = read_with(usual(), true, true, false, true);
    let why = format!("{HOST}: skipped: the domain has no Kerberos name for it");
    assert_eq!(r.services.status, CheckStatus::NotCollected);
    assert_eq!(r.services.reason.as_deref(), Some(why.as_str()));
    assert_eq!(r.tasks.unwrap().reason.as_deref(), Some(why.as_str()));
    assert_eq!(api.registry_asked.load(Ordering::SeqCst), 0);
    assert_eq!(api.share_asked.load(Ordering::SeqCst), 0);
    let log = api.c.log.lock().unwrap();
    assert!(log.opened.is_empty() && log.listed.is_empty() && log.read.is_empty());
}

/// A computer that doesn't answer: both parts not collected, with why.
#[test]
fn an_unreachable_computer_is_not_collected() {
    let (r, _) = read(usual(), true, true, true);
    let why = format!("{HOST}: 445/tcp unreachable");
    assert_eq!(r.services.status, CheckStatus::NotCollected);
    assert_eq!(r.services.reason.as_deref(), Some(why.as_str()));
    assert_eq!(r.tasks.unwrap().reason.as_deref(), Some(why.as_str()));
}

/// A hostile computer: more services than the limit, names too long or
/// with control characters, a task file with a DTD (an entity bomb) or a
/// namespace flood, and one larger than it says.
#[test]
fn hostile_answers_are_bounded() {
    let mut c = Computer::default();
    let long = "N".repeat(5000);
    c.service(
        "Long",
        &[
            ("ObjectName", sz(&format!("NORTH\\{long}"))),
            ("Type", dword(OWN)),
        ],
    );
    c.service("Bad\u{1}Name", &[("ObjectName", sz("NORTH\\x"))]);
    for i in 0..MAX_SERVICES {
        c.key(&format!(r"{SERVICES_KEY}\Filler{i}"));
    }
    let bomb = br#"<?xml version="1.0"?>
<!DOCTYPE Task [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
<Task><Principals><Principal><UserId>NORTH\da_admin</UserId><LogonType>Password</LogonType></Principal></Principals><Actions><Exec><Arguments>&b;</Arguments></Exec></Actions></Task>"#
        .to_vec();
    c.task("Bomb", "{00000001-0000-0000-0000-000000000000}", bomb, None);
    let mut ns =
        String::from(r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task""#);
    for i in 0..64 {
        ns.push_str(&format!(r#" xmlns:p{i}="urn:x{i}""#));
    }
    ns.push_str(r"><Principals><Principal><UserId>NORTH\da_admin</UserId><LogonType>Password</LogonType></Principal></Principals></Task>");
    c.task(
        "Namespaces",
        "{00000002-0000-0000-0000-000000000000}",
        ns.into_bytes(),
        None,
    );
    let big = vec![b' '; pathwarden_core::taskxml::MAX_TASK_FILE + 10];
    c.task("Big", "{00000003-0000-0000-0000-000000000000}", big, None);
    let (r, _) = read(c, true, true, false);
    assert_eq!(r.services.status, CheckStatus::Partial);
    assert!(r
        .services
        .reason
        .as_deref()
        .unwrap()
        .contains("more than 4096"));
    let long_one = r.stored.iter().find(|s| s.via == Via::Service).unwrap();
    assert_eq!(long_one.account.chars().count(), MAX_TEXT);
    let tasks = r.tasks.unwrap();
    assert_eq!(tasks.status, CheckStatus::Partial, "{tasks:?}");
    let why = tasks.reason.unwrap();
    assert!(why.contains("not readable as a task"), "{why}");
    assert!(why.contains("over the 1024 KiB limit"), "{why}");
    assert!(!r.stored.iter().any(|s| s.via == Via::Task));
    assert!(!r.stored.iter().any(|s| s.account.contains("da_admin")));
}
