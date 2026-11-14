//! Scheduled tasks that store a domain account's password.
//!
//! A task set to run "whether the user is logged on or not" keeps its
//! account's password in the computer's credential store, where any
//! administrator of the computer can read it. In a Full collection over
//! Kerberos, each reached computer's `C$` is opened on a signed Kerberos SMB
//! session ([`super::krbreg::connect`]: the computer's `cifs/` ticket, every
//! reply signed and checked, no NTLM) and only `Windows\System32\Tasks` is
//! listed and read. Only files Task Scheduler registered are read, and only
//! when they match the SHA-256 their registration records
//! ([`registered_tasks`], over Remote Registry on the same session): any
//! user can write files into that folder, and a user who registered a task
//! of their own may be able to rewrite its file. Each task file is parsed
//! in memory
//! ([`pathwarden_core::taskxml`]) for its principal, logon type and enabled
//! flag only, then dropped: never its actions, arguments or description,
//! and never the password, which isn't in the file.
//!
//! Everything a computer answers is untrusted: at most [`MAX_FILES`] files
//! and [`MAX_LISTED`] directory entries, folders at most [`MAX_DEPTH`]
//! deep, files at most [`pathwarden_core::taskxml::MAX_TASK_FILE`] bytes
//! (however large the computer says they are), names cut, and each computer
//! gets [`PER_HOST`]. Reading `C$` is share access: Windows logs it as
//! event 5140, and with detailed file share auditing as 5145 per file.
//!
//! The result goes into the same `pathwarden-storedcreds.json` as the
//! services ([`super::storedcreds`]), with each computer's tasks status, so
//! a computer that wasn't read is "can't tell" in retest rather than
//! "fixed". The reads have their own switch (`--no-task-reads`,
//! `[collect] task_reads`).

use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use pathwarden_core::storedcreds::{account_ref, AccountRef, HostRecord, Sidecar, Stored, Via};
use pathwarden_core::sysvol::{Check, CheckStatus};
use rusthound_ce::objects::computer::Computer;
use smb2_client::msg::FILE_ATTRIBUTE_REPARSE_POINT;
use smb2_client::{DirEntry, SmbClient};

use super::hostauth::Skipped;
use super::hosts::{self, KerberosSignIn};
use super::storedcreds::{clean, not_collected, skip_words, sum_up, words, Progress};
use super::Msg;

/// The tasks folder on `C$`. Nothing outside it is listed or read.
pub(crate) const TASKS_DIR: &str = r"Windows\System32\Tasks";
/// Most task files read from one computer (real ones: a few hundred).
pub(crate) const MAX_FILES: usize = 5000;
/// Most directory entries listed on one computer, folders included.
pub(crate) const MAX_LISTED: usize = 20_000;
/// Deepest folder under the tasks folder that is read (real ones: four).
pub(crate) const MAX_DEPTH: usize = 8;
/// Longest file or folder name used (Windows allows 255).
const MAX_NAME: usize = 255;
/// How long one computer's tasks may take, sign-in included.
pub(crate) const PER_HOST: Duration = Duration::from_secs(60);
/// Computers read at once.
const AT_ONCE: usize = 16;
/// Computers whose account password is older than this aren't contacted
/// (as the modules do).
const EXPIRY_DAYS: i64 = 60;
/// The whole tasks step's time, all computers.
pub(crate) const STEP_BUDGET: Duration = Duration::from_secs(30 * 60);
/// Why a computer wasn't read when [`STEP_BUDGET`] ran out.
pub(crate) const OUT_OF_TIME: &str = "the scheduled tasks step ran out of time (30 minutes)";
/// Rough time to read one computer's tasks on a LAN: a couple of hundred
/// small files, three calls each.
pub(crate) const PER_HOST_ESTIMATE: Duration = Duration::from_millis(1500);
/// Why tasks aren't read without Kerberos.
pub(crate) const NO_KERBEROS: &str = "scheduled tasks are read only over Kerberos; this \
     collection signed in to computers with NTLM";
/// Why tasks weren't read when they were turned off.
pub(crate) const TURNED_OFF: &str = "task reads were turned off for this collection";

/// The share calls the walk makes, so a fake can stand in for a computer
/// in tests. Paths are relative to the share's root.
pub(crate) trait Share {
    /// A folder's entries (at most `max`), and whether there were more.
    async fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String>;
    /// A file's first `max` bytes, and whether it goes on.
    async fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String>;
}

impl Share for SmbClient {
    async fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String> {
        self.list_directory_max(path, max)
            .await
            .map_err(|e| e.to_string())
    }
    async fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        self.read_file_max(path, max)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Whether a task's account is one whose password matters: a domain
/// account by name or UPN (not the computer's own, built-in or virtual
/// accounts), or an account's SID (resolved against the directory later).
pub(crate) fn is_task_account(account: &str, host: &str) -> bool {
    super::storedcreds::is_domain_account(account, host)
        || matches!(account_ref(account), Some(AccountRef::Sid(_)))
}

/// A name a folder listing gave that is safe to use in a path.
fn usable(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.chars().count() <= MAX_NAME
        && !name.contains(['\\', '/', ':'])
        && !name.chars().any(char::is_control)
}

/// What a walk left out, for the reason.
#[derive(Default)]
struct Left {
    deep: usize,
    oversize: usize,
    unparsed: usize,
    folders: usize,
    names: usize,
    links: usize,
    unregistered: usize,
    /// Task files that don't match their registration, or whose
    /// registration is a leftover.
    unmatched: usize,
    /// Registered tasks with no SHA-256 to check their file against.
    unchecked: usize,
    files: bool,
    listed: bool,
    time: bool,
}

/// Reads the tasks of one computer through `share` (already connected to
/// its `C$`) until `deadline`: the tasks that store a domain account's
/// password, and how far the read got.
pub(crate) async fn read_tasks<S: Share>(
    share: &mut S,
    host: &str,
    deadline: Instant,
    registered: &Registered,
) -> (Check, Vec<Stored>) {
    let mut stored = Vec::new();
    let mut check = Check {
        status: CheckStatus::Complete,
        ..Check::default()
    };
    let mut left = Left::default();
    let mut listed = 0usize;
    let mut files = 0usize;
    let mut matched = 0usize;
    // Folders to list, relative to the tasks folder, with their depth.
    let mut folders: Vec<(String, usize)> = vec![(String::new(), 0)];
    while let Some((rel, depth)) = folders.pop() {
        if Instant::now() >= deadline {
            left.time = true;
            break;
        }
        if listed >= MAX_LISTED {
            left.listed = true;
            break;
        }
        let path = if rel.is_empty() {
            TASKS_DIR.to_string()
        } else {
            format!(r"{TASKS_DIR}\{rel}")
        };
        let room = MAX_LISTED.saturating_sub(listed);
        let (entries, more) = match share.list(&path, room).await {
            Ok(r) => r,
            // The tasks folder itself: nothing read.
            Err(e) if rel.is_empty() => return (not_collected(&words(&e)), stored),
            Err(_) => {
                left.folders += 1;
                continue;
            }
        };
        listed += entries.len();
        if more {
            left.listed = true;
        }
        for e in entries {
            if !usable(&e.name) {
                left.names += 1;
                continue;
            }
            // A link (symbolic link, junction) is never followed.
            if e.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                left.links += 1;
                continue;
            }
            let child = if rel.is_empty() {
                e.name.clone()
            } else {
                format!(r"{rel}\{}", e.name)
            };
            // Only what Task Scheduler registered (any user can write to the
            // tasks folder), and a task's file only when it matches its
            // registration (a user may rewrite their own task's file).
            let expect = registered.get(&child);
            if e.is_dir {
                if expect != Some(&Expect::Folder) {
                    left.unregistered += 1;
                    continue;
                }
                if depth + 1 > MAX_DEPTH {
                    left.deep += 1;
                } else {
                    folders.push((child, depth + 1));
                }
                continue;
            }
            let hash = match expect {
                None | Some(Expect::Folder) => {
                    left.unregistered += 1;
                    continue;
                }
                Some(Expect::Unmatched) => {
                    left.unmatched += 1;
                    continue;
                }
                Some(Expect::NoHash) => {
                    left.unchecked += 1;
                    continue;
                }
                Some(Expect::Hash(h)) => h.clone(),
            };
            if files >= MAX_FILES {
                left.files = true;
                continue;
            }
            if Instant::now() >= deadline {
                left.time = true;
                break;
            }
            files += 1;
            if e.size > pathwarden_core::taskxml::MAX_TASK_FILE as u64 {
                left.oversize += 1;
                continue;
            }
            let file = format!(r"{TASKS_DIR}\{child}");
            let bytes = match share
                .read(&file, pathwarden_core::taskxml::MAX_TASK_FILE)
                .await
            {
                Ok((_, true)) => {
                    // Larger than it said.
                    left.oversize += 1;
                    continue;
                }
                Ok((b, false)) => b,
                Err(_) => {
                    check.failed += 1;
                    continue;
                }
            };
            if !pathwarden_core::taskxml::matches_registration(&bytes, &hash) {
                left.unmatched += 1;
                continue;
            }
            matched += 1;
            // Parsed off the async threads: bounded, but CPU work.
            let parsed = tokio::task::spawn_blocking(move || {
                pathwarden_core::taskxml::stored_account(&bytes)
            })
            .await
            .unwrap_or_else(|_| Err("the parse stopped".into()));
            match parsed {
                Ok(found) => {
                    check.read += 1;
                    let Some(t) = found else { continue };
                    let Some(account) = clean(&t.account).filter(|a| is_task_account(a, host))
                    else {
                        continue;
                    };
                    let Some(name) = clean(&format!(r"\{child}")) else {
                        continue;
                    };
                    stored.push(Stored {
                        via: Via::Task,
                        name,
                        account,
                        enabled: t.enabled,
                        logon_type: Some(t.logon_type.to_string()),
                        ..Stored::default()
                    });
                }
                Err(_) => left.unparsed += 1,
            }
        }
    }
    let mut why: Vec<String> = Vec::new();
    let count = pathwarden_core::text::count;
    if left.time {
        why.push("ran out of time".into());
    }
    if left.files {
        why.push(format!(
            "more than {MAX_FILES} task files; the rest were not read"
        ));
    }
    if left.listed {
        why.push(format!(
            "more than {MAX_LISTED} entries listed; the rest were not read"
        ));
    }
    if left.deep > 0 {
        why.push(format!(
            "{} deeper than {MAX_DEPTH} levels not read",
            count(left.deep, "folder", "folders")
        ));
    }
    if left.folders > 0 {
        why.push(format!(
            "{} could not be listed",
            count(left.folders, "folder", "folders")
        ));
    }
    if check.failed > 0 {
        why.push(format!(
            "{} could not be read",
            count(check.failed, "task file", "task files")
        ));
    }
    if left.oversize > 0 {
        why.push(format!(
            "{} over the {} KiB limit",
            count(left.oversize, "task file", "task files"),
            pathwarden_core::taskxml::MAX_TASK_FILE / 1024
        ));
    }
    if left.unparsed > 0 {
        why.push(format!(
            "{} not readable as a task",
            count(left.unparsed, "file was", "files were")
        ));
    }
    if left.names > 0 {
        why.push(format!(
            "{} not usable",
            count(left.names, "name was", "names were")
        ));
    }
    if left.links > 0 {
        why.push(format!(
            "{} not followed",
            count(left.links, "link was", "links were")
        ));
    }
    if left.unchecked > 0 {
        why.push(format!(
            "{} no SHA-256 in {} registration (older Windows?), so {} not trusted",
            count(left.unchecked, "task has", "tasks have"),
            if left.unchecked == 1 { "its" } else { "their" },
            if left.unchecked == 1 {
                "it was"
            } else {
                "they were"
            },
        ));
    }
    // Files that don't match their registration are skipped and the read
    // stays complete, unless none matched: then nothing could be checked
    // (or the hash isn't what Pathwarden expects), and "complete" would
    // wrongly clear findings.
    if left.unmatched > 0 && matched == 0 {
        why.push(format!(
            "no task file matched its registration ({} checked)",
            left.unmatched
        ));
    }
    // Files and folders Task Scheduler doesn't know are not tasks: skipped,
    // and the read is still complete.
    check.skipped = left.deep
        + left.oversize
        + left.unparsed
        + left.names
        + left.links
        + left.unregistered
        + left.unmatched
        + left.unchecked;
    if !why.is_empty() {
        check.status = CheckStatus::Partial;
        check.reason = Some(why.join("; "));
    }
    // A hostile computer could list one task file after another storing a
    // password: as many as the analysis keeps.
    if stored.len() > MAX_STORED {
        stored.truncate(MAX_STORED);
        check.status = CheckStatus::Partial;
        check.reason.get_or_insert_with(|| {
            format!("more than {MAX_STORED} tasks store a password; the rest were not kept")
        });
    }
    (check, stored)
}

/// Most stored passwords kept per computer (the analysis keeps as many).
const MAX_STORED: usize = 1024;

/// Task Scheduler's own list of the registered tasks and folders: one key
/// per folder and task, mirroring the tasks folder, written by the Task
/// Scheduler service (a user can't write it directly, though any user can
/// register a task of their own through the service).
pub(crate) const TREE_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

/// Task Scheduler's cache of each registered task, by its Id: its `Hash`
/// value is a hash of the task's file as Task Scheduler wrote it.
pub(crate) const TASKS_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";

/// What the registration says a path under the tasks folder should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    /// A registered folder.
    Folder,
    /// A registered task, and the SHA-256 its registration records.
    Hash(Vec<u8>),
    /// A registered task whose registration records no SHA-256 (an older
    /// Windows, or a value that couldn't be read): its file can't be tied
    /// to it, so it isn't trusted.
    NoHash,
    /// A Tree entry with no usable Id, or whose Id has no cache entry (a
    /// leftover): no file is trusted under its name.
    Unmatched,
}

/// The registered tasks and folders, by their path under the tasks folder
/// (`Folder\Name`, compared case-insensitively), with what each file must
/// match. Only these are read. Any user can write files into the tasks
/// folder, and a user can register a task of their own and may then be
/// able to rewrite its file; so a task file counts only when it matches
/// the hash its registration records.
#[derive(Debug, Default, Clone)]
pub(crate) struct Registered(std::collections::HashMap<String, Expect>);

impl Registered {
    pub(crate) fn get(&self, rel: &str) -> Option<&Expect> {
        self.0.get(&rel.to_lowercase())
    }

    pub(crate) fn insert(&mut self, rel: &str, expect: Expect) {
        self.0.insert(rel.to_lowercase(), expect);
    }
}

/// The computer's status when its registered tasks couldn't be listed:
/// nothing is parsed. Access denied is not collected (as for `C$`); any
/// other failure (Remote Registry not running, ...) leaves it partly
/// collected, with the reason.
pub(crate) fn tree_unread(why: &str) -> Check {
    if why.ends_with("access denied") {
        return not_collected(why);
    }
    Check {
        status: CheckStatus::Partial,
        reason: Some(format!(
            "the list of registered tasks couldn't be read ({why}), so no task file was read"
        )),
        ..Check::default()
    }
}

/// A task's Id as the Tree key gives it, when it is a GUID in braces.
fn task_id(v: &dcerpc::rrp::RegValue) -> Option<String> {
    const REG_SZ: u32 = 1;
    let s = (v.ty == REG_SZ).then(|| v.as_string())?;
    let s = s.trim_end_matches('\0').trim();
    let ok = s.len() == 38
        && s.starts_with('{')
        && s.ends_with('}')
        && s[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    ok.then(|| s.to_string())
}

/// A registered task's expected hash, from `TaskCache\Tasks\{id}`'s `Hash`
/// value: the key opened for KEY_QUERY_VALUE, that one value queried, the
/// key closed.
async fn expected_hash<R: super::storedcreds::Registry>(
    reg: &mut R,
    hklm: &R::Key,
    id: &str,
) -> Expect {
    use super::storedcreds::{not_set, KEY_QUERY_VALUE};
    const REG_BINARY: u32 = 3;
    let key = match reg
        .open_key(hklm, &format!(r"{TASKS_KEY}\{id}"), KEY_QUERY_VALUE)
        .await
    {
        Ok(k) => k,
        // No cache entry: a leftover Tree entry.
        Err(e) if not_set(&e) => return Expect::Unmatched,
        Err(_) => return Expect::NoHash,
    };
    let hash = reg.query(&key, "Hash").await;
    reg.close(&key).await;
    match hash {
        // SHA-256 (Windows 10 and Server 2016 on); a CRC32 (4 bytes, older
        // Windows) or anything else can't tie the file to its registration.
        Ok(v) if v.ty == REG_BINARY && v.data.len() == 32 => Expect::Hash(v.data),
        _ => Expect::NoHash,
    }
}

/// Lists Task Scheduler's registered tasks ([`TREE_KEY`]) through `reg`,
/// with each task's expected hash ([`TASKS_KEY`]): Tree keys opened for
/// KEY_ENUMERATE_SUB_KEYS (and KEY_QUERY_VALUE below the root, for `Id`),
/// cache keys for KEY_QUERY_VALUE; only `Id` and `Hash` are ever queried.
/// Returns the paths, and why the list is incomplete when it is (limits,
/// time, a key that couldn't be opened). An error when the list can't be
/// read at all.
pub(crate) async fn registered_tasks<R: super::storedcreds::Registry>(
    reg: &mut R,
    deadline: Instant,
) -> Result<(Registered, Option<String>), String> {
    use super::storedcreds::{not_set, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE};
    let hklm = reg.hklm().await.map_err(|e| words(&e))?;
    let root = match reg.open_key(&hklm, TREE_KEY, KEY_ENUMERATE_SUB_KEYS).await {
        Ok(k) => k,
        Err(e) => {
            reg.close(&hklm).await;
            return Err(words(&e));
        }
    };
    let mut out = Registered::default();
    let (mut seen, mut deep, mut failed, mut names) = (0usize, 0usize, 0usize, 0usize);
    let mut time = false;
    // Tasks whose cache entry is still to be read: (path, Id).
    let mut ids: Vec<(String, String)> = Vec::new();
    // Keys to list, with their path and depth.
    let mut keys = vec![(root, String::new(), 0usize)];
    while let Some((key, rel, depth)) = keys.pop() {
        let mut index = 0u32;
        loop {
            if Instant::now() >= deadline {
                time = true;
                break;
            }
            if seen >= MAX_LISTED {
                break;
            }
            let name = match reg.enum_key(&key, index).await {
                Ok(None) => break,
                Ok(Some(n)) => n,
                Err(_) => {
                    failed += 1;
                    break;
                }
            };
            index += 1;
            seen += 1;
            if !usable(&name) {
                names += 1;
                continue;
            }
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!(r"{rel}\{name}")
            };
            if depth + 1 > MAX_DEPTH {
                deep += 1;
                out.insert(&child, Expect::Unmatched);
                continue;
            }
            let k = match reg
                .open_key(&key, &name, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE)
                .await
            {
                Ok(k) => k,
                Err(_) => {
                    failed += 1;
                    out.insert(&child, Expect::Unmatched);
                    continue;
                }
            };
            // A task's key has an Id; a folder's has none.
            match reg.query(&k, "Id").await {
                Ok(v) => {
                    match task_id(&v) {
                        Some(id) => ids.push((child.clone(), id)),
                        None => out.insert(&child, Expect::Unmatched),
                    }
                    reg.close(&k).await;
                }
                Err(e) if not_set(&e) => {
                    out.insert(&child, Expect::Folder);
                    keys.push((k, child, depth + 1));
                }
                Err(_) => {
                    out.insert(&child, Expect::Unmatched);
                    reg.close(&k).await;
                }
            }
        }
        reg.close(&key).await;
        if time || seen >= MAX_LISTED {
            for (k, _, _) in keys.drain(..) {
                reg.close(&k).await;
            }
        }
    }
    for (path, id) in ids {
        if Instant::now() >= deadline {
            time = true;
            out.insert(&path, Expect::NoHash);
            continue;
        }
        let expect = expected_hash(reg, &hklm, &id).await;
        out.insert(&path, expect);
    }
    reg.close(&hklm).await;
    let count = pathwarden_core::text::count;
    let mut why: Vec<String> = Vec::new();
    if time {
        why.push("ran out of time listing the registered tasks".into());
    }
    if seen >= MAX_LISTED {
        why.push(format!(
            "more than {MAX_LISTED} registered tasks and folders"
        ));
    }
    if deep > 0 {
        why.push(format!(
            "{} of registered tasks deeper than {MAX_DEPTH} levels not listed",
            count(deep, "folder", "folders")
        ));
    }
    if failed > 0 {
        why.push(format!(
            "{} of registered tasks could not be listed",
            count(failed, "key", "keys")
        ));
    }
    if names > 0 {
        why.push(format!(
            "{} of registered tasks not usable",
            count(names, "name", "names")
        ));
    }
    Ok((out, (!why.is_empty()).then(|| why.join("; "))))
}

/// A computer's tasks status with what listing its registered tasks left
/// out (`tree_left`) in front: partial, with both reasons.
pub(crate) fn with_tree_left(mut check: Check, tree_left: Option<String>) -> Check {
    if let Some(why) = tree_left {
        if check.status != CheckStatus::NotCollected {
            check.status = CheckStatus::Partial;
        }
        check.reason = Some(match check.reason.take() {
            Some(r) => format!("{why}; {r}"),
            None => why,
        });
    }
    check
}

/// One computer, over Kerberos: its `cifs/` ticket, the signed SMB
/// session, `C$`, then [`read_tasks`].
pub(crate) async fn read_host(
    host: &str,
    k: &KerberosSignIn,
    domain: &str,
    user: &str,
    until: Instant,
    retry: bool,
) -> (Check, Vec<Stored>) {
    let now = Instant::now();
    if now >= until {
        return (not_collected(OUT_OF_TIME), Vec::new());
    }
    let deadline = (now + PER_HOST).min(until);
    let work = async {
        let mut smb = match super::krbreg::connect(host, &k.ccache, &k.kdc, domain, user).await {
            Ok(s) => s,
            Err(e) => return (not_collected(&words(&e.to_string())), Vec::new()),
        };
        // The registered tasks first, over Remote Registry on the same
        // session's IPC$; then C$.
        let tree = {
            let mut opened = super::krbreg::Registry::open(&mut smb).await;
            let starting = opened.as_ref().is_err_and(|e| {
                e.to_ascii_lowercase()
                    .contains(super::storedcreds::PIPE_NOT_AVAILABLE)
            });
            if starting && retry {
                // Remote Registry was starting.
                drop(opened);
                tokio::time::sleep(super::storedcreds::REGISTRY_START).await;
                opened = super::krbreg::Registry::open(&mut smb).await;
            }
            match opened {
                Ok(mut reg) => registered_tasks(&mut reg, deadline).await,
                Err(e) => Err(format!("Remote Registry: {}", words(&e))),
            }
        };
        let (registered, tree_left) = match tree {
            Ok(t) => t,
            Err(e) => return (tree_unread(&e), Vec::new()),
        };
        if let Err(e) = smb.tree_connect(&format!(r"\\{host}\C$")).await {
            return (
                not_collected(&format!("C$: {}", words(&e.to_string()))),
                Vec::new(),
            );
        }
        let (check, stored) = read_tasks(&mut smb, host, deadline, &registered).await;
        (with_tree_left(check, tree_left), stored)
    };
    // The walk stops itself at the deadline; this is for a call that hangs.
    match tokio::time::timeout(PER_HOST + Duration::from_secs(10), work).await {
        Ok(r) => r,
        Err(_) => (
            not_collected(&format!("no answer within {}s", PER_HOST.as_secs())),
            Vec::new(),
        ),
    }
}

/// The tasks step's plan: who signs in, as which domain and user, and when
/// the step stops.
pub(crate) struct Plan<'a> {
    pub k: &'a KerberosSignIn,
    pub smb_domain: &'a str,
    pub user: &'a str,
    pub until: Instant,
    /// Computers (object IDs) whose Remote Registry the services step
    /// already found unavailable, after its own wait: not waited for again.
    pub registry_down: std::collections::HashSet<String>,
}

/// One computer's tasks read.
pub(crate) struct HostTasks {
    pub id: String,
    pub name: String,
    pub tasks: Check,
    pub stored: Vec<Stored>,
}

/// The tasks step's share of the progress bar, as the services step's.
pub(crate) fn weight(computers: usize, read_weight: f64, read: Duration) -> f64 {
    let expected = (computers as f64 * PER_HOST_ESTIMATE.as_secs_f64() / AT_ONCE as f64)
        .min(STEP_BUDGET.as_secs_f64());
    let read = read.as_secs_f64().max(1.0);
    (read_weight * expected / read).clamp(0.0, 10.0 * read_weight)
}

/// Reads the tasks of every computer the modules reached, over Kerberos.
/// Computers that were skipped or not reached are listed as not collected,
/// with the reason; inactive ones aren't listed.
pub(crate) async fn collect(
    plan: Plan<'_>,
    computers: &mut [Computer],
    skipped: &Skipped,
    tx: &mpsc::Sender<Msg>,
) -> Vec<HostTasks> {
    let Plan {
        k,
        smb_domain,
        user,
        until,
        registry_down,
    } = plan;
    let log = |l: String| {
        let _ = tx.send(Msg::Log(l));
    };
    let mut records: Vec<HostTasks> = Vec::new();
    let mut ask: Vec<(usize, String, bool)> = Vec::new();
    for c in computers.iter_mut() {
        let host = c.properties().name().clone();
        let id = c.object_identifier().clone();
        if host.is_empty() || !c.is_active(EXPIRY_DAYS) {
            continue;
        }
        let retry = !registry_down.contains(&id);
        let mut record = HostTasks {
            id,
            name: host.clone(),
            tasks: Check::default(),
            stored: Vec::new(),
        };
        if let Some(s) = skipped.get(record.id.as_str()) {
            record.tasks = not_collected(&skip_words(s));
        } else if !hosts::reached(c) {
            record.tasks = not_collected("not reached");
        } else {
            ask.push((records.len(), host, retry));
        }
        records.push(record);
    }
    if !ask.is_empty() {
        log(format!(
            "[tasks] reading the scheduled tasks on {} over Kerberos (C$)",
            pathwarden_core::text::count(ask.len(), "computer", "computers")
        ));
    }
    let mut progress = Progress::new(tx.clone(), "Reading scheduled tasks", ask.len());
    let sem = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    let mut set = tokio::task::JoinSet::new();
    let mut pending: std::collections::HashSet<usize> = Default::default();
    for (i, host, retry) in ask {
        pending.insert(i);
        let (sem, k) = (sem.clone(), k.clone());
        let (smb_domain, user) = (smb_domain.to_string(), user.to_string());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let read = read_host(&host, &k, &smb_domain, &user, until, retry).await;
            (i, host, read)
        });
    }
    while let Some(done) = set.join_next().await {
        let Ok((i, host, (check, stored))) = done else {
            continue;
        };
        pending.remove(&i);
        progress.done();
        if let Some(why) = check.reason.as_deref() {
            log(format!("warning: [tasks] {host}: {why}"));
        }
        records[i].tasks = check;
        records[i].stored = stored;
    }
    // A task that never answered (a panic) is not collected, never taken
    // as read.
    for i in pending {
        records[i].tasks = not_collected("the read stopped unexpectedly");
    }
    progress.finish();
    let step = sum_up(&records.iter().map(|r| &r.tasks).collect::<Vec<_>>());
    let found: usize = records.iter().map(|r| r.stored.len()).sum();
    log(format!(
        "[tasks] {} of {} read in full; {} store a domain account's password",
        pathwarden_core::report::num(step.read),
        pathwarden_core::text::count(records.len(), "computer", "computers"),
        pathwarden_core::text::count(found, "scheduled task", "scheduled tasks"),
    ));
    if step.status != CheckStatus::Complete && !records.is_empty() {
        let _ = tx.send(Msg::Warning(format!(
            "Scheduled tasks weren't read on {} of {}, so findings that rest on them can't be \
             confirmed fixed. The collection log names each one.",
            pathwarden_core::report::num(step.failed),
            pathwarden_core::text::count(records.len(), "computer", "computers"),
        )));
    }
    records
}

/// Adds the tasks step's reads to the sidecar: each computer's tasks
/// status and the tasks that store a password, and the step as a whole.
/// A computer the services step didn't list (its reads off or not run) is
/// added with its services not collected, for the sidecar's reason.
pub(crate) fn merge(s: &mut Sidecar, reads: Vec<HostTasks>) {
    let services_why = s
        .services
        .reason
        .clone()
        .unwrap_or_else(|| "not read".into());
    let step = sum_up(&reads.iter().map(|r| &r.tasks).collect::<Vec<_>>());
    for r in reads {
        match s.hosts.iter_mut().find(|h| h.id == r.id) {
            Some(h) => {
                h.tasks = Some(r.tasks);
                h.stored.extend(r.stored);
            }
            None => s.hosts.push(HostRecord {
                id: r.id,
                name: r.name,
                services: not_collected(&services_why),
                tasks: Some(r.tasks),
                stored: r.stored,
            }),
        }
    }
    s.tasks = Some(step);
    s.tasks_turned_off = false;
}

/// Marks the sidecar's tasks step not read, for `why` (`turned_off`: by
/// the switch).
pub(crate) fn not_read(s: &mut Sidecar, why: &str, turned_off: bool) {
    s.tasks = Some(not_collected(why));
    s.tasks_turned_off = turned_off;
}

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tests;
