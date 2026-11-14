//! Reading computers as the signed-in Windows account (Windows only).
//!
//! RustHound-CE's sessions and local groups modules sign in over SMB with
//! NTLM, so they need a user and password. Windows' own calls sign in as
//! the current logon session instead (Kerberos, or NTLM through SSPI), so
//! the same reads need no password:
//!
//! - sessions: NetSessionEnum level 10 (SRVSVC, network connections only,
//!   supporting information), NetWkstaUserEnum level 1 (WKSSVC, logged-on
//!   users; local administrator) and the SIDs under HKEY_USERS over Remote
//!   Registry (WINREG), filling the same three lists the sessions module
//!   fills;
//! - local groups: the members (SIDs) of the BUILTIN aliases the SAMR path
//!   reads, by RID (Administrators 544, Remote Desktop Users 555,
//!   Distributed COM Users 562, Remote Management Users 580), each named on
//!   the computer from its well-known SID, so a localized name doesn't
//!   matter; and the computer's account domain (NetUserModalsGet), so local
//!   accounts are left out as the SAMR path leaves them out;
//! - stored credentials: the accounts its services run as and
//!   the scheduled tasks that store a domain account's password, read as a
//!   Full collection over Kerberos reads them ([`super::storedcreds`],
//!   [`super::tasks`]: the same walks, limits and checks), through Remote
//!   Registry's HKLM (`RegConnectRegistryW`) and the `C$` share by UNC path
//!   instead of Pathwarden's own SMB client. Only `ObjectName`, `Start` and
//!   `Type` of each service, Task Scheduler's `TaskCache` registrations
//!   (`Id`, `Hash`) and each registered task file whose SHA-256 matches its
//!   registration are read; a task file is parsed in memory for its
//!   principal and enabled flag only, then dropped. Never `ImagePath`,
//!   `Parameters`, a task's actions, arguments or description, the LSA
//!   secrets, SAM, DPAPI, Credential Manager or `\pipe\atsvc`.
//!
//! The calls block and can hang, so each computer is read on its own
//! thread with its own time limit, ten at a time, all within one deadline;
//! a thread that overruns is abandoned and its computer reported as not
//! answering in time ([`read_hosts`]). What was read is written into the
//! computers exactly as the modules write it ([`apply`]), so the rest of a
//! retest ([`super::hosts::host_read`], the ingest) is the same either way;
//! the stored credentials come back as the computer's record for
//! `pathwarden-storedcreds.json`.
//!
//! The calls themselves are behind [`HostApi`]: Windows' in [`super::winnet`],
//! fakes in tests. A Full collection as the Windows account can reuse
//! [`read_hosts`] and [`apply`] later.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use dcerpc::rrp::RegValue;
use pathwarden_core::storedcreds::{HostRecord, Stored};
use pathwarden_core::sysvol::Check;
use rusthound_ce::modules::localgroup::types::{group_display_name, group_object_id, ALIASES};
use rusthound_ce::objects::common::{LocalGroup, Member, Session, UserComputerSession, UserRight};
use rusthound_ce::objects::computer::Computer;
use rusthound_ce::objects::user::User;
use smb2_client::DirEntry;

use super::hosts::{kind_of, valid_host, Kind};
use super::storedcreds::{not_collected, words};

/// A Win32 or NetAPI error code.
pub(crate) type Code = u32;

/// HKLM in a [`HostRegistry`]: the key its other keys are opened under.
pub(crate) const HKLM: usize = 0;

/// One computer's HKLM over Remote Registry, blocking. Keys are numbers
/// the registry hands out ([`HKLM`] the root). Errors carry the Win32 code
/// as `(rc=N)`, which [`words`] and [`super::storedcreds::not_set`] read.
pub(crate) trait HostRegistry: Send {
    /// Opens `subkey` under `parent` for `access` (and nothing more).
    fn open_key(&mut self, parent: usize, subkey: &str, access: u32) -> Result<usize, String>;
    /// The name of `key`'s subkey at `index`; `None` past the last.
    fn enum_key(&mut self, key: usize, index: u32) -> Result<Option<String>, String>;
    /// One named value of `key`.
    fn query(&mut self, key: usize, value: &str) -> Result<RegValue, String>;
    /// Closes `key` (closing [`HKLM`] does nothing: it lives with the
    /// connection).
    fn close(&mut self, key: usize);
}

/// One computer's `C$`, blocking. Paths are relative to the share's root.
pub(crate) trait HostShare: Send {
    /// A folder's entries (at most `max`), and whether there were more.
    fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String>;
    /// A file's first `max` bytes, and whether it goes on.
    fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String>;
}

/// A [`HostRegistry`] as the services and tasks walks take a registry.
struct RegOf<'a>(&'a mut dyn HostRegistry);

impl super::storedcreds::Registry for RegOf<'_> {
    type Key = usize;
    async fn hklm(&mut self) -> Result<usize, String> {
        Ok(HKLM)
    }
    async fn open_key(
        &mut self,
        parent: &usize,
        subkey: &str,
        access: u32,
    ) -> Result<usize, String> {
        self.0.open_key(*parent, subkey, access)
    }
    async fn enum_key(&mut self, key: &usize, index: u32) -> Result<Option<String>, String> {
        self.0.enum_key(*key, index)
    }
    async fn query(&mut self, key: &usize, value: &str) -> Result<RegValue, String> {
        self.0.query(*key, value)
    }
    async fn close(&mut self, key: &usize) {
        self.0.close(*key)
    }
}

/// A [`HostShare`] as the tasks walk takes a share.
struct ShareOf<'a>(&'a mut dyn HostShare);

impl super::tasks::Share for ShareOf<'_> {
    async fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String> {
        self.0.list(path, max)
    }
    async fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        self.0.read(path, max)
    }
}

/// Windows' calls for reading one computer, by its DNS name. Each blocks.
pub(crate) trait HostApi: Send + Sync + 'static {
    /// Whether the computer answers on port 445 within `timeout`.
    fn reachable(&self, host: &str, timeout: Duration) -> bool;
    /// NetSessionEnum level 10: the user name of each network session.
    fn net_sessions(&self, host: &str) -> Result<Vec<String>, Code>;
    /// NetWkstaUserEnum level 1: (logon domain, user name) of each
    /// logged-on user.
    fn logged_on(&self, host: &str) -> Result<Vec<(String, String)>, Code>;
    /// The subkeys of HKEY_USERS, over Remote Registry.
    fn registry_users(&self, host: &str) -> Result<Vec<String>, Code>;
    /// NetUserModalsGet level 2: the computer's account domain (its name
    /// and SID): the computer's own on a member, the domain's on a DC.
    fn account_domain(&self, host: &str) -> Result<(String, String), Code>;
    /// The members (SIDs) of the BUILTIN alias `S-1-5-32-<rid>`.
    fn alias_members(&self, host: &str, rid: u32) -> Result<Vec<String>, Code>;
    /// Remote Registry's HKLM (`RegConnectRegistryW`): the services' keys
    /// and Task Scheduler's registrations are read through it.
    fn services(&self, host: &str) -> Result<Box<dyn HostRegistry>, Code>;
    /// The `C$` share by UNC path: the task files are read through it.
    fn tasks(&self, host: &str) -> Result<Box<dyn HostShare>, Code>;
    /// Whether Windows gets the computer's `cifs/` Kerberos ticket
    /// (`winkrb`); the reason recorded for it when not. Asked before its
    /// services or tasks are read: without one, neither is.
    fn cifs_ticket(&self, host: &str) -> Result<(), String>;
}

/// A code in words: `rc=53 (unreachable)`. Told from the code
/// ([`kind_of`]), never from the words around it.
pub(crate) fn code_words(code: Code) -> String {
    let words = match kind_of(code) {
        Kind::AccessDenied => "access denied",
        Kind::Unreachable => "unreachable",
        Kind::SignIn => "logon failure",
        Kind::Timeout => "timed out",
        Kind::Other => "error",
    };
    format!("rc={code} ({words})")
}

/// A failed call's reason: `HOST CALL: rc=5 (access denied)`.
pub(crate) fn failure(host: &str, call: &str, code: Code) -> String {
    format!("{host} {call}: {}", code_words(code))
}

/// One call's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call<T> {
    /// Not asked for.
    NotRun,
    /// Asked for, no answer yet.
    Pending,
    Done(T),
    /// The reason, as written to `FailureReason`.
    Failed(String),
}

impl<T> Call<T> {
    fn pending(asked: bool) -> Self {
        if asked {
            Call::Pending
        } else {
            Call::NotRun
        }
    }

    fn fail_pending(&mut self, why: &str) {
        if matches!(self, Call::Pending) {
            *self = Call::Failed(why.to_string());
        }
    }

    fn from_result(host: &str, call: &str, r: Result<T, Code>) -> Self {
        match r {
            Ok(v) => Call::Done(v),
            Err(code) => Call::Failed(failure(host, call, code)),
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Call::Failed(why) => Some(why),
            _ => None,
        }
    }
}

/// A computer to read, by the name the directory gave it (`dNSHostName`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostAsk {
    pub name: String,
    pub sessions: bool,
    pub local_groups: bool,
    /// The accounts its services run as.
    pub services: bool,
    /// Its scheduled tasks that store a password.
    pub tasks: bool,
}

/// What one stored credentials read gave: how far it got, and what stores
/// a domain account's password.
pub(crate) type StoredRead = (Check, Vec<Stored>);

/// What was read of one computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostFound {
    pub name: String,
    /// NetSessionEnum: user names.
    pub srvsvc: Call<Vec<String>>,
    /// NetWkstaUserEnum: (logon domain, user name).
    pub wkssvc: Call<Vec<(String, String)>>,
    /// HKEY_USERS subkeys.
    pub winreg: Call<Vec<String>>,
    /// The account domain (name, SID).
    pub account: Call<(String, String)>,
    /// One per alias of [`ALIASES`], by RID, when local groups were asked.
    pub aliases: Vec<(u32, Call<Vec<String>>)>,
    /// The services read, when asked.
    pub services: Call<StoredRead>,
    /// The scheduled tasks read, when asked.
    pub tasks: Call<StoredRead>,
    /// What stopped the whole computer (unreachable, timed out), first.
    pub errors: Vec<String>,
}

impl HostFound {
    fn new(ask: &HostAsk) -> Self {
        Self {
            name: ask.name.clone(),
            srvsvc: Call::pending(ask.sessions),
            wkssvc: Call::pending(ask.sessions),
            winreg: Call::pending(ask.sessions),
            account: Call::pending(ask.local_groups),
            aliases: if ask.local_groups {
                ALIASES.iter().map(|a| (a.rid, Call::Pending)).collect()
            } else {
                Vec::new()
            },
            services: Call::pending(ask.services),
            tasks: Call::pending(ask.tasks),
            errors: Vec::new(),
        }
    }

    /// Every call without an answer fails with `why`; finished ones stay.
    fn fail_pending(&mut self, why: &str) {
        let before = self.pending();
        self.srvsvc.fail_pending(why);
        self.wkssvc.fail_pending(why);
        self.winreg.fail_pending(why);
        self.account.fail_pending(why);
        for (_, c) in &mut self.aliases {
            c.fail_pending(why);
        }
        self.services.fail_pending(why);
        self.tasks.fail_pending(why);
        if before {
            self.errors.push(why.to_string());
        }
    }

    fn pending(&self) -> bool {
        matches!(self.srvsvc, Call::Pending)
            || matches!(self.wkssvc, Call::Pending)
            || matches!(self.winreg, Call::Pending)
            || matches!(self.account, Call::Pending)
            || self.aliases.iter().any(|(_, c)| matches!(c, Call::Pending))
            || matches!(self.services, Call::Pending)
            || matches!(self.tasks, Call::Pending)
    }

    fn take(&mut self, part: Part) {
        let host = self.name.clone();
        match part {
            Part::Unreachable => self.fail_pending(&format!("{host}: 445/tcp unreachable")),
            Part::Srvsvc(r) => self.srvsvc = Call::from_result(&host, "SRVSVC", r),
            Part::Wkssvc(r) => self.wkssvc = Call::from_result(&host, "WKSSVC", r),
            Part::Winreg(r) => self.winreg = Call::from_result(&host, "WINREG", r),
            Part::Account(r) => self.account = Call::from_result(&host, "machine SID", r),
            Part::Alias(rid, r) => {
                if let Some((_, c)) = self.aliases.iter_mut().find(|(x, _)| *x == rid) {
                    *c = Call::from_result(&host, &format!("alias {rid}"), r);
                }
            }
            Part::Services(r) => self.services = Call::Done(r),
            Part::Tasks(r) => self.tasks = Call::Done(r),
            Part::Done => self.fail_pending(&format!("{host}: not read")),
        }
    }

    /// The local groups' errors, as [`super::hosts::host_read`] takes them
    /// (`HOST: ...`, `HOST alias 544: ...`): the computer's own first, then
    /// the groups', then the account domain's.
    pub(crate) fn group_errors(&self) -> Vec<String> {
        if self.aliases.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<String> = self.errors.clone();
        for (_, c) in &self.aliases {
            if let Some(e) = c.error() {
                if !out.iter().any(|o| o == e) {
                    out.push(e.to_string());
                }
            }
        }
        if let Some(e) = self.account.error() {
            if !out.iter().any(|o| o == e) {
                out.push(e.to_string());
            }
        }
        out
    }
}

/// One finished call of one computer, sent from its thread.
enum Part {
    Unreachable,
    Srvsvc(Result<Vec<String>, Code>),
    Wkssvc(Result<Vec<(String, String)>, Code>),
    Winreg(Result<Vec<String>, Code>),
    Account(Result<(String, String), Code>),
    Alias(u32, Result<Vec<String>, Code>),
    Services(StoredRead),
    Tasks(StoredRead),
    /// The thread is finished.
    Done,
}

/// How long and how many.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// The port 445 check.
    pub port: Duration,
    /// One computer, from the start of its thread.
    pub per_host: Duration,
    /// Computers read at once.
    pub at_once: usize,
    /// Nothing is waited for after this.
    pub deadline: Instant,
}

/// The port 445 check, as the modules make it.
pub(crate) const PORT_TIMEOUT: Duration = Duration::from_millis(1_500);
/// One computer: the port check, then its sessions and local groups (the
/// two modules give eight seconds each).
pub(crate) const HOST_TIMEOUT: Duration = Duration::from_secs(18);
/// Computers read at once, as the modules do.
pub(crate) const AT_ONCE: usize = 10;
/// More time for a computer whose services, or whose tasks, are read: each
/// walk's own limit in a Full collection ([`super::storedcreds::PER_HOST`],
/// [`super::tasks::PER_HOST`]).
pub(crate) const STORED_TIME: Duration = super::storedcreds::PER_HOST;
/// The walks stop this long before their computer's thread is abandoned,
/// so what they read still comes back.
const STORED_MARGIN: Duration = Duration::from_secs(2);
/// Remote Registry still starting (ERROR_PIPE_BUSY, RPC_S_SERVER_UNAVAILABLE):
/// asked once more after [`super::storedcreds::REGISTRY_START`].
const REGISTRY_STARTING: [Code; 2] = [231, 1722];

/// How long `ask`'s computer may take, from the start of its thread.
fn time_for(ask: &HostAsk, per_host: Duration) -> Duration {
    let walks = u32::from(ask.services) + u32::from(ask.tasks);
    per_host + STORED_TIME * walks
}

impl Limits {
    pub(crate) fn until(deadline: Instant) -> Self {
        Self {
            port: PORT_TIMEOUT,
            per_host: HOST_TIMEOUT,
            at_once: AT_ONCE,
            deadline,
        }
    }
}

/// Host-read threads alive in this process: reading, or abandoned and
/// still waiting for Windows.
pub(crate) static ALIVE: AtomicUsize = AtomicUsize::new(0);
/// With more threads than this still alive, no new reads start.
pub(crate) const MAX_WAITING: usize = 50;
/// Why no computer is read while too many earlier reads are still alive.
pub(crate) const STILL_WAITING: &str =
    "Earlier reads of computers are still waiting for Windows. Try again in a few minutes.";

/// Counts one thread in both counters while it lives (and on a panic).
struct Alive {
    process: &'static AtomicUsize,
    mine: Arc<AtomicUsize>,
}

impl Alive {
    fn new(process: &'static AtomicUsize, mine: &Arc<AtomicUsize>) -> Self {
        process.fetch_add(1, Ordering::SeqCst);
        mine.fetch_add(1, Ordering::SeqCst);
        Self {
            process,
            mine: mine.clone(),
        }
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        self.process.fetch_sub(1, Ordering::SeqCst);
        self.mine.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One computer's calls, on its own thread; each answer is sent as it
/// comes, so a timeout keeps the ones that finished.
/// The stored credentials walks stop by `until`.
fn work(api: &dyn HostApi, ask: &HostAsk, port: Duration, until: Instant, send: &dyn Fn(Part)) {
    let host = ask.name.as_str();
    if !api.reachable(host, port) {
        send(Part::Unreachable);
        return;
    }
    if ask.sessions {
        send(Part::Srvsvc(api.net_sessions(host)));
        send(Part::Wkssvc(api.logged_on(host)));
        send(Part::Winreg(api.registry_users(host)));
    }
    if ask.local_groups {
        send(Part::Account(api.account_domain(host)));
        for a in ALIASES {
            send(Part::Alias(a.rid, api.alias_members(host, a.rid)));
        }
    }
    if ask.services || ask.tasks {
        stored(api, ask, until, send);
    }
}

/// Remote Registry's HKLM on `host`, asked once more when it was still
/// starting (and there is time); the reason in words when it can't be had.
fn connect(api: &dyn HostApi, host: &str, until: Instant) -> Result<Box<dyn HostRegistry>, String> {
    let wait = super::storedcreds::REGISTRY_START;
    let mut r = api.services(host);
    if matches!(&r, Err(c) if REGISTRY_STARTING.contains(c)) && Instant::now() + wait < until {
        std::thread::sleep(wait);
        r = api.services(host);
    }
    r.map_err(|code| format!("Remote Registry: {}", words(&code_words(code))))
}

/// The services and scheduled tasks of one computer, read as a Full
/// collection reads them over Kerberos ([`super::storedcreds::read_services`],
/// [`super::tasks::registered_tasks`], [`super::tasks::read_tasks`]: the
/// same values, limits and checks) through Windows' Remote Registry and
/// UNC paths. Each walk gets [`STORED_TIME`], within `until`. The walks run
/// on a runtime of this thread's own: a task file is parsed on its
/// blocking pool, as in a collection.
fn stored(api: &dyn HostApi, ask: &HostAsk, until: Instant, send: &dyn Fn(Part)) {
    use super::tasks;
    let host = ask.name.as_str();
    let fail = |why: &str| {
        if ask.services {
            send(Part::Services((not_collected(why), Vec::new())));
        }
        if ask.tasks {
            send(Part::Tasks((not_collected(why), Vec::new())));
        }
    };
    // Kerberos first, whatever the sessions allowed: no ticket,
    // nothing read, and Windows never signs in for these reads.
    if let Err(why) = api.cifs_ticket(host) {
        fail(&why);
        return;
    }
    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(e) => {
            fail(&format!("not read: {e}"));
            return;
        }
    };
    let walk_until = || (Instant::now() + STORED_TIME).min(until);
    let mut reg = connect(api, host, until);
    if ask.services {
        let read = match &mut reg {
            Ok(r) => rt.block_on(super::storedcreds::read_services(
                &mut RegOf(r.as_mut()),
                host,
                walk_until(),
            )),
            Err(why) => (not_collected(why), Vec::new()),
        };
        send(Part::Services(read));
    }
    if ask.tasks {
        let deadline = walk_until();
        // Task Scheduler's registrations first, then only the files they
        // name and whose hash matches.
        let tree = match &mut reg {
            Ok(r) => rt.block_on(tasks::registered_tasks(&mut RegOf(r.as_mut()), deadline)),
            Err(why) => Err(why.clone()),
        };
        let read = match tree {
            Err(why) => (tasks::tree_unread(&why), Vec::new()),
            Ok((registered, left)) => match api.tasks(host) {
                Err(code) => (
                    not_collected(&format!("C$: {}", words(&code_words(code)))),
                    Vec::new(),
                ),
                Ok(mut share) => {
                    let (check, found) = rt.block_on(tasks::read_tasks(
                        &mut ShareOf(share.as_mut()),
                        host,
                        deadline,
                        &registered,
                    ));
                    (tasks::with_tree_left(check, left), found)
                }
            },
        };
        send(Part::Tasks(read));
    }
}

/// Reads `asks` with `api`: each computer on its own thread, at most
/// `limits.at_once` at a time, each within `limits.per_host`, all within
/// `limits.deadline`. A computer whose thread overruns is left to finish
/// on its own (its answers are ignored) and reported as timed out; one not
/// started by the deadline, as timed out before it was contacted. One
/// [`HostFound`] per ask, in order.
///
/// Abandoned threads count against `limits.at_once` until they end, so
/// this read never has more threads alive than that. `alive` counts the
/// process's host-read threads ([`ALIVE`]); with more than
/// [`MAX_WAITING`] of them still alive nothing is read ([`STILL_WAITING`]).
pub(crate) fn read_hosts(
    api: Arc<dyn HostApi>,
    asks: &[HostAsk],
    limits: Limits,
    alive: &'static AtomicUsize,
) -> Result<Vec<HostFound>, String> {
    if alive.load(Ordering::SeqCst) > MAX_WAITING {
        return Err(STILL_WAITING.into());
    }
    let mut found: Vec<HostFound> = asks.iter().map(HostFound::new).collect();
    let (tx, rx) = mpsc::channel::<(usize, Part)>();
    // Running computers and when each must have finished.
    let mut running: HashMap<usize, Instant> = HashMap::new();
    // This read's threads alive, running or abandoned.
    let mine = Arc::new(AtomicUsize::new(0));
    let mut next = 0;
    loop {
        let now = Instant::now();
        while mine.load(Ordering::SeqCst) < limits.at_once.max(1)
            && next < asks.len()
            && now < limits.deadline
        {
            let i = next;
            next += 1;
            let ask = asks[i].clone();
            if !valid_host(&ask.name) {
                let why = format!("{}: not a computer name that can be contacted", ask.name);
                found[i].fail_pending(&why);
                continue;
            }
            let (api, tx) = (api.clone(), tx.clone());
            let counted = Alive::new(alive, &mine);
            let by = (now + time_for(&ask, limits.per_host)).min(limits.deadline);
            let until = by.checked_sub(STORED_MARGIN).unwrap_or(by);
            let spawned = std::thread::Builder::new()
                .name("pathwarden-host-read".into())
                .spawn(move || {
                    let send = |p: Part| {
                        let _ = tx.send((i, p));
                    };
                    work(api.as_ref(), &ask, limits.port, until, &send);
                    // Uncounted first, so a read waiting for a free place
                    // sees it when Done wakes it.
                    drop(counted);
                    send(Part::Done);
                });
            match spawned {
                Ok(_) => {
                    running.insert(i, now + time_for(&asks[i], limits.per_host));
                }
                Err(e) => found[i].fail_pending(&format!("{}: not read: {e}", asks[i].name)),
            }
        }
        if running.is_empty() && (next >= asks.len() || now >= limits.deadline) {
            break;
        }
        let until = running
            .values()
            .copied()
            .min()
            .unwrap_or(limits.deadline)
            .min(limits.deadline);
        match rx.recv_timeout(until.saturating_duration_since(now)) {
            // Answers from an abandoned thread come too late.
            Ok((i, part)) if running.contains_key(&i) => {
                let done = matches!(part, Part::Done);
                found[i].take(part);
                if done {
                    running.remove(&i);
                }
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            // `tx` is held here, so this doesn't happen.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Whoever is past their limit, answers arriving or not.
        let now = Instant::now();
        let over: Vec<usize> = running
            .iter()
            .filter(|(_, &by)| by <= now || limits.deadline <= now)
            .map(|(&i, _)| i)
            .collect();
        for i in over {
            running.remove(&i);
            let why = format!("{}: per-host timeout", asks[i].name);
            found[i].fail_pending(&why);
        }
    }
    for (i, f) in found.iter_mut().enumerate().skip(next) {
        let why = format!("{}: timed out before it was contacted", asks[i].name);
        f.fail_pending(&why);
    }
    Ok(found)
}

/// User name (bare or `SAM@DOMAIN`, upper case) to SID, from the users the
/// directory gave, as the sessions module resolves names.
pub(crate) struct SidIndex {
    by_name: HashMap<String, String>,
    domain: String,
}

impl SidIndex {
    pub(crate) fn new(users: &[User], domain: &str) -> Self {
        let mut by_name = HashMap::with_capacity(users.len() * 2);
        for u in users {
            let sid = u.object_identifier().clone();
            if sid.is_empty() {
                continue;
            }
            let upn = u.properties().name().to_uppercase();
            if let Some(sam) = upn.split('@').next() {
                by_name
                    .entry(sam.to_string())
                    .or_insert_with(|| sid.clone());
            }
            by_name.insert(upn, sid);
        }
        Self {
            by_name,
            domain: domain.to_uppercase(),
        }
    }

    /// The SID of `DOMAIN\user`, `DOMAIN/user` or `user`; none for an
    /// empty, `?` or machine (`$`) name or one the directory didn't give.
    pub(crate) fn resolve(&self, raw: &str) -> Option<String> {
        let bare = raw.rsplit(['\\', '/']).next().unwrap_or(raw).trim();
        if bare.is_empty() || bare == "?" || bare.ends_with('$') {
            return None;
        }
        let sam = bare.to_uppercase();
        let upn = format!("{sam}@{}", self.domain);
        self.by_name
            .get(&upn)
            .or_else(|| self.by_name.get(&sam))
            .cloned()
    }
}

/// A user's profile key under HKEY_USERS (a domain or local account's SID,
/// not its `_Classes` key or a service's).
fn profile_sid(key: &str) -> bool {
    key.starts_with("S-1-5-21-") && !key.to_ascii_lowercase().ends_with("_classes")
}

/// Whether `member` is an account of the domain `prefix` (`prefix-RID`).
fn is_under(member: &str, prefix: &str) -> bool {
    member.len() > prefix.len() + 1
        && member[..prefix.len()].eq_ignore_ascii_case(prefix)
        && member.as_bytes()[prefix.len()] == b'-'
}

/// The domain part of an account SID (`S-1-5-21-a-b-c` of `...-c-1001`).
fn domain_of(sid: &str) -> Option<&str> {
    sid.rsplit_once('-').map(|(d, _)| d)
}

fn set_status<T>(s: &mut Session, call: &Call<T>) {
    match call {
        Call::NotRun => {}
        Call::Done(_) => {
            *s.collected_mut() = true;
            *s.failure_reason_mut() = None;
        }
        Call::Failed(why) => {
            *s.collected_mut() = false;
            *s.failure_reason_mut() = Some(why.clone());
        }
        Call::Pending => {
            *s.collected_mut() = false;
            *s.failure_reason_mut() = Some("not read".into());
        }
    }
}

fn link(user_sid: String, computer_sid: &str) -> UserComputerSession {
    let mut l = UserComputerSession::new();
    *l.user_sid_mut() = user_sid;
    *l.computer_sid_mut() = computer_sid.to_string();
    l
}

fn push_links(s: &mut Session, sids: impl IntoIterator<Item = String>, computer_sid: &str) {
    let mut seen = BTreeSet::new();
    for sid in sids {
        if seen.insert(sid.clone()) {
            s.results_mut().push(link(sid, computer_sid));
        }
    }
}

/// Writes what was read of `c` into it, as RustHound-CE's sessions and
/// local groups modules write it: each session list collected only when
/// its call answered (names resolved with `users`, as the module does,
/// SRVSVC's on this computer as the module puts them), and per alias a
/// local group in SharpHound's two forms (on a DC, the domain's BUILTIN
/// group; on a member, `<computer SID>-<RID>` without its local accounts),
/// with the Remote Desktop logon right SharpHound assumes. `domain` is the
/// collected domain.
///
/// When its services or tasks were asked, returns the computer's record
/// for `pathwarden-storedcreds.json` ([`stored_record`]).
pub(crate) fn apply(
    c: &mut Computer,
    f: &HostFound,
    users: &SidIndex,
    sid_type: &HashMap<String, String>,
    domain: &str,
) -> Option<HostRecord> {
    let record = stored_record(c, f);
    apply_hosts(c, f, users, sid_type, domain);
    record
}

/// A stored credentials read's outcome: as read, or not collected with why
/// (the computer didn't answer, the thread ran out of time).
fn stored_part(call: &Call<StoredRead>) -> Option<StoredRead> {
    match call {
        Call::NotRun => None,
        Call::Done(r) => Some(r.clone()),
        Call::Failed(why) => Some((not_collected(why), Vec::new())),
        Call::Pending => Some((not_collected("not read"), Vec::new())),
    }
}

/// `c`'s record for `pathwarden-storedcreds.json`, as a Full collection
/// writes it: each part's status and what stores a domain account's
/// password. A part not asked is recorded as turned off (the collection's
/// switch). `None` when neither was asked.
pub(crate) fn stored_record(c: &Computer, f: &HostFound) -> Option<HostRecord> {
    let services = stored_part(&f.services);
    let tasks = stored_part(&f.tasks);
    if services.is_none() && tasks.is_none() {
        return None;
    }
    let (services, mut stored) =
        services.unwrap_or_else(|| (not_collected(super::storedcreds::TURNED_OFF), Vec::new()));
    let (tasks, task_stored) =
        tasks.unwrap_or_else(|| (not_collected(super::tasks::TURNED_OFF), Vec::new()));
    stored.extend(task_stored);
    Some(HostRecord {
        id: c.object_identifier().clone(),
        name: f.name.clone(),
        services,
        tasks: Some(tasks),
        stored,
    })
}

/// [`apply`]'s sessions and local groups.
fn apply_hosts(
    c: &mut Computer,
    f: &HostFound,
    users: &SidIndex,
    sid_type: &HashMap<String, String>,
    domain: &str,
) {
    let computer_sid = c.object_identifier().clone();
    if let Call::Done(names) = &f.srvsvc {
        let sids = names.iter().filter_map(|n| users.resolve(n));
        push_links(c.sessions_mut(), sids, &computer_sid);
    }
    set_status(c.sessions_mut(), &f.srvsvc);
    if let Call::Done(users_on) = &f.wkssvc {
        let sids = users_on.iter().filter_map(|(_, n)| users.resolve(n));
        push_links(c.privileged_sessions_mut(), sids, &computer_sid);
    }
    set_status(c.privileged_sessions_mut(), &f.wkssvc);
    if let Call::Done(keys) = &f.winreg {
        let sids = keys.iter().filter(|k| profile_sid(k)).cloned();
        push_links(c.registry_sessions_mut(), sids, &computer_sid);
    }
    set_status(c.registry_sessions_mut(), &f.winreg);

    if f.aliases.is_empty() {
        return;
    }
    // A DC's account domain is the domain itself (its SID the prefix of
    // the computer's own): nothing to leave out, and its groups are the
    // domain's BUILTIN groups.
    let own_domain = domain_of(&computer_sid);
    let machine = match &f.account {
        Call::Done((_, sid)) => Some(sid.as_str()),
        _ => None,
    };
    let is_dc = *c.properties().get_is_dc()
        || machine.is_some_and(|m| own_domain.is_some_and(|d| m.eq_ignore_ascii_case(d)));
    let local = machine.filter(|_| !is_dc);
    let host = c.properties().name().clone();
    for (rid, call) in &f.aliases {
        let Some(alias) = ALIASES.iter().find(|a| a.rid == *rid) else {
            continue;
        };
        let mut g = LocalGroup::new();
        *g.object_identifier_mut() = group_object_id(*rid, domain, is_dc, &computer_sid);
        *g.name_mut() = group_display_name(alias.name, &host, is_dc);
        match call {
            Call::Done(members) => {
                *g.collected_mut() = true;
                for sid in members {
                    if local.is_some_and(|m| is_under(sid, m)) {
                        continue;
                    }
                    let mut m = Member::new();
                    *m.object_identifier_mut() = sid.clone();
                    *m.object_type_mut() =
                        sid_type.get(sid).cloned().unwrap_or_else(|| "Base".into());
                    g.results_mut().push(m);
                }
            }
            other => {
                *g.collected_mut() = false;
                *g.failure_reason_mut() = Some(other.error().unwrap_or("not read").to_string());
            }
        }
        c.local_groups_mut().push(g);
    }
    c.users_rights_mut()
        .push(rdp_right(&computer_sid, domain, is_dc));
}

/// SeRemoteInteractiveLogonRight for Administrators and Remote Desktop
/// Users, which SharpHound (and the local groups module) assume on every
/// computer.
fn rdp_right(computer_sid: &str, domain: &str, is_dc: bool) -> UserRight {
    let (ty, ids) = if is_dc {
        let d = domain.to_uppercase();
        (
            "Group",
            [format!("{d}-S-1-5-32-544"), format!("{d}-S-1-5-32-555")],
        )
    } else {
        (
            "ADLocalGroup",
            [format!("{computer_sid}-544"), format!("{computer_sid}-555")],
        )
    };
    let mut right = UserRight::new();
    *right.privilege_mut() = "SeRemoteInteractiveLogonRight".into();
    *right.collected_mut() = true;
    for id in ids {
        let mut m = Member::new();
        *m.object_identifier_mut() = id;
        *m.object_type_mut() = ty.into();
        right.results_mut().push(m);
    }
    right
}

// The services and scheduled tasks read as the Windows account:
// a fake registry and `C$`, with the Kerberos walks' cases.
#[cfg(test)]
#[path = "winhosts_stored_tests.rs"]
mod stored_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const DOMAIN_SID: &str = "S-1-5-21-1000-2000-3000";
    const MACHINE_SID: &str = "S-1-5-21-7-8-9";

    /// A fake: answers per host from a table, sleeping first where told
    /// to (to hang), and counts the calls.
    #[derive(Default)]
    struct Fake {
        down: Vec<&'static str>,
        hang: Vec<(&'static str, Duration)>,
        denied: Vec<&'static str>,
        dc: Vec<&'static str>,
        calls: AtomicUsize,
        running: AtomicUsize,
        most: AtomicUsize,
        seen: Mutex<Vec<String>>,
    }

    impl Fake {
        fn call(&self, host: &str) -> Result<(), Code> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(host.to_string());
            if let Some((_, d)) = self.hang.iter().find(|(h, _)| *h == host) {
                std::thread::sleep(*d);
            }
            if self.denied.contains(&host) {
                return Err(5);
            }
            Ok(())
        }
    }

    impl HostApi for Fake {
        fn reachable(&self, host: &str, _: Duration) -> bool {
            let n = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            self.running.fetch_sub(1, Ordering::SeqCst);
            !self.down.contains(&host)
        }
        fn net_sessions(&self, host: &str) -> Result<Vec<String>, Code> {
            self.call(host).map(|_| vec!["alice".into()])
        }
        fn logged_on(&self, host: &str) -> Result<Vec<(String, String)>, Code> {
            self.call(host).map(|_| {
                vec![
                    ("CONTOSO".into(), "alice".into()),
                    ("CONTOSO".into(), "alice".into()),
                    ("CONTOSO".into(), "WS1$".into()),
                ]
            })
        }
        fn registry_users(&self, host: &str) -> Result<Vec<String>, Code> {
            self.call(host).map(|_| {
                vec![
                    ".DEFAULT".into(),
                    "S-1-5-18".into(),
                    format!("{DOMAIN_SID}-1105"),
                    format!("{DOMAIN_SID}-1105_Classes"),
                ]
            })
        }
        fn account_domain(&self, host: &str) -> Result<(String, String), Code> {
            self.call(host)?;
            Ok(if self.dc.contains(&host) {
                ("CONTOSO".into(), DOMAIN_SID.into())
            } else {
                ("WS1".into(), MACHINE_SID.into())
            })
        }
        fn alias_members(&self, host: &str, rid: u32) -> Result<Vec<String>, Code> {
            self.call(host)?;
            if rid == 580 {
                // Not on this (older) computer.
                return Err(1332);
            }
            Ok(vec![
                format!("{DOMAIN_SID}-512"),
                format!("{MACHINE_SID}-500"),
                "S-1-5-4".into(),
            ])
        }
        // These tests read no stored credentials (`winhosts_stored_tests`
        // does): Remote Registry and C$ aren't there.
        fn services(&self, host: &str) -> Result<Box<dyn HostRegistry>, Code> {
            self.call(host)?;
            Err(2)
        }
        fn tasks(&self, host: &str) -> Result<Box<dyn HostShare>, Code> {
            self.call(host)?;
            Err(53)
        }
        fn cifs_ticket(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn ask(name: &str) -> HostAsk {
        HostAsk {
            name: name.into(),
            sessions: true,
            local_groups: true,
            ..Default::default()
        }
    }

    fn limits(per_host: Duration, overall: Duration) -> Limits {
        Limits {
            port: PORT_TIMEOUT,
            per_host,
            at_once: AT_ONCE,
            deadline: Instant::now() + overall,
        }
    }

    /// [`read_hosts`] with a counter of its own (tests run side by side).
    fn read(api: Arc<dyn HostApi>, asks: &[HostAsk], limits: Limits) -> Vec<HostFound> {
        read_hosts(api, asks, limits, Box::leak(Box::new(AtomicUsize::new(0)))).unwrap()
    }

    /// Abandoned threads keep their place until they end: a read never has
    /// more than `at_once` threads alive, and with too many still alive in
    /// the process no new read starts.
    #[test]
    fn abandoned_threads_are_counted_until_they_end() {
        let hung: Vec<&'static str> = (0..4)
            .map(|i| &*Box::leak(format!("HUNG{i}.X.LOCAL").into_boxed_str()))
            .collect();
        let fake = Arc::new(Fake {
            // Each of the nine calls hangs, so a thread lives about 2.7 s.
            hang: hung
                .iter()
                .map(|h| (*h, Duration::from_millis(300)))
                .collect(),
            ..Default::default()
        });
        let alive: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        let mut asks: Vec<HostAsk> = hung.iter().map(|h| ask(h)).collect();
        asks.push(ask("WS1.X.LOCAL"));
        let mut l = limits(Duration::from_millis(200), Duration::from_millis(900));
        l.at_once = 2;
        let started = Instant::now();
        let found = read_hosts(fake.clone(), &asks, l, alive).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        // The two hung threads held both places until the deadline: the
        // rest never started.
        assert!(fake.most.load(Ordering::SeqCst) <= 2);
        assert_eq!(found[0].errors, ["HUNG0.X.LOCAL: per-host timeout"]);
        assert_eq!(found[1].errors, ["HUNG1.X.LOCAL: per-host timeout"]);
        for f in &found[2..] {
            assert!(
                f.errors[0].ends_with("timed out before it was contacted"),
                "{f:?}"
            );
        }
        // Still alive in the process, until they end.
        assert_eq!(alive.load(Ordering::SeqCst), 2);
        let waiting = Instant::now();
        while alive.load(Ordering::SeqCst) > 0 && waiting.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(alive.load(Ordering::SeqCst), 0);

        // Too many still alive: nothing is contacted.
        let busy: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(MAX_WAITING + 1)));
        let fake = Arc::new(Fake::default());
        let err = read_hosts(fake.clone(), &[ask("WS1.X.LOCAL")], l, busy).unwrap_err();
        assert_eq!(err, STILL_WAITING);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        assert!(fake.seen.lock().unwrap().is_empty());
    }

    /// A host name says nothing about the error: the code does.
    #[test]
    fn host_names_dont_change_the_reason() {
        use super::super::hosts::{error_kind, reason_on};
        for host in [
            "DNS01.CONTOSO.LOCAL",
            "CONNECT-GW.CONTOSO.LOCAL",
            "SRV445.CONTOSO.LOCAL",
            "TIMEOUT.CONTOSO.LOCAL",
            "KERBEROS1.CONTOSO.LOCAL",
            "ACCESS-DENIED.CONTOSO.LOCAL",
        ] {
            let denied = failure(host, "WKSSVC", 5);
            assert_eq!(error_kind(&denied), "access denied", "{denied}");
            assert_eq!(
                reason_on(host, &denied),
                ("access denied", false),
                "{denied}"
            );
            let other = failure(host, "alias 580", 1332);
            assert_eq!(
                reason_on(host, &other),
                ("it couldn't be read", false),
                "{other}"
            );
            let gone = failure(host, "WINREG", 53);
            assert_eq!(
                reason_on(host, &gone),
                ("it couldn't be reached", true),
                "{gone}"
            );
        }
        // rc=1445 is a code, not port 445.
        assert_eq!(error_kind("WS1.X.LOCAL WKSSVC: rc=1445 (error)"), "other");
    }

    #[test]
    fn win32_errors_map_to_the_read_reasons() {
        use super::super::hosts::reason;
        let r = |code| reason(&failure("WS1.CONTOSO.LOCAL", "WKSSVC", code));
        assert_eq!(r(5), ("access denied", false));
        for unreachable in [53, 51, 67, 1722, 1231, 1232, 1225, 1727, 1753] {
            assert_eq!(kind_of(unreachable), Kind::Unreachable, "{unreachable}");
            assert_eq!(r(unreachable), ("it couldn't be reached", true));
        }
        for sign_in in [1326, 1311, 1909, 1331] {
            assert_eq!(r(sign_in), ("the sign-in was refused", false));
        }
        assert_eq!(r(1460), ("it didn't answer in time", true));
        // NERR_GroupNotFound, ERROR_NONE_MAPPED, RPC_S_UNKNOWN_IF, others.
        for other in [2220, 1332, 1717, 87, 2184] {
            assert_eq!(kind_of(other), Kind::Other, "{other}");
            assert_eq!(r(other), ("it couldn't be read", false));
        }
        assert_eq!(
            failure("WS1", "alias 544", 5),
            "WS1 alias 544: rc=5 (access denied)"
        );
        // rc=53 is not rc=5.
        assert_ne!(kind_of(53), Kind::AccessDenied);
    }

    #[test]
    fn host_names_must_be_plain_dns_names() {
        for ok in ["WS1.CONTOSO.LOCAL", "ws-1", "SRV_01.x.local"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "\\\\evil\\share",
            "a/b",
            "ws1 contoso",
            ".hidden",
            "-x",
            "ws1\0",
            "host:445",
        ] {
            assert!(!valid_host(bad), "{bad:?}");
        }
    }

    #[test]
    fn every_computer_is_read_ten_at_a_time() {
        let fake = Arc::new(Fake {
            down: vec!["DOWN.CONTOSO.LOCAL"],
            denied: vec!["DENIED.CONTOSO.LOCAL"],
            ..Default::default()
        });
        let mut asks: Vec<HostAsk> = (0..25)
            .map(|i| ask(&format!("WS{i}.CONTOSO.LOCAL")))
            .collect();
        asks.push(ask("DOWN.CONTOSO.LOCAL"));
        asks.push(ask("DENIED.CONTOSO.LOCAL"));
        asks.push(ask("bad\\name"));
        let found = read(
            fake.clone(),
            &asks,
            limits(Duration::from_secs(5), Duration::from_secs(30)),
        );
        assert_eq!(found.len(), asks.len());
        assert!(fake.most.load(Ordering::SeqCst) <= AT_ONCE);
        let ws0 = &found[0];
        assert_eq!(ws0.name, "WS0.CONTOSO.LOCAL");
        assert!(matches!(&ws0.wkssvc, Call::Done(v) if v.len() == 3));
        assert!(
            ws0.aliases
                .iter()
                .filter(|(_, c)| matches!(c, Call::Done(_)))
                .count()
                == 3
        );
        assert!(ws0.errors.is_empty());
        let down = &found[25];
        assert_eq!(down.errors, ["DOWN.CONTOSO.LOCAL: 445/tcp unreachable"]);
        assert_eq!(
            down.srvsvc,
            Call::Failed("DOWN.CONTOSO.LOCAL: 445/tcp unreachable".into())
        );
        let denied = &found[26];
        assert_eq!(
            denied.wkssvc,
            Call::Failed("DENIED.CONTOSO.LOCAL WKSSVC: rc=5 (access denied)".into())
        );
        assert_eq!(
            denied.group_errors()[0],
            "DENIED.CONTOSO.LOCAL alias 544: rc=5 (access denied)"
        );
        // Never contacted with a name that isn't one.
        assert!(found[27].errors[0].contains("not a computer name"));
        assert!(!fake.seen.lock().unwrap().iter().any(|h| h.contains('\\')));
    }

    #[test]
    fn a_hung_computer_is_abandoned_and_keeps_what_finished() {
        // SLOW hangs in every call after the port check: its first call
        // (NetSessionEnum) never finishes within its limit.
        let fake = Arc::new(Fake {
            hang: vec![("SLOW.CONTOSO.LOCAL", Duration::from_secs(3))],
            ..Default::default()
        });
        let asks = [ask("SLOW.CONTOSO.LOCAL"), ask("WS1.CONTOSO.LOCAL")];
        let started = Instant::now();
        let found = read(
            fake,
            &asks,
            limits(Duration::from_millis(400), Duration::from_secs(30)),
        );
        // Not waited for: the other computer and the limit decide.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        let slow = &found[0];
        let why = "SLOW.CONTOSO.LOCAL: per-host timeout";
        assert_eq!(slow.errors, [why]);
        assert_eq!(slow.wkssvc, Call::Failed(why.into()));
        assert_eq!(slow.group_errors()[0], why);
        assert_eq!(
            super::super::hosts::reason(why),
            ("it didn't answer in time", true)
        );
        assert!(matches!(found[1].wkssvc, Call::Done(_)));
    }

    #[test]
    fn nothing_is_waited_for_after_the_deadline() {
        let fake = Arc::new(Fake {
            hang: (0..3)
                .map(|i| {
                    let n: &'static str = Box::leak(format!("H{i}.X.LOCAL").into_boxed_str());
                    (n, Duration::from_secs(3))
                })
                .collect(),
            ..Default::default()
        });
        let asks: Vec<HostAsk> = (0..3).map(|i| ask(&format!("H{i}.X.LOCAL"))).collect();
        let mut l = limits(Duration::from_secs(60), Duration::from_millis(300));
        l.at_once = 2;
        let started = Instant::now();
        let found = read(fake, &asks, l);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(found[0].errors, ["H0.X.LOCAL: per-host timeout"]);
        assert_eq!(found[1].errors, ["H1.X.LOCAL: per-host timeout"]);
        // The third never started.
        let why = "H2.X.LOCAL: timed out before it was contacted";
        assert_eq!(found[2].errors, [why]);
        assert_eq!(
            super::super::hosts::reason(why),
            ("it didn't answer in time", true)
        );
    }

    #[test]
    fn only_what_was_asked_is_read() {
        let fake = Arc::new(Fake::default());
        let asks = [HostAsk {
            name: "WS1.CONTOSO.LOCAL".into(),
            sessions: true,
            local_groups: false,
            ..Default::default()
        }];
        let found = read(
            fake.clone(),
            &asks,
            limits(Duration::from_secs(5), Duration::from_secs(10)),
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
        assert_eq!(found[0].account, Call::NotRun);
        assert!(found[0].aliases.is_empty());
        assert!(found[0].group_errors().is_empty());
    }

    fn computer(name: &str, sid: &str, is_dc: bool) -> Computer {
        let mut v = serde_json::to_value(Computer::default()).unwrap();
        v["Properties"]["name"] = name.into();
        v["Properties"]["is_dc"] = is_dc.into();
        v["ObjectIdentifier"] = sid.into();
        v["IsDC"] = is_dc.into();
        serde_json::from_value(v).unwrap()
    }

    fn user(name: &str, sid: &str) -> User {
        let mut v = serde_json::to_value(User::default()).unwrap();
        v["Properties"]["name"] = name.into();
        v["ObjectIdentifier"] = sid.into();
        serde_json::from_value(v).unwrap()
    }

    fn read_one(fake: Fake, name: &str) -> HostFound {
        read(
            Arc::new(fake),
            &[ask(name)],
            limits(Duration::from_secs(5), Duration::from_secs(10)),
        )
        .remove(0)
    }

    #[test]
    fn what_was_read_is_written_as_the_modules_write_it() {
        let host = "WS1.CONTOSO.LOCAL";
        let ws1 = format!("{DOMAIN_SID}-1104");
        let alice = format!("{DOMAIN_SID}-1105");
        let users = SidIndex::new(&[user("ALICE@CONTOSO.LOCAL", &alice)], "contoso.local");
        let types: HashMap<String, String> =
            [(format!("{DOMAIN_SID}-512"), "Group".to_string())].into();
        let mut c = computer(host, &ws1, false);
        super::super::hosts::mark_sessions_not_collected(
            std::slice::from_mut(&mut c),
            super::super::hosts::NOT_ATTEMPTED,
        );
        let found = read_one(Fake::default(), host);
        apply(&mut c, &found, &users, &types, "contoso.local");

        // Each list collected, alice once each, machine accounts dropped.
        for s in [
            c.sessions_mut().clone(),
            c.privileged_sessions_mut().clone(),
            c.registry_sessions_mut().clone(),
        ] {
            assert!(*s.collected());
            assert_eq!(s.failure_reason(), &None);
            let sids: Vec<_> = s.results().iter().map(|l| l.user_sid().clone()).collect();
            assert_eq!(sids, std::slice::from_ref(&alice));
            assert_eq!(s.results()[0].computer_sid(), &ws1);
        }
        // The SAMR path's groups: <computer SID>-<RID>, named on the host,
        // the local Administrator left out, 580 not on this computer.
        let groups = c.local_groups_mut().clone();
        let ids: Vec<_> = groups
            .iter()
            .map(|g| g.object_identifier().clone())
            .collect();
        assert_eq!(
            ids,
            ALIASES
                .iter()
                .map(|a| format!("{ws1}-{}", a.rid))
                .collect::<Vec<_>>()
        );
        let admins = &groups[0];
        assert!(*admins.collected());
        let members: Vec<_> = admins
            .results()
            .iter()
            .map(|m| (m.object_identifier().clone(), m.object_type().clone()))
            .collect();
        assert_eq!(
            members,
            [
                (format!("{DOMAIN_SID}-512"), "Group".to_string()),
                ("S-1-5-4".to_string(), "Base".to_string()),
            ]
        );
        let json = serde_json::to_value(admins).unwrap();
        assert_eq!(json["Name"], "ADMINISTRATORS@WS1.CONTOSO.LOCAL");
        let rmu = groups
            .iter()
            .find(|g| g.object_identifier().ends_with("-580"))
            .unwrap();
        assert!(!*rmu.collected());
        assert_eq!(
            rmu.failure_reason().as_deref(),
            Some("WS1.CONTOSO.LOCAL alias 580: rc=1332 (error)")
        );
        assert_eq!(c.users_rights_mut().len(), 1);

        // And a retest reads it as such: sessions read, local groups not
        // (one group didn't answer), with the reason.
        let want = pathwarden_core::retest::targeted::SliceHost {
            id: ws1.clone(),
            sessions: true,
            local_groups: true,
            ..Default::default()
        };
        let r = super::super::hosts::host_read(&mut c, &want, &found.group_errors());
        assert_eq!((r.sessions, r.local_groups), (Some(true), Some(false)));
        assert_eq!(r.why.as_deref(), Some("it couldn't be read"));
    }

    #[test]
    fn a_dcs_groups_are_the_domains_builtin_groups() {
        let host = "DC01.CONTOSO.LOCAL";
        let dc_sid = format!("{DOMAIN_SID}-1000");
        // Not marked a DC by the directory: the account domain tells.
        let mut c = computer(host, &dc_sid, false);
        let found = read_one(
            Fake {
                dc: vec![host],
                ..Default::default()
            },
            host,
        );
        apply(
            &mut c,
            &found,
            &SidIndex::new(&[], "contoso.local"),
            &HashMap::new(),
            "contoso.local",
        );
        let groups = c.local_groups_mut().clone();
        assert_eq!(groups[0].object_identifier(), "CONTOSO.LOCAL-S-1-5-32-544");
        assert_eq!(
            serde_json::to_value(&groups[0]).unwrap()["Name"],
            "IGNOREME"
        );
        // Nothing left out on a DC (the account domain is the domain).
        assert_eq!(groups[0].results().len(), 3);
    }

    #[test]
    fn a_failed_read_keeps_the_reason_and_nothing_else() {
        let host = "DENIED.CONTOSO.LOCAL";
        let sid = format!("{DOMAIN_SID}-1200");
        let mut c = computer(host, &sid, false);
        let found = read_one(
            Fake {
                denied: vec![host],
                ..Default::default()
            },
            host,
        );
        apply(
            &mut c,
            &found,
            &SidIndex::new(&[], "contoso.local"),
            &HashMap::new(),
            "contoso.local",
        );
        assert!(!*c.privileged_sessions_mut().collected());
        assert!(c.privileged_sessions_mut().results().is_empty());
        let want = pathwarden_core::retest::targeted::SliceHost {
            id: sid,
            sessions: true,
            local_groups: true,
            ..Default::default()
        };
        let r = super::super::hosts::host_read(&mut c, &want, &found.group_errors());
        assert_eq!((r.sessions, r.local_groups), (Some(false), Some(false)));
        assert_eq!(r.why.as_deref(), Some("access denied"));
        assert!(!r.unreachable);

        // Unreachable: every call fails with the port check.
        let host = "DOWN.CONTOSO.LOCAL";
        let mut c = computer(host, &format!("{DOMAIN_SID}-1201"), false);
        let found = read_one(
            Fake {
                down: vec![host],
                ..Default::default()
            },
            host,
        );
        apply(
            &mut c,
            &found,
            &SidIndex::new(&[], "contoso.local"),
            &HashMap::new(),
            "contoso.local",
        );
        let want = pathwarden_core::retest::targeted::SliceHost {
            id: c.object_identifier().clone(),
            sessions: true,
            local_groups: true,
            ..Default::default()
        };
        let r = super::super::hosts::host_read(&mut c, &want, &found.group_errors());
        assert!(r.unreachable);
        assert_eq!(r.why.as_deref(), Some("it didn't answer on port 445"));
    }

    #[test]
    fn srvsvc_alone_is_not_sessions_read() {
        // SRVSVC answered; WKSSVC and Remote Registry were denied.
        let host = "WS2.CONTOSO.LOCAL";
        let sid = format!("{DOMAIN_SID}-1300");
        let mut c = computer(host, &sid, false);
        let mut found = read_one(Fake::default(), host);
        found.wkssvc = Call::Failed(failure(host, "WKSSVC", 5));
        found.winreg = Call::Failed(failure(host, "WINREG", 5));
        apply(
            &mut c,
            &found,
            &SidIndex::new(&[], "contoso.local"),
            &HashMap::new(),
            "contoso.local",
        );
        assert!(*c.sessions_mut().collected());
        let want = pathwarden_core::retest::targeted::SliceHost {
            id: sid,
            sessions: true,
            local_groups: false,
            ..Default::default()
        };
        let r = super::super::hosts::host_read(&mut c, &want, &[]);
        assert_eq!(r.sessions, Some(false));
        assert_eq!(r.why.as_deref(), Some("access denied"));
    }

    #[test]
    fn sids_and_names_match_exactly() {
        assert!(is_under(&format!("{MACHINE_SID}-500"), MACHINE_SID));
        assert!(is_under(
            &format!("{MACHINE_SID}-500"),
            &MACHINE_SID.to_lowercase()
        ));
        // A longer domain SID that starts the same is another domain.
        assert!(!is_under("S-1-5-21-7-8-90-500", MACHINE_SID));
        assert!(!is_under(MACHINE_SID, MACHINE_SID));
        assert_eq!(domain_of(&format!("{DOMAIN_SID}-1105")), Some(DOMAIN_SID));
        assert!(profile_sid(&format!("{DOMAIN_SID}-1105")));
        assert!(!profile_sid(&format!("{DOMAIN_SID}-1105_Classes")));
        assert!(!profile_sid("S-1-5-18"));
        assert!(!profile_sid(".DEFAULT"));
        let users = SidIndex::new(
            &[
                user("ALICE@CONTOSO.LOCAL", "S-1-5-21-1-2-3-1105"),
                user("ALICE@CHILD.CONTOSO.LOCAL", "S-1-5-21-4-5-6-1105"),
            ],
            "contoso.local",
        );
        // The collected domain's first, as the sessions module resolves.
        assert_eq!(
            users.resolve("CONTOSO\\alice").as_deref(),
            Some("S-1-5-21-1-2-3-1105")
        );
        assert_eq!(
            users.resolve("alice").as_deref(),
            Some("S-1-5-21-1-2-3-1105")
        );
        assert_eq!(users.resolve("WS1$"), None);
        assert_eq!(users.resolve("?"), None);
        assert_eq!(users.resolve("bob"), None);
        // The aliases are the SAMR path's, by RID.
        let rids: Vec<u32> = ALIASES.iter().map(|a| a.rid).collect();
        assert_eq!(rids, [544, 555, 562, 580]);
    }
}
