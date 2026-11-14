//! Services that store a domain account's password.
//!
//! A Windows service that runs as a domain account keeps the account's
//! password in the computer's LSA secrets, where any administrator of the
//! computer can read it. In a Full collection over Kerberos, each reached
//! computer's `HKLM\SYSTEM\CurrentControlSet\Services` keys are listed over
//! its Remote Registry ([`super::krbreg`]: the computer's `cifs/` ticket,
//! every SMB reply signed and checked, no NTLM), and only three values are
//! read from each: `ObjectName` (the account the service runs as), `Start`
//! and `Type`. Nothing else is opened or queried: never `ImagePath`, never
//! `Parameters`, never the LSA secrets, SAM or DPAPI. The password is never
//! read; the file this writes has no place for one.
//!
//! The result is `pathwarden-storedcreds.json` in the zip
//! (`pathwarden_core::storedcreds`): the services that run as a domain
//! account, and each computer's status (collected, partly collected, not
//! collected and why), so a computer that wasn't read is "can't tell" in
//! retest rather than "fixed". It also carries the forest's NetBIOS domain
//! names, so `DOMAIN\user` resolves.
//!
//! Everything a computer answers is untrusted: names are cut to
//! [`MAX_TEXT`] characters, a computer lists at most [`MAX_SERVICES`]
//! services, and each computer gets [`PER_HOST`].
//!
//! The scheduled tasks (slice 2) are read by [`super::tasks`] into the same
//! file, with their own switch.

use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use dcerpc::rrp::{Hkey, RegValue};
use pathwarden_core::storedcreds::{
    account_ref, AccountRef, HostRecord, NetbiosName, Sidecar, Stored, Via, MAX_TEXT, SCHEMA,
};
use pathwarden_core::sysvol::{Check, CheckStatus};
use rusthound_ce::objects::computer::Computer;

use super::hostauth::{Skip, Skipped};
use super::hosts::{self, KerberosSignIn};
use super::Msg;

/// The file name inside the zip.
pub(crate) const SIDECAR_FILE: &str = pathwarden_core::storedcreds::FILE_NAME;
/// The services key under HKLM.
pub(crate) const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
/// The only values ever read from a service's key.
pub(crate) const VALUES: [&str; 3] = ["ObjectName", "Start", "Type"];
/// Most services read from one computer (real ones: a few hundred).
pub(crate) const MAX_SERVICES: u32 = 4096;
/// How long one computer's services may take, sign-in included.
pub(crate) const PER_HOST: Duration = Duration::from_secs(60);
/// Computers read at once.
const AT_ONCE: usize = 16;
/// Computers whose account password is older than this aren't contacted
/// (as the modules do).
const EXPIRY_DAYS: i64 = 60;
/// RPC "pipe not available": Remote Registry was still starting.
pub(crate) const PIPE_NOT_AVAILABLE: &str = "0xc00000ac";
/// How long Remote Registry gets to start before it is asked again.
pub(crate) const REGISTRY_START: Duration = Duration::from_secs(3);
/// `SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS`: a service,
/// not a driver.
const SERVICE_WIN32: u32 = 0x30;
/// REG_SZ, REG_EXPAND_SZ.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
/// Why services aren't read without Kerberos.
pub(crate) const NO_KERBEROS: &str =
    "services are read only over Kerberos; this collection signed \
     in to computers with NTLM";

/// KEY_ENUMERATE_SUB_KEYS: all the services key is opened for.
pub(crate) const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
/// KEY_QUERY_VALUE: all a service's key is opened for.
pub(crate) const KEY_QUERY_VALUE: u32 = 0x0001;
/// The whole services step's time, all computers: what isn't read by then
/// is not collected, with that reason.
pub(crate) const STEP_BUDGET: Duration = Duration::from_secs(30 * 60);
/// Why a computer wasn't read when [`STEP_BUDGET`] ran out.
pub(crate) const OUT_OF_TIME: &str = "the services step ran out of time (30 minutes)";
/// Rough time to read one computer's services on a LAN: a few hundred
/// services, three or four calls each.
pub(crate) const PER_HOST_ESTIMATE: Duration = Duration::from_millis(800);

/// The registry calls the walk makes, so a fake can stand in for a
/// computer in tests.
pub(crate) trait Registry {
    type Key;
    async fn hklm(&mut self) -> Result<Self::Key, String>;
    async fn open_key(
        &mut self,
        parent: &Self::Key,
        subkey: &str,
        access: u32,
    ) -> Result<Self::Key, String>;
    async fn enum_key(&mut self, key: &Self::Key, index: u32) -> Result<Option<String>, String>;
    async fn query(&mut self, key: &Self::Key, value: &str) -> Result<RegValue, String>;
    async fn close(&mut self, key: &Self::Key);
}

impl Registry for super::krbreg::Registry<'_> {
    type Key = Hkey;
    async fn hklm(&mut self) -> Result<Hkey, String> {
        super::krbreg::Registry::hklm(self).await
    }
    async fn open_key(&mut self, parent: &Hkey, subkey: &str, access: u32) -> Result<Hkey, String> {
        super::krbreg::Registry::open_key_with(self, parent, subkey, access).await
    }
    async fn enum_key(&mut self, key: &Hkey, index: u32) -> Result<Option<String>, String> {
        super::krbreg::Registry::enum_key(self, key, index).await
    }
    async fn query(&mut self, key: &Hkey, value: &str) -> Result<RegValue, String> {
        super::krbreg::Registry::query(self, key, value).await
    }
    async fn close(&mut self, key: &Hkey) {
        super::krbreg::Registry::close(self, key).await
    }
}

/// Plain words for a registry or sign-in error, cut short.
pub(crate) fn words(e: &str) -> String {
    let lower = e.to_ascii_lowercase();
    if lower.contains("rc=5)")
        || lower.contains("win32 5)")
        || lower.contains("access_denied")
        || lower.contains("0xc0000022")
        || lower.contains("access denied")
    {
        return "access denied".into();
    }
    e.trim().chars().take(200).collect()
}

pub(crate) fn not_collected(why: &str) -> Check {
    Check {
        status: CheckStatus::NotCollected,
        reason: Some(why.to_string()),
        ..Check::default()
    }
}

/// `s` cut to [`MAX_TEXT`] characters, or `None` when it holds control
/// characters or nothing.
pub(crate) fn clean(s: &str) -> Option<String> {
    let s: String = s.trim().chars().take(MAX_TEXT).collect();
    (!s.is_empty() && !s.chars().any(char::is_control)).then_some(s)
}

/// Whether a service's `ObjectName` names a domain account worth keeping:
/// not a built-in, virtual or local account (`.\x`, or the computer's own
/// name, `host` being its DNS name).
pub(crate) fn is_domain_account(object_name: &str, host: &str) -> bool {
    let own = host.split('.').next().unwrap_or(host);
    match account_ref(object_name) {
        Some(AccountRef::Domain { domain, .. }) => !domain.eq_ignore_ascii_case(own),
        Some(AccountRef::Upn { .. }) => true,
        _ => false,
    }
}

/// The text of a string value; `None` for another type.
fn text(v: &RegValue) -> Option<String> {
    matches!(v.ty, REG_SZ | REG_EXPAND_SZ).then(|| v.as_string())
}

/// Whether a query error says the value isn't set (win32 2).
pub(crate) fn not_set(e: &str) -> bool {
    e.contains("win32 2)") || e.contains("rc=2)")
}

/// Reads the services of one computer through `reg` until `deadline`: the
/// services that run as a domain account, and how far the read got.
pub(crate) async fn read_services<R: Registry>(
    reg: &mut R,
    host: &str,
    deadline: Instant,
) -> (Check, Vec<Stored>) {
    let mut stored = Vec::new();
    let hklm = match reg.hklm().await {
        Ok(k) => k,
        Err(e) => return (not_collected(&words(&e)), stored),
    };
    let services = match reg
        .open_key(&hklm, SERVICES_KEY, KEY_ENUMERATE_SUB_KEYS)
        .await
    {
        Ok(k) => k,
        Err(e) => {
            reg.close(&hklm).await;
            return (not_collected(&words(&e)), stored);
        }
    };
    let mut check = Check {
        status: CheckStatus::Complete,
        ..Check::default()
    };
    let partial = |check: &mut Check, why: String| {
        check.status = CheckStatus::Partial;
        check.reason.get_or_insert(why);
    };
    let mut index = 0u32;
    loop {
        if index >= MAX_SERVICES {
            partial(
                &mut check,
                format!("more than {MAX_SERVICES} services; the rest were not read"),
            );
            break;
        }
        if Instant::now() >= deadline {
            partial(&mut check, "ran out of time".into());
            break;
        }
        let name = match reg.enum_key(&services, index).await {
            Ok(None) => break,
            Ok(Some(n)) => n,
            Err(e) => {
                partial(&mut check, words(&e));
                break;
            }
        };
        index += 1;
        let Some(name) = clean(&name).filter(|n| !n.contains('\\')) else {
            check.skipped += 1;
            continue;
        };
        let key = match reg.open_key(&services, &name, KEY_QUERY_VALUE).await {
            Ok(k) => k,
            Err(_) => {
                check.failed += 1;
                continue;
            }
        };
        let account = match reg.query(&key, VALUES[0]).await {
            Ok(v) => text(&v).and_then(|a| clean(&a)),
            Err(e) if not_set(&e) => None,
            Err(_) => {
                check.failed += 1;
                reg.close(&key).await;
                continue;
            }
        };
        if let Some(account) = account.filter(|a| is_domain_account(a, host)) {
            let dword = |r: Result<RegValue, String>| r.ok().and_then(|v| v.as_dword());
            let start = dword(reg.query(&key, VALUES[1]).await);
            let kind = dword(reg.query(&key, VALUES[2]).await);
            if kind.is_none_or(|t| t & SERVICE_WIN32 != 0) {
                stored.push(Stored {
                    via: Via::Service,
                    name,
                    account,
                    start,
                    ..Stored::default()
                });
            }
        }
        check.read += 1;
        reg.close(&key).await;
    }
    if check.read == 0 && check.skipped > 0 {
        let n = check.skipped;
        partial(
            &mut check,
            format!(
                "{} not usable",
                pathwarden_core::text::count(n, "service name was", "service names were")
            ),
        );
    }
    if check.failed > 0 {
        let n = check.failed;
        partial(
            &mut check,
            format!(
                "{} could not be read",
                pathwarden_core::text::count(n, "service", "services")
            ),
        );
    }
    reg.close(&services).await;
    reg.close(&hklm).await;
    (check, stored)
}

/// One computer, over Kerberos: its `cifs/` ticket, the signed SMB
/// session, Remote Registry, then [`read_services`].
pub(crate) async fn read_host(
    host: &str,
    k: &KerberosSignIn,
    domain: &str,
    user: &str,
    until: Instant,
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
        let mut reg = match super::krbreg::Registry::open(&mut smb).await {
            Ok(r) => r,
            Err(e) => {
                return (
                    not_collected(&format!("Remote Registry: {}", words(&e))),
                    Vec::new(),
                )
            }
        };
        read_services(&mut reg, host, deadline).await
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

/// A computer's Remote Registry sessions and its services in one Kerberos
/// SMB session and one `\winreg` pipe (the sessions pass's): the logged-on
/// SIDs, then the services until `until` or [`PER_HOST`] after the sessions.
pub(crate) async fn sessions_and_services(
    host: &str,
    ccache: &str,
    kdc: &str,
    domain: &str,
    user: &str,
    until: Instant,
) -> (Result<Vec<String>, String>, (Check, Vec<Stored>)) {
    let mut smb = match super::krbreg::connect(host, ccache, kdc, domain, user).await {
        Ok(s) => s,
        Err(e) => {
            let e = e.to_string();
            return (
                Err(format!("{host}: {e}")),
                (not_collected(&words(&e)), Vec::new()),
            );
        }
    };
    let mut reg = match super::krbreg::Registry::open(&mut smb).await {
        Ok(r) => r,
        Err(e) => {
            return (
                Err(format!("{host} WINREG: {e}")),
                (
                    not_collected(&format!("Remote Registry: {}", words(&e))),
                    Vec::new(),
                ),
            )
        }
    };
    let sessions = reg
        .logged_on_sids()
        .await
        .map_err(|e| format!("{host} WINREG: {e}"));
    let now = Instant::now();
    let services = if now >= until {
        (not_collected(OUT_OF_TIME), Vec::new())
    } else {
        read_services(&mut reg, host, (now + PER_HOST).min(until)).await
    };
    (sessions, services)
}

/// What one computer's services read gave.
pub(crate) type HostRead = (Check, Vec<Stored>);

/// The services step's own plan: who signs in, the run's domain, the
/// forest's NetBIOS names, what the sessions pass already read (by object
/// ID) and when the step stops.
pub(crate) struct Plan<'a> {
    pub k: &'a KerberosSignIn,
    pub domain: &'a str,
    pub smb_domain: &'a str,
    pub user: &'a str,
    pub netbios: Vec<NetbiosName>,
    pub already: std::collections::HashMap<String, HostRead>,
    pub until: Instant,
}

/// The services step's share of the progress bar, from the computers it
/// may read: [`PER_HOST_ESTIMATE`] each, [`AT_ONCE`] at a time, relative to
/// the read step's weight and time (as the SYSVOL step is weighted).
pub(crate) fn weight(computers: usize, read_weight: f64, read: Duration) -> f64 {
    let expected = (computers as f64 * PER_HOST_ESTIMATE.as_secs_f64() / AT_ONCE as f64)
        .min(STEP_BUDGET.as_secs_f64());
    let read = read.as_secs_f64().max(1.0);
    (read_weight * expected / read).clamp(0.0, 10.0 * read_weight)
}

/// Why a skipped computer's services (or tasks) weren't read.
pub(crate) fn skip_words(s: &Skip) -> String {
    match s {
        Skip::NoName => "skipped: the domain has no Kerberos name for it".into(),
        Skip::Unsigned => "skipped: its replies weren't signed".into(),
        Skip::BadReply => "skipped: its replies didn't answer Pathwarden's requests".into(),
        Skip::Rc4Trust => "skipped: the trust to its domain allows only RC4".into(),
        Skip::Unreachable(realm) => {
            format!("skipped: couldn't reach {realm}'s domain controller for Kerberos")
        }
        Skip::Refused => "skipped: its Kerberos ticket was refused".into(),
    }
}

/// The step as a whole, from each computer's status.
pub(crate) fn step_check(hosts: &[HostRecord]) -> Check {
    sum_up(&hosts.iter().map(|h| &h.services).collect::<Vec<_>>())
}

/// A step as a whole, from each computer's status for it.
pub(crate) fn sum_up(hosts: &[&Check]) -> Check {
    let complete = hosts
        .iter()
        .filter(|h| h.status == CheckStatus::Complete)
        .count();
    let read = hosts
        .iter()
        .filter(|h| h.status != CheckStatus::NotCollected)
        .count();
    let status = if complete == hosts.len() {
        CheckStatus::Complete
    } else if read == 0 {
        CheckStatus::NotCollected
    } else {
        CheckStatus::Partial
    };
    let reason = match status {
        CheckStatus::Complete => None,
        CheckStatus::NotCollected => {
            // One reason for all, when they share it.
            let first = hosts.first().and_then(|h| h.reason.clone());
            Some(match first {
                Some(r) if hosts.iter().all(|h| h.reason.as_ref() == Some(&r)) => r,
                _ => "no computer could be read".into(),
            })
        }
        CheckStatus::Partial => Some(format!(
            "{} of {} read in full",
            pathwarden_core::report::num(complete),
            pathwarden_core::text::count(hosts.len(), "computer", "computers")
        )),
    };
    Check {
        status,
        reason,
        read: complete,
        failed: hosts.len() - complete,
        skipped: 0,
    }
}

/// The sidecar of a collection whose computers can't be read for their
/// services (`why`): every computer not collected.
pub(crate) fn not_read(domain: &str, netbios: Vec<NetbiosName>, why: &str) -> Sidecar {
    Sidecar {
        schema: SCHEMA.into(),
        domain: domain.to_string(),
        netbios,
        services: not_collected(why),
        turned_off: false,
        tasks: None,
        tasks_turned_off: false,
        hosts: Vec::new(),
    }
}

/// Why services weren't read when they were turned off.
pub(crate) const TURNED_OFF: &str = "service reads were turned off for this collection";

/// The sidecar of a collection whose service reads were turned off: it
/// still says so, so the completeness shows "off", not 0%.
pub(crate) fn turned_off(domain: &str, netbios: Vec<NetbiosName>) -> Sidecar {
    Sidecar {
        turned_off: true,
        ..not_read(domain, netbios, TURNED_OFF)
    }
}

/// Reads the services of every computer the modules reached, over
/// Kerberos, and returns the sidecar. Computers that were skipped or not
/// reached are listed as not collected, with the reason.
pub(crate) async fn collect(
    plan: Plan<'_>,
    computers: &mut [Computer],
    skipped: &Skipped,
    tx: &mpsc::Sender<Msg>,
) -> Sidecar {
    let Plan {
        k,
        domain,
        smb_domain,
        user,
        netbios,
        mut already,
        until,
    } = plan;
    let log = |l: String| {
        let _ = tx.send(Msg::Log(l));
    };
    let mut records: Vec<HostRecord> = Vec::new();
    let mut ask: Vec<(usize, String)> = Vec::new();
    for c in computers.iter_mut() {
        let host = c.properties().name().clone();
        let id = c.object_identifier().clone();
        if host.is_empty() || !c.is_active(EXPIRY_DAYS) {
            continue;
        }
        let mut record = HostRecord {
            id: id.clone(),
            name: host.clone(),
            ..HostRecord::default()
        };
        if let Some(s) = skipped.get(id.as_str()) {
            record.services = not_collected(&skip_words(s));
        } else if let Some((check, stored)) = already.remove(&id) {
            // Read with the sessions, on the same pipe.
            if let Some(why) = check.reason.as_deref() {
                log(format!("warning: [services] {host}: {why}"));
            }
            record.services = check;
            record.stored = stored;
        } else if !hosts::reached(c) {
            record.services = not_collected("not reached");
        } else {
            ask.push((records.len(), host));
        }
        records.push(record);
    }
    if !ask.is_empty() {
        log(format!(
            "[services] reading the accounts services run as on {} over Kerberos",
            pathwarden_core::text::count(ask.len(), "computer", "computers")
        ));
    }
    let mut progress = Progress::new(tx.clone(), "Reading services", ask.len());
    for attempt in 0..2 {
        if ask.is_empty() {
            break;
        }
        if attempt > 0 {
            log(format!(
                "[services] Remote Registry was starting on {}; asking again in {}s",
                pathwarden_core::text::count(ask.len(), "computer", "computers"),
                REGISTRY_START.as_secs()
            ));
            tokio::time::sleep(REGISTRY_START).await;
        }
        let sem = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
        let mut set = tokio::task::JoinSet::new();
        let mut pending: std::collections::HashMap<usize, String> = Default::default();
        for (i, host) in std::mem::take(&mut ask) {
            pending.insert(i, host.clone());
            let (sem, k) = (sem.clone(), k.clone());
            let (smb_domain, user) = (smb_domain.to_string(), user.to_string());
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                let read = read_host(&host, &k, &smb_domain, &user, until).await;
                (i, host, read)
            });
        }
        while let Some(done) = set.join_next().await {
            let Ok((i, host, (check, stored))) = done else {
                continue;
            };
            pending.remove(&i);
            progress.done();
            let starting = check
                .reason
                .as_deref()
                .is_some_and(|r| r.to_ascii_lowercase().contains(PIPE_NOT_AVAILABLE));
            if starting && attempt == 0 && check.status == CheckStatus::NotCollected {
                ask.push((i, host));
                continue;
            }
            if let Some(why) = check.reason.as_deref() {
                log(format!("warning: [services] {host}: {why}"));
            }
            records[i].services = check;
            records[i].stored = stored;
        }
        // A task that never answered (a panic) is not collected, never
        // taken as read.
        for (i, _) in pending {
            records[i].services = not_collected("the read stopped unexpectedly");
        }
    }
    progress.finish();
    let services = step_check(&records);
    let found: usize = records.iter().map(|r| r.stored.len()).sum();
    log(format!(
        "[services] {} of {} read in full; {} run as a domain account",
        pathwarden_core::report::num(services.read),
        pathwarden_core::text::count(records.len(), "computer", "computers"),
        pathwarden_core::text::count(found, "service", "services"),
    ));
    if services.status != CheckStatus::Complete && !records.is_empty() {
        let _ = tx.send(Msg::Warning(format!(
            "Services weren't read on {} of {}, so findings that rest on them can't be \
             confirmed fixed. The collection log names each one.",
            pathwarden_core::report::num(services.failed),
            pathwarden_core::text::count(records.len(), "computer", "computers"),
        )));
    }
    Sidecar {
        schema: SCHEMA.into(),
        domain: domain.to_string(),
        netbios,
        services,
        turned_off: false,
        tasks: None,
        tasks_turned_off: false,
        hosts: records,
    }
}

/// Most often the step reports its progress.
const REPORT_EVERY: Duration = Duration::from_millis(250);

/// A step's detail line ("Reading services: computer 12 of 40"), at most
/// every [`REPORT_EVERY`].
pub(crate) struct Progress {
    tx: mpsc::Sender<Msg>,
    what: &'static str,
    total: usize,
    done: usize,
    last: Option<Instant>,
}

impl Progress {
    pub(crate) fn new(tx: mpsc::Sender<Msg>, what: &'static str, total: usize) -> Self {
        let mut p = Progress {
            tx,
            what,
            total,
            done: 0,
            last: None,
        };
        p.report(true);
        p
    }

    pub(crate) fn done(&mut self) {
        self.done = (self.done + 1).min(self.total);
        self.report(self.done == self.total);
    }

    fn report(&mut self, force: bool) {
        if self.total == 0 {
            return;
        }
        let now = Instant::now();
        if !force
            && self
                .last
                .is_some_and(|t| now.duration_since(t) < REPORT_EVERY)
        {
            return;
        }
        self.last = Some(now);
        let _ = self.tx.send(Msg::Detail(format!(
            "{}: computer {} of {}",
            self.what,
            pathwarden_core::report::num((self.done + 1).min(self.total)),
            pathwarden_core::report::num(self.total)
        )));
    }

    pub(crate) fn finish(&mut self) {
        if self.total > 0 {
            let _ = self.tx.send(Msg::Detail(String::new()));
        }
    }
}

/// Adds the sidecar to the collector's zip.
pub(crate) fn append_to(s: &Sidecar, zip_path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let json = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(zip_path)
        .map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new_append(file).map_err(|e| e.to_string())?;
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file(SIDECAR_FILE, options)
        .map_err(|e| e.to_string())?;
    zip.write_all(&json).map_err(|e| e.to_string())?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    /// A computer's registry: keys by path (lower case), each with its
    /// values. Records every call.
    #[derive(Default)]
    struct FakeRegistry {
        keys: BTreeMap<String, HashMap<String, RegValue>>,
        /// Subkey names under the services key, in order.
        services: Vec<String>,
        deny_services: bool,
        deny_open: Vec<String>,
        /// Fails `enum_key` from this index on.
        enum_fails_at: Option<u32>,
        opened: Vec<String>,
        /// The access each key was opened with.
        access: Vec<(String, u32)>,
        queried: Vec<(String, String)>,
        open_handles: i64,
    }

    fn sz(s: &str) -> RegValue {
        let mut data: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        data.extend_from_slice(&[0, 0]);
        RegValue { ty: REG_SZ, data }
    }

    fn dword(v: u32) -> RegValue {
        RegValue {
            ty: 4,
            data: v.to_le_bytes().to_vec(),
        }
    }

    impl FakeRegistry {
        fn service(&mut self, name: &str, values: &[(&str, RegValue)]) {
            self.services.push(name.to_string());
            self.keys.insert(
                format!("{}\\{}", SERVICES_KEY, name).to_ascii_lowercase(),
                values
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect(),
            );
        }
    }

    impl Registry for FakeRegistry {
        type Key = String;
        async fn hklm(&mut self) -> Result<String, String> {
            self.open_handles += 1;
            Ok(String::new())
        }
        async fn open_key(
            &mut self,
            parent: &String,
            subkey: &str,
            access: u32,
        ) -> Result<String, String> {
            let path = if parent.is_empty() {
                subkey.to_string()
            } else {
                format!("{parent}\\{subkey}")
            };
            self.opened.push(path.clone());
            self.access.push((path.clone(), access));
            if path.eq_ignore_ascii_case(SERVICES_KEY) {
                if self.deny_services {
                    return Err(format!("BaseRegOpenKey('{subkey}') failed (rc=5)"));
                }
                self.open_handles += 1;
                return Ok(path);
            }
            if self
                .deny_open
                .iter()
                .any(|d| d.eq_ignore_ascii_case(subkey))
            {
                return Err(format!("BaseRegOpenKey('{subkey}') failed (rc=5)"));
            }
            if self.keys.contains_key(&path.to_ascii_lowercase()) {
                self.open_handles += 1;
                Ok(path)
            } else {
                Err(format!("BaseRegOpenKey('{subkey}') failed (rc=2)"))
            }
        }
        async fn enum_key(&mut self, key: &String, index: u32) -> Result<Option<String>, String> {
            assert!(
                key.eq_ignore_ascii_case(SERVICES_KEY),
                "only the services key is listed"
            );
            if self.enum_fails_at.is_some_and(|f| index >= f) {
                return Err("SMB2 READ answered without a valid signature".into());
            }
            Ok(self.services.get(index as usize).cloned())
        }
        async fn query(&mut self, key: &String, value: &str) -> Result<RegValue, String> {
            self.queried.push((key.clone(), value.to_string()));
            self.keys
                .get(&key.to_ascii_lowercase())
                .and_then(|m| m.get(value))
                .cloned()
                .ok_or_else(|| "BaseRegQueryValue failed (win32 2)".to_string())
        }
        async fn close(&mut self, _key: &String) {
            self.open_handles -= 1;
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    const OWN: u32 = 0x10;

    /// A computer with the usual mix: only domain accounts are kept, a
    /// disabled one too; a gMSA is kept here (the analysis gives it no
    /// edge); a key's Password value and ImagePath are never read; only the
    /// three values are ever queried, and nothing below a service's key is
    /// opened.
    #[test]
    fn only_domain_accounts_and_only_three_values() {
        let mut reg = FakeRegistry::default();
        reg.service(
            "Spooler",
            &[("ObjectName", sz("LocalSystem")), ("Type", dword(OWN))],
        );
        reg.service(
            "MSSQL$SQLEXPRESS",
            &[
                ("ObjectName", sz("NT Service\\MSSQL$SQLEXPRESS")),
                ("Type", dword(OWN)),
            ],
        );
        reg.service(
            "LocalBackup",
            &[("ObjectName", sz(".\\backup")), ("Type", dword(OWN))],
        );
        reg.service(
            "OwnName",
            &[
                ("ObjectName", sz("APP01\\localadmin")),
                ("Type", dword(OWN)),
            ],
        );
        reg.service(
            "SqlAgent",
            &[
                ("ObjectName", sz("NORTH\\sql_svc")),
                ("Start", dword(2)),
                ("Type", dword(OWN)),
                ("ImagePath", sz("C:\\sql\\agent.exe -p Hunter2!")),
                ("Password", sz("Hunter2!")),
            ],
        );
        reg.service(
            "Reports",
            &[
                ("ObjectName", sz("svc@north.contoso.local")),
                ("Start", dword(3)),
                ("Type", dword(0x20)),
            ],
        );
        reg.service(
            "Backup",
            &[
                ("ObjectName", sz("NORTH\\gmsa01$")),
                ("Start", dword(2)),
                ("Type", dword(OWN)),
            ],
        );
        reg.service(
            "OldJob",
            &[
                ("ObjectName", sz("NORTH\\old_svc")),
                ("Start", dword(4)),
                ("Type", dword(OWN)),
            ],
        );
        // A driver with an ObjectName that looks like an account.
        reg.service("Drv", &[("ObjectName", sz("NORTH\\x")), ("Type", dword(1))]);
        reg.service("NoAccount", &[("Type", dword(OWN))]);
        let deadline = Instant::now() + PER_HOST;
        let (check, stored) = run(read_services(
            &mut reg,
            "APP01.NORTH.CONTOSO.LOCAL",
            deadline,
        ));
        assert_eq!(check.status, CheckStatus::Complete, "{check:?}");
        assert_eq!(check.read, 10);
        let got: Vec<(&str, &str, Option<u32>)> = stored
            .iter()
            .map(|s| (s.name.as_str(), s.account.as_str(), s.start))
            .collect();
        assert_eq!(
            got,
            [
                ("SqlAgent", "NORTH\\sql_svc", Some(2)),
                ("Reports", "svc@north.contoso.local", Some(3)),
                ("Backup", "NORTH\\gmsa01$", Some(2)),
                ("OldJob", "NORTH\\old_svc", Some(4)),
            ]
        );
        assert!(
            reg.queried
                .iter()
                .all(|(_, v)| VALUES.contains(&v.as_str())),
            "{:?}",
            reg.queried
        );
        // Only a service's own key, never one below it.
        assert!(reg
            .queried
            .iter()
            .all(|(k, _)| k.matches('\\').count() == 3));
        for o in &reg.opened {
            assert!(!o.to_ascii_lowercase().contains("parameters"), "{o}");
            assert!(o
                .to_ascii_lowercase()
                .starts_with(&SERVICES_KEY.to_ascii_lowercase()));
        }
        assert_eq!(reg.open_handles, 0, "every key closed");
        // The least access: list the services key, query a service's.
        for (path, access) in &reg.access {
            let want = if path.eq_ignore_ascii_case(SERVICES_KEY) {
                KEY_ENUMERATE_SUB_KEYS
            } else {
                KEY_QUERY_VALUE
            };
            assert_eq!(*access, want, "{path}");
        }
        let json = serde_json::to_string(&stored).unwrap();
        assert!(!json.contains("Hunter2"), "{json}");
        assert!(!json.contains("agent.exe"), "{json}");
    }

    /// The services key denied (a plain user): not collected, access denied.
    #[test]
    fn access_denied_is_not_collected() {
        let mut reg = FakeRegistry {
            deny_services: true,
            ..FakeRegistry::default()
        };
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now() + PER_HOST));
        assert_eq!(check.status, CheckStatus::NotCollected);
        assert_eq!(check.reason.as_deref(), Some("access denied"));
        assert!(stored.is_empty());
        assert_eq!(reg.open_handles, 0);
    }

    /// A service key that can't be opened, a listing that breaks off, and
    /// the time running out each leave the computer partly collected.
    #[test]
    fn failures_and_limits_are_partial() {
        let mut reg = FakeRegistry::default();
        reg.service("A", &[("ObjectName", sz("NORTH\\a")), ("Type", dword(OWN))]);
        reg.service("B", &[("ObjectName", sz("NORTH\\b")), ("Type", dword(OWN))]);
        reg.deny_open = vec!["B".into()];
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now() + PER_HOST));
        assert_eq!(check.status, CheckStatus::Partial);
        assert_eq!((check.read, check.failed), (1, 1));
        assert_eq!(check.reason.as_deref(), Some("1 service could not be read"));
        assert_eq!(stored.len(), 1);

        let mut reg = FakeRegistry::default();
        reg.service("A", &[("ObjectName", sz("NORTH\\a")), ("Type", dword(OWN))]);
        reg.service("B", &[("ObjectName", sz("NORTH\\b")), ("Type", dword(OWN))]);
        reg.enum_fails_at = Some(1);
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now() + PER_HOST));
        assert_eq!(check.status, CheckStatus::Partial);
        assert!(check.reason.as_deref().unwrap().contains("signature"));
        assert_eq!(stored.len(), 1);

        let mut reg = FakeRegistry::default();
        reg.service("A", &[("ObjectName", sz("NORTH\\a")), ("Type", dword(OWN))]);
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now()));
        assert_eq!(check.status, CheckStatus::Partial);
        assert_eq!(check.reason.as_deref(), Some("ran out of time"));
        assert!(stored.is_empty());
        assert_eq!(reg.open_handles, 0);
    }

    /// A hostile computer: more services than the limit, names too long or
    /// with control characters, an account name far too long.
    #[test]
    fn hostile_answers_are_bounded() {
        let mut reg = FakeRegistry::default();
        let long = "N".repeat(5000);
        reg.service(
            "Long",
            &[
                ("ObjectName", sz(&format!("NORTH\\{long}"))),
                ("Type", dword(OWN)),
            ],
        );
        reg.service("Bad\u{1}Name", &[("ObjectName", sz("NORTH\\x"))]);
        reg.service("Sub\\Key", &[("ObjectName", sz("NORTH\\x"))]);
        for i in 0..MAX_SERVICES {
            reg.services.push(format!("Filler{i}"));
        }
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now() + PER_HOST));
        assert_eq!(check.status, CheckStatus::Partial);
        assert!(check.reason.as_deref().unwrap().contains("more than 4096"));
        assert_eq!(check.skipped, 2);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].account.chars().count(), MAX_TEXT);
        assert_eq!(reg.open_handles, 0);
    }

    /// A listing whose names were all unusable is partial, not complete.
    #[test]
    fn only_unusable_names_is_partial() {
        let mut reg = FakeRegistry {
            services: vec!["Bad\u{1}".into(), "a\\b".into()],
            ..FakeRegistry::default()
        };
        let (check, stored) = run(read_services(&mut reg, "WS01", Instant::now() + PER_HOST));
        assert_eq!(check.status, CheckStatus::Partial);
        assert_eq!(
            check.reason.as_deref(),
            Some("2 service names were not usable")
        );
        assert!(stored.is_empty());
    }

    /// The services step's weight follows the computers, never past the
    /// budget.
    #[test]
    fn the_step_is_weighted_by_computers() {
        let small = weight(10, 35.0, Duration::from_secs(60));
        let big = weight(10_000, 35.0, Duration::from_secs(60));
        assert!(small < big, "{small} {big}");
        assert!(big <= 350.0);
        assert_eq!(weight(0, 35.0, Duration::from_secs(60)), 0.0);
    }

    #[test]
    fn domain_accounts() {
        assert!(is_domain_account("NORTH\\sql_svc", "APP01.NORTH.LOCAL"));
        assert!(is_domain_account("svc@north.local", "APP01.NORTH.LOCAL"));
        assert!(!is_domain_account("APP01\\admin", "app01.north.local"));
        assert!(!is_domain_account(".\\admin", "APP01"));
        assert!(!is_domain_account("LocalSystem", "APP01"));
        assert!(!is_domain_account("NT AUTHORITY\\NetworkService", "APP01"));
        assert!(!is_domain_account("NT SERVICE\\MSSQLSERVER", "APP01"));
        assert!(!is_domain_account("admin", "APP01"));
    }

    #[test]
    fn the_step_sums_up_the_computers() {
        let rec = |status, reason: Option<&str>| HostRecord {
            id: "S-1-5-21-1-2-3-1000".into(),
            services: Check {
                status,
                reason: reason.map(str::to_string),
                ..Check::default()
            },
            ..HostRecord::default()
        };
        let all = step_check(&[rec(CheckStatus::Complete, None)]);
        assert_eq!(all.status, CheckStatus::Complete);
        let denied = step_check(&[
            rec(CheckStatus::NotCollected, Some("access denied")),
            rec(CheckStatus::NotCollected, Some("access denied")),
        ]);
        assert_eq!(denied.status, CheckStatus::NotCollected);
        assert_eq!(denied.reason.as_deref(), Some("access denied"));
        let some = step_check(&[
            rec(CheckStatus::Complete, None),
            rec(CheckStatus::NotCollected, Some("not reached")),
        ]);
        assert_eq!(some.status, CheckStatus::Partial);
        assert_eq!(
            some.reason.as_deref(),
            Some("1 of 2 computers read in full")
        );
        assert_eq!((some.read, some.failed), (1, 1));
        assert_eq!(step_check(&[]).status, CheckStatus::Complete);
    }

    /// Computers the modules skipped or didn't reach are listed as not
    /// collected, with why, and never contacted; inactive ones aren't
    /// listed.
    #[test]
    fn skipped_and_unreached_computers_say_why() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let computer = |name: &str, sid: &str, active: bool| {
            let mut v = serde_json::to_value(Computer::default()).unwrap();
            v["Properties"]["name"] = name.into();
            v["Properties"]["enabled"] = active.into();
            v["Properties"]["is_dc"] = false.into();
            v["Properties"]["pwdlastset"] = (now - 86_400).into();
            v["ObjectIdentifier"] = sid.into();
            serde_json::from_value::<Computer>(v).unwrap()
        };
        let mut computers = vec![
            computer("WS1.NORTH.LOCAL", "S-1-5-21-1-2-3-1101", true),
            computer("WS2.NORTH.LOCAL", "S-1-5-21-1-2-3-1102", true),
            computer("OLD.NORTH.LOCAL", "S-1-5-21-1-2-3-1103", false),
        ];
        let skipped: Skipped = [("S-1-5-21-1-2-3-1101".to_string(), Skip::NoName)].into();
        let k = KerberosSignIn {
            // Never used: no computer here is contacted.
            ccache: "FILE:nowhere".into(),
            kdc: "127.0.0.1:1".into(),
        };
        let (tx, rx) = mpsc::channel();
        let plan = Plan {
            k: &k,
            domain: "north.local",
            smb_domain: "north.local",
            user: "collector",
            netbios: vec![NetbiosName {
                dns: "north.local".into(),
                netbios: "NORTH".into(),
            }],
            already: Default::default(),
            until: Instant::now() + STEP_BUDGET,
        };
        let s = run(collect(plan, &mut computers, &skipped, &tx));
        assert_eq!(s.hosts.len(), 2);
        assert_eq!(
            s.hosts[0].services.reason.as_deref(),
            Some("skipped: the domain has no Kerberos name for it")
        );
        assert_eq!(s.hosts[1].services.reason.as_deref(), Some("not reached"));
        assert_eq!(s.services.status, CheckStatus::NotCollected);
        assert_eq!(
            s.services.reason.as_deref(),
            Some("no computer could be read")
        );
        assert_eq!(s.netbios.len(), 1);
        let said: Vec<String> = rx
            .try_iter()
            .filter_map(|m| match m {
                Msg::Warning(w) => Some(w),
                _ => None,
            })
            .collect();
        assert_eq!(
            said,
            [
                "Services weren't read on 2 of 2 computers, so findings that rest on them can't be \
              confirmed fixed. The collection log names each one."
            ]
        );
    }

    #[test]
    fn the_file_name_is_the_one_analysis_reads() {
        assert!(pathwarden_core::storedcreds::is_sidecar_name(SIDECAR_FILE));
        let s = not_read("north.contoso.local", Vec::new(), NO_KERBEROS);
        let text = serde_json::to_vec(&s).unwrap();
        let mut notes = Vec::new();
        let back = Sidecar::parse(&text, &mut notes).unwrap();
        assert_eq!(back.services.status, CheckStatus::NotCollected);
        assert!(notes.is_empty());
        // Turned off: said so, for "off" rather than 0%.
        let off = turned_off("north.contoso.local", Vec::new());
        let back = Sidecar::parse(&serde_json::to_vec(&off).unwrap(), &mut notes).unwrap();
        assert!(back.turned_off);
        assert_eq!(back.services.reason.as_deref(), Some(TURNED_OFF));
        // The flag reaches the request; on by default.
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
        assert!(req(&[]).service_reads);
        assert!(!req(&["--no-service-reads"]).service_reads);
    }
}
