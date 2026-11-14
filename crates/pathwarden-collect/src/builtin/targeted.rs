//! The built-in side of [`crate::refresh_objects`]: bind as a collection
//! does ([`super::open`]), then search every naming context with the
//! targeted filter (LDAP only) and parse what comes back as a collection
//! does ([`super::read_directory`], the checker), so the objects are written
//! exactly as in a full collection. A search the domain controller ends
//! with an error fails the re-read.
//!
//! An object asked for that the search didn't return is looked up on its
//! own, by `<SID=...>` or `<GUID=...>` with the show-deleted control: it
//! counts as deleted only when the directory answers noSuchObject or with
//! its tombstone ([`Refreshed::deleted`]). Otherwise it may be hidden from
//! this account, and the retest can't call it gone.
//!
//! With computers to read ([`crate::RefreshTarget::hosts`]), only those
//! computers are contacted after the objects: the sessions
//! module (SRVSVC, WKSSVC, Remote Registry) on the ones whose sessions are
//! wanted, the local groups module (SAMR) on the ones whose local groups
//! are, signing in over SMB as a Full collection does
//! ([`super::smb_signin`]). Nothing else (SYSVOL, WebClient, the CAs'
//! registry) is read. Each module gives every computer its own time limit
//! (a port 445 check, then eight seconds for its calls).
//!
//! As the current Windows account (Windows only), the same computers are
//! read through Windows' own calls instead (`winhosts`), with the same
//! limits, and written into them as the modules write them
//! ([`crate::refresh::host_reader`] picks which).
//!
//! For a finding that rests on a password a computer stores (PW-033),
//! the computers that store it get their services and scheduled tasks read
//! again, as a Full collection reads them (each with its own switch): over
//! Kerberos with a user and password ([`super::storedcreds`],
//! [`super::tasks`]), or as the Windows account through Remote Registry and
//! UNC paths after the `winkrb` check (`winhosts`). What was read goes into
//! the re-read's zip as `pathwarden-storedcreds.json`, so the analysis
//! reads it as it reads a collection's.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use pathwarden_core::storedcreds::{
    account_ref, AccountRef, HostRecord, NetbiosName, Sidecar, SCHEMA,
};
use pathwarden_core::sysvol::{Check, CheckStatus};

use rusthound_ce::args::CollectionMethod;
use rusthound_ce::objects::computer::Computer;

use super::{
    base_options, checker, close, domain_dn, hostauth, hosts, is_dns_partition, job_for,
    kerberos_hosts, log_bridge, open, own_realm_for, read_in_memory, smb_signin, sysvol,
    who_am_i_answer, BusyGuard, Msg, Signing, BUSY,
};
use crate::output::{self, Snapshot};
#[cfg(windows)]
use crate::refresh::HostReader;
use crate::refresh::{HostRead, Refreshed, SliceHost};
use crate::{CollectRequest, ConnectionError};

/// A targeted re-collection reads a handful of objects; give up after this.
const TIMEOUT: Duration = Duration::from_secs(120);
/// With computers to read (each module has a per-computer limit, ten at a
/// time): give up after this.
const HOSTS_TIMEOUT: Duration = Duration::from_secs(240);
/// The computers are read until this long before [`HOSTS_TIMEOUT`],
/// leaving time to write the collection (as the Windows account; and the
/// services and tasks over Kerberos).
const WRITE_MARGIN: Duration = Duration::from_secs(20);
/// Over Kerberos, computers whose services and tasks are read at once (a
/// Full collection's number).
const STORED_AT_ONCE: usize = 16;
/// Computers whose account password is older than this are probably gone
/// and aren't contacted, as the modules do.
const EXPIRY_DAYS: i64 = 60;
/// Over Kerberos, the services and tasks of the computers are read until
/// this long after they start (each computer with its own limit too).
const STORED_TIME: Duration = Duration::from_secs(150);
/// Why a computer's stored passwords can't be checked without the forest's
/// NetBIOS names: a `DOMAIN\user` account wouldn't be recognized.
const NO_NETBIOS: &str = "The forest's NetBIOS names couldn't be read.";

/// What a re-read reads of the computers' stored credentials: which
/// of the two (the collection's switches), and the forest's NetBIOS names
/// for the file.
pub(crate) struct StoredPlan {
    pub reads: super::sysvol::Reads,
    pub netbios: Vec<NetbiosName>,
    /// Nothing is read after this: the re-read's time less the time to
    /// write it.
    pub until: Instant,
}

/// How the computers are read.
pub(crate) enum HostSource<'a> {
    /// Over SMB with the request's user and password (RustHound-CE's
    /// sessions and local groups modules).
    Smb(&'a hosts::SmbIdentity),
    /// As the signed-in Windows account, until `deadline`. With
    /// `kerberos_only`, a computer Windows gets no Kerberos ticket
    /// for is skipped.
    #[cfg(windows)]
    Windows {
        api: std::sync::Arc<dyn super::winhosts::HostApi>,
        deadline: Instant,
        kerberos_only: bool,
    },
}

pub(crate) fn run(
    req: &CollectRequest,
    filter: &str,
    ids: &[String],
    hosts: &[SliceHost],
) -> anyhow::Result<Refreshed> {
    if BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!("a built-in collection is already running in this process");
    }
    let _busy = BusyGuard;
    #[cfg_attr(not(windows), allow(unused_variables))]
    let started = Instant::now();
    // Created private to this account if it doesn't exist (the UI passes a
    // folder in its private workspace).
    output::prepare_dir(&req.output_dir)?;
    let before = Snapshot::take(&req.output_dir);
    // How the computers are read, if any are asked for.
    let reader = if hosts.is_empty() {
        None
    } else {
        crate::refresh::host_reader(&req.auth)
    };
    // LDAP only: no SMB, so no password is handed to RustHound-CE. With
    // computers and a password, the password goes to the SMB modules as in
    // a Full collection.
    let method = if reader.is_none() {
        CollectionMethod::LdapOnly
    } else {
        CollectionMethod::All
    };
    let job = job_for(req, method.clone()).map_err(anyhow::Error::msg)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let limit = if reader.is_none() {
        TIMEOUT
    } else {
        HOSTS_TIMEOUT
    };
    // Required SMB signing for the computers.
    let signing = Signing::require(!job.allow_unsigned_smb);
    // Why the re-read stopped before reading computers, in plain words.
    let mut refused: Option<ConnectionError> = None;
    // Stored credentials to read, with each of the collection's
    // switches.
    let stored_wanted = reader.is_some() && hosts.iter().any(SliceHost::stored);
    let reads = super::sysvol::Reads {
        services: job.service_reads,
        tasks: job.task_reads,
    };
    let result = runtime.block_on(async {
        let work = async {
            let (mut ldap, driver, dc_fqdn, contexts) = open(&job, &|_| {}, &|_| {}).await?;
            let mut options = base_options(
                &job.domain,
                &job.out_dir,
                method.clone(),
                dc_fqdn.clone(),
                job.ldaps,
            );
            options.ldap_filter = filter.to_string();
            let domain_nc = contexts
                .domain
                .clone()
                .unwrap_or_else(|| domain_dn(&job.domain));
            // The forest's NetBIOS names, for the accounts the computers
            // store (`DOMAIN\user`).
            let netbios = match (&contexts.configuration, stored_wanted) {
                (Some(config), true) => super::forest_netbios(&mut ldap, config).await,
                _ => Vec::new(),
            };
            let stored = StoredPlan {
                reads,
                netbios,
                until: started + HOSTS_TIMEOUT - WRITE_MARGIN,
            };
            let r = match reader {
                None => match read_objects(&mut ldap, &options, &domain_nc, ids).await {
                    Ok((ad, deleted)) => rusthound_ce::make_result(&options, ad)
                        .map(|_| (Vec::new(), deleted))
                        .map_err(|e| format!("cannot write the collection: {e}")),
                    Err(e) => Err(e),
                },
                #[cfg(windows)]
                Some(HostReader::WindowsAccount) => {
                    // No SMB sign-in and no password: Windows signs in to
                    // each computer as this account.
                    let source = HostSource::Windows {
                        api: std::sync::Arc::new(super::winnet::WinNet),
                        deadline: started + HOSTS_TIMEOUT - WRITE_MARGIN,
                        kerberos_only: !job.allow_ntlm,
                    };
                    with_hosts(&mut ldap, &options, source, &domain_nc, ids, hosts, stored).await
                }
                Some(_) => {
                    let answer = who_am_i_answer(&mut ldap).await;
                    let mut smb = smb_signin(
                        &job,
                        &mut ldap,
                        answer.as_deref(),
                        contexts.configuration.as_deref(),
                        &domain_nc,
                        &|_| {},
                        &mut options,
                    )
                    .await;
                    // Kerberos only: a ticket from the verified DC,
                    // or the account's own domain's, or nothing is
                    // read.
                    let own_realm = own_realm_for(
                        &job,
                        &mut ldap,
                        &smb,
                        contexts.configuration.as_deref(),
                        &domain_nc,
                    )
                    .await;
                    let r = match kerberos_hosts(
                        &job,
                        &dc_fqdn,
                        answer.as_deref(),
                        own_realm,
                        &mut smb,
                        &mut options,
                        &|_| {},
                    )
                    .await
                    {
                        Ok(guard) => {
                            let r = with_hosts(
                                &mut ldap,
                                &options,
                                HostSource::Smb(&smb),
                                &domain_nc,
                                ids,
                                hosts,
                                stored,
                            )
                            .await;
                            drop(guard);
                            r
                        }
                        Err(why) => {
                            let message = why.message();
                            refused = Some(why);
                            Err(message)
                        }
                    };
                    if let Some(mut p) = options.password.take() {
                        zeroize::Zeroize::zeroize(&mut p);
                    }
                    r
                }
            };
            close(ldap, driver).await;
            r.map(|reads| (dc_fqdn, reads))
        };
        tokio::time::timeout(limit, work).await.unwrap_or_else(|_| {
            Err(format!(
                "timeout: no answer within {} minutes",
                limit.as_secs() / 60
            ))
        })
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    drop(signing);
    drop(job);
    if let (Err(_), Some(why)) = (&result, refused) {
        output::remove_new_outputs(&req.output_dir, &before);
        return Err(why.into());
    }
    match result {
        Ok((server, (reads, deleted))) => {
            let files = output::discover_outputs(&req.output_dir, &before);
            output::restrict_permissions(&files);
            if files.is_empty() {
                anyhow::bail!("the re-read wrote no files");
            }
            Ok(Refreshed {
                files,
                server: Some(server),
                hosts: reads,
                deleted,
            })
        }
        Err(e) => {
            output::remove_new_outputs(&req.output_dir, &before);
            Err(anyhow::anyhow!(e))
        }
    }
}

/// Whether `c`'s sessions (or local groups) are wanted.
fn wants(want: &HashMap<&str, &SliceHost>, c: &Computer, sessions: bool) -> bool {
    want.get(c.object_identifier().as_str()).is_some_and(|h| {
        if sessions {
            h.sessions
        } else {
            h.local_groups
        }
    })
}

/// Most objects the search didn't return that are looked up on their own.
const MAX_LOOKUPS: usize = 64;

/// Reads the filter's objects into memory and parses them as a collection
/// does; and of `ids` (the objects asked for), those the search didn't
/// return that the directory says are deleted. A search cut short fails.
async fn read_objects(
    ldap: &mut ldap3::Ldap,
    options: &rusthound_ce::args::Options,
    domain_nc: &str,
    ids: &[String],
) -> Result<(rusthound_ce::api::ADResults, Vec<String>), String> {
    // Progress goes nowhere: a retest shows only its result. A search cut
    // short is an error, never a line in a log nobody reads.
    let (tx, _rx) = mpsc::channel::<Msg>();
    let mut timings = super::timings::Timings::default();
    let contexts: Vec<String> = rusthound_ce::transport::ldap::get_all_naming_contexts(ldap)
        .await
        .map_err(|e| format!("re-reading the objects failed: {e}"))?
        .into_iter()
        .filter(|nc| !is_dns_partition(nc))
        .collect();
    // A filtered read is small: in memory.
    let entries = read_in_memory(
        ldap,
        &options.ldap_filter,
        &contexts,
        domain_nc,
        &tx,
        &mut timings,
    )
    .await
    .map_err(|e| format!("re-reading the objects failed: {e}"))?;
    let missing = not_returned(ids, &entries);
    let mut deleted = Vec::new();
    for id in missing.into_iter().take(MAX_LOOKUPS) {
        if lookup(ldap, id).await == Lookup::Deleted {
            deleted.push(id.clone());
        }
    }
    let mut ad = rusthound_ce::api::parse_result_type_from_source(options, entries, None)
        .map_err(|e| format!("re-reading the objects failed: {e}"))?;
    checker::check_all(options, &mut ad)
        .map_err(|e| format!("re-reading the objects failed: {e}"))?;
    Ok((ad, deleted))
}

/// Of `ids` (SIDs or GUIDs), those no entry has as its `objectSid` or
/// `objectGUID`.
fn not_returned<'a>(
    ids: &'a [String],
    entries: &[rusthound_ce::transport::ldap::LdapSearchEntry],
) -> Vec<&'a String> {
    let mut have = std::collections::HashSet::new();
    for e in entries {
        for (k, values) in &e.bin_attrs {
            let id = if k.eq_ignore_ascii_case("objectSid") {
                values.first().and_then(|b| crate::refresh::sid_string(b))
            } else if k.eq_ignore_ascii_case("objectGUID") {
                values.first().and_then(|b| crate::refresh::guid_string(b))
            } else {
                None
            };
            if let Some(id) = id {
                have.insert(id.to_ascii_uppercase());
            }
        }
    }
    ids.iter()
        .filter(|id| !have.contains(&id.trim().to_ascii_uppercase()))
        .collect()
}

/// What looking up one object the search didn't return found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// noSuchObject, or its tombstone: deleted.
    Deleted,
    /// There, though the search didn't return it: hidden from this account
    /// (or changed since), so nothing is known.
    There,
    /// The lookup failed: nothing is known.
    Unknown,
}

/// Looks up `id` (a SID or a GUID) by `<SID=...>` or `<GUID=...>`, Base
/// scope, with the show-deleted control.
async fn lookup(ldap: &mut ldap3::Ldap, id: &str) -> Lookup {
    let id = id.trim();
    let dn = if id.starts_with("S-") {
        format!("<SID={id}>")
    } else {
        format!("<GUID={id}>")
    };
    let what = format!("looking up {dn}");
    let search = async {
        ldap.with_controls(vec![super::show_deleted_control()])
            .search(
                &dn,
                ldap3::Scope::Base,
                "(objectClass=*)",
                vec!["isDeleted"],
            )
            .await
    };
    match super::or_stalled(Duration::from_secs(30), &what, search).await {
        Ok(ldap3::SearchResult(entries, res)) => lookup_answer(
            res.rc,
            entries
                .into_iter()
                .next()
                .map(ldap3::SearchEntry::construct)
                .as_ref(),
        ),
        Err(_) => Lookup::Unknown,
    }
}

/// [`Lookup`] from a lookup's result code and entry.
pub(crate) fn lookup_answer(rc: u32, entry: Option<&ldap3::SearchEntry>) -> Lookup {
    const NO_SUCH_OBJECT: u32 = 32;
    match (rc, entry) {
        (NO_SUCH_OBJECT, _) => Lookup::Deleted,
        (0, Some(e)) => {
            let tombstone = e.attrs.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("isDeleted")
                    && v.iter().any(|x| x.eq_ignore_ascii_case("TRUE"))
            });
            if tombstone {
                Lookup::Deleted
            } else {
                Lookup::There
            }
        }
        _ => Lookup::Unknown,
    }
}

/// Reads the filter's objects, then the sessions and local groups (and,
/// where the finding rests on them, the services and scheduled tasks) of
/// just the computers in `hosts`, and writes the collection. Returns what
/// was read of each of those computers (one per entry of `hosts`; a
/// computer the directory doesn't have is not read), and the objects of
/// `ids` the directory says are deleted ([`read_objects`]).
async fn with_hosts(
    ldap: &mut ldap3::Ldap,
    options: &rusthound_ce::args::Options,
    source: HostSource<'_>,
    domain_nc: &str,
    ids: &[String],
    wanted: &[SliceHost],
    stored: StoredPlan,
) -> Result<(Vec<HostRead>, Vec<String>), String> {
    let (tx, _rx) = mpsc::channel::<Msg>();
    let (mut ad, deleted) = read_objects(ldap, options, domain_nc, ids).await?;
    // Every computer read stays "not contacted" but those asked for.
    hosts::mark_sessions_not_collected(&mut ad.computers, hosts::NOT_CONTACTED);
    let want: HashMap<&str, &SliceHost> = wanted.iter().map(|h| (h.id.as_str(), h)).collect();

    let (contact, mut group_errors, mut records) =
        only_in_domain(&mut ad.computers, &want, &options.domain, stored.reads);

    let (errors, read) = match source {
        HostSource::Smb(smb) => smb_reads(options, smb, &mut ad, &contact, &stored, &tx).await?,
        #[cfg(windows)]
        HostSource::Windows {
            api,
            deadline,
            kerberos_only,
        } => {
            windows_reads(
                options,
                api,
                deadline,
                kerberos_only,
                stored.reads,
                &mut ad,
                &contact,
            )
            .await?
        }
    };
    group_errors.extend(errors);
    records.extend(read);
    if stored.netbios.is_empty() {
        for r in records.iter_mut() {
            needs_netbios(r);
        }
    }

    let mut reads: Vec<HostRead> = Vec::new();
    for c in ad.computers.iter_mut() {
        if let Some(h) = want.get(c.object_identifier().as_str()) {
            let mut read = hosts::host_read(c, h, &group_errors);
            let id = c.object_identifier().clone();
            stored_read(&mut read, h, records.iter().find(|r| r.id == id));
            reads.push(read);
        }
    }
    let zip = rusthound_ce::make_result(options, ad)
        .map_err(|e| format!("cannot write the collection: {e}"))?;
    if wanted.iter().any(SliceHost::stored) {
        // Without the file the re-read computers would look clean: the
        // retest fails instead.
        let s = sidecar(&options.domain, stored, records);
        super::storedcreds::append_to(&s, std::path::Path::new(&zip))
            .map_err(|e| format!("cannot write the services and tasks read: {e}"))?;
    }
    Ok((reads, deleted))
}

/// Of the computers `want`ed, those a retest may contact, whichever way
/// they are read: only names the directory gives them in `domain` (never
/// an IP address, `localhost` or a name elsewhere, [`hosts::contactable`]).
/// The others are marked not collected, with why, and left out. Returns
/// the computers to contact, the reasons, and the services and tasks
/// records of those left out.
fn only_in_domain<'a>(
    computers: &mut [Computer],
    want: &HashMap<&'a str, &'a SliceHost>,
    domain: &str,
    reads: super::sysvol::Reads,
) -> (
    HashMap<&'a str, &'a SliceHost>,
    Vec<String>,
    Vec<HostRecord>,
) {
    let mut contact = want.clone();
    let mut errors = Vec::new();
    let mut records: Vec<HostRecord> = Vec::new();
    for c in computers.iter_mut() {
        let id = c.object_identifier().clone();
        let Some(h) = want.get(id.as_str()) else {
            continue;
        };
        let name = c.properties().name().clone();
        if hosts::contactable(&name, domain) {
            continue;
        }
        let why = format!("{name}: {}", hosts::NOT_IN_DOMAIN);
        if h.sessions {
            hosts::mark_sessions_not_collected(std::slice::from_mut(c), &why);
        }
        if h.stored() {
            records.push(not_read_record(c, reads, &why));
        }
        errors.push(why);
        contact.remove(id.as_str());
    }
    (contact, errors, records)
}

/// The re-read's `pathwarden-storedcreds.json`: the computers asked for,
/// each with its status, and the steps as a whole, as a Full collection
/// writes it (a switch that was off says so).
fn sidecar(domain: &str, plan: StoredPlan, records: Vec<HostRecord>) -> Sidecar {
    use super::storedcreds::{sum_up, TURNED_OFF};
    let services = if plan.reads.services {
        sum_up(&records.iter().map(|r| &r.services).collect::<Vec<_>>())
    } else {
        super::storedcreds::not_collected(TURNED_OFF)
    };
    let tasks = if plan.reads.tasks {
        let parts: Vec<&Check> = records.iter().filter_map(|r| r.tasks.as_ref()).collect();
        sum_up(&parts)
    } else {
        super::storedcreds::not_collected(super::tasks::TURNED_OFF)
    };
    Sidecar {
        schema: SCHEMA.into(),
        domain: domain.to_string(),
        netbios: plan.netbios,
        services,
        turned_off: !plan.reads.services,
        tasks: Some(tasks),
        tasks_turned_off: !plan.reads.tasks,
        hosts: records,
    }
}

/// `c`'s record when its services and tasks weren't read, for `why` (a
/// part whose switch is off says so instead).
fn not_read_record(c: &Computer, reads: super::sysvol::Reads, why: &str) -> HostRecord {
    let part = |on: bool, off: &str| super::storedcreds::not_collected(if on { why } else { off });
    HostRecord {
        id: c.object_identifier().clone(),
        name: c.properties().name().clone(),
        services: part(reads.services, super::storedcreds::TURNED_OFF),
        tasks: Some(part(reads.tasks, super::tasks::TURNED_OFF)),
        stored: Vec::new(),
    }
}

/// Without the forest's NetBIOS names, a `DOMAIN\user` account the
/// computer stores might not be recognized, and a computer that still
/// stores the password would look clean: a read that found one counts as
/// partial.
fn needs_netbios(r: &mut HostRecord) {
    let by_name = |via| {
        r.stored.iter().any(|s| {
            s.via == via && matches!(account_ref(&s.account), Some(AccountRef::Domain { .. }))
        })
    };
    let (services, tasks) = (
        by_name(pathwarden_core::storedcreds::Via::Service),
        by_name(pathwarden_core::storedcreds::Via::Task),
    );
    let partial = |c: &mut Check| {
        if c.status == CheckStatus::Complete {
            c.status = CheckStatus::Partial;
            c.reason = Some(NO_NETBIOS.into());
        }
    };
    if services {
        partial(&mut r.services);
    }
    if tasks {
        if let Some(t) = r.tasks.as_mut() {
            partial(t);
        }
    }
}

/// Adds to `read` how far the services and tasks of its computer were read
/// (`rec`), when the finding rests on a password it stores (`h`): each
/// read in full or not, and, when nothing else said why, why the first
/// that wasn't. Both count, whichever stored the password in the run: it
/// may have moved from one to the other.
fn stored_read(read: &mut HostRead, h: &SliceHost, rec: Option<&HostRecord>) {
    if !h.stored() {
        return;
    }
    let services = rec.map(|r| &r.services);
    let tasks = rec.and_then(|r| r.tasks.as_ref());
    let full = |c: Option<&Check>| c.is_some_and(|c| c.status == CheckStatus::Complete);
    read.services = Some(full(services));
    read.tasks = Some(full(tasks));
    if read.why.is_some() {
        return;
    }
    let missing = [("services", services), ("scheduled tasks", tasks)]
        .into_iter()
        .find(|(_, c)| !full(*c));
    let Some((part, check)) = missing else {
        return;
    };
    let (why, unreachable, skipped) = stored_why(&read.name, part, check);
    read.why = Some(why);
    read.unreachable = unreachable;
    read.skipped = skipped;
}

/// Why a computer's `part` (its services, its scheduled tasks) wasn't
/// read in full, for the retest: a sentence, or the computer's reason in
/// the words the other reads use. Whether it didn't answer, and whether
/// it was skipped.
fn stored_why(host: &str, part: &str, check: Option<&Check>) -> (String, bool, bool) {
    let Some(c) = check else {
        return (format!("Its {part} weren't read."), false, false);
    };
    let reason = c.reason.as_deref().unwrap_or_default();
    if reason == super::storedcreds::TURNED_OFF || reason == super::tasks::TURNED_OFF {
        let switch = if part == "services" {
            "service"
        } else {
            "task"
        };
        return (
            format!("Its {part} weren't checked, because {switch} reads are turned off."),
            false,
            false,
        );
    }
    if c.status == CheckStatus::Partial {
        if reason == NO_NETBIOS {
            return (NO_NETBIOS.into(), false, false);
        }
        let why = reason.trim_end_matches('.');
        return (
            format!("Its {part} were read only in part: {why}."),
            false,
            false,
        );
    }
    let (words, unreachable) = hosts::reason_on(host, reason);
    let words = match words {
        "access denied" if reason.starts_with("Remote Registry") => {
            "Remote Registry refused access."
        }
        "access denied" if reason.starts_with("C$") => "The C$ share refused access.",
        w => w,
    };
    (
        words.to_string(),
        unreachable,
        hosts::skip_of(reason).is_some(),
    )
}

/// The sessions and local groups modules over SMB, on the computers whose
/// sessions or local groups are wanted, then the services and scheduled
/// tasks over Kerberos of those whose stored credentials are
/// ([`stored_reads`]).
/// Returns what the local groups module logged, and the stored credentials
/// records.
async fn smb_reads(
    options: &rusthound_ce::args::Options,
    smb: &hosts::SmbIdentity,
    ad: &mut rusthound_ce::api::ADResults,
    want: &HashMap<&str, &SliceHost>,
    stored: &StoredPlan,
    tx: &mpsc::Sender<Msg>,
) -> Result<(Vec<String>, Vec<HostRecord>), String> {
    // Kerberos only: a computer without a ticket is never contacted;
    // why goes into its sessions and the local groups' errors.
    let mut skipped = hostauth::Skipped::new();
    let mut group_errors = Vec::new();
    // The modules' KDC, until they finish.
    let mut relay = None;
    if let Some(k) = &smb.kerberos {
        hostauth::ccache_ready(k)?;
        relay = Some(hostauth::relay(k, tx).await?);
        let asked = |c: &Computer| {
            wants(want, c, true)
                || wants(want, c, false)
                || want
                    .get(c.object_identifier().as_str())
                    .is_some_and(|h| h.stored())
        };
        skipped = hostauth::precheck(k, &mut ad.computers, &asked, tx).await;
        for c in ad.computers.iter_mut() {
            if skipped.contains_key(c.object_identifier().as_str()) {
                group_errors.extend(hosts::session_reasons(c).into_iter().take(1));
            }
        }
    }
    let skip = |c: &Computer| skipped.contains_key(c.object_identifier().as_str());

    // Sessions, on the computers whose sessions are wanted.
    let (picked, mut rest): (Vec<_>, Vec<_>) = std::mem::take(&mut ad.computers)
        .into_iter()
        .partition(|c| wants(want, c, true) && !skip(c));
    ad.computers = picked;
    if !ad.computers.is_empty() {
        let mut first = super::krbrelay::via(relay.as_ref(), &smb.options(options));
        first.collection_method = CollectionMethod::Session;
        hosts::mark_sessions_not_collected(&mut ad.computers, hosts::NOT_ATTEMPTED);
        log_bridge::start_capture(hosts::SESSIONS_LOG_TARGET);
        let ran = rusthound_ce::modules::session::run(&first, &ad.users, &mut ad.computers).await;
        let errors = log_bridge::take_capture();
        if let Err(e) = ran {
            ad.computers.append(&mut rest);
            return Err(format!("reading sessions failed: {e}"));
        }
        hosts::apply_session_errors(&mut ad.computers, errors.as_deref());
        let retried = sysvol::retry_starting_registry(&first, ad, tx).await;
        if let (Some(k), Ok(())) = (&smb.kerberos, &retried) {
            let user = rusthound_ce::transport::smb::smb_identity(
                options.username.as_deref().unwrap_or_default(),
                &smb.domain,
            )
            .1;
            hostauth::registry_sessions(
                k,
                &smb.domain,
                &user,
                &mut ad.computers,
                &skipped,
                None,
                tx,
            )
            .await;
        }
        if let Err(e) = retried {
            ad.computers.append(&mut rest);
            return Err(e);
        }
    }
    ad.computers.append(&mut rest);
    let mut more = hostauth::Skipped::new();
    hostauth::unsigned(&mut ad.computers, &[], &mut more, tx);
    for c in ad.computers.iter_mut() {
        if more.contains_key(c.object_identifier().as_str()) {
            group_errors.extend(hosts::session_reasons(c).into_iter().take(1));
        }
    }
    skipped.extend(more);
    let skip = |c: &Computer| skipped.contains_key(c.object_identifier().as_str());

    // Local groups, on the computers whose local groups are wanted.
    let (picked, mut rest): (Vec<_>, Vec<_>) = std::mem::take(&mut ad.computers)
        .into_iter()
        .partition(|c| wants(want, c, false) && !skip(c));
    ad.computers = picked;
    if !ad.computers.is_empty() {
        log_bridge::start_capture(sysvol::LOCAL_GROUPS_LOG_TARGET);
        let groups = super::krbrelay::via(relay.as_ref(), options);
        let ran = sysvol::local_groups(&groups, smb, ad, tx).await;
        let errors = log_bridge::take_capture().unwrap_or_default();
        if let Err(e) = ran {
            ad.computers.append(&mut rest);
            return Err(e);
        }
        // A computer whose replies weren't signed: its local groups error
        // says so in the skip's words.
        for e in errors {
            let unsigned = e.contains(hosts::UNSIGNED_REPLY);
            if unsigned || e.contains(hosts::OTHER_REPLY) {
                let host = e.split(':').next().unwrap_or_default().trim();
                let detail = e
                    .find("SMB2 ")
                    .map(|at| e[at..].trim().to_string())
                    .unwrap_or_else(|| e.clone());
                group_errors.push(if unsigned {
                    hosts::skipped_unsigned(host, &detail)
                } else {
                    hosts::skipped_bad_reply(host, &detail)
                });
            } else {
                group_errors.push(e);
            }
        }
    }
    ad.computers.append(&mut rest);
    let records = stored_reads(options, smb, ad, want, stored, &skipped).await;
    Ok((group_errors, records))
}

/// The services and scheduled tasks of the computers whose stored
/// credentials are wanted, as a Full collection reads them: over Kerberos
/// only ([`super::storedcreds::read_host`], [`super::tasks::read_host`]),
/// each with its switch, never on a skipped, disabled or long-unused
/// computer. With NTLM, nothing is read and each says why.
async fn stored_reads(
    options: &rusthound_ce::args::Options,
    smb: &hosts::SmbIdentity,
    ad: &mut rusthound_ce::api::ADResults,
    want: &HashMap<&str, &SliceHost>,
    plan: &StoredPlan,
    skipped: &super::hostauth::Skipped,
) -> Vec<HostRecord> {
    let reads = plan.reads;
    let mut records = Vec::new();
    let mut ask: Vec<(usize, String)> = Vec::new();
    for c in ad.computers.iter_mut() {
        let id = c.object_identifier().clone();
        if !want.get(id.as_str()).is_some_and(|h| h.stored()) {
            continue;
        }
        let why = if let Some(s) = skipped.get(id.as_str()) {
            Some(super::storedcreds::skip_words(s))
        } else if !c.is_active(EXPIRY_DAYS) {
            Some(hosts::NOT_ATTEMPTED.to_string())
        } else if smb.kerberos.is_none() {
            Some(super::storedcreds::NO_KERBEROS.to_string())
        } else {
            None
        };
        if let Some(why) = why {
            records.push(not_read_record(c, reads, &why));
        } else {
            records.push(not_read_record(c, reads, "not read"));
            ask.push((records.len() - 1, c.properties().name().clone()));
        }
    }
    let Some(k) = smb.kerberos.as_ref().filter(|_| !ask.is_empty()) else {
        return records;
    };
    let user = rusthound_ce::transport::smb::smb_identity(
        options.username.as_deref().unwrap_or_default(),
        &smb.domain,
    )
    .1;
    // Within the re-read's own time, less the time to write it.
    let until = (Instant::now() + STORED_TIME).min(plan.until);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(STORED_AT_ONCE));
    let mut set = tokio::task::JoinSet::new();
    for (i, host) in ask {
        let (k, domain, user) = (k.clone(), smb.domain.clone(), user.clone());
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let late = || super::storedcreds::not_collected(super::storedcreds::OUT_OF_TIME);
            // A walk stops itself at `until`; this is for a call that hangs.
            let at = tokio::time::Instant::from_std(until + Duration::from_secs(5));
            let services = if reads.services {
                let read = super::storedcreds::read_host(&host, &k, &domain, &user, until);
                Some(
                    tokio::time::timeout_at(at, read)
                        .await
                        .unwrap_or_else(|_| (late(), Vec::new())),
                )
            } else {
                None
            };
            let tasks = if reads.tasks {
                let read = super::tasks::read_host(&host, &k, &domain, &user, until, true);
                Some(
                    tokio::time::timeout_at(at, read)
                        .await
                        .unwrap_or_else(|_| (late(), Vec::new())),
                )
            } else {
                None
            };
            (i, services, tasks)
        });
    }
    while let Some(done) = set.join_next().await {
        // A task that stopped (a panic) stays "not read".
        let Ok((i, services, tasks)) = done else {
            continue;
        };
        let r = &mut records[i];
        if let Some((check, found)) = services {
            r.services = check;
            r.stored.extend(found);
        }
        if let Some((check, found)) = tasks {
            r.tasks = Some(check);
            r.stored.extend(found);
        }
    }
    records
}

/// The same reads as the signed-in Windows account, through Windows' own
/// calls (`winhosts`), on blocking threads until `deadline`. As the
/// modules do, the computers whose sessions are wanted start "not
/// attempted", and disabled or long-unused ones aren't contacted. Host
/// names are the directory's (`dNSHostName`, just re-read). Returns the
/// local groups' errors and the stored credentials records.
///
/// A computer's services and tasks are read only after Windows got
/// its `cifs/` Kerberos ticket (`winkrb`), even with NTLM allowed for its
/// sessions and local groups, as a Full collection reads them only over
/// Kerberos.
#[cfg(windows)]
async fn windows_reads(
    options: &rusthound_ce::args::Options,
    api: std::sync::Arc<dyn super::winhosts::HostApi>,
    deadline: Instant,
    kerberos_only: bool,
    reads: super::sysvol::Reads,
    ad: &mut rusthound_ce::api::ADResults,
    want: &HashMap<&str, &SliceHost>,
) -> Result<(Vec<String>, Vec<HostRecord>), String> {
    use super::winhosts;
    // Kerberos only: the computers Windows gets no cifs/ ticket for
    // are skipped before Windows signs in to any. Those whose stored
    // credentials are wanted are checked either way.
    let names: Vec<String> = ad
        .computers
        .iter()
        .filter(|c| {
            want.get(c.object_identifier().as_str())
                .is_some_and(|h| kerberos_only || h.stored())
        })
        .filter(|c| c.is_active(EXPIRY_DAYS))
        .map(|c| c.properties().name().clone())
        .collect();
    let no_ticket: HashMap<String, String> = if names.is_empty() {
        HashMap::new()
    } else {
        let api = api.clone();
        tokio::task::spawn_blocking(move || {
            names
                .into_iter()
                .filter_map(|n| api.cifs_ticket(&n).err().map(|e| (n, e)))
                .collect()
        })
        .await
        .map_err(|e| format!("asking for Kerberos tickets failed: {e}"))?
    };
    let mut errors = Vec::new();
    let mut records = Vec::new();
    let mut asks = Vec::new();
    let mut at = Vec::new();
    for (i, c) in ad.computers.iter_mut().enumerate() {
        let Some(h) = want.get(c.object_identifier().as_str()) else {
            continue;
        };
        if h.sessions {
            hosts::mark_sessions_not_collected(std::slice::from_mut(c), hosts::NOT_ATTEMPTED);
        }
        if !c.is_active(EXPIRY_DAYS) {
            if h.stored() {
                records.push(not_read_record(c, reads, hosts::NOT_ATTEMPTED));
            }
            continue;
        }
        let name = c.properties().name().clone();
        let mut ask = winhosts::HostAsk {
            name: name.clone(),
            sessions: h.sessions,
            local_groups: h.local_groups,
            services: h.stored() && reads.services,
            tasks: h.stored() && reads.tasks,
        };
        if let Some(why) = no_ticket.get(&name) {
            let reason = why.clone();
            if h.stored() {
                records.push(not_read_record(c, reads, &reason));
                (ask.services, ask.tasks) = (false, false);
            }
            if kerberos_only {
                if h.sessions {
                    hosts::set_all_not_collected(c, &reason);
                }
                errors.push(reason);
                continue;
            }
        } else if h.stored() && !ask.services && !ask.tasks {
            // Both switches off: nothing of it to read.
            records.push(not_read_record(c, reads, "not read"));
        }
        if !(ask.sessions || ask.local_groups || ask.services || ask.tasks) {
            continue;
        }
        asks.push(ask);
        at.push(i);
    }
    if asks.is_empty() {
        return Ok((errors, records));
    }
    let limits = winhosts::Limits::until(deadline);
    let found = tokio::task::spawn_blocking(move || {
        winhosts::read_hosts(api, &asks, limits, &winhosts::ALIVE)
    })
    .await
    .map_err(|e| format!("reading the computers failed: {e}"))??;
    let users = winhosts::SidIndex::new(&ad.users, &options.domain);
    for (i, f) in at.into_iter().zip(&found) {
        let record = winhosts::apply(
            &mut ad.computers[i],
            f,
            &users,
            &ad.mappings.sid_type,
            &options.domain,
        );
        records.extend(record);
        errors.extend(f.group_errors());
    }
    Ok((errors, records))
}

#[cfg(test)]
mod stored_tests {
    use super::*;
    use pathwarden_core::storedcreds::{Stored, Via};

    const HOST: &str = "APP01.NORTH.CONTOSO.LOCAL";

    /// The re-read's computers, as the directory names them, go through
    /// the one filter both ways of reading use: only names in the
    /// collected domain are contacted; an IP address, `localhost`, a UNC
    /// path or a name elsewhere is never handed to a reader, and each one
    /// left out says why in the run.
    #[test]
    fn only_computers_named_in_the_domain_are_contacted() {
        let names = [
            ("S-1-5-21-1-2-3-1101", "WS1.CONTOSO.LOCAL"),
            ("S-1-5-21-1-2-3-1102", "APP01.NORTH.CONTOSO.LOCAL"),
            ("S-1-5-21-1-2-3-1103", "10.0.0.5"),
            ("S-1-5-21-1-2-3-1104", "localhost.contoso.local"),
            ("S-1-5-21-1-2-3-1105", "relay.fabrikam.com"),
            ("S-1-5-21-1-2-3-1106", "\\\\relay\\share"),
            ("S-1-5-21-1-2-3-1107", "WS9.CONTOSO.LOCAL.fabrikam.com"),
            ("S-1-5-21-1-2-3-1108", "CONTOSO.LOCAL"),
        ];
        let mut computers: Vec<Computer> = names
            .iter()
            .map(|(sid, name)| {
                let mut v = serde_json::to_value(Computer::default()).unwrap();
                v["Properties"]["name"] = (*name).into();
                v["Properties"]["is_dc"] = false.into();
                v["ObjectIdentifier"] = (*sid).into();
                serde_json::from_value(v).unwrap()
            })
            .collect();
        let wanted: Vec<SliceHost> = names
            .iter()
            .map(|(sid, _)| SliceHost {
                id: (*sid).into(),
                sessions: true,
                local_groups: true,
                services: true,
                tasks: false,
            })
            .collect();
        let want: HashMap<&str, &SliceHost> = wanted.iter().map(|h| (h.id.as_str(), h)).collect();
        let reads = super::super::sysvol::Reads {
            services: true,
            tasks: true,
        };
        let (contact, errors, records) =
            only_in_domain(&mut computers, &want, "contoso.local", reads);
        let mut ids: Vec<&str> = contact.keys().copied().collect();
        ids.sort_unstable();
        assert_eq!(ids, ["S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1102"]);
        assert_eq!(errors.len(), 6, "{errors:?}");
        for (_, name) in &names[2..] {
            let why = format!("{name}: {}", hosts::NOT_IN_DOMAIN);
            assert!(errors.contains(&why), "{name}: {errors:?}");
        }
        // Their services are recorded as not read, with the reason.
        assert_eq!(records.len(), 6);
        assert!(records
            .iter()
            .all(|r| r.services.status != CheckStatus::Complete));
    }

    fn record(services: Check, tasks: Check) -> HostRecord {
        HostRecord {
            id: "S-1-5-21-1-2-3-1104".into(),
            name: HOST.into(),
            services,
            tasks: Some(tasks),
            stored: Vec::new(),
        }
    }

    fn complete() -> Check {
        Check {
            status: CheckStatus::Complete,
            ..Check::default()
        }
    }

    fn not(why: &str) -> Check {
        super::super::storedcreds::not_collected(why)
    }

    fn host(services: bool, tasks: bool) -> SliceHost {
        SliceHost {
            id: "S-1-5-21-1-2-3-1104".into(),
            services,
            tasks,
            ..SliceHost::default()
        }
    }

    fn read_of(h: &SliceHost, rec: Option<&HostRecord>) -> HostRead {
        let mut r = HostRead {
            id: h.id.clone(),
            name: HOST.into(),
            ..HostRead::default()
        };
        stored_read(&mut r, h, rec);
        r
    }

    /// What a retest is told of a computer's services and tasks: each read
    /// in full or not, and why the part the finding rests on wasn't, in
    /// the retest's words.
    #[test]
    fn a_computers_stored_reads_tell_the_retest_why() {
        // Both read in full.
        let r = read_of(&host(true, false), Some(&record(complete(), complete())));
        assert_eq!((r.services, r.tasks, r.why), (Some(true), Some(true), None));

        // The services denied; the finding rests on them.
        let rec = record(not("Remote Registry: access denied"), complete());
        let r = read_of(&host(true, false), Some(&rec));
        assert_eq!(r.services, Some(false));
        assert_eq!(r.why.as_deref(), Some("Remote Registry refused access."));
        assert!(!r.unreachable && !r.skipped);
        // ... or on the tasks only: the services are a gap all the same
        // (the password may have moved there).
        let r = read_of(&host(false, true), Some(&rec));
        assert_eq!(r.why.as_deref(), Some("Remote Registry refused access."));
        // C$ denied, though the finding rests on a service.
        let rec = record(complete(), not("C$: access denied"));
        let r = read_of(&host(true, false), Some(&rec));
        assert_eq!(r.tasks, Some(false));
        assert_eq!(r.why.as_deref(), Some("The C$ share refused access."));

        // Not answering: unreachable.
        let why = format!("{HOST}: 445/tcp unreachable");
        let r = read_of(&host(true, true), Some(&record(not(&why), not(&why))));
        assert_eq!(r.why.as_deref(), Some("it didn't answer on port 445"));
        assert!(r.unreachable);

        // Skipped with Kerberos only: skipped, and why.
        let why = format!("{HOST}: skipped: the domain has no Kerberos name for it");
        let r = read_of(&host(true, false), Some(&record(not(&why), not(&why))));
        assert!(r.skipped, "{r:?}");
        assert_eq!(
            r.why.as_deref(),
            Some(pathwarden_core::ingest::SKIP_NO_KERBEROS_NAME)
        );

        // A switch off, even for the part the finding doesn't rest on:
        // says that part wasn't checked.
        let rec = record(complete(), not(super::super::tasks::TURNED_OFF));
        let r = read_of(&host(true, false), Some(&rec));
        assert_eq!(r.tasks, Some(false));
        assert_eq!(
            r.why.as_deref(),
            Some("Its scheduled tasks weren't checked, because task reads are turned off.")
        );
        let rec = record(not(super::super::storedcreds::TURNED_OFF), complete());
        let r = read_of(&host(false, true), Some(&rec));
        assert_eq!(
            r.why.as_deref(),
            Some("Its services weren't checked, because service reads are turned off.")
        );

        // Partly read: the read's own reason, in a sentence.
        let partial = Check {
            status: CheckStatus::Partial,
            reason: Some("ran out of time".into()),
            ..Check::default()
        };
        let r = read_of(&host(true, false), Some(&record(partial, complete())));
        assert_eq!(
            r.why.as_deref(),
            Some("Its services were read only in part: ran out of time.")
        );
        let netbios = Check {
            status: CheckStatus::Partial,
            reason: Some(NO_NETBIOS.into()),
            ..Check::default()
        };
        let r = read_of(&host(true, false), Some(&record(netbios, complete())));
        assert_eq!(r.why.as_deref(), Some(NO_NETBIOS));

        // Not in the reads at all; or not resting on stored passwords.
        let r = read_of(&host(true, false), None);
        assert_eq!(
            (r.services, r.why.as_deref()),
            (Some(false), Some("Its services weren't read."))
        );
        let r = read_of(&host(false, false), None);
        assert_eq!((r.services, r.tasks), (None, None));
    }

    /// The re-read's file says what was read, a switch that was off, and
    /// reads back as the analysis reads it.
    #[test]
    fn the_rereads_file_is_a_collections_file() {
        let mut found = record(complete(), not(super::super::tasks::TURNED_OFF));
        found.stored.push(Stored {
            via: Via::Service,
            name: "SqlAgent".into(),
            account: r"NORTH\sql_svc".into(),
            start: Some(2),
            ..Stored::default()
        });
        let plan = StoredPlan {
            reads: super::super::sysvol::Reads {
                services: true,
                tasks: false,
            },
            netbios: vec![NetbiosName {
                dns: "north.contoso.local".into(),
                netbios: "NORTH".into(),
            }],
            until: Instant::now(),
        };
        let s = sidecar("north.contoso.local", plan, vec![found]);
        assert_eq!(s.services.status, CheckStatus::Complete);
        assert!(s.tasks_turned_off && !s.turned_off);
        let mut notes = Vec::new();
        let back = Sidecar::parse(&serde_json::to_vec(&s).unwrap(), &mut notes).unwrap();
        assert_eq!(back.hosts[0].stored.len(), 1);
        assert_eq!(back.netbios.len(), 1);
        assert!(notes.is_empty(), "{notes:?}");
    }

    /// Without the NetBIOS names, a computer that stores a `DOMAIN\user`
    /// account's password can't be told clean: partial. UPNs and SIDs
    /// resolve without them.
    #[test]
    fn without_netbios_names_a_domain_user_is_partial() {
        let stored = |account: &str, via| Stored {
            via,
            name: "x".into(),
            account: account.into(),
            ..Stored::default()
        };
        let mut r = record(complete(), complete());
        r.stored = vec![
            stored(r"NORTH\sql_svc", Via::Service),
            stored("svc@north.contoso.local", Via::Task),
        ];
        needs_netbios(&mut r);
        assert_eq!(r.services.status, CheckStatus::Partial);
        assert_eq!(r.services.reason.as_deref(), Some(NO_NETBIOS));
        assert_eq!(r.tasks.unwrap().status, CheckStatus::Complete);
    }
}

#[cfg(test)]
mod tests {
    use crate::{Auth, CollectRequest, RefreshTarget, Secret};

    /// Nothing listens on LDAPS at 127.0.0.1: the re-read fails fast, leaves
    /// no files, and never shows the password.
    #[test]
    fn a_refused_connection_fails_cleanly() {
        // The re-read sets the process-wide signing switch.
        let _serial = super::super::SIGNING_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let out = std::env::temp_dir().join(format!("pw-refresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let mut r = CollectRequest::new("contoso.local", &out);
        r.server = Some("127.0.0.1".into());
        r.ldaps = true;
        r.scope = crate::Scope::DcOnly;
        r.auth = Auth::Password {
            user: "svc".into(),
            password: Secret::new("Refresh-Secret-37"),
        };
        let target = RefreshTarget {
            ids: vec!["S-1-5-21-1-2-3-500".into()],
            group_dns: vec![],
            domain_sid: Some("S-1-5-21-1-2-3".into()),
            hosts: vec![],
        };
        // Another test may hold the one-collection-at-a-time lock briefly.
        let mut err = crate::refresh_objects(&r, &target).unwrap_err();
        for _ in 0..50 {
            if !format!("{err}").contains("already running") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            err = crate::refresh_objects(&r, &target).unwrap_err();
        }
        let shown = format!("{err:?} {err}");
        assert!(!shown.contains("Refresh-Secret-37"), "{shown}");
        assert!(shown.contains("connect"), "{shown}");
        assert!(std::fs::read_dir(&out).map_or(true, |mut d| d.next().is_none()));
        let _ = std::fs::remove_dir_all(&out);
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::{lookup_answer, not_returned, Lookup};
    use rusthound_ce::transport::ldap::LdapSearchEntry;

    fn entry(attrs: &[(&str, &str)]) -> ldap3::SearchEntry {
        ldap3::SearchEntry {
            dn: "CN=x".into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect(),
            bin_attrs: Default::default(),
        }
    }

    /// Only noSuchObject or a tombstone says an object is
    /// deleted; one there (hidden from the search) or a failed lookup
    /// says nothing.
    #[test]
    fn only_no_such_object_or_a_tombstone_is_deleted() {
        assert_eq!(lookup_answer(32, None), Lookup::Deleted);
        let tomb = entry(&[("isDeleted", "TRUE")]);
        assert_eq!(lookup_answer(0, Some(&tomb)), Lookup::Deleted);
        assert_eq!(lookup_answer(0, Some(&entry(&[]))), Lookup::There);
        let live = entry(&[("isDeleted", "FALSE")]);
        assert_eq!(lookup_answer(0, Some(&live)), Lookup::There);
        // insufficientAccessRights, unwillingToPerform, nothing returned.
        assert_eq!(lookup_answer(50, None), Lookup::Unknown);
        assert_eq!(lookup_answer(53, None), Lookup::Unknown);
        assert_eq!(lookup_answer(0, None), Lookup::Unknown);
    }

    #[test]
    fn objects_not_returned_are_found_by_sid_and_guid() {
        let sid = "S-1-5-21-1-2-3-1104";
        let guid = "2B9A4F6C-0E2A-4B8D-9E55-1C2D3E4F5A6B";
        let returned = LdapSearchEntry {
            dn: "CN=bob".into(),
            attrs: Default::default(),
            bin_attrs: [
                (
                    "objectSid".to_string(),
                    vec![crate::refresh::sid_bytes(sid).unwrap()],
                ),
                (
                    "objectGUID".to_string(),
                    vec![crate::refresh::guid_bytes(guid).unwrap()],
                ),
            ]
            .into(),
        };
        let ids: Vec<String> = [sid, &guid.to_ascii_lowercase(), "S-1-5-21-1-2-3-1105"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(not_returned(&ids, &[returned]), [&ids[2]]);
    }
}
