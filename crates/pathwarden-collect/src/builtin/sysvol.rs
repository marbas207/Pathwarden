//! RustHound-CE's modules step (`modules::run_modules`, MIT, see
//! THIRD-PARTY-NOTICES.md), with Pathwarden reading SYSVOL itself so that
//! `Groups.xml` is checked before RustHound-CE's parser sees it, and so that
//! GPP passwords and file permissions can be read.
//!
//! RUSTSEC-2026-0194: quick-xml 0.37 (used by `parse_groups_xml`) checked for
//! duplicate attributes in quadratic time. The vendored RustHound-CE
//! (vendor/rusthound-ce) now uses quick-xml 0.41, which is fixed; the check
//! below stays, as a bound on the parser and the password scan both.
//! Anyone who can edit a GPO can plant
//! a `Groups.xml` with one element carrying hundreds of thousands of
//! attributes and pin the collector's CPU, which stops the collection that
//! would show their path. Upstream's SYSVOL walk (`gpo::sysvol::collect`) is
//! private, so it is repeated here from the public pieces
//! (`transport::smb::{connect_sysvol, list_dir}`, files read capped, the parsers,
//! `gpo::apply_gpo`), with [`xml_is_safe`] in front of the XML parser:
//! files over [`MAX_GPP_XML`] or with an element of more than
//! [`MAX_ATTRIBUTES`] attributes are skipped with a warning. Real files are a
//! few kilobytes, with a handful of attributes per element. The GPP password
//! scan ([`super::gpp`]) applies the same check to every GPP file.
//!
//! Two ways in:
//!
//! - **With a password** (`--user`): RustHound-CE's SMB client, as before.
//!   It reads files but not their security descriptors, so only the GPP
//!   scan is done; GPO folder and logon script permissions are recorded as
//!   not collected.
//! - **As the current Windows user**: Windows' own SMB client on UNC paths
//!   (Kerberos, no password). Files with `std::fs`, permissions with
//!   `GetNamedSecurityInfoW` ([`super::winsec`]). Everything is read: GPP
//!   passwords, GPO folder permissions, logon script permissions. Only the
//!   domain controller is contacted.
//!
//! Either way the result is `pathwarden-sysvol.json` in the zip, which says
//! per part whether it was read, so that a part that wasn't is "can't tell"
//! in retest rather than "fixed".
//!
//! The order of the modules is upstream's: sessions and the ESC8 probe (one
//! call to upstream with the `Session` method, which runs exactly those for a
//! full collection), SYSVOL, local groups, WebClient.

use std::sync::mpsc;

use rusthound_ce::api::ADResults;
use rusthound_ce::args::{CollectionMethod, Options};
use rusthound_ce::modules::gpo::sysvol::SysvolGpo;
use rusthound_ce::modules::gpo::{
    apply_gpo, parse_gpttmpl_bytes, parse_groups_xml, ObjectResolver,
};
use rusthound_ce::objects::common::LdapObject;
use rusthound_ce::transport::smb::{connect_sysvol, list_dir, smb_identity, SmbAuth};

use super::gpp::{CheckOut, RegistryPolGot, SidecarOut, GPP_FILES};
use super::hostauth;
use super::hosts::{self, SmbIdentity};
use super::krbrelay::{self, KdcRelay};
use super::pool;
use super::Msg;

/// Largest GPP file (`Groups.xml`, ...) handed to a parser or the password
/// scan (real ones are kilobytes).
pub(crate) const MAX_GPP_XML: usize = 4 * 1024 * 1024;
/// Most attributes one XML element may carry (real ones: under 15).
pub(crate) const MAX_ATTRIBUTES: usize = 256;

/// Why GPO folder and logon script permissions are not read with a password.
const NO_SD_WITH_PASSWORD: &str = "file permissions are read through Windows as the current user; \
     with --user, the SMB client the built-in collector uses cannot read security descriptors";

/// Whether `xml` is small enough, and has few enough attributes per
/// element, for quick-xml's quadratic duplicate-attribute check (and the
/// password scan). Linear: it counts `=` outside quoted values inside each
/// tag.
pub(crate) fn xml_is_safe(xml: &[u8]) -> Result<(), String> {
    if xml.len() > MAX_GPP_XML {
        return Err(format!(
            "{} bytes, over the {} MiB limit",
            xml.len(),
            MAX_GPP_XML / (1024 * 1024)
        ));
    }
    let mut in_tag = false;
    let mut quote: Option<u8> = None;
    let mut attrs = 0usize;
    for &b in xml {
        match (in_tag, quote, b) {
            (true, Some(q), _) if b == q => quote = None,
            (true, Some(_), _) => {}
            (true, None, b'"' | b'\'') => quote = Some(b),
            (true, None, b'=') => {
                attrs += 1;
                if attrs > MAX_ATTRIBUTES {
                    return Err(format!(
                        "an element with more than {MAX_ATTRIBUTES} attributes"
                    ));
                }
            }
            (true, None, b'>') => in_tag = false,
            (false, _, b'<') => {
                in_tag = true;
                attrs = 0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Most often the SYSVOL step reports its progress: a domain with thousands
/// of GPOs on a fast link would otherwise flood the channel.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

/// The SYSVOL step's progress: GPOs, then logon scripts, as
/// units of the step and a detail line ("GPO 412 of 1,830"). Reports at
/// most every [`REPORT_EVERY`], and always the first and the last item.
/// Owns a sender, so it moves to the blocking thread that reads SYSVOL.
/// Nothing to read (no GPOs, no scripts): it says nothing.
pub(crate) struct SysvolProgress {
    tx: mpsc::Sender<Msg>,
    gpos: u64,
    scripts: u64,
    gpos_done: u64,
    scripts_done: u64,
    /// Whether SYSVOL is the whole step, so the units are the step's.
    /// In a full collection it is a part of contacting computers: the
    /// detail line only.
    units: bool,
    last: Option<std::time::Instant>,
    /// Set when the step gave up on the thread doing the reading: a
    /// thread that comes back late must not report into the next step.
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SysvolProgress {
    pub(crate) fn new(tx: mpsc::Sender<Msg>, gpos: usize, scripts: usize, units: bool) -> Self {
        Self {
            tx,
            gpos: gpos as u64,
            scripts: scripts as u64,
            gpos_done: 0,
            scripts_done: 0,
            units,
            last: None,
            stopped: Default::default(),
        }
    }

    /// Set it, and this progress sends nothing more.
    #[cfg(any(windows, test))]
    pub(crate) fn stop_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.stopped.clone()
    }

    fn silent(&self) -> bool {
        self.gpos + self.scripts == 0 || self.stopped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Says the step is starting, with its total.
    pub(crate) fn start(&mut self) {
        if self.silent() {
            return;
        }
        if self.units {
            let _ = self.tx.send(Msg::Unit("items"));
        }
        self.report(std::time::Instant::now(), true);
    }

    pub(crate) fn gpo_done(&mut self) {
        self.gpo_done_at(std::time::Instant::now());
    }

    #[cfg(windows)]
    pub(crate) fn script_done(&mut self) {
        self.script_done_at(std::time::Instant::now());
    }

    fn gpo_done_at(&mut self, now: std::time::Instant) {
        let last = self.gpos_done + 1 == self.gpos;
        self.gpos_done = (self.gpos_done + 1).min(self.gpos);
        self.report(now, last);
    }

    #[cfg(any(windows, test))]
    fn script_done_at(&mut self, now: std::time::Instant) {
        let last = self.scripts_done + 1 == self.scripts;
        self.scripts_done = (self.scripts_done + 1).min(self.scripts);
        self.report(now, last);
    }

    /// GPOs read so far, of how many.
    #[cfg(windows)]
    pub(crate) fn gpos(&self) -> (u64, u64) {
        (self.gpos_done, self.gpos)
    }

    /// Logon scripts read so far, of how many.
    #[cfg(windows)]
    pub(crate) fn scripts(&self) -> (u64, u64) {
        (self.scripts_done, self.scripts)
    }

    /// "GPO 412 of 1,830", then "logon scripts 40 of 95".
    fn words(&self) -> String {
        use crate::progress::thousands;
        if self.gpos_done < self.gpos || self.scripts == 0 {
            // The GPO being read, not the ones finished.
            let at = (self.gpos_done + 1).min(self.gpos);
            format!("GPO {} of {}", thousands(at), thousands(self.gpos))
        } else {
            format!(
                "logon scripts {} of {}",
                thousands(self.scripts_done),
                thousands(self.scripts)
            )
        }
    }

    fn report(&mut self, now: std::time::Instant, force: bool) {
        if self.silent() {
            return;
        }
        if !force
            && self
                .last
                .is_some_and(|t| now.duration_since(t) < REPORT_EVERY)
        {
            return;
        }
        self.last = Some(now);
        let _ = self.tx.send(Msg::Detail(self.words()));
        if self.units {
            let _ = self.tx.send(Msg::Units {
                done: self.gpos_done + self.scripts_done,
                total: Some(self.gpos + self.scripts),
            });
        }
    }

    /// The step ended: in a full collection, the detail line goes (local
    /// groups come next in the same step).
    pub(crate) fn finish(&mut self) {
        if !self.units && !self.silent() {
            let _ = self.tx.send(Msg::Detail(String::new()));
        }
    }
}

/// The SYSVOL step's weight in the progress bar, once the number of GPOs
/// and logon scripts is known. Steps are weighted before the directory is
/// read (`super::steps`); a domain with thousands of GPOs spends minutes on
/// SYSVOL, so the weight follows the expected time, relative to the read
/// step's weight and the time the read took. Each GPO is a few dozen SMB
/// round trips (folder permissions, every GPP file), a logon script one.
/// Never below `base`, never more than most of the bar. With a `budget`
/// (as the current user, [`SYSVOL_BUDGET`]), the expected time is never
/// more than it: the step ends there.
pub(crate) fn sysvol_weight(
    base: f64,
    gpos: usize,
    scripts: usize,
    read_weight: f64,
    read: std::time::Duration,
    budget: Option<std::time::Duration>,
) -> f64 {
    /// Rough time per GPO and per logon script on a LAN.
    const PER_GPO: f64 = 0.1;
    const PER_SCRIPT: f64 = 0.01;
    let expected = gpos as f64 * PER_GPO + scripts as f64 * PER_SCRIPT;
    let expected = budget.map_or(expected, |b| expected.min(b.as_secs_f64()));
    // A read of a second or less says little about the link.
    let read = read.as_secs_f64().max(1.0);
    (read_weight * expected / read).clamp(base, 10.0 * read_weight.max(base))
}

/// What a full collection reads for stored credentials, each with
/// its own switch.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Reads {
    /// The accounts services run as (`--no-service-reads`, `[collect]
    /// service_reads`).
    pub services: bool,
    /// The scheduled tasks over C$ (`--no-task-reads`, `[collect]
    /// task_reads`).
    pub tasks: bool,
}

/// The stored credentials steps of a full collection: what to read,
/// and the forest's NetBIOS names for their file.
#[derive(Default)]
pub(crate) struct Services {
    pub netbios: Vec<pathwarden_core::storedcreds::NetbiosName>,
    pub reads: Reads,
}

/// What the modules add to the zip besides RustHound-CE's files.
#[derive(Default)]
pub(crate) struct ModulesOut {
    /// The SYSVOL sidecar, when SYSVOL was read.
    pub sysvol: Option<SidecarOut>,
    /// The stored credentials sidecar, in a full collection.
    pub stored: Option<pathwarden_core::storedcreds::Sidecar>,
}

/// The modules the collection method calls for (not `LdapOnly`), and the
/// SYSVOL sidecar when SYSVOL was read. `timings` gets how long reading
/// SYSVOL took and, for a full collection, the computers contacted. In a
/// full collection over Kerberos, the reached computers' services are read
/// for the domain accounts they run as, and their scheduled tasks for the
/// passwords they store (`netbios`: the forest's domains by NetBIOS name,
/// for that file; `reads`: which of the two are on).
pub(crate) async fn run_modules(
    options: &Options,
    smb: &SmbIdentity,
    ad: &mut ADResults,
    tx: &mpsc::Sender<Msg>,
    timings: &mut super::timings::Timings,
    services: Services,
    mut early: Early,
) -> Result<ModulesOut, String> {
    let Services { netbios, reads } = services;
    let read = reads.services;
    let mut stored = None;
    let full = options.collection_method == CollectionMethod::All;
    let mut host_errors: Vec<String> = Vec::new();
    let mut sessions_time = None;
    // Computers left out of the modules (Kerberos only, required signing).
    let mut skipped = hostauth::Skipped::new();
    // Kerberos only: the modules' KDC, until they finish.
    let mut relay: Option<KdcRelay> = None;
    // `smb`: sign in to the account's own domain (a trusted domain's
    // account collecting this one), see `hosts`.
    if full {
        // Sessions and the ESC8 probe, exactly as upstream runs them for
        // `All` (`Session` does the same three RPC paths and skips the rest).
        // The sessions module uses the domain only to sign in and to look
        // up `name@domain` before the bare name.
        let mut first = smb.options(options);
        first.collection_method = CollectionMethod::Session;
        hosts::mark_sessions_not_collected(&mut ad.computers, hosts::NOT_ATTEMPTED);
        let started = std::time::Instant::now();
        // Kerberos only: a computer without a ticket is never contacted.
        if let Some(k) = &smb.kerberos {
            hostauth::ccache_ready(k)?;
            let r = hostauth::relay(k, tx).await?;
            first = r.options(&first);
            relay = Some(r);
            skipped = hostauth::precheck(k, &mut ad.computers, &|_| true, tx).await;
        }
        let taken = hostauth::take(ad, &skipped);
        super::log_bridge::start_capture(hosts::SESSIONS_LOG_TARGET);
        let ran = rusthound_ce::modules::run_modules(&first, ad).await;
        let errors = super::log_bridge::take_capture();
        if let Err(e) = ran {
            hostauth::put_back(ad, taken);
            return Err(format!("collection failed in the SMB/RPC modules: {e}"));
        }
        hosts::apply_session_errors(&mut ad.computers, errors.as_deref());
        hostauth::unsigned(&mut ad.computers, &[], &mut skipped, tx);
        host_errors.extend(errors.unwrap_or_default());
        let retried = retry_starting_registry(&first, ad, tx).await;
        // The services step's end: its reads start with the sessions'.
        let until = read.then(|| std::time::Instant::now() + super::storedcreds::STEP_BUDGET);
        let mut already = std::collections::HashMap::new();
        if let (Some(k), Ok(())) = (&smb.kerberos, &retried) {
            let user = smb_identity(options.username.as_deref().unwrap_or_default(), &smb.domain).1;
            already = hostauth::registry_sessions(
                k,
                &smb.domain,
                &user,
                &mut ad.computers,
                &skipped,
                until,
                tx,
            )
            .await;
        }
        hostauth::put_back(ad, taken);
        retried?;
        sessions_time = Some(started.elapsed());
        // The accounts services run as: over Kerberos only, on the
        // computers the sessions pass reached, in the same signed sessions'
        // way. With NTLM every computer stays not collected, with the reason.
        stored = Some(match (&smb.kerberos, until) {
            (_, None) => super::storedcreds::turned_off(&options.domain, netbios),
            (Some(k), Some(until)) => {
                let user =
                    smb_identity(options.username.as_deref().unwrap_or_default(), &smb.domain).1;
                let plan = super::storedcreds::Plan {
                    k,
                    domain: &options.domain,
                    smb_domain: &smb.domain,
                    user: &user,
                    netbios,
                    already,
                    until,
                };
                super::storedcreds::collect(plan, &mut ad.computers, &skipped, tx).await
            }
            (None, Some(_)) => super::storedcreds::not_read(
                &options.domain,
                netbios,
                super::storedcreds::NO_KERBEROS,
            ),
        });
        // The scheduled tasks: over Kerberos only, on the
        // computers the sessions pass reached, in their own signed sessions
        // to C$, with their own switch and time.
        if let Some(s) = stored.as_mut() {
            use super::tasks;
            match (&smb.kerberos, reads.tasks) {
                (_, false) => tasks::not_read(s, tasks::TURNED_OFF, true),
                (Some(k), true) => {
                    let user =
                        smb_identity(options.username.as_deref().unwrap_or_default(), &smb.domain)
                            .1;
                    // Remote Registry the services step found down, after its
                    // own wait: not waited for again.
                    let registry_down = s
                        .hosts
                        .iter()
                        .filter(|h| {
                            h.services.status == pathwarden_core::sysvol::CheckStatus::NotCollected
                                && h.services
                                    .reason
                                    .as_deref()
                                    .is_some_and(|r| r.starts_with("Remote Registry:"))
                        })
                        .map(|h| h.id.clone())
                        .collect();
                    let plan = tasks::Plan {
                        k,
                        smb_domain: &smb.domain,
                        user: &user,
                        until: std::time::Instant::now() + tasks::STEP_BUDGET,
                        registry_down,
                    };
                    let read = tasks::collect(plan, &mut ad.computers, &skipped, tx).await;
                    tasks::merge(s, read);
                }
                (None, true) => tasks::not_read(s, tasks::NO_KERBEROS, false),
            }
        }
        let complete = hosts::fully_collected(&mut ad.computers);
        let some = hosts::partly_collected(&mut ad.computers);
        let _ = tx.send(Msg::Log(format!(
            "[sessions] collected from at least one source on {some} of {}, from \
             all three (SRVSVC, WKSSVC, Remote Registry) on {complete}; what was not read is \
             recorded as not collected, with the reason",
            pathwarden_core::text::count(ad.computers.len(), "computer", "computers")
        )));
    }
    let mut not_read = if full {
        hosts::NotRead::of_sessions(&mut ad.computers)
    } else {
        hosts::NotRead::default()
    };
    let mut sidecar = None;
    if options.collection_method.does_gpo() {
        let mut out = SidecarOut::new(&options.domain, &dc_host(options));
        out.checks.gpo_acl = CheckOut::not_collected(NO_SD_WITH_PASSWORD);
        out.checks.logon_script_acl = CheckOut::not_collected(NO_SD_WITH_PASSWORD);
        out.checks.logon_script_acl.skipped = super::gpp::logon_scripts(user_scripts(ad)).0.len();
        let started = std::time::Instant::now();
        // Read while the directory was, when it could be.
        let files = early.smb_files().await;
        let read = collect_sysvol(options, smb, ad, tx, &mut out, !full, files).await;
        timings.sysvol = Some(started.elapsed());
        match read {
            Ok(sysvol) => {
                // Partial when the read ran out of time (set by it).
                out.checks.gpo_local_groups.get_or_insert(CheckOut {
                    status: "complete",
                    read: sysvol.len(),
                    ..CheckOut::default()
                });
                if !sysvol.is_empty() {
                    // Which GPO and setting gives each member, before the
                    // merge loses it.
                    let ids: std::collections::HashMap<String, String> = gpo_folders(ad)
                        .into_iter()
                        .map(|(folder, id, _)| (folder, id))
                        .collect();
                    let resolver = ObjectResolver::build(&ad.users, &ad.groups, &ad.computers);
                    let found =
                        super::gpolocal::attribute(&sysvol, &ids, &resolver, &options.domain);
                    drop(resolver);
                    if found.over_cap > 0 {
                        let _ = tx.send(Msg::Log(format!(
                            "warning: [gpo] {} GPO local group entries, over the cap of {}: \
                             none recorded, so fixes list the linked GPOs as candidates",
                            crate::progress::thousands(found.over_cap as u64),
                            crate::progress::thousands(super::gpolocal::MAX_ENTRIES as u64)
                        )));
                    }
                    if found.truncated > 0 {
                        let _ = tx.send(Msg::Log(format!(
                            "warning: [gpo] {} over {} members: fixes list the linked GPOs as \
                             candidates wherever their GPOs are linked",
                            pathwarden_core::text::count(
                                found.truncated,
                                "GPO local group entry has",
                                "GPO local group entries have"
                            ),
                            crate::progress::thousands(super::gpolocal::MAX_MEMBERS as u64)
                        )));
                    }
                    out.gpo_local_groups = found.entries;
                    apply_gpo(
                        &mut ad.ous,
                        &mut ad.domains,
                        &ad.users,
                        &ad.groups,
                        &mut ad.computers,
                        &sysvol,
                        &ad.mappings.dn_sid,
                        &options.domain,
                    );
                }
            }
            Err(e) => {
                let _ = tx.send(Msg::Log(format!(
                    "warning: [gpo] SYSVOL collection failed: {e}"
                )));
                out.checks.gpp = CheckOut::not_collected(&format!("SYSVOL could not be read: {e}"));
                out.checks.gpo_local_groups = Some(CheckOut::not_collected(&format!(
                    "SYSVOL could not be read: {e}"
                )));
                out.checks.registry_pol = Some(CheckOut::not_collected(&format!(
                    "SYSVOL could not be read: {e}"
                )));
            }
        }
        sidecar = Some(out);
    }
    if full {
        let started = std::time::Instant::now();
        let taken = hostauth::take(ad, &skipped);
        super::log_bridge::start_capture(LOCAL_GROUPS_LOG_TARGET);
        let ran = local_groups(&krbrelay::via(relay.as_ref(), options), smb, ad, tx).await;
        let errors = super::log_bridge::take_capture().unwrap_or_default();
        if let Err(e) = ran {
            hostauth::put_back(ad, taken);
            return Err(e);
        }
        hostauth::unsigned(&mut ad.computers, &errors, &mut skipped, tx);
        not_read.local_groups = hosts::hosts_with_errors(
            ad.computers
                .iter()
                .filter(|c| !skipped.contains_key(c.object_identifier().as_str())),
            &errors,
        );
        hostauth::put_back(ad, taken);
        let mut summary = hosts::summary(&mut ad.computers);
        summary.local_groups_failed = not_read.local_groups;
        summary.errors = hosts::error_kinds(host_errors.iter().chain(&errors));
        summary.sessions_ms = sessions_time.map(|d| d.as_millis() as u64);
        summary.local_groups_ms = Some(started.elapsed().as_millis() as u64);
        timings.hosts = Some(summary);
        for w in hostauth::warnings(&skipped) {
            let _ = tx.send(Msg::Warning(w));
        }
        if let Some(w) = not_read.warning() {
            let _ = tx.send(Msg::Warning(w));
        }
        let taken = hostauth::take(ad, &skipped);
        let webclient = krbrelay::via(relay.as_ref(), &smb.options(options));
        let ran = rusthound_ce::modules::webclient::run(&webclient, &mut ad.computers)
            .await
            .map_err(|e| format!("collection failed in the WebClient module: {e}"));
        hostauth::put_back(ad, taken);
        ran?;
    }
    // The modules are done: the relay stops.
    drop(relay);
    Ok(ModulesOut {
        sysvol: sidecar,
        stored,
    })
}

/// How long Remote Registry gets to start before it is asked again.
const REGISTRY_START: std::time::Duration = std::time::Duration::from_secs(3);

/// Asks the computers whose Remote Registry was still starting once more
/// (the whole sessions pass, which is read-only), and keeps what that
/// second pass collected. See `hosts::registry_was_starting`.
pub(super) async fn retry_starting_registry(
    options: &Options,
    ad: &mut ADResults,
    tx: &mpsc::Sender<Msg>,
) -> Result<(), String> {
    let again: Vec<usize> = (0..ad.computers.len())
        .filter(|&i| hosts::registry_was_starting(&mut ad.computers[i]))
        .collect();
    if again.is_empty() {
        return Ok(());
    }
    let _ = tx.send(Msg::Log(format!(
        "[sessions] Remote Registry was starting on {}; asking again in {}s",
        pathwarden_core::text::count(again.len(), "computer", "computers"),
        REGISTRY_START.as_secs()
    )));
    tokio::time::sleep(REGISTRY_START).await;
    let mut retried: Vec<_> = again.iter().map(|&i| ad.computers[i].clone()).collect();
    hosts::mark_sessions_not_collected(&mut retried, hosts::NOT_ATTEMPTED);
    super::log_bridge::start_capture(hosts::SESSIONS_LOG_TARGET);
    let ran = rusthound_ce::modules::session::run(options, &ad.users, &mut retried).await;
    let errors = super::log_bridge::take_capture();
    ran.map_err(|e| format!("collection failed in the sessions module: {e}"))?;
    hosts::apply_session_errors(&mut retried, errors.as_deref());
    for (&i, r) in again.iter().zip(retried.iter_mut()) {
        hosts::take_retried(&mut ad.computers[i], r);
    }
    Ok(())
}

/// The log target of RustHound-CE's local groups module, whose warnings
/// carry the per-computer errors (`HOST: ...`, `HOST SamrConnect2: ...`).
pub(super) const LOCAL_GROUPS_LOG_TARGET: &str = "rusthound_ce::modules::localgroup";

/// Upstream's local groups module. It uses the domain both to sign in and
/// to recognise a domain controller (whose groups it names after the
/// domain), so with another domain's account only member computers are
/// read, signing in to the account's domain; a DC's local groups are the
/// domain's BUILTIN groups, already read from the directory.
pub(super) async fn local_groups(
    options: &Options,
    smb: &SmbIdentity,
    ad: &mut ADResults,
    tx: &mpsc::Sender<Msg>,
) -> Result<(), String> {
    let fail = |e: Box<dyn std::error::Error>| {
        format!("collection failed in the local groups module: {e}")
    };
    if !smb.other_domain {
        return rusthound_ce::modules::localgroup::run(
            options,
            &ad.users,
            &mut ad.computers,
            &ad.mappings.sid_type,
        )
        .await
        .map_err(fail);
    }
    let (dcs, mut members): (Vec<_>, Vec<_>) = std::mem::take(&mut ad.computers)
        .into_iter()
        .enumerate()
        .partition(|(_, c)| *c.properties().get_is_dc());
    if !dcs.is_empty() {
        let _ = tx.send(Msg::Log(format!(
            "[localgroups] {} not read: the account is from {}, and a DC's \
             local groups are {}'s BUILTIN groups, read from the directory",
            pathwarden_core::text::count(dcs.len(), "domain controller", "domain controllers"),
            smb.domain,
            options.domain
        )));
    }
    let order: Vec<usize> = members.iter().map(|(i, _)| *i).collect();
    let mut computers: Vec<_> = members.drain(..).map(|(_, c)| c).collect();
    let ran = rusthound_ce::modules::localgroup::run(
        &smb.options(options),
        &ad.users,
        &mut computers,
        &ad.mappings.sid_type,
    )
    .await;
    // Back in their original order, whatever happened.
    let mut all: Vec<_> = order.into_iter().zip(computers).chain(dcs).collect();
    all.sort_by_key(|(i, _)| *i);
    ad.computers = all.into_iter().map(|(_, c)| c).collect();
    ran.map_err(fail)
}

fn dc_host(options: &Options) -> String {
    options
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| options.domain.clone())
}

/// The folder name (`{GUID}`) of a GPO, from its `gpcpath`.
fn folder_of(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .find(|p| !p.is_empty())
        .map(str::to_uppercase)
        .filter(|g| super::gpp::is_gpo_guid(g))
}

/// Every GPO: its folder name, its ObjectIdentifier, and whether its
/// computer configuration applies (upstream's `ComputerGpoScope::from_gpos`,
/// whose lookup is crate-private).
fn gpo_folders(ad: &ADResults) -> Vec<(String, String, bool)> {
    ad.gpos
        .iter()
        .filter_map(|g| {
            let json = g.to_json();
            let folder = folder_of(json["Properties"]["gpcpath"].as_str().unwrap_or_default())?;
            Some((
                folder,
                g.get_object_identifier().clone(),
                g.computer_configuration_enabled(),
            ))
        })
        .collect()
}

/// What the SYSVOL step has to read: GPO folders, and the logon scripts
/// the users name (read as the current Windows user only).
pub(crate) fn size(ad: &ADResults) -> (usize, usize) {
    (
        gpo_folders(ad).len(),
        super::gpp::logon_scripts(user_scripts(ad)).0.len(),
    )
}

/// (SID, scriptPath) of every user with a logon script.
fn user_scripts(ad: &ADResults) -> Vec<(String, String)> {
    ad.users
        .iter()
        .filter_map(|u| {
            let props = serde_json::to_value(u.properties()).ok()?;
            let script = props["logonscript"].as_str()?.trim().to_string();
            (!script.is_empty()).then(|| (u.get_object_identifier().clone(), script))
        })
        .collect()
}

/// What reading one file got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Got {
    Bytes(Vec<u8>),
    /// Not there (nor its folder).
    Missing,
    Failed(String),
}

/// One GPO folder's files, read with RustHound-CE's SMB client: its
/// `GptTmpl.inf` (when readable) and each GPP file, in [`GPP_FILES`] order
/// under `Machine` then `User`.
#[derive(Debug, Clone)]
pub(crate) struct GpoSmb {
    /// `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`: Restricted
    /// Groups and user rights.
    gpttmpl: Got,
    gpp: Vec<(&'static str, &'static str, &'static str, Got)>,
    /// `Machine\Registry.pol`, parsed as read.
    regpol: RegistryPolGot,
}

/// The path of a GPO's computer `Registry.pol`, under its folder.
pub(crate) const REGISTRY_POL: &str = r"Machine\Registry.pol";

/// What reading a `Registry.pol` got, from its bytes or the read error.
fn registry_pol(read: Result<Option<Vec<u8>>, String>) -> RegistryPolGot {
    match read {
        Ok(Some(b)) if b.len() > pathwarden_core::sysvol::regpol::MAX_FILE => {
            RegistryPolGot::Unreadable(format!(
                "over {} MiB",
                pathwarden_core::sysvol::regpol::MAX_FILE / (1024 * 1024)
            ))
        }
        Ok(Some(b)) => RegistryPolGot::of(&b),
        Ok(None) => RegistryPolGot::Missing,
        Err(e) => RegistryPolGot::Unreadable(e),
    }
}

/// What reading SYSVOL with a password got, before what it means is worked
/// out: the GPO folders `Policies` lists, and each one's files.
pub(crate) struct SmbFiles {
    /// `Err`: SYSVOL could not be read (signing in, or listing it).
    listed: Result<Vec<String>, String>,
    /// Each listed folder's files; `None`: not read (no session, or the
    /// budget ran out first).
    gpos: Vec<Option<GpoSmb>>,
    /// The first error a worker had connecting.
    lost: Option<String>,
    /// The budget ran out with folders left.
    timed_out: bool,
    /// How long it took.
    took: std::time::Duration,
    /// Workers it read with.
    workers: usize,
}

impl SmbFiles {
    fn failed(e: String, took: std::time::Duration) -> Self {
        Self {
            listed: Err(e),
            gpos: Vec::new(),
            lost: None,
            timed_out: false,
            took,
            workers: 0,
        }
    }
}

/// How the SMB workers sign in to the domain controller's SYSVOL: as the
/// modules do, Kerberos only unless NTLM is allowed.
pub(crate) struct SmbSignIn {
    identity: SmbIdentity,
    /// The bare user name; the domain is `identity.domain`.
    user: String,
    password: crate::Secret,
    dc_host: String,
}

impl SmbSignIn {
    fn of(options: &Options, identity: &SmbIdentity) -> Self {
        // Bare name only; the domain is `identity.domain` (2.5.26 folded
        // smb_user into smb_identity, which returns (domain, user)).
        let user = smb_identity(
            options.username.as_deref().unwrap_or_default(),
            &identity.domain,
        )
        .1;
        Self {
            identity: identity.clone(),
            user,
            password: crate::Secret::new(options.password.clone().unwrap_or_default()),
            dc_host: dc_host(options),
        }
    }

    /// A session on SYSVOL. Kerberos only: the DC's cifs/ ticket,
    /// never NTLM.
    async fn connect(&self) -> Result<smb2_client::SmbClient, String> {
        match &self.identity.kerberos {
            Some(k) => {
                let (blob, key) = super::krb::service_ticket(&k.ccache, &self.dc_host, &k.kdc)
                    .await
                    .map_err(|e| e.words())?;
                connect_sysvol(
                    &self.dc_host,
                    &self.identity.domain,
                    &self.user,
                    SmbAuth::Kerberos {
                        gss_blob: &blob,
                        session_key: &key,
                    },
                )
                .await
            }
            None => {
                connect_sysvol(
                    &self.dc_host,
                    &self.identity.domain,
                    &self.user,
                    SmbAuth::Password(self.password.expose()),
                )
                .await
            }
        }
        .map_err(|e| e.to_string())
    }
}

/// A capped read of one SYSVOL file, so a file planted there can't make
/// the collector hold gigabytes (a fake stands in in tests).
pub(crate) trait CappedRead {
    /// The file's first `max` bytes and whether it goes on past them;
    /// `None` when it (or its folder) isn't there.
    async fn read_capped(
        &mut self,
        path: &str,
        max: usize,
    ) -> Result<Option<(Vec<u8>, bool)>, String>;
}

impl CappedRead for smb2_client::SmbClient {
    async fn read_capped(
        &mut self,
        path: &str,
        max: usize,
    ) -> Result<Option<(Vec<u8>, bool)>, String> {
        const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
        match self.read_file_max(path, max).await {
            Ok(read) => Ok(Some(read)),
            Err(smb2_client::SmbError::Status(code, _))
                if code == smb2_client::status::OBJECT_NAME_NOT_FOUND
                    || code == OBJECT_PATH_NOT_FOUND =>
            {
                Ok(None)
            }
            Err(e) => Err(format!("read {path}: {e}")),
        }
    }
}

/// A file of at most `cap` bytes. A longer one comes back with one byte
/// past the cap (never more), so the size checks after it refuse it.
async fn read_bounded(
    smb: &mut impl CappedRead,
    path: &str,
    cap: usize,
) -> Result<Option<Vec<u8>>, String> {
    Ok(smb.read_capped(path, cap).await?.map(|(mut b, more)| {
        if more {
            b.truncate(cap);
            b.push(0);
        }
        b
    }))
}

/// One GPO folder's files at `base`, each read to its cap at most.
async fn read_gpo_smb(smb: &mut impl CappedRead, base: &str) -> GpoSmb {
    let gpttmpl = format!(r"{base}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf");
    let gpttmpl = match read_bounded(smb, &gpttmpl, MAX_GPP_XML).await {
        Ok(Some(b)) if b.len() > MAX_GPP_XML => {
            Got::Failed(format!("over {} MiB", MAX_GPP_XML / (1024 * 1024)))
        }
        Ok(Some(b)) => Got::Bytes(b),
        Ok(None) => Got::Missing,
        Err(e) => Got::Failed(e),
    };
    let mut gpp = Vec::new();
    for scope_dir in ["Machine", "User"] {
        for (dir, file) in GPP_FILES {
            let path = format!(r"{base}\{scope_dir}\Preferences\{dir}\{file}");
            let got = match read_bounded(smb, &path, MAX_GPP_XML).await {
                Ok(Some(b)) => Got::Bytes(b),
                Ok(None) => Got::Missing,
                Err(e) => Got::Failed(e),
            };
            gpp.push((scope_dir, dir, file, got));
        }
    }
    let regpol = registry_pol(
        read_bounded(
            smb,
            &format!(r"{base}\{REGISTRY_POL}"),
            pathwarden_core::sysvol::regpol::MAX_FILE,
        )
        .await,
    );
    GpoSmb {
        gpttmpl,
        gpp,
        regpol,
    }
}

/// What a password SYSVOL read has got so far, published as it goes: a read
/// that runs out of time keeps what it read.
#[derive(Default)]
struct Partial {
    /// The listing, once read (`Err`: SYSVOL could not be read).
    listed: Option<Result<Vec<String>, String>>,
    gpos: Vec<Option<GpoSmb>>,
    lost: Option<String>,
}

type Published = std::sync::Arc<std::sync::Mutex<Partial>>;

impl SmbFiles {
    /// What `p` holds now. `timed_out`: the read was cut short.
    fn from_partial(
        p: &Published,
        timed_out: bool,
        took: std::time::Duration,
        workers: usize,
    ) -> Self {
        let mut p = p.lock().unwrap_or_else(|e| e.into_inner());
        match p.listed.take() {
            Some(Ok(names)) => {
                let mut gpos = std::mem::take(&mut p.gpos);
                gpos.resize(names.len(), None);
                SmbFiles {
                    listed: Ok(names),
                    gpos,
                    lost: p.lost.take(),
                    timed_out,
                    took,
                    workers,
                }
            }
            Some(Err(e)) => SmbFiles::failed(e, took),
            None if timed_out => {
                SmbFiles::failed("the domain controller did not answer in time".into(), took)
            }
            None => SmbFiles::failed("SYSVOL was not read".into(), took),
        }
    }
}

/// The GPO folders `names` under `root`, with `workers` sessions (the
/// first given one) until `stop`, each published in `into` at its index
/// plus `at` as soon as it is read. Returns whether the time ran out, and
/// the first error connecting.
#[allow(clippy::too_many_arguments)]
async fn read_gpo_folders(
    s: &SmbSignIn,
    root: &str,
    names: &[String],
    workers: usize,
    first: Option<smb2_client::SmbClient>,
    stop: &(dyn Fn() -> bool + Sync),
    into: &Published,
    at: usize,
) -> (bool, Option<String>) {
    let items: Vec<(usize, &String)> = names.iter().enumerate().collect();
    let (read, lost) = pool::concurrent(
        &items,
        workers,
        stop,
        first,
        async || s.connect().await,
        async |smb: &mut smb2_client::SmbClient, (i, name): &(usize, &String)| {
            let got = read_gpo_smb(smb, &format!(r"{root}\{name}")).await;
            if let Ok(mut p) = into.lock() {
                let k = at + *i;
                if p.gpos.len() <= k {
                    p.gpos.resize(k + 1, None);
                }
                p.gpos[k] = Some(got);
            }
        },
        |_| {},
    )
    .await;
    if let (Some(e), Ok(mut p)) = (&lost, into.lock()) {
        p.lost.get_or_insert_with(|| e.clone());
    }
    (read.timed_out, lost)
}

/// Lists the GPO folders of `domain`'s SYSVOL and reads their files, with
/// `workers` sessions, until `stop`, publishing into `into` as it goes.
/// Returns whether the time ran out.
async fn read_smb_files(
    s: &SmbSignIn,
    domain: &str,
    workers: usize,
    stop: &(dyn Fn() -> bool + Sync),
    into: &Published,
) -> bool {
    let publish = |r: Result<Vec<String>, String>| {
        if let Ok(mut p) = into.lock() {
            p.listed = Some(r);
        }
    };
    let mut first = match s.connect().await {
        Ok(c) => c,
        Err(e) => {
            publish(Err(e));
            return false;
        }
    };
    let root = format!(r"{domain}\Policies");
    let names: Vec<String> = match list_dir(&mut first, &s.dc_host, &root).await {
        Ok(entries) => entries
            .into_iter()
            .filter(|e| e.is_dir && super::gpp::is_gpo_guid(&e.name.to_uppercase()))
            .map(|e| e.name)
            .collect(),
        Err(e) => {
            publish(Err(e.to_string()));
            return false;
        }
    };
    publish(Ok(names.clone()));
    read_gpo_folders(s, &root, &names, workers, Some(first), stop, into, 0)
        .await
        .0
}

/// [`read_smb_files`] within [`SYSVOL_BUDGET`]: no folder is started past
/// it, and a session that hangs gets a minute more; then what was read is
/// kept, as out of time.
async fn read_smb_bounded(s: &SmbSignIn, domain: &str, workers: usize) -> SmbFiles {
    let started = std::time::Instant::now();
    let deadline = started + SYSVOL_BUDGET;
    let into = Published::default();
    let stop = || std::time::Instant::now() > deadline;
    let read = tokio::time::timeout(
        SYSVOL_BUDGET + std::time::Duration::from_secs(60),
        read_smb_files(s, domain, workers, &stop, &into),
    )
    .await;
    let timed_out = read.unwrap_or(true);
    SmbFiles::from_partial(&into, timed_out, started.elapsed(), workers)
}

/// GPO folders made during the read: SYSVOL's listing now against the one
/// taken at the start (`listed`). A GPO in the directory with no folder in
/// SYSVOL is in neither, and isn't read. They are read within the budget
/// and appended to `files`.
async fn read_new_folders(
    s: &SmbSignIn,
    domain: &str,
    files: &mut SmbFiles,
    tx: &mpsc::Sender<Msg>,
) {
    let Ok(listed) = &files.listed else { return };
    let have: std::collections::HashSet<String> = listed.iter().map(|n| n.to_uppercase()).collect();
    let deadline = std::time::Instant::now() + SYSVOL_BUDGET;
    let into = Published::default();
    let root = format!(r"{domain}\Policies");
    let work = async {
        let mut first = s.connect().await.ok()?;
        let now = list_dir(&mut first, &s.dc_host, &root).await.ok()?;
        let new: Vec<String> = now
            .into_iter()
            .filter(|e| e.is_dir && super::gpp::is_gpo_guid(&e.name.to_uppercase()))
            .map(|e| e.name)
            .filter(|n| !have.contains(&n.to_uppercase()))
            .collect();
        if new.is_empty() {
            return Some((new, false));
        }
        if let Ok(mut p) = into.lock() {
            p.listed = Some(Ok(new.clone()));
        }
        let stop = || std::time::Instant::now() > deadline;
        let workers = pool::SYSVOL_WORKERS.min(new.len());
        let (timed_out, _) =
            read_gpo_folders(s, &root, &new, workers, Some(first), &stop, &into, 0).await;
        Some((new, timed_out))
    };
    let (new, timed_out) = match tokio::time::timeout(
        SYSVOL_BUDGET + std::time::Duration::from_secs(60),
        work,
    )
    .await
    {
        Ok(Some((new, t))) => (new, t),
        // Not listed again: what the start's listing had stands.
        Ok(None) => return,
        Err(_) => {
            let p = into.lock().unwrap_or_else(|e| e.into_inner());
            match &p.listed {
                Some(Ok(n)) => (n.clone(), true),
                _ => return,
            }
        }
    };
    if new.is_empty() {
        return;
    }
    let _ = tx.send(Msg::Log(format!(
        "[sysvol] {} made during the read, read now",
        pathwarden_core::text::count(new.len(), "GPO folder", "GPO folders")
    )));
    let got = SmbFiles::from_partial(&into, timed_out, std::time::Duration::ZERO, 0);
    if let (Ok(listed), Ok(names)) = (&mut files.listed, got.listed) {
        listed.extend(names);
        files.gpos.extend(got.gpos);
        files.timed_out |= got.timed_out;
        if files.lost.is_none() {
            files.lost = got.lost;
        }
    }
}

/// Upstream `collect_sysvol_targets` and `collect` (password or NT hash; the
/// built-in collector never uses a ticket cache), with the `Groups.xml` check
/// and the GPP password scan of every GPO. The files come from `early`, read
/// while the directory was ([`Early`]), else they are read now; a GPO folder
/// made during the read is read now too. Each read keeps to the budget.
async fn collect_sysvol(
    options: &Options,
    identity: &SmbIdentity,
    ad: &ADResults,
    tx: &mpsc::Sender<Msg>,
    out: &mut SidecarOut,
    whole_step: bool,
    early: Option<SmbFiles>,
) -> Result<Vec<SysvolGpo>, String> {
    let warn = |m: String| {
        let _ = tx.send(Msg::Log(format!("warning: [gpo] {m}")));
    };
    let dc_host = dc_host(options);
    let gpos = gpo_folders(ad);
    let was_early = early.is_some();
    let s = SmbSignIn::of(options, identity);
    let mut files = match early {
        Some(f) => {
            if let Ok(listed) = &f.listed {
                let _ = tx.send(Msg::Log(format!(
                    "[sysvol] {} read early with {} SMB sessions in {}",
                    pathwarden_core::text::count(listed.len(), "GPO folder", "GPO folders"),
                    f.workers,
                    super::timings::secs(f.took)
                )));
            }
            f
        }
        None => read_smb_bounded(&s, &options.domain, pool::SYSVOL_WORKERS).await,
    };
    if was_early && !files.timed_out {
        read_new_folders(&s, &options.domain, &mut files, tx).await;
    }
    let timed_out = files.timed_out;
    let entries = files.listed?;
    let ids: std::collections::HashMap<&str, &String> =
        gpos.iter().map(|(f, id, _)| (f.as_str(), id)).collect();
    let mut progress = SysvolProgress::new(tx.clone(), entries.len(), 0, whole_step);
    progress.start();
    let mut result = Vec::new();
    let mut first_error = None;
    let mut regpol_error = None;
    out.checks.registry_pol = Some(CheckOut::default());
    let mut read = files.gpos.into_iter();
    // The local groups part: a GPO folder counts as read when
    // its GptTmpl.inf and Groups.xml were read and parsed (or aren't
    // there), else as failed; one no worker read fails when its computer
    // settings apply. Out of time: partial.
    let mut groups = CheckOut::default();
    let mut groups_error: Option<String> = None;
    for listed in entries {
        let name = listed.to_uppercase();
        let in_scope = gpos.iter().any(|(f, _, computer)| *f == name && *computer);
        let mut gpo = SysvolGpo {
            guid: listed.clone(),
            ..Default::default()
        };
        let Some(raw) = read.next().flatten() else {
            // Out of time: the part is partial. Otherwise no worker could
            // read it.
            if !timed_out {
                let why = files
                    .lost
                    .clone()
                    .unwrap_or_else(|| "no session to read it".into());
                out.checks.gpp.failed += 1;
                if let Some(c) = out.checks.registry_pol.as_mut() {
                    c.failed += 1;
                }
                if in_scope {
                    groups.failed += 1;
                    groups_error.get_or_insert_with(|| format!("{name}: {why}"));
                }
                first_error.get_or_insert(why);
            }
            progress.gpo_done();
            continue;
        };
        // Why this GPO's local groups weren't read whole, if they weren't.
        let mut groups_failed: Option<String> = None;
        // The computer settings of a GPO whose computer configuration is
        // off don't apply: its Registry.pol is not used.
        if in_scope {
            out.add_registry_pol(
                &name,
                ids.get(name.as_str()).copied(),
                &raw.regpol,
                &mut regpol_error,
                &warn,
            );
        } else if raw.regpol != RegistryPolGot::Missing {
            if let Some(c) = out.checks.registry_pol.as_mut() {
                c.skipped += 1;
            }
        }
        if in_scope {
            match &raw.gpttmpl {
                Got::Bytes(bytes) => match parse_gpttmpl_bytes(bytes) {
                    Ok(policy) => {
                        gpo.privileges = policy.privilege_rights().to_vec();
                        gpo.restricted_groups = policy.restricted_groups().to_vec();
                    }
                    Err(e) => {
                        warn(format!(
                            "{name} GptTmpl.inf not parsed ({e}): its local groups are not \
                             collected. Check who can edit this GPO"
                        ));
                        groups_failed.get_or_insert_with(|| format!("{name} GptTmpl.inf: {e}"));
                    }
                },
                Got::Missing => {}
                Got::Failed(e) => {
                    warn(format!(
                        "{name} GptTmpl.inf not read ({e}): its local groups are not collected"
                    ));
                    groups_failed.get_or_insert_with(|| format!("{name} GptTmpl.inf: {e}"));
                }
            }
        }
        for (scope_dir, dir, file, got) in raw.gpp {
            let rel = format!(r"{scope_dir}\Preferences\{dir}\{file}");
            let bytes = match got {
                Got::Bytes(b) => b,
                Got::Missing => continue,
                Got::Failed(e) => {
                    out.checks.gpp.failed += 1;
                    if in_scope && dir == "Groups" {
                        warn(format!(
                            "{name} {scope_dir} Groups.xml not read ({e}): its local groups are \
                             not collected"
                        ));
                        groups_failed
                            .get_or_insert_with(|| format!("{name} {scope_dir} Groups.xml: {e}"));
                    }
                    first_error.get_or_insert(e);
                    continue;
                }
            };
            out.scan_gpp(
                &name,
                ids.get(name.as_str()).copied(),
                &rel,
                &bytes,
                &mut first_error,
                &warn,
            );
            if !(in_scope && dir == "Groups") {
                continue;
            }
            if let Err(why) = xml_is_safe(&bytes) {
                warn(format!(
                    "{name} {scope_dir} Groups.xml skipped ({why}): its local groups are not \
                     collected. Check who can edit this GPO"
                ));
                groups_failed
                    .get_or_insert_with(|| format!("{name} {scope_dir} Groups.xml: {why}"));
                continue;
            }
            match parse_groups_xml(&bytes) {
                Ok(mut found) => gpo.gpp_local_groups.append(&mut found),
                Err(e) => {
                    warn(format!(
                        "{name} {scope_dir} Groups.xml not parsed ({e}): its local groups are \
                         not collected. Check who can edit this GPO"
                    ));
                    groups_failed
                        .get_or_insert_with(|| format!("{name} {scope_dir} Groups.xml: {e}"));
                }
            }
        }
        // A GPO whose computer settings don't apply sets no local group:
        // read, with nothing in it.
        match groups_failed {
            Some(why) => {
                groups.failed += 1;
                groups_error.get_or_insert(why);
            }
            None => groups.read += 1,
        }
        if !gpo.privileges.is_empty()
            || !gpo.restricted_groups.is_empty()
            || !gpo.gpp_local_groups.is_empty()
        {
            result.push(gpo);
        }
        progress.gpo_done();
    }
    progress.finish();
    out.checks.gpp.finish(timed_out, first_error);
    if let Some(c) = out.checks.registry_pol.as_mut() {
        c.finish(timed_out, regpol_error);
    }
    if timed_out {
        // Some GPOs weren't reached at all: the failures alone don't say
        // which GPOs are missing, so the part stays partial.
        out.registry_pol_failed.clear();
    }
    groups.finish(timed_out, groups_error);
    out.checks.gpo_local_groups = Some(groups);
    if timed_out {
        warn(format!(
            "SYSVOL read stopped after {} min: some GPOs were not read",
            SYSVOL_BUDGET.as_secs() / 60
        ));
    }
    let _ = tx.send(Msg::Log(format!(
        "[gpo] collected directives from {} on {dc_host} SYSVOL",
        pathwarden_core::text::count(result.len(), "GPO", "GPOs")
    )));
    Ok(result)
}

/// SYSVOL workers while the directory is read with `streams` streams: up
/// to [`pool::SYSVOL_WORKERS`], twice the streams at most.
pub(crate) fn early_workers(streams: usize) -> usize {
    pool::SYSVOL_WORKERS.min(2 * streams.max(1))
}

/// SYSVOL read alongside the directory: the GPO folders' files by
/// [`early_workers`] workers while the directory is read, the logon
/// scripts once it is (the entries name them), and what it all means
/// worked out after the parse, as before. Dropped, it stops its workers.
pub(crate) struct Early {
    work: EarlyWork,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

enum EarlyWork {
    /// Read after the parse, as before.
    Later,
    /// With a password: RustHound-CE's SMB client, on a thread of its own,
    /// and when its budget ends.
    Smb(
        std::thread::JoinHandle<SmbFiles>,
        std::time::Instant,
        Published,
        usize,
    ),
    /// As the current Windows user.
    #[cfg(windows)]
    CurrentUser(CurrentUserEarly),
}

impl Drop for Early {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Early {
    fn later() -> Self {
        Self {
            work: EarlyWork::Later,
            stop: Default::default(),
        }
    }

    /// Starts reading SYSVOL as the collection method does: with a
    /// password (`smb`), or as the current Windows user (finding the GPOs
    /// with one small indexed search on `ldap` first), with
    /// [`early_workers`]`(streams)` workers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        options: &Options,
        smb: &SmbIdentity,
        ldap: &mut ldap3::Ldap,
        domain_nc: &str,
        tx: &mpsc::Sender<Msg>,
        kerberos_only: bool,
        streams: usize,
    ) -> Self {
        let stop: std::sync::Arc<std::sync::atomic::AtomicBool> = Default::default();
        let workers = early_workers(streams);
        match options.collection_method {
            #[cfg(windows)]
            CollectionMethod::LdapOnly => {
                let work = CurrentUserEarly::start(
                    options,
                    ldap,
                    domain_nc,
                    tx,
                    kerberos_only,
                    &stop,
                    workers,
                )
                .await;
                Self {
                    work: EarlyWork::CurrentUser(work),
                    stop,
                }
            }
            ref m if m.does_gpo() => {
                let sign_in = SmbSignIn::of(options, smb);
                let domain = options.domain.clone();
                let flag = stop.clone();
                let deadline = std::time::Instant::now() + SYSVOL_BUDGET;
                let into = Published::default();
                let published = into.clone();
                let spawned = std::thread::Builder::new()
                    .name("pathwarden-sysvol".into())
                    .spawn(move || {
                        let halt = move || {
                            flag.load(std::sync::atomic::Ordering::Relaxed)
                                || std::time::Instant::now() > deadline
                        };
                        match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(rt) => {
                                let started = std::time::Instant::now();
                                let timed_out = rt.block_on(read_smb_files(
                                    &sign_in, &domain, workers, &halt, &published,
                                ));
                                SmbFiles::from_partial(
                                    &published,
                                    timed_out,
                                    started.elapsed(),
                                    workers,
                                )
                            }
                            Err(e) => SmbFiles::failed(
                                format!("cannot start reading SYSVOL: {e}"),
                                std::time::Duration::ZERO,
                            ),
                        }
                    });
                let _ = (ldap, domain_nc, tx, kerberos_only);
                match spawned {
                    Ok(h) => Self {
                        work: EarlyWork::Smb(h, deadline, into, workers),
                        stop,
                    },
                    Err(_) => Self::later(),
                }
            }
            _ => {
                let _ = (ldap, domain_nc, tx, kerberos_only, smb, workers);
                Self::later()
            }
        }
    }

    /// The read ended, naming these logon scripts (`scriptPath`, as
    /// given): as the current Windows user they are read now, while the
    /// parse runs.
    #[cfg_attr(not(windows), allow(unused_mut))]
    pub(crate) fn scripts(mut self, scripts: std::collections::BTreeSet<String>) -> Self {
        #[cfg(windows)]
        if let EarlyWork::CurrentUser(w) = &mut self.work {
            w.scripts(scripts, &self.stop);
        }
        #[cfg(not(windows))]
        let _ = scripts;
        self
    }

    /// With a password: the files read, once the workers are done. They
    /// start no folder past the budget; a session that hangs on the last
    /// ones is given a minute more, then the read counts as out of time.
    async fn smb_files(&mut self) -> Option<SmbFiles> {
        let EarlyWork::Smb(h, deadline, into, workers) =
            std::mem::replace(&mut self.work, EarlyWork::Later)
        else {
            return None;
        };
        let limit = deadline.saturating_duration_since(std::time::Instant::now())
            + std::time::Duration::from_secs(60);
        let joined =
            tokio::time::timeout(limit, tokio::task::spawn_blocking(move || h.join())).await;
        match joined {
            Ok(Ok(Ok(files))) => Some(files),
            Ok(_) => Some(SmbFiles::failed(
                "reading SYSVOL stopped unexpectedly".into(),
                std::time::Duration::ZERO,
            )),
            Err(_) => {
                // The workers stop at their next folder; what they read is
                // kept, as out of time.
                self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                Some(SmbFiles::from_partial(
                    &into,
                    true,
                    SYSVOL_BUDGET + std::time::Duration::from_secs(60),
                    workers,
                ))
            }
        }
    }
}
/// Most time the current-user SYSVOL step may take. Items not read by then
/// leave their part partial ("can't tell"). Read during the directory's
/// read, the GPO folders have it, across their workers; the logon scripts
/// (read once the read ends) and whatever the step reads itself share one
/// more, so the step ends within it. With a password, the GPO folders have
/// it too.
pub(crate) const SYSVOL_BUDGET: std::time::Duration = std::time::Duration::from_secs(600);

/// One GPO folder read as the current Windows user: the permissions of
/// the folder and its [`GPO_SUBFOLDERS`] (none past a missing folder), and
/// each GPP file, in [`GPP_FILES`] order under `Machine` then `User`.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub(crate) struct GpoFiles {
    sds: Vec<(&'static str, Got)>,
    gpp: Vec<(String, Got)>,
    /// `Machine\Registry.pol`, parsed as read.
    regpol: RegistryPolGot,
}

/// Reads the folder `folder` (`{GUID}`) of `domain`'s policies on `dc`.
#[cfg(windows)]
fn read_gpo_files(dc: &str, domain: &str, folder: &str) -> GpoFiles {
    use std::io::Read;
    let base = format!(r"\\{dc}\SYSVOL\{domain}\Policies\{folder}");
    let mut sds = Vec::new();
    for sub in GPO_SUBFOLDERS {
        let path = if sub.is_empty() {
            base.clone()
        } else {
            format!(r"{base}\{sub}")
        };
        let got = match super::winsec::file_sd(&path) {
            Ok(Some(sd)) => Got::Bytes(sd),
            Ok(None) => Got::Missing,
            Err(e) => Got::Failed(e),
        };
        // A GPO in AD with no folder: nothing under it either.
        let none = sub.is_empty() && got == Got::Missing;
        sds.push((sub, got));
        if none {
            break;
        }
    }
    let mut gpp = Vec::new();
    for scope_dir in ["Machine", "User"] {
        for (dir, file) in GPP_FILES {
            let rel = format!(r"{scope_dir}\Preferences\{dir}\{file}");
            let read = std::fs::File::open(format!(r"{base}\{rel}")).and_then(|f| {
                let mut bytes = Vec::new();
                f.take(MAX_GPP_XML as u64 + 1).read_to_end(&mut bytes)?;
                Ok(bytes)
            });
            let got = match read {
                Ok(bytes) => Got::Bytes(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Got::Missing,
                Err(e) => Got::Failed(e.to_string()),
            };
            gpp.push((rel, got));
        }
    }
    let read = std::fs::File::open(format!(r"{base}\{REGISTRY_POL}")).and_then(|f| {
        let mut bytes = Vec::new();
        f.take(pathwarden_core::sysvol::regpol::MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let regpol = registry_pol(match read {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    });
    GpoFiles { sds, gpp, regpol }
}

/// A logon script's permissions, from NETLOGON on `dc`.
#[cfg(windows)]
fn read_script(dc: &str, script: &str) -> Got {
    match super::winsec::file_sd(&format!(r"\\{dc}\NETLOGON\{script}")) {
        Ok(Some(sd)) => Got::Bytes(sd),
        Ok(None) => Got::Missing,
        Err(e) => Got::Failed(e),
    }
}

/// A pass of the current user's SYSVOL read: the items (GPO folders, or
/// logon scripts by lower-case name) and what each got.
#[cfg(windows)]
struct Pass<R> {
    items: Vec<String>,
    read: pool::Pooled<R>,
    took: std::time::Duration,
    /// When its budget ends.
    deadline: std::time::Instant,
    workers: usize,
}

#[cfg(windows)]
impl<R> Pass<R> {
    /// Each item read, by name.
    fn into_map(self) -> (std::collections::HashMap<String, R>, bool) {
        let timed_out = self.read.timed_out;
        let map = self
            .items
            .into_iter()
            .zip(self.read.results)
            .filter_map(|(k, r)| Some((k, r?)))
            .collect();
        (map, timed_out)
    }
}

/// What reading SYSVOL early as the current user got: the GPO folders,
/// and the logon scripts once the read named them.
#[cfg(windows)]
type Passes = (Option<Pass<GpoFiles>>, Option<Pass<Got>>);

/// The current user's early SYSVOL read.
#[cfg(windows)]
pub(crate) struct CurrentUserEarly {
    /// Why SYSVOL is not read (Kerberos only, and no ticket for the DC).
    refused: Option<String>,
    work: Option<std::thread::JoinHandle<Passes>>,
    dc: String,
    /// Workers each pass reads with.
    workers: usize,
}

#[cfg(windows)]
impl CurrentUserEarly {
    async fn start(
        options: &Options,
        ldap: &mut ldap3::Ldap,
        domain_nc: &str,
        tx: &mpsc::Sender<Msg>,
        kerberos_only: bool,
        stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        workers: usize,
    ) -> Self {
        let dc = dc_host(options);
        let mut me = Self {
            refused: None,
            work: None,
            dc: dc.clone(),
            workers,
        };
        // Kerberos only: the DC's cifs/ ticket first, so Windows
        // never signs in to it with NTLM.
        if kerberos_only {
            if let Err(why) = cifs_ticket(&dc).await {
                me.refused = Some(why.words());
                return me;
            }
        }
        let folders = match gpo_containers(ldap, domain_nc).await {
            Ok(f) => f,
            Err(e) => {
                let _ = tx.send(Msg::Log(format!(
                    "[sysvol] the GPOs could not be listed before the read ({e}): SYSVOL is \
                     read after it"
                )));
                return me;
            }
        };
        let (domain, flag) = (options.domain.clone(), stop.clone());
        me.work = std::thread::Builder::new()
            .name("pathwarden-sysvol".into())
            .spawn(move || {
                let started = std::time::Instant::now();
                let deadline = started + SYSVOL_BUDGET;
                let halt = || {
                    flag.load(std::sync::atomic::Ordering::Relaxed)
                        || std::time::Instant::now() > deadline
                };
                let read = pool::blocking(
                    &folders,
                    workers,
                    halt,
                    |f| read_gpo_files(&dc, &domain, f),
                    |_| {},
                );
                let pass = Pass {
                    items: folders,
                    read,
                    took: started.elapsed(),
                    deadline,
                    workers,
                };
                (Some(pass), None)
            })
            .ok();
        me
    }

    /// Reads `scripts` once the GPO folders are read: the same workers'
    /// count, never more at once.
    fn scripts(
        &mut self,
        scripts: std::collections::BTreeSet<String>,
        stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        if self.refused.is_some() {
            return;
        }
        // As the parse will group them (`gpp::logon_scripts`).
        let (scripts, _) =
            super::gpp::logon_scripts(scripts.into_iter().map(|s| (String::new(), s)));
        let names: Vec<String> = scripts.into_iter().map(|(s, _)| s).collect();
        let before = self.work.take();
        let (dc, flag, workers) = (self.dc.clone(), stop.clone(), self.workers);
        self.work = std::thread::Builder::new()
            .name("pathwarden-sysvol".into())
            .spawn(move || {
                let gpos = before.and_then(|h| h.join().ok()).and_then(|(g, _)| g);
                let started = std::time::Instant::now();
                let deadline = started + SYSVOL_BUDGET;
                let halt = || {
                    flag.load(std::sync::atomic::Ordering::Relaxed)
                        || std::time::Instant::now() > deadline
                };
                let read = pool::blocking(&names, workers, halt, |s| read_script(&dc, s), |_| {});
                let items = names.iter().map(|s| s.to_ascii_lowercase()).collect();
                let pass = Pass {
                    items,
                    read,
                    took: started.elapsed(),
                    deadline,
                    workers,
                };
                (gpos, Some(pass))
            })
            .ok();
    }
}

/// Asks SSPI for the DC's cifs/ ticket, on a blocking thread.
#[cfg(windows)]
async fn cifs_ticket(dc: &str) -> Result<(), super::krb::NoTicket> {
    let probe = dc.to_string();
    let asked = tokio::task::spawn_blocking(move || super::winkrb::cifs_ticket(&probe)).await;
    // A check that didn't come back (a panic) counts as no ticket.
    asked.unwrap_or_else(|_| {
        Err(super::krb::NoTicket::Refused(
            "Kerberos: asking for the ticket stopped unexpectedly".into(),
        ))
    })
}

/// The GPOs' folder names (`{GUID}`), from one indexed search of the
/// domain: `groupPolicyContainer` objects, their `gPCFileSysPath`.
#[cfg(windows)]
async fn gpo_containers(ldap: &mut ldap3::Ldap, domain_nc: &str) -> Result<Vec<String>, String> {
    use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
    let mut ldap = ldap.clone();
    let adapters: Vec<Box<dyn Adapter<'_, &str, Vec<&str>>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(999)),
    ];
    let what = "listing the GPOs";
    let mut search = super::or_stalled(
        super::STALL_TIMEOUT,
        what,
        ldap.streaming_search_with(
            adapters,
            domain_nc,
            ldap3::Scope::Subtree,
            "(objectCategory=groupPolicyContainer)",
            vec!["gPCFileSysPath", "objectGUID"],
        ),
    )
    .await?;
    let mut folders = Vec::new();
    while let Some(e) = super::or_stalled(super::STALL_TIMEOUT, what, search.next()).await? {
        let e = ldap3::SearchEntry::construct(e);
        let from_path = e
            .attrs
            .get("gPCFileSysPath")
            .and_then(|v| v.first())
            .and_then(|p| folder_of(p));
        // `CN={GUID},CN=Policies,...` otherwise.
        let from_dn = || {
            let cn = e.dn.split(',').next()?.trim();
            let (k, v) = cn.split_once('=')?;
            let v = v.trim().to_uppercase();
            (k.eq_ignore_ascii_case("CN") && super::gpp::is_gpo_guid(&v)).then_some(v)
        };
        if let Some(f) = from_path.or_else(from_dn) {
            if !folders.contains(&f) {
                folders.push(f);
            }
        }
    }
    search
        .finish()
        .await
        .success()
        .map_err(|e| format!("{what} failed: {e}"))?;
    Ok(folders)
}

/// The SYSVOL step as the current Windows user: GPP passwords, GPO folder
/// permissions and logon script permissions, through Windows' SMB client.
/// What `early` read while the directory was is used; the rest is read
/// now. Runs on a blocking thread; a Win32 call that hangs can't be
/// interrupted, so past the budget (plus a minute) the step is given up
/// and every part recorded as not collected.
#[cfg(windows)]
pub(crate) async fn current_user(
    options: &Options,
    ad: &ADResults,
    tx: &mpsc::Sender<Msg>,
    kerberos_only: bool,
    mut early: Early,
) -> SidecarOut {
    let early = match std::mem::replace(&mut early.work, EarlyWork::Later) {
        EarlyWork::CurrentUser(w) => Some(w),
        _ => None,
    };
    let dc = dc_host(options);
    // Kerberos only: the DC's cifs/ ticket first, so Windows never
    // signs in to it with NTLM. Asked before the read when SYSVOL was read
    // early.
    let refused = match &early {
        Some(e) => e.refused.clone(),
        None if kerberos_only => cifs_ticket(&dc).await.err().map(|w| w.words()),
        None => None,
    };
    if let Some(reason) = refused {
        let _ = tx.send(Msg::Log(format!(
            "warning: [sysvol] {dc}: skipped: {reason}"
        )));
        let not_read = CheckOut::not_collected(&format!("SYSVOL was not read: {reason}"));
        let mut out = SidecarOut::new(&options.domain, &dc);
        out.checks.gpp = not_read.clone();
        out.checks.gpo_acl = not_read.clone();
        out.checks.logon_script_acl = not_read.clone();
        out.checks.registry_pol = Some(not_read.clone());
        out.checks.gpo_local_groups = Some(not_read);
        return out;
    }
    let mut out = current_user_files(options, ad, tx, early.and_then(|e| e.work)).await;
    out.checks.gpo_local_groups = Some(CheckOut::not_collected(NO_LOCAL_GROUPS_AS_CURRENT_USER));
    out
}

/// Why GPO local groups are missing from a collection as the current user.
#[cfg(windows)]
const NO_LOCAL_GROUPS_AS_CURRENT_USER: &str =
    "not read as the current Windows user: GPO local groups are read with a user and password (--user)";

#[cfg(windows)]
async fn current_user_files(
    options: &Options,
    ad: &ADResults,
    tx: &mpsc::Sender<Msg>,
    early: Option<std::thread::JoinHandle<Passes>>,
) -> SidecarOut {
    let domain = options.domain.clone();
    let dc = dc_host(options);
    let gpos = gpo_folders(ad);
    let scripts = super::gpp::logon_scripts(user_scripts(ad));
    let tx2 = tx.clone();
    let mut progress = SysvolProgress::new(tx.clone(), gpos.len(), scripts.0.len(), true);
    let stop = progress.stop_handle();
    // The step's budget: what is read now (late GPOs, scripts not read
    // early) shares it with the scripts' early pass, so the step ends within
    // it and the outer limit below never drops what was read.
    let step_deadline = std::time::Instant::now() + SYSVOL_BUDGET;
    let work = tokio::task::spawn_blocking({
        let (domain, dc) = (domain.clone(), dc.clone());
        move || {
            let warn = |m: String| {
                let _ = tx2.send(Msg::Log(format!("warning: [sysvol] {m}")));
            };
            progress.start();
            // What was read alongside the directory (its own budget per pass).
            let (gpos_early, scripts_early) =
                early.and_then(|h| h.join().ok()).unwrap_or((None, None));
            let said = |what: String, workers: usize, took: std::time::Duration| {
                let _ = tx2.send(Msg::Log(format!(
                    "[sysvol] {what} read early with {workers} workers in {}",
                    super::timings::secs(took)
                )));
            };
            if let Some(p) = &gpos_early {
                let n = p.items.len();
                said(
                    pathwarden_core::text::count(n, "GPO folder", "GPO folders"),
                    p.workers,
                    p.took,
                );
            }
            if let Some(p) = &scripts_early {
                let n = p.items.len();
                said(
                    pathwarden_core::text::count(n, "logon script", "logon scripts"),
                    p.workers,
                    p.took,
                );
            }
            let deadline = scripts_early
                .as_ref()
                .map_or(step_deadline, |p| p.deadline.min(step_deadline));
            let early = Early2 {
                deadline,
                gpos: gpos_early.map(Pass::into_map),
                scripts: scripts_early.map(Pass::into_map),
            };
            let out =
                read_as_current_user(&domain, &dc, &gpos, scripts, early, &mut progress, &warn);
            progress.finish();
            out
        }
    });
    let limit = SYSVOL_BUDGET + std::time::Duration::from_secs(60);
    match tokio::time::timeout(limit, work).await {
        Ok(Ok(out)) => {
            let _ = tx.send(Msg::Log(format!(
                "[sysvol] read {}, {}, {} on {dc}; {} found",
                pathwarden_core::text::count(out.checks.gpo_acl.read, "GPO folder", "GPO folders"),
                pathwarden_core::text::count(
                    out.checks.logon_script_acl.read,
                    "logon script",
                    "logon scripts"
                ),
                pathwarden_core::text::count(out.checks.gpp.read, "GPP file", "GPP files"),
                pathwarden_core::text::count(
                    out.gpp_passwords.len(),
                    "GPP password",
                    "GPP passwords"
                )
            )));
            out
        }
        Ok(Err(e)) => not_read(&domain, &dc, &format!("the SYSVOL step failed: {e}")),
        Err(_) => {
            // The thread may still finish later: it reports nothing more.
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = tx.send(Msg::Log(
                "warning: [sysvol] no answer from SYSVOL in time; its findings can't be checked \
                 this run"
                    .into(),
            ));
            not_read(&domain, &dc, "the domain controller did not answer in time")
        }
    }
}

/// What the current user's early SYSVOL read got, by name, and whether
/// each pass ran out of time.
#[cfg(windows)]
struct Early2 {
    /// What isn't read early is read by then (one deadline for the step).
    deadline: std::time::Instant,
    gpos: Option<(std::collections::HashMap<String, GpoFiles>, bool)>,
    scripts: Option<(std::collections::HashMap<String, Got>, bool)>,
}

#[cfg(windows)]
fn not_read(domain: &str, dc: &str, why: &str) -> SidecarOut {
    let mut out = SidecarOut::new(domain, dc);
    out.checks.gpo_acl = CheckOut::not_collected(why);
    out.checks.logon_script_acl = CheckOut::not_collected(why);
    out.checks.gpp = CheckOut::not_collected(why);
    out.checks.registry_pol = Some(CheckOut::not_collected(why));
    out
}

/// Subfolders of a GPO whose permissions are read: the folder itself and
/// where settings, scripts and preferences live. Files inherit from these.
#[cfg(windows)]
pub(crate) const GPO_SUBFOLDERS: [&str; 5] =
    ["", "Machine", "User", r"Machine\Scripts", r"User\Scripts"];

/// The sidecar from what was read early, reading what wasn't now (a GPO
/// made during the read, or the GPOs when they couldn't be listed), each
/// pass within its budget.
#[cfg(windows)]
fn read_as_current_user(
    domain: &str,
    dc: &str,
    gpos: &[(String, String, bool)],
    (scripts, outside): (Vec<(String, Vec<String>)>, usize),
    early: Early2,
    progress: &mut SysvolProgress,
    warn: &dyn Fn(String),
) -> SidecarOut {
    use super::gpp::{hex, FolderOut, GpoOut, ScriptOut};

    let mut out = SidecarOut::new(domain, dc);
    let (mut gpos_early, gpos_early_late) = early.gpos.unwrap_or_default();
    let mut timed_out = false;
    let deadline = early.deadline;
    let (mut acl_error, mut gpp_error) = (None, None);
    let mut regpol_error = None;
    out.checks.registry_pol = Some(CheckOut::default());
    for (folder, object_id, computer) in gpos {
        let raw = match gpos_early.remove(folder) {
            Some(r) => r,
            // Its pass ran out of time before it.
            None if gpos_early_late => {
                timed_out = true;
                continue;
            }
            None => {
                if std::time::Instant::now() > deadline {
                    timed_out = true;
                    break;
                }
                read_gpo_files(dc, domain, folder)
            }
        };
        let mut entry = GpoOut {
            guid: folder.clone(),
            object_id: Some(object_id.clone()),
            folders: Vec::new(),
        };
        for (sub, got) in raw.sds {
            match got {
                Got::Bytes(sd) => {
                    out.checks.gpo_acl.read += 1;
                    entry.folders.push(FolderOut {
                        path: sub.to_string(),
                        sd: hex(&sd),
                    });
                }
                // A GPO in AD with no folder: nothing to write to.
                Got::Missing if sub.is_empty() => out.checks.gpo_acl.skipped += 1,
                Got::Missing => {}
                Got::Failed(e) => {
                    out.checks.gpo_acl.failed += 1;
                    acl_error.get_or_insert(e);
                }
            }
        }
        if !entry.folders.is_empty() {
            out.gpos.push(entry);
        }
        for (rel, got) in raw.gpp {
            match got {
                Got::Bytes(bytes) => {
                    out.scan_gpp(folder, Some(object_id), &rel, &bytes, &mut gpp_error, warn)
                }
                Got::Missing => {}
                Got::Failed(e) => {
                    out.checks.gpp.failed += 1;
                    gpp_error.get_or_insert(e);
                }
            }
        }
        // As in a password collection: computer settings that are off
        // don't apply.
        if *computer {
            out.add_registry_pol(
                folder,
                Some(object_id),
                &raw.regpol,
                &mut regpol_error,
                warn,
            );
        } else if raw.regpol != RegistryPolGot::Missing {
            if let Some(c) = out.checks.registry_pol.as_mut() {
                c.skipped += 1;
            }
        }
        progress.gpo_done();
    }
    out.checks.gpo_acl.finish(timed_out, acl_error);
    out.checks.gpp.finish(timed_out, gpp_error);
    if let Some(c) = out.checks.registry_pol.as_mut() {
        c.finish(timed_out, regpol_error);
    }
    if timed_out {
        // Some GPOs weren't reached at all: the failures alone don't say
        // which GPOs are missing, so the part stays partial.
        out.registry_pol_failed.clear();
    }

    out.checks.logon_script_acl.skipped = outside;
    let (mut scripts_early, scripts_early_late) = early.scripts.unwrap_or_default();
    let mut script_error = None;
    let mut script_timeout = false;
    for (script, sids) in scripts {
        let got = match scripts_early.remove(&script.to_ascii_lowercase()) {
            Some(g) => g,
            None if scripts_early_late => {
                script_timeout = true;
                continue;
            }
            None => {
                if std::time::Instant::now() > deadline {
                    script_timeout = true;
                    break;
                }
                read_script(dc, &script)
            }
        };
        match got {
            Got::Bytes(sd) => {
                out.checks.logon_script_acl.read += 1;
                out.logon_scripts.push(ScriptOut {
                    script,
                    users: sids,
                    sd: hex(&sd),
                });
            }
            // A script the users name but NETLOGON lacks: nothing runs.
            Got::Missing => out.checks.logon_script_acl.skipped += 1,
            Got::Failed(e) => {
                out.checks.logon_script_acl.failed += 1;
                script_error.get_or_insert(e);
            }
        }
        progress.script_done();
    }
    out.checks
        .logon_script_acl
        .finish(script_timeout, script_error);
    if timed_out || script_timeout {
        let ((g, gs), (l, ls)) = (progress.gpos(), progress.scripts());
        warn(format!(
            "SYSVOL step stopped after {} min: {} of {} GPOs read, {} of {} logon scripts",
            SYSVOL_BUDGET.as_secs() / 60,
            crate::progress::thousands(g),
            crate::progress::thousands(gs),
            crate::progress::thousands(l),
            crate::progress::thousands(ls)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2024-01-01 10:00:00" uid="{A1}"><Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)"><Members><Member name="CONTOSO\Helpdesk" action="ADD" sid="S-1-5-21-1-2-3-1105"/></Members></Properties></Group></Groups>"#;

    #[test]
    fn real_groups_xml_passes_and_parses() {
        assert_eq!(xml_is_safe(REAL.as_bytes()), Ok(()));
        let groups = parse_groups_xml(REAL.as_bytes())
            .map_err(|e| e.to_string())
            .unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn hostile_groups_xml_is_refused_quickly() {
        // One element, 300k attributes: quick-xml would take minutes.
        let mut x = String::from("<Groups><Group ");
        for i in 0..300_000 {
            x.push_str(&format!("a{i}=\"\" "));
        }
        x.push_str("/></Groups>");
        let started = std::time::Instant::now();
        let err = xml_is_safe(x.as_bytes()).unwrap_err();
        assert!(err.contains("more than 256 attributes"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // `=` and `>` inside quoted values are not attributes or tag ends.
        let quoted = format!("<a b=\"{}\" c='x>y'/>", "=".repeat(1000));
        assert_eq!(xml_is_safe(quoted.as_bytes()), Ok(()));
        // 256 is fine, 257 is not; the count restarts at each tag.
        let tag = |n: usize| {
            format!(
                "<e {}/>",
                (0..n).map(|i| format!("a{i}='1' ")).collect::<String>()
            )
        };
        assert!(xml_is_safe(tag(256).as_bytes()).is_ok());
        assert!(xml_is_safe(tag(257).as_bytes()).is_err());
        assert!(xml_is_safe(format!("{}{}", tag(200), tag(200)).as_bytes()).is_ok());
        let big = vec![b' '; MAX_GPP_XML + 1];
        assert!(xml_is_safe(&big).unwrap_err().contains("4 MiB"));
    }

    /// One message a [`SysvolProgress`] sent: a detail, or units.
    type Sent = (Option<String>, Option<(u64, u64)>);

    fn drain(rx: &mpsc::Receiver<Msg>) -> Vec<Sent> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Detail(d) => out.push((Some(d), None)),
                Msg::Units { done, total } => out.push((None, Some((done, total.unwrap())))),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn progress_is_throttled_and_says_what_it_reads() {
        use std::time::{Duration, Instant};
        let (tx, rx) = mpsc::channel();
        let mut p = SysvolProgress::new(tx, 1830, 95, true);
        p.start();
        assert!(matches!(rx.try_recv(), Ok(Msg::Unit("items"))));
        assert_eq!(
            drain(&rx),
            [
                (Some("GPO 1 of 1,830".into()), None),
                (None, Some((0, 1925)))
            ]
        );
        // 1,000 GPOs in 100 ms: nothing more within the 250 ms.
        let t0 = p.last.unwrap();
        for i in 0..1000u64 {
            p.gpo_done_at(t0 + Duration::from_micros(i * 100));
        }
        assert!(drain(&rx).is_empty());
        // The next one past 250 ms reports, once.
        p.gpo_done_at(t0 + Duration::from_millis(300));
        p.gpo_done_at(t0 + Duration::from_millis(301));
        assert_eq!(
            drain(&rx),
            [
                (Some("GPO 1,002 of 1,830".into()), None),
                (None, Some((1001, 1925)))
            ]
        );
        // The last GPO always reports, however soon; then the scripts.
        for _ in 1002..1830 {
            p.gpo_done_at(t0 + Duration::from_millis(302));
        }
        assert_eq!(
            drain(&rx),
            [
                (Some("logon scripts 0 of 95".into()), None),
                (None, Some((1830, 1925)))
            ]
        );
        let t1 = Instant::now() + Duration::from_secs(1);
        p.script_done_at(t1);
        for i in 1..95 {
            p.script_done_at(t1 + Duration::from_millis(i));
        }
        assert_eq!(
            drain(&rx),
            [
                (Some("logon scripts 1 of 95".into()), None),
                (None, Some((1831, 1925))),
                (Some("logon scripts 95 of 95".into()), None),
                (None, Some((1925, 1925)))
            ]
        );
        // More items than counted never go past the total.
        p.gpo_done_at(t1 + Duration::from_secs(5));
        assert_eq!(drain(&rx).last().unwrap().1, Some((1925, 1925)));
    }

    /// In a full collection SYSVOL is part of contacting computers: the
    /// detail line only, cleared at the end.
    #[test]
    fn progress_inside_a_larger_step_sends_no_units() {
        let (tx, rx) = mpsc::channel();
        let mut p = SysvolProgress::new(tx, 2, 0, false);
        p.start();
        p.gpo_done();
        p.gpo_done();
        p.finish();
        assert_eq!(
            drain(&rx),
            [
                (Some("GPO 1 of 2".into()), None),
                (Some("GPO 2 of 2".into()), None),
                (Some(String::new()), None)
            ]
        );
    }

    /// Nothing to read: no "GPO 0 of 0", no "0 of ~0 items".
    #[test]
    fn progress_with_nothing_to_read_says_nothing() {
        for units in [true, false] {
            let (tx, rx) = mpsc::channel();
            let mut p = SysvolProgress::new(tx, 0, 0, units);
            p.start();
            p.gpo_done();
            p.finish();
            assert!(rx.try_recv().is_err());
        }
    }

    /// After the step gave up on the reading thread, a late thread reports
    /// nothing into the next step.
    #[test]
    fn progress_stopped_sends_nothing_more() {
        let (tx, rx) = mpsc::channel();
        let mut p = SysvolProgress::new(tx, 3, 1, true);
        p.start();
        assert!(!drain(&rx).is_empty());
        p.stop_handle()
            .store(true, std::sync::atomic::Ordering::Relaxed);
        std::thread::spawn(move || {
            for _ in 0..3 {
                p.gpo_done();
            }
            p.script_done_at(std::time::Instant::now());
            p.finish();
        })
        .join()
        .unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn sysvol_weight_follows_the_gpo_count() {
        use std::time::Duration;
        let read = Duration::from_secs(60);
        // A handful of GPOs: the planned weight.
        assert_eq!(sysvol_weight(4.0, 10, 0, 62.0, read, None), 4.0);
        // 1,800 GPOs, about 3 minutes against a 1 minute read: about 3
        // times the read's share.
        let w = sysvol_weight(4.0, 1800, 0, 62.0, read, None);
        assert!((180.0..=190.0).contains(&w), "{w}");
        // Logon scripts count too, for less.
        assert!(sysvol_weight(4.0, 1800, 5000, 62.0, read, None) > w);
        // Never more than 10 reads' worth; a read of no time says little.
        assert_eq!(sysvol_weight(4.0, 100_000, 0, 62.0, read, None), 620.0);
        assert_eq!(sysvol_weight(4.0, 10, 0, 62.0, Duration::ZERO, None), 62.0);
        // As the current user the step ends at its budget: 10,000 GPOs
        // weigh what 10 minutes do (5 reads of 2 minutes), not 8 reads.
        let ten_min = Some(SYSVOL_BUDGET);
        let long_read = Duration::from_secs(120);
        assert_eq!(
            sysvol_weight(4.0, 10_000, 0, 62.0, long_read, None),
            62.0 * 1000.0 / 120.0
        );
        assert_eq!(
            sysvol_weight(4.0, 10_000, 0, 62.0, long_read, ten_min),
            62.0 * 5.0
        );
        assert_eq!(sysvol_weight(4.0, 1800, 0, 62.0, read, ten_min), w);
    }

    #[test]
    fn gpo_folder_names_come_from_gpcpath_and_are_checked() {
        assert_eq!(
            folder_of(r"\\contoso.local\sysvol\contoso.local\Policies\{31b2f340-016d-11d2-945f-00c04fb984f9}")
                .as_deref(),
            Some("{31B2F340-016D-11D2-945F-00C04FB984F9}")
        );
        // A gpcpath pointing anywhere else is never followed: only the
        // name is used, under the DC's own SYSVOL.
        assert_eq!(folder_of(r"\\evil\share\x"), None);
        assert_eq!(folder_of(""), None);
    }

    const GPO_A: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
    const GPO_B: &str = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";
    const GPO_C: &str = "{0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9}";
    const SERVICES: &[u8] = br#"<NTServices><NTService name="svc"><Properties serviceName="x" accountName="CONTOSO\svc_sql" cpassword="abc"/></NTService></NTServices>"#;

    /// Files by path; records the largest read it was asked for.
    struct FakeShare {
        files: std::collections::HashMap<String, Vec<u8>>,
        asked: usize,
    }

    impl CappedRead for FakeShare {
        async fn read_capped(
            &mut self,
            path: &str,
            max: usize,
        ) -> Result<Option<(Vec<u8>, bool)>, String> {
            self.asked = self.asked.max(max);
            Ok(self.files.get(path).map(|b| {
                let n = b.len().min(max);
                (b[..n].to_vec(), b.len() > max)
            }))
        }
    }

    #[test]
    fn planted_files_are_read_to_their_cap_only() {
        let base = r"contoso.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}";
        let huge = vec![b'x'; 9 * 1024 * 1024];
        let mut share = FakeShare {
            files: [
                (format!(r"{base}\{REGISTRY_POL}"), huge.clone()),
                (
                    format!(r"{base}\Machine\Preferences\Groups\Groups.xml"),
                    huge,
                ),
            ]
            .into(),
            asked: 0,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let got = rt.block_on(read_gpo_smb(&mut share, base));
        assert!(share.asked <= MAX_GPP_XML.max(pathwarden_core::sysvol::regpol::MAX_FILE));
        assert!(
            matches!(&got.regpol, RegistryPolGot::Unreadable(why) if why.contains("MiB")),
            "{:?}",
            got.regpol
        );
        let groups = got
            .gpp
            .iter()
            .find(|(s, d, _, _)| *s == "Machine" && *d == "Groups")
            .unwrap();
        match &groups.3 {
            Got::Bytes(b) => {
                assert_eq!(b.len(), MAX_GPP_XML + 1);
                assert!(xml_is_safe(b).is_err());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(got.gpttmpl, Got::Missing);
    }

    /// A `Registry.pol` that points computers at the WSUS server `url`.
    fn wsus_pol(url: &str) -> Vec<u8> {
        use pathwarden_core::sysvol::regpol::{build, sz};
        let wu = r"Software\Policies\Microsoft\Windows\WindowsUpdate";
        build(&[
            (wu, "WUServer", 1, &sz(url)),
            (wu, "WUStatusServer", 1, &sz(url)),
            (&format!(r"{wu}\AU"), "UseWUServer", 4, &1u32.to_le_bytes()),
            (
                r"Software\Policies\Microsoft\Windows\System",
                "EnableSmartScreen",
                4,
                &1u32.to_le_bytes(),
            ),
        ])
    }

    /// Each GPP file under `Machine` and `User`: `services` as the Machine
    /// `Services.xml`, the rest missing.
    fn gpp_files(services: Got) -> Vec<(&'static str, &'static str, &'static str, Got)> {
        let mut out = Vec::new();
        for scope_dir in ["Machine", "User"] {
            for (dir, file) in GPP_FILES {
                let got = if scope_dir == "Machine" && dir == "Services" {
                    services.clone()
                } else {
                    Got::Missing
                };
                out.push((scope_dir, dir, file, got));
            }
        }
        out
    }

    /// What the SMB workers read while the directory was read makes
    /// the sidecar as reading it after the parse did: GPP passwords found,
    /// a GPO no worker read and a file that failed counted as failed (the
    /// first error said), and a SYSVOL that couldn't be listed an error.
    #[test]
    fn a_password_read_out_of_time_keeps_what_it_read() {
        // Published as read: GPO A, not yet B and C, when the time ran out.
        let into = Published::default();
        {
            let mut p = into.lock().unwrap();
            p.listed = Some(Ok(vec![GPO_A.into(), GPO_B.into(), GPO_C.into()]));
            p.gpos = vec![Some(GpoSmb {
                gpttmpl: Got::Missing,
                gpp: gpp_files(Got::Bytes(SERVICES.to_vec())),
                regpol: RegistryPolGot::Missing,
            })];
        }
        let files = SmbFiles::from_partial(&into, true, std::time::Duration::from_secs(660), 8);
        assert!(files.timed_out);
        assert_eq!(files.gpos.len(), 3);
        let options = super::super::base_options(
            "contoso.local",
            std::path::Path::new("."),
            CollectionMethod::DCOnly,
            "dc01.contoso.local".into(),
            true,
        );
        let identity = SmbIdentity {
            domain: "CONTOSO".into(),
            other_domain: false,
            kerberos: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (tx, _rx) = mpsc::channel();
        let mut out = SidecarOut::new("contoso.local", "dc01.contoso.local");
        rt.block_on(collect_sysvol(
            &options,
            &identity,
            &ADResults::default(),
            &tx,
            &mut out,
            true,
            Some(files),
        ))
        .unwrap();
        // A's password kept; the part partial, out of time, not failed.
        assert_eq!(out.gpp_passwords.len(), 1);
        let gpp = &out.checks.gpp;
        assert_eq!((gpp.read, gpp.failed, gpp.status), (1, 0, "partial"));
        assert_eq!(
            gpp.reason.as_deref(),
            Some("the SYSVOL step ran out of time")
        );
        assert_eq!(
            out.checks.gpo_local_groups.as_ref().map(|c| c.status),
            Some("partial")
        );
        // Nothing listed by then: not read, said so.
        let none = SmbFiles::from_partial(&Published::default(), true, Default::default(), 8);
        assert_eq!(
            none.listed.unwrap_err(),
            "the domain controller did not answer in time"
        );
    }

    #[test]
    fn smb_files_read_early_make_the_same_sidecar() {
        let options = super::super::base_options(
            "contoso.local",
            std::path::Path::new("."),
            CollectionMethod::DCOnly,
            "dc01.contoso.local".into(),
            true,
        );
        let identity = SmbIdentity {
            domain: "CONTOSO".into(),
            other_domain: false,
            kerberos: None,
        };
        let ad = ADResults::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let files = SmbFiles {
            listed: Ok(vec![GPO_A.into(), GPO_B.into(), GPO_C.into()]),
            gpos: vec![
                Some(GpoSmb {
                    gpttmpl: Got::Missing,
                    gpp: gpp_files(Got::Bytes(SERVICES.to_vec())),
                    regpol: RegistryPolGot::of(&wsus_pol("http://wsus01.contoso.local:8530")),
                }),
                None,
                Some(GpoSmb {
                    gpttmpl: Got::Missing,
                    gpp: gpp_files(Got::Failed("read: STATUS_ACCESS_DENIED".into())),
                    regpol: RegistryPolGot::Unreadable("read: STATUS_ACCESS_DENIED".into()),
                }),
            ],
            lost: Some("STATUS_LOGON_FAILURE".into()),
            timed_out: false,
            took: std::time::Duration::from_secs(72),
            workers: 8,
        };
        let (tx, _rx) = mpsc::channel();
        let mut out = SidecarOut::new("contoso.local", "dc01.contoso.local");
        let gpos = rt
            .block_on(collect_sysvol(
                &options,
                &identity,
                &ad,
                &tx,
                &mut out,
                true,
                Some(files),
            ))
            .unwrap();
        assert!(gpos.is_empty());
        assert_eq!(out.gpp_passwords.len(), 1);
        assert_eq!(out.gpp_passwords[0].guid, GPO_A);
        assert_eq!(out.gpp_passwords[0].accounts, ["CONTOSO\\svc_sql"]);
        let gpp = &out.checks.gpp;
        assert_eq!((gpp.read, gpp.failed, gpp.status), (1, 2, "partial"));
        assert_eq!(
            gpp.reason.as_deref(),
            Some("2 items could not be read, first: STATUS_LOGON_FAILURE")
        );
        // No GPO in AD, so no computer settings apply: A's and C's
        // Registry.pol are skipped, B's not read.
        let pol = out.checks.registry_pol.as_ref().unwrap();
        assert_eq!(
            (pol.read, pol.failed, pol.skipped, pol.status),
            (0, 1, 2, "not_collected")
        );
        assert!(out.registry_policy.is_empty());
        // SYSVOL could not be listed: the error, as before.
        let files = SmbFiles {
            listed: Err("list contoso.local\\Policies: STATUS_ACCESS_DENIED".into()),
            gpos: Vec::new(),
            lost: None,
            timed_out: false,
            took: std::time::Duration::ZERO,
            workers: 8,
        };
        let mut out = SidecarOut::new("contoso.local", "dc01.contoso.local");
        let e = rt
            .block_on(collect_sysvol(
                &options,
                &identity,
                &ad,
                &tx,
                &mut out,
                true,
                Some(files),
            ))
            .unwrap_err();
        assert!(e.contains("STATUS_ACCESS_DENIED"), "{e}");
    }

    /// A GPO in AD whose computer settings apply, with its folder `guid`.
    fn ad_gpo(guid: &str) -> rusthound_ce::objects::gpo::Gpo {
        serde_json::from_value(serde_json::json!({
            "Properties": {
                "domain": "CONTOSO.LOCAL", "name": guid, "distinguishedname": "",
                "domainsid": "", "objectguid": "", "doesanyacegrantownerrights": false,
                "doesanyinheritedacegrantownerrights": false, "isaclprotected": false,
                "highvalue": false, "whencreated": 0,
                "gpcpath": format!(r"\\contoso.local\SysVol\contoso.local\Policies\{guid}"),
                "gpostatus": "0"
            },
            "Aces": [], "ObjectIdentifier": guid.trim_matches(['{', '}']),
            "IsDeleted": false, "IsACLProtected": false, "ContainedBy": null
        }))
        .unwrap()
    }

    /// A GptTmpl.inf that couldn't be read, a Groups.xml refused
    /// and a GPO folder no worker read leave the local groups part partial,
    /// the first named; a GPO read whole counts as read.
    #[test]
    fn unread_local_group_files_make_the_part_partial() {
        let options = super::super::base_options(
            "contoso.local",
            std::path::Path::new("."),
            CollectionMethod::DCOnly,
            "dc01.contoso.local".into(),
            true,
        );
        let identity = SmbIdentity {
            domain: "CONTOSO".into(),
            other_domain: false,
            kerberos: None,
        };
        const GPO_D: &str = "{0D1B2C3D-4E5F-4061-8273-94A5B6C7D8E9}";
        let mut ad = ADResults::default();
        for g in [GPO_A, GPO_B, GPO_C, GPO_D] {
            ad.gpos.push(ad_gpo(g));
        }
        let mut hostile = String::from("<Groups><User ");
        for i in 0..300 {
            hostile.push_str(&format!("a{i}=\"\" "));
        }
        hostile.push_str("/></Groups>");
        let groups_xml = |got: Got| {
            gpp_files(Got::Missing)
                .into_iter()
                .map(|(s, d, f, g)| {
                    if s == "Machine" && d == "Groups" {
                        (s, d, f, got.clone())
                    } else {
                        (s, d, f, g)
                    }
                })
                .collect::<Vec<_>>()
        };
        let files = SmbFiles {
            listed: Ok(vec![GPO_A.into(), GPO_B.into(), GPO_C.into(), GPO_D.into()]),
            gpos: vec![
                Some(GpoSmb {
                    gpttmpl: Got::Failed("read: STATUS_ACCESS_DENIED".into()),
                    gpp: gpp_files(Got::Missing),
                    regpol: RegistryPolGot::Missing,
                }),
                Some(GpoSmb {
                    gpttmpl: Got::Missing,
                    gpp: groups_xml(Got::Bytes(hostile.into_bytes())),
                    regpol: RegistryPolGot::Missing,
                }),
                None,
                Some(GpoSmb {
                    gpttmpl: Got::Missing,
                    gpp: gpp_files(Got::Missing),
                    regpol: RegistryPolGot::Missing,
                }),
            ],
            lost: Some("STATUS_LOGON_FAILURE".into()),
            timed_out: false,
            took: std::time::Duration::from_secs(1),
            workers: 8,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = mpsc::channel();
        let mut out = SidecarOut::new("contoso.local", "dc01.contoso.local");
        rt.block_on(collect_sysvol(
            &options,
            &identity,
            &ad,
            &tx,
            &mut out,
            true,
            Some(files),
        ))
        .unwrap();
        let groups = out.checks.gpo_local_groups.as_ref().unwrap();
        assert_eq!(
            (groups.read, groups.failed, groups.status),
            (1, 3, "partial")
        );
        let reason = groups.reason.as_deref().unwrap();
        assert!(
            reason.contains(&format!("{GPO_A} GptTmpl.inf: read: STATUS_ACCESS_DENIED")),
            "{reason}"
        );
        let said: Vec<String> = rx
            .try_iter()
            .filter_map(|m| match m {
                Msg::Log(l) => Some(l),
                _ => None,
            })
            .collect();
        assert!(said
            .iter()
            .any(|l| l.contains("GptTmpl.inf not read") && l.contains("local groups")));
        assert!(said.iter().any(|l| l.contains("Groups.xml skipped")));
    }

    /// As the current Windows user: what the workers read early makes
    /// the sidecar (folder permissions read, missing, failed; GPP files;
    /// logon scripts), and a GPO the GPO pass ran out of time before
    /// leaves that part partial, the scripts' pass not.
    #[cfg(windows)]
    #[test]
    fn current_user_files_read_early_make_the_sidecar() {
        let sd = vec![1u8, 0, 4, 128];
        let a = GpoFiles {
            sds: vec![
                ("", Got::Bytes(sd.clone())),
                ("Machine", Got::Missing),
                ("User", Got::Failed("Access is denied. (os error 5)".into())),
                (r"Machine\Scripts", Got::Bytes(sd.clone())),
                (r"User\Scripts", Got::Missing),
            ],
            gpp: gpp_files(Got::Bytes(SERVICES.to_vec()))
                .into_iter()
                .map(|(s, d, f, g)| (format!(r"{s}\Preferences\{d}\{f}"), g))
                .collect(),
            regpol: RegistryPolGot::of(&wsus_pol("http://wsus01.contoso.local:8530")),
        };
        // In AD, no folder in SYSVOL.
        let b = GpoFiles {
            sds: vec![("", Got::Missing)],
            gpp: Vec::new(),
            regpol: RegistryPolGot::Missing,
        };
        let gpos = vec![
            (GPO_A.to_string(), "A-ID".to_string(), true),
            (GPO_B.to_string(), "B-ID".to_string(), true),
            (GPO_C.to_string(), "C-ID".to_string(), true),
        ];
        let early = Early2 {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            // C: its pass ran out of time before it.
            gpos: Some(([(GPO_A.into(), a), (GPO_B.into(), b)].into(), true)),
            scripts: Some((
                [
                    ("logon.bat".to_string(), Got::Bytes(sd.clone())),
                    (r"it\gone.cmd".to_string(), Got::Missing),
                ]
                .into(),
                false,
            )),
        };
        let scripts = (
            vec![
                ("LOGON.BAT".to_string(), vec!["S-1".to_string()]),
                (r"it\gone.cmd".to_string(), vec!["S-2".to_string()]),
            ],
            1,
        );
        let (tx, _rx) = mpsc::channel();
        let mut progress = SysvolProgress::new(tx, 3, 2, true);
        let warned = std::cell::RefCell::new(Vec::new());
        let out = read_as_current_user(
            "contoso.local",
            "dc01.contoso.local",
            &gpos,
            scripts,
            early,
            &mut progress,
            &|m| warned.borrow_mut().push(m),
        );
        let acl = &out.checks.gpo_acl;
        assert_eq!((acl.read, acl.failed, acl.skipped), (2, 1, 1));
        assert_eq!(acl.status, "partial");
        assert_eq!(
            acl.reason.as_deref(),
            Some("the SYSVOL step ran out of time")
        );
        assert_eq!(out.gpos.len(), 1);
        assert_eq!(out.gpos[0].object_id.as_deref(), Some("A-ID"));
        let paths: Vec<&str> = out.gpos[0]
            .folders
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(paths, ["", r"Machine\Scripts"]);
        assert_eq!(out.gpp_passwords.len(), 1);
        assert_eq!(out.checks.gpp.read, 1);
        let scripts = &out.checks.logon_script_acl;
        assert_eq!(
            (scripts.read, scripts.skipped, scripts.status),
            (1, 2, "complete")
        );
        assert_eq!(out.logon_scripts[0].script, "LOGON.BAT");
        assert_eq!(out.logon_scripts[0].users, ["S-1"]);
        // A's Windows Update values (not the rest of its file); C not read
        // in time.
        let pol = out.checks.registry_pol.as_ref().unwrap();
        assert_eq!((pol.read, pol.failed, pol.status), (1, 0, "partial"));
        assert_eq!(out.registry_policy.len(), 1);
        assert_eq!(out.registry_policy[0].object_id.as_deref(), Some("A-ID"));
        assert_eq!(out.registry_policy[0].values.len(), 3);
        assert!(warned
            .borrow()
            .iter()
            .any(|w| w.contains("SYSVOL step stopped after 10 min: 2 of 3 GPOs read")));
    }
}
