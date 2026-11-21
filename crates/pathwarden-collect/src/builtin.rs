//! Built-in collection: Pathwarden opens and binds the LDAP connection, reads
//! the directory, then hands the entries to RustHound-CE (MIT, see
//! THIRD-PARTY-NOTICES.md) for parsing, its SMB/RPC modules and the
//! BloodHound CE JSON.
//!
//! The steps of RustHound-CE's `api::run_collection` are run one by one here
//! rather than through it, so that progress can be reported: the LDAP read
//! (`collect_from_ldap_into` in the library, which is crate-private) is
//! reimplemented below with a per-entry count, and the parse is fed through
//! a counting [`EntrySource`]. While the directory is read, a second handle
//! on the same connection counts what there is to read (attributes `1.1`,
//! cheap for the DC), which gives the percentage and the ETA. This also keeps
//! RustHound-CE's own `indicatif` spinners off the terminal (only the one in
//! its OU post-processing remains; the CLI hides that by pointing stderr
//! elsewhere while it draws its own progress).
//!
//! RustHound-CE's own `ldap_auth` is deliberately not used: it disables TLS
//! certificate validation unconditionally and logs the password at debug
//! level. Binding here keeps validation on, and the log bridge below only
//! forwards `info` and above.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use ldap3::controls::RawControl;
use ldap3::exop::WhoAmI;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope as LdapScope, SearchEntry};
use rusthound_ce::args::{CollectionMethod, Options};
use rusthound_ce::enums::{get_type, Type};
use rusthound_ce::transport::ldap::LdapSearchEntry;
use rusthound_ce::EntrySource;
use zeroize::Zeroize;

use crate::external::{no_sessions_warning, strip_ansi};
use crate::output::{self, Snapshot};
use crate::{
    markers, Auth, Cancelled, CollectRequest, ConnectionCheck, ConnectionError, Count, Outcome,
    Reporter, Scope, Secret, Step,
};

// The attributes the read asks for.
pub(crate) mod attributes;
#[cfg(test)]
mod attributes_tests;
// The read on disk while the directory is read.
mod cache;
#[cfg(test)]
mod cache_tests;
// The Enterprise CAs' registry flags (ESC6, ESC11), read as a domain user.
mod careg;
// RustHound-CE's checker with indexed versions of its quadratic passes.
mod checker;
// Shared zip-rewriting for data added after RustHound-CE writes the zip.
mod fixups;
// SCCM site objects and OUs that block inheritance, noted as the entries
// go to the parser.
mod dirextras;
// Which GPO and setting puts each member in the local groups.
mod gpolocal;
// GPP password scan and the pathwarden-sysvol.json sidecar.
mod gpp;
// What the computer-contacting modules really collected; the SMB sign-in
// domain.
mod hosts;
// Kerberos only with a password: the TGT, its ticket cache, the computers'
// service tickets.
mod krb;
// Kerberos only and required signing around the modules: computers without
// a ticket or whose replies aren't signed are skipped.
mod hostauth;
// Remote Registry over a Kerberos SMB session, without NTLM.
mod krbreg;
// A computer in another realm: following the KDC's referrals.
mod krbref;
// Kerberos only with an account from another domain or forest: the TGT
// from the account's own domain, its controller checked over LDAPS.
mod ownrealm;
#[cfg(test)]
mod ownrealm_tests;
// A KDC relay on 127.0.0.1 for RustHound-CE's modules: their service
// tickets checked, and referrals followed for them.
mod krbrelay;
#[cfg(test)]
mod krbrelay_tests;
// Kerberos only as the current Windows account: a computer's cifs/ ticket
// from SSPI before Windows signs in to it.
#[cfg(windows)]
mod winkrb;
// The patched SMB client's signature checks, against a fake server.
#[cfg(test)]
mod signing_tests;

/// Tests that flip the process-wide signing switch ([`Signing`]) hold this,
/// so they don't see each other's setting.
#[cfg(test)]
pub(crate) static SIGNING_TEST_LOCK: Mutex<()> = Mutex::new(());
/// Tests that set `KRB5CCNAME` hold this.
#[cfg(test)]
pub(crate) static KRB_ENV_LOCK: Mutex<()> = Mutex::new(());
// The SMB/RPC modules, with SYSVOL read here (Groups.xml size check, GPP
// passwords, file permissions).
mod sysvol;
// The accounts services run as, read over Kerberos in a Full collection,
// and the pathwarden-storedcreds.json sidecar.
mod storedcreds;
// The scheduled tasks that store a password, read over C$ into the same
// sidecar.
mod tasks;
// File security descriptors through Windows (current user).
#[cfg(windows)]
mod winsec;
// Sessions and local groups of computers, read as the current user.
#[cfg(windows)]
mod winhosts;
// Windows' NetAPI, Remote Registry and LSA calls for `winhosts`.
#[cfg(windows)]
mod winnet;
// SYSVOL's worker pools.
mod pool;
// Ranged retrieval in a pool of its own.
mod ranged;
#[cfg(test)]
use ranged::range_high;
// The read on several connections at once.
pub(crate) mod streams;
#[cfg(test)]
mod streams_tests;
// Where a collection's time goes (PATHWARDEN_TIMINGS=1 for details).
mod timings;
use timings::Timings;
// Targeted re-collection for retesting one finding (`crate::refresh`).
pub(crate) mod targeted;

/// What the collection thread tells the waiting one.
enum Msg {
    /// A step started.
    Step(&'static str),
    /// Words about the current step ("Connecting to ldaps://...").
    Detail(String),
    Log(String),
    /// A warning for the collection's warnings (and the log): one line
    /// that sums up what the log says per computer.
    Warning(String),
    /// LDAPS failed on the domain controller, so it is read over plain
    /// LDAP: the warning ([`fell_back_warning`]).
    FellBack(String),
    /// Units done in the current step, of `total` when known.
    Units {
        done: u64,
        total: Option<u64>,
    },
    /// What the current step's units are ("items").
    Unit(&'static str),
    /// A step's share of the bar, once its size is known.
    Weight(&'static str, f64),
    /// Entries read so far, by type.
    Counts(BTreeMap<&'static str, u64>),
    /// Entries the read will return in all (from the sizing count).
    ExpectTotal(u64),
    /// Objects of one type expected.
    Expect(&'static str, u64),
    /// Where the time went (sent once, before `Done`, on success).
    Timings(Box<pathwarden_core::diagnostics::CollectionTimings>),
    /// Why the collection stopped before collecting, in plain words (sent
    /// before `Done` with an error): no Kerberos ticket.
    Refused(Box<ConnectionError>),
    /// Who the directory says the sign-in was (`DOMAIN\user`), for the
    /// other domains of a run.
    SignedInAs(String),
    /// The disk can't hold the read (sent before `Done` with an error).
    NoSpace(Box<crate::NoSpace>),
    /// The read stopped and is kept on disk to resume (sent before `Done`
    /// with an error).
    Stopped,
    /// The read resumed one that started then (Unix time).
    Resumed(i64),
    /// The domain controller connected to.
    DcHost(String),
    /// The read goes on from this many entries, read before it resumed:
    /// the rate starts afresh from there.
    ResumedUnits(u64),
    /// The read in parts: streams reading now, and its parts, done.
    Streams {
        streams: u32,
        parts: u64,
        done: u64,
    },
    Done(Result<PathBuf, String>),
}

/// The steps of a built-in collection and their rough share of the time.
pub(crate) fn steps(method: &CollectionMethod) -> Vec<Step> {
    let contacts_computers = matches!(method, CollectionMethod::All);
    let mut steps = vec![
        Step::new("connect", "Connecting and signing in", 2.0),
        Step::new(
            "read",
            "Reading the directory",
            if contacts_computers { 35.0 } else { 62.0 },
        ),
        Step::new(
            "parse",
            "Processing objects",
            if contacts_computers { 10.0 } else { 18.0 },
        ),
        Step::new("resolve", "Resolving memberships and permissions", 6.0),
    ];
    match method {
        // As the current Windows user: SYSVOL through Windows' SMB client.
        CollectionMethod::LdapOnly if cfg!(windows) => steps.push(Step::new(
            "modules",
            "Reading SYSVOL (permissions, GPP passwords)",
            3.0,
        )),
        CollectionMethod::LdapOnly => {}
        CollectionMethod::DCOnly => {
            steps.push(Step::new("modules", "Reading group policy (SYSVOL)", 4.0))
        }
        _ => steps.push(Step::new(
            "modules",
            "Contacting computers (sessions, local groups)",
            40.0,
        )),
    }
    steps.push(Step::new("write", "Writing the output", 6.0));
    steps
}

enum JobAuth {
    CurrentUser,
    Ntlm {
        /// The user name as typed, domain-qualified ([`qualified_user`]):
        /// for messages and the SMB fallback.
        user: String,
        /// What the LDAP NTLM bind is given ([`ntlm_bind_name`]).
        bind: String,
        password: Secret,
    },
}

struct Job {
    domain: String,
    url: String,
    server: Option<String>,
    ldaps: bool,
    skip_verify: bool,
    /// LDAPS first, plain LDAP when LDAPS fails on the domain controller
    /// ([`fall_back`]): `--ldaps` with `--allow-unencrypted-ldap` and a
    /// password.
    plain_fallback: bool,
    /// Why LDAPS failed on the domain controller, in plain words, once the
    /// job switched to plain LDAP ([`to_plain`]).
    ldaps_failed: Option<String>,
    auth: JobAuth,
    method: CollectionMethod,
    out_dir: PathBuf,
    /// NTLM to computers where Kerberos can't be used.
    allow_ntlm: bool,
    /// Computers' unsigned SMB replies accepted.
    allow_unsigned_smb: bool,
    /// Full collection: read the accounts services run as.
    service_reads: bool,
    /// Full collection: read the scheduled tasks over C$.
    task_reads: bool,
    /// What the domains of the run share: the account's Kerberos ticket.
    sign_in: crate::RunSignIn,
    /// Where the read goes on disk; `None`: into memory.
    cache: Option<crate::ReadCache>,
    free_space: cache::FreeSpace,
    /// The sign-in asked for ([`crate::sign_in_key`]), keyed into the
    /// read's key on disk ([`cache::keyed`]): part of the
    /// read's key on disk.
    sign_in_key: String,
    /// What the read asks for ([`attributes::asked`]).
    attributes: &'static [&'static str],
    /// Streams the read uses ([`streams::streams`]).
    streams: usize,
    /// Where the account's own domain's controller comes from, with an
    /// account from another domain.
    own_realm_dc: Arc<dyn ownrealm::OwnRealmDc>,
    /// The domain controllers `--server DOMAIN=HOST` names, for the
    /// account's own domain too.
    servers: Vec<(String, String)>,
}

/// The Kerberos ticket (TGT) of the account's own domain, from its domain
/// controller verified over LDAPS: kept for the other domains of a
/// run, whose computers' tickets are asked of `kdc` and follow the
/// referrals through the trust ([`krbref`]). The cache is deleted when the
/// last copy is dropped.
pub(crate) struct HomeTicket {
    pub cache: krb::TicketCache,
    /// The domain controller that gave it.
    pub kdc: String,
    /// Its realm: the account's domain, upper case.
    pub realm: String,
    /// The account, as the directory named it.
    pub who: String,
}

/// While this lives, every SMB client created requires signed replies
/// (vendor/smb2-client), or none does; afterwards, none (the published
/// behaviour). One built-in collection at a time per process ([`BUSY`]).
pub(crate) struct Signing;

impl Signing {
    pub(crate) fn require(on: bool) -> Self {
        smb2_client::set_require_signing(on);
        Signing
    }
}

impl Drop for Signing {
    fn drop(&mut self) {
        smb2_client::set_require_signing(false);
    }
}

/// The Kerberos ticket cache of a collection that reads computers with
/// Kerberos only, and `KRB5CCNAME` pointing at it. Dropping it
/// restores the variable, then deletes the cache.
#[derive(Default)]
pub(crate) struct HostsGuard {
    _env: Option<krb::CcacheEnv>,
    _home: Option<Arc<HomeTicket>>,
}

/// Kerberos only for the computers a password collection reads:
/// unless NTLM is allowed (or no computer is read), gets a TGT for the
/// account from `dc_fqdn`, the domain controller verified over LDAPS,
/// keeps it in a private ticket cache for RustHound-CE's modules
/// (`--kerberos`, `KRB5CCNAME`) and Pathwarden's own reads (`smb`), and
/// takes the password out of `options`, so no module can fall back to
/// NTLM. `answer` is the directory's "Who am I?" answer. With an account
/// from another domain the TGT comes from the run's first domain, or
/// else from the account's own domain `own_realm` ([`own_realm_for`]), its
/// controller checked over LDAPS first ([`ownrealm::own_realm_ticket`]).
/// No ticket: an error in plain words, and nothing is collected.
async fn kerberos_hosts(
    job: &Job,
    dc_fqdn: &str,
    answer: Option<&str>,
    own_realm: Result<Option<String>, ConnectionError>,
    smb: &mut hosts::SmbIdentity,
    options: &mut Options,
    log: &dyn Fn(String),
) -> Result<HostsGuard, ConnectionError> {
    let JobAuth::Ntlm { user, password, .. } = &job.auth else {
        return Ok(HostsGuard::default());
    };
    if job.allow_ntlm || job.method == CollectionMethod::LdapOnly {
        return Ok(HostsGuard::default());
    }
    if smb.other_domain {
        // A trusted domain of a run whose first domain gave the account's
        // ticket, else the account's own domain's: used
        // through the trust.
        let home = match (job.sign_in.home(), own_realm) {
            (Some(home), _) => home,
            (None, _) if !job.ldaps => return Err(ownrealm::needs_ldaps(&job.domain)),
            (None, Err(e)) => return Err(e),
            (None, Ok(Some(realm))) => {
                own_realm_home(job, &realm, answer, user, password, log).await?
            }
            (None, Ok(None)) => {
                return Err(ownrealm::account_domain_unknown(&smb.domain, &job.domain))
            }
        };
        log(format!(
            "[hosts] Kerberos ticket for {} from {} ({}), used through the trust to {}.",
            home.who,
            home.kdc,
            home.realm.to_ascii_lowercase(),
            job.domain
        ));
        let env = krb::CcacheEnv::set(&home.cache);
        options.kerberos = true;
        if let Some(mut p) = options.password.take() {
            p.zeroize();
        }
        smb.kerberos = Some(hosts::KerberosSignIn {
            ccache: home.cache.name(),
            kdc: home.kdc.clone(),
        });
        return Ok(HostsGuard {
            _env: Some(env),
            _home: Some(home),
        });
    }
    let sam = answer
        .and_then(hosts::parse_who_am_i)
        .map(|(_, sam)| sam)
        .unwrap_or_else(|| rusthound_ce::transport::smb::smb_identity(user, &job.domain).1);
    let who = answer
        .and_then(bound_identity)
        .unwrap_or_else(|| user.clone());
    let tgt = krb::request_tgt(dc_fqdn, &job.domain, &sam, password)
        .await
        .map_err(|f| ConnectionError::no_ticket(f.headline, f.detail))?;
    log(format!(
        "[hosts] Kerberos ticket for {who} from {dc_fqdn} ({}).",
        tgt.summary()
    ));
    let cache = krb::TicketCache::write(&tgt).map_err(|e| {
        ConnectionError::no_ticket(
            "Kerberos didn't work: the ticket couldn't be kept in a private file on this \
             computer.",
            format!("ticket cache in {}: {e}", std::env::temp_dir().display()),
        )
    })?;
    let realm = tgt.realm.to_ascii_uppercase();
    drop(tgt);
    log::debug!("Kerberos ticket cache: {}", cache.path().display());
    // Kept for the other domains of the run.
    let home = job.sign_in.keep(HomeTicket {
        cache,
        kdc: dc_fqdn.to_string(),
        realm,
        who,
    });
    let env = krb::CcacheEnv::set(&home.cache);
    options.kerberos = true;
    if let Some(mut p) = options.password.take() {
        p.zeroize();
    }
    smb.kerberos = Some(hosts::KerberosSignIn {
        ccache: home.cache.name(),
        kdc: home.kdc.clone(),
    });
    Ok(HostsGuard {
        _env: Some(env),
        _home: Some(home),
    })
}

/// The account's TGT from its own domain `realm`, its controller
/// checked over LDAPS first ([`ownrealm::own_realm_ticket`]): the one
/// `--server REALM=HOST` names, else found through DNS. Kept for the run's
/// other domains like a first domain's.
async fn own_realm_home(
    job: &Job,
    realm: &str,
    answer: Option<&str>,
    user: &str,
    password: &Secret,
    log: &dyn Fn(String),
) -> Result<Arc<HomeTicket>, ConnectionError> {
    let sam = answer
        .and_then(hosts::parse_who_am_i)
        .map(|(_, sam)| sam)
        .unwrap_or_else(|| rusthound_ce::transport::smb::smb_identity(user, &job.domain).1);
    let who = answer
        .and_then(bound_identity)
        .unwrap_or_else(|| user.to_string());
    let named = crate::domains::server_for(&job.servers, realm);
    let (tgt, kdc) = ownrealm::own_realm_ticket(
        job.own_realm_dc.as_ref(),
        realm,
        named.as_deref(),
        &job.domain,
        &sam,
        password,
        job.skip_verify,
        log,
    )
    .await?;
    let cache = krb::TicketCache::write(&tgt).map_err(|e| {
        ConnectionError::no_ticket(
            "Kerberos didn't work: the ticket couldn't be kept in a private file on this \
             computer.",
            format!("ticket cache in {}: {e}", std::env::temp_dir().display()),
        )
    })?;
    let realm = tgt.realm.to_ascii_uppercase();
    drop(tgt);
    Ok(job.sign_in.keep(HomeTicket {
        cache,
        kdc,
        realm,
        who,
    }))
}

/// Whether the account's own domain must give the TGT: Kerberos
/// only with a password, computers read, an account from another domain
/// than the one collected (`smb`), and no ticket from the run's first
/// domain.
fn needs_own_realm(job: &Job, smb: &hosts::SmbIdentity) -> bool {
    matches!(job.auth, JobAuth::Ntlm { .. })
        && !job.allow_ntlm
        && job.method != CollectionMethod::LdapOnly
        && smb.other_domain
        && job.sign_in.home().is_none()
}

/// When [`needs_own_realm`]: the account's own domain's DNS name, from the
/// collected domain's directory ([`account_realm`]), or why not (plain
/// LDAP, a domain the directory doesn't name or doesn't trust, or one
/// other than the user name gives). `Ok(None)` when not needed.
async fn own_realm_for(
    job: &Job,
    ldap: &mut ldap3::Ldap,
    smb: &hosts::SmbIdentity,
    configuration: Option<&str>,
    domain_nc: &str,
) -> Result<Option<String>, ConnectionError> {
    if !needs_own_realm(job, smb) {
        return Ok(None);
    }
    if !job.ldaps {
        return Err(ownrealm::needs_ldaps(&job.domain));
    }
    let JobAuth::Ntlm { user, .. } = &job.auth else {
        return Ok(None);
    };
    account_realm(
        ldap,
        &smb.domain,
        user,
        configuration,
        domain_nc,
        &job.domain,
    )
    .await
    .map(Some)
}

/// The DNS name of the account's domain `account` (as the directory names
/// it, usually its NetBIOS name), from the collected domain's directory:
/// its forest's partitions, then the trusts it gives
/// ([`ownrealm::pick_realm`]). A DNS domain in the user name as typed
/// (`user`) must be the one found.
async fn account_realm(
    ldap: &mut ldap3::Ldap,
    account: &str,
    user: &str,
    configuration: Option<&str>,
    domain_nc: &str,
    collected: &str,
) -> Result<String, ConnectionError> {
    let forest = match configuration {
        Some(config) => forest_netbios(ldap, config).await,
        None => Vec::new(),
    };
    let trusts = if ownrealm::realm_of(account, &forest).is_some() {
        Vec::new()
    } else {
        trusted_domains(ldap, domain_nc).await
    };
    ownrealm::pick_realm(
        account,
        ownrealm::typed_dns_domain(user).as_deref(),
        &forest,
        &trusts,
        collected,
    )
}

/// The domains the collected domain (`domain_nc`) has trusts with, from its
/// `trustedDomain` objects ([`trust_entry`]). Empty if the account can't
/// read them.
async fn trusted_domains(ldap: &mut ldap3::Ldap, domain_nc: &str) -> Vec<ownrealm::Trust> {
    let found = ldap
        .with_timeout(IDENTITY_TIMEOUT)
        .with_search_options(ldap3::SearchOptions::new().sizelimit(MAX_PARTITIONS as i32))
        .search(
            &format!("CN=System,{domain_nc}"),
            LdapScope::OneLevel,
            "(&(objectClass=trustedDomain)(flatName=*)(trustPartner=*))",
            vec!["flatName", "trustPartner", "trustDirection"],
        )
        .await
        .ok()
        .and_then(|r| r.success().ok());
    let Some((entries, _)) = found else {
        return Vec::new();
    };
    entries
        .into_iter()
        .take(MAX_PARTITIONS)
        .filter_map(|e| trust_entry(&SearchEntry::construct(e).attrs))
        .collect()
}

/// A `trustedDomain` object's NetBIOS name (`flatName`), DNS name
/// (`trustPartner`) and whether `trustDirection` includes outbound.
fn trust_entry(attrs: &std::collections::HashMap<String, Vec<String>>) -> Option<ownrealm::Trust> {
    let first = |k: &str| {
        attrs
            .get(k)
            .and_then(|v| v.first())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.len() <= 255)
    };
    Some(ownrealm::Trust {
        name: pathwarden_core::storedcreds::NetbiosName {
            dns: first("trustPartner")?,
            netbios: first("flatName")?,
        },
        outbound: first("trustDirection").is_some_and(|d| ownrealm::outbound(&d)),
    })
}

/// Whether a request reads computers with Kerberos only and a password,
/// so a TGT is needed.
fn needs_tgt(req: &CollectRequest) -> bool {
    matches!(req.auth, Auth::Password { .. }) && !req.allow_ntlm
}

/// The collection settings a request maps to, plus warnings for the user.
pub(crate) struct Plan {
    pub method: CollectionMethod,
    pub warnings: Vec<String>,
}

/// Decides what RustHound-CE collects, or refuses unsafe combinations.
pub(crate) fn plan(req: &CollectRequest) -> anyhow::Result<Plan> {
    let mut warnings = Vec::new();
    let has_password = match &req.auth {
        Auth::Password { .. } => true,
        Auth::CurrentUser => {
            if !cfg!(windows) {
                anyhow::bail!(
                    "current-user (Kerberos) authentication in the built-in collector needs \
                     Windows SSPI. On Linux use --user with LDAPS, or an external rusthound-ce \
                     with --kerberos"
                );
            }
            false
        }
        Auth::KerberosCache { .. } => anyhow::bail!(
            "the built-in collector does not read Kerberos ticket caches; on Windows use the \
             current user, elsewhere --user, or an external rusthound-ce with --kerberos"
        ),
    };
    if has_password && !req.ldaps {
        if !req.allow_unencrypted_ldap {
            anyhow::bail!(
                "password authentication needs LDAPS (--ldaps): over plain LDAP the NTLM bind \
                 cannot sign or seal, so the directory travels unencrypted and DCs that require \
                 LDAP signing refuse it. Pass --allow-unencrypted-ldap to accept that"
            );
        }
        warnings.push(
            "This collection used plain LDAP with NTLM, which neither signs nor encrypts, so \
             anyone on the network could read or change it."
                .into(),
        );
    }
    if req.ldaps && req.insecure_skip_tls_verify {
        warnings.push(UNCHECKED_CERTIFICATES.into());
    }
    // Opting out of Kerberos only or required signing. Every
    // built-in collection reads at least SYSVOL over SMB.
    if req.allow_ntlm && has_password {
        warnings.push(
            "NTLM was allowed for computers: a computer without a Kerberos name got an NTLM \
             response from this account, which anyone who can add a name to the domain's DNS \
             can capture or relay."
                .into(),
        );
    }
    if req.allow_unsigned_smb && has_password {
        warnings.push(
            "SMB signing was not required, so a machine in the middle could change what \
             computers answered."
                .into(),
        );
    }
    warnings.extend(unnamed_dc_warning(req.server.as_deref()));
    let method = match (req.scope, has_password) {
        (Scope::All, true) => CollectionMethod::All,
        (Scope::All, false) => anyhow::bail!(
            "sessions and local groups (--scope all) need SMB credentials, which the built-in \
             collector only has with --user. As the current Windows user, run SharpHound \
             (--sharphound) for a full collection"
        ),
        (Scope::DcOnly | Scope::Default, true) => {
            warnings.push(no_sessions_warning());
            CollectionMethod::DCOnly
        }
        (Scope::DcOnly | Scope::Default, false) => {
            warnings.push(no_sessions_warning());
            warnings.push(crate::NO_SYSVOL_NOTE.into());
            CollectionMethod::LdapOnly
        }
    };
    Ok(Plan { method, warnings })
}

/// The run warning with the LDAPS certificate not checked. Dropped when the
/// domain controller was read over plain LDAP instead ([`fall_back`]).
const UNCHECKED_CERTIFICATES: &str =
    "LDAPS certificates were not checked, so a machine in the middle could read or change the \
     collection and capture the sign-in.";

/// A collection's warnings once LDAPS failed on its domain controller and
/// it was read over plain LDAP (`w`): no certificate was used.
fn fell_back_in(warnings: &mut Vec<String>, w: String) {
    warnings.retain(|x| x != UNCHECKED_CERTIFICATES);
    warnings.push(w);
}

/// The run warning when the domain controller wasn't named by its full name:
/// DNS picked it, and the Kerberos name it is checked against
/// comes from its own unauthenticated answer, so a domain controller
/// spoofed through DNS, with a computer account an attacker made in the
/// domain, could hand back a clean directory and close findings. `None`
/// when `server` is a full DNS name.
pub(crate) fn unnamed_dc_warning(server: Option<&str>) -> Option<String> {
    let named = server.map(str::trim).is_some_and(|s| {
        let host = s.trim_start_matches('[').trim_end_matches(']');
        let host = host.strip_suffix('.').unwrap_or(host);
        host.contains('.')
            && host.parse::<std::net::IpAddr>().is_err()
            && host.split('.').all(|label| !label.is_empty())
    });
    (!named).then(|| UNNAMED_DC.to_string())
}

/// [`unnamed_dc_warning`]'s words.
pub(crate) const UNNAMED_DC: &str =
    "The domain controller wasn't named by its full name, so DNS picked it and these results \
     are only as trustworthy as DNS: a spoofed domain controller could return a clean directory \
     and mark findings fixed. Name the domain controller by its full name.";

/// `ldap[s]://host:port` for the request.
pub(crate) fn ldap_url(req: &CollectRequest) -> String {
    url_for(
        req.server.as_deref().unwrap_or(req.domain.trim()),
        req.ldaps,
    )
}

/// `ldap[s]://host:port`.
fn url_for(host: &str, ldaps: bool) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if ldaps {
        format!("ldaps://{host}:636")
    } else {
        format!("ldap://{host}:389")
    }
}

/// Whether a request tries LDAPS first and reads a domain controller whose
/// LDAPS fails over plain LDAP: LDAPS with plain LDAP allowed, signing in
/// with a password. Without `allow_unencrypted_ldap` nothing falls back.
pub(crate) fn falls_back(req: &CollectRequest) -> bool {
    req.ldaps && req.allow_unencrypted_ldap && matches!(req.auth, Auth::Password { .. })
}

/// How long trying LDAPS before falling back to plain LDAP may take.
const LDAPS_TRY: Duration = Duration::from_secs(10);

/// Connects to `url` (LDAPS) and completes the TLS handshake, the
/// certificate checked unless `skip_verify`, then hangs up.
async fn try_ldaps(url: String, skip_verify: bool) -> Result<(), String> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(LDAPS_TRY)
        .set_no_tls_verify(skip_verify);
    match tokio::time::timeout(LDAPS_TRY, LdapConnAsync::with_settings(settings, &url)).await {
        Ok(Ok((conn, ldap))) => {
            drop(ldap);
            drop(conn);
            Ok(())
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "timeout: no answer within {} seconds",
            LDAPS_TRY.as_secs()
        )),
    }
}

/// Why LDAPS failed, in a few plain words, from its error `e`. Words that
/// [`crate::Problem::classify`] reads as their own problem are avoided, so
/// a plain LDAP error that carries them keeps its own reason.
fn ldaps_failure_words(e: &str) -> &'static str {
    use crate::Problem;
    match Problem::classify(e) {
        Problem::CertificateUntrusted => "the certificate isn't trusted",
        Problem::CertificateName => "the certificate doesn't match its name",
        Problem::CertificateExpired => "the certificate has expired or isn't valid yet",
        Problem::Tls => "the encrypted connection couldn't be set up",
        Problem::Refused => "nothing answered on port 636",
        Problem::Timeout => "no answer on port 636 in time",
        Problem::Unreachable => "no network route to it",
        Problem::Dns => "its name wasn't found",
        _ => "the connection didn't work",
    }
}

/// Switches `job` to plain LDAP (port 389) on the same host for every
/// later connection, LDAPS having failed there for `why`.
fn to_plain(job: &mut Job, why: &str) {
    job.ldaps = false;
    job.url = url_for(connected_host(job), false);
    job.ldaps_failed = Some(why.to_string());
}

/// With [`Job::plain_fallback`], after the domain controller was chosen:
/// LDAPS is tried on it (`try_it`, [`try_ldaps`] outside tests), and when
/// that fails for any reason the job switches to plain LDAP
/// ([`to_plain`]). Returns the warning when the job is on plain LDAP
/// because LDAPS failed ([`fell_back_warning`]; `done`: the collection's
/// words, else the check's). `log` gets LDAPS's own error.
async fn fall_back<F, Fut>(
    job: &mut Job,
    try_it: F,
    done: bool,
    log: &dyn Fn(String),
) -> Option<String>
where
    F: FnOnce(String, bool) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    if job.plain_fallback && job.ldaps && job.ldaps_failed.is_none() {
        if let Err(e) = try_it(job.url.clone(), job.skip_verify).await {
            log(format!(
                "[ldaps] {} failed: {}",
                job.url,
                crate::one_line(&without_unsupported_names(&e))
            ));
            to_plain(job, ldaps_failure_words(&e));
            log(format!("[ldaps] plain LDAP from now on: {}", job.url));
        }
    }
    let why = job.ldaps_failed.as_deref()?;
    Some(fell_back_warning(connected_host(job), why, done))
}

/// The warning a domain controller read over plain LDAP after its LDAPS
/// failed (`why`) gives: the collection's (`done`) or the check's.
fn fell_back_warning(host: &str, why: &str, done: bool) -> String {
    if done {
        format!("LDAPS failed on {host} ({why}), so it was read over plain LDAP, unencrypted.")
    } else {
        format!("LDAPS failed on {host} ({why}), so it will be read over plain LDAP, unencrypted.")
    }
}

/// An error of plain LDAP after LDAPS failed: says both.
fn with_ldaps_failure(job: &Job, e: String) -> String {
    match &job.ldaps_failed {
        Some(why) => format!("{e}. LDAPS had failed first: {why}"),
        None => e,
    }
}

/// `user@domain` unless the name already names its domain.
fn qualified_user(user: &str, domain: &str) -> String {
    let user = user.trim();
    if user.contains('\\') || user.contains('@') {
        user.to_string()
    } else {
        format!("{user}@{domain}")
    }
}

/// The user name for ldap3's `sasl_ntlm_bind`, which hands it to sspi's
/// `Username::parse`: the NTLM AUTHENTICATE message then carries
/// - `DOMAIN\user`: user `user`, domain `DOMAIN` (as typed);
/// - `user@suffix`: user `user@suffix`, an empty domain, as Windows sends a
///   UPN. The DC looks the UPN up in the global catalog, so an alternative
///   suffix (`alice@example.com`) or another domain's UPN works against any
///   DC of the forest. `Username::parse` splits at the last `@`, and an
///   account name may contain `@`, so a trailing `@` gives exactly that
///   (sspi's `Username::new_upn(upn, "")`); ldap3 takes only a string;
/// - a bare `user`: user `user`, domain `domain` (the collected domain).
///
/// A UPN with an empty domain resolves inside the forest, or across a forest
/// trust that routes its suffix, but not across an external trust: such an
/// account must be given as `DOMAIN\user` ([`bind_failed`] says so).
///
/// Names sspi can't parse (where ldap3 would panic) are refused here, in
/// plain words.
fn ntlm_bind_name(user: &str, domain: &str) -> Result<String, String> {
    const FORMS: &str = "give it as user, DOMAIN\\user or user@domain";
    let user = user.trim();
    if user.is_empty() {
        return Err("The user name is empty.".into());
    }
    let empty_part = || format!("User name \"{user}\" has an empty part; {FORMS}.");
    match (user.contains('\\'), user.contains('@')) {
        (true, true) => Err(format!(
            "User name \"{user}\" mixes DOMAIN\\user and user@domain; give one of them."
        )),
        (true, false) => {
            let (d, u) = user.split_once('\\').unwrap_or_default();
            if u.contains('\\') {
                Err(format!(
                    "User name \"{user}\" has more than one \\; give it as DOMAIN\\user."
                ))
            } else if d.trim().is_empty() || u.trim().is_empty() {
                Err(empty_part())
            } else {
                Ok(user.to_string())
            }
        }
        (false, true) => {
            let (u, suffix) = user.rsplit_once('@').unwrap_or_default();
            if u.trim().is_empty() || suffix.trim().is_empty() {
                Err(empty_part())
            } else {
                Ok(format!("{user}@"))
            }
        }
        (false, false) => {
            let domain = domain.trim();
            if domain.is_empty() || domain.contains(['\\', '@']) {
                Err(format!(
                    "Domain \"{domain}\" is not a DNS name; give it like contoso.local."
                ))
            } else {
                Ok(format!("{user}@{domain}"))
            }
        }
    }
}

/// The error for a failed NTLM bind as `user` (as typed, qualified), given
/// `bind` ([`ntlm_bind_name`]): the LDAP error `e`, and for a UPN (sent
/// whole, so `bind` ends in `@`) refused as invalid credentials, the way an
/// externally trusted domain's account must be given.
fn bind_failed(user: &str, bind: &str, e: &str) -> String {
    let mut msg = format!("NTLM bind as {user} failed: {e}");
    let upn = bind.ends_with('@');
    let lower = e.to_ascii_lowercase();
    let refused = lower.contains("rc=49") || lower.contains("data 52e");
    if upn && refused {
        msg.push_str(
            ". If the account is from an externally trusted domain, give it as DOMAIN\\user.",
        );
    }
    msg
}

/// The worker's copy of a request (the password copied into a new `Secret`).
/// Refuses a user name the NTLM bind can't use ([`ntlm_bind_name`]).
fn job_for(req: &CollectRequest, method: CollectionMethod) -> Result<Job, String> {
    let auth = match &req.auth {
        Auth::Password { user, password } => JobAuth::Ntlm {
            user: qualified_user(user, req.domain.trim()),
            bind: ntlm_bind_name(user, req.domain.trim())?,
            password: Secret::new(password.expose()),
        },
        _ => JobAuth::CurrentUser,
    };
    Ok(Job {
        domain: req.domain.trim().to_string(),
        url: ldap_url(req),
        server: req.server.clone(),
        ldaps: req.ldaps,
        skip_verify: req.insecure_skip_tls_verify,
        plain_fallback: falls_back(req),
        ldaps_failed: None,
        auth,
        method,
        out_dir: req.output_dir.clone(),
        allow_ntlm: req.allow_ntlm,
        allow_unsigned_smb: req.allow_unsigned_smb,
        service_reads: req.service_reads,
        task_reads: req.task_reads,
        sign_in: crate::RunSignIn::default(),
        cache: req.cache.clone(),
        free_space: cache::free_space,
        sign_in_key: crate::sign_in_key(&req.auth),
        attributes: attributes::asked(req.all_attributes),
        streams: streams::streams(req.read_streams),
        own_realm_dc: Arc::new(ownrealm::System),
        servers: req.servers.clone(),
    })
}

/// Connects, binds and reads the domain's size, without collecting.
/// `sign_in`: the run's other domains.
pub(crate) fn check(
    req: &CollectRequest,
    sign_in: &crate::RunSignIn,
) -> Result<ConnectionCheck, ConnectionError> {
    let Plan { method, .. } = plan(req).map_err(|e| ConnectionError::settings(e.to_string()))?;
    let mut job = job_for(req, method).map_err(ConnectionError::settings)?;
    job.sign_in = sign_in.clone();
    let not_found = locate_dc(&mut job, req, &mut crate::locate::find_dc_here, &mut |_| {});
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ConnectionError::new(format!("cannot start async runtime: {e}")))?;
    let tgt = needs_tgt(req);
    let fell_back = runtime.block_on(fall_back(&mut job, try_ldaps, false, &|_| {}));
    let result = runtime.block_on(async {
        tokio::time::timeout(CHECK_TIMEOUT, check_async(&job, tgt, not_found.as_ref()))
            .await
            .unwrap_or_else(|_| Err(ConnectionError::new("timeout: no answer within a minute")))
    });
    let ldaps = job.ldaps;
    drop(job);
    let mut check = result?;
    check.warnings.extend(fell_back);
    if ldaps && req.insecure_skip_tls_verify {
        check.warnings.push(
            "The certificate is not checked, so another machine on the network could pretend \
             to be the domain controller. Use this for test labs only."
                .into(),
        );
        if tgt {
            check.warnings.push(
                "With the certificate not checked, a machine pretending to be the domain \
                 controller would also get the Kerberos sign-in."
                    .into(),
            );
        }
    }
    Ok(check)
}

const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the check spends counting users and computers.
const COUNT_BUDGET: Duration = Duration::from_secs(8);

/// The check: connect, sign in, count; with `tgt` (Kerberos only with a
/// password), also get the Kerberos ticket the computers will be
/// read with, from the domain controller just verified.
/// `not_found`: no domain controller of a trusted domain was found, so its
/// domain's name is tried; a failure to connect to it says so
/// ([`not_located`]), a failure after the connection doesn't.
async fn check_async(
    job: &Job,
    tgt: bool,
    not_found: Option<&crate::locate::NotFound>,
) -> Result<ConnectionCheck, ConnectionError> {
    let (mut ldap, driver, dc_fqdn, contexts) = open(job, &|_| {}, &|_| {})
        .await
        .map_err(|e| not_located(&job.domain, not_found, false, ConnectionError::new(e)))?;
    let answer = who_am_i_answer(&mut ldap).await;
    let bound_as = answer.as_deref().and_then(bound_identity);
    let base = contexts
        .domain
        .clone()
        .unwrap_or_else(|| domain_dn(&job.domain));
    let mut kerberos = None;
    let mut warnings = Vec::new();
    // A trusted domain of a run: the account's own domain's ticket,
    // through the trust, for this domain controller.
    let through = job
        .sign_in
        .home()
        .filter(|h| tgt && !h.realm.eq_ignore_ascii_case(&job.domain));
    if let Some(home) = through {
        match krb::service_ticket(&home.cache.name(), &dc_fqdn, &home.kdc).await {
            Ok(_) => {
                kerberos = Some(format!(
                    "Got a Kerberos ticket for {dc_fqdn} through the trust from {}.",
                    home.realm.to_ascii_lowercase()
                ))
            }
            Err(why) => warnings.push(through_the_trust(&job.domain, &why)),
        }
    } else if let (true, JobAuth::Ntlm { user, password, .. }) = (tgt, &job.auth) {
        // A ticket is asked only of the account's own domain's controller:
        // another domain's would get a timestamp salted with the password
        // for nothing. An account from another domain gets it from
        // its own domain, whose controller is checked over LDAPS first, and
        // this domain controller's ticket through the trust.
        let reported = answer.as_deref().and_then(hosts::parse_who_am_i);
        let netbios = match (&reported, contexts.configuration.as_deref()) {
            (Some((domain, _)), Some(config)) if !hosts::is_dns_name_of(domain, &job.domain) => {
                domain_netbios(&mut ldap, config, &base).await
            }
            _ => None,
        };
        let account = hosts::smb_account(user, answer.as_deref(), &job.domain, netbios.as_deref());
        if account.identity.other_domain {
            // No computer read (LDAP only): no ticket asked at all.
            if job.method != CollectionMethod::LdapOnly {
                let realm = if job.ldaps {
                    account_realm(
                        &mut ldap,
                        &account.identity.domain,
                        user,
                        contexts.configuration.as_deref(),
                        &base,
                        &job.domain,
                    )
                    .await
                } else {
                    Err(ownrealm::needs_ldaps(&job.domain))
                };
                match check_foreign(job, realm, answer.as_deref(), user, password, &dc_fqdn).await {
                    Ok((line, warning)) => {
                        kerberos = Some(line);
                        warnings.extend(warning);
                    }
                    Err(e) => {
                        close(ldap, driver).await;
                        return Err(e);
                    }
                }
            }
        } else {
            let sam = answer
                .as_deref()
                .and_then(hosts::parse_who_am_i)
                .map(|(_, sam)| sam)
                .unwrap_or_else(|| rusthound_ce::transport::smb::smb_identity(user, &job.domain).1);
            match krb::request_tgt(&dc_fqdn, &job.domain, &sam, password).await {
                Ok(t) => {
                    let who = bound_as.clone().unwrap_or_else(|| user.clone());
                    kerberos = Some(format!("Got a Kerberos ticket for {who} from {dc_fqdn}."));
                    // The other domains of the run check theirs with it.
                    if job.sign_in.shared() {
                        match krb::TicketCache::write(&t) {
                            Ok(cache) => {
                                job.sign_in.keep(HomeTicket {
                                    cache,
                                    kdc: dc_fqdn.clone(),
                                    realm: t.realm.to_ascii_uppercase(),
                                    who,
                                });
                            }
                            // The trusted domains are then skipped, unasked.
                            Err(e) => warnings.push(format!(
                                "The Kerberos ticket couldn't be kept in a private file on this \
                             computer, so the trusted domains will be skipped ({e})."
                            )),
                        }
                    }
                }
                Err(f) => {
                    close(ldap, driver).await;
                    return Err(ConnectionError::no_ticket(f.headline, f.detail));
                }
            }
        }
    }
    let deadline = tokio::time::Instant::now() + COUNT_BUDGET;
    // sAMAccountType: normal user accounts, then computer accounts.
    let users = count(&mut ldap, &base, "(sAMAccountType=805306368)", deadline).await;
    let computers = match users {
        Some(Count {
            at_least: false, ..
        }) => count(&mut ldap, &base, "(sAMAccountType=805306369)", deadline).await,
        _ => None,
    };
    close(ldap, driver).await;
    Ok(ConnectionCheck {
        server: Some(dc_fqdn),
        bound_as,
        naming_context: Some(base),
        users,
        computers,
        kerberos,
        warnings,
        ..ConnectionCheck::default()
    })
}

/// What a trusted domain's check says when its domain controller's ticket
/// can't be had through the trust: its computers will be skipped.
fn through_the_trust(domain: &str, why: &krb::NoTicket) -> String {
    match why {
        krb::NoTicket::Rc4Trust(_) => format!(
            "The trust to {domain} allows only RC4, so its computers will be skipped. Set the \
             trust to use AES."
        ),
        other => format!(
            "Kerberos through the trust to {domain} didn't work, so its computers will be \
             skipped: {}.",
            other.words().trim_end_matches('.')
        ),
    }
}

/// The check with an account from another domain: the TGT from the
/// account's own domain `realm` (or why not), its controller checked over
/// LDAPS first, then `dc_fqdn`'s ticket through the trust. The check's
/// Kerberos line, and a warning when the trust lets no ticket through.
async fn check_foreign(
    job: &Job,
    realm: Result<String, ConnectionError>,
    answer: Option<&str>,
    user: &str,
    password: &Secret,
    dc_fqdn: &str,
) -> Result<(String, Option<String>), ConnectionError> {
    let home = own_realm_home(job, &realm?, answer, user, password, &|_| {}).await?;
    let line = format!(
        "Got a Kerberos ticket for {} from a domain controller of {}.",
        home.who,
        home.realm.to_ascii_lowercase()
    );
    let warning = krb::service_ticket(&home.cache.name(), dc_fqdn, &home.kdc)
        .await
        .err()
        .map(|why| through_the_trust(&job.domain, &why));
    Ok((line, warning))
}

/// `DC=contoso,DC=local` for `contoso.local`.
/// The DC's own domain when its naming context isn't the one entered: a
/// misspelt domain with a working DC name would otherwise collect that DC's
/// domain under the wrong name (and miss SYSVOL, read by the domain name).
fn wrong_domain(domain: &str, naming_context: &str) -> Option<String> {
    let actual = naming_context
        .split(',')
        .filter_map(|rdn| {
            let (k, v) = rdn.trim().split_once('=')?;
            k.eq_ignore_ascii_case("DC").then_some(v)
        })
        .collect::<Vec<_>>()
        .join(".");
    let entered = domain.trim().trim_end_matches('.');
    (!actual.is_empty() && !actual.eq_ignore_ascii_case(entered)).then_some(actual)
}

fn domain_dn(domain: &str) -> String {
    domain
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| format!("DC={l}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A "Who am I?" answer without its `u:`/`dn:` prefix, if not empty.
fn bound_identity(answer: &str) -> Option<String> {
    let v = answer
        .strip_prefix("u:")
        .or_else(|| answer.strip_prefix("dn:"))
        .unwrap_or(answer);
    (!v.is_empty()).then(|| v.to_string())
}

/// The LDAP "Who am I?" answer (RFC 4532) as the server gives it, prefix
/// and all (`u:DOMAIN\user` from Active Directory).
async fn who_am_i_answer(ldap: &mut ldap3::Ldap) -> Option<String> {
    let (exop, _) = ldap
        .with_timeout(IDENTITY_TIMEOUT)
        .extended(WhoAmI)
        .await
        .ok()?
        .success()
        .ok()?;
    Some(String::from_utf8_lossy(&exop.val?).into_owned())
}

/// How long the small identity lookups ("Who am I?", the domain's NetBIOS
/// name) may wait for the DC. Both are optional: without an answer the
/// collector falls back to what was typed.
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(30);

/// The collected domain's NetBIOS name, from its `crossRef` under
/// `CN=Partitions` of the configuration partition (`config_nc`), if the
/// bound account can read it.
async fn domain_netbios(
    ldap: &mut ldap3::Ldap,
    config_nc: &str,
    domain_nc: &str,
) -> Option<String> {
    let filter = format!(
        "(&(objectClass=crossRef)(nCName={}))",
        ldap3::ldap_escape(domain_nc)
    );
    let (entries, _) = ldap
        .with_timeout(IDENTITY_TIMEOUT)
        .search(
            &format!("CN=Partitions,{config_nc}"),
            LdapScope::OneLevel,
            &filter,
            vec!["nETBIOSName"],
        )
        .await
        .ok()?
        .success()
        .ok()?;
    let entry = SearchEntry::construct(entries.into_iter().next()?);
    let name = entry.attrs.get("nETBIOSName")?.first()?.trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// Most domains read from `CN=Partitions` (real forests: a handful).
const MAX_PARTITIONS: usize = 4096;

/// The forest's domains by NetBIOS name: each `crossRef` under
/// `CN=Partitions` of the configuration partition (`config_nc`) that has
/// one, with its `dnsRoot`. Empty if the bound account can't read them;
/// `DOMAIN\user` then resolves by the domain's first label only.
pub(crate) async fn forest_netbios(
    ldap: &mut ldap3::Ldap,
    config_nc: &str,
) -> Vec<pathwarden_core::storedcreds::NetbiosName> {
    let found = ldap
        .with_timeout(IDENTITY_TIMEOUT)
        .with_search_options(ldap3::SearchOptions::new().sizelimit(MAX_PARTITIONS as i32))
        .search(
            &format!("CN=Partitions,{config_nc}"),
            LdapScope::OneLevel,
            "(&(objectClass=crossRef)(nETBIOSName=*)(dnsRoot=*))",
            vec!["nETBIOSName", "dnsRoot"],
        )
        .await
        .ok()
        .and_then(|r| r.success().ok());
    let Some((entries, _)) = found else {
        return Vec::new();
    };
    entries
        .into_iter()
        .take(MAX_PARTITIONS)
        .filter_map(|e| {
            let e = SearchEntry::construct(e);
            let first = |k: &str| {
                e.attrs
                    .get(k)
                    .and_then(|v| v.first())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && s.len() <= 255)
            };
            Some(pathwarden_core::storedcreds::NetbiosName {
                dns: first("dnsRoot")?,
                netbios: first("nETBIOSName")?,
            })
        })
        .collect()
}

/// Counts entries matching `filter`, a page at a time, until `deadline`.
async fn count(
    ldap: &mut ldap3::Ldap,
    base: &str,
    filter: &str,
    deadline: tokio::time::Instant,
) -> Option<Count> {
    use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
    let adapters: Vec<Box<dyn Adapter<'_, &str, Vec<&str>>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(1000)),
    ];
    let mut search = ldap
        .streaming_search_with(adapters, base, LdapScope::Subtree, filter, vec!["1.1"])
        .await
        .ok()?;
    let mut n = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, search.next()).await {
            Ok(Ok(Some(_))) => n += 1,
            Ok(Ok(None)) => break,
            Ok(Err(_)) => return None,
            // Out of time: the connection is closed right after, which
            // ends the search on the server too.
            Err(_) => return Some(Count { n, at_least: true }),
        }
    }
    (search.finish().await.rc == 0).then_some(Count { n, at_least: false })
}

static BUSY: AtomicBool = AtomicBool::new(false);

struct BusyGuard;

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn run(
    req: &CollectRequest,
    sign_in: &crate::RunSignIn,
    rep: &mut Reporter,
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    let Plan {
        method,
        mut warnings,
    } = plan(req)?;
    if BUSY.swap(true, Ordering::SeqCst) {
        anyhow::bail!("a built-in collection is already running in this process");
    }
    let _busy = BusyGuard;

    let mut job = job_for(req, method).map_err(anyhow::Error::msg)?;
    job.sign_in = sign_in.clone();

    let (tx, rx) = mpsc::channel::<Msg>();
    let not_found = pick_dc(
        &mut job,
        req,
        &mut crate::locate::find_dc_here,
        &mut |line| {
            let _ = tx.send(Msg::Log(line));
        },
    );
    if !log_bridge::install() {
        warnings.push(
            "Another logger is installed in this process, so RustHound-CE's messages go there."
                .into(),
        );
    }
    log_bridge::set_sink(Some(tx.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let before = Snapshot::take(&req.output_dir);

    let worker = {
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("pathwarden-collect".into())
            .spawn(move || worker(job, tx, stop))?
    };

    let mut expected_total: Option<u64> = None;
    let mut saved_timings = None;
    let mut refused = None;
    let mut signed_in_as = None;
    let mut no_space = None;
    let mut stopped = false;
    let mut read_started = None;
    let mut dc_host = None;
    let mut plain_ldap = false;
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Msg::Done(r)) => break r,
            Ok(Msg::Warning(w)) => {
                rep.log(format!("warning: {w}"));
                warnings.push(w);
            }
            Ok(Msg::FellBack(w)) => {
                rep.log(format!("warning: {w}"));
                fell_back_in(&mut warnings, w);
                plain_ldap = true;
            }
            Ok(Msg::Timings(t)) => saved_timings = Some(*t),
            Ok(Msg::Refused(e)) => refused = Some(*e),
            Ok(Msg::SignedInAs(who)) => signed_in_as = Some(who),
            Ok(Msg::DcHost(host)) => dc_host = Some(host),
            Ok(Msg::NoSpace(e)) => no_space = Some(*e),
            Ok(Msg::Stopped) => stopped = true,
            Ok(Msg::Resumed(t)) => read_started = Some(t),
            Ok(msg) => apply(rep, msg, &mut expected_total),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err("the collector thread stopped unexpectedly".into())
            }
        }
        rep.tick();
    };
    log_bridge::set_sink(None);
    let _ = worker.join();
    while let Ok(msg) = rx.try_recv() {
        match msg {
            Msg::Log(l) => rep.log(l),
            Msg::Warning(w) => {
                rep.log(format!("warning: {w}"));
                warnings.push(w);
            }
            Msg::FellBack(w) => {
                rep.log(format!("warning: {w}"));
                fell_back_in(&mut warnings, w);
                plain_ldap = true;
            }
            _ => {}
        }
    }

    match result {
        Ok(path) => {
            let mut files = output::discover_outputs(&req.output_dir, &before);
            if files.is_empty() && path.is_file() {
                files.push(path);
            }
            Ok(Outcome {
                files,
                warnings,
                timings: saved_timings,
                signed_in_as,
                read_started,
                plain_ldap,
            })
        }
        Err(e) => {
            output::remove_new_outputs(&req.output_dir, &before);
            // A domain controller answered: its own reason stands.
            let connected = dc_host.is_some();
            if stop.load(Ordering::Relaxed) {
                Err(Cancelled.into())
            } else if let Some(why) = refused {
                Err(not_located(&req.domain, not_found.as_ref(), connected, why).into())
            } else if let Some(why) = no_space {
                Err(why.into())
            } else if stopped {
                // The raw error stays in the log; the message says it plainly.
                rep.log(format!("error: {}", crate::one_line(&e)));
                Err(crate::ReadStopped {
                    domain: req.domain.trim().to_string(),
                    dc: dc_host,
                    reason: crate::one_line(&e),
                }
                .into())
            } else {
                let e = crate::one_line(&e);
                match unlocated(
                    &req.domain,
                    not_found.as_ref(),
                    connected,
                    &ConnectionError::new(e.clone()),
                ) {
                    Some(n) => Err(n.into()),
                    None => Err(anyhow::anyhow!(e)),
                }
            }
        }
    }
}

/// A trusted domain's error after no domain controller of it was found
/// (`not_found`, [`locate_dc`]'s) and its domain's name was used, as that
/// reason ([`crate::locate::not_located`]): only when nothing answered
/// (`connected` false: the connection to the domain's name failed). After
/// a connection, a refused sign-in or a read that stalled keeps its own
/// reason. `None`: as it is.
fn unlocated(
    domain: &str,
    not_found: Option<&crate::locate::NotFound>,
    connected: bool,
    e: &ConnectionError,
) -> Option<ConnectionError> {
    if connected {
        return None;
    }
    not_found.and_then(|none| crate::locate::not_located(domain, none, e.problem, &e.detail))
}

/// [`unlocated`], else the error as it is.
fn not_located(
    domain: &str,
    not_found: Option<&crate::locate::NotFound>,
    connected: bool,
    e: ConnectionError,
) -> ConnectionError {
    unlocated(domain, not_found, connected, &e).unwrap_or(e)
}

/// Applies a message from the collection thread to the progress.
fn apply(rep: &mut Reporter, msg: Msg, expected_total: &mut Option<u64>) {
    match msg {
        Msg::Step(key) => rep.enter(key),
        // An empty detail clears it.
        Msg::Detail(d) => rep.with(|t| t.detail(Some(d).filter(|d| !d.is_empty()))),
        Msg::Log(line) => {
            if let Some(m) = markers::rusthound(&line) {
                rep.marker(m);
            }
            rep.log(line);
        }
        Msg::Units { done, total } => {
            // The sizing count estimates the domain from the object types
            // it can count cheaply: past it, keep the bar just short of full.
            if rep.current() == "read" && expected_total.is_some_and(|n| done > n) {
                *expected_total = Some(done + done / 20 + 1);
            }
            rep.with(|t| t.units(done, total))
        }
        Msg::Counts(counts) => rep.with(|t| {
            for (kind, n) in counts {
                t.count(kind, n);
            }
        }),
        Msg::Unit(u) => rep.with(|t| t.unit(u)),
        Msg::Weight(key, w) => rep.with(|t| {
            t.reweight(key, w);
        }),
        Msg::ExpectTotal(n) => *expected_total = Some(n),
        Msg::ResumedUnits(n) => rep.with(|t| t.resume_units(n)),
        Msg::Streams {
            streams,
            parts,
            done,
        } => rep.with(|t| t.streams(streams, parts, done)),
        Msg::Expect(kind, n) => rep.with(|t| t.expect(kind, n)),
        // Taken by `run`.
        Msg::Done(_)
        | Msg::Warning(_)
        | Msg::FellBack(_)
        | Msg::Timings(_)
        | Msg::Refused(_)
        | Msg::SignedInAs(_)
        | Msg::NoSpace(_)
        | Msg::Stopped
        | Msg::DcHost(_)
        | Msg::Resumed(_) => {}
    }
    if let (Some(n), "read") = (*expected_total, rep.current()) {
        rep.with(|t| t.expect_units(n));
    }
}

/// [`crate::sweep_stopped_reads`].
pub(crate) fn sweep_reads(root: &std::path::Path) -> usize {
    if root.is_dir() {
        cache::sweep(root)
    } else {
        0
    }
}

/// [`crate::stopped_read`].
pub(crate) fn stopped_read(
    root: &std::path::Path,
    domain: &str,
    auth: &Auth,
) -> Option<crate::StoppedRead> {
    let cp = cache::stopped(root, domain, &crate::sign_in_key(auth), cache::now())?;
    let started = cp.started_at()?;
    Some(crate::StoppedRead {
        domain: domain.trim().trim_end_matches('.').to_string(),
        percent: cp.percent(),
        started,
        stopped: pathwarden_core::time::parse_rfc3339(&cp.updated).unwrap_or(started),
    })
}

/// [`crate::fake_stopped_read`].
pub(crate) fn fake_stopped_read(
    root: &std::path::Path,
    domain: &str,
    auth: &Auth,
    percent: u8,
    started: i64,
) -> std::io::Result<()> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let k = cache::root_key(root, true)?.unwrap_or_default();
    let key = cache::Key {
        domain: domain.clone(),
        dc_host: format!("dc01.{domain}"),
        ds_service_name: "CN=NTDS Settings,CN=DC01".into(),
        invocation_id: "00112233445566778899aabbccddeeff".into(),
        account: cache::keyed(&k, "test\\account"),
        sign_in: cache::keyed(&k, &crate::sign_in_key(auth)),
        filter: "(objectClass=*)".into(),
        attributes: cache::attributes_hash(attributes::PARSED),
    };
    let nc = domain_dn(&domain);
    let mut cp = cache::Checkpoint::new(
        key,
        &nc,
        6400,
        cache::plan(std::slice::from_ref(&nc), &nc, Some(6400)),
    );
    cp.expected = Some(100_000);
    let mut left = u64::from(percent) * 1000;
    for c in cp.chunks.iter_mut() {
        if left == 0 {
            break;
        }
        c.state = cache::State::Done;
        c.entries = left.min(2_000);
        left -= c.entries;
    }
    cp.retotal();
    let at = pathwarden_core::time::format_rfc3339(started);
    cp.started = at.clone();
    cp.updated = at;
    let dir = cache::domain_dir(root, &domain);
    std::fs::create_dir_all(&dir)?;
    cp.save(&dir)
}

/// Resuming with no domain controller named: the one the read started on,
/// as uSNs are that controller's own (another one makes the read start
/// over). Returns its name when it is used.
fn pin_resumed_dc(job: &mut Job) -> Option<String> {
    let c = job.cache.as_ref().filter(|c| c.resume)?;
    if job.server.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return None;
    }
    let cp = cache::stopped(&c.root, &job.domain, &job.sign_in_key, cache::now())?;
    let host = cp.key.dc_host.trim().to_string();
    if host.is_empty() {
        return None;
    }
    job.url = url_for(&host, job.ldaps);
    job.server = Some(host.clone());
    Some(host)
}

/// Finds a domain controller of a domain to connect to on a port
/// ([`crate::locate::find_dc_here`]; a fake in tests).
type FindDc<'a> =
    dyn FnMut(&str, u16, &mut dyn FnMut(String)) -> Result<String, crate::locate::NotFound> + 'a;

/// A trusted domain of a run with no domain controller named: one
/// found by its full name in the domain ([`crate::locate`]), so the LDAPS
/// certificate is checked against the name it was issued to. None found:
/// the domain's name, as before, and `Some` with what each way said, for
/// the reason if that fails too ([`not_located`]). `log` gets what was
/// tried. A named one (`--server DOMAIN=HOST`) is left as it is: the
/// certificate must match that name.
fn locate_dc(
    job: &mut Job,
    req: &CollectRequest,
    find: &mut FindDc,
    log: &mut dyn FnMut(String),
) -> Option<crate::locate::NotFound> {
    if !req.locate_dc || job.server.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return None;
    }
    let port = if job.ldaps { 636 } else { 389 };
    match find(&job.domain, port, log) {
        Ok(host) => {
            job.url = url_for(&host, job.ldaps);
            job.server = Some(host);
            None
        }
        // LDAPS first with plain LDAP allowed: one that answers on 389,
        // read over plain LDAP ([`fall_back`] says so).
        Err(none) if job.ldaps && job.plain_fallback => match find(&job.domain, 389, log) {
            Ok(host) => {
                job.server = Some(host);
                to_plain(job, "nothing answered on port 636");
                None
            }
            Err(_) => Some(none),
        },
        Err(none) => Some(none),
    }
}

/// The domain controller a collection connects to: a resumed read's own
/// first ([`pin_resumed_dc`]: its uSNs are that controller's), else one
/// found for a trusted domain ([`locate_dc`], whose answer this is).
fn pick_dc(
    job: &mut Job,
    req: &CollectRequest,
    find: &mut FindDc,
    log: &mut dyn FnMut(String),
) -> Option<crate::locate::NotFound> {
    if let Some(host) = pin_resumed_dc(job) {
        log(format!(
            "[cache] resuming on {host}, the domain controller the read started on"
        ));
    }
    locate_dc(job, req, find, log)
}

fn worker(mut job: Job, tx: mpsc::Sender<Msg>, stop: Arc<AtomicBool>) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("pathwarden-collect-rt")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = tx.send(Msg::Done(Err(format!("cannot start async runtime: {e}"))));
            return;
        }
    };
    // A panic in the library must still end the collection with an error:
    // `collect` waits for `Done`.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let log = |l: String| {
                let _ = tx.send(Msg::Log(l));
            };
            if let Some(w) = fall_back(&mut job, try_ldaps, true, &log).await {
                let _ = tx.send(Msg::FellBack(w));
            }
            let mut work = std::pin::pin!(collect_async(&job, &tx));
            loop {
                match tokio::time::timeout(Duration::from_millis(100), work.as_mut()).await {
                    Ok(r) => break r,
                    Err(_) if stop.load(Ordering::Relaxed) => break Err("cancelled".to_string()),
                    Err(_) => {}
                }
            }
        })
    }))
    .unwrap_or_else(|panic| {
        let what = panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        Err(format!("the collector crashed: {what}"))
    });
    // Stops module tasks still running after a cancel.
    runtime.shutdown_timeout(Duration::from_secs(2));
    drop(job);
    let _ = tx.send(Msg::Done(result));
}

async fn collect_async(job: &Job, tx: &mpsc::Sender<Msg>) -> Result<PathBuf, String> {
    let detail = |p: String| {
        let _ = tx.send(Msg::Detail(p));
    };
    let log = |l: String| {
        let _ = tx.send(Msg::Log(l));
    };

    let started = Instant::now();
    if let Some(line) = crate::memory::line("start") {
        log(line);
    }
    let (mut ldap, driver, dc_fqdn, contexts) = open(job, &detail, &log).await?;
    let answer = who_am_i_answer(&mut ldap).await;
    let _ = tx.send(Msg::DcHost(dc_fqdn.clone()));
    if let Some(who) = answer.as_deref().and_then(bound_identity) {
        log(format!("Authenticated as {who}"));
        let _ = tx.send(Msg::SignedInAs(who));
    }
    let mut timings = Timings {
        connect: started.elapsed(),
        ..Timings::default()
    };
    let domain_nc = contexts.domain.unwrap_or_else(|| domain_dn(&job.domain));

    let mut options = base_options(
        &job.domain,
        &job.out_dir,
        job.method.clone(),
        dc_fqdn.clone(),
        job.ldaps,
    );
    let mut smb = smb_signin(
        job,
        &mut ldap,
        answer.as_deref(),
        contexts.configuration.as_deref(),
        &domain_nc,
        &log,
        &mut options,
    )
    .await;
    // Required SMB signing and Kerberos only for the computers.
    let signing = Signing::require(!job.allow_unsigned_smb);
    let own_realm = own_realm_for(
        job,
        &mut ldap,
        &smb,
        contexts.configuration.as_deref(),
        &domain_nc,
    )
    .await;
    let hosts_guard = match kerberos_hosts(
        job,
        &dc_fqdn,
        answer.as_deref(),
        own_realm,
        &mut smb,
        &mut options,
        &log,
    )
    .await
    {
        Ok(g) => g,
        Err(why) => {
            if let Some(mut p) = options.password.take() {
                p.zeroize();
            }
            close(ldap, driver).await;
            let message = why.message();
            let _ = tx.send(Msg::Refused(Box::new(why)));
            return Err(message);
        }
    };
    let read = ReadPlan {
        cache: job.cache.as_ref(),
        domain: &job.domain,
        free_space: job.free_space,
        dc_host: &dc_fqdn,
        account: answer
            .as_deref()
            .and_then(bound_identity)
            .unwrap_or_default()
            .to_ascii_lowercase(),
        sign_in: job.sign_in_key.clone(),
        attributes: job.attributes,
        streams: job.streams,
        connector: Some(Arc::new(Connector::of(job, &dc_fqdn))),
    };
    let result = run_collection(
        &mut ldap,
        &options,
        &smb,
        &domain_nc,
        tx,
        &mut timings,
        !job.allow_ntlm,
        &read,
        sysvol::Reads {
            services: job.service_reads,
            tasks: job.task_reads,
        },
    )
    .await;
    if let Some(mut p) = options.password.take() {
        p.zeroize();
    }
    drop(hosts_guard);
    drop(signing);
    close(ldap, driver).await;
    if result.is_ok() {
        log(timings.summary());
        if timings::detailed() {
            for line in timings.details() {
                log(line);
            }
        }
        let saved = timings.to_saved(started.elapsed());
        let _ = tx.send(Msg::Timings(Box::new(saved)));
    }
    result
}

/// The account the SMB modules sign in as, set in `options` (user name and
/// password), and the domain they sign in to. Sessions, local groups and
/// SYSVOL go over SMB and need the password; Kerberos (the current user)
/// has no password and no SMB user name. `answer` is the directory's "Who
/// am I?" answer after the bind; `configuration` the configuration naming
/// context.
async fn smb_signin(
    job: &Job,
    ldap: &mut ldap3::Ldap,
    answer: Option<&str>,
    configuration: Option<&str>,
    domain_nc: &str,
    log: &dyn Fn(String),
    options: &mut Options,
) -> hosts::SmbIdentity {
    let (account, password) = match &job.auth {
        // Sessions, local groups and SYSVOL go over SMB and need the password.
        // Kerberos (the current user) has no password and no SMB user name.
        JobAuth::Ntlm { user, password, .. } if job.method != CollectionMethod::LdapOnly => {
            // A UPN suffix is not always a domain: sign in over SMB as the
            // account the directory reports (see `hosts::smb_account`).
            // The collected domain's NetBIOS name tells whether that account
            // is from it; not needed when the answer names its DNS name.
            let reported = answer.and_then(hosts::parse_who_am_i);
            let netbios = match (reported, configuration) {
                (Some((domain, _)), Some(config))
                    if !hosts::is_dns_name_of(&domain, &job.domain) =>
                {
                    domain_netbios(ldap, config, domain_nc).await
                }
                (Some((domain, _)), None) if !hosts::is_dns_name_of(&domain, &job.domain) => {
                    log::debug!(
                        "no configurationNamingContext in the RootDSE: guessing from the \
                         first label of {} whether {domain} is the collected domain",
                        job.domain
                    );
                    None
                }
                _ => None,
            };
            let account = hosts::smb_account(user, answer, &job.domain, netbios.as_deref());
            log(match &account.source {
                hosts::SmbUserSource::Directory { reported } => format!(
                    "SMB sign-ins as {} (the directory reports {reported})",
                    account.user
                ),
                hosts::SmbUserSource::Typed => format!(
                    "SMB sign-ins as {user}, as typed: the directory did not name the account \
                     as DOMAIN\\user"
                ),
            });
            (Some(account), Some(password.expose().to_string()))
        }
        _ => (None, None),
    };
    options.username = account.as_ref().map(|a| a.user.clone());
    options.password = password;
    match account {
        Some(a) => a.identity,
        None => hosts::SmbIdentity::of(options),
    }
}

/// Whether a naming context is one of AD's DNS application partitions
/// (`DC=DomainDnsZones,...`, `DC=ForestDnsZones,...`). They hold DNS zones
/// and records, which RustHound-CE's parser discards, and two
/// `CN=MicrosoftDNS` containers.
fn is_dns_partition(nc: &str) -> bool {
    let first = nc.split(',').next().unwrap_or("").trim();
    first.eq_ignore_ascii_case("DC=DomainDnsZones")
        || first.eq_ignore_ascii_case("DC=ForestDnsZones")
}

/// What a naming context is, for the timings (not its name).
fn nc_kind(nc: &str, domain_nc: &str) -> &'static str {
    let lower = nc.to_ascii_lowercase();
    if lower.starts_with("cn=schema,") {
        "schema"
    } else if lower.starts_with("cn=configuration,") {
        "configuration"
    } else if nc.eq_ignore_ascii_case(domain_nc) {
        "domain"
    } else if is_dns_partition(nc) {
        "DNS partition"
    } else {
        "other partition"
    }
}

/// Where a read goes.
struct ReadPlan<'a> {
    /// On disk, in a folder for the domain in this one; `None`: into memory.
    cache: Option<&'a crate::ReadCache>,
    domain: &'a str,
    free_space: cache::FreeSpace,
    /// The domain controller read.
    dc_host: &'a str,
    /// The account the directory names, and the sign-in asked for, as
    /// given: keyed into [`cache::Key`] by [`prepare_cache`].
    account: String,
    sign_in: String,
    /// What the read asks for ([`attributes::asked`]): part of its key.
    attributes: &'static [&'static str],
    /// Streams to read with ([`streams::streams`]).
    streams: usize,
    /// More connections to the same domain controller: the streams, the
    /// ranged pool, the sizing count. `None`: the first connection only.
    connector: Option<Arc<Connector>>,
}

/// What the domain controller's RootDSE says of its database, for reading
/// in uSN windows and resuming.
#[derive(Debug, Clone, Default)]
struct DcSnapshot {
    /// `highestCommittedUSN`.
    highest_usn: Option<u64>,
    /// `dsServiceName`.
    ds_service_name: String,
    /// That object's `invocationId`, in hex.
    invocation_id: String,
}

/// One attribute of the object at `base` (the RootDSE when empty).
async fn read_one(ldap: &ldap3::Ldap, base: &str, attr: &str) -> Option<SearchEntry> {
    let mut ldap = ldap.clone();
    let search = async {
        ldap.search(base, LdapScope::Base, "(objectClass=*)", vec![attr])
            .await?
            .success()
    };
    let (entries, _) = or_stalled(STALL_TIMEOUT, "reading the domain controller's uSN", search)
        .await
        .ok()?;
    Some(SearchEntry::construct(entries.into_iter().next()?))
}

/// [`DcSnapshot`] from the RootDSE and the DC's NTDS Settings object. What
/// can't be read stays empty: then the domain is read whole and the read
/// can't be resumed.
async fn dc_snapshot(ldap: &ldap3::Ldap) -> DcSnapshot {
    let mut snap = DcSnapshot::default();
    let Some(root) = read_one(ldap, "", "highestCommittedUSN").await else {
        return snap;
    };
    snap.highest_usn = root
        .attrs
        .get("highestCommittedUSN")
        .and_then(|v| v.first())
        .and_then(|v| v.trim().parse().ok());
    let ds = read_one(ldap, "", "dsServiceName")
        .await
        .and_then(|e| e.attrs.get("dsServiceName")?.first().cloned());
    if let Some(ds) = ds {
        if let Some(e) = read_one(ldap, &ds, "invocationId").await {
            let raw = e
                .bin_attrs
                .get("invocationId")
                .and_then(|v| v.first().cloned())
                .or_else(|| {
                    e.attrs
                        .get("invocationId")
                        .and_then(|v| v.first())
                        .map(|s| s.as_bytes().to_vec())
                });
            snap.invocation_id = raw
                .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
                .unwrap_or_default();
        }
        snap.ds_service_name = ds;
    }
    snap
}

/// `timings.note_memory`, and the `[memory]` line for the log.
fn note_memory(tx: &mpsc::Sender<Msg>, timings: &mut Timings, phase: &'static str) {
    timings.note_memory(phase);
    log_memory(tx, phase);
}

fn log_memory(tx: &mpsc::Sender<Msg>, phase: &str) {
    if let Some(line) = crate::memory::line(phase) {
        let _ = tx.send(Msg::Log(line));
    }
}

/// Refuses (with [`Msg::NoSpace`]) when `dir`'s volume can't hold `need`.
fn check_space(
    dir: &std::path::Path,
    need: u64,
    free: cache::FreeSpace,
    tx: &mpsc::Sender<Msg>,
) -> Result<(), String> {
    cache::check_space(dir, need, free).map_err(|e| {
        let message = e.to_string();
        let _ = tx.send(Msg::NoSpace(Box::new(e)));
        message
    })
}

/// RustHound-CE's `api::run_collection`, step by step, with progress:
/// read every naming context (counting it alongside), parse, run the
/// modules the collection method calls for, write the zip. `smb` is the
/// domain the SMB modules sign in to.
#[allow(clippy::too_many_arguments)]
async fn run_collection(
    ldap: &mut ldap3::Ldap,
    options: &Options,
    smb: &hosts::SmbIdentity,
    domain_nc: &str,
    tx: &mpsc::Sender<Msg>,
    timings: &mut Timings,
    kerberos_only: bool,
    plan: &ReadPlan<'_>,
    reads: sysvol::Reads,
) -> Result<PathBuf, String> {
    let send = |m: Msg| {
        let _ = tx.send(m);
    };
    send(Msg::Step("read"));
    let read_started = Instant::now();
    let all_contexts = or_stalled(
        STALL_TIMEOUT,
        "listing the naming contexts",
        rusthound_ce::transport::ldap::get_all_naming_contexts(ldap),
    )
    .await?;
    if !all_contexts.iter().any(|s| s.contains("Configuration")) {
        return Err(
            "no Configuration naming context found (is the server a domain controller?)".into(),
        );
    }
    let config_nc = all_contexts
        .iter()
        .find(|c| c.to_ascii_lowercase().starts_with("cn=configuration,"))
        .cloned();
    // The DNS partitions are records the parser throws away: not read.
    let (dns, contexts): (Vec<String>, Vec<String>) = all_contexts
        .into_iter()
        .partition(|nc| is_dns_partition(nc));
    timings.skipped_ncs = dns.len();
    if !dns.is_empty() {
        send(Msg::Log(format!(
            "Not reading the DNS partitions ({}): RustHound-CE does not use DNS records",
            dns.join("; ")
        )));
    }
    send(Msg::Log(if plan.attributes == attributes::ALL {
        "[read] asking for every attribute (all attributes is on)".to_string()
    } else {
        format!(
            "[read] asking for the {} attributes RustHound-CE reads",
            plan.attributes.len()
        )
    }));

    // On disk: our folder (removed once parsed; kept when the read stops,
    // to resume), the plan of its chunks, and the free space for what the
    // last read of the domain took.
    let snapshot = match plan.cache {
        Some(_) => dc_snapshot(ldap).await,
        None => DcSnapshot::default(),
    };
    let mut disk = prepare_cache(
        plan,
        &contexts,
        domain_nc,
        &options.ldap_filter,
        &snapshot,
        tx,
    )?;
    let chunks = match &disk {
        Some(d) => d.chunks.clone(),
        None => cache::whole_plan(&contexts),
    };
    let (sink, stats) = match &disk {
        Some(d) => {
            let writer = cache::Writer::for_streams(&d.folder, plan.streams)?;
            let stats = writer.stats();
            (Sink::Disk(writer), Some(stats))
        }
        None => (Sink::memory(), None),
    };

    // Streams for this read: one into memory or with no windows.
    let parallel = disk.is_some()
        && chunks
            .iter()
            .any(|c| c.kind == cache::Kind::Window && !c.is_done());
    let n = if parallel {
        streams::streams(Some(plan.streams))
    } else {
        1
    };
    // The other connections go to the domain controller the read started
    // on: its NTDS Settings object, as the snapshot named it.
    if let Some(c) = &plan.connector {
        let host = read_one(ldap, "", "dnsHostName")
            .await
            .and_then(|e| e.attrs.get("dnsHostName")?.first().cloned());
        c.pin(&snapshot.ds_service_name, host.as_deref());
    }

    // How large the read is: what a recent read of the domain had, else a
    // count while the read runs (on a connection of its own when reading
    // with several). The count stops (is dropped) as soon as the read ends.
    let previous = plan.cache.and_then(|c| {
        let recent = c
            .last_when
            // A run dated ahead of this clock is no guide either.
            .is_some_and(|t| (0..LAST_SIZE_DAYS * 86_400).contains(&(cache::now() - t)));
        match c.last_entries {
            Some(n) if recent && !c.last_counts.is_empty() => Some((n, &c.last_counts)),
            _ => None,
        }
    });
    if let Some((n, kinds)) = previous {
        send(Msg::Log(format!(
            "[read] about {} entries, as the last read of the domain had: not counted again",
            crate::progress::thousands(n)
        )));
        for (kind, k) in kinds {
            let kind = static_kind(kind);
            if matches!(kind, "users" | "computers" | "groups") {
                send(Msg::Expect(kind, *k));
            }
        }
        send(Msg::ExpectTotal(n));
    }
    let counter = match (&previous, &plan.connector) {
        (None, Some(c)) if n > 1 => c.connect().await.ok(),
        _ => None,
    };
    // SYSVOL alongside the read: its files are read while the
    // directory is; what they mean is worked out after the parse.
    let early = sysvol::Early::start(options, smb, ldap, domain_nc, tx, kerberos_only, n).await;
    let mut sized: Option<Duration> = None;
    // One stream: ranged retrieval inline, as before, so the load is
    // today's single connection's.
    let streams = LdapStreams::new(ldap.clone(), plan.connector.clone(), plan.attributes, n, tx);
    let read: Result<streams::Read, String> = {
        let count_on = counter
            .as_ref()
            .map_or_else(|| ldap.clone(), |(l, _)| l.clone());
        let sizing = size_directory(count_on, contexts.clone(), domain_nc.to_string(), tx);
        let read_plan = streams::Plan {
            filter: &options.ldap_filter,
            chunks: &chunks,
            domain_nc,
            tx,
            streams: n,
            refused_wait: streams::REFUSED_WAIT,
        };
        let fetch = streams::read(&streams, &read_plan, timings, sink);
        tokio::pin!(sizing);
        tokio::pin!(fetch);
        let mut counting = previous.is_none();
        loop {
            tokio::select! {
                r = &mut fetch => break r,
                (d, total) = &mut sizing, if counting => {
                    counting = false;
                    sized = Some(d);
                    if let (Some(d), Some(total), Some(s)) = (disk.as_mut(), total, &stats) {
                        // For the checkpoint, unless an earlier read said.
                        let _ = s.expected.compare_exchange(0, total, Ordering::Relaxed, Ordering::Relaxed);
                        let written = s.written.load(Ordering::Relaxed);
                        if let Err(e) = recheck_space(d, total, written, plan.free_space, tx) {
                            break Err(e);
                        }
                    }
                }
            }
        }
    };
    streams.close().await;
    if let Some((l, driver)) = counter {
        close(l, driver).await;
    }
    // No more connections: the password's copy goes now.
    if let Some(c) = &plan.connector {
        c.forget();
    }
    let read = match read {
        Ok(r) => r,
        Err(e) => {
            let e = disk_full(disk.as_ref(), stats.as_deref(), e, plan.free_space, tx);
            // Kept on disk: it can be resumed.
            if disk.as_ref().is_some_and(|d| d.folder.resumable()) {
                send(Msg::Stopped);
            }
            return Err(e);
        }
    };
    let streams::Read { out: read, scripts } = read;
    // The logon scripts the entries named, read while the parse runs.
    let early = early.scripts(scripts);
    // Read completely: removed once parsed, or if the parse fails.
    if let Some(d) = disk.as_mut() {
        d.folder.remove_on_drop();
    }
    timings.sizing = sized.map(|d| (d, true));
    timings.sized_from_last = previous.is_some();
    timings.read = read_started.elapsed();
    note_memory(tx, timings, "read");

    if let ReadOut::Disk(w) = &read {
        timings.cache = Some((w.entries, w.bytes));
        if let Some(t) = w.resumed_from {
            send(Msg::Resumed(t));
        }
    }
    let parse_started = Instant::now();
    send(Msg::Step("parse"));
    let (mut results, extras) = parse(options, read, tx)?;
    // Parsed: the read on disk is no longer needed, and the zip gets its room.
    drop(disk);
    timings.parse = parse_started.elapsed();
    note_memory(tx, timings, "parse");
    // RustHound-CE's checker, with indexed versions of its quadratic passes.
    send(Msg::Step("resolve"));
    let resolve_started = Instant::now();
    checker::check_all(options, &mut results)
        .map_err(|e| format!("collection failed while resolving memberships: {e}"))?;
    timings.resolve = resolve_started.elapsed();
    note_memory(tx, timings, "resolve");
    send(Msg::Log(shape(&results)));

    // Only a full collection contacts computers; otherwise record why the
    // sessions aren't collected, with a reason (see `hosts`).
    if options.collection_method != CollectionMethod::All {
        hosts::mark_sessions_not_collected(&mut results.computers, hosts::NOT_CONTACTED);
    }
    let mut sidecar = None;
    let mut stored = None;
    if let Some(w) = modules_weight(&options.collection_method, &results, timings.read, reads) {
        send(Msg::Weight("modules", w));
    }
    if options.collection_method != CollectionMethod::LdapOnly {
        send(Msg::Step("modules"));
        let started = Instant::now();
        // The forest's NetBIOS names, for the accounts services run as.
        let netbios = match &config_nc {
            Some(config) if options.collection_method == CollectionMethod::All => {
                forest_netbios(ldap, config).await
            }
            _ => Vec::new(),
        };
        let services = sysvol::Services { netbios, reads };
        let out =
            sysvol::run_modules(options, smb, &mut results, tx, timings, services, early).await?;
        sidecar = out.sysvol;
        stored = out.stored;
        timings.modules = Some(started.elapsed());
        note_memory(tx, timings, "modules");
    } else if cfg!(windows) {
        // LdapOnly is the current Windows user: read SYSVOL as that user.
        send(Msg::Step("modules"));
        let started = Instant::now();
        #[cfg(windows)]
        {
            sidecar = Some(sysvol::current_user(options, &results, tx, kerberos_only, early).await);
        }
        #[cfg(not(windows))]
        drop(early);
        timings.modules = Some(started.elapsed());
        timings.sysvol = timings.modules;
    }
    // Only the current Windows user's SYSVOL read needs it here.
    #[cfg(not(windows))]
    let _ = kerberos_only;
    // The CAs' registry flags: a full collection already contacts computers.
    let ca_flags = if options.collection_method == CollectionMethod::All {
        careg::read(options, smb, &results.enterprisecas, tx).await
    } else {
        Vec::new()
    };
    // SCCM's site objects, disabled GPO links and computers made through
    // the machine account quota go with the SYSVOL results.
    if let Some(s) = sidecar.as_mut() {
        s.disabled_gp_links = Some(extras.disabled_links.clone());
        s.machine_quota_computers = Some(extras.quota_computers.clone());
        let n = extras.sccm.sites.len() + extras.sccm.management_points.len();
        s.checks.sccm_sites = Some(gpp::CheckOut {
            status: "complete",
            read: n,
            ..gpp::CheckOut::default()
        });
        if n > 0 {
            send(Msg::Log(format!(
                "[sccm] {} and {} in the directory",
                pathwarden_core::text::count(extras.sccm.sites.len(), "SCCM site", "SCCM sites"),
                pathwarden_core::text::count(
                    extras.sccm.management_points.len(),
                    "management point",
                    "management points"
                )
            )));
            s.sccm = Some(extras.sccm.clone());
        }
    }
    send(Msg::Step("write"));
    let write_started = Instant::now();
    let written = rusthound_ce::make_result(options, results)
        .map(PathBuf::from)
        .map_err(|e| format!("cannot write the collection: {e}"));
    // RustHound-CE never sets blocksinheritance (it matches gPOptions
    // misspelt): set it on the OUs that block inheritance.
    if let Ok(zip) = &written {
        if let Err(e) = dirextras::apply_to_zip(zip, &extras.blocked_ous) {
            send(Msg::Log(format!(
                "warning: [gpo] could not mark the OUs that block inheritance in the zip: {e}"
            )));
        }
    }
    if let Ok(zip) = &written {
        if let Err(e) = careg::apply_to_zip(zip, &ca_flags) {
            send(Msg::Log(format!(
                "warning: [adcs] could not add the CAs' registry flags (ESC6) to the zip: {e}"
            )));
        }
    }
    // The SYSVOL results go into the same zip. Failing to add them leaves a
    // collection without SYSVOL data, which analysis treats as "can't tell".
    if let (Ok(zip), Some(s)) = (&written, &sidecar) {
        if let Err(e) = s.append_to(zip) {
            send(Msg::Log(format!(
                "warning: [sysvol] could not add the SYSVOL results to the zip: {e}"
            )));
        }
    }
    // Likewise the services' accounts and the tasks': without them, "can't
    // tell".
    if let (Ok(zip), Some(s)) = (&written, &stored) {
        if let Err(e) = storedcreds::append_to(s, zip) {
            send(Msg::Log(format!(
                "warning: [services] could not add the stored credentials (services, \
                 scheduled tasks) to the zip: {e}"
            )));
        }
    }
    timings.write = write_started.elapsed();
    // `make_result` took the results: this is after they are freed.
    note_memory(tx, timings, "write");
    written
}

/// A run of the domain this many days old or newer gives the read's size;
/// an older one, or one that didn't say its counts by type, is counted
/// again.
const LAST_SIZE_DAYS: i64 = 30;

/// A read on disk: its folder, what it needs, and its chunks.
struct DiskPlan {
    folder: cache::Folder,
    /// Whether `need` comes from an earlier read (else the sizing count
    /// refines it).
    known: bool,
    /// Bytes the read needs on disk ([`cache::needed`]).
    need: u64,
    /// The plan: the chunks done before it resumed, and those to read.
    chunks: Vec<cache::Chunk>,
}

/// The folder for a read on disk (sweeping earlier ones), checked for free
/// space against the last read of the domain, and its plan: the earlier
/// read's, when resuming was asked for and it can be resumed (same
/// domain controller database, account, filter and attributes, under 24
/// hours old), else a new one from `snapshot`. `None` reads into memory.
fn prepare_cache(
    plan: &ReadPlan<'_>,
    contexts: &[String],
    domain_nc: &str,
    filter: &str,
    snapshot: &DcSnapshot,
    tx: &mpsc::Sender<Msg>,
) -> Result<Option<DiskPlan>, String> {
    let Some(c) = plan.cache else {
        return Ok(None);
    };
    let log = |l: String| {
        let _ = tx.send(Msg::Log(l));
    };
    let domain = plan.domain.trim().trim_end_matches('.');
    // Keyed with the cache's own key: no account name in the checkpoint.
    let k = cache::root_key(&c.root, true)
        .map_err(|e| format!("cannot keep the read in {}: {e}", c.root.display()))?
        .unwrap_or_default();
    let key = cache::Key {
        domain: domain.to_ascii_lowercase(),
        dc_host: plan.dc_host.to_string(),
        ds_service_name: snapshot.ds_service_name.clone(),
        invocation_id: snapshot.invocation_id.clone(),
        account: cache::keyed(&k, &plan.account),
        sign_in: cache::keyed(&k, &plan.sign_in),
        filter: filter.to_string(),
        attributes: cache::attributes_hash(plan.attributes),
    };
    let mut fresh = cache::Checkpoint::new(
        key,
        domain_nc,
        snapshot.highest_usn.unwrap_or(0),
        cache::plan(contexts, domain_nc, snapshot.highest_usn),
    );
    fresh.expected = c.last_entries;
    let opened = cache::Folder::open(&c.root, fresh, c.resume)?;
    if opened.swept > 0 {
        log(format!(
            "[cache] removed {} left from an earlier collection",
            pathwarden_core::text::count(opened.swept, "read", "reads")
        ));
    }
    if let Some(why) = opened.replaced {
        log(format!(
            "[cache] the earlier read of {domain} was not resumed: {why}. Starting over."
        ));
    }
    let cp = &opened.checkpoint;
    if opened.resumed {
        log(format!(
            "[cache] resuming the read of {domain} that started {}: {} of {} parts read",
            pathwarden_core::time::parse_rfc3339(&cp.started)
                .map_or_else(|| cp.started.clone(), pathwarden_core::time::format_utc),
            cp.totals.done,
            cp.totals.chunks
        ));
    } else if snapshot.highest_usn.is_none() || snapshot.invocation_id.is_empty() {
        log(
            "[cache] the domain controller's uSN or database ID could not be read: the \
             domain is read whole, and this read can't be resumed"
                .into(),
        );
    }
    let entry_bytes = match (c.last_entries, c.last_bytes) {
        (Some(n), Some(b)) if n > 0 => Some(b / n),
        _ => None,
    };
    // The last read most likely asked for the list: an entry with every
    // attribute takes more, so at least the 16 KB the estimate takes with
    // no earlier read (a list read after an `*` one is over-estimated,
    // which is safe). A disk that fills up anyway stops the read, to resume.
    let entry_bytes = if plan.attributes == attributes::ALL {
        entry_bytes.map(|b| b.max(cache::DEFAULT_ENTRY_BYTES))
    } else {
        entry_bytes
    };
    // What is on disk already counts.
    let need = cache::needed(c.last_entries.unwrap_or(0), entry_bytes);
    let folder = opened.folder;
    check_space(
        folder.path(),
        need.saturating_sub(cp.totals.bytes),
        plan.free_space,
        tx,
    )?;
    Ok(Some(DiskPlan {
        known: c.last_entries.is_some(),
        need,
        chunks: opened.checkpoint.chunks,
        folder,
    }))
}

/// With no earlier read, the sizing count's estimate (at 16 KB an entry),
/// less what is already on disk, against what is free now.
fn recheck_space(
    d: &mut DiskPlan,
    total: u64,
    written: u64,
    free: cache::FreeSpace,
    tx: &mpsc::Sender<Msg>,
) -> Result<(), String> {
    if d.known {
        return Ok(());
    }
    d.need = cache::needed(total, None);
    check_space(d.folder.path(), d.need.saturating_sub(written), free, tx)
}

/// The read's error, as [`crate::NoSpace`] when the disk filled up, with
/// the space free now.
fn disk_full(
    d: Option<&DiskPlan>,
    stats: Option<&cache::WriteStats>,
    e: String,
    free: cache::FreeSpace,
    tx: &mpsc::Sender<Msg>,
) -> String {
    let (Some(d), Some(s)) = (d, stats) else {
        return e;
    };
    if !s.full.load(Ordering::Relaxed) {
        return e;
    }
    let written = s.written.load(Ordering::Relaxed);
    let dir = d.folder.path();
    let full = crate::NoSpace {
        place: cache::place(dir),
        // The domain is larger than estimated: at least what was written.
        needed: d.need.max(written.saturating_add(written / 10)),
        free: free(dir).unwrap_or(0),
    };
    let message = full.to_string();
    let _ = tx.send(Msg::NoSpace(Box::new(full)));
    message
}

/// RustHound-CE's parse of what was read, from memory or from disk, with
/// progress.
fn parse(
    options: &Options,
    read: ReadOut,
    tx: &mpsc::Sender<Msg>,
) -> Result<(rusthound_ce::api::ADResults, dirextras::Extras), String> {
    let n = read.entries();
    let _ = tx.send(Msg::Units {
        done: 0,
        total: Some(n),
    });
    let extras = std::rc::Rc::new(std::cell::RefCell::new(dirextras::Extras::default()));
    // `None`: no total, so the library draws no progress bar of its own.
    let parsed = match read {
        ReadOut::Memory(entries) => rusthound_ce::api::parse_result_type_from_source(
            options,
            Counting::new(entries.into_iter().map(Ok), n, tx.clone()).noting(extras.clone()),
            None,
        ),
        ReadOut::Disk(written) => {
            let reader = cache::Reader::open(&written.dir)?;
            let took = reader.took();
            let dropped = reader.dropped();
            let parsed = rusthound_ce::api::parse_result_type_from_source(
                options,
                Counting::new(reader, n, tx.clone()).noting(extras.clone()),
                None,
            );
            let read_back = Duration::from_micros(took.load(Ordering::Relaxed));
            let dropped = dropped.load(Ordering::Relaxed);
            let _ = tx.send(Msg::Log(cache_line(&written, read_back, dropped)));
            parsed
        }
    };
    let parsed = parsed.map_err(|e| format!("collection failed while processing objects: {e}"))?;
    let extras = std::rc::Rc::try_unwrap(extras)
        .map(std::cell::RefCell::into_inner)
        .unwrap_or_else(|rc| std::mem::take(&mut *rc.borrow_mut()));
    Ok((parsed, extras))
}

/// `[cache] 69 chunks, 746,326 entries, 12 GB on disk, written in 1:20,
/// read back in 2:31`, and the entries left out as older versions of an
/// object (or the domain head again) when there are any.
fn cache_line(w: &cache::Written, read_back: Duration, dropped: u64) -> String {
    let mut line = format!(
        "[cache] {}, {} entries, {} on disk, written in {}, read back in {}",
        pathwarden_core::text::count(w.chunks, "chunk", "chunks"),
        crate::progress::thousands(w.entries),
        crate::progress::bytes(w.bytes),
        timings::secs(w.busy),
        timings::secs(read_back)
    );
    if dropped > 0 {
        line.push_str(&format!(
            ", {} left out as read again",
            crate::progress::thousands(dropped)
        ));
    }
    line
}

/// What the parsed results hold, as counts (no names), to calibrate the
/// memory figures.
fn shape(r: &rusthound_ce::api::ADResults) -> String {
    use rusthound_ce::objects::common::LdapObject;
    fn aces<T: LdapObject>(v: &[T]) -> usize {
        v.iter().map(|o| o.get_aces().len()).sum()
    }
    let ace_count = aces(&r.users)
        + aces(&r.groups)
        + aces(&r.computers)
        + aces(&r.ous)
        + aces(&r.domains)
        + aces(&r.gpos)
        + aces(&r.fsps)
        + aces(&r.containers)
        + aces(&r.ntauthstores)
        + aces(&r.aiacas)
        + aces(&r.rootcas)
        + aces(&r.enterprisecas)
        + aces(&r.certtemplates)
        + aces(&r.issuancepolicies);
    let members: usize = r.groups.iter().map(|g| g.members().len()).sum();
    let other = r.fsps.len()
        + r.trusts.len()
        + r.ntauthstores.len()
        + r.aiacas.len()
        + r.rootcas.len()
        + r.enterprisecas.len()
        + r.certtemplates.len()
        + r.issuancepolicies.len();
    let n = |v: usize| crate::progress::thousands(v as u64);
    format!(
        "[memory] results: users {}, computers {}, groups {}, ous {}, gpos {}, containers {}, \
         domains {}, other {}; ACEs {}; members {}; dn_sid {}",
        n(r.users.len()),
        n(r.computers.len()),
        n(r.groups.len()),
        n(r.ous.len()),
        n(r.gpos.len()),
        n(r.containers.len()),
        n(r.domains.len()),
        n(other),
        n(ace_count),
        n(members),
        n(r.mappings.dn_sid.len())
    )
}

/// The modules step's share of the bar once the GPOs are known:
/// reading SYSVOL takes time by the GPO, so a domain with thousands
/// of them gets a larger share. `None` when the step doesn't read SYSVOL.
fn modules_weight(
    method: &CollectionMethod,
    results: &rusthound_ce::api::ADResults,
    read: Duration,
    reads: sysvol::Reads,
) -> Option<f64> {
    let planned = steps(method);
    let weight = |key| planned.iter().find(|s| s.key == key).map(|s| s.weight);
    let (base, read_weight) = (weight("modules")?, weight("read")?);
    let (gpos, scripts) = sysvol::size(results);
    Some(match method {
        // Logon scripts are read as the current Windows user only.
        // The step stops at its budget.
        CollectionMethod::LdapOnly => sysvol::sysvol_weight(
            base,
            gpos,
            scripts,
            read_weight,
            read,
            Some(sysvol::SYSVOL_BUDGET),
        ),
        CollectionMethod::DCOnly => sysvol::sysvol_weight(base, gpos, 0, read_weight, read, None),
        // Contacting computers, and SYSVOL, the services and the scheduled
        // tasks on top.
        _ if method.does_gpo() => {
            base + sysvol::sysvol_weight(0.0, gpos, 0, read_weight, read, None)
                + if reads.services {
                    storedcreds::weight(results.computers.len(), read_weight, read)
                } else {
                    0.0
                }
                + if reads.tasks {
                    tasks::weight(results.computers.len(), read_weight, read)
                } else {
                    0.0
                }
        }
        _ => return None,
    })
}

/// LDAP_SERVER_SHOW_DELETED_OID.
fn show_deleted_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.417".into(),
        crit: true,
        val: None,
    }
}

/// LDAP_SERVER_SD_FLAGS_OID: owner, DACL (not the SACL).
fn sd_flags_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.801".into(),
        crit: true,
        val: Some(vec![48, 3, 2, 1, 5]),
    }
}

/// The BloodHound type an entry will become, as the output files name it.
fn kind_of(entry: &SearchEntry) -> &'static str {
    match get_type(entry).unwrap_or(Type::Unknown) {
        Type::User => "users",
        Type::Group => "groups",
        Type::Computer => "computers",
        Type::Ou => "ous",
        Type::Domain => "domains",
        Type::Gpo => "gpos",
        Type::Container => "containers",
        Type::CertTemplate => "certtemplates",
        Type::EnterpriseCA => "enterprisecas",
        Type::RootCA => "rootcas",
        Type::AIACA => "aiacas",
        Type::NtAutStore => "ntauthstores",
        Type::IssuancePolicie => "issuancepolicies",
        _ => "other",
    }
}

/// Where an entry goes in the timings: kept by the parser, or why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Kept,
    Deleted,
    Dns,
    Schema,
    Other,
}

fn category(entry: &SearchEntry, kind: &str) -> Category {
    let has = |attr: &str, f: &dyn Fn(&str) -> bool| {
        entry
            .attrs
            .get(attr)
            .is_some_and(|v| v.iter().any(|x| f(x)))
    };
    if has("isDeleted", &|v| v.eq_ignore_ascii_case("TRUE")) {
        Category::Deleted
    } else if kind != "other" {
        Category::Kept
    } else if has("objectClass", &|v| v.starts_with("dns")) {
        Category::Dns
    } else if has("objectClass", &|v| {
        v == "attributeSchema" || v == "classSchema"
    }) {
        Category::Schema
    } else {
        Category::Other
    }
}

/// Attribute bytes in an entry (values, binary ones included).
fn entry_bytes(entry: &SearchEntry) -> u64 {
    let text: usize = entry.attrs.values().flatten().map(String::len).sum();
    let bin: usize = entry.bin_attrs.values().flatten().map(Vec::len).sum();
    (entry.dn.len() + text + bin) as u64
}

/// Entries per page: AD's MaxPageSize is 1,000.
const PAGE_SIZE: i32 = 999;

/// How long the read waits for the next reply before calling the connection
/// stalled. A DC gives up on a search request itself after its
/// MaxQueryDuration (two minutes by default), so a page that is merely slow
/// comes well within this.
const STALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// `op`, failing with a clear error instead of waiting forever when the
/// DC sends nothing for `limit`.
async fn or_stalled<T, E: std::fmt::Display>(
    limit: Duration,
    what: &str,
    op: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout(limit, op).await {
        Ok(r) => r.map_err(|e| format!("{what} failed: {e}")),
        Err(_) => {
            // `Problem::classify` recognizes "connection stalled".
            let minutes = limit.as_millis().div_ceil(60_000);
            let unit = if minutes == 1 { "minute" } else { "minutes" };
            Err(format!(
                "{what}: connection stalled: the domain controller sent nothing for \
                 {minutes} {unit}"
            ))
        }
    }
}

/// One page of a search, its ranged attributes complete.
struct Page {
    entries: Vec<SearchEntry>,
    /// How long its first entry took to come: one round trip after the
    /// first page.
    wait: Duration,
    /// When its first entry came.
    first_at: Instant,
    /// Ranged retrieval for its entries: entries, extra searches, time.
    ranged_entries: u64,
    ranged_searches: u64,
    ranged: Duration,
}

impl Page {
    fn new(entries: Vec<SearchEntry>) -> Self {
        Self {
            entries,
            wait: Duration::ZERO,
            first_at: Instant::now(),
            ranged_entries: 0,
            ranged_searches: 0,
            ranged: Duration::ZERO,
        }
    }
}

/// Where the read gets its pages: one search at a time, a chunk of the plan
/// ([`cache::plan`]). Each stream has its own ([`streams`]). [`LdapPages`]
/// reads the DC; the tests read a fake.
trait PageSource {
    /// Starts reading `chunk`: its naming context, or the head alone,
    /// within its uSN window.
    async fn start(&mut self, chunk: &cache::Chunk, filter: &str) -> Result<(), String>;
    /// Starts one search of the rest chunk ([`cache::Kind::Rest`]) of
    /// `chunk.nc`, with `filter`: as [`Lookup`] says.
    async fn start_rest(
        &mut self,
        chunk: &cache::Chunk,
        filter: &str,
        lookup: Lookup<'_>,
    ) -> Result<(), String>;
    /// The objects the last [`Lookup::Objects`] found gone (LDAP result 32,
    /// noSuchObject: deleted, renamed or moved since they were listed).
    fn take_gone(&mut self) -> Vec<String>;
    /// The next page, `None` at the end.
    async fn next_page(&mut self) -> Result<Option<Page>, String>;
    /// Ends the search. `Err`: the DC did not return everything (a warning).
    async fn end(&mut self) -> Result<(), String>;
}

/// A search of the rest chunk ([`PageSource::start_rest`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup<'a> {
    /// Every object of the naming context, its DN alone (the attribute
    /// list `1.1`).
    List,
    /// Each of these objects alone (a Base search each, with the
    /// attributes the read asks for), [`OBJECTS_AT_ONCE`] at a time, their
    /// entries in this order. One no longer there is in
    /// [`PageSource::take_gone`].
    Objects(&'a [String]),
}

/// Base searches of the rest chunk in flight at once, on the stream's
/// connection: one at a time would be a round trip per object.
const OBJECTS_AT_ONCE: usize = 16;

/// What one Base search of the rest chunk found: the entry, or `None` when
/// the object isn't there (noSuchObject).
type ObjectRead = tokio::task::JoinHandle<Result<Option<Vec<SearchEntry>>, String>>;

/// The rest chunk's Base searches ([`Lookup::Objects`]) as they go.
struct Objects {
    ldap: ldap3::Ldap,
    filter: String,
    attributes: &'static [&'static str],
    todo: std::collections::VecDeque<String>,
    running: std::collections::VecDeque<(String, ObjectRead)>,
    gone: Vec<String>,
}

impl Objects {
    /// Starts reads until [`OBJECTS_AT_ONCE`] are in flight.
    fn top_up(&mut self) {
        while self.running.len() < OBJECTS_AT_ONCE {
            let Some(dn) = self.todo.pop_front() else {
                return;
            };
            let mut ldap = self.ldap.clone();
            let (base, filter, attributes) = (dn.clone(), self.filter.clone(), self.attributes);
            let read = tokio::spawn(async move {
                let what = "LDAP search of an object no uSN range returned";
                ldap.with_controls(vec![sd_flags_control()]);
                let ldap3::SearchResult(entries, result) = or_stalled(
                    STALL_TIMEOUT,
                    what,
                    ldap.search(&base, LdapScope::Base, &filter, attributes.to_vec()),
                )
                .await?;
                match result.rc {
                    0 => Ok(Some(
                        entries.into_iter().map(SearchEntry::construct).collect(),
                    )),
                    32 => Ok(None),
                    _ => Err(format!("{what} failed: {result}")),
                }
            });
            self.running.push_back((dn, read));
        }
    }

    /// The next object's entries (none when it is gone), in order; `None`
    /// once every one is read.
    async fn next(&mut self) -> Result<Option<Vec<SearchEntry>>, String> {
        self.top_up();
        let Some((dn, read)) = self.running.pop_front() else {
            return Ok(None);
        };
        let found = read
            .await
            .map_err(|e| format!("an object's read stopped: {e}"))??;
        Ok(Some(found.unwrap_or_else(|| {
            self.gone.push(dn);
            Vec::new()
        })))
    }
}

impl Drop for Objects {
    fn drop(&mut self) {
        for (_, read) in &self.running {
            read.abort();
        }
    }
}

/// The attribute list that asks for no attribute (RFC 4511): DNs alone.
const NO_ATTRIBUTES: &[&str] = &["1.1"];

type Search = ldap3::SearchStream<'static, &'static str, Vec<&'static str>>;

/// How [`LdapPages`] completes the attributes AD cut short (groups of more
/// than 1,500 members).
enum RangedVia {
    /// On a second handle of the same connection, before the next entry: a
    /// retest's small read.
    Inline(ldap3::Ldap),
    /// The pool's workers, on connections of their own, while the stream
    /// reads its next page ([`ranged::Pool`]).
    /// With a handle of the stream's own connection, for when the pool has
    /// none.
    Pool(Arc<ranged::Pool>, ldap3::Ldap),
}

/// A page read, waiting for its entries' ranged attributes.
struct Pending {
    page: Page,
    waits: Vec<(usize, tokio::sync::oneshot::Receiver<ranged::Done>)>,
}

/// Pages a stream holds while their ranged attributes are completed: one
/// more is read meanwhile, never more.
const PENDING_PAGES: usize = 2;

/// Pages from the DC, as RustHound-CE's `collect_from_ldap_into` asks for
/// them (same SD flags; MIT, see THIRD-PARTY-NOTICES.md), with the
/// attributes its parser reads unless asked for all ([`attributes`]).
struct LdapPages {
    ldap: ldap3::Ldap,
    /// The connection's driver, when the connection is this source's own.
    own: Option<Driver>,
    ranged: RangedVia,
    search: Option<Search>,
    what: String,
    attributes: &'static [&'static str],
    pending: std::collections::VecDeque<Pending>,
    /// The search has no more pages.
    exhausted: bool,
    /// The rest chunk's Base searches, in place of `search`.
    objects: Option<Objects>,
    /// What the last ones found gone.
    gone: Vec<String>,
}

impl LdapPages {
    /// Pages over `ldap`, ranged attributes completed inline.
    fn new(ldap: ldap3::Ldap, attributes: &'static [&'static str]) -> Self {
        let ranged = RangedVia::Inline(ldap.clone());
        Self::with(ldap, None, ranged, attributes)
    }

    fn with(
        ldap: ldap3::Ldap,
        own: Option<Driver>,
        ranged: RangedVia,
        attributes: &'static [&'static str],
    ) -> Self {
        Self {
            ldap,
            own,
            ranged,
            search: None,
            what: String::new(),
            attributes,
            pending: Default::default(),
            exhausted: false,
            objects: None,
            gone: Vec::new(),
        }
    }

    /// Ends the connection, when it is this source's own.
    async fn close(self) {
        drop(self.search);
        if let Some(driver) = self.own {
            close(self.ldap, driver).await;
        }
    }

    /// The next entries of the search as they came, up to a page.
    async fn raw_page(&mut self) -> Result<Option<Page>, String> {
        if let Some(objects) = self.objects.as_mut() {
            let mut page = Page::new(Vec::with_capacity(PAGE_SIZE as usize));
            let waited = Instant::now();
            while page.entries.len() < PAGE_SIZE as usize {
                let Some(found) = objects.next().await? else {
                    break;
                };
                if page.entries.is_empty() && !found.is_empty() {
                    page.wait = waited.elapsed();
                    page.first_at = Instant::now();
                }
                page.entries.extend(found);
            }
            return Ok((!page.entries.is_empty()).then_some(page));
        }
        let Some(search) = self.search.as_mut() else {
            return Ok(None);
        };
        let mut page = Page::new(Vec::with_capacity(PAGE_SIZE as usize));
        while page.entries.len() < PAGE_SIZE as usize {
            // ldap3 asks for the next page only when this one is used up,
            // so the wait for a page's first entry is one round trip.
            let waited = Instant::now();
            let Some(entry) = or_stalled(STALL_TIMEOUT, &self.what, search.next()).await? else {
                break;
            };
            if page.entries.is_empty() {
                page.wait = waited.elapsed();
                page.first_at = Instant::now();
            }
            page.entries.push(SearchEntry::construct(entry));
        }
        Ok((!page.entries.is_empty()).then_some(page))
    }
}

/// An entry with nothing in it, holding an entry's place in its page.
fn placeholder() -> SearchEntry {
    SearchEntry {
        dn: String::new(),
        attrs: Default::default(),
        bin_attrs: Default::default(),
    }
}

impl LdapPages {
    /// Starts a paged search of `base`, with the SD flags (and
    /// SHOW_DELETED when `deleted`).
    async fn search(
        &mut self,
        base: &str,
        scope: LdapScope,
        filter: &str,
        attributes: &'static [&'static str],
        deleted: bool,
    ) -> Result<(), String> {
        use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
        // An earlier try's pages go.
        self.pending.clear();
        self.exhausted = false;
        self.objects = None;
        let mut controls = vec![sd_flags_control()];
        if deleted {
            controls.push(show_deleted_control());
        }
        self.ldap.with_controls(controls);
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(PAGE_SIZE)),
        ];
        let search = or_stalled(
            STALL_TIMEOUT,
            &self.what,
            self.ldap
                .streaming_search_with(adapters, base, scope, filter, attributes.to_vec()),
        )
        .await?;
        self.search = Some(search);
        Ok(())
    }
}

impl PageSource for LdapPages {
    async fn start(&mut self, chunk: &cache::Chunk, filter: &str) -> Result<(), String> {
        let base = chunk.nc.as_str();
        let scope = if chunk.base_only() {
            LdapScope::Base
        } else {
            LdapScope::Subtree
        };
        let filter = chunk.filter(filter);
        self.what = match (chunk.usn_lo, chunk.usn_hi) {
            (None, None) => format!("LDAP search of {base}"),
            (lo, hi) => format!(
                "LDAP search of {base} (uSNChanged {}-{})",
                lo.unwrap_or(0),
                hi.map_or(String::new(), |h| h.to_string())
            ),
        };
        // The delta also asks for deleted objects: one deleted during the
        // read is left out of its earlier window ([`cache::Reader`]).
        self.search(base, scope, &filter, self.attributes, chunk.shows_deleted())
            .await
    }

    async fn start_rest(
        &mut self,
        chunk: &cache::Chunk,
        filter: &str,
        lookup: Lookup<'_>,
    ) -> Result<(), String> {
        let nc = chunk.nc.as_str();
        match lookup {
            Lookup::List => {
                self.what = format!("LDAP search of {nc} (DNs)");
                self.search(nc, LdapScope::Subtree, filter, NO_ATTRIBUTES, false)
                    .await
            }
            Lookup::Objects(dns) => {
                self.pending.clear();
                self.exhausted = false;
                self.search = None;
                self.gone.clear();
                self.what = format!("LDAP search of the objects of {nc} no uSN range returned");
                self.objects = Some(Objects {
                    ldap: self.ldap.clone(),
                    filter: filter.to_string(),
                    attributes: self.attributes,
                    todo: dns.iter().cloned().collect(),
                    running: Default::default(),
                    gone: Vec::new(),
                });
                Ok(())
            }
        }
    }

    fn take_gone(&mut self) -> Vec<String> {
        std::mem::take(&mut self.gone)
    }

    async fn next_page(&mut self) -> Result<Option<Page>, String> {
        let (pool, mut inline) = match &mut self.ranged {
            RangedVia::Pool(p, inline) => (p.clone(), inline.clone()),
            RangedVia::Inline(_) => {
                let Some(mut page) = self.raw_page().await? else {
                    return Ok(None);
                };
                let RangedVia::Inline(ldap) = &mut self.ranged else {
                    return Ok(Some(page));
                };
                for entry in page.entries.iter_mut() {
                    let started = Instant::now();
                    let searches = ranged::complete(ldap, entry).await?;
                    if searches > 0 {
                        page.ranged_entries += 1;
                        page.ranged_searches += searches;
                        page.ranged += started.elapsed();
                    }
                }
                return Ok(Some(page));
            }
        };
        loop {
            if self.pending.front().is_some_and(|p| p.waits.is_empty()) {
                return Ok(self.pending.pop_front().map(|p| p.page));
            }
            if !self.exhausted && self.pending.len() < PENDING_PAGES {
                match self.raw_page().await? {
                    Some(mut page) => {
                        let mut waits = Vec::new();
                        for (i, entry) in page.entries.iter_mut().enumerate() {
                            if ranged::is_ranged(entry) {
                                let entry = std::mem::replace(entry, placeholder());
                                waits.push((i, pool.submit(entry).await));
                            }
                        }
                        self.pending.push_back(Pending { page, waits });
                    }
                    None => self.exhausted = true,
                }
                continue;
            }
            let Some(front) = self.pending.front_mut() else {
                return Ok(None);
            };
            for (i, rx) in std::mem::take(&mut front.waits) {
                let done = rx
                    .await
                    .map_err(|_| "the members' reader stopped".to_string())?;
                let (entry, searches, took) = match done {
                    Ok(d) => d,
                    // The pool has no connection: on this stream's own.
                    Err(ranged::Failed::NoConnection(mut entry)) => {
                        let started = Instant::now();
                        let n = ranged::complete(&mut inline, &mut entry).await?;
                        (entry, n, started.elapsed())
                    }
                    Err(ranged::Failed::Search(e)) => return Err(e),
                };
                front.page.entries[i] = entry;
                front.page.ranged_entries += 1;
                front.page.ranged_searches += searches;
                front.page.ranged += took;
            }
        }
    }

    async fn end(&mut self) -> Result<(), String> {
        if let Some(mut objects) = self.objects.take() {
            self.gone = std::mem::take(&mut objects.gone);
            return Ok(());
        }
        match self.search.take() {
            Some(mut search) => search
                .finish()
                .await
                .success()
                .map(|_| ())
                .map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }
}

/// How another connection to the domain controller the read started on is
/// made: the same address, sign-in and certificate checks as the first
/// ([`open`]), bound as the same account. Kerberos as the current user
/// reuses the logon session's ticket. Before signing in, its RootDSE must
/// name the controller the read started on ([`Connector::pin`]): a DNS
/// alias or round robin landing on another one is refused.
///
/// The URL is the first connection's when a server was named, else the
/// controller's own name, which the first connection checked against DNS
/// and the RootDSE ([`dc_host`]); the certificate is checked against that
/// name in the same way.
pub(super) struct Connector {
    url: String,
    ldaps: bool,
    skip_verify: bool,
    dc_fqdn: String,
    auth: ConnectAuth,
    /// The `dsServiceName` the read's snapshot named (empty: not known).
    pinned: Mutex<String>,
    /// The first connection's RootDSE `dnsHostName` (empty: not known).
    pinned_host: Mutex<String>,
}

enum ConnectAuth {
    CurrentUser,
    Ntlm {
        user: String,
        bind: String,
        /// Dropped once the read no longer opens connections ([`Connector::forget`]).
        password: Mutex<Option<Secret>>,
    },
}

impl Connector {
    /// For `job`, whose first connection reached `dc_fqdn`: the uSN windows
    /// are that controller's, so every connection goes to it.
    fn of(job: &Job, dc_fqdn: &str) -> Self {
        let named = job.server.as_deref().is_some_and(|s| !s.trim().is_empty());
        Self {
            url: if named {
                job.url.clone()
            } else {
                url_for(dc_fqdn, job.ldaps)
            },
            ldaps: job.ldaps,
            skip_verify: job.skip_verify,
            dc_fqdn: dc_fqdn.to_string(),
            auth: match &job.auth {
                JobAuth::CurrentUser => ConnectAuth::CurrentUser,
                JobAuth::Ntlm {
                    user,
                    bind,
                    password,
                } => ConnectAuth::Ntlm {
                    user: user.clone(),
                    bind: bind.clone(),
                    password: Mutex::new(Some(password.duplicate())),
                },
            },
            pinned: Mutex::new(String::new()),
            pinned_host: Mutex::new(String::new()),
        }
    }

    /// Every connection from now on must reach the controller whose NTDS
    /// Settings object is `ds_service_name` or, when that isn't known, whose
    /// RootDSE names itself `host` as the first connection's did.
    fn pin(&self, ds_service_name: &str, host: Option<&str>) {
        if let Ok(mut p) = self.pinned.lock() {
            *p = ds_service_name.trim().to_string();
        }
        if let (Ok(mut h), Some(host)) = (self.pinned_host.lock(), host) {
            *h = host.trim().trim_end_matches('.').to_string();
        }
    }

    /// The password's copy goes: no more connections.
    fn forget(&self) {
        if let ConnectAuth::Ntlm { password, .. } = &self.auth {
            if let Ok(mut p) = password.lock() {
                p.take();
            }
        }
    }

    /// Why the controller whose RootDSE says `ds` (`dsServiceName`) and
    /// `host` (`dnsHostName`) is not the one the read started on, if it
    /// isn't.
    fn elsewhere(&self, ds: Option<&str>, host: Option<&str>) -> Option<String> {
        let pinned = self.pinned.lock().map(|p| p.clone()).unwrap_or_default();
        let first_host = self
            .pinned_host
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default();
        // The first connection's own name for itself, else the DC's name
        // when it is one (not an address).
        let expected = if !first_host.is_empty() {
            Some(first_host.as_str())
        } else if is_fqdn(&self.dc_fqdn) {
            Some(self.dc_fqdn.trim_end_matches('.'))
        } else {
            None
        };
        if !pinned.is_empty() {
            return match ds {
                Some(ds) if ds.trim().eq_ignore_ascii_case(&pinned) => None,
                Some(_) => Some(format!(
                    "{} reached {}, not {}, the domain controller the read started on",
                    self.url,
                    host.unwrap_or("another domain controller"),
                    self.dc_fqdn
                )),
                None => Some(format!(
                    "{} did not say which domain controller it is",
                    self.url
                )),
            };
        }
        match (host, expected) {
            (Some(h), Some(want)) if !h.trim().trim_end_matches('.').eq_ignore_ascii_case(want) => {
                Some(format!(
                    "{} reached {h}, not {want}, the domain controller the read started on",
                    self.url
                ))
            }
            (None, Some(_)) => Some(format!(
                "{} did not say which domain controller it is",
                self.url
            )),
            _ => None,
        }
    }

    /// A new connection to the read's domain controller, bound. End it
    /// with [`close`].
    async fn connect(&self) -> Result<(ldap3::Ldap, Driver), String> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(15))
            .set_no_tls_verify(self.skip_verify);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .map_err(|e| connect_error(&self.url, self.ldaps, &e.to_string()))?;
        let driver = Driver(tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                log::warn!("LDAP connection error: {e}");
            }
        }));
        let checked = match read_one(&ldap, "", "dsServiceName").await {
            Some(e) => {
                let ds = e.attrs.get("dsServiceName").and_then(|v| v.first());
                let host = read_one(&ldap, "", "dnsHostName").await;
                let host = host
                    .as_ref()
                    .and_then(|e| e.attrs.get("dnsHostName")?.first());
                match self.elsewhere(ds.map(String::as_str), host.map(String::as_str)) {
                    Some(why) => Err(why),
                    None => Ok(()),
                }
            }
            None => match self.elsewhere(None, None) {
                Some(why) => Err(why),
                None => Ok(()),
            },
        };
        let bound = match checked {
            Err(e) => Err(e),
            Ok(()) => match &self.auth {
                ConnectAuth::Ntlm {
                    user,
                    bind,
                    password,
                } => {
                    let password = password
                        .lock()
                        .ok()
                        .and_then(|p| p.as_ref().map(|s| Secret::new(s.expose())));
                    match password {
                        Some(p) => ldap
                            .sasl_ntlm_bind(bind, p.expose())
                            .await
                            .and_then(|r| r.success())
                            .map(|_| ())
                            .map_err(|e| bind_failed(user, bind, &e.to_string())),
                        None => Err("the read is over: no more connections".into()),
                    }
                }
                ConnectAuth::CurrentUser => gssapi_bind(&mut ldap, &self.dc_fqdn).await,
            },
        };
        match bound {
            Ok(()) => Ok((ldap, driver)),
            Err(e) => {
                close(ldap, driver).await;
                Err(e)
            }
        }
    }

    /// For the ranged pool's workers.
    fn opener(self: &Arc<Self>) -> ranged::Opener {
        let me = self.clone();
        Arc::new(move || {
            let me = me.clone();
            Box::pin(async move {
                let (ldap, driver) = me.connect().await?;
                Ok(Box::new(ranged::Owned { ldap, driver }) as Box<dyn ranged::RangedConn>)
            })
        })
    }
}

/// The streams of a read from the domain controller: stream 1 starts on
/// the connection already open, the others (and any stream's second try)
/// on new ones. With several streams, ranged retrieval goes to one pool
/// for all, of as many workers as streams, at most four; with one, it is
/// done inline on the stream's connection, as before.
struct LdapStreams {
    main: ldap3::Ldap,
    main_taken: std::cell::Cell<bool>,
    connector: Option<Arc<Connector>>,
    pool: Option<Arc<ranged::Pool>>,
    attributes: &'static [&'static str],
}

impl LdapStreams {
    fn new(
        main: ldap3::Ldap,
        connector: Option<Arc<Connector>>,
        attributes: &'static [&'static str],
        streams: usize,
        tx: &mpsc::Sender<Msg>,
    ) -> Self {
        let pool = connector.as_ref().filter(|_| streams > 1).map(|c| {
            Arc::new(ranged::Pool::start(
                ranged::WORKERS.min(streams),
                c.opener(),
                Some(tx.clone()),
            ))
        });
        Self {
            main,
            main_taken: Default::default(),
            connector,
            pool,
            attributes,
        }
    }

    fn ranged(&self, ldap: &ldap3::Ldap) -> RangedVia {
        match &self.pool {
            Some(p) => RangedVia::Pool(p.clone(), ldap.clone()),
            None => RangedVia::Inline(ldap.clone()),
        }
    }

    /// Ends the ranged pool's connections.
    async fn close(self) {
        if let Some(pool) = self.pool.and_then(|p| Arc::try_unwrap(p).ok()) {
            pool.close().await;
        }
    }
}

impl streams::Streams for LdapStreams {
    type Source = LdapPages;

    async fn open(&self, stream: usize, fresh: bool) -> Result<LdapPages, String> {
        if stream == 0 && !fresh && !self.main_taken.replace(true) {
            let ranged = self.ranged(&self.main);
            return Ok(LdapPages::with(
                self.main.clone(),
                None,
                ranged,
                self.attributes,
            ));
        }
        let Some(connector) = &self.connector else {
            return Err("there is no other connection to read it again on".into());
        };
        let (ldap, driver) = connector.connect().await?;
        let ranged = self.ranged(&ldap);
        Ok(LdapPages::with(ldap, Some(driver), ranged, self.attributes))
    }

    async fn release(&self, source: LdapPages) {
        source.close().await;
    }
}

/// Where the read puts the entries.
enum Sink {
    /// In memory (`--no-cache`): the entries, and where each chunk being
    /// read started in them (to take a failed one back out).
    Memory(Vec<LdapSearchEntry>, BTreeMap<u32, usize>),
    /// On disk, a file per chunk.
    Disk(cache::Writer),
}

/// What the read read.
enum ReadOut {
    Memory(Vec<LdapSearchEntry>),
    Disk(cache::Written),
}

impl ReadOut {
    fn entries(&self) -> u64 {
        match self {
            ReadOut::Memory(v) => v.len() as u64,
            ReadOut::Disk(w) => w.entries,
        }
    }
}

impl Sink {
    fn memory() -> Self {
        Sink::Memory(Vec::new(), BTreeMap::new())
    }

    fn begin(&mut self, id: u32, nc: &str) -> Result<(), String> {
        match self {
            Sink::Memory(v, starts) => {
                starts.insert(id, v.len());
                Ok(())
            }
            Sink::Disk(w) => w.begin(id, nc),
        }
    }

    fn page(&mut self, id: u32, page: Vec<LdapSearchEntry>) -> Result<(), String> {
        match self {
            Sink::Memory(v, _) => {
                v.extend(page);
                Ok(())
            }
            Sink::Disk(w) => w.page(id, page),
        }
    }

    fn end(&mut self, id: u32, counts: BTreeMap<String, u64>) -> Result<(), String> {
        match self {
            Sink::Memory(_, starts) => {
                starts.remove(&id);
                Ok(())
            }
            Sink::Disk(w) => w.end(id, counts),
        }
    }

    /// Chunk `id` failed: what it wrote goes. In memory one chunk is read
    /// at a time, so it is the end of the entries.
    fn abort(&mut self, id: u32) -> Result<(), String> {
        match self {
            Sink::Memory(v, starts) => {
                if let Some(at) = starts.remove(&id) {
                    v.truncate(at);
                }
                Ok(())
            }
            Sink::Disk(w) => w.abort(id),
        }
    }

    fn finish(self) -> Result<ReadOut, String> {
        match self {
            Sink::Memory(v, _) => Ok(ReadOut::Memory(v)),
            Sink::Disk(w) => w.finish().map(ReadOut::Disk),
        }
    }
}

/// [`read_directory`] from the DC into memory: for small, filtered reads.
async fn read_in_memory(
    ldap: &mut ldap3::Ldap,
    filter: &str,
    contexts: &[String],
    domain_nc: &str,
    tx: &mpsc::Sender<Msg>,
    timings: &mut Timings,
) -> Result<Vec<LdapSearchEntry>, String> {
    // A retest asks for what the parser reads, as a collection does.
    let mut pages = LdapPages::new(ldap.clone(), attributes::PARSED);
    let chunks = cache::whole_plan(contexts);
    let sink = Sink::memory();
    match read_directory(&mut pages, filter, &chunks, domain_nc, tx, timings, sink).await? {
        ReadOut::Memory(entries) => Ok(entries),
        ReadOut::Disk(_) => Err("the read went to disk".into()),
    }
}

/// A `[memory]` line every this many pages of the read.
const MEMORY_EVERY_PAGES: u64 = 100;

/// The name [`kind_of`] gives, for one read back from a checkpoint.
fn static_kind(kind: &str) -> &'static str {
    const KINDS: [&str; 13] = [
        "users",
        "groups",
        "computers",
        "ous",
        "domains",
        "gpos",
        "containers",
        "certtemplates",
        "enterprisecas",
        "rootcas",
        "aiacas",
        "ntauthstores",
        "issuancepolicies",
    ];
    KINDS.into_iter().find(|k| *k == kind).unwrap_or("other")
}

/// Every chunk of the plan not yet done, in order, from one source into
/// `sink` ([`streams::read`] with one stream, and no second connection to
/// read a failed chunk again on). On disk, the order the parser needs
/// (Schema first, the domain head before its objects) comes from
/// [`cache::Reader`]; into memory, the plan is each naming context whole,
/// in RustHound-CE's order.
///
/// Unlike upstream, deleted objects are not asked for (no SHOW_DELETED
/// control): Pathwarden's ingest drops them, and with the AD Recycle Bin
/// they keep every attribute and their security descriptor for 180 days.
async fn read_directory(
    pages: &mut impl PageSource,
    filter: &str,
    chunks: &[cache::Chunk],
    domain_nc: &str,
    tx: &mpsc::Sender<Msg>,
    timings: &mut Timings,
    sink: Sink,
) -> Result<ReadOut, String> {
    let plan = streams::Plan {
        filter,
        chunks,
        domain_nc,
        tx,
        streams: 1,
        refused_wait: streams::REFUSED_WAIT,
    };
    streams::read(&streams::Single::new(pages), &plan, timings, sink)
        .await
        .map(|r| r.out)
}

/// A `[memory]` line every this many entries of the parse.
const MEMORY_EVERY_ENTRIES: u64 = 100_000;

/// Feeds the parser and reports how far it got: from memory (`--no-cache`)
/// or from disk ([`cache::Reader`]).
struct Counting<I> {
    inner: I,
    done: u64,
    total: u64,
    tx: mpsc::Sender<Msg>,
    /// Where the entries Pathwarden keeps for itself are noted.
    extras: Option<std::rc::Rc<std::cell::RefCell<dirextras::Extras>>>,
}

type Entry = Result<LdapSearchEntry, Box<dyn std::error::Error>>;

impl<I: Iterator<Item = Entry>> Counting<I> {
    fn new(inner: I, total: u64, tx: mpsc::Sender<Msg>) -> Self {
        Self {
            inner,
            done: 0,
            total,
            tx,
            extras: None,
        }
    }

    /// Notes the entries [`dirextras::Extras`] keeps into `extras`.
    fn noting(mut self, extras: std::rc::Rc<std::cell::RefCell<dirextras::Extras>>) -> Self {
        self.extras = Some(extras);
        self
    }
}

impl<I: Iterator<Item = Entry>> Iterator for Counting<I> {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.inner.next()?;
        if let (Some(x), Ok(e)) = (&self.extras, &entry) {
            x.borrow_mut().see(e);
        }
        self.done += 1;
        if self.done.is_multiple_of(2048) || self.done == self.total {
            let _ = self.tx.send(Msg::Units {
                done: self.done,
                total: Some(self.total),
            });
        }
        if self.done.is_multiple_of(MEMORY_EVERY_ENTRIES) {
            log_memory(
                &self.tx,
                &format!("parse, {} entries", crate::progress::thousands(self.done)),
            );
        }
        Some(entry)
    }
}

impl<I: Iterator<Item = Entry>> EntrySource for Counting<I> {
    type Iter = Self;

    fn into_entry_iter(self) -> Self {
        self
    }
}

/// Estimates what [`read_directory`] will return, on its own handle, and
/// returns how long that took. The domain naming context, by far the
/// largest, is no longer walked whole (`(objectClass=*)` touches every
/// object a second time on the DC): its users, computers, groups, OUs, GPOs
/// and containers are counted through indexed filters instead, and the
/// small Schema, Configuration and other partitions exactly. Objects of
/// other types in the domain (BitLocker keys, service connection points,
/// ...) are not in the estimate; the progress raises its total when the
/// read passes it. Also returns the estimate, when the count finished.
async fn size_directory(
    mut ldap: ldap3::Ldap,
    contexts: Vec<String>,
    domain_nc: String,
    tx: &mpsc::Sender<Msg>,
) -> (Duration, Option<u64>) {
    let started = Instant::now();
    let never = tokio::time::Instant::now() + Duration::from_secs(24 * 3600);
    let mut total = 0;
    let mut domain_read = false;
    for (kind, filter) in KIND_FILTERS {
        if !contexts.iter().any(|c| c.eq_ignore_ascii_case(&domain_nc)) {
            break;
        }
        domain_read = true;
        match count(&mut ldap, &domain_nc, filter, never).await {
            Some(c) => {
                total += c.n as u64;
                if matches!(kind, "users" | "computers" | "groups") {
                    let _ = tx.send(Msg::Expect(kind, c.n as u64));
                }
            }
            None => return (started.elapsed(), None),
        }
    }
    // The domain object itself.
    total += u64::from(domain_read);
    for cn in contexts
        .iter()
        .filter(|c| !c.eq_ignore_ascii_case(&domain_nc))
    {
        match count(&mut ldap, cn, "(objectClass=*)", never).await {
            Some(c) => total += c.n as u64,
            None => return (started.elapsed(), None),
        }
    }
    let _ = tx.send(Msg::ExpectTotal(total));
    (started.elapsed(), Some(total))
}

/// LDAP filters for the object types SharpHound and RustHound-CE read.
const KIND_FILTERS: [(&str, &str); 6] = [
    ("users", "(sAMAccountType=805306368)"),
    ("computers", "(sAMAccountType=805306369)"),
    ("groups", "(objectCategory=group)"),
    ("ous", "(objectClass=organizationalUnit)"),
    ("gpos", "(objectClass=groupPolicyContainer)"),
    ("containers", "(objectClass=container)"),
];

/// How long [`estimate`] may count.
#[cfg(windows)]
const ESTIMATE_BUDGET: Duration = Duration::from_secs(60);

/// Counts the domain's users, computers, groups, OUs, GPOs and containers
/// as the current user: about what SharpHound processes, for its progress.
/// `None` if the domain can't be reached or bound. Only SharpHound runs on
/// Windows use it.
#[cfg(windows)]
pub(crate) fn estimate(req: &CollectRequest) -> Option<crate::external::Estimate> {
    use crate::external::Estimate;
    let job = job_for(req, CollectionMethod::LdapOnly).ok()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async {
        tokio::time::timeout(ESTIMATE_BUDGET, async {
            let (mut ldap, driver, _, contexts) = open(&job, &|_| {}, &|_| {}).await.ok()?;
            let base = contexts.domain.unwrap_or_else(|| domain_dn(&job.domain));
            let deadline = tokio::time::Instant::now() + ESTIMATE_BUDGET;
            let mut est = Estimate::default();
            let mut total = Some(0u64);
            for (kind, filter) in KIND_FILTERS {
                match count(&mut ldap, &base, filter, deadline).await {
                    Some(Count { n, at_least: false }) => {
                        est.by_kind.push((kind, n as u64));
                        total = total.map(|t| t + n as u64);
                    }
                    _ => total = None,
                }
            }
            // The domain object itself.
            est.total = total.map(|t| t + 1);
            close(ldap, driver).await;
            Some(est)
        })
        .await
        .ok()
        .flatten()
    })
}

/// ldap3's connection driver: the task that reads and writes the socket.
pub(super) struct Driver(tokio::task::JoinHandle<()>);

/// Ends a connection from [`open`]: an unbind, then the driver stops.
///
/// ldap3's driver sends the unbind, closes its side and keeps reading. The
/// domain controller resets the connection once it has the unbind, and the
/// driver then logged "socket receive error: An existing connection was
/// forcibly closed by the remote host. (os error 10054)" when that reset
/// arrived before the runtime stopped, at the end of a collection whose work
/// was done. Nothing is left to read after an unbind, so the driver stops as
/// soon as the unbind is sent; the reset can still come first (the driver
/// runs on another thread), so the log bridge drops ldap3's socket errors
/// while a connection closes ([`CLOSING`]).
pub(super) async fn close(mut ldap: ldap3::Ldap, driver: Driver) {
    // Lowered when dropped: a close cancelled midway leaves no count up.
    let _closing = Closing::new();
    let _ = ldap.unbind().await;
    driver.0.abort();
    let _ = driver.0.await;
}

/// One connection being closed, counted in [`CLOSING`] while it lives.
struct Closing;

impl Closing {
    fn new() -> Self {
        CLOSING.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        CLOSING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Connections being closed ([`close`]): until each one's driver has
/// stopped, a reset the domain controller sends after the unbind is the
/// normal end of the connection.
static CLOSING: AtomicUsize = AtomicUsize::new(0);

/// Connects and binds as the job says. Returns the connection and its
/// driver (end both with [`close`]), the DC's FQDN and the naming contexts
/// the RootDSE names.
async fn open(
    job: &Job,
    phase: &dyn Fn(String),
    log: &dyn Fn(String),
) -> Result<(ldap3::Ldap, Driver, String, NamingContexts), String> {
    open_once(job, phase, log)
        .await
        .map_err(|e| with_ldaps_failure(job, e))
}

/// [`open`], whose errors don't yet say LDAPS failed first.
async fn open_once(
    job: &Job,
    phase: &dyn Fn(String),
    log: &dyn Fn(String),
) -> Result<(ldap3::Ldap, Driver, String, NamingContexts), String> {
    phase(format!("Connecting to {}", job.url));
    let connected_addrs = resolve_dc(job).await?;
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_no_tls_verify(job.skip_verify);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &job.url)
        .await
        .map_err(|e| connect_error(&job.url, job.ldaps, &e.to_string()))?;
    // `ldap3::drive!`, keeping the task's handle for `close`.
    let driver = Driver(tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            log::warn!("LDAP connection error: {e}");
        }
    }));

    // The RootDSE is readable before binding and names the DC we reached,
    // which Kerberos needs for the ldap/<fqdn> service principal. It is
    // unauthenticated, so it only names the SPN host after checks (L6).
    let (host, contexts) = root_dse(&mut ldap).await;
    if let Some(actual) = contexts
        .domain
        .as_deref()
        .and_then(|nc| wrong_domain(&job.domain, nc))
    {
        close(ldap, driver).await;
        return Err(format!(
            "{} is a domain controller for {actual}, not {}",
            job.server.as_deref().unwrap_or(&job.url),
            job.domain
        ));
    }
    let kerberos = matches!(job.auth, JobAuth::CurrentUser);
    let dc_fqdn = dc_host(job, &connected_addrs, host.as_deref(), kerberos, log).await?;
    log(format!("Domain controller: {dc_fqdn}"));

    phase(format!("Signing in to {dc_fqdn}"));
    match &job.auth {
        JobAuth::Ntlm {
            user,
            bind,
            password,
        } => {
            ldap.sasl_ntlm_bind(bind, password.expose())
                .await
                .and_then(|r| r.success())
                // The plain explanation (wrong password, signing required)
                // comes from `Problem::classify`, in front of this.
                .map_err(|e| bind_failed(user, bind, &e.to_string()))?;
        }
        JobAuth::CurrentUser => gssapi_bind(&mut ldap, &dc_fqdn).await?,
    }
    Ok((ldap, driver, dc_fqdn, contexts))
}

/// How long the DNS lookup of the DC (or domain) may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(20);

/// The host the job connects to: `--server`, else the domain name.
fn connected_host(job: &Job) -> &str {
    job.server
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(job.domain.trim())
}

/// Looks up the host to connect to before connecting, so a name that
/// doesn't exist fails as soon as DNS says so (with its own message), and a
/// slow DNS server doesn't eat the connection's own timeout. The answer is
/// cached by the system, so the connection's lookup that follows is quick.
/// Returns its addresses, which [`dc_host`] compares with the RootDSE's name.
async fn resolve_dc(job: &Job) -> Result<Vec<std::net::IpAddr>, String> {
    let host = connected_host(job);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = if job.ldaps { 636 } else { 389 };
    match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => {
            let addrs: Vec<_> = addrs.map(|a| a.ip()).collect();
            if addrs.is_empty() {
                Err(format!(
                    "cannot connect to {}: DNS lookup of {host} found no address (no such host)",
                    job.url
                ))
            } else {
                Ok(addrs)
            }
        }
        Ok(Err(e)) => Err(connect_error(
            &job.url,
            job.ldaps,
            &format!("I/O error: {e}"),
        )),
        Err(_) => Err(format!(
            "cannot connect to {}: DNS lookup of {host} got no answer within {} seconds",
            job.url,
            DNS_TIMEOUT.as_secs()
        )),
    }
}

/// RustHound-CE options for a collection written as a zip into `out_dir`.
pub(crate) fn base_options(
    domain: &str,
    out_dir: &std::path::Path,
    method: CollectionMethod,
    dc_fqdn: String,
    ldaps: bool,
) -> Options {
    Options {
        domain: domain.to_string(),
        username: None,
        password: None,
        ldapfqdn: Some(dc_fqdn),
        ip: None,
        port: None,
        name_server: "not set".to_string(),
        path: out_dir.to_string_lossy().into_owned(),
        collection_method: method,
        ldaps,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
    }
}

/// The naming contexts the RootDSE names.
#[derive(Default)]
pub(super) struct NamingContexts {
    /// `defaultNamingContext`: the domain's.
    pub domain: Option<String>,
    /// `configurationNamingContext`.
    pub configuration: Option<String>,
}

/// The DC's `dnsHostName` and the naming contexts, from the RootDSE.
async fn root_dse(ldap: &mut ldap3::Ldap) -> (Option<String>, NamingContexts) {
    let entry = async {
        let (entries, _) = ldap
            .search(
                "",
                LdapScope::Base,
                "(objectClass=*)",
                vec![
                    "dnsHostName",
                    "defaultNamingContext",
                    "configurationNamingContext",
                ],
            )
            .await
            .ok()?
            .success()
            .ok()?;
        Some(SearchEntry::construct(entries.into_iter().next()?))
    }
    .await;
    let attr = |name: &str| {
        entry
            .as_ref()
            .and_then(|e| e.attrs.get(name))
            .and_then(|v| v.first().cloned())
    };
    let contexts = NamingContexts {
        domain: attr("defaultNamingContext"),
        configuration: attr("configurationNamingContext"),
    };
    (attr("dnsHostName"), contexts)
}

/// Where the DC's name for the Kerberos SPN comes from.
#[derive(Debug, PartialEq, Eq)]
enum SpnSource {
    /// The user named the DC by FQDN: use that, whatever the server says.
    Given(String),
    /// The RootDSE's `dnsHostName`, in the domain; it must still resolve to
    /// the address we connected to.
    RootDse(String),
    /// No usable name from the server: the host we connected to.
    Connected(String),
}

/// A DNS name: ASCII letters, digits, `-` and `.`, at least two labels.
fn is_fqdn(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `host` is `domain` or a name under it (ASCII, case-insensitive).
fn in_domain(host: &str, domain: &str) -> bool {
    crate::locate::in_domain(host, domain)
}

/// Decides the SPN host from the request and the RootDSE's `dnsHostName`.
/// `Err` holds a printable reason the RootDSE name was refused.
fn spn_source(
    server: Option<&str>,
    domain: &str,
    root_dse_host: Option<&str>,
) -> Result<SpnSource, String> {
    let server = server.map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = server.filter(|s| is_fqdn(s)) {
        return Ok(SpnSource::Given(s.trim_end_matches('.').to_string()));
    }
    let connected = server.unwrap_or(domain.trim()).to_string();
    let Some(host) = root_dse_host.map(str::trim) else {
        return Ok(SpnSource::Connected(connected));
    };
    if !is_fqdn(host) {
        return Err(format!(
            "the server named itself {:?}, which is not a DNS name",
            host.escape_debug().to_string()
        ));
    }
    if !in_domain(host, domain) {
        return Err(format!(
            "the server named itself {host}, which is outside the domain {}",
            domain.trim()
        ));
    }
    Ok(SpnSource::RootDse(host.trim_end_matches('.').to_string()))
}

/// The DC's FQDN for the bind's SPN and for RustHound-CE. A name the
/// unauthenticated RootDSE gives must be in the domain and resolve to an
/// address of the host we connected to; otherwise Kerberos refuses (pass
/// `--server <DC FQDN>`) and NTLM falls back to the connected host.
async fn dc_host(
    job: &Job,
    ours: &[std::net::IpAddr],
    root_dse_host: Option<&str>,
    kerberos: bool,
    log: &dyn Fn(String),
) -> Result<String, String> {
    let connected = connected_host(job).to_string();
    let refuse = |why: String| -> Result<String, String> {
        if kerberos {
            Err(format!(
                "{why}, so it is not trusted as the Kerberos service name. Name the domain \
                 controller with --server <DC FQDN>"
            ))
        } else {
            log(format!("{why}; using {connected}"));
            Ok(connected.clone())
        }
    };
    match spn_source(job.server.as_deref(), &job.domain, root_dse_host) {
        Ok(SpnSource::Given(h) | SpnSource::Connected(h)) => Ok(h),
        Ok(SpnSource::RootDse(h)) => {
            // `ours` is the lookup made before connecting (resolve_dc).
            let theirs = resolve(&h).await;
            if theirs.iter().any(|ip| ours.contains(ip)) {
                Ok(h)
            } else {
                refuse(format!(
                    "the server named itself {h}, which does not resolve to the address of \
                     {connected}"
                ))
            }
        }
        Err(why) => refuse(why),
    }
}

/// The addresses `host` resolves to (empty if it doesn't within a few
/// seconds).
async fn resolve(host: &str) -> Vec<std::net::IpAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let lookup = tokio::net::lookup_host((host, 0));
    match tokio::time::timeout(Duration::from_secs(5), lookup).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

#[cfg(windows)]
async fn gssapi_bind(ldap: &mut ldap3::Ldap, dc_fqdn: &str) -> Result<(), String> {
    ldap.sasl_gssapi_bind(dc_fqdn)
        .await
        .and_then(|r| r.success())
        .map(|_| ())
        .map_err(|e| {
            format!(
                "Kerberos bind as the current user to ldap/{dc_fqdn} failed: {}. Is this \
                 account in the domain (or a trusted one), and is the DC name right?",
                e.to_string().trim_end()
            )
        })
}

#[cfg(not(windows))]
async fn gssapi_bind(_ldap: &mut ldap3::Ldap, _dc_fqdn: &str) -> Result<(), String> {
    Err("current-user authentication is Windows only".into())
}

fn connect_error(url: &str, ldaps: bool, e: &str) -> String {
    let mut msg = format!("cannot connect to {url}: {}", without_unsupported_names(e));
    if ldaps && (e.contains("certificate") || e.contains("Certificate") || e.contains("TLS")) {
        msg.push_str(
            ". The DC's certificate must chain to a root this computer trusts and name the \
             host you connect to, so give the domain controller's full DNS name as the server. \
             Turning off the certificate check (--insecure-skip-tls-verify, or \"Don't check \
             the certificate\" in the app) gets past this, for test labs only",
        );
    }
    msg
}

/// Drops rustls's `Unsupported(0x..) or ` entries from a name-mismatch
/// error: certificate names it can't show (a DC certificate's directory
/// GUID name), which only make the list of valid names harder to read.
fn without_unsupported_names(e: &str) -> String {
    let mut out = String::with_capacity(e.len());
    let mut rest = e;
    while let Some(i) = rest.find("Unsupported(0x") {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        match after.find(')') {
            Some(j) => {
                rest = &after[j + 1..];
                rest = rest.strip_prefix(" or ").unwrap_or(rest);
            }
            None => {
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Sends RustHound-CE's `log` output to the collection's progress channel.
/// Only `info` and above: the library logs credentials at `debug`.
mod log_bridge {
    use super::*;
    use log::{Level, LevelFilter, Log, Metadata, Record};
    use std::sync::OnceLock;

    static SINK: Mutex<Option<mpsc::Sender<Msg>>> = Mutex::new(None);
    static INSTALLED: OnceLock<bool> = OnceLock::new();

    struct Bridge;
    static BRIDGE: Bridge = Bridge;

    impl Log for Bridge {
        fn enabled(&self, m: &Metadata) -> bool {
            m.level() <= Level::Info || (krb_debug() && is_krb(m.target()))
        }

        fn log(&self, r: &Record) {
            if r.level() <= Level::Warn {
                if let Ok(mut guard) = CAPTURE.lock() {
                    if let Some((target, lines)) = guard.as_mut() {
                        if r.target().starts_with(*target) {
                            let text = strip_ansi(&r.args().to_string());
                            lines.push(crate::redact::log_line(&text).into_owned());
                        }
                    }
                }
            }
            let Some(line) = line_for(r) else { return };
            let Ok(guard) = SINK.lock() else { return };
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(Msg::Log(line));
            }
        }

        fn flush(&self) {}
    }

    /// The line a library record becomes, if it is passed on at all: `info`
    /// and above from RustHound-CE and ldap3, without colors, and with any
    /// password material (RustHound-CE logs readable LAPS passwords at
    /// `info`) taken out. Only the message is used, never key-value fields.
    pub(super) fn line_for(r: &Record) -> Option<String> {
        let target = r.target();
        // Pathwarden's own Kerberos steps (each hop: realm, KDC, ticket and
        // session key types; never a key or ticket), with RUST_LOG=debug.
        if is_krb(target) && krb_debug() && r.level() <= Level::Debug {
            return Some(format!("debug: {}", crate::one_line(&r.args().to_string())));
        }
        if r.level() > Level::Info {
            return None;
        }
        if !(target.starts_with("rusthound_ce") || target.starts_with("ldap3")) {
            return None;
        }
        let text = crate::one_line(&strip_ansi(&r.args().to_string()));
        if target.starts_with("ldap3") && is_abandoned_reply(&text) {
            return None;
        }
        if target.starts_with("ldap3") && is_socket_error(&text) {
            // The end of a connection being closed: nothing to say.
            if CLOSING.load(Ordering::SeqCst) > 0 {
                return None;
            }
            // Otherwise the search on it (if any) fails with its own
            // error, so this is no warning of its own: shown with -v.
            if is_reset(&text) {
                return Some(format!(
                    "[ldap] the domain controller closed a connection ({})",
                    crate::redact::log_line(&text)
                ));
            }
        }
        let text = crate::redact::log_line(&text).into_owned();
        Some(match r.level() {
            Level::Error => format!("error: {text}"),
            Level::Warn => format!("warning: {text}"),
            _ => text,
        })
    }

    /// ldap3's words for a reply to a search nobody reads any more. The
    /// sizing count (`size_directory`) is dropped when the read ends first;
    /// the rest of its current page (up to a thousand entries) then arrives
    /// for a dropped search, and ldap3 warns once per entry. Expected, and
    /// it buried the real warnings of a collection under hundreds of lines.
    fn is_abandoned_reply(text: &str) -> bool {
        text.starts_with("unmatched id: ") || text.starts_with("ldap search item send error")
    }

    /// ldap3's connection driver's words for a socket that failed.
    fn is_socket_error(text: &str) -> bool {
        [
            "socket receive error",
            "socket shutdown error",
            "socket close error",
        ]
        .iter()
        .any(|w| text.starts_with(w))
    }

    /// A connection the other end reset or closed: WSAECONNRESET (10054),
    /// WSAECONNABORTED (10053), ECONNRESET, a broken pipe.
    fn is_reset(text: &str) -> bool {
        let t = text.to_ascii_lowercase();
        [
            "(os error 10054)",
            "(os error 10053)",
            "(os error 104)",
            "(os error 32)",
        ]
        .iter()
        .any(|w| t.contains(w))
            || t.contains("forcibly closed")
            || t.contains("connection reset")
            || t.contains("broken pipe")
    }

    /// Warnings and errors of the targets starting with `target`, kept from
    /// [`start_capture`] to [`take_capture`] (alongside the usual output).
    static CAPTURE: Mutex<Option<(&'static str, Vec<String>)>> = Mutex::new(None);

    /// Starts keeping the warnings and errors logged by `target`.
    pub(super) fn start_capture(target: &'static str) {
        if let Ok(mut guard) = CAPTURE.lock() {
            *guard = Some((target, Vec::new()));
        }
    }

    /// What was kept since [`start_capture`], or `None` if nothing could be
    /// (the bridge is not the process logger).
    pub(super) fn take_capture() -> Option<Vec<String>> {
        let kept = CAPTURE.lock().ok()?.take().map(|(_, lines)| lines);
        if INSTALLED.get().copied() == Some(true) {
            kept
        } else {
            None
        }
    }

    /// Pathwarden's Kerberos modules (`builtin::krb`, `krbref`, ...).
    fn is_krb(target: &str) -> bool {
        target.starts_with("pathwarden_collect::builtin::krb")
    }

    /// Whether RUST_LOG asks for debug output: then Pathwarden's Kerberos
    /// steps are logged (RustHound-CE's debug output never is: it holds
    /// credentials).
    pub(super) fn krb_debug() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| {
            std::env::var("RUST_LOG").is_ok_and(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("debug") || v.contains("trace")
            })
        })
    }

    /// Installs the bridge as the process logger, once. False if another
    /// logger was already installed.
    pub(super) fn install() -> bool {
        *INSTALLED.get_or_init(|| {
            let ok = log::set_logger(&BRIDGE).is_ok();
            if ok {
                log::set_max_level(if krb_debug() {
                    LevelFilter::Debug
                } else {
                    LevelFilter::Info
                });
            }
            ok
        })
    }

    pub(super) fn set_sink(tx: Option<mpsc::Sender<Msg>>) {
        if let Ok(mut guard) = SINK.lock() {
            *guard = tx;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_req() -> CollectRequest {
        let mut r = CollectRequest::new("contoso.local", "out");
        r.auth = Auth::Password {
            user: "svc".into(),
            password: Secret::new("x"),
        };
        r
    }

    #[test]
    fn password_requires_ldaps_unless_allowed() {
        let mut r = password_req();
        let err = plan(&r).err().expect("refused").to_string();
        assert!(err.contains("--ldaps"), "{err}");
        r.allow_unencrypted_ldap = true;
        let p = plan(&r).unwrap();
        assert!(p.warnings.iter().any(|w| w.contains("plain LDAP")));
        r.allow_unencrypted_ldap = false;
        r.ldaps = true;
        let p = plan(&r).unwrap();
        assert_eq!(p.method, CollectionMethod::DCOnly);
        r.scope = Scope::All;
        assert_eq!(plan(&r).unwrap().method, CollectionMethod::All);
    }

    /// LDAPS with plain LDAP allowed is planned as LDAPS: no plain LDAP
    /// warning until a domain controller actually falls back.
    #[test]
    fn ldaps_with_plain_allowed_plans_as_ldaps() {
        let mut r = password_req();
        r.ldaps = true;
        r.allow_unencrypted_ldap = true;
        let p = plan(&r).unwrap();
        assert!(
            !p.warnings.iter().any(|w| w.contains("plain LDAP")),
            "{:?}",
            p.warnings
        );
        assert!(falls_back(&r));
        r.allow_unencrypted_ldap = false;
        assert!(!falls_back(&r));
        // Plain LDAP only, or as the Windows account: nothing to fall back from.
        r.allow_unencrypted_ldap = true;
        r.ldaps = false;
        assert!(!falls_back(&r));
        let mut me = CollectRequest::new("contoso.local", "out");
        me.ldaps = true;
        me.allow_unencrypted_ldap = true;
        assert!(!falls_back(&me));
    }

    /// Runs [`fall_back`] on `job` with LDAPS's result `tried` (`None`: it
    /// must not be tried at all). The warning and the log.
    fn falls_back_with(
        job: &mut Job,
        tried: Option<Result<(), String>>,
    ) -> (Option<String>, Vec<String>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let log = std::cell::RefCell::new(Vec::new());
        let w = rt.block_on(fall_back(
            job,
            |url: String, _skip: bool| async move {
                assert!(url.starts_with("ldaps://"), "{url}");
                tried.expect("LDAPS must not be tried")
            },
            true,
            &|l| log.borrow_mut().push(l),
        ));
        (w, log.into_inner())
    }

    /// LDAPS that works stays LDAPS; LDAPS that fails, with plain LDAP
    /// allowed, switches the job to plain LDAP on the same host with a
    /// warning naming it and why; without plain LDAP allowed nothing is
    /// tried and the job stays LDAPS (its connection fails as before);
    /// plain LDAP only tries no LDAPS.
    #[test]
    fn ldaps_falls_back_only_when_allowed() {
        let mut req = password_req();
        req.ldaps = true;
        req.allow_unencrypted_ldap = true;
        req.server = Some("DC01.CONTOSO.LOCAL".into());
        let method = CollectionMethod::DCOnly;

        let mut job = job_for(&req, method.clone()).unwrap();
        assert_eq!(falls_back_with(&mut job, Some(Ok(()))).0, None);
        assert!(job.ldaps);
        assert_eq!(job.url, "ldaps://DC01.CONTOSO.LOCAL:636");

        let mut job = job_for(&req, method.clone()).unwrap();
        let (w, log) = falls_back_with(
            &mut job,
            Some(Err(
                "rustls error: invalid peer certificate: UnknownIssuer".into()
            )),
        );
        assert_eq!(
            w.as_deref(),
            Some(
                "LDAPS failed on DC01.CONTOSO.LOCAL (the certificate isn't trusted), so it was \
                 read over plain LDAP, unencrypted."
            )
        );
        assert!(!job.ldaps);
        assert_eq!(job.url, "ldap://DC01.CONTOSO.LOCAL:389");
        assert!(log[0].contains("UnknownIssuer"), "{log:?}");
        // Every later connection is plain: the readers' too.
        let c = Connector::of(&job, "dc01.contoso.local");
        assert_eq!(
            (c.url.as_str(), c.ldaps),
            ("ldap://DC01.CONTOSO.LOCAL:389", false)
        );
        // Plain LDAP failing too says both, and keeps its own reason.
        let e = with_ldaps_failure(
            &job,
            "cannot connect to ldap://DC01.CONTOSO.LOCAL:389: connection refused (os error 10061)"
                .into(),
        );
        assert!(
            e.ends_with("LDAPS had failed first: the certificate isn't trusted"),
            "{e}"
        );
        assert_eq!(crate::Problem::classify(&e), crate::Problem::Refused);
        // The check's words.
        assert!(fell_back_warning("DC01.CONTOSO.LOCAL", "x", false).contains("will be read"));

        // Not allowed: nothing tried, LDAPS as before.
        req.allow_unencrypted_ldap = false;
        let mut job = job_for(&req, method.clone()).unwrap();
        assert_eq!(falls_back_with(&mut job, None).0, None);
        assert!(job.ldaps);
        assert_eq!(with_ldaps_failure(&job, "e".into()), "e");

        // Plain LDAP only: no LDAPS tried, no warning.
        req.allow_unencrypted_ldap = true;
        req.ldaps = false;
        let mut job = job_for(&req, method).unwrap();
        assert_eq!(falls_back_with(&mut job, None).0, None);
        assert_eq!(job.url, "ldap://DC01.CONTOSO.LOCAL:389");
    }

    /// A domain controller read over plain LDAP after its LDAPS failed:
    /// the certificate warning goes, the fallback's is said.
    #[test]
    fn a_fallback_drops_the_certificate_warning() {
        let mut r = password_req();
        r.ldaps = true;
        r.allow_unencrypted_ldap = true;
        r.insecure_skip_tls_verify = true;
        let mut warnings = plan(&r).unwrap().warnings;
        assert!(warnings.iter().any(|w| w == UNCHECKED_CERTIFICATES));
        let before = warnings.len();
        fell_back_in(
            &mut warnings,
            fell_back_warning("dc01.contoso.local", "x", true),
        );
        assert!(!warnings.iter().any(|w| w == UNCHECKED_CERTIFICATES));
        assert_eq!(warnings.len(), before);
        assert!(warnings
            .last()
            .unwrap()
            .starts_with("LDAPS failed on dc01.contoso.local"));
    }

    /// LDAPS's errors in a few plain words.
    #[test]
    fn ldaps_failures_in_plain_words() {
        for (e, want) in [
            (
                "invalid peer certificate: UnknownIssuer",
                "the certificate isn't trusted",
            ),
            (
                "invalid peer certificate: certificate not valid for name \"x\"",
                "the certificate doesn't match its name",
            ),
            (
                "invalid peer certificate: certificate expired",
                "the certificate has expired or isn't valid yet",
            ),
            (
                "received fatal alert: HandshakeFailure (tls)",
                "the encrypted connection couldn't be set up",
            ),
            (
                "I/O error: connection refused (os error 10061)",
                "nothing answered on port 636",
            ),
            (
                "timeout: no answer within 10 seconds",
                "no answer on port 636 in time",
            ),
            ("something else", "the connection didn't work"),
        ] {
            assert_eq!(ldaps_failure_words(e), want, "{e}");
        }
    }

    /// A trusted domain whose domain controllers answer on 389 only, with
    /// plain LDAP allowed: one is found there and read over plain LDAP, the
    /// warning said without trying LDAPS on it. Not allowed: none found,
    /// as before.
    #[test]
    fn a_dc_found_on_389_only_falls_back() {
        let mut req = password_req();
        req.domain = "north.lab".into();
        req.ldaps = true;
        req.allow_unencrypted_ldap = true;
        req.locate_dc = true;
        let asked = std::cell::RefCell::new(Vec::new());
        let mut find = |d: &str, port: u16, _: &mut dyn FnMut(String)| {
            asked.borrow_mut().push(port);
            if port == 389 {
                Ok("dc02.north.lab".to_string())
            } else {
                Err(crate::locate::NotFound {
                    why: format!("dc02.{d} (from DNS) didn't answer on port {port}"),
                    found: true,
                    outside: false,
                })
            }
        };
        let mut job = job_for(&req, CollectionMethod::DCOnly).unwrap();
        assert_eq!(pick_dc(&mut job, &req, &mut find, &mut |_| {}), None);
        assert_eq!(*asked.borrow(), [636, 389]);
        assert_eq!(job.url, "ldap://dc02.north.lab:389");
        assert_eq!(job.server.as_deref(), Some("dc02.north.lab"));
        let (w, _) = falls_back_with(&mut job, None);
        assert_eq!(
            w.as_deref(),
            Some(
                "LDAPS failed on dc02.north.lab (nothing answered on port 636), so it was read \
                 over plain LDAP, unencrypted."
            )
        );

        asked.borrow_mut().clear();
        req.allow_unencrypted_ldap = false;
        let mut job = job_for(&req, CollectionMethod::DCOnly).unwrap();
        assert!(pick_dc(&mut job, &req, &mut find, &mut |_| {}).is_some());
        assert_eq!(*asked.borrow(), [636]);
        assert_eq!(job.url, "ldaps://north.lab:636");
    }

    #[test]
    fn current_user_is_dc_only() {
        let mut r = CollectRequest::new("contoso.local", "out");
        if cfg!(windows) {
            assert_eq!(plan(&r).unwrap().method, CollectionMethod::LdapOnly);
            r.scope = Scope::All;
            assert!(plan(&r).is_err());
        } else {
            assert!(plan(&r).is_err());
        }
    }

    #[test]
    fn urls_and_users() {
        let mut r = CollectRequest::new("contoso.local", "out");
        assert_eq!(ldap_url(&r), "ldap://contoso.local:389");
        r.server = Some("dc01.contoso.local".into());
        r.ldaps = true;
        assert_eq!(ldap_url(&r), "ldaps://dc01.contoso.local:636");
        assert_eq!(qualified_user("svc", "contoso.local"), "svc@contoso.local");
        assert_eq!(
            qualified_user("CONTOSO\\svc", "contoso.local"),
            "CONTOSO\\svc"
        );
    }

    /// The user and domain fields of the NTLM AUTHENTICATE message for a
    /// `sasl_ntlm_bind` user name, as ldap3 builds them (sspi's
    /// `Username::parse`, then `AuthIdentityBuffers::from`).
    fn ntlm_fields(bind: &str) -> (String, String) {
        let identity = sspi::AuthIdentity {
            username: sspi::Username::parse(bind).unwrap(),
            password: String::from("x").into(),
        };
        let buffers = sspi::AuthIdentityBuffers::from(identity);
        let text = |b: &[u8]| {
            let (pairs, rest) = b.as_chunks::<2>();
            assert!(rest.is_empty());
            let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16(&units).unwrap()
        };
        (text(&buffers.user), text(&buffers.domain))
    }

    #[test]
    fn ntlm_bind_sends_a_upn_whole_with_no_domain() {
        let f = |user: &str, domain: &str| ntlm_fields(&ntlm_bind_name(user, domain).unwrap());
        let s = |u: &str, d: &str| (u.to_string(), d.to_string());
        // A UPN, whatever its suffix: whole, empty domain, as Windows sends it.
        assert_eq!(
            f("samwell.tarly@example.com", "sevenkingdoms.local"),
            s("samwell.tarly@example.com", "")
        );
        assert_eq!(
            f(
                " samwell.tarly@north.sevenkingdoms.local ",
                "north.sevenkingdoms.local"
            ),
            s("samwell.tarly@north.sevenkingdoms.local", "")
        );
        // DOMAIN\user and a bare name: as before.
        assert_eq!(
            f(r"NORTH\samwell.tarly", "sevenkingdoms.local"),
            s("samwell.tarly", "NORTH")
        );
        assert_eq!(f("svc", "contoso.local"), s("svc", "contoso.local"));
        assert_eq!(
            ntlm_bind_name("svc", "contoso.local").as_deref(),
            Ok("svc@contoso.local")
        );
        assert_eq!(
            ntlm_bind_name(r"CONTOSO\svc", "x").as_deref(),
            Ok(r"CONTOSO\svc")
        );
        // An account name may itself contain @: sent whole.
        assert_eq!(f("a@b@example.com", "x"), s("a@b@example.com", ""));
        // What a UPN gave before: split at the @, which only works when the
        // suffix happens to be the account's domain.
        assert_eq!(
            ntlm_fields("samwell.tarly@example.com"),
            s("samwell.tarly", "example.com")
        );
    }

    #[test]
    fn malformed_bind_names_are_refused_in_plain_words() {
        for (user, domain, says) in [
            (r"NORTH\samwell@example.com", "north.local", "mixes"),
            (r"A\B\svc", "north.local", "more than one"),
            (r"\svc", "north.local", "empty part"),
            (r"NORTH\", "north.local", "empty part"),
            (r"NORTH\ ", "north.local", "empty part"),
            ("@example.com", "north.local", "empty part"),
            ("svc@", "north.local", "empty part"),
            ("svc@ ", "north.local", "empty part"),
            ("", "north.local", "empty"),
            ("  ", "north.local", "empty"),
            ("svc", r"NORTH\x", "not a DNS name"),
            ("svc", "a@north.local", "not a DNS name"),
            ("svc", " ", "not a DNS name"),
        ] {
            let e = ntlm_bind_name(user, domain).unwrap_err();
            assert!(e.contains(says), "{user:?} {domain:?}: {e}");
        }
        // Whatever passes, sspi parses (ldap3 unwraps it).
        for (user, domain) in [
            ("svc", "contoso.local"),
            (r"CONTOSO\svc", "contoso.local"),
            ("svc@contoso.local", "contoso.local"),
            ("a@b@example.com", "contoso.local"),
        ] {
            let bind = ntlm_bind_name(user, domain).unwrap();
            assert!(sspi::Username::parse(&bind).is_ok(), "{bind}");
        }
        // A malformed name reaches no DC: the check refuses it as a setting.
        let mut req = CollectRequest::new("contoso.local", "out");
        req.auth = Auth::Password {
            user: r"CONTOSO\svc@contoso.local".into(),
            password: Secret::new("x"),
        };
        req.ldaps = true;
        let e = check(&req, &crate::RunSignIn::default()).unwrap_err();
        assert_eq!(e.problem, crate::Problem::Settings);
        assert!(e.detail.contains("mixes"), "{}", e.detail);
    }

    /// Kerberos only with an account from another domain: on
    /// its own, with a domain the directory doesn't name, refused before
    /// anything is collected or asked; as a trusted domain
    /// of a run whose first domain gave the account's ticket, read with that
    /// ticket through the trust, the password taken out of the modules'
    /// options all the same.
    #[test]
    fn a_trusted_domain_uses_the_first_domains_ticket() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut req = CollectRequest::new("fabrikam.com", "out");
        req.auth = Auth::Password {
            user: r"CONTOSO\svc".into(),
            password: Secret::new("Pw-Trust-1"),
        };
        req.ldaps = true;
        req.scope = Scope::All;
        let options = || {
            let mut o = base_options(
                "fabrikam.com",
                std::path::Path::new("out"),
                CollectionMethod::All,
                "dc01.fabrikam.com".into(),
                true,
            );
            o.username = Some(r"CONTOSO\svc".into());
            o.password = Some("Pw-Trust-1".into());
            o
        };
        let identity = || hosts::SmbIdentity {
            domain: "CONTOSO".into(),
            other_domain: true,
            kerberos: None,
        };
        // Alone, its domain not found in the directory: refused.
        let job = job_for(&req, CollectionMethod::All).unwrap();
        let (mut smb, mut o) = (identity(), options());
        let e = rt
            .block_on(kerberos_hosts(
                &job,
                "dc01.fabrikam.com",
                None,
                Ok(None),
                &mut smb,
                &mut o,
                &|_| {},
            ))
            .err()
            .expect("refused");
        assert!(
            e.message()
                .contains("the account's domain (CONTOSO) isn't in fabrikam.com's forest"),
            "{}",
            e.message()
        );
        drop(job);

        // In a run: the first domain's ticket.
        let parent = std::env::temp_dir().join(format!("pw-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let sign_in = crate::RunSignIn::several();
        sign_in.keep(HomeTicket {
            cache: krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap(),
            kdc: "dc01.contoso.local".into(),
            realm: "CONTOSO.LOCAL".into(),
            who: r"CONTOSO\svc".into(),
        });
        let mut job = job_for(&req, CollectionMethod::All).unwrap();
        job.sign_in = sign_in.clone();
        let (mut smb, mut o) = (identity(), options());
        let lines = Mutex::new(Vec::new());
        let _env = KRB_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let guard = rt
            .block_on(kerberos_hosts(
                &job,
                "dc01.fabrikam.com",
                None,
                Ok(None),
                &mut smb,
                &mut o,
                &|l| lines.lock().unwrap().push(l),
            ))
            .expect("the first domain's ticket");
        let k = smb.kerberos.clone().expect("Kerberos only");
        assert_eq!(
            k.kdc, "dc01.contoso.local",
            "the account's own domain's controller"
        );
        assert_eq!(std::env::var("KRB5CCNAME").ok(), Some(k.ccache.clone()));
        assert!(
            o.kerberos && o.password.is_none(),
            "no password for the modules"
        );
        assert!(
            lines.lock().unwrap()[0].contains("used through the trust to fabrikam.com"),
            "{:?}",
            lines.lock().unwrap()
        );
        drop(guard);
        drop(job);
        // The run still holds it until it ends.
        let file = k.ccache.trim_start_matches("FILE:").to_string();
        assert!(std::path::Path::new(&file).is_file());
        drop(sign_in);
        assert!(
            !std::path::Path::new(&file).exists(),
            "deleted with the run"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// An account whose domain is not the collected one: the collected
    /// domain's controller is asked no ticket; when the
    /// directory doesn't name the account's domain, the check and the
    /// collection say so.
    #[test]
    fn the_check_asks_a_ticket_only_of_the_accounts_own_domain() {
        let foreign = hosts::smb_account(
            r"NORTH\svc",
            Some(r"u:NORTH\svc"),
            "essos.local",
            Some("ESSOS"),
        );
        assert!(foreign.identity.other_domain);
        let own = hosts::smb_account(
            r"NORTH\svc",
            Some(r"u:NORTH\svc"),
            "north.contoso.local",
            Some("NORTH"),
        );
        assert!(!own.identity.other_domain);
        let e = ownrealm::account_domain_unknown(&foreign.identity.domain, "essos.local");
        assert_eq!(e.problem, crate::Problem::NoTicket);
        assert_eq!(
            e.message(),
            "Kerberos didn't work: the account's domain (NORTH) isn't in essos.local's forest \
             or its trusts, so its domain controller can't be found. Accounts from a child \
             domain of a trusted forest aren't supported yet. Use an account from essos.local."
        );
    }

    /// A trusted domain's check: no ticket through the trust is a
    /// warning that its computers will be skipped, not a failed check.
    #[test]
    fn the_check_says_when_the_trust_lets_no_ticket_through() {
        let rc4 = krb::NoTicket::Rc4Trust("between contoso.local and fabrikam.com".into());
        assert_eq!(
            through_the_trust("fabrikam.com", &rc4),
            "The trust to fabrikam.com allows only RC4, so its computers will be skipped. Set \
             the trust to use AES."
        );
        let other = krb::NoTicket::Refused("Kerberos: no answer from fabrikam.com:88".into());
        assert_eq!(
            through_the_trust("fabrikam.com", &other),
            "Kerberos through the trust to fabrikam.com didn't work, so its computers will be \
             skipped: Kerberos: no answer from fabrikam.com:88."
        );
    }

    #[test]
    fn a_refused_upn_hints_at_external_trusts() {
        let refused = "LDAP operation result: rc=49 (invalidCredentials), dn: \"\", text: \
                       \"80090308: LdapErr: DSID-0C09041C, data 52e, v4563\"";
        let hint = "If the account is from an externally trusted domain, give it as DOMAIN\\user.";
        let e = bind_failed("alice@trusted.local", "alice@trusted.local@", refused);
        assert!(e.starts_with("NTLM bind as alice@trusted.local failed: LDAP operation"));
        assert!(e.ends_with(hint), "{e}");
        assert_eq!(crate::Problem::classify(&e), crate::Problem::Credentials);
        // Not for DOMAIN\user or a bare name, nor for other failures.
        for (user, bind) in [
            (r"TRUSTED\alice", r"TRUSTED\alice"),
            ("svc@contoso.local", "svc@contoso.local"),
        ] {
            assert!(!bind_failed(user, bind, refused).contains(hint));
        }
        assert!(!bind_failed("a@b.c", "a@b.c@", "rc=8 (strongerAuthRequired)").contains(hint));
    }

    #[test]
    fn spn_host_is_not_taken_blindly_from_the_root_dse() {
        let dse = |s: Option<&str>, h: Option<&str>| spn_source(s, "contoso.local", h);
        // An FQDN the user gave wins over whatever the server says.
        assert_eq!(
            dse(Some("dc01.contoso.local"), Some("evil.attacker.net")),
            Ok(SpnSource::Given("dc01.contoso.local".into()))
        );
        // Otherwise the RootDSE name must be a DNS name in the domain.
        assert_eq!(
            dse(None, Some("DC02.Contoso.Local")),
            Ok(SpnSource::RootDse("DC02.Contoso.Local".into()))
        );
        assert_eq!(
            dse(Some("10.0.0.5"), Some("dc02.child.contoso.local")),
            Ok(SpnSource::RootDse("dc02.child.contoso.local".into()))
        );
        assert!(dse(None, Some("dc.evilcontoso.local")).is_err());
        assert!(dse(None, Some("evil.attacker.net")).is_err());
        assert!(dse(None, Some("dc01")).is_err());
        let err = dse(None, Some("dc\u{1b}[2K.contoso.local")).unwrap_err();
        assert!(!err.contains('\u{1b}'), "{err}");
        // No name from the server: the host connected to.
        assert_eq!(
            dse(Some("10.0.0.5"), None),
            Ok(SpnSource::Connected("10.0.0.5".into()))
        );
        assert_eq!(
            dse(None, None),
            Ok(SpnSource::Connected("contoso.local".into()))
        );
    }

    #[test]
    fn spn_host_must_resolve_to_the_connected_address() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut req = CollectRequest::new("pathwarden.invalid", "out");
        req.server = Some("127.0.0.1".into());
        let job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        // In the domain, but resolves elsewhere (nowhere): refused for
        // Kerberos, the connected host for NTLM.
        let host = Some("dc.pathwarden.invalid");
        let ours = rt.block_on(resolve_dc(&job)).unwrap();
        assert_eq!(ours, [std::net::IpAddr::from([127, 0, 0, 1])]);
        let kerb = rt.block_on(dc_host(&job, &ours, host, true, &|_| {}));
        assert!(kerb.unwrap_err().contains("--server"));
        let ntlm = rt.block_on(dc_host(&job, &ours, host, false, &|_| {}));
        assert_eq!(ntlm.unwrap(), "127.0.0.1");
    }

    #[test]
    fn steps_follow_the_method() {
        let keys = |m| steps(&m).iter().map(|s| s.key).collect::<Vec<_>>();
        if cfg!(windows) {
            assert_eq!(
                keys(CollectionMethod::LdapOnly),
                ["connect", "read", "parse", "resolve", "modules", "write"]
            );
        } else {
            assert_eq!(
                keys(CollectionMethod::LdapOnly),
                ["connect", "read", "parse", "resolve", "write"]
            );
        }
        assert_eq!(
            keys(CollectionMethod::All),
            ["connect", "read", "parse", "resolve", "modules", "write"]
        );
        assert!(steps(&CollectionMethod::DCOnly)[4].label.contains("SYSVOL"));
    }

    /// The SYSVOL step's progress, sent from the blocking thread
    /// that reads SYSVOL (here a fake reader, no network), reaches the
    /// tracker through the message pump: units, the detail line, the unit,
    /// and the step's new weight.
    #[test]
    fn sysvol_units_from_a_worker_thread_reach_the_tracker() {
        let mut statuses = Vec::new();
        let mut sink = |p: crate::Progress| {
            if let crate::Progress::Status(s) = p {
                statuses.push(*s);
            }
        };
        let mut rep = Reporter::new(steps(&CollectionMethod::DCOnly), &mut sink);
        let mut expected = None;
        for key in ["read", "parse", "resolve"] {
            apply(&mut rep, Msg::Step(key), &mut expected);
        }
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(Msg::Weight("modules", 200.0));
        let _ = tx.send(Msg::Step("modules"));
        let reader = std::thread::spawn(move || {
            let mut progress = sysvol::SysvolProgress::new(tx, 40, 0, true);
            progress.start();
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(1));
                progress.gpo_done();
            }
            progress.finish();
        });
        // The pump, as in `run`, until the reader's sender is gone.
        while let Ok(msg) = rx.recv_timeout(Duration::from_secs(10)) {
            apply(&mut rep, msg, &mut expected);
        }
        reader.join().unwrap();
        rep.emit();
        drop(rep);
        let last = statuses.last().unwrap();
        assert_eq!(last.key, "modules");
        assert_eq!((last.done, last.total), (40, Some(40)));
        assert_eq!(last.unit, "items");
        assert_eq!(last.detail.as_deref(), Some("GPO 40 of 40"));
        // The bar didn't jump back when the step got heavier (84% at the
        // start of resolving, a little more past it), and the step is now
        // most of what was left: its 99% (the cap) moves the bar most of
        // the way.
        let entered = statuses.iter().find(|s| s.key == "modules").unwrap();
        assert!(
            (84.0..=85.0).contains(&entered.percent),
            "{}",
            entered.percent
        );
        assert!(last.percent > 96.0, "{}", last.percent);
    }

    #[test]
    fn new_connections_must_reach_the_reads_domain_controller() {
        let c = |dc: &str| Connector {
            url: format!("ldaps://{dc}:636"),
            ldaps: true,
            skip_verify: false,
            dc_fqdn: dc.into(),
            auth: ConnectAuth::CurrentUser,
            pinned: Mutex::new(String::new()),
            pinned_host: Mutex::new(String::new()),
        };
        const DS: &str =
            "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=x";
        const DS2: &str =
            "CN=NTDS Settings,CN=DC02,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=x";
        // With the snapshot's dsServiceName: only that controller.
        let pinned = c("dc01.contoso.local");
        pinned.pin(DS, Some("dc01.contoso.local"));
        assert_eq!(pinned.elsewhere(Some(DS), Some("dc01.contoso.local")), None);
        assert_eq!(
            pinned.elsewhere(Some(&DS.to_lowercase()), Some("x")),
            None,
            "case-insensitive"
        );
        let e = pinned
            .elsewhere(Some(DS2), Some("dc02.contoso.local"))
            .unwrap();
        assert!(
            e.contains("reached dc02.contoso.local, not dc01.contoso.local"),
            "{e}"
        );
        assert!(pinned.elsewhere(None, None).is_some());
        // No snapshot, a server named by its address: the first connection's
        // RootDSE name.
        let by_ip = c("10.0.0.5");
        by_ip.pin("", Some("dc01.contoso.local."));
        assert_eq!(by_ip.elsewhere(None, Some("DC01.contoso.local")), None);
        assert!(by_ip
            .elsewhere(None, Some("dc02.contoso.local"))
            .unwrap()
            .contains("not dc01.contoso.local"));
        // Nothing known about the first one, an address: nothing to check.
        let bare = c("10.0.0.5");
        assert_eq!(bare.elsewhere(None, Some("dc02.contoso.local")), None);
        // Nothing pinned but a name: the name.
        let named = c("dc01.contoso.local");
        assert!(named.elsewhere(None, Some("dc02.contoso.local")).is_some());
        // The password's copy goes when the read ends.
        let ntlm = Connector {
            auth: ConnectAuth::Ntlm {
                user: "CONTOSO\\svc".into(),
                bind: "svc@contoso.local".into(),
                password: Mutex::new(Some(Secret::new("pw"))),
            },
            ..c("dc01.contoso.local")
        };
        ntlm.forget();
        let ConnectAuth::Ntlm { password, .. } = &ntlm.auth else {
            panic!()
        };
        assert!(password.lock().unwrap().is_none());
    }

    #[test]
    fn ranges_and_kinds() {
        assert_eq!(range_high("member;range=0-1499"), Some(1499));
        assert_eq!(range_high("member;Range=1500-*"), None);
        assert_eq!(range_high("member"), None);
        let mut e = SearchEntry {
            dn: "CN=x".into(),
            attrs: Default::default(),
            bin_attrs: Default::default(),
        };
        e.attrs.insert(
            "objectClass".into(),
            vec!["top".into(), "person".into(), "user".into()],
        );
        assert_eq!(kind_of(&e), "users");
        e.attrs.insert(
            "objectClass".into(),
            vec![
                "top".into(),
                "person".into(),
                "user".into(),
                "computer".into(),
            ],
        );
        assert_eq!(kind_of(&e), "computers");
        e.attrs
            .insert("objectClass".into(), vec!["top".into(), "dnsNode".into()]);
        assert_eq!(kind_of(&e), "other");
    }

    /// Lab item 88: the domain controller resetting a connection Pathwarden
    /// is closing is no warning; a reset at another time is a plain line
    /// (shown with -v), and other socket errors stay warnings.
    #[test]
    fn a_connection_closed_normally_is_no_warning() {
        use log::{Level, Record};
        let line = |text: &str| {
            log_bridge::line_for(
                &Record::builder()
                    .level(Level::Warn)
                    .target("ldap3::conn")
                    .args(format_args!("{text}"))
                    .build(),
            )
        };
        let reset = "socket receive error: An existing connection was forcibly closed by the \
                     remote host. (os error 10054)";
        CLOSING.fetch_add(1, Ordering::SeqCst);
        let closing = line(reset);
        CLOSING.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(closing, None);
        let other = line(reset).unwrap();
        assert!(
            other.starts_with("[ldap] the domain controller closed a connection (socket receive"),
            "{other}"
        );
        assert_eq!(
            line("socket receive error: invalid data").as_deref(),
            Some("warning: socket receive error: invalid data")
        );
    }

    /// RustHound-CE's LAPS lines (`objects/computer.rs`, colored as it logs
    /// them) never reach the job log with the password; debug records and
    /// other crates' records are dropped as before.
    #[test]
    fn log_bridge_hides_laps_passwords() {
        use log::{Level, Record};
        let secret = "Pa55-LAPS-Value!";
        let line = |level: Level, target: &str, args: std::fmt::Arguments| {
            log_bridge::line_for(
                &Record::builder()
                    .level(level)
                    .target(target)
                    .args(args)
                    .build(),
            )
        };
        let name = "\u{1b}[1;33mWS01\u{1b}[0m";
        let value = format!("\u{1b}[1;33m{secret}\u{1b}[0m");
        let legacy = line(
            Level::Info,
            "rusthound_ce::objects::computer",
            format_args!("Your user can read LAPS password on {}: {}", name, value),
        )
        .unwrap();
        assert!(!legacy.contains(secret), "{legacy}");
        assert!(
            legacy.contains("password of WS01 (the password is not shown)"),
            "{legacy}"
        );
        let windows_laps = line(
            Level::Info,
            "rusthound_ce::objects::computer",
            format_args!(
                "Your user can read LAPS password on {}: {:?}",
                name,
                format!("{{\"n\":\"Administrator\",\"p\":\"{secret}\"}}")
            ),
        )
        .unwrap();
        assert!(!windows_laps.contains(secret), "{windows_laps}");
        let warned = line(
            Level::Warn,
            "rusthound_ce::modules::gpo::sysvol",
            format_args!("[gpo] cpassword {secret}"),
        )
        .unwrap();
        assert!(
            warned.starts_with("warning: ") && !warned.contains(secret),
            "{warned}"
        );
        // Upstream's padded SAMR message is one tidy line.
        assert_eq!(
            line(
                Level::Warn,
                "rusthound_ce::modules::localgroup",
                format_args!("WS01 SamrConnect2:                         rc=5\n  denied")
            )
            .as_deref(),
            Some("warning: WS01 SamrConnect2: rc=5 denied")
        );
        assert_eq!(
            line(
                Level::Debug,
                "rusthound_ce::transport::ldap",
                format_args!("Password: {secret}")
            ),
            None
        );
        assert_eq!(
            line(Level::Info, "other_crate", format_args!("hello")),
            None
        );
        assert_eq!(
            line(
                Level::Info,
                "rusthound_ce::api",
                format_args!("Starting the LDAP objects parsing...")
            )
            .as_deref(),
            Some("Starting the LDAP objects parsing...")
        );
        // Replies to the dropped sizing count: hundreds of these in the
        // GOAD essos.local run. Other ldap3 warnings still show.
        for noise in [
            "unmatched id: 20",
            "ldap search item send error, op=20: SendError { .. }",
        ] {
            assert_eq!(
                line(Level::Warn, "ldap3::conn", format_args!("{noise}")),
                None
            );
        }
        assert_eq!(
            line(
                Level::Warn,
                "ldap3::conn",
                format_args!("socket send error: x")
            )
            .as_deref(),
            Some("warning: socket send error: x")
        );
    }

    /// The sessions module's per-computer errors are kept for `hosts`,
    /// and only that module's.
    #[test]
    fn log_bridge_keeps_the_sessions_errors() {
        assert!(log_bridge::install());
        log_bridge::start_capture(hosts::SESSIONS_LOG_TARGET);
        log::warn!(target: "rusthound_ce::modules::session", "WS1.X.LOCAL: 445/tcp unreachable");
        log::info!(target: "rusthound_ce::modules::session", "[sessions] 1 active target(s)");
        log::warn!(target: "rusthound_ce::modules::localgroup", "WS1.X.LOCAL: auth: x");
        assert_eq!(
            log_bridge::take_capture(),
            Some(vec!["WS1.X.LOCAL: 445/tcp unreachable".to_string()])
        );
        // Nothing kept once taken.
        log::warn!(target: "rusthound_ce::modules::session", "WS2.X.LOCAL: auth: x");
        assert_eq!(log_bridge::take_capture(), None);
    }

    #[test]
    fn dns_partitions_and_kinds() {
        let d = "DC=contoso,DC=local";
        assert!(is_dns_partition("DC=DomainDnsZones,DC=contoso,DC=local"));
        assert!(is_dns_partition("dc=forestdnszones,DC=contoso,DC=local"));
        assert!(!is_dns_partition(d));
        assert!(!is_dns_partition("DC=DomainDnsZonesX,DC=contoso,DC=local"));
        assert!(!is_dns_partition("CN=Configuration,DC=contoso,DC=local"));
        assert_eq!(
            nc_kind("CN=Schema,CN=Configuration,DC=contoso,DC=local", d),
            "schema"
        );
        assert_eq!(
            nc_kind("CN=Configuration,DC=contoso,DC=local", d),
            "configuration"
        );
        assert_eq!(nc_kind("dc=contoso,dc=local", d), "domain");
        assert_eq!(
            nc_kind("DC=ForestDnsZones,DC=contoso,DC=local", d),
            "DNS partition"
        );
        assert_eq!(nc_kind("DC=App,DC=contoso,DC=local", d), "other partition");
    }

    /// Phase 1 volume cuts: not reading the DNS partitions and not asking for
    /// deleted objects leaves every object Pathwarden keeps exactly as it
    /// was, apart from references to the objects no longer read. Both
    /// entry sets go through RustHound-CE's parser and the checker as in a
    /// collection; objects are compared by identifier, arrays as sets
    /// (upstream's own order follows HashMap iteration, which differs
    /// between two parses anyway).
    #[test]
    fn volume_cuts_keep_the_objects_we_keep() {
        use checker::tests::{entry, guid, options, sid, synthetic};
        use serde_json::Value;
        let base = "DC=contoso,DC=local";
        let mut dropped_entries = Vec::new();
        for (zi, zone) in ["DomainDnsZones", "ForestDnsZones"].into_iter().enumerate() {
            let nc = format!("DC={zone},{base}");
            dropped_entries.extend([
                // The partition head is a domainDNS object without a SID.
                entry(
                    &nc,
                    &["top", "domain", "domainDNS"],
                    &[("name", zone.into())],
                    vec![],
                ),
                entry(
                    &format!("CN=MicrosoftDNS,{nc}"),
                    &["top", "container"],
                    &[("name", "MicrosoftDNS".into())],
                    vec![("objectGUID", guid(900 + zi as u64, 8))],
                ),
                entry(
                    &format!("DC=contoso.local,CN=MicrosoftDNS,{nc}"),
                    &["top", "dnsZone"],
                    &[("name", "contoso.local".into())],
                    vec![("objectGUID", guid(910 + zi as u64, 8))],
                ),
                entry(
                    &format!("DC=ws01,DC=contoso.local,CN=MicrosoftDNS,{nc}"),
                    &["top", "dnsNode"],
                    &[("name", "ws01".into())],
                    vec![
                        ("objectGUID", guid(920 + zi as u64, 8)),
                        ("dnsRecord", vec![1, 2, 3, 4]),
                    ],
                ),
                entry(
                    &format!("CN=Infrastructure,{nc}"),
                    &["top", "infrastructureUpdate"],
                    &[("name", "Infrastructure".into())],
                    vec![("objectGUID", guid(930 + zi as u64, 8))],
                ),
            ]);
        }
        let deleted = format!("CN=Deleted Objects,{base}");
        dropped_entries.extend([
            entry(
                &deleted,
                &["top", "container"],
                &[
                    ("name", "Deleted Objects".into()),
                    ("isDeleted", "TRUE".into()),
                ],
                vec![("objectGUID", guid(950, 8))],
            ),
            entry(
                &format!("CN=old\\0ADEL:1234,{deleted}"),
                &["top", "person", "organizationalPerson", "user"],
                &[
                    ("name", "old".into()),
                    ("sAMAccountName", "old".into()),
                    ("isDeleted", "TRUE".into()),
                ],
                vec![("objectSid", sid(99_001)), ("objectGUID", guid(951, 8))],
            ),
            entry(
                &format!("CN=oldpc\\0ADEL:5678,{deleted}"),
                &["top", "person", "organizationalPerson", "user", "computer"],
                &[
                    ("name", "OLDPC".into()),
                    ("sAMAccountName", "OLDPC$".into()),
                    ("isDeleted", "TRUE".into()),
                ],
                vec![("objectSid", sid(99_002)), ("objectGUID", guid(952, 8))],
            ),
        ]);
        let mut kept = synthetic(6);
        // Without the user whose DN contains a GPO's GUID: which of the two
        // a gPLink resolves to follows HashMap order in upstream, which
        // differs between two parses (one parse is compared in the checker
        // tests).
        kept.retain(|e| !e.dn.starts_with("CN=ABC"));
        let mut full = kept.clone();
        full.extend(dropped_entries);

        let out = std::env::temp_dir();
        let options = options(&out);
        let run = |entries: Vec<rusthound_ce::transport::ldap::LdapSearchEntry>| {
            let n = entries.len();
            let mut r =
                rusthound_ce::api::parse_result_type_from_source(&options, entries, Some(n))
                    .map_err(|e| e.to_string())
                    .unwrap();
            checker::check_all(&options, &mut r)
                .map_err(|e| e.to_string())
                .unwrap();
            let all = [
                serde_json::to_value(&r.users).unwrap(),
                serde_json::to_value(&r.groups).unwrap(),
                serde_json::to_value(&r.computers).unwrap(),
                serde_json::to_value(&r.ous).unwrap(),
                serde_json::to_value(&r.domains).unwrap(),
                serde_json::to_value(&r.gpos).unwrap(),
                serde_json::to_value(&r.containers).unwrap(),
            ];
            let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
            for list in all {
                for o in list.as_array().unwrap() {
                    let id = o["ObjectIdentifier"].as_str().unwrap().to_string();
                    by_id.insert(id, o.clone());
                }
            }
            by_id
        };
        let before = run(full);
        let after = run(kept);

        // What disappears: the deleted objects (which ingest drops), the
        // `CN=Deleted Objects` container (RustHound-CE's container parser
        // ignores isDeleted, so ingest used to keep it as a real container)
        // and the DNS partitions' MicrosoftDNS containers. Nothing appears.
        let gone: Vec<&String> = before.keys().filter(|k| !after.contains_key(*k)).collect();
        assert!(after.keys().all(|k| before.contains_key(k)));
        assert_eq!(gone.len(), 5, "{gone:?}");
        let mut deleted_n = 0;
        for id in &gone {
            let o = &before[*id];
            let dn = o["Properties"]["distinguishedname"].as_str().unwrap_or("");
            if o["IsDeleted"] == Value::Bool(true) {
                deleted_n += 1;
            } else if dn.starts_with("CN=DELETED OBJECTS,") {
                assert_eq!(o["IsDeleted"], Value::Bool(false));
            } else {
                assert!(
                    dn.starts_with("CN=MICROSOFTDNS,DC=") && dn.contains("DNSZONES"),
                    "{o}"
                );
            }
        }
        assert_eq!(deleted_n, 2);

        // Kept objects are identical, once references to what is gone are
        // removed from both sides.
        fn canon(v: &Value, gone: &[&String]) -> Value {
            match v {
                Value::Array(a) => {
                    let mut items: Vec<Value> = a
                        .iter()
                        .filter(|x| {
                            !["ObjectIdentifier", "PrincipalSID"].iter().any(|k| {
                                x.get(k)
                                    .and_then(Value::as_str)
                                    .is_some_and(|id| gone.iter().any(|g| g.as_str() == id))
                            })
                        })
                        .map(|x| canon(x, gone))
                        .collect();
                    items.sort_by_key(|x| x.to_string());
                    Value::Array(items)
                }
                Value::Object(m) => {
                    Value::Object(m.iter().map(|(k, x)| (k.clone(), canon(x, gone))).collect())
                }
                x => x.clone(),
            }
        }
        let mut differences = 0;
        for (id, a) in &after {
            let b = &before[id];
            if canon(a, &gone) != canon(b, &gone) {
                differences += 1;
                eprintln!("{id}:\n  with cuts {a}\n  before    {b}");
            }
        }
        assert_eq!(differences, 0);
        assert!(after.len() > 60, "{}", after.len());
    }

    #[test]
    fn a_stalled_read_fails_instead_of_waiting_forever() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let limit = Duration::from_millis(20);
            // A reply that never comes (the lost SearchResultDone).
            let never = std::future::pending::<Result<u8, String>>();
            let e = or_stalled(limit, "LDAP search of DC=x", never)
                .await
                .unwrap_err();
            assert_eq!(
                e,
                "LDAP search of DC=x: connection stalled: the domain controller sent \
                 nothing for 1 minute"
            );
            assert_eq!(crate::Problem::classify(&e), crate::Problem::Stalled);
            // Replies and errors that do come pass through.
            let ok = or_stalled(limit, "x", async { Ok::<_, String>(7) }).await;
            assert_eq!(ok, Ok(7));
            let err = or_stalled(limit, "x", async { Err::<u8, _>("busy") }).await;
            assert_eq!(err, Err("x failed: busy".to_string()));
        });
        // Long enough for a DC that is slow but working: past its own
        // two-minute MaxQueryDuration with room to spare.
        assert!(STALL_TIMEOUT >= Duration::from_secs(4 * 60));
    }

    #[test]
    fn naming_context_from_domain() {
        assert_eq!(domain_dn("contoso.local"), "DC=contoso,DC=local");
        assert_eq!(domain_dn("a.b.c."), "DC=a,DC=b,DC=c");
    }

    #[test]
    fn name_mismatch_lists_only_readable_names() {
        let e = "I/O error: invalid peer certificate: certificate not valid for name \
                 \"192.168.56.11\"; certificate is only valid for Unsupported(0x00) or \
                 DnsName(\"winterfell.north.sevenkingdoms.local\")";
        let msg = connect_error("ldaps://192.168.56.11:636", true, e);
        assert!(!msg.contains("Unsupported"), "{msg}");
        assert!(
            msg.contains("only valid for DnsName(\"winterfell.north.sevenkingdoms.local\")"),
            "{msg}"
        );
        assert_eq!(without_unsupported_names("no names here"), "no names here");
        assert_eq!(
            without_unsupported_names("x Unsupported(0x0"),
            "x Unsupported(0x0"
        );
    }

    /// A misspelt domain with a working DC name is refused, naming the DC's
    /// own domain; the right one passes in any case.
    #[test]
    fn a_dc_of_another_domain_is_refused() {
        let nc = "DC=north,DC=sevenkingdoms,DC=local";
        assert_eq!(wrong_domain("north.sevenkingdoms.local", nc), None);
        assert_eq!(wrong_domain("NORTH.SevenKingdoms.Local.", nc), None);
        assert_eq!(
            wrong_domain("nroth.sevenkingdoms.local", nc).as_deref(),
            Some("north.sevenkingdoms.local")
        );
        assert_eq!(
            wrong_domain("sevenkingdoms.local", nc).as_deref(),
            Some("north.sevenkingdoms.local")
        );
        assert_eq!(wrong_domain("contoso.local", ""), None);
        let message = "winterfell.north.sevenkingdoms.local is a domain controller for \
                       north.sevenkingdoms.local, not nroth.sevenkingdoms.local";
        assert_eq!(
            crate::Problem::classify(message),
            crate::Problem::WrongDomain
        );
    }

    /// Nothing listens on LDAPS at 127.0.0.1: the check fails fast, with a
    /// plain "refused" (and no password in the error).
    #[test]
    fn check_reports_a_refused_connection() {
        let mut r = CollectRequest::new("contoso.local", "out");
        r.server = Some("127.0.0.1".into());
        r.ldaps = true;
        r.auth = Auth::Password {
            user: "svc".into(),
            password: Secret::new("Check-Secret-91"),
        };
        let err = crate::test_connection(&r).unwrap_err();
        let ce = err.downcast_ref::<ConnectionError>().expect("typed");
        assert!(
            matches!(
                ce.problem,
                crate::Problem::Refused | crate::Problem::Timeout
            ),
            "{ce:?}"
        );
        assert!(!format!("{err:?} {err}").contains("Check-Secret-91"));
    }

    #[test]
    fn skip_verify_warns() {
        let mut r = password_req();
        r.ldaps = true;
        r.insecure_skip_tls_verify = true;
        assert!(plan(&r)
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("certificates were not checked")));
    }

    /// A collection that reached its domain controller through
    /// DNS (no name, an IP address, a short name) warns that its results
    /// are only as trustworthy as DNS; one named by its full name doesn't.
    #[test]
    fn a_dc_not_named_by_its_full_name_warns() {
        let mut r = password_req();
        r.ldaps = true;
        let warned = |r: &CollectRequest| {
            plan(r)
                .unwrap()
                .warnings
                .iter()
                .any(|w| w.as_str() == UNNAMED_DC)
        };
        assert!(warned(&r));
        for unnamed in ["10.0.0.5", "dc01", "[fe80::1]", "", "dc01..contoso.local"] {
            r.server = Some(unnamed.into());
            assert!(warned(&r), "{unnamed}");
        }
        for named in ["dc01.contoso.local", "DC01.contoso.local."] {
            r.server = Some(named.into());
            assert!(!warned(&r), "{named}");
        }
        assert!(UNNAMED_DC.contains("only as trustworthy as DNS"));
    }

    /// Cancel while the connection attempt hangs (TEST-NET address that
    /// never answers): `collect` must return `Cancelled` promptly.
    #[cfg(windows)]
    #[test]
    fn cancel_stops_a_hanging_connection() {
        use std::time::Instant;
        let out = std::env::temp_dir().join(format!("pw-cancel-{}", std::process::id()));
        let mut r = CollectRequest::new("contoso.local", &out);
        r.server = Some("192.0.2.1".into());
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let result = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                cancel.store(true, Ordering::SeqCst);
            });
            crate::collect(&r, &mut |_| {}, &cancel)
        });
        let err = result.expect_err("cancelled");
        // Either the cancel won, or the network refused at once.
        if err.is::<Cancelled>() {
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        let _ = std::fs::remove_dir_all(&out);
    }

    /// Binary `objectSid` for S-1-5-21-<subs...>.
    pub(super) fn sid_bytes(subs: &[u32]) -> Vec<u8> {
        let mut all = vec![21u32];
        all.extend_from_slice(subs);
        let mut b = vec![1u8, all.len() as u8, 0, 0, 0, 0, 0, 5];
        for s in all {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    pub(super) fn entry(
        dn: &str,
        classes: &[&str],
        attrs: &[(&str, &str)],
        multi: &[(&str, Vec<&str>)],
        sid: &[u32],
    ) -> rusthound_ce::transport::ldap::LdapSearchEntry {
        use std::collections::HashMap;
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert(
            "objectClass".into(),
            classes.iter().map(|c| c.to_string()).collect(),
        );
        a.insert("distinguishedName".into(), vec![dn.to_string()]);
        for (k, v) in attrs {
            a.insert(k.to_string(), vec![v.to_string()]);
        }
        for (k, v) in multi {
            a.insert(k.to_string(), v.iter().map(|x| x.to_string()).collect());
        }
        let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        bin.insert("objectSid".into(), vec![sid_bytes(sid)]);
        rusthound_ce::transport::ldap::LdapSearchEntry {
            dn: dn.to_string(),
            attrs: a,
            bin_attrs: bin,
        }
    }

    /// The certificate hint reads right in the app and in the terminal.
    #[test]
    fn certificate_hint_names_both_the_app_and_the_flag() {
        let e = connect_error(
            "ldaps://dc01:636",
            true,
            "rustls error: invalid peer certificate: UnknownIssuer",
        );
        assert!(
            e.contains("Don't check the certificate") && e.contains("--insecure-skip-tls-verify"),
            "{e}"
        );
        assert!(!e.contains("use --server"), "{e}");
        assert!(!connect_error("ldap://dc01:389", false, "certificate").contains("labs"));
    }

    /// Synthetic directory -> RustHound-CE parser and JSON writer (the same
    /// options the built-in collector uses) -> Pathwarden's ingest.
    #[test]
    fn output_round_trips_through_pathwarden_ingest() {
        let out = std::env::temp_dir().join(format!("pw-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let before = Snapshot::take(&out);

        let base = "DC=contoso,DC=local";
        let alice = format!("CN=Alice,CN=Users,{base}");
        let entries = vec![
            entry(
                base,
                &["top", "domain", "domainDNS"],
                &[("name", "contoso")],
                &[],
                &[1, 2, 3],
            ),
            entry(
                &alice,
                &["top", "person", "organizationalPerson", "user"],
                &[
                    ("name", "Alice"),
                    ("sAMAccountName", "alice"),
                    ("userAccountControl", "512"),
                    ("primaryGroupID", "513"),
                ],
                &[],
                &[1, 2, 3, 1104],
            ),
            entry(
                &format!("CN=Domain Admins,CN=Users,{base}"),
                &["top", "group"],
                &[
                    ("name", "Domain Admins"),
                    ("sAMAccountName", "Domain Admins"),
                ],
                &[("member", vec![alice.as_str()])],
                &[1, 2, 3, 512],
            ),
            entry(
                &format!("CN=WS01,CN=Computers,{base}"),
                &["top", "person", "organizationalPerson", "user", "computer"],
                &[
                    ("name", "WS01"),
                    ("sAMAccountName", "WS01$"),
                    ("dNSHostName", "ws01.contoso.local"),
                    ("userAccountControl", "4096"),
                    ("primaryGroupID", "515"),
                ],
                &[],
                &[1, 2, 3, 1105],
            ),
        ];

        let options = base_options(
            "contoso.local",
            &out,
            CollectionMethod::LdapOnly,
            "dc01.contoso.local".into(),
            true,
        );
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let n = entries.len();
        let results = rt
            .block_on(rusthound_ce::prepare_results_from_source(
                entries,
                &options,
                Some(n),
            ))
            .map_err(|e| e.to_string())
            .unwrap();
        let written = rusthound_ce::make_result(&options, results)
            .map_err(|e| e.to_string())
            .unwrap();

        let files = output::discover_outputs(&out, &before);
        assert_eq!(files.len(), 1, "one zip: {files:?} ({written})");
        let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            pathwarden_core::time::timestamp_in_name(&name).is_some(),
            "file name carries the collection time: {name}"
        );
        let summary: std::collections::BTreeMap<_, _> =
            output::summarize_outputs(&files).into_iter().collect();
        // RustHound-CE adds well-known principals (NT AUTHORITY, builtin
        // groups), so users and groups exceed the synthetic counts.
        assert!(summary.get("users").is_some_and(|&n| n >= 1), "{summary:?}");
        assert!(
            summary.get("groups").is_some_and(|&n| n >= 1),
            "{summary:?}"
        );
        assert_eq!(summary.get("computers"), Some(&1), "{summary:?}");
        assert_eq!(summary.get("domains"), Some(&1), "{summary:?}");

        // Pathwarden loads the directory exactly as `report -i <dir>` would.
        let (g, stats) =
            pathwarden_core::load(&[&out], &pathwarden_core::LoadOptions::default()).unwrap();
        assert!(stats.collected_at.is_some());
        assert!(stats.skipped_files.is_empty(), "{:?}", stats.skipped_files);
        let user = g.lookup("S-1-5-21-1-2-3-1104").expect("user ingested");
        let da = g.lookup("S-1-5-21-1-2-3-512").expect("group ingested");
        assert!(
            g.lookup("S-1-5-21-1-2-3-1105").is_some(),
            "computer ingested"
        );
        assert!(
            g.transitive_members(da).contains(&user),
            "Alice is a member of Domain Admins"
        );
        assert!(g.node(da).tier_zero, "Domain Admins is Tier Zero");
        let _ = std::fs::remove_dir_all(&out);
    }

    /// A resumed read keeps the domain controller it started on, before
    /// any is located; a trusted domain otherwise gets the located one, on
    /// the LDAPS port; a named one is never replaced.
    #[test]
    fn a_resumed_read_keeps_its_dc_before_one_is_located() {
        let root = std::env::temp_dir().join(format!("pw-pick-dc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut req = CollectRequest::new("fabrikam.com", root.join("out"));
        req.ldaps = true;
        req.locate_dc = true;
        req.cache = Some(crate::ReadCache {
            root: root.clone(),
            resume: true,
            ..crate::ReadCache::default()
        });
        let asked = std::cell::RefCell::new(Vec::new());
        let mut find = |d: &str, port: u16, _: &mut dyn FnMut(String)| {
            asked.borrow_mut().push((d.to_string(), port));
            Ok::<_, crate::locate::NotFound>("dc02.fabrikam.com".to_string())
        };
        // Nothing to resume: the located one, on 636.
        let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        assert_eq!(pick_dc(&mut job, &req, &mut find, &mut |_| {}), None);
        assert_eq!(job.server.as_deref(), Some("dc02.fabrikam.com"));
        assert_eq!(job.url, "ldaps://dc02.fabrikam.com:636");
        assert_eq!(*asked.borrow(), [("fabrikam.com".to_string(), 636)]);

        // A stopped read: its own controller, and nothing located.
        asked.borrow_mut().clear();
        fake_stopped_read(&root, "fabrikam.com", &req.auth, 40, cache::now()).unwrap();
        let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        let mut log = Vec::new();
        pick_dc(&mut job, &req, &mut find, &mut |l| log.push(l));
        assert_eq!(job.server.as_deref(), Some("dc01.fabrikam.com"));
        assert!(asked.borrow().is_empty(), "{:?}", asked.borrow());
        assert!(log[0].contains("resuming on dc01.fabrikam.com"), "{log:?}");

        // Named with --server DOMAIN=HOST: kept, nothing located.
        req.cache = None;
        req.server = Some("dc07.fabrikam.com".into());
        req.locate_dc = false;
        let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        pick_dc(&mut job, &req, &mut find, &mut |_| {});
        assert_eq!(job.url, "ldaps://dc07.fabrikam.com:636");
        assert!(asked.borrow().is_empty());
        // The first domain (no locate_dc) keeps the domain's name.
        req.server = None;
        let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        pick_dc(&mut job, &req, &mut find, &mut |_| {});
        assert_eq!(job.url, "ldaps://fabrikam.com:636");
        assert!(asked.borrow().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// No domain controller found: the domain's name is used, and
    /// when it fails as a name would (its certificate names the host), the
    /// error says none was found, with what each way said behind it; a
    /// domain controller that answered keeps its own reason.
    #[test]
    fn none_located_says_why() {
        let mut req = CollectRequest::new("fabrikam.com", "out");
        req.ldaps = true;
        req.locate_dc = true;
        let mut none = |_: &str, _: u16, _: &mut dyn FnMut(String)| {
            Err(crate::locate::NotFound {
                why: "DNS found none: no such name (DNS error 9003)".into(),
                found: false,
                outside: false,
            })
        };
        let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
        let why = pick_dc(&mut job, &req, &mut none, &mut |_| {});
        assert_eq!(job.url, "ldaps://fabrikam.com:636");
        assert_eq!(job.server, None);
        let cert = ConnectionError::new(
            "rustls error: invalid peer certificate: certificate not valid for name \
             \"fabrikam.com\"",
        );
        let e = not_located("fabrikam.com", why.as_ref(), false, cert.clone());
        assert_eq!(e.problem, crate::Problem::NotLocated);
        assert_eq!(e.message(), crate::locate::not_found("fabrikam.com"));
        assert!(e.detail.starts_with("DNS found none: no such name (DNS error 9003); then by the domain's name: rustls error"), "{}", e.detail);
        // Located (or named): the error as it is.
        assert_eq!(
            not_located("fabrikam.com", None, false, cert.clone()).problem,
            crate::Problem::CertificateName
        );
        let refused = ConnectionError::new("rc=49 (invalidCredentials)");
        assert_eq!(
            not_located("fabrikam.com", why.as_ref(), false, refused).problem,
            crate::Problem::Credentials
        );
        // After a connection (the run had its domain controller), a
        // timeout or a refusal keeps its own reason.
        let stalled = ConnectionError::new("timeout: no answer from the domain controller");
        assert_eq!(stalled.problem, crate::Problem::Timeout);
        assert_eq!(
            not_located("fabrikam.com", why.as_ref(), true, stalled.clone()).problem,
            crate::Problem::Timeout
        );
        assert!(unlocated("fabrikam.com", why.as_ref(), true, &stalled).is_none());
        assert_eq!(
            unlocated("fabrikam.com", why.as_ref(), false, &stalled)
                .unwrap()
                .problem,
            crate::Problem::NotLocated
        );
        assert_eq!(
            not_located("fabrikam.com", why.as_ref(), true, cert).problem,
            crate::Problem::CertificateName
        );
    }
}
