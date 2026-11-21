//! Collection: reads Active Directory and writes BloodHound-compatible JSON
//! that Pathwarden (or BloodHound CE) can analyze.
//!
//! Two methods:
//! - **Built-in** (Cargo feature `builtin`, on by default): LDAP collection by
//!   [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (MIT) used as a
//!   library. Pathwarden opens and binds the LDAP connection itself, so TLS
//!   certificates are verified and the password never reaches a log line.
//! - **External**: runs SharpHound or a `rusthound-ce` executable and picks up
//!   the files it writes.
//!
//! [`collect`] is blocking, reports [`Progress`] through a callback and stops
//! when the `cancel` flag is set, so a UI can run it on a background thread.
//! Besides phases, counts and log lines, it reports a [`Status`] a few times
//! a second: the numbered step, objects by type, expected totals, percent
//! and a smoothed ETA (see [`progress`]).
//! [`test_connection`] checks a request first (bind, RootDSE, a quick count of
//! users and computers; or that an external program exists) and explains
//! failures as a [`Problem`] in plain words.

// The only unsafe code is Windows API calls in memory.rs, locate.rs,
// signature.rs, builtin/cache.rs, builtin/winsec.rs, builtin/winnet.rs and builtin/winkrb.rs.
#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

mod check;
mod cli;
pub mod compare;
mod domains;
mod external;
pub mod locate;
mod markers;
pub mod memory;
mod output;
pub mod progress;
mod redact;
mod refresh;
mod secret;
pub mod signature;

#[cfg(feature = "builtin")]
mod builtin;

pub use check::{
    test_connection, test_connection_with, ConnectionCheck, ConnectionError, Count, Problem,
};
pub use cli::{
    named_servers, parse_servers, server_host, CollectArgs, DomainServers, ServerError, Verbosity,
};
pub use domains::{
    collect_domains, domain_folder, merged, names_account_domain, short_reason, test_domains,
    unused_servers, DomainEvent, DomainResult, DomainState,
};
pub use output::{discover_outputs, summarize_outputs, Snapshot};
pub use progress::{Status, Step, Tracker};
pub use refresh::{
    host_reader, ldap_filter, refresh_objects, BuiltinRefresher, FixedRefresher, HostRead,
    HostReader, RefreshTarget, Refreshed, Refresher, SliceHost, MAX_HOSTS,
};
pub use secret::{Secret, PASSWORD_ENV};

/// What a DC-only (Quick) collection leaves out by design. A note about the
/// chosen depth, not a problem ([`is_scope_note`]).
pub const NO_SESSIONS_NOTE: &str = "This collection read only the domain controllers, so it has \
     no sessions or local groups. Paths through logged-on administrators and local administrator \
     rights are not in this run.";

/// What the built-in collector leaves out when it signs in without a
/// password. A note about the chosen sign-in, not a problem
/// ([`is_scope_note`]).
pub const NO_SYSVOL_NOTE: &str =
    "Group Policy local groups (SYSVOL) are not collected without a password.";

/// Whether a collector warning only says what the chosen depth or sign-in
/// doesn't collect ([`NO_SESSIONS_NOTE`], [`NO_SYSVOL_NOTE`], and their
/// wording in older runs): information about an intended collection, not
/// something that went wrong. Everything else (computers not reached,
/// unchecked certificates, plain LDAP, a folder others can open) is a
/// warning.
pub fn is_scope_note(w: &str) -> bool {
    let w = w.trim();
    w == NO_SESSIONS_NOTE
        || w == NO_SYSVOL_NOTE
        // Older runs kept these.
        || w.starts_with("DC-only collection: no sessions or local groups")
        || w.trim_end_matches('.')
            .eq_ignore_ascii_case("group policy local groups (SYSVOL) are not collected without a password")
}

/// How a collection signs in to computers, for its summary: "Kerberos
/// only, SMB signing required." The app's check recap and Run details say the
/// same from the run's record ([`computers_phrase`]).
pub fn computers_words(req: &CollectRequest) -> String {
    match &req.method {
        Method::External {
            kind: ExternalKind::SharpHound,
            ..
        } => "Kerberos only and SMB signing weren't enforced: SharpHound signs in to computers \
              its own way."
            .into(),
        Method::External {
            kind: ExternalKind::RustHound,
            ..
        } => "Kerberos (RustHound-CE's own); SMB replies not checked for signatures.".into(),
        // As the Windows account, Windows' own SMB client signs as its
        // policy says; Pathwarden can't check its replies, so
        // --allow-unsigned-smb changes nothing there.
        Method::Builtin if matches!(req.auth, Auth::CurrentUser) => format!(
            "{}, SMB signing left to Windows.{}",
            if req.allow_ntlm {
                "NTLM allowed"
            } else {
                "Kerberos only"
            },
            if req.allow_unsigned_smb {
                " (--allow-unsigned-smb has no effect as the Windows account.)"
            } else {
                ""
            }
        ),
        Method::Builtin => format!(
            "{}.",
            computers_phrase(!req.allow_ntlm, !req.allow_unsigned_smb)
        ),
    }
}

/// "Kerberos only, SMB signing required", and the other three.
pub fn computers_phrase(kerberos_only: bool, smb_signing: bool) -> String {
    format!(
        "{}, {}",
        if kerberos_only {
            "Kerberos only"
        } else {
            "NTLM allowed"
        },
        if smb_signing {
            "SMB signing required"
        } else {
            "SMB signing not required"
        }
    )
}

/// How to authenticate to the domain.
#[derive(Debug)]
pub enum Auth {
    /// The identity this process runs as: Kerberos through Windows SSPI
    /// (built-in, Windows only) or SharpHound's own logon. The right choice
    /// for a gMSA scheduled task.
    CurrentUser,
    /// A domain account and password (`user`, `DOMAIN\user` or
    /// `user@domain`). Built-in mode uses NTLM over the LDAP connection.
    Password { user: String, password: Secret },
    /// A Kerberos ticket cache (`KRB5CCNAME`); external RustHound-CE only.
    /// `None` uses the `KRB5CCNAME` already in the environment.
    KerberosCache { ccache: Option<PathBuf> },
}

/// External collector programs Pathwarden can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKind {
    SharpHound,
    RustHound,
}

/// Which collector does the work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// RustHound-CE linked into Pathwarden (needs the `builtin` feature).
    Builtin,
    /// An executable on disk.
    External {
        program: PathBuf,
        kind: ExternalKind,
    },
}

/// How much to collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Scope {
    /// Quick (directory only): LDAP from the domain controller (and SYSVOL
    /// group policy when a password is given). No sessions or local groups.
    #[value(
        help = "Quick (directory only): LDAP from the domain controller (and SYSVOL group policy when a password is given). No sessions or local groups."
    )]
    DcOnly,
    /// Full: everything the collector can do, including sessions and local
    /// groups from every reachable computer. Noisier and slower.
    #[value(
        help = "Full: everything the collector can do, including sessions and local groups from every reachable computer. Noisier and slower."
    )]
    All,
    /// The method's default: `dc-only` for built-in, `all` for SharpHound
    /// and RustHound-CE.
    #[default]
    #[value(skip)]
    Default,
}

/// A collection to run.
#[derive(Debug)]
pub struct CollectRequest {
    /// DNS name of the domain, e.g. `contoso.local`.
    pub domain: String,
    /// Domain controller to query (preferably its FQDN). Defaults to the
    /// domain name, which DNS resolves to some DC.
    pub server: Option<String>,
    /// The other domains' domain controllers in a run of several,
    /// as `--server DOMAIN=HOST` names them: (domain, host).
    pub servers: Vec<(String, String)>,
    /// Built-in collector, no `server`: find a domain controller of the
    /// domain by its full name first ([`locate`]), so the LDAPS
    /// certificate's name matches. Set for a run's trusted domains.
    pub locate_dc: bool,
    pub auth: Auth,
    /// Use LDAPS (636) instead of LDAP (389).
    pub ldaps: bool,
    /// Skip LDAPS certificate validation. Insecure: only for labs.
    pub insecure_skip_tls_verify: bool,
    /// Allow a password bind over plain LDAP (NTLM, no signing or sealing):
    /// the directory travels unencrypted and can be tampered with.
    pub allow_unencrypted_ldap: bool,
    /// Sign in to computers (sessions, local groups, SYSVOL, the CAs'
    /// registry) with NTLM where Kerberos can't be used. Off by default
    /// (Kerberos only): a computer the domain has no Kerberos name for is
    /// skipped, so a name someone added to DNS gets no NTLM response.
    pub allow_ntlm: bool,
    /// Read computers whose SMB replies aren't signed. Off by default: every
    /// reply after sign-in must carry a valid signature, and a computer
    /// whose replies don't is skipped.
    pub allow_unsigned_smb: bool,
    /// In a Full collection by the built-in collector, read the account each
    /// service runs as on the computers. On by default; off with
    /// `--no-service-reads` or `[collect] service_reads = false`.
    pub service_reads: bool,
    /// In a Full collection by the built-in collector, read the scheduled
    /// tasks on the computers over `C$`. On by default; off
    /// with `--no-task-reads` or `[collect] task_reads = false`.
    pub task_reads: bool,
    /// Where the output goes. Pathwarden writes nothing anywhere else.
    pub output_dir: PathBuf,
    pub method: Method,
    pub scope: Scope,
    /// About how many objects the collector will process, when known from
    /// elsewhere (e.g. the last collection of this domain). SharpHound's
    /// percentage and ETA use it until a count of the domain is available.
    /// The built-in collector counts the directory itself.
    pub expected_objects: Option<u64>,
    /// Where the built-in collector keeps the directory while it reads it.
    /// `None` reads it into memory (`--no-cache`).
    pub cache: Option<ReadCache>,
    /// Built-in collector: ask the directory for every attribute (`*`), as
    /// RustHound-CE does, instead of only those its parser reads.
    /// For comparing the two (`--all-attributes`, `[collect]
    /// all_attributes`).
    pub all_attributes: bool,
    /// Built-in collector: how many connections read the directory at once,
    /// 1 to 8 (`--read-streams`, `[collect] read_streams`). `None`:
    /// 4.
    pub read_streams: Option<usize>,
}

/// The folder in an environment's folder that holds the built-in
/// collector's reads in progress, one folder per domain.
pub const CACHE_DIR: &str = "collect-cache";

/// Where the built-in collector keeps a read on disk, and how large the last
/// read of the domain was (for the free-space check).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadCache {
    /// `<environment folder>\collect-cache`: a folder per domain goes in it.
    pub root: PathBuf,
    /// Entries the last read of this domain returned.
    pub last_entries: Option<u64>,
    /// Bytes that read took on disk (`None` when it read into memory).
    pub last_bytes: Option<u64>,
    /// Its entries by type (`users`, `computers`, ...), when it said: with
    /// `last_entries`, the read's expected size without counting again.
    pub last_counts: std::collections::BTreeMap<String, u64>,
    /// When that run was made (Unix time): an older one is no estimate,
    /// and the read is counted again.
    pub last_when: Option<i64>,
    /// Go on with a read of the domain that stopped, when it can be
    /// ([`stopped_read`]); otherwise it starts over.
    pub resume: bool,
}

/// How long a stopped read can be resumed, from when it started.
pub const RESUME_HOURS: u32 = 24;

/// A read of a domain on disk that stopped and can be resumed, as
/// far as can be told without connecting: the domain controller must still
/// be the same one, with the same database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoppedRead {
    pub domain: String,
    /// How far it got, under 100.
    pub percent: u8,
    /// When it started and when it last finished a part (Unix time).
    pub started: i64,
    pub stopped: i64,
}

impl StoppedRead {
    /// How long ago it stopped: "just now", "5 min ago", "2 h ago".
    pub fn ago(&self, now: i64) -> String {
        let s = (now - self.stopped).max(0);
        match s {
            0..60 => "just now".into(),
            60..3600 => format!("{} min ago", s / 60),
            _ => format!("{} h ago", s / 3600),
        }
    }
}

/// The read of `domain` in `cache` that stopped and that the sign-in `auth`
/// can resume, if there is one: under 24 hours old, written by this
/// version's format, by the same sign-in, with something read, and not in
/// use. The app offers it; `pathwarden collect --resume` takes it.
pub fn stopped_read(cache: &ReadCache, domain: &str, auth: &Auth) -> Option<StoppedRead> {
    #[cfg(feature = "builtin")]
    {
        builtin::stopped_read(&cache.root, domain, auth)
    }
    #[cfg(not(feature = "builtin"))]
    {
        let _ = (cache, domain, auth);
        None
    }
}

/// Removes the reads in `cache_root` (a `collect-cache` folder) that can't
/// be resumed any more: more than 24 hours old, another format's, damaged,
/// or with nothing read. Only Pathwarden's files, in folders holding its
/// checkpoint, and never a read in progress. Returns how many went. The app
/// and `pathwarden collect` call it when they start.
pub fn sweep_stopped_reads(cache_root: &Path) -> usize {
    #[cfg(feature = "builtin")]
    {
        builtin::sweep_reads(cache_root)
    }
    #[cfg(not(feature = "builtin"))]
    {
        let _ = cache_root;
        0
    }
}

/// For other crates' tests: writes the checkpoint of a read of `domain`
/// that stopped at `percent`, started at `started` (Unix time), signed in
/// as `auth`, in `cache`'s folder. No chunk is written. Does nothing
/// without the built-in collector.
#[doc(hidden)]
pub fn fake_stopped_read(
    cache: &ReadCache,
    domain: &str,
    auth: &Auth,
    percent: u8,
    started: i64,
) -> std::io::Result<()> {
    #[cfg(feature = "builtin")]
    {
        builtin::fake_stopped_read(&cache.root, domain, auth, percent, started)
    }
    #[cfg(not(feature = "builtin"))]
    {
        let _ = (cache, domain, auth, percent, started);
        Ok(())
    }
}

/// The sign-in a collection asks for, as the read on disk keys it (an HMAC
/// there): the kind, and the account's name without its domain, in lower
/// case, the same for each domain of a run (`svc`, `CONTOSO\svc` and
/// `svc@contoso.local` are one). The account the directory names is
/// checked once connected.
#[cfg(feature = "builtin")]
pub(crate) fn sign_in_key(auth: &Auth) -> String {
    match auth {
        Auth::CurrentUser => "current-user".into(),
        Auth::Password { user, .. } => {
            let user = user.trim();
            let name = match user.split_once('\\') {
                Some((_, n)) => n,
                None => user.split('@').next().unwrap_or(user),
            };
            format!("password:{}", name.to_lowercase())
        }
        Auth::KerberosCache { .. } => "kerberos-cache".into(),
    }
}

/// Returned (inside `anyhow::Error`) when the built-in collector's read
/// stopped and is kept on disk to resume. Check with
/// `err.downcast_ref::<ReadStopped>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadStopped {
    pub domain: String,
    /// The domain controller it read, when it got that far.
    pub dc: Option<String>,
    /// What stopped it, as the collector said (for the log).
    pub reason: String,
}

impl ReadStopped {
    /// What stopped it in plain words: the common causes ("the connection
    /// to dc01.contoso.local was lost"), else the collector's words.
    pub fn plain_reason(&self) -> String {
        let raw = self.reason.trim().trim_end_matches('.');
        let lower = raw.to_ascii_lowercase();
        let dc = self.dc.as_deref().unwrap_or("the domain controller");
        let any = |words: &[&str]| words.iter().any(|w| lower.contains(w));
        if any(&["cannot write the read to disk"]) {
            "it could not be written to disk".into()
        } else if any(&["connection stalled", "timed out", "timeout"]) {
            format!("{dc} stopped answering")
        } else if any(&[
            "connection reset",
            "forcibly closed",
            "connection aborted",
            "broken pipe",
            "unexpected eof",
            "connection closed",
            "os error 10054",
            "os error 10053",
            "os error 10060",
            "network is unreachable",
            "host is unreachable",
        ]) {
            format!("the connection to {dc} was lost")
        } else if any(&["did not return all of"]) {
            format!("{dc} did not return everything")
        } else {
            raw.to_string()
        }
    }
}

impl std::fmt::Display for ReadStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The read stopped: {}. It can be resumed for {RESUME_HOURS} hours.",
            self.plain_reason()
        )
    }
}

impl std::error::Error for ReadStopped {}

/// Returned (inside `anyhow::Error`) when the disk can't hold the read.
/// Check with `err.downcast_ref::<NoSpace>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoSpace {
    /// `C:`, or the folder when it is on no drive letter.
    pub place: String,
    pub needed: u64,
    pub free: u64,
}

impl std::fmt::Display for NoSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // In GB, or in MB under 1 GB: a small read isn't said to need 1 GB.
        const GB: u64 = 1 << 30;
        const MB: u64 = 1 << 20;
        let (unit, size) = if self.needed >= GB {
            ("GB", GB)
        } else {
            ("MB", MB)
        };
        write!(
            f,
            "Not enough free space on {} for this read: about {} {unit} needed, {} {unit} free.",
            self.place,
            self.needed.div_ceil(size).max(1),
            self.free / size
        )
    }
}

impl std::error::Error for NoSpace {}

impl CollectRequest {
    /// A request with secure defaults: current user, plain LDAP with
    /// Kerberos sealing, built-in method, default scope.
    pub fn new(domain: impl Into<String>, output_dir: impl Into<PathBuf>) -> Self {
        Self {
            domain: domain.into(),
            server: None,
            servers: Vec::new(),
            locate_dc: false,
            auth: Auth::CurrentUser,
            ldaps: false,
            insecure_skip_tls_verify: false,
            allow_unencrypted_ldap: false,
            allow_ntlm: false,
            allow_unsigned_smb: false,
            service_reads: true,
            task_reads: true,
            output_dir: output_dir.into(),
            method: Method::Builtin,
            scope: Scope::Default,
            expected_objects: None,
            cache: None,
            all_attributes: false,
            read_streams: None,
        }
    }

    /// The same request, writing to `output_dir` instead.
    pub(crate) fn writing_to(&self, output_dir: PathBuf) -> Self {
        let auth = match &self.auth {
            Auth::CurrentUser => Auth::CurrentUser,
            Auth::Password { user, password } => Auth::Password {
                user: user.clone(),
                password: password.duplicate(),
            },
            Auth::KerberosCache { ccache } => Auth::KerberosCache {
                ccache: ccache.clone(),
            },
        };
        Self {
            domain: self.domain.clone(),
            server: self.server.clone(),
            servers: self.servers.clone(),
            locate_dc: self.locate_dc,
            auth,
            ldaps: self.ldaps,
            insecure_skip_tls_verify: self.insecure_skip_tls_verify,
            allow_unencrypted_ldap: self.allow_unencrypted_ldap,
            allow_ntlm: self.allow_ntlm,
            allow_unsigned_smb: self.allow_unsigned_smb,
            service_reads: self.service_reads,
            task_reads: self.task_reads,
            output_dir,
            method: self.method.clone(),
            scope: self.scope,
            expected_objects: self.expected_objects,
            cache: self.cache.clone(),
            all_attributes: self.all_attributes,
            read_streams: self.read_streams,
        }
    }
}

/// Progress reported while a collection runs.
#[derive(Debug, Clone, PartialEq)]
pub enum Progress {
    /// A new step started ("Reading the directory", ...). The same label is
    /// in the next [`Progress::Status`].
    Phase(String),
    /// Objects written, by BloodHound type (`users`, `computers`, ...), once
    /// the output files exist.
    Objects { kind: String, count: usize },
    /// A line of collector output.
    Log(String),
    /// Where the collection is: sent on every step change and a few times a
    /// second while it runs, and once more (finished) at the end.
    Status(Box<Status>),
    /// Several domains in one run: one of them started, finished or
    /// failed ([`collect_domains`]). The progress in between is that
    /// domain's.
    Domain(DomainEvent),
}

/// How often [`Progress::Status`] is sent while nothing else happens.
pub const STATUS_EVERY: Duration = Duration::from_millis(250);

/// Turns collector events into [`Progress`] for the caller: keeps the
/// [`Tracker`] and sends a [`Status`] on step changes and every
/// [`STATUS_EVERY`].
pub(crate) struct Reporter<'a> {
    tracker: Tracker,
    sink: &'a mut dyn FnMut(Progress),
    last: Option<Instant>,
}

impl<'a> Reporter<'a> {
    pub(crate) fn new(steps: Vec<Step>, sink: &'a mut dyn FnMut(Progress)) -> Self {
        Self {
            tracker: Tracker::new(steps),
            sink,
            last: None,
        }
    }

    /// Sends a log line, with any password material taken out (the collector
    /// sources filter already; this is the last gate before the caller).
    pub(crate) fn log(&mut self, line: impl Into<String>) {
        let line = redact::log_line(&line.into()).into_owned();
        (self.sink)(Progress::Log(line));
    }

    /// Moves to step `key` (forward only) and says so at once.
    pub(crate) fn enter(&mut self, key: &str) {
        if self.tracker.enter(key) {
            let label = self.tracker.label().to_string();
            (self.sink)(Progress::Phase(label));
            self.emit();
        }
    }

    pub(crate) fn current(&self) -> &'static str {
        self.tracker.current()
    }

    /// Changes the tracker, then reports if it is time to.
    pub(crate) fn with(&mut self, f: impl FnOnce(&mut Tracker)) {
        f(&mut self.tracker);
        self.tick();
    }

    /// Applies what a collector output line said.
    pub(crate) fn marker(&mut self, m: markers::Marker) {
        use markers::Marker;
        match m {
            Marker::Step(key) => self.enter(key),
            Marker::Done(n) => self.with(|t| t.units(n, None)),
            Marker::Count(kind, n) => self.with(|t| t.count(&kind, n)),
            Marker::Targets(n) => self.with(|t| {
                t.detail(Some(format!(
                    "{} computers to contact",
                    progress::thousands(n)
                )))
            }),
            Marker::Finished => {}
        }
    }

    /// Sends a status if the last one is older than [`STATUS_EVERY`].
    pub(crate) fn tick(&mut self) {
        if self.last.is_none_or(|t| t.elapsed() >= STATUS_EVERY) {
            self.emit();
        }
    }

    pub(crate) fn emit(&mut self) {
        let status = self.tracker.status();
        (self.sink)(Progress::Status(Box::new(status)));
        self.last = Some(Instant::now());
    }

    fn objects(&mut self, kind: String, count: usize) {
        self.tracker.count(&kind, count as u64);
        (self.sink)(Progress::Objects { kind, count });
    }

    fn finish(&mut self) {
        self.tracker.finish();
        self.emit();
    }
}

/// The steps a request goes through, with their rough share of the time.
pub fn steps_for(req: &CollectRequest) -> Vec<Step> {
    match &req.method {
        Method::External {
            kind: ExternalKind::SharpHound,
            ..
        } => vec![
            Step::new("start", "Starting SharpHound", 3.0),
            Step::new("enumerate", "Collecting objects", 87.0),
            Step::new("write", "Writing the output", 10.0),
        ],
        Method::External {
            kind: ExternalKind::RustHound,
            ..
        } => {
            let mut steps = vec![
                Step::new("start", "Starting RustHound-CE", 3.0),
                Step::new("read", "Reading the directory", 50.0),
                Step::new("parse", "Processing objects", 15.0),
                Step::new("resolve", "Resolving memberships and permissions", 8.0),
            ];
            if req.scope != Scope::DcOnly {
                steps.push(Step::new(
                    "modules",
                    "Contacting computers (sessions, local groups)",
                    30.0,
                ));
            }
            steps.push(Step::new("write", "Writing the output", 5.0));
            steps
        }
        Method::Builtin => builtin_steps(req),
    }
}

#[cfg(feature = "builtin")]
fn builtin_steps(req: &CollectRequest) -> Vec<Step> {
    match builtin::plan(req) {
        Ok(plan) => builtin::steps(&plan.method),
        Err(_) => builtin::steps(&rusthound_ce::args::CollectionMethod::LdapOnly),
    }
}

#[cfg(not(feature = "builtin"))]
fn builtin_steps(_req: &CollectRequest) -> Vec<Step> {
    vec![Step::new("connect", "Connecting", 1.0)]
}

/// What a finished collection produced.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Files written to the output directory (`.zip` or `.json`), ready for
    /// `pathwarden report -i <output_dir>`.
    pub files: Vec<PathBuf>,
    /// Things the user should know, e.g. no sessions were collected.
    pub warnings: Vec<String>,
    /// Where the time went, for the run's `timings.json`
    /// ([`pathwarden_core::diagnostics`]).
    pub timings: Option<pathwarden_core::diagnostics::CollectionTimings>,
    /// Who the directory says the sign-in was (`DOMAIN\user`, LDAP "Who am
    /// I?"), when the built-in collector got an answer: the name the other
    /// domains of a run sign in with ([`collect_domains`]).
    pub signed_in_as: Option<String>,
    /// When the read started, when it resumed an earlier one (Unix time):
    /// the run is dated by when it finished.
    pub read_started: Option<i64>,
    /// LDAPS was asked for but failed on a domain controller, which was
    /// read over plain LDAP (`--ldaps` with `--allow-unencrypted-ldap`);
    /// the warnings name it.
    pub plain_ldap: bool,
}

/// Returned (inside `anyhow::Error`) when the `cancel` flag stopped a
/// collection. Check with `err.is::<Cancelled>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("collection cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Whether this build includes the built-in collector.
pub const fn builtin_available() -> bool {
    cfg!(feature = "builtin")
}

/// What the domains of one run share: the Kerberos ticket the
/// account got from its own domain's domain controller, verified over
/// LDAPS, so the trusted domains' computers are read with it, through the
/// trust, rather than with a ticket asked of each trusted domain (whose
/// controller doesn't know the account). The ticket cache is deleted when
/// the last copy is dropped.
#[derive(Clone, Default)]
pub struct RunSignIn {
    #[cfg(feature = "builtin")]
    pub(crate) home: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<builtin::HomeTicket>>>>,
    /// Several domains share it: a connection check keeps its ticket too.
    shared: bool,
}

impl std::fmt::Debug for RunSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunSignIn")
    }
}

impl RunSignIn {
    /// For the domains of one run ([`collect_domains`], [`test_domains`]).
    pub fn several() -> Self {
        Self {
            #[cfg(feature = "builtin")]
            home: Default::default(),
            shared: true,
        }
    }

    /// Whether several domains share it.
    #[cfg_attr(not(feature = "builtin"), allow(dead_code))]
    pub(crate) fn shared(&self) -> bool {
        self.shared
    }

    /// Whether a domain of the run got the account's Kerberos ticket.
    pub(crate) fn has_home(&self) -> bool {
        #[cfg(feature = "builtin")]
        {
            self.home().is_some()
        }
        #[cfg(not(feature = "builtin"))]
        {
            false
        }
    }
}

#[cfg(feature = "builtin")]
impl RunSignIn {
    /// The ticket of the account's own domain, once one domain got it.
    pub(crate) fn home(&self) -> Option<std::sync::Arc<builtin::HomeTicket>> {
        self.home.lock().ok().and_then(|h| h.clone())
    }

    /// Keeps `t` for the other domains, unless one is kept already.
    pub(crate) fn keep(&self, t: builtin::HomeTicket) -> std::sync::Arc<builtin::HomeTicket> {
        let mut h = self.home.lock().unwrap_or_else(|e| e.into_inner());
        h.get_or_insert_with(|| std::sync::Arc::new(t)).clone()
    }
}

/// Runs a collection. Blocks until it finishes, fails, or `cancel` is set
/// (then returns a [`Cancelled`] error and removes partial output).
///
/// Call it from a background thread; `progress` is called on the calling
/// thread. Only one built-in collection can run at a time per process.
pub fn collect(
    req: &CollectRequest,
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    collect_with(req, &RunSignIn::default(), progress, cancel)
}

/// [`collect`], as one domain of a run of several ([`collect_domains`]):
/// with Kerberos only, the account's ticket comes from `sign_in` when this
/// domain isn't the account's own, and is kept there when it is.
pub fn collect_with(
    req: &CollectRequest,
    sign_in: &RunSignIn,
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    validate(req)?;
    let others = output::prepare_dir(&req.output_dir).map_err(|e| {
        anyhow::anyhow!(
            "cannot create output directory {}: {e}",
            req.output_dir.display()
        )
    })?;
    let mut rep = Reporter::new(steps_for(req), progress);
    rep.log(format!(
        "Output goes to {} only. It is a full map of the directory (accounts, groups, \
         permissions): keep it as sensitive as the domain itself.",
        req.output_dir.display()
    ));
    let exposed = (!others.is_empty()).then(|| output::exposure_warning(&req.output_dir, &others));
    if let Some(w) = &exposed {
        rep.log(format!("warning: {w}"));
    }
    rep.emit();
    let mut outcome = if exposed.is_some() {
        // Others can open the folder: collect into a private folder inside
        // it, so no file is ever readable by them, then move the files out
        // with their own permissions.
        let staging = output::staging_dir(&req.output_dir).map_err(|e| {
            anyhow::anyhow!(
                "cannot create a private folder in {}: {e}",
                req.output_dir.display()
            )
        })?;
        let staged = req.writing_to(staging.clone());
        let result = run_method(&staged, sign_in, &mut rep, cancel).and_then(|mut outcome| {
            outcome.files = output::publish(&outcome.files, &req.output_dir)?;
            Ok(outcome)
        });
        drop(staged);
        // Created above, private and only ever written by the collector.
        let _ = std::fs::remove_dir_all(&staging);
        result?
    } else {
        let outcome = run_method(req, sign_in, &mut rep, cancel)?;
        output::restrict_permissions(&outcome.files);
        outcome
    };
    outcome.warnings.extend(exposed);
    if let Some(t) = outcome.timings.as_mut() {
        // So a run is only compared with one collected the same way.
        let all = match req.scope {
            Scope::All => true,
            Scope::DcOnly => false,
            Scope::Default => !matches!(req.method, Method::Builtin),
        };
        t.scope = Some(if all { "all" } else { "dc-only" }.into());
    }
    rep.enter("write");
    for (kind, count) in summarize_outputs(&outcome.files) {
        rep.objects(kind, count);
    }
    if outcome.files.is_empty() {
        anyhow::bail!(
            "the collector finished but wrote no .zip or .json files to {}",
            req.output_dir.display()
        );
    }
    rep.finish();
    outcome.warnings.sort();
    outcome.warnings.dedup();
    Ok(outcome)
}

/// Runs the request's collector, writing to `req.output_dir`. Errors that a
/// person can act on (DNS, refused, certificate, password, ...) come back as
/// a [`ConnectionError`], whose message says what to do first.
fn run_method(
    req: &CollectRequest,
    sign_in: &RunSignIn,
    rep: &mut Reporter,
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    let result = match &req.method {
        Method::Builtin => run_builtin(req, sign_in, rep, cancel),
        Method::External { program, kind } => external::run(req, program, *kind, rep, cancel),
    };
    result.map_err(explained)
}

/// A collector error as a [`ConnectionError`] when it is one a person can
/// act on; otherwise unchanged.
fn explained(e: anyhow::Error) -> anyhow::Error {
    if e.is::<Cancelled>()
        || e.is::<ConnectionError>()
        || e.is::<NoSpace>()
        || e.is::<ReadStopped>()
    {
        return e;
    }
    let detail = one_line(&format!("{e:#}"));
    match Problem::classify(&detail) {
        Problem::Other | Problem::Settings | Problem::NoBuiltin => e,
        problem => ConnectionError {
            problem,
            detail,
            headline: None,
        }
        .into(),
    }
}

#[cfg(feature = "builtin")]
fn run_builtin(
    req: &CollectRequest,
    sign_in: &RunSignIn,
    rep: &mut Reporter,
    cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    builtin::run(req, sign_in, rep, cancel)
}

#[cfg(not(feature = "builtin"))]
fn run_builtin(
    _req: &CollectRequest,
    _sign_in: &RunSignIn,
    _rep: &mut Reporter,
    _cancel: &AtomicBool,
) -> anyhow::Result<Outcome> {
    anyhow::bail!(
        "this Pathwarden build has no built-in collector (built without the `builtin` \
         feature); use --sharphound or --rusthound"
    )
}

/// Checks a request before anything touches the network or disk.
fn validate(req: &CollectRequest) -> anyhow::Result<()> {
    validate_target(req)?;
    if req.output_dir.as_os_str().is_empty() {
        anyhow::bail!("an output directory is required");
    }
    Ok(())
}

/// Everything [`validate`] checks except the output directory, which a
/// connection test does not need.
pub(crate) fn validate_target(req: &CollectRequest) -> anyhow::Result<()> {
    let domain = req.domain.trim();
    if domain.is_empty() {
        anyhow::bail!("a domain is required, e.g. contoso.local");
    }
    if !is_host_like(domain) {
        anyhow::bail!("'{domain}' does not look like a DNS domain name");
    }
    if let Some(server) = &req.server {
        if !is_host_like(server) {
            anyhow::bail!("'{server}' does not look like a host name or address");
        }
    }
    if let Auth::Password { user, password } = &req.auth {
        if user.trim().is_empty() {
            anyhow::bail!("a user name is required for password authentication");
        }
        if password.is_empty() {
            anyhow::bail!("the password is empty");
        }
    }
    match &req.method {
        Method::External { program, .. } => check_program(program)?,
        #[cfg(feature = "builtin")]
        Method::Builtin => {
            builtin::plan(req)?;
        }
        #[cfg(not(feature = "builtin"))]
        Method::Builtin => {}
    }
    Ok(())
}

/// `s` as one clean line: control characters (AD ends its LDAP diagnostic
/// text with a NUL) are dropped, and runs of whitespace, line breaks
/// included (RustHound-CE pads some messages with dozens of spaces), become
/// one space.
pub(crate) fn one_line(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Letters, digits, `.`, `-`, `_` and `:` (IPv6) only: anything else could
/// be an option or a shell metacharacter when passed to an external tool.
fn is_host_like(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// An external collector's program as given on the command line, as the
/// full path it is run from. A path with a folder in it
/// (`.\SharpHound.exe`, `tools\SharpHound.exe`, `./rusthound-ce`) is
/// resolved against the current folder, as scheduled tasks from before 0.3
/// give it; a bare file name (`SharpHound.exe`) is refused, so nothing is
/// ever looked up in the current folder or on PATH. A network or device
/// path is refused before anything looks at it, as given and once
/// resolved (the current folder may be a share): even checking that
/// `\\server\share\x.exe` exists makes Windows sign in to that server as
/// the user. The file system isn't touched.
pub fn resolve_program(program: &Path) -> anyhow::Result<PathBuf> {
    let network = |p: &Path| -> anyhow::Result<()> {
        if pathwarden_core::plugins::is_network_path(&p.to_string_lossy()) {
            anyhow::bail!(
                "collector program {} is a network or device path: copy it to this computer and \
                 give its local path (even checking a network path makes Windows sign in to that \
                 server as you)",
                p.display()
            );
        }
        Ok(())
    };
    network(program)?;
    if program.is_absolute() {
        return Ok(program.to_path_buf());
    }
    let has_folder = program.parent().is_some_and(|p| !p.as_os_str().is_empty());
    if !has_folder {
        anyhow::bail!(
            "collector program {}: give its full path, like {} (collectors are never looked up in \
             the current folder or on PATH)",
            program.display(),
            if cfg!(windows) {
                r"C:\Tools\SharpHound.exe"
            } else {
                "/opt/rusthound-ce/rusthound-ce"
            }
        );
    }
    let full = std::path::absolute(program)
        .map_err(|e| anyhow::anyhow!("collector program {}: {e}", program.display()))?;
    network(&full)?;
    Ok(full)
}

/// An external collector's program: a file on this computer, by its full
/// path or one [`resolve_program`] resolves. The network check comes before
/// the file system is touched.
fn check_program(program: &Path) -> anyhow::Result<()> {
    let program = resolve_program(program)?;
    let program = program.as_path();
    if !program.is_absolute() {
        anyhow::bail!(
            "collector program {}: give its full path, like {} (collectors are never looked up in \
             the current folder or on PATH)",
            program.display(),
            if cfg!(windows) {
                r"C:\Tools\SharpHound.exe"
            } else {
                "/opt/rusthound-ce/rusthound-ce"
            }
        );
    }
    match std::fs::metadata(program) {
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("{} is not a file", program.display()),
        Err(e) => anyhow::bail!("collector program {}: {e}", program.display()),
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
