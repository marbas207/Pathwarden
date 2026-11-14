//! Several domains in one run: the domain asked for and trusted
//! domains, collected one after another with the same sign-in, each into
//! its own folder, then analyzed together. A domain that fails is skipped;
//! the others still count.
//!
//! With Kerberos only and a password, the account's ticket comes from the
//! first domain's domain controller, verified over LDAPS, and the trusted
//! domains' computers are read with it through the trust
//! ([`crate::RunSignIn`]): a trusted domain's controller doesn't know the
//! account, so it can't give it a ticket. The app's Collect page and
//! `pathwarden collect --domain A --domain B` both run [`collect_domains`]
//! and check with [`test_domains`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{
    is_scope_note, summarize_outputs, Auth, Cancelled, CollectRequest, ConnectionCheck,
    ConnectionError, Outcome, Problem, Progress, RunSignIn,
};

/// One domain of a run of several started, finished or failed.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainEvent {
    /// 0 for the first domain.
    pub index: usize,
    pub total: usize,
    pub domain: String,
    pub state: DomainState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DomainState {
    Started,
    Done {
        seconds: u64,
        objects: usize,
    },
    /// `reason` in one short sentence ([`short_reason`]), `detail` behind it.
    Failed {
        reason: String,
        detail: String,
    },
}

/// What collecting one domain of a run gave.
#[derive(Debug)]
pub struct DomainResult {
    pub domain: String,
    pub outcome: anyhow::Result<Outcome>,
    pub elapsed: Duration,
}

impl DomainResult {
    /// Objects written, by every type.
    pub fn objects(&self) -> usize {
        match &self.outcome {
            Ok(o) => summarize_outputs(&o.files).iter().map(|(_, n)| n).sum(),
            Err(_) => 0,
        }
    }

    /// Why it failed, short and in full ([`short_reason`]).
    pub fn failure(&self) -> Option<(String, String)> {
        self.outcome.as_ref().err().map(short_reason)
    }

    /// Why it failed, for its line in the table at the end of a run of
    /// several (the command line's): [`short_reason`], except that a
    /// certificate problem names the domain's own controller ("Its domain
    /// controller's certificate wasn't accepted."), checked and rejected or
    /// not checked at all, and that when no domain controller was found
    ///  it says how to name one ("Name one with --server
    /// fabrikam.com=HOST.").
    pub fn table_reason(&self) -> Option<String> {
        let e = self.outcome.as_ref().err()?;
        Some(match problem_of(e) {
            Problem::CertificateUntrusted
            | Problem::CertificateName
            | Problem::CertificateExpired => CERT_REJECTED.to_string(),
            Problem::Tls => CERT_UNCHECKED.to_string(),
            Problem::NotLocated => format!(
                "{} Name one with --server {}=HOST.",
                short_reason(e).0,
                self.domain
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            ),
            _ => short_reason(e).0,
        })
    }

    /// Why it failed, as a run's record keeps it for the app's Run details
    /// ([`DomainResult::failure`]): when no domain controller was found,
    /// with where to name one, in plain words.
    pub fn saved_failure(&self) -> Option<(String, String)> {
        let (reason, detail) = self.failure()?;
        Some(if self.not_located() {
            (format!("{reason} {NAME_IN_FIELD}"), detail)
        } else {
            (reason, detail)
        })
    }

    /// Whether it failed because no domain controller of it was found,
    /// and its domain's name didn't do either.
    pub fn not_located(&self) -> bool {
        self.outcome
            .as_ref()
            .err()
            .is_some_and(|e| problem_of(e) == Problem::NotLocated)
    }

    /// Whether it failed on its domain controller's certificate.
    pub fn certificate_failed(&self) -> bool {
        self.outcome.as_ref().err().is_some_and(|e| {
            matches!(
                problem_of(e),
                Problem::CertificateUntrusted
                    | Problem::CertificateName
                    | Problem::CertificateExpired
                    | Problem::Tls
            )
        })
    }
}

/// A trusted domain's line: its controller's certificate was checked and
/// rejected (untrusted, another name, expired).
pub const CERT_REJECTED: &str = "Its domain controller's certificate wasn't accepted.";
/// A trusted domain's line: the encrypted connection failed before its
/// certificate could be checked.
pub const CERT_UNCHECKED: &str = "Its domain controller's certificate couldn't be checked.";
/// After a trusted domain's reason when no domain controller of it was
/// found, in the app: where to name one.
pub const NAME_IN_FIELD: &str = "Enter one in its Domain controller field.";

fn problem_of(e: &anyhow::Error) -> Problem {
    match e.downcast_ref::<ConnectionError>() {
        Some(ce) => ce.problem,
        None => Problem::classify(&crate::one_line(&format!("{e:#}"))),
    }
}

/// Why a domain failed: one short sentence for its line ("Couldn't reach a
/// domain controller."), and what to do with the technical detail, for
/// behind it.
pub fn short_reason(e: &anyhow::Error) -> (String, String) {
    if let Some(ce) = e.downcast_ref::<ConnectionError>() {
        let short = match ce.problem {
            Problem::Settings => sentence(&ce.detail),
            // It names the domain.
            Problem::NotLocated => ce.message(),
            p => p.short().to_string(),
        };
        let detail = match ce.problem {
            Problem::Settings => String::new(),
            Problem::NotLocated => ce.detail.clone(),
            _ => format!("{} ({})", ce.message(), ce.detail),
        };
        return (short, detail);
    }
    let text = crate::one_line(&format!("{e:#}"));
    match Problem::classify(&text) {
        Problem::Other | Problem::Settings => (Problem::Other.short().to_string(), text),
        p => (p.short().to_string(), format!("{} ({text})", p.explain())),
    }
}

/// `s` as a sentence: a capital first letter and a full stop.
fn sentence(s: &str) -> String {
    let s = s.trim();
    let mut c = s.chars();
    let mut out: String = match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// The folder a domain of a run of several collects into, in `out`: its
/// name, lower case. One analysis reads `out` with every domain in it.
pub fn domain_folder(out: &Path, domain: &str) -> PathBuf {
    out.join(domain.trim().trim_end_matches('.').to_ascii_lowercase())
}

/// The run's domains: the request's, then the trusted ones, each once (any
/// case).
fn run_domains(req: &CollectRequest, trusted: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in std::iter::once(&req.domain).chain(trusted) {
        let d = d.trim().trim_end_matches('.');
        if !d.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(d)) {
            out.push(d.to_string());
        }
    }
    out
}

/// The name a trusted domain is signed in to with a password: the account
/// the first domain's directory named (`DOMAIN\user`), which a trusted
/// domain's controller passes on to the account's domain; before that
/// answer, the name as typed, with the first domain's name when it has
/// none (a bare name would be looked up in the trusted domain).
fn trusted_user(typed: &str, home: &str, signed_in_as: Option<&str>) -> String {
    match signed_in_as {
        Some(who) if who.contains('\\') => who.to_string(),
        _ if typed.contains('\\') || typed.contains('@') => typed.trim().to_string(),
        _ => format!("{home}\\{}", typed.trim()),
    }
}

impl CollectRequest {
    /// The same request for `domain`, another domain of its run: into
    /// `output_dir`; its domain controller the one `servers` names, else
    /// one found by its full name ([`crate::locate`]: the one chosen is the
    /// first domain's); signed in as `user` with a password.
    pub(crate) fn for_domain(&self, domain: &str, output_dir: PathBuf, user: Option<&str>) -> Self {
        let mut r = self.writing_to(output_dir);
        r.domain = domain.to_string();
        r.server = server_for(&self.servers, domain);
        r.locate_dc = r.server.is_none();
        r.expected_objects = None;
        // Its read on disk too, in its own folder of the same cache;
        // the first domain's last size is no estimate of this one's.
        r.cache = r.cache.map(|c| crate::ReadCache {
            root: c.root,
            resume: c.resume,
            ..crate::ReadCache::default()
        });
        if let (Some(u), Auth::Password { user, .. }) = (user, &mut r.auth) {
            *user = u.to_string();
        }
        r
    }
}

/// The domain controller `servers` names for `domain` (any case).
pub(crate) fn server_for(servers: &[(String, String)], domain: &str) -> Option<String> {
    let d = domain.trim().trim_end_matches('.');
    servers
        .iter()
        .find(|(n, _)| n.trim_end_matches('.').eq_ignore_ascii_case(d))
        .map(|(_, h)| h.clone())
}

/// The domains `servers` names that a run of `first` and `trusted` doesn't
/// collect as a trusted domain: likely a typing slip, so the run stops
/// before it starts.
pub fn unused_servers(
    first: &str,
    servers: &[(String, String)],
    trusted: &[String],
) -> Vec<String> {
    let domains = run_domains(&CollectRequest::new(first, ""), trusted);
    servers
        .iter()
        .map(|(d, _)| d.clone())
        .filter(|d| {
            !domains
                .iter()
                .skip(1)
                .any(|o| o.eq_ignore_ascii_case(d.trim_end_matches('.')))
        })
        .collect()
}

/// Whether `domain` (a `--server DOMAIN=HOST` domain) may be the domain of
/// the account `user` as typed: its DNS domain (`user@dns`,
/// `DNS\user`), or a NetBIOS name (`NAME\user`) that is the first label of
/// `domain`. Such a domain controller is used only for the account's own
/// domain as the directory names it, and is checked over LDAPS like any.
pub fn names_account_domain(user: Option<&str>, domain: &str) -> bool {
    let Some(user) = user.map(str::trim) else {
        return false;
    };
    let domain = domain.trim().trim_end_matches('.');
    let typed = match user.split_once('\\') {
        Some((d, _)) => d,
        None => match user.rsplit_once('@') {
            Some((_, d)) => d,
            None => return false,
        },
    };
    let typed = typed.trim().trim_end_matches('.');
    !typed.is_empty()
        && (typed.eq_ignore_ascii_case(domain)
            || (!typed.contains('.')
                && user.contains('\\')
                && domain
                    .split('.')
                    .next()
                    .is_some_and(|l| l.eq_ignore_ascii_case(typed))))
}

/// The requests of a run, in order: the first is `req` itself, into its
/// own folder when there are several.
fn legs(
    req: &CollectRequest,
    domains: &[String],
    signed_in_as: Option<&str>,
    index: usize,
) -> CollectRequest {
    let d = &domains[index];
    let out = domain_folder(&req.output_dir, d);
    if index == 0 {
        let mut r = req.writing_to(out);
        r.domain = d.clone();
        return r;
    }
    let user = match &req.auth {
        Auth::Password { user, .. } => Some(trusted_user(user, &domains[0], signed_in_as)),
        _ => None,
    };
    req.for_domain(d, out, user.as_deref())
}

/// Why a trusted domain isn't contacted: with Kerberos only and a password,
/// it is read with the first domain's ticket, and there is none.
pub const NO_FIRST_TICKET: &str = "The first domain gave no Kerberos ticket.";

/// Whether the trusted domain at `index` must be skipped without being
/// contacted: Kerberos only with a password needs the first domain's
/// ticket, and the first domain gave none. Contacting it anyway would send
/// it an NTLM sign-in and, for the check, a ticket request salted with the
/// password, both for nothing.
fn needs_first_ticket(req: &CollectRequest, index: usize, sign_in: &RunSignIn) -> bool {
    index > 0
        && cfg!(feature = "builtin")
        && req.method == crate::Method::Builtin
        && matches!(req.auth, Auth::Password { .. })
        && !req.allow_ntlm
        && !sign_in.has_home()
}

fn no_first_ticket() -> anyhow::Error {
    ConnectionError::settings(NO_FIRST_TICKET).into()
}

/// Collects `req`'s domain, then each of `trusted`, one after
/// another with the same sign-in. With no trusted domain it is
/// [`crate::collect`], into `req.output_dir`; with some, each domain goes
/// into its own folder there ([`domain_folder`]). `progress` gets a
/// [`Progress::Domain`] as each starts and ends, and that domain's progress
/// in between.
///
/// A domain that fails doesn't stop the others: its result says why.
/// Cancelling stops them all ([`Cancelled`]), and what they wrote is
/// removed.
pub fn collect_domains(
    req: &CollectRequest,
    trusted: &[String],
    progress: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> anyhow::Result<Vec<DomainResult>> {
    let domains = run_domains(req, trusted);
    if domains.len() <= 1 {
        let started = Instant::now();
        let outcome = crate::collect(req, progress, cancel);
        if cancel.load(Ordering::SeqCst) || outcome.as_ref().is_err_and(|e| e.is::<Cancelled>()) {
            return Err(Cancelled.into());
        }
        return Ok(vec![DomainResult {
            domain: req.domain.trim().to_string(),
            outcome,
            elapsed: started.elapsed(),
        }]);
    }
    let total = domains.len();
    if cancel.load(Ordering::SeqCst) {
        return Err(Cancelled.into());
    }
    // The run's folder, private when made here; each domain's folder in it
    // is checked as one collection's.
    crate::output::prepare_dir(&req.output_dir).map_err(|e| {
        anyhow::anyhow!(
            "cannot create output directory {}: {e}",
            req.output_dir.display()
        )
    })?;
    let sign_in = RunSignIn::several();
    let mut signed_in_as: Option<String> = None;
    let mut results = Vec::with_capacity(total);
    for index in 0..total {
        if cancel.load(Ordering::SeqCst) {
            return Err(Cancelled.into());
        }
        let domain = domains[index].clone();
        let event = |state| {
            Progress::Domain(DomainEvent {
                index,
                total,
                domain: domain.clone(),
                state,
            })
        };
        progress(event(DomainState::Started));
        progress(Progress::Log(format!(
            "Domain {} of {total}: {domain}",
            index + 1
        )));
        let started = Instant::now();
        let outcome = if needs_first_ticket(req, index, &sign_in) {
            Err(no_first_ticket())
        } else {
            let leg = legs(req, &domains, signed_in_as.as_deref(), index);
            let outcome = crate::collect_with(&leg, &sign_in, progress, cancel);
            // Zeroes this domain's copy of the password.
            drop(leg);
            outcome
        };
        if cancel.load(Ordering::SeqCst) || outcome.as_ref().is_err_and(|e| e.is::<Cancelled>()) {
            return Err(Cancelled.into());
        }
        let result = DomainResult {
            domain: domain.clone(),
            outcome,
            elapsed: started.elapsed(),
        };
        match &result.outcome {
            Ok(o) => {
                if signed_in_as.is_none() {
                    signed_in_as = o.signed_in_as.clone();
                }
                progress(event(DomainState::Done {
                    seconds: result.elapsed.as_secs(),
                    objects: result.objects(),
                }));
            }
            Err(e) => {
                let (reason, detail) = short_reason(e);
                progress(Progress::Log(format!(
                    "{}: not collected: {reason} {detail}",
                    result.domain
                )));
                progress(event(DomainState::Failed { reason, detail }));
            }
        }
        results.push(result);
    }
    Ok(results)
}

/// The run's outcome from its domains' ([`collect_domains`]): every file
/// collected, the warnings (each domain's named when there are several;
/// what the chosen depth leaves out said once), and the timings of the
/// first domain that was collected (one domain's, so runs compare more like
/// with like; when the first domain failed, they are another domain's).
pub fn merged(results: &[DomainResult]) -> Outcome {
    let several = results.len() > 1;
    let mut out = Outcome::default();
    for r in results {
        let Ok(o) = &r.outcome else { continue };
        out.files.extend(o.files.iter().cloned());
        for w in &o.warnings {
            let w = if several && !is_scope_note(w) {
                format!("{}: {w}", r.domain.to_ascii_uppercase())
            } else {
                w.clone()
            };
            if !out.warnings.contains(&w) {
                out.warnings.push(w);
            }
        }
        if out.timings.is_none() {
            out.timings = o.timings.clone();
        }
        if out.signed_in_as.is_none() {
            out.signed_in_as = o.signed_in_as.clone();
        }
        // The earliest start of a resumed read.
        out.read_started = match (out.read_started, o.read_started) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    out
}

/// Checks `req`'s domain, then each of `trusted`, as
/// [`collect_domains`] will collect them: with Kerberos only and a password,
/// the first domain's ticket is kept and each trusted domain's domain
/// controller is asked for through the trust with it. Each result is
/// [`crate::test_connection`]'s.
pub fn test_domains(
    req: &CollectRequest,
    trusted: &[String],
) -> Vec<(String, anyhow::Result<ConnectionCheck>)> {
    let domains = run_domains(req, trusted);
    if domains.len() <= 1 {
        return vec![(req.domain.trim().to_string(), crate::test_connection(req))];
    }
    let sign_in = RunSignIn::several();
    let mut signed_in_as: Option<String> = None;
    let mut out = Vec::with_capacity(domains.len());
    for index in 0..domains.len() {
        if needs_first_ticket(req, index, &sign_in) {
            out.push((domains[index].clone(), Err(no_first_ticket())));
            continue;
        }
        let mut leg = legs(req, &domains, signed_in_as.as_deref(), index);
        leg.output_dir = PathBuf::from("connection-check");
        let check = crate::test_connection_with(&leg, &sign_in);
        drop(leg);
        if let (None, Ok(c)) = (&signed_in_as, &check) {
            signed_in_as = c.bound_as.clone();
        }
        out.push((domains[index].clone(), check));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    fn password_req() -> CollectRequest {
        let mut r = CollectRequest::new("contoso.local", "out");
        r.auth = Auth::Password {
            user: "svc".into(),
            password: Secret::new("Pw-Leg-1"),
        };
        r.server = Some("dc01.contoso.local".into());
        r.ldaps = true;
        r.expected_objects = Some(10);
        r
    }

    #[test]
    fn each_domain_once_the_first_first() {
        let r = password_req();
        let d = run_domains(
            &r,
            &[
                "north.contoso.local".into(),
                "CONTOSO.LOCAL".into(),
                "fabrikam.com.".into(),
                "North.Contoso.Local".into(),
                " ".into(),
            ],
        );
        assert_eq!(d, ["contoso.local", "north.contoso.local", "fabrikam.com"]);
    }

    /// A trusted domain: its own folder, its controller from DNS, the
    /// account as the first domain's directory named it.
    #[test]
    fn a_trusted_domain_signs_in_as_the_account() {
        let r = password_req();
        let domains = vec!["contoso.local".to_string(), "fabrikam.com".to_string()];
        let first = legs(&r, &domains, None, 0);
        assert_eq!(first.output_dir, Path::new("out").join("contoso.local"));
        assert_eq!(first.server.as_deref(), Some("dc01.contoso.local"));
        assert_eq!(first.expected_objects, Some(10));
        let second = legs(&r, &domains, Some("CONTOSO\\svc"), 1);
        assert_eq!(second.domain, "fabrikam.com");
        assert_eq!(second.output_dir, Path::new("out").join("fabrikam.com"));
        // No controller named: one is found by its full name.
        assert_eq!(second.server, None);
        assert!(second.locate_dc && !first.locate_dc);
        assert_eq!(second.expected_objects, None);
        assert!(second.ldaps);
        assert!(matches!(&second.auth, Auth::Password { user, password }
            if user == "CONTOSO\\svc" && password.expose() == "Pw-Leg-1"));
        // Each domain's read goes on disk too, in its own folder of the same
        // cache; only the first keeps the last read's size.
        let mut cached = password_req();
        cached.cache = Some(crate::ReadCache {
            root: PathBuf::from("ws/collect-cache"),
            last_entries: Some(5),
            last_bytes: Some(9),
            resume: true,
            ..crate::ReadCache::default()
        });
        let first = legs(&cached, &domains, None, 0);
        assert_eq!(first.cache, cached.cache);
        let second = legs(&cached, &domains, None, 1);
        // Each domain resumes its own read.
        assert_eq!(
            second.cache,
            Some(crate::ReadCache {
                root: PathBuf::from("ws/collect-cache"),
                resume: true,
                ..crate::ReadCache::default()
            })
        );
        // Before the directory answered: the first domain's name.
        let early = legs(&r, &domains, None, 1);
        assert!(matches!(&early.auth, Auth::Password { user, .. } if user == "contoso.local\\svc"));
        assert_eq!(
            trusted_user("svc@contoso.com", "contoso.local", None),
            "svc@contoso.com"
        );
        assert_eq!(
            trusted_user("C\\svc", "contoso.local", Some("dn:x")),
            "C\\svc"
        );
        let mut current = CollectRequest::new("contoso.local", "out");
        current.auth = Auth::CurrentUser;
        assert!(matches!(
            legs(&current, &domains, None, 1).auth,
            Auth::CurrentUser
        ));
    }

    /// A domain controller named for the account's own domain.
    #[test]
    fn a_server_for_the_accounts_domain() {
        for (user, domain) in [
            (Some("svc@Contoso.Local"), "contoso.local"),
            (Some(r"contoso.local\svc"), "CONTOSO.LOCAL."),
            (Some(r"CONTOSO\svc"), "contoso.local"),
        ] {
            assert!(names_account_domain(user, domain), "{user:?} {domain}");
        }
        for (user, domain) in [
            (None, "contoso.local"),
            (Some("svc"), "contoso.local"),
            (Some("svc@contoso"), "contoso.local"),
            (Some(r"FABRIKAM\svc"), "contoso.local"),
            (Some("svc@fabrikam.com"), "contoso.local"),
        ] {
            assert!(!names_account_domain(user, domain), "{user:?} {domain}");
        }
    }

    /// `--server DOMAIN=HOST`: that domain's leg goes to that host
    /// and finds none; the others find theirs; a name the run doesn't
    /// collect is reported.
    #[test]
    fn a_server_named_per_domain() {
        let mut r = password_req();
        r.servers = vec![
            ("Fabrikam.com.".into(), "dc07.fabrikam.com".into()),
            ("typo.example".into(), "dc.typo.example".into()),
        ];
        let domains = vec![
            "contoso.local".to_string(),
            "FABRIKAM.COM".to_string(),
            "tailspin.com".to_string(),
        ];
        let first = legs(&r, &domains, None, 0);
        assert_eq!(first.server.as_deref(), Some("dc01.contoso.local"));
        let named = legs(&r, &domains, None, 1);
        assert_eq!(named.server.as_deref(), Some("dc07.fabrikam.com"));
        assert!(!named.locate_dc);
        let found = legs(&r, &domains, None, 2);
        assert_eq!((found.server, found.locate_dc), (None, true));
        assert_eq!(
            unused_servers(&r.domain, &r.servers, &domains[1..]),
            ["typo.example".to_string()]
        );
        r.servers.pop();
        assert!(unused_servers(&r.domain, &r.servers, &domains[1..]).is_empty());
        // The first domain's own name isn't another domain's.
        r.servers = vec![("contoso.local".into(), "x".into())];
        assert_eq!(
            unused_servers(&r.domain, &r.servers, &[]),
            ["contoso.local".to_string()]
        );
    }

    /// Kerberos only with a password: a trusted domain is read with the
    /// first domain's ticket, so without one it isn't contacted at all; as
    /// the Windows account, or with NTLM allowed, it is.
    #[test]
    fn no_first_ticket_no_trusted_domain() {
        let r = password_req();
        let none = RunSignIn::several();
        assert!(!needs_first_ticket(&r, 0, &none), "the first is its own");
        assert_eq!(needs_first_ticket(&r, 1, &none), cfg!(feature = "builtin"));
        let mut ntlm = password_req();
        ntlm.allow_ntlm = true;
        assert!(!needs_first_ticket(&ntlm, 1, &none));
        let mut me = password_req();
        me.auth = Auth::CurrentUser;
        assert!(!needs_first_ticket(&me, 1, &none));
        let (short, detail) = short_reason(&no_first_ticket());
        assert_eq!((short.as_str(), detail.as_str()), (NO_FIRST_TICKET, ""));
    }

    /// The first domain's check fails (no such domain): the trusted domain
    /// is skipped with the reason, never asked.
    #[cfg(feature = "builtin")]
    #[test]
    fn a_failed_first_check_skips_the_trusted_domains() {
        let mut r = password_req();
        r.domain = "contoso.invalid".into();
        r.server = None;
        let checks = test_domains(&r, &["fabrikam.invalid".into()]);
        assert_eq!(checks.len(), 2);
        assert!(checks[0].1.is_err());
        let e = checks[1].1.as_ref().unwrap_err();
        assert_eq!(short_reason(e).0, NO_FIRST_TICKET);
    }

    #[test]
    fn reasons_are_short_with_the_detail_behind() {
        let e: anyhow::Error = ConnectionError::new(
            "cannot connect to ldaps://dc01.fabrikam.com:636: I/O error: No connection could be \
             made because the target machine actively refused it. (os error 10061)",
        )
        .into();
        let (short, detail) = short_reason(&e);
        assert_eq!(short, "Couldn't reach a domain controller.");
        assert!(
            detail.starts_with("The domain controller refused the connection."),
            "{detail}"
        );
        assert!(detail.contains("os error 10061"), "{detail}");
        let e = anyhow::anyhow!("NTLM bind as CONTOSO\\svc failed: rc=49 (invalidCredentials)");
        assert_eq!(short_reason(&e).0, "The sign-in was refused.");
        let e: anyhow::Error = ConnectionError::no_ticket(
            "Kerberos didn't work: this computer's clock is 9 minutes off dc01's.",
            "KRB_AP_ERR_SKEW (37)",
        )
        .into();
        let (short, detail) = short_reason(&e);
        assert_eq!(short, "Kerberos didn't work.");
        assert!(detail.contains("9 minutes"), "{detail}");
        let (short, detail) = short_reason(&anyhow::anyhow!("the collector crashed: x"));
        assert_eq!(short, "The collection failed.");
        assert_eq!(detail, "the collector crashed: x");
    }

    /// The table's line for a certificate problem names the domain's own
    /// controller; elsewhere the general wording stays.
    #[test]
    fn a_certificate_problem_in_the_table() {
        let failed = |e: anyhow::Error| DomainResult {
            domain: "fabrikam.com".into(),
            outcome: Err(e),
            elapsed: Duration::from_secs(1),
        };
        let name = failed(
            ConnectionError::new(
                "rustls error: invalid peer certificate: certificate not valid for name \
                 \"fabrikam.com\"",
            )
            .into(),
        );
        assert_eq!(name.table_reason().as_deref(), Some(CERT_REJECTED));
        assert!(name.certificate_failed());
        assert_eq!(
            name.failure().unwrap().0,
            "The domain controller's certificate wasn't accepted."
        );
        let tls = failed(anyhow::anyhow!("TLS handshake failed: eof"));
        assert_eq!(tls.table_reason().as_deref(), Some(CERT_UNCHECKED));
        assert!(tls.certificate_failed());
        let refused = failed(anyhow::anyhow!("rc=49 (invalidCredentials)"));
        assert_eq!(
            refused.table_reason().as_deref(),
            Some("The sign-in was refused.")
        );
        assert!(!refused.certificate_failed());
        assert!(!refused.not_located());
        assert_eq!(refused.saved_failure(), refused.failure());
    }

    /// No domain controller found: one sentence naming the domain,
    /// what each way said behind it; on the command line's table, how to
    /// name one there; in the run's record, where in the app.
    #[test]
    fn no_domain_controller_found() {
        let found = crate::locate::not_found("fabrikam.com");
        let none = crate::locate::NotFound {
            why: "DsGetDcName found none: error 1355; DNS found none: no such name (DNS error \
                  9003)"
                .into(),
            found: false,
            outside: false,
        };
        let e = crate::locate::not_located(
            "fabrikam.com",
            &none,
            Problem::Dns,
            "no such host is known. (os error 11001)",
        )
        .unwrap();
        let r = DomainResult {
            domain: "FABRIKAM.COM".into(),
            outcome: Err(e.into()),
            elapsed: Duration::from_secs(1),
        };
        assert!(r.not_located() && !r.certificate_failed());
        let (short, detail) = r.failure().unwrap();
        assert_eq!(short, found);
        assert_eq!(
            detail,
            "DsGetDcName found none: error 1355; DNS found none: no such name (DNS error 9003); \
             then by the domain's name: no such host is known. (os error 11001)"
        );
        assert_eq!(
            r.table_reason().unwrap(),
            format!("{found} Name one with --server fabrikam.com=HOST.")
        );
        let (saved, saved_detail) = r.saved_failure().unwrap();
        assert_eq!(
            saved,
            format!("{found} Enter one in its Domain controller field.")
        );
        assert!(!saved.contains("--"), "{saved}");
        assert_eq!(saved_detail, detail);

        // Some found, none answered: the old wording, no hint.
        let down = crate::locate::NotFound {
            why: "meereen.essos.local (from DNS) didn't answer on port 636".into(),
            found: true,
            outside: false,
        };
        let e = crate::locate::not_located("essos.local", &down, Problem::Timeout, "timed out")
            .unwrap();
        let r = DomainResult {
            domain: "ESSOS.LOCAL".into(),
            outcome: Err(e.into()),
            elapsed: Duration::from_secs(1),
        };
        assert!(!r.not_located());
        let (short, detail) = r.failure().unwrap();
        assert_eq!(short, "Couldn't reach a domain controller.");
        assert!(
            detail.contains("meereen.essos.local (from DNS)"),
            "{detail}"
        );
        assert_eq!(r.table_reason().as_deref(), Some(short.as_str()));
        assert_eq!(r.saved_failure().unwrap().0, short);
    }

    #[test]
    fn merged_names_each_domains_warnings() {
        let ok = |files: &[&str], warnings: &[&str]| Outcome {
            files: files.iter().map(PathBuf::from).collect(),
            warnings: warnings.iter().map(|w| w.to_string()).collect(),
            timings: None,
            signed_in_as: Some("CONTOSO\\svc".into()),
            read_started: None,
        };
        let results = vec![
            DomainResult {
                domain: "contoso.local".into(),
                outcome: Ok(ok(
                    &["a.zip"],
                    &[crate::NO_SESSIONS_NOTE, "2 computers were skipped."],
                )),
                elapsed: Duration::from_secs(1),
            },
            DomainResult {
                domain: "fabrikam.com".into(),
                outcome: Err(anyhow::anyhow!("x")),
                elapsed: Duration::from_secs(1),
            },
            DomainResult {
                domain: "north.contoso.local".into(),
                outcome: Ok(ok(&["b.zip"], &[crate::NO_SESSIONS_NOTE])),
                elapsed: Duration::from_secs(1),
            },
        ];
        let m = merged(&results);
        assert_eq!(m.files, [PathBuf::from("a.zip"), PathBuf::from("b.zip")]);
        assert_eq!(
            m.warnings,
            [
                crate::NO_SESSIONS_NOTE.to_string(),
                "CONTOSO.LOCAL: 2 computers were skipped.".to_string()
            ]
        );
        assert_eq!(m.signed_in_as.as_deref(), Some("CONTOSO\\svc"));
        // One domain: its warnings as they are.
        let one = merged(&results[..1]);
        assert_eq!(one.warnings[1], "2 computers were skipped.");
    }

    /// A domain that can't be reached fails on its own; the run goes on to
    /// the next, and each says so as it starts and ends.
    #[test]
    fn a_failed_domain_doesnt_stop_the_others() {
        let dir = std::env::temp_dir().join(format!("pw-domains-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut r = CollectRequest::new("contoso.invalid", &dir);
        // Nothing to run: each domain fails at once, before any network.
        r.method = crate::Method::External {
            program: dir.join("no-such-SharpHound.exe"),
            kind: crate::ExternalKind::SharpHound,
        };
        let mut events = Vec::new();
        let results = collect_domains(
            &r,
            &["fabrikam.invalid".into()],
            &mut |p| {
                if let Progress::Domain(e) = p {
                    events.push((
                        e.index,
                        e.total,
                        e.domain,
                        matches!(e.state, DomainState::Failed { .. }),
                    ));
                }
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.outcome.is_err()));
        assert_eq!(
            events,
            [
                (0, 2, "contoso.invalid".to_string(), false),
                (0, 2, "contoso.invalid".to_string(), true),
                (1, 2, "fabrikam.invalid".to_string(), false),
                (1, 2, "fabrikam.invalid".to_string(), true),
            ]
        );
        assert!(results[1].failure().is_some());
        let cancelled = collect_domains(
            &r,
            &["x.invalid".into()],
            &mut |_| {},
            &AtomicBool::new(true),
        );
        assert!(cancelled.unwrap_err().is::<Cancelled>());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
