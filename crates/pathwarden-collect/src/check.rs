//! Checking a collection's settings before running it: for the built-in
//! collector, connect, read the RootDSE, bind and count users and computers;
//! for an external collector, check that the program exists.
//!
//! Errors carry a [`Problem`] with a plain-language explanation, for people
//! who don't read LDAP result codes.

use std::fmt;
use std::path::PathBuf;

use crate::{CollectRequest, ExternalKind, Method};

/// What a successful check found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectionCheck {
    /// The domain controller that answered (its `dnsHostName`), when known.
    pub server: Option<String>,
    /// Who the bind authenticated as, e.g. `CONTOSO\alice` (from LDAP
    /// "Who am I?"), when the server says.
    pub bound_as: Option<String>,
    /// The domain's naming context, e.g. `DC=contoso,DC=local`.
    pub naming_context: Option<String>,
    /// Enabled and disabled user accounts, when they could be counted quickly.
    pub users: Option<Count>,
    /// Computer accounts, when they could be counted quickly.
    pub computers: Option<Count>,
    /// For an external collector: the program that was found.
    pub program: Option<PathBuf>,
    /// Things to know before collecting (e.g. certificate checks are off).
    pub warnings: Vec<String>,
    /// Kerberos only with a password: the ticket the check got for
    /// reading computers, in a sentence ("Got a Kerberos ticket for
    /// CONTOSO\svc from dc01.contoso.local.").
    pub kerberos: Option<String>,
}

/// An object count that may have been cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub n: usize,
    /// Counting stopped at the time limit: there are at least `n`.
    pub at_least: bool,
}

/// Why a check (or a collection) failed, in terms a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The settings themselves are wrong (the detail says how).
    Settings,
    /// The name did not resolve in DNS.
    Dns,
    /// Nothing listens on the LDAP/LDAPS port, or a firewall said no.
    Refused,
    /// No route to the host.
    Unreachable,
    /// No answer in time.
    Timeout,
    /// The domain controller stopped answering partway through a collection.
    Stalled,
    /// The domain controller belongs to another domain than the one entered.
    WrongDomain,
    /// The LDAPS certificate does not chain to a root this computer trusts.
    CertificateUntrusted,
    /// The LDAPS certificate does not name the host that was contacted.
    CertificateName,
    /// The LDAPS certificate has expired or is not valid yet.
    CertificateExpired,
    /// Another TLS failure.
    Tls,
    /// Wrong user name or password, or the account cannot sign in.
    Credentials,
    /// The DC requires LDAP signing or channel binding.
    SigningRequired,
    /// Signing in as the current Windows user (Kerberos) failed.
    Kerberos,
    /// Kerberos only: no Kerberos ticket could be had for reading
    /// computers. [`ConnectionError::message`] says why (the clock, port
    /// 88, the password).
    NoTicket,
    /// A trusted domain: no domain controller of it was found, and
    /// its domain's name didn't do either. [`ConnectionError::message`]
    /// names the domain; never from [`Problem::classify`].
    NotLocated,
    /// This build has no built-in collector.
    NoBuiltin,
    /// Anything else.
    Other,
}

impl Problem {
    /// Recognizes a problem from an error message (ldap3, rustls, the OS).
    pub fn classify(message: &str) -> Problem {
        let m = message.to_ascii_lowercase();
        let has = |needles: &[&str]| needles.iter().any(|n| m.contains(n));
        if has(&["no built-in collector"]) {
            Problem::NoBuiltin
        } else if has(&["is a domain controller for"]) {
            Problem::WrongDomain
        } else if has(&["connection stalled"]) {
            Problem::Stalled
        } else if has(&[
            "unknownissuer",
            "unknown issuer",
            "untrusted",
            "badsignature",
            "certificate chain",
        ]) {
            Problem::CertificateUntrusted
        } else if has(&["not valid for name", "notvalidforname"]) {
            Problem::CertificateName
        } else if has(&[
            "certificate expired",
            "notvalidyet",
            "certificate not valid yet",
        ]) {
            Problem::CertificateExpired
        } else if has(&["rustls dns error", "invalid dns name"]) {
            Problem::Settings
        } else if has(&[
            "no such host",
            "failed to lookup address",
            "name or service not known",
            "nodename nor servname",
            "os error 11001",
            "os error 11004",
            "temporary failure in name resolution",
            "dns lookup",
        ]) {
            Problem::Dns
        } else if has(&[
            "actively refused",
            "connection refused",
            "os error 10061",
            "os error 111)",
        ]) {
            Problem::Refused
        } else if has(&[
            "network is unreachable",
            "no route to host",
            "host is unreachable",
            "os error 10051",
            "os error 10065",
        ]) {
            Problem::Unreachable
        } else if has(&["timeout", "timed out", "os error 10060"]) {
            Problem::Timeout
        } else if has(&[
            "rc=8 ",
            "rc=8)",
            "strongerauthrequired",
            "confidentialityrequired",
        ]) {
            Problem::SigningRequired
        } else if has(&["rc=49", "invalidcredentials", "logon failure"]) {
            Problem::Credentials
        } else if has(&["gssapi", "sspi", "kerberos"]) {
            Problem::Kerberos
        } else if has(&["rustls error", "tls", "handshake", "certificate"]) {
            Problem::Tls
        } else {
            Problem::Other
        }
    }

    /// What went wrong, in one short sentence: a domain's line in a run of
    /// several, with [`Problem::explain`] and the detail behind it.
    pub fn short(self) -> &'static str {
        match self {
            Problem::Settings => "Some settings need fixing.",
            Problem::Dns => "Couldn't find a domain controller.",
            Problem::Refused | Problem::Unreachable | Problem::Timeout => {
                "Couldn't reach a domain controller."
            }
            Problem::Stalled => "The domain controller stopped answering.",
            Problem::WrongDomain => "A domain controller of another domain answered.",
            Problem::CertificateUntrusted
            | Problem::CertificateName
            | Problem::CertificateExpired
            | Problem::Tls => "The domain controller's certificate wasn't accepted.",
            Problem::Credentials | Problem::Kerberos => "The sign-in was refused.",
            Problem::SigningRequired => "The domain controller requires LDAP signing.",
            Problem::NoTicket => "Kerberos didn't work.",
            Problem::NotLocated => "No domain controller was found.",
            Problem::NoBuiltin => "This version has no built-in collector.",
            Problem::Other => "The collection failed.",
        }
    }

    /// What went wrong and what to do about it, in plain words.
    pub fn explain(self) -> &'static str {
        match self {
            Problem::Settings => "Some settings need fixing.",
            Problem::Dns => {
                "This computer can't find that domain or domain controller. Check the spelling, \
                 and that this computer uses your domain's DNS (it does when it's joined to the \
                 domain or connected through the VPN)."
            }
            Problem::Refused => {
                "The domain controller refused the connection. Check the name, and that LDAP \
                 (port 389) or LDAPS (port 636) is open from this computer."
            }
            Problem::Unreachable => {
                "This computer has no network route to the domain controller. Check your \
                 network or VPN connection."
            }
            Problem::Timeout => {
                "The domain controller didn't answer in time. Check the name, your network or \
                 VPN, and any firewall between this computer and the domain controller."
            }
            Problem::Stalled => {
                "The domain controller stopped answering partway through the collection, so \
                 Pathwarden stopped instead of waiting forever. Try again; if it happens again, \
                 turn on LDAPS."
            }
            Problem::WrongDomain => {
                "That domain controller belongs to a different domain than the one you entered. \
                 Check the spelling of the domain, or enter one of its own domain controllers."
            }
            Problem::CertificateUntrusted => {
                "The domain controller's certificate isn't trusted by this computer. The \
                 certificate authority that issued it must be in this computer's trusted roots \
                 (domain-joined computers usually get it through group policy)."
            }
            Problem::CertificateName => {
                "The domain controller's certificate doesn't match the name you entered. Use the \
                 domain controller's full name, like dc01.contoso.local, not an IP address or a \
                 short name."
            }
            Problem::CertificateExpired => {
                "The domain controller's certificate has expired or isn't valid yet. Ask \
                 whoever manages your certificates to renew it, and check this computer's clock."
            }
            Problem::Tls => {
                "The encrypted connection (LDAPS) failed. The domain controller may not have a \
                 certificate for LDAPS. Ask your Active Directory team whether LDAPS is enabled."
            }
            Problem::Credentials => {
                "The user name or password is wrong, or the account is locked, disabled or \
                 expired."
            }
            Problem::SigningRequired => {
                "The domain controller requires LDAP signing, which a password sign-in over \
                 plain LDAP can't provide. Turn on LDAPS."
            }
            Problem::Kerberos => {
                "Windows couldn't sign in to the domain controller as your account. Make sure \
                 you're signed in with a domain account, and use the domain controller's full \
                 name."
            }
            Problem::NotLocated => {
                "No domain controller of the domain was found that answers. Name one by its \
                 full name."
            }
            Problem::NoBuiltin => {
                "This version of Pathwarden doesn't include the built-in collector. Use \
                 SharpHound, or collect elsewhere and upload the file."
            }
            Problem::NoTicket => {
                "Kerberos didn't work, so computers can't be read without NTLM. Check this \
                 computer's clock and that TCP port 88 to the domain controller is open."
            }
            Problem::Other => "Pathwarden couldn't connect to the domain controller.",
        }
    }
}

/// A failed check: the [`Problem`] plus the technical detail.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    pub problem: Problem,
    /// The underlying message. Never contains a password.
    pub detail: String,
    /// What went wrong and what to do, when more precise than
    /// [`Problem::explain`] ("Kerberos didn't work: this computer's clock is
    /// 9 minutes off dc01.contoso.local's. ..."). No command-line flags.
    pub headline: Option<String>,
}

impl ConnectionError {
    pub fn new(detail: impl Into<String>) -> Self {
        let detail = crate::one_line(&detail.into());
        Self {
            problem: Problem::classify(&detail),
            detail,
            headline: None,
        }
    }

    pub(crate) fn settings(detail: impl Into<String>) -> Self {
        Self {
            problem: Problem::Settings,
            detail: detail.into(),
            headline: None,
        }
    }

    /// No Kerberos ticket for reading computers: `headline` says why.
    #[cfg_attr(not(feature = "builtin"), allow(dead_code))]
    pub(crate) fn no_ticket(headline: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            problem: Problem::NoTicket,
            detail: detail.into(),
            headline: Some(headline.into()),
        }
    }

    /// What went wrong and what to do, in plain words: the headline, else
    /// the problem's explanation (for [`Problem::Settings`], the detail).
    pub fn message(&self) -> String {
        match (&self.headline, self.problem) {
            (Some(h), _) => h.clone(),
            (None, Problem::Settings) => self.detail.clone(),
            (None, p) => p.explain().to_string(),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.problem {
            Problem::Settings => f.write_str(&self.detail),
            _ => write!(f, "{} ({})", self.message(), self.detail),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Checks that a collection can run, without collecting: for the built-in
/// collector, connects to the DC, binds as the request says and counts users
/// and computers (giving up on the counts after a few seconds); for an
/// external collector, checks the program exists and accepts the request's
/// authentication. Blocks for up to about a minute.
///
/// The error is a [`ConnectionError`] (`err.downcast_ref::<ConnectionError>()`).
pub fn test_connection(req: &CollectRequest) -> anyhow::Result<ConnectionCheck> {
    test_connection_with(req, &crate::RunSignIn::default())
}

/// [`test_connection`], as one domain of a run of several
/// ([`crate::test_domains`]): with Kerberos only and a password, the account's
/// own domain keeps its ticket in `sign_in`, and a trusted domain checks a
/// ticket for its domain controller through the trust with it.
pub fn test_connection_with(
    req: &CollectRequest,
    sign_in: &crate::RunSignIn,
) -> anyhow::Result<ConnectionCheck> {
    crate::validate_target(req).map_err(|e| ConnectionError::settings(e.to_string()))?;
    match &req.method {
        Method::External { program, kind } => {
            if *kind == ExternalKind::SharpHound && !cfg!(windows) {
                return Err(ConnectionError::settings("SharpHound runs on Windows only.").into());
            }
            let inv = match kind {
                ExternalKind::SharpHound => crate::external::sharphound_invocation(req),
                ExternalKind::RustHound => crate::external::rusthound_invocation(req),
            }
            .map_err(|e| ConnectionError::settings(e.to_string()))?;
            Ok(ConnectionCheck {
                program: Some(program.clone()),
                warnings: inv.warnings,
                ..ConnectionCheck::default()
            })
        }
        Method::Builtin => builtin_check(req, sign_in),
    }
}

#[cfg(feature = "builtin")]
fn builtin_check(
    req: &CollectRequest,
    sign_in: &crate::RunSignIn,
) -> anyhow::Result<ConnectionCheck> {
    Ok(crate::builtin::check(req, sign_in)?)
}

#[cfg(not(feature = "builtin"))]
fn builtin_check(
    _req: &CollectRequest,
    _sign_in: &crate::RunSignIn,
) -> anyhow::Result<ConnectionCheck> {
    Err(ConnectionError {
        problem: Problem::NoBuiltin,
        detail: "built without the `builtin` feature".into(),
        headline: None,
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Auth;

    /// Every explanation is clean prose: a line continuation missed in the
    /// source leaves a run of spaces in the middle of a sentence.
    #[test]
    fn explanations_have_no_stray_spaces() {
        use Problem::*;
        for p in [
            Settings,
            Dns,
            Refused,
            Unreachable,
            Timeout,
            Stalled,
            WrongDomain,
            CertificateUntrusted,
            CertificateName,
            CertificateExpired,
            Tls,
            Credentials,
            SigningRequired,
            Kerberos,
            NoTicket,
            NotLocated,
            NoBuiltin,
            Other,
        ] {
            let text = p.explain();
            assert!(
                !text.contains("  ") && !text.contains('\n'),
                "{p:?}: {text:?}"
            );
        }
    }

    #[test]
    fn classifies_common_failures() {
        let cases = [
            ("cannot connect to ldap://x:389: I/O error: No such host is known. (os error 11001)", Problem::Dns),
            ("cannot connect to ldap://x:389: I/O error: failed to lookup address information: Name or service not known", Problem::Dns),
            ("cannot connect to ldap://x:389: DNS lookup of x got no answer within 20 seconds", Problem::Dns),
            ("cannot connect to ldaps://x:636: I/O error: failed to lookup address information: Temporary failure in name resolution", Problem::Dns),
            ("cannot connect to ldaps://x:636: I/O error: failed to lookup address information: No address associated with hostname", Problem::Dns),
            ("cannot connect to ldap://x:389: DNS lookup of x found no address (no such host)", Problem::Dns),
            ("I/O error: No connection could be made because the target machine actively refused it. (os error 10061)", Problem::Refused),
            ("I/O error: Connection refused (os error 111)", Problem::Refused),
            ("timeout: deadline has elapsed", Problem::Timeout),
            ("LDAP search of DC=x: connection stalled: the domain controller sent nothing for 5 minutes", Problem::Stalled),
            ("rustls error: invalid peer certificate: UnknownIssuer", Problem::CertificateUntrusted),
            ("rustls error: invalid peer certificate: certificate not valid for name \"10.0.0.1\"; certificate is only valid for dc01.contoso.local", Problem::CertificateName),
            ("rustls error: invalid peer certificate: certificate expired: verification time 1 (UNIX), but certificate is not valid after 0 (1 seconds ago)", Problem::CertificateExpired),
            ("NTLM bind as svc@contoso.local failed: LDAP operation result: rc=49 (invalidCredentials), dn: \"\", text: \"80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data 52e, v4563\"", Problem::Credentials),
            ("NTLM bind failed: LDAP operation result: rc=8 (strongerAuthRequired), dn: \"\", text: \"\"", Problem::SigningRequired),
            ("Kerberos bind as the current user to ldap/dc01 failed: GSSAPI operation error: x", Problem::Kerberos),
            ("this Pathwarden build has no built-in collector", Problem::NoBuiltin),
            ("something odd", Problem::Other),
        ];
        for (msg, want) in cases {
            assert_eq!(Problem::classify(msg), want, "{msg}");
        }
    }

    #[test]
    fn details_lose_the_nul_ad_puts_after_its_diagnostic() {
        let e = ConnectionError::new(
            "NTLM bind as svc failed: LDAP operation result: rc=49 (invalidCredentials), dn: \
             \"\", text: \"80090308: LdapErr: DSID-0C09041C, data 52e, v4563\0\"",
        );
        assert_eq!(e.problem, Problem::Credentials);
        assert!(e.detail.ends_with("v4563\""), "{:?}", e.detail);
    }

    #[test]
    fn display_is_plain_first() {
        let e = ConnectionError::new("rustls error: invalid peer certificate: UnknownIssuer");
        let shown = e.to_string();
        assert!(
            shown.starts_with("The domain controller's certificate isn't trusted by this computer"),
            "{shown}"
        );
        assert!(shown.contains("UnknownIssuer"));
        assert_eq!(ConnectionError::settings("Fix it.").to_string(), "Fix it.");
    }

    #[test]
    fn external_check_finds_the_program() {
        let dir = std::env::temp_dir().join(format!("pw-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("rusthound-ce");
        std::fs::write(&program, "x").unwrap();
        let mut req = CollectRequest::new("contoso.local", dir.join("out"));
        req.auth = Auth::KerberosCache { ccache: None };
        req.server = Some("dc01.contoso.local".into());
        req.method = Method::External {
            program: program.clone(),
            kind: ExternalKind::RustHound,
        };
        let check = test_connection(&req).unwrap();
        assert_eq!(check.program.as_deref(), Some(program.as_path()));

        req.method = Method::External {
            program: dir.join("missing.exe"),
            kind: ExternalKind::RustHound,
        };
        let err = test_connection(&req).unwrap_err();
        let ce = err.downcast_ref::<ConnectionError>().expect("typed");
        assert_eq!(ce.problem, Problem::Settings);
        assert!(ce.detail.contains("missing.exe"), "{}", ce.detail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "builtin"))]
    #[test]
    fn lean_build_says_so() {
        let req = CollectRequest::new("contoso.local", "out");
        let err = test_connection(&req).unwrap_err();
        let ce = err.downcast_ref::<ConnectionError>().expect("typed");
        assert_eq!(ce.problem, Problem::NoBuiltin);
    }
}
