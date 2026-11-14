//! `pathwarden collect`: its arguments. The command itself (with its live
//! progress display) is in the `pathwarden` binary.

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::Args;

use crate::{Auth, CollectRequest, ExternalKind, Method, Scope, Secret, PASSWORD_ENV};

#[derive(Debug, Args)]
#[command(after_help = "\
Authentication:
  Without --user, the built-in collector signs in with Kerberos as the current Windows user
  (SSPI; right for a gMSA scheduled task) and SharpHound runs as the current user.
  With --user, the password is read from the PATHWARDEN_COLLECT_PASSWORD environment
  variable, or prompted for without echo. It is never accepted on the command line.

Computers (sessions, local groups, SYSVOL, the CAs' registry):
  Kerberos only: with --user, Pathwarden gets a Kerberos ticket from the domain controller
  (TCP port 88; the clocks must be within 5 minutes), and a computer the domain has no
  Kerberos name for is skipped. Every SMB reply must be signed; a computer whose replies
  aren't is skipped. --allow-ntlm and --allow-unsigned-smb turn these off.

Several domains:
  --domain again, or --trusted, collects trusted domains in the same run, one after another,
  each into its own folder in --output, then analyzed together. It asks first (--yes where
  nothing can answer). A domain that fails is skipped; exit status 3 says some weren't
  collected. With --user and Kerberos only, the first domain's ticket reads the trusted
  domains' computers through the trust. Each trusted domain's domain controller is found by
  its full name, so its LDAPS certificate is checked; --server DOMAIN=HOST names one.
  Only collect from domains you are authorized to assess.

Disk:
  The built-in collector keeps the directory on disk while it reads it, in a private folder
  under the workspace (collect-cache), and removes it when the collection is written. It
  stops first when the disk can't hold the read. --no-cache reads into memory instead.
  A read that stops (a lost connection, Ctrl+C) is kept for 24 hours: --resume continues
  it from the same domain controller. Without --resume, the read starts over.

Progress:
  On a terminal, a live status on stderr: the step, objects by type, a bar, the elapsed time
  and an estimate of the time left. Otherwise, a plain progress line on stderr every 10
  seconds. -v also shows the collector's own output; -q shows only errors and the summary.

The output is a full map of the directory. It is written only to --output.
Analyze it with `pathwarden report -i <DIR>`.")]
pub struct CollectArgs {
    /// The domain to collect, e.g. scale.local. Give it again for trusted
    /// domains to collect in the same run, one after another with the same
    /// sign-in, then analyzed together.
    #[arg(long, short, required = true, value_name = "DOMAIN")]
    pub domain: Vec<String>,

    /// The domain controller to query, preferably its FQDN (default: the
    /// domain name). DOMAIN=HOST names one for a trusted domain of the run
    /// (default: one found in DNS); give it once per domain.
    #[arg(long, short = 's', value_name = "[DOMAIN=]HOST")]
    pub server: Vec<String>,

    /// The account to sign in as (user, DOMAIN\user or user@domain); the
    /// password from PATHWARDEN_COLLECT_PASSWORD or a prompt. Give an
    /// account from an externally trusted domain, or from a forest whose UPN
    /// suffix isn't routed, as DOMAIN\user.
    #[arg(long, short = 'u', value_name = "USER")]
    pub user: Option<String>,

    /// Use LDAPS (port 636); the server certificate is validated.
    #[arg(long)]
    pub ldaps: bool,

    /// Don't validate the LDAPS certificate (insecure; labs only).
    #[arg(long, requires = "ldaps")]
    pub insecure_skip_tls_verify: bool,

    /// Allow --user over plain LDAP (NTLM without signing or encryption).
    #[arg(long)]
    pub allow_unencrypted_ldap: bool,

    /// Sign in to computers with NTLM when Kerberos can't be used
    /// (default: Kerberos only; a computer without a Kerberos name is
    /// skipped).
    #[arg(long)]
    pub allow_ntlm: bool,

    /// Read computers whose SMB replies aren't signed
    /// (default: every reply must be signed).
    #[arg(long)]
    pub allow_unsigned_smb: bool,

    /// Full collection: don't read the accounts services run as on the
    /// computers (default: read them, for stored credentials).
    #[arg(long)]
    pub no_service_reads: bool,

    /// Full collection: read the accounts services run as even when
    /// pathwarden.toml turns them off (`[collect] service_reads = false`).
    #[arg(long, conflicts_with = "no_service_reads")]
    pub service_reads: bool,

    /// Full collection: don't read the scheduled tasks on the computers
    /// (default: read them over C$, for stored credentials).
    #[arg(long)]
    pub no_task_reads: bool,

    /// Full collection: read the scheduled tasks even when pathwarden.toml
    /// turns them off (`[collect] task_reads = false`).
    #[arg(long, conflicts_with = "no_task_reads")]
    pub task_reads: bool,

    /// The folder to write the collection to (created if missing).
    #[arg(long = "output", short = 'o', alias = "out", value_name = "DIR")]
    pub out: PathBuf,

    /// What to collect: dc-only (Quick: directory only) or all (Full: also
    /// sessions and local groups from every computer). Default: dc-only for
    /// the built-in collector, all for SharpHound and RustHound-CE.
    #[arg(long, value_enum)]
    pub scope: Option<Scope>,

    /// Run SharpHound (Windows, current user) instead of the built-in
    /// collector.
    #[arg(long, value_name = "PATH", conflicts_with = "rusthound")]
    pub sharphound: Option<PathBuf>,

    /// Run an external rusthound-ce program (needs --kerberos).
    #[arg(long, value_name = "PATH")]
    pub rusthound: Option<PathBuf>,

    /// Authenticate the external rusthound-ce with a Kerberos ticket cache
    /// (KRB5CCNAME, or the file given here).
    #[arg(long, value_name = "CCACHE", num_args = 0..=1)]
    pub kerberos: Option<Option<PathBuf>>,

    /// Also show the collector's own output.
    #[arg(long, short = 'v', conflicts_with = "quiet")]
    pub verbose: bool,

    /// Show only errors and the final summary.
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Built-in collector: read the directory into memory instead of
    /// keeping it on disk while it is read (needs much more memory on a
    /// large domain).
    #[arg(long)]
    pub no_cache: bool,

    /// Built-in collector: continue a read of the domain that stopped in the
    /// last 24 hours, from where it stopped (otherwise it starts over).
    #[arg(long, conflicts_with = "no_cache")]
    pub resume: bool,

    /// Built-in collector: ask the directory for every attribute, as
    /// RustHound-CE does, not only those its parser reads (for comparing
    /// the two; LAPS passwords the account can read are then read too).
    #[arg(long)]
    pub all_attributes: bool,

    /// Built-in collector: connections that read the directory at once, 1
    /// to 8 (default: 4, or `[collect] read_streams`). Fewer are used when
    /// the domain controller slows down.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=8))]
    pub read_streams: Option<u8>,
}

/// How much `pathwarden collect` prints while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// Errors and the final summary.
    Quiet,
    /// Progress (live on a terminal, a line every few seconds otherwise).
    Normal,
    /// Progress plus every line of collector output.
    Verbose,
}

impl CollectArgs {
    pub fn verbosity(&self) -> Verbosity {
        match (self.quiet, self.verbose) {
            (true, _) => Verbosity::Quiet,
            (_, true) => Verbosity::Verbose,
            _ => Verbosity::Normal,
        }
    }

    /// The first `--domain`: the one the run is of.
    pub fn first_domain(&self) -> &str {
        self.domain.first().map(String::as_str).unwrap_or_default()
    }

    /// The other `--domain`s: trusted domains collected after the
    /// first, in the same run.
    pub fn trusted(&self) -> Vec<String> {
        self.domain.iter().skip(1).cloned().collect()
    }

    /// Builds the request for the first domain, prompting for the password
    /// when needed.
    pub fn into_request(self) -> anyhow::Result<CollectRequest> {
        let (server, servers) = parse_servers(&self.server, self.first_domain())?;
        // A full path from here on: what is checked, signed or not,
        // and run is the same file, named in full.
        let method = match (&self.sharphound, &self.rusthound) {
            (Some(p), _) => Method::External {
                program: crate::resolve_program(p)?,
                kind: ExternalKind::SharpHound,
            },
            (None, Some(p)) => Method::External {
                program: crate::resolve_program(p)?,
                kind: ExternalKind::RustHound,
            },
            (None, None) => Method::Builtin,
        };
        let auth = match (&self.user, &self.kerberos) {
            (Some(_), Some(_)) => anyhow::bail!("Use either --user or --kerberos, not both."),
            (Some(user), None) => Auth::Password {
                user: user.clone(),
                password: read_password(user)?,
            },
            (None, Some(cc)) => Auth::KerberosCache { ccache: cc.clone() },
            (None, None) => Auth::CurrentUser,
        };
        Ok(CollectRequest {
            domain: self.domain.into_iter().next().unwrap_or_default(),
            server,
            servers,
            locate_dc: false,
            auth,
            ldaps: self.ldaps,
            insecure_skip_tls_verify: self.insecure_skip_tls_verify,
            allow_unencrypted_ldap: self.allow_unencrypted_ldap,
            allow_ntlm: self.allow_ntlm,
            allow_unsigned_smb: self.allow_unsigned_smb,
            service_reads: !self.no_service_reads,
            task_reads: !self.no_task_reads,
            output_dir: self.out,
            method,
            scope: self.scope.unwrap_or_default(),
            expected_objects: None,
            // Set by the caller, which knows the workspace (unless --no-cache).
            cache: None,
            all_attributes: self.all_attributes,
            // `[collect] read_streams` comes from the caller, which knows
            // the workspace.
            read_streams: self.read_streams.map(usize::from),
        })
    }
}

/// Domain controllers named per domain: (domain, host).
pub type DomainServers = Vec<(String, String)>;

/// `--server` as given: a plain HOST is the first domain's
/// (`first`); DOMAIN=HOST names another domain's. Each domain once. The
/// domains are lower case, without the root's dot.
pub fn parse_servers(
    values: &[String],
    first: &str,
) -> anyhow::Result<(Option<String>, DomainServers)> {
    let pairs: Vec<(Option<String>, String)> = values
        .iter()
        .map(|v| match v.split_once('=') {
            Some((d, h)) => (Some(d.to_string()), h.to_string()),
            None => (None, v.clone()),
        })
        .collect();
    named_servers(first, &pairs).map_err(|e| match e {
        ServerError::Empty(i) => anyhow::anyhow!(
            "--server {}: give HOST, or DOMAIN=HOST for a trusted domain",
            values[i]
        ),
        ServerError::FirstTwice(d) => anyhow::anyhow!(
            "--server names {d}'s domain controller twice; name a trusted domain's as \
             DOMAIN=HOST"
        ),
        ServerError::Twice(d) => anyhow::anyhow!("--server names {d}'s domain controller twice"),
        ServerError::BadHost(i) => anyhow::anyhow!(
            "--server {}: give the domain controller's name or address, like dc01.contoso.local, \
             without a port, path or user",
            values[i]
        ),
    })
}

/// Why [`named_servers`] refused the domain controllers named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    /// The entry at this index has no host, or an empty domain.
    Empty(usize),
    /// The first domain's named twice.
    FirstTwice(String),
    /// Another domain's named twice.
    Twice(String),
    /// The entry at this index isn't a host name or address ([`server_host`]).
    BadHost(usize),
}

/// A domain controller's name as typed, ready to connect to: a DNS name
/// (lower case, without the root's dot) or an IP address (IPv6 with or
/// without brackets, kept without). `None` for anything else: a port, a
/// path or query, a user (`@`), spaces or other characters.
pub fn server_host(raw: &str) -> Option<String> {
    let t = raw.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(t);
    if let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() {
        return Some(ip.to_string());
    }
    if inner.len() != t.len() {
        // Brackets around anything but an IPv6 address.
        return None;
    }
    let h = t.trim_end_matches('.').to_ascii_lowercase();
    let ok = !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['-', '.'])
        && !h.contains("..")
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    ok.then_some(h)
}

/// The domain controllers named for a run, the CLI's `--server`
/// and the app's per-domain field alike: (domain, host) pairs, no domain
/// meaning `first`. Returns the first domain's and the others'; each domain
/// once, lower case, without the root's dot; each host as
/// [`server_host`] has it. A name is used as given: the certificate must
/// match it (unless the run turns the check off), and it may be outside the
/// domain (a disjoint namespace).
pub fn named_servers(
    first: &str,
    pairs: &[(Option<String>, String)],
) -> Result<(Option<String>, DomainServers), ServerError> {
    let clean = |d: &str| d.trim().trim_end_matches('.').to_ascii_lowercase();
    let first = clean(first);
    let mut plain: Option<String> = None;
    let mut named: DomainServers = Vec::new();
    for (i, (domain, host)) in pairs.iter().enumerate() {
        let domain = domain.as_deref().map(clean);
        if host.trim().is_empty() || domain.as_deref() == Some("") {
            return Err(ServerError::Empty(i));
        }
        let host = server_host(host).ok_or(ServerError::BadHost(i))?;
        match domain.filter(|d| *d != first) {
            None => {
                if plain.is_some() {
                    return Err(ServerError::FirstTwice(first));
                }
                plain = Some(host);
            }
            Some(d) => {
                if named.iter().any(|(n, _)| *n == d) {
                    return Err(ServerError::Twice(d));
                }
                named.push((d, host));
            }
        }
    }
    Ok((plain, named))
}

fn read_password(user: &str) -> anyhow::Result<Secret> {
    if let Some(secret) = Secret::from_env() {
        return Ok(secret);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no password: set {PASSWORD_ENV} or run interactively to be prompted (passwords \
             are never taken from the command line)"
        );
    }
    Ok(Secret::prompt(&format!("Password for {user}: "))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: CollectArgs,
    }

    #[test]
    fn no_password_flag_exists() {
        let parsed = Cli::try_parse_from([
            "collect",
            "-d",
            "contoso.local",
            "--out",
            "o",
            "--password",
            "x",
        ]);
        assert!(parsed.is_err(), "a --password flag must not exist");
        let parsed =
            Cli::try_parse_from(["collect", "-d", "contoso.local", "--out", "o", "-p", "x"]);
        assert!(parsed.is_err());
    }

    #[test]
    fn verbosity_flags() {
        let parse = |extra: &[&str]| {
            let mut a = vec!["collect", "-d", "contoso.local", "-o", "o"];
            a.extend_from_slice(extra);
            Cli::try_parse_from(a)
        };
        assert_eq!(parse(&[]).unwrap().args.verbosity(), Verbosity::Normal);
        assert_eq!(parse(&["-v"]).unwrap().args.verbosity(), Verbosity::Verbose);
        assert_eq!(
            parse(&["--quiet"]).unwrap().args.verbosity(),
            Verbosity::Quiet
        );
        assert!(parse(&["-v", "-q"]).is_err());
    }

    /// `--domain` again names trusted domains for the same run; the
    /// first is the request's.
    #[test]
    fn several_domains() {
        let cli = Cli::try_parse_from([
            "collect",
            "-d",
            "contoso.local",
            "--domain",
            "child.contoso.local",
            "-d",
            "fabrikam.com",
            "-o",
            "out",
        ])
        .unwrap();
        assert_eq!(cli.args.first_domain(), "contoso.local");
        assert_eq!(cli.args.trusted(), ["child.contoso.local", "fabrikam.com"]);
        let req = cli.args.into_request().unwrap();
        assert_eq!(req.domain, "contoso.local");
        assert!(Cli::try_parse_from(["collect", "-o", "out"]).is_err());
    }

    /// `--server` again, as DOMAIN=HOST, for a trusted domain; the
    /// plain form stays the first domain's.
    #[test]
    fn a_server_per_domain() {
        let cli = Cli::try_parse_from([
            "collect",
            "-d",
            "north.sevenkingdoms.local",
            "-d",
            "essos.local",
            "-s",
            "winterfell.north.sevenkingdoms.local",
            "--server",
            "ESSOS.LOCAL.=meereen.essos.local",
            "-s",
            "sevenkingdoms.local= kingslanding.sevenkingdoms.local",
            "-o",
            "out",
        ])
        .unwrap();
        let req = cli.args.into_request().unwrap();
        assert_eq!(
            req.server.as_deref(),
            Some("winterfell.north.sevenkingdoms.local")
        );
        assert_eq!(
            req.servers,
            [
                ("essos.local".to_string(), "meereen.essos.local".to_string()),
                (
                    "sevenkingdoms.local".to_string(),
                    "kingslanding.sevenkingdoms.local".to_string()
                ),
            ]
        );
        assert!(!req.locate_dc);

        let s = |v: &[&str]| {
            parse_servers(
                &v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "Contoso.Local",
            )
        };
        // The first domain named as DOMAIN=HOST is the plain form.
        assert_eq!(
            s(&["contoso.local=dc01.contoso.local"]).unwrap(),
            (Some("dc01.contoso.local".to_string()), Vec::new())
        );
        assert_eq!(s(&[]).unwrap(), (None, Vec::new()));
        let err = |v: &[&str]| s(v).unwrap_err().to_string();
        // IPv6: the colons aren't the separator; brackets are allowed.
        assert_eq!(
            s(&["fd00::11", "fabrikam.com=[FD00::12]"]).unwrap(),
            (
                Some("fd00::11".to_string()),
                vec![("fabrikam.com".to_string(), "fd00::12".to_string())]
            )
        );
        // Names are cleaned: case, the root's dot.
        assert_eq!(
            s(&["fabrikam.com.=DC01.Fabrikam.COM."]).unwrap().1,
            [("fabrikam.com".to_string(), "dc01.fabrikam.com".to_string())]
        );
        // Not a host: refused, naming the entry.
        for bad in [
            "dc01.contoso.local:636",
            "fabrikam.com=dc01:636",
            "fabrikam.com=dc01/x",
            "fabrikam.com=dc01?x=1",
            "fabrikam.com=svc@dc01",
            "fabrikam.com=dc 01",
            "fabrikam.com=ldaps://dc01",
            "fabrikam.com=[dc01]",
            "fabrikam.com=-dc01",
            "fabrikam.com=dc01..x",
        ] {
            let e = err(&[bad]);
            assert!(
                e.contains(bad) && e.contains("without a port"),
                "{bad}: {e}"
            );
        }
        assert!(err(&["dc01", "dc02"]).contains("twice"));
        assert!(err(&["dc01", "contoso.local=dc02"]).contains("twice"));
        assert!(err(&["a.com=x", "A.COM=y"]).contains("a.com's domain controller twice"));
        assert!(err(&["a.com="]).contains("DOMAIN=HOST"));
        assert!(err(&["=x"]).contains("DOMAIN=HOST"));
        assert!(err(&[" "]).contains("DOMAIN=HOST"));
    }

    #[test]
    fn external_and_kerberos_flags() {
        let cli = Cli::try_parse_from([
            "collect",
            "-d",
            "contoso.local",
            "-o",
            "out",
            "--rusthound",
            "./rh",
            "--kerberos",
            "--server",
            "dc01.contoso.local",
        ])
        .unwrap();
        let req = cli.args.into_request().unwrap();
        assert!(matches!(req.auth, Auth::KerberosCache { ccache: None }));
        assert!(matches!(
            req.method,
            Method::External {
                kind: ExternalKind::RustHound,
                ..
            }
        ));
        assert!(Cli::try_parse_from([
            "collect",
            "-d",
            "x.local",
            "-o",
            "o",
            "--sharphound",
            "a",
            "--rusthound",
            "b"
        ])
        .is_err());
    }
}
