//! What the computer-contacting modules really collected, and which domain
//! they sign in to over SMB.
//!
//! RustHound-CE (MIT, see THIRD-PARTY-NOTICES.md) leaves a computer's
//! `Sessions`, `PrivilegedSessions` and `RegistrySessions` with no
//! per-call reason. Since 2.5.26 (the fix this file asked for) the
//! `Session` default is `Collected: false` and the sessions module sets
//! `Collected: true` only on the calls that succeeded, with a `FailureReason`
//! on the rest; before that every tried computer was marked collected whether
//! or not the call failed, so an empty "collected" list read as "nobody is
//! logged on" and hid the paths a full collection is run to find. Pathwarden
//! still drives the accounting for its completeness report: every computer
//! starts as not collected with a reason (DC-only, skipped), the computers the
//! module tried are taken from it, and each session list the module logged an
//! error for is kept not collected with that error as the reason. This works
//! the same whichever default the library ships, and adds the per-call
//! attribution and summary the report needs.
//!
//! The SMB modules also sign in to the domain being collected rather than
//! the account's own: `NORTH\jdoe` collecting `fabrikam.local` signed
//! in as `fabrikam.local\jdoe`, which the DCs refuse (or, worse, is
//! another account of the same name there). [`SmbIdentity`] gives the
//! account's domain to sign in with: the account the directory reports
//! after the LDAP bind ([`smb_account`]), since a UPN suffix
//! (`alice@example.com`) is not always a domain.

use rusthound_ce::args::Options;
use rusthound_ce::objects::common::Session;
use rusthound_ce::objects::computer::Computer;

/// Why sessions are not collected in a collection that contacts no computer.
/// Shared with the reader, which takes it to mean the run did not target
/// sessions ([`pathwarden_core::ingest::NOT_CONTACTED`]).
pub(crate) use pathwarden_core::ingest::NOT_CONTACTED;
/// Why sessions are not collected on a computer the sessions module skipped.
pub(crate) const NOT_ATTEMPTED: &str = "not collected: computer not contacted (disabled, or its \
     account password is older than 60 days, so it is probably gone)";
/// The log target of RustHound-CE's sessions module, whose warnings carry
/// the per-computer errors.
pub(crate) const SESSIONS_LOG_TARGET: &str = "rusthound_ce::modules::session";

/// Which of a computer's session lists an error of the sessions module is
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// SRVSVC NetSessionEnum: `Sessions`.
    Srvsvc,
    /// WKSSVC NetWkstaUserEnum: `PrivilegedSessions`.
    Wkssvc,
    /// WINREG HKEY_USERS: `RegistrySessions`.
    Winreg,
    /// The computer was not reached or the sign-in failed: all three.
    All,
}

/// `rest` after a case-insensitive `prefix`, if `s` starts with it.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// The call an error of the sessions module (its wording, unchanged through
/// 2.5.26) is about, if it is about `host`. The module writes `[HOST] SRVSVC rc=5 ...`,
/// `HOST SRVSVC: ...`, `[HOST] WKSSVC rc=5 ...`, `HOST WKSSVC: ...`,
/// `HOST WINREG: ...`, `HOST krb: ...` and `HOST: ...` (445 closed, sign-in,
/// tree connect, timeout).
fn call_of(host: &str, msg: &str) -> Option<Call> {
    if host.is_empty() {
        return None;
    }
    let msg = msg.trim();
    let rest = strip_ci(msg, "[")
        .and_then(|r| strip_ci(r, host))
        .and_then(|r| r.strip_prefix(']'))
        .or_else(|| strip_ci(msg, host))?;
    if rest.starts_with(':') || rest.starts_with(" krb:") {
        Some(Call::All)
    } else if rest.starts_with(" SRVSVC") {
        Some(Call::Srvsvc)
    } else if rest.starts_with(" WKSSVC") {
        Some(Call::Wkssvc)
    } else if rest.starts_with(" WINREG") {
        Some(Call::Winreg)
    } else {
        None
    }
}

fn set_not_collected(s: &mut Session, why: &str) {
    *s.collected_mut() = false;
    *s.failure_reason_mut() = Some(why.to_string());
}

/// Marks every computer's three session lists as not collected, with `why`.
/// The sessions module then marks the computers it tries as collected.
pub(crate) fn mark_sessions_not_collected(computers: &mut [Computer], why: &str) {
    for c in computers {
        for call in LISTS {
            set_not_collected(list(c, call), why);
        }
    }
}

/// The three session lists, by the call that fills them.
const LISTS: [Call; 3] = [Call::Srvsvc, Call::Wkssvc, Call::Winreg];

fn list(c: &mut Computer, call: Call) -> &mut Session {
    match call {
        Call::Srvsvc => c.sessions_mut(),
        Call::Wkssvc => c.privileged_sessions_mut(),
        Call::Winreg | Call::All => c.registry_sessions_mut(),
    }
}

/// After the sessions module: records, for each session list that is not
/// collected, the error the module logged as the reason. Since RustHound-CE
/// 2.5.26 the module marks a list collected only when its call
/// succeeded (with real results) and sets a `FailureReason` on the rest, so a
/// list it left collected is a genuine success and is never demoted here —
/// only a `Call::All` line (a per-host timeout) can match such a list, and the
/// other calls really did succeed. The log supplies the per-host reason for
/// the calls the module reports per host rather than per list (sign-in, 445,
/// tree connect, timeout). `errors` is what the module logged, `None` if that
/// couldn't be read: then the module's own per-list state stands.
pub(crate) fn apply_session_errors(computers: &mut [Computer], errors: Option<&[String]>) {
    for c in computers {
        let host = c.properties().name().clone();
        if let Some(errors) = errors {
            for msg in errors {
                let Some(call) = call_of(&host, msg) else {
                    continue;
                };
                for one in LISTS {
                    let s = list(c, one);
                    if (call == Call::All || call == one) && !*s.collected() {
                        set_not_collected(s, msg);
                    }
                }
            }
        }
        // A list the module collected keeps no reason from before.
        for l in LISTS {
            let s = list(c, l);
            if *s.collected() {
                *s.failure_reason_mut() = None;
            }
        }
    }
}

/// STATUS_PIPE_NOT_AVAILABLE, as the sessions module prints it: opening
/// `\winreg` while Windows is still starting the Remote Registry service.
/// On Server 2016 and later the service is "Automatic (Trigger Start)" and
/// stops when idle, so the first open starts it and fails; a second one a
/// moment later is answered. In a lab every computer failed this
/// way on the first pass, and the retry read a user's logon on a member
/// server and a domain controller as a plain domain user.
const PIPE_NOT_AVAILABLE: &str = "0xc00000ac";

/// Whether `c`'s registry sessions failed because Remote Registry was
/// still starting (worth asking again).
pub(crate) fn registry_was_starting(c: &mut Computer) -> bool {
    let s = c.registry_sessions_mut();
    !*s.collected()
        && s.failure_reason()
            .as_deref()
            .is_some_and(|r| r.contains("WINREG") && r.contains(PIPE_NOT_AVAILABLE))
}

/// Whether the sessions module signed in to `c`: a session list was read,
/// or SRVSVC or WKSSVC failed on its own (a call's error, not the
/// computer's: unreachable, the sign-in, a timeout).
pub(crate) fn reached(c: &mut Computer) -> bool {
    let host = c.properties().name().clone();
    [Call::Srvsvc, Call::Wkssvc].into_iter().any(|l| {
        let s = list(c, l);
        *s.collected()
            || s.failure_reason()
                .as_deref()
                .and_then(|r| call_of(&host, r))
                .is_some_and(|call| call == l)
    })
}

/// Sets all three of `c`'s session lists not collected, with `why`.
pub(crate) fn set_all_not_collected(c: &mut Computer, why: &str) {
    for l in LISTS {
        set_not_collected(list(c, l), why);
    }
}

/// The reasons recorded on `c`'s session lists.
pub(crate) fn session_reasons(c: &mut Computer) -> Vec<String> {
    LISTS
        .iter()
        .filter_map(|&l| list(c, l).failure_reason().clone())
        .collect()
}

/// Records the SIDs of the accounts with a profile loaded on `c` (read
/// from its Remote Registry) as its registry sessions, collected; or, with
/// an error, as not collected with it.
pub(crate) fn set_registry_sessions(c: &mut Computer, read: Result<Vec<String>, String>) {
    let computer = c.object_identifier().clone();
    let s = c.registry_sessions_mut();
    match read {
        Ok(sids) => {
            let mut seen = std::collections::BTreeSet::new();
            s.results_mut().clear();
            for sid in sids {
                if seen.insert(sid.clone()) {
                    let mut link = rusthound_ce::objects::common::UserComputerSession::new();
                    *link.user_sid_mut() = sid;
                    *link.computer_sid_mut() = computer.clone();
                    s.results_mut().push(link);
                }
            }
            *s.collected_mut() = true;
            *s.failure_reason_mut() = None;
        }
        Err(why) => set_not_collected(s, &why),
    }
}

/// The computers whose three session lists are all collected.
pub(crate) fn fully_collected(computers: &mut [Computer]) -> usize {
    let mut n = 0;
    for c in computers {
        n += usize::from(LISTS.iter().all(|&l| *list(c, l).collected()));
    }
    n
}

/// The computers with at least one of the three session lists collected
/// (what the report counts as sessions collected).
pub(crate) fn partly_collected(computers: &mut [Computer]) -> usize {
    let mut n = 0;
    for c in computers {
        n += usize::from(LISTS.iter().any(|&l| *list(c, l).collected()));
    }
    n
}

/// What the computer-contacting modules could not read, for one summary
/// warning (the log has each computer and its reason).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct NotRead {
    /// Computers the sessions module tried.
    pub tried: usize,
    /// Of those, computers with a session list it couldn't read.
    pub sessions: usize,
    /// Per list (SRVSVC, WKSSVC, Remote Registry): computers it failed on.
    pub by_call: [usize; 3],
    /// Computers whose local groups (SAMR) couldn't be read.
    pub local_groups: usize,
}

impl NotRead {
    /// The sessions part, from the computers after the sessions module.
    pub(crate) fn of_sessions(computers: &mut [Computer]) -> Self {
        let mut out = Self::default();
        for c in computers {
            let failed: Vec<bool> = LISTS
                .iter()
                .map(|&l| {
                    let s = list(c, l);
                    !*s.collected() && s.failure_reason().as_deref() != Some(NOT_ATTEMPTED)
                })
                .collect();
            let skipped = LISTS.iter().all(|&l| {
                let s = list(c, l);
                !*s.collected() && s.failure_reason().as_deref() == Some(NOT_ATTEMPTED)
            });
            // Left out by Kerberos only or required signing: their
            // own warning says so.
            let left_out = LISTS.iter().all(|&l| {
                let s = list(c, l);
                !*s.collected()
                    && s.failure_reason()
                        .as_deref()
                        .is_some_and(|r| skip_of(r).is_some())
            });
            if skipped || left_out {
                continue;
            }
            out.tried += 1;
            out.sessions += usize::from(failed.iter().any(|f| *f));
            for (n, f) in out.by_call.iter_mut().zip(&failed) {
                *n += usize::from(*f);
            }
        }
        out
    }

    /// The one-line warning, if anything was not read.
    pub(crate) fn warning(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.sessions > 0 {
            let calls: Vec<String> = ["SRVSVC", "WKSSVC", "Remote Registry"]
                .iter()
                .zip(self.by_call)
                .filter(|(_, n)| *n > 0)
                .map(|(name, n)| format!("{name} on {n}"))
                .collect();
            parts.push(format!(
                "Sessions were not fully read on {} of {} ({}).",
                pathwarden_core::report::num(self.sessions),
                pathwarden_core::text::count(self.tried, "computer", "computers"),
                calls.join(", ")
            ));
        }
        if self.local_groups > 0 {
            parts.push(format!(
                "Local groups were not read on {}.",
                pathwarden_core::text::count(self.local_groups, "computer", "computers")
            ));
        }
        (!parts.is_empty()).then(|| {
            format!(
                "{} This is usually access denied (not a local administrator) or an unreachable \
                 computer. The collection log names each computer and the reason.",
                parts.join(" ")
            )
        })
    }
}

/// The computers the sessions module tried, reached (a session list read),
/// timed out on (nothing read, the per-host timeout ran out) and failed on
/// (nothing read otherwise), for the run's timings. Counts only.
pub(crate) fn summary(computers: &mut [Computer]) -> pathwarden_core::diagnostics::HostSummary {
    let mut out = pathwarden_core::diagnostics::HostSummary {
        computers: computers.len(),
        ..Default::default()
    };
    for c in computers {
        let reasons: Vec<(bool, Option<String>)> = LISTS
            .iter()
            .map(|&l| {
                let s = list(c, l);
                (*s.collected(), s.failure_reason().clone())
            })
            .collect();
        if reasons
            .iter()
            .all(|(done, why)| !done && why.as_deref() == Some(NOT_ATTEMPTED))
        {
            continue;
        }
        out.tried += 1;
        if reasons.iter().any(|(done, _)| *done) {
            out.reached += 1;
        } else if reasons
            .iter()
            .any(|(_, why)| why.as_deref().is_some_and(|w| error_kind(w) == "timeout"))
        {
            out.timed_out += 1;
        } else {
            out.failed += 1;
        }
    }
    out
}

/// What a Win32 or NetAPI error code means for a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    AccessDenied,
    Unreachable,
    SignIn,
    Timeout,
    Other,
}

impl Kind {
    /// The [`error_kind`] name of this kind.
    fn name(self) -> &'static str {
        match self {
            Kind::AccessDenied => "access denied",
            Kind::Unreachable => "unreachable",
            Kind::SignIn => "sign-in",
            Kind::Timeout => "timeout",
            Kind::Other => "other",
        }
    }
}

/// What a Win32 or NetAPI error code (`rc=` in the modules' messages and
/// the Windows reader's) means.
pub(crate) fn kind_of(code: u32) -> Kind {
    match code {
        // ERROR_ACCESS_DENIED
        5 => Kind::AccessDenied,
        // ERROR_REM_NOT_LIST, ERROR_BAD_NETPATH, ERROR_NETNAME_DELETED,
        // ERROR_BAD_NET_NAME, ERROR_NO_NET_OR_BAD_PATH, ERROR_INVALID_NETNAME,
        // ERROR_NO_NETWORK, ERROR_CONNECTION_REFUSED, ERROR_NETWORK_UNREACHABLE,
        // ERROR_HOST_UNREACHABLE, RPC_S_SERVER_UNAVAILABLE,
        // RPC_S_CALL_FAILED_DNE, EPT_S_NOT_REGISTERED
        51 | 53 | 64 | 67 | 1203 | 1214 | 1222 | 1225 | 1231 | 1232 | 1722 | 1727 | 1753 => {
            Kind::Unreachable
        }
        // ERROR_SESSION_CREDENTIAL_CONFLICT, ERROR_NO_LOGON_SERVERS,
        // ERROR_LOGON_FAILURE, ERROR_ACCOUNT_RESTRICTION,
        // ERROR_PASSWORD_EXPIRED, ERROR_ACCOUNT_DISABLED,
        // ERROR_LOGON_TYPE_NOT_GRANTED, ERROR_TRUSTED_RELATIONSHIP_FAILURE,
        // ERROR_PASSWORD_MUST_CHANGE, ERROR_ACCOUNT_LOCKED_OUT
        1219 | 1311 | 1326 | 1327 | 1330 | 1331 | 1385 | 1789 | 1907 | 1909 => Kind::SignIn,
        // ERROR_SEM_TIMEOUT, WAIT_TIMEOUT, ERROR_TIMEOUT, RPC_S_CALL_CANCELLED
        121 | 258 | 1460 | 1818 => Kind::Timeout,
        _ => Kind::Other,
    }
}

/// The code after `rc=` in a message, if it has one.
fn rc_code(m: &str) -> Option<u32> {
    let rest = &m[m.find("rc=")? + 3..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// `msg` without the computer it starts with: `[HOST] ...`, or a first
/// word with a dot in it (`HOST: ...`, `HOST WINREG: ...`). A host name
/// says nothing about the error (`DNS01.CONTOSO.LOCAL`).
fn without_host(msg: &str) -> &str {
    let msg = msg.trim_start();
    if let Some(rest) = msg.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[end + 1..];
        }
    }
    let end = msg.find([' ', ':']).unwrap_or(msg.len());
    if msg[..end].contains('.') {
        &msg[end..]
    } else {
        msg
    }
}

/// `msg` without `host` at its start (`[HOST] ...`, `HOST ...`), else
/// [`without_host`].
fn without_this_host<'a>(host: &str, msg: &'a str) -> &'a str {
    let m = msg.trim_start();
    if !host.is_empty() {
        if let Some(rest) = strip_ci(m, "[")
            .and_then(|r| strip_ci(r, host))
            .and_then(|r| r.strip_prefix(']'))
            .or_else(|| strip_ci(m, host))
        {
            return rest;
        }
    }
    without_host(m)
}

/// What kind of error a module's message is (its wording through
/// RustHound-CE 2.5.27), without the computer it names. A message with a
/// Win32 code (`rc=5`) is sorted by the code.
pub(crate) fn error_kind(msg: &str) -> &'static str {
    kind_of_text(without_host(msg))
}

fn kind_of_text(msg: &str) -> &'static str {
    let m = msg.to_ascii_lowercase();
    // The code says it all (`rc=1445` is not port 445).
    if let Some(code) = rc_code(&m) {
        return kind_of(code).name();
    }
    let has = |needles: &[&str]| needles.iter().any(|n| m.contains(n));
    // Skipped by Kerberos only or required signing: before the
    // words below, which their messages also contain ("connect", "Kerberos").
    if has(&[&SKIP_NO_KERBEROS_NAME.to_ascii_lowercase()]) {
        return "no Kerberos name";
    }
    if has(&[SKIP_UNSIGNED, UNSIGNED_REPLY]) {
        return "unsigned";
    }
    if has(&[&SKIP_BAD_REPLY.to_ascii_lowercase(), OTHER_REPLY]) {
        return "reply to another request";
    }
    if has(&[&SKIP_RC4_TRUST.to_ascii_lowercase()]) {
        return "RC4-only trust";
    }
    if has(&["timeout", "timed out"]) {
        "timeout"
    } else if has(&[PIPE_NOT_AVAILABLE]) {
        "remote registry starting"
    } else if has(&[
        "rc=5 ",
        "rc=5,",
        "0xc0000022",
        "access denied",
        "access_denied",
        "accessdenied",
    ]) {
        "access denied"
    } else if has(&[
        "0xc000006d",
        "0xc000015b",
        "0xc0000071",
        "0xc0000072",
        "0xc0000234",
        "logon failure",
        "logon_failure",
        "krb:",
        "kerberos",
        "sign-in",
        "authentication",
    ]) {
        "sign-in"
    } else if has(&[
        "445",
        "refused",
        "unreachable",
        "no route",
        "connect",
        "10060",
        "10061",
        "dns",
        "resolve",
    ]) {
        "unreachable"
    } else {
        "other"
    }
}

/// The modules' error messages counted by [`error_kind`].
pub(crate) fn error_kinds<'a>(
    errors: impl IntoIterator<Item = &'a String>,
) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    for e in errors {
        *out.entry(error_kind(e).to_string()).or_insert(0) += 1;
    }
    out
}

/// The computers that one of `errors` (as the local groups module logs
/// them: `HOST: ...`, `HOST SAMR bind: ...`) is about.
pub(crate) fn hosts_with_errors<'a>(
    computers: impl IntoIterator<Item = &'a Computer>,
    errors: &[String],
) -> usize {
    computers
        .into_iter()
        .filter(|c| {
            let host = c.properties().name();
            !host.is_empty()
                && errors
                    .iter()
                    .any(|e| strip_ci(e.trim(), host).is_some_and(|r| r.starts_with([':', ' '])))
        })
        .count()
}

/// Takes from `retried` (the same computer, asked again) every session list
/// it collected and `c` did not.
pub(crate) fn take_retried(c: &mut Computer, retried: &mut Computer) {
    for l in LISTS {
        if !*list(c, l).collected() && *list(retried, l).collected() {
            *list(c, l) = list(retried, l).clone();
        }
    }
}

/// The account the SMB modules sign in as, and the domain they sign in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmbIdentity {
    /// The domain to put in the NTLM sign-in: the account's own.
    pub domain: String,
    /// The account is from another domain than the one collected (a
    /// trusted domain's user).
    pub other_domain: bool,
    /// Kerberos only with a password: the ticket cache and the KDC
    /// that computers' service tickets come from. `None`: NTLM with the
    /// password (`--allow-ntlm`), or no SMB sign-in at all.
    pub kerberos: Option<KerberosSignIn>,
}

/// Where computers' Kerberos tickets come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KerberosSignIn {
    /// The `KRB5CCNAME` of the ticket cache holding the TGT.
    pub ccache: String,
    /// The domain controller that gave the TGT (port 88).
    pub kdc: String,
}

impl SmbIdentity {
    /// From the user name in `options` as typed (see [`smb_account`] for
    /// the account the directory reports).
    pub(crate) fn of(options: &Options) -> Self {
        Self::for_user(options.username.as_deref(), &options.domain)
    }

    /// From `user` as typed, collecting `target`.
    pub(crate) fn for_user(user: Option<&str>, target: &str) -> Self {
        let target = target.trim();
        match user.and_then(account_domain) {
            Some(own) if !same_domain(own, target) => Self {
                domain: own.to_string(),
                other_domain: true,
                kerberos: None,
            },
            _ => Self {
                domain: target.to_string(),
                other_domain: false,
                kerberos: None,
            },
        }
    }

    /// `options` for an SMB module: signing in to the account's domain.
    /// Only for modules that use the domain for nothing else (sessions,
    /// WebClient, local groups on member computers).
    pub(crate) fn options(&self, options: &Options) -> Options {
        let mut o = options.clone();
        o.domain = self.domain.clone();
        o
    }
}

/// The domain part of `DOMAIN\user` or `user@domain`, if the name has one.
fn account_domain(user: &str) -> Option<&str> {
    let user = user.trim();
    let domain = if let Some((d, _)) = user.split_once('\\') {
        d
    } else {
        user.rsplit_once('@')?.1
    };
    Some(domain.trim()).filter(|d| !d.is_empty())
}

/// The NetBIOS domain and sAMAccountName in an LDAP "Who am I?" answer
/// (RFC 4532). Active Directory answers `u:DOMAIN\samaccountname`; any
/// other form (`dn:...`, a bare `u:name`, anonymous) gives `None`.
pub(crate) fn parse_who_am_i(answer: &str) -> Option<(String, String)> {
    let (domain, user) = answer.trim().strip_prefix("u:")?.split_once('\\')?;
    let (domain, user) = (domain.trim(), user.trim());
    (!domain.is_empty() && !user.is_empty() && !user.contains('\\'))
        .then(|| (domain.to_string(), user.to_string()))
}

/// The account the SMB modules sign in as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmbAccount {
    /// The user name for `Options::username` (the modules take the bare
    /// name from it with RustHound-CE's `smb_identity`).
    pub user: String,
    /// The domain they sign in to.
    pub identity: SmbIdentity,
    pub source: SmbUserSource,
}

/// Where [`smb_account`] took the account from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SmbUserSource {
    /// The directory's "Who am I?" answer after the bind, `DOMAIN\sam`.
    Directory { reported: String },
    /// The user name as typed (no usable answer).
    Typed,
}

/// The account the SMB modules sign in as. A UPN suffix is not always a
/// domain (`alice@example.com` for an account in `CORP`), so it is the
/// account the directory reports after the bind (`who_am_i`, the raw "Who
/// am I?" answer): `<collected domain>\sam` when its domain is the collected
/// one, else `NETBIOS\sam`, from another domain. With the collected
/// domain's NetBIOS name (`target_netbios`, from its crossRef), "the
/// collected one" means that name or the DNS name `target`; without it, the
/// first label of `target` is the guess. Without a usable answer, the name
/// as typed (`typed`), read as before ([`SmbIdentity::of`]).
pub(crate) fn smb_account(
    typed: &str,
    who_am_i: Option<&str>,
    target: &str,
    target_netbios: Option<&str>,
) -> SmbAccount {
    let target = target.trim().trim_end_matches('.');
    let Some((domain, sam)) = who_am_i.and_then(parse_who_am_i) else {
        return SmbAccount {
            user: typed.to_string(),
            identity: SmbIdentity::for_user(Some(typed), target),
            source: SmbUserSource::Typed,
        };
    };
    let own = match target_netbios.map(str::trim).filter(|n| !n.is_empty()) {
        Some(netbios) => netbios.eq_ignore_ascii_case(&domain) || is_dns_name_of(&domain, target),
        None => same_domain(&domain, target),
    };
    let reported = format!("{domain}\\{sam}");
    let identity = SmbIdentity {
        domain: if own { target.to_string() } else { domain },
        other_domain: !own,
        kerberos: None,
    };
    SmbAccount {
        user: format!("{}\\{sam}", identity.domain),
        identity,
        source: SmbUserSource::Directory { reported },
    }
}

/// Whether `domain` is the DNS name `target` (any case, trailing dot).
pub(crate) fn is_dns_name_of(domain: &str, target: &str) -> bool {
    domain
        .trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(target.trim().trim_end_matches('.'))
}

/// Whether `account` (a NetBIOS or DNS domain name) names `target` (a DNS
/// name). The NetBIOS name is taken to be the first label of the DNS name,
/// as RustHound-CE's own DC detection does.
fn same_domain(account: &str, target: &str) -> bool {
    let account = account.trim_end_matches('.');
    let target = target.trim_end_matches('.');
    account.eq_ignore_ascii_case(target)
        || target
            .split('.')
            .next()
            .is_some_and(|label| account.eq_ignore_ascii_case(label))
}

/// Why a computer on a retest's path wasn't contacted: the name the
/// directory gives it isn't a name in the collected domain
/// ([`contactable`]). Written as `HOST: <this>`.
pub(crate) const NOT_IN_DOMAIN: &str = "not contacted: its name isn't in the domain";

/// A DNS name that can go into `\\HOST` (letters, digits, `-`, `_`, `.`).
pub(crate) fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(['.', '-'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Whether a retest may contact the computer the directory names `name`,
/// collecting `domain`: a plain DNS name ([`valid_host`]), not an IP
/// address or `localhost`, ending in the domain's DNS name
/// (`WS1.CONTOSO.LOCAL` or `WS1.CHILD.CONTOSO.LOCAL` in `contoso.local`).
/// The domain's other allowed DNS suffixes (msDS-AllowedDNSSuffixes)
/// aren't read, so a computer named only under one of them isn't
/// contacted.
pub(crate) fn contactable(name: &str, domain: &str) -> bool {
    let name = name.trim().trim_end_matches('.');
    let domain = domain.trim().trim_end_matches('.');
    if !valid_host(name) || domain.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let first = name.split('.').next().unwrap_or_default();
    if first.eq_ignore_ascii_case("localhost") {
        return false;
    }
    let Some(head) = name.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    head > 0
        && name.as_bytes()[head] == b'.'
        && name[head + 1..].eq_ignore_ascii_case(domain)
        && !name[..head].split('.').any(str::is_empty)
}

/// A module's error, as one short reason for a sentence ("access denied"),
/// and whether it means the computer didn't answer.
#[cfg(all(test, windows))]
pub(crate) fn reason(msg: &str) -> (&'static str, bool) {
    reason_on("", msg)
}

/// [`reason`] for a message about `host`, read without the host's name.
pub(crate) fn reason_on(host: &str, msg: &str) -> (&'static str, bool) {
    if msg == NOT_ATTEMPTED {
        return (
            "not contacted, because it is disabled or its account password is older than 60 days",
            false,
        );
    }
    if msg.ends_with(NOT_IN_DOMAIN) {
        return (
            "its name in the directory isn't in the domain, so it wasn't contacted",
            false,
        );
    }
    if let Some(skip) = skip_of(msg) {
        return (skip, false);
    }
    // The computer refused the Kerberos ticket (the patched SMB client reads
    // the KRB-ERROR in its answer).
    if msg.contains("refused the Kerberos ticket") {
        return (
            if msg.contains("KRB_AP_ERR_SKEW") {
                "its clock is more than 5 minutes off the domain's, so it refused the Kerberos \
                 ticket"
            } else if msg.contains("KRB_AP_ERR_MODIFIED") {
                "it couldn't read its Kerberos ticket (its account's key doesn't match the \
                 domain's)"
            } else if msg.contains("KDC_ERR_WRONG_REALM") {
                "its Kerberos ticket was for another domain"
            } else {
                "it refused the Kerberos ticket"
            },
            false,
        );
    }
    let text = without_this_host(host, msg);
    match kind_of_text(text) {
        "timeout" => ("it didn't answer in time", true),
        "unreachable" if text.contains("445") => ("it didn't answer on port 445", true),
        "unreachable" => ("it couldn't be reached", true),
        "access denied" => ("access denied", false),
        "sign-in" => ("the sign-in was refused", false),
        "remote registry starting" => ("Remote Registry was still starting", false),
        _ => ("it couldn't be read", false),
    }
}

/// What a retest read of one computer on a finding's path (`want`): its
/// sessions when a list that names logged-on users answered (WKSSVC or
/// Remote Registry; SRVSVC lists only network connections), its local
/// groups when every group asked answered. `group_errors` is what the
/// local groups module logged.
pub(crate) fn host_read(
    c: &mut Computer,
    want: &pathwarden_core::retest::targeted::SliceHost,
    group_errors: &[String],
) -> pathwarden_core::retest::targeted::HostRead {
    let name = c.properties().name().clone();
    let mut reasons: Vec<(&'static str, bool)> = Vec::new();
    let sessions = want.sessions.then(|| {
        let ok = *c.privileged_sessions_mut().collected() || *c.registry_sessions_mut().collected();
        if !ok {
            for l in [Call::Wkssvc, Call::Winreg, Call::Srvsvc] {
                if let Some(why) = list(c, l).failure_reason().as_deref() {
                    reasons.push(reason_on(&name, why));
                    break;
                }
            }
        }
        ok
    });
    let local_groups = want.local_groups.then(|| {
        let groups = c.local_groups_mut();
        let ok = !groups.is_empty() && groups.iter().all(|g| *g.collected());
        if !ok {
            let logged = group_errors
                .iter()
                .find(|e| strip_ci(e.trim(), &name).is_some_and(|r| r.starts_with([':', ' '])));
            let failed = groups.iter().find_map(|g| g.failure_reason().clone());
            match logged.cloned().or(failed) {
                Some(why) => reasons.push(reason_on(&name, &why)),
                None => reasons.push(("its local groups weren't read", false)),
            }
        }
        ok
    });
    let skipped = reasons.first().is_some_and(|(w, _)| {
        [
            SKIP_NO_KERBEROS_NAME,
            SKIP_UNSIGNED,
            SKIP_BAD_REPLY,
            SKIP_RC4_TRUST,
        ]
        .contains(w)
    });
    pathwarden_core::retest::targeted::HostRead {
        id: c.object_identifier().clone(),
        name,
        sessions,
        local_groups,
        why: reasons.first().map(|(w, _)| w.to_string()),
        unreachable: !reasons.is_empty() && reasons.iter().all(|(_, u)| *u),
        skipped,
        ..Default::default()
    }
}

/// Why the collector skipped a computer, in the words the report
/// and the retest use, when `msg` (a session list's reason or a logged
/// error) says it did.
pub(crate) fn skip_of(msg: &str) -> Option<&'static str> {
    if msg.contains(SKIP_NO_KERBEROS_NAME) {
        Some(SKIP_NO_KERBEROS_NAME)
    } else if msg.contains(SKIP_UNSIGNED) || msg.contains(UNSIGNED_REPLY) {
        Some(SKIP_UNSIGNED)
    } else if msg.contains(SKIP_BAD_REPLY) || msg.contains(OTHER_REPLY) {
        Some(SKIP_BAD_REPLY)
    } else if msg.contains(SKIP_RC4_TRUST) {
        Some(SKIP_RC4_TRUST)
    } else {
        None
    }
}

/// What the patched SMB client (vendor/smb2-client) says when a reply's
/// signature is missing or wrong: "SMB2 READ answered without a valid
/// signature".
pub(crate) const UNSIGNED_REPLY: &str = "without a valid signature";

/// What it says when a reply answers another request (replayed or
/// misdirected): "SMB2 READ answered with a reply to another request".
pub(crate) const OTHER_REPLY: &str = "answered with a reply to another request";

pub(crate) use pathwarden_core::ingest::{
    SKIP_BAD_REPLY, SKIP_NO_KERBEROS_NAME, SKIP_RC4_TRUST, SKIP_UNSIGNED,
};

/// The reason recorded for a computer whose reply answered another request
/// (`detail`: the SMB client's error).
pub(crate) fn skipped_bad_reply(host: &str, detail: &str) -> String {
    format!("{host}: skipped: {SKIP_BAD_REPLY} ({detail})")
}

/// The reason recorded for a computer whose replies weren't signed
/// (`detail`: the SMB client's error).
pub(crate) fn skipped_unsigned(host: &str, detail: &str) -> String {
    format!("{host}: skipped: {SKIP_UNSIGNED} ({detail})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A computer named `name`, as the parser leaves it (2.5.26: no session
    /// list collected).
    fn computer(name: &str, sid: &str) -> Computer {
        let mut v = serde_json::to_value(Computer::default()).unwrap();
        v["Properties"]["name"] = name.into();
        v["Properties"]["is_dc"] = false.into();
        v["ObjectIdentifier"] = sid.into();
        serde_json::from_value(v).unwrap()
    }

    fn state(c: &mut Computer) -> [(bool, Option<String>); 3] {
        LISTS.map(|l| {
            let s = list(c, l);
            (*s.collected(), s.failure_reason().clone())
        })
    }

    /// What a retest read of a computer: sessions when a list naming
    /// logged-on users answered, local groups when every group did, with a
    /// short reason otherwise.
    #[test]
    fn host_reads_say_what_was_read_and_why_not() {
        use pathwarden_core::retest::targeted::SliceHost;
        let host = "WS1.CONTOSO.LOCAL";
        let want = SliceHost {
            id: "S-1-5-21-1-2-3-1001".into(),
            sessions: true,
            local_groups: true,
            ..Default::default()
        };
        // 445 closed: nothing read, unreachable.
        let mut c = computer(host, &want.id);
        let gone = format!("{host}: 445/tcp unreachable");
        mark_sessions_not_collected(std::slice::from_mut(&mut c), &gone);
        let r = host_read(&mut c, &want, std::slice::from_ref(&gone));
        assert_eq!((r.sessions, r.local_groups), (Some(false), Some(false)));
        assert!(r.unreachable);
        assert_eq!(r.why.as_deref(), Some("it didn't answer on port 445"));
        assert_eq!(r.name, host);

        // Only SRVSVC answered: not enough to say nobody is logged on.
        let mut c = computer(host, &want.id);
        mark_sessions_not_collected(std::slice::from_mut(&mut c), "x");
        *c.sessions_mut().collected_mut() = true;
        let denied = format!("[{host}] WKSSVC rc=5 (local admin required)");
        *c.privileged_sessions_mut().failure_reason_mut() = Some(denied);
        let mut g = rusthound_ce::objects::common::LocalGroup::new();
        *g.collected_mut() = true;
        c.local_groups_mut().push(g);
        let r = host_read(&mut c, &want, &[]);
        assert_eq!((r.sessions, r.local_groups), (Some(false), Some(true)));
        assert!(!r.unreachable);
        assert_eq!(r.why.as_deref(), Some("access denied"));

        // Remote Registry answered: read.
        *c.registry_sessions_mut().collected_mut() = true;
        let only_sessions = SliceHost {
            local_groups: false,
            ..want.clone()
        };
        let r = host_read(&mut c, &only_sessions, &[]);
        assert_eq!(
            (r.sessions, r.local_groups, r.why),
            (Some(true), None, None)
        );
    }

    /// Only DNS names in the collected domain are contacted.
    #[test]
    fn only_names_in_the_domain_are_contacted() {
        for ok in [
            "WS1.CONTOSO.LOCAL",
            "ws1.contoso.local.",
            "SRV_01.CHILD.CONTOSO.LOCAL",
        ] {
            assert!(contactable(ok, "contoso.local"), "{ok}");
        }
        for bad in [
            "",
            "WS1",
            "CONTOSO.LOCAL",
            "WS1.EVILCONTOSO.LOCAL",
            "WS1.CONTOSO.LOCAL.EVIL.COM",
            "WS1.FABRIKAM.LOCAL",
            "10.0.0.5",
            "::1",
            "[::1]",
            "fe80::1%3",
            "localhost",
            "LOCALHOST.CONTOSO.LOCAL",
            "localhost.",
            "WS1..CONTOSO.LOCAL",
            ".CONTOSO.LOCAL",
            "\\\\WS1.CONTOSO.LOCAL\\C$",
            "WS1.CONTOSO.LOCAL/x",
            "WS1 .CONTOSO.LOCAL",
        ] {
            assert!(!contactable(bad, "contoso.local"), "{bad:?}");
        }
        assert!(!contactable("WS1.CONTOSO.LOCAL", ""));

        // A computer that wasn't contacted for its name says why.
        let host = "WS9.ELSEWHERE.EXAMPLE";
        let want = pathwarden_core::retest::targeted::SliceHost {
            id: "S-1-5-21-1-2-3-1009".into(),
            sessions: true,
            local_groups: true,
            ..Default::default()
        };
        let mut c = computer(host, &want.id);
        let why = format!("{host}: {NOT_IN_DOMAIN}");
        mark_sessions_not_collected(std::slice::from_mut(&mut c), &why);
        let r = host_read(&mut c, &want, std::slice::from_ref(&why));
        assert_eq!((r.sessions, r.local_groups), (Some(false), Some(false)));
        assert!(!r.unreachable);
        assert_eq!(
            r.why.as_deref(),
            Some("its name in the directory isn't in the domain, so it wasn't contacted")
        );
    }

    /// A computer that refused the Kerberos ticket: why, in plain words, and
    /// a sign-in error in the counts.
    #[test]
    fn kerberos_refusals_in_plain_words() {
        let host = "SRV01.CONTOSO.LOCAL";
        let msg = |code: &str| {
            format!("{host}: auth(krb): SMB2 SESSION_SETUP refused the Kerberos ticket: {code}")
        };
        assert!(reason_on(host, &msg("KRB_AP_ERR_SKEW (37)"))
            .0
            .contains("clock"));
        assert!(reason_on(host, &msg("KRB_AP_ERR_MODIFIED (41)"))
            .0
            .contains("key"));
        assert!(reason_on(host, &msg("KDC_ERR_WRONG_REALM (68)"))
            .0
            .contains("another domain"));
        assert_eq!(
            reason_on(host, &msg("Kerberos error (99)")).0,
            "it refused the Kerberos ticket"
        );
        assert_eq!(error_kind(&msg("KRB_AP_ERR_SKEW (37)")), "sign-in");
    }

    /// The SMB path's messages are sorted by what follows the host name.
    #[test]
    fn host_names_dont_decide_the_kind() {
        for host in [
            "DNS01.CONTOSO.LOCAL",
            "CONNECT.CONTOSO.LOCAL",
            "SRV445.CONTOSO.LOCAL",
            "TIMEOUT01.CONTOSO.LOCAL",
            "KERBEROS.CONTOSO.LOCAL",
        ] {
            let denied = format!("[{host}] WKSSVC rc=5 (local admin required)");
            assert_eq!(error_kind(&denied), "access denied", "{denied}");
            assert_eq!(reason_on(host, &denied), ("access denied", false));
            let share = format!("{host}: tree connect \\\\x\\IPC$: SMB2 status 0xc0000022");
            assert_eq!(error_kind(&share), "access denied", "{share}");
            let odd = format!("{host} SAMR bind: something new");
            assert_eq!(error_kind(&odd), "other", "{odd}");
            assert_eq!(reason_on(host, &odd), ("it couldn't be read", false));
            let gone = format!("{host}: 445/tcp unreachable");
            assert_eq!(
                reason_on(host, &gone),
                ("it didn't answer on port 445", true)
            );
            let slow = format!("{host}: per-host timeout");
            assert_eq!(reason_on(host, &slow), ("it didn't answer in time", true));
        }
        // A short name with a keyword, as the host_read path strips it.
        assert_eq!(
            reason_on("DNS01", "DNS01 SAMR bind: something new"),
            ("it couldn't be read", false)
        );
    }

    #[test]
    fn marking_sessions_not_collected_records_the_reason() {
        // RustHound-CE 2.5.26 defaults Session to not collected with no
        // reason; marking records why (DC-only, skipped, etc.).
        let mut c = computer("WS1.CONTOSO.LOCAL", "S-1-5-21-1-2-3-1001");
        assert!(state(&mut c)
            .iter()
            .all(|(collected, why)| !collected && why.is_none()));
        mark_sessions_not_collected(std::slice::from_mut(&mut c), NOT_CONTACTED);
        assert!(state(&mut c)
            .iter()
            .all(|(collected, why)| !collected && why.as_deref() == Some(NOT_CONTACTED)));
    }

    #[test]
    fn errors_are_matched_to_their_computer_and_call() {
        let host = "CASTELBLACK.NORTH.SEVENKINGDOMS.LOCAL";
        assert_eq!(
            call_of(
                host,
                &format!("[{host}] SRVSVC rc=5 ACCESS_DENIED (hardened / non-admin)")
            ),
            Some(Call::Srvsvc)
        );
        assert_eq!(
            call_of(host, &format!("{host} SRVSVC: bind failed")),
            Some(Call::Srvsvc)
        );
        assert_eq!(
            call_of(
                host,
                &format!("[{host}] WKSSVC rc=5 (local admin required)")
            ),
            Some(Call::Wkssvc)
        );
        assert_eq!(
            call_of(host, &format!("{host} WINREG: protocol: open \\winreg: SMB2 status 0xc00000ac for command 0x0005 (RemoteRegistry stopped?)")),
            Some(Call::Winreg)
        );
        for all in [
            format!("{host}: auth: SMB2 status 0xc000006d for command 0x0001"),
            format!("{host}: tree connect \\\\{host}\\IPC$: SMB2 status 0xc0000022"),
            format!("{host}: 445/tcp unreachable"),
            format!("{host}: per-host timeout"),
            format!("{host} krb: no ticket"),
        ] {
            assert_eq!(call_of(host, &all), Some(Call::All), "{all}");
        }
        // Case-insensitive host, as names come from LDAP.
        assert_eq!(
            call_of(
                host,
                &format!("{}: 445/tcp unreachable", host.to_lowercase())
            ),
            Some(Call::All)
        );
        // Another computer whose name starts the same, and other warnings.
        assert_eq!(
            call_of("WS1.CONTOSO.LOCAL", "WS1.CONTOSO.LOCAL.EVIL: x"),
            None
        );
        assert_eq!(call_of("WS1", "WS10: auth: x"), None);
        assert_eq!(
            call_of(
                host,
                "[S-1-5-21-1-2-3-1105] unresolved SRVSVC principal 'x'"
            ),
            None
        );
        assert_eq!(call_of("", ": x"), None);
    }

    #[test]
    fn failed_calls_are_not_collected_and_successes_lose_their_reason() {
        // As in the GOAD run: castelblack denied all three calls, braavos
        // refused the share, winterfell denied SRVSVC only; ws2 answered;
        // old was never tried.
        let mut cs = vec![
            computer("CASTELBLACK.NORTH.LOCAL", "S-1"),
            computer("BRAAVOS.ESSOS.LOCAL", "S-2"),
            computer("WINTERFELL.NORTH.LOCAL", "S-3"),
            computer("WS2.NORTH.LOCAL", "S-4"),
            computer("OLD.NORTH.LOCAL", "S-5"),
        ];
        mark_sessions_not_collected(&mut cs, NOT_ATTEMPTED);
        // What the 2.5.26 module leaves on the computers it tried: Collected
        // only on the calls that succeeded. castelblack and braavos failed
        // every call; winterfell's SRVSVC failed but WKSSVC and WINREG
        // succeeded; ws2 succeeded on all three. (Failed lists keep the
        // module's reason; apply_session_errors fills it from the log below.)
        *cs[2].privileged_sessions_mut().collected_mut() = true;
        *cs[2].registry_sessions_mut().collected_mut() = true;
        for l in LISTS {
            *list(&mut cs[3], l).collected_mut() = true;
        }
        let errors = vec![
            "[CASTELBLACK.NORTH.LOCAL] SRVSVC rc=5 ACCESS_DENIED (hardened / non-admin)".to_string(),
            "[CASTELBLACK.NORTH.LOCAL] WKSSVC rc=5 (local admin required)".to_string(),
            "CASTELBLACK.NORTH.LOCAL WINREG: pipe not available (RemoteRegistry stopped?)".to_string(),
            "BRAAVOS.ESSOS.LOCAL: tree connect \\\\BRAAVOS.ESSOS.LOCAL\\IPC$: SMB2 status 0xc0000022".to_string(),
            "[WINTERFELL.NORTH.LOCAL] SRVSVC rc=5 ACCESS_DENIED (hardened / non-admin)".to_string(),
        ];
        apply_session_errors(&mut cs, Some(&errors));
        assert_eq!(fully_collected(&mut cs), 1);
        // Winterfell still has two lists: the report counts it collected.
        assert_eq!(partly_collected(&mut cs), 2);
        let mut not_read = NotRead::of_sessions(&mut cs);
        assert_eq!(
            not_read,
            NotRead {
                tried: 4,
                sessions: 3,
                by_call: [3, 2, 2],
                local_groups: 0,
            }
        );
        not_read.local_groups = hosts_with_errors(
            &cs,
            &[
                "CASTELBLACK.NORTH.LOCAL SamrConnect2: rc=5".to_string(),
                "castelblack.north.local: per-host timeout".to_string(),
                "BRAAVOS.ESSOS.LOCAL: 445/tcp unreachable".to_string(),
                "[localgroups] no computer object for SID S-9".to_string(),
                "WS2.NORTH.LOCALX: not this one".to_string(),
            ],
        );
        assert_eq!(not_read.local_groups, 2);
        let w = not_read.warning().unwrap();
        assert!(
            w.contains("Sessions were not fully read on 3 of 4 computers (SRVSVC on 3, WKSSVC on 2, Remote Registry on 2).")
                && w.contains("Local groups were not read on 2 computers."),
            "{w}"
        );
        assert_eq!(NotRead::default().warning(), None);
        assert!(state(&mut cs[0]).iter().all(|(c, why)| !c && why.is_some()));
        let braavos = state(&mut cs[1]);
        assert!(braavos
            .iter()
            .all(|(c, why)| !c && why.as_deref().unwrap().contains("0xc0000022")));
        let winterfell = state(&mut cs[2]);
        assert!(!winterfell[0].0);
        assert_eq!(winterfell[1], (true, None));
        assert_eq!(winterfell[2], (true, None));
        assert!(state(&mut cs[3]).iter().all(|s| *s == (true, None)));
        assert!(state(&mut cs[4])
            .iter()
            .all(|(c, why)| !c && why.as_deref() == Some(NOT_ATTEMPTED)));
    }

    #[test]
    fn a_per_host_timeout_keeps_an_earlier_success() {
        // 2.5.26: SRVSVC succeeded with real sessions, then WKSSVC/WINREG hung
        // and the module logged one per-host timeout (Call::All). The success
        // and its result links must survive; only the unfinished calls fail.
        let mut c = computer("WS1.NORTH.LOCAL", "S-1");
        mark_sessions_not_collected(std::slice::from_mut(&mut c), NOT_ATTEMPTED);
        let mut link = rusthound_ce::objects::common::UserComputerSession::new();
        *link.user_sid_mut() = "S-1-5-21-1-2-3-1113".into();
        *link.computer_sid_mut() = "S-1".into();
        c.sessions_mut().results_mut().push(link);
        *c.sessions_mut().collected_mut() = true;
        apply_session_errors(
            std::slice::from_mut(&mut c),
            Some(&["WS1.NORTH.LOCAL: per-host timeout".to_string()]),
        );
        let st = state(&mut c);
        assert_eq!(st[0], (true, None));
        assert_eq!(c.sessions_mut().results().len(), 1);
        assert!(st[1..]
            .iter()
            .all(|(col, why)| !col && why.as_deref() == Some("WS1.NORTH.LOCAL: per-host timeout")));
    }

    #[test]
    fn the_host_summary_counts_reached_failed_and_timed_out() {
        let names = ["SKIP", "OK", "SLOW", "DENIED"];
        let mut cs: Vec<Computer> = names
            .iter()
            .map(|n| computer(&format!("{n}.NORTH.LOCAL"), "S-1"))
            .collect();
        mark_sessions_not_collected(&mut cs, NOT_ATTEMPTED);
        *cs[1].sessions_mut().collected_mut() = true;
        let errors = [
            "SLOW.NORTH.LOCAL: per-host timeout".to_string(),
            "[DENIED.NORTH.LOCAL] SRVSVC rc=5 (access denied)".to_string(),
            "DENIED.NORTH.LOCAL WKSSVC: rc=5, access denied".to_string(),
            "DENIED.NORTH.LOCAL WINREG: STATUS_ACCESS_DENIED".to_string(),
        ];
        apply_session_errors(&mut cs, Some(&errors));
        // Untried after the module: still NOT_ATTEMPTED.
        let s = summary(&mut cs);
        assert_eq!(
            (s.computers, s.tried, s.reached, s.failed, s.timed_out),
            (4, 3, 1, 1, 1)
        );
        let kinds = error_kinds(&errors);
        assert_eq!(kinds.get("access denied"), Some(&3));
        assert_eq!(kinds.get("timeout"), Some(&1));
        // Counts by kind only: no computer in the keys.
        assert!(kinds.keys().all(|k| !k.contains("NORTH")));
        assert_eq!(error_kind("WS1: 445 closed"), "unreachable");
        assert_eq!(error_kind("WS1: logon failure 0xc000006d"), "sign-in");
        assert_eq!(
            error_kind("WS1 WINREG: 0xc00000ac"),
            "remote registry starting"
        );
        assert_eq!(error_kind("WS1: something new"), "other");
        // The bundle's check knows every kind as Pathwarden's own.
        for msg in [
            "timed out",
            "WS1 WINREG: 0xc00000ac",
            "access denied",
            "logon failure",
            "445",
            "new",
        ] {
            let kind = error_kind(msg);
            assert!(
                pathwarden_core::diagnostics::ERROR_KINDS.contains(&kind),
                "{kind}"
            );
        }
    }

    #[test]
    fn without_the_errors_the_modules_state_stands() {
        // RustHound-CE 2.5.26 marks a list collected only when its call
        // succeeded, so when the log can't be read its per-list state is
        // trusted as is.
        let mut cs = vec![computer("A.X.LOCAL", "S-1")];
        mark_sessions_not_collected(&mut cs, NOT_ATTEMPTED);
        // The module reached SRVSVC (an empty but genuine success); the other
        // two it left not collected.
        *cs[0].sessions_mut().collected_mut() = true;
        *cs[0].sessions_mut().failure_reason_mut() = None;
        apply_session_errors(&mut cs, None);
        assert_eq!(partly_collected(&mut cs), 1);
        let st = state(&mut cs[0]);
        assert_eq!(st[0], (true, None));
        assert!(st[1..]
            .iter()
            .all(|(c, why)| !c && why.as_deref() == Some(NOT_ATTEMPTED)));
    }

    #[test]
    fn a_starting_remote_registry_is_asked_again() {
        let starting = "CASTELBLACK.NORTH.LOCAL WINREG: protocol: open \\winreg: SMB2 status \
                        0xc00000ac for command 0x0005 (RemoteRegistry stopped?)";
        let mut c = computer("CASTELBLACK.NORTH.LOCAL", "S-1");
        apply_session_errors(
            std::slice::from_mut(&mut c),
            Some(&[
                "[CASTELBLACK.NORTH.LOCAL] SRVSVC rc=5 ACCESS_DENIED (hardened / non-admin)"
                    .to_string(),
                starting.to_string(),
            ]),
        );
        assert!(registry_was_starting(&mut c));
        // Denied, or another WINREG error: not retried.
        let mut denied = computer("WS1.NORTH.LOCAL", "S-2");
        apply_session_errors(
            std::slice::from_mut(&mut denied),
            Some(&["WS1.NORTH.LOCAL WINREG: SMB2 status 0xc0000022".to_string()]),
        );
        assert!(!registry_was_starting(&mut denied));
        assert!(!registry_was_starting(&mut computer(
            "WS2.NORTH.LOCAL",
            "S-3"
        )));

        // The second pass reads the registry (SRVSVC still denied): only
        // what it newly collected is taken.
        let mut retried = computer("CASTELBLACK.NORTH.LOCAL", "S-1");
        let mut link = rusthound_ce::objects::common::UserComputerSession::new();
        *link.user_sid_mut() = "S-1-5-21-1-2-3-1113".into();
        *link.computer_sid_mut() = "S-1".into();
        retried.registry_sessions_mut().results_mut().push(link);
        // 2.5.26 marks the list collected on the successful retry.
        *retried.registry_sessions_mut().collected_mut() = true;
        set_not_collected(retried.sessions_mut(), "denied again");
        take_retried(&mut c, &mut retried);
        let after = state(&mut c);
        assert!(!after[0].0 && after[0].1.as_deref().unwrap().contains("SRVSVC"));
        assert_eq!(after[2], (true, None));
        assert_eq!(c.registry_sessions_mut().results().len(), 1);
        assert!(!registry_was_starting(&mut c));
    }

    #[test]
    fn smb_signs_in_to_the_accounts_own_domain() {
        let o = |domain: &str, user: Option<&str>| {
            let mut o = crate::builtin::base_options(
                domain,
                std::path::Path::new("."),
                rusthound_ce::args::CollectionMethod::All,
                "dc".into(),
                true,
            );
            o.username = user.map(str::to_string);
            o
        };
        let id = |domain: &str, user: Option<&str>| {
            let i = SmbIdentity::of(&o(domain, user));
            (i.domain, i.other_domain)
        };
        // The GOAD case: a north account collecting the parent and a trusted forest.
        assert_eq!(
            id("essos.local", Some(r"NORTH\samwell.tarly")),
            ("NORTH".to_string(), true)
        );
        assert_eq!(
            id(
                "sevenkingdoms.local",
                Some("samwell.tarly@north.sevenkingdoms.local")
            ),
            ("north.sevenkingdoms.local".to_string(), true)
        );
        // Its own domain, by NetBIOS or DNS name, or no domain given: as before.
        for user in [
            r"NORTH\samwell.tarly",
            r"north.sevenkingdoms.local\samwell.tarly",
            "samwell.tarly@NORTH.SEVENKINGDOMS.LOCAL",
            "samwell.tarly@north.sevenkingdoms.local",
        ] {
            assert_eq!(
                id("north.sevenkingdoms.local", Some(user)),
                ("north.sevenkingdoms.local".to_string(), false),
                "{user}"
            );
        }
        assert_eq!(
            id("contoso.local", None),
            ("contoso.local".to_string(), false)
        );
        assert_eq!(
            id("contoso.local", Some(r"\svc")),
            ("contoso.local".to_string(), false)
        );
        let opts = o("essos.local", Some(r"NORTH\samwell.tarly"));
        let smb = SmbIdentity::of(&opts).options(&opts);
        assert_eq!(smb.domain, "NORTH");
        assert_eq!(smb.username, opts.username);
    }

    #[test]
    fn who_am_i_answers_are_parsed() {
        let p = |s: &str| parse_who_am_i(s);
        assert_eq!(p(r"u:CHILD\alice"), Some(("CHILD".into(), "alice".into())));
        // Case kept as the directory gave it.
        assert_eq!(
            p(r"u:North\Samwell.Tarly"),
            Some(("North".into(), "Samwell.Tarly".into()))
        );
        assert_eq!(
            p(" u:CHILD\\alice \n"),
            Some(("CHILD".into(), "alice".into()))
        );
        for s in [
            "u:alice",
            "dn:CN=alice,CN=Users,DC=child,DC=example,DC=local",
            "",
            "u:",
            "   ",
            r"u:\alice",
            r"u:CHILD\",
            r"u:CHILD\ ",
            r"u:A\B\c",
            r"CHILD\alice",
        ] {
            assert_eq!(p(s), None, "{s:?}");
        }
    }

    /// What the SMB modules send for `account`, collecting `target`: the
    /// bare user name and domain (RustHound-CE's `smb_identity`, fed the name
    /// and `SmbIdentity::options`' domain), and whether the account is from
    /// another domain.
    fn sent(account: &SmbAccount, target: &str) -> (String, String, bool) {
        let mut o = crate::builtin::base_options(
            target,
            std::path::Path::new("."),
            rusthound_ce::args::CollectionMethod::All,
            "dc".into(),
            true,
        );
        o.username = Some(account.user.clone());
        let smb = account.identity.options(&o);
        // The module derives both from the name and --domain (2.5.26's
        // smb_identity, which returns (domain, user)).
        let (domain, user) = rusthound_ce::transport::smb::smb_identity(
            smb.username.as_deref().unwrap(),
            &smb.domain,
        );
        (user, domain, account.identity.other_domain)
    }

    fn s(user: &str, domain: &str, other: bool) -> (String, String, bool) {
        (user.to_string(), domain.to_string(), other)
    }

    #[test]
    fn smb_account_follows_the_directory() {
        let a = |typed: &str, who: &str, target: &str, nb: Option<&str>| {
            let account = smb_account(typed, Some(who), target, nb);
            let reported = parse_who_am_i(who).map(|(d, u)| format!("{d}\\{u}"));
            assert_eq!(
                account.source,
                SmbUserSource::Directory {
                    reported: reported.unwrap()
                },
                "{who}"
            );
            (account.user.clone(), sent(&account, target))
        };
        // An alternative UPN suffix, collecting the account's own domain.
        assert_eq!(
            a(
                "alice@example.com",
                r"u:CORP\alice",
                "corp.local",
                Some("CORP")
            ),
            (r"corp.local\alice".into(), s("alice", "corp.local", false))
        );
        // NetBIOS name unlike the first label: matched by the looked-up name.
        assert_eq!(
            a(
                "alice@example.com",
                r"u:CORPAD\alice",
                "corp.local",
                Some("corpad")
            ),
            (r"corp.local\alice".into(), s("alice", "corp.local", false))
        );
        // The collision: collected corp.local is CORPAD; CORP is a trusted
        // domain, whatever the first label says.
        assert_eq!(
            a(
                "alice@example.com",
                r"u:CORP\alice",
                "corp.local",
                Some("CORPAD")
            ),
            (r"CORP\alice".into(), s("alice", "CORP", true))
        );
        // No NetBIOS name known: the first label is the guess.
        assert_eq!(
            a("alice@example.com", r"u:CORP\alice", "corp.local.", None),
            (r"corp.local\alice".into(), s("alice", "corp.local", false))
        );
        // A lowercase answer against an uppercase --domain.
        assert_eq!(
            a(
                "alice@example.com",
                r"u:corp\Alice",
                "CORP.LOCAL",
                Some("CORP")
            ),
            (r"CORP.LOCAL\Alice".into(), s("Alice", "CORP.LOCAL", false))
        );
        // An answer naming the DNS name (not what AD sends, but the same domain).
        assert_eq!(
            a(
                "alice@example.com",
                r"u:corp.local\alice",
                "corp.local",
                Some("CORPAD")
            ),
            (r"corp.local\alice".into(), s("alice", "corp.local", false))
        );
        // A child domain's account collecting the parent: its own NetBIOS name.
        assert_eq!(
            a(
                "alice@example.com",
                r"u:CHILD\Alice",
                "example.local",
                Some("EXAMPLE")
            ),
            (r"CHILD\Alice".into(), s("Alice", "CHILD", true))
        );
        // The lab case: samwell.tarly@example.com, collecting north and the parent.
        assert_eq!(
            a(
                "samwell.tarly@example.com",
                r"u:NORTH\samwell.tarly",
                "north.sevenkingdoms.local",
                Some("NORTH")
            ),
            (
                r"north.sevenkingdoms.local\samwell.tarly".into(),
                s("samwell.tarly", "north.sevenkingdoms.local", false)
            )
        );
        assert_eq!(
            a(
                "samwell.tarly@example.com",
                r"u:NORTH\samwell.tarly",
                "sevenkingdoms.local",
                Some("SEVENKINGDOMS")
            ),
            (
                r"NORTH\samwell.tarly".into(),
                s("samwell.tarly", "NORTH", true)
            )
        );
    }

    #[test]
    fn without_an_answer_the_typed_name_is_used() {
        for who in [
            None,
            Some(""),
            Some("u:alice"),
            Some("dn:CN=alice,DC=corp,DC=local"),
        ] {
            let account = smb_account(
                "alice@child.example.local",
                who,
                "example.local",
                Some("EXAMPLE"),
            );
            assert_eq!(account.source, SmbUserSource::Typed, "{who:?}");
            assert_eq!(account.user, "alice@child.example.local");
            assert_eq!(
                sent(&account, "example.local"),
                s("alice", "child.example.local", true),
                "{who:?}"
            );
        }
        // Typed in the collected domain: its own domain. 2.5.26's smb_identity
        // takes the NetBIOS domain from the `DOMAIN\user` name (both forms sign
        // in to the same domain).
        let account = smb_account(
            r"NORTH\samwell.tarly",
            None,
            "north.sevenkingdoms.local",
            None,
        );
        assert_eq!(
            sent(&account, "north.sevenkingdoms.local"),
            s("samwell.tarly", "NORTH", false)
        );
    }
}
