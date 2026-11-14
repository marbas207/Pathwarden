//! Kerberos only with an account from another domain or forest.
//!
//! The collected domain's controller doesn't know such an account, so it
//! can't give it a TGT. The TGT comes from the account's own domain instead,
//! and the computers' tickets follow the referrals from there
//! ([`super::krbref`]), as for the trusted domains of a run.
//!
//! The AS-REQ carries pre-authentication data (a timestamp encrypted with a
//! key from the password), which can be cracked offline. So it goes only to
//! a domain controller that was checked the way the collected domain's is:
//!
//! 1. LDAPS only: the collected domain's directory is read over its checked
//!    LDAPS connection. Over plain LDAP the run is refused ([`needs_ldaps`]).
//! 2. The account's domain's DNS name comes from that directory
//!    ([`pick_realm`]): the forest's partitions (`crossRef`, NetBIOS name to
//!    `dnsRoot`), then the domain's trusts (`trustedDomain`, `flatName` to
//!    `trustPartner`), and only a trust the collected domain gives
//!    (outbound: it trusts the account's domain). When the user name was
//!    typed with a DNS domain, that must be the domain found. Anything else
//!    is refused, never guessed.
//! 3. Its domain controller: the one `--server REALM=HOST` names, else up to
//!    [`MAX_TRIED`] found by DNS ([`crate::locate::candidates`]), by full
//!    name inside that domain only.
//! 4. Before anything is sent on port 88, each is checked over LDAPS in
//!    turn ([`verify_ldaps`]): its name is resolved once, the connection
//!    goes to that address, the certificate must chain to a root this
//!    computer trusts and match the name, and the RootDSE must name that
//!    domain. If none passes, nothing is sent and the collection stops.
//! 5. The AS-REQs go to the address just checked, port 88; the reply is
//!    checked as the collected domain's is (nonce, client, realm, the
//!    `krbtgt/REALM` service, AES256, `krb::request_tgt`).
//!
//! "Don't check the certificate" (`--insecure-skip-tls-verify`) turns off
//! step 4's certificate check as it does every other LDAPS check of the
//! run; the RootDSE check stays.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings};
use pathwarden_core::storedcreds::NetbiosName;

use super::krb;
use crate::{ConnectionError, Secret};

/// The LDAPS port a domain controller is checked on.
pub(crate) const LDAPS_PORT: u16 = 636;
/// How long the LDAPS check may take.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one address has to accept the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Most located domain controllers checked before refusing.
pub(crate) const MAX_TRIED: usize = 3;

/// What [`OwnRealmDc::verify`] returns: the address to send the AS-REQs to.
pub(crate) type Verifying<'a> = Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;

/// Where the account's own domain's controllers come from, and their
/// check. [`System`] in a collection; a fake in tests.
pub(crate) trait OwnRealmDc: Send + Sync {
    /// `realm`'s domain controllers by full name, best first (only names
    /// inside the domain are used). `log` gets what was tried.
    fn locate(&self, realm: &str, log: &mut dyn FnMut(String)) -> Vec<String>;
    /// When none of those passed: the names found afresh, not from
    /// a cache (`DsGetDcName` with forced rediscovery), other than `known`.
    fn rediscover(
        &self,
        _realm: &str,
        _known: &[String],
        _log: &mut dyn FnMut(String),
    ) -> Vec<String> {
        Vec::new()
    }
    /// Checks `host` over LDAPS as a domain controller of `realm`; `Ok`
    /// with the KDC address to use (the address checked, port 88), `Err`
    /// with why not.
    fn verify<'a>(&'a self, host: &'a str, realm: &'a str, skip_verify: bool) -> Verifying<'a>;
}

/// DNS (and `DsGetDcName` on Windows), then [`verify_ldaps`] on port 636.
pub(crate) struct System;

impl OwnRealmDc for System {
    fn locate(&self, realm: &str, log: &mut dyn FnMut(String)) -> Vec<String> {
        crate::locate::candidates_here(realm, log)
    }

    fn rediscover(
        &self,
        realm: &str,
        known: &[String],
        log: &mut dyn FnMut(String),
    ) -> Vec<String> {
        crate::locate::rediscovered_here(realm, known, log)
    }

    fn verify<'a>(&'a self, host: &'a str, realm: &'a str, skip_verify: bool) -> Verifying<'a> {
        Box::pin(async move {
            let addr = verify_ldaps(host, LDAPS_PORT, realm, skip_verify).await?;
            Ok(kdc_address(addr))
        })
    }
}

/// The KDC on the host at `checked` (the address the LDAPS check
/// connected to): the same address, port 88.
pub(crate) fn kdc_address(checked: SocketAddr) -> String {
    SocketAddr::new(checked.ip(), 88).to_string()
}

/// Checks that `host` is a domain controller of `realm` over LDAPS on
/// `port`, as the collected domain's is checked: `host` is resolved once,
/// the TLS connection goes to the first address that answers, its
/// certificate must chain to a root this computer trusts and match `host`
/// (unless `skip_verify`), then the RootDSE must name `realm` as its
/// domain. No sign-in: nothing about the account is sent. `Ok` with the
/// address checked.
pub(crate) async fn verify_ldaps(
    host: &str,
    port: u16,
    realm: &str,
    skip_verify: bool,
) -> Result<SocketAddr, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(VERIFY_TIMEOUT, tokio::net::lookup_host((bare, port)))
            .await
            .map_err(|_| "its name didn't resolve in time".to_string())?
            .map_err(|e| format!("its name didn't resolve: {e}"))?
            .collect();
    let mut stream = None;
    let mut last = "its name resolves to no address".to_string();
    for a in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                stream = Some((a, s));
                break;
            }
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: no answer on port {port}"),
        }
    }
    let (addr, stream) = stream.ok_or(last)?;
    let stream = stream.into_std().map_err(|e| format!("{addr}: {e}"))?;
    // The connection is to `addr`; the certificate is checked against the
    // name in the URL.
    let url = if bare.contains(':') {
        format!("ldaps://[{bare}]:{port}")
    } else {
        format!("ldaps://{bare}:{port}")
    };
    let settings = LdapConnSettings::new()
        .set_conn_timeout(VERIFY_TIMEOUT)
        .set_no_tls_verify(skip_verify)
        .set_std_stream(ldap3::StdStream::Tcp(stream));
    let (conn, mut ldap) =
        tokio::time::timeout(VERIFY_TIMEOUT, LdapConnAsync::with_settings(settings, &url))
            .await
            .map_err(|_| format!("{addr}: no TLS answer within {}s", VERIFY_TIMEOUT.as_secs()))?
            .map_err(|e| super::without_unsupported_names(&e.to_string()))?;
    let driver = super::Driver(tokio::spawn(async move {
        let _ = conn.drive().await;
    }));
    let dse = tokio::time::timeout(VERIFY_TIMEOUT, super::root_dse(&mut ldap)).await;
    super::close(ldap, driver).await;
    let (_, contexts) = dse.map_err(|_| "its RootDSE didn't answer in time".to_string())?;
    let nc = contexts
        .domain
        .ok_or_else(|| "its RootDSE names no domain".to_string())?;
    match super::wrong_domain(realm, &nc) {
        Some(actual) => Err(format!(
            "it is a domain controller for {actual}, not {realm}"
        )),
        None => Ok(addr),
    }
}

/// A domain the collected domain has a trust with (its `trustedDomain`
/// object), and whether the trust is outbound: the collected domain trusts
/// it, so its accounts are accepted.
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    pub name: NetbiosName,
    pub outbound: bool,
}

/// TRUST_DIRECTION_OUTBOUND (MS-ADTS 6.1.6.7.12): the collected domain
/// trusts the other one.
const TRUST_DIRECTION_OUTBOUND: u32 = 2;

/// Whether a `trustDirection` value includes outbound.
pub(crate) fn outbound(direction: &str) -> bool {
    direction
        .trim()
        .parse::<u32>()
        .is_ok_and(|d| d & TRUST_DIRECTION_OUTBOUND != 0)
}

/// The DNS name of the account's domain `account` (the NetBIOS name the
/// directory reports, or a DNS name) among `known`. Lower case; `None` if
/// it isn't there.
pub(crate) fn realm_of(account: &str, known: &[NetbiosName]) -> Option<String> {
    let account = account.trim().trim_end_matches('.');
    if account.is_empty() {
        return None;
    }
    known
        .iter()
        .find(|k| {
            k.netbios.trim().eq_ignore_ascii_case(account)
                || k.dns
                    .trim()
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(account)
        })
        .map(|k| k.dns.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| super::is_fqdn(d))
}

/// The DNS domain in the user name as typed (`user@dns` or `DNS\user`),
/// when it has one (a name with a dot).
pub(crate) fn typed_dns_domain(user: &str) -> Option<String> {
    let user = user.trim();
    let domain = match user.split_once('\\') {
        Some((d, _)) => d,
        None => user.rsplit_once('@')?.1,
    };
    let d = domain.trim().trim_end_matches('.');
    d.contains('.').then(|| d.to_ascii_lowercase())
}

/// The account's own domain: `account` (as the directory names it)
/// among the collected domain's forest (`forest`), then its trusts
/// (`trusts`, outbound ones only). With a DNS domain typed in the user name
/// (`typed`), that must be the domain found. `collected` is for the
/// messages.
pub(crate) fn pick_realm(
    account: &str,
    typed: Option<&str>,
    forest: &[NetbiosName],
    trusts: &[Trust],
    collected: &str,
) -> Result<String, ConnectionError> {
    let realm = match realm_of(account, forest) {
        Some(r) => r,
        None => {
            let outbound: Vec<NetbiosName> = trusts
                .iter()
                .filter(|t| t.outbound)
                .map(|t| t.name.clone())
                .collect();
            match realm_of(account, &outbound) {
                Some(r) => r,
                None => {
                    let all: Vec<NetbiosName> = trusts.iter().map(|t| t.name.clone()).collect();
                    return Err(match realm_of(account, &all) {
                        Some(r) => not_trusted(&r, collected),
                        None => account_domain_unknown(account, collected),
                    });
                }
            }
        }
    };
    match typed {
        Some(t) if !t.trim_end_matches('.').eq_ignore_ascii_case(&realm) => {
            Err(typed_mismatch(t, &realm, collected))
        }
        _ => Ok(realm),
    }
}

/// The account's TGT from a domain controller of its own domain `realm`,
/// checked over LDAPS ([`OwnRealmDc::verify`]) before any AS-REQ is sent;
/// with the KDC address it came from. The domain controller is `named`
/// (`--server REALM=HOST`) when given, else located ones in turn
/// ([`OwnRealmDc::locate`]), then, if none passes, those found afresh
/// ([`OwnRealmDc::rediscover`]): [`MAX_TRIED`] checks in all, the
/// rediscovered ones filling the slots left, or one more when the located
/// ones used them all. None located or rediscovered: the domain's name.
/// `collected` is the domain being collected, for the message; `sam` the
/// account's sAMAccountName.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn own_realm_ticket(
    dc: &dyn OwnRealmDc,
    realm: &str,
    named: Option<&str>,
    collected: &str,
    sam: &str,
    password: &Secret,
    skip_verify: bool,
    log: &dyn Fn(String),
) -> Result<(krb::Tgt, String), ConnectionError> {
    let realm = realm.trim().trim_end_matches('.').to_ascii_lowercase();
    let named = named.map(str::trim).filter(|n| !n.is_empty());
    let first: Vec<String> = match named {
        // Named by the user: used as given, checked all the same.
        Some(host) => {
            log(format!("[dc] {realm}: {host}, named with --server"));
            vec![host.to_string()]
        }
        None => {
            let mut lines = Vec::new();
            let found: Vec<String> = dc
                .locate(&realm, &mut |l| lines.push(l))
                .into_iter()
                .filter(|h| crate::locate::in_domain(h, &realm))
                .take(MAX_TRIED)
                .collect();
            for l in lines {
                log(l);
            }
            found
        }
    };
    let mut why = Vec::new();
    let mut tried = Vec::new();
    let mut checked = verify_each(dc, &first, &realm, skip_verify, log, &mut why, &mut tried).await;
    if checked.is_none() && named.is_none() {
        // Asked once more, found afresh, in the slots left (one more
        // when there are none); still none: the domain's name, whose
        // certificate rarely matches.
        let slots = MAX_TRIED.saturating_sub(tried.len()).max(1);
        let mut lines = Vec::new();
        let mut again: Vec<String> = dc
            .rediscover(&realm, &tried, &mut |l| lines.push(l))
            .into_iter()
            .filter(|h| crate::locate::in_domain(h, &realm) && !tried.contains(h))
            .take(slots)
            .collect();
        for l in lines {
            log(l);
        }
        if again.is_empty() && tried.is_empty() {
            again.push(realm.clone());
        }
        checked = verify_each(dc, &again, &realm, skip_verify, log, &mut why, &mut tried).await;
    }
    let Some((host, kdc)) = checked else {
        return Err(unverified(&realm, collected, why.join("; ")));
    };
    log(format!(
        "[hosts] {host} checked over LDAPS: a domain controller of {realm}, the account's \
         own domain."
    ));
    let tgt = krb::request_tgt(&kdc, &realm, sam, password)
        .await
        .map_err(|f| ConnectionError::no_ticket(f.headline, f.detail))?;
    Ok((tgt, kdc))
}

/// Checks `hosts` in turn ([`OwnRealmDc::verify`]), each added to `tried`
/// and, when it fails, to `why`: the first that passes, with its KDC
/// address.
async fn verify_each(
    dc: &dyn OwnRealmDc,
    hosts: &[String],
    realm: &str,
    skip_verify: bool,
    log: &dyn Fn(String),
    why: &mut Vec<String>,
    tried: &mut Vec<String>,
) -> Option<(String, String)> {
    for host in hosts {
        tried.push(host.clone());
        match dc.verify(host, realm, skip_verify).await {
            Ok(kdc) => return Some((host.clone(), kdc)),
            Err(e) => {
                log(format!("[dc] {realm}: {host} failed the check: {e}"));
                why.push(format!("{host}: {e}"));
            }
        }
    }
    None
}

/// No domain controller of the account's domain `realm` passed the check
/// (`detail` says why): nothing was sent to it.
pub(crate) fn unverified(realm: &str, collected: &str, detail: String) -> ConnectionError {
    ConnectionError::no_ticket(
        format!(
            "Kerberos didn't work: no domain controller of the account's domain ({realm}) \
             passed the domain controller check, so the password wasn't sent to it. Use an \
             account from {collected}."
        ),
        format!("LDAPS check of {detail}"),
    )
}

/// The account's domain (`account`, as the directory names it) is in
/// neither the collected domain's forest nor its trusts.
pub(crate) fn account_domain_unknown(account: &str, collected: &str) -> ConnectionError {
    ConnectionError::no_ticket(
        format!(
            "Kerberos didn't work: the account's domain ({account}) isn't in {collected}'s \
             forest or its trusts, so its domain controller can't be found. Accounts from a \
             child domain of a trusted forest aren't supported yet. Use an account from \
             {collected}."
        ),
        format!(
            "{account} is in neither the forest's partitions nor {collected}'s trusted domain \
             objects"
        ),
    )
}

/// The collected domain has a trust with the account's domain `realm`, but
/// doesn't trust it (inbound only).
pub(crate) fn not_trusted(realm: &str, collected: &str) -> ConnectionError {
    ConnectionError::no_ticket(
        format!(
            "Kerberos didn't work: {collected} doesn't trust the account's domain ({realm}), so \
             its tickets aren't accepted there. Use an account from {collected}."
        ),
        format!("{collected}'s trust with {realm} isn't outbound"),
    )
}

/// The user name was typed with the DNS domain `typed`, but the directory
/// places the account in `realm`.
pub(crate) fn typed_mismatch(typed: &str, realm: &str, collected: &str) -> ConnectionError {
    ConnectionError::no_ticket(
        format!(
            "Kerberos didn't work: the user name gives the domain {typed}, but the directory \
             places the account in {realm}. Give the user name as DOMAIN\\user, or use an \
             account from {collected}."
        ),
        format!("typed {typed}, found {realm}"),
    )
}

/// Kerberos only with an account from another domain, over plain LDAP:
/// its domain couldn't be read from a checked connection.
pub(crate) fn needs_ldaps(collected: &str) -> ConnectionError {
    ConnectionError::no_ticket(
        format!(
            "Kerberos didn't work: an account from another domain needs LDAPS, so its domain \
             is read from a checked connection. Turn on LDAPS, or use an account from \
             {collected}."
        ),
        "plain LDAP: the account's domain isn't looked up",
    )
}
