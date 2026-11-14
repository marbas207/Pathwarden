//! Finding a domain controller of a trusted domain by its full name,
//! so the LDAPS certificate is checked against the name it was issued to.
//! Reached by the domain's name, a domain controller's certificate rarely
//! matches: it names the host (`dc01.fabrikam.com`), not the domain.
//!
//! The ways tried, in order ([`system`]): on Windows, `DsGetDcName`, as
//! Windows itself finds one, and when the one it names doesn't answer, once
//! more with forced rediscovery; then the DNS SRV record
//! `_ldap._tcp.dc._msdcs.<domain>`, on Windows asked of the Windows DNS
//! client (`DnsQuery_W`), so NRPT rules, VPN split DNS and conditional
//! forwarders apply as they do for the rest of the system. Each name they
//! give must be in the domain ([`in_domain`]): DNS answers aren't signed,
//! and a spoofed one naming `dc.attacker.example` would come with a valid
//! certificate for that name, so the certificate check alone can't catch
//! it. A domain controller in a disjoint namespace is named with
//! `--server DOMAIN=HOST`. Every name in the domain is tried, best first,
//! each once; the first that answers on the port wins. None: the domain's
//! name, as before, and when that fails too the reason says none was found
//! ([`not_found`]). Nothing here weakens the certificate check: the name
//! found is the one the certificate must match, and the trust store
//! decides as for the first domain.

use std::time::Duration;

use crate::{ConnectionError, Problem};

/// A way to find a domain's domain controllers.
pub trait DcLocator {
    /// What it is, for the log ("DNS", "DsGetDcName").
    fn name(&self) -> &'static str;
    /// `domain`'s domain controllers by full name, best first; `Err` says
    /// why none was found.
    fn locate(&self, domain: &str) -> Result<Vec<String>, String>;
    /// Asked once when the names [`DcLocator::locate`] gave in the domain
    /// didn't answer: the same, found afresh rather than from a cache
    /// (`DsGetDcName` with `DS_FORCE_REDISCOVERY`). `None`: this way has no
    /// such thing ([`DcLocator::rediscovers`]).
    fn rediscover(&self, _domain: &str) -> Option<Result<Vec<String>, String>> {
        None
    }
    /// Whether [`DcLocator::rediscover`] gives anything.
    fn rediscovers(&self) -> bool {
        false
    }
}

/// Whether `host` is `domain` or a name under it (any case, the root's dot
/// ignored).
pub fn in_domain(host: &str, domain: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    !domain.is_empty()
        && (host == domain
            || host
                .strip_suffix(&domain)
                .is_some_and(|rest| rest.ends_with('.')))
}

/// `name` as a host name to connect to: lower case, without the root's
/// dot. `None` for anything else (an empty or "." SRV target means the
/// service isn't offered, RFC 2782).
fn host_name(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(n)
}

/// SRV targets best first: the lowest priority, then the highest weight
/// (RFC 2782 picks by weight at random; the heaviest is the likeliest),
/// then the name, each once.
pub fn order_srv(mut records: Vec<(u16, u16, String)>) -> Vec<String> {
    records.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    let mut out: Vec<String> = Vec::new();
    for (_, _, target) in records {
        if let Some(h) = host_name(&target) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

/// Whether a host answers on a port, for [`find_dc`].
pub trait Reach {
    fn reaches(&self, host: &str, port: u16) -> bool;
}

/// What [`find_dc`] tried, for the log and, when none answered, the reason.
struct Tried<'a> {
    domain: &'a str,
    port: u16,
    hosts: Vec<String>,
    why: Vec<String>,
    /// Some way named a domain controller outside the domain.
    outside: bool,
    log: &'a mut dyn FnMut(String),
}

/// What one way's answer gave [`find_dc`].
enum Answer {
    /// A name in the domain that answers.
    Found(String),
    /// Names in the domain, none of which answers.
    NoneAnswered,
    /// No name in the domain (an error, none, or only outside ones).
    NoneInDomain,
}

impl Tried<'_> {
    /// A step that found nothing: logged, and kept for the reason.
    fn note(&mut self, what: String) {
        (self.log)(format!("[dc] {}: {what}", self.domain));
        self.why.push(what);
    }

    /// Tries the names one way gave, in turn: the first in the domain, not
    /// tried before, that answers on the port.
    fn answer(
        &mut self,
        way: &str,
        answer: Result<Vec<String>, String>,
        reach: &dyn Reach,
    ) -> Answer {
        let hosts = match answer {
            Ok(hosts) => hosts,
            Err(why) => {
                self.note(format!("{way} found none: {why}"));
                return Answer::NoneInDomain;
            }
        };
        let mut named = false;
        let mut in_it = false;
        for raw in &hosts {
            let Some(h) = host_name(raw) else { continue };
            named = true;
            if !in_domain(&h, self.domain) {
                self.outside = true;
                self.note(format!(
                    "{way} named {h}, which is outside the domain: not used"
                ));
                continue;
            }
            // Tried already (another way named it): it didn't answer.
            in_it = true;
            if self.hosts.contains(&h) {
                continue;
            }
            self.hosts.push(h.clone());
            if reach.reaches(&h, self.port) {
                (self.log)(format!("[dc] {}: {h}, found with {way}", self.domain));
                return Answer::Found(h);
            }
            let port = self.port;
            self.note(format!("{h} (from {way}) didn't answer on port {port}"));
        }
        if !named {
            self.note(format!("{way} named no domain controller"));
        }
        if in_it {
            Answer::NoneAnswered
        } else {
            Answer::NoneInDomain
        }
    }
}

/// A domain controller of `domain` to connect to on `port`: every name the
/// locators give, in turn, best first, each once, that is in the domain and
/// answers on the port (`reach`). A locator that named some in the domain,
/// none of which answers, is asked once more ([`DcLocator::rediscover`])
/// before the next; one that found none (an error) isn't. A name
/// outside the domain is never used. `log` gets a line for each way and
/// name tried. `Err` when none did ([`NotFound`]): the domain's name is
/// used, as before.
pub fn find_dc(
    domain: &str,
    port: u16,
    locators: &[&dyn DcLocator],
    reach: &dyn Reach,
    log: &mut dyn FnMut(String),
) -> Result<String, NotFound> {
    let domain = domain.trim().trim_end_matches('.');
    let mut t = Tried {
        domain,
        port,
        hosts: Vec::new(),
        why: Vec::new(),
        outside: false,
        log,
    };
    for l in locators {
        match t.answer(l.name(), l.locate(domain), reach) {
            Answer::Found(h) => return Ok(h),
            Answer::NoneInDomain => continue,
            Answer::NoneAnswered => {}
        }
        if let Some(again) = l.rediscover(domain) {
            (t.log)(format!(
                "[dc] {domain}: asking {} again, with forced rediscovery",
                l.name()
            ));
            if let Answer::Found(h) = t.answer(l.name(), again, reach) {
                return Ok(h);
            }
        }
    }
    if t.why.is_empty() {
        t.why.push("no way to find one on this computer".into());
    }
    Err(NotFound {
        why: t.why.join("; "),
        found: !t.hosts.is_empty(),
        outside: t.outside,
    })
}

/// No domain controller of a domain was found that answers ([`find_dc`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotFound {
    /// What each way said, in one line.
    pub why: String,
    /// Whether some were found in the domain (and none answered).
    pub found: bool,
    /// Whether some were named outside the domain (and not used).
    pub outside: bool,
}

/// Every domain controller of `domain` the locators name, by full name
/// inside the domain only, best first, each once, without contacting any
/// (each is checked over LDAPS in turn). `log` gets a line for each
/// way tried and each name refused.
pub fn candidates(
    domain: &str,
    locators: &[&dyn DcLocator],
    log: &mut dyn FnMut(String),
) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.');
    let mut out: Vec<String> = Vec::new();
    for l in locators {
        add_named(domain, l.name(), l.locate(domain), &mut out, log);
    }
    out
}

/// The names the locators give when asked once more
/// ([`DcLocator::rediscover`]), for when none of the [`candidates`] passed
/// (`tried`: those checked, none passing): inside the domain only, each
/// once, not those in `tried`. Only a locator whose own answer named one of
/// `tried` is asked again (its answer is asked for once more, not forced:
/// `DsGetDcName` gives it from its cache); one that found none isn't.
pub fn rediscovered(
    domain: &str,
    locators: &[&dyn DcLocator],
    tried: &[String],
    log: &mut dyn FnMut(String),
) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.');
    let known = tried;
    let mut out: Vec<String> = Vec::new();
    for l in locators {
        let named_tried = |hosts: Vec<String>| {
            hosts
                .iter()
                .filter_map(|raw| host_name(raw))
                .any(|h| in_domain(&h, domain) && tried.contains(&h))
        };
        if !l.rediscovers() || !l.locate(domain).is_ok_and(named_tried) {
            continue;
        }
        if let Some(again) = l.rediscover(domain) {
            log(format!(
                "[dc] {domain}: asking {} again, with forced rediscovery",
                l.name()
            ));
            let mut found = Vec::new();
            add_named(domain, l.name(), again, &mut found, log);
            for h in found {
                if !known.contains(&h) && !out.contains(&h) {
                    out.push(h);
                }
            }
        }
    }
    out
}

/// Adds to `out` the names in `answer` that are in `domain`, each once.
fn add_named(
    domain: &str,
    way: &str,
    answer: Result<Vec<String>, String>,
    out: &mut Vec<String>,
    log: &mut dyn FnMut(String),
) {
    match answer {
        Ok(hosts) => {
            for h in hosts.iter().filter_map(|raw| host_name(raw)) {
                if !in_domain(&h, domain) {
                    log(format!(
                        "[dc] {domain}: {way} named {h}, which is outside the domain: not used"
                    ));
                } else if !out.contains(&h) {
                    log(format!("[dc] {domain}: {h}, found with {way}"));
                    out.push(h);
                }
            }
        }
        Err(why) => log(format!("[dc] {domain}: {way} found none: {why}")),
    }
}

/// [`candidates`] with this computer's locators.
pub fn candidates_here(domain: &str, log: &mut dyn FnMut(String)) -> Vec<String> {
    let boxed = system();
    let refs: Vec<&dyn DcLocator> = boxed.iter().map(|b| b.as_ref()).collect();
    candidates(domain, &refs, log)
}

/// [`rediscovered`] with this computer's locators.
pub fn rediscovered_here(
    domain: &str,
    tried: &[String],
    log: &mut dyn FnMut(String),
) -> Vec<String> {
    let boxed = system();
    let refs: Vec<&dyn DcLocator> = boxed.iter().map(|b| b.as_ref()).collect();
    rediscovered(domain, &refs, tried, log)
}

/// The locators of this computer, in the order tried.
#[allow(clippy::vec_init_then_push)]
pub fn system() -> Vec<Box<dyn DcLocator>> {
    // Pushed one by one: which there are depends on the platform and build.
    #[allow(unused_mut)]
    let mut out: Vec<Box<dyn DcLocator>> = Vec::new();
    #[cfg(windows)]
    {
        out.push(Box::new(win::DsGetDcName));
        out.push(Box::new(win::Dns));
    }
    #[cfg(all(feature = "builtin", not(windows)))]
    out.push(Box::new(Srv));
    out
}

/// The ways [`system`] tries, for the reason none was found.
const WAYS: &str = if cfg!(windows) {
    "Windows or DNS"
} else {
    "DNS"
};

/// Why a trusted domain wasn't collected when no domain controller of it
/// was found at all, and its domain's name didn't do either: one
/// sentence, with no command-line flags; where to name one is said where
/// it is shown ([`crate::DomainResult::table_reason`],
/// [`crate::DomainResult::saved_failure`]).
pub fn not_found(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("No domain controller of {d} was found through {WAYS}.")
}

/// [`not_found`] when the only names found were outside the domain, which
/// are never used.
pub fn only_outside(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{WAYS} named only domain controllers outside {d}, which aren't used.")
}

/// A trusted domain's failure (`problem`, `detail`) after no domain
/// controller was found that answers (`none`, [`find_dc`]'s) and its
/// domain's name was used, when it comes from that name (it doesn't
/// resolve or answer, or its certificate names the host, not the domain):
/// with none found in the domain, [`Problem::NotLocated`] ([`not_found`],
/// or [`only_outside`] when the only names found were outside it); with
/// some found that didn't answer, the name's own problem with the names
/// tried in the detail ("Couldn't reach a domain controller.", a
/// certificate that wasn't accepted), a name that didn't resolve as
/// [`Problem::Timeout`]. `None` for anything else: a domain controller
/// answered, and what it said is the reason.
#[cfg_attr(not(feature = "builtin"), allow(dead_code))]
pub(crate) fn not_located(
    domain: &str,
    none: &NotFound,
    problem: Problem,
    detail: &str,
) -> Option<ConnectionError> {
    let why = &none.why;
    matches!(
        problem,
        Problem::Dns
            | Problem::Refused
            | Problem::Unreachable
            | Problem::Timeout
            | Problem::CertificateName
    )
    .then(|| {
        let detail = crate::one_line(&format!("{why}; then by the domain's name: {detail}"));
        if none.found {
            let problem = match problem {
                Problem::Dns => Problem::Timeout,
                p => p,
            };
            ConnectionError {
                problem,
                detail,
                headline: None,
            }
        } else {
            ConnectionError {
                problem: Problem::NotLocated,
                detail,
                headline: Some(if none.outside {
                    only_outside(domain)
                } else {
                    not_found(domain)
                }),
            }
        }
    })
}

/// How long a located domain controller has to accept a connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A TCP connection within [`CONNECT_TIMEOUT`] to any of the host's
/// addresses.
pub struct Tcp;

impl Reach for Tcp {
    fn reaches(&self, host: &str, port: u16) -> bool {
        use std::net::{TcpStream, ToSocketAddrs};
        let Ok(addrs) = (host, port).to_socket_addrs() else {
            return false;
        };
        addrs
            .into_iter()
            .any(|a| TcpStream::connect_timeout(&a, CONNECT_TIMEOUT).is_ok())
    }
}

/// [`find_dc`] with this computer's locators and a TCP connection.
pub fn find_dc_here(
    domain: &str,
    port: u16,
    log: &mut dyn FnMut(String),
) -> Result<String, NotFound> {
    let boxed = system();
    let refs: Vec<&dyn DcLocator> = boxed.iter().map(|b| b.as_ref()).collect();
    find_dc(domain, port, &refs, &Tcp, log)
}

/// Whether `DsGetDcName`'s answer is for `domain`: its domain's DNS name is
/// the one asked for. A forest name alone isn't enough: the forest root's
/// controllers aren't the child domain's.
pub fn ds_answer_for(domain: &str, answered: &str) -> bool {
    let clean = |d: &str| d.trim().trim_end_matches('.').to_ascii_lowercase();
    !clean(domain).is_empty() && clean(domain) == clean(answered)
}

/// How long a DNS lookup may take.
#[cfg_attr(not(any(windows, feature = "builtin")), allow(dead_code))]
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// The SRV record a domain's domain controllers are listed under.
#[cfg_attr(not(any(windows, feature = "builtin")), allow(dead_code))]
fn srv_name(domain: &str) -> String {
    format!("_ldap._tcp.dc._msdcs.{domain}.")
}

/// The DNS SRV record `_ldap._tcp.dc._msdcs.<domain>`, asked of the DNS
/// servers this computer's network settings list (the Rust resolver's own
/// reading of them). Other platforms than Windows; on Windows the Windows
/// DNS client is asked instead (`win::Dns`), which also follows NRPT and VPN
/// rules.
#[cfg(feature = "builtin")]
#[cfg_attr(windows, allow(dead_code))]
pub struct Srv;

#[cfg(feature = "builtin")]
impl DcLocator for Srv {
    fn name(&self) -> &'static str {
        "DNS"
    }

    fn locate(&self, domain: &str) -> Result<Vec<String>, String> {
        let query = srv_name(domain);
        // Its own thread and runtime: the caller may be inside one.
        std::thread::scope(|s| {
            s.spawn(move || -> Result<Vec<String>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                rt.block_on(async move {
                    let resolver = hickory_resolver::TokioResolver::builder_tokio()
                        .and_then(|b| b.build())
                        .map_err(|e| e.to_string())?;
                    let found = tokio::time::timeout(DNS_TIMEOUT, resolver.srv_lookup(query))
                        .await
                        .map_err(|_| "no answer in time".to_string())?
                        .map_err(|e| e.to_string())?;
                    Ok::<_, String>(order_srv(
                        found
                            .answers()
                            .iter()
                            .filter_map(|r| match &r.data {
                                hickory_resolver::proto::rr::RData::SRV(r) => {
                                    Some((r.priority, r.weight, r.target.to_utf8()))
                                }
                                _ => None,
                            })
                            .collect(),
                    ))
                })
            })
            .join()
            .unwrap_or_else(|_| Err("the lookup failed".into()))
        })
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use windows_sys::core::PWSTR;
    use windows_sys::Win32::NetworkManagement::Dns::{
        DnsFree, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_STANDARD, DNS_RECORDW, DNS_SRV_DATAW,
        DNS_TYPE_SRV,
    };
    use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
    use windows_sys::Win32::Networking::ActiveDirectory::{
        DsGetDcNameW, DOMAIN_CONTROLLER_INFOW, DS_DIRECTORY_SERVICE_REQUIRED, DS_FORCE_REDISCOVERY,
        DS_IS_DNS_NAME, DS_RETURN_DNS_NAME, DS_TRY_NEXTCLOSEST_SITE,
    };

    /// Windows' own domain controller locator.
    pub struct DsGetDcName;

    /// # Safety
    /// `p` is null or a NUL-terminated UTF-16 string.
    unsafe fn text(p: PWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        // SAFETY: as the caller promises, NUL-terminated.
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// `DsGetDcName` for `domain` with `more` flags.
    fn ds_get_dc_name(domain: &str, more: u32) -> Result<Vec<String>, String> {
        let wide: Vec<u16> = domain.encode_utf16().chain(Some(0)).collect();
        let mut info: *mut DOMAIN_CONTROLLER_INFOW = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the
        // other inputs may be null. On success `info` is a buffer the
        // API allocated, read once and freed below.
        let rc = unsafe {
            DsGetDcNameW(
                std::ptr::null(),
                wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                DS_IS_DNS_NAME
                    | DS_RETURN_DNS_NAME
                    | DS_DIRECTORY_SERVICE_REQUIRED
                    | DS_TRY_NEXTCLOSEST_SITE
                    | more,
                &mut info,
            )
        };
        if rc != 0 || info.is_null() {
            return Err(format!("error {rc}"));
        }
        // SAFETY: `info` points to the API's DOMAIN_CONTROLLER_INFOW,
        // whose strings are NUL-terminated or null; freed once, here.
        let (dc, answered) = unsafe {
            let got = (text((*info).DomainControllerName), text((*info).DomainName));
            NetApiBufferFree(info.cast());
            got
        };
        if !super::ds_answer_for(domain, &answered) {
            return Err(format!("it answered for {answered}, not {domain}"));
        }
        // "\\dc01.fabrikam.com"
        Ok(vec![dc.trim_start_matches('\\').to_string()])
    }

    impl super::DcLocator for DsGetDcName {
        fn name(&self) -> &'static str {
            "DsGetDcName"
        }

        fn locate(&self, domain: &str) -> Result<Vec<String>, String> {
            ds_get_dc_name(domain, 0)
        }

        /// Windows may give a cached domain controller that has since gone
        /// away; forced rediscovery finds one that answers now.
        fn rediscover(&self, domain: &str) -> Option<Result<Vec<String>, String>> {
            Some(ds_get_dc_name(domain, DS_FORCE_REDISCOVERY))
        }

        fn rediscovers(&self) -> bool {
            true
        }
    }

    /// The DNS SRV record `_ldap._tcp.dc._msdcs.<domain>`, asked of the
    /// Windows DNS client, so it resolves as `Resolve-DnsName` does:
    /// NRPT rules, VPN split DNS and the VPN adapter's servers included.
    pub struct Dns;

    /// A record list from `DnsQuery_W`, freed once when dropped.
    struct Records(*mut DNS_RECORDW);

    impl Drop for Records {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the list `DnsQuery_W` returned, freed once, with
                // the free type for a record list.
                unsafe { DnsFree(self.0.cast_const().cast(), DnsFreeRecordList) };
            }
        }
    }

    /// `DnsQuery_W`'s result codes that mean the record isn't there.
    fn dns_error(rc: u32) -> String {
        match rc {
            9003 => "no such name (DNS error 9003)".into(),
            9501 => "no such record (DNS error 9501)".into(),
            9002 => "the DNS server failed (DNS error 9002)".into(),
            1460 => "no answer in time (error 1460)".into(),
            rc => format!("error {rc}"),
        }
    }

    /// The SRV answers for `name`: (priority, weight, target).
    fn srv_records(name: &str) -> Result<Vec<(u16, u16, String)>, String> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut list: *mut DNS_RECORDW = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `pextra`
        // and `preserved` may be null. The API writes a record list it
        // allocated to `list` (with the _W call, its strings are UTF-16:
        // DNS_RECORDW, though the binding names the A type), freed by
        // `Records` below.
        let rc = unsafe {
            DnsQuery_W(
                wide.as_ptr(),
                DNS_TYPE_SRV,
                DNS_QUERY_STANDARD,
                std::ptr::null_mut(),
                (&mut list as *mut *mut DNS_RECORDW).cast(),
                std::ptr::null_mut(),
            )
        };
        let records = Records(list);
        if rc != 0 {
            return Err(dns_error(rc));
        }
        let mut out = Vec::new();
        let mut p = records.0;
        while !p.is_null() {
            // SAFETY: `p` is a record of the list, alive until `records` is
            // dropped. Only the header's fields are read, each through its
            // own place (no reference to the whole record: a record is
            // allocated as large as its own data, and an A record's is
            // smaller than the union).
            let (kind, flags, len, next) =
                unsafe { ((*p).wType, (*p).Flags.DW, (*p).wDataLength, (*p).pNext) };
            // The section is the low two bits of the flags (1: the answer).
            if kind == DNS_TYPE_SRV
                && flags & 0x3 == 1
                && usize::from(len) >= std::mem::size_of::<DNS_SRV_DATAW>()
            {
                // SAFETY: an SRV record whose data is at least a
                // DNS_SRV_DATAW, read by its place; its target is
                // NUL-terminated or null, alive with the list.
                let (priority, weight, target) = unsafe {
                    let srv = std::ptr::addr_of!((*p).Data.SRV).read_unaligned();
                    (srv.wPriority, srv.wWeight, text(srv.pNameTarget))
                };
                out.push((priority, weight, target));
            }
            p = next;
        }
        Ok(out)
    }

    impl super::DcLocator for Dns {
        fn name(&self) -> &'static str {
            "DNS"
        }

        fn locate(&self, domain: &str) -> Result<Vec<String>, String> {
            let query = super::srv_name(domain);
            // On its own thread, so a slow DNS server can't hold the run
            // past the timeout; a late answer is freed there.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("pathwarden-dns".into())
                .spawn(move || {
                    let _ = tx.send(srv_records(&query));
                })
                .map_err(|e| e.to_string())?;
            match rx.recv_timeout(super::DNS_TIMEOUT) {
                Ok(Ok(records)) => Ok(super::order_srv(records)),
                Ok(Err(why)) => Err(why),
                Err(_) => Err("no answer in time".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A locator that answers from a list, and records what it was asked.
    struct Fake {
        name: &'static str,
        answer: Result<Vec<String>, String>,
        asked: RefCell<Vec<String>>,
        /// What it says when asked again with forced rediscovery, if it can.
        again: Option<Result<Vec<String>, String>>,
        asked_again: RefCell<usize>,
    }

    fn owned(answer: Result<&[&str], &str>) -> Result<Vec<String>, String> {
        answer
            .map(|a| a.iter().map(|s| s.to_string()).collect())
            .map_err(str::to_string)
    }

    impl Fake {
        fn new(name: &'static str, answer: Result<&[&str], &str>) -> Self {
            Self {
                name,
                answer: owned(answer),
                asked: RefCell::new(Vec::new()),
                again: None,
                asked_again: RefCell::new(0),
            }
        }

        /// Like `DsGetDcName`: asked again, it says `again`.
        fn again(mut self, again: Result<&[&str], &str>) -> Self {
            self.again = Some(owned(again));
            self
        }
    }

    impl DcLocator for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        fn locate(&self, domain: &str) -> Result<Vec<String>, String> {
            self.asked.borrow_mut().push(domain.to_string());
            self.answer.clone()
        }
        fn rediscover(&self, _domain: &str) -> Option<Result<Vec<String>, String>> {
            let again = self.again.clone()?;
            *self.asked_again.borrow_mut() += 1;
            Some(again)
        }
        fn rediscovers(&self) -> bool {
            self.again.is_some()
        }
    }

    /// Answers for the hosts listed, and records what it was asked.
    struct Up(Vec<&'static str>, RefCell<Vec<(String, u16)>>);

    impl Up {
        fn of(hosts: &[&'static str]) -> Self {
            Self(hosts.to_vec(), RefCell::new(Vec::new()))
        }
    }

    impl Reach for Up {
        fn reaches(&self, host: &str, port: u16) -> bool {
            self.1.borrow_mut().push((host.to_string(), port));
            self.0.contains(&host)
        }
    }

    #[test]
    fn the_first_locator_that_names_one_wins() {
        let ds = Fake::new("DsGetDcName", Err("error 1355"));
        let empty = Fake::new("DNS", Ok(&["."]));
        let dns = Fake::new("DNS", Ok(&["MEEREEN.essos.local.", "braavos.essos.local"]));
        let never = Fake::new("never", Ok(&["x.essos.local"]));
        let up = Up::of(&["meereen.essos.local"]);
        let mut log = Vec::new();
        let got = find_dc(
            "ESSOS.LOCAL.",
            636,
            &[&ds, &empty, &dns, &never],
            &up,
            &mut |l| log.push(l),
        );
        assert_eq!(got.as_deref().ok(), Some("meereen.essos.local"));
        assert_eq!(*ds.asked.borrow(), ["ESSOS.LOCAL"]);
        assert!(never.asked.borrow().is_empty());
        assert_eq!(*up.1.borrow(), [("meereen.essos.local".to_string(), 636)]);
        assert_eq!(
            log,
            [
                "[dc] ESSOS.LOCAL: DsGetDcName found none: error 1355",
                "[dc] ESSOS.LOCAL: DNS named no domain controller",
                "[dc] ESSOS.LOCAL: meereen.essos.local, found with DNS",
            ]
        );
        // None found: the domain's name is used, as before.
        assert_eq!(
            find_dc("essos.local", 636, &[&ds, &empty], &up, &mut |_| {}),
            Err(NotFound {
                why: "DsGetDcName found none: error 1355; DNS named no domain controller".into(),
                found: false,
                outside: false,
            })
        );
        assert_eq!(
            find_dc("essos.local", 636, &[], &up, &mut |_| {}),
            Err(NotFound {
                why: "no way to find one on this computer".into(),
                found: false,
                outside: false,
            })
        );
    }

    /// A spoofed answer naming a host outside the domain is never used,
    /// though its own certificate would match it: the next name is tried,
    /// or the domain's name is used.
    #[test]
    fn a_host_outside_the_domain_is_never_used() {
        let evil = Fake::new(
            "DNS",
            Ok(&["evil.attacker.com", "essos.local.attacker.com"]),
        );
        let up = Up::of(&["evil.attacker.com", "essos.local.attacker.com"]);
        let mut log = Vec::new();
        assert!(find_dc("essos.local", 636, &[&evil], &up, &mut |l| log.push(l)).is_err());
        assert!(up.1.borrow().is_empty(), "never contacted");
        assert_eq!(
            log,
            [
                "[dc] essos.local: DNS named evil.attacker.com, which is outside the domain: \
                 not used",
                "[dc] essos.local: DNS named essos.local.attacker.com, which is outside the \
                 domain: not used",
            ]
        );
        let mixed = Fake::new("DNS", Ok(&["evil.attacker.com", "meereen.essos.local"]));
        let up = Up::of(&["evil.attacker.com", "meereen.essos.local"]);
        assert_eq!(
            find_dc("essos.local", 636, &[&mixed], &up, &mut |_| {})
                .as_deref()
                .ok(),
            Some("meereen.essos.local")
        );
        assert!(in_domain("MEEREEN.Essos.Local.", "essos.local"));
        assert!(in_domain("essos.local", "ESSOS.LOCAL"));
        assert!(!in_domain("notessos.local", "essos.local"));
        assert!(!in_domain("essos.local.attacker.com", "essos.local"));
        assert!(!in_domain("x", ""));
    }

    /// The located names are tried in turn until one answers; then the
    /// next locator's; a name already tried isn't tried again.
    #[test]
    fn each_located_name_in_turn_until_one_answers() {
        let ds = Fake::new("DsGetDcName", Ok(&["\\dc01.fabrikam.com"]));
        let dns = Fake::new(
            "DNS",
            Ok(&[
                "dc01.fabrikam.com",
                "dc02.fabrikam.com",
                "dc03.fabrikam.com",
            ]),
        );
        let up = Up::of(&["dc03.fabrikam.com"]);
        let mut log = Vec::new();
        let got = find_dc("fabrikam.com", 389, &[&ds, &dns], &up, &mut |l| log.push(l));
        assert_eq!(got.as_deref().ok(), Some("dc03.fabrikam.com"));
        let asked: Vec<String> = up.1.borrow().iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(
            asked,
            [
                "dc01.fabrikam.com",
                "dc02.fabrikam.com",
                "dc03.fabrikam.com"
            ]
        );
        assert!(log.contains(
            &"[dc] fabrikam.com: dc01.fabrikam.com (from DNS) didn't answer on port 389".into()
        ) || log.contains(
            &"[dc] fabrikam.com: dc01.fabrikam.com (from DsGetDcName) didn't answer on port 389"
                .into()
        ));
        // None answers: the domain's name, as before.
        assert!(find_dc("fabrikam.com", 389, &[&ds, &dns], &Up::of(&[]), &mut |_| {}).is_err());
    }

    /// `DsGetDcName`'s domain controller doesn't answer: it is asked
    /// once more, with forced rediscovery, and the new one is tried before
    /// DNS's; one it named already isn't tried again.
    #[test]
    fn a_dc_that_doesnt_answer_is_rediscovered_once() {
        let ds =
            Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"])).again(Ok(&["dc02.fabrikam.com"]));
        let dns = Fake::new("DNS", Ok(&["dc03.fabrikam.com"]));
        let up = Up::of(&["dc02.fabrikam.com", "dc03.fabrikam.com"]);
        let mut log = Vec::new();
        let got = find_dc("fabrikam.com", 636, &[&ds, &dns], &up, &mut |l| log.push(l));
        assert_eq!(got.as_deref().ok(), Some("dc02.fabrikam.com"));
        assert_eq!(*ds.asked_again.borrow(), 1);
        assert!(
            dns.asked.borrow().is_empty(),
            "the rediscovered one answered"
        );
        assert_eq!(
            log,
            [
                "[dc] fabrikam.com: dc01.fabrikam.com (from DsGetDcName) didn't answer on port 636",
                "[dc] fabrikam.com: asking DsGetDcName again, with forced rediscovery",
                "[dc] fabrikam.com: dc02.fabrikam.com, found with DsGetDcName",
            ]
        );

        // The first answers: no rediscovery.
        let ds =
            Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"])).again(Ok(&["dc02.fabrikam.com"]));
        let up = Up::of(&["dc01.fabrikam.com"]);
        let got = find_dc("fabrikam.com", 636, &[&ds], &up, &mut |_| {});
        assert_eq!(got.as_deref().ok(), Some("dc01.fabrikam.com"));
        assert_eq!(*ds.asked_again.borrow(), 0);

        // The same one again (Windows still names it): not tried twice,
        // and DNS's names are tried next.
        let ds =
            Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"])).again(Ok(&["dc01.fabrikam.com"]));
        let dns = Fake::new("DNS", Ok(&["dc01.fabrikam.com", "dc04.fabrikam.com"]));
        let up = Up::of(&["dc04.fabrikam.com"]);
        let got = find_dc("fabrikam.com", 636, &[&ds, &dns], &up, &mut |_| {});
        assert_eq!(got.as_deref().ok(), Some("dc04.fabrikam.com"));
        assert_eq!(*ds.asked_again.borrow(), 1);
        let asked: Vec<String> = up.1.borrow().iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(asked, ["dc01.fabrikam.com", "dc04.fabrikam.com"]);
    }

    /// Every name from every way, best first, each once, before the
    /// domain's name; a rediscovered name outside the domain is refused as
    /// any other; the reason says what each way gave.
    #[test]
    fn every_candidate_is_tried_before_the_domains_name() {
        let ds = Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"]))
            .again(Ok(&["dc.attacker.example"]));
        let dns = Fake::new(
            "DNS",
            Ok(&[
                "dc02.fabrikam.com",
                "dc01.fabrikam.com",
                "evil.attacker.example",
                "dc03.fabrikam.com",
            ]),
        );
        let up = Up::of(&["dc.attacker.example", "evil.attacker.example"]);
        let mut log = Vec::new();
        let none =
            find_dc("fabrikam.com", 636, &[&ds, &dns], &up, &mut |l| log.push(l)).unwrap_err();
        assert!(none.found, "found, none answered");
        let asked: Vec<String> = up.1.borrow().iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(
            asked,
            [
                "dc01.fabrikam.com",
                "dc02.fabrikam.com",
                "dc03.fabrikam.com"
            ]
        );
        assert_eq!(*ds.asked_again.borrow(), 1);
        assert_eq!(
            none.why,
            "dc01.fabrikam.com (from DsGetDcName) didn't answer on port 636; DsGetDcName \
             named dc.attacker.example, which is outside the domain: not used; \
             dc02.fabrikam.com (from DNS) didn't answer on port 636; DNS named \
             evil.attacker.example, which is outside the domain: not used; dc03.fabrikam.com \
             (from DNS) didn't answer on port 636"
        );
        assert_eq!(log.len(), 6, "{log:?}");
    }

    /// When no domain controller is found and the domain's name
    /// fails too, the reason says so, in one sentence with no flags; a
    /// domain controller that answered keeps its own reason.
    #[test]
    fn the_reason_when_none_is_found() {
        let ways = if cfg!(windows) {
            "Windows or DNS"
        } else {
            "DNS"
        };
        assert_eq!(
            not_found("Fabrikam.COM."),
            format!("No domain controller of fabrikam.com was found through {ways}.")
        );
        // Some found, none answered: the old wording, the names tried behind it.
        let down = NotFound {
            why: "meereen.essos.local (from DNS) didn't answer on port 636".into(),
            found: true,
            outside: false,
        };
        for (p, kept) in [
            (Problem::Refused, Problem::Refused),
            (Problem::Timeout, Problem::Timeout),
            (Problem::Dns, Problem::Timeout),
            (Problem::Unreachable, Problem::Unreachable),
        ] {
            let e = not_located("essos.local", &down, p, "y").unwrap();
            assert_eq!(e.problem, kept, "{p:?}");
            assert_eq!(e.problem.short(), "Couldn't reach a domain controller.");
            assert!(
                e.detail.starts_with("meereen.essos.local (from DNS)"),
                "{}",
                e.detail
            );
        }
        assert!(not_located("essos.local", &down, Problem::Credentials, "y").is_none());
        let none = NotFound {
            why: "DNS found none: no such name".into(),
            found: false,
            outside: false,
        };
        let e = not_located(
            "fabrikam.com",
            &none,
            Problem::CertificateName,
            "certificate not valid for name \"fabrikam.com\"",
        )
        .unwrap();
        assert_eq!(e.problem, Problem::NotLocated);
        assert_eq!(e.message(), not_found("fabrikam.com"));
        assert!(!e.message().contains("--"), "{}", e.message());
        assert_eq!(
            e.detail,
            "DNS found none: no such name; then by the domain's name: certificate not valid \
             for name \"fabrikam.com\""
        );
        for p in [
            Problem::Dns,
            Problem::Refused,
            Problem::Unreachable,
            Problem::Timeout,
        ] {
            assert!(
                not_located("fabrikam.com", &none, p, "y").is_some(),
                "{p:?}"
            );
        }
        for p in [
            Problem::Credentials,
            Problem::CertificateUntrusted,
            Problem::WrongDomain,
            Problem::Other,
        ] {
            assert!(
                not_located("fabrikam.com", &none, p, "y").is_none(),
                "{p:?}"
            );
        }
    }

    /// `DsGetDcName` itself failed (or named only names outside the
    /// domain): it isn't asked again; DNS's names are tried.
    #[test]
    fn no_rediscovery_when_the_locator_found_none() {
        for first in [
            Err("error 1355"),
            Ok(&["dc.attacker.example"][..]),
            Ok(&[][..]),
        ] {
            let ds = Fake::new("DsGetDcName", first).again(Ok(&["dc02.fabrikam.com"]));
            let dns = Fake::new("DNS", Ok(&["dc03.fabrikam.com"]));
            let up = Up::of(&["dc02.fabrikam.com", "dc03.fabrikam.com"]);
            let got = find_dc("fabrikam.com", 636, &[&ds, &dns], &up, &mut |_| {});
            assert_eq!(got.as_deref().ok(), Some("dc03.fabrikam.com"), "{first:?}");
            assert_eq!(*ds.asked_again.borrow(), 0, "{first:?}");
            // Nor for the account's own domain.
            let tried = vec!["dc03.fabrikam.com".to_string()];
            assert!(rediscovered("fabrikam.com", &[&ds, &dns], &tried, &mut |_| {}).is_empty());
            assert_eq!(*ds.asked_again.borrow(), 0, "{first:?}");
        }
        // Its own name was tried and failed: asked again.
        let ds =
            Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"])).again(Ok(&["dc02.fabrikam.com"]));
        let tried = vec!["dc01.fabrikam.com".to_string()];
        assert_eq!(
            rediscovered("fabrikam.com", &[&ds], &tried, &mut |_| {}),
            ["dc02.fabrikam.com"]
        );
        // Named, but not among those tried (cut off by the cap): not asked.
        let other = vec!["dc09.fabrikam.com".to_string()];
        assert!(rediscovered("fabrikam.com", &[&ds], &other, &mut |_| {}).is_empty());
        assert_eq!(*ds.asked_again.borrow(), 1);
    }

    /// Only names outside the domain: none is used, and the reason
    /// says so; with names in the domain too, the usual reasons.
    #[test]
    fn only_outside_names_say_so() {
        let ways = if cfg!(windows) {
            "Windows or DNS"
        } else {
            "DNS"
        };
        let evil = Fake::new("DNS", Ok(&["dc.attacker.example"]));
        let up = Up::of(&["dc.attacker.example"]);
        let none = find_dc("fabrikam.com", 636, &[&evil], &up, &mut |_| {}).unwrap_err();
        assert!(none.outside && !none.found);
        assert!(up.1.borrow().is_empty(), "never contacted");
        let e = not_located("fabrikam.com", &none, Problem::CertificateName, "x").unwrap();
        assert_eq!(e.problem, Problem::NotLocated);
        assert_eq!(
            e.message(),
            format!(
                "{ways} named only domain controllers outside fabrikam.com, which aren't used."
            )
        );
        assert_eq!(e.message(), only_outside("FABRIKAM.COM."));
        // An error, or none named: not found.
        let failed = Fake::new("DNS", Err("no such name"));
        let none = find_dc("fabrikam.com", 636, &[&failed], &up, &mut |_| {}).unwrap_err();
        assert!(!none.outside && !none.found);
        let e = not_located("fabrikam.com", &none, Problem::Dns, "x").unwrap();
        assert_eq!(e.message(), not_found("fabrikam.com"));
    }

    /// Found but none answered, the domain's name rejected for its
    /// certificate's name: the certificate's reason stays.
    #[test]
    fn found_then_a_certificate_name_keeps_its_reason() {
        let dns = Fake::new("DNS", Ok(&["dc01.fabrikam.com"]));
        let none = find_dc("fabrikam.com", 636, &[&dns], &Up::of(&[]), &mut |_| {}).unwrap_err();
        assert!(none.found);
        let e = not_located(
            "fabrikam.com",
            &none,
            Problem::CertificateName,
            "not valid for name",
        )
        .unwrap();
        assert_eq!(e.problem, Problem::CertificateName);
        assert!(
            e.detail.starts_with("dc01.fabrikam.com (from DNS)"),
            "{}",
            e.detail
        );
    }

    /// Windows only, not run by default (it asks this computer's DNS): the
    /// `DnsQuery_W` walk answers a name that doesn't exist with an error,
    /// and, with `PW_TEST_SRV_DOMAIN` set to a domain whose SRV record
    /// resolves here, lists its domain controllers. Never a lab's.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn windows_dns_srv_lookup() {
        let dns = win::Dns;
        let e = dns.locate("pathwarden-test.invalid").unwrap_err();
        assert!(!e.is_empty());
        if let Ok(domain) = std::env::var("PW_TEST_SRV_DOMAIN") {
            let got = dns.locate(&domain).unwrap();
            assert!(!got.is_empty(), "{got:?}");
            assert!(got.iter().all(|h| host_name(h).is_some()), "{got:?}");
        }
    }

    /// An account from another domain, rediscovered: asked once more, only new names inside the domain.
    #[test]
    fn rediscovered_names_are_new_and_in_the_domain() {
        let ds =
            Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"])).again(Ok(&["dc05.fabrikam.com"]));
        let plain = Fake::new("DNS", Ok(&["dc02.fabrikam.com"]));
        let mut log = Vec::new();
        let known = vec!["dc01.fabrikam.com".to_string()];
        let got = rediscovered("fabrikam.com", &[&ds, &plain], &known, &mut |l| log.push(l));
        assert_eq!(got, ["dc05.fabrikam.com"]);
        assert_eq!(*ds.asked_again.borrow(), 1);
        assert!(plain.asked.borrow().is_empty());
        let evil = Fake::new("DsGetDcName", Ok(&["dc01.fabrikam.com"]))
            .again(Ok(&["dc01.fabrikam.com", "x.evil"]));
        let got = rediscovered("fabrikam.com", &[&evil], &known, &mut |_| {});
        assert!(got.is_empty(), "{got:?}");
        assert_eq!(*evil.asked_again.borrow(), 1);
    }

    /// Every in-domain name, each once, best first; outside names never.
    #[test]
    fn candidates_are_every_name_in_the_domain() {
        let ds = Fake::new("DsGetDcName", Ok(&["dc02.fabrikam.com"]));
        let dns = Fake::new(
            "DNS",
            Ok(&[
                "evil.attacker.com",
                "DC01.fabrikam.com.",
                "dc02.fabrikam.com",
            ]),
        );
        let mut log = Vec::new();
        let got = candidates("fabrikam.com", &[&ds, &dns], &mut |l| log.push(l));
        assert_eq!(got, ["dc02.fabrikam.com", "dc01.fabrikam.com"]);
        assert!(log
            .iter()
            .any(|l| l.contains("evil.attacker.com, which is outside")));
    }

    #[test]
    fn ds_get_dc_name_must_answer_for_the_domain() {
        assert!(ds_answer_for("Essos.Local", "essos.local."));
        assert!(!ds_answer_for(
            "north.sevenkingdoms.local",
            "sevenkingdoms.local"
        ));
        assert!(!ds_answer_for("essos.local", ""));
        assert!(!ds_answer_for("", ""));
    }

    #[test]
    fn srv_targets_by_priority_then_weight() {
        let got = order_srv(vec![
            (10, 0, "backup.fabrikam.com.".into()),
            (0, 50, "dc02.fabrikam.com.".into()),
            (0, 100, "DC01.fabrikam.com.".into()),
            (0, 100, "dc01.fabrikam.com".into()),
            (0, 0, ".".into()),
            (0, 0, "bad name.fabrikam.com".into()),
        ]);
        assert_eq!(
            got,
            [
                "dc01.fabrikam.com",
                "dc02.fabrikam.com",
                "backup.fabrikam.com"
            ]
        );
    }

    #[test]
    fn host_names_are_checked() {
        assert_eq!(
            host_name(" Kingslanding.SevenKingdoms.Local. ").as_deref(),
            Some("kingslanding.sevenkingdoms.local")
        );
        for bad in ["", ".", "a..b", "-a.b", "a b", "dc01/x", "a:636"] {
            assert_eq!(host_name(bad), None, "{bad:?}");
        }
    }
}
