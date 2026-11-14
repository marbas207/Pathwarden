//! A KDC relay on 127.0.0.1 for RustHound-CE's own service tickets.
//!
//! RustHound-CE's sessions, local groups and WebClient modules ask "the
//! KDC" (`Options::ldapfqdn`, `host:port` taken as is) for `cifs/<host>`
//! with the TGT in the ticket cache, and take whatever comes back: they
//! check neither the reply's nonce nor the service named in its encrypted
//! part, and can't follow a referral to another realm. With Kerberos only,
//! the modules get this relay as their KDC instead. For each request it:
//!
//! 1. takes only a TGS-REQ for `cifs/<host>` in the run's realm, as
//!    RustHound-CE sends it (one PA-TGS-REQ, its KDC options), presenting
//!    the run's own TGT (the same ticket, and an authenticator that opens
//!    with its session key, made in the last 5 minutes). An AS-REQ, or
//!    anything else, is refused. It is bound to 127.0.0.1 only, on a port
//!    the system picks for this run, and drops a connection from any other
//!    address. At most [`AT_ONCE`] connections are taken at once, each with
//!    one deadline ([`DEADLINE`]) for the whole exchange, so a local user
//!    holding connections open can slow it, never stop it. A request that
//!    doesn't present the run's ticket is refused quietly (debug level) and
//!    counted; the count is logged once, when the relay stops.
//! 2. takes RC4 out of the key types asked for, and forwards it to the
//!    domain controller verified over LDAPS.
//! 3. checks the reply with the session key Pathwarden holds: the nonce,
//!    the service and realm named in its encrypted part, and AES256 for
//!    the reply and the new session key. A KDC error is passed on as is; a
//!    reply that fails a check is refused with a KRB-ERROR, and logged.
//! 4. a referral (a computer in another realm: a trusted domain of the run,
//!    or another domain of the forest) is followed by the relay itself,
//!    every hop checked ([`super::krbref::follow`]). The last reply's
//!    encrypted part is opened with the referral's session key, its nonce
//!    set to the module's, and encrypted again under the key the module's
//!    request was made with, so the module gets an ordinary TGS-REP for the
//!    computer. SMB signing still holds end to end: the computer's session
//!    key travels encrypted to the module, which makes its own subkey.
//!
//! The relay stops when it is dropped (its connections with it).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag11,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag8, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncryptedData};
use picky_krb::messages::{
    ApReq, AsReq, EncTgsRepPart, KdcRep, KrbError, KrbErrorInner, TgsRep, TgsReq,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use super::krb::{self, NoTicket};
use super::krbref::{self, CachedTgt, Got, Hop};

const AES256: u8 = 18;
const PA_TGS_REQ: i64 = 1;
/// The KDC options RustHound-CE (and Pathwarden) ask with: forwardable,
/// renewable, canonicalize.
const KDC_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x00];
/// KRB_ERR_GENERIC, for a request or reply the relay refuses.
const KRB_ERR_GENERIC: u32 = 60;
/// KDC_ERR_S_PRINCIPAL_UNKNOWN and KDC_ERR_ETYPE_NOSUPP, for a referral
/// that ends there.
const KDC_ERR_S_PRINCIPAL_UNKNOWN: u32 = 7;
const KDC_ERR_ETYPE_NOSUPP: u32 = 14;
/// Connections handled at once; the next waits for a free place before it
/// is accepted.
pub(crate) const AT_ONCE: usize = 32;
/// Largest request taken (a TGS-REQ with a TGT and its PAC is a few KB).
const MAX_REQUEST: usize = 256 * 1024;
/// How long one connection may take, from accepting it to the answer
/// (reading the request, the domain controller, any referrals): about
/// RustHound-CE's own wait for a computer.
const DEADLINE: Duration = Duration::from_secs(8);
/// How old an authenticator may be (Kerberos' default clock skew).
const MAX_SKEW_SECS: i64 = 300;

/// A realm's KDC, for a referral.
pub(crate) type KdcFor = Arc<dyn Fn(&str) -> String + Send + Sync>;
/// Where the relay's refusals are logged.
pub(crate) type Log = Arc<dyn Fn(String) + Send + Sync>;

/// The running relay: its address for the modules. Dropping it stops it.
pub(crate) struct KdcRelay {
    addr: String,
    task: tokio::task::JoinHandle<()>,
    inner: Arc<Inner>,
}

impl Drop for KdcRelay {
    fn drop(&mut self) {
        self.task.abort();
        let n = self.inner.turned_away.load(Ordering::Relaxed);
        if n > 0 {
            (self.inner.log)(format!(
                "warning: [krb] the modules' KDC relay refused {} that didn't present this \
                 run's ticket.",
                pathwarden_core::text::count(n, "request", "requests")
            ));
        }
    }
}

struct Inner {
    tgt: CachedTgt,
    /// The DER of the run's TGT, as the modules present it.
    ticket_der: Vec<u8>,
    /// The domain controller verified over LDAPS that gave the TGT.
    home_kdc: String,
    kdc_for: KdcFor,
    log: Log,
    /// The longest a connection may take.
    deadline: Duration,
    /// Requests refused before they presented the run's ticket.
    turned_away: AtomicUsize,
}

impl KdcRelay {
    /// Starts a relay for the TGT in `ccache` (a `KRB5CCNAME`), forwarding
    /// to `home_kdc`; referrals go to each realm's KDC by its DNS name.
    pub(crate) async fn start(ccache: &str, home_kdc: &str, log: Log) -> Result<Self, String> {
        Self::start_with(ccache, home_kdc, Arc::new(krbref::kdc_by_dns), log).await
    }

    /// [`Self::start`], each realm's KDC from `kdc_for`.
    pub(crate) async fn start_with(
        ccache: &str,
        home_kdc: &str,
        kdc_for: KdcFor,
        log: Log,
    ) -> Result<Self, String> {
        Self::start_inner(ccache, home_kdc, kdc_for, log, DEADLINE).await
    }

    /// [`Self::start_with`], each connection given `deadline`.
    #[cfg(test)]
    pub(crate) async fn start_with_deadline(
        ccache: &str,
        home_kdc: &str,
        kdc_for: KdcFor,
        log: Log,
        deadline: Duration,
    ) -> Result<Self, String> {
        Self::start_inner(ccache, home_kdc, kdc_for, log, deadline).await
    }

    async fn start_inner(
        ccache: &str,
        home_kdc: &str,
        kdc_for: KdcFor,
        log: Log,
        deadline: Duration,
    ) -> Result<Self, String> {
        let tgt = krbref::read_cache(ccache)?;
        let ticket_der =
            picky_asn1_der::to_vec(&tgt.ticket).map_err(|e| format!("the TGT: {e}"))?;
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| format!("127.0.0.1: {e}"))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("127.0.0.1: {e}"))?;
        if !local.ip().is_loopback() {
            return Err(format!("bound to {local}, not to 127.0.0.1"));
        }
        let inner = Arc::new(Inner {
            tgt,
            ticket_der,
            home_kdc: home_kdc.to_string(),
            kdc_for,
            log,
            deadline,
            turned_away: AtomicUsize::new(0),
        });
        let task = tokio::spawn(serve(listener, inner.clone()));
        log::debug!("[krb] KDC relay for the modules on {local}");
        Ok(Self {
            addr: local.to_string(),
            task,
            inner,
        })
    }

    /// `127.0.0.1:<port>`.
    pub(crate) fn addr(&self) -> &str {
        &self.addr
    }

    /// `options` for a RustHound-CE module: the relay as its KDC (the
    /// modules use `ldapfqdn` for nothing else).
    pub(crate) fn options(
        &self,
        options: &rusthound_ce::args::Options,
    ) -> rusthound_ce::args::Options {
        let mut o = options.clone();
        o.ldapfqdn = Some(self.addr().to_string());
        o
    }
}

/// `options` through `relay`, if there is one.
pub(crate) fn via(
    relay: Option<&KdcRelay>,
    options: &rusthound_ce::args::Options,
) -> rusthound_ce::args::Options {
    match relay {
        Some(r) => r.options(options),
        None => options.clone(),
    }
}

async fn serve(listener: tokio::net::TcpListener, inner: Arc<Inner>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    // Owned here: when the relay is stopped, its connections go too.
    let mut conns = tokio::task::JoinSet::new();
    loop {
        // A free place first: a connection beyond AT_ONCE waits in the
        // system's queue, not in a task.
        let Ok(permit) = sem.clone().acquire_owned().await else {
            return;
        };
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let inner = inner.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    // One deadline for the whole exchange.
                    let _ = tokio::time::timeout(inner.deadline, connection(stream, &inner)).await;
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

/// One request and its answer (TCP framing: a 4-byte length first).
async fn connection(mut stream: tokio::net::TcpStream, inner: &Inner) {
    let mut len = [0u8; 4];
    if stream.read_exact(&mut len).await.is_err() {
        return;
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_REQUEST {
        return;
    }
    let mut req = vec![0u8; n];
    if stream.read_exact(&mut req).await.is_err() {
        return;
    }
    let reply = answer(inner, &req).await;
    let mut framed = Vec::with_capacity(reply.len() + 4);
    framed.extend_from_slice(&(reply.len() as u32).to_be_bytes());
    framed.extend_from_slice(&reply);
    let _ = stream.write_all(&framed).await;
}

/// The answer to one request: the KDC's checked reply, or a KRB-ERROR.
async fn answer(inner: &Inner, req: &[u8]) -> Vec<u8> {
    match relay(inner, req).await {
        Ok(reply) => reply,
        Err(Refusal {
            code,
            why,
            quiet: true,
        }) => {
            // Not this run's: anyone on this computer can connect.
            log::debug!("[krb] KDC relay: refused {why}");
            inner.turned_away.fetch_add(1, Ordering::Relaxed);
            krb_error(code, &inner.tgt.realm, "")
        }
        Err(Refusal { code, why, .. }) => {
            log::warn!("[krb] KDC relay: {why}");
            (inner.log)(format!(
                "warning: [krb] the modules' KDC relay refused {why}."
            ));
            krb_error(code, &inner.tgt.realm, &why)
        }
    }
}

/// Why the relay refused, and the KRB-ERROR code the module gets. `quiet`:
/// before the request presented the run's ticket.
#[derive(Debug)]
struct Refusal {
    code: u32,
    why: String,
    quiet: bool,
}

fn refuse(why: impl Into<String>) -> Refusal {
    Refusal {
        code: KRB_ERR_GENERIC,
        why: why.into(),
        quiet: false,
    }
}

/// [`refuse`], for a request that didn't present the run's ticket.
fn turn_away(why: impl Into<String>) -> Refusal {
    Refusal {
        quiet: true,
        ..refuse(why)
    }
}

/// A ticket refusal from [`krbref`], as a KDC error the module can read.
fn no_ticket(host: &str, e: NoTicket) -> Refusal {
    let code = match e {
        NoTicket::NoName(_) => KDC_ERR_S_PRINCIPAL_UNKNOWN,
        NoTicket::Rc4Trust(_) => KDC_ERR_ETYPE_NOSUPP,
        NoTicket::Unreachable(_) | NoTicket::Refused(_) => KRB_ERR_GENERIC,
    };
    Refusal {
        code,
        why: format!("a ticket for cifs/{host}: {}", e.words()),
        quiet: false,
    }
}

fn der<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Refusal> {
    picky_asn1_der::to_vec(v).map_err(|e| refuse(format!("a message: {e}")))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A plain DNS name for a computer.
fn plain_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with(['.', '-'])
}

/// The key the module's reply is encrypted with, and its key usage: the
/// authenticator's subkey (9), or the TGT's session key (8).
struct ReplyKey {
    key: Vec<u8>,
    usage: i32,
}

impl Drop for ReplyKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Checks that the request presents this run's TGT, made by someone holding
/// its session key: the PA-TGS-REQ's ticket is the run's, and its
/// authenticator opens with the session key, names the run's client and was
/// made in the last 5 minutes.
fn check_presented(inner: &Inner, req: &TgsReq) -> Result<ReplyKey, Refusal> {
    let pas: &[picky_krb::data_types::PaData] = req
        .0
        .padata
        .0
        .as_ref()
        .map(|p| p.0 .0.as_slice())
        .unwrap_or(&[]);
    // Exactly one: the PA-TGS-REQ, as RustHound-CE sends it.
    let [pa] = pas else {
        return Err(turn_away("a request without exactly one PA-DATA"));
    };
    if krbref::int(&pa.padata_type.0) != PA_TGS_REQ {
        return Err(turn_away("a request whose PA-DATA isn't a PA-TGS-REQ"));
    }
    let ap: ApReq = picky_asn1_der::from_bytes(&pa.padata_data.0 .0)
        .map_err(|_| turn_away("a request whose PA-TGS-REQ isn't an AP-REQ"))?;
    if der(&ap.0.ticket.0).map_err(|r| turn_away(r.why))? != inner.ticket_der {
        return Err(turn_away("a request with a TGT that isn't this run's"));
    }
    let enc = &ap.0.authenticator.0;
    if krbref::int(&enc.etype.0) != i64::from(AES256) {
        return Err(turn_away("a request whose authenticator isn't AES256"));
    }
    let mut plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(
            &inner.tgt.key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &enc.cipher.0 .0,
        )
        .map_err(|_| turn_away("a request whose authenticator doesn't open with this run's key"))?;
    let auth = picky_asn1_der::from_bytes::<Authenticator>(&plain);
    plain.zeroize();
    let mut auth = auth.map_err(|_| turn_away("a request whose authenticator doesn't decode"))?;
    let crealm = krbref::text(&auth.0.crealm.0);
    let cname: Vec<String> = auth
        .0
        .cname
        .0
        .name_string
        .0
         .0
        .iter()
        .map(krbref::text)
        .collect();
    if !crealm.eq_ignore_ascii_case(&inner.tgt.realm)
        || cname.len() != 1
        || !cname[0].eq_ignore_ascii_case(&inner.tgt.user)
    {
        return Err(turn_away("a request from another client than this run's"));
    }
    let made = krb::unix_of_pub(&auth.0.ctime.0);
    if (now_unix() - made).abs() > MAX_SKEW_SECS {
        return Err(turn_away("a request whose authenticator isn't fresh"));
    }
    match auth.0.subkey.0.as_mut() {
        None => Ok(ReplyKey {
            key: inner.tgt.key.clone(),
            usage: TGS_REP_ENC_SESSION_KEY,
        }),
        Some(sub) => {
            let key = std::mem::take(&mut sub.0.key_value.0 .0);
            if krbref::int(&sub.0.key_type.0) != i64::from(AES256) || key.len() != 32 {
                let mut key = key;
                key.zeroize();
                return Err(turn_away("a request whose subkey isn't AES256"));
            }
            Ok(ReplyKey {
                key,
                usage: TGS_REP_ENC_SUB_KEY,
            })
        }
    }
}

/// The relay's work for one request: Ok is the reply to pass on.
async fn relay(inner: &Inner, raw: &[u8]) -> Result<Vec<u8>, Refusal> {
    let req: TgsReq = match picky_asn1_der::from_bytes(raw) {
        Ok(r) => r,
        Err(_) if picky_asn1_der::from_bytes::<AsReq>(raw).is_ok() => {
            return Err(turn_away(
                "an AS-REQ: it passes service ticket requests only",
            ));
        }
        Err(_) => return Err(turn_away("a request that isn't a TGS-REQ")),
    };
    let key = check_presented(inner, &req)?;
    let body = &req.0.req_body.0;
    let options = picky_asn1::wrapper::BitStringAsn1::from(
        picky_asn1::bit_string::BitString::with_bytes(KDC_OPTIONS.to_vec()),
    );
    if der(&body.kdc_options.0)? != der(&options)? {
        return Err(refuse(
            "a request with other KDC options than RustHound-CE's",
        ));
    }
    let realm = krbref::text(&body.realm.0);
    if !realm.eq_ignore_ascii_case(&inner.tgt.realm) {
        return Err(refuse(format!(
            "a request for realm {realm}, not {}",
            inner.tgt.realm
        )));
    }
    let sname: Vec<String> = body
        .sname
        .0
        .as_ref()
        .map(|s| s.0.name_string.0 .0.iter().map(krbref::text).collect())
        .unwrap_or_default();
    let host = match sname.as_slice() {
        [service, host] if service.eq_ignore_ascii_case("cifs") && plain_host(host) => host.clone(),
        _ => {
            return Err(refuse(format!(
                "a request for {}, not cifs/<computer>",
                sname.join("/")
            )))
        }
    };
    if body.additional_tickets.0.is_some() || body.enc_authorization_data.0.is_some() {
        return Err(refuse(format!(
            "a request for cifs/{host} with extra tickets or authorization data"
        )));
    }
    let asked: Vec<i64> = body.etype.0 .0.iter().map(krbref::int).collect();
    if !asked.contains(&i64::from(AES256)) {
        return Err(refuse(format!(
            "a request for cifs/{host} that asks for no AES256 key"
        )));
    }
    let nonce = body.nonce.0.clone();
    // RC4 (and anything else) out: AES256 only.
    let mut forward = req.clone();
    forward.0.req_body.0.etype =
        ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![AES256])]));
    let reply = krb::exchange_pub(&inner.home_kdc, &der(&forward)?)
        .await
        .map_err(|e| no_ticket(&host, e))?;
    let rep: TgsRep = match picky_asn1_der::from_bytes(&reply) {
        Ok(r) => r,
        // The KDC's own error goes to the module as is.
        Err(_) if picky_asn1_der::from_bytes::<KrbError>(&reply).is_ok() => return Ok(reply),
        Err(_) => {
            return Err(refuse(format!(
                "an answer for cifs/{host} from {} that isn't Kerberos",
                inner.home_kdc
            )))
        }
    };
    let got = krbref::check_rep(&rep, &inner.tgt.realm, &host, &key.key, key.usage, &nonce)
        .map_err(|e| no_ticket(&host, e))?;
    if got.is_for(&host) {
        return Ok(reply);
    }
    let Some(next) = got.referral() else {
        return Err(refuse(format!(
            "a ticket for {}, not cifs/{host}",
            got.sname.join("/")
        )));
    };
    if next.eq_ignore_ascii_case(&inner.tgt.realm) {
        return Err(refuse(format!("a referral for cifs/{host} back to {next}")));
    }
    log::debug!("[krb] KDC relay: cifs/{host} is in {next}; following the referral");
    let hop = Hop {
        kdc: (inner.kdc_for)(&next),
        realm: next.clone(),
        ticket: got.ticket.clone(),
        key: got.key.clone(),
    };
    let path = vec![inner.tgt.realm.to_ascii_uppercase(), next];
    let last = krbref::follow(&inner.tgt, &host, hop, path, &*inner.kdc_for)
        .await
        .map_err(|e| no_ticket(&host, e))?;
    reencrypt(&last, &nonce, &key)
}

/// The last hop's reply as a TGS-REP to the module's request: its
/// encrypted part, with the module's nonce, under the module's key.
fn reencrypt(last: &Got, nonce: &IntegerAsn1, key: &ReplyKey) -> Result<Vec<u8>, Refusal> {
    let mut part = last.part.clone();
    part.nonce = ExplicitContextTag2::from(nonce.clone());
    let plain = der(&EncTgsRepPart::from(part.clone()));
    part.key.0.key_value.0 .0.zeroize();
    let mut plain = plain?;
    let cipher = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(&key.key, key.usage, &plain)
        .map_err(|e| refuse(format!("encrypting the ticket: {e}")));
    plain.zeroize();
    let rep = TgsRep::from(KdcRep {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![13])),
        padata: Optional::from(None),
        crealm: ExplicitContextTag3::from(last.crealm.clone()),
        cname: ExplicitContextTag4::from(last.cname.clone()),
        ticket: ExplicitContextTag5::from(last.ticket.clone()),
        enc_part: ExplicitContextTag6::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher?)),
        }),
    });
    der(&rep)
}

/// A KRB-ERROR with `code` and `why` as its text.
fn krb_error(code: u32, realm: &str, why: &str) -> Vec<u8> {
    let string = |s: &str| {
        picky_asn1::restricted_string::Ia5String::from_string(s.to_string())
            .ok()
            .map(picky_asn1::wrapper::GeneralStringAsn1::from)
    };
    let sname = picky_krb::data_types::PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            ["krbtgt", realm]
                .iter()
                .filter_map(|p| string(p))
                .collect::<Vec<_>>(),
        )),
    };
    let e = KrbError::from(KrbErrorInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![30])),
        ctime: Optional::from(None),
        cusec: Optional::from(None),
        stime: ExplicitContextTag4::from(krb::kerberos_time_pub(now_unix())),
        susec: ExplicitContextTag5::from(IntegerAsn1(vec![0])),
        error_code: ExplicitContextTag6::from(code),
        crealm: Optional::from(None),
        cname: Optional::from(None),
        realm: ExplicitContextTag9::from(
            string(realm).unwrap_or_else(|| string("").expect("empty")),
        ),
        sname: picky_asn1::wrapper::ExplicitContextTag10::from(sname),
        e_text: Optional::from(string(why).map(ExplicitContextTag11::from)),
        e_data: Optional::from(None),
    });
    picky_asn1_der::to_vec(&e).unwrap_or_default()
}
