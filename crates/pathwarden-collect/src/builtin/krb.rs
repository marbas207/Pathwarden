//! Kerberos only, with a user and password.
//!
//! With a password the LDAP sign-in is NTLM over a checked LDAPS
//! certificate (the certificate proves the domain controller). Computers
//! (sessions, local groups, SYSVOL, the CAs' registry) are another matter:
//! an NTLM sign-in to a name someone added to the domain's DNS hands them a
//! response they can crack or relay. So computers are signed in to with
//! Kerberos only:
//!
//! 1. [`request_tgt`]: the first ticket (TGT) is asked of the domain
//!    controller already verified over LDAPS (TCP 88, AES256 pre-auth), in
//!    pure Rust with picky-krb. No SSPI, no system Kerberos.
//! 2. [`TicketCache`]: it is written to a ticket cache (MIT ccache v4) in a
//!    folder private to this account, deleted when the collection ends. The
//!    ticket is never logged; its path only at debug level.
//! 3. RustHound-CE's SMB modules (sessions, local groups, WebClient) take
//!    the cache through `KRB5CCNAME` with `--kerberos` and never fall back to
//!    NTLM, and ask for their service tickets through a relay that checks
//!    them ([`super::krbrelay`]); Pathwarden's own SYSVOL and CA
//!    registry reads use it too ([`super::hosts::SmbIdentity::kerberos`]).
//! 4. [`service_ticket`]: before a computer is contacted, its `cifs/<name>`
//!    ticket is asked for. A name the domain has no Kerberos name (SPN) for,
//!    as one added to DNS, gets `KDC_ERR_S_PRINCIPAL_UNKNOWN`: the computer
//!    is skipped and never connected to.
//!
//! If no TGT can be had (clock skew, port 88, the password, an account
//! without AES keys), the collection stops before collecting, with the
//! reason ([`KrbFailure`]).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use picky_asn1::bit_string::BitString;
use picky_asn1::date::Date;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, GeneralStringAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{AS_REP_ENC, AS_REQ_TIMESTAMP};
use picky_krb::constants::types::{AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    EncryptedData, EtypeInfo2, KerbPaPacRequest, KerberosTime, PaData, PaEncTsEnc, PrincipalName,
};
use picky_krb::messages::{
    ApReq, AsRep, AsReq, EncAsRepPart, EncTgsRepPart, KdcReq, KdcReqBody, KrbError,
};
use zeroize::Zeroize;

use crate::Secret;

/// AES256-CTS-HMAC-SHA1-96: the only type asked for, for the pre-auth and
/// the TGT's session key (RustHound-CE's ticket code takes a 32-byte key
/// as AES256, a 16-byte one as RC4).
const AES256: u8 = 18;
/// PA-ENC-TIMESTAMP, PA-ETYPE-INFO2, PA-PAC-REQUEST.
const PA_ENC_TIMESTAMP: u8 = 2;
const PA_ETYPE_INFO2: u8 = 19;
const PA_PAC_REQUEST: u8 = 128;
/// How long one exchange with the KDC may take.
const KDC_TIMEOUT: Duration = Duration::from_secs(15);
/// Most clock difference Kerberos allows (Windows' default).
const MAX_SKEW_MINUTES: i64 = 5;

/// KDC error codes Pathwarden explains (RFC 4120 7.5.9, MS-KILE).
const KDC_ERR_C_PRINCIPAL_UNKNOWN: u32 = 6;
const KDC_ERR_POLICY: u32 = 12;
const KRB_AP_ERR_TKT_EXPIRED: u32 = 32;
pub(crate) const KDC_ERR_S_PRINCIPAL_UNKNOWN: u32 = 7;
const KDC_ERR_ETYPE_NOSUPP: u32 = 14;
const KDC_ERR_CLIENT_REVOKED: u32 = 18;
const KDC_ERR_KEY_EXPIRED: u32 = 23;
const KDC_ERR_PREAUTH_FAILED: u32 = 24;
const KDC_ERR_PREAUTH_REQUIRED: u32 = 25;
const KRB_AP_ERR_SKEW: u32 = 37;
const KDC_ERR_WRONG_REALM: u32 = 68;

/// The name of a KDC error code, for the details line.
pub(crate) fn error_name(code: u32) -> &'static str {
    match code {
        KDC_ERR_C_PRINCIPAL_UNKNOWN => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        KDC_ERR_S_PRINCIPAL_UNKNOWN => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        KDC_ERR_POLICY => "KDC_ERR_POLICY",
        KDC_ERR_ETYPE_NOSUPP => "KDC_ERR_ETYPE_NOSUPP",
        KDC_ERR_CLIENT_REVOKED => "KDC_ERR_CLIENT_REVOKED",
        KDC_ERR_KEY_EXPIRED => "KDC_ERR_KEY_EXPIRED",
        KDC_ERR_PREAUTH_FAILED => "KDC_ERR_PREAUTH_FAILED",
        KDC_ERR_PREAUTH_REQUIRED => "KDC_ERR_PREAUTH_REQUIRED",
        KRB_AP_ERR_SKEW => "KRB_AP_ERR_SKEW",
        KDC_ERR_WRONG_REALM => "KDC_ERR_WRONG_REALM",
        _ => "KDC error",
    }
}

/// Why no TGT could be had, in plain words: what went wrong and what to do
/// (`headline`, no command-line flags: the app shows it as is, the CLI adds
/// `--allow-ntlm`), and the technical detail (`detail`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KrbFailure {
    pub headline: String,
    pub detail: String,
}

impl KrbFailure {
    fn new(headline: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            headline: headline.into(),
            detail: detail.into(),
        }
    }

    /// For a KDC error `code` from `kdc` (host:88), asking for `who`'s
    /// ticket in `realm`; `skew` is how far this computer's clock is from
    /// the KDC's (seconds, + ahead), when the error says.
    fn from_kdc(code: u32, kdc: &str, who: &str, realm: &str, skew: Option<i64>) -> Self {
        let dc = kdc_host(kdc);
        let detail = format!("{} ({code}) from {}", error_name(code), with_port(kdc));
        let headline = match code {
            KRB_AP_ERR_SKEW => {
                let minutes = skew.map(|s| (s.abs() + 59) / 60).unwrap_or(0);
                if minutes > 0 {
                    format!(
                        "Kerberos didn't work: this computer's clock is {} off {dc}'s. Kerberos \
                         allows {MAX_SKEW_MINUTES} minutes, so set this computer's clock from \
                         the domain and try again.",
                        pathwarden_core::text::count(minutes as usize, "minute", "minutes")
                    )
                } else {
                    format!(
                        "Kerberos didn't work: this computer's clock is too far off {dc}'s. \
                         Kerberos allows {MAX_SKEW_MINUTES} minutes, so set this computer's \
                         clock from the domain and try again."
                    )
                }
            }
            KDC_ERR_PREAUTH_FAILED => {
                "Kerberos didn't work: the domain controller refused the password.".to_string()
            }
            KDC_ERR_C_PRINCIPAL_UNKNOWN => {
                format!("Kerberos didn't work: {dc} doesn't know the account {who} in {realm}.")
            }
            KDC_ERR_CLIENT_REVOKED => {
                "Kerberos didn't work: the account is disabled, locked out or expired.".to_string()
            }
            KDC_ERR_KEY_EXPIRED => {
                "Kerberos didn't work: the account's password has expired.".to_string()
            }
            KDC_ERR_ETYPE_NOSUPP => no_aes(),
            KDC_ERR_WRONG_REALM => format!(
                "Kerberos didn't work: {dc} sent the sign-in to another domain. Use an account \
                 from {}.",
                realm.to_ascii_lowercase()
            ),
            _ => format!(
                "Kerberos didn't work: {dc} refused the ticket ({}).",
                error_name(code)
            ),
        };
        Self::new(headline, detail)
    }
}

/// The headline for an account without AES keys.
fn no_aes() -> String {
    "Kerberos didn't work: the account has no AES Kerberos keys. Change its password once \
     (the domain then stores them) and try again."
        .to_string()
}

/// `host` of `host:port` (an IPv6 address in brackets kept whole).
fn kdc_host(kdc: &str) -> &str {
    match kdc.rsplit_once(':') {
        Some((h, p))
            if !h.is_empty()
                && p.parse::<u16>().is_ok()
                && (!h.contains(':') || (h.starts_with('[') && h.ends_with(']'))) =>
        {
            h
        }
        _ => kdc,
    }
}

/// `kdc` with the Kerberos port, unless it names one.
fn with_port(kdc: &str) -> String {
    if kdc_host(kdc) == kdc {
        format!("{kdc}:88")
    } else {
        kdc.to_string()
    }
}

/// The TGT, and what the ticket cache needs to hold it.
pub(crate) struct Tgt {
    pub realm: String,
    /// The client name (the account's sAMAccountName, as the KDC returned it).
    pub user: String,
    ticket_der: Vec<u8>,
    session_key: Vec<u8>,
    key_type: u16,
    auth_time: u32,
    start_time: u32,
    pub end_time: u32,
    renew_till: u32,
}

impl Drop for Tgt {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.ticket_der.zeroize();
    }
}

impl std::fmt::Debug for Tgt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tgt")
            .field("realm", &self.realm)
            .field("user", &self.user)
            .field("end_time", &self.end_time)
            .finish_non_exhaustive()
    }
}

impl Tgt {
    /// "AES256, valid 10:00": the key type and the time left, for the log.
    pub(crate) fn summary(&self) -> String {
        let left = i64::from(self.end_time) - now_unix();
        let left = left.max(0);
        format!(
            "{}, valid {}:{:02}",
            if self.key_type == u16::from(AES256) {
                "AES256"
            } else {
                "AES"
            },
            left / 3600,
            (left % 3600) / 60
        )
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- times ---------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Seconds since 1970 of a Kerberos time.
fn unix_of(t: &KerberosTime) -> i64 {
    let d = &t.0;
    days_from_civil(
        i64::from(d.year()),
        i64::from(d.month()),
        i64::from(d.day()),
    ) * 86_400
        + i64::from(d.hour()) * 3600
        + i64::from(d.minute()) * 60
        + i64::from(d.second())
}

/// A Kerberos time from seconds since 1970.
fn kerberos_time(secs: i64) -> KerberosTime {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    KerberosTime::from(
        Date::new(
            y as u16,
            m as u8,
            d as u8,
            (tod / 3600) as u8,
            ((tod % 3600) / 60) as u8,
            (tod % 60) as u8,
        )
        .unwrap_or_else(|| Date::new(2037, 9, 13, 2, 48, 5).expect("a valid date")),
    )
}

/// [`unix_of`], for the KDC relay (`super::krbrelay`).
pub(crate) fn unix_of_pub(t: &KerberosTime) -> i64 {
    unix_of(t)
}

/// [`kerberos_time`], for the referral code (`super::krbref`).
pub(crate) fn kerberos_time_pub(secs: i64) -> KerberosTime {
    kerberos_time(secs)
}

/// [`exchange`] with `kdc`, a failure (no connection, no answer) as an
/// unreachable KDC.
pub(crate) async fn exchange_pub(kdc: &str, request: &[u8]) -> Result<Vec<u8>, NoTicket> {
    exchange(kdc, request)
        .await
        .map_err(|d| NoTicket::Unreachable(format!("Kerberos: {d}")))
}

/// A u32 ccache time (seconds since 1970, clamped).
fn ccache_time(secs: i64) -> u32 {
    secs.clamp(0, i64::from(u32::MAX)) as u32
}

// ---- ASN.1 helpers -------------------------------------------------------

fn krb_string(s: &str) -> Result<GeneralStringAsn1, String> {
    Ia5String::from_string(s.to_owned())
        .map(GeneralStringAsn1::from)
        .map_err(|_| format!("{s:?} has characters Kerberos names can't have"))
}

fn principal(name_type: u8, parts: &[&str]) -> Result<PrincipalName, String> {
    let strings = parts
        .iter()
        .map(|p| krb_string(p))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
    })
}

/// An ASN.1 INTEGER as a number (two's complement, big-endian).
fn int(i: &IntegerAsn1) -> i64 {
    let bytes = &i.0;
    let mut v: i64 = if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for b in bytes.iter().take(8) {
        v = (v << 8) | i64::from(*b);
    }
    v
}

fn text(s: &GeneralStringAsn1) -> String {
    String::from_utf8_lossy(s.0.as_bytes()).into_owned()
}

fn padata(kind: u8, data: Vec<u8>) -> PaData {
    PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(if kind >= 0x80 {
            vec![0, kind]
        } else {
            vec![kind]
        })),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(data)),
    }
}

fn nonce() -> Vec<u8> {
    let mut n = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n[0] &= 0x7f;
    n.to_vec()
}

fn as_req(realm: &str, user: &str, nonce: &[u8], padatas: Vec<PaData>) -> Result<Vec<u8>, String> {
    let body = KdcReqBody {
        // forwardable, renewable, canonicalize, renewable-ok
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x40, 0x81, 0x00, 0x10,
        ]))),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(
            NT_PRINCIPAL,
            &[user],
        )?))),
        realm: ExplicitContextTag2::from(krb_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["krbtgt", realm],
        )?))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(kerberos_time(now_unix() + 10 * 3600)),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1(nonce.to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![AES256])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let req = AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(
            padatas,
        )))),
        req_body: ExplicitContextTag4::from(body),
    });
    picky_asn1_der::to_vec(&req).map_err(|e| format!("AS-REQ: {e}"))
}

fn pac_request() -> Result<PaData, String> {
    let der = picky_asn1_der::to_vec(&KerbPaPacRequest {
        include_pac: ExplicitContextTag0::from(true),
    })
    .map_err(|e| format!("PA-PAC-REQUEST: {e}"))?;
    Ok(padata(PA_PAC_REQUEST, der))
}

// ---- the exchange --------------------------------------------------------

/// Why one exchange with the KDC failed.
#[derive(Debug)]
enum Exchange {
    /// It couldn't be reached on `kdc` (port 88), or didn't answer.
    Unreachable(String),
    /// It answered with a KRB-ERROR.
    Error(Box<KrbError>),
    /// It answered something else, or a reply didn't decode.
    Garbled(String),
}

/// Sends `request` to `kdc` (`host` or `host:port`, port 88 by default)
/// over TCP and returns the reply.
async fn exchange(kdc: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = with_port(kdc);
    let talk = async {
        let mut stream = tokio::net::TcpStream::connect(&addr).await?;
        let mut framed = Vec::with_capacity(request.len() + 4);
        framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
        framed.extend_from_slice(request);
        stream.write_all(&framed).await?;
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > 1024 * 1024 {
            return Err(std::io::Error::other(format!("a {n}-byte answer")));
        }
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    match tokio::time::timeout(KDC_TIMEOUT, talk).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(e)) => Err(format!("{addr}: {e}")),
        Err(_) => Err(format!(
            "{addr}: no answer within {}s",
            KDC_TIMEOUT.as_secs()
        )),
    }
}

/// A reply: an AS-REP, or a KRB-ERROR.
fn as_rep(reply: &[u8]) -> Result<AsRep, Exchange> {
    match picky_asn1_der::from_bytes::<AsRep>(reply) {
        Ok(rep) => Ok(rep),
        Err(_) => match picky_asn1_der::from_bytes::<KrbError>(reply) {
            Ok(err) => Err(Exchange::Error(Box::new(err))),
            Err(e) => Err(Exchange::Garbled(format!(
                "an answer that isn't Kerberos: {e}"
            ))),
        },
    }
}

/// The salt for AES256 from a KRB-ERROR's or AS-REP's padata
/// (PA-ETYPE-INFO2), if it offers AES256.
fn aes_salt(padatas: &[PaData]) -> Option<Option<String>> {
    let entries = etype_info(padatas)?;
    entries
        .iter()
        .find(|(etype, _)| *etype == i64::from(AES256))
        .map(|(_, salt)| salt.clone())
}

/// The key types (and salts) PA-ETYPE-INFO2 offers, if there is one.
fn etype_info(padatas: &[PaData]) -> Option<Vec<(i64, Option<String>)>> {
    let p = padatas
        .iter()
        .find(|p| int(&p.padata_type.0) == i64::from(PA_ETYPE_INFO2))?;
    let info: EtypeInfo2 = picky_asn1_der::from_bytes(&p.padata_data.0 .0).ok()?;
    Some(
        info.0
            .iter()
            .map(|e| (int(&e.etype.0), e.salt.0.as_ref().map(|s| text(&s.0))))
            .collect(),
    )
}

/// AES128-CTS-HMAC-SHA1-96.
const AES128: i64 = 17;

/// The headline for an account whose keys don't include AES256: AES128
/// only, or no AES at all.
fn no_aes256(offered: &[(i64, Option<String>)]) -> String {
    if offered.iter().any(|(e, _)| *e == AES128) {
        "Kerberos didn't work: the account has AES128 Kerberos keys only, and Pathwarden \
         uses AES256. Allow AES256 for the account and try again."
            .to_string()
    } else {
        no_aes()
    }
}

/// The METHOD-DATA (a SEQUENCE OF PA-DATA) in a KRB-ERROR's e-data.
fn method_data(err: &KrbError) -> Vec<PaData> {
    err.0
        .e_data
        .0
        .as_ref()
        .and_then(|d| picky_asn1_der::from_bytes::<Asn1SequenceOf<PaData>>(&d.0 .0).ok())
        .map(|s| s.0)
        .unwrap_or_default()
}

/// Asks `kdc` (the domain controller already verified over LDAPS) for a
/// TGT for `user` (the sAMAccountName) in `realm` (the domain's DNS name,
/// any case) with `password`. AES256 only; pre-auth with an encrypted
/// timestamp, salted as the KDC says (PA-ETYPE-INFO2).
pub(crate) async fn request_tgt(
    kdc: &str,
    realm: &str,
    user: &str,
    password: &Secret,
) -> Result<Tgt, KrbFailure> {
    let realm = realm.trim().to_ascii_uppercase();
    let who = user.to_string();
    let failed = |e: Exchange| -> KrbFailure {
        match e {
            Exchange::Unreachable(detail) => KrbFailure::new(
                format!(
                    "Kerberos didn't work: this computer can't reach {} on port 88. Open TCP \
                     port 88 to the domain controller and try again.",
                    kdc_host(kdc)
                ),
                detail,
            ),
            Exchange::Error(err) => {
                let skew = unix_of(&err.0.stime.0);
                KrbFailure::from_kdc(
                    err.0.error_code.0,
                    kdc,
                    &who,
                    &realm,
                    Some(now_unix() - skew),
                )
            }
            Exchange::Garbled(detail) => KrbFailure::new(
                format!(
                    "Kerberos didn't work: {} didn't answer as a domain controller does on \
                     port 88.",
                    kdc_host(kdc)
                ),
                detail,
            ),
        }
    };
    let settings = |e: String| KrbFailure::new(format!("Kerberos didn't work: {e}."), e.clone());

    // 1. Without pre-auth: the KDC says how to salt the key.
    let first_nonce = nonce();
    let request = as_req(
        &realm,
        user,
        &first_nonce,
        vec![pac_request().map_err(settings)?],
    )
    .map_err(settings)?;
    let reply = exchange(kdc, &request)
        .await
        .map_err(|d| failed(Exchange::Unreachable(d)))?;
    let salt = match as_rep(&reply) {
        // An account that doesn't require pre-auth answers at once.
        Ok(rep) => {
            let pa = rep
                .0
                .padata
                .0
                .as_ref()
                .map(|p| p.0 .0.clone())
                .unwrap_or_default();
            let salt = aes_salt(&pa).flatten();
            return finish(rep, &first_nonce, &realm, user, password, salt);
        }
        Err(Exchange::Error(err)) if err.0.error_code.0 == KDC_ERR_PREAUTH_REQUIRED => {
            let methods = method_data(&err);
            match aes_salt(&methods) {
                Some(salt) => salt,
                None => {
                    let offered = etype_info(&methods).unwrap_or_default();
                    let types: Vec<String> = offered.iter().map(|(e, _)| e.to_string()).collect();
                    return Err(KrbFailure::new(
                        no_aes256(&offered),
                        format!(
                            "no AES256 in PA-ETYPE-INFO2 from {} (offered: {})",
                            with_port(kdc),
                            types.join(", ")
                        ),
                    ));
                }
            }
        }
        Err(e) => return Err(failed(e)),
    };

    // 2. With an encrypted timestamp.
    let salt = salt.unwrap_or_else(|| format!("{realm}{user}"));
    let mut key = string_to_key(password, &salt).map_err(settings)?;
    let now = now_unix();
    let stamp = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(kerberos_time(now)),
        pausec: Optional::from(None),
    };
    let stamp = picky_asn1_der::to_vec(&stamp).map_err(|e| settings(format!("timestamp: {e}")))?;
    let cipher = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(&key, AS_REQ_TIMESTAMP, &stamp)
        .map_err(|e| settings(format!("timestamp: {e}")))?;
    let enc = EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
    };
    let enc = picky_asn1_der::to_vec(&enc).map_err(|e| settings(format!("timestamp: {e}")))?;
    let second_nonce = nonce();
    let request = as_req(
        &realm,
        user,
        &second_nonce,
        vec![
            padata(PA_ENC_TIMESTAMP, enc),
            pac_request().map_err(settings)?,
        ],
    )
    .map_err(settings)?;
    let reply = exchange(kdc, &request).await;
    let result = match reply {
        Ok(reply) => match as_rep(&reply) {
            Ok(rep) => decrypt(rep, &second_nonce, &key, &realm, user),
            Err(e) => Err(failed(e)),
        },
        Err(d) => Err(failed(Exchange::Unreachable(d))),
    };
    key.zeroize();
    result
}

/// The AES256 key of `password` salted with `salt` (RFC 3962).
fn string_to_key(password: &Secret, salt: &str) -> Result<Vec<u8>, String> {
    CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .generate_key_from_password(password.expose().as_bytes(), salt.as_bytes())
        .map_err(|e| format!("the password's key: {e}"))
}

/// An AS-REP that came without pre-auth: its key from the password.
fn finish(
    rep: AsRep,
    nonce: &[u8],
    realm: &str,
    user: &str,
    password: &Secret,
    salt: Option<String>,
) -> Result<Tgt, KrbFailure> {
    let salt = salt.unwrap_or_else(|| format!("{realm}{user}"));
    let mut key = string_to_key(password, &salt)
        .map_err(|e| KrbFailure::new(format!("Kerberos didn't work: {e}."), e))?;
    let r = decrypt(rep, nonce, &key, realm, user);
    key.zeroize();
    r
}

/// The TGT in an AS-REP, its encrypted part opened with `key`.
fn decrypt(
    rep: AsRep,
    nonce: &[u8],
    key: &[u8],
    realm: &str,
    user: &str,
) -> Result<Tgt, KrbFailure> {
    let bad = |what: String| {
        KrbFailure::new(
            "Kerberos didn't work: the domain controller's answer couldn't be read with the \
             password.",
            what,
        )
    };
    // The ticket must be for the account's own realm.
    let crealm = text(&rep.0.crealm.0);
    if !crealm.is_empty() && !crealm.eq_ignore_ascii_case(realm) {
        return Err(bad(format!(
            "the answer is for realm {crealm}, not {realm}"
        )));
    }
    let enc = &rep.0.enc_part.0;
    if int(&enc.etype.0) != i64::from(AES256) {
        return Err(KrbFailure::new(
            no_aes(),
            format!("AS-REP encrypted with etype {}", int(&enc.etype.0)),
        ));
    }
    let mut plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(key, AS_REP_ENC, &enc.cipher.0 .0)
        .map_err(|e| bad(format!("AS-REP: {e}")))?;
    // Windows' KDC tags it as an EncTGSRepPart; RFC 4120 says EncASRepPart.
    let part = picky_asn1_der::from_bytes::<EncAsRepPart>(&plain)
        .map(|p| p.0)
        .or_else(|_| picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain).map(|p| p.0))
        .map_err(|e| bad(format!("EncASRepPart: {e}")));
    plain.zeroize();
    let part = part?;
    let expected = int(&IntegerAsn1(nonce.to_vec()));
    if int(&part.nonce.0) != expected {
        return Err(bad("the answer's nonce isn't the request's".into()));
    }
    // A TGT of this realm (`krbtgt/REALM`, issued by REALM), for the
    // account asked for.
    let srealm = text(&part.srealm.0);
    let sname: Vec<String> = part.sname.0.name_string.0 .0.iter().map(text).collect();
    let is_tgt = sname.len() == 2
        && sname[0].eq_ignore_ascii_case("krbtgt")
        && sname[1].eq_ignore_ascii_case(realm);
    if !srealm.eq_ignore_ascii_case(realm) || !is_tgt {
        return Err(bad(format!(
            "the answer is {} from realm {srealm}, not krbtgt/{realm}",
            sname.join("/")
        )));
    }
    let cname: Vec<String> = rep.0.cname.0.name_string.0 .0.iter().map(text).collect();
    if cname.len() != 1 || !cname[0].eq_ignore_ascii_case(user) {
        return Err(bad(format!(
            "the answer is for {}, not {user}",
            cname.join("/")
        )));
    }
    let session_key = part.key.0.key_value.0 .0.clone();
    let key_type = int(&part.key.0.key_type.0);
    if key_type != i64::from(AES256) || session_key.len() != 32 {
        return Err(KrbFailure::new(
            no_aes(),
            format!("TGT session key of etype {key_type}"),
        ));
    }
    let ticket_der =
        picky_asn1_der::to_vec(&rep.0.ticket.0).map_err(|e| bad(format!("ticket: {e}")))?;
    let auth_time = unix_of(&part.auth_time.0);
    let start_time = part
        .start_time
        .0
        .as_ref()
        .map(|t| unix_of(&t.0))
        .unwrap_or(auth_time);
    let end_time = unix_of(&part.end_time.0);
    let renew_till = part
        .renew_till
        .0
        .as_ref()
        .map(|t| unix_of(&t.0))
        .unwrap_or(0);
    let client = rep
        .0
        .cname
        .0
        .name_string
        .0
         .0
        .first()
        .map(text)
        .unwrap_or_else(|| user.to_string());
    let crealm = text(&rep.0.crealm.0);
    Ok(Tgt {
        realm: if crealm.is_empty() {
            realm.to_string()
        } else {
            crealm
        },
        user: if client.is_empty() {
            user.to_string()
        } else {
            client
        },
        ticket_der,
        session_key,
        key_type: AES256.into(),
        auth_time: ccache_time(auth_time),
        start_time: ccache_time(start_time),
        end_time: ccache_time(end_time),
        renew_till: ccache_time(renew_till),
    })
}

// ---- the ticket cache ----------------------------------------------------

/// A TGT as an MIT credential cache, version 4 (the format RustHound-CE's
/// ticket code reads).
fn ccache_bytes(t: &Tgt) -> Vec<u8> {
    fn data(b: &mut Vec<u8>, bytes: &[u8]) {
        b.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        b.extend_from_slice(bytes);
    }
    fn principal(b: &mut Vec<u8>, name_type: u32, realm: &str, parts: &[&str]) {
        b.extend_from_slice(&name_type.to_be_bytes());
        b.extend_from_slice(&(parts.len() as u32).to_be_bytes());
        data(b, realm.as_bytes());
        for p in parts {
            data(b, p.as_bytes());
        }
    }
    let mut b = Vec::new();
    b.extend_from_slice(&0x0504u16.to_be_bytes());
    // Header: one tag, the KDC time offset (none).
    b.extend_from_slice(&12u16.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&8u16.to_be_bytes());
    b.extend_from_slice(&[0u8; 8]);
    let client = [t.user.as_str()];
    principal(&mut b, u32::from(NT_PRINCIPAL), &t.realm, &client);
    // The credential.
    principal(&mut b, u32::from(NT_PRINCIPAL), &t.realm, &client);
    principal(
        &mut b,
        u32::from(NT_SRV_INST),
        &t.realm,
        &["krbtgt", t.realm.as_str()],
    );
    b.extend_from_slice(&t.key_type.to_be_bytes());
    data(&mut b, &t.session_key);
    for time in [t.auth_time, t.start_time, t.end_time, t.renew_till] {
        b.extend_from_slice(&time.to_be_bytes());
    }
    b.push(0); // is_skey
    b.extend_from_slice(&0x50e1_0000u32.to_be_bytes()); // forwardable, proxiable, renewable, initial, pre-authent
    b.extend_from_slice(&0u32.to_be_bytes()); // addresses
    b.extend_from_slice(&0u32.to_be_bytes()); // authdata
    data(&mut b, &t.ticket_der);
    data(&mut b, &[]); // second ticket
    b
}

/// A TGT in a ticket cache file, in a folder private to this account (a
/// protected DACL on Windows, mode 700/600 elsewhere), deleted (overwritten
/// first) when dropped.
pub(crate) struct TicketCache {
    dir: PathBuf,
    file: PathBuf,
    len: usize,
}

impl TicketCache {
    /// Writes `tgt` to a new private folder in Pathwarden's own private
    /// folder in the system's temp folder (`pathwarden-krb`), where caches a
    /// killed run left are swept. If that folder can't be made, isn't
    /// private, or can't be written to, straight in the temp folder, with
    /// no sweep.
    pub(crate) fn write(tgt: &Tgt) -> std::io::Result<Self> {
        let temp = std::env::temp_dir();
        let home = temp.join("pathwarden-krb");
        if !home.exists() {
            let _ = pathwarden_core::perms::create_private_dir(&home);
        }
        if pathwarden_core::perms::is_private_dir(&home) {
            if let Ok(cache) = Self::write_in(&home, tgt) {
                sweep_stale(&home, &cache.dir, STALE_AFTER);
                return Ok(cache);
            }
        }
        Self::write_in(&temp, tgt)
    }

    pub(crate) fn write_in(parent: &Path, tgt: &Tgt) -> std::io::Result<Self> {
        let mut last = None;
        for _ in 0..8 {
            let mut tag = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tag);
            let name: String = tag.iter().map(|b| format!("{b:02x}")).collect();
            let dir = parent.join(format!("pathwarden-krb-{name}"));
            match pathwarden_core::perms::create_private_dir(&dir) {
                Ok(()) => {
                    let file = dir.join("tgt.ccache");
                    let mut bytes = ccache_bytes(tgt);
                    let written = write_new_private(&file, &bytes);
                    let len = bytes.len();
                    bytes.zeroize();
                    if let Err(e) = written {
                        let _ = std::fs::remove_file(&file);
                        let _ = std::fs::remove_dir(&dir);
                        return Err(e);
                    }
                    return Ok(Self { dir, file, len });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no free folder name")))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.file
    }

    /// The `KRB5CCNAME` value for it.
    pub(crate) fn name(&self) -> String {
        format!("FILE:{}", self.file.display())
    }
}

/// Creates `file` (which must not exist) readable by this account only.
fn write_new_private(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(file)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Overwrites `file` in place with zeros (no truncation first, so the same
/// blocks are written over) and flushes it to disk.
fn overwrite(file: &Path, len: usize) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).open(file)?;
    f.write_all(&vec![0u8; len])?;
    f.sync_all()
}

/// How old a leftover ticket cache folder must be before it is swept: past
/// a TGT's lifetime (10 hours by default), so its ticket has expired and no
/// running collection can still use it.
const STALE_AFTER: Duration = Duration::from_secs(12 * 3600);

/// Removes leftover `pathwarden-krb-*` folders (a run that was killed before
/// it could delete its cache) older than [`STALE_AFTER`] from `parent`,
/// Pathwarden's own private folder (checked again here: anything else is
/// left alone), except `keep`. Nothing is overwritten or followed: only a
/// plain folder (not a link or junction) holding a plain `tgt.ccache` file
/// is deleted, the file first (deleting a link removes the link, not what it
/// points to), then the folder if empty.
fn sweep_stale(parent: &Path, keep: &Path, stale_after: Duration) {
    if !pathwarden_core::perms::is_private_dir(parent) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for e in entries.flatten() {
        let dir = e.path();
        if dir == keep
            || !e
                .file_name()
                .to_string_lossy()
                .starts_with("pathwarden-krb-")
        {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let old = meta
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= stale_after);
        if !old {
            continue;
        }
        let file = dir.join("tgt.ccache");
        if std::fs::symlink_metadata(&file).is_ok_and(|m| m.is_file()) {
            let _ = std::fs::remove_file(&file);
        }
        // Only an empty folder goes: anything else in it isn't ours.
        let _ = std::fs::remove_dir(&dir);
    }
}

impl Drop for TicketCache {
    fn drop(&mut self) {
        // Overwritten in place before it goes, so the ticket isn't left on
        // disk.
        let _ = overwrite(&self.file, self.len);
        let _ = std::fs::remove_file(&self.file);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// `KRB5CCNAME` pointed at a ticket cache while this lives; the previous
/// value back afterwards. RustHound-CE's modules read it with `--kerberos`
/// (one built-in collection at a time per process, `super::BUSY`).
pub(crate) struct CcacheEnv {
    previous: Option<std::ffi::OsString>,
}

impl CcacheEnv {
    pub(crate) fn set(cache: &TicketCache) -> Self {
        let previous = std::env::var_os("KRB5CCNAME");
        std::env::set_var("KRB5CCNAME", cache.name());
        Self { previous }
    }
}

impl Drop for CcacheEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(v) => std::env::set_var("KRB5CCNAME", v),
            None => std::env::remove_var("KRB5CCNAME"),
        }
    }
}

// ---- computers -----------------------------------------------------------

/// Why a computer gets no service ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoTicket {
    /// The domain has no Kerberos name (SPN) for it: skipped.
    NoName(String),
    /// It is in another domain, and a trust on the way allows only RC4
    /// (Pathwarden uses AES): skipped. The detail names the trust.
    Rc4Trust(String),
    /// A KDC on the way couldn't be reached, or didn't answer: not read
    /// (after a few, the rest of its realm is skipped, see
    /// `super::hostauth::precheck`).
    Unreachable(String),
    /// Another refusal (a policy, a bad reply): not read.
    Refused(String),
}

impl NoTicket {
    /// The reason in words, without the computer's name.
    pub(crate) fn words(&self) -> String {
        match self {
            NoTicket::NoName(d) => format!("{} ({d})", super::hosts::SKIP_NO_KERBEROS_NAME),
            NoTicket::Rc4Trust(d) => format!(
                "{} ({d}; set the trust to use AES)",
                super::hosts::SKIP_RC4_TRUST
            ),
            NoTicket::Unreachable(d) | NoTicket::Refused(d) => d.clone(),
        }
    }

    /// The reason recorded for `host`: "HOST: skipped: ..." for a skip.
    pub(crate) fn reason(&self, host: &str) -> String {
        match self {
            NoTicket::Unreachable(d) | NoTicket::Refused(d) => format!("{host}: {d}"),
            _ => format!("{host}: skipped: {}", self.words()),
        }
    }
}

/// What the KDC (through RustHound-CE's ticket code) said about
/// `cifs/<host>`: a "KDC error 7" is no Kerberos name for it.
pub(crate) fn no_ticket(host: &str, error: &str) -> NoTicket {
    let code = error
        .rsplit("KDC error ")
        .next()
        .filter(|_| error.contains("KDC error "))
        .and_then(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .ok()
        });
    match code {
        Some(KDC_ERR_S_PRINCIPAL_UNKNOWN) => NoTicket::NoName(format!("no SPN cifs/{host}")),
        Some(code) => NoTicket::Refused(format!(
            "Kerberos refused a ticket for cifs/{host}: {} ({} {code})",
            plain_words(code),
            error_name(code)
        )),
        None => NoTicket::Refused(format!("Kerberos: {error}")),
    }
}

/// What a KDC error means for a computer's ticket, in plain words.
fn plain_words(code: u32) -> &'static str {
    match code {
        KDC_ERR_POLICY => "a domain policy doesn't allow it",
        KDC_ERR_ETYPE_NOSUPP => "no AES key for it",
        KDC_ERR_CLIENT_REVOKED => "the account is disabled or locked out",
        KRB_AP_ERR_TKT_EXPIRED => "the Kerberos ticket has expired",
        KRB_AP_ERR_SKEW => "a clock is more than 5 minutes off",
        KDC_ERR_WRONG_REALM => "it was asked of the wrong domain",
        _ => "the domain controller said no",
    }
}

/// The `cifs/<host>` ticket material (the SPNEGO AP-REQ and the SMB
/// session key) from `kdc` with the TGT in `ccache`, through Pathwarden's
/// own TGS exchange ([`super::krbref`]), not RustHound-CE's: every reply's
/// nonce, encrypted service name, realm and key type are checked, and a
/// referral to another realm is followed. RustHound-CE's ticket code checks
/// neither the nonce nor the encrypted service name, and takes a referral
/// for the service ticket.
pub(crate) async fn service_ticket(
    ccache: &str,
    host: &str,
    kdc: &str,
) -> Result<(Vec<u8>, [u8; 16]), NoTicket> {
    let m = tokio::time::timeout(
        KDC_TIMEOUT * (super::krbref::MAX_HOPS as u32 + 1),
        super::krbref::service_ticket(ccache, host, kdc, &super::krbref::kdc_by_dns),
    )
    .await
    .unwrap_or_else(|_| {
        Err(NoTicket::Unreachable(format!(
            "Kerberos: no answer for cifs/{host} from {} or its domain's KDC within {}s",
            with_port(kdc),
            (KDC_TIMEOUT * (super::krbref::MAX_HOPS as u32 + 1)).as_secs()
        )))
    })?;
    // Belt and braces: the AP-REQ carries the ticket for this computer.
    check_ticket(&m.0, host)?;
    Ok(m)
}

/// The service name of the ticket in a SPNEGO token carrying a Kerberos
/// AP-REQ (RustHound-CE's `gss::spnego_krb5_init`: the AP-REQ, tag
/// `[APPLICATION 14]`, is the token's last element).
fn ticket_sname(blob: &[u8]) -> Option<Vec<String>> {
    blob.iter()
        .enumerate()
        .filter(|(_, b)| **b == 0x6e)
        .find_map(|(i, _)| picky_asn1_der::from_bytes::<ApReq>(&blob[i..]).ok())
        .map(|ap| {
            let ticket = &ap.0.ticket.0 .0;
            ticket.sname.0.name_string.0 .0.iter().map(text).collect()
        })
}

/// [`check_ticket`], for the referral code's tests.
#[cfg(test)]
pub(crate) fn check_ticket_pub(blob: &[u8], host: &str) -> Result<(), NoTicket> {
    check_ticket(blob, host)
}

/// Refuses an AP-REQ whose ticket isn't for `cifs/<host>` (any case).
fn check_ticket(blob: &[u8], host: &str) -> Result<(), NoTicket> {
    match ticket_sname(blob) {
        Some(sname)
            if sname.len() == 2
                && sname[0].eq_ignore_ascii_case("cifs")
                && sname[1].eq_ignore_ascii_case(host) =>
        {
            Ok(())
        }
        Some(sname) => Err(NoTicket::Refused(format!(
            "Kerberos: the domain controller's ticket is for {}, not cifs/{host}",
            sname.join("/")
        ))),
        None => Err(NoTicket::Refused(format!(
            "Kerberos: no ticket could be read for cifs/{host}"
        ))),
    }
}

/// A TGT with a well-formed (made-up) ticket, and KDC errors, for tests of
/// what uses them.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use picky_asn1::wrapper::{ExplicitContextTag12, ExplicitContextTag6, ExplicitContextTag9};
    use picky_krb::data_types::{Ticket, TicketInner};
    use picky_krb::messages::KrbErrorInner;

    pub(crate) fn tgt() -> Tgt {
        let ticket = Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            realm: ExplicitContextTag1::from(krb_string("CONTOSO.LOCAL").unwrap()),
            sname: ExplicitContextTag2::from(
                principal(NT_SRV_INST, &["krbtgt", "CONTOSO.LOCAL"]).unwrap(),
            ),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![7u8; 48])),
            }),
        });
        let now = now_unix();
        Tgt {
            realm: "CONTOSO.LOCAL".into(),
            user: "svc-pathwarden".into(),
            ticket_der: picky_asn1_der::to_vec(&ticket).unwrap(),
            session_key: vec![9u8; 32],
            key_type: 18,
            auth_time: ccache_time(now),
            start_time: ccache_time(now),
            end_time: ccache_time(now + 36_000),
            renew_till: ccache_time(now + 604_800),
        }
    }

    /// Another run's TGT: another ticket and session key, the same client.
    pub(crate) fn other_tgt() -> Tgt {
        let mut t = tgt();
        let mut ticket: Ticket = picky_asn1_der::from_bytes(&t.ticket_der).unwrap();
        ticket.0.enc_part.0.cipher = ExplicitContextTag2::from(OctetStringAsn1(vec![8u8; 48]));
        t.ticket_der = picky_asn1_der::to_vec(&ticket).unwrap();
        t.session_key = vec![5u8; 32];
        t
    }

    /// The DER of a well-formed (made-up) TGT ticket.
    pub(crate) fn tgt_ticket_der() -> Vec<u8> {
        tgt().ticket_der.clone()
    }

    /// A SPNEGO token with an AP-REQ whose ticket is for `sname`, as
    /// RustHound-CE builds it.
    pub(crate) fn ap_req_token(sname: &[&str]) -> Vec<u8> {
        use picky_asn1::wrapper::{BitStringAsn1, ExplicitContextTag4};
        use picky_krb::messages::ApReqInner;
        let ticket = Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            realm: ExplicitContextTag1::from(krb_string("CONTOSO.LOCAL").unwrap()),
            sname: ExplicitContextTag2::from(principal(NT_SRV_INST, sname).unwrap()),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![7u8; 48])),
            }),
        });
        let ap = ApReq::from(ApReqInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![14])),
            ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(
                vec![0, 0, 0, 0],
            ))),
            ticket: ExplicitContextTag3::from(ticket),
            authenticator: ExplicitContextTag4::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![3u8; 64])),
            }),
        });
        rusthound_ce::transport::gss::spnego_krb5_init(&picky_asn1_der::to_vec(&ap).unwrap())
    }

    /// A KRB-ERROR with `code`, the KDC's time `stime`.
    pub(crate) fn error(code: u32, stime: i64, e_data: Option<Vec<u8>>) -> Vec<u8> {
        let e = KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(kerberos_time(stime)),
            susec: ExplicitContextTag5::from(IntegerAsn1(vec![0])),
            error_code: ExplicitContextTag6::from(code),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(krb_string("CONTOSO.LOCAL").unwrap()),
            sname: picky_asn1::wrapper::ExplicitContextTag10::from(
                principal(NT_SRV_INST, &["krbtgt", "CONTOSO.LOCAL"]).unwrap(),
            ),
            e_text: Optional::from(None),
            e_data: Optional::from(e_data.map(|d| ExplicitContextTag12::from(OctetStringAsn1(d)))),
        });
        picky_asn1_der::to_vec(&e).unwrap()
    }

    /// An AS-REP as a KDC builds it: its encrypted part (key usage 3) under
    /// `key`, with `etype`, holding a session key of `key_type` (bytes of
    /// 5) and `nonce`, for `crealm`, issued by it.
    pub(crate) fn as_rep_for(
        key: &[u8],
        etype: u8,
        key_type: u8,
        nonce: &[u8],
        crealm: &str,
    ) -> AsRep {
        let srealm = crealm.to_ascii_uppercase();
        as_rep_full(
            key,
            (etype, key_type),
            nonce,
            crealm,
            &srealm,
            &["krbtgt", &srealm],
        )
    }

    /// [`as_rep_for`], its encrypted part naming `srealm` and `sname`.
    pub(crate) fn as_rep_full(
        key: &[u8],
        (etype, key_type): (u8, u8),
        nonce: &[u8],
        crealm: &str,
        srealm: &str,
        sname: &[&str],
    ) -> AsRep {
        use picky_asn1::wrapper::ExplicitContextTag10;
        use picky_krb::data_types::{EncryptionKey, LastReqInner};
        use picky_krb::messages::{EncKdcRepPart, KdcRep};
        let now = now_unix();
        let part = EncAsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1(vec![key_type])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1(vec![
                    5u8;
                    if key_type == AES256 {
                        32
                    } else {
                        16
                    }
                ])),
            }),
            last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![LastReqInner {
                lr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
                lr_value: ExplicitContextTag1::from(kerberos_time(now)),
            }])),
            nonce: ExplicitContextTag2::from(IntegerAsn1(nonce.to_vec())),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(BitStringAsn1::from(BitString::with_bytes(vec![
                0x50, 0xe1, 0, 0,
            ]))),
            auth_time: ExplicitContextTag5::from(kerberos_time(now)),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(kerberos_time(now + 36_000)),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(krb_string(srealm).unwrap()),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, sname).unwrap()),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let plain = picky_asn1_der::to_vec(&part).unwrap();
        let cipher = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(key, AS_REP_ENC, &plain)
            .unwrap();
        let ticket: Ticket = picky_asn1_der::from_bytes(&tgt_ticket_der()).unwrap();
        AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![11])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(krb_string(crealm).unwrap()),
            cname: ExplicitContextTag4::from(principal(NT_PRINCIPAL, &["svc"]).unwrap()),
            ticket: ExplicitContextTag5::from(ticket),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
            }),
        })
    }

    /// A KDC's AS-REP to an account `svc` of `realm` with `password` that
    /// doesn't require pre-auth, answering `nonce`: AES256, its session
    /// key 32 bytes of 5.
    pub(crate) fn as_rep_reply(password: &str, realm: &str, nonce: &[u8]) -> Vec<u8> {
        let realm = realm.to_ascii_uppercase();
        let key = string_to_key(&Secret::new(password), &format!("{realm}svc")).unwrap();
        picky_asn1_der::to_vec(&as_rep_for(&key, AES256, AES256, nonce, &realm)).unwrap()
    }

    /// A KDC's answer to an AS-REQ (`req`) for `svc` with `password`, which
    /// requires pre-auth: without PA-ENC-TIMESTAMP, KDC_ERR_PREAUTH_REQUIRED
    /// with the AES256 salt; with one that opens with the password's key
    /// and is within 5 minutes, the TGT ([`as_rep_reply`]); else
    /// KDC_ERR_PREAUTH_FAILED. `None` if it isn't an AS-REQ.
    pub(crate) fn preauth_answer(req: &[u8], password: &str) -> Option<Vec<u8>> {
        let req: AsReq = picky_asn1_der::from_bytes(req).ok()?;
        let realm = text(&req.0.req_body.0.realm.0).to_ascii_uppercase();
        let nonce = req.0.req_body.0.nonce.0 .0.clone();
        let salt = format!("{realm}svc");
        let stamp = req.0.padata.0.as_ref().and_then(|p| {
            p.0 .0
                .iter()
                .find(|p| int(&p.padata_type.0) == i64::from(PA_ENC_TIMESTAMP))
                .cloned()
        });
        let Some(stamp) = stamp else {
            let info = picky_krb::data_types::EtypeInfo2Entry {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                salt: Optional::from(Some(ExplicitContextTag1::from(krb_string(&salt).unwrap()))),
                s2kparams: Optional::from(None),
            };
            let info = picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![info])).unwrap();
            let method =
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![padata(PA_ETYPE_INFO2, info)]))
                    .unwrap();
            return Some(error(KDC_ERR_PREAUTH_REQUIRED, now_unix(), Some(method)));
        };
        let key = string_to_key(&Secret::new(password), &salt).unwrap();
        let opened = picky_asn1_der::from_bytes::<EncryptedData>(&stamp.padata_data.0 .0)
            .ok()
            .and_then(|enc| {
                CipherSuite::Aes256CtsHmacSha196
                    .cipher()
                    .decrypt(&key, AS_REQ_TIMESTAMP, &enc.cipher.0 .0)
                    .ok()
            })
            .and_then(|plain| picky_asn1_der::from_bytes::<PaEncTsEnc>(&plain).ok())
            .filter(|ts| (unix_of(&ts.patimestamp.0) - now_unix()).abs() < 300);
        Some(match opened {
            Some(_) => as_rep_reply(password, &realm, &nonce),
            None => error(KDC_ERR_PREAUTH_FAILED, now_unix(), None),
        })
    }

    /// A fake KDC on 127.0.0.1 answering every request with `reply`;
    /// returns its address. Counts the requests it got.
    pub(crate) async fn kdc(
        reply: Vec<u8>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).await.is_err() {
                    continue;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                if s.read_exact(&mut req).await.is_err() {
                    continue;
                }
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = s.write_all(&(reply.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&reply).await;
            }
        });
        (addr, asked)
    }
}

#[cfg(test)]
#[path = "krb_tests.rs"]
mod tests;
