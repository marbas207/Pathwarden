//! Pathwarden's own TGS exchange for `cifs/<host>`: every service
//! ticket Pathwarden itself uses (the before-contact check, SYSVOL, the
//! CAs' registry, Remote Registry sessions) comes from here.
//!
//! RustHound-CE's ticket code sends one TGS-REQ and takes whatever comes
//! back: it checks neither the reply's nonce nor the service named in its
//! encrypted part, and for a computer in another realm it hands the KDC's
//! referral (a TGT for `krbtgt/<OTHER REALM>`) to the computer as its
//! service ticket (the lab's forest root CA, read from a child domain,
//! answered SESSION_SETUP with STATUS_MORE_PROCESSING_REQUIRED). Here,
//! starting from the TGT in the ticket cache: ask the home KDC (the
//! verified DC) for `cifs/<host>`; follow each referral to the next realm's
//! KDC, reached by the realm's DNS name (the domain's name, which resolves
//! to its domain controllers; Windows would look up the
//! `_kerberos._tcp.dc._msdcs` SRV record instead, so a realm whose name
//! doesn't resolve to a DC fails with a plain reason); check every reply's
//! nonce, the service and realm its encrypted part names, and AES256; and
//! build the AP-REQ and SMB session key as RustHound-CE would.

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, GeneralStringAsn1, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::{
    AP_REQ_AUTHENTICATOR, TGS_REP_ENC_SESSION_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, TGS_REQ_MSG_TYPE};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, Checksum, EncryptedData, EncryptionKey, PaData,
    PrincipalName, Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcReq, KdcReqBody, KrbError,
    TgsRep, TgsReq,
};
use zeroize::Zeroize;

use super::krb::{self, NoTicket};

/// Most referrals followed for one computer.
pub(crate) const MAX_HOPS: usize = 4;
/// Most principal parts, addresses or authorization entries read from the
/// ticket cache (Pathwarden writes 1 or 2 parts and none of the others).
const MAX_COUNT: usize = 16;
const AES256: u8 = 18;
const PA_TGS_REQ: u8 = 1;

/// The TGT read back from Pathwarden's ticket cache.
pub(crate) struct CachedTgt {
    pub user: String,
    pub realm: String,
    pub ticket: Ticket,
    pub key: Vec<u8>,
}

impl Drop for CachedTgt {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Reads the TGT back from a ticket cache Pathwarden wrote
/// ([`super::krb::TicketCache`]: MIT ccache v4, one credential).
pub(crate) fn read_cache(ccache: &str) -> Result<CachedTgt, String> {
    let path = ccache.strip_prefix("FILE:").unwrap_or(ccache);
    let mut bytes = std::fs::read(path).map_err(|e| format!("the ticket cache: {e}"))?;
    let parsed = parse_cache(&bytes);
    bytes.zeroize();
    parsed
}

fn parse_cache(b: &[u8]) -> Result<CachedTgt, String> {
    struct R<'a>(&'a [u8], usize);
    impl R<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8], String> {
            let s = self
                .0
                .get(self.1..self.1 + n)
                .ok_or_else(|| "the ticket cache is cut short".to_string())?;
            self.1 += n;
            Ok(s)
        }
        fn u16(&mut self) -> Result<u16, String> {
            Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
        }
        fn u32(&mut self) -> Result<u32, String> {
            Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
        }
        fn data(&mut self) -> Result<Vec<u8>, String> {
            let n = self.u32()? as usize;
            Ok(self.take(n)?.to_vec())
        }
        fn principal(&mut self) -> Result<(String, Vec<String>), String> {
            let _type = self.u32()?;
            let n = self.u32()? as usize;
            if n > MAX_COUNT {
                return Err("the ticket cache names a principal of too many parts".into());
            }
            let realm = String::from_utf8_lossy(&self.data()?).into_owned();
            let mut parts = Vec::with_capacity(n);
            for _ in 0..n {
                parts.push(String::from_utf8_lossy(&self.data()?).into_owned());
            }
            Ok((realm, parts))
        }
    }
    let mut r = R(b, 0);
    if r.u16()? != 0x0504 {
        return Err("not a version 4 ticket cache".into());
    }
    let header = r.u16()? as usize;
    r.take(header)?;
    let _default = r.principal()?;
    let (realm, client) = r.principal()?;
    let (_, server) = r.principal()?;
    if server.first().map(String::as_str) != Some("krbtgt") {
        return Err("the ticket cache holds no TGT".into());
    }
    let _keytype = r.u16()?;
    let key = r.data()?;
    r.take(16 + 1 + 4)?;
    let addresses = r.u32()? as usize;
    let authdata_cap = |n: usize| {
        (n <= MAX_COUNT)
            .then_some(n)
            .ok_or_else(|| "the ticket cache lists too many entries".to_string())
    };
    for _ in 0..authdata_cap(addresses)? {
        r.u16()?;
        r.data()?;
    }
    let authdata = r.u32()? as usize;
    for _ in 0..authdata_cap(authdata)? {
        r.u16()?;
        r.data()?;
    }
    let ticket_der = r.data()?;
    let ticket = picky_asn1_der::from_bytes(&ticket_der).map_err(|e| format!("the TGT: {e}"))?;
    Ok(CachedTgt {
        user: client.first().cloned().unwrap_or_default(),
        realm,
        ticket,
        key,
    })
}

fn principal(name_type: u8, parts: &[&str]) -> Result<PrincipalName, NoTicket> {
    let strings = parts
        .iter()
        .map(|p| {
            picky_asn1::restricted_string::Ia5String::from_string(p.to_string())
                .map(picky_asn1::wrapper::GeneralStringAsn1::from)
                .map_err(|_| NoTicket::Refused(format!("Kerberos: {p:?} can't be a Kerberos name")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
    })
}

fn realm_string(s: &str) -> Result<picky_asn1::wrapper::GeneralStringAsn1, NoTicket> {
    picky_asn1::restricted_string::Ia5String::from_string(s.to_string())
        .map(picky_asn1::wrapper::GeneralStringAsn1::from)
        .map_err(|_| NoTicket::Refused(format!("Kerberos: {s:?} can't be a realm")))
}

pub(crate) fn text(s: &picky_asn1::wrapper::GeneralStringAsn1) -> String {
    String::from_utf8_lossy(s.0.as_bytes()).into_owned()
}

pub(crate) fn int(i: &IntegerAsn1) -> i64 {
    let mut v: i64 = if i.0.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for b in i.0.iter().take(8) {
        v = (v << 8) | i64::from(*b);
    }
    v
}

fn encrypt(key: &[u8], usage: i32, plain: &[u8]) -> Result<EncryptedData, NoTicket> {
    if key.len() != 32 {
        return Err(NoTicket::Refused(
            "Kerberos: a ticket's session key isn't AES256".into(),
        ));
    }
    let cipher = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(key, usage, plain)
        .map_err(|e| NoTicket::Refused(format!("Kerberos: {e}")))?;
    Ok(EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
    })
}

fn der<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, NoTicket> {
    picky_asn1_der::to_vec(v).map_err(|e| NoTicket::Refused(format!("Kerberos: {e}")))
}

fn authenticator(
    tgt: &CachedTgt,
    cksum: Option<Checksum>,
    subkey: Option<EncryptionKey>,
) -> Result<Vec<u8>, NoTicket> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    der(&Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(realm_string(&tgt.realm)?),
        cname: ExplicitContextTag2::from(principal(NT_PRINCIPAL, &[tgt.user.as_str()])?),
        cksum: Optional::from(cksum.map(ExplicitContextTag3::from)),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(krb::kerberos_time_pub(now)),
        subkey: Optional::from(subkey.map(ExplicitContextTag6::from)),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    }))
}

fn ap_req(ticket: &Ticket, auth: EncryptedData) -> Result<Vec<u8>, NoTicket> {
    der(&ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0, 0, 0, 0,
        ]))),
        ticket: ExplicitContextTag3::from(ticket.clone()),
        authenticator: ExplicitContextTag4::from(auth),
    }))
}

/// A ticket and its session key from one TGS exchange, and the service it
/// names; with the reply's decrypted part and client, for the KDC relay
/// ([`super::krbrelay`]) to pass on.
pub(crate) struct Got {
    pub ticket: Ticket,
    pub key: Vec<u8>,
    pub sname: Vec<String>,
    key_type: i64,
    pub part: EncKdcRepPart,
    pub crealm: GeneralStringAsn1,
    pub cname: PrincipalName,
}

impl Drop for Got {
    fn drop(&mut self) {
        self.key.zeroize();
        self.part.key.0.key_value.0 .0.zeroize();
    }
}

impl Got {
    /// Whether it is the ticket for `cifs/<host>` (any case).
    pub(crate) fn is_for(&self, host: &str) -> bool {
        self.sname.len() == 2
            && self.sname[0].eq_ignore_ascii_case("cifs")
            && self.sname[1].eq_ignore_ascii_case(host)
    }

    /// The realm it refers to, if it is a referral (`krbtgt/<REALM>`).
    pub(crate) fn referral(&self) -> Option<String> {
        (self.sname.len() == 2 && self.sname[0].eq_ignore_ascii_case("krbtgt"))
            .then(|| self.sname[1].to_ascii_uppercase())
    }
}

/// The TGS-REQ for `cifs/<host>` in `realm`, presenting `ticket` (with its
/// session key `key`) as `tgt`'s client, and its nonce.
pub(crate) fn tgs_req(
    realm: &str,
    host: &str,
    tgt: &CachedTgt,
    ticket: &Ticket,
    key: &[u8],
) -> Result<(Vec<u8>, IntegerAsn1), NoTicket> {
    let auth = encrypt(
        key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &authenticator(tgt, None, None)?,
    )?;
    let ap = ap_req(ticket, auth)?;
    let mut nonce = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce[0] &= 0x7f;
    let nonce = IntegerAsn1(nonce.to_vec());
    let far = krb::kerberos_time_pub(2_136_422_885);
    let req = TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![PA_TGS_REQ])),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1(ap)),
            },
        ])))),
        req_body: ExplicitContextTag4::from(KdcReqBody {
            // forwardable, renewable, canonicalize
            kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(
                vec![0x40, 0x81, 0x00, 0x00],
            ))),
            cname: Optional::from(None),
            realm: ExplicitContextTag2::from(realm_string(realm)?),
            sname: Optional::from(Some(ExplicitContextTag3::from(principal(
                NT_SRV_INST,
                &["cifs", host],
            )?))),
            from: Optional::from(None),
            till: ExplicitContextTag5::from(far),
            rtime: Optional::from(None),
            nonce: ExplicitContextTag7::from(nonce.clone()),
            etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![AES256])])),
            addresses: Optional::from(None),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    });
    Ok((der(&req)?, nonce))
}

/// One TGS exchange with `kdc` for `cifs/<host>` in `realm`, presenting
/// `ticket` (with its session key `key`) as `tgt`'s client.
async fn tgs(
    kdc: &str,
    realm: &str,
    host: &str,
    tgt: &CachedTgt,
    ticket: &Ticket,
    key: &[u8],
) -> Result<Got, NoTicket> {
    let (req, nonce) = tgs_req(realm, host, tgt, ticket, key)?;
    let reply = krb::exchange_pub(kdc, &req).await?;
    let rep: TgsRep = match picky_asn1_der::from_bytes(&reply) {
        Ok(r) => r,
        Err(_) => {
            return Err(match picky_asn1_der::from_bytes::<KrbError>(&reply) {
                Ok(e) => refused_by(&e, kdc, realm, host, &tgt.realm),
                Err(e) => NoTicket::Refused(format!("Kerberos: {kdc} answered no ticket: {e}")),
            });
        }
    };
    check_rep(&rep, realm, host, key, TGS_REP_ENC_SESSION_KEY, &nonce)
}

/// What a KRB-ERROR from `kdc` (of `realm`, asked for `cifs/<host>` while
/// signing in from `home`) means.
fn refused_by(e: &KrbError, kdc: &str, realm: &str, host: &str, home: &str) -> NoTicket {
    let code = e.0.error_code.0;
    log::debug!(
        "[krb] cifs/{host}: {kdc} (realm {realm}) answered {} ({code})",
        krb::error_name(code)
    );
    if code == KDC_ERR_ETYPE_NOSUPP {
        no_aes(host, realm, home)
    } else {
        krb::no_ticket(host, &format!("KDC error {code}"))
    }
}

/// Checks a TGS-REP from `realm`'s KDC to a request for `cifs/<host>` with
/// `nonce`: its encrypted part opens with `key` (key usage `usage`: 8 for
/// the TGT's session key, 9 for an authenticator's subkey) and is AES256;
/// it answers this request (the nonce); the ticket is issued by `realm`
/// and names the same service as the encrypted part; and its session key is
/// AES256. The service it names (the computer, or a referral) is the
/// caller's to check.
pub(crate) fn check_rep(
    rep: &TgsRep,
    realm: &str,
    host: &str,
    key: &[u8],
    usage: i32,
    nonce: &IntegerAsn1,
) -> Result<Got, NoTicket> {
    let enc = &rep.0.enc_part.0;
    if int(&enc.etype.0) != i64::from(AES256) || key.len() != 32 {
        return Err(NoTicket::Refused(format!(
            "Kerberos: a ticket for cifs/{host} encrypted with etype {}",
            int(&enc.etype.0)
        )));
    }
    let mut plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(key, usage, &enc.cipher.0 .0)
        .map_err(|e| NoTicket::Refused(format!("Kerberos: the ticket for cifs/{host}: {e}")))?;
    let part = picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain)
        .map(|p| p.0)
        .or_else(|_| picky_asn1_der::from_bytes::<EncAsRepPart>(&plain).map(|p| p.0));
    plain.zeroize();
    let part = part.map_err(|e| NoTicket::Refused(format!("Kerberos: {e}")))?;
    if int(&part.nonce.0) != int(nonce) {
        return Err(NoTicket::Refused(format!(
            "Kerberos: the answer for cifs/{host} isn't for this request (nonce)"
        )));
    }
    // The ticket is issued by the realm asked (a referral's too: a TGT for
    // the next realm, issued by this one).
    let srealm = text(&part.srealm.0);
    if !srealm.eq_ignore_ascii_case(realm) {
        return Err(NoTicket::Refused(format!(
            "Kerberos: the answer for cifs/{host} comes from realm {srealm}, not {realm}"
        )));
    }
    let sname: Vec<String> = part.sname.0.name_string.0 .0.iter().map(text).collect();
    let ticket_sname: Vec<String> = rep
        .0
        .ticket
        .0
         .0
        .sname
        .0
        .name_string
        .0
         .0
        .iter()
        .map(text)
        .collect();
    if !same(&sname, &ticket_sname) {
        return Err(NoTicket::Refused(format!(
            "Kerberos: the answer for cifs/{host} names two services"
        )));
    }
    // The new session key: AES256, as asked.
    let key_type = int(&part.key.0.key_type.0);
    if key_type != i64::from(AES256) || part.key.0.key_value.0 .0.len() != 32 {
        return Err(NoTicket::Refused(format!(
            "Kerberos: the session key for cifs/{host} is etype {key_type}, not AES256"
        )));
    }
    Ok(Got {
        ticket: rep.0.ticket.0.clone(),
        key: part.key.0.key_value.0 .0.clone(),
        key_type,
        sname,
        crealm: rep.0.crealm.0.clone(),
        cname: rep.0.cname.0.clone(),
        part,
    })
}

/// KDC_ERR_ETYPE_NOSUPP.
const KDC_ERR_ETYPE_NOSUPP: u32 = 14;

/// Why a KDC (of `realm`, asked while signing in from `home`) couldn't give
/// an AES256 ticket for `host`, in plain words. Pathwarden asks for AES256
/// only. For a computer in another domain the usual cause is the trust
/// between the two, which allows only RC4 (its
/// msDS-SupportedEncryptionTypes is not set): the KDC can't make the
/// referral's session key AES. Otherwise the computer has no AES keys.
fn no_aes(host: &str, realm: &str, home: &str) -> NoTicket {
    // The KDC that said no is the one asked (`realm`). Only one outside the
    // computer's own domain was issuing a referral, over a trust.
    let host_domain = host.split_once('.').map(|(_, d)| d).unwrap_or_default();
    if !host_domain.is_empty() && !host_domain.eq_ignore_ascii_case(realm) {
        log::debug!(
            "[krb] cifs/{host}: {realm} can't issue an AES referral toward {host_domain} \
             (signed in from {home})"
        );
        NoTicket::Rc4Trust(format!(
            "between {} and {}",
            realm.to_ascii_lowercase(),
            host_domain.to_ascii_lowercase()
        ))
    } else {
        NoTicket::Refused(format!(
            "Kerberos: {host} has no AES256 Kerberos keys, and Pathwarden uses AES256"
        ))
    }
}

fn same(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// The AP-REQ for SMB (SPNEGO-wrapped) and its 16-byte session key (a fresh
/// AES128 subkey), as RustHound-CE's `build_ap_req_gss` builds them.
fn smb_ap_req(tgt: &CachedTgt, got: &Got) -> Result<(Vec<u8>, [u8; 16]), NoTicket> {
    let mut subkey = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);
    let mut gss = Vec::with_capacity(24);
    gss.extend_from_slice(&16u32.to_le_bytes());
    gss.extend_from_slice(&[0u8; 16]);
    gss.extend_from_slice(&0x0000_003cu32.to_le_bytes());
    let auth = authenticator(
        tgt,
        Some(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80, 0x03])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1(gss)),
        }),
        Some(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![17])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1(subkey.to_vec())),
        }),
    )?;
    let auth = encrypt(&got.key, AP_REQ_AUTHENTICATOR, &auth)?;
    let ap = ap_req(&got.ticket, auth)?;
    Ok((rusthound_ce::transport::gss::spnego_krb5_init(&ap), subkey))
}

/// `cifs/<host>`'s ticket, following referrals from `home_kdc` (the
/// collected domain's verified DC) through each realm's KDC (`kdc_for`).
pub(crate) async fn service_ticket(
    ccache: &str,
    host: &str,
    home_kdc: &str,
    kdc_for: &(dyn Fn(&str) -> String + Sync),
) -> Result<(Vec<u8>, [u8; 16]), NoTicket> {
    let tgt = read_cache(ccache).map_err(|e| NoTicket::Refused(format!("Kerberos: {e}")))?;
    let start = Hop {
        kdc: home_kdc.to_string(),
        realm: tgt.realm.clone(),
        ticket: tgt.ticket.clone(),
        key: tgt.key.clone(),
    };
    let got = follow(&tgt, host, start, vec![tgt.realm.clone()], kdc_for).await?;
    smb_ap_req(&tgt, &got)
}

/// Where the next TGS exchange goes: `kdc`, of `realm`, presenting
/// `ticket` with its session key `key`.
pub(crate) struct Hop {
    pub kdc: String,
    pub realm: String,
    pub ticket: Ticket,
    pub key: Vec<u8>,
}

impl Drop for Hop {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// `cifs/<host>`'s ticket, from `start` on, following each referral to the
/// next realm's KDC (`kdc_for`), at most [`MAX_HOPS`] exchanges, never back
/// to a realm on `path` (the realms already asked). Every reply is checked
/// ([`check_rep`]).
pub(crate) async fn follow(
    tgt: &CachedTgt,
    host: &str,
    start: Hop,
    mut path: Vec<String>,
    kdc_for: &(dyn Fn(&str) -> String + Sync),
) -> Result<Got, NoTicket> {
    let mut hop = start;
    for _ in 0..MAX_HOPS {
        log::debug!(
            "[krb] cifs/{host}: asking {} (realm {})",
            hop.kdc,
            hop.realm
        );
        let got = tgs(&hop.kdc, &hop.realm, host, tgt, &hop.ticket, &hop.key).await?;
        log::debug!(
            "[krb] cifs/{host}: {} gave a ticket for {} (ticket etype {}, session key \
             etype {})",
            hop.realm,
            got.sname.join("/"),
            int(&got.ticket.0.enc_part.0.etype.0),
            got.key_type
        );
        if got.is_for(host) {
            return Ok(got);
        }
        if let Some(next) = got.referral() {
            if path.iter().any(|r| r.eq_ignore_ascii_case(&next)) {
                break;
            }
            log::debug!("[krb] cifs/{host}: referral from {} to {next}", hop.realm);
            path.push(next.clone());
            hop = Hop {
                kdc: kdc_for(&next),
                realm: next,
                ticket: got.ticket.clone(),
                key: got.key.clone(),
            };
            continue;
        }
        return Err(NoTicket::Refused(format!(
            "Kerberos: the domain controller's ticket is for {}, not cifs/{host}",
            got.sname.join("/")
        )));
    }
    Err(NoTicket::Refused(format!(
        "Kerberos: no ticket for cifs/{host} through {}",
        path.join(", ")
    )))
}

/// A realm's KDC: its DNS name, which resolves to its domain controllers.
pub(crate) fn kdc_by_dns(realm: &str) -> String {
    realm.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1::wrapper::{ExplicitContextTag10, ExplicitContextTag9};
    use picky_krb::data_types::{LastReqInner, TicketInner};
    use picky_krb::messages::{EncKdcRepPart, KdcRep};
    use std::sync::{Arc, Mutex};

    fn ticket(sname: &[&str], realm: &str) -> Ticket {
        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            realm: ExplicitContextTag1::from(realm_string(realm).unwrap()),
            sname: ExplicitContextTag2::from(principal(NT_SRV_INST, sname).unwrap()),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![7u8; 48])),
            }),
        })
    }

    /// A TGS-REP for `sname` with session key `new_key`, its encrypted part
    /// under `key` with `nonce`.
    fn tgs_rep(
        sname: &[&str],
        key: &[u8],
        new_key: &[u8],
        nonce: Vec<u8>,
        srealm: &str,
    ) -> Vec<u8> {
        let now = 1_900_000_000;
        let part = EncTgsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1(new_key.to_vec())),
            }),
            last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![LastReqInner {
                lr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
                lr_value: ExplicitContextTag1::from(krb::kerberos_time_pub(now)),
            }])),
            nonce: ExplicitContextTag2::from(IntegerAsn1(nonce)),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(BitStringAsn1::from(BitString::with_bytes(vec![
                0x40, 0xa1, 0, 0,
            ]))),
            auth_time: ExplicitContextTag5::from(krb::kerberos_time_pub(now)),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(krb::kerberos_time_pub(now + 3600)),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(realm_string(srealm).unwrap()),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, sname).unwrap()),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let enc = encrypt(key, TGS_REP_ENC_SESSION_KEY, &der(&part).unwrap()).unwrap();
        der(&TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![13])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(realm_string("CONTOSO.LOCAL").unwrap()),
            cname: ExplicitContextTag4::from(principal(NT_PRINCIPAL, &["svc-pathwarden"]).unwrap()),
            ticket: ExplicitContextTag5::from(ticket(sname, "CONTOSO.LOCAL")),
            enc_part: ExplicitContextTag6::from(enc),
        }))
        .unwrap()
    }

    type Answer = Box<dyn Fn(Vec<u8>, String) -> Vec<u8> + Send + Sync>;

    /// A fake KDC answering each TGS-REQ with `answer(nonce, realm asked)`;
    /// the realms it was asked for go in `asked`.
    async fn kdc(answer: Answer, asked: Arc<Mutex<Vec<String>>>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
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
                let req: TgsReq = picky_asn1_der::from_bytes(&req).unwrap();
                let realm = text(&req.0.req_body.0.realm.0);
                asked.lock().unwrap().push(realm.clone());
                let reply = answer(req.0.req_body.0.nonce.0 .0.clone(), realm);
                let _ = s.write_all(&(reply.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&reply).await;
            }
        });
        addr
    }

    /// The forest root's CA from a child domain: the home KDC refers to
    /// FABRIKAM.LOCAL, whose KDC gives the ticket. The AP-REQ is for the CA
    /// host. A wrong nonce, or a referral back where it came from, is
    /// refused.
    #[test]
    fn a_referral_is_followed_to_the_computers_realm() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent = std::env::temp_dir().join(format!("pw-krbref-hop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let host = "CA01.FABRIKAM.LOCAL";
        let run = |second: Answer| {
            let ccache = cache.name();
            rt.block_on(async move {
                let asked = Arc::new(Mutex::new(Vec::new()));
                let home = kdc(
                    Box::new(|nonce, realm| {
                        tgs_rep(
                            &["krbtgt", "FABRIKAM.LOCAL"],
                            &[9u8; 32],
                            &[2u8; 32],
                            nonce,
                            &realm,
                        )
                    }),
                    asked.clone(),
                )
                .await;
                let other = kdc(second, asked.clone()).await;
                let r = service_ticket(&ccache, host, &home, &move |realm: &str| {
                    assert_eq!(realm, "FABRIKAM.LOCAL");
                    other.clone()
                })
                .await;
                let asked = asked.lock().unwrap().clone();
                (r, asked)
            })
        };
        let (r, asked) = run(Box::new(|nonce, realm| {
            tgs_rep(
                &["cifs", "ca01.fabrikam.local"],
                &[2u8; 32],
                &[3u8; 32],
                nonce,
                &realm,
            )
        }));
        let (blob, _key) = r.unwrap();
        assert_eq!(asked, ["CONTOSO.LOCAL", "FABRIKAM.LOCAL"]);
        assert_eq!(krb::check_ticket_pub(&blob, host), Ok(()));

        let (r, _) = run(Box::new(|_, realm| {
            tgs_rep(
                &["cifs", "ca01.fabrikam.local"],
                &[2u8; 32],
                &[3u8; 32],
                vec![1, 2, 3],
                &realm,
            )
        }));
        assert!(matches!(r, Err(NoTicket::Refused(w)) if w.contains("nonce")));

        // A ticket issued by another realm than the one asked.
        let (r, _) = run(Box::new(|nonce, _| {
            tgs_rep(
                &["cifs", "ca01.fabrikam.local"],
                &[2u8; 32],
                &[3u8; 32],
                nonce,
                "EVIL.LOCAL",
            )
        }));
        assert!(matches!(r, Err(NoTicket::Refused(w)) if w.contains("realm EVIL.LOCAL")));

        let (r, _) = run(Box::new(|nonce, realm| {
            tgs_rep(
                &["krbtgt", "CONTOSO.LOCAL"],
                &[2u8; 32],
                &[3u8; 32],
                nonce,
                &realm,
            )
        }));
        assert!(
            matches!(r, Err(NoTicket::Refused(w)) if w.contains("through CONTOSO.LOCAL, FABRIKAM.LOCAL"))
        );

        // The other realm doesn't know the name: no Kerberos name for it.
        let (r, _) = run(Box::new(|_, _| krb::fake::error(7, 0, None)));
        assert!(matches!(r, Err(NoTicket::NoName(_))), "{r:?}");
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// No AES for the referral (a trust that allows only RC4): a plain
    /// reason naming the trust; for a computer of the home domain, its keys.
    #[test]
    fn no_aes_names_the_trust() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent = std::env::temp_dir().join(format!("pw-krbref-aes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let ccache = cache.name();
        let (other, home, there) = rt.block_on(async move {
            let asked = Arc::new(Mutex::new(Vec::new()));
            let no = kdc(
                Box::new(|_, _| krb::fake::error(14, 0, None)),
                asked.clone(),
            )
            .await;
            // The home KDC can't issue the referral: the trust.
            let other = service_ticket(&ccache, "CA01.FABRIKAM.LOCAL", &no, &|r: &str| {
                r.to_string()
            })
            .await;
            // A computer of the home domain: its own keys.
            let home =
                service_ticket(&ccache, "WS01.CONTOSO.LOCAL", &no, &|r: &str| r.to_string()).await;
            // The referral works, the computer's own KDC says no: its keys.
            let referring = kdc(
                Box::new(|nonce, realm| {
                    tgs_rep(
                        &["krbtgt", "FABRIKAM.LOCAL"],
                        &[9u8; 32],
                        &[2u8; 32],
                        nonce,
                        &realm,
                    )
                }),
                asked,
            )
            .await;
            let there = service_ticket(&ccache, "CA01.FABRIKAM.LOCAL", &referring, &move |_| {
                no.clone()
            })
            .await;
            (other, home, there)
        });
        assert_eq!(
            other.as_ref().unwrap_err(),
            &NoTicket::Rc4Trust("between contoso.local and fabrikam.local".into())
        );
        assert!(other.unwrap_err().words().contains(
            "the trust to its domain allows only RC4 (between contoso.local and \
                           fabrikam.local; set the trust to use AES)"
        ),);
        for (r, host) in [(home, "WS01.CONTOSO.LOCAL"), (there, "CA01.FABRIKAM.LOCAL")] {
            assert!(
                matches!(&r, Err(NoTicket::Refused(w))
                    if w.contains(&format!("{host} has no AES256 Kerberos keys"))),
                "{r:?}"
            );
        }
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn the_cache_reads_back() {
        let parent = std::env::temp_dir().join(format!("pw-krbref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let t = read_cache(&cache.name()).unwrap();
        assert_eq!(
            (t.user.as_str(), t.realm.as_str()),
            ("svc-pathwarden", "CONTOSO.LOCAL")
        );
        assert_eq!(t.key, vec![9u8; 32]);
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }
}
