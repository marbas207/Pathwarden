//! The modules' KDC relay against fake KDCs, through RustHound-CE's
//! own ticket code (`kerberos_material_for`, what the modules call).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, EncryptedData, EncryptionKey, LastReqInner, PaData,
    PrincipalName, Ticket, TicketInner,
};
use picky_krb::messages::{
    ApReq, AsReq, EncKdcRepPart, EncTgsRepPart, KdcRep, KrbError, TgsRep, TgsReq,
};

use super::krb;
use super::krbref;
use super::krbrelay::{KdcFor, KdcRelay, Log, AT_ONCE};

const HOME: &str = "CONTOSO.LOCAL";
const TGT_KEY: [u8; 32] = [9u8; 32];

fn name(s: &str) -> picky_asn1::wrapper::GeneralStringAsn1 {
    picky_asn1::restricted_string::Ia5String::from_string(s.to_string())
        .unwrap()
        .into()
}

fn principal(name_type: u8, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            parts.iter().map(|p| name(p)).collect::<Vec<_>>(),
        )),
    }
}

fn ticket(sname: &[&str], realm: &str, mark: u8) -> Ticket {
    Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        realm: ExplicitContextTag1::from(name(realm)),
        sname: ExplicitContextTag2::from(principal(NT_SRV_INST, sname)),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1(vec![mark; 48])),
        }),
    })
}

/// How a fake KDC's reply is made.
#[derive(Clone)]
pub(crate) struct Rep {
    sname: Vec<String>,
    /// The ticket's service, if not `sname`.
    ticket_sname: Option<Vec<String>>,
    /// The key its encrypted part is under, and the key usage (8: the
    /// TGT's session key, 9: the authenticator's subkey).
    key: Vec<u8>,
    usage: i32,
    /// The new session key and its type.
    new_key: Vec<u8>,
    key_type: u8,
    /// The encrypted part's etype label.
    etype: u8,
    /// The nonce: the request's, unless set.
    nonce: Option<Vec<u8>>,
    /// The issuing realm: the realm asked, unless set.
    srealm: Option<String>,
    /// Marks the ticket's (made-up) cipher, to tell tickets apart.
    mark: u8,
}

impl Rep {
    pub(crate) fn new(sname: &[&str], key: &[u8], new_key: &[u8], mark: u8) -> Self {
        Self {
            sname: sname.iter().map(|s| s.to_string()).collect(),
            ticket_sname: None,
            key: key.to_vec(),
            usage: TGS_REP_ENC_SESSION_KEY,
            new_key: new_key.to_vec(),
            key_type: 18,
            etype: 18,
            nonce: None,
            srealm: None,
            mark,
        }
    }

    pub(crate) fn make(&self, req: &TgsReq) -> Vec<u8> {
        let now = 1_900_000_000;
        let realm = krbref::text(&req.0.req_body.0.realm.0);
        let srealm = self.srealm.clone().unwrap_or(realm.clone());
        let sname: Vec<&str> = self.sname.iter().map(String::as_str).collect();
        let tsname: Vec<&str> = self
            .ticket_sname
            .as_ref()
            .unwrap_or(&self.sname)
            .iter()
            .map(String::as_str)
            .collect();
        let part = EncTgsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1(vec![self.key_type])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1(self.new_key.clone())),
            }),
            last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![LastReqInner {
                lr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
                lr_value: ExplicitContextTag1::from(krb::kerberos_time_pub(now)),
            }])),
            nonce: ExplicitContextTag2::from(IntegerAsn1(
                self.nonce
                    .clone()
                    .unwrap_or_else(|| req.0.req_body.0.nonce.0 .0.clone()),
            )),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(BitStringAsn1::from(BitString::with_bytes(vec![
                0x40, 0xa1, 0, 0,
            ]))),
            auth_time: ExplicitContextTag5::from(krb::kerberos_time_pub(now)),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(krb::kerberos_time_pub(now + 3600)),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(name(&srealm)),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, &sname)),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let cipher = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(
                &self.key,
                self.usage,
                &picky_asn1_der::to_vec(&part).unwrap(),
            )
            .unwrap();
        picky_asn1_der::to_vec(&TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![13])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(name(HOME)),
            cname: ExplicitContextTag4::from(principal(NT_PRINCIPAL, &["svc-pathwarden"])),
            ticket: ExplicitContextTag5::from(ticket(&tsname, &srealm, self.mark)),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![self.etype])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
            }),
        }))
        .unwrap()
    }
}

pub(crate) type Answer = Box<dyn Fn(&TgsReq) -> Vec<u8> + Send + Sync>;

/// What a fake KDC was sent.
pub(crate) type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// A fake KDC on 127.0.0.1: each TGS-REQ answered with `answer`.
pub(crate) async fn kdc(answer: Answer) -> (String, Seen) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen: Seen = Arc::default();
    let log = seen.clone();
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
            log.lock().unwrap().push(req.clone());
            let reply = match picky_asn1_der::from_bytes::<TgsReq>(&req) {
                Ok(r) => answer(&r),
                Err(_) => krb::fake::error(60, 0, None),
            };
            let _ = s.write_all(&(reply.len() as u32).to_be_bytes()).await;
            let _ = s.write_all(&reply).await;
        }
    });
    (addr, seen)
}

/// The computer a TGS-REQ asks about (`cifs/<this>`).
pub(crate) fn requested(req: &TgsReq) -> String {
    req.0
        .req_body
        .0
        .sname
        .0
        .as_ref()
        .and_then(|s| s.0.name_string.0 .0.get(1).map(krbref::text))
        .unwrap_or_default()
}

fn answer(rep: Rep) -> Answer {
    Box::new(move |req| rep.make(req))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct Cache {
    parent: PathBuf,
    cache: Option<krb::TicketCache>,
}

impl Cache {
    fn new(tag: &str, tgt: &krb::Tgt) -> Self {
        let parent = std::env::temp_dir().join(format!("pw-relay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, tgt).unwrap();
        Self {
            parent,
            cache: Some(cache),
        }
    }

    fn name(&self) -> String {
        self.cache.as_ref().unwrap().name()
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        drop(self.cache.take());
        let _ = std::fs::remove_dir_all(&self.parent);
    }
}

fn logger() -> (Log, Arc<Mutex<Vec<String>>>) {
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let l = lines.clone();
    (Arc::new(move |line| l.lock().unwrap().push(line)), lines)
}

/// Each realm's KDC from a list.
fn realms(list: Vec<(&'static str, String)>) -> KdcFor {
    Arc::new(move |realm: &str| {
        list.iter()
            .find(|(r, _)| r.eq_ignore_ascii_case(realm))
            .map(|(_, a)| a.clone())
            .unwrap_or_else(|| "127.0.0.1:9".into())
    })
}

/// RustHound-CE's own ticket code, as the modules call it, with the relay
/// as its KDC: Ok when the SPNEGO token's ticket is for `host`.
async fn module(ccache: &str, host: &str, relay: &KdcRelay) -> Result<(), String> {
    let (blob, _key) = rusthound_ce::transport::kerberos::kerberos_material_for(
        ccache,
        &format!("cifs/{host}"),
        relay.addr(),
    )
    .await
    .map_err(|e| format!("{e:#}"))?;
    krb::check_ticket_pub(&blob, host).map_err(|e| e.words())
}

/// The key types of a TGS-REQ a fake KDC got.
fn etypes(raw: &[u8]) -> Vec<i64> {
    let req: TgsReq = picky_asn1_der::from_bytes(raw).unwrap();
    req.0
        .req_body
        .0
        .etype
        .0
         .0
        .iter()
        .map(krbref::int)
        .collect()
}

/// Bound to 127.0.0.1 only.
#[test]
fn the_relay_listens_on_loopback_only() {
    let cache = Cache::new("bind", &krb::fake::tgt());
    rt().block_on(async {
        let (log, _) = logger();
        let relay = KdcRelay::start(&cache.name(), "127.0.0.1:9", log)
            .await
            .unwrap();
        let addr: std::net::SocketAddr = relay.addr().parse().unwrap();
        assert!(addr.ip().is_loopback(), "{addr}");
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
        assert_ne!(addr.port(), 88);
        // Stopped when dropped: nothing listens there any more.
        drop(relay);
        tokio::task::yield_now().await;
        let again = tokio::net::TcpStream::connect(addr).await;
        assert!(again.is_err(), "the relay still answers after it stopped");
    });
}

/// A good reply passes, through RustHound-CE's own ticket code, and the
/// domain controller is asked for AES256 only (RustHound-CE asks for RC4
/// too).
#[test]
fn a_good_reply_passes_and_rc4_is_not_asked_for() {
    let cache = Cache::new("good", &krb::fake::tgt());
    let host = "WS01.CONTOSO.LOCAL";
    rt().block_on(async {
        let (dc, seen) = kdc(answer(Rep::new(
            &["cifs", "ws01.contoso.local"],
            &TGT_KEY,
            &[3u8; 32],
            1,
        )))
        .await;
        let (log, lines) = logger();
        let relay = KdcRelay::start(&cache.name(), &dc, log).await.unwrap();
        assert_eq!(module(&cache.name(), host, &relay).await, Ok(()));
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(etypes(&seen[0]), [18], "RC4 taken out of the request");
        assert!(lines.lock().unwrap().is_empty());
    });
}

/// Each forged or weakened reply is refused: the module gets a KDC error,
/// never the ticket, and the refusal is logged.
#[test]
fn bad_replies_are_refused() {
    let cache = Cache::new("bad", &krb::fake::tgt());
    let host = "WS01.CONTOSO.LOCAL";
    let good = Rep::new(&["cifs", "ws01.contoso.local"], &TGT_KEY, &[3u8; 32], 1);
    let cases: Vec<(&str, Rep)> = vec![
        (
            "nonce",
            Rep {
                nonce: Some(vec![1, 2, 3]),
                ..good.clone()
            },
        ),
        // Another computer's reply, replayed: its encrypted part names it.
        (
            "a ticket for cifs/ws02.contoso.local",
            Rep::new(&["cifs", "ws02.contoso.local"], &TGT_KEY, &[3u8; 32], 2),
        ),
        (
            "names two services",
            Rep {
                ticket_sname: Some(vec!["cifs".into(), "ws02.contoso.local".into()]),
                ..good.clone()
            },
        ),
        (
            "realm EVIL.LOCAL",
            Rep {
                srealm: Some("EVIL.LOCAL".into()),
                ..good.clone()
            },
        ),
        (
            "etype 23",
            Rep {
                etype: 23,
                ..good.clone()
            },
        ),
        (
            "not AES256",
            Rep {
                key_type: 23,
                new_key: vec![3u8; 16],
                ..good.clone()
            },
        ),
        // Under a key the relay doesn't hold.
        (
            "cifs/WS01.CONTOSO.LOCAL",
            Rep {
                key: vec![7u8; 32],
                ..good.clone()
            },
        ),
    ];
    let rt = rt();
    for (says, rep) in cases {
        rt.block_on(async {
            let (dc, _) = kdc(answer(rep)).await;
            let (log, lines) = logger();
            let relay = KdcRelay::start(&cache.name(), &dc, log).await.unwrap();
            let r = module(&cache.name(), host, &relay).await;
            assert!(
                matches!(&r, Err(e) if e.contains("KDC error 60")),
                "{says}: {r:?}"
            );
            let lines = lines.lock().unwrap().clone();
            assert_eq!(lines.len(), 1, "{says}: {lines:?}");
            assert!(lines[0].contains(says), "{says}: {lines:?}");
            assert!(lines[0].starts_with("warning: [krb] "), "{lines:?}");
        });
    }
    // The KDC's own error goes to the module as is.
    rt.block_on(async {
        let (dc, _) = kdc(Box::new(|_| {
            krb::fake::error(krb::KDC_ERR_S_PRINCIPAL_UNKNOWN, 0, None)
        }))
        .await;
        let (log, lines) = logger();
        let relay = KdcRelay::start(&cache.name(), &dc, log).await.unwrap();
        let r = module(&cache.name(), host, &relay).await;
        assert!(matches!(&r, Err(e) if e.contains("KDC error 7")), "{r:?}");
        assert!(lines.lock().unwrap().is_empty());
    });
}

/// An AS-REQ, garbage, and a request presenting another TGT (another
/// run's, or this one's ticket without its session key) are refused
/// before the domain controller is asked.
#[test]
fn only_this_runs_ticket_requests_pass() {
    let ours = Cache::new("ours", &krb::fake::tgt());
    let other = Cache::new("other", &krb::fake::other_tgt());
    rt().block_on(async {
        let (dc, seen) = kdc(answer(Rep::new(
            &["cifs", "ws01.contoso.local"],
            &TGT_KEY,
            &[3u8; 32],
            1,
        )))
        .await;
        let (log, lines) = logger();
        let relay = KdcRelay::start(&ours.name(), &dc, log).await.unwrap();
        let refused = |reply: Vec<u8>| -> u32 {
            picky_asn1_der::from_bytes::<KrbError>(&reply)
                .expect("a KRB-ERROR")
                .0
                .error_code
                .0
        };

        // An AS-REQ: the relay never asks for a TGT.
        let tgt = krbref::read_cache(&ours.name()).unwrap();
        let (tgs, _) =
            krbref::tgs_req(HOME, "ws01.contoso.local", &tgt, &tgt.ticket, &tgt.key).unwrap();
        let tgs: TgsReq = picky_asn1_der::from_bytes(&tgs).unwrap();
        let mut body = tgs.0.clone();
        body.msg_type = ExplicitContextTag2::from(IntegerAsn1(vec![10]));
        let as_req = picky_asn1_der::to_vec(&AsReq::from(body)).unwrap();
        let reply = krb::exchange_pub(relay.addr(), &as_req).await.unwrap();
        assert_eq!(refused(reply), 60);
        // Not Kerberos at all.
        let reply = krb::exchange_pub(relay.addr(), b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(refused(reply), 60);

        // Another run's TGT, through RustHound-CE's ticket code.
        let r = module(&other.name(), "WS01.CONTOSO.LOCAL", &relay).await;
        assert!(matches!(&r, Err(e) if e.contains("KDC error 60")), "{r:?}");

        // This run's ticket, with an authenticator under another key.
        let forged = krbref::tgs_req(HOME, "ws01.contoso.local", &tgt, &tgt.ticket, &[5u8; 32])
            .unwrap()
            .0;
        let reply = krb::exchange_pub(relay.addr(), &forged).await.unwrap();
        assert_eq!(refused(reply), 60);

        assert!(seen.lock().unwrap().is_empty(), "the KDC was never asked");
        // Anyone on this computer can connect: quiet, counted, one line
        // when the relay stops.
        assert!(
            lines.lock().unwrap().is_empty(),
            "{:?}",
            lines.lock().unwrap()
        );
        drop(relay);
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "warning: [krb] the modules' KDC relay refused 4 requests that didn't present \
              this run's ticket."
            ]
        );
    });
}

/// A computer in a trusted realm, one referral away: the relay follows it
/// and hands the module an ordinary TGS-REP for the computer, its
/// encrypted part under the TGT's session key with the module's nonce.
#[test]
fn one_referral_is_followed_and_encrypted_again() {
    let cache = Cache::new("hop1", &krb::fake::tgt());
    let host = "WS01.FABRIKAM.LOCAL";
    rt().block_on(async {
        let (home, _) = kdc(answer(Rep::new(
            &["krbtgt", "FABRIKAM.LOCAL"],
            &TGT_KEY,
            &[2u8; 32],
            1,
        )))
        .await;
        let (there, seen) = kdc(answer(Rep::new(
            &["cifs", "ws01.fabrikam.local"],
            &[2u8; 32],
            &[3u8; 32],
            4,
        )))
        .await;
        let (log, lines) = logger();
        let relay = KdcRelay::start_with(
            &cache.name(),
            &home,
            realms(vec![("FABRIKAM.LOCAL", there)]),
            log,
        )
        .await
        .unwrap();
        assert_eq!(module(&cache.name(), host, &relay).await, Ok(()));
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the trusted realm's KDC asked"
        );

        // Decrypted with the presented TGT's session key: the module's
        // nonce, the computer's session key and the trusted realm's ticket.
        let tgt = krbref::read_cache(&cache.name()).unwrap();
        let (req, nonce) =
            krbref::tgs_req(HOME, "ws01.fabrikam.local", &tgt, &tgt.ticket, &tgt.key).unwrap();
        let reply = krb::exchange_pub(relay.addr(), &req).await.unwrap();
        let rep: TgsRep = picky_asn1_der::from_bytes(&reply).expect("a TGS-REP");
        assert_eq!(krbref::int(&rep.0.enc_part.0.etype.0), 18);
        let plain = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .decrypt(
                &TGT_KEY,
                TGS_REP_ENC_SESSION_KEY,
                &rep.0.enc_part.0.cipher.0 .0,
            )
            .expect("under the TGT's session key");
        let part = picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain)
            .unwrap()
            .0;
        assert_eq!(krbref::int(&part.nonce.0), krbref::int(&nonce));
        assert_eq!(part.key.0.key_value.0 .0, vec![3u8; 32]);
        assert_eq!(krbref::text(&part.srealm.0), "FABRIKAM.LOCAL");
        let ticket = &rep.0.ticket.0 .0;
        assert_eq!(
            ticket.enc_part.0.cipher.0 .0,
            vec![4u8; 48],
            "the computer's ticket"
        );
        assert_eq!(krbref::text(&rep.0.crealm.0), HOME);
        assert!(
            lines.lock().unwrap().is_empty(),
            "{:?}",
            lines.lock().unwrap()
        );
    });
}

/// Two referrals (a child domain's account, a computer across the forest
/// trust): each hop's KDC asked in turn, the module gets the ticket. A
/// forged hop (a reply under a key the relay doesn't hold, or with another
/// nonce) is refused; a realm that doesn't know the computer is the
/// module's "no Kerberos name".
#[test]
fn two_referrals_and_a_forged_hop() {
    let cache = Cache::new("hop2", &krb::fake::tgt());
    let host = "WS09.FABRIKAM.COM";
    let rt = rt();
    let run = |last: Answer| {
        let ccache = cache.name();
        rt.block_on(async move {
            let (home, a) = kdc(answer(Rep::new(
                &["krbtgt", "CORP.LOCAL"],
                &TGT_KEY,
                &[2u8; 32],
                1,
            )))
            .await;
            let (parent, b) = kdc(answer(Rep::new(
                &["krbtgt", "FABRIKAM.COM"],
                &[2u8; 32],
                &[4u8; 32],
                2,
            )))
            .await;
            let (other, c) = kdc(last).await;
            let (log, lines) = logger();
            let relay = KdcRelay::start_with(
                &ccache,
                &home,
                realms(vec![("CORP.LOCAL", parent), ("FABRIKAM.COM", other)]),
                log,
            )
            .await
            .unwrap();
            let r = module(&ccache, host, &relay).await;
            let asked = [a, b, c].map(|s| s.lock().unwrap().len());
            let lines = lines.lock().unwrap().clone();
            (r, asked, lines)
        })
    };
    let (r, asked, lines) = run(answer(Rep::new(
        &["cifs", "ws09.fabrikam.com"],
        &[4u8; 32],
        &[3u8; 32],
        5,
    )));
    assert_eq!(r, Ok(()));
    assert_eq!(asked, [1, 1, 1]);
    assert!(lines.is_empty(), "{lines:?}");

    for forged in [
        Rep::new(&["cifs", "ws09.fabrikam.com"], &[7u8; 32], &[3u8; 32], 5),
        Rep {
            nonce: Some(vec![1, 2, 3]),
            ..Rep::new(&["cifs", "ws09.fabrikam.com"], &[4u8; 32], &[3u8; 32], 5)
        },
    ] {
        let (r, _, lines) = run(answer(forged));
        assert!(matches!(&r, Err(e) if e.contains("KDC error 60")), "{r:?}");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("cifs/WS09.FABRIKAM.COM"), "{lines:?}");
    }

    let (r, _, _) = run(Box::new(|_| krb::fake::error(7, 0, None)));
    let e = r.unwrap_err();
    assert!(e.contains("KDC error 7"), "{e}");
    assert!(matches!(krb::no_ticket(host, &e), krb::NoTicket::NoName(_)));
}

/// A request as `krbref` makes it, then changed: its body by `body`, its
/// authenticator by `auth` (encrypted again under `key`).
fn changed(
    tgt: &krbref::CachedTgt,
    host: &str,
    key: &[u8],
    auth: impl FnOnce(&mut AuthenticatorInner),
    body: impl FnOnce(&mut TgsReq),
) -> Vec<u8> {
    let (raw, _) = krbref::tgs_req(HOME, host, tgt, &tgt.ticket, &tgt.key).unwrap();
    let mut req: TgsReq = picky_asn1_der::from_bytes(&raw).unwrap();
    let pa = &mut req.0.padata.0.as_mut().unwrap().0 .0[0];
    let mut ap: ApReq = picky_asn1_der::from_bytes(&pa.padata_data.0 .0).unwrap();
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(
            &tgt.key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &ap.0.authenticator.0.cipher.0 .0,
        )
        .unwrap();
    let mut a: Authenticator = picky_asn1_der::from_bytes(&plain).unwrap();
    auth(&mut a.0);
    let sealed = cipher
        .encrypt(
            key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &picky_asn1_der::to_vec(&a).unwrap(),
        )
        .unwrap();
    ap.0.authenticator.0.cipher = ExplicitContextTag2::from(OctetStringAsn1(sealed));
    pa.padata_data =
        ExplicitContextTag2::from(OctetStringAsn1(picky_asn1_der::to_vec(&ap).unwrap()));
    body(&mut req);
    picky_asn1_der::to_vec(&req).unwrap()
}

fn error_code(reply: &[u8]) -> u32 {
    picky_asn1_der::from_bytes::<KrbError>(reply)
        .expect("a KRB-ERROR")
        .0
        .error_code
        .0
}

/// An authenticator with an AES256 subkey: the reply, and a referral's
/// re-encrypted one, are under the subkey with key usage 9.
#[test]
fn a_subkey_gets_its_reply_under_the_subkey() {
    let cache = Cache::new("subkey", &krb::fake::tgt());
    const SUB: [u8; 32] = [6u8; 32];
    rt().block_on(async {
        let (home, _) = kdc(answer(Rep {
            usage: TGS_REP_ENC_SUB_KEY,
            ..Rep::new(&["krbtgt", "FABRIKAM.COM"], &SUB, &[2u8; 32], 1)
        }))
        .await;
        let (there, _) = kdc(answer(Rep::new(
            &["cifs", "ws01.fabrikam.com"],
            &[2u8; 32],
            &[3u8; 32],
            4,
        )))
        .await;
        let (log, lines) = logger();
        let relay = KdcRelay::start_with(
            &cache.name(),
            &home,
            realms(vec![("FABRIKAM.COM", there)]),
            log,
        )
        .await
        .unwrap();
        let tgt = krbref::read_cache(&cache.name()).unwrap();
        let req = changed(
            &tgt,
            "ws01.fabrikam.com",
            &TGT_KEY,
            |a| {
                a.subkey = Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
                    key_type: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
                    key_value: ExplicitContextTag1::from(OctetStringAsn1(SUB.to_vec())),
                })));
            },
            |_| {},
        );
        let reply = krb::exchange_pub(relay.addr(), &req).await.unwrap();
        let rep: TgsRep = picky_asn1_der::from_bytes(&reply).expect("a TGS-REP");
        let plain = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .decrypt(&SUB, TGS_REP_ENC_SUB_KEY, &rep.0.enc_part.0.cipher.0 .0)
            .expect("under the subkey, key usage 9");
        let part = picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain)
            .unwrap()
            .0;
        assert_eq!(part.key.0.key_value.0 .0, vec![3u8; 32]);
        assert!(
            lines.lock().unwrap().is_empty(),
            "{:?}",
            lines.lock().unwrap()
        );
    });
}

/// Requests that present the run's ticket but aren't as RustHound-CE sends
/// them, or that don't present it properly, are refused before the KDC is
/// asked: a stale authenticator, another client or realm, another service,
/// extra tickets, extra PA-DATA, other KDC options.
#[test]
fn malformed_requests_are_refused() {
    let cache = Cache::new("malformed", &krb::fake::tgt());
    let host = "ws01.contoso.local";
    rt().block_on(async {
        let (dc, seen) = kdc(answer(Rep::new(&["cifs", host], &TGT_KEY, &[3u8; 32], 1))).await;
        let (log, lines) = logger();
        let relay = KdcRelay::start(&cache.name(), &dc, log).await.unwrap();
        let tgt = krbref::read_cache(&cache.name()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        type Auth = Box<dyn FnOnce(&mut AuthenticatorInner)>;
        type Body = Box<dyn FnOnce(&mut TgsReq)>;
        let none_a = || -> Auth { Box::new(|_: &mut AuthenticatorInner| {}) };
        let none_b = || -> Body { Box::new(|_: &mut TgsReq| {}) };
        // (quiet: refused before the run's ticket is accepted, the change)
        let cases: Vec<(bool, Auth, Body)> = vec![
            (
                true,
                Box::new(move |a: &mut AuthenticatorInner| {
                    a.ctime = ExplicitContextTag5::from(krb::kerberos_time_pub(now - 600))
                }),
                none_b(),
            ),
            (
                true,
                Box::new(|a: &mut AuthenticatorInner| {
                    a.cname = ExplicitContextTag2::from(principal(NT_PRINCIPAL, &["someone-else"]))
                }),
                none_b(),
            ),
            (
                true,
                Box::new(|a: &mut AuthenticatorInner| {
                    a.crealm = ExplicitContextTag1::from(name("EVIL.LOCAL"))
                }),
                none_b(),
            ),
            (
                true,
                none_a(),
                Box::new(|r: &mut TgsReq| {
                    r.0.padata.0.as_mut().unwrap().0 .0.push(PaData {
                        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0, 128])),
                        padata_data: ExplicitContextTag2::from(OctetStringAsn1(vec![0x30, 0])),
                    });
                }),
            ),
            (
                false,
                none_a(),
                Box::new(|r: &mut TgsReq| {
                    r.0.req_body.0.sname = Optional::from(Some(ExplicitContextTag3::from(
                        principal(NT_SRV_INST, &["krbtgt", "FABRIKAM.COM"]),
                    )));
                }),
            ),
            (
                false,
                none_a(),
                Box::new(|r: &mut TgsReq| {
                    r.0.req_body.0.additional_tickets =
                        Optional::from(Some(picky_asn1::wrapper::ExplicitContextTag11::from(
                            Asn1SequenceOf::from(vec![ticket(&["krbtgt", HOME], HOME, 3)]),
                        )));
                }),
            ),
            (
                false,
                none_a(),
                Box::new(|r: &mut TgsReq| {
                    r.0.req_body.0.kdc_options = ExplicitContextTag0::from(BitStringAsn1::from(
                        BitString::with_bytes(vec![0x40, 0x81, 0x00, 0x08]),
                    ));
                }),
            ),
        ];
        let loud = cases.iter().filter(|(quiet, _, _)| !quiet).count();
        for (quiet, auth, body) in cases {
            let before = lines.lock().unwrap().len();
            let req = changed(&tgt, host, &TGT_KEY, auth, body);
            let reply = krb::exchange_pub(relay.addr(), &req).await.unwrap();
            assert_eq!(error_code(&reply), 60);
            let after = lines.lock().unwrap().len();
            assert_eq!(
                after - before,
                usize::from(!quiet),
                "{:?}",
                lines.lock().unwrap()
            );
        }
        assert!(seen.lock().unwrap().is_empty(), "the KDC was never asked");
        let shown = lines.lock().unwrap().clone();
        assert_eq!(shown.len(), loud);
        assert!(
            shown[0].contains("krbtgt/FABRIKAM.COM, not cifs/<computer>"),
            "{shown:?}"
        );
        assert!(shown[1].contains("extra tickets"), "{shown:?}");
        assert!(shown[2].contains("other KDC options"), "{shown:?}");
        drop(relay);
        let last = lines.lock().unwrap().last().cloned().unwrap();
        assert!(last.contains("refused 4 requests"), "{last}");
    });
}

/// A referral back to the run's own realm, and a chain longer than the
/// relay follows, are refused.
#[test]
fn a_referral_home_and_too_many_hops_are_refused() {
    let cache = Cache::new("loops", &krb::fake::tgt());
    let host = "WS01.FABRIKAM.COM";
    let rt = rt();
    // Back home.
    rt.block_on(async {
        let (home, _) = kdc(answer(Rep::new(&["krbtgt", HOME], &TGT_KEY, &[2u8; 32], 1))).await;
        let (log, lines) = logger();
        let relay = KdcRelay::start(&cache.name(), &home, log).await.unwrap();
        let r = module(&cache.name(), host, &relay).await;
        assert!(matches!(&r, Err(e) if e.contains("KDC error 60")), "{r:?}");
        let lines = lines.lock().unwrap().clone();
        assert!(lines[0].contains("back to CONTOSO.LOCAL"), "{lines:?}");
    });
    // R1 refers to R2, R2 to R3, and so on.
    rt.block_on(async {
        let (home, _) = kdc(answer(Rep::new(
            &["krbtgt", "R1.LOCAL"],
            &TGT_KEY,
            &[2u8; 32],
            1,
        )))
        .await;
        let (chain, seen) = kdc(Box::new(|req| {
            let realm = krbref::text(&req.0.req_body.0.realm.0);
            let n: u32 = realm
                .trim_start_matches('R')
                .trim_end_matches(".LOCAL")
                .parse()
                .unwrap();
            let next = format!("R{}.LOCAL", n + 1);
            Rep::new(&["krbtgt", &next], &[2u8; 32], &[2u8; 32], 1).make(req)
        }))
        .await;
        let to_chain = chain.clone();
        let (log, lines) = logger();
        let relay = KdcRelay::start_with(
            &cache.name(),
            &home,
            Arc::new(move |_: &str| to_chain.clone()),
            log,
        )
        .await
        .unwrap();
        let r = module(&cache.name(), host, &relay).await;
        assert!(matches!(&r, Err(e) if e.contains("KDC error 60")), "{r:?}");
        assert_eq!(seen.lock().unwrap().len(), krbref::MAX_HOPS);
        let lines = lines.lock().unwrap().clone();
        assert!(
            lines[0].contains("through CONTOSO.LOCAL, R1.LOCAL"),
            "{lines:?}"
        );
    });
}

/// Connections held open by someone else (all of them, idle) don't stop the
/// relay: each is dropped at its deadline and the module's request is
/// answered after it. A KDC that never answers costs one deadline, not the
/// KDC timeout.
#[test]
fn idle_connections_and_a_silent_kdc_cost_one_deadline() {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    let cache = Cache::new("stall", &krb::fake::tgt());
    let host = "WS01.CONTOSO.LOCAL";
    let deadline = Duration::from_secs(1);
    let rt = rt();
    rt.block_on(async {
        let (dc, _) = kdc(answer(Rep::new(
            &["cifs", "ws01.contoso.local"],
            &TGT_KEY,
            &[3u8; 32],
            1,
        )))
        .await;
        let (log, _) = logger();
        let relay =
            KdcRelay::start_with_deadline(&cache.name(), &dc, realms(vec![]), log, deadline)
                .await
                .unwrap();
        let mut idle = Vec::new();
        for _ in 0..AT_ONCE + 4 {
            idle.push(tokio::net::TcpStream::connect(relay.addr()).await.unwrap());
        }
        let started = Instant::now();
        assert_eq!(module(&cache.name(), host, &relay).await, Ok(()));
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
        // The first ones were closed by the relay at their deadline.
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(3), idle[0].read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
    });
    rt.block_on(async {
        // Takes the request and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let (log, _) = logger();
        let relay =
            KdcRelay::start_with_deadline(&cache.name(), &dc, realms(vec![]), log, deadline)
                .await
                .unwrap();
        let started = Instant::now();
        let r = module(&cache.name(), host, &relay).await;
        assert!(r.is_err(), "{r:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    });
}
