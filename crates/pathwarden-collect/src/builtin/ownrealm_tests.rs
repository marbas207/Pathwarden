//! Kerberos only with an account from another domain or forest,
//! against fake KDCs: the TGT from the account's own domain, whose
//! controller is checked before any AS-REQ, then the referrals to the
//! collected domain.

use std::sync::{Arc, Mutex};

use pathwarden_core::storedcreds::NetbiosName;
use picky_krb::messages::{AsReq, TgsReq};
use rusthound_ce::args::CollectionMethod;

use super::krbrelay_tests::Rep;
use super::ownrealm::{self, OwnRealmDc, Trust, Verifying};
use super::{
    base_options, check_foreign, hosts, job_for, kerberos_hosts, krb, krbref, through_the_trust,
    trust_entry, Job,
};
use crate::{Auth, CollectRequest, Problem, Scope, Secret};

const PASSWORD: &str = "Pw-Own-Realm-1";

/// What happened, in order: the locator, the checks and each KDC request.
type Events = Arc<Mutex<Vec<String>>>;

/// A locator and LDAPS check that answer as told (each host's check result,
/// else a failure), recording each call.
struct FakeDc {
    found: Vec<String>,
    verified: Vec<(String, Result<String, String>)>,
    events: Events,
    /// What it finds when asked once more.
    again: Vec<String>,
}

impl FakeDc {
    fn one(host: &str, verified: Result<String, String>, events: &Events) -> Self {
        Self {
            found: vec![host.to_string()],
            verified: vec![(host.to_string(), verified)],
            events: events.clone(),
            again: Vec::new(),
        }
    }
}

impl OwnRealmDc for FakeDc {
    fn locate(&self, realm: &str, log: &mut dyn FnMut(String)) -> Vec<String> {
        self.events.lock().unwrap().push(format!("locate {realm}"));
        log(format!("[dc] {realm}: located"));
        self.found.clone()
    }

    fn rediscover(&self, realm: &str, known: &[String], _: &mut dyn FnMut(String)) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .push(format!("rediscover {realm}"));
        self.again
            .iter()
            .filter(|h| !known.contains(h))
            .cloned()
            .collect()
    }

    fn verify<'a>(&'a self, host: &'a str, realm: &'a str, skip_verify: bool) -> Verifying<'a> {
        Box::pin(async move {
            self.events
                .lock()
                .unwrap()
                .push(format!("verify {host} {realm} skip={skip_verify}"));
            self.verified
                .iter()
                .find(|(h, _)| h == host)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| Err("connection refused".into()))
        })
    }
}

type Tgs = Box<dyn Fn(&TgsReq) -> Vec<u8> + Send + Sync>;

/// A fake KDC named `name` on 127.0.0.1. An AS-REQ for `svc` must carry
/// PA-ENC-TIMESTAMP made with the password's key
/// ([`krb::fake::preauth_answer`]); a TGS-REQ gets `tgs`'s answer. Each
/// request goes in `events` ("AS" without a timestamp, "AS+ts" with one).
async fn kdc(name: &'static str, tgs: Tgs, events: Events) -> String {
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
            let reply = if let Ok(r) = picky_asn1_der::from_bytes::<AsReq>(&req) {
                let realm = krbref::text(&r.0.req_body.0.realm.0);
                let stamped =
                    r.0.padata
                        .0
                        .as_ref()
                        .is_some_and(|p| p.0 .0.iter().any(|p| p.padata_type.0 .0 == [2]));
                let kind = if stamped { "AS+ts" } else { "AS" };
                events
                    .lock()
                    .unwrap()
                    .push(format!("{name}: {kind} {realm}"));
                krb::fake::preauth_answer(&req, PASSWORD).unwrap()
            } else if let Ok(r) = picky_asn1_der::from_bytes::<TgsReq>(&req) {
                let realm = krbref::text(&r.0.req_body.0.realm.0);
                events.lock().unwrap().push(format!("{name}: TGS {realm}"));
                tgs(&r)
            } else {
                krb::fake::error(60, 0, None)
            };
            let _ = s.write_all(&(reply.len() as u32).to_be_bytes()).await;
            let _ = s.write_all(&reply).await;
        }
    });
    addr
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The TGT's session key in [`krb::fake::as_rep_reply`].
const TGT_KEY: [u8; 32] = [5u8; 32];

fn answer(rep: Rep) -> Tgs {
    Box::new(move |req| rep.make(req))
}

fn referral(to: &str) -> Tgs {
    answer(Rep::new(&["krbtgt", to], &TGT_KEY, &[2u8; 32], 1))
}

fn cifs(host: &str) -> Tgs {
    answer(Rep::new(&["cifs", host], &[2u8; 32], &[3u8; 32], 2))
}

/// A ticket cache in a folder of its own, removed with it.
struct Cache {
    parent: std::path::PathBuf,
    cache: Option<krb::TicketCache>,
}

impl Cache {
    fn new(tag: &str, tgt: &krb::Tgt) -> Self {
        let parent = std::env::temp_dir().join(format!("pw-own-{tag}-{}", std::process::id()));
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

/// The account's TGT from `realm`'s checked controller (`dc`), then
/// `cifs/<host>` from it through the referrals (each realm's KDC from
/// `kdc_for`). The TGT's realm and the KDC it came from.
async fn own_then_ticket(
    dc: &FakeDc,
    realm: &str,
    collected: &str,
    host: &str,
    kdc_for: &(dyn Fn(&str) -> String + Sync),
    tag: &str,
) -> Result<(String, String), String> {
    let lines = Mutex::new(Vec::new());
    let (tgt, kdc) = ownrealm::own_realm_ticket(
        dc,
        realm,
        None,
        collected,
        "svc",
        &Secret::new(PASSWORD),
        false,
        &|l| lines.lock().unwrap().push(l),
    )
    .await
    .map_err(|e| e.message())?;
    let tgt_realm = tgt.realm.clone();
    let cache = Cache::new(tag, &tgt);
    let (blob, _key) = krbref::service_ticket(&cache.name(), host, &kdc, kdc_for)
        .await
        .map_err(|e| e.words())?;
    krb::check_ticket_pub(&blob, host).map_err(|e| e.words())?;
    Ok((tgt_realm, kdc))
}

/// A parent-domain account collecting a child domain: the TGT from the
/// parent's controller, checked first, with pre-auth; the child's computer
/// through the parent's referral.
#[test]
fn a_parent_domain_account_collects_a_child_domain() {
    let events: Events = Arc::default();
    rt().block_on(async {
        let parent = kdc("parent", referral("NORTH.CONTOSO.LOCAL"), events.clone()).await;
        let child = kdc("child", cifs("dc01.north.contoso.local"), events.clone()).await;
        let dc = FakeDc::one("dc01.contoso.local", Ok(parent.clone()), &events);
        let (realm, kdc) = own_then_ticket(
            &dc,
            "CONTOSO.LOCAL",
            "north.contoso.local",
            "DC01.NORTH.CONTOSO.LOCAL",
            &move |r: &str| {
                assert_eq!(r, "NORTH.CONTOSO.LOCAL");
                child.clone()
            },
            "child",
        )
        .await
        .unwrap();
        assert_eq!(realm, "CONTOSO.LOCAL");
        assert_eq!(kdc, parent, "the address checked");
    });
    assert_eq!(
        *events.lock().unwrap(),
        [
            "locate contoso.local",
            "verify dc01.contoso.local contoso.local skip=false",
            "parent: AS CONTOSO.LOCAL",
            "parent: AS+ts CONTOSO.LOCAL",
            "parent: TGS CONTOSO.LOCAL",
            "child: TGS NORTH.CONTOSO.LOCAL",
        ],
        "checked before any AS-REQ; both AS-REQs to the address checked"
    );
}

/// A wrong password: the pre-auth is refused, no ticket.
#[test]
fn a_wrong_password_is_refused_by_the_pre_auth() {
    let events: Events = Arc::default();
    let e = rt().block_on(async {
        let home = kdc("home", referral("X"), events.clone()).await;
        let dc = FakeDc::one("dc01.contoso.local", Ok(home), &events);
        ownrealm::own_realm_ticket(
            &dc,
            "contoso.local",
            None,
            "north.contoso.local",
            "svc",
            &Secret::new("Wrong-1"),
            false,
            &|_| {},
        )
        .await
        .map(|_| ())
        .unwrap_err()
    });
    assert!(e.message().contains("refused the password"), "{e}");
}

/// An account from a trusted forest: the TGT from its forest's controller,
/// the collected domain's computer through the forest trust's referral.
#[test]
fn a_trusted_forest_account_collects_this_forest() {
    let events: Events = Arc::default();
    rt().block_on(async {
        let theirs = kdc("fabrikam", referral("CONTOSO.LOCAL"), events.clone()).await;
        let ours = kdc("contoso", cifs("ws01.contoso.local"), events.clone()).await;
        let dc = FakeDc::one("dc01.fabrikam.com", Ok(theirs), &events);
        let (realm, _) = own_then_ticket(
            &dc,
            "fabrikam.com",
            "contoso.local",
            "WS01.CONTOSO.LOCAL",
            &move |_: &str| ours.clone(),
            "forest",
        )
        .await
        .unwrap();
        assert_eq!(realm, "FABRIKAM.COM");
    });
    let e = events.lock().unwrap().clone();
    assert_eq!(e[1], "verify dc01.fabrikam.com fabrikam.com skip=false");
    assert_eq!(
        &e[2..],
        [
            "fabrikam: AS FABRIKAM.COM",
            "fabrikam: AS+ts FABRIKAM.COM",
            "fabrikam: TGS FABRIKAM.COM",
            "contoso: TGS CONTOSO.LOCAL",
        ]
    );
}

const REFUSED: &str = "Kerberos didn't work: no domain controller of the account's domain \
                       (contoso.local) passed the domain controller check, so the password \
                       wasn't sent to it. Use an account from fabrikam.com.";

/// A controller of the account's domain that fails the LDAPS check, or a
/// located name outside the domain, is refused in plain words, and no
/// AS-REQ (no pre-auth to crack) is sent anywhere.
#[test]
fn a_home_dc_that_fails_the_ldaps_check_gets_no_as_req() {
    let events: Events = Arc::default();
    let refused = rt().block_on(async {
        let home = kdc("home", referral("X"), events.clone()).await;
        let mut out = Vec::new();
        for dc in [
            FakeDc::one(
                "dc01.contoso.local",
                Err("invalid peer certificate: UnknownIssuer".to_string()),
                &events,
            ),
            // A spoofed locator answer outside the domain: never checked.
            FakeDc::one("dc01.attacker.example", Ok(home.clone()), &events),
        ] {
            out.push(
                own_then_ticket(
                    &dc,
                    "contoso.local",
                    "fabrikam.com",
                    "X.Y",
                    &|_| home.clone(),
                    "no",
                )
                .await
                .unwrap_err(),
            );
        }
        out
    });
    for e in &refused {
        assert_eq!(e, REFUSED);
    }
    let e = events.lock().unwrap().clone();
    assert!(!e.iter().any(|l| l.contains("AS")), "{e:?}");
    // The outside name wasn't checked: the domain's own name was, and failed.
    assert_eq!(
        e.iter()
            .filter(|l| l.starts_with("verify"))
            .collect::<Vec<_>>(),
        [
            "verify dc01.contoso.local contoso.local skip=false",
            "verify contoso.local contoso.local skip=false",
        ]
    );

    let e = ownrealm::unverified(
        "contoso.local",
        "fabrikam.com",
        "dc01.contoso.local: invalid peer certificate: UnknownIssuer".into(),
    );
    assert_eq!(e.problem, Problem::NoTicket);
    assert!(e.detail.contains("UnknownIssuer"), "{}", e.detail);
    assert!(!e.message().contains("--"), "no command-line flags");
}

/// The best located controller fails: up to two more are each checked in
/// turn, and the first that passes gives the ticket; a fourth is never
/// tried.
#[test]
fn up_to_three_located_controllers_are_checked() {
    let events: Events = Arc::default();
    let (ok, all_fail) = rt().block_on(async {
        let home = kdc("home", referral("NORTH.CONTOSO.LOCAL"), events.clone()).await;
        let child = kdc("child", cifs("ws01.north.contoso.local"), events.clone()).await;
        let found = ["dc1", "dc2", "dc3", "dc4"].map(|h| format!("{h}.contoso.local"));
        let third = FakeDc {
            found: found.to_vec(),
            verified: vec![(found[2].clone(), Ok(home.clone()))],
            events: events.clone(),
            again: Vec::new(),
        };
        let child2 = child.clone();
        let ok = own_then_ticket(
            &third,
            "contoso.local",
            "north.contoso.local",
            "WS01.NORTH.CONTOSO.LOCAL",
            &move |_| child2.clone(),
            "third",
        )
        .await;
        let fourth = FakeDc {
            found: found.to_vec(),
            verified: vec![(found[3].clone(), Ok(home.clone()))],
            events: events.clone(),
            again: Vec::new(),
        };
        let all_fail = own_then_ticket(
            &fourth,
            "contoso.local",
            "fabrikam.com",
            "X.Y",
            &move |_| child.clone(),
            "fourth",
        )
        .await;
        (ok, all_fail)
    });
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(all_fail.unwrap_err(), REFUSED);
    let e = events.lock().unwrap().clone();
    assert!(!e.iter().any(|l| l.contains("verify dc4")), "{e:?}");
    assert_eq!(e.iter().filter(|l| l.contains(": AS ")).count(), 1, "{e:?}");
}

/// `--server REALM=HOST`: that host only, checked all the same; no
/// locator asked.
#[test]
fn a_named_controller_is_checked_and_used() {
    let events: Events = Arc::default();
    let (ok, bad) = rt().block_on(async {
        let home = kdc("home", referral("X"), events.clone()).await;
        let dc = FakeDc {
            found: vec!["dc9.contoso.local".into()],
            verified: vec![("dc05.corp.example".into(), Ok(home.clone()))],
            events: events.clone(),
            again: Vec::new(),
        };
        let pw = Secret::new(PASSWORD);
        let mut got = Vec::new();
        for named in ["dc05.corp.example", "dc06.corp.example"] {
            got.push(
                ownrealm::own_realm_ticket(
                    &dc,
                    "contoso.local",
                    Some(named),
                    "fabrikam.com",
                    "svc",
                    &pw,
                    false,
                    &|_| {},
                )
                .await
                .map(|(_, kdc)| kdc),
            );
        }
        let bad = got.pop().unwrap().unwrap_err();
        let ok = got.pop().unwrap();
        (ok.map(|k| (k, home)), bad)
    });
    let (kdc, home) = ok.unwrap();
    assert_eq!(kdc, home);
    assert_eq!(bad.message(), REFUSED);
    let e = events.lock().unwrap().clone();
    assert!(!e.iter().any(|l| l.starts_with("locate")), "{e:?}");
    assert!(!e.iter().any(|l| l.starts_with("rediscover")), "{e:?}");
}

/// The located controllers fail the check: the locator is asked once
/// more, and a new one inside the domain is checked before the domain's
/// name; one outside it never is.
#[test]
fn a_rediscovered_controller_is_checked_once() {
    let events: Events = Arc::default();
    let (ok, outside) = rt().block_on(async {
        let home = kdc("home", referral("NORTH.CONTOSO.LOCAL"), events.clone()).await;
        let child = kdc("child", cifs("ws01.north.contoso.local"), events.clone()).await;
        let fresh = FakeDc {
            found: vec!["dc1.contoso.local".into()],
            verified: vec![("dc7.contoso.local".into(), Ok(home.clone()))],
            events: events.clone(),
            again: vec!["dc1.contoso.local".into(), "dc7.contoso.local".into()],
        };
        let child2 = child.clone();
        let ok = own_then_ticket(
            &fresh,
            "contoso.local",
            "north.contoso.local",
            "WS01.NORTH.CONTOSO.LOCAL",
            &move |_| child2.clone(),
            "fresh",
        )
        .await;
        let spoofed = FakeDc {
            found: vec!["dc1.contoso.local".into()],
            verified: vec![("dc.attacker.example".into(), Ok(home.clone()))],
            events: events.clone(),
            again: vec!["dc.attacker.example".into()],
        };
        let outside = own_then_ticket(
            &spoofed,
            "contoso.local",
            "fabrikam.com",
            "X.Y",
            &move |_| child.clone(),
            "spoofed",
        )
        .await;
        (ok, outside)
    });
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(outside.unwrap_err(), REFUSED);
    let e = events.lock().unwrap().clone();
    let checks: Vec<&String> = e
        .iter()
        .filter(|l| l.starts_with("verify") || l.starts_with("rediscover"))
        .collect();
    assert_eq!(
        checks,
        [
            "verify dc1.contoso.local contoso.local skip=false",
            "rediscover contoso.local",
            "verify dc7.contoso.local contoso.local skip=false",
            "verify dc1.contoso.local contoso.local skip=false",
            "rediscover contoso.local",
        ],
        "dc1 checked once each run; the outside name never"
    );
    assert_eq!(e.iter().filter(|l| l.contains(": AS ")).count(), 1, "{e:?}");
}

/// The real LDAPS check against something that isn't a TLS LDAP server
/// fails, and the AS-REQ is never sent.
#[test]
fn the_real_ldaps_check_fails_closed() {
    struct Real {
        port: u16,
        kdc: String,
    }
    impl OwnRealmDc for Real {
        fn locate(&self, _: &str, _: &mut dyn FnMut(String)) -> Vec<String> {
            Vec::new()
        }
        fn verify<'a>(&'a self, host: &'a str, realm: &'a str, skip: bool) -> Verifying<'a> {
            Box::pin(async move {
                ownrealm::verify_ldaps(host, self.port, realm, skip).await?;
                Ok(self.kdc.clone())
            })
        }
    }
    let events: Events = Arc::default();
    let (e, direct) = rt().block_on(async {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"HTTP/1.0 400 Bad Request\r\n\r\n").await;
            }
        });
        let direct = ownrealm::verify_ldaps("127.0.0.1", port, "contoso.local", false).await;
        let kdc = kdc("home", referral("X"), events.clone()).await;
        // Named, so the address is used as given.
        let e = ownrealm::own_realm_ticket(
            &Real { port, kdc },
            "contoso.local",
            Some("127.0.0.1"),
            "fabrikam.com",
            "svc",
            &Secret::new(PASSWORD),
            false,
            &|_| {},
        )
        .await
        .map(|_| ())
        .unwrap_err();
        (e, direct)
    });
    assert!(direct.is_err(), "{direct:?}");
    assert_eq!(e.problem, Problem::NoTicket);
    assert!(
        e.message().contains("passed the domain controller check"),
        "{e}"
    );
    assert!(events.lock().unwrap().is_empty(), "no AS-REQ");
}

/// The production check's KDC: the address checked, port 88.
#[test]
fn the_kdc_is_the_address_checked() {
    let v4: std::net::SocketAddr = "10.0.0.5:636".parse().unwrap();
    assert_eq!(ownrealm::kdc_address(v4), "10.0.0.5:88");
    let v6: std::net::SocketAddr = "[fd00::5]:636".parse().unwrap();
    assert_eq!(ownrealm::kdc_address(v6), "[fd00::5]:88");
}

/// Between the account's domain and the collected one, a referral loop or
/// a hop that doesn't check out is refused.
#[test]
fn a_referral_loop_or_a_bad_hop_is_refused() {
    let run = |child_rep: Rep, tag: &'static str| {
        let events: Events = Arc::default();
        rt().block_on(async move {
            let parent = kdc("parent", referral("NORTH.CONTOSO.LOCAL"), events.clone()).await;
            let child = kdc("child", answer(child_rep), events.clone()).await;
            let dc = FakeDc::one("dc01.contoso.local", Ok(parent), &events);
            own_then_ticket(
                &dc,
                "contoso.local",
                "north.contoso.local",
                "DC01.NORTH.CONTOSO.LOCAL",
                &move |_: &str| child.clone(),
                tag,
            )
            .await
        })
    };
    // The child refers back to the parent.
    let e = run(
        Rep::new(&["krbtgt", "CONTOSO.LOCAL"], &[2u8; 32], &[4u8; 32], 2),
        "loop",
    )
    .unwrap_err();
    assert!(
        e.contains("through CONTOSO.LOCAL, NORTH.CONTOSO.LOCAL"),
        "{e}"
    );
    // The child's answer isn't under the referral's session key.
    let e = run(
        Rep::new(
            &["cifs", "dc01.north.contoso.local"],
            &[9u8; 32],
            &[3u8; 32],
            2,
        ),
        "key",
    )
    .unwrap_err();
    assert!(
        e.contains("the ticket for cifs/DC01.NORTH.CONTOSO.LOCAL"),
        "{e}"
    );
    // A ticket for another computer.
    let e = run(
        Rep::new(
            &["cifs", "evil.north.contoso.local"],
            &[2u8; 32],
            &[3u8; 32],
            2,
        ),
        "other",
    )
    .unwrap_err();
    assert!(e.contains("not cifs/DC01.NORTH.CONTOSO.LOCAL"), "{e}");
}

/// A trust that allows only RC4 between the account's domain and the
/// collected one: the computers are skipped with the Kerberos-only words.
#[test]
fn an_rc4_only_trust_is_skipped() {
    let events: Events = Arc::default();
    let e = rt().block_on(async {
        let parent = kdc(
            "parent",
            Box::new(|_| krb::fake::error(14, 0, None)),
            events.clone(),
        )
        .await;
        let dc = FakeDc::one("dc01.contoso.local", Ok(parent), &events);
        own_then_ticket(
            &dc,
            "contoso.local",
            "north.contoso.local",
            "WS01.NORTH.CONTOSO.LOCAL",
            &|r: &str| r.to_string(),
            "rc4",
        )
        .await
        .unwrap_err()
    });
    assert_eq!(
        e,
        "the trust to its domain allows only RC4 (between contoso.local and \
         north.contoso.local; set the trust to use AES)"
    );
    let why = krb::NoTicket::Rc4Trust("between contoso.local and north.contoso.local".into());
    assert_eq!(
        through_the_trust("north.contoso.local", &why),
        "The trust to north.contoso.local allows only RC4, so its computers will be \
         skipped. Set the trust to use AES."
    );
}

fn foreign_request(domain: &str, user: &str, ldaps: bool) -> CollectRequest {
    let mut req = CollectRequest::new(domain, "out");
    req.auth = Auth::Password {
        user: user.into(),
        password: Secret::new(PASSWORD),
    };
    req.ldaps = ldaps;
    req.allow_unencrypted_ldap = !ldaps;
    req.scope = Scope::All;
    req
}

fn job_with(req: &CollectRequest, dc: FakeDc) -> Job {
    let mut job = job_for(req, CollectionMethod::All).unwrap();
    job.own_realm_dc = Arc::new(dc);
    job
}

/// The collection's Kerberos only with an account from another domain and
/// no run ticket: the TGT from the account's own domain (its controller
/// checked), kept for the run, and the computers' tickets asked of that
/// controller; no password left for the modules.
#[test]
fn kerberos_only_uses_the_accounts_own_domain() {
    let events: Events = Arc::default();
    let req = foreign_request("north.contoso.local", r"CONTOSO\svc", true);
    let mut options = base_options(
        "north.contoso.local",
        std::path::Path::new("out"),
        CollectionMethod::All,
        "dc01.north.contoso.local".into(),
        true,
    );
    options.username = Some(r"CONTOSO\svc".into());
    options.password = Some(PASSWORD.into());
    let mut smb = hosts::SmbIdentity {
        domain: "CONTOSO".into(),
        other_domain: true,
        kerberos: None,
    };
    let _env = super::KRB_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let lines = Mutex::new(Vec::new());
    let (home_kdc, file, sign_in) = rt().block_on(async {
        let home = kdc("parent", referral("X"), events.clone()).await;
        let job = job_with(&req, FakeDc::one("dc01.contoso.local", Ok(home), &events));
        let guard = kerberos_hosts(
            &job,
            "dc01.north.contoso.local",
            Some(r"u:CONTOSO\svc"),
            Ok(Some("contoso.local".into())),
            &mut smb,
            &mut options,
            &|l| lines.lock().unwrap().push(l),
        )
        .await
        .expect("the account's own domain's ticket");
        let k = smb.kerberos.clone().expect("Kerberos only");
        assert_eq!(std::env::var("KRB5CCNAME").ok(), Some(k.ccache.clone()));
        let t = krbref::read_cache(&k.ccache).unwrap();
        assert_eq!(
            (t.realm.as_str(), t.user.as_str()),
            ("CONTOSO.LOCAL", "svc")
        );
        drop(guard);
        (k.kdc, k.ccache, job.sign_in.clone())
    });
    assert!(home_kdc.starts_with("127.0.0.1:"), "{home_kdc}");
    assert!(
        options.kerberos && options.password.is_none(),
        "no password for the modules"
    );
    let home = sign_in.home().expect("kept for the run");
    assert_eq!(home.realm, "CONTOSO.LOCAL");
    assert_eq!(home.who, r"CONTOSO\svc");
    drop(home);
    let lines = lines.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("checked over LDAPS: a domain controller of contoso.local")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("used through the trust to north.contoso.local")),
        "{lines:?}"
    );
    assert_eq!(
        events.lock().unwrap()[..3],
        [
            "locate contoso.local",
            "verify dc01.contoso.local contoso.local skip=false",
            "parent: AS CONTOSO.LOCAL",
        ]
    );
    let path = file.trim_start_matches("FILE:").to_string();
    drop(sign_in);
    assert!(!std::path::Path::new(&path).exists());
}

/// Over plain LDAP, or with the account's domain refused, Kerberos only
/// with an account from another domain stops before anything is asked.
#[test]
fn no_foreign_ticket_over_plain_ldap_or_a_refused_domain() {
    let events: Events = Arc::default();
    let refusals = rt().block_on(async {
        let home = kdc("home", referral("X"), events.clone()).await;
        let mut out = Vec::new();
        for (ldaps, realm) in [
            (false, Ok(Some("contoso.local".to_string()))),
            (
                true,
                Err(ownrealm::not_trusted(
                    "contoso.local",
                    "north.contoso.local",
                )),
            ),
        ] {
            let req = foreign_request("north.contoso.local", r"CONTOSO\svc", ldaps);
            let job = job_with(
                &req,
                FakeDc::one("dc01.contoso.local", Ok(home.clone()), &events),
            );
            let mut smb = hosts::SmbIdentity {
                domain: "CONTOSO".into(),
                other_domain: true,
                kerberos: None,
            };
            let mut o = base_options(
                "north.contoso.local",
                std::path::Path::new("out"),
                CollectionMethod::All,
                "dc01.north.contoso.local".into(),
                ldaps,
            );
            let e = kerberos_hosts(&job, "dc", None, realm, &mut smb, &mut o, &|_| {})
                .await
                .err()
                .expect("refused");
            out.push(e.message());
        }
        out
    });
    assert_eq!(
        refusals[0],
        "Kerberos didn't work: an account from another domain needs LDAPS, so its domain is \
         read from a checked connection. Turn on LDAPS, or use an account from \
         north.contoso.local."
    );
    assert!(
        refusals[1].contains("north.contoso.local doesn't trust the account's domain"),
        "{}",
        refusals[1]
    );
    assert!(events.lock().unwrap().is_empty(), "nothing asked");
}

/// The check with an account from another domain: the TGT from its own
/// domain, then the collected controller's ticket through the trust; an
/// RC4-only trust is a warning, a refused domain an error with nothing
/// asked.
#[test]
fn the_check_gets_the_ticket_from_the_accounts_own_domain() {
    let events: Events = Arc::default();
    let (ok, rc4, refused) = rt().block_on(async {
        // The collected controller is in the account's own domain here, so
        // its ticket comes straight from the home KDC (no referral by DNS).
        let home = kdc(
            "home",
            answer(Rep::new(
                &["cifs", "dc02.contoso.local"],
                &TGT_KEY,
                &[3u8; 32],
                2,
            )),
            events.clone(),
        )
        .await;
        let req = foreign_request("fabrikam.com", r"CONTOSO\svc", true);
        let job = job_with(
            &req,
            FakeDc::one("dc01.contoso.local", Ok(home.clone()), &events),
        );
        let pw = Secret::new(PASSWORD);
        let ok = check_foreign(
            &job,
            Ok("contoso.local".into()),
            Some(r"u:CONTOSO\svc"),
            r"CONTOSO\svc",
            &pw,
            "DC02.CONTOSO.LOCAL",
        )
        .await;
        let no = kdc(
            "rc4",
            Box::new(|_| krb::fake::error(14, 0, None)),
            events.clone(),
        )
        .await;
        let job = job_with(&req, FakeDc::one("dc01.contoso.local", Ok(no), &events));
        let rc4 = check_foreign(
            &job,
            Ok("contoso.local".into()),
            None,
            r"CONTOSO\svc",
            &pw,
            "dc01.fabrikam.com",
        )
        .await;
        let before = events.lock().unwrap().len();
        let refused = check_foreign(
            &job,
            Err(ownrealm::account_domain_unknown("CONTOSO", "fabrikam.com")),
            None,
            r"CONTOSO\svc",
            &pw,
            "dc01.fabrikam.com",
        )
        .await
        .err()
        .map(|e| (e.message(), events.lock().unwrap().len() == before));
        (ok, rc4, refused)
    });
    let (line, warning) = ok.unwrap();
    assert_eq!(
        line,
        r"Got a Kerberos ticket for CONTOSO\svc from a domain controller of contoso.local."
    );
    assert_eq!(warning, None);
    let (_, warning) = rc4.unwrap();
    assert_eq!(
        warning.as_deref(),
        Some(
            "The trust to fabrikam.com allows only RC4, so its computers will be skipped. Set \
             the trust to use AES."
        )
    );
    let (message, quiet) = refused.unwrap();
    assert!(
        message.contains("child domain of a trusted forest aren't supported yet"),
        "{message}"
    );
    assert!(quiet, "nothing asked");
}

fn nb(dns: &str, netbios: &str) -> NetbiosName {
    NetbiosName {
        dns: dns.into(),
        netbios: netbios.into(),
    }
}

/// The account's domain comes from what the collected domain's directory
/// names (the forest's partitions, or a trust it gives), by NetBIOS or DNS
/// name; a DNS domain typed in the user name must be the one found.
#[test]
fn the_accounts_domain_comes_from_the_directory() {
    let forest = [nb("Contoso.Local.", "CONTOSO"), nb("not a name", "BAD")];
    let trusts = [
        Trust {
            name: nb("fabrikam.com", "FABRIKAM"),
            outbound: true,
        },
        Trust {
            name: nb("evil.example", "EVIL"),
            outbound: false,
        },
    ];
    let pick = |account: &str, typed: Option<&str>| {
        ownrealm::pick_realm(account, typed, &forest, &trusts, "north.contoso.local")
            .map_err(|e| e.message())
    };
    assert_eq!(pick("contoso", None).as_deref(), Ok("contoso.local"));
    assert_eq!(pick("FABRIKAM.COM.", None).as_deref(), Ok("fabrikam.com"));
    assert_eq!(
        pick("FABRIKAM", Some("fabrikam.com")).as_deref(),
        Ok("fabrikam.com")
    );
    // A trust the collected domain doesn't give (inbound only).
    assert!(pick("EVIL", None)
        .unwrap_err()
        .contains("north.contoso.local doesn't trust the account's domain (evil.example)"));
    // A typed DNS domain other than the one found: a steered realm.
    assert_eq!(
        pick("FABRIKAM", Some("contoso.local")).unwrap_err(),
        r"Kerberos didn't work: the user name gives the domain contoso.local, but the directory places the account in fabrikam.com. Give the user name as DOMAIN\user, or use an account from north.contoso.local."
    );
    for unknown in ["NORTH", "BAD", " "] {
        assert!(
            pick(unknown, None)
                .unwrap_err()
                .contains("isn't in north.contoso.local's forest"),
            "{unknown}"
        );
    }
    assert_eq!(
        ownrealm::typed_dns_domain("svc@Fabrikam.COM").as_deref(),
        Some("fabrikam.com")
    );
    assert_eq!(
        ownrealm::typed_dns_domain(r"contoso.local\svc").as_deref(),
        Some("contoso.local")
    );
    assert_eq!(ownrealm::typed_dns_domain(r"CONTOSO\svc"), None);
    assert_eq!(ownrealm::typed_dns_domain("svc"), None);
}

/// A `trustedDomain` entry as the directory returns it: the direction's
/// outbound bit decides.
#[test]
fn trust_entries_are_read_with_their_direction() {
    let entry = |dir: &str| {
        let mut a = std::collections::HashMap::new();
        a.insert("flatName".to_string(), vec!["FABRIKAM".to_string()]);
        a.insert("trustPartner".to_string(), vec!["fabrikam.com".to_string()]);
        if !dir.is_empty() {
            a.insert("trustDirection".to_string(), vec![dir.to_string()]);
        }
        trust_entry(&a)
    };
    for (dir, outbound) in [
        ("1", false),
        ("2", true),
        ("3", true),
        ("x", false),
        ("", false),
    ] {
        let t = entry(dir).unwrap();
        assert_eq!(t.outbound, outbound, "{dir}");
        assert_eq!(t.name.dns, "fabrikam.com");
    }
    let mut a = std::collections::HashMap::new();
    a.insert("flatName".to_string(), vec!["X".to_string()]);
    assert!(trust_entry(&a).is_none(), "no trustPartner");
}

/// [`ownrealm::MAX_TRIED`] checks in all. Rediscovered names fill the
/// slots the located ones left; when those used all three, one more. None
/// located: rediscovered ones, else the domain's name.
#[test]
fn rediscovered_controllers_fill_the_slots_left() {
    let events: Events = Arc::default();
    let fails = |found: &[&str], again: &[&str]| FakeDc {
        found: found.iter().map(|s| s.to_string()).collect(),
        verified: Vec::new(),
        events: events.clone(),
        again: again.iter().map(|s| s.to_string()).collect(),
    };
    let runs = [
        // One located: two slots left for the rediscovered.
        fails(
            &["dc1.contoso.local"],
            &[
                "dc5.contoso.local",
                "dc6.contoso.local",
                "dc7.contoso.local",
            ],
        ),
        // Three located: one more.
        fails(
            &[
                "dc1.contoso.local",
                "dc2.contoso.local",
                "dc3.contoso.local",
            ],
            &["dc5.contoso.local", "dc6.contoso.local"],
        ),
        // None located, none rediscovered: the domain's name.
        fails(&[], &[]),
        // None located, one rediscovered: it, not the domain's name.
        fails(&[], &["dc5.contoso.local"]),
    ];
    let mut checks = Vec::new();
    rt().block_on(async {
        for dc in &runs {
            let e = ownrealm::own_realm_ticket(
                dc,
                "contoso.local",
                None,
                "fabrikam.com",
                "svc",
                &Secret::new(PASSWORD),
                false,
                &|_| {},
            )
            .await
            .map(|_| ())
            .unwrap_err();
            assert_eq!(e.message(), REFUSED);
            let mut ev = events.lock().unwrap();
            checks.push(
                ev.iter()
                    .filter(|l| l.starts_with("verify") || l.starts_with("rediscover"))
                    .map(|l| l.replace(" contoso.local skip=false", ""))
                    .collect::<Vec<_>>(),
            );
            ev.clear();
        }
    });
    assert_eq!(
        checks,
        [
            vec![
                "verify dc1.contoso.local",
                "rediscover contoso.local",
                "verify dc5.contoso.local",
                "verify dc6.contoso.local",
            ],
            vec![
                "verify dc1.contoso.local",
                "verify dc2.contoso.local",
                "verify dc3.contoso.local",
                "rediscover contoso.local",
                "verify dc5.contoso.local",
            ],
            vec!["rediscover contoso.local", "verify contoso.local"],
            vec!["rediscover contoso.local", "verify dc5.contoso.local"],
        ]
    );
}
