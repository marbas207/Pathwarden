//! Kerberos only and required SMB signing around the computer-contacting
//! modules, for a Full collection and a retest's computers.
//!
//! - [`precheck`]: before any computer is contacted, its `cifs/<name>`
//!   ticket is asked for. A computer the domain has no Kerberos name for is
//!   skipped: left out of every module (never connected to, not even on port
//!   445), its sessions recorded as not collected with the reason, and named
//!   in the log.
//! - [`relay`]: the modules' KDC, a relay on 127.0.0.1 that checks their
//!   service tickets and follows referrals for them.
//! - [`unsigned`]: after a module, a computer whose replies weren't signed
//!   (the patched SMB client refused them) is recorded as skipped for that
//!   reason and left out of the modules after it.
//! - [`registry_sessions`]: RustHound-CE reads Remote Registry sessions with
//!   an NTLM bind only, so with Kerberos it leaves them not collected; they
//!   are read here over the Kerberos SMB session instead ([`super::krbreg`]).
//! - [`warnings`]: one line per reason for the collection's warnings.

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use rusthound_ce::api::ADResults;
use rusthound_ce::objects::computer::Computer;

use super::hosts::{self, KerberosSignIn};
use super::krb::{self, NoTicket};
use super::Msg;

/// Computers asked about at once.
const AT_ONCE: usize = 16;
/// How long one computer's Remote Registry read may take.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long Remote Registry gets to start before it is asked again.
const REGISTRY_START: Duration = Duration::from_secs(3);
/// Computers whose account password is older than this aren't contacted
/// (as the modules do).
const EXPIRY_DAYS: i64 = 60;
/// After this many computers of a realm whose KDC couldn't be reached (no
/// connection, no answer; not a KDC error), its other computers aren't
/// asked about.
const TRIPS: usize = 3;

/// Why a computer was left out of the modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Skip {
    /// The domain has no Kerberos name for it.
    NoName,
    /// Its replies weren't signed.
    Unsigned,
    /// A reply answered another request (replayed or misdirected).
    BadReply,
    /// In another domain, behind a trust that allows only RC4.
    Rc4Trust,
    /// Its domain's (the realm's) KDC couldn't be reached.
    Unreachable(String),
    /// The KDC refused its ticket otherwise (not a skip in the counts: a
    /// computer not read, as an unreachable one).
    Refused,
}

/// The computers left out of the modules, by object ID.
pub(crate) type Skipped = HashMap<String, Skip>;

fn log(tx: &mpsc::Sender<Msg>, line: String) {
    let _ = tx.send(Msg::Log(line));
}

/// A computer's realm: its DNS name's domain, upper case.
fn realm_of(host: &str) -> String {
    host.split_once('.')
        .map_or(host, |(_, d)| d)
        .to_ascii_uppercase()
}

/// Why a computer was skipped when its realm's KDC couldn't be reached.
fn unreachable_words(realm: &str) -> String {
    format!("couldn't reach {realm}'s domain controller for Kerberos")
}

/// Asks each computer the modules will contact (enabled, password changed
/// in the last 60 days, `want` says so) for its `cifs/` ticket; records and
/// returns the ones that get none. A trusted domain's computers are
/// asked the same way, through the trust: the modules get their tickets
/// through the KDC relay ([`relay`]), which follows the referral too.
/// After [`TRIPS`] computers of one realm whose KDC couldn't be reached,
/// that realm's other computers are skipped unasked, all with one reason.
pub(crate) async fn precheck(
    k: &KerberosSignIn,
    computers: &mut [Computer],
    want: &dyn Fn(&Computer) -> bool,
    tx: &mpsc::Sender<Msg>,
) -> Skipped {
    let sem = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    let mut set = tokio::task::JoinSet::new();
    // Every computer asked about, until its answer comes back: one whose
    // task never answers (a panic) is refused, never let through.
    let mut pending: HashMap<usize, String> = HashMap::new();
    // Per realm, the computers whose KDC couldn't be reached.
    let failed: Arc<std::sync::Mutex<HashMap<String, usize>>> = Arc::default();
    for (i, c) in computers.iter().enumerate() {
        let host = c.properties().name().clone();
        if host.is_empty() || !c.is_active(EXPIRY_DAYS) || !want(c) {
            continue;
        }
        pending.insert(i, host.clone());
        let (sem, ccache, kdc) = (sem.clone(), k.ccache.clone(), k.kdc.clone());
        let failed = failed.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let realm = realm_of(&host);
            let tripped = failed
                .lock()
                .map(|f| f.get(&realm).copied().unwrap_or(0) >= TRIPS)
                .unwrap_or(false);
            if tripped {
                return (i, host, Err(NoTicket::Unreachable(String::new())));
            }
            let r = krb::service_ticket(&ccache, &host, &kdc).await.map(|_| ());
            if matches!(r, Err(NoTicket::Unreachable(_))) {
                if let Ok(mut f) = failed.lock() {
                    *f.entry(realm).or_insert(0) += 1;
                }
            }
            (i, host, r)
        });
    }
    let mut answers = Vec::new();
    while let Some(done) = set.join_next().await {
        if let Ok((i, host, r)) = done {
            pending.remove(&i);
            if let Err(why) = r {
                answers.push((i, host, why));
            }
        }
    }
    answers.extend(pending.into_iter().map(|(i, host)| {
        (
            i,
            host,
            NoTicket::Refused("Kerberos: asking for the ticket stopped unexpectedly".into()),
        )
    }));
    answers.sort_by_key(|(i, _, _)| *i);
    let mut out = Skipped::new();
    for (i, host, why) in answers {
        let c = &mut computers[i];
        let (skip, reason) = match &why {
            NoTicket::NoName(_) => (Skip::NoName, why.reason(&host)),
            NoTicket::Rc4Trust(_) => (Skip::Rc4Trust, why.reason(&host)),
            NoTicket::Unreachable(d) => {
                let realm = realm_of(&host);
                let words = unreachable_words(&realm);
                let reason = if d.is_empty() {
                    format!("{host}: skipped: {words}")
                } else {
                    format!("{host}: skipped: {words} ({d})")
                };
                (Skip::Unreachable(realm), reason)
            }
            NoTicket::Refused(_) => (Skip::Refused, why.reason(&host)),
        };
        log(tx, format!("[hosts] {reason}."));
        hosts::set_all_not_collected(c, &reason);
        out.insert(c.object_identifier().clone(), skip);
    }
    out
}

/// Starts the modules' KDC relay for `k`'s ticket: RustHound-CE's
/// modules get their service tickets through it, checked, and across a
/// trust. What it refuses goes to the log. If it can't start, no computer
/// is contacted.
pub(crate) async fn relay(
    k: &KerberosSignIn,
    tx: &mpsc::Sender<Msg>,
) -> Result<super::krbrelay::KdcRelay, String> {
    let to_log = tx.clone();
    let relay = super::krbrelay::KdcRelay::start(
        &k.ccache,
        &k.kdc,
        Arc::new(move |line| {
            let _ = to_log.send(Msg::Log(line));
        }),
    )
    .await
    .map_err(|e| {
        format!(
            "the Kerberos relay for the modules couldn't start, so no computer was contacted \
             ({e})"
        )
    })?;
    log(
        tx,
        format!(
            "[hosts] The modules get their Kerberos tickets through a relay on {}, checked.",
            relay.addr()
        ),
    );
    Ok(relay)
}

/// Refuses to run RustHound-CE's modules with `--kerberos` unless
/// `KRB5CCNAME` names the ticket cache: without it they would sign in with
/// the (empty) password, over NTLM.
pub(crate) fn ccache_ready(k: &KerberosSignIn) -> Result<(), String> {
    match std::env::var("KRB5CCNAME") {
        Ok(v) if v == k.ccache => Ok(()),
        _ => Err(
            "the Kerberos ticket cache isn't set for the modules, so no computer was \
                  contacted"
                .into(),
        ),
    }
}

/// Takes the computers in `skipped` out of `ad` (for the modules), with
/// their places.
pub(crate) fn take(ad: &mut ADResults, skipped: &Skipped) -> Vec<(usize, Computer)> {
    if skipped.is_empty() {
        return Vec::new();
    }
    let (out, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut ad.computers)
        .into_iter()
        .enumerate()
        .partition(|(_, c)| skipped.contains_key(c.object_identifier().as_str()));
    ad.computers = keep.into_iter().map(|(_, c)| c).collect();
    out
}

/// Puts back what [`take`] took, in their places.
pub(crate) fn put_back(ad: &mut ADResults, taken: Vec<(usize, Computer)>) {
    for (i, c) in taken {
        let at = i.min(ad.computers.len());
        ad.computers.insert(at, c);
    }
}

/// After a module: the computers whose replies weren't signed (a session
/// list's reason says so, or one of `errors`, the module's log, names the
/// computer and says so) are recorded as skipped for it.
pub(crate) fn unsigned(
    computers: &mut [Computer],
    errors: &[String],
    skipped: &mut Skipped,
    tx: &mpsc::Sender<Msg>,
) {
    for c in computers.iter_mut() {
        let id = c.object_identifier().clone();
        if skipped.contains_key(id.as_str()) {
            continue;
        }
        let host = c.properties().name().clone();
        let bad = |r: &str| r.contains(hosts::UNSIGNED_REPLY) || r.contains(hosts::OTHER_REPLY);
        let from_lists = hosts::session_reasons(c).into_iter().find(|r| bad(r));
        let from_log = || {
            errors
                .iter()
                .find(|e| {
                    bad(e)
                        && e.trim()
                            .get(..host.len())
                            .is_some_and(|h| !host.is_empty() && h.eq_ignore_ascii_case(&host))
                })
                .cloned()
        };
        let Some(error) = from_lists.or_else(from_log) else {
            continue;
        };
        let detail = error
            .find("SMB2 ")
            .map(|at| error[at..].trim().to_string())
            .unwrap_or_else(|| error.trim().to_string());
        // A reply to another request (replayed or misdirected) has its own
        // words; still a skip.
        let (reason, skip) = if error.contains(hosts::OTHER_REPLY) {
            (hosts::skipped_bad_reply(&host, &detail), Skip::BadReply)
        } else {
            (hosts::skipped_unsigned(&host, &detail), Skip::Unsigned)
        };
        log(tx, format!("[hosts] {reason}."));
        hosts::set_all_not_collected(c, &reason);
        skipped.insert(id, skip);
    }
}

/// The Remote Registry sessions RustHound-CE left unread for want of an
/// NTLM bind, read over the Kerberos SMB session (`domain`, `user`: the
/// SMB sign-in's, for its log lines). Only computers the sessions module
/// signed in to are asked. Remote Registry still starting is asked again
/// once, a moment later. With `services` (the services step's end),
/// each computer's services are read on the same pipe right after its
/// sessions; what was read is returned by object ID.
pub(crate) async fn registry_sessions(
    k: &KerberosSignIn,
    domain: &str,
    user: &str,
    computers: &mut [Computer],
    skipped: &Skipped,
    services: Option<std::time::Instant>,
    tx: &mpsc::Sender<Msg>,
) -> HashMap<String, super::storedcreds::HostRead> {
    let mut read_services = HashMap::new();
    const NEEDS_NTLM: &str = "MS-RRP bind needs a password";
    let mut ask: Vec<(usize, String)> = Vec::new();
    for (i, c) in computers.iter_mut().enumerate() {
        if skipped.contains_key(c.object_identifier().as_str())
            || *c.registry_sessions_mut().collected()
        {
            continue;
        }
        let unread = c
            .registry_sessions_mut()
            .failure_reason()
            .as_deref()
            .is_some_and(|r| r.contains(NEEDS_NTLM));
        if unread && hosts::reached(c) {
            ask.push((i, c.properties().name().clone()));
        }
    }
    if ask.is_empty() {
        return read_services;
    }
    log(
        tx,
        format!(
            "[sessions] reading Remote Registry sessions over Kerberos on {}",
            pathwarden_core::text::count(ask.len(), "computer", "computers")
        ),
    );
    for attempt in 0..2 {
        if ask.is_empty() {
            break;
        }
        if attempt > 0 {
            log(
                tx,
                format!(
                    "[sessions] Remote Registry was starting on {}; asking again in {}s",
                    pathwarden_core::text::count(ask.len(), "computer", "computers"),
                    REGISTRY_START.as_secs()
                ),
            );
            tokio::time::sleep(REGISTRY_START).await;
        }
        let sem = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
        let mut set = tokio::task::JoinSet::new();
        for (i, host) in std::mem::take(&mut ask) {
            let (sem, ccache, kdc) = (sem.clone(), k.ccache.clone(), k.kdc.clone());
            let (domain, user) = (domain.to_string(), user.to_string());
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                let (read, stored) = match services {
                    None => (
                        tokio::time::timeout(
                            REGISTRY_TIMEOUT,
                            super::krbreg::registry_sessions(&host, &ccache, &kdc, &domain, &user),
                        )
                        .await
                        .unwrap_or_else(|_| Err(format!("{host} WINREG: per-host timeout"))),
                        None,
                    ),
                    Some(until) => tokio::time::timeout(
                        REGISTRY_TIMEOUT + super::storedcreds::PER_HOST,
                        super::storedcreds::sessions_and_services(
                            &host, &ccache, &kdc, &domain, &user, until,
                        ),
                    )
                    .await
                    .map(|(r, s)| (r, Some(s)))
                    .unwrap_or_else(|_| (Err(format!("{host} WINREG: per-host timeout")), None)),
                };
                (i, host, read, stored)
            });
        }
        while let Some(done) = set.join_next().await {
            let Ok((i, host, read, stored)) = done else {
                continue;
            };
            let starting = read
                .as_ref()
                .is_err_and(|e| e.to_ascii_lowercase().contains("0xc00000ac"));
            if starting && attempt == 0 {
                ask.push((i, host));
                continue;
            }
            if let Err(e) = &read {
                log(tx, format!("warning: [sessions] {e}"));
            }
            if let Some(s) = stored {
                read_services.insert(computers[i].object_identifier().clone(), s);
            }
            hosts::set_registry_sessions(&mut computers[i], read);
        }
    }
    read_services
}

/// One warning per reason computers were skipped, as the collection's
/// warnings say it.
pub(crate) fn warnings(skipped: &Skipped) -> Vec<String> {
    let count = |s: Skip| skipped.values().filter(|v| **v == s).count();
    let mut out = Vec::new();
    let line = |n: usize, why_one: &str, why_many: &str| {
        if n == 1 {
            format!("1 computer was skipped: {why_one}. The collection log names it.")
        } else {
            format!(
                "{} computers were skipped: {why_many}. The collection log names each one.",
                pathwarden_core::report::num(n)
            )
        }
    };
    let n = count(Skip::NoName);
    if n > 0 {
        out.push(line(
            n,
            "the domain has no Kerberos name for it",
            "the domain has no Kerberos name for them",
        ));
    }
    let n = count(Skip::Unsigned);
    if n > 0 {
        out.push(line(
            n,
            "its replies weren't signed",
            "their replies weren't signed",
        ));
    }
    let n = count(Skip::BadReply);
    if n > 0 {
        out.push(line(
            n,
            "its replies didn't answer Pathwarden's requests",
            "their replies didn't answer Pathwarden's requests",
        ));
    }
    let n = count(Skip::Rc4Trust);
    if n > 0 {
        out.push(line(
            n,
            "the trust to its domain allows only RC4",
            "the trust to their domain allows only RC4",
        ));
    }
    // A realm whose KDC couldn't be reached, per realm.
    let mut realms: Vec<&String> = skipped
        .values()
        .filter_map(|s| match s {
            Skip::Unreachable(r) => Some(r),
            _ => None,
        })
        .collect();
    realms.sort();
    realms.dedup();
    for realm in realms {
        let n = count(Skip::Unreachable(realm.clone()));
        let words = unreachable_words(realm);
        let words = format!("{}{}", words[..1].to_uppercase(), &words[1..]);
        out.push(if n == 1 {
            format!("1 computer was skipped. {words}. The collection log names it.")
        } else {
            format!(
                "{} computers were skipped. {words}. The collection log names each one.",
                pathwarden_core::report::num(n)
            )
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn computer(name: &str, sid: &str) -> Computer {
        let mut v = serde_json::to_value(Computer::default()).unwrap();
        v["Properties"]["name"] = name.into();
        v["Properties"]["is_dc"] = false.into();
        v["ObjectIdentifier"] = sid.into();
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn skipped_ones_go_out_and_back_in_their_places() {
        let mut ad = ADResults {
            computers: (0..5)
                .map(|i| computer(&format!("WS{i}.CONTOSO.LOCAL"), &format!("S-1-5-21-1-{i}")))
                .collect(),
            ..ADResults::default()
        };
        let skipped: Skipped = [
            ("S-1-5-21-1-1".to_string(), Skip::NoName),
            ("S-1-5-21-1-4".to_string(), Skip::Unsigned),
        ]
        .into();
        let taken = take(&mut ad, &skipped);
        let left: Vec<_> = ad
            .computers
            .iter()
            .map(|c| c.object_identifier().clone())
            .collect();
        assert_eq!(left, ["S-1-5-21-1-0", "S-1-5-21-1-2", "S-1-5-21-1-3"]);
        put_back(&mut ad, taken);
        let all: Vec<_> = ad
            .computers
            .iter()
            .map(|c| c.object_identifier().clone())
            .collect();
        assert_eq!(
            all,
            [
                "S-1-5-21-1-0",
                "S-1-5-21-1-1",
                "S-1-5-21-1-2",
                "S-1-5-21-1-3",
                "S-1-5-21-1-4"
            ]
        );
    }

    /// A computer whose replies weren't signed is recorded as skipped, with
    /// the SMB client's words; the report reads it as such.
    #[test]
    fn unsigned_replies_are_a_skip() {
        let (tx, rx) = mpsc::channel();
        let mut computers = vec![
            computer("NAS1.CONTOSO.LOCAL", "S-1"),
            computer("WS2.CONTOSO.LOCAL", "S-2"),
        ];
        hosts::set_all_not_collected(
            &mut computers[0],
            "NAS1.CONTOSO.LOCAL: tree connect \\\\NAS1.CONTOSO.LOCAL\\IPC$: SMB2 TREE_CONNECT \
             answered without a valid signature",
        );
        hosts::set_all_not_collected(&mut computers[1], "WS2.CONTOSO.LOCAL: 445/tcp unreachable");
        let mut skipped = Skipped::new();
        unsigned(&mut computers, &[], &mut skipped, &tx);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped.get("S-1"), Some(&Skip::Unsigned));
        let why = hosts::session_reasons(&mut computers[0]);
        assert!(why[0].contains(hosts::SKIP_UNSIGNED), "{why:?}");
        assert!(why[0].contains("SMB2 TREE_CONNECT answered without a valid signature"));
        let logged: Vec<_> = rx.try_iter().collect();
        assert_eq!(logged.len(), 1);
        assert_eq!(
            warnings(&skipped),
            ["1 computer was skipped: its replies weren't signed. The collection log names it."]
        );
    }

    /// A name the domain has no Kerberos name for (a fake KDC answers
    /// KDC_ERR_S_PRINCIPAL_UNKNOWN): skipped before any module runs, so it
    /// is never connected to, not even on port 445; the KDC is the only
    /// thing asked. A disabled computer isn't even asked about.
    #[test]
    fn a_computer_without_a_kerberos_name_is_never_contacted() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent = std::env::temp_dir().join(format!("pw-precheck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let active = |name: &str, sid: &str, enabled: bool| {
            let mut v = serde_json::to_value(computer(name, sid)).unwrap();
            v["Properties"]["enabled"] = enabled.into();
            v["Properties"]["is_dc"] = false.into();
            v["Properties"]["pwdlastset"] = (chrono_now() - 86_400).into();
            serde_json::from_value::<Computer>(v).unwrap()
        };
        let (tx, rx) = mpsc::channel();
        let (skipped, asked, left) = rt.block_on(async {
            let (kdc, asked) =
                krb::fake::kdc(krb::fake::error(krb::KDC_ERR_S_PRINCIPAL_UNKNOWN, 0, None)).await;
            let k = KerberosSignIn {
                ccache: cache.name(),
                kdc,
            };
            let mut ad = ADResults {
                computers: vec![
                    active("ROGUE.CONTOSO.LOCAL", "S-1-5-21-1-9", true),
                    active("OLD.CONTOSO.LOCAL", "S-1-5-21-1-8", false),
                ],
                ..ADResults::default()
            };
            let skipped = precheck(&k, &mut ad.computers, &|_| true, &tx).await;
            let _taken = take(&mut ad, &skipped);
            let left: Vec<String> = ad
                .computers
                .iter()
                .map(|c| c.properties().name().clone())
                .collect();
            (
                skipped,
                asked.load(std::sync::atomic::Ordering::SeqCst),
                left,
            )
        });
        assert_eq!(skipped.get("S-1-5-21-1-9"), Some(&Skip::NoName));
        assert_eq!(asked, 1, "only the active computer is asked about");
        assert_eq!(left, ["OLD.CONTOSO.LOCAL"], "the modules never see it");
        let logged: Vec<String> = rx
            .try_iter()
            .filter_map(|m| match m {
                Msg::Log(l) => Some(l),
                _ => None,
            })
            .collect();
        assert_eq!(
            logged,
            [
                "[hosts] ROGUE.CONTOSO.LOCAL: skipped: the domain has no Kerberos name for it (no \
              SPN cifs/ROGUE.CONTOSO.LOCAL)."
            ]
        );
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// A trusted domain of a run: its computers are asked about
    /// through the trust like the first domain's and, with a ticket, go to
    /// the modules (which get theirs through the KDC relay). Behind a
    /// trust that allows only RC4 each is a counted skip with that reason,
    /// never an NTLM fallback.
    #[test]
    fn a_trusted_domains_computers_go_to_the_modules() {
        use super::super::krbrelay_tests::{kdc, requested, Rep};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent = std::env::temp_dir().join(format!("pw-across-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let active = |name: &str, sid: &str| {
            let mut v = serde_json::to_value(computer(name, sid)).unwrap();
            v["Properties"]["enabled"] = true.into();
            v["Properties"]["is_dc"] = false.into();
            v["Properties"]["pwdlastset"] = (chrono_now() - 86_400).into();
            serde_json::from_value::<Computer>(v).unwrap()
        };
        let trusted = || ADResults {
            computers: vec![
                active("WS1.FABRIKAM.COM", "S-1-5-21-2-1"),
                active("WS2.FABRIKAM.COM", "S-1-5-21-2-2"),
            ],
            ..ADResults::default()
        };

        // A ticket for each: none skipped, both for the modules.
        let (tx, rx) = mpsc::channel();
        let (skipped, asked, mut ad) = rt.block_on(async {
            let (kdc, seen) = kdc(Box::new(|req| {
                let host = requested(req);
                Rep::new(&["cifs", &host], &[9u8; 32], &[3u8; 32], 1).make(req)
            }))
            .await;
            let k = KerberosSignIn {
                ccache: cache.name(),
                kdc,
            };
            let mut ad = trusted();
            let skipped = precheck(&k, &mut ad.computers, &|_| true, &tx).await;
            let asked = seen.lock().unwrap().len();
            (skipped, asked, ad)
        });
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(asked, 2, "each computer asked about");
        assert_eq!(rx.try_iter().count(), 0);
        let _taken = take(&mut ad, &skipped);
        assert_eq!(ad.computers.len(), 2, "the modules get both");
        assert!(warnings(&skipped).is_empty());

        // An RC4-only trust: each skipped, counted, with the reason.
        let (tx, rx) = mpsc::channel();
        let (skipped, mut ad) = rt.block_on(async {
            let (kdc, _) = krb::fake::kdc(krb::fake::error(14, 0, None)).await;
            let k = KerberosSignIn {
                ccache: cache.name(),
                kdc,
            };
            let mut ad = trusted();
            let skipped = precheck(&k, &mut ad.computers, &|_| true, &tx).await;
            (skipped, ad)
        });
        assert_eq!(skipped.len(), 2);
        assert!(
            skipped.values().all(|s| *s == Skip::Rc4Trust),
            "{skipped:?}"
        );
        let why = hosts::session_reasons(&mut ad.computers[1]);
        assert!(why[0].starts_with("WS2.FABRIKAM.COM: skipped: "), "{why:?}");
        assert!(why[0].contains(hosts::SKIP_RC4_TRUST), "{why:?}");
        assert_eq!(rx.try_iter().count(), 2, "the log names each one");
        let _taken = take(&mut ad, &skipped);
        assert!(ad.computers.is_empty(), "the modules get none");
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// A realm whose KDC can't be reached (it closes every connection): after
    /// a few computers, the rest of that realm is skipped unasked, every one
    /// counted with one reason.
    #[test]
    fn an_unreachable_realm_is_skipped_after_a_few() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent = std::env::temp_dir().join(format!("pw-breaker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let cache = krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap();
        let active = |name: &str, sid: &str| {
            let mut v = serde_json::to_value(computer(name, sid)).unwrap();
            v["Properties"]["enabled"] = true.into();
            v["Properties"]["is_dc"] = false.into();
            v["Properties"]["pwdlastset"] = (chrono_now() - 86_400).into();
            serde_json::from_value::<Computer>(v).unwrap()
        };
        const MANY: usize = 60;
        let (tx, rx) = mpsc::channel();
        let (skipped, asked) = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let kdc = listener.local_addr().unwrap().to_string();
            let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = asked.clone();
            tokio::spawn(async move {
                // Every connection closed at once: no answer.
                while let Ok((s, _)) = listener.accept().await {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(s);
                }
            });
            let k = KerberosSignIn {
                ccache: cache.name(),
                kdc,
            };
            let mut computers: Vec<Computer> = (0..MANY)
                .map(|i| active(&format!("WS{i}.FABRIKAM.COM"), &format!("S-1-5-21-2-{i}")))
                .collect();
            let skipped = precheck(&k, &mut computers, &|_| true, &tx).await;
            (skipped, asked.load(std::sync::atomic::Ordering::SeqCst))
        });
        assert_eq!(skipped.len(), MANY, "every computer counted");
        assert!(
            skipped
                .values()
                .all(|s| *s == Skip::Unreachable("FABRIKAM.COM".into())),
            "{skipped:?}"
        );
        assert!(
            asked < MANY / 2,
            "the rest of the realm isn't asked about ({asked} asked)"
        );
        let logged: Vec<String> = rx
            .try_iter()
            .filter_map(|m| match m {
                Msg::Log(l) => Some(l),
                _ => None,
            })
            .collect();
        assert_eq!(logged.len(), MANY, "the log names each one");
        assert!(logged.iter().all(
            |l| l.contains("skipped: couldn't reach FABRIKAM.COM's domain controller for Kerberos")
        ));
        assert_eq!(
            warnings(&skipped),
            [format!(
                "{MANY} computers were skipped. Couldn't reach FABRIKAM.COM's domain controller \
                 for Kerberos. The collection log names each one."
            )]
        );
        drop(cache);
        let _ = std::fs::remove_dir_all(&parent);
    }

    fn chrono_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Without KRB5CCNAME naming the cache, the modules aren't run.
    #[test]
    fn the_modules_need_the_ticket_cache_set() {
        let k = KerberosSignIn {
            ccache: "FILE:C:\\not\\this\\one.ccache".into(),
            kdc: "dc01.contoso.local".into(),
        };
        assert!(ccache_ready(&k)
            .unwrap_err()
            .contains("no computer was contacted"));
    }

    /// A reply to another request is a skip in its own words.
    #[test]
    fn a_reply_to_another_request_is_its_own_skip() {
        let (tx, _rx) = mpsc::channel();
        let mut computers = vec![computer("WS3.CONTOSO.LOCAL", "S-3")];
        hosts::set_all_not_collected(
            &mut computers[0],
            "WS3.CONTOSO.LOCAL: tree connect \\\\WS3\\IPC$: SMB2 TREE_CONNECT answered with a \
             reply to another request",
        );
        let mut skipped = Skipped::new();
        unsigned(&mut computers, &[], &mut skipped, &tx);
        assert_eq!(skipped.get("S-3"), Some(&Skip::BadReply));
        let why = hosts::session_reasons(&mut computers[0]);
        assert!(why[0].contains(hosts::SKIP_BAD_REPLY), "{why:?}");
        assert_eq!(
            warnings(&skipped),
            [
                "1 computer was skipped: its replies didn't answer Pathwarden's requests. The \
              collection log names it."
            ]
        );
    }

    /// A computer behind an RC4-only trust is a counted skip, with the
    /// reason the report reads.
    #[test]
    fn an_rc4_only_trust_is_a_skip() {
        let why = NoTicket::Rc4Trust("between north.contoso.local and contoso.local".into());
        let reason = why.reason("CA01.CONTOSO.LOCAL");
        assert!(
            reason.starts_with("CA01.CONTOSO.LOCAL: skipped: "),
            "{reason}"
        );
        assert!(reason.contains(hosts::SKIP_RC4_TRUST));
        assert_eq!(hosts::skip_of(&reason), Some(hosts::SKIP_RC4_TRUST));
        let skipped: Skipped = [
            ("a".to_string(), Skip::Rc4Trust),
            ("b".to_string(), Skip::Rc4Trust),
        ]
        .into();
        assert_eq!(
            warnings(&skipped),
            [
                "2 computers were skipped: the trust to their domain allows only RC4. The \
              collection log names each one."
            ]
        );
    }

    #[test]
    fn warnings_say_how_many_and_why() {
        let mut skipped = Skipped::new();
        for i in 0..14 {
            skipped.insert(format!("a{i}"), Skip::NoName);
        }
        skipped.insert("b1".into(), Skip::Unsigned);
        skipped.insert("b2".into(), Skip::Unsigned);
        skipped.insert("c".into(), Skip::Refused);
        assert_eq!(
            warnings(&skipped),
            [
                "14 computers were skipped: the domain has no Kerberos name for them. The \
                 collection log names each one.",
                "2 computers were skipped: their replies weren't signed. The collection log \
                 names each one."
            ]
        );
    }
}
