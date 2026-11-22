use super::*;

fn password_req() -> CollectRequest {
    let mut r = CollectRequest::new("contoso.local", "out");
    r.auth = Auth::Password {
        user: "svc".into(),
        password: Secret::new("x"),
    };
    r
}

#[test]
fn password_requires_ldaps_unless_allowed() {
    let mut r = password_req();
    let err = plan(&r).err().expect("refused").to_string();
    assert!(err.contains("--ldaps"), "{err}");
    r.allow_unencrypted_ldap = true;
    let p = plan(&r).unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("plain LDAP")));
    r.allow_unencrypted_ldap = false;
    r.ldaps = true;
    let p = plan(&r).unwrap();
    assert_eq!(p.method, CollectionMethod::DCOnly);
    r.scope = Scope::All;
    assert_eq!(plan(&r).unwrap().method, CollectionMethod::All);
}

/// LDAPS with plain LDAP allowed is planned as LDAPS: no plain LDAP
/// warning until a domain controller actually falls back.
#[test]
fn ldaps_with_plain_allowed_plans_as_ldaps() {
    let mut r = password_req();
    r.ldaps = true;
    r.allow_unencrypted_ldap = true;
    let p = plan(&r).unwrap();
    assert!(
        !p.warnings.iter().any(|w| w.contains("plain LDAP")),
        "{:?}",
        p.warnings
    );
    assert!(falls_back(&r));
    r.allow_unencrypted_ldap = false;
    assert!(!falls_back(&r));
    // Plain LDAP only, or as the Windows account: nothing to fall back from.
    r.allow_unencrypted_ldap = true;
    r.ldaps = false;
    assert!(!falls_back(&r));
    let mut me = CollectRequest::new("contoso.local", "out");
    me.ldaps = true;
    me.allow_unencrypted_ldap = true;
    assert!(!falls_back(&me));
}

/// Runs [`fall_back`] on `job` with LDAPS's result `tried` (`None`: it
/// must not be tried at all). The warning and the log.
fn falls_back_with(
    job: &mut Job,
    tried: Option<Result<(), String>>,
) -> (Option<String>, Vec<String>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let log = std::cell::RefCell::new(Vec::new());
    let w = rt.block_on(fall_back(
        job,
        |url: String, _skip: bool| async move {
            assert!(url.starts_with("ldaps://"), "{url}");
            tried.expect("LDAPS must not be tried")
        },
        true,
        &|l| log.borrow_mut().push(l),
    ));
    (w, log.into_inner())
}

/// LDAPS that works stays LDAPS; LDAPS that fails, with plain LDAP
/// allowed, switches the job to plain LDAP on the same host with a
/// warning naming it and why; without plain LDAP allowed nothing is
/// tried and the job stays LDAPS (its connection fails as before);
/// plain LDAP only tries no LDAPS.
#[test]
fn ldaps_falls_back_only_when_allowed() {
    let mut req = password_req();
    req.ldaps = true;
    req.allow_unencrypted_ldap = true;
    req.server = Some("DC01.CONTOSO.LOCAL".into());
    let method = CollectionMethod::DCOnly;

    let mut job = job_for(&req, method.clone()).unwrap();
    assert_eq!(falls_back_with(&mut job, Some(Ok(()))).0, None);
    assert!(job.ldaps);
    assert_eq!(job.url, "ldaps://DC01.CONTOSO.LOCAL:636");

    let mut job = job_for(&req, method.clone()).unwrap();
    let (w, log) = falls_back_with(
        &mut job,
        Some(Err(
            "rustls error: invalid peer certificate: UnknownIssuer".into()
        )),
    );
    assert_eq!(
        w.as_deref(),
        Some(
            "LDAPS failed on DC01.CONTOSO.LOCAL (the certificate isn't trusted), so it was \
                 read over plain LDAP, unencrypted."
        )
    );
    assert!(!job.ldaps);
    assert_eq!(job.url, "ldap://DC01.CONTOSO.LOCAL:389");
    assert!(log[0].contains("UnknownIssuer"), "{log:?}");
    // Every later connection is plain: the readers' too.
    let c = Connector::of(&job, "dc01.contoso.local");
    assert_eq!(
        (c.url.as_str(), c.ldaps),
        ("ldap://DC01.CONTOSO.LOCAL:389", false)
    );
    // Plain LDAP failing too says both, and keeps its own reason.
    let e = with_ldaps_failure(
        &job,
        "cannot connect to ldap://DC01.CONTOSO.LOCAL:389: connection refused (os error 10061)"
            .into(),
    );
    assert!(
        e.ends_with("LDAPS had failed first: the certificate isn't trusted"),
        "{e}"
    );
    assert_eq!(crate::Problem::classify(&e), crate::Problem::Refused);
    // The check's words.
    assert!(fell_back_warning("DC01.CONTOSO.LOCAL", "x", false).contains("will be read"));

    // Not allowed: nothing tried, LDAPS as before.
    req.allow_unencrypted_ldap = false;
    let mut job = job_for(&req, method.clone()).unwrap();
    assert_eq!(falls_back_with(&mut job, None).0, None);
    assert!(job.ldaps);
    assert_eq!(with_ldaps_failure(&job, "e".into()), "e");

    // Plain LDAP only: no LDAPS tried, no warning.
    req.allow_unencrypted_ldap = true;
    req.ldaps = false;
    let mut job = job_for(&req, method).unwrap();
    assert_eq!(falls_back_with(&mut job, None).0, None);
    assert_eq!(job.url, "ldap://DC01.CONTOSO.LOCAL:389");
}

/// A domain controller read over plain LDAP after its LDAPS failed:
/// the certificate warning goes, the fallback's is said.
#[test]
fn a_fallback_drops_the_certificate_warning() {
    let mut r = password_req();
    r.ldaps = true;
    r.allow_unencrypted_ldap = true;
    r.insecure_skip_tls_verify = true;
    let mut warnings = plan(&r).unwrap().warnings;
    assert!(warnings.iter().any(|w| w == UNCHECKED_CERTIFICATES));
    let before = warnings.len();
    fell_back_in(
        &mut warnings,
        fell_back_warning("dc01.contoso.local", "x", true),
    );
    assert!(!warnings.iter().any(|w| w == UNCHECKED_CERTIFICATES));
    assert_eq!(warnings.len(), before);
    assert!(warnings
        .last()
        .unwrap()
        .starts_with("LDAPS failed on dc01.contoso.local"));
}

/// LDAPS's errors in a few plain words.
#[test]
fn ldaps_failures_in_plain_words() {
    for (e, want) in [
        (
            "invalid peer certificate: UnknownIssuer",
            "the certificate isn't trusted",
        ),
        (
            "invalid peer certificate: certificate not valid for name \"x\"",
            "the certificate doesn't match its name",
        ),
        (
            "invalid peer certificate: certificate expired",
            "the certificate has expired or isn't valid yet",
        ),
        (
            "received fatal alert: HandshakeFailure (tls)",
            "the encrypted connection couldn't be set up",
        ),
        (
            "I/O error: connection refused (os error 10061)",
            "nothing answered on port 636",
        ),
        (
            "timeout: no answer within 10 seconds",
            "no answer on port 636 in time",
        ),
        ("something else", "the connection didn't work"),
    ] {
        assert_eq!(ldaps_failure_words(e), want, "{e}");
    }
}

/// A trusted domain whose domain controllers answer on 389 only, with
/// plain LDAP allowed: one is found there and read over plain LDAP, the
/// warning said without trying LDAPS on it. Not allowed: none found,
/// as before.
#[test]
fn a_dc_found_on_389_only_falls_back() {
    let mut req = password_req();
    req.domain = "north.lab".into();
    req.ldaps = true;
    req.allow_unencrypted_ldap = true;
    req.locate_dc = true;
    let asked = std::cell::RefCell::new(Vec::new());
    let mut find = |d: &str, port: u16, _: &mut dyn FnMut(String)| {
        asked.borrow_mut().push(port);
        if port == 389 {
            Ok("dc02.north.lab".to_string())
        } else {
            Err(crate::locate::NotFound {
                why: format!("dc02.{d} (from DNS) didn't answer on port {port}"),
                found: true,
                outside: false,
            })
        }
    };
    let mut job = job_for(&req, CollectionMethod::DCOnly).unwrap();
    assert_eq!(pick_dc(&mut job, &req, &mut find, &mut |_| {}), None);
    assert_eq!(*asked.borrow(), [636, 389]);
    assert_eq!(job.url, "ldap://dc02.north.lab:389");
    assert_eq!(job.server.as_deref(), Some("dc02.north.lab"));
    let (w, _) = falls_back_with(&mut job, None);
    assert_eq!(
        w.as_deref(),
        Some(
            "LDAPS failed on dc02.north.lab (nothing answered on port 636), so it was read \
                 over plain LDAP, unencrypted."
        )
    );

    asked.borrow_mut().clear();
    req.allow_unencrypted_ldap = false;
    let mut job = job_for(&req, CollectionMethod::DCOnly).unwrap();
    assert!(pick_dc(&mut job, &req, &mut find, &mut |_| {}).is_some());
    assert_eq!(*asked.borrow(), [636]);
    assert_eq!(job.url, "ldaps://north.lab:636");
}

#[test]
fn current_user_is_dc_only() {
    let mut r = CollectRequest::new("contoso.local", "out");
    if cfg!(windows) {
        assert_eq!(plan(&r).unwrap().method, CollectionMethod::LdapOnly);
        r.scope = Scope::All;
        assert!(plan(&r).is_err());
    } else {
        assert!(plan(&r).is_err());
    }
}

#[test]
fn urls_and_users() {
    let mut r = CollectRequest::new("contoso.local", "out");
    assert_eq!(ldap_url(&r), "ldap://contoso.local:389");
    r.server = Some("dc01.contoso.local".into());
    r.ldaps = true;
    assert_eq!(ldap_url(&r), "ldaps://dc01.contoso.local:636");
    assert_eq!(qualified_user("svc", "contoso.local"), "svc@contoso.local");
    assert_eq!(
        qualified_user("CONTOSO\\svc", "contoso.local"),
        "CONTOSO\\svc"
    );
}

/// The user and domain fields of the NTLM AUTHENTICATE message for a
/// `sasl_ntlm_bind` user name, as ldap3 builds them (sspi's
/// `Username::parse`, then `AuthIdentityBuffers::from`).
fn ntlm_fields(bind: &str) -> (String, String) {
    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(bind).unwrap(),
        password: String::from("x").into(),
    };
    let buffers = sspi::AuthIdentityBuffers::from(identity);
    let text = |b: &[u8]| {
        let (pairs, rest) = b.as_chunks::<2>();
        assert!(rest.is_empty());
        let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16(&units).unwrap()
    };
    (text(&buffers.user), text(&buffers.domain))
}

#[test]
fn ntlm_bind_sends_a_upn_whole_with_no_domain() {
    let f = |user: &str, domain: &str| ntlm_fields(&ntlm_bind_name(user, domain).unwrap());
    let s = |u: &str, d: &str| (u.to_string(), d.to_string());
    // A UPN, whatever its suffix: whole, empty domain, as Windows sends it.
    assert_eq!(
        f("samwell.tarly@example.com", "sevenkingdoms.local"),
        s("samwell.tarly@example.com", "")
    );
    assert_eq!(
        f(
            " samwell.tarly@north.sevenkingdoms.local ",
            "north.sevenkingdoms.local"
        ),
        s("samwell.tarly@north.sevenkingdoms.local", "")
    );
    // DOMAIN\user and a bare name: as before.
    assert_eq!(
        f(r"NORTH\samwell.tarly", "sevenkingdoms.local"),
        s("samwell.tarly", "NORTH")
    );
    assert_eq!(f("svc", "contoso.local"), s("svc", "contoso.local"));
    assert_eq!(
        ntlm_bind_name("svc", "contoso.local").as_deref(),
        Ok("svc@contoso.local")
    );
    assert_eq!(
        ntlm_bind_name(r"CONTOSO\svc", "x").as_deref(),
        Ok(r"CONTOSO\svc")
    );
    // An account name may itself contain @: sent whole.
    assert_eq!(f("a@b@example.com", "x"), s("a@b@example.com", ""));
    // What a UPN gave before: split at the @, which only works when the
    // suffix happens to be the account's domain.
    assert_eq!(
        ntlm_fields("samwell.tarly@example.com"),
        s("samwell.tarly", "example.com")
    );
}

#[test]
fn malformed_bind_names_are_refused_in_plain_words() {
    for (user, domain, says) in [
        (r"NORTH\samwell@example.com", "north.local", "mixes"),
        (r"A\B\svc", "north.local", "more than one"),
        (r"\svc", "north.local", "empty part"),
        (r"NORTH\", "north.local", "empty part"),
        (r"NORTH\ ", "north.local", "empty part"),
        ("@example.com", "north.local", "empty part"),
        ("svc@", "north.local", "empty part"),
        ("svc@ ", "north.local", "empty part"),
        ("", "north.local", "empty"),
        ("  ", "north.local", "empty"),
        ("svc", r"NORTH\x", "not a DNS name"),
        ("svc", "a@north.local", "not a DNS name"),
        ("svc", " ", "not a DNS name"),
    ] {
        let e = ntlm_bind_name(user, domain).unwrap_err();
        assert!(e.contains(says), "{user:?} {domain:?}: {e}");
    }
    // Whatever passes, sspi parses (ldap3 unwraps it).
    for (user, domain) in [
        ("svc", "contoso.local"),
        (r"CONTOSO\svc", "contoso.local"),
        ("svc@contoso.local", "contoso.local"),
        ("a@b@example.com", "contoso.local"),
    ] {
        let bind = ntlm_bind_name(user, domain).unwrap();
        assert!(sspi::Username::parse(&bind).is_ok(), "{bind}");
    }
    // A malformed name reaches no DC: the check refuses it as a setting.
    let mut req = CollectRequest::new("contoso.local", "out");
    req.auth = Auth::Password {
        user: r"CONTOSO\svc@contoso.local".into(),
        password: Secret::new("x"),
    };
    req.ldaps = true;
    let e = check(&req, &crate::RunSignIn::default()).unwrap_err();
    assert_eq!(e.problem, crate::Problem::Settings);
    assert!(e.detail.contains("mixes"), "{}", e.detail);
}

/// Kerberos only with an account from another domain: on
/// its own, with a domain the directory doesn't name, refused before
/// anything is collected or asked; as a trusted domain
/// of a run whose first domain gave the account's ticket, read with that
/// ticket through the trust, the password taken out of the modules'
/// options all the same.
#[test]
fn a_trusted_domain_uses_the_first_domains_ticket() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut req = CollectRequest::new("fabrikam.com", "out");
    req.auth = Auth::Password {
        user: r"CONTOSO\svc".into(),
        password: Secret::new("Pw-Trust-1"),
    };
    req.ldaps = true;
    req.scope = Scope::All;
    let options = || {
        let mut o = base_options(
            "fabrikam.com",
            std::path::Path::new("out"),
            CollectionMethod::All,
            "dc01.fabrikam.com".into(),
            true,
        );
        o.username = Some(r"CONTOSO\svc".into());
        o.password = Some("Pw-Trust-1".into());
        o
    };
    let identity = || hosts::SmbIdentity {
        domain: "CONTOSO".into(),
        other_domain: true,
        kerberos: None,
    };
    // Alone, its domain not found in the directory: refused.
    let job = job_for(&req, CollectionMethod::All).unwrap();
    let (mut smb, mut o) = (identity(), options());
    let e = rt
        .block_on(kerberos_hosts(
            &job,
            "dc01.fabrikam.com",
            None,
            Ok(None),
            &mut smb,
            &mut o,
            &|_| {},
        ))
        .err()
        .expect("refused");
    assert!(
        e.message()
            .contains("the account's domain (CONTOSO) isn't in fabrikam.com's forest"),
        "{}",
        e.message()
    );
    drop(job);

    // In a run: the first domain's ticket.
    let parent = std::env::temp_dir().join(format!("pw-home-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).unwrap();
    let sign_in = crate::RunSignIn::several();
    sign_in.keep(HomeTicket {
        cache: krb::TicketCache::write_in(&parent, &krb::fake::tgt()).unwrap(),
        kdc: "dc01.contoso.local".into(),
        realm: "CONTOSO.LOCAL".into(),
        who: r"CONTOSO\svc".into(),
    });
    let mut job = job_for(&req, CollectionMethod::All).unwrap();
    job.sign_in = sign_in.clone();
    let (mut smb, mut o) = (identity(), options());
    let lines = Mutex::new(Vec::new());
    let _env = KRB_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guard = rt
        .block_on(kerberos_hosts(
            &job,
            "dc01.fabrikam.com",
            None,
            Ok(None),
            &mut smb,
            &mut o,
            &|l| lines.lock().unwrap().push(l),
        ))
        .expect("the first domain's ticket");
    let k = smb.kerberos.clone().expect("Kerberos only");
    assert_eq!(
        k.kdc, "dc01.contoso.local",
        "the account's own domain's controller"
    );
    assert_eq!(std::env::var("KRB5CCNAME").ok(), Some(k.ccache.clone()));
    assert!(
        o.kerberos && o.password.is_none(),
        "no password for the modules"
    );
    assert!(
        lines.lock().unwrap()[0].contains("used through the trust to fabrikam.com"),
        "{:?}",
        lines.lock().unwrap()
    );
    drop(guard);
    drop(job);
    // The run still holds it until it ends.
    let file = k.ccache.trim_start_matches("FILE:").to_string();
    assert!(std::path::Path::new(&file).is_file());
    drop(sign_in);
    assert!(
        !std::path::Path::new(&file).exists(),
        "deleted with the run"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// An account whose domain is not the collected one: the collected
/// domain's controller is asked no ticket; when the
/// directory doesn't name the account's domain, the check and the
/// collection say so.
#[test]
fn the_check_asks_a_ticket_only_of_the_accounts_own_domain() {
    let foreign = hosts::smb_account(
        r"NORTH\svc",
        Some(r"u:NORTH\svc"),
        "essos.local",
        Some("ESSOS"),
    );
    assert!(foreign.identity.other_domain);
    let own = hosts::smb_account(
        r"NORTH\svc",
        Some(r"u:NORTH\svc"),
        "north.contoso.local",
        Some("NORTH"),
    );
    assert!(!own.identity.other_domain);
    let e = ownrealm::account_domain_unknown(&foreign.identity.domain, "essos.local");
    assert_eq!(e.problem, crate::Problem::NoTicket);
    assert_eq!(
        e.message(),
        "Kerberos didn't work: the account's domain (NORTH) isn't in essos.local's forest \
             or its trusts, so its domain controller can't be found. Accounts from a child \
             domain of a trusted forest aren't supported yet. Use an account from essos.local."
    );
}

/// A trusted domain's check: no ticket through the trust is a
/// warning that its computers will be skipped, not a failed check.
#[test]
fn the_check_says_when_the_trust_lets_no_ticket_through() {
    let rc4 = krb::NoTicket::Rc4Trust("between contoso.local and fabrikam.com".into());
    assert_eq!(
        through_the_trust("fabrikam.com", &rc4),
        "The trust to fabrikam.com allows only RC4, so its computers will be skipped. Set \
             the trust to use AES."
    );
    let other = krb::NoTicket::Refused("Kerberos: no answer from fabrikam.com:88".into());
    assert_eq!(
        through_the_trust("fabrikam.com", &other),
        "Kerberos through the trust to fabrikam.com didn't work, so its computers will be \
             skipped: Kerberos: no answer from fabrikam.com:88."
    );
}

#[test]
fn a_refused_upn_hints_at_external_trusts() {
    let refused = "LDAP operation result: rc=49 (invalidCredentials), dn: \"\", text: \
                       \"80090308: LdapErr: DSID-0C09041C, data 52e, v4563\"";
    let hint = "If the account is from an externally trusted domain, give it as DOMAIN\\user.";
    let e = bind_failed("alice@trusted.local", "alice@trusted.local@", refused);
    assert!(e.starts_with("NTLM bind as alice@trusted.local failed: LDAP operation"));
    assert!(e.ends_with(hint), "{e}");
    assert_eq!(crate::Problem::classify(&e), crate::Problem::Credentials);
    // Not for DOMAIN\user or a bare name, nor for other failures.
    for (user, bind) in [
        (r"TRUSTED\alice", r"TRUSTED\alice"),
        ("svc@contoso.local", "svc@contoso.local"),
    ] {
        assert!(!bind_failed(user, bind, refused).contains(hint));
    }
    assert!(!bind_failed("a@b.c", "a@b.c@", "rc=8 (strongerAuthRequired)").contains(hint));
}

#[test]
fn spn_host_is_not_taken_blindly_from_the_root_dse() {
    let dse = |s: Option<&str>, h: Option<&str>| spn_source(s, "contoso.local", h);
    // An FQDN the user gave wins over whatever the server says.
    assert_eq!(
        dse(Some("dc01.contoso.local"), Some("evil.attacker.net")),
        Ok(SpnSource::Given("dc01.contoso.local".into()))
    );
    // Otherwise the RootDSE name must be a DNS name in the domain.
    assert_eq!(
        dse(None, Some("DC02.Contoso.Local")),
        Ok(SpnSource::RootDse("DC02.Contoso.Local".into()))
    );
    assert_eq!(
        dse(Some("10.0.0.5"), Some("dc02.child.contoso.local")),
        Ok(SpnSource::RootDse("dc02.child.contoso.local".into()))
    );
    assert!(dse(None, Some("dc.evilcontoso.local")).is_err());
    assert!(dse(None, Some("evil.attacker.net")).is_err());
    assert!(dse(None, Some("dc01")).is_err());
    let err = dse(None, Some("dc\u{1b}[2K.contoso.local")).unwrap_err();
    assert!(!err.contains('\u{1b}'), "{err}");
    // No name from the server: the host connected to.
    assert_eq!(
        dse(Some("10.0.0.5"), None),
        Ok(SpnSource::Connected("10.0.0.5".into()))
    );
    assert_eq!(
        dse(None, None),
        Ok(SpnSource::Connected("contoso.local".into()))
    );
}

#[test]
fn spn_host_must_resolve_to_the_connected_address() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut req = CollectRequest::new("pathwarden.invalid", "out");
    req.server = Some("127.0.0.1".into());
    let job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    // In the domain, but resolves elsewhere (nowhere): refused for
    // Kerberos, the connected host for NTLM.
    let host = Some("dc.pathwarden.invalid");
    let ours = rt.block_on(resolve_dc(&job)).unwrap();
    assert_eq!(ours, [std::net::IpAddr::from([127, 0, 0, 1])]);
    let kerb = rt.block_on(dc_host(&job, &ours, host, true, &|_| {}));
    assert!(kerb.unwrap_err().contains("--server"));
    let ntlm = rt.block_on(dc_host(&job, &ours, host, false, &|_| {}));
    assert_eq!(ntlm.unwrap(), "127.0.0.1");
}

#[test]
fn steps_follow_the_method() {
    let keys = |m| steps(&m).iter().map(|s| s.key).collect::<Vec<_>>();
    if cfg!(windows) {
        assert_eq!(
            keys(CollectionMethod::LdapOnly),
            ["connect", "read", "parse", "resolve", "modules", "write"]
        );
    } else {
        assert_eq!(
            keys(CollectionMethod::LdapOnly),
            ["connect", "read", "parse", "resolve", "write"]
        );
    }
    assert_eq!(
        keys(CollectionMethod::All),
        ["connect", "read", "parse", "resolve", "modules", "write"]
    );
    assert!(steps(&CollectionMethod::DCOnly)[4].label.contains("SYSVOL"));
}

/// The SYSVOL step's progress, sent from the blocking thread
/// that reads SYSVOL (here a fake reader, no network), reaches the
/// tracker through the message pump: units, the detail line, the unit,
/// and the step's new weight.
#[test]
fn sysvol_units_from_a_worker_thread_reach_the_tracker() {
    let mut statuses = Vec::new();
    let mut sink = |p: crate::Progress| {
        if let crate::Progress::Status(s) = p {
            statuses.push(*s);
        }
    };
    let mut rep = Reporter::new(steps(&CollectionMethod::DCOnly), &mut sink);
    let mut expected = None;
    for key in ["read", "parse", "resolve"] {
        apply(&mut rep, Msg::Step(key), &mut expected);
    }
    let (tx, rx) = mpsc::channel();
    let _ = tx.send(Msg::Weight("modules", 200.0));
    let _ = tx.send(Msg::Step("modules"));
    let reader = std::thread::spawn(move || {
        let mut progress = sysvol::SysvolProgress::new(tx, 40, 0, true);
        progress.start();
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(1));
            progress.gpo_done();
        }
        progress.finish();
    });
    // The pump, as in `run`, until the reader's sender is gone.
    while let Ok(msg) = rx.recv_timeout(Duration::from_secs(10)) {
        apply(&mut rep, msg, &mut expected);
    }
    reader.join().unwrap();
    rep.emit();
    drop(rep);
    let last = statuses.last().unwrap();
    assert_eq!(last.key, "modules");
    assert_eq!((last.done, last.total), (40, Some(40)));
    assert_eq!(last.unit, "items");
    assert_eq!(last.detail.as_deref(), Some("GPO 40 of 40"));
    // The bar didn't jump back when the step got heavier (84% at the
    // start of resolving, a little more past it), and the step is now
    // most of what was left: its 99% (the cap) moves the bar most of
    // the way.
    let entered = statuses.iter().find(|s| s.key == "modules").unwrap();
    assert!(
        (84.0..=85.0).contains(&entered.percent),
        "{}",
        entered.percent
    );
    assert!(last.percent > 96.0, "{}", last.percent);
}

#[test]
fn new_connections_must_reach_the_reads_domain_controller() {
    let c = |dc: &str| Connector {
        url: format!("ldaps://{dc}:636"),
        ldaps: true,
        skip_verify: false,
        dc_fqdn: dc.into(),
        auth: ConnectAuth::CurrentUser,
        pinned: Mutex::new(String::new()),
        pinned_host: Mutex::new(String::new()),
    };
    const DS: &str = "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=x";
    const DS2: &str = "CN=NTDS Settings,CN=DC02,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=x";
    // With the snapshot's dsServiceName: only that controller.
    let pinned = c("dc01.contoso.local");
    pinned.pin(DS, Some("dc01.contoso.local"));
    assert_eq!(pinned.elsewhere(Some(DS), Some("dc01.contoso.local")), None);
    assert_eq!(
        pinned.elsewhere(Some(&DS.to_lowercase()), Some("x")),
        None,
        "case-insensitive"
    );
    let e = pinned
        .elsewhere(Some(DS2), Some("dc02.contoso.local"))
        .unwrap();
    assert!(
        e.contains("reached dc02.contoso.local, not dc01.contoso.local"),
        "{e}"
    );
    assert!(pinned.elsewhere(None, None).is_some());
    // No snapshot, a server named by its address: the first connection's
    // RootDSE name.
    let by_ip = c("10.0.0.5");
    by_ip.pin("", Some("dc01.contoso.local."));
    assert_eq!(by_ip.elsewhere(None, Some("DC01.contoso.local")), None);
    assert!(by_ip
        .elsewhere(None, Some("dc02.contoso.local"))
        .unwrap()
        .contains("not dc01.contoso.local"));
    // Nothing known about the first one, an address: nothing to check.
    let bare = c("10.0.0.5");
    assert_eq!(bare.elsewhere(None, Some("dc02.contoso.local")), None);
    // Nothing pinned but a name: the name.
    let named = c("dc01.contoso.local");
    assert!(named.elsewhere(None, Some("dc02.contoso.local")).is_some());
    // The password's copy goes when the read ends.
    let ntlm = Connector {
        auth: ConnectAuth::Ntlm {
            user: "CONTOSO\\svc".into(),
            bind: "svc@contoso.local".into(),
            password: Mutex::new(Some(Secret::new("pw"))),
        },
        ..c("dc01.contoso.local")
    };
    ntlm.forget();
    let ConnectAuth::Ntlm { password, .. } = &ntlm.auth else {
        panic!()
    };
    assert!(password.lock().unwrap().is_none());
}

#[test]
fn ranges_and_kinds() {
    assert_eq!(range_high("member;range=0-1499"), Some(1499));
    assert_eq!(range_high("member;Range=1500-*"), None);
    assert_eq!(range_high("member"), None);
    let mut e = SearchEntry {
        dn: "CN=x".into(),
        attrs: Default::default(),
        bin_attrs: Default::default(),
    };
    e.attrs.insert(
        "objectClass".into(),
        vec!["top".into(), "person".into(), "user".into()],
    );
    assert_eq!(kind_of(&e), "users");
    e.attrs.insert(
        "objectClass".into(),
        vec![
            "top".into(),
            "person".into(),
            "user".into(),
            "computer".into(),
        ],
    );
    assert_eq!(kind_of(&e), "computers");
    e.attrs
        .insert("objectClass".into(), vec!["top".into(), "dnsNode".into()]);
    assert_eq!(kind_of(&e), "other");
}

/// Lab item 88: the domain controller resetting a connection Pathwarden
/// is closing is no warning; a reset at another time is a plain line
/// (shown with -v), and other socket errors stay warnings.
#[test]
fn a_connection_closed_normally_is_no_warning() {
    use log::{Level, Record};
    let line = |text: &str| {
        log_bridge::line_for(
            &Record::builder()
                .level(Level::Warn)
                .target("ldap3::conn")
                .args(format_args!("{text}"))
                .build(),
        )
    };
    let reset = "socket receive error: An existing connection was forcibly closed by the \
                     remote host. (os error 10054)";
    CLOSING.fetch_add(1, Ordering::SeqCst);
    let closing = line(reset);
    CLOSING.fetch_sub(1, Ordering::SeqCst);
    assert_eq!(closing, None);
    let other = line(reset).unwrap();
    assert!(
        other.starts_with("[ldap] the domain controller closed a connection (socket receive"),
        "{other}"
    );
    assert_eq!(
        line("socket receive error: invalid data").as_deref(),
        Some("warning: socket receive error: invalid data")
    );
}

/// RustHound-CE's LAPS lines (`objects/computer.rs`, colored as it logs
/// them) never reach the job log with the password; debug records and
/// other crates' records are dropped as before.
#[test]
fn log_bridge_hides_laps_passwords() {
    use log::{Level, Record};
    let secret = "Pa55-LAPS-Value!";
    let line = |level: Level, target: &str, args: std::fmt::Arguments| {
        log_bridge::line_for(
            &Record::builder()
                .level(level)
                .target(target)
                .args(args)
                .build(),
        )
    };
    let name = "\u{1b}[1;33mWS01\u{1b}[0m";
    let value = format!("\u{1b}[1;33m{secret}\u{1b}[0m");
    let legacy = line(
        Level::Info,
        "rusthound_ce::objects::computer",
        format_args!("Your user can read LAPS password on {}: {}", name, value),
    )
    .unwrap();
    assert!(!legacy.contains(secret), "{legacy}");
    assert!(
        legacy.contains("password of WS01 (the password is not shown)"),
        "{legacy}"
    );
    let windows_laps = line(
        Level::Info,
        "rusthound_ce::objects::computer",
        format_args!(
            "Your user can read LAPS password on {}: {:?}",
            name,
            format!("{{\"n\":\"Administrator\",\"p\":\"{secret}\"}}")
        ),
    )
    .unwrap();
    assert!(!windows_laps.contains(secret), "{windows_laps}");
    let warned = line(
        Level::Warn,
        "rusthound_ce::modules::gpo::sysvol",
        format_args!("[gpo] cpassword {secret}"),
    )
    .unwrap();
    assert!(
        warned.starts_with("warning: ") && !warned.contains(secret),
        "{warned}"
    );
    // Upstream's padded SAMR message is one tidy line.
    assert_eq!(
        line(
            Level::Warn,
            "rusthound_ce::modules::localgroup",
            format_args!("WS01 SamrConnect2:                         rc=5\n  denied")
        )
        .as_deref(),
        Some("warning: WS01 SamrConnect2: rc=5 denied")
    );
    assert_eq!(
        line(
            Level::Debug,
            "rusthound_ce::transport::ldap",
            format_args!("Password: {secret}")
        ),
        None
    );
    assert_eq!(
        line(Level::Info, "other_crate", format_args!("hello")),
        None
    );
    assert_eq!(
        line(
            Level::Info,
            "rusthound_ce::api",
            format_args!("Starting the LDAP objects parsing...")
        )
        .as_deref(),
        Some("Starting the LDAP objects parsing...")
    );
    // Replies to the dropped sizing count: hundreds of these in the
    // GOAD essos.local run. Other ldap3 warnings still show.
    for noise in [
        "unmatched id: 20",
        "ldap search item send error, op=20: SendError { .. }",
    ] {
        assert_eq!(
            line(Level::Warn, "ldap3::conn", format_args!("{noise}")),
            None
        );
    }
    assert_eq!(
        line(
            Level::Warn,
            "ldap3::conn",
            format_args!("socket send error: x")
        )
        .as_deref(),
        Some("warning: socket send error: x")
    );
}

/// The sessions module's per-computer errors are kept for `hosts`,
/// and only that module's.
#[test]
fn log_bridge_keeps_the_sessions_errors() {
    assert!(log_bridge::install());
    log_bridge::start_capture(hosts::SESSIONS_LOG_TARGET);
    log::warn!(target: "rusthound_ce::modules::session", "WS1.X.LOCAL: 445/tcp unreachable");
    log::info!(target: "rusthound_ce::modules::session", "[sessions] 1 active target(s)");
    log::warn!(target: "rusthound_ce::modules::localgroup", "WS1.X.LOCAL: auth: x");
    assert_eq!(
        log_bridge::take_capture(),
        Some(vec!["WS1.X.LOCAL: 445/tcp unreachable".to_string()])
    );
    // Nothing kept once taken.
    log::warn!(target: "rusthound_ce::modules::session", "WS2.X.LOCAL: auth: x");
    assert_eq!(log_bridge::take_capture(), None);
}

#[test]
fn dns_partitions_and_kinds() {
    let d = "DC=contoso,DC=local";
    assert!(is_dns_partition("DC=DomainDnsZones,DC=contoso,DC=local"));
    assert!(is_dns_partition("dc=forestdnszones,DC=contoso,DC=local"));
    assert!(!is_dns_partition(d));
    assert!(!is_dns_partition("DC=DomainDnsZonesX,DC=contoso,DC=local"));
    assert!(!is_dns_partition("CN=Configuration,DC=contoso,DC=local"));
    assert_eq!(
        nc_kind("CN=Schema,CN=Configuration,DC=contoso,DC=local", d),
        "schema"
    );
    assert_eq!(
        nc_kind("CN=Configuration,DC=contoso,DC=local", d),
        "configuration"
    );
    assert_eq!(nc_kind("dc=contoso,dc=local", d), "domain");
    assert_eq!(
        nc_kind("DC=ForestDnsZones,DC=contoso,DC=local", d),
        "DNS partition"
    );
    assert_eq!(nc_kind("DC=App,DC=contoso,DC=local", d), "other partition");
}

/// Phase 1 volume cuts: not reading the DNS partitions and not asking for
/// deleted objects leaves every object Pathwarden keeps exactly as it
/// was, apart from references to the objects no longer read. Both
/// entry sets go through RustHound-CE's parser and the checker as in a
/// collection; objects are compared by identifier, arrays as sets
/// (upstream's own order follows HashMap iteration, which differs
/// between two parses anyway).
#[test]
fn volume_cuts_keep_the_objects_we_keep() {
    use checker::tests::{entry, guid, options, sid, synthetic};
    use serde_json::Value;
    let base = "DC=contoso,DC=local";
    let mut dropped_entries = Vec::new();
    for (zi, zone) in ["DomainDnsZones", "ForestDnsZones"].into_iter().enumerate() {
        let nc = format!("DC={zone},{base}");
        dropped_entries.extend([
            // The partition head is a domainDNS object without a SID.
            entry(
                &nc,
                &["top", "domain", "domainDNS"],
                &[("name", zone.into())],
                vec![],
            ),
            entry(
                &format!("CN=MicrosoftDNS,{nc}"),
                &["top", "container"],
                &[("name", "MicrosoftDNS".into())],
                vec![("objectGUID", guid(900 + zi as u64, 8))],
            ),
            entry(
                &format!("DC=contoso.local,CN=MicrosoftDNS,{nc}"),
                &["top", "dnsZone"],
                &[("name", "contoso.local".into())],
                vec![("objectGUID", guid(910 + zi as u64, 8))],
            ),
            entry(
                &format!("DC=ws01,DC=contoso.local,CN=MicrosoftDNS,{nc}"),
                &["top", "dnsNode"],
                &[("name", "ws01".into())],
                vec![
                    ("objectGUID", guid(920 + zi as u64, 8)),
                    ("dnsRecord", vec![1, 2, 3, 4]),
                ],
            ),
            entry(
                &format!("CN=Infrastructure,{nc}"),
                &["top", "infrastructureUpdate"],
                &[("name", "Infrastructure".into())],
                vec![("objectGUID", guid(930 + zi as u64, 8))],
            ),
        ]);
    }
    let deleted = format!("CN=Deleted Objects,{base}");
    dropped_entries.extend([
        entry(
            &deleted,
            &["top", "container"],
            &[
                ("name", "Deleted Objects".into()),
                ("isDeleted", "TRUE".into()),
            ],
            vec![("objectGUID", guid(950, 8))],
        ),
        entry(
            &format!("CN=old\\0ADEL:1234,{deleted}"),
            &["top", "person", "organizationalPerson", "user"],
            &[
                ("name", "old".into()),
                ("sAMAccountName", "old".into()),
                ("isDeleted", "TRUE".into()),
            ],
            vec![("objectSid", sid(99_001)), ("objectGUID", guid(951, 8))],
        ),
        entry(
            &format!("CN=oldpc\\0ADEL:5678,{deleted}"),
            &["top", "person", "organizationalPerson", "user", "computer"],
            &[
                ("name", "OLDPC".into()),
                ("sAMAccountName", "OLDPC$".into()),
                ("isDeleted", "TRUE".into()),
            ],
            vec![("objectSid", sid(99_002)), ("objectGUID", guid(952, 8))],
        ),
    ]);
    let mut kept = synthetic(6);
    // Without the user whose DN contains a GPO's GUID: which of the two
    // a gPLink resolves to follows HashMap order in upstream, which
    // differs between two parses (one parse is compared in the checker
    // tests).
    kept.retain(|e| !e.dn.starts_with("CN=ABC"));
    let mut full = kept.clone();
    full.extend(dropped_entries);

    let out = std::env::temp_dir();
    let options = options(&out);
    let run = |entries: Vec<rusthound_ce::transport::ldap::LdapSearchEntry>| {
        let n = entries.len();
        let mut r = rusthound_ce::api::parse_result_type_from_source(&options, entries, Some(n))
            .map_err(|e| e.to_string())
            .unwrap();
        checker::check_all(&options, &mut r)
            .map_err(|e| e.to_string())
            .unwrap();
        let all = [
            serde_json::to_value(&r.users).unwrap(),
            serde_json::to_value(&r.groups).unwrap(),
            serde_json::to_value(&r.computers).unwrap(),
            serde_json::to_value(&r.ous).unwrap(),
            serde_json::to_value(&r.domains).unwrap(),
            serde_json::to_value(&r.gpos).unwrap(),
            serde_json::to_value(&r.containers).unwrap(),
        ];
        let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
        for list in all {
            for o in list.as_array().unwrap() {
                let id = o["ObjectIdentifier"].as_str().unwrap().to_string();
                by_id.insert(id, o.clone());
            }
        }
        by_id
    };
    let before = run(full);
    let after = run(kept);

    // What disappears: the deleted objects (which ingest drops), the
    // `CN=Deleted Objects` container (RustHound-CE's container parser
    // ignores isDeleted, so ingest used to keep it as a real container)
    // and the DNS partitions' MicrosoftDNS containers. Nothing appears.
    let gone: Vec<&String> = before.keys().filter(|k| !after.contains_key(*k)).collect();
    assert!(after.keys().all(|k| before.contains_key(k)));
    assert_eq!(gone.len(), 5, "{gone:?}");
    let mut deleted_n = 0;
    for id in &gone {
        let o = &before[*id];
        let dn = o["Properties"]["distinguishedname"].as_str().unwrap_or("");
        if o["IsDeleted"] == Value::Bool(true) {
            deleted_n += 1;
        } else if dn.starts_with("CN=DELETED OBJECTS,") {
            assert_eq!(o["IsDeleted"], Value::Bool(false));
        } else {
            assert!(
                dn.starts_with("CN=MICROSOFTDNS,DC=") && dn.contains("DNSZONES"),
                "{o}"
            );
        }
    }
    assert_eq!(deleted_n, 2);

    // Kept objects are identical, once references to what is gone are
    // removed from both sides.
    fn canon(v: &Value, gone: &[&String]) -> Value {
        match v {
            Value::Array(a) => {
                let mut items: Vec<Value> = a
                    .iter()
                    .filter(|x| {
                        !["ObjectIdentifier", "PrincipalSID"].iter().any(|k| {
                            x.get(k)
                                .and_then(Value::as_str)
                                .is_some_and(|id| gone.iter().any(|g| g.as_str() == id))
                        })
                    })
                    .map(|x| canon(x, gone))
                    .collect();
                items.sort_by_key(|x| x.to_string());
                Value::Array(items)
            }
            Value::Object(m) => {
                Value::Object(m.iter().map(|(k, x)| (k.clone(), canon(x, gone))).collect())
            }
            x => x.clone(),
        }
    }
    let mut differences = 0;
    for (id, a) in &after {
        let b = &before[id];
        if canon(a, &gone) != canon(b, &gone) {
            differences += 1;
            eprintln!("{id}:\n  with cuts {a}\n  before    {b}");
        }
    }
    assert_eq!(differences, 0);
    assert!(after.len() > 60, "{}", after.len());
}

#[test]
fn a_stalled_read_fails_instead_of_waiting_forever() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let limit = Duration::from_millis(20);
        // A reply that never comes (the lost SearchResultDone).
        let never = std::future::pending::<Result<u8, String>>();
        let e = or_stalled(limit, "LDAP search of DC=x", never)
            .await
            .unwrap_err();
        assert_eq!(
            e,
            "LDAP search of DC=x: connection stalled: the domain controller sent \
                 nothing for 1 minute"
        );
        assert_eq!(crate::Problem::classify(&e), crate::Problem::Stalled);
        // Replies and errors that do come pass through.
        let ok = or_stalled(limit, "x", async { Ok::<_, String>(7) }).await;
        assert_eq!(ok, Ok(7));
        let err = or_stalled(limit, "x", async { Err::<u8, _>("busy") }).await;
        assert_eq!(err, Err("x failed: busy".to_string()));
    });
    // Long enough for a DC that is slow but working: past its own
    // two-minute MaxQueryDuration with room to spare.
    assert!(STALL_TIMEOUT >= Duration::from_secs(4 * 60));
}

#[test]
fn naming_context_from_domain() {
    assert_eq!(domain_dn("contoso.local"), "DC=contoso,DC=local");
    assert_eq!(domain_dn("a.b.c."), "DC=a,DC=b,DC=c");
}

#[test]
fn name_mismatch_lists_only_readable_names() {
    let e = "I/O error: invalid peer certificate: certificate not valid for name \
                 \"192.168.56.11\"; certificate is only valid for Unsupported(0x00) or \
                 DnsName(\"winterfell.north.sevenkingdoms.local\")";
    let msg = connect_error("ldaps://192.168.56.11:636", true, e);
    assert!(!msg.contains("Unsupported"), "{msg}");
    assert!(
        msg.contains("only valid for DnsName(\"winterfell.north.sevenkingdoms.local\")"),
        "{msg}"
    );
    assert_eq!(without_unsupported_names("no names here"), "no names here");
    assert_eq!(
        without_unsupported_names("x Unsupported(0x0"),
        "x Unsupported(0x0"
    );
}

/// A misspelt domain with a working DC name is refused, naming the DC's
/// own domain; the right one passes in any case.
#[test]
fn a_dc_of_another_domain_is_refused() {
    let nc = "DC=north,DC=sevenkingdoms,DC=local";
    assert_eq!(wrong_domain("north.sevenkingdoms.local", nc), None);
    assert_eq!(wrong_domain("NORTH.SevenKingdoms.Local.", nc), None);
    assert_eq!(
        wrong_domain("nroth.sevenkingdoms.local", nc).as_deref(),
        Some("north.sevenkingdoms.local")
    );
    assert_eq!(
        wrong_domain("sevenkingdoms.local", nc).as_deref(),
        Some("north.sevenkingdoms.local")
    );
    assert_eq!(wrong_domain("contoso.local", ""), None);
    let message = "winterfell.north.sevenkingdoms.local is a domain controller for \
                       north.sevenkingdoms.local, not nroth.sevenkingdoms.local";
    assert_eq!(
        crate::Problem::classify(message),
        crate::Problem::WrongDomain
    );
}

/// Nothing listens on LDAPS at 127.0.0.1: the check fails fast, with a
/// plain "refused" (and no password in the error).
#[test]
fn check_reports_a_refused_connection() {
    let mut r = CollectRequest::new("contoso.local", "out");
    r.server = Some("127.0.0.1".into());
    r.ldaps = true;
    r.auth = Auth::Password {
        user: "svc".into(),
        password: Secret::new("Check-Secret-91"),
    };
    let err = crate::test_connection(&r).unwrap_err();
    let ce = err.downcast_ref::<ConnectionError>().expect("typed");
    assert!(
        matches!(
            ce.problem,
            crate::Problem::Refused | crate::Problem::Timeout
        ),
        "{ce:?}"
    );
    assert!(!format!("{err:?} {err}").contains("Check-Secret-91"));
}

#[test]
fn skip_verify_warns() {
    let mut r = password_req();
    r.ldaps = true;
    r.insecure_skip_tls_verify = true;
    assert!(plan(&r)
        .unwrap()
        .warnings
        .iter()
        .any(|w| w.contains("certificates were not checked")));
}

/// A collection that reached its domain controller through
/// DNS (no name, an IP address, a short name) warns that its results
/// are only as trustworthy as DNS; one named by its full name doesn't.
#[test]
fn a_dc_not_named_by_its_full_name_warns() {
    let mut r = password_req();
    r.ldaps = true;
    let warned = |r: &CollectRequest| {
        plan(r)
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.as_str() == UNNAMED_DC)
    };
    assert!(warned(&r));
    for unnamed in ["10.0.0.5", "dc01", "[fe80::1]", "", "dc01..contoso.local"] {
        r.server = Some(unnamed.into());
        assert!(warned(&r), "{unnamed}");
    }
    for named in ["dc01.contoso.local", "DC01.contoso.local."] {
        r.server = Some(named.into());
        assert!(!warned(&r), "{named}");
    }
    assert!(UNNAMED_DC.contains("only as trustworthy as DNS"));
}

/// Cancel while the connection attempt hangs (TEST-NET address that
/// never answers): `collect` must return `Cancelled` promptly.
#[cfg(windows)]
#[test]
fn cancel_stops_a_hanging_connection() {
    use std::time::Instant;
    let out = std::env::temp_dir().join(format!("pw-cancel-{}", std::process::id()));
    let mut r = CollectRequest::new("contoso.local", &out);
    r.server = Some("192.0.2.1".into());
    let cancel = AtomicBool::new(false);
    let started = Instant::now();
    let result = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            cancel.store(true, Ordering::SeqCst);
        });
        crate::collect(&r, &mut |_| {}, &cancel)
    });
    let err = result.expect_err("cancelled");
    // Either the cancel won, or the network refused at once.
    if err.is::<Cancelled>() {
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    let _ = std::fs::remove_dir_all(&out);
}

/// Binary `objectSid` for S-1-5-21-<subs...>.
pub(super) fn sid_bytes(subs: &[u32]) -> Vec<u8> {
    let mut all = vec![21u32];
    all.extend_from_slice(subs);
    let mut b = vec![1u8, all.len() as u8, 0, 0, 0, 0, 0, 5];
    for s in all {
        b.extend_from_slice(&s.to_le_bytes());
    }
    b
}

pub(super) fn entry(
    dn: &str,
    classes: &[&str],
    attrs: &[(&str, &str)],
    multi: &[(&str, Vec<&str>)],
    sid: &[u32],
) -> rusthound_ce::transport::ldap::LdapSearchEntry {
    use std::collections::HashMap;
    let mut a: HashMap<String, Vec<String>> = HashMap::new();
    a.insert(
        "objectClass".into(),
        classes.iter().map(|c| c.to_string()).collect(),
    );
    a.insert("distinguishedName".into(), vec![dn.to_string()]);
    for (k, v) in attrs {
        a.insert(k.to_string(), vec![v.to_string()]);
    }
    for (k, v) in multi {
        a.insert(k.to_string(), v.iter().map(|x| x.to_string()).collect());
    }
    let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    bin.insert("objectSid".into(), vec![sid_bytes(sid)]);
    rusthound_ce::transport::ldap::LdapSearchEntry {
        dn: dn.to_string(),
        attrs: a,
        bin_attrs: bin,
    }
}

/// The certificate hint reads right in the app and in the terminal.
#[test]
fn certificate_hint_names_both_the_app_and_the_flag() {
    let e = connect_error(
        "ldaps://dc01:636",
        true,
        "rustls error: invalid peer certificate: UnknownIssuer",
    );
    assert!(
        e.contains("Don't check the certificate") && e.contains("--insecure-skip-tls-verify"),
        "{e}"
    );
    assert!(!e.contains("use --server"), "{e}");
    assert!(!connect_error("ldap://dc01:389", false, "certificate").contains("labs"));
}

/// Synthetic directory -> RustHound-CE parser and JSON writer (the same
/// options the built-in collector uses) -> Pathwarden's ingest.
#[test]
fn output_round_trips_through_pathwarden_ingest() {
    let out = std::env::temp_dir().join(format!("pw-roundtrip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let before = Snapshot::take(&out);

    let base = "DC=contoso,DC=local";
    let alice = format!("CN=Alice,CN=Users,{base}");
    let entries = vec![
        entry(
            base,
            &["top", "domain", "domainDNS"],
            &[("name", "contoso")],
            &[],
            &[1, 2, 3],
        ),
        entry(
            &alice,
            &["top", "person", "organizationalPerson", "user"],
            &[
                ("name", "Alice"),
                ("sAMAccountName", "alice"),
                ("userAccountControl", "512"),
                ("primaryGroupID", "513"),
            ],
            &[],
            &[1, 2, 3, 1104],
        ),
        entry(
            &format!("CN=Domain Admins,CN=Users,{base}"),
            &["top", "group"],
            &[
                ("name", "Domain Admins"),
                ("sAMAccountName", "Domain Admins"),
            ],
            &[("member", vec![alice.as_str()])],
            &[1, 2, 3, 512],
        ),
        entry(
            &format!("CN=WS01,CN=Computers,{base}"),
            &["top", "person", "organizationalPerson", "user", "computer"],
            &[
                ("name", "WS01"),
                ("sAMAccountName", "WS01$"),
                ("dNSHostName", "ws01.contoso.local"),
                ("userAccountControl", "4096"),
                ("primaryGroupID", "515"),
            ],
            &[],
            &[1, 2, 3, 1105],
        ),
    ];

    let options = base_options(
        "contoso.local",
        &out,
        CollectionMethod::LdapOnly,
        "dc01.contoso.local".into(),
        true,
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let n = entries.len();
    let results = rt
        .block_on(rusthound_ce::prepare_results_from_source(
            entries,
            &options,
            Some(n),
        ))
        .map_err(|e| e.to_string())
        .unwrap();
    let written = rusthound_ce::make_result(&options, results)
        .map_err(|e| e.to_string())
        .unwrap();

    let files = output::discover_outputs(&out, &before);
    assert_eq!(files.len(), 1, "one zip: {files:?} ({written})");
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        pathwarden_core::time::timestamp_in_name(&name).is_some(),
        "file name carries the collection time: {name}"
    );
    let summary: std::collections::BTreeMap<_, _> =
        output::summarize_outputs(&files).into_iter().collect();
    // RustHound-CE adds well-known principals (NT AUTHORITY, builtin
    // groups), so users and groups exceed the synthetic counts.
    assert!(summary.get("users").is_some_and(|&n| n >= 1), "{summary:?}");
    assert!(
        summary.get("groups").is_some_and(|&n| n >= 1),
        "{summary:?}"
    );
    assert_eq!(summary.get("computers"), Some(&1), "{summary:?}");
    assert_eq!(summary.get("domains"), Some(&1), "{summary:?}");

    // Pathwarden loads the directory exactly as `report -i <dir>` would.
    let (g, stats) =
        pathwarden_core::load(&[&out], &pathwarden_core::LoadOptions::default()).unwrap();
    assert!(stats.collected_at.is_some());
    assert!(stats.skipped_files.is_empty(), "{:?}", stats.skipped_files);
    let user = g.lookup("S-1-5-21-1-2-3-1104").expect("user ingested");
    let da = g.lookup("S-1-5-21-1-2-3-512").expect("group ingested");
    assert!(
        g.lookup("S-1-5-21-1-2-3-1105").is_some(),
        "computer ingested"
    );
    assert!(
        g.transitive_members(da).contains(&user),
        "Alice is a member of Domain Admins"
    );
    assert!(g.node(da).tier_zero, "Domain Admins is Tier Zero");
    let _ = std::fs::remove_dir_all(&out);
}

/// A resumed read keeps the domain controller it started on, before
/// any is located; a trusted domain otherwise gets the located one, on
/// the LDAPS port; a named one is never replaced.
#[test]
fn a_resumed_read_keeps_its_dc_before_one_is_located() {
    let root = std::env::temp_dir().join(format!("pw-pick-dc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut req = CollectRequest::new("fabrikam.com", root.join("out"));
    req.ldaps = true;
    req.locate_dc = true;
    req.cache = Some(crate::ReadCache {
        root: root.clone(),
        resume: true,
        ..crate::ReadCache::default()
    });
    let asked = std::cell::RefCell::new(Vec::new());
    let mut find = |d: &str, port: u16, _: &mut dyn FnMut(String)| {
        asked.borrow_mut().push((d.to_string(), port));
        Ok::<_, crate::locate::NotFound>("dc02.fabrikam.com".to_string())
    };
    // Nothing to resume: the located one, on 636.
    let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    assert_eq!(pick_dc(&mut job, &req, &mut find, &mut |_| {}), None);
    assert_eq!(job.server.as_deref(), Some("dc02.fabrikam.com"));
    assert_eq!(job.url, "ldaps://dc02.fabrikam.com:636");
    assert_eq!(*asked.borrow(), [("fabrikam.com".to_string(), 636)]);

    // A stopped read: its own controller, and nothing located.
    asked.borrow_mut().clear();
    fake_stopped_read(&root, "fabrikam.com", &req.auth, 40, cache::now()).unwrap();
    let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    let mut log = Vec::new();
    pick_dc(&mut job, &req, &mut find, &mut |l| log.push(l));
    assert_eq!(job.server.as_deref(), Some("dc01.fabrikam.com"));
    assert!(asked.borrow().is_empty(), "{:?}", asked.borrow());
    assert!(log[0].contains("resuming on dc01.fabrikam.com"), "{log:?}");

    // Named with --server DOMAIN=HOST: kept, nothing located.
    req.cache = None;
    req.server = Some("dc07.fabrikam.com".into());
    req.locate_dc = false;
    let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    pick_dc(&mut job, &req, &mut find, &mut |_| {});
    assert_eq!(job.url, "ldaps://dc07.fabrikam.com:636");
    assert!(asked.borrow().is_empty());
    // The first domain (no locate_dc) keeps the domain's name.
    req.server = None;
    let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    pick_dc(&mut job, &req, &mut find, &mut |_| {});
    assert_eq!(job.url, "ldaps://fabrikam.com:636");
    assert!(asked.borrow().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

/// No domain controller found: the domain's name is used, and
/// when it fails as a name would (its certificate names the host), the
/// error says none was found, with what each way said behind it; a
/// domain controller that answered keeps its own reason.
#[test]
fn none_located_says_why() {
    let mut req = CollectRequest::new("fabrikam.com", "out");
    req.ldaps = true;
    req.locate_dc = true;
    let mut none = |_: &str, _: u16, _: &mut dyn FnMut(String)| {
        Err(crate::locate::NotFound {
            why: "DNS found none: no such name (DNS error 9003)".into(),
            found: false,
            outside: false,
        })
    };
    let mut job = job_for(&req, CollectionMethod::LdapOnly).unwrap();
    let why = pick_dc(&mut job, &req, &mut none, &mut |_| {});
    assert_eq!(job.url, "ldaps://fabrikam.com:636");
    assert_eq!(job.server, None);
    let cert = ConnectionError::new(
        "rustls error: invalid peer certificate: certificate not valid for name \
             \"fabrikam.com\"",
    );
    let e = not_located("fabrikam.com", why.as_ref(), false, cert.clone());
    assert_eq!(e.problem, crate::Problem::NotLocated);
    assert_eq!(e.message(), crate::locate::not_found("fabrikam.com"));
    assert!(e.detail.starts_with("DNS found none: no such name (DNS error 9003); then by the domain's name: rustls error"), "{}", e.detail);
    // Located (or named): the error as it is.
    assert_eq!(
        not_located("fabrikam.com", None, false, cert.clone()).problem,
        crate::Problem::CertificateName
    );
    let refused = ConnectionError::new("rc=49 (invalidCredentials)");
    assert_eq!(
        not_located("fabrikam.com", why.as_ref(), false, refused).problem,
        crate::Problem::Credentials
    );
    // After a connection (the run had its domain controller), a
    // timeout or a refusal keeps its own reason.
    let stalled = ConnectionError::new("timeout: no answer from the domain controller");
    assert_eq!(stalled.problem, crate::Problem::Timeout);
    assert_eq!(
        not_located("fabrikam.com", why.as_ref(), true, stalled.clone()).problem,
        crate::Problem::Timeout
    );
    assert!(unlocated("fabrikam.com", why.as_ref(), true, &stalled).is_none());
    assert_eq!(
        unlocated("fabrikam.com", why.as_ref(), false, &stalled)
            .unwrap()
            .problem,
        crate::Problem::NotLocated
    );
    assert_eq!(
        not_located("fabrikam.com", why.as_ref(), true, cert).problem,
        crate::Problem::CertificateName
    );
}
