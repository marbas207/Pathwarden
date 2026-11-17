use super::*;

fn tgt() -> Tgt {
    Tgt {
        realm: "CONTOSO.LOCAL".into(),
        user: "svc-pathwarden".into(),
        ticket_der: vec![0x61, 3, 1, 2, 3],
        session_key: vec![9u8; 32],
        key_type: 18,
        auth_time: 1_800_000_000,
        start_time: 1_800_000_000,
        end_time: 1_800_036_000,
        renew_till: 1_800_604_800,
    }
}

#[test]
fn times_round_trip() {
    for secs in [0i64, 1_700_000_000, 1_800_036_000, 951_782_400] {
        assert_eq!(unix_of(&kerberos_time(secs)), secs, "{secs}");
    }
}

/// The cache is MIT ccache v4 as RustHound-CE parses it: the credential
/// for krbtgt/REALM with the 32-byte key and the ticket.
#[test]
fn the_cache_is_a_v4_ccache() {
    let b = ccache_bytes(&tgt());
    assert_eq!(&b[..2], &[0x05, 0x04]);
    let hlen = u16::from_be_bytes([b[2], b[3]]) as usize;
    assert_eq!(hlen, 12);
    let text = String::from_utf8_lossy(&b);
    assert!(text.contains("krbtgt"), "{text}");
    assert!(text.contains("CONTOSO.LOCAL"));
    assert!(b.windows(32).any(|w| w == [9u8; 32]), "the session key");
    assert!(
        b.ends_with(&[0x61, 3, 1, 2, 3, 0, 0, 0, 0]),
        "ticket, then no second ticket"
    );
}

/// Written to a new folder only this account can open, deleted with
/// its folder when dropped, and never in a Debug.
#[test]
fn the_cache_is_private_and_deleted() {
    let parent = std::env::temp_dir().join(format!("pw-krb-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).unwrap();
    let cache = TicketCache::write_in(&parent, &tgt()).unwrap();
    let file = cache.path().to_path_buf();
    let dir = file.parent().unwrap().to_path_buf();
    assert!(file.is_file());
    assert!(cache.name().starts_with("FILE:"));
    assert!(
        pathwarden_core::perms::others_with_access(&dir).is_empty(),
        "{:?}",
        pathwarden_core::perms::others_with_access(&dir)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    drop(cache);
    assert!(!file.exists(), "the cache is deleted");
    assert!(!dir.exists(), "and its folder");
    let _ = std::fs::remove_dir_all(&parent);
    let shown = format!("{:?}", tgt());
    assert!(!shown.contains("9, 9"), "{shown}");
}

/// A cache left by a run that was killed is swept by the next one once
/// stale: its file overwritten and removed with its folder. Other
/// folders, and one with something else in it, stay.
#[test]
fn stale_caches_are_swept() {
    let parent = std::env::temp_dir().join(format!("pw-krb-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    // A folder others can open is never swept.
    let open = std::env::temp_dir().join(format!("pw-krb-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&open);
    std::fs::create_dir_all(&open).unwrap();
    let in_open = TicketCache::write_in(&open, &tgt()).unwrap();
    let in_open_dir = in_open.path().parent().unwrap().to_path_buf();
    std::mem::forget(in_open);
    if !pathwarden_core::perms::is_private_dir(&open) {
        sweep_stale(&open, &open.join("x"), Duration::ZERO);
        assert!(
            in_open_dir.exists(),
            "not Pathwarden's private folder: left alone"
        );
    }
    let _ = std::fs::remove_dir_all(&open);
    pathwarden_core::perms::create_private_dir(&parent).unwrap();
    let left = TicketCache::write_in(&parent, &tgt()).unwrap();
    let left_dir = left.path().parent().unwrap().to_path_buf();
    std::mem::forget(left); // as a killed process leaves it
    let other = parent.join("not-pathwarden");
    std::fs::create_dir(&other).unwrap();
    let busy = parent.join("pathwarden-krb-busy");
    pathwarden_core::perms::create_private_dir(&busy).unwrap();
    std::fs::write(busy.join("something-else"), b"x").unwrap();
    // Not stale yet: kept.
    let now = parent.join("pathwarden-krb-now");
    pathwarden_core::perms::create_private_dir(&now).unwrap();
    sweep_stale(&parent, &now, STALE_AFTER);
    assert!(left_dir.exists());
    // Stale: swept.
    sweep_stale(&parent, &now, Duration::ZERO);
    assert!(!left_dir.exists(), "the leftover cache is gone");
    assert!(other.exists() && busy.exists() && now.exists());
    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn the_variable_is_restored() {
    let parent = std::env::temp_dir().join(format!("pw-krb-env-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(&parent).unwrap();
    let cache = TicketCache::write_in(&parent, &tgt()).unwrap();
    let _lock = super::super::KRB_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let before = std::env::var_os("KRB5CCNAME");
    {
        let _env = CcacheEnv::set(&cache);
        assert_eq!(std::env::var("KRB5CCNAME").unwrap(), cache.name());
    }
    assert_eq!(std::env::var_os("KRB5CCNAME"), before);
    drop(cache);
    let _ = std::fs::remove_dir_all(&parent);
}

/// KDC errors become plain words: the clock, the password, port 88.
#[test]
fn kdc_errors_in_plain_words() {
    let skew = KrbFailure::from_kdc(
        KRB_AP_ERR_SKEW,
        "dc01.contoso.local",
        "svc",
        "CONTOSO.LOCAL",
        Some(-540),
    );
    assert!(
        skew.headline
            .contains("clock is 9 minutes off dc01.contoso.local's"),
        "{skew:?}"
    );
    assert!(skew.headline.contains("allows 5 minutes"));
    assert_eq!(
        skew.detail,
        "KRB_AP_ERR_SKEW (37) from dc01.contoso.local:88"
    );
    let pw = KrbFailure::from_kdc(24, "dc01:88", "svc", "C.LOCAL", None);
    assert!(pw.headline.contains("refused the password"), "{pw:?}");
    assert_eq!(pw.detail, "KDC_ERR_PREAUTH_FAILED (24) from dc01:88");
    assert!(KrbFailure::from_kdc(14, "dc", "s", "R", None)
        .headline
        .contains("no AES Kerberos keys"));
    assert!(KrbFailure::from_kdc(18, "dc", "s", "R", None)
        .headline
        .contains("disabled, locked out"));
    assert!(KrbFailure::from_kdc(6, "dc", "svc", "R.LOCAL", None)
        .headline
        .contains("doesn't know the account svc in R.LOCAL"));
    for f in [skew, pw] {
        assert!(!f.headline.contains("--"), "no command-line flags: {f:?}");
        assert!(f.headline.ends_with('.'));
    }
}

/// Nothing listens on port 88 here: the reason is the port, at once.
#[test]
fn an_unreachable_kdc_is_port_88() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // A port that was free a moment ago.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let kdc = format!("127.0.0.1:{port}");
    let err = rt
        .block_on(request_tgt(
            &kdc,
            "contoso.local",
            "svc",
            &Secret::new("Krb-Secret-88"),
        ))
        .unwrap_err();
    assert!(err.headline.contains("port 88"), "{err:?}");
    assert!(!format!("{err:?}").contains("Krb-Secret-88"));
}

/// A fake KDC that answers pre-auth required, then the clock error:
/// the request carries an AES256 timestamp, and the skew is reported.
#[test]
fn a_fake_kdc_clock_error() {
    use picky_krb::messages::KrbErrorInner;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = |code: u32, stime: i64, e_data: Option<Vec<u8>>| -> Vec<u8> {
        let e = KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: picky_asn1::wrapper::ExplicitContextTag4::from(kerberos_time(stime)),
            susec: picky_asn1::wrapper::ExplicitContextTag5::from(IntegerAsn1(vec![0])),
            error_code: picky_asn1::wrapper::ExplicitContextTag6::from(code),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: picky_asn1::wrapper::ExplicitContextTag9::from(
                krb_string("CONTOSO.LOCAL").unwrap(),
            ),
            sname: picky_asn1::wrapper::ExplicitContextTag10::from(
                principal(NT_SRV_INST, &["krbtgt", "CONTOSO.LOCAL"]).unwrap(),
            ),
            e_text: Optional::from(None),
            e_data: Optional::from(
                e_data.map(|d| picky_asn1::wrapper::ExplicitContextTag12::from(OctetStringAsn1(d))),
            ),
        });
        picky_asn1_der::to_vec(&e).unwrap()
    };
    let info = picky_krb::data_types::EtypeInfo2Entry {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![AES256])),
        salt: Optional::from(Some(ExplicitContextTag1::from(
            krb_string("CONTOSO.LOCALsvc").unwrap(),
        ))),
        s2kparams: Optional::from(None),
    };
    let info = picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![info])).unwrap();
    let method =
        picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![padata(PA_ETYPE_INFO2, info)])).unwrap();
    let first = err(KDC_ERR_PREAUTH_REQUIRED, now_unix(), Some(method));
    let second = err(KRB_AP_ERR_SKEW, now_unix() + 9 * 60, None);
    let got = rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kdc = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut asked = Vec::new();
            for reply in [first, second] {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut len = [0u8; 4];
                s.read_exact(&mut len).await.unwrap();
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                s.read_exact(&mut req).await.unwrap();
                asked.push(req);
                s.write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                s.write_all(&reply).await.unwrap();
            }
            asked
        });
        let r = request_tgt(&kdc, "contoso.local", "svc", &Secret::new("Pw-Clock-1")).await;
        (r, server.await.unwrap(), kdc)
    });
    let (result, asked, kdc) = got;
    let e = result.unwrap_err();
    assert!(e.headline.contains("9 minutes off 127.0.0.1's"), "{e:?}");
    assert_eq!(e.detail, format!("KRB_AP_ERR_SKEW (37) from {kdc}"));
    // The first request has no timestamp; the second one does.
    let req: AsReq = picky_asn1_der::from_bytes(&asked[1]).unwrap();
    let pa = req.0.padata.0.unwrap().0 .0;
    assert!(pa
        .iter()
        .any(|p| int(&p.padata_type.0) == i64::from(PA_ENC_TIMESTAMP)));
    let etypes: Vec<i64> = req.0.req_body.0.etype.0 .0.iter().map(int).collect();
    assert_eq!(etypes, vec![18]);
    for r in &asked {
        assert!(!String::from_utf8_lossy(r).contains("Pw-Clock-1"));
    }
}

use super::fake::as_rep_for;

/// The AS-REP is opened with the key from the password and the salt;
/// a wrong nonce, a wrong key, another realm or anything but AES256 is
/// refused.
#[test]
fn an_as_rep_is_checked_before_its_ticket_is_kept() {
    let password = Secret::new("Pw-AsRep-1");
    let key = string_to_key(&password, "CONTOSO.LOCALsvc").unwrap();
    let nonce = vec![0x12, 0x34, 0x56, 0x78];
    let ok = decrypt(
        as_rep_for(&key, AES256, AES256, &nonce, "CONTOSO.LOCAL"),
        &nonce,
        &key,
        "CONTOSO.LOCAL",
        "svc",
    )
    .unwrap();
    assert_eq!(
        (ok.realm.as_str(), ok.user.as_str()),
        ("CONTOSO.LOCAL", "svc")
    );
    assert!(
        ok.summary().starts_with("AES256, valid "),
        "{}",
        ok.summary()
    );
    // The same through the no-pre-auth path, from the password.
    assert!(finish(
        as_rep_for(&key, AES256, AES256, &nonce, "contoso.local"),
        &nonce,
        "CONTOSO.LOCAL",
        "svc",
        &password,
        Some("CONTOSO.LOCALsvc".into()),
    )
    .is_ok());

    let refused =
        |rep: AsRep, k: &[u8]| decrypt(rep, &nonce, k, "CONTOSO.LOCAL", "svc").unwrap_err();
    let e = refused(
        as_rep_for(&key, AES256, AES256, &[1, 2, 3, 4], "CONTOSO.LOCAL"),
        &key,
    );
    assert!(e.detail.contains("nonce"), "{e:?}");
    let other = string_to_key(&Secret::new("Other-1"), "CONTOSO.LOCALsvc").unwrap();
    let e = refused(
        as_rep_for(&key, AES256, AES256, &nonce, "CONTOSO.LOCAL"),
        &other,
    );
    assert!(e.headline.contains("couldn't be read"), "{e:?}");
    let e = refused(as_rep_for(&key, AES256, AES256, &nonce, "EVIL.LOCAL"), &key);
    assert!(e.detail.contains("realm EVIL.LOCAL"), "{e:?}");
    let e = refused(as_rep_for(&key, 17, AES256, &nonce, "CONTOSO.LOCAL"), &key);
    assert!(e.headline.contains("no AES Kerberos keys"), "{e:?}");
    let e = refused(as_rep_for(&key, AES256, 17, &nonce, "CONTOSO.LOCAL"), &key);
    assert!(e.detail.contains("session key of etype 17"), "{e:?}");
    let e = refused(as_rep_for(&key, AES256, 23, &nonce, "CONTOSO.LOCAL"), &key);
    assert!(e.detail.contains("etype 23"), "{e:?}");
    // Another account, another service or another issuing realm.
    let e = decrypt(
        as_rep_for(&key, AES256, AES256, &nonce, "CONTOSO.LOCAL"),
        &nonce,
        &key,
        "CONTOSO.LOCAL",
        "admin",
    )
    .unwrap_err();
    assert!(e.detail.contains("for svc, not admin"), "{e:?}");
    for (srealm, sname) in [
        ("CONTOSO.LOCAL", ["krbtgt", "EVIL.LOCAL"]),
        ("CONTOSO.LOCAL", ["cifs", "CONTOSO.LOCAL"]),
        ("EVIL.LOCAL", ["krbtgt", "CONTOSO.LOCAL"]),
    ] {
        let rep = fake::as_rep_full(
            &key,
            (AES256, AES256),
            &nonce,
            "CONTOSO.LOCAL",
            srealm,
            &sname,
        );
        let e = refused(rep, &key);
        assert!(e.detail.contains("not krbtgt/CONTOSO.LOCAL"), "{e:?}");
    }
}

#[test]
fn aes128_only_accounts_are_told_so() {
    assert!(no_aes256(&[(17, None), (23, None)]).contains("AES128 Kerberos keys only"));
    assert!(no_aes256(&[(23, None)]).contains("no AES Kerberos keys"));
}

/// The ticket in the AP-REQ must be for this computer's cifs/ name (any
/// case); one for another name or service is refused.
#[test]
fn a_ticket_for_another_name_is_refused() {
    let good = fake::ap_req_token(&["cifs", "ws01.contoso.local"]);
    assert_eq!(check_ticket(&good, "WS01.CONTOSO.LOCAL"), Ok(()));
    let other = fake::ap_req_token(&["cifs", "evil.contoso.local"]);
    assert!(matches!(
        check_ticket(&other, "WS01.CONTOSO.LOCAL"),
        Err(NoTicket::Refused(w)) if w.contains("for cifs/evil.contoso.local, not cifs/WS01")
    ));
    let service = fake::ap_req_token(&["host", "ws01.contoso.local"]);
    assert!(check_ticket(&service, "WS01.CONTOSO.LOCAL").is_err());
    assert!(check_ticket(b"\x60\x00", "WS01.CONTOSO.LOCAL").is_err());
}

#[test]
fn service_ticket_errors() {
    assert_eq!(
        no_ticket("WS1.CONTOSO.LOCAL", "TGS-REP: KDC error 7"),
        NoTicket::NoName("no SPN cifs/WS1.CONTOSO.LOCAL".into())
    );
    assert!(matches!(
        no_ticket("WS1", "TGS-REP: KDC error 12"),
        NoTicket::Refused(w) if w.contains("a domain policy doesn't allow it (KDC_ERR_POLICY 12)")
    ));
    assert!(matches!(
        no_ticket("WS1", "connection refused"),
        NoTicket::Refused(w) if w.contains("connection refused")
    ));
}
