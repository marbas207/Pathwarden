use super::*;

fn local() -> Detected {
    Detected {
        account: Some(r"MAINDESKTOP\benja".into()),
        workgroup: true,
        ..Detected::default()
    }
}

#[test]
fn a_domain_account_defaults_to_itself() {
    let d = Detected {
        account: Some(r"CONTOSO\alice".into()),
        domain: Some("contoso.local".into()),
        domain_account: true,
        ..Detected::default()
    };
    let (current, text, why) = who_defaults(&d, true);
    assert!(current);
    assert!(text.contains(r"CONTOSO\alice") && text.contains("No password needed"));
    assert!(why.is_empty());
}

#[test]
fn a_local_account_defaults_to_a_password_and_says_why() {
    let (current, text, why) = who_defaults(&local(), true);
    // Without the built-in collector a password is no use.
    assert_eq!(current, !BUILTIN);
    assert!(text.contains("isn't a domain account"), "{text}");
    assert!(!text.contains("No password needed"));
    assert!(why.contains("isn't a domain account"), "{why}");
    assert!(why.contains("runas /netonly"));
    if BUILTIN {
        assert!(why.contains("chose a user and password"), "{why}");
    }
}

#[test]
fn elsewhere_only_a_password_works() {
    let (current, _, why) = who_defaults(&local(), false);
    assert!(!current);
    assert!(why.is_empty());
}

/// A run reads LDAPS, LDAP as the Windows account, or plain LDAP with a
/// password (a domain controller whose LDAPS failed).
#[test]
fn the_connection_is_said_as_it_was() {
    let mut c = CollectionInfo {
        read_started: None,
        plain_allowed: false,
        plain_fallback: false,
        method: "builtin".into(),
        scope: "dc-only".into(),
        domain: "CONTOSO.LOCAL".into(),
        server: Some("dc01.contoso.local".into()),
        ldaps: true,
        current_user: false,
        warnings: Vec::new(),
        kept: None,
        kerberos_only: Some(true),
        smb_signing: Some(true),
        domains: Vec::new(),
    };
    assert!(collected_words(&c).0.contains("over LDAPS,"));
    // A domain controller fell back: said, and LDAPS stays as asked.
    c.plain_fallback = true;
    assert!(
        collected_words(&c).0.contains(
            "over LDAPS (plain LDAP where it failed), signed in with a user and password."
        ),
        "{}",
        collected_words(&c).0
    );
    c.plain_fallback = false;
    c.ldaps = false;
    assert!(collected_words(&c).0.contains("over plain LDAP,"));
    c.current_user = true;
    assert!(collected_words(&c).0.contains("over LDAP,"));
}
