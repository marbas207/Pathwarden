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
