use super::*;

/// What a Quick collection leaves out by design is information, in
/// today's words and older runs'; a real problem is a warning.
#[test]
fn scope_notes_are_not_warnings() {
    for note in [
            NO_SESSIONS_NOTE,
            NO_SYSVOL_NOTE,
            "DC-only collection: no sessions or local groups, so paths through logged-on admins and \
             local admin rights are missing (Pathwarden reports this under collection completeness)",
            "group policy local groups (SYSVOL) are not collected without a password",
        ] {
            assert!(is_scope_note(note), "{note}");
        }
    for warning in [
        "LDAPS certificates were not checked, so a machine in the middle could read or change \
             the collection.",
        "Sessions were not fully read on 3 of 4 computers (SRVSVC on 3).",
        "",
    ] {
        assert!(!is_scope_note(warning), "{warning}");
    }
}

#[test]
fn one_line_drops_control_characters_and_runs_of_spaces() {
    assert_eq!(
        one_line("text: \"80090308: LdapErr: DSID-0C09041C, data 52e, v4563\0\""),
        "text: \"80090308: LdapErr: DSID-0C09041C, data 52e, v4563\""
    );
    assert_eq!(
        one_line("  WS1 SamrConnect2:                         rc=5\r\n  denied\t"),
        "WS1 SamrConnect2: rc=5 denied"
    );
    assert_eq!(one_line(""), "");
}

#[test]
fn collector_errors_lead_with_plain_words() {
    let dns = explained(anyhow::anyhow!(
        "cannot connect to ldaps://nort.sevenkingdoms.local:636: I/O error: No such host is \
             known. (os error 11001)"
    ));
    let ce = dns.downcast_ref::<ConnectionError>().expect("explained");
    assert_eq!(ce.problem, Problem::Dns);
    assert!(ce.detail.contains("nort.sevenkingdoms.local"), "{ce:?}");
    assert!(dns.to_string().starts_with(Problem::Dns.explain()), "{dns}");

    let password = explained(anyhow::anyhow!(
        "NTLM bind as NORTH\\x failed: LDAP operation result: rc=49 (invalidCredentials), \
             dn: \"\", text: \"80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext \
             error, data 52e, v4563\""
    ));
    assert!(
        password
            .to_string()
            .starts_with("The user name or password is wrong"),
        "{password}"
    );

    // Anything else, and cancelling, are left as they are.
    let odd = explained(anyhow::anyhow!("the collector crashed: x"));
    assert!(!odd.is::<ConnectionError>());
    assert!(explained(Cancelled.into()).is::<Cancelled>());
}

/// The summary's Computers line: with a password, both settings; as the
/// Windows account, signing is Windows' own; SharpHound enforces none.
#[test]
fn computers_words_say_how_computers_are_read() {
    let mut r = CollectRequest::new("contoso.local", "o");
    r.auth = Auth::Password {
        user: "svc".into(),
        password: Secret::new("Pw-1"),
    };
    assert_eq!(computers_words(&r), "Kerberos only, SMB signing required.");
    r.allow_unsigned_smb = true;
    assert_eq!(
        computers_words(&r),
        "Kerberos only, SMB signing not required."
    );
    r.auth = Auth::CurrentUser;
    assert_eq!(
        computers_words(&r),
        "Kerberos only, SMB signing left to Windows. (--allow-unsigned-smb has no effect \
             as the Windows account.)"
    );
    r.method = Method::External {
        program: "SharpHound.exe".into(),
        kind: ExternalKind::SharpHound,
    };
    assert!(computers_words(&r).starts_with("Kerberos only and SMB signing weren't enforced"));
}

#[test]
fn writing_to_changes_only_the_folder() {
    let mut r = CollectRequest::new("contoso.local", "a");
    r.auth = Auth::Password {
        user: "svc".into(),
        password: Secret::new("Pw-1"),
    };
    r.ldaps = true;
    let s = r.writing_to(PathBuf::from("b"));
    assert_eq!(s.output_dir, PathBuf::from("b"));
    assert!(s.ldaps);
    assert!(matches!(&s.auth, Auth::Password { user, password }
            if user == "svc" && password.expose() == "Pw-1"));
}

#[test]
fn host_names() {
    assert!(is_host_like("contoso.local"));
    assert!(is_host_like("dc01.contoso.local"));
    assert!(is_host_like("10.0.0.1"));
    assert!(!is_host_like("--collectionmethods"));
    assert!(!is_host_like("a b"));
    assert!(!is_host_like("x;rm -rf /"));
    assert!(!is_host_like(""));
}

/// Every log line the caller (Collect page, `/api/jobs`, terminal) gets
/// goes through the redaction, whatever its source.
#[test]
fn reporter_logs_never_carry_laps_passwords() {
    let mut got = Vec::new();
    {
        let mut sink = |p: Progress| {
            if let Progress::Log(l) = p {
                got.push(l)
            }
        };
        let mut rep = Reporter::new(vec![Step::new("x", "X", 1.0)], &mut sink);
        rep.log("Your user can read LAPS password on WS01: S3cr3t-Laps");
        rep.log("[2026-10-09T10:00:00Z INFO  rusthound_ce::objects::computer] Your user can read LAPS password on DC01: \"{\\\"p\\\":\\\"S3cr3t-Laps\\\"}\"");
        rep.log("1 users parsed!");
    }
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|l| !l.contains("S3cr3t-Laps")), "{got:?}");
    assert!(got[0].contains("WS01"));
    assert_eq!(got[2], "1 users parsed!");
}

#[test]
fn rejects_missing_program() {
    let mut req = CollectRequest::new("contoso.local", "out");
    req.method = Method::External {
        program: PathBuf::from("definitely/not/here/SharpHound.exe"),
        kind: ExternalKind::SharpHound,
    };
    let err = validate(&req).unwrap_err().to_string();
    assert!(err.contains("SharpHound.exe"), "{err}");
    let absent = std::env::temp_dir().join("pathwarden-no-such-dir/SharpHound.exe");
    req.method = Method::External {
        program: absent,
        kind: ExternalKind::SharpHound,
    };
    let err = validate(&req).unwrap_err().to_string();
    assert!(err.starts_with("collector program"), "{err}");
}

/// Collector paths on the command line: a path with a folder in
/// it is resolved against the current folder (as older scheduled tasks
/// give `.\SharpHound.exe`); a bare file name, which would be a lookup
/// in the current folder or on PATH, is refused; so is a network or
/// device path, before the file system is touched.
#[test]
fn collector_paths_are_full_and_local() {
    let cwd = std::env::current_dir().unwrap();
    for (given, want) in [
        (r".\SharpHound.exe", cwd.join("SharpHound.exe")),
        (
            r"tools\SharpHound.exe",
            cwd.join("tools").join("SharpHound.exe"),
        ),
        ("./rusthound-ce", cwd.join("rusthound-ce")),
    ] {
        // `\` separates folders on Windows only: elsewhere `.\SharpHound.exe`
        // is a bare file name, refused like one.
        if !cfg!(windows) && given.contains('\\') {
            let e = resolve_program(Path::new(given)).unwrap_err().to_string();
            assert!(e.contains("give its full path"), "{given}: {e}");
            continue;
        }
        let got = resolve_program(Path::new(given)).unwrap();
        assert!(got.is_absolute(), "{given}: {}", got.display());
        assert_eq!(got, want, "{given}");
    }
    let full = cwd.join("SharpHound.exe");
    assert_eq!(resolve_program(&full).unwrap(), full);

    let mut req = CollectRequest::new("contoso.local", "out");
    let refused = |req: &mut CollectRequest, p: &str| {
        req.method = Method::External {
            program: PathBuf::from(p),
            kind: ExternalKind::SharpHound,
        };
        validate(req).unwrap_err().to_string()
    };
    for bare in ["SharpHound.exe", "rusthound-ce"] {
        let e = refused(&mut req, bare);
        assert!(e.contains("give its full path"), "{bare}: {e}");
        assert!(resolve_program(Path::new(bare)).is_err());
    }
    // Resolved, then looked for: missing here, so refused as missing.
    let missing = if cfg!(windows) {
        r".\no-such-SharpHound.exe"
    } else {
        "./no-such-SharpHound.exe"
    };
    let e = refused(&mut req, missing);
    assert!(e.contains("no-such-SharpHound.exe"), "{e}");
    assert!(e.contains(&cwd.display().to_string()), "{e}");
    for network in [
        r"\\pathwarden-unc-test.invalid\share\SharpHound.exe",
        "//pathwarden-unc-test.invalid/share/SharpHound.exe",
        r"\\?\UNC\pathwarden-unc-test.invalid\share\SharpHound.exe",
        r"\\.\pipe\SharpHound",
    ] {
        let e = refused(&mut req, network);
        assert!(e.contains("network or device path"), "{network}: {e}");
    }
}

#[test]
fn password_errors_never_contain_the_password() {
    let mut req = CollectRequest::new("bad domain", "out");
    req.auth = Auth::Password {
        user: "svc".into(),
        password: Secret::new("S3cr3t-Value"),
    };
    let err = format!("{:?}", validate(&req).unwrap_err());
    assert!(!err.contains("S3cr3t-Value"));
    let dbg = format!("{req:?}");
    assert!(!dbg.contains("S3cr3t-Value"), "{dbg}");
}
