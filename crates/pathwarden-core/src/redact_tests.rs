use super::*;

/// Every secret form the module names is masked in a log line.
#[test]
fn log_lines_keep_no_secret() {
    let s = "S3cr3tValue-xyz987";
    let lines = [
        format!("pushing to https://ci:{s}@git.example.test/team/history.git"),
        format!("token={s}"),
        format!("request: {{\"api_key\": \"{s}\", \"n\": 1}}"),
        format!("settings: client_secret: {s}"),
        format!("Authorization: Bearer {s}"),
        format!("Cookie: session={s}; theme=dark"),
        format!("Set-Cookie: id={s}; HttpOnly"),
        format!("sent with Bearer {s} to the instance"),
        format!("the passphrase: {s}"),
        format!("https://example.test/x?sig={s}&se=2026"),
        format!("a LAPS line: {s}"),
        format!("Groups.xml cpassword={s}"),
    ];
    for line in &lines {
        let out = log_line(line);
        assert!(!out.contains(s), "{line} -> {out}");
    }
    assert_eq!(log_line(&lines[1]), "token=***");
    assert_eq!(
        log_line(&lines[4]),
        "Authorization: ***",
        "a header keeps nothing after its name"
    );
}

#[test]
fn tokens_are_masked_by_their_form() {
    for t in [
        "ghp_0123456789abcdefABCDEF0123456789abcd",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
        "glpat-abcdefghij0123456789",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl",
        "AKIAABCDEFGHIJKLMNOP",
    ] {
        let out = log_line(&format!("the plugin said {t} was refused"));
        assert!(!out.contains(t), "{out}");
        assert!(out.contains("***"), "{out}");
    }
}

/// Values of secret environment variables are masked wherever they are.
#[test]
fn registered_secrets_are_masked() {
    register_secret("Wx9-registered-value");
    register_secret("ab"); // too short to mask: ignored
    let out = log_line("history: sealing with Wx9-registered-value as typed");
    assert_eq!(out, "history: sealing with *** as typed");
    assert_eq!(log_line("ab cd"), "ab cd");
}

/// Ordinary lines, and the names of environment variables, pass as they are.
#[test]
fn ordinary_lines_pass() {
    for line in [
        "collector RustHound-CE 2.4.1 started (pid 11820)",
        "SharpHound exited with exit code: 3",
        "users 41,208 · groups 6,914 · computers 12,377",
        "settings: token_env=PATHWARDEN_JIRA_TOKEN, timeout 30 s",
        "domain controller dc01.scale.local (chosen)",
        "the session ended",
        "result: failed: The collection failed: the LDAP connection was reset",
    ] {
        assert_eq!(log_line(line), line);
    }
}

#[test]
fn a_password_line_is_hidden_whole() {
    assert_eq!(log_line("Password for svc is hunter22"), HIDDEN_LINE);
    // A collector's line, already hidden or rewritten, stays as it said.
    assert_eq!(log_line(HIDDEN), HIDDEN);
    assert_eq!(
        log_line("Your user can read LAPS password on WS01: x"),
        "LAPS: the collecting account can read the local administrator password of WS01 \
         (the password is not shown)"
    );
}

/// Webhook URLs lose their secret path, any URL its query values.
#[test]
fn urls_keep_no_secret() {
    for (url, want) in [
        (
            "https://hooks.slack.com/services/T000/B000/XXXXsecret",
            "https://hooks.slack.com/services/***",
        ),
        (
            "https://contoso.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/456",
            "https://contoso.webhook.office.com/webhookb2/***",
        ),
        (
            "https://discord.com/api/webhooks/123/tok-en",
            "https://discord.com/api/webhooks/***",
        ),
        (
            "https://desk.example.test/api/x?id=7&key=abc123&flag",
            "https://desk.example.test/api/x?id=***&key=***&flag",
        ),
        (
            "https://desk.example.test/ticket/42",
            "https://desk.example.test/ticket/42",
        ),
    ] {
        assert_eq!(
            log_line(&format!("posted to {url} (200)")),
            format!("posted to {want} (200)")
        );
    }
}

/// A form's password is masked while its job runs, then no longer held.
#[test]
fn a_typed_secret_is_masked_for_its_job() {
    {
        let _m = mask_while("Typed-Form-Secret-77");
        assert_eq!(
            log_line("bind as x with Typed-Form-Secret-77"),
            "bind as x with ***"
        );
    }
    assert_eq!(
        log_line("bind as x with Typed-Form-Secret-77"),
        "bind as x with Typed-Form-Secret-77"
    );
}
