use super::*;

/// The exact lines RustHound-CE 2.5.23 logs (`objects/computer.rs`), after
/// the ANSI colors are stripped; `{:?}` quotes the new-LAPS JSON.
#[test]
fn laps_values_never_pass() {
    let secret = "Xk7!pq2#LongLapsValue";
    let lines = [
            format!("Your user can read LAPS password on WS01: {secret}"),
            format!(
                "Your user can read LAPS password on SRV-02: \"{{\\\"n\\\":\\\"Administrator\\\",\\\"t\\\":\\\"1d9\\\",\\\"p\\\":\\\"{secret}\\\"}}\""
            ),
            format!("Your user can read LAPS password on \u{1b}[1;33mWS03\u{1b}[0m: {secret}"),
            format!("ms-Mcs-AdmPwd for WS01 = {secret}"),
            format!("msLAPS-Password: {secret}"),
            format!("[gpo] Groups.xml cpassword={secret}"),
            format!("something about a PASSWORD: {secret}"),
            format!("pwd={secret}"),
            format!("LAPS {secret}"),
        ];
    for line in &lines {
        let out = log_line(line);
        assert!(!out.contains(secret), "{line} -> {out}");
        assert!(!out.contains("1d9"), "{out}");
    }
    assert_eq!(
        log_line(&lines[0]),
        "LAPS: the collecting account can read the local administrator password of WS01 \
             (the password is not shown)"
    );
    assert!(log_line(&lines[1]).contains("password of SRV-02 ("));
    // A colored name is not a plain name: the line is hidden instead.
    assert_eq!(log_line(&lines[2]), HIDDEN);
    assert_eq!(log_line(&lines[5]), HIDDEN);
    assert_eq!(
            log_line("Your user can read uncrypted LAPS password on PC9 please check manually to decrypt it!"),
            "LAPS: the collecting account can read the local administrator password of PC9 \
             (the password is not shown)"
        );
}

#[test]
fn ordinary_lines_pass_unchanged() {
    for line in [
        "Starting the LDAP objects parsing...",
        "Starting checker to replace some values...",
        "All data collected for naming context DC=contoso,DC=local",
        "1234 users parsed!",
        "[gpo] collected directives from 12 GPO(s) on dc01.contoso.local SYSVOL",
        "warning: WriteRDN ACE: S-1-5-21-1 has WriteProperty on the RDN/name of X",
        "MachineAccountQuota: 10",
        // "laps" inside a word is not LAPS.
        "collapsed 3 entries",
    ] {
        assert!(
            matches!(log_line(line), Cow::Borrowed(l) if l == line),
            "{line}"
        );
    }
}
