//! Keeps secrets out of collector log lines before they reach the Collect
//! page, `/api/jobs`, the terminal or an error message.
//!
//! RustHound-CE logs readable LAPS passwords at `info` level ("Your user can
//! read LAPS password on PC01: <password>", for `ms-Mcs-AdmPwd` and
//! `msLAPS-Password`, in `objects/computer.rs`), and an external
//! `rusthound-ce` prints the same lines. A LAPS line is rewritten to name the
//! computer only; any other line that mentions a password or LAPS is
//! replaced as a whole, because its format is not known and the secret could
//! be anywhere in it. The rule errs on the side of hiding: a harmless line
//! that says "password" is hidden too.

use std::borrow::Cow;

/// What replaces a line that mentions password material.
pub(crate) const HIDDEN: &str =
    "(a collector message that mentions a password was hidden; Pathwarden never shows password values)";

/// `line`, or a safe replacement when it may carry a password.
pub(crate) fn log_line(line: &str) -> Cow<'_, str> {
    if !sensitive(line) {
        return Cow::Borrowed(line);
    }
    match laps_computer(line) {
        Some(name) => Cow::Owned(format!(
            "LAPS: the collecting account can read the local administrator password of {name} \
             (the password is not shown)"
        )),
        None => Cow::Borrowed(HIDDEN),
    }
}

/// Whether a word of `line` names password material: `password`,
/// `passwd`, `pwd`, `ms-Mcs-AdmPwd`, `msLAPS-*`, `cpassword`, or `LAPS`.
fn sensitive(line: &str) -> bool {
    line.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .any(|w| {
            let w = w.to_lowercase();
            w.contains("password")
                || w.contains("passwd")
                || w.contains("admpwd")
                || w.contains("pwd")
                || w == "laps"
                || w.starts_with("mslaps")
        })
}

/// The computer in RustHound-CE's "...can read [uncrypted ]LAPS password on
/// NAME..." line, when it is a plain computer name.
fn laps_computer(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("can read") {
        return None;
    }
    let at = lower.find("laps password on ")? + "laps password on ".len();
    let rest = &line[at..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '$')))
        .unwrap_or(rest.len());
    let name = rest[..end].trim_end_matches('.');
    (!name.is_empty() && name.len() <= 64).then_some(name)
}

#[cfg(test)]
mod tests {
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
}
