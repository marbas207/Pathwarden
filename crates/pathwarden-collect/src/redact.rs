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
#[path = "redact_tests.rs"]
mod tests;
