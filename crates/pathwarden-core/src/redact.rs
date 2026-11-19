//! Keeps secrets out of text Pathwarden shows or writes down: collector
//! output lines before they reach the Collect page, `/api/jobs`, the
//! terminal or an error message ([`collector_line`]), and every line of a
//! log or crash report ([`log_line`]). Redaction is never optional.
//!
//! RustHound-CE logs readable LAPS passwords at `info` level ("Your user can
//! read LAPS password on PC01: <password>", for `ms-Mcs-AdmPwd` and
//! `msLAPS-Password`, in `objects/computer.rs`), and an external
//! `rusthound-ce` prints the same lines. A LAPS line is rewritten to name the
//! computer only; any other line that mentions a password or LAPS is
//! replaced as a whole, because its format is not known and the secret could
//! be anywhere in it. The rule errs on the side of hiding: a harmless line
//! that says "password" is hidden too.
//!
//! A log line also loses ([`log_line`]): the user name and password of a
//! URL (`https://user:token@host`), the value after a key that names a
//! secret (`token=`, `"api_key": "..."`, `Authorization:`, `Cookie:`), the
//! word after `Bearer` or `Basic`, access tokens by their well-known
//! prefixes (`ghp_`, `glpat-`, `xoxb-` ...), JSON web tokens, and the
//! values of the secret environment variables this process read
//! ([`register_secret`]).

use std::borrow::Cow;
use std::sync::Mutex;

/// What replaces a line that mentions password material.
pub const HIDDEN: &str =
    "(a collector message that mentions a password was hidden; Pathwarden never shows password values)";

/// What replaces a secret value in a log line.
pub const MASK: &str = "***";

/// `line`, or a safe replacement when it may carry a password.
pub fn collector_line(line: &str) -> Cow<'_, str> {
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

/// Secret values this process read (the history passphrase, the collect
/// password and the variables a plugin's `*_env` settings name), masked
/// wherever a log line holds them.
static SECRETS: Mutex<Vec<zeroize::Zeroizing<String>>> = Mutex::new(Vec::new());

/// The most secret values kept for [`log_line`].
const MAX_SECRETS: usize = 64;

/// Masks `value` in every later [`log_line`]. Values shorter than 4
/// characters are ignored: they would mask ordinary words.
pub fn register_secret(value: &str) {
    let v = value.trim();
    if v.chars().count() < 4 {
        return;
    }
    let mut all = SECRETS.lock().unwrap_or_else(|e| e.into_inner());
    if all.len() < MAX_SECRETS && !all.iter().any(|s| s.as_str() == v) {
        all.push(zeroize::Zeroizing::new(v.to_string()));
    }
}

/// `line` as a log may keep it: [`collector_line`], then every secret the
/// module's documentation lists masked with [`MASK`].
pub fn log_line(line: &str) -> String {
    let line = collector_line(line);
    let mut out = crate::config::redact_urls(&line);
    {
        let all = SECRETS.lock().unwrap_or_else(|e| e.into_inner());
        for s in all.iter() {
            if out.contains(s.as_str()) {
                out = out.replace(s.as_str(), MASK);
            }
        }
    }
    let out = keyed_values(&out);
    words(&out)
}

/// Keys whose whole rest of the line is a secret (HTTP headers).
const HEADER_KEYS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

/// Whether a key (lower case) names a secret.
fn secret_key(k: &str) -> bool {
    if k.ends_with("_env") || k.ends_with("-env") {
        // An environment variable's name, not its value.
        return false;
    }
    HEADER_KEYS.contains(&k)
        || [
            "token",
            "secret",
            "passphrase",
            "apikey",
            "api_key",
            "api-key",
            "cookie",
            "credential",
            "private_key",
            "access_key",
            "sessionid",
            "session_id",
        ]
        .iter()
        .any(|w| k.contains(w))
        || matches!(k, "auth" | "sig")
}

/// The value after every key that names a secret, masked: `key=value`,
/// `key: value`, `"key": "value"`; a header key masks the rest of the line.
fn keyed_values(line: &str) -> String {
    let b = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    let mut copied = 0;
    let key_byte = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    while i < b.len() {
        if !key_byte(b[i]) || (i > 0 && key_byte(b[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && key_byte(b[i]) {
            i += 1;
        }
        let key = line[start..i].to_ascii_lowercase();
        if !secret_key(&key) {
            continue;
        }
        let mut j = i;
        if j < b.len() && matches!(b[j], b'"' | b'\'') {
            j += 1;
        }
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        if j >= b.len() || !matches!(b[j], b'=' | b':') {
            continue;
        }
        j += 1;
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        let quote = (j < b.len() && matches!(b[j], b'"' | b'\'')).then(|| b[j]);
        if quote.is_some() {
            j += 1;
        }
        let end = if HEADER_KEYS.contains(&key.as_str()) && quote.is_none() {
            b.len()
        } else {
            let mut e = j;
            while e < b.len() {
                let c = b[e];
                let stop = match quote {
                    Some(q) => c == q,
                    None => {
                        c.is_ascii_whitespace() || matches!(c, b',' | b';' | b'&' | b'}' | b')')
                    }
                };
                if stop {
                    break;
                }
                e += 1;
            }
            e
        };
        if end > j && &line[j..end] != MASK {
            out.push_str(&line[copied..j]);
            out.push_str(MASK);
            copied = end;
        }
        i = end.max(i);
    }
    out.push_str(&line[copied..]);
    out
}

/// Words that are secrets by their form: the word after `Bearer`, `Basic`
/// or `Negotiate`, access tokens by their prefix, JSON web tokens and AWS
/// access key IDs.
fn words(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut after_scheme = false;
    for (i, part) in line.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let word = part.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')'));
        let lower = word.to_ascii_lowercase();
        let secret = !word.is_empty()
            && word != MASK
            && (after_scheme
                || crate::config::TOKEN_PREFIXES
                    .iter()
                    .any(|p| lower.starts_with(p) && word.len() >= p.len() + 8)
                || jwt(word)
                || aws_key(word));
        after_scheme = matches!(lower.as_str(), "bearer" | "basic" | "negotiate");
        if secret {
            out.push_str(&part.replacen(word, MASK, 1));
        } else {
            out.push_str(part);
        }
    }
    out
}

/// `eyJ...` with two dots: a JSON web token.
fn jwt(w: &str) -> bool {
    w.starts_with("eyJ")
        && w.len() > 20
        && w.matches('.').count() >= 2
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '='))
}

/// `AKIA` and 16 upper-case letters or digits: an AWS access key ID.
fn aws_key(w: &str) -> bool {
    w.len() == 20
        && (w.starts_with("AKIA") || w.starts_with("ASIA"))
        && w.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
