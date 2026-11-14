//! Who is running Pathwarden, and on which computer: what an accepted risk
//! (and later a shared run) records as its author. Every path that records
//! one takes it from [`Actor::current`], so the app, the CLI and a schedule
//! name people and machines the same way.
//!
//! It is the account the process runs as: the person in the app or at the
//! command line, and for a scheduled task the task's account (a gMSA or a
//! managed service account ends in `$`, such as `CONTOSO\svc-pathwarden$`).
//! It is read from the environment, so it records who ran Pathwarden, not
//! a proof of it.

use std::borrow::Cow;

/// Longest name kept (Windows allows 256 for a domain plus 20 for a user).
const MAX_NAME: usize = 300;

/// A user and the computer they used.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Actor {
    /// `DOMAIN\user` on Windows, the login name elsewhere. `None` when the
    /// environment doesn't say.
    pub user: Option<String>,
    /// The computer name (`COMPUTERNAME` on Windows, the host name elsewhere).
    pub computer: Option<String>,
}

impl Actor {
    /// The account this process runs as, and this computer.
    pub fn current() -> Actor {
        let var = |k: &str| std::env::var(k).ok();
        // Windows: DOMAIN\user. Elsewhere USERNAME is no standard and
        // USERDOMAIN means nothing, so only the login name.
        let (domain, username) = if cfg!(windows) {
            (var("USERDOMAIN"), var("USERNAME"))
        } else {
            (None, None)
        };
        Actor {
            user: user_name(domain, username, var("USER"), var("LOGNAME"))
                .or_else(|| tidy(os_user_name().map(Cow::Owned))),
            computer: tidy(var("COMPUTERNAME").map(Cow::Owned))
                .or_else(|| tidy(var("HOSTNAME").map(Cow::Owned)))
                .or_else(|| tidy(os_host_name().map(Cow::Owned))),
        }
    }
}

/// The user name from the variables [`Actor::current`] reads: Windows'
/// `USERDOMAIN\USERNAME` when `USERNAME` is set (the domain left out when it
/// isn't), otherwise `USER`, then `LOGNAME`.
fn user_name(
    domain: Option<String>,
    username: Option<String>,
    user: Option<String>,
    logname: Option<String>,
) -> Option<String> {
    let domain = tidy(domain.map(Cow::Owned));
    if let Some(name) = tidy(username.map(Cow::Owned)) {
        return Some(match domain {
            Some(d) if !name.contains('\\') => format!("{d}\\{name}"),
            _ => name,
        });
    }
    tidy(user.map(Cow::Owned)).or_else(|| tidy(logname.map(Cow::Owned)))
}

/// Trimmed, control characters dropped, at most [`MAX_NAME`] characters;
/// `None` when nothing is left.
fn tidy(s: Option<Cow<'_, str>>) -> Option<String> {
    let s: String = s?
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect();
    (!s.is_empty()).then_some(s)
}

/// The host name where shells don't export `HOSTNAME` (a systemd service,
/// cron). Windows always sets `COMPUTERNAME`, services and scheduled tasks
/// included. Read from files, so the crate's unsafe code stays where it is.
fn os_host_name() -> Option<String> {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .filter(|_| cfg!(unix))
        .find_map(|p| {
            let s = std::fs::read_to_string(p).ok()?;
            let s = s.trim();
            (!s.is_empty()).then(|| s.to_string())
        })
}

/// The account's name where the environment has none (a service started
/// with a stripped environment, a container): this process's user ID,
/// looked up in `/etc/passwd`. Windows always sets `USERNAME`; without it
/// the user is left unknown, and accepted risks say "by an unknown user".
#[cfg(unix)]
fn os_user_name() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd_name(&passwd, uid)
}

#[cfg(not(unix))]
fn os_user_name() -> Option<String> {
    None
}

/// The name of user `uid` in an `/etc/passwd` text.
#[cfg_attr(not(unix), allow(dead_code))]
fn passwd_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let id = f.nth(1)?.parse::<u32>().ok()?;
        (id == uid && !name.is_empty()).then(|| name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_id_is_named_from_passwd() {
        let passwd =
            "root:x:0:0:root:/root:/bin/sh\n# comment\nned:x:1000:1000::/home/ned:/bin/bash\n";
        assert_eq!(passwd_name(passwd, 1000).as_deref(), Some("ned"));
        assert_eq!(passwd_name(passwd, 0).as_deref(), Some("root"));
        assert_eq!(passwd_name(passwd, 7), None);
    }

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn windows_names_carry_the_domain() {
        assert_eq!(
            user_name(s("NORTH"), s("eddard.stark"), None, None).as_deref(),
            Some("NORTH\\eddard.stark")
        );
        // A scheduled task's gMSA.
        assert_eq!(
            user_name(s("NORTH"), s("svc-pathwarden$"), s("ignored"), None).as_deref(),
            Some("NORTH\\svc-pathwarden$")
        );
        assert_eq!(
            user_name(None, s("analyst"), None, None).as_deref(),
            Some("analyst")
        );
        assert_eq!(
            user_name(s("  "), s(" analyst "), None, None).as_deref(),
            Some("analyst")
        );
    }

    #[test]
    fn elsewhere_the_login_name() {
        assert_eq!(
            user_name(None, None, s("ned"), s("other")).as_deref(),
            Some("ned")
        );
        assert_eq!(
            user_name(None, None, None, s("ned")).as_deref(),
            Some("ned")
        );
        assert_eq!(user_name(None, s(""), s(""), None), None);
    }

    #[test]
    fn names_are_tidied() {
        assert_eq!(tidy(Some("a\nb\u{7}".into())).as_deref(), Some("ab"));
        assert_eq!(tidy(Some("x".repeat(400).into())).unwrap().len(), MAX_NAME);
        assert_eq!(tidy(Some("\t".into())), None);
    }

    #[test]
    fn this_computer_has_a_name() {
        let me = Actor::current();
        // The user can be missing (a container without USER); the computer
        // always has a name.
        assert!(me.computer.is_some(), "{me:?}");
    }
}
