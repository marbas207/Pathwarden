//! What this computer and the signed-in account say about the domain, to
//! pre-fill the Collect wizard.
//!
//! The facts are read in one place ([`Facts::read`]) and turned into
//! [`Detected`] by a pure function, so the rules are tested without a domain.
//!
//! - The signed-in account is a *domain* account when Windows logged it on
//!   through a domain: `USERDNSDOMAIN` is set and `USERDOMAIN` is not this
//!   computer's name (a local account) nor `AzureAD` (Entra ID, which
//!   Active Directory doesn't accept).
//! - The computer's own domain comes from `NetGetJoinInformation` (is it
//!   joined to a domain, and its NetBIOS name) and `GetComputerNameExW`
//!   (its DNS name). A workgroup computer can have a DNS suffix too, so the
//!   suffix only counts when the computer is joined.

use std::path::PathBuf;

use super::host_like;

/// What this computer says about its domain, to pre-fill the wizard.
#[derive(Debug, Clone, Default)]
pub struct Detected {
    /// The domain to pre-fill, lower case: the signed-in account's domain
    /// (`USERDNSDOMAIN`) for a domain account, else the domain this computer
    /// is joined to.
    pub domain: Option<String>,
    /// The DC this session logged on through: `LOGONSERVER` plus the domain.
    pub dc: Option<String>,
    /// `DOMAIN\user` of the signed-in Windows account.
    pub account: Option<String>,
    /// Whether the signed-in account is a domain account (so "Use my Windows
    /// account" can sign in to Active Directory).
    pub domain_account: bool,
    /// The DNS name of the domain this computer is joined to, lower case.
    pub machine_domain: Option<String>,
    /// Windows says this computer is not joined to a domain.
    pub workgroup: bool,
    /// The domain's NetBIOS name, for the gMSA example.
    pub netbios: Option<String>,
    /// A `SharpHound.exe` next to Pathwarden.
    pub sharphound: Option<PathBuf>,
}

/// The raw facts [`Detected`] is made from.
#[derive(Debug, Clone, Default)]
pub(crate) struct Facts {
    /// `USERDOMAIN`: the account's domain, or this computer's name for a
    /// local account.
    pub user_domain: Option<String>,
    /// `USERDNSDOMAIN`: set only when a domain logged the account on.
    pub user_dns_domain: Option<String>,
    /// `USERNAME`.
    pub user_name: Option<String>,
    /// `COMPUTERNAME`.
    pub computer: Option<String>,
    /// `LOGONSERVER`, like `\\DC01` (or `\\THISPC` for a local logon).
    pub logon_server: Option<String>,
    /// What Windows says about joining a domain (`None`: not asked or not
    /// Windows).
    pub join: Option<Join>,
}

/// Whether this computer is joined to a domain. Only read on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum Join {
    /// Joined: the domain's NetBIOS name and, when known, its DNS name.
    Domain {
        netbios: String,
        dns: Option<String>,
    },
    /// In a workgroup, or not joined at all.
    Workgroup,
}

impl Detected {
    pub fn from_env() -> Self {
        let mut d = Detected::from_facts(&Facts::read());
        // Beside pathwarden.exe only: never the current folder,
        // which can be any folder Pathwarden was started from.
        if cfg!(windows) {
            d.sharphound = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("SharpHound.exe")))
                .filter(|p| p.is_file());
        }
        d
    }

    pub(crate) fn from_facts(f: &Facts) -> Self {
        let clean = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let (user_domain, user_name, computer) = (
            clean(&f.user_domain),
            clean(&f.user_name),
            clean(&f.computer),
        );
        let user_dns = clean(&f.user_dns_domain)
            .map(|v| v.to_ascii_lowercase())
            .filter(|v| host_like(v));
        // A domain account: a domain logged it on, and its domain is neither
        // this computer (a local account) nor Entra ID.
        let domain_account = match (&user_domain, &user_dns) {
            (Some(ud), Some(_)) => {
                !computer
                    .as_deref()
                    .is_some_and(|c| c.eq_ignore_ascii_case(ud))
                    && !ud.eq_ignore_ascii_case("AzureAD")
            }
            _ => false,
        };
        let mut d = Detected {
            domain_account,
            account: match (&user_domain, &user_name) {
                (Some(dom), Some(user)) => Some(format!("{dom}\\{user}")),
                _ => None,
            },
            ..Detected::default()
        };

        match &f.join {
            Some(Join::Domain { netbios, dns }) => {
                d.machine_domain = dns
                    .as_deref()
                    .map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase())
                    .filter(|v| host_like(v) && v.contains('.'));
                let n = netbios.trim();
                if !n.is_empty() {
                    d.netbios = Some(n.to_string());
                }
            }
            Some(Join::Workgroup) => d.workgroup = true,
            None => {}
        }

        if d.domain_account {
            d.domain = user_dns.clone();
            d.netbios = user_domain.clone();
            d.dc = user_dns.as_ref().and_then(|domain| {
                let server = clean(&f.logon_server)?;
                let name = server.trim_start_matches('\\');
                // A local logon names this computer, not a DC.
                (host_like(name)
                    && !computer
                        .as_deref()
                        .is_some_and(|c| name.eq_ignore_ascii_case(c)))
                .then(|| format!("{}.{domain}", name.to_ascii_lowercase()))
            });
        } else {
            d.domain = d.machine_domain.clone();
        }
        d
    }
}

impl Facts {
    /// Reads the facts from the environment and, on Windows, the system.
    pub fn read() -> Self {
        if !cfg!(windows) {
            return Facts::default();
        }
        let env = |k: &str| std::env::var(k).ok();
        Facts {
            user_domain: env("USERDOMAIN"),
            user_dns_domain: env("USERDNSDOMAIN"),
            user_name: env("USERNAME"),
            computer: env("COMPUTERNAME"),
            logon_server: env("LOGONSERVER"),
            join: join_information(),
        }
    }
}

#[cfg(windows)]
fn join_information() -> Option<Join> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName, NETSETUP_JOIN_STATUS,
    };
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsDomain, GetComputerNameExW,
    };

    let mut name: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut status: NETSETUP_JOIN_STATUS = 0;
    // SAFETY: both out-pointers are valid; the buffer Windows returns is
    // read up to its NUL and then freed with NetApiBufferFree.
    let netbios = unsafe {
        if NetGetJoinInformation(std::ptr::null(), &mut name, &mut status) != 0 {
            return None;
        }
        let s = if name.is_null() {
            String::new()
        } else {
            let len = (0..).take_while(|&i| *name.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
        };
        if !name.is_null() {
            NetApiBufferFree(name.cast());
        }
        s
    };
    if status != NetSetupDomainName {
        return Some(Join::Workgroup);
    }
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units; on success `len` is the length
    // written, without the NUL.
    let dns = unsafe {
        (GetComputerNameExW(ComputerNameDnsDomain, buf.as_mut_ptr(), &mut len) != 0)
            .then(|| String::from_utf16_lossy(&buf[..len as usize]))
    };
    Some(Join::Domain { netbios, dns })
}

#[cfg(not(windows))]
fn join_information() -> Option<Join> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.into())
    }

    /// A domain account on a joined computer.
    fn domain_user() -> Facts {
        Facts {
            user_domain: s("CONTOSO"),
            user_dns_domain: s("CONTOSO.LOCAL"),
            user_name: s("alice"),
            computer: s("WS01"),
            logon_server: s("\\\\DC01"),
            join: Some(Join::Domain {
                netbios: "CONTOSO".into(),
                dns: s("contoso.local"),
            }),
        }
    }

    #[test]
    fn domain_account_on_a_joined_computer() {
        let d = Detected::from_facts(&domain_user());
        assert!(d.domain_account);
        assert_eq!(d.domain.as_deref(), Some("contoso.local"));
        assert_eq!(d.dc.as_deref(), Some("dc01.contoso.local"));
        assert_eq!(d.account.as_deref(), Some("CONTOSO\\alice"));
        assert_eq!(d.netbios.as_deref(), Some("CONTOSO"));
        assert_eq!(d.machine_domain.as_deref(), Some("contoso.local"));
        assert!(!d.workgroup);
    }

    #[test]
    fn account_from_a_trusted_domain_keeps_its_own_domain() {
        let mut f = domain_user();
        f.user_domain = s("FABRIKAM");
        f.user_dns_domain = s("fabrikam.local");
        let d = Detected::from_facts(&f);
        assert!(d.domain_account);
        assert_eq!(d.domain.as_deref(), Some("fabrikam.local"));
        assert_eq!(d.dc.as_deref(), Some("dc01.fabrikam.local"));
        assert_eq!(d.netbios.as_deref(), Some("FABRIKAM"));
        assert_eq!(d.machine_domain.as_deref(), Some("contoso.local"));
    }

    #[test]
    fn local_account_on_a_joined_computer() {
        let f = Facts {
            user_domain: s("WS01"),
            user_dns_domain: None,
            user_name: s("admin"),
            computer: s("WS01"),
            logon_server: s("\\\\WS01"),
            ..domain_user()
        };
        let d = Detected::from_facts(&f);
        assert!(!d.domain_account);
        // The domain still comes from the computer; no DC from a local logon.
        assert_eq!(d.domain.as_deref(), Some("contoso.local"));
        assert_eq!(d.dc, None);
        assert_eq!(d.account.as_deref(), Some("WS01\\admin"));
        assert_eq!(d.netbios.as_deref(), Some("CONTOSO"));
    }

    #[test]
    fn local_account_on_a_workgroup_computer() {
        // The review's machine: USERDOMAIN is the computer's own name.
        let f = Facts {
            user_domain: s("MAINDESKTOP"),
            user_dns_domain: None,
            user_name: s("benja"),
            computer: s("MAINDESKTOP"),
            logon_server: s("\\\\MAINDESKTOP"),
            join: Some(Join::Workgroup),
        };
        let d = Detected::from_facts(&f);
        assert!(!d.domain_account);
        assert!(d.workgroup);
        assert_eq!(d.domain, None);
        assert_eq!(d.dc, None);
        assert_eq!(d.netbios, None);
        assert_eq!(d.account.as_deref(), Some("MAINDESKTOP\\benja"));
    }

    #[test]
    fn computer_name_comparison_ignores_case() {
        let mut f = domain_user();
        f.user_domain = s("ws01");
        assert!(!Detected::from_facts(&f).domain_account);
    }

    #[test]
    fn entra_id_account_is_not_a_domain_account() {
        let f = Facts {
            user_domain: s("AzureAD"),
            user_dns_domain: s("contoso.onmicrosoft.com"),
            user_name: s("alice"),
            computer: s("LAPTOP1"),
            logon_server: s("\\\\LAPTOP1"),
            join: Some(Join::Workgroup),
        };
        let d = Detected::from_facts(&f);
        assert!(!d.domain_account);
        assert_eq!(d.domain, None);
    }

    #[test]
    fn workgroup_dns_suffix_is_not_a_domain() {
        // A workgroup computer with a primary DNS suffix: not joined, so
        // the suffix isn't offered.
        let f = Facts {
            user_domain: s("PC"),
            computer: s("PC"),
            join: Some(Join::Workgroup),
            ..Facts::default()
        };
        assert_eq!(Detected::from_facts(&f).domain, None);
    }

    #[test]
    fn odd_values_are_dropped() {
        let mut f = domain_user();
        f.user_dns_domain = s("contoso.local; calc");
        f.join = Some(Join::Domain {
            netbios: " ".into(),
            dns: s("-evil"),
        });
        let d = Detected::from_facts(&f);
        assert!(!d.domain_account, "no usable DNS domain");
        assert_eq!(d.domain, None);
        assert_eq!(d.machine_domain, None);
        assert_eq!(d.netbios, None);
        // A logon server that isn't a host name gives no DC.
        let mut f = domain_user();
        f.logon_server = s("\\\\DC 01");
        assert_eq!(Detected::from_facts(&f).dc, None);
    }

    #[test]
    fn nothing_known_detects_nothing() {
        let d = Detected::from_facts(&Facts::default());
        assert!(!d.domain_account && !d.workgroup);
        assert_eq!(
            (d.domain, d.dc, d.account, d.netbios),
            (None, None, None, None)
        );
    }

    #[test]
    fn reading_this_computer_does_not_fail() {
        // Whatever this machine is, reading it works and is consistent.
        let d = Detected::from_env();
        if d.domain_account {
            assert!(d.domain.is_some());
        }
        if d.workgroup {
            assert!(d.machine_domain.is_none());
        }
    }
}
