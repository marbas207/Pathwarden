//! SCCM's site objects in the directory: the `mSSMSSite`
//! and `mSSMSManagementPoint` entries a site publishes under
//! `CN=System Management,CN=System`. Neither collector writes them to its
//! BloodHound files (RustHound-CE reads and drops them, SharpHound doesn't
//! read them), so Pathwarden's built-in collector keeps them in its
//! sidecar.
//!
//! They tie a site code to the computers of the site: the site object's
//! owner (the site server that created it) and each management point's
//! host. With them, an SCCM client domain controller is matched to the site
//! servers of its own site, not to every site server in its forest.

use serde::{Deserialize, Serialize};

/// Most sites and management points one sidecar lists.
const MAX_ENTRIES: usize = 10_000;

/// A site (`mSSMSSite`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    /// `mSSMSSiteCode`, upper case.
    pub site_code: String,
    /// The SID of the object's owner: the site server that published it,
    /// when it wasn't an administrator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// A management point (`mSSMSManagementPoint`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementPoint {
    /// `mSSMSSiteCode`, upper case.
    pub site_code: String,
    /// The management point's host (`dNSHostName`, else `mSSMSMPName`).
    pub host: String,
    /// `mSSMSDefaultMP`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default: bool,
}

/// What the collector found under `CN=System Management`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SccmSites {
    #[serde(default)]
    pub sites: Vec<Site>,
    #[serde(default)]
    pub management_points: Vec<ManagementPoint>,
}

/// An SCCM site code: three letters or digits.
pub fn is_site_code(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A DNS host name, as a management point names its host.
pub fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn is_sid(s: &str) -> bool {
    s.len() <= 200
        && s.strip_prefix("S-1-").is_some_and(|rest| {
            rest.split('-')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
}

impl SccmSites {
    /// Drops entries that aren't right (and any over the cap), upper-cases
    /// the site codes. Returns how many were dropped.
    pub fn check(&mut self) -> usize {
        let before = self.sites.len() + self.management_points.len();
        self.sites.truncate(MAX_ENTRIES);
        self.management_points.truncate(MAX_ENTRIES);
        self.sites.retain_mut(|s| {
            s.site_code = s.site_code.trim().to_ascii_uppercase();
            s.owner = s.owner.take().filter(|o| is_sid(o));
            is_site_code(&s.site_code)
        });
        self.management_points.retain_mut(|m| {
            m.site_code = m.site_code.trim().to_ascii_uppercase();
            m.host = m.host.trim().trim_end_matches('.').to_ascii_lowercase();
            is_site_code(&m.site_code) && is_host_name(&m.host)
        });
        before - self.sites.len() - self.management_points.len()
    }
}

/// The site code SCCM's client setup parameters name
/// (`SMSSITECODE=P01`), unless it is `AUTO` or missing.
pub fn site_code_in(setup_parameters: &str) -> Option<String> {
    setup_parameters
        .split_whitespace()
        .filter_map(|t| t.split_once('='))
        .find(|(k, _)| {
            k.trim_start_matches('/')
                .eq_ignore_ascii_case("SMSSITECODE")
        })
        .map(|(_, v)| v.trim_matches('"').to_ascii_uppercase())
        .filter(|v| is_site_code(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_codes_from_setup_parameters() {
        assert_eq!(
            site_code_in("SMSSITECODE=p01 SMSMP=mp01.example.test").as_deref(),
            Some("P01")
        );
        assert_eq!(
            site_code_in(r#"/mp:mp01 SMSSITECODE="ABC""#).as_deref(),
            Some("ABC")
        );
        assert_eq!(site_code_in("SMSSITECODE=AUTO"), None);
        assert_eq!(site_code_in("SMSMP=mp01"), None);
        assert_eq!(site_code_in("SMSSITECODE=TOOLONG"), None);
    }

    #[test]
    fn bad_entries_are_dropped() {
        let mut s = SccmSites {
            sites: vec![
                Site {
                    site_code: "p01".into(),
                    owner: Some("S-1-5-21-1-2-3-1105".into()),
                },
                Site {
                    site_code: "P0".into(),
                    owner: None,
                },
                Site {
                    site_code: "P02".into(),
                    owner: Some("not a sid".into()),
                },
            ],
            management_points: vec![
                ManagementPoint {
                    site_code: "P01".into(),
                    host: "MP01.Example.Test.".into(),
                    default: true,
                },
                ManagementPoint {
                    site_code: "P01".into(),
                    host: r"\\evil".into(),
                    default: false,
                },
            ],
        };
        assert_eq!(s.check(), 2);
        assert_eq!(s.sites[0].site_code, "P01");
        assert_eq!(s.sites[1].owner, None);
        assert_eq!(s.management_points[0].host, "mp01.example.test");
    }
}
