//! Directory entries RustHound-CE reads and drops, or misreads, that
//! Pathwarden keeps for itself, noted as each entry goes to
//! the parser:
//!
//! - SCCM's site objects (`mSSMSSite`, `mSSMSManagementPoint`) under
//!   `CN=System Management`: RustHound-CE has no type for them, so they
//!   never reach its output. They go to the SYSVOL sidecar
//!   (`pathwarden_core::sysvol::sccm`).
//! - OUs that block inheritance (`gPOptions` 1): RustHound-CE 2.5.30 matches
//!   the attribute misspelt (`gPOtions`), so every OU it writes says
//!   `blocksinheritance: false`. [`patch_ous`] corrects its `ous.json`
//!   (a fix to offer upstream).
//! - Disabled GPO links: RustHound-CE writes every `gPLink` entry as a link,
//!   disabled or not. The disabled ones (option bit 1) go to the sidecar,
//!   so Group Policy precedence leaves them out.
//! - Computers created through the machine account quota
//!   (`mS-DS-CreatorSID` set): their SIDs go to the sidecar, so a setting
//!   that names one (a WSUS server) is reviewed, not trusted.

use std::collections::HashSet;

use pathwarden_core::sysvol::sccm::{ManagementPoint, SccmSites, Site};
use pathwarden_core::sysvol::DisabledLink;
use rusthound_ce::transport::ldap::LdapSearchEntry;
use serde_json::Value;

/// What [`Extras::see`] kept.
#[derive(Debug, Default)]
pub(crate) struct Extras {
    pub sccm: SccmSites,
    /// Distinguished names (upper case) of the OUs that block inheritance.
    pub blocked_ous: HashSet<String>,
    /// Disabled GPO links of the OUs and domains.
    pub disabled_links: Vec<DisabledLink>,
    /// SIDs of computers created through the machine account quota.
    pub quota_computers: Vec<String>,
}

/// The `gPLink` entries whose option has the disabled bit (1), as GPO
/// GUIDs without braces, upper case. `[LDAP://cn={GUID},cn=policies,...;N]`.
pub(crate) fn disabled_in(gplink: &str) -> Vec<String> {
    let mut out = Vec::new();
    for entry in gplink.split('[').filter(|e| !e.trim().is_empty()) {
        let entry = entry.trim().trim_end_matches(']');
        let Some((path, option)) = entry.rsplit_once(';') else {
            continue;
        };
        let disabled = option.trim().parse::<u32>().is_ok_and(|o| o & 1 == 1);
        let lower = path.to_ascii_lowercase();
        let guid = lower
            .find("cn={")
            .and_then(|at| {
                let rest = &path[at + 4..];
                rest.find('}').map(|end| &rest[..end])
            })
            .filter(|g| g.len() == 36);
        if let (true, Some(g)) = (disabled, guid) {
            out.push(g.to_ascii_uppercase());
        }
    }
    out
}

/// Most SCCM entries and blocking OUs kept; real domains have a handful.
const MAX_KEPT: usize = 10_000;

fn values<'a>(e: &'a LdapSearchEntry, attr: &'a str) -> impl Iterator<Item = &'a String> {
    e.attrs
        .iter()
        .filter(move |(k, _)| k.eq_ignore_ascii_case(attr))
        .flat_map(|(_, v)| v.iter())
}

fn first<'a>(e: &'a LdapSearchEntry, attr: &'a str) -> Option<&'a str> {
    values(e, attr).map(|v| v.trim()).find(|v| !v.is_empty())
}

fn has_class(e: &LdapSearchEntry, class: &str) -> bool {
    values(e, "objectClass").any(|c| c.eq_ignore_ascii_case(class))
}

impl Extras {
    /// Notes `e` if it is one of the entries kept.
    pub(crate) fn see(&mut self, e: &LdapSearchEntry) {
        let ou = has_class(e, "organizationalUnit");
        if ou || has_class(e, "domainDNS") {
            if let Some(link) = first(e, "gPLink") {
                for gpo in disabled_in(link) {
                    if self.disabled_links.len() < MAX_KEPT {
                        self.disabled_links.push(DisabledLink {
                            container: e.dn.trim().to_ascii_uppercase(),
                            gpo,
                        });
                    }
                }
            }
        }
        if ou {
            if first(e, "gPOptions") == Some("1") && self.blocked_ous.len() < MAX_KEPT {
                self.blocked_ous.insert(e.dn.trim().to_ascii_uppercase());
            }
            return;
        }
        if has_class(e, "computer") {
            let bin = |attr: &str| {
                e.bin_attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(attr))
                    .and_then(|(_, v)| v.first())
            };
            let made = bin("mS-DS-CreatorSID").is_some() || first(e, "mS-DS-CreatorSID").is_some();
            if made && self.quota_computers.len() < MAX_KEPT {
                if let Some((sid, _)) =
                    bin("objectSid").and_then(|b| pathwarden_core::sysvol::sd::parse_sid(b, 0).ok())
                {
                    self.quota_computers.push(sid);
                }
            }
            return;
        }
        if has_class(e, "mSSMSSite") {
            if self.sccm.sites.len() >= MAX_KEPT {
                return;
            }
            let Some(code) = first(e, "mSSMSSiteCode") else {
                return;
            };
            let owner = e
                .bin_attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("nTSecurityDescriptor"))
                .and_then(|(_, v)| v.first())
                .and_then(|sd| pathwarden_core::sysvol::sd::parse(sd).ok())
                .and_then(|sd| sd.owner);
            self.sccm.sites.push(Site {
                site_code: code.to_string(),
                owner,
            });
        } else if has_class(e, "mSSMSManagementPoint") {
            if self.sccm.management_points.len() >= MAX_KEPT {
                return;
            }
            let (Some(code), Some(host)) = (
                first(e, "mSSMSSiteCode"),
                first(e, "dNSHostName").or_else(|| first(e, "mSSMSMPName")),
            ) else {
                return;
            };
            self.sccm.management_points.push(ManagementPoint {
                site_code: code.to_string(),
                host: host.to_string(),
                default: first(e, "mSSMSDefaultMP").is_some_and(|v| v.eq_ignore_ascii_case("TRUE")),
            });
        }
    }
}

/// Sets `blocksinheritance` on the OUs of an `ous.json` document whose
/// distinguished name is in `blocked`. Returns how many it set.
pub(crate) fn patch_ous(doc: &mut Value, blocked: &HashSet<String>) -> usize {
    let Some(data) = doc.get_mut("data").and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut n = 0;
    for o in data.iter_mut() {
        let Some(props) = o.get_mut("Properties").and_then(Value::as_object_mut) else {
            continue;
        };
        let dn = props
            .get("distinguishedname")
            .and_then(Value::as_str)
            .map(|d| d.trim().to_ascii_uppercase());
        if dn.is_some_and(|d| blocked.contains(&d)) {
            props.insert("blocksinheritance".into(), Value::Bool(true));
            n += 1;
        }
    }
    n
}

/// [`patch_ous`] on the collection zip's `ous.json`.
pub(crate) fn apply_to_zip(
    zip: &std::path::Path,
    blocked: &HashSet<String>,
) -> Result<usize, String> {
    if blocked.is_empty() {
        return Ok(0);
    }
    let mut n = 0;
    super::fixups::patch_zip(
        zip,
        |name| name.ends_with("_ous.json"),
        |_, doc| n += patch_ous(doc, blocked),
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> LdapSearchEntry {
        LdapSearchEntry {
            dn: dn.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
            bin_attrs: HashMap::new(),
        }
    }

    #[test]
    fn disabled_links_and_quota_computers() {
        const A: &str = "AAAA0000-0000-0000-0000-000000000001";
        const B: &str = "BBBB0000-0000-0000-0000-000000000002";
        const C: &str = "CCCC0000-0000-0000-0000-000000000003";
        // ;0 enabled, ;1 disabled, ;2 enforced, ;3 enforced and disabled.
        let gplink = format!(
            "[LDAP://cn={{{A}}},cn=policies,cn=system,DC=example,DC=test;1]\
             [LDAP://CN={{{B}}},CN=Policies,CN=System,DC=example,DC=test;2]\
             [LDAP://cn={{{C}}},cn=policies,cn=system,DC=example,DC=test;3]"
        );
        assert_eq!(disabled_in(&gplink), [A, C]);
        assert!(disabled_in("garbage;1]").is_empty());
        let mut x = Extras::default();
        x.see(&entry(
            "DC=example,DC=test",
            &[
                ("objectClass", &["top", "domainDNS"]),
                ("gPLink", &[&gplink]),
            ],
        ));
        assert_eq!(x.disabled_links.len(), 2);
        assert_eq!(x.disabled_links[0].container, "DC=EXAMPLE,DC=TEST");
        let sid = pathwarden_core::sysvol::sd::build::sid("S-1-5-21-1-2-3-1150");
        let mut made = entry(
            "CN=WSUS,CN=Computers,DC=example,DC=test",
            &[("objectClass", &["top", "computer"])],
        );
        made.bin_attrs.insert("objectSid".into(), vec![sid.clone()]);
        made.bin_attrs
            .insert("mS-DS-CreatorSID".into(), vec![sid.clone()]);
        x.see(&made);
        let mut plain = made.clone();
        plain.bin_attrs.remove("mS-DS-CreatorSID");
        x.see(&plain);
        assert_eq!(x.quota_computers, ["S-1-5-21-1-2-3-1150"]);
    }

    #[test]
    fn keeps_sccm_sites_and_blocking_ous() {
        let mut x = Extras::default();
        let mut site = entry(
            "CN=SMS-Site-P01,CN=System Management,CN=System,DC=example,DC=test",
            &[
                ("objectClass", &["top", "mSSMSSite"]),
                ("mSSMSSiteCode", &["P01"]),
            ],
        );
        site.bin_attrs.insert(
            "nTSecurityDescriptor".into(),
            vec![pathwarden_core::sysvol::sd::build::sd(
                Some("S-1-5-21-1-2-3-1105"),
                None,
            )],
        );
        x.see(&site);
        x.see(&entry(
            "CN=SMS-MP-P01-SCCM01.EXAMPLE.TEST,CN=System Management,CN=System,DC=example,DC=test",
            &[
                ("objectClass", &["top", "mSSMSManagementPoint"]),
                ("mSSMSSiteCode", &["P01"]),
                ("mSSMSMPName", &["SCCM01.example.test"]),
                ("dNSHostName", &["sccm01.example.test"]),
                ("mSSMSDefaultMP", &["TRUE"]),
            ],
        ));
        x.see(&entry(
            "OU=Tier0,DC=example,DC=test",
            &[
                ("objectClass", &["top", "organizationalUnit"]),
                ("gPOptions", &["1"]),
            ],
        ));
        x.see(&entry(
            "OU=Other,DC=example,DC=test",
            &[
                ("objectClass", &["top", "organizationalUnit"]),
                ("gPOptions", &["0"]),
            ],
        ));
        // A site with no code is not kept.
        x.see(&entry("CN=x", &[("objectClass", &["mSSMSSite"])]));
        assert_eq!(x.sccm.sites.len(), 1);
        assert_eq!(x.sccm.sites[0].site_code, "P01");
        assert_eq!(
            x.sccm.sites[0].owner.as_deref(),
            Some("S-1-5-21-1-2-3-1105")
        );
        assert_eq!(x.sccm.management_points[0].host, "sccm01.example.test");
        assert!(x.sccm.management_points[0].default);
        assert_eq!(
            x.blocked_ous.iter().collect::<Vec<_>>(),
            ["OU=TIER0,DC=EXAMPLE,DC=TEST"]
        );

        let mut doc = serde_json::json!({"data": [
            {"Properties": {"distinguishedname": "OU=TIER0,DC=EXAMPLE,DC=TEST", "blocksinheritance": false}},
            {"Properties": {"distinguishedname": "OU=OTHER,DC=EXAMPLE,DC=TEST", "blocksinheritance": false}}
        ]});
        assert_eq!(patch_ous(&mut doc, &x.blocked_ous), 1);
        assert_eq!(doc["data"][0]["Properties"]["blocksinheritance"], true);
        assert_eq!(doc["data"][1]["Properties"]["blocksinheritance"], false);
    }
}
