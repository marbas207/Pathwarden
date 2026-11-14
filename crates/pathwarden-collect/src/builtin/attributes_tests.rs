//! Guard (b) for the attribute list: the same fake
//! directory read with `*` and with [`attributes::PARSED`] writes the same
//! collection, though the directory holds much the list leaves out
//! (thumbnail photos, Exchange data, certificates, LAPS passwords). And
//! with the list, no LAPS password reaches the disk. Re-run on every
//! RustHound-CE bump, with guard (a) in `attributes.rs`.

use std::path::Path;

use rusthound_ce::transport::ldap::LdapSearchEntry;

use super::cache_tests::{
    disk, output_from, output_from_memory, read, scratch, sd_bytes, synthetic, FakePages,
};
use super::tests::{entry, sid_bytes};
use super::*;

const BASE: &str = "DC=contoso,DC=local";
const CONFIG: &str = "CN=Configuration,DC=contoso,DC=local";
const PKI: &str = "CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local";
const GPO: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";

/// A test CA certificate (self-signed, `CN=CONTOSO-CA`).
const CA_CERT: &[u8] = include_bytes!("../../../../testdata/certs/contoso-ca.der");

/// A Windows time span (100 ns units, negative) of `days`, as AD stores
/// `pKIExpirationPeriod`.
fn span(days: i64) -> Vec<u8> {
    (-days * 864_000_000_000).to_ne_bytes().to_vec()
}

/// `ms-Mcs-AdmPwd`'s `schemaIDGUID` in the fake schema.
const LAPS_GUID: [u8; 16] = [
    0x42, 0x10, 0x5e, 0x81, 0x6e, 0xa6, 0x4b, 0x4b, 0x9a, 0x6f, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61,
];

/// A self-relative security descriptor: `owner`, and a DACL with one
/// object ACE allowing `who` `mask` on the property or right `object`.
fn sd_object(owner: &[u32], who: &[u32], mask: u32, object: [u8; 16]) -> Vec<u8> {
    let owner = sid_bytes(owner);
    let who = sid_bytes(who);
    let mut ace = vec![0x05, 0]; // ACCESS_ALLOWED_OBJECT, no flags
    ace.extend_from_slice(&((4 + 4 + 4 + 16 + who.len()) as u16).to_le_bytes());
    ace.extend_from_slice(&mask.to_le_bytes());
    ace.extend_from_slice(&1u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
    ace.extend_from_slice(&object);
    ace.extend_from_slice(&who);
    let owner_at = 20u32;
    let dacl_at = owner_at + owner.len() as u32;
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // self-relative, DACL present
    sd.extend_from_slice(&owner_at.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_at.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&[4, 0]); // ACL revision 4 (object ACEs)
    sd.extend_from_slice(&((8 + ace.len()) as u16).to_le_bytes());
    sd.extend_from_slice(&1u16.to_le_bytes());
    sd.extend_from_slice(&[0, 0]);
    sd.extend_from_slice(&ace);
    sd
}

/// One object of each type the parser routes that [`synthetic`] lacks,
/// each with the attributes its parser reads: a GPO, a trust, a gMSA, a
/// foreign principal, a container, a deleted user, a group whose members
/// came by ranged retrieval, and AD CS (a template, an Enterprise CA, a
/// root CA, an AIA CA, the NTAuth store, an issuance policy).
fn routed(ncs: &mut [(String, Vec<LdapSearchEntry>)]) {
    let sd = |e: LdapSearchEntry| {
        let mut e = e;
        bin(
            &mut e,
            "nTSecurityDescriptor",
            sd_bytes(
                &[1, 2, 3, 512],
                &[(&[1, 2, 3, 512], 0x000F_01FF), (&[1, 2, 3, 2000], 0x20)],
            ),
        );
        e
    };
    let mut guid = 0x9000u128;
    let mut next_guid = |e: &mut LdapSearchEntry| {
        guid += 1;
        bin(e, "objectGUID", guid.to_le_bytes().to_vec());
    };
    let da = format!("CN=Domain Admins,CN=Users,{BASE}");

    let mut domain = Vec::new();
    let sysvol = format!("\\\\contoso.local\\SysVol\\contoso.local\\Policies\\{GPO}");
    let mut gpo = sd(entry(
        &format!("CN={GPO},CN=Policies,CN=System,{BASE}"),
        &["top", "container", "groupPolicyContainer"],
        &[
            ("name", GPO),
            ("displayName", "Default Domain Policy"),
            ("gPCFileSysPath", sysvol.as_str()),
            ("flags", "0"),
        ],
        &[],
        &[1, 2, 3, 8000],
    ));
    next_guid(&mut gpo);
    domain.push(gpo);
    let mut trust = entry(
        &format!("CN=essos.local,CN=System,{BASE}"),
        &["top", "leaf", "trustedDomain"],
        &[
            ("name", "essos.local"),
            ("trustDirection", "3"),
            ("trustAttributes", "8"),
        ],
        &[],
        &[1, 2, 3, 8001],
    );
    bin(&mut trust, "securityIdentifier", sid_bytes(&[9, 9, 9]));
    next_guid(&mut trust);
    domain.push(trust);
    let mut gmsa = sd(entry(
        &format!("CN=gmsa01,CN=Managed Service Accounts,{BASE}"),
        &[
            "top",
            "person",
            "organizationalPerson",
            "user",
            "computer",
            "msDS-GroupManagedServiceAccount",
        ],
        &[
            ("name", "gmsa01"),
            ("sAMAccountName", "gmsa01$"),
            ("dNSHostName", "gmsa01.contoso.local"),
            ("userAccountControl", "4096"),
            ("primaryGroupID", "515"),
        ],
        &[],
        &[1, 2, 3, 1200],
    ));
    // WS01's account may read its password.
    bin(
        &mut gmsa,
        "msDS-GroupMSAMembership",
        sd_bytes(&[32, 544], &[(&[1, 2, 3, 1105], 0x000F_01FF)]),
    );
    next_guid(&mut gmsa);
    domain.push(gmsa);
    let foreign = "S-1-5-21-9-9-9-1105";
    let mut fsp = entry(
        &format!("CN={foreign},CN=ForeignSecurityPrincipals,{BASE}"),
        &["top", "foreignSecurityPrincipal"],
        &[("name", foreign)],
        &[],
        &[9, 9, 9, 1105],
    );
    next_guid(&mut fsp);
    domain.push(fsp);
    let mut users = sd(entry(
        &format!("CN=Users,{BASE}"),
        &["top", "container"],
        &[
            ("name", "Users"),
            (
                "description",
                "Default container for upgraded user accounts",
            ),
            ("isCriticalSystemObject", "TRUE"),
        ],
        &[],
        &[1, 2, 3, 8002],
    ));
    next_guid(&mut users);
    domain.push(users);
    let mut gone = entry(
        &format!("CN=old\\0ADEL:1234,CN=Deleted Objects,{BASE}"),
        &["top", "person", "organizationalPerson", "user"],
        &[
            ("name", "old"),
            ("sAMAccountName", "old"),
            ("isDeleted", "TRUE"),
        ],
        &[],
        &[1, 2, 3, 8003],
    );
    next_guid(&mut gone);
    domain.push(gone);
    // AD sends a long member list as `member;range=0-1499` and so on; the
    // read puts the ranges together under `member` ([`complete_ranged`]).
    let members: Vec<String> = (0..3)
        .map(|i| format!("CN=User{i},CN=Users,{BASE}"))
        .chain([
            da.clone(),
            format!("CN={foreign},CN=ForeignSecurityPrincipals,{BASE}"),
        ])
        .collect();
    let members: Vec<&str> = members.iter().map(String::as_str).collect();
    let mut big = sd(entry(
        &format!("CN=Big Group,CN=Users,{BASE}"),
        &["top", "group"],
        &[
            ("name", "Big Group"),
            ("sAMAccountName", "Big Group"),
            ("groupType", "-2147483646"),
        ],
        &[("member;range=0-*", members)],
        &[1, 2, 3, 1300],
    ));
    next_guid(&mut big);
    domain.push(big);

    // The schema's ms-Mcs-AdmPwd, for WS01's object ACE.
    let mut laps = entry(
        &format!("CN=ms-Mcs-AdmPwd,CN=Schema,{CONFIG}"),
        &["top", "attributeSchema"],
        &[
            ("name", "ms-Mcs-AdmPwd"),
            ("lDAPDisplayName", "ms-Mcs-AdmPwd"),
        ],
        &[],
        &[1, 2, 3, 8200],
    );
    bin(&mut laps, "schemaIDGUID", LAPS_GUID.to_vec());
    next_guid(&mut laps);
    ncs[0].1.push(laps);

    let mut config = Vec::new();
    let mut template = sd(entry(
        &format!("CN=User,CN=Certificate Templates,{PKI}"),
        &["top", "pKICertificateTemplate"],
        &[
            ("name", "User"),
            ("displayName", "User"),
            ("description", "a template"),
            ("msPKI-Certificate-Name-Flag", "-1509949440"),
            ("msPKI-Enrollment-Flag", "41"),
            ("msPKI-Private-Key-Flag", "16"),
            ("msPKI-RA-Signature", "1"),
            ("msPKI-Template-Schema-Version", "2"),
            ("msPKI-Cert-Template-OID", "1.3.6.1.4.1.311.21.8.1.1"),
        ],
        &[
            (
                "msPKI-Certificate-Application-Policy",
                vec!["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.4"],
            ),
            (
                "msPKI-RA-Application-Policies",
                vec!["1.3.6.1.4.1.311.20.2.1"],
            ),
            ("msPKI-RA-Policies", vec!["1.3.6.1.4.1.311.21.8.1.2"]),
            ("msPKI-Certificate-Policy", vec!["1.3.6.1.4.1.311.21.8.1.2"]),
            ("pKIExtendedKeyUsage", vec!["1.3.6.1.5.5.7.3.2"]),
        ],
        &[1, 2, 3, 8100],
    ));
    bin(&mut template, "pKIExpirationPeriod", span(365));
    bin(&mut template, "pKIOverlapPeriod", span(42));
    next_guid(&mut template);
    config.push(template);
    let mut enterprise = sd(entry(
        &format!("CN=CONTOSO-CA,CN=Enrollment Services,{PKI}"),
        &["top", "pKIEnrollmentService"],
        &[
            ("name", "CONTOSO-CA"),
            ("dNSHostName", "ca01.contoso.local"),
            ("description", "the CA"),
        ],
        &[("certificateTemplates", vec!["User"])],
        &[1, 2, 3, 8101],
    ));
    bin(&mut enterprise, "cACertificate", CA_CERT.to_vec());
    next_guid(&mut enterprise);
    config.push(enterprise);
    for (dn, sid) in [
        (
            format!("CN=CONTOSO-CA,CN=Certification Authorities,{PKI}"),
            8102,
        ),
        (format!("CN=CONTOSO-CA,CN=AIA,{PKI}"), 8103),
        (format!("CN=NTAuthCertificates,{PKI}"), 8104),
    ] {
        let cn = dn[3..].split(',').next().unwrap().to_string();
        let mut e = sd(entry(
            &dn,
            &["top", "certificationAuthority"],
            &[("name", cn.as_str()), ("description", "a store")],
            &[],
            &[1, 2, 3, sid],
        ));
        bin(&mut e, "cACertificate", CA_CERT.to_vec());
        if dn.contains("CN=AIA") {
            text(&mut e, "crossCertificatePair", &["a pair"]);
        }
        next_guid(&mut e);
        config.push(e);
    }
    let mut policy = sd(entry(
        &format!("CN=400.1A2B3C,CN=OID,{PKI}"),
        &["top", "msPKI-Enterprise-Oid"],
        &[
            ("name", "400.1A2B3C"),
            ("displayName", "High assurance"),
            ("flags", "2"),
            ("msPKI-Cert-Template-OID", "1.3.6.1.4.1.311.21.8.1.2"),
            ("msDS-OIDToGroupLink", da.as_str()),
        ],
        &[],
        &[1, 2, 3, 8105],
    ));
    next_guid(&mut policy);
    config.push(policy);

    for (nc, entries) in ncs.iter_mut() {
        if *nc == BASE {
            entries.append(&mut domain);
        } else if *nc == CONFIG {
            entries.append(&mut config);
        }
    }
}

/// The ranges of an attribute AD sent under `member;range=...`, under
/// `member`, as the read's ranged retrieval leaves them.
fn complete_ranged(
    mut ncs: Vec<(String, Vec<LdapSearchEntry>)>,
) -> Vec<(String, Vec<LdapSearchEntry>)> {
    for (_, entries) in ncs.iter_mut() {
        for e in entries.iter_mut() {
            let ranged: Vec<String> = e
                .attrs
                .keys()
                .filter(|k| k.contains(";range="))
                .cloned()
                .collect();
            for k in ranged {
                let values = e.attrs.remove(&k).unwrap_or_default();
                let base = k.split(';').next().unwrap_or_default().to_string();
                e.attrs.entry(base).or_default().extend(values);
            }
        }
    }
    ncs
}

/// LAPS passwords in the fake directory: none may reach the disk.
const SECRETS: [&str; 3] = [
    "LapsSecret-legacy",
    "LapsSecret-windows",
    "LapsSecret-encrypted",
];

fn text(e: &mut LdapSearchEntry, k: &str, v: &[&str]) {
    e.attrs
        .insert(k.into(), v.iter().map(|s| s.to_string()).collect());
}

fn bin(e: &mut LdapSearchEntry, k: &str, v: Vec<u8>) {
    e.bin_attrs.insert(k.into(), vec![v]);
}

/// [`synthetic`] with what a real directory also holds: attributes the
/// parser reads, and many it doesn't.
fn rich(users: usize) -> Vec<(String, Vec<LdapSearchEntry>)> {
    let mut ncs = synthetic(users);
    // Two more computers, with Windows LAPS.
    let mut ws02 = entry(
        &format!("CN=WS02,CN=Computers,{BASE}"),
        &["top", "person", "organizationalPerson", "user", "computer"],
        &[
            ("name", "WS02"),
            ("sAMAccountName", "WS02$"),
            ("dNSHostName", "ws02.contoso.local"),
            ("userAccountControl", "4096"),
            ("primaryGroupID", "515"),
            (
                "msLAPS-Password",
                r#"{"n":"Administrator","t":"1db2c3d4e5f6a7b8","p":"LapsSecret-windows"}"#,
            ),
            ("msLAPS-PasswordExpirationTime", "134100000000000000"),
        ],
        &[],
        &[1, 2, 3, 1106],
    );
    let mut enc = vec![0u8; 16];
    enc.extend_from_slice(b"\xffLapsSecret-encrypted");
    bin(&mut ws02, "msLAPS-EncryptedPassword", enc);
    bin(&mut ws02, "objectGUID", 0x7106u128.to_le_bytes().to_vec());
    // Resource-based constrained delegation: User1 may act on WS02.
    bin(
        &mut ws02,
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        sd_bytes(&[32, 544], &[(&[1, 2, 3, 2001], 0x000F_01FF)]),
    );
    ncs[1].1.push(ws02);
    routed(&mut ncs);

    for (nc, entries) in ncs.iter_mut() {
        for e in entries.iter_mut() {
            let name = e.attrs["distinguishedName"][0].clone();
            let cn = name
                .split(',')
                .next()
                .unwrap_or_default()
                .trim_start_matches("CN=")
                .to_string();
            // What every object has and the parser ignores.
            text(e, "cn", &[&cn]);
            text(e, "whenChanged", &["20261030120000.0Z"]);
            text(e, "uSNCreated", &["12"]);
            text(e, "showInAdvancedViewOnly", &["FALSE"]);
            text(
                e,
                "objectCategory",
                &[&format!("CN=Person,CN=Schema,CN=Configuration,{BASE}")],
            );
            text(e, "dSCorePropagationData", &["16010101000000.0Z"]);
            text(e, "whenCreated", &["20240102030405.0Z"]);
            let classes = e.attrs["objectClass"].clone();
            let is = |c: &str| classes.iter().any(|x| x == c);
            if is("classSchema") {
                text(e, "adminDescription", &["a schema class"]);
                text(e, "governsID", &["1.2.840.113556.1.5.9"]);
            }
            if nc == BASE && e.dn == BASE {
                text(e, "gPLink", &[&format!(
                    "[LDAP://cn={{31B2F340-016D-11D2-945F-00C04FB984F9}},cn=policies,cn=system,{BASE};0]"
                )]);
                text(e, "ms-DS-MachineAccountQuota", &["10"]);
                text(e, "msDS-Behavior-Version", &["7"]);
                text(e, "minPwdLength", &["7"]);
                text(e, "maxPwdAge", &["-36288000000000"]);
                text(e, "lockoutThreshold", &["5"]);
                text(
                    e,
                    "wellKnownObjects",
                    &["B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers"],
                );
                bin(e, "auditingPolicy", vec![0, 1, 2, 3]);
                text(e, "lockoutDuration", &["-18000000000"]);
                text(e, "lockOutObservationWindow", &["-18000000000"]);
                text(e, "minPwdAge", &["-864000000000"]);
                text(e, "pwdHistoryLength", &["24"]);
                text(e, "pwdProperties", &["1"]);
                text(e, "dSHeuristics", &["00000002"]);
                text(e, "isCriticalSystemObject", &["TRUE"]);
                text(e, "msDS-ExpirePasswordsOnSmartCardOnlyAccounts", &["TRUE"]);
            }
            if is("organizationalUnit") {
                text(e, "gPOptions", &["1"]);
                // SCCM's site attributes: only Pathwarden reads them, from
                // site objects RustHound-CE drops (`dirextras.rs`). Held
                // here so the fixture has every attribute of the list.
                text(e, "mSSMSSiteCode", &["P01"]);
                text(e, "mSSMSMPName", &["mp01.contoso.local"]);
                text(e, "mSSMSDefaultMP", &["TRUE"]);
                bin(
                    e,
                    "mS-DS-CreatorSID",
                    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                );
                text(e, "description", &["Servers"]);
                text(
                    e,
                    "gPLink",
                    &[&format!("[LDAP://cn={GPO},cn=policies,cn=system,{BASE};2]")],
                );
            }
            if is("user") && !is("computer") {
                let n = cn.trim_start_matches("User");
                text(e, "description", &[&format!("user {n}")]);
                text(e, "mail", &[&format!("user{n}@contoso.local")]);
                text(e, "title", &["Engineer"]);
                text(e, "pwdLastSet", &["133500000000000000"]);
                text(e, "lastLogonTimestamp", &["133600000000000000"]);
                text(e, "displayName", &[&format!("User {n}")]);
                if n == "0" {
                    text(e, "servicePrincipalName", &["HTTP/web.contoso.local"]);
                    text(e, "adminCount", &["1"]);
                    text(e, "msDS-SupportedEncryptionTypes", &["24"]);
                    // Constrained delegation, a logon script, a home folder.
                    text(
                        e,
                        "msDS-AllowedToDelegateTo",
                        &["cifs/ws01.contoso.local", "cifs/WS01"],
                    );
                    text(e, "scriptPath", &["logon.bat"]);
                    text(e, "homeDirectory", &["\\\\fs01\\home\\user0"]);
                    text(e, "profilePath", &["\\\\fs01\\profiles\\user0"]);
                    text(e, "lastLogon", &["133600000000000000"]);
                    text(e, "msDS-User-Account-Control-Computed", &["8388608"]);
                }
                if n == "1" {
                    // Migrated from another domain; old Unix and plain
                    // passwords (what RustHound-CE reports as such).
                    bin(e, "sIDHistory", sid_bytes(&[7, 7, 7, 1500]));
                    text(e, "userPassword", &["Summer2024"]);
                    text(e, "unixUserPassword", &["crypt-x"]);
                    text(e, "unicodePwd", &["never-readable"]);
                }
                // Exchange, a photo, a certificate: none of it is parsed.
                text(
                    e,
                    "proxyAddresses",
                    &[&format!("SMTP:user{n}@contoso.local")],
                );
                text(
                    e,
                    "legacyExchangeDN",
                    &["/o=Contoso/ou=Exchange/cn=Recipients"],
                );
                text(e, "msExchHomeServerName", &["/o=Contoso/cn=EX01"]);
                bin(e, "msExchMailboxGuid", vec![0xa5; 16]);
                bin(e, "thumbnailPhoto", vec![0xd8; 4096]);
                bin(e, "userCertificate", vec![0x30, 0x82, 0x01, 0x00, 0xff]);
            }
            if is("computer") {
                text(e, "operatingSystem", &["Windows Server 2022 Datacenter"]);
                text(e, "msDS-SupportedEncryptionTypes", &["28"]);
                text(e, "servicePrincipalName", &[&format!("HOST/{cn}")]);
                text(e, "lastLogonTimestamp", &["133600000000000000"]);
                if cn == "WS01" {
                    // User0 may read its LAPS password: an object ACE for
                    // the schema's ms-Mcs-AdmPwd (ReadLAPSPassword).
                    bin(
                        e,
                        "nTSecurityDescriptor",
                        sd_object(&[1, 2, 3, 512], &[1, 2, 3, 2000], 0x110, LAPS_GUID),
                    );
                    text(e, "msDS-AllowedToDelegateTo", &["HOST/ws02.contoso.local"]);
                    text(e, "ms-Mcs-AdmPwd", &["LapsSecret-legacy"]);
                    text(e, "ms-Mcs-AdmPwdExpirationTime", &["134100000000000000"]);
                }
            }
        }
    }
    ncs
}

/// What a domain controller returns of `ncs` asked for `asked`: with `*`
/// everything (the fake's operational attributes are asked for by name in
/// both lists), else only what is named, in any case.
fn as_asked(
    ncs: &[(String, Vec<LdapSearchEntry>)],
    asked: &[&str],
) -> Vec<(String, Vec<LdapSearchEntry>)> {
    if asked.contains(&"*") {
        return ncs.to_vec();
    }
    let named = |k: &String| {
        let base = k.split(';').next().unwrap_or(k);
        asked.iter().any(|a| a.eq_ignore_ascii_case(base))
    };
    ncs.iter()
        .map(|(nc, entries)| {
            let entries = entries
                .iter()
                .map(|e| {
                    let mut e = e.clone();
                    e.attrs.retain(|k, _| named(k));
                    e.bin_attrs.retain(|k, _| named(k));
                    e
                })
                .collect();
            (nc.clone(), entries)
        })
        .collect()
}

/// Every file under `dir` that holds `needle`.
fn holding(dir: &Path, needle: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(holding(&p, needle));
        } else if let Ok(bytes) = std::fs::read(&p) {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                out.push(p.display().to_string());
            }
        }
    }
    out
}

/// A read of `ncs` asked for `asked`, onto disk under `root`, and the
/// collection RustHound-CE writes from it into `root/out`.
fn collect(
    root: &Path,
    ncs: &[(String, Vec<LdapSearchEntry>)],
    asked: &[&str],
) -> (cache::Folder, cache::Written) {
    let (folder, sink) = disk(&root.join("cache"));
    let returned = complete_ranged(as_asked(ncs, asked));
    let Ok(ReadOut::Disk(written)) = read(&mut FakePages::of(returned, 7), sink) else {
        panic!("on disk")
    };
    output_from(folder.path(), &root.join("out"));
    (folder, written)
}

/// The collection RustHound-CE writes from `ncs` asked for `asked`, read
/// into memory (quicker, for many reads).
fn in_memory(
    out: &Path,
    ncs: &[(String, Vec<LdapSearchEntry>)],
    asked: &[&str],
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let entries = complete_ranged(as_asked(ncs, asked))
        .into_iter()
        .flat_map(|(_, v)| v)
        .collect();
    output_from_memory(entries, out)
}

/// Attributes of the list whose loss the fixture can't show, and why.
/// Guard (a) still holds them to the parser's source.
const INERT: &[(&str, &str)] = &[
    (
        "uSNChanged",
        "Pathwarden's: the read's ranges, not the parser",
    ),
    (
        "gPOptions",
        "RustHound-CE matches it misspelt (gPOtions), so it is unused",
    ),
    (
        "msPKI-Private-Key-Flag",
        "its arm in certtemplate.rs is commented out",
    ),
    (
        "mSSMSSiteCode",
        "Pathwarden's: SCCM site objects for its sidecar, not the parser",
    ),
    (
        "mSSMSMPName",
        "Pathwarden's: SCCM site objects for its sidecar, not the parser",
    ),
    (
        "mSSMSDefaultMP",
        "Pathwarden's: SCCM site objects for its sidecar, not the parser",
    ),
    (
        "mS-DS-CreatorSID",
        "Pathwarden's: computers made through the machine account quota, for its sidecar",
    ),
];

/// The fixture holds every attribute of the list, so dropping one can
/// show in [`each_attribute_of_the_list_is_needed`].
#[test]
fn the_fixture_holds_every_attribute_of_the_list() {
    let ncs = rich(3);
    let mut held = std::collections::BTreeSet::new();
    for (_, entries) in &ncs {
        for e in entries {
            for k in e.attrs.keys().chain(e.bin_attrs.keys()) {
                held.insert(k.split(';').next().unwrap_or(k).to_string());
            }
        }
    }
    let missing: Vec<&str> = attributes::PARSED
        .iter()
        .copied()
        .filter(|a| !held.contains(*a))
        .collect();
    assert!(missing.is_empty(), "not in the fixture: {missing:?}");
}

/// Guard (b) proves only what its fixture exercises: each attribute of
/// the list changes the output when it alone is left out, but the few on
/// [`INERT`]. A list missing one fails [`the_list_writes_what_every_attribute_writes`].
#[test]
fn each_attribute_of_the_list_is_needed() {
    let root = scratch("attrs-needed");
    let ncs = rich(3);
    let base = in_memory(&root.join("base"), &ncs, attributes::PARSED);
    let mut unseen = Vec::new();
    for (i, a) in attributes::PARSED.iter().enumerate() {
        let without: Vec<&str> = attributes::PARSED
            .iter()
            .copied()
            .filter(|x| x != a)
            .collect();
        let out = in_memory(&root.join(format!("w{i}")), &ncs, &without);
        let inert = INERT.iter().any(|(n, _)| n == a);
        let same = crate::compare::compare_normalized(&base, &out).same();
        if same != inert {
            unseen.push(format!(
                "{a}: {}",
                if same {
                    "no change"
                } else {
                    "changes the output"
                }
            ));
        }
    }
    assert!(
        unseen.is_empty(),
        "left out alone, these don't do what INERT says: {unseen:#?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_list_writes_what_every_attribute_writes() {
    let root = scratch("attrs-same");
    let ncs = rich(30);
    let (all_folder, all) = collect(&root.join("all"), &ncs, attributes::ALL);
    let (list_folder, list) = collect(&root.join("list"), &ncs, attributes::PARSED);

    // The same collection, file by file, object by object.
    let diff = crate::compare::compare(&root.join("all/out"), &root.join("list/out")).unwrap();
    assert!(diff.same(), "{:#?}", diff.differences);
    assert!(diff.objects > 30 && diff.files >= 5, "{diff:?}");
    assert_eq!(all.entries, list.entries);

    // The test means something: the data has what the list leaves out,
    // and the parser read what it keeps (LAPS from the expiration times).
    let out = crate::compare::normalized(&root.join("list/out")).unwrap();
    let computers = out["computers.json"]["data"].as_array().unwrap();
    let laps = computers
        .iter()
        .filter(|c| c["Properties"]["haslaps"] == true)
        .count();
    assert_eq!(laps, 2, "{computers:#?}");
    // The schema, the security descriptor and haslaps together: User0 can
    // read WS01's LAPS password.
    assert!(
        computers.iter().any(|c| c["Aces"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["RightName"] == "ReadLAPSPassword"))),
        "{computers:#?}"
    );
    let users = out["users.json"]["data"].as_array().unwrap();
    assert!(users
        .iter()
        .any(|u| u["Properties"]["description"] == "user 0" && u["Properties"]["hasspn"] == true));
    assert!(
        list.bytes * 2 < all.bytes,
        "the list read {} bytes, every attribute {}",
        list.bytes,
        all.bytes
    );

    // LAPS passwords: on disk with every attribute, never with the list.
    assert!(
        !holding(all_folder.path(), SECRETS[0].as_bytes()).is_empty(),
        "the fake directory's LAPS password reaches the read with *"
    );
    // Nor in either collection's output (its JSON, the zip unpacked).
    let all_out = crate::compare::normalized(&root.join("all/out")).unwrap();
    let json = serde_json::to_string(&all_out).unwrap() + &serde_json::to_string(&out).unwrap();
    for s in SECRETS {
        let found = holding(&root.join("list"), s.as_bytes());
        assert!(found.is_empty(), "{s} in {found:?}");
        assert!(!json.contains(s), "{s} in the output");
    }
    drop((all_folder, list_folder));
    let _ = std::fs::remove_dir_all(&root);
}

/// A collection asks for the list unless every attribute is asked for.
#[test]
fn a_request_asks_for_the_list_by_default() {
    let mut req = crate::CollectRequest::new("contoso.local", "out");
    let job = job_for(&req, CollectionMethod::DCOnly).unwrap();
    assert_eq!(job.attributes, attributes::PARSED);
    req.all_attributes = true;
    let job = job_for(&req, CollectionMethod::DCOnly).unwrap();
    assert_eq!(job.attributes, attributes::ALL);
    // Every domain of a run asks the same.
    let other = req.for_domain("fabrikam.local", "out2".into(), None);
    assert!(other.all_attributes);
}

/// A read stopped by an earlier Pathwarden (or with `--all-attributes`)
/// asked for `*`: its key differs from the list's, so it starts over.
#[test]
fn reads_asked_differently_have_different_keys() {
    let before_1b = [
        "*",
        "nTSecurityDescriptor",
        "msDS-User-Account-Control-Computed",
    ];
    assert_eq!(
        cache::attributes_hash(&before_1b),
        cache::attributes_hash(attributes::ALL)
    );
    assert_ne!(
        cache::attributes_hash(attributes::ALL),
        cache::attributes_hash(attributes::PARSED)
    );
}
