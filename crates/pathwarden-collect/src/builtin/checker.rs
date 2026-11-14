//! RustHound-CE's post-parse checker (`json::checker::check_all_result`,
//! MIT, see THIRD-PARTY-NOTICES.md), the "resolving" step of a built-in
//! collection.
//!
//! Up to RustHound-CE 2.5.27, two of its passes grew with the square of the
//! directory (`add_childobjects_members` and `replace_guid_gplink`: about
//! 67 s of 81 s at 368k objects), so Pathwarden ran the checker step by step
//! with indexed versions of those two. RustHound-CE 2.5.28
//! (g0h4n/RustHound-CE#101) makes both linear with an Aho-Corasick
//! automaton and the same output, element for element and in the same order,
//! and its step list is the one Pathwarden ran (ESC13 group links included),
//! so the library's checker is called as it is. 2.5.29 builds
//! the ChildObjects automaton over reversed DNs, which share suffixes, so it
//! is smaller, again with the same output. 2.5.30 types
//! foreign and unresolved principals `Base` instead of `Group`. The tests
//! keep 2.5.27's two passes as the reference and check that the output has
//! not changed.

use std::error::Error;

use rusthound_ce::api::ADResults;
use rusthound_ce::args::Options;

/// RustHound-CE's `check_all_result` on a parse.
pub(crate) fn check_all(options: &Options, r: &mut ADResults) -> Result<(), Box<dyn Error>> {
    rusthound_ce::json::checker::check_all_result(
        options,
        &mut r.users,
        &mut r.groups,
        &mut r.computers,
        &mut r.ous,
        &mut r.domains,
        &mut r.gpos,
        &mut r.fsps,
        &mut r.containers,
        &mut r.trusts,
        &mut r.ntauthstores,
        &mut r.aiacas,
        &mut r.rootcas,
        &mut r.enterprisecas,
        &mut r.certtemplates,
        &mut r.issuancepolicies,
        &r.mappings.dn_sid,
        &r.mappings.sid_type,
        &r.mappings.fqdn_sid,
        &r.mappings.fqdn_ip,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    use rusthound_ce::enums::{templates_enabled_change_displayname_to_sid, Type};
    use rusthound_ce::json::checker::common;
    use rusthound_ce::objects::common::{LdapObject, Link, Member};
    use rusthound_ce::objects::ou::Ou;
    use rusthound_ce::transport::ldap::LdapSearchEntry;

    /// SID -> DN as RustHound-CE's private `build_sid_to_dn`: the smallest
    /// DN when several share a SID.
    fn sid_to_dn(dn_sid: &HashMap<String, String>) -> HashMap<&str, &str> {
        let mut map: HashMap<&str, &str> = HashMap::with_capacity(dn_sid.len());
        for (dn, sid) in dn_sid {
            map.entry(sid.as_str())
                .and_modify(|e| {
                    if dn.as_str() < *e {
                        *e = dn.as_str();
                    }
                })
                .or_insert(dn.as_str());
        }
        map
    }

    /// `add_childobjects_members` as of RustHound-CE 2.5.27 (MIT): a
    /// substring test of every `dn_sid` entry against every object. The
    /// behaviour Pathwarden's indexed copy reproduced up to 2.5.27.
    fn previous_childobjects<T: LdapObject>(
        objects: &mut [T],
        dn_sid: &HashMap<String, String>,
        sid_type: &HashMap<String, String>,
    ) {
        let sid_to_dn = sid_to_dn(dn_sid);
        let dn_upper: Vec<(String, &String)> = dn_sid
            .iter()
            .map(|(dn, sid)| (dn.to_uppercase(), sid))
            .collect();
        for object in objects.iter_mut() {
            let sid = object.get_object_identifier().to_uppercase();
            let dn: &str = sid_to_dn.get(sid.as_str()).copied().unwrap_or(sid.as_str());
            let name = common::get_name_from_full_distinguishedname(dn);
            let members: Vec<Member> = dn_upper
                .iter()
                .filter_map(|(child, value_sid)| {
                    if child.contains(dn)
                        && child.as_str() != dn
                        && child.split(',').nth(1).and_then(|s| s.split('=').nth(1))
                            == Some(name.as_str())
                        && !value_sid.is_empty()
                    {
                        let mut m = Member::new();
                        *m.object_identifier_mut() = (*value_sid).clone();
                        *m.object_type_mut() =
                            sid_type.get(*value_sid).unwrap_or(value_sid).to_string();
                        return Some(m);
                    }
                    None
                })
                .collect();
            object.set_child_objects(members);
        }
    }

    /// `replace_guid_gplink` as of RustHound-CE 2.5.27 (MIT): a scan of
    /// `dn_sid` per link, first key in iteration order.
    fn previous_gplink<T: LdapObject>(objects: &mut [T], dn_sid: &HashMap<String, String>) {
        for object in objects.iter_mut() {
            if object.get_links().is_empty() {
                continue;
            }
            let links: Vec<Link> = object
                .get_links()
                .iter()
                .map(|link| {
                    let mut new_link = link.clone();
                    if let Some(v) = dn_sid
                        .iter()
                        .find(|(key, _)| key.contains(link.guid()))
                        .map(|(_, v)| v)
                    {
                        *new_link.guid_mut() = v.to_owned();
                    }
                    new_link
                })
                .collect();
            object.set_links(links);
        }
    }

    /// The checker as Pathwarden ran it up to RustHound-CE 2.5.27: the
    /// library's steps in its order, with the 2.5.27 behaviour of the two
    /// passes 2.5.28 rewrote.
    fn previous_check_all(options: &Options, r: &mut ADResults) -> Result<(), Box<dyn Error>> {
        let domain = &options.domain;
        let dn_sid = &r.mappings.dn_sid;
        let sid_type = &r.mappings.sid_type;
        let fqdn_sid = &r.mappings.fqdn_sid;

        common::replace_fqdn_by_sid(Type::User, &mut r.users, fqdn_sid)?;
        common::replace_fqdn_by_sid(Type::Computer, &mut r.computers, fqdn_sid)?;
        templates_enabled_change_displayname_to_sid(&mut r.certtemplates, &mut r.enterprisecas)?;
        common::replace_sid_members(&mut r.groups, dn_sid, sid_type, &r.trusts)?;

        common::add_default_groups(&mut r.groups, &r.computers, domain.to_owned())?;
        common::add_default_users(&mut r.users, domain.to_owned())?;

        common::add_type_for_ace(&mut r.users, sid_type)?;
        common::add_type_for_ace(&mut r.groups, sid_type)?;
        common::add_type_for_ace(&mut r.computers, sid_type)?;
        common::add_type_for_ace(&mut r.gpos, sid_type)?;
        common::add_type_for_ace(&mut r.ous, sid_type)?;
        common::add_type_for_ace(&mut r.domains, sid_type)?;
        common::add_type_for_ace(&mut r.containers, sid_type)?;
        common::add_type_for_ace(&mut r.ntauthstores, sid_type)?;
        common::add_type_for_ace(&mut r.aiacas, sid_type)?;
        common::add_type_for_ace(&mut r.rootcas, sid_type)?;
        common::add_type_for_ace(&mut r.enterprisecas, sid_type)?;
        common::add_type_for_ace(&mut r.certtemplates, sid_type)?;
        common::add_type_for_ace(&mut r.issuancepolicies, sid_type)?;

        common::add_type_for_allowtedtoact(&mut r.computers, sid_type)?;
        common::add_type_for_sidhistory(&mut r.users, &mut r.groups, &mut r.computers, sid_type)?;

        previous_childobjects(&mut r.ous, dn_sid, sid_type);
        previous_childobjects(&mut r.domains, dn_sid, sid_type);
        previous_childobjects(&mut r.containers, dn_sid, sid_type);

        common::add_contained_by_for(&mut r.users, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.groups, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.computers, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.gpos, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.ous, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.containers, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.ntauthstores, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.aiacas, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.rootcas, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.enterprisecas, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.certtemplates, dn_sid, sid_type)?;
        common::add_contained_by_for(&mut r.issuancepolicies, dn_sid, sid_type)?;

        // ESC13 (restored in Pathwarden's copy in cac4b3d; also upstream's).
        common::add_group_link_for_issuancepolicies(&mut r.issuancepolicies, dn_sid, sid_type)?;

        common::add_affected_computers(&mut r.domains, sid_type)?;
        common::add_affected_computers_for_ou(&mut r.ous, dn_sid, sid_type)?;

        previous_gplink(&mut r.ous, dn_sid);
        previous_gplink(&mut r.domains, dn_sid);

        if !r.trusts.is_empty() {
            common::add_trustdomain(&mut r.domains, &mut r.trusts)?;
        }
        Ok(())
    }

    /// Binary `objectSid` for S-1-5-21-1-2-3-<rid>.
    pub(crate) fn sid(rid: u32) -> Vec<u8> {
        let mut b = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for s in [21u32, 1, 2, 3, rid] {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    pub(crate) fn guid(n: u64, tag: u8) -> Vec<u8> {
        let mut g = vec![tag; 16];
        g[..8].copy_from_slice(&n.to_le_bytes());
        g
    }

    pub(crate) fn entry(
        dn: &str,
        classes: &[&str],
        attrs: &[(&str, String)],
        bins: Vec<(&str, Vec<u8>)>,
    ) -> LdapSearchEntry {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert(
            "objectClass".into(),
            classes.iter().map(|c| c.to_string()).collect(),
        );
        a.insert("distinguishedName".into(), vec![dn.to_string()]);
        for (k, v) in attrs {
            a.insert(k.to_string(), vec![v.clone()]);
        }
        LdapSearchEntry {
            dn: dn.to_string(),
            attrs: a,
            bin_attrs: bins
                .into_iter()
                .map(|(k, v)| (k.to_string(), vec![v]))
                .collect(),
        }
    }

    /// A small domain full of the shapes the passes care about: nested and
    /// same-named OUs and containers (`OU=Computers` under every site),
    /// lower-case DNs, a value that contains another, objects under the
    /// domain root, GPOs linked from OUs and the domain (one link to a GPO
    /// that is not there, one with a long upper-case run around a GUID).
    pub(crate) fn synthetic(n_sites: usize) -> Vec<LdapSearchEntry> {
        let base = "DC=contoso,DC=local";
        let gpo = |i: usize| format!("{{{:08X}-0000-0000-0000-{:012X}}}", i, i);
        let mut v = vec![entry(
            base,
            &["top", "domain", "domainDNS"],
            &[
                ("name", "contoso".into()),
                (
                    "gPLink",
                    format!(
                        "[LDAP://cn={},cn=policies,cn=system,{base};0][LDAP://cn={{DEADBEEF-0000-0000-0000-000000000000}},cn=policies,cn=system,{base};2]",
                        gpo(0)
                    ),
                ),
            ],
            vec![("objectSid", {
                let mut b = vec![1u8, 4, 0, 0, 0, 0, 0, 5];
                for s in [21u32, 1, 2, 3] {
                    b.extend_from_slice(&s.to_le_bytes());
                }
                b
            })],
        )];
        let mut rid = 1000u32;
        let mut g = 0u64;
        let mut next = |tag: u8| {
            g += 1;
            guid(g, tag)
        };
        for i in 0..4 {
            v.push(entry(
                &format!("CN={},CN=Policies,CN=System,{base}", gpo(i)),
                &["top", "container", "groupPolicyContainer"],
                &[
                    ("displayName", format!("GPO {i}")),
                    (
                        "gPCFileSysPath",
                        format!(
                            "\\\\contoso.local\\SysVol\\contoso.local\\Policies\\{}",
                            gpo(i)
                        ),
                    ),
                    ("flags", "0".into()),
                ],
                vec![("objectGUID", next(7))],
            ));
        }
        v.push(entry(
            &format!("CN=System,{base}"),
            &["top", "container"],
            &[("name", "System".into())],
            vec![("objectGUID", next(2))],
        ));
        v.push(entry(
            &format!("CN=Users,{base}"),
            &["top", "container"],
            &[("name", "Users".into())],
            vec![("objectGUID", next(2))],
        ));
        for s in 0..n_sites {
            let site = format!("OU=Site{s},{base}");
            v.push(entry(
                &site,
                &["top", "organizationalUnit"],
                &[
                    ("name", format!("Site{s}")),
                    (
                        "gPLink",
                        format!(
                            "[LDAP://cn={},cn=policies,cn=system,{base};0]",
                            gpo(1 + s % 3)
                        ),
                    ),
                ],
                vec![("objectGUID", next(1))],
            ));
            // Every site has OUs with the same names.
            for sub in ["Computers", "Users", "Servers"] {
                let ou = format!("OU={sub},{site}");
                v.push(entry(
                    &ou,
                    &["top", "organizationalUnit"],
                    &[
                        ("name", sub.into()),
                        (
                            "gPLink",
                            format!("[LDAP://cn={},cn=policies,cn=system,{base};0]", gpo(s % 4)),
                        ),
                    ],
                    vec![("objectGUID", next(1))],
                ));
                for k in 0..3 {
                    rid += 1;
                    if sub == "Computers" {
                        v.push(entry(
                            &format!("CN=PC{s}X{k},{ou}"),
                            &["top", "person", "organizationalPerson", "user", "computer"],
                            &[
                                ("name", format!("PC{s}X{k}")),
                                ("sAMAccountName", format!("PC{s}X{k}$")),
                                ("dNSHostName", format!("pc{s}x{k}.contoso.local")),
                                ("userAccountControl", "4096".into()),
                            ],
                            vec![("objectSid", sid(rid)), ("objectGUID", next(4))],
                        ));
                    } else {
                        v.push(entry(
                            &format!("CN=u{s}x{k},{ou}"),
                            &["top", "person", "organizationalPerson", "user"],
                            &[
                                ("name", format!("u{s}x{k}")),
                                ("sAMAccountName", format!("u{s}x{k}")),
                                ("userAccountControl", "512".into()),
                            ],
                            vec![("objectSid", sid(rid)), ("objectGUID", next(3))],
                        ));
                    }
                }
            }
            // A nested OU whose name repeats its parent's, and a container
            // inside an OU.
            let inner = format!("OU=Site{s},OU=Servers,{site}");
            v.push(entry(
                &inner,
                &["top", "organizationalUnit"],
                &[("name", format!("Site{s}"))],
                vec![("objectGUID", next(1))],
            ));
            rid += 1;
            v.push(entry(
                &format!("CN=deep{s},{inner}"),
                &["top", "person", "organizationalPerson", "user"],
                &[
                    ("name", format!("deep{s}")),
                    ("sAMAccountName", format!("deep{s}")),
                ],
                vec![("objectSid", sid(rid)), ("objectGUID", next(3))],
            ));
            v.push(entry(
                &format!("CN=Stuff,{site}"),
                &["top", "container"],
                &[("name", "Stuff".into())],
                vec![("objectGUID", next(2))],
            ));
            rid += 1;
            v.push(entry(
                &format!("CN=grp{s},CN=Stuff,{site}"),
                &["top", "group"],
                &[
                    ("name", format!("grp{s}")),
                    ("sAMAccountName", format!("grp{s}")),
                ],
                vec![("objectSid", sid(rid)), ("objectGUID", next(5))],
            ));
        }
        // Lower-case DN (some tools write them), an OU whose name is a prefix
        // of another's, and a long upper-case run around a GUID-like value.
        v.push(entry(
            &format!("ou=lower,{base}"),
            &["top", "organizationalUnit"],
            &[("name", "lower".into())],
            vec![("objectGUID", next(1))],
        ));
        v.push(entry(
            &format!("OU=Site1X,{base}"),
            &["top", "organizationalUnit"],
            &[("name", "Site1X".into())],
            vec![("objectGUID", next(1))],
        ));
        rid += 1;
        v.push(entry(
            &format!(
                "CN=ABC{}XYZ,CN=Users,{base}",
                gpo(2).trim_matches(['{', '}'])
            ),
            &["top", "person", "organizationalPerson", "user"],
            &[("name", "odd".into()), ("sAMAccountName", "odd".into())],
            vec![("objectSid", sid(rid)), ("objectGUID", next(3))],
        ));
        // An Enterprise CA publishing templates whose names contain others'.
        let pks = format!("CN=Public Key Services,CN=Services,CN=Configuration,{base}");
        for name in ["ESC1", "ESC13", "User", "ExchangeUser"] {
            v.push(entry(
                &format!("CN={name},CN=Certificate Templates,{pks}"),
                &["top", "pKICertificateTemplate"],
                &[("name", name.into())],
                vec![("objectGUID", next(4))],
            ));
        }
        let mut ca = entry(
            &format!("CN=CONTOSO-CA,CN=Enrollment Services,{pks}"),
            &["top", "pKIEnrollmentService"],
            &[("name", "CONTOSO-CA".into())],
            vec![("objectGUID", next(5))],
        );
        ca.attrs.insert(
            "certificateTemplates".into(),
            ["ESC1", "User"].map(String::from).to_vec(),
        );
        v.push(ca);
        // An issuance policy linked to a group (ESC13), resolved by the checker.
        rid += 1;
        v.push(entry(
            &format!("CN=PKI Admins,CN=Users,{base}"),
            &["top", "group"],
            &[
                ("name", "PKI Admins".into()),
                ("sAMAccountName", "PKI Admins".into()),
            ],
            vec![("objectSid", sid(rid)), ("objectGUID", next(5))],
        ));
        v.push(entry(
            &format!("CN=1.2ABCDEF,CN=OID,{pks}"),
            &["top", "msPKI-Enterprise-Oid"],
            &[
                ("displayName", "LabPolicy".into()),
                ("flags", "2".into()),
                ("msPKI-Cert-Template-OID", "1.3.6.1.4.1.311.21.8.1.2".into()),
                (
                    "msDS-OIDToGroupLink",
                    format!("CN=PKI Admins,CN=Users,{base}"),
                ),
            ],
            vec![("objectGUID", next(6))],
        ));
        v
    }

    pub(crate) fn options(out: &std::path::Path) -> Options {
        super::super::base_options(
            "contoso.local",
            out,
            rusthound_ce::args::CollectionMethod::LdapOnly,
            "dc01.contoso.local".into(),
            true,
        )
    }

    fn json<T: serde::Serialize>(v: &[T]) -> Vec<serde_json::Value> {
        v.iter().map(|o| serde_json::to_value(o).unwrap()).collect()
    }

    fn copy(r: &ADResults) -> ADResults {
        ADResults {
            users: r.users.clone(),
            groups: r.groups.clone(),
            computers: r.computers.clone(),
            ous: r.ous.clone(),
            domains: r.domains.clone(),
            gpos: r.gpos.clone(),
            fsps: r.fsps.clone(),
            containers: r.containers.clone(),
            trusts: r.trusts.clone(),
            ntauthstores: r.ntauthstores.clone(),
            aiacas: r.aiacas.clone(),
            rootcas: r.rootcas.clone(),
            enterprisecas: r.enterprisecas.clone(),
            certtemplates: r.certtemplates.clone(),
            issuancepolicies: r.issuancepolicies.clone(),
            mappings: Default::default(),
        }
    }

    /// Parses once, then runs the checker and the previous one (2.5.27's
    /// passes) on copies of the same parse, so the same `dn_sid` iteration
    /// order: every object comes out identical, arrays in the same order.
    #[test]
    fn same_output_as_previous() {
        let out = std::env::temp_dir();
        let options = options(&out);
        let entries = synthetic(12);
        let n = entries.len();
        let parsed = rusthound_ce::api::parse_result_type_from_source(&options, entries, Some(n))
            .map_err(|e| e.to_string())
            .unwrap();
        let mut ours = copy(&parsed);
        let mut theirs = parsed;
        // The same map instances, so the same iteration order.
        ours.mappings = std::mem::take(&mut theirs.mappings);
        check_all(&options, &mut ours)
            .map_err(|e| e.to_string())
            .unwrap();
        theirs.mappings = std::mem::take(&mut ours.mappings);
        previous_check_all(&options, &mut theirs)
            .map_err(|e| e.to_string())
            .unwrap();

        assert_eq!(json(&ours.users), json(&theirs.users));
        assert_eq!(json(&ours.groups), json(&theirs.groups));
        assert_eq!(json(&ours.computers), json(&theirs.computers));
        assert_eq!(json(&ours.gpos), json(&theirs.gpos));
        assert_eq!(json(&ours.trusts), json(&theirs.trusts));
        let (a, b) = (json(&ours.ous), json(&theirs.ous));
        assert_eq!(a, b);
        assert_eq!(json(&ours.domains), json(&theirs.domains));
        assert_eq!(json(&ours.containers), json(&theirs.containers));
        assert_eq!(json(&ours.enterprisecas), json(&theirs.enterprisecas));
        assert_eq!(ours.enterprisecas.len(), 1);
        assert_eq!(ours.enterprisecas[0].enabled_cert_templates().len(), 2);
        assert_eq!(json(&ours.certtemplates), json(&theirs.certtemplates));
        let policies = json(&ours.issuancepolicies);
        assert_eq!(policies, json(&theirs.issuancepolicies));
        // The ESC13 group link was resolved (equal by doing the work).
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies[0]["GroupLink"]["ObjectType"], "Group",
            "{policies:?}"
        );

        // The passes did real work on this data (not equal by being empty).
        let children: usize = a
            .iter()
            .map(|o| o["ChildObjects"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(children > 50, "{children}");
        let as_linked: Vec<String> = (0..4)
            .map(|i| format!("{:08X}-0000-0000-0000-{:012X}", i, i))
            .collect();
        let linked = a
            .iter()
            .flat_map(|o| o["Links"].as_array().cloned().unwrap_or_default())
            .filter(|l| {
                l["GUID"]
                    .as_str()
                    .is_some_and(|g| !as_linked.iter().any(|x| x == g))
            })
            .count();
        assert!(linked > 0, "some links were replaced");
        let domain = &json(&ours.domains)[0];
        assert!(
            domain["Links"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l["GUID"] == "DEADBEEF-0000-0000-0000-000000000000"),
            "a link to a missing GPO stays as it was: {domain}"
        );
    }

    /// An OU with identifier `id` and links to `links` (no setter for the
    /// identifier: through the serialized form).
    fn ou(id: &str, links: &[&str]) -> Ou {
        let mut v = serde_json::to_value(Ou::new()).unwrap();
        v["ObjectIdentifier"] = id.into();
        let mut ou: Ou = serde_json::from_value(v).unwrap();
        ou.set_links(
            links
                .iter()
                .map(|g| Link::new(false, g.to_string()))
                .collect(),
        );
        ou
    }

    /// RustHound-CE's two passes and the previous ones on copies of
    /// `objects` with the same map: the same JSON, which is returned.
    fn same_passes(
        objects: Vec<Ou>,
        dn_sid: &HashMap<String, String>,
        sid_type: &HashMap<String, String>,
    ) -> Vec<serde_json::Value> {
        let mut ours = objects.clone();
        let mut theirs = objects;
        common::add_childobjects_members(&mut ours, dn_sid, sid_type)
            .map_err(|e| e.to_string())
            .unwrap();
        common::replace_guid_gplink(&mut ours, dn_sid)
            .map_err(|e| e.to_string())
            .unwrap();
        previous_childobjects(&mut theirs, dn_sid, sid_type);
        previous_gplink(&mut theirs, dn_sid);
        let out = json(&ours);
        assert_eq!(out, json(&theirs));
        out
    }

    /// The two passes against 2.5.27's on hand-made maps with every quirk:
    /// ties, substrings, GUIDs inside long runs, odd links.
    #[test]
    fn passes_match_previous_on_edge_cases() {
        let mut dn_sid: HashMap<String, String> = HashMap::new();
        let gpo = "31B2F340-016D-11D2-945F-00C04FB984F9";
        for (dn, sid) in [
            (
                format!("CN={{{gpo}}},CN=POLICIES,CN=SYSTEM,DC=X,DC=Y"),
                "GPO-SID-1",
            ),
            (
                format!("CN=MACHINE,CN={{{gpo}}},CN=POLICIES,CN=SYSTEM,DC=X,DC=Y"),
                "GPO-CHILD",
            ),
            (format!("CN=LONG{gpo}RUN,DC=X,DC=Y"), "LONG-RUN"),
            ("OU=A,DC=X,DC=Y".into(), "OU-A"),
            ("CN=U1,OU=A,DC=X,DC=Y".into(), "U1"),
            ("CN=U2,OU=A,OU=B,OU=A,DC=X,DC=Y".into(), "U2"),
            ("OU=A,OU=B,OU=A,DC=X,DC=Y".into(), "OU-A2"),
            ("CN=U3,CN=A,OU=A,DC=X,DC=Y".into(), "U3"),
            ("CN=E,OU=A,DC=X,DC=Y".into(), ""),
            ("OU=B,OU=A,DC=X,DC=Y".into(), "OU-B"),
            ("ou=c,dc=x,dc=y".into(), "OU-C"),
            ("CN=V,OU=C,DC=X,DC=Y".into(), "V"),
            ("DC=X,DC=Y".into(), "DOM"),
            ("CN=W,DC=X,DC=Y".into(), "W"),
            ("CN=Z,DC=X,DC=YY".into(), "Z"),
            // Two objects named A whose DNs start at the same place in Q.
            ("OU=A,DC=X,DC=Y,DC=Z".into(), "OU-AZ"),
            ("CN=Q,OU=A,DC=X,DC=Y,DC=Z".into(), "Q"),
        ] {
            dn_sid.insert(dn, sid.to_string());
        }
        let sid_type: HashMap<String, String> = [("U1", "User"), ("OU-B", "OU")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let lk = [
            gpo,
            "016D-11D2-945F-00C04FB984F9",
            "",
            "NOPE",
            "ou-a",
            "DC=X",
        ];
        let objects = ["OU-A", "OU-A2", "OU-B", "OU-C", "DOM", "ou-b", "OU-AZ"]
            .iter()
            .map(|id| ou(id, &lk))
            .collect();
        let out = same_passes(objects, &dn_sid, &sid_type);
        // OU=A finds its direct child, the deeper U2 (the substring quirk)
        // and not the empty-SID entry.
        let a = &out[0];
        let kids: Vec<_> = a["ChildObjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["ObjectIdentifier"].as_str().unwrap().to_string())
            .collect();
        assert!(kids.contains(&"U1".to_string()), "{a}");
        assert!(!kids.contains(&String::new()));
        // Not direct children, but listed: a parent-DN index would miss them.
        for quirk in ["U2", "U3"] {
            assert!(kids.contains(&quirk.to_string()), "{quirk}: {a}");
        }
        // Q is under OU=A,...,DC=Z, and OU=A,DC=X,DC=Y is a prefix of that.
        for o in [a, &out[6]] {
            assert!(o["ChildObjects"].to_string().contains("\"Q\""), "{o}");
        }
        // The domain lists W and, through the DC=YY prefix, Z.
        let kids = out[4]["ChildObjects"].to_string();
        assert!(kids.contains("\"W\"") && kids.contains("\"Z\""), "{kids}");
        // Whichever key the map yields first (the GPO, its child container,
        // or the long run that contains the GUID).
        let first = a["Links"][0]["GUID"].as_str().unwrap();
        assert!(
            ["GPO-SID-1", "GPO-CHILD", "LONG-RUN"].contains(&first),
            "{a}"
        );
    }

    /// The two passes against 2.5.27's on the DNs of the repository's
    /// collection fixtures (`testdata/*`, BloodHound JSON from RustHound-CE
    /// and other collectors, non-ASCII names included). A GPO written without
    /// its DN gets the `CN={GUID},CN=POLICIES,...` key RustHound-CE's
    /// `dn_sid` has for it; every object with `Links` becomes an OU.
    #[test]
    fn passes_match_previous_on_testdata() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        let mut files = Vec::new();
        let mut dirs = vec![root];
        while let Some(dir) = dirs.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    dirs.push(p);
                } else if p.extension().is_some_and(|x| x == "json") {
                    files.push(p);
                }
            }
        }
        files.sort();
        let mut dn_sid: HashMap<String, String> = HashMap::new();
        let mut linked: Vec<(String, Vec<String>)> = Vec::new();
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            let Ok(doc) =
                serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
            else {
                continue;
            };
            let kind = doc["meta"]["type"].as_str().unwrap_or("").to_string();
            let Some(data) = doc["data"].as_array() else {
                continue;
            };
            for o in data {
                let Some(id) = o["ObjectIdentifier"].as_str() else {
                    continue;
                };
                match o["Properties"]["distinguishedname"].as_str() {
                    Some(dn) => {
                        dn_sid.insert(dn.to_string(), id.to_string());
                    }
                    None if kind == "gpos" => {
                        dn_sid.insert(format!("CN={{{id}}},CN=POLICIES,CN=SYSTEM"), id.to_string());
                    }
                    None => {}
                }
                if let Some(links) = o["Links"].as_array() {
                    let guids = links
                        .iter()
                        .filter_map(|l| l["GUID"].as_str().map(str::to_string))
                        .collect();
                    linked.push((id.to_string(), guids));
                }
            }
        }
        // Fixture sets in different folders may reuse a domain's DN with
        // another SID (CONTOSO.LOCAL); keep only objects whose DN maps to
        // them, as in one real collection.
        let objects = linked
            .iter()
            .filter(|(id, _)| dn_sid.values().any(|s| s == id))
            .map(|(id, links)| ou(id, &links.iter().map(String::as_str).collect::<Vec<_>>()))
            .collect();
        let out = same_passes(objects, &dn_sid, &HashMap::new());
        // Not equal by being empty: the fixtures' domains list their OUs, and
        // links resolve to the GPOs.
        let children: usize = out
            .iter()
            .map(|o| o["ChildObjects"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(
            out.len() >= 5 && children > 0,
            "{} objects, {children} children",
            out.len()
        );
        let links: usize = out
            .iter()
            .map(|o| o["Links"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(links > 0);
    }

    /// One object of a BloodHound JSON file, as far as the two passes need
    /// it (the other fields are skipped, so large files stay small).
    #[derive(serde::Deserialize)]
    struct DnObject {
        #[serde(rename = "ObjectIdentifier")]
        id: Option<serde_json::Value>,
        #[serde(rename = "Properties")]
        properties: Option<DnProperties>,
        #[serde(rename = "Links")]
        links: Option<Vec<serde_json::Value>>,
    }

    #[derive(serde::Deserialize)]
    struct DnProperties {
        distinguishedname: Option<serde_json::Value>,
    }

    #[derive(serde::Deserialize)]
    struct DnFile {
        #[serde(default)]
        data: Vec<DnObject>,
        meta: Option<serde_json::Value>,
    }

    /// [`passes_match_previous_on_testdata`] on local collections, which stay
    /// out of the repository: `PATHWARDEN_CHECKER_DATA` lists folders of
    /// BloodHound JSON files and zips, separated by `;`. Prints the time of
    /// both passes and of 2.5.27's. Run with `--release --ignored
    /// --nocapture passes_match_previous_on_local_data`.
    #[test]
    #[ignore = "local data; run on demand"]
    fn passes_match_previous_on_local_data() {
        use std::io::Read;
        let Ok(roots) = std::env::var("PATHWARDEN_CHECKER_DATA") else {
            return;
        };
        let mut dn_sid: HashMap<String, String> = HashMap::new();
        let mut linked: Vec<(String, Vec<String>)> = Vec::new();
        let mut add = |name: &str, bytes: Vec<u8>| {
            let Ok(doc) = serde_json::from_slice::<DnFile>(
                bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes),
            ) else {
                println!("skipped {name}");
                return;
            };
            let kind = doc
                .meta
                .as_ref()
                .and_then(|m| m["type"].as_str())
                .unwrap_or("")
                .to_string();
            for o in doc.data {
                let Some(id) = o.id.as_ref().and_then(|v| v.as_str()) else {
                    continue;
                };
                let dn = o.properties.and_then(|p| p.distinguishedname);
                match dn.as_ref().and_then(|v| v.as_str()) {
                    Some(dn) => {
                        dn_sid.insert(dn.to_string(), id.to_string());
                    }
                    None if kind == "gpos" => {
                        dn_sid.insert(format!("CN={{{id}}},CN=POLICIES,CN=SYSTEM"), id.to_string());
                    }
                    None => {}
                }
                if let Some(links) = o.links {
                    let guids = links
                        .iter()
                        .filter_map(|l| l["GUID"].as_str().map(str::to_string))
                        .collect();
                    linked.push((id.to_string(), guids));
                }
            }
        };
        for root in roots.split(';').filter(|r| !r.is_empty()) {
            let mut paths: Vec<_> = std::fs::read_dir(root)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            paths.sort();
            for p in paths {
                let name = p.display().to_string();
                match p.extension().and_then(|x| x.to_str()) {
                    Some("json") => add(&name, std::fs::read(&p).unwrap()),
                    Some("zip") => {
                        let mut zip =
                            zip::ZipArchive::new(std::fs::File::open(&p).unwrap()).unwrap();
                        for i in 0..zip.len() {
                            let mut f = zip.by_index(i).unwrap();
                            if !f.name().unwrap().ends_with(".json") {
                                continue;
                            }
                            let inner = format!("{name}:{}", f.name().unwrap());
                            let mut bytes = Vec::new();
                            f.read_to_end(&mut bytes).unwrap();
                            add(&inner, bytes);
                        }
                    }
                    _ => {}
                }
            }
        }
        let objects: Vec<Ou> = linked
            .iter()
            .map(|(id, links)| ou(id, &links.iter().map(String::as_str).collect::<Vec<_>>()))
            .collect();
        let sid_type = HashMap::new();
        let mut ours = objects.clone();
        let mut theirs = objects;
        let started = std::time::Instant::now();
        common::add_childobjects_members(&mut ours, &dn_sid, &sid_type)
            .map_err(|e| e.to_string())
            .unwrap();
        let child_pass = started.elapsed();
        let started = std::time::Instant::now();
        common::replace_guid_gplink(&mut ours, &dn_sid)
            .map_err(|e| e.to_string())
            .unwrap();
        let link_pass = started.elapsed();
        let started = std::time::Instant::now();
        previous_childobjects(&mut theirs, &dn_sid, &sid_type);
        previous_gplink(&mut theirs, &dn_sid);
        let previous = started.elapsed();
        let out = json(&ours);
        assert_eq!(out, json(&theirs));
        let children: usize = out
            .iter()
            .map(|o| o["ChildObjects"].as_array().map_or(0, Vec::len))
            .sum();
        let links: usize = out
            .iter()
            .map(|o| o["Links"].as_array().map_or(0, Vec::len))
            .sum();
        println!(
            "local data: {} DNs, {} objects with links, {children} children, {links} links: \
             ChildObjects pass {child_pass:.2?}, gPLink pass {link_pass:.2?}; \
             2.5.27's passes {previous:.2?}; same output",
            dn_sid.len(),
            out.len()
        );
    }

    /// Times [`check_all`] on [`synthetic`] with `PATHWARDEN_CHECKER_SITES`
    /// sites (default 10 000, about 230k entries, a third of them OUs and
    /// containers, with the same OU names under every site). Run with
    /// `--release --ignored --nocapture checker_scale`.
    #[test]
    #[ignore = "timing; run on demand"]
    fn checker_scale() {
        let sites: usize = std::env::var("PATHWARDEN_CHECKER_SITES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let out = std::env::temp_dir();
        let options = options(&out);
        let entries = synthetic(sites);
        let n = entries.len();
        let mut r = rusthound_ce::api::parse_result_type_from_source(&options, entries, Some(n))
            .map_err(|e| e.to_string())
            .unwrap();
        let containers = r.ous.len() + r.containers.len() + r.domains.len();
        let before = super::super::timings::peak_memory();
        let started = std::time::Instant::now();
        check_all(&options, &mut r)
            .map_err(|e| e.to_string())
            .unwrap();
        let took = started.elapsed();
        let after = super::super::timings::peak_memory();
        let children: usize = r.ous.iter().map(|o| o.get_child_objects().len()).sum();
        // The two passes 2.5.28 rewrote, again on their own (idempotent: the
        // links already hold the GPOs' identifiers, which resolve to
        // themselves).
        let (dn_sid, sid_type) = (&r.mappings.dn_sid, &r.mappings.sid_type);
        let started = std::time::Instant::now();
        common::add_childobjects_members(&mut r.ous, dn_sid, sid_type).unwrap();
        common::add_childobjects_members(&mut r.domains, dn_sid, sid_type).unwrap();
        common::add_childobjects_members(&mut r.containers, dn_sid, sid_type).unwrap();
        let child_pass = started.elapsed();
        let started = std::time::Instant::now();
        common::replace_guid_gplink(&mut r.ous, dn_sid).unwrap();
        common::replace_guid_gplink(&mut r.domains, dn_sid).unwrap();
        let link_pass = started.elapsed();
        let mb = |b: Option<u64>| b.map_or("?".into(), |b| (b >> 20).to_string());
        println!(
            "checker: {n} entries, {containers} OUs/containers/domains, {children} OU children: \
             {took:.2?} (ChildObjects pass {child_pass:.2?}, gPLink pass {link_pass:.2?}); \
             peak memory {} MB before, {} MB after",
            mb(before),
            mb(after)
        );
    }

    /// Parses `entries` and runs [`check_all`], as the built-in collector does.
    fn checked(entries: Vec<LdapSearchEntry>) -> ADResults {
        let out = std::env::temp_dir();
        let options = options(&out);
        let n = entries.len();
        let mut r = rusthound_ce::api::parse_result_type_from_source(&options, entries, Some(n))
            .map_err(|e| e.to_string())
            .unwrap();
        check_all(&options, &mut r)
            .map_err(|e| e.to_string())
            .unwrap();
        r
    }

    /// GOAD's essos templates whose names contain one another: up to
    /// RustHound-CE 2.5.24 `ESC1` resolved to `ESC13`, `ESC3` to `ESC3-CRA`
    /// and `User` to `ExchangeUser` (g0h4n/RustHound-CE#85, fixed in 2.5.25).
    #[test]
    fn templates_are_published_by_exact_name() {
        let pks = "CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local";
        let names = ["ESC1", "ESC13", "ESC3", "ESC3-CRA", "User", "ExchangeUser"];
        let mut entries: Vec<LdapSearchEntry> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                entry(
                    &format!("CN={n},CN=Certificate Templates,{pks}"),
                    &["top", "pKICertificateTemplate"],
                    &[("name", n.to_string())],
                    vec![("objectGUID", guid(i as u64 + 1, 0x11))],
                )
            })
            .collect();
        let mut ca = entry(
            &format!("CN=CONTOSO-CA,CN=Enrollment Services,{pks}"),
            &["top", "pKIEnrollmentService"],
            &[("name", "CONTOSO-CA".into())],
            vec![("objectGUID", guid(99, 0x22))],
        );
        ca.attrs.insert(
            "certificateTemplates".into(),
            ["ESC1", "ESC3", "User"].map(String::from).to_vec(),
        );
        entries.push(ca);
        let r = checked(entries);
        let id_of = |name: &str| {
            r.certtemplates
                .iter()
                .find(|t| {
                    t.properties()
                        .name()
                        .starts_with(&format!("{}@", name.to_uppercase()))
                })
                .map(|t| t.object_identifier().clone())
                .unwrap()
        };
        let want: Vec<String> = ["ESC1", "ESC3", "User"].iter().map(|n| id_of(n)).collect();
        assert!(want.iter().all(|id| !id.is_empty()), "{want:?}");
        let got: Vec<String> = r.enterprisecas[0]
            .enabled_cert_templates()
            .iter()
            .map(|m| m.object_identifier().clone())
            .collect();
        assert_eq!(got, want);
    }

    /// The GOAD shape: a group with members from a trusted forest and a
    /// well-known SID, through foreign security principals. Up to
    /// RustHound-CE 2.5.24 these were named by objectGUID, so the members
    /// matched no other node (g0h4n/RustHound-CE#87, fixed in 2.5.25).
    #[test]
    fn foreign_principals_resolve_to_their_sid() {
        let base = "DC=contoso,DC=local";
        let foreign = "S-1-5-21-1821261621-2407627684-1290984713-1108";
        let foreign_dn = format!("CN={foreign},CN=ForeignSecurityPrincipals,{base}");
        let well_known_dn = format!("CN=S-1-5-11,CN=ForeignSecurityPrincipals,{base}");
        // A domain SID is not valid UTF-8, so ldap3 delivers it in bin_attrs;
        // S-1-5-11 is, so it arrives as text.
        let mut foreign_sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for s in [21u32, 1821261621, 2407627684, 1290984713, 1108] {
            foreign_sid.extend_from_slice(&s.to_le_bytes());
        }
        assert!(std::str::from_utf8(&foreign_sid).is_err());
        let well_known_sid = String::from_utf8(vec![1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0]).unwrap();
        let mut group = entry(
            &format!("CN=Spys,CN=Users,{base}"),
            &["top", "group"],
            &[("name", "Spys".into()), ("sAMAccountName", "Spys".into())],
            vec![("objectSid", sid(1112)), ("objectGUID", guid(1, 0x33))],
        );
        group.attrs.insert(
            "member".into(),
            vec![foreign_dn.clone(), well_known_dn.clone()],
        );
        let entries = vec![
            group,
            entry(
                &foreign_dn,
                &["top", "foreignSecurityPrincipal"],
                &[("name", foreign.into())],
                vec![("objectSid", foreign_sid), ("objectGUID", guid(2, 0x44))],
            ),
            entry(
                &well_known_dn,
                &["top", "foreignSecurityPrincipal"],
                &[("name", "S-1-5-11".into()), ("objectSid", well_known_sid)],
                vec![("objectGUID", guid(3, 0x44))],
            ),
        ];
        let r = checked(entries);
        let spys = r
            .groups
            .iter()
            .find(|g| g.object_identifier() == "S-1-5-21-1-2-3-1112")
            .unwrap();
        let mut members: Vec<(String, String)> = spys
            .members()
            .iter()
            .map(|m| (m.object_identifier().clone(), m.object_type().clone()))
            .collect();
        members.sort();
        // Up to 2.5.29 every foreign principal was typed "Group". From
        // 2.5.30 (g0h4n/RustHound-CE#107) a domain SID is "Base",
        // since User, Group and Computer share its RID space, and only the
        // well-known SIDs get a kind (S-1-5-11 is a group). The ingest turns
        // a Base member into a placeholder of unknown kind, which the real
        // object replaces when its domain is collected too. A change here
        // alters the placeholder nodes' kind.
        assert_eq!(
            members,
            [
                ("CONTOSO.LOCAL-S-1-5-11".to_string(), "Group".to_string()),
                (foreign.to_string(), "Base".to_string()),
            ]
        );
    }
}
