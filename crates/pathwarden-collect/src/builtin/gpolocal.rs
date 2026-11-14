//! Which GPO, and which of its settings, puts each member in the four local
//! groups RustHound-CE turns into `GPOChanges`.
//!
//! Upstream merges the GPOs linked to an OU or domain, so the merged result
//! no longer says which GPO set a member. Here each GPO is run alone through
//! upstream's own `compute_merged`, once per setting (Restricted Groups, GPP
//! Local Users and Groups), with the same resolver: the members match
//! `GPOChanges` exactly. Nothing in RustHound-CE changes.

use std::collections::{HashMap, HashSet};

use rusthound_ce::modules::gpo::local_group::{MergedGroups, TypedPrincipal};
use rusthound_ce::modules::gpo::sysvol::SysvolGpo;
use rusthound_ce::modules::gpo::{compute_merged, Resolver};

use super::gpp::GpoLocalOut;

/// Most entries written (a GPO, a setting, a group).
pub(crate) const MAX_ENTRIES: usize = 100_000;
/// Most members written per entry.
pub(crate) const MAX_MEMBERS: usize = 1_000;

/// What [`attribute`] found.
#[derive(Debug, Default)]
pub(crate) struct Attributed {
    /// The sidecar entries; empty when there were more than [`MAX_ENTRIES`].
    pub entries: Vec<GpoLocalOut>,
    /// How many entries there were when over [`MAX_ENTRIES`], else 0.
    pub over_cap: usize,
    /// Entries whose members were cut at [`MAX_MEMBERS`]. Ingest names no
    /// GPO wherever such a GPO is linked.
    pub truncated: usize,
}

/// The sidecar entries for `sysvol`. `ids`: GPO folder name, upper case with
/// braces, to the GPO's ObjectIdentifier. All or nothing: a partial list
/// could name one GPO where another also sets the member, so over
/// [`MAX_ENTRIES`] none is written, and an entry over [`MAX_MEMBERS`] says
/// so (`members_truncated`).
pub(crate) fn attribute(
    sysvol: &[SysvolGpo],
    ids: &HashMap<String, String>,
    resolver: &impl Resolver,
    domain: &str,
) -> Attributed {
    let mut out = Vec::new();
    for gpo in sysvol {
        let guid = gpo.guid.to_uppercase();
        let object_id = ids.get(&guid).cloned();
        let entry = |setting, group, targeted, mut members: Vec<String>| {
            let members_truncated = members.len() > MAX_MEMBERS;
            members.truncate(MAX_MEMBERS);
            GpoLocalOut {
                guid: guid.clone(),
                object_id: object_id.clone(),
                setting,
                group,
                item_level_targeting: targeted,
                members_truncated,
                members,
            }
        };

        if !gpo.restricted_groups.is_empty() {
            let alone = SysvolGpo {
                guid: gpo.guid.clone(),
                restricted_groups: gpo.restricted_groups.clone(),
                ..Default::default()
            };
            for (group, members) in groups(&compute_merged(&[&alone], resolver, domain)) {
                if !members.is_empty() {
                    out.push(entry("restricted_groups", group, false, sids(members)));
                }
            }
        }

        if !gpo.gpp_local_groups.is_empty() {
            let alone = SysvolGpo {
                guid: gpo.guid.clone(),
                gpp_local_groups: gpo.gpp_local_groups.clone(),
                ..Default::default()
            };
            let all = compute_merged(&[&alone], resolver, domain);
            // What the items without item-level targeting give alone: a
            // member only the targeted items add may not be on every computer.
            let untargeted = SysvolGpo {
                guid: gpo.guid.clone(),
                gpp_local_groups: gpo
                    .gpp_local_groups
                    .iter()
                    .filter(|g| !g.has_item_level_targeting())
                    .cloned()
                    .collect(),
                ..Default::default()
            };
            let plain = compute_merged(&[&untargeted], resolver, domain);
            for ((group, members), (_, plain)) in groups(&all).into_iter().zip(groups(&plain)) {
                let plain: HashSet<&str> = plain.iter().map(|p| p.sid.as_str()).collect();
                let (everywhere, targeted): (Vec<&TypedPrincipal>, Vec<&TypedPrincipal>) =
                    members.iter().partition(|p| plain.contains(p.sid.as_str()));
                for (targeted, members) in [(false, everywhere), (true, targeted)] {
                    if !members.is_empty() {
                        let members = members.into_iter().map(|p| p.sid.clone()).collect();
                        out.push(entry("gpp", group, targeted, members));
                    }
                }
            }
        }
    }
    if out.len() > MAX_ENTRIES {
        return Attributed {
            over_cap: out.len(),
            ..Attributed::default()
        };
    }
    let truncated = out.iter().filter(|e| e.members_truncated).count();
    Attributed {
        entries: out,
        over_cap: 0,
        truncated,
    }
}

/// The four groups, by their sidecar names.
fn groups(m: &MergedGroups) -> [(&'static str, &[TypedPrincipal]); 4] {
    [
        ("administrators", &m.local_admins),
        ("remote_desktop", &m.remote_desktop_users),
        ("dcom", &m.dcom_users),
        ("ps_remote", &m.psremote_users),
    ]
}

fn sids(members: &[TypedPrincipal]) -> Vec<String> {
    members.iter().map(|p| p.sid.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusthound_ce::modules::gpo::{
        GppGroupAction, GppGroupMember, GppLocalGroup, GppMemberAction, RestrictedGroupDirective,
        RestrictedGroupOperation,
    };

    const DOMAIN: &str = "example.test";
    const ALICE: &str = "S-1-5-21-10-20-30-1101";
    const OPS: &str = "S-1-5-21-10-20-30-1201";

    /// Resolves two names; everything else is unknown.
    struct FakeResolver;

    impl Resolver for FakeResolver {
        fn resolve_name(&self, name: &str) -> Option<(String, String)> {
            match name.to_uppercase().as_str() {
                "ALICE" => Some((ALICE.into(), "User".into())),
                "IT OPS" => Some((OPS.into(), "Group".into())),
                _ => None,
            }
        }
        fn type_of_sid(&self, sid: &str) -> Option<String> {
            match sid {
                ALICE => Some("User".into()),
                OPS => Some("Group".into()),
                _ => None,
            }
        }
    }

    fn guid(n: u8) -> String {
        format!("{{0000000{n}-0000-0000-0000-000000000000}}")
    }

    fn ids(n: &[u8]) -> HashMap<String, String> {
        n.iter()
            .map(|&n| (guid(n), format!("0000000{n}-0000-0000-0000-000000000000")))
            .collect()
    }

    fn gpp(targeted: bool, members: Vec<GppGroupMember>) -> GppLocalGroup {
        GppLocalGroup::new(
            Some("S-1-5-32-544".into()),
            Some("Administrators (built-in)".into()),
            GppGroupAction::Update,
            false,
            false,
            targeted,
            members,
        )
    }

    fn add(name: &str) -> GppGroupMember {
        GppGroupMember::new(None, Some(name.into()), GppMemberAction::Add)
    }

    #[test]
    fn one_gpo_adds_by_restricted_groups_and_the_other_is_empty() {
        let setting = SysvolGpo {
            guid: guid(1).to_lowercase(),
            restricted_groups: vec![RestrictedGroupDirective::new(
                r"EXAMPLE\alice",
                RestrictedGroupOperation::AddToParentGroups,
                vec!["*S-1-5-32-544".into()],
            )],
            ..Default::default()
        };
        let empty = SysvolGpo {
            guid: guid(2),
            ..Default::default()
        };
        let found = attribute(&[setting, empty], &ids(&[1, 2]), &FakeResolver, DOMAIN);
        let (out, cut) = (found.entries, found.over_cap);
        assert_eq!(cut, 0);
        assert_eq!(out.len(), 1, "{out:?}");
        let e = &out[0];
        assert_eq!(e.guid, guid(1));
        assert_eq!(
            e.object_id.as_deref(),
            Some("00000001-0000-0000-0000-000000000000")
        );
        assert_eq!(
            (e.setting, e.group),
            ("restricted_groups", "administrators")
        );
        assert!(!e.item_level_targeting);
        assert_eq!(e.members, [ALICE]);
    }

    #[test]
    fn a_gpp_add_then_delete_in_the_same_gpo_writes_nothing() {
        let gpo = SysvolGpo {
            guid: guid(1),
            gpp_local_groups: vec![gpp(
                false,
                vec![
                    add("alice"),
                    GppGroupMember::new(Some(ALICE.into()), None, GppMemberAction::Remove),
                ],
            )],
            ..Default::default()
        };
        let out = attribute(&[gpo], &ids(&[1]), &FakeResolver, DOMAIN).entries;
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn a_name_the_resolver_does_not_know_writes_nothing() {
        let gpo = SysvolGpo {
            guid: guid(1),
            restricted_groups: vec![RestrictedGroupDirective::new(
                "*S-1-5-32-544",
                RestrictedGroupOperation::ReplaceMembers,
                vec!["NOBODY".into(), r"EXAMPLE\gone".into()],
            )],
            gpp_local_groups: vec![gpp(false, vec![add("nobody")])],
            ..Default::default()
        };
        let out = attribute(&[gpo], &ids(&[1]), &FakeResolver, DOMAIN).entries;
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn members_only_targeted_items_add_are_marked() {
        let gpo = SysvolGpo {
            guid: guid(1),
            gpp_local_groups: vec![
                gpp(false, vec![add("alice")]),
                gpp(true, vec![add("IT Ops")]),
            ],
            ..Default::default()
        };
        let out = attribute(&[gpo], &ids(&[1]), &FakeResolver, DOMAIN).entries;
        let got: Vec<(&str, bool, &[String])> = out
            .iter()
            .map(|e| (e.setting, e.item_level_targeting, e.members.as_slice()))
            .collect();
        assert_eq!(
            got,
            [
                ("gpp", false, &[ALICE.to_string()][..]),
                ("gpp", true, &[OPS.to_string()][..])
            ]
        );
    }

    #[test]
    fn members_are_capped() {
        struct Everyone;
        impl Resolver for Everyone {
            fn resolve_name(&self, name: &str) -> Option<(String, String)> {
                Some((format!("S-1-5-21-10-20-30-{name}"), "User".into()))
            }
            fn type_of_sid(&self, _: &str) -> Option<String> {
                Some("User".into())
            }
        }
        let many: Vec<GppGroupMember> = (0..MAX_MEMBERS + 5).map(|i| add(&i.to_string())).collect();
        let gpo = SysvolGpo {
            guid: guid(1),
            gpp_local_groups: vec![gpp(false, many)],
            ..Default::default()
        };
        let found = attribute(&[gpo], &ids(&[1]), &Everyone, DOMAIN);
        assert_eq!(found.entries[0].members.len(), MAX_MEMBERS);
        assert!(found.entries[0].members_truncated);
        assert_eq!(found.truncated, 1);
        let json = serde_json::to_value(&found.entries[0]).unwrap();
        assert_eq!(json["members_truncated"], true);

        // At the cap exactly: not marked, and the flag is left out.
        let gpo = SysvolGpo {
            guid: guid(1),
            gpp_local_groups: vec![gpp(
                false,
                (0..MAX_MEMBERS).map(|i| add(&i.to_string())).collect(),
            )],
            ..Default::default()
        };
        let found = attribute(&[gpo], &ids(&[1]), &Everyone, DOMAIN);
        assert!(!found.entries[0].members_truncated && found.truncated == 0);
        let json = serde_json::to_value(&found.entries[0]).unwrap();
        assert!(json.get("members_truncated").is_none());
    }

    #[test]
    fn over_the_entry_cap_nothing_is_written() {
        // Each GPO puts alice in all four groups: four entries.
        let gpos: Vec<SysvolGpo> = (0..MAX_ENTRIES / 4 + 1)
            .map(|i| SysvolGpo {
                guid: format!("{{{i:08X}-0000-0000-0000-000000000000}}"),
                restricted_groups: vec![RestrictedGroupDirective::new(
                    "alice",
                    RestrictedGroupOperation::AddToParentGroups,
                    ["544", "555", "562", "580"]
                        .iter()
                        .map(|r| format!("*S-1-5-32-{r}"))
                        .collect(),
                )],
                ..Default::default()
            })
            .collect();
        let found = attribute(&gpos, &HashMap::new(), &FakeResolver, DOMAIN);
        assert!(found.entries.is_empty());
        assert_eq!(found.over_cap, MAX_ENTRIES + 4);
        let found = attribute(
            &gpos[..MAX_ENTRIES / 4],
            &HashMap::new(),
            &FakeResolver,
            DOMAIN,
        );
        assert_eq!((found.entries.len(), found.over_cap), (MAX_ENTRIES, 0));
    }

    /// Every member the merge of several GPOs gives is in some GPO's own
    /// entry, whatever the precedence: attribution may name too many GPOs,
    /// never too few.
    #[test]
    fn every_merged_member_is_attributed() {
        let item = |delete_all_users: bool, members: Vec<GppGroupMember>| {
            GppLocalGroup::new(
                Some("S-1-5-32-544".into()),
                None,
                GppGroupAction::Update,
                delete_all_users,
                false,
                false,
                members,
            )
        };
        let remove = || GppGroupMember::new(Some(ALICE.into()), None, GppMemberAction::Remove);
        let gpo = |n: u8| -> SysvolGpo {
            let mut g = SysvolGpo {
                guid: guid(n),
                ..Default::default()
            };
            match n {
                // A adds alice, B removes her, C adds her again.
                1 | 3 => g.gpp_local_groups = vec![item(false, vec![add("alice")])],
                2 => g.gpp_local_groups = vec![item(false, vec![remove()])],
                // D removes every user.
                4 => g.gpp_local_groups = vec![item(true, Vec::new())],
                // E replaces the members (Restricted Groups win over GPP).
                5 => {
                    g.restricted_groups = vec![RestrictedGroupDirective::new(
                        "*S-1-5-32-544",
                        RestrictedGroupOperation::ReplaceMembers,
                        vec!["IT Ops".into()],
                    )]
                }
                // F: alice Member of Administrators, beside E's list.
                _ => {
                    g.restricted_groups = vec![RestrictedGroupDirective::new(
                        "alice",
                        RestrictedGroupOperation::AddToParentGroups,
                        vec!["*S-1-5-32-544".into()],
                    )]
                }
            }
            g
        };
        let admins = |order: &[u8]| -> (Vec<String>, HashSet<String>) {
            let gpos: Vec<SysvolGpo> = order.iter().map(|&n| gpo(n)).collect();
            let refs: Vec<&SysvolGpo> = gpos.iter().collect();
            let merged = sids(&compute_merged(&refs, &FakeResolver, DOMAIN).local_admins);
            let named = attribute(&gpos, &ids(order), &FakeResolver, DOMAIN)
                .entries
                .into_iter()
                .filter(|e| e.group == "administrators")
                .flat_map(|e| e.members)
                .collect();
            (merged, named)
        };
        for order in [
            &[1, 2, 3][..],
            &[1, 2],
            &[1, 4],
            &[4, 1],
            &[1, 5],
            &[1, 5, 6],
            &[6, 1, 2],
            &[2, 6],
        ] {
            let (merged, named) = admins(order);
            for m in &merged {
                assert!(named.contains(m), "{order:?}: {m} merged but not named");
            }
        }
        // Over-naming, by design: B removes alice and D removes every user
        // after A adds her, so the merge has nobody, yet A's own entry still
        // names her. The fix then names A too; removing it there is harmless.
        for order in [&[1, 2][..], &[1, 4]] {
            let (merged, named) = admins(order);
            assert!(merged.is_empty(), "{order:?}");
            assert!(named.contains(ALICE), "{order:?}");
        }
        // E's Restricted Groups list drops A's GPP member from the merge.
        let (merged, named) = admins(&[1, 5]);
        assert_eq!(merged, [OPS]);
        assert!(named.contains(ALICE) && named.contains(OPS));
    }

    #[test]
    fn the_entries_round_trip_through_the_core_parser() {
        let gpo = SysvolGpo {
            guid: guid(1),
            restricted_groups: vec![RestrictedGroupDirective::new(
                "alice",
                RestrictedGroupOperation::AddToParentGroups,
                vec!["*S-1-5-32-555".into()],
            )],
            gpp_local_groups: vec![gpp(true, vec![add("IT Ops")])],
            ..Default::default()
        };
        use super::super::gpp::CheckOut;
        let mut s = super::super::gpp::SidecarOut::new(DOMAIN, "dc01");
        s.checks.gpo_acl = CheckOut::not_collected("password authentication");
        s.checks.logon_script_acl = CheckOut::not_collected("password authentication");
        s.checks.gpp.finish(false, None);
        s.gpo_local_groups = attribute(&[gpo], &ids(&[1]), &FakeResolver, DOMAIN).entries;
        let json = serde_json::to_vec(&s).unwrap();
        let mut notes = Vec::new();
        let back = pathwarden_core::sysvol::Sidecar::parse(&json, &mut notes).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        use pathwarden_core::sysvol::{LocalGroup, LocalSetting};
        let got: Vec<_> = back
            .gpo_local_groups
            .iter()
            .map(|e| {
                (
                    e.setting,
                    e.group,
                    e.item_level_targeting,
                    e.members.clone(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    LocalSetting::RestrictedGroups,
                    LocalGroup::RemoteDesktop,
                    false,
                    vec![ALICE.to_string()]
                ),
                (
                    LocalSetting::Gpp,
                    LocalGroup::Administrators,
                    true,
                    vec![OPS.to_string()]
                ),
            ]
        );
        assert_eq!(
            back.gpo_local_groups[0].object_id.as_deref(),
            Some("00000001-0000-0000-0000-000000000000")
        );
    }
}
