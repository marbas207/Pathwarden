//! End-to-end checks against `testdata/forest`, a two-domain forest
//! (CONTOSO.LOCAL with child CHILD.CONTOSO.LOCAL) with known attack paths:
//!
//! - JDOE -> HELPDESK -GenericAll-> SVC_SQL -AdminTo-> SRV01 -HasSession-> DA_ALICE
//! - SVC_SYNC holds GetChanges directly and GetChangesAll via SYNC_OPERATORS (DCSync)
//! - CAROL -GenericAll-> CHILD_DA, and the child domain trusts up into CONTOSO
//! - Authenticated Users can edit the GPO linked to the WORKSTATIONS OU (not Tier Zero)

use std::path::PathBuf;

use pathwarden_core::analysis;
use pathwarden_core::model::EdgeKind;
use pathwarden_core::{load, AdGraph, IngestStats, LoadOptions, NodeIndex};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest")
}

fn fixture() -> (AdGraph, IngestStats) {
    load(&[fixture_dir()], &LoadOptions::default()).expect("fixture loads")
}

fn node(g: &AdGraph, query: &str) -> NodeIndex {
    match g.find(query).as_slice() {
        [one] => *one,
        other => panic!("expected one match for {query}, got {}", other.len()),
    }
}

fn edges(p: &analysis::AttackPath) -> Vec<EdgeKind> {
    p.steps.iter().map(|s| s.edge).collect()
}

#[test]
fn ingests_all_files_and_skips_deleted_objects() {
    let (g, stats) = fixture();
    assert_eq!(stats.files.len(), 6);
    assert_eq!(stats.deleted_objects, 1);
    assert!(g.find("GONE").is_empty());
    assert_eq!(stats.unmapped_rights.get("SomeFutureRight"), Some(&1));
    assert_eq!(stats.trusts.len(), 3);
}

/// SharpHound writes only the domains it collected: both count, and the
/// trusted FABRIKAM.COM (no domain object, only the trust) does not.
#[test]
fn collected_domains_are_the_domain_objects() {
    let (g, _) = fixture();
    assert_eq!(
        pathwarden_core::analyze::domain_names(&g),
        ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"]
    );
    assert!(pathwarden_core::analyze::trusted_domain_names(&g).is_empty());
}

#[test]
fn identifies_tier_zero() {
    let (g, _) = fixture();
    let tier_zero = [
        "DA_ALICE@CONTOSO.LOCAL",
        "ADMINISTRATOR@CONTOSO.LOCAL",
        "KRBTGT@CONTOSO.LOCAL",
        "DC01.CONTOSO.LOCAL",
        "CONTOSO.LOCAL",
        "CHILD.CONTOSO.LOCAL",
        "CHILD_DA@CHILD.CONTOSO.LOCAL",
        "ENTERPRISE ADMINS@CONTOSO.LOCAL",
        "DEFAULT DOMAIN POLICY@CONTOSO.LOCAL",
        "DEFAULT DOMAIN CONTROLLERS POLICY@CONTOSO.LOCAL",
        // Domain Controllers OU (the group shares its name, so look up by GUID).
        "BBBB0000-0000-0000-0000-000000000002",
    ];
    for name in tier_zero {
        assert!(
            g.node(node(&g, name)).tier_zero,
            "{name} should be Tier Zero"
        );
    }
    for name in [
        "JDOE",
        "BOB",
        "SVC_SQL",
        "SVC_SYNC",
        "SRV01.CONTOSO.LOCAL",
        "WORKSTATION POLICY",
        "CAROL",
    ] {
        assert!(
            !g.node(node(&g, name)).tier_zero,
            "{name} should not be Tier Zero"
        );
    }
}

#[test]
fn finds_multi_hop_path_through_acl_admin_rights_and_sessions() {
    let (g, _) = fixture();
    let p = analysis::path_to_tier_zero(&g, node(&g, "JDOE")).expect("JDOE has a path");
    assert_eq!(
        edges(&p),
        [
            EdgeKind::MemberOf,
            EdgeKind::GenericAll,
            EdgeKind::AdminTo,
            EdgeKind::HasSession
        ]
    );
    assert_eq!(p.target, "DA_ALICE@CONTOSO.LOCAL");
}

#[test]
fn derives_dcsync_from_rights_split_across_group_membership() {
    let (g, _) = fixture();
    let p = analysis::path_to_tier_zero(&g, node(&g, "SVC_SYNC")).expect("SVC_SYNC has a path");
    assert_eq!(edges(&p), [EdgeKind::DcSync]);
    assert_eq!(p.target, "CONTOSO.LOCAL");
}

#[test]
fn child_domain_compromise_reaches_forest_root() {
    let (g, _) = fixture();
    let (carol, root) = (node(&g, "CAROL"), node(&g, "CONTOSO.LOCAL"));
    // An attack path ends at the first Tier Zero object: CAROL's ends at
    // the child's domain admin, whose domain reaches the root over the trust.
    assert!(analysis::shortest_path(&g, carol, root).is_none());
    let p = analysis::path_through_tier_zero(&g, carol, root).expect("path to Tier Zero");
    assert_eq!(edges(&p), [EdgeKind::GenericAll]);
    assert_eq!(p.target, "CHILD_DA@CHILD.CONTOSO.LOCAL");
    let child = node(&g, "CHILD.CONTOSO.LOCAL");
    let trust = analysis::shortest_path(&g, child, root).expect("the child reaches the root");
    assert_eq!(edges(&trust), [EdgeKind::SameForestTrust]);
}

#[test]
fn authenticated_users_membership_is_implicit() {
    let (g, _) = fixture();
    let p =
        analysis::shortest_path(&g, node(&g, "BOB"), node(&g, "WS01.CONTOSO.LOCAL")).expect("path");
    assert_eq!(p.steps[0].to, "AUTHENTICATED USERS@CONTOSO.LOCAL");
    assert_eq!(
        edges(&p),
        [
            EdgeKind::MemberOf,
            EdgeKind::GenericWrite,
            EdgeKind::GpLink,
            EdgeKind::Contains
        ]
    );
    // ...but control of WS01 only yields BOB, so BOB is not exposed.
    assert!(analysis::path_to_tier_zero(&g, node(&g, "BOB")).is_none());
}

#[test]
fn placeholders_get_readable_names() {
    let (g, _) = fixture();
    let ix = g
        .lookup("S-1-5-21-1000-1000-1000-515")
        .expect("Domain Computers referenced");
    assert!(g.node(ix).placeholder);
    assert_eq!(g.node(ix).name, "DOMAIN COMPUTERS@CONTOSO.LOCAL");
}

#[test]
fn exposure_counts_enabled_non_tier_zero_principals() {
    let (g, _) = fixture();
    let r = analysis::exposure(&g, 5, &analysis::Relevance::new(&g, 0, 90));
    let contoso = &r.per_domain["CONTOSO.LOCAL"];
    assert_eq!((contoso.users_exposed, contoso.users_total), (3, 4));
    assert_eq!((contoso.computers_exposed, contoso.computers_total), (2, 3));
    let child = &r.per_domain["CHILD.CONTOSO.LOCAL"];
    assert_eq!((child.users_exposed, child.users_total), (1, 1));
    assert_eq!(
        r.sample_paths[0].steps.len(),
        1,
        "shortest paths come first"
    );
}

#[test]
fn top_choke_point_is_the_domain_admin_session() {
    let (g, _) = fixture();
    let top = &analysis::choke_points(&g, 5, &analysis::Relevance::new(&g, 0, 90))[0];
    assert_eq!(top.edge, EdgeKind::HasSession);
    assert_eq!(top.from, "SRV01.CONTOSO.LOCAL");
    assert_eq!(top.to, "DA_ALICE@CONTOSO.LOCAL");
    assert_eq!(top.principals_cut_off, 3);
}

#[test]
fn extra_tier_zero_from_config() {
    let opts = LoadOptions {
        extra_tier_zero: vec!["srv01.contoso.local".into()],
        ..Default::default()
    };
    let (g, _) = load(&[fixture_dir()], &opts).unwrap();
    assert!(g.node(node(&g, "SRV01.CONTOSO.LOCAL")).tier_zero);
}

#[test]
fn ingests_zip_archives() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("pathwarden-zip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let zip_path = dir.join("collection.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    for entry in std::fs::read_dir(fixture_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&std::fs::read(&path).unwrap()).unwrap();
    }
    zip.finish().unwrap();

    let (g, stats) = load(&[&zip_path], &LoadOptions::default()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(stats.files.len(), 6);
    assert!(analysis::path_to_tier_zero(&g, node(&g, "JDOE")).is_some());
}

#[test]
fn large_top_and_broad_tier_zero_do_not_panic() {
    let (g, _) = fixture();
    // `--top` above the candidate cap used to panic in clamp().
    let points = analysis::choke_points(&g, 100, &analysis::Relevance::new(&g, 0, 90));
    assert!(!points.is_empty());

    // A broad group configured as Tier Zero has an empty path; PW-001 must skip it.
    let opts = LoadOptions {
        extra_tier_zero: vec!["DOMAIN USERS@CONTOSO.LOCAL".into()],
        ..Default::default()
    };
    let (g, stats) = load(&[fixture_dir()], &opts).unwrap();
    let settings = pathwarden_core::findings::RuleSettings::default();
    let ctx = pathwarden_core::findings::Context::new(&g, &stats.trusts, &settings);
    let all = pathwarden_core::findings::evaluate(&ctx, &[]);
    assert!(all
        .iter()
        .all(|f| f.rule != "PW-001" || f.path.as_ref().is_some_and(|p| !p.steps.is_empty())));
}

/// The forest fixture with local groups set by Group Policy, as SharpHound
/// and RustHound-CE write them on OUs and domains (`GPOChanges`): BOB local
/// admin and HELPDESK RDP on the WORKSTATIONS OU's computers (WS01), JDOE
/// local admin on every computer of the domain (SRV01, DC01).
fn fixture_with_gpo_local_groups() -> (AdGraph, IngestStats) {
    gpo_local_groups_fixture(false, false)
}

/// [`fixture_with_gpo_local_groups`], and when `second_gpo` a second GPO
/// linked to the WORKSTATIONS OU that sets nothing (the data can't say which
/// linked GPO produced the OU's `GPOChanges`). When `bob_from_domain`, the
/// domain's GPOs also make BOB local admin on WS01.
fn gpo_local_groups_fixture(second_gpo: bool, bob_from_domain: bool) -> (AdGraph, IngestStats) {
    gpo_local_groups_fixture_with(second_gpo, bob_from_domain, None)
}

/// [`gpo_local_groups_fixture`] with a built-in collector SYSVOL sidecar
/// whose `gpo_local_groups` is `local`; `Some(null)` writes a sidecar
/// without the field, as older versions did.
fn gpo_local_groups_fixture_with(
    second_gpo: bool,
    bob_from_domain: bool,
    local: Option<serde_json::Value>,
) -> (AdGraph, IngestStats) {
    let complete = serde_json::json!({ "status": "complete", "read": 3 });
    gpo_local_groups_run(second_gpo, bob_from_domain, local, true, complete)
}

/// [`gpo_local_groups_fixture_with`], with the OUs' and domain's
/// `GPOChanges` only when `changes`, and `check` as the sidecar's local
/// groups part.
fn gpo_local_groups_run(
    second_gpo: bool,
    bob_from_domain: bool,
    local: Option<serde_json::Value>,
    changes: bool,
    check: serde_json::Value,
) -> (AdGraph, IngestStats) {
    // Tests run in parallel: each call gets its own folder.
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pathwarden-gpolocal-{}-{call}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let r =
        |id: &str, kind: &str| serde_json::json!({ "ObjectIdentifier": id, "ObjectType": kind });
    for entry in std::fs::read_dir(fixture_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if second_gpo && name == "contoso_gpos.json" {
            doc["data"].as_array_mut().unwrap().push(serde_json::json!({
                "ObjectIdentifier": "AAAA0000-0000-0000-0000-000000000002",
                "Properties": {
                    "name": "BROWSER SETTINGS@CONTOSO.LOCAL",
                    "domain": "CONTOSO.LOCAL",
                    "domainsid": "S-1-5-21-1000-1000-1000",
                },
                "Aces": [], "IsDeleted": false,
            }));
        }
        for o in doc["data"].as_array_mut().unwrap() {
            if second_gpo && o["ObjectIdentifier"] == "BBBB0000-0000-0000-0000-000000000001" {
                o["Links"].as_array_mut().unwrap().push(serde_json::json!({
                    "IsEnforced": false, "GUID": "AAAA0000-0000-0000-0000-000000000002",
                }));
            }
            let gpo_changes = match o["ObjectIdentifier"].as_str().unwrap() {
                "BBBB0000-0000-0000-0000-000000000001" => serde_json::json!({
                    "LocalAdmins": [r("S-1-5-21-1000-1000-1000-1104", "User")],
                    "RemoteDesktopUsers": [r("S-1-5-21-1000-1000-1000-1150", "Group")],
                    "DcomUsers": [], "PSRemoteUsers": null,
                    "AffectedComputers": [r("S-1-5-21-1000-1000-1000-1002", "Computer")],
                }),
                "S-1-5-21-1000-1000-1000" if bob_from_domain => serde_json::json!({
                    "LocalAdmins": [
                        r("S-1-5-21-1000-1000-1000-1102", "User"),
                        r("S-1-5-21-1000-1000-1000-1104", "User"),
                    ],
                    "AffectedComputers": [
                        r("S-1-5-21-1000-1000-1000-1001", "Computer"),
                        r("S-1-5-21-1000-1000-1000-1000", "Computer"),
                        r("S-1-5-21-1000-1000-1000-1002", "Computer"),
                    ],
                }),
                "S-1-5-21-1000-1000-1000" => serde_json::json!({
                    "LocalAdmins": [r("S-1-5-21-1000-1000-1000-1102", "User")],
                    "AffectedComputers": [
                        r("S-1-5-21-1000-1000-1000-1001", "Computer"),
                        r("S-1-5-21-1000-1000-1000-1000", "Computer"),
                    ],
                }),
                _ => continue,
            };
            if changes {
                o["GPOChanges"] = gpo_changes;
            }
        }
        std::fs::write(dir.join(name), serde_json::to_string(&doc).unwrap()).unwrap();
    }
    if let Some(local) = local {
        let mut sidecar = serde_json::json!({
            "schema": "pathwarden.sysvol.v1", "domain": "contoso.local", "dc": "dc01.contoso.local",
            "checks": { "gpo_acl": { "status": "complete" }, "logon_script_acl": { "status": "complete" },
                        "gpp": { "status": "complete" },
                        "gpo_local_groups": check },
            "gpos": [], "logon_scripts": [], "gpp_passwords": []
        });
        if !local.is_null() {
            sidecar["gpo_local_groups"] = local;
        }
        std::fs::write(
            dir.join("contoso_pathwarden-sysvol.json"),
            serde_json::to_string(&sidecar).unwrap(),
        )
        .unwrap();
    }
    let loaded = load(&[&dir], &LoadOptions::default()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    loaded
}

const BOB: &str = "S-1-5-21-1000-1000-1000-1104";
const WORKSTATION_POLICY: &str = "AAAA0000-0000-0000-0000-000000000001";
const BROWSER_SETTINGS: &str = "AAAA0000-0000-0000-0000-000000000002";
const DEFAULT_DOMAIN_POLICY: &str = "31B2F340-016D-11D2-945F-00C04FB984F9";
const DC_POLICY: &str = "6AC1786C-016F-11D2-945F-00C04FB984F9";

/// One `gpo_local_groups` entry: `gpo` puts BOB in the local Administrators
/// group through `setting`.
fn bob_admin(gpo: &str, setting: &str, targeted: bool) -> serde_json::Value {
    serde_json::json!({
        "guid": format!("{{{gpo}}}"), "object_id": gpo, "setting": setting,
        "group": "administrators", "item_level_targeting": targeted, "members": [BOB],
    })
}

fn bob_fix(g: &AdGraph) -> String {
    let bob = edge_between(g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    pathwarden_core::remediation::fix_for_edges(g, &[bob])
}

#[test]
fn gpo_local_group_fix_names_the_gpo_the_collector_recorded() {
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        false,
        Some(serde_json::json!([bob_admin(
            BROWSER_SETTINGS,
            "restricted_groups",
            false
        )])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Restricted Groups setting of BROWSER SETTINGS@CONTOSO.LOCAL (linked to \
         WORKSTATIONS@CONTOSO.LOCAL). Removing it on WS01.CONTOSO.LOCAL alone comes back at the next \
         policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_names_both_gpos_that_set_it() {
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        false,
        Some(serde_json::json!([
            bob_admin(WORKSTATION_POLICY, "gpp", false),
            bob_admin(BROWSER_SETTINGS, "restricted_groups", false),
        ])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Restricted Groups setting of BROWSER SETTINGS@CONTOSO.LOCAL and the Local \
         Users and Groups setting of WORKSTATION POLICY@CONTOSO.LOCAL (both linked to \
         WORKSTATIONS@CONTOSO.LOCAL). Removing it on WS01.CONTOSO.LOCAL alone comes back at the next \
         policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_names_both_settings_of_one_gpo() {
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        false,
        Some(serde_json::json!([
            bob_admin(WORKSTATION_POLICY, "gpp", false),
            bob_admin(WORKSTATION_POLICY, "restricted_groups", false),
        ])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Restricted Groups and Local Users and Groups settings of WORKSTATION \
         POLICY@CONTOSO.LOCAL (linked to WORKSTATIONS@CONTOSO.LOCAL). Removing it on \
         WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_marks_item_level_targeting() {
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        false,
        Some(serde_json::json!([bob_admin(
            WORKSTATION_POLICY,
            "gpp",
            true
        )])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Local Users and Groups items with item-level targeting in WORKSTATION \
         POLICY@CONTOSO.LOCAL (linked to WORKSTATIONS@CONTOSO.LOCAL). Removing it on \
         WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );

    // Restricted Groups too, in the same GPO.
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        false,
        Some(serde_json::json!([
            bob_admin(WORKSTATION_POLICY, "gpp", true),
            bob_admin(WORKSTATION_POLICY, "restricted_groups", false),
        ])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Restricted Groups setting of WORKSTATION POLICY@CONTOSO.LOCAL and its \
         Local Users and Groups items with item-level targeting (linked to WORKSTATIONS@CONTOSO.LOCAL). \
         Removing it on WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_with_an_incomplete_record_lists_candidates() {
    let (plain, _) = gpo_local_groups_fixture(true, false);
    let want = bob_fix(&plain);
    let named = bob_admin(WORKSTATION_POLICY, "gpp", false);
    let mut cut = bob_admin(BROWSER_SETTINGS, "restricted_groups", false);
    cut["members_truncated"] = true.into();
    let mut over: Vec<String> = (0..1_001).map(|i| format!("S-1-5-21-9-9-9-{i}")).collect();
    over.push(BOB.into());
    let mut over_cap = bob_admin(BROWSER_SETTINGS, "restricted_groups", false);
    over_cap["members"] = over.into();
    let mut bad_member = bob_admin(BROWSER_SETTINGS, "gpp", false);
    bad_member["members"] = serde_json::json!(["not a sid", BOB]);
    for other in [
        // BROWSER SETTINGS' members were cut by the collector, or are over
        // the cap here, or one was unreadable.
        cut,
        over_cap,
        bad_member,
        // An entry of BROWSER SETTINGS that does not read: a wrong type, or
        // a setting a later version writes.
        serde_json::json!({ "guid": format!("{{{BROWSER_SETTINGS}}}"), "object_id": BROWSER_SETTINGS,
                            "setting": "gpp", "group": "administrators", "members": "S-1-5-21-1" }),
        serde_json::json!({ "guid": format!("{{{BROWSER_SETTINGS}}}"), "object_id": BROWSER_SETTINGS,
                            "setting": "a later setting", "group": "administrators",
                            "members": [BOB] }),
        // One that names no GPO at all: nothing can be named anywhere.
        serde_json::json!(42),
    ] {
        let local = serde_json::json!([named.clone(), other]);
        let (g, stats) = gpo_local_groups_fixture_with(true, false, Some(local.clone()));
        assert_eq!(bob_fix(&g), want, "{local}");
        assert_eq!(stats.sysvol.len(), 1, "the sidecar is read: {local}");
    }
    // An incomplete GPO linked elsewhere doesn't matter here.
    let mut cut = bob_admin(DC_POLICY, "restricted_groups", false);
    cut["members_truncated"] = true.into();
    let (g, _) = gpo_local_groups_fixture_with(true, false, Some(serde_json::json!([named, cut])));
    assert!(bob_fix(&g).contains("the Local Users and Groups setting of WORKSTATION POLICY"));
}

#[test]
fn gpo_local_group_fix_names_one_gpo_at_each_level() {
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        true,
        Some(serde_json::json!([
            bob_admin(DEFAULT_DOMAIN_POLICY, "restricted_groups", false),
            bob_admin(WORKSTATION_POLICY, "gpp", false),
        ])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL \
         from each of these levels: CONTOSO.LOCAL (the Restricted Groups setting of DEFAULT DOMAIN \
         POLICY@CONTOSO.LOCAL) and WORKSTATIONS@CONTOSO.LOCAL (the Local Users and Groups setting of \
         WORKSTATION POLICY@CONTOSO.LOCAL). Remove it from the setting named at each level. Removing \
         it on WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );

    // Only the OU recorded: the domain level keeps its linked GPO.
    let (g, _) = gpo_local_groups_fixture_with(
        true,
        true,
        Some(serde_json::json!([bob_admin(
            WORKSTATION_POLICY,
            "gpp",
            false
        )])),
    );
    assert_eq!(
        bob_fix(&g),
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL \
         from each of these levels: CONTOSO.LOCAL (DEFAULT DOMAIN POLICY@CONTOSO.LOCAL) and \
         WORKSTATIONS@CONTOSO.LOCAL (the Local Users and Groups setting of WORKSTATION \
         POLICY@CONTOSO.LOCAL). Remove it from the Restricted Groups or Local Users and Groups setting \
         at each level. Removing it on WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_without_a_record_is_unchanged() {
    let (plain, _) = gpo_local_groups_fixture(true, false);
    let want = bob_fix(&plain);
    // A sidecar without the field (an older one, or a run as the current
    // Windows user), and one naming a GPO not linked to the OU.
    for local in [
        serde_json::Value::Null,
        serde_json::json!([bob_admin(DC_POLICY, "restricted_groups", false)]),
        serde_json::json!([{ "guid": "not a guid", "object_id": BROWSER_SETTINGS,
                             "setting": "gpp", "group": "administrators", "members": [BOB] }]),
        serde_json::json!([{ "guid": format!("{{{BROWSER_SETTINGS}}}"), "object_id": BROWSER_SETTINGS,
                             "setting": "a later setting", "group": "administrators",
                             "members": [BOB] }]),
    ] {
        let (g, stats) = gpo_local_groups_fixture_with(true, false, Some(local.clone()));
        assert_eq!(bob_fix(&g), want, "{local}");
        assert_eq!(stats.sysvol.len(), 1, "the sidecar is read: {local}");
    }
    let (g, _) = gpo_local_groups_fixture_with(false, true, Some(serde_json::Value::Null));
    let (plain, _) = gpo_local_groups_fixture(false, true);
    assert_eq!(bob_fix(&g), bob_fix(&plain));
}

fn edge_between(g: &AdGraph, from: &str, to: &str, kind: EdgeKind) -> petgraph::graph::EdgeIndex {
    let (a, b) = (node(g, from), node(g, to));
    g.inner()
        .edges_connecting(a, b)
        .find(|e| *e.weight() == kind)
        .map(|e| petgraph::visit::EdgeRef::id(&e))
        .unwrap_or_else(|| panic!("no {kind:?} from {from} to {to}"))
}

#[test]
fn gpo_local_groups_become_edges_to_the_affected_computers() {
    let (g, _) = fixture_with_gpo_local_groups();
    let ou = node(&g, "BBBB0000-0000-0000-0000-000000000001");
    let domain = node(&g, "CONTOSO.LOCAL");

    let bob = edge_between(&g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    assert_eq!(g.gpo_grants(bob), [ou]);
    let rdp = edge_between(&g, "HELPDESK", "WS01.CONTOSO.LOCAL", EdgeKind::CanRdp);
    assert_eq!(g.gpo_grants(rdp), [ou]);
    for computer in ["SRV01.CONTOSO.LOCAL", "DC01.CONTOSO.LOCAL"] {
        let e = edge_between(&g, "JDOE", computer, EdgeKind::AdminTo);
        assert_eq!(g.gpo_grants(e), [domain]);
    }
    // A right read from the computer itself has no GPO behind it.
    let host = edge_between(&g, "SVC_SQL", "SRV01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    assert!(g.gpo_grants(host).is_empty());

    // Local admin on a domain controller set by GPO is a path to the domain.
    let p = analysis::path_to_tier_zero(&g, node(&g, "JDOE")).expect("JDOE has a path");
    assert_eq!(edges(&p), [EdgeKind::AdminTo]);
    assert_eq!(p.target, "DC01.CONTOSO.LOCAL");
}

#[test]
fn gpo_local_group_fix_names_the_gpo_not_the_computer() {
    let (g, _) = fixture_with_gpo_local_groups();
    let bob = edge_between(&g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    let fix = pathwarden_core::remediation::fix_for_edges(&g, &[bob]);
    assert_eq!(
        fix,
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL: \
         remove it from the Restricted Groups or Local Users and Groups setting of WORKSTATION \
         POLICY@CONTOSO.LOCAL (linked to WORKSTATIONS@CONTOSO.LOCAL). Removing it on WS01.CONTOSO.LOCAL \
         alone comes back at the next policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_with_several_linked_gpos_names_them_as_candidates() {
    let (g, _) = gpo_local_groups_fixture(true, false);
    let bob = edge_between(&g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    let fix = pathwarden_core::remediation::fix_for_edges(&g, &[bob]);
    assert_eq!(
        fix,
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL, \
         set by one of the GPOs linked to WORKSTATIONS@CONTOSO.LOCAL: BROWSER SETTINGS@CONTOSO.LOCAL or \
         WORKSTATION POLICY@CONTOSO.LOCAL. Open each in Group Policy Management (Settings: Restricted \
         Groups, or Preferences: Local Users and Groups) to find it, and remove it there. Removing it on \
         WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );
}

#[test]
fn gpo_local_group_fix_from_two_levels_says_remove_it_at_each() {
    let (g, _) = gpo_local_groups_fixture(false, true);
    let bob = edge_between(&g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    let fix = pathwarden_core::remediation::fix_for_edges(&g, &[bob]);
    assert_eq!(
        fix,
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL \
         from each of these levels: CONTOSO.LOCAL (DEFAULT DOMAIN POLICY@CONTOSO.LOCAL) and \
         WORKSTATIONS@CONTOSO.LOCAL (WORKSTATION POLICY@CONTOSO.LOCAL). Remove it from the Restricted \
         Groups or Local Users and Groups setting at each level. Removing it on WS01.CONTOSO.LOCAL \
         alone comes back at the next policy refresh."
    );

    let (g, _) = gpo_local_groups_fixture(true, true);
    let bob = edge_between(&g, "BOB", "WS01.CONTOSO.LOCAL", EdgeKind::AdminTo);
    let fix = pathwarden_core::remediation::fix_for_edges(&g, &[bob]);
    assert_eq!(
        fix,
        "Group Policy puts BOB@CONTOSO.LOCAL in the local Administrators group on WS01.CONTOSO.LOCAL \
         from each of these levels: CONTOSO.LOCAL (DEFAULT DOMAIN POLICY@CONTOSO.LOCAL) and \
         WORKSTATIONS@CONTOSO.LOCAL (one of BROWSER SETTINGS@CONTOSO.LOCAL or WORKSTATION \
         POLICY@CONTOSO.LOCAL). Remove it from the Restricted Groups or Local Users and Groups setting \
         at each level. Where a level lists several GPOs, open each in Group Policy Management \
         (Settings: Restricted Groups, or Preferences: Local Users and Groups) to find it. Removing it \
         on WS01.CONTOSO.LOCAL alone comes back at the next policy refresh."
    );
}

#[test]
fn collections_without_gpo_local_groups_are_unchanged() {
    let (g, _) = fixture();
    for (ix, _) in g.nodes() {
        for e in g.inner().edges(ix) {
            assert!(g.gpo_grants(petgraph::visit::EdgeRef::id(&e)).is_empty());
        }
    }
}

/// The forest fixture with the domains file's `meta.methods` set and, when
/// given, a built-in collector SYSVOL sidecar for CONTOSO.LOCAL whose
/// `gpo_local_groups` check is `check`.
fn fixture_with_gpo_local_record(
    tag: &str,
    methods: u64,
    check: Option<serde_json::Value>,
) -> Vec<pathwarden_core::posture::Completeness> {
    let dir = std::env::temp_dir().join(format!("pathwarden-gporec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(fixture_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "domains" {
            doc["meta"]["methods"] = methods.into();
        }
        std::fs::write(dir.join(name), serde_json::to_string(&doc).unwrap()).unwrap();
    }
    if let Some(check) = check {
        let sidecar = serde_json::json!({
            "schema": "pathwarden.sysvol.v1", "domain": "contoso.local", "dc": "dc01.contoso.local",
            "checks": { "gpo_acl": { "status": "complete" }, "logon_script_acl": { "status": "complete" },
                        "gpp": { "status": "complete" }, "gpo_local_groups": check },
            "gpos": [], "logon_scripts": [], "gpp_passwords": []
        });
        std::fs::write(
            dir.join("contoso_pathwarden-sysvol.json"),
            serde_json::to_string(&sidecar).unwrap(),
        )
        .unwrap();
    }
    let (g, _) = load(&[&dir], &LoadOptions::default()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    pathwarden_core::posture::completeness(&g, 1_791_417_600)
}

fn gpo_local(c: &[pathwarden_core::posture::Completeness], domain: &str) -> Option<bool> {
    c.iter()
        .find(|d| d.domain == domain)
        .unwrap_or_else(|| panic!("{domain} in completeness"))
        .gpo_local_groups
}

#[test]
fn gpo_local_groups_completeness_from_sharphound_methods() {
    // RustHound-CE (and this fixture) write methods 0: not recorded.
    let c = fixture_with_gpo_local_record("none", 0, None);
    assert_eq!(gpo_local(&c, "CONTOSO.LOCAL"), None);
    // SharpHound All (GPOLocalGroup is 1 << 2).
    let c = fixture_with_gpo_local_record("all", 521_215, None);
    assert_eq!(gpo_local(&c, "CONTOSO.LOCAL"), Some(true));
    // SharpHound without GPOLocalGroup.
    let c = fixture_with_gpo_local_record("nogpo", 521_215 & !4, None);
    assert_eq!(gpo_local(&c, "CONTOSO.LOCAL"), Some(false));
}

#[test]
fn gpo_local_groups_completeness_from_the_builtin_sidecar() {
    let c = fixture_with_gpo_local_record(
        "current-user",
        0,
        Some(
            serde_json::json!({ "status": "not_collected", "reason": "not read as the current Windows user" }),
        ),
    );
    assert_eq!(gpo_local(&c, "CONTOSO.LOCAL"), Some(false));
    let c = fixture_with_gpo_local_record(
        "password",
        0,
        Some(serde_json::json!({ "status": "complete", "read": 3 })),
    );
    assert_eq!(gpo_local(&c, "CONTOSO.LOCAL"), Some(true));
}

/// A right a linked GPO grants rests on the sidecar's GPO local
/// groups part. A later run that read that part only partly (a GptTmpl.inf
/// it couldn't read) and so lacks the right holds the finding; one that
/// read it whole and found the right gone fixes it.
#[test]
fn gpo_local_group_findings_are_held_while_the_part_is_partial() {
    use pathwarden_core::findings::{self, Context, RuleSettings};
    use pathwarden_core::opengraph::coverage::RunSources;
    use pathwarden_core::state::{self, ResolveScope};
    let part = "SYSVOL GPO local groups (CONTOSO.LOCAL)";
    let run = |(g, stats): &(AdGraph, IngestStats)| {
        let settings = RuleSettings::default();
        findings::evaluate(&Context::new(g, &stats.trusts, &settings), &[])
    };
    let complete = serde_json::json!({ "status": "complete", "read": 3 });
    let before = gpo_local_groups_run(
        false,
        false,
        Some(serde_json::json!([])),
        true,
        complete.clone(),
    );
    let first = run(&before);
    let resting: Vec<&findings::Finding> = first
        .iter()
        .filter(|f| f.sources.iter().any(|s| s == part))
        .collect();
    assert!(!resting.is_empty(), "no finding cites {part}");
    let keys = RunSources::from_analysis(&before.0, &before.1).keys();
    assert!(
        keys.contains(&pathwarden_core::opengraph::source_key(part)),
        "{keys:?}"
    );
    let prev = state::reconcile(&state::FindingsState::default(), &first, 1, false).state;
    let fps: Vec<&str> = resting.iter().map(|f| f.fingerprint.as_str()).collect();

    // Partly read: GPOChanges lost, the findings held.
    let partial = serde_json::json!({
        "status": "partial", "read": 2, "failed": 1,
        "reason": "1 item could not be read, first: GptTmpl.inf: STATUS_ACCESS_DENIED"
    });
    let after = gpo_local_groups_run(false, false, Some(serde_json::json!([])), false, partial);
    let second = run(&after);
    assert!(second
        .iter()
        .all(|f| !fps.contains(&f.fingerprint.as_str())));
    let scope = ResolveScope::everything()
        .with_sources(RunSources::from_analysis(&after.0, &after.1), &keys);
    let r = state::reconcile_scoped(&prev, &second, 2, false, &scope);
    for fp in &fps {
        assert!(
            !r.resolved.iter().any(|x| x.fingerprint == *fp),
            "{fp} resolved while the part was partial"
        );
    }
    assert!(r.counts.held >= fps.len(), "held {}", r.counts.held);

    // Read whole and gone: fixed.
    let clean = gpo_local_groups_run(false, false, Some(serde_json::json!([])), false, complete);
    let third = run(&clean);
    let scope = ResolveScope::everything()
        .with_sources(RunSources::from_analysis(&clean.0, &clean.1), &keys);
    let r = state::reconcile_scoped(&prev, &third, 3, false, &scope);
    for fp in &fps {
        assert!(
            r.resolved.iter().any(|x| x.fingerprint == *fp),
            "{fp} not resolved"
        );
    }
}
