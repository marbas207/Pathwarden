//! Management planes against `testdata/mgmt`: an Entra Connect
//! server named by its MSOL_ account, the Seamless SSO account, an SCCM site
//! server with Full Control of System Management, a SCOM management server
//! whose AD integration group has DC01 as an agent, a VMM server found by
//! SPN, and objects named after backup, WSUS and ESXi products. The
//! directory part added a Hyper-V host (HV01) and a SCOM Health Service server (MON01)
//! found by SPN, the Entra Connect sync service account (ADSYNCMSA1A2B3$,
//! read by AADC01), ADSYNCADMINS with DAVE in it, an ESXi host (ESX01) next
//! to ESX ADMINS, and a Seamless SSO key 31 days old. Variants of the
//! fixture (written under the test target's temporary folder) cover the
//! rest: SCCM clients, SCOM agents, and the ESX Admins cases.

use std::collections::BTreeMap;
use std::path::PathBuf;

use pathwarden_core::findings::{self, Category, Context, Finding, RuleSettings, Severity};
use pathwarden_core::model::EdgeKind;
use pathwarden_core::{analysis, load, mgmt, remediation, AdGraph, IngestStats, LoadOptions};
use petgraph::visit::EdgeRef;
use serde_json::{json, Value};

const NOW: i64 = 1_791_417_600;

fn dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn load_with(not_tier_zero: &[&str]) -> (AdGraph, IngestStats) {
    let opts = LoadOptions {
        not_tier_zero_planes: not_tier_zero.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    load(&[dir("mgmt")], &opts).expect("fixture loads")
}

fn run(g: &AdGraph, stats: &IngestStats) -> Vec<Finding> {
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    findings::evaluate(&Context::new(g, &stats.trusts, &settings), &[])
}

fn node<'a>(g: &'a AdGraph, name: &str) -> &'a pathwarden_core::model::Node {
    g.node(g.find(name)[0])
}

fn rule<'a>(all: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    all.iter().filter(|f| f.rule == id).collect()
}

fn titles(fs: &[&Finding]) -> Vec<String> {
    let mut t: Vec<String> = fs.iter().map(|f| f.title.clone()).collect();
    t.sort();
    t
}

#[test]
fn strong_and_linked_planes_become_tier_zero() {
    let (g, _) = load_with(&[]);
    for name in [
        "MSOL_1A2B3C4D5E6F@MGMT.LOCAL",
        "AADC01.MGMT.LOCAL",
        "AZUREADSSOACC.MGMT.LOCAL",
        "SCOM01.MGMT.LOCAL",
        "ADSYNCADMINS@MGMT.LOCAL",
    ] {
        let n = node(&g, name);
        assert!(n.tier_zero, "{name} should be Tier Zero");
        assert!(mgmt::is_plane_reason(n), "{name}: {:?}", n.tier_zero_reason);
    }
    assert!(node(&g, "AADC01.MGMT.LOCAL")
        .tier_zero_reason
        .as_deref()
        .unwrap()
        .contains("MSOL_1A2B3C4D5E6F@MGMT.LOCAL"));
    // Inferred without a link to Tier Zero, or names only: not Tier Zero.
    for name in [
        "CM01.MGMT.LOCAL",
        "VMM01.MGMT.LOCAL",
        "VEEAM01.MGMT.LOCAL",
        "WS01.MGMT.LOCAL",
        "MSOL_0B5D1E7E0000@MGMT.LOCAL",
        "SVC_WSUS@MGMT.LOCAL",
        "HV01.MGMT.LOCAL",
        "MON01.MGMT.LOCAL",
        "ESX01.MGMT.LOCAL",
        "ESX ADMINS@MGMT.LOCAL",
        "ADSYNCMSA1A2B3$@MGMT.LOCAL",
    ] {
        assert!(!node(&g, name).tier_zero, "{name} should not be Tier Zero");
    }
    // SCOM01 manages DC01 (an agent in its AD integration group), not WS01.
    let manages: Vec<(String, String)> = g
        .inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::ManagesHost)
        .map(|e| {
            (
                g.node(e.source()).name.clone(),
                g.node(e.target()).name.clone(),
            )
        })
        .collect();
    assert_eq!(
        manages,
        [(
            "SCOM01.MGMT.LOCAL".to_string(),
            "DC01.MGMT.LOCAL".to_string()
        )]
    );
}

#[test]
fn findings_on_management_planes() {
    let (g, stats) = load_with(&[]);
    let all = run(&g, &stats);

    // The sync account is Tier Zero now: its DCSync is by design, and the
    // server that holds its password is what PW-025 reports.
    assert!(
        rule(&all, "PW-002").is_empty(),
        "{:?}",
        titles(&rule(&all, "PW-002"))
    );

    let pw025 = rule(&all, "PW-025");
    assert_eq!(
        titles(&pw025),
        [
            "AADC01.MGMT.LOCAL (Entra Connect server) controls Tier Zero",
            "SCOM01.MGMT.LOCAL (SCOM server) controls Tier Zero",
        ]
    );
    for f in &pw025 {
        assert_eq!(f.category, Category::AttackPath);
        assert!(f.severity >= Severity::High);
    }
    let scom = pw025
        .iter()
        .find(|f| f.title.starts_with("SCOM01"))
        .unwrap();
    let path = scom.path.as_ref().expect("a ManagesHost path");
    assert_eq!(path.steps.len(), 1);
    assert_eq!(path.steps[0].edge, EdgeKind::ManagesHost);
    // BOB is local admin on SCOM01, so he can use it.
    assert!(scom.exposure.as_ref().unwrap().principals >= 1);

    // Existing rules now cover the classified systems.
    let pw003 = titles(&rule(&all, "PW-003"));
    for t in [
        "ALICE@MGMT.LOCAL has AdminTo on AADC01.MGMT.LOCAL",
        "BOB@MGMT.LOCAL has AdminTo on SCOM01.MGMT.LOCAL",
        "CAROL@MGMT.LOCAL has GenericAll on AZUREADSSOACC.MGMT.LOCAL",
    ] {
        assert!(pw003.iter().any(|x| x == t), "missing {t} in {pw003:?}");
    }

    let pw028 = rule(&all, "PW-028");
    for f in &pw028 {
        assert_eq!(f.category, Category::Hygiene);
    }
    let inferred: Vec<&&Finding> = pw028
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();
    assert_eq!(
        titles(&inferred.into_iter().copied().collect::<Vec<_>>()),
        [
            "CM01.MGMT.LOCAL looks like an SCCM site server",
            "Hyper-V hosts in MGMT.LOCAL",
            "SCOM Health Service hosts in MGMT.LOCAL",
            "VMM01.MGMT.LOCAL looks like a Virtual Machine Manager server or account",
        ]
    );
    // No Tier Zero host is a client or agent with an unknown server.
    assert!(
        pw028.iter().all(|f| f.severity != Severity::High),
        "{:?}",
        titles(&pw028)
    );
    let by_name: Vec<&Finding> = pw028
        .iter()
        .copied()
        .filter(|f| f.severity == Severity::Low)
        .collect();
    assert_eq!(
        titles(&by_name),
        [
            "Possible Entra Connect systems in MGMT.LOCAL, by name",
            "Possible SCCM systems in MGMT.LOCAL, by name",
            "Possible WSUS systems in MGMT.LOCAL, by name",
            "Possible backup systems in MGMT.LOCAL, by name",
            "Possible virtualization systems in MGMT.LOCAL, by name",
        ]
    );
    // The SCCM group is listed, but CM01 is reported once, as inferred; the
    // SCOM agent group and its workstation are not "SCOM systems".
    let names: Vec<&str> = by_name
        .iter()
        .flat_map(|f| f.affected.iter().map(|a| a.name.as_str()))
        .collect();
    assert!(names.contains(&"SCCM SITE SERVERS@MGMT.LOCAL"));
    assert!(names.contains(&"ESX01.MGMT.LOCAL"));
    // Found by structure, so not "by name": PW-029 reports ESX Admins, and
    // the Hyper-V finding lists HV01.
    for n in [
        "CM01.MGMT.LOCAL",
        "ESX ADMINS@MGMT.LOCAL",
        "HV01.MGMT.LOCAL",
        "MON01.MGMT.LOCAL",
        "ADSYNCMSA1A2B3$@MGMT.LOCAL",
    ] {
        assert!(!names.contains(&n), "{n} in {names:?}");
    }
    assert!(!names
        .iter()
        .any(|n| n.contains("SCOM") || n.starts_with("WS01")));
}

#[test]
fn a_plane_configured_as_not_tier_zero_is_a_path() {
    let (g, stats) = load_with(&["SCOM01.MGMT.LOCAL"]);
    assert!(!node(&g, "SCOM01.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("SCOM01"))
        .expect("PW-025 still reports the server");
    assert!(f.summary.contains("not Tier Zero in the settings"));
    // BOB -> AdminTo -> SCOM01 -> ManagesHost -> DC01 is a path to Tier Zero
    // now, and the plan cuts it.
    let bob = g.find("BOB@MGMT.LOCAL")[0];
    let reach = analysis::reach_targets(&g, analysis::tier_zero(&g), None);
    assert!(reach.reaches(bob));
    let plan = remediation::plan(&g, &pathwarden_core::analysis::Relevance::new(&g, NOW, 90));
    assert!(
        plan.fixes
            .iter()
            .any(|s| s.to.starts_with("SCOM01") || s.from.starts_with("SCOM01")),
        "{:?}",
        plan.fixes
            .iter()
            .map(|s| (&s.from, &s.to))
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_unidentified_sync_server_is_reported_on_the_account() {
    let (g, stats) = load_with(&["AADC01.MGMT.LOCAL"]);
    assert!(!node(&g, "AADC01.MGMT.LOCAL").tier_zero);
    assert!(node(&g, "MSOL_1A2B3C4D5E6F@MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let pw025 = titles(&rule(&all, "PW-025"));
    assert!(
        pw025.contains(
            &"The Entra Connect server of MSOL_1A2B3C4D5E6F@MGMT.LOCAL is not identified"
                .to_string()
        ),
        "{pw025:?}"
    );
}

#[test]
fn other_fixtures_have_no_management_planes() {
    let demo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../demo");
    // (inputs read together, whether its known Entra Connect sync account
    // and server may be detected)
    let mut inputs: Vec<(Vec<PathBuf>, bool)> = [
        "forest",
        "broad",
        "adcs",
        "sdprop",
        "opengraph/ad",
        "hostile",
        "trusts",
        "rusthound",
        // A SYSVOL sidecar without registry policy or SCCM site objects.
        "sysvol",
    ]
    .iter()
    .map(|n| (vec![dir(n)], false))
    .collect();
    inputs.push((vec![demo], false));
    inputs.push((vec![dir("entra/ad"), dir("entra/azurehound")], true));
    for pack in ["configmanbearpig", "configmanbearpig_other"] {
        inputs.push((
            vec![dir("opengraph/ad"), dir(&format!("opengraph/{pack}"))],
            false,
        ));
    }
    // Lab data that isn't in the repository, when present (GOAD).
    if let Ok(extra) = std::env::var("PATHWARDEN_MGMT_EXTRA") {
        inputs.extend(std::env::split_paths(&extra).map(|p| (vec![p], false)));
    }
    for (input, entra) in inputs {
        let name = format!("{input:?}");
        let (g, stats) = load(&input, &LoadOptions::default()).unwrap();
        let detections = mgmt::detect(&g);
        // The Entra Connect sync account and the server its description
        // names: what the directory part already found there.
        let known = |d: &mgmt::Detection| {
            entra
                && d.plane == mgmt::Plane::EntraConnect
                && matches!(d.role, mgmt::Role::Account | mgmt::Role::Server)
                && !d.evidence.contains("sync service account")
        };
        let found: Vec<String> = detections
            .iter()
            .filter(|d| !known(d))
            .map(|d| format!("{} ({:?})", g.node(d.object).name, d.plane))
            .collect();
        assert!(found.is_empty(), "{name}: {found:?}");
        // Tier Zero is what it was without them.
        let allowed: Vec<_> = detections
            .iter()
            .filter(|d| known(d))
            .map(|d| d.object)
            .collect();
        let planes: Vec<&str> = g
            .nodes()
            .filter(|(ix, n)| mgmt::is_plane_reason(n) && !allowed.contains(ix))
            .map(|(_, n)| n.name.as_str())
            .collect();
        assert!(planes.is_empty(), "{name}: {planes:?}");
        let all = run(&g, &stats);
        let new_rules: Vec<&str> = all
            .iter()
            .filter(|f| ["PW-029", "PW-037", "PW-038"].contains(&f.rule))
            .map(|f| f.title.as_str())
            .collect();
        assert!(new_rules.is_empty(), "{name}: {new_rules:?}");
    }
}

// ---- More detection from the data already collected ----

const DOMAIN_SID: &str = "S-1-5-21-7000-7000-7000";
const KINDS: &[&str] = &["computers", "containers", "domains", "groups", "users"];

/// The fixture's files, by kind ("computers", ...), to change for a variant.
struct Files(BTreeMap<&'static str, Value>);

impl Files {
    fn data(&mut self, kind: &str) -> &mut Vec<Value> {
        self.0
            .get_mut(kind)
            .unwrap()
            .get_mut("data")
            .unwrap()
            .as_array_mut()
            .unwrap()
    }

    /// The object named `name` (its `Properties.name`).
    fn obj(&mut self, kind: &str, name: &str) -> &mut Value {
        self.data(kind)
            .iter_mut()
            .find(|o| o["Properties"]["name"] == name)
            .unwrap_or_else(|| panic!("no {name} in {kind}"))
    }

    fn remove(&mut self, kind: &str, name: &str) {
        self.data(kind).retain(|o| o["Properties"]["name"] != name);
    }

    fn add_spn(&mut self, computer: &str, spn: &str) {
        self.obj("computers", computer)["Properties"]["serviceprincipalnames"]
            .as_array_mut()
            .unwrap()
            .push(spn.into());
    }

    fn add_computer(&mut self, rid: u32, name: &str) {
        self.data("computers").push(json!({
            "ObjectIdentifier": format!("{DOMAIN_SID}-{rid}"),
            "PrimaryGroupSID": format!("{DOMAIN_SID}-515"),
            "Properties": {
                "name": name,
                "domain": "MGMT.LOCAL",
                "domainsid": DOMAIN_SID,
                "enabled": true,
                "isdc": false,
                "serviceprincipalnames": []
            },
            "IsDC": false,
            "DomainSID": DOMAIN_SID,
            "LocalGroups": [],
            "Sessions": { "Results": [], "Collected": true, "FailureReason": null },
            "Aces": [],
            "IsDeleted": false
        }));
    }

    fn add_member(&mut self, group: &str, rid: u32, kind: &str) {
        self.obj("groups", group)["Members"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "ObjectIdentifier": format!("{DOMAIN_SID}-{rid}"), "ObjectType": kind }));
    }

    fn set_members(&mut self, group: &str, rids: &[(u32, &str)]) {
        self.obj("groups", group)["Members"] = rids
            .iter()
            .map(|(rid, kind)| {
                json!({ "ObjectIdentifier": format!("{DOMAIN_SID}-{rid}"), "ObjectType": kind })
            })
            .collect();
    }
}

/// `testdata/mgmt` changed by `edit`, written under the test target's
/// temporary folder as `name`, and loaded.
fn variant(
    name: &str,
    not_tier_zero: &[&str],
    edit: impl FnOnce(&mut Files),
) -> (AdGraph, IngestStats) {
    variant_with(name, not_tier_zero, edit, Vec::new())
}

/// [`variant`], with `extra` files (name, JSON) written next to it.
fn variant_with(
    name: &str,
    not_tier_zero: &[&str],
    edit: impl FnOnce(&mut Files),
    extra: Vec<(&str, Value)>,
) -> (AdGraph, IngestStats) {
    variant_at(name, not_tier_zero, edit, extra, None)
}

/// [`variant_with`], analyzed at `now` (the wall clock when `None`).
fn variant_at(
    name: &str,
    not_tier_zero: &[&str],
    edit: impl FnOnce(&mut Files),
    extra: Vec<(&str, Value)>,
    now: Option<i64>,
) -> (AdGraph, IngestStats) {
    let mut files = Files(
        KINDS
            .iter()
            .map(|k| {
                let text =
                    std::fs::read_to_string(dir("mgmt").join(format!("mgmt_{k}.json"))).unwrap();
                (*k, serde_json::from_str(&text).unwrap())
            })
            .collect(),
    );
    edit(&mut files);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("mgmt-variants")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    for (k, mut doc) in files.0 {
        let count = doc["data"].as_array().unwrap().len();
        doc["meta"]["count"] = count.into();
        std::fs::write(
            out.join(format!("mgmt_{k}.json")),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();
    }
    for (file, doc) in extra {
        std::fs::write(out.join(file), serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    }
    let opts = LoadOptions {
        not_tier_zero_planes: not_tier_zero.iter().map(|s| s.to_string()).collect(),
        now,
        ..Default::default()
    };
    load(&[out], &opts).expect("variant loads")
}

fn manages_host(g: &AdGraph) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = g
        .inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::ManagesHost)
        .map(|e| {
            (
                g.node(e.source()).name.clone(),
                g.node(e.target()).name.clone(),
            )
        })
        .collect();
    v.sort();
    v
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

#[test]
fn an_sccm_client_dc_with_one_site_server_makes_it_tier_zero() {
    let (g, stats) = variant("sccm-one", &[], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local")
    });
    let cm = node(&g, "CM01.MGMT.LOCAL");
    assert!(cm.tier_zero);
    let reason = cm.tier_zero_reason.as_deref().unwrap();
    assert!(reason.starts_with(mgmt::REASON_PREFIX), "{reason}");
    assert!(reason.contains("DC01.MGMT.LOCAL"), "{reason}");
    assert_eq!(
        manages_host(&g),
        [
            pair("CM01.MGMT.LOCAL", "DC01.MGMT.LOCAL"),
            pair("SCOM01.MGMT.LOCAL", "DC01.MGMT.LOCAL"),
        ]
    );
    let all = run(&g, &stats);
    let pw025 = rule(&all, "PW-025");
    let f = pw025
        .iter()
        .find(|f| f.title == "CM01.MGMT.LOCAL (SCCM server) controls Tier Zero")
        .unwrap_or_else(|| panic!("{:?}", titles(&pw025)));
    assert!(f.summary.contains("CmRcService/"), "{}", f.summary);
    assert!(f.summary.contains("inferred"), "{}", f.summary);
    assert_eq!(
        f.path.as_ref().unwrap().steps[0].edge,
        EdgeKind::ManagesHost
    );
    // Not a review any more.
    let pw028 = titles(&rule(&all, "PW-028"));
    assert!(!pw028.iter().any(|t| t.starts_with("CM01")), "{pw028:?}");
    assert!(
        !pw028.iter().any(|t| t.contains("SCCM client")),
        "{pw028:?}"
    );
}

#[test]
fn an_sccm_client_dc_with_two_site_servers_is_reviewed() {
    let (g, stats) = variant("sccm-two", &[], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local");
        f.add_computer(1140, "CM02.MGMT.LOCAL");
        f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
    });
    for name in ["CM01.MGMT.LOCAL", "CM02.MGMT.LOCAL"] {
        assert!(!node(&g, name).tier_zero, "{name}");
    }
    assert_eq!(
        manages_host(&g),
        [pair("SCOM01.MGMT.LOCAL", "DC01.MGMT.LOCAL")]
    );
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| f.title == "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown")
        .expect("a review of the client");
    assert_eq!(f.rule, "PW-028");
    assert_eq!(f.severity, Severity::High);
    assert!(f.summary.contains("2 site servers"), "{}", f.summary);
    let affected: Vec<&str> = f.affected.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        affected,
        ["DC01.MGMT.LOCAL", "CM01.MGMT.LOCAL", "CM02.MGMT.LOCAL"]
    );
}

#[test]
fn an_sccm_client_dc_without_a_site_server_is_reviewed() {
    let (g, stats) = variant("sccm-none", &[], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "CMRCSERVICE/DC01");
        f.obj("containers", "SYSTEM MANAGEMENT@MGMT.LOCAL")["Aces"] = json!([]);
    });
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| f.title == "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown")
        .expect("a review of the client");
    assert_eq!(f.severity, Severity::High);
    assert!(f.summary.contains("no SCCM site server"), "{}", f.summary);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
}

#[test]
fn client_spns_on_other_computers_change_nothing() {
    let (base, base_stats) = load_with(&[]);
    let (g, stats) = variant("spn-non-dc", &[], |f| {
        f.add_spn("WS01.MGMT.LOCAL", "CmRcService/ws01.mgmt.local");
        f.add_spn("WS01.MGMT.LOCAL", "MSOMHSvc/ws01.mgmt.local");
    });
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert_eq!(manages_host(&g), manages_host(&base));
    let fps = |all: &[Finding]| -> Vec<String> {
        let mut v: Vec<String> = all
            .iter()
            .filter(|f| f.rule == "PW-025" || f.severity == Severity::High && f.rule == "PW-028")
            .map(|f| f.fingerprint.clone())
            .collect();
        v.sort();
        v
    };
    assert_eq!(fps(&run(&g, &stats)), fps(&run(&base, &base_stats)));
    // WS01 has a Health Service SPN: listed with MON01, in one finding.
    let all = run(&g, &stats);
    let health: Vec<&Finding> = all
        .iter()
        .filter(|f| f.title == "SCOM Health Service hosts in MGMT.LOCAL")
        .collect();
    assert_eq!(health.len(), 1);
    let listed: Vec<&str> = health[0].affected.iter().map(|a| a.name.as_str()).collect();
    assert!(
        listed.contains(&"WS01.MGMT.LOCAL") && listed.contains(&"MON01.MGMT.LOCAL"),
        "{listed:?}"
    );
}

#[test]
fn an_sccm_client_review_closes_when_every_site_server_is_tier_zero() {
    let edit = |f: &mut Files| {
        f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local");
        f.add_computer(1140, "CM02.MGMT.LOCAL");
        f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
    };
    let (g, stats) = variant("sccm-two-declared", &[], edit);
    let mut g = g;
    pathwarden_core::tierzero::mark(
        &mut g,
        &["CM01.MGMT.LOCAL".to_string(), "CM02.MGMT.LOCAL".to_string()],
    );
    assert!(node(&g, "CM02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    assert!(
        !all.iter().any(|f| f.title.contains("is an SCCM client")),
        "{:?}",
        titles(&rule(&all, "PW-028"))
    );
}

#[test]
fn an_sccm_site_server_configured_as_not_tier_zero_is_a_path() {
    let (g, stats) = variant("sccm-not-tier-zero", &["CM01.MGMT.LOCAL"], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local")
    });
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert!(manages_host(&g).contains(&pair("CM01.MGMT.LOCAL", "DC01.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("CM01"))
        .expect("PW-025 still reports the site server");
    assert!(
        f.summary.contains("not Tier Zero in the settings"),
        "{}",
        f.summary
    );
}

#[test]
fn a_scom_agent_dc_without_a_known_server_is_reviewed() {
    // In the AD integration group, the server is known: no review.
    let (g, stats) = variant("scom-known", &[], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "MSOMHSvc/dc01.mgmt.local")
    });
    let all = run(&g, &stats);
    assert!(!all.iter().any(|f| f.title.contains("SCOM agent")));
    assert!(node(&g, "SCOM01.MGMT.LOCAL").tier_zero);

    // Out of the group: an agent with an unknown server.
    let (g, stats) = variant("scom-unknown", &[], |f| {
        f.add_spn("DC01.MGMT.LOCAL", "MSOMHSvc/dc01.mgmt.local");
        f.set_members(
            "MG1_SCOM01_PRIMARYSG_412345@MGMT.LOCAL",
            &[(1107, "Computer")],
        );
    });
    assert!(!node(&g, "SCOM01.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| {
            f.title == "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown"
        })
        .expect("a review of the agent");
    assert_eq!((f.rule, f.severity), ("PW-028", Severity::High));
    assert!(f.summary.contains("MSOMHSvc/"), "{}", f.summary);
}

#[test]
fn hyper_v_hosts_are_one_review_per_domain() {
    let (g, stats) = variant("hyper-v", &[], |f| {
        f.add_computer(1141, "HV02.MGMT.LOCAL");
        f.add_spn(
            "HV02.MGMT.LOCAL",
            "Microsoft Virtual Console Service/hv02.mgmt.local",
        );
    });
    let all = run(&g, &stats);
    let hv: Vec<&Finding> = all
        .iter()
        .filter(|f| f.title == "Hyper-V hosts in MGMT.LOCAL")
        .collect();
    assert_eq!(hv.len(), 1);
    let f = hv[0];
    assert_eq!((f.rule, f.severity), ("PW-028", Severity::Medium));
    let affected: Vec<(&str, &str)> = f
        .affected
        .iter()
        .map(|a| (a.name.as_str(), a.detail.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(affected.len(), 2);
    assert!(affected
        .iter()
        .any(|(n, d)| *n == "HV01.MGMT.LOCAL" && d.contains("failover cluster node")));
    assert!(affected
        .iter()
        .any(|(n, d)| *n == "HV02.MGMT.LOCAL" && !d.contains("cluster")));
    assert!(!node(&g, "HV01.MGMT.LOCAL").tier_zero);
}

fn pw029(g: &AdGraph, stats: &IngestStats) -> Vec<(String, Severity)> {
    let mut v: Vec<(String, Severity)> = run(g, stats)
        .into_iter()
        .filter(|f| f.rule == "PW-029")
        .map(|f| (f.title, f.severity))
        .collect();
    v.sort();
    v
}

#[test]
fn esx_admins_with_esxi_evidence() {
    let (g, stats) = load_with(&[]);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-029");
    assert_eq!(f.len(), 1, "{:?}", titles(&f));
    let f = f[0];
    assert_eq!(
        f.title,
        "ESX ADMINS@MGMT.LOCAL makes accounts outside Tier Zero ESXi administrators"
    );
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, Category::Hygiene);
    assert!(f.summary.contains("CVE-2024-37085"));
    assert!(f.summary.contains("BOB@MGMT.LOCAL"), "{}", f.summary);
    assert!(f.summary.contains("ESX01.MGMT.LOCAL"), "{}", f.summary);
    assert!(f.affected.iter().any(|a| a.name == "ESX01.MGMT.LOCAL"
        && a.detail.as_deref() == Some("operating system VMware ESXi 8.0.2")));
}

#[test]
fn esx_admins_without_esxi_evidence_is_low() {
    let (g, stats) = variant("esx-no-evidence", &[], |f| {
        f.remove("computers", "ESX01.MGMT.LOCAL")
    });
    assert_eq!(
        pw029(&g, &stats),
        [(
            "ESX ADMINS@MGMT.LOCAL makes accounts outside Tier Zero ESXi administrators"
                .to_string(),
            Severity::Low
        )]
    );
}

#[test]
fn a_missing_esx_admins_group_matters_only_with_esxi_evidence() {
    let (g, stats) = variant("esx-missing", &[], |f| {
        f.remove("groups", "ESX ADMINS@MGMT.LOCAL")
    });
    assert_eq!(
        pw029(&g, &stats),
        [(
            "MGMT.LOCAL shows signs of ESXi or vCenter but has no ESX Admins group".to_string(),
            Severity::Medium
        )]
    );
    let (g, stats) = variant("esx-missing-no-evidence", &[], |f| {
        f.remove("groups", "ESX ADMINS@MGMT.LOCAL");
        f.remove("computers", "ESX01.MGMT.LOCAL");
    });
    assert!(pw029(&g, &stats).is_empty());
}

#[test]
fn esx_admins_control_and_tier_zero_members() {
    // Only a Tier Zero member, and nobody else controls it: nothing.
    let (g, stats) = variant("esx-tier-zero-only", &[], |f| {
        f.set_members("ESX ADMINS@MGMT.LOCAL", &[(500, "User")]);
    });
    assert!(pw029(&g, &stats).is_empty());

    // No members, but CAROL can change it.
    let (g, stats) = variant("esx-controlled", &[], |f| {
        f.set_members("ESX ADMINS@MGMT.LOCAL", &[]);
        f.obj("groups", "ESX ADMINS@MGMT.LOCAL")["Aces"] = json!([{
            "PrincipalSID": format!("{DOMAIN_SID}-1112"),
            "PrincipalType": "User",
            "RightName": "GenericAll",
            "IsInherited": false
        }]);
    });
    let all = run(&g, &stats);
    let f = rule(&all, "PW-029");
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::High);
    assert!(f[0]
        .affected
        .iter()
        .any(|a| a.name == "CAROL@MGMT.LOCAL" && a.detail.as_deref() == Some("GenericAll")));
    assert!(
        !f[0].summary.contains("Members outside"),
        "{}",
        f[0].summary
    );
}

#[test]
fn seamless_sso_key_age() {
    let (g, stats) = load_with(&[]);
    let all = run(&g, &stats);
    assert_eq!(
        titles(&rule(&all, "PW-037")),
        ["The Kerberos key of AZUREADSSOACC.MGMT.LOCAL is 31 days old"]
    );
    let f = rule(&all, "PW-037")[0];
    assert_eq!(
        (f.severity, f.category),
        (Severity::Medium, Category::Hygiene)
    );

    // A longer limit (`[rules] sso_key_age_days`): not old yet.
    let settings = RuleSettings {
        now: NOW,
        sso_key_age_days: 60,
        ..RuleSettings::default()
    };
    let longer = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    assert!(rule(&longer, "PW-037").is_empty());
    let config =
        pathwarden_core::config::Config::parse("[rules]\nsso_key_age_days = 45\n").unwrap();
    assert_eq!(config.settings().sso_key_age_days, 45);

    let (g, stats) = variant("sso-29-days", &[], |f| {
        f.obj("computers", "AZUREADSSOACC.MGMT.LOCAL")["Properties"]["pwdlastset"] =
            (NOW - 29 * 86_400).into();
    });
    assert!(rule(&run(&g, &stats), "PW-037").is_empty());
}

#[test]
fn a_retest_re_reads_the_seamless_sso_key() {
    use pathwarden_core::retest::targeted::Slice;
    use pathwarden_core::retest::Verdict;

    let a = pathwarden_core::analyze::run(&[dir("mgmt")], &Default::default(), &[], &mut |_| {})
        .unwrap();
    let slice = Slice::build(&a.graph, &a.stats.trusts, &a.findings);
    let slice: Slice = serde_json::from_str(&serde_json::to_string(&slice).unwrap()).unwrap();
    let fp = slice
        .findings
        .iter()
        .find(|f| f.rule == "PW-037")
        .expect("a PW-037 finding")
        .fingerprint
        .clone();
    assert!(slice.finding(&fp).unwrap().targetable());
    // The account as a re-read finds it: with the old key, and rolled over.
    let reread = |pwdlastset: i64| -> AdGraph {
        let text = std::fs::read_to_string(dir("mgmt").join("mgmt_computers.json")).unwrap();
        let mut doc: Value = serde_json::from_str(&text).unwrap();
        let data = doc["data"].as_array_mut().unwrap();
        data.retain(|o| o["Properties"]["name"] == "AZUREADSSOACC.MGMT.LOCAL");
        data[0]["Properties"]["pwdlastset"] = pwdlastset.into();
        doc["meta"]["count"] = 1.into();
        let mut ing = pathwarden_core::ingest::Ingestor::new();
        ing.ingest_text("computers.json", &doc.to_string()).unwrap();
        ing.finish().0
    };
    let old = slice.retest(&fp, &reread(NOW - 31 * 86_400), NOW).unwrap();
    assert_eq!(old.verdict, Verdict::StillOpen, "{:?}", old.details);
    let rolled = slice.retest(&fp, &reread(NOW - 86_400), NOW).unwrap();
    assert_eq!(rolled.verdict, Verdict::Fixed, "{:?}", rolled.details);
}

#[test]
fn the_entra_connect_service_account_and_its_admins() {
    let (g, stats) = load_with(&[]);
    // AADC01 is named by MSOL_ and reads ADSyncMSA: one server, strong.
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("AADC01"))
        .unwrap();
    assert!(
        f.summary.contains("ADSYNCMSA1A2B3$@MGMT.LOCAL"),
        "{}",
        f.summary
    );
    assert!(f.summary.contains("Evidence (strong)"), "{}", f.summary);
    let admins = node(&g, "ADSYNCADMINS@MGMT.LOCAL");
    assert!(admins
        .tier_zero_reason
        .as_deref()
        .unwrap()
        .contains("AADC01.MGMT.LOCAL"));
    assert_eq!(
        node(&g, "DAVE@MGMT.LOCAL").tier_zero_reason.as_deref(),
        Some("Member of ADSYNCADMINS@MGMT.LOCAL")
    );
    // The service account is not taken for a sync account.
    assert!(!titles(&rule(&all, "PW-028"))
        .iter()
        .any(|t| t.starts_with("Possible Entra Connect") && t.contains("ADSYNC")));

    // A second reader (a staging server) is a server too, inferred.
    let (g, stats) = variant("adsync-staging", &[], |f| {
        f.add_computer(1142, "AADC02.MGMT.LOCAL");
        f.obj("users", "ADSYNCMSA1A2B3$@MGMT.LOCAL")["Aces"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "PrincipalSID": format!("{DOMAIN_SID}-1142"),
                "PrincipalType": "Computer",
                "RightName": "ReadGMSAPassword",
                "IsInherited": false
            }));
    });
    let n = node(&g, "AADC02.MGMT.LOCAL");
    assert!(mgmt::is_plane_reason(n), "{:?}", n.tier_zero_reason);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title == "AADC02.MGMT.LOCAL (Entra Connect server) controls Tier Zero")
        .expect("PW-025 for the staging server");
    assert!(f.summary.contains("inferred"), "{}", f.summary);
    // Its MSOL_ account has a server, so no "not identified" finding.
    assert!(!titles(&rule(&all, "PW-025"))
        .iter()
        .any(|t| t.contains("is not identified")));
}

#[test]
fn adsync_admins_follow_the_server() {
    // The server configured as not Tier Zero: its admins aren't either.
    let (g, stats) = load_with(&["AADC01.MGMT.LOCAL"]);
    assert!(!node(&g, "ADSYNCADMINS@MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "DAVE@MGMT.LOCAL").tier_zero);
    // ... and they are reviewed, not left out.
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| {
            f.title == "ADSYNCADMINS@MGMT.LOCAL looks like the Entra Connect administrators group"
        })
        .expect("a review of ADSyncAdmins");
    assert!(
        f.summary.contains("configured as not Tier Zero"),
        "{}",
        f.summary
    );

    // No sync account can DCSync: the reader is only a review.
    let (g, stats) = variant("adsync-no-dcsync", &[], |f| {
        f.obj("domains", "MGMT.LOCAL")["Aces"] = json!([{
            "PrincipalSID": format!("{DOMAIN_SID}-512"),
            "PrincipalType": "Group",
            "RightName": "GenericAll",
            "IsInherited": false
        }]);
    });
    for name in [
        "AADC01.MGMT.LOCAL",
        "ADSYNCADMINS@MGMT.LOCAL",
        "DAVE@MGMT.LOCAL",
    ] {
        assert!(!node(&g, name).tier_zero, "{name}");
    }
    let pw028 = titles(&rule(&run(&g, &stats), "PW-028"));
    for t in [
        "AADC01.MGMT.LOCAL looks like an Entra Connect server",
        "ADSYNCADMINS@MGMT.LOCAL looks like the Entra Connect administrators group",
    ] {
        assert!(pw028.iter().any(|x| x == t), "missing {t} in {pw028:?}");
    }
}

#[test]
fn fingerprints_are_stable_across_runs() {
    let edit = |f: &mut Files| {
        f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local");
        f.add_computer(1140, "CM02.MGMT.LOCAL");
        f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
    };
    let fps = |g: &AdGraph, stats: &IngestStats| -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = run(g, stats)
            .into_iter()
            .filter(|f| ["PW-025", "PW-028", "PW-029", "PW-037"].contains(&f.rule))
            .map(|f| (f.fingerprint, f.title))
            .collect();
        v.sort();
        v
    };
    let (g1, s1) = variant("stable-1", &[], edit);
    let (g2, s2) = variant("stable-2", &[], edit);
    let (a, b) = (fps(&g1, &s1), fps(&g2, &s2));
    assert_eq!(a, b);
    for rule in ["PW-028", "PW-029", "PW-037"] {
        assert!(a.iter().any(|(fp, _)| fp.starts_with(rule)), "{rule}");
    }
}

// ---- SYSVOL registry policy and SCCM site objects ----

/// GPOs: one linked to the domain, two to the Domain Controllers OU.
const GPO_DOM: &str = "A0000000-0000-0000-0000-000000000001";
const GPO_DC: &str = "A0000000-0000-0000-0000-000000000002";
const GPO_DC2: &str = "A0000000-0000-0000-0000-000000000003";
const DC_OU: &str = "D0000000-0000-0000-0000-000000000001";
const WU: &str = r"SOFTWARE\POLICIES\MICROSOFT\WINDOWS\WINDOWSUPDATE";
const WU_AU: &str = r"SOFTWARE\POLICIES\MICROSOFT\WINDOWS\WINDOWSUPDATE\AU";
const POLICY_SOURCE: &str = "SYSVOL registry policy (MGMT.LOCAL)";
const SITES_SOURCE: &str = "SCCM site objects (MGMT.LOCAL)";

/// How the GPOs are linked.
#[derive(Clone, Copy, Default)]
struct Links {
    /// The domain's link is enforced.
    enforced: bool,
    /// The Domain Controllers OU blocks inheritance.
    blocks: bool,
}

/// The registry policy entries a GPO's `Registry.pol` gives for a WSUS
/// server at `url`.
fn wsus(url: &str) -> Value {
    json!([
        { "key": WU, "name": "WUSERVER", "text": url },
        { "key": WU, "name": "WUSTATUSSERVER", "text": url },
        { "key": WU_AU, "name": "USEWUSERVER", "number": 1 },
    ])
}

/// The SCCM client setup a GPO pushes, for `site`.
fn ccm_setup(site: &str) -> Value {
    json!([{
        "key": r"SOFTWARE\POLICIES\MICROSOFT\CCMSETUP",
        "name": "SETUPPARAMETERS",
        "text": format!("SMSSITECODE={site} SMSMP=cm01.mgmt.local"),
    }])
}

/// The SYSVOL sidecar with `policy` (GPO ID, values) and `sccm`, as the
/// built-in collector writes it.
fn sidecar(policy: &[(&str, Value)], sccm: Option<Value>) -> Value {
    let complete = json!({ "status": "complete", "read": 3 });
    let mut v = json!({
        "schema": "pathwarden.sysvol.v1",
        "domain": "mgmt.local",
        "dc": "dc01.mgmt.local",
        "checks": {
            "gpo_acl": complete, "logon_script_acl": complete, "gpp": complete,
            "gpo_local_groups": complete, "registry_pol": complete,
            "sccm_sites": complete,
        },
        "gpos": [], "logon_scripts": [], "gpp_passwords": [],
        "disabled_gp_links": [], "machine_quota_computers": [],
        "registry_policy": policy
            .iter()
            .map(|(id, values)| json!({ "guid": format!("{{{id}}}"), "object_id": id, "values": values }))
            .collect::<Vec<_>>(),
    });
    if let Some(s) = sccm {
        v["sccm"] = s;
    }
    v
}

/// `testdata/mgmt` with the GPO layout: the domain links GPO_DOM, the
/// Domain Controllers OU (DC01's) links GPO_DC then GPO_DC2. WSUS01 and
/// WSUS02 are member servers. `sidecar`, when given, is the SYSVOL sidecar.
fn policy_variant(
    name: &str,
    links: Links,
    sidecar: Option<Value>,
    edit: impl FnOnce(&mut Files),
) -> (AdGraph, IngestStats) {
    policy_variant_with(name, links, sidecar, edit, Vec::new(), None)
}

/// [`policy_variant`] with `more` files next to it, analyzed at `now`.
fn policy_variant_with(
    name: &str,
    links: Links,
    sidecar: Option<Value>,
    edit: impl FnOnce(&mut Files),
    more: Vec<(&str, Value)>,
    now: Option<i64>,
) -> (AdGraph, IngestStats) {
    let gpo = |id: &str, name: &str| {
        json!({
            "ObjectIdentifier": id,
            "Properties": {
                "name": name, "domain": "MGMT.LOCAL", "domainsid": DOMAIN_SID,
                "gpcpath": format!(r"\\mgmt.local\sysvol\mgmt.local\Policies\{{{id}}}"),
            },
            "Aces": [], "IsDeleted": false
        })
    };
    let meta = |kind: &str, count: usize| json!({ "methods": 0, "type": kind, "count": count, "version": 6 });
    let gpos = json!({
        "data": [
            gpo(GPO_DOM, "UPDATES DOMAIN@MGMT.LOCAL"),
            gpo(GPO_DC, "UPDATES DCS@MGMT.LOCAL"),
            gpo(GPO_DC2, "UPDATES DCS 2@MGMT.LOCAL"),
        ],
        "meta": meta("gpos", 3),
    });
    let ous = json!({
        "data": [{
            "ObjectIdentifier": DC_OU,
            "Properties": {
                "name": "DOMAIN CONTROLLERS@MGMT.LOCAL", "domain": "MGMT.LOCAL",
                "domainsid": DOMAIN_SID,
                "distinguishedname": "OU=DOMAIN CONTROLLERS,DC=MGMT,DC=LOCAL",
                "blocksinheritance": links.blocks,
            },
            "Links": [
                { "GUID": GPO_DC, "IsEnforced": false },
                { "GUID": GPO_DC2, "IsEnforced": false },
            ],
            "ChildObjects": [{ "ObjectIdentifier": format!("{DOMAIN_SID}-1000"), "ObjectType": "Computer" }],
            "ContainedBy": { "ObjectIdentifier": DOMAIN_SID, "ObjectType": "Domain" },
            "Aces": [], "IsDeleted": false
        }],
        "meta": meta("ous", 1),
    });
    let mut extra = vec![("mgmt_gpos.json", gpos), ("mgmt_ous.json", ous)];
    if let Some(s) = sidecar {
        extra.push(("20261101000000_pathwarden-sysvol.json", s));
    }
    extra.extend(more);
    variant_at(
        name,
        &[],
        |f| {
            let d = f.obj("domains", "MGMT.LOCAL");
            d["Links"] = json!([{ "GUID": GPO_DOM, "IsEnforced": links.enforced }]);
            d["ChildObjects"] = json!([{ "ObjectIdentifier": DC_OU, "ObjectType": "OU" }]);
            f.obj("computers", "DC01.MGMT.LOCAL")["ContainedBy"] =
                json!({ "ObjectIdentifier": DC_OU, "ObjectType": "OU" });
            f.add_computer(1150, "WSUS01.MGMT.LOCAL");
            f.add_computer(1151, "WSUS02.MGMT.LOCAL");
            edit(f);
        },
        extra,
        now,
    )
}

/// The `ManagesHost` edges with the source each came from.
fn manages_from(g: &AdGraph) -> Vec<(String, String, Option<String>)> {
    let mut v: Vec<_> = g
        .inner()
        .edge_references()
        .filter(|e| *e.weight() == EdgeKind::ManagesHost)
        .map(|e| {
            (
                g.node(e.source()).name.clone(),
                g.node(e.target()).name.clone(),
                g.edge_source_name(e.id()).map(str::to_string),
            )
        })
        .collect();
    v.sort();
    v
}

fn wsus_edge(server: &str) -> (String, String, Option<String>) {
    (
        server.to_string(),
        "DC01.MGMT.LOCAL".to_string(),
        Some(POLICY_SOURCE.to_string()),
    )
}

#[test]
fn the_domain_controllers_ou_gpo_wins_over_the_domain() {
    let side = sidecar(
        &[
            (GPO_DOM, wsus("http://wsus01.mgmt.local:8530")),
            (GPO_DC, wsus("https://WSUS02.mgmt.local:8531")),
        ],
        None,
    );
    let (g, stats) = policy_variant("wsus-ou", Links::default(), Some(side), |_| {});
    assert_eq!(
        stats.sysvol[0].policy_gpos, 2,
        "{:?}",
        stats.sysvol[0].notes
    );
    let w2 = node(&g, "WSUS02.MGMT.LOCAL");
    assert!(w2.tier_zero);
    let reason = w2.tier_zero_reason.as_deref().unwrap();
    assert_eq!(reason, "Management plane: WSUS server for DC01.MGMT.LOCAL");
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g).contains(&wsus_edge("WSUS02.MGMT.LOCAL")));
    let all = run(&g, &stats);
    // HTTPS: no PW-038.
    assert!(rule(&all, "PW-038").is_empty());
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title == "WSUS02.MGMT.LOCAL (WSUS server) controls Tier Zero")
        .unwrap_or_else(|| panic!("{:?}", titles(&rule(&all, "PW-025"))));
    assert!(
        f.summary.contains("UPDATES DCS@MGMT.LOCAL"),
        "{}",
        f.summary
    );
    assert!(f.summary.contains("inferred"), "{}", f.summary);
    assert_eq!(f.sources, [POLICY_SOURCE]);
    assert_eq!(
        f.path.as_ref().unwrap().steps[0].edge,
        EdgeKind::ManagesHost
    );
}

#[test]
fn an_enforced_domain_gpo_wins_and_http_is_reported() {
    let side = sidecar(
        &[
            (GPO_DOM, wsus("http://wsus01.mgmt.local:8530")),
            (GPO_DC, wsus("https://wsus02.mgmt.local:8531")),
        ],
        None,
    );
    let links = Links {
        enforced: true,
        ..Links::default()
    };
    let (g, stats) = policy_variant("wsus-enforced", links, Some(side), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "WSUS02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let pw038 = rule(&all, "PW-038");
    assert_eq!(pw038.len(), 1, "{:?}", titles(&pw038));
    let f = pw038[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, Category::Hygiene);
    assert_eq!(
        f.title,
        "Tier Zero computers in MGMT.LOCAL take updates from WSUS over HTTP"
    );
    assert!(
        f.summary.contains("http://wsus01.mgmt.local:8530"),
        "{}",
        f.summary
    );
    assert!(
        f.summary.contains("UPDATES DOMAIN@MGMT.LOCAL"),
        "{}",
        f.summary
    );
    assert_eq!(f.sources, [POLICY_SOURCE]);
    let affected: Vec<&str> = f.affected.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(affected, ["DC01.MGMT.LOCAL", "UPDATES DOMAIN@MGMT.LOCAL"]);
    // The same twice: a stable fingerprint.
    let (g2, s2) = policy_variant(
        "wsus-enforced-2",
        links,
        Some(sidecar(
            &[
                (GPO_DOM, wsus("http://wsus01.mgmt.local:8530")),
                (GPO_DC, wsus("https://wsus02.mgmt.local:8531")),
            ],
            None,
        )),
        |_| {},
    );
    assert_eq!(rule(&run(&g2, &s2), "PW-038")[0].fingerprint, f.fingerprint);
}

#[test]
fn block_inheritance_keeps_the_domain_gpo_off_unless_enforced() {
    let side = || sidecar(&[(GPO_DOM, wsus("http://wsus01.mgmt.local:8530"))], None);
    // Without the block, the domain's GPO applies.
    let (g, stats) = policy_variant("wsus-inherit", Links::default(), Some(side()), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert_eq!(rule(&run(&g, &stats), "PW-038").len(), 1);
    // Blocked: nothing applies.
    let blocks = Links {
        blocks: true,
        ..Links::default()
    };
    let (g, stats) = policy_variant("wsus-blocked", blocks, Some(side()), |_| {});
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g)
        .iter()
        .all(|(s, _, _)| s != "WSUS01.MGMT.LOCAL"));
    assert!(rule(&run(&g, &stats), "PW-038").is_empty());
    // Enforced: the block doesn't stop it.
    let both = Links {
        blocks: true,
        enforced: true,
    };
    let (g, stats) = policy_variant("wsus-blocked-enforced", both, Some(side()), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert_eq!(rule(&run(&g, &stats), "PW-038").len(), 1);
}

#[test]
fn wsus_needs_use_wu_server_and_a_gpo_below_can_delete_it() {
    // WUServer without UseWUServer: Windows Update doesn't use it.
    let no_use = json!([{ "key": WU, "name": "WUSERVER", "text": "http://wsus01.mgmt.local" }]);
    let (g, _) = policy_variant(
        "wsus-unused",
        Links::default(),
        Some(sidecar(&[(GPO_DOM, no_use)], None)),
        |_| {},
    );
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    // The Domain Controllers OU's GPO deletes the server (policy disabled).
    let delete = json!([{ "key": WU, "name": "WUSERVER", "delete": true }]);
    let (g, stats) = policy_variant(
        "wsus-deleted",
        Links::default(),
        Some(sidecar(
            &[
                (GPO_DOM, wsus("http://wsus01.mgmt.local")),
                (GPO_DC, delete),
            ],
            None,
        )),
        |_| {},
    );
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(rule(&run(&g, &stats), "PW-038").is_empty());
}

#[test]
fn two_gpos_on_one_ou_that_disagree_keep_both_servers() {
    let side = sidecar(
        &[
            (GPO_DC, wsus("http://wsus01.mgmt.local:8530")),
            (GPO_DC2, wsus("https://wsus02.mgmt.local:8531")),
        ],
        None,
    );
    let (g, stats) = policy_variant("wsus-two", Links::default(), Some(side), |_| {});
    for s in ["WSUS01.MGMT.LOCAL", "WSUS02.MGMT.LOCAL"] {
        assert!(node(&g, s).tier_zero, "{s}");
        assert!(manages_from(&g).contains(&wsus_edge(s)), "{s}");
    }
    let f = rule(&run(&g, &stats), "PW-038")[0].clone();
    assert!(f.summary.contains("http://wsus01"), "{}", f.summary);
    assert!(!f.summary.contains("wsus02"), "{}", f.summary);
}

#[test]
fn a_wsus_server_outside_the_collection_is_reviewed() {
    let side = sidecar(&[(GPO_DC, wsus("http://10.0.0.9:8530"))], None);
    let (g, stats) = policy_variant("wsus-ip", Links::default(), Some(side), |_| {});
    assert!(manages_from(&g)
        .iter()
        .all(|(_, _, s)| s.as_deref() != Some(POLICY_SOURCE)));
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| {
            f.title == "DC01.MGMT.LOCAL takes its updates from a WSUS server outside the collection"
        })
        .unwrap_or_else(|| panic!("{:?}", titles(&rule(&all, "PW-028"))));
    assert_eq!((f.rule, f.severity), ("PW-028", Severity::High));
    assert!(f.summary.contains("http://10.0.0.9:8530"), "{}", f.summary);
    assert_eq!(f.sources, [POLICY_SOURCE]);
    // Still HTTP.
    assert_eq!(rule(&all, "PW-038").len(), 1);
}

#[test]
fn without_the_sidecar_wsus_findings_are_held_not_fixed() {
    use pathwarden_core::opengraph::coverage::RunSources;
    use pathwarden_core::state::{self, ResolveScope};

    let links = Links {
        enforced: true,
        ..Links::default()
    };
    let side = || sidecar(&[(GPO_DOM, wsus("http://wsus01.mgmt.local:8530"))], None);
    let (g, stats) = policy_variant("hold-1", links, Some(side()), |_| {});
    let first = run(&g, &stats);
    let watched: Vec<String> = first
        .iter()
        .filter(|f| f.rule == "PW-038" || (f.rule == "PW-025" && f.title.starts_with("WSUS01")))
        .map(|f| f.fingerprint.clone())
        .collect();
    assert_eq!(
        watched.len(),
        2,
        "{:?}",
        titles(&first.iter().collect::<Vec<_>>())
    );
    let prev = state::reconcile(&state::FindingsState::default(), &first, 1, false).state;
    let keys = RunSources::from_analysis(&g, &stats).keys();
    assert!(
        keys.contains(&pathwarden_core::opengraph::source_key(POLICY_SOURCE)),
        "the run records the source its edge came from"
    );

    // SharpHound data: no SYSVOL sidecar. Not read, so held.
    let (g2, stats2) = policy_variant("hold-2", links, None, |_| {});
    assert!(!node(&g2, "WSUS01.MGMT.LOCAL").tier_zero);
    let second = run(&g2, &stats2);
    assert!(rule(&second, "PW-038").is_empty());
    let sources = RunSources::from_analysis(&g2, &stats2);
    let scope = ResolveScope::everything().with_sources(sources, &keys);
    let r = state::reconcile_scoped(&prev, &second, 2, false, &scope);
    for fp in &watched {
        assert!(
            !r.resolved.iter().any(|x| &x.fingerprint == fp),
            "{fp} resolved without the registry policy"
        );
    }
    assert!(r.counts.held >= 2, "{:?}", r.counts);

    // Read again, and the GPO fixed (HTTPS): PW-038 is fixed.
    let fixed = sidecar(&[(GPO_DOM, wsus("https://wsus01.mgmt.local:8531"))], None);
    let (g3, stats3) = policy_variant("hold-3", links, Some(fixed), |_| {});
    let third = run(&g3, &stats3);
    let scope =
        ResolveScope::everything().with_sources(RunSources::from_analysis(&g3, &stats3), &keys);
    let r = state::reconcile_scoped(&prev, &third, 3, false, &scope);
    let pw038 = first.iter().find(|f| f.rule == "PW-038").unwrap();
    assert!(r
        .resolved
        .iter()
        .any(|x| x.fingerprint == pw038.fingerprint));
}

/// CM02 joins CM01 as a site server (both through SCCM SITE SERVERS).
fn two_site_servers(f: &mut Files) {
    f.add_spn("DC01.MGMT.LOCAL", "CmRcService/dc01.mgmt.local");
    f.add_computer(1140, "CM02.MGMT.LOCAL");
    f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
}

#[test]
fn the_client_site_picks_its_site_server() {
    // Two sites: P01 published by CM02, P02 by CM01. The GPO that pushes
    // the client names P01.
    let sccm = json!({
        "sites": [
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") },
            { "site_code": "P02", "owner": format!("{DOMAIN_SID}-1102") },
        ],
        "management_points": [],
    });
    let side = sidecar(&[(GPO_DC, ccm_setup("P01"))], Some(sccm));
    let (g, stats) = policy_variant("sccm-site", Links::default(), Some(side), two_site_servers);
    assert!(node(&g, "CM02.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g).contains(&(
        "CM02.MGMT.LOCAL".to_string(),
        "DC01.MGMT.LOCAL".to_string(),
        Some(SITES_SOURCE.to_string())
    )));
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("CM02"))
        .unwrap();
    assert!(f.summary.contains("site P01"), "{}", f.summary);
    assert_eq!(f.sources, [SITES_SOURCE, POLICY_SOURCE]);
    assert!(!titles(&rule(&all, "PW-028"))
        .iter()
        .any(|t| t.contains("SCCM client")));
}

#[test]
fn the_forest_only_site_picks_its_management_point() {
    // One site, its management point on CM02; no GPO names the site.
    let sccm = json!({
        "sites": [{ "site_code": "P01" }],
        "management_points": [{ "site_code": "P01", "host": "cm02.mgmt.local", "default": true }],
    });
    let (g, _) = policy_variant(
        "sccm-mp",
        Links::default(),
        Some(sidecar(&[], Some(sccm))),
        two_site_servers,
    );
    assert!(node(&g, "CM02.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
}

#[test]
fn without_site_objects_two_site_servers_stay_unknown_and_say_so() {
    let (g, stats) = policy_variant("sccm-no-sites", Links::default(), None, two_site_servers);
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| f.title == "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown")
        .unwrap();
    assert!(
        f.summary.contains("The SCCM site objects were not read"),
        "{}",
        f.summary
    );
    // Read, but naming no site of these servers: reviewed, and said so.
    let sccm = json!({ "sites": [{ "site_code": "P09" }, { "site_code": "P08" }] });
    let (g, stats) = policy_variant(
        "sccm-other-sites",
        Links::default(),
        Some(sidecar(&[], Some(sccm))),
        two_site_servers,
    );
    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| f.title == "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown")
        .unwrap();
    assert!(
        f.summary.contains("don't narrow them to one"),
        "{}",
        f.summary
    );
    assert_eq!(f.sources, [SITES_SOURCE]);
}

#[test]
fn a_gpo_that_pushes_the_sccm_client_makes_a_dc_a_client() {
    // No CmRcService/ SPN: the GPO's client setup alone. One site server.
    let side = sidecar(&[(GPO_DOM, ccm_setup("P01"))], None);
    let (g, stats) = policy_variant("sccm-gpo", Links::default(), Some(side), |_| {});
    let cm = node(&g, "CM01.MGMT.LOCAL");
    assert!(cm.tier_zero, "{:?}", cm.tier_zero_reason);
    assert!(manages_from(&g).contains(&(
        "CM01.MGMT.LOCAL".to_string(),
        "DC01.MGMT.LOCAL".to_string(),
        Some(POLICY_SOURCE.to_string())
    )));
    let f = rule(&run(&g, &stats), "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("CM01"))
        .unwrap()
        .clone();
    assert!(
        f.summary.contains("UPDATES DOMAIN@MGMT.LOCAL"),
        "{}",
        f.summary
    );
    // Without the sidecar: nothing shows DC01 is a client.
    let (g, _) = policy_variant("sccm-gpo-none", Links::default(), None, |_| {});
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
}

/// The PW-028 finding titled `title`.
fn review<'a>(all: &'a [Finding], title: &str) -> &'a Finding {
    all.iter()
        .find(|f| f.rule == "PW-028" && f.title == title)
        .unwrap_or_else(|| panic!("no {title:?} in {:?}", titles(&rule(all, "PW-028"))))
}

const OUTSIDE: &str = "DC01.MGMT.LOCAL takes its updates from a WSUS server outside the collection";

#[test]
fn a_wsus_url_names_a_computer_only_by_its_own_name() {
    // An alias: WSUS01's short name in a name that isn't WSUS01's.
    let side = sidecar(
        &[(GPO_DC, wsus("http://wsus01.corp.mgmt.local:8530"))],
        None,
    );
    let (g, stats) = policy_variant("wsus-alias", Links::default(), Some(side), |_| {});
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    review(&run(&g, &stats), OUTSIDE);
    // Its full name in another case, with the root's dot: WSUS01.
    let side = sidecar(&[(GPO_DC, wsus("https://WSUS01.Mgmt.Local.:8531"))], None);
    let (g, _) = policy_variant("wsus-dot", Links::default(), Some(side), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    // A short name: the computer of that name in the host's domain.
    let side = sidecar(&[(GPO_DC, wsus("https://wsus01:8531"))], None);
    let (g, _) = policy_variant("wsus-short", Links::default(), Some(side), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    // The same short name in another forest only: not that computer.
    let other = |f: &mut Files| {
        f.add_computer(1160, "WSUS09.OTHER.LOCAL");
        let c = f.obj("computers", "WSUS09.OTHER.LOCAL");
        c["ObjectIdentifier"] = "S-1-5-21-9000-9000-9000-1160".into();
        c["Properties"]["domain"] = "OTHER.LOCAL".into();
    };
    let side = sidecar(&[(GPO_DC, wsus("https://wsus09:8531"))], None);
    let (g, stats) = policy_variant("wsus-other-forest", Links::default(), Some(side), other);
    assert!(!node(&g, "WSUS09.OTHER.LOCAL").tier_zero);
    review(&run(&g, &stats), OUTSIDE);
}

#[test]
fn a_wsus_server_made_through_the_machine_account_quota_is_reviewed() {
    let mut side = sidecar(&[(GPO_DC, wsus("https://wsus01.mgmt.local:8531"))], None);
    side["machine_quota_computers"] = json!([format!("{DOMAIN_SID}-1150")]);
    let (g, stats) = policy_variant("wsus-quota", Links::default(), Some(side), |_| {});
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(!manages_from(&g).contains(&wsus_edge("WSUS01.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let f = review(
        &all,
        "DC01.MGMT.LOCAL takes its updates from a computer a domain user may have created",
    );
    assert_eq!(f.severity, Severity::High);
    assert!(f.summary.contains("machine account quota"), "{}", f.summary);
}

#[test]
fn a_disabled_link_is_left_out_and_an_unknown_one_keeps_both_values() {
    let delete = json!([{ "key": WU, "name": "WUSERVER", "delete": true }]);
    let side = || {
        sidecar(
            &[
                (GPO_DOM, wsus("http://wsus01.mgmt.local:8530")),
                (GPO_DC, delete.clone()),
            ],
            None,
        )
    };
    // The link of the GPO that deletes the server is disabled: the domain's
    // server stands.
    let mut disabled = side();
    disabled["disabled_gp_links"] = json!([{
        "container": "OU=Domain Controllers,DC=mgmt,DC=local",
        "gpo": format!("{{{GPO_DC}}}"),
    }]);
    let (g, stats) = policy_variant("wsus-link-off", Links::default(), Some(disabled), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert_eq!(rule(&run(&g, &stats), "PW-038").len(), 1);
    // Every link enabled: the delete wins.
    let (g, _) = policy_variant("wsus-link-on", Links::default(), Some(side()), |_| {});
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    // The links' status not read: the delete doesn't override for sure.
    let mut unknown = side();
    unknown.as_object_mut().unwrap().remove("disabled_gp_links");
    let (g, _) = policy_variant("wsus-link-unknown", Links::default(), Some(unknown), |_| {});
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
}

#[test]
fn site_objects_that_disagree_narrow_nothing() {
    let unknown = "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown";
    // Two site objects with the code the GPO names.
    let sccm = json!({
        "sites": [
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") },
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1102") },
        ],
    });
    let side = sidecar(&[(GPO_DC, ccm_setup("P01"))], Some(sccm));
    let (g, stats) = policy_variant(
        "sccm-two-owners",
        Links::default(),
        Some(side),
        two_site_servers,
    );
    assert!(!node(&g, "CM02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = review(&all, unknown);
    assert!(f.summary.contains("CM01.MGMT.LOCAL"), "{}", f.summary);
    assert!(f.summary.contains("CM02.MGMT.LOCAL"), "{}", f.summary);
    // The owner and the management point's host differ.
    let sccm = json!({
        "sites": [{ "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") }],
        "management_points": [{ "site_code": "P01", "host": "cm01.mgmt.local" }],
    });
    let side = sidecar(&[(GPO_DC, ccm_setup("P01"))], Some(sccm));
    let (g, stats) = policy_variant(
        "sccm-owner-mp",
        Links::default(),
        Some(side),
        two_site_servers,
    );
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM02.MGMT.LOCAL").tier_zero);
    review(&run(&g, &stats), unknown);
}

#[test]
fn a_registry_pol_that_failed_matters_only_above_a_tier_zero_host() {
    use pathwarden_core::sysvol::CheckStatus;

    let side = |gpo: &str| {
        let mut s = sidecar(&[], None);
        s["checks"]["registry_pol"] = json!({
            "status": "partial", "read": 2, "failed": 1,
            "reason": "1 item could not be read, first: not in the format",
        });
        s["registry_pol_failed"] = json!([{ "guid": format!("{{{gpo}}}"), "object_id": gpo }]);
        s
    };
    let status = |stats: &IngestStats| stats.sysvol[0].checks.registry_pol.as_ref().unwrap().status;
    // GPO_DC is linked above DC01: partial.
    let (_, stats) = policy_variant(
        "pol-failed-dc",
        Links::default(),
        Some(side(GPO_DC)),
        |_| {},
    );
    assert_eq!(status(&stats), CheckStatus::Partial);
    // GPO_DOM, with the domain's link gone, applies to no Tier Zero host.
    let unlink = |f: &mut Files| f.obj("domains", "MGMT.LOCAL")["Links"] = json!([]);
    let (_, stats) = policy_variant(
        "pol-failed-elsewhere",
        Links::default(),
        Some(side(GPO_DOM)),
        unlink,
    );
    assert_eq!(status(&stats), CheckStatus::Complete);
    // A GPO not in the collection: partial.
    let gone = "A0000000-0000-0000-0000-0000000000FF";
    let (_, stats) = policy_variant(
        "pol-failed-gone",
        Links::default(),
        Some(side(gone)),
        unlink,
    );
    assert_eq!(status(&stats), CheckStatus::Partial);
}

// ---- The Tier Zero host probe ----

/// Read a week before the analysis ([`NOW`]), and nine months before it.
const CURRENT: &str = "2026-10-01T00:00:00Z";
const OLD: &str = "2026-01-01T00:00:00Z";
const DC01_PROBE: &str = "Tier Zero host probe (DC01.MGMT.LOCAL)";
const DC01_FILE: &str = "pathwarden-tierzero-DC01.mgmt.local.json";

/// The `agents` part of a v2 file with nothing found, changed by `edit`.
fn agents(edit: impl FnOnce(&mut Value)) -> Value {
    let mut a = json!({
        "sccm": { "present": false, "site_code": null, "error": null },
        "scom": { "present": false, "management_groups": [], "error": null },
        "wsus": { "present": false, "server": null, "status_server": null,
                  "use_wu_server": null, "error": null },
        "hyperv": { "present": false, "host": null, "error": null },
        "vmware": { "present": false, "error": null },
        "sshd": { "present": false, "start": null, "error": null },
        "backup": { "present": false, "agents": [], "error": null },
    });
    edit(&mut a);
    a
}

/// A v2 file from `host` (in MGMT.LOCAL), as the script writes it on a DC.
fn probe(host: &str, read_at: &str, agents: Value) -> Value {
    json!({
        "schema": "pathwarden.tierzero.v2",
        "tool": "Get-PathwardenTierZeroSettings.ps1",
        "domain": "mgmt.local",
        "dc": { "hostname": host, "dns_name": format!("{}.mgmt.local", host.to_lowercase()),
                "os_build": "20348.4171" },
        "read_at": read_at,
        "values": [{ "name": "StrongCertificateBindingEnforcement",
                     "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc",
                     "present": true, "value": 2 }],
        "agents": agents,
    })
}

/// `testdata/mgmt` as the built-in collector reads it (a SYSVOL sidecar,
/// so who created each computer is known), with SCOM02, WSUS01 and WSUS02
/// (member servers) and `files`, analyzed at [`NOW`].
fn probe_variant(
    name: &str,
    edit: impl FnOnce(&mut Files),
    files: Vec<(&str, Value)>,
) -> (AdGraph, IngestStats) {
    policy_variant_with(
        name,
        Links::default(),
        Some(sidecar(&[], None)),
        |f| {
            f.add_computer(1160, "SCOM02.MGMT.LOCAL");
            edit(f);
        },
        files,
        Some(NOW),
    )
}

/// [`probe_variant`] as SharpHound data: no SYSVOL sidecar, so nobody knows
/// who created a computer.
fn probe_variant_sharphound(
    name: &str,
    edit: impl FnOnce(&mut Files),
    files: Vec<(&str, Value)>,
) -> (AdGraph, IngestStats) {
    variant_at(
        name,
        &[],
        |f| {
            f.add_computer(1160, "SCOM02.MGMT.LOCAL");
            f.add_computer(1150, "WSUS01.MGMT.LOCAL");
            edit(f);
        },
        files,
        Some(NOW),
    )
}

fn add_dc(f: &mut Files, rid: u32, name: &str) {
    f.add_computer(rid, name);
    let c = f.obj("computers", name);
    c["IsDC"] = true.into();
    c["Properties"]["isdc"] = true.into();
}

fn probe_edge(server: &str) -> (String, String, Option<String>) {
    (
        server.to_string(),
        "DC01.MGMT.LOCAL".to_string(),
        Some(DC01_PROBE.to_string()),
    )
}

#[test]
fn v1_and_v2_files_together_and_the_coverage_line() {
    let a = agents(|a| {
        a["scom"] = json!({ "present": true, "error": null, "management_groups": [
            { "name": "MG2", "servers": ["scom02.mgmt.local"] }] });
        a["vmware"]["present"] = true.into();
    });
    // DC02 has an older script's file: DC values, no agents.
    let mut v1 = probe("DC02", CURRENT, Value::Null);
    v1["schema"] = "pathwarden.tierzero.v1".into();
    v1.as_object_mut().unwrap().remove("agents");
    let (g, stats) = probe_variant(
        "probe-mixed",
        |f| add_dc(f, 1170, "DC02.MGMT.LOCAL"),
        vec![
            (DC01_FILE, probe("DC01", CURRENT, a)),
            ("pathwarden-tierzero-DC02.mgmt.local.json", v1),
        ],
    );
    // Both files' DC values are used; only the v2 file has agents.
    let matched: Vec<Option<&str>> = stats
        .dc_settings
        .iter()
        .map(|s| s.matched.as_deref())
        .collect();
    assert_eq!(
        matched,
        [Some("DC01.MGMT.LOCAL"), Some("DC02.MGMT.LOCAL")],
        "{:?}",
        stats.skipped_files
    );
    assert_eq!(stats.host_probes.len(), 1);
    assert_eq!(stats.host_probes[0].found, ["SCOM agent", "VMware Tools"]);
    // The SCOM server the DC's registry names manages it, from its probe.
    let scom = node(&g, "SCOM02.MGMT.LOCAL");
    assert!(scom.tier_zero);
    assert!(mgmt::is_plane_reason(scom));
    assert!(manages_from(&g).contains(&probe_edge("SCOM02.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title == "SCOM02.MGMT.LOCAL (SCOM server) controls Tier Zero")
        .unwrap_or_else(|| panic!("{:?}", titles(&rule(&all, "PW-025"))));
    assert!(f.summary.contains("management group MG2"), "{}", f.summary);
    assert!(f.summary.contains("(strong)"), "{}", f.summary);
    assert_eq!(f.sources, [DC01_PROBE]);
    // VMware Tools: the hypervisor isn't modelled.
    let vms = rule(&all, "PW-039");
    assert_eq!(vms.len(), 1, "{:?}", titles(&vms));
    assert_eq!(
        vms[0].title,
        "A Tier Zero computer in MGMT.LOCAL is a VMware virtual machine"
    );
    assert_eq!(
        (vms[0].severity, vms[0].category),
        (Severity::Medium, Category::Hygiene)
    );
    assert_eq!(vms[0].sources, [DC01_PROBE]);
    // The completeness line: DC02 has no agents read.
    let c = pathwarden_core::hostprobe::completeness(&g);
    assert_eq!(
        c.line(),
        "Management agents read on Tier Zero computers: 1 of 2"
    );
    let dc01 = &c.hosts[0];
    assert_eq!(dc01.host, "DC01.MGMT.LOCAL");
    assert_eq!(dc01.read_words(), "Read on Oct 1, 2026.");
    assert_eq!(dc01.found_words(), "SCOM agent, VMware Tools.");
    assert_eq!(c.hosts[1].read_words(), "No settings file yet.");
    assert_eq!(c.hosts[1].found_words(), "");
}

#[test]
fn a_name_that_matches_no_computer_is_reviewed_never_guessed() {
    // HV01.MGMT.LOCAL exists, but the registry names another domain's HV01;
    // the SCOM server is no computer at all.
    let a = agents(|a| {
        a["hyperv"] = json!({ "present": true, "host": "HV01.ELSEWHERE.LOCAL", "error": null });
        a["scom"] = json!({ "present": true, "error": null, "management_groups": [
            { "name": "MG9", "servers": ["scom9.mgmt.local"] }] });
    });
    let (g, stats) = probe_variant(
        "probe-unresolved",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    assert!(!node(&g, "HV01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g)
        .iter()
        .all(|(_, _, s)| s.as_deref() != Some(DC01_PROBE)));
    let all = run(&g, &stats);
    let hv = review(
        &all,
        "DC01.MGMT.LOCAL is a Hyper-V virtual machine, and its host is unknown",
    );
    assert_eq!((hv.rule, hv.severity), ("PW-028", Severity::High));
    assert!(
        hv.summary.contains("HV01.ELSEWHERE.LOCAL"),
        "{}",
        hv.summary
    );
    assert_eq!(hv.sources, [DC01_PROBE]);
    let scom = review(
        &all,
        "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown",
    );
    assert!(
        scom.summary.contains("scom9.mgmt.local"),
        "{}",
        scom.summary
    );
    assert!(!scom.summary.contains("AD integration"), "{}", scom.summary);

    // The short name, inside the host's domain, is exactly one computer.
    let a = agents(|a| {
        a["hyperv"] = json!({ "present": true, "host": "hv01", "error": null });
    });
    let (g, _) = probe_variant(
        "probe-short",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    let hv = node(&g, "HV01.MGMT.LOCAL");
    assert!(hv.tier_zero);
    assert_eq!(
        hv.tier_zero_reason.as_deref(),
        Some("Management plane: Hyper-V host of DC01.MGMT.LOCAL")
    );
    assert!(manages_from(&g).contains(&probe_edge("HV01.MGMT.LOCAL")));
}

#[test]
fn a_site_code_in_two_hierarchies_is_ambiguous() {
    let site_servers = |f: &mut Files| {
        f.add_computer(1140, "CM02.MGMT.LOCAL");
        f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
    };
    let client = || {
        probe(
            "DC01",
            CURRENT,
            agents(|a| a["sccm"] = json!({ "present": true, "site_code": "P01", "error": null })),
        )
    };
    // P01 published twice, by CM02 and by CM01.
    let sccm = json!({
        "sites": [
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") },
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1102") },
        ],
        "management_points": [],
    });
    let (g, stats) = policy_variant_with(
        "probe-site-twice",
        Links::default(),
        Some(sidecar(&[], Some(sccm))),
        site_servers,
        vec![(DC01_FILE, client())],
        Some(NOW),
    );
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = review(
        &all,
        "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown",
    );
    assert!(f.summary.contains("assigned to site P01"), "{}", f.summary);
    assert!(f.summary.contains("ambiguous"), "{}", f.summary);
    assert!(
        f.sources.contains(&DC01_PROBE.to_string()),
        "{:?}",
        f.sources
    );

    // One site each: the registry's site picks its server.
    let sccm = json!({
        "sites": [
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") },
            { "site_code": "P02", "owner": format!("{DOMAIN_SID}-1102") },
        ],
        "management_points": [],
    });
    let (g, stats) = policy_variant_with(
        "probe-site-once",
        Links::default(),
        Some(sidecar(&[], Some(sccm))),
        site_servers,
        vec![(DC01_FILE, client())],
        Some(NOW),
    );
    assert!(node(&g, "CM02.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("CM02"))
        .unwrap();
    assert_eq!(f.sources, [SITES_SOURCE, DC01_PROBE]);
}

#[test]
fn wsus_and_backup_agents_from_the_registry() {
    let a = agents(|a| {
        a["wsus"] = json!({ "present": true, "server": "http://wsus01.mgmt.local:8530",
                            "status_server": "http://wsus01.mgmt.local:8530",
                            "use_wu_server": 1, "error": null });
        a["backup"] = json!({ "present": true, "error": null, "agents": [
            { "product": "Veeam", "service": "VeeamTransportSvc", "start": 2 },
            { "product": "DPM", "service": "DPMRA", "start": 4 }] });
    });
    let (g, stats) = probe_variant(
        "probe-wsus",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    assert!(node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g).contains(&probe_edge("WSUS01.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let http = rule(&all, "PW-038");
    assert_eq!(http.len(), 1);
    assert!(
        http[0].summary.contains("as their registry shows"),
        "{}",
        http[0].summary
    );
    assert_eq!(http[0].sources, [DC01_PROBE]);
    let backup = review(
        &all,
        "Tier Zero computers in MGMT.LOCAL run the Veeam backup agent",
    );
    assert_eq!(backup.severity, Severity::Medium);
    assert!(
        backup.affected[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("Veeam backup agent (service VeeamTransportSvc)"),
        "{:?}",
        backup.affected
    );
    // A disabled service is not an agent.
    assert!(!all.iter().any(|f| f.title.contains("DPM")));
    // Without UseWUServer, Windows Update doesn't use the server.
    let a = agents(|a| {
        a["wsus"] = json!({ "present": true, "server": "http://wsus01.mgmt.local:8530",
                            "use_wu_server": 0, "error": null });
    });
    let (g, _) = probe_variant(
        "probe-wsus-off",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
}

/// What rests on a host's probe is held, never fixed, without a current,
/// trusted file from that host: none at all, one over 90 days old, or a
/// settings folder's file nobody vouches for. A current file of the
/// collection that shows the agents gone fixes it.
#[test]
fn without_a_current_trusted_file_probe_findings_are_held() {
    use pathwarden_core::opengraph::{coverage::RunSources, source_key};
    use pathwarden_core::state::{self, ResolveScope};

    let shown = || {
        agents(|a| {
            a["vmware"]["present"] = true.into();
            a["hyperv"] = json!({ "present": true, "host": "hv01.mgmt.local", "error": null });
        })
    };
    let (g, stats) = probe_variant(
        "hold-p1",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, shown()))],
    );
    let first = run(&g, &stats);
    let watched: Vec<String> = first
        .iter()
        .filter(|f| f.rule == "PW-039" || (f.rule == "PW-025" && f.title.starts_with("HV01")))
        .map(|f| f.fingerprint.clone())
        .collect();
    assert_eq!(
        watched.len(),
        2,
        "{:?}",
        titles(&first.iter().collect::<Vec<_>>())
    );
    let prev = state::reconcile(&state::FindingsState::default(), &first, 1, false).state;
    let keys = RunSources::from_analysis(&g, &stats).keys();

    let reconcile = |name: &str, files: Vec<(&str, Value)>, folder: Option<PathBuf>| {
        let (g, stats) = match folder {
            None => probe_variant(name, |_| {}, files),
            Some(folder) => {
                let (_, _) = probe_variant(name, |_| {}, files);
                let opts = LoadOptions {
                    settings_folders: vec![folder],
                    now: Some(NOW),
                    ..Default::default()
                };
                let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                    .join("mgmt-variants")
                    .join(name);
                load(&[out], &opts).unwrap()
            }
        };
        let fresh = run(&g, &stats);
        let sources = RunSources::from_analysis(&g, &stats);
        let reason = sources.hold_reason(&[source_key(DC01_PROBE)], &[]);
        let scope = ResolveScope::everything().with_sources(sources, &keys);
        (
            state::reconcile_scoped(&prev, &fresh, 2, false, &scope),
            reason,
            fresh,
        )
    };
    let held = |r: &state::Reconciled, what: &str| {
        for fp in &watched {
            assert!(
                !r.resolved.iter().any(|x| &x.fingerprint == fp),
                "{what}: {fp} resolved"
            );
        }
        assert!(r.counts.held >= 2, "{what}: {:?}", r.counts);
    };
    // No file: held, and the reason names the host's probe.
    let (r, reason, _) = reconcile("hold-p2", vec![], None);
    held(&r, "no file");
    let reason = reason.unwrap();
    assert!(reason.contains(DC01_PROBE), "{reason}");
    // An old file that shows nothing: it can't clear.
    let (r, _, _) = reconcile(
        "hold-p3",
        vec![(DC01_FILE, probe("DC01", OLD, agents(|_| {})))],
        None,
    );
    held(&r, "old file");
    // An old file that still shows them: still open.
    let (_, _, fresh) = reconcile(
        "hold-p3b",
        vec![(DC01_FILE, probe("DC01", OLD, shown()))],
        None,
    );
    assert!(fresh
        .iter()
        .any(|f| f.fingerprint == watched[0] || f.fingerprint == watched[1]));
    // A current file in a settings folder, owned by whoever runs the test
    // (no Tier Zero account): it can show an agent, not show one gone.
    let folder = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("probe-folder");
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join(DC01_FILE),
        serde_json::to_string(&probe("DC01", CURRENT, agents(|_| {}))).unwrap(),
    )
    .unwrap();
    let (r, _, _) = reconcile("hold-p4", vec![], Some(folder.clone()));
    held(&r, "unverified folder file");
    std::fs::write(
        folder.join(DC01_FILE),
        serde_json::to_string(&probe("DC01", CURRENT, shown())).unwrap(),
    )
    .unwrap();
    let (_, _, fresh) = reconcile("hold-p4b", vec![], Some(folder.clone()));
    let _ = std::fs::remove_dir_all(&folder);
    assert!(
        fresh.iter().any(|f| f.rule == "PW-039"),
        "an unverified file still shows VMware Tools"
    );
    // A current file with the collection that shows them gone: fixed.
    let (r, reason, _) = reconcile(
        "hold-p5",
        vec![(DC01_FILE, probe("DC01", CURRENT, agents(|_| {})))],
        None,
    );
    assert_eq!(reason, None);
    for fp in &watched {
        assert!(
            r.resolved.iter().any(|x| &x.fingerprint == fp),
            "{fp} not resolved"
        );
    }
}

/// The OpenSSH server on a domain controller adds a note to PW-023, whose
/// fingerprint stays the same.
#[test]
fn sshd_on_a_dc_adds_a_note_to_pw023() {
    let forest = dir("forest");
    let (g, stats) = load(std::slice::from_ref(&forest), &LoadOptions::default()).unwrap();
    let before = run(&g, &stats);
    let rdp = before.iter().find(|f| f.rule == "PW-023").unwrap();
    let files = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("probe-sshd");
    let _ = std::fs::remove_dir_all(&files);
    std::fs::create_dir_all(&files).unwrap();
    let mut p = probe(
        "DC01",
        CURRENT,
        agents(|a| a["sshd"] = json!({ "present": true, "start": 2, "error": null })),
    );
    p["domain"] = "contoso.local".into();
    p["dc"]["dns_name"] = "dc01.contoso.local".into();
    std::fs::write(
        files.join("pathwarden-tierzero-DC01.contoso.local.json"),
        serde_json::to_string(&p).unwrap(),
    )
    .unwrap();
    let opts = LoadOptions {
        now: Some(NOW),
        ..Default::default()
    };
    let (g, stats) = load(&[forest, files.clone()], &opts).unwrap();
    let _ = std::fs::remove_dir_all(&files);
    assert_eq!(
        stats.host_probes[0].matched.as_deref(),
        Some("DC01.CONTOSO.LOCAL")
    );
    let after = run(&g, &stats);
    let noted = after.iter().find(|f| f.rule == "PW-023").unwrap();
    assert_eq!(noted.fingerprint, rdp.fingerprint);
    assert!(
        noted
            .summary
            .contains("DC01.CONTOSO.LOCAL also runs an SSH server (sshd)"),
        "{}",
        noted.summary
    );
    assert!(noted.sources.is_empty(), "{:?}", noted.sources);
}

/// The variant `name` already written, read again with a settings folder
/// holding `files` (owned by whoever runs the test: no Tier Zero account,
/// so they are unverified).
fn reload_with_folder(name: &str, files: Vec<(&str, Value)>) -> (AdGraph, IngestStats) {
    let folder = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("probe-folders")
        .join(name);
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    for (file, doc) in files {
        std::fs::write(folder.join(file), serde_json::to_string(&doc).unwrap()).unwrap();
    }
    let opts = LoadOptions {
        settings_folders: vec![folder],
        now: Some(NOW),
        ..Default::default()
    };
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("mgmt-variants")
        .join(name);
    load(&[out], &opts).unwrap()
}

fn scom_names(servers: &[&str]) -> Value {
    agents(|a| {
        a["scom"] = json!({ "present": true, "error": null, "management_groups": [
            { "name": "MG2", "servers": servers }] });
    })
}

#[test]
fn an_old_or_unverified_file_never_makes_a_server_tier_zero() {
    // An old file of the collection.
    let (g, stats) = probe_variant(
        "probe-old-names",
        |_| {},
        vec![(
            DC01_FILE,
            probe("DC01", OLD, scom_names(&["scom02.mgmt.local"])),
        )],
    );
    assert!(!node(&g, "SCOM02.MGMT.LOCAL").tier_zero);
    assert!(!manages_from(&g).contains(&probe_edge("SCOM02.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let f = review(
        &all,
        "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown",
    );
    assert!(f.summary.contains("over 90 days old"), "{}", f.summary);
    assert!(f.summary.contains("(inferred"), "{}", f.summary);
    // A current file in a settings folder that nothing vouches for: the
    // Hyper-V host it names isn't Tier Zero either.
    probe_variant("probe-folder-names", |_| {}, vec![]);
    let hv = agents(|a| a["hyperv"] = json!({ "present": true, "host": "hv01", "error": null }));
    let (g, stats) = reload_with_folder(
        "probe-folder-names",
        vec![(DC01_FILE, probe("DC01", CURRENT, hv))],
    );
    assert_eq!(stats.host_probes.len(), 1, "{:?}", stats.skipped_files);
    assert!(!node(&g, "HV01.MGMT.LOCAL").tier_zero);
    assert!(manages_from(&g)
        .iter()
        .all(|(_, _, s)| s.as_deref() != Some(DC01_PROBE)));
    let all = run(&g, &stats);
    review(
        &all,
        "DC01.MGMT.LOCAL is a Hyper-V virtual machine, and its host is unknown",
    );
}

#[test]
fn an_unverified_newer_site_code_never_overrides() {
    let sccm = json!({
        "sites": [
            { "site_code": "P01", "owner": format!("{DOMAIN_SID}-1140") },
            { "site_code": "P02", "owner": format!("{DOMAIN_SID}-1102") },
        ],
        "management_points": [],
    });
    let site_servers = |f: &mut Files| {
        f.add_computer(1140, "CM02.MGMT.LOCAL");
        f.add_member("SCCM SITE SERVERS@MGMT.LOCAL", 1140, "Computer");
    };
    // The GPO names P02 (CM01's site); a forged newer file says P01.
    policy_variant_with(
        "probe-site-forged",
        Links::default(),
        Some(sidecar(&[(GPO_DC, ccm_setup("P02"))], Some(sccm))),
        site_servers,
        Vec::new(),
        Some(NOW),
    );
    let forged = probe(
        "DC01",
        CURRENT,
        agents(|a| a["sccm"] = json!({ "present": true, "site_code": "P01", "error": null })),
    );
    let (g, stats) = reload_with_folder("probe-site-forged", vec![(DC01_FILE, forged)]);
    assert!(node(&g, "CM01.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "CM02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("CM01"))
        .unwrap();
    assert!(f.summary.contains("site P02"), "{}", f.summary);
    // A forged file alone doesn't make a client's site server Tier Zero.
    let (g, _) = probe_variant("probe-client-forged", |_| {}, vec![]);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    let only = probe(
        "DC01",
        CURRENT,
        agents(|a| a["sccm"] = json!({ "present": true, "site_code": null, "error": null })),
    );
    let (g, stats) = reload_with_folder("probe-client-forged", vec![(DC01_FILE, only)]);
    assert!(!node(&g, "CM01.MGMT.LOCAL").tier_zero);
    review(
        &run(&g, &stats),
        "DC01.MGMT.LOCAL is an SCCM client, and its site server is unknown",
    );
}

#[test]
fn parts_merge_file_by_file() {
    let earlier = "2026-09-20T00:00:00Z";
    // A newer file couldn't read SCOM: the older full one still counts.
    let mut partial = probe("DC01", CURRENT, agents(|_| {}));
    partial["agents"]["scom"] = json!({ "present": false, "error": "Access is denied" });
    let (g, _) = probe_variant(
        "probe-partial",
        |_| {},
        vec![
            (
                "pathwarden-tierzero-DC01.json",
                probe("DC01", earlier, scom_names(&["scom02.mgmt.local"])),
            ),
            (DC01_FILE, partial),
        ],
    );
    assert!(node(&g, "SCOM02.MGMT.LOCAL").tier_zero);
    let c = pathwarden_core::hostprobe::completeness(&g);
    assert_eq!(
        c.line(),
        "Management agents read on Tier Zero computers: 1 of 1"
    );
    // Two trusted files that disagree: the newer one wins, both ways.
    let hv = |host: &str| {
        agents(|a| a["hyperv"] = json!({ "present": true, "host": host, "error": null }))
    };
    let (g, _) = probe_variant(
        "probe-disagree-1",
        |_| {},
        vec![
            (
                "pathwarden-tierzero-DC01.json",
                probe("DC01", earlier, hv("hv01")),
            ),
            (DC01_FILE, probe("DC01", CURRENT, agents(|_| {}))),
        ],
    );
    assert!(!node(&g, "HV01.MGMT.LOCAL").tier_zero);
    let (g, _) = probe_variant(
        "probe-disagree-2",
        |_| {},
        vec![
            (
                "pathwarden-tierzero-DC01.json",
                probe("DC01", earlier, agents(|_| {})),
            ),
            (DC01_FILE, probe("DC01", CURRENT, hv("hv01"))),
        ],
    );
    assert!(node(&g, "HV01.MGMT.LOCAL").tier_zero);
}

#[test]
fn confidence_comes_from_the_file_that_names_the_server() {
    // A trusted file names SCOM02; a newer unverified one names SCOM03.
    probe_variant(
        "probe-confidence",
        |f| f.add_computer(1161, "SCOM03.MGMT.LOCAL"),
        vec![(
            DC01_FILE,
            probe(
                "DC01",
                "2026-09-20T00:00:00Z",
                scom_names(&["scom02.mgmt.local"]),
            ),
        )],
    );
    let (g, stats) = reload_with_folder(
        "probe-confidence",
        vec![(
            DC01_FILE,
            probe("DC01", CURRENT, scom_names(&["scom03.mgmt.local"])),
        )],
    );
    assert!(node(&g, "SCOM02.MGMT.LOCAL").tier_zero);
    assert!(!node(&g, "SCOM03.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let f = rule(&all, "PW-025")
        .into_iter()
        .find(|f| f.title.starts_with("SCOM02"))
        .unwrap();
    assert!(f.summary.contains("(strong)"), "{}", f.summary);
    let r = review(
        &all,
        "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown",
    );
    assert!(r.summary.contains("scom03.mgmt.local"), "{}", r.summary);
    assert!(r.summary.contains("(inferred"), "{}", r.summary);
}

#[test]
fn a_named_server_whose_creator_is_unknown_is_only_reviewed() {
    // SharpHound data: who created SCOM02 isn't known.
    let (g, stats) = probe_variant_sharphound(
        "probe-sharphound",
        |_| {},
        vec![(
            DC01_FILE,
            probe("DC01", CURRENT, scom_names(&["scom02.mgmt.local"])),
        )],
    );
    assert!(!node(&g, "SCOM02.MGMT.LOCAL").tier_zero);
    assert!(!manages_from(&g).contains(&probe_edge("SCOM02.MGMT.LOCAL")));
    let all = run(&g, &stats);
    let r = review(
        &all,
        "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown",
    );
    assert!(r.summary.contains("machine account quota"), "{}", r.summary);
    assert!(r.summary.contains("(inferred"), "{}", r.summary);
    // The built-in collector shows SCOM02 was made through the quota.
    let mut side = sidecar(&[], None);
    side["machine_quota_computers"] = json!([format!("{DOMAIN_SID}-1160")]);
    let (g, stats) = policy_variant_with(
        "probe-quota",
        Links::default(),
        Some(side),
        |f| f.add_computer(1160, "SCOM02.MGMT.LOCAL"),
        vec![(
            DC01_FILE,
            probe("DC01", CURRENT, scom_names(&["scom02.mgmt.local"])),
        )],
        Some(NOW),
    );
    assert!(!node(&g, "SCOM02.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    let r = review(
        &all,
        "DC01.MGMT.LOCAL is a SCOM agent, and its management server is unknown",
    );
    assert!(
        r.summary
            .contains("created through the machine account quota"),
        "{}",
        r.summary
    );
}

#[test]
fn backup_agents_on_several_dcs_are_one_finding_per_product() {
    let veeam = || {
        agents(|a| {
            a["backup"] = json!({ "present": true, "error": null, "agents": [
                { "product": "Veeam", "service": "VeeamTransportSvc", "start": 2 }] });
        })
    };
    let (g, stats) = probe_variant(
        "probe-backup-many",
        |f| add_dc(f, 1170, "DC02.MGMT.LOCAL"),
        vec![
            (DC01_FILE, probe("DC01", CURRENT, veeam())),
            (
                "pathwarden-tierzero-DC02.mgmt.local.json",
                probe("DC02", CURRENT, veeam()),
            ),
        ],
    );
    let all = run(&g, &stats);
    let backups: Vec<&Finding> = all
        .iter()
        .filter(|f| f.rule == "PW-028" && f.title.contains("backup agent"))
        .collect();
    assert_eq!(backups.len(), 1, "{:?}", titles(&backups));
    let f = backups[0];
    assert_eq!(f.severity, Severity::Medium);
    assert!(
        f.summary
            .starts_with("2 Tier Zero computers run the Veeam backup agent"),
        "{}",
        f.summary
    );
    let mut sources = f.sources.clone();
    sources.sort();
    assert_eq!(
        sources,
        [DC01_PROBE, "Tier Zero host probe (DC02.MGMT.LOCAL)"]
    );
}

#[test]
fn unknown_backup_products_are_one_other_finding() {
    let a = agents(|a| {
        a["backup"] = json!({ "present": true, "error": null, "agents": [
            { "product": "Made Up One", "service": "Svc1", "start": 2 },
            { "product": "made up two", "service": "Svc2", "start": 2 },
            { "product": "veeam", "service": "VeeamTransportSvc", "start": 2 }] });
    });
    let (g, stats) = probe_variant(
        "probe-backup-other",
        |_| {},
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    let all = run(&g, &stats);
    let mut t: Vec<String> = all
        .iter()
        .filter(|f| f.rule == "PW-028" && f.title.contains("backup agent"))
        .map(|f| f.title.clone())
        .collect();
    t.sort();
    assert_eq!(
        t,
        [
            "Tier Zero computers in MGMT.LOCAL run other backup agents",
            "Tier Zero computers in MGMT.LOCAL run the Veeam backup agent",
        ]
    );
}

#[test]
fn an_unverified_files_wsus_url_is_no_pw038() {
    probe_variant("probe-wsus-forged", |_| {}, vec![]);
    let a = agents(|a| {
        a["wsus"] = json!({ "present": true, "server": "http://wsus01.mgmt.local:8530",
                            "use_wu_server": 1, "error": null });
    });
    let (g, stats) = reload_with_folder(
        "probe-wsus-forged",
        vec![(DC01_FILE, probe("DC01", CURRENT, a))],
    );
    assert!(!node(&g, "WSUS01.MGMT.LOCAL").tier_zero);
    let all = run(&g, &stats);
    assert!(rule(&all, "PW-038").is_empty());
    review(
        &all,
        "DC01.MGMT.LOCAL takes its updates from a WSUS server Pathwarden can't confirm",
    );
}
