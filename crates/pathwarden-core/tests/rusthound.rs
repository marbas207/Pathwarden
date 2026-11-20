//! RustHound-CE's data shapes, against `testdata/rusthound`: objects trimmed
//! (user, group, computer and domain ACEs dropped) from a real RustHound-CE
//! 2.5.23 collection of the GOAD lab's essos.local, made by Pathwarden's
//! built-in collector before its fixes, plus sevenkingdoms.local's domain
//! object (the forest trust to essos). What it shows:
//!
//! - Certificate templates have an empty ObjectIdentifier; their objectGUID
//!   names them.
//! - ESSOS-CA lists 18 published templates, all with an empty identifier.
//! - sevenkingdoms' trust to essos has TrustAttributes 0x48 (forest trust with
//!   SID history enabled) but SidFilteringEnabled true.
//! - SEVENKINGDOMS$ is an interdomain trust account (userAccountControl
//!   0x820, PASSWD_NOTREQD by design).
//! - gmsaDragon$ (taken from a later RustHound-CE 2.5.25 collection of the
//!   same lab, ACEs dropped) is a gMSA typed as a user, with SPNs, no `gmsa`
//!   flag and userAccountControl 0x1000.
//! - No certificate policies on templates, no issuance policy group links,
//!   no CA registry values.

use std::path::PathBuf;

use pathwarden_core::adcs::Esc;
use pathwarden_core::analyze;
use pathwarden_core::findings::{self, Context, RuleSettings};
use pathwarden_core::model::{EdgeKind, NodeKind};
use pathwarden_core::posture;
use pathwarden_core::{load, AdGraph, IngestStats, LoadOptions};

fn fixture() -> (AdGraph, IngestStats) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
    load(&[dir], &LoadOptions::default()).expect("fixture loads")
}

fn one(g: &AdGraph, name: &str) -> pathwarden_core::NodeIndex {
    match g.find(name).as_slice() {
        [ix] => *ix,
        other => panic!("{name}: {} matches", other.len()),
    }
}

#[test]
fn templates_without_object_identifier_are_ingested_by_guid() {
    let (g, stats) = fixture();
    assert_eq!(
        stats.objects.get("CertTemplate"),
        Some(&4),
        "{:?}",
        stats.objects
    );
    let esc1 = one(&g, "ESC1@ESSOS.LOCAL");
    assert_eq!(g.node(esc1).id, "ED645827-CB42-459D-BE7E-B2001503BD2D");
    assert_eq!(g.node(esc1).kind, NodeKind::CertTemplate);
}

#[test]
fn unresolved_publication_counts_every_forest_template_and_says_so() {
    let (g, _) = fixture();
    // The root and AIA CA objects share the name.
    let ca = g
        .find("ESSOS-CA@ESSOS.LOCAL")
        .into_iter()
        .find(|&ix| g.node(ix).kind == NodeKind::EnterpriseCa)
        .unwrap();
    let published = g
        .inner()
        .edges_directed(ca, petgraph::Direction::Incoming)
        .filter(|e| *e.weight() == EdgeKind::PublishedTo)
        .count();
    assert_eq!(published, 4);
    let c = posture::adcs_completeness(&g);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].ca, "ESSOS-CA@ESSOS.LOCAL");
    assert!(!c[0].published_templates);
    assert!(
        !c[0].esc6,
        "RustHound-CE's CA registry placeholders are not data"
    );
    assert!(!c[0].esc13, "no certificate policies were collected");
}

#[test]
fn goad_essos_adcs_paths_are_found() {
    let (g, _) = fixture();
    let found = |esc: Esc, template: &str| {
        g.esc_instances()
            .iter()
            .any(|i| i.esc == esc && i.template.is_some_and(|t| g.node(t).name == template))
    };
    assert!(found(Esc::Esc1, "ESC1@ESSOS.LOCAL"));
    assert!(found(Esc::Esc4, "ESC4@ESSOS.LOCAL"));
    // ESC6 is never asserted from RustHound-CE's placeholder registry block.
    assert!(!g.esc_instances().iter().any(|i| i.esc == Esc::Esc6a));
}

fn rule(g: &AdGraph, stats: &IngestStats, id: &str) -> Vec<findings::Finding> {
    let settings = RuleSettings::default();
    let ctx = Context::new(g, &stats.trusts, &settings);
    findings::evaluate(&ctx, &[])
        .into_iter()
        .filter(|f| f.rule == id)
        .collect()
}

#[test]
fn forest_trust_with_sid_history_is_reported_from_trust_attributes() {
    let (g, stats) = fixture();
    let pw012 = rule(&g, &stats, "PW-012");
    let titles: Vec<&str> = pw012.iter().map(|f| f.title.as_str()).collect();
    // sevenkingdoms' side (0x48) only; essos' side (0x8) filters SIDs.
    assert_eq!(
        titles,
        ["Trust SEVENKINGDOMS.LOCAL → ESSOS.LOCAL lets SID history through (SID filtering relaxed)"]
    );
    // The attributes are known, so it says so firmly.
    assert_eq!(pw012[0].severity, findings::Severity::High);
    assert!(
        pw012[0]
            .summary
            .contains("filters only the built-in and privileged SIDs (RIDs under 1000)"),
        "{}",
        pw012[0].summary
    );
}

#[test]
fn trust_accounts_are_not_empty_password_accounts() {
    let (g, stats) = fixture();
    let ix = one(&g, "SEVENKINGDOMS$@ESSOS.LOCAL");
    assert_eq!(g.node(ix).props.passwordnotreqd, Some(true));
    assert_eq!(g.node(ix).props.trustaccount, Some(true));
    assert!(rule(&g, &stats, "PW-013").is_empty());
}

/// RustHound-CE types gmsaDragon$ as a user with SPNs and no `gmsa` flag;
/// userAccountControl 0x1000 marks it as a gMSA, whose password can't be
/// cracked. The trust account (0x820) and ordinary users are not marked.
#[test]
fn gmsa_is_recognised_and_not_kerberoastable() {
    let (g, stats) = fixture();
    let gmsa = one(&g, "GMSADRAGON$@ESSOS.LOCAL");
    assert_eq!(g.node(gmsa).kind, NodeKind::User);
    assert_eq!(g.node(gmsa).props.hasspn, Some(true));
    assert_eq!(g.node(gmsa).props.managedpassword, Some(true));
    for name in ["SEVENKINGDOMS$@ESSOS.LOCAL", "ADMINISTRATOR@ESSOS.LOCAL"] {
        assert_eq!(g.node(one(&g, name)).props.managedpassword, None, "{name}");
    }
    assert!(rule(&g, &stats, "PW-006").iter().all(|f| f
        .affected
        .iter()
        .all(|a| a.name != "GMSADRAGON$@ESSOS.LOCAL")));
}

/// What the built-in collector now adds to RustHound-CE's output for ESC13
/// (templates' `certificatepolicy`, the issuance policy's `GroupLink`, in
/// SharpHound's shape) makes the GOAD ESC13 template a finding.
#[test]
fn esc13_with_the_collector_patch() {
    const POLICY: &str =
        "1.3.6.1.4.1.311.21.8.15379420.11269011.1329286.12020410.14802519.153.15694297.71523850";
    const GREATMASTER: &str = "S-1-5-21-907917752-839331996-494631781-1106";
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
    let dir = std::env::temp_dir().join(format!("pw-rusthound-esc13-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for o in doc["data"].as_array_mut().unwrap() {
            if name.ends_with("_certtemplates.json") {
                let policies = if o["Properties"]["name"] == "ESC13@ESSOS.LOCAL" {
                    serde_json::json!([POLICY])
                } else {
                    serde_json::json!([])
                };
                o["Properties"]["certificatepolicy"] = policies;
            } else if name.ends_with("_issuancepolicies.json") {
                o["GroupLink"] =
                    serde_json::json!({"ObjectIdentifier": GREATMASTER, "ObjectType": "Group"});
            }
        }
        std::fs::write(dir.join(&name), serde_json::to_vec(&doc).unwrap()).unwrap();
    }
    let (g, _) = load(std::slice::from_ref(&dir), &LoadOptions::default()).expect("loads");
    let _ = std::fs::remove_dir_all(&dir);
    let esc13 = g
        .esc_instances()
        .iter()
        .find(|i| i.esc == Esc::Esc13)
        .expect("ESC13");
    assert_eq!(g.node(esc13.template.unwrap()).name, "ESC13@ESSOS.LOCAL");
    assert_eq!(
        g.node(esc13.related.unwrap()).name,
        "GREATMASTER@ESSOS.LOCAL"
    );
    assert!(posture::adcs_completeness(&g)[0].esc13);
}

/// RustHound-CE's object for a trusted domain, as it writes one beside the
/// collected domain: name and SID from the trust, no trusts, ACEs or
/// children of its own, and `collected` false.
fn trusted_domain(name: &str, sid: &str) -> serde_json::Value {
    serde_json::json!({
        "Properties": {
            "domain": name, "name": name, "domainsid": "",
            "distinguishedname": format!("DC={}", name.replace('.', ",DC=")),
            "highvalue": true, "collected": false,
        },
        "Aces": [], "ChildObjects": [], "Trusts": [], "Links": [],
        "ObjectIdentifier": sid, "IsDeleted": false, "IsACLProtected": false,
    })
}

const SEVENKINGDOMS_SID: &str = "S-1-5-21-1821261621-2407627684-1290984713";
const ESSOS_SID: &str = "S-1-5-21-907917752-839331996-494631781";

/// The fixture copied to a temporary folder, `edit` applied to each file's
/// JSON (with the file's name), and loaded.
fn edited(
    tag: &str,
    edit: impl Fn(&str, &mut serde_json::Value) -> bool,
) -> (AdGraph, IngestStats) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
    let dir = std::env::temp_dir().join(format!("pw-rusthound-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if edit(&name, &mut doc) {
            std::fs::write(dir.join(&name), serde_json::to_vec(&doc).unwrap()).unwrap();
        }
    }
    let loaded = load(std::slice::from_ref(&dir), &LoadOptions::default()).expect("loads");
    let _ = std::fs::remove_dir_all(&dir);
    loaded
}

/// The essos collection as RustHound-CE writes it: its domains file also
/// holds a not-collected object for the trusted sevenkingdoms.
/// `with_sevenkingdoms` keeps sevenkingdoms' own (collected) domain object.
fn essos_with_trust(tag: &str, with_sevenkingdoms: bool) -> (AdGraph, IngestStats) {
    edited(tag, |name, doc| {
        if name.ends_with("essos-local_domains.json") {
            let data = doc["data"].as_array_mut().unwrap();
            data.push(trusted_domain("SEVENKINGDOMS.LOCAL", SEVENKINGDOMS_SID));
            doc["meta"]["count"] = data.len().into();
        }
        with_sevenkingdoms || !name.contains("sevenkingdoms")
    })
}

/// A trusted domain's object stays in the graph, but only the collected
/// domain counts as collected (one domain with 13 trusts was
/// named "X and 13 more forests, 15 domains").
#[test]
fn trusted_domain_objects_are_not_collected_domains() {
    let (g, _) = essos_with_trust("trusted", false);
    assert_eq!(analyze::domain_names(&g), ["ESSOS.LOCAL"]);
    assert_eq!(analyze::trusted_domain_names(&g), ["SEVENKINGDOMS.LOCAL"]);
    assert_eq!(
        analyze::known_domain_names(&g),
        ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]
    );
    let seven = g.node(one(&g, "SEVENKINGDOMS.LOCAL"));
    assert!(!seven.placeholder, "kept in the graph for the trust");
    assert_eq!(seven.kind, NodeKind::Domain);
}

/// Both collections loaded together: one's not-collected object for the
/// other does not hide that the other was collected.
#[test]
fn a_trusted_domain_collected_too_counts() {
    let (g, _) = essos_with_trust("both", true);
    assert_eq!(
        analyze::domain_names(&g),
        ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]
    );
    assert!(analyze::trusted_domain_names(&g).is_empty());
}

/// A domain object marked not collected whose users and computers are in
/// the data was collected all the same.
#[test]
fn a_domain_with_collected_principals_counts() {
    let (g, _) = edited("flag", |name, doc| {
        if name.ends_with("_domains.json") {
            doc["data"] = serde_json::json!([trusted_domain("ESSOS.LOCAL", ESSOS_SID)]);
        }
        !name.contains("sevenkingdoms")
    });
    assert_eq!(analyze::domain_names(&g), ["ESSOS.LOCAL"]);
    assert!(analyze::trusted_domain_names(&g).is_empty());
}
