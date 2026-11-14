//! Cypher `name` answers what BloodHound CE has: a name a
//! record gave, never one Pathwarden made up for display (a well-known
//! group's name, a SID or an ID), and an OpenGraph name in the case its file
//! wrote.

use std::path::PathBuf;

use pathwarden_core::cypher::{self, AdGraphView, EvalLimits};
use pathwarden_core::{load, LoadOptions};

const D: &str = "S-1-5-21-3000-3000-3000";

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

/// A fresh temp dir for one test's fixture.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cypher-names-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `testdata/opengraph/ad`, with DAVE's record written without a `name`
/// and ERIN's (1103) with no properties at all.
fn ad_without_names() -> PathBuf {
    let dir = temp_dir("ad");
    for f in std::fs::read_dir(testdata("opengraph/ad")).unwrap() {
        let f = f.unwrap().path();
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        for rec in doc["data"].as_array_mut().unwrap() {
            match rec["ObjectIdentifier"].as_str() {
                Some(id) if id == format!("{D}-1104") => {
                    rec["Properties"].as_object_mut().unwrap().remove("name");
                }
                Some(id) if id == format!("{D}-1103") && rec["Properties"].is_object() => {
                    rec["Properties"] = serde_json::json!({});
                }
                _ => {}
            }
        }
        std::fs::write(dir.join(f.file_name().unwrap()), doc.to_string()).unwrap();
    }
    dir
}

fn count(inputs: &[PathBuf], all_properties: bool, query: &str) -> usize {
    let opts = LoadOptions {
        all_properties,
        ..LoadOptions::default()
    };
    let g = load(inputs, &opts).unwrap().0;
    let view = AdGraphView::new(&g);
    cypher::run(&view, query, &EvalLimits::default())
        .unwrap_or_else(|e| panic!("{query}: {e}"))
        .node_ids()
        .len()
}

/// Domain Computers (-515) and Domain Controllers (-516) are only
/// referenced: Pathwarden names them for display, BHE has no name.
#[test]
fn an_uncollected_well_known_group_has_no_name() {
    // Pathwarden does show a name for it.
    let g = load(&[testdata("opengraph/ad")], &LoadOptions::default())
        .unwrap()
        .0;
    let ix = g.lookup(&format!("{D}-515")).unwrap();
    assert_eq!(g.node(ix).name, "DOMAIN COMPUTERS@CORP.LOCAL");
    for kept in [false, true] {
        let ad = [testdata("opengraph/ad")];
        for rid in ["515", "516"] {
            let q = format!(
                "MATCH (n) WHERE n.objectid ENDS WITH '-{rid}' AND n.name IS NULL RETURN n"
            );
            assert_eq!(count(&ad, kept, &q), 1, "{q} kept={kept}");
        }
        assert_eq!(
            count(
                &ad,
                kept,
                "MATCH (n) WHERE n.name = 'DOMAIN COMPUTERS@CORP.LOCAL' RETURN n"
            ),
            0,
            "kept={kept}"
        );
        // A collected group keeps its record's name.
        assert_eq!(
            count(
                &ad,
                kept,
                "MATCH (n) WHERE n.name = 'DOMAIN ADMINS@CORP.LOCAL' RETURN n"
            ),
            1,
            "kept={kept}"
        );
    }
}

/// A record written without a `name` answers null, not its SID.
#[test]
fn a_record_without_a_name_has_none() {
    let dir = ad_without_names();
    for kept in [false, true] {
        for rid in ["1103", "1104"] {
            let q = format!("MATCH (n) WHERE n.objectid = '{D}-{rid}' AND n.name IS NULL RETURN n");
            assert_eq!(
                count(std::slice::from_ref(&dir), kept, &q),
                1,
                "{q} kept={kept}"
            );
            let q = format!("MATCH (n) WHERE n.name = '{D}-{rid}' RETURN n");
            assert_eq!(
                count(std::slice::from_ref(&dir), kept, &q),
                0,
                "{q} kept={kept}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// OpenGraph names come back as the file wrote them.
#[test]
fn an_opengraph_name_keeps_its_case() {
    for kept in [false, true] {
        let widget = [testdata("opengraph/ad"), testdata("opengraph/widgethound")];
        assert_eq!(
            count(
                &widget,
                kept,
                "MATCH (n) WHERE n.name = 'Widget console' RETURN n"
            ),
            1,
            "kept={kept}"
        );
        let mssql = [testdata("forest"), testdata("opengraph/mssqlhound")];
        assert_eq!(
            count(&mssql, kept, "MATCH (n) WHERE n.name = 'sa' RETURN n"),
            1,
            "kept={kept}"
        );
    }
}

/// An OpenGraph edge to a SID no data described, an OpenGraph node of an AD
/// kind written without a name, and an external one without a name: none
/// has a name in BHE, though Pathwarden shows one (a well-known group's
/// name, the SID, the ID).
#[test]
fn opengraph_objects_nobody_named_have_no_name() {
    // widgethound, plus an edge to CORP's Key Admins (-526, which no data
    // collected), a nameless User and a nameless widget.
    let dir = temp_dir("og");
    let src = testdata("opengraph/widgethound/widgethound.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(src).unwrap()).unwrap();
    let graph = &mut doc["graph"];
    graph["nodes"].as_array_mut().unwrap().extend([
        serde_json::json!({"id": "S-1-5-21-1000-1000-1000-1105", "kinds": ["User"],
            "properties": {"enabled": true}}),
        serde_json::json!({"id": "WIDGET-AGENT-9", "kinds": ["WH_Agent"], "properties": {}}),
    ]);
    graph["edges"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kind": "WH_Manages",
            "start": {"value": "WIDGET-CONSOLE-1", "match_by": "id"},
            "end": {"value": format!("{D}-526"), "match_by": "id"},
            "properties": {}
        }));
    std::fs::write(dir.join("widgethound.json"), doc.to_string()).unwrap();
    let inputs = [testdata("opengraph/ad"), dir.clone()];
    let w = "S-1-5-21-1000-1000-1000";
    for kept in [false, true] {
        let n = |q: &str| count(&inputs, kept, q);
        let null =
            |id: &str| format!("MATCH (n) WHERE n.objectid = '{id}' AND n.name IS NULL RETURN n");
        let named = |name: &str| format!("MATCH (n) WHERE n.name = '{name}' RETURN n");
        // Key Admins, named by an edge only.
        assert_eq!(n(&null(&format!("{D}-526"))), 1, "kept={kept}");
        assert_eq!(n(&named("KEY ADMINS@CORP.LOCAL")), 0, "kept={kept}");
        // SIDs only widgethound's edges name.
        assert_eq!(n(&named(&format!("DOMAIN ADMINS@{w}"))), 0, "kept={kept}");
        assert_eq!(n(&named(&format!("{w}-1000"))), 0, "kept={kept}");
        assert_eq!(n(&null(&format!("{w}-512"))), 1, "kept={kept}");
        // Nodes written without a name.
        assert_eq!(n(&named(&format!("{w}-1105"))), 0, "kept={kept}");
        assert_eq!(n(&null(&format!("{w}-1105"))), 1, "kept={kept}");
        assert_eq!(n(&named("WIDGET-AGENT-9")), 0, "kept={kept}");
        assert_eq!(n(&null("WIDGET-AGENT-9")), 1, "kept={kept}");
        // What the file named keeps its name, as written.
        assert_eq!(n(&named("Widget console")), 1, "kept={kept}");
        assert_eq!(n(&named("WIDGET-CONSOLE-1")), 0, "kept={kept}");
        assert_eq!(n(&named("DA_ALICE@CONTOSO.LOCAL")), 1, "kept={kept}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An AzureHound object whose record gave no name answers null, not its
/// ID; named ones answer their (upper-cased) name.
#[test]
fn an_azurehound_record_without_a_name_has_none() {
    let dir = temp_dir("az");
    let src = testdata("entra/azurehound/azurehound_hybrid.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(src).unwrap()).unwrap();
    let bob = "aaaaaaaa-0000-0000-0000-000000000002";
    for rec in doc["data"].as_array_mut().unwrap() {
        if rec["kind"] == "AZUser" && rec["data"]["id"] == bob {
            let data = rec["data"].as_object_mut().unwrap();
            data.remove("userPrincipalName");
            data.remove("displayName");
        }
    }
    std::fs::write(dir.join("azurehound_hybrid.json"), doc.to_string()).unwrap();
    let inputs = [testdata("entra/ad"), dir.clone()];
    let bob = bob.to_ascii_uppercase();
    for kept in [false, true] {
        let n = |q: &str| count(&inputs, kept, q);
        assert_eq!(
            n(&format!(
                "MATCH (n) WHERE n.objectid = '{bob}' AND n.name IS NULL RETURN n"
            )),
            1,
            "kept={kept}"
        );
        assert_eq!(
            n(&format!("MATCH (n) WHERE n.name = '{bob}' RETURN n")),
            0,
            "kept={kept}"
        );
        assert_eq!(
            n("MATCH (n:AZUser) WHERE n.name = 'ALICE@HYBRID.LOCAL' RETURN n"),
            1,
            "kept={kept}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// BloodHound CE's names for AzureHound objects: a tenant answers its
/// display name (Pathwarden shows its default domain); a user without a UPN
/// and an application without a publisher domain answer null, not a name
/// Pathwarden makes up for display.
#[test]
fn azurehound_names_are_bloodhound_ce_s() {
    let dir = temp_dir("az-bh");
    let src = testdata("entra/azurehound/azurehound_hybrid.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(src).unwrap()).unwrap();
    let carol = "aaaaaaaa-0000-0000-0000-000000000004";
    let app = "aaaaaaaa-0000-0000-0000-000000000200";
    for rec in doc["data"].as_array_mut().unwrap() {
        if rec["kind"] == "AZUser" && rec["data"]["id"] == carol {
            rec["data"]
                .as_object_mut()
                .unwrap()
                .remove("userPrincipalName");
        }
        if rec["kind"] == "AZApp" && rec["data"]["appId"] == app {
            rec["data"]
                .as_object_mut()
                .unwrap()
                .remove("publisherDomain");
        }
    }
    std::fs::write(dir.join("azurehound_hybrid.json"), doc.to_string()).unwrap();
    let inputs = [testdata("entra/ad"), dir.clone()];
    for kept in [false, true] {
        let n = |q: &str| count(&inputs, kept, q);
        assert_eq!(
            n("MATCH (n:AZTenant) WHERE n.name = 'HYBRID CORP' RETURN n"),
            1,
            "kept={kept}"
        );
        assert_eq!(
            n("MATCH (n:AZTenant) WHERE n.name = 'HYBRID.ONMICROSOFT.COM' RETURN n"),
            0,
            "kept={kept}"
        );
        let null = |id: &str| {
            format!(
                "MATCH (n) WHERE n.objectid = '{}' AND n.name IS NULL RETURN n",
                id.to_ascii_uppercase()
            )
        };
        assert_eq!(n(&null(carol)), 1, "kept={kept}");
        assert_eq!(n(&null(app)), 1, "kept={kept}");
        // The others keep their names.
        assert_eq!(
            n("MATCH (n:AZUser) WHERE n.name = 'ALICE@HYBRID.LOCAL' RETURN n"),
            1,
            "kept={kept}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A trust names a domain no data collected: BHE writes TargetDomainName
/// onto it, so it answers that name.
#[test]
fn a_trust_names_its_uncollected_target() {
    for kept in [false, true] {
        assert_eq!(
            count(
                &[testdata("forest")],
                kept,
                "MATCH (n:Domain) WHERE n.name = 'FABRIKAM.COM' RETURN n"
            ),
            1,
            "kept={kept}"
        );
    }
}
