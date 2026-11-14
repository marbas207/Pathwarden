//! The MSSQLHound and ConfigManBearPig packs: paths to Tier
//! Zero through SQL Server and SCCM once a pack is trusted, context edges
//! that never make paths, and the corrections Pathwarden applies to each
//! collector's known bugs.
//!
//! Fixtures (`testdata/opengraph/`, written by
//! `scripts/gen_opengraph_fixtures.py` in the shape of the tools' real
//! output) against the CORP.LOCAL AD fixture (`ad/`):
//! - `mssqlhound_corp/`: WS01:1433 runs as SVC_BACKUP (a Domain Admin);
//!   ALICE is sysadmin; DAVE is denied CONTROL SERVER but in a role that
//!   grants it; CAROL's sysadmin login is disabled; two TRUSTWORTHY
//!   databases, one owned by a login that controls nothing. APP01:1433
//!   grants impersonation of a sysadmin to `public`, has a login with
//!   IMPERSONATE ANY LOGIN, and linked servers both ways (one measured under
//!   another mapping). APP01:1434's only admin login is disabled.
//! - `configmanbearpig/`: site PS1 manages DC01 and APP01. ALICE is Full
//!   Administrator over them, BOB has every permission on the site, CAROL
//!   is sysadmin on the site database. Assumed relay, co-location and
//!   "possible client" edges, user affinity, native edges.
//! - `configmanbearpig_other/`: another hierarchy, also PS1, in another
//!   collection, where DAVE administers WS01.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

use pathwarden_core::analysis;
use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::config::Config;
use pathwarden_core::findings::{self, fingerprint};
use pathwarden_core::model::EdgeKind;
use pathwarden_core::AdGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

const D: &str = "S-1-5-21-3000-3000-3000";

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn analyze(inputs: &[&str], trust: &[&str]) -> Analysis {
    let cfg = if trust.is_empty() {
        Config::default()
    } else {
        let list: Vec<String> = trust.iter().map(|t| format!("\"{t}\"")).collect();
        Config::parse(&format!("[opengraph]\ntrust = [{}]\n", list.join(", "))).unwrap()
    };
    let inputs: Vec<PathBuf> = inputs.iter().map(|i| testdata(i)).collect();
    analyze::run(&inputs, &cfg, &[], &mut analyze::Quiet).unwrap()
}

fn ix(g: &AdGraph, id: &str) -> NodeIndex {
    g.lookup(id)
        .unwrap_or_else(|| panic!("{id} not in the graph"))
}

fn user(g: &AdGraph, rid: u32) -> NodeIndex {
    ix(g, &format!("{D}-{rid}"))
}

/// The kinds of the edges `from -> to`.
fn kinds(g: &AdGraph, from: NodeIndex, to: NodeIndex) -> Vec<String> {
    g.inner()
        .edges_connecting(from, to)
        .map(|e| e.weight().as_str().to_string())
        .collect()
}

/// Whether `to` is reachable from `from` through traversable edges.
fn reaches(g: &AdGraph, from: NodeIndex, to: NodeIndex) -> bool {
    let mut seen = HashSet::from([from]);
    let mut queue = VecDeque::from([from]);
    while let Some(u) = queue.pop_front() {
        if u == to {
            return true;
        }
        for e in g.inner().edges_directed(u, Direction::Outgoing) {
            if g.traversable(*e.weight(), e.target()) && seen.insert(e.target()) {
                queue.push_back(e.target());
            }
        }
    }
    false
}

fn rule<'a>(a: &'a Analysis, id: &str) -> Vec<&'a findings::Finding> {
    a.findings.iter().filter(|f| f.rule == id).collect()
}

/// Every edge an OpenGraph file added that is traversable.
fn traversable_og(g: &AdGraph) -> Vec<String> {
    g.inner()
        .edge_references()
        .filter(|e| g.edge_origin(e.id()).is_some() && g.traversable(*e.weight(), e.target()))
        .map(|e| e.weight().as_str().to_string())
        .collect()
}

// ------------------------------------------------------------ MSSQLHound

const SQL: &[&str] = &["opengraph/ad", "opengraph/mssqlhound_corp"];

fn ws01_sql() -> String {
    format!("{D}-1002:1433")
}

fn app01_sql() -> String {
    format!("{D}-1001:1433")
}

#[test]
fn sql_is_context_only_until_the_pack_is_trusted() {
    let a = analyze(SQL, &[]);
    let s = &a.stats.opengraph.sources[0];
    assert_eq!(s.pack.as_deref(), Some("mssqlhound"));
    assert!(!s.trusted);
    assert!(traversable_og(&a.graph).is_empty());
    assert!(rule(&a, "PW-034").is_empty() && rule(&a, "PW-030").is_empty());
    // The corrections still ran (they only label).
    assert!(!a.stats.opengraph.corrections.is_empty());
}

#[test]
fn a_sql_server_running_as_tier_zero_is_a_path_and_pw034() {
    let a = analyze(SQL, &["mssqlhound"]);
    let g = &a.graph;
    let alice = user(g, 1101);
    let svc = user(g, 1201);
    let server = ix(g, &ws01_sql());

    // ALICE -HasLogin-> login -MemberOf-> sysadmin -ControlServer->
    // WS01:1433 -RunsAs-> SVC_BACKUP (Domain Admins); or, as short, through
    // the TRUSTWORTHY database her login owns.
    let path = analysis::path_to_tier_zero(g, alice).expect("a path through SQL Server");
    let steps: Vec<&str> = path.steps.iter().map(|s| s.edge.as_str()).collect();
    assert!(
        steps
            == [
                "MSSQL_HasLogin",
                "MSSQL_MemberOf",
                "MSSQL_ControlServer",
                "MSSQL_RunsAs"
            ]
            || steps
                == [
                    "MSSQL_HasLogin",
                    "MSSQL_Owns",
                    "MSSQL_ExecuteAsOwner",
                    "MSSQL_RunsAs"
                ],
        "{steps:?}"
    );
    let login = ix(g, &format!("CORP\\ALICE@{}", ws01_sql()));
    let sysadmin = ix(g, &format!("SYSADMIN@{}", ws01_sql()));
    assert!(reaches(g, login, sysadmin) && reaches(g, sysadmin, server));
    assert_eq!(path.target, "SVC_BACKUP@CORP.LOCAL");
    assert!(path
        .steps
        .iter()
        .all(|s| s.source.as_deref() == Some("MSSQL_Base")));
    assert_eq!(kinds(g, server, svc), ["MSSQL_RunsAs"]);

    let found = rule(&a, "PW-034");
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = found[0];
    assert_eq!(
        f.fingerprint,
        fingerprint("PW-034", &[&ws01_sql(), &format!("{D}-1201")])
    );
    assert!(f.summary.contains("ALICE@CORP.LOCAL"), "{}", f.summary);
    assert!(
        f.remediation.contains("group managed service account"),
        "{}",
        f.remediation
    );
    assert_eq!(f.sources, ["MSSQL_Base"]);
    assert!(f.severity >= findings::Severity::High);
    // PW-034 reports the run-as edge; PW-030 doesn't repeat it.
    assert!(rule(&a, "PW-030").is_empty(), "{:#?}", rule(&a, "PW-030"));

    // A forged MSSQL_RunsAs in a file is context only: Pathwarden derives
    // it, the collector never writes it.
    let forged = ix(g, &app01_sql());
    assert_eq!(kinds(g, forged, svc), ["MSSQL_RunsAs (context)"]);
}

#[test]
fn mssql_corrections() {
    let a = analyze(SQL, &["mssqlhound"]);
    let g = &a.graph;
    let ws01 = ix(g, &ws01_sql());
    let app01 = ix(g, &app01_sql());

    // DENY wins over a role's GRANT: DAVE's membership of opsrole (whose
    // only control is CONTROL SERVER, which he is denied) is context, so
    // DAVE doesn't control WS01:1433.
    let dave_login = ix(g, &format!("CORP\\DAVE@{}", ws01_sql()));
    let opsrole = ix(g, &format!("OPSROLE@{}", ws01_sql()));
    assert_eq!(kinds(g, dave_login, opsrole), ["MSSQL_MemberOf (context)"]);
    assert!(!reaches(g, user(g, 1104), ws01));

    // public: BOB has no role, but every login is in public, and public may
    // impersonate a sysadmin on APP01:1433.
    let bob_login = ix(g, &format!("CORP\\BOB@{}", app01_sql()));
    let public = ix(g, &format!("PUBLIC@{}", app01_sql()));
    assert_eq!(kinds(g, bob_login, public), ["MSSQL_PublicMember"]);
    assert!(reaches(g, user(g, 1102), app01));
    // MSSQLHound's own membership edge to public is re-kinded: the plan
    // can't cut it.
    let alice_login = ix(g, &format!("CORP\\ALICE@{}", ws01_sql()));
    let ws_public = ix(g, &format!("PUBLIC@{}", ws01_sql()));
    assert_eq!(kinds(g, alice_login, ws_public), ["MSSQL_PublicMember"]);
    assert!(a
        .plan
        .fixes
        .iter()
        .all(|f| f.edges.iter().all(|e| e.as_str() != "MSSQL_PublicMember")));

    // IMPERSONATE ANY LOGIN is a path, whatever MSSQLHound's schema says.
    let dave_app = ix(g, &format!("CORP\\DAVE@{}", app01_sql()));
    assert_eq!(kinds(g, dave_app, app01), ["MSSQL_ImpersonateAnyLogin"]);
    assert!(g.traversable(
        g.inner()[g.inner().find_edge(dave_app, app01).unwrap()],
        app01
    ));
    assert!(reaches(g, user(g, 1104), app01));

    // A disabled login is no way in.
    let carol_login = ix(g, &format!("CORP\\CAROL@{}", ws01_sql()));
    assert_eq!(
        kinds(g, user(g, 1103), carol_login),
        ["MSSQL_HasLogin (context)"]
    );

    // TRUSTWORTHY: kept where the owner controls the server, context where
    // it doesn't.
    let app_db = ix(g, &format!("{}\\APPDB", ws01_sql()));
    let ops_db = ix(g, &format!("{}\\OPSDB", ws01_sql()));
    let app_db_kinds = kinds(g, app_db, ws01);
    assert!(app_db_kinds.contains(&"MSSQL_ExecuteAsOwner (context)".to_string()));
    assert!(!app_db_kinds.contains(&"MSSQL_ExecuteAsOwner".to_string()));
    assert_eq!(kinds(g, ops_db, ws01), ["MSSQL_ExecuteAsOwner"]);
    assert!(!reaches(g, app_db, ws01));

    // GetAdminTGS: kept on WS01:1433 (ALICE's login is enabled), context on
    // APP01:1434 (its only admin login is disabled).
    let reports = ix(g, &format!("{D}-1001:1434"));
    assert!(kinds(g, user(g, 1201), ws01).contains(&"MSSQL_GetAdminTGS".to_string()));
    let to_reports = kinds(g, user(g, 1104), reports);
    assert!(to_reports.contains(&"MSSQL_GetAdminTGS (context)".to_string()));
    assert!(!to_reports.contains(&"MSSQL_GetAdminTGS".to_string()));

    // Linked servers: a path when the remote rights were measured under the
    // mapping's own login; context when measured under another.
    assert!(kinds(g, ws01, app01).contains(&"MSSQL_LinkedAsAdmin".to_string()));
    assert!(kinds(g, app01, ws01).contains(&"MSSQL_LinkedAsAdmin (context)".to_string()));

    let notes = a.stats.opengraph.corrections.join("\n");
    for want in ["DENY", "public", "ExecuteAsOwner", "GetAdminTGS", "RunsAs"] {
        assert!(notes.contains(want), "{want}: {notes}");
    }
}

#[test]
fn sql_context_edges_never_make_paths() {
    let a = analyze(SQL, &["mssqlhound"]);
    let g = &a.graph;
    let travel: HashSet<String> = traversable_og(g).into_iter().collect();
    for kind in [
        "MSSQL_ExecuteOnHost",
        "MSSQL_ServiceAccountFor",
        "MSSQL_CoerceAndRelayToMSSQL",
        "MSSQL_IsTrustedBy",
        "MSSQL_LinkedTo",
        "MSSQL_Impersonate",
    ] {
        assert!(!travel.contains(kind), "{kind} is a path");
    }
    // Native kinds in the file (HasSession) are dropped.
    let s = &a.stats.opengraph.sources[0];
    assert_eq!(s.dropped_native, 1);
    let ws01 = user(g, 1002);
    assert!(kinds(g, ws01, user(g, 1201)).is_empty());
}

// ------------------------------------------------------------ ConfigManBearPig

const SCCM: &[&str] = &["opengraph/ad", "opengraph/configmanbearpig"];
const SCCM_TRUST: &[&str] = &["configmanbearpig", "mssqlhound"];
const DC01_DEVICE: &str = "GUID:0D0C0001-0000-0000-0000-000000000001";

#[test]
fn sccm_files_are_read_as_one_collection() {
    let a = analyze(SCCM, &[]);
    let og = &a.stats.opengraph;
    let sccm = og.sources.iter().find(|s| s.name == "SCCM").expect("SCCM");
    assert_eq!(sccm.pack.as_deref(), Some("configmanbearpig"));
    assert!(!sccm.trusted);
    // The untagged ad_edges file belongs to it, by its edge kinds.
    assert!(
        sccm.files.iter().any(|f| f.ends_with("ad_edges-1.json")),
        "{:?}",
        sccm.files
    );
    assert_eq!(sccm.dropped_native, 2, "MemberOf and HasSession");
    // The site databases are read with the MSSQLHound pack.
    let mssql = og
        .sources
        .iter()
        .find(|s| s.name == "MSSQL")
        .expect("MSSQL");
    assert_eq!(mssql.pack.as_deref(), Some("mssqlhound"));
    // Untrusted: labels only.
    assert!(traversable_og(&a.graph).is_empty());
    assert!(rule(&a, "PW-035").is_empty());
}

#[test]
fn sccm_administrators_reach_tier_zero_and_pw035() {
    let a = analyze(SCCM, SCCM_TRUST);
    let g = &a.graph;
    let dc01 = user(g, 1000);
    let site = ix(g, "PS1@PS1-PSS.CORP.LOCAL");
    let device = ix(g, DC01_DEVICE);
    assert_eq!(kinds(g, site, device), ["SCCM_HasClient"]);

    // ALICE (Full Administrator over the collection), BOB (every permission
    // on the site) and CAROL (sysadmin on the site database) all reach DC01.
    let alice = analysis::path_to_tier_zero(g, user(g, 1101)).expect("ALICE");
    let steps: Vec<&str> = alice.steps.iter().map(|s| s.edge.as_str()).collect();
    assert_eq!(
        steps,
        [
            "SCCM_IsMappedTo",
            "SCCM_FullAdministrator",
            "SCCM_SameHostAs"
        ]
    );
    assert_eq!(alice.target, "DC01.CORP.LOCAL");
    assert!(reaches(g, user(g, 1102), dc01));
    // CAROL: MSSQL_HasLogin from the untagged file (kept with the
    // MSSQLHound pack's meaning), the site database, the site.
    let carol = analysis::path_to_tier_zero(g, user(g, 1103)).expect("CAROL");
    let steps: Vec<&str> = carol.steps.iter().map(|s| s.edge.as_str()).collect();
    assert_eq!(steps.first(), Some(&"MSSQL_HasLogin"));
    assert!(steps.contains(&"SCCM_AssignAllPermissions"), "{steps:?}");

    let found = rule(&a, "PW-035");
    assert_eq!(found.len(), 1, "one finding per Tier Zero host: {found:#?}");
    let f = found[0];
    assert_eq!(
        f.fingerprint,
        fingerprint("PW-035", &[&format!("{D}-1000")])
    );
    for who in ["ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"] {
        assert!(f.summary.contains(who), "{who}: {}", f.summary);
    }
    assert!(f.summary.contains("PS1"), "{}", f.summary);
    assert!(f.remediation.contains("SCCM"), "{}", f.remediation);
    assert!(f.sources.contains(&"SCCM".to_string()));
    assert!(f.exposure.as_ref().unwrap().principals >= 3);
    // APP01 is not Tier Zero: no finding; PW-030 stays silent.
    assert!(rule(&a, "PW-030").is_empty(), "{:#?}", rule(&a, "PW-030"));
}

#[test]
fn sccm_assumed_and_context_edges_never_make_paths() {
    let a = analyze(SCCM, SCCM_TRUST);
    let g = &a.graph;
    let travel: HashSet<String> = traversable_og(g).into_iter().collect();
    for kind in [
        "SCCM_CoerceAndRelayToSMB",
        "SCCM_CoerceAndRelayToAdminService",
        "SCCM_LocalAdminRequired",
        "SCCM_HasPrimaryUser",
        "SCCM_HasADLastLogonUser",
        "SCCM_HasMember",
    ] {
        assert!(!travel.contains(kind), "{kind} is a path");
    }
    // Edges ConfigManBearPig marks assumed are context, whatever their kind.
    let site = ix(g, "PS1@PS1-PSS.CORP.LOCAL");
    let app01 = user(g, 1001);
    assert_eq!(
        kinds(g, app01, site),
        ["SCCM_AssignAllPermissions (context)"]
    );
    let possible = ix(g, "GUID:0FFF0001-0000-0000-0000-000000000003");
    assert_eq!(kinds(g, site, possible), ["SCCM_HasClient (context)"]);
    assert_eq!(
        kinds(g, possible, user(g, 1000)),
        ["SCCM_SameHostAs (context)"]
    );
    // Authenticated Users reaches nothing through the assumed relays.
    let auth = ix(g, "CORP.LOCAL-S-1-5-11");
    assert!(!reaches(g, auth, user(g, 1000)));
    // WS01 (the site database host) doesn't reach DC01 through the assumed
    // local admin mesh.
    let ws01 = user(g, 1002);
    assert_eq!(
        kinds(g, ws01, user(g, 1000)),
        ["SCCM_LocalAdminRequired"],
        "kept as context, under its own (unmapped-to-path) kind"
    );
    assert!(!g.traversable(
        EdgeKind::from_name_or_external("SCCM_LocalAdminRequired").unwrap(),
        user(g, 1000)
    ));
}

#[test]
fn sccm_sites_are_rekeyed_per_hierarchy() {
    let a = analyze(
        &[
            "opengraph/ad",
            "opengraph/configmanbearpig",
            "opengraph/configmanbearpig_other",
        ],
        SCCM_TRUST,
    );
    let g = &a.graph;
    // Two sites called PS1, one per hierarchy; no bare "PS1" node.
    let ours = ix(g, "PS1@PS1-PSS.CORP.LOCAL");
    let theirs = ix(g, "PS1@PS1.OTHER.CORP.LOCAL");
    assert_ne!(ours, theirs);
    assert!(g.lookup("PS1").is_none());
    assert!(g.lookup("CORP\\DAVE@PS1@PS1.OTHER.CORP.LOCAL").is_some());
    // DAVE administers the other hierarchy's clients (WS01), not ours.
    let dave = user(g, 1104);
    assert!(reaches(g, dave, user(g, 1002)));
    assert!(!reaches(g, dave, user(g, 1000)));
    let ws01_device = ix(g, "GUID:0E0E0001-0000-0000-0000-000000000004");
    assert_eq!(kinds(g, theirs, ws01_device), ["SCCM_HasClient"]);
    assert!(kinds(g, ours, ws01_device).is_empty());
    assert!(a
        .stats
        .opengraph
        .corrections
        .iter()
        .any(|c| c.contains("re-keyed")));
    // Same findings as with our collection alone (WS01 is not Tier Zero).
    let alone = analyze(SCCM, SCCM_TRUST);
    let fps = |a: &Analysis| -> Vec<String> {
        rule(a, "PW-035")
            .iter()
            .map(|f| f.fingerprint.clone())
            .collect()
    };
    assert_eq!(fps(&a), fps(&alone));
}

/// A packs' trust can only come from the pack or the configuration: with
/// both new packs untrusted, adding their files changes no finding,
/// exposure or plan.
#[test]
fn untrusted_sql_and_sccm_change_nothing() {
    let base = analyze(&["opengraph/ad"], &[]);
    let with = analyze(
        &[
            "opengraph/ad",
            "opengraph/mssqlhound_corp",
            "opengraph/configmanbearpig",
        ],
        &[],
    );
    let fps = |a: &Analysis| -> Vec<String> {
        a.findings.iter().map(|f| f.fingerprint.clone()).collect()
    };
    assert_eq!(fps(&base), fps(&with));
    assert_eq!(
        serde_json::to_string(&base.plan).unwrap(),
        serde_json::to_string(&with.plan).unwrap()
    );
}
