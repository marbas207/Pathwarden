//! Entra ID and hybrid paths from AzureHound data.
//!
//! Fixtures (`testdata/entra/`, hand-written in AzureHound's and
//! SharpHound's formats):
//! - `ad/`: HYBRID.LOCAL. MSOL_1A2B3C4D5E6F is the Entra Connect account
//!   (DCSync; its description names AADC01) and may reset CAROL and, granted
//!   by hand, DA_EVE (a Domain Admin). DA_EVE has a session on WS01.
//! - `azurehound/`: the tenant. ALICE's synchronized account is Global
//!   Administrator; BOB's is Helpdesk Administrator; INTUNEOP (cloud-only)
//!   is Intune Administrator; APPADMIN is Application Administrator; the
//!   Automation service principal is Privileged Role Administrator and FRANK
//!   owns its application; PAUL is Privileged Authentication Administrator
//!   through the role-assignable group PAA Admins; the Sync_AADC01_... user
//!   holds Directory Synchronization Accounts. WS01 is hybrid joined and
//!   Intune-managed.
//! - `azurehound_other/`: another tenant, collected on its own.

use std::path::PathBuf;

use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::config::Config;
use pathwarden_core::findings::Finding;
use pathwarden_core::model::{EdgeKind, NodeKind};
use pathwarden_core::opengraph::coverage::{CoverageState, RunSources};
use pathwarden_core::state::{self, FindingsState, ResolveScope, Status};
use petgraph::visit::EdgeRef;

const D: &str = "S-1-5-21-4000-4000-4000";
const TENANT: &str = "11111111-2222-3333-4444-555555555555";

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn analyze(inputs: &[PathBuf]) -> Analysis {
    analyze::run(inputs, &Config::default(), &[], &mut analyze::Quiet).unwrap()
}

fn hybrid() -> Analysis {
    analyze(&[testdata("entra/ad"), testdata("entra/azurehound")])
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-entra-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The hybrid AzureHound file with `edit` applied, in a folder of its own.
fn edited(name: &str, edit: impl Fn(String) -> String) -> PathBuf {
    let dir = scratch(name);
    let text =
        std::fs::read_to_string(testdata("entra/azurehound/azurehound_hybrid.json")).unwrap();
    std::fs::write(dir.join("azurehound_hybrid.json"), edit(text)).unwrap();
    dir
}

fn guid(n: u64) -> String {
    format!("AAAAAAAA-0000-0000-0000-{n:012}")
}

fn rule<'a>(a: &'a Analysis, id: &str) -> Vec<&'a Finding> {
    a.findings.iter().filter(|f| f.rule == id).collect()
}

fn edge(a: &Analysis, from: &str, to: &str, kind: &str) -> bool {
    let g = &a.graph;
    let (Some(f), Some(t)) = (g.lookup(from), g.lookup(to)) else {
        return false;
    };
    g.inner()
        .edges_connecting(f, t)
        .any(|e| e.weight().as_str() == kind)
}

#[test]
fn reads_azurehound_and_links_synced_users_by_sid() {
    let a = hybrid();
    let s = a
        .stats
        .opengraph
        .sources
        .iter()
        .find(|s| s.name == "AzureHound")
        .expect("AzureHound source");
    assert!(s.trusted && s.complete, "{s:#?}");
    assert_eq!(s.pack.as_deref(), Some("azurehound"));
    // 9 users, 7 roles, 2 groups, app, SP, device, tenant (not the trust).
    assert_eq!(s.created, 22, "{s:#?}");
    assert_eq!(s.clashes, 0);
    assert_eq!(s.unresolved, 0);
    assert_eq!(s.dropped_secrets, 1, "passwordCredentials");
    assert_eq!(s.coverage.state, CoverageState::Collector);
    assert_eq!(s.coverage.ok, [TENANT]);

    let g = &a.graph;
    let alice = g.lookup(&guid(1)).unwrap();
    assert_eq!(g.node(alice).name, "ALICE@HYBRID.LOCAL");
    assert_eq!(g.node(alice).kind.as_str(), "AZUser");
    assert!(g.node(alice).domain.is_none());

    // Synced users link to the AD user with their SID, both ways only
    // where the Entra Connect account can reset the AD password.
    for (n, rid) in [(1, 1101), (2, 1102), (3, 1103), (4, 1104)] {
        assert!(
            edge(&a, &format!("{D}-{rid}"), &guid(n), "SyncedToEntraUser"),
            "{rid}"
        );
    }
    assert!(edge(&a, &guid(3), &format!("{D}-1103"), "SyncedToADUser"));
    assert!(edge(&a, &guid(4), &format!("{D}-1104"), "SyncedToADUser"));
    assert!(!edge(&a, &guid(1), &format!("{D}-1101"), "SyncedToADUser"));
    // Cloud-only users link to nothing.
    assert!(g
        .inner()
        .edges_directed(g.lookup(&guid(5)).unwrap(), petgraph::Direction::Incoming)
        .all(|e| e.weight().as_str() != "SyncedToEntraUser"));
    // The hybrid-joined device, and the Entra Connect server's cloud account.
    assert!(edge(
        &a,
        &guid(300),
        &format!("{D}-1002"),
        "SyncedToADComputer"
    ));
    assert!(edge(
        &a,
        &format!("{D}-1001"),
        &guid(6),
        "HasEntraSyncCredential"
    ));

    // Every Entra relationship records its source and tenant.
    for e in g.inner().edge_references() {
        if e.weight().as_str().starts_with("AZ") || e.weight().as_str().starts_with("Synced") {
            let o = g.edge_origin(e.id()).expect("origin");
            assert_eq!(g.source_name(o.source), "AzureHound");
            assert_eq!(o.unit.as_deref(), Some(TENANT));
        }
    }
}

#[test]
fn role_abilities_follow_the_reset_rules() {
    let a = hybrid();
    let helpdesk = format!("729827E3-9C14-49F7-BB1B-9608F156BBB8@{TENANT}");
    // Users without roles, and other helpdesk admins.
    for n in [2, 3, 4, 8] {
        assert!(edge(&a, &helpdesk, &guid(n), "AZResetPassword"), "{n}");
    }
    // Not admins of other kinds, and not role-assignable group members.
    for n in [1, 5, 6, 7, 9] {
        assert!(!edge(&a, &helpdesk, &guid(n), "AZResetPassword"), "{n}");
    }
    let intune = format!("3A2C62DB-5318-420D-8D74-23AFFEE5D9D5@{TENANT}");
    assert!(edge(&a, &intune, &guid(300), "AZExecuteCommand"));
    let app_admin = format!("9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3@{TENANT}");
    assert!(edge(&a, &app_admin, &guid(202), "AZAddSecret"));
    assert!(edge(&a, &guid(200), &guid(202), "AZRunsAs"));
    assert!(edge(&a, &guid(8), &guid(200), "AZOwns"));
    // Nobody holds Privileged Role Administrator's abilities other than the
    // tenant edge; the Global Administrator role reaches the tenant.
    let ga = format!("62E90394-69F5-4237-9190-012177145E10@{TENANT}");
    assert!(edge(&a, &ga, TENANT, "AZGlobalAdmin"));
}

#[test]
fn entra_tier_zero_is_seeded_from_roles() {
    let a = hybrid();
    let g = &a.graph;
    let t0 = |id: &str| g.node(g.lookup(id).unwrap()).tier_zero;
    let reason = |id: &str| {
        g.node(g.lookup(id).unwrap())
            .tier_zero_reason
            .clone()
            .unwrap_or_default()
    };
    assert!(t0(TENANT));
    for tpl in [
        "62E90394-69F5-4237-9190-012177145E10",
        "E8611AB8-C189-46E8-94E1-60213AB1F814",
        "7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13",
        "D29B2B05-8046-44BA-8758-1E26182FCF32",
    ] {
        let id = format!("{tpl}@{TENANT}");
        assert!(
            t0(&id) && reason(&id).starts_with("Entra Tier Zero role"),
            "{id}"
        );
    }
    assert!(!t0(&format!(
        "729827E3-9C14-49F7-BB1B-9608F156BBB8@{TENANT}"
    )));
    assert!(t0(&guid(1)), "alice: Global Administrator");
    assert!(reason(&guid(1)).starts_with("Holds Entra role GLOBAL ADMINISTRATOR"));
    assert!(
        t0(&guid(202)),
        "the service principal: Privileged Role Administrator"
    );
    // Its application: a credential added to it signs in as the
    // service principal.
    assert!(
        t0(&guid(200)),
        "the application of a Tier Zero service principal"
    );
    assert!(reason(&guid(200)).starts_with("Application of Entra service principal"));
    assert!(
        t0(&guid(100)) && t0(&guid(9)),
        "PAA through a role-assignable group"
    );
    assert!(reason(&guid(9)).starts_with("Member of Entra group"));
    assert!(t0(&guid(6)), "the sync account");
    for n in [2, 3, 4, 5, 7, 8] {
        assert!(!t0(&guid(n)), "{n}");
    }

    // Entra data never makes an AD object Tier Zero: same AD Tier Zero as
    // the AD data alone.
    let ad = analyze(&[testdata("entra/ad")]);
    let ad_t0 = |a: &Analysis| -> Vec<String> {
        let mut v: Vec<String> = a
            .graph
            .nodes()
            .filter(|(_, n)| n.tier_zero && !n.kind.is_external())
            .map(|(_, n)| n.id.clone())
            .collect();
        v.sort();
        v
    };
    assert_eq!(ad_t0(&ad), ad_t0(&a));
    assert!(!t0(&format!("{D}-1101")), "ALICE stays outside Tier Zero");
    assert!(t0(&format!("{D}-1001")), "AADC01, from the AD side (#34)");
}

#[test]
fn ad_to_entra_a_synced_admin_is_pw031() {
    let a = hybrid();
    let f = rule(&a, "PW-031");
    let alice = f
        .iter()
        .find(|f| f.affected[0].id == format!("{D}-1101"))
        .expect("ALICE -> Entra Global Administrator");
    assert!(alice.title.contains("synchronized to Entra Tier Zero"));
    assert_eq!(alice.sources, ["AzureHound"]);
    assert_eq!(alice.requires.len(), 1);
    assert_eq!(alice.domain.as_deref(), Some("HYBRID.LOCAL"));
    assert!(alice.severity >= pathwarden_core::findings::Severity::High);
    assert!(alice.remediation.contains("cloud-only"));
    let p = alice.path.as_ref().unwrap();
    assert_eq!(p.steps.len(), 1);

    // Other Entra Tier Zero control: the application of the privileged
    // service principal is Tier Zero itself, so its owner is the finding;
    // the Application Administrator role, which can add a secret to both,
    // is one finding on the application, with both affected.
    let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
    assert!(
        titles.contains(
            &"Entra user FRANK@HYBRID.ONMICROSOFT.COM can take over Tier Zero Entra application AUTOMATION@HYBRID.ONMICROSOFT.COM"
        ),
        "{titles:#?}"
    );
    assert!(
        !titles
            .iter()
            .any(|t| t.starts_with("Entra application AUTOMATION@")),
        "{titles:#?}"
    );
    let app_admin: Vec<&&str> = titles
        .iter()
        .filter(|t| t.starts_with("Entra role APPLICATION ADMINISTRATOR"))
        .collect();
    assert_eq!(
        app_admin,
        [&"Entra role APPLICATION ADMINISTRATOR@HYBRID.ONMICROSOFT.COM can take over Tier Zero Entra application AUTOMATION@HYBRID.ONMICROSOFT.COM"],
        "{titles:#?}"
    );
    // The role's fix names its assignment (the cuttable step).
    let role = f
        .iter()
        .find(|f| f.title.starts_with("Entra role APPLICATION ADMINISTRATOR"))
        .unwrap();
    assert!(
        role.affected.iter().any(|o| o.id == guid(202)),
        "the service principal is affected too"
    );
    assert!(
        role.remediation.contains("APPADMIN@"),
        "{}",
        role.remediation
    );
    // AADC01 is Tier Zero already: its sync credential is no finding, and
    // nothing reports through PW-030.
    assert!(!titles.iter().any(|t| t.contains("SYNC_AADC01")));
    assert!(rule(&a, "PW-030").is_empty());

    // The AD user's own Tier Zero exposure now counts the cloud path.
    let ad = analyze(&[testdata("entra/ad")]);
    assert!(a.posture.tier_zero.exposed > ad.posture.tier_zero.exposed);
}

#[test]
fn entra_to_ad_writeback_and_intune_are_pw032() {
    let a = hybrid();
    let f = rule(&a, "PW-032");
    assert_eq!(
        f.len(),
        2,
        "{:#?}",
        f.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    let eve = f
        .iter()
        .find(|f| f.affected[1].id == format!("{D}-1103"))
        .expect("Helpdesk -> eve -> DA_EVE");
    assert!(eve
        .title
        .contains("on-premises Tier Zero DA_EVE@HYBRID.LOCAL"));
    assert!(eve.summary.contains("HELPDESK ADMINISTRATOR"));
    assert!(eve.summary.contains("password writeback"));
    assert!(eve.severity >= pathwarden_core::findings::Severity::High);
    let steps: Vec<&str> = eve
        .path
        .as_ref()
        .unwrap()
        .steps
        .iter()
        .map(|s| s.edge.as_str())
        .collect();
    assert_eq!(steps, ["AZResetPassword", "SyncedToADUser"]);
    assert!(eve.remediation.contains("Exclude"));

    let ws = f
        .iter()
        .find(|f| f.affected[1].id == format!("{D}-1002"))
        .expect("Intune -> WS01 -> DA_EVE's session");
    assert!(ws.title.contains("has a path to Tier Zero"));
    let steps: Vec<&str> = ws
        .path
        .as_ref()
        .unwrap()
        .steps
        .iter()
        .map(|s| s.edge.as_str())
        .collect();
    assert_eq!(steps[..2], ["AZExecuteCommand", "SyncedToADComputer"]);
    assert!(steps.contains(&"HasSession"));
    assert!(ws.severity >= pathwarden_core::findings::Severity::Medium);

    // CAROL is synced and resettable, but leads nowhere: no finding.
    assert!(!f.iter().any(|f| f.affected[1].id == format!("{D}-1104")));
    // The plan cuts ALICE off from her Entra admin account (the synced
    // account must not hold the role) and leaves nobody exposed.
    assert!(
        a.plan
            .fixes
            .iter()
            .any(|f| f.edges.iter().any(|k| k.as_str() == "SyncedToEntraUser")),
        "{:#?}",
        a.plan.fixes
    );
    assert_eq!(a.plan.exposed_after, 0);
}

/// The status of every Entra finding of a first, full run after `second`.
fn second_run(second: &[PathBuf]) -> Vec<(String, Status)> {
    let first = hybrid();
    let first_sources = RunSources::from_analysis(&first.graph, &first.stats);
    let r1 = state::reconcile(&FindingsState::default(), &first.findings, 100, false);
    let b = analyze(second);
    let sources = RunSources::from_analysis(&b.graph, &b.stats);
    let scope =
        ResolveScope::domains(&b.domains, true).with_sources(sources, &first_sources.keys());
    let r2 = state::reconcile_scoped(&r1.state, &b.findings, 200, false, &scope);
    first
        .findings
        .iter()
        .filter(|f| f.rule == "PW-031" || f.rule == "PW-032")
        .map(|f| (f.title.clone(), r2.state.findings[&f.fingerprint].status))
        .collect()
}

#[test]
fn a_tenant_not_collected_holds_its_findings() {
    // AD data only: AzureHound is missing, everything Entra is held.
    let held = second_run(&[testdata("entra/ad")]);
    assert!(held.len() >= 4);
    assert!(held.iter().all(|(_, s)| *s == Status::Open), "{held:#?}");

    // Another tenant's data: its source is there, but this tenant wasn't
    // collected.
    let held = second_run(&[testdata("entra/ad"), testdata("entra/azurehound_other")]);
    assert!(held.iter().all(|(_, s)| *s == Status::Open), "{held:#?}");

    // The tenant listed but not marked collected (a trust, or a failed
    // collection): held.
    let dir = edited("uncollected", |t| {
        t.replace("\"collected\": true", "\"collected\": false")
    });
    let held = second_run(&[testdata("entra/ad"), dir]);
    assert!(held.iter().all(|(_, s)| *s == Status::Open), "{held:#?}");

    // No role assignments at all (that part of the collection failed):
    // held, even though the findings are gone.
    let dir = edited("noassign", |t| {
        t.replace("\"AZRoleAssignment\"", "\"AZIgnored\"")
    });
    let b = analyze(&[testdata("entra/ad"), dir.clone()]);
    assert!(rule(&b, "PW-031")
        .iter()
        .all(|f| !f.title.contains("ALICE")));
    let held = second_run(&[testdata("entra/ad"), dir]);
    assert!(held.iter().all(|(_, s)| *s == Status::Open), "{held:#?}");

    // The same tenant, collected, with ALICE's role removed: that finding
    // resolves, the others stay open.
    let dir = edited("fixed", |t| {
        t.replace(
            "\"principalId\": \"aaaaaaaa-0000-0000-0000-000000000001\"",
            "\"principalId\": \"aaaaaaaa-0000-0000-0000-000000000099\"",
        )
    });
    let after = second_run(&[testdata("entra/ad"), dir]);
    for (title, status) in &after {
        let expected = if title.contains("ALICE") {
            Status::Resolved
        } else {
            Status::Open
        };
        assert_eq!(*status, expected, "{title}");
    }
}

#[test]
fn hostile_azurehound_input_stays_in_its_lane() {
    let dir = scratch("hostile");
    let big = "x".repeat(40 << 20);
    let text = serde_json::json!({
        "data": [
            // An Entra object claiming an AD SID and the domain's SID: clashes.
            {"kind": "AZUser", "data": {"id": format!("{D}-1103"), "userPrincipalName": "evil@x", "tenantId": TENANT}},
            {"kind": "AZGroup", "data": {"id": D, "displayName": "evil", "tenantId": TENANT}},
            {"kind": "AZUser", "data": {"id": "cafe", "userPrincipalName": "mallory@x", "tenantId": TENANT,
                "password": "hunter2", "onPremisesSecurityIdentifier": format!("{D}-500")}},
            // Ownership of an AD object, and a role for an AD principal:
            // unresolved, never an edge onto AD data.
            {"kind": "AZGroupOwner", "data": {"groupId": format!("{D}-512"), "owners": [{"owner": {"id": "cafe"}}]}},
            {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "tenantId": TENANT,
                "roleAssignments": [{"principalId": format!("{D}-1101"), "directoryScopeId": "/"}]}},
            // A record far over the per-record limit.
            {"kind": "AZUser", "data": {"id": "big", "displayName": big, "tenantId": TENANT}},
            {"kind": 42, "data": null},
        ],
        "meta": {"type": "azure", "version": 5}
    })
    .to_string();
    std::fs::write(dir.join("hostile.json"), text).unwrap();
    let a = analyze(&[testdata("entra/ad"), dir]);
    let s = a
        .stats
        .opengraph
        .sources
        .iter()
        .find(|s| s.name == "AzureHound")
        .unwrap();
    assert_eq!(s.clashes, 2, "{s:#?}");
    assert!(s.unresolved >= 2, "{s:#?}");
    assert!(
        !s.complete,
        "an oversized record or error makes it incomplete"
    );
    assert!(s.dropped_secrets >= 1);
    let g = &a.graph;
    // The AD objects are untouched.
    let eve = g.node(g.lookup(&format!("{D}-1103")).unwrap());
    assert_eq!(eve.kind, NodeKind::User);
    assert!(eve.ext.is_none());
    // No Entra edge touches an AD object except the derived hybrid links;
    // mallory claims Administrator's SID but isn't synced: no link.
    for e in g.inner().edge_references() {
        let (u, v) = (g.node(e.source()), g.node(e.target()));
        if e.weight().is_external() && !u.kind.is_external() && !v.kind.is_external() {
            panic!("{} -> {} ({})", u.name, v.name, e.weight().as_str());
        }
    }
    let admin = g.lookup(&format!("{D}-500")).unwrap();
    assert!(g
        .inner()
        .edges_directed(admin, petgraph::Direction::Outgoing)
        .all(|e| !e.weight().is_external()));
    // No secret is kept anywhere.
    let all = format!("{:?}", g.nodes().map(|(_, n)| n).collect::<Vec<_>>());
    assert!(!all.contains("hunter2"));

    // Nothing from this file is ever resolved: incomplete source.
    let sources = RunSources::from_analysis(&a.graph, &a.stats);
    assert!(sources
        .hold_reason(&[pathwarden_core::opengraph::source_key("AzureHound")], &[])
        .is_some());
}

#[test]
fn an_opengraph_file_cannot_forge_entra_paths() {
    // An OpenGraph file that calls itself AzureHound and uses AZ kinds next
    // to real AzureHound data: kept as context, never traversable.
    let dir = scratch("forged");
    let og = serde_json::json!({
        "metadata": {"source_kind": "AzureHound"},
        "graph": {
            "nodes": [{"id": "FORGED", "kinds": ["AZUser"], "properties": {"name": "FORGED"}}],
            "edges": [{"kind": "AZOwns", "start": {"value": "FORGED"}, "end": {"value": guid(202)}},
                      {"kind": "AZHasRole", "start": {"value": format!("{D}-1106")},
                       "end": {"value": format!("62E90394-69F5-4237-9190-012177145E10@{TENANT}")}}]
        }
    });
    std::fs::write(dir.join("forged.json"), og.to_string()).unwrap();
    let a = analyze(&[testdata("entra/ad"), testdata("entra/azurehound"), dir]);
    let g = &a.graph;
    for e in g.inner().edge_references() {
        let src = g.edge_source_name(e.id());
        if src == Some("AzureHound") {
            continue;
        }
        if let EdgeKind::External(_) = e.weight() {
            assert!(
                !g.traversable(*e.weight(), e.target()),
                "{} from {src:?} is traversable",
                e.weight().as_str()
            );
        }
    }
    // DAVE stays outside Tier Zero and the forged node is no Entra object.
    let dave = g.node(g.lookup(&format!("{D}-1106")).unwrap());
    assert!(!dave.tier_zero);
    let forged = g.node(g.lookup("FORGED").unwrap());
    assert!(!forged.tier_zero);
}

#[test]
fn without_azurehound_nothing_changes() {
    // The AzureHound pack is only in effect with AzureHound data.
    let a = analyze(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    assert!(a
        .stats
        .opengraph
        .packs
        .iter()
        .all(|p| p.name != "azurehound"));
    assert!(a
        .findings
        .iter()
        .all(|f| f.rule != "PW-031" && f.rule != "PW-032"));
    let ad = analyze(&[testdata("entra/ad")]);
    assert!(ad.stats.opengraph.is_empty());
}

#[test]
fn the_report_shows_entra_objects() {
    let a = hybrid();
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains("AzureHound"));
    assert!(html.contains("1 tenant collected"));
    assert!(html.contains("PW-031") && html.contains("PW-032"));
    assert!(html.contains("(Entra ID), besides the directory"));
    assert!(!html.contains("DO-NOT-KEEP"));
    // The explorer data carries the pack's labels.
    let bin = pathwarden_core::explore::encode(&a.graph, &a.findings, &a.zones);
    assert!(String::from_utf8_lossy(&bin).contains("Entra user"));
}

/// A finding card draws Entra objects with the pack's icons and labels, as
/// Explore does: in the path diagram, the path as text and the affected
/// objects (grouped by kind). The raw kind names stay out of sight.
#[test]
fn the_report_draws_entra_objects_with_the_pack_s_icons_and_labels() {
    let a = hybrid();
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    // The sprite has every pack icon.
    for name in pathwarden_core::opengraph::pack::ICONS {
        assert!(
            html.contains(&format!(r#"<symbol id="i-x-{name}""#)),
            "{name}"
        );
    }
    let cards: Vec<&str> = html
        .split(r#"<details class="row finding""#)
        .skip(1)
        .map(|c| c.split("</details>\n").next().unwrap_or(c))
        .filter(|c| c.contains("PW-031"))
        .collect();
    assert!(!cards.is_empty());
    let card = cards
        .iter()
        .find(|c| c.contains("(Entra role)</title>"))
        .unwrap_or_else(|| {
            panic!(
                "no PW-031 diagram through an Entra role: {}",
                cards.concat()
            )
        });
    assert!(card.contains(r##"<use class="glyph" href="#i-x-id-card""##));
    assert!(card.contains(r#"<text class="sub""#) && card.contains(">Entra role"));
    assert!(card.contains("(Entra role)</title>"));
    assert!(card.contains(r#"<span class="muted">(Entra role)</span>"#));
    let all = cards.concat();
    for raw in ["(AZRole)", ">AZRole<", "AZRole \u{b7}"] {
        assert!(!all.contains(raw), "{raw}");
    }
    // Affected objects grouped by kind, under the pack's label and icon.
    let groups: Vec<&str> = html.split(r#"<div class="agroup"><h5>"#).skip(1).collect();
    assert!(groups.iter().any(|g| g.starts_with(
        r##"<svg class="ic" aria-hidden="true"><use href="#i-x-id-card"/></svg>Entra role"##
    )));
    assert!(!groups
        .iter()
        .any(|g| g.contains("#i-object") && g.contains(">Objects <")));
}

fn analyze_config(inputs: &[PathBuf], toml: &str) -> Analysis {
    let config = Config::parse(toml).unwrap();
    analyze::run(inputs, &config, &[], &mut analyze::Quiet).unwrap()
}

/// The AzureHound source of `a`, not read whole.
fn incomplete(a: &Analysis) -> pathwarden_core::ingest::OgIncomplete {
    let all = pathwarden_core::ingest::OgIncomplete::all(&a.stats.opengraph);
    assert_eq!(all.len(), 1, "{all:#?}");
    all[0].clone()
}

/// A read stopped by the kept-properties limit, or with a record too large,
/// says which and the setting that raises it: the CLI by its key, a
/// page by where it is. A whole read says nothing.
#[test]
fn an_azurehound_read_that_stops_says_why() {
    assert!(pathwarden_core::ingest::OgIncomplete::all(&hybrid().stats.opengraph).is_empty());

    let kept = analyze_config(
        &[testdata("entra/ad"), testdata("entra/azurehound")],
        "[opengraph]\nmax_kept_mib = 0\n",
    );
    let i = incomplete(&kept);
    assert_eq!(i.source, "AzureHound");
    assert_eq!(i.limits, ["kept properties"]);
    assert_eq!(
        i.sentences("AzureHound", true),
        [
            "AzureHound was read only part way (the limit on kept properties).",
            "Raise the limit with max_kept_mib under [opengraph] in pathwarden.toml.",
            "Findings that rest on it aren't marked fixed.",
        ]
    );
    assert_eq!(
        i.sentences("AzureHound", false)[1],
        "A higher limit can be set in this environment's settings file."
    );

    let big = "x".repeat(3 << 19);
    let dir = edited("oversized", |t| {
        t.replace(
            "\"displayName\": \"Partner\"",
            &format!("\"displayName\": \"{big}\""),
        )
    });
    let over = analyze_config(
        &[testdata("entra/ad"), dir],
        "[opengraph]\nmax_record_mib = 1\n",
    );
    let i = incomplete(&over);
    assert_eq!((i.too_large, i.errors), (1, 0), "{i:#?}");
    assert_eq!(
        i.sentences("AzureHound", true)[..2],
        [
            "AzureHound was read only part way (1 record too large to load).",
            "Raise the limit with max_record_mib under [opengraph] in pathwarden.toml.",
        ]
    );
    // Both, with read errors: one sentence for why, one for the limits.
    let both = pathwarden_core::ingest::OgIncomplete {
        too_large: 2,
        errors: 1,
        ..incomplete(&kept)
    };
    assert_eq!(
        both.sentences("AzureHound", true)[..2],
        [
            "AzureHound was read only part way (the limit on kept properties, 2 records too large to load, 1 read error).",
            "Raise the limits with max_kept_mib and max_record_mib under [opengraph] in pathwarden.toml.",
        ]
    );
    // Errors alone: no limit to raise.
    let errors = pathwarden_core::ingest::OgIncomplete {
        source: "AzureHound".into(),
        errors: 2,
        ..Default::default()
    };
    assert_eq!(
        errors.sentences("AzureHound", false),
        [
            "AzureHound was read only part way (2 read errors).",
            "Findings that rest on it aren't marked fixed.",
        ]
    );
}

/// A finding gone from a read that stopped part way is held, not fixed,
/// as for an unread computer.
#[test]
fn a_read_that_stops_holds_what_it_no_longer_shows() {
    let dir = edited("fixed-partial", |t| {
        t.replace(
            "\"principalId\": \"aaaaaaaa-0000-0000-0000-000000000001\"",
            "\"principalId\": \"aaaaaaaa-0000-0000-0000-000000000099\"",
        )
    });
    let first = hybrid();
    let first_sources = RunSources::from_analysis(&first.graph, &first.stats);
    let r1 = state::reconcile(&FindingsState::default(), &first.findings, 100, false);
    let b = analyze_config(
        &[testdata("entra/ad"), dir],
        "[opengraph]\nmax_kept_mib = 0\n",
    );
    assert!(!incomplete(&b).limits.is_empty());
    let sources = RunSources::from_analysis(&b.graph, &b.stats);
    let scope =
        ResolveScope::domains(&b.domains, true).with_sources(sources, &first_sources.keys());
    let r2 = state::reconcile_scoped(&r1.state, &b.findings, 200, false, &scope);
    let alice: Vec<_> = first
        .findings
        .iter()
        .filter(|f| (f.rule == "PW-031" || f.rule == "PW-032") && f.title.contains("ALICE"))
        .collect();
    assert!(!alice.is_empty());
    for f in alice {
        assert_eq!(
            r2.state.findings[&f.fingerprint].status,
            Status::Open,
            "{}",
            f.title
        );
    }
}
