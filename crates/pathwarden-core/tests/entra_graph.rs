//! Microsoft Graph application permissions, federated identity credentials,
//! roles scoped to administrative units and synchronized groups.
//!
//! Fixture `testdata/entra/graph/` (hand-written, made-up names):
//! - `ad/`: CONTOSO.LOCAL. MARK can add members to CLOUD-OPS.
//! - `azurehound/`: the Contoso tenant. Service principals granted
//!   Microsoft Graph application permissions: Provisioner
//!   (RoleManagement.ReadWrite.Directory; DEV owns it, and its application
//!   trusts a GitHub repository and a Kubernetes service account), Grantor
//!   (AppRoleAssignment.ReadWrite.All), AppManager
//!   (Application.ReadWrite.All), EndpointBot
//!   (ServicePrincipalEndpoint.ReadWrite.All), GroupBot, DirBot and
//!   MemberBot (Group.ReadWrite.All, Directory.ReadWrite.All,
//!   GroupMember.ReadWrite.All) and Reader (User.Read.All, and a look-alike
//!   on another API). HELPDESK, AUADMIN (Global Administrator!) and
//!   USERADMIN (eligible) hold roles scoped to an administrative unit. The
//!   Entra group Cloud Ops is synchronized from CLOUD-OPS.

use std::path::PathBuf;

use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::config::Config;
use pathwarden_core::findings::{Finding, Severity};
use petgraph::visit::EdgeRef;

const D: &str = "S-1-5-21-5000-5000-5000";
const TENANT: &str = "22222222-3333-4444-5555-666666666666";
const GRAPH_SP: &str = "BBBBBBBB-0000-0000-0000-000000000900";

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn contoso() -> Analysis {
    analyze::run(
        &[
            testdata("entra/graph/ad"),
            testdata("entra/graph/azurehound"),
        ],
        &Config::default(),
        &[],
        &mut analyze::Quiet,
    )
    .unwrap()
}

fn g(n: u64) -> String {
    format!("BBBBBBBB-0000-0000-0000-{n:012}")
}

fn role(tpl: &str) -> String {
    format!("{}@{TENANT}", tpl.to_ascii_uppercase())
}

const GA: &str = "62e90394-69f5-4237-9190-012177145e10";
const HELPDESK: &str = "729827e3-9c14-49f7-bb1b-9608f156bbb8";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";

fn edge(a: &Analysis, from: &str, to: &str, kind: &str) -> bool {
    let gr = &a.graph;
    let (Some(f), Some(t)) = (gr.lookup(from), gr.lookup(to)) else {
        return false;
    };
    gr.inner()
        .edges_connecting(f, t)
        .any(|e| e.weight().as_str() == kind)
}

fn out_kinds(a: &Analysis, from: &str) -> Vec<String> {
    let gr = &a.graph;
    let f = gr.lookup(from).unwrap();
    let mut v: Vec<String> = gr
        .inner()
        .edges_directed(f, petgraph::Direction::Outgoing)
        .map(|e| e.weight().as_str().to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn pw031(a: &Analysis) -> Vec<&Finding> {
    a.findings.iter().filter(|f| f.rule == "PW-031").collect()
}

fn t0(a: &Analysis, id: &str) -> bool {
    a.graph.node(a.graph.lookup(id).unwrap()).tier_zero
}

/// Each permission ID gives its stated edge to Microsoft Graph's service
/// principal, and only Graph application permissions granted to a
/// service principal count.
#[test]
fn graph_permission_ids_give_their_stated_edges() {
    let a = contoso();
    for (sp, kind) in [
        (101, "AZMGRoleManagement_ReadWrite_Directory"),
        (201, "AZMGAppRoleAssignment_ReadWrite_All"),
        (301, "AZMGApplication_ReadWrite_All"),
        (401, "AZMGServicePrincipalEndpoint_ReadWrite_All"),
        (501, "AZMGGroup_ReadWrite_All"),
        (601, "AZMGDirectory_ReadWrite_All"),
        (701, "AZMGGroupMember_ReadWrite_All"),
    ] {
        assert!(edge(&a, &g(sp), GRAPH_SP, kind), "{sp} {kind}");
    }
    // User.Read.All, the same ID on another API, and an app role granted to
    // a user: nothing.
    assert!(
        out_kinds(&a, &g(801))
            .iter()
            .all(|k| !k.starts_with("AZMG")),
        "{:?}",
        out_kinds(&a, &g(801))
    );
    assert!(out_kinds(&a, &g(4)).iter().all(|k| !k.starts_with("AZMG")));
    // The IDs are BloodHound CE's and Microsoft's.
    use pathwarden_core::entra;
    let ids: Vec<(&str, &str)> = entra::GRAPH_PERMISSIONS
        .iter()
        .map(|p| (p.name, p.id))
        .collect();
    assert_eq!(
        ids,
        [
            (
                "Application.ReadWrite.All",
                "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
            ),
            (
                "AppRoleAssignment.ReadWrite.All",
                "06b708a9-e830-4db3-a914-8e69da51d44f"
            ),
            (
                "Directory.ReadWrite.All",
                "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
            ),
            (
                "Group.ReadWrite.All",
                "62a82d76-70ea-41e2-9197-370581804d09"
            ),
            (
                "GroupMember.ReadWrite.All",
                "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"
            ),
            (
                "RoleManagement.ReadWrite.Directory",
                "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
            ),
            (
                "ServicePrincipalEndpoint.ReadWrite.All",
                "89c8469c-83ad-45f7-8ff2-6e3d4285709e"
            ),
        ]
    );
    // The stated grants are context, not paths.
    let gr = &a.graph;
    let e = gr
        .inner()
        .edge_references()
        .find(|e| e.weight().as_str() == "AZMGApplication_ReadWrite_All")
        .unwrap();
    assert!(!gr.traversable(*e.weight(), e.target()));
}

#[test]
fn azmg_grant_role_and_grant_app_roles() {
    let a = contoso();
    // RoleManagement.ReadWrite.Directory: every role.
    for tpl in [GA, HELPDESK, USER_ADMIN] {
        assert!(edge(&a, &g(101), &role(tpl), "AZMGGrantRole"), "{tpl}");
    }
    assert!(!edge(&a, &g(201), &role(GA), "AZMGGrantRole"));
    // AppRoleAssignment.ReadWrite.All: the tenant.
    assert!(edge(&a, &g(201), TENANT, "AZMGGrantAppRoles"));
    assert!(!edge(&a, &g(101), TENANT, "AZMGGrantAppRoles"));
    // Both are Tier Zero, with the permission as the reason; and the
    // application of Provisioner too.
    let reason = |id: &str| {
        a.graph
            .node(a.graph.lookup(id).unwrap())
            .tier_zero_reason
            .clone()
            .unwrap_or_default()
    };
    assert!(t0(&a, &g(101)));
    assert_eq!(
        reason(&g(101)),
        "Holds Microsoft Graph permission RoleManagement.ReadWrite.Directory"
    );
    assert!(t0(&a, &g(201)));
    assert_eq!(
        reason(&g(201)),
        "Holds Microsoft Graph permission AppRoleAssignment.ReadWrite.All"
    );
    assert!(t0(&a, &g(100)), "the Provisioner application");
    for n in [301, 401, 501, 601, 701, 801] {
        assert!(!t0(&a, &g(n)), "{n}");
    }

    // Its owner is a PW-031 finding, whose fix also names the grant.
    let f = pw031(&a);
    let dev = f
        .iter()
        .find(|f| f.affected[0].id == g(4))
        .unwrap_or_else(|| panic!("{:#?}", f.iter().map(|f| &f.title).collect::<Vec<_>>()));
    assert!(dev.title.contains("PROVISIONER@"), "{}", dev.title);
    assert!(dev.summary.contains("RoleManagement.ReadWrite.Directory"));
    assert!(
        dev.remediation
            .contains("Or remove the Microsoft Graph application permission RoleManagement.ReadWrite.Directory from PROVISIONER@CONTOSO.ONMICROSOFT.COM"),
        "{}",
        dev.remediation
    );
}

#[test]
fn azmg_add_secret_and_add_owner() {
    let a = contoso();
    // Application.ReadWrite.All: every application and service principal.
    for to in [g(100), g(101), g(201), g(801), GRAPH_SP.to_string()] {
        assert!(edge(&a, &g(301), &to, "AZMGAddSecret"), "{to}");
        assert!(edge(&a, &g(301), &to, "AZMGAddOwner"), "{to}");
    }
    assert!(!edge(&a, &g(301), &g(301), "AZMGAddSecret"), "not itself");
    // ServicePrincipalEndpoint.ReadWrite.All: owners of service principals
    // only, no secrets.
    assert!(edge(&a, &g(401), &g(101), "AZMGAddOwner"));
    assert!(!edge(&a, &g(401), &g(100), "AZMGAddOwner"));
    assert!(!edge(&a, &g(401), &g(101), "AZMGAddSecret"));
    // Groups management gives no ownership of applications.
    for n in [501, 601, 701] {
        assert!(!edge(&a, &g(n), &g(101), "AZMGAddOwner"), "{n}");
    }

    // AppManager can take over the Tier Zero Provisioner: one finding on
    // the application (with its service principal), whose fix names the
    // grant exactly.
    let f = pw031(&a);
    let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
    let am: Vec<&&Finding> = f.iter().filter(|f| f.affected[0].id == g(301)).collect();
    let prov = am
        .iter()
        .find(|f| f.affected[1].id == g(100))
        .unwrap_or_else(|| panic!("{titles:#?}"));
    assert!(prov.affected.iter().any(|o| o.id == g(101)));
    assert!(
        prov.remediation.starts_with(
            "Remove the Microsoft Graph application permission Application.ReadWrite.All from APPMANAGER@CONTOSO.ONMICROSOFT.COM"
        ),
        "{}",
        prov.remediation
    );
    assert!(prov.severity >= Severity::High);
    assert!(
        !am.iter().any(|f| f.affected[1].id == g(101)),
        "merged into the application's finding"
    );
    // ... and Grantor (no application here).
    assert!(am.iter().any(|f| f.affected[1].id == g(201)), "{titles:#?}");
    // EndpointBot: by ServicePrincipalEndpoint.ReadWrite.All.
    let ep = f
        .iter()
        .find(|f| f.affected[0].id == g(401) && f.affected[1].id == g(101))
        .unwrap_or_else(|| panic!("{titles:#?}"));
    assert!(
        ep.remediation
            .contains("ServicePrincipalEndpoint.ReadWrite.All")
            && !ep.remediation.contains("Application.ReadWrite.All"),
        "{}",
        ep.remediation
    );
    // The plan can cut the permission's edges: removing the grant.
    let gr = &a.graph;
    let e = gr
        .inner()
        .edges_connecting(gr.lookup(&g(301)).unwrap(), gr.lookup(&g(100)).unwrap())
        .find(|e| e.weight().as_str() == "AZMGAddSecret")
        .unwrap();
    assert_eq!(pathwarden_core::remediation::edge_cost(gr, e.id()), Some(1));
    assert!(pathwarden_core::remediation::fix_for(gr, e.id())
        .contains("Application.ReadWrite.All from APPMANAGER@"));

    // MARK (AD) is synchronized to the owner of AppManager: his exposure
    // runs through the permission, and the plan cuts it.
    let mark = gr.node(gr.lookup(&format!("{D}-1101")).unwrap());
    assert!(!mark.tier_zero);
    assert!(a.posture.tier_zero.exposed >= 1);
    assert!(!a.plan.fixes.is_empty());
    assert_eq!(a.plan.exposed_after, 0, "{:#?}", a.plan.fixes);
}

#[test]
fn azmg_add_member_only_on_groups_the_cloud_can_change() {
    let a = contoso();
    for n in [501, 601, 701] {
        assert!(edge(&a, &g(n), &g(800), "AZMGAddMember"), "{n}");
        // Not role-assignable groups, not groups synchronized from AD.
        assert!(!edge(&a, &g(n), &g(810), "AZMGAddMember"), "{n}");
        assert!(!edge(&a, &g(n), &g(820), "AZMGAddMember"), "{n}");
        // No owners of groups drawn (a member is the path).
        assert!(!edge(&a, &g(n), &g(800), "AZMGAddOwner"), "{n}");
    }
    assert!(!edge(&a, &g(301), &g(800), "AZMGAddMember"));
}

/// A federated identity credential on a Tier Zero application is a PW-031
/// finding naming the issuer and subject.
#[test]
fn a_federated_credential_on_a_tier_zero_application_is_pw031() {
    let a = contoso();
    let gr = &a.graph;
    let ids: Vec<String> = gr
        .nodes()
        .filter(|(_, n)| n.kind.as_str() == "AZFederatedIdentityCredential")
        .map(|(_, n)| n.id.clone())
        .collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    let github = "FIC|HTTPS://TOKEN.ACTIONS.GITHUBUSERCONTENT.COM|REPO:CONTOSO/PROVISIONER:REF:REFS/HEADS/MAIN";
    assert!(edge(&a, github, &g(100), "AZAuthenticatesTo"));
    let node = gr.node(gr.lookup(github).unwrap());
    assert_eq!(
        node.name,
        "repo:contoso/provisioner:ref:refs/heads/main (https://token.actions.githubusercontent.com)"
    );
    assert!(!node.tier_zero);

    let f = pw031(&a);
    let fic: Vec<&&Finding> = f
        .iter()
        .filter(|f| f.title.starts_with("Federated identity "))
        .collect();
    assert_eq!(
        fic.len(),
        2,
        "{:#?}",
        f.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    let gh = fic
        .iter()
        .find(|f| f.affected[0].id == github)
        .expect("the GitHub subject");
    assert_eq!(
        gh.title,
        "Federated identity repo:contoso/provisioner:ref:refs/heads/main (https://token.actions.githubusercontent.com) can take over Tier Zero Entra application PROVISIONER@CONTOSO.ONMICROSOFT.COM"
    );
    assert!(gh
        .summary
        .contains("trusts tokens that https://token.actions.githubusercontent.com issues for the subject repo:contoso/provisioner:ref:refs/heads/main: whoever can get one"));
    assert!(
        gh.remediation.starts_with(
            "Remove the federated identity credential on the application PROVISIONER@"
        ),
        "{}",
        gh.remediation
    );
    assert!(gh
        .remediation
        .contains("RoleManagement.ReadWrite.Directory from PROVISIONER@"));
    assert_eq!(gh.sources, ["AzureHound"]);
    assert!(gh.severity >= Severity::High);
    let aks = fic.iter().find(|f| f.affected[0].id != github).unwrap();
    assert!(aks
        .title
        .contains("system:serviceaccount:provisioning:runner (https://oidc.prod-aks.azure.com/fabrikam-cluster/)"));
}

/// No role assignment scoped to an administrative unit is tenant-wide:
/// none gives a role edge or Tier Zero, and they are counted as not
/// modeled.
#[test]
fn administrative_unit_roles_are_never_tenant_wide() {
    let a = contoso();
    // HELPDESK (Helpdesk Administrator), AUADMIN (Global Administrator) and
    // USERADMIN (eligible User Administrator), all scoped to a unit.
    for n in [2, 3, 5] {
        let kinds = out_kinds(&a, &g(n));
        assert!(
            kinds
                .iter()
                .all(|k| k != "AZHasRole" && k != "AZRoleEligible"),
            "{n}: {kinds:?}"
        );
        assert!(!t0(&a, &g(n)), "{n}");
    }
    assert!(t0(&a, &g(1)), "the tenant-wide Global Administrator");
    // Nobody holds Helpdesk or User Administrator tenant-wide: they reset
    // nobody.
    let gr = &a.graph;
    for tpl in [HELPDESK, USER_ADMIN] {
        let r = gr.lookup(&role(tpl)).unwrap();
        assert!(gr
            .inner()
            .edges_directed(r, petgraph::Direction::Outgoing)
            .all(|e| e.weight().as_str() != "AZResetPassword"));
    }
    assert!(!pw031(&a).iter().any(|f| f.affected[0].id == g(5)));
    let s = a
        .stats
        .opengraph
        .sources
        .iter()
        .find(|s| s.name == "AzureHound")
        .unwrap();
    assert_eq!(s.scoped_roles, 3);
    assert!(s.complete, "{s:#?}");
    assert_eq!(s.coverage.ok, [TENANT]);
    assert_eq!(
        s.not_modeled().as_deref(),
        Some("3 role assignments scoped to an administrative unit or one object")
    );
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains(
        "AzureHound: 3 role assignments scoped to an administrative unit or one object not modeled (never counted as tenant-wide)"
    ));
}

/// Control of the AD group that syncs to an Entra group carries into
/// Entra ID.
#[test]
fn a_synchronized_group_links_from_its_ad_group() {
    let a = contoso();
    assert!(edge(
        &a,
        &format!("{D}-1201"),
        &g(820),
        "SyncedToEntraGroup"
    ));
    assert!(edge(
        &a,
        &format!("{D}-1101"),
        &format!("{D}-1201"),
        "AddMember"
    ));
    // Cloud groups link to nothing on-premises.
    let gr = &a.graph;
    for n in [800, 810] {
        let ix = gr.lookup(&g(n)).unwrap();
        assert!(gr
            .inner()
            .edges_directed(ix, petgraph::Direction::Incoming)
            .all(|e| e.weight().as_str() != "SyncedToEntraGroup"));
    }
    let e = gr
        .inner()
        .edge_references()
        .find(|e| e.weight().as_str() == "SyncedToEntraGroup")
        .unwrap();
    assert!(gr.traversable(*e.weight(), e.target()));
    let o = gr.edge_origin(e.id()).unwrap();
    assert_eq!(gr.source_name(o.source), "AzureHound");
    assert_eq!(o.unit.as_deref(), Some(TENANT));
}

/// The new kinds are the pack's: labels and icons in Explore and the report.
#[test]
fn new_kinds_show_with_the_pack_s_labels() {
    let a = contoso();
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(
        html.contains("(Federated identity)"),
        "the path diagram's label"
    );
    assert!(html.contains(r##"href="#i-x-link""##));
    assert!(!html.contains("(AZFederatedIdentityCredential)"));
    let bin = pathwarden_core::explore::encode(&a.graph, &a.findings, &a.zones);
    let text = String::from_utf8_lossy(&bin);
    assert!(text.contains("Federated identity"));
    assert!(text.contains("AZMGAddSecret"));
    assert!(
        a.findings.iter().all(|f| f.rule != "PW-030"),
        "every traversable AzureHound kind names a rule"
    );
}
