//! Entra ID (Azure AD) and hybrid attack paths, from AzureHound data.
//!
//! The AzureHound reader ([`crate::ingest`]) adds Entra objects as external
//! objects of the built-in `azurehound` pack (`packs/azurehound.toml`) with
//! the relationships AzureHound states: group membership (`AZMemberOf`),
//! ownership (`AZOwns`), role assignments (`AZHasRole`, `AZRoleEligible`,
//! app-scoped `AZAppAdmin` / `AZCloudAppAdmin`) and `AZRunsAs`.
//!
//! This module, run at the end of post-processing ([`derive`]), adds what
//! those imply, the way BloodHound CE's Azure post-processing does
//! (`packages/go/analysis/azure/post.go`), with the differences listed in
//! `docs/entra.md`:
//!
//! - role abilities, drawn from the role object: `AZResetPassword`,
//!   `AZAddMembers`, `AZAddSecret`, `AZAddOwner`, `AZExecuteCommand`, and
//!   `AZGlobalAdmin` / `AZPrivilegedRoleAdmin` / `AZPrivilegedAuthAdmin` to
//!   the tenant;
//! - what Microsoft Graph application permissions allow, drawn from the
//!   service principal that holds them: `AZMGGrantRole`,
//!   `AZMGGrantAppRoles`, `AZMGAddSecret`, `AZMGAddOwner`, `AZMGAddMember`
//!   (see [`graph_permissions`]);
//! - hybrid links between the directory and the tenant:
//!   - `SyncedToEntraUser` (AD user to the Entra user whose
//!     `onPremisesSecurityIdentifier` is its SID);
//!   - `SyncedToADUser` (back, for password writeback), only when the Entra
//!     Connect connector account can reset that AD user's password;
//!   - `SyncedToADComputer` (a hybrid-joined device to its AD computer, by
//!     unique name);
//!   - `HasEntraSyncCredential` (the Entra Connect server to the Entra
//!     `Sync_<server>_…` account);
//!   - `SyncedToEntraGroup` (AD group to the Entra group synchronized from
//!     it).
//!
//! [`mark_tier_zero`] makes the tenant, the Tier Zero roles (Global
//! Administrator, Privileged Role Administrator, Privileged Authentication
//! Administrator, Directory Synchronization Accounts) and their holders
//! (active or eligible, directly or through a role-assignable group) Tier
//! Zero, with service principals granted RoleManagement.ReadWrite.Directory
//! or AppRoleAssignment.ReadWrite.All and the application of a service
//! principal that is. It is the one exception to "external data never makes anything
//! Tier Zero", and it never marks an AD object.

use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::AdGraph;
use crate::kinds;
use crate::model::{EdgeKind, Node, NodeKind, SourceId};
use crate::opengraph::EdgeOrigin;

/// The source name AzureHound data is recorded under.
pub const SOURCE: &str = "AzureHound";

/// The built-in mapping pack AzureHound kinds belong to.
pub const PACK: &str = "azurehound";

// Role template IDs (Microsoft Entra built-in roles, lower case).
pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
pub const PRIVILEGED_ROLE_ADMIN: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";
pub const PRIVILEGED_AUTH_ADMIN: &str = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13";
pub const DIRECTORY_SYNC_ACCOUNTS: &str = "d29b2b05-8046-44ba-8758-1e26182fcf32";
pub const AUTHENTICATION_ADMIN: &str = "c4e39bd9-1100-46d3-8c65-fb160da0071f";
pub const HELPDESK_ADMIN: &str = "729827e3-9c14-49f7-bb1b-9608f156bbb8";
pub const PASSWORD_ADMIN: &str = "966707d0-3269-4727-9be2-8c3a10f19b9d";
pub const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
pub const INTUNE_ADMIN: &str = "3a2c62db-5318-420d-8d74-23affee5d9d5";
pub const HYBRID_IDENTITY_ADMIN: &str = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2";
pub const APPLICATION_ADMIN: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
pub const CLOUD_APPLICATION_ADMIN: &str = "158c047a-c907-4556-b7ef-446551a6b5f7";
pub const GROUPS_ADMIN: &str = "fdd7a751-b60b-444a-984c-02652fe8fa1c";
pub const PARTNER_TIER1: &str = "4ba39ca4-527c-499a-b93d-d9b492c50246";
pub const PARTNER_TIER2: &str = "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8";
pub const DIRECTORY_WRITERS: &str = "9360feb5-f418-4baa-8175-e2a00bac4301";
pub const IDENTITY_GOVERNANCE_ADMIN: &str = "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e";
pub const KNOWLEDGE_ADMIN: &str = "b5a8dcf3-09d5-43a9-a639-8e29ef291470";
pub const KNOWLEDGE_MANAGER: &str = "744ec460-397e-42ad-a462-8b3f9747a02c";
pub const DIRECTORY_READERS: &str = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b";
pub const GUEST_INVITER: &str = "95e79109-95c0-4d8e-aee3-d01accf2d47b";
pub const MESSAGE_CENTER_READER: &str = "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b";
pub const REPORTS_READER: &str = "4a5d8f65-41da-4de4-8968-e035b65339cf";
pub const USAGE_SUMMARY_READER: &str = "75934031-6c7e-415a-99d7-48dbd49e875e";

/// Microsoft Graph's application ID, the same in every tenant.
pub const MS_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// The kind of the external identity a federated identity credential
/// trusts (one object per issuer and subject).
pub const EXTERNAL_IDENTITY: &str = "AZFederatedIdentityCredential";

/// A Microsoft Graph application permission Pathwarden reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphPermission {
    /// The app role ID (`appRoleId`), lower case.
    pub id: &'static str,
    /// Its name, as Microsoft writes it.
    pub name: &'static str,
    /// The kind of the stated edge, from the service principal to Microsoft
    /// Graph's: BloodHound CE's name.
    pub stated: &'static str,
}

// Microsoft Graph application permission IDs, as BloodHound CE lists them
// (packages/go/graphschema/azure/identifiers.go) and Microsoft documents
// them (https://learn.microsoft.com/en-us/graph/permissions-reference).
pub const APPLICATION_RW_ALL: GraphPermission = GraphPermission {
    id: "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
    name: "Application.ReadWrite.All",
    stated: "AZMGApplication_ReadWrite_All",
};
pub const APP_ROLE_ASSIGNMENT_RW_ALL: GraphPermission = GraphPermission {
    id: "06b708a9-e830-4db3-a914-8e69da51d44f",
    name: "AppRoleAssignment.ReadWrite.All",
    stated: "AZMGAppRoleAssignment_ReadWrite_All",
};
pub const DIRECTORY_RW_ALL: GraphPermission = GraphPermission {
    id: "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
    name: "Directory.ReadWrite.All",
    stated: "AZMGDirectory_ReadWrite_All",
};
pub const GROUP_RW_ALL: GraphPermission = GraphPermission {
    id: "62a82d76-70ea-41e2-9197-370581804d09",
    name: "Group.ReadWrite.All",
    stated: "AZMGGroup_ReadWrite_All",
};
pub const GROUP_MEMBER_RW_ALL: GraphPermission = GraphPermission {
    id: "dbaae8cf-10b5-4b86-a4a1-f871c94c6695",
    name: "GroupMember.ReadWrite.All",
    stated: "AZMGGroupMember_ReadWrite_All",
};
pub const ROLE_MANAGEMENT_RW_DIRECTORY: GraphPermission = GraphPermission {
    id: "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    name: "RoleManagement.ReadWrite.Directory",
    stated: "AZMGRoleManagement_ReadWrite_Directory",
};
pub const SP_ENDPOINT_RW_ALL: GraphPermission = GraphPermission {
    id: "89c8469c-83ad-45f7-8ff2-6e3d4285709e",
    name: "ServicePrincipalEndpoint.ReadWrite.All",
    stated: "AZMGServicePrincipalEndpoint_ReadWrite_All",
};

/// Every Microsoft Graph application permission read.
pub const GRAPH_PERMISSIONS: &[GraphPermission] = &[
    APPLICATION_RW_ALL,
    APP_ROLE_ASSIGNMENT_RW_ALL,
    DIRECTORY_RW_ALL,
    GROUP_RW_ALL,
    GROUP_MEMBER_RW_ALL,
    ROLE_MANAGEMENT_RW_DIRECTORY,
    SP_ENDPOINT_RW_ALL,
];

/// Permissions that make their holder Tier Zero: it can grant itself
/// Global Administrator (RoleManagement.ReadWrite.Directory), or grant
/// itself that permission (AppRoleAssignment.ReadWrite.All).
pub const TIER_ZERO_PERMISSIONS: &[GraphPermission] =
    &[ROLE_MANAGEMENT_RW_DIRECTORY, APP_ROLE_ASSIGNMENT_RW_ALL];

/// The Microsoft Graph permission with app role ID `id`, if one is read.
pub fn graph_permission(id: &str) -> Option<&'static GraphPermission> {
    let id = id.trim();
    GRAPH_PERMISSIONS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id))
}

/// The Microsoft Graph permissions that give `derived` (an `AZMG...` kind
/// drawn in [`derive`]) on an object of kind `target`.
pub fn permissions_for(derived: &str, target: Option<&str>) -> &'static [GraphPermission] {
    match (derived, target) {
        ("AZMGGrantRole", _) => &[ROLE_MANAGEMENT_RW_DIRECTORY],
        ("AZMGGrantAppRoles", _) => &[APP_ROLE_ASSIGNMENT_RW_ALL],
        ("AZMGAddSecret", _) => &[APPLICATION_RW_ALL],
        ("AZMGAddOwner", Some("AZServicePrincipal")) => &[APPLICATION_RW_ALL, SP_ENDPOINT_RW_ALL],
        ("AZMGAddOwner", _) => &[APPLICATION_RW_ALL],
        ("AZMGAddMember", _) => &[DIRECTORY_RW_ALL, GROUP_RW_ALL, GROUP_MEMBER_RW_ALL],
        _ => &[],
    }
}

/// The Microsoft Graph permissions `sp` is granted (stated edges from this
/// source).
pub fn granted(g: &AdGraph, sp: NodeIndex) -> Vec<&'static GraphPermission> {
    let src = source_id(g);
    let mut out: Vec<&'static GraphPermission> = Vec::new();
    for e in g.inner().edges_directed(sp, Direction::Outgoing) {
        if src.is_none() || g.edge_origin(e.id()).map(|o| o.source) != src {
            continue;
        }
        if let Some(p) = GRAPH_PERMISSIONS
            .iter()
            .find(|p| kind_is(*e.weight(), p.stated))
        {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// The name shown for an external identity: its subject and issuer.
/// Each part is cut to 512 bytes.
pub fn external_identity_name(issuer: &str, subject: &str) -> String {
    fn cut(s: &str) -> &str {
        let s = s.trim();
        let mut end = s.len().min(512);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
    format!("{} ({})", cut(subject), cut(issuer))
}

/// Roles that seed Entra Tier Zero.
pub const TIER_ZERO_ROLES: &[(&str, &str)] = &[
    (GLOBAL_ADMIN, "Global Administrator"),
    (PRIVILEGED_ROLE_ADMIN, "Privileged Role Administrator"),
    (
        PRIVILEGED_AUTH_ADMIN,
        "Privileged Authentication Administrator",
    ),
    (
        DIRECTORY_SYNC_ACCOUNTS,
        "Directory Synchronization Accounts",
    ),
];

/// Whose password a role can reset, by the target's own active roles
/// (Microsoft's "who can reset passwords" table, as BloodHound encodes it).
/// `None`: every user. `Some(list)`: users without roles, or whose roles
/// are all in `list`; members and owners of role-assignable groups never.
fn reset_scope(template: &str) -> Option<Option<&'static [&'static str]>> {
    const USER_ADMIN_OK: &[&str] = &[
        USER_ADMIN,
        REPORTS_READER,
        MESSAGE_CENTER_READER,
        HELPDESK_ADMIN,
        GUEST_INVITER,
        DIRECTORY_READERS,
        PASSWORD_ADMIN,
        USAGE_SUMMARY_READER,
        GROUPS_ADMIN,
    ];
    const HELPDESK_OK: &[&str] = &[
        REPORTS_READER,
        MESSAGE_CENTER_READER,
        HELPDESK_ADMIN,
        GUEST_INVITER,
        DIRECTORY_READERS,
        PASSWORD_ADMIN,
        USAGE_SUMMARY_READER,
    ];
    const AUTH_ADMIN_OK: &[&str] = &[
        AUTHENTICATION_ADMIN,
        REPORTS_READER,
        MESSAGE_CENTER_READER,
        GUEST_INVITER,
        DIRECTORY_READERS,
        PASSWORD_ADMIN,
        USAGE_SUMMARY_READER,
    ];
    const PASSWORD_ADMIN_OK: &[&str] = &[PASSWORD_ADMIN, GUEST_INVITER, DIRECTORY_READERS];
    Some(match template {
        GLOBAL_ADMIN | PRIVILEGED_AUTH_ADMIN | PARTNER_TIER2 => None,
        USER_ADMIN => Some(USER_ADMIN_OK),
        HELPDESK_ADMIN => Some(HELPDESK_OK),
        AUTHENTICATION_ADMIN => Some(AUTH_ADMIN_OK),
        PASSWORD_ADMIN => Some(PASSWORD_ADMIN_OK),
        PARTNER_TIER1 => Some(&[]),
        _ => return None,
    })
}

/// Roles that can add members to groups that are not role-assignable.
const ADD_MEMBERS: &[&str] = &[
    GROUPS_ADMIN,
    DIRECTORY_WRITERS,
    IDENTITY_GOVERNANCE_ADMIN,
    USER_ADMIN,
    INTUNE_ADMIN,
    KNOWLEDGE_ADMIN,
    KNOWLEDGE_MANAGER,
];

/// Roles that can add secrets to every application and service principal.
const ADD_SECRET: &[&str] = &[APPLICATION_ADMIN, CLOUD_APPLICATION_ADMIN];

/// Roles that can add owners to every application and service principal.
/// (Directory Synchronization Accounts too, but it is Tier Zero.)
const ADD_OWNER: &[&str] = &[HYBRID_IDENTITY_ADMIN, PARTNER_TIER1, PARTNER_TIER2];

/// The `AZ...` kind of an object AzureHound data created, if it is one.
pub fn az_kind(n: &Node) -> Option<&'static str> {
    match n.kind {
        NodeKind::External(k) if n.og_created() => {
            let name = kinds::name(k);
            name.starts_with("AZ").then_some(name)
        }
        _ => None,
    }
}

/// Whether `n` is an Entra object (from AzureHound data).
pub fn is_entra(n: &Node) -> bool {
    az_kind(n).is_some()
}

fn prop<'a>(n: &'a Node, key: &str) -> Option<&'a serde_json::Value> {
    n.ext.as_ref().and_then(|e| e.prop(key))
}

fn prop_str<'a>(n: &'a Node, key: &str) -> Option<&'a str> {
    prop(n, key).and_then(|v| v.as_str())
}

fn prop_bool(n: &Node, key: &str) -> bool {
    prop(n, key).is_some_and(truthy)
}

/// A boolean as collectors write it (`true`, `"True"`, `1`). AzureHound
/// omits false booleans, so a missing one is false.
pub fn truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        serde_json::Value::Number(n) => n.as_i64().is_some_and(|i| i != 0),
        _ => false,
    }
}

/// The tenant (upper-case ID) an Entra object belongs to.
pub fn tenant_of(n: &Node) -> Option<String> {
    prop_str(n, "tenantid").map(str::to_ascii_uppercase)
}

/// A role object's template ID, lower case.
pub fn role_template(n: &Node) -> Option<String> {
    if az_kind(n) != Some("AZRole") {
        return None;
    }
    prop_str(n, "roletemplateid")
        .map(str::to_owned)
        .or_else(|| n.id.split('@').next().map(str::to_owned))
        .map(|t| t.to_ascii_lowercase())
}

/// The source ID of AzureHound data in this graph.
pub fn source_id(g: &AdGraph) -> Option<SourceId> {
    g.og_sources()
        .iter()
        .position(|s| s == SOURCE)
        .map(|i| i as SourceId)
}

fn kind_is(k: EdgeKind, name: &str) -> bool {
    matches!(k, EdgeKind::External(x) if kinds::name(x) == name)
}

fn ext(name: &str) -> EdgeKind {
    EdgeKind::External(kinds::intern(name))
}

/// Entra objects by kind, and who holds which role.
struct Tenant {
    roles: Vec<(NodeIndex, String)>,
    users: Vec<NodeIndex>,
    groups: Vec<NodeIndex>,
    apps: Vec<NodeIndex>,
    /// Service principals (also in `apps`).
    sps: Vec<NodeIndex>,
    devices: Vec<NodeIndex>,
    tenant: Option<NodeIndex>,
}

/// Principals that hold `role` (`active`: assignments only; else also
/// eligibility), directly or as a member of a group that holds it.
fn holders(g: &AdGraph, role: NodeIndex, active: bool) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    for e in g.inner().edges_directed(role, Direction::Incoming) {
        let k = *e.weight();
        if !(kind_is(k, "AZHasRole") || (!active && kind_is(k, "AZRoleEligible"))) {
            continue;
        }
        let p = e.source();
        if !out.contains(&p) {
            out.push(p);
        }
        if az_kind(g.node(p)) == Some("AZGroup") {
            for m in g.inner().edges_directed(p, Direction::Incoming) {
                if kind_is(*m.weight(), "AZMemberOf") && !out.contains(&m.source()) {
                    out.push(m.source());
                }
            }
        }
    }
    out
}

/// Adds the edges AzureHound data implies (see the module documentation).
/// Part of post-processing; without AzureHound data it does nothing.
pub fn derive(g: &mut AdGraph) {
    let Some(src) = source_id(g) else {
        return;
    };
    let mut by_tenant: HashMap<String, Tenant> = HashMap::new();
    for (ix, n) in g.nodes() {
        let Some(kind) = az_kind(n) else { continue };
        let Some(t) = tenant_of(n) else { continue };
        let entry = by_tenant.entry(t).or_insert_with(|| Tenant {
            roles: Vec::new(),
            users: Vec::new(),
            groups: Vec::new(),
            apps: Vec::new(),
            sps: Vec::new(),
            devices: Vec::new(),
            tenant: None,
        });
        match kind {
            "AZRole" => {
                if let Some(tpl) = role_template(n) {
                    entry.roles.push((ix, tpl));
                }
            }
            "AZUser" => entry.users.push(ix),
            "AZGroup" => entry.groups.push(ix),
            "AZApp" => entry.apps.push(ix),
            "AZServicePrincipal" => {
                entry.apps.push(ix);
                entry.sps.push(ix);
            }
            "AZDevice" => entry.devices.push(ix),
            "AZTenant" => entry.tenant = Some(ix),
            _ => {}
        }
    }

    let mut add: Vec<(NodeIndex, NodeIndex, &'static str, String)> = Vec::new();
    for (tid, t) in &by_tenant {
        // Each user's active roles, and who is protected by a
        // role-assignable group (member or owner).
        let mut user_roles: HashMap<NodeIndex, HashSet<&str>> = HashMap::new();
        for (role, tpl) in &t.roles {
            for h in holders(g, *role, true) {
                user_roles.entry(h).or_default().insert(tpl.as_str());
            }
        }
        let mut protected: HashSet<NodeIndex> = HashSet::new();
        for &grp in &t.groups {
            if prop_bool(g.node(grp), "isassignabletorole") {
                for e in g.inner().edges_directed(grp, Direction::Incoming) {
                    if kind_is(*e.weight(), "AZMemberOf") || kind_is(*e.weight(), "AZOwns") {
                        protected.insert(e.source());
                    }
                }
            }
        }

        for (role, tpl) in &t.roles {
            let tpl = tpl.as_str();
            // Tier Zero roles: their holders already won; only the tenant
            // edge is drawn, for reading the graph.
            if TIER_ZERO_ROLES.iter().any(|(r, _)| *r == tpl) {
                let kind = match tpl {
                    GLOBAL_ADMIN => Some("AZGlobalAdmin"),
                    PRIVILEGED_ROLE_ADMIN => Some("AZPrivilegedRoleAdmin"),
                    PRIVILEGED_AUTH_ADMIN => Some("AZPrivilegedAuthAdmin"),
                    _ => None,
                };
                if let (Some(kind), Some(tenant)) = (kind, t.tenant) {
                    add.push((*role, tenant, kind, tid.clone()));
                }
                continue;
            }
            // A role nobody holds (or may activate) is no path.
            if holders(g, *role, false).is_empty() {
                continue;
            }
            if let Some(scope) = reset_scope(tpl) {
                for &u in &t.users {
                    let ok = match scope {
                        None => true,
                        Some(allowed) => {
                            !protected.contains(&u)
                                && user_roles
                                    .get(&u)
                                    .is_none_or(|rs| rs.iter().all(|r| allowed.contains(r)))
                        }
                    };
                    if ok {
                        add.push((*role, u, "AZResetPassword", tid.clone()));
                    }
                }
            }
            if ADD_MEMBERS.contains(&tpl) {
                for &grp in &t.groups {
                    let n = g.node(grp);
                    if cloud_changeable(n) {
                        add.push((*role, grp, "AZAddMembers", tid.clone()));
                    }
                }
            }
            if ADD_SECRET.contains(&tpl) {
                for &a in &t.apps {
                    add.push((*role, a, "AZAddSecret", tid.clone()));
                }
            }
            if ADD_OWNER.contains(&tpl) {
                for &a in &t.apps {
                    add.push((*role, a, "AZAddOwner", tid.clone()));
                }
            }
            if tpl == INTUNE_ADMIN {
                for &d in &t.devices {
                    let n = g.node(d);
                    let windows = prop_str(n, "operatingsystem")
                        .is_some_and(|os| os.to_ascii_lowercase().contains("windows"));
                    // Only Intune-managed devices run Intune scripts.
                    if windows && prop_bool(n, "ismanaged") {
                        add.push((*role, d, "AZExecuteCommand", tid.clone()));
                    }
                }
            }
        }

        graph_permissions(g, tid, t, &mut add);
    }

    hybrid(g, &by_tenant, &mut add);

    for (from, to, kind, tenant) in add {
        g.add_og_edge(
            from,
            to,
            ext(kind),
            EdgeOrigin {
                source: src,
                unit: Some(tenant),
            },
        );
    }
}

/// Whether a group's members can be changed by a role or permission that
/// manages groups. Role-assignable groups only by Global and Privileged
/// Role Administrators (and RoleManagement.ReadWrite.Directory, which is
/// Tier Zero); synchronized groups are managed on-premises and can't be
/// changed in the cloud.
fn cloud_changeable(n: &Node) -> bool {
    !prop_bool(n, "isassignabletorole") && !prop_bool(n, "onpremisessyncenabled")
}

/// What a tenant's Microsoft Graph application permissions allow, drawn
/// from the service principal that holds them, as BloodHound CE's
/// `AppRoleAssignments` post-processing does
/// (`packages/go/analysis/azure/post.go`):
///
/// - RoleManagement.ReadWrite.Directory: `AZMGGrantRole` to every role;
/// - AppRoleAssignment.ReadWrite.All: `AZMGGrantAppRoles` to the tenant;
/// - Application.ReadWrite.All: `AZMGAddSecret` and `AZMGAddOwner` to every
///   application and service principal;
/// - ServicePrincipalEndpoint.ReadWrite.All: `AZMGAddOwner` to every
///   service principal;
/// - Directory.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All:
///   `AZMGAddMember` to groups that are neither role-assignable nor
///   synchronized from AD.
///
/// BloodHound also draws `AZMGAddOwner` to those groups for
/// Directory.ReadWrite.All and Group.ReadWrite.All: an owner of a group
/// gains nothing a new member doesn't, so `AZMGAddMember` is the path.
fn graph_permissions(
    g: &AdGraph,
    tid: &str,
    t: &Tenant,
    add: &mut Vec<(NodeIndex, NodeIndex, &'static str, String)>,
) {
    for &sp in &t.sps {
        let perms = granted(g, sp);
        if perms.is_empty() {
            continue;
        }
        let has = |p: GraphPermission| perms.iter().any(|q| **q == p);
        let mut push = |to: NodeIndex, kind: &'static str| {
            if to != sp {
                add.push((sp, to, kind, tid.to_string()));
            }
        };
        if has(ROLE_MANAGEMENT_RW_DIRECTORY) {
            for (role, _) in &t.roles {
                push(*role, "AZMGGrantRole");
            }
        }
        if has(APP_ROLE_ASSIGNMENT_RW_ALL) {
            if let Some(tenant) = t.tenant {
                push(tenant, "AZMGGrantAppRoles");
            }
        }
        if has(APPLICATION_RW_ALL) {
            for &a in &t.apps {
                push(a, "AZMGAddSecret");
                push(a, "AZMGAddOwner");
            }
        } else if has(SP_ENDPOINT_RW_ALL) {
            for &a in &t.sps {
                push(a, "AZMGAddOwner");
            }
        }
        if has(DIRECTORY_RW_ALL) || has(GROUP_RW_ALL) || has(GROUP_MEMBER_RW_ALL) {
            for &grp in &t.groups {
                if cloud_changeable(g.node(grp)) {
                    push(grp, "AZMGAddMember");
                }
            }
        }
    }
}

/// An AD object (collected, not from external data).
fn ad_object(n: &Node) -> bool {
    !n.placeholder && n.ext.as_ref().is_none_or(|e| !e.og_created)
}

/// The hybrid links (see the module documentation).
fn hybrid(
    g: &AdGraph,
    by_tenant: &HashMap<String, Tenant>,
    add: &mut Vec<(NodeIndex, NodeIndex, &'static str, String)>,
) {
    // AD users the Entra Connect connector account can reset: password
    // writeback runs as that account.
    let connectors: Vec<NodeIndex> = crate::mgmt::detect(g)
        .into_iter()
        .filter(|d| {
            d.plane == crate::mgmt::Plane::EntraConnect
                && d.role == crate::mgmt::Role::Account
                && d.confidence == crate::mgmt::Confidence::Strong
        })
        .map(|d| d.object)
        .collect();
    let mut acting: HashSet<NodeIndex> = connectors.iter().copied().collect();
    let mut queue: Vec<NodeIndex> = connectors;
    while let Some(v) = queue.pop() {
        for e in g.inner().edges_directed(v, Direction::Outgoing) {
            if *e.weight() == EdgeKind::MemberOf
                && g.edge_origin(e.id()).is_none()
                && acting.insert(e.target())
            {
                queue.push(e.target());
            }
        }
    }
    let mut resettable: HashSet<NodeIndex> = HashSet::new();
    for &a in &acting {
        for e in g.inner().edges_directed(a, Direction::Outgoing) {
            let reset = matches!(
                *e.weight(),
                EdgeKind::ForceChangePassword | EdgeKind::GenericAll | EdgeKind::AllExtendedRights
            );
            if reset && g.edge_origin(e.id()).is_none() {
                resettable.insert(e.target());
            }
        }
    }

    // AD computers by short name, for devices and the Sync_ account.
    let mut computers: HashMap<String, Vec<NodeIndex>> = HashMap::new();
    for (ix, n) in g.nodes() {
        if n.kind == NodeKind::Computer && ad_object(n) && n.is_enabled() {
            let short = n.name.split(['.', '@']).next().unwrap_or(&n.name);
            computers
                .entry(short.trim_end_matches('$').to_ascii_uppercase())
                .or_default()
                .push(ix);
        }
    }
    let computer = |name: &str| -> Option<NodeIndex> {
        let short = name.split('.').next()?.trim().to_ascii_uppercase();
        match computers.get(&short)?.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };

    for (tid, t) in by_tenant {
        let dir_sync = t
            .roles
            .iter()
            .find(|(_, tpl)| tpl == DIRECTORY_SYNC_ACCOUNTS)
            .map(|(r, _)| holders(g, *r, true))
            .unwrap_or_default();
        for &u in &t.users {
            let n = g.node(u);
            if prop_bool(n, "onpremisessyncenabled") {
                let ad = prop_str(n, "onpremisessecurityidentifier")
                    .filter(|s| crate::opengraph::is_sid_shaped(s))
                    .and_then(|s| g.lookup(s))
                    .filter(|&a| {
                        let an = g.node(a);
                        an.kind == NodeKind::User && ad_object(an)
                    });
                if let Some(a) = ad {
                    add.push((a, u, "SyncedToEntraUser", tid.clone()));
                    if resettable.contains(&a) {
                        add.push((u, a, "SyncedToADUser", tid.clone()));
                    }
                }
            }
            // Entra Connect's own cloud account: Sync_<SERVER>_<hex>@...
            if dir_sync.contains(&u) {
                if let Some(host) = sync_account_host(&n.name) {
                    if let Some(c) = computer(&host) {
                        add.push((c, u, "HasEntraSyncCredential", tid.clone()));
                    }
                }
            }
        }
        // A group Entra Connect synchronizes from AD: whoever can add
        // members to the AD group adds them to the Entra group too.
        for &grp in &t.groups {
            let n = g.node(grp);
            if !prop_bool(n, "onpremisessyncenabled") {
                continue;
            }
            let ad = prop_str(n, "onpremisessecurityidentifier")
                .filter(|s| crate::opengraph::is_sid_shaped(s))
                .and_then(|s| g.lookup(s))
                .filter(|&a| {
                    let an = g.node(a);
                    an.kind == NodeKind::Group && ad_object(an)
                });
            if let Some(a) = ad {
                add.push((a, grp, "SyncedToEntraGroup", tid.clone()));
            }
        }
        for &d in &t.devices {
            let n = g.node(d);
            let hybrid_joined =
                prop_str(n, "trusttype").is_some_and(|s| s.eq_ignore_ascii_case("ServerAd"));
            if !hybrid_joined {
                continue;
            }
            if let Some(c) = prop_str(n, "displayname").and_then(computer) {
                add.push((d, c, "SyncedToADComputer", tid.clone()));
            }
        }
    }
}

/// The server in an Entra Connect cloud sync account's name
/// (`SYNC_AADC01_0A1B2C3D4E5F@CONTOSO.ONMICROSOFT.COM`).
pub fn sync_account_host(upn: &str) -> Option<String> {
    let local = upn.split('@').next()?.to_ascii_uppercase();
    let rest = local.strip_prefix("SYNC_")?;
    let (host, suffix) = rest.rsplit_once('_')?;
    let hex = suffix.len() >= 6 && suffix.bytes().all(|b| b.is_ascii_hexdigit());
    (hex && !host.is_empty()).then(|| host.to_string())
}

/// Marks Entra Tier Zero (see the module documentation). Called by
/// [`crate::tierzero::mark_with`]; without AzureHound data it does nothing.
pub fn mark_tier_zero(g: &mut AdGraph) {
    let Some(src) = source_id(g) else {
        return;
    };
    let mut queue: Vec<NodeIndex> = Vec::new();
    let seeds: Vec<(NodeIndex, String)> = g
        .nodes()
        .filter(|(_, n)| !n.tier_zero)
        .filter_map(|(ix, n)| {
            let reason = match az_kind(n)? {
                "AZTenant" => "Entra tenant".to_string(),
                "AZRole" => {
                    let tpl = role_template(n)?;
                    let (_, name) = TIER_ZERO_ROLES.iter().find(|(r, _)| *r == tpl)?;
                    format!("Entra Tier Zero role ({name})")
                }
                // A service principal that can grant itself Global
                // Administrator, or the permission that can.
                "AZServicePrincipal" => {
                    let perms = granted(g, ix);
                    let p = TIER_ZERO_PERMISSIONS.iter().find(|p| perms.contains(p))?;
                    format!("Holds Microsoft Graph permission {}", p.name)
                }
                _ => return None,
            };
            Some((ix, reason))
        })
        .collect();
    for (ix, reason) in seeds {
        set(g, ix, reason);
        queue.push(ix);
    }
    while let Some(v) = queue.pop() {
        let name = g.node(v).name.clone();
        let incoming: Vec<(NodeIndex, String)> = g
            .inner()
            .edges_directed(v, Direction::Incoming)
            .filter(|e| g.edge_origin(e.id()).is_some_and(|o| o.source == src))
            .filter(|e| !g.node(e.source()).tier_zero && is_entra(g.node(e.source())))
            .filter_map(|e| {
                let k = *e.weight();
                let reason = if kind_is(k, "AZHasRole") {
                    format!("Holds Entra role {name}")
                } else if kind_is(k, "AZRoleEligible") {
                    format!("Eligible for Entra role {name}")
                } else if kind_is(k, "AZMemberOf") {
                    format!("Member of Entra group {name}")
                } else if kind_is(k, "AZRunsAs") {
                    // Whoever adds a credential to the application signs
                    // in as its service principal.
                    format!("Application of Entra service principal {name}")
                } else {
                    return None;
                };
                Some((e.source(), reason))
            })
            .collect();
        for (ix, reason) in incoming {
            if !g.node(ix).tier_zero {
                set(g, ix, reason);
                queue.push(ix);
            }
        }
    }
}

fn set(g: &mut AdGraph, ix: NodeIndex, reason: String) {
    let n = g.node_mut(ix);
    n.tier_zero = true;
    n.tier_zero_reason = Some(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_account_names() {
        assert_eq!(
            sync_account_host("Sync_AADC01_3a5b7c9d1e2f@contoso.onmicrosoft.com").as_deref(),
            Some("AADC01")
        );
        assert_eq!(
            sync_account_host("SYNC_SRV_CONNECT_01_ABCDEF123456@X").as_deref(),
            Some("SRV_CONNECT_01")
        );
        assert_eq!(sync_account_host("syncadmin@contoso.com"), None);
        assert_eq!(sync_account_host("Sync_AADC01_notHex@x"), None);
    }

    #[test]
    fn reset_rules_follow_microsoft() {
        assert_eq!(reset_scope(GLOBAL_ADMIN), Some(None));
        assert!(reset_scope(HELPDESK_ADMIN)
            .unwrap()
            .unwrap()
            .contains(&PASSWORD_ADMIN));
        assert!(!reset_scope(HELPDESK_ADMIN)
            .unwrap()
            .unwrap()
            .contains(&USER_ADMIN));
        assert_eq!(reset_scope(PARTNER_TIER1), Some(Some(&[][..])));
        assert_eq!(reset_scope(INTUNE_ADMIN), None);
    }
}
