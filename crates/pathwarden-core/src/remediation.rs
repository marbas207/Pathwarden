//! Remediation: what to change for each kind of edge, and the minimum set of
//! changes that separates every exposed principal from Tier Zero.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::Serialize;

use crate::analysis;
use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::sid;

/// The concrete change that removes an edge from `from` to `to`.
pub fn edge_fix(kind: EdgeKind, from: &str, to: &str) -> String {
    edge_fix_on(kind, from, to, None)
}

/// What kind of permission a directory right on a `to_kind` object is, in
/// words: a GPO's are its Group Policy security permissions (the
/// Delegation tab), a certificate template's its template permissions, the
/// rest Active Directory security permissions. `n` is how many rights.
pub fn permission_kind(to_kind: NodeKind, n: usize) -> &'static str {
    match (to_kind, n == 1) {
        (NodeKind::Gpo, true) => "Group Policy security permission",
        (NodeKind::Gpo, false) => "Group Policy security permissions",
        (NodeKind::CertTemplate, true) => "certificate template permission",
        (NodeKind::CertTemplate, false) => "certificate template permissions",
        (_, true) => "Active Directory security permission",
        (_, false) => "Active Directory security permissions",
    }
}

/// `name` with its kind in words: "the GPO X", "the group X", "the domain
/// object X"; the bare name for a kind without a noun.
pub fn the_kind(kind: NodeKind, name: &str) -> String {
    match kind {
        NodeKind::Domain => format!("the domain object {name}"),
        k => match k.noun() {
            Some(noun) => format!("the {noun} {name}"),
            None => name.to_string(),
        },
    }
}

/// Certificate templates, CAs and the other PKI objects in the
/// Configuration partition: the PKI administrators own and change them.
fn is_pki(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::CertTemplate
            | NodeKind::EnterpriseCa
            | NodeKind::RootCa
            | NodeKind::AiaCa
            | NodeKind::NtAuthStore
            | NodeKind::IssuancePolicy
    )
}

/// The weakness and the rule whose finding has the exact fix, for an AD CS
/// abuse edge.
fn adcs_rule(kind: EdgeKind) -> Option<(&'static str, &'static str)> {
    use EdgeKind::*;
    Some(match kind {
        AdcsEsc1 => ("ESC1", "PW-015"),
        AdcsEsc3 => ("ESC3", "PW-016"),
        AdcsEsc4 => ("ESC4", "PW-017"),
        AdcsEsc6a | AdcsEsc6b => ("ESC6", "PW-018"),
        AdcsEsc9a | AdcsEsc9b => ("ESC9", "PW-020"),
        AdcsEsc10a | AdcsEsc10b => ("ESC10", "PW-020"),
        AdcsEsc13 => ("ESC13", "PW-021"),
        _ => return None,
    })
}

/// The fix for AD CS abuse edges from `from` to `to` (each with an
/// [`adcs_rule`]): one sentence for all of them, naming each weakness and
/// the findings that have the exact change.
fn adcs_fix(kinds: &[EdgeKind], from: &str, to: &str) -> String {
    let mut escs: Vec<&str> = Vec::new();
    let mut rules: Vec<&str> = Vec::new();
    for (esc, rule) in kinds.iter().filter_map(|&k| adcs_rule(k)) {
        if !escs.contains(&esc) {
            escs.push(esc);
        }
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    let rules_words = match rules.as_slice() {
        [one] => format!("The {one} finding has"),
        [init @ .., last] => format!("The {} and {last} findings have", init.join(", ")),
        [] => "The matching AD CS finding has".to_string(),
    };
    format!(
        "{from} can get a certificate that takes over {to} ({}). {rules_words} the exact change \
         to the certificate template or CA.",
        escs.join(", ")
    )
}

/// [`edge_fix`] knowing the kind of `to`, when there is one: the object's
/// kind is named in words, and its owner is the right one for it.
pub fn edge_fix_on(kind: EdgeKind, from: &str, to: &str, to_kind: Option<NodeKind>) -> String {
    use EdgeKind::*;
    let the_to = || match to_kind {
        Some(k) => the_kind(k, to),
        None => to.to_string(),
    };
    match kind {
        MemberOf => format!("Remove {from} from the group {to}."),
        HasSession => format!(
            "Stop {to} from logging on to {from}, then log off or reboot {from} to clear its cached credentials."
        ),
        AdminTo => format!("Remove {from} from the local Administrators group on {to}."),
        CanRdp => format!("Remove {from} from Remote Desktop Users on {to}, or from the GPO that grants it."),
        ExecuteDcom => format!("Remove {from} from Distributed COM Users on {to}."),
        CanPsRemote => format!("Remove {from} from Remote Management Users on {to}."),
        AllowedToDelegate => format!("Remove {to} from the constrained delegation list (msDS-AllowedToDelegateTo) of {from}."),
        AllowedToAct => format!("Remove {from} from msDS-AllowedToActOnBehalfOfOtherIdentity on {to}."),
        HasSidHistory => format!("Clear the sIDHistory attribute on {from}."),
        Contains => format!(
            "Move {to} into a container that only Tier Zero can modify, or remove the delegated rights on {from} \
             that {to} inherits."
        ),
        GpLink => format!("Restrict who can edit the GPO {from}, or unlink it from {to}."),
        SameForestTrust => format!(
            "Intra-forest trusts cannot be filtered; protect {from} with the same controls as Tier Zero in {to}."
        ),
        DcSync => format!(
            "Remove the Active Directory security permissions Replicating Directory Changes and \
             Replicating Directory Changes All that {from} holds on the domain object {to}, or remove \
             {from} from the group that grants them."
        ),
        CoerceToTgt => format!("Disable unconstrained delegation on {from}."),
        Owns => format!(
            "Change the owner of {} to {}. The owner can always change the permissions, so removing \
             the other entries of {from} isn't enough while it owns {to}.",
            the_to(),
            if to_kind.is_some_and(is_pki) {
                "Enterprise Admins"
            } else {
                "Domain Admins"
            }
        ),
        ManageCa => format!(
            "Remove the Manage CA permission held by {from} on {to} (certsrv.msc > CA Properties > Security). \
             With it, {from} can enable EDITF_ATTRIBUTESUBJECTALTNAME2 or approve its own requests (ESC7)."
        ),
        HostsCaService | GoldenCert => format!(
            "{from} hosts a certificate authority; anyone who controls it can steal the CA key and forge \
             certificates for any account. Manage {from} as Tier Zero."
        ),
        k if k.is_adcs_abuse() => match adcs_rule(k) {
            Some((esc, rule)) => format!(
                "{from} can get a certificate that takes over {to} ({esc}). The {rule} finding has \
                 the exact change to the certificate template or CA."
            ),
            None => format!(
                "{from} can get a certificate that takes over {to}. The matching AD CS finding has \
                 the exact change to the certificate template or CA."
            ),
        },
        ReadLapsPassword | SyncLapsPassword => format!("Remove {from}'s permission to read the LAPS password of {to}."),
        ReadGmsaPassword => format!("Remove {from} from the principals allowed to retrieve the gMSA password of {to}."),
        ManagesHost => format!(
            "{from} manages {to}, so whoever controls {from} can run code on {to}. Take {to} out of \
             {from}'s management (uninstall the agent), or manage {from} as Tier Zero."
        ),
        WriteGpoFiles => format!(
            "Remove the write access {from} has to the SYSVOL folder of the GPO {to} \
             (\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{{GUID}}). Opening the GPO in Group Policy Management \
             offers to make its SYSVOL folder permissions match its Group Policy security permissions."
        ),
        WriteLogonScript => format!(
            "Remove the write access {from} has to the logon script of {to} in NETLOGON, or point {to}'s \
             logon script at a file only administrators can change."
        ),
        HasStoredCredential => format!(
            "Stop storing {to}'s password on {from}: run its services and scheduled tasks there as \
             a group managed service account (gMSA) or a virtual account instead. Then change \
             {to}'s password: any administrator of {from} could read it."
        ),
        External(_) => external_fix(None, kind, from, to),
        _ => permissions_fix_on(&[kind], from, to, to_kind),
    }
}

/// The fix for a `HasStoredCredential` edge, naming the services and
/// scheduled tasks that store the password.
pub fn stored_fix(g: &AdGraph, e: EdgeIndex) -> Option<String> {
    use crate::storedcreds::Via;
    let vias = g.stored_via(e);
    let (a, b) = g.inner().edge_endpoints(e)?;
    if vias.is_empty() {
        return None;
    }
    let (from, to) = (&g.node(a).name, &g.node(b).name);
    // "the service SqlAgent and the scheduled tasks \Sync and \Backup".
    let mut parts: Vec<String> = Vec::new();
    for (via, one, many) in [
        (Via::Service, "the service", "the services"),
        (Via::Task, "the scheduled task", "the scheduled tasks"),
    ] {
        let of: Vec<&str> = vias
            .iter()
            .filter(|v| v.via == via)
            .map(|v| v.name.as_str())
            .collect();
        if of.is_empty() {
            continue;
        }
        let mut list = and_list(&of[..of.len().min(MAX_GRANTS_SHOWN)]);
        if of.len() > MAX_GRANTS_SHOWN {
            list = format!(
                "{list} and {}",
                crate::text::count(of.len() - MAX_GRANTS_SHOWN, "more", "more")
            );
        }
        parts.push(format!("{} {list}", if of.len() == 1 { one } else { many }));
    }
    Some(format!(
        "Stop storing {to}'s password on {from}: run {} as a group managed service account \
         (gMSA) or a virtual account instead, or remove {} if no longer needed. Then change \
         {to}'s password: any administrator of {from} could read it.",
        parts.join(" and "),
        if vias.len() == 1 { "it" } else { "them" }
    ))
}

/// [`edge_fix`] that also knows the fix text the mapping packs give external
/// (OpenGraph) kinds.
pub fn edge_fix_in(g: &AdGraph, kind: EdgeKind, from: &str, to: &str) -> String {
    match kind {
        EdgeKind::External(_) => external_fix(Some(g), kind, from, to),
        _ => edge_fix(kind, from, to),
    }
}

/// The fix for an external edge: its pack's text, or a generic sentence.
fn external_fix(g: Option<&AdGraph>, kind: EdgeKind, from: &str, to: &str) -> String {
    if let Some(text) = g
        .and_then(|g| g.edge_sem(kind))
        .and_then(|s| s.fix_text(from, to))
    {
        return text;
    }
    let source = g
        .and_then(|g| g.edge_sem(kind))
        .map(|s| s.source_title.as_str())
        .unwrap_or("the collector that reported it");
    format!(
        "Remove the {} relationship from {from} to {to} where it is configured, then collect again with {source} to confirm it is gone.",
        kind.as_str()
    )
}

/// Rights that are plain permissions on an object (an ACE), all fixed the same
/// way. Several of them between the same two objects read as one sentence.
fn is_plain_permission(kind: EdgeKind) -> bool {
    use EdgeKind::*;
    !matches!(
        kind,
        MemberOf
            | HasSession
            | AdminTo
            | CanRdp
            | ExecuteDcom
            | CanPsRemote
            | AllowedToDelegate
            | AllowedToAct
            | HasSidHistory
            | Contains
            | GpLink
            | SameForestTrust
            | DcSync
            | CoerceToTgt
            | Owns
            | ManageCa
            | HostsCaService
            | GoldenCert
            | ReadLapsPassword
            | SyncLapsPassword
            | ReadGmsaPassword
            | WriteGpoFiles
            | WriteLogonScript
            | ManagesHost
            | HasStoredCredential
            | External(_)
    ) && !kind.is_adcs_abuse()
}

/// "A", "A and B", "A, B and C".
fn and_list(items: &[&str]) -> String {
    joined_list(items, "and")
}

/// "A", "A or B", "A, B or C".
fn or_list(items: &[&str]) -> String {
    joined_list(items, "or")
}

fn joined_list(items: &[&str], word: &str) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} {word} {last}", rest.join(", ")),
    }
}

/// One sentence for any number of plain permissions on the same object,
/// and where to look when they are inherited.
pub fn permissions_fix(kinds: &[EdgeKind], from: &str, to: &str) -> String {
    permissions_fix_on(kinds, from, to, None)
}

/// [`permissions_fix`] knowing the kind of `to`.
fn permissions_fix_on(
    kinds: &[EdgeKind],
    from: &str,
    to: &str,
    to_kind: Option<NodeKind>,
) -> String {
    format!(
        "{} {}",
        permissions_sentence(kinds, from, to, to_kind),
        inherited_hint(kinds.len())
    )
}

/// "Remove the Group Policy security permissions GenericWrite and WriteDacl
/// that APP-GROUP holds on the GPO LEGACY OUTLOOK SETTINGS."
fn permissions_sentence(
    kinds: &[EdgeKind],
    from: &str,
    to: &str,
    to_kind: Option<NodeKind>,
) -> String {
    let names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let names = and_list(&names);
    match to_kind.filter(|k| !k.is_external()) {
        Some(k) => format!(
            "Remove the {} {names} that {from} holds on {}.",
            permission_kind(k, kinds.len()),
            the_kind(k, to)
        ),
        None => {
            let word = if kinds.len() == 1 {
                "permission"
            } else {
                "permissions"
            };
            format!("Remove the {names} {word} that {from} holds on {to}.")
        }
    }
}

/// For permissions the data doesn't show as inherited: they may still be.
fn inherited_hint(n: usize) -> &'static str {
    if n == 1 {
        "If the permission is inherited, fix the ACE on the parent container and check \
         inheritance on the affected objects."
    } else {
        "If the permissions are inherited, fix the ACE on the parent container and check \
         inheritance on the affected objects."
    }
}

/// The fix for a set of rights between the same two objects, without
/// repeating itself: plain permissions share one sentence, other rights keep
/// their own instructions, and inheritance is explained once.
pub fn fix_text(kinds: &[EdgeKind], from: &str, to: &str) -> String {
    fix_text_with(None, kinds, from, to, None, true, None)
}

/// `after_remove` follows the sentence that removes the plain permissions
/// (what to keep instead); with `where_hint`, the inheritance hint ends it.
fn fix_text_with(
    g: Option<&AdGraph>,
    kinds: &[EdgeKind],
    from: &str,
    to: &str,
    to_kind: Option<NodeKind>,
    where_hint: bool,
    after_remove: Option<&str>,
) -> String {
    let mut plain: Vec<EdgeKind> = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    // AD CS abuses of one pair say their weaknesses in one sentence, not
    // one "finding has the exact change" each.
    let mut adcs: Vec<EdgeKind> = Vec::new();
    let mut adcs_at = None;
    for &k in kinds {
        if is_plain_permission(k) {
            if !plain.contains(&k) {
                plain.push(k);
            }
        } else if k.is_adcs_abuse() && adcs_rule(k).is_some() {
            adcs_at.get_or_insert(parts.len());
            if !adcs.contains(&k) {
                adcs.push(k);
            }
        } else {
            let fix = match k {
                EdgeKind::External(_) => external_fix(g, k, from, to),
                _ => edge_fix_on(k, from, to, to_kind),
            };
            if !parts.contains(&fix) {
                parts.push(fix);
            }
        }
    }
    if let Some(at) = adcs_at {
        parts.insert(at, adcs_fix(&adcs, from, to));
    }
    if !plain.is_empty() {
        if let Some(after) = after_remove {
            parts.insert(0, after.to_string());
        }
        parts.insert(0, permissions_sentence(&plain, from, to, to_kind));
        if where_hint {
            parts.push(inherited_hint(plain.len()).to_string());
        }
    }
    parts.join(" ")
}

/// Rights that are an allow entry (ACE) in an object's permissions.
fn is_ace_right(kind: EdgeKind) -> bool {
    use EdgeKind::*;
    matches!(
        kind,
        GenericAll
            | GenericWrite
            | WriteOwner
            | WriteDacl
            | AddMember
            | AddSelf
            | ForceChangePassword
            | AllExtendedRights
            | AddKeyCredentialLink
            | AddAllowedToAct
            | WriteSpn
            | WriteAccountRestrictions
            | WriteGpLink
            | GetChanges
            | GetChangesAll
            | GetChangesInFilteredSet
            | OwnsLimitedRights
            | WriteOwnerLimitedRights
            | Enroll
            | ManageCertificates
            | WritePkiEnrollmentFlag
            | WritePkiNameFlag
    )
}

/// Well-known principals that hold Read on a GPO so it applies: Everyone,
/// Authenticated Users and Domain Computers. Removing their rights outright
/// can stop the GPO applying.
fn reads_gpo_to_apply(id: &str) -> bool {
    let (_, sid) = sid::split_prefixed(id);
    matches!(sid, "S-1-1-0" | "S-1-5-11") || sid::domain_rid(id) == Some(515)
}

/// The Default Domain Policy and the Default Domain Controllers Policy,
/// which are never deleted: their fixed GUIDs, in the distinguished name
/// (or the ID, where a collector uses it).
pub(crate) fn is_default_gpo(id: &str, dn: Option<&str>) -> bool {
    let both = format!("{id} {}", dn.unwrap_or_default()).to_ascii_uppercase();
    both.contains("31B2F340-016D-11D2-945F-00C04FB984F9")
        || both.contains("6AC1786C-016F-11D2-945F-00C04FB984F9")
}

/// An Exchange object, where the name or location says so: the Exchange
/// security groups, or objects in Exchange's configuration.
fn is_exchange(name: &str, dn: Option<&str>) -> bool {
    let name = name.to_ascii_uppercase();
    let short = name.split('@').next().unwrap_or(&name);
    let dn = dn.unwrap_or_default().to_ascii_uppercase();
    dn.contains("OU=MICROSOFT EXCHANGE SECURITY GROUPS,")
        || dn.contains("CN=MICROSOFT EXCHANGE,")
        || short.starts_with("EXCHANGE ")
        || matches!(
            short,
            "ORGANIZATION MANAGEMENT" | "EXCHANGE SERVERS" | "EXCHANGE TRUSTED SUBSYSTEM"
        )
}

/// For directory permissions between `a` and `b`: what to keep instead of
/// what is removed, and who should hold the right. `None` when none of
/// `kinds` is a plain permission.
fn permission_advice(
    g: &AdGraph,
    a: NodeIndex,
    b: NodeIndex,
    kinds: &[EdgeKind],
    scope: Keepers,
) -> Option<(String, String)> {
    if !kinds.iter().any(|&k| is_ace_right(k)) {
        return None;
    }
    let (from, to) = (g.node(a), g.node(b));
    let dn = to.props.distinguishedname.as_deref();
    let gpo = to.kind == NodeKind::Gpo;
    let (_, from_sid) = sid::split_prefixed(&from.id);
    let keep = if gpo && from_sid == "S-1-1-0" {
        "If you remove the entry of Everyone, give Authenticated Users Read in its place, so the GPO \
         still applies."
            .to_string()
    } else if gpo && reads_gpo_to_apply(&from.id) {
        format!(
            "Keep its Read permission (and Apply group policy where Security Filtering uses it): \
             Group Policy needs it to apply the GPO, so removing the whole entry of {} can stop the \
             GPO applying.",
            from.name
        )
    } else if gpo && sid::is_broad_group(&from.id) {
        format!(
            "Keep its Read and Apply group policy permissions if Security Filtering applies the GPO \
             to {}.",
            from.name
        )
    } else if sid::is_broad_group(&from.id) {
        format!(
            "Remove only these permissions: the default read access of {} stays.",
            from.name
        )
    } else {
        format!(
            "If {} needs to change {}, delegate only the rights it needs.",
            from.name, to.name
        )
    };
    let who = if gpo {
        let mut s = "Only Domain Admins, Enterprise Admins and your designated Group Policy \
                     administrators should be able to edit the GPO, change its permissions or own it."
            .to_string();
        if !is_default_gpo(&to.id, dn) {
            s.push_str(" If nobody uses this GPO any more, unlink and delete it instead.");
        }
        s
    } else {
        let what = to.kind.noun().unwrap_or("object");
        if is_exchange(&to.name, dn) {
            format!(
                "Leave the right to change the {what} only with the Exchange and Active Directory \
                 administrators."
            )
        } else if is_pki(to.kind) {
            format!(
                "Only the PKI administrators (by default Enterprise Admins and the forest root's \
                 Domain Admins) should be able to change the {what}."
            )
        } else {
            let admins = match scope {
                Keepers::TierZero => "the Tier Zero administrators responsible for it",
                Keepers::Zone => "the zone's administrators",
                Keepers::Any => "the administrators responsible for it",
            };
            format!("Leave the right to change the {what} only with {admins}.")
        }
    };
    Some((keep, who))
}

/// Who should keep the rights on the object a fix is about, where nothing
/// more specific (a GPO, PKI, Exchange) says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepers {
    /// A Tier Zero object (PW-003).
    TierZero,
    /// An object in a Privilege Zone (PW-022).
    Zone,
    /// Any object, such as the first step of a path (PW-001).
    Any,
}

/// Says that deny entries aren't read, for a finding about directory
/// permissions: the collectors (SharpHound, RustHound-CE, the built-in
/// one) keep only allow entries, so a deny that cancels one is not seen.
pub fn deny_note(kinds: &[EdgeKind]) -> Option<&'static str> {
    kinds
        .iter()
        .any(|&k| is_ace_right(k))
        .then_some("Deny entries: not checked. Pathwarden reads allowed permissions only.")
}

/// [`fix_text`] for edges in the graph, pointing inherited permissions at the
/// container where they are defined. All edges are expected to share their
/// endpoints.
pub fn fix_for_edges(g: &AdGraph, edges: &[EdgeIndex]) -> String {
    fix_for_edges_with(g, edges, None)
}

/// [`fix_for_edges`] for a finding about the rights one object holds on
/// another: after removing directory permissions, what to keep instead and
/// who should hold the right (`keepers`, where the object says nothing more
/// specific).
pub fn fix_for_edges_advised(g: &AdGraph, edges: &[EdgeIndex], keepers: Keepers) -> String {
    fix_for_edges_with(g, edges, Some(keepers))
}

fn fix_for_edges_with(g: &AdGraph, edges: &[EdgeIndex], advised: Option<Keepers>) -> String {
    // File permissions in SYSVOL and NETLOGON name their folder or file;
    // local rights set by Group Policy name the GPOs.
    let (files, edges): (Vec<EdgeIndex>, Vec<EdgeIndex>) = edges.iter().partition(|&&e| {
        !g.file_grants(e).is_empty() || !g.gpo_grants(e).is_empty() || !g.stored_via(e).is_empty()
    });
    let file_fixes: Vec<String> = files
        .iter()
        .filter_map(|&e| {
            file_fix(g, e)
                .or_else(|| gpo_local_fix(g, e))
                .or_else(|| stored_fix(g, e))
        })
        .collect();
    let rest = acl_fix_for_edges(g, &edges, advised);
    match (file_fixes.is_empty(), rest.is_empty()) {
        (true, _) => rest,
        (false, true) => file_fixes.join(" "),
        (false, false) => format!("{} {rest}", file_fixes.join(" ")),
    }
}

/// Most folders or files one fix lists.
const MAX_GRANTS_SHOWN: usize = 4;

/// The fix for a `WriteGPOFiles` or `WriteLogonScript` edge: the folder or
/// file, the permission, and the `icacls` command that removes it.
pub fn file_fix(g: &AdGraph, e: EdgeIndex) -> Option<String> {
    let (lead, details) = file_fix_body(g, e)?;
    if g.inner()[e] != EdgeKind::WriteGpoFiles {
        return Some(format!("{lead} {details}"));
    }
    Some(format!(
        "{lead} These are SYSVOL folder permissions, separate from the GPO's Group Policy security \
         permissions. {}{details}",
        GPMC_FIRST
    ))
}

/// Group Policy Management's own repair first (it rewrites the folder's
/// permissions from the GPO's, read access included), then by hand.
const GPMC_FIRST: &str = "The simplest fix: open the GPO in Group Policy Management and accept its \
     offer to make the SYSVOL folder permissions match its Group Policy security permissions. Or by \
     hand, after saving the permissions to roll back (`icacls <folder> /save gpo-acl.txt /t`): ";

/// The fix for the `WriteGPOFiles` edges into one GPO (PW-027): Group
/// Policy Management first, then by hand for each account or group, with
/// how to roll back once.
pub fn gpo_files_fix(g: &AdGraph, edges: &[EdgeIndex]) -> Option<String> {
    let each: Vec<String> = edges
        .iter()
        .filter_map(|&e| file_fix_body(g, e))
        .map(|(lead, details)| format!("{lead} {details}"))
        .collect();
    (!each.is_empty()).then(|| format!("{GPMC_FIRST}{}", each.join(" ")))
}

/// A `WriteGPOFiles` or `WriteLogonScript` edge's fix: what to change,
/// then the folders or file and the `icacls` commands. A broad group keeps
/// Read & Execute on a GPO folder: Group Policy reads it to apply the GPO,
/// and `/remove:g` takes away every right the group was granted there,
/// read included.
fn file_fix_body(g: &AdGraph, e: EdgeIndex) -> Option<(String, String)> {
    let grants = g.file_grants(e);
    let (a, b) = g.inner().edge_endpoints(e)?;
    if grants.is_empty() {
        return None;
    }
    let (from, to) = (g.node(a), g.node(b));
    let sid = sid::split_prefixed(&from.id).1;
    let gpo = g.inner()[e] == EdgeKind::WriteGpoFiles;
    let keep_read = gpo && sid::is_broad_group(&from.id);
    let lead = if keep_read {
        format!(
            "Reduce the access {} has to the SYSVOL folder of the GPO {} to Read & Execute: Group \
             Policy reads the folder to apply the GPO.",
            from.name, to.name
        )
    } else if gpo {
        format!(
            "Remove the write access {} has to the SYSVOL folder of the GPO {}.",
            from.name, to.name
        )
    } else {
        format!(
            "Remove the write access {} has to the logon script of {}, which runs as {} at every logon.",
            from.name, to.name, to.name
        )
    };
    let mut parts = Vec::new();
    for gr in grants.iter().take(MAX_GRANTS_SHOWN) {
        let rights: Vec<&str> = gr.rights.iter().map(String::as_str).collect();
        parts.push(if gr.owner {
            format!(
                "It owns {}: give it to Administrators (`icacls \"{}\" /setowner *S-1-5-32-544`).",
                gr.path, gr.path
            )
        } else if gr.inherited {
            format!(
                "Its {} on {} is inherited: remove {} on the parent folder it comes from (`icacls \"{}\"` \
                 marks inherited entries with (I)).",
                and_list(&rights),
                gr.path,
                if keep_read {
                    "the write access, keeping Read & Execute,"
                } else {
                    "it"
                },
                gr.path
            )
        } else if keep_read {
            format!(
                "It has {} on {}: `icacls \"{}\" /remove:g *{sid}`, then `icacls \"{}\" /grant \
                 *{sid}:(OI)(CI)RX`, because `/remove:g` also removes its read access.",
                and_list(&rights),
                gr.path,
                gr.path,
                gr.path
            )
        } else {
            format!(
                "It has {} on {}: `icacls \"{}\" /remove:g *{sid}`.",
                and_list(&rights),
                gr.path,
                gr.path
            )
        });
    }
    if grants.len() > MAX_GRANTS_SHOWN {
        parts.push(format!(
            "And {} the same way.",
            crate::text::count(
                grants.len() - MAX_GRANTS_SHOWN,
                "more folder or file",
                "more folders or files"
            )
        ));
    }
    Some((lead, parts.join(" ")))
}

/// The fix for a local right Group Policy sets: the OUs or domains and the
/// GPOs linked there. Removing the member on the computer alone comes back at
/// the next policy refresh.
///
/// `GPOChanges` sits on the OU or domain whose own links produced it (a GPO
/// linked to a parent OU or the domain shows up on that parent, with the
/// computers below it), so one GPO per recorded container sets the member.
/// The built-in collector records which GPO and setting it is, and
/// then the fix names them. Otherwise (SharpHound or RustHound-CE data, a run
/// as the current Windows user, an older sidecar) the data does not say which
/// of a container's GPOs it is, so with several we name them as candidates
/// rather than telling the admin to edit each. With several containers, it
/// has to go at each of them.
pub fn gpo_local_fix(g: &AdGraph, e: EdgeIndex) -> Option<String> {
    let containers = g.gpo_grants(e);
    let (a, b) = g.inner().edge_endpoints(e)?;
    if containers.is_empty() {
        return None;
    }
    let (from, to) = (g.node(a), g.node(b));
    let kind = g.inner()[e];
    let group = match kind {
        EdgeKind::AdminTo => "Administrators",
        EdgeKind::CanRdp => "Remote Desktop Users",
        EdgeKind::ExecuteDcom => "Distributed COM Users",
        _ => "Remote Management Users",
    };
    let linked = |c: NodeIndex| {
        let mut gpos: Vec<&str> = g
            .inner()
            .edges_directed(c, petgraph::Direction::Incoming)
            .filter(|l| *l.weight() == EdgeKind::GpLink)
            .map(|l| g.node(l.source()).name.as_str())
            .collect();
        gpos.sort_unstable();
        gpos.dedup();
        gpos
    };
    let levels: Vec<(&str, Vec<&str>)> = containers
        .iter()
        .map(|&c| (g.node(c).name.as_str(), linked(c)))
        .collect();
    let named: Vec<Option<(String, usize)>> = containers
        .iter()
        .map(|&c| named_gpo_settings(g, c, a, kind))
        .collect();
    let refresh = format!(
        "Removing it on {} alone comes back at the next policy refresh.",
        to.name
    );
    if levels.len() > 1 && levels.iter().any(|(_, gpos)| !gpos.is_empty()) {
        // One GPO per level sets it: removing it from one level leaves the others.
        let each: Vec<String> = levels
            .iter()
            .zip(&named)
            .map(|((name, gpos), named)| match (named, gpos.as_slice()) {
                (Some((named, _)), _) => format!("{name} ({named})"),
                (None, []) => (*name).to_string(),
                (None, [gpo]) => format!("{name} ({gpo})"),
                (None, _) => format!("{name} (one of {})", or_list(gpos)),
            })
            .collect();
        let each: Vec<&str> = each.iter().map(String::as_str).collect();
        let open = if levels
            .iter()
            .zip(&named)
            .any(|((_, gpos), named)| named.is_none() && gpos.len() > 1)
        {
            " Where a level lists several GPOs, open each in Group Policy Management (Settings: \
             Restricted Groups, or Preferences: Local Users and Groups) to find it."
        } else {
            ""
        };
        let remove = if named.iter().all(Option::is_some) {
            "Remove it from the setting named at each level."
        } else {
            "Remove it from the Restricted Groups or Local Users and Groups setting at each level."
        };
        return Some(format!(
            "Group Policy puts {} in the local {group} group on {} from each of these levels: {}. \
             {remove}{open} {refresh}",
            from.name,
            to.name,
            and_list(&each)
        ));
    }
    if let [Some((named, gpos))] = named.as_slice() {
        let linked = match gpos {
            1 => "linked",
            2 => "both linked",
            _ => "all linked",
        };
        return Some(format!(
            "Group Policy puts {} in the local {group} group on {}: remove it from {named} \
             ({linked} to {}). {refresh}",
            from.name, to.name, levels[0].0
        ));
    }
    let mut gpos: Vec<&str> = levels.iter().flat_map(|(_, gpos)| gpos.clone()).collect();
    gpos.sort_unstable();
    gpos.dedup();
    let wheres: Vec<&str> = levels.iter().map(|(name, _)| *name).collect();
    let wheres = and_list(&wheres);
    let fix = match gpos.as_slice() {
        [] => format!(
            ": remove it from the Restricted Groups or Local Users and Groups setting of the GPOs \
             linked to {wheres}."
        ),
        [gpo] => format!(
            ": remove it from the Restricted Groups or Local Users and Groups setting of {gpo} \
             (linked to {wheres})."
        ),
        _ => format!(
            ", set by one of the GPOs linked to {wheres}: {}. Open each in Group Policy Management \
             (Settings: Restricted Groups, or Preferences: Local Users and Groups) to find it, and \
             remove it there.",
            or_list(&gpos)
        ),
    };
    Some(format!(
        "Group Policy puts {} in the local {group} group on {}{fix} {refresh}",
        from.name, to.name
    ))
}

/// "the Restricted Groups setting of A and the Local Users and Groups
/// setting of B", for the GPOs linked to `container` that the built-in
/// collector recorded putting `member` in the group behind `kind`, with how
/// many GPOs it names. A member only item-level targeting adds is said so.
/// `None` when nothing was recorded there, or when a GPO linked there has an
/// incomplete record (naming only the others could be wrong).
fn named_gpo_settings(
    g: &AdGraph,
    container: NodeIndex,
    member: NodeIndex,
    kind: EdgeKind,
) -> Option<(String, usize)> {
    use crate::sysvol::LocalSetting;
    if !g.has_gpo_settings() {
        return None;
    }
    let mut gpos: Vec<NodeIndex> = g
        .inner()
        .edges_directed(container, petgraph::Direction::Incoming)
        .filter(|l| *l.weight() == EdgeKind::GpLink)
        .map(|l| l.source())
        .collect();
    gpos.sort_unstable();
    gpos.dedup();
    if gpos.iter().any(|&gpo| g.gpo_record_incomplete(gpo)) {
        return None;
    }
    // Per GPO: Restricted Groups, Local Users and Groups for every computer,
    // Local Users and Groups through item-level targeting only.
    let mut by: std::collections::BTreeMap<&str, [bool; 3]> = Default::default();
    for gpo in gpos {
        for s in g.gpo_settings(gpo, member, kind) {
            let f = by.entry(g.node(gpo).name.as_str()).or_default();
            match (s.setting, s.targeted) {
                (LocalSetting::RestrictedGroups, _) => f[0] = true,
                (_, false) => f[1] = true,
                (_, true) => f[2] = true,
            }
        }
    }
    if by.is_empty() {
        return None;
    }
    let rg = LocalSetting::RestrictedGroups.label();
    let gpp = LocalSetting::Gpp.label();
    let each: Vec<String> = by
        .iter()
        .map(|(gpo, f)| match (f[0], f[1], f[2]) {
            (true, true, _) => format!("the {rg} and {gpp} settings of {gpo}"),
            (true, false, true) => {
                format!("the {rg} setting of {gpo} and its {gpp} items with item-level targeting")
            }
            (true, false, false) => format!("the {rg} setting of {gpo}"),
            (false, true, _) => format!("the {gpp} setting of {gpo}"),
            (false, false, _) => format!("the {gpp} items with item-level targeting in {gpo}"),
        })
        .collect();
    let each: Vec<&str> = each.iter().map(String::as_str).collect();
    Some((and_list(&each), by.len()))
}

/// [`fix_for_edges`] for edges that are directory permissions.
fn acl_fix_for_edges(g: &AdGraph, edges: &[EdgeIndex], advised: Option<Keepers>) -> String {
    let Some(&first) = edges.first() else {
        return String::new();
    };
    let (a, b) = g
        .inner()
        .edge_endpoints(first)
        .expect("edge from this graph");
    let kinds: Vec<EdgeKind> = edges.iter().map(|&e| g.inner()[e]).collect();
    let inherited = edges.iter().filter(|&&e| g.is_inherited(e)).count();
    let advice = advised.and_then(|scope| permission_advice(g, a, b, &kinds, scope));
    let (keep, who) = match &advice {
        Some((keep, who)) => (Some(keep.as_str()), format!(" {who}")),
        None => (None, String::new()),
    };
    // When we know where a permission comes from, say so instead of hedging.
    let fix = fix_text_with(
        Some(g),
        &kinds,
        &g.node(a).name,
        &g.node(b).name,
        Some(g.node(b).kind),
        inherited == 0,
        keep,
    );
    if inherited == 0 {
        return format!("{fix}{who}");
    }
    let source = match g.parent(b) {
        Some(p) => format!("{} or a container above it", g.node(p).name),
        None => "a parent container".to_string(),
    };
    let note = if inherited < edges.len() {
        format!(
            "Some of these permissions are inherited from {source}: fix those entries there, where they \
             are defined, and check inheritance on the objects below it, because the change applies to \
             all of them."
        )
    } else if inherited == 1 {
        format!(
            "It is inherited from {source}: fix the entry there, where it is defined, and check \
             inheritance on the objects below it, because the change applies to all of them."
        )
    } else {
        format!(
            "They are inherited from {source}: fix the entries there, where they are defined, and check \
             inheritance on the objects below it, because the change applies to all of them."
        )
    };
    format!("{fix} {note}{who}")
}

/// [`fix_for_edges`] for a single edge.
pub fn fix_for(g: &AdGraph, e: EdgeIndex) -> String {
    fix_for_edges(g, &[e])
}

/// If `src`'s `kind` right on `target` is a copy SDProp made from AdminSDHolder,
/// the AdminSDHolder object it comes from. Such copies come back within the hour
/// unless the right is removed from AdminSDHolder itself.
pub fn sdprop_origin(
    g: &AdGraph,
    src: NodeIndex,
    kind: EdgeKind,
    target: NodeIndex,
) -> Option<NodeIndex> {
    let t = g.node(target);
    if t.is_adminsdholder() || t.props.admincount != Some(true) {
        return None;
    }
    g.inner()
        .edges_directed(src, Direction::Outgoing)
        .find(|e| *e.weight() == kind && g.node(e.target()).is_adminsdholder())
        .map(|e| e.target())
}

const INF: u64 = u64::MAX / 4;

/// Relative effort of removing an edge; `None` when it cannot be removed.
/// Sessions cost more than permissions because they come back unless the admin
/// changes how they work; moving objects or GPO links is more disruptive still.
pub fn edge_cost(g: &AdGraph, e: EdgeIndex) -> Option<u64> {
    let (_, to) = g.inner().edge_endpoints(e)?;
    match g.inner()[e] {
        // A mapping pack's cost; "not cuttable" means fix it elsewhere.
        k @ EdgeKind::External(_) => match g.edge_sem(k) {
            Some(s) if !s.cuttable => None,
            Some(s) => Some(s.cost),
            None => Some(1),
        },
        EdgeKind::SameForestTrust => None,
        EdgeKind::MemberOf if sid::is_broad_group(&g.node(to).id) => None,
        EdgeKind::HasSession => Some(3),
        // Moving a service to a gMSA, as TaskHound's pack prices it.
        EdgeKind::HasStoredCredential => Some(2),
        // Uninstalling a management agent is a real but disruptive change.
        EdgeKind::Contains | EdgeKind::GpLink | EdgeKind::ManagesHost => Some(5),
        _ => Some(1),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedFix {
    pub from: String,
    pub from_kind: NodeKind,
    /// Rights or relationships to remove, all from `from` to `to`.
    pub edges: Vec<EdgeKind>,
    pub to: String,
    pub to_kind: NodeKind,
    /// The target is a group or standalone managed service account (gMSA,
    /// sMSA): the domain rotates its 240-byte password, so setting an SPN on it
    /// doesn't yield a crackable credential (not Kerberoastable; see PW-006).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub to_managed: bool,
    pub cost: u64,
    /// Exposed principals with any path to Tier Zero through this fix.
    pub principals_through: usize,
    /// Exposed principals whose shortest path to Tier Zero uses these edges.
    pub shortest_paths_through: usize,
    /// Protected objects SDProp copied this right onto; removing it from
    /// AdminSDHolder removes those copies too.
    pub sdprop_copies: usize,
    /// Objects below `to` that inherit this right; removing it on `to` (or the
    /// container above it that defines it) removes all of them.
    pub inherited_by: usize,
    pub action: String,
    /// The OpenGraph source that reported these edges, when not AD data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationPlan {
    pub exposed_before: usize,
    /// Exposed principals left after applying every fix (0 unless some path
    /// consists only of edges that cannot be removed).
    pub exposed_after: usize,
    /// Exposure percentage before the plan: `exposed_before /
    /// relevant_population`, the same hero figure the Posture page shows for
    /// this target set (see [`crate::posture::ZonePosture::exposure_percent`]).
    pub exposure_before: f64,
    /// Exposure percentage once every removable fix is applied, as a fresh
    /// run would read it: `exposed_after / relevant_population_after`.
    pub exposure_after: f64,
    /// Points of exposure the whole plan removes
    /// (`exposure_before - exposure_after`).
    pub exposure_delta: f64,
    /// The denominator of `exposure_before`: the relevant population for
    /// this target set (the active, [`analysis::Relevance`]).
    pub relevant_population: usize,
    /// The denominator of `exposure_after`: `relevant_population`, since
    /// only active accounts count and fixes never move it. Kept so the JSON
    /// doesn't lose a key.
    pub relevant_population_after: usize,
    /// Exposure percentage after only the first fix (`fixes[0]`), as a fresh
    /// run would read it. `None` when there is no fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_fix_exposure_after: Option<f64>,
    pub total_cost: u64,
    pub fixes: Vec<PlannedFix>,
    /// Which accounts each step cuts off, and their paths
    /// ([`crate::exposed`]); never serialized, so the event is unchanged.
    #[serde(skip)]
    pub detail: Option<PlanDetail>,
}

/// The accounts behind a plan's counts, kept while the analysis is: who is
/// exposed, and for each step who it cuts off and by which path.
#[derive(Debug, Clone, Default)]
pub struct PlanDetail {
    /// The exposed principals: active population members outside the
    /// targets with a path to them (`exposed_before` of them).
    pub exposed: Vec<NodeIndex>,
    /// One per distinct `from` of the steps.
    pub sources: Vec<SourceTree>,
    /// For each step, in `fixes` order: the index of its `from` in
    /// `sources`.
    pub step_source: Vec<usize>,
    /// For each step: from its `from` on to the targets, an edge the step
    /// removes, then the shortest path on from that edge's end.
    pub step_tail: Vec<Vec<EdgeIndex>>,
}

/// The exposed principals with a path to one step's `from`, and those paths.
#[derive(Debug, Clone, Default)]
pub struct SourceTree {
    pub from: NodeIndex,
    /// Each exposed principal with a path to `from` that passes no target
    /// (the step's `principals_through`), with the hops to `from`. In the
    /// order of [`PlanDetail::exposed`].
    pub accounts: Vec<(NodeIndex, u32)>,
    /// The shortest paths to `from` of those principals, as
    /// `(node, next node, edge)` indices, sorted by node; `from` has none.
    pub next: Vec<(u32, u32, u32)>,
}

impl SourceTree {
    /// The edges from `account` to `from`: empty for `from` itself, `None`
    /// for an account not on the tree.
    pub fn path(&self, account: NodeIndex) -> Option<Vec<EdgeIndex>> {
        let mut cur = account.index() as u32;
        let mut out = Vec::new();
        while cur != self.from.index() as u32 {
            let i = self.next.binary_search_by_key(&cur, |&(n, _, _)| n).ok()?;
            let (_, next, edge) = self.next[i];
            out.push(EdgeIndex::new(edge as usize));
            cur = next;
            if out.len() > self.next.len() {
                return None;
            }
        }
        Some(out)
    }
}

/// The exposed principals that reach `from` by `up` (a search toward
/// `from` that passes no target), with their hops and paths.
fn source_tree(from: NodeIndex, up: &analysis::ReachTree, exposed: &[NodeIndex]) -> SourceTree {
    use std::collections::hash_map::Entry;
    // Hops to `from` of the nodes walked so far.
    let mut depth: HashMap<u32, u32> = HashMap::new();
    depth.insert(from.index() as u32, 0);
    let mut next: Vec<(u32, u32, u32)> = Vec::new();
    let mut accounts = Vec::new();
    let mut chain: Vec<(u32, u32, u32)> = Vec::new();
    for &p in exposed {
        if !up.reaches(p) {
            continue;
        }
        chain.clear();
        let mut cur = p;
        let mut d = loop {
            if let Some(&d) = depth.get(&(cur.index() as u32)) {
                break d;
            }
            let Some((nx, e)) = up.next(cur) else {
                // Not on the way to `from` after all (never: the search
                // starts there).
                break u32::MAX;
            };
            chain.push((cur.index() as u32, nx.index() as u32, e.index() as u32));
            cur = nx;
        };
        if d == u32::MAX {
            continue;
        }
        for &(node, nx, e) in chain.iter().rev() {
            d += 1;
            if let Entry::Vacant(v) = depth.entry(node) {
                v.insert(d);
                next.push((node, nx, e));
            }
        }
        accounts.push((p, depth[&(p.index() as u32)]));
    }
    next.sort_unstable();
    SourceTree {
        from,
        accounts,
        next,
    }
}

/// The cheapest set of edge removals (by [`edge_cost`]) that cuts every exposed
/// principal off from Tier Zero: a minimum s-t cut, with all exposed principals
/// as sources and all Tier Zero objects as the sink.
/// `rel` says which principals are active (the exposure denominator).
pub fn plan(g: &AdGraph, rel: &analysis::Relevance) -> RemediationPlan {
    plan_to(g, &analysis::tier_zero(g), rel)
}

/// [`plan`] for an arbitrary set of targets (for example a Privilege Zone plus
/// Tier Zero). Principals in the set are not counted as exposed.
pub fn plan_to(g: &AdGraph, targets: &[NodeIndex], rel: &analysis::Relevance) -> RemediationPlan {
    let t0 = targets;
    let mut is_target = vec![false; g.node_count()];
    for &t in targets {
        is_target[t.index()] = true;
    }
    let clock = std::time::Instant::now();
    let tree = analysis::reach_targets(g, t0.iter().copied(), None);
    let pop = analysis::population(g);
    let exposed: Vec<NodeIndex> = pop
        .iter()
        .copied()
        .filter(|&ix| !is_target[ix.index()] && tree.reaches(ix) && rel.is_active(ix))
        .collect();
    // Inactive accounts don't count: the plan cuts the active exposed ones
    // off. The denominator is the active, for this target set, so the
    // plan's "before" matches the Posture hero.
    let pop: Vec<NodeIndex> = pop
        .into_iter()
        .filter(|ix| !is_target[ix.index()])
        .collect();
    let relevant = rel.relevant(&pop);

    // Only nodes on some exposed -> Tier Zero path matter.
    let n = g.node_count();
    let mut on_path = vec![false; n];
    let mut stack = exposed.clone();
    for &ix in &exposed {
        on_path[ix.index()] = true;
    }
    while let Some(u) = stack.pop() {
        if is_target[u.index()] {
            continue;
        }
        for e in g.inner().edges_directed(u, Direction::Outgoing) {
            let v = e.target();
            if g.traversable(*e.weight(), v) && tree.reaches(v) && !on_path[v.index()] {
                on_path[v.index()] = true;
                stack.push(v);
            }
        }
    }

    crate::timing::report("  plan: paths", clock.elapsed());
    let clock = std::time::Instant::now();
    const SOURCE: usize = 0;
    const SINK: usize = 1;
    let mut id = vec![usize::MAX; n];
    let mut count = 2;
    for (ix, _) in g.nodes() {
        if on_path[ix.index()] && !is_target[ix.index()] {
            id[ix.index()] = count;
            count += 1;
        }
    }
    let node_of = |v: NodeIndex| {
        if is_target[v.index()] {
            SINK
        } else {
            id[v.index()]
        }
    };

    // Edges one change removes together (inherited copies of an ACE, the
    // copies SDProp makes of an AdminSDHolder right) go through one auxiliary
    // node, so the cut pays for that change once instead of once per copy.
    let mut candidates: Vec<EdgeIndex> = Vec::new();
    let mut explicit: HashSet<(NodeIndex, EdgeKind, NodeIndex)> = HashSet::new();
    for (ix, _) in g.nodes().filter(|(ix, _)| id[ix.index()] != usize::MAX) {
        for e in g.inner().edges_directed(ix, Direction::Outgoing) {
            // Only rights on containers are ever looked up here (where an
            // inherited right is defined); skip the millions of others.
            let container = matches!(
                g.node(e.target()).kind,
                NodeKind::Ou | NodeKind::Container | NodeKind::Domain
            );
            if container && !g.is_inherited(e.id()) {
                explicit.insert((ix, *e.weight(), e.target()));
            }
            if g.traversable(*e.weight(), e.target()) && on_path[e.target().index()] {
                candidates.push(e.id());
            }
        }
    }
    let mut shared: std::collections::BTreeMap<FixKey, Vec<EdgeIndex>> = Default::default();
    let mut single: Vec<EdgeIndex> = Vec::new();
    for e in candidates {
        match fix_key(g, e, &explicit) {
            Some(k) => shared.entry(k).or_default().push(e),
            None => single.push(e),
        }
    }
    let shared: Vec<(FixKey, Vec<EdgeIndex>)> = shared
        .into_iter()
        .filter_map(|(k, edges)| {
            if edges.len() == 1 {
                single.push(edges[0]);
                None
            } else {
                Some((k, edges))
            }
        })
        .collect();

    let mut net = FlowNet::new(count + shared.len());
    for &ix in &exposed {
        net.add(SOURCE, id[ix.index()], INF, None);
    }
    for &e in &single {
        let (a, b) = g.inner().edge_endpoints(e).expect("edge from this graph");
        net.add(
            id[a.index()],
            node_of(b),
            edge_cost(g, e).unwrap_or(INF),
            Some(Cut::Edge(e)),
        );
    }
    for (i, (key, edges)) in shared.iter().enumerate() {
        let x = count + i;
        let cost = edges
            .iter()
            .map(|&e| edge_cost(g, e).unwrap_or(INF))
            .max()
            .unwrap_or(INF);
        net.add(id[key.from.index()], x, cost, Some(Cut::Shared(i)));
        for &e in edges {
            let b = g.inner().edge_endpoints(e).expect("edge from this graph").1;
            net.add(x, node_of(b), INF, None);
        }
    }
    crate::timing::report("  plan: network", clock.elapsed());
    crate::timing::phase("  plan: max flow", || net.max_flow(SOURCE, SINK));
    let clock = std::time::Instant::now();

    let source_side = net.residual_reachable(SOURCE);
    let cut: Vec<(Cut, u64)> = net
        .arcs
        .iter()
        .filter(|a| a.cap_orig < INF && source_side[a.from] && !source_side[a.to])
        .filter_map(|a| Some((a.cut?, a.cap_orig)))
        .collect();

    let mut usage: HashMap<EdgeIndex, usize> = HashMap::new();
    for &ix in &exposed {
        for e in tree.path(ix).unwrap_or_default() {
            *usage.entry(e).or_default() += 1;
        }
    }
    let members = |c: Cut| match c {
        Cut::Edge(e) => vec![e],
        Cut::Shared(i) => shared[i].1.clone(),
    };
    let removed: HashSet<EdgeIndex> = cut.iter().flat_map(|&(c, _)| members(c)).collect();
    let after = analysis::reach_targets_where(g, t0.iter().copied(), |e| !removed.contains(&e));
    let exposed_after = rel.exposed(&exposed, |ix| after.reaches(ix));
    // Only active accounts count, so fixes never move the denominator.
    let relevant_after = relevant;

    // One fix per principal and object, as in the findings. Rights SDProp
    // copied onto protected objects are fixed once, on AdminSDHolder; inherited
    // rights once, on the container that defines them.
    #[derive(Default)]
    struct Group {
        edges: Vec<EdgeIndex>,
        kinds: Vec<EdgeKind>,
        cost: u64,
        through: usize,
        copies: usize,
        below: Vec<NodeIndex>,
        exact: bool,
        /// Every graph edge this step removes (copies included).
        removes: Vec<EdgeIndex>,
    }
    let mut groups: std::collections::BTreeMap<(NodeIndex, NodeIndex), Group> = Default::default();
    for &(c, cost) in &cut {
        let edges = members(c);
        let key = match c {
            Cut::Edge(_) => None,
            Cut::Shared(i) => Some(shared[i].0),
        };
        let (a, b0) = g
            .inner()
            .edge_endpoints(edges[0])
            .expect("edge from this graph");
        let display_to = match key {
            Some(k) => k.origin,
            None => sdprop_origin(g, a, g.inner()[edges[0]], b0).unwrap_or(b0),
        };
        let group = groups.entry((a, display_to)).or_default();
        group.cost += cost;
        group.removes.extend(edges.iter().copied());
        for e in edges {
            let b = g.inner().edge_endpoints(e).expect("edge from this graph").1;
            let kind = g.inner()[e];
            if !group.kinds.contains(&kind) {
                group.kinds.push(kind);
            }
            group.through += usage.get(&e).copied().unwrap_or_default();
            if b == display_to {
                group.edges.push(e);
                group.exact = true;
            } else if key.is_some_and(|k| !k.sdprop) {
                group.below.push(b);
            } else {
                group.copies += 1;
            }
        }
    }
    crate::timing::report("  plan: cut and grouping", clock.elapsed());
    let started = std::time::Instant::now();
    // Everyone exposed who can reach a step's `from` has a path through it:
    // one search per distinct source, run in parallel.
    // Who each reaches is kept, with their paths (the search trees are not).
    let mut sources: Vec<NodeIndex> = groups.keys().map(|(a, _)| *a).collect();
    sources.dedup();
    let trees = crate::par::map(&sources, |&a| {
        let upstream = analysis::reach_filtered(g, [a], |_| true, |n| !is_target[n.index()]);
        source_tree(a, &upstream, &exposed)
    });
    let source_of: HashMap<NodeIndex, usize> =
        sources.iter().enumerate().map(|(i, &a)| (a, i)).collect();
    let through: HashMap<NodeIndex, usize> =
        trees.iter().map(|t| (t.from, t.accounts.len())).collect();
    #[allow(clippy::type_complexity)]
    let mut fixes: Vec<(PlannedFix, Vec<EdgeIndex>, (usize, Vec<EdgeIndex>))> = groups
        .into_iter()
        .map(|((a, b), mut group)| {
            let (from, to) = (g.node(a), g.node(b));
            let mut actions: Vec<String> = Vec::new();
            if group.edges.is_empty() {
                // Only copies were cut: the fix is where they come from.
                actions.push(fix_text_with(
                    Some(g),
                    &group.kinds,
                    &from.name,
                    &to.name,
                    Some(to.kind),
                    true,
                    None,
                ));
            } else {
                actions.push(fix_for_edges(g, &group.edges));
            }
            if !group.below.is_empty() {
                group.below.sort_unstable();
                group.below.dedup();
                let names: Vec<&str> = group
                    .below
                    .iter()
                    .take(3)
                    .map(|&ix| g.node(ix).name.as_str())
                    .collect();
                let more = if group.below.len() > 3 { ", ..." } else { "" };
                let place = if group.exact {
                    to.name.clone()
                } else {
                    format!("{} or a container above it", to.name)
                };
                actions.push(format!(
                    "{} below {} {} this ({}{more}); removing it where it is defined \
                     ({place}) removes all of them.",
                    crate::text::count(group.below.len(), "object", "objects"),
                    to.name,
                    if group.below.len() == 1 {
                        "inherits"
                    } else {
                        "inherit"
                    },
                    names.join(", ")
                ));
            }
            if group.copies > 0 {
                actions.push(format!(
                    "SDProp copied this onto {}; removing it from {} \
                     removes those copies at the next SDProp run (within an hour).",
                    crate::text::count(
                        group.copies,
                        "protected account or group",
                        "protected accounts and groups"
                    ),
                    to.name
                ));
            }
            let principals_through = through[&a];
            let source = group
                .edges
                .iter()
                .find_map(|&e| g.edge_source_name(e))
                .map(str::to_owned);
            let fix = PlannedFix {
                source,
                from: from.name.clone(),
                from_kind: from.kind,
                edges: group.kinds,
                to: to.name.clone(),
                to_kind: to.kind,
                to_managed: to.props.managedpassword == Some(true),
                cost: group.cost,
                principals_through,
                shortest_paths_through: group.through,
                sdprop_copies: group.copies,
                inherited_by: group.below.len(),
                action: actions.join(" "),
            };
            // From `a` on: one edge the step removes, then the shortest
            // path on from its end.
            let edge = group.edges.first().or(group.removes.first()).copied();
            let tail = edge
                .map(|e| {
                    let end = g.inner().edge_endpoints(e).expect("edge from this graph").1;
                    std::iter::once(e)
                        .chain(tree.path(end).unwrap_or_default())
                        .collect()
                })
                .unwrap_or_default();
            (fix, group.removes, (source_of[&a], tail))
        })
        .collect();
    crate::timing::report("  plan: steps", started.elapsed());
    fixes.sort_by(|(a, _, _), (b, _, _)| {
        b.principals_through
            .cmp(&a.principals_through)
            .then(b.shortest_paths_through.cmp(&a.shortest_paths_through))
            .then(a.cost.cmp(&b.cost))
            .then(a.from.cmp(&b.from))
    });
    // The first step on its own, as a fresh run after just that change would
    // read it (one more search).
    let first_fix_exposure_after = fixes.first().map(|(_, removes, _)| {
        let removes: HashSet<EdgeIndex> = removes.iter().copied().collect();
        let tree = analysis::reach_targets_where(g, t0.iter().copied(), |e| !removes.contains(&e));
        analysis::pct(rel.exposed(&exposed, |ix| tree.reaches(ix)), relevant)
    });
    let mut step_source = Vec::with_capacity(fixes.len());
    let mut step_tail = Vec::with_capacity(fixes.len());
    let fixes: Vec<PlannedFix> = fixes
        .into_iter()
        .map(|(f, _, (source, tail))| {
            step_source.push(source);
            step_tail.push(tail);
            f
        })
        .collect();
    let exposure_before = analysis::pct(exposed.len(), relevant);
    let exposure_after = analysis::pct(exposed_after, relevant_after);
    RemediationPlan {
        exposed_before: exposed.len(),
        exposed_after,
        exposure_before,
        exposure_after,
        exposure_delta: exposure_before - exposure_after,
        relevant_population: relevant,
        relevant_population_after: relevant_after,
        first_fix_exposure_after,
        total_cost: fixes.iter().map(|f| f.cost).sum(),
        fixes,
        detail: Some(PlanDetail {
            exposed,
            sources: trees,
            step_source,
            step_tail,
        }),
    }
}

/// An arc in the flow network that stands for a change: one edge, or a group
/// of edges removed together.
#[derive(Debug, Clone, Copy)]
enum Cut {
    Edge(EdgeIndex),
    Shared(usize),
}

/// Edges with the same key are removed by one change: SDProp copies together
/// with the right on AdminSDHolder, inherited ACEs together with the
/// container that defines them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FixKey {
    from: NodeIndex,
    kind: EdgeKind,
    origin: NodeIndex,
    sdprop: bool,
}

fn fix_key(
    g: &AdGraph,
    e: EdgeIndex,
    explicit: &HashSet<(NodeIndex, EdgeKind, NodeIndex)>,
) -> Option<FixKey> {
    let (a, b) = g.inner().edge_endpoints(e)?;
    let kind = g.inner()[e];
    let key = |origin, sdprop| {
        Some(FixKey {
            from: a,
            kind,
            origin,
            sdprop,
        })
    };
    if g.node(b).is_adminsdholder() {
        return key(b, true);
    }
    if let Some(holder) = sdprop_origin(g, a, kind, b) {
        return key(holder, true);
    }
    if g.is_inherited(e) {
        // Defined on the topmost container above `b` that has the same right
        // explicitly; without one (an inherit-only ACE), on the parent.
        let mut origin = None;
        let mut cur = g.parent(b);
        while let Some(p) = cur {
            if explicit.contains(&(a, kind, p)) {
                origin = Some(p);
            }
            cur = g.parent(p);
        }
        return key(origin.or(g.parent(b))?, false);
    }
    if matches!(
        g.node(b).kind,
        NodeKind::Ou | NodeKind::Container | NodeKind::Domain
    ) {
        // An explicit right on a container: where its inherited copies come from.
        return key(b, false);
    }
    None
}

struct Arc {
    from: usize,
    to: usize,
    cap: u64,
    cap_orig: u64,
    cut: Option<Cut>,
}

/// Dinic's max-flow. Arcs are stored in pairs: `i` forward, `i ^ 1` reverse.
struct FlowNet {
    arcs: Vec<Arc>,
    adj: Vec<Vec<usize>>,
}

impl FlowNet {
    fn new(n: usize) -> Self {
        FlowNet {
            arcs: Vec::new(),
            adj: vec![Vec::new(); n],
        }
    }

    fn add(&mut self, from: usize, to: usize, cap: u64, cut: Option<Cut>) {
        self.adj[from].push(self.arcs.len());
        self.arcs.push(Arc {
            from,
            to,
            cap,
            cap_orig: cap,
            cut,
        });
        self.adj[to].push(self.arcs.len());
        self.arcs.push(Arc {
            from: to,
            to: from,
            cap: 0,
            cap_orig: 0,
            cut: None,
        });
    }

    fn levels(&self, s: usize) -> Vec<u32> {
        let mut level = vec![u32::MAX; self.adj.len()];
        level[s] = 0;
        let mut queue = VecDeque::from([s]);
        while let Some(u) = queue.pop_front() {
            for &a in &self.adj[u] {
                let arc = &self.arcs[a];
                if arc.cap > 0 && level[arc.to] == u32::MAX {
                    level[arc.to] = level[u] + 1;
                    queue.push_back(arc.to);
                }
            }
        }
        level
    }

    fn max_flow(&mut self, s: usize, t: usize) -> u64 {
        let mut flow: u64 = 0;
        loop {
            let level = self.levels(s);
            if level[t] == u32::MAX {
                return flow;
            }
            let mut next = vec![0usize; self.adj.len()];
            loop {
                let pushed = self.augment(s, t, INF, &level, &mut next);
                if pushed == 0 {
                    break;
                }
                flow = flow.saturating_add(pushed);
                // A path of uncuttable edges: no finite cut separates it.
                if flow >= INF {
                    return flow;
                }
            }
        }
    }

    fn augment(
        &mut self,
        u: usize,
        t: usize,
        limit: u64,
        level: &[u32],
        next: &mut [usize],
    ) -> u64 {
        if u == t {
            return limit;
        }
        while next[u] < self.adj[u].len() {
            let a = self.adj[u][next[u]];
            let (to, cap) = (self.arcs[a].to, self.arcs[a].cap);
            if cap > 0 && level[to] == level[u] + 1 {
                let pushed = self.augment(to, t, limit.min(cap), level, next);
                if pushed > 0 {
                    self.arcs[a].cap -= pushed;
                    self.arcs[a ^ 1].cap += pushed;
                    return pushed;
                }
            }
            next[u] += 1;
        }
        0
    }

    fn residual_reachable(&self, s: usize) -> Vec<bool> {
        let mut seen = vec![false; self.adj.len()];
        seen[s] = true;
        let mut queue = VecDeque::from([s]);
        while let Some(u) = queue.pop_front() {
            for &a in &self.adj[u] {
                let arc = &self.arcs[a];
                if arc.cap > 0 && !seen[arc.to] {
                    seen[arc.to] = true;
                    queue.push_back(arc.to);
                }
            }
        }
        seen
    }
}

#[cfg(test)]
mod fix_text_tests {
    use super::*;

    #[test]
    fn plain_permissions_share_one_sentence() {
        let kinds = [
            EdgeKind::GenericWrite,
            EdgeKind::WriteOwner,
            EdgeKind::WriteDacl,
        ];
        let text = fix_text(&kinds, "SAMWELL", "STARKWALLPAPER");
        assert_eq!(
            text,
            "Remove the GenericWrite, WriteOwner and WriteDacl permissions that SAMWELL holds on STARKWALLPAPER. \
             If the permissions are inherited, fix the ACE on the parent container and check inheritance on \
             the affected objects."
        );
        assert_eq!(text.matches("SAMWELL").count(), 1);
    }

    #[test]
    fn dedicated_instructions_are_kept() {
        let text = fix_text(&[EdgeKind::GenericAll, EdgeKind::Owns], "A", "B");
        assert!(text.starts_with("Remove the GenericAll permission that A holds on B."));
        assert!(
            text.contains("Change the owner of B to Domain Admins. The owner can always change")
        );
        assert!(text.ends_with("check inheritance on the affected objects."));
    }

    /// The kind of permission and of object in words, the PKI owner, and
    /// the one AD CS finding with the exact fix.
    #[test]
    fn fixes_name_the_kind_and_the_owner() {
        let gpo = permissions_fix_on(
            &[EdgeKind::GenericWrite, EdgeKind::WriteDacl],
            "APP-GROUP",
            "LEGACY OUTLOOK SETTINGS",
            Some(NodeKind::Gpo),
        );
        assert!(gpo.starts_with(
            "Remove the Group Policy security permissions GenericWrite and WriteDacl that APP-GROUP \
             holds on the GPO LEGACY OUTLOOK SETTINGS."
        ));
        let owner = edge_fix_on(
            EdgeKind::Owns,
            "J.DOE",
            "WEBSERVER",
            Some(NodeKind::CertTemplate),
        );
        assert!(owner.starts_with(
            "Change the owner of the certificate template WEBSERVER to Enterprise Admins."
        ));
        assert_eq!(
            edge_fix(EdgeKind::AdcsEsc4, "J.DOE", "SCALE.LOCAL"),
            "J.DOE can get a certificate that takes over SCALE.LOCAL (ESC4). The PW-017 finding has the \
             exact change to the certificate template or CA."
        );
        assert!(edge_fix(EdgeKind::DcSync, "SYNC", "SCALE.LOCAL").contains(
            "Replicating Directory Changes All that SYNC holds on the domain object SCALE.LOCAL"
        ));
    }

    fn node(g: &mut AdGraph, id: &str, name: &str, kind: NodeKind) -> NodeIndex {
        let mut n = crate::model::Node::placeholder(id.to_string(), kind);
        n.placeholder = false;
        n.name = name.to_string();
        g.upsert(n)
    }

    /// Everyone on a GPO keeps Read through Authenticated Users, and
    /// the GPO's editors are named.
    #[test]
    fn everyone_on_a_gpo_keeps_it_readable() {
        let mut g = AdGraph::new();
        let everyone = node(
            &mut g,
            "SCALE.LOCAL-S-1-1-0",
            "EVERYONE@SCALE.LOCAL",
            NodeKind::Group,
        );
        let gpo = node(
            &mut g,
            "GPO-1",
            "LEGACY OUTLOOK SETTINGS@SCALE.LOCAL",
            NodeKind::Gpo,
        );
        g.add_ace_edge(everyone, gpo, EdgeKind::GenericWrite, false);
        let e = g.inner().find_edge(everyone, gpo).unwrap();
        let fix = fix_for_edges_advised(&g, &[e], Keepers::TierZero);
        assert_eq!(
            fix,
            "Remove the Group Policy security permission GenericWrite that EVERYONE@SCALE.LOCAL holds on \
             the GPO LEGACY OUTLOOK SETTINGS@SCALE.LOCAL. If you remove the entry of Everyone, give \
             Authenticated Users Read in its place, so the GPO still applies. If the permission is \
             inherited, fix the ACE on the parent container and check inheritance on the affected \
             objects. Only Domain Admins, Enterprise Admins and your designated Group Policy \
             administrators should be able to edit the GPO, change its permissions or own it. If nobody \
             uses this GPO any more, unlink and delete it instead."
        );
        // The plan's step keeps the plain fix.
        assert!(!fix_for_edges(&g, &[e]).contains("in its place"));
    }

    /// Authenticated Users keeps Read on a GPO, and a broad group's default
    /// read access stays on any other object.
    #[test]
    fn broad_groups_keep_their_read_access() {
        let mut g = AdGraph::new();
        let users = node(
            &mut g,
            "SCALE.LOCAL-S-1-5-11",
            "AUTHENTICATED USERS@SCALE.LOCAL",
            NodeKind::Group,
        );
        let gpo = node(
            &mut g,
            "GPO-1",
            "WORKSTATION BASELINE@SCALE.LOCAL",
            NodeKind::Gpo,
        );
        let jdoe = node(
            &mut g,
            "S-1-5-21-1-2-3-1100",
            "J.DOE@SCALE.LOCAL",
            NodeKind::User,
        );
        g.add_ace_edge(users, gpo, EdgeKind::GenericWrite, false);
        g.add_ace_edge(users, jdoe, EdgeKind::GenericWrite, false);
        let on_gpo = g.inner().find_edge(users, gpo).unwrap();
        let on_user = g.inner().find_edge(users, jdoe).unwrap();
        assert!(fix_for_edges_advised(&g, &[on_gpo], Keepers::Any).contains(
            "Keep its Read permission (and Apply group policy where Security Filtering uses it): \
                 Group Policy needs it to apply the GPO"
        ));
        let fix = fix_for_edges_advised(&g, &[on_user], Keepers::TierZero);
        assert!(fix.contains(
            "Remove only these permissions: the default read access of AUTHENTICATED USERS@SCALE.LOCAL stays."
        ));
        assert!(fix.ends_with(
            "Leave the right to change the user only with the Tier Zero administrators responsible for it."
        ));
    }

    /// A broad group keeps Read & Execute on a GPO's SYSVOL folder:
    /// `icacls /remove:g` takes its read access too, so it's given back.
    /// Group Policy Management's own repair comes first.
    #[test]
    fn broad_groups_keep_read_on_the_sysvol_folder() {
        let mut g = AdGraph::new();
        let users = node(
            &mut g,
            "SCALE.LOCAL-S-1-5-11",
            "AUTHENTICATED USERS@SCALE.LOCAL",
            NodeKind::Group,
        );
        let bob = node(
            &mut g,
            "S-1-5-21-1-2-3-1102",
            "BOB@SCALE.LOCAL",
            NodeKind::User,
        );
        let gpo = node(
            &mut g,
            "GPO-1",
            "WORKSTATION BASELINE@SCALE.LOCAL",
            NodeKind::Gpo,
        );
        let path = r"\\scale.local\SYSVOL\scale.local\Policies\{GPO-1}";
        for who in [users, bob] {
            g.add_edge(who, gpo, EdgeKind::WriteGpoFiles);
            g.add_file_grants(
                who,
                gpo,
                EdgeKind::WriteGpoFiles,
                vec![crate::sysvol::FileGrant {
                    path: path.to_string(),
                    rights: vec!["write".to_string()],
                    owner: false,
                    inherited: false,
                }],
            );
        }
        let e = g.inner().find_edge(users, gpo).unwrap();
        let fix = file_fix(&g, e).unwrap();
        assert!(fix.starts_with(
            "Reduce the access AUTHENTICATED USERS@SCALE.LOCAL has to the SYSVOL folder of the GPO \
             WORKSTATION BASELINE@SCALE.LOCAL to Read & Execute"
        ));
        assert!(fix.contains("The simplest fix: open the GPO in Group Policy Management"));
        assert!(fix.ends_with(&format!(
            "`icacls \"{path}\" /remove:g *S-1-5-11`, then `icacls \"{path}\" /grant \
             *S-1-5-11:(OI)(CI)RX`, because `/remove:g` also removes its read access."
        )));
        let b = g.inner().find_edge(bob, gpo).unwrap();
        let fix = file_fix(&g, b).unwrap();
        assert!(fix.starts_with("Remove the write access BOB@SCALE.LOCAL has"));
        assert!(!fix.contains("/grant"));
        // PW-027: Group Policy Management once, then each account.
        let both = gpo_files_fix(&g, &[e, b]).unwrap();
        assert_eq!(both.matches("The simplest fix").count(), 1);
        assert_eq!(both.matches("/save gpo-acl.txt").count(), 1);
    }

    /// An inherited right is fixed where it is defined, and the objects
    /// below that container are checked.
    #[test]
    fn inherited_rights_are_fixed_on_the_parent() {
        let mut g = AdGraph::new();
        let jdoe = node(
            &mut g,
            "S-1-5-21-1-2-3-1100",
            "J.DOE@SCALE.LOCAL",
            NodeKind::User,
        );
        let ou = node(&mut g, "OU-1", "SERVERS@SCALE.LOCAL", NodeKind::Ou);
        let grp = node(
            &mut g,
            "S-1-5-21-1-2-3-1200",
            "SQL ADMINS@SCALE.LOCAL",
            NodeKind::Group,
        );
        g.add_edge(ou, grp, EdgeKind::Contains);
        g.add_ace_edge(jdoe, grp, EdgeKind::GenericAll, true);
        let e = g.inner().find_edge(jdoe, grp).unwrap();
        assert!(fix_for_edges(&g, &[e]).ends_with(
            "It is inherited from SERVERS@SCALE.LOCAL or a container above it: fix the entry there, where \
             it is defined, and check inheritance on the objects below it, because the change applies to \
             all of them."
        ));
    }

    #[test]
    fn who_keeps_the_right_depends_on_the_object() {
        let mut g = AdGraph::new();
        let jdoe = node(
            &mut g,
            "S-1-5-21-1-2-3-1100",
            "J.DOE@SCALE.LOCAL",
            NodeKind::User,
        );
        let exch = node(
            &mut g,
            "S-1-5-21-1-2-3-1200",
            "EXCHANGE WINDOWS PERMISSIONS@SCALE.LOCAL",
            NodeKind::Group,
        );
        let certs = node(
            &mut g,
            "S-1-5-21-1-2-3-1300",
            "CERT USERS@SCALE.LOCAL",
            NodeKind::Group,
        );
        g.add_ace_edge(jdoe, exch, EdgeKind::AddMember, false);
        let a = g.inner().find_edge(jdoe, exch).unwrap();
        g.add_ace_edge(jdoe, certs, EdgeKind::AddMember, false);
        let b = g.inner().find_edge(jdoe, certs).unwrap();
        let fix = fix_for_edges_advised(&g, &[a], Keepers::TierZero);
        assert!(fix.contains(
            "If J.DOE@SCALE.LOCAL needs to change EXCHANGE WINDOWS PERMISSIONS@SCALE.LOCAL, delegate only \
             the rights it needs."
        ));
        assert!(fix.ends_with(
            "Leave the right to change the group only with the Exchange and Active Directory administrators."
        ));
        assert!(fix_for_edges_advised(&g, &[b], Keepers::Any).ends_with(
            "Leave the right to change the group only with the administrators responsible for it."
        ));
        assert!(fix_for_edges_advised(&g, &[b], Keepers::Zone)
            .ends_with("Leave the right to change the group only with the zone's administrators."));
        assert_eq!(
            deny_note(&[EdgeKind::AddMember]),
            Some("Deny entries: not checked. Pathwarden reads allowed permissions only.")
        );
        assert_eq!(deny_note(&[EdgeKind::MemberOf]), None);
    }

    #[test]
    fn default_gpos_are_never_deleted() {
        assert!(is_default_gpo(
            "0F1E2D3C-0000-0000-0000-000000000001",
            Some(
                "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=SCALE,DC=LOCAL"
            )
        ));
        assert!(is_default_gpo("6AC1786C-016F-11D2-945F-00C04FB984F9", None));
        assert!(!is_default_gpo(
            "0F1E2D3C-0000-0000-0000-000000000001",
            Some(
                "CN={11111111-016D-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=SCALE,DC=LOCAL"
            )
        ));
        assert!(reads_gpo_to_apply("S-1-5-21-1-2-3-515"));
        assert!(reads_gpo_to_apply("SCALE.LOCAL-S-1-5-11"));
        assert!(!reads_gpo_to_apply("S-1-5-21-1-2-3-513"));
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::model::Node;

    fn node(g: &mut AdGraph, id: &str, kind: NodeKind) -> NodeIndex {
        let mut n = Node::placeholder(id.to_string(), kind);
        n.placeholder = false;
        n.name = format!("{id}@CORP.LOCAL");
        g.upsert(n)
    }

    #[test]
    fn inherited_copies_of_one_ace_are_one_fix() {
        // ATTACKER holds GenericAll on the SERVERS OU, inherited by four groups
        // in it, each of which can write the target. Without grouping the cut
        // costs four (either the four inherited copies or the four group
        // rights); one change on the OU removes all of them.
        let mut g = AdGraph::new();
        let attacker = node(&mut g, "S-1-5-21-1-2-3-1000", NodeKind::User);
        let ou = node(&mut g, "OU-SERVERS", NodeKind::Ou);
        let target = node(&mut g, "S-1-5-21-1-2-3-512", NodeKind::Group);
        g.add_ace_edge(attacker, ou, EdgeKind::GenericAll, false);
        for i in 0..4 {
            let grp = node(
                &mut g,
                &format!("S-1-5-21-1-2-3-{}", 2000 + i),
                NodeKind::Group,
            );
            g.add_edge(ou, grp, EdgeKind::Contains);
            g.add_ace_edge(attacker, grp, EdgeKind::GenericAll, true);
            g.add_ace_edge(grp, target, EdgeKind::GenericWrite, false);
        }

        let plan = plan_to(&g, &[target], &analysis::Relevance::new(&g, 0, 90));
        assert_eq!((plan.exposed_before, plan.exposed_after), (1, 0));
        assert_eq!(plan.fixes.len(), 1, "{:#?}", plan.fixes);
        let fix = &plan.fixes[0];
        assert_eq!(fix.to, "OU-SERVERS@CORP.LOCAL");
        assert_eq!(fix.inherited_by, 4);
        assert_eq!(fix.cost, 1);
        assert_eq!(fix.principals_through, 1);
        assert!(
            fix.action
                .contains("4 objects below OU-SERVERS@CORP.LOCAL inherit this"),
            "{}",
            fix.action
        );
    }
}
