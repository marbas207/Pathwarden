//! Rules on what the built-in collector read from SYSVOL (see
//! [`crate::sysvol`]): GPP passwords (PW-026) and GPO folder permissions
//! that differ from the GPO's AD permissions (PW-027). Attack paths through
//! `WriteGPOFiles` and `WriteLogonScript` need no rule of their own: they
//! are ordinary control edges, so PW-001, PW-003 and PW-022 report them.

use std::collections::BTreeMap;

use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;

use super::{Context, Finding, Severity};
use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::sid;
use crate::sysvol::Part;

const MS14_025: &str =
    "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025";
const ATTACK_GPP: &str = "https://attack.mitre.org/techniques/T1552/006/";
const ATTACK_GPO_MOD: &str = "https://attack.mitre.org/techniques/T1484/001/";

/// The account a GPP file names, if the collection has it. Local accounts
/// ("Administrator (built-in)") are not in the directory.
fn account(g: &AdGraph, domain: &str, name: &str) -> Option<NodeIndex> {
    let name = name.trim();
    if name.is_empty() || name.contains('(') {
        return None;
    }
    let query = match name.split_once('\\') {
        Some((_, user)) => format!("{user}@{domain}"),
        None if name.contains('@') => name.to_string(),
        None => format!("{name}@{domain}"),
    };
    g.find(&query)
        .into_iter()
        .find(|&ix| g.node(ix).kind == NodeKind::User)
}

/// PW-026: a Group Policy Preferences file in SYSVOL holds a `cpassword`.
/// Any authenticated user can read SYSVOL, and Microsoft published the AES
/// key, so the password is as good as public.
pub(super) fn gpp_passwords(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    let mut out = Vec::new();
    for d in g.sysvol_domains() {
        for hit in &d.gpp {
            let gpo_name = hit
                .gpo
                .map(|ix| g.node(ix).name.clone())
                .unwrap_or_else(|| hit.guid.clone());
            let accounts: Vec<(String, Option<NodeIndex>)> = hit
                .accounts
                .iter()
                .map(|a| (a.clone(), account(g, &d.domain, a)))
                .collect();
            let tier_zero: Vec<&str> = accounts
                .iter()
                .filter_map(|(_, ix)| ix.filter(|&i| g.node(i).tier_zero))
                .map(|ix| g.node(ix).name.as_str())
                .collect();
            let who = if accounts.is_empty() {
                "an account the file does not name".to_string()
            } else {
                accounts
                    .iter()
                    .map(|(a, _)| a.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let t0_note = if tier_zero.is_empty() {
                String::new()
            } else {
                format!(" {} is Tier Zero.", tier_zero.join(", "))
            };
            let file = hit.file.rsplit('\\').next().unwrap_or(&hit.file);
            let mut affected: Vec<(NodeIndex, Option<String>)> = Vec::new();
            if let Some(ix) = hit.gpo {
                affected.push((ix, Some(hit.path.clone())));
            }
            for (_, ix) in &accounts {
                if let Some(ix) = ix {
                    if !affected.iter().any(|(a, _)| a == ix) {
                        affected.push((*ix, Some("password stored in SYSVOL".into())));
                    }
                }
            }
            let mut f = Finding::new(
                "PW-026",
                Severity::Critical,
                &[&d.domain, &hit.guid, &hit.file.to_ascii_uppercase()],
                format!("Group Policy Preferences password in {gpo_name} ({file})"),
            )
            .domain(Some(&d.domain))
            .summary(format!(
                "{} in the GPO {gpo_name} stores a password (cpassword) for {who}. Every \
                 authenticated user can read SYSVOL, and Microsoft published the key that decrypts \
                 it (MS14-025), so treat the password as known to anyone in the domain.{t0_note}",
                hit.path
            ))
            .remediation(format!(
                "Change the password of {who} now: it has to be treated as compromised. Then delete \
                 the preference item that holds it in Group Policy Management (Computer or User \
                 Configuration > Preferences), or delete {} if the GPO needs nothing else from it. \
                 Use LAPS or a gMSA instead of a password in Group Policy. The guide has an audit \
                 command that lists every cpassword left in SYSVOL.",
                hit.path
            ))
            .affect_with(g, affected)
            .refs(&[MS14_025, ATTACK_GPP]);
            f.sources = vec![Part::Gpp.source(&d.domain)];
            out.push(f);
        }
    }
    out
}

/// PW-027: principals that can write a GPO's folder in SYSVOL without the
/// matching rights on the GPO in AD. One finding per GPO, from its
/// `WriteGPOFiles` edges (which are exactly those writers).
pub(super) fn sysvol_drift(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    if g.sysvol_domains().is_empty() {
        return Vec::new();
    }
    let mut by_gpo: BTreeMap<NodeIndex, Vec<EdgeIndex>> = BTreeMap::new();
    for e in g.inner().edge_references() {
        if *e.weight() == EdgeKind::WriteGpoFiles {
            by_gpo.entry(e.target()).or_default().push(e.id());
        }
    }
    by_gpo
        .into_iter()
        .map(|(gix, edges)| {
            let gpo = g.node(gix);
            let mut writers: Vec<(NodeIndex, Option<String>)> = Vec::new();
            let mut lines: Vec<String> = Vec::new();
            let mut broad = false;
            for &e in &edges {
                let (p, _) = g.inner().edge_endpoints(e).expect("edge from this graph");
                let who = g.node(p);
                broad |= sid::is_broad_group(&who.id);
                let grants = g.file_grants(e);
                let detail = grants
                    .iter()
                    .map(|gr| format!("{} on {}", gr.rights.join(", "), gr.path))
                    .collect::<Vec<_>>()
                    .join("; ");
                if lines.len() < 10 {
                    lines.push(format!("{} ({detail})", who.name));
                }
                writers.push((p, Some(detail)));
            }
            if edges.len() > lines.len() {
                lines.push(format!("and {} more", edges.len() - lines.len()));
            }
            let severity = if gpo.tier_zero || broad {
                Severity::High
            } else {
                Severity::Medium
            };
            let t0 = if gpo.tier_zero {
                format!(
                    " The GPO is Tier Zero ({}), so this is also a path to Tier Zero (PW-003).",
                    gpo.tier_zero_reason.as_deref().unwrap_or("Tier Zero")
                )
            } else {
                String::new()
            };
            let mut fix = crate::remediation::gpo_files_fix(g, &edges[..edges.len().min(5)])
                .unwrap_or_default();
            if edges.len() > 5 {
                fix.push_str(&format!(
                    " And {} the same way.",
                    crate::text::count(edges.len() - 5, "more account", "more accounts")
                ));
            }
            let delete = if crate::remediation::is_default_gpo(
                &gpo.id,
                gpo.props.distinguishedname.as_deref(),
            ) {
                ""
            } else {
                " If nobody uses this GPO any more, unlink and delete it instead."
            };
            Finding::new(
                "PW-027",
                severity,
                &[&gpo.id],
                format!(
                    "SYSVOL permissions of {} differ from its AD permissions",
                    gpo.name
                ),
            )
            .domain(gpo.domain.as_ref())
            .summary(format!(
                "{} can write the SYSVOL folder of the GPO {} (its SYSVOL folder permissions) without \
                 the Group Policy security permissions to edit the GPO: {}. Whoever writes these files \
                 decides what the GPO applies to every computer and user it is linked to, and the \
                 Delegation tab in Group Policy Management doesn't show it.{t0}",
                crate::text::count(edges.len(), "account", "accounts"),
                gpo.name,
                lines.join(", ")
            ))
            .remediation(format!(
                "{fix}{delete} Then collect again and check that this finding is gone."
            ))
            .affect_with(g, std::iter::once((gix, None)).chain(writers))
            .evidence(edges)
            .refs(&[ATTACK_GPO_MOD])
        })
        .collect()
}
