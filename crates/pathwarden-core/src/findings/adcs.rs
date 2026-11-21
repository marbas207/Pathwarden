//! AD CS findings: one per exploitable template / CA condition found by
//! [`crate::adcs`], listing only the principals outside Tier Zero that can abuse it.

use petgraph::graph::NodeIndex;

use super::{Context, Finding, Severity};
use crate::adcs::{Esc, EscInstance, WeakDc};
use crate::dcsettings::{CertUpdate, Mapping, Weakness};
use crate::graph::AdGraph;
use crate::model::EdgeKind;
use crate::sid;

const CERTIFIED_PRE_OWNED: &str =
    "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf";
const MS_ADCS_HARDENING: &str =
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts";
const RPC_RELAY: &str =
    "https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/";
const MS_CERT_BINDING: &str = "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16";

pub(super) fn esc1(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-015", &[Esc::Esc1])
}

pub(super) fn esc3(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-016", &[Esc::Esc3])
}

pub(super) fn esc4(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-017", &[Esc::Esc4])
}

pub(super) fn esc6(ctx: &Context) -> Vec<Finding> {
    let g = ctx.graph;
    // Only verified ESC6 is an attack path. When the DC mapping settings could
    // not be read, the flag finding below says the same thing with the same fix.
    let verified =
        |i: &EscInstance| matches!(i.esc, Esc::Esc6a | Esc::Esc6b) && !i.targets.is_empty();
    let instances = g.esc_instances().iter().filter(|i| verified(i)).collect();
    let mut out: Vec<Finding> = merge(instances)
        .iter()
        .filter_map(|m| finding(ctx, "PW-018", m))
        .collect();
    // The flag is dangerous even when no template completes the attack today:
    // one template change, or one DC in compatibility mode, is all it takes.
    for (ix, ca) in g.nodes() {
        let flagged = ca.kind == crate::model::NodeKind::EnterpriseCa
            && ca
                .adcs
                .as_deref()
                .is_some_and(|p| p.isuserspecifiessanenabled == Some(true));
        let exploitable = g.esc_instances().iter().any(|i| i.ca == ix && verified(i));
        if !flagged || exploitable {
            continue;
        }
        let config = ca_config(g, ix);
        out.push(
            Finding::new("PW-018", Severity::High, &["flag", &ca.id], format!(
                "{} has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                ca.name
            ))
            .domain(ca.domain.as_ref())
            .summary(format!(
                "{} lets every request name an arbitrary identity in the subject alternative name. No template is \
                 known to complete the ESC6 attack today, but a template without the security extension, or a \
                 domain controller with weak certificate mapping (which the collector may not have been able to \
                 read), makes it a direct path to domain compromise.",
                ca.name
            ))
            .remediation(format!(
                "Disable the flag: `certutil -config \"{config}\" -setreg policy\\EditFlags \
                 -EDITF_ATTRIBUTESUBJECTALTNAME2`, then restart Certificate Services (`net stop certsvc && net start \
                 certsvc`)."
            ))
            .affect(g, [ix])
            .refs(&[CERTIFIED_PRE_OWNED, MS_ADCS_HARDENING]),
        );
    }
    out
}

/// `host\CA name` as certutil's -config expects.
fn ca_config(g: &AdGraph, ca: NodeIndex) -> String {
    match g.node(ca).adcs.as_deref() {
        Some(p) => format!(
            "{}\\{}",
            p.dnshostname.as_deref().unwrap_or("<ca-host>"),
            p.caname.as_deref().unwrap_or("<ca-name>")
        ),
        None => "<ca-host>\\<ca-name>".to_string(),
    }
}

pub(super) fn esc8(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-019", &[Esc::Esc8])
}

pub(super) fn esc11(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-036", &[Esc::Esc11])
}

pub(super) fn esc9_10(ctx: &Context) -> Vec<Finding> {
    findings(
        ctx,
        "PW-020",
        &[Esc::Esc9a, Esc::Esc9b, Esc::Esc10a, Esc::Esc10b],
    )
}

pub(super) fn esc13(ctx: &Context) -> Vec<Finding> {
    findings(ctx, "PW-021", &[Esc::Esc13])
}

fn names(g: &AdGraph, ixs: &[NodeIndex]) -> String {
    let mut s: Vec<&str> = ixs
        .iter()
        .take(8)
        .map(|&ix| g.node(ix).name.as_str())
        .collect();
    if ixs.len() > 8 {
        s.push("...");
    }
    s.join(", ")
}

/// Certificates an ESC1 template issued before the fix still log on as
/// whoever they name.
const ISSUED_STAY_VALID: &str =
    "Certificates it already issued stay valid after the fix: check the \
     CA's Issued Certificates for subjects that don't match the requester, and revoke them.";

/// The rights on a template that let ESC4 change it.
const TEMPLATE_WRITE: &[EdgeKind] = &[
    EdgeKind::Owns,
    EdgeKind::GenericAll,
    EdgeKind::GenericWrite,
    EdgeKind::WriteDacl,
    EdgeKind::WriteOwner,
    EdgeKind::WritePkiNameFlag,
    EdgeKind::WritePkiEnrollmentFlag,
];

/// A template right as the template's Advanced Security Settings name it.
fn template_right(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::GenericAll => "Full Control",
        EdgeKind::GenericWrite => "Write",
        EdgeKind::WriteDacl => "Modify permissions",
        EdgeKind::WriteOwner => "Modify owner",
        EdgeKind::WritePkiNameFlag => "write access to msPKI-Certificate-Name-Flag",
        EdgeKind::WritePkiEnrollmentFlag => "write access to msPKI-Enrollment-Flag",
        EdgeKind::Owns => "ownership",
        _ => kind.as_str(),
    }
}

/// "A", "A and B", "A, B and C".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// PW-017's fix: the rights each holder outside Tier Zero has on the
/// template `t` that let `sources` change it (the holder is a source, a
/// group a source is in, or a broad group), the owner, and where an
/// inherited entry comes from.
fn esc4_fix(g: &AdGraph, t: NodeIndex, sources: &[NodeIndex], t_short: &str) -> String {
    use petgraph::visit::EdgeRef;
    let mut by: std::collections::BTreeMap<NodeIndex, (Vec<EdgeKind>, bool)> = Default::default();
    for e in g.inner().edges_directed(t, petgraph::Direction::Incoming) {
        let (h, kind) = (e.source(), *e.weight());
        if !TEMPLATE_WRITE.contains(&kind) || g.node(h).tier_zero {
            continue;
        }
        let related = sources.contains(&h)
            || sid::is_broad_group(&g.node(h).id)
            || g.transitive_members(h).iter().any(|m| sources.contains(m));
        if !related {
            continue;
        }
        let entry = by.entry(h).or_insert((Vec::new(), true));
        if !entry.0.contains(&kind) {
            entry.0.push(kind);
        }
        entry.1 &= kind == EdgeKind::Owns || g.is_inherited(e.id());
    }
    let keepers = "Anyone who needs certificates from it keeps Read and Enroll. Only the PKI \
                   administrators (by default Enterprise Admins and the forest root's Domain Admins) should \
                   be able to change certificate templates.";
    if by.is_empty() {
        return format!(
            "Remove the certificate template permissions (Full Control, Write, Modify permissions, Modify \
             owner, or write access to msPKI-Certificate-Name-Flag or msPKI-Enrollment-Flag) that let \
             accounts outside Tier Zero change {t_short}. {keepers}"
        );
    }
    let mut held: Vec<String> = Vec::new();
    let mut owners: Vec<String> = Vec::new();
    let mut inherited: Vec<String> = Vec::new();
    for (&h, (kinds, all_inherited)) in &by {
        let name = g.node(h).name.clone();
        let mut rights: Vec<String> = kinds
            .iter()
            .filter(|&&k| k != EdgeKind::Owns)
            .map(|&k| template_right(k).to_string())
            .collect();
        rights.sort_unstable();
        if kinds.contains(&EdgeKind::Owns) {
            owners.push(name.clone());
        }
        if !rights.is_empty() {
            held.push(format!("{} of {name}", and_list(&rights)));
            if *all_inherited {
                inherited.push(name);
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !held.is_empty() {
        parts.push(format!(
            "Remove these certificate template permissions on {t_short}: {}.",
            held.join("; ")
        ));
    }
    if !owners.is_empty() {
        parts.push(format!(
            "{} {} {t_short}: change the owner to Enterprise Admins, since the owner can always change \
             the permissions.",
            and_list(&owners),
            if owners.len() == 1 { "owns" } else { "own" }
        ));
    }
    parts.push(keepers.to_string());
    if !inherited.is_empty() {
        parts.push(format!(
            "The entries of {} are inherited from the Certificate Templates container (or a container \
             above it in the Configuration partition): fix them there and check inheritance on the other \
             templates.",
            and_list(&inherited)
        ));
    }
    parts.join(" ")
}

/// The name when there is one principal, otherwise "N principals" (the full
/// list is in the summary and the affected objects).
fn count_or_name(g: &AdGraph, ixs: &[NodeIndex]) -> String {
    match ixs {
        [one] => g.node(*one).name.clone(),
        many => format!("{} accounts", many.len()),
    }
}

/// `WEBSERVER@CONTOSO.LOCAL` -> `WEBSERVER`, the name certutil and the console use.
fn short(g: &AdGraph, ix: NodeIndex) -> String {
    let name = &g.node(ix).name;
    name.split('@').next().unwrap_or(name).to_string()
}

/// How to close the weak DCs of one mapping: their registry value, or (when
/// their build made them weak) the Windows updates. `None` when no DC is
/// known to be weak.
fn dc_fix(g: &AdGraph, weak: &[WeakDc], mappings: &[Mapping]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for &mapping in mappings {
        let by_value: Vec<NodeIndex> = weak
            .iter()
            .filter(|w| w.mapping == mapping && w.why == Weakness::Value)
            .map(|w| w.dc)
            .collect();
        if !by_value.is_empty() {
            let dcs = names(g, &by_value);
            parts.push(match mapping {
                Mapping::Kerberos => format!("Set StrongCertificateBindingEnforcement to 2 on {dcs}."),
                Mapping::Schannel => format!(
                    "Remove the UPN mapping bit (0x4) from HKLM\\SYSTEM\\CurrentControlSet\\Control\\\
                     SecurityProviders\\Schannel\\CertificateMappingMethods on {dcs}."
                ),
            });
        }
    }
    for &mapping in mappings {
        for w in weak.iter().filter(|w| w.mapping == mapping) {
            let Weakness::Build { build, update } = w.why else {
                continue;
            };
            let dc = &g.node(w.dc).name;
            parts.push(format!(
                "Install the current Windows updates on {dc} (build {}.{} predates the {} \
                 certificate-mapping update).",
                build.major,
                build.ubr,
                update.label()
            ));
            // Before May 2022 only the updates help: the KDC checks no
            // mapping, and Schannel's 0x18 maps through that same KDC.
            if (mapping, update) == (Mapping::Kerberos, CertUpdate::Feb2025) {
                parts.push(format!(
                    "Until then, set StrongCertificateBindingEnforcement to 2 on {dc}."
                ));
            }
        }
    }
    // One DC weak for both mappings needs the updates once.
    let mut seen = std::collections::HashSet::new();
    parts.retain(|p| seen.insert(p.clone()));
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Why DCs whose build made them weak count as weak, for the summary.
fn build_note(g: &AdGraph, weak: &[WeakDc]) -> String {
    let mut out = String::new();
    for w in weak {
        let Weakness::Build { build, update } = w.why else {
            continue;
        };
        let dc = &g.node(w.dc).name;
        let b = format!("{}.{}", build.major, build.ubr);
        out.push(' ');
        out.push_str(&match (w.mapping, update) {
            (Mapping::Schannel, _) => match g.node(w.dc).props.certificatemappingmethods {
                crate::model::DcSetting::Value(v) => format!(
                    "{dc} sets CertificateMappingMethods to {v:#x}, which hands mapping to the KDC \
                     (S4U2Self), and its build {b} predates the May 2022 update: that KDC maps by \
                     UPN and checks nothing."
                ),
                _ => format!(
                    "{dc} has no CertificateMappingMethods set, and its build {b} predates the May 2022 \
                     update, when the default was 0x1F, which includes UPN mapping."
                ),
            },
            (Mapping::Kerberos, CertUpdate::May2022) => format!(
                "{dc} runs build {b}, which predates the May 2022 update: its KDC checks no certificate \
                 mapping, whatever StrongCertificateBindingEnforcement says."
            ),
            (Mapping::Kerberos, CertUpdate::Feb2025) => format!(
                "{dc} has no StrongCertificateBindingEnforcement set, and its build {b} predates the \
                 February 2025 update: unset then means compatibility mode, which allows weak mappings."
            ),
        });
    }
    out
}

/// Instances merged to the level the fix happens at: an ESC3 finding per agent
/// template (fixed by restricting it), an ESC6 finding per CA (fixed by the CA
/// flag), an ESC9/ESC10 finding per CA covering its templates and both
/// variants (the DC mapping setting is the shared fix), an ESC11 finding per
/// CA (fixed by its InterfaceFlags).
struct Merged {
    inst: EscInstance,
    /// Label for titles and the fingerprint: "ESC3", "ESC6", "ESC9", ...
    family: &'static str,
    /// Variant labels actually present, e.g. "ESC9a/ESC9b".
    variants: String,
    /// ESC3: target templates. ESC6: templates that make the flag exploitable.
    /// ESC9/ESC10: the templates with weak mapping. ESC11: the authentication
    /// templates a relayed logon can enroll in.
    covers: Vec<NodeIndex>,
}

/// Family, CA, and the template / related object a finding is keyed on.
type GroupKey = (
    &'static str,
    NodeIndex,
    Option<NodeIndex>,
    Option<NodeIndex>,
);

fn merge(instances: Vec<&EscInstance>) -> Vec<Merged> {
    let mut groups: std::collections::BTreeMap<GroupKey, Merged> = Default::default();
    for i in instances {
        let (family, template, related) = match i.esc {
            Esc::Esc3 => ("ESC3", i.template, None),
            Esc::Esc6a | Esc::Esc6b => ("ESC6", None, None),
            Esc::Esc9a | Esc::Esc9b => ("ESC9", None, None),
            Esc::Esc10a | Esc::Esc10b => ("ESC10", None, None),
            Esc::Esc11 => ("ESC11", None, None),
            other => (other.label(), i.template, i.related),
        };
        let m = groups
            .entry((family, i.ca, template, related))
            .or_insert_with(|| Merged {
                inst: EscInstance {
                    template,
                    related,
                    sources: Vec::new(),
                    victims: Vec::new(),
                    targets: Vec::new(),
                    unverified: Vec::new(),
                    weak_dcs: Vec::new(),
                    ..i.clone()
                },
                family,
                variants: String::new(),
                covers: Vec::new(),
            });
        m.inst.sources.extend(&i.sources);
        m.inst.victims.extend(&i.victims);
        m.inst.targets.extend(&i.targets);
        m.inst.unverified.extend(&i.unverified);
        m.inst.weak_dcs.extend(&i.weak_dcs);
        let label = i.esc.label();
        let mut variants: Vec<&str> = m.variants.split('/').filter(|v| !v.is_empty()).collect();
        if !variants.contains(&label) {
            variants.push(label);
            variants.sort_unstable();
            m.variants = variants.join("/");
        }
        match i.esc {
            Esc::Esc3 => m.covers.extend(i.related),
            Esc::Esc6a
            | Esc::Esc6b
            | Esc::Esc9a
            | Esc::Esc9b
            | Esc::Esc10a
            | Esc::Esc10b
            | Esc::Esc11 => m.covers.extend(i.template),
            _ => {}
        }
    }
    groups
        .into_values()
        .map(|mut m| {
            for v in [
                &mut m.inst.sources,
                &mut m.inst.victims,
                &mut m.inst.targets,
                &mut m.inst.unverified,
                &mut m.covers,
            ] {
                v.sort_unstable();
                v.dedup();
            }
            m.inst.weak_dcs.sort_unstable();
            m.inst.weak_dcs.dedup();
            m
        })
        .collect()
}

fn findings(ctx: &Context, rule: &'static str, kinds: &[Esc]) -> Vec<Finding> {
    let g = ctx.graph;
    let instances = g
        .esc_instances()
        .iter()
        .filter(|i| kinds.contains(&i.esc))
        .collect();
    merge(instances)
        .iter()
        .filter_map(|m| finding(ctx, rule, m))
        .collect()
}

fn finding(ctx: &Context, rule: &'static str, m: &Merged) -> Option<Finding> {
    let g = ctx.graph;
    let i = &m.inst;
    let who_ix: Vec<NodeIndex> = i
        .sources
        .iter()
        .copied()
        .filter(|&s| !g.node(s).tier_zero)
        .collect();
    // Relay needs no rights of its own: every principal is exposed.
    let relay = matches!(i.esc, Esc::Esc8 | Esc::Esc11);
    if !relay && who_ix.is_empty() {
        return None;
    }
    let everyone = who_ix.iter().any(|&s| sid::is_broad_group(&g.node(s).id));
    let who = if everyone {
        format!("{} (effectively every account)", names(g, &who_ix))
    } else {
        names(g, &who_ix)
    };
    let ca = g.node(i.ca);
    let ca_name = ca.name.clone();
    let config = match ca.adcs.as_deref() {
        Some(p) => format!(
            "{}\\{}",
            p.dnshostname.as_deref().unwrap_or("<ca-host>"),
            p.caname.as_deref().unwrap_or("<ca-name>")
        ),
        None => "<ca-host>\\<ca-name>".to_string(),
    };
    let t = i.template.map(|t| (g.node(t).name.clone(), short(g, t)));
    let (t_name, t_short) = t.clone().unwrap_or_default();
    let label = m.variants.as_str();
    let covers = names(g, &m.covers);
    let ca_short = short(g, i.ca);

    let (severity, title, summary, remediation) = match i.esc {
        Esc::Esc1 => (
            Severity::Critical,
            format!("{label}: template {t_name} on {ca_short} lets requesters choose any identity"),
            format!(
                "{t_name} is published by {ca_name}, lets the enrollee supply the certificate subject, allows \
                 client authentication, and needs no manager approval. {who} can request a certificate as any \
                 user, including Domain Admins, and sign in with it."
            ),
            format!(
                "On the certificate template {t_short}, set Subject Name to 'Build from this Active Directory \
                 information', or turn on 'CA certificate manager approval' under Issuance Requirements. Remove \
                 the certificate template permission Enroll (and Full Control, which includes it) for {who} if \
                 they don't need this template, and give it to a dedicated group instead of a broad one. If \
                 nothing uses the template, stop publishing it from {ca_name} (certsrv.msc > Certificate \
                 Templates > Delete). {ISSUED_STAY_VALID}"
            ),
        ),
        Esc::Esc3 => {
            let target = covers.clone();
            let what = if m.covers.len() == 1 {
                target.clone()
            } else {
                format!("{} authentication templates", m.covers.len())
            };
            (
                Severity::Critical,
                format!("{label}: enrollment agent template {t_name} on {ca_short} can request {what} for anyone"),
                format!(
                    "{who} can enroll in {t_name}, which issues enrollment agent certificates, and then request \
                     {target} (an authentication certificate) on behalf of any user, including Domain Admins."
                ),
                format!(
                    "Restrict the certificate template permission Enroll (and Full Control, which includes it) \
                     on {t_short} to the few accounts that request certificates for others, for example a \
                     dedicated enrollment agent group the PKI administrators manage. Set enrollment agent \
                     restrictions on {ca_name} (certsrv.msc > CA Properties > Enrollment Agents) to limit which \
                     templates and users agents may enroll for. If nobody uses enrollment agents, stop \
                     publishing {t_short}. Certificates already issued stay valid after the fix: check the \
                     certificates {ca_name} issued on behalf of others for requests nobody expected, and revoke \
                     them."
                ),
            )
        }
        Esc::Esc4 => (
            Severity::Critical,
            format!("{label}: {} can modify template {t_name} on {ca_short}", count_or_name(g, &who_ix)),
            format!(
                "{who} can change the settings of the certificate template {t_name} (for example, let the \
                 enrollee supply the subject) and enroll in it through {ca_name}, turning it into ESC1.{}",
                crate::remediation::deny_note(&[EdgeKind::GenericWrite])
                    .map(|n| format!(" {n}"))
                    .unwrap_or_default()
            ),
            i.template
                .map(|t| esc4_fix(g, t, &who_ix, &t_short))
                .unwrap_or_default(),
        ),
        Esc::Esc6a | Esc::Esc6b => (
            Severity::Critical,
            format!(
                "{label}: {ca_name} accepts requester-supplied SANs ({})",
                crate::text::count(m.covers.len(), "usable template", "usable templates")
            ),
            format!(
                "{ca_name} has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, so any request may name an arbitrary \
                 identity in the subject alternative name. {who} can enroll in {covers} and impersonate any \
                 user.{}",
                build_note(g, &i.weak_dcs)
            ),
            {
                let mut fix = format!(
                    "Disable the flag: `certutil -config \"{config}\" -setreg policy\\EditFlags \
                     -EDITF_ATTRIBUTESUBJECTALTNAME2`, then restart Certificate Services (`net stop certsvc \
                     && net start certsvc`)."
                );
                if let Some(dcs) = dc_fix(g, &i.weak_dcs, &[Mapping::Kerberos, Mapping::Schannel]) {
                    fix.push_str(" Also on the domain controllers: ");
                    fix.push_str(&dcs);
                }
                // ESC6b with no DC known to be weak (unverified): the generic step.
                if m.variants.contains("ESC6b") && !i.weak_dcs.iter().any(|w| w.mapping == Mapping::Schannel) {
                    fix.push_str(
                        " Also remove the UPN mapping bit (0x4) from Schannel CertificateMappingMethods on \
                         domain controllers.",
                    );
                }
                fix
            },
        ),
        Esc::Esc8 => {
            let urls = ca
                .adcs
                .as_deref()
                .map(|p| p.vulnerableendpoints.join(", "))
                .unwrap_or_default();
            (
                Severity::High,
                format!("{label}: {ca_name} web enrollment accepts relayed NTLM"),
                format!(
                    "{urls} accept NTLM over HTTP, or HTTPS without Extended Protection for Authentication. An \
                     attacker can coerce a domain controller to authenticate (for example with PetitPotam), relay \
                     it to this endpoint, obtain a certificate for the DC, and compromise the domain."
                ),
                "Require HTTPS with Extended Protection for Authentication on these endpoints (IIS Manager > \
                 CertSrv > Authentication > Windows Authentication > Advanced Settings > Required) and disable \
                 HTTP, or remove the Web Enrollment / Certificate Enrollment Web Service roles if unused. \
                 Disabling NTLM on the CA server also blocks the relay. Until it's fixed, turning off the Print \
                 Spooler on domain controllers removes one way to coerce them (PrinterBug), but not the others, \
                 so it doesn't close the relay."
                    .to_string(),
            )
        }
        Esc::Esc11 => {
            let mut templates: Vec<String> = m.covers.iter().map(|&t| short(g, t)).collect();
            templates.sort_unstable();
            let templates = templates.join(", ");
            (
                Severity::High,
                format!("{label}: {ca_name} accepts relayed NTLM over RPC"),
                format!(
                    "{ca_name} does not require encrypted certificate requests on its RPC interface \
                     (IF_ENFORCEENCRYPTICERTREQUEST is off in InterfaceFlags), so it accepts NTLM-authenticated \
                     requests without packet privacy. An attacker can coerce a domain controller to authenticate \
                     (for example with PetitPotam), relay it to the CA over RPC, enroll in {templates} as the DC, \
                     and compromise the domain."
                ),
                format!(
                    "Require encrypted requests: `certutil -config \"{config}\" -setreg CA\\InterfaceFlags \
                     +IF_ENFORCEENCRYPTICERTREQUEST`, then restart Certificate Services (`net stop certsvc && net \
                     start certsvc`). Until it's fixed, turning off the Print Spooler on domain controllers \
                     removes one way to coerce them (PrinterBug), but not the others, so it doesn't close the \
                     relay."
                ),
            )
        }
        Esc::Esc9a | Esc::Esc9b | Esc::Esc10a | Esc::Esc10b => {
            let kerberos = matches!(i.esc, Esc::Esc9a | Esc::Esc9b);
            let attribute = if matches!(i.esc, Esc::Esc9b | Esc::Esc10b) { "dNSHostName" } else { "userPrincipalName" };
            let templates = m.covers.iter().map(|&t| short(g, t)).collect::<Vec<_>>().join(", ");
            let mapping = if kerberos { Mapping::Kerberos } else { Mapping::Schannel };
            let mapping_fix = match (dc_fix(g, &i.weak_dcs, &[mapping]), kerberos) {
                (Some(dcs), true) => format!(
                    "{dcs} Clear CT_FLAG_NO_SECURITY_EXTENSION (0x80000 in msPKI-Enrollment-Flag) on {templates}."
                ),
                (Some(dcs), false) => dcs,
                (None, true) => format!(
                    "Set StrongCertificateBindingEnforcement to 2 on every domain controller, and clear \
                     CT_FLAG_NO_SECURITY_EXTENSION (0x80000 in msPKI-Enrollment-Flag) on {templates}."
                ),
                (None, false) => "Remove the UPN mapping bit (0x4) from HKLM\\SYSTEM\\CurrentControlSet\\Control\\\
                     SecurityProviders\\Schannel\\CertificateMappingMethods on every domain controller."
                    .to_string(),
            };
            (
                Severity::High,
                format!(
                    "{label}: weak certificate mapping on {ca_short} lets {} impersonate others",
                    count_or_name(g, &who_ix)
                ),
                format!(
                    "Domain controllers accept weak certificate mappings for {covers}, published by {ca_name}. \
                     {who} can write the {attribute} of {} that can enroll, enroll as that account, \
                     and have the certificate map to a different, privileged account.{}",
                    crate::text::count(i.victims.len(), "account", "accounts"),
                    build_note(g, &i.weak_dcs)
                ),
                format!(
                    "{mapping_fix} Also remove the Active Directory security permissions (GenericAll, \
                     GenericWrite, WriteDacl, WriteOwner or ownership) that {who} hold on the {} that can \
                     enroll: with them, {who} can rewrite their {attribute}.",
                    crate::text::count(i.victims.len(), "account", "accounts")
                ),
            )
        }
        Esc::Esc13 => {
            let group = i.related.map(|r| g.node(r));
            let group_name = group.map(|n| n.name.clone()).unwrap_or_default();
            let severity = if group.is_some_and(|n| n.tier_zero) { Severity::Critical } else { Severity::High };
            (
                severity,
                format!("{label}: {t_name} on {ca_short} grants the access of {group_name}"),
                format!(
                    "{t_name} carries an issuance policy linked to {group_name} (msDS-OIDToGroupLink). Logging on \
                     with a certificate from it adds that group's SID to the logon token. {who} can enroll."
                ),
                format!(
                    "Remove the group link (msDS-OIDToGroupLink) from the issuance policy, or restrict the \
                     certificate template permission Enroll on {t_short} to accounts that should have the access \
                     of the group {group_name}. Certificates it already issued still carry the policy: revoke \
                     those held by accounts that shouldn't have it."
                ),
            )
        }
    };

    // Abuse that hinges on a DC setting the collector could not read is shown,
    // but as hygiene with no attack path until the setting is confirmed.
    let verified = !i.targets.is_empty() || i.unverified.is_empty();
    let (severity, title, summary) = if verified {
        (severity, title, summary)
    } else {
        let setting = match i.esc {
            Esc::Esc6b | Esc::Esc10a | Esc::Esc10b => "Schannel CertificateMappingMethods",
            _ => "Kdc StrongCertificateBindingEnforcement",
        };
        (
            Severity::Medium,
            format!("{title} (unverified)"),
            format!(
                "{summary} Whether domain controllers allow this could not be verified: the collector could \
                 not read {setting} on them, or it is not set and the DC's patch level (from a current Tier \
                 Zero settings file) is unknown. \
                 Check it on every domain controller in {}: have their admins run \
                 Get-PathwardenTierZeroSettings.ps1 and load its files with the collection. If they enforce \
                 strong mapping, this finding closes itself.",
                names(g, &i.unverified)
            ),
        )
    };

    let mut key = vec![m.family.to_string(), ca.id.clone()];
    key.extend(i.template.map(|t| g.node(t).id.clone()));
    key.extend(i.related.map(|r| g.node(r).id.clone()));
    let key: Vec<&str> = key.iter().map(String::as_str).collect();

    let path = i.esc.edge().and_then(|kind| {
        let src = *who_ix.first()?;
        let dst = *i.targets.first()?;
        let e = g
            .inner()
            .edges_connecting(src, dst)
            .find(|e| *e.weight() == kind)?;
        Some(ctx.edge_path(src, petgraph::visit::EdgeRef::id(&e)))
    });
    let affected = i
        .template
        .into_iter()
        .chain([i.ca])
        .chain(i.related)
        .chain(m.covers.iter().copied())
        .chain(who_ix.iter().copied());
    let refs: &[&'static str] = match i.esc {
        Esc::Esc9a | Esc::Esc9b | Esc::Esc10a | Esc::Esc10b => {
            &[CERTIFIED_PRE_OWNED, MS_CERT_BINDING]
        }
        Esc::Esc11 => &[RPC_RELAY, MS_ADCS_HARDENING],
        _ => &[CERTIFIED_PRE_OWNED, MS_ADCS_HARDENING],
    };
    let f = Finding::new(rule, severity, &key, title)
        .domain(ca.domain.as_ref())
        .summary(summary)
        .remediation(remediation)
        .affect(
            g,
            affected.chain(i.targets.iter().chain(&i.unverified).copied()),
        );
    if !verified {
        return Some(f.refs(refs));
    }
    let f = f
        .entry_principals_or_everyone(&who_ix, relay)
        .hits(i.targets.iter().copied().filter(|&t| g.node(t).tier_zero))
        .path(path)
        .refs(refs);
    // Abuse that ends in Tier Zero (the domain, or a Tier Zero group for
    // ESC13) is a domain compromise however few accounts can start it.
    Some(if i.targets.iter().any(|&t| g.node(t).tier_zero) {
        f.floor(Severity::High)
    } else {
        f
    })
}
