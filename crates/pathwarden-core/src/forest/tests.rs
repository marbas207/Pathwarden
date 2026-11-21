use super::*;
use crate::{load, LoadOptions};
use std::path::PathBuf;

fn fixture() -> (AdGraph, IngestStats) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    load(&[dir], &LoadOptions::default()).unwrap()
}

fn map_of(g: &AdGraph, stats: &IngestStats) -> ForestMap {
    // No logon times: every enabled account counts as active.
    forest_map(g, stats, &Relevance::new(g, 0, 90))
}

/// A graph and trust records built by hand, for exact counts.
#[derive(Default)]
struct Data {
    g: AdGraph,
    stats: IngestStats,
}

impl Data {
    /// A collected domain.
    fn domain(&mut self, sid: &str, name: &str) -> NodeIndex {
        let ix = self.g.ensure(sid, NodeKind::Domain);
        let n = self.g.node_mut(ix);
        n.name = name.into();
        n.domain = Some(name.into());
        n.placeholder = false;
        ix
    }

    /// A domain known only from a trust.
    fn trusted(&mut self, sid: &str, name: &str) -> NodeIndex {
        let ix = self.g.ensure(sid, NodeKind::Domain);
        self.g.node_mut(ix).name = name.into();
        ix
    }

    fn same_forest(&mut self, a: NodeIndex, b: NodeIndex) {
        self.g.add_edge(a, b, EdgeKind::SameForestTrust);
        self.g.add_edge(b, a, EdgeKind::SameForestTrust);
    }

    /// A collected object of the domain with SID `dom`, RID `rid`.
    fn obj(&mut self, dom: NodeIndex, rid: u32, kind: NodeKind, tier_zero: bool) -> NodeIndex {
        let (dsid, dname) = {
            let d = self.g.node(dom);
            (d.id.clone(), d.name.clone())
        };
        let ix = self.g.ensure(&format!("{dsid}-{rid}"), kind);
        let n = self.g.node_mut(ix);
        n.name = format!("{kind:?}{rid}@{dname}").to_ascii_uppercase();
        n.domain = Some(dname);
        n.domain_sid = Some(dsid);
        n.placeholder = false;
        n.tier_zero = tier_zero;
        ix
    }

    fn edge(&mut self, a: NodeIndex, b: NodeIndex, kind: EdgeKind) {
        self.g.add_edge(a, b, kind);
    }

    /// `source`'s record of its trust of `target`.
    fn record(&mut self, source: NodeIndex, target: NodeIndex, kind: &str, direction: &str) {
        self.record_with(source, target, kind, direction, false, None);
    }

    fn record_with(
        &mut self,
        source: NodeIndex,
        target: NodeIndex,
        kind: &str,
        direction: &str,
        sid_filtering: bool,
        attrs: Option<u64>,
    ) {
        let (s, t) = (self.g.node(source), self.g.node(target));
        self.stats.trusts.push(TrustInfo {
            source: s.name.clone(),
            target: t.name.clone(),
            trust_type: kind.into(),
            direction: direction.into(),
            transitive: true,
            sid_filtering,
            selective_auth: attrs.map(|a| a & 0x10 != 0),
            source_sid: s.id.clone(),
            target_sid: t.id.clone(),
            trust_attributes: attrs,
        });
    }

    fn map(&self) -> ForestMap {
        map_of(&self.g, &self.stats)
    }
}

const A: &str = "S-1-5-21-1-1-1";
const B: &str = "S-1-5-21-2-2-2";
const C: &str = "S-1-5-21-3-3-3";
const D: &str = "S-1-5-21-4-4-4";

fn crossing(t: &TrustEdge) -> Vec<(&str, &str, [usize; 4])> {
    t.crossing
        .iter()
        .map(|c| {
            (
                c.from.as_str(),
                c.to.as_str(),
                [c.memberships, c.admin_rights, c.aces, c.sid_history],
            )
        })
        .collect()
}

/// CONTOSO.LOCAL and its child are one forest; FABRIKAM.COM, known only
/// from CONTOSO's external trust, is another, whose shape is unknown.
#[test]
fn domains_group_into_forests() {
    let (g, stats) = fixture();
    let m = map_of(&g, &stats);
    let names: Vec<(&str, usize, bool, DomainRole)> = m
        .domains
        .iter()
        .map(|d| (d.name.as_str(), d.forest, d.collected, d.role))
        .collect();
    assert_eq!(
        names,
        [
            ("CONTOSO.LOCAL", 0, true, DomainRole::ForestRoot),
            ("CHILD.CONTOSO.LOCAL", 0, true, DomainRole::Child),
            ("FABRIKAM.COM", 1, false, DomainRole::Unknown),
        ]
    );
    assert_eq!(m.forests[0].name, "CONTOSO.LOCAL");
    assert_eq!(
        m.forests[0].domains,
        ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"]
    );
    let fabrikam = m.domain("fabrikam.com").unwrap();
    assert_eq!(fabrikam.exposure_percent, None);
    assert_eq!((fabrikam.users, fabrikam.tier_zero), (0, 0));
    assert!(m.domain("CONTOSO.LOCAL").unwrap().users > 0);
}

/// Three trust records, two trusts: the parent-child trust is recorded by
/// both domains; CONTOSO trusts FABRIKAM one way without filtering SIDs.
#[test]
fn each_trust_once_with_its_flags() {
    let (g, stats) = fixture();
    let m = map_of(&g, &stats);
    assert_eq!(m.trusts.len(), 2);
    let pc = &m.trusts[0];
    assert_eq!(
        (pc.trust_type.as_str(), pc.direction.as_str()),
        ("ParentChild", "Bidirectional")
    );
    assert_eq!(pc.records.len(), 2);
    assert!(pc.intra_forest && pc.enables_forest_takeover && !pc.records_disagree);
    assert!(!pc.abusable_sid_history && pc.findings.is_empty());

    let ext = &m.trusts[1];
    assert_eq!(
        (
            ext.source.as_str(),
            ext.target.as_str(),
            ext.direction.as_str()
        ),
        ("CONTOSO.LOCAL", "FABRIKAM.COM", "Outbound")
    );
    assert_eq!(ext.ways.len(), 1);
    let way = &ext.ways[0];
    assert_eq!(
        (way.from.as_str(), way.to.as_str()),
        ("FABRIKAM.COM", "CONTOSO.LOCAL")
    );
    assert_eq!(way.sid_filtering, Some(false));
    // An external trust not quarantined still filters RIDs under 1000.
    assert!(way.sid_history_abuse && way.rid_1000_and_up);
    assert!(ext.abusable_sid_history && !ext.enables_forest_takeover);
    assert_eq!(
        ext.findings,
        [crate::findings::fingerprint(
            "PW-012",
            &["CONTOSO.LOCAL", "FABRIKAM.COM"]
        )]
    );
    assert_eq!(ext.selective_auth, None);
}

/// What crosses each trust, each way: memberships, admin rights and ACEs,
/// counted once. Tier Zero's rights inside its own forest are wiring and
/// left out; across forests they count. Pairs no trust joins go to the
/// trust between their forests, or to `indirect`.
#[test]
fn crossings_by_direction() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let c = x.domain(C, "C.A.LOCAL");
    let d = x.domain(D, "D.A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.same_forest(a, c);
    x.same_forest(a, d);
    for (s, t, kind) in [
        (a, c, "ParentChild"),
        (c, a, "ParentChild"),
        (a, d, "ParentChild"),
        (d, a, "ParentChild"),
        (a, b, "Forest"),
        (b, a, "Forest"),
    ] {
        x.record(s, t, kind, "Bidirectional");
    }
    let (ga, ca, ua) = (
        x.obj(a, 1101, NodeKind::Group, false),
        x.obj(a, 1102, NodeKind::Computer, false),
        x.obj(a, 1103, NodeKind::User, false),
    );
    let (cu, ct0) = (
        x.obj(c, 1101, NodeKind::User, false),
        x.obj(c, 1102, NodeKind::User, true),
    );
    let (bu, bt0) = (
        x.obj(b, 1101, NodeKind::User, false),
        x.obj(b, 1102, NodeKind::User, true),
    );
    let gd = x.obj(d, 1101, NodeKind::Group, false);
    let everyone = x.g.ensure("A.LOCAL-S-1-5-11", NodeKind::Group);
    for holder in [cu, ct0, bu, bt0] {
        x.edge(holder, ga, EdgeKind::MemberOf);
        x.edge(holder, ca, EdgeKind::AdminTo);
        x.edge(holder, ua, EdgeKind::GenericAll);
        x.edge(holder, everyone, EdgeKind::MemberOf);
    }
    // No trust joins C and B directly, nor C and D.
    x.edge(cu, bu, EdgeKind::WriteDacl);
    x.edge(cu, gd, EdgeKind::MemberOf);

    let m = x.map();
    let ac = m.trusts.iter().find(|t| t.target == "C.A.LOCAL").unwrap();
    assert_eq!(crossing(ac), [("C.A.LOCAL", "A.LOCAL", [1, 1, 1, 0])]);
    let ab = m.trusts.iter().find(|t| t.target == "B.LOCAL").unwrap();
    assert_eq!(
        crossing(ab),
        [
            ("B.LOCAL", "A.LOCAL", [2, 2, 2, 0]),
            ("C.A.LOCAL", "B.LOCAL", [0, 0, 1, 0]),
        ]
    );
    assert!(m
        .trusts
        .iter()
        .find(|t| t.target == "D.A.LOCAL")
        .unwrap()
        .crossing
        .is_empty());
    assert_eq!(
        m.indirect,
        [Crossing {
            from: "C.A.LOCAL".into(),
            to: "D.A.LOCAL".into(),
            memberships: 1,
            rights: vec![CrossingRight {
                from: format!("{C}-1101"),
                from_name: "USER1101@C.A.LOCAL".into(),
                to: format!("{D}-1101"),
                to_name: "GROUP1101@D.A.LOCAL".into(),
                kind: "MemberOf".into(),
            }],
            counts: "1 group membership".into(),
            ..Crossing::default()
        }]
    );

    // Each counted right is listed, memberships first, then admin rights
    // and ACEs; Tier Zero's wiring inside the forest is neither counted
    // nor listed.
    let listed = |c: &Crossing| -> Vec<(String, String, String)> {
        c.rights
            .iter()
            .map(|r| (r.from_name.clone(), r.kind.clone(), r.to_name.clone()))
            .collect()
    };
    let s = |x: &str| x.to_string();
    assert_eq!(
        listed(&ac.crossing[0]),
        [
            (
                s("USER1101@C.A.LOCAL"),
                s("MemberOf"),
                s("GROUP1101@A.LOCAL")
            ),
            (
                s("USER1101@C.A.LOCAL"),
                s("AdminTo"),
                s("COMPUTER1102@A.LOCAL")
            ),
            (
                s("USER1101@C.A.LOCAL"),
                s("GenericAll"),
                s("USER1103@A.LOCAL")
            ),
        ]
    );
    let b_into_a = &ab.crossing[0];
    assert_eq!(b_into_a.rights.len(), 6, "Tier Zero's count across forests");
    assert_eq!(
        b_into_a.counts_text(),
        "2 group memberships, 2 admin rights, 2 control ACEs"
    );
}

/// A crossing lists its first [`RIGHTS_LISTED`] rights and counts them all.
#[test]
fn rights_listed_are_capped() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.record(a, b, "External", "Bidirectional");
    x.record(b, a, "External", "Bidirectional");
    let target = x.obj(a, 1100, NodeKind::Group, false);
    for rid in 0..(RIGHTS_LISTED as u32 + 5) {
        let u = x.obj(b, 2000 + rid, NodeKind::User, false);
        x.edge(u, target, EdgeKind::MemberOf);
    }
    let m = x.map();
    let c = &m.trusts[0].crossing[0];
    assert_eq!(c.memberships, RIGHTS_LISTED + 5);
    assert_eq!(c.rights.len(), RIGHTS_LISTED);
    assert_eq!(c.rights[0].from_name, "USER2000@B.LOCAL");
}

/// The line above the map: counts, and what stands out, worst first;
/// forest takeover is on the trusts, not here.
#[test]
fn the_headline() {
    let (g, stats) = fixture();
    let h = map_of(&g, &stats).headline();
    assert_eq!(h.lead, "3 domains in 2 forests");
    assert_eq!(h.detail, "2 trusts, 1 between forests · 1 not collected");
    assert_eq!(
        h.status,
        [Status {
            kind: "abuse",
            text: "1 trust with SID history abuse".into()
        }]
    );

    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let c = x.domain(C, "C.A.LOCAL");
    x.same_forest(a, c);
    x.record(a, c, "ParentChild", "Bidirectional");
    x.record(c, a, "ParentChild", "Bidirectional");
    let h = x.map().headline();
    assert_eq!(h.lead, "2 domains in 1 forest");
    assert_eq!(h.detail, "1 trust, 0 between forests · all collected");
    assert_eq!(h.status[0].text, "No SID history abuse");

    // PW-012 on a forest trust's flag alone: unknown, not abuse.
    let b = x.domain(B, "B.LOCAL");
    x.record_with(a, b, "Forest", "Bidirectional", false, None);
    let m = x.map();
    let t = m.trusts.iter().find(|t| t.target == "B.LOCAL").unwrap();
    assert!(t.sid_filtering_unknown());
    // It says what the finding says: the flag can't tell; collect.
    assert_eq!(
        t.pw012_note.as_deref(),
        Some(format!("{PW012_FLAG_ALONE}; to know, {COLLECT_TRUST_ATTRIBUTES}").as_str())
    );
    assert_eq!(t.flags[0].text, "SID filtering unknown · PW-012");
    assert_eq!(
        m.headline().status,
        [Status {
            kind: "unknown",
            text: "1 trust: SID filtering unknown".into()
        }]
    );
    let doc = serde_json::to_value(m.document()).unwrap();
    assert_eq!(doc["headline"]["sid_filtering_unknown"], 1);
    assert_eq!(doc["domains"], serde_json::to_value(&m.domains).unwrap());
}

/// One way, seen from each end: one trust, named after the first record.
#[test]
fn a_one_way_trust_from_both_ends() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.record(a, b, "External", "Outbound");
    x.record(b, a, "External", "Inbound");
    let m = x.map();
    assert_eq!(m.trusts.len(), 1);
    let t = &m.trusts[0];
    assert_eq!(
        (t.source.as_str(), t.direction.as_str()),
        ("A.LOCAL", "Outbound")
    );
    assert!(!t.records_disagree);
    assert_eq!(t.ways.len(), 1);
    assert_eq!(
        (t.ways[0].from.as_str(), t.ways[0].to.as_str()),
        ("B.LOCAL", "A.LOCAL")
    );

    x.stats.trusts.reverse();
    let t = &x.map().trusts[0];
    assert_eq!(
        (t.source.as_str(), t.direction.as_str()),
        ("B.LOCAL", "Inbound")
    );
    assert_eq!(
        (t.ways[0].from.as_str(), t.ways[0].to.as_str()),
        ("B.LOCAL", "A.LOCAL")
    );
}

/// Each way's SID filtering is its trusting side's.
#[test]
fn sid_filtering_per_way() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.record_with(a, b, "External", "Bidirectional", true, None);
    x.record_with(b, a, "External", "Bidirectional", false, None);
    let t = &x.map().trusts[0];
    let ways: Vec<(&str, Option<bool>, bool)> = t
        .ways
        .iter()
        .map(|w| (w.to.as_str(), w.sid_filtering, w.sid_history_abuse))
        .collect();
    assert_eq!(
        ways,
        [
            ("B.LOCAL", Some(false), true),
            ("A.LOCAL", Some(true), false)
        ]
    );
    assert_eq!(t.sid_filtering, Some(false));
    assert!(t.abusable_sid_history);

    // Both filter.
    x.stats.trusts[1].sid_filtering = true;
    let t = &x.map().trusts[0];
    assert_eq!(t.sid_filtering, Some(true));
    assert!(!t.abusable_sid_history && t.findings.is_empty());
}

/// An inbound record says nothing about what its other side filters: the
/// way is unknown, not abusable, though PW-012 fires on the record.
#[test]
fn an_inbound_record_governs_nothing() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.trusted(B, "B.LOCAL");
    x.record(a, b, "External", "Inbound");
    let t = &x.map().trusts[0];
    assert_eq!(t.ways.len(), 1);
    assert_eq!(
        (t.ways[0].to.as_str(), t.ways[0].sid_filtering),
        ("B.LOCAL", None)
    );
    assert_eq!(t.sid_filtering, None);
    assert!(!t.abusable_sid_history);
    assert_eq!(t.findings.len(), 1, "PW-012 itself is unchanged");
}

/// A disabled trust is not used: no way, no takeover, no abuse.
#[test]
fn disabled_trusts_carry_nothing() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    let c = x.domain(C, "C.A.LOCAL");
    x.same_forest(a, c);
    x.record(a, b, "Forest", "Disabled");
    x.record(a, c, "ParentChild", "Disabled");
    let m = x.map();
    for t in &m.trusts {
        assert_eq!(t.direction, "Disabled");
        assert!(t.ways.is_empty());
        assert!(!t.enables_forest_takeover && !t.abusable_sid_history);
        assert_eq!((t.sid_filtering, t.selective_auth), (None, None));
    }
}

/// Two records that disagree are one trust, flagged; every way either
/// side records is kept.
#[test]
fn disagreeing_records_are_one_trust() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.record(a, b, "Forest", "Bidirectional");
    x.record(b, a, "Forest", "Inbound");
    let m = x.map();
    assert_eq!(m.trusts.len(), 1);
    assert!(m.trusts[0].records_disagree);
    assert_eq!(m.trusts[0].direction, "Bidirectional");
    // One side disabled.
    x.stats.trusts[1].direction = "Disabled".into();
    let m = x.map();
    assert_eq!(m.trusts.len(), 1);
    assert!(m.trusts[0].records_disagree);
}

/// Selective authentication: required only when every way requires it,
/// unknown when a trusting side is missing.
#[test]
fn selective_auth_per_way() {
    let selective = |a_attrs, b_attrs: Option<u64>| {
        let mut x = Data::default();
        let a = x.domain(A, "A.LOCAL");
        let b = x.domain(B, "B.LOCAL");
        x.record_with(a, b, "Forest", "Bidirectional", true, a_attrs);
        if let Some(attrs) = b_attrs {
            x.record_with(b, a, "Forest", "Bidirectional", true, Some(attrs));
        }
        x.map().trusts[0].selective_auth
    };
    assert_eq!(selective(Some(0x18), Some(0x18)), Some(true));
    assert_eq!(selective(Some(0x18), Some(0x8)), Some(false));
    assert_eq!(selective(Some(0x8), Some(0x18)), Some(false));
    assert_eq!(selective(Some(0x18), None), None, "B's side unknown");
    assert_eq!(selective(None, Some(0x18)), None);
}

/// Across any trust between forests the built-in privileged groups never
/// pass (MS-PAC 4.1.2.2): SID history enabled (TREAT_AS_EXTERNAL), or an
/// external trust not quarantined, lets RIDs of 1000 and above through;
/// without the attributes, a forest trust's flag can't tell, so it is
/// unknown. A forest trust without TREAT_AS_EXTERNAL filters.
#[test]
fn what_sid_history_can_carry() {
    let way = |kind: &str, filtering: bool, attrs: Option<u64>| {
        let mut x = Data::default();
        let a = x.domain(A, "A.LOCAL");
        let b = x.trusted(B, "B.LOCAL");
        x.record_with(a, b, kind, "Outbound", filtering, attrs);
        let w = x.map().trusts[0].ways[0].clone();
        (w.sid_history_abuse, w.rid_1000_and_up, w.attributes_known)
    };
    assert_eq!(way("Forest", false, Some(0x48)), (true, true, true));
    assert_eq!(way("Forest", false, None), (false, false, false), "unknown");
    assert_eq!(way("External", false, Some(0x0)), (true, true, true));
    assert_eq!(way("External", false, None), (true, true, false));
    // A forest trust's own attributes decide, not the collector's flag.
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.trusted(B, "B.LOCAL");
    x.record_with(a, b, "Forest", "Outbound", true, Some(0x8));
    assert!(!x.map().trusts[0].ways[0].sid_history_abuse);
}

/// Trusted domains with no name are named by their SIDs and stay apart.
#[test]
fn nameless_domains_stay_apart() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.trusted(B, "");
    let c = x.trusted(C, " ");
    x.record(a, b, "External", "Outbound");
    x.record(a, c, "External", "Outbound");
    let m = x.map();
    assert_eq!(m.trusts.len(), 2);
    assert_eq!(m.forests.len(), 3);
    assert!(m.domain(B).is_some() && m.domain(C).is_some());
    let targets: Vec<&str> = m.trusts.iter().map(|t| t.target.as_str()).collect();
    assert_eq!(targets, [B, C]);
}

/// A trust recorded before its domain's own file was read names the domain
/// by its SID; the map names it as the domain is named.
#[test]
fn trust_ends_are_named_as_their_domains() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    // As ingest leaves a domain without a name: named by its SID.
    let b = x.trusted(B, B);
    x.record(a, b, "Forest", "Bidirectional");
    x.domain(B, "B.LOCAL");
    let m = x.map();
    let t = &m.trusts[0];
    assert_eq!(t.records[0].target, B);
    assert_eq!(t.target, "B.LOCAL");
    assert!(t.ways.iter().all(|w| w.from != B && w.to != B));
    assert_eq!(m.domain("B.LOCAL").unwrap().role, DomainRole::ForestRoot);
}

/// A domain without accounts has no exposure, rather than 0%.
#[test]
fn no_accounts_no_exposure() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    x.obj(a, 1101, NodeKind::Group, false);
    x.obj(a, 1102, NodeKind::User, true);
    let d = &x.map().domains[0];
    assert_eq!(
        (d.population, d.relevant_population, d.exposure_percent),
        (0, 0, None)
    );
    x.obj(a, 1103, NodeKind::User, false);
    let d = &x.map().domains[0];
    assert_eq!(
        (d.population, d.relevant_population, d.exposure_percent),
        (1, 1, Some(0.0))
    );
}

/// The forest root is the domain of Enterprise Admins, though another
/// domain of the forest is also a tree root by DNS (SharpHound records
/// tree-root trusts as ParentChild); without it, the DNS rule.
#[test]
fn forest_root_holds_enterprise_admins() {
    let mut x = Data::default();
    let ghost = x.domain(A, "GHOST.CORP");
    let phantom = x.domain(B, "PHANTOM.CORP");
    let child = x.domain(C, "CHILD.PHANTOM.CORP");
    x.same_forest(ghost, phantom);
    x.same_forest(phantom, child);
    let roles = |x: &Data| {
        let m = x.map();
        let r: Vec<(String, DomainRole)> =
            m.domains.iter().map(|d| (d.name.clone(), d.role)).collect();
        (m.forests[0].name.clone(), r)
    };
    let (name, r) = roles(&x);
    assert_eq!(
        name, "GHOST.CORP",
        "first by name without Enterprise Admins"
    );
    assert_eq!(r[0], ("GHOST.CORP".into(), DomainRole::ForestRoot));

    x.obj(phantom, 519, NodeKind::Group, true);
    let (name, r) = roles(&x);
    assert_eq!(name, "PHANTOM.CORP");
    assert_eq!(
        r,
        [
            ("PHANTOM.CORP".into(), DomainRole::ForestRoot),
            ("GHOST.CORP".into(), DomainRole::TreeRoot),
            ("CHILD.PHANTOM.CORP".into(), DomainRole::Child),
        ]
    );
}

/// The JSON shape round-trips, as a saved run stores it.
#[test]
fn round_trips_as_json() {
    let (g, stats) = fixture();
    let m = map_of(&g, &stats);
    let back: ForestMap = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    assert_eq!(back, m);
}

/// GOAD collected by RustHound-CE, with trust attributes: SEVENKINGDOMS
/// enabled SID history for ESSOS (0x48), ESSOS did not for SEVENKINGDOMS
/// (0x8). Only ESSOS into SEVENKINGDOMS can carry forged SID history.
#[test]
fn rusthound_goad_one_way_abusable() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rusthound");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let m = map_of(&g, &stats);
    let t = m.trusts.iter().find(|t| t.trust_type == "Forest").unwrap();
    let mut ways: Vec<(&str, Option<bool>, bool, bool)> = t
        .ways
        .iter()
        .map(|w| {
            (
                w.to.as_str(),
                w.sid_filtering,
                w.sid_history_abuse,
                w.rid_1000_and_up,
            )
        })
        .collect();
    ways.sort();
    assert_eq!(
        ways,
        [
            ("ESSOS.LOCAL", Some(true), false, false),
            ("SEVENKINGDOMS.LOCAL", Some(false), true, true),
        ]
    );
    assert!(t.ways.iter().all(|w| w.attributes_known));
}

/// A crossing with more memberships than the cap still lists its other
/// kinds: the cap is shared out between them in turn.
#[test]
fn the_cap_lists_every_kind() {
    let mut x = Data::default();
    let a = x.domain(A, "A.LOCAL");
    let b = x.domain(B, "B.LOCAL");
    x.record(a, b, "External", "Bidirectional");
    x.record(b, a, "External", "Bidirectional");
    let group = x.obj(a, 1100, NodeKind::Group, false);
    let computer = x.obj(a, 1101, NodeKind::Computer, false);
    let user = x.obj(a, 1102, NodeKind::User, false);
    for rid in 0..(RIGHTS_LISTED as u32 * 2) {
        let u = x.obj(b, 2000 + rid, NodeKind::User, false);
        x.edge(u, group, EdgeKind::MemberOf);
        if rid < 3 {
            x.edge(u, computer, EdgeKind::AdminTo);
        }
        if rid < 40 {
            x.edge(u, user, EdgeKind::GenericAll);
        }
    }
    let m = x.map();
    let c = &m.trusts[0].crossing[0];
    assert_eq!((c.memberships, c.admin_rights, c.aces), (200, 3, 40));
    assert_eq!(c.rights.len(), RIGHTS_LISTED);
    let of = |k: &str| c.rights.iter().filter(|r| r.kind == k).count();
    // Admin rights all (3); the rest shared between the two big kinds.
    assert_eq!(of("AdminTo"), 3);
    assert_eq!(of("GenericAll"), 40);
    assert_eq!(of("MemberOf"), RIGHTS_LISTED - 43);
    // Still in kind order: memberships, admin rights, ACEs.
    let kinds: Vec<&str> = c.rights.iter().map(|r| r.kind.as_str()).collect();
    let first = |k: &str| kinds.iter().position(|x| *x == k).unwrap();
    assert!(first("MemberOf") < first("AdminTo") && first("AdminTo") < first("GenericAll"));
}

/// The words every view shows come from the map: roles, attack paths,
/// each way, flags and notes.
#[test]
fn the_map_says_it_in_words() {
    let (g, stats) = fixture();
    let m = map_of(&g, &stats);
    let contoso = m.domain("CONTOSO.LOCAL").unwrap();
    assert_eq!(contoso.role_text, "forest root");
    let p = contoso.paths.as_ref().unwrap();
    assert!(p.count.ends_with("active accounts"), "{p:?}");
    assert_eq!(p.tail, "have an attack path to Tier Zero");
    let fabrikam = m.domain("FABRIKAM.COM").unwrap();
    assert_eq!(fabrikam.note.as_deref(), Some(NOT_COLLECTED));
    assert!(fabrikam.paths.is_none());

    let pc = &m.trusts[0];
    assert_eq!(pc.flags[0].kind, "takeover");
    assert_eq!(pc.crossing_note.as_deref(), Some(TIER_ZERO_NOT_LISTED));
    assert_eq!(pc.way_word, "two-way");
    let ext = &m.trusts[1];
    assert_eq!(ext.flags[0].kind, "abuse");
    assert!(ext.flags[0].is_tag());
    let w = &ext.ways[0];
    assert_eq!(w.filtering, "SID filtering off");
    assert_eq!(w.filtering_note.as_deref(), Some(FLAG_ONLY));
    assert_eq!(w.selective, "selective authentication not in the data");
    let abuse = w.abuse_text.as_deref().unwrap();
    assert!(
        abuse.starts_with("whoever controls FABRIKAM.COM"),
        "{abuse}"
    );
    // An external trust not quarantined still filters RIDs under 1000
    // (MS-PAC 4.1.2.2): the text must not say privileged groups pass.
    assert!(!abuse.contains("privileged groups included"), "{abuse}");
    assert!(
        abuse.contains("for accounts with RID 1000 and above"),
        "{abuse}"
    );
    assert!(!definition("sidhist").contains("does not filter SIDs"));
    assert_eq!(m.focus(), Some(1), "the abusable trust first");

    // The definitions name what the view says.
    assert!(definition("sidhist").contains(NOT_A_PATH_STEP));
    assert!(definition("not_collected").starts_with(NOT_COLLECTED));
    for key in [
        "attack",
        "takeover",
        "forest",
        "inside",
        "between",
        "between_abuse",
        "way_in",
        "unknown",
        "ways",
        "crossing",
    ] {
        assert!(!definition(key).is_empty(), "{key}");
    }
}

/// A map saved before crossings listed their rights, or before its words
/// existed, still reads; its document fills the words in.
#[test]
fn a_map_saved_before_reads_and_gets_its_words() {
    let (g, stats) = fixture();
    let m = map_of(&g, &stats);
    let mut v = serde_json::to_value(&m).unwrap();
    // As saved then: no word fields, no rights.
    for d in v["domains"].as_array_mut().unwrap() {
        let o = d.as_object_mut().unwrap();
        for k in ["role_text", "paths", "note"] {
            o.remove(k);
        }
    }
    for t in v["trusts"].as_array_mut().unwrap() {
        let o = t.as_object_mut().unwrap();
        for k in ["flags", "pw012_note", "crossing_note", "way_word"] {
            o.remove(k);
        }
        for w in o["ways"].as_array_mut().unwrap() {
            let w = w.as_object_mut().unwrap();
            for k in ["filtering", "filtering_note", "selective", "abuse_text"] {
                w.remove(k);
            }
        }
        for c in o["crossing"].as_array_mut().unwrap() {
            let c = c.as_object_mut().unwrap();
            c.remove("rights");
            c.remove("counts");
        }
    }
    let old: ForestMap = serde_json::from_value(v).unwrap();
    assert!(old.trusts[0].flags.is_empty());
    let doc = old.document();
    assert_eq!(doc.map, m, "the document fills in what the map would say");
}
