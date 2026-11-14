//! The forest map on GOAD (SEVENKINGDOMS.LOCAL with its child
//! NORTH.SEVENKINGDOMS.LOCAL, and ESSOS.LOCAL in a forest of its own):
//! four trust records are two trusts, each with its flag.
//!
//! The GOAD capture is git-ignored (`data/goad`, or the folder in
//! `PATHWARDEN_GOAD`); without it the test skips (prints why and passes).

use std::path::PathBuf;

use pathwarden_core::config::Config;
use pathwarden_core::forest::DomainRole;

fn goad_dir() -> PathBuf {
    std::env::var_os("PATHWARDEN_GOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/goad"))
}

#[test]
fn goad_is_two_forests_and_two_trusts() {
    let dir = goad_dir();
    if !dir.exists() {
        eprintln!(
            "skipping the GOAD forest map: {} not present (the GOAD capture is git-ignored)",
            dir.display()
        );
        return;
    }
    let a = pathwarden_core::analyze::run(&[dir], &Config::default(), &[], &mut |_| {}).unwrap();
    assert_eq!(a.stats.trusts.len(), 4);
    let m = a.forest_map();

    let domains: Vec<(&str, usize, bool, DomainRole)> = m
        .domains
        .iter()
        .map(|d| (d.name.as_str(), d.forest, d.collected, d.role))
        .collect();
    assert_eq!(
        domains,
        [
            ("ESSOS.LOCAL", 0, true, DomainRole::ForestRoot),
            ("SEVENKINGDOMS.LOCAL", 1, true, DomainRole::ForestRoot),
            ("NORTH.SEVENKINGDOMS.LOCAL", 1, true, DomainRole::Child),
        ]
    );
    let forests: Vec<&str> = m.forests.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(forests, ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]);

    assert_eq!(m.trusts.len(), 2);
    let (pc, forest) = (&m.trusts[0], &m.trusts[1]);
    assert_eq!(pc.trust_type, "ParentChild");
    assert_eq!(forest.trust_type, "Forest");
    for t in [pc, forest] {
        assert_eq!(t.direction, "Bidirectional");
        assert_eq!(t.records.len(), 2, "recorded by both domains");
        assert!(t.transitive && !t.records_disagree);
        assert_eq!(t.ways.len(), 2);
        // SharpHound 2.3 gives no trust attributes.
        assert_eq!(t.selective_auth, None);
    }
    assert!(pc.intra_forest && pc.enables_forest_takeover && !pc.abusable_sid_history);
    assert!(!forest.intra_forest && !forest.enables_forest_takeover);
    // SharpHound 2.3 gives no trust attributes, and its flag can't tell a
    // forest trust's default filtering from SID history enabled: unknown,
    // not abuse, though PW-012 fires on both records.
    assert!(!forest.abusable_sid_history);
    assert_eq!(forest.sid_filtering, None);
    assert!(forest.ways.iter().all(|w| w.sid_filtering.is_none()
        && w.sid_filtering_unknown.is_some()
        && !w.sid_history_abuse
        && !w.attributes_known));

    // The flag names the PW-012 findings the analysis fired, one per side.
    let fired: Vec<&str> = a
        .findings
        .iter()
        .filter(|f| f.rule == "PW-012")
        .map(|f| f.fingerprint.as_str())
        .collect();
    assert_eq!(forest.findings.len(), 2);
    for fp in &forest.findings {
        assert!(fired.contains(&fp.as_str()), "{fp} not among {fired:?}");
    }
    // And those findings say what the map says: unknown, not "does
    // not filter SIDs".
    for f in a.findings.iter().filter(|f| f.rule == "PW-012") {
        assert!(
            f.title
                .ends_with(": SID filtering unknown (the collector's flag can't tell)"),
            "{}",
            f.title
        );
        assert_eq!(
            f.severity,
            pathwarden_core::findings::PW012_FLAG_ONLY_SEVERITY
        );
        assert!(f
            .summary
            .contains(pathwarden_core::forest::FOREST_FLAG_UNKNOWN));
        assert!(f
            .summary
            .contains(pathwarden_core::forest::COLLECT_TRUST_ATTRIBUTES));
    }

    // What crosses: inside the forest only Tier Zero's wiring, left out;
    // across it, DAENERYS (ESSOS's Domain Admin) in a SEVENKINGDOMS group
    // and two SEVENKINGDOMS principals in ESSOS groups.
    assert!(pc.crossing.is_empty(), "{:?}", pc.crossing);
    let crossing: Vec<(&str, &str, [usize; 4])> = forest
        .crossing
        .iter()
        .map(|c| {
            (
                c.from.as_str(),
                c.to.as_str(),
                [c.memberships, c.admin_rights, c.aces, c.sid_history],
            )
        })
        .collect();
    assert_eq!(
        crossing,
        [
            ("ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL", [1, 0, 0, 0]),
            ("SEVENKINGDOMS.LOCAL", "ESSOS.LOCAL", [2, 0, 0, 0]),
        ]
    );
    assert!(m.indirect.is_empty());
    // Each one is listed, by name.
    let essos_in = &forest.crossing[0].rights;
    assert_eq!(essos_in.len(), 1);
    assert_eq!(essos_in[0].kind, "MemberOf");
    assert!(
        essos_in[0].from_name.starts_with("DAENERYS"),
        "{essos_in:?}"
    );
    assert_eq!(forest.crossing[1].rights.len(), 2);

    let h = m.headline();
    assert_eq!(h.lead, "3 domains in 2 forests");
    assert_eq!(h.detail, "2 trusts, 1 between forests · all collected");
    assert_eq!(h.status[0].text, "1 trust: SID filtering unknown");

    // Per-domain exposure adds up to the Tier Zero headline (every GOAD
    // account's domain is known).
    let t0 = &a.posture.tier_zero;
    let exposed: usize = m.domains.iter().map(|d| d.exposed).sum();
    let relevant: usize = m.domains.iter().map(|d| d.relevant_population).sum();
    assert_eq!(exposed, t0.exposed);
    assert_eq!(relevant, t0.relevant_population);
}

/// SpecterOps' sample (git-ignored `data/specterops`, or the folder in
/// `PATHWARDEN_SPECTEROPS`): GHOST.CORP joins PHANTOM.CORP's forest as a
/// tree, though SharpHound records the trust as ParentChild; PHANTOM's
/// inbound record of REVENANT.CORP says nothing about what REVENANT
/// filters.
#[test]
fn specterops_roots_and_an_inbound_trust() {
    let dir = std::env::var_os("PATHWARDEN_SPECTEROPS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/specterops"));
    if !dir.exists() {
        eprintln!(
            "skipping the SpecterOps forest map: {} not present",
            dir.display()
        );
        return;
    }
    let a = pathwarden_core::analyze::run(&[dir], &Config::default(), &[], &mut |_| {}).unwrap();
    let m = a.forest_map();
    let phantom = m.domain("PHANTOM.CORP").unwrap();
    assert_eq!(phantom.role, DomainRole::ForestRoot);
    assert_eq!(m.forests[phantom.forest].name, "PHANTOM.CORP");
    assert_eq!(m.domain("GHOST.CORP").unwrap().role, DomainRole::TreeRoot);
    let revenant = m
        .trusts
        .iter()
        .find(|t| t.target == "REVENANT.CORP")
        .unwrap();
    assert_eq!(revenant.direction, "Inbound");
    assert_eq!(revenant.sid_filtering, None);
    assert!(!revenant.abusable_sid_history);
    assert_eq!(
        revenant.findings.len(),
        1,
        "PW-012 still fires on the record"
    );
    let role = m.domain("REVENANT.CORP").unwrap().role;
    assert_eq!(
        role,
        DomainRole::Unknown,
        "known only from an external trust"
    );
    // PW-012 fires on PHANTOM's inbound record, which can't say what
    // REVENANT filters: unknown, in the headline too.
    assert!(revenant.sid_filtering_unknown());
    let h = m.headline();
    assert_eq!(h.lead, "5 domains in 3 forests");
    assert_eq!(h.sid_history_abuse, 0);
    assert!(h.sid_filtering_unknown >= 1, "{h:?}");
    // Every crossing lists what it counts, up to the cap.
    for c in m.trusts.iter().flat_map(|t| &t.crossing).chain(&m.indirect) {
        let counted = c.memberships + c.admin_rights + c.aces + c.sid_history;
        assert_eq!(
            c.rights.len(),
            counted.min(pathwarden_core::forest::RIGHTS_LISTED)
        );
    }
}
