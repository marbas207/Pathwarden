//! The Tier Zero exposure denominator (basis 3): exposure % =
//! exposed / relevant, where both count only the *active* population
//! members (logged on within the stale window before the
//! collection time). Edges never decide who counts. These build small
//! synthetic graphs by hand (no lab data) so the counts are exact.

use std::collections::HashSet;

use pathwarden_core::analysis::{self, Relevance};
use pathwarden_core::findings::RuleSettings;
use pathwarden_core::model::{EdgeKind, Node, NodeKind};
use pathwarden_core::posture::{self, ExposureGrade, GradeInputs, PlanSummary};
use pathwarden_core::remediation;
use pathwarden_core::{AdGraph, NodeIndex};

/// 2026-10-08, the collection time of every graph here.
const NOW: i64 = 1_791_417_600;
/// The default stale window (PW-009).
const STALE: i64 = 90;
const DOMAIN: &str = "CORP.LOCAL";
const DOMAIN_USERS: &str = "S-1-5-21-1-2-3-513";

/// A collected (non-placeholder), enabled principal in `DOMAIN`.
fn node(g: &mut AdGraph, id: &str, kind: NodeKind) -> NodeIndex {
    node_in(g, id, kind, DOMAIN)
}

fn node_in(g: &mut AdGraph, id: &str, kind: NodeKind, domain: &str) -> NodeIndex {
    let mut n = Node::placeholder(id.to_string(), kind);
    n.placeholder = false;
    n.name = format!("{id}@{domain}");
    n.domain = Some(domain.to_string());
    g.upsert(n)
}

/// A principal that last logged on `days` days before the collection.
fn active(g: &mut AdGraph, id: &str, kind: NodeKind, days: i64) -> NodeIndex {
    let ix = node(g, id, kind);
    g.node_mut(ix).props.lastlogontimestamp = Some(NOW - days * 86_400);
    ix
}

/// A principal that never logged on (`0`, as collectors write it).
fn never(g: &mut AdGraph, id: &str, kind: NodeKind) -> NodeIndex {
    let ix = node(g, id, kind);
    g.node_mut(ix).props.lastlogontimestamp = Some(0);
    ix
}

/// A Tier Zero object.
fn tier_zero(g: &mut AdGraph, id: &str) -> NodeIndex {
    let ix = node(g, id, NodeKind::Group);
    g.node_mut(ix).tier_zero = true;
    ix
}

fn settings() -> RuleSettings {
    RuleSettings {
        now: NOW,
        stale_days: STALE,
        ..RuleSettings::default()
    }
}

fn t0_posture(g: &AdGraph) -> posture::ZonePosture {
    posture::compute(g, &[], &[], &settings()).tier_zero
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// A small domain: ALICE (active) and EVE (inactive, 200 days) reach Tier
/// Zero through a group; BOB and CAROL are active and reach nothing; DAVE
/// has a stale logon and no path.
fn base() -> AdGraph {
    let mut g = AdGraph::new();
    let da = tier_zero(&mut g, "DA");
    let admins = node(&mut g, "HELPDESK", NodeKind::Group);
    g.add_edge(admins, da, EdgeKind::GenericAll);
    let alice = active(&mut g, "ALICE", NodeKind::User, 2);
    g.add_edge(alice, admins, EdgeKind::MemberOf);
    let eve = active(&mut g, "EVE", NodeKind::User, 200);
    g.add_edge(eve, admins, EdgeKind::MemberOf);
    active(&mut g, "BOB", NodeKind::User, 10);
    active(&mut g, "CAROL", NodeKind::Computer, 1);
    active(&mut g, "DAVE", NodeKind::User, 400);
    g
}

#[test]
fn inactive_accounts_dont_count() {
    let g = base();
    let p = t0_posture(&g);
    assert_eq!(p.population, 5);
    // ALICE, BOB, CAROL are active; EVE (inactive, exposed) and DAVE
    // (inactive) don't count.
    assert_eq!(p.relevant_population, 3);
    assert_eq!(p.exposed, 1);
    assert!(close(p.exposure_percent, 100.0 / 3.0));
    let rel = Relevance::from_settings(&g, &settings());
    assert!(rel.activity_unknown_domains.is_empty());
    assert_eq!(rel.stale_days, STALE);
    // The shared function agrees with posture.
    assert_eq!(analysis::relevant_population_for(&g, &rel).len(), 3);
}

/// The window edge: a logon exactly `stale_days` ago is active (PW-009 calls
/// an account stale only past it); a day more is not.
#[test]
fn the_stale_window_is_pw009s() {
    let mut g = AdGraph::new();
    let _ = tier_zero(&mut g, "DA");
    let edge = active(&mut g, "EDGE", NodeKind::User, STALE);
    let past = active(&mut g, "PAST", NodeKind::User, STALE + 1);
    let rel = Relevance::from_settings(&g, &settings());
    assert!(rel.is_active(edge));
    assert!(!rel.is_active(past));
}

/// Onboarding objects nobody uses, objects in groups that grant nothing,
/// or computers holding sessions of non-exposed users must not move the
/// percentage (a review finding). Each is checked on its own.
#[test]
fn benign_inflation_does_not_move_exposure() {
    let before = t0_posture(&base());
    let check = |name: &str, g: &AdGraph| {
        let after = t0_posture(g);
        assert!(
            after.population > before.population,
            "{name}: nothing added"
        );
        assert_eq!(
            after.relevant_population, before.relevant_population,
            "{name}"
        );
        assert_eq!(after.exposed, before.exposed, "{name}");
        assert!(
            close(after.exposure_percent, before.exposure_percent),
            "{name}"
        );
        assert_eq!(after.exposure_grade, before.exposure_grade, "{name}");
    };

    // 50 never-logged-on users and 50 computers off for a year.
    let mut g = base();
    for i in 0..50 {
        never(&mut g, &format!("NEW{i}"), NodeKind::User);
        active(&mut g, &format!("OLDWS{i}"), NodeKind::Computer, 365);
    }
    check("inactive objects", &g);

    // 50 inactive users in a rightless group, and in Domain Users.
    let mut g = base();
    let rightless = node(&mut g, "PROJECT-X", NodeKind::Group);
    let du = node(&mut g, DOMAIN_USERS, NodeKind::Group);
    for i in 0..50 {
        let u = never(&mut g, &format!("MEMBER{i}"), NodeKind::User);
        g.add_edge(u, rightless, EdgeKind::MemberOf);
        g.add_edge(u, du, EdgeKind::MemberOf);
    }
    check("rightless groups", &g);

    // 50 inactive workstations holding a session of BOB (not exposed).
    let mut g = base();
    let bob = g.lookup("BOB").unwrap();
    for i in 0..50 {
        let ws = active(&mut g, &format!("WS{i}"), NodeKind::Computer, 120);
        g.add_edge(ws, bob, EdgeKind::HasSession);
    }
    check("sessions", &g);

    // A right handed to an inactive principal that leads nowhere.
    let mut g = base();
    let carol = g.lookup("CAROL").unwrap();
    for i in 0..50 {
        let u = never(&mut g, &format!("ADM{i}"), NodeKind::User);
        g.add_edge(u, carol, EdgeKind::AdminTo);
    }
    check("rights that lead nowhere", &g);
}

/// Hygiene neutrality: removing a right from an active principal that is not
/// exposed never changes the percentage (under the capability gate it could
/// raise it, from 50% to 100%).
#[test]
fn removing_a_right_from_a_non_exposed_principal_is_neutral() {
    let build = |with_right: bool| {
        let mut g = base();
        let bob = g.lookup("BOB").unwrap();
        let carol = g.lookup("CAROL").unwrap();
        if with_right {
            g.add_edge(bob, carol, EdgeKind::AdminTo);
        }
        g
    };
    let with = t0_posture(&build(true));
    let without = t0_posture(&build(false));
    assert_eq!(with.relevant_population, without.relevant_population);
    assert!(close(with.exposure_percent, without.exposure_percent));
}

/// `exposed ⊆ relevant` and the percentage stays within 0–100% on many
/// random graphs, for Tier Zero and for a zone; and a principal exposed only
/// through a default group still counts.
#[test]
fn exposed_is_a_subset_of_relevant() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let kinds = [
        EdgeKind::MemberOf,
        EdgeKind::AdminTo,
        EdgeKind::HasSession,
        EdgeKind::GenericAll,
        EdgeKind::GenericWrite,
    ];
    for round in 0..200 {
        let mut g = AdGraph::new();
        let mut ixs = vec![tier_zero(&mut g, "DA")];
        for i in 0..12 {
            let kind = if next(2) == 0 {
                NodeKind::User
            } else {
                NodeKind::Computer
            };
            let ix = node(&mut g, &format!("P{i}"), kind);
            g.node_mut(ix).props.lastlogontimestamp = match next(4) {
                0 => None,
                1 => Some(0),
                2 => Some(NOW - 5 * 86_400),
                _ => Some(NOW - 300 * 86_400),
            };
            ixs.push(ix);
        }
        let grp = node(&mut g, "G", NodeKind::Group);
        ixs.push(grp);
        for _ in 0..20 {
            let (a, b) = (
                ixs[next(ixs.len() as u64) as usize],
                ixs[next(ixs.len() as u64) as usize],
            );
            if a != b {
                g.add_edge(a, b, kinds[next(kinds.len() as u64) as usize]);
            }
        }
        let p = posture::compute(&g, &[], &[], &settings());
        let t0 = &p.tier_zero;
        assert!(t0.exposed <= t0.relevant_population, "round {round}");
        assert!(t0.relevant_population <= t0.population, "round {round}");
        assert!(
            (0.0..=100.0).contains(&t0.exposure_percent),
            "round {round}"
        );
    }

    // Exposed only through Domain Users, never logged on: inactive, so not
    // counted.
    let mut g = AdGraph::new();
    let da = tier_zero(&mut g, "DA");
    let du = node(&mut g, DOMAIN_USERS, NodeKind::Group);
    g.add_edge(du, da, EdgeKind::GenericAll);
    let u = never(&mut g, "USER", NodeKind::User);
    g.add_edge(u, du, EdgeKind::MemberOf);
    active(&mut g, "OTHER", NodeKind::User, 1);
    let p = t0_posture(&g);
    assert_eq!((p.exposed, p.relevant_population), (0, 1));
    assert!(close(p.exposure_percent, 0.0));
}

/// A domain whose data has no logon times can't tell activity: every enabled
/// member of it counts, and it is named. Decided per domain: a domain next
/// to it that has logon times keeps the active basis.
#[test]
fn domains_without_logon_times_count_every_enabled_account() {
    let mut g = base();
    for i in 0..4 {
        node_in(&mut g, &format!("N{i}"), NodeKind::User, "NOLOGON.LOCAL");
    }
    let rel = Relevance::from_settings(&g, &settings());
    assert_eq!(rel.activity_unknown_domains, ["NOLOGON.LOCAL"]);
    let p = posture::compute(&g, &[], &[], &settings());
    // CORP.LOCAL: its 3 active; NOLOGON.LOCAL: all 4.
    assert_eq!(p.tier_zero.relevant_population, 7);
    assert_eq!(p.activity_unknown_domains, ["NOLOGON.LOCAL"]);
    assert_eq!(p.exposure_basis, analysis::EXPOSURE_BASIS);
    // `pathwarden exposure` uses the same basis per domain.
    let r = analysis::exposure(&g, 0, &rel);
    assert_eq!(r.per_domain["NOLOGON.LOCAL"].users_total, 4);
    assert_eq!(r.per_domain["CORP.LOCAL"].relevant(), 3);
    assert_eq!(r.total.relevant(), p.tier_zero.relevant_population);
    assert_eq!(r.total.exposed(), p.tier_zero.exposed);
    assert_eq!(r.activity_unknown_domains, ["NOLOGON.LOCAL"]);
}

/// Logon times are decided per kind. Users with logon times and
/// computers with none: the computers' activity can't be told, so they all
/// count, rather than all counting as inactive. The users keep the active
/// basis, and the domain isn't listed: its users' activity is known.
#[test]
fn computers_without_logon_times_are_not_all_inactive() {
    let mut g = AdGraph::new();
    active(&mut g, "ALICE", NodeKind::User, 2);
    active(&mut g, "DAVE", NodeKind::User, 400);
    never(&mut g, "NEW", NodeKind::User);
    let ws: Vec<_> = (0..3)
        .map(|i| node(&mut g, &format!("WS{i}"), NodeKind::Computer))
        .collect();
    let rel = Relevance::from_settings(&g, &settings());
    assert!(ws.iter().all(|&ix| rel.is_active(ix)));
    assert!(rel.activity_unknown_domains.is_empty());
    let p = t0_posture(&g);
    // ALICE and the three computers; DAVE is stale, NEW never logged on.
    assert_eq!((p.population, p.relevant_population), (6, 4));

    // Computers with logon times keep theirs: one stale, one active.
    let stale = active(&mut g, "OLD", NodeKind::Computer, 300);
    let recent = active(&mut g, "SRV", NodeKind::Computer, 5);
    for &ix in &ws[1..] {
        g.node_mut(ix).props.lastlogontimestamp = Some(-1);
    }
    let rel = Relevance::from_settings(&g, &settings());
    assert!(rel.is_active(recent) && !rel.is_active(stale));
    // WS0 has no logon time where most computers have one: never logged on.
    assert!(ws.iter().all(|&ix| !rel.is_active(ix)));

    // And the other way round: computers with logon times, users with none.
    let mut g = AdGraph::new();
    let u = node(&mut g, "BOB", NodeKind::User);
    let c = active(&mut g, "OLD", NodeKind::Computer, 300);
    let rel = Relevance::from_settings(&g, &settings());
    assert!(rel.is_active(u) && !rel.is_active(c));
    assert!(rel.activity_unknown_domains.is_empty());
}

/// A graph where three paths reach Tier Zero; `skip` leaves edges out, so a
/// "fixed" graph can be built fresh.
fn plan_graph(skip: &HashSet<(String, EdgeKind, String)>) -> AdGraph {
    let mut g = AdGraph::new();
    let edge = |g: &mut AdGraph, a: NodeIndex, b: NodeIndex, k: EdgeKind| {
        let key = (g.node(a).name.clone(), k, g.node(b).name.clone());
        if !skip.contains(&key) {
            g.add_edge(a, b, k);
        }
    };
    // A Tier Zero user, so a session of it is a step.
    let da = node(&mut g, "ADMIN", NodeKind::User);
    g.node_mut(da).tier_zero = true;
    let srv = active(&mut g, "SRV", NodeKind::Computer, 1);
    let helpdesk = node(&mut g, "HELPDESK", NodeKind::Group);
    let ops = node(&mut g, "OPS", NodeKind::Group);
    edge(&mut g, srv, da, EdgeKind::HasSession);
    edge(&mut g, helpdesk, srv, EdgeKind::AdminTo);
    edge(&mut g, ops, da, EdgeKind::GenericWrite);
    for (i, days) in [1, 2, 200, 300].into_iter().enumerate() {
        let u = active(&mut g, &format!("HD{i}"), NodeKind::User, days);
        edge(&mut g, u, helpdesk, EdgeKind::MemberOf);
    }
    for (i, days) in [3, 500].into_iter().enumerate() {
        let u = active(&mut g, &format!("OP{i}"), NodeKind::User, days);
        edge(&mut g, u, ops, EdgeKind::MemberOf);
    }
    for i in 0..3 {
        active(&mut g, &format!("IDLE{i}"), NodeKind::User, 1000);
        active(&mut g, &format!("BUSY{i}"), NodeKind::User, 4);
    }
    g
}

/// M5: the plan's "after" is what a fresh run after applying its removals
/// reports, including the denominator, and the first step's own effect is a
/// fresh run after that step alone.
#[test]
fn plan_after_matches_a_fresh_run() {
    let g = plan_graph(&HashSet::new());
    let rel = Relevance::from_settings(&g, &settings());
    let plan = remediation::plan(&g, &rel);
    let before = t0_posture(&g);
    assert_eq!(plan.relevant_population, before.relevant_population);
    assert!(close(plan.exposure_before, before.exposure_percent));
    assert!(plan.exposed_before > 0 && !plan.fixes.is_empty());

    let removals = |fixes: &[remediation::PlannedFix]| -> HashSet<(String, EdgeKind, String)> {
        fixes
            .iter()
            .flat_map(|f| f.edges.iter().map(|&k| (f.from.clone(), k, f.to.clone())))
            .collect()
    };
    let fixed = t0_posture(&plan_graph(&removals(&plan.fixes)));
    assert_eq!(plan.exposed_after, fixed.exposed);
    assert_eq!(plan.relevant_population_after, fixed.relevant_population);
    assert!(
        close(plan.exposure_after, fixed.exposure_percent),
        "{} vs {}",
        plan.exposure_after,
        fixed.exposure_percent
    );
    // Only active accounts count, so fixes never move the denominator.
    assert_eq!(plan.relevant_population_after, plan.relevant_population);

    let first = t0_posture(&plan_graph(&removals(&plan.fixes[..1])));
    assert!(close(
        plan.first_fix_exposure_after.unwrap(),
        first.exposure_percent
    ));

    // Choke points: each row's "after" is a fresh run without that edge.
    for c in analysis::choke_points(&g, 10, &rel) {
        let skip: HashSet<_> = [(c.from.clone(), c.edge, c.to.clone())]
            .into_iter()
            .collect();
        let fresh = t0_posture(&plan_graph(&skip));
        assert_eq!(
            c.relevant_population_after, fresh.relevant_population,
            "{c:?}"
        );
        assert!(close(c.exposure_after, fresh.exposure_percent), "{c:?}");
        assert!(close(c.exposure_before, before.exposure_percent));
    }
}

/// The grade comes from paths and findings, not from a share: any path is
/// at least High however large the domain, a broad group's path or a
/// critical finding is Critical, and Low needs no path and nothing at medium
/// or above.
#[test]
fn grade_follows_paths_and_findings_not_the_share() {
    use ExposureGrade::*;
    let g = |exposed: usize, broad: &[&str], critical: usize, high_or_medium: usize| {
        let i = GradeInputs {
            exposed,
            broad_groups: broad.iter().map(|s| s.to_string()).collect(),
            critical,
            high_or_medium,
            ..GradeInputs::default()
        };
        (
            ExposureGrade::assess(&i),
            ExposureGrade::reason(&i, "Tier Zero"),
        )
    };
    // A 400,000-account domain with 509 ways in: 0.13%, and High.
    let (grade, why) = g(509, &[], 0, 108);
    assert_eq!(grade, High);
    assert_eq!(why, "509 accounts outside Tier Zero can reach it");
    assert_eq!(
        g(1, &[], 0, 0).1,
        "1 account outside Tier Zero can reach it"
    );
    let (grade, why) = g(509, &[], 2, 108);
    assert_eq!(grade, Critical);
    assert_eq!(why, "2 critical findings are open");
    let (grade, why) = g(3, &["DOMAIN USERS@CORP.LOCAL"], 1, 0);
    assert_eq!(grade, Critical);
    assert_eq!(
        why,
        "DOMAIN USERS@CORP.LOCAL, which holds nearly every account, can reach Tier Zero; 1 critical finding is open"
    );
    assert!(g(3, &["A", "B", "C"], 0, 0)
        .1
        .starts_with("A and 2 other groups that hold nearly every account"));
    // A critical finding with no path (a Kerberoastable Tier Zero account).
    assert_eq!(g(0, &[], 1, 0).0, Critical);
    let (grade, why) = g(0, &[], 0, 3);
    assert_eq!(grade, Moderate);
    assert_eq!(
        why,
        "No account outside Tier Zero can reach it; 3 findings at medium or above are open"
    );
    assert_eq!(g(0, &[], 0, 0).0, Low);
    for (grade, class) in [
        (Low, "low"),
        (Moderate, "medium"),
        (High, "high"),
        (Critical, "critical"),
    ] {
        assert_eq!(grade.css_class(), class);
    }
}

/// The line under the status says why, as what an attacker can do: a broad
/// group's path first, then weak accounts on a path (when they are what
/// made the grade), else the plain reason. It names the words to link.
#[test]
fn status_reason_says_what_an_attacker_can_do() {
    let reason = |i: GradeInputs| ExposureGrade::status_reason(&i, "Tier Zero");
    // Ten Kerberoastable Tier Zero accounts: they are the critical findings.
    let r = reason(GradeInputs {
        exposed: 8975,
        critical: 10,
        kerberoastable: 10,
        critical_roastable: 10,
        ..GradeInputs::default()
    });
    assert_eq!(
        r.text,
        "10 Kerberoastable service accounts are on a path to Tier Zero."
    );
    let link = r.link.unwrap();
    assert_eq!(
        (link.words.as_str(), link.rule.as_str()),
        ("10 Kerberoastable service accounts", "PW-006")
    );
    assert!(r.text.contains(&link.words));
    // Some of them are in Tier Zero themselves, or all of them.
    let in_zone = |n| {
        reason(GradeInputs {
            exposed: 8975,
            critical: 10,
            kerberoastable: 10,
            critical_roastable: 10,
            roastable_in_zone: n,
            ..GradeInputs::default()
        })
        .text
    };
    assert_eq!(
        in_zone(1),
        "10 Kerberoastable service accounts are in or on a path to Tier Zero."
    );
    assert_eq!(
        in_zone(10),
        "10 Kerberoastable service accounts are in Tier Zero."
    );
    // AS-REP roastable only: no credentials needed.
    let r = reason(GradeInputs {
        exposed: 4,
        asrep: 1,
        ..GradeInputs::default()
    });
    assert_eq!(
        r.text,
        "1 account without Kerberos pre-authentication is on a path to Tier Zero."
    );
    assert_eq!(r.link.unwrap().rule, "PW-007");
    // Both kinds: counted together, linked to the larger.
    let r = reason(GradeInputs {
        exposed: 4,
        kerberoastable: 1,
        asrep: 2,
        ..GradeInputs::default()
    });
    assert_eq!(
        r.text,
        "3 crackable accounts are on a path to Tier Zero (1 Kerberoastable, 2 without Kerberos pre-authentication)."
    );
    assert_eq!(r.link.unwrap().rule, "PW-007");
    // A broad group reaching Tier Zero comes first.
    let r = reason(GradeInputs {
        exposed: 3,
        broad_groups: vec!["DOMAIN USERS@CORP.LOCAL".into()],
        kerberoastable: 2,
        ..GradeInputs::default()
    });
    assert_eq!(
        r.text,
        "Every account has an attack path to Tier Zero through DOMAIN USERS@CORP.LOCAL, which holds nearly every account."
    );
    assert_eq!(r.link.unwrap().rule, "PW-001");
    // Another critical finding made the grade: the plain reason, unlinked.
    let r = reason(GradeInputs {
        exposed: 3,
        critical: 2,
        kerberoastable: 1,
        ..GradeInputs::default()
    });
    assert_eq!(r.text, "2 critical findings are open.");
    assert!(r.link.is_none());
    let r = reason(GradeInputs {
        exposed: 509,
        ..GradeInputs::default()
    });
    assert_eq!(r.text, "509 accounts outside Tier Zero can reach it.");
}

/// The headline leads with the count and the work, then the share, with the
/// precision a small share needs.
#[test]
fn headline_counts_first() {
    let plan = |steps, exposed_after| {
        Some(PlanSummary {
            steps,
            exposed_after,
        })
    };
    let h = posture::headline(509, 398_161, 0.12783773398198217, plan(7, 0));
    assert_eq!(h.title, "509 accounts have an attack path to Tier Zero");
    assert_eq!(
        h.fixes.as_deref(),
        Some("7 plan steps cut every attack path")
    );
    assert_eq!(h.share, "0.13% of 398,161 active accounts");
    let h = posture::headline(1, 10, 10.0, plan(1, 0));
    assert_eq!(h.title, "1 account has an attack path to Tier Zero");
    assert_eq!(
        h.fixes.as_deref(),
        Some("1 plan step cuts every attack path")
    );
    assert_eq!(
        posture::headline(1_200, 5_000, 24.0, plan(4, 200))
            .fixes
            .as_deref(),
        Some("4 plan steps cut off 1,000 of them")
    );
    assert_eq!(
        posture::headline(5, 9, 55.5, plan(0, 5)).fixes.as_deref(),
        Some("No plan step cuts these paths")
    );
    assert_eq!(posture::headline(5, 9, 55.5, None).fixes, None);
    let none = posture::headline(0, 400, 0.0, plan(0, 0));
    assert_eq!(
        none.title,
        "No account outside Tier Zero has an attack path to it"
    );
    assert_eq!(none.fixes, None);
    assert_eq!(none.share, "0% of 400 active accounts");
    assert_eq!(posture::share_percent(0.004), "<0.01%");
    assert_eq!(posture::share_percent(39.908), "39.91%");
}
