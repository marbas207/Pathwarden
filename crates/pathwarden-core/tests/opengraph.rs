//! OpenGraph ingest: TaskHound paths, packs, coverage and hostile files.
//!
//! Fixtures (`testdata/opengraph/`):
//! - `ad/`: a small CORP.LOCAL. ALICE, BOB and CAROL are each local admins
//!   of APP01; SVC_BACKUP is a Domain Admin.
//! - `taskhound/`: APP01 stores SVC_BACKUP's password in a scheduled task
//!   (`TH_HasTaskWithStoredCreds` + `TH_RunsAs`), plus tasks and a gMSA
//!   service that must not be paths. `taskhound_fixed/`: the same after the
//!   fix (the task no longer stores a password).
//! - `mssqlhound/` (untrusted pack) and `widgethound/` (no pack, forged
//!   native edges) against `testdata/forest`.

use std::path::{Path, PathBuf};

use pathwarden_core::analysis;
use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::config::Config;
use pathwarden_core::explore::{self, ExploreGraph};
use pathwarden_core::findings::{self, fingerprint, Context, RuleSettings};
use pathwarden_core::ingest::{IngestError, IngestLimits, Ingestor, OgLimits};
use pathwarden_core::model::{EdgeKind, NodeKind};
use pathwarden_core::opengraph::coverage::{sha256_hex, CoverageState, RunSources};
use pathwarden_core::opengraph::Pack;
use pathwarden_core::remediation;
use pathwarden_core::retest::{self, Baseline, Coverage, FindingView, Selection, Verdict};
use pathwarden_core::state::{self, FindingsState, ResolveScope, Status};
use pathwarden_core::{load, LoadOptions};

const D: &str = "S-1-5-21-3000-3000-3000";

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn analyze(inputs: &[PathBuf]) -> Analysis {
    analyze::run(inputs, &Config::default(), &[], &mut analyze::Quiet).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-og-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw033(a: &Analysis) -> Vec<&findings::Finding> {
    a.findings.iter().filter(|f| f.rule == "PW-033").collect()
}

/// Everything an analysis writes out, as text.
fn outputs(a: &Analysis) -> String {
    let mut s = String::new();
    s += &serde_json::to_string(&a.findings).unwrap();
    s += &serde_json::to_string(&a.plan).unwrap();
    s += &serde_json::to_string(&a.posture).unwrap();
    s += &serde_json::to_string(&a.stats).unwrap();
    s += &a.report_html(1_800_000_000, &mut analyze::Quiet);
    s += &String::from_utf8_lossy(&explore::encode(&a.graph, &a.findings, &a.zones));
    for (_, n) in a.graph.nodes() {
        s += &format!("{n:?}");
    }
    s
}

#[test]
fn a_stored_task_credential_is_a_path_and_the_plan_cuts_it() {
    let a = analyze(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let g = &a.graph;

    let og = &a.stats.opengraph;
    assert_eq!(og.sources.len(), 1);
    let s = &og.sources[0];
    assert_eq!(s.name, "TaskHound");
    assert_eq!(s.pack.as_deref(), Some("taskhound"));
    assert!(s.trusted && s.complete, "{s:#?}");
    assert_eq!(s.merged, 1, "APP01 merged into the AD object");
    assert_eq!(s.created, 4, "three tasks and a service");
    assert_eq!(s.placeholders, 1, "the unknown SID");
    assert_eq!(s.unresolved, 1, "the name nothing matches");
    assert!(s.dropped_secrets >= 2, "password and passwordanalysis");
    assert_eq!(s.coverage.state, CoverageState::None);

    // The AD object keeps what AD said.
    let app01 = g.lookup(&format!("{D}-1001")).unwrap();
    let n = g.node(app01);
    assert!(n.is_enabled());
    assert_eq!(n.name, "APP01.CORP.LOCAL");
    assert_eq!(n.kind, NodeKind::Computer);
    assert!(!n.tier_zero);

    // ALICE -AdminTo-> APP01 -TH_HasTaskWithStoredCreds-> task -TH_RunsAs-> SVC_BACKUP.
    let alice = g.lookup(&format!("{D}-1101")).unwrap();
    let path = analysis::path_to_tier_zero(g, alice).expect("a path through the task");
    let kinds: Vec<&str> = path.steps.iter().map(|s| s.edge.as_str()).collect();
    assert_eq!(kinds, ["AdminTo", "TH_HasTaskWithStoredCreds", "TH_RunsAs"]);
    assert_eq!(path.steps[0].source, None);
    assert_eq!(path.steps[1].source.as_deref(), Some("TaskHound"));
    assert_eq!(path.target, "SVC_BACKUP@CORP.LOCAL");

    // ALICE, BOB, CAROL and APP01 itself are exposed; the cheapest cut is the
    // stored credential (2), not the three admin rights (3), and never the
    // run-as fact (not cuttable).
    assert_eq!(a.plan.exposed_before, 4);
    assert_eq!(a.plan.exposed_after, 0);
    assert_eq!(a.plan.fixes.len(), 1, "{:#?}", a.plan.fixes);
    let fix = &a.plan.fixes[0];
    assert_eq!(fix.edges.len(), 1);
    assert_eq!(fix.edges[0].as_str(), "TH_HasTaskWithStoredCreds");
    assert_eq!(fix.cost, 2);
    assert_eq!(fix.source.as_deref(), Some("TaskHound"));
    assert!(fix.action.contains("gMSA"), "{}", fix.action);
    assert!(fix.action.contains("APP01.CORP.LOCAL"), "{}", fix.action);

    // PW-033 (one finding per Tier Zero account) for the task that stores
    // a password; not for the task that doesn't, nor the gMSA service. The
    // pack names PW-033 for TH_RunsAs, so PW-030 stays silent.
    assert!(a.findings.iter().all(|f| f.rule != "PW-030"));
    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = found[0];
    assert_eq!(
        f.fingerprint,
        fingerprint("PW-033", &[&format!("{D}-1201")])
    );
    assert!(f.title.contains("SVC_BACKUP@CORP.LOCAL"), "{}", f.title);
    assert!(f.title.contains("APP01.CORP.LOCAL"), "{}", f.title);
    assert!(f.summary.contains("TaskHound"), "{}", f.summary);
    assert_eq!(f.sources, ["TaskHound"]);
    assert_eq!(f.requires.len(), 1, "one unit: APP01");
    assert!(f.remediation.contains("gMSA"), "{}", f.remediation);
    assert_eq!(f.exposure.as_ref().unwrap().principals, 4);
    assert!(f.severity >= findings::Severity::High);

    // The gMSA service and its run-as account stay context.
    let gmsa = g.lookup("TH-WS01-SVC-BACKUPAGENT").unwrap();
    for e in g
        .inner()
        .edges_directed(gmsa, petgraph::Direction::Incoming)
    {
        assert!(!g.traversable(*e.weight(), gmsa), "{}", e.weight().as_str());
    }

    // Name and property matching resolved exactly one object each.
    let reports = g.lookup("TH-WS01-REPORTS").unwrap();
    let dave = g.lookup(&format!("{D}-1104")).unwrap();
    assert!(g.inner().find_edge(reports, dave).is_some());
    let ws01 = g.lookup(&format!("{D}-1002")).unwrap();
    assert!(g.inner().find_edge(ws01, reports).is_some());
    // The unknown SID is a placeholder, outside the population.
    let ghost = g.lookup(&format!("{D}-1999")).unwrap();
    assert!(g.node(ghost).placeholder);
    assert!(!analysis::population(g).contains(&ghost));

    // The password TaskHound recovered never reaches any output.
    let all = outputs(&a);
    assert!(!all.contains("Hunter2"), "a secret was kept");
    assert!(!all.contains("15 chars"), "passwordanalysis was kept");
}

#[test]
fn input_order_does_not_matter() {
    let a = analyze(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let b = analyze(&[testdata("opengraph/taskhound"), testdata("opengraph/ad")]);
    let fps = |a: &Analysis| {
        a.findings
            .iter()
            .map(|f| f.fingerprint.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(fps(&a), fps(&b));
    assert_eq!(
        serde_json::to_string(&a.plan).unwrap(),
        serde_json::to_string(&b.plan).unwrap()
    );
}

#[test]
fn opengraph_alone_is_not_a_collection() {
    let err = load(&[testdata("opengraph/taskhound")], &LoadOptions::default())
        .err()
        .expect("no AD data");
    assert!(matches!(err, IngestError::Empty), "{err}");
}

/// What decides findings, exposure and the plan, as text.
fn verdicts(g: &pathwarden_core::AdGraph, trusts: &[pathwarden_core::ingest::TrustInfo]) -> String {
    let settings = RuleSettings {
        now: 1_800_000_000,
        ..RuleSettings::default()
    };
    let ctx = Context::new(g, trusts, &settings);
    let mut all = findings::evaluate(&ctx, &[]);
    for f in &mut all {
        // Exposure numbers are compared through the findings themselves.
        f.summary.clear();
    }
    let tier_zero: Vec<&str> = g
        .nodes()
        .filter(|(_, n)| n.tier_zero)
        .map(|(_, n)| n.id.as_str())
        .collect();
    format!(
        "{}\n{}\n{}\n{:?}",
        serde_json::to_string(&all).unwrap(),
        serde_json::to_string(&remediation::plan(
            g,
            &pathwarden_core::analysis::Relevance::new(g, 0, 90)
        ))
        .unwrap(),
        serde_json::to_string(&analysis::exposure(
            g,
            20,
            &pathwarden_core::analysis::Relevance::new(g, 0, 90)
        ))
        .unwrap(),
        tier_zero
    )
}

#[test]
fn unmapped_and_untrusted_sources_change_no_finding_exposure_or_plan() {
    let forest = testdata("forest");
    let (g0, s0) = load(std::slice::from_ref(&forest), &LoadOptions::default()).unwrap();
    let inputs = [
        forest,
        testdata("opengraph/mssqlhound"),
        testdata("opengraph/widgethound"),
    ];
    let (g1, s1) = load(&inputs, &LoadOptions::default()).unwrap();
    assert_eq!(verdicts(&g0, &s0.trusts), verdicts(&g1, &s1.trusts));

    let og = &s1.opengraph;
    let mssql = og.sources.iter().find(|s| s.name == "MSSQL_Base").unwrap();
    assert_eq!(mssql.pack.as_deref(), Some("mssqlhound"));
    assert!(!mssql.trusted);
    assert!(mssql.edges >= 6);
    let widget = og.sources.iter().find(|s| s.name == "WidgetHound").unwrap();
    assert_eq!(widget.pack, None);
    assert_eq!(
        widget.dropped_native, 3,
        "forged MemberOf, GenericAll, AdminTo"
    );
    assert!(widget.dropped_secrets >= 1);
    assert!(og.unmapped_kinds.contains_key("WH_Manages"));

    // The forged MemberOf into Domain Admins was not added; JDOE stays
    // outside Tier Zero. The stubs did not change what AD said.
    let jdoe = g1.lookup("S-1-5-21-1000-1000-1000-1102").unwrap();
    let da = g1.lookup("S-1-5-21-1000-1000-1000-512").unwrap();
    assert!(g1.inner().find_edge(jdoe, da).is_none());
    assert!(!g1.node(jdoe).tier_zero);
    let alice = g1.lookup("S-1-5-21-1000-1000-1000-1101").unwrap();
    assert!(g1.node(alice).is_enabled() && g1.node(alice).tier_zero);
    let svc = g1.lookup("S-1-5-21-1000-1000-1000-1103").unwrap();
    assert!(g1.node(svc).is_enabled());
    assert_eq!(g1.node(svc).props.admincount, g0.node(svc).props.admincount);
    // Unmapped edges are kept as context.
    let console = g1.lookup("WIDGET-CONSOLE-1").unwrap();
    assert!(matches!(g1.node(console).kind, NodeKind::External(_)));
    assert!(g1.inner().edges(console).count() >= 2);
    assert!(g1
        .inner()
        .edges(console)
        .all(|e| !g1.traversable(*e.weight(), petgraph::visit::EdgeRef::target(&e))));
}

#[test]
fn an_untrusted_pack_changes_nothing() {
    let taskhound = pathwarden_core::opengraph::pack::EMBEDDED
        .iter()
        .find(|(f, _)| *f == "taskhound.toml")
        .unwrap()
        .1;
    let untrusted = Pack::parse(&taskhound.replace("trusted = true", "trusted = false")).unwrap();
    let opts = LoadOptions {
        packs: Some(vec![untrusted]),
        ..Default::default()
    };
    let (g0, s0) = load(&[testdata("opengraph/ad")], &opts).unwrap();
    let (g1, s1) = load(
        &[testdata("opengraph/ad"), testdata("opengraph/taskhound")],
        &opts,
    )
    .unwrap();
    assert!(g1.has_og_edges());
    assert_eq!(verdicts(&g0, &s0.trusts), verdicts(&g1, &s1.trusts));
}

// ------------------------------------------------------------ coverage

/// A folder with the TaskHound file of `variant` and, optionally, a
/// sidecar built by `sidecar(sha256)`.
fn taskhound_run(name: &str, variant: &str, sidecar: Option<&dyn Fn(&str) -> String>) -> PathBuf {
    let dir = scratch(name);
    let bytes = std::fs::read(testdata(&format!("opengraph/{variant}/taskhound.json"))).unwrap();
    std::fs::write(dir.join("taskhound.json"), &bytes).unwrap();
    if let Some(make) = sidecar {
        std::fs::write(
            dir.join("taskhound.coverage.json"),
            make(&sha256_hex(&bytes)),
        )
        .unwrap();
    }
    dir
}

fn sidecar(hash: &str, ok: &[&str], failed: &[&str], all_in: bool, complete: bool) -> String {
    serde_json::json!({
        "schema": "pathwarden.coverage.v1",
        "source_kind": "TaskHound",
        "payloads": [{ "file": "taskhound.json", "sha256": hash }],
        "collected_at": 1_791_512_129,
        "collector": { "name": "TaskHound", "version": "1.2.0", "via": "test" },
        "domains": ["CORP.LOCAL"],
        "units": {
            "type": "computer",
            "ok": ok,
            "failed": failed.iter().map(|f| serde_json::json!({"id": f, "reason": "access denied"})).collect::<Vec<_>>(),
            "all_in_domains": all_in
        },
        "complete": complete,
        "asserted_by": "plugin"
    })
    .to_string()
}

struct Run {
    a: Analysis,
    sources: RunSources,
}

fn run(inputs: &[PathBuf]) -> Run {
    let a = analyze(inputs);
    let sources = RunSources::from_analysis(&a.graph, &a.stats);
    Run { a, sources }
}

/// The PW-033 finding's status after a second run, starting from a first
/// run with the vulnerable TaskHound data (and its own coverage).
fn second_run_status(second: &Run) -> (Status, state::ChangeCounts) {
    let first = run(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let fp = pw033(&first.a)[0].fingerprint.clone();
    let r1 = state::reconcile(&FindingsState::default(), &first.a.findings, 100, false);
    let tracked = &r1.state.findings[&fp];
    assert_eq!(tracked.sources.len(), 1);
    assert_eq!(tracked.requires.len(), 1);
    // Name-free: hashes only.
    assert!(!serde_json::to_string(&r1.state)
        .unwrap()
        .contains("TaskHound"));
    let scope = ResolveScope::domains(&second.a.domains, true)
        .with_sources(second.sources.clone(), &first.sources.keys());
    let r2 = state::reconcile_scoped(&r1.state, &second.a.findings, 200, false, &scope);
    (r2.state.findings[&fp].status, r2.counts)
}

/// The retest verdict for the PW-033 finding against `second`.
fn retest_verdict(second: &Run, missing: Vec<String>) -> (Verdict, Vec<String>) {
    let first = run(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let base = Baseline::from_views(
        first.a.findings.iter().map(FindingView::from).collect(),
        "test",
    );
    let current: Vec<FindingView> = second.a.findings.iter().map(FindingView::from).collect();
    let coverage = Coverage {
        domains: second.a.domains.clone(),
        complete: true,
        sources: second.sources.clone(),
        missing_sources: missing,
        ..Default::default()
    };
    let selection = Selection {
        rules: vec!["PW-033".into()],
        ..Selection::default()
    };
    let r = retest::compare(&base, &current, &coverage, &selection).unwrap();
    assert_eq!(r.results.len(), 1);
    (r.results[0].verdict, r.results[0].details.clone())
}

#[test]
fn coverage_decides_held_or_fixed() {
    let ad = testdata("opengraph/ad");
    let app01 = format!("{D}-1001");
    let cases: Vec<(&str, PathBuf, Status, Verdict)> = vec![
        (
            "fixed, but no coverage file",
            taskhound_run("nocov", "taskhound_fixed", None),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "fixed, APP01 covered",
            taskhound_run(
                "ok",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &[&app01], &[], false, true)),
            ),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "fixed, APP01 covered by name",
            taskhound_run(
                "byname",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &["app01.corp.local"], &[], false, true)),
            ),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "fixed, APP01 failed",
            taskhound_run(
                "failed",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &[], &[&app01], false, true)),
            ),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "fixed, another host covered",
            taskhound_run(
                "other",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &[&format!("{D}-1002")], &[], false, true)),
            ),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "fixed, every computer in the domain attempted",
            taskhound_run(
                "allin",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &[], &[], true, true)),
            ),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "fixed, collection not complete",
            taskhound_run(
                "partial",
                "taskhound_fixed",
                Some(&|h| sidecar(h, &[&app01], &[], false, false)),
            ),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "fixed, sidecar for another file",
            taskhound_run(
                "mismatch",
                "taskhound_fixed",
                Some(&|_| sidecar(&"0".repeat(64), &[&app01], &[], false, true)),
            ),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "still vulnerable, covered",
            taskhound_run(
                "open",
                "taskhound",
                Some(&|h| sidecar(h, &[&app01], &[], false, true)),
            ),
            Status::Open,
            Verdict::StillOpen,
        ),
    ];
    for (what, dir, status, verdict) in cases {
        let second = run(&[ad.clone(), dir.clone()]);
        let (got, counts) = second_run_status(&second);
        assert_eq!(got, status, "{what}: {counts:?}");
        let (v, details) = retest_verdict(&second, Vec::new());
        assert_eq!(v, verdict, "{what}: {details:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // The source is missing altogether: held, and every attack path with it.
    let second = run(std::slice::from_ref(&ad));
    let (got, counts) = second_run_status(&second);
    assert_eq!(got, Status::Open);
    assert!(counts.held >= 1);
    let first = run(&[ad, testdata("opengraph/taskhound")]);
    let before = first.sources.keys();
    let missing: Vec<String> = second
        .sources
        .missing_since(&before)
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(missing.len(), 1);
    let (v, details) = retest_verdict(&second, missing);
    assert_eq!(v, Verdict::CantTell, "{details:?}");
}

#[test]
fn a_mismatched_sidecar_is_reported() {
    let dir = taskhound_run(
        "mismatch-stats",
        "taskhound",
        Some(&|_| sidecar(&"0".repeat(64), &[], &[], false, true)),
    );
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let s = &a.stats.opengraph.sources[0];
    assert_eq!(s.coverage.state, CoverageState::Invalid);
    assert!(
        s.coverage.notes.iter().any(|n| n.contains("SHA-256")),
        "{:?}",
        s.coverage.notes
    );
    std::fs::remove_dir_all(&dir).ok();

    // The sidecar beside a file given on its own is found too.
    let dir = taskhound_run(
        "beside",
        "taskhound",
        Some(&|h| sidecar(h, &[], &[], true, true)),
    );
    let a = analyze(&[testdata("opengraph/ad"), dir.join("taskhound.json")]);
    assert_eq!(
        a.stats.opengraph.sources[0].coverage.state,
        CoverageState::Sidecar
    );
    assert!(
        a.stats.skipped_files.is_empty(),
        "{:?}",
        a.stats.skipped_files
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ------------------------------------------------------------ hostile files

fn ingest_with(
    limits: IngestLimits,
    og_text: &str,
) -> (pathwarden_core::AdGraph, pathwarden_core::IngestStats) {
    let mut ing = Ingestor::with_limits(limits);
    ing.ingest_path(&testdata("opengraph/ad")).unwrap();
    ing.ingest_text("hostile.json", og_text).unwrap();
    ing.finish()
}

#[test]
fn ten_thousand_kinds_are_capped() {
    let nodes: Vec<String> = (0..10_000)
        .map(|i| format!(r#"{{"id":"N{i}","kinds":["ZZK_{i}"],"properties":{{"name":"n{i}"}}}}"#))
        .collect();
    let edges: Vec<String> = (1..10_000)
        .map(|i| {
            format!(
                r#"{{"kind":"ZZE_{i}","start":{{"value":"N{}"}},"end":{{"value":"N{i}"}}}}"#,
                i - 1
            )
        })
        .collect();
    let text = format!(
        r#"{{"metadata":{{"source_kind":"KindStorm"}},"graph":{{"nodes":[{}],"edges":[{}]}}}}"#,
        nodes.join(","),
        edges.join(",")
    );
    let (_, stats) = ingest_with(IngestLimits::default(), &text);
    let og = &stats.opengraph;
    assert!(og.kinds_over_cap > 0);
    let s = &og.sources[0];
    assert!(!s.complete);
    assert!(s.caps_hit.iter().any(|c| c == "kinds"), "{:?}", s.caps_hit);
    // The process-wide table never saw most of them.
    assert!(pathwarden_core::kinds::lookup("ZZK_9999").is_none());
    assert!(pathwarden_core::kinds::lookup("ZZE_9999").is_none());
}

#[test]
fn node_and_edge_caps_mark_the_source_incomplete() {
    let limits = IngestLimits {
        og: OgLimits {
            max_nodes: 2,
            ..OgLimits::default()
        },
        ..IngestLimits::default()
    };
    let text = std::fs::read_to_string(testdata("opengraph/taskhound/taskhound.json")).unwrap();
    let (g, stats) = ingest_with(limits, &text);
    let s = &stats.opengraph.sources[0];
    assert!(!s.complete);
    assert_eq!(s.caps_hit, ["nodes"]);
    // A halted source reads no edges.
    assert!(!g.has_og_edges());
}

/// Past the kept-properties budget a node keeps only its name (what
/// Cypher answers for `name`), and the source is marked incomplete.
#[test]
fn the_kept_properties_cap_keeps_the_name() {
    let limits = IngestLimits {
        og: OgLimits {
            max_kept_bytes: 16,
            ..OgLimits::default()
        },
        ..IngestLimits::default()
    };
    let text = r#"{"metadata":{"source_kind":"Small"},"graph":{"nodes":[
        {"id":"FIRST","kinds":["SM_Thing"],"properties":{"name":"First thing","description":"over the budget"}}
    ],"edges":[]}}"#;
    let (g, stats) = ingest_with(limits, text);
    let s = &stats.opengraph.sources[0];
    assert!(!s.complete);
    assert_eq!(s.caps_hit, ["kept properties"]);
    let ext = g.node(g.lookup("FIRST").unwrap()).ext.as_ref().unwrap();
    assert_eq!(
        ext.prop("name").and_then(|v| v.as_str()),
        Some("First thing")
    );
    assert!(ext.prop("description").is_none());
}

#[test]
fn huge_properties_are_cut_or_refused() {
    let limits = IngestLimits {
        og: OgLimits {
            max_item_bytes: 1 << 20,
            ..OgLimits::default()
        },
        ..IngestLimits::default()
    };
    let long = "x".repeat(300 << 10);
    let too_big = "y".repeat(1536 << 10);
    let text = format!(
        r#"{{"metadata":{{"source_kind":"Big"}},"graph":{{"nodes":[
            {{"id":"LONG","kinds":["BG_Thing"],"properties":{{"name":"long","description":"{long}","ignored":"{long}","nested":{{"a":{{"b":1}}}}}}}},
            {{"id":"HUGE","kinds":["BG_Thing"],"properties":{{"name":"{too_big}"}}}},
            {{"id":"AFTER","kinds":["BG_Thing"],"properties":{{"name":"after","password":"P@ss"}}}}
        ],"edges":[]}}}}"#
    );
    let (g, stats) = ingest_with(limits, &text);
    let s = &stats.opengraph.sources[0];
    let long_node = g.node(g.lookup("LONG").unwrap());
    let ext = long_node.ext.as_ref().unwrap();
    let desc = ext.prop("description").unwrap().as_str().unwrap();
    assert_eq!(desc.len(), 1024, "strings are cut");
    assert!(ext.prop("ignored").is_none() && ext.prop("nested").is_none());
    // Over the per-record budget: skipped, the source incomplete, and the
    // records after it still read.
    assert!(g.lookup("HUGE").is_none());
    assert_eq!(s.oversized, 1);
    assert!(!s.complete);
    let after = g.node(g.lookup("AFTER").unwrap());
    assert!(after.ext.as_ref().unwrap().prop("password").is_none());
    assert_eq!(s.dropped_secrets, 1);

    // A value too large to even skip stops the file, not the analysis.
    let enormous = "z".repeat(3 << 20);
    let text = format!(
        r#"{{"metadata":{{"source_kind":"Big"}},"graph":{{"nodes":[{{"id":"E","kinds":["BG_Thing"],"properties":{{"name":"{enormous}"}}}}]}}}}"#
    );
    let (_, stats) = ingest_with(limits, &text);
    let s = &stats.opengraph.sources[0];
    assert!(!s.complete && !s.errors.is_empty(), "{s:#?}");
}

#[test]
fn an_opengraph_zip_bomb_is_refused() {
    use std::io::Write;
    let dir = scratch("bomb");
    let zip_path = dir.join("bomb.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    zip.start_file(
        "taskhound.json",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(true),
    )
    .unwrap();
    zip.write_all(
        br#"{"metadata":{"source_kind":"TaskHound"},"graph":{"nodes":[],"edges":[], "pad":""#,
    )
    .unwrap();
    let chunk = vec![b' '; 1 << 20];
    for _ in 0..80 {
        zip.write_all(&chunk).unwrap();
    }
    zip.write_all(br#""}}"#).unwrap();
    zip.finish().unwrap();
    let mut ing = Ingestor::new();
    ing.ingest_path(&testdata("opengraph/ad")).unwrap();
    let err = ing.ingest_path(&zip_path).unwrap_err();
    assert!(matches!(err, IngestError::TooLarge { .. }), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opengraph_never_makes_anything_tier_zero() {
    // A file that names the Domain Admins SID of a domain with no AD data,
    // and an external object configured nowhere.
    let text = r#"{"metadata":{"source_kind":"Sneaky"},"graph":{"nodes":[
        {"id":"S-1-5-21-9-9-9-512","kinds":["Group"],"properties":{"name":"DOMAIN ADMINS@ELSEWHERE"}},
        {"id":"S-1-5-21-9-9-9-1000","kinds":["Computer"],"properties":{"name":"DC@ELSEWHERE","isdc":true}},
        {"id":"THING","kinds":["SN_Thing"]}
    ],"edges":[]}}"#;
    let mut ing = Ingestor::new();
    ing.ingest_path(&testdata("opengraph/ad")).unwrap();
    ing.ingest_text("sneaky.json", text).unwrap();
    let (mut g, _) = ing.finish();
    pathwarden_core::postprocess::run(&mut g);
    pathwarden_core::tierzero::mark(&mut g, &[]);
    for id in ["S-1-5-21-9-9-9-512", "S-1-5-21-9-9-9-1000", "THING"] {
        let n = g.node(g.lookup(id).unwrap());
        assert!(!n.tier_zero && !n.is_dc, "{id}");
    }
    // Configuring it is the only way.
    pathwarden_core::tierzero::mark(&mut g, &["THING".to_string()]);
    assert!(g.node(g.lookup("THING").unwrap()).tier_zero);
}

// ------------------------------------------------------------ explorer

#[test]
fn explorer_reads_both_versions() {
    // Without external kinds: version 1, as before.
    let (g, _) = load(&[testdata("forest")], &LoadOptions::default()).unwrap();
    let bytes = explore::encode(&g, &[], &[]);
    assert_eq!(bytes[6], explore::FORMAT_VERSION);
    let x = ExploreGraph::decode(&bytes).unwrap();
    assert_eq!(x.edge_count(), g.edge_count());
    assert!(x.kinds_info.nodes.is_empty());

    // With them: version 2, with the kind table.
    let a = analyze(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let g = &a.graph;
    let bytes = explore::encode(g, &a.findings, &a.zones);
    assert_eq!(bytes[6], explore::FORMAT_VERSION_KINDS);
    let x = ExploreGraph::decode(&bytes).unwrap();
    assert_eq!(x.node_count(), g.node_count());
    assert_eq!(x.edge_count(), g.edge_count());
    for e in g.inner().edge_indices() {
        let (s, t) = g.inner().edge_endpoints(e).unwrap();
        assert!(x
            .edge(s.index() as u32, t.index() as u32, g.inner()[e])
            .is_some());
    }
    let task = g.lookup("TH-APP01-NIGHTLYBACKUP").unwrap().index() as u32;
    assert_eq!(x.kind(task).as_str(), "TH_ScheduledTask");
    let info = x.node_kind_info(x.kind(task)).unwrap();
    assert_eq!(info.label.as_deref(), Some("Scheduled task"));
    assert_eq!(info.icon.as_deref(), Some("clock"));
    let stored = EdgeKind::from_name_or_external("TH_HasTaskWithStoredCreds").unwrap();
    assert!(x.edge_kind_info(stored).unwrap().traversable);
    assert!(
        !x.edge_kind_info(EdgeKind::from_name_or_external("TH_HasTask").unwrap())
            .unwrap()
            .traversable
    );

    // The explorer finds the analysis's path.
    let alice = g.lookup(&format!("{D}-1101")).unwrap();
    let want: Vec<String> = analysis::path_to_tier_zero(g, alice)
        .unwrap()
        .steps
        .iter()
        .map(|s| s.edge.as_str().to_string())
        .collect();
    let got: Vec<String> = x
        .tier_zero_tree()
        .path(alice.index() as u32)
        .unwrap()
        .iter()
        .map(|e| e.kind.as_str().to_string())
        .collect();
    assert_eq!(got, want);

    // Damage is an error, not a panic.
    assert!(ExploreGraph::decode(&bytes[..bytes.len() / 2]).is_err());
    let mut bad = bytes.clone();
    bad[8] = b'!';
    assert!(ExploreGraph::decode(&bad).is_err());
}

/// Without OpenGraph files nothing new is written: the outputs stay byte
/// for byte as before, but for the computers whose sessions and local
/// groups a finding rests on (in its `requires`).
#[test]
fn outputs_without_opengraph_have_no_new_fields() {
    for input in ["demo", "testdata/forest", "testdata/adcs"] {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(input);
        let a = analyze(&[dir]);
        let mut findings = a.findings.clone();
        for f in &mut findings {
            assert!(
                f.requires
                    .iter()
                    .all(|u| u.starts_with(pathwarden_core::opengraph::SESSION_HOST)
                        || u.starts_with(pathwarden_core::opengraph::LOCAL_GROUP_HOST)),
                "{input}: {:?}",
                f.requires
            );
            f.requires.clear();
        }
        let json = format!(
            "{}{}{}",
            serde_json::to_string(&findings).unwrap(),
            serde_json::to_string(&a.plan).unwrap(),
            serde_json::to_string(&a.stats).unwrap()
        );
        for key in ["\"sources\"", "\"requires\"", "\"opengraph\"", "OpenGraph"] {
            assert!(!json.contains(key), "{input}: {key}");
        }
        let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
        assert!(!html.contains("Other sources (OpenGraph)"), "{input}");
        assert_eq!(
            explore::encode(&a.graph, &a.findings, &a.zones)[6],
            1,
            "{input}"
        );
        assert!(!a.graph.has_og_edges());
    }
}

#[allow(dead_code)]
fn exists(p: &Path) -> bool {
    p.exists()
}

// ------------------------------------------------------------ phase D

/// A coverage declaration (the UI's form) becomes a sidecar that binds the
/// payload by SHA-256 and gives the source coverage.
#[test]
fn a_declared_coverage_binds_the_payload() {
    use pathwarden_core::opengraph::coverage::{Declaration, Sidecar};
    let dir = taskhound_run("declared", "taskhound", None);
    let bytes = std::fs::read(dir.join("taskhound.json")).unwrap();
    let hash = sha256_hex(&bytes);
    let d = Declaration {
        all_in_domains: vec!["CORP.LOCAL".into()],
        ok: vec![],
        failed: vec![" ".into()],
        complete: true,
    };
    let text = d
        .sidecar(
            "TaskHound",
            "C:\\up\\0\\taskhound.json",
            &hash,
            1_791_512_129,
        )
        .unwrap();
    let s = Sidecar::parse(text.as_bytes()).unwrap();
    assert!(s.binds("taskhound.json", &hash));
    assert_eq!(s.asserted_by.as_deref(), Some("user"));
    assert!(s.units.all_in_domains && s.units.failed.is_empty());
    std::fs::write(dir.join("taskhound.json.coverage.json"), &text).unwrap();
    let a = analyze(&[testdata("opengraph/ad"), dir.join("taskhound.json")]);
    let c = &a.stats.opengraph.sources[0].coverage;
    assert_eq!(c.state, CoverageState::Sidecar, "{c:?}");
    assert_eq!(c.asserted_by.as_deref(), Some("user"));

    // Nothing declared, or a control character, is refused.
    assert!(Declaration::default()
        .sidecar("TaskHound", "t.json", &hash, 0)
        .is_err());
    let bad = Declaration {
        ok: vec!["APP01\nX".into()],
        ..Default::default()
    };
    assert!(bad.sidecar("TaskHound", "t.json", &hash, 0).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// `[[mapping]]` packs are read relative to the config file, validated
/// whole, and `[opengraph] trust` marks a reviewed pack trusted.
#[test]
fn user_packs_and_trust_come_from_the_config() {
    let dir = scratch("user-packs");
    std::fs::create_dir_all(dir.join("packs")).unwrap();
    std::fs::write(
        dir.join("packs/widget.toml"),
        r#"
[pack]
name = "widgethound"
version = 2
source_kinds = ["WidgetHound"]
kind_prefix = "WH_"

[[edge]]
kind = "WH_Manages"
traversable = true
"#,
    )
    .unwrap();
    let cfg = dir.join("pathwarden.toml");
    std::fs::write(
        &cfg,
        "[opengraph]\ntrust = [\"mssqlhound\"]\n\n[[mapping]]\npath = \"packs/widget.toml\"\n",
    )
    .unwrap();
    let c = Config::from_file(&cfg).unwrap();
    assert_eq!(c.user_packs.len(), 1);
    let packs = c.packs().unwrap();
    assert!(packs
        .iter()
        .any(|p| p.name() == "mssqlhound" && p.trusted()));
    assert!(packs
        .iter()
        .any(|p| p.name() == "widgethound" && !p.trusted()));
    assert!(analyze::load_options(&c, &[]).packs.is_some());
    // Without either, the built-in packs are used as they are.
    assert!(Config::default().packs().is_none());

    // A pack that fails validation refuses the config, naming its path.
    std::fs::write(
        dir.join("packs/widget.toml"),
        "[pack]\nname = \"widgethound\"\nversion = 1\nsource_kinds = [\"W\"]\nkind_prefix = \"WH_\"\n[[edge]]\nkind = \"MemberOf\"\n",
    )
    .unwrap();
    let e = Config::from_file(&cfg).unwrap_err().to_string();
    assert!(e.contains("packs/widget.toml"), "{e}");
    // A built-in pack's name, network paths, other files, odd trust names.
    std::fs::write(
        dir.join("packs/widget.toml"),
        "[pack]\nname = \"taskhound\"\nversion = 1\nsource_kinds = [\"W\"]\nkind_prefix = \"WH_\"\n",
    )
    .unwrap();
    assert!(Config::from_file(&cfg).is_err());
    for bad in [
        "[[mapping]]\npath = \"\\\\\\\\server\\\\share\\\\p.toml\"",
        "[[mapping]]\npath = \"packs/run.exe\"",
        "[opengraph]\ntrust = [\"a b\"]",
    ] {
        assert!(Config::parse(bad).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The explorer's kind table names the sources each external kind came from.
#[test]
fn explorer_kinds_name_their_sources() {
    let a = analyze(&[testdata("opengraph/ad"), testdata("opengraph/taskhound")]);
    let bytes = explore::encode(&a.graph, &a.findings, &a.zones);
    let x = ExploreGraph::decode(&bytes).unwrap();
    let th = x
        .kinds_info
        .edges
        .iter()
        .find(|e| e.name == "TH_HasTaskWithStoredCreds")
        .unwrap();
    assert_eq!(th.sources, vec!["TaskHound".to_string()]);
    assert!(x
        .kinds_info
        .edges
        .iter()
        .filter(|e| e.name == "MemberOf")
        .all(|e| e.sources.is_empty()));
}
