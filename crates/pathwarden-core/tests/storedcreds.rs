//! Stored credentials in services: the built-in collector's
//! `pathwarden-storedcreds.json`, the `HasStoredCredential` edge, PW-033
//! with TaskHound's data, coverage per computer, and NetBIOS names.
//!
//! Fixtures: `testdata/opengraph/ad` (CORP.LOCAL: ALICE, BOB and CAROL are
//! local admins of APP01; SVC_BACKUP is a Domain Admin; DAVE is a plain
//! user) and synthetic sidecars written here.

use std::path::PathBuf;

use pathwarden_core::analysis;
use pathwarden_core::analyze::{self, Analysis};
use pathwarden_core::config::Config;
use pathwarden_core::explore;
use pathwarden_core::findings::{self, fingerprint};
use pathwarden_core::model::EdgeKind;
use pathwarden_core::opengraph::coverage::RunSources;
use pathwarden_core::retest::{self, Baseline, Coverage, FindingView, Selection, Verdict};
use pathwarden_core::state::{self, FindingsState, ResolveScope, Status};
use pathwarden_core::storedcreds;
use serde_json::{json, Value};

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
    // Tests run at once and some share a name (`after`'s first run).
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("pathwarden-sc-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn host(rid: u32, name: &str, status: &str, stored: Value) -> Value {
    json!({
        "id": format!("{D}-{rid}"),
        "name": name,
        "services": { "status": status, "read": 120, "reason": if status == "complete" { Value::Null } else { json!("access denied") } },
        "stored": stored,
    })
}

/// APP01 runs a service as CORP\svc_backup, WS01 another as its UPN, a
/// gMSA and DAVE; DC01 (Tier Zero) runs one as svc_backup too; an account
/// nobody has.
fn vulnerable() -> Value {
    json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.local",
        "netbios": [{ "dns": "corp.local", "netbios": "CORP" }],
        "services": { "status": "complete", "read": 3 },
        "hosts": [
            host(1001, "APP01.CORP.LOCAL", "complete", json!([
                { "via": "service", "name": "SqlAgent", "account": "CORP\\svc_backup", "start": 2 },
                { "via": "service", "name": "Ghost", "account": "CORP\\nobody", "start": 2 },
            ])),
            host(1002, "WS01.CORP.LOCAL", "complete", json!([
                { "via": "service", "name": "Reports", "account": "svc_backup@corp.local", "start": 4 },
                { "via": "service", "name": "BackupAgent", "account": "CORP\\gmsa_backup$", "start": 2 },
                { "via": "service", "name": "Tool", "account": "CORP\\dave", "start": 3 },
            ])),
            host(1000, "DC01.CORP.LOCAL", "complete", json!([
                { "via": "service", "name": "DcJob", "account": "CORP\\svc_backup", "start": 2 },
            ])),
        ]
    })
}

/// The same after the fix: no service runs as svc_backup.
fn fixed(ws01: &str) -> Value {
    json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.local",
        "netbios": [{ "dns": "corp.local", "netbios": "CORP" }],
        "services": { "status": if ws01 == "complete" { "complete" } else { "partial" } },
        "hosts": [
            host(1001, "APP01.CORP.LOCAL", "complete", json!([])),
            host(1002, "WS01.CORP.LOCAL", ws01, json!([])),
            host(1000, "DC01.CORP.LOCAL", "complete", json!([])),
        ]
    })
}

fn with_sidecar(name: &str, s: &Value) -> PathBuf {
    let dir = scratch(name);
    std::fs::write(
        dir.join(storedcreds::FILE_NAME),
        serde_json::to_vec_pretty(s).unwrap(),
    )
    .unwrap();
    dir
}

fn pw033(a: &Analysis) -> Vec<&findings::Finding> {
    a.findings.iter().filter(|f| f.rule == "PW-033").collect()
}

fn source() -> String {
    storedcreds::source("CORP.LOCAL")
}

#[test]
fn a_service_account_stored_outside_tier_zero_is_pw033_and_a_path() {
    let dir = with_sidecar("path", &vulnerable());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let g = &a.graph;
    let st = &a.stats.stored_credentials;
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].edges, 4, "{st:#?}");
    assert_eq!(st[0].managed, 1, "the gMSA");
    assert_eq!(st[0].unresolved, 1, "CORP\\nobody");
    assert_eq!(st[0].hosts_complete, 3);

    let at = |rid: u32| g.lookup(&format!("{D}-{rid}")).unwrap();
    let stored = |from: u32, to: u32| {
        g.inner()
            .edges_connecting(at(from), at(to))
            .any(|e| *e.weight() == EdgeKind::HasStoredCredential)
    };
    assert!(stored(1001, 1201), "APP01 stores svc_backup");
    assert!(stored(1002, 1201), "WS01 stores svc_backup (UPN)");
    assert!(stored(1000, 1201), "the DC's edge is kept");
    assert!(
        stored(1002, 1104),
        "DAVE, outside Tier Zero, is an edge too"
    );

    // ALICE -AdminTo-> APP01 -HasStoredCredential-> SVC_BACKUP.
    let path = analysis::path_to_tier_zero(g, at(1101)).expect("a path");
    let kinds: Vec<&str> = path.steps.iter().map(|s| s.edge.as_str()).collect();
    assert_eq!(kinds, ["AdminTo", "HasStoredCredential"]);
    assert_eq!(path.steps[1].source.as_deref(), Some(source().as_str()));

    // One finding for the account, the two hosts outside Tier Zero; the DC
    // is in-tier.
    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = found[0];
    assert_eq!(
        f.fingerprint,
        fingerprint("PW-033", &[&format!("{D}-1201")])
    );
    assert!(f.title.contains("2 computers"), "{}", f.title);
    assert!(
        f.summary
            .contains("The built-in collector reports 2 services that run as "),
        "{}",
        f.summary
    );
    assert!(
        f.summary.contains(") and store its password on "),
        "{}",
        f.summary
    );
    assert!(!f.summary.contains("DC01"), "{}", f.summary);
    assert_eq!(f.sources, [source()]);
    assert_eq!(f.requires.len(), 2, "APP01 and WS01");
    assert!(f.remediation.contains("SqlAgent"), "{}", f.remediation);
    assert!(
        f.remediation.contains("Full collection"),
        "{}",
        f.remediation
    );
    let details: Vec<&str> = f
        .affected
        .iter()
        .filter_map(|x| x.detail.as_deref())
        .collect();
    assert!(
        details.contains(&"Service Reports (disabled), as reported by the computer"),
        "{details:?}"
    );
    assert!(f.severity >= findings::Severity::High);
    // Not reported again as plain control of Tier Zero.
    assert!(a
        .findings
        .iter()
        .filter(|f| f.rule == "PW-003")
        .all(|f| !f.title.contains("HasStoredCredential")));

    // The plan cuts the stored credential (2) rather than three admin rights.
    let cut = a
        .plan
        .fixes
        .iter()
        .find(|x| x.edges.contains(&EdgeKind::HasStoredCredential))
        .expect("a stored credential cut");
    assert_eq!(cut.cost, 2);
    assert!(cut.action.contains("gMSA"), "{}", cut.action);

    // Completeness counts the computers read in full.
    let c = &a.posture.completeness[0];
    assert_eq!(c.stored_credentials_collected, Some(3), "{c:#?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn without_the_file_nothing_changes() {
    let a = analyze(&[testdata("opengraph/ad")]);
    assert!(pw033(&a).is_empty());
    assert!(a.stats.stored_credentials.is_empty());
    assert_eq!(a.posture.completeness[0].stored_credentials_collected, None);
    let posture = serde_json::to_string(&a.posture).unwrap();
    assert!(!posture.contains("stored_credentials"), "{posture}");
    let stats = serde_json::to_string(&a.stats).unwrap();
    assert!(!stats.contains("stored_credentials"), "{stats}");
}

/// TaskHound and the built-in collector report the same account: one
/// finding, both sources.
#[test]
fn taskhound_and_native_give_one_finding() {
    let dir = with_sidecar("both", &vulnerable());
    let a = analyze(&[
        testdata("opengraph/ad"),
        testdata("opengraph/taskhound"),
        dir.clone(),
    ]);
    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = found[0];
    assert_eq!(f.sources, [source(), "TaskHound".to_string()]);
    assert!(
        f.summary
            .starts_with("TaskHound and the built-in collector report"),
        "{}",
        f.summary
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// TaskHound names its run-as account `CORP\svc_backup`: it resolves with
/// the NetBIOS names the built-in collector read, and only with them.
#[test]
fn netbios_names_resolve_taskhound_run_as_accounts() {
    let mut th: Value = serde_json::from_slice(
        &std::fs::read(testdata("opengraph/taskhound/taskhound.json")).unwrap(),
    )
    .unwrap();
    for e in th["graph"]["edges"].as_array_mut().unwrap() {
        if e["kind"] == "TH_RunsAs" && e["start"]["value"] == "TH-APP01-NIGHTLYBACKUP" {
            e["end"] = json!({ "value": "CORP\\svc_backup", "match_by": "name" });
        }
    }
    let og = scratch("nb-th");
    std::fs::write(og.join("taskhound.json"), serde_json::to_vec(&th).unwrap()).unwrap();
    let without = analyze(&[testdata("opengraph/ad"), og.clone()]);
    assert!(pw033(&without).is_empty());

    let names = with_sidecar(
        "nb-names",
        &json!({
            "schema": storedcreds::SCHEMA,
            "domain": "corp.local",
            "netbios": [{ "dns": "corp.local", "netbios": "CORP" }],
            "services": { "status": "not_collected", "reason": "services are read only over Kerberos" },
        }),
    );
    let with = analyze(&[testdata("opengraph/ad"), og.clone(), names.clone()]);
    let found = pw033(&with);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].sources, ["TaskHound"]);
    std::fs::remove_dir_all(&og).ok();
    std::fs::remove_dir_all(&names).ok();
}

/// The stored credential units a run records for the next
/// ([`RunSources::all_keys`] without sessions and local groups).
fn stored_keys(s: &RunSources) -> Vec<String> {
    s.all_keys()
        .into_iter()
        .filter(|k| k.starts_with(pathwarden_core::opengraph::HOST_UNIT))
        .collect()
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

/// The PW-033 finding's status and retest verdict after `second`, from a
/// first run where APP01 and WS01 store svc_backup.
fn after(second: &Run) -> (Status, Verdict, Vec<String>) {
    let dir = with_sidecar("first", &vulnerable());
    let first = run(&[testdata("opengraph/ad"), dir.clone()]);
    std::fs::remove_dir_all(&dir).ok();
    let fp = pw033(&first.a)[0].fingerprint.clone();
    let r1 = state::reconcile(&FindingsState::default(), &first.a.findings, 100, false);
    // Name-free: hashes only.
    assert!(!serde_json::to_string(&r1.state)
        .unwrap()
        .contains("Stored credentials"));
    let before = stored_keys(&first.sources);
    let scope = ResolveScope::domains(&second.a.domains, true)
        .with_sources(second.sources.clone(), &before);
    let r2 = state::reconcile_scoped(&r1.state, &second.a.findings, 200, false, &scope);
    let status = r2.state.findings[&fp].status;

    let base = Baseline::from_views(
        first.a.findings.iter().map(FindingView::from).collect(),
        "test",
    );
    let current: Vec<FindingView> = second.a.findings.iter().map(FindingView::from).collect();
    let coverage = Coverage {
        domains: second.a.domains.clone(),
        complete: true,
        sources: second.sources.clone(),
        ..Default::default()
    }
    .compared_with(&before);
    let selection = Selection {
        rules: vec!["PW-033".into()],
        ..Selection::default()
    };
    let r = retest::compare(&base, &current, &coverage, &selection).unwrap();
    assert_eq!(r.results.len(), 1);
    (status, r.results[0].verdict, r.results[0].details.clone())
}

/// Fixed only when every computer that held the credential was read again
/// in full; any computer not read holds it.
#[test]
fn fixed_only_when_every_host_was_read_again() {
    let ad = testdata("opengraph/ad");
    let cases: Vec<(&str, Option<Value>, Status, Verdict)> = vec![
        (
            "both read in full",
            Some(fixed("complete")),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "WS01 access denied",
            Some(fixed("not_collected")),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "WS01 partly read",
            Some(fixed("partial")),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "still stored",
            Some(vulnerable()),
            Status::Open,
            Verdict::StillOpen,
        ),
        (
            "the step not run (NTLM)",
            Some(json!({
                "schema": storedcreds::SCHEMA,
                "domain": "corp.local",
                "services": { "status": "not_collected", "reason": "services are read only over Kerberos" },
            })),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "no stored credentials file (DC only)",
            None,
            Status::Open,
            Verdict::CantTell,
        ),
    ];
    for (what, sidecar, status, verdict) in cases {
        let mut inputs = vec![ad.clone()];
        let dir = sidecar.map(|s| with_sidecar("second", &s));
        inputs.extend(dir.clone());
        let second = run(&inputs);
        let (got, v, details) = after(&second);
        assert_eq!(got, status, "{what}");
        assert_eq!(v, verdict, "{what}: {details:?}");
        if let Some(d) = dir {
            std::fs::remove_dir_all(&d).ok();
        }
    }
}

/// A source that gave no edge last time holds nothing when it is missing;
/// one that did holds what rests on the computers that had an edge.
#[test]
fn a_missing_source_holds_paths_only_if_it_gave_edges() {
    let none = with_sidecar("noedge", &fixed("complete"));
    let first = run(&[testdata("opengraph/ad"), none.clone()]);
    assert!(
        stored_keys(&first.sources).is_empty(),
        "no edge, nothing to hold"
    );
    let some = with_sidecar("edge", &vulnerable());
    let first = run(&[testdata("opengraph/ad"), some.clone()]);
    let second = run(&[testdata("opengraph/ad")]);
    let before = stored_keys(&first.sources);
    assert_eq!(before.len(), 3, "APP01, WS01 and DC01 had an edge");
    let missing = second.sources.missing_hosts_since(&before);
    assert_eq!(missing.len(), 3);
    let words = second
        .sources
        .describe(&missing.into_iter().cloned().collect::<Vec<_>>());
    assert_eq!(
        words,
        "services not read in full on 3 computers that stored a credential when last read"
    );
    // All three read in full again: nothing missing.
    let clean = with_sidecar("clean", &fixed("complete"));
    let third = run(&[testdata("opengraph/ad"), clean.clone()]);
    assert!(third.sources.missing_hosts_since(&before).is_empty());
    for d in [none, some, clean] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// APP01 and WS01 read again and clean, but DC01 (which stored the same
/// account last time, in-tier, so not on the finding) not reached: the
/// finding rests on APP01 and WS01 alone, so it is fixed. DC01 holds only
/// the findings that reach Tier Zero by any path (`ResolveScope::missing_hosts`).
#[test]
fn a_partial_read_holds_only_what_rests_on_it() {
    let first_dir = with_sidecar("pa-first", &vulnerable());
    let first = run(&[testdata("opengraph/ad"), first_dir.clone()]);
    let f = pw033(&first.a)[0];
    assert_eq!(f.requires.len(), 2, "APP01 and WS01, not DC01");
    let fp = f.fingerprint.clone();
    let r1 = state::reconcile(&FindingsState::default(), &first.a.findings, 100, false);
    let before = stored_keys(&first.sources);

    let mut s = fixed("complete");
    s["hosts"][2]["services"] = json!({ "status": "not_collected", "reason": "not reached" });
    let second_dir = with_sidecar("pa-second", &s);
    let second = run(&[testdata("opengraph/ad"), second_dir.clone()]);
    assert!(pw033(&second.a).is_empty());
    let missing = second.sources.missing_hosts_since(&before);
    assert_eq!(missing.len(), 1, "DC01 wasn't read");
    let scope = ResolveScope::domains(&second.a.domains, true)
        .with_sources(second.sources.clone(), &before);
    assert!(
        scope.missing_sources.is_empty(),
        "a computer isn't a source"
    );
    assert_eq!(scope.missing_hosts.len(), 1);
    let r2 = state::reconcile_scoped(&r1.state, &second.a.findings, 200, false, &scope);
    assert_eq!(r2.state.findings[&fp].status, Status::Resolved);
    let (_, verdict, details) = after(&second);
    assert_eq!(verdict, Verdict::Fixed, "{details:?}");
    for d in [first_dir, second_dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// A computer deleted from the directory no longer holds the credential:
/// its finding resolves, and it holds no attack path.
#[test]
fn a_deleted_computer_no_longer_holds_it() {
    let dir = with_sidecar("del-first", &vulnerable());
    let first = run(&[testdata("opengraph/ad"), dir.clone()]);
    let fp = pw033(&first.a)[0].fingerprint.clone();
    let r1 = state::reconcile(&FindingsState::default(), &first.a.findings, 100, false);
    let before = stored_keys(&first.sources);

    // WS01 gone from the directory, APP01 read and clean.
    let ad = scratch("del-ad");
    for f in ["corp_users.json", "corp_groups.json", "corp_domains.json"] {
        std::fs::copy(testdata(&format!("opengraph/ad/{f}")), ad.join(f)).unwrap();
    }
    let mut c: Value = serde_json::from_slice(
        &std::fs::read(testdata("opengraph/ad/corp_computers.json")).unwrap(),
    )
    .unwrap();
    c["data"]
        .as_array_mut()
        .unwrap()
        .retain(|x| x["ObjectIdentifier"] != format!("{D}-1002"));
    c["meta"]["count"] = json!(2);
    std::fs::write(
        ad.join("corp_computers.json"),
        serde_json::to_vec(&c).unwrap(),
    )
    .unwrap();
    let mut s = fixed("complete");
    s["hosts"].as_array_mut().unwrap().remove(1);
    let second_dir = with_sidecar("del-second", &s);
    let second = run(&[ad.clone(), second_dir.clone()]);
    assert!(second.sources.missing_hosts_since(&before).is_empty());
    let scope = ResolveScope::domains(&second.a.domains, true)
        .with_sources(second.sources.clone(), &before);
    let r2 = state::reconcile_scoped(&r1.state, &second.a.findings, 200, false, &scope);
    assert_eq!(r2.state.findings[&fp].status, Status::Resolved);
    for d in [dir, ad, second_dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// A NetBIOS name two forests of a run share names neither: services and
/// TaskHound's run-as accounts in it stay unresolved, while each sidecar's
/// own name still resolves its own services.
#[test]
fn a_netbios_name_two_forests_share_is_ambiguous() {
    let mut own = vulnerable();
    own["hosts"] = json!([host(
        1001,
        "APP01.CORP.LOCAL",
        "complete",
        json!([
            { "name": "SqlAgent", "account": "CORP\\svc_backup" }
        ])
    )]);
    let other = json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.example",
        "netbios": [{ "dns": "corp.example", "netbios": "CORP" }],
        "services": { "status": "complete" },
    });
    let a_dir = with_sidecar("nb-a", &own);
    let b_dir = with_sidecar("nb-b", &other);
    let a = analyze(&[testdata("opengraph/ad"), a_dir.clone(), b_dir.clone()]);
    assert_eq!(a.graph.netbios().get("CORP"), None, "ambiguous");
    // Its own forest's name: still APP01's svc_backup.
    assert_eq!(pw033(&a).len(), 1);

    // TaskHound's CORP\svc_backup: no NetBIOS name to go by.
    let mut th: Value = serde_json::from_slice(
        &std::fs::read(testdata("opengraph/taskhound/taskhound.json")).unwrap(),
    )
    .unwrap();
    for e in th["graph"]["edges"].as_array_mut().unwrap() {
        if e["kind"] == "TH_RunsAs" && e["start"]["value"] == "TH-APP01-NIGHTLYBACKUP" {
            e["end"] = json!({ "value": "CORP\\svc_backup", "match_by": "name" });
        }
    }
    let og = scratch("nb-th2");
    std::fs::write(og.join("taskhound.json"), serde_json::to_vec(&th).unwrap()).unwrap();
    let mut names_only = vulnerable();
    names_only["hosts"] = json!([]);
    let n_dir = with_sidecar("nb-n", &names_only);
    let a = analyze(&[
        testdata("opengraph/ad"),
        og.clone(),
        n_dir.clone(),
        b_dir.clone(),
    ]);
    assert!(pw033(&a).is_empty(), "{:#?}", pw033(&a));
    for d in [a_dir, b_dir, og, n_dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// `user@suffix` is the user whose userPrincipalName it is, even when
/// another user's sAMAccountName equals its prefix.
#[test]
fn a_upn_matches_its_owner_not_a_same_named_account() {
    let ad = scratch("upn-ad");
    for f in [
        "corp_computers.json",
        "corp_groups.json",
        "corp_domains.json",
    ] {
        std::fs::copy(testdata(&format!("opengraph/ad/{f}")), ad.join(f)).unwrap();
    }
    let mut u: Value =
        serde_json::from_slice(&std::fs::read(testdata("opengraph/ad/corp_users.json")).unwrap())
            .unwrap();
    for x in u["data"].as_array_mut().unwrap() {
        // SVC_BACKUP (a Domain Admin) signs in as backup@corp.local.
        if x["ObjectIdentifier"] == format!("{D}-1201") {
            x["Properties"]["userprincipalname"] = json!("backup@corp.local");
        }
    }
    // BACKUP, a plain user, whose name is BACKUP@CORP.LOCAL.
    let mut other = u["data"][2].clone();
    other["ObjectIdentifier"] = json!(format!("{D}-1301"));
    other["Properties"]["name"] = json!("BACKUP@CORP.LOCAL");
    other["Properties"]["userprincipalname"] = json!("plain.backup@corp.local");
    u["data"].as_array_mut().unwrap().push(other);
    u["meta"]["count"] = json!(7);
    std::fs::write(ad.join("corp_users.json"), serde_json::to_vec(&u).unwrap()).unwrap();
    let mut s = vulnerable();
    s["hosts"] = json!([host(
        1001,
        "APP01.CORP.LOCAL",
        "complete",
        json!([
            { "name": "Backup", "account": "backup@corp.local" }
        ])
    )]);
    let dir = with_sidecar("upn", &s);
    let a = analyze(&[ad.clone(), dir.clone()]);
    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].affected[0].name, "SVC_BACKUP@CORP.LOCAL");
    for d in [ad, dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// Service reads turned off: completeness says "off", not 0%, and a
/// finding that rests on them is held with that reason.
#[test]
fn turned_off_reads_say_so() {
    let off = json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.local",
        "turned_off": true,
        "services": { "status": "not_collected", "reason": "service reads were turned off for this collection" },
    });
    let dir = with_sidecar("off", &off);
    let second = run(&[testdata("opengraph/ad"), dir.clone()]);
    let c = &second.a.posture.completeness[0];
    assert!(c.stored_credentials_off);
    assert_eq!(c.stored_credentials_collected, None);
    assert_eq!(c.services_words().as_deref(), Some("off"));
    let html = second.a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains("<th>Services read</th>"));
    assert!(html.contains(pathwarden_core::posture::STORED_CREDENTIALS_OFF));
    let (status, verdict, details) = after(&second);
    assert_eq!(status, Status::Open);
    assert_eq!(verdict, Verdict::CantTell);
    assert!(
        details.iter().any(|d| d.contains("turned off")),
        "{details:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_report_counts_services_read() {
    let dir = with_sidecar("col", &fixed("not_collected"));
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains("<th>Services read</th>"), "the column");
    assert!(html.contains("2/3 ("), "APP01 and DC01 of 3");
    assert!(html.contains(pathwarden_core::posture::STORED_CREDENTIALS_DEF));
    // Without service data, no column.
    let plain =
        analyze(&[testdata("opengraph/ad")]).report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(!plain.contains("Services read"));
    std::fs::remove_dir_all(&dir).ok();
}

/// A hostile file: secret-looking fields, oversize names, control
/// characters and bad IDs never reach any output.
#[test]
fn a_hostile_file_leaks_nothing() {
    let mut s = vulnerable();
    s["password"] = json!("Hunter2!top");
    s["hosts"][0]["password"] = json!("Hunter2!host");
    s["hosts"][0]["stored"][0]["password"] = json!("Hunter2!svc");
    s["hosts"][0]["stored"][0]["imagepath"] = json!("C:\\x.exe /p Hunter2!cmd");
    s["hosts"][0]["stored"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "x".repeat(10_000), "account": "CORP\\dave" }));
    s["hosts"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": "not a sid", "name": "EVIL" }));
    let dir = with_sidecar("hostile", &s);
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let mut out = String::new();
    out += &serde_json::to_string(&a.findings).unwrap();
    out += &serde_json::to_string(&a.plan).unwrap();
    out += &serde_json::to_string(&a.posture).unwrap();
    out += &serde_json::to_string(&a.stats).unwrap();
    out += &a.report_html(1_800_000_000, &mut analyze::Quiet);
    out += &String::from_utf8_lossy(&explore::encode(&a.graph, &a.findings, &a.zones));
    assert!(!out.contains("Hunter2"), "a secret reached an output");
    assert!(
        !out.contains(&"x".repeat(300)),
        "an oversize name reached an output"
    );
    assert_eq!(pw033(&a).len(), 1);
    let notes = &a.stats.stored_credentials[0].notes;
    assert!(notes.iter().any(|n| n.contains("valid ID")), "{notes:?}");
    std::fs::remove_dir_all(&dir).ok();

    // Too large, another schema, not JSON: refused whole, and said so.
    let big = scratch("big");
    std::fs::write(
        big.join(storedcreds::FILE_NAME),
        vec![b' '; storedcreds::MAX_SIDECAR_BYTES as usize + 1],
    )
    .unwrap();
    let a = analyze(&[testdata("opengraph/ad"), big.clone()]);
    assert!(a.stats.stored_credentials.is_empty());
    assert!(a
        .stats
        .skipped_files
        .iter()
        .any(|f| f.contains("stored credentials data")));
    std::fs::remove_dir_all(&big).ok();
}

// ---- Scheduled tasks (slice 2) ----

fn tasks_host(rid: u32, name: &str, services: &str, tasks: &str, stored: Value) -> Value {
    let mut h = host(rid, name, services, stored);
    h["tasks"] = json!({
        "status": tasks,
        "read": 150,
        "reason": if tasks == "complete" { Value::Null } else { json!("access denied") },
    });
    h
}

/// APP01 runs a service as svc_backup; WS01 has a scheduled task that
/// stores svc_backup's password (by SID, disabled), one for DAVE, one for
/// a computer account and one for a SID nobody has; DC01 (Tier Zero) a
/// task as svc_backup. Both steps read in full.
fn with_tasks() -> Value {
    json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.local",
        "netbios": [{ "dns": "corp.local", "netbios": "CORP" }],
        "services": { "status": "complete", "read": 3 },
        "tasks": { "status": "complete", "read": 3 },
        "hosts": [
            tasks_host(1001, "APP01.CORP.LOCAL", "complete", "complete", json!([
                { "via": "service", "name": "SqlAgent", "account": "CORP\\svc_backup", "start": 2 },
            ])),
            tasks_host(1002, "WS01.CORP.LOCAL", "complete", "complete", json!([
                { "via": "task", "name": "\\Backups\\Nightly", "account": format!("{D}-1201"),
                  "enabled": false, "logon_type": "Password" },
                { "via": "task", "name": "\\Tool", "account": "CORP\\dave",
                  "logon_type": "InteractiveTokenOrPassword" },
                { "via": "task", "name": "\\Machine", "account": format!("{D}-1001"),
                  "logon_type": "Password" },
                { "via": "task", "name": "\\Local", "account": format!("{D}-9999"),
                  "logon_type": "Password" },
            ])),
            tasks_host(1000, "DC01.CORP.LOCAL", "complete", "complete", json!([
                { "via": "task", "name": "\\DcJob", "account": "CORP\\svc_backup", "logon_type": "Password" },
            ])),
        ]
    })
}

/// Clean after the fix, with APP01's and WS01's (services, tasks) status.
fn with_tasks_fixed(app01: (&str, &str), ws01: (&str, &str)) -> Value {
    let step = |a: &str, b: &str| {
        if a == "complete" && b == "complete" {
            "complete"
        } else {
            "partial"
        }
    };
    json!({
        "schema": storedcreds::SCHEMA,
        "domain": "corp.local",
        "netbios": [{ "dns": "corp.local", "netbios": "CORP" }],
        "services": { "status": step(app01.0, ws01.0) },
        "tasks": { "status": step(app01.1, ws01.1) },
        "hosts": [
            tasks_host(1001, "APP01.CORP.LOCAL", app01.0, app01.1, json!([])),
            tasks_host(1002, "WS01.CORP.LOCAL", ws01.0, ws01.1, json!([])),
            tasks_host(1000, "DC01.CORP.LOCAL", "complete", "complete", json!([])),
        ]
    })
}

fn task_source() -> String {
    storedcreds::task_source("CORP.LOCAL")
}

/// A task and a service storing one Tier Zero account on two hosts: one
/// PW-033 with both sources, each host's unit for the source that found
/// it; a task by SID resolves; a computer account's SID is managed; a SID
/// the directory doesn't have is unresolved; the DC's task is in-tier.
#[test]
fn a_task_feeds_pw033_with_the_services() {
    let dir = with_sidecar("tasks", &with_tasks());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let g = &a.graph;
    let st = &a.stats.stored_credentials[0];
    assert_eq!(st.edges, 4, "{st:#?}");
    assert_eq!(st.managed, 1, "the computer account");
    assert_eq!(st.unresolved, 1, "the unknown SID");
    let t = st.tasks.as_ref().expect("a tasks step");
    assert_eq!((t.hosts, t.hosts_complete, t.edges), (3, 3, 3));
    assert_eq!(t.edge_host_ids.len(), 2, "WS01 and DC01");
    assert_eq!(st.edge_host_ids.len(), 1, "APP01's service");

    let at = |rid: u32| g.lookup(&format!("{D}-{rid}")).unwrap();
    let edge = |from: u32, to: u32| {
        g.inner()
            .edges_connecting(at(from), at(to))
            .find(|e| *e.weight() == EdgeKind::HasStoredCredential)
            .map(|e| petgraph::visit::EdgeRef::id(&e))
    };
    let e = edge(1002, 1201).expect("WS01 stores svc_backup in a task");
    assert_eq!(g.edge_source_name(e), Some(task_source().as_str()));
    assert!(edge(1002, 1104).is_some(), "DAVE's task is an edge too");

    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = found[0];
    assert_eq!(f.sources, [task_source(), source()], "sorted");
    assert_eq!(f.requires.len(), 2, "APP01's services, WS01's tasks");
    assert!(
        f.summary
            .contains("The built-in collector reports 2 scheduled tasks or services"),
        "{}",
        f.summary
    );
    assert!(
        f.summary
            .contains("service and scheduled task configuration"),
        "{}",
        f.summary
    );
    let details: Vec<&str> = f
        .affected
        .iter()
        .filter_map(|x| x.detail.as_deref())
        .collect();
    assert!(
        details
            .contains(&"Scheduled task \\Backups\\Nightly (disabled), as reported by the computer"),
        "{details:?}"
    );
    assert!(
        f.remediation
            .contains("the scheduled task \\Backups\\Nightly"),
        "{}",
        f.remediation
    );
    assert!(!f.summary.contains("DC01"), "{}", f.summary);

    // Completeness has both columns.
    let c = &a.posture.completeness[0];
    assert_eq!(c.task_credentials_collected, Some(3));
    assert_eq!(c.tasks_words().as_deref(), Some("3/3"));
    let html = a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains("<th>Services read</th><th>Tasks read</th>"));
    assert!(html.contains(pathwarden_core::posture::TASK_CREDENTIALS_DEF));
    std::fs::remove_dir_all(&dir).ok();
}

/// Only tasks: the finding speaks of scheduled tasks alone.
#[test]
fn tasks_alone_say_tasks() {
    let mut s = with_tasks();
    s["hosts"][0]["stored"] = json!([]);
    let dir = with_sidecar("tasks-only", &s);
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let f = pw033(&a)[0];
    assert_eq!(f.sources, [task_source()]);
    assert!(
        f.summary
            .contains("The built-in collector reports 1 scheduled task that runs as "),
        "{}",
        f.summary
    );
    assert!(
        f.summary.contains(") and stores its password on "),
        "{}",
        f.summary
    );
    assert!(
        f.summary
            .contains("computers' scheduled task configuration"),
        "{}",
        f.summary
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// One host storing the account in a service and a task: one edge, one
/// finding that needs the host read again by both.
#[test]
fn a_service_and_a_task_on_one_host_need_both_reads() {
    let mut s = with_tasks();
    s["hosts"][0]["stored"].as_array_mut().unwrap().push(json!({
        "via": "task", "name": "\\Sync", "account": "CORP\\svc_backup", "logon_type": "Password"
    }));
    let dir = with_sidecar("both-kinds", &s);
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let f = pw033(&a)[0];
    assert_eq!(f.requires.len(), 3, "APP01 twice, WS01's tasks");
    let details: Vec<&str> = f
        .affected
        .iter()
        .filter_map(|x| x.detail.as_deref())
        .collect();
    assert!(
        details.contains(&"Service SqlAgent; scheduled task \\Sync, as reported by the computer"),
        "{details:?}"
    );
    // Read again: APP01's services in full but its tasks not: held.
    let second_dir = with_sidecar(
        "both-kinds-2",
        &with_tasks_fixed(("complete", "not_collected"), ("complete", "complete")),
    );
    let second = run(&[testdata("opengraph/ad"), second_dir.clone()]);
    let (status, verdict, details) = after_from(&s, &second);
    assert_eq!(status, Status::Open);
    assert_eq!(verdict, Verdict::CantTell, "{details:?}");
    for d in [dir, second_dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// [`after`], from a first run of `first_sidecar`.
fn after_from(first_sidecar: &Value, second: &Run) -> (Status, Verdict, Vec<String>) {
    let dir = with_sidecar("t-first", first_sidecar);
    let first = run(&[testdata("opengraph/ad"), dir.clone()]);
    std::fs::remove_dir_all(&dir).ok();
    let fp = pw033(&first.a)[0].fingerprint.clone();
    let r1 = state::reconcile(&FindingsState::default(), &first.a.findings, 100, false);
    let before = stored_keys(&first.sources);
    let scope = ResolveScope::domains(&second.a.domains, true)
        .with_sources(second.sources.clone(), &before);
    let r2 = state::reconcile_scoped(&r1.state, &second.a.findings, 200, false, &scope);
    let status = r2.state.findings[&fp].status;
    let base = Baseline::from_views(
        first.a.findings.iter().map(FindingView::from).collect(),
        "test",
    );
    let current: Vec<FindingView> = second.a.findings.iter().map(FindingView::from).collect();
    let coverage = Coverage {
        domains: second.a.domains.clone(),
        complete: true,
        sources: second.sources.clone(),
        ..Default::default()
    }
    .compared_with(&before);
    let selection = Selection {
        rules: vec!["PW-033".into()],
        ..Selection::default()
    };
    let r = retest::compare(&base, &current, &coverage, &selection).unwrap();
    (status, r.results[0].verdict, r.results[0].details.clone())
}

/// Fixed only when every computer that held the credential was read again
/// in full by the step that found it there: WS01's tasks, APP01's
/// services. DC01 held it too (in-tier), and is read in full each time.
#[test]
fn tasks_fixed_only_when_every_host_was_read_again() {
    let ad = testdata("opengraph/ad");
    let c = "complete";
    let cases: Vec<(&str, Option<Value>, Status, Verdict)> = vec![
        (
            "both read in full",
            Some(with_tasks_fixed((c, c), (c, c))),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "WS01's services unread, its tasks read: still fixed",
            Some(with_tasks_fixed((c, c), ("not_collected", c))),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "WS01's tasks denied",
            Some(with_tasks_fixed((c, c), (c, "not_collected"))),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "WS01's tasks partly read",
            Some(with_tasks_fixed((c, c), (c, "partial"))),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "APP01's tasks unread, its services read: still fixed",
            Some(with_tasks_fixed((c, "not_collected"), (c, c))),
            Status::Resolved,
            Verdict::Fixed,
        ),
        (
            "still stored",
            Some(with_tasks()),
            Status::Open,
            Verdict::StillOpen,
        ),
        (
            "a file from before tasks were read",
            Some(fixed("complete")),
            Status::Open,
            Verdict::CantTell,
        ),
        (
            "no stored credentials file",
            None,
            Status::Open,
            Verdict::CantTell,
        ),
    ];
    for (what, sidecar, status, verdict) in cases {
        let mut inputs = vec![ad.clone()];
        let dir = sidecar.map(|s| with_sidecar("t-second", &s));
        inputs.extend(dir.clone());
        let second = run(&inputs);
        let (got, v, details) = after_from(&with_tasks(), &second);
        assert_eq!(got, status, "{what}");
        assert_eq!(v, verdict, "{what}: {details:?}");
        if let Some(d) = dir {
            std::fs::remove_dir_all(&d).ok();
        }
    }
}

/// Task reads turned off: "off" in completeness, the finding held with
/// that reason, and the services still counted.
#[test]
fn turned_off_task_reads_say_so() {
    let mut s = with_tasks_fixed(("complete", "not_collected"), ("complete", "not_collected"));
    s["tasks"] = json!({
        "status": "not_collected",
        "reason": "task reads were turned off for this collection"
    });
    s["tasks_turned_off"] = json!(true);
    s["hosts"][2]["tasks"] = json!({ "status": "not_collected" });
    let dir = with_sidecar("t-off", &s);
    let second = run(&[testdata("opengraph/ad"), dir.clone()]);
    let c = &second.a.posture.completeness[0];
    assert!(c.task_credentials_off && !c.stored_credentials_off);
    assert_eq!(c.task_credentials_collected, None);
    assert_eq!(c.stored_credentials_collected, Some(3));
    assert_eq!(c.tasks_words().as_deref(), Some("off"));
    let html = second.a.report_html(1_800_000_000, &mut analyze::Quiet);
    assert!(html.contains("<th>Tasks read</th>"));
    assert!(html.contains(pathwarden_core::posture::TASK_CREDENTIALS_OFF_DEF));
    let (status, verdict, details) = after_from(&with_tasks(), &second);
    assert_eq!(status, Status::Open);
    assert_eq!(verdict, Verdict::CantTell);
    assert!(
        details.iter().any(|d| d.contains("turned off")),
        "{details:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Computers whose tasks gave an edge last time and weren't read in full
/// this time hold what rests on them, and say so as tasks.
#[test]
fn missing_task_reads_hold_paths_and_say_so() {
    let first_dir = with_sidecar("t-hold1", &with_tasks());
    let first = run(&[testdata("opengraph/ad"), first_dir.clone()]);
    let before = stored_keys(&first.sources);
    assert_eq!(before.len(), 3, "APP01's services, WS01's and DC01's tasks");
    let mut s = with_tasks_fixed(("complete", "complete"), ("complete", "complete"));
    s["hosts"][2]["tasks"] = json!({ "status": "not_collected", "reason": "not reached" });
    let second_dir = with_sidecar("t-hold2", &s);
    let second = run(&[testdata("opengraph/ad"), second_dir.clone()]);
    let missing: Vec<String> = second
        .sources
        .missing_hosts_since(&before)
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(missing.len(), 1, "DC01's tasks");
    assert_eq!(
        second.sources.describe(&missing),
        "scheduled tasks not read in full on 1 computer that stored a credential when last read"
    );
    for d in [first_dir, second_dir] {
        std::fs::remove_dir_all(&d).ok();
    }
}

/// TaskHound and the built-in collector's tasks for the same account:
/// one finding with every source.
#[test]
fn taskhound_and_native_tasks_give_one_finding() {
    let dir = with_sidecar("t-th", &with_tasks());
    let a = analyze(&[
        testdata("opengraph/ad"),
        testdata("opengraph/taskhound"),
        dir.clone(),
    ]);
    let found = pw033(&a);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        found[0].sources,
        [task_source(), source(), "TaskHound".to_string()]
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A hostile file's task entries: secret-looking fields, a made-up logon
/// type and oversize names never reach an output.
#[test]
fn hostile_task_entries_leak_nothing() {
    let mut s = with_tasks();
    let task = &mut s["hosts"][1]["stored"][0];
    task["arguments"] = json!("/p Hunter2!arg");
    task["password"] = json!("Hunter2!pw");
    task["logon_type"] = json!("Hunter2!type");
    s["hosts"][1]["stored"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "via": "task", "name": "y".repeat(10_000), "account": "CORP\\dave" }));
    let dir = with_sidecar("t-hostile", &s);
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let mut out = String::new();
    out += &serde_json::to_string(&a.findings).unwrap();
    out += &serde_json::to_string(&a.plan).unwrap();
    out += &serde_json::to_string(&a.posture).unwrap();
    out += &serde_json::to_string(&a.stats).unwrap();
    out += &a.report_html(1_800_000_000, &mut analyze::Quiet);
    out += &String::from_utf8_lossy(&explore::encode(&a.graph, &a.findings, &a.zones));
    assert!(!out.contains("Hunter2"), "a secret reached an output");
    assert!(!out.contains(&"y".repeat(300)));
    assert_eq!(pw033(&a).len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Targeted retest of PW-033 (slice 3) ----
//
// The computers that store the password are read again, through their
// services and scheduled tasks.

use pathwarden_core::retest::targeted::{
    HostRead, HostReads, Slice, SliceHost, HOSTS_NEED_PASSWORD,
};

/// The run's slice, as stored with it.
fn slice_of(a: &Analysis) -> Slice {
    let s = Slice::build(&a.graph, &a.stats.trusts, &a.findings);
    serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap()
}

/// The re-read: the AD fixture's objects with `ids`, and `sidecar` as the
/// computers' services and tasks read again.
fn reread(ids: &[String], sidecar: &Value) -> pathwarden_core::graph::AdGraph {
    reread_with(ids, sidecar, |_| {})
}

/// [`reread`], each object changed by `edit` first.
fn reread_with(
    ids: &[String],
    sidecar: &Value,
    edit: impl Fn(&mut Value),
) -> pathwarden_core::graph::AdGraph {
    let mut ing = pathwarden_core::ingest::Ingestor::new();
    for file in ["users", "computers", "groups", "domains"] {
        let text =
            std::fs::read_to_string(testdata(&format!("opengraph/ad/corp_{file}.json"))).unwrap();
        let mut doc: Value = serde_json::from_str(&text).unwrap();
        let data = doc["data"].as_array_mut().unwrap();
        data.retain(|o| {
            ids.iter()
                .any(|i| i == o["ObjectIdentifier"].as_str().unwrap())
        });
        data.iter_mut().for_each(&edit);
        doc["meta"]["count"] = (data.len() as u64).into();
        ing.ingest_text(&format!("{file}.json"), &doc.to_string())
            .unwrap();
    }
    ing.ingest_text(storedcreds::FILE_NAME, &sidecar.to_string())
        .unwrap();
    ing.finish().0
}

/// What the collector says of one computer's services: read in full, or
/// not and why.
fn services_read(rid: u32, name: &str, read: bool, why: Option<&str>) -> HostRead {
    HostRead {
        id: format!("{D}-{rid}"),
        name: name.into(),
        services: Some(read),
        tasks: Some(read),
        why: why.map(str::to_string),
        ..HostRead::default()
    }
}

/// The password stored by a service: a computer whose services were read
/// but whose tasks were denied or switched off can't be told clean (the
/// password may have moved to a task).
#[test]
fn a_part_not_read_is_a_gap() {
    let dir = with_sidecar("retest-gap", &vulnerable());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let s = slice_of(&a);
    let fp = pw033(&a)[0].fingerprint.clone();
    let ids = s.finding(&fp).unwrap().refresh.clone();
    let clean = reread(&ids, &fixed("complete"));
    for why in [
        "The C$ share refused access.",
        "Its scheduled tasks weren't checked, because task reads are turned off.",
    ] {
        let mut reads = both_read();
        reads.reads[1].tasks = Some(false);
        reads.reads[1].why = Some(why.into());
        let r = s.retest_with(&fp, &clean, &reads, NOW).unwrap();
        assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
        // One period, the reason's own.
        assert_eq!(r.details[1], format!("WS01.CORP.LOCAL: {why}"));
    }
    // Tasks never reported at all (an older collector): the same.
    let mut reads = both_read();
    reads.reads[0].tasks = None;
    let r = s.retest_with(&fp, &clean, &reads, NOW).unwrap();
    assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
    std::fs::remove_dir_all(&dir).ok();
}

/// SVC_BACKUP renamed since the run: the computers still store its
/// password under the old name, which the directory no longer gives. It
/// resolves against the run's names, so the finding stays open.
#[test]
fn a_renamed_account_is_still_stored() {
    let dir = with_sidecar("retest-renamed", &vulnerable());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let s = slice_of(&a);
    let fp = pw033(&a)[0].fingerprint.clone();
    let ids = s.finding(&fp).unwrap().refresh.clone();
    let renamed = reread_with(&ids, &vulnerable(), |o| {
        if o["ObjectIdentifier"] == format!("{D}-1201") {
            o["Properties"]["name"] = json!("SVC_NEWNAME@CORP.LOCAL");
            o["Properties"]["samaccountname"] = json!("svc_newname");
            o["Properties"]["userprincipalname"] = json!("svc_newname@corp.local");
        }
    });
    let r = s.retest_with(&fp, &renamed, &both_read(), NOW).unwrap();
    assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
    // And clean once neither stores it.
    let gone = reread_with(&ids, &fixed("complete"), |o| {
        if o["ObjectIdentifier"] == format!("{D}-1201") {
            o["Properties"]["name"] = json!("SVC_NEWNAME@CORP.LOCAL");
        }
    });
    let r = s.retest_with(&fp, &gone, &both_read(), NOW).unwrap();
    assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");
    std::fs::remove_dir_all(&dir).ok();
}

fn both_read() -> HostReads {
    HostReads {
        reads: vec![
            services_read(1001, "APP01.CORP.LOCAL", true, None),
            services_read(1002, "WS01.CORP.LOCAL", true, None),
        ],
        skipped: None,
        deleted: Vec::new(),
    }
}

const NOW: i64 = 1_791_417_600;

/// SVC_BACKUP's password stored by services on APP01 and WS01: the retest
/// reads those two computers' services. Fixed when neither stores it any
/// more; still open when one does; "can't tell" when one couldn't be read
/// and the other doesn't store it, naming it and why.
#[test]
fn a_stored_password_is_retested_on_the_computers_that_store_it() {
    let dir = with_sidecar("retest", &vulnerable());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let s = slice_of(&a);
    let fp = pw033(&a)[0].fingerprint.clone();
    let sf = s.finding(&fp).unwrap();
    assert!(sf.targetable(), "{:?}", sf.unsupported);
    // The two computers outside Tier Zero, through their services; the
    // DC's own copy is in-tier.
    let host = |rid: u32| SliceHost {
        id: format!("{D}-{rid}"),
        services: true,
        ..SliceHost::default()
    };
    assert_eq!(s.hosts_of(sf), [host(1001), host(1002)]);
    let ids = sf.refresh.clone();
    for id in [
        format!("{D}-1201"),
        format!("{D}-1001"),
        format!("{D}-1002"),
    ] {
        assert!(ids.contains(&id), "{id} in {ids:?}");
    }

    // Read again, both still store it: still open.
    let r = s
        .retest_with(&fp, &reread(&ids, &vulnerable()), &both_read(), NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
    assert_eq!((r.hosts_read, r.hosts), (2, 2));

    // Neither does: fixed.
    let r = s
        .retest_with(&fp, &reread(&ids, &fixed("complete")), &both_read(), NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");

    // WS01 denied, APP01 clean: the slice's WS01 copy decides nothing.
    let mut denied = both_read();
    denied.reads[1] = services_read(1002, "WS01.CORP.LOCAL", false, Some("access denied"));
    let mut partial = fixed("partial");
    partial["hosts"][1]["services"]["status"] = json!("not_collected");
    let r = s
        .retest_with(&fp, &reread(&ids, &partial), &denied, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
    assert_eq!(
        r.details,
        [
            "1 of 2 computers on its path couldn't be read, so it can't be checked.",
            "WS01.CORP.LOCAL: access denied."
        ]
    );
    assert_eq!(r.hosts_read, 1);

    // WS01 denied, APP01 still stores it: still open with what was read.
    let r = s
        .retest_with(&fp, &reread(&ids, &vulnerable()), &denied, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");

    // Nothing read (the computers can't be read with this sign-in).
    let none = HostReads {
        reads: Vec::new(),
        skipped: Some(HOSTS_NEED_PASSWORD.into()),
        deleted: Vec::new(),
    };
    let r = s
        .retest_with(&fp, &reread(&ids, &fixed("complete")), &none, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::CantTell);
    assert_eq!(r.details, [HOSTS_NEED_PASSWORD]);

    // Read, but the services switch was off: can't tell, and why.
    let off = "service reads were turned off for this collection";
    let switched = HostReads {
        reads: vec![
            services_read(1001, "APP01.CORP.LOCAL", false, Some(off)),
            services_read(1002, "WS01.CORP.LOCAL", false, Some(off)),
        ],
        skipped: None,
        deleted: Vec::new(),
    };
    let r = s
        .retest_with(&fp, &reread(&ids, &fixed("complete")), &switched, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::CantTell);
    assert_eq!(r.details[1], format!("APP01.CORP.LOCAL: {off}."));
    std::fs::remove_dir_all(&dir).ok();
}

/// A password a scheduled task stores is checked on the tasks: a computer
/// whose services were read but not its tasks can't tell.
#[test]
fn a_stored_task_password_needs_the_tasks_read() {
    let dir = with_sidecar("retest-tasks", &with_tasks());
    let a = analyze(&[testdata("opengraph/ad"), dir.clone()]);
    let s = slice_of(&a);
    let fp = pw033(&a)[0].fingerprint.clone();
    let sf = s.finding(&fp).unwrap();
    assert!(sf.targetable(), "{:?}", sf.unsupported);
    let hosts = s.hosts_of(sf);
    assert!(hosts.iter().any(|h| h.tasks && !h.services), "{hosts:?}");
    let ids = sf.refresh.clone();
    // Every computer's services read, not its tasks.
    let reads = HostReads {
        reads: hosts
            .iter()
            .map(|h| HostRead {
                id: h.id.clone(),
                name: h.id.clone(),
                services: Some(true),
                tasks: Some(false),
                why: Some("task reads were turned off for this collection".into()),
                ..HostRead::default()
            })
            .collect(),
        skipped: None,
        deleted: Vec::new(),
    };
    let clean = with_tasks_fixed(("complete", "complete"), ("complete", "complete"));
    let r = s
        .retest_with(&fp, &reread(&ids, &clean), &reads, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::CantTell, "{r:?}");
    // Both read: fixed.
    let mut all = reads.clone();
    for h in all.reads.iter_mut() {
        h.tasks = Some(true);
        h.why = None;
    }
    let r = s
        .retest_with(&fp, &reread(&ids, &clean), &all, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::Fixed, "{r:?}");
    // Still stored by the task: still open.
    let r = s
        .retest_with(&fp, &reread(&ids, &with_tasks()), &all, NOW)
        .unwrap();
    assert_eq!(r.verdict, Verdict::StillOpen, "{r:?}");
    std::fs::remove_dir_all(&dir).ok();
}

/// TaskHound's data can't be read again: a finding it backs keeps saying
/// how to retest it.
#[test]
fn taskhound_findings_are_still_retested_by_collecting() {
    let dir = with_sidecar("retest-th", &vulnerable());
    let a = analyze(&[
        testdata("opengraph/ad"),
        testdata("opengraph/taskhound"),
        dir.clone(),
    ]);
    let s = slice_of(&a);
    let sf = s.finding(&pw033(&a)[0].fingerprint).unwrap();
    assert!(!sf.targetable());
    assert!(
        sf.unsupported.as_deref().unwrap().contains("TaskHound"),
        "{:?}",
        sf.unsupported
    );
    std::fs::remove_dir_all(&dir).ok();
}
