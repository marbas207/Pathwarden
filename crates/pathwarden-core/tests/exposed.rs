//! The accounts behind the plan's counts: on the lab forest and the
//! demo, each step's list holds as many accounts as the step says it cuts
//! off, every path runs from the account through the step to Tier Zero,
//! and the keys a run keeps count the accounts the posture counts.

use std::path::PathBuf;

use pathwarden_core::analyze::{self, Quiet};
use pathwarden_core::config::Config;
use pathwarden_core::exposed::{self, ExposedRecord, ExposureLists};
use pathwarden_core::object_index::ObjectIndex;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn check(input: PathBuf) {
    let a = analyze::run(
        std::slice::from_ref(&input),
        &Config::default(),
        &[],
        &mut Quiet,
    )
    .unwrap();
    let g = &a.graph;
    let plan = &a.plan;
    let d = plan.detail.as_ref().expect("the plan keeps its accounts");
    let name = input.display();
    assert_eq!(d.exposed.len(), plan.exposed_before, "{name}");
    assert_eq!(d.exposed.len(), a.posture.tier_zero.exposed, "{name}");
    assert!(!plan.fixes.is_empty(), "{name}: a plan to check");
    assert_eq!(d.step_source.len(), plan.fixes.len());
    assert_eq!(d.step_tail.len(), plan.fixes.len());
    for (i, f) in plan.fixes.iter().enumerate() {
        let src = &d.sources[d.step_source[i]];
        assert_eq!(
            src.accounts.len(),
            f.principals_through,
            "{name}: step {}",
            i + 1
        );
        assert_eq!(g.node(src.from).name, f.from, "{name}: step {}", i + 1);
        // The tail leaves `from` by an edge the step removes and ends in
        // Tier Zero.
        let tail = &d.step_tail[i];
        let (a0, _) = g.inner().edge_endpoints(tail[0]).unwrap();
        assert_eq!(a0, src.from, "{name}: step {}", i + 1);
        assert!(
            f.edges.contains(&g.inner()[tail[0]]),
            "{name}: step {}",
            i + 1
        );
        let end = g.inner().edge_endpoints(*tail.last().unwrap()).unwrap().1;
        assert!(g.node(end).tier_zero, "{name}: step {}", i + 1);
        // Paths from the accounts to `from`, a sample of them.
        for &(acc, hops) in src.accounts.iter().take(200) {
            let path = src.path(acc).unwrap();
            assert_eq!(path.len(), hops as usize);
            let mut at = acc;
            for e in path {
                let (x, y) = g.inner().edge_endpoints(e).unwrap();
                assert_eq!(x, at);
                at = y;
            }
            assert_eq!(at, src.from);
        }
    }
    // The run's keys count what the posture counts.
    let rec = ExposedRecord::from_plan("R1", 2, g, plan).unwrap();
    assert_eq!(
        rec.sets[exposed::TIER_ZERO].count,
        a.posture.tier_zero.exposed,
        "{name}"
    );
    // Read back from the files a full run keeps, the graph finds every
    // account the keys hold. It has no logon times, so it finds the
    // inactive ones with a path too; `previous` uses its keys only when
    // the counts match.
    let mut graph = Vec::new();
    pathwarden_core::explore::encode_analysis_to(&mut graph, &a).unwrap();
    let objects = serde_json::to_vec(&ObjectIndex::from_graph(g)).unwrap();
    let t = std::time::Instant::now();
    let earlier = exposed::EarlierRun::from_files("R1", &graph, &objects).unwrap();
    eprintln!(
        "{name}: {} objects, {} exposed, the earlier graph read in {} ms",
        g.node_count(),
        earlier.keys().len(),
        t.elapsed().as_millis()
    );
    let all = earlier.keys();
    let keys = rec.sets[exposed::TIER_ZERO].keys().unwrap();
    assert!(keys.iter().all(|k| all.binary_search(k).is_ok()), "{name}");
    // The lists hold every account of every step, with paths into Tier
    // Zero, and read back as written.
    let lists = a.exposure_lists(&Default::default());
    assert!(lists.change.is_none());
    for (i, f) in plan.fixes.iter().enumerate() {
        let accounts = lists.step_accounts(i + 1).unwrap();
        assert_eq!(accounts.len(), f.principals_through);
        assert_eq!(lists.steps[i].exposed, f.principals_through);
        for acc in accounts.iter().take(200) {
            assert!(!acc.new);
            let last = acc.path.last().unwrap();
            assert!(
                a.graph
                    .nodes()
                    .any(|(_, n)| n.tier_zero && n.name == last.name),
                "{name}: {} ends at {}",
                acc.name,
                last.name
            );
        }
        // New ones first, then the closest.
        let hops: Vec<usize> = accounts.iter().map(|a| a.hops()).collect();
        assert!(
            hops.windows(2).all(|w| w[0] <= w[1]),
            "{name}: step {}",
            i + 1
        );
    }
    let bytes = serde_json::to_vec(&lists).unwrap();
    assert_eq!(ExposureLists::parse(&bytes).unwrap(), lists);
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    w.write_all(bytes).unwrap();
    w.finish().unwrap()
}

/// An earlier run kept in full in an encrypted history: its graph is read
/// through the seam, decrypted, and gives its accounts as its keys would.
#[test]
fn an_encrypted_history_gives_its_full_run_too() {
    use pathwarden_core::crypt::{self, SecretString};
    use pathwarden_core::state::{ChangeCounts, HistoryPoint};
    use pathwarden_core::store::Store;

    let a = analyze::run(
        &[repo("testdata/forest")],
        &Config::default(),
        &[],
        &mut Quiet,
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("pw-exposed-encrypted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("history")).unwrap();
    pathwarden_core::keystore::use_test_store(&dir.with_extension("keystore"));
    let before = HistoryPoint::new("R1", 100, None, &a.posture, ChangeCounts::default());
    let this = HistoryPoint::new("R2", 200, None, &a.posture, ChangeCounts::default());
    assert!(!before.exposed_keys);
    for p in [&before, &this] {
        std::fs::write(
            dir.join("history").join(format!("{}.json", p.run_id)),
            serde_json::to_vec(p).unwrap(),
        )
        .unwrap();
    }
    let folder = dir.join("runs").join("R1");
    std::fs::create_dir_all(&folder).unwrap();
    let mut graph = Vec::new();
    pathwarden_core::explore::encode_analysis_to(&mut graph, &a).unwrap();
    std::fs::write(folder.join("graph.bin.gz"), gz(&graph)).unwrap();
    let objects = serde_json::to_vec(&ObjectIndex::from_graph(&a.graph)).unwrap();
    std::fs::write(folder.join("objects.json.gz"), gz(&objects)).unwrap();

    let pass = || SecretString::from("correct horse battery staple".to_string());
    let store = Store::new(&Default::default(), Some(&dir)).unwrap();
    store.encrypt(&pass(), true).unwrap();
    assert!(!folder.join("graph.bin.gz").exists());
    // Before its passphrase is given, it can't be read; that isn't
    // remembered as a failure, so it is read once it is given.
    crypt::forget_in_process(&dir);
    let empty = dir.with_extension("keystore-empty");
    let _ = std::fs::remove_dir_all(&empty);
    pathwarden_core::keystore::use_test_store(&empty);
    let limits = exposed::Limits::of(&before);
    assert!(exposed::earlier_run(&dir, "R1", limits).is_err());
    crypt::give_passphrase(&dir, pass());

    let h = pathwarden_core::history::for_report_in(
        &dir,
        &[],
        pathwarden_core::history::This::Run("R2"),
    );
    let prev = exposed::previous(&h, this.completeness.as_ref(), a.posture.exposure_basis).unwrap();
    assert!(prev.from_full_run, "{:?}", prev.keys);
    let want = ExposedRecord::from_plan("R1", 2, &a.graph, &a.plan).unwrap();
    assert_eq!(prev.keys.ok(), want.sets[exposed::TIER_ZERO].keys());
    exposed::release_earlier();
    crypt::forget_in_process(&dir);
    for d in [&dir, &dir.with_extension("keystore"), &empty] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn lab_forest_lists_match_the_plan() {
    check(repo("testdata/forest"));
}

#[test]
fn demo_lists_match_the_plan() {
    check(repo("demo/20261001020000_PathwardenDemo.zip"));
}
