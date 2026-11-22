use super::*;

#[test]
fn leb128_and_base64_round_trip() {
    for v in [0u64, 1, 127, 128, 300, LOW, u64::MAX] {
        let mut b = Vec::new();
        leb128(&mut b, v);
        let mut at = 0;
        assert_eq!(read_leb128(&b, &mut at), Some(v));
        assert_eq!(at, b.len());
    }
    for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        let t = base64(bytes);
        assert_eq!(unbase64(&t).as_deref(), Some(bytes), "{t}");
    }
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert!(unbase64("Zm8").is_none());
    assert!(unbase64("Z===").is_none());
    assert!(unbase64("Zm=8").is_none());
}

fn round_trip(keys: &[u64]) -> KeySet {
    let set = KeySet::new(keys.iter().copied());
    let mut want = keys.to_vec();
    want.sort_unstable();
    want.dedup();
    assert_eq!(set.count, want.len());
    assert_eq!(set.keys().as_deref(), Some(want.as_slice()));
    // And through the file's JSON.
    let rec = ExposedRecord {
        sets: BTreeMap::from([(TIER_ZERO.to_string(), set.clone())]),
        ..ExposedRecord::new("R1", 2, [])
    };
    let back = ExposedRecord::parse(&rec.to_bytes()).unwrap();
    assert_eq!(back, rec);
    set
}

#[test]
fn keys_round_trip() {
    assert!(round_trip(&[]).buckets.is_empty());
    let one = round_trip(&[0x1f00_0000_0000_0005]);
    assert_eq!(one.buckets.keys().collect::<Vec<_>>(), ["1f"]);
    // The edges of the buckets and of the low bits.
    round_trip(&[
        0,
        1,
        LOW,
        LOW + 1,
        0xff00_0000_0000_0000,
        u64::MAX,
        u64::MAX - 1,
    ]);
    // Duplicates count once.
    assert_eq!(round_trip(&[5, 5, 5, 9]).count, 2);
}

/// 500,000 accounts, the size of a large domain all exposed: the keys
/// decode as they were, in at most 10 bytes each.
#[test]
fn half_a_million_keys_round_trip_within_their_size() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let keys: Vec<u64> = (0..500_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
        .collect();
    let rec = ExposedRecord::new("20261028T020000.000Z", 2, keys.iter().copied());
    let bytes = rec.to_bytes();
    assert!(
        bytes.len() < 10 * keys.len() + 16 * 1024,
        "{} bytes for {} keys",
        bytes.len(),
        keys.len()
    );
    let back = ExposedRecord::parse(&bytes).unwrap();
    let mut want = keys;
    want.sort_unstable();
    want.dedup();
    assert_eq!(back.sets[TIER_ZERO].keys().unwrap(), want);
}

fn point_of(run: &str, exposed: usize) -> HistoryPoint {
    let mut p: HistoryPoint = serde_json::from_value(serde_json::json!({
        "version": 1, "run_id": run, "at": 100, "collected_at": null,
        "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": exposed,
        "tier_zero_population": 100, "tier_zero_relevant_population": 100,
        "exposure_basis": 2, "tier_zero_objects": 1, "protection_score": null,
        "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0, "resolved": 0},
    }))
    .unwrap();
    p.exposed_keys = true;
    p
}

/// A file of another version, another run, or whose counts don't
/// match its point or its keys is not used.
#[test]
fn mismatches_are_not_used() {
    let rec = ExposedRecord::new("R1", 2, [1, 2, 3]);
    assert_eq!(rec.tier_zero_for(&point_of("R1", 3)), Ok(vec![1, 2, 3]));
    assert_eq!(rec.tier_zero_for(&point_of("R1", 4)), Err(Why::Unreadable));
    assert_eq!(rec.tier_zero_for(&point_of("R2", 3)), Err(Why::Unreadable));
    let mut damaged = rec.clone();
    damaged.sets.get_mut(TIER_ZERO).unwrap().count = 4;
    assert_eq!(
        damaged.tier_zero_for(&point_of("R1", 4)),
        Err(Why::Unreadable)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&rec.to_bytes()).unwrap();
    v["version"] = 2.into();
    assert_eq!(
        ExposedRecord::parse(v.to_string().as_bytes()),
        Err(Why::NewerFormat)
    );
    v["version"] = 1.into();
    v["key"] = "sha256".into();
    assert_eq!(
        ExposedRecord::parse(v.to_string().as_bytes()),
        Err(Why::Unreadable)
    );
    assert_eq!(ExposedRecord::parse(b"{"), Err(Why::Unreadable));
    // Keys out of order in a bucket.
    let mut bad = KeySet::new([1, 2]);
    let mut b = Vec::new();
    leb128(&mut b, 2);
    leb128(&mut b, 0);
    bad.buckets.insert("00".into(), base64(&b));
    assert_eq!(bad.keys(), None);
    bad.buckets.clear();
    bad.buckets.insert("0G".into(), "AQ==".into());
    bad.count = 1;
    assert_eq!(bad.keys(), None);
}

use crate::analysis::Relevance;
use crate::model::{EdgeKind, Node};

fn node(g: &mut AdGraph, id: &str, name: &str, kind: NodeKind) -> NodeIndex {
    let mut n = Node::placeholder(id.to_string(), kind);
    n.placeholder = false;
    n.name = name.to_string();
    g.upsert(n)
}

/// Tier Zero (DA) and a group that can write it, with three members.
/// The previous run had two of them (one under another name since),
/// an account in Tier Zero now, one disabled since, one with no path
/// now and one no longer in the directory.
fn lab() -> (AdGraph, Vec<u64>) {
    let mut g = AdGraph::new();
    let da = node(&mut g, "S-1-5-21-1-2-3-512", "DA@CORP", NodeKind::Group);
    g.node_mut(da).tier_zero = true;
    let ops = node(&mut g, "S-1-5-21-1-2-3-1100", "OPS@CORP", NodeKind::Group);
    g.add_ace_edge(ops, da, EdgeKind::GenericWrite, false);
    for (id, name) in [
        ("S-1-5-21-1-2-3-1201", "RENAMED@CORP"),
        ("S-1-5-21-1-2-3-1202", "BOB@CORP"),
        ("S-1-5-21-1-2-3-1203", "NEWBIE@CORP"),
    ] {
        let u = node(&mut g, id, name, NodeKind::User);
        g.add_edge(u, ops, EdgeKind::MemberOf);
    }
    let t0 = node(
        &mut g,
        "S-1-5-21-1-2-3-1300",
        "PROMOTED@CORP",
        NodeKind::User,
    );
    g.node_mut(t0).tier_zero = true;
    let off = node(
        &mut g,
        "S-1-5-21-1-2-3-1301",
        "GONEOFF@CORP",
        NodeKind::User,
    );
    g.node_mut(off).props.enabled = Some(false);
    g.add_edge(off, ops, EdgeKind::MemberOf);
    node(&mut g, "S-1-5-21-1-2-3-1302", "SAFE@CORP", NodeKind::User);
    let prev = [
        "S-1-5-21-1-2-3-1201",
        "S-1-5-21-1-2-3-1202",
        "S-1-5-21-1-2-3-1300",
        "S-1-5-21-1-2-3-1301",
        "S-1-5-21-1-2-3-1302",
        "S-1-5-21-1-2-3-9999",
    ];
    let mut keys: Vec<u64> = prev.iter().map(|id| key(id)).collect();
    keys.sort_unstable();
    (g, keys)
}

fn prev(keys: Result<Vec<u64>, Why>) -> PreviousExposed {
    PreviousExposed::new("R0", 50, keys)
}

#[test]
fn lists_say_who_reaches_tier_zero_now_and_who_no_longer_does() {
    let (g, keys) = lab();
    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    let detail = plan.detail.as_ref().unwrap();
    assert_eq!(detail.exposed.len(), plan.exposed_before);
    let lists = lists(&g, &plan, Some(&prev(Ok(keys))));
    // One step, OPS's write on DA, cutting off all three.
    assert_eq!(lists.steps.len(), 1);
    assert_eq!(lists.steps[0].exposed, 3);
    assert_eq!(lists.steps[0].new, 1);
    let accounts = lists.step_accounts(1).unwrap();
    let names: Vec<(&str, bool, usize)> =
        accounts.iter().map(|a| (a.name, a.new, a.hops())).collect();
    // New first, then by hops and name; a renamed account isn't new.
    assert_eq!(
        names,
        [
            ("NEWBIE@CORP", true, 2),
            ("BOB@CORP", false, 2),
            ("RENAMED@CORP", false, 2)
        ]
    );
    let path: Vec<(&str, &str)> = accounts[0].path.iter().map(|h| (h.edge, h.name)).collect();
    assert_eq!(
        path,
        [("MemberOf", "OPS@CORP"), ("GenericWrite", "DA@CORP")]
    );
    assert!(lists.step_accounts(2).is_none() && lists.step_accounts(0).is_none());
    // What changed.
    let now = lists.now_reach();
    assert_eq!(now.len(), 1);
    assert_eq!((now[0].0.name, now[0].1), ("NEWBIE@CORP", Some(1)));
    let gone: Vec<(&str, &str)> = lists
        .no_longer()
        .iter()
        .map(|a| (a.name, a.why.words()))
        .collect();
    assert_eq!(
        gone,
        [
            ("GONEOFF@CORP", "Disabled"),
            ("PROMOTED@CORP", "Now Tier Zero"),
            ("SAFE@CORP", "No path now")
        ]
    );
    let c = lists.compared().unwrap();
    assert_eq!(c.gone_unnamed, 1);
    assert_eq!(unnamed_sentence(1), "1 more is no longer in the directory.");
    assert_eq!(
        unnamed_sentence(2),
        "2 more are no longer in the directory."
    );
    assert_eq!(lists.same_total_sentence(), None);
    // Through the file and back.
    let back = ExposureLists::parse(&serde_json::to_vec(&lists).unwrap()).unwrap();
    assert_eq!(back, lists);
    // A newer file, in another shape: said so, not "can't be read".
    let newer = serde_json::json!({"version": 2, "nodes": "elsewhere"});
    assert_eq!(
        ExposureLists::parse(newer.to_string().as_bytes()),
        Err(NEWER_LISTS.to_string())
    );
    let mut damaged = serde_json::to_value(&lists).unwrap();
    damaged["sources"][0]["from"] = 999.into();
    assert!(ExposureLists::parse(damaged.to_string().as_bytes())
        .unwrap_err()
        .contains("damaged"));
}

/// At most 1,000 a step and 20,000 in all, the earlier steps first.
#[test]
fn a_page_lists_at_most_twenty_thousand() {
    let mut l = ExposureLists::default();
    for (i, exposed) in [900, 5_000, 300].into_iter().chain([1_000; 20]).enumerate() {
        l.steps.push(StepList {
            step: i + 1,
            exposed,
            ..Default::default()
        });
    }
    let listed = l.listed_per_step();
    assert_eq!(&listed[..3], [900, 1_000, 300]);
    assert_eq!(listed.iter().sum::<usize>(), LISTED_TOTAL);
    // 2,200 so far, then 17 full steps and 800 of the next.
    assert_eq!(listed[3 + 16], 1_000);
    assert_eq!(listed[3 + 17], 800);
    assert_eq!(listed[3 + 18], 0);
    assert_eq!(listed_words(1_000), LISTED_WORDS);
    assert_eq!(
        listed_words(800),
        "The first 800 are listed: new ones first, then the closest."
    );
    assert_eq!(listed_words(0), "None are listed.");
}

/// What Home keeps: what changed alone, each path written out, the
/// same accounts with the same paths and steps.
#[test]
fn change_only_keeps_what_changed_as_it_reads() {
    let (g, keys) = lab();
    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    let full = lists(&g, &plan, Some(&prev(Ok(keys))));
    let small = full.change_only();
    assert!(small.steps.is_empty() && small.sources.is_empty());
    assert!(small.nodes.len() < full.nodes.len());
    assert_eq!(small.now_reach(), full.now_reach());
    assert_eq!(small.no_longer(), full.no_longer());
    assert_eq!(small.same_total_sentence(), full.same_total_sentence());
    assert_eq!(
        small.compared().map(|c| c.gone_unnamed),
        full.compared().map(|c| c.gone_unnamed)
    );
    // Without a change: nothing.
    assert!(lists(&g, &plan, None).change_only().change.is_none());
}

/// As many came as went: the count says nothing changed, the sentence
/// says what did.
#[test]
fn the_same_total_says_who_came_and_went() {
    let (g, _) = lab();
    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    // Before: BOB, RENAMED and two who are gone now.
    let mut before: Vec<u64> = [
        "S-1-5-21-1-2-3-1201",
        "S-1-5-21-1-2-3-1202",
        "S-1-5-21-1-2-3-1302",
        "S-1-5-21-1-2-3-9999",
    ]
    .iter()
    .map(|id| key(id))
    .collect();
    before.sort_unstable();
    // NEWBIE is new; SAFE and the deleted account went: 1 against 2.
    let l = lists(&g, &plan, Some(&prev(Ok(before.clone()))));
    assert_eq!(l.same_total_sentence(), None);
    before.retain(|&k| k != key("S-1-5-21-1-2-3-9999"));
    let l = lists(&g, &plan, Some(&prev(Ok(before))));
    assert_eq!(
        l.same_total_sentence().as_deref(),
        Some("1 new account reaches Tier Zero, and 1 older account no longer does.")
    );
}

/// Without the previous run's keys: no "New" marks, the reason kept
/// (said for all but a numbers-only run); without a previous run, no
/// change at all.
#[test]
fn without_the_previous_keys_nothing_is_new() {
    let (g, _) = lab();
    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    for why in [
        Why::NoKeys,
        Why::NotKept,
        Why::NotComparable,
        Why::NewerFormat,
        Why::Unreadable,
    ] {
        let l = lists(&g, &plan, Some(&prev(Err(why))));
        assert_eq!(l.steps[0].new, 0);
        assert!(l.step_accounts(1).unwrap().iter().all(|a| !a.new));
        let c = l.change.as_ref().unwrap();
        assert_eq!(c.unavailable, Some(why));
        assert!(l.compared().is_none() && l.now_reach().is_empty());
        assert_eq!(why.sentence().is_none(), why == Why::NoKeys);
    }
    let l = lists(&g, &plan, None);
    assert!(l.change.is_none());
    assert_eq!(l.step_accounts(1).unwrap().len(), 3);
}

/// A Full run's point (sessions and local groups read) or a Quick
/// run's (neither), with `exposed` accounts.
fn run_point(run: &str, at: i64, quick: bool, exposed: usize) -> HistoryPoint {
    let mut p = point_of(run, exposed);
    p.at = at;
    p.completeness = Some(
        serde_json::from_value(serde_json::json!({
            "computers": 10, "sessions_collected": if quick { 0 } else { 10 },
            "sessions_percent": if quick { 0.0 } else { 100.0 },
            "member_computers": 10, "local_groups_collected": if quick { 0 } else { 10 },
            "local_groups_percent": if quick { 0.0 } else { 100.0 }, "low_domains": 0,
            "sessions_targeted": !quick, "local_groups_targeted": !quick,
        }))
        .unwrap(),
    );
    p
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pw-exposed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("history")).unwrap();
    std::fs::create_dir_all(dir.join(DIR)).unwrap();
    dir
}

fn write_point(dir: &Path, p: &HistoryPoint) {
    std::fs::write(
        dir.join("history").join(format!("{}.json", p.run_id)),
        serde_json::to_vec(p).unwrap(),
    )
    .unwrap();
}

fn write_keys(dir: &Path, rec: &ExposedRecord) {
    std::fs::write(
        dir.join(DIR).join(format!("{}.json", rec.run_id)),
        rec.to_bytes(),
    )
    .unwrap();
}

/// Quick and Full runs interleaved: each compares its accounts with
/// the run "What changed" compares with, the last of its kind.
#[test]
fn the_lists_compare_with_the_run_what_changed_does() {
    let dir = scratch("interleaved");
    let runs = [
        run_point("F1", 100, false, 3),
        run_point("Q1", 200, true, 2),
        run_point("F2", 300, false, 3),
        run_point("Q2", 400, true, 2),
    ];
    for (i, p) in runs.iter().enumerate() {
        write_point(&dir, p);
        write_keys(
            &dir,
            &ExposedRecord::new(
                &p.run_id,
                2,
                (0..p.tier_zero_exposed as u64).map(|k| k + i as u64),
            ),
        );
    }
    let (points, _) = crate::history::load(&dir).unwrap();
    for (this, want) in [("F2", "F1"), ("Q2", "Q1"), ("Q1", "F1")] {
        let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run(this));
        let this_point = points.iter().find(|p| p.run_id == this).unwrap();
        assert_eq!(h.before().map(|p| p.run_id.as_str()), Some(want));
        let since = crate::history::since_run_in(&dir, this).unwrap();
        assert_eq!(since.previous_run, want);
        let prev = previous(&h, this_point.completeness.as_ref(), 2).unwrap();
        assert_eq!(prev.run_id, want);
        // Q1 after F1 read other data.
        if this == "Q1" {
            assert_eq!(prev.keys, Err(Why::NotComparable));
        } else {
            assert!(prev.keys.is_ok(), "{this}: {:?}", prev.keys);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each reason the previous run's keys can't be used.
#[test]
fn each_reason_the_previous_keys_are_missing() {
    let dir = scratch("reasons");
    let this = run_point("R2", 200, false, 3);
    let full = this.completeness.clone();
    let check = |before: HistoryPoint, keys: Option<Vec<u8>>, basis: u8| {
        let _ = std::fs::remove_dir_all(dir.join("history"));
        let _ = std::fs::remove_dir_all(dir.join(DIR));
        std::fs::create_dir_all(dir.join("history")).unwrap();
        std::fs::create_dir_all(dir.join(DIR)).unwrap();
        write_point(&dir, &before);
        write_point(&dir, &this);
        if let Some(k) = keys {
            std::fs::write(dir.join(DIR).join("R1.json"), k).unwrap();
        }
        let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("R2"));
        previous(&h, full.as_ref(), basis).unwrap().keys
    };
    let good = ExposedRecord::new("R1", 2, [1, 2, 3]).to_bytes();
    let before = run_point("R1", 100, false, 3);
    assert_eq!(
        check(before.clone(), Some(good.clone()), 2),
        Ok(vec![1, 2, 3])
    );
    let mut numbers = before.clone();
    numbers.exposed_keys = false;
    assert_eq!(check(numbers, Some(good.clone()), 2), Err(Why::NoKeys));
    assert_eq!(check(before.clone(), None, 2), Err(Why::NotKept));
    assert_eq!(
        check(before.clone(), Some(good.clone()), 3),
        Err(Why::NotComparable)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    v["version"] = 9.into();
    assert_eq!(
        check(before.clone(), Some(v.to_string().into_bytes()), 2),
        Err(Why::NewerFormat)
    );
    let mut more = before.clone();
    more.tier_zero_exposed = 4;
    assert_eq!(check(more, Some(good.clone()), 2), Err(Why::Unreadable));
    // No earlier run: nothing to compare with.
    let h = crate::history::ReportHistory::default();
    assert!(previous(&h, full.as_ref(), 2).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each environment keeps its latest ten runs' keys and its latest of
/// each kind; a run added after a newer one doesn't count as the
/// latest of its kind.
#[test]
fn the_latest_ten_and_the_latest_of_each_kind_are_kept() {
    let mut points = vec![run_point("Q00", 1, true, 1)];
    for i in 1..=12 {
        points.push(run_point(&format!("F{i:02}"), 1 + i, false, 1));
    }
    let mut other = run_point("OTHER", 1, true, 1);
    other.scopes = vec!["other".into()];
    points.push(other);
    let keep = kept_runs(&points);
    let mut kept: Vec<&str> = keep.iter().map(String::as_str).collect();
    kept.sort_unstable();
    assert_eq!(
        kept,
        ["F03", "F04", "F05", "F06", "F07", "F08", "F09", "F10", "F11", "F12", "OTHER", "Q00"]
    );
    // A newer Quick run added after the fact: Q00 stays the one kept.
    let mut late = run_point("Q99", 0, true, 1);
    late.inserted = true;
    points.push(late);
    let keep = kept_runs(&points);
    assert!(keep.contains("Q00") && !keep.contains("Q99"));
}

/// A weekly Full run with ten Quick runs between: the history keeps
/// the last Full run's keys, and the new Full run's lists compare
/// with them after the history was pruned.
#[test]
fn a_full_run_after_ten_quick_runs_compares_with_the_last_full_one() {
    let dir = scratch("weekly");
    let mut runs = vec![run_point("F1", 100, false, 3)];
    for i in 0..10 {
        runs.push(run_point(&format!("Q{i:02}"), 200 + i, true, 2));
    }
    runs.push(run_point("F2", 300, false, 3));
    for (i, p) in runs.iter().enumerate() {
        write_point(&dir, p);
        write_keys(
            &dir,
            &ExposedRecord::new(
                &p.run_id,
                2,
                (0..p.tier_zero_exposed as u64).map(|k| k + i as u64),
            ),
        );
    }
    let store = crate::store::Store::new(&Default::default(), Some(&dir)).unwrap();
    // Q00, the oldest Quick run, goes; F1 stays.
    assert_eq!(store.prune_exposed().unwrap(), 1);
    assert!(dir.join(DIR).join("F1.json").is_file());
    assert!(!dir.join(DIR).join("Q00.json").exists());
    let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("F2"));
    let prev = previous(&h, runs[11].completeness.as_ref(), 2).unwrap();
    assert_eq!(prev.run_id, "F1");
    assert_eq!(prev.keys, Ok(vec![0, 1, 2]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The previous run of [`lab`] as its full run kept it: all six
/// accounts in OPS (the one deleted since as GONE@CORP), none in Tier
/// Zero, none disabled.
fn lab_then() -> AdGraph {
    let mut g = AdGraph::new();
    let da = node(&mut g, "S-1-5-21-1-2-3-512", "DA@CORP", NodeKind::Group);
    g.node_mut(da).tier_zero = true;
    let ops = node(&mut g, "S-1-5-21-1-2-3-1100", "OPS@CORP", NodeKind::Group);
    g.add_ace_edge(ops, da, EdgeKind::GenericWrite, false);
    for (id, name) in [
        ("S-1-5-21-1-2-3-1201", "OLDNAME@CORP"),
        ("S-1-5-21-1-2-3-1202", "BOB@CORP"),
        ("S-1-5-21-1-2-3-1300", "PROMOTED@CORP"),
        ("S-1-5-21-1-2-3-1301", "GONEOFF@CORP"),
        ("S-1-5-21-1-2-3-1302", "SAFE@CORP"),
        ("S-1-5-21-1-2-3-9999", "GONE@CORP"),
    ] {
        let u = node(&mut g, id, name, NodeKind::User);
        g.add_edge(u, ops, EdgeKind::MemberOf);
    }
    g
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    w.write_all(bytes).unwrap();
    w.finish().unwrap()
}

/// Writes `g` as run `run`'s full run in the history in `dir`.
fn write_full_run(dir: &Path, run: &str, g: &AdGraph) {
    let folder = dir.join(crate::store::BUNDLE_DIR).join(run);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join(FULL_RUN_GRAPH),
        gz(&crate::explore::encode(g, &[], &[])),
    )
    .unwrap();
    let index = crate::object_index::ObjectIndex::from_graph(g);
    std::fs::write(
        folder.join(FULL_RUN_OBJECTS),
        gz(&serde_json::to_vec(&index).unwrap()),
    )
    .unwrap();
}

/// A previous run without keys but with its full run: its accounts come
/// from its graph, so What changed lists who no longer reaches Tier
/// Zero, each with its path then, and names the one deleted since.
#[test]
fn an_earlier_run_without_keys_is_read_from_its_full_run() {
    let dir = scratch("full-run");
    let mut before = run_point("R1", 100, false, 6);
    before.exposed_keys = false;
    // Its graph: six users of nine objects.
    before.tier_zero_population = 6;
    let this = run_point("R2", 200, false, 3);
    write_point(&dir, &before);
    write_point(&dir, &this);
    write_full_run(&dir, "R1", &lab_then());
    let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("R2"));
    let prev = previous(&h, this.completeness.as_ref(), 2).unwrap();
    assert!(prev.from_full_run);
    let (g, keys) = lab();
    assert_eq!(prev.keys, Ok(keys));
    // Read once for both the keys and the paths.
    let again = earlier_run(&dir, "R1", Limits::of(&before))
        .unwrap()
        .unwrap();
    assert_eq!(again.keys(), prev.earlier().unwrap().keys());

    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    let l = lists(&g, &plan, Some(&prev));
    let c = l.compared().unwrap();
    assert!(c.from_full_run);
    // NEWBIE is new; the renamed account is not.
    let now: Vec<&str> = l.now_reach().iter().map(|(a, _)| a.name).collect();
    assert_eq!(now, ["NEWBIE@CORP"]);
    type Row<'a> = (&'a str, Gone, Vec<(&'a str, &'a str)>);
    let gone: Vec<Row> = l
        .no_longer()
        .into_iter()
        .map(|a| {
            let path = a.path.iter().map(|h| (h.edge, h.name)).collect();
            (a.name, a.why, path)
        })
        .collect();
    let then = vec![("MemberOf", "OPS@CORP"), ("GenericWrite", "DA@CORP")];
    assert_eq!(
        gone,
        [
            ("GONE@CORP", Gone::NotInDirectory, then.clone()),
            ("GONEOFF@CORP", Gone::Disabled, then.clone()),
            ("PROMOTED@CORP", Gone::NowTierZero, then.clone()),
            ("SAFE@CORP", Gone::NoPath, then.clone()),
        ]
    );
    assert_eq!(c.gone_unnamed, 0);
    assert!(l.earlier_paths());
    // Home's copy keeps the paths; the file reads back as written.
    assert_eq!(l.change_only().no_longer(), l.no_longer());
    let back = ExposureLists::parse(&serde_json::to_vec(&l).unwrap()).unwrap();
    assert_eq!(back, l);

    // A graph that doesn't count what the run counted is not used.
    let mut more = before.clone();
    more.tier_zero_exposed = 7;
    write_point(&dir, &more);
    let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("R2"));
    let prev = previous(&h, this.completeness.as_ref(), 2).unwrap();
    assert_eq!(prev.keys, Err(Why::NoKeys));
    assert!(!prev.from_full_run);
    // Nor one of a run that read other data.
    write_point(&dir, &before);
    let quick = run_point("R2", 200, true, 3);
    write_point(&dir, &quick);
    let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("R2"));
    let prev = previous(&h, quick.completeness.as_ref(), 2).unwrap();
    assert!(prev.keys.is_err() && !prev.from_full_run);
    let _ = std::fs::remove_dir_all(&dir);
}

/// With the previous run's keys and its full run, the keys say who is
/// new and the graph adds each gone account's path then; without its
/// full run, the gone accounts have no path and the deleted one is
/// counted.
#[test]
fn kept_keys_take_their_paths_from_the_full_run_when_there_is_one() {
    let dir = scratch("keys-and-full-run");
    let mut before = run_point("R1", 100, false, 6);
    before.tier_zero_population = 6;
    let this = run_point("R2", 200, false, 3);
    write_point(&dir, &before);
    write_point(&dir, &this);
    let (g, keys) = lab();
    write_keys(&dir, &ExposedRecord::new("R1", 2, keys.iter().copied()));
    let plan = crate::remediation::plan(&g, &Relevance::new(&g, 0, 90));
    let h = crate::history::for_report_in(&dir, &[], crate::history::This::Run("R2"));
    let l = lists(
        &g,
        &plan,
        previous(&h, this.completeness.as_ref(), 2).as_ref(),
    );
    assert!(!l.earlier_paths() && l.compared().unwrap().gone_unnamed == 1);
    write_full_run(&dir, "R1", &lab_then());
    let prev = previous(&h, this.completeness.as_ref(), 2).unwrap();
    assert!(!prev.from_full_run);
    let l = lists(&g, &plan, Some(&prev));
    assert!(l.earlier_paths());
    assert_eq!(l.compared().unwrap().gone_unnamed, 0);
    assert!(l.no_longer().iter().all(|a| a.path.len() == 2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A planted full-run file larger than a full run takes is not read.
#[test]
fn an_oversized_full_run_is_not_read() {
    let dir = scratch("oversized");
    write_full_run(&dir, "R1", &lab_then());
    let f = std::fs::File::options()
        .write(true)
        .open(
            dir.join(crate::store::BUNDLE_DIR)
                .join("R1")
                .join(FULL_RUN_GRAPH),
        )
        .unwrap();
    f.set_len(crate::store::max_on_disk(LEGACY_FULL_RUN_FILE) + 1)
        .unwrap();
    drop(f);
    assert!(read_full_run(&dir, "R1", Limits::ANY).is_err());
    assert!(read_full_run(&dir, "R9", Limits::ANY).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full run's files are held to the limit its `run.json`
/// recorded, at most [`MAX_FULL_RUN_FILE`], and to the sizes it lists:
/// a file larger than its manifest says is refused before it is read.
#[test]
fn a_full_run_is_held_to_its_own_manifest() {
    let dir = scratch("manifest-limit");
    write_full_run(&dir, "R1", &lab_then());
    let folder = dir.join(crate::store::BUNDLE_DIR).join("R1");
    let len = |name: &str| std::fs::metadata(folder.join(name)).unwrap().len();
    let manifest = |v: serde_json::Value| {
        std::fs::write(folder.join("run.json"), v.to_string()).unwrap();
    };
    // None: the 45 MB full runs were written under.
    assert_eq!(full_run_sizes(&dir, "R1"), [LEGACY_FULL_RUN_FILE; 2]);
    manifest(serde_json::json!({ "max_file_bytes": 200u64 << 20, "files": [] }));
    assert_eq!(full_run_sizes(&dir, "R1"), [200 << 20; 2]);
    manifest(serde_json::json!({ "max_file_bytes": u64::MAX, "files": [] }));
    assert_eq!(full_run_sizes(&dir, "R1"), [MAX_FULL_RUN_FILE; 2]);
    // As listed: read.
    let (graph, objects) = (len(FULL_RUN_GRAPH), len(FULL_RUN_OBJECTS));
    manifest(serde_json::json!({
        "max_file_bytes": 75u64 << 20,
        "files": [
            { "name": FULL_RUN_GRAPH, "bytes": graph },
            { "name": FULL_RUN_OBJECTS, "bytes": objects },
        ],
    }));
    assert_eq!(full_run_sizes(&dir, "R1"), [graph, objects]);
    assert!(read_full_run(&dir, "R1", Limits::ANY).unwrap().is_some());
    // Larger than listed: refused unread.
    manifest(serde_json::json!({
        "max_file_bytes": 75u64 << 20,
        "files": [
            { "name": FULL_RUN_GRAPH, "bytes": graph },
            { "name": FULL_RUN_OBJECTS, "bytes": 10 },
        ],
    }));
    let err = read_full_run(&dir, "R1", Limits::ANY).err().unwrap();
    assert!(err.contains("larger than a full run takes"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn full_run_file(dir: &Path, run: &str, name: &str) -> PathBuf {
    dir.join(crate::store::BUNDLE_DIR).join(run).join(name)
}

/// Zeros that inflate a thousand times: refused once past a full run's
/// ratio, long before the 1 GiB a file may take at most; and the failed
/// read is remembered, so the next analysis doesn't read it again.
#[test]
fn a_zip_bomb_in_a_full_run_is_refused_early_and_once() {
    let dir = scratch("bomb");
    write_full_run(&dir, "R1", &lab_then());
    let zeros = vec![0u8; 64 << 20];
    let bomb = gz(&zeros);
    assert!(bomb.len() < 1 << 20);
    drop(zeros);
    for name in [FULL_RUN_GRAPH, FULL_RUN_OBJECTS] {
        write_full_run(&dir, "R1", &lab_then());
        std::fs::write(full_run_file(&dir, "R1", name), &bomb).unwrap();
        let err = read_full_run(&dir, "R1", Limits::ANY).unwrap_err();
        assert!(err.contains("inflate to more"), "{name}: {err}");
    }
    // The cap: 32 times the file, at least 8 MiB, at most 1 KiB an
    // object the point allows and 1 GiB.
    assert_eq!(inflate_cap(1 << 20, Limits::ANY), 32 << 20);
    assert_eq!(inflate_cap(10, Limits::ANY), 8 << 20);
    assert_eq!(inflate_cap(40 << 20, Limits::ANY), 1 << 30);
    let small = Limits {
        min_objects: 0,
        max_objects: 1_000,
    };
    assert_eq!(inflate_cap(1 << 20, small), 1_024_000);
    assert!(inflate(&gz(b"abc"), 3).is_ok() && inflate(&gz(b"abcd"), 3).is_err());
    // Remembered: the same files fail without being read.
    assert!(earlier_run(&dir, "R1", Limits::ANY).is_err());
    let again = earlier_run(&dir, "R1", Limits::ANY).unwrap_err();
    assert!(again.contains("before"), "{again}");
    // Replaced, it is read again.
    write_full_run(&dir, "R1", &lab_then());
    let e = earlier_run(&dir, "R1", Limits::ANY).unwrap().unwrap();
    assert_eq!(e.keys().len(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A graph of more or fewer objects than its point allows, an object
/// index of more objects than the graph, and a graph that isn't one are
/// all refused.
#[test]
fn a_full_run_that_disagrees_with_its_point_is_refused() {
    let g = lab_then();
    let graph = crate::explore::encode(&g, &[], &[]);
    let index = crate::object_index::ObjectIndex::from_graph(&g);
    let objects = serde_json::to_vec(&index).unwrap();
    let n = g.node_count();
    let within = |min, max| Limits {
        min_objects: min,
        max_objects: max,
    };
    assert!(EarlierRun::from_files_within("R1", &graph, &objects, within(n, n)).is_ok());
    let more = EarlierRun::from_files_within("R1", &graph, &objects, within(0, n - 1));
    assert!(more
        .unwrap_err()
        .contains("more objects than its run counted"));
    let fewer = EarlierRun::from_files_within("R1", &graph, &objects, within(n + 1, n * 9));
    assert!(fewer.unwrap_err().contains("fewer objects"));
    // An index of one more object: refused as it reads.
    let mut longer = index.clone();
    longer.objects.push(index.objects[0].clone());
    let longer = serde_json::to_vec(&longer).unwrap();
    let err = EarlierRun::from_files("R1", &graph, &longer).unwrap_err();
    assert!(err.contains("more objects than the graph has"), "{err}");
    // One fewer: they disagree.
    let mut shorter = index.clone();
    shorter.objects.pop();
    let shorter = serde_json::to_vec(&shorter).unwrap();
    assert!(EarlierRun::from_files("R1", &graph, &shorter)
        .unwrap_err()
        .contains("disagree"));
    // Not a graph, a cut one, not an index.
    assert!(EarlierRun::from_files("R1", b"nonsense", &objects).is_err());
    assert!(EarlierRun::from_files("R1", &graph[..graph.len() / 2], &objects).is_err());
    assert!(EarlierRun::from_files("R1", &graph, b"{\"objects\": 5}").is_err());
    assert!(EarlierRun::from_files("R1", &graph, b"{}").is_err());
    // Its point's limits: its population at least, 16 times what it
    // counted and 100,000 at most.
    let mut p = point_of("R1", 3);
    p.tier_zero_population = 1_000;
    p.tier_zero_objects = 10;
    assert_eq!(Limits::of(&p), within(1_000, 16_160 + 100_000));
    // Its summary widens them to twice what it collected, and some.
    assert_eq!(
        Limits::of(&p).with_collected(500_000),
        within(1_000, 1_100_000)
    );
    assert_eq!(Limits::of(&p).with_collected(10), Limits::of(&p));
}

/// A planted graph of as many objects as a real-sized point counts,
/// one of them with edges past what they may have: refused before
/// anything is made for the edges, and not read again.
#[test]
fn an_edge_bomb_with_a_real_sized_point_is_refused() {
    let dir = scratch("edge-bomb");
    let mut p = point_of("R1", 3);
    p.tier_zero_population = 1_000;
    let limits = Limits::of(&p);
    write_full_run(&dir, "R1", &lab_then());
    let bomb = crate::explore::edge_bomb(1_000, crate::explore::edge_budget(1_000) + 1);
    std::fs::write(full_run_file(&dir, "R1", FULL_RUN_GRAPH), gz(&bomb)).unwrap();
    let err = earlier_run(&dir, "R1", limits).unwrap_err();
    assert!(err.contains("more edges"), "{err}");
    let again = earlier_run(&dir, "R1", limits).unwrap_err();
    assert!(again.contains("before"), "{again}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run with far more objects than its point counts (large OpenGraph
/// data, or mostly groups and disabled accounts) is read when its
/// summary says it collected them, and refused without one.
#[test]
fn a_large_opengraph_full_run_is_not_refused() {
    let dir = scratch("large-opengraph");
    let mut p = point_of("R1", 0);
    p.tier_zero_population = 1;
    p.tier_zero_objects = 0;
    let limits = Limits::of(&p);
    let mut g = AdGraph::new();
    let n = limits.max_objects + 100;
    for i in 0..n {
        let id = format!("OG-{i}");
        let kind = if i == 0 {
            NodeKind::User
        } else {
            NodeKind::Group
        };
        node(&mut g, &id, &id, kind);
    }
    write_full_run(&dir, "R1", &g);
    let err = read_full_run(&dir, "R1", limits).unwrap_err();
    assert!(err.contains("more objects"), "{err}");
    let summary = full_run_file(&dir, "R1", "summary.json");
    std::fs::write(&summary, format!("{{\"objects\": {n}, \"files\": 1}}")).unwrap();
    let e = read_full_run(&dir, "R1", limits).unwrap().unwrap();
    assert_eq!(e.names.len(), n);
    // A summary larger than a run's takes is not read.
    let f = std::fs::File::options().write(true).open(&summary).unwrap();
    f.set_len(crate::store::max_on_disk(MAX_SUMMARY) + 1)
        .unwrap();
    drop(f);
    assert!(read_full_run(&dir, "R1", limits).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
