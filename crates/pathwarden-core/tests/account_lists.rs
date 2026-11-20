//! The account lists in the report: What changed opens to the
//! accounts that now reach Tier Zero and those that no longer do, the hero's
//! change links there, each step lists the accounts it cuts off (the first
//! 1,000), and the data the page's script draws from is safe with hostile
//! names. Why the accounts weren't compared is one sentence, and nothing
//! at all after a run that kept numbers only.

use std::path::PathBuf;

use pathwarden_core::analyze::{self, Analysis, Quiet};
use pathwarden_core::config::Config;
use pathwarden_core::exposed::{self, ExposureLists, PreviousExposed, Why};
use pathwarden_core::history::ReportHistory;
use pathwarden_core::state::{ChangeCounts, HistoryPoint};

const NOW: i64 = 1_791_417_600;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn analysis(path: &str) -> Analysis {
    analyze::run(&[repo(path)], &Config::default(), &[], &mut Quiet).unwrap()
}

/// The keys of the accounts `a` found exposed, sorted.
fn keys(a: &Analysis) -> Vec<u64> {
    let d = a.plan.detail.as_ref().unwrap();
    let mut k: Vec<u64> = d
        .exposed
        .iter()
        .map(|&ix| exposed::key(&a.graph.node(ix).id))
        .collect();
    k.sort_unstable();
    k
}

/// A history of one earlier run with `before` accounts exposed, and this
/// run.
fn history(a: &Analysis, before: usize) -> ReportHistory<'static> {
    let mut b = HistoryPoint::new(
        "r0",
        NOW - 7 * 86_400,
        None,
        &a.posture,
        ChangeCounts::default(),
    );
    b.tier_zero_exposed = before;
    ReportHistory {
        earlier: vec![b],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            &a.posture,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    }
}

fn previous(keys: Result<Vec<u64>, Why>) -> PreviousExposed {
    PreviousExposed::new("r0", NOW - 7 * 86_400, keys)
}

/// The report of `a` with `lists`, and Home's Overview of it.
fn render(a: &Analysis, h: &ReportHistory, lists: &ExposureLists) -> (String, String) {
    let html = a.report_html_lists(NOW, h, lists, &mut Quiet);
    let input = pathwarden_core::report::OverviewInput {
        posture: &a.posture,
        plan_steps: a.plan.fixes.len(),
        exposed_before: a.plan.exposed_before,
        first_step: a.plan.fixes.first(),
        collected_at: a.stats.collected_at,
        generated_at: NOW,
        history: h,
        introduced: None,
        lists: Some(lists),
    };
    (html, pathwarden_core::report::overview_fragment(&input))
}

/// The data blocks of a page, parsed.
fn data(html: &str) -> Vec<serde_json::Value> {
    const OPEN: &str = r#"<script type="application/json" class="acc-data">"#;
    html.split(OPEN)
        .skip(1)
        .map(|s| {
            let json = s.split("</script>").next().unwrap();
            assert!(
                !json.contains('<') && !json.contains('>') && !json.contains('&'),
                "{json:.300}"
            );
            serde_json::from_str(json).unwrap()
        })
        .collect()
}

const HOSTILE: &str = "EVE</script><img src=x onerror=alert(1)>@CONTOSO.LOCAL";

#[test]
fn the_report_lists_who_now_reaches_tier_zero_and_each_step_s_accounts() {
    let mut a = analysis("testdata/forest");
    let all = keys(&a);
    assert!(all.len() >= 3, "{}", all.len());
    // Two accounts are new since the last run (one with a hostile name),
    // and three that reached Tier Zero then are no longer in the directory.
    let d = a.plan.detail.as_ref().unwrap();
    let first = d.exposed[0];
    a.graph.node_mut(first).name = HOSTILE.to_string();
    let new: Vec<u64> = d
        .exposed
        .iter()
        .take(2)
        .map(|&ix| exposed::key(&a.graph.node(ix).id))
        .collect();
    let mut before: Vec<u64> = all.iter().copied().filter(|k| !new.contains(k)).collect();
    before.extend([1, 2, 3]);
    before.sort_unstable();
    let h = history(&a, before.len());
    let lists = exposed::lists(&a.graph, &a.plan, Some(&previous(Ok(before))));
    let (html, fragment) = render(&a, &h, &lists);

    // The hero's change links to What changed's accounts.
    assert!(
        html.contains(r##"<p class="hero-change"><a class="delta-link" href="#since-tier-zero" title="Show which accounts changed">"##),
        "{html:.2000}"
    );
    // The Tier Zero row opens to them: two now, three no longer.
    assert!(
        html.contains(r#"<details class="wc-more wc-accts" id="since-tier-zero">"#),
        "row"
    );
    assert!(html.contains("<b>2</b> now reach it · <b>3</b> no longer do"));
    assert!(html.contains("3 more are no longer in the directory."));
    // The hostile name is data, never markup.
    assert!(!html.contains("<img src=x"), "hostile name as markup");
    // Two data blocks: What changed's and the steps'.
    let blocks = data(&html);
    assert_eq!(blocks.len(), 2);
    let change = &blocks[0];
    assert_eq!(change["lists"]["now"]["total"], 2);
    assert_eq!(change["lists"]["now"]["rows"].as_array().unwrap().len(), 2);
    assert!(change["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n[0] == HOSTILE && n[1] == "i-user" || n[0] == HOSTILE && n[1] == "i-computer"));
    for row in change["lists"]["now"]["rows"].as_array().unwrap() {
        // Each says the step that cuts it off, and its path is shown in
        // at most three hops.
        assert!(row["s"].as_u64().is_some(), "{row}");
        assert!(row["p"].as_array().unwrap().len() <= 3, "{row}");
        assert!(row["h"].as_u64().unwrap() >= 1, "{row}");
    }
    let steps = &blocks[1];
    for (i, f) in a.plan.fixes.iter().enumerate() {
        let list = &steps["lists"][format!("step-{}", i + 1)];
        assert_eq!(list["total"], f.principals_through, "step {}", i + 1);
        let rows = list["rows"].as_array().unwrap();
        assert_eq!(rows.len(), f.principals_through.min(exposed::LISTED));
        // New ones first.
        let flags: Vec<bool> = rows.iter().map(|r| r["n"] == true).collect();
        assert!(flags.windows(2).all(|w| w[0] >= w[1]), "step {}", i + 1);
        // Its folded list, and how many are new beside its count.
        let block = html
            .split(&format!(
                r#"<details class="acc" id="step-{}-accounts">"#,
                i + 1
            ))
            .nth(1)
            .unwrap_or_else(|| panic!("step {}", i + 1));
        let n_new = lists.steps[i].new;
        assert_eq!(
            block
                .split("</summary>")
                .next()
                .unwrap()
                .contains(&format!("{n_new} new since the last run")),
            n_new > 0,
            "step {}",
            i + 1
        );
    }
    assert!(lists.steps.iter().any(|s| s.new > 0));
    // The app's Runs list links its change there.
    assert!(pathwarden_core::report::opens_change(&html));
    // Home's Overview carries What changed's lists and data, not the
    // steps'.
    assert!(fragment.contains(r#"id="since-tier-zero""#));
    assert_eq!(data(&fragment).len(), 1);
}

/// Why the accounts weren't compared: one sentence on the Tier Zero row and
/// each step; a run that kept numbers only says nothing, and nothing links.
#[test]
fn without_the_last_run_s_accounts_the_report_says_why_or_nothing() {
    let a = analysis("testdata/forest");
    let h = history(&a, a.posture.tier_zero.exposed + 4);
    for why in [Why::NotKept, Why::NotComparable, Why::NoKeys] {
        let lists = exposed::lists(&a.graph, &a.plan, Some(&previous(Err(why))));
        let (html, _) = render(&a, &h, &lists);
        assert!(!html.contains(r#"class="delta-link""#), "{why:?}");
        assert!(!html.contains(r#"id="since-tier-zero""#), "{why:?}");
        assert!(!pathwarden_core::report::opens_change(&html), "{why:?}");
        assert!(
            !html.contains("new since the last run"),
            "{why:?}: no New badge"
        );
        match why.sentence() {
            Some(s) => {
                let s = s.replace('\'', "&#39;");
                // On the Tier Zero row and in each step's list.
                assert_eq!(html.matches(&s).count(), 1 + a.plan.fixes.len(), "{why:?}");
            }
            None => assert!(!html.contains("isn&#39;t known"), "{why:?}"),
        }
        // The steps still list their accounts.
        assert_eq!(data(&html).len(), 1, "{why:?}");
    }
}

/// As many came as went: the count says nothing changed, a row says who.
#[test]
fn the_same_total_has_a_row_of_its_own() {
    let a = analysis("testdata/forest");
    let all = keys(&a);
    let mut before: Vec<u64> = all[2..].to_vec();
    before.extend([7, 8]);
    before.sort_unstable();
    let h = history(&a, before.len());
    let lists = exposed::lists(&a.graph, &a.plan, Some(&previous(Ok(before))));
    let (html, _) = render(&a, &h, &lists);
    let sentence = "2 new accounts reach Tier Zero, and 2 older accounts no longer do.";
    let row = html
        .split(r#"<details class="wc-more wc-accts" id="since-tier-zero">"#)
        .nth(1)
        .expect("the row");
    assert!(
        row.starts_with(&format!(
            r#"<summary><span class="wc-text">{sentence}</span>"#
        )),
        "{row:.400}"
    );
    // Right under "No change".
    let rows: Vec<&str> = html
        .split("<tbody>")
        .nth(1)
        .unwrap()
        .split("</tbody>")
        .next()
        .unwrap()
        .split("<tr ")
        .skip(1)
        .collect();
    assert!(rows[0].contains("No change"), "{:.300}", rows[0]);
    assert!(
        rows[1].contains(r#"id="since-tier-zero""#),
        "{:.300}",
        rows[1]
    );
    assert_eq!(data(&html).len(), 2);
}

/// A step that cuts off more than 1,000 accounts lists the first 1,000 and
/// says so; a report without a history lists them without New marks.
#[test]
fn a_long_step_lists_the_first_thousand() {
    let a = analysis("demo/20261001020000_PathwardenDemo.zip");
    let html = a.report_html(NOW, &mut Quiet);
    assert!(a.plan.fixes[0].principals_through > exposed::LISTED);
    let blocks = data(&html);
    assert_eq!(blocks.len(), 1, "no What changed without a history");
    let first = &blocks[0]["lists"]["step-1"];
    assert_eq!(first["rows"].as_array().unwrap().len(), exposed::LISTED);
    assert_eq!(first["total"], a.plan.fixes[0].principals_through);
    assert!(first["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["n"].is_null()));
    let block = html
        .split(r#"<details class="acc" id="step-1-accounts">"#)
        .nth(1)
        .unwrap();
    assert!(block.contains(r#"placeholder="Search the first 1,000 accounts""#));
    assert!(block.contains(&format!(r#"data-capped="{}""#, exposed::LISTED_WORDS)));
    assert!(!html.contains("new since the last run"));
}

/// The accounts no longer in Tier Zero's reach say why, each in a word:
/// now Tier Zero, disabled, or no path now.
#[test]
fn accounts_that_no_longer_reach_tier_zero_say_why() {
    let mut a = analysis("testdata/forest");
    let all = keys(&a);
    let reach: Vec<_> = a.plan.detail.as_ref().unwrap().exposed.clone();
    // Three users or computers with no path to Tier Zero: one joined Tier
    // Zero since, one was disabled, one lost its path.
    let others: Vec<_> = a
        .graph
        .nodes()
        .filter(|(ix, n)| {
            matches!(
                n.kind,
                pathwarden_core::model::NodeKind::User | pathwarden_core::model::NodeKind::Computer
            ) && !n.placeholder
                && !reach.contains(ix)
        })
        .map(|(ix, _)| ix)
        .take(3)
        .collect();
    assert_eq!(others.len(), 3);
    for (i, &ix) in others.iter().enumerate() {
        let n = a.graph.node_mut(ix);
        n.tier_zero = i == 0;
        n.props.enabled = Some(i != 1);
    }
    let mut before = all.clone();
    before.extend(others.iter().map(|&ix| exposed::key(&a.graph.node(ix).id)));
    before.sort_unstable();
    let h = history(&a, before.len());
    let lists = exposed::lists(&a.graph, &a.plan, Some(&previous(Ok(before))));
    let (html, _) = render(&a, &h, &lists);
    assert!(html.contains("<b>3</b> no longer do"), "brief");
    let change = &data(&html)[0];
    let gone = &change["lists"]["gone"];
    assert_eq!(gone["total"], 3);
    let mut why: Vec<(String, String)> = gone["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let n = r["a"].as_u64().unwrap() as usize;
            (
                change["nodes"][n][0].as_str().unwrap().to_string(),
                r["w"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    why.sort_by(|x, y| x.1.cmp(&y.1));
    let name = |i: usize| a.graph.node(others[i]).name.clone();
    assert_eq!(
        why,
        [
            (name(1), "Disabled".to_string()),
            (name(2), "No path now".to_string()),
            (name(0), "Now Tier Zero".to_string()),
        ]
    );
}

/// More than 1,000 accounts now reach Tier Zero, and more than 1,000 no
/// longer do: each list carries its first 1,000 and its total, and says
/// so; Home keeps the same.
#[test]
fn what_changed_lists_the_first_thousand_of_each() {
    let a = analysis("testdata/forest");
    let all = keys(&a);
    let mut before = all[1..].to_vec();
    before.push(1);
    before.sort_unstable();
    let h = history(&a, before.len() + 10);
    let mut lists = exposed::lists(&a.graph, &a.plan, Some(&previous(Ok(before))));
    // Made up: 1,500 more that now reach it, 1,200 that no longer do.
    let base = lists.nodes.len() as u32;
    for i in 0..2_700 {
        lists.nodes.push((
            format!("U{i:05}@CONTOSO.LOCAL"),
            pathwarden_core::model::NodeKind::User,
        ));
    }
    let c = lists.change.as_mut().unwrap();
    for i in 0..1_500 {
        c.now.push(exposed::NowRow {
            node: base + i,
            hops: 1,
            step: None,
            path: vec![[0, 0]],
        });
    }
    for i in 1_500..2_700 {
        c.gone.push(exposed::GoneRow {
            node: base + i,
            why: exposed::Gone::NoPath,
            path: Vec::new(),
        });
    }
    let (now, gone) = (c.now.len(), c.gone.len());
    let (html, fragment) = render(&a, &h, &lists);
    let change = &data(&html)[0];
    assert_eq!(change["lists"]["now"]["total"], now);
    assert_eq!(
        change["lists"]["now"]["rows"].as_array().unwrap().len(),
        exposed::LISTED
    );
    assert_eq!(change["lists"]["gone"]["total"], gone);
    assert_eq!(
        change["lists"]["gone"]["rows"].as_array().unwrap().len(),
        exposed::LISTED
    );
    for key in ["now", "gone"] {
        assert!(
            html.contains(&format!(
                r#"data-acc="{key}" data-kind="{key}" data-capped="The first 1,000 are listed.""#
            )),
            "{key}"
        );
    }
    assert!(html.contains(&format!(
        "<b>{}</b> now reach it · <b>{}</b> no longer do",
        pathwarden_core::text::num(now),
        pathwarden_core::text::num(gone + 1)
    )));
    // What Home keeps: the first 1,000 of each, and the same page.
    let small = lists.change_only();
    let sc = small.change.as_ref().unwrap();
    assert_eq!(
        (sc.now.len(), sc.gone.len()),
        (exposed::LISTED, exposed::LISTED)
    );
    assert_eq!((sc.now_total(), sc.gone_total()), (now, gone));
    let (_, home) = render(&a, &h, &small);
    assert_eq!(home, fragment);
}
/// The page and `runs show` say the same of an account no step cuts off.
#[test]
fn the_page_says_what_the_cli_does_of_no_step() {
    assert!(pathwarden_core::report::ACCOUNTS_JS.contains(&format!("\"{}\"", exposed::NO_STEP)));
    assert!(pathwarden_core::report::REPORT_JS.ends_with(pathwarden_core::report::ACCOUNTS_JS));
}

/// A report lists at most 20,000 accounts over all its steps: past that,
/// later steps list fewer, then none, and say how many; their counts stay.
#[test]
fn a_report_lists_at_most_twenty_thousand_accounts() {
    let a = analysis("testdata/forest");
    let mut lists = a.exposure_lists(&ReportHistory::default());
    // 24 more steps, each cutting off the same 1,000 made-up accounts.
    let base = lists.nodes.len() as u32;
    for i in 0..1_000 {
        lists.nodes.push((
            format!("S{i:04}@CONTOSO.LOCAL"),
            pathwarden_core::model::NodeKind::User,
        ));
    }
    let src = lists.sources.len();
    lists.sources.push(exposed::SourceList {
        from: 0,
        accounts: (base..base + 1_000).collect(),
        new: 0,
        next: Vec::new(),
    });
    let mut plan = a.plan.clone();
    let real = plan.fixes.len();
    for i in 0..24 {
        plan.fixes.push(plan.fixes[0].clone());
        lists.steps.push(exposed::StepList {
            step: real + i + 1,
            source: src,
            exposed: 1_000,
            new: 0,
            tail: Vec::new(),
        });
    }
    let listed = lists.listed_per_step();
    assert_eq!(listed.iter().sum::<usize>(), exposed::LISTED_TOTAL);
    assert_eq!(*listed.last().unwrap(), 0);
    let h = ReportHistory::default();
    let html = pathwarden_core::report::render_html(&pathwarden_core::report::ReportInput {
        posture: &a.posture,
        findings: &a.findings,
        plan: &plan,
        stats: &a.stats,
        domains: &a.domains,
        generated_at: NOW,
        history: &h,
        introduced: None,
        forest: None,
        lists: Some(&lists),
        kinds: None,
    });
    let blocks = data(&html);
    assert_eq!(blocks.len(), 1);
    let mut rows = 0;
    for (i, st) in lists.steps.iter().enumerate() {
        let n = i + 1;
        let list = &blocks[0]["lists"][format!("step-{n}")];
        // The count stays the step's; the rows are what it lists.
        assert_eq!(list["total"], st.exposed, "step {n}");
        assert_eq!(
            list["rows"].as_array().unwrap().len(),
            listed[i],
            "step {n}"
        );
        rows += listed[i];
        let block = html
            .split(&format!(r#"<details class="acc" id="step-{n}-accounts">"#))
            .nth(1)
            .unwrap_or_else(|| panic!("step {n}"))
            .split("</details>")
            .next()
            .unwrap();
        assert!(
            block.contains(&format!(
                r#"<span class="acount">{}</span>"#,
                pathwarden_core::text::num(st.exposed)
            )),
            "step {n}"
        );
        if listed[i] < st.exposed {
            assert!(
                block.contains(&format!(
                    r#"data-capped="{}""#,
                    exposed::listed_words(listed[i])
                )),
                "step {n}: {block:.400}"
            );
        }
        // Nothing listed: nothing to search.
        assert_eq!(block.contains("acc-search"), listed[i] > 0, "step {n}");
    }
    assert_eq!(rows, exposed::LISTED_TOTAL);
    assert!(html.contains(r#"data-capped="None are listed.""#));
}
