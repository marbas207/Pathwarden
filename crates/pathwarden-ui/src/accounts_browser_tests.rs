//! The account lists in a real browser: the report's What changed
//! draws the accounts that now reach Tier Zero, with the step that cuts
//! each off; a step's list shows 20, then the first 1,000 and says so; its
//! search filters by name; a hostile name stays text. Home's What changed,
//! lifted from the report with its data, draws the same with links to the
//! run page. Headless Edge or Chrome (`PATHWARDEN_TEST_BROWSER` names one),
//! skipped with a note when there is none.

use std::path::{Path, PathBuf};

use pathwarden_core::analyze::{self, Analysis, Quiet};
use pathwarden_core::config::Config;
use pathwarden_core::exposed::{self, PreviousExposed};
use pathwarden_core::history::ReportHistory;
use pathwarden_core::state::{ChangeCounts, HistoryPoint};

const NOW: i64 = 1_791_417_600;
const HOSTILE: &str = "EVE</script><img src=x onerror=alert(1)>@CONTOSO.LOCAL";

fn analysis(path: &str) -> Analysis {
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path);
    analyze::run(&[input], &Config::default(), &[], &mut Quiet).unwrap()
}

/// The forest's report against an earlier run: two accounts are new (one
/// renamed to a hostile name), one earlier account has no path now and
/// one is no longer in the directory.
/// With `then`, the earlier run's graph is read from its full run's files,
/// where the account with no path now had one: its row shows that path.
fn forest_report(then: bool) -> String {
    let mut a = analysis("testdata/forest");
    let d = a.plan.detail.as_ref().unwrap();
    let first = d.exposed[0];
    let new: Vec<u64> = d
        .exposed
        .iter()
        .take(2)
        .map(|&ix| exposed::key(&a.graph.node(ix).id))
        .collect();
    let mut before: Vec<u64> = d
        .exposed
        .iter()
        .map(|&ix| exposed::key(&a.graph.node(ix).id))
        .filter(|k| !new.contains(k))
        .chain([5])
        .collect();
    // An enabled user outside Tier Zero with no path to it now.
    let lost_ix = a
        .graph
        .nodes()
        .find(|(ix, n)| {
            n.kind == pathwarden_core::model::NodeKind::User
                && !n.placeholder
                && !n.tier_zero
                && n.is_enabled()
                && !d.exposed.contains(ix)
        })
        .map(|(ix, _)| ix)
        .unwrap();
    before.push(exposed::key(&a.graph.node(lost_ix).id));
    let earlier = then.then(|| {
        let mut t = analysis("testdata/forest");
        let t0 = t.graph.nodes().find(|(_, n)| n.tier_zero).unwrap().0;
        t.graph.add_ace_edge(
            lost_ix,
            t0,
            pathwarden_core::model::EdgeKind::GenericAll,
            false,
        );
        let graph = pathwarden_core::explore::encode(&t.graph, &[], &[]);
        let objects = serde_json::to_vec(&pathwarden_core::object_index::ObjectIndex::from_graph(
            &t.graph,
        ))
        .unwrap();
        std::sync::Arc::new(exposed::EarlierRun::from_files("r0", &graph, &objects).unwrap())
    });
    before.sort_unstable();
    a.graph.node_mut(first).name = HOSTILE.to_string();
    let mut b = HistoryPoint::new(
        "r0",
        NOW - 86_400,
        None,
        &a.posture,
        ChangeCounts::default(),
    );
    b.tier_zero_exposed = before.len();
    let h = ReportHistory {
        earlier: vec![b],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            &a.posture,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    };
    let lists = exposed::lists(
        &a.graph,
        &a.plan,
        Some(&PreviousExposed::new("r0", NOW - 86_400, Ok(before)).with_earlier(earlier)),
    );
    a.report_html_lists(NOW, &h, &lists, &mut Quiet)
}

/// `page` with `probe` run after it loads (and its lists drew), which puts
/// what it found in `#out` as JSON; that JSON.
fn run(exe: &Path, dir: &Path, name: &str, page: &str, probe: &str) -> serde_json::Value {
    let script = format!(
        r#"<pre id="out"></pre><script>window.addEventListener("load", function () {{ var out = {{}}; function q(s) {{ return document.querySelector(s); }} function qa(s) {{ return document.querySelectorAll(s); }} function done() {{ document.getElementById("out").textContent = JSON.stringify(out); }} {probe} }});</script></body>"#
    );
    let path = dir.join(format!("{name}.html"));
    std::fs::write(&path, page.replacen("</body>", &script, 1)).unwrap();
    let profile = dir.join(format!("profile-{name}"));
    let url = format!("file:///{}", path.display().to_string().replace('\\', "/"));
    let out = pathwarden_core::spawn::quiet(exe)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--window-size=1440,1200",
            "--virtual-time-budget=5000",
            "--dump-dom",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(url)
        .output()
        .unwrap();
    let dom = String::from_utf8_lossy(&out.stdout);
    let json = dom
        .split(r#"<pre id="out">"#)
        .nth(1)
        .and_then(|s| s.split("</pre>").next())
        .unwrap_or("")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&json).unwrap_or_else(|e| {
        panic!(
            "{name}: {e}: {json:.300}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn the_account_lists_draw_in_a_browser() {
    let Some(exe) = crate::run_details::browser_tests::browser() else {
        eprintln!("no Edge or Chrome found: the account lists browser test was skipped");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pw-acc-browser-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The report: What changed's accounts, a step's list and its search.
    let report = forest_report(false);
    let got = run(
        &exe,
        &dir,
        "report",
        &report,
        r##"
        q("#since-tier-zero").open = true;
        q("#step-1").open = true;
        q("#step-1-accounts").open = true;
        setTimeout(function () {
          out.now = qa('#since-tier-zero ul[data-acc="now"] li').length;
          out.gone = qa('#since-tier-zero ul[data-acc="gone"] li').length;
          out.unnamed = q("#since-tier-zero .acc-unnamed").textContent;
          out.why = Array.prototype.map.call(qa('#since-tier-zero ul[data-acc="gone"] .acc-end'), function (e) { return e.textContent; });
          out.links = Array.prototype.map.call(qa("#since-tier-zero a.steplink"), function (a) { return a.getAttribute("href"); });
          out.hostile = Array.prototype.some.call(qa("#since-tier-zero .nm"), function (n) { return n.title === "EVE</" + "script><img src=x onerror=alert(1)>@CONTOSO.LOCAL"; });
          out.imgs = qa("img").length;
          var ul = q("#step-1-accounts ul.acc-list");
          out.step = ul.children.length;
          out.firstHops = ul.children[0].querySelector(".hops").textContent;
          var s = q("#step-1-accounts input.acc-search");
          var name = ul.children[ul.children.length - 1].querySelector(".nm").title;
          s.value = name.slice(0, name.indexOf("@") > 0 ? name.indexOf("@") : name.length);
          s.dispatchEvent(new Event("input", { bubbles: true }));
          out.searched = ul.children.length;
          out.match = q("#step-1-accounts .acc-match").textContent;
          done();
        }, 300);
        "##,
    );
    assert_eq!(got["now"], 2, "{got}");
    assert_eq!(got["gone"], 1, "{got}");
    assert_eq!(got["why"], serde_json::json!(["No path now"]), "{got}");
    assert_eq!(
        got["unnamed"], "1 more is no longer in the directory.",
        "{got}"
    );
    let links = got["links"].as_array().unwrap();
    assert_eq!(links.len(), 2, "{got}");
    assert!(
        links
            .iter()
            .all(|l| l.as_str().unwrap().starts_with("#step-")),
        "{got}"
    );
    assert_eq!(got["hostile"], true, "the hostile name, as text: {got}");
    assert_eq!(got["imgs"], 0, "a hostile name made an element: {got}");
    assert!(got["step"].as_u64().unwrap() >= 1, "{got}");
    assert!(
        got["firstHops"].as_str().unwrap().ends_with("hop")
            || got["firstHops"].as_str().unwrap().ends_with("hops"),
        "{got}"
    );
    assert!(got["searched"].as_u64().unwrap() >= 1, "{got}");
    assert!(got["match"].as_str().unwrap().ends_with(" match."), "{got}");

    // With the earlier run's graph: the gone account's path then.
    let got = run(
        &exe,
        &dir,
        "then",
        &forest_report(true),
        r##"
        q("#since-tier-zero").open = true;
        setTimeout(function () {
          out.why = Array.prototype.map.call(qa('#since-tier-zero ul[data-acc="gone"] .acc-end'), function (e) { return e.textContent; });
          out.hops = Array.prototype.map.call(qa('#since-tier-zero ul[data-acc="gone"] .hops'), function (e) { return e.textContent; });
          out.unnamed = q("#since-tier-zero .acc-unnamed").textContent;
          done();
        }, 300);
        "##,
    );
    assert_eq!(
        got["why"],
        serde_json::json!(["No path now · path on Oct 7"]),
        "{got}"
    );
    assert_eq!(got["hops"], serde_json::json!(["1 hop"]), "{got}");
    // Key 5 was never in the earlier graph: still counted.
    assert_eq!(
        got["unnamed"], "1 more is no longer in the directory.",
        "{got}"
    );

    // Home: What changed lifted from the report with its data; the steps
    // are on the run page.
    let fragment = super::localize(
        &super::extract(&report).unwrap(),
        "20261028-020000-abcdef",
        0,
    );
    let home = format!(
        "<!doctype html><html><body><section class=\"env-ov\">{fragment}</section><script>{}</script></body></html>",
        pathwarden_core::report::ACCOUNTS_JS
    );
    let got = run(
        &exe,
        &dir,
        "home",
        &home,
        r##"
        q("#h0-since-tier-zero").open = true;
        setTimeout(function () {
          out.now = qa('#h0-since-tier-zero ul[data-acc="now"] li').length;
          out.links = Array.prototype.map.call(qa("#h0-since-tier-zero a.steplink"), function (a) { return a.getAttribute("href"); });
          out.hero = q("a.delta-link").getAttribute("href");
          done();
        }, 300);
        "##,
    );
    assert_eq!(got["now"], 2, "{got}");
    assert!(
        got["links"].as_array().unwrap().iter().all(|l| l
            .as_str()
            .unwrap()
            .starts_with("/runs/20261028-020000-abcdef#step-")),
        "{got}"
    );
    assert_eq!(
        got["hero"], "/runs/20261028-020000-abcdef#since-tier-zero",
        "{got}"
    );

    // A step of more than 1,000: 20, then the first 1,000, said so.
    let demo = analysis("demo/20261001020000_PathwardenDemo.zip").report_html(NOW, &mut Quiet);
    let got = run(
        &exe,
        &dir,
        "demo",
        &demo,
        r##"
        q("#step-1").open = true;
        q("#step-1-accounts").open = true;
        setTimeout(function () {
          var ul = q("#step-1-accounts ul.acc-list");
          out.before = ul.children.length;
          out.footBefore = q("#step-1-accounts .acc-foot").textContent;
          q("#step-1-accounts button.acc-all").click();
          out.after = ul.children.length;
          out.footAfter = q("#step-1-accounts .acc-foot").textContent;
          out.newMarks = qa("#step-1-accounts .ibadge").length;
          done();
        }, 300);
        "##,
    );
    assert_eq!(got["before"], 20, "{got}");
    assert_eq!(
        got["footBefore"], "Showing 20 of 3,646.Show the first 1,000",
        "{got}"
    );
    assert_eq!(got["after"], 1000, "{got}");
    assert_eq!(got["footAfter"], exposed::LISTED_WORDS, "{got}");
    assert_eq!(got["newMarks"], 0, "no earlier run: nothing is new: {got}");
    let _ = std::fs::remove_dir_all(&dir);
}
