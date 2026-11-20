//! The HTML report: complete, self-contained, and safe with hostile names.

use std::path::PathBuf;

use pathwarden_core::findings::{self, Context, RuleSettings};
use pathwarden_core::history::ReportHistory;
use pathwarden_core::ingest::Ingestor;
use pathwarden_core::report::{render_html, OverviewInput, ReportInput};
use pathwarden_core::state::{ChangeCounts, HistoryPoint};
use pathwarden_core::{load, posture, remediation, LoadOptions};

const NOW: i64 = 1_791_417_600;

fn render(dir: &str) -> String {
    render_with_rules(dir).0
}

/// The report and the distinct rules among its findings.
fn render_with_rules(dir: &str) -> (String, Vec<&'static str>) {
    let (html, rules, _) = render_with_history(dir, |_| Vec::new());
    (html, rules)
}

/// The report with the earlier runs `history` makes from this run's
/// posture, its rules, and the posture.
fn render_with_history(
    dir: &str,
    history: impl Fn(&posture::Posture) -> Vec<HistoryPoint>,
) -> (String, Vec<&'static str>, posture::Posture) {
    render_with(dir, |p| ReportHistory {
        earlier: history(p),
        ..ReportHistory::default()
    })
}

/// The report with the run history `history` makes from this run's
/// posture.
fn render_with(
    dir: &str,
    history: impl Fn(&posture::Posture) -> ReportHistory,
) -> (String, Vec<&'static str>, posture::Posture) {
    render_zoned(dir, |_| Vec::new(), history)
}

/// [`render_with`], with the zones `zones` makes from the data.
fn render_zoned(
    dir: &str,
    zones: impl Fn(&pathwarden_core::AdGraph) -> Vec<pathwarden_core::zones::Zone>,
    history: impl Fn(&posture::Posture) -> ReportHistory,
) -> (String, Vec<&'static str>, posture::Posture) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(dir);
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    let zones = zones(&g);
    let p = posture::compute(&g, &all, &zones, &settings);
    let plan = remediation::plan(
        &g,
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    let earlier = history(&p);
    let html = render_html(&ReportInput {
        posture: &p,
        findings: &all,
        plan: &plan,
        stats: &stats,
        domains: &["CONTOSO.LOCAL".to_string()],
        generated_at: NOW,
        history: &earlier,
        introduced: None,
        forest: None,
        lists: None,
        kinds: None,
    });
    let mut rules: Vec<&'static str> = all.iter().map(|f| f.rule).collect();
    rules.sort_unstable();
    rules.dedup();
    (html, rules, p)
}

/// The Overview tab's markup.
fn overview(html: &str) -> &str {
    html.split(r#"<section id="overview""#)
        .nth(1)
        .and_then(|s| s.split("</section>").next())
        .unwrap()
}

/// A run label goes in the title and the rail, escaped, once.
#[test]
fn a_label_goes_in_the_title_and_the_rail() {
    let html = render("forest");
    assert!(html.contains("<title>Pathwarden report: CONTOSO.LOCAL</title>"));
    let labeled = pathwarden_core::report::with_label(&html, "after <GPO> fix");
    assert!(
        labeled.contains("<title>Pathwarden report: after &lt;GPO&gt; fix (CONTOSO.LOCAL)</title>"),
        "{}",
        &labeled[..600]
    );
    assert!(labeled.contains(
        "<dl class=\"meta\">\n    <div><dt>Run</dt><dd>after &lt;GPO&gt; fix</dd></div>\n    <div><dt>Domains</dt>"
    ));
    assert!(!labeled.contains("<GPO>"));
    // Once only, and nothing for an empty label or a page that isn't a report.
    assert_eq!(
        pathwarden_core::report::with_label(&labeled, "other"),
        labeled
    );
    assert_eq!(pathwarden_core::report::with_label(&html, "  "), html);
    assert_eq!(
        pathwarden_core::report::with_label("<html>old</html>", "x"),
        "<html>old</html>"
    );
}

#[test]
fn report_has_every_section_and_guide_link_targets() {
    let html = render("forest");
    for id in ["overview", "plan", "findings", "environment"] {
        assert!(
            html.contains(&format!(
                r#"<section id="{id}" class="panel" role="tabpanel" aria-labelledby="tab-{id}""#
            )),
            "missing section {id}"
        );
        assert!(
            html.contains(&format!(
                r##"role="tab" id="tab-{id}" href="#{id}" aria-controls="{id}""##
            )),
            "missing tab {id}"
        );
    }
    assert!(html.contains(r#"role="tablist""#));
    // Every link to a guide has a matching anchor.
    for part in html.split(r##"href="#guide-"##).skip(1) {
        let rule = &part[..6];
        assert!(
            html.contains(&format!(r#"id="guide-{rule}""#)),
            "guide {rule} missing"
        );
    }
    assert!(html.contains("The share of active accounts with a path"));
    // Dark by default, with a button to switch to light.
    assert!(html.contains(r#"<html lang="en" data-theme="dark">"#));
    assert!(html.contains(r#"id="theme-toggle""#));
    // The Crown W lockup is inlined once (its gradient IDs are fixed) and
    // plays its intro; the old stacked logos are gone.
    assert_eq!(
        html.matches(r#"<svg xmlns="http://www.w3.org/2000/svg" class="cw""#)
            .count(),
        1
    );
    assert!(html.contains(r#"class="cw-word""#));
    assert!(html.contains(r#"<div class="lockup cw-intro" role="img" aria-label="Pathwarden">"#));
    assert!(!html.contains("logo-light") && !html.contains(r#"id="title""#));
    assert!(html.contains("DA_ALICE@CONTOSO.LOCAL"));
}

#[test]
fn report_counts_dc_settings_for_esc9_and_esc10() {
    // DC01's Kdc and Schannel values are in the collection.
    // The Tier Zero settings row: DCs and CAs.
    let html = render("adcs");
    assert!(html.contains(r#"<span class="title">Tier Zero settings</span>"#));
    assert!(!html.contains("DC settings (ESC9, ESC10)"));
    assert!(html.contains("<td>PKI.LOCAL</td><td>1 of 1</td><td>Nothing.</td>"));
    // PKI-CA's ESC6 and ESC11 were collected; ROGUE-CA's ESC11 was not.
    assert!(html.contains("<td>PKI-CA</td><td>Read by the collection.</td><td>Nothing.</td>"));
    assert!(html.contains(r#"<td>ROGUE-CA</td><td class="warn">No settings file yet.</td><td>A settings file from this CA.</td>"#));
    assert!(
        html.contains(r#"<span class="aside warn">1 server needs a current settings file</span>"#)
    );
}

#[test]
fn report_is_self_contained() {
    let html = render("adcs");
    for external in [
        r#"src="http"#,
        r#"href="http://"#,
        "<link ",
        "@import",
        "url(http",
    ] {
        assert!(
            !html.contains(external),
            "report loads an external resource: {external}"
        );
    }
}

#[test]
fn names_are_escaped() {
    // Directory names are attacker-controlled: a user named like markup must
    // never become markup in the report.
    let evil = r#"<IMG SRC=X ONERROR=ALERT(1)>@EVIL.LOCAL"#;
    let users = format!(
        r#"{{"data":[{{"ObjectIdentifier":"S-1-5-21-9-9-9-1105","PrimaryGroupSID":"S-1-5-21-9-9-9-513",
        "Properties":{{"name":"{evil}","domain":"EVIL.LOCAL","enabled":true,"dontreqpreauth":true}}}}],
        "meta":{{"type":"users","count":1,"version":6}}}}"#
    );
    let mut ing = Ingestor::new();
    ing.ingest_text("users.json", &users).unwrap();
    let (g, stats) = ing.finish();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    assert!(
        all.iter().any(|f| f.title.contains("<IMG")),
        "the AS-REP finding names the user"
    );
    let p = posture::compute(&g, &all, &[], &settings);
    let plan = remediation::plan(
        &g,
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    let html = render_html(&ReportInput {
        posture: &p,
        findings: &all,
        plan: &plan,
        stats: &stats,
        domains: &["EVIL.LOCAL".to_string()],
        generated_at: NOW,
        history: &ReportHistory::default(),
        introduced: None,
        forest: None,
        lists: None,
        kinds: None,
    });
    assert!(!html.contains("<IMG"), "unescaped markup in report");
    assert!(html.contains("&lt;IMG SRC=X ONERROR=ALERT(1)&gt;"));
    // The findings search matches the name as written: escaped once, not
    // twice.
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "search text"
    );
    assert!(!html.contains("&amp;lt;img"), "escaped twice");
}

/// Kerberoastable accounts are exposed to everyone alike, so their rows
/// show the password's age, not "100.0% exposed".
#[test]
fn crackable_passwords_show_their_age() {
    let html = render("forest");
    let start = html.find(r#"id="rule-PW-006""#).expect("a PW-006 group");
    let group = &html[start..];
    let group = &group[..group
        .find(r#"<details class="row group""#)
        .unwrap_or(group.len())];
    let row = &group[group.find(r#"class="row finding""#).unwrap()..];
    let summary = &row[..row.find("</summary>").unwrap()];
    assert!(
        summary.contains("password <strong>") || summary.contains("password age unknown"),
        "{summary}"
    );
    assert!(!summary.contains("exposed</span>"), "{summary}");
}

#[test]
fn findings_are_grouped_by_rule() {
    let (html, rules) = render_with_rules("forest");
    let groups = html.matches(r#"<details class="row group""#).count();
    assert!(groups > 0);
    assert_eq!(groups, rules.len(), "one group per rule");
    // Each group holds its rule's guide.
    for rule in &rules {
        assert!(html.contains(&format!(r#"id="guide-{rule}""#)));
    }
}

/// A fixed finding whose ticket is still open is listed on the Findings
/// tab, above the findings, with its records' chips and when it was fixed;
/// the card is left out when there are none.
#[test]
fn fixed_findings_with_an_open_ticket_are_listed() {
    use pathwarden_core::action_log::FixedFinding;
    use pathwarden_core::actions::{ActionRecord, Record};
    let rec = |number: &str, status: &str| ActionRecord {
        action: "desk/open".into(),
        record: Record {
            id: format!("sys-{number}"),
            number: Some(number.into()),
            status: Some(status.into()),
            open: true,
            ..Record::default()
        },
        by: None,
        on: None,
        at: String::new(),
        updated_at: String::new(),
    };
    let fixed = vec![
        FixedFinding {
            fingerprint: "PW-012-b".into(),
            rule: "PW-012".into(),
            severity: findings::Severity::High,
            title: "Unconstrained delegation on <FS02>.NORTH.LAB".into(),
            fixed_at: NOW,
            records: vec![
                rec("RITM0010822", "Work in Progress"),
                rec("RITM0010824", "Open"),
            ],
        },
        FixedFinding {
            fingerprint: "PW-006-a".into(),
            rule: "PW-006".into(),
            severity: findings::Severity::Critical,
            title: "Kerberoastable account SVC-SQL01@NORTH.LAB is Tier Zero".into(),
            fixed_at: NOW - 6 * 86_400,
            records: vec![rec("RITM0010816", "Open")],
        },
    ];
    let (html, _, _) = render_with("forest", |_| ReportHistory {
        fixed_open: fixed.clone(),
        ..ReportHistory::default()
    });
    let findings_tab = html.split(r#"<section id="findings""#).nth(1).unwrap();
    let card = findings_tab
        .split(r#"<section class="card fixed-open""#)
        .nth(1)
        .and_then(|s| s.split("</section>").next())
        .expect("the card");
    assert!(card.contains("Fixed, ticket still open"), "{card}");
    let items: Vec<&str> = card.split("<li>").skip(1).collect();
    assert_eq!(items.len(), 2);
    // Newest fix first, as given; the title escaped.
    assert!(
        items[0].contains(
            r#"<span class="rule">PW-012</span>Unconstrained delegation on &lt;FS02&gt;.NORTH.LAB"#
        ),
        "{}",
        items[0]
    );
    assert!(items[0].contains(r#"<span class="ac-chip">RITM0010822 · Work in Progress</span><span class="ac-chip">RITM0010824 · Open</span>"#), "{}", items[0]);
    let today = pathwarden_core::report::short_date(NOW);
    assert!(
        items[0].contains(&format!(
            r#"Fixed <time data-unix="{NOW}" data-fmt="day">{today}</time></span>"#
        )),
        "{}",
        items[0]
    );
    assert!(items[1].contains("RITM0010816 · Open"));
    let earlier = pathwarden_core::report::short_date(NOW - 6 * 86_400);
    assert!(items[1].contains(&format!(">{earlier}</time></span>")));
    // Between the filters and the findings.
    let at = |s: &str| findings_tab.find(s).unwrap();
    assert!(at(r#"class="filters card""#) < at("fixed-open"));
    assert!(at("fixed-open") < at(r#"<div class="rows groups card">"#));
    // Its styles are the report's.
    assert!(html.contains(".fixed-open li {"));

    // None: no card.
    let html = render("forest");
    assert!(!html.contains(r#"class="card fixed-open""#));
    assert!(!html.contains(r#"id="fo-h""#));
}

/// Layout A without a run history: the hero (badge, count, reason) on its
/// own, four cards, findings by severity, the tiers, the collection note
/// and the definitions last. No trend and no "since the last run"; the
/// plan and the fix-directly list live on their own tabs.
#[test]
fn overview_without_history_is_this_run_alone() {
    let (html, _, p) = render_with_history("forest", |_| Vec::new());
    let o = overview(&html);
    let t0 = &p.tier_zero;
    assert!(o.contains(r#"<div class="hero card solo">"#), "{o}");
    // The status, with why on its badge (`pathwarden posture` prints it as
    // a line): the hero itself is counts.
    assert!(o.contains(&format!(
        r#"<span class="grade-badge" title="{}">{}</span>"#,
        t0.reason.text,
        t0.exposure_grade.as_str()
    )));
    assert!(!o.contains("hero-reason"));
    assert!(!o.contains("hero-trend") && !o.contains("<svg class=\"trend\""));
    assert!(
        !o.contains("since the last run"),
        "no deltas without history"
    );
    // Four cards, each with its definition; the count has one too.
    assert_eq!(o.matches(r#"<div class="card ov-card">"#).count(), 4);
    for label in [
        "Remediation path",
        "Open findings",
        "Tier Zero protected",
        "Collection",
    ] {
        assert!(
            o.contains(&format!(r#"aria-label="About: {label}""#)),
            "{label}"
        );
    }
    assert!(o.contains(r#"aria-label="About: Accounts with an attack path to Tier Zero""#));
    assert_eq!(o.matches(r#"role="tooltip""#).count(), 7);
    // The first step, linked; the plan's rows stay on the Remediation tab.
    assert!(o.contains(r##"href="#step-1""##));
    assert!(!o.contains(r#"class="row step"#));
    assert!(!o.contains("Cut these paths first"));
    assert!(!o.contains("Then fix these directly"));
    // Severity cards open Findings filtered to their severity.
    assert!(o.contains(r##"<a class="sevcard critical" href="#findings" data-only="critical""##));
    // Tiers, then the collection note, then all definitions, last.
    let tiers = o.find(r#"<div class="card tiers">"#).unwrap();
    let note = o.find(r#"class="ov-note"#).unwrap();
    let defs = o.find("All definitions").unwrap();
    assert!(o.find(r#"class="sevcards""#).unwrap() < tiers && tiers < note && note < defs);
    assert!(o.contains(r#"<th scope="row">Tier Zero</th>"#));
    assert!(!o.contains("What these numbers mean"));
}

/// With earlier runs: the trend of the last six (same exposure basis), and
/// each number's change since the last run.
#[test]
fn overview_with_history_shows_the_trend_and_changes() {
    let point = |p: &posture::Posture, run: &str, days_ago: i64, exposed: usize| {
        let mut h = HistoryPoint::new(
            run,
            NOW - days_ago * 86_400,
            None,
            p,
            ChangeCounts::default(),
        );
        h.tier_zero_exposed = exposed;
        h
    };
    let (html, _, p) = render_with_history("forest", |p| {
        let n = p.tier_zero.exposed;
        let mut old = point(p, "r0", 70, n + 900);
        // Counted another way: left off the trend.
        old.exposure_basis = 0;
        old.tier_zero_relevant_population = 0;
        let mut v = vec![old];
        for (i, extra) in [50, 40, 30, 20, 10, 5].into_iter().enumerate() {
            v.push(point(
                p,
                &format!("r{}", i + 1),
                60 - 7 * i as i64,
                n + extra,
            ));
        }
        let last = v.last_mut().unwrap();
        last.findings.critical += 2;
        last.protection_score = p.tier_zero.protection_score.map(|s| s - 10.0);
        v
    });
    let o = overview(&html);
    let n = p.tier_zero.exposed;
    assert!(o.contains(r#"<div class="hero card">"#));
    assert!(o.contains(r#"<p class="trend-title">Accounts with an attack path to Tier Zero</p>"#));
    assert!(o.contains("last 6 runs &middot; lower is better"));
    // Five earlier runs and this one: the first shown is n + 40.
    assert_eq!(o.matches(r#"<circle class="dot""#).count(), 6);
    let first = pathwarden_core::report::num(n + 40);
    assert!(o.contains(&format!(">{first}</text>")), "first value");
    assert!(!o.contains(&format!(
        ">{}</text>",
        pathwarden_core::report::num(n + 900)
    )));
    // Since the last run: 5 fewer accounts (good), 2 fewer critical
    // findings, more of Tier Zero protected.
    assert!(o.contains(r#"<span class="delta good"><span aria-hidden="true">&#9660;</span><span class="vh">down</span> 5</span>"#));
    assert!(o.contains(r#"<span class="vh">down</span> 2</span>"#));
    if p.tier_zero.protection_score.is_some() {
        assert!(
            o.contains(r#"<span class="vh">up</span> 10.00 points</span>"#),
            "{o}"
        );
    }
    assert!(o.contains("since the last run"));

    // The last run counted another way: no change shown, and said why.
    let (html, _, _) = render_with_history("forest", |p| {
        let mut old = point(p, "r0", 7, p.tier_zero.exposed + 900);
        old.exposure_basis = 0;
        old.tier_zero_relevant_population = 0;
        vec![old]
    });
    let o = overview(&html);
    assert!(o.contains("counted these with an older method"));
    assert!(
        o.contains(r#"<div class="hero card solo">"#),
        "no trend from one other-basis run"
    );
}

/// The top tick is at or above the highest value, whatever it is.
#[test]
fn trend_scale_tops_the_highest_value() {
    let (html, _, p) = render_with_history("forest", |p| {
        let mut h = HistoryPoint::new("r0", NOW - 7 * 86_400, None, p, ChangeCounts::default());
        h.tier_zero_exposed = 9_900;
        vec![h]
    });
    let o = overview(&html);
    assert!(p.tier_zero.exposed < 9_900);
    let ticks: Vec<&str> = o
        .split(r#"<text class="tick""#)
        .skip(1)
        .map(|t| &t[t.find('>').unwrap() + 1..t.find("</text>").unwrap()])
        .collect();
    assert_eq!(ticks, ["0", "5k", "10k"], "{o}");
}

/// Two runs of one day: the trend's dates carry the time.
#[test]
fn runs_of_one_day_show_the_time() {
    let (html, _, _) = render_with_history("forest", |p| {
        vec![HistoryPoint::new(
            "r0",
            NOW - 3 * 3_600,
            None,
            p,
            ChangeCounts::default(),
        )]
    });
    let o = overview(&html);
    // NOW is midnight UTC: the earlier run was the day before.
    assert!(
        o.contains(">Oct 7</tspan>") && o.contains(">Oct 8</tspan>"),
        "{o}"
    );
    // One day: the report (generated at NOW) beside a run an hour later.
    let at = NOW + 9 * 3_600 + 12 * 60;
    let (html, _, _) = render_with("forest", |p| ReportHistory {
        earlier: vec![HistoryPoint::new(
            "r0",
            NOW + 3_600,
            None,
            p,
            ChangeCounts::default(),
        )],
        this_run: Some(HistoryPoint::new(
            "r1",
            at,
            None,
            p,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    });
    let o = overview(&html);
    // In UTC until the page's script shows the reader's time.
    assert!(o.contains(">Oct 8, 1:00 AM UTC</tspan>"), "{o}");
    // This run's point is the run's own time, not when the report was made.
    assert!(o.contains(">Oct 8, 9:12 AM UTC</tspan>"), "{o}");
    assert!(o.contains("on Oct 8, 1:00 AM to"), "the label too");
}

/// "What changed" lists the lines `pathwarden history` prints, from the
/// same comparison; a report of data no run recorded doesn't say that no
/// finding opened or closed.
#[test]
fn overview_lists_what_changed_as_history_does() {
    let earlier = |p: &posture::Posture| {
        let mut h = HistoryPoint::new("r0", NOW - 86_400 * 7, None, p, ChangeCounts::default());
        h.tier_zero_exposed = p.tier_zero.exposed + 5;
        h
    };
    let (html, _, p) = render_with("forest", |p| ReportHistory {
        earlier: vec![earlier(p)],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            p,
            ChangeCounts {
                new: 3,
                resolved: 2,
                ..ChangeCounts::default()
            },
        )),
        ..ReportHistory::default()
    });
    let o = overview(&html);
    let list = o
        .split(r#"<div class="ov-since""#)
        .nth(1)
        .expect("a What changed list");
    assert!(
        list.contains(">What changed since <time") && list.contains(">Oct 1, 2026</time>"),
        "{list}"
    );
    let since = pathwarden_core::since::compare(
        &earlier(&p),
        &HistoryPoint::new(
            "r1",
            NOW,
            None,
            &p,
            ChangeCounts {
                new: 3,
                resolved: 2,
                ..ChangeCounts::default()
            },
        ),
        None,
    );
    let lines = since.lines();
    assert!(lines.len() >= 3);
    for l in &lines {
        assert!(
            rows(list).iter().any(|r| row_says(r, &l.text)),
            "{}",
            l.text
        );
    }
    assert!(list.contains(r#"<tr class="better">"#));
    // The terminal's commands are not in a page.
    assert!(!list.contains(r#"class="next""#));
    // Its section sits under the four cards and the severities.
    assert!(o.find("ov-cards").unwrap() < o.find("Findings by severity").unwrap());
    assert!(o.find("Findings by severity").unwrap() < o.find("ov-since").unwrap());

    // Data no run recorded: the counts, never "no finding opened".
    let (html, _, p) = render_with("forest", |p| {
        let mut h = earlier(p);
        h.tier_zero_exposed = p.tier_zero.exposed;
        ReportHistory {
            earlier: vec![h],
            ..ReportHistory::default()
        }
    });
    let o = overview(&html);
    assert!(o.contains("No change: as many accounts as before have an attack path to Tier Zero<"));
    assert!(!o.contains("no finding opened or closed"));
    assert!(p.tier_zero.exposed > 0);
}

/// "What changed" names findings whole, one per line, without the
/// terminal's commands, and shows the Tiers' status change beside the count.
#[test]
fn what_changed_names_in_full_with_its_settings() {
    let long = "a finding title well over seventy characters long, which the terminal cuts short";
    let (html, _, p) = render_with("forest", |p| {
        let mut before = HistoryPoint::new("r0", NOW + 10, None, p, ChangeCounts::default());
        before.tier_zero_exposed = p.tier_zero.exposed + 5;
        before.tier_zero_grade = Some(posture::ExposureGrade::Low);
        let state: pathwarden_core::state::FindingsState =
            serde_json::from_value(serde_json::json!({
                "version": 1, "findings": {"f1": {
                    "rule": "PW-003", "severity": "high", "category": "attack_path",
                    "status": "open", "first_seen": NOW + 40, "last_seen": NOW + 40,
                    "times_seen": 1, "title": long}}
            }))
            .unwrap();
        ReportHistory {
            earlier: vec![before],
            this_run: Some(HistoryPoint::new(
                "r1",
                NOW + 40,
                None,
                p,
                ChangeCounts {
                    new: 1,
                    ..ChangeCounts::default()
                },
            )),
            state: Some(std::borrow::Cow::Owned(state)),
            context: vec!["-c".into(), "x 2.toml".into()],
            state_dir: None,
            fixed_open: Vec::new(),
        }
    });
    let o = overview(&html);
    assert!(
        o.contains(&format!(
            r#"<ul class="items"><li><span class="dot high" role="img" aria-label="High" title="High"></span><span class="rid">PW-003</span> {long}</li></ul>"#
        )),
        "{o}"
    );
    assert!(!o.contains("The commands take"), "{o}");
    // Seconds apart on one day: the times say which is which.
    assert!(o.contains("What changed since <time"), "{o}");
    assert!(o.contains(">Oct 8, 2026, 12:00:10 AM UTC</time>"), "{o}");
    if p.tier_zero.exposure_grade != posture::ExposureGrade::Low {
        assert!(o.contains(" was Low</span>"), "{o}");
    }
}

/// Hostile zone names, finding titles and setting paths come out escaped
/// in "What changed" and the Tiers' "was" badge.
#[test]
fn what_changed_and_tiers_escape_names() {
    let zone = "<img src=x onerror=alert(1)>";
    let gone = "<script>alert(2)</script> zone";
    let title = "<script>alert(3)</script> title";
    let path = "<script>alert(4)</script>.toml";
    let (html, _, p) = render_zoned(
        "forest",
        |g| {
            let mut members = g.find("SRV01.CONTOSO.LOCAL");
            members.sort_unstable();
            vec![pathwarden_core::zones::Zone {
                name: zone.into(),
                members,
                unresolved: Vec::new(),
            }]
        },
        |p| {
            let mut before =
                HistoryPoint::new("r0", NOW - 86_400 * 7, None, p, ChangeCounts::default());
            for z in &mut before.zones {
                z.exposed = Some(z.exposed.unwrap_or(0) + 5);
                z.grade = Some(match z.grade {
                    Some(posture::ExposureGrade::Critical) => posture::ExposureGrade::Low,
                    _ => posture::ExposureGrade::Critical,
                });
            }
            let mut removed = before.zones[0].clone();
            removed.zone = gone.into();
            before.zones.push(removed);
            let state: pathwarden_core::state::FindingsState =
                serde_json::from_value(serde_json::json!({
                    "version": 1, "findings": {"f1": {
                        "rule": "PW-003", "severity": "high", "category": "attack_path",
                        "status": "open", "first_seen": NOW, "last_seen": NOW,
                        "times_seen": 1, "title": title}}
                }))
                .unwrap();
            ReportHistory {
                earlier: vec![before],
                this_run: Some(HistoryPoint::new(
                    "r1",
                    NOW,
                    None,
                    p,
                    ChangeCounts {
                        new: 1,
                        ..ChangeCounts::default()
                    },
                )),
                state: Some(std::borrow::Cow::Owned(state)),
                context: vec!["-c".into(), path.into()],
                state_dir: None,
                fixed_open: Vec::new(),
            }
        },
    );
    assert_eq!(p.zones.len(), 1);
    let o = overview(&html);
    let since = o
        .split(r#"<div class="ov-since""#)
        .nth(1)
        .and_then(|s| s.split(r#"<div class="card tiers">"#).next())
        .expect("a What changed list");
    let tiers = o
        .split(r#"<div class="card tiers">"#)
        .nth(1)
        .and_then(|s| s.split(r#"class="ov-note"#).next())
        .expect("the Tiers card");
    let escaped = |s: &str| s.replace('<', "&lt;").replace('>', "&gt;");
    for raw in [zone, gone, title, path] {
        assert!(!html.contains(raw), "{raw} unescaped");
    }
    for raw in [zone, gone, title] {
        assert!(since.contains(&escaped(raw)), "{raw}: {since}");
    }
    // The commands note, and the settings path in it, stay in the terminal.
    assert!(!since.contains(&escaped(path)), "{since}");
    assert!(tiers.contains(&escaped(zone)), "{tiers}");
    assert!(tiers.contains(" was "), "{tiers}");
}

#[test]
fn plan_and_findings_link_both_ways() {
    let html = render("forest");
    // Every link to a plan step, a finding, a rule group or a fix has its anchor.
    for prefix in ["step-", "f-", "rule-", "fix-"] {
        for part in html.split(&format!(r##"href="#{prefix}"##)).skip(1) {
            let id = &part[..part.find('"').unwrap()];
            let anchor = format!(r#"id="{prefix}{id}""#);
            assert!(html.contains(&anchor), "missing anchor {anchor}");
        }
    }
    // Each open finding says how the plan deals with it: closed or cut by a
    // step, or fix directly. Accepted risks don't.
    let findings = html.matches(r#"<details class="row finding""#).count();
    let accepted = html.matches(r#"data-suppressed="true" data-text"#).count();
    let notes = html.matches(r#"<p class="plannote"#).count();
    assert!(findings > 0);
    assert_eq!(notes, findings - accepted);
    // The overview explains its numbers, at the bottom.
    assert!(overview(&html).contains("All definitions"));
}

#[test]
fn embed_hooks_stay() {
    // The web UI adds its Retest button after each finding row's aside and
    // reads the row's title: keep those hooks.
    let html = render("forest");
    for part in html.split(r#"<details class="row finding" id="f-"#).skip(1) {
        let summary = &part[part.find("<summary>").unwrap()..part.find("</summary>").unwrap()];
        assert!(summary.contains(r#"<span class="title">"#));
        assert!(summary.contains(r#"<span class="aside">"#), "{summary}");
    }
    assert!(html.contains("Show accepted risks"));
    assert!(!html.contains("Show suppressed"));
}

/// "Group by: change that fixes it" places every open finding: under the
/// changes that close it or cut its path, or among those on no path, never
/// both; and the report draws one row per change with findings.
#[test]
fn every_open_finding_is_under_a_change_or_on_no_path() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    let plan = remediation::plan(
        &g,
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    let groups = pathwarden_core::report::fix_groups(&plan, &all);
    assert!(!plan.fixes.is_empty(), "the fixture needs a plan");

    let under: std::collections::BTreeSet<&str> = groups
        .groups
        .iter()
        .flat_map(|g| g.closes.iter().chain(&g.cuts))
        .map(|f| f.fingerprint.as_str())
        .collect();
    let alone: std::collections::BTreeSet<&str> = groups
        .alone
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    for f in all.iter().filter(|f| f.suppressed.is_none()) {
        let fp = f.fingerprint.as_str();
        assert!(
            under.contains(fp) != alone.contains(fp),
            "{fp} must be under a change or on no path, not both"
        );
    }
    // Most findings first; every group has one; the counts add up.
    assert!(groups.groups.windows(2).all(|w| w[0].len() >= w[1].len()));
    assert!(groups.groups.iter().all(|g| !g.is_empty()));
    assert_eq!(
        groups.groups.len() + groups.without_findings,
        plan.fixes.len()
    );
    assert_eq!(groups.closed() + groups.cut_only(), under.len());

    let html = render("forest");
    let rows = html.matches(r#"<details class="row step fixgroup"#).count();
    assert_eq!(
        rows,
        groups.groups.len() + usize::from(!groups.alone.is_empty())
    );
    assert!(html.contains(r#"name="f-group" value="fix""#));
}

/// A report of the run that left the findings state has the Introduced
/// filter: each finding's dates, a badge for the last run, its objects
/// dated (the gained ones first), and the new paths into Tier Zero with the
/// step that cuts them and the start's node for Explore.
#[test]
fn introduced_dates_findings_objects_and_paths() {
    use pathwarden_core::introduced::{self, ForReport, Names, PathsTrack, Runs};
    use pathwarden_core::state::{reconcile, FindingsState};
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    let p = posture::compute(&g, &all, &[], &settings);
    let plan = remediation::plan(
        &g,
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    // A week before, one finding listed one object fewer and one edge into
    // Tier Zero wasn't there.
    let before_at = NOW - 7 * 86_400;
    let grown = all
        .iter()
        .position(|f| f.affected.len() > 1 && !f.objects_are_its_key())
        .expect("a list");
    let mut earlier = all.clone();
    let dropped = earlier[grown].affected.pop().unwrap();
    let edges: Vec<String> = introduced::zone_edges(&g, &[])[0]
        .1
        .iter()
        .map(|e| e.key(&g))
        .collect();
    assert!(edges.len() > 1, "the forest has edges into Tier Zero");
    let mut r1 = reconcile(&FindingsState::default(), &earlier, before_at, false);
    let members: Vec<String> = introduced::zone_members(&g, &[])[0]
        .1
        .iter()
        .map(|ix| introduced::object_key(&g.node(*ix).id))
        .collect();
    r1.state.paths = Some(PathsTrack::update(
        None,
        &introduced::env_key(&[]),
        &[(
            introduced::TIER_ZERO.to_string(),
            edges[1..].to_vec(),
            members,
        )],
        before_at,
        0,
        true,
    ));
    let mut r2 = reconcile(&r1.state, &all, NOW, false);
    r2.state.paths = Some(PathsTrack::record(
        r1.state.paths.as_ref(),
        &[],
        &g,
        &[],
        NOW,
        true,
    ));
    let names = Names::new(&all, &g, &[], Some(&plan));
    let intro = ForReport::new(
        &r2.state,
        NOW,
        Runs::new(vec![before_at, NOW]),
        true,
        &names,
    );
    let html = render_html(&ReportInput {
        posture: &p,
        findings: &all,
        plan: &plan,
        stats: &stats,
        domains: &["CONTOSO.LOCAL".to_string()],
        generated_at: NOW,
        history: &ReportHistory::default(),
        introduced: Some(&intro),
        forest: None,
        lists: None,
        kinds: None,
    });
    // The picker, with the words for each period from the core.
    assert!(html.contains(r#"<select id="f-intro">"#), "picker");
    assert!(html.contains(r#"data-last="since the last run""#));
    assert!(html.contains(r#"<option value="last">Since the last run</option>"#));
    // The finding that grew: its dates and its badge for the last run.
    let fp = &all[grown].fingerprint;
    let row = html
        .split(&format!(r#"<details class="row finding" id="f-{fp}""#))
        .nth(1)
        .unwrap();
    let row = &row[..row.find("</p></div></details>\n").unwrap()];
    assert!(row.contains(&format!(r#"data-gained="{NOW}:1""#)), "{row}");
    assert!(
        row.contains(r#"<span class="ibadge gained" data-ibadge>+1 object</span>"#),
        "{row}"
    );
    // Its new object first, dated.
    let first_li = row.split("<li ").nth(1).unwrap();
    assert!(
        first_li.contains(&format!(r#"data-seen="{NOW}""#))
            && first_li.contains(r#"<span class="aseen">first seen "#)
            && first_li.contains("(run 2)</span>"),
        "{first_li}"
    );
    assert!(
        first_li.starts_with(&format!(r#"data-name="{}""#, dropped.name)),
        "{first_li}"
    );
    // The other findings were there a week before: no badge.
    assert_eq!(html.matches("data-ibadge hidden").count(), all.len() - 1);
    // The new path, with its step and its start for Explore.
    // Hidden until a period is picked under Introduced.
    assert!(html.contains(r#"id="intro-paths" aria-labelledby="ip-h" hidden>"#));
    let panel = html.split(r#"id="intro-paths""#).nth(1).expect("paths");
    assert_eq!(panel.matches("<li data-seen=").count(), 1, "{panel}");
    assert!(panel.contains(r#"class="ip-xp" data-node=""#), "{panel}");
    assert!(
        panel.contains(r##"class="steplink" href="#"##) || panel.contains("no plan step"),
        "{panel}"
    );
    // Each Explore button says which object it opens.
    assert!(
        panel.contains(r#"aria-label="Open "#) && panel.contains(r#" in Explore" hidden>"#),
        "{panel}"
    );
    // The summary for the periods offered is the core's lines, as
    // `pathwarden changes --since` prints them.
    let runs = Runs::new(vec![before_at, NOW]);
    for (key, period) in [
        ("last", introduced::Period::LastRun),
        ("7", introduced::Period::Days(7)),
        ("30", introduced::Period::Days(30)),
    ] {
        let lines: Vec<String> = introduced::period(&r2.state, period, NOW, &runs)
            .lines()
            .into_iter()
            .map(|l| l.text)
            .collect();
        let embedded = html
            .split(r#"data-lines=""#)
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap()
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&");
        let embedded: serde_json::Value = serde_json::from_str(&embedded).unwrap();
        assert_eq!(embedded[key], serde_json::json!(lines), "{key}");
    }
    // The definitions at the bottom have the terms the tooltips use.
    for term in [
        "<dt>Introduced</dt>",
        "<dt>First seen</dt>",
        "<dt>New paths and members</dt>",
    ] {
        assert!(html.contains(term), "{term}");
    }
}

/// A report of data no run recorded (earlier runs, but none for this data):
/// What changed compares the counts and says why it names no findings.
#[test]
fn what_changed_says_when_findings_cant_be_named() {
    let (html, _, _) = render_with_history("forest", |p| {
        let mut before = HistoryPoint::new("r0", NOW - 86_400, None, p, ChangeCounts::default());
        before.tier_zero_exposed = p.tier_zero.exposed + 3;
        vec![before]
    });
    let o = overview(&html);
    assert!(o.contains("What changed since"), "{o}");
    assert!(
        o.contains("The last run didn't keep its findings, so only the counts are compared."),
        "{o}"
    );
    // A run that recorded it names them, so it says nothing of the kind.
    let (html, _, _) = render_with("forest", |p| ReportHistory {
        earlier: vec![HistoryPoint::new(
            "r0",
            NOW - 86_400,
            None,
            p,
            ChangeCounts::default(),
        )],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            p,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    });
    assert!(!overview(&html).contains("No run recorded this data"));
}

/// What changed with its cards' count markup taken out: the lines' text.
/// What changed's rows as text, a cell each ("5", "fewer accounts with an
/// attack path to Tier Zero", "11 → 6").
fn rows(html: &str) -> Vec<Vec<String>> {
    html.split("<tr ")
        .skip(1)
        .map(|r| {
            let r = r.split("</tr>").next().unwrap();
            // After the row's own tag.
            let r = &r[r.find('>').unwrap() + 1..];
            r.split("</td>")
                .map(|c| {
                    // The hidden word and the mark are not the cell's text.
                    let c = c
                        .replace(r#"<span class="vh">Worse: </span>"#, "")
                        .replace(r#"<span class="vh">Better: </span>"#, "");
                    // Nor the brief beside a row that opens.
                    let c = match c.find(r#"<span class="wc-brief">"#) {
                        Some(at) => c[..at].to_string(),
                        None => c,
                    };
                    let mut out = String::new();
                    let mut tag = false;
                    for ch in c.chars() {
                        match ch {
                            '<' => tag = true,
                            '>' => tag = false,
                            _ if !tag => out.push(ch),
                            _ => {}
                        }
                    }
                    out.replace("&#9650;", "")
                        .replace("&#9660;", "")
                        .replace("&#8226;", "")
                        .trim()
                        .to_string()
                })
                .collect()
        })
        .collect()
}

/// A row says a line of `pathwarden history`: its count, its words, and
/// the before and after in their own cell.
fn row_says(row: &[String], text: &str) -> bool {
    let (count, rest) = match text.split_once(' ') {
        Some((n, r)) if n.chars().all(|c| c.is_ascii_digit() || c == ',') => (n, r),
        _ => ("", text),
    };
    let (what, ba) = match (rest.find(" ("), rest.find(')')) {
        (Some(o), Some(c)) if rest[o..c].contains('→') => {
            (format!("{}{}", &rest[..o], &rest[c + 1..]), &rest[o + 2..c])
        }
        _ => (rest.to_string(), ""),
    };
    row.len() >= 3 && row[0] == count && row[1] == what && row[2] == ba
}

/// The Trusts table of a report of `dir`, analyzed.
fn trusts_table(dir: PathBuf) -> String {
    let a = pathwarden_core::analyze::run(
        &[dir],
        &pathwarden_core::config::Config::default(),
        &[],
        &mut |_| {},
    )
    .unwrap();
    let html = a.report_html(NOW, &mut |_| {});
    html.split(r#"<span class="title">Trusts</span>"#)
        .nth(1)
        .and_then(|s| s.split("</details>").next())
        .unwrap()
        .to_string()
}

/// The Trusts table flags each trust as the forest map does: forest
/// takeover inside a forest, SID history abuse (PW-012) across one, and
/// its summary line says what stands out. Its SID filtering column is
/// each way as the trusting side records it, so it agrees with Risk.
#[test]
fn the_trusts_table_carries_the_forest_flags() {
    let table =
        trusts_table(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest"));
    assert!(table.contains("1 trust with SID history abuse"), "{table}");
    assert!(table.contains("<th>Risk</th>"), "{table}");
    let rows: Vec<&str> = table.split("<tr>").skip(2).collect();
    assert_eq!(rows.len(), 2, "{table}");
    let child = rows
        .iter()
        .find(|r| r.contains("CHILD.CONTOSO.LOCAL"))
        .unwrap();
    assert!(
        child.contains(r#"<span class="ttag">Forest takeover</span>"#),
        "{child}"
    );
    let ext = rows.iter().find(|r| r.contains("FABRIKAM.COM")).unwrap();
    assert!(ext.contains("SID history abuse"), "{ext}");
    assert!(
        ext.contains("FABRIKAM.COM into CONTOSO.LOCAL: off (collector&#x27;s flag)")
            || ext.contains("FABRIKAM.COM into CONTOSO.LOCAL: off (from the collector)"),
        "{ext}"
    );
    assert!(!ext.contains("Forest takeover"), "{ext}");
}

/// On GOAD (SharpHound 2.3, no trust attributes) the forest trust's
/// filtering is unknown each way, as Risk says, not the flag's "off".
#[test]
fn the_sid_filtering_column_agrees_with_risk_on_goad() {
    let dir = std::env::var_os("PATHWARDEN_GOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/goad"));
    if !dir.exists() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }
    let table = trusts_table(dir);
    let forest = table
        .split("<tr>")
        .find(|r| r.contains("ESSOS.LOCAL") && r.contains("Forest"))
        .unwrap();
    assert!(forest.contains("SID filtering unknown"), "{forest}");
    let cells: Vec<&str> = forest.split("<td>").collect();
    let sid = cells[5];
    assert!(
        sid.contains("unknown (the collected data doesn't say)"),
        "{forest}"
    );
    assert!(!sid.contains(": off") && !sid.contains(": on"), "{forest}");
}

/// A copy of `testdata/forest` as a Quick (DC only) collection writes it,
/// as an absolute path [`render_zoned`] takes in place of a fixture name.
fn quick_forest(tag: &str) -> String {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let dir = std::env::temp_dir().join(format!("pathwarden-quick-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            for c in doc["data"].as_array_mut().unwrap() {
                for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                    c[k] = serde_json::json!({"Results": [], "Collected": false,
                        "FailureReason": pathwarden_core::ingest::NOT_CONTACTED});
                }
                c["LocalGroups"] = serde_json::json!([]);
                c.as_object_mut().unwrap().remove("LocalAdmins");
            }
        }
        std::fs::write(
            dir.join(path.file_name().unwrap()),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
    }
    dir.to_string_lossy().into_owned()
}

/// A Quick run's report says "Not targeted", without the incomplete
/// collection warning, and doesn't compare its counts with a Full run.
#[test]
fn a_quick_report_says_not_targeted_and_compares_nothing_with_a_full_run() {
    let dir = quick_forest("report");
    // The last run was Full: more accounts, every computer read.
    let full = |p: &posture::Posture| {
        let mut h = HistoryPoint::new("r0", NOW - 86_400 * 7, None, p, ChangeCounts::default());
        h.tier_zero_exposed = p.tier_zero.exposed + 50;
        h.completeness = Some(pathwarden_core::state::CompletenessPoint {
            computers: 4,
            sessions_collected: 4,
            sessions_percent: 100.0,
            member_computers: 3,
            local_groups_collected: 3,
            local_groups_percent: Some(100.0),
            low_domains: 0,
            sessions_targeted: true,
            local_groups_targeted: true,
            untargeted_domains: Vec::new(),
        });
        h
    };
    let (html, _, p) = render_with(&dir, |p| ReportHistory {
        earlier: vec![full(p)],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            p,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    });
    std::fs::remove_dir_all(&dir).ok();
    assert!(!p.completeness[0].sessions_targeted);
    let o = overview(&html);
    // The Collection card.
    assert!(
        o.contains(r#"<span class="ov-num">Not collected</span><span class="ov-sub">This run read the directory only.</span>"#),
        "{o}"
    );
    assert!(o.contains("Not collected: this collection didn&#39;t ask for them."));
    // The note under the tiers: muted, no warning.
    assert!(
        o.contains("from the directory only: sessions and local groups weren&#39;t collected. Paths through sessions and local administrator rights are not in this run.</p>"),
        "{o}"
    );
    assert!(!o.contains("Incomplete collection."), "{o}");
    // What changed: one neutral line, and no counts since the last run.
    let list = o
        .split(r#"<div class="ov-since""#)
        .nth(1)
        .expect("What changed");
    assert!(list.contains("Sessions and local groups weren&#39;t collected in this run, so this run&#39;s counts aren&#39;t compared with the last run."), "{list}");
    assert!(!list.contains("fewer accounts"), "{list}");
    assert!(!o.contains("since the last run"), "no delta: {o}");
    assert!(!o.contains("hero-change"), "{o}");
    // Environment: plain aside, muted cells, the definition.
    let env = html
        .split("Collection completeness</span>")
        .nth(1)
        .unwrap()
        .split("</details>")
        .next()
        .unwrap();
    assert!(
        env.starts_with(r#"<span class="aside">sessions and local groups not collected</span>"#),
        "{env}"
    );
    assert!(
        env.contains(r#"<td class="muted">Not collected</td><td class="muted">Not collected</td>"#),
        "{env}"
    );
    assert!(!env.contains("cmeter"), "{env}");
    assert!(env.contains("Not collected: this collection didn't ask for them."));
}

/// Home's Overview of a run loaded from the history is the report's own
/// hero, cards and What changed, made again from the posture and plan the
/// run's event document carries: the same markup as the report's.
#[test]
fn the_overview_fragment_is_the_report_s_and_reads_back_from_the_event() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    let p = posture::compute(&g, &all, &[], &settings);
    let plan = remediation::plan(
        &g,
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    let mut before = HistoryPoint::new("r0", NOW - 86_400 * 7, None, &p, ChangeCounts::default());
    before.tier_zero_exposed = p.tier_zero.exposed + 5;
    let history = ReportHistory {
        earlier: vec![before],
        this_run: Some(HistoryPoint::new(
            "r1",
            NOW,
            None,
            &p,
            ChangeCounts::default(),
        )),
        ..ReportHistory::default()
    };
    let domains = ["CONTOSO.LOCAL".to_string()];
    let input = ReportInput {
        posture: &p,
        findings: &all,
        plan: &plan,
        stats: &stats,
        domains: &domains,
        generated_at: NOW,
        history: &history,
        introduced: None,
        forest: None,
        lists: None,
        kinds: None,
    };
    let html = render_html(&input);
    let fragment = pathwarden_core::report::overview_fragment(&input.overview_input());
    let cards = fragment.find(r#"<div class="ov-cards">"#).unwrap();
    let since = fragment.find(r#"<div class="ov-since""#).unwrap();
    for part in [
        &fragment[..cards],
        &fragment[cards..since],
        &fragment[since..],
    ] {
        assert!(html.contains(part), "{part}");
    }
    assert!(fragment.starts_with(r#"<div class="hero card"#));
    assert!(!fragment.contains("Findings by severity"));
    assert!(p.tier_zero.exposed > 0 && !plan.fixes.is_empty());

    // From what an event document gives: the plan's first step and its
    // length, without the findings or the collection's statistics.
    let again = pathwarden_core::report::overview_fragment(&OverviewInput {
        posture: &p,
        plan_steps: plan.fixes.len(),
        exposed_before: plan.exposed_before,
        first_step: plan.fixes.first(),
        collected_at: stats.collected_at,
        generated_at: NOW,
        history: &history,
        introduced: None,
        lists: None,
    });
    assert_eq!(again, fragment);

    // Counts from someone else's data never overflow: more objects with
    // findings than objects, and counts that add up past the largest.
    let mut odd = p.clone();
    odd.tier_zero.objects_with_findings = odd.tier_zero.objects + 3;
    odd.findings.critical = usize::MAX;
    odd.findings.high = 2;
    let o = pathwarden_core::report::overview_fragment(&OverviewInput {
        posture: &odd,
        history: &ReportHistory::default(),
        ..input.overview_input()
    });
    assert!(
        o.contains(&format!("0 of {} objects", odd.tier_zero.objects)),
        "{o}"
    );
}
