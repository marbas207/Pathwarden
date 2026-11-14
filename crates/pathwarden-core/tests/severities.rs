//! Severities set per rule (`[rules.severities]`): a set severity
//! rates every finding of its rule in both ways of rating attack paths and
//! over floors; finding IDs and accepted risks stay; the zone status
//! follows the counts, but a broad group keeps a zone Critical; the
//! settings file refuses unknown rules and levels; What changed reads a
//! change of these settings as neither better nor worse.

use std::path::PathBuf;

use pathwarden_core::config::Config;
use pathwarden_core::config_edit::{ConfigDoc, RulesEdit, Stamp};
use pathwarden_core::findings::{self, Context, Finding, RuleSettings, Severity};
use pathwarden_core::posture::{self, ExposureGrade};
use pathwarden_core::state::{ChangeCounts, HistoryPoint};
use pathwarden_core::{load, AdGraph, IngestStats, LoadOptions};

/// 2026-10-08.
const NOW: i64 = 1_791_417_600;

fn load_dir(name: &str) -> (AdGraph, IngestStats) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    load(&[dir], &LoadOptions::default()).expect("fixture loads")
}

fn config(text: &str) -> Config {
    Config::parse(text).unwrap()
}

fn run(g: &AdGraph, stats: &IngestStats, c: &Config) -> (RuleSettings, Vec<Finding>) {
    let settings = RuleSettings {
        now: NOW,
        ..c.settings()
    };
    let mut all = findings::evaluate(&Context::new(g, &stats.trusts, &settings), &[]);
    c.apply_suppressions(&mut all, NOW);
    (settings, all)
}

fn of<'a>(all: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    all.iter().filter(|f| f.rule == rule).collect()
}

fn rules_edit(severities: &[(&str, &str)]) -> RulesEdit {
    RulesEdit {
        stale_days: 90,
        password_age_days: 365,
        krbtgt_age_days: 180,
        sso_key_age_days: None,
        severity: "exposure".into(),
        disabled: Vec::new(),
        severities: severities
            .iter()
            .map(|(r, l)| (r.to_string(), l.to_string()))
            .collect(),
    }
}

fn stamp() -> Stamp {
    Stamp {
        by: Some(r"NORTH\eddard.stark".into()),
        on: Some("SECOPS-WS02".into()),
        at: "2026-10-24T09:00:00Z".into(),
    }
}

/// PW-002 is Critical by its rule with a High floor by exposure; PW-011
/// is Medium hygiene. Set, they are Low and Critical whichever way attack
/// paths are rated, with the rating they would have had kept beside.
#[test]
fn a_set_severity_wins_in_both_modes_and_over_floors() {
    let (g, stats) = load_dir("forest");
    for mode in ["exposure", "static"] {
        let plain = config(&format!("[rules]\nseverity = \"{mode}\"\n"));
        let (_, before) = run(&g, &stats, &plain);
        let set = config(&format!(
            "[rules]\nseverity = \"{mode}\"\n[rules.severities]\n\"PW-002\" = \"low\"\n\"pw-011\" = {{ severity = \"Critical\", by = 'NORTH\\ned' }}\n"
        ));
        let (_, after) = run(&g, &stats, &set);
        assert!(!of(&before, "PW-002").is_empty() && !of(&before, "PW-011").is_empty());
        for f in of(&after, "PW-002") {
            assert_eq!(f.severity, Severity::Low, "{mode}: {}", f.title);
            let was = of(&before, "PW-002")
                .into_iter()
                .find(|b| b.fingerprint == f.fingerprint)
                .unwrap();
            assert!(was.severity >= Severity::High, "the floor: {mode}");
            assert_eq!(f.severity_default, Some(was.severity), "{mode}");
        }
        for f in of(&after, "PW-011") {
            assert_eq!(f.severity, Severity::Critical, "{mode}");
            assert_eq!(f.severity_default, Some(Severity::Medium), "{mode}");
        }
        // Other rules are untouched; the most severe still come first.
        for f in after
            .iter()
            .filter(|f| f.rule != "PW-002" && f.rule != "PW-011")
        {
            assert!(f.severity_default.is_none(), "{}", f.rule);
        }
        assert!(after.windows(2).all(|w| w[0].severity >= w[1].severity));
        // Finding IDs are the same.
        let ids = |v: &[Finding]| {
            let mut ids: Vec<String> = v.iter().map(|f| f.fingerprint.clone()).collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&before), ids(&after), "{mode}");
        // The event document carries the default only when one was set.
        let json = serde_json::to_value(of(&after, "PW-011")[0]).unwrap();
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["severity_default"], "medium");
        let json = serde_json::to_value(after.iter().find(|f| f.rule == "PW-003")).unwrap();
        assert!(json.get("severity_default").is_none(), "{json}");
    }
}

/// Accepted risks match by finding ID or rule, whatever the severity.
#[test]
fn accepted_risks_still_apply() {
    let (g, stats) = load_dir("forest");
    let (_, plain) = run(&g, &stats, &config(""));
    let fp = of(&plain, "PW-002")[0].fingerprint.clone();
    let c = config(&format!(
        "[rules.severities]\n\"PW-002\" = \"critical\"\n\"PW-011\" = \"low\"\n\n[[suppress]]\nfingerprint = \"{fp}\"\nreason = \"r\"\n\n[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n"
    ));
    let (_, all) = run(&g, &stats, &c);
    assert!(of(&all, "PW-002")
        .iter()
        .any(|f| f.fingerprint == fp && f.suppressed.is_some()));
    assert!(of(&all, "PW-011").iter().all(|f| f.suppressed.is_some()));
}

/// The status follows the counts: every rule set to Low leaves no
/// critical finding. A broad group with a path to Tier Zero keeps it
/// Critical whatever PW-001's severity (`ExposureGrade::assess`).
#[test]
fn zone_status_follows_the_counts_but_a_broad_group_keeps_critical() {
    let all_low = |text: &str| {
        let mut t = String::from(text);
        t.push_str("[rules.severities]\n");
        for r in findings::rules() {
            t.push_str(&format!("\"{}\" = \"low\"\n", r.id));
        }
        config(&t)
    };
    let all_critical = || {
        let mut t = String::from("[rules.severities]\n");
        for r in findings::rules() {
            t.push_str(&format!("\"{}\" = \"critical\"\n", r.id));
        }
        config(&t)
    };
    let (g, stats) = load_dir("forest");
    let grade = |c: &Config| {
        let (settings, all) = run(&g, &stats, c);
        let p = posture::compute(&g, &all, &[], &settings);
        (p.tier_zero.exposure_grade, p.findings.critical, p)
    };
    let (low, critical, p) = grade(&all_low(""));
    assert_eq!(critical, 0);
    assert_eq!(
        low,
        ExposureGrade::High,
        "accounts can still reach Tier Zero"
    );
    assert_eq!(p.severities_set.len(), findings::rules().len());
    assert_eq!(grade(&all_critical()).0, ExposureGrade::Critical);

    let (g, stats) = load_dir("broad");
    let (settings, all) = run(&g, &stats, &all_low(""));
    assert!(!of(&all, "PW-001").is_empty());
    assert!(all.iter().all(|f| f.severity == Severity::Low));
    let p = posture::compute(&g, &all, &[], &settings);
    assert_eq!(p.findings.critical, 0);
    assert_eq!(p.tier_zero.exposure_grade, ExposureGrade::Critical);
}

/// Saved from the app or the command line: the level with who set it; a
/// level left as it was keeps its record; Default takes it off, and the
/// table with the last one.
#[test]
fn set_and_reset_through_the_settings_file() {
    let mut d = ConfigDoc::template();
    d.set_rules(
        &rules_edit(&[("pw-002", "Critical"), ("PW-011", "low")]),
        &stamp(),
    )
    .unwrap();
    let text = d.text();
    assert!(
        text.lines().any(|l| l.trim() == "[rules.severities]"),
        "{text}"
    );
    let c = Config::parse(&text).unwrap();
    let set = c.rules.set_severities();
    assert_eq!(set["PW-002"].severity, Severity::Critical);
    assert_eq!(set["PW-002"].by.as_deref(), Some(r"NORTH\eddard.stark"));
    assert_eq!(set["PW-002"].at.as_deref(), Some("2026-10-24T09:00:00Z"));
    // Saved again unchanged by someone else: the record stays.
    let other = Stamp {
        by: Some(r"NORTH\robb.stark".into()),
        on: None,
        at: "2026-10-25T09:00:00Z".into(),
    };
    d.set_rules(
        &rules_edit(&[("PW-002", "critical"), ("PW-011", "medium")]),
        &other,
    )
    .unwrap();
    let set = Config::parse(&d.text()).unwrap().rules.set_severities();
    assert_eq!(set["PW-002"].by.as_deref(), Some(r"NORTH\eddard.stark"));
    assert_eq!(set["PW-011"].by.as_deref(), Some(r"NORTH\robb.stark"));
    assert_eq!(set["PW-011"].severity, Severity::Medium);
    // Rules not named keep theirs; Default takes one off.
    d.set_rules(&rules_edit(&[("PW-011", "default")]), &other)
        .unwrap();
    let set = Config::parse(&d.text()).unwrap().rules.set_severities();
    assert_eq!(set.keys().collect::<Vec<_>>(), ["PW-002"]);
    d.set_rules(&rules_edit(&[("PW-002", "default")]), &other)
        .unwrap();
    let text = d.text();
    assert!(
        !text.lines().any(|l| l.trim() == "[rules.severities]"),
        "{text}"
    );
    let (g, stats) = load_dir("forest");
    let (_, all) = run(&g, &stats, &Config::parse(&text).unwrap());
    assert!(all.iter().all(|f| f.severity_default.is_none()));
}

#[test]
fn unknown_rules_and_levels_are_refused() {
    let mut d = ConfigDoc::template();
    let e = d
        .set_rules(&rules_edit(&[("PW-999", "low")]), &stamp())
        .unwrap_err();
    assert_eq!(e, "PW-999 is not a rule Pathwarden has.");
    for level in ["info", "urgent"] {
        let e = d
            .set_rules(&rules_edit(&[("PW-002", level)]), &stamp())
            .unwrap_err();
        assert!(e.contains("use critical, high, medium or low."), "{e}");
    }
    assert!(!d.text().lines().any(|l| l.trim() == "[rules.severities]"));
    // In the file (perhaps from a newer version, through the shared
    // settings): what this version can't read is kept, ignored and named
    // in one warning per kind, never an error.
    let warned = |text: &str| {
        let c = Config::parse(text).unwrap();
        let w: Vec<String> = c.warnings.iter().map(|w| w.to_string()).collect();
        (c, w)
    };
    let (c, w) = warned(
        "[rules.severities]\n\"PW-002\" = \"urgent\"\n\"PW-003\" = { severity = 5 }\n\"PW-011\" = { level = \"low\" }\n\"PW-013\" = \"low\"\n",
    );
    assert_eq!(
        w,
        ["[rules.severities]: 3 entries have a severity or form this version doesn't read. They are kept in the file and ignored."]
    );
    assert_eq!(
        c.settings().severities.keys().collect::<Vec<_>>(),
        ["PW-013"]
    );
    let (_, w) = warned("[rules.severities]\n\"PW-998\" = \"low\"\n\"PW-999\" = \"low\"\n");
    assert_eq!(
        w,
        ["[rules.severities]: 2 entries are for rules this version doesn't have. They are kept in the file and ignored."]
    );
    let (_, w) = warned("[rules.severities]\n\"PW-999\" = \"low\"\n");
    assert_eq!(
        w,
        ["[rules.severities]: 1 entry is for a rule this version doesn't have. It is kept in the file and ignored."]
    );
    let (c, w) = warned("[rules]\nseverities = \"low\"\n");
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(c.settings().severities.is_empty());
    let c = Config::parse("[rules.severities]\n\"PW-999\" = \"low\"\n").unwrap();
    assert!(c.settings().severities.is_empty());
    // `severities` is a key of [rules], not a typo of `severity`.
    assert!(Config::parse("[rules]\nseverity = \"static\"\nseverities = {}\n").is_ok());
}

/// The report: the SET chip on the finding and its rule, the severity fact,
/// the Overview's line under the severity cards, the Environment tab's Rule
/// settings, and What changed's one neutral line.
#[test]
fn the_report_says_what_the_team_set() {
    let (g, stats) = load_dir("forest");
    let render = |c: &Config, earlier: Vec<HistoryPoint>| {
        let (settings, all) = run(&g, &stats, c);
        let p = posture::compute(&g, &all, &[], &settings);
        let plan = pathwarden_core::remediation::plan(
            &g,
            &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
        );
        let history = pathwarden_core::history::ReportHistory {
            earlier,
            ..Default::default()
        };
        let html = pathwarden_core::report::render_html(&pathwarden_core::report::ReportInput {
            posture: &p,
            findings: &all,
            plan: &plan,
            stats: &stats,
            domains: &["CONTOSO.LOCAL".to_string()],
            generated_at: NOW,
            history: &history,
            introduced: None,
            forest: None,
            lists: None,
            kinds: None,
        });
        (html, p)
    };
    let (plain, p0) = render(&config(""), Vec::new());
    assert!(!plain.contains(r#"class="sevset""#));
    assert!(!plain.contains("env-severities"));
    assert!(!plain.contains("Your team set"));
    let earlier = vec![HistoryPoint::new(
        "a",
        NOW - 86_400,
        Some(NOW - 86_400),
        &p0,
        ChangeCounts::default(),
    )];
    let set = config(
        "[rules.severities]\n\"PW-002\" = { severity = \"critical\", by = 'NORTH\\eddard.stark', at = \"2026-10-24T09:00:00Z\" }\n\"PW-011\" = \"low\"\n",
    );
    let (html, _) = render(&set, earlier);
    assert!(html.contains(
        r#"<span class="sevset" title="Severity set by your team. The default is Medium.">set</span>"#
    ));
    assert!(html.contains(
        "<div><dt>Severity</dt><dd>Low &middot; set by your team &middot; default Medium</dd></div>"
    ));
    assert!(html.contains(
        r##"Your team set the severity of 2 rules: <a href="#env-severities">PW-002 and PW-011</a>."##
    ));
    let env = &html[html.find(r#"id="env-severities""#).unwrap()..];
    let env = &env[..env.find("</details>").unwrap()];
    assert!(env.contains("2 severities set by your team"), "{env}");
    assert!(env.contains("<th>Rule</th><th>Severity</th><th>Default</th><th>Set by</th>"));
    assert!(
        env.contains(r"<td>By exposure</td><td>NORTH\eddard.stark on Oct 24, 2026</td>"),
        "{env}"
    );
    assert!(
        env.contains("<td>Medium</td><td><span class=\"muted\">Not recorded</span></td>"),
        "{env}"
    );
    assert!(env.contains("Other rules' attack paths are rated by exposure."));
    assert!(html.contains(
        "Rule severities set in Settings: PW-002 by exposure → Critical, PW-011 Medium → Low."
    ));
    // Counts compared like for like: no severity card moved.
    let cards = &html[html.find(r#"<div class="sevcards">"#).unwrap()..];
    let cards = &cards[..cards.find("</div>").unwrap()];
    assert!(
        !cards.contains("since the last run</span>") || !cards.contains("▲"),
        "{cards}"
    );
}

#[test]
fn default_labels() {
    assert_eq!(findings::default_label("PW-002", true), "exposure");
    assert_eq!(findings::default_label("PW-002", false), "Critical");
    assert_eq!(findings::default_label("PW-011", true), "Medium");
    assert_eq!(findings::default_label("PW-013", true), "High or Low");
    assert_eq!(findings::default_label("PW-028", false), "Low to High");
    assert_eq!(findings::default_label("PW-003", false), "Critical or High");
    // Every rule has one, and nothing else does.
    for r in findings::rules() {
        assert!(findings::default_levels(r.id).is_some(), "{}", r.id);
    }
    assert!(findings::default_levels("PW-024").is_none());
}

/// The run before rated with no severity set; this one sets PW-002 to
/// Critical and PW-011 to Low. Nothing else changed: the earlier counts are
/// re-rated, no severity moves, and the one line about it is neither better
/// nor worse.
#[test]
fn what_changed_is_neutral_when_only_the_settings_changed() {
    let (g, stats) = load_dir("forest");
    let point = |c: &Config, id: &str, at: i64| {
        let (settings, all) = run(&g, &stats, c);
        let p = posture::compute(&g, &all, &[], &settings);
        HistoryPoint::new(id, at, Some(NOW), &p, ChangeCounts::default())
    };
    let before = point(&config(""), "a", 100);
    let set = config("[rules.severities]\n\"PW-002\" = \"critical\"\n\"PW-011\" = \"low\"\n");
    let after = point(&set, "b", 200);
    assert_ne!(before.severity_settings, after.severity_settings);
    assert_ne!(
        (
            before.findings.critical,
            before.findings.medium,
            before.findings.low
        ),
        (
            after.findings.critical,
            after.findings.medium,
            after.findings.low
        ),
        "the raw counts moved"
    );
    let s = pathwarden_core::since::compare(&before, &after, None);
    assert!(!s.rating_changed);
    for (sev, d) in s.open.by_severity() {
        assert!(!d.changed(), "{sev:?}: {d:?}");
    }
    assert!(s.tier_zero_grade.is_none());
    let lines = s.lines();
    assert!(
        lines
            .iter()
            .all(|l| l.tone == pathwarden_core::since::Tone::Same),
        "{lines:?}"
    );
    assert!(s.is_empty());
    let text = s.rating_line().unwrap();
    assert_eq!(
        text,
        "Rule severities set in Settings: PW-002 by exposure → Critical, PW-011 Medium → Low."
    );
    assert!(lines.iter().any(|l| l.text == text));
    // JSON: the changes, and the earlier run's re-rated counts.
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["severities_changed"][0]["rule"], "PW-002");
    assert_eq!(v["severities_changed"][0]["after"], "critical");
    assert!(v["severities_changed"][0]["before"].is_null());

    // Taken off again: the same, the other way.
    let back = pathwarden_core::since::compare(&after, &point(&config(""), "c", 300), None);
    assert!(back.open.by_severity().iter().all(|(_, d)| !d.changed()));
    assert_eq!(
        back.rating_line().unwrap(),
        "Rule severities set in Settings: PW-002 Critical → by exposure, PW-011 Low → Medium."
    );

    // An earlier run that didn't record its counts per rule can't be
    // re-rated: findings by severity aren't compared, and the line says so.
    let mut old = before.clone();
    old.severity_settings = None;
    old.findings.open_by_rule.clear();
    let s = pathwarden_core::since::compare(&old, &after, None);
    assert!(s.rating_changed);
    assert!(s
        .rating_line()
        .unwrap()
        .ends_with("Findings by severity are not compared with the last run."));
    // Attack paths rated another way: not compared either.
    let s = pathwarden_core::since::compare(
        &before,
        &point(&config("[rules]\nseverity = \"static\"\n"), "d", 400),
        None,
    );
    assert!(s.rating_changed && s.severities_changed.is_empty());
    assert_eq!(
        s.rating_line().unwrap(),
        "Attack paths are rated another way in Settings. Findings by severity are not compared with the last run."
    );
    // The same settings: nothing about them.
    let s = pathwarden_core::since::compare(&before, &point(&config(""), "e", 500), None);
    assert!(s.rating_line().is_none() && !s.rating_changed);
    // A rule set to the one level it has anyway changes nothing, not even
    // the digest; one whose default depends on the case says so.
    let same = point(
        &config("[rules.severities]\n\"PW-008\" = \"medium\"\n"),
        "f",
        600,
    );
    assert_eq!(same.severity_settings, before.severity_settings);
    let s = pathwarden_core::since::compare(&before, &same, None);
    assert!(s.rating_line().is_none() && !s.severity_settings_changed);
    let s = pathwarden_core::since::compare(
        &before,
        &point(
            &config("[rules.severities]\n\"PW-013\" = \"high\"\n\"PW-008\" = \"medium\"\n"),
            "g",
            700,
        ),
        None,
    );
    assert_eq!(
        s.rating_line().unwrap(),
        "Rule severities set in Settings: PW-013 default (High or Low) → High."
    );

    // A run that also read other things: one line says both, and
    // "not compared" once.
    let mut quick = after.clone();
    if let Some(c) = quick.completeness.as_mut() {
        c.sessions_targeted = false;
    }
    let s = pathwarden_core::since::compare(&old, &quick, None);
    assert!(!s.comparable() && s.rating_changed);
    let lines = s.lines();
    let first = &lines[0].text;
    assert!(
        first.ends_with(
            "so its counts are not compared with the last run. Rule severities set in Settings: PW-002 by exposure → Critical, PW-011 Medium → Low."
        ),
        "{first}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.text.contains("not compared"))
            .count(),
        1,
        "{lines:?}"
    );

    // A status that moved with the settings is shown, as neither better
    // nor worse.
    let mut moved = after.clone();
    moved.tier_zero_grade = Some(ExposureGrade::Critical);
    let mut was = before.clone();
    was.tier_zero_grade = Some(ExposureGrade::High);
    let s = pathwarden_core::since::compare(&was, &moved, None);
    assert!(s.tier_zero_grade.is_some());
    let line = s
        .lines()
        .into_iter()
        .find(|l| l.text.contains("status"))
        .unwrap();
    assert_eq!(line.tone, pathwarden_core::since::Tone::Same, "{line:?}");
    assert!(
        line.text == "Tier Zero status: High → Critical (rule severities changed in Settings)",
        "{}",
        line.text
    );
    // Without a change of settings it is worse, as before.
    let mut moved = before.clone();
    moved.run_id = "h".into();
    moved.tier_zero_grade = Some(ExposureGrade::Critical);
    let s = pathwarden_core::since::compare(&was, &moved, None);
    let line = s
        .lines()
        .into_iter()
        .find(|l| l.text.contains("status"))
        .unwrap();
    assert_eq!(line.tone, pathwarden_core::since::Tone::Worse);
}
