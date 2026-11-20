//! The Progress page from a run history written here: the time range, the
//! cards and what changed since the last run, the five charts, the notes
//! for older runs, and the empty and one-run states.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use pathwarden_core::state::HistoryPoint;
use pathwarden_ui::security::Token;
use pathwarden_ui::server::{router, AppState};
use pathwarden_ui::workspace::Workspace;
use serde_json::json;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:4251";
const DAY: i64 = 86_400;
/// The latest run's time (2026-10-20).
const LATEST: i64 = 1_792_454_400;

struct App {
    router: Router,
    state: Arc<AppState>,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app(name: &str) -> App {
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-pv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ws = Workspace::open(dir.join("ws")).unwrap();
    let state = Arc::new(AppState::new(ws, Token::generate().unwrap(), 4251));
    App {
        router: router(state.clone()),
        state,
        dir,
    }
}

impl App {
    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::COOKIE, self.state.session_cookie())
            .body(Body::empty())
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.join("ws").join("pathwarden-state")
    }

    /// Writes history points into the workspace's run history, and a last
    /// run that names the domain.
    fn history(&self, points: &[HistoryPoint]) {
        let dir = self.state_dir().join("history");
        std::fs::create_dir_all(&dir).unwrap();
        for p in points {
            std::fs::write(
                dir.join(format!("{}.json", p.run_id)),
                serde_json::to_vec(p).unwrap(),
            )
            .unwrap();
        }
        let last = points.last().unwrap();
        std::fs::write(
            self.state_dir().join("last-run.json"),
            json!({"version": 1, "run_id": last.run_id, "started_at": last.at,
                "finished_at": last.at, "collected_at": null, "pathwarden": "test",
                "collector_files": 1, "domains": ["CONTOSO.LOCAL"], "objects": 100,
                "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0, "resolved": 0}})
            .to_string(),
        )
        .unwrap();
    }
}

/// One run `weeks_ago` weeks before the latest, with the risk-scoring figures
/// (zones, completeness, plan) unless `old`.
#[allow(clippy::too_many_arguments)]
fn point(
    weeks_ago: i64,
    exposed: usize,
    zone: usize,
    steps: usize,
    critical: usize,
    attack: usize,
    sessions: f64,
    old: bool,
) -> HistoryPoint {
    let at = LATEST - weeks_ago * 7 * DAY;
    let mut v = json!({
        "version": 1, "run_id": format!("r{at}"), "at": at, "collected_at": null,
        "tier_zero_exposure_percent": exposed as f64 / 10.0, "tier_zero_exposed": exposed,
        "tier_zero_population": 1000, "tier_zero_relevant_population": 1000,
        "exposure_basis": 2, "tier_zero_objects": 40 + (10 - weeks_ago) as usize,
        "protection_score": 90.0 - weeks_ago as f64,
        "tier_zero_grade": if critical > 0 { "Critical" } else { "High" },
        "plan": {"steps": steps, "exposed_after": 0},
        "findings": {"attack_path": attack, "hygiene": 3, "suppressed": 0,
            "critical": critical, "high": 2, "medium": 1, "low": attack, "info": 0},
        "changes": {"new": 1, "open": 5, "regressed": 0, "suppressed": 0, "resolved": 2},
        "zones": [{"zone": "Tier 1 <servers>", "exposure_percent": 1.0,
            "protection_score": 50.0, "objects": 12, "exposed": zone, "grade": "High"}],
        "completeness": {"computers": 100, "sessions_collected": sessions as usize,
            "sessions_percent": sessions, "member_computers": 90,
            "local_groups_collected": 88, "local_groups_percent": 97.0,
            "low_domains": usize::from(sessions < 80.0)},
    });
    if old {
        let o = v.as_object_mut().unwrap();
        o.remove("plan");
        o.remove("completeness");
        o.remove("tier_zero_grade");
        o["zones"][0]
            .as_object_mut()
            .unwrap()
            .retain(|k, _| !matches!(k.as_str(), "objects" | "exposed" | "grade"));
    }
    let p: HistoryPoint = serde_json::from_value(v).unwrap();
    p.with_domains(&["CONTOSO.LOCAL".to_string()])
}

/// Eight weekly runs, the first from before the risk-scoring figures.
fn series() -> Vec<HistoryPoint> {
    vec![
        point(7, 9100, 9000, 6, 4, 9, 88.0, true),
        point(6, 8975, 8900, 5, 4, 9, 88.0, false),
        point(5, 4713, 4600, 4, 3, 8, 90.0, false),
        point(4, 2335, 1200, 3, 3, 7, 64.0, false),
        point(3, 2455, 1180, 4, 3, 7, 91.0, false),
        point(2, 900, 300, 3, 2, 5, 92.0, false),
        point(1, 120, 40, 2, 2, 4, 93.0, false),
        point(0, 31, 12, 1, 1, 2, 94.0, false),
    ]
}

#[tokio::test]
async fn progress_charts_the_history_over_a_range() {
    let a = app("charts");
    a.history(&series());
    let (s, body) = a.get("/progress").await;
    assert_eq!(s, StatusCode::OK);

    // The time range: 3 months by default, each a link keeping the
    // environment.
    for r in ["1w", "1m", "3m", "all"] {
        assert!(body.contains(&format!("range={r}")), "{r}: {body}");
    }
    assert!(
        body.contains(r#"range=3m" aria-current="page">3 months</a>"#),
        "{body}"
    );

    // The cards: one number each, with its change since the last run.
    for want in [
        "With an attack path to Tier Zero · Critical",
        r#"<span class="kpi-value">31</span>"#,
        "Remediation path steps",
        r#"<span class="kpi-value">1</span>"#,
        "Open findings",
        "Tier Zero protected",
        r#"<span class="kpi-value">90.00%</span>"#,
        "since the last run",
        r#"<span class="vh">down</span> 89"#,
        r#"<span class="vh">up</span> 1.00 pts"#,
        // The change over the range, and the objects behind the share.
        r#"<span class="vh">down</span> 9,069</span> in 7 weeks"#,
        "45 of 50 objects",
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    // What changed: the lines `pathwarden history` prints, from the same
    // comparison, the zone's name escaped.
    assert!(body.contains("What changed since"), "{body}");
    let since = pathwarden_core::since::compare(&series()[6], &series()[7], None);
    for l in since.lines() {
        assert!(
            body.contains(&pathwarden_ui::pages::esc(&l.text)),
            "{}: {body}",
            l.text
        );
    }
    assert!(body.contains("Tier 1 &lt;servers&gt;"), "{body}");
    assert!(!body.contains("Tier 1 <servers>"), "{body}");

    // The five charts, each with a title, a subtitle and a legend.
    for title in [
        "Accounts with an attack path to each tier",
        "Remediation path steps",
        "Open findings and attack paths",
        "Objects per tier",
        "Collection completeness",
    ] {
        assert!(
            body.contains(&format!(r#"<h2 class="sub">{title}"#)),
            "{title}"
        );
    }
    assert_eq!(body.matches(r#"<ul class="pv-legend">"#).count(), 5);
    // From 9,100 to 31: log by default, both scales drawn.
    assert!(
        body.contains(r#"value="lin">Linear"#) && body.contains(r#"value="log" checked>Log"#),
        "{body}"
    );
    assert!(body.contains("pv-lin") && body.contains("pv-log"));
    // The attack path line is part of the bars, and the legend says so.
    assert!(body.contains("Attack path findings (dashed)"));
    assert!(body.contains(r#"class="pv-line attack dashed""#), "{body}");
    // The dip below 80% is shaded, and says so in full even with eight
    // runs (a band narrower than its words).
    assert!(body.contains(r#"class="pv-low""#), "{body}");
    assert!(body.contains("Below 80%: counts may be low"));
    assert!(
        body.contains(r#"class="pv-low-label""#) && !body.contains(">low</text>"),
        "{body}"
    );
    // Each line's values are labeled in its colour, so a label reads with
    // its own line.
    for class in ["s1", "s2", "sess", "lg"] {
        assert!(
            body.contains(&format!(r#"class="pv-val end halo {class}""#)),
            "{class}: {body}"
        );
    }
    // Objects per tier has a hover/focus target per run, too, with each
    // row's count.
    let objects = &body[body.find(r#"pv card pv-objects"#).unwrap()..];
    let objects = &objects[..objects.find("</figure>").unwrap()];
    assert_eq!(objects.matches(r#"class="pv-hit""#).count(), 8, "{objects}");
    assert!(objects.contains("Tier Zero: 50 objects"), "{objects}");
    assert!(objects.contains("not recorded"), "{objects}");
    // The oldest run lacks the zone figures, the plan and completeness:
    // their lines start at the next run, and the page says so.
    assert!(
        body.contains("Tier 1 &lt;servers&gt; is charted from"),
        "{body}"
    );
    assert!(
        body.contains("didn't record the remediation path"),
        "{body}"
    );
    assert!(
        body.contains("didn't record collection completeness"),
        "{body}"
    );
    // Definitions: in (i) tooltips, and all of them at the bottom.
    assert!(body.contains(r#"class="tip-btn""#));
    assert!(body.contains("All definitions"));
    assert!(!body.contains(" style=\""));

    // A week: the two latest runs, and the page says how many it left out.
    let (_, week) = a.get("/progress?range=1w").await;
    assert!(week.contains(r#"range=1w" aria-current="page""#), "{week}");
    assert!(
        week.contains("2 of 8 runs: the week up to the latest."),
        "{week}"
    );
    assert!(!week.contains("runs are charted;"), "{week}");
    // All: every run, no note.
    let (_, all) = a.get("/progress?range=all").await;
    assert!(!all.contains("runs: the "), "{all}");
    assert!(!all.contains("runs are charted;"), "{all}");
    assert!(all.matches(r#"class="pv-hit""#).count() > week.matches(r#"class="pv-hit""#).count());
}

/// Counts within ten times of each other: linear by default.
#[tokio::test]
async fn small_moves_are_linear() {
    let a = app("linear");
    a.history(&[
        point(1, 40, 30, 2, 1, 3, 95.0, false),
        point(0, 31, 25, 1, 1, 2, 96.0, false),
    ]);
    let (_, body) = a.get("/progress").await;
    assert!(body.contains(r#"value="lin" checked>Linear"#), "{body}");
    assert!(!body.contains("pv-low\""), "no dip: {body}");
}

/// A Quick run after Full ones: the completeness lines end at the last
/// Full run, its slot says "not targeted" (no "counts may be low"), the
/// attack-path chart marks it, and the cards don't compare it with a Full
/// run.
#[tokio::test]
async fn a_quick_run_is_not_targeted_not_a_dip() {
    let a = app("quick");
    let mut quick = point(0, 1, 1, 1, 1, 2, 0.0, false);
    quick.completeness = Some(pathwarden_core::state::CompletenessPoint {
        computers: 0,
        sessions_collected: 0,
        sessions_percent: 0.0,
        member_computers: 0,
        local_groups_collected: 0,
        local_groups_percent: Some(0.0),
        low_domains: 0,
        sessions_targeted: false,
        local_groups_targeted: false,
        untargeted_domains: Vec::new(),
    });
    a.history(&[
        point(2, 900, 300, 3, 2, 5, 92.0, false),
        point(1, 880, 290, 3, 2, 5, 93.0, false),
        quick,
    ]);
    let (_, body) = a.get("/progress").await;
    assert!(!body.contains("pv-low\""), "no dip band: {body}");
    assert!(!body.contains("counts may be low</text>"), "{body}");
    // One label on each chart that marks it (the accounts chart twice: linear and log).
    assert_eq!(body.matches(r#"class="pv-nt""#).count(), 3, "{body}");
    assert!(body.contains("Sessions not targeted"), "{body}");
    assert!(body.contains("Local groups not targeted"), "{body}");
    assert!(
        body.contains("Sessions and local groups not targeted"),
        "{body}"
    );
    assert_eq!(
        body.matches(r#"<td class="muted">Not targeted</td>"#)
            .count(),
        2,
        "{body}"
    );
    assert!(
        body.contains("Not targeted: the run didn&#39;t ask for them.")
            || body.contains("Not targeted: the run didn't ask for them."),
        "{body}"
    );
    // The cards and What changed: not compared with the Full run.
    assert!(body.contains("not compared with the last run"), "{body}");
    assert!(!body.contains("since the last run</span>"), "{body}");
    assert!(
        body.contains("Sessions and local groups were not targeted this run, so its counts are not compared with the last run."),
        "{body}"
    );
}

/// No run, one run, and one run in the range: an action instead of charts
/// of a single dot.
#[tokio::test]
async fn empty_and_single_runs_offer_an_action() {
    let a = app("empty");
    let (_, body) = a.get("/progress").await;
    assert!(body.contains("No runs yet."), "{body}");
    // The empty state Home has.
    assert!(body.contains(r#"href="/collect""#) && body.contains("Collect or analyze"));

    a.history(&[point(0, 31, 12, 1, 1, 2, 94.0, false)]);
    let (_, body) = a.get("/progress").await;
    assert!(body.contains("One run so far"), "{body}");
    assert!(body.contains("> Analyze</a>"), "{body}");
    assert!(!body.contains(r#"<figure class="pv"#), "no charts: {body}");
    assert!(!body.contains("What changed since"), "{body}");
    assert!(body.contains("the first run"), "{body}");
    // No range switch for a single run.
    assert!(!body.contains("range=1w"), "{body}");

    // Two runs ten weeks apart: one in the last week.
    let b = app("one-in-range");
    b.history(&[
        point(10, 40, 30, 2, 1, 3, 95.0, false),
        point(0, 31, 25, 1, 1, 2, 96.0, false),
    ]);
    let (_, body) = b.get("/progress?range=1w").await;
    assert!(
        body.contains("One run in the week up to the latest."),
        "{body}"
    );
    assert!(body.contains("Show all 2 runs"), "{body}");
    assert!(body.contains("What changed since"), "{body}");
    assert!(!body.contains(r#"<figure class="pv"#), "{body}");
}

/// More runs than the page charts: on All it says the latest 40 are
/// charted and where the rest are, with no "Show all" back to itself; on a
/// range it says both what the range and what the cap leave out.
#[tokio::test]
async fn more_runs_than_charted() {
    let a = app("many");
    let pts: Vec<HistoryPoint> = (0..50)
        .rev()
        .map(|days_ago| {
            let mut p = point(0, 100 + days_ago as usize, 50, 3, 1, 2, 95.0, false);
            p.at = LATEST - days_ago * DAY;
            p.run_id = format!("r{}", p.at);
            p
        })
        .collect();
    a.history(&pts);
    let (_, all) = a.get("/progress?range=all").await;
    assert!(
        all.contains("The latest 40 of these 50 runs are charted."),
        "{all}"
    );
    assert!(!all.contains("Show all"), "{all}");
    assert!(!all.contains("runs: the "), "{all}");
    // 40 runs in each chart's hover layer (the accounts chart twice).
    assert_eq!(all.matches(r#"class="pv-hit""#).count(), 40 * 6);
    // Three months: 50 of 50 runs in range, 40 charted.
    let (_, q) = a.get("/progress?range=3m").await;
    assert!(!q.contains("runs: the "), "{q}");
    assert!(
        q.contains("The latest 40 of these 50 runs are charted."),
        "{q}"
    );
    // A month: 31 of 50, all charted.
    let (_, m) = a.get("/progress?range=1m").await;
    assert!(
        m.contains("31 of 50 runs: the month up to the latest."),
        "{m}"
    );
    assert!(!m.contains("runs are charted;"), "{m}");
}

/// A history from before the risk-scoring figures: no plan, completeness or
/// objects. Those figures are a card with what to do, not an empty chart.
#[tokio::test]
async fn figures_no_run_recorded_are_not_charted() {
    let a = app("old");
    let mut old = vec![
        point(2, 900, 300, 3, 2, 5, 92.0, true),
        point(1, 120, 40, 2, 2, 4, 93.0, true),
        point(0, 31, 12, 1, 1, 2, 94.0, true),
    ];
    for p in &mut old {
        p.tier_zero_objects = 0;
    }
    a.history(&old);
    let (_, body) = a.get("/progress").await;
    assert_eq!(
        body.matches("pv-empty").count(),
        3,
        "plan, objects, completeness: {body}"
    );
    assert_eq!(body.matches("Analyze again to record it").count(), 3);
    assert!(
        body.contains("No run in this range recorded the remediation path"),
        "{body}"
    );
    assert!(
        !body.contains(r#"<span class="sw plan">"#),
        "no legend: {body}"
    );
    assert!(!body.contains(r#"<span class="sw sess">"#), "{body}");
    // The accounts and findings still chart.
    assert_eq!(body.matches(r#"<ul class="pv-legend">"#).count(), 2);
}

/// More zones than the accounts chart draws: Objects per tier draws the
/// same ones and points to the rest, as `pathwarden history` does.
#[tokio::test]
async fn objects_per_tier_draws_the_charted_zones() {
    let a = app("zones");
    let zones = |p: &mut HistoryPoint| {
        let z = p.zones[0].clone();
        p.zones = ["Alpha", "Beta", "Gamma", "Delta"]
            .iter()
            .map(|n| {
                let mut z = z.clone();
                z.zone = n.to_string();
                z
            })
            .collect();
    };
    let mut pts = vec![
        point(1, 120, 40, 2, 2, 4, 93.0, false),
        point(0, 31, 12, 1, 1, 2, 94.0, false),
    ];
    pts.iter_mut().for_each(zones);
    a.history(&pts);
    let (_, body) = a.get("/progress").await;
    let objects = &body[body.find("pv-objects").unwrap()..];
    let objects = &objects[..objects.find("</figure>").unwrap()];
    assert!(
        objects.contains("Alpha") && objects.contains("Beta"),
        "{objects}"
    );
    assert!(!objects.contains("Gamma"), "{objects}");
    assert!(
        objects.contains("and 2 more zones not charted"),
        "{objects}"
    );
    assert!(!objects.contains("sw s0"), "{objects}");
}

/// What changed over a period: the picker beside the heading, and for a
/// period everything net new in it from the findings state, the lines
/// `pathwarden changes --since` prints, with the note for a period that
/// reaches back before objects were dated.
#[tokio::test]
async fn what_changed_over_a_period() {
    let a = app("introduced");
    a.history(&series());
    let since = LATEST - 6 * 7 * DAY;
    let k = |t: i64| t.to_string();
    let env = pathwarden_core::introduced::env_key(&pathwarden_core::state::scopes_of(&[
        "CONTOSO.LOCAL".to_string(),
    ]));
    let state = json!({
        "version": 1,
        "tracked_since": since,
        "findings": {
            "PW-011-a": {"rule": "PW-011", "severity": "high", "category": "hygiene",
                "status": "open", "first_seen": LATEST - 2 * DAY, "last_seen": LATEST,
                "times_seen": 1},
            "PW-008-b": {"rule": "PW-008", "severity": "medium", "category": "hygiene",
                "status": "open", "first_seen": since, "last_seen": LATEST, "times_seen": 7,
                "objects": {"since": since, "seen": {
                    k(since): ["aaaaaaaaaaaaaaaa"],
                    k(LATEST - 7 * DAY): ["bbbbbbbbbbbbbbbb", "cccccccccccccccc"]}}},
            "PW-003-c": {"rule": "PW-003", "severity": "high", "category": "attack_path",
                "status": "resolved", "first_seen": since, "last_seen": LATEST - 7 * DAY,
                "resolved_at": LATEST - 3 * DAY, "times_seen": 6}
        },
        // The zones of the history's environment (its points' domains).
        "paths": {"envs": {env: {"at": LATEST, "zones": {"Tier Zero": {"since": since, "open": {
            k(since): ["1111111111111111"], k(LATEST): ["2222222222222222"]}}}}}}
    });
    std::fs::write(a.state_dir().join("findings.json"), state.to_string()).unwrap();

    // By default, since the last run; the other choice is the page's
    // own time range, the one switch.
    let (_, body) = a.get("/progress").await;
    assert!(body.contains("What changed since"), "{body}");
    assert!(
        body.contains(r#"range=3m" aria-current="true">Since the last run</a>"#),
        "{body}"
    );
    assert!(
        body.contains(r#"range=3m&amp;changes=range">Over 3 months</a>"#),
        "{body}"
    );
    assert_eq!(
        body.matches("pv-changes").count(),
        0,
        "no second range switch"
    );
    // The last run added a path into Tier Zero: since the last run says so.
    assert!(body.contains("1 new path into Tier Zero"), "{body}");

    // Over the month the page shows: the lines of `pathwarden changes
    // --since 30d`.
    let (s, body) = a.get("/progress?range=1m&changes=range").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("Introduced in the 30 days up to Oct 20 (first seen by Pathwarden)"),
        "{body}"
    );
    for want in [
        "1 new finding",
        "1 older finding gained 2 objects",
        "1 new path into Tier Zero",
        "1 finding fixed",
        r#"changes=range" aria-current="true">Over the month</a>"#,
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    // The terminal's commands stay in the terminal.
    assert!(!body.contains("pathwarden findings --introduced"), "{body}");
    // The range switch keeps What changed on the range.
    assert!(body.contains("range=1w&amp;changes=range"), "{body}");
    assert!(
        !body.contains(r#"class="muted small pv-note""#),
        "after tracking began: {body}"
    );
    // Its days and dates are UTC, as `pathwarden changes` says them, not
    // the local time of the charts beside it; the date fields say so too.
    assert!(
        body.contains(r#"<p class="muted small pv-utc">Dates are UTC.</p>"#),
        "{body}"
    );
    assert!(
        body.contains(r#"<span class="muted small">Dates are UTC.</span>"#),
        "{body}"
    );

    // The whole history reaches back to the run tracking began in (run 2).
    let (_, body) = a.get("/progress?range=all&changes=range").await;
    assert!(
        body.contains("Objects and paths are dated from Sep 8 (run 2) on; before that, only whole findings are."),
        "{body}"
    );

    // Two days: only what they hold.
    let (_, body) = a
        .get("/progress?env=x&range=3m&from=2026-10-19&to=2026-10-20")
        .await;
    assert!(body.contains("Introduced from Oct 19 to Oct 20"), "{body}");
    assert!(body.contains("1 new path into Tier Zero"), "{body}");
    assert!(!body.contains("1 new finding"), "{body}");
    assert!(body.contains(r#"name="from" value="2026-10-19""#), "{body}");

    // Only To: up to that day.
    let (_, body) = a.get("/progress?to=2026-10-19").await;
    assert!(body.contains("Introduced up to Oct 19"), "{body}");
    assert!(body.contains(r#"name="to" value="2026-10-19""#), "{body}");

    // To before From: said, and the last run shown.
    let (s, body) = a.get("/progress?from=2026-10-25&to=2026-10-01").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("The To day is before the From day"), "{body}");
    assert!(
        body.contains(r#"name="from" value="2026-10-25""#),
        "kept: {body}"
    );
    assert!(body.contains("What changed since"), "{body}");

    // With the latest run in the app, each card links to its report's
    // Findings tab on the same period, which names what the lines count.
    let rdir = a.dir.join("ws").join("runs").join("20261020-000000-abcdef");
    std::fs::create_dir_all(&rdir).unwrap();
    let summary = json!({"id": "20261020-000000-abcdef", "created_at": LATEST,
        "collected_at": null, "source": "Uploaded", "demo": false,
        "domains": ["CONTOSO.LOCAL"], "objects": 1, "files": 1,
        "exposure_percent": 3.1, "exposed": 31, "population": 1000,
        "protection_score": 94.0, "critical": 1, "high": 2, "medium": 1, "low": 2,
        "info": 0, "suppressed": 0, "plan_steps": 1, "pathwarden": "0.1.0",
        "history": {"run_id": format!("r{LATEST}")}});
    std::fs::write(rdir.join("summary.json"), summary.to_string()).unwrap();
    std::fs::write(rdir.join("report.html"), "<html></html>").unwrap();
    let (_, body) = a.get("/progress").await;
    assert!(
        body.contains(
            r#"href="/runs/20261020-000000-abcdef#introduced-last">See them in the report"#
        ),
        "{body}"
    );
    let (_, body) = a.get("/progress?range=1m&changes=range").await;
    assert!(
        body.contains(r#"href="/runs/20261020-000000-abcdef#introduced-30">"#),
        "{body}"
    );
    let (_, body) = a.get("/progress?from=2026-10-19").await;
    assert!(
        body.contains(r#"href="/runs/20261020-000000-abcdef#introduced-2026-10-19_2026-10-20">"#),
        "{body}"
    );

    // Junk, and a period ending in a character of more than one byte: the
    // last run, not an error (nor a panic).
    for junk in ["7%C3%A9", "%E6%97%A5", "x", "%F0%9F%98%80d"] {
        let (s, body) = a.get(&format!("/progress?changes={junk}")).await;
        assert_eq!(s, StatusCode::OK, "{junk}");
        assert!(body.contains("What changed since"), "{junk}: {body}");
    }
}
