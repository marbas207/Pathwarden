//! The CLI's front door: grouped help, the built-in demo, and exit codes
//! that mean the same in every command (docs/running.md).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OK: i32 = 0;
const FINDINGS: i32 = 1;
const ERROR: i32 = 2;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn testdata(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-front-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn bare_run_shows_the_groups_and_where_to_start() {
    let dir = scratch("help");
    let o = pw(&dir, &[]);
    assert_eq!(o.status.code(), Some(OK));
    let t = text(&o);
    for group in [
        "Getting started:",
        "Collect:",
        "Analyze:",
        "Track & retest:",
        "Configure & automate:",
    ] {
        assert!(t.contains(group), "{t}");
    }
    assert!(t.contains("New here?"), "{t}");
    assert!(t.contains("-i demo:"), "{t}");
}

#[test]
fn demo_writes_a_report_with_only_the_binary() {
    // Run from an empty folder: nothing from the repository is needed.
    let dir = scratch("demo");
    let o = pw(&dir, &["demo", "-o", "demo.html"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let html = std::fs::read_to_string(dir.join("demo.html")).unwrap();
    assert!(
        html.contains("SCALE.LOCAL"),
        "the demo domain is in the report"
    );
    // The demo's five runs, recorded as a real history: the trend, what
    // changed since the run before, and the Introduced filter with the zone.
    assert!(
        html.contains("last 5 runs &middot; lower is better"),
        "the demo's trend"
    );
    assert!(!html.contains("made-up demo history"));
    assert!(html.contains(r#"<h3 class="sub" id="ov-since-h">What changed since "#));
    assert!(html.contains("3 findings fixed"), "what changed");
    assert!(html.contains("2 members left Tier Zero"), "what changed");
    assert!(
        html.contains("1 new path into R01 servers"),
        "the demo's zone"
    );
    assert!(html.contains(r#"id="f-intro""#), "the Introduced filter");
    // Every finding says when it was first seen, and What changed links
    // what is new (not what was fixed) to the Introduced filter.
    assert!(
        html.contains(r#"<span class="seen">first seen "#),
        "dated findings"
    );
    assert!(html.contains("<dt>First seen</dt>"), "dated findings");
    assert!(
        html.contains(r##"href="#introduced-last" title="Show only what is new since the last run">new findings</a>"##),
        "a link to the new findings"
    );
    assert!(
        !html.contains(r#"">findings fixed</a>"#),
        "fixed isn't linked"
    );
    let t = text(&o);
    assert!(t.contains("pathwarden ui"), "{t}");
    assert!(t.contains("-i demo:"), "{t}");

    // `-i demo:` works on the analysis commands too.
    let o = pw(&dir, &["report", "-i", "demo:", "-o", "r.html"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    assert!(dir.join("r.html").is_file());
}

/// The line saying why Tier Zero has its status is one line, from shared
/// code: `posture` and `run` print it, the report's status badge has it. The report
/// of `run` compares with the runs before it once there are some.
#[test]
fn the_status_reason_is_the_same_everywhere() {
    let dir = scratch("reason");
    let reason = "13 crackable accounts are in or on a path to Tier Zero (10 Kerberoastable, 3 without Kerberos pre-authentication).";
    let o = pw(&dir, &["posture", "-i", "demo:"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let t = text(&o);
    assert_eq!(
        t.lines().next(),
        Some(format!("Status: Critical. {reason}").as_str()),
        "{t}"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&pw(&dir, &["posture", "-i", "demo:", "--json"]).stdout).unwrap();
    assert_eq!(json["tier_zero"]["reason"]["text"], reason);
    assert_eq!(json["tier_zero"]["reason"]["link"]["rule"], "PW-006");

    // No history: this run alone.
    let o = pw(&dir, &["report", "-i", "demo:", "-o", "r.html"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let html = std::fs::read_to_string(dir.join("r.html")).unwrap();
    assert!(html.contains(&format!(
        r#"<span class="grade-badge" title="{reason}">Critical</span>"#
    )));
    assert!(html.contains(r#"<div class="hero card solo">"#));
    assert!(!html.contains(r#"<span class="since">"#));

    // `run --report`: the first run has nothing to compare with, the
    // second has the first.
    for n in 1..=2 {
        let o = pw(
            &dir,
            &[
                "run",
                "-i",
                "demo:",
                "--state",
                "st",
                "--no-push",
                "--report",
                "run.html",
            ],
        );
        assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
        assert!(text(&o).contains(&format!("  {reason}\n")), "{}", text(&o));
        let html = std::fs::read_to_string(dir.join("run.html")).unwrap();
        assert_eq!(html.contains(r#"<span class="since">"#), n == 2, "run {n}");
        assert_eq!(html.contains("last 2 runs"), n == 2, "run {n}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Tier Zero protected reads the same in `posture`, the findings header,
/// `run` and the report: objects and a percentage, never a score.
#[test]
fn tier_zero_protected_is_said_the_same_everywhere() {
    let dir = scratch("protected");
    let words = "53 of 59 objects (89.83%)";

    let o = pw(&dir, &["posture", "-i", "demo:"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains(&format!("\n  Protected:        {words}\n")),
        "{t}"
    );
    assert!(!t.contains("Protection Score"), "{t}");

    let o = pw(&dir, &["findings", "-i", "demo:"]);
    let t = text(&o);
    assert!(
        t.contains(&format!(" · Tier Zero protected: {words} · ")),
        "{t}"
    );
    assert!(!t.contains("Protection Score"), "{t}");

    let o = pw(
        &dir,
        &[
            "run",
            "-i",
            "demo:",
            "--state",
            "st",
            "--no-push",
            "--report",
            "run.html",
        ],
    );
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains(&format!(" · Tier Zero protected: {words}\n")),
        "{t}"
    );
    assert!(!t.contains("Protection Score"), "{t}");

    let html = std::fs::read_to_string(dir.join("run.html")).unwrap();
    assert!(html.contains(&format!(
        r#"<td class="num prot">{words}<span class="cell-label"> protected</span></td>"#
    )));
    assert!(html.contains(&format!(r#"Tier Zero protected: {words}</span></summary>"#)));
    assert!(html.contains(r#"<span class="ov-sub">53 of 59 objects"#));
    assert!(!html.contains("Protection Score"));
    assert!(!html.contains("Higher is better"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fail_on_exits_1_in_findings_and_run() {
    let dir = scratch("fail-on");
    let forest = testdata("forest");
    let o = pw(
        &dir,
        &["findings", "-i", &forest, "--fail-on", "low", "--json"],
    );
    assert_eq!(o.status.code(), Some(FINDINGS), "{}", text(&o));
    let o = pw(&dir, &["findings", "-i", &forest, "--json"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));

    // --rule narrows both the list and what --fail-on looks at.
    let all: serde_json::Value =
        serde_json::from_slice(&pw(&dir, &["findings", "-i", &forest, "--json"]).stdout).unwrap();
    let rule = all[0]["rule"].as_str().unwrap().to_string();
    let o = pw(
        &dir,
        &["findings", "-i", &forest, "--rule", &rule, "--json"],
    );
    let only: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let only = only.as_array().unwrap();
    assert!(!only.is_empty());
    assert!(only.iter().all(|f| f["rule"] == rule.as_str()));
    let o = pw(&dir, &["findings", "-i", &forest, "--rule", "PW-999"]);
    assert_eq!(o.status.code(), Some(ERROR), "unknown rule: {}", text(&o));

    // --by-fix places every open finding under a change or on no path, and
    // --fail-on still applies.
    let o = pw(&dir, &["findings", "-i", &forest, "--by-fix", "--json"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let by_fix: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let mut placed: Vec<&str> = by_fix["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| {
            g["closes"]
                .as_array()
                .unwrap()
                .iter()
                .chain(g["cuts"].as_array().unwrap())
        })
        .chain(by_fix["not_on_a_path"].as_array().unwrap())
        .map(|f| f["fingerprint"].as_str().unwrap())
        .collect();
    placed.sort_unstable();
    placed.dedup();
    let mut open: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["fingerprint"].as_str().unwrap())
        .collect();
    open.sort_unstable();
    assert_eq!(placed, open);
    let o = pw(
        &dir,
        &["findings", "-i", &forest, "--by-fix", "--fail-on", "low"],
    );
    assert_eq!(o.status.code(), Some(FINDINGS), "{}", text(&o));
    assert!(
        text(&o).contains("cut every attack path to Tier Zero"),
        "{}",
        text(&o)
    );

    let o = pw(
        &dir,
        &["run", "-i", &forest, "--state", "st", "--fail-on", "low"],
    );
    assert_eq!(o.status.code(), Some(FINDINGS), "{}", text(&o));
    assert!(
        dir.join("st").join("findings.json").is_file(),
        "state saved first"
    );
    let o = pw(&dir, &["run", "-i", &forest, "--state", "st"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
}

#[test]
fn errors_exit_2_and_say_it_once() {
    let dir = scratch("errors");
    let o = pw(&dir, &["posture", "-i", "nothere"]);
    assert_eq!(o.status.code(), Some(ERROR));
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    let line = err
        .lines()
        .find(|l| l.starts_with("error:"))
        .unwrap_or_default();
    let tail = line.rsplit(": ").next().unwrap();
    assert_eq!(line.matches(tail).count(), 1, "repeated cause: {line}");

    // Usage errors (clap's) and runtime errors share the code.
    assert_eq!(pw(&dir, &["no-such-command"]).status.code(), Some(ERROR));
    assert_eq!(pw(&dir, &["findings"]).status.code(), Some(ERROR));
    assert_eq!(pw(&dir, &["guide", "PW-999"]).status.code(), Some(ERROR));
}

/// `pathwarden` with only these banner-related variables set.
fn bare_with(dir: &Path, vars: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir);
    for v in [
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "COLORTERM",
        "TERM",
        "TERM_PROGRAM",
        "WT_SESSION",
        "ConEmuANSI",
        "LC_ALL",
        "LC_CTYPE",
        "LANG",
        "COLUMNS",
    ] {
        cmd.env_remove(v);
    }
    cmd.envs(vars.iter().copied());
    let o = cmd.output().unwrap();
    assert_eq!(o.status.code(), Some(OK));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn the_banner_follows_the_terminal() {
    let dir = scratch("banner");
    // Piped (as here): no logo, one plain line naming the program.
    let t = bare_with(&dir, &[("WT_SESSION", "1")]);
    assert!(
        t.starts_with("Pathwarden ") && t.contains("Defend every path to privilege."),
        "{t}"
    );
    assert!(
        !t.contains('╲') && !t.contains("\\_/") && !t.contains('\x1b'),
        "{t}"
    );

    // Color forced, Windows Terminal, 100 columns: the line-art hero in truecolor.
    let t = bare_with(
        &dir,
        &[
            ("CLICOLOR_FORCE", "1"),
            ("WT_SESSION", "1"),
            ("COLUMNS", "100"),
        ],
    );
    assert!(
        t.contains('╲') && t.contains('▁') && t.contains("\x1b[38;2;"),
        "{t}"
    );

    // No color: the 7-bit ASCII crown.
    let t = bare_with(
        &dir,
        &[
            ("CLICOLOR_FORCE", "1"),
            ("NO_COLOR", "1"),
            ("COLUMNS", "100"),
        ],
    );
    assert!(
        t.contains("\\_/       \\_/") && t.contains("==============="),
        "{t}"
    );
    let banner = t.lines().take(7).collect::<Vec<_>>().join("\n");
    assert!(banner.is_ascii(), "{banner}");

    // Narrow: the two-line form.
    let t = bare_with(
        &dir,
        &[
            ("CLICOLOR_FORCE", "1"),
            ("WT_SESSION", "1"),
            ("COLUMNS", "60"),
        ],
    );
    assert!(!t.contains('╲') && t.contains("Pathwarden"), "{t}");
}

/// `path --from` a Tier Zero object says so, instead of a one-line path.
#[test]
fn path_from_tier_zero_says_so() {
    let dir = scratch("path-t0");
    let forest = testdata("forest");
    let o = pw(
        &dir,
        &[
            "path",
            "--from",
            "domain admins@contoso.local",
            "-i",
            &forest,
        ],
    );
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains("DOMAIN ADMINS@CONTOSO.LOCAL (Group) is Tier Zero itself"),
        "{t}"
    );
    assert!(!t.contains("already the target"), "{t}");

    // The JSON says so too, beside the zero-step path to itself.
    let o = pw(
        &dir,
        &[
            "path",
            "--from",
            "domain admins@contoso.local",
            "-i",
            &forest,
            "--json",
        ],
    );
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["tier_zero"], true, "{v}");
    assert!(!v["tier_zero_reason"].as_str().unwrap().is_empty(), "{v}");
    assert_eq!(v["steps"].as_array().map(Vec::len), Some(0), "{v}");
}

/// A path ends at the first Tier Zero object: to an object reached only
/// through Tier Zero, `path --to` says so and draws the path up to it, from
/// an ordinary start and from a Tier Zero one (text and JSON alike).
#[test]
fn path_to_an_object_reached_only_through_tier_zero() {
    let dir = scratch("path-through-t0");
    let forest = testdata("forest");
    for (from, last, t0_start) in [
        (
            "carol@child.contoso.local",
            "CHILD_DA@CHILD.CONTOSO.LOCAL",
            false,
        ),
        (
            "child_da@child.contoso.local",
            "DOMAIN ADMINS@CHILD.CONTOSO.LOCAL",
            true,
        ),
    ] {
        let args = [
            "path",
            "--from",
            from,
            "--to",
            "contoso.local",
            "-i",
            &forest,
        ];
        let o = pw(&dir, &args);
        assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
        let t = text(&o);
        assert!(
            t.contains("CONTOSO.LOCAL is reached only through Tier Zero."),
            "{t}"
        );
        assert!(!t.contains("SameForestTrust"), "{t}");
        let o = pw(&dir, &[&args[..], &["--json"]].concat());
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(
            v["through_tier_zero"], "CONTOSO.LOCAL is reached only through Tier Zero.",
            "{v}"
        );
        assert_eq!(v["target"], last, "{v}");
        assert_eq!(v["tier_zero"] == true, t0_start, "{v}");
    }
}

/// `summary` counts a trust both domains recorded once, in the text and
/// in the JSON.
#[test]
fn summary_counts_each_trust_once() {
    let dir = scratch("summary-trusts");
    let input = testdata("rusthound");
    let o = pw(&dir, &["summary", "-i", &input, "--json"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let sides = v["ingest"]["trusts"].as_array().unwrap().len();
    let trusts = v["trusts"].as_array().unwrap();
    assert!(trusts.len() < sides, "{v}");
    assert!(trusts.iter().any(|t| t["other_side"].is_object()), "{v}");
    assert!(trusts.iter().all(|t| t["source"].is_string()), "{v}");

    let o = pw(&dir, &["summary", "-i", &input]);
    assert!(
        text(&o).contains(&format!("Trusts ({})", trusts.len())),
        "{}",
        text(&o)
    );
}

/// `summary` groups the domains into forests and flags each trust, in the
/// text and, as the app's API returns it, in the JSON.
#[test]
fn summary_maps_the_forest() {
    let dir = scratch("summary-forest");
    let input = testdata("forest");
    let o = pw(&dir, &["summary", "-i", &input, "--json"]);
    assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let forest = &v["forest"];
    assert_eq!(forest["forests"].as_array().unwrap().len(), 2, "{forest}");
    assert_eq!(forest["domains"][2]["name"], "FABRIKAM.COM");
    assert_eq!(forest["domains"][2]["collected"], false);
    let trusts = forest["trusts"].as_array().unwrap();
    assert_eq!(trusts.len(), v["trusts"].as_array().unwrap().len());
    assert_eq!(trusts[0]["enables_forest_takeover"], true);
    assert_eq!(trusts[1]["abusable_sid_history"], true);
    assert_eq!(forest["headline"]["lead"], "3 domains in 2 forests");
    assert_eq!(forest["headline"]["sid_history_abuse"], 1);

    let o = pw(&dir, &["summary", "-i", &input]);
    let out = text(&o);
    // The line above the app's Forest view, and its status.
    assert!(
        out.contains("3 domains in 2 forests · 2 trusts, 1 between forests · 1 not collected"),
        "{out}"
    );
    assert!(out.contains("1 trust with SID history abuse"), "{out}");
    assert!(out.contains("Forests (2, 3 domains)"), "{out}");
    assert!(
        out.contains(pathwarden_core::forest::TIER_ZERO_NOT_LISTED),
        "{out}"
    );
    assert!(out.contains("recorded by CONTOSO.LOCAL only"), "{out}");
    // Nothing crosses either trust, said as the Forest view says it.
    assert!(out.contains("Nothing else crosses it."), "{out}");
    assert!(out.contains("Nothing in the data crosses it."), "{out}");
    assert!(!out.contains("(below)"), "{out}");
    assert!(out.contains("not collected (known from a trust)"), "{out}");
    assert!(out.contains("Forest takeover:"), "{out}");
    assert!(out.contains("SID history abuse (PW-012):"), "{out}");
    assert!(out.contains("CONTOSO.LOCAL trusts FABRIKAM.COM"), "{out}");
    assert!(
        out.contains("FABRIKAM.COM into CONTOSO.LOCAL: SID filtering off"),
        "{out}"
    );
}

/// A user named like a certificate template (as in GOAD) is found at
/// either end of `path`, and two objects with one full name are told
/// apart only by their IDs.
#[test]
fn path_ends_prefer_principals() {
    let dir = scratch("path-ends");
    let input = dir.join("in");
    std::fs::create_dir_all(&input).unwrap();
    for e in std::fs::read_dir(testdata("adcs")).unwrap() {
        let p = e.unwrap().path();
        std::fs::copy(&p, input.join(p.file_name().unwrap())).unwrap();
    }
    let user = |sid: &str, name: &str| {
        serde_json::json!({
            "ObjectIdentifier": format!("S-1-5-21-5000-5000-5000-{sid}"),
            "PrimaryGroupSID": "S-1-5-21-5000-5000-5000-513",
            "Properties": {
                "name": name,
                "domain": "PKI.LOCAL",
                "domainsid": "S-1-5-21-5000-5000-5000",
                "enabled": true
            },
            "Aces": []
        })
    };
    // USER@PKI.LOCAL is also a certificate template in the fixture.
    let extra = serde_json::json!({
        "data": [
            user("1190", "USER@PKI.LOCAL"),
            user("1191", "TWIN@PKI.LOCAL"),
            user("1192", "TWIN@PKI.LOCAL"),
        ],
        "meta": { "methods": 0, "type": "users", "count": 3, "version": 6 }
    });
    std::fs::write(input.join("extra_users.json"), extra.to_string()).unwrap();
    let input = input.to_string_lossy().into_owned();

    for (from, to) in [
        ("alice@pki.local", "user@pki.local"),
        ("user@pki.local", "alice@pki.local"),
    ] {
        let o = pw(&dir, &["path", "--from", from, "--to", to, "-i", &input]);
        assert_eq!(o.status.code(), Some(OK), "{}", text(&o));
        assert!(!text(&o).contains("ambiguous"), "{}", text(&o));
    }

    let o = pw(
        &dir,
        &[
            "path",
            "--from",
            "alice@pki.local",
            "--to",
            "twin@pki.local",
            "-i",
            &input,
        ],
    );
    assert_eq!(o.status.code(), Some(ERROR), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("is ambiguous. Use the object ID:"), "{t}");
    assert!(t.contains("S-1-5-21-5000-5000-5000-1191"), "{t}");
}
