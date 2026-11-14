//! What is net new over a period, from the run history: `pathwarden
//! changes --since 3d` and `pathwarden findings --introduced 7d`. The
//! period, what counts as new and the words are the app's own
//! ([`pathwarden_core::introduced`]): the report's Introduced filter and
//! the Progress page's What changed show the same.

use std::path::Path;
use std::process::ExitCode;

use anstream::println;
use anyhow::{bail, Result};
use pathwarden_core::config::Config;
use pathwarden_core::findings::{Finding, Severity};
use pathwarden_core::introduced::{self, Badge, Introduced, Names, Period, Runs};
use pathwarden_core::state::FindingsState;
use pathwarden_core::store;

use crate::progress::{self, Through};
use crate::{emit_json, exit, read_config, run_rules, settings_args, Input};

/// The run history a period is read from.
pub(crate) struct History {
    pub state: FindingsState,
    /// The latest run: the one that left the findings state.
    pub latest: i64,
    /// The environment's runs, to number them.
    pub runs: Runs,
    /// The history's points, oldest first.
    pub points: Vec<pathwarden_core::state::HistoryPoint>,
}

/// The findings state and history under `state` (or the config's
/// `[state]`), numbering the runs of `domains` (or the latest run's
/// environment).
pub(crate) fn history(
    config: &Config,
    state: Option<&Path>,
    domains: Option<&[String]>,
) -> Result<History> {
    let store = store::Store::new(&config.state, state)?;
    if !store.dir.is_dir() {
        bail!(
            "No run history at {}. Run `pathwarden run` first, or point --state at the history folder.",
            store.dir.display()
        );
    }
    store.check_expected()?;
    let (points, _) = pathwarden_core::history::load(&store.dir).map_err(anyhow::Error::msg)?;
    let found = store.load()?;
    let (latest, runs) = introduced::runs_of(&points, domains);
    let Some(latest) = latest.or_else(|| introduced::latest(&found)) else {
        bail!(
            "no runs recorded in {}: run `pathwarden run` first",
            store.dir.display()
        );
    };
    Ok(History {
        state: found,
        latest,
        runs,
        points,
    })
}

/// `--since YYYY-MM-DD` of `findings`: from that day on.
pub(crate) fn parse_day(s: &str) -> std::result::Result<Period, String> {
    match Period::parse(s)? {
        p @ (Period::From(_) | Period::Between(..)) => Ok(p),
        _ => Err(format!(
            "'{s}' is not a day: use YYYY-MM-DD (or --introduced for 7d, 30d, last)"
        )),
    }
}

pub(crate) fn parse_period(s: &str) -> std::result::Result<Period, String> {
    Period::parse(s)
}

/// What `changes --fail-on` fails on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailOn {
    /// Anything new: a new or returning finding, objects gained, a new path
    /// or a new member of Tier Zero or a zone. A path or member back after
    /// it was resolved is not new: sessions come and go with logons.
    New,
    /// A new, returning or grown finding at least this severe.
    Severity(Severity),
}

pub(crate) fn parse_fail_on(s: &str) -> std::result::Result<FailOn, String> {
    if s.trim().eq_ignore_ascii_case("new") {
        return Ok(FailOn::New);
    }
    s.parse::<Severity>()
        .map(FailOn::Severity)
        .map_err(|_| format!("'{s}': use new, or a severity (info, low, medium, high, critical)"))
}

impl FailOn {
    /// Whether `intro` has what it fails on.
    fn fails(self, intro: &Introduced) -> bool {
        match self {
            FailOn::New => {
                !intro.findings.is_empty() || intro.new_paths() > 0 || intro.joined() > 0
            }
            FailOn::Severity(min) => intro.findings.iter().any(|f| f.severity >= min),
        }
    }
}

/// The environment had no run before the latest, and the period is since
/// the last run: there is nothing to compare with (the report and Progress
/// offer no such period then).
pub(crate) fn no_earlier(h: &History, period: Period) -> bool {
    period == Period::LastRun && h.runs.len() == 1
}

/// "New, first seen Oct 18 (run 3)", "Back Oct 18 (run 3)", "+3 objects".
pub(crate) fn badge_words(f: &introduced::IntroFinding, h: &History) -> String {
    match f.badge {
        Badge::New => format!(
            "New, {}",
            introduced::seen_label(f.at, false, &h.runs, h.latest)
        ),
        Badge::Back => {
            let label = introduced::seen_label(f.at, true, &h.runs, h.latest);
            format!("Back {}", label.trim_start_matches("back "))
        }
        Badge::Gained(_) => f.label.clone(),
    }
}

/// `pathwarden changes --since PERIOD`: everything net new in the period
/// and what was fixed, as the Progress page's What changed lists it. With
/// `-i`, the objects and paths are named and each path gets the remediation
/// step that cuts it; with `paths`, every new member and path follows, one
/// a line, as the report's Findings tab lists them. `fail_on`: exit with
/// status 1 when the period has that.
pub(crate) fn changes(
    input: &Input,
    period: Period,
    state: Option<&Path>,
    fail_on: Option<FailOn>,
    paths: bool,
) -> Result<ExitCode> {
    let config = read_config(input)?;
    let analysis = if input.input.is_empty() {
        None
    } else {
        let mut p = progress::Analysis::new(Through::Report, input.verbose);
        let a = run_rules(input, &mut p)?.finish(&mut p);
        p.done();
        Some(a)
    };
    let h = history(
        &config,
        state,
        analysis.as_ref().map(|a| a.domains.as_slice()),
    )?;
    if no_earlier(&h, period) {
        if input.json {
            emit_json(&serde_json::json!({
                "period": period.key(),
                "heading": Introduced::heading(period, h.latest),
                "latest": h.latest,
                "latest_run": h.runs.number(h.latest),
                "lines": [],
                "introduced": null,
                "reason": introduced::NO_EARLIER,
            }))?;
        } else {
            println!(
                "{}:\n  {}",
                Introduced::heading(period, h.latest),
                introduced::NO_EARLIER
            );
        }
        return Ok(ExitCode::from(exit::OK));
    }
    let mut intro =
        introduced::period(&h.state, period, h.latest, &h.runs).with_exposure(&h.points, &h.runs);
    if let Some(a) = &analysis {
        intro.name(&Names::new(&a.findings, &a.graph, &a.zones, Some(&a.plan)));
    }
    let code = ExitCode::from(match fail_on {
        Some(f) if f.fails(&intro) => exit::FINDINGS,
        _ => exit::OK,
    });
    if input.json {
        emit_json(&serde_json::json!({
            "period": period.key(),
            "heading": Introduced::heading(period, h.latest),
            "latest": h.latest,
            "latest_run": h.runs.number(h.latest),
            "note": intro.note(&h.runs, h.latest),
            "named": analysis.is_some(),
            "lines": intro.lines(),
            "introduced": intro,
        }))?;
        return Ok(code);
    }
    anstream::print!(
        "{}",
        intro.render(period, h.latest, &h.runs, &settings_args(input))
    );
    if paths {
        anstream::print!("\n{}", intro.listing());
    }
    if analysis.is_none()
        && (intro.findings.iter().any(|f| !f.objects.is_empty())
            || intro.new_paths() > 0
            || intro.joined() > 0)
    {
        println!("  With -i (the collection), the objects and paths are named.");
    }
    Ok(code)
}

/// `findings --introduced`: the period's findings, from the history under
/// `state`, named by the analysis's `findings`.
pub(crate) fn introduced_findings(
    config: &Config,
    state: Option<&Path>,
    period: Period,
    ev: &pathwarden_core::analyze::Evaluated,
    domains: &[String],
) -> Result<(Introduced, History)> {
    let h = history(config, state, Some(domains))?;
    let mut intro = introduced::period(&h.state, period, h.latest, &h.runs);
    if no_earlier(&h, period) {
        // Nothing to compare with: none is new since the last run.
        intro.findings.clear();
    }
    intro.name(&Names::new(&ev.findings, &ev.graph, &ev.zones, None));
    Ok((intro, h))
}

/// A finding's affected objects for the terminal with `--introduced`: the
/// ones gained in the period first, each with "first seen Oct 18 (run 3)";
/// then the others. Each as its name, when it appeared (gained ones), and
/// its detail.
pub(crate) fn affected_first<'a>(
    f: &'a Finding,
    intro: Option<&'a introduced::IntroFinding>,
) -> Vec<(&'a str, Option<&'a str>, Option<&'a str>)> {
    let mut out = Vec::with_capacity(f.affected.len());
    let mut first: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for o in intro.map(|i| i.objects.as_slice()).unwrap_or_default() {
        if let Some(a) =
            o.id.as_deref()
                .and_then(|id| f.affected.iter().find(|a| a.id == id))
        {
            first.insert(a.id.as_str());
            out.push((a.name.as_str(), Some(o.label.as_str()), a.detail.as_deref()));
        }
    }
    for a in f.affected.iter().filter(|a| !first.contains(a.id.as_str())) {
        out.push((a.name.as_str(), None, a.detail.as_deref()));
    }
    out
}
