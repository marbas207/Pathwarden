//! A run's collection performance and its diagnostics bundle: the
//! "Collection performance" panel and "Download diagnostics" (on the
//! Environments page for each environment's latest timed collection, and
//! on each run's own performance page, which the run page links), and
//! `pathwarden diagnose [RUN] [--bundle]`, from the same code.
//!
//! The timings are the run folder's `timings.json`, written when Pathwarden
//! collected the data (the Collect wizard, `collect --save`, or `collect`
//! then `run -i ... --save`); uploads and runs from before have none. A run
//! a schedule (or `collect` then `run -i`) recorded in the history has its
//! timings in the history's state folder (`timings/<run>.json`,
//! [`pathwarden_core::store::run_timings`]), and its own panel page. A run
//! is compared with the latest earlier run of its environment that has
//! timings and was collected the same way (collector and scope).
//!
//! The bundle ([`pathwarden_core::diagnostics::Bundle`]) is made from the
//! run's saved files only: `summary.json` for the posture numbers, the event
//! document for completeness, the plan and findings by rule, `timings.json`,
//! and this computer's system. Its names are searched for in every file
//! with the run's objects (`objects.json.gz`), domains, environment names,
//! zones and Tier Zero additions; one found and it is refused. A history
//! run's bundle has its numbers and timings only.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use pathwarden_core::diagnostics::{
    self, Bundle, CollectionTimings, Measure, NameScan, Refused, SystemInfo, Trend, TIMINGS_FILE,
};
use pathwarden_core::object_index::ObjectIndex;
use pathwarden_core::state::HistoryPoint;
use serde_json::{json, Value};

use crate::pages::{esc, icon};
use crate::workspace::{RunSummary, Workspace};

/// Why a run loaded from the history's full runs has no timings: they
/// aren't part of a full run.
const SHARED_MISSING: &str = "Timings stay on the computer that collected this run.";

/// A run's `timings.json`, if it has one.
pub fn timings_of(run_dir: &Path) -> Option<CollectionTimings> {
    CollectionTimings::parse(&std::fs::read_to_string(run_dir.join(TIMINGS_FILE)).ok()?)
}

/// A run's collection performance, compared with its environment's
/// previous run that has timings and was collected the same way.
#[derive(Debug, Clone)]
pub struct Performance {
    pub run: RunSummary,
    pub timings: Option<CollectionTimings>,
    pub previous: Option<(RunSummary, CollectionTimings)>,
    /// With no `previous`: how this run and the latest earlier one with
    /// timings were collected, when they differ ("built-in, all" and
    /// "built-in, dc-only"), so they aren't compared.
    pub unlike: Option<(String, String)>,
    /// Recorded in the history (a schedule, `pathwarden run`), not saved
    /// in the workspace.
    pub recorded: bool,
}

impl Performance {
    pub fn of(ws: &Workspace, run: &RunSummary) -> Self {
        let timings = ws.run_dir(&run.id).and_then(|d| timings_of(&d));
        let earlier = ws
            .for_run(run)
            .runs()
            .into_iter()
            .filter(|r| r.id != run.id && run.newer_than(r))
            .filter_map(|r| {
                let t = timings_of(&ws.run_dir(&r.id)?)?;
                Some((r, t))
            });
        Self::compared(run.clone(), timings, earlier, false)
    }

    /// A run recorded in the history in `state_dir` (`points` oldest
    /// first): its timings from the state, compared with the earlier
    /// points of the same domains that have some, in the state or, for a
    /// run saved in `ws` too, in its folder.
    pub fn of_point(
        ws: &Workspace,
        state_dir: &Path,
        points: &[HistoryPoint],
        point: &HistoryPoint,
        domains: &[String],
    ) -> Self {
        let run = crate::history_ui::point_summary(point, domains);
        // The saved runs' folders by history ID, read once.
        let saved: std::collections::HashMap<String, String> = ws
            .all_runs()
            .into_iter()
            .map(|r| (r.run_id(), r.id))
            .collect();
        let timings_of_point = |run_id: &str| {
            pathwarden_core::store::run_timings(state_dir, run_id)
                .or_else(|| timings_of(&ws.run_dir(saved.get(run_id)?)?))
        };
        let timings = timings_of_point(&point.run_id);
        let earlier = points
            .iter()
            .rev()
            .filter(|p| p.run_id != point.run_id && p.at <= point.at && p.scopes == point.scopes)
            .filter_map(|p| {
                let t = timings_of_point(&p.run_id)?;
                Some((crate::history_ui::point_summary(p, domains), t))
            });
        Self::compared(run, timings, earlier, true)
    }

    /// `earlier`, newest first: the first collected the same way is
    /// compared with. Timings the same as this run's are the same
    /// collection analyzed twice, not an earlier one: passed over.
    fn compared(
        run: RunSummary,
        timings: Option<CollectionTimings>,
        earlier: impl Iterator<Item = (RunSummary, CollectionTimings)>,
        recorded: bool,
    ) -> Self {
        let (mut previous, mut unlike) = (None, None);
        if let Some(t) = &timings {
            for (r, p) in earlier.filter(|(_, p)| p != t) {
                if t.same_collection(&p) {
                    previous = Some((r, p));
                    break;
                }
                unlike.get_or_insert_with(|| (t.kind_words(), p.kind_words()));
            }
        }
        if previous.is_some() {
            unlike = None;
        }
        Self {
            run,
            timings,
            previous,
            unlike,
            recorded,
        }
    }

    pub fn measures(&self) -> Vec<Measure> {
        match &self.timings {
            Some(t) => diagnostics::measures(t, self.previous.as_ref().map(|(_, p)| p)),
            None => Vec::new(),
        }
    }

    /// The collection took longer than the previous run's collected the
    /// same way (by more than varies run to run): the Environments page
    /// opens the panel by itself, and the run page says so.
    pub fn slower(&self) -> bool {
        self.measures()
            .iter()
            .any(|m| m.key == "total" && m.trend == Some(Trend::Worse))
    }

    /// Why there are no timings, in words.
    pub fn missing(&self) -> &'static str {
        if self.run.demo {
            "No collection timings: demo data isn't collected."
        } else if self.run.shared.is_some() {
            // A full run from the history carries no timings.
            SHARED_MISSING
        } else if self.recorded {
            "No collection timings: Pathwarden keeps them with a recorded run when pathwarden collect wrote its data (as a schedule does), and this run's data came from elsewhere or was recorded before Pathwarden kept them."
        } else if self.run.collection.is_none() {
            "No collection timings: Pathwarden times the collections it runs itself (the Collect wizard, pathwarden collect, a schedule), and this run's data was uploaded, read from files it didn't collect, or analyzed again after a run recorded its collection."
        } else {
            "No collection timings: this run was collected before Pathwarden saved them."
        }
    }

    /// `diagnose --json` and `/api/runs/{id}/performance`.
    pub fn to_json(&self) -> Value {
        let errors = self
            .timings
            .as_ref()
            .and_then(|t| t.hosts.as_ref())
            .map(|h| h.errors.clone())
            .unwrap_or_default();
        json!({
            "run": self.run.run_id(),
            "folder": self.run.id,
            "collector": self.timings.as_ref().map(|t| t.collector.clone()),
            "previous_run": self.previous.as_ref().map(|(r, _)| r.run_id()),
            "not_compared": self.unlike.as_ref().map(|(this, last)| json!({
                "this_run": this,
                "last_timed_run": last,
            })),
            "recorded": self.recorded,
            "slower": self.slower(),
            "measures": self.measures(),
            "errors": errors,
            "missing": self.timings.is_none().then(|| self.missing()),
            "timings": self.timings,
            "previous_timings": self.previous.as_ref().map(|(_, t)| t),
        })
    }

    /// "Built-in collector".
    fn collector(t: &CollectionTimings) -> String {
        let mut c = t.collector.chars();
        match c.next() {
            Some(f) => f.to_uppercase().chain(c).collect::<String>() + " collector",
            None => "Collector".into(),
        }
    }

    /// What the run is compared with, as a sentence.
    fn compared_words(&self) -> String {
        match (&self.previous, &self.unlike) {
            (Some((r, _)), _) => format!(
                "Compared with run {} of {}, the previous one of this environment collected the same way.",
                r.run_id(),
                pathwarden_core::time::format_local(r.created_at)
            ),
            (None, Some((this, last))) => format!(
                "Not compared: the last timed run of this environment was collected another way ({last}; this one {this})."
            ),
            (None, None) => {
                "No earlier run of this environment has timings to compare with.".into()
            }
        }
    }

    /// What `pathwarden diagnose` prints: plain lines, the same numbers as
    /// the panel; with `details`, the `[timing]` block too.
    pub fn text(&self, details: bool) -> Vec<String> {
        let mut out = vec![format!(
            "Collection performance of run {}",
            self.run.run_id()
        )];
        let Some(t) = &self.timings else {
            out.push(if self.run.shared.is_some() {
                "Timings stay on the computer that collected this run: pathwarden diagnose there \
                 shows them."
                    .into()
            } else {
                self.missing().into()
            });
            return out;
        };
        out.push(format!("{}. {}", Self::collector(t), self.compared_words()));
        out.push(String::new());
        let m = self.measures();
        let lw = m.iter().map(|x| x.label.len()).max().unwrap_or(0);
        let vw = m.iter().map(|x| x.value.chars().count()).max().unwrap_or(0);
        for x in &m {
            let line = format!("  {:<lw$}  {:>vw$}", x.label, x.value);
            out.push(match &x.change {
                Some(c) => format!("{line}  {c}"),
                None => line,
            });
        }
        if let Some(h) = &t.hosts {
            if let Some(e) = diagnostics::error_line(h) {
                out.push(format!("  Errors by kind: {e}"));
            }
            if h.local_groups_failed > 0 {
                out.push(format!(
                    "  Local groups not read on {}",
                    pathwarden_core::text::count(h.local_groups_failed, "computer", "computers")
                ));
            }
            if h.tried > 0 && h.p95_ms.is_none() {
                out.push(
                    "  Time per computer: not measured (the collector's modules don't report it)"
                        .into(),
                );
            }
        }
        if details {
            out.push(String::new());
            if let Some(s) = &t.summary {
                out.push(s.clone());
            }
            out.extend(t.details.iter().cloned());
        }
        out
    }
}

/// A run's own performance page: the panel alone, open.
pub fn panel(p: &Performance) -> String {
    panel_in(p, true, "perf", 2, false)
}

/// The panel on the Environments page, in an environment's row: its
/// latest timed collection, closed to one line unless that collection got
/// slower than the previous one collected the same way. `id` keeps each
/// row's IDs apart.
pub fn env_panel(p: &Performance, id: &str) -> String {
    panel_in(p, p.slower(), id, 3, true)
}

/// The run page's link to the run's performance page, "Collection slower"
/// when it got slower than the previous one collected the same way.
/// Demo data isn't collected: none.
pub fn run_link(p: &Performance) -> String {
    if p.run.demo {
        return String::new();
    }
    let slower = p.slower();
    let class = if slower { " slower" } else { "" };
    let words = crate::run_details::perf_words(slower);
    format!(
        r#"<a class="rh-perf{class}" href="/runs/{id}/performance" title="How long the collection took, against the previous one, and the diagnostics download">{i} {words}</a>"#,
        id = esc(&p.run.id),
        i = icon("i-clock"),
    )
}

/// One number per card with its change, the error kinds, the definitions
/// and the `[timing]` block collapsed, and the bundle's download. With
/// `name_run`, the line under the title names the run it is of.
fn panel_in(p: &Performance, open: bool, id: &str, level: u8, name_run: bool) -> String {
    let download = format!(
        r#"<a class="btn" href="/runs/{}/diagnostics.zip" title="A zip of numbers that is safe to share: timings, completeness, posture and plan size, every name replaced">{} Download diagnostics</a>"#,
        esc(&p.run.id),
        icon("i-download")
    );
    let open = if open { " open" } else { "" };
    let summary = |line: &str| {
        format!(
            r#"<summary><span class="perf-sum"><span class="perf-title" id="{id}-title" role="heading" aria-level="{level}">Collection performance</span><span class="muted small">{}</span></span></summary>"#,
            esc(line)
        )
    };
    let of_run = if name_run {
        format!(
            r#"Run <a href="/runs/{}">{}</a>, {} · "#,
            esc(&p.run.id),
            esc(&p.run.title()),
            crate::pages::time(p.run.created_at)
        )
    } else {
        String::new()
    };
    let Some(t) = &p.timings else {
        // Closed to one line as well: most runs have no timings.
        return format!(
            r#"<details class="perf card" id="{id}"{open}>{}<div class="perf-head perf-none"><p class="muted small">{of_run}{}</p>{download}</div>{has}</details>"#,
            summary("not timed"),
            esc(p.missing()),
            has = contents(id),
        );
    };
    let measures = p.measures();
    // Closed, one line: the total and its change, and the computers
    // reached. The report below stays the page's headline.
    let mut headline = Vec::new();
    if let Some(total) = measures.iter().find(|m| m.key == "total") {
        headline.push(match &total.change {
            Some(c) => format!("{} in all, {}", total.value, diagnostics::against_last(c)),
            None => format!("{} in all", total.value),
        });
    }
    if let Some(r) = measures.iter().find(|m| m.key == "hosts_reached") {
        headline.push(format!("{} computers reached", r.value));
    }
    let compared = format!(
        "{of_run}{} · {}",
        esc(&Performance::collector(t)),
        esc(&p.compared_words())
    );
    let mut b = format!(
        r#"<details class="perf card" id="{id}"{open}>{}<div class="perf-head"><p class="muted small">{compared}</p>{download}</div>{has}<div class="perf-cards">"#,
        summary(&headline.join(" · ")),
        has = contents(id),
    );
    for (i, m) in measures.iter().enumerate() {
        let delta = match (&m.change, m.trend) {
            (Some(c), Some(trend)) => {
                let class = match trend {
                    Trend::Better => "good",
                    Trend::Worse => "bad",
                    Trend::Same | Trend::Neutral => "same",
                };
                // Better or worse in words too, not only the colour.
                let word = match trend {
                    Trend::Better => r#"<span class="sr-only"> (better)</span>"#,
                    Trend::Worse => r#"<span class="sr-only"> (worse)</span>"#,
                    Trend::Same | Trend::Neutral => "",
                };
                // "30.0s slower" coloured, "than the last timed run" not.
                let phrase = diagnostics::against_last(c);
                let rest = phrase.strip_prefix(c.as_str()).unwrap_or_default();
                format!(
                    r#"<span class="ov-sub"><span class="delta {class}">{}{word}</span>{}</span>"#,
                    esc(c),
                    esc(rest)
                )
            }
            _ => String::new(),
        };
        let _ = write!(
            b,
            r#"<div class="ov-card card" data-measure="{key}"><span class="ov-label">{label}{tip}</span><span class="perf-num">{value}</span>{delta}</div>"#,
            key = m.key,
            label = esc(m.label),
            tip = tip(&format!("{id}-{i}"), m.label, m.definition),
            value = esc(&m.value),
        );
    }
    b.push_str("</div>");
    if let Some(h) = &t.hosts {
        let mut notes = Vec::new();
        if let Some(e) = diagnostics::error_line(h) {
            notes.push(format!("Errors by kind: {}.", esc(&e)));
        }
        if h.local_groups_failed > 0 {
            notes.push(format!(
                "Local groups not read on {}.",
                esc(&pathwarden_core::text::count(
                    h.local_groups_failed,
                    "computer",
                    "computers"
                ))
            ));
        }
        if !notes.is_empty() {
            let _ = write!(
                b,
                r#"<p class="perf-note muted small">{}</p>"#,
                notes.join(" ")
            );
        }
    }
    let _ = write!(
        b,
        r#"<details class="explain"><summary>{info} All definitions and timings</summary><dl>"#,
        info = icon("i-info")
    );
    for (term, def) in diagnostics::DEFINITIONS {
        let _ = write!(b, "<div><dt>{}</dt><dd>{}</dd></div>", esc(term), esc(def));
    }
    b.push_str("</dl>");
    let lines: Vec<&str> = t
        .summary
        .iter()
        .map(String::as_str)
        .chain(t.details.iter().map(String::as_str))
        .collect();
    if !lines.is_empty() {
        let _ = write!(
            b,
            r#"<p class="muted small">The collection log's timing lines:</p><pre class="perf-log" tabindex="0">{}</pre>"#,
            esc(&lines.join("\n"))
        );
    }
    b.push_str("</details></details>");
    b
}

/// What the diagnostics zip holds, under its download: every name in it
/// replaced.
fn contents(id: &str) -> String {
    let items: String = diagnostics::CONTENTS
        .iter()
        .map(|c| format!("<li>{}</li>", esc(c)))
        .collect();
    format!(
        r#"<div class="diag-has-wrap"><p class="muted small">In the zip, every name replaced: {}</p><ul class="diag-has">{items}</ul></div>"#,
        tip(
            &format!("{id}-zip"),
            "what's in the zip",
            diagnostics::CONTENTS_TIP
        )
    )
}

/// A small (i) with its definition, as the report's.
fn tip(id: &str, term: &str, text: &str) -> String {
    format!(
        r#"<span class="tip"><button type="button" class="tip-btn" aria-label="About: {term}" aria-describedby="tip-{id}">{icon}</button><span class="tip-text" role="tooltip" id="tip-{id}">{text}</span></span>"#,
        term = esc(term),
        text = esc(text),
        icon = icon("i-info"),
    )
}

// --------------------------------------------------------------- bundle

/// The bundle's file name.
pub fn bundle_name(run: &RunSummary) -> String {
    let id: String = run
        .run_id()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    format!("pathwarden-diagnostics-{id}.zip")
}

/// Why no bundle was made.
#[derive(Debug)]
pub enum BundleError {
    /// A name was found: nothing written.
    Refused(Refused),
    /// The run's files can't be read.
    Unreadable(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Refused(r) => r.fmt(f),
            BundleError::Unreadable(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for BundleError {}

/// The diagnostics bundle of `run` (blocking: it reads the run's objects),
/// with the logs and crash reports of the logs folder `logs`
/// ([`pathwarden_core::logs::for_bundle`]).
pub fn bundle(
    ws: &Workspace,
    run: &RunSummary,
    logs: Option<&Path>,
) -> Result<Vec<u8>, BundleError> {
    let dir = ws
        .run_dir(&run.id)
        .ok_or_else(|| BundleError::Unreadable("that run can't be found".into()))?;
    let perf = Performance::of(ws, run);
    let event: Option<Value> = crate::run_data::read_event(&dir)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let mut findings: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    if let Some(list) = event.as_ref().and_then(|e| e["findings"].as_array()) {
        for f in list {
            let rule = f["rule"].as_str().unwrap_or("?");
            let severity = if f["suppressed"].is_null() {
                f["severity"].as_str().unwrap_or("?")
            } else {
                "accepted"
            };
            *findings
                .entry(rule.to_string())
                .or_default()
                .entry(severity.to_string())
                .or_default() += 1;
        }
    }
    let b = Bundle {
        system: system_info(),
        run: run_numbers(run),
        timings: perf.timings.clone(),
        previous: perf.previous.as_ref().map(|(_, t)| t.clone()),
        posture: event.as_ref().map(|e| e["posture"].clone()),
        plan: event.as_ref().map(|e| e["plan"].clone()),
        findings_by_rule: findings,
        collection: run.collection.as_ref().map(|c| {
            json!({
                "method": c.method,
                "scope": c.scope,
                "domain": c.domain,
                "domain_controller_chosen": c.server.is_some(),
                "ldaps": c.ldaps,
                "current_user": c.current_user,
                "raw_collection_kept": c.kept.is_some(),
                "warnings": c.warnings.len(),
            })
        }),
        logs: logs_of(logs),
    };
    let scan = names_of(ws, &perf, &dir)?;
    b.zip(&scan).map_err(BundleError::Refused)
}

/// The bundle of a run recorded in the history ([`Performance::of_point`]):
/// its numbers and timings, the previous timings and this computer. The
/// history keeps no objects, so there are none to search for; nor would
/// they be in it: every string of these files is Pathwarden's own or
/// replaced by a placeholder. The run's domains and the environments are
/// still searched for.
pub fn bundle_point(
    ws: &Workspace,
    perf: &Performance,
    logs: Option<&Path>,
) -> Result<Vec<u8>, BundleError> {
    let b = Bundle {
        system: system_info(),
        run: run_numbers(&perf.run),
        timings: perf.timings.clone(),
        previous: perf.previous.as_ref().map(|(_, t)| t.clone()),
        logs: logs_of(logs),
        ..Bundle::default()
    };
    let mut scan = NameScan::default();
    known_names(ws, perf, &mut scan);
    b.zip(&scan).map_err(BundleError::Refused)
}

/// The logs a bundle takes from the logs folder `logs`.
fn logs_of(logs: Option<&Path>) -> Vec<(String, String)> {
    logs.map(|d| pathwarden_core::logs::for_bundle(d, pathwarden_core::analyze::now()))
        .unwrap_or_default()
}

/// The history run `run_id` of the environment `ws` (its history in use,
/// or `flag`'s), with its timings.
pub fn point_performance(ws: &Workspace, flag: Option<&Path>, run_id: &str) -> Option<Performance> {
    let snap = crate::history_ui::snapshot(ws, flag);
    let loc = snap.location.as_ref().ok()?;
    let p = snap.history.points.iter().find(|p| p.run_id == run_id)?;
    let domains = crate::history_ui::domains_for(
        &crate::history_ui::point_scopes_key(p),
        &ws.runs(),
        snap.history.last.as_ref(),
    );
    Some(Performance::of_point(
        ws,
        &loc.dir,
        &snap.history.points,
        p,
        &domains,
    ))
}

/// The run's numbers from its summary: no source, label or reason text.
fn run_numbers(r: &RunSummary) -> Value {
    json!({
        "pathwarden": r.pathwarden,
        "demo": r.demo,
        "domains": r.domains,
        "trusted_domains": r.trusted_domains.as_ref().map_or(0, Vec::len),
        "collector_files": r.files,
        "objects": r.objects,
        "skipped_objects": r.skipped_objects,
        "exposure_basis": r.basis(),
        "exposure_percent": r.exposure_percent,
        "exposed": r.exposed,
        "population": r.population,
        "relevant_population": r.relevant_pop(),
        "protection_score": r.protection_score,
        "status": format!("{:?}", r.grade()),
        "findings": {
            "critical": r.critical,
            "high": r.high,
            "medium": r.medium,
            "low": r.low,
            "info": r.info,
            "accepted": r.suppressed,
        },
        "plan_steps": r.plan_steps,
        "exposed_after_plan": r.exposed_after,
        "exposure_delta": r.exposure_delta,
        "next_step_delta": r.next_step_delta,
    })
}

/// Every name the bundle must not hold: the run's objects and
/// [`known_names`].
fn names_of(ws: &Workspace, perf: &Performance, dir: &Path) -> Result<NameScan, BundleError> {
    let mut scan = NameScan::default();
    known_names(ws, perf, &mut scan);
    // The objects: without them the search would miss most names, so no
    // bundle (a run saved before object indexes has to be analyzed again).
    let objects = dir.join(crate::run_data::OBJECTS_FILE);
    let index: ObjectIndex = crate::run_data::read_gz(&objects)
        .ok()
        .and_then(|b| serde_json::from_slice::<ObjectIndex>(&b).ok())
        .filter(|i| {
            pathwarden_core::formats::of_u32(
                i.version,
                pathwarden_core::object_index::INDEX_VERSION,
            )
            .is_known()
        })
        .ok_or_else(|| {
            BundleError::Unreadable(
                "this run's object list (objects.json.gz) can't be read, so its names can't be \
                 searched for; analyze the data again for a bundle"
                    .into(),
            )
        })?;
    scan.add_index(&index);
    Ok(scan)
}

/// The names known without the objects: the run's and the compared run's
/// domains, trusted domains, domain controller and label, the workspace's
/// environments (names and domains), and the environment's zones (names,
/// members, groups, OUs), Tier Zero additions and management planes.
fn known_names(ws: &Workspace, perf: &Performance, scan: &mut NameScan) {
    let runs = std::iter::once(&perf.run).chain(perf.previous.as_ref().map(|(r, _)| r));
    for run in runs {
        for d in run
            .domains
            .iter()
            .chain(run.trusted_domains.iter().flatten())
        {
            scan.add_domain(d);
        }
        if let Some(c) = &run.collection {
            scan.add_domain(&c.domain);
            if let Some(s) = &c.server {
                scan.add_name(s);
            }
        }
        if let Some(l) = &run.label {
            scan.add_name(l);
        }
    }
    for e in &ws.named_registry().environments {
        scan.add_name(&e.name);
        for d in &e.domains {
            scan.add_domain(d);
        }
    }
    // An unreadable config has no names to add; the analysis that used it
    // read it, so it can't have been far off.
    if let Ok(config) = ws.for_run(&perf.run).config() {
        let mut entry = |s: &str| {
            if s.contains('=') {
                scan.add_dn(s);
            } else {
                scan.add_sid(s);
                scan.add_name(s);
            }
        };
        for z in &config.zones {
            entry(&z.name);
            for m in z.members.iter().chain(&z.groups).chain(&z.ous) {
                entry(m);
            }
        }
        for t in config
            .tier_zero
            .iter()
            .chain(&config.management_planes.not_tier_zero)
        {
            entry(t);
        }
    }
}

/// This computer: Pathwarden's version, the OS, cores and memory.
pub fn system_info() -> SystemInfo {
    SystemInfo {
        pathwarden: env!("CARGO_PKG_VERSION").to_string(),
        os: os_name(),
        arch: std::env::consts::ARCH.to_string(),
        logical_processors: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        memory_bytes: memory(),
    }
}

#[cfg(windows)]
fn os_name() -> String {
    let read = |value: &str| -> Option<String> {
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
        };
        let key: Vec<u16> = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let name: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let mut buf = [0u16; 256];
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: `key` and `name` are NUL-terminated; `buf` holds `bytes`
        // bytes, and on success `bytes` is the size written.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc != 0 {
            return None;
        }
        let n = (bytes as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        (!s.is_empty()).then_some(s)
    };
    let product = read("ProductName").unwrap_or_else(|| "Windows".into());
    let build = read("CurrentBuildNumber").unwrap_or_default();
    // Windows 11 still says "Windows 10" in ProductName: the build tells.
    let product = match build.parse::<u32>() {
        Ok(b) if b >= 22000 => product.replacen("Windows 10", "Windows 11", 1),
        _ => product,
    };
    match (read("DisplayVersion"), build.is_empty()) {
        (Some(v), false) => format!("{product} {v} (build {build})"),
        (None, false) => format!("{product} (build {build})"),
        _ => product,
    }
}

#[cfg(not(windows))]
fn os_name() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

#[cfg(windows)]
fn memory() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: MEMORYSTATUSEX is plain data; dwLength is set as the call
    // requires.
    let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: `m` is a valid, sized MEMORYSTATUSEX.
    (unsafe { GlobalMemoryStatusEx(&mut m) } != 0).then_some(m.ullTotalPhys)
}

#[cfg(not(windows))]
fn memory() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = t
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb * 1024)
}

// ---------------------------------------------------------------- routes

use axum::extract::{Path as UrlPath, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::server::Shared;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/runs/{id}/diagnostics.zip", get(download))
        .route("/api/runs/{id}/performance", get(performance))
        .route("/runs/{id}/performance", get(run_page))
        .route("/history/{run}/performance", get(point_page))
}

/// What a run ID names: a run saved in the workspace (its folder or
/// history ID), else a run recorded in the current environment's history.
enum Found {
    Saved(Box<RunSummary>),
    Recorded(Box<Performance>),
}

/// Blocking: a history run reads the history.
fn find(st: &Shared, id: &str) -> Option<Found> {
    let saved = st.workspace.run(id).or_else(|| {
        st.workspace
            .find_run(id)
            .and_then(|folder| st.workspace.run(&folder))
    });
    match saved {
        Some(run) => Some(Found::Saved(Box::new(run))),
        None => point_performance(&st.ws(), st.state_dir().as_deref(), id)
            .map(|p| Found::Recorded(Box::new(p))),
    }
}

async fn performance(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let ws = st.workspace.clone();
    let found = tokio::task::spawn_blocking(move || {
        find(&st, &id).map(|f| match f {
            Found::Saved(run) => Performance::of(&ws, &run).to_json(),
            Found::Recorded(p) => p.to_json(),
        })
    })
    .await;
    match found {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "No such run." })),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// A saved run's page (the run page links it): the panel alone, open.
async fn run_page(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let ws = st.workspace.clone();
    let found = tokio::task::spawn_blocking(move || {
        let run = ws.run(&id)?;
        Some(Performance::of(&ws, &run))
    })
    .await;
    match found {
        Ok(Some(p)) => perf_page(&st, &p, Some(&format!("/runs/{}", p.run.id))),
        _ => (StatusCode::NOT_FOUND, Html(crate::pages::not_found())).into_response(),
    }
}

/// A history run's page: the panel alone, open.
async fn point_page(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let ws = st.ws();
    let flag = st.state_dir();
    let found =
        tokio::task::spawn_blocking(move || point_performance(&ws, flag.as_deref(), &id)).await;
    let Ok(Some(p)) = found else {
        return (StatusCode::NOT_FOUND, Html(crate::pages::not_found())).into_response();
    };
    perf_page(&st, &p, None)
}

/// The panel alone under the run's name; `back` its run page, if saved.
fn perf_page(st: &Shared, p: &Performance, back: Option<&str>) -> Response {
    let runs = st.ws().runs();
    let title = match back {
        Some(href) => format!(r#"<a href="{}">{}</a>"#, esc(href), esc(&p.run.title())),
        None => format!("Run {}", esc(&p.run.run_id())),
    };
    let body = format!(
        r#"<div class="page-head"><div><h1 class="panel-title">{title}</h1><p class="lead">{source} · {when}</p></div></div>{panel}"#,
        source = esc(&crate::workspace::hide_profile(&p.run.source)),
        when = crate::pages::time(p.run.created_at),
        panel = panel(p),
    );
    Html(crate::pages::shell(
        &crate::pages::Ctx::new(st, &runs),
        Some(crate::pages::Nav::Runs),
        "Collection performance",
        "",
        &body,
    ))
    .into_response()
}

async fn download(State(st): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let ws = st.workspace.clone();
    let logs = st.jobs.logs_dir();
    let made = tokio::task::spawn_blocking(move || {
        find(&st, &id).map(|f| match f {
            Found::Saved(run) => (
                bundle_name(&run),
                format!("/runs/{}/performance", run.id),
                bundle(&ws, &run, logs.as_deref()),
            ),
            Found::Recorded(p) => (
                bundle_name(&p.run),
                format!("/history/{}/performance", p.run.run_id()),
                bundle_point(&st.ws(), &p, logs.as_deref()),
            ),
        })
    })
    .await;
    let (name, back, made) = match made {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Html(crate::pages::not_found())).into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    match made {
        Ok(zip) => {
            let mut r = ([(header::CONTENT_TYPE, "application/zip")], zip).into_response();
            // `name` is letters, digits and dashes.
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
                r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
            }
            r
        }
        Err(e) => {
            let status = match e {
                BundleError::Refused(_) => StatusCode::CONFLICT,
                BundleError::Unreadable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            };
            let mut text = e.to_string();
            if let Some(first) = text.get(..1) {
                text = first.to_uppercase() + &text[1..];
            }
            (status, Html(not_made(&text, &back))).into_response()
        }
    }
}

/// The page a refused or failed bundle opens instead of a download.
fn not_made(text: &str, back: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>No diagnostics bundle · Pathwarden</title>
{links}
<link rel="stylesheet" href="/static/app.css"><script src="/static/theme.js"></script></head>
<body class="app bare"><main class="card lone"><h1 class="panel-title">No diagnostics bundle</h1><p class="muted">{text}</p><p><a class="btn primary" href="{back}">Back to the run</a></p></main></body></html>"#,
        links = crate::brand::HEAD_LINKS,
        text = esc(text),
        back = esc(back),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run loaded from the history's full runs was collected
    /// elsewhere, and its timings stayed there: the page says so, and the
    /// command line says where to look.
    #[test]
    fn a_shared_run_says_its_timings_stay_where_it_was_collected() {
        let run: RunSummary = serde_json::from_value(json!({
            "id": "20261009-020000-abcdef", "created_at": 1, "collected_at": null,
            "source": "x", "demo": false, "domains": ["CONTOSO.LOCAL"], "objects": 900,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "0.2.0",
            "collection": {"method": "builtin", "scope": "all", "domain": "contoso.local"},
            "shared": {"remote": "https://git.example/h.git", "recorded_from": "app",
                "pathwarden": "0.2.0", "mirrored_at": 1, "manifest_sha256": ""},
        }))
        .unwrap();
        let p = Performance::compared(run.clone(), None, std::iter::empty(), false);
        assert_eq!(p.missing(), SHARED_MISSING);
        assert!(!p.missing().contains("pathwarden"));
        assert_eq!(
            p.text(false)[1],
            "Timings stay on the computer that collected this run: pathwarden diagnose there \
             shows them."
        );
        assert!(panel(&p).contains(SHARED_MISSING));
        // The same run collected here, before timings were saved.
        let mut here = run;
        here.shared = None;
        let p = Performance::compared(here, None, std::iter::empty(), false);
        assert!(p.missing().contains("before Pathwarden saved them"));
    }
}
