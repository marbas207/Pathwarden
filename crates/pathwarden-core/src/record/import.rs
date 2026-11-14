//! Importing analyses saved by the app into the run history, as if each
//! had been recorded when it was analyzed: shared by the History storage
//! page's "Import them in order" and `pathwarden history import`.
//!
//! The app picks the runs (its own, not yet in the history, newer than the
//! history's last run) and holds the store's lock with the history pulled;
//! [`import_runs`] compares each with the state in order, saves it, and
//! publishes once when the history is a git repository.

use serde::Deserialize;

use super::by;
use crate::config::Config;
use crate::posture::{Completeness, ExposureGrade, FindingCounts, PlanSummary};
use crate::state::{self, ChangeCounts, FindingsState, HistoryPoint, LastRun, ObservedFinding};
use crate::store::Store;

/// What an imported run needs from its saved event document.
#[derive(Deserialize)]
pub struct SavedEvent {
    run: SavedRun,
    #[serde(default)]
    posture: serde_json::Value,
    findings: Vec<ObservedFinding>,
}

#[derive(Deserialize)]
struct SavedRun {
    #[serde(default)]
    collected_at: Option<i64>,
    #[serde(default)]
    collector_files: usize,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    trusted_domains: Option<Vec<String>>,
    #[serde(default)]
    objects: usize,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    sources_exact: bool,
    #[serde(default)]
    settings_files: Vec<crate::dcsettings::SettingsFileUse>,
    #[serde(default, with = "crate::state::packed_hosts")]
    hosts: Option<Vec<String>>,
}

impl SavedEvent {
    /// A saved event document; `None` when it isn't one (runs saved before
    /// the app kept their findings).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// What the app's summary of a run says, besides its event.
#[derive(Debug, Clone)]
pub struct Analyzed {
    /// When it was analyzed (Unix time): the imported run's time.
    pub at: i64,
    pub collected_at: Option<i64>,
    /// The Pathwarden version that analyzed it.
    pub pathwarden: String,
    /// Objects left out as too large to load; any keeps findings from
    /// being resolved.
    pub skipped_objects: usize,
    pub exposure_percent: f64,
    pub exposed: usize,
    pub population: usize,
    /// The exposure denominator as recorded: 0 for a run from before risk scoring.
    pub relevant_population: usize,
    pub exposure_basis: u8,
    pub protection_score: Option<f64>,
    pub grade: ExposureGrade,
    pub plan: Option<PlanSummary>,
    /// Used when the event's posture has no counts.
    pub findings: FindingCounts,
    pub label: Option<String>,
}

/// One run to import, oldest first.
pub struct ToImport {
    /// Its name in messages (its environment).
    pub name: String,
    pub analyzed: Analyzed,
    /// `None` when its saved event couldn't be read.
    pub event: Option<SavedEvent>,
}

/// A run compared with the state, ready to save.
pub struct Imported {
    pub state: FindingsState,
    pub last: LastRun,
    pub point: HistoryPoint,
}

/// Compares one saved run with `state`, as recording it then would have.
/// `prev_objects`: the previous run's object count, so a much smaller
/// collection resolves nothing.
pub fn import_run(
    state: &FindingsState,
    ev: &SavedEvent,
    r: &Analyzed,
    prev_objects: usize,
    config: &Config,
) -> Imported {
    let at = r.at;
    let allow_resolve =
        !(prev_objects > 0 && ev.run.objects * 2 < prev_objects) && r.skipped_objects == 0;
    let scope = state::ResolveScope::domains(&ev.run.domains, allow_resolve)
        .with_rules_off(&config.rules.disabled)
        .with_untargeted(&imported_untargeted(&ev.posture));
    let rec = state::reconcile_scoped(state, &ev.findings, at, config.state.keeps_names(), &scope);
    let run_id = state::run_id_millis(at * 1000);
    let last = LastRun {
        version: state::STATE_VERSION,
        run_id: run_id.clone(),
        started_at: at,
        finished_at: at,
        collected_at: ev.run.collected_at.or(r.collected_at),
        pathwarden: r.pathwarden.clone(),
        collector_files: ev.run.collector_files,
        domains: ev.run.domains.clone(),
        trusted_domains: ev.run.trusted_domains.clone(),
        objects: ev.run.objects,
        changes: rec.counts,
        sources: ev.run.sources.clone(),
        sources_exact: ev.run.sources_exact,
        settings_files: ev.run.settings_files.clone(),
        hosts: ev.run.hosts.clone(),
    };
    let point = imported_point(r, ev, &run_id, rec.counts);
    Imported {
        state: rec.state,
        last,
        point,
    }
}

/// Imports `runs` in order into the history in `store`, whose lock the
/// caller holds and which it has pulled; publishes once when `publish`.
/// Returns the history run ID of each run, `None` for those skipped
/// because their findings weren't kept; with none imported and some
/// skipped, an error naming them. Also returns notes for the user: what
/// became of runs an earlier failed push left, or that this push failed
/// with the runs committed here for the next run to push.
pub fn import_runs(
    store: &Store,
    config: &Config,
    last: Option<&LastRun>,
    runs: &[ToImport],
    publish: bool,
) -> Result<(Vec<Option<String>>, Vec<String>), String> {
    let mut notes = Vec::new();
    // Compares and saves each run in order on top of the state in `store`.
    let apply = |last: Option<&LastRun>| -> Result<Vec<Option<String>>, String> {
        let mut state: FindingsState = store.load().map_err(|e| format!("{e:#}"))?;
        let mut prev_objects = last.map_or(0, |l| l.objects);
        let mut ids = Vec::with_capacity(runs.len());
        for r in runs {
            let Some(ev) = &r.event else {
                ids.push(None);
                continue;
            };
            let i = import_run(&state, ev, &r.analyzed, prev_objects, config);
            store
                .save(&i.state, &i.last, &i.point)
                .map_err(|e| format!("Could not save to the history: {e:#}"))?;
            prev_objects = ev.run.objects;
            state = i.state;
            ids.push(Some(i.last.run_id));
        }
        Ok(ids)
    };
    let ids = apply(last)?;
    let skipped: Vec<&str> = runs
        .iter()
        .filter(|r| r.event.is_none())
        .map(|r| r.name.as_str())
        .collect();
    let n = ids.iter().flatten().count();
    if n == 0 {
        return if skipped.is_empty() {
            Ok((ids, notes))
        } else {
            Err(format!(
                "These runs were saved before Pathwarden kept their findings, so they can't be imported: {}. Keep them local only.",
                skipped.join(", ")
            ))
        };
    }
    if publish {
        // Another run pushed first: import again on top of what it left,
        // as long as these are still newer than everything in the history.
        let first = ids.iter().flatten().next().cloned().unwrap_or_default();
        let message = format!("pathwarden: import {n} run(s) analyzed in the UI");
        let published = store.publish_with(&message, || {
            let last = crate::store::last_run(store);
            if let Some(l) = last.as_ref().filter(|l| l.run_id >= first) {
                anyhow::bail!(
                    "a newer run ({}) was recorded in the history meanwhile, so these analyses \
                         are older than its latest run now and can't be imported in order",
                    l.run_id
                );
            }
            apply(last.as_ref()).map_err(anyhow::Error::msg)?;
            Ok(Some(message.clone()))
        });
        match published {
            Ok(p) => notes = p.notes,
            // Imported and committed here; the next run that can push
            // pushes it.
            Err(e) => match e.downcast::<crate::store::KeptUnpushed>() {
                Ok(kept) => {
                    notes = kept.notes.clone();
                    notes.push(kept.sentence("The analyses were imported"));
                }
                Err(e) => return Err(format!("{e:#}")),
            },
        }
    }
    Ok((ids, notes))
}

fn imported_point(
    r: &Analyzed,
    ev: &SavedEvent,
    run_id: &str,
    changes: ChangeCounts,
) -> HistoryPoint {
    point(r, Some(ev), &ev.run.domains, run_id, changes).with_recorded_by(by::IMPORT)
}

/// A run the app analyzed as a history point: imported ([`import_run`]),
/// or charted by the app's Progress page while it is local only. The
/// figures come from its saved event when there is one (zones,
/// completeness, attack path findings, Tier Zero objects), else from the
/// summary alone, without them. `domains` are used without an event.
pub fn point(
    r: &Analyzed,
    ev: Option<&SavedEvent>,
    domains: &[String],
    run_id: &str,
    changes: ChangeCounts,
) -> HistoryPoint {
    let posture = ev.map(|e| &e.posture);
    let findings: FindingCounts = posture
        .and_then(|p| serde_json::from_value(p["findings"].clone()).ok())
        .unwrap_or_else(|| r.findings.clone());
    HistoryPoint {
        version: state::STATE_VERSION,
        run_id: run_id.to_string(),
        at: r.at,
        collected_at: ev.and_then(|e| e.run.collected_at).or(r.collected_at),
        tier_zero_exposure_percent: r.exposure_percent,
        tier_zero_exposed: r.exposed,
        tier_zero_population: r.population,
        tier_zero_relevant_population: r.relevant_population,
        exposure_basis: r.exposure_basis,
        tier_zero_objects: posture
            .and_then(|p| p["tier_zero"]["objects"].as_u64())
            .unwrap_or(0) as usize,
        protection_score: r.protection_score,
        tier_zero_grade: Some(r.grade),
        plan: r.plan,
        findings,
        changes,
        zones: posture.map(imported_zones).unwrap_or_default(),
        completeness: posture.and_then(imported_completeness),
        scopes: Vec::new(),
        trusted_scopes: ev
            .and_then(|e| e.run.trusted_domains.as_deref())
            .map(state::scopes_of),
        recorded_by: None,
        label: r.label.clone(),
        data: None,
        inserted: false,
        exposed_keys: false,
        severity_settings: posture
            .and_then(|p| p["severity_settings"].as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        rule_severities: posture
            .and_then(|p| {
                serde_json::from_value::<Vec<crate::posture::SeveritySetting>>(
                    p["severities_set"].clone(),
                )
                .ok()
            })
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.rule, s.severity))
            .collect(),
    }
    .with_domains(ev.map_or(domains, |e| e.run.domains.as_slice()))
}

/// The zones of a saved run's posture, as history points. A zone's status
/// is kept only when the run was graded the way runs are now, from paths
/// and findings: runs saved before have an `exposure_grade` from the
/// old percentage bands, with the same names and another meaning, and no
/// `grade_reason`.
pub fn imported_zones(posture: &serde_json::Value) -> Vec<state::ZonePoint> {
    posture["zones"]
        .as_array()
        .map(|zs| {
            zs.iter()
                .filter_map(|z| {
                    Some(state::ZonePoint {
                        zone: z["zone"].as_str()?.to_string(),
                        exposure_percent: z["exposure_percent"].as_f64().unwrap_or(0.0),
                        protection_score: crate::status_keys::get(z, "protection_score")
                            .and_then(|v| v.as_f64()),
                        objects: z["objects"].as_u64().map(|n| n as usize),
                        exposed: z["exposed"].as_u64().map(|n| n as usize),
                        grade: crate::status_keys::get(z, "grade_reason")
                            .is_some_and(|r| r.is_string())
                            .then(|| {
                                crate::status_keys::get(z, "exposure_grade")
                                    .and_then(|g| serde_json::from_value(g.clone()).ok())
                            })
                            .flatten(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What each domain of a saved run did not target, from its posture's
/// completeness (nothing when it doesn't say: saved before it was
/// recorded, read as targeted).
pub fn imported_untargeted(
    posture: &serde_json::Value,
) -> Vec<(String, crate::posture::Untargeted)> {
    serde_json::from_value::<Vec<Completeness>>(posture["completeness"].clone())
        .map(|c| crate::posture::untargeted_domains(&c))
        .unwrap_or_default()
}

/// A saved run's collection completeness; `None` when its posture has none
/// (saved before it was recorded) or no computers.
pub fn imported_completeness(posture: &serde_json::Value) -> Option<state::CompletenessPoint> {
    let domains: Vec<Completeness> =
        serde_json::from_value(posture["completeness"].clone()).ok()?;
    state::CompletenessPoint::new(&domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An imported run's zones keep their counts; their status only when
    /// the run was graded the current way (it then has `grade_reason`): an
    /// older run's grade came from percentage bands and means something
    /// else under the same name.
    #[test]
    fn imported_zones_trust_only_current_grades() {
        let posture = serde_json::json!({"zones": [
            {"zone": "Finance", "exposure_percent": 2.0, "protection_score": 50.0,
                "objects": 4, "exposed": 7, "exposure_grade": "High",
                "grade_reason": "7 accounts have an attack path to it."},
            {"zone": "Old", "exposure_percent": 0.5, "protection_score": null,
                "objects": 2, "exposed": 1, "exposure_grade": "Low"},
        ]});
        let zs = imported_zones(&posture);
        assert_eq!(zs.len(), 2);
        assert_eq!(
            (zs[0].objects, zs[0].exposed, zs[0].grade),
            (Some(4), Some(7), Some(crate::posture::ExposureGrade::High))
        );
        assert_eq!((zs[1].objects, zs[1].exposed), (Some(2), Some(1)));
        assert_eq!(zs[1].grade, None);
        // From before the counts were saved: none of them.
        let older = serde_json::json!({"zones": [
            {"zone": "Older", "exposure_percent": 0.5, "protection_score": null},
        ]});
        let z = &imported_zones(&older)[0];
        assert!(z.objects.is_none() && z.exposed.is_none() && z.grade.is_none());
    }

    /// Completeness saved by older releases lacks the member computer fields; the
    /// sessions figures are recovered all the same, and local groups read
    /// as not applying rather than as a share of the wrong base.
    #[test]
    fn imported_completeness_from_an_older_posture() {
        let posture = serde_json::json!({"completeness": [
            {"domain": "DEMO.LOCAL", "computers": 10, "sessions_collected": 9,
                "local_groups_collected": 8, "sessions_percent": 90.0,
                "local_groups_percent": 80.0},
        ]});
        let c = imported_completeness(&posture).unwrap();
        assert_eq!((c.computers, c.sessions_collected), (10, 9));
        assert_eq!(c.sessions_percent, 90.0);
        assert_eq!(c.local_groups_percent, None);
        assert!(imported_completeness(&serde_json::json!({})).is_none());
    }

    fn analyzed(at: i64) -> Analyzed {
        Analyzed {
            at,
            collected_at: None,
            pathwarden: "test".into(),
            skipped_objects: 0,
            exposure_percent: 1.0,
            exposed: 5,
            population: 100,
            relevant_population: 100,
            exposure_basis: 2,
            protection_score: None,
            grade: ExposureGrade::High,
            plan: None,
            findings: FindingCounts::default(),
            label: None,
        }
    }

    /// A saved run with one finding (or none), its domain's sessions and
    /// local groups targeted or not.
    fn saved(finding: bool, targeted: bool) -> SavedEvent {
        let findings = if finding {
            serde_json::json!([{"fingerprint": "PW-006-a", "rule": "PW-006",
                "severity": "high", "category": "attack_path", "domain": "DEMO.LOCAL",
                "rests_on": {"sessions": true, "local_groups": true}}])
        } else {
            serde_json::json!([])
        };
        let doc = serde_json::json!({
            "run": {"domains": ["DEMO.LOCAL"], "objects": 100},
            "posture": {"completeness": [{"domain": "DEMO.LOCAL", "computers": 10,
                "member_computers": 9, "sessions_collected": 0, "local_groups_collected": 0,
                "sessions_percent": 0.0, "local_groups_percent": 0.0,
                "sessions_targeted": targeted, "local_groups_targeted": targeted}]},
            "findings": findings,
        });
        SavedEvent::parse(doc.to_string().as_bytes()).unwrap()
    }

    /// Importing a Full run, then a Quick run without its attack path:
    /// held, not fixed, as recording them would have.
    #[test]
    fn an_imported_quick_run_holds_what_a_full_run_saw() {
        let config = Config::default();
        let full = import_run(
            &FindingsState::default(),
            &saved(true, true),
            &analyzed(100),
            0,
            &config,
        );
        let quick = import_run(
            &full.state,
            &saved(false, false),
            &analyzed(200),
            100,
            &config,
        );
        assert_eq!(
            (quick.last.changes.resolved, quick.last.changes.held),
            (0, 1)
        );
        assert_eq!(quick.state.findings["PW-006-a"].status, state::Status::Open);
        // A Full run without it: fixed.
        let full2 = import_run(
            &quick.state,
            &saved(false, true),
            &analyzed(300),
            100,
            &config,
        );
        assert_eq!(full2.last.changes.resolved, 1);
    }
}
