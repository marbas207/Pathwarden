//! Recording an analysis as a run in the state: what `pathwarden run` and
//! the UI share, so both compare a run with the previous state the same way
//! and their fingerprints, lifecycle and history agree.
//!
//! [`prepare`] compares an evaluated collection with the previous state,
//! guarding against resolving findings that were simply not collected, and
//! returns the new state, the `last-run.json` record and the history point.
//! The caller holds the store's lock, then saves and publishes
//! ([`save_and_publish`]), which records the run on top of another that
//! pushed first.

use crate::analyze::{self, Analysis, Evaluated, Progress};
use crate::config::Config;
use crate::state::{self, FindingsState, HistoryPoint, LastRun, Reconciled};
use crate::store::{Published, Store};

pub mod import;

/// Where an analysis is recorded from, for the history point's `recorded_by`.
pub mod by {
    /// The nightly scripts the UI generates (they set `PATHWARDEN_SCHEDULED`).
    pub const SCHEDULE: &str = "schedule";
    /// `pathwarden run` by hand or in a pipeline.
    pub const CLI: &str = "cli";
    /// An analysis started in `pathwarden ui`.
    pub const UI: &str = "ui";
    /// An earlier UI analysis imported into the state.
    pub const IMPORT: &str = "import";
}

/// An analysis's progress, plus somewhere to put warnings about the
/// comparison (shown on the terminal, or kept with the UI's run).
pub trait RecordProgress: Progress {
    fn warn(&mut self, message: String);
}

pub struct Options<'a> {
    /// When the run started, in milliseconds (the run ID comes from it).
    pub started_ms: i64,
    /// Resolve findings even when the collection is much smaller than the
    /// last one.
    pub accept_shrink: bool,
    /// See [`by`].
    pub recorded_by: &'a str,
    /// When the analysis finished, for a run dated in the past (the demo's
    /// earlier runs); `None`, now.
    pub finished_at: Option<i64>,
}

/// A run ready to save.
pub struct Prepared {
    pub analysis: Analysis,
    pub reconciled: Reconciled,
    pub last: LastRun,
    pub point: HistoryPoint,
    /// Unix time the analysis finished.
    pub finished: i64,
    /// The last run in the state it was compared with, if any.
    pub compared_with: Option<String>,
    /// The accounts with a path to Tier Zero, as name-free keys
    /// (`exposed/<run>.json`, [`crate::exposed`]); saved with the point.
    pub exposed: Option<crate::exposed::ExposedRecord>,
    /// Servers the last run had a Tier Zero settings file for and this one
    /// has none for, domain controllers first.
    pub settings_fewer: Vec<String>,
}

impl Prepared {
    pub fn run_id(&self) -> &str {
        &self.last.run_id
    }

    /// The git commit message for this run.
    pub fn commit_message(&self) -> String {
        commit_message(&self.last.run_id, &self.reconciled.counts)
    }
}

pub fn commit_message(run_id: &str, c: &state::ChangeCounts) -> String {
    format!(
        "pathwarden run {run_id}: {} new, {} regressed, {} resolved, {} open",
        c.new,
        c.regressed,
        c.resolved,
        c.open + c.new + c.regressed
    )
}

/// Compares `ev` with the `previous` state (and the last run, to notice a
/// collection that looks incomplete) and finishes the analysis.
pub fn prepare<P: RecordProgress>(
    prev_run: Option<&LastRun>,
    previous: &FindingsState,
    ev: Evaluated,
    config: &Config,
    opts: &Options,
    p: &mut P,
) -> Prepared {
    let opts = &Options {
        started_ms: start_after(prev_run, opts.started_ms),
        ..*opts
    };
    let c = compare(
        prev_run,
        previous,
        &ev.graph,
        &ev.stats,
        &ev.zones,
        &ev.findings,
        config,
        opts,
        p,
    );
    let a = ev.finish(p);
    let finished = opts
        .finished_at
        .unwrap_or_else(analyze::now)
        .max(opts.started_ms.div_euclid(1000));
    c.prepared(a, finished, opts)
}

/// When a run starts, in milliseconds: `started_ms`, or the second after
/// the last run's start when it started in the same second (runs saved in
/// a loop). The history, the findings state and the Introduced periods
/// date runs by the second, so two runs never share one.
fn start_after(prev_run: Option<&LastRun>, started_ms: i64) -> i64 {
    match prev_run {
        // A start in the second of the last one, or a few before it (a
        // clock that hands every run the same time): the next second free.
        Some(prev)
            if (0..60).contains(&prev.started_at.saturating_sub(started_ms.div_euclid(1000))) =>
        {
            started_ms.max(prev.started_at.saturating_add(1).saturating_mul(1000))
        }
        _ => started_ms,
    }
}

/// Compares a prepared run again, with a newer `previous` state: another
/// run was recorded while this one was (see [`save_and_publish`]). Keeps
/// its analysis, run ID, finish time and label.
pub fn reprepare<P: RecordProgress>(
    prep: Prepared,
    prev_run: Option<&LastRun>,
    previous: &FindingsState,
    config: &Config,
    opts: &Options,
    p: &mut P,
) -> Prepared {
    let a = prep.analysis;
    // The run keeps its ID ([`start_after`] may have moved it on).
    let opts = &Options {
        started_ms: state::run_id_to_millis(&prep.last.run_id).unwrap_or(opts.started_ms),
        ..*opts
    };
    let c = compare(
        prev_run,
        previous,
        &a.graph,
        &a.stats,
        &a.zones,
        &a.findings,
        config,
        opts,
        p,
    );
    let mut again = c.prepared(a, prep.finished, opts);
    again.point.label = prep.point.label;
    again
}

/// A run compared with the previous state, before its history point.
struct Compared {
    reconciled: Reconciled,
    domains: Vec<String>,
    trusted: Vec<String>,
    objects: usize,
    run_sources: crate::opengraph::coverage::RunSources,
    /// The last run's sources and hosts ([`LastRun::baseline_sources`]):
    /// this run carries forward the computers it didn't read
    /// ([`crate::opengraph::coverage::RunSources::recorded`]).
    prev_sources: Vec<String>,
    /// The last run recorded no computers ([`LastRun::hosts`] absent).
    legacy_hosts: bool,
    compared_with: Option<String>,
    settings_files: Vec<crate::dcsettings::SettingsFileUse>,
    settings_fewer: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn compare<P: RecordProgress>(
    prev_run: Option<&LastRun>,
    previous: &FindingsState,
    g: &crate::graph::AdGraph,
    stats: &crate::ingest::IngestStats,
    zones: &[crate::zones::Zone],
    all: &[crate::findings::Finding],
    config: &Config,
    opts: &Options,
    p: &mut P,
) -> Compared {
    let started_ms = opts.started_ms;
    let started = started_ms / 1000;
    // Guard against resolving findings that were simply not collected this
    // time: findings are only resolved in domains present in this collection,
    // and nothing is resolved when the collection looks incomplete.
    let domains = analyze::domain_names(g);
    let trusted = analyze::trusted_domain_names(g);
    let objects = g.nodes().filter(|(_, n)| !n.placeholder).count();
    let mut allow_resolve = true;
    if !stats.skipped_objects.is_empty() {
        // Objects too large to load: what they would have shown is unknown.
        allow_resolve = false;
        p.warn(format!(
            "{} object(s) were too large to load (see `pathwarden summary`); no findings will be marked resolved",
            stats.skipped_objects.len()
        ));
    }
    if let Some(prev) = prev_run {
        if prev.objects > 0 && objects * 2 < prev.objects {
            if opts.accept_shrink {
                p.warn(format!(
                    "this collection has {objects} objects, less than half of the last run's {}; resolving anyway (--accept-shrink)",
                    prev.objects
                ));
            } else {
                allow_resolve = false;
                p.warn(format!(
                    "this collection has {objects} objects, less than half of the last run's {}; no findings will be marked resolved. If the environment really shrank, run again with --accept-shrink.",
                    prev.objects
                ));
            }
        }
        // A last run recorded before trusted domains were left out lists
        // them as collected: a domain trusted now is not missing. This is
        // on purpose and can be wrong: that run may really have collected
        // the domain too, and its list can't tell. Only the warning is
        // left out; the resolve scope still holds the domain's findings.
        let legacy = prev.trusted_domains.is_none();
        let missing: Vec<&String> = prev
            .domains
            .iter()
            .filter(|d| !domains.contains(d) && !(legacy && trusted.contains(d)))
            .collect();
        if !missing.is_empty() {
            p.warn(format!(
                "not in this collection: {}; their findings are kept as they were, not resolved",
                missing
                    .iter()
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if prev.collected_at.is_some() && prev.collected_at == stats.collected_at {
            p.warn(format!(
                "the collector's files carry the same collection time as the last run's ({}): if a new collection was meant, check that its files are the new ones",
                stats
                    .collected_at
                    .map(crate::time::format_collected)
                    .unwrap_or_default()
            ));
        }
    }
    // OpenGraph sources and SYSVOL parts: findings that rest on one resolve
    // only when it covered them this run; a source the last run had data
    // from and this one lacks holds every attack-path finding.
    let run_sources = crate::opengraph::coverage::RunSources::from_analysis_at(
        g,
        stats,
        Some((
            stats.collected_at.unwrap_or(started),
            config.rules.stale_days,
        )),
    );
    let prev_sources = prev_run
        .map(|p| p.baseline_sources(&run_sources, previous))
        .unwrap_or_default();
    // A last run of 0.2 or earlier recorded no computers: findings that
    // rest on sessions or local groups without listing their computers are
    // held while any isn't read, and this run records the unread ones.
    let legacy_hosts = prev_run.is_some_and(|l| l.hosts.is_none());
    // Sessions and local groups this run did not ask for (a Quick run):
    // findings that rest on them and were seen when they were read are
    // held, and so are sessions and admin rights into the zones.
    let untargeted = crate::posture::untargeted_domains(&crate::posture::completeness(
        g,
        stats.collected_at.unwrap_or(started),
    ));
    let scope = state::ResolveScope::domains(&domains, allow_resolve)
        .with_sources(run_sources.clone(), &prev_sources)
        .with_legacy_hosts(legacy_hosts)
        .with_rules_off(&config.rules.disabled)
        .with_untargeted(&untargeted);
    if !scope.missing_sources.is_empty() {
        p.warn(format!(
            "data the last run had is missing or incomplete ({}); attack-path findings will not be marked resolved",
            run_sources.describe(&scope.missing_sources)
        ));
    }
    // Computers not read; those whose part this run didn't target at all
    // (a Quick run) are said by the completeness lines instead.
    let not_targeted = untargeted
        .iter()
        .fold(crate::posture::Untargeted::default(), |a, (_, u)| a.or(*u));
    let unread: Vec<String> = scope
        .missing_hosts
        .iter()
        .filter(|k| {
            !(not_targeted.sessions && k.starts_with(crate::opengraph::SESSION_HOST)
                || not_targeted.local_groups && k.starts_with(crate::opengraph::LOCAL_GROUP_HOST))
        })
        .cloned()
        .collect();
    if let Some(words) = run_sources.unread_sentences(&unread) {
        p.warn(words);
    }
    for s in &stats.opengraph.sources {
        if !matches!(
            s.coverage.state,
            crate::opengraph::coverage::CoverageState::Sidecar
                | crate::opengraph::coverage::CoverageState::Collector
        ) {
            p.warn(format!(
                "{} data has no valid coverage file; findings that rest on it can open but will not be marked resolved",
                s.name
            ));
        }
    }
    let mut r = state::reconcile_scoped(previous, all, started, config.state.keeps_names(), &scope);
    // Edges into Tier Zero and the zones, and when each appeared, kept per
    // environment (the domains collected): a state folder shared by two
    // never makes one's edges new or gone by the other's run. Resolved
    // only when the collection looks complete next to the environment's
    // own last run, and no source is missing.
    let env_scopes = state::scopes_of(&domains);
    let shrunk = !opts.accept_shrink
        && previous
            .paths
            .as_ref()
            .is_some_and(|t| t.shrunk(&crate::introduced::env_key(&env_scopes), objects));
    let may_resolve =
        stats.skipped_objects.is_empty() && !shrunk && scope.missing_sources.is_empty();
    r.state.paths = Some(crate::introduced::PathsTrack::record_checked(
        previous.paths.as_ref(),
        &env_scopes,
        g,
        zones,
        started,
        (may_resolve, untargeted.is_empty()),
        &|u| run_sources.host_read_or_gone(u),
    ));
    r.state.tracked_since.get_or_insert(started);
    // Tier Zero settings files the last run had and this one lacks:
    // said, not held; findings that rested on them turn unverified.
    let settings_files = stats.settings_files(started);
    let settings_fewer = prev_run
        .map(|l| crate::dcsettings::fewer(&l.settings_files, &settings_files))
        .unwrap_or_default();
    Compared {
        reconciled: r,
        domains,
        trusted,
        objects,
        run_sources,
        prev_sources,
        legacy_hosts,
        compared_with: prev_run.map(|l| l.run_id.clone()),
        settings_files,
        settings_fewer,
    }
}

impl Compared {
    /// The run ready to save, with its finished analysis.
    fn prepared(self, a: Analysis, finished: i64, opts: &Options) -> Prepared {
        let Compared {
            reconciled: r,
            domains,
            trusted,
            objects,
            run_sources,
            prev_sources,
            legacy_hosts,
            compared_with,
            settings_files,
            settings_fewer,
        } = self;
        let (sources, hosts) = run_sources.recorded(&prev_sources, legacy_hosts);
        let started = opts.started_ms / 1000;
        let run_id = state::run_id_millis(opts.started_ms);
        let last = LastRun {
            version: state::STATE_VERSION,
            run_id: run_id.clone(),
            started_at: started,
            finished_at: finished,
            collected_at: a.stats.collected_at,
            pathwarden: env!("CARGO_PKG_VERSION").to_string(),
            collector_files: a.stats.files.len(),
            domains: domains.clone(),
            trusted_domains: Some(trusted.clone()),
            objects,
            changes: r.counts,
            sources,
            sources_exact: true,
            settings_files,
            hosts: Some(hosts),
        };
        let mut point =
            HistoryPoint::new(&run_id, started, a.stats.collected_at, &a.posture, r.counts)
                .with_domains(&domains)
                .with_trusted(&trusted)
                .with_recorded_by(opts.recorded_by);
        point.data = Some(a.data_digest());
        let exposed =
            crate::exposed::ExposedRecord::from_plan(&run_id, point.basis(), &a.graph, &a.plan);
        point.exposed_keys = exposed.is_some();
        Prepared {
            analysis: a,
            reconciled: r,
            last,
            point,
            finished,
            compared_with,
            exposed,
            settings_fewer,
        }
    }
}

/// What became of a run [`save_and_publish`] recorded.
#[derive(Debug, Default)]
pub struct Saved {
    /// Committed and pushed.
    pub pushed: bool,
    /// Added before a newer run another machine pushed first: only its
    /// history point was recorded ([`HistoryPoint::inserted`]), and the
    /// findings state is the newer run's. Its event is older than the
    /// state, so output plugins must not act on it.
    pub inserted: bool,
    /// Why the push failed when the run is still recorded, committed in the
    /// working copy for the next run to push
    /// ([`crate::store::KeptUnpushed::sentence`] says it).
    pub unpushed: Option<crate::store::KeptUnpushed>,
}

/// Whether the history in `store` has a point for run `run_id` already.
fn taken(store: &Store, run_id: &str) -> bool {
    store.has_state_file(&format!("history/{run_id}.json"))
}

/// Warnings kept aside while a run is compared again, given once it is
/// recorded.
#[derive(Default)]
struct Kept(Vec<String>);

impl Progress for Kept {
    fn phase(&mut self, _: analyze::Phase) {}
}

impl RecordProgress for Kept {
    fn warn(&mut self, message: String) {
        if !self.0.contains(&message) {
            self.0.push(message);
        }
    }
}

/// Saves a prepared run in `store` (with its collection `timings`) and,
/// when `push` and the state is a git repository, commits and pushes it.
/// The caller holds the store's lock and pulled before [`prepare`].
///
/// When another run pushed first, this run is recorded on top of what that
/// run left, so neither is lost: if this run is the newer one (by run ID,
/// the time it started), it is compared again with the state the other left
/// ([`reprepare`]); if the other is newer, only this run's history point is
/// added, before it ([`HistoryPoint::inserted`]), and the findings state
/// stays as the newer run left it. Once it is recorded, `p` gets one
/// warning saying which, with what the comparison found again and what
/// became of runs an earlier failed push left ([`Store::pull`]).
///
/// A push that fails for another reason leaves the run recorded in the
/// working copy: [`Saved::unpushed`], not an error. Returns the run as
/// recorded (compared again or not). What the writes have to say (an
/// upgrade of the history's binding that couldn't rewrite every file)
/// goes to the run's warnings, once.
pub fn save_and_publish<P: RecordProgress>(
    store: &Store,
    prep: Prepared,
    config: &Config,
    opts: &Options,
    timings: Option<&crate::diagnostics::CollectionTimings>,
    push: bool,
    p: &mut P,
) -> (Prepared, anyhow::Result<Saved>) {
    let notes = std::cell::RefCell::new(Vec::<String>::new());
    // A damaged findings state the pull brought ([`Store::load_for_run`]).
    let fresh = std::cell::RefCell::new(None::<String>);
    let save = |prep: &Prepared, whole: bool| -> anyhow::Result<()> {
        let mut said = if whole {
            store.save(&prep.reconciled.state, &prep.last, &prep.point)?
        } else {
            store.save_point(&prep.point)?
        };
        if let Some(t) = timings {
            said.extend(store.save_timings(&prep.last.run_id, t)?);
        }
        if let Some(e) = &prep.exposed {
            said.extend(store.save_exposed(e)?);
            // Older runs' keys the history no longer needs; a history
            // that can't be read for it keeps them for the next run.
            let _ = store.prune_exposed();
        }
        // Each try writes everything again: only the last one's notes
        // say how it stands (an upgrade a retry finished says nothing).
        *notes.borrow_mut() = said;
        Ok(())
    };
    let tell = |p: &mut P| {
        for n in crate::store::once_each(notes.take()) {
            p.warn(n);
        }
    };
    // Two runs started in the same millisecond share an ID: never let one
    // overwrite the other's point.
    if taken(store, prep.run_id()) {
        let e = anyhow::anyhow!(
            "run {} is in the history already (another run started in the same millisecond?); \
             this run was not recorded",
            prep.run_id()
        );
        return (prep, Err(e));
    }
    if let Err(e) = save(&prep, true) {
        return (prep, Err(e));
    }
    if !push || !store.is_git() {
        tell(p);
        return (with_actions(store, prep), Ok(Saved::default()));
    }
    let message = prep.commit_message();
    let first_compared = prep.compared_with.clone();
    let mut slot = Some(prep);
    let mut inserted = false;
    let mut said = None;
    let mut again = Kept::default();
    let published = store.publish_with(&message, || {
        let (previous, damaged) = store.load_for_run()?;
        *fresh.borrow_mut() = damaged;
        let prev_run = crate::store::last_run(store);
        let other = prev_run.as_ref().map(|l| l.run_id.clone());
        let ours = slot.as_mut().expect("the run is kept between tries");
        if taken(store, ours.run_id()) {
            anyhow::bail!(
                "run {} is in the history already (another run started in the same millisecond?)",
                ours.run_id()
            );
        }
        if other.as_deref().is_some_and(|o| o > ours.run_id()) {
            let other = other.unwrap_or_default();
            ours.point.inserted = true;
            save(ours, false)?;
            inserted = true;
            said = Some(format!(
                "a newer run ({other}) was pushed to the history while this one ran: this run was \
                 added to the history before it, as an earlier point, and the findings state \
                 stays as the newer run left it"
            ));
            return Ok(Some(ours.commit_message()));
        }
        let ours = slot.take().expect("the run is kept between tries");
        let mut kept = Kept::default();
        let mut prep = reprepare(ours, prev_run.as_ref(), &previous, config, opts, &mut kept);
        prep.point.inserted = false;
        inserted = false;
        let message = prep.commit_message();
        let saved = save(&prep, true);
        slot = Some(prep);
        saved?;
        again = kept;
        said = Some(match other {
            Some(o) if Some(&o) != first_compared.as_ref() => format!(
                "another run ({o}) was pushed to the history while this one ran: this run was \
                 compared again with the state it left, and recorded after it"
            ),
            _ => "the history changed while this run ran (another machine removed or imported \
                  runs): this run was recorded again on top of it"
                .to_string(),
        });
        Ok(Some(message))
    });
    let prep = slot.expect("the run is kept between tries");
    let (published, unpushed) = match published {
        Ok(published) => (published, None),
        Err(e) => match e.downcast::<crate::store::KeptUnpushed>() {
            Ok(kept) => (
                Published {
                    notes: kept.notes.clone(),
                    ..Published::default()
                },
                Some(kept),
            ),
            Err(e) => return (prep, Err(e)),
        },
    };
    if let Some(s) = said {
        p.warn(s);
    }
    if let Some(s) = fresh.take() {
        p.warn(s);
    }
    for w in again.0 {
        p.warn(format!("compared again: {w}"));
    }
    for n in published.notes {
        p.warn(n);
    }
    tell(p);
    (
        with_actions(store, prep),
        Ok(Saved {
            pushed: published.pushed,
            inserted,
            unpushed,
        }),
    )
}

/// The run's findings and those it found fixed, with what finding
/// actions did on each ([`crate::action_log::annotate`]), as the history
/// holds it now: so the event, the report and the exports carry it. A
/// file this version can't read leaves them without.
fn with_actions(store: &Store, mut prep: Prepared) -> Prepared {
    if let Ok(file) = crate::action_log::load(store) {
        crate::action_log::annotate(
            &file,
            &mut prep.analysis.findings,
            &mut prep.reconciled.resolved,
        );
    }
    prep
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run started in the same second as the last one starts a second
    /// later, so no two runs share a second in the history.
    #[test]
    fn runs_of_one_second_get_their_own() {
        let prev: LastRun = serde_json::from_str(
            r#"{"version":1,"run_id":"x","started_at":100,"finished_at":100,"collected_at":null,
            "pathwarden":"1","collector_files":1,"domains":[],"changes":{"new":0,"open":0,
            "regressed":0,"suppressed":0,"resolved":0}}"#,
        )
        .unwrap();
        assert_eq!(start_after(Some(&prev), 100_250), 101_000);
        assert_eq!(start_after(Some(&prev), 101_250), 101_250);
        // An earlier start (a run dated in the past) is left as it is.
        assert_eq!(start_after(Some(&prev), 10_000), 10_000);
        // A clock that gives every run the same start: each one a second on.
        assert_eq!(start_after(Some(&prev), 99_000), 101_000);
        assert_eq!(start_after(None, 100_250), 100_250);
    }
}
