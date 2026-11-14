//! The analysis pipeline shared by the command line and the local UI: load the
//! collector data, apply the config (extra Tier Zero, zones, rule settings,
//! suppressions), run every rule, then compute posture and the remediation
//! plan and, on request, render the HTML report.
//!
//! Two stages, so commands that only need findings skip the plan:
//! [`evaluate`] loads and runs the rules; [`Evaluated::finish`] adds posture
//! and the plan. [`run`] does both. A [`Progress`] hears each [`Phase`] as it
//! starts, and how many bytes of collector data have been read; any
//! `FnMut(Phase)` closure is a `Progress`.

use std::path::Path;

use serde::Serialize;

use crate::config::Config;
use crate::findings::{self, Context, Finding, RuleSettings};
use crate::graph::AdGraph;
use crate::ingest::{IngestError, IngestStats};
use crate::model::NodeKind;
use crate::posture::{self, Posture};
use crate::remediation::{self, RemediationPlan};
use crate::report::{self, ReportInput};
use crate::timing::phase;
use crate::zones::{self, Zone};
use crate::LoadOptions;

/// A step of the analysis, reported to the progress callback as it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Reading collector files.
    Reading,
    /// Building the graph: implicit edges and Tier Zero.
    Graph,
    /// Running the rules.
    Rules,
    /// Posture and the remediation path.
    Remediation,
    /// Rendering the HTML report.
    Report,
}

/// Hears an analysis's progress.
pub trait Progress {
    /// A phase started.
    fn phase(&mut self, phase: Phase);
    /// Bytes of collector data read so far, of `total` (during
    /// [`Phase::Reading`], several times a second).
    fn bytes(&mut self, _read: u64, _total: u64) {}
}

impl<F: FnMut(Phase)> Progress for F {
    fn phase(&mut self, phase: Phase) {
        self(phase)
    }
}

/// A [`Progress`] that ignores everything.
pub struct Quiet;

impl Progress for Quiet {
    fn phase(&mut self, _: Phase) {}
}

impl Phase {
    pub const ALL: [Phase; 5] = [
        Phase::Reading,
        Phase::Graph,
        Phase::Rules,
        Phase::Remediation,
        Phase::Report,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Reading => "reading",
            Phase::Graph => "graph",
            Phase::Rules => "rules",
            Phase::Remediation => "remediation",
            Phase::Report => "report",
        }
    }
}

/// The load options a config implies: its Tier Zero additions, then `extra`.
pub fn load_options(config: &Config, extra_tier_zero: &[String]) -> LoadOptions {
    LoadOptions {
        extra_tier_zero: config
            .tier_zero
            .iter()
            .chain(extra_tier_zero)
            .cloned()
            .collect(),
        limits: config.ingest.limits_with(&config.opengraph),
        packs: config.packs(),
        not_tier_zero_planes: config.management_planes.applied().to_vec(),
        now: Some(config.settings().now),
        all_properties: false,
        settings_folders: config.settings_folder_paths(),
    }
}

/// The rule settings a config implies for data loaded with `stats`: `now` is
/// the collection time when the file names carry one, as [`evaluate`] uses.
/// Commands that skip the rules (`exposure`, `choke-points`, `plan`) use this
/// so their exposure denominators match the Posture page.
pub fn settings_for(config: &Config, stats: &IngestStats) -> RuleSettings {
    let mut settings = config.settings();
    if let Some(collected) = stats.collected_at {
        settings.now = collected;
    }
    settings
}

/// Data loaded and every enabled rule run, with suppressions applied.
pub struct Evaluated {
    pub graph: AdGraph,
    pub stats: IngestStats,
    pub zones: Vec<Zone>,
    /// Rule settings; `now` is the collection time when the file names carry one.
    pub settings: RuleSettings,
    pub findings: Vec<Finding>,
}

/// A complete analysis: findings plus posture and the remediation plan.
pub struct Analysis {
    pub graph: AdGraph,
    pub stats: IngestStats,
    pub zones: Vec<Zone>,
    pub settings: RuleSettings,
    pub findings: Vec<Finding>,
    pub posture: Posture,
    pub plan: RemediationPlan,
    /// Domains whose data was collected, sorted ([`domain_names`]).
    pub domains: Vec<String>,
    /// Domains the data has an object for but did not collect, sorted
    /// ([`trusted_domain_names`]).
    pub trusted_domains: Vec<String>,
}

/// Loads the data and runs every enabled rule.
///
/// Ages (stale accounts, password age, active computers) are measured from
/// when the data was collected, not from today; suppressions expire in real
/// time.
pub fn evaluate<P: AsRef<Path>>(
    inputs: &[P],
    config: &Config,
    extra_tier_zero: &[String],
    progress: &mut dyn Progress,
) -> Result<Evaluated, IngestError> {
    let mut settings = config.settings();
    let wall_clock = settings.now;
    // Ingest judges Tier Zero settings files by the same clock.
    let opts = LoadOptions {
        now: Some(wall_clock),
        ..load_options(config, extra_tier_zero)
    };
    // PingCastle reports ride along with the collector data.
    let (inputs, reports) = crate::pingcastle::split_inputs(inputs);
    let (graph, mut stats) = crate::load_with_progress(&inputs, &opts, progress)?;
    let (external, infos) = crate::pingcastle::load(&reports)
        .map_err(|(path, detail)| IngestError::External { path, detail })?;
    stats.pingcastle = infos;
    let zones = zones::resolve(&graph, &config.zones);
    if let Some(collected) = stats.collected_at {
        settings.now = collected;
    }
    progress.phase(Phase::Rules);
    let ctx = Context::new(&graph, &stats.trusts, &settings).with_zones(&zones);
    let mut all = phase("rules", || findings::evaluate(&ctx, &config.rules.disabled));
    all.extend(external.into_iter().filter(|f| {
        !config
            .rules
            .disabled
            .iter()
            .any(|d| d.eq_ignore_ascii_case(f.rule))
    }));
    config.apply_suppressions(&mut all, wall_clock);
    Ok(Evaluated {
        graph,
        stats,
        zones,
        settings,
        findings: all,
    })
}

impl Evaluated {
    /// Posture against Tier Zero and every zone.
    pub fn posture(&self) -> Posture {
        posture::compute(&self.graph, &self.findings, &self.zones, &self.settings)
    }

    /// Which principals count toward the exposure denominators
    /// ([`crate::analysis::Relevance`]), at the collection time.
    pub fn relevance(&self) -> crate::analysis::Relevance {
        crate::analysis::Relevance::from_settings(&self.graph, &self.settings)
    }

    /// Adds posture and the Tier Zero remediation plan.
    pub fn finish(self, progress: &mut dyn Progress) -> Analysis {
        progress.phase(Phase::Remediation);
        let mut posture = phase("posture", || self.posture());
        let rel = self.relevance();
        let plan = phase("remediation plan", || remediation::plan(&self.graph, &rel));
        posture.plan = Some(crate::posture::PlanSummary {
            steps: plan.fixes.len(),
            exposed_after: plan.exposed_after,
        });
        let domains = domain_names(&self.graph);
        let trusted_domains = trusted_domain_names(&self.graph);
        Analysis {
            graph: self.graph,
            stats: self.stats,
            zones: self.zones,
            settings: self.settings,
            findings: self.findings,
            posture,
            plan,
            domains,
            trusted_domains,
        }
    }
}

/// Loads, evaluates and finishes in one go.
pub fn run<P: AsRef<Path>>(
    inputs: &[P],
    config: &Config,
    extra_tier_zero: &[String],
    progress: &mut dyn Progress,
) -> Result<Analysis, IngestError> {
    Ok(evaluate(inputs, config, extra_tier_zero, progress)?.finish(progress))
}

impl Analysis {
    /// The self-contained HTML report, stamped as generated at `generated_at`
    /// (Unix time), without a run history: the Overview shows this run
    /// alone.
    pub fn report_html(&self, generated_at: i64, progress: &mut dyn Progress) -> String {
        self.report_html_with(generated_at, &Default::default(), progress)
    }

    /// [`Analysis::report_html`] with its environment's run history
    /// ([`crate::history::for_report`]): the Overview's trend and what
    /// changed since the last run.
    pub fn report_html_with(
        &self,
        generated_at: i64,
        history: &crate::history::ReportHistory,
        progress: &mut dyn Progress,
    ) -> String {
        let lists = self.exposure_lists(history);
        self.report_html_lists(generated_at, history, &lists, progress)
    }

    /// [`Analysis::report_html_with`] with the run's account lists already
    /// made ([`Analysis::exposure_lists`] against the same `history`), for
    /// a caller that saves them too.
    pub fn report_html_lists(
        &self,
        generated_at: i64,
        history: &crate::history::ReportHistory,
        lists: &crate::exposed::ExposureLists,
        progress: &mut dyn Progress,
    ) -> String {
        progress.phase(Phase::Report);
        phase("render report", || {
            // A report of the run that left the findings state dates its
            // findings, objects and paths (the Introduced filter).
            let introduced = history.state.as_deref().map(|state| {
                let latest = history.this_run.as_ref().map_or(generated_at, |p| p.at);
                let mut runs = crate::introduced::Runs::new(
                    history
                        .earlier
                        .iter()
                        .map(|p| p.at)
                        .chain([latest])
                        .collect(),
                );
                if let Some(p) = &history.this_run {
                    runs = runs.in_env_of(p);
                }
                let names = crate::introduced::Names::new(
                    &self.findings,
                    &self.graph,
                    &self.zones,
                    Some(&self.plan),
                );
                crate::introduced::ForReport::new(
                    state,
                    latest,
                    runs,
                    !history.earlier.is_empty(),
                    &names,
                )
            });
            let forest = (!self.stats.trusts.is_empty()).then(|| self.forest_map());
            report::render_html(&ReportInput {
                posture: &self.posture,
                findings: &self.findings,
                plan: &self.plan,
                stats: &self.stats,
                domains: &self.domains,
                generated_at,
                history,
                introduced: introduced.as_ref(),
                forest: forest.as_ref(),
                lists: Some(lists),
                kinds: Some(self.graph.kind_table()),
            })
        })
    }

    /// [`Analysis::report_html_with`] with the run's label, when it has one
    /// ([`report::with_label`]).
    pub fn report_html_labeled(
        &self,
        generated_at: i64,
        label: Option<&str>,
        history: &crate::history::ReportHistory,
        progress: &mut dyn Progress,
    ) -> String {
        let html = self.report_html_with(generated_at, history, progress);
        match label {
            Some(l) => report::with_label(&html, l),
            None => html,
        }
    }

    /// Which accounts each remediation step cuts off, and which reach Tier
    /// Zero now or no longer against the run `history` compares with
    /// ([`crate::exposed::lists_for`]).
    pub fn exposure_lists(
        &self,
        history: &crate::history::ReportHistory,
    ) -> crate::exposed::ExposureLists {
        crate::exposed::lists_for(self, history)
    }

    /// The domains its trust records name that it didn't collect,
    /// sorted: by name, or by SID when a record has no name. What the forest
    /// map counts as not collected, without building it.
    pub fn uncollected_domains(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in &self.stats.trusts {
            for (name, sid) in [(&t.source, &t.source_sid), (&t.target, &t.target_sid)] {
                let n = if name.trim().is_empty() { sid } else { name };
                let n = n.trim();
                if n.is_empty()
                    || self.domains.iter().any(|d| d.eq_ignore_ascii_case(n))
                    || out.iter().any(|o| o.eq_ignore_ascii_case(n))
                {
                    continue;
                }
                out.push(n.to_string());
            }
        }
        out.sort();
        out
    }

    /// The domains and trusts ([`crate::forest::forest_map`]), exposure
    /// counted at the collection time.
    pub fn forest_map(&self) -> crate::forest::ForestMap {
        let rel = crate::analysis::Relevance::from_settings(&self.graph, &self.settings);
        crate::forest::forest_map(&self.graph, &self.stats, &rel)
    }

    /// Objects that were collected (not just referenced).
    pub fn collected_objects(&self) -> usize {
        self.graph.nodes().filter(|(_, n)| !n.placeholder).count()
    }

    /// A digest of the collection this analysis read, recorded with each run
    /// ([`crate::state::HistoryPoint::data`]): when it was collected, its
    /// domains, how many objects of each kind and edges it has, and the
    /// findings it gave. A report of the data the last run already recorded
    /// has the same digest, and compares with the run before it instead of
    /// with itself. Names stay out (the digest is of their fingerprints).
    pub fn data_digest(&self) -> String {
        let mut fingerprints: Vec<&str> = self
            .findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        fingerprints.sort_unstable();
        let text = serde_json::json!({
            "collected_at": self.stats.collected_at,
            "domains": crate::state::scopes_of(&self.domains),
            "objects": self.stats.objects,
            "nodes": self.graph.node_count(),
            "edges": self.graph.edge_count(),
            "findings": fingerprints,
        })
        .to_string();
        crate::opengraph::coverage::sha256_hex(text.as_bytes())
    }
}

/// Domains whose data was collected, sorted: the domain objects that are
/// not marked as not collected, and any domain a collected user or computer
/// belongs to.
///
/// RustHound-CE (and so the built-in collector) writes an object for each
/// trusted domain beside the one it collected, marked `collected: false`.
/// Those stay in the graph for the trusts, but are not counted here: one
/// domain with ten trusts is one collected domain. SharpHound writes only
/// the domains it collected.
pub fn domain_names(g: &AdGraph) -> Vec<String> {
    let mut domains: Vec<String> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain && !n.placeholder)
        .map(|(_, n)| n)
        .filter(|n| n.props.collected != Some(false))
        .map(|n| n.name.clone())
        .collect();
    let mut known: Vec<&str> = domain_objects(g).collect();
    known.retain(|d| !domains.iter().any(|c| c == d));
    if !known.is_empty() {
        // A domain object marked not collected whose users or computers
        // are in the data was collected all the same.
        let with_principals: std::collections::HashSet<&str> = g
            .nodes()
            .filter(|(_, n)| matches!(n.kind, NodeKind::User | NodeKind::Computer))
            .filter(|(_, n)| !n.placeholder)
            .filter_map(|(_, n)| n.domain.as_deref())
            .collect();
        domains.extend(
            known
                .into_iter()
                .filter(|d| with_principals.contains(d))
                .map(str::to_owned),
        );
    }
    domains.sort();
    domains.dedup();
    domains
}

/// Domains the data has an object for whose data was not collected
/// (trusted domains, see [`domain_names`]), sorted.
pub fn trusted_domain_names(g: &AdGraph) -> Vec<String> {
    let collected = domain_names(g);
    let mut trusted: Vec<String> = domain_objects(g)
        .filter(|d| !collected.iter().any(|c| c == d))
        .map(str::to_owned)
        .collect();
    trusted.sort();
    trusted.dedup();
    trusted
}

/// Every domain the data has an object for, collected or not, sorted: what
/// [`domain_names`] returned before it left trusted domains out.
pub fn known_domain_names(g: &AdGraph) -> Vec<String> {
    let mut known: Vec<String> = domain_objects(g).map(str::to_owned).collect();
    known.sort();
    known.dedup();
    known
}

fn domain_objects(g: &AdGraph) -> impl Iterator<Item = &str> {
    g.nodes()
        .filter(|(_, n)| n.kind == NodeKind::Domain && !n.placeholder)
        .map(|(_, n)| n.name.as_str())
}

/// Wall-clock Unix time, as the report's "generated" stamp uses.
pub fn now() -> i64 {
    RuleSettings::default().now
}
