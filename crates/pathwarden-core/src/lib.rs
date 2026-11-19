//! pathwarden-core: attack path analysis for Active Directory, built on the
//! BloodHound collector data format (SharpHound / RustHound-CE output).

// The only unsafe code is in proc_tree (Job Objects, process groups),
// perms (Windows access lists), keystore (Credential Manager, DPAPI-NG),
// time, and two functions of plugins (drive types, known folders).
#![deny(unsafe_code)]

pub mod action_log;
pub mod actions;
pub mod adcs;
pub mod analysis;
pub mod analyze;
pub mod binding;
pub mod config;
pub mod config_edit;
pub mod connect;
pub mod crypt;
pub mod cypher;
pub mod dcsettings;
pub mod diagnostics;
pub mod entra;
pub mod event;
pub mod evidence;
pub mod explore;
pub mod exposed;
pub mod findings;
pub mod folder_origin;
pub mod forest;
pub mod formats;
pub mod graph;
pub mod guides;
pub mod history;
pub mod hostprobe;
pub mod identity;
pub mod ingest;
pub mod introduced;
#[allow(unsafe_code)]
pub mod keystore;
pub mod kinds;
pub mod logs;
pub mod mgmt;
pub mod model;
pub mod object_index;
pub mod opengraph;
pub mod owned;
pub mod pack_origin;
mod par;
#[allow(unsafe_code)]
pub mod perms;
pub mod pingcastle;
pub mod plugin_form;
pub mod plugins;
pub mod point_findings;
pub mod postprocess;
pub mod posture;
pub mod prepared;
#[allow(unsafe_code)]
mod proc_tree;
pub mod record;
pub mod redact;
pub mod remediation;
pub mod report;
pub mod retest;
pub mod settings_sync;
pub mod sid;
pub mod since;
pub mod spawn;
pub mod state;
pub mod status_keys;
pub mod store;
pub mod storedcreds;
pub mod sysvol;
pub mod taskxml;
pub mod text;
pub mod tierzero;
pub mod time;
pub mod timing;
pub mod zones;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

pub use graph::AdGraph;
pub use ingest::{IngestError, IngestStats};
pub use petgraph::graph::NodeIndex;

#[derive(Debug, Default, Clone)]
pub struct LoadOptions {
    /// Additional object IDs or names to treat as Tier Zero.
    pub extra_tier_zero: Vec<String>,
    /// Size limits for reading collector files.
    pub limits: ingest::IngestLimits,
    /// Mapping packs for OpenGraph files; `None` for the embedded ones.
    pub packs: Option<Vec<opengraph::Pack>>,
    /// Management planes (object IDs or names) not to treat as Tier Zero
    /// (`[management_planes] not_tier_zero`).
    pub not_tier_zero_planes: Vec<String>,
    /// The analysis's wall clock (Unix seconds), the `now` of its
    /// [`findings::RuleSettings`] before the collection time replaces it.
    /// Tier Zero settings files are judged stale or future-dated against
    /// it when the collection time is unknown. `None`: the system clock.
    pub now: Option<i64>,
    /// Keep every property the collector wrote on each object, not only
    /// those the analysis reads, so Cypher queries can filter on them
    /// (`pathwarden query`). Off by default: it costs memory per object.
    pub all_properties: bool,
    /// Tier Zero settings folders (`settings_folders` in the config): their
    /// settings files are read after the inputs
    /// ([`ingest::Ingestor::ingest_settings_folder`]).
    pub settings_folders: Vec<PathBuf>,
}

/// Ingests collector output, derives implicit edges, and marks Tier Zero.
pub fn load<P: AsRef<Path>>(
    inputs: &[P],
    opts: &LoadOptions,
) -> Result<(AdGraph, IngestStats), IngestError> {
    load_with_progress(inputs, opts, &mut analyze::Quiet)
}

/// How often [`load_with_progress`] reports bytes read.
const BYTES_EVERY: Duration = Duration::from_millis(100);

/// Every object's name and domain on one line ([`text::one_line`]): a GPO,
/// OU or other name holding a line break can't add a line to the
/// remediation text, tickets or exports that quote it.
fn names_on_one_line(g: &mut graph::AdGraph) {
    let broken = |s: &str| s.chars().any(text::breaks_line);
    let bad: Vec<_> = g
        .nodes()
        .filter(|(_, n)| broken(&n.name) || n.domain.as_deref().is_some_and(broken))
        .map(|(ix, _)| ix)
        .collect();
    for ix in bad {
        let n = g.node_mut(ix);
        n.name = text::one_line(&n.name).into_owned();
        if let Some(d) = n.domain.as_mut() {
            *d = text::one_line(d).into_owned();
        }
    }
}

/// [`load`], telling `progress` when reading starts, how many bytes have been
/// read (several times a second), and when graph building starts.
///
/// The files are read on a worker thread while this one reports.
pub fn load_with_progress<P: AsRef<Path>>(
    inputs: &[P],
    opts: &LoadOptions,
    progress: &mut dyn analyze::Progress,
) -> Result<(AdGraph, IngestStats), IngestError> {
    progress.phase(analyze::Phase::Reading);
    let paths: Vec<PathBuf> = inputs.iter().map(|p| p.as_ref().to_path_buf()).collect();
    let total = ingest::work_bytes(&paths);
    let mut ingestor = ingest::Ingestor::with_limits(opts.limits)
        .with_now(opts.now)
        .with_all_properties(opts.all_properties);
    if let Some(packs) = &opts.packs {
        ingestor = ingestor.with_packs(packs.clone());
    }
    let read = ingestor.bytes_read();
    progress.bytes(0, total);
    let me = std::thread::current();
    let folders = &opts.settings_folders;
    let ingestor = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let result = paths
                .iter()
                .try_for_each(|p| timing::phase("ingest", || ingestor.ingest_path(p)));
            if result.is_ok() {
                for d in folders {
                    ingestor.ingest_settings_folder(d);
                }
                timing::phase("ingest: opengraph", || ingestor.ingest_opengraph());
            }
            me.unpark();
            result.map(|()| ingestor)
        });
        while !worker.is_finished() {
            progress.bytes(read.load(Ordering::Relaxed).min(total), total);
            std::thread::park_timeout(BYTES_EVERY);
        }
        worker.join().expect("collector reader thread panicked")
    })?;
    progress.bytes(total, total);
    progress.phase(analyze::Phase::Graph);
    let (mut graph, stats) = timing::phase("ingest: build graph", || ingestor.finish());
    if stats.files.is_empty() {
        return Err(IngestError::Empty);
    }
    // Users and computers are where every path starts; OpenGraph-only data
    // (its own kinds) is measured by its own sources, so it is let through.
    if !graph.nodes().any(|(_, n)| {
        !n.placeholder
            && matches!(
                n.kind,
                model::NodeKind::User | model::NodeKind::Computer | model::NodeKind::External(_)
            )
    }) {
        return Err(IngestError::NoPrincipals {
            files: stats.files.join(", "),
        });
    }
    timing::phase("names on one line", || names_on_one_line(&mut graph));
    timing::phase("postprocess", || postprocess::run(&mut graph));
    timing::phase("tier zero", || {
        tierzero::mark_with(
            &mut graph,
            &opts.extra_tier_zero,
            &opts.not_tier_zero_planes,
        )
    });
    Ok((graph, stats))
}
