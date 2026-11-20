//! The `pathwarden.coverage.v1` sidecar: which units an OpenGraph collector
//! really covered.
//!
//! No OpenGraph collector records which hosts it scanned and found clean,
//! and OpenGraph's `metadata` block rejects extra fields. So coverage goes
//! in a sidecar file BloodHound ignores, bound to its payload by SHA-256:
//!
//! ```json
//! {
//!   "schema": "pathwarden.coverage.v1",
//!   "source_kind": "TaskHound",
//!   "payloads": [{ "file": "taskhound.json", "sha256": "…" }],
//!   "collected_at": 1791512129,
//!   "collector": { "name": "TaskHound", "version": "1.2.0", "via": "pathwarden-collect-taskhound" },
//!   "domains": ["CONTOSO.LOCAL"],
//!   "units": {
//!     "type": "computer",
//!     "ok": ["S-1-5-21-…-1104", "APP01.CONTOSO.LOCAL"],
//!     "failed": [{ "id": "S-1-5-21-…-1107", "reason": "access denied" }],
//!     "all_in_domains": false
//!   },
//!   "complete": true,
//!   "asserted_by": "plugin"
//! }
//! ```
//!
//! Without a valid sidecar a source's findings can open but never resolve:
//! their absence proves nothing ("can't tell").

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::{
    host_unit_key, is_host_key, source_key, unit_key, HOST_UNIT, LOCAL_GROUP_HOST, SESSION_HOST,
};
use crate::graph::AdGraph;
use crate::ingest::{IngestStats, OgSourceStats};
use crate::model::NodeKind;

pub const SCHEMA: &str = "pathwarden.coverage.v1";

/// The unit a finding depends on when it touches too many to list: the
/// source's whole coverage. Satisfied only when the sidecar says every
/// enabled computer of its domains was attempted, and none failed.
pub const ALL_UNITS: &str = "*";

/// Largest sidecar read.
pub const MAX_SIDECAR_BYTES: u64 = 64 << 20;

/// SHA-256 of `bytes` in lower-case hex, as `payloads[].sha256` holds it.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether a file name is a coverage sidecar's: `<payload>.coverage.json`
/// or `pathwarden-coverage.json`.
pub fn is_sidecar_name(label: &str) -> bool {
    let name = label
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(label)
        .to_ascii_lowercase();
    name.ends_with(".coverage.json") || name == "pathwarden-coverage.json"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema: String,
    pub source_kind: String,
    pub payloads: Vec<Payload>,
    #[serde(default)]
    pub collected_at: Option<i64>,
    #[serde(default)]
    pub collector: Option<Collector>,
    #[serde(default)]
    pub domains: Vec<String>,
    pub units: Units,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub asserted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collector {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Units {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub ok: Vec<String>,
    #[serde(default)]
    pub failed: Vec<Failed>,
    #[serde(default)]
    pub all_in_domains: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failed {
    pub id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Most unit entries one sidecar may list.
const MAX_UNITS: usize = 2_000_000;

impl Sidecar {
    /// Parses and checks a sidecar.
    pub fn parse(bytes: &[u8]) -> Result<Sidecar, String> {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let s: Sidecar = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if s.schema != SCHEMA {
            return Err(format!("schema '{}' is not {SCHEMA}", s.schema));
        }
        if s.payloads.is_empty() {
            return Err("it lists no payloads".into());
        }
        if s.units.ok.len() + s.units.failed.len() > MAX_UNITS {
            return Err("it lists too many units".into());
        }
        if s.units.all_in_domains && s.domains.is_empty() {
            return Err("all_in_domains is set but no domains are listed".into());
        }
        Ok(s)
    }

    /// Whether this sidecar vouches for a payload named `file` with this
    /// SHA-256 (hex).
    pub fn binds(&self, file: &str, sha256: &str) -> bool {
        let base = file.rsplit(['/', '\\', '!']).next().unwrap_or(file);
        self.payloads.iter().any(|p| {
            let pb = p.file.rsplit(['/', '\\']).next().unwrap_or(&p.file);
            pb.eq_ignore_ascii_case(base) && p.sha256.trim().eq_ignore_ascii_case(sha256)
        })
    }
}

/// What a person declares a collector covered (the UI's coverage form), to
/// turn into a sidecar with [`Declaration::sidecar`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Declaration {
    /// Every enabled computer of these domains was attempted.
    pub all_in_domains: Vec<String>,
    /// Computers attempted (SIDs or host names).
    pub ok: Vec<String>,
    /// Computers attempted that failed.
    pub failed: Vec<String>,
    /// The collection run finished.
    pub complete: bool,
}

/// Most entries a declaration may list.
pub const MAX_DECLARED: usize = 100_000;

impl Declaration {
    /// The `pathwarden.coverage.v1` sidecar for the payload `file` of
    /// `source_kind` with this SHA-256, asserted by the user, as JSON text.
    /// It is checked with [`Sidecar::parse`] before it is returned.
    pub fn sidecar(
        &self,
        source_kind: &str,
        file: &str,
        sha256: &str,
        now: i64,
    ) -> Result<String, String> {
        fn clean(list: &[String], what: &str) -> Result<Vec<String>, String> {
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for raw in list {
                let s = raw.trim();
                if s.is_empty() {
                    continue;
                }
                if s.len() > 512 || s.chars().any(char::is_control) {
                    return Err(format!("{what}: '{s}' is not a host name or SID"));
                }
                if seen.insert(s.to_ascii_uppercase()) {
                    out.push(s.to_string());
                }
            }
            if out.len() > MAX_DECLARED {
                return Err(format!("{what}: more than {MAX_DECLARED} entries"));
            }
            Ok(out)
        }
        let domains = clean(&self.all_in_domains, "Domains")?;
        let ok = clean(&self.ok, "Computers covered")?;
        let failed = clean(&self.failed, "Computers that failed")?;
        if domains.is_empty() && ok.is_empty() {
            return Err(
                "Say what was scanned: every computer in a domain, or a list of computers.".into(),
            );
        }
        let base = file.rsplit(['/', '\\', '!']).next().unwrap_or(file);
        let sidecar = Sidecar {
            schema: SCHEMA.into(),
            source_kind: source_kind.into(),
            payloads: vec![Payload {
                file: base.into(),
                sha256: sha256.to_ascii_lowercase(),
            }],
            collected_at: Some(now),
            collector: Some(Collector {
                name: Some(source_kind.into()),
                version: None,
                via: Some("pathwarden-ui coverage form".into()),
            }),
            domains: domains.clone(),
            units: Units {
                kind: "computer".into(),
                ok,
                failed: failed
                    .into_iter()
                    .map(|id| Failed {
                        id,
                        reason: Some("declared failed".into()),
                    })
                    .collect(),
                all_in_domains: !domains.is_empty(),
            },
            complete: self.complete,
            asserted_by: Some("user".into()),
        };
        let text = serde_json::to_string_pretty(&sidecar).map_err(|e| e.to_string())?;
        Sidecar::parse(text.as_bytes())?;
        Ok(text)
    }
}

/// A source's coverage as recorded in the ingest statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageInfo {
    /// `none` (no sidecar), `sidecar`, or `invalid`.
    pub state: CoverageState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,
    /// Units covered, as object IDs where they resolve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ok: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    /// Every enabled computer in these domains was attempted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_in_domains: Vec<String>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<i64>,
    /// Why there is no usable coverage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    #[default]
    None,
    Sidecar,
    Invalid,
    /// The collector's own output says what it covered, without a sidecar:
    /// AzureHound lists each tenant it collected (`AZTenant` with
    /// `collected: true`). The units are tenant IDs; see `docs/entra.md`.
    Collector,
}

/// What one source covered in this run, by name-free keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceCoverage {
    pub name: String,
    /// A valid sidecar vouches for every file of the source.
    pub has_coverage: bool,
    /// The source was read whole (no cap hit, no error) and its sidecar
    /// says the collection completed.
    pub complete: bool,
    /// The files were read whole: no cap hit, no error.
    pub read_complete: bool,
    /// Unit keys ([`unit_key`]) covered and not failed.
    pub ok: HashSet<String>,
    /// For a SYSVOL part: how far it was read, and the edges it added.
    /// `None` for an OpenGraph source or another tool's report.
    pub sysvol: Option<SysvolPart>,
    /// For the stored credentials in a domain's services: how far the step
    /// read, and the edges it added. `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<HostsPart>,
    /// For the stored credentials in a domain's services: the computers
    /// with an edge, as [`host_unit_key`]s. The run records these, not the
    /// source, so a later run holds attack paths only when one of them
    /// wasn't read in full ([`RunSources::missing_since`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_units: Vec<String>,
}

/// What a run read of the stored credentials in one domain's services (a
/// source of [`RunSources`] whose units are its computers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostsPart {
    pub status: crate::sysvol::CheckStatus,
    /// `HasStoredCredential` edges it added.
    pub edges: usize,
    /// The reads were turned off for the collection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turned_off: bool,
}

/// What a run read of one SYSVOL part (a source of [`RunSources`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysvolPart {
    pub part: crate::sysvol::Part,
    pub status: crate::sysvol::CheckStatus,
    /// `WriteGPOFiles` or `WriteLogonScript` edges it added (always 0 for
    /// GPP passwords, which add none).
    pub edges: usize,
}

/// Every OpenGraph source of a run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunSources {
    /// By [`source_key`].
    pub sources: HashMap<String, SourceCoverage>,
    /// Reports from other tools (PingCastle), by [`source_key`]. They hold
    /// and resolve their own findings like a source, but are not recorded
    /// as the run's sources: a run without one never holds attack paths.
    pub external: HashMap<String, SourceCoverage>,
    /// Every SYSVOL part of every domain in the collection, by
    /// [`source_key`], with its name: to name a part the last run had when
    /// this run has no SYSVOL data for its domain at all.
    pub sysvol_parts: HashMap<String, (String, crate::sysvol::Part)>,
    /// The stored credentials source of every domain in the collection, by
    /// [`source_key`], with its name, as [`Self::sysvol_parts`].
    #[serde(default)]
    pub stored_parts: HashMap<String, String>,
    /// Every computer in the directory this run, as the [`host_unit_key`]
    /// of its domain's stored credentials source. A computer's unit that
    /// isn't here was deleted, so it no longer holds a credential. `None`
    /// when not worked out (read back from a file): every computer counts
    /// as present.
    #[serde(skip)]
    pub present_hosts: Option<HashSet<String>>,
    /// Of [`Self::present_hosts`], the units of the scheduled tasks
    /// sources, to name them apart from the services' in words.
    #[serde(skip)]
    pub task_hosts: HashSet<String>,
    /// The units of the computers whose session, local group right or
    /// stored credential leads to Tier Zero this run (the edge's far end
    /// reaches Tier Zero): [`super::hosts`] units and stored credential
    /// [`host_unit_key`]s. The run records them ([`Self::recorded`]), so a
    /// later run that doesn't read one again holds the findings that exist
    /// because an account reaches Tier Zero by any path.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub host_edges: BTreeSet<String>,
    /// What this run read of every computer in the directory, by
    /// [`super::hosts::host_hash`]: the bits of the session and local group
    /// lists read ([`crate::model::Props::host_lists`]). A computer that
    /// isn't here is gone: deleted, or stale (no logon within the stale
    /// window). Empty for a run saved before it was recorded: every
    /// computer then counts as read.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub host_reads: HashMap<String, u8>,
    /// Of [`Self::host_reads`], the lists the collection didn't ask for, by
    /// computer ([`crate::model::Props::host_lists_unasked`]); computers
    /// asked for every list aren't here. A unit of such a list is not
    /// targeted, not unread: it holds what rests on it with the
    /// not-targeted words, and isn't carried to the next run.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub host_unasked: HashMap<String, u8>,
    /// Of the last run's computers ([`Self::note_missing`]), those whose
    /// list this run didn't ask for.
    #[serde(skip)]
    pub unasked_hosts: HashSet<String>,
    /// Of the last run's computers ([`Self::note_missing`]), those this run
    /// didn't read again in full.
    #[serde(skip)]
    pub missing_hosts: HashSet<String>,
}

pub use super::hosts::ANY_HOST;

/// One stored credentials source of a sidecar, for
/// [`RunSources::add_hosts_source`].
struct HostsSource<'a> {
    name: String,
    status: crate::sysvol::CheckStatus,
    edges: usize,
    turned_off: bool,
    complete_ids: &'a [String],
    edge_host_ids: &'a [String],
    /// Every computer listed was read in full.
    all: bool,
}

impl RunSources {
    /// The sources of an analysis, with `all_in_domains` expanded to the
    /// enabled computers of those domains. Computers count as stale after
    /// the default window (90 days before the collection time);
    /// [`Self::from_analysis_at`] takes the settings'.
    pub fn from_analysis(g: &AdGraph, stats: &IngestStats) -> Self {
        let defaults = crate::findings::RuleSettings::default();
        Self::from_analysis_at(
            g,
            stats,
            stats.collected_at.map(|now| (now, defaults.stale_days)),
        )
    }

    /// [`Self::from_analysis`] with `stale_window` (the analysis time and the
    /// stale days, `None` for none): a computer with no logon within it is
    /// taken as gone.
    pub fn from_analysis_at(
        g: &AdGraph,
        stats: &IngestStats,
        stale_window: Option<(i64, i64)>,
    ) -> Self {
        let mut out = RunSources::default();
        for s in &stats.opengraph.sources {
            out.sources.insert(source_key(&s.name), coverage_of(g, s));
        }
        // Each part of a SYSVOL sidecar is a source: complete only when the
        // collector read all of it. A part that was not collected, or only
        // partly, holds the findings that rest on it ("can't tell").
        use crate::sysvol::{CheckStatus, Part};
        // The `ManagesHost` edges the registry policy and SCCM site parts
        // led to, by source name: added after the sidecars were read.
        let mut derived: HashMap<&str, usize> = HashMap::new();
        if !stats.sysvol.is_empty() && g.has_og_edges() {
            use petgraph::visit::EdgeRef;
            for e in g.inner().edge_references() {
                if *e.weight() == crate::model::EdgeKind::ManagesHost {
                    if let Some(name) = g.edge_source_name(e.id()) {
                        *derived.entry(name).or_default() += 1;
                    }
                }
            }
        }
        // The local rights linked GPOs grant, by domain: counted
        // only where a sidecar recorded the local groups part, as its
        // findings cite it only there.
        let mut gpo_local: HashMap<String, usize> = HashMap::new();
        if stats
            .sysvol
            .iter()
            .any(|s| s.checks.gpo_local_groups.is_some())
        {
            for d in g.gpo_grant_domains() {
                *gpo_local.entry(d).or_default() += 1;
            }
        }
        for s in &stats.sysvol {
            for part in Part::ALL {
                let name = part.source(&s.domain);
                let key = source_key(&name);
                let mut status = part.of(&s.checks).status;
                let mut edges = match part {
                    Part::GpoAcl => s.gpo_edges,
                    Part::LogonScriptAcl => s.script_edges,
                    Part::Gpp => 0,
                    Part::RegistryPol | Part::SccmSites | Part::GpoLocalGroups => 0,
                };
                let whole = derived.get(name.as_str()).copied().unwrap_or(0);
                // Two sidecars for one domain: complete only if both are,
                // not collected only if neither was.
                if let Some(p) = out.sources.get(&key).and_then(|c| c.sysvol) {
                    edges += p.edges;
                    if p.status != status {
                        status = CheckStatus::Partial;
                    }
                }
                // Counted over the graph, once per domain.
                if matches!(part, Part::RegistryPol | Part::SccmSites) {
                    edges = whole;
                }
                if part == Part::GpoLocalGroups {
                    edges = if s.checks.gpo_local_groups.is_some() {
                        gpo_local
                            .get(&s.domain.trim().to_ascii_uppercase())
                            .copied()
                            .unwrap_or(0)
                    } else {
                        edges
                    };
                }
                let done = status == CheckStatus::Complete;
                out.sources.insert(
                    key,
                    SourceCoverage {
                        name,
                        has_coverage: true,
                        complete: done,
                        read_complete: done,
                        ok: HashSet::new(),
                        sysvol: Some(SysvolPart {
                            part,
                            status,
                            edges,
                        }),
                        hosts: None,
                        edge_units: Vec::new(),
                    },
                );
            }
        }
        // The stored credentials in each domain's services, and in its
        // scheduled tasks: two sources whose units are the computers read
        // in full. One read only partly, or not reached, holds the findings
        // that rest on it; the step having run is what makes the source
        // there.
        for s in &stats.stored_credentials {
            out.add_hosts_source(HostsSource {
                name: crate::storedcreds::source(&s.domain),
                status: s.services.status,
                edges: s.edges,
                turned_off: s.turned_off,
                complete_ids: &s.complete_ids,
                edge_host_ids: &s.edge_host_ids,
                all: s.hosts_complete == s.hosts,
            });
            if let Some(t) = &s.tasks {
                out.add_hosts_source(HostsSource {
                    name: crate::storedcreds::task_source(&s.domain),
                    status: t.tasks.status,
                    edges: t.edges,
                    turned_off: t.turned_off,
                    complete_ids: &t.complete_ids,
                    edge_host_ids: &t.edge_host_ids,
                    all: t.hosts_complete == t.hosts,
                });
            }
        }
        for d in crate::analyze::known_domain_names(g)
            .iter()
            .chain(stats.sysvol.iter().map(|s| &s.domain))
        {
            for part in Part::ALL {
                let name = part.source(d);
                out.sysvol_parts.insert(source_key(&name), (name, part));
            }
        }
        for d in crate::analyze::known_domain_names(g)
            .iter()
            .chain(stats.stored_credentials.iter().map(|s| &s.domain))
        {
            for name in [
                crate::storedcreds::source(d),
                crate::storedcreds::task_source(d),
            ] {
                out.stored_parts.insert(source_key(&name), name);
            }
        }
        // A computer disabled, or not active within the stale window
        // (never logged on included), counts as gone: switched off for good
        // or pre-staged, it doesn't hold findings forever
        // ([`crate::analysis::computer_gone`]).
        let gone = stale_window.map(|(now, days)| crate::analysis::computer_gone(g, now, days));
        let stale = |ix: petgraph::graph::NodeIndex| match &gone {
            Some(v) => v[ix.index()],
            None => !g.node(ix).is_enabled(),
        };
        let mut present = HashSet::new();
        for (ix, n) in g.nodes() {
            if n.kind != NodeKind::Computer || n.placeholder || stale(ix) {
                continue;
            }
            if let Some(d) = &n.domain {
                present.insert(host_unit_key(&crate::storedcreds::source(d), &n.id));
                let task = host_unit_key(&crate::storedcreds::task_source(d), &n.id);
                out.task_hosts.insert(task.clone());
                present.insert(task);
            }
            // Sessions and local groups: the lists read. A domain
            // controller's local groups are the domain's, always read.
            let mut bits = n.props.host_lists;
            let mut unasked = n.props.host_lists_unasked;
            if !crate::posture::local_groups_on_host(g, ix) {
                bits |= super::hosts::GROUP_BITS;
                unasked &= !super::hosts::GROUP_BITS;
            }
            let h = super::hosts::host_hash(&n.id);
            if unasked != 0 {
                out.host_unasked.insert(h.clone(), unasked);
            }
            out.host_reads.insert(h, bits);
        }
        out.present_hosts = Some(present);
        // The computers whose edge leads to Tier Zero: a session whose
        // account reaches it, a local group right on a computer that does,
        // a stored credential of an account that does. Each computer's
        // hash is worked out once.
        let tree = crate::analysis::reach_targets(g, crate::analysis::tier_zero(g), None);
        let mut hashes: HashMap<petgraph::graph::NodeIndex, String> = HashMap::new();
        for e in g.inner().edge_indices() {
            let Some((_, to)) = g.inner().edge_endpoints(e) else {
                continue;
            };
            if !tree.reaches(to) {
                continue;
            }
            if g.inner()[e] == crate::model::EdgeKind::HasStoredCredential {
                for (source, u) in crate::storedcreds::edge_units(g, e) {
                    out.host_edges.insert(host_unit_key(&source, &u));
                }
            } else if let Some((ix, mark)) = super::hosts::edge_host(g, e) {
                let h = hashes
                    .entry(ix)
                    .or_insert_with(|| super::hosts::host_hash(&g.node(ix).id));
                out.host_edges.extend(super::hosts::units_of_hash(
                    h,
                    mark,
                    g.node(ix).props.host_lists,
                ));
            }
        }
        // Each Tier Zero host's probe: read only from a current,
        // trusted file that read every part. Like a report from another
        // tool, it holds and resolves its own findings only: a run without
        // one never holds attack paths for it.
        for (name, read) in crate::hostprobe::coverage(g) {
            out.external.insert(
                source_key(&name),
                SourceCoverage {
                    name,
                    has_coverage: true,
                    complete: read,
                    read_complete: read,
                    ok: HashSet::new(),
                    sysvol: None,
                    hosts: None,
                    edge_units: Vec::new(),
                },
            );
        }
        if !stats.pingcastle.is_empty() {
            let name = crate::pingcastle::SOURCE;
            out.external.insert(
                source_key(name),
                SourceCoverage {
                    name: name.to_string(),
                    has_coverage: true,
                    complete: true,
                    read_complete: true,
                    // A health check covers its whole domain.
                    ok: stats
                        .pingcastle
                        .iter()
                        .map(|r| unit_key(name, &r.domain))
                        .collect(),
                    sysvol: None,
                    hosts: None,
                    edge_units: Vec::new(),
                },
            );
        }
        out
    }

    /// Adds one sidecar's services or scheduled tasks source; two
    /// sidecars for one domain make one source.
    fn add_hosts_source(&mut self, s: HostsSource<'_>) {
        use crate::sysvol::CheckStatus;
        let HostsSource {
            name,
            mut status,
            mut edges,
            mut turned_off,
            complete_ids,
            edge_host_ids,
            all,
        } = s;
        let key = source_key(&name);
        let mut ok: HashSet<String> = complete_ids
            .iter()
            .map(|id| host_unit_key(&name, id))
            .collect();
        let mut edge_units: Vec<String> = edge_host_ids
            .iter()
            .map(|id| host_unit_key(&name, id))
            .collect();
        let mut all = all && status == CheckStatus::Complete;
        if let Some(c) = self.sources.get(&key) {
            if let Some(p) = c.hosts {
                edges += p.edges;
                turned_off &= p.turned_off;
                if p.status != status {
                    status = CheckStatus::Partial;
                }
            }
            all &= c.ok.contains(&unit_key(&name, ALL_UNITS));
            ok.extend(c.ok.iter().cloned());
            for u in &c.edge_units {
                if !edge_units.contains(u) {
                    edge_units.push(u.clone());
                }
            }
        }
        if all {
            ok.insert(unit_key(&name, ALL_UNITS));
        } else {
            ok.remove(&unit_key(&name, ALL_UNITS));
        }
        let ran = status != CheckStatus::NotCollected;
        self.sources.insert(
            key,
            SourceCoverage {
                name,
                has_coverage: true,
                complete: ran,
                read_complete: ran,
                ok,
                sysvol: None,
                hosts: Some(HostsPart {
                    status,
                    edges,
                    turned_off,
                }),
                edge_units,
            },
        );
    }

    /// Keys of the sources this run had data from, sorted (for
    /// `last-run.json`): every OpenGraph source, and each SYSVOL part that
    /// added at least one edge. A part that was not collected, or was read
    /// and gave no edge, can't have carried an attack path, so a later run
    /// without it has no reason to hold attack-path findings
    /// ([`Self::missing_since`]). GPP passwords add no edges: their findings
    /// are held through their own `sources`.
    pub fn keys(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self
            .sources
            .iter()
            .filter(|(_, c)| c.sysvol.is_none_or(|p| p.edges > 0) && c.hosts.is_none())
            .map(|(k, _)| k)
            .collect();
        set.into_iter().cloned().collect()
    }

    /// The computers whose edge led to Tier Zero this run, sorted:
    /// [`Self::host_edges`].
    pub fn host_keys(&self) -> Vec<String> {
        self.host_edges.iter().cloned().collect()
    }

    /// [`Self::keys`] and [`Self::host_keys`]: everything a later run
    /// compares with.
    pub fn all_keys(&self) -> Vec<String> {
        let mut v = self.keys();
        v.extend(self.host_keys());
        v
    }

    /// What a run records for the next one to compare with: `sources` and
    /// `hosts`, as `last-run.json` has them. A computer the baseline
    /// (`previous`, as [`Self::missing_hosts_since`] takes it) had and this
    /// run didn't read again is kept, edge or not, so a run after this one
    /// still holds what may rest on it. It drops off once its lists are
    /// read again, or it is deleted from the directory or stale. `seed`
    /// (the first run after a version that didn't record computers) adds
    /// every computer read in neither kind ([`super::hosts::SEEDED`]).
    pub fn recorded(&self, previous: &[String], seed: bool) -> (Vec<String>, Vec<String>) {
        use super::hosts::{any_unit, SEEDED};
        let mut hosts: BTreeSet<String> = self.host_edges.clone();
        hosts.extend(self.missing_hosts_since(previous).into_iter().cloned());
        if seed {
            for h in self.host_reads.keys() {
                for mark in [SESSION_HOST, LOCAL_GROUP_HOST] {
                    if self.kind_unread(h, mark) {
                        hosts.insert(any_unit(h, mark, SEEDED));
                    }
                }
            }
        }
        (self.keys(), hosts.into_iter().collect())
    }

    /// Notes which of `previous` (the baseline's sources and hosts) are
    /// computers this run didn't read again in full
    /// ([`Self::missing_hosts`]), and which it didn't ask for
    /// ([`Self::unasked_hosts`]).
    pub fn note_missing(&mut self, previous: &[String]) {
        self.missing_hosts = self
            .missing_hosts_since(previous)
            .into_iter()
            .cloned()
            .collect();
        self.unasked_hosts = previous
            .iter()
            .filter(|k| self.not_asked(k))
            .cloned()
            .collect();
    }

    /// Whether `u`, a host unit a finding rests on, is still not read this
    /// run: its computer present and its list unread (asked for or not),
    /// or for an [`ANY_HOST`] unit, any computer of its kind the last run
    /// had and this one didn't read again.
    ///
    /// An [`ANY_HOST`] unit relies on the last run having recorded the
    /// computers it stands for: those whose edge led to Tier Zero, and on
    /// an upgrade every unread one ([`super::hosts::SEEDED`]). A computer
    /// of a capped finding that neither lists is not waited for; the cap
    /// (256 computers of a kind) makes that a finding about very many
    /// computers, most of which hold it anyway.
    pub fn still_unread(&self, u: &str) -> bool {
        match u.strip_suffix(ANY_HOST) {
            Some(mark) if mark == SESSION_HOST || mark == LOCAL_GROUP_HOST => {
                self.missing_hosts.iter().any(|k| k.starts_with(mark))
            }
            _ => is_host_key(u) && !self.host_read_or_gone(u),
        }
    }

    /// Whether computer `h` (a [`super::hosts::host_hash`]) had none of
    /// `mark`'s lists read this run, though some were asked for.
    fn kind_unread(&self, h: &str, mark: &str) -> bool {
        let kind = super::hosts::kind_bits(mark);
        let read = self.host_reads.get(h).copied().unwrap_or(kind);
        let unasked = self.host_unasked.get(h).copied().unwrap_or(0);
        read & kind == 0 && unasked & kind != kind
    }

    /// Whether any computer in the directory had none of `mark`'s lists
    /// read this run, though some were asked for.
    pub fn any_unread(&self, mark: &str) -> bool {
        self.host_reads.keys().any(|h| self.kind_unread(h, mark))
    }

    /// Whether `u`, a session or local group unit, is of a list this run
    /// didn't ask its computer for (its computer present, the list not
    /// read): not targeted. An any-list unit is when every list of its kind
    /// wasn't asked for.
    pub fn not_asked(&self, u: &str) -> bool {
        let Some((mark, h, c)) = super::hosts::parse(u) else {
            return false;
        };
        let bit = super::hosts::list_bit(mark, c);
        self.host_reads.get(h).is_some_and(|read| read & bit == 0)
            && self
                .host_unasked
                .get(h)
                .is_some_and(|unasked| unasked & bit == bit)
    }

    /// Of [`Self::missing_hosts`] and [`Self::unasked_hosts`], those the
    /// reach findings wait for: not [`super::hosts::SEEDED`] ones.
    pub fn missing_reach_hosts(&self) -> bool {
        self.reach_keys().next().is_some()
    }

    /// The units [`Self::missing_reach_hosts`] looks at.
    pub fn reach_keys(&self) -> impl Iterator<Item = &String> {
        self.missing_hosts
            .iter()
            .chain(&self.unasked_hosts)
            .filter(|k| super::hosts::parse(k).is_none_or(|(_, _, c)| c != super::hosts::SEEDED))
    }

    /// The sources a baseline had data from, as [`Self::keys`] lists them
    /// today, from what it recorded. `legacy_cited` is `Some` for a list
    /// written before that (`LastRun::sources_exact` unset), which named
    /// every SYSVOL part of every sidecar whether it was read or not; it
    /// holds the source keys the baseline's findings cite. From such a list
    /// this drops GPP password parts (never an edge), and parts this run
    /// reports as not collected that no baseline finding cites: the usual
    /// cause is the same collection method both times (a password
    /// collection can't read SYSVOL permissions), and a part whose edges
    /// were on a finding's path is cited by that finding. A part this run
    /// has no SYSVOL data for at all, or read only partly, is kept.
    pub fn baseline_keys(
        &self,
        recorded: &[String],
        legacy_cited: Option<&HashSet<String>>,
    ) -> Vec<String> {
        use crate::sysvol::{CheckStatus, Part};
        let Some(cited) = legacy_cited else {
            return recorded.to_vec();
        };
        recorded
            .iter()
            .filter(|k| {
                if matches!(self.sysvol_parts.get(*k), Some((_, Part::Gpp))) {
                    return false;
                }
                let not_collected = self
                    .sources
                    .get(*k)
                    .and_then(|c| c.sysvol)
                    .is_some_and(|p| p.status == CheckStatus::NotCollected);
                !not_collected || cited.contains(*k)
            })
            .cloned()
            .collect()
    }

    /// The sources `keys` names (from [`Self::missing_since`]), in words:
    /// "SYSVOL GPO permissions (CONTOSO.LOCAL): not collected", "OpenGraph
    /// source TaskHound: read only partly".
    pub fn describe(&self, keys: &[String]) -> String {
        let mut named: Vec<String> = Vec::new();
        let mut unnamed = 0usize;
        let (tasks, services): (Vec<&String>, Vec<&String>) = keys
            .iter()
            .filter(|k| k.starts_with(HOST_UNIT))
            .partition(|k| self.task_hosts.contains(*k));
        if !services.is_empty() {
            named.push(format!(
                "services not read in full on {} that stored a credential when last read",
                crate::text::count(services.len(), "computer", "computers")
            ));
        }
        if !tasks.is_empty() {
            named.push(format!(
                "scheduled tasks not read in full on {} that stored a credential when last read",
                crate::text::count(tasks.len(), "computer", "computers")
            ));
        }
        let sessions = super::hosts::computers(keys.iter().filter(|k| k.starts_with(SESSION_HOST)));
        if sessions > 0 {
            named.push(format!(
                "sessions not read on {} that had one when last read",
                crate::text::count(sessions, "computer", "computers")
            ));
        }
        let groups =
            super::hosts::computers(keys.iter().filter(|k| k.starts_with(LOCAL_GROUP_HOST)));
        if groups > 0 {
            named.push(format!(
                "local groups not read on {} that granted a right when last read",
                crate::text::count(groups, "computer", "computers")
            ));
        }
        for k in keys.iter().filter(|k| !is_host_key(k)) {
            match (self.sources.get(k), self.sysvol_parts.get(k)) {
                (Some(c), _) => named.push(match (c.sysvol, c.hosts) {
                    (Some(p), _) => format!("{}: {}", c.name, p.status.label()),
                    (None, Some(p)) => format!("{}: {}", c.name, p.status.label()),
                    (None, None) => format!("OpenGraph source {}: read only partly", c.name),
                }),
                (None, Some((name, _))) => {
                    named.push(format!("{name}: no SYSVOL data in this collection"))
                }
                (None, None) => match self.stored_parts.get(k) {
                    Some(name) => named.push(format!(
                        "{name}: not read in this collection (a Full collection reads them)"
                    )),
                    None => unnamed += 1,
                },
            }
        }
        if unnamed > 0 {
            named.push(format!(
                "{unnamed} OpenGraph or SYSVOL source(s) not in this collection at all"
            ));
        }
        named.join("; ")
    }

    /// The computers of `keys` (from [`Self::missing_hosts`]) in sentences
    /// for the run's warning: "Sessions weren't read on 1 computer that had
    /// one. Findings that rest on it aren't marked fixed." `None` when there
    /// are none. Computers recorded on an upgrade
    /// ([`super::hosts::SEEDED`]) had nothing known, so they aren't named.
    pub fn unread_sentences(&self, keys: &[String]) -> Option<String> {
        use super::hosts::{computers, parse, SEEDED};
        let shown: Vec<&String> = keys
            .iter()
            .filter(|k| parse(k).is_none_or(|(_, _, c)| c != SEEDED))
            .collect();
        let of = |mark: &str| computers(shown.iter().copied().filter(|k| k.starts_with(mark)));
        let n = |c| crate::text::count(c, "computer", "computers");
        let mut out: Vec<String> = Vec::new();
        let (s, l) = (of(SESSION_HOST), of(LOCAL_GROUP_HOST));
        if s > 0 {
            out.push(format!("Sessions weren't read on {} that had one.", n(s)));
        }
        if l > 0 {
            out.push(format!(
                "Local groups weren't read on {} that granted a right.",
                n(l)
            ));
        }
        let stored: Vec<String> = shown
            .iter()
            .filter(|k| k.starts_with(HOST_UNIT))
            .map(|k| k.to_string())
            .collect();
        let h = stored.len();
        if h > 0 {
            let words = self.describe(&stored);
            let mut c = words.chars();
            if let Some(f) = c.next() {
                out.push(format!("{}{}.", f.to_uppercase(), c.as_str()));
            }
        }
        if out.is_empty() {
            return None;
        }
        let them = if s + l + h == 1 { "it" } else { "them" };
        out.push(format!("Findings that rest on {them} aren't marked fixed."));
        Some(out.join(" "))
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Why a finding that depends on `sources` and `requires` (keys) can't
    /// be resolved this run, or `None` when it can.
    pub fn hold_reason(&self, sources: &[String], requires: &[String]) -> Option<String> {
        for s in sources {
            match self.sources.get(s).or_else(|| self.external.get(s)) {
                None if *s == source_key(crate::pingcastle::SOURCE) => {
                    return Some("no PingCastle report was read this run".into())
                }
                None => {
                    if let Some(name) = self.stored_parts.get(s) {
                        return Some(format!(
                            "{name} were not read in this collection (a Full collection reads them)"
                        ));
                    }
                    return Some(
                        "its data source (OpenGraph or SYSVOL) is not in this collection".into(),
                    );
                }
                Some(c) if !c.has_coverage => {
                    return Some(format!(
                        "{} data has no coverage file, so its absence proves nothing",
                        c.name
                    ))
                }
                Some(c) if !c.complete && crate::hostprobe::is_source(&c.name) => {
                    return Some(format!(
                        "{}: no current Tier Zero settings file from that computer read every \
                         management agent this run (none, one over {} days old, or one from a \
                         settings folder nobody vouches for)",
                        c.name,
                        crate::dcsettings::STALE_DAYS
                    ))
                }
                Some(c) if !c.complete => {
                    if let Some(p) = c.hosts {
                        return Some(if p.turned_off {
                            format!("{} were turned off for this collection", c.name)
                        } else {
                            format!("{} were not read in this collection", c.name)
                        });
                    }
                    return Some(match c.sysvol {
                        Some(p) => format!(
                            "{} {} in this collection",
                            c.name,
                            match p.status {
                                crate::sysvol::CheckStatus::NotCollected => "was not collected",
                                _ => "was read only partly",
                            }
                        ),
                        None => format!("{} data is incomplete in this collection", c.name),
                    });
                }
                _ => {}
            }
        }
        for u in requires {
            if u.starts_with(SESSION_HOST) || u.starts_with(LOCAL_GROUP_HOST) {
                continue;
            }
            if u.starts_with(HOST_UNIT) && self.host_read_or_gone(u) {
                continue;
            }
            if !self
                .sources
                .values()
                .chain(self.external.values())
                .any(|c| c.ok.contains(u))
            {
                if sources
                    .iter()
                    .any(|s| *s == source_key(crate::pingcastle::SOURCE))
                {
                    return Some("no PingCastle report for its domain was read this run".into());
                }
                return Some(
                    "its source did not report covering the affected host this run".into(),
                );
            }
        }
        let computers = |n| crate::text::count(n, "computer", "computers");
        match self.unread_hosts(requires) {
            // Only lists this run didn't ask for: not targeted.
            (0, 0) => {
                let unasked = |mark: &str| {
                    requires
                        .iter()
                        .any(|u| u.starts_with(mark) && self.not_asked(u))
                };
                crate::posture::Untargeted {
                    sessions: unasked(SESSION_HOST),
                    local_groups: unasked(LOCAL_GROUP_HOST),
                }
                .words()
                .map(|w| {
                    format!(
                        "{w} weren't collected in this run, and the finding may depend on them"
                    )
                })
            }
            (s, 0) => Some(format!(
                "Sessions weren't read on {} this finding rests on, so it can't be confirmed fixed.",
                computers(s)
            )),
            (0, l) => Some(format!(
                "Local groups weren't read on {} this finding rests on, so it can't be confirmed fixed.",
                computers(l)
            )),
            (s, l) => Some(format!(
                "Sessions weren't read on {} and local groups on {} this finding rests on, so it can't be confirmed fixed.",
                computers(s),
                computers(l)
            )),
        }
    }

    /// Source keys from `previous` (the sources the baseline had data from,
    /// [`Self::baseline_keys`]) that are absent now, or were not read whole.
    /// Attack-path findings are held while any is: a path may have run
    /// through that source's edges without its sample path showing it. A
    /// source the baseline never had data from is not in `previous`, so it
    /// holds nothing here, collected now or not.
    ///
    /// Computers' units (stored credentials, sessions, local groups) are
    /// not sources: they are in [`Self::missing_hosts_since`].
    pub fn missing_since<'a>(&self, previous: &'a [String]) -> Vec<&'a String> {
        previous
            .iter()
            .filter(|k| !is_host_key(k) && !self.sources.get(*k).is_some_and(|c| c.read_complete))
            .collect()
    }

    /// The computers in `previous` (the baseline's sources and hosts) that
    /// had an edge then and weren't read again in full this run: a
    /// session's computer whose sessions weren't read, a member computer
    /// whose local groups weren't, one that stored a credential and whose
    /// services or tasks weren't. Findings that rest on one are held by
    /// their own `requires` ([`Self::hold_reason`]); those that exist
    /// because an account reaches Tier Zero by any path
    /// ([`crate::posture::REACH_RULES`]) are held while any is, since such a
    /// path may have run through it without the sample path showing it.
    pub fn missing_hosts_since<'a>(&self, previous: &'a [String]) -> Vec<&'a String> {
        let mut seen = HashSet::new();
        previous
            .iter()
            .filter(|k| {
                is_host_key(k)
                    && !self.host_read_or_gone(k)
                    && !self.not_asked(k)
                    && seen.insert(k.as_str())
            })
            .collect()
    }

    /// Whether a computer's unit ([`host_unit_key`], or a session or local
    /// group unit of [`super::hosts`]) was read again this run, or the
    /// computer is gone from the directory (deleted or stale, so it no
    /// longer holds a credential, a session or a right). A session or local
    /// group unit's list must be read again; an any-list unit's, any list
    /// of its kind. A run that recorded no reads (saved before they were)
    /// reads them all.
    pub fn host_read_or_gone(&self, u: &str) -> bool {
        if let Some((mark, h, c)) = super::hosts::parse(u) {
            if self.host_reads.is_empty() {
                return true;
            }
            return match self.host_reads.get(h) {
                None => true,
                Some(bits) => bits & super::hosts::list_bit(mark, c) != 0,
            };
        }
        self.sources.values().any(|c| c.ok.contains(u))
            || self.present_hosts.as_ref().is_some_and(|p| !p.contains(u))
    }

    /// Of `units` (a finding's `requires`), the session and local group
    /// computers not read again this run, as counts. An [`ANY_HOST`] unit
    /// counts the computers of its kind the last run had and this one
    /// didn't read ([`Self::missing_hosts`]).
    fn unread_hosts(&self, units: &[String]) -> (usize, usize) {
        let count = |mark: &str| {
            let any = format!("{mark}{ANY_HOST}");
            if units.contains(&any) {
                return super::hosts::computers(
                    self.missing_hosts.iter().filter(|u| u.starts_with(mark)),
                );
            }
            super::hosts::computers(units.iter().filter(|u| {
                u.starts_with(mark) && !self.host_read_or_gone(u) && !self.not_asked(u)
            }))
        };
        (count(SESSION_HOST), count(LOCAL_GROUP_HOST))
    }
}

fn coverage_of(g: &AdGraph, s: &OgSourceStats) -> SourceCoverage {
    let c = &s.coverage;
    let has_coverage = matches!(c.state, CoverageState::Sidecar | CoverageState::Collector);
    let mut ok: HashSet<String> = HashSet::new();
    let failed: HashSet<&str> = c.failed.iter().map(String::as_str).collect();
    if has_coverage {
        for u in &c.ok {
            if !failed.contains(u.as_str()) {
                ok.insert(unit_key(&s.name, u));
            }
        }
        if !c.all_in_domains.is_empty() && c.failed.is_empty() {
            ok.insert(unit_key(&s.name, ALL_UNITS));
        }
        if !c.all_in_domains.is_empty() {
            let domains: HashSet<String> = c
                .all_in_domains
                .iter()
                .map(|d| d.to_ascii_uppercase())
                .collect();
            for (_, n) in g.nodes() {
                let in_domain = n
                    .domain
                    .as_ref()
                    .is_some_and(|d| domains.contains(&d.to_ascii_uppercase()));
                if n.kind == NodeKind::Computer
                    && !n.placeholder
                    && n.is_enabled()
                    && in_domain
                    && !failed.contains(n.id.as_str())
                {
                    ok.insert(unit_key(&s.name, &n.id));
                }
            }
        }
    }
    SourceCoverage {
        name: s.name.clone(),
        has_coverage,
        complete: has_coverage && c.complete && s.complete,
        read_complete: s.complete,
        ok,
        sysvol: None,
        hosts: None,
        edge_units: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_names() {
        assert!(is_sidecar_name("C:\\x\\taskhound.coverage.json"));
        assert!(is_sidecar_name("a.zip!pathwarden-coverage.json"));
        assert!(!is_sidecar_name("taskhound.json"));
    }

    #[test]
    fn parses_and_binds() {
        let text = br#"{"schema":"pathwarden.coverage.v1","source_kind":"TaskHound",
            "payloads":[{"file":"th.json","sha256":"ABCD"}],
            "units":{"type":"computer","ok":["S-1-5-21-1-2-3-1104"]},"complete":true}"#;
        let s = Sidecar::parse(text).unwrap();
        assert!(s.binds("dir/TH.json", "abcd"));
        assert!(!s.binds("th.json", "abce"));
        assert!(!s.binds("other.json", "abcd"));
        assert!(Sidecar::parse(br#"{"schema":"x"}"#).is_err());
        let wrong = String::from_utf8_lossy(text).replace("coverage.v1", "coverage.v9");
        assert!(Sidecar::parse(wrong.as_bytes()).is_err());
    }

    use super::super::hosts::{self, units, GROUP_BITS, SESSION_BITS};

    /// The session list unit of `id` (sessions, read).
    fn s(id: &str) -> String {
        units(id, SESSION_HOST, 1).remove(0)
    }

    /// A run that read `reads` (computer ID, list bits) in the directory,
    /// whose `edges` (IDs) had a session leading to Tier Zero, and whose
    /// `present` computers (IDs) a stored credentials source knows.
    fn hosts_run(reads: &[(&str, u8)], edges: &[&str], present: &[&str]) -> RunSources {
        let source = crate::storedcreds::source("CORP.LOCAL");
        RunSources {
            host_reads: reads
                .iter()
                .map(|(id, bits)| (hosts::host_hash(id), *bits))
                .collect(),
            host_edges: edges.iter().map(|id| s(id)).collect(),
            present_hosts: Some(
                present
                    .iter()
                    .map(|id| host_unit_key(&source, id))
                    .collect(),
            ),
            ..RunSources::default()
        }
    }

    const ALL: u8 = SESSION_BITS | GROUP_BITS;

    /// A computer that had a session is kept while it isn't read, edge or
    /// not, and drops off once it is read or gone; one that never had an
    /// edge is never recorded.
    #[test]
    fn unread_computers_are_carried_forward() {
        let (h, other) = ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002");
        let stored = host_unit_key(&crate::storedcreds::source("CORP.LOCAL"), h);
        // Run 1 read H, which had a session; OTHER was never read.
        let (_, hosts1) = hosts_run(&[(h, ALL), (other, 0)], &[h], &[h]).recorded(&[], false);
        assert_eq!(hosts1, [s(h)]);
        let mut prev = hosts1;
        prev.push(stored.clone());
        // Runs 2 and 3: H not read (no session seen): kept, and so is the
        // stored credential unit no source read.
        let unread = hosts_run(&[(h, 0), (other, 0)], &[], &[h]);
        assert_eq!(unread.missing_hosts_since(&prev).len(), 2);
        assert!(
            unread.missing_since(&prev).is_empty(),
            "computers aren't sources"
        );
        let (sources2, hosts2) = unread.recorded(&prev, false);
        assert!(sources2.is_empty());
        let mut want = vec![s(h), stored.clone()];
        want.sort();
        assert_eq!(hosts2, want);
        let (_, hosts3) = unread.recorded(&hosts2, false);
        assert_eq!(hosts3, want);
        // H's sessions read, none there: dropped (its stored credential
        // unit, which no source read, stays).
        let read = hosts_run(&[(h, ALL), (other, 0)], &[], &[h]);
        assert_eq!(read.missing_hosts_since(&hosts3), [&stored]);
        assert_eq!(read.recorded(&hosts3, false).1, vec![stored.clone()]);
        // H deleted from the directory: both dropped.
        let gone = hosts_run(&[(other, 0)], &[], &[]);
        assert!(gone.missing_hosts_since(&hosts3).is_empty());
        assert_eq!(gone.recorded(&hosts3, false), (Vec::new(), Vec::new()));
        // The first run after an upgrade records the unread computers,
        // marked as seeded: not named in the warning.
        let (_, seeded) = gone.recorded(&[], true);
        assert_eq!(seeded.len(), 2, "OTHER's sessions and local groups");
        assert!(seeded.iter().all(|k| k.ends_with(hosts::SEEDED)));
        assert_eq!(unread.unread_sentences(&seeded), None);
        let mut lg = units(h, LOCAL_GROUP_HOST, 8);
        lg.push(s(h));
        assert_eq!(
            unread.unread_sentences(&lg).as_deref(),
            Some(
                "Sessions weren't read on 1 computer that had one. Local groups weren't \
                 read on 1 computer that granted a right. Findings that rest on them \
                 aren't marked fixed."
            )
        );
        assert_eq!(
            unread.describe(&lg),
            "sessions not read on 1 computer that had one when last read; \
             local groups not read on 1 computer that granted a right when last read"
        );
    }

    /// Read in full means every list read before: a privileged sessions
    /// list that fails alone holds what it showed.
    #[test]
    fn every_list_read_before_must_be_read_again() {
        let h = "S-1-5-21-1-2-3-1001";
        let before = units(h, SESSION_HOST, 1 | 2);
        assert_eq!(before.len(), 2);
        let sessions_only = hosts_run(&[(h, 1 | GROUP_BITS)], &[], &[]);
        assert_eq!(
            sessions_only.missing_hosts_since(&before).len(),
            1,
            "privileged sessions not read"
        );
        assert!(sessions_only
            .hold_reason(&[], &before)
            .is_some_and(|w| w.starts_with("Sessions weren't read on 1 computer")));
        let both = hosts_run(&[(h, 1 | 2)], &[], &[]);
        assert!(both.missing_hosts_since(&before).is_empty());
    }

    /// A finding's own computers hold it, in words; read, they don't.
    #[test]
    fn a_findings_unread_computers_hold_it() {
        let h = "S-1-5-21-1-2-3-1001";
        let requires = [s(h)];
        assert_eq!(
            hosts_run(&[(h, 0)], &[], &[])
                .hold_reason(&[], &requires)
                .as_deref(),
            Some(
                "Sessions weren't read on 1 computer this finding rests on, \
                 so it can't be confirmed fixed."
            )
        );
        assert_eq!(
            hosts_run(&[(h, ALL)], &[], &[]).hold_reason(&[], &requires),
            None
        );
        let mut both = units(h, LOCAL_GROUP_HOST, 8);
        both.push(s(h));
        assert_eq!(
            hosts_run(&[(h, 0)], &[], &[])
                .hold_reason(&[], &both)
                .as_deref(),
            Some(
                "Sessions weren't read on 1 computer and local groups on 1 computer \
                 this finding rests on, so it can't be confirmed fixed."
            )
        );
        // More computers than it lists: held by the computers of the kind
        // the last run had and this one didn't read, not by every one
        // never read.
        let any = [format!("{SESSION_HOST}{ANY_HOST}")];
        let mut down = hosts_run(&[(h, 0), ("S-1-5-21-1-2-3-9", 0)], &[], &[]);
        assert!(down.hold_reason(&[], &any).is_none(), "no edge last run");
        down.note_missing(&[s(h)]);
        assert_eq!(
            down.hold_reason(&[], &any).as_deref(),
            Some(
                "Sessions weren't read on 1 computer this finding rests on, \
                 so it can't be confirmed fixed."
            )
        );
        assert!(down.still_unread(&any[0]));
    }
}
