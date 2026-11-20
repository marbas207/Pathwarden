//! Full runs in the history: with "Full runs and settings"
//! (`[state] keep = "full"`), every recorded run also goes into the history
//! in full, so a machine that reads the history can open it as the
//! recording machine does (report, Explore, findings, retest).
//!
//! A full run is a folder next to its point, `runs/<history run ID>/`, with
//! the files of [`store::BUNDLE_FILES`] only:
//!
//! - `run.json`: the [`Manifest`]: who recorded it (user and computer, and
//!   whether from the app, a schedule or the command line), with which
//!   Pathwarden, each file's size and SHA-256, and the files left out;
//! - `summary.json`: the run's summary, without anything of this computer's
//!   (folders, the environment's local ID, where a collection was kept);
//! - `report.html.gz`, `graph.bin.gz`, `objects.json.gz`, `event.json.gz`,
//!   `retest.json.gz`, `opengraph.json`: as in the run's folder
//!   ([`crate::run_data`]);
//! - `settings.toml`: the shared sections of `pathwarden.toml` the run was
//!   analysed with (never `[state]`, plugins, paths or pack trust).
//!
//! It goes in a commit of its own, right after the point's, under the
//! history's lock: a point is never held back by its full run (too big,
//! refused). Every file goes through the history's seam
//! ([`Store::write_bundle_file`]), so in an encrypted history each one is
//! encrypted like the points, and the commit names nobody. A file over
//! [`file_limit`] (`[state] full_run_file_mb`, 75 MB by default, held to
//! 95 MB on GitHub) is left out and named in the manifest, which records
//! the limit; a reader holds the run's files to it. The history
//! keeps the latest `[state] full_runs_kept` full runs (50 by default): an
//! older one, and one whose point is gone (removed by an older Pathwarden),
//! is removed by the next full run's commit; its point stays.

use std::io::Write as _;
use std::path::Path;

use flate2::write::GzEncoder;
use flate2::Compression;
use pathwarden_core::config::{Config, Keep};
use pathwarden_core::identity::Actor;
use pathwarden_core::store::{self, KeptUnpushed, Store, BUNDLE_FILES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::workspace::{RunSummary, Workspace, REPORT_FILE};

/// What `run.json` says it is.
pub const SCHEMA: &str = "pathwarden.run-bundle.v1";

/// The manifest's format; a reader leaves a full run of a newer format
/// alone. 2 (0.2) added `exposed.json.gz`: an older reader refuses a full
/// run holding a file it doesn't know, so it is told to update instead.
/// Any file added to [`BUNDLE_FILES`] needs another bump.
pub const FORMAT: u32 = 2;

pub const MANIFEST_FILE: &str = "run.json";
pub const SUMMARY_FILE: &str = "summary.json";
pub const REPORT_GZ: &str = "report.html.gz";
pub const SETTINGS_FILE: &str = "settings.toml";

/// The largest file any full run takes, whatever `[state]
/// full_run_file_mb` or a manifest says (2 GB). The limit a run is
/// written under is [`file_limit`]; a larger file is left out and named,
/// and the point and the rest of the run are still kept.
pub const MAX_FILE_BYTES: u64 = pathwarden_core::config::MAX_FULL_RUN_FILE_MB * 1024 * 1024;

// The core reads an earlier run's graph from its full run no larger.
const _: () = assert!(MAX_FILE_BYTES == pathwarden_core::exposed::MAX_FULL_RUN_FILE);

/// The limit of a full run whose manifest records none (written by older
/// releases): 45 MB.
pub const LEGACY_FILE_BYTES: u64 = pathwarden_core::exposed::LEGACY_FULL_RUN_FILE;

/// The largest file a full run recorded here takes, for the history in
/// `store`: `[state] full_run_file_mb`, held to 95 MB on a GitHub remote
/// ([`pathwarden_core::config::StateConfig::full_run_file_bytes_for`]).
pub fn file_limit(state: &pathwarden_core::config::StateConfig, store: &Store) -> u64 {
    state.full_run_file_bytes_for(remote_of(state, store).as_deref())
}

/// The git remote of the history in `store` (`None`: a folder).
fn remote_of(state: &pathwarden_core::config::StateConfig, store: &Store) -> Option<String> {
    if !store.is_git() {
        return None;
    }
    store.remote().map(|(r, _)| r).or(state.remote.clone())
}

/// Whether the history in `store` is on GitHub, which holds the limit.
pub fn on_github(state: &pathwarden_core::config::StateConfig, store: &Store) -> bool {
    remote_of(state, store).is_some_and(|r| pathwarden_core::config::is_github_remote(&r))
}

/// [`file_limit`] in MB, and whether GitHub holds the setting to it.
pub fn file_limit_mb(state: &pathwarden_core::config::StateConfig, store: &Store) -> (u64, bool) {
    let mb = file_limit(state, store) >> 20;
    (mb, mb < state.full_run_file_mb())
}

/// Why the limit is lower than set, on History storage's card and in
/// `history storage show`.
pub const GITHUB_HOLD_WORDS: &str =
    "GitHub refuses files over 100 MB, so a larger setting is held to 95 MB.";

/// What larger files become, on History storage's card.
pub const FILE_LIMIT_WORDS: &str =
    "Larger files are left out of the full run and named on its page. Its numbers are always kept.";

/// What `history storage show` says about the limit, under "Largest
/// file": "75 MB. Larger files are left out ...".
pub fn file_limit_words(mb: u64, held: bool) -> String {
    if held {
        format!("{mb} MB. {GITHUB_HOLD_WORDS} {FILE_LIMIT_WORDS}")
    } else {
        format!("{mb} MB. {FILE_LIMIT_WORDS}")
    }
}

/// What a run without a folder here (a schedule's `pathwarden run`) says
/// when its full run is committed but not pushed.
pub const NO_FOLDER_WORDS: &str = "If this run's upload is lost before it is shared, its full \
run can't be made again. Its numbers are kept.";

/// Most runs a publish adds from this computer's backlog (full runs a
/// crash or a failed build kept from going in).
const BACKLOG_MAX: usize = 10;

/// `run.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    pub format: u32,
    /// The history run ID (`20261009T021000.042Z`): the point's and the
    /// folder's name.
    pub run_id: String,
    /// The Pathwarden that wrote it.
    pub pathwarden: String,
    /// The account that recorded it (`DOMAIN\user`; a schedule's gMSA),
    /// as [`Actor::current`] reads it.
    #[serde(default)]
    pub recorded_by: Option<String>,
    /// The computer it was recorded on.
    #[serde(default)]
    pub recorded_on: Option<String>,
    /// How: `ui` (the app), `schedule`, `cli` (the command line) or
    /// `import` ([`pathwarden_core::record::by`]).
    pub recorded_from: String,
    /// The recording computer's own folder ID for the run, for reference
    /// only (none when it kept no folder: a schedule's `pathwarden run`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// When the analysis finished (Unix seconds).
    pub finished_at: i64,
    /// The SHA-256 of `settings.toml`, when it is there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_sha256: Option<String>,
    /// Every other file of the full run, as written.
    pub files: Vec<FileEntry>,
    /// Files the run had that were left out, and why.
    #[serde(default)]
    pub left_out: Vec<LeftOut>,
    /// The largest file it was written to take, in bytes (`[state]
    /// full_run_file_mb` on the computer that recorded it). A reader holds
    /// its files to it ([`Manifest::file_limit`]); written by newer releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
}

impl Manifest {
    /// The largest file this full run may hold: its own
    /// [`Manifest::max_file_bytes`], [`LEGACY_FILE_BYTES`] when it records
    /// none, and never more than [`MAX_FILE_BYTES`].
    pub fn file_limit(&self) -> u64 {
        self.max_file_bytes
            .unwrap_or(LEGACY_FILE_BYTES)
            .min(MAX_FILE_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftOut {
    pub name: String,
    pub bytes: u64,
    pub why: String,
}

impl LeftOut {
    /// "graph.bin.gz (120 MB)".
    pub fn words(&self) -> String {
        format!(
            "{} ({})",
            self.name,
            pathwarden_core::diagnostics::bytes(self.bytes)
        )
    }
}

/// A recorded run's place as a full run in the history, kept with the run
/// on the computer that recorded it ([`crate::workspace::HistoryLink`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullRunLink {
    pub state: FullRunState,
    /// Why it isn't shared (or not pushed yet), in one sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// Files left out ([`LeftOut::words`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_out: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullRunState {
    /// Saved here, on its way into the history (a crash leaves it so; the
    /// next full run from this computer adds it).
    Pending,
    /// In the history (pushed, or in the folder).
    Shared,
    /// Committed here, not pushed yet: it goes with the next push.
    Unpushed,
    /// Not in the history: [`FullRunLink::why`].
    NotShared,
}

/// A full run ready to write.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub manifest: Manifest,
    /// The files, the manifest last, by their names in [`BUNDLE_FILES`].
    files: Vec<(&'static str, Vec<u8>)>,
}

/// What a full run is made of.
pub struct Parts<'a> {
    /// The history run ID.
    pub run_id: &'a str,
    pub summary: &'a RunSummary,
    /// The report as the run's folder keeps it (without its label).
    pub report_html: &'a str,
    /// The run's other files ([`crate::run_data::files_for`]); names not in
    /// [`BUNDLE_FILES`] (its timings) are left out.
    pub extra: Vec<(&'a str, Vec<u8>)>,
    /// The `pathwarden.toml` it was analysed with, if any.
    pub config_text: Option<&'a str>,
    /// [`Manifest::recorded_from`].
    pub recorded_from: &'a str,
    /// The run's folder here, if it has one.
    pub folder: Option<&'a str>,
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
    let _ = enc.write_all(bytes);
    enc.finish().unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The shared sections of `pathwarden.toml` ([`pathwarden_core::config_edit::SHARED_SECTIONS`]),
/// as a run's `settings.toml` keeps them: never `[state]`, `[[output]]`,
/// `[ingest]` or `[opengraph]` (pack trust stays each computer's), and no
/// mapping packs. `None` when the file can't be read.
pub fn settings_snapshot(config_text: &str) -> Option<String> {
    let doc = pathwarden_core::config_edit::ConfigDoc::parse(config_text).ok()?;
    let header = "# The shared settings this run was analyzed with (a snapshot; never applied).\n";
    Some(doc.shared_text(header, &|k| k != "mapping", &|_| false, &[], None))
}

/// A folder on this computer, as it shows in text: a drive path with
/// either slash (`C:\Users\x`, `C:/Users/x`), a UNC path (`\\srv\share`),
/// an absolute POSIX path or one from the home folder, quoted or not. A
/// folder's name may hold spaces when another part follows it
/// (`C:\Users\Ann Smith\x`); the last part may not, so the words after a
/// path stay.
fn path_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        let part = r#"[^\\/\s'"<>|*?`{};]+"#;
        let last = r#"[^\\/\s'"<>|*?`{};]*"#;
        let rest = format!(r#"(?:{part}(?: {part})*[\\/])*{last}"#);
        // A drive or UNC path after anything but a letter or digit
        // (`file:C:\x`, `<C:\x>`, `;C:\x`), with `file://` and `\\?\` as
        // prefixes; a POSIX path only after a space, quote or bracket, so
        // "and/or" keeps its slash.
        regex::Regex::new(&format!(
            r#"(?P<pre>^|[^A-Za-z0-9])(?P<path>(?:file:/{{2,3}})?(?:\\\\\?\\UNC\\|\\\\\?\\[A-Za-z]:[\\/]|[A-Za-z]:[\\/]|\\\\){rest})|(?P<pre2>^|[\s'"(=,\[`<{{;])(?P<path2>(?:/|~/)(?:{part}(?: {part})*[\\/])*{part}[\\/]?)"#
        ))
        .expect("the path pattern compiles")
    })
}

/// Each path in `text` reduced to its last part: "C:\Users\ann\data.zip"
/// becomes "data.zip", "'\\srv\share'" becomes "'share'". Other words stay.
pub(crate) fn scrub_path_words(text: &str) -> String {
    path_regex()
        .replace_all(text, |c: &regex::Captures| {
            let (pre, path) = match (c.name("path"), c.name("path2")) {
                (Some(p), _) => (c.name("pre"), p.as_str()),
                (None, Some(p)) => (c.name("pre2"), p.as_str()),
                (None, None) => (None, ""),
            };
            let last = path
                .rsplit(['\\', '/'])
                .find(|p| !p.is_empty())
                .unwrap_or("");
            format!("{}{last}", pre.map_or("", |m| m.as_str()))
        })
        .into_owned()
}

/// What was analysed, without this computer's folders: a path (and "and N
/// more") becomes the file's name.
fn scrub_source(source: &str) -> String {
    let (head, tail) = match source.rfind(" and ") {
        Some(i) if source[i + 5..].ends_with(" more") => source.split_at(i),
        _ => (source, ""),
    };
    if head.contains(['\\', '/']) {
        let name = head
            .trim_end_matches(['\\', '/'])
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or("");
        format!("{name}{tail}")
    } else {
        scrub_path_words(source)
    }
}

/// The summary as a full run keeps it: nothing of this computer's. Where
/// the data came from is reduced to file names, where a collection was
/// kept is dropped, and so are the environment's local ID, how it was
/// placed and what the recording said about this computer's history.
pub fn redact_summary(s: &RunSummary) -> RunSummary {
    let mut out = s.clone();
    out.source = scrub_source(&s.source);
    out.environment = None;
    out.assigned = None;
    out.shared = None;
    if let Some(c) = &mut out.collection {
        c.kept = None;
        c.warnings = c.warnings.iter().map(|w| scrub_path_words(w)).collect();
        // Each domain's failure: already without account names when
        // saved; no local paths here either, whatever wrote it.
        for d in &mut c.domains {
            d.reason = d.reason.as_deref().map(scrub_path_words);
            d.detail = d.detail.as_deref().map(scrub_path_words);
        }
    }
    out.history = s
        .history
        .as_ref()
        .and_then(|h| h.run_id.clone())
        .map(|run_id| crate::workspace::HistoryLink {
            run_id: Some(run_id),
            ..Default::default()
        });
    out
}

impl Bundle {
    /// The full run of `parts`, files over `limit` bytes left out (the
    /// manifest and summary always stay).
    pub fn build(parts: Parts, limit: u64) -> Bundle {
        let limit = limit.min(MAX_FILE_BYTES);
        let actor = Actor::current();
        let mut files: Vec<(&'static str, Vec<u8>)> = Vec::new();
        let mut left_out = Vec::new();
        let mut add = |name: &'static str, bytes: Vec<u8>, files: &mut Vec<_>| {
            if bytes.len() as u64 > limit && name != SUMMARY_FILE {
                left_out.push(LeftOut {
                    name: name.to_string(),
                    bytes: bytes.len() as u64,
                    why: format!(
                        "over the {} per-file limit",
                        pathwarden_core::diagnostics::bytes(limit)
                    ),
                });
            } else {
                files.push((name, bytes));
            }
        };
        let mut summary = redact_summary(parts.summary);
        // The lists only when the full run keeps them (not left out as too
        // large).
        summary.tier_zero_lists = parts
            .extra
            .iter()
            .any(|(n, b)| *n == crate::run_data::EXPOSED_FILE && b.len() as u64 <= limit);
        // Its report's link to which accounts, only when the report is kept.
        let report_gz = gzip(parts.report_html.as_bytes());
        summary.tier_zero_change &= report_gz.len() as u64 <= limit;
        let summary_bytes = serde_json::to_vec_pretty(&summary).unwrap_or_default();
        add(SUMMARY_FILE, summary_bytes, &mut files);
        add(REPORT_GZ, report_gz, &mut files);
        for (name, bytes) in parts.extra {
            if let Some(name) = BUNDLE_FILES.iter().find(|n| **n == name) {
                if ![MANIFEST_FILE, SUMMARY_FILE, REPORT_GZ, SETTINGS_FILE].contains(name) {
                    add(name, bytes, &mut files);
                }
            }
        }
        let settings = parts.config_text.and_then(settings_snapshot);
        let settings_sha256 = settings.as_deref().map(|s| sha256_hex(s.as_bytes()));
        if let Some(s) = settings {
            add(SETTINGS_FILE, s.into_bytes(), &mut files);
        }
        let manifest = Manifest {
            schema: SCHEMA.into(),
            format: FORMAT,
            run_id: parts.run_id.to_string(),
            pathwarden: env!("CARGO_PKG_VERSION").to_string(),
            recorded_by: actor.user,
            recorded_on: actor.computer,
            recorded_from: parts.recorded_from.to_string(),
            folder: parts.folder.map(str::to_string),
            finished_at: parts.summary.created_at,
            settings_sha256,
            files: files
                .iter()
                .map(|(n, b)| FileEntry {
                    name: n.to_string(),
                    bytes: b.len() as u64,
                    sha256: sha256_hex(b),
                })
                .collect(),
            left_out,
            max_file_bytes: Some(limit),
        };
        Bundle { manifest, files }
    }

    /// For a full run already in the history, made again here to add the
    /// files it left out: it keeps the `settings.toml` the history
    /// holds for it (the settings now may not be the ones it was analysed
    /// with), when that matches the manifest there.
    fn keep_settings_from(mut self, store: &Store) -> Bundle {
        if self.files.iter().any(|(n, _)| *n == SETTINGS_FILE) {
            return self;
        }
        let id = self.run_id().to_string();
        let old = read_manifest(store, &id)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok());
        let Some(sha) = old.and_then(|m| m.settings_sha256) else {
            return self;
        };
        let small = store
            .bundle_file_len(&id, SETTINGS_FILE)
            .ok()
            .flatten()
            .is_some_and(|n| n <= store::max_on_disk(4 << 20));
        let Some(bytes) = small
            .then(|| store.read_bundle_file(&id, SETTINGS_FILE).ok().flatten())
            .flatten()
            .filter(|b| sha256_hex(b) == sha)
        else {
            return self;
        };
        self.manifest.settings_sha256 = Some(sha.clone());
        self.manifest.files.push(FileEntry {
            name: SETTINGS_FILE.to_string(),
            bytes: bytes.len() as u64,
            sha256: sha,
        });
        self.files.push((SETTINGS_FILE, bytes));
        self
    }

    /// The full run of the run saved in `dir` here (its report and data
    /// files), for runs saved before they could go in.
    pub fn from_run_dir(
        dir: &Path,
        summary: &RunSummary,
        run_id: &str,
        config_text: Option<&str>,
        recorded_from: &str,
        limit: u64,
    ) -> Result<Bundle, String> {
        let report = std::fs::read_to_string(dir.join(REPORT_FILE))
            .map_err(|e| format!("its report can't be read: {e}"))?;
        let extra: Vec<(&str, Vec<u8>)> = BUNDLE_FILES
            .iter()
            .filter_map(|n| std::fs::read(dir.join(n)).ok().map(|b| (*n, b)))
            .collect();
        Ok(Bundle::build(
            Parts {
                run_id,
                summary,
                report_html: &report,
                extra,
                config_text,
                recorded_from,
                folder: Some(&summary.id),
            },
            limit,
        ))
    }

    pub fn run_id(&self) -> &str {
        &self.manifest.run_id
    }

    /// The bytes written, the manifest included.
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|(_, b)| b.len() as u64).sum::<u64>()
            + self.manifest_bytes().len() as u64
    }

    fn manifest_bytes(&self) -> Vec<u8> {
        let mut b = serde_json::to_vec_pretty(&self.manifest).unwrap_or_default();
        b.push(b'\n');
        b
    }

    /// Writes the full run into `store` (its point must be there): its
    /// files, the manifest last, and removes the files of an earlier
    /// write of it that this one doesn't have (one left out now).
    fn write(&self, store: &Store) -> anyhow::Result<()> {
        let id = self.run_id();
        anyhow::ensure!(
            !is_newer_bundle(store, id),
            "Run {id} was saved by a newer Pathwarden, so it is left as it is."
        );
        for (name, bytes) in &self.files {
            store.write_bundle_file(id, name, bytes)?;
        }
        for name in store::bundle_files(&store.dir, id) {
            if name != MANIFEST_FILE && !self.files.iter().any(|(n, _)| *n == name) {
                store.remove_state_file(&store::bundle_rel(id, name))?;
            }
        }
        store.write_bundle_file(id, MANIFEST_FILE, &self.manifest_bytes())
    }
}

/// What [`publish`] did.
#[derive(Debug, Clone, Default)]
pub struct Published {
    /// The runs written, by run ID.
    pub shared: Vec<String>,
    /// Runs not written, and why: (run ID, why).
    pub skipped: Vec<(String, String)>,
    /// What was written, in bytes.
    pub bytes: u64,
    /// Older full runs (and ones without a point) removed.
    pub removed: usize,
    /// Committed and pushed (git).
    pub pushed: bool,
    /// Committed here, but the push failed: it goes with the next one.
    pub unpushed: Option<KeptUnpushed>,
    /// For the user: what the store said about earlier pushes.
    pub notes: Vec<String>,
}

/// The run IDs whose full run the history keeps once `adding` are in it:
/// of the full runs with a point (those there, and those being added), the
/// latest `keep`.
fn kept_ids(store: &Store, adding: &[&str], keep: usize) -> anyhow::Result<Vec<String>> {
    let points: std::collections::HashSet<String> = store
        .list_state_files("history")?
        .into_iter()
        .filter_map(|r| {
            r.strip_prefix("history/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .collect();
    let mut with_point: Vec<String> = store
        .bundles()
        .into_iter()
        .chain(adding.iter().map(|s| s.to_string()))
        .filter(|id| points.contains(id))
        .collect();
    with_point.sort();
    with_point.dedup();
    with_point.reverse();
    with_point.truncate(keep);
    Ok(with_point)
}

/// What one write did: the runs written, those skipped and why, the
/// bytes written, and the older full runs removed.
type Written = (Vec<String>, Vec<(String, String)>, u64, usize);

/// One write of `bundles` and the trim, as on the first try and again on
/// top of another machine's push. Which full runs the history keeps is
/// settled first, so a run is never written only to be trimmed in the same
/// commit, and a run written is never trimmed by it.
fn write_all(store: &Store, bundles: &[Bundle], keep: usize) -> anyhow::Result<Written> {
    let mut skipped = Vec::new();
    let mut with_point: Vec<&Bundle> = Vec::new();
    for b in bundles {
        if store.has_state_file(&format!("history/{}.json", b.run_id())) {
            with_point.push(b);
        } else {
            skipped.push((
                b.run_id().to_string(),
                "its numbers aren't in the history".to_string(),
            ));
        }
    }
    let adding: Vec<&str> = with_point.iter().map(|b| b.run_id()).collect();
    let kept = kept_ids(store, &adding, keep)?;
    let mut shared = Vec::new();
    let mut bytes = 0;
    for b in with_point {
        if !kept.iter().any(|k| k == b.run_id()) {
            skipped.push((
                b.run_id().to_string(),
                format!(
                    "it is older than the latest {}",
                    pathwarden_core::text::count(keep, "full run", "full runs")
                ),
            ));
            continue;
        }
        // A newer Pathwarden's full run is left as it is, and the others
        // still go in.
        if is_newer_bundle(store, b.run_id()) {
            skipped.push((
                b.run_id().to_string(),
                "a newer Pathwarden saved its full run".to_string(),
            ));
            continue;
        }
        b.write(store)?;
        shared.push(b.run_id().to_string());
        bytes += b.bytes();
    }
    let mut removed = 0;
    for id in store.bundles() {
        // A newer Pathwarden's full run is left to it (docs/dev/formats.md).
        if !kept.contains(&id) && !shared.contains(&id) && !is_newer_bundle(store, &id) {
            store.remove_bundle(&id)?;
            removed += 1;
        }
    }
    Ok((shared, skipped, bytes, removed))
}

/// The commit message: "pathwarden run <id>: full run (2.1 MB)" (an
/// encrypted history's commits keep only "pathwarden run <id>").
fn message(shared: &[String], bytes: u64, removed: usize) -> String {
    let size = pathwarden_core::diagnostics::bytes(bytes);
    let mut m = match shared {
        [one] => format!("pathwarden run {one}: full run ({size})"),
        many => format!(
            "pathwarden: {} ({size})",
            pathwarden_core::text::count(many.len(), "full run", "full runs")
        ),
    };
    if removed > 0 {
        m.push_str(&format!(
            "; {} removed",
            pathwarden_core::text::count(removed, "older full run", "older full runs")
        ));
    }
    m
}

/// Writes `bundles` into the history and, with git, commits and pushes
/// them in one commit; when another machine pushed first, writes them
/// again on top of what it left. Keeps the latest `keep` full runs.
/// The caller holds the store's lock (and pulled, or just published the
/// runs' points). `push`: with git, commit and push (off, nothing is
/// written: a reader's or `--no-push` run's point isn't kept either).
pub fn publish(
    store: &Store,
    bundles: &[Bundle],
    keep: usize,
    push: bool,
) -> anyhow::Result<Published> {
    let keep = keep.max(1);
    if store.is_git() && !push {
        return Ok(Published {
            skipped: bundles
                .iter()
                .map(|b| {
                    (
                        b.run_id().to_string(),
                        "this computer doesn't push to the history".to_string(),
                    )
                })
                .collect(),
            ..Published::default()
        });
    }
    store.check_expected()?;
    let (shared, skipped, bytes, removed) = write_all(store, bundles, keep)?;
    let mut out = Published {
        shared,
        skipped,
        bytes,
        removed,
        ..Published::default()
    };
    if out.shared.is_empty() && out.removed == 0 {
        return Ok(out);
    }
    if !store.is_git() {
        return Ok(out);
    }
    let first = message(&out.shared, out.bytes, out.removed);
    let mut again: Option<Written> = None;
    let published = store.publish_with(&first, || {
        let w = write_all(store, bundles, keep)?;
        let m = (!w.0.is_empty() || w.3 > 0).then(|| message(&w.0, w.2, w.3));
        again = Some(w);
        Ok(m)
    });
    if let Some((shared, skipped, bytes, removed)) = again {
        out.shared = shared;
        out.skipped = skipped;
        out.bytes = bytes;
        out.removed = removed;
    }
    match published {
        Ok(p) => {
            out.pushed = p.pushed;
            out.notes = p.notes;
        }
        Err(e) => {
            let kept = e.downcast::<KeptUnpushed>()?;
            out.notes = kept.notes.clone();
            out.unpushed = Some(kept);
        }
    }
    Ok(out)
}

/// Whether runs recorded with `config` go into its history in full:
/// "Full runs and settings", and the history is written from here (a
/// folder, or a git repository this computer pushes to).
pub fn wanted(config: &Config) -> bool {
    config.state.keep() == Keep::Full
}

/// What [`Published`] means for run `run_id`, kept with the run.
pub fn link_for(run_id: &str, p: &anyhow::Result<Published>) -> FullRunLink {
    match p {
        Err(e) => FullRunLink {
            state: FullRunState::NotShared,
            why: Some(format!("{e:#}")),
            left_out: Vec::new(),
        },
        Ok(p) => {
            if let Some((_, why)) = p.skipped.iter().find(|(id, _)| id == run_id) {
                return FullRunLink {
                    state: FullRunState::NotShared,
                    why: Some(why.clone()),
                    left_out: Vec::new(),
                };
            }
            match &p.unpushed {
                Some(k) => FullRunLink {
                    state: FullRunState::Unpushed,
                    why: Some(k.sentence("The full run is committed")),
                    left_out: Vec::new(),
                },
                None => FullRunLink {
                    state: FullRunState::Shared,
                    why: None,
                    left_out: Vec::new(),
                },
            }
        }
    }
}

/// The one line the command line prints about a run's full run, and
/// whether it is a warning.
pub fn words(link: &FullRunLink, bytes: Option<u64>) -> (String, bool) {
    let left = if link.left_out.is_empty() {
        String::new()
    } else {
        format!(" Left out: {}.", link.left_out.join(", "))
    };
    match link.state {
        FullRunState::Shared => (
            format!(
                "Full run in the history{}.{left}",
                bytes
                    .map(|b| format!(" ({})", pathwarden_core::diagnostics::bytes(b)))
                    .unwrap_or_default()
            ),
            !link.left_out.is_empty(),
        ),
        FullRunState::Pending => ("Full run not in the history yet.".into(), true),
        FullRunState::Unpushed | FullRunState::NotShared => (
            format!(
                "Full run not shared: {}{left}",
                link.why.as_deref().unwrap_or("unknown")
            ),
            true,
        ),
    }
}

/// Shares a run the app (or `run --save`, `collect --save`) just saved in
/// `ws`, with its point just recorded in `held`'s history under the lock
/// it still holds ([`crate::history_ui::record_analysis_held`]): publishes
/// its full run there, with any of this computer's full runs still waiting
/// ([`waiting`]). No second lock and no second pull: nothing else
/// takes the history between the point and its full run, as with
/// `pathwarden run`; a push another machine beat is made again on top of
/// its push ([`publish`]). The run's summary (and theirs) then says how it
/// went. `None` when the history doesn't keep full runs, or this computer
/// doesn't write it.
pub fn share_saved(
    ws: &Workspace,
    held: &crate::history_ui::Held,
    config: &Config,
    bundle: Bundle,
) -> Option<(FullRunLink, u64)> {
    if !wanted(config) {
        return None;
    }
    let loc = &held.loc;
    if !loc.records() {
        return None;
    }
    let run_id = bundle.run_id().to_string();
    let mut bundles = vec![bundle];
    let backlog = backlog(
        ws,
        &loc.store,
        config.state.full_runs_kept(),
        &run_id,
        file_limit(&config.state, &loc.store),
    );
    let backlog_ids: Vec<Backlogged> = backlog.iter().map(Backlogged::of).collect();
    bundles.extend(backlog.into_iter().map(|b| b.bundle));
    let left_out: Vec<String> = bundles[0]
        .manifest
        .left_out
        .iter()
        .map(LeftOut::words)
        .collect();
    let bytes = bundles[0].bytes();
    let published = publish(
        &loc.store,
        &bundles,
        config.state.full_runs_kept(),
        loc.push,
    );
    // The backlog's runs say how it went too.
    for b in backlog_ids {
        b.save(ws, &published);
    }
    let mut link = link_for(&run_id, &published);
    link.left_out = left_out;
    if !loc.store.has_unpushed() {
        push_worked(&loc.dir);
    }
    mark_shared(ws, &loc.store, &run_id);
    Some((link, bytes))
}

/// Whether a run's full run is waiting to go into the history, as its row
/// on the Runs list and in `pathwarden runs list` says ([`waiting`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// In the history, not kept in full, or nothing to say.
    No,
    /// It goes with the next push from here ([`WAITING_WORDS`]).
    Yes,
    /// It would, but it can't be made again: its report isn't here any
    /// more ([`CANT_SHARE_WORDS`]).
    CantShare,
}

impl Waiting {
    /// The row's words.
    pub fn words(self) -> Option<&'static str> {
        match self {
            Waiting::No => None,
            Waiting::Yes => Some(WAITING_WORDS),
            Waiting::CantShare => Some(CANT_SHARE_WORDS),
        }
    }
}

/// A run's line on the Runs list and in `pathwarden runs list` when its
/// full run is waiting.
pub const WAITING_WORDS: &str = "Its full run is waiting to be shared.";

/// The same, when it can't be made again from the run's folder.
pub const CANT_SHARE_WORDS: &str =
    "Its full run can't be shared: its report isn't on this computer.";

/// Whether run `r`'s full run is waiting, by its summary alone: `None` when
/// it isn't; `Some(true)` when it must be made again from its folder,
/// `Some(false)` when it is committed here already. Waiting: recorded in the
/// history with "Full runs and settings" (`keep_full`), and its full run
/// pending, committed but not pushed, or not shared for a reason the next
/// push may get past (the history in use, out of reach, a sign-in). Not one
/// older than every full run the history keeps, nor one only read here.
/// `facts`: the history's ([`bundle_facts`]).
fn waiting_state(r: &RunSummary, facts: &BundleFacts, keep_full: bool) -> Option<bool> {
    if r.demo || r.shared.is_some() || !keep_full || !facts.pushes {
        return None;
    }
    let h = r.history.as_ref()?;
    let (id, f) = (h.run_id.as_deref()?, h.full_run.as_ref()?);
    let trimmed = facts.held.len() >= facts.kept && facts.oldest.as_deref().is_some_and(|o| id < o);
    match f.state {
        FullRunState::Shared => None,
        // Committed here: in the working copy, waiting for the push.
        FullRunState::Unpushed if facts.held.contains(id) => facts.unpushed.then_some(false),
        FullRunState::Pending | FullRunState::Unpushed | FullRunState::NotShared => {
            (!facts.held.contains(id) && !trimmed).then_some(true)
        }
    }
}

/// Whether run `r` of `ws` can be made into a full run again from its
/// folder ([`Bundle::from_run_dir`] needs its report).
fn rebuildable(ws: &Workspace, r: &RunSummary) -> bool {
    ws.run_dir(&r.id)
        .is_some_and(|d| d.join(REPORT_FILE).is_file())
}

/// [`Waiting`] of run `r` of `ws`: see [`waiting_state`]; one that must be
/// made again and can't is [`Waiting::CantShare`]. A run in the history
/// in full with files left out that its folder here holds and that fit
/// the limit now waits too ([`refill_state`], [`fills_in`]).
pub fn waiting(ws: &Workspace, r: &RunSummary, facts: &BundleFacts, keep_full: bool) -> Waiting {
    match waiting_state(r, facts, keep_full) {
        None if refill_state(r, facts, keep_full) && fills_in(ws, r, facts.file_limit) => {
            Waiting::Yes
        }
        None => Waiting::No,
        Some(false) => Waiting::Yes,
        Some(true) if rebuildable(ws, r) => Waiting::Yes,
        Some(true) => Waiting::CantShare,
    }
}

/// The runs recorded here still waiting to be pushed to the git history at
/// `loc`, for History storage's In use line and the sidebar's footer
/// ([`crate::last_pull::Status::with_waiting`]): a run whose point a failed
/// push left here, and with "Full runs and settings" one whose full run
/// goes with the next push ([`Waiting::Yes`]). None for a folder, or a
/// history this computer only reads.
pub fn waiting_runs(
    ws: &Workspace,
    loc: &crate::history_ui::Location,
) -> Vec<crate::last_pull::WaitingRun> {
    if loc.git.is_none() || !loc.records() {
        return Vec::new();
    }
    let state = crate::settings::load_ws(ws).config.state;
    let keep_full = state.keep() == Keep::Full;
    let unpushed = loc.store.has_unpushed();
    let facts = if keep_full {
        let held: Vec<String> = loc.store.bundles();
        BundleFacts {
            oldest: held.first().cloned(),
            held: held.into_iter().collect(),
            newer: Default::default(),
            kept: state.full_runs_kept(),
            pushes: true,
            unpushed,
            file_limit: file_limit(&state, &loc.store),
        }
    } else {
        BundleFacts::default()
    };
    ws.runs()
        .iter()
        .filter(|r| !r.demo && r.shared.is_none())
        .filter_map(|r| {
            let h = r.history.as_ref()?;
            h.run_id.as_ref()?;
            let point = unpushed && h.unpushed.is_some();
            let full = keep_full && waiting(ws, r, &facts, true) == Waiting::Yes;
            (point || full).then_some(crate::last_pull::WaitingRun {
                at: r.created_at,
                full: !point,
            })
        })
        .collect()
}

/// [`waiting_runs`], noted with the last sync's record
/// ([`crate::last_pull::set_waiting`]) for the pages to read: after a
/// recording, a sync or a push. Returns them.
pub fn record_waiting(
    ws: &Workspace,
    loc: &crate::history_ui::Location,
) -> Vec<crate::last_pull::WaitingRun> {
    if loc.git.is_none() {
        return Vec::new();
    }
    let w = waiting_runs(ws, loc);
    crate::last_pull::set_waiting(&loc.store, w.clone());
    w
}

/// Who asked for a pull, for what [`push_waiting`] pushes with it.
pub enum PullBy<'a> {
    /// Sync now, Sign in, `history storage sync`, connecting: everything waiting.
    Asked,
    /// The app's own pulls ([`crate::auto_pull`]): nothing while `busy`
    /// (an analysis is running), nor for an hour after a push that failed
    /// ([`BACKOFF`]); else what is committed here and at most one full run
    /// made again, so a recording never waits long for the history. A push
    /// that fails says how many full runs still wait in that pull's notes
    /// (the pull's own line on commits not pushed yet follows every pull
    /// while there are some); the pulls of the next hour try nothing and
    /// add nothing of their own.
    Background { busy: &'a dyn Fn() -> bool },
}

/// How long the app's own pulls wait after a push of theirs failed before
/// they try again (Sync now, `history storage sync` and recordings don't).
pub const BACKOFF: std::time::Duration = std::time::Duration::from_secs(3600);

/// When a push of what was waiting last failed, by history folder.
fn failed_pushes(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<std::path::PathBuf, std::time::Instant>>
{
    static FAILED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    FAILED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A push from the history at `dir` worked: the app's pulls try again at
/// once next time.
pub fn push_worked(dir: &Path) {
    failed_pushes().remove(dir);
}

/// After a pull, under the history's lock: what was recorded here and is
/// still waiting goes in and is pushed. That is the commits a failed push
/// left here (a run's point, a full run, a settings change), and this
/// computer's full runs still to be made ([`waiting`]: pending, or not
/// shared because the history was in use or out of reach), as `by` allows
/// ([`PullBy`]). What happened, for the user: `Ok` when it all went, `Err`
/// when some still waits; `None` when nothing was waiting or tried.
pub fn push_waiting(
    ws: Option<&Workspace>,
    loc: &crate::history_ui::Location,
    by: PullBy,
) -> Option<Result<String, String>> {
    if !loc.records() {
        return None;
    }
    let busy = match by {
        PullBy::Background { busy } => Some(busy),
        PullBy::Asked => None,
    };
    let background = busy.is_some();
    if let Some(busy) = busy {
        if busy() {
            return None;
        }
        let failed = failed_pushes().get(&loc.dir).copied();
        if failed.is_some_and(|t| t.elapsed() < BACKOFF) {
            return None;
        }
    }
    let kept = loc.git.is_some() && loc.store.has_unpushed();
    // Full runs to make again: with "Full runs and settings" and a history
    // this computer can write (encrypted, it needs the passphrase).
    let config = ws.map(|ws| crate::settings::load_ws(ws).config);
    let keep = config.as_ref().map_or(1, |c| c.state.full_runs_kept());
    let backlog = match (ws, &config) {
        (Some(ws), Some(c)) if wanted(c) && crate::encryption_ui::lock_reason(loc).is_none() => {
            let limit = file_limit(&c.state, &loc.store);
            let mut b = backlog(ws, &loc.store, keep, "", limit);
            if background {
                b.truncate(1);
            }
            b
        }
        _ => Vec::new(),
    };
    if backlog.is_empty() && !kept {
        return None;
    }
    // An analysis that started while the full run was made: it goes in
    // later, and the push with it.
    if busy.is_some_and(|busy| busy()) {
        return None;
    }
    // Full runs already committed here, waiting for the push.
    let have = loc.store.bundles();
    let committed = match (ws, kept) {
        (Some(ws), true) => ws
            .runs()
            .iter()
            .filter(|r| {
                r.history.as_ref().is_some_and(|h| {
                    h.full_run
                        .as_ref()
                        .is_some_and(|f| f.state == FullRunState::Unpushed)
                        && h.run_id.as_ref().is_some_and(|id| have.contains(id))
                })
            })
            .count(),
        _ => 0,
    };
    let went = |n: usize| {
        format!(
            "{} recorded here went into the history.",
            pathwarden_core::text::count(n, "full run", "full runs")
        )
    };
    let still = |n: usize| {
        format!(
            "{} still waiting to be shared.",
            pathwarden_core::text::count(
                n,
                "full run recorded here is",
                "full runs recorded here are"
            )
        )
    };
    let result = if backlog.is_empty() {
        match loc
            .store
            .publish_with("pathwarden: changes kept from an earlier push", || Ok(None))
        {
            Ok(p) if p.pushed => Some(Ok(if committed > 0 {
                went(committed)
            } else {
                crate::history_ui::KEPT_PUSHED.to_string()
            })),
            Ok(_) => None,
            // What else is kept is said with the pull's own notes.
            Err(_) => (committed > 0).then(|| Err(still(committed))),
        }
    } else {
        let ids: Vec<Backlogged> = backlog.iter().map(Backlogged::of).collect();
        let bundles: Vec<Bundle> = backlog.into_iter().map(|b| b.bundle).collect();
        // The commits kept here go with it.
        let published = publish(&loc.store, &bundles, keep, loc.push);
        let mut shared = 0;
        if let Some(ws) = ws {
            for b in &ids {
                if b.save(ws, &published) == FullRunState::Shared {
                    shared += 1;
                }
            }
        }
        Some(if shared == ids.len() {
            Ok(went(shared + committed))
        } else {
            Err(still(ids.len() - shared + committed))
        })
    };
    // Nothing kept here any more: the push worked.
    if loc.store.has_unpushed() || matches!(result, Some(Err(_))) {
        failed_pushes().insert(loc.dir.clone(), std::time::Instant::now());
    } else {
        push_worked(&loc.dir);
    }
    if let Some(ws) = ws {
        mark_shared(ws, &loc.store, "");
    }
    result
}

/// What a run left out of the history because this computer wasn't signed
/// in says once a sync has worked.
pub const SIGNED_OUT_THEN: &str =
    "This run wasn't shared: the computer wasn't signed in. Sign in on History storage, then Sync now.";

/// After a sync of the git history that worked: runs left out of it
/// because this computer wasn't signed in no longer offer Sign in.
pub fn signed_in(ws: &Workspace) {
    for r in ws.runs() {
        let stale = r
            .history
            .as_ref()
            .is_some_and(|h| h.sign_in && h.run_id.is_none());
        if !stale {
            continue;
        }
        if let Some(mut s) = ws.summary(&r.id) {
            if let Some(h) = s.history.as_mut() {
                h.sign_in = false;
                h.no_helper = false;
                h.refused = false;
                h.not_recorded = Some(SIGNED_OUT_THEN.into());
                let _ = ws.update_summary(&s);
            }
        }
    }
}

/// Runs saved here whose full run said pending, not pushed or not shared,
/// and which the history now holds with nothing left unpushed here (a
/// later push took them along): marked shared. `except`: a run whose
/// summary the caller writes itself.
pub fn mark_shared(ws: &Workspace, store: &Store, except: &str) {
    if store.has_unpushed() {
        return;
    }
    let have = store.bundles();
    for r in ws.runs() {
        let Some(h) = r.history.as_ref() else {
            continue;
        };
        // Its point went with a later push: it says so no more.
        if h.unpushed.is_some()
            && h.run_id.as_deref().is_some_and(|id| {
                id != except && store.has_state_file(&format!("history/{id}.json"))
            })
        {
            if let Some(mut s) = ws.summary(&r.id) {
                if let Some(h) = s.history.as_mut() {
                    h.unpushed = None;
                    h.sign_in = false;
                    h.no_helper = false;
                    h.refused = false;
                    let _ = ws.update_summary(&s);
                }
            }
        }
        let (Some(id), Some(f)) = (h.run_id.as_deref(), h.full_run.as_ref()) else {
            continue;
        };
        if id == except || f.state == FullRunState::Shared || !have.iter().any(|b| b == id) {
            continue;
        }
        if let Some(mut s) = ws.summary(&r.id) {
            if let Some(f) = s.history.as_mut().and_then(|h| h.full_run.as_mut()) {
                f.state = FullRunState::Shared;
                f.why = None;
                let _ = ws.update_summary(&s);
            }
        }
    }
}

/// How the run with point `run_id` was recorded (its point's
/// `recorded_by`), for a full run made later from its folder; `fallback`
/// when the point doesn't say.
pub fn recorded_from_point(store: &Store, run_id: &str, fallback: &str) -> String {
    store
        .read_state_file(&format!("history/{run_id}.json"))
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["recorded_by"].as_str().map(str::to_string))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// A run of this computer's backlog, made into its full run again.
struct BacklogRun {
    /// Its folder here.
    folder: String,
    bundle: Bundle,
    /// In the history in full already, with files left out that fit now:
    /// only those are added.
    refill: bool,
    /// What its full run left out before.
    left_before: Vec<String>,
}

/// What [`publish`] of the backlog says to each of its runs.
struct Backlogged {
    folder: String,
    run_id: String,
    refill: bool,
    left_out: Vec<String>,
    left_before: Vec<String>,
}

impl Backlogged {
    fn of(b: &BacklogRun) -> Backlogged {
        Backlogged {
            folder: b.folder.clone(),
            run_id: b.bundle.run_id().to_string(),
            refill: b.refill,
            left_out: b
                .bundle
                .manifest
                .left_out
                .iter()
                .map(LeftOut::words)
                .collect(),
            left_before: b.left_before.clone(),
        }
    }

    /// Saves how it went in the run's summary; returns its state now.
    fn save(&self, ws: &Workspace, published: &anyhow::Result<Published>) -> FullRunState {
        let mut link = link_for(&self.run_id, published);
        // What the history holds: the files left out now once it went in;
        // until then, a run filled in keeps saying what it lacks.
        link.left_out = if link.state == FullRunState::Shared || !self.refill {
            self.left_out.clone()
        } else {
            self.left_before.clone()
        };
        let state = link.state;
        if let Some(mut s) = ws.summary(&self.folder) {
            if let Some(h) = s.history.as_mut() {
                h.full_run = Some(link);
                let _ = ws.update_summary(&s);
            }
        }
        state
    }
}

/// The name of a file a [`FullRunLink`] says was left out
/// ("objects.json.gz (50 MB)").
pub fn left_out_name(words: &str) -> &str {
    words.split(" (").next().unwrap_or(words).trim()
}

/// What a full run's file is, as a run page names it: "object index".
pub fn file_words(name: &str) -> &str {
    match name {
        REPORT_GZ => "report",
        "graph.bin.gz" => "graph",
        "objects.json.gz" => "object index",
        "event.json.gz" => "findings list",
        "retest.json.gz" => "retest data",
        crate::run_data::EXPOSED_FILE => "account lists",
        SETTINGS_FILE => "settings",
        other => other,
    }
}

/// Whether Explore needs file `name` of a full run.
pub fn explore_needs(name: &str) -> bool {
    matches!(name, "graph.bin.gz" | "objects.json.gz")
}

/// "object index left out, so Explore can't open it": what a run loaded
/// from the history lacks, for its "Where it came from" row.
pub fn left_out_status<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.into_iter().collect();
    let what: Vec<String> = names.iter().map(|n| file_words(n).to_string()).collect();
    let mut s = format!("{} left out", pathwarden_core::text::and_list(&what));
    if names.iter().any(|n| explore_needs(n)) {
        s.push_str(", so Explore can't open it");
    }
    s
}

/// What the run page of a run recorded here says when its full run left
/// out a file Explore needs.
pub const EXPLORE_ELSEWHERE_WORDS: &str = "Explore won't open this run on other computers.";

/// Whether the folder of run `r` here holds a file its full run left out,
/// no larger than `limit` now. Never a run loaded from the history.
fn fills_in(ws: &Workspace, r: &RunSummary, limit: u64) -> bool {
    let Some(f) = r.history.as_ref().and_then(|h| h.full_run.as_ref()) else {
        return false;
    };
    let Some(dir) = ws.run_dir(&r.id) else {
        return false;
    };
    if r.shared.is_some() || dir.join(LOADED_MARKER).exists() {
        return false;
    }
    f.left_out.iter().any(|w| {
        let name = left_out_name(w);
        // The report is kept as it is here and smaller once compressed.
        let here = match name {
            REPORT_GZ => REPORT_FILE,
            MANIFEST_FILE | SUMMARY_FILE | SETTINGS_FILE => return false,
            n if BUNDLE_FILES.contains(&n) => n,
            _ => return false,
        };
        std::fs::symlink_metadata(dir.join(here)).is_ok_and(|m| m.is_file() && m.len() <= limit)
    })
}

/// Whether run `r`'s full run is in the history with files left out, and
/// among the full runs it keeps, so the files that fit now can be added:
/// with "Full runs and settings" (`keep_full`), on a computer that
/// writes the history. Its folder decides the rest ([`fills_in`]).
fn refill_state(r: &RunSummary, facts: &BundleFacts, keep_full: bool) -> bool {
    if r.demo || r.shared.is_some() || !keep_full || !facts.pushes {
        return false;
    }
    let Some(h) = r.history.as_ref() else {
        return false;
    };
    let (Some(id), Some(f)) = (h.run_id.as_deref(), h.full_run.as_ref()) else {
        return false;
    };
    f.state == FullRunState::Shared
        && !f.left_out.is_empty()
        && facts.held.contains(id)
        && !facts.newer.contains(id)
        && facts.held.iter().filter(|o| o.as_str() > id).count() < facts.kept
}

/// Runs saved here whose full run isn't in the history (a crash left it
/// pending, a push failed and another machine's push came first, or it
/// couldn't be written): in the history by their point, not in it in
/// full, and recent enough to be kept. Made from their folders, without a
/// `settings.toml` (the settings now may not be the ones they were
/// analysed with), with files up to `limit`. And runs in the history in
/// full whose files left out fit `limit` now ([`fills_in`]): made again
/// the same way, keeping the history's `settings.toml` for them.
fn backlog(
    ws: &Workspace,
    store: &Store,
    keep: usize,
    except: &str,
    limit: u64,
) -> Vec<BacklogRun> {
    let have = store.bundles();
    // Older than every full run kept: it would be trimmed at once.
    let kept = kept_ids(store, &[], keep).unwrap_or_default();
    let oldest = (kept.len() >= keep).then(|| kept.last().cloned()).flatten();
    ws.runs()
        .into_iter()
        .filter(|r| !r.demo && r.shared.is_none())
        .filter_map(|r| {
            let h = r.history.as_ref()?;
            let id = h.run_id.clone()?;
            let f = h.full_run.as_ref()?;
            if id == except || !store.has_state_file(&format!("history/{id}.json")) {
                return None;
            }
            let missing = matches!(
                f.state,
                FullRunState::Pending | FullRunState::Unpushed | FullRunState::NotShared
            ) && !have.contains(&id)
                && oldest.as_ref().is_none_or(|o| id > *o);
            let refill = f.state == FullRunState::Shared
                && !f.left_out.is_empty()
                && have.contains(&id)
                && kept.contains(&id)
                && fills_in(ws, &r, limit);
            (missing || refill).then_some((r, id, refill))
        })
        .take(BACKLOG_MAX)
        .filter_map(|(r, id, refill)| {
            let dir = ws.run_dir(&r.id)?;
            let from = recorded_from_point(store, &id, pathwarden_core::record::by::UI);
            let mut b = Bundle::from_run_dir(&dir, &r, &id, None, &from, limit).ok()?;
            if refill {
                b = b.keep_settings_from(store);
            }
            let left_before = r
                .history
                .as_ref()
                .and_then(|h| h.full_run.as_ref())
                .map(|f| f.left_out.clone())
                .unwrap_or_default();
            Some(BacklogRun {
                folder: r.id.clone(),
                bundle: b,
                refill,
                left_before,
            })
        })
        .collect()
}

// ------------------------------------------------------------- mirroring

/// Where a run loaded from the history's full runs came from
/// ([`RunSummary::shared`]): kept with its folder here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFrom {
    /// The repository (credentials hidden), or the history folder.
    pub remote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// [`Manifest::recorded_by`], [`Manifest::recorded_on`] and
    /// [`Manifest::recorded_from`].
    #[serde(default)]
    pub recorded_by: Option<String>,
    #[serde(default)]
    pub recorded_on: Option<String>,
    pub recorded_from: String,
    /// The Pathwarden that recorded it.
    pub pathwarden: String,
    /// When it was loaded here (Unix seconds).
    pub mirrored_at: i64,
    /// The SHA-256 of its `run.json` when loaded: a changed one is loaded
    /// again.
    pub manifest_sha256: String,
    /// Files left out of the full run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_out: Vec<LeftOut>,
}

impl SharedFrom {
    /// "recorded by the schedule as CONTOSO\svc$ on PW-SCHED01": how, who
    /// and where, as far as the full run says.
    pub fn recorded_words(&self) -> String {
        recorded_words(
            &self.recorded_from,
            self.recorded_by.as_deref(),
            self.recorded_on.as_deref(),
        )
    }
}

/// "recorded by the schedule as CONTOSO\svc$ on PW-SCHED01", "recorded in
/// the app by NORTH\arya on SECOPS-WS02", "recorded from the command line
/// by ...": how a full run was recorded, by whom and on which computer, as
/// its manifest says. The Runs page, the run page and `runs show` say it
/// this way.
pub fn recorded_words(from: &str, by: Option<&str>, on: Option<&str>) -> String {
    use pathwarden_core::record::by as how;
    let mut s = match from {
        how::SCHEDULE => {
            let mut s = "recorded by the schedule".to_string();
            if let Some(u) = by {
                s.push_str(&format!(" as {u}"));
            }
            s
        }
        how::UI => match by {
            Some(u) => format!("recorded in the app by {u}"),
            None => "recorded in the app".into(),
        },
        how::IMPORT => match by {
            Some(u) => format!("imported from the app by {u}"),
            None => "imported from the app".into(),
        },
        _ => match by {
            Some(u) => format!("recorded from the command line by {u}"),
            None => "recorded from the command line".into(),
        },
    };
    if let Some(c) = on {
        s.push_str(&format!(" on {c}"));
    }
    s
}

/// Runs of the history this computer was told not to show (a reader's
/// "Hide on this computer"), by history run ID, in the environment's folder.
pub const HIDDEN_FILE: &str = "history-hidden.json";

#[derive(Default, Serialize, Deserialize)]
struct Hidden {
    #[serde(default)]
    runs: Vec<String>,
}

fn hidden(ws: &Workspace) -> Vec<String> {
    std::fs::read_to_string(ws.env_dir().join(HIDDEN_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<Hidden>(&t).ok())
        .map(|h| h.runs)
        .unwrap_or_default()
}

/// Keeps the history's run `run_id` from being loaded here again (a
/// computer that doesn't push can't remove it from the history).
pub fn hide(ws: &Workspace, run_id: &str) -> Result<(), String> {
    let mut runs = hidden(ws);
    if !runs.iter().any(|r| r == run_id) {
        runs.push(run_id.to_string());
        runs.sort();
    }
    let text = serde_json::to_string_pretty(&Hidden { runs }).map_err(|e| e.to_string())?;
    pathwarden_core::config_edit::write_atomic(&ws.env_dir().join(HIDDEN_FILE), &text)
        .map_err(|e| format!("Couldn't save the choice: {e}"))
}

/// The folder ID a full run loaded from `source` gets here:
/// `YYYYMMDD-HHMMSS-` from its run ID and 6 hex digits of SHA-256 of the
/// source and run ID, so loading it again lands on the same folder and
/// links keep working.
pub fn mirror_folder_id(source: &str, run_id: &str) -> Option<String> {
    if !crate::workspace::looks_like_history_id(run_id) {
        return None;
    }
    let digest = Sha256::digest(format!("{source}\n{run_id}").as_bytes());
    Some(format!(
        "{}-{}-{:02x}{:02x}{:02x}",
        &run_id[..8],
        &run_id[9..15],
        digest[0],
        digest[1],
        digest[2]
    ))
}

/// What the history holds in full, for the Runs list
/// ([`crate::run_list::kept_full_runs`]).
#[derive(Debug, Clone, Default)]
pub struct BundleFacts {
    /// Runs whose full run the history holds.
    pub held: std::collections::HashSet<String>,
    /// Of those, the ones a newer Pathwarden wrote.
    pub newer: std::collections::HashSet<String>,
    /// The oldest run the history holds in full.
    pub oldest: Option<String>,
    /// How many full runs it keeps (`[state] full_runs_kept` here).
    pub kept: usize,
    /// This computer pushes to the history, so `kept` is what the history
    /// keeps (a reader's own setting says nothing of it).
    pub pushes: bool,
    /// The working copy has commits a failed push left ([`Store::has_unpushed`]).
    pub unpushed: bool,
    /// The largest file a full run recorded here takes ([`file_limit`]).
    pub file_limit: u64,
}

/// What a full run's `run.json` is to this version: one to load, one a
/// newer Pathwarden wrote (its version), or not a manifest at all.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestKind {
    Ours,
    Newer(String),
    Foreign,
}

/// [`ManifestKind`] of manifest `value`: our schema at a format we know,
/// our schema at a newer format, or anything else (another schema, none).
fn manifest_kind(value: &serde_json::Value) -> ManifestKind {
    if value["schema"].as_str() != Some(SCHEMA) {
        return ManifestKind::Foreign;
    }
    // Read as every format number is (docs/dev/formats.md): a string or a
    // fraction is not one this version knows.
    if !pathwarden_core::formats::of_json(value, "format", FORMAT).is_known() {
        return ManifestKind::Newer(value["pathwarden"].as_str().unwrap_or("newer").to_string());
    }
    ManifestKind::Ours
}

/// Most bytes a full run's `run.json` may have: it lists a few files.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Full run `id`'s `run.json`, when it is no larger than
/// [`MAX_MANIFEST_BYTES`] (checked before it is read).
fn read_manifest(store: &Store, id: &str) -> Result<Option<Vec<u8>>, String> {
    match store.bundle_file_len(id, MANIFEST_FILE) {
        Ok(Some(n)) if n > pathwarden_core::store::max_on_disk(MAX_MANIFEST_BYTES) => {
            return Err("its run.json is too large".into())
        }
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("{e:#}")),
    }
    let bytes = store
        .read_bundle_file(id, MANIFEST_FILE)
        .map_err(|e| format!("{e:#}"))?;
    match bytes {
        Some(b) if b.len() as u64 > MAX_MANIFEST_BYTES => Err("its run.json is too large".into()),
        b => Ok(b),
    }
}

/// Whether full run `id` is of a format this version doesn't know.
fn is_newer_bundle(store: &Store, id: &str) -> bool {
    matches!(read_manifest(store, id), Ok(Some(b))
        if serde_json::from_slice::<serde_json::Value>(&b)
            .is_ok_and(|v| matches!(manifest_kind(&v), ManifestKind::Newer(_))))
}

/// [`BundleFacts`] of the history in `store`, for workspace `ws`; `pushes`:
/// this computer pushes to it.
pub fn bundle_facts(store: &Store, ws: &Workspace, pushes: bool) -> BundleFacts {
    let held: Vec<String> = store.bundles();
    let readable = !held.is_empty() && pathwarden_core::store::check_readable(&store.dir).is_ok();
    let newer = if readable {
        held.iter()
            .filter(|id| {
                read_manifest(store, id)
                    .ok()
                    .flatten()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .is_some_and(|v| matches!(manifest_kind(&v), ManifestKind::Newer(_)))
            })
            .cloned()
            .collect()
    } else {
        Default::default()
    };
    let state = crate::settings::load_ws(ws).config.state;
    BundleFacts {
        oldest: held.first().cloned(),
        held: held.into_iter().collect(),
        newer,
        kept: state.full_runs_kept(),
        pushes,
        unpushed: store.has_unpushed(),
        file_limit: file_limit(&state, store),
    }
}

/// `s` with its first letter in capitals: "Recorded by the schedule ...".
pub fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The file [`mirror`] puts in each folder it loads a full run into, with
/// the folder (never a file of a full run's: [`BUNDLE_FILES`] can't name
/// it). Its presence marks the folder's content as the repository's.
pub const LOADED_MARKER: &str = "loaded-from-history";

/// Whether folder `dir` holds a run loaded from the history: its
/// [`LOADED_MARKER`], a loaded run's summary, or a summary that says so.
/// What [`mirror`] may replace or remove; a folder it can't tell isn't.
pub fn loaded_run_dir(dir: &std::path::Path) -> bool {
    dir.join(LOADED_MARKER).is_file()
        || dir.join(crate::workspace::LOADED_SUMMARY_FILE).is_file()
        || std::fs::read(dir.join(crate::workspace::SUMMARY_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<RunSummary>(&b).ok())
            .is_some_and(|s| s.shared.is_some())
}

/// Whether the run in folder `dir` was analysed on this computer, so its
/// report and summary are this computer's own: no [`LOADED_MARKER`], and a
/// summary that reads and says it wasn't loaded from the history. When
/// unsure (no summary, one that can't be read), it isn't: repository
/// content only reaches an app page as parsed, escaped data.
pub fn trusted_run_dir(dir: &std::path::Path) -> bool {
    // A loaded run's summary (run folder format 2) is never this computer's.
    if dir.join(LOADED_MARKER).exists() || dir.join(crate::workspace::LOADED_SUMMARY_FILE).exists()
    {
        return false;
    }
    std::fs::read(dir.join(crate::workspace::SUMMARY_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<RunSummary>(&b).ok())
        .is_some_and(|s| s.shared.is_none())
}

/// What [`mirror`] did.
#[derive(Debug, Clone, Default)]
pub struct Mirrored {
    /// Full runs loaded (new or changed), by run ID.
    pub loaded: Vec<String>,
    /// Loaded runs removed here: gone from the history, or hidden.
    pub removed: usize,
    /// Their folder IDs here (a run page open on one says so).
    pub removed_ids: Vec<String>,
    /// Full runs of a newer format: (run ID, the Pathwarden that wrote it).
    pub newer: Vec<(String, String)>,
    /// Full runs whose folder here a newer Pathwarden saved: not loaded.
    pub newer_here: usize,
    /// Full runs that couldn't be loaded: (run ID, why).
    pub failed: Vec<(String, String)>,
    /// Why no full run could be read at all (no passphrase here).
    pub unreadable: Option<String>,
}

impl Mirrored {
    /// One line for the user, if there is something to say: "2 full runs
    /// loaded from the repository."
    pub fn words(&self, git: bool) -> Option<String> {
        let place = if git { "repository" } else { "folder" };
        let mut parts = Vec::new();
        if let Some(why) = &self.unreadable {
            parts.push(format!(
                "The full runs in the history can't be read here: {why}"
            ));
        }
        if !self.loaded.is_empty() {
            parts.push(format!(
                "{} loaded from the {place}.",
                pathwarden_core::text::count(self.loaded.len(), "full run", "full runs")
            ));
        }
        if self.removed > 0 {
            parts.push(format!(
                "{} no longer in the {place} {} removed here.",
                pathwarden_core::text::count(self.removed, "run", "runs"),
                if self.removed == 1 { "was" } else { "were" }
            ));
        }
        for (id, version) in &self.newer {
            parts.push(format!(
                "Run {id} was saved by Pathwarden {version}. Update Pathwarden to open it."
            ));
        }
        if let Some(w) = crate::workspace::newer_runs_words(self.newer_here) {
            parts.push(w);
        }
        for (id, why) in &self.failed {
            parts.push(format!("Couldn't load the full run of {id}: {why}"));
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

/// Reads file `name` of full run `id`, checked against the manifest. Its
/// size on disk is checked first, against the manifest and the limit the
/// run was written under (`limit`, [`Manifest::file_limit`]), so an
/// oversized file is never read.
fn checked_file(store: &Store, id: &str, entry: &FileEntry, limit: u64) -> Result<Vec<u8>, String> {
    if entry.bytes > limit {
        return Err(format!("{} is too large", entry.name));
    }
    match store.bundle_file_len(id, &entry.name) {
        Ok(Some(n)) if n > pathwarden_core::store::max_on_disk(entry.bytes) => {
            return Err(format!("it is damaged: {} changed", entry.name))
        }
        Ok(Some(_)) => {}
        Ok(None) => return Err(format!("{} is missing", entry.name)),
        Err(e) => return Err(format!("{e:#}")),
    }
    let bytes = store
        .read_bundle_file(id, &entry.name)
        .map_err(|e| format!("{e:#}"))?
        .ok_or_else(|| format!("{} is missing", entry.name))?;
    if bytes.len() as u64 != entry.bytes || sha256_hex(&bytes) != entry.sha256 {
        return Err(format!("it is damaged: {} changed", entry.name));
    }
    Ok(bytes)
}

/// The report a run whose report was left out shows: what is missing.
fn left_out_report(left: &LeftOut) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Report left out</title></head>\
         <body style=\"font-family:system-ui,sans-serif;margin:32px\"><p>The report isn't \
         available: {} was {}, {}.</p></body></html>",
        crate::pages::esc(&left.name),
        pathwarden_core::diagnostics::bytes(left.bytes),
        crate::pages::esc(&left.why)
    )
}

/// Loads full run `id` from the history into a folder here.
fn load_one(
    ws: &Workspace,
    store: &Store,
    id: &str,
    m: &Manifest,
    manifest_sha256: String,
    from: (&str, Option<&str>),
    folder: &str,
) -> Result<(), String> {
    let mut extra: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut summary: Option<RunSummary> = None;
    let mut report: Option<String> = None;
    for entry in &m.files {
        let Some(name) = BUNDLE_FILES.iter().find(|n| **n == entry.name) else {
            return Err(format!("it names a file it may not hold ({})", entry.name));
        };
        let bytes = checked_file(store, id, entry, m.file_limit())?;
        match *name {
            MANIFEST_FILE => {}
            SUMMARY_FILE => {
                summary = Some(
                    serde_json::from_slice(&bytes)
                        .map_err(|e| format!("its summary can't be read ({e})"))?,
                )
            }
            REPORT_GZ => {
                use std::io::Read as _;
                let mut out = Vec::new();
                flate2::read::GzDecoder::new(bytes.as_slice())
                    .take(crate::run_data::MAX_GZ_BYTES + 1)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("its report can't be read ({e})"))?;
                if out.len() as u64 > crate::run_data::MAX_GZ_BYTES {
                    return Err("its report is too large".into());
                }
                report =
                    Some(String::from_utf8(out).map_err(|_| "its report isn't text".to_string())?);
            }
            other => extra.push((other, bytes)),
        }
    }
    let mut s = summary.ok_or("it has no summary")?;
    let report = match report {
        Some(r) => r,
        None => match m.left_out.iter().find(|l| l.name == REPORT_GZ) {
            Some(l) => left_out_report(l),
            None => return Err("it has no report".into()),
        },
    };
    s.id = folder.to_string();
    s.demo = false;
    // Its dates are the repository's: at most now, so a run dated in the
    // future can't stay the latest anywhere.
    let now = pathwarden_core::analyze::now();
    s.created_at = s.created_at.min(now);
    s.collected_at = s.collected_at.map(|t| t.min(now));
    s.environment = (!ws.is_default_env()).then(|| ws.env_id().to_string());
    s.assigned = None;
    if let Some(c) = &mut s.collection {
        c.kept = None;
    }
    s.history = Some(crate::workspace::HistoryLink {
        run_id: Some(id.to_string()),
        ..Default::default()
    });
    s.shared = Some(SharedFrom {
        remote: from.0.to_string(),
        branch: from.1.map(str::to_string),
        recorded_by: m.recorded_by.clone(),
        recorded_on: m.recorded_on.clone(),
        recorded_from: m.recorded_from.clone(),
        pathwarden: m.pathwarden.clone(),
        mirrored_at: now,
        manifest_sha256,
        left_out: m.left_out.clone(),
    });
    extra.push((
        LOADED_MARKER,
        format!("Loaded from {} (run {id}).\n", from.0).into_bytes(),
    ));
    // A changed run loaded again keeps what was done with it here: its
    // retests and its label.
    let mut retests: Option<Vec<u8>> = None;
    if let Some(dir) = ws.run_dir(folder) {
        // Only a run loaded before is replaced: runs recorded here never
        // are, even one whose folder name happens to be the same.
        if !loaded_run_dir(&dir) {
            return Err(format!(
                "a run made on this computer has the same ID ({folder})"
            ));
        }
        retests = std::fs::read(dir.join(crate::retest_ui::RETESTS_FILE)).ok();
        if let Some(label) = ws.run(folder).and_then(|old| old.label) {
            s.label = Some(label);
        }
        ws.delete_run(folder).map_err(|e| format!("{e:#}"))?;
    }
    ws.save_run_with(&s, &report, &extra)
        .map_err(|e| format!("{e:#}"))?;
    if let (Some(bytes), Some(dir)) = (retests, ws.run_dir(folder)) {
        std::fs::write(dir.join(crate::retest_ui::RETESTS_FILE), bytes)
            .map_err(|e| format!("{e:#}"))?;
    }
    Ok(())
}

/// Loads the history's full runs into this environment's runs, so each
/// opens here as on the computer that recorded it (report, Explore,
/// findings, retest): each full run with a point in the history, of a
/// format this version knows, that isn't a run of this computer's own or
/// hidden here. Its files are checked against its manifest; one that
/// changed is loaded again. Runs loaded earlier whose full run or point is
/// gone from the history are removed here (only folders this made). Call
/// after a pull, with the history's lock held.
pub fn mirror(ws: &Workspace, loc: &crate::history_ui::Location) -> Mirrored {
    let mut out = Mirrored::default();
    let store = &loc.store;
    let (source, branch) = match &loc.git {
        Some((remote, branch)) => (remote.clone(), Some(branch.as_str())),
        None => (loc.dir.display().to_string(), None),
    };
    let bundles = store.bundles();
    let runs = ws.runs();
    let loaded_here: Vec<&RunSummary> = runs.iter().filter(|r| r.shared.is_some()).collect();
    if bundles.is_empty() && loaded_here.is_empty() {
        return out;
    }
    if let Err(e) = pathwarden_core::store::check_readable(&store.dir) {
        out.unreadable = Some(format!("{e:#}"));
        return out;
    }
    let points: std::collections::HashSet<String> = store
        .list_state_files("history")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            r.strip_prefix("history/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .collect();
    let hidden = hidden(ws);
    // Runs of this computer's own, by history run ID: never replaced.
    let own: std::collections::HashSet<String> = ws
        .all_runs()
        .into_iter()
        .filter(|r| r.shared.is_none())
        .filter_map(|r| r.history.and_then(|h| h.run_id))
        .collect();
    let mut keep: Vec<String> = Vec::new();
    for id in &bundles {
        if !points.contains(id) || own.contains(id) || hidden.contains(id) {
            continue;
        }
        let Some(folder) = mirror_folder_id(&source, id) else {
            continue;
        };
        // Its folder here is a newer Pathwarden's: never written into
        // (docs/dev/formats.md). Counted, and said once.
        if crate::workspace::is_newer_folder(&ws.runs_dir().join(&folder)) {
            out.newer_here += 1;
            continue;
        }
        let bytes = match read_manifest(store, id) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(why) => {
                out.failed.push((id.clone(), why));
                continue;
            }
        };
        let sha = sha256_hex(&bytes);
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                pathwarden_core::logs::session_line(&format!("Full run {id}: run.json: {e}"));
                out.failed.push((id.clone(), "it is damaged".into()));
                continue;
            }
        };
        match manifest_kind(&value) {
            ManifestKind::Ours => {}
            ManifestKind::Newer(version) => {
                out.newer.push((id.clone(), version));
                continue;
            }
            ManifestKind::Foreign => {
                out.failed
                    .push((id.clone(), "it isn't a Pathwarden full run".into()));
                continue;
            }
        }
        let m: Manifest = match serde_json::from_value::<Manifest>(value) {
            Ok(m) if m.run_id == *id => m,
            Ok(_) => {
                out.failed
                    .push((id.clone(), "it is damaged (it names another run)".into()));
                continue;
            }
            Err(e) => {
                pathwarden_core::logs::session_line(&format!("Full run {id}: run.json: {e}"));
                out.failed.push((id.clone(), "it is damaged".into()));
                continue;
            }
        };
        keep.push(folder.clone());
        let same = loaded_here
            .iter()
            .any(|r| r.id == folder && r.shared.as_ref().is_some_and(|s| s.manifest_sha256 == sha));
        if same {
            continue;
        }
        match load_one(ws, store, id, &m, sha, (&source, branch), &folder) {
            Ok(()) => out.loaded.push(id.clone()),
            Err(why) => out.failed.push((id.clone(), why)),
        }
    }
    // A full run that couldn't be loaded keeps what was loaded before.
    for r in loaded_here {
        let gone = !keep.contains(&r.id)
            && !out
                .failed
                .iter()
                .any(|(id, _)| mirror_folder_id(&source, id).as_deref() == Some(r.id.as_str()));
        if gone && ws.delete_run(&r.id).unwrap_or(false) {
            out.removed += 1;
            out.removed_ids.push(r.id.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a folder that holds a loaded run may be replaced by loading:
    /// one with this computer's own run, or one that can't be told, never.
    #[test]
    fn only_a_loaded_run_folder_is_replaced() {
        let dir = std::env::temp_dir().join(format!("pw-loaded-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!loaded_run_dir(&dir), "nothing in it");
        let own = run("r1", None);
        std::fs::write(
            dir.join(crate::workspace::SUMMARY_FILE),
            serde_json::to_vec(&own).unwrap(),
        )
        .unwrap();
        assert!(!loaded_run_dir(&dir), "a run made here");
        std::fs::write(dir.join(LOADED_MARKER), b"Loaded.\n").unwrap();
        assert!(loaded_run_dir(&dir));
        std::fs::remove_file(dir.join(LOADED_MARKER)).unwrap();
        std::fs::write(dir.join(crate::workspace::LOADED_SUMMARY_FILE), b"{}").unwrap();
        assert!(loaded_run_dir(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn run(id: &str, state: Option<FullRunState>) -> RunSummary {
        let mut r: RunSummary = serde_json::from_value(serde_json::json!({
            "id": "folder", "created_at": 0, "source": "x", "demo": false,
            "domains": [], "objects": 0, "files": 0, "exposure_percent": 0.0,
            "exposed": 0, "population": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0, "suppressed": 0,
            "plan_steps": 0, "pathwarden": "0",
        }))
        .unwrap();
        r.history = Some(crate::workspace::HistoryLink {
            run_id: Some(id.to_string()),
            full_run: state.map(|state| FullRunLink {
                state,
                why: None,
                left_out: Vec::new(),
            }),
            ..Default::default()
        });
        r
    }

    /// The trim to the latest full runs never removes a newer Pathwarden's
    /// (docs/dev/formats.md), and does remove an older one of ours.
    #[test]
    fn the_trim_leaves_a_newer_full_run() {
        let dir = std::env::temp_dir().join(format!("pw-trim-newer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("history")).unwrap();
        let config = pathwarden_core::config::StateConfig {
            path: Some(dir.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let store = Store::new(&config, None).unwrap();
        let runs = [
            ("20261001T000000.000Z", 1),
            ("20261002T000000.000Z", 99),
            ("20261003T000000.000Z", 1),
        ];
        for (id, format) in runs {
            std::fs::write(dir.join(format!("history/{id}.json")), "{}").unwrap();
            let folder = dir.join("runs").join(id);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join(MANIFEST_FILE),
                serde_json::json!({"schema": SCHEMA, "format": format, "pathwarden": "9.0"})
                    .to_string(),
            )
            .unwrap();
        }
        let (_, _, _, removed) = write_all(&store, &[], 1).unwrap();
        assert_eq!(removed, 1);
        assert!(!dir.join("runs/20261001T000000.000Z").exists());
        assert!(dir.join("runs/20261002T000000.000Z/run.json").is_file());
        assert!(dir.join("runs/20261003T000000.000Z/run.json").is_file());

        // Writing a full run over a newer one: refused by the write, and
        // skipped (not an error) by a write of several.
        let id = "20261002T000000.000Z";
        let manifest = dir.join("runs").join(id).join(MANIFEST_FILE);
        let before = std::fs::read(&manifest).unwrap();
        let bundle = || Bundle {
            manifest: Manifest {
                schema: SCHEMA.into(),
                format: FORMAT,
                run_id: id.into(),
                pathwarden: "0.2.0".into(),
                recorded_by: None,
                recorded_on: None,
                recorded_from: "cli".into(),
                folder: None,
                finished_at: 1,
                settings_sha256: None,
                files: Vec::new(),
                left_out: Vec::new(),
                max_file_bytes: None,
            },
            files: vec![(SUMMARY_FILE, b"{}".to_vec())],
        };
        let e = bundle().write(&store).unwrap_err();
        assert!(
            e.to_string().contains("was saved by a newer Pathwarden"),
            "{e}"
        );
        let (shared, skipped, _, _) = write_all(&store, &[bundle()], 5).unwrap();
        assert!(shared.is_empty());
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(skipped[0].0, id);
        assert_eq!(std::fs::read(&manifest).unwrap(), before);
        assert!(!dir.join("runs").join(id).join(SUMMARY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A full run says it has account lists only when it keeps them.
    #[test]
    fn the_lists_are_claimed_only_when_kept() {
        let mut summary = run("20261003T000000.000Z", None);
        summary.tier_zero_lists = true;
        let lists = |limit: u64| {
            let b = Bundle::build(
                Parts {
                    run_id: "20261003T000000.000Z",
                    summary: &summary,
                    report_html: "<html></html>",
                    extra: vec![(crate::run_data::EXPOSED_FILE, vec![b'x'; 100])],
                    config_text: None,
                    recorded_from: "cli",
                    folder: None,
                },
                limit,
            );
            let (_, bytes) = b.files.iter().find(|(n, _)| *n == SUMMARY_FILE).unwrap();
            let s: RunSummary = serde_json::from_slice(bytes).unwrap();
            let kept = b
                .files
                .iter()
                .any(|(n, _)| *n == crate::run_data::EXPOSED_FILE);
            (s.tier_zero_lists, kept)
        };
        assert_eq!(lists(1000), (true, true));
        assert_eq!(lists(50), (false, false));
    }

    /// Which runs of this computer say their full run is waiting.
    #[test]
    fn which_full_runs_are_waiting() {
        let waiting = |r: &RunSummary, f: &BundleFacts, keep: bool| {
            let w = waiting_state(r, f, keep);
            // Made again from its folder unless committed here already.
            if let Some(again) = w {
                assert_eq!(again, !f.held.contains(&r.run_id()), "{r:?}");
            }
            w.is_some()
        };
        let facts = BundleFacts {
            held: ["20261002T000000.000Z".to_string()].into_iter().collect(),
            oldest: Some("20261002T000000.000Z".into()),
            kept: 1,
            pushes: true,
            ..BundleFacts::default()
        };
        let newer = "20261003T000000.000Z";
        let older = "20261001T000000.000Z";
        for state in [
            FullRunState::Pending,
            FullRunState::Unpushed,
            FullRunState::NotShared,
        ] {
            assert!(waiting(&run(newer, Some(state)), &facts, true), "{state:?}");
            // Older than every full run kept: it would be trimmed at once.
            assert!(
                !waiting(&run(older, Some(state)), &facts, true),
                "{state:?}"
            );
            // Not kept in full, or only read here.
            assert!(!waiting(&run(newer, Some(state)), &facts, false));
            let reader = BundleFacts {
                pushes: false,
                ..facts.clone()
            };
            assert!(!waiting(&run(newer, Some(state)), &reader, true));
        }
        assert!(!waiting(
            &run(newer, Some(FullRunState::Shared)),
            &facts,
            true
        ));
        assert!(!waiting(&run(newer, None), &facts, true));
        // Committed here: waiting while the commit is.
        let held = "20261002T000000.000Z";
        let committed = BundleFacts {
            unpushed: true,
            ..facts.clone()
        };
        assert!(waiting(
            &run(held, Some(FullRunState::Unpushed)),
            &committed,
            true
        ));
        assert!(!waiting(
            &run(held, Some(FullRunState::Unpushed)),
            &facts,
            true
        ));
        assert_eq!(WAITING_WORDS, "Its full run is waiting to be shared.");
    }

    /// A run in the history in full, with files left out, may have
    /// them added: only from the computer that writes the history, and
    /// only while the history keeps its full run.
    #[test]
    fn which_full_runs_may_be_filled_in() {
        let held = |ids: &[&str], kept: usize| BundleFacts {
            held: ids.iter().map(|s| s.to_string()).collect(),
            oldest: ids.first().map(|s| s.to_string()),
            kept,
            pushes: true,
            ..BundleFacts::default()
        };
        let id = "20261002T000000.000Z";
        let left = |mut r: RunSummary, words: &[&str]| {
            if let Some(f) = r.history.as_mut().and_then(|h| h.full_run.as_mut()) {
                f.left_out = words.iter().map(|s| s.to_string()).collect();
            }
            r
        };
        let shared = left(
            run(id, Some(FullRunState::Shared)),
            &["objects.json.gz (50 MB)"],
        );
        let facts = held(&[id], 5);
        assert!(refill_state(&shared, &facts, true));
        // Nothing left out; not kept in full; only read here.
        assert!(!refill_state(
            &run(id, Some(FullRunState::Shared)),
            &facts,
            true
        ));
        assert!(!refill_state(&shared, &facts, false));
        let reader = BundleFacts {
            pushes: false,
            ..facts.clone()
        };
        assert!(!refill_state(&shared, &reader, true));
        // Not in the history in full, or a newer Pathwarden's.
        assert!(!refill_state(&shared, &held(&[], 5), true));
        let newer = BundleFacts {
            newer: [id.to_string()].into_iter().collect(),
            ..facts.clone()
        };
        assert!(!refill_state(&shared, &newer, true));
        // Trimmed with the next full run: two newer ones and a keep of 2.
        let trimmed = held(&[id, "20261003T000000.000Z", "20261004T000000.000Z"], 2);
        assert!(!refill_state(&shared, &trimmed, true));
        let kept = held(&[id, "20261003T000000.000Z"], 2);
        assert!(refill_state(&shared, &kept, true));
        // A run loaded from the history is never filled in from here.
        let mut loaded = shared.clone();
        loaded.shared = Some(SharedFrom {
            remote: "x".into(),
            branch: None,
            recorded_by: None,
            recorded_on: None,
            recorded_from: "cli".into(),
            pathwarden: "0".into(),
            mirrored_at: 0,
            manifest_sha256: String::new(),
            left_out: Vec::new(),
        });
        assert!(!refill_state(&loaded, &facts, true));
        assert_eq!(left_out_name("objects.json.gz (50 MB)"), "objects.json.gz");
    }

    /// The manifest records the limit its files were held to; one
    /// written before says nothing, and is held to 45 MB.
    #[test]
    fn the_manifest_records_its_limit() {
        let summary = run("20261003T000000.000Z", None);
        let b = Bundle::build(
            Parts {
                run_id: "20261003T000000.000Z",
                summary: &summary,
                report_html: "<html></html>",
                extra: vec![(crate::run_data::OBJECTS_FILE, vec![b'x'; 100])],
                config_text: None,
                recorded_from: "cli",
                folder: None,
            },
            75 << 20,
        );
        assert_eq!(b.manifest.max_file_bytes, Some(75 << 20));
        assert_eq!(b.manifest.file_limit(), 75 << 20);
        let mut old = b.manifest.clone();
        old.max_file_bytes = None;
        assert_eq!(old.file_limit(), 45 << 20);
        old.max_file_bytes = Some(u64::MAX);
        assert_eq!(old.file_limit(), MAX_FILE_BYTES);
        let text = serde_json::to_string(&b.manifest).unwrap();
        assert!(text.contains(r#""max_file_bytes":78643200"#), "{text}");
        assert_eq!(
            file_limit_words(95, true),
            "95 MB. GitHub refuses files over 100 MB, so a larger setting is held to 95 MB. \
             Larger files are left out of the full run and named on its page. Its numbers \
             are always kept."
        );
    }

    #[test]
    fn sources_lose_their_folders() {
        assert_eq!(scrub_source(r"C:\Users\ann\data\goad.zip"), "goad.zip");
        assert_eq!(
            scrub_source(r"C:\Users\Ann Smith\x\goad.zip and 2 more"),
            "goad.zip and 2 more"
        );
        assert_eq!(scrub_source("/home/ann/c/"), "c");
        assert_eq!(scrub_source("2 uploaded files"), "2 uploaded files");
        assert_eq!(
            scrub_source("Collected from north.sevenkingdoms.local (All, built-in)"),
            "Collected from north.sevenkingdoms.local (All, built-in)"
        );
        assert_eq!(
            scrub_path_words(r"wrote C:\Temp\x\out.zip and /var/tmp/y.json"),
            "wrote out.zip and y.json"
        );
        assert_eq!(scrub_path_words("kept in C:/Users/ann/x"), "kept in x");
        assert_eq!(
            scrub_path_words(r"can't read '\\srv\share' now"),
            "can't read 'share' now"
        );
        assert_eq!(
            scrub_path_words(r"wrote C:\Users\Ann Smith\x and stopped"),
            "wrote x and stopped"
        );
        assert_eq!(
            scrub_path_words(r#"see "C:\Program Files\Pathwarden\out.zip" for it"#),
            r#"see "out.zip" for it"#
        );
        assert_eq!(
            scrub_path_words("LDAP/SMB and/or Kerberos"),
            "LDAP/SMB and/or Kerberos"
        );
        for (given, want) in [
            (r"see file:C:\Users\ann\x.zip", "see file:x.zip"),
            (r"in `C:\Users\ann\x` now", "in `x` now"),
            (r"at <C:\Users\ann\x>", "at <x>"),
            (r"{C:\Users\ann\x}", "{x}"),
            (r"a;C:\Users\ann\x", "a;x"),
            ("open file:///C:/Users/ann/x.html", "open x.html"),
            (r"long \\?\C:\Users\ann\x", "long x"),
            (r"share \\?\UNC\srv\share\x", "share x"),
            ("this and / or that", "this and / or that"),
            ("ratio 3:2 and http://host/x", "ratio 3:2 and http://host/x"),
        ] {
            assert_eq!(scrub_path_words(given), want, "{given}");
        }
    }

    /// A domain's failure goes into the shared summary without the
    /// local paths its detail named.
    #[test]
    fn domain_failures_lose_their_folders() {
        let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
            "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
            "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
            "tier_zero_population": 100, "tier_zero_objects": 1,
            "protection_score": null,
            "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
                "resolved": 0},
            "recorded_by": "app",
        }))
        .unwrap();
        let mut s = crate::history_ui::point_summary(&p, &[]);
        s.collection = Some(crate::workspace::CollectionInfo {
            read_started: None,
            method: "builtin".into(),
            scope: "dc-only".into(),
            domain: "contoso.local".into(),
            server: None,
            ldaps: true,
            current_user: false,
            warnings: Vec::new(),
            kept: None,
            kerberos_only: Some(true),
            smb_signing: Some(true),
            domains: vec![crate::workspace::DomainOutcome {
                domain: "FABRIKAM.COM".into(),
                collected: false,
                objects: None,
                seconds: Some(3),
                reason: Some("The collection failed.".into()),
                detail: Some(r"cannot create C:\Users\Ann Smith\out\fabrikam.com: denied".into()),
            }],
        });
        let r = redact_summary(&s);
        let d = &r.collection.unwrap().domains[0];
        assert_eq!(
            d.detail.as_deref(),
            Some("cannot create fabrikam.com: denied")
        );
        assert_eq!(d.reason.as_deref(), Some("The collection failed."));
    }

    #[test]
    fn messages_say_what_and_how_big() {
        assert_eq!(
            message(&["20261009T021000.042Z".into()], 2_200_000, 0),
            "pathwarden run 20261009T021000.042Z: full run (2.1 MB)"
        );
        assert_eq!(
            message(&["a".into(), "b".into()], 2048, 1),
            "pathwarden: 2 full runs (2.0 KB); 1 older full run removed"
        );
    }
}
