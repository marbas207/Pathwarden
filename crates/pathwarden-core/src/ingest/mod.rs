//! Loads BloodHound collector output (loose `.json` files, `.zip` archives, or
//! directories of either) into an [`AdGraph`].

mod azurehound;
mod budget;
mod opengraph;
pub mod peek;
pub mod raw;
mod stream;

pub use opengraph::{OgIncomplete, OgLimits, OgSourceStats, OpenGraphStats};
pub use peek::{peek_domains, PeekedDomains};

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use petgraph::graph::NodeIndex;
use serde::Serialize;

use crate::graph::{normalize_id, AdGraph};
use crate::model::{
    AdcsProps, DcSetting, EdgeKind, Node, NodeKind, Props, UF_WORKSTATION_TRUST_ACCOUNT,
};
use crate::sid;
use budget::ObjectCost;
use raw::{RawAce, RawMeta, RawObject, TypedRef};

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to open archive {path}: {source}")]
    Zip {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },
    #[error("no BloodHound collector files found in the given inputs")]
    Empty,
    /// Collector files that hold no users or computers: an interrupted or
    /// failed collection, which would otherwise read as "nothing exposed".
    #[error(
        "the collector files hold no users or computers ({files}); the collection is incomplete or failed, so there is nothing to analyze"
    )]
    NoPrincipals { files: String },
    /// A report from another tool (PingCastle) that could not be used.
    #[error("failed to read {path}: {detail}")]
    External { path: PathBuf, detail: String },
    #[error(
        "{path} is too large to load safely ({detail}); extract the archive and check its contents"
    )]
    TooLarge { path: String, detail: String },
}

/// Largest single collector file accepted (uncompressed). Collector output for
/// very large forests stays well below this.
pub const MAX_ENTRY_BYTES: u64 = 4 << 30;
/// Compression ratio above which a large zip entry is treated as a zip bomb.
const MAX_RATIO: u64 = 200;
/// Entries up to this size are never held to [`MAX_RATIO`].
const RATIO_FREE_BYTES: u64 = 64 << 20;

/// Limits that keep hostile or broken input from exhausting memory or time.
/// The defaults leave ample room for very large real collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    /// Most entries a `.zip` may hold. Collector zips hold about ten.
    pub max_zip_entries: usize,
    /// Most bytes all the entries of one `.zip` may decompress to, counted
    /// as they are read (the sizes in the archive's headers are not trusted).
    pub max_archive_bytes: u64,
    /// Estimated memory one collector object may take while parsed. Larger
    /// objects are skipped and reported (see [`IngestStats::skipped_objects`]).
    pub max_object_bytes: u64,
    /// Limits for OpenGraph files.
    pub og: OgLimits,
}

impl Default for IngestLimits {
    fn default() -> Self {
        IngestLimits {
            max_zip_entries: 4096,
            max_archive_bytes: 64 << 30,
            max_object_bytes: 128 << 20,
            og: OgLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct TrustInfo {
    pub source: String,
    pub target: String,
    pub trust_type: String,
    pub direction: String,
    pub transitive: bool,
    pub sid_filtering: bool,
    /// Selective authentication ([`raw::RawTrust::selective_auth`]); `None`
    /// when the collector does not say.
    #[serde(default)]
    pub selective_auth: Option<bool>,
    /// The domains' SIDs, when known (`source` and `target` are names).
    #[serde(default)]
    pub source_sid: String,
    #[serde(default)]
    pub target_sid: String,
    /// The raw `trustAttributes`, when the collector gives them.
    #[serde(default)]
    pub trust_attributes: Option<u64>,
}

impl TrustInfo {
    /// Whether the trust stays inside one forest, by the same rule the
    /// graph's trust edges use ([`raw::is_same_forest_type`]).
    pub fn is_same_forest(&self) -> bool {
        raw::is_same_forest_type(&self.trust_type)
    }

    /// Whether SID history can be forged across the trust: a forest or
    /// external trust, in use, whose trusting side filters only RIDs under
    /// 1000 and the built-in SIDs from the other side (PW-012). The
    /// forest map asks it only of the trusting side's record of each way
    /// ([`crate::forest::TrustWay`]).
    pub fn sid_history_abusable(&self) -> bool {
        matches!(
            self.trust_type.to_ascii_lowercase().as_str(),
            "forest" | "external"
        ) && !self.sid_filtering
            && self.direction != "Disabled"
    }

    /// Whether this record's SID filtering is only the collector's
    /// `SidFilteringEnabled` flag on a forest trust, which can't tell: the
    /// flag only reports quarantine, which forest trusts don't use, and the
    /// trust attributes that would show SID history enabled
    /// (TREAT_AS_EXTERNAL) are not in the data.
    pub fn sid_filtering_flag_only(&self) -> bool {
        self.trust_attributes.is_none() && self.trust_type.eq_ignore_ascii_case("forest")
    }

    /// Whether `other` is this trust as the domain at its other end records
    /// it. Each side of a trust keeps its own trust object, so a collection
    /// of both domains lists the trust twice: A -> B and B -> A, of one
    /// type, the directions mirrored (Inbound on one side is Outbound on
    /// the other).
    pub fn is_other_side_of(&self, other: &TrustInfo) -> bool {
        let mirrored = matches!(
            (self.direction.as_str(), other.direction.as_str()),
            ("Bidirectional", "Bidirectional") | ("Inbound", "Outbound") | ("Outbound", "Inbound")
        );
        mirrored
            && self.source.eq_ignore_ascii_case(&other.target)
            && self.target.eq_ignore_ascii_case(&other.source)
            && self.trust_type.eq_ignore_ascii_case(&other.trust_type)
    }
}

/// Each trust once, in the order collected: a trust whose two domains were
/// both collected comes with its other side ([`TrustInfo::is_other_side_of`]),
/// which may differ in what it records (SID filtering is set on each side).
pub fn distinct_trusts(trusts: &[TrustInfo]) -> Vec<(&TrustInfo, Option<&TrustInfo>)> {
    let mut used = vec![false; trusts.len()];
    let mut out = Vec::new();
    for (i, t) in trusts.iter().enumerate() {
        if used[i] {
            continue;
        }
        used[i] = true;
        let other = (i + 1..trusts.len()).find(|&j| !used[j] && trusts[j].is_other_side_of(t));
        if let Some(j) = other {
            used[j] = true;
        }
        out.push((t, other.map(|j| &trusts[j])));
    }
    out
}

#[derive(Debug, Default, Serialize)]
pub struct IngestStats {
    pub files: Vec<String>,
    pub skipped_files: Vec<String>,
    /// Objects not ingested because they were too large to load safely
    /// (`file: object ID`). The collection is incomplete when this is not
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_objects: Vec<String>,
    pub objects: BTreeMap<String, usize>,
    pub deleted_objects: usize,
    /// ACE right names this version does not model yet; worth watching after
    /// collector upgrades.
    pub unmapped_rights: BTreeMap<String, usize>,
    pub trusts: Vec<TrustInfo>,
    /// When the data was collected, from collector file names (latest file).
    pub collected_at: Option<i64>,
    /// OpenGraph files read (see [`Ingestor::ingest_opengraph`]).
    #[serde(default, skip_serializing_if = "OpenGraphStats::is_empty")]
    pub opengraph: OpenGraphStats,
    /// PingCastle reports read (see [`crate::pingcastle`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pingcastle: Vec<crate::pingcastle::ReportInfo>,
    /// SYSVOL sidecars read (see [`crate::sysvol`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sysvol: Vec<crate::sysvol::SysvolStats>,
    /// Tier Zero settings files read (see [`crate::dcsettings`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dc_settings: Vec<crate::dcsettings::DcSettingsStats>,
    /// The certification authorities those files hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_settings: Vec<crate::dcsettings::CaSettingsStats>,
    /// The management agents those files read on their hosts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_probes: Vec<crate::hostprobe::ProbeStats>,
    /// Tier Zero settings folders that could not be opened, with why
    /// ([`Ingestor::ingest_settings_folder`]). Never saved: it names the
    /// folders, and runs record file names only.
    #[serde(skip)]
    pub settings_folders_unread: Vec<(String, String)>,
    /// Settings folders that hit a cap ([`FolderLimits`]): what was left
    /// out, with the folder. Never saved, as the above.
    #[serde(skip)]
    pub settings_folder_warnings: Vec<String>,
    /// Stored credentials sidecars read (see [`crate::storedcreds`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stored_credentials: Vec<crate::storedcreds::StoredStats>,
}

/// SharpHound's GPOLocalGroup collection method (`CollectionMethod`, 1 << 2).
const GPO_LOCAL_GROUP: u64 = 1 << 2;

/// SharpHound's methods that read sessions (`CollectionMethod`): Session,
/// LoggedOn, SessionLoop and LoggedOnLoop.
const SESSION_METHODS: u64 = 1 << 3 | 1 << 4 | 1 << 10 | 1 << 11;

/// SharpHound's methods that read local groups (`CollectionMethod`):
/// LocalAdmin, RDP, DCOM and PSRemote.
const LOCAL_GROUP_METHODS: u64 = 1 << 1 | 1 << 8 | 1 << 12 | 1 << 14;

/// The reason the built-in collector gives every session list of a
/// collection that contacts no computer (Quick, DC only). A computer whose
/// lists all say this, or say nothing (RustHound-CE 2.5.26 and later run
/// with DCOnly), was not asked for its sessions: the run did not target
/// them ([`crate::model::Props::sessions_targeted`]).
pub const NOT_CONTACTED: &str =
    "not collected: this collection does not contact computers (DC only)";

/// Why the built-in collector skipped a computer with Kerberos only:
/// its session lists' reasons say this ("WS01.CONTOSO.LOCAL: skipped: the
/// domain has no Kerberos name for it (no SPN cifs/...)").
pub const SKIP_NO_KERBEROS_NAME: &str = "the domain has no Kerberos name for it";

/// Why the built-in collector skipped a computer with SMB signing required,
/// as [`SKIP_NO_KERBEROS_NAME`].
pub const SKIP_UNSIGNED: &str = "its replies weren't signed";

/// Why the built-in collector skipped a computer whose reply answered
/// another request than the one sent, as [`SKIP_NO_KERBEROS_NAME`].
pub const SKIP_BAD_REPLY: &str = "its replies didn't answer Pathwarden's requests";

/// Why the built-in collector skipped a computer in another domain whose
/// trust allows only RC4 (Pathwarden uses AES), as
/// [`SKIP_NO_KERBEROS_NAME`].
pub const SKIP_RC4_TRUST: &str = "the trust to its domain allows only RC4";

/// The skip a computer's session list reasons record, if any.
fn host_skip(o: &RawObject) -> Option<crate::model::HostSkip> {
    let lists = [&o.sessions, &o.privileged_sessions, &o.registry_sessions];
    if lists.iter().any(|s| s.collected == Some(true)) {
        return None;
    }
    lists.iter().find_map(|s| {
        let why = s.failure_reason.as_deref()?;
        if why.contains(SKIP_NO_KERBEROS_NAME) {
            Some(crate::model::HostSkip::NoKerberosName)
        } else if why.contains(SKIP_UNSIGNED) {
            Some(crate::model::HostSkip::Unsigned)
        } else if why.contains(SKIP_BAD_REPLY) {
            Some(crate::model::HostSkip::BadReply)
        } else if why.contains(SKIP_RC4_TRUST) {
            Some(crate::model::HostSkip::Rc4Trust)
        } else {
            None
        }
    })
}

#[derive(Default)]
pub struct Ingestor {
    graph: AdGraph,
    stats: IngestStats,
    /// Work done reading files, in the units of [`work_bytes`].
    read: Arc<AtomicU64>,
    limits: IngestLimits,
    /// Files and directories already read (canonical paths), so a file
    /// given twice, or reached twice through links, is ingested once.
    seen: HashSet<PathBuf>,
    /// OpenGraph files and coverage sidecars waiting for the AD data.
    og: opengraph::OgQueue,
    /// SYSVOL sidecars waiting for the AD data: label, the sidecar or why
    /// it was refused, and notes on entries dropped while parsing.
    sysvol: Vec<SysvolQueued>,
    /// Tier Zero settings files waiting for the AD data.
    dc_settings: Vec<(String, crate::dcsettings::Sidecar, Vec<String>)>,
    /// Stored credentials sidecars waiting for the AD data.
    stored: Vec<(String, crate::storedcreds::Sidecar, Vec<String>)>,
    /// Enterprise CAs whose published templates the collector listed without
    /// identifiers (RustHound-CE up to 2.5.23), linked in [`Self::finish`].
    unresolved_publication: Vec<NodeIndex>,
    /// The current file's SharpHound collection methods (0: not said).
    methods: u64,
    /// The analysis's wall clock ([`crate::LoadOptions::now`]).
    now: Option<i64>,
    /// Keep every collector property ([`crate::LoadOptions::all_properties`]).
    all_properties: bool,
    /// Bytes read from settings folders so far ([`FolderLimits::total_bytes`]).
    folder_bytes: u64,
}

impl IngestStats {
    /// The Tier Zero settings files this data used, for the run record
    /// ([`crate::dcsettings::settings_files`]); `now` stands in for an
    /// unknown collection time.
    pub fn settings_files(&self, now: i64) -> Vec<crate::dcsettings::SettingsFileUse> {
        crate::dcsettings::settings_files(
            &self.dc_settings,
            &self.ca_settings,
            self.collected_at,
            now,
        )
    }
}

/// What the ends of a `.json` file say it is (the UI's Detected sources
/// panel, before anything is analyzed). The same tests the reader uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniffed {
    /// SharpHound or RustHound-CE data, with its `meta.type` (`users`, ...).
    Collector(String),
    /// An OpenGraph file, with `metadata.source_kind` when it is in sight.
    OpenGraph {
        source_kind: Option<String>,
    },
    Unknown,
}

/// How many bytes of each end [`sniff`] looks at.
pub const SNIFF_BYTES: usize = stream::PEEK;

/// Recognises a collector file from its first and last [`SNIFF_BYTES`].
pub fn sniff(head: &[u8], tail: &[u8]) -> Sniffed {
    if let Some(meta) = stream::find_meta(head, tail) {
        return Sniffed::Collector(meta.kind);
    }
    match stream::find_opengraph(head, tail) {
        Some(og) => Sniffed::OpenGraph {
            source_kind: og.source_kind,
        },
        None => Sniffed::Unknown,
    }
}

/// Refuses a zip unless every entry's local header agrees with the central
/// directory (name, sizes, CRC, method, flags), no two entries share a name
/// or bytes, and nothing sits between entries that a local-header reader
/// would take for another file. Otherwise Pathwarden (which reads the
/// central directory) and a tool that walks local headers would see
/// different contents in the same archive ("zip cloaking"). Check the
/// entry count first: this reads every entry's local header.
pub fn check_zip<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> zip::result::ZipResult<()> {
    archive.validate_header_consistency()
}

/// An entry's name as text (`""` when it isn't valid in its encoding).
pub fn entry_name<R: Read + ?Sized>(entry: &zip::read::ZipFile<'_, R>) -> String {
    entry.name().map(|n| n.into_owned()).unwrap_or_default()
}

type SysvolQueued = (String, Result<crate::sysvol::Sidecar, String>, Vec<String>);

/// How much reading `paths` is, in bytes, for progress: a `.json` file
/// counts its size; a `.zip` entry is read twice (once to find its `meta`
/// block, once to parse it), the first, much cheaper pass counted at a
/// quarter. Unreadable inputs count zero.
pub fn work_bytes(paths: &[PathBuf]) -> u64 {
    let mut seen = HashSet::new();
    paths
        .iter()
        .filter_map(|p| input_files(p, &mut Vec::new()).ok())
        .flatten()
        .filter(|f| seen.insert(canonical(f)))
        .map(|f| work_bytes_of(&f))
        .sum()
}

/// The files an analysis of `paths` reads, each once, with the input it
/// came from: a file as given, the `.json` and `.zip` files below a folder
/// (links not followed), as [`work_bytes`] and the loader pick them.
/// Unreadable inputs are left out.
pub fn files_read(paths: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        for f in input_files(p, &mut Vec::new()).unwrap_or_default() {
            if seen.insert(canonical(&f)) {
                out.push((p.clone(), f));
            }
        }
    }
    out
}

fn work_bytes_of(path: &Path) -> u64 {
    let Ok(meta) = fs::metadata(path) else {
        return 0;
    };
    match extension(path).as_str() {
        "json" => meta.len(),
        "zip" => {
            let Ok(file) = File::open(path) else {
                return 0;
            };
            let Ok(mut archive) = zip::ZipArchive::new(BufReader::new(file)) else {
                return 0;
            };
            (0..archive.len())
                .filter_map(|i| {
                    archive
                        .by_index_raw(i)
                        .ok()
                        .map(|e| (entry_name(&e).to_ascii_lowercase(), e.size()))
                })
                .filter(|(name, _)| name.ends_with(".json"))
                .map(|(_, size)| size + size / FIRST_PASS_SHARE)
                .sum()
        }
        _ => 0,
    }
}

/// A path made absolute and free of links, to recognise a file or folder
/// reached twice; the path as given when that fails.
fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// What one settings folder may cost ([`Ingestor::ingest_settings_folder_with`]).
#[derive(Debug, Clone)]
pub struct FolderLimits {
    /// Entries looked at in the folder (of any name).
    pub max_entries: usize,
    /// Settings files read from it.
    pub max_files: usize,
    /// Bytes read from it.
    pub folder_bytes: u64,
    /// Bytes read from every settings folder of an analysis.
    pub total_bytes: u64,
    /// How long the folder has to answer.
    pub timeout: std::time::Duration,
}

impl Default for FolderLimits {
    fn default() -> Self {
        FolderLimits {
            max_entries: 100_000,
            max_files: 4_096,
            folder_bytes: 64 << 20,
            total_bytes: 256 << 20,
            timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// One settings file a folder held, as read on the folder's thread.
struct FolderFile {
    name: String,
    canonical: PathBuf,
    bytes: Result<Vec<u8>, String>,
    security: Option<crate::perms::FileSecurity>,
}

/// What a folder's thread read: its files, and caps it hit.
struct FolderRead {
    files: Vec<FolderFile>,
    warnings: Vec<String>,
}

/// Lists and reads one settings folder (on its own thread): only plain
/// files directly in it with a settings file's name, files named for a
/// `known` host first, then by name, within `limits` and `budget` bytes.
fn read_settings_folder(
    dir: &Path,
    known: &HashSet<String>,
    limits: &FolderLimits,
    budget: u64,
) -> Result<FolderRead, String> {
    // The folder itself is the one configured, wherever it leads (a DFS
    // path may be a link); what is in it is never followed.
    match fs::metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err("it is not a folder".into()),
        Err(e) => return Err(e.to_string()),
    }
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    let mut names: Vec<(bool, String, PathBuf)> = Vec::new();
    let mut looked = 0usize;
    for e in entries {
        looked += 1;
        if looked > limits.max_entries {
            warnings.push(format!(
                "it holds more than {} entries; the rest weren't looked at",
                limits.max_entries
            ));
            break;
        }
        let Ok(e) = e else { continue };
        // The entry itself, not what a link points at.
        if !e.file_type().is_ok_and(|t| t.is_file() && !t.is_symlink()) {
            continue;
        }
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !crate::dcsettings::is_folder_file_name(&name) {
            continue;
        }
        let host = name
            .to_ascii_uppercase()
            .trim_start_matches("PATHWARDEN-TIERZERO-")
            .split('.')
            .next()
            .unwrap_or_default()
            .to_string();
        names.push((!known.contains(&host), name, e.path()));
    }
    // Known hosts first, then by name: the caps cut planted names, never
    // the servers the collection has.
    names.sort();
    if names.len() > limits.max_files {
        warnings.push(format!(
            "it holds {} settings files; only {} were read",
            names.len(),
            limits.max_files
        ));
        names.truncate(limits.max_files);
    }
    let cap = limits.folder_bytes.min(budget);
    let mut used = 0u64;
    let mut files = Vec::new();
    for (_, name, path) in names {
        if used >= cap {
            warnings.push(format!(
                "its settings files passed the {} MiB read for settings folders; the rest weren't read",
                cap >> 20
            ));
            break;
        }
        let mut security = None;
        let bytes = open_no_follow(&path)
            .map_err(|e| e.to_string())
            .and_then(|f| {
                // Opened, then checked again: still a plain file, not a link
                // put there since it was listed.
                match f.metadata() {
                    Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(f),
                    Ok(_) => Err("not a plain file".to_string()),
                    Err(e) => Err(e.to_string()),
                }
            })
            .and_then(|f| {
                // Who wrote it, from the handle that is read.
                security = crate::perms::file_security(&f);
                let limit = crate::dcsettings::MAX_SIDECAR_BYTES.min(cap - used);
                let mut b = Vec::new();
                f.take(limit + 1)
                    .read_to_end(&mut b)
                    .map_err(|e| e.to_string())?;
                if b.len() as u64 > limit {
                    Err("too large".to_string())
                } else {
                    Ok(b)
                }
            });
        used += bytes.as_ref().map_or(0, |b| b.len() as u64);
        files.push(FolderFile {
            canonical: canonical(&path),
            name,
            bytes,
            security,
        });
    }
    Ok(FolderRead { files, warnings })
}

/// Opens `path` for reading without following a link: on Windows a link
/// opens as the link itself (`FILE_FLAG_OPEN_REPARSE_POINT`), which the
/// caller then refuses as not a plain file.
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT.
        o.custom_flags(0x0020_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
}

/// The files to read for one input: a file as given, or every `.json` and
/// `.zip` file below a folder, in name order. Below a folder, links
/// (symlinks and junctions) are not followed (they are noted in `skipped`)
/// and each folder is read once, so a link loop can't make the walk endless
/// or read the same data twice.
fn input_files(path: &Path, skipped: &mut Vec<String>) -> Result<Vec<PathBuf>, IngestError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| IngestError::Io { path, source }
    };
    let mut out = Vec::new();
    if fs::metadata(path).map_err(io(path))?.is_dir() {
        let mut dirs = HashSet::new();
        walk(path, &mut dirs, &mut out, skipped)?;
    } else {
        out.push(path.to_path_buf());
    }
    return Ok(out);

    fn walk(
        dir: &Path,
        dirs: &mut HashSet<PathBuf>,
        out: &mut Vec<PathBuf>,
        skipped: &mut Vec<String>,
    ) -> Result<(), IngestError> {
        if !dirs.insert(canonical(dir)) {
            return Ok(());
        }
        let io = |source| IngestError::Io {
            path: dir.to_path_buf(),
            source,
        };
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(io)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for entry in entries {
            let ext = extension(&entry);
            let wanted = ext == "json" || ext == "zip";
            match fs::symlink_metadata(&entry) {
                Ok(meta) if meta.file_type().is_symlink() => skipped.push(format!(
                    "{} (a link; links inside a folder are not followed)",
                    entry.display()
                )),
                Ok(meta) if meta.is_dir() => walk(&entry, dirs, out, skipped)?,
                // Unreadable entries are tried, so the error is reported.
                Ok(_) | Err(_) if wanted => out.push(entry),
                _ => {}
            }
        }
        Ok(())
    }
}

/// A zip entry's first pass counts `1/FIRST_PASS_SHARE` of its bytes.
const FIRST_PASS_SHARE: u64 = 4;

/// Counts what passes through a reader, `1/share` of it.
struct Counted<'a, R> {
    inner: R,
    read: &'a AtomicU64,
    share: u64,
    carry: u64,
}

impl<'a, R> Counted<'a, R> {
    fn new(inner: R, read: &'a AtomicU64, share: u64) -> Self {
        Self {
            inner,
            read,
            share: share.max(1),
            carry: 0,
        }
    }
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.carry += n as u64;
        let whole = self.carry / self.share;
        if whole > 0 {
            self.read.fetch_add(whole, Ordering::Relaxed);
            self.carry -= whole * self.share;
        }
        Ok(n)
    }
}

impl Ingestor {
    pub fn new() -> Self {
        Self::default()
    }

    /// A counter of the bytes read so far (see [`work_bytes`]), to watch
    /// from another thread.
    pub fn bytes_read(&self) -> Arc<AtomicU64> {
        self.read.clone()
    }

    /// The graph and statistics, after stitching any OpenGraph files
    /// on (see [`Ingestor::ingest_opengraph`]).
    pub fn finish(mut self) -> (AdGraph, IngestStats) {
        self.link_unresolved_publication();
        self.ingest_opengraph();
        self.ingest_azurehound();
        self.ingest_sysvol();
        self.ingest_stored();
        self.ingest_dc_settings();
        (self.graph, self.stats)
    }

    /// A stored credentials sidecar's bytes, parsed and queued for
    /// [`Self::ingest_stored`]. Its NetBIOS names are kept at once, so
    /// OpenGraph files (TaskHound's `DOMAIN\user`) resolve with them.
    fn take_stored(&mut self, label: &str, bytes: Result<Vec<u8>, String>) {
        let mut notes = Vec::new();
        match bytes.and_then(|b| crate::storedcreds::Sidecar::parse(&b, &mut notes)) {
            Ok(s) => {
                self.graph.add_netbios(&s.netbios);
                self.stored.push((label.to_string(), s, notes));
            }
            Err(e) => self
                .stats
                .skipped_files
                .push(format!("{label} (stored credentials data: {e})")),
        }
    }

    /// Adds the queued stored credentials sidecars to the graph (after the
    /// AD data and the OpenGraph files, whose source list it extends).
    fn ingest_stored(&mut self) {
        let files = std::mem::take(&mut self.stored);
        if files.is_empty() {
            return;
        }
        let users = crate::storedcreds::UserIndex::new(&self.graph);
        for (label, s, notes) in files {
            let st = crate::storedcreds::apply(&mut self.graph, &label, s, notes, &users);
            self.stats.stored_credentials.push(st);
        }
    }

    /// A Tier Zero settings file's bytes, parsed and queued for
    /// [`Self::ingest_dc_settings`]. A file refused whole is noted now.
    fn take_dc_settings(&mut self, label: &str, bytes: Result<Vec<u8>, String>) {
        let mut notes = Vec::new();
        match bytes.and_then(|b| crate::dcsettings::Sidecar::parse(&b, &mut notes)) {
            Ok(s) => self.dc_settings.push((label.to_string(), s, notes)),
            Err(e) => self
                .stats
                .skipped_files
                .push(format!("{label} (Tier Zero settings: {e})")),
        }
    }

    /// Applies the queued Tier Zero settings files to their domain
    /// controllers (after the AD data, before the AD CS checks).
    fn ingest_dc_settings(&mut self) {
        let files = std::mem::take(&mut self.dc_settings);
        if files.is_empty() {
            return;
        }
        let now = self
            .now
            .unwrap_or_else(|| crate::findings::RuleSettings::default().now);
        self.stats.ca_settings = crate::dcsettings::apply_cas(
            &mut self.graph,
            &files,
            self.stats.collected_at,
            now,
            &mut self.stats.skipped_files,
        );
        self.stats.host_probes = crate::hostprobe::apply(
            &mut self.graph,
            &files,
            self.stats.collected_at,
            now,
            &mut self.stats.skipped_files,
        );
        self.stats.dc_settings = crate::dcsettings::apply_all(
            &mut self.graph,
            files,
            self.stats.collected_at,
            now,
            &mut self.stats.skipped_files,
        );
    }

    /// Reads the Tier Zero settings files in a settings folder: only
    /// regular files directly in it whose names pass
    /// [`crate::dcsettings::is_folder_file_name`], each within
    /// [`crate::dcsettings::MAX_SIDECAR_BYTES`]. Links and subfolders are
    /// never followed, and no other file is read, so a shared folder can't
    /// feed AD data in. Each file is labelled by its name alone: runs
    /// record file names, not the folder they came from. A folder that
    /// can't be opened is noted ([`IngestStats::settings_folders_unread`]),
    /// never an error.
    pub fn ingest_settings_folder(&mut self, dir: &Path) {
        self.ingest_settings_folder_with(dir, &FolderLimits::default());
    }

    /// [`Self::ingest_settings_folder`] within `limits`. The folder is read
    /// on a thread of its own: one that doesn't answer within
    /// `limits.timeout` (a share that hangs) counts as unread, so it can't
    /// hold up a scheduled run. Files named for a domain controller or CA
    /// host the collection has are read first, so names planted in the
    /// folder can't crowd them out of the caps.
    pub fn ingest_settings_folder_with(&mut self, dir: &Path, limits: &FolderLimits) {
        let label = dir.display().to_string();
        // The host of a share (`\\HOST\share\...`): a SYSTEM-owned file is
        // the server's own only on its own share.
        let share_host = label
            .strip_prefix(r"\\")
            .and_then(|r| r.split(['\\', '/']).next())
            .filter(|h| !h.is_empty())
            .map(str::to_ascii_uppercase);
        let known = self.known_hosts();
        let budget = limits.total_bytes.saturating_sub(self.folder_bytes);
        let (tx, rx) = std::sync::mpsc::channel();
        let (owned_dir, lim) = (dir.to_path_buf(), limits.clone());
        let spawned = std::thread::Builder::new()
            .name("settings-folder".into())
            .spawn(move || {
                let _ = tx.send(read_settings_folder(&owned_dir, &known, &lim, budget));
            });
        if let Err(e) = spawned {
            self.stats
                .settings_folders_unread
                .push((label, e.to_string()));
            return;
        }
        let read = match rx.recv_timeout(limits.timeout) {
            Ok(r) => r,
            Err(_) => {
                // The thread is left to finish on its own; nothing it reads
                // is used. At most one such thread per configured folder
                // per analysis (32 folders at most), each bounded by the
                // folder's caps, so the leak is bounded too.
                self.stats.settings_folders_unread.push((
                    label,
                    format!(
                        "it didn't answer within {} seconds",
                        limits.timeout.as_secs()
                    ),
                ));
                return;
            }
        };
        let read = match read {
            Ok(r) => r,
            Err(e) => {
                self.stats.settings_folders_unread.push((label, e));
                return;
            }
        };
        for w in read.warnings {
            self.stats
                .settings_folder_warnings
                .push(format!("{label}: {w}"));
        }
        for f in read.files {
            // Read once whichever way it was reached (a folder that is also
            // the collection's).
            if !self.seen.insert(f.canonical) {
                continue;
            }
            self.folder_bytes += f.bytes.as_ref().map_or(0, |b| b.len() as u64);
            self.read.fetch_add(
                f.bytes.as_ref().map_or(0, |b| b.len() as u64),
                Ordering::Relaxed,
            );
            let mut notes = Vec::new();
            match f
                .bytes
                .and_then(|b| crate::dcsettings::Sidecar::parse(&b, &mut notes))
            {
                Ok(mut s) => {
                    if !crate::dcsettings::name_matches_host(&f.name, &s) {
                        self.stats.skipped_files.push(format!(
                            "{} (Tier Zero settings: its name is for another host than the {} it describes)",
                            f.name,
                            s.dc.hostname.trim()
                        ));
                        continue;
                    }
                    s.origin = crate::dcsettings::Origin::Folder {
                        security: f.security,
                        share_host: share_host.clone(),
                    };
                    self.dc_settings.push((f.name, s, notes));
                }
                Err(e) => self
                    .stats
                    .skipped_files
                    .push(format!("{} (Tier Zero settings: {e})", f.name)),
            }
        }
    }

    /// The short host names (upper case) of the collection's domain
    /// controllers and Enterprise CA hosts, read so far.
    fn known_hosts(&self) -> HashSet<String> {
        let short = |s: &str| {
            s.split(['.', '@'])
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase()
        };
        self.graph
            .nodes()
            .filter_map(|(_, n)| match n.kind {
                NodeKind::Computer if n.is_dc => Some(short(&n.name)),
                NodeKind::EnterpriseCa => n
                    .adcs
                    .as_deref()
                    .and_then(|a| a.dnshostname.as_deref())
                    .map(short),
                _ => None,
            })
            .collect()
    }

    /// A SYSVOL sidecar's bytes, parsed and queued for [`Self::ingest_sysvol`].
    fn take_sysvol(&mut self, label: &str, bytes: Result<Vec<u8>, String>) {
        let mut notes = Vec::new();
        let parsed = bytes.and_then(|b| crate::sysvol::Sidecar::parse(&b, &mut notes));
        self.sysvol.push((label.to_string(), parsed, notes));
    }

    /// Adds the queued SYSVOL sidecars to the graph (after the AD data and
    /// the OpenGraph files, whose source list it extends).
    fn ingest_sysvol(&mut self) {
        for (label, parsed, notes) in std::mem::take(&mut self.sysvol) {
            match parsed {
                Ok(s) => {
                    let st = crate::sysvol::apply(&mut self.graph, &label, s, notes);
                    self.stats.sysvol.push(st);
                }
                Err(e) => self
                    .stats
                    .skipped_files
                    .push(format!("{label} (SYSVOL data: {e})")),
            }
        }
    }

    /// For a CA whose published templates were listed without identifiers,
    /// treats every template of its forest (same Public Key Services
    /// container) as published to it, and marks the CA so reports say the
    /// publication list was not collected. Over-reporting a template that is
    /// not published beats hiding ESC1-4 on every template that is. A CA
    /// that another collection resolved keeps only what that one says.
    fn link_unresolved_publication(&mut self) {
        let pks = |dn: &str| {
            dn.find("CN=PUBLIC KEY SERVICES,")
                .map(|at| dn[at..].to_string())
        };
        for ca in std::mem::take(&mut self.unresolved_publication) {
            let resolved = self
                .graph
                .inner()
                .edges_directed(ca, petgraph::Direction::Incoming)
                .any(|e| *e.weight() == EdgeKind::PublishedTo);
            if resolved {
                continue;
            }
            let Some(container) = self
                .graph
                .node(ca)
                .props
                .distinguishedname
                .as_deref()
                .and_then(pks)
            else {
                continue;
            };
            let templates: Vec<NodeIndex> = self
                .graph
                .nodes()
                .filter(|(_, n)| {
                    n.kind == NodeKind::CertTemplate
                        && n.props
                            .distinguishedname
                            .as_deref()
                            .and_then(pks)
                            .as_deref()
                            == Some(container.as_str())
                })
                .map(|(ix, _)| ix)
                .collect();
            for t in templates {
                self.graph.add_edge(t, ca, EdgeKind::PublishedTo);
            }
            if let Some(adcs) = self.graph.node_mut(ca).adcs.as_mut() {
                adcs.publishedtemplatesunresolved = true;
            }
        }
    }

    /// Reads up to `limit` bytes of a sidecar; an error when there is more.
    fn read_sidecar(&self, r: impl Read, limit: u64) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        let n = Counted::new(r.take(limit + 1), &self.read, 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if n as u64 > limit {
            Err("too large".to_string())
        } else {
            Ok(bytes)
        }
    }

    /// Uses `limits` instead of the defaults.
    pub fn with_limits(limits: IngestLimits) -> Self {
        Ingestor {
            limits,
            ..Self::default()
        }
    }

    /// Uses `now` as the wall clock (`None`: the system clock).
    pub fn with_now(mut self, now: Option<i64>) -> Self {
        self.now = now;
        self
    }

    /// Keeps every property the collector wrote on each node
    /// ([`crate::model::Props::extra`]), for Cypher queries.
    pub fn with_all_properties(mut self, all: bool) -> Self {
        self.all_properties = all;
        if all {
            self.graph.keep_all_properties();
        }
        self
    }

    /// Ingests a `.json` file, a `.zip` archive, or a folder of them (see
    /// [`input_files`]). A file already ingested is not read again.
    pub fn ingest_path(&mut self, path: &Path) -> Result<(), IngestError> {
        for file in input_files(path, &mut self.stats.skipped_files)? {
            if !self.seen.insert(canonical(&file)) {
                if crate::opengraph::coverage::is_sidecar_name(&file.to_string_lossy())
                    || crate::sysvol::is_sidecar_name(&file.to_string_lossy())
                    || crate::dcsettings::is_sidecar_name(&file.to_string_lossy())
                    || crate::storedcreds::is_sidecar_name(&file.to_string_lossy())
                {
                    continue;
                }
                self.stats
                    .skipped_files
                    .push(format!("{} (already read)", file.display()));
                continue;
            }
            match extension(&file).as_str() {
                "zip" => self.ingest_zip(&file)?,
                "json" => self.ingest_json_file(&file)?,
                _ => self
                    .stats
                    .skipped_files
                    .push(format!("{} (not .json or .zip)", file.display())),
            }
        }
        Ok(())
    }

    fn ingest_zip(&mut self, path: &Path) -> Result<(), IngestError> {
        let file = File::open(path).map_err(|source| IngestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let zip_err = |source| IngestError::Zip {
            path: path.to_path_buf(),
            source,
        };
        let archive_len = file.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        // The archive is opened (its central directory parsed) once, and
        // each entry read from it: reopening it per entry made reading
        // quadratic in the number of entries.
        let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(zip_err)?;
        if archive.len() > self.limits.max_zip_entries {
            return Err(IngestError::TooLarge {
                path: path.display().to_string(),
                detail: format!(
                    "{} entries, more than the {} allowed",
                    archive.len(),
                    self.limits.max_zip_entries
                ),
            });
        }
        check_zip(&mut archive).map_err(zip_err)?;
        // Bytes the entries may still decompress to, counted as read.
        let mut remaining = self.limits.max_archive_bytes;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(zip_err)?;
            let name = entry_name(&entry);
            if !name.to_ascii_lowercase().ends_with(".json") {
                continue;
            }
            let label = format!("{}!{}", path.display(), name);
            if crate::sysvol::is_sidecar_name(&label) {
                let limit = crate::sysvol::MAX_SIDECAR_BYTES.min(remaining);
                let size = entry.size();
                let read = self.read_sidecar(&mut entry, limit);
                self.read
                    .fetch_add(size / FIRST_PASS_SHARE, Ordering::Relaxed);
                remaining = remaining.saturating_sub(size.min(limit));
                drop(entry);
                self.take_sysvol(&label, read);
                continue;
            }
            if crate::storedcreds::is_sidecar_name(&label) {
                let limit = crate::storedcreds::MAX_SIDECAR_BYTES.min(remaining);
                let size = entry.size();
                let read = self.read_sidecar(&mut entry, limit);
                self.read
                    .fetch_add(size / FIRST_PASS_SHARE, Ordering::Relaxed);
                remaining = remaining.saturating_sub(size.min(limit));
                drop(entry);
                self.take_stored(&label, read);
                continue;
            }
            if crate::dcsettings::is_sidecar_name(&label) {
                let limit = crate::dcsettings::MAX_SIDECAR_BYTES.min(remaining);
                let size = entry.size();
                let read = self.read_sidecar(&mut entry, limit);
                self.read
                    .fetch_add(size / FIRST_PASS_SHARE, Ordering::Relaxed);
                remaining = remaining.saturating_sub(size.min(limit));
                drop(entry);
                self.take_dc_settings(&label, read);
                continue;
            }
            if crate::opengraph::coverage::is_sidecar_name(&label) {
                let limit = crate::opengraph::coverage::MAX_SIDECAR_BYTES.min(remaining);
                let size = entry.size();
                let mut bytes = Vec::new();
                let read = Counted::new((&mut entry).take(limit + 1), &self.read, 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|n| {
                        if n as u64 > limit {
                            Err("too large for a coverage file".to_string())
                        } else {
                            Ok(bytes)
                        }
                    });
                self.read
                    .fetch_add(size / FIRST_PASS_SHARE, Ordering::Relaxed);
                remaining = remaining.saturating_sub(size.min(limit));
                drop(entry);
                self.take_sidecar(&label, read);
                continue;
            }
            // Zip bombs: a tiny archive can claim (or truly hold) gigabytes.
            // Real collector files are large but compress at most ~20x.
            // The sizes in the headers are only a first check: what an entry
            // really decompresses to is counted below as it is read.
            let declared = entry.size();
            let compressed = entry.compressed_size().min(archive_len).max(1);
            if declared > MAX_ENTRY_BYTES
                || (declared > RATIO_FREE_BYTES && declared / compressed > MAX_RATIO)
            {
                return Err(IngestError::TooLarge {
                    path: label,
                    detail: format!("{declared} bytes uncompressed from {compressed} compressed"),
                });
            }
            let by_ratio = compressed.saturating_mul(MAX_RATIO).max(RATIO_FREE_BYTES);
            let allowed = MAX_ENTRY_BYTES.min(by_ratio).min(remaining);
            // First pass: the size, and the ends of the entry for its meta
            // block. Second pass: stream the objects.
            let (mut head, mut tail) = (Vec::new(), Vec::new());
            let first_pass =
                Counted::new((&mut entry).take(allowed + 1), &self.read, FIRST_PASS_SHARE);
            let size =
                stream::head_and_tail(first_pass, &mut head, &mut tail).map_err(|source| {
                    IngestError::Io {
                        path: PathBuf::from(&label),
                        source,
                    }
                })?;
            if size > allowed {
                let detail = if allowed == remaining {
                    format!(
                        "the archive decompresses to more than {} bytes in all",
                        self.limits.max_archive_bytes
                    )
                } else if allowed == MAX_ENTRY_BYTES {
                    format!("more than {MAX_ENTRY_BYTES} bytes uncompressed")
                } else {
                    format!(
                        "more than {allowed} bytes uncompressed from {compressed} compressed (declared {declared})"
                    )
                };
                return Err(IngestError::TooLarge {
                    path: label,
                    detail,
                });
            }
            remaining -= size;
            drop(entry);
            let meta = stream::find_meta(&head, &tail);
            if azurehound::is_azure(&meta) {
                let input = opengraph::OgInput::Zip {
                    path: path.to_path_buf(),
                    index: i,
                    size,
                    bom: has_bom(&head),
                };
                self.defer_azurehound(&label, input);
                continue;
            }
            if meta.is_none() {
                if let Some(og) = stream::find_opengraph(&head, &tail) {
                    let input = opengraph::OgInput::Zip {
                        path: path.to_path_buf(),
                        index: i,
                        size,
                        bom: has_bom(&head),
                    };
                    self.defer_opengraph(&label, input, og.source_kind);
                    continue;
                }
            }
            let Some(kind) = self.begin_file(&label, meta) else {
                continue;
            };
            let source = Source::Zip {
                archive: &mut archive,
                path,
                index: i,
                size,
                bom: has_bom(&head),
            };
            self.stream_objects(&label, kind, source)?;
        }
        Ok(())
    }

    /// Ingests one collector file. `label` is only used for messages.
    pub fn ingest_text(&mut self, label: &str, text: &str) -> Result<(), IngestError> {
        let bytes = text.trim_start_matches('\u{feff}').as_bytes();
        if crate::sysvol::is_sidecar_name(label) {
            self.take_sysvol(label, Ok(bytes.to_vec()));
            return Ok(());
        }
        if crate::dcsettings::is_sidecar_name(label) {
            self.take_dc_settings(label, Ok(bytes.to_vec()));
            return Ok(());
        }
        if crate::storedcreds::is_sidecar_name(label) {
            self.take_stored(label, Ok(bytes.to_vec()));
            return Ok(());
        }
        if crate::opengraph::coverage::is_sidecar_name(label) {
            self.take_sidecar(label, Ok(bytes.to_vec()));
            return Ok(());
        }
        let head = &bytes[..bytes.len().min(stream::PEEK)];
        let tail = &bytes[bytes.len().saturating_sub(stream::PEEK)..];
        let meta = stream::find_meta(head, tail);
        if azurehound::is_azure(&meta) {
            self.defer_azurehound(label, opengraph::OgInput::Text(Arc::from(bytes)));
            return Ok(());
        }
        if meta.is_none() {
            if let Some(og) = stream::find_opengraph(head, tail) {
                let input = opengraph::OgInput::Text(Arc::from(bytes));
                self.defer_opengraph(label, input, og.source_kind);
                return Ok(());
            }
        }
        let Some(kind) = self.begin_file(label, meta) else {
            return Ok(());
        };
        let mut de = serde_json::Deserializer::from_slice(bytes);
        let limit = self.limits.max_object_bytes;
        budget::reset();
        budget::keep_all_properties(self.all_properties);
        let parsed = stream::for_each_object(&mut de, limit, |o, cost| {
            self.take_object(label, kind, o, cost)
        });
        budget::keep_all_properties(false);
        parsed.map_err(|source| IngestError::Json {
            path: label.to_string(),
            source,
        })
    }

    /// An object from the parser: ingested, or noted when it was too large.
    fn take_object(&mut self, label: &str, kind: NodeKind, o: RawObject, cost: ObjectCost) {
        if cost.oversized {
            self.stats.skipped_objects.push(format!(
                "{label}: {} (over the {} MiB limit for one object)",
                if o.object_identifier.is_empty() {
                    "an object without an ID"
                } else {
                    &o.object_identifier
                },
                self.limits.max_object_bytes >> 20
            ));
        } else {
            self.ingest_object(kind, o);
        }
    }

    /// A `.json` file on disk, streamed: its meta block is read from the ends
    /// of the file, then the objects one at a time.
    fn ingest_json_file(&mut self, path: &Path) -> Result<(), IngestError> {
        let io = |source| IngestError::Io {
            path: path.to_path_buf(),
            source,
        };
        let mut file = File::open(path).map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        let label = path.display().to_string();
        if crate::sysvol::is_sidecar_name(&label) {
            let read = self.read_sidecar(&mut file, crate::sysvol::MAX_SIDECAR_BYTES);
            self.take_sysvol(&label, read);
            return Ok(());
        }
        if crate::storedcreds::is_sidecar_name(&label) {
            let read = self.read_sidecar(&mut file, crate::storedcreds::MAX_SIDECAR_BYTES);
            self.take_stored(&label, read);
            return Ok(());
        }
        if crate::dcsettings::is_sidecar_name(&label) {
            let read = self.read_sidecar(&mut file, crate::dcsettings::MAX_SIDECAR_BYTES);
            self.take_dc_settings(&label, read);
            return Ok(());
        }
        if crate::opengraph::coverage::is_sidecar_name(&label) {
            let limit = crate::opengraph::coverage::MAX_SIDECAR_BYTES;
            let mut bytes = Vec::new();
            let read = Counted::new((&mut file).take(limit + 1), &self.read, 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())
                .and_then(|n| {
                    if n as u64 > limit {
                        Err("too large for a coverage file".to_string())
                    } else {
                        Ok(bytes)
                    }
                });
            self.take_sidecar(&label, read);
            return Ok(());
        }
        if len > MAX_ENTRY_BYTES {
            return Err(IngestError::TooLarge {
                path: path.display().to_string(),
                detail: format!("{len} bytes"),
            });
        }
        let peek = stream::PEEK as u64;
        let mut head = Vec::new();
        (&mut file).take(peek).read_to_end(&mut head).map_err(io)?;
        let mut tail = Vec::new();
        file.seek(SeekFrom::Start(len.saturating_sub(peek)))
            .map_err(io)?;
        file.read_to_end(&mut tail).map_err(io)?;
        let meta = stream::find_meta(&head, &tail);
        if azurehound::is_azure(&meta) {
            drop(file);
            let input = opengraph::OgInput::File {
                path: path.to_path_buf(),
                bom: has_bom(&head),
            };
            self.defer_azurehound(&label, input);
            return Ok(());
        }
        if meta.is_none() {
            if let Some(og) = stream::find_opengraph(&head, &tail) {
                drop(file);
                let input = opengraph::OgInput::File {
                    path: path.to_path_buf(),
                    bom: has_bom(&head),
                };
                self.defer_opengraph(&label, input, og.source_kind);
                self.probe_sidecars(path);
                return Ok(());
            }
        }
        let Some(kind) = self.begin_file(&label, meta) else {
            return Ok(());
        };
        drop(file);
        let bom = has_bom(&head);
        self.stream_objects(
            &label,
            kind,
            Source::File {
                path: path.to_path_buf(),
                bom,
            },
        )
    }

    /// Parses objects on a second thread while this one builds the graph, so a
    /// file costs about the larger of the two rather than their sum. Objects
    /// arrive in file order (results stay deterministic) through a small
    /// bounded queue: at most a few batches, and at most about one object
    /// budget of parsed objects waiting ([`InFlight`]), so memory stays flat
    /// however the objects are sized.
    fn stream_objects(
        &mut self,
        label: &str,
        kind: NodeKind,
        source: Source,
    ) -> Result<(), IngestError> {
        const BATCH: usize = 512;
        type Batch = (Vec<(RawObject, ObjectCost)>, u64);
        let limit = self.limits.max_object_bytes;
        // A batch is sent once it holds BATCH objects or this much.
        let batch_bytes = (limit / 8).max(1);
        let (tx, rx) = std::sync::mpsc::sync_channel::<Batch>(8);
        let in_flight = InFlight::new(limit);
        let started = std::time::Instant::now();
        let mut building = std::time::Duration::ZERO;
        let read = self.read.clone();
        let all_properties = self.all_properties;
        let result = std::thread::scope(|scope| {
            let in_flight = &in_flight;
            let parser = scope.spawn(move || {
                budget::keep_all_properties(all_properties);
                source.read(|reader| {
                    budget::reset();
                    let counted = Counted::new(reader, &read, 1);
                    let reader = BufReader::with_capacity(1 << 20, budget::Tracked(counted));
                    let mut de = serde_json::Deserializer::from_reader(reader);
                    let mut batch = Vec::with_capacity(BATCH);
                    let mut bytes = 0u64;
                    let send = |batch: Vec<_>, bytes: u64| {
                        in_flight.acquire(bytes);
                        // Fails only if the builder stopped; nothing to do then.
                        if tx.send((batch, bytes)).is_err() {
                            in_flight.release(bytes);
                        }
                    };
                    let parsed = stream::for_each_object(&mut de, limit, |o, cost| {
                        bytes += cost.bytes;
                        batch.push((o, cost));
                        if batch.len() == BATCH || bytes >= batch_bytes {
                            let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
                            send(full, std::mem::take(&mut bytes));
                        }
                    });
                    if !batch.is_empty() {
                        send(batch, bytes);
                    }
                    parsed.map_err(|source| {
                        if budget::tripped() {
                            IngestError::TooLarge {
                                path: label.to_string(),
                                detail: format!(
                                    "an object larger than {} MiB",
                                    budget::HARD_FACTOR * (limit >> 20)
                                ),
                            }
                        } else {
                            IngestError::Json {
                                path: label.to_string(),
                                source,
                            }
                        }
                    })
                })
            });
            // Should building panic, the parser must not wait for room forever.
            let _close = in_flight.closer();
            for (batch, bytes) in rx {
                let t = std::time::Instant::now();
                for (o, cost) in batch {
                    self.take_object(label, kind, o, cost);
                }
                in_flight.release(bytes);
                building += t.elapsed();
            }
            parser.join().expect("collector parser thread panicked")
        });
        crate::timing::report(&format!("  {} file", kind.as_str()), started.elapsed());
        crate::timing::report(&format!("  {} graph (overlapped)", kind.as_str()), building);
        result
    }

    /// Records a collector file and returns the kind of object it holds, or
    /// `None` (noting why) when it is not one Pathwarden reads.
    fn begin_file(&mut self, label: &str, meta: Option<RawMeta>) -> Option<NodeKind> {
        let Some(meta) = meta else {
            self.stats
                .skipped_files
                .push(format!("{label} (no BloodHound meta block)"));
            return None;
        };
        let Some(kind) = NodeKind::from_meta_type(&meta.kind) else {
            self.stats
                .skipped_files
                .push(format!("{label} (unsupported type '{}')", meta.kind));
            return None;
        };
        self.stats.files.push(label.to_string());
        self.methods = meta.methods;
        // Only file names carry the collection time; a directory called
        // "CHG20300101000000" must not move every age-based rule.
        let stamp = label
            .rsplit('!')
            .map(|part| part.rsplit(['/', '\\']).next().unwrap_or(part))
            .find_map(crate::time::timestamp_in_name);
        if let Some(t) = stamp {
            self.stats.collected_at = Some(self.stats.collected_at.map_or(t, |c| c.max(t)));
        }
        Some(kind)
    }

    /// Reads the coverage sidecar beside an OpenGraph file given on its own
    /// (`x.coverage.json` or `x.json.coverage.json`), unless it was read.
    fn probe_sidecars(&mut self, payload: &Path) {
        let Some(dir) = payload.parent() else { return };
        let Some(name) = payload.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let stem = name.strip_suffix(".json").unwrap_or(name);
        for candidate in [
            format!("{stem}.coverage.json"),
            format!("{name}.coverage.json"),
        ] {
            let p = dir.join(candidate);
            if p.is_file() && self.seen.insert(canonical(&p)) {
                // Errors reading it are recorded with the sidecar.
                let _ = self.ingest_json_file(&p);
            }
        }
    }

    fn reference(&mut self, r: &TypedRef) -> Option<NodeIndex> {
        (!r.object_identifier.is_empty()).then(|| {
            self.graph.ensure(
                &r.object_identifier,
                NodeKind::from_object_type(&r.object_type),
            )
        })
    }

    fn ingest_object(&mut self, kind: NodeKind, o: RawObject) {
        let mut id = normalize_id(&o.object_identifier);
        if id.is_empty() {
            // RustHound-CE up to 2.5.23 writes certificate templates with an
            // empty ObjectIdentifier; their objectGUID still names them.
            id = o
                .properties
                .get("objectguid")
                .and_then(|v| v.as_str())
                .map(normalize_id)
                .unwrap_or_default();
        }
        if id.is_empty() {
            return;
        }
        if o.is_deleted {
            self.stats.deleted_objects += 1;
            return;
        }
        *self
            .stats
            .objects
            .entry(kind.as_str().to_string())
            .or_default() += 1;

        let mut props = Props::from_map(&o.properties);
        if self.all_properties {
            props.extra = self.graph.prop_bag(&o.properties);
        }
        if is_adcs(kind) {
            forest_root_name(&mut props);
        }
        if let Some(dc) = &o.dc_registry_data {
            if let Some(v) = registry_setting(dc, "CertificateMappingMethods") {
                props.certificatemappingmethods = v;
            }
            if let Some(v) = registry_setting(dc, "StrongCertificateBindingEnforcement") {
                props.strongcertificatebindingenforcement = v;
            }
        }
        if kind == NodeKind::Computer {
            let lists = [&o.sessions, &o.privileged_sessions, &o.registry_sessions];
            props.sessions_collected = any_collected(lists.map(|s| s.collected));
            props.local_groups_collected = any_collected(
                o.local_groups
                    .iter()
                    .map(|g| g.collected)
                    .chain([o.local_admins.collected]),
            );
            (props.host_lists, props.host_lists_unasked) = host_lists(self.methods, &o);
            let (sessions, groups) = targeted(self.methods, &o);
            props.sessions_targeted = sessions;
            props.local_groups_targeted = groups;
            props.host_skipped = host_skip(&o);
        }
        if kind == NodeKind::User && props.managedpassword != Some(true) {
            // RustHound-CE (and so the built-in collector, which runs it)
            // types a gMSA as a user but writes no `gmsa` flag;
            // its userAccountControl keeps the computer-account bit.
            let uac = o
                .properties
                .get("useraccountcontrol")
                .and_then(serde_json::Value::as_i64);
            if uac.is_some_and(|u| u & UF_WORKSTATION_TRUST_ACCOUNT != 0) {
                props.managedpassword = Some(true);
            }
        }
        if kind == NodeKind::Computer && props.managedpassword != Some(true) {
            // The same collectors type an sMSA as a computer and write no
            // `msa` flag. A real computer carries the computer-account bit
            // too, so userAccountControl can't tell them apart; the Managed
            // Service Accounts container holds only gMSAs and sMSAs, so a
            // computer in it is an sMSA. Without this, PW-011 reports it as
            // a computer missing LAPS.
            if props
                .distinguishedname
                .as_deref()
                .is_some_and(in_msa_container)
            {
                props.managedpassword = Some(true);
            }
        }
        if kind == NodeKind::Domain && self.methods != 0 {
            props.gpo_local_groups_collected = Some(self.methods & GPO_LOCAL_GROUP != 0);
        }
        if kind == NodeKind::Domain {
            props.collected = o.properties.get("collected").and_then(|v| v.as_bool());
        }
        let adcs = is_adcs(kind).then(|| Box::new(self.adcs_props(kind, &o)));
        let domain_sid = props
            .domainsid
            .clone()
            .or_else(|| o.domain_sid.as_deref().map(normalize_id))
            .or_else(|| sid::domain_sid_of(&id));
        let domain = match kind {
            NodeKind::Domain => props.domain.clone().or_else(|| props.name.clone()),
            _ => props.domain.clone(),
        };
        let node = Node {
            name: props.name.clone().unwrap_or_else(|| sid::display_name(&id)),
            id: id.clone(),
            kind,
            domain,
            domain_sid,
            is_dc: o.is_dc || props.isdc.unwrap_or(false),
            placeholder: false,
            tier_zero: false,
            tier_zero_reason: None,
            props,
            adcs,
            ext: None,
        };
        let me = self.graph.upsert_merged(node);

        if kind == NodeKind::EnterpriseCa {
            let aces = enterprise_ca_aces(&o);
            self.ingest_aces(me, aces);
            self.ingest_enterprise_ca(me, &o);
        } else {
            self.ingest_aces(me, o.aces.iter());
        }
        if let Some(link) = o.group_link.as_ref().and_then(|g| self.reference(g)) {
            self.graph.add_edge(me, link, EdgeKind::OidGroupLink);
        }
        if matches!(kind, NodeKind::RootCa | NodeKind::NtAuthStore) {
            let domain_sid = o
                .domain_sid
                .clone()
                .or_else(|| self.graph.node(me).domain_sid.clone());
            if let Some(d) = domain_sid.filter(|d| !d.is_empty()) {
                let d = self.graph.ensure(&d, NodeKind::Domain);
                let edge = if kind == NodeKind::RootCa {
                    EdgeKind::RootCaFor
                } else {
                    EdgeKind::NtAuthStoreFor
                };
                self.graph.add_edge(me, d, edge);
            }
        }

        for m in &o.members {
            if let Some(m) = self.reference(m) {
                self.graph.add_edge(m, me, EdgeKind::MemberOf);
            }
        }
        if let Some(pg) = o.primary_group_sid.as_deref().filter(|s| !s.is_empty()) {
            let pg = self.graph.ensure(pg, NodeKind::Group);
            self.graph.add_edge(me, pg, EdgeKind::MemberOf);
        }
        for t in &o.allowed_to_delegate {
            if let Some(t) = self.reference(t) {
                self.graph.add_edge(me, t, EdgeKind::AllowedToDelegate);
            }
        }
        for p in &o.allowed_to_act {
            if let Some(p) = self.reference(p) {
                self.graph.add_edge(p, me, EdgeKind::AllowedToAct);
            }
        }
        for t in &o.has_sid_history {
            if let Some(t) = self.reference(t) {
                self.graph.add_edge(me, t, EdgeKind::HasSidHistory);
            }
        }

        // Computer collection: who is logged on, and who holds local rights.
        for s in o
            .sessions
            .items
            .iter()
            .chain(&o.privileged_sessions.items)
            .chain(&o.registry_sessions.items)
        {
            let Some(user) = s.user_sid.as_deref().filter(|u| !u.is_empty()) else {
                continue;
            };
            let computer = match s.computer_sid.as_deref().filter(|c| !c.is_empty()) {
                Some(c) => self.graph.ensure(c, NodeKind::Computer),
                None => me,
            };
            let user = self.graph.ensure(user, NodeKind::User);
            self.graph.add_edge(computer, user, EdgeKind::HasSession);
        }
        let legacy = [
            (&o.local_admins, EdgeKind::AdminTo),
            (&o.remote_desktop_users, EdgeKind::CanRdp),
            (&o.dcom_users, EdgeKind::ExecuteDcom),
            (&o.ps_remote_users, EdgeKind::CanPsRemote),
        ];
        for (set, edge) in legacy {
            for p in &set.items {
                if let Some(p) = self.reference(p) {
                    self.graph.add_edge(p, me, edge);
                }
            }
        }
        for group in &o.local_groups {
            let edge = match sid::local_group_rid(&group.object_identifier) {
                Some(544) => EdgeKind::AdminTo,
                Some(555) => EdgeKind::CanRdp,
                Some(562) => EdgeKind::ExecuteDcom,
                Some(580) => EdgeKind::CanPsRemote,
                _ => continue,
            };
            for p in &group.results {
                if let Some(p) = self.reference(p) {
                    self.graph.add_edge(p, me, edge);
                }
            }
        }

        // OUs and domains: local groups their GPOs set on the computers below.
        if let Some(changes) = &o.gpo_changes {
            let computers: Vec<NodeIndex> = changes
                .affected_computers
                .iter()
                .filter_map(|c| self.reference(c))
                .collect();
            let granted = [
                (&changes.local_admins, EdgeKind::AdminTo),
                (&changes.remote_desktop_users, EdgeKind::CanRdp),
                (&changes.dcom_users, EdgeKind::ExecuteDcom),
                (&changes.ps_remote_users, EdgeKind::CanPsRemote),
            ];
            for (set, edge) in granted {
                for p in set {
                    let Some(p) = self.reference(p) else { continue };
                    for &c in &computers {
                        if p != c {
                            self.graph.add_gpo_grant(p, c, edge, me);
                        }
                    }
                }
            }
        }

        // Containers, OUs and domains.
        for c in &o.child_objects {
            if let Some(c) = self.reference(c) {
                self.graph.add_edge(me, c, EdgeKind::Contains);
            }
        }
        if let Some(parent) = o.contained_by.as_ref().and_then(|p| self.reference(p)) {
            self.graph.add_edge(parent, me, EdgeKind::Contains);
        }
        let mut links = Vec::new();
        for link in &o.links {
            if !link.guid.is_empty() {
                let gpo = self.graph.ensure(&link.guid, NodeKind::Gpo);
                self.graph.add_edge(gpo, me, EdgeKind::GpLink);
                links.push((gpo, link.is_enforced));
            }
        }
        // Which GPO wins on a computer: the links' order and
        // enforcement, and OUs that block inheritance.
        if !links.is_empty() {
            self.graph.set_gp_links(me, links);
        }
        if kind == NodeKind::Ou
            && o.properties
                .get("blocksinheritance")
                .and_then(|v| v.as_bool())
                == Some(true)
        {
            self.graph.set_blocks_inheritance(me);
        }

        for t in &o.trusts {
            if t.target_domain_sid.is_empty() {
                continue;
            }
            let target = self.graph.ensure(&t.target_domain_sid, NodeKind::Domain);
            // A blank name is no name: the domain keeps its SID as one.
            if let Some(name) = t
                .target_domain_name
                .as_ref()
                .filter(|n| !n.trim().is_empty())
            {
                let n = self.graph.node_mut(target);
                if n.placeholder {
                    n.name = name.to_ascii_uppercase();
                    n.domain = Some(n.name.clone());
                    n.props.named_by_trust = true;
                }
            }
            if t.is_same_forest() {
                self.graph.add_edge(me, target, EdgeKind::SameForestTrust);
                self.graph.add_edge(target, me, EdgeKind::SameForestTrust);
            } else {
                // Informational only: crossing a forest boundary needs SID filtering
                // gaps or delegation abuse, which findings evaluate explicitly.
                self.graph.add_edge(me, target, EdgeKind::CrossForestTrust);
            }
            let source_name = self.graph.node(me).name.clone();
            self.stats.trusts.push(TrustInfo {
                source: source_name,
                target: self.graph.node(target).name.clone(),
                trust_type: t.kind(),
                direction: t.direction(),
                transitive: t.is_transitive,
                sid_filtering: t.sid_filtering(),
                selective_auth: t.selective_auth(),
                source_sid: self.graph.node(me).id.clone(),
                target_sid: self.graph.node(target).id.clone(),
                trust_attributes: t.trust_attributes.as_u64(),
            });
        }
    }
}

impl Ingestor {
    fn ingest_aces<'a>(&mut self, me: NodeIndex, aces: impl IntoIterator<Item = &'a RawAce>) {
        for ace in aces {
            if ace.principal_sid.is_empty() {
                continue;
            }
            match EdgeKind::from_name(&ace.right_name) {
                Some(edge) => {
                    let p = self.graph.ensure(
                        &ace.principal_sid,
                        NodeKind::from_object_type(&ace.principal_type),
                    );
                    self.graph.add_ace_edge(p, me, edge, ace.is_inherited);
                }
                None => {
                    *self
                        .stats
                        .unmapped_rights
                        .entry(ace.right_name.clone())
                        .or_default() += 1
                }
            }
        }
    }

    fn adcs_props(&self, kind: NodeKind, o: &RawObject) -> AdcsProps {
        let mut adcs = AdcsProps::from_map(&o.properties);
        if kind != NodeKind::EnterpriseCa {
            return adcs;
        }
        // Registry values only count when the collector says it really read them;
        // RustHound-CE fills these blocks with defaults.
        let collected = |key: &str| o.properties.get(key).and_then(|v| v.as_bool()) == Some(true);
        if let Some(reg) = &o.ca_registry_data {
            if let Some(san) = &reg.is_user_specifies_san_enabled {
                if san.collected && collected("isuserspecifiessanenabledcollected") {
                    adcs.isuserspecifiessanenabled = san.value;
                }
            }
            if let Some(r) = &reg.enrollment_agent_restrictions {
                adcs.enrollmentagentrestricted = r.collected
                    && collected("enrollmentagentrestrictionscollected")
                    && !r.restrictions.is_empty();
            }
        }
        // Written only when the CA's InterfaceFlags were read.
        adcs.enforceencryptionforrequests = o
            .properties
            .get("enforceencryptionforrequests")
            .and_then(|v| v.as_bool());
        for endpoint in &o.http_enrollment_endpoints {
            if endpoint.get("Collected").and_then(|v| v.as_bool()) != Some(true) {
                continue;
            }
            let Some(result) = endpoint.get("Result").filter(|r| r.is_object()) else {
                continue;
            };
            let flag = |k: &str| result.get(k).and_then(|v| v.as_bool()) == Some(true);
            let http = flag("ADCSWebEnrollmentHTTP");
            let https_without_epa = flag("ADCSWebEnrollmentHTTPS") && !flag("ADCSWebEnrollmentEPA");
            if http || https_without_epa {
                if let Some(url) = result.get("Url").and_then(|v| v.as_str()) {
                    adcs.vulnerableendpoints.push(url.to_string());
                }
            }
        }
        adcs
    }

    fn ingest_enterprise_ca(&mut self, me: NodeIndex, o: &RawObject) {
        if let Some(host) = o.hosting_computer.as_deref().filter(|h| !h.is_empty()) {
            let host = self.graph.ensure(host, NodeKind::Computer);
            self.graph.add_edge(host, me, EdgeKind::HostsCaService);
        }
        // RustHound-CE up to 2.5.23 lists each published template with an
        // empty identifier: the CA publishes templates, but which is lost.
        if !o.enabled_cert_templates.is_empty()
            && o.enabled_cert_templates
                .iter()
                .all(|t| t.object_identifier.trim().is_empty())
        {
            self.unresolved_publication.push(me);
        }
        let mut templates = Vec::new();
        for t in &o.enabled_cert_templates {
            if let Some(t) = self.reference(t) {
                self.graph.add_edge(t, me, EdgeKind::PublishedTo);
                templates.push(t);
            }
        }
        let Some(restrictions) = o
            .ca_registry_data
            .as_ref()
            .and_then(|r| r.enrollment_agent_restrictions.as_ref())
            .filter(|r| r.collected)
        else {
            return;
        };
        for r in &restrictions.restrictions {
            if r.access_type != "AccessAllowedCallback" {
                continue;
            }
            let Some(agent) = r.agent.as_ref().and_then(|a| self.reference(a)) else {
                continue;
            };
            let targets: Vec<NodeIndex> = if r.all_templates {
                templates.clone()
            } else {
                r.template
                    .as_ref()
                    .and_then(|t| self.reference(t))
                    .into_iter()
                    .collect()
            };
            for t in targets {
                self.graph
                    .add_edge(agent, t, EdgeKind::DelegatedEnrollmentAgent);
            }
        }
    }
}

/// AD CS objects live in the forest's Configuration partition, and every
/// domain's collection holds a copy. SharpHound names them after the forest
/// root (`CONTOSO-CA@CONTOSO.LOCAL`); RustHound-CE after the
/// domain it collected (`CONTOSO-CA@NORTH.CONTOSO.LOCAL`), so the
/// name depended on which collection was read first. Both now give the
/// forest root's name, taken from the object's DN.
fn forest_root_name(props: &mut Props) {
    let Some(dn) = props.distinguishedname.as_deref() else {
        return;
    };
    let Some(at) = dn.find(",CN=CONFIGURATION,") else {
        return;
    };
    let root: Vec<&str> = dn[at + ",CN=CONFIGURATION,".len()..]
        .split(',')
        .filter_map(|rdn| rdn.trim().strip_prefix("DC="))
        .collect();
    if root.is_empty() {
        return;
    }
    let root = root.join(".");
    let Some(old) = props.domain.replace(root.clone()) else {
        return;
    };
    if old == root {
        return;
    }
    if let Some(name) = props.name.as_mut() {
        if let Some(base) = name.strip_suffix(&format!("@{old}")) {
            *name = format!("{base}@{root}");
        }
    }
}

/// Whether a distinguished name sits in the domain's Managed Service Accounts
/// container, which holds only gMSAs and sMSAs. `dn` is already upper-cased by
/// [`Props::from_map`], like the other DN checks here.
fn in_msa_container(dn: &str) -> bool {
    dn.contains(",CN=MANAGED SERVICE ACCOUNTS,")
}

fn is_adcs(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::CertTemplate
            | NodeKind::EnterpriseCa
            | NodeKind::RootCa
            | NodeKind::AiaCa
            | NodeKind::NtAuthStore
            | NodeKind::IssuancePolicy
    )
}

/// CA permissions, merged the way BloodHound CE does: when the CA registry
/// security was collected it is authoritative for CA rights (minus local groups
/// and the owner), and LDAP ACEs only contribute generic rights, plus CA rights
/// held by the hosting computer itself.
fn enterprise_ca_aces(o: &RawObject) -> Vec<&RawAce> {
    let security = o
        .ca_registry_data
        .as_ref()
        .and_then(|r| r.ca_security.as_ref())
        .filter(|s| s.collected);
    let Some(security) = security else {
        return o.aces.iter().collect();
    };
    let host = o.hosting_computer.as_deref().map(normalize_id);
    let ca_right = |a: &RawAce| {
        matches!(
            a.right_name.as_str(),
            "ManageCA" | "ManageCertificates" | "Enroll"
        )
    };
    security
        .data
        .iter()
        .filter(|a| !a.principal_type.eq_ignore_ascii_case("LocalGroup") && a.right_name != "Owns")
        .chain(o.aces.iter().filter(|a| {
            !ca_right(a) || host.as_deref() == Some(normalize_id(&a.principal_sid).as_str())
        }))
        .collect()
}

/// Whether the collection asked a computer for its sessions and its local
/// groups (`None`: it doesn't say, read as asked). SharpHound says so in its
/// collection methods. The built-in collector and RustHound-CE (2.5.26 and
/// later) leave a list they never tried uncollected with no reason, or with
/// [`NOT_CONTACTED`]; a list that failed has another reason. Neither says
/// whether local groups were asked for, so a computer with none is taken as
/// not asked only when its sessions weren't either (a full collection that
/// reached no computer still targeted both). Older RustHound-CE marks every
/// list collected, so nothing reads as not targeted there.
fn targeted(methods: u64, o: &RawObject) -> (Option<bool>, Option<bool>) {
    if methods != 0 {
        return (
            Some(methods & SESSION_METHODS != 0),
            Some(methods & LOCAL_GROUP_METHODS != 0),
        );
    }
    let lists = [&o.sessions, &o.privileged_sessions, &o.registry_sessions];
    if lists.iter().all(|s| s.collected.is_none()) {
        return (None, None);
    }
    let sessions = lists.iter().any(|s| {
        s.collected != Some(false)
            || s.failure_reason
                .as_deref()
                .is_some_and(|r| r != NOT_CONTACTED)
    });
    let has_groups = !o.local_groups.is_empty()
        || o.local_admins.collected.is_some()
        || !o.local_admins.items.is_empty();
    let groups = if has_groups || sessions {
        Some(true)
    } else {
        Some(false)
    };
    (Some(sessions), groups)
}

/// Which of a computer's session and local group lists the collector read,
/// and which it wasn't asked for ([`crate::model::Props::host_lists`],
/// [`crate::model::Props::host_lists_unasked`]). A kind none of whose
/// lists says is read as read: the collector doesn't say, as before lists
/// were checked one by one. A list is not asked for when SharpHound's
/// methods (`methods`) leave it out, or, without methods, when it is left
/// uncollected with no reason or with [`NOT_CONTACTED`], as [`targeted`]
/// tells them; one that failed with another reason was asked.
fn host_lists(methods: u64, o: &RawObject) -> (u8, u8) {
    use crate::opengraph::hosts::{group_bit, GROUP_BITS, SESSION_BITS};
    let mut bits = 0u8;
    let mut unasked = 0u8;
    // SharpHound's method for each list: Session (and its loop), LoggedOn
    // (and its loop) for the privileged and registry lists, LocalAdmin,
    // RDP, DCOM, PSRemote.
    let method_of = |bit: u8| -> u64 {
        match bit {
            1 => 1 << 3 | 1 << 10,
            2 | 4 => 1 << 4 | 1 << 11,
            8 => 1 << 1,
            16 => 1 << 8,
            32 => 1 << 12,
            _ => 1 << 14,
        }
    };
    let not_tried = |c: Option<bool>, reason: Option<&str>| {
        c == Some(false) && reason.is_none_or(|r| r == NOT_CONTACTED)
    };
    let mut list = |bit: u8, c: Option<bool>, reason: Option<&str>| {
        if c == Some(true) {
            bits |= bit;
        } else if (methods != 0 && methods & method_of(bit) == 0)
            || (methods == 0 && not_tried(c, reason))
        {
            unasked |= bit;
        }
    };
    let sessions = [
        (&o.sessions, 1u8),
        (&o.privileged_sessions, 2),
        (&o.registry_sessions, 4),
    ];
    let sessions_said = sessions.iter().any(|(s, _)| s.collected.is_some());
    for (s, b) in sessions {
        list(b, s.collected, s.failure_reason.as_deref());
    }
    // Each group's list: from LocalGroups (which gives no reason), or the
    // older per-group fields.
    let legacy = [
        (544, &o.local_admins),
        (555, &o.remote_desktop_users),
        (562, &o.dcom_users),
        (580, &o.ps_remote_users),
    ];
    let mut groups_said = false;
    for (rid, s) in legacy {
        groups_said |= s.collected.is_some();
        if s.collected.is_some() {
            list(
                group_bit(rid).unwrap_or(0),
                s.collected,
                s.failure_reason.as_deref(),
            );
        }
    }
    for g in &o.local_groups {
        let Some(bit) = sid::local_group_rid(&g.object_identifier).and_then(group_bit) else {
            continue;
        };
        groups_said |= g.collected.is_some();
        if g.collected.is_some() {
            list(bit, g.collected, Some("not given"));
        }
    }
    if !sessions_said {
        bits |= SESSION_BITS;
        unasked &= !SESSION_BITS;
    }
    if !groups_said {
        bits |= GROUP_BITS;
        unasked &= !GROUP_BITS;
    }
    (bits, unasked & !bits)
}

/// True if any collection attempt succeeded, false if all reported failure,
/// unknown if the collector said nothing.
fn any_collected(flags: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    flags.into_iter().flatten().reduce(|a, b| a || b)
}

/// Reads `{"Name": {"Value": n, ...}}` or `{"Name": n}` from DC registry data.
/// A `DCRegistryData` value, or `None` when the collector could not read it
/// (`"Collected": false`, typically for lack of rights): its `Value` is then a
/// placeholder 0 and must not be mistaken for a real setting.
fn registry_setting(data: &serde_json::Value, name: &str) -> Option<DcSetting> {
    let v = data.get(name).filter(|v| !v.is_null())?;
    if v.get("Collected").and_then(|c| c.as_bool()) == Some(false) {
        return None;
    }
    let value = v.get("Value").unwrap_or(v).as_i64();
    Some(match value {
        Some(n) if n >= 0 => DcSetting::Value(n),
        _ => DcSetting::NotSet,
    })
}

fn has_bom(head: &[u8]) -> bool {
    head.starts_with(b"\xEF\xBB\xBF")
}

/// Where a collector file's bytes come from, for the parser thread. A zip
/// entry is read from the archive opened once by [`Ingestor::ingest_zip`],
/// which the parser thread borrows.
enum Source<'a> {
    File {
        path: PathBuf,
        bom: bool,
    },
    Zip {
        archive: &'a mut zip::ZipArchive<BufReader<File>>,
        path: &'a Path,
        index: usize,
        /// What the first pass read.
        size: u64,
        bom: bool,
    },
}

impl Source<'_> {
    /// Opens the source (skipping a byte order mark) and hands it to `f`.
    fn read<T>(
        self,
        f: impl FnOnce(&mut dyn Read) -> Result<T, IngestError>,
    ) -> Result<T, IngestError> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| IngestError::Io { path, source }
        };
        match self {
            Source::File { path, bom } => {
                let mut file = File::open(&path).map_err(io(&path))?;
                if bom {
                    file.read_exact(&mut [0u8; 3]).map_err(io(&path))?;
                }
                // The size was checked before; cap it in case the file grew.
                f(&mut file.take(MAX_ENTRY_BYTES))
            }
            Source::Zip {
                archive,
                path,
                index,
                size,
                bom,
            } => {
                let mut entry = archive.by_index(index).map_err(|source| IngestError::Zip {
                    path: path.to_path_buf(),
                    source,
                })?;
                if bom {
                    entry.read_exact(&mut [0u8; 3]).map_err(io(path))?;
                }
                // No more than the first pass read and was allowed.
                let rest = size.saturating_sub(if bom { 3 } else { 0 });
                f(&mut (&mut entry).take(rest))
            }
        }
    }
}

/// Bytes of parsed objects handed to the builder and not yet built. The
/// parser waits while more than `limit` are waiting (one batch always
/// passes, so an object as large as the limit still goes through).
struct InFlight {
    state: std::sync::Mutex<(u64, bool)>,
    room: std::sync::Condvar,
    limit: u64,
}

impl InFlight {
    fn new(limit: u64) -> Self {
        InFlight {
            state: std::sync::Mutex::new((0, false)),
            room: std::sync::Condvar::new(),
            limit,
        }
    }

    fn acquire(&self, bytes: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while !s.1 && s.0 > 0 && s.0 + bytes > self.limit {
            s = self.room.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.0 += bytes;
    }

    fn release(&self, bytes: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.0 = s.0.saturating_sub(bytes);
        self.room.notify_all();
    }

    /// Stops all waiting when dropped (the builder is gone).
    fn closer(&self) -> impl Drop + '_ {
        struct Close<'a>(&'a InFlight);
        impl Drop for Close<'_> {
            fn drop(&mut self) {
                let mut s = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
                s.1 = true;
                self.0.room.notify_all();
            }
        }
        Close(self)
    }
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod trust_tests {
    use super::*;

    fn trust(source: &str, target: &str, kind: &str, direction: &str) -> TrustInfo {
        TrustInfo {
            source: source.into(),
            target: target.into(),
            trust_type: kind.into(),
            direction: direction.into(),
            transitive: true,
            sid_filtering: false,
            selective_auth: None,
            source_sid: String::new(),
            target_sid: String::new(),
            trust_attributes: None,
        }
    }

    /// A trust recorded by both of its domains is one trust.
    #[test]
    fn both_sides_of_a_trust_are_one() {
        let trusts = [
            trust(
                "ESSOS.LOCAL",
                "SEVENKINGDOMS.LOCAL",
                "Forest",
                "Bidirectional",
            ),
            trust(
                "NORTH.SEVENKINGDOMS.LOCAL",
                "SEVENKINGDOMS.LOCAL",
                "ParentChild",
                "Bidirectional",
            ),
            trust(
                "SEVENKINGDOMS.LOCAL",
                "NORTH.SEVENKINGDOMS.LOCAL",
                "ParentChild",
                "Bidirectional",
            ),
            trust(
                "sevenkingdoms.local",
                "essos.local",
                "Forest",
                "Bidirectional",
            ),
            // One way, seen from each end.
            trust("A.LOCAL", "B.LOCAL", "External", "Outbound"),
            trust("B.LOCAL", "A.LOCAL", "External", "Inbound"),
            // Not mirrored: two trusts.
            trust("C.LOCAL", "D.LOCAL", "External", "Outbound"),
            trust("D.LOCAL", "C.LOCAL", "External", "Outbound"),
        ];
        let distinct = distinct_trusts(&trusts);
        let sides: Vec<(&str, Option<&str>)> = distinct
            .iter()
            .map(|(t, o)| (t.source.as_str(), o.map(|o| o.source.as_str())))
            .collect();
        assert_eq!(
            sides,
            [
                ("ESSOS.LOCAL", Some("sevenkingdoms.local")),
                ("NORTH.SEVENKINGDOMS.LOCAL", Some("SEVENKINGDOMS.LOCAL")),
                ("A.LOCAL", Some("B.LOCAL")),
                ("C.LOCAL", None),
                ("D.LOCAL", None),
            ]
        );
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Reading counts up to exactly the work it announced, for zips (two
    /// passes) and loose JSON files alike.
    #[test]
    fn bytes_read_reach_the_total() {
        for input in ["demo", "testdata/forest", "testdata/adcs"] {
            let path = root().join(input);
            let total = work_bytes(std::slice::from_ref(&path));
            assert!(total > 0, "{input}");
            let mut ing = Ingestor::new();
            let read = ing.bytes_read();
            ing.ingest_path(&path).unwrap();
            let got = read.load(Ordering::Relaxed);
            // BOMs and per-entry rounding: a few bytes per file at most.
            assert!(
                got <= total && total - got < 64,
                "{input}: {got} of {total}"
            );
        }
    }

    #[test]
    fn counted_reader_divides() {
        let n = AtomicU64::new(0);
        let data = vec![0u8; 10_001];
        let mut r = Counted::new(&data[..], &n, 4);
        std::io::copy(&mut r, &mut std::io::sink()).unwrap();
        assert_eq!(n.load(Ordering::Relaxed), 2500);
        assert_eq!(work_bytes(&[PathBuf::from("no/such/file.json")]), 0);
    }
}

#[cfg(test)]
mod hardening_tests;
