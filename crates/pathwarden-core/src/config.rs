//! `pathwarden.toml`: organization-specific Tier Zero, rule settings, and
//! accepted risks.
//!
//! ```toml
//! tier_zero = ["BACKUP01.CONTOSO.LOCAL", "SVC_AADCONNECT@CONTOSO.LOCAL"]
//!
//! [rules]
//! disabled = ["PW-011"]
//! stale_days = 90
//! password_age_days = 365
//! krbtgt_age_days = 180
//! sso_key_age_days = 30  # the Seamless SSO key (PW-037)
//! severity = "exposure"   # or "static": keep each rule's own severity
//!
//! [rules.severities]      # a rule's severity, whatever its exposure
//! "PW-011" = "low"
//!
//! [[zone]]
//! name = "Tier 1 servers"
//! groups = ["TIER1 SERVERS@CONTOSO.LOCAL"]
//! ous = ["OU=SERVERS,DC=CONTOSO,DC=LOCAL"]
//!
//! [[suppress]]
//! fingerprint = "PW-004-1f2e3d4c5b6a7980"
//! reason = "Break-glass account, reviewed quarterly (CHG0012345)"
//! expires = "2027-01-31"
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, RuleSettings};
use crate::time::parse_date;
use crate::zones::ZoneConfig;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// The file's format (docs/dev/formats.md): absent means 1. A file of a
    /// newer format than [`CONFIG_FORMAT`] is refused, never read as this
    /// version's or rewritten. Pathwarden writes it only once a format
    /// after 1 exists, since 0.1.9 and earlier refuse a key they don't
    /// know here.
    pub format: Option<u32>,
    /// Extra object IDs or names to treat as Tier Zero.
    pub tier_zero: Vec<String>,
    pub rules: RulesConfig,
    pub suppress: Vec<Suppression>,
    /// Privilege Zones to protect besides Tier Zero.
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    /// Where `pathwarden run` keeps state between runs.
    pub state: StateConfig,
    /// Output plugins `pathwarden run` sends the event document to.
    #[serde(rename = "output")]
    pub outputs: Vec<OutputConfig>,
    /// Finding actions: programs someone runs for one finding, when they
    /// ask ([`crate::actions`]). Never run by `pathwarden run` or a
    /// schedule, and never shared through the history.
    #[serde(rename = "action")]
    pub actions: Vec<ActionConfig>,
    /// Size limits for reading collector files; the defaults suit very
    /// large collections.
    pub ingest: IngestConfig,
    /// Limits for OpenGraph files (TaskHound, MSSQLHound, ...), and which
    /// mapping packs are trusted.
    pub opengraph: OpenGraphConfig,
    /// Your own mapping packs (`[[mapping]] path = "..."`), after the
    /// built-in ones.
    #[serde(rename = "mapping")]
    pub mappings: Vec<MappingConfig>,
    /// The packs `[[mapping]]` names, read and validated by
    /// [`Config::from_file`] (paths are relative to the config file's
    /// folder). Empty for a config parsed from text.
    #[serde(skip)]
    pub user_packs: Vec<UserPack>,
    /// What [`Config::parse`] ignored and why (keys a newer version wrote),
    /// for the command line to print.
    #[serde(skip)]
    pub warnings: Vec<ConfigWarning>,
    /// Management planes Pathwarden should not treat as Tier Zero.
    pub management_planes: ManagementPlanesConfig,
    /// How the built-in collector reads, on this computer.
    pub collect: CollectConfig,
    /// Tier Zero settings folders: shared folders whose
    /// `pathwarden-tierzero-*.json` files every analysis reads
    /// ([`Config::settings_folders`]). A shared section.
    pub settings_folders: Vec<String>,
    /// Of `settings_folders`, those the shared history brought that no one
    /// on this computer reviewed: listed, not read
    /// ([`crate::folder_origin`]). Set by [`Config::from_file`].
    #[serde(skip)]
    pub settings_folders_unreviewed: Vec<String>,
    /// Set by [`Config::from_file`] once it knows which folders this
    /// computer uses: a config read from text alone reads no folder.
    #[serde(skip)]
    pub settings_folders_checked: bool,
}

/// `[management_planes]`: Pathwarden treats systems that manage Tier Zero
/// (an Entra Connect server, the SCOM server of a domain controller, ...)
/// as Tier Zero. List here the ones you have checked and found not to.
///
/// ```toml
/// [management_planes]
/// not_tier_zero = ["OLDSYNC01.CONTOSO.LOCAL"]
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ManagementPlanesConfig {
    pub not_tier_zero: Vec<String>,
    /// Keys this version doesn't know (a newer one wrote them): the section
    /// is then not applied ([`ManagementPlanesConfig::applied`]), as a key
    /// it doesn't know could narrow what it covers.
    #[serde(skip)]
    pub unknown_keys: Vec<String>,
}

impl ManagementPlanesConfig {
    /// The planes the analysis treats as not Tier Zero: none while the
    /// section has keys this version doesn't know.
    pub fn applied(&self) -> &[String] {
        if self.unknown_keys.is_empty() {
            &self.not_tier_zero
        } else {
            &[]
        }
    }
}

/// `[[mapping]]`: a mapping pack of your own, as TOML data. It is parsed
/// and validated like the built-in packs (a pack that fails is refused
/// whole, and the config with it). It is data: nothing in it is run.
///
/// ```toml
/// [[mapping]]
/// path = "packs/acme-sccm.toml"   # relative to pathwarden.toml's folder
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MappingConfig {
    pub path: String,
}

/// A `[[mapping]]` pack, read.
#[derive(Debug, Clone)]
pub struct UserPack {
    /// As written in the config.
    pub path: String,
    pub pack: crate::opengraph::Pack,
    /// Written by a sync from the shared history ([`crate::pack_origin`]):
    /// trusted only when reviewed here at this text, never by name.
    pub from_repo: Option<crate::pack_origin::RepoPack>,
}

/// A `[[mapping]]` pack as [`Config::read_user_packs`] read it.
pub type ReadPack = (
    String,
    Result<crate::opengraph::Pack, String>,
    Option<crate::pack_origin::RepoPack>,
);

/// Largest mapping pack file read.
pub const MAX_PACK_BYTES: u64 = 1 << 20;

/// `[opengraph]`: limits for OpenGraph files, and packs you trust. Past a
/// limit, the source is read no further and marked incomplete, so it can't
/// prove a finding fixed.
///
/// ```toml
/// [opengraph]
/// max_nodes = 2000000    # node records per source
/// max_edges = 10000000   # edge records per source
/// max_kinds = 512        # distinct external kind names per analysis
/// max_kept_mib = 64      # kept properties per source (AzureHound: 16 times)
/// max_record_mib = 16    # memory one node or edge record may take
/// trust = ["mssqlhound"] # packs reviewed and trusted (docs/opengraph.md)
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OpenGraphConfig {
    pub max_nodes: Option<usize>,
    pub max_edges: Option<usize>,
    pub max_kinds: Option<usize>,
    pub max_kept_mib: Option<u64>,
    pub max_record_mib: Option<u64>,
    /// Mapping packs (by name) you reviewed and trust although they ship
    /// untrusted: their traversable kinds then make paths and findings.
    /// The Mappings page adds a name here after a confirmation.
    pub trust: Vec<String>,
}

impl OpenGraphConfig {
    /// Whether `[opengraph] trust` names the pack `name`.
    pub fn trusts(&self, name: &str) -> bool {
        self.trust
            .iter()
            .any(|t| t.trim().eq_ignore_ascii_case(name))
    }
}

/// Whether `name` may be a pack name (as [`crate::opengraph::Pack`] checks).
pub fn valid_pack_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `path` may name a mapping pack: a local `.toml` file.
pub(crate) fn check_pack_path(path: &str) -> Result<(), String> {
    let p = path.trim();
    if p.is_empty() {
        return Err("path is empty".into());
    }
    if p.chars().any(char::is_control) {
        return Err(format!("path {p:?} contains a control character"));
    }
    if !p.to_ascii_lowercase().ends_with(".toml") {
        return Err(format!("path {p:?} must name a .toml file"));
    }
    // Opening a network path signs in to that server as the user.
    let mut c = p.chars();
    let network = matches!((c.next(), c.next()), (Some('\\' | '/'), Some('\\' | '/')))
        || p.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("file:"));
    if network {
        return Err(format!(
            "path {p:?} is a network path; copy the pack to this computer"
        ));
    }
    Ok(())
}

/// Reads one `[[mapping]]` pack (see [`Config::read_user_packs`]), with
/// its text.
fn read_pack(base: &Path, path: &str) -> Result<(crate::opengraph::Pack, String), String> {
    use std::io::Read;
    check_pack_path(path)?;
    let full = base.join(path.trim());
    let mut text = String::new();
    std::fs::File::open(&full)
        .and_then(|f| f.take(MAX_PACK_BYTES + 1).read_to_string(&mut text))
        .map_err(|e| format!("could not read {}: {e}", full.display()))?;
    if text.len() as u64 > MAX_PACK_BYTES {
        return Err(format!("{} is larger than 1 MiB", full.display()));
    }
    check_pack_text(&text).map(|p| (p, text))
}

/// Parses and checks the text of a `[[mapping]]` pack as [`read_pack`]
/// does: for packs that arrive through a shared history
/// ([`crate::settings_sync`]) before they are written.
pub fn check_pack_text(text: &str) -> Result<crate::opengraph::Pack, String> {
    if text.len() as u64 > MAX_PACK_BYTES {
        return Err("the pack is larger than 1 MiB".into());
    }
    let pack = crate::opengraph::Pack::parse(text.trim_start_matches('\u{feff}'))?;
    if crate::opengraph::pack::embedded()
        .iter()
        .any(|b| b.name().eq_ignore_ascii_case(pack.name()))
    {
        // Overriding a built-in pack's kinds is allowed (a later pack wins
        // per kind), taking its name is not: runs record packs by name.
        return Err(format!(
            "pack name '{}' is a built-in pack's; give yours another name",
            pack.name()
        ));
    }
    Ok(pack)
}

/// `[collect]`: how this computer's built-in collector reads the directory.
///
/// ```toml
/// [collect]
/// all_attributes = true   # ask for every attribute, as RustHound-CE does
/// service_reads = false   # don't read the accounts services run as
/// task_reads = false      # don't read the scheduled tasks
/// read_streams = 2        # connections that read the directory at once
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CollectConfig {
    /// Ask the directory for every attribute (`*`) instead of only those
    /// RustHound-CE reads, for comparing the two. Off by default.
    pub all_attributes: bool,
    /// Read the account each service runs as on the computers in a Full
    /// collection, for the credentials they store. On when not set.
    pub service_reads: Option<bool>,
    /// Read the scheduled tasks on the computers in a Full collection, for
    /// the passwords they store. On when not set.
    pub task_reads: Option<bool>,
    /// Connections that read the directory at once: 1 to 8, 4 when
    /// not set. Fewer are used when the domain controller slows down.
    pub read_streams: Option<u32>,
}

/// Most connections a read may use ([`CollectConfig::read_streams`]).
pub const MAX_READ_STREAMS: u32 = 8;

impl CollectConfig {
    /// The streams asked for, within 1 to [`MAX_READ_STREAMS`]; `None`
    /// when not set (the collector's default).
    pub fn read_streams(&self) -> Option<usize> {
        self.read_streams
            .map(|n| n.clamp(1, MAX_READ_STREAMS) as usize)
    }

    /// Whether a Full collection reads the services: on unless this file
    /// or the command (`turned_off`, `--no-service-reads`) says not.
    pub fn service_reads(&self, turned_off: bool) -> bool {
        !turned_off && self.service_reads != Some(false)
    }

    /// Whether a Full collection reads the scheduled tasks: on unless this
    /// file or the command (`turned_off`, `--no-task-reads`) says not.
    pub fn task_reads(&self, turned_off: bool) -> bool {
        !turned_off && self.task_reads != Some(false)
    }
}

/// `[ingest]`: limits that protect against hostile or broken input.
///
/// ```toml
/// [ingest]
/// max_zip_entries = 4096    # entries in one .zip
/// max_archive_gib = 64      # what one .zip may decompress to in all
/// max_object_mib = 128      # memory one collector object may take
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IngestConfig {
    pub max_zip_entries: Option<usize>,
    pub max_archive_gib: Option<u64>,
    pub max_object_mib: Option<u64>,
}

impl IngestConfig {
    pub fn limits(&self) -> crate::ingest::IngestLimits {
        self.limits_with(&OpenGraphConfig::default())
    }

    /// [`limits`](Self::limits) with the `[opengraph]` limits.
    pub fn limits_with(&self, og: &OpenGraphConfig) -> crate::ingest::IngestLimits {
        let d = crate::ingest::IngestLimits::default();
        let o = d.og;
        crate::ingest::IngestLimits {
            max_zip_entries: self.max_zip_entries.unwrap_or(d.max_zip_entries),
            max_archive_bytes: self
                .max_archive_gib
                .map_or(d.max_archive_bytes, |g| g.saturating_mul(1 << 30)),
            max_object_bytes: self
                .max_object_mib
                .map_or(d.max_object_bytes, |m| m.saturating_mul(1 << 20)),
            og: crate::ingest::OgLimits {
                max_nodes: og.max_nodes.unwrap_or(o.max_nodes),
                max_edges: og.max_edges.unwrap_or(o.max_edges),
                max_kinds: og.max_kinds.unwrap_or(o.max_kinds),
                max_kept_bytes: og
                    .max_kept_mib
                    .map_or(o.max_kept_bytes, |m| m.saturating_mul(1 << 20)),
                max_item_bytes: og
                    .max_record_mib
                    .map_or(o.max_item_bytes, |m| m.saturating_mul(1 << 20)),
            },
        }
    }
}

/// One output plugin. `plugin` names the program (`pathwarden-output-<plugin>`)
/// unless `command` gives one explicitly; every other key is passed to the
/// plugin as JSON in `PATHWARDEN_OUTPUT_SETTINGS`.
#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    pub plugin: String,
    /// Program and arguments to run instead of `pathwarden-output-<plugin>`,
    /// for example `["powershell", "-NoProfile", "-File", "teams.ps1"]`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(flatten)]
    pub settings: serde_json::Map<String, serde_json::Value>,
}

/// One `[[action]]` block: a program someone runs for one finding, when they
/// ask ([`crate::actions`]). `plugin` names the program
/// (`pathwarden-action-<plugin>`, found as output plugins are) unless
/// `command` gives one; one program may offer several actions, each
/// addressed as `<name>/<id>`. Every key but [`ACTION_KEYS`] is passed to
/// the program as a setting, inside the request.
///
/// ```toml
/// [[action]]
/// name = "service-desk"
/// command = ["python", "C:\\Pathwarden\\actions\\service_desk.py"]
/// timeout_seconds = 900
/// min_severity = "medium"
/// group = "Identity"            # a setting
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ActionConfig {
    /// The name in effect: as written, else `plugin`, else `action-N` (N
    /// counting the `[[action]]` blocks from 1). Set by [`Config::parse`].
    #[serde(default)]
    pub name: String,
    /// Runs `pathwarden-action-<plugin>` from beside pathwarden or its
    /// `plugins` folder.
    #[serde(default)]
    pub plugin: Option<String>,
    /// Program and arguments, checked as an output's `command` is.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// How long one run may take before its process tree is stopped:
    /// [`ACTION_TIMEOUT_DEFAULT`], at most [`ACTION_TIMEOUT_MAX`].
    #[serde(default = "action_timeout_default")]
    pub timeout_seconds: u64,
    /// Only findings at least this severe.
    #[serde(default, deserialize_with = "severity_text")]
    pub min_severity: Option<crate::findings::Severity>,
    /// Only findings of these rules (IDs, any case). Empty: every rule.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Only findings of these categories. Empty: both.
    #[serde(default, deserialize_with = "category_list")]
    pub categories: Vec<crate::findings::Category>,
    /// Every other key: the program's settings.
    #[serde(flatten)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// The block has neither `name` nor `plugin`, so its name is
    /// `action-N`, which changes when blocks move. Set by
    /// [`Config::parse`].
    #[serde(skip)]
    pub positional_name: bool,
}

/// An action's `timeout_seconds` when it sets none.
pub const ACTION_TIMEOUT_DEFAULT: u64 = 300;
/// The longest `timeout_seconds` an action may set (sign-in can be slow).
pub const ACTION_TIMEOUT_MAX: u64 = 1800;

fn action_timeout_default() -> u64 {
    ACTION_TIMEOUT_DEFAULT
}

/// The keys of `[[action]]` this version knows. Every other key is a
/// setting for the program, except a near miss of one of these, which is
/// refused as the typo it most likely is: an ignored `rule` would quietly
/// widen the action to every rule.
pub const ACTION_KEYS: &[&str] = &[
    "name",
    "plugin",
    "command",
    "timeout_seconds",
    "min_severity",
    "rules",
    "categories",
];

/// The block key `key` is a singular or plural of (`rule` for `rules`),
/// for a warning: it stays a setting for the program.
pub fn action_key_like(key: &str) -> Option<&'static str> {
    let plural = |a: &str, b: &str| {
        b == format!("{a}s")
            || b == format!("{a}es")
            || a.strip_suffix('y').is_some_and(|s| b == format!("{s}ies"))
    };
    ACTION_KEYS
        .iter()
        .find(|k| plural(k, key) || plural(key, k))
        .copied()
}

/// The name a new `[[action]]` block gets when none is given: its plugin's,
/// else the file name of the script its command runs (the last argument
/// ending in a script's extension), else of its program, as lowercase
/// letters, digits and dashes; `action` when nothing is left.
pub fn action_name_for(plugin: Option<&str>, command: Option<&[String]>) -> String {
    if let Some(p) = plugin {
        return p.to_string();
    }
    const SCRIPTS: &[&str] = &[
        "ps1", "psm1", "py", "pyw", "sh", "bash", "js", "mjs", "cjs", "cmd", "bat", "rb", "pl",
    ];
    let file = |a: &str| a.rsplit(['/', '\\']).next().unwrap_or(a).to_string();
    let argv = command.unwrap_or_default();
    let pick = argv
        .iter()
        .rev()
        .map(|a| file(a.split_once('=').map_or(a.as_str(), |(_, v)| v)))
        .find(|f| {
            f.rsplit_once('.')
                .is_some_and(|(_, x)| SCRIPTS.contains(&x.to_ascii_lowercase().as_str()))
        })
        .or_else(|| argv.first().map(|p| file(p)))
        .unwrap_or_default();
    let stem = pick.rsplit_once('.').map_or(pick.as_str(), |(s, _)| s);
    let mut out = String::new();
    for c in stem.to_ascii_lowercase().chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if !(c == '-' && (out.is_empty() || out.ends_with('-'))) {
            out.push(c);
        }
    }
    let out: String = out.trim_end_matches('-').chars().take(64).collect();
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "action".into()
    } else {
        out
    }
}

/// A severity in any case ("Medium").
fn severity_text<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<crate::findings::Severity>, D::Error> {
    use serde::de::Error;
    match Option::<String>::deserialize(d)? {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s.trim().parse().map(Some).map_err(D::Error::custom),
    }
}

/// Categories as the event writes them (`attack_path`, `hygiene`), or any
/// spelling `Category` reads.
fn category_list<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<crate::findings::Category>, D::Error> {
    use serde::de::Error;
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|_| D::Error::custom(format!("'{s}' isn't one of attack_path, hygiene")))
        })
        .collect()
}

/// Whether `name` can name a plugin or an action: lowercase letters, digits
/// and dashes, at most 64.
pub fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Checks the `[[action]]` blocks and sets each one's name in effect
/// ([`ActionConfig::name`]).
fn check_actions(actions: &mut [ActionConfig]) -> Result<(), ConfigError> {
    let bad = |m: String| Err(ConfigError::Invalid(m));
    let mut names = std::collections::HashSet::new();
    for (i, a) in actions.iter_mut().enumerate() {
        let n = i + 1;
        if let Some(p) = &a.plugin {
            if !valid_plugin_name(p) {
                return bad(format!(
                    "[[action]] {n}: plugin = \"{p}\": use lowercase letters, digits and dashes"
                ));
            }
        }
        match (&a.plugin, &a.command) {
            (Some(_), Some(_)) => {
                return bad(format!("[[action]] {n}: give plugin or command, not both"))
            }
            (None, None) => {
                return bad(format!(
                    "[[action]] {n}: name the program with plugin or command"
                ))
            }
            (None, Some(c)) if c.first().is_none_or(|p| p.trim().is_empty()) => {
                return bad(format!("[[action]] {n}: command is empty"))
            }
            _ => {}
        }
        let name = a.name.trim().to_string();
        a.positional_name = name.is_empty() && a.plugin.is_none();
        a.name = if !name.is_empty() {
            name
        } else if let Some(p) = &a.plugin {
            p.clone()
        } else {
            format!("action-{n}")
        };
        if !valid_plugin_name(&a.name) {
            return bad(format!(
                "[[action]] {n}: name = \"{}\": use lowercase letters, digits and dashes",
                a.name
            ));
        }
        if !names.insert(a.name.clone()) {
            return bad(format!(
                "Two [[action]] blocks are named {}: give one of them another name",
                a.name
            ));
        }
        if a.timeout_seconds == 0 || a.timeout_seconds > ACTION_TIMEOUT_MAX {
            return bad(format!(
                "[[action]] {}: timeout_seconds must be from 1 to {ACTION_TIMEOUT_MAX}",
                a.name
            ));
        }
        if let Some(r) = a
            .rules
            .iter()
            .find(|r| r.is_empty() || !r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        {
            return bad(format!(
                "[[action]] {}: rules: \"{r}\" is not a rule ID such as PW-001",
                a.name
            ));
        }
    }
    Ok(())
}

/// Where run state lives between runs.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct StateConfig {
    pub backend: StateBackend,
    /// The local state folder, or the git working copy. Default "pathwarden-state".
    pub path: Option<String>,
    /// Git only: the repository to pull state from and push it to.
    pub remote: Option<String>,
    /// Git only: the branch to use. Default "main".
    pub branch: Option<String>,
    /// Keep finding titles and domains in the state. Off by default, so the
    /// state holds fingerprints, rules, severities and dates only.
    pub include_names: bool,
    /// Git only: commit and push each recorded run (default true). Off, runs
    /// are kept in the local working copy until the next pull resets it, as
    /// with `--no-push`; the UI then only reads the shared history.
    pub push: Option<bool>,
    /// The history here is encrypted: any plain history at this location is
    /// refused, whatever the repository says, until `history storage set
    /// --no-encrypt` clears it. Written by `set --encrypt`. Local to this
    /// computer: `[state]` is never shared through the history.
    pub encrypted: bool,
    /// What the history keeps ([`Keep`]): `"names"` (the default) or
    /// `"full"`.
    pub keep: Option<Keep>,
    /// With "Full runs and settings": how many full runs the history keeps
    /// at its tip, the latest by run ID ([`StateConfig::full_runs_kept`]).
    /// Older runs keep their history point. Written only when it isn't the
    /// default, so a `pathwarden.toml` that keeps 50 still reads in 0.1.7.
    pub full_runs_kept: Option<usize>,
    /// Git only: how often the app pulls while it is open, in minutes
    /// ([`StateConfig::refresh_minutes`]). Local to this computer, like
    /// all of `[state]`. Written only when it isn't the default, so a
    /// `pathwarden.toml` that keeps 5 still reads in 0.1.7.
    pub refresh: Option<u32>,
    /// With "Full runs and settings": the largest file a full run keeps,
    /// in MB (MiB, [`StateConfig::full_run_file_mb`]); a larger one is left
    /// out and named in its manifest. Local to this computer: the computer
    /// that records a run sets it. Written only when it isn't the default.
    pub full_run_file_mb: Option<u64>,
}

/// The largest file a full run keeps, in MB, unless `[state]
/// full_run_file_mb` says otherwise.
pub const DEFAULT_FULL_RUN_FILE_MB: u64 = 75;

/// What `[state] full_run_file_mb` is held to on a GitHub remote: GitHub
/// refuses files over 100 MB.
pub const GITHUB_FULL_RUN_FILE_MB: u64 = 95;

/// The most `[state] full_run_file_mb` takes anywhere.
pub const MAX_FULL_RUN_FILE_MB: u64 = 2048;

/// Whether git remote `remote` is on github.com (`https://github.com/o/r`,
/// with or without a user part, `git@github.com:o/r`,
/// `ssh://git@github.com/o/r`). GitHub Enterprise Server's own hosts
/// aren't recognised.
pub fn is_github_remote(remote: &str) -> bool {
    let r = remote.trim();
    let rest = match r.find("://") {
        Some(i) => &r[i + 3..],
        // scp-like `user@host:path`; a Windows path (`C:/x`) has no `@`.
        None if r.contains('@') => r,
        None => return false,
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit('@').next().unwrap_or_default();
    // `host:port`, or scp-like `host:path`.
    let host = host.split(':').next().unwrap_or_default();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "github.com" || host == "www.github.com"
}

/// How often the app pulls a git history while it is open, in minutes,
/// unless `[state] refresh` says otherwise.
pub const DEFAULT_REFRESH_MINUTES: u32 = 5;

/// The most `[state] refresh` takes: a day.
pub const MAX_REFRESH_MINUTES: u32 = 1440;

/// Full runs the history keeps at its tip unless `[state] full_runs_kept`
/// says otherwise.
pub const DEFAULT_FULL_RUNS_KEPT: usize = 50;

/// The most `[state] full_runs_kept` takes.
pub const MAX_FULL_RUNS_KEPT: usize = 1000;

/// What the history keeps (`[state] keep`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Keep {
    /// Numbers with names ([`NAMES_WORDS`]).
    #[default]
    Names,
    /// Full runs and settings: also the environment's shared settings and
    /// accepted risks, with who accepted them ([`crate::settings_sync`]),
    /// and each run in full (`runs/<run>/` in the history).
    Full,
}

impl Keep {
    /// As written in `[state] keep`.
    pub fn as_str(self) -> &'static str {
        match self {
            Keep::Names => "names",
            Keep::Full => "full",
        }
    }

    /// In plain words, as the History storage page names the choice.
    pub fn words(self) -> &'static str {
        match self {
            Keep::Names => "Numbers with names",
            Keep::Full => "Full runs and settings",
        }
    }

    /// What the level keeps, in one sentence: [`NAMES_WORDS`] or
    /// [`FULL_WORDS`].
    pub fn description(self) -> &'static str {
        match self {
            Keep::Names => NAMES_WORDS,
            Keep::Full => FULL_WORDS,
        }
    }
}

/// What "Numbers with names" keeps, said the same way everywhere (the
/// History storage page, `history storage`, the docs).
pub const NAMES_WORDS: &str = "Numbers with names: IDs, rules, severities and dates, plus each \
finding's title, which names the accounts, groups and computers it is about (e.g. \
\"SVC-ADSYNC@SCALE.LOCAL has a path to Tier Zero\"), and its domain.";

/// What "Full runs and settings" keeps.
pub const FULL_WORDS: &str = "Full runs and settings: numbers with names, plus each run in full \
(report, Explore, findings, retest) and, with a git repository, the environment's shared settings \
and accepted risks with who accepted them.";

impl StateConfig {
    /// Whether recorded runs are committed and pushed (git).
    pub fn pushes(&self) -> bool {
        self.push.unwrap_or(true)
    }

    /// What the history keeps.
    pub fn keep(&self) -> Keep {
        self.keep.unwrap_or_default()
    }

    /// How many full runs the history keeps at its tip: `[state]
    /// full_runs_kept`, else [`DEFAULT_FULL_RUNS_KEPT`]; at least 1 and at
    /// most [`MAX_FULL_RUNS_KEPT`].
    pub fn full_runs_kept(&self) -> usize {
        self.full_runs_kept
            .unwrap_or(DEFAULT_FULL_RUNS_KEPT)
            .clamp(1, MAX_FULL_RUNS_KEPT)
    }

    /// How often the app pulls a git history while it is open: `[state]
    /// refresh` minutes, else [`DEFAULT_REFRESH_MINUTES`]; at least 1 and
    /// at most [`MAX_REFRESH_MINUTES`].
    pub fn refresh_minutes(&self) -> u32 {
        self.refresh
            .unwrap_or(DEFAULT_REFRESH_MINUTES)
            .clamp(1, MAX_REFRESH_MINUTES)
    }

    /// The largest file a full run keeps, in MB, as set: `[state]
    /// full_run_file_mb`, else [`DEFAULT_FULL_RUN_FILE_MB`]; at least 1 and
    /// at most [`MAX_FULL_RUN_FILE_MB`].
    pub fn full_run_file_mb(&self) -> u64 {
        self.full_run_file_mb
            .unwrap_or(DEFAULT_FULL_RUN_FILE_MB)
            .clamp(1, MAX_FULL_RUN_FILE_MB)
    }

    /// [`StateConfig::full_run_file_mb`] as it applies to a history at git
    /// remote `remote` (`None`: a folder): held to
    /// [`GITHUB_FULL_RUN_FILE_MB`] on GitHub.
    pub fn full_run_file_mb_for(&self, remote: Option<&str>) -> u64 {
        let mb = self.full_run_file_mb();
        if remote.is_some_and(is_github_remote) {
            mb.min(GITHUB_FULL_RUN_FILE_MB)
        } else {
            mb
        }
    }

    /// [`StateConfig::full_run_file_mb_for`] in bytes.
    pub fn full_run_file_bytes_for(&self, remote: Option<&str>) -> u64 {
        self.full_run_file_mb_for(remote) * 1024 * 1024
    }

    /// Whether the history keeps finding titles (which name the objects a
    /// finding is about) and domain names: at every level since 0.1.7
    /// (`include_names = false` is ignored with a warning).
    pub fn keeps_names(&self) -> bool {
        true
    }
}

/// What `[state] include_names = false` is told: the history keeps names
/// at every level now.
pub const NAMES_FALSE_WARNING: &str =
    "[state] include_names = false is no longer used: the history keeps each finding's title, \
     which names the accounts, groups and computers it is about, and its domain, at every \
     level (keep = \"names\", the default). Remove the line.";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateBackend {
    /// A folder on this machine (or a network share).
    #[default]
    Local,
    /// A git repository: pulled before each run, committed and pushed after.
    Git,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
    pub stale_days: i64,
    pub password_age_days: i64,
    pub krbtgt_age_days: i64,
    /// Seamless SSO keys older than this are reported (PW-037).
    pub sso_key_age_days: i64,
    pub severity: SeverityMode,
    /// Severities the team set per rule: `"PW-011" = "low"` by hand, or
    /// with who set it as the app and `pathwarden config rules set` write
    /// it (`{ severity = "low", by = …, on = …, at = … }`). A set severity
    /// rates every finding of the rule. Read leniently: what this version
    /// can't read (a newer version's level or form) is kept in the file,
    /// ignored and named in the warnings, never an error.
    #[serde(deserialize_with = "lenient_severities")]
    pub severities: std::collections::BTreeMap<String, SeverityEntry>,
}

/// `[rules.severities]`, or nothing when it isn't a table (a warning says
/// so).
fn lenient_severities<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<std::collections::BTreeMap<String, SeverityEntry>, D::Error> {
    Ok(match toml::Value::deserialize(d)? {
        toml::Value::Table(t) => t
            .into_iter()
            .map(|(k, v)| {
                let e = v
                    .clone()
                    .try_into::<SeverityEntry>()
                    .unwrap_or(SeverityEntry::Other(v));
                (k, e)
            })
            .collect(),
        _ => Default::default(),
    })
}

/// One `[rules.severities]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum SeverityEntry {
    /// `"PW-011" = "low"`.
    Level(String),
    /// `"PW-011" = { severity = "low", by = …, on = …, at = … }`.
    Stamped {
        severity: String,
        #[serde(default)]
        by: Option<String>,
        #[serde(default)]
        on: Option<String>,
        #[serde(default)]
        at: Option<String>,
    },
    /// A form this version doesn't read (a newer one's): ignored.
    Other(toml::Value),
}

impl SeverityEntry {
    /// The level as written ("" for a form this version doesn't read).
    pub fn level(&self) -> &str {
        match self {
            SeverityEntry::Level(s) => s,
            SeverityEntry::Stamped { severity, .. } => severity,
            SeverityEntry::Other(_) => "",
        }
    }

    /// The entry, when its level is one a rule can be set to.
    pub fn to_set(&self) -> Option<crate::findings::SetSeverity> {
        let severity = crate::findings::Severity::parse_settable(self.level()).ok()?;
        let (by, on, at) = match self {
            SeverityEntry::Level(_) | SeverityEntry::Other(_) => (None, None, None),
            SeverityEntry::Stamped { by, on, at, .. } => (by.clone(), on.clone(), at.clone()),
        };
        let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Some(crate::findings::SetSeverity {
            severity,
            by: clean(by),
            on: clean(on),
            at: clean(at),
        })
    }
}

/// One rule as the Settings page and `pathwarden config rules show
/// --rules` list it: on or off, and its severity.
#[derive(Debug, Clone, Serialize)]
pub struct RuleRow {
    pub id: &'static str,
    pub title: &'static str,
    pub on: bool,
    /// What rates its findings when no severity is set
    /// ([`crate::findings::default_label`]): "exposure", "Medium".
    pub default: String,
    /// The severity set for it, and who set it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set: Option<crate::findings::SetSeverity>,
}

impl RuleRow {
    /// "Default (exposure)", as the Settings page's drop-down says it.
    pub fn default_words(&self) -> String {
        format!("Default ({})", self.default)
    }
}

impl RulesConfig {
    /// Every rule, by ID, with whether it is on and its severity.
    pub fn rows(&self) -> Vec<RuleRow> {
        let set = self.set_severities();
        let by_exposure = self.severity == SeverityMode::Exposure;
        let mut rules: Vec<_> = crate::findings::rules().iter().collect();
        rules.sort_by_key(|r| r.id);
        rules
            .into_iter()
            .map(|r| RuleRow {
                id: r.id,
                title: r.title,
                on: !self
                    .disabled
                    .iter()
                    .any(|d| d.trim().eq_ignore_ascii_case(r.id)),
                default: crate::findings::default_label(r.id, by_exposure),
                set: set.get(r.id).cloned(),
            })
            .collect()
    }

    /// The severities set for rules this version has, by rule ID in upper
    /// case. Entries for rules it doesn't have (a newer version's) are left
    /// out ([`Config::warnings`] names them).
    pub fn set_severities(
        &self,
    ) -> std::collections::BTreeMap<String, crate::findings::SetSeverity> {
        let known = crate::findings::rules();
        self.severities
            .iter()
            .filter_map(|(rule, e)| {
                let r = known
                    .iter()
                    .find(|k| k.id.eq_ignore_ascii_case(rule.trim()))?;
                Some((r.id.to_string(), e.to_set()?))
            })
            .collect()
    }
}

/// What this version leaves out of `[rules.severities]`, as one warning
/// each: entries for rules it doesn't have, levels or forms it doesn't
/// read (a newer version's), and a `severities` that isn't a table. They
/// stay in the file.
fn severity_warnings(text: &str, rules: &RulesConfig) -> Vec<ConfigWarning> {
    let mut out = Vec::new();
    let not_table = text
        .parse::<toml::Table>()
        .ok()
        .and_then(|t| t.get("rules")?.get("severities").cloned())
        .is_some_and(|v| !v.is_table());
    if not_table {
        out.push(ConfigWarning::message(
            "[rules.severities] is not a table this version reads; it is kept in the file and ignored.",
        ));
    }
    let known = crate::findings::rules();
    let (mut unknown_rules, mut unknown_levels) = (0, 0);
    for (rule, e) in &rules.severities {
        if !known.iter().any(|k| k.id.eq_ignore_ascii_case(rule.trim())) {
            unknown_rules += 1;
        } else if e.to_set().is_none() {
            unknown_levels += 1;
        }
    }
    let kept = |n: usize| if n == 1 { "It is" } else { "They are" };
    if unknown_rules > 0 {
        out.push(ConfigWarning::message(&format!(
            "[rules.severities]: {} for {} this version doesn't have. {} kept in the file and ignored.",
            crate::text::count(unknown_rules, "entry is", "entries are"),
            if unknown_rules == 1 { "a rule" } else { "rules" },
            kept(unknown_rules)
        )));
    }
    if unknown_levels > 0 {
        out.push(ConfigWarning::message(&format!(
            "[rules.severities]: {} a severity or form this version doesn't read. {} kept in the file and ignored.",
            crate::text::count(unknown_levels, "entry has", "entries have"),
            kept(unknown_levels)
        )));
    }
    out
}

/// Where attack path severity comes from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityMode {
    /// Share of principals that can abuse the finding (BloodHound Enterprise bands).
    #[default]
    Exposure,
    /// The rule's own severity.
    Static,
}

impl Default for RulesConfig {
    fn default() -> Self {
        let d = RuleSettings::default();
        RulesConfig {
            disabled: Vec::new(),
            stale_days: d.stale_days,
            password_age_days: d.password_age_days,
            krbtgt_age_days: d.krbtgt_age_days,
            sso_key_age_days: d.sso_key_age_days,
            severity: SeverityMode::default(),
            severities: Default::default(),
        }
    }
}

/// An accepted risk: hides one finding (by fingerprint) or a whole rule.
///
/// Who accepted it and when are recorded by every path that writes one
/// (the app and `pathwarden config risk`), from
/// [`crate::identity::Actor::current`]. Entries written by hand or by an
/// older version have none of them: they read as "not recorded".
///
/// ```toml
/// [[suppress]]
/// fingerprint = "PW-004-13b0863341b2e306"
/// reason = "Break-glass account, reviewed quarterly (CHG0012345)"
/// expires = "2027-01-31"
/// accepted_by = 'NORTH\a.admin'
/// accepted_on = "SECOPS-WS02"
/// accepted_at = "2026-10-22T14:03:11Z"
///
/// [[suppress.notes]]
/// by = 'NORTH\a.admin'
/// on = "SECOPS-WS02"
/// at = "2026-11-02T09:15:00Z"
/// text = "CHG0012345 renewed for Q1."
/// ```
///
/// Keys this version doesn't know are ignored with a warning (a newer
/// Pathwarden may write them), unless they look like a typo of one it
/// knows: see [`Config::parse`]. Times may be quoted or bare TOML times.
#[derive(Debug, Clone, Deserialize)]
pub struct Suppression {
    pub fingerprint: Option<String>,
    pub rule: Option<String>,
    /// Why it is accepted: shown with the finding in every report, and sent
    /// as the justification to ticketing and SARIF. Later notes go in
    /// `notes`; this stays the current reason.
    pub reason: String,
    /// `YYYY-MM-DD`; the suppression lapses after this day (UTC) so accepted
    /// risks get re-reviewed instead of hiding forever.
    pub expires: Option<String>,
    /// Who accepted it: `DOMAIN\user` on Windows (a scheduled task's gMSA
    /// ends in `$`), the login name elsewhere.
    pub accepted_by: Option<String>,
    /// The computer it was accepted on.
    pub accepted_on: Option<String>,
    /// When, RFC 3339 in UTC (`2026-10-22T14:03:11Z`).
    #[serde(default, deserialize_with = "time_text")]
    pub accepted_at: Option<String>,
    /// The last change to what it covers, its reason or its review date:
    /// who, where and when. Not set until it is changed.
    pub changed_by: Option<String>,
    pub changed_on: Option<String>,
    #[serde(default, deserialize_with = "time_text")]
    pub changed_at: Option<String>,
    /// Notes added later (`[[suppress.notes]]`), oldest first.
    #[serde(default)]
    pub notes: Vec<SuppressionNote>,
    /// Keys of this entry this version doesn't know (a newer one wrote
    /// them). Such an entry is not applied: a key it doesn't know could
    /// narrow what the risk covers.
    #[serde(skip)]
    pub unknown_keys: Vec<String>,
}

/// A note added to an accepted risk after it was accepted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SuppressionNote {
    /// Who wrote it, as [`Suppression::accepted_by`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The computer it was written on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    /// When, RFC 3339 in UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "time_text"
    )]
    pub at: Option<String>,
    pub text: String,
}

/// The keys of `[[suppress]]` this version knows.
pub const SUPPRESS_KEYS: &[&str] = &[
    "fingerprint",
    "rule",
    "reason",
    "expires",
    "accepted_by",
    "accepted_on",
    "accepted_at",
    "changed_by",
    "changed_on",
    "changed_at",
    "notes",
];

/// The keys of `[[suppress.notes]]` this version knows.
pub const NOTE_KEYS: &[&str] = &["by", "on", "at", "text"];

/// The keys of `[rules]` this version knows.
pub const RULES_KEYS: &[&str] = &[
    "disabled",
    "stale_days",
    "password_age_days",
    "krbtgt_age_days",
    "sso_key_age_days",
    "severity",
    "severities",
];

/// The keys of `[[zone]]` this version knows.
pub const ZONE_KEYS: &[&str] = &["name", "members", "groups", "ous"];

/// Where a warning about `[management_planes]` points.
const MANAGEMENT_PLANES_PLACE: &str = "[management_planes]";

/// The keys of `[management_planes]` this version knows.
pub const MANAGEMENT_PLANES_KEYS: &[&str] = &["not_tier_zero"];

/// The top-level keys and sections this version knows ([`Config`]).
pub const TOP_KEYS: &[&str] = &[
    "format",
    "tier_zero",
    "rules",
    "suppress",
    "zone",
    "state",
    "output",
    "action",
    "ingest",
    "opengraph",
    "mapping",
    "management_planes",
    "collect",
    "settings_folders",
];

/// The keys of `[state]` this version knows ([`StateConfig`]).
pub const STATE_KEYS: &[&str] = &[
    "backend",
    "path",
    "remote",
    "branch",
    "include_names",
    "push",
    "encrypted",
    "keep",
    "full_runs_kept",
    "refresh",
    "full_run_file_mb",
];

/// The keys of `[ingest]` this version knows ([`IngestConfig`]).
pub const INGEST_KEYS: &[&str] = &["max_zip_entries", "max_archive_gib", "max_object_mib"];

/// The keys of `[collect]` this version knows ([`CollectConfig`]).
pub const COLLECT_KEYS: &[&str] = &[
    "all_attributes",
    "service_reads",
    "task_reads",
    "read_streams",
];

/// The keys of `[opengraph]` this version knows ([`OpenGraphConfig`]).
pub const OPENGRAPH_KEYS: &[&str] = &[
    "max_nodes",
    "max_edges",
    "max_kinds",
    "max_kept_mib",
    "max_record_mib",
    "trust",
];

/// Keys a later Pathwarden may well add to this computer's own sections.
/// A test runs [`local_near_miss`] over them against every local list, so
/// a new known key that comes into typo range of one shows at once; a new
/// version adding a key there should add it here too.
pub const LOCAL_FUTURE: &[&str] = &[
    "exclude_names",
    "min_nodes",
    "min_edges",
    "min_kinds",
    "masking",
    "sync_window",
    "timeout",
    "proxy",
    "retries",
    "signing",
    "max_files",
    "compress",
    "notes",
    "audit",
    "telemetry",
];

/// The keys of a local section (or the top level, `place` "the top
/// level") this version doesn't know. A near miss of a known key
/// ([`local_near_miss`]) is refused as the typo it most likely is: an
/// ignored `tierzero` or `encryped` would quietly drop Tier Zero objects
/// or leave encryption off. Any other is named in a warning and ignored,
/// and the rest of the file is used, so a newer version's new key never
/// stops this one.
fn local_unknown(
    t: &toml::Table,
    known: &[&'static str],
    place: &str,
    out: &mut Vec<ConfigWarning>,
) -> Result<(), ConfigError> {
    for key in t.keys() {
        if known.contains(&key.as_str()) {
            continue;
        }
        if let Some(k) = local_near_miss(key, known) {
            return Err(ConfigError::Invalid(format!(
                "{place}: unknown key `{key}`. Did you mean `{k}`?"
            )));
        }
        out.push(ConfigWarning {
            risk: 0,
            note: None,
            key: key.clone(),
            place: Some(place.to_string()),
            zone: 0,
        });
    }
    Ok(())
}

/// The known key `key` most likely meant, for this computer's own
/// sections: one letter off; the same without underscores (`tierzero`);
/// a plural or singular (`outputs`, `zones`, `rule`); or a key holding
/// the stem of a setting whose loss would weaken Pathwarden (`encrypt`,
/// `push` anywhere, `tier` at the start). No exemption for
/// [`RESERVED_FUTURE`] names: a newer version's key here is kept out of
/// this range of every known one ([`LOCAL_FUTURE`]).
pub fn local_near_miss(key: &str, known: &[&'static str]) -> Option<&'static str> {
    let lower = key.to_lowercase();
    // Stems of the settings whose loss would quietly weaken Pathwarden:
    // whatever is said around them, they mean the known key.
    for (stem, at_start, k) in [
        ("encrypt", false, "encrypted"),
        ("push", false, "push"),
        ("tier", true, "tier_zero"),
    ] {
        let hit = if at_start {
            lower.starts_with(stem)
        } else {
            lower.contains(stem)
        };
        if hit {
            if let Some(k) = known.iter().find(|known| **known == k) {
                return Some(k);
            }
        }
    }
    // `b` is a plural of `a`: zone/zones, match/matches, entry/entries.
    let plural = |a: &str, b: &str| {
        b == format!("{a}s")
            || b == format!("{a}es")
            || a.strip_suffix('y').is_some_and(|s| b == format!("{s}ies"))
    };
    if let Some(k) = known.iter().find(|k| {
        plural(k, &lower) || plural(&lower, k) || lower.replace('_', "") == k.replace('_', "")
    }) {
        return Some(k);
    }
    // One letter off at most (none for a two-letter key): a newer
    // version's key two letters from a known one (`exclude_names`,
    // `min_kinds`, `masking`) is not taken for a typo.
    known
        .iter()
        .map(|k| (edit_distance(&lower, k), *k))
        .filter(|(d, k)| *d <= usize::from(k.len() > 2))
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

/// The keys of `[[mapping]]` this version knows.
pub const MAPPING_KEYS: &[&str] = &["path"];

/// A time as text: quoted (`"2026-10-22T14:03:11Z"`, as Pathwarden writes
/// it) or a bare TOML time, as someone may write it by hand.
fn time_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    use serde::de::Error;
    Ok(match Option::<toml::Value>::deserialize(d)? {
        None => None,
        Some(toml::Value::String(s)) => Some(s),
        Some(toml::Value::Datetime(t)) => Some(t.to_string()),
        Some(other) => {
            return Err(D::Error::custom(format!(
                "expected a time such as \"2026-10-22T14:03:11Z\", found {}",
                other.type_str()
            )))
        }
    })
}

/// Keys a later Pathwarden may well add to accepted risks or their notes.
/// They are never taken for typos, so a file a newer version wrote still
/// loads here (with a warning). A test runs [`near_miss`] over them, so the
/// typo rule can't drift into refusing them; a new version adding a key
/// should add it here too, and keep new keys out of typo range of known ones.
pub const RESERVED_FUTURE: &[&str] = &[
    "rules",
    "fingerprints",
    "zones",
    "zone",
    "scope",
    "ticket",
    "tickets",
    "tags",
    "reasons",
    "approved_by",
    "approved_on",
    "approved_at",
    "review",
    "reviewed_by",
    "reviewed_on",
    "reviewed_at",
    "accepted_in",
    "accepted_for",
    "accepted_as",
    "changed_in",
    "changed_for",
    "accepted_tz",
    "changed_tz",
    "accepted_id",
    "changed_id",
    "accepted_ip",
    "changed_ip",
    "accepted_why",
    "changed_why",
    "tz",
    "ip",
    "why",
    "id",
    "ok",
    "in",
    "as",
    "or",
    "one",
    "kind",
    "link",
    "url",
];

/// Edits from `a` to `b`, case-insensitive: insertions, deletions,
/// substitutions and swaps of two neighbouring letters (`resaon`) count one
/// each (optimal string alignment).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_lowercase().chars().collect();
    let b: Vec<char> = b.to_lowercase().chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[n][m]
}

/// The known key an unknown `key` is probably a typo of, or `None` when it
/// is more likely a key of its own (a newer version's):
/// - anything starting `expir` other than `expires` is refused as a typo of
///   it: ignoring a slip there would make the acceptance permanent;
/// - a key in [`RESERVED_FUTURE`], or a plural of a known key (`rules`,
///   `fingerprints`, but not `expiress`), is never a typo;
/// - two-letter keys (`by`, `on`, `at`) only match in another case (`BY`):
///   one letter off is a different word (`in`, `as`, `or`, `ok`);
/// - otherwise one edit for keys of up to 6 letters, two for longer ones,
///   so a slip in the last word of `accepted_by` (`accepted_bt`) is a typo.
pub fn near_miss(key: &str, known: &[&'static str]) -> Option<&'static str> {
    let lower = key.to_lowercase();
    if lower.starts_with("expir") {
        if let Some(k) = known.iter().find(|k| **k == "expires") {
            return Some(k);
        }
    }
    if RESERVED_FUTURE.contains(&lower.as_str()) {
        return None;
    }
    known
        .iter()
        .filter(|k| lower != format!("{k}s") && lower != format!("{k}es"))
        .map(|k| (edit_distance(&lower, k), *k))
        .filter(|(d, k)| {
            *d <= match k.len() {
                0..=2 => 0,
                3..=6 => 1,
                _ => 2,
            }
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

/// A key in a shared section (most often an accepted risk or one of its
/// notes) that this version doesn't know, kept in the file and ignored:
/// probably a newer version's. Or another warning about the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// The accepted risk, from 1 as `config risk list` numbers them; 0 when
    /// the key is elsewhere.
    pub risk: usize,
    /// Its note, from 1, when the key is in a note.
    pub note: Option<usize>,
    /// The key; empty for a warning about something else ([`Self::place`]
    /// is then the whole message).
    pub key: String,
    /// Where, when not in an accepted risk: "[rules]", "zone 2 ([[zone]])".
    pub place: Option<String>,
    /// The zone, from 1, when the key is in a `[[zone]]`; 0 otherwise.
    pub zone: usize,
}

impl ConfigWarning {
    /// A warning about the file that names no key.
    pub fn message(text: &str) -> Self {
        ConfigWarning {
            risk: 0,
            note: None,
            key: String::new(),
            place: Some(text.to_string()),
            zone: 0,
        }
    }
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every warning is complete sentences, ending with a period.
        if self.key.is_empty() {
            let text = self.place.as_deref().unwrap_or_default();
            f.write_str(text)?;
            if !text.is_empty() && !text.ends_with(['.', '?']) {
                f.write_str(".")?;
            }
            return Ok(());
        }
        match (&self.place, self.note) {
            (Some(p), _) => f.write_str(p)?,
            (None, Some(n)) => write!(
                f,
                "Accepted risk {}, note {n} ([[suppress.notes]])",
                self.risk
            )?,
            (None, None) => write!(f, "Accepted risk {} ([[suppress]])", self.risk)?,
        }
        write!(
            f,
            ": `{}` is not a key this version of Pathwarden knows (a newer one may have written it); it is kept in the file and ignored",
            self.key
        )?;
        // An accepted risk or zone with a key this version doesn't know is
        // not applied: the key could narrow it.
        if (self.risk > 0 && self.note.is_none()) || self.zone > 0 {
            f.write_str(if self.zone > 0 {
                ". The zone is not applied here until Pathwarden is updated"
            } else {
                ". The accepted risk is not applied here until Pathwarden is updated"
            })?;
        } else if self.place.as_deref() == Some(MANAGEMENT_PLANES_PLACE) {
            f.write_str(". The section is not applied here until Pathwarden is updated")?;
        }
        f.write_str(".")
    }
}

/// The newest `pathwarden.toml` format this version reads
/// ([`Config::format`], docs/dev/formats.md).
pub const CONFIG_FORMAT: u32 = 1;

/// What a `pathwarden.toml` of a newer format says.
pub fn newer_config_words(format: i64) -> String {
    format!(
        "This pathwarden.toml was saved by a newer Pathwarden (format {format}). Update \
         Pathwarden to read it."
    )
}

/// Refuses a file of a format this version doesn't read: before any of
/// it is read as this version's, so no key a newer format changed is
/// taken for what it meant before.
fn check_format(text: &str) -> Result<(), ConfigError> {
    let Ok(raw) = text.parse::<toml::Table>() else {
        return Ok(());
    };
    if crate::formats::of_toml(&raw, "format", CONFIG_FORMAT).is_known() {
        return Ok(());
    }
    match raw.get("format") {
        Some(toml::Value::Integer(n)) if *n > i64::from(CONFIG_FORMAT) => {
            Err(ConfigError::Invalid(newer_config_words(*n)))
        }
        _ => Err(ConfigError::Invalid(
            "format must be a whole number from 1 (leave it out for 1).".into(),
        )),
    }
}

/// Checks the keys of the sections that travel through a shared history
/// ([`crate::config_edit::SHARED_SECTIONS`]: every `[[suppress]]` entry
/// and its notes, `[rules]`, every `[[zone]]`, `[management_planes]` and
/// every `[[mapping]]`), so an older Pathwarden reads what a newer one
/// wrote: a typo of a known key is an error ("did you mean"); any other
/// unknown key, such as one a newer Pathwarden wrote, is ignored and named
/// in the warnings. This computer's own sections ([`local_unknown`])
/// refuse a near miss ([`local_near_miss`]) and name and ignore every
/// other unknown key.
fn check_shared_keys(text: &str) -> Result<Vec<ConfigWarning>, ConfigError> {
    let mut warnings = Vec::new();
    let Ok(raw) = text.parse::<toml::Table>() else {
        return Ok(warnings);
    };
    if raw
        .get("state")
        .and_then(|s| s.get("include_names"))
        .and_then(toml::Value::as_bool)
        == Some(false)
    {
        warnings.push(ConfigWarning::message(NAMES_FALSE_WARNING));
    }
    // A Tier Zero settings folder that is not a full path is not read.
    for f in raw
        .get("settings_folders")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
    {
        if let Err(e) = crate::config_edit::check_settings_folder(f) {
            warnings.push(ConfigWarning::message(&format!(
                "settings_folders: {e} It is not read."
            )));
        }
    }
    // This computer's own sections: a near miss is refused, any other
    // unknown key named and ignored.
    local_unknown(&raw, TOP_KEYS, "the top level", &mut warnings)?;
    // `[[action]]`: every other key is a setting for the program, but a
    // singular or plural of one of the block's own keys is named, as it
    // may have been meant as the filter.
    for (i, t) in raw
        .get("action")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .enumerate()
    {
        for key in t.keys().filter(|k| !ACTION_KEYS.contains(&k.as_str())) {
            if let Some(k) = action_key_like(key) {
                warnings.push(ConfigWarning::message(&format!(
                    "[[action]] {}: `{key}` is passed to the program as a setting; the block's own key is `{k}`.",
                    i + 1
                )));
            }
        }
    }
    for (section, known) in [
        ("state", STATE_KEYS),
        ("ingest", INGEST_KEYS),
        ("opengraph", OPENGRAPH_KEYS),
        ("collect", COLLECT_KEYS),
    ] {
        if let Some(t) = raw.get(section).and_then(toml::Value::as_table) {
            local_unknown(t, known, &format!("[{section}]"), &mut warnings)?;
        }
    }
    let mut check = |t: &toml::Table,
                     known: &[&'static str],
                     what: String,
                     risk: usize,
                     note: Option<usize>,
                     zone: usize| {
        for key in t.keys() {
            if known.contains(&key.as_str()) {
                continue;
            }
            // Listing Tier Zero here would read as the opposite.
            let near = if known == MANAGEMENT_PLANES_KEYS
                && key
                    .trim_start_matches("is_")
                    .eq_ignore_ascii_case("tier_zero")
            {
                Some("not_tier_zero")
            } else {
                near_miss(key, known)
            };
            if let Some(k) = near {
                return Err(ConfigError::Invalid(format!(
                    "{what}: unknown key `{key}`; did you mean `{k}`?"
                )));
            }
            warnings.push(ConfigWarning {
                risk,
                note,
                key: key.clone(),
                place: (risk == 0).then(|| what.clone()),
                zone,
            });
        }
        Ok(())
    };
    if let Some(t) = raw.get("rules").and_then(toml::Value::as_table) {
        check(t, RULES_KEYS, "[rules]".into(), 0, None, 0)?;
    }
    if let Some(t) = raw.get("management_planes").and_then(toml::Value::as_table) {
        check(
            t,
            MANAGEMENT_PLANES_KEYS,
            "[management_planes]".into(),
            0,
            None,
            0,
        )?;
    }
    for (key, known, what) in [
        ("zone", ZONE_KEYS, "zone"),
        ("mapping", MAPPING_KEYS, "mapping pack"),
    ] {
        let list = raw.get(key).and_then(toml::Value::as_array);
        for (i, entry) in list.into_iter().flatten().enumerate() {
            if let Some(t) = entry.as_table() {
                let zone = if key == "zone" { i + 1 } else { 0 };
                check(
                    t,
                    known,
                    format!("{what} {} ([[{key}]])", i + 1),
                    0,
                    None,
                    zone,
                )?;
            }
        }
    }
    let Some(list) = raw.get("suppress").and_then(toml::Value::as_array) else {
        return Ok(warnings);
    };
    for (i, entry) in list.iter().enumerate() {
        let Some(t) = entry.as_table() else { continue };
        check(
            t,
            SUPPRESS_KEYS,
            format!("Accepted risk {} ([[suppress]])", i + 1),
            i + 1,
            None,
            0,
        )?;
        if let Some(notes) = t.get("notes").and_then(toml::Value::as_array) {
            for (j, n) in notes.iter().enumerate() {
                if let Some(n) = n.as_table() {
                    check(
                        n,
                        NOTE_KEYS,
                        format!(
                            "Accepted risk {}, note {} ([[suppress.notes]])",
                            i + 1,
                            j + 1
                        ),
                        i + 1,
                        Some(j + 1),
                        0,
                    )?;
                }
            }
        }
    }
    Ok(warnings)
}

/// How a finding came to be accepted: the matching [`Suppression`]'s
/// attribution, carried on the finding (`accepted` in `--json`) so the
/// report and the command line can say who accepted it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Acceptance {
    /// Which `[[suppress]]` entry (from 0) accepted it, when it came from
    /// [`Config::apply_suppressions`]; not written out.
    #[serde(skip)]
    pub entry: Option<usize>,
    /// Accepted for every finding of its rule, not this finding alone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub whole_rule: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<SuppressionNote>,
}

impl Suppression {
    /// What it covers: its finding ID, or its rule. Edits send it back so
    /// a change never lands on another entry that took this one's place.
    pub fn target(&self) -> &str {
        self.fingerprint
            .as_deref()
            .or(self.rule.as_deref())
            .unwrap_or_default()
    }

    /// "finding PW-004-…" or "every PW-011 finding".
    pub fn target_words(&self) -> String {
        match (&self.fingerprint, &self.rule) {
            (Some(f), _) => format!("finding {f}"),
            (None, Some(r)) => format!("every {r} finding"),
            (None, None) => String::new(),
        }
    }

    /// Its attribution, for a finding it covers.
    pub fn acceptance(&self) -> Acceptance {
        Acceptance {
            entry: None,
            whole_rule: self.fingerprint.is_none() && self.rule.is_some(),
            expires: self.expires.clone(),
            accepted_by: self.accepted_by.clone(),
            accepted_on: self.accepted_on.clone(),
            accepted_at: self.accepted_at.clone(),
            changed_by: self.changed_by.clone(),
            changed_on: self.changed_on.clone(),
            changed_at: self.changed_at.clone(),
            notes: self.notes.clone(),
        }
    }
}

impl Acceptance {
    /// "accepted by NORTH\a.admin on SECOPS-WS02, Oct 22, 2026", or
    /// "who accepted it and when wasn't recorded" for an entry from before
    /// attribution (hand-written or an older version).
    pub fn accepted_line(&self) -> String {
        match stamp_words(&self.accepted_by, &self.accepted_on, &self.accepted_at) {
            Some(w) => format!("accepted {w}"),
            None => NOT_RECORDED.into(),
        }
    }

    /// "changed by ... on ..., Nov 2, 2026", once it was changed.
    pub fn changed_line(&self) -> Option<String> {
        stamp_words(&self.changed_by, &self.changed_on, &self.changed_at)
            .map(|w| format!("changed {w}"))
    }
}

/// What an accepted risk from before attribution says about its author.
pub const NOT_RECORDED: &str = "who accepted it and when wasn't recorded";

/// "by USER on COMPUTER, Oct 22, 2026" (its local day), with the parts that
/// are known; `None` when none is. A time that isn't RFC 3339 is shown as written.
pub fn stamp_words(
    by: &Option<String>,
    on: &Option<String>,
    at: &Option<String>,
) -> Option<String> {
    let mut out = String::new();
    match by {
        Some(b) => {
            out.push_str("by ");
            out.push_str(b);
        }
        // Recorded where and when, but the account wasn't known.
        None if on.is_some() => out.push_str("by an unknown user"),
        None => {}
    }
    if let Some(o) = on {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str("on ");
        out.push_str(o);
    }
    if let Some(a) = at {
        let day = crate::time::day_of(a);
        out = if out.is_empty() {
            format!("on {day}")
        } else {
            format!("{out}, {day}")
        };
    }
    (!out.is_empty()).then_some(out)
}

/// Checks a `[state]` remote the way `pathwarden run` does: a URL or path
/// that cannot be mistaken for a command-line option.
pub fn validate_remote(remote: &str) -> Result<(), String> {
    let r = remote.trim();
    if r.is_empty() || r.starts_with('-') {
        return Err(format!(
            "[state] remote {:?} is not a valid repository URL or path",
            redact_urls(remote)
        ));
    }
    Ok(())
}

/// `text` with the user name and password of every `scheme://user:pw@host`
/// URL in it replaced by `***`.
pub fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(at) => {
                out.push_str("***");
                out.push_str(&tail[at..end]);
            }
            None => out.push_str(&tail[..end]),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// A `[state] remote` whose URL carries a password or token
/// (`https://user:token@host/...`). Git then keeps it in `.git/config`.
pub fn remote_has_password(remote: &str) -> bool {
    let Some(i) = remote.find("://") else {
        return false;
    };
    let tail = &remote[i + 3..];
    let authority = &tail[..tail.find(['/', '?', '#']).unwrap_or(tail.len())];
    authority
        .rfind('@')
        .is_some_and(|at| authority[..at].contains(':'))
}

/// Prefixes of well-known access tokens: GitHub (classic, OAuth, user,
/// server, refresh, fine-grained), GitLab (personal, pipeline trigger,
/// deploy, runner, feed, OAuth), Bitbucket app passwords and Atlassian API
/// tokens, Hugging Face, Slack. Compared ignoring case.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "glptt-",
    "gldt-",
    "glrt-",
    "glft-",
    "gloas-",
    "atbb",
    "atatt",
    "hf_",
    "xoxb-",
    "xoxp-",
];

/// A `[state] remote` over http(s) whose user part (before the `@`) is a
/// token rather than a user name: one of [`TOKEN_PREFIXES`], or 32
/// characters or more of letters and digits alone (no `.`, `-` or `_`,
/// which user and organisation names carry): an Azure DevOps personal
/// access token is 52 such characters. A plain user name stays allowed
/// (Azure DevOps' own `https://org@dev.azure.com/org/project/_git/repo`),
/// and `user:password@` is [`remote_has_password`]. SSH's `git@host:x` and
/// `ssh://git@host/x` are not http(s).
pub fn remote_has_token(remote: &str) -> bool {
    let r = remote.trim();
    let Some(i) = r.find("://") else {
        return false;
    };
    if !matches!(r[..i].to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    let tail = &r[i + 3..];
    let authority = &tail[..tail.find(['/', '?', '#']).unwrap_or(tail.len())];
    let Some(at) = authority.rfind('@') else {
        return false;
    };
    let user = authority[..at]
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    TOKEN_PREFIXES.iter().any(|p| user.starts_with(p))
        || (user.len() >= 32 && user.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Why a `[state] remote` with a password or token is refused, and what to
/// do instead.
pub const REMOTE_PASSWORD_REFUSED: &str =
    "[state] remote contains a password or token, which git would keep in plain text in the \
     working copy's .git/config; it is not used. Remove it from pathwarden.toml and sign in \
     through git's credential helper (Git Credential Manager, a CI token from the checkout).";

/// A conservative branch-name check (no option injection, no odd refs), as
/// `pathwarden run` applies to `[state] branch`.
pub fn validate_branch(branch: &str) -> Result<(), String> {
    let ok = !branch.is_empty()
        && !branch.starts_with('-')
        && !branch.starts_with('/')
        && !branch.ends_with('/')
        && !branch.ends_with(".lock")
        && !branch.contains("..")
        && !branch.contains("//")
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    if !ok {
        return Err(format!(
            "[state] branch {branch:?} is not an allowed branch name (letters, digits, . _ / -)"
        ));
    }
    Ok(())
}

impl Config {
    /// The Tier Zero settings folders to read, as paths: each entry
    /// trimmed; those that are not full paths are left out (the config's
    /// warnings name them).
    pub fn settings_folder_paths(&self) -> Vec<std::path::PathBuf> {
        if !self.settings_folders_checked {
            return Vec::new();
        }
        let waiting: Vec<String> = self
            .settings_folders_unreviewed
            .iter()
            .map(|f| crate::folder_origin::key(f))
            .collect();
        self.settings_folders
            .iter()
            .map(|f| f.trim())
            .filter(|f| crate::config_edit::check_settings_folder(f).is_ok())
            .filter(|f| !waiting.contains(&crate::folder_origin::key(f)))
            .map(std::path::PathBuf::from)
            .collect()
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mut config = Self::parse(&text)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.user_packs = config
            .read_user_packs(base)
            .into_iter()
            .map(|(path, read, from_repo)| {
                read.map(|pack| UserPack {
                    path: path.clone(),
                    pack,
                    from_repo,
                })
                .map_err(|e| ConfigError::Invalid(format!("[[mapping]] {path}: {e}")))
            })
            .collect::<Result<_, _>>()?;
        // Settings folders the shared history brought: read once reviewed
        // here.
        config.settings_folders_unreviewed = crate::folder_origin::waiting(&config, path);
        config.settings_folders_checked = true;
        Ok(config)
    }

    /// Reads and validates every `[[mapping]]` pack relative to `base` (the
    /// config file's folder): each path, with its pack or why it was
    /// refused. Only local `.toml` files are read. A pack a sync from the
    /// shared history wrote ([`crate::pack_origin`]) comes with its record,
    /// and is trusted only when it was reviewed here at the text it holds,
    /// whatever its own file says.
    pub fn read_user_packs(&self, base: &Path) -> Vec<ReadPack> {
        use crate::pack_origin::{self, path_key, RepoPack};
        // Which packs came from the repository: the sync's own data (the
        // working copy, the last sync), and the record next to this file.
        // That record lost, packs the sync owns are still from the
        // repository; broken, every pack in packs/ is taken to be.
        let origins = pack_origin::load(base);
        let owned = crate::settings_sync::repo_pack_paths(&self.state, base);
        self.mappings
            .iter()
            .map(|m| {
                let key = path_key(&m.path);
                let record = origins.as_ref().ok().and_then(|o| o.find(&m.path)).cloned();
                let broken = origins.is_err()
                    && key.starts_with(&format!("{}/", crate::settings_sync::PACKS_DIR));
                let mut from_repo = record.or_else(|| {
                    (owned.contains(&key) || broken).then(|| RepoPack {
                        path: m.path.clone(),
                        unreadable: broken,
                        ..RepoPack::default()
                    })
                });
                let read = read_pack(base, &m.path).map(|(pack, text)| match &mut from_repo {
                    Some(r) => {
                        let now = pack_origin::text_digest(&text);
                        let trusted = r.reviewed_sha256.as_deref() == Some(now.as_str());
                        r.current_sha256 = Some(now);
                        pack.with_trusted(trusted)
                    }
                    None => pack,
                });
                (m.path.clone(), read, from_repo)
            })
            .collect()
    }

    /// The mapping packs in effect: the built-in ones, then the
    /// `[[mapping]]` packs in order, with `[opengraph] trust` applied.
    /// `None` when nothing changes the built-in set.
    pub fn packs(&self) -> Option<Vec<crate::opengraph::Pack>> {
        if self.user_packs.is_empty() && self.opengraph.trust.is_empty() {
            return None;
        }
        Some(
            crate::opengraph::pack::embedded()
                .iter()
                .cloned()
                .map(|p| (p, false))
                .chain(
                    self.user_packs
                        .iter()
                        .map(|u| (u.pack.clone(), u.from_repo.is_some())),
                )
                // Trust by name never reaches a pack from the repository.
                .map(|(p, from_repo)| {
                    if !from_repo && !p.trusted() && self.opengraph.trusts(p.name()) {
                        p.with_trusted(true)
                    } else {
                        p
                    }
                })
                .collect(),
        )
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        // A newer format first, before anything in it is read as ours.
        check_format(text)?;
        // Typos in the shared sections first: serde ignores unknown keys
        // there.
        let warnings = check_shared_keys(text)?;
        let mut config: Config = toml::from_str(text)?;
        // Entries with keys this version doesn't know are kept, not applied.
        for w in &warnings {
            if w.risk > 0 && w.note.is_none() {
                if let Some(s) = config.suppress.get_mut(w.risk - 1) {
                    s.unknown_keys.push(w.key.clone());
                }
            }
            if w.zone > 0 {
                if let Some(z) = config.zones.get_mut(w.zone - 1) {
                    z.unknown_keys.push(w.key.clone());
                }
            }
            if !w.key.is_empty() && w.place.as_deref() == Some(MANAGEMENT_PLANES_PLACE) {
                config.management_planes.unknown_keys.push(w.key.clone());
            }
        }
        config.warnings = warnings;
        config
            .warnings
            .extend(severity_warnings(text, &config.rules));
        for o in &config.outputs {
            if o.plugin.is_empty()
                || !o
                    .plugin
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(ConfigError::Invalid(format!(
                    "[[output]] plugin = \"{}\": use lowercase letters, digits and dashes",
                    o.plugin
                )));
            }
            if o.command.as_ref().is_some_and(|c| c.is_empty()) {
                return Err(ConfigError::Invalid(format!(
                    "[[output]] {}: command is empty",
                    o.plugin
                )));
            }
        }
        check_actions(&mut config.actions)?;
        if config.state.backend == StateBackend::Git && config.state.remote.is_none() {
            return Err(ConfigError::Invalid(
                "[state] backend = \"git\" needs a `remote` repository URL".into(),
            ));
        }
        let mut names = std::collections::HashSet::new();
        for z in &config.zones {
            if z.name.trim().is_empty() {
                return Err(ConfigError::Invalid("every [[zone]] needs a name".into()));
            }
            // One rule with the saves' and `--zone`'s (`zones::same_name`).
            if !names.insert(crate::zones::name_key(&z.name)) {
                return Err(ConfigError::Invalid(format!(
                    "zone '{}' is defined twice (names match in any case and spacing): rename one",
                    z.name.trim()
                )));
            }
            if z.members.is_empty() && z.groups.is_empty() && z.ous.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "zone '{}' needs at least one of members, groups or ous",
                    z.name
                )));
            }
        }
        if let Some(name) = config
            .opengraph
            .trust
            .iter()
            .find(|n| !valid_pack_name(n.trim()))
        {
            return Err(ConfigError::Invalid(format!(
                "[opengraph] trust: '{name}' is not a pack name (letters, digits, - or _)"
            )));
        }
        for m in &config.mappings {
            check_pack_path(&m.path)
                .map_err(|e| ConfigError::Invalid(format!("[[mapping]] {e}")))?;
        }
        for s in &config.suppress {
            if s.fingerprint.is_some() == s.rule.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "suppression '{}' needs exactly one of `fingerprint` or `rule`",
                    s.reason
                )));
            }
            if let Some(date) = &s.expires {
                parse_date(date).ok_or_else(|| {
                    ConfigError::Invalid(format!("expires = \"{date}\" is not a YYYY-MM-DD date"))
                })?;
            }
        }
        Ok(config)
    }

    pub fn settings(&self) -> RuleSettings {
        RuleSettings {
            stale_days: self.rules.stale_days,
            password_age_days: self.rules.password_age_days,
            krbtgt_age_days: self.rules.krbtgt_age_days,
            sso_key_age_days: self.rules.sso_key_age_days,
            severity_from_exposure: self.rules.severity == SeverityMode::Exposure,
            severities: self.rules.set_severities(),
            ..RuleSettings::default()
        }
    }

    /// Marks findings covered by an unexpired suppression.
    pub fn apply_suppressions(&self, findings: &mut [Finding], now: i64) {
        for f in findings.iter_mut() {
            let active = self.active_suppression(&f.fingerprint, f.rule, now);
            let entry = active.map(|i| &self.suppress[i]);
            f.suppressed = entry.map(|s| s.reason.clone());
            f.accepted = active.map(|i| Acceptance {
                entry: Some(i),
                ..self.suppress[i].acceptance()
            });
        }
    }

    /// The accepted risk that covers a finding at `now`: the first entry in
    /// the file, by its ID or its rule, that hasn't expired. Every place
    /// that says which risk accepts a finding (the analysis, the run page's
    /// Add a note) asks this, so they always name the same entry.
    pub fn active_suppression(&self, fingerprint: &str, rule: &str, now: i64) -> Option<usize> {
        self.suppress.iter().position(|s| {
            // A newer version's entry: its unknown keys could narrow it.
            if !s.unknown_keys.is_empty() {
                return false;
            }
            let matches = s
                .fingerprint
                .as_deref()
                .is_some_and(|fp| fp.eq_ignore_ascii_case(fingerprint))
                || s.rule
                    .as_deref()
                    .is_some_and(|r| r.eq_ignore_ascii_case(rule));
            let over = s.expires.as_deref().is_some_and(|d| expired(d, now));
            matches && !over
        })
    }
}

/// Whether an accepted risk's `expires` day (YYYY-MM-DD) is over at `now`:
/// it lasts to the end of that day (UTC). Not a date: never.
pub fn expired(date: &str, now: i64) -> bool {
    parse_date(date).is_some_and(|day| now >= day + 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mapping pack on a network path is refused before it is opened
    /// (gap 22): opening it would sign in to that server as the user.
    #[test]
    fn packs_on_network_paths_are_refused() {
        for p in [
            r"\\fabrikam\packs\pack.toml",
            "//fabrikam/packs/pack.toml",
            r"\/fabrikam\packs\pack.toml",
            r"\\?\UNC\fabrikam\packs\pack.toml",
            "file://fabrikam/packs/pack.toml",
            "FILE:C:/packs/pack.toml",
            r"  \\fabrikam\packs\pack.toml",
        ] {
            let e = check_pack_path(p).unwrap_err();
            assert!(e.contains("network path"), "{p}: {e}");
            let e = read_pack(Path::new("C:/contoso"), p).err().unwrap();
            assert!(e.contains("network path"), "{p}: {e}");
        }
        assert!(check_pack_path("packs/contoso.toml").is_ok());
        assert!(check_pack_path(r"C:\packs\contoso.toml").is_ok());
        assert!(check_pack_path("packs/contoso.txt").is_err());
        assert!(check_pack_path("packs/a\u{7}.toml").is_err());
    }

    /// docs/dev/formats.md: absent or 1 reads; a newer format is refused
    /// before anything in it is read, even keys this version can't parse.
    #[test]
    fn the_format_key() {
        assert_eq!(Config::parse("").unwrap().format, None);
        assert_eq!(Config::parse("format = 1\n").unwrap().format, Some(1));
        let e = Config::parse("format = 2\n[rules]\nstale_days = \"soon\"\nnew_thing = 1\n")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("This pathwarden.toml was saved by a newer Pathwarden (format 2)."),
            "{e}"
        );
        for bad in ["format = 0\n", "format = \"2\"\n", "format = -1\n"] {
            let e = Config::parse(bad).unwrap_err().to_string();
            assert!(e.contains("format must be a whole number"), "{bad}: {e}");
        }
    }

    /// This computer's own sections name and ignore a key this version
    /// doesn't know, and the rest of the file is used.
    #[test]
    fn unknown_local_keys_are_named_and_ignored() {
        let c = Config::parse(
            "new_section = 1\n[state]\nbackend = \"local\"\npath = \"h\"\nsoon = true\n\
             [ingest]\nmax_zip_entries = 9\nlater = 1\n[opengraph]\nmax_kinds = 3\nnext = []\n",
        )
        .unwrap();
        assert_eq!(c.state.path.as_deref(), Some("h"));
        assert_eq!(c.ingest.max_zip_entries, Some(9));
        assert_eq!(c.opengraph.max_kinds, Some(3));
        let words: Vec<String> = c.warnings.iter().map(|w| w.to_string()).collect();
        for (place, key) in [
            ("the top level", "new_section"),
            ("[state]", "soon"),
            ("[ingest]", "later"),
            ("[opengraph]", "next"),
        ] {
            assert!(
                words
                    .iter()
                    .any(|w| w.starts_with(&format!("{place}: `{key}` is not a key"))),
                "{place} {key}: {words:?}"
            );
        }
        assert_eq!(words.len(), 4, "{words:?}");
        assert!(words.iter().all(|w| w.ends_with('.')), "{words:?}");
    }

    /// A typo of a known key or section in this computer's own sections
    /// is refused, never ignored: each would quietly weaken the analysis
    /// or the history.
    #[test]
    fn local_typos_are_refused() {
        for (text, place, key, meant) in [
            // Drops the extra Tier Zero objects: a false negative.
            (
                "tierzero = [\"A\"]\n",
                "the top level",
                "tierzero",
                "tier_zero",
            ),
            // Plurals of the sections.
            (
                "[[outputs]]\nplugin = \"x\"\n",
                "the top level",
                "outputs",
                "output",
            ),
            (
                "[[zones]]\nname = \"Z\"\n",
                "the top level",
                "zones",
                "zone",
            ),
            (
                "[[mappings]]\npath = \"p.toml\"\n",
                "the top level",
                "mappings",
                "mapping",
            ),
            ("[rule]\nstale_days = 9\n", "the top level", "rule", "rules"),
            // Would leave encryption off.
            (
                "[state]\nencryped = true\n",
                "[state]",
                "encryped",
                "encrypted",
            ),
            // Would still push.
            ("[state]\npushh = false\n", "[state]", "pushh", "push"),
            (
                "[state]\nbakend = \"git\"\n",
                "[state]",
                "bakend",
                "backend",
            ),
            (
                "[ingest]\nmax_zip_entry = 9\n",
                "[ingest]",
                "max_zip_entry",
                "max_zip_entries",
            ),
            (
                "[opengraph]\ntrusts = []\n",
                "[opengraph]",
                "trusts",
                "trust",
            ),
            // Stems: whatever is said around them.
            (
                "[state]\nencryption = true\n",
                "[state]",
                "encryption",
                "encrypted",
            ),
            (
                "[state]\nencrypt_history = true\n",
                "[state]",
                "encrypt_history",
                "encrypted",
            ),
            ("[state]\nno_push = true\n", "[state]", "no_push", "push"),
            ("tier0 = [\"A\"]\n", "the top level", "tier0", "tier_zero"),
            ("tier_0 = [\"A\"]\n", "the top level", "tier_0", "tier_zero"),
        ] {
            let e = Config::parse(text).unwrap_err().to_string();
            assert!(
                e.ends_with(&format!(
                    "{place}: unknown key `{key}`. Did you mean `{meant}`?"
                )),
                "{text}: {e}"
            );
        }
        // A key no known one is near is a newer version's: named, ignored.
        let c = Config::parse("[state]\nsync_window = 3\n").unwrap();
        assert_eq!(c.warnings.len(), 1);
    }

    /// The keys a later version may add to this computer's sections never
    /// read as typos of today's: a known key added within one
    /// letter of one of them fails here first.
    #[test]
    fn local_future_keys_are_not_typos() {
        for known in [
            TOP_KEYS,
            STATE_KEYS,
            INGEST_KEYS,
            OPENGRAPH_KEYS,
            COLLECT_KEYS,
        ] {
            for k in LOCAL_FUTURE {
                assert_eq!(local_near_miss(k, known), None, "{k} in {known:?}");
            }
        }
        // Two letters off is not a near miss here.
        assert_eq!(local_near_miss("exclude_names", STATE_KEYS), None);
        assert_eq!(local_near_miss("mapping", &["masking"]), None);
    }

    #[test]
    fn collect_all_attributes_is_off_unless_set() {
        assert!(!Config::parse("").unwrap().collect.all_attributes);
        let c = Config::parse("[collect]\nall_attributes = true\n").unwrap();
        assert!(c.collect.all_attributes && c.warnings.is_empty());
        let e = Config::parse("[collect]\nall_attribute = true\n").unwrap_err();
        assert!(e.to_string().contains("all_attributes"), "{e}");
    }

    /// `[collect] read_streams`, within 1 to 8; not set, the
    /// collector's default.
    #[test]
    fn collect_read_streams_is_kept_within_one_to_eight() {
        let at = |text: &str| Config::parse(text).unwrap().collect.read_streams();
        assert_eq!(at(""), None);
        assert_eq!(at("[collect]\nread_streams = 2\n"), Some(2));
        assert_eq!(at("[collect]\nread_streams = 0\n"), Some(1));
        assert_eq!(at("[collect]\nread_streams = 64\n"), Some(8));
        assert!(Config::parse("[collect]\nread_streams = \"four\"\n").is_err());
        let c = Config::parse("[collect]\nread_streams = 4\n").unwrap();
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    }

    #[test]
    fn pull_every_reads_and_clamps() {
        let at = |text: &str| Config::parse(text).unwrap().state.refresh_minutes();
        assert_eq!(at(""), DEFAULT_REFRESH_MINUTES);
        assert_eq!(
            at("[state]\nbackend = \"git\"\nremote = \"https://e.com/s.git\"\nrefresh = 30\n"),
            30
        );
        assert_eq!(at("[state]\nrefresh = 0\n"), 1);
        assert_eq!(at("[state]\nrefresh = 100000\n"), MAX_REFRESH_MINUTES);
        assert!(Config::parse("[state]\nrefresh = -1\n").is_err());
    }

    #[test]
    fn dates() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("1970-03-01"), Some(59 * 86_400));
        assert_eq!(parse_date("2026-10-08"), Some(1_791_417_600));
        assert_eq!(parse_date("2026-13-01"), None);
        assert_eq!(parse_date("soon"), None);
    }

    #[test]
    fn parses_and_validates() {
        let c = Config::parse(
            r#"
            tier_zero = ["BACKUP01.CONTOSO.LOCAL"]
            [rules]
            disabled = ["PW-011"]
            stale_days = 30
            [[suppress]]
            rule = "PW-013"
            reason = "accepted"
            expires = "2030-01-01"
            "#,
        )
        .unwrap();
        assert_eq!(c.tier_zero.len(), 1);
        assert_eq!(c.settings().stale_days, 30);
        assert_eq!(c.settings().password_age_days, 365);

        assert!(Config::parse("[[suppress]]\nreason = \"x\"").is_err());
        assert!(Config::parse(
            "[[suppress]]\nrule = \"PW-001\"\nreason = \"x\"\nexpires = \"tomorrow\""
        )
        .is_err());
        // An unknown top-level key is named and ignored.
        assert_eq!(Config::parse("unknown_key = 1").unwrap().warnings.len(), 1);
    }

    #[test]
    fn accepted_risks_old_and_new() {
        let c = Config::parse(
            r#"
            # Before attribution: reads as not recorded.
            [[suppress]]
            rule = "PW-011"
            reason = "Kiosks"

            [[suppress]]
            fingerprint = "PW-004-13b0863341b2e306"
            reason = "Break-glass account"
            expires = "2099-01-31"
            accepted_by = 'NORTH\eddard.stark'
            accepted_on = "PW-SCHED01"
            accepted_at = "2026-10-22T14:03:11Z"
            changed_by = 'NORTH\robb.stark'
            changed_on = "SECOPS-WS02"
            changed_at = "2026-11-02T09:15:00Z"

            [[suppress.notes]]
            by = 'NORTH\robb.stark'
            on = "SECOPS-WS02"
            at = "2026-11-02T09:15:00Z"
            text = "CHG0012345 renewed for Q1."

            [[suppress.notes]]
            text = "Written by hand."
            "#,
        )
        .unwrap();
        let (old, new) = (&c.suppress[0], &c.suppress[1]);
        assert!(old.accepted_by.is_none() && old.notes.is_empty());
        let a = old.acceptance();
        assert!(a.whole_rule);
        assert_eq!(a.accepted_line(), NOT_RECORDED);
        assert_eq!(a.changed_line(), None);
        // Nothing unknown in the JSON either.
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({"whole_rule": true})
        );
        let a = new.acceptance();
        assert_eq!(
            a.accepted_line(),
            "accepted by NORTH\\eddard.stark on PW-SCHED01, Oct 22, 2026"
        );
        assert_eq!(
            a.changed_line().as_deref(),
            Some("changed by NORTH\\robb.stark on SECOPS-WS02, Nov 2, 2026")
        );
        assert_eq!(a.notes.len(), 2);
        assert_eq!(a.notes[1].by, None);
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["accepted_on"], "PW-SCHED01");
        assert_eq!(v["notes"][0]["text"], "CHG0012345 renewed for Q1.");
        assert!(v["notes"][1].get("by").is_none());

        // A time that isn't RFC 3339 is shown as written, not refused.
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\naccepted_at = \"last Tuesday\"\n",
        )
        .unwrap();
        assert_eq!(
            c.suppress[0].acceptance().accepted_line(),
            "accepted on last Tuesday"
        );
        // A note needs its text.
        assert!(Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n[[suppress.notes]]\nby = \"y\""
        )
        .is_err());
    }

    #[test]
    fn keys_from_a_newer_version_are_ignored_but_typos_are_refused() {
        // A newer Pathwarden's keys: kept out of the way, with a warning.
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nticket = \"CHG7\"\n[[suppress.notes]]\ntext = \"x\"\nvisibility = \"team\"\n",
        )
        .unwrap();
        assert_eq!(c.suppress.len(), 1);
        assert_eq!(c.warnings.len(), 2, "{:?}", c.warnings);
        let w: Vec<String> = c.warnings.iter().map(|w| w.to_string()).collect();
        assert!(w[0].contains("Accepted risk 1") && w[0].contains("`ticket`"));
        assert_eq!(
            (
                c.warnings[0].risk,
                c.warnings[0].note,
                c.warnings[0].key.as_str()
            ),
            (1, None, "ticket")
        );
        assert!(w[1].contains("note 1") && w[1].contains("`visibility`"));
        assert_eq!(c.warnings[1].note, Some(1));
        // A typo of a known key is an error, saying which.
        for (typo, meant) in [
            ("expire = \"2030-01-01\"", "expires"),
            ("Reason2 = \"x\"", "reason"),
            ("acceptd_by = \"x\"", "accepted_by"),
            ("note = []", "notes"),
            ("REASON = \"x\"", "reason"),
        ] {
            let e = Config::parse(&format!(
                "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n{typo}\n"
            ))
            .unwrap_err()
            .to_string();
            assert!(
                e.contains(&format!("did you mean `{meant}`?")),
                "{typo}: {e}"
            );
        }
        let e = Config::parse(
            "[[suppress]]\nfingerprnt = \"PW-004-13b0863341b2e306\"\nrule = \"PW-011\"\nreason = \"r\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("did you mean `fingerprint`?"), "{e}");
        let e = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n[[suppress.notes]]\ntxt = \"x\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("note 1") && e.contains("did you mean `text`?"),
            "{e}"
        );
        // Two-letter keys only match in another case.
        assert_eq!(near_miss("bt", NOTE_KEYS), None);
        assert_eq!(near_miss("BY", NOTE_KEYS), Some("by"));
        // A typo in another shared section is refused too.
        assert!(Config::parse("[rules]\nstale_dayz = 3").is_err());
    }

    /// Keys a later version may add are never refused as typos, here or
    /// in notes; real typos still are.
    #[test]
    fn future_keys_are_not_typos() {
        for k in RESERVED_FUTURE {
            assert_eq!(near_miss(k, SUPPRESS_KEYS), None, "{k}");
            assert_eq!(near_miss(k, NOTE_KEYS), None, "{k}");
        }
        for k in SUPPRESS_KEYS
            .iter()
            .chain(NOTE_KEYS)
            .filter(|k| **k != "expires")
        {
            assert_eq!(near_miss(&format!("{k}s"), SUPPRESS_KEYS), None, "{k}s");
            assert_eq!(near_miss(&format!("{k}s"), NOTE_KEYS), None, "{k}s");
        }
        for (typo, meant) in [
            ("expire", "expires"),
            ("fingerprnt", "fingerprint"),
            ("acceptd_by", "accepted_by"),
            ("resaon", "reason"),
            ("reaosn", "reason"),
            ("Reason", "reason"),
            ("rul", "rule"),
            ("note", "notes"),
            ("changd_at", "changed_at"),
            // A slip in the last word drops who accepted it: still a typo.
            ("accepted_bt", "accepted_by"),
            ("accepted_b", "accepted_by"),
            ("accepted_yb", "accepted_by"),
            ("changed_byy", "changed_by"),
            ("changed_ax", "changed_at"),
            ("changed_oon", "changed_on"),
            ("accepted_att", "accepted_at"),
            // Anything that reads like the expiry: never ignored.
            ("expired", "expires"),
            ("expires_at", "expires"),
            ("expiry", "expires"),
            ("expiress", "expires"),
            ("Expiration", "expires"),
            ("nodes", "notes"),
        ] {
            assert_eq!(near_miss(typo, SUPPRESS_KEYS), Some(meant), "{typo}");
        }
        for (typo, meant) in [("txt", "text"), ("Text", "text"), ("AT", "at")] {
            assert_eq!(near_miss(typo, NOTE_KEYS), Some(meant), "{typo}");
        }
        // Each one in a file loads, with a warning, in entries and notes.
        for k in RESERVED_FUTURE {
            let c = Config::parse(&format!(
                "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\n{k} = \"x\"\n[[suppress.notes]]\ntext = \"x\"\n{k} = \"y\"\n"
            ))
            .unwrap_or_else(|e| panic!("{k}: {e}"));
            assert_eq!(c.warnings.len(), 2, "{k}: {:?}", c.warnings);
        }
        // And a file with them loads, with warnings.
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\nrules = [\"PW-012\"]\nzones = [\"Tier 1\"]\naccepted_in = \"x\"\n[[suppress.notes]]\ntext = \"x\"\nok = true\nin = \"y\"\n",
        )
        .unwrap();
        assert_eq!(c.warnings.len(), 5, "{:?}", c.warnings);
    }

    #[test]
    fn times_may_be_bare_toml_times() {
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\naccepted_by = \"ned\"\naccepted_at = 2026-10-22T14:03:11Z\nchanged_at = 2026-11-02T09:15:00Z\n[[suppress.notes]]\nat = 2026-11-03T08:00:00Z\ntext = \"x\"\n",
        )
        .unwrap();
        let s = &c.suppress[0];
        assert_eq!(s.accepted_at.as_deref(), Some("2026-10-22T14:03:11Z"));
        assert_eq!(s.changed_at.as_deref(), Some("2026-11-02T09:15:00Z"));
        assert_eq!(s.notes[0].at.as_deref(), Some("2026-11-03T08:00:00Z"));
        assert_eq!(
            s.acceptance().accepted_line(),
            "accepted by ned, Oct 22, 2026"
        );
        let e = Config::parse("[[suppress]]\nrule = \"PW-011\"\nreason = \"r\"\naccepted_at = 5\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("expected a time"), "{e}");
    }

    #[test]
    fn an_unknown_user_is_said_so() {
        let on = Some("PW-SCHED01".to_string());
        let at = Some("2026-10-22T14:03:11Z".to_string());
        assert_eq!(
            stamp_words(&None, &on, &at).as_deref(),
            Some("by an unknown user on PW-SCHED01, Oct 22, 2026")
        );
        assert_eq!(stamp_words(&None, &None, &None), None);
    }

    #[test]
    fn the_first_active_entry_in_the_file_accepts_a_finding() {
        use crate::findings::Severity;
        let c = Config::parse(
            r#"[[suppress]]
rule = "PW-004"
reason = "rule first"
[[suppress]]
fingerprint = "PW-004-13b0863341b2e306"
reason = "then the finding"
[[suppress]]
fingerprint = "PW-011-e184e20d17a96b1c"
reason = "expired"
expires = "1970-01-01"
[[suppress]]
rule = "PW-011"
reason = "the rule, still on"
"#,
        )
        .unwrap();
        let now = 10 * 86_400;
        // A rule entry before a finding's own: the rule's (file order).
        assert_eq!(
            c.active_suppression("PW-004-13b0863341b2e306", "PW-004", now),
            Some(0)
        );
        // An expired entry for the finding: the rule's that is still on.
        assert_eq!(
            c.active_suppression("PW-011-e184e20d17a96b1c", "PW-011", now),
            Some(3)
        );
        // Only an expired entry: none.
        let only = Config::parse(
            "[[suppress]]\nfingerprint = \"PW-011-e184e20d17a96b1c\"\nreason = \"x\"\nexpires = \"1970-01-01\"\n",
        )
        .unwrap();
        assert_eq!(
            only.active_suppression("PW-011-e184e20d17a96b1c", "PW-011", now),
            None
        );
        // The analysis names the same entry.
        let mut f = vec![Finding::new("PW-011", Severity::Medium, &["a"], "x")];
        c.apply_suppressions(&mut f, now);
        assert_eq!(f[0].accepted.as_ref().unwrap().entry, Some(3));
        assert_eq!(f[0].suppressed.as_deref(), Some("the rule, still on"));
        // The entry number isn't written out.
        assert!(serde_json::to_value(&f[0]).unwrap()["accepted"]
            .get("entry")
            .is_none());
    }

    #[test]
    fn findings_carry_who_accepted_them() {
        use crate::findings::Severity;
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\"\naccepted_by = 'NORTH\\ned'\naccepted_at = \"2026-10-22T14:03:11Z\"\n",
        )
        .unwrap();
        let mut f = vec![
            Finding::new("PW-011", Severity::Medium, &["a"], "x"),
            Finding::new("PW-012", Severity::Medium, &["b"], "y"),
        ];
        c.apply_suppressions(&mut f, 0);
        assert_eq!(f[0].suppressed.as_deref(), Some("Kiosks"));
        let a = f[0].accepted.as_ref().unwrap();
        assert_eq!(a.accepted_by.as_deref(), Some("NORTH\\ned"));
        assert!(a.whole_rule);
        assert!(f[1].accepted.is_none());
        let v = serde_json::to_value(&f[0]).unwrap();
        assert_eq!(v["accepted"]["accepted_by"], "NORTH\\ned");
        assert!(serde_json::to_value(&f[1])
            .unwrap()
            .get("accepted")
            .is_none());
        // Expired: neither.
        let c = Config::parse(
            "[[suppress]]\nrule = \"PW-011\"\nreason = \"Kiosks\"\nexpires = \"1970-01-01\"\n",
        )
        .unwrap();
        c.apply_suppressions(&mut f, 10 * 86_400);
        assert!(f[0].suppressed.is_none() && f[0].accepted.is_none());
    }

    #[test]
    fn every_url_is_redacted_and_passwords_are_noticed() {
        assert_eq!(
            redact_urls("fetch https://u:p@a.example/x failed; https://t@b.example/y?q=1@2"),
            "fetch https://***@a.example/x failed; https://***@b.example/y?q=1@2"
        );
        assert_eq!(
            redact_urls("https://host/a@b and git@github.com:o/r.git"),
            "https://host/a@b and git@github.com:o/r.git"
        );
        assert!(remote_has_password("https://user:ghp_x@github.com/o/s.git"));
        assert!(!remote_has_password(
            "https://org@dev.azure.com/org/p/_git/s"
        ));
        assert!(!remote_has_password("git@github.com:o/s.git"));
        assert!(!remote_has_password("https://host/a:b@c"));
        // A user name stays allowed; a token in its place doesn't.
        assert!(!remote_has_token("https://org@dev.azure.com/org/p/_git/r"));
        assert!(!remote_has_token(
            "https://first.last@git.example.com/x.git"
        ));
        assert!(remote_has_token(
            "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/s.git"
        ));
        assert!(remote_has_token(
            "https://GLPAT-abc@gitlab.example.com/x.git"
        ));
        assert!(remote_has_token(&format!(
            "https://{}@dev.azure.com/org/p/_git/r",
            "a1b2c3d4e5".repeat(5) + "zz"
        )));
        // user:password is the other check's.
        assert!(remote_has_password("https://x:ghp_abc@github.com/o/s.git"));
        assert!(!remote_has_token("ssh://git@host/x.git"));
        assert!(!remote_has_token("git@github.com:o/s.git"));
        assert!(!remote_has_token("https://host/a@b"));
        assert!(!remote_has_token("https://host/x.git"));
        let e = validate_remote("-https://u:secret@x").unwrap_err();
        assert!(!e.contains("secret"), "{e}");
    }

    /// The full-run file limit, and GitHub's hold on it.
    #[test]
    fn the_full_run_file_limit_is_held_on_github() {
        for gh in [
            "https://github.com/contoso/history.git",
            "https://***@github.com/contoso/history.git",
            "https://user:tok@GitHub.com:443/contoso/history",
            "git@github.com:contoso/history.git",
            "ssh://git@github.com/contoso/history.git",
        ] {
            assert!(is_github_remote(gh), "{gh}");
        }
        for other in [
            "https://contoso@dev.azure.com/contoso/p/_git/history",
            "https://git.fabrikam.example/github.com/x.git",
            "https://github.com.fabrikam.example/x.git",
            "C:/Users/ann/state.git",
            "/srv/git/history.git",
            "",
        ] {
            assert!(!is_github_remote(other), "{other}");
        }
        let at = |mb: Option<u64>| StateConfig {
            full_run_file_mb: mb,
            ..StateConfig::default()
        };
        assert_eq!(at(None).full_run_file_mb(), DEFAULT_FULL_RUN_FILE_MB);
        assert_eq!(at(Some(0)).full_run_file_mb(), 1);
        assert_eq!(at(Some(99_999)).full_run_file_mb(), MAX_FULL_RUN_FILE_MB);
        let gh = Some("https://github.com/contoso/history.git");
        let ado = Some("https://contoso@dev.azure.com/contoso/p/_git/history");
        assert_eq!(at(Some(200)).full_run_file_mb_for(gh), 95);
        assert_eq!(at(Some(200)).full_run_file_mb_for(ado), 200);
        assert_eq!(at(Some(200)).full_run_file_mb_for(None), 200);
        assert_eq!(at(None).full_run_file_mb_for(gh), 75);
        assert_eq!(at(Some(60)).full_run_file_bytes_for(gh), 60 << 20);
    }
}

#[cfg(test)]
mod doc_tests {
    use super::Config;

    /// Every TOML snippet in the docs, and the example config, must be valid.
    #[test]
    fn documented_config_parses() {
        for (name, doc) in [
            (
                "privilege-zones.md",
                include_str!("../../../docs/privilege-zones.md"),
            ),
            ("running.md", include_str!("../../../docs/running.md")),
            ("plugins.md", include_str!("../../../docs/plugins.md")),
        ] {
            let mut blocks = 0;
            for block in doc.split("```toml").skip(1) {
                let body = block.split("```").next().unwrap();
                // Indented blocks (inside list items) are dedented first.
                let body: String = body
                    .lines()
                    .map(|l| format!("{}\n", l.trim_start()))
                    .collect();
                let c = Config::parse(&body)
                    .unwrap_or_else(|e| panic!("invalid example in {name}:\n{body}\n{e}"));
                // Every documented key is one the lists of known keys have.
                for w in &c.warnings {
                    assert!(
                        !w.to_string().contains("is not a key this version"),
                        "{name}: {w}\n{body}"
                    );
                }
                blocks += 1;
            }
            assert!(blocks >= 1, "found {blocks} toml examples in {name}");
        }
        let c = Config::parse(include_str!("../../../pathwarden.example.toml"))
            .expect("pathwarden.example.toml parses");
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    }
}
