//! SYSVOL and NETLOGON: who can write the files that Group Policy and logon
//! scripts run, and Group Policy Preferences passwords.
//!
//! Pathwarden's built-in collector reads these from the domain controller
//! and writes them to `pathwarden-sysvol.json` in its zip (schema
//! `pathwarden.sysvol.v1`). Nothing here is in BloodHound's data model:
//!
//! - **`WriteGPOFiles`** (principal → GPO): write access to the GPO's folder
//!   in SYSVOL, or to one of its key subfolders, by someone who is neither a
//!   default writer nor allowed to edit the GPO in AD. Writing the files
//!   changes what the GPO applies, so it is control of the GPO, and through
//!   its links of every object it applies to, exactly like `GenericWrite` on
//!   the GPO object.
//! - **`WriteLogonScript`** (principal → user): write access to the script in
//!   NETLOGON that the user's `scriptPath` names. It runs as the user at the
//!   next logon.
//! - **GPP passwords**: a Group Policy Preferences file with a `cpassword`
//!   attribute. The collector records that one exists, in which GPO and
//!   file, and for which account. The value itself is never read into the
//!   output.
//!
//! - **Registry policy**: the Windows Update and SCCM setup
//!   values each GPO's `Machine\Registry.pol` sets ([`regpol`]). They name
//!   the WSUS server, and the SCCM site, of the domain controllers and CA
//!   hosts the GPOs apply to ([`policy`]).
//! - **SCCM site objects**: not SYSVOL, but the same
//!   collector's sidecar is where data outside BloodHound's model goes. The
//!   sites and management points under `CN=System Management` ([`sccm`]).
//!
//! The collector sends the security descriptors as the server returned them;
//! [`sd`] interprets them. Each part has a status (complete, partial, not
//! collected) that becomes a data source for retest, so a part that was not
//! read this time can't turn a finding into "fixed".

pub mod policy;
pub mod regpol;
pub mod sccm;
pub mod sd;

use std::collections::{BTreeMap, HashSet};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::opengraph::EdgeOrigin;
use crate::sid;

pub const SCHEMA: &str = "pathwarden.sysvol.v1";
/// The file name the collector writes (in its zip).
pub const FILE_NAME: &str = "pathwarden-sysvol.json";
/// Largest sidecar read.
pub const MAX_SIDECAR_BYTES: u64 = 64 << 20;

/// Caps on what one sidecar may list. Real domains stay far below them.
const MAX_GPOS: usize = 200_000;
const MAX_FOLDERS_PER_GPO: usize = 16;
const MAX_SCRIPTS: usize = 200_000;
const MAX_SCRIPT_USERS: usize = 5_000_000;
const MAX_GPP: usize = 100_000;
const MAX_ACCOUNTS: usize = 64;
/// The collector's caps for `gpo_local_groups`.
const MAX_LOCAL_ENTRIES: usize = 100_000;
const MAX_LOCAL_MEMBERS: usize = 1_000;
/// A security descriptor is at most 64 KiB, so 128 Ki hex digits.
const MAX_SD_HEX: usize = 128 * 1024;
const MAX_TEXT: usize = 1024;
/// Why the registry policy part is partial when the sidecar had entries
/// that were not right.
const POLICY_DROPPED: &str = "some GPOs' registry policy entries were not right";
/// Notes kept per sidecar in the ingest statistics.
const MAX_NOTES: usize = 20;

/// Whether a file name is a SYSVOL sidecar's (`pathwarden-sysvol.json`, or
/// anything ending in it).
pub fn is_sidecar_name(label: &str) -> bool {
    let name = label
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(label)
        .to_ascii_lowercase();
    name.ends_with(FILE_NAME)
}

/// How much of one part the collector read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Not read at all (no rights, an unsupported platform, ...).
    #[default]
    NotCollected,
    /// Read, but some items failed or the step ran out of time.
    Partial,
    /// Every item read.
    Complete,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::NotCollected => "not collected",
            CheckStatus::Partial => "partly collected",
            CheckStatus::Complete => "collected",
        }
    }
}

/// One part of the SYSVOL step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    #[serde(default)]
    pub status: CheckStatus,
    /// Why it is not complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Items read (folders, scripts, files).
    #[serde(default)]
    pub read: usize,
    /// Items that could not be read.
    #[serde(default)]
    pub failed: usize,
    /// Items not checked on purpose (a logon script on another server, a
    /// file over the size limit, ...).
    #[serde(default)]
    pub skipped: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checks {
    /// GPO folder permissions.
    #[serde(default)]
    pub gpo_acl: Check,
    /// Logon script permissions.
    #[serde(default)]
    pub logon_script_acl: Check,
    /// GPP password scan.
    #[serde(default)]
    pub gpp: Check,
    /// Local groups set by GPOs. `None` in sidecars from before it was
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpo_local_groups: Option<Check>,
    /// `Machine\Registry.pol` of the GPOs. `None` in sidecars from
    /// before it was read: not collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_pol: Option<Check>,
    /// SCCM's site objects from the directory read. `None` in
    /// sidecars from before they were kept: not collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sccm_sites: Option<Check>,
}

/// What a part that a sidecar doesn't record reads as.
static NOT_READ: Check = Check {
    status: CheckStatus::NotCollected,
    reason: None,
    read: 0,
    failed: 0,
    skipped: 0,
};

/// The sidecar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema: String,
    /// DNS name of the domain.
    pub domain: String,
    /// The domain controller read.
    #[serde(default)]
    pub dc: Option<String>,
    #[serde(default)]
    pub checks: Checks,
    #[serde(default)]
    pub gpos: Vec<GpoFolder>,
    #[serde(default)]
    pub logon_scripts: Vec<LogonScript>,
    #[serde(default)]
    pub gpp_passwords: Vec<GppPassword>,
    /// Which GPO and setting puts each member in the local groups.
    /// Empty in sidecars from before it was recorded and in runs as the
    /// current Windows user.
    /// Read entry by entry: one that is not right is skipped, never the file.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "lenient_local_groups"
    )]
    pub gpo_local_groups: Vec<GpoLocalGroup>,
    /// GPOs (object IDs) whose `gpo_local_groups` record is incomplete: an
    /// entry was skipped or its members cut. Fixes name no GPO wherever they
    /// are linked. Set by [`Sidecar::parse`].
    #[serde(skip)]
    pub gpo_local_incomplete: Vec<String>,
    /// The Windows Update and SCCM setup values each GPO's
    /// `Machine\Registry.pol` sets. Only GPOs that set one are
    /// listed. Read entry by entry: one that is not right is dropped, and
    /// the part then counts as read only partly.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "lenient_policy"
    )]
    pub registry_policy: Vec<GpoPolicy>,
    /// SCCM's site objects. Empty when there are none, or in
    /// sidecars from before they were kept (`checks.sccm_sites` tells).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sccm: Option<sccm::SccmSites>,
    /// GPO links the collector found disabled (`gPLink` status).
    /// `None` when not read (older sidecars): the links' status is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_gp_links: Option<Vec<DisabledLink>>,
    /// GPOs whose `Machine\Registry.pol` could not be read or parsed:
    /// the registry policy part is held only where one of them applies to
    /// a Tier Zero host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_pol_failed: Vec<GpoRef>,
    /// SIDs of computers created through the machine account quota
    /// (`mS-DS-CreatorSID` set). `None` when not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_quota_computers: Option<Vec<String>>,
}

/// A disabled GPO link: the OU's or domain's distinguished name and the
/// GPO's ID (its GUID, without braces).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisabledLink {
    pub container: String,
    pub gpo: String,
}

/// A GPO by folder name and ObjectIdentifier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoRef {
    pub guid: String,
    #[serde(default)]
    pub object_id: Option<String>,
}

/// `registry_policy`, with each entry that does not read kept as an empty
/// placeholder (no GUID) that [`Sidecar::parse`] drops and notes.
fn lenient_policy<'de, D>(d: D) -> Result<Vec<GpoPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|v| GpoPolicy::deserialize(&v).unwrap_or_default())
            .collect(),
        _ => vec![GpoPolicy::default()],
    })
}

/// The registry values one GPO's `Machine\Registry.pol` sets under the
/// keys Pathwarden keeps ([`regpol`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoPolicy {
    /// The folder name, `{GUID}`.
    pub guid: String,
    /// The GPO's ObjectIdentifier in the collection.
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub values: Vec<regpol::PolicyValue>,
}

/// `gpo_local_groups`, with each entry that does not read (a wrong type,
/// a missing field) kept as a placeholder that [`Sidecar::parse`] drops and
/// notes: its `object_id`, when it has a readable one, and unknown setting.
/// Not a list at all: one placeholder without an object ID.
fn lenient_local_groups<'de, D>(d: D) -> Result<Vec<GpoLocalGroup>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let placeholder = |v: &serde_json::Value| GpoLocalGroup {
        guid: String::new(),
        object_id: v
            .get("object_id")
            .and_then(|id| id.as_str())
            .map(str::to_string),
        setting: LocalSetting::Unknown,
        group: LocalGroup::Unknown,
        item_level_targeting: false,
        members_truncated: false,
        members: Vec::new(),
    };
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|v| GpoLocalGroup::deserialize(&v).unwrap_or_else(|_| placeholder(&v)))
            .collect(),
        _ => vec![placeholder(&serde_json::Value::Null)],
    })
}

/// The GPO setting that puts members in a local group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSetting {
    /// Security Settings: Restricted Groups (`GptTmpl.inf`).
    RestrictedGroups,
    /// Preferences: Local Users and Groups (`Groups.xml`).
    Gpp,
    /// A setting this version does not know; the entry is dropped.
    #[serde(other)]
    Unknown,
}

impl LocalSetting {
    /// Its name in Group Policy Management.
    pub fn label(self) -> &'static str {
        match self {
            LocalSetting::RestrictedGroups => "Restricted Groups",
            _ => "Local Users and Groups",
        }
    }
}

/// The four local groups Group Policy can fill that become edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalGroup {
    Administrators,
    RemoteDesktop,
    Dcom,
    PsRemote,
    /// A group this version does not know; the entry is dropped.
    #[serde(other)]
    Unknown,
}

impl LocalGroup {
    /// The edge membership gives on the computers.
    pub fn edge(self) -> Option<EdgeKind> {
        Some(match self {
            LocalGroup::Administrators => EdgeKind::AdminTo,
            LocalGroup::RemoteDesktop => EdgeKind::CanRdp,
            LocalGroup::Dcom => EdgeKind::ExecuteDcom,
            LocalGroup::PsRemote => EdgeKind::CanPsRemote,
            LocalGroup::Unknown => return None,
        })
    }
}

/// What one GPO, through one setting, puts in one local group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoLocalGroup {
    /// The folder name, `{GUID}`.
    pub guid: String,
    /// The GPO's ObjectIdentifier in the collection.
    #[serde(default)]
    pub object_id: Option<String>,
    pub setting: LocalSetting,
    pub group: LocalGroup,
    /// Only Local Users and Groups items with item-level targeting add
    /// these members, so they may not be on every computer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub item_level_targeting: bool,
    /// The collector cut the members at its cap.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub members_truncated: bool,
    /// Object IDs, as `GPOChanges` writes them.
    #[serde(default)]
    pub members: Vec<String>,
}

/// Where a local right Group Policy sets comes from: the setting of a GPO
/// that puts the member in the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpoSetting {
    pub setting: LocalSetting,
    /// Only through item-level targeting.
    pub targeted: bool,
}

/// An object ID that is a SID, or a well-known SID with its domain prefix.
fn is_member_id(id: &str) -> bool {
    let (_, s) = sid::split_prefixed(id);
    id.len() <= 300
        && s.strip_prefix("S-1-").is_some_and(|rest| {
            rest.split('-')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// The security descriptors of one GPO's folder and key subfolders.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpoFolder {
    /// The folder name, `{GUID}` (the GPO's `cn`).
    pub guid: String,
    /// The GPO's ObjectIdentifier in the collection.
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub folders: Vec<FolderSd>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FolderSd {
    /// Relative to the GPO folder: "" for the folder itself, `Machine`, ...
    #[serde(default)]
    pub path: String,
    /// Self-relative security descriptor, hex.
    pub sd: String,
}

/// One script in NETLOGON and the users whose `scriptPath` names it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogonScript {
    /// Relative to NETLOGON, as the users' `scriptPath` gives it.
    pub script: String,
    /// The users' SIDs.
    #[serde(default)]
    pub users: Vec<String>,
    pub sd: String,
}

/// A GPP file with a `cpassword` attribute. Never the value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GppPassword {
    pub guid: String,
    #[serde(default)]
    pub object_id: Option<String>,
    /// Relative to the GPO folder, e.g. `Machine\Preferences\Groups\Groups.xml`.
    pub file: String,
    /// The accounts the passwords belong to, as the file names them.
    #[serde(default)]
    pub accounts: Vec<String>,
}

/// `{8-4-4-4-12}` in hex: a GPO folder name.
pub fn is_gpo_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// A path that stays inside its share: relative, no `..`, no drive, no
/// characters Windows refuses in file names.
pub fn is_safe_relative(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 260
        && !p.starts_with(['\\', '/'])
        && !p.contains(':')
        && !p
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
        && p.split(['\\', '/'])
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

impl Sidecar {
    /// Parses and checks a sidecar. Entries that are malformed are dropped
    /// (and named in `notes`); a sidecar that is too large, of another
    /// schema, or not JSON is refused whole.
    pub fn parse(bytes: &[u8], notes: &mut Vec<String>) -> Result<Sidecar, String> {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        if bytes.len() as u64 > MAX_SIDECAR_BYTES {
            return Err("too large for a SYSVOL file".into());
        }
        let mut s: Sidecar = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if s.schema != SCHEMA {
            return Err(format!("schema '{}' is not {SCHEMA}", s.schema));
        }
        if s.domain.trim().is_empty() || s.domain.len() > 255 {
            return Err("no domain".into());
        }
        if s.gpos.len() > MAX_GPOS
            || s.logon_scripts.len() > MAX_SCRIPTS
            || s.gpp_passwords.len() > MAX_GPP
            || s.logon_scripts.iter().map(|l| l.users.len()).sum::<usize>() > MAX_SCRIPT_USERS
        {
            return Err("it lists too many entries".into());
        }
        let mut note = |n: String| {
            if notes.len() < MAX_NOTES {
                notes.push(n);
            }
        };
        s.gpos.retain_mut(|g| {
            if !is_gpo_guid(&g.guid) || g.folders.len() > MAX_FOLDERS_PER_GPO {
                note("a GPO folder entry with a malformed name was skipped".into());
                return false;
            }
            g.folders.retain(|f| {
                let ok =
                    (f.path.is_empty() || is_safe_relative(&f.path)) && f.sd.len() <= MAX_SD_HEX;
                if !ok {
                    note(format!("{}: a malformed folder entry was skipped", g.guid));
                }
                ok
            });
            true
        });
        s.logon_scripts.retain(|l| {
            let ok = is_safe_relative(&l.script) && l.sd.len() <= MAX_SD_HEX;
            if !ok {
                note("a malformed logon script entry was skipped".into());
            }
            ok
        });
        s.gpp_passwords.retain_mut(|p| {
            let ok = is_gpo_guid(&p.guid) && is_safe_relative(&p.file);
            if !ok {
                note("a malformed GPP entry was skipped".into());
            }
            p.accounts.truncate(MAX_ACCOUNTS);
            p.accounts.retain(|a| a.len() <= MAX_TEXT);
            ok
        });
        // Additive: an entry or list that is not right only loses the GPO
        // names in the fixes, never the rest of the file. All or nothing per
        // GPO: a GPO whose record is not whole names nobody, since a partial
        // one could name another GPO alone where both set the member.
        let mut incomplete: HashSet<String> = HashSet::new();
        let mut unusable = s.gpo_local_groups.len() > MAX_LOCAL_ENTRIES;
        if unusable {
            note("the GPO local group list is too long and was skipped".into());
        }
        if !unusable {
            for e in &mut s.gpo_local_groups {
                let id = e.object_id.as_deref().filter(|id| id.len() <= MAX_TEXT);
                if !is_gpo_guid(&e.guid)
                    || e.setting == LocalSetting::Unknown
                    || e.group == LocalGroup::Unknown
                {
                    note("a malformed GPO local group entry was skipped".into());
                    match id {
                        Some(id) => {
                            incomplete.insert(id.to_string());
                        }
                        // It can't be told which GPO it was: none is named.
                        None => unusable = true,
                    }
                    e.members.clear();
                    continue;
                }
                let Some(id) = id else {
                    // No GPO to resolve: nothing to name.
                    e.members.clear();
                    continue;
                };
                if e.members.len() > MAX_LOCAL_MEMBERS {
                    note(format!(
                        "{}: members over {MAX_LOCAL_MEMBERS} were skipped",
                        e.guid
                    ));
                    e.members.truncate(MAX_LOCAL_MEMBERS);
                    e.members_truncated = true;
                }
                let before = e.members.len();
                e.members.retain(|m| is_member_id(m));
                if e.members.len() < before {
                    note(format!("{}: a malformed member was skipped", e.guid));
                    e.members_truncated = true;
                }
                if e.members_truncated {
                    incomplete.insert(id.to_string());
                }
            }
        }
        if unusable {
            s.gpo_local_groups.clear();
        } else {
            s.gpo_local_groups.retain(|e| !e.members.is_empty());
            s.gpo_local_incomplete = incomplete.into_iter().collect();
            s.gpo_local_incomplete.sort();
        }
        // Registry policy: an entry that is not right is dropped, and what
        // the GPOs set can then not be told whole, so the part is partial.
        let mut dropped = 0usize;
        if s.registry_policy.len() > MAX_GPOS {
            dropped = s.registry_policy.len();
            s.registry_policy.clear();
        }
        s.registry_policy.retain_mut(|p| {
            let ok = is_gpo_guid(&p.guid)
                && p.object_id.as_ref().is_none_or(|id| id.len() <= MAX_TEXT)
                && p.values.len() <= regpol::MAX_VALUES;
            if !ok {
                dropped += 1;
                return false;
            }
            let before = p.values.len();
            p.values.retain(regpol::PolicyValue::is_valid);
            dropped += usize::from(p.values.len() < before);
            !p.values.is_empty()
        });
        if let Some(list) = s.disabled_gp_links.as_mut() {
            list.truncate(MAX_GPOS);
            list.retain(|l| l.container.len() <= MAX_TEXT && l.gpo.len() <= MAX_TEXT);
        }
        s.registry_pol_failed.truncate(MAX_GPOS);
        s.registry_pol_failed.retain(|f| {
            f.guid.len() <= MAX_TEXT && f.object_id.as_ref().is_none_or(|id| id.len() <= MAX_TEXT)
        });
        if let Some(list) = s.machine_quota_computers.as_mut() {
            list.truncate(MAX_SCRIPT_USERS);
            list.retain(|sid| is_member_id(sid));
        }
        if let Some(sites) = s.sccm.as_mut() {
            let n = sites.check();
            if n > 0 {
                note(format!(
                    "{} not right and skipped",
                    crate::text::count(n, "SCCM site entry was", "SCCM site entries were")
                ));
            }
        }
        if dropped > 0 {
            note(format!(
                "{} not right and skipped",
                crate::text::count(
                    dropped,
                    "registry policy entry was",
                    "registry policy entries were"
                )
            ));
            if let Some(c) = s.checks.registry_pol.as_mut() {
                if c.status == CheckStatus::Complete {
                    c.status = CheckStatus::Partial;
                    c.reason = Some(POLICY_DROPPED.into());
                }
            }
        }
        Ok(s)
    }
}

/// The three parts, as data sources for retest (see
/// [`crate::opengraph::coverage::RunSources`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Part {
    GpoAcl,
    LogonScriptAcl,
    Gpp,
    /// `Machine\Registry.pol` of the GPOs: the WSUS server and SCCM
    /// site of the domain controllers and CA hosts.
    RegistryPol,
    /// SCCM's site objects: the site of each site server.
    SccmSites,
    /// The local groups GPOs set (Restricted Groups, Group Policy
    /// Preferences): the AdminTo, CanRDP, ExecuteDCOM and CanPSRemote
    /// rights linked GPOs grant.
    GpoLocalGroups,
}

impl Part {
    pub const ALL: [Part; 6] = [
        Part::GpoAcl,
        Part::LogonScriptAcl,
        Part::Gpp,
        Part::RegistryPol,
        Part::SccmSites,
        Part::GpoLocalGroups,
    ];

    /// The source name findings that rest on this part carry.
    pub fn source(self, domain: &str) -> String {
        let what = match self {
            Part::GpoAcl => "SYSVOL GPO permissions",
            Part::LogonScriptAcl => "NETLOGON logon script permissions",
            Part::Gpp => "SYSVOL GPP passwords",
            Part::RegistryPol => "SYSVOL registry policy",
            Part::SccmSites => "SCCM site objects",
            Part::GpoLocalGroups => "SYSVOL GPO local groups",
        };
        format!("{what} ({})", domain.trim().to_ascii_uppercase())
    }

    pub fn of(self, c: &Checks) -> &Check {
        match self {
            Part::GpoAcl => &c.gpo_acl,
            Part::LogonScriptAcl => &c.logon_script_acl,
            Part::Gpp => &c.gpp,
            Part::RegistryPol => c.registry_pol.as_ref().unwrap_or(&NOT_READ),
            Part::SccmSites => c.sccm_sites.as_ref().unwrap_or(&NOT_READ),
            Part::GpoLocalGroups => c.gpo_local_groups.as_ref().unwrap_or(&NOT_READ),
        }
    }
}

/// Well-known writers of GPO folders and logon scripts that are never
/// reported: SYSTEM, CREATOR OWNER, OWNER RIGHTS, CREATOR GROUP, BUILTIN
/// Administrators, Enterprise Domain Controllers, Domain Admins, Enterprise
/// Admins, and (for GPO folders) Group Policy Creator Owners. All but the
/// last are Tier Zero anyway; Group Policy Creator Owners appear on folders
/// of GPOs their members created.
pub fn is_default_writer(sid: &str, gpo: bool) -> bool {
    let (_, s) = sid::split_prefixed(sid);
    matches!(
        s,
        "S-1-5-18" | "S-1-3-0" | "S-1-3-1" | "S-1-3-4" | "S-1-5-32-544" | "S-1-5-9"
    ) || match sid::domain_rid(s) {
        Some(512 | 519) => true,
        Some(520) => gpo,
        _ => false,
    }
}

/// Rights on a GPO object in AD that let a principal edit it.
fn is_ad_edit(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::GenericAll
            | EdgeKind::GenericWrite
            | EdgeKind::WriteDacl
            | EdgeKind::WriteOwner
            | EdgeKind::Owns
            | EdgeKind::OwnsLimitedRights
            | EdgeKind::WriteOwnerLimitedRights
    )
}

/// The object ID a SID from a file's security descriptor has in the
/// collection: domain SIDs as they are, well-known groups prefixed with the
/// domain the way collectors write them. `None` for SIDs Pathwarden does
/// not model (service SIDs, app containers, ...).
pub fn principal_id(sid_str: &str, domain: &str) -> Option<(String, NodeKind)> {
    if sid_str.starts_with("S-1-5-21-") {
        return Some((sid_str.to_string(), NodeKind::Base));
    }
    sid::well_known_name(sid_str)?;
    Some((
        format!("{}-{sid_str}", domain.trim().to_ascii_uppercase()),
        NodeKind::Group,
    ))
}

/// Where a write right was found, for the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileGrant {
    /// UNC path of the folder or file.
    pub path: String,
    pub rights: Vec<String>,
    /// Only as the owner.
    pub owner: bool,
    /// Every granting ACE is inherited from a parent folder.
    pub inherited: bool,
}

/// A GPP password found, with its GPO resolved.
#[derive(Debug, Clone)]
pub struct GppHit {
    pub gpo: Option<NodeIndex>,
    pub guid: String,
    pub file: String,
    pub accounts: Vec<String>,
    /// UNC path of the file.
    pub path: String,
}

/// What one domain's SYSVOL sidecar said, kept on the graph for the rules
/// and the collection completeness.
#[derive(Debug, Clone)]
pub struct SysvolDomain {
    pub domain: String,
    pub dc: Option<String>,
    pub checks: Checks,
    pub gpp: Vec<GppHit>,
    /// What each GPO's `Registry.pol` sets ([`GpoPolicy`]), for the GPOs in
    /// the collection.
    pub policy: Vec<(NodeIndex, Vec<regpol::PolicyValue>)>,
    /// SCCM's site objects in the domain.
    pub sccm: sccm::SccmSites,
    /// Disabled GPO links (container DN, GPO ID), upper case; `None` when
    /// the links' status wasn't read.
    pub disabled_links: Option<Vec<(String, String)>>,
    /// Computers created through the machine account quota (SIDs, upper
    /// case); empty when not read.
    pub quota_computers: HashSet<String>,
    /// The sidecar listed them ([`Self::quota_computers`] is the whole
    /// list, not "not read").
    pub quota_read: bool,
}

/// Ingest statistics for one sidecar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysvolStats {
    pub file: String,
    pub domain: String,
    #[serde(default)]
    pub dc: Option<String>,
    pub checks: Checks,
    pub gpo_edges: usize,
    pub script_edges: usize,
    pub gpp_files: usize,
    /// GPOs whose registry policy was recorded.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub policy_gpos: usize,
    /// GPOs, users and principals that are not in the AD data.
    pub unresolved: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// UNC path of a GPO folder (or a path inside it) through the domain's
/// SYSVOL share.
pub fn gpo_path(domain: &str, guid: &str, sub: &str) -> String {
    let d = domain.trim().to_ascii_lowercase();
    let mut p = format!(r"\\{d}\SYSVOL\{d}\Policies\{}", guid.to_ascii_uppercase());
    if !sub.is_empty() {
        p.push('\\');
        p.push_str(&sub.replace('/', "\\"));
    }
    p
}

/// UNC path of a logon script.
pub fn script_path(domain: &str, script: &str) -> String {
    format!(
        r"\\{}\NETLOGON\{}",
        domain.trim().to_ascii_lowercase(),
        script.replace('/', "\\")
    )
}

/// Adds one sidecar to the graph: the edges, the GPP hits, and the parts'
/// statuses. Runs after every AD file is read.
pub(crate) fn apply(
    g: &mut AdGraph,
    label: &str,
    s: Sidecar,
    mut notes: Vec<String>,
) -> SysvolStats {
    let domain = s.domain.trim().to_ascii_uppercase();
    let mut stats = SysvolStats {
        file: label.to_string(),
        domain: domain.clone(),
        dc: s.dc.clone(),
        checks: s.checks.clone(),
        ..SysvolStats::default()
    };
    let note = |notes: &mut Vec<String>, n: String| {
        if notes.len() < MAX_NOTES {
            notes.push(n);
        }
    };
    let gpo_source = g.add_og_source(&Part::GpoAcl.source(&domain));
    let script_source = g.add_og_source(&Part::LogonScriptAcl.source(&domain));
    g.add_og_source(&Part::Gpp.source(&domain));
    g.add_og_source(&Part::RegistryPol.source(&domain));
    g.add_og_source(&Part::SccmSites.source(&domain));

    // The principal behind a SID, creating a placeholder for a domain SID
    // the collection lacks (a deleted or foreign account), as ACEs do.
    let principal = |g: &mut AdGraph, sid_str: &str, unresolved: &mut usize| {
        let (id, hint) = principal_id(sid_str, &domain)?;
        Some(match g.lookup(&id) {
            Some(ix) => ix,
            None => {
                *unresolved += 1;
                g.ensure(&id, hint)
            }
        })
    };

    for gpo in &s.gpos {
        let Some(gix) = gpo
            .object_id
            .as_deref()
            .and_then(|id| g.lookup(id))
            .filter(|&ix| g.node(ix).kind == NodeKind::Gpo)
        else {
            stats.unresolved += 1;
            note(
                &mut notes,
                format!("GPO folder {} has no GPO in the collection", gpo.guid),
            );
            continue;
        };
        // Who may already edit the GPO in AD.
        let editors: HashSet<String> = g
            .inner()
            .edges_directed(gix, Direction::Incoming)
            .filter(|e| is_ad_edit(*e.weight()))
            .map(|e| g.node(e.source()).id.clone())
            .collect();
        // Per principal, the folders it can write.
        let mut grants: BTreeMap<String, Vec<FileGrant>> = BTreeMap::new();
        for f in &gpo.folders {
            let parsed = sd::from_hex(&f.sd).and_then(|b| sd::parse(&b));
            let parsed = match parsed {
                Ok(p) => p,
                Err(e) => {
                    note(&mut notes, format!("{} {}: {e}", gpo.guid, f.path));
                    continue;
                }
            };
            for w in sd::writers(&parsed, sd::Target::Folder) {
                if is_default_writer(&w.sid, true) {
                    continue;
                }
                grants.entry(w.sid.clone()).or_default().push(FileGrant {
                    path: gpo_path(&domain, &gpo.guid, &f.path),
                    rights: w.rights.iter().map(|r| r.to_string()).collect(),
                    owner: w.owner,
                    inherited: w.inherited,
                });
            }
        }
        for (sid_str, gs) in grants {
            let Some(pix) = principal(g, &sid_str, &mut stats.unresolved) else {
                continue;
            };
            if editors.contains(&g.node(pix).id) {
                continue;
            }
            let origin = EdgeOrigin {
                source: gpo_source,
                unit: None,
            };
            if g.add_og_edge(pix, gix, EdgeKind::WriteGpoFiles, origin) {
                stats.gpo_edges += 1;
            }
            g.add_file_grants(pix, gix, EdgeKind::WriteGpoFiles, gs);
        }
    }

    for script in &s.logon_scripts {
        let parsed = match sd::from_hex(&script.sd).and_then(|b| sd::parse(&b)) {
            Ok(p) => p,
            Err(e) => {
                note(&mut notes, format!("logon script {}: {e}", script.script));
                continue;
            }
        };
        let writers: Vec<sd::Writer> = sd::writers(&parsed, sd::Target::File)
            .into_iter()
            .filter(|w| !is_default_writer(&w.sid, false))
            .collect();
        if writers.is_empty() {
            continue;
        }
        let path = script_path(&domain, &script.script);
        let mut principals = Vec::new();
        for w in &writers {
            if let Some(pix) = principal(g, &w.sid, &mut stats.unresolved) {
                principals.push((pix, w));
            }
        }
        for user in &script.users {
            let Some(uix) = g
                .lookup(user)
                .filter(|&ix| g.node(ix).kind == NodeKind::User)
            else {
                stats.unresolved += 1;
                continue;
            };
            for (pix, w) in &principals {
                let origin = EdgeOrigin {
                    source: script_source,
                    unit: None,
                };
                if g.add_og_edge(*pix, uix, EdgeKind::WriteLogonScript, origin) {
                    stats.script_edges += 1;
                    g.add_file_grants(
                        *pix,
                        uix,
                        EdgeKind::WriteLogonScript,
                        vec![FileGrant {
                            path: path.clone(),
                            rights: w.rights.iter().map(|r| r.to_string()).collect(),
                            owner: w.owner,
                            inherited: w.inherited,
                        }],
                    );
                }
            }
        }
    }

    // Which GPO and setting gives each local right: the fix names it, at
    // the OUs and domains it is linked to, instead of every linked GPO.
    // Keyed by GPO, so it stays as small as the settings themselves.
    let gpo_node =
        |g: &AdGraph, id: &str| g.lookup(id).filter(|&ix| g.node(ix).kind == NodeKind::Gpo);
    for id in &s.gpo_local_incomplete {
        if let Some(gix) = gpo_node(g, id) {
            g.mark_gpo_record_incomplete(gix);
        }
    }
    for e in &s.gpo_local_groups {
        let Some(kind) = e.group.edge() else {
            continue;
        };
        let Some(gix) = e.object_id.as_deref().and_then(|id| gpo_node(g, id)) else {
            stats.unresolved += 1;
            note(
                &mut notes,
                format!(
                    "GPO local groups of {} have no GPO in the collection",
                    e.guid
                ),
            );
            continue;
        };
        let set = GpoSetting {
            setting: e.setting,
            targeted: e.item_level_targeting,
        };
        for m in &e.members {
            // A member the AD data lacks has no edge to name the GPO for.
            let Some(mix) = g.lookup(m) else {
                continue;
            };
            g.add_gpo_setting(gix, mix, kind, set);
        }
    }

    let gpp: Vec<GppHit> = s
        .gpp_passwords
        .iter()
        .map(|p| GppHit {
            gpo: p
                .object_id
                .as_deref()
                .and_then(|id| g.lookup(id))
                .filter(|&ix| g.node(ix).kind == NodeKind::Gpo),
            guid: p.guid.to_ascii_uppercase(),
            file: p.file.replace('/', "\\"),
            accounts: p.accounts.clone(),
            path: gpo_path(&domain, &p.guid, &p.file),
        })
        .collect();
    stats.gpp_files = gpp.len();
    let mut policy = Vec::new();
    for p in s.registry_policy {
        match p.object_id.as_deref().and_then(|id| gpo_node(g, id)) {
            Some(gix) => policy.push((gix, p.values)),
            None => {
                stats.unresolved += 1;
                note(
                    &mut notes,
                    format!("registry policy of {} has no GPO in the collection", p.guid),
                );
            }
        }
    }
    stats.policy_gpos = policy.len();
    stats.notes = notes;
    let failed: Vec<Option<NodeIndex>> = s
        .registry_pol_failed
        .iter()
        .map(|f| f.object_id.as_deref().and_then(|id| gpo_node(g, id)))
        .collect();
    g.add_sysvol_domain(SysvolDomain {
        domain,
        dc: s.dc,
        checks: s.checks,
        gpp,
        policy,
        sccm: s.sccm.unwrap_or_default(),
        disabled_links: s.disabled_gp_links.map(|list| {
            list.into_iter()
                .map(|l| {
                    (
                        l.container.trim().to_ascii_uppercase(),
                        l.gpo.trim().trim_matches(['{', '}']).to_ascii_uppercase(),
                    )
                })
                .collect()
        }),
        quota_read: s.machine_quota_computers.is_some(),
        quota_computers: s
            .machine_quota_computers
            .unwrap_or_default()
            .into_iter()
            .map(|sid| sid.to_ascii_uppercase())
            .collect(),
    });
    // A Registry.pol that couldn't be read holds the part only when its GPO
    // applies to a Tier Zero host: a broken file elsewhere says nothing
    // about their WSUS server.
    if let Some(check) = relevant_registry_pol(g, &failed) {
        stats.checks.registry_pol = Some(check.clone());
        if let Some(d) = g.sysvol_domains_mut().last_mut() {
            d.checks.registry_pol = Some(check);
        }
    }
    stats
}

/// The registry policy part's status once the GPOs whose `Registry.pol`
/// failed are known: complete when every failure was read as such (none
/// of the GPOs simply not reached, no timeout) and none of those GPOs
/// applies to a domain controller or CA host. `None` when unchanged.
fn relevant_registry_pol(g: &AdGraph, failed: &[Option<NodeIndex>]) -> Option<Check> {
    let check = g.sysvol_domains().last()?.checks.registry_pol.clone()?;
    if check.status != CheckStatus::Partial
        || check.reason.as_deref() == Some(POLICY_DROPPED)
        || failed.is_empty()
        || check.failed != failed.len()
        || failed.iter().any(Option::is_none)
    {
        return None;
    }
    let links = policy::LinkStatus::new(g);
    let applying = policy::applying(g, &links, crate::mgmt::tier_zero_hosts(g));
    if failed.iter().flatten().any(|gpo| applying.contains(gpo)) {
        return None;
    }
    Some(Check {
        status: CheckStatus::Complete,
        reason: Some(format!(
            "{} could not be read; none applies to a domain controller or CA host",
            crate::text::count(failed.len(), "GPO's Registry.pol", "GPOs' Registry.pol")
        )),
        ..check
    })
}

/// The SYSVOL parts of a run, per domain, for collection completeness.
#[derive(Debug, Clone, Serialize)]
pub struct Completeness {
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dc: Option<String>,
    pub checks: Checks,
    /// Enabled users with a logon script, in the AD data.
    pub users_with_logon_scripts: usize,
}

pub fn completeness(g: &AdGraph) -> Vec<Completeness> {
    let mut scripts: BTreeMap<String, usize> = BTreeMap::new();
    if !g.sysvol_domains().is_empty() {
        for (_, n) in g.nodes() {
            if n.kind == NodeKind::User && n.is_enabled() && n.props.logonscript.is_some() {
                *scripts
                    .entry(n.domain.clone().unwrap_or_default())
                    .or_default() += 1;
            }
        }
    }
    g.sysvol_domains()
        .iter()
        .map(|d| Completeness {
            domain: d.domain.clone(),
            dc: d.dc.clone(),
            checks: d.checks.clone(),
            users_with_logon_scripts: scripts.get(&d.domain).copied().unwrap_or(0),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths() {
        assert!(is_sidecar_name("a.zip!pathwarden-sysvol.json"));
        assert!(is_sidecar_name(
            r"C:\x\20261010_CONTOSO_pathwarden-sysvol.json"
        ));
        assert!(!is_sidecar_name("users.json"));
        assert!(is_gpo_guid("{31B2F340-016D-11D2-945F-00C04FB984F9}"));
        assert!(!is_gpo_guid("31B2F340-016D-11D2-945F-00C04FB984F9"));
        assert!(!is_gpo_guid("{31B2F340-016D-11D2-945F-00C04FB984FZ}"));
        assert!(is_safe_relative("logon.bat"));
        assert!(is_safe_relative(r"dept\it\logon.cmd"));
        for bad in [
            "",
            r"\\evil\share\x.bat",
            "/x",
            r"..\x",
            r"a\..\b",
            "c:x",
            "a\\\\b",
            "a|b",
        ] {
            assert!(!is_safe_relative(bad), "{bad}");
        }
        assert_eq!(
            gpo_path("contoso.local", "{ab}", "Machine"),
            r"\\contoso.local\SYSVOL\contoso.local\Policies\{AB}\Machine"
        );
        assert_eq!(
            script_path("CONTOSO.LOCAL", "it/logon.bat"),
            r"\\contoso.local\NETLOGON\it\logon.bat"
        );
    }

    #[test]
    fn default_writers() {
        for s in [
            "S-1-5-18",
            "S-1-3-0",
            "S-1-5-32-544",
            "S-1-5-9",
            "S-1-5-21-1-2-3-512",
            "S-1-5-21-1-2-3-519",
            "CONTOSO.LOCAL-S-1-5-32-544",
        ] {
            assert!(is_default_writer(s, true), "{s}");
            assert!(is_default_writer(s, false), "{s}");
        }
        // Group Policy Creator Owners: only on GPO folders.
        assert!(is_default_writer("S-1-5-21-1-2-3-520", true));
        assert!(!is_default_writer("S-1-5-21-1-2-3-520", false));
        for s in [
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
            "S-1-5-32-549",
            "S-1-5-21-1-2-3-513",
            "S-1-5-21-1-2-3-1105",
        ] {
            assert!(!is_default_writer(s, true), "{s}");
        }
        assert_eq!(
            principal_id("S-1-5-11", "contoso.local"),
            Some(("CONTOSO.LOCAL-S-1-5-11".into(), NodeKind::Group))
        );
        assert_eq!(principal_id("S-1-5-80-1-2-3-4-5", "contoso.local"), None);
    }

    #[test]
    fn parse_checks_and_drops_bad_entries() {
        let mut notes = Vec::new();
        let text = format!(
            r#"{{"schema":"{SCHEMA}","domain":"contoso.local",
            "checks":{{"gpo_acl":{{"status":"complete","read":2}}}},
            "gpos":[{{"guid":"{{31B2F340-016D-11D2-945F-00C04FB984F9}}","folders":[{{"path":"","sd":"01"}},{{"path":"..\\x","sd":"01"}}]}},
                    {{"guid":"nope","folders":[]}}],
            "logon_scripts":[{{"script":"\\\\evil\\x.bat","users":[],"sd":""}}],
            "gpp_passwords":[{{"guid":"{{31B2F340-016D-11D2-945F-00C04FB984F9}}","file":"Machine\\Preferences\\Groups\\Groups.xml","accounts":["svc"]}}]}}"#
        );
        let s = Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
        assert_eq!(s.checks.gpo_acl.status, CheckStatus::Complete);
        assert_eq!(s.checks.gpp.status, CheckStatus::NotCollected);
        assert_eq!(s.gpos.len(), 1);
        assert_eq!(s.gpos[0].folders.len(), 1);
        assert!(s.logon_scripts.is_empty());
        assert_eq!(s.gpp_passwords.len(), 1);
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(Sidecar::parse(br#"{"schema":"x","domain":"a"}"#, &mut notes).is_err());
        assert!(Sidecar::parse(b"[]", &mut notes).is_err());
    }

    const ID: &str = "AAAA0000-0000-0000-0000-000000000001";

    fn local_entry(
        guid: &str,
        setting: &str,
        group: &str,
        members: &[String],
    ) -> serde_json::Value {
        serde_json::json!({ "guid": guid, "object_id": ID,
                            "setting": setting, "group": group, "members": members })
    }

    fn with_local(entries: Vec<serde_json::Value>) -> (Sidecar, Vec<String>) {
        let text = serde_json::json!({ "schema": SCHEMA, "domain": "example.test",
                                       "gpo_local_groups": entries });
        let mut notes = Vec::new();
        let s = Sidecar::parse(text.to_string().as_bytes(), &mut notes).unwrap();
        (s, notes)
    }

    #[test]
    fn gpo_local_groups_are_checked_and_capped() {
        const G: &str = "{AAAA0000-0000-0000-0000-000000000001}";
        let alice = "S-1-5-21-10-20-30-1101".to_string();
        let ops = "EXAMPLE.TEST-S-1-5-32-555".to_string();
        let (s, notes) = with_local(vec![
            local_entry(
                G,
                "restricted_groups",
                "administrators",
                &[alice.clone(), ops.clone()],
            ),
            local_entry(
                G,
                "gpp",
                "ps_remote",
                &[alice.clone(), "alice".into(), "S-1-x".into()],
            ),
            local_entry("nope", "gpp", "dcom", std::slice::from_ref(&alice)),
            // A later version's setting or group: dropped, the file kept.
            local_entry(
                G,
                "startup_script",
                "administrators",
                std::slice::from_ref(&alice),
            ),
            local_entry(G, "gpp", "backup_operators", std::slice::from_ref(&alice)),
            local_entry(G, "gpp", "dcom", &["bad".into()]),
        ]);
        let got: Vec<_> = s
            .gpo_local_groups
            .iter()
            .map(|e| (e.setting, e.group, e.members.clone()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    LocalSetting::RestrictedGroups,
                    LocalGroup::Administrators,
                    vec![alice.clone(), ops]
                ),
                (LocalSetting::Gpp, LocalGroup::PsRemote, vec![alice.clone()]),
            ]
        );
        assert_eq!(notes.len(), 5, "{notes:?}");

        let many: Vec<String> = (0..MAX_LOCAL_MEMBERS + 3)
            .map(|i| format!("S-1-5-21-10-20-30-{i}"))
            .collect();
        // Every entry here is of one GPO, now incomplete.
        assert_eq!(s.gpo_local_incomplete, [ID]);

        let (s, notes) = with_local(vec![local_entry(G, "gpp", "dcom", &many)]);
        assert_eq!(s.gpo_local_groups[0].members.len(), MAX_LOCAL_MEMBERS);
        assert!(s.gpo_local_groups[0].members_truncated);
        assert_eq!(s.gpo_local_incomplete, [ID]);
        assert_eq!(notes.len(), 1, "{notes:?}");

        // Cut by the collector.
        let mut cut = local_entry(G, "gpp", "dcom", std::slice::from_ref(&alice));
        cut["members_truncated"] = true.into();
        let (s, notes) = with_local(vec![cut]);
        assert_eq!(s.gpo_local_incomplete, [ID]);
        assert!(notes.is_empty(), "{notes:?}");

        let entries = vec![local_entry(G, "gpp", "dcom", &[alice]); MAX_LOCAL_ENTRIES + 1];
        let (s, notes) = with_local(entries);
        assert!(s.gpo_local_groups.is_empty());
        assert_eq!(notes.len(), 1, "{notes:?}");

        // An older sidecar has no list.
        let (s, notes) = with_local(Vec::new());
        assert!(s.gpo_local_groups.is_empty() && notes.is_empty());
    }

    #[test]
    fn registry_policy_and_sccm_entries_are_checked() {
        const G: &str = "{AAAA0000-0000-0000-0000-000000000001}";
        let wu = regpol::WINDOWS_UPDATE;
        let text = serde_json::json!({
            "schema": SCHEMA, "domain": "example.test",
            "checks": { "registry_pol": { "status": "complete", "read": 4 },
                        "sccm_sites": { "status": "complete", "read": 2 } },
            "registry_policy": [
                { "guid": G, "object_id": "AAAA0000-0000-0000-0000-000000000001",
                  "values": [ { "key": wu, "name": "WUSERVER", "text": "http://w" },
                              { "key": r"SOFTWARE\OTHER", "name": "X", "number": 1 },
                              { "key": wu, "name": "WUSERVER", "text": "a", "number": 1 } ] },
                { "guid": "nope", "values": [] },
                "not an object",
            ],
            "sccm": { "sites": [ { "site_code": "p01" }, { "site_code": "TOOLONG" } ],
                      "management_points": [ { "site_code": "P01", "host": "mp01.example.test" } ] },
        });
        let mut notes = Vec::new();
        let s = Sidecar::parse(text.to_string().as_bytes(), &mut notes).unwrap();
        assert_eq!(s.registry_policy.len(), 1);
        assert_eq!(s.registry_policy[0].values.len(), 1);
        let pol = s.checks.registry_pol.as_ref().unwrap();
        assert_eq!(pol.status, CheckStatus::Partial);
        let sccm = s.sccm.as_ref().unwrap();
        assert_eq!(sccm.sites.len(), 1);
        assert_eq!(sccm.sites[0].site_code, "P01");
        assert_eq!(notes.len(), 2, "{notes:?}");
        // Older sidecars: neither part, so both not collected.
        let old = Sidecar::parse(
            br#"{"schema":"pathwarden.sysvol.v1","domain":"example.test"}"#,
            &mut Vec::new(),
        )
        .unwrap();
        for part in [Part::RegistryPol, Part::SccmSites] {
            assert_eq!(part.of(&old.checks).status, CheckStatus::NotCollected);
        }
        assert_eq!(
            Part::RegistryPol.source("example.test"),
            "SYSVOL registry policy (EXAMPLE.TEST)"
        );
    }

    #[test]
    fn a_wrong_typed_gpo_local_group_entry_loses_only_the_names() {
        const G: &str = "{AAAA0000-0000-0000-0000-000000000001}";
        let alice = "S-1-5-21-10-20-30-1101".to_string();
        let good = local_entry(G, "gpp", "dcom", std::slice::from_ref(&alice));
        let parse = |local: serde_json::Value| {
            let text = serde_json::json!({
                "schema": SCHEMA, "domain": "example.test",
                "checks": { "gpo_acl": { "status": "complete", "read": 1 } },
                "gpos": [{ "guid": G, "folders": [{ "path": "", "sd": "01" }] }],
                "gpp_passwords": [{ "guid": G, "file": r"Machine\Preferences\Groups\Groups.xml",
                                    "accounts": ["svc"] }],
                "gpo_local_groups": local,
            });
            let mut notes = Vec::new();
            let s = Sidecar::parse(text.to_string().as_bytes(), &mut notes).unwrap();
            assert_eq!(s.gpos.len(), 1);
            assert_eq!(s.gpp_passwords[0].accounts, ["svc"]);
            assert_eq!(s.checks.gpo_acl.status, CheckStatus::Complete);
            (s, notes)
        };
        // Members not a list: that GPO names nobody, the rest is kept.
        let other = serde_json::json!({ "guid": "{BBBB0000-0000-0000-0000-000000000001}",
            "object_id": "BBBB0000-0000-0000-0000-000000000001", "setting": "gpp",
            "group": "dcom", "members": 7 });
        let (s, notes) = parse(serde_json::json!([good.clone(), other]));
        assert_eq!(s.gpo_local_groups.len(), 1);
        assert_eq!(
            s.gpo_local_incomplete,
            ["BBBB0000-0000-0000-0000-000000000001"]
        );
        assert_eq!(notes.len(), 1, "{notes:?}");
        // An entry that is not an object, or a list that is not a list: it
        // can't be told whose it was, so no GPO is named at all.
        for local in [
            serde_json::json!([good.clone(), "x"]),
            serde_json::json!({ "a": 1 }),
            serde_json::json!("x"),
        ] {
            let (s, notes) = parse(local.clone());
            assert!(s.gpo_local_groups.is_empty(), "{local}");
            assert_eq!(notes.len(), 1, "{local}: {notes:?}");
        }
        // null is as absent.
        let (s, notes) = parse(serde_json::Value::Null);
        assert!(s.gpo_local_groups.is_empty() && notes.is_empty());
    }
}
