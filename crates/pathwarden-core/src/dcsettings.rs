//! Domain controller registry settings read on the DC itself.
//!
//! ESC9 and ESC10 depend on two registry values on every domain controller:
//! `Services\Kdc\StrongCertificateBindingEnforcement` and
//! `SecurityProviders\Schannel\CertificateMappingMethods`. Reading them
//! remotely needs admin rights on the DCs, which a collection account should
//! not have. Instead the DCs' own admins run
//! `scripts/collector/Get-PathwardenTierZeroSettings.ps1`, which reads them
//! locally and writes `pathwarden-tierzero-<host>.<domain>.json` (schema
//! `pathwarden.tierzero.v1`). Put the files beside the collection (or in its
//! zip) and they are read with it.
//!
//! Each file is matched to a domain controller in the AD data, by SID, then
//! by DNS name, then by host name and domain. Its values fill the DC's
//! [`DcSetting`]s, which the AD CS checks read exactly as they read
//! SharpHound's `DCRegistryData`.
//!
//! **Which value wins.** A value the file read replaces the collection's,
//! unless the collection read that value itself and is newer than the file
//! (by the collection time in the collector's file names), or the file has
//! no read time. When only the collection time is unknown, the file wins: it
//! was read on the DC by its admin. A value the file could not read leaves
//! the collection's. Of two files for one DC, the newer one wins.
//!
//! **Stale files.** A file read more than [`STALE_DAYS`] days before the
//! collection (before now when that is unknown), or with no read time (a
//! read time more than a day in the future counts as none), can
//! still show a weakness (weak binding, the UPN mapping bit) but never clear
//! one: its values that would close ESC9/ESC10 are not used.
//!
//! **Unset values.** What an unset value means depends on the DC's patch
//! level, which the file's `os_build` gives (see [`kdc_weak_mapping`] and
//! [`schannel_upn_mapping`]). A stale file's build can open a finding but
//! not close one.

use std::collections::BTreeMap;

use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

use crate::graph::AdGraph;
use crate::model::{DcSetting, NodeKind};

/// The first schema: DC and CA registry values only.
pub const SCHEMA: &str = "pathwarden.tierzero.v1";
/// The current schema: v1 plus the management agents on the
/// host ([`crate::hostprobe::Agents`]). Both are read.
pub const SCHEMA_V2: &str = "pathwarden.tierzero.v2";
/// The file name prefix the script writes (`pathwarden-tierzero-<host>.<domain>.json`).
pub const FILE_PREFIX: &str = "pathwarden-tierzero";
/// Largest file read. Real ones are about 2 KiB.
pub const MAX_SIDECAR_BYTES: u64 = 1 << 20;
/// A file read longer ago than this before the analysis is stale.
pub const STALE_DAYS: i64 = 90;
/// The value names the AD CS checks use.
pub const STRONG_BINDING: &str = "StrongCertificateBindingEnforcement";
pub const MAPPING_METHODS: &str = "CertificateMappingMethods";

/// A Windows build and update revision: `14393.1944` is build 14393, UBR 1944.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OsBuild {
    pub major: u32,
    pub ubr: u32,
}

impl OsBuild {
    /// `14393.1944`, or `10.0.14393.1944`. A build without its update
    /// revision says nothing about the patch level: `None`.
    pub fn parse(s: &str) -> Option<OsBuild> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        let (major, ubr) = match parts.as_slice() {
            [major, ubr] | [_, _, major, ubr] => (major, ubr),
            _ => return None,
        };
        Some(OsBuild {
            major: major.parse().ok()?,
            ubr: ubr.parse().ok()?,
        })
    }
}

/// A domain controller's OS build, as its newest settings file read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcOsBuild {
    pub build: OsBuild,
    /// From a stale or undated file: it may open a finding, never close one.
    pub stale: bool,
}

/// The first update revision of each Windows Server build that carries a
/// certificate mapping change (KB5014754), per the update titles on
/// support.microsoft.com (`<date>—KB<n> (OS Build <build>.<ubr>)`):
///
/// | Server | Build | May 10, 2022          | Feb 11, 2025          | Sep 9, 2025           |
/// |--------|-------|-----------------------|-----------------------|-----------------------|
/// | 2016   | 14393 | KB5013952 → .5125     | KB5052006 → .7785     | KB5065427 → .8422     |
/// | 2019   | 17763 | KB5013941 → .2928     | KB5052000 → .6893     | KB5065428 → .7792     |
/// | 2022   | 20348 | KB5013944 → .707      | KB5051979 → .3207     | KB5065432 → .4171     |
/// | 2025   | 26100 | (released 2024: all)  | KB5051987 → .3194     | KB5065426 → .6584     |
///
/// What each one changes, per KB5014754
/// (<https://support.microsoft.com/topic/ad2c23b0-15d8-4340-a468-4d4f3b188f16>):
/// - May 2022: the KDC starts checking certificate mappings (compatibility
///   mode). The Schannel CertificateMappingMethods default "was 0x1F and is
///   now 0x18": before it, an unset value includes UPN mapping (0x4).
/// - February 2025: an unset StrongCertificateBindingEnforcement means Full
///   Enforcement.
/// - September 2025: "The option to move back to Compatibility mode will
///   remain until the September 9, 2025 Windows security update is
///   installed"; after it the value "will no longer be supported", so 0 and
///   1 no longer allow weak mappings.
///
/// KB pages: `https://support.microsoft.com/help/<number>`. Other builds (2012 R2,
/// semi-annual channel releases) are not listed: their unset values stay
/// unknown.
///
/// Server 2025: KB5014754's "Applies to" stops at Server 2022, so reading its
/// builds before .3194 as compatibility mode is derived from the timeline, not
/// stated. Hotpatch builds (KB5052105 is 26100.3107, released the same month as
/// .3194) carry a lower revision than that month's cumulative update: they read
/// as older, which can open a finding that is closed (never the reverse).
const UPDATES: &[CertMappingUpdates] = &[
    CertMappingUpdates {
        major: 14393,
        may_2022: 5125,
        feb_2025: 7785,
        sep_2025: 8422,
    },
    CertMappingUpdates {
        major: 17763,
        may_2022: 2928,
        feb_2025: 6893,
        sep_2025: 7792,
    },
    CertMappingUpdates {
        major: 20348,
        may_2022: 707,
        feb_2025: 3207,
        sep_2025: 4171,
    },
    // Windows Server 2025 shipped in November 2024, after the May 2022
    // change: every build has it.
    CertMappingUpdates {
        major: 26100,
        may_2022: 0,
        feb_2025: 3194,
        sep_2025: 6584,
    },
];

/// First update revision (UBR) of one build with each change.
struct CertMappingUpdates {
    major: u32,
    may_2022: u32,
    feb_2025: u32,
    sep_2025: u32,
}

fn updates(build: OsBuild) -> Option<&'static CertMappingUpdates> {
    UPDATES.iter().find(|u| u.major == build.major)
}

/// A certificate mapping update a DC's build predates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CertUpdate {
    May2022,
    Feb2025,
}

impl CertUpdate {
    pub fn label(self) -> &'static str {
        match self {
            CertUpdate::May2022 => "May 2022",
            CertUpdate::Feb2025 => "February 2025",
        }
    }
}

/// Why a domain controller accepts weak certificate mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weakness {
    /// Its registry value is weak (binding 0 or 1, mapping with 0x4).
    Value,
    /// Its build predates `update`: the value is not set and defaults to weak,
    /// or (Kerberos before May 2022) the KDC ignores it.
    Build { build: OsBuild, update: CertUpdate },
}

/// What a domain controller does with weak certificate mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Weak(Weakness),
    Strong,
    Unknown,
}

/// The two places a DC maps certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mapping {
    /// Kdc StrongCertificateBindingEnforcement (ESC6a, ESC9).
    Kerberos,
    /// Schannel CertificateMappingMethods, UPN bit 0x4 (ESC6b, ESC10).
    Schannel,
}

/// Whether the KDC accepts weak (implicit) certificate mappings. `build` is
/// the DC's, when known.
pub fn kdc_weak_mapping(setting: DcSetting, build: Option<OsBuild>) -> Verdict {
    let u = build.and_then(|b| updates(b).map(|u| (b, u)));
    let by_build = |build, update| Verdict::Weak(Weakness::Build { build, update });
    match (setting, u) {
        (DcSetting::Unknown, _) => Verdict::Unknown,
        // Before May 2022 the KDC checks no mapping, whatever the value.
        (_, Some((b, u))) if b.ubr < u.may_2022 => by_build(b, CertUpdate::May2022),
        // From September 2025 compatibility mode is gone.
        (_, Some((b, u))) if b.ubr >= u.sep_2025 => Verdict::Strong,
        (DcSetting::Value(0 | 1), _) => Verdict::Weak(Weakness::Value),
        (DcSetting::Value(_), _) => Verdict::Strong,
        // Unset: compatibility mode until February 2025, then full enforcement.
        (DcSetting::NotSet, Some((b, u))) if b.ubr < u.feb_2025 => by_build(b, CertUpdate::Feb2025),
        (DcSetting::NotSet, Some(_)) => Verdict::Strong,
        (DcSetting::NotSet, None) => Verdict::Unknown,
    }
}

/// Whether Schannel maps certificates by UPN (CertificateMappingMethods bit
/// 0x4).
pub fn schannel_upn_mapping(setting: DcSetting, build: Option<OsBuild>) -> Verdict {
    match setting {
        DcSetting::Unknown => Verdict::Unknown,
        DcSetting::Value(v) if v & 0x4 != 0 => Verdict::Weak(Weakness::Value),
        // The S4U2Self bits (0x8, 0x10) hand the mapping to the KDC. Before
        // the May 2022 update (KB5014754) the KDC maps implicitly by UPN /
        // sAMAccountName and checks nothing ([`kdc_weak_mapping`] says so for
        // the same DC), so on such a build an explicit 0x18 is as weak as the
        // KDC: weak because of the build, fixed by the updates. A
        // build without a known update timeline is taken at face value, as
        // the KDC check does.
        DcSetting::Value(v) if v & 0x18 != 0 => {
            match build.and_then(|b| updates(b).map(|u| (b, u))) {
                Some((b, u)) if b.ubr < u.may_2022 => Verdict::Weak(Weakness::Build {
                    build: b,
                    update: CertUpdate::May2022,
                }),
                _ => Verdict::Strong,
            }
        }
        // Neither UPN nor S4U2Self: subject/issuer mapping only.
        DcSetting::Value(_) => Verdict::Strong,
        // Unset: 0x1F before May 2022, 0x18 after.
        DcSetting::NotSet => match build.and_then(|b| updates(b).map(|u| (b, u))) {
            Some((b, u)) if b.ubr < u.may_2022 => Verdict::Weak(Weakness::Build {
                build: b,
                update: CertUpdate::May2022,
            }),
            Some(_) => Verdict::Strong,
            None => Verdict::Unknown,
        },
    }
}

/// `check` with a DC's build. A stale build may open, never close: when it
/// would close, the answer is what the value alone says.
pub fn with_build(build: Option<DcOsBuild>, check: impl Fn(Option<OsBuild>) -> Verdict) -> Verdict {
    let answer = check(build.map(|b| b.build));
    match build {
        Some(b) if b.stale && answer == Verdict::Strong => check(None),
        _ => answer,
    }
}

/// What a domain controller's settings and build say about one mapping.
pub fn verdict(p: &crate::model::Props, mapping: Mapping) -> Verdict {
    with_build(p.os_build, |b| match mapping {
        Mapping::Kerberos => kdc_weak_mapping(p.strongcertificatebindingenforcement, b),
        Mapping::Schannel => schannel_upn_mapping(p.certificatemappingmethods, b),
    })
}

const MAX_VALUES: usize = 64;
const MAX_TEXT: usize = 1024;
const MAX_NOTES: usize = 20;

/// Whether a file name is a Tier Zero settings file's:
/// `pathwarden-tierzero*.json` or `*-tierzero.json`. The script writes
/// `pathwarden-tierzero-<host>.<domain>.json`; older files have no domain.
pub fn is_sidecar_name(label: &str) -> bool {
    let name = label
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(label)
        .to_ascii_lowercase();
    // `*.coverage.json` is an OpenGraph coverage file, whatever its prefix.
    name.ends_with(".json")
        && !name.ends_with(".coverage.json")
        && (name.starts_with(FILE_PREFIX) || name.ends_with("-tierzero.json"))
}

/// Whether a file name in a Tier Zero settings folder is one to read: what
/// the script writes, `pathwarden-tierzero-<host>[.<domain>].json`, in
/// letters, digits, dots, hyphens and underscores only. Stricter than
/// [`is_sidecar_name`] (which also takes `*-tierzero.json` inside a
/// collection): a shared folder holds files anyone with write access put
/// there.
pub fn is_folder_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(host) = lower
        .strip_prefix("pathwarden-tierzero-")
        .and_then(|r| r.strip_suffix(".json"))
    else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && host.as_bytes()[0].is_ascii_alphanumeric()
        && !host.contains("..")
        && !lower.ends_with(".coverage.json")
}

/// The domain controller the file was read on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DcInfo {
    /// NetBIOS host name (`DC01`).
    #[serde(default)]
    pub hostname: String,
    /// `dc01.north.contoso.local`.
    #[serde(default)]
    pub dns_name: Option<String>,
    /// The computer account's SID.
    #[serde(default)]
    pub object_sid: Option<String>,
    #[serde(default)]
    pub distinguished_name: Option<String>,
    /// `17763.5458`: defaults of unset values depend on the patch level.
    #[serde(default)]
    pub os_build: Option<String>,
}

/// One registry value as the script read it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueRead {
    pub name: String,
    /// The registry key, `HKLM\...`.
    #[serde(default)]
    pub path: String,
    /// The value exists.
    #[serde(default)]
    pub present: bool,
    /// The value's data when it is a number.
    #[serde(default)]
    pub value: Option<i64>,
    /// Why it could not be read.
    #[serde(default)]
    pub error: Option<String>,
}

impl ValueRead {
    /// What the value says, or `None` when it was not read.
    pub fn setting(&self) -> Option<DcSetting> {
        if self.error.is_some() {
            return None;
        }
        match (self.present, self.value) {
            (false, _) => Some(DcSetting::NotSet),
            (true, Some(v)) if v >= 0 => Some(DcSetting::Value(v)),
            // Present but not a number: not something the checks can use.
            (true, _) => None,
        }
    }
}

/// The file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema: String,
    /// DNS name of the domain. Missing fields are checked after the schema,
    /// so another file says what it is.
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub dc: DcInfo,
    /// When the values were read, UTC (`2026-10-13T08:30:00Z`).
    #[serde(default)]
    pub read_at: Option<String>,
    #[serde(default)]
    pub values: Vec<ValueRead>,
    /// The certification authorities on this host: absent in files
    /// from older scripts and on hosts without AD CS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cas: Vec<CaRead>,
    /// The management agents on the host (schema v2): `None` in v1
    /// files, which never read them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<crate::hostprobe::Agents>,
    /// Where it was read from: never from the file itself.
    #[serde(skip)]
    pub origin: Origin,
}

/// Where a settings file was read from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Origin {
    /// Given with the collection (in its folder or zip, or as an input):
    /// whoever ran the analysis chose it.
    #[default]
    Collection,
    /// From a settings folder, which anyone who can write there can fill.
    /// `security` is the file's owner and who may change it (Windows;
    /// `None` elsewhere or when it can't be read); `share_host` the host of
    /// the share it was read from (`\\HOST\...`), upper case.
    Folder {
        security: Option<crate::perms::FileSecurity>,
        share_host: Option<String>,
    },
}

/// SYSTEM and BUILTIN\Administrators: local to the file server.
const LOCAL_SYSTEM: &str = "S-1-5-18";
const LOCAL_ADMINS: &str = "S-1-5-32-544";

/// Whether a file's values may clear what is known: replace or weaken a
/// value, fill one toward strong, or let a recent OS build count an unset
/// value as strong. A collection's file may. A settings folder's file only
/// when it proves who wrote it and that nobody else can change it:
/// - its owner is the server it describes (`server`, as a SYSTEM task on
///   it writes the file) or a Tier Zero principal of that server's forest
///   (`forest`, its domain); a bare SYSTEM or BUILTIN\Administrators owner
///   only when the share is on that server itself;
/// - and every SID allowed to write, append, change permissions or owner,
///   or delete it is the owner, the file server's SYSTEM or
///   Administrators, or such a principal. An unknown one makes it
///   untrusted.
///
/// Anyone else's file can only confirm weaknesses.
pub(crate) fn authoritative(g: &AdGraph, s: &Sidecar, server: &[NodeIndex]) -> bool {
    let (sec, share_host) = match &s.origin {
        Origin::Collection => return true,
        Origin::Folder { security: None, .. } => return false,
        Origin::Folder {
            security: Some(sec),
            share_host,
        } => (sec, share_host),
    };
    let Some(&srv) = server.first() else {
        return false;
    };
    let forest = g.node(srv).domain.clone().unwrap_or_default();
    let srv_name = g.node(srv).name.to_ascii_uppercase();
    let srv_host = srv_name.split('.').next().unwrap_or_default().to_string();
    let on_server = share_host.as_deref().is_some_and(|h| {
        let h = h.to_ascii_uppercase();
        h == srv_name || h == srv_host
    });
    let principal = |sid: &str| -> bool {
        g.lookup(sid)
            .is_some_and(|ix| server.contains(&ix) || is_tier_zero_principal(g, ix, &forest))
    };
    let owner_ok = match sec.owner.as_str() {
        LOCAL_SYSTEM | LOCAL_ADMINS => on_server,
        o => principal(o),
    };
    // The file server's own SYSTEM and Administrators can change the file:
    // fine only when that server is itself Tier Zero (the server the file
    // describes, or a domain controller of its forest). On a member server
    // its local admins could have written it.
    let local_ok = on_server
        || share_host
            .as_deref()
            .is_some_and(|h| tier_zero_host(g, h, &forest));
    let writer_ok = |w: &String| {
        if w == LOCAL_SYSTEM || w == LOCAL_ADMINS {
            local_ok
        } else {
            w == &sec.owner || principal(w)
        }
    };
    owner_ok && sec.writers.iter().all(writer_ok)
}

/// Whether `host` (a share's host: a NetBIOS or DNS name) is exactly one
/// computer that is Tier Zero of `forest` ([`is_tier_zero_principal`]).
fn tier_zero_host(g: &AdGraph, host: &str, forest: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_uppercase();
    let found: Vec<NodeIndex> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::Computer && !n.placeholder)
        .filter(|(_, n)| {
            let name = n.name.to_ascii_uppercase();
            if h.contains('.') {
                name == h
            } else {
                name.split('.').next() == Some(h.as_str())
                    && n.domain.as_deref().is_some_and(|d| same_forest(d, forest))
            }
        })
        .map(|(ix, _)| ix)
        .collect();
    matches!(found.as_slice(), [one] if is_tier_zero_principal(g, *one, forest))
}

/// Whether domains `a` and `b` (DNS names) are in one forest, as far as
/// their names tell: the same, or one a child of the other.
fn same_forest(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_uppercase(), b.to_ascii_uppercase());
    !a.is_empty()
        && !b.is_empty()
        && (a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")))
}

/// Whether `ix` is Tier Zero of `forest` (a domain of it) by what the
/// collection shows before Tier Zero is marked (settings files are applied
/// first): a domain controller, a built-in Tier Zero SID (Domain Admins,
/// Enterprise Admins, ...), or a member of one, however deeply nested, all
/// in that forest. Broad groups never count.
fn is_tier_zero_principal(g: &AdGraph, ix: NodeIndex, forest: &str) -> bool {
    use petgraph::visit::EdgeRef;
    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![ix];
    while let Some(v) = queue.pop() {
        if !seen.insert(v) || seen.len() > 10_000 {
            continue;
        }
        let n = g.node(v);
        if n.placeholder && v == ix {
            return false;
        }
        let in_forest = n.domain.as_deref().is_some_and(|d| same_forest(d, forest));
        if in_forest
            && ((n.kind == NodeKind::Computer && n.is_dc)
                || crate::sid::tier_zero_reason(&n.id).is_some())
        {
            return true;
        }
        for e in g.inner().edges_directed(v, petgraph::Direction::Outgoing) {
            if *e.weight() == crate::model::EdgeKind::MemberOf
                && !crate::sid::is_broad_group(&g.node(e.target()).id)
            {
                queue.push(e.target());
            }
        }
    }
    false
}

/// What a settings folder's file says of its host in its name
/// (`pathwarden-tierzero-<HOST>[.<domain>].json`) must be the host inside
/// it: a file named for one server and describing another is refused.
pub fn name_matches_host(file_name: &str, s: &Sidecar) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("pathwarden-tierzero-") else {
        return true;
    };
    let host = rest.split('.').next().unwrap_or(rest);
    host.eq_ignore_ascii_case(s.dc.hostname.trim())
}

/// One certification authority as the script read it on its host
/// (`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaRead {
    /// The CA's name, as `caname` in the collection.
    pub name: String,
    /// `CACertHash`: the thumbprints of the CA's certificates, which match
    /// it to its Enterprise CA object (`certthumbprint`).
    #[serde(default)]
    pub cert_hashes: Vec<String>,
    /// `EditFlags` ([`EDIT_FLAGS`]), `InterfaceFlags` ([`INTERFACE_FLAGS`])
    /// and `RoleSeparationEnabled` ([`ROLE_SEPARATION`]), in the DC values'
    /// shape.
    #[serde(default)]
    pub values: Vec<ValueRead>,
}

impl CaRead {
    /// The value named `name` (case-insensitive).
    pub fn value(&self, name: &str) -> Option<&ValueRead> {
        self.values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

/// The CA values the AD CS checks use, and the one recorded only.
pub const EDIT_FLAGS: &str = "EditFlags";
pub const INTERFACE_FLAGS: &str = "InterfaceFlags";
pub const ROLE_SEPARATION: &str = "RoleSeparationEnabled";
/// `EDITF_ATTRIBUTESUBJECTALTNAME2` in `EditFlags`: any requester may put
/// any name in the SAN (ESC6). The built-in collector's `careg.rs` and
/// RustHound-CE (`user_specifies_san_from_editflags`) test the same bit.
pub const SAN_FLAG: i64 = 0x0004_0000;
/// `IF_ENFORCEENCRYPTICERTREQUEST` in `InterfaceFlags`: without it the
/// CA's RPC interface takes NTLM-relayed requests (ESC11). Not set at all
/// means the default, which enforces it.
pub const ENCRYPT_FLAG: i64 = 0x0000_0200;
const MAX_CAS: usize = 16;
const MAX_HASHES: usize = 32;

/// Whether `h` is a certificate thumbprint: 40 (SHA-1) or 64 (SHA-256) hex
/// digits.
fn is_thumbprint(h: &str) -> bool {
    matches!(h.len(), 40 | 64) && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Text from a shared folder: within `max` bytes and without control
/// characters.
pub(crate) fn plain(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

impl Sidecar {
    /// Parses and checks a file. A file that is too large, of another
    /// schema, or not JSON is refused whole; malformed values are dropped
    /// and named in `notes`.
    pub fn parse(bytes: &[u8], notes: &mut Vec<String>) -> Result<Sidecar, String> {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        if bytes.len() as u64 > MAX_SIDECAR_BYTES {
            return Err("too large for a Tier Zero settings file".into());
        }
        let mut s: Sidecar = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if s.schema != SCHEMA && s.schema != SCHEMA_V2 {
            return Err(format!(
                "schema '{}' is not {SCHEMA} or {SCHEMA_V2}",
                s.schema
            ));
        }
        // A v1 file never read the agents: whatever it says of them is not
        // the script's.
        if s.schema == SCHEMA && s.agents.take().is_some() && notes.len() < MAX_NOTES {
            notes.push(format!(
                "a {SCHEMA} file has no management agents part: it was ignored"
            ));
        }
        if let Some(a) = &mut s.agents {
            a.check(notes);
        }
        if s.domain.trim().is_empty() || s.domain.len() > 255 {
            return Err("no domain".into());
        }
        let host = s.dc.hostname.trim();
        if host.is_empty() || host.len() > 255 {
            return Err("no domain controller host name".into());
        }
        if !plain(&s.domain, 255) || !plain(host, 255) {
            return Err("its domain or host name holds control characters".into());
        }
        if s.values.len() > MAX_VALUES {
            return Err("it lists too many values".into());
        }
        if s.cas.len() > MAX_CAS {
            return Err("it lists too many certification authorities".into());
        }
        if s.read_at.is_some() && s.read_time().is_none() {
            notes.push(format!(
                "read time '{}' is not a UTC time",
                s.read_at.as_deref().unwrap_or_default()
            ));
            s.read_at = None;
        }
        s.values.retain_mut(|v| {
            let ok = !v.name.is_empty() && v.name.len() <= 255 && v.path.len() <= MAX_TEXT;
            if !ok && notes.len() < MAX_NOTES {
                notes.push("a malformed value entry was skipped".into());
            }
            if let Some(e) = &mut v.error {
                if e.len() > MAX_TEXT {
                    *e = e.chars().take(MAX_TEXT / 4).collect();
                }
            }
            ok
        });
        s.cas.retain_mut(|ca| {
            ca.name = ca.name.trim().to_string();
            let ok = !ca.name.is_empty()
                && plain(&ca.name, 255)
                && ca.values.len() <= MAX_VALUES
                && ca.cert_hashes.len() <= MAX_HASHES;
            if !ok {
                if notes.len() < MAX_NOTES {
                    notes.push("a malformed certification authority entry was skipped".into());
                }
                return false;
            }
            let before = ca.cert_hashes.len();
            ca.cert_hashes.retain(|h| is_thumbprint(h.trim()));
            for h in &mut ca.cert_hashes {
                *h = h.trim().to_ascii_uppercase();
            }
            if ca.cert_hashes.len() < before && notes.len() < MAX_NOTES {
                notes.push(format!(
                    "{}: a certificate hash that is not a thumbprint was skipped",
                    ca.name
                ));
            }
            ca.values.retain_mut(|v| {
                if let Some(e) = &mut v.error {
                    if e.len() > MAX_TEXT {
                        *e = e.chars().take(MAX_TEXT / 4).collect();
                    }
                }
                !v.name.is_empty() && plain(&v.name, 255) && v.path.len() <= MAX_TEXT
            });
            true
        });
        Ok(s)
    }

    /// [`Self::read_at`] in Unix seconds.
    pub fn read_time(&self) -> Option<i64> {
        parse_utc(self.read_at.as_deref()?)
    }

    /// The value named `name` (case-insensitive).
    pub fn value(&self, name: &str) -> Option<&ValueRead> {
        self.values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
    }

    /// `HOST.DOMAIN`, upper case: how collectors name a DC.
    pub(crate) fn dns_name(&self) -> String {
        match &self.dc.dns_name {
            Some(d) if !d.trim().is_empty() => d.trim().to_ascii_uppercase(),
            _ => format!(
                "{}.{}",
                self.dc.hostname.trim().to_ascii_uppercase(),
                self.domain.trim().to_ascii_uppercase()
            ),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` (or `+00:00`) to Unix seconds.
pub fn parse_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let body = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;
    let (date, time) = body.split_once('T')?;
    let time = time.split('.').next()?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let mut t = time.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    crate::time::unix_from_civil(
        d.next()??,
        d.next()??,
        d.next()??,
        t.next()??,
        t.next()??,
        t.next()??,
    )
}

/// A file applied to a domain controller, kept on the graph for the
/// completeness report.
#[derive(Debug, Clone)]
pub struct DcSettingsFile {
    pub dc: NodeIndex,
    pub file: String,
    pub read_at: Option<i64>,
    /// Some of its values were used (a stale file may supply none).
    pub applied: bool,
    /// Given with the collection, or a settings folder's verified file
    /// ([`authoritative`]): only such a file makes the DC's settings current.
    pub trusted: bool,
}

/// Ingest statistics for one file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DcSettingsStats {
    pub file: String,
    pub domain: String,
    /// The DC as the file names it.
    pub dc: String,
    #[serde(default)]
    pub read_at: Option<i64>,
    #[serde(default)]
    pub os_build: Option<String>,
    /// The OS build was read and given to the DC (it decides what unset
    /// values mean).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub os_build_used: bool,
    /// The domain controller it was matched to, `None` when it is not in
    /// the AD data.
    #[serde(default)]
    pub matched: Option<String>,
    /// Values taken from the file.
    #[serde(default)]
    pub applied: Vec<String>,
    /// Values the collection read more recently, kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<String>,
    /// Values a stale or unverified file holds that would clear a weakness,
    /// not used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
    /// Read from a settings folder ([`Origin::Folder`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_folder: bool,
    /// From a settings folder, and owned by the server or a Tier Zero
    /// account: it may clear weaknesses.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_verified: bool,
    /// Every value the file holds, as read (the optional LDAP hardening
    /// values too, which no check uses yet).
    #[serde(default)]
    pub values: Vec<ValueRead>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// The computer a file names: by SID, then DNS name, then host name in the
/// file's domain. A SID that belongs to a computer of another name is
/// refused: the file names one computer and the SID another.
pub(crate) fn find_dc(g: &AdGraph, s: &Sidecar) -> Result<NodeIndex, String> {
    let dns = s.dns_name();
    let host = s.dc.hostname.trim().to_ascii_uppercase();
    let domain = s.domain.trim().to_ascii_uppercase();
    let by_sid =
        s.dc.object_sid
            .as_deref()
            .and_then(|sid| g.lookup(sid))
            .filter(|&ix| {
                let n = g.node(ix);
                n.kind == NodeKind::Computer && !n.placeholder
            });
    if let Some(ix) = by_sid {
        let name = g.node(ix).name.to_ascii_uppercase();
        let short = name.split('.').next().unwrap_or(&name);
        // A computer named without its domain can only be checked by host.
        // The collection may name it by its primary DNS suffix while the
        // script names it by the AD domain (disjoint namespace): the same
        // host in the same AD domain is the same computer.
        let same_domain = g.node(ix).domain.as_deref() == Some(domain.as_str());
        if short == host && (!name.contains('.') || name == dns || same_domain) {
            return Ok(ix);
        }
        return Err(format!(
            "its SID {} is {name} in the collection, not {dns}",
            s.dc.object_sid.as_deref().unwrap_or_default()
        ));
    }
    let mut by_host = Vec::new();
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::Computer || n.placeholder {
            continue;
        }
        let name = n.name.to_ascii_uppercase();
        if name == dns {
            return Ok(ix);
        }
        let short = name.split('.').next().unwrap_or(&name);
        if short == host && n.domain.as_deref() == Some(domain.as_str()) {
            by_host.push(ix);
        }
    }
    match by_host.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("no computer {dns} in the collection")),
        many => Err(format!(
            "{} computers named {host} in {domain} in the collection, so it can't tell which",
            many.len()
        )),
    }
}

/// Whether a value can open ESC9 or ESC10 on a DC of `build` (weak binding,
/// the Schannel UPN mapping bit, or an unset value that defaults to one). A
/// stale file only supplies these: it may show a weakness, never clear one.
fn opens(name: &str, setting: DcSetting, build: Option<OsBuild>) -> bool {
    let weak = match name {
        STRONG_BINDING => kdc_weak_mapping(setting, build),
        _ => schannel_upn_mapping(setting, build),
    };
    // Unlike `with_build`, no fallback to the value alone: a stale file's
    // binding 1 on a build after September 2025 is not used here, while the
    // same build next to a collected 1 leaves it weak. Neither closes.
    matches!(weak, Verdict::Weak(_))
}

/// The note on a settings folder's file its server or a Tier Zero account
/// didn't write.
pub const UNVERIFIED_NOTE: &str =
    "its file is of unknown origin, so it can show a weakness but not clear one";

/// Slack for clocks before a read time counts as in the future.
const FUTURE_SLACK: i64 = 86_400;

/// The file's read time, or `None` when it has none or it is more than a
/// day after `now` (a wrong clock): such a file counts as stale, so it can't
/// beat the collection or clear a finding.
pub(crate) fn effective_read_time(s: &Sidecar, now: i64) -> Option<i64> {
    s.read_time().filter(|&r| r <= now + FUTURE_SLACK)
}

/// Both of a DC's ESC9/ESC10 settings are known.
fn known(g: &AdGraph, ix: NodeIndex) -> bool {
    let p = &g.node(ix).props;
    [Mapping::Kerberos, Mapping::Schannel]
        .into_iter()
        .all(|m| verdict(p, m) != Verdict::Unknown)
}

/// Whether a file is stale: read more than [`STALE_DAYS`] days before the
/// collection (before `now` when the collection time is unknown), or with no
/// usable read time.
pub fn is_stale(read_at: Option<i64>, collected_at: Option<i64>, now: i64) -> bool {
    let reference = collected_at.unwrap_or(now);
    read_at.is_none_or(|r| r < reference - STALE_DAYS * 86_400)
}

/// Applies the files, oldest first so the newest wins. Runs after every AD
/// file is read and before the AD CS checks. `collected_at` is the
/// collection time from the collector's file names; `now` stands in for it
/// when it is unknown.
///
/// Per value: the collection's own reading is kept when it is newer than the
/// file, or when the file has no read time. A stale file supplies only
/// values that open ESC9/ESC10.
pub(crate) fn apply_all(
    g: &mut AdGraph,
    mut files: Vec<(String, Sidecar, Vec<String>)>,
    collected_at: Option<i64>,
    now: i64,
    skipped: &mut Vec<String>,
) -> Vec<DcSettingsStats> {
    files.sort_by_key(|(_, s, _)| effective_read_time(s, now));
    let mut out = Vec::new();
    // What the collection itself read, before any file changed it.
    let mut collected: BTreeMap<(NodeIndex, &'static str), DcSetting> = BTreeMap::new();
    for (label, s, mut notes) in files {
        // A certification authority's host that is not a domain controller:
        // the script reads no DC values there, and its CAs are applied by
        // [`apply_cas`], its agents by [`crate::hostprobe::apply`].
        if s.values.is_empty() && (!s.cas.is_empty() || s.agents.is_some()) {
            continue;
        }
        let read_at = effective_read_time(&s, now);
        if read_at.is_none() && s.read_time().is_some() && notes.len() < MAX_NOTES {
            notes.push(format!(
                "read time {} is in the future (a clock is wrong): it counts as having none",
                s.read_at.as_deref().unwrap_or_default()
            ));
        }
        let mut st = DcSettingsStats {
            file: label.clone(),
            domain: s.domain.trim().to_ascii_uppercase(),
            dc: s.dns_name(),
            read_at,
            os_build: s.dc.os_build.clone(),
            values: s.values.clone(),
            ..DcSettingsStats::default()
        };
        let ix = match find_dc(g, &s) {
            Ok(ix) => ix,
            Err(why) => {
                skipped.push(format!("{label} (Tier Zero settings: {why})"));
                out.push(st);
                continue;
            }
        };
        if !g.node(ix).is_dc && notes.len() < MAX_NOTES {
            notes.push(format!(
                "{} is not a domain controller in the collection; its settings are not used by the AD CS checks",
                g.node(ix).name
            ));
        }
        st.matched = Some(g.node(ix).name.clone());
        let stale = is_stale(read_at, collected_at, now);
        // A settings folder's file not written by the DC or a Tier Zero
        // account: it can confirm weaknesses and fill what nobody read.
        let trusted = authoritative(g, &s, &[ix]);
        st.from_folder = matches!(s.origin, Origin::Folder { .. });
        st.owner_verified = st.from_folder && trusted;
        if !trusted && notes.len() < MAX_NOTES {
            notes.push(UNVERIFIED_NOTE.into());
        }
        let build = s.dc.os_build.as_deref().and_then(OsBuild::parse);
        match (build, s.dc.os_build.as_deref()) {
            (Some(build), _) => {
                // An unverified file's build may open, never close, as a
                // stale one's.
                let stale = stale || !trusted;
                g.node_mut(ix).props.os_build = Some(DcOsBuild { build, stale });
                st.os_build_used = true;
            }
            (None, Some(text)) if notes.len() < MAX_NOTES => notes.push(format!(
                "OS build '{text}' is not build.revision: unset values are judged without it"
            )),
            _ => {}
        }
        if stale && notes.len() < MAX_NOTES {
            notes.push(match read_at {
                None => "it has no read time, so it counts as stale: only values that show a weakness are used"
                    .to_string(),
                Some(_) => format!(
                    "read more than {STALE_DAYS} days before the collection: only values that show a weakness are used"
                ),
            });
        }
        for name in [STRONG_BINDING, MAPPING_METHODS] {
            let Some(v) = s.value(name) else { continue };
            let Some(setting) = v.setting() else {
                if notes.len() < MAX_NOTES {
                    notes.push(match &v.error {
                        Some(e) => format!("{name} was not read: {e}"),
                        None => format!("{name} has no number"),
                    });
                }
                continue;
            };
            let props = &mut g.node_mut(ix).props;
            let current = match name {
                STRONG_BINDING => &mut props.strongcertificatebindingenforcement,
                _ => &mut props.certificatemappingmethods,
            };
            let own = *collected.entry((ix, name)).or_insert(*current);
            // The collection's own reading is kept when it is newer than this
            // file, or when this file's time is unknown.
            let collection_wins = own != DcSetting::Unknown
                && match (collected_at, read_at) {
                    (Some(c), Some(r)) => c > r,
                    (_, None) => true,
                    (None, Some(_)) => false,
                };
            let weakens = opens(name, setting, build);
            if collection_wins {
                *current = own;
                st.kept.push(name.to_string());
            } else if (stale || !trusted) && !weakens {
                // A stale or unverified file never clears: it can only
                // show a weakness, never fill a value toward strong.
                st.ignored.push(name.to_string());
            } else {
                *current = setting;
                st.applied.push(name.to_string());
            }
        }
        if stale && st.applied.is_empty() && known(g, ix) && notes.len() < MAX_NOTES {
            notes.push("old settings file ignored: the collection's own values are used".into());
        }
        // An unverified file that gave nothing isn't the DC's settings file:
        // it mustn't make a row current or hide a trusted stale file.
        if !st.applied.is_empty() || (trusted && (!st.ignored.is_empty() || st.os_build_used)) {
            g.add_dc_settings_file(DcSettingsFile {
                dc: ix,
                file: label,
                read_at,
                // A fresh file's build is used both ways; a stale one's may
                // only open, like its values.
                applied: !st.applied.is_empty() || (st.os_build_used && !stale && trusted),
                trusted,
            });
        }
        st.notes = notes;
        out.push(st);
    }
    out
}

/// A file applied to an Enterprise CA, kept on the graph for the report.
#[derive(Debug, Clone)]
pub struct CaSettingsFile {
    pub ca: NodeIndex,
    pub file: String,
    pub read_at: Option<i64>,
    /// Read more than [`STALE_DAYS`] days before the collection, or undated.
    pub stale: bool,
    /// ESC6's and ESC11's values came from this file.
    pub esc6: bool,
    pub esc11: bool,
    /// As [`DcSettingsFile::trusted`].
    pub trusted: bool,
}

/// Ingest statistics for one certification authority of one file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaSettingsStats {
    pub file: String,
    /// The CA as the file names it.
    pub ca: String,
    /// Its host, as the file names it.
    pub host: String,
    #[serde(default)]
    pub read_at: Option<i64>,
    /// The Enterprise CA it was matched to, `None` when it is not in the
    /// AD data.
    #[serde(default)]
    pub matched: Option<String>,
    #[serde(default)]
    pub applied: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
    /// `RoleSeparationEnabled`, recorded only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_separation: Option<i64>,
    /// As [`DcSettingsStats::from_folder`] and
    /// [`DcSettingsStats::owner_verified`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_folder: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_verified: bool,
    #[serde(default)]
    pub values: Vec<ValueRead>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// ESC6 from `EditFlags`: the SAN flag. Unset `EditFlags` is the policy
/// module's default, which lacks it.
pub fn san_enabled(edit_flags: DcSetting) -> Option<bool> {
    match edit_flags {
        DcSetting::Value(v) => Some(v & SAN_FLAG != 0),
        DcSetting::NotSet => Some(false),
        DcSetting::Unknown => None,
    }
}

/// ESC11 from `InterfaceFlags`: encryption is enforced unless the value is
/// set without [`ENCRYPT_FLAG`].
pub fn encryption_enforced(interface_flags: DcSetting) -> Option<bool> {
    match interface_flags {
        DcSetting::Value(v) => Some(v & ENCRYPT_FLAG != 0),
        DcSetting::NotSet => Some(true),
        DcSetting::Unknown => None,
    }
}

/// The Enterprise CA a file's entry names: by certificate thumbprint, else
/// by CA name and host. When both match, they must agree, as a DC's SID
/// and name must.
/// Whether the Enterprise CA `a` is on the host file `s` describes, when
/// the collection names its host.
fn ca_on_host(s: &Sidecar, a: &crate::model::AdcsProps) -> Option<bool> {
    let host = s.dns_name();
    let short = s.dc.hostname.trim().to_ascii_uppercase();
    a.dnshostname.as_deref().map(|d| {
        let d = d.trim().to_ascii_uppercase();
        d == host || (!d.contains('.') && d == short)
    })
}

fn find_ca(g: &AdGraph, s: &Sidecar, ca: &CaRead) -> Result<NodeIndex, String> {
    let host = s.dns_name();
    let on_host = |a: &crate::model::AdcsProps| ca_on_host(s, a);
    let mut by_hash = None;
    let mut by_name: Vec<NodeIndex> = Vec::new();
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::EnterpriseCa || n.placeholder {
            continue;
        }
        let Some(a) = n.adcs.as_deref() else { continue };
        if a.certthumbprint
            .as_deref()
            .is_some_and(|t| ca.cert_hashes.iter().any(|h| h.eq_ignore_ascii_case(t)))
        {
            by_hash = Some(ix);
        }
        let name = a.caname.as_deref().unwrap_or(&n.name);
        if name.trim().eq_ignore_ascii_case(&ca.name) && on_host(a) == Some(true) {
            by_name.push(ix);
        }
    }
    if by_name.len() > 1 {
        return Err(format!(
            "{} Enterprise CAs named {} on {host} in the collection, so it can't tell which",
            by_name.len(),
            ca.name
        ));
    }
    match (by_hash, by_name.first().copied()) {
        (Some(h), Some(n)) if h != n => Err(format!(
            "its certificate is {} in the collection, not {} on {host}",
            g.node(h).name,
            ca.name
        )),
        (Some(h), _) => {
            // A thumbprint of a CA of another name, or on another host: the
            // file names one CA and the certificate another.
            let a = g.node(h).adcs.as_deref();
            let other_name = a
                .and_then(|a| a.caname.as_deref())
                .is_some_and(|n| !n.trim().eq_ignore_ascii_case(&ca.name));
            let other_host = a.and_then(on_host) == Some(false);
            if other_name || other_host {
                Err(format!(
                    "its certificate is {} in the collection, not {} on {host}",
                    g.node(h).name,
                    ca.name
                ))
            } else {
                Ok(h)
            }
        }
        (None, Some(n)) => Ok(n),
        (None, None) => Err(format!(
            "no Enterprise CA {} on {host} in the collection",
            ca.name
        )),
    }
}

/// Applies the files' certification authority values to their Enterprise
/// CAs, oldest first so the newest wins, with the precedence and staleness
/// rules of [`apply_all`]: the collection's own reading is kept when it is
/// newer than the file, or when the file has no read time; a stale file
/// supplies only values that open ESC6 (the SAN flag on) or ESC11
/// (`InterfaceFlags` set without [`ENCRYPT_FLAG`]).
pub(crate) fn apply_cas(
    g: &mut AdGraph,
    files: &[(String, Sidecar, Vec<String>)],
    collected_at: Option<i64>,
    now: i64,
    skipped: &mut Vec<String>,
) -> Vec<CaSettingsStats> {
    let mut order: Vec<&(String, Sidecar, Vec<String>)> =
        files.iter().filter(|(_, s, _)| !s.cas.is_empty()).collect();
    order.sort_by_key(|(_, s, _)| effective_read_time(s, now));
    let mut out = Vec::new();
    // What the collection itself read, before any file changed it.
    let mut collected: BTreeMap<(NodeIndex, &'static str), Option<bool>> = BTreeMap::new();
    for (label, s, _) in order {
        let read_at = effective_read_time(s, now);
        let stale = is_stale(read_at, collected_at, now);
        // The computer the file describes: its CAs' host, matched as a DC
        // is (find_ca checks the CA is on that host).
        let host: Vec<NodeIndex> = find_dc(g, s).ok().into_iter().collect();
        let file_trusted = authoritative(g, s, &host);
        for ca in &s.cas {
            let mut st = CaSettingsStats {
                file: label.clone(),
                ca: ca.name.clone(),
                host: s.dns_name(),
                read_at,
                values: ca.values.clone(),
                role_separation: ca.value(ROLE_SEPARATION).and_then(|v| v.value),
                ..CaSettingsStats::default()
            };
            let ix = match find_ca(g, s, ca) {
                Ok(ix) => ix,
                Err(why) => {
                    skipped.push(format!("{label} (Tier Zero settings: {why})"));
                    out.push(st);
                    continue;
                }
            };
            st.matched = Some(g.node(ix).name.clone());
            st.from_folder = matches!(s.origin, Origin::Folder { .. });
            // A folder's file vouches for a CA only on the host the
            // collection gives it: a matching thumbprint alone could be
            // carried by any machine's file.
            let trusted = file_trusted
                && (!st.from_folder
                    || g.node(ix).adcs.as_deref().and_then(|a| ca_on_host(s, a)) == Some(true));
            st.owner_verified = st.from_folder && trusted;
            if !trusted {
                st.notes.push(UNVERIFIED_NOTE.into());
            }
            if stale && st.notes.len() < MAX_NOTES {
                st.notes.push(match read_at {
                    None => "it has no read time, so it counts as stale: only values that show a weakness are used".to_string(),
                    Some(_) => format!(
                        "read more than {STALE_DAYS} days before the collection: only values that show a weakness are used"
                    ),
                });
            }
            let (mut esc6, mut esc11) = (false, false);
            for name in [EDIT_FLAGS, INTERFACE_FLAGS] {
                let Some(v) = ca.value(name) else { continue };
                let Some(setting) = v.setting() else {
                    if st.notes.len() < MAX_NOTES {
                        st.notes.push(match &v.error {
                            Some(e) => format!("{name} was not read: {e}"),
                            None => format!("{name} has no number"),
                        });
                    }
                    continue;
                };
                let (value, weak) = match name {
                    EDIT_FLAGS => {
                        let on = san_enabled(setting);
                        (on, on == Some(true))
                    }
                    _ => {
                        let on = encryption_enforced(setting);
                        (on, on == Some(false))
                    }
                };
                let Some(adcs) = g.node_mut(ix).adcs.as_deref_mut() else {
                    continue;
                };
                let current = match name {
                    EDIT_FLAGS => &mut adcs.isuserspecifiessanenabled,
                    _ => &mut adcs.enforceencryptionforrequests,
                };
                let own = *collected.entry((ix, name)).or_insert(*current);
                let collection_wins = own.is_some()
                    && match (collected_at, read_at) {
                        (Some(c), Some(r)) => c > r,
                        (_, None) => true,
                        (None, Some(_)) => false,
                    };
                if collection_wins {
                    *current = own;
                    st.kept.push(name.to_string());
                } else if (stale || !trusted) && !weak {
                    // A stale or unverified file never clears: it can only
                    // show a weakness, never fill a value toward strong.
                    st.ignored.push(name.to_string());
                } else {
                    *current = value;
                    st.applied.push(name.to_string());
                    match name {
                        EDIT_FLAGS => esc6 = true,
                        _ => esc11 = true,
                    }
                }
            }
            // An unverified file that gave nothing doesn't count as the
            // CA's settings file: what it held wasn't used.
            let counts = !st.applied.is_empty()
                || (trusted && (!st.ignored.is_empty() || !st.kept.is_empty()));
            if counts {
                g.add_ca_settings_file(CaSettingsFile {
                    ca: ix,
                    file: label.clone(),
                    read_at,
                    stale,
                    esc6,
                    esc11,
                    trusted,
                });
            }
            out.push(st);
        }
    }
    out
}

/// Where an Enterprise CA's ESC6 or ESC11 value came from, when a settings
/// file is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAge {
    /// From a current settings file.
    Current,
    /// From a settings file over [`STALE_DAYS`] days old, or one whose
    /// value was not used because it was.
    Stale,
}

/// Per Enterprise CA, for the AD CS data row: where ESC6 and ESC11 came
/// from when a settings file is involved, by CA node.
pub fn ca_file_ages(g: &AdGraph) -> BTreeMap<NodeIndex, (Option<FileAge>, Option<FileAge>)> {
    let mut out: BTreeMap<NodeIndex, (Option<FileAge>, Option<FileAge>)> = BTreeMap::new();
    // Oldest first, so the newest file that set a value has the last word.
    let mut files: Vec<&CaSettingsFile> = g.ca_settings_files().iter().collect();
    files.sort_by_key(|f| f.read_at);
    for f in files {
        let age = if f.stale {
            FileAge::Stale
        } else {
            FileAge::Current
        };
        let e = out.entry(f.ca).or_default();
        if f.esc6 {
            e.0 = Some(age);
        }
        if f.esc11 {
            e.1 = Some(age);
        }
    }
    // A stale file whose value was not used, on a CA the collection could
    // not read: still unknown, because the file is old.
    for f in g.ca_settings_files() {
        let Some(a) = g.node(f.ca).adcs.as_deref() else {
            continue;
        };
        let e = out.entry(f.ca).or_default();
        if f.stale && a.isuserspecifiessanenabled.is_none() && e.0.is_none() {
            e.0 = Some(FileAge::Stale);
        }
        if f.stale && a.enforceencryptionforrequests.is_none() && e.1.is_none() {
            e.1 = Some(FileAge::Stale);
        }
    }
    out
}

/// One Enterprise CA's settings, for the report's Tier Zero settings row.
#[derive(Debug, Clone, Serialize)]
pub struct CaCompleteness {
    pub ca: String,
    /// When its newest settings file was read; `None` without one, or when
    /// that file has no read time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
    /// A settings file for it was read.
    pub has_file: bool,
    /// Its newest file is over [`STALE_DAYS`] days old, or undated.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    /// The collection read ESC6 and ESC11 itself, without a file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collected: bool,
}

impl CaCompleteness {
    /// It needs a (newer) settings file: none, a stale one, or one that
    /// left a value unknown.
    pub fn needs_file(&self) -> bool {
        if self.has_file {
            self.stale
        } else {
            !self.collected
        }
    }
}

/// [`CaCompleteness`] for every collected Enterprise CA, by name.
pub fn ca_completeness(g: &AdGraph) -> Vec<CaCompleteness> {
    let mut newest: BTreeMap<NodeIndex, &CaSettingsFile> = BTreeMap::new();
    // Only trusted files count as a CA's settings file.
    for f in g.ca_settings_files().iter().filter(|f| f.trusted) {
        let e = newest.entry(f.ca).or_insert(f);
        if f.read_at > e.read_at {
            *e = f;
        }
    }
    let mut out: Vec<CaCompleteness> = g
        .nodes()
        .filter(|(_, n)| n.kind == NodeKind::EnterpriseCa && !n.placeholder)
        .map(|(ix, n)| {
            let a = n.adcs.as_deref();
            // The collection read both values itself, and no file gave one
            // (a file it was newer than, kept or not, changes nothing).
            let supplied = g
                .ca_settings_files()
                .iter()
                .any(|f| f.ca == ix && (f.esc6 || f.esc11));
            let collected = !supplied
                && a.is_some_and(|a| {
                    a.isuserspecifiessanenabled.is_some()
                        && a.enforceencryptionforrequests.is_some()
                });
            let f = newest.get(&ix).filter(|_| !collected);
            CaCompleteness {
                // The CA's own name ("CONTOSO-CA"), as the report says it.
                ca: a
                    .and_then(|a| a.caname.clone())
                    .unwrap_or_else(|| n.name.clone()),
                read_at: f.and_then(|f| f.read_at),
                has_file: f.is_some(),
                stale: f.is_some_and(|f| f.stale),
                collected,
            }
        })
        .collect();
    out.sort_by(|a, b| a.ca.cmp(&b.ca));
    out
}

/// A Tier Zero settings file a run used, as the run records it:
/// its file name only, never the folder it came from, since runs are
/// shared through the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsFileUse {
    pub file_name: String,
    /// The domain controller or Enterprise CA it was matched to.
    pub server: String,
    pub kind: ServerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
    /// Over [`STALE_DAYS`] days old (or undated): it can confirm a weakness
    /// but not show one fixed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    /// Some of its values were used.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub applied: bool,
}

/// What a settings file describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKind {
    Dc,
    Ca,
}

/// A file label's file name: what follows the last `/`, `\` or `!`.
pub fn file_name(label: &str) -> &str {
    label.rsplit(['/', '\\', '!']).next().unwrap_or(label)
}

/// The settings files an analysis used, matched to a domain controller or
/// an Enterprise CA, by server: what `last-run.json`, the run and its
/// details record. `collected_at` (else `now`) is what staleness is judged
/// against.
pub fn settings_files(
    dcs: &[DcSettingsStats],
    cas: &[CaSettingsStats],
    collected_at: Option<i64>,
    now: i64,
) -> Vec<SettingsFileUse> {
    let mut out: Vec<SettingsFileUse> = Vec::new();
    let mut push = |u: SettingsFileUse| {
        // The same file read twice (in the collection and a folder).
        if !out.iter().any(|o| {
            o.file_name.eq_ignore_ascii_case(&u.file_name)
                && o.server == u.server
                && o.kind == u.kind
                && o.read_at == u.read_at
        }) {
            out.push(u);
        }
    };
    for d in dcs {
        let Some(server) = &d.matched else { continue };
        // Only a file that was used, or could have been: an unverified one
        // that gave nothing is not one the run relied on.
        if d.applied.is_empty() && d.from_folder && !d.owner_verified {
            continue;
        }
        push(SettingsFileUse {
            file_name: file_name(&d.file).to_string(),
            server: server.clone(),
            kind: ServerKind::Dc,
            read_at: d.read_at,
            stale: is_stale(d.read_at, collected_at, now),
            applied: !d.applied.is_empty() || d.os_build_used,
        });
    }
    for c in cas {
        if c.matched.is_none() || (c.applied.is_empty() && c.from_folder && !c.owner_verified) {
            continue;
        }
        push(SettingsFileUse {
            file_name: file_name(&c.file).to_string(),
            // The CA's own name ("CONTOSO-CA"), as the file and the
            // collection's `caname` give it.
            server: c.ca.clone(),
            kind: ServerKind::Ca,
            read_at: c.read_at,
            stale: is_stale(c.read_at, collected_at, now),
            applied: !c.applied.is_empty(),
        });
    }
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.server.cmp(&b.server)));
    out
}

/// The servers `before` had a settings file for and `now` has none for,
/// domain controllers first, as `before` lists them: a run with fewer files
/// than the last says so (its findings that relied on them turn
/// unverified, not fixed).
pub fn fewer(before: &[SettingsFileUse], now: &[SettingsFileUse]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for b in before {
        let kept = now
            .iter()
            .any(|n| n.kind == b.kind && n.server.eq_ignore_ascii_case(&b.server));
        if !kept && !out.contains(&b.server) {
            out.push(b.server.clone());
        }
    }
    out
}

/// A run's settings files in a few words, as Run details' status and the
/// command line say them: "6 files, 2 over 90 days old", with ", 2 fewer
/// than the last run" when `fewer` servers lost theirs.
pub fn files_status(files: &[SettingsFileUse], fewer: usize) -> String {
    let stale = files.iter().filter(|f| f.stale).count();
    let mut s = crate::text::count(files.len(), "file", "files");
    if stale > 0 {
        s.push_str(&format!(", {stale} over {STALE_DAYS} days old"));
    }
    if fewer > 0 {
        s.push_str(&format!(", {fewer} fewer than the last run"));
    }
    s
}

/// What a run with fewer settings files than the last says, naming the
/// servers ([`fewer`]); `None` with none.
pub fn fewer_sentence(fewer: &[String]) -> Option<String> {
    (!fewer.is_empty()).then(|| {
        format!(
            "The last run also had files for {}. Findings that relied on them are marked unverified until the files are back. They don't count as fixed.",
            crate::text::and_list(fewer)
        )
    })
}

/// What a run says when `n` settings folders couldn't be opened.
pub fn unread_sentence(n: usize) -> Option<String> {
    match n {
        0 => None,
        1 => Some("A settings folder couldn't be opened, so its files weren't read.".into()),
        n => Some(format!(
            "{n} settings folders couldn't be opened, so their files weren't read."
        )),
    }
}

/// How many domain controllers' ESC9/ESC10 settings one domain's data holds.
#[derive(Debug, Clone, Serialize)]
pub struct Completeness {
    pub domain: String,
    pub domain_controllers: usize,
    /// DCs whose two settings are determined: read (by the collector, or
    /// from a Tier Zero settings file) and, when not set, with the DC's OS
    /// build from a current file to say what unset means.
    pub read: usize,
    /// Of those, read from a Tier Zero settings file.
    pub from_file: usize,
    /// DCs whose settings are not known, or not set with no current OS
    /// build.
    pub missing: Vec<String>,
    /// DCs whose newest file was read more than [`STALE_DAYS`] days before
    /// `now` (the collection time), or has no read time, unless the
    /// collection read the DC's values itself and the file supplied none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<String>,
}

impl Completeness {
    pub fn is_complete(&self) -> bool {
        self.read == self.domain_controllers && self.stale.is_empty()
    }

    /// Domain controllers missing a current settings file: not known, or
    /// with a file over [`STALE_DAYS`] days old, each once.
    pub fn needing(&self) -> usize {
        self.missing
            .iter()
            .filter(|n| !self.stale.contains(n))
            .count()
            + self.stale.len()
    }

    /// Domain controllers with current settings ("3 of 4").
    pub fn current(&self) -> usize {
        self.domain_controllers.saturating_sub(self.needing())
    }

    /// What the domain still needs, in the report's words: "A newer file
    /// from DC04. Its file is over 90 days old.", or "Nothing.".
    pub fn still_needed(&self) -> String {
        let short = |n: &String| n.split('.').next().unwrap_or(n).to_string();
        let missing: Vec<String> = self
            .missing
            .iter()
            .filter(|n| !self.stale.contains(n))
            .map(short)
            .collect();
        let stale: Vec<String> = self.stale.iter().map(short).collect();
        let mut out = Vec::new();
        if !stale.is_empty() {
            out.push(format!(
                "A newer file from {}. {} over {STALE_DAYS} days old.",
                crate::text::and_list(&stale),
                if stale.len() == 1 {
                    "Its file is"
                } else {
                    "Their files are"
                }
            ));
        }
        if !missing.is_empty() {
            out.push(format!(
                "A settings file from {}.",
                crate::text::and_list(&missing)
            ));
        }
        if out.is_empty() {
            "Nothing.".into()
        } else {
            out.join(" ")
        }
    }
}

impl CaCompleteness {
    /// What the report says of its settings: "Read from its settings file
    /// on Oct 29, 2026.", "No settings file yet.", or, read by the
    /// collection itself, "Read by the collection.".
    pub fn settings_words(&self) -> String {
        match (self.has_file, self.read_at) {
            (true, Some(t)) => format!(
                "Read from its settings file on {}.",
                crate::time::format_day(t)
            ),
            (true, None) => "Read from its settings file, which has no date.".into(),
            (false, _) if self.collected => "Read by the collection.".into(),
            (false, _) => "No settings file yet.".into(),
        }
    }

    /// What it still needs: "Nothing.", "A settings file from this CA.", or
    /// "A newer file. This one is over 90 days old.".
    pub fn still_needed(&self) -> String {
        match (self.has_file, self.stale, self.read_at) {
            (true, false, _) => "Nothing.".into(),
            (true, true, Some(_)) => {
                format!("A newer file. This one is over {STALE_DAYS} days old.")
            }
            (true, true, None) => "A dated file. This one has no date.".into(),
            (false, ..) if self.collected => "Nothing.".into(),
            (false, ..) => "A settings file from this CA.".into(),
        }
    }
}

/// The Tier Zero settings row's summary: "3 servers need a current settings
/// file", or "Current on every server" when none does.
pub fn needing_words(dcs: &[Completeness], cas: &[CaCompleteness]) -> (usize, String) {
    let n = dcs.iter().map(Completeness::needing).sum::<usize>()
        + cas.iter().filter(|c| c.needs_file()).count();
    let words = match n {
        0 => "Current on every server".to_string(),
        1 => "1 server needs a current settings file".to_string(),
        n => format!("{n} servers need a current settings file"),
    };
    (n, words)
}

/// Per domain with domain controllers, when the data has an Enterprise CA
/// or a Tier Zero settings file (otherwise ESC9/ESC10 don't apply).
pub fn completeness(g: &AdGraph, now: i64) -> Vec<Completeness> {
    let has_ca = g
        .nodes()
        .any(|(_, n)| n.kind == NodeKind::EnterpriseCa && !n.placeholder);
    if !has_ca && g.dc_settings_files().is_empty() {
        return Vec::new();
    }
    // Per DC: the newest file's read time, and whether any file was used.
    let mut newest: BTreeMap<NodeIndex, (Option<i64>, bool)> = BTreeMap::new();
    // Only trusted files make a DC's settings current, or stale; a DC whose
    // values only an unverified file gave still needs a file.
    let mut unverified: std::collections::BTreeSet<NodeIndex> = Default::default();
    for f in g.dc_settings_files() {
        if !f.trusted {
            unverified.insert(f.dc);
            continue;
        }
        let e = newest.entry(f.dc).or_insert((f.read_at, false));
        e.0 = e.0.max(f.read_at);
        e.1 |= f.applied;
    }
    let mut by_domain: BTreeMap<String, Completeness> = BTreeMap::new();
    for (ix, n) in g.nodes() {
        if n.kind != NodeKind::Computer || n.placeholder || !n.is_dc {
            continue;
        }
        let domain = n.domain.clone().unwrap_or_else(|| "UNKNOWN".into());
        let c = by_domain
            .entry(domain.clone())
            .or_insert_with(|| Completeness {
                domain,
                domain_controllers: 0,
                read: 0,
                from_file: 0,
                missing: Vec::new(),
                stale: Vec::new(),
            });
        c.domain_controllers += 1;
        let known = known(g, ix) && (newest.contains_key(&ix) || !unverified.contains(&ix));
        if known {
            c.read += 1;
        } else {
            c.missing.push(n.name.clone());
        }
        if let Some(&(read_at, applied)) = newest.get(&ix) {
            if applied {
                c.from_file += 1;
            }
            // An old file the collection's own values made moot is not
            // worth flagging (its stats say it was ignored).
            if is_stale(read_at, Some(now), now) && (applied || !known) {
                c.stale.push(n.name.clone());
            }
        }
    }
    let mut out: Vec<Completeness> = by_domain.into_values().collect();
    for c in &mut out {
        c.missing.sort();
        c.stale.sort();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "schema": "pathwarden.tierzero.v1",
        "domain": "north.sevenkingdoms.local",
        "dc": {"hostname": "WINTERFELL", "dns_name": "winterfell.north.sevenkingdoms.local",
               "object_sid": "S-1-5-21-1-2-3-1001", "os_build": "17763.5458"},
        "read_at": "2026-10-13T08:30:00Z",
        "values": [
            {"name": "StrongCertificateBindingEnforcement", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc", "present": true, "value": 1},
            {"name": "CertificateMappingMethods", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel", "present": false},
            {"name": "LDAPServerIntegrity", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", "present": false, "error": "Access is denied"}
        ]
    }"#;

    #[test]
    fn names() {
        assert!(is_sidecar_name("pathwarden-tierzero-WINTERFELL.json"));
        assert!(is_sidecar_name(r"C:\x\WINTERFELL-tierzero.json"));
        assert!(is_sidecar_name("a.zip!dir/PathWarden-TierZero-dc01.json"));
        assert!(!is_sidecar_name("tierzero.json"));
        assert!(!is_sidecar_name("users.json"));
        assert!(!is_sidecar_name("pathwarden-tierzero-dc01.txt"));
        assert!(is_sidecar_name("pathwarden-tierzero-DC01.pki.local.json"));
        assert!(!is_sidecar_name("pathwarden-tierzero-x.coverage.json"));
        assert!(crate::opengraph::coverage::is_sidecar_name(
            "pathwarden-tierzero-x.coverage.json"
        ));
    }

    #[test]
    fn parses_a_valid_file() {
        let mut notes = Vec::new();
        let s = Sidecar::parse(VALID.as_bytes(), &mut notes).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(s.dns_name(), "WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL");
        assert_eq!(
            s.read_time(),
            crate::time::unix_from_civil(2026, 10, 13, 8, 30, 0)
        );
        assert_eq!(
            s.value("strongcertificatebindingenforcement")
                .unwrap()
                .setting(),
            Some(DcSetting::Value(1))
        );
        assert_eq!(
            s.value(MAPPING_METHODS).unwrap().setting(),
            Some(DcSetting::NotSet)
        );
        assert_eq!(s.value("LDAPServerIntegrity").unwrap().setting(), None);
        // A byte order mark (Windows PowerShell 5.1 writes one) is fine.
        let bom = [b"\xEF\xBB\xBF".as_slice(), VALID.as_bytes()].concat();
        assert!(Sidecar::parse(&bom, &mut Vec::new()).is_ok());
    }

    #[test]
    fn refuses_other_schemas_and_garbage() {
        let other = VALID.replace("pathwarden.tierzero.v1", "pathwarden.sysvol.v1");
        let e = Sidecar::parse(other.as_bytes(), &mut Vec::new()).unwrap_err();
        assert!(e.contains("is not pathwarden.tierzero.v1"), "{e}");
        assert!(Sidecar::parse(b"not json", &mut Vec::new()).is_err());
        assert!(Sidecar::parse(b"{}", &mut Vec::new()).is_err());
        let no_host = VALID.replace("\"WINTERFELL\"", "\"\"");
        assert!(Sidecar::parse(no_host.as_bytes(), &mut Vec::new()).is_err());
        let big = vec![b' '; MAX_SIDECAR_BYTES as usize + 1];
        assert!(Sidecar::parse(&big, &mut Vec::new()).is_err());
    }

    fn dc(g: &mut AdGraph, sid: &str, name: &str, domain: &str) -> NodeIndex {
        let mut n = crate::model::Node::placeholder(sid.into(), NodeKind::Computer);
        n.placeholder = false;
        n.is_dc = true;
        n.name = name.into();
        n.domain = Some(domain.into());
        g.upsert(n)
    }

    fn file(
        host: &str,
        domain: &str,
        sid: Option<&str>,
        read_at: Option<&str>,
        binding: i64,
    ) -> Sidecar {
        Sidecar {
            schema: SCHEMA.into(),
            domain: domain.into(),
            dc: DcInfo {
                hostname: host.into(),
                object_sid: sid.map(Into::into),
                ..DcInfo::default()
            },
            read_at: read_at.map(Into::into),
            values: vec![ValueRead {
                name: STRONG_BINDING.into(),
                present: true,
                value: Some(binding),
                ..ValueRead::default()
            }],
            cas: Vec::new(),
            agents: None,
            origin: Origin::default(),
        }
    }

    fn binding(g: &AdGraph, ix: NodeIndex) -> DcSetting {
        g.node(ix).props.strongcertificatebindingenforcement
    }

    const T: &str = "2026-10-13T08:30:00Z";

    #[test]
    fn same_host_names_in_two_domains_go_to_their_own_dc() {
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let b = dc(&mut g, "S-1-5-21-2-2-2-1000", "DC01.B.LOCAL", "B.LOCAL");
        let now = parse_utc(T).unwrap();
        let files = vec![
            (
                "a".to_string(),
                file("DC01", "a.local", None, Some(T), 1),
                vec![],
            ),
            (
                "b".to_string(),
                file("dc01", "B.local", None, Some(T), 2),
                vec![],
            ),
        ];
        let mut skipped = Vec::new();
        let st = apply_all(&mut g, files, Some(now), now, &mut skipped);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(st[0].matched.as_deref(), Some("DC01.A.LOCAL"));
        assert_eq!(st[1].matched.as_deref(), Some("DC01.B.LOCAL"));
        assert_eq!(binding(&g, a), DcSetting::Value(1));
        assert_eq!(binding(&g, b), DcSetting::Value(2));
    }

    #[test]
    fn a_sid_of_another_computer_is_refused() {
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let b = dc(&mut g, "S-1-5-21-1-1-1-1001", "DC02.A.LOCAL", "A.LOCAL");
        let now = parse_utc(T).unwrap();
        // Names DC01, carries DC02's SID.
        let files = vec![(
            "f".to_string(),
            file("DC01", "a.local", Some("S-1-5-21-1-1-1-1001"), Some(T), 1),
            vec![],
        )];
        let mut skipped = Vec::new();
        let st = apply_all(&mut g, files, Some(now), now, &mut skipped);
        assert_eq!(st[0].matched, None);
        assert!(
            skipped[0].contains("is DC02.A.LOCAL in the collection, not DC01.A.LOCAL"),
            "{skipped:?}"
        );
        assert_eq!(binding(&g, a), DcSetting::Unknown);
        assert_eq!(binding(&g, b), DcSetting::Unknown);
        // The matching SID and name are fine.
        let files = vec![(
            "f".to_string(),
            file("DC02", "a.local", Some("S-1-5-21-1-1-1-1001"), Some(T), 1),
            vec![],
        )];
        let st = apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert_eq!(st[0].matched.as_deref(), Some("DC02.A.LOCAL"));
    }

    #[test]
    fn an_ambiguous_short_name_is_refused() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        // Two DC01s in A.LOCAL, by DNS suffixes that aren't the domain.
        dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.X.EXAMPLE", "A.LOCAL");
        dc(&mut g, "S-1-5-21-1-1-1-1001", "DC01.Y.EXAMPLE", "A.LOCAL");
        let mut skipped = Vec::new();
        let st = apply_all(
            &mut g,
            vec![(
                "f".to_string(),
                file("DC01", "a.local", None, Some(T), 1),
                vec![],
            )],
            Some(now),
            now,
            &mut skipped,
        );
        assert_eq!(st[0].matched, None);
        assert!(skipped[0].contains("2 computers named DC01"), "{skipped:?}");
    }

    #[test]
    fn a_sid_match_survives_a_disjoint_dns_namespace() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        // Primary DNS suffix corp.example, AD domain A.LOCAL.
        let a = dc(
            &mut g,
            "S-1-5-21-1-1-1-1000",
            "DC01.CORP.EXAMPLE",
            "A.LOCAL",
        );
        let sid = Some("S-1-5-21-1-1-1-1000");
        let files = vec![(
            "f".to_string(),
            file("DC01", "a.local", sid, Some(T), 1),
            vec![],
        )];
        let mut skipped = Vec::new();
        let st = apply_all(&mut g, files, Some(now), now, &mut skipped);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(st[0].matched.as_deref(), Some("DC01.CORP.EXAMPLE"));
        assert_eq!(binding(&g, a), DcSetting::Value(1));
        // Another host with that SID, or the same host in another domain, is
        // still refused.
        for f in [
            file("DC02", "a.local", sid, Some(T), 1),
            file("DC01", "b.local", sid, Some(T), 1),
        ] {
            let mut skipped = Vec::new();
            apply_all(
                &mut g,
                vec![("f".to_string(), f, vec![])],
                Some(now),
                now,
                &mut skipped,
            );
            assert_eq!(skipped.len(), 1);
        }
    }

    #[test]
    fn a_future_read_time_counts_as_none() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        g.node_mut(a).props.strongcertificatebindingenforcement = DcSetting::Value(1);
        g.node_mut(a).props.certificatemappingmethods = DcSetting::Value(0x18);
        // A clock a year ahead: it must neither beat the collection's weak
        // reading nor close anything.
        let files = vec![(
            "f".to_string(),
            file("DC01", "a.local", None, Some("2027-10-13T08:30:00Z"), 2),
            vec![],
        )];
        let st = apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert_eq!(binding(&g, a), DcSetting::Value(1));
        assert_eq!(st[0].read_at, None);
        assert_eq!(st[0].kept, [STRONG_BINDING]);
        assert!(st[0].notes.iter().any(|n| n.contains("in the future")));
        // Within a day is clock skew, not a wrong clock.
        let soon = file("DC01", "a.local", None, Some("2026-10-13T20:00:00Z"), 1);
        assert_eq!(effective_read_time(&soon, now), soon.read_time());
    }

    #[test]
    fn an_ignored_old_file_does_not_mark_a_collected_dc_stale() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        g.node_mut(a).props.strongcertificatebindingenforcement = DcSetting::Value(2);
        g.node_mut(a).props.certificatemappingmethods = DcSetting::Value(0x18);
        // No collection time, so the collection doesn't win outright; the
        // old file's strong value is ignored.
        let files = vec![(
            "f".to_string(),
            file("DC01", "a.local", None, Some("2024-01-01T00:00:00Z"), 2),
            vec![],
        )];
        let st = apply_all(&mut g, files, None, now, &mut Vec::new());
        assert_eq!(st[0].ignored, [STRONG_BINDING]);
        assert!(st[0]
            .notes
            .iter()
            .any(|n| n.contains("old settings file ignored")));
        let c = completeness(&g, now);
        assert!(c[0].stale.is_empty(), "{c:?}");
        assert!(c[0].is_complete());
    }

    #[test]
    fn each_file_is_compared_with_the_collection_on_its_own() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        g.node_mut(a).props.strongcertificatebindingenforcement = DcSetting::Value(2);
        // Both older than the collection: one with no time, one dated.
        let files = vec![
            (
                "dated".to_string(),
                file("DC01", "a.local", None, Some("2026-10-01T00:00:00Z"), 1),
                vec![],
            ),
            (
                "undated".to_string(),
                file("DC01", "a.local", None, None, 1),
                vec![],
            ),
        ];
        let st = apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert_eq!(binding(&g, a), DcSetting::Value(2));
        assert!(st
            .iter()
            .all(|s| s.applied.is_empty() && s.kept == [STRONG_BINDING]));
        // A newer file wins; an older one after it doesn't undo it.
        let files = vec![
            (
                "newer".to_string(),
                file("DC01", "a.local", None, Some("2026-10-20T00:00:00Z"), 1),
                vec![],
            ),
            (
                "older".to_string(),
                file("DC01", "a.local", None, Some("2026-10-01T00:00:00Z"), 2),
                vec![],
            ),
        ];
        // The analysis runs a week after the collection.
        let later = parse_utc("2026-10-27T00:00:00Z").unwrap();
        apply_all(&mut g, files, Some(now), later, &mut Vec::new());
        assert_eq!(binding(&g, a), DcSetting::Value(1));
    }

    #[test]
    fn a_stale_or_undated_file_shows_weaknesses_but_never_clears_them() {
        let now = parse_utc(T).unwrap();
        for (read_at, collected_at) in [
            (Some("2024-01-01T00:00:00Z"), Some(now)),
            (Some("2024-01-01T00:00:00Z"), None),
            (None, Some(now)),
            (None, None),
        ] {
            let mut g = AdGraph::new();
            let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
            let st = apply_all(
                &mut g,
                vec![(
                    "f".to_string(),
                    file("DC01", "a.local", None, read_at, 2),
                    vec![],
                )],
                collected_at,
                now,
                &mut Vec::new(),
            );
            assert_eq!(
                binding(&g, a),
                DcSetting::Unknown,
                "{read_at:?} {collected_at:?}"
            );
            assert_eq!(st[0].ignored, [STRONG_BINDING]);
            assert!(st[0]
                .notes
                .iter()
                .any(|n| n.contains("only values that show a weakness")));
            let c = completeness(&g, collected_at.unwrap_or(now));
            assert_eq!(c[0].stale, ["DC01.A.LOCAL"]);
            assert_eq!((c[0].read, c[0].from_file), (0, 0));

            let mut g = AdGraph::new();
            let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
            apply_all(
                &mut g,
                vec![(
                    "f".to_string(),
                    file("DC01", "a.local", None, read_at, 1),
                    vec![],
                )],
                collected_at,
                now,
                &mut Vec::new(),
            );
            assert_eq!(
                binding(&g, a),
                DcSetting::Value(1),
                "{read_at:?} {collected_at:?}"
            );
        }
        assert!(opens(MAPPING_METHODS, DcSetting::Value(0x1f), None));
        assert!(!opens(MAPPING_METHODS, DcSetting::Value(0x18), None));
        assert!(!opens(MAPPING_METHODS, DcSetting::NotSet, None));
        assert!(!opens(STRONG_BINDING, DcSetting::NotSet, None));
        // Unset on an unpatched DC is weak; on a patched one it is not.
        let old = OsBuild::parse("14393.1944");
        let new = OsBuild::parse("20348.4171");
        assert!(opens(MAPPING_METHODS, DcSetting::NotSet, old));
        assert!(opens(STRONG_BINDING, DcSetting::NotSet, old));
        assert!(!opens(MAPPING_METHODS, DcSetting::NotSet, new));
        assert!(!opens(STRONG_BINDING, DcSetting::NotSet, new));
    }

    fn b(s: &str) -> Option<OsBuild> {
        Some(OsBuild::parse(s).unwrap())
    }

    #[test]
    fn os_builds_parse_with_their_revision_only() {
        assert_eq!(
            OsBuild::parse("14393.1944"),
            Some(OsBuild {
                major: 14393,
                ubr: 1944
            })
        );
        assert_eq!(OsBuild::parse(" 10.0.17763.5458 "), b("17763.5458"));
        assert_eq!(OsBuild::parse("17763"), None);
        assert_eq!(OsBuild::parse("17763.x"), None);
        assert_eq!(OsBuild::parse(""), None);
        // Numeric, not text, order.
        assert!(b("14393.999") < b("14393.1944"));
    }

    /// A verdict as weak (`Some(true)`), strong or unknown.
    fn yes(v: Verdict) -> Option<bool> {
        match v {
            Verdict::Weak(_) => Some(true),
            Verdict::Strong => Some(false),
            Verdict::Unknown => None,
        }
    }

    fn kd(setting: DcSetting, build: Option<OsBuild>) -> Option<bool> {
        yes(kdc_weak_mapping(setting, build))
    }

    fn sc(setting: DcSetting, build: Option<OsBuild>) -> Option<bool> {
        yes(schannel_upn_mapping(setting, build))
    }

    #[test]
    fn weak_verdicts_say_why() {
        use DcSetting::{NotSet, Value};
        let old = b("14393.1944").unwrap();
        let mid = b("17763.5458").unwrap();
        let by = |build, update| Verdict::Weak(Weakness::Build { build, update });
        assert_eq!(
            schannel_upn_mapping(NotSet, Some(old)),
            by(old, CertUpdate::May2022)
        );
        assert_eq!(
            kdc_weak_mapping(NotSet, Some(old)),
            by(old, CertUpdate::May2022)
        );
        assert_eq!(
            kdc_weak_mapping(Value(2), Some(old)),
            by(old, CertUpdate::May2022)
        );
        assert_eq!(
            kdc_weak_mapping(NotSet, Some(mid)),
            by(mid, CertUpdate::Feb2025)
        );
        assert_eq!(
            kdc_weak_mapping(Value(1), Some(mid)),
            Verdict::Weak(Weakness::Value)
        );
        assert_eq!(
            schannel_upn_mapping(Value(0x1f), Some(old)),
            Verdict::Weak(Weakness::Value)
        );
    }

    #[test]
    fn unset_values_follow_the_patch_level() {
        use DcSetting::{NotSet, Unknown, Value};
        // First revision with the May 2022, February 2025 and September
        // 2025 changes; each is checked at the revision and one before.
        for (major, may, feb, sep) in [
            (14393, 5125, 7785, 8422),
            (17763, 2928, 6893, 7792),
            (20348, 707, 3207, 4171),
        ] {
            let at = |ubr: u32| Some(OsBuild { major, ubr });
            // Schannel: 0x1F (UPN mapping) before May 2022, 0x18 from it.
            assert_eq!(sc(NotSet, at(may - 1)), Some(true));
            assert_eq!(sc(NotSet, at(may)), Some(false));
            // Kerberos: no checks, then compatibility mode, then enforcement.
            assert_eq!(kd(NotSet, at(may - 1)), Some(true));
            assert_eq!(kd(NotSet, at(may)), Some(true));
            assert_eq!(kd(NotSet, at(feb - 1)), Some(true));
            assert_eq!(kd(NotSet, at(feb)), Some(false));
            // 0 and 1 allow weak mappings until September 2025.
            assert_eq!(kd(Value(1), at(sep - 1)), Some(true));
            assert_eq!(kd(Value(0), at(sep - 1)), Some(true));
            assert_eq!(kd(Value(1), at(sep)), Some(false));
            assert_eq!(kd(Value(2), at(feb)), Some(false));
            // Before May 2022 the KDC ignores the value.
            assert_eq!(kd(Value(2), at(may - 1)), Some(true));
            // Explicit 0x18 (no UPN bit) maps through S4U2Self/KDC: strong
            // from May 2022, weak by build before it, like the KDC.
            assert_eq!(sc(Value(0x18), at(may - 1)), Some(true));
            assert_eq!(
                schannel_upn_mapping(Value(0x18), at(may - 1)),
                Verdict::Weak(Weakness::Build {
                    build: OsBuild {
                        major,
                        ubr: may - 1
                    },
                    update: CertUpdate::May2022
                })
            );
            assert_eq!(sc(Value(0x8), at(may - 1)), Some(true));
            assert_eq!(sc(Value(0x18), at(may)), Some(false));
            // Subject/issuer only (no UPN, no S4U2Self): strong on any build.
            assert_eq!(sc(Value(0x3), at(may - 1)), Some(false));
            // An explicit UPN bit (0x4) is weak on any build.
            assert_eq!(sc(Value(0x1f), at(sep)), Some(true));
            assert_eq!(sc(Value(0x1f), at(may - 1)), Some(true));
            assert_eq!(kd(Unknown, at(1)), None);
            assert_eq!(sc(Unknown, at(1)), None);
        }
        // Server 2025 always has the May 2022 change.
        assert_eq!(sc(NotSet, b("26100.1")), Some(false));
        assert_eq!(kd(NotSet, b("26100.3193")), Some(true));
        assert_eq!(kd(NotSet, b("26100.3194")), Some(false));
        assert_eq!(kd(Value(1), b("26100.6584")), Some(false));
        // No build, or one without known updates: unset is unknown, never
        // closed; set values say what they say.
        for build in [None, b("9600.20365"), b("19042.1000")] {
            assert_eq!(sc(NotSet, build), None);
            assert_eq!(kd(NotSet, build), None);
            assert_eq!(kd(Value(1), build), Some(true));
            assert_eq!(kd(Value(2), build), Some(false));
            // No known update timeline: an explicit 0x18 is taken at face
            // value (strong); the pre-May-2022 doubt needs a known build.
            assert_eq!(sc(Value(0x18), build), Some(false));
        }
    }

    #[test]
    fn a_stale_build_opens_but_never_closes() {
        use DcSetting::{NotSet, Value};
        let dc_build = |s: &str, stale: bool| {
            Some(DcOsBuild {
                build: OsBuild::parse(s).unwrap(),
                stale,
            })
        };
        let kdc = |setting| move |b| kdc_weak_mapping(setting, b);
        let schannel = |setting| move |b| schannel_upn_mapping(setting, b);
        // Fresh: the build decides both ways.
        assert_eq!(
            yes(with_build(dc_build("14393.1944", false), kdc(NotSet))),
            Some(true)
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", false), kdc(NotSet))),
            Some(false)
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", false), kdc(Value(1)))),
            Some(false)
        );
        // Stale: it may open, not close.
        assert_eq!(
            yes(with_build(dc_build("14393.1944", true), schannel(NotSet))),
            Some(true)
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", true), schannel(NotSet))),
            None
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", true), kdc(NotSet))),
            None
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", true), kdc(Value(1)))),
            Some(true)
        );
        assert_eq!(
            yes(with_build(dc_build("20348.4171", true), kdc(Value(2)))),
            Some(false)
        );
        assert_eq!(yes(with_build(None, schannel(NotSet))), None);
    }

    #[test]
    fn the_newest_files_build_is_kept_with_its_staleness() {
        let now = parse_utc(T).unwrap();
        let with_build = |read_at: &str, build: &str| {
            let mut f = file("DC01", "a.local", None, Some(read_at), 2);
            f.dc.os_build = Some(build.into());
            f
        };
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let files = vec![
            (
                "new".to_string(),
                with_build("2026-10-01T00:00:00Z", "20348.4171"),
                vec![],
            ),
            (
                "old".to_string(),
                with_build("2024-01-01T00:00:00Z", "20348.2700"),
                vec![],
            ),
        ];
        apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert_eq!(
            g.node(a).props.os_build,
            Some(DcOsBuild {
                build: OsBuild::parse("20348.4171").unwrap(),
                stale: false
            })
        );
        // A stale file's build is marked stale; an unreadable one is noted.
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let files = vec![(
            "old".to_string(),
            with_build("2024-01-01T00:00:00Z", "14393.1944"),
            vec![],
        )];
        apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert!(g.node(a).props.os_build.unwrap().stale);
        let files = vec![(
            "bad".to_string(),
            with_build("2026-10-01T00:00:00Z", "14393"),
            vec![],
        )];
        let st = apply_all(&mut g, files, Some(now), now, &mut Vec::new());
        assert!(
            st[0].notes.iter().any(|n| n.contains("OS build '14393'")),
            "{:?}",
            st[0].notes
        );
    }

    /// A settings folder's file is untrusted unless its owner is the DC or a
    /// Tier Zero account of its forest and nobody else can change it: it
    /// can only show weaknesses, never fill toward strong, replace a value
    /// or make unset values strong with a forged build. The owner and the
    /// writers are injected through [`Sidecar::origin`], as the folder
    /// reader sets them from the opened file.
    #[test]
    fn an_unverified_folder_file_confirms_weaknesses_only() {
        let now = parse_utc(T).unwrap();
        let folder_on =
            |owner: Option<&str>, writers: &[&str], host: Option<&str>| Origin::Folder {
                security: owner.map(|o| crate::perms::FileSecurity {
                    owner: o.into(),
                    writers: writers.iter().map(|w| w.to_string()).collect(),
                }),
                share_host: host.map(Into::into),
            };
        // On the DC's own share, its SYSTEM and Administrators may write.
        let folder =
            |owner: Option<&str>| folder_on(owner, &["S-1-5-18", "S-1-5-32-544"], Some("DC01"));
        // Whether a strong file (binding 2) over a collected 1 applies.
        let clears = |origin: Origin, g: &mut AdGraph, ix: NodeIndex| {
            g.node_mut(ix).props.strongcertificatebindingenforcement = DcSetting::Value(1);
            let mut f = file("DC01", "a.local", None, Some(T), 2);
            f.origin = origin;
            apply_all(g, vec![("f".into(), f, vec![])], None, now, &mut Vec::new());
            binding(g, ix) == DcSetting::Value(2)
        };
        // The collection read binding 1 (weak); a forged current file says 2.
        let mut g = AdGraph::new();
        let a = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        g.node_mut(a).props.strongcertificatebindingenforcement = DcSetting::Value(1);
        let mut f = file("DC01", "a.local", None, Some(T), 2);
        f.origin = folder(Some("S-1-5-21-9-9-9-1105"));
        let st = apply_all(
            &mut g,
            vec![("f".into(), f, vec![])],
            None,
            now,
            &mut Vec::new(),
        );
        assert_eq!(binding(&g, a), DcSetting::Value(1));
        assert_eq!(st[0].ignored, [STRONG_BINDING]);
        assert!(st[0].from_folder && !st[0].owner_verified);
        assert!(st[0].notes.iter().any(|n| n == UNVERIFIED_NOTE));
        // A value nobody read stays unknown when the file says strong (the
        // finding stays unverified, not fixed); a weak one shows.
        let mut g = AdGraph::new();
        let b = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let mut f = file("DC01", "a.local", None, Some(T), 2);
        f.origin = folder(None);
        apply_all(
            &mut g,
            vec![("f".into(), f, vec![])],
            None,
            now,
            &mut Vec::new(),
        );
        assert_eq!(binding(&g, b), DcSetting::Unknown);
        let mut f = file("DC01", "a.local", None, Some(T), 1);
        f.origin = folder(None);
        apply_all(
            &mut g,
            vec![("f".into(), f, vec![])],
            None,
            now,
            &mut Vec::new(),
        );
        assert_eq!(binding(&g, b), DcSetting::Value(1));
        // A forged recent build doesn't make unset values strong.
        let mut g = AdGraph::new();
        let c = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let mut f = file("DC01", "a.local", None, Some(T), 2);
        f.values[0].present = false;
        f.values[0].value = None;
        f.dc.os_build = Some("20348.4171".into());
        f.origin = folder(None);
        apply_all(
            &mut g,
            vec![("f".into(), f, vec![])],
            None,
            now,
            &mut Vec::new(),
        );
        assert!(g.node(c).props.os_build.unwrap().stale);
        assert_eq!(
            verdict(&g.node(c).props, Mapping::Kerberos),
            Verdict::Unknown
        );
        // Owned by the DC itself (a SYSTEM task on it): it may clear.
        let mut g = AdGraph::new();
        let d = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        g.node_mut(d).props.strongcertificatebindingenforcement = DcSetting::Value(1);
        let mut f = file("DC01", "a.local", None, Some(T), 2);
        f.origin = folder(Some("S-1-5-21-1-1-1-1000"));
        let st = apply_all(
            &mut g,
            vec![("f".into(), f, vec![])],
            None,
            now,
            &mut Vec::new(),
        );
        assert_eq!(binding(&g, d), DcSetting::Value(2));
        assert!(st[0].owner_verified);
        let dc_sid = "S-1-5-21-1-1-1-1000";
        // The same file on a member server's share whose local SYSTEM and
        // Administrators can write: its local admins could have written it.
        let mut fs =
            crate::model::Node::placeholder("S-1-5-21-1-1-1-1105".into(), NodeKind::Computer);
        fs.placeholder = false;
        fs.name = "FS01.A.LOCAL".into();
        fs.domain = Some("A.LOCAL".into());
        g.upsert(fs);
        let local = ["S-1-5-18", "S-1-5-32-544"];
        assert!(!clears(
            folder_on(Some(dc_sid), &local, Some("FS01")),
            &mut g,
            d
        ));
        assert!(!clears(
            folder_on(Some(dc_sid), &local, Some("fs01.a.local")),
            &mut g,
            d
        ));
        // On another domain controller of the forest (Tier Zero), they may.
        dc(&mut g, "S-1-5-21-1-1-1-1002", "DC02.A.LOCAL", "A.LOCAL");
        assert!(clears(
            folder_on(Some(dc_sid), &local, Some("DC02")),
            &mut g,
            d
        ));
        // The DC's own file that Domain Users may edit in place (a share's
        // inherited Modify): anyone could have written it.
        assert!(!clears(
            folder_on(Some(dc_sid), &["S-1-5-21-1-1-1-513"], Some("FS01")),
            &mut g,
            d
        ));
        // An entry not read (an object ACE) makes it untrusted too.
        assert!(!clears(
            folder_on(Some(dc_sid), &["?"], Some("FS01")),
            &mut g,
            d
        ));
        // A bare SYSTEM or Administrators owner: only on the DC's own share.
        assert!(!clears(
            folder_on(Some("S-1-5-18"), &[], Some("FS01")),
            &mut g,
            d
        ));
        assert!(clears(
            folder_on(Some("S-1-5-18"), &[], Some("DC01")),
            &mut g,
            d
        ));
        assert!(clears(
            folder_on(Some("S-1-5-32-544"), &["S-1-5-18"], Some("dc01.a.local")),
            &mut g,
            d
        ));
        // Or by a member of Domain Admins of the DC's forest.
        let mut g = AdGraph::new();
        let e = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        let principal = |g: &mut AdGraph, sid: &str, kind: NodeKind, name: &str, domain: &str| {
            let mut n = crate::model::Node::placeholder(sid.into(), kind);
            n.placeholder = false;
            n.name = name.into();
            n.domain = Some(domain.into());
            g.upsert(n)
        };
        let admin = principal(
            &mut g,
            "S-1-5-21-1-1-1-1500",
            NodeKind::User,
            "ADMIN@A.LOCAL",
            "A.LOCAL",
        );
        let da = principal(
            &mut g,
            "S-1-5-21-1-1-1-512",
            NodeKind::Group,
            "DOMAIN ADMINS@A.LOCAL",
            "A.LOCAL",
        );
        g.add_edge(admin, da, crate::model::EdgeKind::MemberOf);
        assert!(clears(folder(Some("S-1-5-21-1-1-1-1500")), &mut g, e));
        // A child domain is the same forest; another forest's admins aren't.
        let child = principal(
            &mut g,
            "S-1-5-21-2-2-2-1500",
            NodeKind::User,
            "C@CHILD.A.LOCAL",
            "CHILD.A.LOCAL",
        );
        let child_da = principal(
            &mut g,
            "S-1-5-21-2-2-2-512",
            NodeKind::Group,
            "DOMAIN ADMINS@CHILD.A.LOCAL",
            "CHILD.A.LOCAL",
        );
        g.add_edge(child, child_da, crate::model::EdgeKind::MemberOf);
        assert!(clears(folder(Some("S-1-5-21-2-2-2-1500")), &mut g, e));
        let other = principal(
            &mut g,
            "S-1-5-21-3-3-3-1500",
            NodeKind::User,
            "O@B.OTHER",
            "B.OTHER",
        );
        let other_da = principal(
            &mut g,
            "S-1-5-21-3-3-3-512",
            NodeKind::Group,
            "DOMAIN ADMINS@B.OTHER",
            "B.OTHER",
        );
        g.add_edge(other, other_da, crate::model::EdgeKind::MemberOf);
        assert!(!clears(folder(Some("S-1-5-21-3-3-3-1500")), &mut g, e));
    }

    /// A file server's own accounts never stand for a domain principal: a
    /// bare BUILTIN\Administrators or a machine's local Administrator
    /// (RID 500 of the machine's SID) owning a file, even when the
    /// collection references them, is not Tier Zero. Nor is a read-only DC.
    #[test]
    fn local_accounts_and_rodcs_never_vouch() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        let d = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL", "A.LOCAL");
        // Referenced by ACEs, so placeholders exist for them.
        g.ensure("S-1-5-32-544", NodeKind::Group);
        g.ensure("S-1-5-21-9-9-9-500", NodeKind::User);
        // A read-only DC: not IsDC, a member of Read-only Domain
        // Controllers (521).
        let mut rodc =
            crate::model::Node::placeholder("S-1-5-21-1-1-1-1600".into(), NodeKind::Computer);
        rodc.placeholder = false;
        rodc.name = "RODC01.A.LOCAL".into();
        rodc.domain = Some("A.LOCAL".into());
        let rodc = g.upsert(rodc);
        let mut rodcs =
            crate::model::Node::placeholder("S-1-5-21-1-1-1-521".into(), NodeKind::Group);
        rodcs.placeholder = false;
        rodcs.name = "READ-ONLY DOMAIN CONTROLLERS@A.LOCAL".into();
        rodcs.domain = Some("A.LOCAL".into());
        let rodcs = g.upsert(rodcs);
        g.add_edge(rodc, rodcs, crate::model::EdgeKind::MemberOf);
        for owner in ["S-1-5-32-544", "S-1-5-21-9-9-9-500", "S-1-5-21-1-1-1-1600"] {
            assert!(
                g.lookup(owner)
                    .is_none_or(|ix| !is_tier_zero_principal(&g, ix, "A.LOCAL")),
                "{owner}"
            );
            g.node_mut(d).props.strongcertificatebindingenforcement = DcSetting::Value(1);
            let mut f = file("DC01", "a.local", None, Some(T), 2);
            f.origin = Origin::Folder {
                security: Some(crate::perms::FileSecurity {
                    owner: owner.into(),
                    writers: Vec::new(),
                }),
                share_host: Some("FS01".into()),
            };
            apply_all(
                &mut g,
                vec![("f".into(), f, vec![])],
                None,
                now,
                &mut Vec::new(),
            );
            assert_eq!(binding(&g, d), DcSetting::Value(1), "{owner}");
        }
    }

    #[test]
    fn a_folder_file_named_for_another_host_is_caught() {
        let f = file("DC01", "a.local", None, Some(T), 2);
        assert!(name_matches_host(
            "pathwarden-tierzero-DC01.a.local.json",
            &f
        ));
        assert!(name_matches_host("pathwarden-tierzero-dc01.json", &f));
        assert!(!name_matches_host(
            "pathwarden-tierzero-DC02.a.local.json",
            &f
        ));
    }

    #[test]
    fn the_tier_zero_settings_row_says_what_each_domain_still_needs() {
        let c = |missing: &[&str], stale: &[&str]| Completeness {
            domain: "CONTOSO.LOCAL".into(),
            domain_controllers: 4,
            read: 4 - missing.len(),
            from_file: 3,
            missing: missing.iter().map(|s| s.to_string()).collect(),
            stale: stale.iter().map(|s| s.to_string()).collect(),
        };
        let one = c(&[], &["DC04.CONTOSO.LOCAL"]);
        assert_eq!((one.current(), one.needing()), (3, 1));
        assert_eq!(
            one.still_needed(),
            "A newer file from DC04. Its file is over 90 days old."
        );
        // Missing because stale counts once.
        let both = c(&["DC04.CONTOSO.LOCAL"], &["DC04.CONTOSO.LOCAL"]);
        assert_eq!(both.needing(), 1);
        let more = c(
            &["DC02.CONTOSO.LOCAL"],
            &["DC03.CONTOSO.LOCAL", "DC04.CONTOSO.LOCAL"],
        );
        assert_eq!(
            more.still_needed(),
            "A newer file from DC03 and DC04. Their files are over 90 days old. A settings file from DC02."
        );
        assert_eq!(c(&[], &[]).still_needed(), "Nothing.");
        let ca = |has_file, stale, collected| CaCompleteness {
            ca: "CONTOSO-CA".into(),
            read_at: parse_utc("2026-07-14T10:00:00Z"),
            has_file,
            stale,
            collected,
        };
        assert_eq!(
            needing_words(&[one], &[ca(true, true, false), ca(false, false, false)]).1,
            "3 servers need a current settings file"
        );
        assert_eq!(
            ca(true, true, false).settings_words(),
            "Read from its settings file on Jul 14, 2026."
        );
        assert_eq!(
            ca(true, true, false).still_needed(),
            "A newer file. This one is over 90 days old."
        );
        assert_eq!(
            needing_words(&[], &[ca(false, false, true)]).1,
            "Current on every server"
        );
    }

    #[test]
    fn a_bad_read_time_is_dropped_with_a_note() {
        let bad = VALID.replace("2026-10-13T08:30:00Z", "13/10/2026 08:30");
        let mut notes = Vec::new();
        let s = Sidecar::parse(bad.as_bytes(), &mut notes).unwrap();
        assert_eq!(s.read_at, None);
        assert_eq!(notes.len(), 1);
        assert_eq!(
            parse_utc("2026-10-13T08:30:00.1234567Z"),
            parse_utc("2026-10-13T08:30:00+00:00")
        );
    }
}
