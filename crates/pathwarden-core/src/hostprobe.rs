//! The Tier Zero host probe: which management agents run on
//! the domain controllers and CA hosts, as the Tier Zero settings script
//! reads them there (schema `pathwarden.tierzero.v2`, the `agents` part).
//!
//! The directory doesn't show an SCCM client installed by hand, a SCOM agent
//! outside AD integration, the WSUS server a DC really uses, the hypervisor
//! of a virtual DC or a backup agent. The host's registry does. The script
//! reads it read-only and offline, and records presence and names only.
//!
//! A file is matched to its computer as the DC settings are
//! ([`crate::dcsettings::find_dc`]), and follows their trust rules: a file
//! read more than [`crate::dcsettings::STALE_DAYS`] days before the
//! collection (or undated), or a settings folder's file its server or a
//! Tier Zero account didn't write ([`crate::dcsettings::authoritative`]),
//! can show an agent but never show one gone.
//!
//! Each host's probe is a source of its own ([`source`]): what rests on it
//! (a server it names, a finding about its agents) carries that source, so
//! a later run without a current, trusted file from the host holds those
//! findings ("can't tell"), never calls them fixed.

use std::collections::BTreeMap;

use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

use crate::dcsettings::{self, Origin, Sidecar};
use crate::graph::AdGraph;
use crate::model::NodeKind;

/// What every host probe source's name starts with.
pub const SOURCE_PREFIX: &str = "Tier Zero host probe";

/// The source of one host's probe: `Tier Zero host probe (DC01.CONTOSO.LOCAL)`.
pub fn source(host: &str) -> String {
    format!("{SOURCE_PREFIX} ({})", host.trim().to_ascii_uppercase())
}

/// Whether a source name is a host probe's.
pub fn is_source(name: &str) -> bool {
    name.starts_with(SOURCE_PREFIX)
}

/// Most management groups, servers per group and backup agents kept.
const MAX_ITEMS: usize = 16;
/// Longest name kept (host names, site codes, service names).
const MAX_NAME: usize = 255;
/// Longest URL or error kept.
const MAX_TEXT: usize = 1024;
/// A service's `Start` value when it is disabled.
const DISABLED: i64 = 4;

/// The SCCM client: `HKLM\SOFTWARE\Microsoft\CCM`, and its site
/// (`SMS\Mobile Client` `AssignedSiteCode`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sccm {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub site_code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// One SCOM management group the agent reports to, and the
/// `Parent Health Services` `NetworkName`s it names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScomGroup {
    pub name: String,
    #[serde(default)]
    pub servers: Vec<String>,
}

/// The SCOM agent: `Agent Management Groups`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scom {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub management_groups: Vec<ScomGroup>,
    #[serde(default)]
    pub error: Option<String>,
}

/// The Windows Update policy: `WUServer`, `WUStatusServer`, `AU\UseWUServer`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wsus {
    /// The policy key exists.
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub status_server: Option<String>,
    #[serde(default)]
    pub use_wu_server: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A Hyper-V guest: `Virtual Machine\Guest\Parameters`
/// `PhysicalHostNameFullyQualified`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyperV {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A key that is there or not (VMware Tools).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub error: Option<String>,
}

/// A service and its `Start` value (the OpenSSH server, `sshd`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub start: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// One backup agent service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupAgent {
    /// Veeam, Commvault, NetBackup, DPM.
    pub product: String,
    pub service: String,
    #[serde(default)]
    pub start: Option<i64>,
}

/// The backup agent services found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub agents: Vec<BackupAgent>,
    #[serde(default)]
    pub error: Option<String>,
}

/// The `agents` part of a v2 file. A part that is missing (another
/// script) or has an error was not read: it shows nothing either way.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agents {
    #[serde(default)]
    pub sccm: Option<Sccm>,
    #[serde(default)]
    pub scom: Option<Scom>,
    #[serde(default)]
    pub wsus: Option<Wsus>,
    #[serde(default)]
    pub hyperv: Option<HyperV>,
    #[serde(default)]
    pub vmware: Option<Presence>,
    #[serde(default)]
    pub sshd: Option<Service>,
    #[serde(default)]
    pub backup: Option<Backup>,
}

/// A name from a shared file: trimmed, plain and short, else dropped.
fn clean_name(v: &mut Option<String>, what: &str, notes: &mut Vec<String>) {
    if let Some(s) = v {
        let t = s.trim().to_string();
        if t.is_empty() || !dcsettings::plain(&t, MAX_NAME) {
            if notes.len() < 20 {
                notes.push(format!("a malformed {what} in the agents part was skipped"));
            }
            *v = None;
        } else {
            *s = t;
        }
    }
}

fn clean_text(v: &mut Option<String>, max: usize) {
    if let Some(s) = v {
        if s.len() > max || !dcsettings::plain(s, max) {
            *s = s
                .chars()
                .filter(|c| !c.is_control())
                .take(max / 4)
                .collect();
        }
    }
}

impl Agents {
    /// Drops what a shared file can't be trusted to hold: names that are
    /// too long or hold control characters, and lists past their caps.
    pub(crate) fn check(&mut self, notes: &mut Vec<String>) {
        if let Some(p) = &mut self.sccm {
            clean_name(&mut p.site_code, "site code", notes);
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.scom {
            if p.management_groups.len() > MAX_ITEMS {
                p.management_groups.truncate(MAX_ITEMS);
                notes.push("more SCOM management groups than Pathwarden reads".into());
            }
            p.management_groups.retain_mut(|mg| {
                mg.name = mg.name.trim().to_string();
                mg.servers.truncate(MAX_ITEMS);
                mg.servers = mg
                    .servers
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && dcsettings::plain(s, MAX_NAME))
                    .collect();
                !mg.name.is_empty() && dcsettings::plain(&mg.name, MAX_NAME)
            });
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.wsus {
            clean_text(&mut p.server, MAX_TEXT);
            clean_text(&mut p.status_server, MAX_TEXT);
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.hyperv {
            clean_name(&mut p.host, "Hyper-V host name", notes);
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.vmware {
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.sshd {
            clean_text(&mut p.error, MAX_TEXT);
        }
        if let Some(p) = &mut self.backup {
            p.agents.truncate(MAX_ITEMS);
            p.agents.retain(|a| {
                !a.product.trim().is_empty()
                    && dcsettings::plain(&a.product, MAX_NAME)
                    && dcsettings::plain(&a.service, MAX_NAME)
            });
            clean_text(&mut p.error, MAX_TEXT);
        }
    }

    /// The parts not read: missing, or read with an error.
    pub fn unread(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut part = |name, err: Option<&Option<String>>| match err {
            None | Some(Some(_)) => out.push(name),
            Some(None) => {}
        };
        part("SCCM", self.sccm.as_ref().map(|p| &p.error));
        part("SCOM", self.scom.as_ref().map(|p| &p.error));
        part("WSUS", self.wsus.as_ref().map(|p| &p.error));
        part("Hyper-V", self.hyperv.as_ref().map(|p| &p.error));
        part("VMware Tools", self.vmware.as_ref().map(|p| &p.error));
        part("sshd", self.sshd.as_ref().map(|p| &p.error));
        part("backup agents", self.backup.as_ref().map(|p| &p.error));
        out
    }

    /// The SCCM client is installed: `Some(site code)`.
    pub fn sccm_client(&self) -> Option<Option<&str>> {
        self.sccm
            .as_ref()
            .filter(|p| p.present && p.error.is_none())
            .map(|p| p.site_code.as_deref())
    }

    /// The SCOM agent is installed: its (management group, server) pairs.
    pub fn scom_agent(&self) -> Option<Vec<(&str, &str)>> {
        let p = self
            .scom
            .as_ref()
            .filter(|p| p.present && p.error.is_none())?;
        Some(
            p.management_groups
                .iter()
                .flat_map(|mg| mg.servers.iter().map(|s| (mg.name.as_str(), s.as_str())))
                .collect(),
        )
    }

    /// The WSUS URLs Windows Update uses: `WUServer` and `WUStatusServer`
    /// when `UseWUServer` is 1.
    pub fn wsus_urls(&self) -> Vec<&str> {
        let Some(p) = self
            .wsus
            .as_ref()
            .filter(|p| p.present && p.error.is_none() && p.use_wu_server == Some(1))
        else {
            return Vec::new();
        };
        let mut out: Vec<&str> = Vec::new();
        for u in [&p.server, &p.status_server].into_iter().flatten() {
            if !u.trim().is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(u.trim())) {
                out.push(u.trim());
            }
        }
        out
    }

    /// A Hyper-V guest: `Some(its host's name)`.
    pub fn hyper_v_guest(&self) -> Option<Option<&str>> {
        self.hyperv
            .as_ref()
            .filter(|p| p.present && p.error.is_none())
            .map(|p| p.host.as_deref())
    }

    pub fn vmware_tools(&self) -> bool {
        self.vmware
            .as_ref()
            .is_some_and(|p| p.present && p.error.is_none())
    }

    /// The OpenSSH server is installed and not disabled.
    pub fn sshd(&self) -> bool {
        self.sshd
            .as_ref()
            .is_some_and(|p| p.present && p.error.is_none() && p.start != Some(DISABLED))
    }

    /// The backup agent services that are not disabled.
    pub fn backup_agents(&self) -> Vec<&BackupAgent> {
        self.backup
            .as_ref()
            .filter(|p| p.error.is_none())
            .map(|p| {
                p.agents
                    .iter()
                    .filter(|a| a.start != Some(DISABLED))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether `part` was read: there, and without an error.
    pub fn part_read(&self, part: Part) -> bool {
        let err = match part {
            Part::Sccm => self.sccm.as_ref().map(|p| &p.error),
            Part::Scom => self.scom.as_ref().map(|p| &p.error),
            Part::Wsus => self.wsus.as_ref().map(|p| &p.error),
            Part::HyperV => self.hyperv.as_ref().map(|p| &p.error),
            Part::Vmware => self.vmware.as_ref().map(|p| &p.error),
            Part::Sshd => self.sshd.as_ref().map(|p| &p.error),
            Part::Backup => self.backup.as_ref().map(|p| &p.error),
        };
        matches!(err, Some(None))
    }

    /// What `part` shows, in short words for the completeness row: "SCCM
    /// client (site P01)", "VMware Tools".
    pub fn found_part(&self, part: Part) -> Vec<String> {
        let mut out = Vec::new();
        match part {
            Part::Sccm => match self.sccm_client() {
                Some(Some(site)) => out.push(format!("SCCM client (site {site})")),
                Some(None) => out.push("SCCM client".into()),
                None => {}
            },
            Part::Scom if self.scom_agent().is_some() => out.push("SCOM agent".into()),
            Part::Wsus if !self.wsus_urls().is_empty() => out.push("WSUS".into()),
            Part::HyperV if self.hyper_v_guest().is_some() => out.push("Hyper-V guest".into()),
            Part::Vmware if self.vmware_tools() => out.push("VMware Tools".into()),
            Part::Sshd if self.sshd() => out.push("SSH server".into()),
            Part::Backup => {
                for a in self.backup_agents() {
                    let p = format!("{} backup agent", a.product);
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
            _ => {}
        }
        out
    }

    /// What it found ([`Self::found_part`] of every part).
    pub fn found(&self) -> Vec<String> {
        Part::ALL.iter().flat_map(|&p| self.found_part(p)).collect()
    }
}

/// One file's agents, applied to the computer it describes.
#[derive(Debug, Clone)]
pub struct HostProbe {
    pub host: NodeIndex,
    /// The file's label.
    pub file: String,
    pub read_at: Option<i64>,
    /// Read more than [`dcsettings::STALE_DAYS`] days before the
    /// collection, or undated.
    pub stale: bool,
    /// Given with the collection, or a settings folder's verified file.
    pub trusted: bool,
    pub agents: Agents,
}

impl HostProbe {
    /// It may show an agent gone: current and trusted.
    pub fn clears(&self) -> bool {
        self.trusted && !self.stale
    }
}

/// Ingest statistics for one file's agents part.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeStats {
    pub file: String,
    /// The host as the file names it.
    pub host: String,
    /// The computer it was matched to.
    #[serde(default)]
    pub matched: Option<String>,
    #[serde(default)]
    pub read_at: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_folder: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_verified: bool,
    /// What it found ([`Agents::found`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub found: Vec<String>,
    /// The parts it couldn't read ([`Agents::unread`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unread: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Applies the files' agents parts to their computers. Runs with the DC
/// and CA settings, after every AD file is read.
pub(crate) fn apply(
    g: &mut AdGraph,
    files: &[(String, Sidecar, Vec<String>)],
    collected_at: Option<i64>,
    now: i64,
    skipped: &mut Vec<String>,
) -> Vec<ProbeStats> {
    let mut out = Vec::new();
    for (label, s, _) in files {
        let Some(agents) = &s.agents else { continue };
        let read_at = dcsettings::effective_read_time(s, now);
        let mut st = ProbeStats {
            file: label.clone(),
            host: s.dns_name(),
            read_at,
            from_folder: matches!(s.origin, Origin::Folder { .. }),
            found: agents.found(),
            unread: agents.unread().into_iter().map(String::from).collect(),
            ..ProbeStats::default()
        };
        let ix = match dcsettings::find_dc(g, s) {
            Ok(ix) => ix,
            Err(why) => {
                // The DC and CA settings report a file they couldn't match.
                if s.values.is_empty() && s.cas.is_empty() {
                    skipped.push(format!("{label} (Tier Zero settings: {why})"));
                }
                out.push(st);
                continue;
            }
        };
        st.matched = Some(g.node(ix).name.clone());
        let stale = dcsettings::is_stale(read_at, collected_at, now);
        let trusted = dcsettings::authoritative(g, s, &[ix]);
        st.stale = stale;
        st.owner_verified = st.from_folder && trusted;
        if !trusted {
            st.notes.push(
                "its management agents can show an agent, not show one gone: it is from a \
                 settings folder, and its owner or permissions don't show that only the server \
                 or a Tier Zero account wrote it"
                    .into(),
            );
        }
        if stale {
            st.notes.push(format!(
                "its management agents can show an agent, not show one gone: it is over {} days \
                 old, or undated",
                dcsettings::STALE_DAYS
            ));
        }
        g.add_host_probe(HostProbe {
            host: ix,
            file: label.clone(),
            read_at,
            stale,
            trusted,
            agents: agents.clone(),
        });
        out.push(st);
    }
    out
}

/// How far a Tier Zero host's management agents are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A current, trusted file read every part.
    Read,
    /// A current, trusted file, with parts it couldn't read.
    Partial,
    /// Only files over 90 days old (or undated).
    Stale,
    /// Only settings folder files nobody vouches for.
    Unverified,
    /// No file with an agents part.
    None,
}

impl Status {
    /// The words of the completeness row.
    pub fn words(self) -> &'static str {
        match self {
            Status::Read => "Read",
            Status::Partial => "Read in part",
            Status::Stale => "File over 90 days old",
            Status::Unverified => "Unverified file",
            Status::None => "No file",
        }
    }
}

/// One part of the agents a file reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Part {
    Sccm,
    Scom,
    Wsus,
    HyperV,
    Vmware,
    Sshd,
    Backup,
}

impl Part {
    pub const ALL: [Part; 7] = [
        Part::Sccm,
        Part::Scom,
        Part::Wsus,
        Part::HyperV,
        Part::Vmware,
        Part::Sshd,
        Part::Backup,
    ];
}

/// What the files say of one host, part by part.
#[derive(Debug, Clone)]
pub struct View<'a> {
    pub status: Status,
    /// Every file, oldest first.
    pub files: Vec<&'a HostProbe>,
    /// Per part, the files used: the newest current, trusted file that read
    /// it and any newer file that read it (which can only show an agent);
    /// without such a file, every file that read it. An older trusted file
    /// stays in use for a part a newer one couldn't read.
    used: BTreeMap<Part, Vec<&'a HostProbe>>,
}

impl<'a> View<'a> {
    /// Every answer to `part`, deduplicated, with whether a current,
    /// trusted file gives it (only then may it make a server Tier Zero).
    pub fn answers<T: PartialEq>(
        &self,
        part: Part,
        f: impl Fn(&'a Agents) -> Vec<T>,
    ) -> Vec<(T, bool)> {
        let mut out: Vec<(T, bool)> = Vec::new();
        for p in self.used.get(&part).into_iter().flatten() {
            for x in f(&p.agents) {
                match out.iter_mut().find(|(y, _)| *y == x) {
                    Some((_, t)) => *t |= p.clears(),
                    None => out.push((x, p.clears())),
                }
            }
        }
        out
    }

    /// Whether a file used for `part` says `f`.
    pub fn any(&self, part: Part, f: impl Fn(&Agents) -> bool) -> bool {
        self.used
            .get(&part)
            .is_some_and(|v| v.iter().any(|p| f(&p.agents)))
    }

    /// Whether a current, trusted file used for `part` says `f`.
    pub fn trusted(&self, part: Part, f: impl Fn(&Agents) -> bool) -> bool {
        self.used
            .get(&part)
            .is_some_and(|v| v.iter().any(|p| p.clears() && f(&p.agents)))
    }

    /// The newest file.
    pub fn newest(&self) -> Option<&'a HostProbe> {
        self.files.iter().max_by_key(|p| p.read_at).copied()
    }

    /// What the files used show ([`Agents::found_part`]).
    /// For a host a current, trusted file reads, only what such files show:
    /// an unverified file doesn't show in the row.
    pub fn found(&self) -> Vec<String> {
        let trusted_only = matches!(self.status, Status::Read | Status::Partial);
        Part::ALL
            .iter()
            .flat_map(|&part| {
                self.answers(part, |a| a.found_part(part))
                    .into_iter()
                    .filter(move |(_, t)| *t || !trusted_only)
                    .map(|(x, _)| x)
            })
            .collect()
    }

    /// When the row says it was read: the newest current, trusted file's
    /// read time for a host such a file reads, else the newest file's.
    pub fn read_at(&self) -> Option<i64> {
        if matches!(self.status, Status::Read | Status::Partial) {
            self.files
                .iter()
                .filter(|p| p.clears())
                .filter_map(|p| p.read_at)
                .max()
        } else {
            self.newest().and_then(|p| p.read_at)
        }
    }
}

/// Per host with a file: what its files say ([`View`]).
pub fn views(g: &AdGraph) -> BTreeMap<NodeIndex, View<'_>> {
    let mut by_host: BTreeMap<NodeIndex, Vec<&HostProbe>> = BTreeMap::new();
    for p in g.host_probes() {
        by_host.entry(p.host).or_default().push(p);
    }
    by_host
        .into_iter()
        .map(|(host, mut files)| {
            files.sort_by_key(|p| p.read_at);
            let mut used: BTreeMap<Part, Vec<&HostProbe>> = BTreeMap::new();
            let mut cleared = 0;
            for part in Part::ALL {
                let read: Vec<&HostProbe> = files
                    .iter()
                    .copied()
                    .filter(|p| p.agents.part_read(part))
                    .collect();
                let best = read.iter().rev().find(|p| p.clears()).copied();
                let list: Vec<&HostProbe> = match best {
                    Some(b) => {
                        cleared += 1;
                        read.into_iter()
                            .filter(|p| p.read_at >= b.read_at)
                            .collect()
                    }
                    None => read,
                };
                used.insert(part, list);
            }
            let status = if cleared == Part::ALL.len() {
                Status::Read
            } else if cleared > 0 {
                Status::Partial
            } else if files.iter().any(|p| p.trusted) {
                Status::Stale
            } else {
                Status::Unverified
            };
            (
                host,
                View {
                    status,
                    files,
                    used,
                },
            )
        })
        .collect()
}

/// Every Tier Zero host's probe source, and whether this run read it in
/// full from a current, trusted file: what holds the findings that rest
/// on it ([`crate::opengraph::coverage::RunSources`]).
pub fn coverage(g: &AdGraph) -> Vec<(String, bool)> {
    let views = views(g);
    let mut hosts: Vec<NodeIndex> = crate::mgmt::tier_zero_hosts(g).into_iter().collect();
    hosts.extend(views.keys().copied());
    hosts.sort_unstable();
    hosts.dedup();
    hosts
        .into_iter()
        .filter(|&ix| !g.node(ix).placeholder)
        .map(|ix| {
            let read = views.get(&ix).is_some_and(|v| v.status == Status::Read);
            (source(&g.node(ix).name), read)
        })
        .collect()
}

/// One Tier Zero host's management agents, for the completeness row.
#[derive(Debug, Clone, Serialize)]
pub struct HostAgents {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// A domain controller (else a CA host).
    pub dc: bool,
    pub status: Status,
    /// When its newest file used was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
    /// What its files show ([`Agents::found`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub found: Vec<String>,
}

impl HostAgents {
    /// How its agents were read, in the report's words: "Read on Oct 29,
    /// 2026.", "No settings file yet.".
    pub fn read_words(&self) -> String {
        let day = self.read_at.map(crate::time::format_day);
        match (self.status, day) {
            (Status::None, _) => "No settings file yet.".into(),
            (Status::Read, Some(d)) => format!("Read on {d}."),
            (Status::Partial, Some(d)) => format!("Read in part on {d}."),
            (Status::Stale, Some(d)) => format!(
                "Its file is from {d}, over {} days old.",
                dcsettings::STALE_DAYS
            ),
            (Status::Unverified, Some(d)) => format!(
                "Its file from {d} is from a settings folder, and nothing shows who wrote it."
            ),
            (Status::Stale, None) => "Its file has no date.".into(),
            (Status::Unverified, None) => {
                "Its file is from a settings folder, and nothing shows who wrote it.".into()
            }
            (_, None) => "Read.".into(),
        }
    }

    /// What its files show: "SCCM client (site P01), VMware Tools.", or
    /// "None." when they show none; empty without a file.
    pub fn found_words(&self) -> String {
        match (self.status, self.found.is_empty()) {
            (Status::None, _) => String::new(),
            (_, true) => "None.".into(),
            (_, false) => format!("{}.", self.found.join(", ")),
        }
    }
}

/// The completeness row: "Management agents read on Tier Zero hosts: n of
/// m". Empty when the run read no Tier Zero settings file at all (then the
/// Tier Zero settings row says what is missing) or has no Tier Zero host.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Completeness {
    pub hosts: Vec<HostAgents>,
}

impl Completeness {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Hosts whose agents were read in full from a current, trusted file.
    pub fn read(&self) -> usize {
        self.hosts
            .iter()
            .filter(|h| h.status == Status::Read)
            .count()
    }

    /// "3 of 4": the row's aside.
    pub fn count_words(&self) -> String {
        format!("{} of {}", self.read(), self.hosts.len())
    }

    /// Some host isn't read.
    pub fn short(&self) -> bool {
        self.read() < self.hosts.len()
    }

    /// "Management agents read on Tier Zero hosts: 3 of 4".
    pub fn line(&self) -> String {
        format!("{TITLE}: {}", self.count_words())
    }

    /// The hosts the row lists, and how many hosts with no settings file it
    /// leaves out: every host with a file, then hosts without one up to
    /// [`ROWS`] in all.
    pub fn shown(&self) -> (Vec<&HostAgents>, usize) {
        let mut out: Vec<&HostAgents> = Vec::new();
        let mut left = 0;
        let filed = self
            .hosts
            .iter()
            .filter(|h| h.status != Status::None)
            .count();
        let mut room = ROWS.saturating_sub(filed);
        for h in &self.hosts {
            if h.status != Status::None {
                out.push(h);
            } else if room > 0 {
                room -= 1;
                out.push(h);
            } else {
                left += 1;
            }
        }
        (out, left)
    }
}

/// The completeness row's title, and the posture line's words.
pub const TITLE: &str = "Management agents read on Tier Zero computers";
/// The row's intro line.
pub const INTRO: &str = "Whoever controls the server of an agent on a Tier Zero computer can run code there, so that server is Tier Zero too.";
/// The ⓘ of the row.
pub const TIP: &str = "The same settings files read them: have each server's admins run Get-PathwardenTierZeroSettings.ps1. A computer counts as read only when current files read every agent. A file older than 90 days, or one from a settings folder that nothing shows who wrote, can show an agent but can't show one gone.";
/// Rows the completeness row lists at least (hosts without a file fill up
/// to it).
pub const ROWS: usize = 5;

/// "5 more hosts with no settings file yet."
pub fn more_words(n: usize) -> Option<String> {
    match n {
        0 => None,
        1 => Some("1 more computer with no settings file yet.".into()),
        n => Some(format!("{n} more computers with no settings file yet.")),
    }
}

/// [`Completeness`] for the run.
pub fn completeness(g: &AdGraph) -> Completeness {
    let any_file = !g.host_probes().is_empty()
        || !g.dc_settings_files().is_empty()
        || !g.ca_settings_files().is_empty();
    if !any_file {
        return Completeness::default();
    }
    let views = views(g);
    let mut hosts: Vec<HostAgents> = crate::mgmt::tier_zero_hosts(g)
        .into_iter()
        .filter(|&ix| {
            let n = g.node(ix);
            n.kind == NodeKind::Computer && !n.placeholder
        })
        .map(|ix| {
            let n = g.node(ix);
            let v = views.get(&ix);
            HostAgents {
                host: n.name.clone(),
                domain: n.domain.clone(),
                dc: n.is_dc,
                status: v.map_or(Status::None, |v| v.status),
                read_at: v.and_then(|v| v.read_at()),
                found: v.map(|v| v.found()).unwrap_or_default(),
            }
        })
        .collect();
    hosts.sort_by(|a, b| (!a.dc, &a.host).cmp(&(!b.dc, &b.host)));
    Completeness { hosts }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcsettings::{parse_utc, DcInfo, SCHEMA_V2};

    const T: &str = "2026-10-13T08:30:00Z";

    fn dc(g: &mut AdGraph, sid: &str, name: &str) -> NodeIndex {
        let mut n = crate::model::Node::placeholder(sid.into(), NodeKind::Computer);
        n.placeholder = false;
        n.is_dc = true;
        n.name = name.into();
        n.domain = Some("A.LOCAL".into());
        g.upsert(n)
    }

    fn agents(vmware: bool) -> Agents {
        Agents {
            sccm: Some(Sccm::default()),
            scom: Some(Scom::default()),
            wsus: Some(Wsus::default()),
            hyperv: Some(HyperV::default()),
            vmware: Some(Presence {
                present: vmware,
                error: None,
            }),
            sshd: Some(Service::default()),
            backup: Some(Backup::default()),
        }
    }

    fn file(read_at: &str, origin: Origin, vmware: bool) -> Sidecar {
        Sidecar {
            schema: SCHEMA_V2.into(),
            domain: "a.local".into(),
            dc: DcInfo {
                hostname: "DC01".into(),
                ..DcInfo::default()
            },
            read_at: Some(read_at.into()),
            agents: Some(agents(vmware)),
            origin,
            ..Sidecar::default()
        }
    }

    fn folder(owner: &str) -> Origin {
        Origin::Folder {
            security: Some(crate::perms::FileSecurity {
                owner: owner.into(),
                writers: vec!["S-1-5-18".into(), "S-1-5-32-544".into()],
            }),
            share_host: Some("DC01".into()),
        }
    }

    fn status(files: Vec<Sidecar>) -> (Status, bool, bool) {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        let ix = dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL");
        let files: Vec<(String, Sidecar, Vec<String>)> = files
            .into_iter()
            .enumerate()
            .map(|(i, s)| (format!("f{i}"), s, Vec::new()))
            .collect();
        apply(&mut g, &files, Some(now), now, &mut Vec::new());
        let v = views(&g);
        let cov = coverage(&g);
        assert_eq!(cov[0].0, "Tier Zero host probe (DC01.A.LOCAL)");
        let view = &v[&ix];
        (
            view.status,
            cov[0].1,
            view.any(Part::Vmware, Agents::vmware_tools),
        )
    }

    #[test]
    fn only_a_current_trusted_file_reads_a_host() {
        let old = "2024-01-01T00:00:00Z";
        assert_eq!(
            status(vec![file(T, Origin::Collection, false)]),
            (Status::Read, true, false)
        );
        // Stale: it shows VMware Tools, but the host isn't read.
        assert_eq!(
            status(vec![file(old, Origin::Collection, true)]),
            (Status::Stale, false, true)
        );
        // A folder file a plain user owns: the same.
        assert_eq!(
            status(vec![file(T, folder("S-1-5-21-9-9-9-1105"), true)]),
            (Status::Unverified, false, true)
        );
        // The DC's own folder file is trusted.
        assert_eq!(
            status(vec![file(T, folder("S-1-5-21-1-1-1-1000"), false)]),
            (Status::Read, true, false)
        );
        // A current trusted file supersedes an old one that showed an agent.
        assert_eq!(
            status(vec![
                file(old, Origin::Collection, true),
                file(T, Origin::Collection, false)
            ]),
            (Status::Read, true, false)
        );
        // A newer unverified file still shows what it shows.
        let newer = "2026-10-14T08:30:00Z";
        assert_eq!(
            status(vec![
                file(T, Origin::Collection, false),
                file(newer, folder("S-1-5-21-9-9-9-1105"), true)
            ]),
            (Status::Read, true, true)
        );
        // A part not read: read in part, so it holds.
        let mut partial = file(T, Origin::Collection, false);
        partial.agents.as_mut().unwrap().scom = Some(Scom {
            error: Some("Access is denied".into()),
            ..Scom::default()
        });
        assert_eq!(status(vec![partial]), (Status::Partial, false, false));
    }

    /// The script's own output (run against an in-memory registry, with
    /// every agent present and DPM's service disabled) parses as it says.
    #[test]
    fn the_scripts_file_parses() {
        let text =
            include_str!("../tests/fixtures/tierzero/pathwarden-tierzero-DC01.contoso.local.json");
        let mut notes = Vec::new();
        let s = Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(s.schema, SCHEMA_V2);
        assert_eq!(s.value(dcsettings::STRONG_BINDING).unwrap().value, Some(2));
        let a = s.agents.unwrap();
        assert!(a.unread().is_empty(), "{:?}", a.unread());
        assert_eq!(a.sccm_client(), Some(Some("P01")));
        assert_eq!(
            a.scom_agent().unwrap(),
            [
                ("MG1", "scom01.contoso.local"),
                ("MG1", "scom02.contoso.local"),
                ("MG2", "gw01.contoso.local")
            ]
        );
        assert_eq!(a.wsus_urls(), ["http://wsus01.contoso.local:8530"]);
        assert_eq!(a.hyper_v_guest(), Some(Some("hv01.contoso.local")));
        assert!(a.vmware_tools() && a.sshd());
        assert_eq!(
            a.found(),
            [
                "SCCM client (site P01)",
                "SCOM agent",
                "WSUS",
                "Hyper-V guest",
                "VMware Tools",
                "SSH server",
                "Veeam backup agent",
                "Commvault backup agent"
            ]
        );
    }

    /// A read host's row shows only what current, trusted files say, and
    /// their date: a newer unverified file doesn't show in it.
    #[test]
    fn a_read_hosts_row_shows_only_trusted_files() {
        let now = parse_utc(T).unwrap();
        let mut g = AdGraph::new();
        dc(&mut g, "S-1-5-21-1-1-1-1000", "DC01.A.LOCAL");
        let files = vec![
            (
                "a".to_string(),
                file(T, Origin::Collection, false),
                Vec::new(),
            ),
            (
                "b".to_string(),
                file("2026-10-14T08:30:00Z", folder("S-1-5-21-9-9-9-1105"), true),
                Vec::new(),
            ),
        ];
        let later = parse_utc("2026-10-15T00:00:00Z").unwrap();
        apply(&mut g, &files, Some(now), later, &mut Vec::new());
        let c = completeness(&g);
        assert_eq!(c.hosts[0].status, Status::Read);
        assert_eq!(c.hosts[0].read_words(), "Read on Oct 13, 2026.");
        assert_eq!(c.hosts[0].found_words(), "None.");
    }

    #[test]
    fn the_row_lists_every_filed_host_then_fills_to_five() {
        let host = |n: usize, status: Status| HostAgents {
            host: format!("DC{n:02}"),
            domain: None,
            dc: true,
            status,
            read_at: None,
            found: Vec::new(),
        };
        let mut c = Completeness {
            hosts: (0..10)
                .map(|n| host(n, if n < 3 { Status::Read } else { Status::None }))
                .collect(),
        };
        let (shown, left) = c.shown();
        assert_eq!((shown.len(), left), (5, 5));
        assert_eq!(c.count_words(), "3 of 10");
        assert!(c.short());
        assert_eq!(
            more_words(left).as_deref(),
            Some("5 more computers with no settings file yet.")
        );
        assert_eq!(
            more_words(1).as_deref(),
            Some("1 more computer with no settings file yet.")
        );
        // Many filed hosts: all listed.
        c.hosts = (0..7).map(|n| host(n, Status::Stale)).collect();
        assert_eq!(c.shown().0.len(), 7);
        assert_eq!(c.hosts[0].read_words(), "Its file has no date.");
    }

    #[test]
    fn a_v1_file_never_has_agents_and_names_are_checked() {
        let v1 = r#"{"schema": "pathwarden.tierzero.v1", "domain": "a.local",
            "dc": {"hostname": "DC01"}, "values": [],
            "agents": {"vmware": {"present": true}}}"#;
        let mut notes = Vec::new();
        let s = Sidecar::parse(v1.as_bytes(), &mut notes).unwrap();
        assert!(s.agents.is_none());
        assert!(notes[0].contains("no management agents part"), "{notes:?}");
        let v2 = r#"{"schema": "pathwarden.tierzero.v2", "domain": "a.local",
            "dc": {"hostname": "DC01"}, "values": [],
            "agents": {"hyperv": {"present": true, "host": "hv\u0001.a.local"},
                       "scom": {"present": true, "management_groups": [
                           {"name": "MG", "servers": [" scom01.a.local ", "bad\u0007"]}]},
                       "wsus": {"present": true, "server": "http://wsus01:8530",
                                "status_server": "HTTP://WSUS01:8530", "use_wu_server": 1}}}"#;
        let mut notes = Vec::new();
        let s = Sidecar::parse(v2.as_bytes(), &mut notes).unwrap();
        let a = s.agents.unwrap();
        assert_eq!(a.hyper_v_guest(), Some(None));
        assert_eq!(a.scom_agent().unwrap(), [("MG", "scom01.a.local")]);
        assert_eq!(a.wsus_urls(), ["http://wsus01:8530"]);
        // Parts the file doesn't have were not read.
        assert_eq!(
            a.unread(),
            ["SCCM", "VMware Tools", "sshd", "backup agents"]
        );
    }
}
