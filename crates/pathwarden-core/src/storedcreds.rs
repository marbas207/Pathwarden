//! Domain accounts whose password a computer stores: a service that
//! runs as a domain account keeps that account's password in the host's
//! LSA secrets, and a scheduled task set to run whether the user is logged
//! on or not keeps it in the host's task credential store. Any
//! administrator of the host can read either. So administering the host is
//! control of the account.
//!
//! Pathwarden's built-in collector reads, in a Full collection over
//! Kerberos, each reached computer's `HKLM\SYSTEM\CurrentControlSet\Services`
//! keys (only their `ObjectName`, `Start` and `Type` values) and the task
//! files under `C$\Windows\System32\Tasks` (only each task's principal,
//! logon type and enabled flag). It writes the services and tasks that
//! store a domain account's password to `pathwarden-storedcreds.json` in
//! its zip (schema `pathwarden.storedcreds.v1`), with each computer's
//! status for each (collected, partly collected, not collected and why). It
//! never reads a password, a secret, `ImagePath`, `Parameters` or a task's
//! actions, and the file has no place for one.
//!
//! - **`HasStoredCredential`** (computer → user): the computer stores the
//!   account's password. Traversable, cost 2, and the fix is "stop storing
//!   it here". Group managed service accounts (and other `name$` accounts),
//!   virtual and local accounts get no edge.
//! - **PW-033** reports a Tier Zero account stored on a computer outside
//!   Tier Zero, one finding per account (with TaskHound's data too).
//! - Each computer is a coverage unit of the domain's two sources ("Stored
//!   credentials in services (DOMAIN)", "Stored credentials in scheduled
//!   tasks (DOMAIN)"): a finding is marked fixed only when every computer
//!   that held the credential was read again in full, by each source that
//!   found it there.
//!
//! The file also carries the forest's NetBIOS domain names (from
//! `CN=Partitions`), so `DOMAIN\user` resolves, for TaskHound's run-as
//! accounts too.

use std::collections::{BTreeMap, HashMap};

use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

use crate::graph::AdGraph;
use crate::model::{EdgeKind, NodeKind};
use crate::opengraph::EdgeOrigin;
use crate::sysvol::{Check, CheckStatus};

pub const SCHEMA: &str = "pathwarden.storedcreds.v1";
/// The file name the collector writes (in its zip).
pub const FILE_NAME: &str = "pathwarden-storedcreds.json";
/// Largest sidecar read.
pub const MAX_SIDECAR_BYTES: u64 = 64 << 20;

/// Caps on what one sidecar may list. Real domains stay far below them.
const MAX_HOSTS: usize = 500_000;
const MAX_STORED_PER_HOST: usize = 1024;
const MAX_STORED: usize = 2_000_000;
const MAX_NETBIOS: usize = 4096;
/// Longest name kept (service, account, host); longer ones are cut.
pub const MAX_TEXT: usize = 256;
/// Most service names one edge keeps, for its path step and fix.
pub const MAX_NAMES_PER_EDGE: usize = 64;
/// Notes kept per sidecar in the ingest statistics.
const MAX_NOTES: usize = 20;

/// Whether a file name is a stored credentials sidecar's
/// (`pathwarden-storedcreds.json`, or anything ending in it).
pub fn is_sidecar_name(label: &str) -> bool {
    let name = label
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(label)
        .to_ascii_lowercase();
    name.ends_with(FILE_NAME)
}

/// The sidecar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema: String,
    /// DNS name of the collected domain.
    pub domain: String,
    /// The forest's domains by NetBIOS name.
    #[serde(default)]
    pub netbios: Vec<NetbiosName>,
    /// The services step as a whole: complete when every reached computer
    /// was read in full.
    #[serde(default)]
    pub services: Check,
    /// The reads were turned off (`--no-service-reads`, `[collect]
    /// service_reads = false`): `services` is not collected, by choice.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turned_off: bool,
    /// The scheduled tasks step as a whole (slice 2). `None` in a file
    /// from before tasks were read: the run then has no tasks source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Check>,
    /// The task reads were turned off (`--no-task-reads`, `[collect]
    /// task_reads = false`): `tasks` is not collected, by choice.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tasks_turned_off: bool,
    /// The computers the steps were for, read or not.
    #[serde(default)]
    pub hosts: Vec<HostRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetbiosName {
    pub dns: String,
    pub netbios: String,
}

/// One computer: how far its services were read, and those that store a
/// domain account's password.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostRecord {
    /// The computer's ObjectIdentifier (its SID).
    pub id: String,
    /// Its DNS name, for messages.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub services: Check,
    /// How far its scheduled tasks were read. `None` when the file has no
    /// tasks step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Check>,
    #[serde(default)]
    pub stored: Vec<Stored>,
}

/// What stores the credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    #[default]
    Service,
    /// A scheduled task (slice 2).
    Task,
    /// A kind a later version writes and this one doesn't know: its
    /// entries are dropped while the file is read, so new kinds stay
    /// additive.
    #[serde(other)]
    Unknown,
}

impl Via {
    pub fn label(self) -> &'static str {
        match self {
            Via::Service => "service",
            Via::Task => "scheduled task",
            Via::Unknown => "unknown",
        }
    }

    /// The source name of a domain's data of this kind. An unknown kind's
    /// entries never get this far ([`Sidecar::parse`] drops them); it names
    /// no source of its own.
    pub fn source(self, domain: &str) -> String {
        let d = domain.trim().to_ascii_uppercase();
        match self {
            Via::Service | Via::Unknown => format!("{SERVICES_SOURCE}{d})"),
            Via::Task => format!("{TASKS_SOURCE}{d})"),
        }
    }
}

/// The start of each source's name.
const SERVICES_SOURCE: &str = "Stored credentials in services (";
const TASKS_SOURCE: &str = "Stored credentials in scheduled tasks (";

/// A service and the account it runs as, as `ObjectName` gives it, or a
/// scheduled task and the account whose password it stores, as its
/// principal gives it. Never the password.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stored {
    #[serde(default)]
    pub via: Via,
    /// The service's key name, or the task's path in the Tasks folder
    /// (`\Folder\Name`).
    pub name: String,
    /// `DOMAIN\user`, `user@domain`, or (a task's) the account's SID.
    pub account: String,
    /// The service's `Start` value (4: disabled, whose password is still
    /// stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    /// A task's `Settings/Enabled` (`false`: disabled, its password still
    /// stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// A task's logon type, one of [`STORED_LOGON_TYPES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<String>,
}

impl Stored {
    /// Disabled: a service whose `Start` is 4, a task not enabled. Its
    /// password is still stored.
    pub fn disabled(&self) -> bool {
        match self.via {
            Via::Service => self.start == Some(4),
            Via::Task => self.enabled == Some(false),
            Via::Unknown => false,
        }
    }
}

/// The logon types of a task whose password the host stores. `S4U`,
/// `InteractiveToken`, `ServiceAccount` and `Group` store none.
pub const STORED_LOGON_TYPES: [&str; 2] = ["Password", "InteractiveTokenOrPassword"];

/// `s` cut to [`MAX_TEXT`] characters.
fn cut(s: &str) -> String {
    s.trim().chars().take(MAX_TEXT).collect()
}

fn clean(s: &str) -> Option<String> {
    let s = cut(s);
    (!s.is_empty() && !s.chars().any(char::is_control)).then_some(s)
}

impl Sidecar {
    /// Parses and checks a sidecar. Entries that are malformed are dropped
    /// (and named in `notes`); a sidecar that is too large, of another
    /// schema, or not JSON is refused whole. Fields it doesn't know (a
    /// value someone added) are never read.
    pub fn parse(bytes: &[u8], notes: &mut Vec<String>) -> Result<Sidecar, String> {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        if bytes.len() as u64 > MAX_SIDECAR_BYTES {
            return Err("too large for a stored credentials file".into());
        }
        let mut s: Sidecar = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if s.schema != SCHEMA {
            return Err(format!("schema '{}' is not {SCHEMA}", s.schema));
        }
        if s.domain.trim().is_empty() || s.domain.len() > 255 {
            return Err("no domain".into());
        }
        if s.hosts.len() > MAX_HOSTS
            || s.netbios.len() > MAX_NETBIOS
            || s.hosts.iter().map(|h| h.stored.len()).sum::<usize>() > MAX_STORED
        {
            return Err("it lists too many entries".into());
        }
        let mut note = |n: String| {
            if notes.len() < MAX_NOTES {
                notes.push(n);
            }
        };
        s.netbios
            .retain_mut(|n| match (clean(&n.dns), clean(&n.netbios)) {
                (Some(d), Some(b)) if d.len() <= 255 && b.len() <= 15 && !b.contains('\\') => {
                    n.dns = d.to_ascii_uppercase();
                    n.netbios = b.to_ascii_uppercase();
                    true
                }
                _ => {
                    note("a malformed NetBIOS name was skipped".into());
                    false
                }
            });
        let reason = |c: &mut Check| {
            c.reason = c.reason.as_deref().and_then(clean);
        };
        reason(&mut s.services);
        if let Some(t) = &mut s.tasks {
            reason(t);
        }
        let tasks_step = s.tasks.is_some();
        s.hosts.retain_mut(|h| {
            if !crate::opengraph::is_sid_shaped(&h.id) || h.id.len() > MAX_TEXT {
                note("a computer entry without a valid ID was skipped".into());
                return false;
            }
            h.name = clean(&h.name).unwrap_or_default();
            reason(&mut h.services);
            if let Some(t) = &mut h.tasks {
                reason(t);
            }
            // A kind this version doesn't know, and tasks in a file with no
            // tasks step (nothing says how far they were read): dropped.
            let before = h.stored.len();
            h.stored.retain(|st| match st.via {
                Via::Unknown => false,
                Via::Task => tasks_step,
                Via::Service => true,
            });
            if h.stored.len() < before {
                note(format!(
                    "{}: {} of a kind this file has no step for were skipped",
                    h.id,
                    crate::text::count(before - h.stored.len(), "entry", "entries")
                ));
            }
            // At most MAX_STORED_PER_HOST of each kind: past that, that
            // kind's read of the computer is partial.
            let mut kept = [0usize; 2];
            let mut over = [false; 2];
            h.stored.retain_mut(|st| {
                let k = st.via as usize;
                if kept[k] >= MAX_STORED_PER_HOST {
                    over[k] = true;
                    return false;
                }
                match (clean(&st.name), clean(&st.account)) {
                    (Some(n), Some(a)) => {
                        st.name = n;
                        st.account = a;
                        st.logon_type = st.logon_type.as_deref().and_then(|t| {
                            STORED_LOGON_TYPES
                                .iter()
                                .find(|l| **l == t.trim())
                                .map(|l| l.to_string())
                        });
                        kept[k] += 1;
                        true
                    }
                    _ => {
                        note(format!(
                            "{}: a malformed {} entry was skipped",
                            h.id,
                            st.via.label()
                        ));
                        false
                    }
                }
            });
            let partial = |c: &mut Check| {
                if c.status == CheckStatus::Complete {
                    c.status = CheckStatus::Partial;
                }
            };
            if over[Via::Service as usize] {
                note(format!(
                    "{}: more services than the limit; the rest were skipped",
                    h.id
                ));
                partial(&mut h.services);
            }
            if over[Via::Task as usize] {
                note(format!(
                    "{}: more scheduled tasks than the limit; the rest were skipped",
                    h.id
                ));
                if let Some(t) = &mut h.tasks {
                    partial(t);
                }
            }
            true
        });
        Ok(s)
    }
}

/// How an account name in a service's `ObjectName` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountRef {
    /// `DOMAIN\user`, the domain as a NetBIOS (or DNS) name.
    Domain { domain: String, user: String },
    /// `user@domain` (a UPN).
    Upn { user: String, suffix: String },
    /// A built-in or virtual account: LocalSystem, `NT AUTHORITY\...`,
    /// `NT SERVICE\...`. No password is stored for it.
    Builtin,
    /// A local account of the computer (`.\user`).
    Local,
    /// An account's SID (`S-1-5-21-...`, upper case), as a task's `UserId`
    /// may give it: a domain account's, or a local one's that the
    /// directory won't have.
    Sid(String),
}

/// Reads a service's `ObjectName` or a task's `UserId`. `None` when it
/// names no account.
pub fn account_ref(object_name: &str) -> Option<AccountRef> {
    let s = object_name.trim();
    if s.is_empty() {
        return None;
    }
    if s.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("S-1-")) {
        let up = s.to_ascii_uppercase();
        if !crate::opengraph::is_sid_shaped(&up) {
            return None;
        }
        // Anything else is well known: SYSTEM, LOCAL SERVICE, BUILTIN.
        return Some(if up.starts_with("S-1-5-21-") {
            AccountRef::Sid(up)
        } else {
            AccountRef::Builtin
        });
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localsystem" | "localservice" | "networkservice" | "system"
    ) {
        return Some(AccountRef::Builtin);
    }
    if let Some((domain, user)) = s.split_once('\\') {
        let d = domain.trim().to_ascii_lowercase();
        if matches!(
            d.as_str(),
            "nt authority"
                | "nt service"
                | "nt virtual machine"
                | "iis apppool"
                | "builtin"
                | "window manager"
                | "font driver host"
        ) {
            return Some(AccountRef::Builtin);
        }
        if d == "." {
            return Some(AccountRef::Local);
        }
        let user = user.trim();
        if d.is_empty() || user.is_empty() || user.contains(['\\', '@']) {
            return None;
        }
        return Some(AccountRef::Domain {
            domain: domain.trim().to_ascii_uppercase(),
            user: user.to_ascii_uppercase(),
        });
    }
    if let Some((user, suffix)) = s.rsplit_once('@') {
        let (user, suffix) = (user.trim(), suffix.trim());
        if user.is_empty() || suffix.is_empty() || !suffix.contains('.') {
            return None;
        }
        return Some(AccountRef::Upn {
            user: user.to_ascii_uppercase(),
            suffix: suffix.to_ascii_uppercase(),
        });
    }
    // A bare name: a local account.
    Some(AccountRef::Local)
}

/// Whether a user name is a managed or computer account's (`name$`): a
/// gMSA's password is rotated by the domain, not one an administrator can
/// reuse.
fn is_dollar(user: &str) -> bool {
    user.ends_with('$')
}

/// The forest's domains by NetBIOS name, from every sidecar of the run:
/// `NETBIOS` → `DNS` (upper case). A NetBIOS name two sidecars give
/// different DNS names for (two forests of a run) is ambiguous: it names
/// neither.
#[derive(Debug, Clone, Default)]
pub struct NetbiosMap(HashMap<String, Option<String>>);

impl NetbiosMap {
    pub fn add(&mut self, names: &[NetbiosName]) {
        for n in names {
            let dns = n.dns.to_ascii_uppercase();
            self.0
                .entry(n.netbios.to_ascii_uppercase())
                .and_modify(|d| {
                    if d.as_deref() != Some(dns.as_str()) {
                        *d = None;
                    }
                })
                .or_insert(Some(dns));
        }
    }

    /// The map of one sidecar's names, with `other`'s for the names it
    /// doesn't have: a sidecar's services resolve against its own forest
    /// first.
    pub fn with_fallback(mut self, other: &NetbiosMap) -> Self {
        for (k, v) in &other.0 {
            self.0.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The DNS name of the domain whose NetBIOS name the collection read
    /// as `netbios`; `None` when it read none, or two.
    pub fn get(&self, netbios: &str) -> Option<&str> {
        self.0
            .get(&netbios.trim().to_ascii_uppercase())
            .and_then(Option::as_deref)
    }

    /// The DNS name of the domain `name` names: its NetBIOS name as the
    /// collection read it, else a DNS name of a known domain, else a known
    /// domain whose first label it is (the usual NetBIOS name) when only one
    /// is. An ambiguous NetBIOS name names none.
    pub fn dns_of(&self, name: &str, known: &[String]) -> Option<String> {
        let up = name.trim().to_ascii_uppercase();
        if let Some(d) = self.0.get(&up) {
            return d.clone();
        }
        if known.contains(&up) {
            return Some(up);
        }
        // A NetBIOS name the collection didn't read: the first label of a
        // known domain, unless another domain's NetBIOS name is that label.
        let mut by_label = known
            .iter()
            .filter(|k| k.split('.').next() == Some(up.as_str()))
            .filter(|k| !self.0.values().any(|d| d.as_deref() == Some(k.as_str())));
        match (by_label.next(), by_label.next()) {
            (Some(one), None) => Some(one.clone()),
            _ => None,
        }
    }
}

/// What a service's account resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    User(NodeIndex),
    /// A gMSA, sMSA or computer account: no edge.
    Managed,
    /// Built-in, virtual or local: no domain password stored.
    NotDomain,
    /// A domain account the collection doesn't have.
    Unknown,
}

/// The users of the graph by name (`SAM@DOMAIN`) and by userPrincipalName
/// where it differs, for resolving.
pub struct UserIndex {
    names: HashMap<String, Vec<NodeIndex>>,
    upns: HashMap<String, Vec<NodeIndex>>,
}

impl UserIndex {
    pub fn new(g: &AdGraph) -> Self {
        let mut names: HashMap<String, Vec<NodeIndex>> = HashMap::new();
        let mut upns: HashMap<String, Vec<NodeIndex>> = HashMap::new();
        for (ix, n) in g.nodes() {
            if n.kind == NodeKind::User && !n.placeholder {
                names
                    .entry(n.name.to_ascii_uppercase())
                    .or_default()
                    .push(ix);
                if let Some(u) = &n.props.upn {
                    upns.entry(u.to_ascii_uppercase()).or_default().push(ix);
                }
            }
        }
        UserIndex { names, upns }
    }

    fn one(m: &HashMap<String, Vec<NodeIndex>>, key: &str) -> Option<Option<NodeIndex>> {
        match m.get(key).map(Vec::as_slice) {
            None | Some([]) => None,
            Some([ix]) => Some(Some(*ix)),
            // Two accounts: neither.
            Some(_) => Some(None),
        }
    }
}

/// Resolves a service's account against the graph. `DOMAIN\user` by the
/// NetBIOS name, then `USER@DNS`; `user@suffix` by userPrincipalName first,
/// then, when the suffix is a known domain, as `USER@DNS` (the implicit UPN).
pub fn resolve(
    g: &AdGraph,
    users: &UserIndex,
    netbios: &NetbiosMap,
    known: &[String],
    account: &str,
) -> Resolved {
    let found = match account_ref(account) {
        None | Some(AccountRef::Builtin | AccountRef::Local) => return Resolved::NotDomain,
        Some(AccountRef::Sid(sid)) => match g.lookup(&sid).map(|ix| (ix, g.node(ix))) {
            Some((ix, n)) if n.kind == NodeKind::User && !n.placeholder => Some(Some(ix)),
            // A computer account: its password is the domain's to rotate.
            Some((_, n)) if n.kind == NodeKind::Computer => return Resolved::Managed,
            // A group or another kind: no one's password.
            Some((_, n)) if !n.placeholder => return Resolved::NotDomain,
            // A local account of the host, or a domain account the
            // collection doesn't have.
            _ => None,
        },
        Some(AccountRef::Domain { domain, user }) => match netbios.dns_of(&domain, known) {
            Some(dns) => {
                if is_dollar(&user) {
                    return Resolved::Managed;
                }
                UserIndex::one(&users.names, &format!("{user}@{dns}"))
            }
            // Not a domain of the forest: the computer's own name (a local
            // account), a domain the collection doesn't know, or an
            // ambiguous NetBIOS name.
            None => return Resolved::NotDomain,
        },
        Some(AccountRef::Upn { user, suffix }) => {
            if is_dollar(&user) {
                return Resolved::Managed;
            }
            let upn = format!("{user}@{suffix}");
            match UserIndex::one(&users.upns, &upn) {
                Some(found) => Some(found),
                None if known.contains(&suffix) => UserIndex::one(&users.names, &upn),
                None => None,
            }
        }
    };
    match found.flatten() {
        Some(ix) if g.node(ix).props.managedpassword == Some(true) => Resolved::Managed,
        Some(ix) => Resolved::User(ix),
        None => Resolved::Unknown,
    }
}

/// The source name of a domain's services data, as findings carry it.
pub fn source(domain: &str) -> String {
    Via::Service.source(domain)
}

/// The source name of a domain's scheduled tasks data.
pub fn task_source(domain: &str) -> String {
    Via::Task.source(domain)
}

/// Whether a source name is a stored credentials source's (services or
/// scheduled tasks).
pub fn is_source(name: &str) -> bool {
    source_parts(name).is_some()
}

/// What a stored credentials source's name says: its kind and domain.
pub fn source_parts(name: &str) -> Option<(Via, &str)> {
    [(Via::Service, SERVICES_SOURCE), (Via::Task, TASKS_SOURCE)]
        .into_iter()
        .find_map(|(via, start)| {
            name.strip_prefix(start)
                .and_then(|r| r.strip_suffix(')'))
                .map(|d| (via, d))
        })
}

/// The sources a `HasStoredCredential` edge rests on, with the computer
/// as the unit: one per kind of thing that stores it there (a service, a
/// scheduled task), so a finding is fixed only when each was read again.
pub fn edge_units(g: &AdGraph, e: petgraph::graph::EdgeIndex) -> Vec<(String, String)> {
    let Some(origin) = g.edge_origin(e) else {
        return Vec::new();
    };
    let name = g.source_name(origin.source);
    let (Some((own, domain)), Some(unit)) = (source_parts(name), origin.unit.as_deref()) else {
        return Vec::new();
    };
    let mut out = vec![(name.to_string(), unit.to_string())];
    for v in g.stored_via(e) {
        if v.via != own && !out.iter().any(|(s, _)| *s == v.via.source(domain)) {
            out.push((v.via.source(domain), unit.to_string()));
        }
    }
    out
}

/// What stores one account's credential on one computer, kept per
/// `HasStoredCredential` edge for its path step and fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredVia {
    pub via: Via,
    pub name: String,
    /// The service or task is disabled (its password is still stored).
    pub disabled: bool,
}

/// What one domain's sidecar said, kept on the graph for the rules and the
/// collection completeness.
#[derive(Debug, Clone)]
pub struct StoredDomain {
    pub domain: String,
    pub services: Check,
    /// The reads were turned off.
    pub turned_off: bool,
    /// Each computer's services status, by node.
    pub hosts: HashMap<NodeIndex, CheckStatus>,
    /// The scheduled tasks step, when the sidecar has one.
    pub tasks: Option<Check>,
    /// The task reads were turned off.
    pub tasks_turned_off: bool,
    /// Each computer's tasks status, by node.
    pub task_hosts: HashMap<NodeIndex, CheckStatus>,
    /// Domain accounts a computer stores that the collection doesn't have
    /// (by computer node, as the file names them), at most
    /// [`MAX_UNRESOLVED`]. A targeted retest resolves them against the
    /// names the run had (an account renamed since).
    pub unresolved: Vec<(NodeIndex, String)>,
}

/// Most unresolved accounts kept per sidecar.
pub const MAX_UNRESOLVED: usize = 10_000;

/// Resolves `account` against `users` (a graph of the accounts a run had,
/// by their names then) with `g`'s NetBIOS names and domains: the
/// account a computer still stores under a name the directory has since
/// changed. `None` when it isn't one of them.
pub fn resolve_in(g: &AdGraph, users: &AdGraph, account: &str) -> Option<NodeIndex> {
    let mut known: Vec<String> = crate::analyze::known_domain_names(g)
        .into_iter()
        .chain(crate::analyze::known_domain_names(users))
        .map(|d| d.to_ascii_uppercase())
        .collect();
    known.dedup();
    match resolve(users, &UserIndex::new(users), g.netbios(), &known, account) {
        Resolved::User(ix) => Some(ix),
        _ => None,
    }
}

/// Ingest statistics for one sidecar's scheduled tasks (slice 2), as
/// [`StoredStats`] has them for its services.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskStats {
    pub tasks: Check,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turned_off: bool,
    /// Computers listed with a tasks status, and those read in full.
    pub hosts: usize,
    pub hosts_complete: usize,
    /// Computer → account pairs a scheduled task stores.
    pub edges: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complete_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_host_ids: Vec<String>,
}

/// Ingest statistics for one sidecar.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredStats {
    pub file: String,
    pub domain: String,
    pub services: Check,
    /// The reads were turned off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turned_off: bool,
    /// Computers listed, and those read in full.
    pub hosts: usize,
    pub hosts_complete: usize,
    /// `HasStoredCredential` edges added.
    pub edges: usize,
    /// Services that run as a gMSA or another managed account (no edge).
    pub managed: usize,
    /// Domain accounts the collection doesn't have, and computers it
    /// doesn't have.
    pub unresolved: usize,
    /// The object IDs of the computers read in full (coverage units).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complete_ids: Vec<String>,
    /// The object IDs of the computers with a `HasStoredCredential` edge
    /// that a service stores.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_host_ids: Vec<String>,
    /// The scheduled tasks, when the sidecar has a tasks step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TaskStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Adds one sidecar to the graph: the edges, and each computer's status.
/// Runs after every AD file and OpenGraph file is read.
pub(crate) fn apply(
    g: &mut AdGraph,
    label: &str,
    s: Sidecar,
    mut notes: Vec<String>,
    users: &UserIndex,
) -> StoredStats {
    let domain = s.domain.trim().to_ascii_uppercase();
    let mut stats = StoredStats {
        file: label.to_string(),
        domain: domain.clone(),
        services: s.services.clone(),
        turned_off: s.turned_off,
        hosts: s.hosts.len(),
        tasks: s.tasks.clone().map(|tasks| TaskStats {
            tasks,
            turned_off: s.tasks_turned_off,
            hosts: s.hosts.len(),
            ..TaskStats::default()
        }),
        ..StoredStats::default()
    };
    let src = g.add_og_source(&source(&domain));
    let mut known = crate::analyze::known_domain_names(g)
        .into_iter()
        .map(|d| d.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if !known.contains(&domain) {
        known.push(domain.clone());
    }
    // This sidecar's forest first, then the run's.
    let netbios = {
        let mut own = NetbiosMap::default();
        own.add(&s.netbios);
        own.with_fallback(g.netbios())
    };
    let mut statuses: HashMap<NodeIndex, CheckStatus> = HashMap::new();
    let mut task_statuses: HashMap<NodeIndex, CheckStatus> = HashMap::new();
    let mut unresolved: Vec<(NodeIndex, String)> = Vec::new();
    // Per edge, what stores it.
    let mut vias: BTreeMap<(NodeIndex, NodeIndex), Vec<StoredVia>> = BTreeMap::new();
    for h in &s.hosts {
        let Some(hix) = g
            .lookup(&h.id)
            .filter(|&ix| g.node(ix).kind == NodeKind::Computer)
        else {
            stats.unresolved += 1;
            if notes.len() < MAX_NOTES {
                notes.push(format!("computer {} is not in the collection", h.id));
            }
            continue;
        };
        statuses.insert(hix, h.services.status);
        if h.services.status == CheckStatus::Complete {
            stats.hosts_complete += 1;
            stats.complete_ids.push(g.node(hix).id.clone());
        }
        if let Some(t) = &mut stats.tasks {
            // A computer the tasks step doesn't list wasn't read for them.
            let status = h.tasks.as_ref().map(|c| c.status).unwrap_or_default();
            task_statuses.insert(hix, status);
            if status == CheckStatus::Complete {
                t.hosts_complete += 1;
                t.complete_ids.push(g.node(hix).id.clone());
            }
        }
        for st in &h.stored {
            let uix = match resolve(g, users, &netbios, &known, &st.account) {
                Resolved::User(ix) => ix,
                Resolved::Managed => {
                    stats.managed += 1;
                    continue;
                }
                Resolved::NotDomain => continue,
                Resolved::Unknown => {
                    stats.unresolved += 1;
                    if unresolved.len() < MAX_UNRESOLVED {
                        unresolved.push((hix, st.account.clone()));
                    }
                    continue;
                }
            };
            let list = vias.entry((hix, uix)).or_default();
            if list.len() < MAX_NAMES_PER_EDGE
                && !list.iter().any(|v| v.via == st.via && v.name == st.name)
            {
                list.push(StoredVia {
                    via: st.via,
                    name: st.name.clone(),
                    disabled: st.disabled(),
                });
            }
        }
    }
    for ((hix, uix), list) in vias {
        let id = g.node(hix).id.clone();
        let by_service = list.iter().any(|v| v.via == Via::Service);
        let by_task = list.iter().any(|v| v.via == Via::Task);
        // The edge's own source: the services', else the tasks'. A finding
        // rests on both when both store it ([`edge_units`]).
        let origin = EdgeOrigin {
            source: if by_service {
                src
            } else {
                g.add_og_source(&task_source(&domain))
            },
            unit: Some(id.clone()),
        };
        if g.add_og_edge(hix, uix, EdgeKind::HasStoredCredential, origin) {
            stats.edges += 1;
        }
        if by_service && !stats.edge_host_ids.contains(&id) {
            stats.edge_host_ids.push(id.clone());
        }
        if by_task {
            let t = stats.tasks.get_or_insert_with(TaskStats::default);
            t.edges += 1;
            if !t.edge_host_ids.contains(&id) {
                t.edge_host_ids.push(id);
            }
        }
        g.add_stored_via(hix, uix, list);
    }
    stats.notes = notes;
    g.add_stored_domain(StoredDomain {
        domain,
        services: s.services,
        turned_off: s.turned_off,
        hosts: statuses,
        tasks: s.tasks,
        tasks_turned_off: s.tasks_turned_off,
        task_hosts: task_statuses,
        unresolved,
    });
    stats
}

/// Whether a domain's service reads were turned off (and not read by
/// another sidecar of the run).
pub fn turned_off(g: &AdGraph, domain: &str) -> bool {
    let d = domain.to_ascii_uppercase();
    let mut of = g
        .stored_domains()
        .iter()
        .filter(|s| s.domain == d)
        .peekable();
    of.peek().is_some() && of.all(|s| s.turned_off)
}

/// Whether a domain's task reads were turned off (and not read by another
/// sidecar of the run that has a tasks step).
pub fn tasks_turned_off(g: &AdGraph, domain: &str) -> bool {
    let d = domain.to_ascii_uppercase();
    let mut of = g
        .stored_domains()
        .iter()
        .filter(|s| s.domain == d && s.tasks.is_some())
        .peekable();
    of.peek().is_some() && of.all(|s| s.tasks_turned_off)
}

/// The services read of one domain, for collection completeness: how many
/// of its computers (by node) were read in full.
pub fn complete_hosts(g: &AdGraph, domain: &str) -> Option<HashMap<NodeIndex, CheckStatus>> {
    best_of(g, domain, |sd| Some(&sd.hosts))
}

/// The scheduled tasks read of one domain, as [`complete_hosts`]. `None`
/// when no sidecar of the domain has a tasks step.
pub fn complete_task_hosts(g: &AdGraph, domain: &str) -> Option<HashMap<NodeIndex, CheckStatus>> {
    best_of(g, domain, |sd| sd.tasks.is_some().then_some(&sd.task_hosts))
}

/// Each computer's best status across a domain's sidecars, from `part`.
fn best_of(
    g: &AdGraph,
    domain: &str,
    part: impl Fn(&StoredDomain) -> Option<&HashMap<NodeIndex, CheckStatus>>,
) -> Option<HashMap<NodeIndex, CheckStatus>> {
    let d = domain.to_ascii_uppercase();
    let mut out: Option<HashMap<NodeIndex, CheckStatus>> = None;
    for sd in g.stored_domains() {
        if sd.domain != d {
            continue;
        }
        let Some(hosts) = part(sd) else {
            continue;
        };
        let m = out.get_or_insert_with(HashMap::new);
        for (&ix, &st) in hosts {
            // Two sidecars for one domain: the better read counts.
            let e = m.entry(ix).or_insert(st);
            if st == CheckStatus::Complete
                || (st == CheckStatus::Partial && *e == CheckStatus::NotCollected)
            {
                *e = st;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_sidecar_name("a.zip!pathwarden-storedcreds.json"));
        assert!(is_sidecar_name(
            r"C:\x\20261010_NORTH_pathwarden-storedcreds.json"
        ));
        assert!(!is_sidecar_name("pathwarden-sysvol.json"));
        assert_eq!(
            source("north.contoso.local"),
            "Stored credentials in services (NORTH.CONTOSO.LOCAL)"
        );
        assert!(is_source(&source("x")));
    }

    #[test]
    fn object_names() {
        use AccountRef::*;
        for b in [
            "LocalSystem",
            "NT AUTHORITY\\NetworkService",
            "NT AUTHORITY\\LocalService",
            "nt service\\MSSQL$SQLEXPRESS",
            "NT SERVICE\\x",
            "localsystem",
        ] {
            assert_eq!(account_ref(b), Some(Builtin), "{b}");
        }
        assert_eq!(account_ref(".\\backup"), Some(Local));
        assert_eq!(account_ref("backup"), Some(Local));
        assert_eq!(account_ref(""), None);
        assert_eq!(account_ref("\\x"), None);
        assert_eq!(
            account_ref("NORTH\\sql_svc"),
            Some(Domain {
                domain: "NORTH".into(),
                user: "SQL_SVC".into()
            })
        );
        assert_eq!(
            account_ref("svc@north.contoso.local"),
            Some(Upn {
                user: "SVC".into(),
                suffix: "NORTH.CONTOSO.LOCAL".into()
            })
        );
        assert_eq!(account_ref("svc@nodot"), None);
        // A task's UserId may be a SID: a domain or local account's, or a
        // well-known one.
        assert_eq!(
            account_ref("s-1-5-21-1-2-3-1201"),
            Some(Sid("S-1-5-21-1-2-3-1201".into()))
        );
        assert_eq!(account_ref("S-1-5-18"), Some(Builtin));
        assert_eq!(account_ref("S-1-5-32-544"), Some(Builtin));
        assert_eq!(account_ref("S-1-x"), None);
    }

    /// Tasks: each kind has its own cap, a made-up logon type is dropped,
    /// and the tasks step's reason is cleaned like the services'.
    #[test]
    fn parse_caps_each_kind() {
        let task = |i: usize| {
            format!(
                r#"{{"via":"task","name":"\\t{i}","account":"CONTOSO\\svc","logon_type":"{}"}}"#,
                if i == 0 { "Bogus" } else { "Password" }
            )
        };
        let tasks: Vec<String> = (0..MAX_STORED_PER_HOST + 1).map(task).collect();
        let text = format!(
            r#"{{"schema":"{SCHEMA}","domain":"contoso.local","tasks":{{"status":"complete","reason":"a\u0007"}},
            "hosts":[{{"id":"S-1-5-21-1-2-3-1104","services":{{"status":"complete"}},"tasks":{{"status":"complete"}},
              "stored":[{{"name":"Svc","account":"CONTOSO\\svc"}},{}]}}]}}"#,
            tasks.join(",")
        );
        let mut notes = Vec::new();
        let s = Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
        let h = &s.hosts[0];
        assert_eq!(h.stored.len(), 1 + MAX_STORED_PER_HOST);
        assert_eq!(h.services.status, CheckStatus::Complete, "services within");
        assert_eq!(h.tasks.as_ref().unwrap().status, CheckStatus::Partial);
        assert_eq!(h.stored[1].logon_type, None, "made up");
        assert_eq!(h.stored[2].logon_type.as_deref(), Some("Password"));
        assert_eq!(s.tasks.as_ref().unwrap().reason, None);
        assert!(
            notes.iter().any(|n| n.contains("scheduled tasks")),
            "{notes:?}"
        );
    }

    /// A kind a later version adds is dropped, not an error; tasks in a
    /// file without a tasks step are dropped, with a note.
    #[test]
    fn unknown_kinds_and_stepless_tasks_are_dropped() {
        let text = format!(
            r#"{{"schema":"{SCHEMA}","domain":"contoso.local",
            "hosts":[{{"id":"S-1-5-21-1-2-3-1104","services":{{"status":"complete"}},
              "stored":[{{"name":"Svc","account":"CONTOSO\\svc"}},
                        {{"via":"wmi_subscription","name":"x","account":"CONTOSO\\a"}},
                        {{"via":"task","name":"\\t","account":"CONTOSO\\b","logon_type":"Password"}}]}}]}}"#
        );
        let mut notes = Vec::new();
        let s = Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
        assert_eq!(s.hosts[0].stored.len(), 1);
        assert_eq!(s.hosts[0].stored[0].via, Via::Service);
        assert!(notes.iter().any(|n| n.contains("2 entries")), "{notes:?}");
        // With a tasks step, the task stays (the unknown kind still goes).
        let with = text.replace(
            r#""domain":"contoso.local","#,
            r#""domain":"contoso.local","tasks":{"status":"complete"},"#,
        );
        let s = Sidecar::parse(with.as_bytes(), &mut Vec::new()).unwrap();
        let vias: Vec<Via> = s.hosts[0].stored.iter().map(|st| st.via).collect();
        assert_eq!(vias, [Via::Service, Via::Task]);
    }

    #[test]
    fn netbios_names_resolve() {
        let mut m = NetbiosMap::default();
        m.add(&[NetbiosName {
            dns: "corp.contoso.local".into(),
            netbios: "CONTOSO".into(),
        }]);
        let known = vec!["CORP.CONTOSO.LOCAL".to_string(), "FABRIKAM.COM".to_string()];
        assert_eq!(
            m.dns_of("contoso", &known).as_deref(),
            Some("CORP.CONTOSO.LOCAL")
        );
        // Not read: the first label of one known domain.
        assert_eq!(
            m.dns_of("FABRIKAM", &known).as_deref(),
            Some("FABRIKAM.COM")
        );
        // The DNS name itself.
        assert_eq!(
            m.dns_of("fabrikam.com", &known).as_deref(),
            Some("FABRIKAM.COM")
        );
        // CORP is the first label of a domain whose NetBIOS name is CONTOSO.
        assert_eq!(m.dns_of("CORP", &known), None);
        assert_eq!(m.dns_of("APP01", &known), None);
    }

    /// Two forests' sidecars with one NetBIOS name: it names neither, but
    /// each sidecar's own name still resolves its services first.
    #[test]
    fn a_shared_netbios_name_is_ambiguous() {
        let a = NetbiosName {
            dns: "corp.local".into(),
            netbios: "CORP".into(),
        };
        let b = NetbiosName {
            dns: "corp.example".into(),
            netbios: "CORP".into(),
        };
        let mut run = NetbiosMap::default();
        run.add(std::slice::from_ref(&a));
        run.add(std::slice::from_ref(&a));
        assert_eq!(
            run.get("corp"),
            Some("CORP.LOCAL"),
            "the same name twice is fine"
        );
        run.add(std::slice::from_ref(&b));
        assert_eq!(run.get("CORP"), None);
        assert_eq!(run.dns_of("CORP", &["CORP.LOCAL".into()]), None);
        let mut own = NetbiosMap::default();
        own.add(&[a]);
        let own = own.with_fallback(&run);
        assert_eq!(own.get("CORP"), Some("CORP.LOCAL"));
    }

    #[test]
    fn the_collect_section_turns_service_reads_off() {
        let c = crate::config::Config::parse("[collect]\nservice_reads = false\n").unwrap();
        assert!(!c.collect.service_reads(false));
        let c = crate::config::Config::parse("").unwrap();
        assert!(c.collect.service_reads(false));
        assert!(!c.collect.service_reads(true), "--no-service-reads");
        let c = crate::config::Config::parse("[collect]\nservice_reads = true\n").unwrap();
        assert!(
            !c.collect.service_reads(true),
            "the command wins when it turns them off"
        );
        assert!(crate::config::Config::parse("[collect]\nservice_read = false\n").is_err());
    }

    #[test]
    fn parse_checks_and_drops_bad_entries() {
        let mut notes = Vec::new();
        let long = "x".repeat(400);
        let text = format!(
            r#"{{"schema":"{SCHEMA}","domain":"contoso.local","password":"Hunter2!",
            "netbios":[{{"dns":"contoso.local","netbios":"contoso"}},{{"dns":"","netbios":"x"}}],
            "services":{{"status":"partial","read":2,"failed":1}},
            "hosts":[
              {{"id":"S-1-5-21-1-2-3-1104","name":"APP01.CONTOSO.LOCAL","services":{{"status":"complete","read":1}},
                "stored":[{{"name":"Svc","account":"CONTOSO\\svc","start":2,"secret":"x"}},
                          {{"name":"{long}","account":"CONTOSO\\svc2"}},
                          {{"name":"bad","account":"a\u0007b"}}]}},
              {{"id":"APP02","services":{{"status":"complete"}}}}
            ]}}"#
        );
        let s = Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
        assert_eq!(s.netbios.len(), 1);
        assert_eq!(s.netbios[0].netbios, "CONTOSO");
        assert_eq!(s.services.status, CheckStatus::Partial);
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].stored.len(), 2);
        assert_eq!(s.hosts[0].stored[1].name.chars().count(), MAX_TEXT);
        assert_eq!(notes.len(), 3, "{notes:?}");
        // Nothing unknown is kept: written back, no secret is there.
        let back = serde_json::to_string(&s).unwrap();
        assert!(
            !back.contains("Hunter2") && !back.contains("secret"),
            "{back}"
        );
        assert!(Sidecar::parse(br#"{"schema":"x","domain":"a"}"#, &mut notes).is_err());
        assert!(Sidecar::parse(b"[]", &mut notes).is_err());
    }
}
