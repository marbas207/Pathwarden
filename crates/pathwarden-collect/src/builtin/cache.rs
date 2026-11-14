//! The read on disk: the directory goes to files while it is read,
//! instead of into memory, and the parser reads it back from them. A read
//! that stops can be resumed for 24 hours (slice 2).
//!
//! - One folder per domain, `<env>\collect-cache\<domain>\`, private to
//!   this account ([`pathwarden_core::perms`]). It holds `checkpoint.json`
//!   (our marker; `format` 2) and one chunk file per part of the read.
//! - The plan ([`plan`]): Schema, Configuration and the other small naming
//!   contexts are one `whole` chunk each. The domain's is a `head` chunk
//!   (its root object alone), 64 `window` chunks splitting `uSNChanged`
//!   `[1, highestCommittedUSN]` evenly, a `delta` chunk for what changed
//!   during the read (`uSNChanged` above the snapshot), and a `rest` chunk,
//!   read last: the objects none of those returned. An account that can't
//!   read an object's `uSNChanged` (a plain user, on the BCKUPKEY secrets,
//!   some well-known foreign security principals, ...) gets it from no
//!   range, so the domain is listed by DN alone (`1.1`) and each object
//!   not seen is read on its own.
//! - A chunk is RustHound-CE's own record format, written through its public
//!   `DiskStorage` (`Storage::add`/`finish`): `chunk-0001.part` while it is
//!   written, then `sync_all`, then renamed to `chunk-0001.seg`, then the
//!   checkpoint says `done`. A `.part` is never read, and a `.seg` the
//!   checkpoint doesn't call done is read again.
//! - Several streams read at once (slice 3): each has at most one chunk,
//!   and so one `.part`, open at a time. One writer thread takes every
//!   stream's pages, so the checkpoint is written by that thread only, a
//!   chunk at a time, always after that chunk's rename.
//! - The checkpoint holds the read's key ([`Key`]: the domain controller's
//!   database, the account, the filter and the attributes). A read is
//!   resumed only on the same key, within 24 hours of its start
//!   ([`RESUME_SECS`]); anything else starts over.
//! - [`Reader`] reads the done chunks back in a fixed order (Schema, the
//!   domain head, its windows, the delta and the rest chunk, Configuration,
//!   the other contexts: Schema first and the head before its objects, as
//!   RustHound-CE's parser needs), whatever order they were read in. An
//!   object in the delta is dropped from the windows (its newest version is
//!   in the delta), one in the rest chunk from both, and the head from all
//!   three.
//! - The folder goes once the parse has read it. A read that stopped keeps
//!   it for resuming; [`sweep`] removes earlier ones that can't be: only
//!   files named as ours, only in folders holding our checkpoint and not
//!   locked by a read in progress.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusthound_ce::transport::ldap::LdapSearchEntry;
use rusthound_ce::{DiskStorage, DiskStorageReader, Storage};
use serde::{Deserialize, Serialize};

use crate::NoSpace;

/// The checkpoint's `format`. An older one is swept; a newer one is
/// another version's: never trusted or rewritten, and removed only when
/// this domain's read starts over.
pub(super) const FORMAT: u32 = 3;
pub(super) const CHECKPOINT: &str = "checkpoint.json";
const CHECKPOINT_TMP: &str = "checkpoint.json.tmp";
/// Locked (`File::try_lock`) while the read runs, so another process's
/// sweep knows the folder is in use.
const LOCK: &str = "checkpoint.json.lock";
/// How long a stopped read can be resumed, from when it started.
pub(super) const RESUME_SECS: i64 = 24 * 3600;
/// The `uSNChanged` windows of the domain's naming context.
pub(super) const WINDOWS: u64 = 64;
/// Bytes an entry takes on disk when no earlier read says.
pub(super) const DEFAULT_ENTRY_BYTES: u64 = 16 * 1024;
/// The least a read asks for: room for the zip of a small domain, written
/// once the read on disk is gone (a larger domain's read frees more than its
/// zip takes).
pub(super) const MIN_ROOM: u64 = 64 << 20;
/// Pages waiting for the writer thread, per stream: the read stops while
/// it is behind.
const WRITE_QUEUE: usize = 2;
/// Entries decoded ahead of the parser.
const READ_AHEAD: usize = 1024;

/// What part of a naming context a chunk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Kind {
    /// The domain's root object alone (a Base search).
    Head,
    /// The domain's objects with `uSNChanged` in `[usn_lo, usn_hi]`.
    Window,
    /// A whole naming context in one search.
    Whole,
    /// The domain's objects changed during the read: `uSNChanged` from
    /// `usn_lo`, the snapshot + 1. Deleted objects too (SHOW_DELETED): an
    /// object deleted during the read is left out of the windows.
    Delta,
    /// The domain's objects the head, the windows and the delta didn't
    /// return: an object whose `uSNChanged` the account can't read matches
    /// no range. Read after the delta: the domain listed by DN alone, then
    /// each object not seen, on its own.
    Rest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum State {
    /// Not read, or not completely: read (again).
    Todo,
    /// Its `.seg` is complete.
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Chunk {
    pub id: u32,
    /// The naming context it reads.
    pub nc: String,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usn_lo: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usn_hi: Option<u64>,
    pub state: State,
    pub entries: u64,
    /// Its size on disk.
    pub bytes: u64,
    /// Its entries by the type they become (for the progress on resume).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<String, u64>,
}

impl Chunk {
    fn new(id: u32, nc: &str, kind: Kind, usn_lo: Option<u64>, usn_hi: Option<u64>) -> Self {
        Self {
            id,
            nc: nc.to_string(),
            kind,
            usn_lo,
            usn_hi,
            state: State::Todo,
            entries: 0,
            bytes: 0,
            counts: BTreeMap::new(),
        }
    }

    pub(super) fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Whether its search also asks for deleted objects (the delta).
    pub(super) fn shows_deleted(&self) -> bool {
        self.kind == Kind::Delta
    }

    /// A Base search of `nc` (the head), else a subtree search.
    pub(super) fn base_only(&self) -> bool {
        self.kind == Kind::Head
    }

    /// `filter` within the chunk's `uSNChanged` window. The attribute is
    /// indexed: each window is one indexed range on the DC.
    pub(super) fn filter(&self, filter: &str) -> String {
        match (self.usn_lo, self.usn_hi) {
            (None, None) => filter.to_string(),
            (Some(lo), Some(hi)) => format!("(&{filter}(uSNChanged>={lo})(uSNChanged<={hi}))"),
            (Some(lo), None) => format!("(&{filter}(uSNChanged>={lo}))"),
            (None, Some(hi)) => format!("(&{filter}(uSNChanged<={hi}))"),
        }
    }

    /// Where it goes when read back: Schema, the domain head, its windows,
    /// the delta and the rest chunk, Configuration, the other contexts.
    fn rank(&self, domain_nc: &str) -> u8 {
        match self.kind {
            Kind::Head => 1,
            Kind::Window => 2,
            Kind::Delta | Kind::Rest => 3,
            Kind::Whole if self.nc.eq_ignore_ascii_case(domain_nc) => 1,
            Kind::Whole => {
                let lower = self.nc.to_ascii_lowercase();
                if lower.starts_with("cn=schema,") {
                    0
                } else if lower.starts_with("cn=configuration,") {
                    4
                } else {
                    5
                }
            }
        }
    }
}

/// Each naming context in one chunk, in order: a read with no snapshot of
/// the domain controller (or into memory).
pub(super) fn whole_plan(contexts: &[String]) -> Vec<Chunk> {
    contexts
        .iter()
        .enumerate()
        .map(|(i, nc)| Chunk::new(i as u32 + 1, nc, Kind::Whole, None, None))
        .collect()
}

/// The chunks of a read, in the order they are read: each naming context
/// whole, but the domain's as its head, [`WINDOWS`] `uSNChanged` windows of
/// `[1, highest_usn]` and, last of all, the delta and the rest chunk.
/// Without a snapshot, the domain's is whole too.
pub(super) fn plan(contexts: &[String], domain_nc: &str, highest_usn: Option<u64>) -> Vec<Chunk> {
    let mut out: Vec<Chunk> = Vec::new();
    let mut delta = None;
    let push = |out: &mut Vec<Chunk>, nc: &str, kind, lo, hi| {
        let id = out.len() as u32 + 1;
        out.push(Chunk::new(id, nc, kind, lo, hi));
    };
    for nc in contexts {
        match highest_usn.filter(|&h| h > 0) {
            Some(h) if nc.eq_ignore_ascii_case(domain_nc) => {
                push(&mut out, nc, Kind::Head, None, None);
                // `n` windows, their bounds at i·h/n: none empty, sizes
                // differing by one at most.
                let n = WINDOWS.min(h);
                let bound = |i: u64| (u128::from(i) * u128::from(h) / u128::from(n)) as u64;
                for i in 0..n {
                    push(
                        &mut out,
                        nc,
                        Kind::Window,
                        Some(bound(i) + 1),
                        Some(bound(i + 1)),
                    );
                }
                delta = Some((nc.clone(), h));
            }
            _ => push(&mut out, nc, Kind::Whole, None, None),
        }
    }
    if let Some((nc, h)) = delta {
        push(&mut out, &nc, Kind::Delta, Some(h + 1), None);
        push(&mut out, &nc, Kind::Rest, None, None);
    }
    out
}

/// What [`dn_key`]s are kept of: the objects of the domain's naming
/// context the head, the windows and the delta returned.
pub(super) fn sees_dns(kind: Kind) -> bool {
    matches!(kind, Kind::Head | Kind::Window | Kind::Delta)
}

/// A DN, as the rest chunk looks it up: the first 128 bits of the SHA-256
/// of it in lower case. The same in every process, so a chunk's keys can be
/// kept beside it ([`keys_file`]) for a read resumed by another process (a
/// per-process random hasher could not be); 128 bits, so two DNs never
/// share one in practice. 750,000 objects take about 20 MB in memory.
pub(super) fn dn_key(dn: &str) -> u128 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(dn.to_lowercase().as_bytes());
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    u128::from_le_bytes(k)
}

/// A done chunk's [`dn_key`]s, beside its `.seg` (`chunk-0003.dns`): 16
/// bytes each, little-endian, one per entry in order. Written for the
/// head, the windows and the delta ([`sees_dns`]) before the `.seg` is
/// renamed, so a done chunk has it unless an older run wrote it.
fn keys_file(dir: &Path, id: u32) -> PathBuf {
    chunk_file(dir, id, "dns")
}

/// The [`dn_key`]s of the done `chunks` in `dir`: what a read that resumed
/// had seen before it stopped. From each chunk's keys ([`keys_file`]);
/// from its `.seg` when they are missing or not whole.
pub(super) fn seen_in(
    dir: &Path,
    chunks: &[&Chunk],
    into: &mut HashSet<u128>,
) -> Result<(), String> {
    for c in chunks {
        let keys = std::fs::read(keys_file(dir, c.id))
            .ok()
            .filter(|b| b.len() as u64 == c.entries.saturating_mul(16));
        match keys {
            Some(bytes) => {
                into.extend(
                    bytes
                        .as_chunks::<16>()
                        .0
                        .iter()
                        .map(|k| u128::from_le_bytes(*k)),
                );
            }
            None => {
                each_entry(&chunk_file(dir, c.id, "seg"), c.entries, |e| {
                    into.insert(dn_key(&e.dn));
                    true
                })?;
            }
        }
    }
    Ok(())
}

/// What a read must share with the one it resumes. `account` and `sign_in`
/// are HMACs with the cache's own key ([`keyed`]), `attributes` a SHA-256
/// hash: no account name is written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Key {
    /// The domain's DNS name, lower case.
    pub domain: String,
    /// The domain controller read.
    pub dc_host: String,
    /// Its `dsServiceName` (its NTDS Settings object).
    pub ds_service_name: String,
    /// Its database's `invocationID`, in hex: another DC, or the same one
    /// restored, has another. uSNs mean nothing across them.
    pub invocation_id: String,
    /// The account the directory says signed in ("Who am I?").
    pub account: String,
    /// The sign-in asked for ([`crate::sign_in_key`]): what the app and the
    /// command line can check before connecting.
    pub sign_in: String,
    /// The LDAP filter.
    pub filter: String,
    /// The attributes asked for.
    pub attributes: String,
}

/// SHA-256 of `text`, hex.
pub(super) fn hash(text: &str) -> String {
    pathwarden_core::opengraph::coverage::sha256_hex(text.as_bytes())
}

/// The cache's own random key, in its root folder (never in a domain's): the
/// account and sign-in in a checkpoint are HMACs with it, so a copied
/// checkpoint can't be matched against a list of names elsewhere.
const KEY_FILE: &str = "read-key";

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> Vec<u8> {
    let hex = pathwarden_core::opengraph::coverage::sha256_hex(bytes);
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// HMAC-SHA256 of `text` with `key` (at most 64 bytes), hex.
pub(super) fn keyed(key: &[u8], text: &str) -> String {
    let mut k = [0u8; 64];
    k[..key.len().min(64)].copy_from_slice(&key[..key.len().min(64)]);
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(text.as_bytes());
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend(sha256(&inner));
    pathwarden_core::opengraph::coverage::sha256_hex(&outer)
}

/// Makes `root` (private) if it isn't there.
fn ensure_root(root: &Path) -> std::io::Result<()> {
    if root.is_dir() {
        return Ok(());
    }
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match pathwarden_core::perms::create_private_dir(root) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// The key of the cache in `root` ([`KEY_FILE`]); made, with `root`, when
/// `create` and it isn't there.
pub(super) fn root_key(root: &Path, create: bool) -> std::io::Result<Option<Vec<u8>>> {
    let path = root.join(KEY_FILE);
    let read = |path: &Path| -> std::io::Result<Option<Vec<u8>>> {
        let text = std::fs::read_to_string(path)?;
        let text = text.trim();
        let key: Vec<u8> = (0..text.len() / 2)
            .filter_map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        Ok((key.len() == 32).then_some(key))
    };
    match read(&path) {
        Ok(Some(k)) => return Ok(Some(k)),
        Ok(None) if !create => return Ok(None),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound || !create => {
            return if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            }
        }
        _ => {}
    }
    ensure_root(root)?;
    let key: [u8; 32] = rand::random();
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    // A damaged key is replaced: the reads keyed with it start over.
    let _ = std::fs::remove_file(&path);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(hex.as_bytes())?;
            f.sync_all()?;
            Ok(Some(key.to_vec()))
        }
        // Another collection made it first.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read(&path),
        Err(e) => Err(e),
    }
}

/// The hash of the attributes a read asks for ([`super::attributes`]):
/// part of its [`Key`], so a read that asked for others starts over.
pub(super) fn attributes_hash(asked: &[&str]) -> String {
    hash(&asked.join("\n"))
}

impl Key {
    /// Why a read with key `now` can't resume one with this key, if it can't.
    fn differs(&self, now: &Key) -> Option<&'static str> {
        if self.invocation_id.is_empty() || now.invocation_id.is_empty() {
            return Some("the domain controller's database could not be identified");
        }
        if !self.domain.eq_ignore_ascii_case(&now.domain) {
            Some("it is of another domain")
        } else if self.invocation_id != now.invocation_id
            || !self
                .ds_service_name
                .eq_ignore_ascii_case(&now.ds_service_name)
        {
            Some("it was read from another domain controller")
        } else if self.account != now.account || self.sign_in != now.sign_in {
            Some("it was read with another account")
        } else if self.filter != now.filter {
            Some("it was read with another filter")
        } else if self.attributes != now.attributes {
            Some("it asked for other attributes")
        } else {
            None
        }
    }
}

/// `checkpoint.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Checkpoint {
    pub format: u32,
    /// The Pathwarden version that wrote it.
    pub pathwarden: String,
    #[serde(flatten)]
    pub key: Key,
    /// The domain's naming context.
    pub domain_nc: String,
    /// `highestCommittedUSN` when the read started (0: none, no windows).
    pub highest_usn: u64,
    /// When the read started (UTC, RFC 3339).
    pub started: String,
    /// When a chunk last finished.
    pub updated: String,
    /// Entries the whole read is expected to have, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<u64>,
    /// The plan, in read order.
    pub chunks: Vec<Chunk>,
    pub totals: Totals,
}

/// What the done chunks hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Totals {
    pub chunks: u64,
    pub done: u64,
    pub entries: u64,
    pub bytes: u64,
}

/// What a checkpoint is, read without trusting it.
#[derive(Debug)]
pub(super) enum Peek {
    /// No checkpoint.
    NotOurs,
    /// Not JSON, or not ours in shape.
    Damaged(String),
    /// Another format: older (swept), or newer (left alone).
    Format(u64),
    Ours(Box<Checkpoint>),
}

impl Checkpoint {
    pub(super) fn new(key: Key, domain_nc: &str, highest_usn: u64, chunks: Vec<Chunk>) -> Self {
        let at = pathwarden_core::time::format_rfc3339(now());
        let mut cp = Self {
            format: FORMAT,
            pathwarden: env!("CARGO_PKG_VERSION").into(),
            key,
            domain_nc: domain_nc.to_string(),
            highest_usn,
            started: at.clone(),
            updated: at,
            expected: None,
            chunks,
            totals: Totals::default(),
        };
        cp.retotal();
        cp
    }

    pub(super) fn retotal(&mut self) {
        let done = self.chunks.iter().filter(|c| c.is_done());
        self.totals = Totals {
            chunks: self.chunks.len() as u64,
            done: done.clone().count() as u64,
            entries: done.clone().map(|c| c.entries).sum(),
            bytes: done.map(|c| c.bytes).sum(),
        };
    }

    /// Written to `checkpoint.json.tmp`, synced, then renamed over
    /// `checkpoint.json` (replaced atomically).
    pub(super) fn save(&self, dir: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = dir.join(CHECKPOINT_TMP);
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(CHECKPOINT))
    }

    pub(super) fn peek(dir: &Path) -> Peek {
        let path = dir.join(CHECKPOINT);
        if !path.is_file() {
            return Peek::NotOurs;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Peek::Damaged(e.to_string()),
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => return Peek::Damaged(e.to_string()),
        };
        match value.get("format").and_then(serde_json::Value::as_u64) {
            Some(f) if f == u64::from(FORMAT) => match serde_json::from_value(value) {
                Ok(cp) => Peek::Ours(Box::new(cp)),
                Err(e) => Peek::Damaged(e.to_string()),
            },
            Some(f) => Peek::Format(f),
            None => Peek::Damaged("no format".into()),
        }
    }

    pub(super) fn load(dir: &Path) -> Result<Self, String> {
        match Self::peek(dir) {
            Peek::Ours(cp) => Ok(*cp),
            Peek::NotOurs => Err("cannot read the read's checkpoint: it is missing".into()),
            Peek::Damaged(e) => Err(format!("the read's checkpoint is damaged: {e}")),
            Peek::Format(f) => Err(format!("the read on disk has format {f}, not {FORMAT}")),
        }
    }

    /// Unix time it started; `None` if unreadable.
    pub(super) fn started_at(&self) -> Option<i64> {
        pathwarden_core::time::parse_rfc3339(&self.started)
    }

    /// Why it can't be resumed at `now` whoever asks, if it can't: more
    /// than 24 hours old, or nothing in it.
    fn expired(&self, now: i64) -> Option<&'static str> {
        if self.key.invocation_id.is_empty() {
            return Some("the domain controller's database could not be identified");
        }
        match self.started_at() {
            None => Some("its start time is unreadable"),
            Some(t) if now - t > RESUME_SECS => Some("it is more than 24 hours old"),
            // A clock put back: not trusted.
            Some(t) if t - now > 300 => Some("it started in the future"),
            Some(_) if !self.chunks.iter().any(Chunk::is_done) => Some("nothing was read"),
            Some(_) => None,
        }
    }

    /// How far it got, in percent (under 100): its entries of those
    /// expected, else its chunks.
    pub(super) fn percent(&self) -> u8 {
        let p = match self.expected.filter(|&e| e > 0) {
            Some(e) => self.totals.entries.saturating_mul(100) / e,
            None if self.totals.chunks > 0 => self.totals.done * 100 / self.totals.chunks,
            None => 0,
        };
        p.min(99) as u8
    }
}

pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn chunk_file(dir: &Path, id: u32, ext: &str) -> PathBuf {
    dir.join(format!("chunk-{id:04}.{ext}"))
}

/// `chunk-<digits>.seg`, `.dns` or `.part`: its number and whether it is
/// kept once its chunk is done (a `.seg`, or its keys).
fn chunk_name(name: &str) -> Option<(u32, bool)> {
    let rest = name.strip_prefix("chunk-")?;
    let (digits, seg) = match rest.strip_suffix(".seg") {
        Some(d) => (d, true),
        None => match rest.strip_suffix(".dns") {
            Some(d) => (d, true),
            None => (rest.strip_suffix(".part")?, false),
        },
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().unwrap_or(u32::MAX), seg))
}

fn is_chunk_name(name: &str) -> bool {
    chunk_name(name).is_some()
}

/// The folder for `domain` in `root`: its DNS name in lower case.
pub(super) fn domain_dir(root: &Path, domain: &str) -> PathBuf {
    let name: String = domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = if name.trim_matches('.').is_empty() {
        "_".to_string()
    } else if is_device_name(name.split('.').next().unwrap_or_default()) {
        // `con.local` would open the console device on Windows.
        format!("_{name}")
    } else {
        name
    };
    root.join(name)
}

/// A name Windows keeps for a device (`con`, `nul`, `com1`, ...), lower case.
fn is_device_name(base: &str) -> bool {
    let numbered = |prefix: &str| {
        base.strip_prefix(prefix)
            .is_some_and(|n| n.len() == 1 && n.bytes().all(|b| b.is_ascii_digit()))
    };
    matches!(base, "con" | "prn" | "aux" | "nul") || numbered("com") || numbered("lpt")
}

/// What [`remove_ours`] did with a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Removal {
    /// No checkpoint in it: not ours, not touched.
    NotOurs,
    /// A read in progress holds its lock: not touched.
    InUse,
    /// This file of ours could not be removed (another program has it
    /// open): the checkpoint stays, so the next sweep tries again.
    Kept(String),
    /// Our files are gone (and the folder, unless a file of someone else's
    /// is in it).
    Removed,
}

/// Whether a read holds `dir`'s lock. Testing it takes the lock for an
/// instant: a read starting then retries ([`hold_lock`]).
fn locked(dir: &Path) -> bool {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(LOCK))
    {
        // Free when it can be locked here (and unlocked on drop).
        Ok(f) => f.try_lock().is_err(),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Removes our files from `dir` if it holds our checkpoint and no read is
/// using it: the chunks, then `checkpoint.json*`, then the folder if nothing
/// else is in it.
pub(super) fn remove_ours(dir: &Path) -> Removal {
    if !dir.join(CHECKPOINT).is_file() {
        return Removal::NotOurs;
    }
    if locked(dir) {
        return Removal::InUse;
    }
    let mut markers = Vec::new();
    let mut kept = None;
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if is_chunk_name(&name) {
            if std::fs::remove_file(e.path()).is_err() && e.path().exists() {
                kept.get_or_insert(name);
            }
        } else if name.starts_with(CHECKPOINT) {
            markers.push(e.path());
        }
    }
    if let Some(name) = kept {
        // The checkpoint stays: the folder is still ours, for the next sweep.
        return Removal::Kept(name);
    }
    // The checkpoint last: until it goes, the folder is still known as ours.
    markers.sort_by_key(|p| p.file_name().is_some_and(|n| n == CHECKPOINT));
    for m in markers {
        let _ = std::fs::remove_file(m);
    }
    if dir.join(CHECKPOINT).exists() {
        return Removal::Kept(CHECKPOINT.into());
    }
    // Only an empty folder is removed: a file we don't name keeps it.
    let _ = std::fs::remove_dir(dir);
    Removal::Removed
}

/// Whether the read in `dir` can still be resumed by someone: ours, this
/// format, under 24 hours old, with something read. A newer format is kept
/// too (another version's, not ours to judge).
fn worth_keeping(dir: &Path, now: i64) -> bool {
    match Checkpoint::peek(dir) {
        Peek::Ours(cp) => cp.expired(now).is_none(),
        Peek::Format(f) => f > u64::from(FORMAT),
        Peek::NotOurs | Peek::Damaged(_) => false,
    }
}

/// Removes every earlier read in `root` that no process is using and that
/// can't be resumed ([`worth_keeping`]). Returns how many there were.
/// [`Folder::open`] sweeps all but its own domain's; the app and
/// `pathwarden collect` sweep when they start.
pub(super) fn sweep(root: &Path) -> usize {
    sweep_except(root, now(), None)
}

fn sweep_except(root: &Path, now: i64, except: Option<&Path>) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
        // Not followed: a link or junction is not ours.
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = e.path();
        if except.is_some_and(|x| x == dir) || worth_keeping(&dir, now) {
            continue;
        }
        if remove_ours(&dir) == Removal::Removed {
            n += 1;
        }
    }
    n
}

/// A read of `domain` in `root` that stopped and can be resumed by the
/// sign-in `sign_in` ([`crate::sign_in_key`], keyed into [`Key::sign_in`]),
/// without connecting: ours, this format, under 24 hours old, its domain
/// controller's database known, not in use. Whether the domain controller
/// is the same is known only once connected.
pub(super) fn stopped(root: &Path, domain: &str, sign_in: &str, at: i64) -> Option<Checkpoint> {
    let dir = domain_dir(root, domain);
    let Peek::Ours(cp) = Checkpoint::peek(&dir) else {
        return None;
    };
    let key = root_key(root, false).ok().flatten()?;
    (cp.expired(at).is_none()
        && cp.key.sign_in == keyed(&key, sign_in)
        && cp
            .key
            .domain
            .eq_ignore_ascii_case(domain.trim().trim_end_matches('.'))
        && !locked(&dir))
    .then_some(*cp)
}

/// Free bytes for this account on the volume holding `dir`.
pub(super) type FreeSpace = fn(&Path) -> Option<u64>;

#[cfg(windows)]
#[allow(unsafe_code)]
pub(super) fn free_space(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let mut free = 0u64;
    // SAFETY: `wide` is NUL-terminated and outlives the call; `free` is a
    // valid u64 out-parameter; the other two may be null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

/// Unknown off Windows: not checked.
#[cfg(not(windows))]
pub(super) fn free_space(_dir: &Path) -> Option<u64> {
    None
}

/// What a read of `entries` entries needs on disk: entries × bytes per
/// entry on disk × 1.1, or [`MIN_ROOM`] for the zip if that is more (the
/// read is removed before the zip is written).
pub(super) fn needed(entries: u64, entry_bytes: Option<u64>) -> u64 {
    let per = entry_bytes
        .filter(|&b| b > 0)
        .unwrap_or(DEFAULT_ENTRY_BYTES);
    // `as` saturates.
    ((entries as f64 * per as f64 * 1.1) as u64).max(MIN_ROOM)
}

/// `C:` for a folder on drive C, else the folder.
pub(super) fn place(dir: &Path) -> String {
    use std::path::{Component, Prefix};
    match dir.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                format!("{}:", char::from(d).to_ascii_uppercase())
            }
            _ => dir.display().to_string(),
        },
        _ => dir.display().to_string(),
    }
}

/// Refuses when the volume holding `dir` has less than `need` free.
pub(super) fn check_space(dir: &Path, need: u64, free: FreeSpace) -> Result<(), NoSpace> {
    match free(dir) {
        Some(f) if f < need => Err(NoSpace {
            place: place(dir),
            needed: need,
            free: f,
        }),
        _ => Ok(()),
    }
}

/// Our folder for this read. Dropping it removes our files from it, unless
/// the read stopped with something read: then they stay for resuming.
pub(super) struct Folder {
    dir: PathBuf,
    lock: Option<std::fs::File>,
    /// Removed on drop whatever it holds: the read is complete (and the
    /// parse has it), or must not be resumed.
    remove: bool,
}

/// [`LOCK`], made (or a crashed read's, reused) and locked: another
/// process's sweep leaves the folder alone while it is held. Taken, it is
/// tried once more (a sweep's [`locked`] holds it for an instant).
fn hold_lock(dir: &Path) -> std::io::Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK))?;
    let take = || {
        f.try_lock().map_err(|e| match e {
            std::fs::TryLockError::Error(e) => e,
            std::fs::TryLockError::WouldBlock => std::io::Error::other("the lock is taken"),
        })
    };
    if take().is_err() {
        std::thread::sleep(Duration::from_millis(100));
        take()?;
    }
    Ok(f)
}

/// [`locked`], asked again after an instant: another process's check may
/// have held the lock then.
fn locked_twice(dir: &Path) -> bool {
    locked(dir) && {
        std::thread::sleep(Duration::from_millis(100));
        locked(dir)
    }
}

/// What [`Folder::open`] found.
pub(super) struct Opened {
    pub folder: Folder,
    /// The checkpoint the read goes on with: the earlier one when resumed.
    pub checkpoint: Checkpoint,
    /// Earlier reads of other domains swept.
    pub swept: usize,
    pub resumed: bool,
    /// Why an earlier read of this domain that was there wasn't resumed
    /// ("it is more than 24 hours old").
    pub replaced: Option<&'static str>,
}

impl Folder {
    /// Sweeps `root`, then makes the folder for `domain` in it, private,
    /// with an empty plan. Returns how many earlier reads were swept.
    #[cfg(test)]
    pub(super) fn create(root: &Path, domain: &str) -> Result<(Self, usize), String> {
        let key = Key {
            domain: domain.trim().to_ascii_lowercase(),
            invocation_id: "00".into(),
            ..Key::default()
        };
        let nc = super::domain_dn(domain);
        let o = Self::open(root, Checkpoint::new(key, &nc, 0, Vec::new()), false)?;
        Ok((o.folder, o.swept))
    }

    /// The folder for `fresh`'s domain in `root` (made private), after
    /// sweeping the other domains' reads that can't be resumed. With
    /// `resume`, an earlier read of the domain with the same key, under 24
    /// hours old, goes on: its `.part` files and the chunks it hadn't
    /// finished are removed, to be read again, and so is its head (one
    /// Base search: the domain object as it is now, with its permissions).
    /// Otherwise the earlier read is removed and `fresh` starts.
    pub(super) fn open(root: &Path, fresh: Checkpoint, resume: bool) -> Result<Opened, String> {
        let domain = fresh.key.domain.clone();
        let cannot = |what: &Path, e: std::io::Error| {
            format!("cannot keep the read in {}: {e}", what.display())
        };
        ensure_root(root).map_err(|e| cannot(root, e))?;
        let at = now();
        let dir = domain_dir(root, &domain);
        let swept = sweep_except(root, at, Some(&dir));
        let in_use = || {
            format!(
                "another collection of {} is reading into {}. Wait for it to finish.",
                domain.trim(),
                dir.display()
            )
        };
        let mut replaced = None;
        if dir.join(CHECKPOINT).is_file() {
            if locked_twice(&dir) {
                return Err(in_use());
            }
            let why = match Checkpoint::peek(&dir) {
                Peek::Ours(cp) => match cp.expired(at).or_else(|| cp.key.differs(&fresh.key)) {
                    None if resume => {
                        let lock = hold_lock(&dir).map_err(|_| in_use())?;
                        let folder = Self {
                            dir,
                            lock: Some(lock),
                            remove: false,
                        };
                        let mut cp = *cp;
                        for c in cp.chunks.iter_mut().filter(|c| c.kind == Kind::Head) {
                            c.state = State::Todo;
                            c.entries = 0;
                            c.bytes = 0;
                            c.counts.clear();
                        }
                        cp.retotal();
                        cp.save(&folder.dir).map_err(|e| cannot(&folder.dir, e))?;
                        folder.clear_unfinished(&cp);
                        return Ok(Opened {
                            folder,
                            checkpoint: cp,
                            swept,
                            resumed: true,
                            replaced: None,
                        });
                    }
                    None => Some("resuming it wasn't asked for"),
                    Some(why) => Some(why),
                },
                Peek::Format(f) if f > u64::from(FORMAT) => {
                    Some("it was written by a newer Pathwarden")
                }
                Peek::Format(_) => Some("it was written by an older Pathwarden"),
                Peek::Damaged(_) => Some("its checkpoint is damaged"),
                Peek::NotOurs => None,
            };
            replaced = why;
            match remove_ours(&dir) {
                Removal::InUse => return Err(in_use()),
                Removal::Kept(name) => {
                    return Err(format!(
                        "cannot remove the last read of {} from {}: another program has {name} \
                         open. Try again once it is closed.",
                        domain.trim(),
                        dir.display()
                    ))
                }
                Removal::NotOurs | Removal::Removed => {}
            }
        }
        if dir.exists() {
            return Err(format!(
                "cannot keep the read in {}: the folder is already there. If no other \
                 collection of {} is running, remove it.",
                dir.display(),
                domain.trim()
            ));
        }
        pathwarden_core::perms::create_private_dir(&dir).map_err(|e| cannot(&dir, e))?;
        let lock = match hold_lock(&dir) {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                return Err(cannot(&dir, e));
            }
        };
        // The marker next: from here on, the sweep knows the folder.
        let folder = Self {
            dir,
            lock: Some(lock),
            remove: false,
        };
        if let Err(e) = fresh.save(&folder.dir) {
            return Err(cannot(&folder.dir, e));
        }
        Ok(Opened {
            folder,
            checkpoint: fresh,
            swept,
            resumed: false,
            replaced,
        })
    }

    /// Removes every `.part`, and the `.seg` of each chunk not done: a
    /// chunk the checkpoint doesn't call done is read again, never trusted.
    fn clear_unfinished(&self, cp: &Checkpoint) {
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some((id, seg)) = chunk_name(&name) else {
                continue;
            };
            let done = cp.chunks.iter().any(|c| c.id == id && c.is_done());
            if !seg || !done {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.dir
    }

    /// Removes the folder when dropped, whatever it holds.
    pub(super) fn remove_on_drop(&mut self) {
        self.remove = true;
    }

    /// Whether dropping it now keeps it for resuming: a chunk is done, and
    /// the read can be resumed ([`Checkpoint::expired`]).
    pub(super) fn resumable(&self) -> bool {
        !self.remove
            && matches!(Checkpoint::peek(&self.dir), Peek::Ours(cp) if cp.expired(now()).is_none())
    }

    /// As a crash leaves it: the lock closed, every file still there.
    #[cfg(test)]
    pub(super) fn crash(mut self) {
        drop(self.lock.take());
        std::mem::forget(self);
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let keep = self.resumable();
        drop(self.lock.take());
        if keep {
            // A stopped read: kept for resuming, or for the sweep.
            return;
        }
        // A chunk another program holds stays for the next sweep.
        if remove_ours(&self.dir) == Removal::NotOurs {
            // Before its checkpoint was written.
            let _ = std::fs::remove_file(self.dir.join(LOCK));
            let _ = std::fs::remove_file(self.dir.join(CHECKPOINT_TMP));
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

enum Cmd {
    Begin {
        id: u32,
        nc: String,
    },
    Page(u32, Vec<LdapSearchEntry>),
    End(u32, BTreeMap<String, u64>),
    /// The chunk failed: its `.part` goes, and it stays to do.
    Abort(u32),
}

/// What [`Writer::finish`] wrote: every done chunk, those of the read it
/// resumed included.
#[derive(Debug, Clone)]
pub(super) struct Written {
    pub dir: PathBuf,
    pub chunks: usize,
    pub entries: u64,
    pub bytes: u64,
    /// Time the writer thread spent writing.
    pub busy: Duration,
    /// When the read started, if it was resumed (Unix time).
    pub resumed_from: Option<i64>,
}

/// What the writer has done so far, for the read to look at while it runs.
#[derive(Debug, Default)]
pub(super) struct WriteStats {
    /// Bytes on disk.
    pub written: AtomicU64,
    /// The disk filled up.
    pub full: AtomicBool,
    /// Entries the read is expected to have (0: not known), for the
    /// checkpoint.
    pub expected: AtomicU64,
}

/// A failure the tests inject into the writer.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum FailAt {
    /// At page `n` (from 1), with this error.
    Page(u64, std::io::ErrorKind),
    /// After chunk `id`'s `.seg` is renamed, before the checkpoint says it
    /// is done: a crash between the two.
    AfterRename(u32),
}

/// Writes chunks on a thread of its own, fed pages over a short queue.
pub(super) struct Writer {
    tx: Option<mpsc::SyncSender<Cmd>>,
    thread: Option<JoinHandle<Result<Written, String>>>,
    stats: Arc<WriteStats>,
    dir: PathBuf,
}

impl Writer {
    /// A writer for one stream.
    #[cfg(test)]
    pub(super) fn start(folder: &Folder) -> Result<Self, String> {
        Self::start_with(folder, None, 1)
    }

    /// A writer for `streams` streams reading at once: [`WRITE_QUEUE`]
    /// pages each may wait.
    pub(super) fn for_streams(folder: &Folder, streams: usize) -> Result<Self, String> {
        Self::start_with(folder, None, streams)
    }

    /// A writer that fails with `kind` at page `page`.
    #[cfg(test)]
    pub(super) fn failing(
        folder: &Folder,
        page: u64,
        kind: std::io::ErrorKind,
    ) -> Result<Self, String> {
        Self::start_with(folder, Some(FailAt::Page(page, kind)), 1)
    }

    /// A writer that stops after renaming chunk `id`, as a crash would.
    #[cfg(test)]
    pub(super) fn crashing_after(folder: &Folder, id: u32) -> Result<Self, String> {
        Self::start_with(folder, Some(FailAt::AfterRename(id)), 1)
    }

    /// [`Writer::for_streams`] that stops after renaming chunk `id`.
    #[cfg(test)]
    pub(super) fn crashing_after_for(
        folder: &Folder,
        id: u32,
        streams: usize,
    ) -> Result<Self, String> {
        Self::start_with(folder, Some(FailAt::AfterRename(id)), streams)
    }

    fn start_with(
        folder: &Folder,
        fail_at: Option<FailAt>,
        streams: usize,
    ) -> Result<Self, String> {
        let dir = folder.dir.clone();
        let checkpoint = Checkpoint::load(&dir)?;
        let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE * streams.max(1));
        let stats = Arc::new(WriteStats::default());
        stats
            .written
            .store(checkpoint.totals.bytes, Ordering::Relaxed);
        if let Some(e) = checkpoint.expected {
            stats.expected.store(e, Ordering::Relaxed);
        }
        let thread = {
            let stats = stats.clone();
            let dir = dir.clone();
            std::thread::Builder::new()
                .name("pathwarden-cache-write".into())
                .spawn(move || write_chunks(dir, checkpoint, rx, &stats, fail_at))
                .map_err(|e| format!("cannot start writing the read: {e}"))?
        };
        Ok(Self {
            tx: Some(tx),
            thread: Some(thread),
            stats,
            dir,
        })
    }

    pub(super) fn stats(&self) -> Arc<WriteStats> {
        self.stats.clone()
    }

    /// The read's folder.
    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    fn send(&mut self, cmd: Cmd) -> Result<(), String> {
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(cmd).is_ok());
        if sent {
            Ok(())
        } else {
            // The thread stopped: its error says why.
            Err(self
                .stop()
                .err()
                .unwrap_or_else(|| "the read's writer stopped".into()))
        }
    }

    /// Starts chunk `id` (a chunk not in the plan is added, whole), reading
    /// naming context `nc`. Whatever an earlier try left of it goes first.
    pub(super) fn begin(&mut self, id: u32, nc: &str) -> Result<(), String> {
        self.send(Cmd::Begin {
            id,
            nc: nc.to_string(),
        })
    }

    /// A page of chunk `id`. Blocks while the writer has [`WRITE_QUEUE`]
    /// pages a stream waiting: the read waits for the disk (on the async
    /// runtime's thread, as the read did when it kept everything in memory
    /// and stalled on nothing).
    pub(super) fn page(&mut self, id: u32, entries: Vec<LdapSearchEntry>) -> Result<(), String> {
        self.send(Cmd::Page(id, entries))
    }

    /// Ends chunk `id`: synced, renamed to `.seg`, then the checkpoint, with
    /// its entries by type.
    pub(super) fn end(&mut self, id: u32, counts: BTreeMap<String, u64>) -> Result<(), String> {
        self.send(Cmd::End(id, counts))
    }

    /// Drops chunk `id` as it is: its `.part` goes, and it stays to do.
    pub(super) fn abort(&mut self, id: u32) -> Result<(), String> {
        self.send(Cmd::Abort(id))
    }

    pub(super) fn finish(mut self) -> Result<Written, String> {
        self.stop()
    }

    fn stop(&mut self) -> Result<Written, String> {
        drop(self.tx.take());
        match self.thread.take().map(JoinHandle::join) {
            Some(Ok(r)) => r,
            Some(Err(_)) => Err("the read's writer crashed".into()),
            None => Err("the read's writer stopped".into()),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The disk (or the user's quota) is full: `ERROR_HANDLE_DISK_FULL` (39) and
/// `ERROR_DISK_FULL` (112) on Windows.
pub(super) fn is_disk_full(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::StorageFull
        || e.kind() == std::io::ErrorKind::QuotaExceeded
        || (cfg!(windows) && matches!(e.raw_os_error(), Some(39 | 112)))
}

fn write_chunks(
    dir: PathBuf,
    mut checkpoint: Checkpoint,
    rx: mpsc::Receiver<Cmd>,
    stats: &WriteStats,
    fail_at: Option<FailAt>,
) -> Result<Written, String> {
    let failed = |e: &(dyn std::error::Error + 'static)| {
        if e.downcast_ref::<std::io::Error>().is_some_and(is_disk_full) {
            stats.full.store(true, Ordering::Relaxed);
        }
        format!("cannot write the read to disk: {e}")
    };
    // Resumed: when the read started.
    let resumed_from = checkpoint
        .chunks
        .iter()
        .any(Chunk::is_done)
        .then(|| checkpoint.started_at())
        .flatten();
    let mut busy = Duration::ZERO;
    // The chunks being written, one a stream: their storage, entries and
    // `.part` bytes.
    let mut open: BTreeMap<u32, (DiskStorage, u64, u64)> = BTreeMap::new();
    let in_parts = |open: &BTreeMap<u32, (DiskStorage, u64, u64)>| -> u64 {
        open.values().map(|(_, _, b)| *b).sum()
    };
    // The DN keys of the open chunks that keep them ([`keys_file`]).
    let mut keys: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut pages = 0u64;
    while let Ok(cmd) = rx.recv() {
        let started = Instant::now();
        match cmd {
            Cmd::Begin { id, nc } => {
                if !checkpoint.chunks.iter().any(|c| c.id == id) {
                    checkpoint
                        .chunks
                        .push(Chunk::new(id, &nc, Kind::Whole, None, None));
                }
                // Begun again (a retry): the earlier try is closed first.
                drop(open.remove(&id));
                keys.remove(&id);
                if checkpoint
                    .chunks
                    .iter()
                    .any(|c| c.id == id && sees_dns(c.kind))
                {
                    keys.insert(id, Vec::new());
                }
                // An earlier try's leftovers: read again, never trusted.
                for ext in ["part", "seg", "dns"] {
                    let f = chunk_file(&dir, id, ext);
                    if f.exists() {
                        std::fs::remove_file(&f).map_err(|e| failed(&e))?;
                    }
                }
                let storage =
                    DiskStorage::new(chunk_file(&dir, id, "part")).map_err(|e| failed(&*e))?;
                open.insert(id, (storage, 0, 0));
            }
            Cmd::Page(id, page) => {
                let Some((storage, n, part)) = open.get_mut(&id) else {
                    return Err("the read's writer got a page outside a chunk".into());
                };
                pages += 1;
                if let Some(FailAt::Page(at, kind)) = fail_at {
                    if at == pages {
                        return Err(failed(&std::io::Error::from(kind)));
                    }
                }
                let mut chunk_keys = keys.get_mut(&id);
                for entry in page {
                    if let Some(k) = chunk_keys.as_mut() {
                        k.extend_from_slice(&dn_key(&entry.dn).to_le_bytes());
                    }
                    storage.add(entry).map_err(|e| failed(&*e))?;
                    *n += 1;
                }
                *part = std::fs::metadata(chunk_file(&dir, id, "part")).map_or(0, |m| m.len());
                stats
                    .written
                    .store(checkpoint.totals.bytes + in_parts(&open), Ordering::Relaxed);
            }
            Cmd::Abort(id) => {
                drop(open.remove(&id));
                keys.remove(&id);
                let part = chunk_file(&dir, id, "part");
                if part.exists() {
                    std::fs::remove_file(&part).map_err(|e| failed(&e))?;
                }
                stats
                    .written
                    .store(checkpoint.totals.bytes + in_parts(&open), Ordering::Relaxed);
            }
            Cmd::End(id, counts) => {
                let Some((storage, n, _)) = open.remove(&id) else {
                    return Err("the read's writer ended no chunk".into());
                };
                storage.finish().map_err(|e| failed(&*e))?;
                let part = chunk_file(&dir, id, "part");
                // DiskStorage closes its file in `finish`: reopened to sync it.
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&part)
                    .map_err(|e| failed(&e))?;
                file.sync_all().map_err(|e| failed(&e))?;
                let mut bytes = file.metadata().map_err(|e| failed(&e))?.len();
                drop(file);
                // Its keys first: a done chunk has them.
                if let Some(k) = keys.remove(&id) {
                    use std::io::Write;
                    let mut f =
                        std::fs::File::create(keys_file(&dir, id)).map_err(|e| failed(&e))?;
                    f.write_all(&k).map_err(|e| failed(&e))?;
                    f.sync_all().map_err(|e| failed(&e))?;
                    bytes += k.len() as u64;
                }
                std::fs::rename(&part, chunk_file(&dir, id, "seg")).map_err(|e| failed(&e))?;
                if matches!(fail_at, Some(FailAt::AfterRename(at)) if at == id) {
                    return Err("the read stopped (a crash, for the tests)".into());
                }
                if let Some(c) = checkpoint.chunks.iter_mut().find(|c| c.id == id) {
                    c.state = State::Done;
                    c.entries = n;
                    c.bytes = bytes;
                    c.counts = counts;
                }
                let expected = stats.expected.load(Ordering::Relaxed);
                if expected > 0 {
                    checkpoint.expected = Some(expected);
                }
                checkpoint.retotal();
                checkpoint.updated = pathwarden_core::time::format_rfc3339(now());
                checkpoint.save(&dir).map_err(|e| failed(&e))?;
                stats
                    .written
                    .store(checkpoint.totals.bytes + in_parts(&open), Ordering::Relaxed);
            }
        }
        busy += started.elapsed();
    }
    if !open.is_empty() {
        // Stopped mid-chunk: its `.part` stays unread, and goes with the folder.
        return Err("the read stopped before its last chunk was written".into());
    }
    Ok(Written {
        dir,
        chunks: checkpoint.totals.done as usize,
        entries: checkpoint.totals.entries,
        bytes: checkpoint.totals.bytes,
        busy,
        resumed_from,
    })
}

enum Item {
    Entry(LdapSearchEntry),
    Failed(String),
    Done,
}

/// The done chunks of a read, in order, decoded on a read-ahead thread. An
/// [`rusthound_ce::EntrySource`] through [`super::Counting`].
pub(super) struct Reader {
    rx: Option<mpsc::Receiver<Item>>,
    thread: Option<JoinHandle<()>>,
    finished: bool,
    /// Microseconds the thread took, once it is done.
    took: Arc<AtomicU64>,
    /// Entries left out as older versions of an object in the delta or the
    /// rest chunk (the domain head read again with its window isn't
    /// counted).
    dropped: Arc<AtomicU64>,
}

/// What reading a chunk back leaves out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Nothing.
    Keep,
    /// The head, and every object the delta or the rest chunk holds a newer
    /// version of.
    Window,
    /// The head, deleted objects, and every object the rest chunk holds a
    /// newer version of.
    Delta,
    /// The head.
    Rest,
}

/// An object's identity across chunks: its `objectGUID` (raw, whichever
/// way ldap3 filed it), else its DN in lower case.
fn identity(e: &LdapSearchEntry) -> Vec<u8> {
    if let Some(g) = e.bin_attrs.get("objectGUID").and_then(|v| v.first()) {
        return g.clone();
    }
    if let Some(g) = e.attrs.get("objectGUID").and_then(|v| v.first()) {
        return g.as_bytes().to_vec();
    }
    let mut dn = b"dn:".to_vec();
    dn.extend(e.dn.to_ascii_lowercase().into_bytes());
    dn
}

impl Reader {
    /// Reads the chunks `checkpoint.json` in `dir` lists as done, Schema
    /// first, the domain head next, then its windows, delta and rest chunk,
    /// then the other contexts. A chunk not done (or a `.part`) is never
    /// opened.
    pub(super) fn open(dir: &Path) -> Result<Self, String> {
        let cp = Checkpoint::load(dir)?;
        let mut done: Vec<&Chunk> = cp.chunks.iter().filter(|c| c.is_done()).collect();
        done.sort_by_key(|c| (c.rank(&cp.domain_nc), c.id));
        let chunks: Vec<(PathBuf, u64, Role)> = done
            .iter()
            .map(|c| {
                let role = match c.kind {
                    Kind::Window => Role::Window,
                    Kind::Delta => Role::Delta,
                    Kind::Rest => Role::Rest,
                    Kind::Head | Kind::Whole => Role::Keep,
                };
                (chunk_file(dir, c.id, "seg"), c.entries, role)
            })
            .collect();
        if let Some((missing, _, _)) = chunks.iter().find(|(p, _, _)| !p.is_file()) {
            return Err(format!(
                "the read on disk is missing {}",
                missing.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
        let head = cp.domain_nc.clone();
        let (tx, rx) = mpsc::sync_channel(READ_AHEAD);
        let took = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let thread = {
            let took = took.clone();
            let dropped = dropped.clone();
            std::thread::Builder::new()
                .name("pathwarden-cache-read".into())
                .spawn(move || {
                    let started = Instant::now();
                    let item = read_chunks(&chunks, &head, &tx, &dropped);
                    took.store(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                    if let Some(item) = item {
                        let _ = tx.send(item);
                    }
                })
                .map_err(|e| format!("cannot start reading the read back: {e}"))?
        };
        Ok(Self {
            rx: Some(rx),
            thread: Some(thread),
            finished: false,
            took,
            dropped,
        })
    }

    /// How long reading back took, once it is done.
    pub(super) fn took(&self) -> Arc<AtomicU64> {
        self.took.clone()
    }

    /// Entries left out ([`Role`]), once it is done.
    pub(super) fn dropped(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }
}

/// Every entry of `path`, or why not; its count must be `expected` (a cut
/// length prefix reads as a clean end).
fn each_entry(
    path: &Path,
    expected: u64,
    mut f: impl FnMut(LdapSearchEntry) -> bool,
) -> Result<bool, String> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let reader = DiskStorageReader::<LdapSearchEntry>::from_path(path)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    let mut n = 0u64;
    for item in reader {
        let entry = item.map_err(|e| format!("cannot read {name}: {e}"))?;
        n += 1;
        if !f(entry) {
            return Ok(false);
        }
    }
    if n != expected {
        return Err(format!("{name} holds {n} entries, not {expected}"));
    }
    Ok(true)
}

/// Sends every entry; returns the last item to send (`Done`, or why not),
/// or `None` when the reader went away.
/// Whether an entry is a deleted object (`isDeleted: TRUE`).
pub(super) fn is_deleted(e: &LdapSearchEntry) -> bool {
    e.attrs
        .get("isDeleted")
        .is_some_and(|v| v.iter().any(|x| x.eq_ignore_ascii_case("TRUE")))
}

fn read_chunks(
    chunks: &[(PathBuf, u64, Role)],
    head: &str,
    tx: &mpsc::SyncSender<Item>,
    dropped: &AtomicU64,
) -> Option<Item> {
    let is_head = |e: &LdapSearchEntry| !head.is_empty() && e.dn.eq_ignore_ascii_case(head);
    // The objects the delta and the rest chunk have a newer version of: a
    // few, usually.
    let mut in_delta: HashSet<Vec<u8>> = HashSet::new();
    let mut in_rest: HashSet<Vec<u8>> = HashSet::new();
    for (path, expected, role) in chunks {
        let into = match role {
            Role::Delta => &mut in_delta,
            Role::Rest => &mut in_rest,
            Role::Keep | Role::Window => continue,
        };
        let read = each_entry(path, *expected, |e| {
            if !is_head(&e) {
                into.insert(identity(&e));
            }
            true
        });
        if let Err(why) = read {
            return Some(Item::Failed(why));
        }
    }
    for (path, expected, role) in chunks {
        let read = each_entry(path, *expected, |e| {
            // The head is read on its own, first; an object deleted during
            // the read (the delta asks for deleted objects) is left out,
            // with its earlier version.
            if *role != Role::Keep && is_head(&e) || *role == Role::Delta && is_deleted(&e) {
                return true;
            }
            let newer = match role {
                Role::Window => {
                    let id = identity(&e);
                    in_delta.contains(&id) || in_rest.contains(&id)
                }
                Role::Delta => in_rest.contains(&identity(&e)),
                Role::Keep | Role::Rest => false,
            };
            if newer {
                dropped.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            tx.send(Item::Entry(e)).is_ok()
        });
        match read {
            Ok(true) => {}
            Ok(false) => return None,
            Err(why) => return Some(Item::Failed(why)),
        }
    }
    Some(Item::Done)
}

impl Iterator for Reader {
    type Item = Result<LdapSearchEntry, Box<dyn std::error::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let item = self.rx.as_ref()?.recv();
        match item {
            Ok(Item::Entry(e)) => Some(Ok(e)),
            Ok(Item::Done) => {
                self.finished = true;
                None
            }
            Ok(Item::Failed(why)) => {
                self.finished = true;
                Some(Err(why.into()))
            }
            Err(_) => {
                self.finished = true;
                Some(Err("reading the read back stopped unexpectedly".into()))
            }
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        // The thread ends at its next send; joined so no file stays open.
        drop(self.rx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_names() {
        assert!(is_chunk_name("chunk-0001.seg"));
        assert!(is_chunk_name("chunk-12345.part"));
        assert_eq!(chunk_name("chunk-0042.seg"), Some((42, true)));
        assert_eq!(chunk_name("chunk-0042.part"), Some((42, false)));
        assert_eq!(chunk_name("chunk-0042.dns"), Some((42, true)));
        assert!(!is_chunk_name("chunk-.seg"));
        assert!(!is_chunk_name("chunk-01a.seg"));
        assert!(!is_chunk_name("chunk-0001.seg.bak"));
        assert!(!is_chunk_name("notes.txt"));
    }

    #[test]
    fn domain_folders() {
        let root = Path::new("r");
        assert_eq!(
            domain_dir(root, "Contoso.Local."),
            root.join("contoso.local")
        );
        assert_eq!(domain_dir(root, ".."), root.join("_"));
        assert_eq!(domain_dir(root, "a/b"), root.join("a_b"));
        // Device names get a prefix.
        assert_eq!(domain_dir(root, "CON.local"), root.join("_con.local"));
        assert_eq!(domain_dir(root, "nul"), root.join("_nul"));
        assert_eq!(domain_dir(root, "com1.x"), root.join("_com1.x"));
        assert_eq!(domain_dir(root, "com10.x"), root.join("com10.x"));
        assert_eq!(
            domain_dir(root, "console.local"),
            root.join("console.local")
        );
    }

    #[test]
    fn needed_space() {
        // Never under the zip's room.
        assert_eq!(needed(0, None), MIN_ROOM);
        assert_eq!(needed(10, Some(0)), MIN_ROOM);
        // GOAD's north: 3,650 entries of 600 bytes, 2.4 MB: the zip's room.
        assert_eq!(needed(3650, Some(600)), MIN_ROOM);
        assert_eq!(needed(100_000, Some(1000)), 110_000_000);
        assert_eq!(needed(1_000_000, Some(10_000)), 11_000_000_000);
        assert_eq!(needed(1_000_000, None), (1e6 * 16384.0 * 1.1) as u64);
        assert_eq!(needed(u64::MAX, Some(u64::MAX)), u64::MAX);
    }

    #[test]
    fn disk_full_errors() {
        use std::io::{Error, ErrorKind};
        assert!(is_disk_full(&Error::from(ErrorKind::StorageFull)));
        assert!(!is_disk_full(&Error::from(ErrorKind::PermissionDenied)));
        if cfg!(windows) {
            assert!(is_disk_full(&Error::from_raw_os_error(112)));
            assert!(is_disk_full(&Error::from_raw_os_error(39)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn places_and_free_space() {
        assert_eq!(place(Path::new(r"c:\Users\x")), "C:");
        assert_eq!(place(Path::new(r"\\?\D:\x")), "D:");
        assert!(free_space(&std::env::temp_dir()).is_some_and(|f| f > 0));
    }

    /// Head, 64 even windows of [1, h], the delta last; the small naming
    /// contexts whole, in their order.
    #[test]
    fn keyed_hashes_are_hmacs_with_the_caches_key() {
        // RFC 4231, test case 2.
        assert_eq!(
            keyed(b"Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let root = std::env::temp_dir().join(format!("pw-cache-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(root_key(&root, false).unwrap(), None);
        let k = root_key(&root, true).unwrap().unwrap();
        assert_eq!(k.len(), 32);
        assert_eq!(root_key(&root, false).unwrap(), Some(k.clone()));
        assert!(pathwarden_core::perms::is_private_dir(&root));
        // Another cache, another key: the same name, another hash.
        let other = root.join("other");
        let k2 = root_key(&other, true).unwrap().unwrap();
        assert_ne!(keyed(&k, "contoso\\svc"), keyed(&k2, "contoso\\svc"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_plan_splits_the_domain_by_usn() {
        let ncs: Vec<String> = [
            "CN=Schema,CN=Configuration,DC=x",
            "DC=x",
            "CN=Configuration,DC=x",
        ]
        .map(String::from)
        .to_vec();
        let p = plan(&ncs, "DC=x", Some(6400));
        assert_eq!(p.len(), 1 + 1 + 64 + 1 + 1 + 1);
        assert_eq!(
            (p[0].kind, p[0].nc.as_str()),
            (Kind::Whole, ncs[0].as_str())
        );
        assert_eq!(p[1].kind, Kind::Head);
        assert!(p[1].base_only());
        assert_eq!((p[2].usn_lo, p[2].usn_hi), (Some(1), Some(100)));
        assert_eq!((p[65].usn_lo, p[65].usn_hi), (Some(6301), Some(6400)));
        assert_eq!(p[66].kind, Kind::Whole);
        let delta = &p[p.len() - 2];
        assert_eq!(
            (delta.kind, delta.usn_lo, delta.usn_hi),
            (Kind::Delta, Some(6401), None)
        );
        // The rest chunk last: the domain whole, no uSN range.
        let rest = p.last().unwrap();
        assert_eq!(
            (rest.kind, rest.nc.as_str(), rest.usn_lo, rest.usn_hi),
            (Kind::Rest, "DC=x", None, None)
        );
        assert!(!rest.base_only() && !rest.shows_deleted());
        assert!(p.iter().enumerate().all(|(i, c)| c.id == i as u32 + 1));
        assert_eq!(
            p[2].filter("(objectClass=*)"),
            "(&(objectClass=*)(uSNChanged>=1)(uSNChanged<=100))"
        );
        assert_eq!(delta.filter("(x=1)"), "(&(x=1)(uSNChanged>=6401))");
        // Uneven: 64 windows of 2 or 3, covering [1, 130] without a gap; a
        // tiny domain gets fewer.
        let p = plan(&ncs, "DC=x", Some(130));
        let windows: Vec<_> = p.iter().filter(|c| c.kind == Kind::Window).collect();
        assert_eq!(windows.len(), 64);
        assert_eq!(windows[0].usn_lo, Some(1));
        assert_eq!(windows.last().unwrap().usn_hi, Some(130));
        assert!(windows
            .windows(2)
            .all(|w| w[0].usn_hi.unwrap() + 1 == w[1].usn_lo.unwrap()));
        assert!(windows
            .iter()
            .all(|w| (2..=3).contains(&(w.usn_hi.unwrap() - w.usn_lo.unwrap() + 1))));
        let p = plan(&ncs, "DC=x", Some(u64::MAX - 1));
        assert_eq!(p[65].usn_hi, Some(u64::MAX - 1));
        assert_eq!(plan(&ncs, "DC=x", Some(5)).len(), 1 + 1 + 5 + 1 + 1 + 1);
        // No snapshot: every context whole.
        assert_eq!(plan(&ncs, "DC=x", None), whole_plan(&ncs));
        // Read back: Schema, head, windows, delta, rest, Configuration,
        // others.
        let p = plan(&ncs, "DC=x", Some(64));
        let mut order: Vec<&Chunk> = p.iter().collect();
        order.sort_by_key(|c| (c.rank("DC=x"), c.id));
        let kinds: Vec<Kind> = order.iter().map(|c| c.kind).collect();
        assert_eq!(kinds[..2], [Kind::Whole, Kind::Head]);
        assert_eq!(kinds[66..], [Kind::Delta, Kind::Rest, Kind::Whole]);
        assert!(order[66].nc.starts_with("DC="));
        assert!(order[67].nc.starts_with("DC="));
        assert!(order[68].nc.starts_with("CN=Configuration"));
    }

    #[test]
    fn how_far_a_read_got() {
        let mut cp = Checkpoint::new(
            Key::default(),
            "DC=x",
            10,
            plan(&["DC=x".into()], "DC=x", Some(10)),
        );
        assert_eq!(cp.percent(), 0);
        for c in cp.chunks.iter_mut().take(6) {
            c.state = State::Done;
            c.entries = 100;
        }
        cp.retotal();
        // 6 of 13 chunks; then 600 of 1,000 entries.
        assert_eq!(cp.percent(), 46);
        cp.expected = Some(1000);
        assert_eq!(cp.percent(), 60);
        cp.expected = Some(10);
        assert_eq!(cp.percent(), 99);
    }
}
