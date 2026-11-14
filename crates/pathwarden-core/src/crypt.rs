//! Encrypting the history (a folder or a git repository) with a passphrase.
//!
//! The format is `age` (<https://age-encryption.org>, the maintained `age`
//! crate), nothing made here:
//!
//! - `.pathwarden-key.age` holds an age X25519 identity, encrypted with the
//!   passphrase (age's scrypt recipient, work factor 2^[`WORK_FACTOR`]).
//! - Every file Pathwarden writes to the history is encrypted to that
//!   identity's public key, as `<name>.age` (`findings.json.age`,
//!   `history/<run>.json.age`, ...), its content starting with a line
//!   that binds it to its path, run and sequence ([`crate::binding`]).
//! - `.pathwarden-encryption` is a plain marker ([`Marker`]): the format
//!   and how to try a passphrase, no secrets. A reader that finds it asks
//!   for the passphrase.
//! - `findings.json` stays as a plain stub whose state version
//!   ([`STUB_VERSION`]) is above any real one, so Pathwarden 0.1.6 and
//!   earlier refuse to record into an encrypted history ("written by a
//!   newer Pathwarden ... upgrade before running") instead of adding plain
//!   files to it.
//!
//! Why a key under the passphrase, and not the passphrase on every file:
//! age's scrypt recipient runs scrypt for each file it opens, so a history
//! of a few hundred runs would take minutes to read at a safe work factor.
//! Here scrypt runs once per process (the key is cached, [`key_for`]), and
//! each file costs an X25519 exchange. Changing the passphrase makes a new
//! key and re-encrypts every file ([`crate::store::Store::change_passphrase`]),
//! so the old passphrase opens only what git history kept from before.
//!
//! The public key is never stored: it is derived from the opened identity,
//! so writing needs the passphrase too, and someone who can push to the
//! repository but lacks the passphrase can't make Pathwarden encrypt to a
//! key of theirs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

pub use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keystore::{self, Source};

/// The plain marker of an encrypted history.
pub const MARKER: &str = ".pathwarden-encryption";
/// The history's key, encrypted with the passphrase.
pub const KEY_FILE: &str = ".pathwarden-key.age";
/// Added to the name of each encrypted file.
pub const SUFFIX: &str = ".age";
/// [`Marker::format`] this version writes, and the newest it reads: 2,
/// every file bound to its path, run and sequence ([`crate::binding`]).
pub const FORMAT: u32 = 2;
/// The marker format of a history encrypted before the binding (0.1.7 to
/// 0.1.9): its files are read without one, and the first write binds them
/// ([`crate::store`] `upgrade_binding`).
pub const UNBOUND_FORMAT: u32 = 1;
/// The scrypt work factor of the key file: N = 2^18 (r = 8, p = 1, so
/// 256 MiB). It runs once per process that opens the history; see
/// docs/running.md for the measured time.
pub const WORK_FACTOR: u8 = 18;
/// The most work a key file may ask for before it is refused: 2^19 (512 MiB,
/// about 1.6 s). Pathwarden writes 2^18; a hostile key file must not cost
/// gigabytes and tens of seconds.
const MAX_WORK_FACTOR: u8 = 19;
/// The shortest passphrase accepted, in characters.
pub const MIN_PASSPHRASE: usize = 12;
/// The longest, in bytes (Windows Credential Manager holds 2,560).
pub const MAX_PASSPHRASE: usize = 1024;
/// The state version in the plain `findings.json` stub of an encrypted
/// history: above any real one, so older versions refuse to record.
pub const STUB_VERSION: u32 = 1000;

/// `.pathwarden-encryption`: what a reader needs to know to ask for a
/// passphrase, and nothing secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Marker {
    /// [`FORMAT`].
    pub format: u32,
    /// Always "age".
    pub cipher: String,
    /// How the files are encrypted.
    pub files: String,
    /// How the key is opened.
    pub key: String,
    /// The key file's scrypt work factor (log2 N).
    pub scrypt_log_n: u8,
    /// For a person who opens the file.
    #[serde(default)]
    pub note: String,
}

impl Marker {
    pub fn new() -> Self {
        Marker {
            format: FORMAT,
            cipher: "age".into(),
            files: format!("age X25519, to the key in {KEY_FILE}"),
            key: format!("age scrypt passphrase, work factor 2^{WORK_FACTOR}"),
            scrypt_log_n: WORK_FACTOR,
            note: "This Pathwarden history is encrypted with a passphrase. Pathwarden 0.2 or \
                   later opens it: `pathwarden history storage passphrase set` stores the \
                   passphrase on a computer. A lost passphrase can't be recovered."
                .into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = serde_json::to_string_pretty(self).expect("a marker serializes");
        text.push('\n');
        text.into_bytes()
    }
}

impl Default for Marker {
    fn default() -> Self {
        Marker::new()
    }
}

/// The plain `findings.json` of an encrypted history ([`STUB_VERSION`]).
pub fn stub() -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "version": STUB_VERSION,
        "findings": {},
        "encrypted": "This history is encrypted (see .pathwarden-encryption). Pathwarden 0.1.7 \
                      or later opens it with its passphrase; older versions refuse it.",
    }))
    .expect("the stub serializes");
    text.push('\n');
    text.into_bytes()
}

/// Whether `bytes` are the stub ([`stub`]), with line endings a checkout
/// may have changed (Git for Windows' `core.autocrlf`).
pub fn is_stub(bytes: &[u8]) -> bool {
    let plain: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'\r').collect();
    plain == stub()
}

/// Why an encrypted history couldn't be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptError {
    /// No passphrase for it here.
    NeedPassphrase,
    /// The passphrase from `Source` doesn't open its key.
    WrongPassphrase(Source),
    /// Encrypted by a newer Pathwarden (its marker's format).
    Newer(u32),
    /// A file (named) that can't be read or decrypted.
    Damaged(String),
}

impl std::fmt::Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::NeedPassphrase => write!(
                f,
                "This history is encrypted, and this computer has no passphrase for it. Store it \
                 with `pathwarden history storage passphrase set`, or set {}.",
                keystore::ENV_VAR
            ),
            CryptError::WrongPassphrase(source) => write!(
                f,
                "That passphrase doesn't open this history ({}).",
                source.words()
            ),
            CryptError::Newer(format) => write!(
                f,
                "This history was encrypted by a newer Pathwarden (encryption format {format}). \
                 Update Pathwarden to read it."
            ),
            CryptError::Damaged(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for CryptError {}

/// Keys opened in this process, by the SHA-256 of their key file: scrypt
/// runs once per key, not per file. Only ever handed out for a history
/// whose own passphrase is known to open it ([`opened_in`], [`key_for`]):
/// a key file copied from another history doesn't open with that
/// history's passphrase here.
fn opened() -> &'static Mutex<HashMap<[u8; 32], Arc<Identity>>> {
    static OPENED: OnceLock<Mutex<HashMap<[u8; 32], Arc<Identity>>>> = OnceLock::new();
    OPENED.get_or_init(Default::default)
}

/// The histories ([`keystore::history_key`]) whose own passphrase opened
/// the key file with this digest in this process: [`key_for`] returns the
/// key for these without looking the passphrase up again.
fn opened_in() -> &'static Mutex<OpenedIn> {
    static IN: OnceLock<Mutex<OpenedIn>> = OnceLock::new();
    IN.get_or_init(Default::default)
}

/// The passphrase that opened each key in this process ([`opened`]'s
/// keys), and where it came from: another folder of the same history (a
/// new clone of one used here before) opens with it too
/// ([`known_passphrase`]).
fn opened_by() -> &'static Mutex<Openers> {
    static BY: OnceLock<Mutex<Openers>> = OnceLock::new();
    BY.get_or_init(Default::default)
}

/// History and key file digest pairs ([`opened_in`]).
type OpenedIn = std::collections::HashSet<(String, [u8; 32])>;

type Openers = HashMap<[u8; 32], (SecretString, Source)>;

fn record_opener(hash: [u8; 32], passphrase: &SecretString, source: Source) {
    opened_by()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(hash)
        .or_insert_with(|| (passphrase.clone(), source));
}

/// Passphrases given in this process (asked for, or about to be stored),
/// by [`keystore::history_key`].
fn given() -> &'static Mutex<HashMap<String, SecretString>> {
    static GIVEN: OnceLock<Mutex<HashMap<String, SecretString>>> = OnceLock::new();
    GIVEN.get_or_init(Default::default)
}

/// Uses `passphrase` for the history in `dir` for the rest of this process,
/// ahead of the environment variable and this computer's store.
pub fn give_passphrase(dir: &Path, passphrase: SecretString) {
    let mut g = given().lock().unwrap_or_else(|e| e.into_inner());
    g.insert(keystore::history_key(dir), passphrase);
}

/// Stops using a passphrase [`give_passphrase`] gave, and every key opened
/// in this process.
pub fn forget_in_process(dir: &Path) {
    given()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&keystore::history_key(dir));
    opened().lock().unwrap_or_else(|e| e.into_inner()).clear();
    opened_in()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    opened_by()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Forgets every passphrase given and every key opened in this process:
/// when the app's last browser session ends, "for this session only"
/// ends with it.
pub fn forget_all_in_process() {
    given().lock().unwrap_or_else(|e| e.into_inner()).clear();
    opened().lock().unwrap_or_else(|e| e.into_inner()).clear();
    opened_in()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    opened_by()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    failed().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Passphrase and key pairs that failed in this process (a digest of
/// both): a wrong stored passphrase costs one scrypt, not one per page.
fn failed() -> &'static Mutex<std::collections::HashSet<[u8; 32]>> {
    static FAILED: OnceLock<Mutex<std::collections::HashSet<[u8; 32]>>> = OnceLock::new();
    FAILED.get_or_init(Default::default)
}

/// `s` as a [`SecretString`] whose buffer is exactly its length, so no
/// copy is left behind by a reallocation; the caller zeroes `s`.
pub fn secret_from(s: &str) -> SecretString {
    let mut exact = String::with_capacity(s.len());
    exact.push_str(s);
    SecretString::from(exact)
}

/// The SHA-256 of `bytes`, in hex.
pub fn digest_hex(bytes: &[u8]) -> String {
    digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of the history's key file, in hex: what a computer pins.
pub fn key_digest(dir: &Path) -> anyhow::Result<String> {
    let path = dir.join(KEY_FILE);
    let bytes = std::fs::read(&path).map_err(|e| {
        CryptError::Damaged(format!(
            "{} can't be read ({e}): the history says it is encrypted, but its key is missing",
            path.display()
        ))
    })?;
    Ok(digest_hex(&bytes))
}

/// The passphrase to try for `dir`, and where it came from.
pub fn passphrase_for(dir: &Path) -> anyhow::Result<Option<(SecretString, Source)>> {
    let key = keystore::history_key(dir);
    if let Some(p) = given().lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(Some((p.clone(), Source::Given)));
    }
    keystore::lookup(dir)
}

/// Where this computer keeps a passphrase for this one history, if it
/// does: given in this process, this account's store or protected file.
/// Not the environment variable or a service credential, which may serve
/// other histories of the same account.
pub fn local_passphrase(dir: &Path) -> anyhow::Result<Option<Source>> {
    if given()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&keystore::history_key(dir))
    {
        return Ok(Some(Source::Given));
    }
    keystore::stored_for_history(dir)
}

/// Whether the history in `dir` is encrypted (its marker is there).
pub fn is_encrypted(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(MARKER)).is_ok_and(|m| m.is_file())
}

/// The marker of the history in `dir`, `None` when it isn't encrypted; an
/// error for a marker this version can't use.
pub fn marker(dir: &Path) -> anyhow::Result<Option<Marker>> {
    if !is_encrypted(dir) {
        return Ok(None);
    }
    let path = dir.join(MARKER);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let m: Marker = serde_json::from_str(&text).map_err(|e| {
        CryptError::Damaged(format!(
            "{} can't be read ({e}); the history's encryption marker is damaged",
            path.display()
        ))
    })?;
    if m.format > FORMAT {
        return Err(CryptError::Newer(m.format).into());
    }
    if m.cipher != "age" {
        return Err(CryptError::Damaged(format!(
            "{} names a cipher Pathwarden doesn't know ({})",
            path.display(),
            m.cipher
        ))
        .into());
    }
    Ok(Some(m))
}

/// A new key for a history, and its key file's bytes (the key encrypted
/// with `passphrase`).
pub fn new_key(passphrase: &SecretString) -> anyhow::Result<(Arc<Identity>, Vec<u8>)> {
    check_passphrase(passphrase).map_err(anyhow::Error::msg)?;
    let id = Identity::generate();
    let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
    recipient.set_work_factor(WORK_FACTOR);
    let bytes = age::encrypt(&recipient, id.to_string().expose_secret().as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypting the history's key: {e}"))?;
    let id = Arc::new(id);
    opened()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(digest(&bytes), id.clone());
    record_opener(digest(&bytes), passphrase, Source::Given);
    Ok((id, bytes))
}

/// Whether `passphrase` may be used: long enough, not too long.
pub fn check_passphrase(passphrase: &SecretString) -> Result<(), String> {
    let p = passphrase.expose_secret();
    if p.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "The passphrase must be at least {MIN_PASSPHRASE} characters: it is all that protects \
             the history from anyone who can read the folder or repository."
        ));
    }
    if p.len() > MAX_PASSPHRASE {
        return Err(format!(
            "The passphrase must be at most {MAX_PASSPHRASE} bytes."
        ));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The work factor (log2 N) the key file's scrypt stanza names, from its
/// plain-text age header: `-> scrypt <salt> <log_n>`. `None` when there is
/// no such line (age then refuses the file).
fn scrypt_work_factor(bytes: &[u8]) -> Option<u8> {
    let header = bytes
        .split(|b| *b == b'\n')
        .take_while(|l| !l.starts_with(b"---"));
    header
        .filter_map(|l| std::str::from_utf8(l).ok())
        .find_map(|l| l.strip_prefix("-> scrypt "))
        .and_then(|rest| rest.split(' ').nth(1))
        .and_then(|n| n.trim().parse().ok())
}

/// Opens the key file `bytes` with `passphrase`.
pub fn open_key(
    bytes: &[u8],
    passphrase: &SecretString,
    source: Source,
) -> Result<Arc<Identity>, CryptError> {
    let hash = digest(bytes);
    let tried: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(hash);
        h.update(passphrase.expose_secret().as_bytes());
        h.finalize().into()
    };
    if failed()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&tried)
    {
        return Err(CryptError::WrongPassphrase(source));
    }
    // Less work than Pathwarden writes makes guessing the passphrase
    // offline cheap for anyone who can read the history: someone who
    // rewrapped the key that way is refused, not followed.
    if let Some(log_n) = scrypt_work_factor(bytes) {
        if log_n < WORK_FACTOR {
            return Err(CryptError::Damaged(format!(
                "{KEY_FILE} asks for less work than Pathwarden requires (2^{log_n}, at least \
                 2^{WORK_FACTOR}); it was not made by Pathwarden"
            )));
        }
    }
    #[cfg(test)]
    let _running = tests::scrypt_started(hash);
    let mut scrypt = age::scrypt::Identity::new(passphrase.clone());
    scrypt.set_max_work_factor(MAX_WORK_FACTOR);
    let text = match age::decrypt(&scrypt, bytes) {
        Ok(t) => t,
        Err(age::DecryptError::ExcessiveWork { required, .. }) => {
            return Err(CryptError::Damaged(format!(
                "{KEY_FILE} asks for more work than Pathwarden allows (2^{required}); it was not \
                 made by Pathwarden"
            )))
        }
        Err(
            age::DecryptError::InvalidHeader
            | age::DecryptError::UnknownFormat
            | age::DecryptError::Io(_),
        ) => {
            return Err(CryptError::Damaged(format!(
                "{KEY_FILE} is not an age file; the history's key is damaged"
            )))
        }
        Err(_) => {
            failed()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(tried);
            return Err(CryptError::WrongPassphrase(source));
        }
    };
    // The key's text is zeroed on every path.
    let text = zeroize::Zeroizing::new(text);
    let id: Identity = std::str::from_utf8(&text)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .ok_or_else(|| CryptError::Damaged(format!("{KEY_FILE} doesn't hold an age key")))?;
    let id = Arc::new(id);
    opened()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(hash, id.clone());
    record_opener(hash, passphrase, source);
    Ok(id)
}

/// What this computer has for opening an encrypted history
/// ([`known_passphrase`]).
#[derive(Debug, Clone)]
pub enum Known {
    /// A passphrase that opens it, and where it came from.
    Opens(SecretString, Source),
    /// The passphrase from `Source` doesn't open it, and nothing else here
    /// does.
    Wrong(Source),
    /// Nothing here for it: it must be given.
    Missing,
}

/// The passphrase this computer has for the encrypted history in `dir`,
/// tried: the one for `dir` itself ([`passphrase_for`]), else the one
/// that opened the same key in this process (another folder of the same
/// history), else one this account's store keeps for another history
/// ([`keystore::stored_passphrases`]: a history used here before, under
/// another folder) recorded for this key file (one kept before Pathwarden
/// recorded the key file with it is not tried). One found that way comes back as
/// [`Source::Another`], for the caller to say so. Each passphrase is tried
/// once per process; a store that can't be read is passed over (the
/// passphrase is asked for).
pub fn known_passphrase(dir: &Path) -> anyhow::Result<Known> {
    marker(dir)?;
    let path = dir.join(KEY_FILE);
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        anyhow::bail!(
            "{} is a symbolic link; Pathwarden does not read state through links",
            path.display()
        );
    }
    let bytes = std::fs::read(&path).map_err(|e| {
        CryptError::Damaged(format!(
            "{} can't be read ({e}): the history says it is encrypted, but its key is missing",
            path.display()
        ))
    })?;
    let hash = digest(&bytes);
    let by = || {
        opened_by()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash)
            .cloned()
    };
    let same = |a: &SecretString, b: &SecretString| a.expose_secret() == b.expose_secret();
    let mut wrong = None;
    let own = passphrase_for(dir)?;
    if let Some((p, source)) = &own {
        if by().is_some_and(|(q, _)| same(&q, p)) {
            return Ok(Known::Opens(p.clone(), source.clone()));
        }
        match open_key(&bytes, p, source.clone()) {
            Ok(_) => return Ok(Known::Opens(p.clone(), source.clone())),
            Err(CryptError::WrongPassphrase(s)) => wrong = Some(s),
            Err(e) => return Err(e.into()),
        }
    }
    let this_key = digest_hex(&bytes);
    // This computer pinned another key for this history: its key file was
    // replaced. Only the history's own passphrase may open the new one,
    // never one that opened another history's key (that key file copied
    // here would move this history onto that history's key).
    if crate::store::pinned_key(dir).is_some_and(|pin| pin != this_key) {
        return Ok(wrong.map_or(Known::Missing, Known::Wrong));
    }
    if let Some((p, source)) = by() {
        return Ok(Known::Opens(p, source));
    }
    for (p, key) in keystore::stored_passphrases().unwrap_or_default() {
        if own.as_ref().is_some_and(|(q, _)| same(q, &p)) {
            continue;
        }
        // Tried only on the key file it was kept for: one kept for
        // another key file isn't this history's, and one kept before
        // Pathwarden recorded the key file (before 0.2) is never tried on
        // another history.
        if key.as_deref() != Some(this_key.as_str()) {
            continue;
        }
        match open_key(&bytes, &p, Source::Another) {
            Ok(_) => return Ok(Known::Opens(p, Source::Another)),
            Err(CryptError::WrongPassphrase(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(wrong.map_or(Known::Missing, Known::Wrong))
}

/// The key of the encrypted history in `dir`, opened with the passphrase
/// given in this process, else [`keystore::ENV_VAR`], else this computer's
/// store; kept for the rest of the process.
pub fn key_for(dir: &Path) -> anyhow::Result<Arc<Identity>> {
    marker(dir)?;
    let path = dir.join(KEY_FILE);
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        anyhow::bail!(
            "{} is a symbolic link; Pathwarden does not read state through links",
            path.display()
        );
    }
    let bytes = std::fs::read(&path).map_err(|e| {
        CryptError::Damaged(format!(
            "{} can't be read ({e}): the history says it is encrypted, but its key is missing",
            path.display()
        ))
    })?;
    let hash = digest(&bytes);
    let here = (keystore::history_key(dir), hash);
    let cached = || {
        opened()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash)
            .cloned()
    };
    if opened_in()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&here)
    {
        if let Some(id) = cached() {
            return Ok(id);
        }
    }
    // Not opened for this history yet: only its own passphrase opens it,
    // never a key some other history opened (its key file copied here).
    let Some((passphrase, source)) = passphrase_for(dir)? else {
        return Err(CryptError::NeedPassphrase.into());
    };
    // A key opened already (here or for another folder of the same
    // history) is reused only when this passphrase is the one that opened it.
    let same_opener = || {
        opened_by()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash)
            .is_some_and(|(p, _)| p.expose_secret() == passphrase.expose_secret())
    };
    let cached = || cached().filter(|_| same_opener());
    // One scrypt per key file at a time: readers that come while it is
    // being opened (the first pages, the warm-up at start) wait for it and
    // find it open. Other histories' keys don't wait.
    type Opening = Vec<([u8; 32], Arc<Mutex<()>>)>;
    static OPENING: Mutex<Opening> = Mutex::new(Vec::new());
    let opening = || OPENING.lock().unwrap_or_else(|e| e.into_inner());
    let flight = {
        let mut o = opening();
        match o.iter().find(|(h, _)| *h == hash) {
            Some((_, f)) => f.clone(),
            None => {
                let f = Arc::new(Mutex::new(()));
                o.push((hash, f.clone()));
                f
            }
        }
    };
    let _opening = flight.lock().unwrap_or_else(|e| e.into_inner());
    let key = match cached() {
        Some(id) => Ok(id),
        None => open_key(&bytes, &passphrase, source),
    };
    opening().retain(|(_, f)| !Arc::ptr_eq(f, &flight));
    let key = key?;
    opened_in()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(here);
    Ok(key)
}

/// Whether `passphrase` opens the encrypted history in `dir`.
pub fn opens(dir: &Path, passphrase: &SecretString) -> anyhow::Result<bool> {
    marker(dir)?;
    let bytes = std::fs::read(dir.join(KEY_FILE))
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", dir.join(KEY_FILE).display()))?;
    match open_key(&bytes, passphrase, Source::Given) {
        Ok(_) => Ok(true),
        Err(CryptError::WrongPassphrase(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `plain`, encrypted to `key`.
pub fn seal(key: &Identity, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    age::encrypt(&key.to_public(), plain).map_err(|e| anyhow::anyhow!("encrypting: {e}"))
}

/// `sealed` ([`seal`]), decrypted with `key`; `what` names the file in the
/// error.
pub fn open(key: &Identity, sealed: &[u8], what: &str) -> anyhow::Result<Vec<u8>> {
    age::decrypt(key, sealed).map_err(|e| {
        CryptError::Damaged(format!(
            "{what} can't be decrypted ({e}): it is damaged, or was encrypted with the key of \
             another passphrase"
        ))
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    /// For each key file: how many scrypts are running on it, and the most
    /// that ran at once. (Another test forgetting opened keys can make a
    /// later reader open it again, but never at the same time.)
    type Scrypts = HashMap<[u8; 32], (usize, usize)>;

    fn scrypts() -> &'static Mutex<Scrypts> {
        static RUNS: OnceLock<Mutex<Scrypts>> = OnceLock::new();
        RUNS.get_or_init(Default::default)
    }

    pub(super) struct Running([u8; 32]);

    impl Drop for Running {
        fn drop(&mut self) {
            scrypts().lock().unwrap().entry(self.0).or_default().0 -= 1;
        }
    }

    pub(super) fn scrypt_started(key_file: [u8; 32]) -> Running {
        let mut runs = scrypts().lock().unwrap();
        let (now, most) = runs.entry(key_file).or_default();
        *now += 1;
        *most = (*most).max(*now);
        Running(key_file)
    }

    #[test]
    fn simultaneous_readers_open_the_key_once() {
        let dir = std::env::temp_dir().join(format!("pathwarden-key-once-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MARKER), Marker::new().to_bytes()).unwrap();
        // Made here rather than with `new_key`, which keeps the key open.
        let p = pass("correct horse battery staple");
        let mut r = age::scrypt::Recipient::new(p.clone());
        r.set_work_factor(WORK_FACTOR);
        let id = Identity::generate();
        let bytes = age::encrypt(&r, id.to_string().expose_secret().as_bytes()).unwrap();
        std::fs::write(dir.join(KEY_FILE), &bytes).unwrap();
        give_passphrase(&dir, p);
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || key_for(&dir).unwrap())
            })
            .collect();
        for r in readers {
            assert_eq!(r.join().unwrap().to_public(), id.to_public());
        }
        assert_eq!(
            scrypts().lock().unwrap().get(&digest(&bytes)),
            Some(&(0, 1))
        );
        given()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&keystore::history_key(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_opens_with_its_passphrase_only() {
        let (id, bytes) = new_key(&pass("correct horse battery")).unwrap();
        // Cached on creation; opening again checks the passphrase anyway.
        let again = open_key(&bytes, &pass("correct horse battery"), Source::Given).unwrap();
        assert_eq!(id.to_public().to_string(), again.to_public().to_string());
        assert_eq!(
            open_key(&bytes, &pass("wrong horse battery"), Source::Env)
                .err()
                .unwrap(),
            CryptError::WrongPassphrase(Source::Env)
        );
        assert_eq!(
            CryptError::WrongPassphrase(Source::Env)
                .to_string()
                .split(" (")
                .next(),
            Some("That passphrase doesn't open this history")
        );
        let sealed = seal(&id, b"{\"a\": 1}").unwrap();
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        assert_eq!(open(&again, &sealed, "x").unwrap(), b"{\"a\": 1}");
        // Another key can't open it.
        let (other, _) = new_key(&pass("correct horse battery")).unwrap();
        assert!(open(&other, &sealed, "x").is_err());
        // Not an age file at all.
        assert!(matches!(
            open_key(b"{}", &pass("correct horse battery"), Source::Given),
            Err(CryptError::Damaged(_))
        ));
    }

    /// A key file asking for more scrypt work than [`MAX_WORK_FACTOR`]
    /// is refused before any of it is done (gap 22): a hostile one
    /// must not cost gigabytes and tens of seconds. Its stanza says 2^25.
    #[test]
    fn a_key_file_asking_too_much_work_is_refused() {
        let p = pass("correct horse battery staple");
        let mut r = age::scrypt::Recipient::new(p.clone());
        r.set_work_factor(WORK_FACTOR);
        let bytes = age::encrypt(
            &r,
            Identity::generate().to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let stanza = text.lines().find(|l| l.starts_with("-> scrypt ")).unwrap();
        assert!(stanza.ends_with(" 18"), "{stanza}");
        let hostile = format!("{} 25", stanza.strip_suffix(" 18").unwrap());
        let mut planted = bytes.clone();
        let at = text.find(stanza).unwrap();
        planted.splice(at..at + stanza.len(), hostile.bytes());
        let start = std::time::Instant::now();
        match open_key(&planted, &p, Source::Given) {
            Err(CryptError::Damaged(why)) => {
                assert!(
                    why.contains("more work than Pathwarden allows (2^25)"),
                    "{why}"
                )
            }
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("opened"),
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        // The file as made opens.
        assert!(open_key(&bytes, &p, Source::Given).is_ok());
    }

    /// A key file with less scrypt work than Pathwarden writes is refused
    /// before any scrypt runs: someone with the passphrase could otherwise
    /// make offline guessing cheap for every reader of the history.
    #[test]
    fn a_key_file_asking_too_little_work_is_refused() {
        let p = pass("correct horse battery staple");
        let mut r = age::scrypt::Recipient::new(p.clone());
        r.set_work_factor(10);
        let bytes = age::encrypt(
            &r,
            Identity::generate().to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        assert_eq!(scrypt_work_factor(&bytes), Some(10));
        match open_key(&bytes, &p, Source::Given) {
            Err(CryptError::Damaged(why)) => assert!(
                why.contains("less work than Pathwarden requires (2^10, at least 2^18)"),
                "{why}"
            ),
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("opened"),
        }
        assert!(!scrypts().lock().unwrap().contains_key(&digest(&bytes)));
        let (_, made) = new_key(&p).unwrap();
        assert_eq!(scrypt_work_factor(&made), Some(WORK_FACTOR));
    }

    /// A key file copied from history B into history A doesn't open A with
    /// B's key, though this process opened B: only A's own passphrase
    /// opens A. Another folder whose own passphrase is B's reuses the key
    /// without another scrypt. A history pinned to its old key isn't
    /// offered B's passphrase either.
    #[test]
    fn a_key_opened_for_one_history_never_opens_another() {
        let root =
            std::env::temp_dir().join(format!("pathwarden-key-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
        let (pa, pb) = (pass("history a passphrase"), pass("history b passphrase"));
        let mut a_key = Vec::new();
        for (dir, p) in [(&a, &pa), (&b, &pb)] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join(MARKER), Marker::new().to_bytes()).unwrap();
            let (_, bytes) = new_key(p).unwrap();
            std::fs::write(dir.join(KEY_FILE), &bytes).unwrap();
            if dir == &a {
                a_key = bytes;
            }
            give_passphrase(dir, p.clone());
        }
        let key_b = key_for(&b).unwrap();
        // B's key file in A: A's passphrase doesn't open it.
        let b_file = std::fs::read(b.join(KEY_FILE)).unwrap();
        std::fs::write(a.join(KEY_FILE), &b_file).unwrap();
        match key_for(&a) {
            Err(e) => assert!(
                matches!(
                    e.downcast_ref::<CryptError>(),
                    Some(CryptError::WrongPassphrase(Source::Given))
                ),
                "{e:#}"
            ),
            Ok(_) => panic!("history A opened with history B's key"),
        }
        // Nor without a passphrase of its own.
        given()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&keystore::history_key(&a));
        if keystore::lookup(&a).unwrap().is_none() {
            assert!(key_for(&a).is_err());
        }
        // A pinned to its old key: B's passphrase isn't offered for it.
        std::fs::create_dir_all(a.join(".git")).unwrap();
        std::fs::write(
            a.join(".git").join("pathwarden-encrypted"),
            format!("{}\n", digest_hex(&a_key)),
        )
        .unwrap();
        give_passphrase(&a, pa.clone());
        assert!(
            matches!(known_passphrase(&a).unwrap(), Known::Wrong(Source::Given)),
            "B's passphrase was offered for A"
        );
        // Another folder of history B, with B's passphrase: the same key,
        // no second scrypt.
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(c.join(MARKER), Marker::new().to_bytes()).unwrap();
        std::fs::write(c.join(KEY_FILE), &b_file).unwrap();
        give_passphrase(&c, pb.clone());
        let before = scrypts().lock().unwrap().get(&digest(&b_file)).copied();
        let key_c = key_for(&c).unwrap();
        assert_eq!(key_c.to_public(), key_b.to_public());
        assert_eq!(
            scrypts().lock().unwrap().get(&digest(&b_file)).copied(),
            before
        );
        for dir in [&a, &b, &c] {
            given()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&keystore::history_key(dir));
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn short_passphrases_are_refused() {
        assert!(check_passphrase(&pass("short")).is_err());
        assert!(new_key(&pass("eleven char")).is_err());
        assert!(check_passphrase(&pass("twelve chars")).is_ok());
        assert!(check_passphrase(&pass(&"x".repeat(MAX_PASSPHRASE + 1))).is_err());
    }

    /// The work factor's cost, for docs/running.md: one scrypt to open the
    /// key, then each file. Run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn measure_the_work_factor() {
        let p = pass("correct horse battery staple");
        let t = std::time::Instant::now();
        let (_, bytes) = new_key(&p).unwrap();
        let made = t.elapsed();
        let t = std::time::Instant::now();
        let id = open_key(&bytes, &p, Source::Given).unwrap();
        let unlocked = t.elapsed();
        let point = vec![b'x'; 4 * 1024];
        let t = std::time::Instant::now();
        for _ in 0..500 {
            let s = seal(&id, &point).unwrap();
            open(&id, &s, "x").unwrap();
        }
        let files = t.elapsed();
        for log_n in [16u8, 17, 18, 19, 20] {
            let mut r = age::scrypt::Recipient::new(p.clone());
            r.set_work_factor(log_n);
            let t = std::time::Instant::now();
            age::encrypt(&r, b"x").unwrap();
            eprintln!("scrypt 2^{log_n}: {:?}", t.elapsed());
        }
        eprintln!(
            "work factor 2^{WORK_FACTOR}: new key {made:?}, open {unlocked:?}; 500 files of 4 KiB \
             sealed and opened: {files:?}"
        );
    }
}
