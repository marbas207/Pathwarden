//! Where this computer keeps the passphrase of an encrypted history
//! ([`crate::crypt`]): never in pathwarden.toml or the history itself.
//!
//! Looked up in this order:
//!
//! 1. [`ENV_VAR`], for automation.
//! 2. This account's credential store: Windows Credential Manager (a
//!    generic credential, persisted on this computer only), or on Linux the
//!    Secret Service (through `secret-tool`, from libsecret).
//! 3. Windows: a file beside the history folder protected with DPAPI-NG to
//!    one account ([`protected_file`]). That is how a scheduled task's gMSA
//!    gets it: an administrator writes it with `passphrase set
//!    --for-account`, and only that account can open it, on any computer
//!    of the domain. It also stands in for Credential Manager in a logon
//!    without one (a task that doesn't store a password).
//! 4. Linux: a systemd credential, `$CREDENTIALS_DIRECTORY/`[`SYSTEMD_CREDENTIAL`]
//!    (`LoadCredentialEncrypted=` in a service unit).
//!
//! An entry is per history: [`history_key`], the history folder's full
//! path ([`full_path`], the one normalisation the store's entry and the
//! protected file share). Moving the folder leaves the entry behind under
//! the old path: forget it first, and set it again for the new place.
//!
//! Debug builds only: tests use [`TEST_STORE_ENV`] or [`use_test_store`],
//! a plain folder in place of the account's store, so they never touch
//! real credentials. A release build ignores both.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::crypt::{self, ExposeSecret, SecretString};

/// The passphrase, for automation (a pipeline, a container).
pub const ENV_VAR: &str = "PATHWARDEN_HISTORY_PASSPHRASE";

/// The new passphrase, for `passphrase change --from-env`.
pub const NEW_ENV_VAR: &str = "PATHWARDEN_HISTORY_NEW_PASSPHRASE";

/// Debug builds only, for tests: a folder that replaces this account's
/// credential store (it holds passphrases in plain text).
pub const TEST_STORE_ENV: &str = "PATHWARDEN_TEST_KEYSTORE";

/// The evidence signing key, for a pipeline (`evidence::KEY_ENV`).
pub const EVIDENCE_KEY_ENV: &str = "PATHWARDEN_EVIDENCE_KEY";

/// The collection password (`pathwarden_collect::PASSWORD_ENV`).
pub const COLLECT_PASSWORD_ENV: &str = "PATHWARDEN_COLLECT_PASSWORD";

/// Every secret Pathwarden reads from its own environment: the history's
/// passphrases, the evidence signing key and the collection password.
/// [`take_env`] takes them out of the environment at start-up, no program
/// Pathwarden starts inherits them ([`scrub_env`]), and a plugin can't ask
/// for one by name ([`is_secret_env`]).
pub const SECRET_ENV: [&str; 4] = [ENV_VAR, NEW_ENV_VAR, EVIDENCE_KEY_ENV, COLLECT_PASSWORD_ENV];

/// Removes the [`SECRET_ENV`] variables from what `cmd` inherits: git, a
/// collector, a browser, a shell or a plugin never sees them. Every
/// program Pathwarden starts goes through this.
pub fn scrub_env(cmd: &mut Command) -> &mut Command {
    for var in SECRET_ENV {
        cmd.env_remove(var);
    }
    cmd
}

/// One variable as [`take_env`] found it: unset (or empty), its value, or
/// not valid Unicode.
type TakenVar = Option<std::result::Result<zeroize::Zeroizing<String>, ()>>;
type Taken = [TakenVar; 4];

fn taken() -> &'static std::sync::OnceLock<Taken> {
    static TAKEN: std::sync::OnceLock<Taken> = std::sync::OnceLock::new();
    &TAKEN
}

/// Reads the [`SECRET_ENV`] variables once and removes them from this
/// process's environment, keeping the values in memory: nothing this
/// process starts afterwards inherits them, whichever way it starts it
/// (ShellExecute, a WebView2, a library). `main` calls it first, before
/// any thread.
pub fn take_env() {
    taken().get_or_init(|| {
        SECRET_ENV.map(|name| {
            let v = match std::env::var(name) {
                Ok(v) if !v.is_empty() => {
                    crate::redact::register_secret(&v);
                    Some(Ok(zeroize::Zeroizing::new(v)))
                }
                Ok(_) | Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(_)) => Some(Err(())),
            };
            std::env::remove_var(name);
            v
        })
    });
}

/// The value of [`SECRET_ENV`] variable `name`: as [`take_env`] kept it,
/// or from the environment when it wasn't called (tests, a library user).
/// `None` when unset or empty.
pub fn secret_env(name: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
    if let Some(all) = taken().get() {
        if let Some(i) = SECRET_ENV.iter().position(|n| *n == name) {
            return match &all[i] {
                None => Ok(None),
                Some(Ok(s)) => Ok(Some(s.clone())),
                Some(Err(())) => bail!("{name} is not valid Unicode"),
            };
        }
    }
    match std::env::var(name).map(zeroize::Zeroizing::new) {
        Ok(v) if !v.is_empty() => {
            crate::redact::register_secret(&v);
            Ok(Some(v))
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid Unicode"),
    }
}

/// The value of passphrase variable `name`, as a secret.
fn env_value(name: &str) -> Result<Option<SecretString>> {
    Ok(secret_env(name)?.map(|v| crypt::secret_from(&v)))
}

/// [`NEW_ENV_VAR`], when set and not empty.
pub fn new_from_env() -> Result<Option<SecretString>> {
    env_value(NEW_ENV_VAR)
}

/// Whether `name` is one of the [`SECRET_ENV`] variables (plugins may not
/// ask for them).
pub fn is_secret_env(name: &str) -> bool {
    SECRET_ENV.iter().any(|v| name.eq_ignore_ascii_case(v))
}

#[cfg(debug_assertions)]
fn test_dir() -> &'static std::sync::Mutex<Option<PathBuf>> {
    static DIR: std::sync::OnceLock<std::sync::Mutex<Option<PathBuf>>> = std::sync::OnceLock::new();
    DIR.get_or_init(Default::default)
}

/// Debug builds only, for tests in this process: use `dir` as this
/// account's store (as [`TEST_STORE_ENV`] does for a child process).
#[cfg(debug_assertions)]
pub fn use_test_store(dir: &Path) {
    *test_dir().lock().unwrap_or_else(|e| e.into_inner()) = Some(dir.to_path_buf());
}

/// The name of the systemd credential read on Linux.
pub const SYSTEMD_CREDENTIAL: &str = "pathwarden-history-passphrase";

/// Where a passphrase came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Given in this process (typed, or read from stdin).
    Given,
    /// [`ENV_VAR`].
    Env,
    /// This account's credential store.
    Store,
    /// A protected file ([`protected_file`]).
    File(PathBuf),
    /// A systemd credential.
    Systemd,
    /// This account's store, kept there for another history (its folder
    /// elsewhere): [`stored_passphrases`].
    Another,
}

impl Source {
    /// For a sentence: "the one stored on this computer".
    pub fn words(&self) -> String {
        match self {
            Source::Given => "the one given".into(),
            Source::Env => format!("from {ENV_VAR}"),
            Source::Store => format!("the one stored on this computer, in {}", store_name()),
            Source::File(p) => format!("the one stored for this account in {}", p.display()),
            Source::Systemd => format!("the systemd credential {SYSTEMD_CREDENTIAL}"),
            Source::Another => "the one kept on this computer for another history".into(),
        }
    }

    /// Where it is kept, for "stored on this computer, {place}".
    pub fn place(&self) -> String {
        match self {
            Source::Store => format!("in {}", store_name()),
            Source::File(p) => format!("in {}", p.display()),
            other => other.words(),
        }
    }
}

/// The name of this computer's credential store, for sentences.
pub fn store_name() -> &'static str {
    if test_store().is_some() {
        "the test keystore"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else if cfg!(target_os = "linux") {
        "the Secret Service keyring"
    } else {
        "no credential store (set the environment variable instead)"
    }
}

/// The name an entry is kept under: the history folder's full path (case
/// folded on Windows), the same for every way of writing it.
pub fn history_key(dir: &Path) -> String {
    let s = full_path(dir).to_string_lossy().into_owned();
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

/// The history folder's full path, links and junctions resolved (`\\?\`
/// left out on Windows): the one normalisation behind [`history_key`] and
/// [`protected_file`]. A folder not made yet gets the name it will have:
/// its nearest existing parent resolved, the rest as given. Otherwise a
/// path through a link or with 8.3 short names (`C:\Users\RUNNER~1`)
/// would name the folder one way before it exists and another after.
pub fn full_path(dir: &Path) -> PathBuf {
    let full = std::fs::canonicalize(dir).unwrap_or_else(|_| {
        let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        abs.ancestors()
            .skip(1)
            .find_map(|a| {
                let real = std::fs::canonicalize(a).ok()?;
                Some(real.join(abs.strip_prefix(a).ok()?))
            })
            .unwrap_or(abs)
    });
    if cfg!(windows) {
        let s = full.to_string_lossy();
        let s = if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else {
            s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
        };
        PathBuf::from(s.replace('/', "\\"))
    } else {
        full
    }
}

/// The credential's name in the store.
fn target(dir: &Path) -> String {
    format!("{TARGET_PREFIX}{}", history_key(dir))
}

/// What every credential's name starts with ([`target`]).
const TARGET_PREFIX: &str = "Pathwarden history ";

/// What a credential's comment starts with: the key file's SHA-256 follows.
const KEY_COMMENT: &str = "Pathwarden key file sha256 ";

/// The key file digest a credential's comment records, if it does.
#[cfg_attr(not(windows), allow(dead_code))]
fn key_of_comment(comment: &str) -> Option<String> {
    let hex = comment.strip_prefix(KEY_COMMENT)?.trim();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

/// The passphrase for `dir` this computer has, and where it came from.
pub fn lookup(dir: &Path) -> Result<Option<(SecretString, Source)>> {
    if let Some(p) = from_env()? {
        return Ok(Some((p, Source::Env)));
    }
    if let Some(p) = read_store(dir)? {
        return Ok(Some((p, Source::Store)));
    }
    if let Some((p, file)) = read_protected_file(dir)? {
        return Ok(Some((p, Source::File(file))));
    }
    if let Some(p) = read_systemd()? {
        return Ok(Some((p, Source::Systemd)));
    }
    Ok(None)
}

/// [`ENV_VAR`], when set and not empty.
pub fn from_env() -> Result<Option<SecretString>> {
    env_value(ENV_VAR)
}

/// Every passphrase this account's store keeps for a history, whichever
/// folder it was kept for, with the SHA-256 of the key file it was kept
/// for ([`crypt::key_digest`]) when it was recorded (entries kept before
/// Pathwarden recorded it have none). A new folder of a history used here
/// before (a new clone, an environment removed and connected again) may
/// open with one recorded for its key file ([`crypt::known_passphrase`]). Windows Credential
/// Manager's Pathwarden entries (the digest in the credential's comment),
/// or the test store's; none elsewhere.
pub fn stored_passphrases() -> Result<Vec<(SecretString, Option<String>)>> {
    let mut all: Vec<(SecretString, Option<String>)> = Vec::new();
    let mut add = |bytes: Vec<u8>, key: Option<String>| {
        if let Ok(p) = secret(bytes) {
            if !p.expose_secret().is_empty()
                && !all
                    .iter()
                    .any(|(q, k)| q.expose_secret() == p.expose_secret() && *k == key)
            {
                all.push((p, key));
            }
        }
    };
    if let Some(folder) = test_store() {
        if let Ok(entries) = std::fs::read_dir(&folder) {
            let mut files: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "txt"))
                .collect();
            files.sort();
            for f in files {
                if let Ok(b) = std::fs::read(&f) {
                    let key = std::fs::read_to_string(f.with_extension("key"))
                        .ok()
                        .map(|k| k.trim().to_string());
                    add(b, key);
                }
            }
        }
        return Ok(all);
    }
    #[cfg(windows)]
    {
        match win::cred_enumerate(&format!("{TARGET_PREFIX}*")) {
            Ok(found) => {
                for (blob, comment) in found {
                    add(blob, comment.as_deref().and_then(key_of_comment));
                }
            }
            // A logon without Credential Manager: nothing kept there.
            Err(e) if e.raw_os_error() == Some(win::ERROR_NO_SUCH_LOGON_SESSION) => {}
            Err(e) => {
                return Err(anyhow::Error::from(e)
                    .context("reading the passphrases kept in Windows Credential Manager"))
            }
        }
    }
    Ok(all)
}

/// Whether this account's store keeps a passphrase without the key file it
/// was kept for (kept before 0.2). Since 0.3 such a one is no longer tried
/// on another history ([`crypt::known_passphrase`]), so a history connected
/// again asks for its passphrase once, and says why
/// ([`crate::connect::OLD_PASSPHRASES`]).
pub fn kept_without_key_file() -> bool {
    stored_passphrases()
        .unwrap_or_default()
        .iter()
        .any(|(_, key)| key.is_none())
}

/// Where this computer keeps a passphrase for `dir` for this account (the
/// environment variable left out): for "stored on this computer".
pub fn stored_here(dir: &Path) -> Result<Option<Source>> {
    if read_store(dir)?.is_some() {
        return Ok(Some(Source::Store));
    }
    if let Some((_, file)) = read_protected_file(dir)? {
        return Ok(Some(Source::File(file)));
    }
    Ok(read_systemd()?.map(|_| Source::Systemd))
}

/// Where this account keeps a passphrase for this one history: the
/// store's entry or the protected file (not the environment variable or a
/// systemd credential, which aren't per history).
pub fn stored_for_history(dir: &Path) -> Result<Option<Source>> {
    if read_store(dir)?.is_some() {
        return Ok(Some(Source::Store));
    }
    Ok(read_protected_file(dir)?.map(|(_, file)| Source::File(file)))
}

/// Keeps `passphrase` for `dir` in this account's store. On Windows, a
/// logon without Credential Manager (ERROR_NO_SUCH_LOGON_SESSION) gets the
/// protected file instead. Returns where it went.
pub fn store(dir: &Path, passphrase: &SecretString) -> Result<Source> {
    // The key file it opens, recorded with it (no secret): another folder
    // of the same history may use it ([`stored_passphrases`]).
    let key = crypt::key_digest(dir).ok();
    if let Some(folder) = test_store() {
        std::fs::create_dir_all(&folder)?;
        let entry = test_entry(&folder, dir);
        std::fs::write(&entry, passphrase.expose_secret())?;
        match &key {
            Some(k) => std::fs::write(entry.with_extension("key"), k)?,
            None => {
                let _ = std::fs::remove_file(entry.with_extension("key"));
            }
        }
        return Ok(Source::Store);
    }
    #[cfg(windows)]
    {
        let comment = key.as_ref().map(|k| format!("{KEY_COMMENT}{k}"));
        match win::cred_write(
            &target(dir),
            passphrase.expose_secret().as_bytes(),
            comment.as_deref(),
        ) {
            Ok(()) => Ok(Source::Store),
            Err(e) if e.raw_os_error() == Some(win::ERROR_NO_SUCH_LOGON_SESSION) => {
                let sid = crate::perms::current_user_sid()
                    .context("finding this account's SID for the protected file")?;
                let file = write_protected_file(dir, &sid, "LOCAL=user", passphrase)
                    .context("Credential Manager isn't available in this logon")?;
                Ok(Source::File(file))
            }
            Err(e) => Err(e).context("saving the passphrase in Windows Credential Manager"),
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux::store(&target(dir), &history_key(dir), passphrase)?;
        Ok(Source::Store)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (dir, passphrase);
        bail!("this system has no credential store Pathwarden can use; set {ENV_VAR} instead")
    }
}

/// Removes what this computer keeps for `dir` for this account (the store's
/// entry and this account's protected file). Returns what was removed, for
/// the user.
pub fn forget(dir: &Path) -> Result<Vec<String>> {
    crate::crypt::forget_in_process(dir);
    let mut removed = Vec::new();
    if let Some(folder) = test_store() {
        let entry = test_entry(&folder, dir);
        let _ = std::fs::remove_file(entry.with_extension("key"));
        if entry.is_file() {
            std::fs::remove_file(&entry)?;
            removed.push(format!("the entry in {}", store_name()));
        }
    } else {
        #[cfg(windows)]
        if win::cred_delete(&target(dir))
            .context("removing the passphrase from Windows Credential Manager")?
        {
            removed.push(format!("the entry in {}", store_name()));
        }
        #[cfg(target_os = "linux")]
        if linux::clear(&history_key(dir))? {
            removed.push(format!("the entry in {}", store_name()));
        }
    }
    #[cfg(windows)]
    if let Ok(sid) = crate::perms::current_user_sid() {
        if let Some(file) = protected_file(dir, &sid) {
            if file.is_file() {
                std::fs::remove_file(&file)
                    .with_context(|| format!("removing {}", file.display()))?;
                removed.push(file.display().to_string());
            }
        }
    }
    Ok(removed)
}

/// Where this account keeps what the repository can't touch about the
/// histories it has used (the sticky "this history is encrypted" records):
/// `%LOCALAPPDATA%\Pathwarden\history-pins` on Windows,
/// `$XDG_STATE_HOME/pathwarden/history-pins` (or
/// `~/.local/state/pathwarden/history-pins`) elsewhere. Debug builds use
/// the test store's `pins` folder, and none without one, so tests never
/// write this account's real data.
///
/// An error when the account's environment doesn't say where its data is
/// (a service with no profile environment, a systemd unit with no HOME):
/// the caller refuses rather than go without the record.
pub fn pins_dir() -> Result<Option<PathBuf>> {
    if let Some(dir) = test_store() {
        return Ok(Some(dir.join("pins")));
    }
    if cfg!(debug_assertions) {
        return Ok(None);
    }
    pins_dir_from(|n| std::env::var_os(n), cfg!(windows)).map(Some)
}

/// [`pins_dir`] from the environment `var` gives, for Windows or not.
/// `XDG_STATE_HOME` counts only when absolute (the XDG rule).
fn pins_dir_from(
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
    windows: bool,
) -> Result<PathBuf> {
    let var = |n: &str| var(n).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if windows {
        var("LOCALAPPDATA")
            .context(
                "LOCALAPPDATA is not set, so Pathwarden can't keep this account's record of \
                 the encrypted history; run it with the account's profile loaded",
            )?
            .join("Pathwarden")
    } else {
        var("XDG_STATE_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| var("HOME").map(|h| h.join(".local").join("state")))
            .context(
                "neither XDG_STATE_HOME nor HOME is set, so Pathwarden can't keep this \
                 account's record of the encrypted history; set HOME for the service",
            )?
            .join("pathwarden")
    };
    Ok(base.join("history-pins"))
}

/// The test store ([`TEST_STORE_ENV`], [`use_test_store`]): debug builds
/// only.
fn test_store() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Some(dir) = test_dir().lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Some(dir);
        }
        std::env::var_os(TEST_STORE_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

fn test_entry(folder: &Path, dir: &Path) -> PathBuf {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(target(dir).as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    folder.join(format!("{hex}.txt"))
}

fn read_store(dir: &Path) -> Result<Option<SecretString>> {
    if let Some(folder) = test_store() {
        return match std::fs::read(test_entry(&folder, dir)) {
            Ok(b) => Ok(Some(secret(b)?)),
            Err(_) => Ok(None),
        };
    }
    #[cfg(windows)]
    {
        let bytes = win::cred_read(&target(dir))
            .context("reading the passphrase from Windows Credential Manager");
        match bytes {
            Ok(Some(b)) => Ok(Some(secret(b)?)),
            Ok(None) => Ok(None),
            // A logon without Credential Manager: the protected file may
            // have it.
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .and_then(|e| e.raw_os_error())
                    == Some(win::ERROR_NO_SUCH_LOGON_SESSION) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux::lookup(&history_key(dir))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = dir;
        Ok(None)
    }
}

/// A stored passphrase's bytes as a secret; the bytes are zeroed.
fn secret(bytes: Vec<u8>) -> Result<SecretString> {
    let bytes = zeroize::Zeroizing::new(bytes);
    std::str::from_utf8(&bytes)
        .map(crypt::secret_from)
        .map_err(|_| anyhow::anyhow!("the stored passphrase is not valid UTF-8"))
}

/// The DPAPI-NG protected file of account `sid` for the history in `dir`:
/// beside the history folder (`<folder>.passphrase.<SID>.dpapi`), where a
/// scheduled task's account may read but not write, and outside anything
/// git commits. `None` for a folder without a parent.
pub fn protected_file(dir: &Path, sid: &str) -> Option<PathBuf> {
    let full = full_path(dir);
    let name = full.file_name()?.to_string_lossy().into_owned();
    Some(
        full.parent()?
            .join(format!("{name}.passphrase.{sid}.dpapi")),
    )
}

#[cfg(windows)]
fn read_protected_file(dir: &Path) -> Result<Option<(SecretString, PathBuf)>> {
    if test_store().is_some() {
        return Ok(None);
    }
    let Ok(sid) = crate::perms::current_user_sid() else {
        return Ok(None);
    };
    let Some(file) = protected_file(dir, &sid) else {
        return Ok(None);
    };
    let mut f = match std::fs::File::open(&file) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    // Anyone can protect a passphrase to this account with DPAPI-NG; what
    // makes the file this account's is who may write it. Read from
    // the handle that is then read, so it is that file's.
    check_protected_file(&file, crate::perms::file_security(&f).as_ref(), &sid)?;
    let mut blob = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut blob)
        .with_context(|| format!("reading {}", file.display()))?;
    let plain = win::unprotect(&blob).with_context(|| {
        format!(
            "{} can't be opened by this account (DPAPI-NG); store the passphrase again with \
             `pathwarden history storage passphrase set --for-account`",
            file.display()
        )
    })?;
    Ok(Some((secret(plain)?, file)))
}

/// Refuses a protected file someone besides account `me`, Administrators
/// and SYSTEM owns or may change ([`crate::perms::untrusted_holders`]), or
/// whose permissions can't be read: such a one could hold a passphrase of
/// their choosing, protected to this account, and this account would
/// write the history with it.
#[cfg_attr(not(windows), allow(dead_code))]
fn check_protected_file(
    file: &Path,
    security: Option<&crate::perms::FileSecurity>,
    me: &str,
) -> Result<()> {
    let Some(sec) = security else {
        bail!(
            "{}: its permissions can't be read, so it isn't used. An administrator can store the \
             passphrase again with `pathwarden history storage passphrase set --for-account`",
            file.display()
        );
    };
    let others = crate::perms::untrusted_holders(sec, me);
    if !others.is_empty() {
        bail!(
            "{} isn't used: it is owned by or can be changed by {}, not only this account, \
             Administrators and SYSTEM, so anyone of them could have put a passphrase of their \
             choosing there. An administrator can store the passphrase again, from an elevated \
             prompt, with `pathwarden history storage passphrase set --for-account`",
            file.display(),
            others.join(", ")
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn read_protected_file(_dir: &Path) -> Result<Option<(SecretString, PathBuf)>> {
    Ok(None)
}

/// Writes `passphrase` for the history in `dir`, protected with DPAPI-NG
/// to `descriptor` ("SID=S-1-5-21-...", "LOCAL=user"), as account `sid`'s
/// file ([`protected_file`]).
#[cfg(windows)]
fn write_protected_file(
    dir: &Path,
    sid: &str,
    descriptor: &str,
    passphrase: &SecretString,
) -> Result<PathBuf> {
    let file = protected_file(dir, sid)
        .with_context(|| format!("{} has no folder above it", dir.display()))?;
    let blob = win::protect(descriptor, passphrase.expose_secret().as_bytes())
        .with_context(|| format!("protecting the passphrase with DPAPI-NG ({descriptor})"))?;
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = file.with_extension("dpapi.tmp");
    std::fs::write(&tmp, blob).with_context(|| format!("writing {}", tmp.display()))?;
    // Its own access list, not the folder's. This account's own
    // file: this account, Administrators and SYSTEM. Another account's:
    // owned by Administrators, changed only by them and SYSTEM, read by
    // that account, which reads nothing anyone else could change.
    let me = crate::perms::current_user_sid().ok();
    let set = if me.as_deref() == Some(sid) {
        crate::perms::make_file_private_for(&tmp, Some(sid)).map_err(anyhow::Error::from)
    } else {
        crate::perms::make_file_admin_owned_for(&tmp, sid).map_err(|e| {
            if e.raw_os_error() == Some(win::ERROR_INVALID_OWNER) {
                anyhow::anyhow!(
                    "storing a passphrase for another account needs an elevated prompt (Run as \
                     administrator): the file must belong to Administrators, so that only they \
                     can change what that account reads"
                )
            } else {
                anyhow::Error::from(e)
            }
        })
    };
    if let Err(e) = set {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("setting the permissions of {}", tmp.display()));
    }
    std::fs::rename(&tmp, &file).with_context(|| format!("writing {}", file.display()))?;
    Ok(file)
}

/// Keeps `passphrase` for the history in `dir` for another account (a
/// scheduled task's gMSA, `DOMAIN\name$`), in a DPAPI-NG protected file only
/// that account can open ([`protected_file`]). Needs a domain (the Group
/// Key Distribution Service, which gMSAs need anyway). Returns the file.
#[cfg(windows)]
pub fn store_for_account(dir: &Path, account: &str, passphrase: &SecretString) -> Result<PathBuf> {
    let sid = crate::perms::account_sid(account)
        .with_context(|| format!("finding the account {account}"))?;
    write_protected_file(dir, &sid, &format!("SID={sid}"), passphrase)
}

#[cfg(not(windows))]
pub fn store_for_account(
    _dir: &Path,
    _account: &str,
    _passphrase: &SecretString,
) -> Result<PathBuf> {
    bail!(
        "--for-account is for Windows (DPAPI-NG); on Linux give the service its passphrase as \
         the systemd credential {SYSTEMD_CREDENTIAL}, or set {ENV_VAR}"
    )
}

/// Removes the protected file of `account` for `dir`; whether there was one.
#[cfg(windows)]
pub fn forget_for_account(dir: &Path, account: &str) -> Result<Option<PathBuf>> {
    let sid = crate::perms::account_sid(account)
        .with_context(|| format!("finding the account {account}"))?;
    let Some(file) = protected_file(dir, &sid) else {
        return Ok(None);
    };
    match std::fs::remove_file(&file) {
        Ok(()) => Ok(Some(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("removing {}", file.display())),
    }
}

#[cfg(not(windows))]
pub fn forget_for_account(_dir: &Path, _account: &str) -> Result<Option<PathBuf>> {
    bail!("--for-account is for Windows (DPAPI-NG)")
}

fn read_systemd() -> Result<Option<SecretString>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY").filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match std::fs::read_to_string(Path::new(&dir).join(SYSTEMD_CREDENTIAL)) {
        Ok(text) => {
            let text = zeroize::Zeroizing::new(text);
            let text = text.trim_end_matches(['\r', '\n']);
            Ok((!text.is_empty()).then(|| crypt::secret_from(text)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context(format!(
            "reading the systemd credential {SYSTEMD_CREDENTIAL}"
        )),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    //! The Secret Service through `secret-tool` (libsecret-tools): no
    //! D-Bus library to build against, and the keyring's own prompts.

    use std::io::Write;
    use std::process::{Command, Stdio};

    use anyhow::{bail, Context, Result};

    use crate::crypt::{ExposeSecret, SecretString};

    const ATTR: [&str; 2] = ["application", "pathwarden-history"];

    fn tool() -> Command {
        let mut c = crate::spawn::quiet("secret-tool");
        super::scrub_env(&mut c);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn missing(e: std::io::Error) -> anyhow::Error {
        anyhow::anyhow!(
            "the Secret Service can't be used ({e}): install libsecret-tools (secret-tool) and \
             run in a desktop session, or set {}",
            super::ENV_VAR
        )
    }

    pub fn store(label: &str, key: &str, passphrase: &SecretString) -> Result<()> {
        let mut child = tool()
            .args(["store", "--label", label, ATTR[0], ATTR[1], "key", key])
            .spawn()
            .map_err(missing)?;
        child
            .stdin
            .take()
            .context("secret-tool's input")?
            .write_all(passphrase.expose_secret().as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "the Secret Service refused the passphrase: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    pub fn lookup(key: &str) -> Result<Option<SecretString>> {
        let out = match tool()
            .args(["lookup", ATTR[0], ATTR[1], "key", key])
            .stdin(Stdio::null())
            .output()
        {
            Ok(o) => o,
            // No secret-tool: nothing stored here.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(missing(e)),
        };
        if !out.status.success() || out.stdout.is_empty() {
            return Ok(None);
        }
        Ok(Some(super::secret(out.stdout)?))
    }

    pub fn clear(key: &str) -> Result<bool> {
        let had = lookup(key)?.is_some();
        if had {
            let out = tool()
                .args(["clear", ATTR[0], ATTR[1], "key", key])
                .stdin(Stdio::null())
                .output()
                .map_err(missing)?;
            if !out.status.success() {
                bail!(
                    "the Secret Service didn't remove it: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
        Ok(had)
    }
}

#[cfg(windows)]
mod win {
    //! Credential Manager (generic credentials) and DPAPI-NG. Each
    //! function frees what the system allocates on every path.

    use std::io;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW,
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCloseProtectionDescriptor, NCryptCreateProtectionDescriptor, NCryptProtectSecret,
        NCryptUnprotectSecret, NCRYPT_SILENT_FLAG,
    };
    use windows_sys::Win32::Security::NCRYPT_DESCRIPTOR_HANDLE;

    /// No credential set in this logon session (a task that doesn't store
    /// a password, a network logon).
    pub const ERROR_NO_SUCH_LOGON_SESSION: i32 = 1312;
    /// This token may not make that SID a file's owner (not elevated).
    pub const ERROR_INVALID_OWNER: i32 = 1307;
    const ERROR_NOT_FOUND: i32 = 1168;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn hresult(hr: i32) -> io::Result<()> {
        if hr == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(hr))
        }
    }

    /// `comment`: the credential's comment (no secret), or none.
    pub fn cred_write(target: &str, secret: &[u8], comment: Option<&str>) -> io::Result<()> {
        let mut name = wide(target);
        let mut note = comment.map(wide);
        // SAFETY: CREDENTIALW is plain data; every pointer set lives until
        // the call returns, and CredWriteW copies what it keeps.
        unsafe {
            let mut cred: CREDENTIALW = std::mem::zeroed();
            cred.Type = CRED_TYPE_GENERIC;
            cred.TargetName = name.as_mut_ptr();
            if let Some(n) = note.as_mut() {
                cred.Comment = n.as_mut_ptr();
            }
            cred.CredentialBlobSize = secret.len() as u32;
            cred.CredentialBlob = secret.as_ptr() as *mut u8;
            cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
            if CredWriteW(&cred, 0) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn cred_read(target: &str) -> io::Result<Option<Vec<u8>>> {
        let name = wide(target);
        let mut cred: *mut CREDENTIALW = null_mut();
        // SAFETY: on success `cred` points at a CREDENTIALW the system
        // allocated, freed with CredFree after its blob is copied.
        unsafe {
            if CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) == 0 {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(ERROR_NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let c = &*cred;
            let blob = if c.CredentialBlob.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec()
            };
            CredFree(cred as *const _);
            Ok(Some(blob))
        }
    }

    /// The blobs and comments of the generic credentials whose names match
    /// `filter` (a trailing `*` matches any rest).
    pub fn cred_enumerate(filter: &str) -> io::Result<Vec<(Vec<u8>, Option<String>)>> {
        let name = wide(filter);
        let mut count: u32 = 0;
        let mut creds: *mut *mut CREDENTIALW = null_mut();
        // SAFETY: on success `creds` points at `count` CREDENTIALW
        // pointers the system allocated in one block, freed with CredFree
        // after the blobs are copied.
        unsafe {
            if CredEnumerateW(name.as_ptr(), 0, &mut count, &mut creds) == 0 {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(ERROR_NOT_FOUND) {
                    Ok(Vec::new())
                } else {
                    Err(e)
                };
            }
            let mut blobs = Vec::with_capacity(count as usize);
            for i in 0..count as usize {
                let c = &**creds.add(i);
                if c.Type == CRED_TYPE_GENERIC && !c.CredentialBlob.is_null() {
                    let comment = if c.Comment.is_null() {
                        None
                    } else {
                        let mut n = 0;
                        while *c.Comment.add(n) != 0 && n < 1024 {
                            n += 1;
                        }
                        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                            c.Comment, n,
                        )))
                    };
                    blobs.push((
                        std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize)
                            .to_vec(),
                        comment,
                    ));
                }
            }
            CredFree(creds as *const _);
            Ok(blobs)
        }
    }

    pub fn cred_delete(target: &str) -> io::Result<bool> {
        let name = wide(target);
        // SAFETY: a NUL-terminated name.
        unsafe {
            if CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(ERROR_NOT_FOUND) {
                    Ok(false)
                } else {
                    Err(e)
                };
            }
        }
        Ok(true)
    }

    /// `data`, protected with DPAPI-NG to `descriptor`.
    pub fn protect(descriptor: &str, data: &[u8]) -> io::Result<Vec<u8>> {
        let rule = wide(descriptor);
        // SAFETY: the descriptor is closed and the blob freed on every path.
        unsafe {
            let mut h: NCRYPT_DESCRIPTOR_HANDLE = std::mem::zeroed();
            hresult(NCryptCreateProtectionDescriptor(rule.as_ptr(), 0, &mut h))?;
            let mut out: *mut u8 = null_mut();
            let mut len = 0u32;
            let hr = NCryptProtectSecret(
                h,
                NCRYPT_SILENT_FLAG,
                data.as_ptr(),
                data.len() as u32,
                null(),
                std::mem::zeroed(),
                &mut out,
                &mut len,
            );
            NCryptCloseProtectionDescriptor(h);
            hresult(hr)?;
            let blob = std::slice::from_raw_parts(out, len as usize).to_vec();
            LocalFree(out as HLOCAL);
            Ok(blob)
        }
    }

    /// A DPAPI-NG blob ([`protect`]) opened by this account.
    pub fn unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
        // SAFETY: the output is freed on every path after it is copied.
        unsafe {
            let mut out: *mut u8 = null_mut();
            let mut len = 0u32;
            hresult(NCryptUnprotectSecret(
                null_mut(),
                NCRYPT_SILENT_FLAG,
                blob.as_ptr(),
                blob.len() as u32,
                null(),
                std::mem::zeroed(),
                &mut out,
                &mut len,
            ))?;
            let data = std::slice::from_raw_parts(out, len as usize).to_vec();
            LocalFree(out as HLOCAL);
            Ok(data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A credential under a name no real one has, removed afterwards.
        #[test]
        fn credential_manager_round_trip() {
            let target = format!(
                "Pathwarden test {}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            match cred_write(&target, b"a test passphrase", Some("a test comment")) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_NO_SUCH_LOGON_SESSION) => {
                    eprintln!("no Credential Manager in this logon: skipping");
                    return;
                }
                Err(e) => panic!("{e}"),
            }
            // Read back, allowing the store a moment: once, under a full
            // machine of parallel builds, the first read found nothing.
            let mut read = cred_read(&target);
            for _ in 0..10 {
                if !matches!(read, Ok(None)) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                read = cred_read(&target);
            }
            let deleted = cred_delete(&target);
            assert_eq!(read.unwrap().as_deref(), Some(&b"a test passphrase"[..]));
            assert!(deleted.unwrap());
            assert_eq!(cred_read(&target).unwrap(), None);
            assert!(!cred_delete(&target).unwrap());
        }

        /// DPAPI-NG to this account ("LOCAL=user"; a gMSA's "SID=" needs a
        /// domain).
        #[test]
        fn dpapi_ng_round_trip() {
            let blob = protect("LOCAL=user", b"a test passphrase").unwrap();
            assert!(!blob.windows(6).any(|w| w == b"a test"));
            assert_eq!(unprotect(&blob).unwrap(), b"a test passphrase");
            let mut bad = blob.clone();
            let n = bad.len() - 1;
            bad[n] ^= 1;
            assert!(unprotect(&bad).is_err());
        }

        /// The protected file gets its own access list: nobody but
        /// this account, Administrators and SYSTEM can change it, and the
        /// account it is for can only read it. What `--for-account` writes,
        /// short of the domain a gMSA's `SID=` needs; forgetting it for an
        /// account removes that account's file only.
        #[test]
        fn the_protected_file_is_private_to_its_account() {
            use crate::crypt;
            use crate::keystore::{
                check_protected_file, protected_file, store_for_account, write_protected_file,
            };
            use crate::perms::{current_user_sid, others_with_access};
            let base = std::env::temp_dir().join(format!("pw-dpapi-acl-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let dir = base.join("state");
            std::fs::create_dir_all(&dir).unwrap();
            let me = current_user_sid().unwrap();
            let pass = crypt::secret_from("a test passphrase");
            let file = write_protected_file(&dir, &me, "LOCAL=user", &pass).unwrap();
            assert_eq!(file, protected_file(&dir, &me).unwrap());
            assert!(others_with_access(&file).is_empty(), "{file:?}");
            assert_eq!(
                unprotect(&std::fs::read(&file).unwrap()).unwrap(),
                b"a test passphrase"
            );
            assert!(!file.with_extension("dpapi.tmp").exists());

            // This account's own file is read.
            let security =
                |p: &std::path::Path| crate::perms::file_security(&std::fs::File::open(p).unwrap());
            assert!(check_protected_file(&file, security(&file).as_ref(), &me).is_ok());

            // For another account (Users, standing in for a gMSA): owned by
            // Administrators, which needs an elevated prompt; it may read,
            // not change, and the account that wrote it can't either.
            let users = "S-1-5-32-545";
            match write_protected_file(&dir, users, "LOCAL=user", &pass) {
                Ok(other) => {
                    let access = others_with_access(&other);
                    assert!(
                        access.iter().any(|a| a.read) && access.iter().all(|a| !a.write),
                        "{access:?}"
                    );
                    let sec = security(&other).unwrap();
                    assert_eq!(sec.owner, "S-1-5-32-544");
                    assert!(!sec.writers.contains(&me), "{sec:?}");
                    assert!(check_protected_file(&other, Some(&sec), users).is_ok());
                }
                Err(e) => {
                    let e = format!("{e:#}");
                    assert!(e.contains("needs an elevated prompt"), "{e}");
                    assert!(!protected_file(&dir, users).unwrap().exists());
                    assert!(!protected_file(&dir, users)
                        .unwrap()
                        .with_extension("dpapi.tmp")
                        .exists());
                }
            }
            let injected = "S-1-5-32-545)(A;;FA;;;WD";
            assert!(crate::perms::make_file_private_for(&file, Some(injected)).is_err());
            assert!(crate::perms::make_file_admin_owned_for(&file, injected).is_err());

            // A file someone else may change isn't read: they could have
            // put a passphrase of their choosing there.
            let ok = crate::spawn::quiet("icacls")
                .arg(&file)
                .args(["/grant", "*S-1-5-32-545:(M)"])
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(ok);
            let e = check_protected_file(&file, security(&file).as_ref(), &me)
                .unwrap_err()
                .to_string();
            assert!(e.contains("can be changed by S-1-5-32-545"), "{e}");
            assert!(e.contains("isn't used"), "{e}");
            let e = check_protected_file(&file, None, &me)
                .unwrap_err()
                .to_string();
            assert!(e.contains("permissions can't be read"), "{e}");

            // An account that doesn't exist is named, and nothing is written.
            let e = format!(
                "{:#}",
                store_for_account(&dir, "CONTOSO\\no-such-gmsa$", &pass).unwrap_err()
            );
            assert!(
                e.contains("finding the account CONTOSO\\no-such-gmsa$"),
                "{e}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder has the same full path, and so the same key, before it
    /// is made and after, also under a parent that isn't there yet and
    /// through a link (a junction on Windows).
    #[test]
    fn a_folder_is_named_the_same_before_and_after_it_is_made() {
        let base = std::env::temp_dir().join(format!("pw-fullpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real")).unwrap();
        let mut ways = vec![base.join("real").join("a").join("history")];
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(base.join("real"), base.join("link")).is_ok();
        #[cfg(windows)]
        let linked = crate::spawn::quiet("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(base.join("link"))
            .arg(base.join("real"))
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        #[cfg(not(any(unix, windows)))]
        let linked = false;
        if linked {
            ways.push(base.join("link").join("a").join("history"));
        }
        let made = base.join("real").join("a").join("history");
        let before: Vec<String> = ways.iter().map(|w| history_key(w)).collect();
        std::fs::create_dir_all(&made).unwrap();
        for (w, key) in ways.iter().zip(&before) {
            assert_eq!(*key, history_key(w), "{}", w.display());
            assert_eq!(*key, history_key(&made), "{}", w.display());
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A program started through [`scrub_env`] (git, here) doesn't get
    /// the passphrase variables, even when its parent has them.
    #[test]
    fn children_never_get_the_passphrase() {
        let mut cmd = crate::spawn::quiet("git");
        cmd.env(ENV_VAR, "secret one")
            .env(NEW_ENV_VAR, "secret two")
            .env(EVIDENCE_KEY_ENV, "secret three")
            .env(COLLECT_PASSWORD_ENV, "secret four");
        scrub_env(&mut cmd).args([
            "-c",
            "alias.zz=!printf '[%s][%s][%s][%s]' \"$PATHWARDEN_HISTORY_PASSPHRASE\" \"$PATHWARDEN_HISTORY_NEW_PASSPHRASE\" \"$PATHWARDEN_EVIDENCE_KEY\" \"$PATHWARDEN_COLLECT_PASSWORD\"",
            "zz",
        ]);
        let Ok(out) = cmd.output() else {
            assert!(std::env::var_os("CI").is_none(), "git is required in CI");
            return;
        };
        assert_eq!(String::from_utf8_lossy(&out.stdout), "[][][][]");
        assert!(is_secret_env("pathwarden_history_passphrase"));
        assert!(is_secret_env(NEW_ENV_VAR));
        // Nor may a plugin ask for the signing key or the collection
        // password by name.
        assert!(is_secret_env("pathwarden_evidence_key"));
        assert!(is_secret_env("PATHWARDEN_COLLECT_PASSWORD"));
        assert!(!is_secret_env("JIRA_TOKEN"));
    }

    /// Without the account's data folder in the environment, the record
    /// can't be kept: an error, never a silent "no record".
    #[test]
    fn the_records_folder_needs_the_accounts_environment() {
        use std::ffi::OsString;
        let none = |_: &str| None::<OsString>;
        let e = pins_dir_from(none, true).unwrap_err().to_string();
        assert!(e.contains("LOCALAPPDATA is not set"), "{e}");
        let e = pins_dir_from(none, false).unwrap_err().to_string();
        assert!(e.contains("XDG_STATE_HOME nor HOME"), "{e}");
        let empty = |_: &str| Some(OsString::new());
        assert!(pins_dir_from(empty, true).is_err());
        let win =
            |n: &str| (n == "LOCALAPPDATA").then(|| OsString::from(r"C:\Users\x\AppData\Local"));
        assert!(pins_dir_from(win, true)
            .unwrap()
            .ends_with(Path::new("Pathwarden").join("history-pins")));
        // A relative XDG_STATE_HOME is ignored (the XDG rule): HOME's.
        let rel = |n: &str| match n {
            "XDG_STATE_HOME" => Some(OsString::from("relative/state")),
            "HOME" => Some(OsString::from(if cfg!(windows) {
                r"C:\home\x"
            } else {
                "/home/x"
            })),
            _ => None,
        };
        let dir = pins_dir_from(rel, false).unwrap();
        assert!(
            !dir.to_string_lossy().contains("relative"),
            "{}",
            dir.display()
        );
        assert!(dir.ends_with(
            std::path::Path::new(".local")
                .join("state")
                .join("pathwarden")
                .join("history-pins")
        ));
        let rel_only = |n: &str| (n == "XDG_STATE_HOME").then(|| OsString::from("relative"));
        assert!(pins_dir_from(rel_only, false).is_err());
    }

    #[test]
    fn a_history_is_known_by_its_full_path() {
        let a = history_key(Path::new("some/relative/state"));
        assert!(std::path::Path::new(&a).is_absolute(), "{a}");
        if cfg!(windows) {
            assert_eq!(
                history_key(Path::new(r"C:\X\State")),
                history_key(Path::new("c:/x/state"))
            );
        }
        let f = protected_file(Path::new("/srv/pw/state"), "S-1-5-21-1").unwrap();
        assert!(
            f.ends_with("state.passphrase.S-1-5-21-1.dpapi"),
            "{}",
            f.display()
        );
    }
}
