//! Evidence packs: a signed, self-contained record for auditors, insurers
//! and customers, "finding X was fixed, shown by the collection of date Y",
//! which anyone can check without trusting the person who hands it over.
//!
//! - [`content`]: what goes into a pack (verdicts, findings before and
//!   after, history, hashes), with names left out when it is redacted;
//! - [`pack`]: the pack on disk or in memory, its manifest, and checking
//!   one;
//! - [`sign`]: Ed25519 keys and signatures in minisign's format.
//!
//! `pathwarden evidence` and the app's run page both build their packs
//! with [`contents`] and [`pack`]; docs/evidence.md describes the format
//! for third-party verification.

pub mod content;
pub mod pack;
pub mod sign;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use sign::{normalize_fingerprint, PublicKey, SecretKey, KEY_ENV};

/// The secret and public key files of a key folder.
pub const KEY_FILE: &str = "evidence.key";
pub const PUB_FILE: &str = "evidence.pub";

/// Creates a signing key in `dir`, a new folder only this account can read
/// (it must not exist yet, so nobody can prepare it in advance): the
/// secret key [`KEY_FILE`] and the public key [`PUB_FILE`].
pub fn create_key_dir(dir: &Path) -> Result<SecretKey> {
    crate::perms::create_private_dir(dir).with_context(|| {
        format!(
            "creating {} (it must not exist yet, so nobody can prepare it in advance)",
            dir.display()
        )
    })?;
    let key = SecretKey::generate()?;
    write_key_files(dir, &key)?;
    Ok(key)
}

/// Writes `key`'s two files into `dir` (an existing private folder); the
/// files must not exist yet.
pub fn write_key_files(dir: &Path, key: &SecretKey) -> Result<()> {
    let secret = dir.join(KEY_FILE);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        use std::io::Write;
        opts.open(&secret)
            .and_then(|mut f| f.write_all(key.file_text().as_bytes()))
            .with_context(|| format!("writing {}", secret.display()))?;
    }
    let public = dir.join(PUB_FILE);
    std::fs::write(&public, key.public().file_text())
        .with_context(|| format!("writing {}", public.display()))?;
    Ok(())
}

/// Puts `key`'s two files into `dir` (an existing private folder) in place
/// of the ones there, if any: each is written to a temporary file in the
/// folder and then renamed over the old one, so the old key is never gone
/// before the new one is whole.
pub fn replace_key_files(dir: &Path, key: &SecretKey) -> Result<()> {
    let tmp = dir.join(".new");
    // Only a leftover of an earlier attempt: this file name and nothing else.
    if tmp.exists() {
        for f in [KEY_FILE, PUB_FILE] {
            let p = tmp.join(f);
            if p.exists() {
                std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
            }
        }
        std::fs::remove_dir(&tmp).with_context(|| format!("removing {}", tmp.display()))?;
    }
    crate::perms::create_private_dir(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    write_key_files(&tmp, key)?;
    // Each rename replaces a whole file; the app reads the public key from
    // the secret one, so it never sees a half-written key.
    // The secret key first: if the public key's rename then fails, it is
    // written again from the key now on disk, so the pair always matches.
    std::fs::rename(tmp.join(KEY_FILE), dir.join(KEY_FILE))
        .with_context(|| format!("replacing {}", dir.join(KEY_FILE).display()))?;
    if std::fs::rename(tmp.join(PUB_FILE), dir.join(PUB_FILE)).is_err() {
        std::fs::write(dir.join(PUB_FILE), key.public().file_text())
            .with_context(|| format!("replacing {}", dir.join(PUB_FILE).display()))?;
        let _ = std::fs::remove_file(tmp.join(PUB_FILE));
    }
    std::fs::remove_dir(&tmp).with_context(|| format!("removing {}", tmp.display()))?;
    Ok(())
}

/// The secret key file `path` names: the file, or [`KEY_FILE`] in a folder.
pub fn key_file(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join(KEY_FILE)
    } else {
        path.to_path_buf()
    }
}

/// Reads the signing key in `path` (a key file, or a key folder).
pub fn read_secret_key(path: &Path) -> Result<SecretKey> {
    let path = key_file(path);
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path)
            .with_context(|| format!("reading the signing key {}", path.display()))?,
    );
    SecretKey::parse(&text).with_context(|| format!("reading the signing key {}", path.display()))
}

/// A pack's files and header, ready for [`pack::write`] or
/// [`pack::zip_bytes`].
pub struct Contents {
    pub files: Vec<(String, Vec<u8>)>,
    pub header: pack::Header,
}

/// The files of a pack, as `pathwarden evidence` and the app write them:
/// `README.txt`, `metadata.json`, `retest.json`, `findings.json`,
/// `history.json`, and `report.html` when there is one (never in a redacted
/// pack). A redacted pack is checked for every name in `withhold` first,
/// and refused if one is found.
pub fn contents(
    src: &content::Sources,
    fingerprint: &str,
    html: Option<String>,
    withhold: Option<&crate::diagnostics::NameScan>,
) -> Result<Contents> {
    let json_file = |v: &serde_json::Value| -> Result<Vec<u8>> {
        let mut out = serde_json::to_vec_pretty(v)?;
        out.push(b'\n');
        Ok(out)
    };
    let mut files = vec![
        (
            "README.txt".to_string(),
            src.readme(fingerprint).into_bytes(),
        ),
        ("metadata.json".to_string(), json_file(&src.metadata())?),
        ("retest.json".to_string(), json_file(&src.retest()?)?),
        ("findings.json".to_string(), json_file(&src.findings())?),
        ("history.json".to_string(), json_file(&src.history())?),
    ];
    if let Some(html) = html.filter(|_| !src.redact) {
        files.push(("report.html".to_string(), html.into_bytes()));
    }
    let summary = src.summary();
    if src.redact {
        let names = withhold.context("a redacted pack needs the names to leave out")?;
        let mut check = files.clone();
        check.push((
            "manifest summary".to_string(),
            serde_json::to_vec(&summary)?,
        ));
        content::check_redacted(&check, names)?;
    }
    Ok(Contents {
        files,
        header: pack::Header {
            created_at: src.created_at,
            redacted: src.redact,
            summary,
        },
    })
}
