//! The pack on disk: files, `manifest.json` (every other file's SHA-256),
//! and `manifest.json.minisig` (the manifest's signature). A pack is a zip
//! or a folder with the same files; verifying one needs only the public key.
//!
//! The format is written up in docs/evidence.md, and
//! scripts/verify_evidence.py checks a pack independently of this code.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::sign::{normalize_fingerprint, PublicKey, SecretKey, Signature};

pub const SCHEMA: &str = "pathwarden.evidence.v1";
pub const MANIFEST: &str = "manifest.json";
pub const SIGNATURE: &str = "manifest.json.minisig";

/// Largest manifest or signature read (they are a few KB).
const MAX_SMALL: u64 = 4 << 20;
/// Most entries a pack may hold (Pathwarden writes fewer than ten).
const MAX_ENTRIES: usize = 1000;
/// Most a zipped pack may unpack to, all files together (a pack holds a
/// report and a few JSON files: a few MB, rarely more than 100).
const MAX_UNPACKED: u64 = 1 << 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    /// Unix time the pack was made, and the same as UTC text.
    pub created_at: i64,
    pub created: String,
    pub pathwarden: String,
    /// Names and the HTML report left out (`--redact`).
    pub redacted: bool,
    pub signer: Signer,
    /// What the pack shows, in brief (the details are in the files).
    pub summary: serde_json::Value,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub algorithm: String,
    /// The minisign-format public key (`RW...`).
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SHA-256 and size of a file, streamed.
pub fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut f = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    hash_reader(&mut f).with_context(|| format!("reading {}", path.display()))
}

fn hash_reader(r: &mut dyn Read) -> std::io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n = 0u64;
    loop {
        let got = r.read(&mut buf)?;
        if got == 0 {
            break;
        }
        h.update(&buf[..got]);
        n += got as u64;
    }
    Ok((hex(&h.finalize()), n))
}

/// What goes into a pack besides the files.
pub struct Header {
    pub created_at: i64,
    pub redacted: bool,
    pub summary: serde_json::Value,
}

/// Writes the pack: a zip when `out` ends in `.zip`, else a new folder.
/// Returns the manifest written.
pub fn write(
    out: &Path,
    files: &[(String, Vec<u8>)],
    header: Header,
    key: &SecretKey,
) -> Result<Manifest> {
    let (manifest, manifest_bytes, sig) = seal(files, header, key)?;
    let all = with_seal(files, &manifest_bytes, &sig);
    if is_zip(out) {
        write_zip(out, &all)?;
    } else {
        write_folder(out, &all)?;
    }
    Ok(manifest)
}

/// The pack as a zip in memory (the app's download), with its manifest.
pub fn zip_bytes(
    files: &[(String, Vec<u8>)],
    header: Header,
    key: &SecretKey,
) -> Result<(Vec<u8>, Manifest)> {
    let (manifest, manifest_bytes, sig) = seal(files, header, key)?;
    let all = with_seal(files, &manifest_bytes, &sig);
    let mut out = std::io::Cursor::new(Vec::new());
    zip_into(&mut out, &all)?;
    Ok((out.into_inner(), manifest))
}

fn with_seal<'a>(
    files: &'a [(String, Vec<u8>)],
    manifest_bytes: &'a [u8],
    sig: &'a str,
) -> Vec<(&'a str, &'a [u8])> {
    let mut all: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    all.push((MANIFEST, manifest_bytes));
    all.push((SIGNATURE, sig.as_bytes()));
    all
}

/// The manifest of `files`, its bytes, and its signature file.
fn seal(
    files: &[(String, Vec<u8>)],
    header: Header,
    key: &SecretKey,
) -> Result<(Manifest, Vec<u8>, String)> {
    for (name, _) in files {
        check_name(name).map_err(anyhow::Error::msg)?;
        if name == MANIFEST || name == SIGNATURE {
            bail!("{name} is reserved");
        }
    }
    let pk = key.public();
    let manifest = Manifest {
        schema: SCHEMA.to_string(),
        created_at: header.created_at,
        created: iso(header.created_at),
        pathwarden: env!("CARGO_PKG_VERSION").to_string(),
        redacted: header.redacted,
        signer: Signer {
            algorithm: "ed25519 (minisign legacy \"Ed\")".into(),
            public_key: pk.minisign(),
            fingerprint: pk.fingerprint(),
        },
        summary: header.summary,
        files: files
            .iter()
            .map(|(path, data)| FileEntry {
                path: path.clone(),
                sha256: sha256_hex(data),
                bytes: data.len() as u64,
            })
            .collect(),
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    let comment = format!(
        "Pathwarden evidence pack, created {} by Pathwarden {}, manifest sha256 {}",
        manifest.created,
        manifest.pathwarden,
        sha256_hex(&manifest_bytes)
    );
    let sig = key.sign(&manifest_bytes, &comment);
    Ok((manifest, manifest_bytes, sig))
}

fn zip_into<W: Write + Seek>(w: W, files: &[(&str, &[u8])]) -> Result<W> {
    let mut zip = zip::ZipWriter::new(w);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in files {
        zip.start_file(*name, opts)?;
        zip.write_all(data)?;
    }
    Ok(zip.finish()?)
}

pub fn is_zip(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
}

fn write_zip(out: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    // Never overwritten: an existing pack is someone's evidence.
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("creating {} (it must not exist yet)", out.display()))?;
    let result = (|| -> Result<()> {
        zip_into(f, files)?.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(out);
        return Err(e.context(format!("writing {}", out.display())));
    }
    Ok(())
}

fn write_folder(out: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    fs::create_dir(out).with_context(|| {
        format!(
            "creating the folder {} (it must not exist yet; end the name in .zip for a zip)",
            out.display()
        )
    })?;
    for (name, data) in files {
        let path = out.join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(data)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// A pack's file names: plain relative paths with `/`, nothing that could
/// escape a folder or mean different files on different systems.
fn check_name(name: &str) -> Result<(), String> {
    let bad = name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains(':')
        || name.contains('\0')
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..");
    if bad {
        Err(format!("{name:?} is not an allowed file name in a pack"))
    } else {
        Ok(())
    }
}

/// One file found in a pack.
struct Found {
    sha256: String,
    bytes: u64,
    /// Kept for the manifest and the signature only.
    content: Option<Vec<u8>>,
}

/// Reads a pack (zip or folder): every file's hash, and the manifest and
/// signature themselves. Errors describe a pack that can't be read at all,
/// or whose structure was tampered with (duplicate or unsafe names).
fn read(pack: &Path) -> Result<BTreeMap<String, Found>> {
    let mut out = BTreeMap::new();
    let keep = |name: &str| name == MANIFEST || name == SIGNATURE;
    if pack.is_dir() {
        for (name, path) in walk(pack, pack)? {
            check_name(&name).map_err(anyhow::Error::msg)?;
            if out.len() >= MAX_ENTRIES {
                bail!("the pack has more than {MAX_ENTRIES} files");
            }
            let found = if keep(&name) {
                let data = read_small(&mut fs::File::open(&path)?)
                    .with_context(|| format!("reading {}", path.display()))?;
                Found {
                    sha256: sha256_hex(&data),
                    bytes: data.len() as u64,
                    content: Some(data),
                }
            } else {
                let (sha256, bytes) = hash_file(&path)?;
                Found {
                    sha256,
                    bytes,
                    content: None,
                }
            };
            out.insert(name, found);
        }
        return Ok(out);
    }
    let f = fs::File::open(pack).with_context(|| format!("opening {}", pack.display()))?;
    read_zip(std::io::BufReader::new(f))
}

/// [`read`] for a zip from anywhere (a file, or bytes the app received).
fn read_zip<R: Read + Seek>(mut r: R) -> Result<BTreeMap<String, Found>> {
    let mut out = BTreeMap::new();
    let keep = |name: &str| name == MANIFEST || name == SIGNATURE;
    let listed = listed_entries(&mut r);
    let mut zip = zip::ZipArchive::new(r)
        .context("not a readable zip file (damaged, or not an evidence pack)")?;
    if zip.len() > MAX_ENTRIES {
        bail!("the pack has more than {MAX_ENTRIES} entries");
    }
    // The zip reader keeps one entry per name: a second file of the same
    // name would go unread, so the count the zip lists must match. A count
    // it doesn't list (Zip64) is refused too: Pathwarden never writes one.
    match listed {
        Some(n) if n == zip.len() as u64 => {}
        Some(_) => bail!("the pack contains two files of the same name"),
        None => bail!("the zip doesn't list how many files it holds (not a pack Pathwarden wrote)"),
    }
    // Each file's own header must say what the zip's directory says (name,
    // sizes, checksum), with nothing hidden between files: otherwise another
    // zip tool could show different files from the ones checked here.
    if let Err(e) = crate::ingest::check_zip(&mut zip) {
        bail!("the pack's file headers don't match its directory (changed after it was made): {e}");
    }
    // Nor anything before the first file (a pack starts with one).
    if zip.offset() != 0 {
        bail!("the pack's file headers don't match its directory (data before its first file)");
    }
    // What the zip says its files unpack to, before reading any: a pack
    // that would unpack to more is refused (a zip bomb, not a pack).
    let mut declared = 0u64;
    for i in 0..zip.len() {
        let e = zip.by_index_raw(i).context("reading the zip")?;
        declared = declared.saturating_add(e.size());
    }
    if declared > MAX_UNPACKED {
        bail!(
            "the pack would unpack to {} MB, more than any evidence pack ({} MB at most)",
            declared >> 20,
            MAX_UNPACKED >> 20
        );
    }
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).context("reading the zip")?;
        let name = entry.name().context("reading the zip")?.into_owned();
        if entry.is_dir() {
            continue;
        }
        check_name(&name).map_err(anyhow::Error::msg)?;
        if out.contains_key(&name) {
            bail!("the pack contains two files named {name}");
        }
        // Never more than the entry says it holds.
        let size = entry.size();
        let found = if keep(&name) {
            let data = read_small(&mut entry).context("reading the zip")?;
            if data.len() as u64 > size {
                bail!("{name} holds more than the zip says it does");
            }
            Found {
                sha256: sha256_hex(&data),
                bytes: data.len() as u64,
                content: Some(data),
            }
        } else {
            let (sha256, bytes) = hash_reader(&mut (&mut entry).take(size.saturating_add(1)))
                .context("reading the zip")?;
            if bytes > size {
                bail!("{name} holds more than the zip says it does");
            }
            Found {
                sha256,
                bytes,
                content: None,
            }
        };
        out.insert(name, found);
    }
    Ok(out)
}

/// How many entries the zip's end record lists (`None` when it can't be
/// read, or for a Zip64 archive, which a pack never is). Leaves `r` at its
/// start.
fn listed_entries<R: Read + Seek>(r: &mut R) -> Option<u64> {
    use std::io::SeekFrom;
    let len = r.seek(SeekFrom::End(0)).ok()?;
    // The end record (22 bytes) and a comment of up to 64 KiB.
    let tail_len = len.min(22 + 0xFFFF);
    r.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    r.read_exact(&mut tail).ok()?;
    r.seek(SeekFrom::Start(0)).ok()?;
    let at = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| &tail[i..i + 4] == b"PK\x05\x06")?;
    let n = u16::from_le_bytes([tail[at + 10], tail[at + 11]]);
    (n != 0xFFFF).then_some(u64::from(n))
}

fn read_small(r: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    r.take(MAX_SMALL + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_SMALL {
        return Err(std::io::Error::other("larger than any manifest"));
    }
    Ok(data)
}

/// Files under `dir`, as (`a/b.json`, path). Links are refused: a pack
/// folder holds plain files.
fn walk(root: &Path, dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let e = e?;
        let path = e.path();
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            bail!(
                "{} is a link; a pack folder holds plain files only",
                path.display()
            );
        }
        if kind.is_dir() {
            out.extend(walk(root, &path)?);
            if out.len() > MAX_ENTRIES {
                bail!("the pack has more than {MAX_ENTRIES} files");
            }
        } else {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(out)
}

/// Which key the signature must come from.
#[derive(Debug, Clone, Default)]
pub struct Expected {
    /// The organisation's public key.
    pub key: Option<PublicKey>,
    /// Or its fingerprint (`SHA256:...`).
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Intact, and signed by the expected key.
    Verified,
    /// Intact and validly signed, but no key or fingerprint was given to say
    /// whose key it is.
    SignerNotChecked,
    /// Changed, damaged, or signed by another key.
    Failed,
}

#[derive(Debug, Serialize)]
pub struct Verification {
    pub outcome: Outcome,
    /// What went wrong, one sentence each.
    pub problems: Vec<String>,
    /// Fingerprint of the key that signed the manifest (when the signature
    /// is valid).
    pub signed_by: Option<String>,
    pub files_checked: usize,
    pub files_ok: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_comment: Option<String>,
}

/// Verifies a pack: the signature over the manifest, the key that made it,
/// and every file's SHA-256. Errors only when the pack can't be found.
pub fn verify(pack: &Path, expected: &Expected) -> Result<Verification> {
    if !pack.exists() {
        bail!("{} does not exist", pack.display());
    }
    Ok(verify_found(read(pack), expected))
}

/// [`verify`] for a zipped pack in memory (one uploaded to the app).
pub fn verify_zip(bytes: &[u8], expected: &Expected) -> Verification {
    verify_found(read_zip(std::io::Cursor::new(bytes)), expected)
}

fn verify_found(read: Result<BTreeMap<String, Found>>, expected: &Expected) -> Verification {
    let mut v = Verification {
        outcome: Outcome::Failed,
        problems: Vec::new(),
        signed_by: None,
        files_checked: 0,
        files_ok: 0,
        manifest: None,
        trusted_comment: None,
    };
    let mut found = match read {
        Ok(f) => f,
        Err(e) => {
            v.problems.push(format!("the pack can't be read: {e:#}"));
            return v;
        }
    };
    let manifest_bytes = found.remove(MANIFEST).and_then(|f| f.content);
    let sig_text = found.remove(SIGNATURE).and_then(|f| f.content);
    let Some(manifest_bytes) = manifest_bytes else {
        v.problems
            .push(format!("{MANIFEST} is missing, so nothing can be checked"));
        return v;
    };
    let manifest: Manifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            v.problems
                .push(format!("{MANIFEST} is not a valid evidence manifest ({e})"));
            return v;
        }
    };
    if manifest.schema != SCHEMA {
        v.problems.push(format!(
            "{MANIFEST} is a {:?} manifest; this Pathwarden reads {SCHEMA}",
            manifest.schema
        ));
    }

    // The signature: with the expected key if given, else the manifest's own
    // (which proves integrity, not who signed).
    let key = match &expected.key {
        Some(k) => Ok(k.clone()),
        None => PublicKey::parse(&manifest.signer.public_key)
            .map_err(|e| format!("the manifest's public key is unusable ({e})")),
    };
    let sig_ok = match (key, sig_text) {
        (Err(e), _) => {
            v.problems.push(e);
            None
        }
        (Ok(_), None) => {
            v.problems
                .push(format!("{SIGNATURE} is missing: the pack is not signed"));
            None
        }
        (Ok(key), Some(text)) => {
            let checked = std::str::from_utf8(&text)
                .map_err(|_| "the signature file is not text".to_string())
                .and_then(|t| {
                    Signature::parse(t)
                        .map_err(|e| e.to_string())
                        .map(|s| (t, s))
                })
                .and_then(|(text, sig)| {
                    sig.verify(&key, &manifest_bytes)?;
                    if sig.file_text(&key) != text {
                        return Err("the signature file was edited (its comment or layout \
                                    changed)"
                            .to_string());
                    }
                    Ok(sig)
                });
            match checked {
                Ok(sig) => {
                    v.trusted_comment = Some(sig.trusted_comment);
                    Some(key)
                }
                Err(e) if expected.key.is_some() && e.contains("different key") => {
                    v.problems.push(format!(
                        "the pack was not signed by the key you gave ({}): {e}",
                        expected
                            .key
                            .as_ref()
                            .map(PublicKey::fingerprint)
                            .unwrap_or_default()
                    ));
                    None
                }
                Err(e) => {
                    v.problems.push(format!("the signature is not valid: {e}"));
                    None
                }
            }
        }
    };
    let mut signer_checked = expected.key.is_some();
    if let Some(key) = &sig_ok {
        let fp = key.fingerprint();
        if key.minisign() != manifest.signer.public_key {
            v.problems.push(format!(
                "the manifest names a different signer ({}) than the key that signed it",
                manifest.signer.fingerprint
            ));
        }
        if let Some(want) = &expected.fingerprint {
            let want = normalize_fingerprint(want);
            if want != fp {
                v.problems.push(format!(
                    "the pack was signed by key {fp}, not by the expected {want}"
                ));
            }
            signer_checked = true;
        }
        v.signed_by = Some(fp);
    }

    // Every file in the manifest, as listed; nothing else in the pack.
    let mut listed = std::collections::HashSet::new();
    for entry in &manifest.files {
        v.files_checked += 1;
        if !listed.insert(entry.path.as_str()) {
            v.problems
                .push(format!("the manifest lists {} twice", entry.path));
            continue;
        }
        match found.get(&entry.path) {
            None => v
                .problems
                .push(format!("{} is missing from the pack", entry.path)),
            Some(f) if !f.sha256.eq_ignore_ascii_case(&entry.sha256) || f.bytes != entry.bytes => {
                v.problems.push(format!(
                    "{} was changed after signing (its SHA-256 does not match the manifest)",
                    entry.path
                ))
            }
            Some(_) => v.files_ok += 1,
        }
    }
    for name in found.keys() {
        if !listed.contains(name.as_str()) {
            v.problems.push(format!(
                "{name} is in the pack but not in the manifest (added after signing)"
            ));
        }
    }
    v.manifest = Some(manifest);
    v.outcome = if !v.problems.is_empty() || sig_ok.is_none() {
        Outcome::Failed
    } else if signer_checked {
        Outcome::Verified
    } else {
        Outcome::SignerNotChecked
    };
    v
}

/// `2026-10-10T08:30:00Z`.
pub fn iso(t: i64) -> String {
    let s = crate::time::format_unix(t); // "YYYY-MM-DD HH:MM"
    format!("{}T{}:{:02}Z", &s[..10], &s[11..16], t.rem_euclid(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_could_escape_are_refused() {
        for bad in ["", "/etc/x", "../x", "a/../x", "a\\b", "C:x", "a//b", "./a"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name("report.html").is_ok());
        assert!(check_name("dir/file.json").is_ok());
    }

    fn header() -> Header {
        Header {
            created_at: 1_791_590_400,
            redacted: false,
            summary: serde_json::json!({"counts": {"fixed": 1}}),
        }
    }

    /// The zip's entries, with `name` changed to `to`.
    fn edited(zip: &[u8], name: &str, to: &[u8]) -> Vec<u8> {
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(zip)).unwrap();
        let mut entries = Vec::new();
        for i in 0..a.len() {
            let mut e = a.by_index(i).unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            let n = e.name().unwrap().into_owned();
            entries.push((n.clone(), if n == name { to.to_vec() } else { data }));
        }
        let all: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        zip_into(std::io::Cursor::new(Vec::new()), &all)
            .unwrap()
            .into_inner()
    }

    #[test]
    fn a_pack_made_in_memory_checks_as_one_on_disk() {
        let key = SecretKey::generate().unwrap();
        let fp = key.public().fingerprint();
        let files = vec![
            ("README.txt".to_string(), b"hello".to_vec()),
            ("findings.json".to_string(), b"{}".to_vec()),
        ];
        let (zip, m) = zip_bytes(&files, header(), &key).unwrap();
        assert_eq!(m.files.len(), 2);
        assert_eq!(m.signer.fingerprint, fp);
        let expect = |fingerprint: Option<String>| Expected {
            key: None,
            fingerprint,
        };

        let v = verify_zip(&zip, &expect(Some(fp.clone())));
        assert_eq!(v.outcome, Outcome::Verified, "{:?}", v.problems);
        assert_eq!((v.files_ok, v.files_checked), (2, 2));
        assert_eq!(v.signed_by.as_deref(), Some(fp.as_str()));
        // Without a signer to expect: intact, but whose key is unknown.
        assert_eq!(
            verify_zip(&zip, &expect(None)).outcome,
            Outcome::SignerNotChecked
        );
        // Another signer expected.
        let other = SecretKey::generate().unwrap().public().fingerprint();
        let v = verify_zip(&zip, &expect(Some(other.clone())));
        assert_eq!(v.outcome, Outcome::Failed);
        assert!(v.problems.iter().any(|p| p.contains(&other)), "{v:?}");
        // A file changed after signing.
        let v = verify_zip(
            &edited(&zip, "findings.json", b"{\"x\":1}"),
            &expect(Some(fp.clone())),
        );
        assert_eq!(v.outcome, Outcome::Failed);
        assert!(
            v.problems
                .iter()
                .any(|p| p.starts_with("findings.json was changed after signing")),
            "{v:?}"
        );
        // Not a zip at all.
        let v = verify_zip(b"not a pack", &expect(None));
        assert_eq!(v.outcome, Outcome::Failed);
        assert!(v.problems[0].contains("can't be read"), "{v:?}");

        // The same files written to disk check the same way.
        let dir = std::env::temp_dir().join(format!("pw-pack-mem-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("p.zip");
        write(&out, &files, header(), &key).unwrap();
        let v = verify(&out, &expect(Some(fp))).unwrap();
        assert_eq!(v.outcome, Outcome::Verified, "{:?}", v.problems);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
        zip_into(std::io::Cursor::new(Vec::new()), entries)
            .unwrap()
            .into_inner()
    }

    /// Sets the uncompressed size the zip declares for `name`, in its local
    /// header and its central directory entry.
    fn declare_size(zip: &mut [u8], name: &str, size: u32) {
        let mut found = 0;
        for i in 0..zip.len().saturating_sub(46) {
            let (len_at, name_at, size_at) = match &zip[i..i + 4] {
                b"PK\x03\x04" => (i + 26, i + 30, i + 22),
                b"PK\x01\x02" => (i + 28, i + 46, i + 24),
                _ => continue,
            };
            let len = u16::from_le_bytes([zip[len_at], zip[len_at + 1]]) as usize;
            if zip.get(name_at..name_at + len) == Some(name.as_bytes()) {
                zip[size_at..size_at + 4].copy_from_slice(&size.to_le_bytes());
                found += 1;
            }
        }
        assert_eq!(found, 2, "{name}");
    }

    /// Every occurrence of `from` (a file name) made `to`, the same length.
    fn rename(zip: &mut [u8], from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let (f, t) = (from.as_bytes(), to.as_bytes());
        let mut i = 0;
        while i + f.len() <= zip.len() {
            if &zip[i..i + f.len()] == f {
                zip[i..i + f.len()].copy_from_slice(t);
            }
            i += 1;
        }
    }

    fn problems(zip: &[u8]) -> String {
        let v = verify_zip(zip, &Expected::default());
        assert_eq!(v.outcome, Outcome::Failed, "{v:?}");
        v.problems.join(" | ")
    }

    #[test]
    fn hostile_zips_are_refused_before_they_are_read() {
        let big = vec![b'x'; 4000];
        // Declaring more than any pack unpacks to.
        let mut z = zipped(&[("README.txt", b"hi"), ("findings.json", &big)]);
        declare_size(&mut z, "findings.json", 0xF000_0000);
        let p = problems(&z);
        assert!(p.contains("would unpack to"), "{p}");
        // Declaring less than the entry holds.
        let mut z = zipped(&[("README.txt", b"hi"), ("findings.json", &big)]);
        declare_size(&mut z, "findings.json", 10);
        let p = problems(&z);
        assert!(p.contains("can't be read"), "{p}");
        // A count the end record doesn't give (Zip64's 0xFFFF): refused,
        // so no duplicate can hide behind it.
        let mut z = zipped(&[("README.txt", b"hi")]);
        let at = (0..z.len() - 21)
            .rev()
            .find(|&i| &z[i..i + 4] == b"PK\x05\x06")
            .unwrap();
        z[at + 8..at + 12].copy_from_slice(&[0xFF; 4]);
        let p = problems(&z);
        assert!(p.contains("can't be read"), "{p}");
        // A name that leaves the folder.
        let mut z = zipped(&[("aa/x.json", b"{}")]);
        rename(&mut z, "aa/x.json", "../x.json");
        let p = problems(&z);
        assert!(p.contains("not an allowed file name"), "{p}");
        // Two files of one name.
        let mut z = zipped(&[("a.json", b"{}"), ("b.json", b"[]")]);
        rename(&mut z, "b.json", "a.json");
        let p = problems(&z);
        assert!(p.contains("two files of the same name"), "{p}");
    }

    /// Where the local header of `name` starts.
    fn local_header(zip: &[u8], name: &str) -> usize {
        (0..zip.len() - 30)
            .find(|&i| {
                &zip[i..i + 4] == b"PK\x03\x04"
                    && zip.get(i + 30..i + 30 + name.len()) == Some(name.as_bytes())
            })
            .unwrap_or_else(|| panic!("no local header for {name}"))
    }

    /// Takes `name` out of the central directory, leaving its local header
    /// and data in place: a file only a local-header reader would see.
    fn unlist(zip: &mut Vec<u8>, name: &str) {
        let at = (0..zip.len() - 46)
            .find(|&i| {
                &zip[i..i + 4] == b"PK\x01\x02"
                    && zip.get(i + 46..i + 46 + name.len()) == Some(name.as_bytes())
            })
            .unwrap();
        let u16_at = |z: &[u8], i: usize| u16::from_le_bytes([z[i], z[i + 1]]) as usize;
        let len = 46 + u16_at(zip, at + 28) + u16_at(zip, at + 30) + u16_at(zip, at + 32);
        zip.drain(at..at + len);
        let end = (0..zip.len() - 21)
            .rev()
            .find(|&i| &zip[i..i + 4] == b"PK\x05\x06")
            .unwrap();
        for count in [end + 8, end + 10] {
            let n = u16_at(zip, count) as u16 - 1;
            zip[count..count + 2].copy_from_slice(&n.to_le_bytes());
        }
        let size = u32::from_le_bytes(zip[end + 12..end + 16].try_into().unwrap()) - len as u32;
        zip[end + 12..end + 16].copy_from_slice(&size.to_le_bytes());
    }

    /// Zip cloaking (zip < 9.0.5): the zip's directory and each file's own
    /// header must agree, or another zip tool would show other files than
    /// the ones verified. Each case starts from a pack that verifies.
    #[test]
    fn a_pack_whose_local_headers_disagree_with_its_directory_is_refused() {
        let key = SecretKey::generate().unwrap();
        let files = vec![
            ("README.txt".to_string(), b"hello".to_vec()),
            ("findings.json".to_string(), b"{}".to_vec()),
        ];
        let (zip, _) = zip_bytes(&files, header(), &key).unwrap();
        let v = verify_zip(&zip, &Expected::default());
        assert_eq!(v.outcome, Outcome::SignerNotChecked, "{:?}", v.problems);

        let at = local_header(&zip, "findings.json");
        // Another name in the file's own header.
        let mut renamed = zip.clone();
        renamed[at + 30..at + 43].copy_from_slice(b"findingz.json");
        // Another size, or checksum.
        let mut resized = zip.clone();
        resized[at + 22..at + 26].copy_from_slice(&99u32.to_le_bytes());
        let mut recrc = zip.clone();
        recrc[at + 14] ^= 0xFF;
        // A file in the zip the directory doesn't list.
        let mut hidden = zipped(&[("README.txt", b"hi"), ("x.json", b"{}"), ("y.json", b"[]")]);
        unlist(&mut hidden, "x.json");
        // Bytes before the first file.
        let prefixed = [vec![0u8; 64], zip.clone()].concat();
        for (what, z) in [
            ("name", renamed),
            ("size", resized),
            ("crc", recrc),
            ("unlisted", hidden),
            ("prefixed", prefixed),
        ] {
            let p = problems(&z);
            assert!(p.contains("don't match its directory"), "{what}: {p}");
        }
    }

    #[test]
    fn iso_times() {
        assert_eq!(iso(1_791_590_400 + 3723), "2026-10-10T01:02:03Z");
    }
}
