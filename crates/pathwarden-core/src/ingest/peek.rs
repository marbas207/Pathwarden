//! The domains in a collection, read without analyzing it: only the
//! collector's domains files (`*domains.json`, alone, in a folder or in a
//! `.zip`). The UI shows them before an analysis starts and the command
//! line decides where a run goes from them; both decide again from the
//! analysis itself ([`crate::analyze::domain_names`]), which also counts a
//! domain whose users or computers are in the data.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use super::extension;

/// The most of one domains file read (decompressed). A domains file holds
/// the domain objects with their GPO links, so it is small next to the
/// users and computers; a larger one is skipped.
pub const MAX_DOMAINS_FILE: u64 = 64 << 20;

/// Domains files read from one input at most (a folder of many
/// collections).
const MAX_FILES: usize = 64;

/// How far a folder is looked through: entries seen and depth. A peek runs
/// as a path is typed, so a path like `C:\` must not walk the whole disk;
/// past these, the analysis itself decides.
const MAX_ENTRIES: usize = 4000;
const MAX_DEPTH: usize = 4;

/// Domain names found in domains files, upper case, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeekedDomains {
    /// Domains whose data was collected.
    pub collected: Vec<String>,
    /// Domains with an object marked not collected (RustHound-CE writes
    /// one for each trusted domain), and not collected in another file.
    pub trusted: Vec<String>,
}

impl PeekedDomains {
    pub fn is_empty(&self) -> bool {
        self.collected.is_empty() && self.trusted.is_empty()
    }

    /// Adds the domains of one domains file ([`domains_in_json`]).
    pub fn add(&mut self, found: &[(String, bool)]) {
        for (name, collected) in found {
            if *collected {
                self.trusted.retain(|t| t != name);
                if !self.collected.contains(name) {
                    self.collected.push(name.clone());
                }
            } else if !self.collected.contains(name) && !self.trusted.contains(name) {
                self.trusted.push(name.clone());
            }
        }
        self.collected.sort();
        self.trusted.sort();
    }
}

/// Whether a file (or zip entry) name is a collector's domains file.
pub fn is_domains_file(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("domains.json")
}

/// The domain objects of a domains file: each one's name (upper case) and
/// whether it was collected (`collected: false` marks a trusted domain).
/// `None` when the text is not a domains file.
pub fn domains_in_json(bytes: &[u8]) -> Option<Vec<(String, bool)>> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if let Some(kind) = v.pointer("/meta/type").and_then(|t| t.as_str()) {
        if !kind.eq_ignore_ascii_case("domains") {
            return None;
        }
    }
    let data = v.get("data")?.as_array()?;
    let mut out = Vec::new();
    for d in data {
        let Some(props) = d.get("Properties") else {
            continue;
        };
        let name = props
            .get("name")
            .or_else(|| props.get("domain"))
            .and_then(|n| n.as_str())
            .map(|n| n.trim().trim_end_matches('.').to_ascii_uppercase())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let collected = props.get("collected").and_then(|c| c.as_bool()) != Some(false);
        out.push((name, collected));
    }
    Some(out)
}

/// The domains in `inputs` (files, folders or zips), from their domains
/// files. Unreadable inputs and files are left out; an empty result means
/// none could be read.
pub fn peek_domains<P: AsRef<Path>>(inputs: &[P]) -> PeekedDomains {
    let mut out = PeekedDomains::default();
    for input in inputs {
        let files = candidates(input.as_ref());
        let mut read = 0;
        for file in files {
            if read >= MAX_FILES {
                break;
            }
            match extension(&file).as_str() {
                "json" if is_domains_file(&file.to_string_lossy()) => {
                    let Ok(f) = File::open(&file) else { continue };
                    if let Some(found) = read_capped(f).and_then(|b| domains_in_json(&b)) {
                        out.add(&found);
                        read += 1;
                    }
                }
                "zip" => read += peek_zip(&file, &mut out, MAX_FILES - read),
                _ => {}
            }
        }
    }
    out
}

/// The `.json` and `.zip` files of one input: the file itself, or those in
/// a folder (links not followed, within [`MAX_ENTRIES`] and
/// [`MAX_DEPTH`]), in name order.
fn candidates(path: &Path) -> Vec<std::path::PathBuf> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Vec::new();
    };
    if !meta.is_dir() {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    let mut seen = 0;
    let mut level = vec![path.to_path_buf()];
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        for dir in level {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                seen += 1;
                if seen > MAX_ENTRIES {
                    return out;
                }
                match std::fs::symlink_metadata(&e) {
                    Ok(m) if m.file_type().is_symlink() => {}
                    Ok(m) if m.is_dir() => next.push(e),
                    Ok(_) if matches!(extension(&e).as_str(), "json" | "zip") => out.push(e),
                    _ => {}
                }
            }
        }
        level = next;
    }
    out
}

/// The domains files in one zip; returns how many were read.
fn peek_zip(path: &Path, out: &mut PeekedDomains, most: usize) -> usize {
    let Ok(file) = File::open(path) else {
        return 0;
    };
    let Ok(mut archive) = zip::ZipArchive::new(BufReader::new(file)) else {
        return 0;
    };
    let mut read = 0;
    for i in 0..archive.len() {
        if read >= most {
            break;
        }
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if !is_domains_file(&super::entry_name(&entry)) || entry.size() > MAX_DOMAINS_FILE {
            continue;
        }
        if let Some(found) = read_capped(entry).and_then(|b| domains_in_json(&b)) {
            out.add(&found);
            read += 1;
        }
    }
    read
}

/// All of `r`, unless it is longer than [`MAX_DOMAINS_FILE`].
fn read_capped(r: impl Read) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(MAX_DOMAINS_FILE + 1).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 <= MAX_DOMAINS_FILE).then_some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn testdata(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(name)
    }

    #[test]
    fn reads_collected_and_trusted_domains() {
        let essos = testdata("rusthound/20261011195626_essos-local_domains.json");
        let p = peek_domains(&[&essos]);
        assert_eq!(p.collected, ["ESSOS.LOCAL"]);
        // Both collections: each domain collected in one of them.
        let both = peek_domains(&[testdata("rusthound")]);
        assert_eq!(both.collected, ["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"]);
        assert!(both.trusted.is_empty());
        // RustHound-CE in a zip: the trusted domain's object is marked.
        let dir = std::env::temp_dir().join(format!("pw-peek-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("20261011195626_essos-local_rusthound-ce.zip");
        let mut z = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        z.start_file("20261011195626_essos-local_users.json", opts)
            .unwrap();
        std::io::Write::write_all(&mut z, br#"{"data":[],"meta":{"type":"users"}}"#).unwrap();
        z.start_file("20261011195626_essos-local_domains.json", opts)
            .unwrap();
        std::io::Write::write_all(
            &mut z,
            br#"{"data":[{"Properties":{"name":"ESSOS.LOCAL","collected":true}},{"Properties":{"name":"SEVENKINGDOMS.LOCAL","collected":false}}],"meta":{"type":"domains"}}"#,
        )
        .unwrap();
        z.finish().unwrap();
        let p = peek_domains(&[&zip_path]);
        assert_eq!(p.collected, ["ESSOS.LOCAL"]);
        assert_eq!(p.trusted, ["SEVENKINGDOMS.LOCAL"]);
        let _ = std::fs::remove_dir_all(&dir);
        // SharpHound: no flag, so collected.
        assert_eq!(
            peek_domains(&[testdata("forest")]).collected,
            ["CHILD.CONTOSO.LOCAL", "CONTOSO.LOCAL"]
        );
    }

    #[test]
    fn other_files_and_bad_text_read_as_nothing() {
        assert_eq!(domains_in_json(b"{not json"), None);
        assert_eq!(
            domains_in_json(br#"{"data":[],"meta":{"type":"users"}}"#),
            None
        );
        assert_eq!(
            domains_in_json(
                br#"{"data":[{"Properties":{"name":"a.local."}},{"Properties":{"name":"B.LOCAL","collected":false}}],"meta":{"type":"domains"}}"#
            ),
            Some(vec![("A.LOCAL".into(), true), ("B.LOCAL".into(), false)])
        );
        assert!(peek_domains(&[testdata("does-not-exist")]).is_empty());
        assert!(is_domains_file("x/20240410083816_DOMAINS.json"));
        assert!(!is_domains_file("x_users.json"));
    }
}
