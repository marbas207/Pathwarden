//! Finding, summarizing and cleaning up the files a collector writes.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pathwarden_core::perms::{self, Access};
use serde::Deserialize;

/// The `.zip` and `.json` files in a directory and their modification
/// times, taken before a collection so its new files can be told apart.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    files: HashMap<PathBuf, Option<SystemTime>>,
}

impl Snapshot {
    pub fn take(dir: &Path) -> Self {
        let files = collector_files(dir)
            .into_iter()
            .map(|p| {
                let modified = fs::metadata(&p).and_then(|m| m.modified()).ok();
                (p, modified)
            })
            .collect();
        Self { files }
    }
}

/// `.zip` and `.json` files directly in `dir` (not in subdirectories).
fn collector_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_collector_file(p))
        .collect();
    files.sort();
    files
}

fn is_collector_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip") || e.eq_ignore_ascii_case("json"))
}

/// Collector output written to `dir` since `before` was taken: files that
/// are new or were modified. If a zip was produced, loose JSON files are
/// ignored (SharpHound and RustHound-CE delete them after zipping).
pub fn discover_outputs(dir: &Path, before: &Snapshot) -> Vec<PathBuf> {
    let new: Vec<PathBuf> = collector_files(dir)
        .into_iter()
        .filter(|p| match before.files.get(p) {
            None => true,
            Some(old) => {
                let now = fs::metadata(p).and_then(|m| m.modified()).ok();
                now != *old
            }
        })
        .collect();
    let zips: Vec<PathBuf> = new
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")))
        .cloned()
        .collect();
    if zips.is_empty() {
        new
    } else {
        zips
    }
}

/// Removes files a failed or cancelled collection left behind.
pub(crate) fn remove_new_outputs(dir: &Path, before: &Snapshot) {
    for f in discover_all_new(dir, before) {
        let _ = fs::remove_file(f);
    }
}

fn discover_all_new(dir: &Path, before: &Snapshot) -> Vec<PathBuf> {
    collector_files(dir)
        .into_iter()
        .filter(|p| !before.files.contains_key(p))
        .collect()
}

#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
    meta: Option<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    count: Option<usize>,
}

/// Object counts by BloodHound type (`users`, `computers`, ...) read from
/// the `meta` blocks of the given `.zip`/`.json` files. Unreadable files
/// are skipped.
pub fn summarize_outputs(files: &[PathBuf]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut add = |reader: &mut dyn Read| {
        if let Ok(Doc { meta: Some(meta) }) = serde_json::from_reader::<_, Doc>(reader) {
            if let (Some(kind), Some(count)) = (meta.kind, meta.count) {
                *counts.entry(kind).or_default() += count;
            }
        }
    };
    for path in files {
        let Ok(file) = File::open(path) else { continue };
        let is_zip = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
        if is_zip {
            let Ok(mut archive) = zip::ZipArchive::new(BufReader::new(file)) else {
                continue;
            };
            for i in 0..archive.len() {
                let Ok(mut entry) = archive.by_index(i) else {
                    continue;
                };
                if pathwarden_core::ingest::entry_name(&entry)
                    .to_ascii_lowercase()
                    .ends_with(".json")
                {
                    add(&mut BufReader::new(&mut entry));
                }
            }
        } else {
            add(&mut BufReader::new(file));
        }
    }
    counts.into_iter().collect()
}

/// Gives each file its own private permissions (mode 600 on Unix; on
/// Windows a protected DACL for this account, Administrators and SYSTEM).
pub(crate) fn restrict_permissions(files: &[PathBuf]) {
    for f in files {
        let _ = perms::make_output_file_private(f);
    }
}

/// Gets the output directory ready. One that doesn't exist is created
/// private to this account (missing parents are created as usual). For one
/// that exists, returns who else can read or change it; its permissions are
/// left alone.
pub(crate) fn prepare_dir(dir: &Path) -> std::io::Result<Vec<Access>> {
    if !dir.is_dir() {
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        match perms::create_output_dir(dir) {
            Ok(()) => return Ok(Vec::new()),
            // Created in the meantime: check it like any existing folder.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(perms::others_with_access(dir))
}

/// The warning for an output directory others can open, naming them.
pub(crate) fn exposure_warning(dir: &Path, others: &[Access]) -> String {
    let names = |read: bool, write: bool| -> Vec<&str> {
        others
            .iter()
            .filter(|a| a.read == read && a.write == write)
            .map(|a| a.who.as_str())
            .collect()
    };
    let mut who = Vec::new();
    for (read, write, verb) in [
        (true, false, "read"),
        (true, true, "read and change"),
        (false, true, "change"),
    ] {
        let n = names(read, write);
        if !n.is_empty() {
            who.push(format!("{} can {verb}", n.join(" and ")));
        }
    }
    let mut text = format!(
        "{} {}. The collection is a full map of the directory, so Pathwarden collects into a \
         private folder there and gives the files their own permissions (this account, \
         Administrators and SYSTEM only)",
        who.join(", "),
        dir.display()
    );
    if others.iter().any(|a| a.write) {
        text.push_str(", but whoever can change the folder can still delete or replace them");
    }
    text.push_str(
        ". It is safer to collect into a folder that doesn't exist yet, which Pathwarden \
         creates private.",
    );
    text
}

/// A new private folder inside `dir` to collect into.
pub(crate) fn staging_dir(dir: &Path) -> std::io::Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let staging = dir.join(format!(
        ".pathwarden-collecting-{}-{nanos}",
        std::process::id()
    ));
    perms::create_output_dir(&staging)?;
    Ok(staging)
}

/// Moves collected files from the staging folder into `dir`, each with its
/// own private permissions first so it is never readable there by others.
/// Returns their new paths.
pub(crate) fn publish(files: &[PathBuf], dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut moved = Vec::with_capacity(files.len());
    for f in files {
        let Some(name) = f.file_name() else { continue };
        perms::make_output_file_private(f)
            .map_err(|e| anyhow::anyhow!("cannot make {} private: {e}", f.display()))?;
        let to = dir.join(name);
        fs::rename(f, &to)
            .map_err(|e| anyhow::anyhow!("cannot move {} to {}: {e}", f.display(), to.display()))?;
        moved.push(to);
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pathwarden-collect-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_zip(path: &Path, entries: &[(&str, &str)]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (name, body) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn discovers_only_new_files_and_prefers_zips() {
        let dir = tempdir("discover");
        fs::write(dir.join("20240101000000_users.json"), "{}").unwrap();
        fs::write(dir.join("notes.txt"), "x").unwrap();
        let before = Snapshot::take(&dir);

        // A collector run writes JSON files and a zip.
        fs::write(dir.join("20261009120000_users.json"), "{}").unwrap();
        write_zip(&dir.join("20261009120000_BloodHound.zip"), &[]);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub").join("20261009120000_groups.json"), "{}").unwrap();

        let found = discover_outputs(&dir, &before);
        assert_eq!(found, vec![dir.join("20261009120000_BloodHound.zip")]);

        // Without a zip, loose JSON files are the output.
        let dir2 = tempdir("discover-json");
        let before2 = Snapshot::take(&dir2);
        fs::write(dir2.join("20261009120000_users.json"), "{}").unwrap();
        fs::write(dir2.join("20261009120000_groups.json"), "{}").unwrap();
        let found2 = discover_outputs(&dir2, &before2);
        assert_eq!(found2.len(), 2);

        remove_new_outputs(&dir, &before);
        assert!(dir.join("20240101000000_users.json").exists());
        assert!(!dir.join("20261009120000_BloodHound.zip").exists());
        assert!(!dir.join("20261009120000_users.json").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn new_output_dirs_are_private_and_staged_files_keep_private() {
        let base = tempdir("private-out");
        // A missing folder (and its missing parent) is created, private.
        let out = base.join("parent").join("out");
        assert!(prepare_dir(&out).unwrap().is_empty());
        assert!(perms::others_with_access(&out).is_empty());
        // An existing private folder: nobody else to warn about.
        assert!(prepare_dir(&out).unwrap().is_empty());

        // Staging inside it, then publishing out of it.
        let staging = staging_dir(&out).unwrap();
        let f = staging.join("20261009120000_BloodHound.zip");
        fs::write(&f, "x").unwrap();
        let moved = publish(std::slice::from_ref(&f), &out).unwrap();
        assert_eq!(moved, vec![out.join("20261009120000_BloodHound.zip")]);
        assert!(!f.exists());
        assert!(perms::others_with_access(&moved[0]).is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn exposure_warning_names_who() {
        let others = [
            Access {
                who: "BUILTIN\\Users".into(),
                read: true,
                write: false,
            },
            Access {
                who: "NT AUTHORITY\\Authenticated Users".into(),
                read: true,
                write: true,
            },
        ];
        let w = exposure_warning(Path::new("C:\\x"), &others);
        assert!(
            w.starts_with(
                "BUILTIN\\Users can read, NT AUTHORITY\\Authenticated Users can read and change \
                 C:\\x. The collection is a full map of the directory"
            ),
            "{w}"
        );
        assert!(w.contains("delete or replace"), "{w}");
        let w = exposure_warning(Path::new("/x"), &others[..1]);
        assert!(w.starts_with("BUILTIN\\Users can read /x. "), "{w}");
        assert!(!w.contains("delete or replace"), "{w}");
    }

    #[test]
    fn summarizes_meta_counts() {
        let dir = tempdir("summary");
        let zip = dir.join("20261009120000_contoso.local_rusthound-ce.zip");
        write_zip(
            &zip,
            &[
                (
                    "20261009120000_contoso.local_users.json",
                    r#"{"data":[{},{}],"meta":{"methods":0,"type":"users","count":2,"version":6}}"#,
                ),
                (
                    "20261009120000_contoso.local_groups.json",
                    r#"{"data":[{}],"meta":{"type":"groups","count":1,"version":6}}"#,
                ),
            ],
        );
        let json = dir.join("20261009120000_users.json");
        fs::write(&json, r#"{"meta":{"type":"users","count":3},"data":[]}"#).unwrap();
        let summary = summarize_outputs(&[zip, json]);
        assert_eq!(
            summary,
            vec![("groups".to_string(), 1), ("users".to_string(), 5)]
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
