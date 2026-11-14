//! Whether two collections wrote the same thing: their
//! BloodHound JSON normalized, file by file. For checking that asking for
//! only the attributes RustHound-CE reads gives the output `*` gives
//! (`pathwarden diagnose --compare-output A B`).
//!
//! Normalized: each file by its type (`users.json`, the time stamp in its
//! name dropped), every array sorted, so only content counts.
//!
//! A large domain's files run to gigabytes, so [`compare`] streams them: it
//! keeps a digest of each object by its `ObjectIdentifier`, then reads
//! again only the objects that differ, for the lines it prints. The
//! `[ingest]` limits apply (entries, bytes in all, bytes an object), as
//! when a collection is analysed.
//!
//! The difference lines name accounts and properties. A property named
//! like a secret ([`is_secret_prop`]: `userpassword`, `unicodepwd`, ...)
//! shows as `(hidden)`, never its value.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use pathwarden_core::cypher::{is_secret_prop, HIDDEN};
use pathwarden_core::ingest::IngestLimits;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Differences listed at most.
pub const MAX_DIFFERENCES: usize = 50;

/// What [`compare`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OutputDiff {
    /// Files in either collection.
    pub files: usize,
    /// Objects (`data` entries) in the first.
    pub objects: usize,
    /// Where they differ, at most [`MAX_DIFFERENCES`]: `users.json:
    /// S-1-5-21-…-1104: Properties.description: "a" / "b"`.
    pub differences: Vec<String>,
    /// More differences than those listed.
    pub more: bool,
}

impl OutputDiff {
    pub fn same(&self) -> bool {
        self.differences.is_empty()
    }
}

/// The zip a collection wrote: `path` itself, or the one zip in the folder
/// `path` (a `collect --out` folder).
fn zip_of(path: &Path) -> Result<PathBuf, String> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let zips: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("zip")))
        .collect();
    match zips.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("{} holds no collection zip", path.display())),
        _ => Err(format!(
            "{} holds {} zips; give the one to compare",
            path.display(),
            zips.len()
        )),
    }
}

fn sort_arrays(v: &mut Value) {
    match v {
        Value::Array(a) => {
            a.iter_mut().for_each(sort_arrays);
            a.sort_by_cached_key(|x| x.to_string());
        }
        Value::Object(o) => o.values_mut().for_each(sort_arrays),
        _ => {}
    }
}

/// A collection's zip: its JSON files by type.
struct Collection {
    zip: PathBuf,
    /// Type (`users.json`) to the file's name in the zip.
    files: BTreeMap<String, String>,
}

impl Collection {
    fn open(path: &Path, limits: &IngestLimits) -> Result<Self, String> {
        let zip = zip_of(path)?;
        let mut archive = Self::archive(&zip)?;
        if archive.len() > limits.max_zip_entries {
            return Err(format!(
                "{} holds {} entries, over the limit of {} ([ingest] max_zip_entries)",
                zip.display(),
                archive.len(),
                limits.max_zip_entries
            ));
        }
        pathwarden_core::ingest::check_zip(&mut archive)
            .map_err(|e| format!("{}: {e}", zip.display()))?;
        let mut files = BTreeMap::new();
        for name in archive.file_names() {
            let name = name.map_err(|e| format!("{}: {e}", zip.display()))?;
            if !name.to_ascii_lowercase().ends_with(".json") {
                continue;
            }
            let kind = name.rsplit(['_', '/']).next().unwrap_or(&name).to_string();
            if let Some(other) = files.insert(kind.clone(), name.to_string()) {
                return Err(format!(
                    "{} holds two {kind} files ({other} and {name}); compare one collection at \
                     a time",
                    zip.display()
                ));
            }
        }
        Ok(Self { zip, files })
    }

    fn archive(zip: &Path) -> Result<zip::ZipArchive<std::fs::File>, String> {
        let file = std::fs::File::open(zip).map_err(|e| format!("{}: {e}", zip.display()))?;
        zip::ZipArchive::new(file).map_err(|e| format!("{}: {e}", zip.display()))
    }

    /// Reads the file of type `kind`, an object of its `data` at a time,
    /// within `limits`; `read` counts the bytes of this pass over the zip.
    fn read(
        &self,
        kind: &str,
        limits: &IngestLimits,
        read: &Rc<Cell<u64>>,
        on: &mut dyn FnMut(Item) -> Result<(), String>,
    ) -> Result<(), String> {
        let name = &self.files[kind];
        let mut archive = Self::archive(&self.zip)?;
        let options = zip::ZipReadOptions::new().enforce_header_consistency(true);
        let f = archive
            .by_name_with_options(name, options)
            .map_err(|e| format!("{name} in {}: {e}", self.zip.display()))?;
        let mark = Rc::new(Cell::new(None));
        let counted = Counted {
            inner: f,
            read: read.clone(),
            mark: mark.clone(),
            limits: *limits,
        };
        let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(counted));
        FileSeed {
            on,
            mark,
            read: read.clone(),
        }
        .deserialize(&mut de)
        .and_then(|()| de.end())
        .map_err(|e| format!("{name} in {}: {e}", self.zip.display()))
    }
}

/// Bytes read from a zip, within the limits: all of its files in one pass
/// ([`IngestLimits::max_archive_bytes`]), and one object
/// ([`IngestLimits::max_object_bytes`]) from `mark`.
struct Counted<R> {
    inner: R,
    read: Rc<Cell<u64>>,
    mark: Rc<Cell<Option<u64>>>,
    limits: IngestLimits,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let total = self.read.get() + n as u64;
        self.read.set(total);
        if total > self.limits.max_archive_bytes {
            return Err(std::io::Error::other(format!(
                "over {} MiB in all ([ingest] max_archive_gib)",
                self.limits.max_archive_bytes >> 20
            )));
        }
        if let Some(from) = self.mark.get() {
            if total.saturating_sub(from) > self.limits.max_object_bytes {
                return Err(std::io::Error::other(format!(
                    "an object over {} MiB ([ingest] max_object_mib)",
                    self.limits.max_object_bytes >> 20
                )));
            }
        }
        Ok(n)
    }
}

/// What a file holds: each object of its `data`, and its other top-level
/// keys (`meta`).
enum Item {
    Object(Value),
    Other(String, Value),
}

struct FileSeed<'a> {
    on: &'a mut dyn FnMut(Item) -> Result<(), String>,
    /// Where the object being read starts, for the per-object limit.
    mark: Rc<Cell<Option<u64>>>,
    /// Bytes read so far.
    read: Rc<Cell<u64>>,
}

impl<'de> DeserializeSeed<'de> for FileSeed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FileSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a BloodHound JSON file")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        let on = self.on;
        while let Some(k) = m.next_key::<String>()? {
            if k == "data" {
                m.next_value_seed(DataSeed {
                    on: &mut *on,
                    mark: self.mark.clone(),
                    read: self.read.clone(),
                })?;
            } else {
                let v: Value = m.next_value()?;
                on(Item::Other(k, v)).map_err(de::Error::custom)?;
            }
        }
        Ok(())
    }
}

struct DataSeed<'a> {
    on: &'a mut dyn FnMut(Item) -> Result<(), String>,
    mark: Rc<Cell<Option<u64>>>,
    read: Rc<Cell<u64>>,
}

impl<'de> DeserializeSeed<'de> for DataSeed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for DataSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of objects")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            // From the bytes read so far: the reader is ahead by its
            // buffer, so the limit holds give or take 8 KB.
            self.mark.set(Some(self.read.get()));
            let next = seq.next_element::<Value>();
            self.mark.set(None);
            let Some(v) = next? else {
                return Ok(());
            };
            (self.on)(Item::Object(v)).map_err(de::Error::custom)?;
        }
    }
}

/// An object's key in its file: its `ObjectIdentifier`, else its content.
fn key_of(v: &Value, digest: u128) -> String {
    match v.get("ObjectIdentifier").and_then(Value::as_str) {
        Some(id) => id.to_string(),
        None => format!("(no ObjectIdentifier, {digest:032x})"),
    }
}

/// A digest of a normalized value (two SipHashes of its text).
fn digest(v: &Value) -> u128 {
    let text = v.to_string();
    let half = |salt: u8| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        salt.hash(&mut h);
        text.hash(&mut h);
        h.finish()
    };
    (u128::from(half(1)) << 64) | u128::from(half(2))
}

/// One file of a collection, digested: each object's digest by its key,
/// and its other top-level keys.
#[derive(Default)]
struct Digested {
    objects: BTreeMap<String, u128>,
    others: BTreeMap<String, Value>,
}

fn digested(
    c: &Collection,
    kind: &str,
    limits: &IngestLimits,
    read: &Rc<Cell<u64>>,
) -> Result<Digested, String> {
    let mut d = Digested::default();
    c.read(kind, limits, read, &mut |item| {
        match item {
            Item::Object(mut v) => {
                sort_arrays(&mut v);
                let h = digest(&v);
                let mut key = key_of(&v, h);
                // The same identifier twice: kept apart.
                let mut n = 1;
                while d.objects.contains_key(&key) {
                    n += 1;
                    key = format!("{} (#{n})", key_of(&v, h));
                }
                d.objects.insert(key, h);
            }
            Item::Other(k, mut v) => {
                sort_arrays(&mut v);
                d.others.insert(k, v);
            }
        }
        Ok(())
    })?;
    Ok(d)
}

/// The objects of `kind` whose keys are in `wanted`, normalized.
fn objects(
    c: &Collection,
    kind: &str,
    limits: &IngestLimits,
    wanted: &BTreeSet<String>,
) -> Result<BTreeMap<String, Value>, String> {
    let read = Rc::new(Cell::new(0));
    let mut out = BTreeMap::new();
    c.read(kind, limits, &read, &mut |item| {
        if let Item::Object(mut v) = item {
            sort_arrays(&mut v);
            let key = key_of(&v, digest(&v));
            if wanted.contains(&key) && !out.contains_key(&key) {
                out.insert(key, v);
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// A collection's JSON files by type, normalized (whole, in memory: for
/// small collections and tests).
pub fn normalized(path: &Path) -> Result<BTreeMap<String, Value>, String> {
    let limits = IngestLimits::default();
    let c = Collection::open(path, &limits)?;
    let read = Rc::new(Cell::new(0));
    let mut out = BTreeMap::new();
    for kind in c.files.keys() {
        let mut file = serde_json::Map::new();
        let mut data = Vec::new();
        c.read(kind, &limits, &read, &mut |item| {
            match item {
                Item::Object(v) => data.push(v),
                Item::Other(k, v) => {
                    file.insert(k, v);
                }
            }
            Ok(())
        })?;
        file.insert("data".into(), Value::Array(data));
        let mut v = Value::Object(file);
        sort_arrays(&mut v);
        out.insert(kind.clone(), v);
    }
    Ok(out)
}

/// A value for a difference line, cut short; `(hidden)` for a secret.
fn shown(v: &Value, secret: bool) -> String {
    if secret {
        return HIDDEN.to_string();
    }
    let s = v.to_string();
    if s.chars().count() > 80 {
        format!("{}…", s.chars().take(80).collect::<String>())
    } else {
        s
    }
}

/// The ID of each element when every one has an `ObjectIdentifier`.
fn by_id(a: &[Value]) -> Option<BTreeMap<String, &Value>> {
    let mut m = BTreeMap::new();
    for v in a {
        let id = v.get("ObjectIdentifier")?.as_str()?;
        m.insert(id.to_string(), v);
    }
    (m.len() == a.len()).then_some(m)
}

struct Diff {
    lines: Vec<String>,
    more: bool,
}

impl Diff {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            more: false,
        }
    }

    fn push(&mut self, line: String) {
        if self.lines.len() < MAX_DIFFERENCES {
            self.lines.push(line);
        } else {
            self.more = true;
        }
    }

    /// The differences of `a` and `b` at `at`; `secret`: under a key named
    /// like a secret, so no value is shown.
    fn walk(&mut self, at: &str, a: &Value, b: &Value, secret: bool) {
        if a == b {
            return;
        }
        let under = |k: &str| {
            if at.ends_with(": ") {
                format!("{at}{k}")
            } else {
                format!("{at}.{k}")
            }
        };
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for (k, va) in x {
                    let here = under(k);
                    match y.get(k) {
                        Some(vb) => self.walk(&here, va, vb, secret || is_secret_prop(k)),
                        None => self.push(format!("{here}: only in the first")),
                    }
                }
                for k in y.keys().filter(|k| !x.contains_key(*k)) {
                    self.push(format!("{}: only in the second", under(k)));
                }
            }
            (Value::Array(x), Value::Array(y)) => match (by_id(x), by_id(y)) {
                (Some(mx), Some(my)) => {
                    let base = at.trim_end_matches(".data");
                    for (id, va) in &mx {
                        match my.get(id) {
                            Some(vb) => self.walk(&format!("{base}: {id}: "), va, vb, secret),
                            None => self.push(format!("{base}: {id}: only in the first")),
                        }
                    }
                    for id in my.keys().filter(|k| !mx.contains_key(*k)) {
                        self.push(format!("{base}: {id}: only in the second"));
                    }
                }
                _ => self.push(format!(
                    "{}: {} / {}",
                    at.trim_end_matches(": "),
                    shown(a, secret),
                    shown(b, secret)
                )),
            },
            _ => self.push(format!(
                "{}: {} / {}",
                at.trim_end_matches(": "),
                shown(a, secret),
                shown(b, secret)
            )),
        }
    }
}

/// Whether the collections at `a` and `b` (zips, or `collect --out`
/// folders) wrote the same JSON, and where not, within the default
/// `[ingest]` limits.
pub fn compare(a: &Path, b: &Path) -> Result<OutputDiff, String> {
    compare_within(a, b, &IngestLimits::default())
}

/// [`compare`] within `limits`. A file at a time, an object at a time.
pub fn compare_within(a: &Path, b: &Path, limits: &IngestLimits) -> Result<OutputDiff, String> {
    let x = Collection::open(a, limits)?;
    let y = Collection::open(b, limits)?;
    let mut d = Diff::new();
    let mut objects_seen = 0;
    let (read_x, read_y) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
    let kinds: BTreeSet<&String> = x.files.keys().chain(y.files.keys()).collect();
    for kind in &kinds {
        let (Some(_), Some(_)) = (x.files.get(*kind), y.files.get(*kind)) else {
            let side = if x.files.contains_key(*kind) {
                "first"
            } else {
                "second"
            };
            d.push(format!("{kind}: only in the {side}"));
            if x.files.contains_key(*kind) {
                objects_seen += digested(&x, kind, limits, &read_x)?.objects.len();
            }
            continue;
        };
        let dx = digested(&x, kind, limits, &read_x)?;
        let dy = digested(&y, kind, limits, &read_y)?;
        objects_seen += dx.objects.len();
        for (k, va) in &dx.others {
            match dy.others.get(k) {
                Some(vb) => d.walk(&format!("{kind}.{k}"), va, vb, false),
                None => d.push(format!("{kind}.{k}: only in the first")),
            }
        }
        for k in dy.others.keys().filter(|k| !dx.others.contains_key(*k)) {
            d.push(format!("{kind}.{k}: only in the second"));
        }
        // The objects that differ, read again for the lines.
        let mut wanted = BTreeSet::new();
        for (id, hx) in &dx.objects {
            match dy.objects.get(id) {
                Some(hy) if hy == hx => {}
                Some(_) => {
                    if wanted.len() < MAX_DIFFERENCES {
                        wanted.insert(id.clone());
                    } else {
                        d.more = true;
                    }
                }
                None => d.push(format!("{kind}: {id}: only in the first")),
            }
        }
        for id in dy.objects.keys().filter(|k| !dx.objects.contains_key(*k)) {
            d.push(format!("{kind}: {id}: only in the second"));
        }
        if !wanted.is_empty() && d.lines.len() < MAX_DIFFERENCES {
            let ox = objects(&x, kind, limits, &wanted)?;
            let oy = objects(&y, kind, limits, &wanted)?;
            for id in &wanted {
                if let (Some(va), Some(vb)) = (ox.get(id), oy.get(id)) {
                    d.walk(&format!("{kind}: {id}: "), va, vb, false);
                }
            }
        } else if !wanted.is_empty() {
            d.more = true;
        }
    }
    Ok(OutputDiff {
        files: kinds.len(),
        objects: objects_seen,
        differences: d.lines,
        more: d.more,
    })
}

/// [`compare`] of two [`normalized`] collections, in memory.
pub fn compare_normalized(x: &BTreeMap<String, Value>, y: &BTreeMap<String, Value>) -> OutputDiff {
    let mut d = Diff::new();
    for (name, va) in x {
        match y.get(name) {
            Some(vb) => d.walk(name, va, vb, false),
            None => d.push(format!("{name}: only in the first")),
        }
    }
    for name in y.keys().filter(|k| !x.contains_key(*k)) {
        d.push(format!("{name}: only in the second"));
    }
    let mut files: Vec<&String> = x.keys().chain(y.keys()).collect();
    files.sort();
    files.dedup();
    OutputDiff {
        files: files.len(),
        objects: x
            .values()
            .filter_map(|v| v.get("data")?.as_array().map(Vec::len))
            .sum(),
        differences: d.lines,
        more: d.more,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn files(users: Value) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("users.json".to_string(), users);
        m
    }

    fn users(data: Value) -> Value {
        json!({"data": data, "meta": {"type": "users", "count": 2}})
    }

    /// A scratch folder for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pw-compare-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A zip at `path` holding `files` (name, JSON).
    fn zip_with(path: &Path, files: &[(&str, &Value)]) {
        use std::io::Write;
        let mut z = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, v) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(v.to_string().as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }

    #[test]
    fn same_content_in_another_order_is_the_same() {
        let mut a = users(json!([
            {"ObjectIdentifier": "S-1", "Properties": {"name": "A"}, "Aces": [1, 2]},
            {"ObjectIdentifier": "S-2", "Properties": {"name": "B"}}
        ]));
        let mut b = users(json!([
            {"ObjectIdentifier": "S-2", "Properties": {"name": "B"}},
            {"ObjectIdentifier": "S-1", "Properties": {"name": "A"}, "Aces": [2, 1]}
        ]));
        sort_arrays(&mut a);
        sort_arrays(&mut b);
        let d = compare_normalized(&files(a.clone()), &files(b.clone()));
        assert!(d.same(), "{:?}", d.differences);
        assert_eq!((d.files, d.objects), (1, 2));
        // Streamed from zips, the same.
        let dir = scratch("order");
        zip_with(&dir.join("a.zip"), &[("1_users.json", &a)]);
        zip_with(&dir.join("b.zip"), &[("2_users.json", &b)]);
        let d = compare(&dir.join("a.zip"), &dir.join("b.zip")).unwrap();
        assert!(d.same(), "{:?}", d.differences);
        assert_eq!((d.files, d.objects), (1, 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_difference_names_the_file_the_object_and_the_property() {
        let a = users(json!([
            {"ObjectIdentifier": "S-1", "Properties": {"haslaps": true, "name": "A"}},
            {"ObjectIdentifier": "S-2", "Properties": {}}
        ]));
        let b = users(json!([
            {"ObjectIdentifier": "S-1", "Properties": {"haslaps": false}},
            {"ObjectIdentifier": "S-3", "Properties": {}}
        ]));
        let expected = [
            "users.json: S-1: Properties.haslaps: true / false",
            "users.json: S-1: Properties.name: only in the first",
            "users.json: S-2: only in the first",
            "users.json: S-3: only in the second",
        ];
        let d = compare_normalized(&files(a.clone()), &files(b.clone()));
        assert_eq!(d.differences, expected);
        // Streamed: the objects only in one first, then the ones that
        // differ, read again.
        let dir = scratch("diff");
        zip_with(&dir.join("a.zip"), &[("1_users.json", &a)]);
        zip_with(
            &dir.join("b.zip"),
            &[
                ("2_users.json", &b),
                ("2_groups.json", &json!({"data": []})),
            ],
        );
        let d = compare(&dir.join("a.zip"), &dir.join("b.zip")).unwrap();
        assert_eq!(
            d.differences,
            [
                "groups.json: only in the second",
                "users.json: S-2: only in the first",
                "users.json: S-3: only in the second",
                "users.json: S-1: Properties.haslaps: true / false",
                "users.json: S-1: Properties.name: only in the first",
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A property named like a secret shows `(hidden)`, never its value.
    #[test]
    fn secrets_are_hidden() {
        let a = users(json!([{"ObjectIdentifier": "S-1", "Properties": {
            "userpassword": "Summer2024", "unicodepassword": "x", "pwdlastset": 1,
            "list": {"secret": ["a"]}
        }}]));
        let b = users(json!([{"ObjectIdentifier": "S-1", "Properties": {
            "userpassword": "Winter2025", "unicodepassword": "y", "pwdlastset": 2,
            "list": {"secret": ["b"]}
        }}]));
        let dir = scratch("secret");
        zip_with(&dir.join("a.zip"), &[("1_users.json", &a)]);
        zip_with(&dir.join("b.zip"), &[("2_users.json", &b)]);
        let d = compare(&dir.join("a.zip"), &dir.join("b.zip")).unwrap();
        let mut lines = d.differences.clone();
        lines.sort();
        assert_eq!(
            lines,
            [
                "users.json: S-1: Properties.list.secret: (hidden) / (hidden)",
                "users.json: S-1: Properties.pwdlastset: 1 / 2",
                "users.json: S-1: Properties.unicodepassword: (hidden) / (hidden)",
                "users.json: S-1: Properties.userpassword: (hidden) / (hidden)",
            ]
        );
        let text = d.differences.join("\n");
        for s in ["Summer2024", "Winter2025"] {
            assert!(!text.contains(s));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_stops_at_its_limit() {
        let many: Vec<Value> = (0..80)
            .map(|i| json!({"ObjectIdentifier": format!("S-{i}"), "v": i}))
            .collect();
        let other: Vec<Value> = (0..80)
            .map(|i| json!({"ObjectIdentifier": format!("S-{i}"), "v": i + 1}))
            .collect();
        let d = compare_normalized(&files(users(json!(many))), &files(users(json!(other))));
        assert_eq!(d.differences.len(), MAX_DIFFERENCES);
        assert!(d.more);
        let dir = scratch("many");
        zip_with(&dir.join("a.zip"), &[("1_users.json", &users(json!(many)))]);
        zip_with(
            &dir.join("b.zip"),
            &[("1_users.json", &users(json!(other)))],
        );
        let d = compare(&dir.join("a.zip"), &dir.join("b.zip")).unwrap();
        assert_eq!(d.differences.len(), MAX_DIFFERENCES);
        assert!(d.more);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `[ingest]` limits hold, and a zip with two files of one type is
    /// refused rather than one read over the other.
    #[test]
    fn limits_and_duplicate_types_are_errors() {
        let dir = scratch("limits");
        let big = users(json!([
            {"ObjectIdentifier": "S-1", "Properties": {"description": "x".repeat(40_000)}},
            {"ObjectIdentifier": "S-2"}
        ]));
        zip_with(&dir.join("a.zip"), &[("1_users.json", &big)]);
        let small_object = IngestLimits {
            max_object_bytes: 20_000,
            ..IngestLimits::default()
        };
        let e = compare_within(&dir.join("a.zip"), &dir.join("a.zip"), &small_object).unwrap_err();
        assert!(
            e.contains("an object over") && e.contains("max_object_mib"),
            "{e}"
        );
        let small_zip = IngestLimits {
            max_archive_bytes: 30_000,
            ..IngestLimits::default()
        };
        let e = compare_within(&dir.join("a.zip"), &dir.join("a.zip"), &small_zip).unwrap_err();
        assert!(e.contains("max_archive_gib"), "{e}");
        let few = IngestLimits {
            max_zip_entries: 0,
            ..IngestLimits::default()
        };
        let e = compare_within(&dir.join("a.zip"), &dir.join("a.zip"), &few).unwrap_err();
        assert!(e.contains("max_zip_entries"), "{e}");
        assert!(compare(&dir.join("a.zip"), &dir.join("a.zip"))
            .unwrap()
            .same());

        let two = users(json!([]));
        zip_with(
            &dir.join("two.zip"),
            &[("1_users.json", &two), ("2_users.json", &two)],
        );
        let e = compare(&dir.join("two.zip"), &dir.join("a.zip")).unwrap_err();
        assert!(e.contains("two users.json files"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_folder_with_one_zip_is_read() {
        let dir = scratch("folder");
        assert!(normalized(&dir).unwrap_err().contains("no collection zip"));
        let path = dir.join("20261031120000_contoso_bloodhound.zip");
        zip_with(
            &path,
            &[(
                "20261031120000_contoso_users.json",
                &json!({"data":[{"ObjectIdentifier":"S-1","x":[2,1]}]}),
            )],
        );
        let n = normalized(&dir).unwrap();
        assert_eq!(n["users.json"]["data"][0]["x"], json!([1, 2]));
        assert!(compare(&dir, &path).unwrap().same());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
