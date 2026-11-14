//! Hostile input: oversized objects, zip bombs, archives with many entries,
//! and link loops in folders. Inputs are generated, small, and written to a
//! temporary folder.

use std::io::Write;

use super::*;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pw-ingest-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn users_file(objects: &[String]) -> String {
    format!(
        r#"{{"data":[{}],"meta":{{"type":"users","count":{},"version":6}}}}"#,
        objects.join(","),
        objects.len()
    )
}

fn user(id: &str) -> String {
    format!(r#"{{"ObjectIdentifier":"{id}","Properties":{{"name":"{id}@X.LOCAL"}}}}"#)
}

fn write_zip(path: &Path, entries: &[(String, Vec<u8>)]) {
    let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
    for (name, data) in entries {
        zip.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

fn small_limits() -> IngestLimits {
    IngestLimits {
        max_object_bytes: 1 << 20,
        ..IngestLimits::default()
    }
}

/// M3: an object whose lists would take far more memory than its input
/// (`"Aces":[{},{},…]`) is skipped and reported, not loaded; the objects
/// around it are ingested.
#[test]
fn oversized_objects_are_skipped_and_reported() {
    let aces = vec!["{}"; 200_000].join(",");
    let big = format!(r#"{{"ObjectIdentifier":"S-1-5-21-1-2-3-1000","Aces":[{aces}]}}"#);
    let text = users_file(&[user("S-1-5-21-1-2-3-999"), big, user("S-1-5-21-1-2-3-1001")]);
    let tmp = TempDir::new("oversized");
    let file = tmp.0.join("users.json");
    fs::write(&file, &text).unwrap();
    for from_file in [false, true] {
        let mut ing = Ingestor::with_limits(small_limits());
        if from_file {
            ing.ingest_path(&file).unwrap();
        } else {
            ing.ingest_text("users.json", &text).unwrap();
        }
        let (g, stats) = ing.finish();
        assert_eq!(stats.objects.get("User"), Some(&2), "{from_file}");
        assert_eq!(stats.skipped_objects.len(), 1, "{from_file}");
        assert!(stats.skipped_objects[0].contains("S-1-5-21-1-2-3-1000"));
        assert!(g.find("S-1-5-21-1-2-3-1000").is_empty());
    }
    // With the default limits the same object is fine.
    let mut ing = Ingestor::new();
    ing.ingest_text("users.json", &text).unwrap();
    assert!(ing.finish().1.skipped_objects.is_empty());
}

/// M3: unknown properties are not kept, however large.
#[test]
fn unknown_properties_cost_nothing() {
    let junk = vec!["0"; 100_000].join(",");
    let text = users_file(&[format!(
        r#"{{"ObjectIdentifier":"S-1-5-21-1-2-3-1000","Properties":{{"x":[{junk}],"name":"A@X.LOCAL","enabled":true}}}}"#
    )]);
    let mut ing = Ingestor::with_limits(small_limits());
    ing.ingest_text("users.json", &text).unwrap();
    let (g, stats) = ing.finish();
    assert!(stats.skipped_objects.is_empty());
    let n = g.node(g.find("S-1-5-21-1-2-3-1000")[0]);
    assert_eq!(n.name, "A@X.LOCAL");
    assert_eq!(n.props.enabled, Some(true));
}

/// Every property is kept when asked (`pathwarden query`), whichever way
/// the file is read: from text, a file, or inside a .zip.
#[test]
fn all_properties_are_kept_from_every_reader() {
    let text = users_file(&[
        r#"{"ObjectIdentifier":"S-1-5-21-1-2-3-1000","Properties":{"name":"A@X.LOCAL","samaccountname":"a","enabled":true}}"#
            .to_string(),
    ]);
    let tmp = TempDir::new("all-properties");
    let file = tmp.0.join("users.json");
    fs::write(&file, &text).unwrap();
    let zip = tmp.0.join("users.zip");
    write_zip(&zip, &[("users.json".into(), text.clone().into_bytes())]);
    for (how, all) in [
        ("text", true),
        ("file", true),
        ("zip", true),
        ("zip", false),
    ] {
        let mut ing = Ingestor::with_limits(small_limits()).with_all_properties(all);
        match how {
            "text" => ing.ingest_text("users.json", &text).unwrap(),
            "file" => ing.ingest_path(&file).unwrap(),
            _ => ing.ingest_path(&zip).unwrap(),
        }
        let (g, _) = ing.finish();
        let ix = g.find("S-1-5-21-1-2-3-1000")[0];
        let sam = g.extra_prop(ix, "samaccountname");
        let want = all.then(|| crate::model::PropValue::Str("a".into()));
        assert_eq!(sam, want, "{how} {all}");
        assert_eq!(g.props_kept(), all);
    }
}

/// M3: a single value too large to skip (a huge string) fails the file
/// cleanly instead of being loaded.
#[test]
fn an_object_far_over_budget_fails_the_file() {
    let tmp = TempDir::new("hard");
    let file = tmp.0.join("users.json");
    let huge = "A".repeat(3 << 20);
    let text = users_file(&[format!(
        r#"{{"ObjectIdentifier":"S-1-5-21-1-2-3-1000","Properties":{{"description":"{huge}"}}}}"#
    )]);
    fs::write(&file, text).unwrap();
    let mut ing = Ingestor::with_limits(small_limits());
    let err = ing.ingest_path(&file).unwrap_err();
    assert!(matches!(err, IngestError::TooLarge { .. }), "{err}");
}

/// M4: archives with more entries than allowed are refused up front; many
/// entries below the limit are read (the archive is opened once).
#[test]
fn zip_entry_count_is_capped() {
    let tmp = TempDir::new("entries");
    let entries: Vec<(String, Vec<u8>)> = (0..300)
        .map(|i| {
            let id = format!("S-1-5-21-1-2-3-{}", 1000 + i);
            (
                format!("{i:04}_users.json"),
                users_file(&[user(&id)]).into_bytes(),
            )
        })
        .collect();
    let zip = tmp.0.join("many.zip");
    write_zip(&zip, &entries);

    let started = std::time::Instant::now();
    let mut ing = Ingestor::new();
    ing.ingest_path(&zip).unwrap();
    let (_, stats) = ing.finish();
    assert_eq!(stats.files.len(), 300);
    assert_eq!(stats.objects.get("User"), Some(&300));
    assert!(started.elapsed() < std::time::Duration::from_secs(20));

    let mut ing = Ingestor::with_limits(IngestLimits {
        max_zip_entries: 299,
        ..IngestLimits::default()
    });
    let err = ing.ingest_path(&zip).unwrap_err();
    assert!(matches!(err, IngestError::TooLarge { .. }), "{err}");
}

/// A zip inside a zip is never opened (gap 22): only the outer
/// archive's own `.json` entries are read, so nesting can't multiply the
/// entry and size caps.
#[test]
fn nested_zips_are_not_opened() {
    let tmp = TempDir::new("nested");
    let inner = tmp.0.join("inner.zip");
    write_zip(
        &inner,
        &[(
            "users.json".into(),
            users_file(&[user("S-1-5-21-1-2-3-2000")]).into_bytes(),
        )],
    );
    let outer = tmp.0.join("outer.zip");
    write_zip(
        &outer,
        &[
            ("inner.zip".into(), fs::read(&inner).unwrap()),
            ("deeper/inner.zip".into(), fs::read(&inner).unwrap()),
            (
                "users.json".into(),
                users_file(&[user("S-1-5-21-1-2-3-1000")]).into_bytes(),
            ),
        ],
    );
    fs::remove_file(&inner).unwrap();
    let mut ing = Ingestor::new();
    ing.ingest_path(&outer).unwrap();
    let (g, stats) = ing.finish();
    assert_eq!(stats.files.len(), 1, "{:?}", stats.files);
    assert_eq!(stats.objects.get("User"), Some(&1));
    assert!(g.find("S-1-5-21-1-2-3-2000@X.LOCAL").is_empty());
}

/// JSON nested past any real collector file's depth is read without a
/// stack overflow (a property no one reads is passed over, a whole file
/// nested so deep fails), and JSON cut short fails that file with a JSON
/// error: no panic, nothing half read kept silently (gap 22). Run on
/// a thread of the default 2 MiB stack.
#[test]
fn deep_or_truncated_json_fails_plainly() {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(|| {
            let deep = format!(
                r#"{{"ObjectIdentifier":"S-1-5-21-1-2-3-1000","Properties":{{"x":{}{}}}}}"#,
                "[".repeat(100_000),
                "]".repeat(100_000)
            );
            let deep_file = users_file(&[deep]);
            let tmp = TempDir::new("deep");
            // A property no one reads, nested deep: passed over.
            let mut ing = Ingestor::with_limits(small_limits());
            ing.ingest_text("users.json", &deep_file).unwrap();
            assert_eq!(ing.finish().1.objects.get("User"), Some(&1));
            let deep_data = format!(
                r#"{{"data":{}{},"meta":{{"type":"users","count":1,"version":6}}}}"#,
                "[".repeat(100_000),
                "]".repeat(100_000)
            );
            let whole = users_file(&[user("S-1-5-21-1-2-3-999"), user("S-1-5-21-1-2-3-1001")]);
            for (name, text) in [
                ("deep", deep_data.as_str()),
                ("cut", &whole[..whole.len() / 2]),
                ("cut-in-meta", &whole[..whole.len() - 8]),
                (
                    "unclosed",
                    "{\"data\":[{\"ObjectIdentifier\":\"S-1-5-21-1-2-3-1\"",
                ),
            ] {
                let file = tmp.0.join(format!("{name}_users.json"));
                fs::write(&file, text).unwrap();
                for from_file in [false, true] {
                    let mut ing = Ingestor::with_limits(small_limits());
                    let r = if from_file {
                        ing.ingest_path(&file)
                    } else {
                        ing.ingest_text("users.json", text)
                    };
                    match r {
                        Err(IngestError::Json { .. } | IngestError::TooLarge { .. }) => {}
                        // A file whose type can't be told is skipped, named.
                        Ok(()) => {
                            let (_, stats) = ing.finish();
                            assert!(
                                stats.objects.is_empty() || !stats.skipped_files.is_empty(),
                                "{name} {from_file}: {stats:?}"
                            );
                        }
                        Err(e) => panic!("{name} {from_file}: {e}"),
                    }
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Sets the uncompressed size recorded for every entry of a zip (local
/// headers and central directory), as a zip bomb would.
fn lie_about_sizes(path: &Path, size: u32) {
    let mut data = fs::read(path).unwrap();
    let patch = |data: &mut Vec<u8>, sig: &[u8], offset: usize| {
        let mut at = 0;
        while let Some(p) = data[at..].windows(4).position(|w| w == sig) {
            let p = at + p;
            data[p + offset..p + offset + 4].copy_from_slice(&size.to_le_bytes());
            at = p + 4;
        }
    };
    patch(&mut data, b"PK\x03\x04", 22);
    patch(&mut data, b"PK\x01\x02", 24);
    fs::write(path, data).unwrap();
}

/// L9: what an archive decompresses to is counted as it is read, and
/// limited across all its entries; an entry holding more than its headers
/// declare is refused.
#[test]
fn archive_size_is_counted_not_declared() {
    let tmp = TempDir::new("bomb");
    let pad = " ".repeat(400 << 10);
    let entries: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| {
            let id = format!("S-1-5-21-1-2-3-{}", 1000 + i);
            let text = format!(
                r#"{{"data":[{}],{pad}"meta":{{"type":"users","count":1,"version":6}}}}"#,
                user(&id)
            );
            (format!("{i}_users.json"), text.into_bytes())
        })
        .collect();
    let zip = tmp.0.join("bomb.zip");
    write_zip(&zip, &entries);
    let mut ing = Ingestor::new();
    ing.ingest_path(&zip).unwrap();
    assert_eq!(ing.finish().1.objects.get("User"), Some(&3));

    // Two entries' worth allowed: the third is refused.
    let mut ing = Ingestor::with_limits(IngestLimits {
        max_archive_bytes: 2 * (400 << 10) + (100 << 10),
        ..IngestLimits::default()
    });
    let err = ing.ingest_path(&zip).unwrap_err();
    match err {
        IngestError::TooLarge { path, detail } => {
            assert!(path.ends_with("2_users.json"), "{path}");
            assert!(detail.contains("in all"), "{detail}");
        }
        other => panic!("{other}"),
    }

    // Headers that declare less than the entries hold: the first entry
    // stops at its declared size and is refused, never read past it.
    lie_about_sizes(&zip, 100);
    let err = Ingestor::new().ingest_path(&zip).unwrap_err();
    match err {
        IngestError::Io { path, source } => {
            assert!(path.to_string_lossy().ends_with("0_users.json"), "{path:?}");
            assert!(source.to_string().contains("declared"), "{source}");
        }
        other => panic!("{other}"),
    }
}

/// Where the local header of `name` starts.
fn local_header(data: &[u8], name: &str) -> usize {
    (0..data.len() - 30)
        .find(|&i| {
            &data[i..i + 4] == b"PK\x03\x04"
                && data.get(i + 30..i + 30 + name.len()) == Some(name.as_bytes())
        })
        .unwrap_or_else(|| panic!("no local header for {name}"))
}

/// Takes `name` out of the central directory, leaving its local header and
/// data where they are: a file only a local-header reader would see.
fn unlist(data: &mut Vec<u8>, name: &str) {
    let at = (0..data.len() - 46)
        .find(|&i| {
            &data[i..i + 4] == b"PK\x01\x02"
                && data.get(i + 46..i + 46 + name.len()) == Some(name.as_bytes())
        })
        .unwrap();
    let u16_at = |d: &[u8], i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as usize;
    let len = 46 + u16_at(data, at + 28) + u16_at(data, at + 30) + u16_at(data, at + 32);
    data.drain(at..at + len);
    let end = (0..data.len() - 21)
        .rev()
        .find(|&i| &data[i..i + 4] == b"PK\x05\x06")
        .unwrap();
    for count in [end + 8, end + 10] {
        let n = u16_at(data, count) as u16 - 1;
        data[count..count + 2].copy_from_slice(&n.to_le_bytes());
    }
    let size = u32::from_le_bytes(data[end + 12..end + 16].try_into().unwrap()) - len as u32;
    data[end + 12..end + 16].copy_from_slice(&size.to_le_bytes());
}

/// Zip cloaking (zip < 9.0.5): a zip whose local file headers say something
/// other than its central directory is refused, since a tool that reads the
/// local headers would see other files than Pathwarden does.
#[test]
fn a_zip_whose_local_headers_disagree_with_its_directory_is_refused() {
    let tmp = TempDir::new("cloak");
    let entries = vec![
        (
            "a_users.json".to_string(),
            users_file(&[user("S-1-5-21-1-2-3-1000")]).into_bytes(),
        ),
        (
            "h_users.json".to_string(),
            users_file(&[user("S-1-5-21-1-2-3-1001")]).into_bytes(),
        ),
    ];
    let zip = tmp.0.join("cloak.zip");
    write_zip(&zip, &entries);
    let good = fs::read(&zip).unwrap();
    let mut ing = Ingestor::new();
    ing.ingest_path(&zip).unwrap();
    assert_eq!(ing.finish().1.objects.get("User"), Some(&2));

    let at = local_header(&good, "h_users.json");
    let mut renamed = good.clone();
    renamed[at + 30] = b'x';
    let mut resized = good.clone();
    resized[at + 22..at + 26].copy_from_slice(&7u32.to_le_bytes());
    let mut hidden = good.clone();
    unlist(&mut hidden, "h_users.json");
    for (what, data) in [
        ("another name", renamed),
        ("another size", resized),
        ("a file the directory doesn't list", hidden),
    ] {
        fs::write(&zip, &data).unwrap();
        let err = Ingestor::new().ingest_path(&zip).unwrap_err();
        assert!(matches!(err, IngestError::Zip { .. }), "{what}: {err}");
        let text = format!("{err} {:?}", std::error::Error::source(&err));
        assert!(text.contains("header inconsistency"), "{what}: {text}");
    }
}

/// L8: a link inside a folder is not followed, so a loop can't make the
/// walk endless or ingest the same file many times; a file given twice is
/// read once.
#[test]
fn folders_are_walked_once_without_following_links() {
    let tmp = TempDir::new("walk");
    let root = tmp.0.join("in");
    fs::create_dir_all(root.join("sub")).unwrap();
    let file = root.join("sub").join("users.json");
    fs::write(&file, users_file(&[user("S-1-5-21-1-2-3-1000")])).unwrap();
    // sub/loop -> in (a loop), where the platform lets us make one.
    let looped = make_dir_link(&root, &root.join("sub").join("loop"));

    let mut ing = Ingestor::new();
    ing.ingest_path(&root).unwrap();
    ing.ingest_path(&file).unwrap();
    ing.ingest_path(&root).unwrap();
    let (_, stats) = ing.finish();
    assert_eq!(stats.files.len(), 1, "{:?}", stats.files);
    assert_eq!(stats.objects.get("User"), Some(&1));
    if looped {
        assert!(
            stats.skipped_files.iter().any(|s| s.contains("a link")),
            "{:?}",
            stats.skipped_files
        );
    }
    let total = work_bytes(&[root.clone(), file.clone()]);
    assert_eq!(total, fs::metadata(&file).unwrap().len());
}

#[cfg(unix)]
fn make_dir_link(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

/// A junction where possible (no privilege needed), else a symlink.
#[cfg(windows)]
fn make_dir_link(target: &Path, link: &Path) -> bool {
    let junction = crate::spawn::quiet("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .is_ok_and(|o| o.status.success());
    junction || std::os::windows::fs::symlink_dir(target, link).is_ok()
}

/// The same object in two collections: a stub record (one domain's
/// collection naming another domain's built-in group) must not hide what
/// the full record says, whichever is read first. Seen in GOAD, where it
/// left Administrators out of the AdminSDHolder finding.
#[test]
fn a_stub_record_does_not_hide_a_fuller_one() {
    let id = "X.LOCAL-S-1-5-32-544";
    let stub = format!(r#"{{"ObjectIdentifier":"{id}","Properties":{{"domain":"X.LOCAL"}}}}"#);
    let full = format!(
        r#"{{"ObjectIdentifier":"{id}","Properties":{{"name":"ADMINISTRATORS@X.LOCAL","domain":"X.LOCAL","admincount":true,"description":"Builtin"}}}}"#
    );
    let groups =
        |o: &str| format!(r#"{{"data":[{o}],"meta":{{"type":"groups","count":1,"version":6}}}}"#);
    for (first, second) in [(&stub, &full), (&full, &stub)] {
        let mut ing = Ingestor::new();
        ing.ingest_text("a_groups.json", &groups(first)).unwrap();
        ing.ingest_text("b_groups.json", &groups(second)).unwrap();
        let (g, _) = ing.finish();
        let n = g.node(g.find(id)[0]);
        assert_eq!(n.name, "ADMINISTRATORS@X.LOCAL");
        assert_eq!(n.props.admincount, Some(true));
        assert_eq!(n.props.description.as_deref(), Some("Builtin"));
    }
    // Values both records set: the first one read is kept, as before.
    let a = format!(r#"{{"ObjectIdentifier":"{id}","Properties":{{"description":"one"}}}}"#);
    let b = format!(r#"{{"ObjectIdentifier":"{id}","Properties":{{"description":"two"}}}}"#);
    let mut ing = Ingestor::new();
    ing.ingest_text("a_groups.json", &groups(&a)).unwrap();
    ing.ingest_text("b_groups.json", &groups(&b)).unwrap();
    let (g, _) = ing.finish();
    assert_eq!(
        g.node(g.find(id)[0]).props.description.as_deref(),
        Some("one")
    );
}

/// GOAD: north's RustHound-CE collection names the forest's CA
/// `SEVENKINGDOMS-CA@NORTH.SEVENKINGDOMS.LOCAL`, sevenkingdoms' names it
/// `...@SEVENKINGDOMS.LOCAL`. Whichever is read first, the CA takes the
/// forest root's name, as SharpHound gives it.
#[test]
fn configuration_objects_take_the_forest_root_name() {
    let ca = |domain: &str| {
        format!(
            r#"{{"data":[{{"ObjectIdentifier":"6C5E1D4A-0000-0000-0000-000000000001","Properties":{{"name":"SEVENKINGDOMS-CA@{domain}","domain":"{domain}","distinguishedname":"CN=SEVENKINGDOMS-CA,CN=ENROLLMENT SERVICES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=SEVENKINGDOMS,DC=LOCAL"}}}}],"meta":{{"type":"enterprisecas","count":1,"version":6}}}}"#
        )
    };
    for first in ["NORTH.SEVENKINGDOMS.LOCAL", "SEVENKINGDOMS.LOCAL"] {
        let mut ing = Ingestor::new();
        ing.ingest_text("a_enterprisecas.json", &ca(first)).unwrap();
        ing.ingest_text("b_enterprisecas.json", &ca("SEVENKINGDOMS.LOCAL"))
            .unwrap();
        let (g, _) = ing.finish();
        let n = g.node(g.lookup("6C5E1D4A-0000-0000-0000-000000000001").unwrap());
        assert_eq!(n.name, "SEVENKINGDOMS-CA@SEVENKINGDOMS.LOCAL");
        assert_eq!(n.domain.as_deref(), Some("SEVENKINGDOMS.LOCAL"));
    }
}

/// A trust whose TargetDomainName is blank names its domain by its SID, as
/// a missing one does; two such domains stay two.
#[test]
fn blank_trust_target_names_fall_back_to_the_sid() {
    let trust = |sid: &str, name: &str| {
        format!(
            r#"{{"TargetDomainSid":"{sid}","TargetDomainName":"{name}","TrustDirection":"Outbound","TrustType":"External","IsTransitive":false,"SidFilteringEnabled":true}}"#
        )
    };
    let domains = format!(
        r#"{{"data":[{{"ObjectIdentifier":"S-1-5-21-1-1-1","Properties":{{"name":"A.LOCAL","domain":"A.LOCAL"}},"Trusts":[{},{}]}}],"meta":{{"type":"domains","count":1,"version":6}}}}"#,
        trust("S-1-5-21-2-2-2", ""),
        trust("S-1-5-21-3-3-3", "  ")
    );
    let mut ing = Ingestor::new();
    ing.ingest_text("a_domains.json", &domains).unwrap();
    let (g, stats) = ing.finish();
    let targets: Vec<&str> = stats.trusts.iter().map(|t| t.target.as_str()).collect();
    assert_eq!(targets, ["S-1-5-21-2-2-2", "S-1-5-21-3-3-3"]);
    for sid in targets {
        assert_eq!(g.node(g.lookup(sid).unwrap()).name, sid);
    }
}

/// RustHound-CE up to 2.5.23: templates without ObjectIdentifier (named by
/// objectGUID) and a CA listing its templates without identifiers. A CA that
/// another collection resolved keeps only what that one says.
#[test]
fn unresolved_template_publication() {
    let pks = "CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=X,DC=LOCAL";
    let templates = format!(
        r#"{{"data":[{{"ObjectIdentifier":"","Properties":{{"name":"A@X.LOCAL","objectguid":"aaaaaaaa-0000-0000-0000-000000000001","distinguishedname":"CN=A,CN=CERTIFICATE TEMPLATES,{pks}"}}}},{{"ObjectIdentifier":"","Properties":{{"name":"B@X.LOCAL","objectguid":"AAAAAAAA-0000-0000-0000-000000000002","distinguishedname":"CN=B,CN=CERTIFICATE TEMPLATES,{pks}"}}}}],"meta":{{"type":"certtemplates","count":2,"version":6}}}}"#
    );
    let ca = |published: &str| {
        format!(
            r#"{{"data":[{{"ObjectIdentifier":"CCCCCCCC-0000-0000-0000-000000000001","Properties":{{"name":"X-CA@X.LOCAL","distinguishedname":"CN=X-CA,CN=ENROLLMENT SERVICES,{pks}"}},"EnabledCertTemplates":[{published}]}}],"meta":{{"type":"enterprisecas","count":1,"version":6}}}}"#
        )
    };
    let blank = r#"{"ObjectIdentifier":"","ObjectType":"CertTemplate"}"#;
    let count = |cas: &[String]| {
        let mut ing = Ingestor::new();
        ing.ingest_text("t_certtemplates.json", &templates).unwrap();
        for (i, c) in cas.iter().enumerate() {
            ing.ingest_text(&format!("{i}_enterprisecas.json"), c)
                .unwrap();
        }
        let (g, _) = ing.finish();
        assert!(g.lookup("AAAAAAAA-0000-0000-0000-000000000001").is_some());
        let ix = g.lookup("CCCCCCCC-0000-0000-0000-000000000001").unwrap();
        let unresolved = g
            .node(ix)
            .adcs
            .as_ref()
            .unwrap()
            .publishedtemplatesunresolved;
        let n = g
            .inner()
            .edges_directed(ix, petgraph::Direction::Incoming)
            .filter(|e| *e.weight() == EdgeKind::PublishedTo)
            .count();
        (n, unresolved)
    };
    assert_eq!(count(&[ca(&format!("{blank},{blank}"))]), (2, true));
    let one = r#"{"ObjectIdentifier":"AAAAAAAA-0000-0000-0000-000000000002","ObjectType":"CertTemplate"}"#;
    assert_eq!(
        count(&[ca(&format!("{blank},{blank}")), ca(one)]),
        (1, false)
    );
    // A CA that publishes nothing is not "unresolved".
    assert_eq!(count(&[ca("")]), (0, false));
}
