//! Tier Zero settings files, part 2: the certification authorities'
//! values (ESC6, ESC11), settings folders, and the run record. Synthetic
//! data only: the AD CS fixture in `testdata/adcs` and the settings file in
//! `tests/fixtures/tierzero`.

use std::path::{Path, PathBuf};

use pathwarden_core::dcsettings::{self, FileAge, ServerKind, SettingsFileUse};
use pathwarden_core::graph::AdGraph;
use pathwarden_core::ingest::IngestStats;
use pathwarden_core::model::NodeKind;
use pathwarden_core::{load, LoadOptions};

/// PKI-CA's certificate thumbprint in these tests.
const THUMB: &str = "3F2504E04F8911D39A0C0305E82C3301AABBCCDD";
/// ROGUE-CA's.
const ROGUE: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
/// The collection time collectors put in file names: 2026-10-13 08:30 UTC.
const STAMP: &str = "20261013083000_";

fn fixture_file() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tierzero/pathwarden-tierzero-CA01.pki.local.json"),
    )
    .unwrap()
}

/// A fresh, empty folder for one test.
fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-t0s-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The AD CS fixture in `dir`, file names prefixed with `stamp`, with the
/// CAs' thumbprints set and, unless `san_collected`, PKI-CA's ESC6 and
/// ESC11 registry values not collected (as SharpHound without rights).
fn write_fixture(dir: &Path, stamp: &str, san_collected: bool) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/adcs");
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        // The CAs' certificates as real thumbprints, wherever they appear
        // (the NTAuth store, the root CAs, the chains).
        let mut text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"AAAA\"", &format!("\"{THUMB}\""))
            .replace("\"BBBB\"", &format!("\"{ROGUE}\""));
        if file == "pki_enterprisecas.json" {
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            for c in v["data"].as_array_mut().unwrap() {
                let rogue = c["Properties"]["caname"] == "ROGUE-CA";
                c["Properties"]["certthumbprint"] = if rogue { ROGUE } else { THUMB }.into();
                if !rogue && !san_collected {
                    c["CARegistryData"]["IsUserSpecifiesSanEnabled"] = serde_json::json!({"Value": false, "Collected": false, "FailureReason": "access denied"});
                    c["Properties"]["isuserspecifiessanenabledcollected"] = false.into();
                    c["Properties"]
                        .as_object_mut()
                        .unwrap()
                        .remove("enforceencryptionforrequests");
                }
            }
            text = v.to_string();
        }
        std::fs::write(dir.join(format!("{stamp}{file}")), text).unwrap();
    }
}

fn load_dir(dir: &Path, opts: &LoadOptions) -> (AdGraph, IngestStats) {
    load(&[dir], opts).expect("fixture loads")
}

fn pki_ca(g: &AdGraph) -> &pathwarden_core::model::AdcsProps {
    g.nodes()
        .find(|(_, n)| n.kind == NodeKind::EnterpriseCa && n.name.starts_with("PKI-CA"))
        .and_then(|(_, n)| n.adcs.as_deref())
        .unwrap()
}

fn with_value(text: &str, name: &str, value: Option<i64>) -> String {
    let mut v: serde_json::Value = serde_json::from_str(text).unwrap();
    for x in v["cas"][0]["values"].as_array_mut().unwrap() {
        if x["name"] == name {
            x["present"] = value.is_some().into();
            x["value"] = value.into();
        }
    }
    v.to_string()
}

fn read_at(text: &str, at: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(text).unwrap();
    v["read_at"] = at.into();
    v.to_string()
}

#[test]
fn a_ca_file_opens_esc6_and_esc11_the_collection_could_not_read() {
    let dir = temp("open");
    write_fixture(&dir, STAMP, false);
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    let before = pathwarden_core::posture::adcs_completeness(&g);
    let pki = before.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    assert!(!pki.esc6 && !pki.esc11);
    assert_eq!(pki.esc6_file, None);
    assert!(stats.ca_settings.is_empty());
    let cas = dcsettings::ca_completeness(&g);
    let c = cas.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    assert!(!c.has_file && !c.collected && c.needs_file());
    assert_eq!(c.settings_words(), "No settings file yet.");
    assert_eq!(c.still_needed(), "A settings file from this CA.");

    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        fixture_file(),
    )
    .unwrap();
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(stats.ca_settings.len(), 1, "{:?}", stats.skipped_files);
    let st = &stats.ca_settings[0];
    assert_eq!(st.matched.as_deref(), Some("PKI-CA@PKI.LOCAL"));
    assert_eq!(st.applied, ["EditFlags", "InterfaceFlags"]);
    // A CA host that is not a domain controller: no DC entry, no skip.
    assert!(stats.dc_settings.is_empty(), "{:?}", stats.dc_settings);
    assert!(stats.skipped_files.is_empty(), "{:?}", stats.skipped_files);
    let a = pki_ca(&g);
    assert_eq!(a.isuserspecifiessanenabled, Some(true));
    assert_eq!(a.enforceencryptionforrequests, Some(false));
    let after = pathwarden_core::posture::adcs_completeness(&g);
    let pki = after.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    assert!(pki.esc6 && pki.esc11);
    assert_eq!(
        (pki.esc6_file, pki.esc11_file),
        (Some(FileAge::Current), Some(FileAge::Current))
    );
    // ESC11 is now an attack path through PKI-CA.
    assert!(g
        .esc_instances()
        .iter()
        .any(|i| i.esc == pathwarden_core::adcs::Esc::Esc11));
    let cas = dcsettings::ca_completeness(&g);
    let c = cas.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    assert!(c.has_file && !c.stale && !c.needs_file());
    assert_eq!(
        c.settings_words(),
        "Read from its settings file on Oct 13, 2026."
    );
    assert_eq!(c.still_needed(), "Nothing.");
    // The run records the file by name, as a CA's.
    let files = stats.settings_files(0);
    assert_eq!(
        files,
        [SettingsFileUse {
            file_name: "pathwarden-tierzero-CA01.pki.local.json".into(),
            server: "PKI-CA".into(),
            kind: ServerKind::Ca,
            read_at: dcsettings::parse_utc("2026-10-13T08:00:00Z"),
            stale: false,
            applied: true,
        }]
    );
}

#[test]
fn a_stale_ca_file_with_the_flag_off_does_not_close_a_collected_on() {
    // No collection time: the file would win if it were current.
    let dir = temp("stale");
    write_fixture(&dir, "", true);
    let off = with_value(&fixture_file(), "EditFlags", Some(0x0011_014E));
    let off = with_value(&off, "InterfaceFlags", None);
    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        read_at(&off, "2024-01-01T00:00:00Z"),
    )
    .unwrap();
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    let st = &stats.ca_settings[0];
    assert_eq!(st.ignored, ["EditFlags", "InterfaceFlags"], "{st:?}");
    assert!(st.applied.is_empty());
    assert!(st
        .notes
        .iter()
        .any(|n| n.contains("only values that show a weakness")));
    let a = pki_ca(&g);
    assert_eq!(a.isuserspecifiessanenabled, Some(true));
    assert_eq!(a.enforceencryptionforrequests, Some(false));
    let cas = dcsettings::ca_completeness(&g);
    let c = cas.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    // The collection read both values itself: no file is needed, and the
    // old one isn't what the report says it read.
    assert!(c.collected && !c.has_file && !c.needs_file());
    assert_eq!(c.settings_words(), "Read by the collection.");
    assert_eq!(c.still_needed(), "Nothing.");
    // The record marks it stale and not applied.
    let files = stats.settings_files(dcsettings::parse_utc("2026-11-01T00:00:00Z").unwrap());
    assert!(files[0].stale && !files[0].applied);

    // A stale file that shows a weakness is used, and says it is old.
    let dir = temp("stale-open");
    write_fixture(&dir, "", false);
    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        read_at(&fixture_file(), "2024-01-01T00:00:00Z"),
    )
    .unwrap();
    let (g, _) = load_dir(&dir, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(true));
    let ages = pathwarden_core::posture::adcs_completeness(&g);
    let pki = ages.iter().find(|c| c.ca.starts_with("PKI-CA")).unwrap();
    assert_eq!(pki.esc6_file, Some(FileAge::Stale));
}

#[test]
fn a_newer_collection_value_wins() {
    // SharpHound read the SAN flag on at 2026-10-13 08:30; the file is from
    // 2026-10-01 and says off.
    let dir = temp("newer");
    write_fixture(&dir, STAMP, true);
    let off = with_value(&fixture_file(), "EditFlags", Some(0x0011_014E));
    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        read_at(&off, "2026-10-01T00:00:00Z"),
    )
    .unwrap();
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(stats.ca_settings[0].kept, ["EditFlags", "InterfaceFlags"]);
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(true));
}

#[test]
fn a_hash_and_name_mismatch_is_skipped() {
    let dir = temp("mismatch");
    write_fixture(&dir, STAMP, false);
    // Names PKI-CA on CA01, with ROGUE-CA's certificate.
    let text = fixture_file().replace(THUMB, ROGUE);
    std::fs::write(dir.join("pathwarden-tierzero-CA01.pki.local.json"), text).unwrap();
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    assert_eq!(stats.ca_settings[0].matched, None);
    assert!(
        stats
            .skipped_files
            .iter()
            .any(|s| s.contains("its certificate is ROGUE-CA@PKI.LOCAL in the collection")),
        "{:?}",
        stats.skipped_files
    );
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, None);
    // Without hashes, the CA name and host match it.
    let mut v: serde_json::Value = serde_json::from_str(&fixture_file()).unwrap();
    v["cas"][0]["cert_hashes"] = serde_json::json!([]);
    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        v.to_string(),
    )
    .unwrap();
    let (g, stats) = load_dir(&dir, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        stats.ca_settings[0].matched.as_deref(),
        Some("PKI-CA@PKI.LOCAL")
    );
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(true));
}

#[test]
fn the_ca_bit_tests_agree_with_the_collectors() {
    use pathwarden_core::model::DcSetting::{NotSet, Value};
    // EDITF_ATTRIBUTESUBJECTALTNAME2 and IF_ENFORCEENCRYPTICERTREQUEST, as
    // the built-in collector's careg.rs and RustHound-CE test them.
    assert_eq!(dcsettings::SAN_FLAG, 0x0004_0000);
    assert_eq!(dcsettings::ENCRYPT_FLAG, 0x0000_0200);
    assert_eq!(dcsettings::san_enabled(Value(0x0015_014E)), Some(true));
    assert_eq!(dcsettings::san_enabled(Value(0x0011_014E)), Some(false));
    assert_eq!(dcsettings::san_enabled(NotSet), Some(false));
    // Not set: the default, which enforces encryption.
    assert_eq!(dcsettings::encryption_enforced(NotSet), Some(true));
    assert_eq!(dcsettings::encryption_enforced(Value(0x641)), Some(true));
    assert_eq!(dcsettings::encryption_enforced(Value(0x441)), Some(false));
}

/// The fields Pathwarden 0.2.0 read from a settings file: a file with `cas`
/// reads the same, since unknown fields are ignored.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct OlderSidecar {
    schema: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    read_at: Option<String>,
    #[serde(default)]
    values: Vec<serde_json::Value>,
}

#[test]
fn a_file_with_cas_is_still_v1() {
    let text = fixture_file();
    let old: OlderSidecar = serde_json::from_str(&text).unwrap();
    assert_eq!(old.schema, dcsettings::SCHEMA);
    assert!(old.values.is_empty());
    let mut notes = Vec::new();
    let s = dcsettings::Sidecar::parse(text.as_bytes(), &mut notes).unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(s.cas.len(), 1);
    assert_eq!(s.cas[0].cert_hashes, [THUMB]);
    // And a file without `cas` parses with none.
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v.as_object_mut().unwrap().remove("cas");
    let s = dcsettings::Sidecar::parse(v.to_string().as_bytes(), &mut notes).unwrap();
    assert!(s.cas.is_empty());
}

#[test]
fn malformed_ca_entries_are_dropped_with_a_note() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture_file()).unwrap();
    v["cas"][0]["cert_hashes"] = serde_json::json!(["not-a-hash", THUMB]);
    v["cas"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"name": "", "values": []}));
    let mut notes = Vec::new();
    let s = dcsettings::Sidecar::parse(v.to_string().as_bytes(), &mut notes).unwrap();
    assert_eq!(s.cas.len(), 1);
    assert_eq!(s.cas[0].cert_hashes, [THUMB]);
    assert_eq!(notes.len(), 2, "{notes:?}");
    // Too many CAs, or a control character in a name, refuse the file.
    let many: Vec<serde_json::Value> = (0..17)
        .map(|i| serde_json::json!({"name": format!("CA{i}")}))
        .collect();
    v["cas"] = many.into();
    assert!(dcsettings::Sidecar::parse(v.to_string().as_bytes(), &mut Vec::new()).is_err());
    let ctl = fixture_file().replace("\"CA01\"", "\"CA\\u000101\"");
    assert!(dcsettings::Sidecar::parse(ctl.as_bytes(), &mut Vec::new()).is_err());
}

// ------------------------------------------------------- settings folders

#[test]
fn folder_file_names_are_strict() {
    for ok in [
        "pathwarden-tierzero-DC01.contoso.local.json",
        "PathWarden-TierZero-dc01.json",
        "pathwarden-tierzero-DC_01.json",
    ] {
        assert!(dcsettings::is_folder_file_name(ok), "{ok}");
    }
    for bad in [
        "DC01-tierzero.json",
        "pathwarden-tierzero-.json",
        "pathwarden-tierzero-..json",
        "pathwarden-tierzero-a..b.json",
        "pathwarden-tierzero-DC01 copy.json",
        "pathwarden-tierzero-DC01.txt",
        "pathwarden-tierzero-x.coverage.json",
        "pathwarden-tierzero-.hidden.json",
        "users.json",
    ] {
        assert!(!dcsettings::is_folder_file_name(bad), "{bad}");
    }
}

#[test]
fn files_in_a_settings_folder_apply_and_nothing_else_is_read() {
    let data = temp("folder-data");
    write_fixture(&data, STAMP, false);
    let folder = temp("folder");
    std::fs::write(
        folder.join("pathwarden-tierzero-CA01.pki.local.json"),
        fixture_file(),
    )
    .unwrap();
    // AD data in the folder is never ingested, nor a subfolder, nor a file
    // whose name the script doesn't write.
    std::fs::copy(
        data.join(format!("{STAMP}pki_users.json")),
        folder.join("users.json"),
    )
    .unwrap();
    std::fs::write(folder.join("DC01-tierzero.json"), "{}").unwrap();
    std::fs::create_dir_all(folder.join("sub")).unwrap();
    std::fs::write(
        folder
            .join("sub")
            .join("pathwarden-tierzero-CA02.pki.local.json"),
        fixture_file(),
    )
    .unwrap();
    // Too large: refused, named by its file name.
    std::fs::write(
        folder.join("pathwarden-tierzero-BIG.pki.local.json"),
        vec![b' '; dcsettings::MAX_SIDECAR_BYTES as usize + 1],
    )
    .unwrap();
    let opts = LoadOptions {
        settings_folders: vec![folder.clone(), folder.join("missing")],
        ..LoadOptions::default()
    };
    let (g, stats) = load_dir(&data, &opts);
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&folder);
    assert_eq!(stats.ca_settings.len(), 1, "{:?}", stats.skipped_files);
    // Labelled by file name alone: no folder path in the run's data.
    assert_eq!(
        stats.ca_settings[0].file,
        "pathwarden-tierzero-CA01.pki.local.json"
    );
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(true));
    assert!(stats.skipped_files.iter().any(|s| s
        .starts_with("pathwarden-tierzero-BIG.pki.local.json")
        && s.contains("too large")));
    assert!(!stats
        .files
        .iter()
        .any(|f| f.contains("users.json") && !f.contains(STAMP)));
    // The missing folder is a warning, not a failure.
    assert_eq!(stats.settings_folders_unread.len(), 1);
    assert!(stats.settings_folders_unread[0].0.ends_with("missing"));
    // And never saved with the stats.
    let json = serde_json::to_string(&stats).unwrap();
    assert!(!json.contains("missing"), "{json}");
}

#[cfg(windows)]
#[test]
fn a_linked_settings_file_is_not_followed() {
    let data = temp("link-data");
    write_fixture(&data, STAMP, false);
    let outside = temp("link-outside");
    let target = outside.join("real.json");
    std::fs::write(&target, fixture_file()).unwrap();
    let folder = temp("link");
    let link = folder.join("pathwarden-tierzero-CA01.pki.local.json");
    // Making a link needs Developer Mode or admin rights; without them
    // there is nothing to test.
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&folder);
        return;
    }
    let opts = LoadOptions {
        settings_folders: vec![folder.clone()],
        ..LoadOptions::default()
    };
    let (_, stats) = load_dir(&data, &opts);
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&outside);
    let _ = std::fs::remove_dir_all(&folder);
    assert!(stats.ca_settings.is_empty());
}

#[test]
fn analyze_reads_the_configured_folders_as_if_the_files_were_dropped_in() {
    use pathwarden_core::analyze;
    let data = temp("eval-data");
    write_fixture(&data, STAMP, false);
    let folder = temp("eval-folder");
    let file = folder.join("pathwarden-tierzero-CA01.pki.local.json");
    std::fs::write(&file, fixture_file()).unwrap();
    // Through the config's folders (run, retest, save, the app's jobs).
    // A TOML literal string: the path as it is. Added on this computer, so
    // used here.
    let toml = format!("settings_folders = ['{}']\n", folder.display());
    let conf_dir = temp("eval-config");
    let conf = conf_dir.join("pathwarden.toml");
    std::fs::write(&conf, &toml).unwrap();
    // Read from text alone, a config reads no folder.
    let text_only = pathwarden_core::config::Config::parse(&toml).unwrap();
    assert!(text_only.settings_folder_paths().is_empty());
    // Not reviewed here: listed, not read.
    let config = pathwarden_core::config::Config::from_file(&conf).unwrap();
    assert!(config.settings_folder_paths().is_empty());
    pathwarden_core::folder_origin::mark(&conf, &[folder.display().to_string()], true).unwrap();
    let config = pathwarden_core::config::Config::from_file(&conf).unwrap();
    let _ = std::fs::remove_dir_all(&conf_dir);
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    assert_eq!(config.settings_folder_paths().len(), 1);
    let a = analyze::evaluate(
        std::slice::from_ref(&data),
        &config,
        &[],
        &mut analyze::Quiet,
    )
    .unwrap();
    // The file given with the collection instead.
    let plain = pathwarden_core::config::Config::default();
    let b = analyze::evaluate(
        &[data.clone(), file.clone()],
        &plain,
        &[],
        &mut analyze::Quiet,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&folder);
    let words = |s: &IngestStats| {
        s.ca_settings
            .iter()
            .map(|c| (c.matched.clone(), c.applied.clone(), c.read_at))
            .collect::<Vec<_>>()
    };
    assert_eq!(words(&a.stats), words(&b.stats));
    assert_eq!(a.stats.settings_files(0), b.stats.settings_files(0));
    let ids = |e: &analyze::Evaluated| {
        let mut f: Vec<String> = e.findings.iter().map(|f| f.fingerprint.clone()).collect();
        f.sort();
        f
    };
    assert_eq!(ids(&a), ids(&b));
}

#[test]
fn settings_folders_round_trip_and_near_misses_are_refused() {
    use pathwarden_core::config::Config;
    use pathwarden_core::config_edit::{check_settings_folder, ConfigDoc};
    let c = Config::parse("settings_folders = ['\\\\fs01\\pathwarden-t0', 'D:\\t0']\n").unwrap();
    assert_eq!(c.settings_folders.len(), 2);
    // From text alone: listed, none used.
    assert!(c.settings_folder_paths().is_empty());
    assert!(c.warnings.is_empty());
    // A singular, or the name without underscores, is a typo.
    for typo in ["settings_folder = ['D:\\\\t0']\n", "settingsfolders = []\n"] {
        let e = Config::parse(typo).unwrap_err().to_string();
        assert!(e.contains("settings_folders"), "{e}");
    }
    // A relative path is not read, and said.
    let c = Config::parse("settings_folders = ['t0']\n").unwrap();
    assert!(c.settings_folder_paths().is_empty());
    assert_eq!(c.warnings.len(), 1);
    for ok in [r"\\fs01\pathwarden-t0", r"D:\t0", "/srv/t0"] {
        assert!(check_settings_folder(ok).is_ok(), "{ok}");
    }
    for bad in [r"t0", r"\\fs01", r"\\fs01\t0\..\other", "C:t0", "//x/y"] {
        assert!(check_settings_folder(bad).is_err(), "{bad}");
    }
    let mut d = ConfigDoc::template();
    d.set_settings_folders(&[
        r"\\fs01\pathwarden-t0".into(),
        r"\\FS01\pathwarden-t0".into(),
    ])
    .unwrap();
    let text = d.text();
    let back = Config::parse(&text).unwrap();
    assert_eq!(back.settings_folders, [r"\\fs01\pathwarden-t0"]);
    assert!(d.set_settings_folders(&["relative".into()]).is_err());
    d.set_settings_folders(&[]).unwrap();
    // The key goes (the template's commented example stays).
    assert!(!d.text().contains("\nsettings_folders"));
    assert!(Config::parse(&d.text())
        .unwrap()
        .settings_folders
        .is_empty());
    // A shared section: it travels with the other shared settings.
    assert!(pathwarden_core::config_edit::is_shared_key(
        "settings_folders"
    ));
}

/// Anyone who can write to a settings folder can drop a current file with
/// the CA's public thumbprint and the SAN flag off. It must not close the
/// ESC6 the collection read; the same file given with the collection does.
#[test]
fn a_forged_folder_file_does_not_close_a_collected_weakness() {
    let data = temp("forged-data");
    write_fixture(&data, "", true);
    let folder = temp("forged");
    let off = with_value(&fixture_file(), "EditFlags", Some(0x0011_014E));
    let off = with_value(&off, "InterfaceFlags", Some(0x641));
    std::fs::write(folder.join("pathwarden-tierzero-CA01.pki.local.json"), &off).unwrap();
    let opts = LoadOptions {
        settings_folders: vec![folder.clone()],
        ..LoadOptions::default()
    };
    let (g, stats) = load_dir(&data, &opts);
    let st = &stats.ca_settings[0];
    assert_eq!(st.ignored, ["EditFlags", "InterfaceFlags"], "{st:?}");
    assert!(st.from_folder && !st.owner_verified);
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(true));
    assert_eq!(pki_ca(&g).enforceencryptionforrequests, Some(false));
    // Given with the collection, whoever analyzes chose it: it applies.
    std::fs::write(data.join("pathwarden-tierzero-CA01.pki.local.json"), &off).unwrap();
    let (g, _) = load_dir(&data, &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&folder);
    assert_eq!(pki_ca(&g).isuserspecifiessanenabled, Some(false));
}

/// A file named for one host and describing another is refused; caps and
/// a slow folder are warnings, never a failure.
#[test]
fn folder_names_caps_and_timeouts() {
    use pathwarden_core::ingest::{FolderLimits, Ingestor};
    let folder = temp("caps");
    let text = fixture_file();
    std::fs::write(
        folder.join("pathwarden-tierzero-CA09.pki.local.json"),
        &text,
    )
    .unwrap();
    for i in 0..5 {
        std::fs::write(folder.join(format!("pathwarden-tierzero-ZZ{i}.json")), "{}").unwrap();
    }
    let mut ing = Ingestor::new();
    let limits = FolderLimits {
        max_files: 3,
        ..FolderLimits::default()
    };
    ing.ingest_settings_folder_with(&folder, &limits);
    let (_, stats) = ing.finish();
    assert!(
        stats
            .skipped_files
            .iter()
            .any(|s| s.contains("pathwarden-tierzero-CA09") && s.contains("another host")),
        "{:?}",
        stats.skipped_files
    );
    assert!(
        stats
            .settings_folder_warnings
            .iter()
            .any(|w| w.contains("holds 6 settings files; only 3 were read")),
        "{:?}",
        stats.settings_folder_warnings
    );
    // A folder that doesn't answer in time is unread, not a failure.
    let mut ing = Ingestor::new();
    let limits = FolderLimits {
        timeout: std::time::Duration::from_nanos(1),
        ..FolderLimits::default()
    };
    ing.ingest_settings_folder_with(&folder, &limits);
    let (_, stats) = ing.finish();
    let _ = std::fs::remove_dir_all(&folder);
    // Either it answered at once or it is unread with the reason.
    assert!(stats
        .settings_folders_unread
        .iter()
        .all(|(_, why)| why.contains("didn't answer")));
}

/// A folder the shared history brought is listed but not read until it is
/// reviewed on this computer; one added here is read at once.
#[test]
fn folders_from_the_repository_wait_for_a_review_here() {
    use pathwarden_core::config::Config;
    let dir = temp("review");
    std::fs::create_dir_all(dir.join("st").join("settings")).unwrap();
    std::fs::write(
        dir.join("pathwarden.toml"),
        "settings_folders = ['\\\\fs01\\t0', 'D:\\t0']\n[state]\nbackend = \"git\"\nremote = \"https://example.invalid/h.git\"\npath = \"st\"\nkeep = \"full\"\n",
    )
    .unwrap();
    // The repository's settings carry the share, not the local folder.
    std::fs::write(
        dir.join("st").join("settings").join("pathwarden.toml"),
        "settings_folders = ['\\\\FS01\\t0']\n",
    )
    .unwrap();
    let path = dir.join("pathwarden.toml");
    // Neither was added or reviewed here (a hand edit, a copied file, the
    // repository): both wait. Only the share is the repository's.
    let c = Config::from_file(&path).unwrap();
    assert_eq!(c.settings_folders_unreviewed.len(), 2);
    assert!(c.settings_folder_paths().is_empty());
    assert_eq!(
        pathwarden_core::folder_origin::from_repo(&c, &path),
        [r"\\fs01\t0"]
    );
    // Added here (as the Settings page and `config settings-folders add`
    // record it), and the share reviewed with Use.
    pathwarden_core::folder_origin::mark(&path, &[r"D:\t0".to_string()], true).unwrap();
    let c = Config::from_file(&path).unwrap();
    assert_eq!(c.settings_folders_unreviewed, [r"\\fs01\t0"]);
    assert_eq!(c.settings_folder_paths(), [PathBuf::from(r"D:\t0")]);
    pathwarden_core::folder_origin::mark(&path, &[r"\\fs01\t0\".to_string()], true).unwrap();
    let c = Config::from_file(&path).unwrap();
    assert!(c.settings_folders_unreviewed.is_empty());
    assert_eq!(c.settings_folder_paths().len(), 2);
    // A broken record reviews nothing.
    std::fs::write(dir.join(pathwarden_core::folder_origin::FILE), "{").unwrap();
    let c = Config::from_file(&path).unwrap();
    assert_eq!(c.settings_folders_unreviewed.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_plain_shares_and_local_paths_are_folders() {
    use pathwarden_core::config_edit::check_settings_folder;
    for bad in [
        r"\\?\C:\t0",
        r"\\.\pipe\x",
        r"\\attacker@SSL\x",
        r"\\attacker@8080\x",
        r"\\attacker@SSL@443\DavWWWRoot\x",
        r"\\host\DavWWWRoot\x",
        "https://host/x",
        "file://host/x",
    ] {
        let e = check_settings_folder(bad).unwrap_err();
        assert!(
            e.contains("not a plain folder or share") || e.contains("not a full folder path"),
            "{bad}: {e}"
        );
    }
    for ok in [
        r"\\fs01.contoso.local\pathwarden-t0",
        r"\\10.0.0.5\t0\sub",
        r"D:\t0",
    ] {
        assert!(check_settings_folder(ok).is_ok(), "{ok}");
    }
}

// ------------------------------------------------------------ run record

fn file(server: &str, kind: ServerKind, stale: bool) -> SettingsFileUse {
    SettingsFileUse {
        file_name: format!("pathwarden-tierzero-{server}.json"),
        server: server.into(),
        kind,
        read_at: Some(1_790_000_000),
        stale,
        applied: true,
    }
}

#[test]
fn fewer_files_than_the_last_run_are_named() {
    let before = vec![
        file("DC01.CONTOSO.LOCAL", ServerKind::Dc, false),
        file("DC03.CONTOSO.LOCAL", ServerKind::Dc, false),
        file("CONTOSO-CA", ServerKind::Ca, false),
    ];
    let now = vec![file("DC01.CONTOSO.LOCAL", ServerKind::Dc, true)];
    let fewer = dcsettings::fewer(&before, &now);
    assert_eq!(fewer, ["DC03.CONTOSO.LOCAL", "CONTOSO-CA"]);
    assert_eq!(
        dcsettings::files_status(&now, fewer.len()),
        "1 file, 1 over 90 days old, 2 fewer than the last run"
    );
    assert_eq!(
        dcsettings::fewer_sentence(&fewer).unwrap(),
        "The last run also had files for DC03.CONTOSO.LOCAL and CONTOSO-CA. Findings that relied on them are marked unverified until the files are back. They don't count as fixed."
    );
    assert!(dcsettings::fewer(&now, &before).is_empty());
    assert!(dcsettings::fewer_sentence(&[]).is_none());
}

#[test]
fn the_run_record_keeps_settings_files_and_older_records_still_load() {
    use pathwarden_core::state::LastRun;
    let compat = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat");
    let mut read = 0;
    for v in std::fs::read_dir(&compat).unwrap() {
        let path = v.unwrap().path().join("state").join("last-run.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let last: LastRun = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert!(last.settings_files.is_empty());
        // Written back without the field: nothing new for older readers.
        assert!(!serde_json::to_string(&last)
            .unwrap()
            .contains("settings_files"));
        read += 1;
    }
    assert!(read >= 1);
    let text = std::fs::read_to_string(compat.join("0.1.9/state/last-run.json")).unwrap();
    let mut last: LastRun = serde_json::from_str(&text).unwrap();
    last.settings_files = vec![file("DC01.CONTOSO.LOCAL", ServerKind::Dc, true)];
    let json = serde_json::to_string(&last).unwrap();
    assert!(json.contains(r#""file_name":"pathwarden-tierzero-DC01.CONTOSO.LOCAL.json""#));
    assert!(json.contains(r#""kind":"dc""#));
    let back: LastRun = serde_json::from_str(&json).unwrap();
    assert_eq!(back.settings_files, last.settings_files);
}

#[test]
fn the_report_shows_the_tier_zero_settings_row() {
    let dir = temp("report");
    write_fixture(&dir, STAMP, false);
    let config = pathwarden_core::config::Config::default();
    let before = pathwarden_core::analyze::run(
        std::slice::from_ref(&dir),
        &config,
        &[],
        &mut pathwarden_core::analyze::Quiet,
    )
    .unwrap();
    let html = before.report_html(0, &mut pathwarden_core::analyze::Quiet);
    assert!(html.contains(r#"<span class="title">Tier Zero settings</span>"#));
    assert!(!html.contains("DC settings (ESC9, ESC10)"));
    assert!(html.contains(
        "ESC6, ESC9, ESC10 and ESC11 need registry settings that only a settings file provides."
    ));
    assert!(
        html.contains("Have each server&#39;s admins run Get-PathwardenTierZeroSettings.ps1")
            || html.contains("Have each server's admins run Get-PathwardenTierZeroSettings.ps1")
    );
    assert!(html.contains("<th>Enterprise CA</th><th>Settings</th><th>Still needed</th>"));
    assert!(html.contains(r#"<td>PKI-CA</td><td class="warn">No settings file yet.</td><td>A settings file from this CA.</td>"#));
    std::fs::write(
        dir.join("pathwarden-tierzero-CA01.pki.local.json"),
        fixture_file(),
    )
    .unwrap();
    let after = pathwarden_core::analyze::run(
        std::slice::from_ref(&dir),
        &config,
        &[],
        &mut pathwarden_core::analyze::Quiet,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let html = after.report_html(0, &mut pathwarden_core::analyze::Quiet);
    assert!(html.contains(
        "<td>PKI-CA</td><td>Read from its settings file on Oct 13, 2026.</td><td>Nothing.</td>"
    ));
    assert!(html.contains("<td>from its settings file</td><td>from its settings file</td>"));
}
