//! A computer's first sync: its words, and the copy of `pathwarden.toml`
//! saved before the history's settings replace anything.

use super::*;

#[test]
fn first_sync_words_name_the_sections_and_the_copy() {
    assert_eq!(
        first_sync_words(
            &["Rule settings", "Zones"],
            Some("pathwarden.toml.before-connect-2026-11-18")
        ),
        "Rule settings and zones were taken from the run history. This computer's earlier \
         settings are saved in pathwarden.toml.before-connect-2026-11-18."
    );
    assert_eq!(
        first_sync_words(
            &["Accepted risks", "Tier Zero additions", "Mapping packs"],
            None
        ),
        "Accepted risks, Tier Zero additions and mapping packs were taken from the run history."
    );
    assert_eq!(
        differ_words(&["Rule settings"]),
        "This computer's rule settings differ from the shared ones."
    );
    assert_eq!(
        differ_words(&["Tier Zero additions", "Zones"]),
        "This computer's Tier Zero additions and zones differ from the shared ones."
    );
}

#[test]
fn the_copy_never_overwrites_one() {
    let dir = std::env::temp_dir().join(format!("pw-before-connect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pathwarden.toml");
    // No pathwarden.toml yet: nothing to save.
    assert_eq!(save_before_connect(&config).unwrap(), None);
    std::fs::write(&config, "[rules]\nstale_days = 90\r\n").unwrap();
    let a = save_before_connect(&config).unwrap().unwrap();
    let b = save_before_connect(&config).unwrap().unwrap();
    let c = save_before_connect(&config).unwrap().unwrap();
    let name = |p: &Path| p.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name(&a).starts_with("pathwarden.toml.before-connect-20"),
        "{a:?}"
    );
    assert_eq!(name(&b), format!("{}-2", name(&a)));
    assert_eq!(name(&c), format!("{}-3", name(&a)));
    for p in [&a, &b, &c] {
        assert_eq!(p.parent(), Some(dir.as_path()));
        assert_eq!(
            std::fs::read(p).unwrap(),
            b"[rules]\nstale_days = 90\r\n",
            "byte for byte"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&a).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "private: {mode:o}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
