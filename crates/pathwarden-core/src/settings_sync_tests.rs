//! A computer's first sync: its words, and the copy of `pathwarden.toml`
//! saved before the history's settings replace anything.

use super::*;

#[test]
fn first_sync_words_name_the_sections_and_the_copy() {
    assert_eq!(
        first_sync_words(
            &["Rule settings", "Zones"],
            &["pathwarden.toml.before-connect-2026-11-18"]
        ),
        "Rule settings and zones were taken from the run history. This computer's earlier \
         settings are saved in pathwarden.toml.before-connect-2026-11-18."
    );
    assert_eq!(
        first_sync_words(
            &["Accepted risks", "Tier Zero additions", "Mapping packs"],
            &[]
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
fn the_first_sync_line_is_told_apart() {
    let line = "Rule settings and zones were taken from the run history. This computer's earlier \
                settings are saved in pathwarden.toml.before-connect-2026-11-18 and \
                packs/acme.toml.before-connect-2026-11-18.";
    let (first, rest) = split_first_sync(&format!(
        "The mapping pack packs/x.toml was left out here: why. {line} This computer's rule \
         settings differ from the shared ones."
    ));
    assert_eq!(first.as_deref(), Some(line));
    assert_eq!(
        rest,
        "The mapping pack packs/x.toml was left out here: why. This computer's rule settings \
         differ from the shared ones."
    );
    let (first, rest) = split_first_sync("Zones were taken from the run history.");
    assert_eq!(
        first.as_deref(),
        Some("Zones were taken from the run history.")
    );
    assert!(rest.is_empty());
    let (first, rest) = split_first_sync("Shared updates applied here: Zones.");
    assert!(first.is_none());
    assert_eq!(rest, "Shared updates applied here: Zones.");
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

/// A pack the tests ship, `color` its only difference.
fn pack(color: &str) -> String {
    format!(
        "[pack]\nname = \"acme\"\nversion = 1\nsource_kinds = [\"AcmeHound\"]\nkind_prefix = \"AC_\"\n\n[[node]]\nkind = \"AC_Thing\"\nicon = \"clock\"\ncolor = \"{color}\"\n"
    )
}

/// A computer in a folder of its own with a history folder (`state`) whose
/// shared settings are `repo`, and its own `pathwarden.toml` `local`.
/// Folder histories keep no base, so every sync is a first one.
struct Here {
    dir: PathBuf,
    store: Store,
}

impl Here {
    fn new(name: &str, local: &str, repo: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pw-first-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state");
        std::fs::create_dir_all(state.join("settings")).unwrap();
        std::fs::write(dir.join("pathwarden.toml"), local).unwrap();
        std::fs::write(state.join(SETTINGS_FILE), repo).unwrap();
        let store = Store::new(&crate::config::StateConfig::default(), Some(&state)).unwrap();
        Here { dir, store }
    }

    fn config(&self) -> PathBuf {
        self.dir.join("pathwarden.toml")
    }

    fn sync(&self) -> Result<Outcome> {
        let config = self.config();
        sync(
            &Place {
                store: &self.store,
                config_path: &config,
                pushes: false,
                env_name: None,
            },
            Resolve::Auto,
        )
    }

    /// The `.before-connect-` copies in `sub` (`""`: beside pathwarden.toml).
    fn copies(&self, sub: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.dir.join(sub))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".before-connect-"))
            .collect();
        v.sort();
        v
    }
}

impl Drop for Here {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_first_sync_saves_the_packs_it_replaces() {
    let repo = format!(
        "[[mapping]]\npath = \"packs/acme.toml\"\n\n[[mapping_files]]\npath = \"packs/acme.toml\"\ntext = '''\n{}'''\n",
        pack("#222")
    );
    let h = Here::new("packs", "[[mapping]]\npath = \"packs/acme.toml\"\n", &repo);
    std::fs::create_dir_all(h.dir.join("packs")).unwrap();
    let mine = pack("#111");
    std::fs::write(h.dir.join("packs/acme.toml"), &mine).unwrap();
    let o = h.sync().unwrap();
    assert_eq!(o.done.first, ["Mapping packs"], "{:?}", o.done);
    assert_eq!(o.done.backups.len(), 2, "{:?}", o.done);
    let ours = h.copies("");
    let packs = h.copies("packs");
    assert_eq!(ours.len(), 1, "{ours:?}");
    assert_eq!(packs.len(), 1, "{packs:?}");
    assert!(
        packs[0].starts_with("acme.toml.before-connect-"),
        "{packs:?}"
    );
    assert_eq!(
        std::fs::read_to_string(h.dir.join("packs").join(&packs[0])).unwrap(),
        mine,
        "this computer's pack, as it was"
    );
    assert_eq!(
        crate::pack_origin::normalize(
            &std::fs::read_to_string(h.dir.join("packs/acme.toml")).unwrap()
        ),
        crate::pack_origin::normalize(&pack("#222")),
        "the history's pack"
    );
    let line = o.sentence().unwrap();
    assert!(
        line.contains(&format!(
            "Mapping packs were taken from the run history. This computer's earlier settings \
             are saved in {} and packs/{}.",
            ours[0], packs[0]
        )),
        "{line}"
    );
}

#[test]
fn nothing_of_this_computers_replaced_means_no_copy() {
    let h = Here::new(
        "nothing",
        "# a fresh computer\n",
        "[[zone]]\nname = \"Tier 1\"\ngroups = [\"SERVER ADMINS@NORTH.LOCAL\"]\n",
    );
    let o = h.sync().unwrap();
    assert!(o.done.first.is_empty(), "{:?}", o.done);
    assert_eq!(o.done.taken, ["Zones"], "{:?}", o.done);
    assert!(o.done.backups.is_empty(), "{:?}", o.done);
    assert!(h.copies("").is_empty());
    let line = o.sentence().unwrap();
    assert!(
        line.contains("Zones were taken from the run history."),
        "{line}"
    );
    assert!(!line.contains("saved in"), "{line}");
}

#[test]
fn a_copy_that_fails_replaces_nothing() {
    let local = "[rules]\nstale_days = 90\n";
    let h = Here::new("fails", local, "[rules]\nstale_days = 30\n");
    FAIL_COPY.with(|f| f.set(true));
    let e = h.sync();
    FAIL_COPY.with(|f| f.set(false));
    let e = format!("{:#}", e.unwrap_err());
    assert!(e.contains("Nothing was changed"), "{e}");
    assert_eq!(std::fs::read_to_string(h.config()).unwrap(), local);
    assert!(h.copies("").is_empty());
    // Once a copy can be made, the history's are taken.
    let o = h.sync().unwrap();
    assert_eq!(o.done.first, ["Rule settings"], "{:?}", o.done);
    assert_eq!(h.copies("").len(), 1);
    assert_eq!(
        std::fs::read_to_string(h.dir.join(&h.copies("")[0])).unwrap(),
        local
    );
}
