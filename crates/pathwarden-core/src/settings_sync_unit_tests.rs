use super::*;

fn side(text: &str) -> Side {
    local_side(text, Path::new(".")).unwrap().0
}

#[test]
fn digests_ignore_form_and_other_sections() {
    let a = side("tier_zero = ['A@X']\n[rules]\nstale_days = 30\n[state]\nbackend = \"local\"\n");
    let b = side("[rules]\n# c\nstale_days   = 30\n\ntier_zero = [\"A@X\"]\n");
    // `tier_zero` after a table belongs to it: not the same.
    assert_ne!(a.all(), b.all());
    let b = side(
        "tier_zero = [\"A@X\",]\n[rules]\n# c\nstale_days   = 30\n[[output]]\nplugin = \"x\"\n",
    );
    assert_eq!(a.all(), b.all());
    // Empty sections are absent ones.
    let c = side("tier_zero = []\n[rules]\n");
    assert!(c.digests.is_empty());
    assert_eq!(c.all(), Side::default().all());
    // CRLF inside a string doesn't count.
    let d = side("[[suppress]]\nrule = \"PW-011\"\nreason = \"\"\"a\r\nb\"\"\"\n");
    let e = side("[[suppress]]\nrule = \"PW-011\"\nreason = \"\"\"a\nb\"\"\"\n");
    assert_eq!(d.all(), e.all());
}

#[test]
fn sections_compare_with_the_base() {
    use Changed::*;
    assert_eq!(compare(Some("a"), Some("a"), None), InStep);
    assert_eq!(compare(Some("a"), Some("b"), Some(Some("a"))), Repository);
    assert_eq!(compare(Some("b"), Some("a"), Some(Some("a"))), Here);
    assert_eq!(compare(Some("b"), Some("c"), Some(Some("a"))), Both);
    assert_eq!(compare(None, Some("a"), Some(None)), Repository);
    assert_eq!(compare(Some("a"), None, Some(None)), Here);
    // Never synced.
    assert_eq!(compare(None, Some("a"), None), Repository);
    assert_eq!(compare(Some("a"), None, None), Here);
    // Both sides, never synced: the history's wins.
    assert_eq!(compare(Some("a"), Some("b"), None), Repository);
    let mut base = Base::default();
    base.set("tier_zero", &side("tier_zero = ['A']\n"));
    base.set("rules", &side(""));
    assert_eq!(base.get("rules"), Some(None));
    assert_eq!(base.get("zone"), None);
    let back: Base = serde_json::from_slice(&serde_json::to_vec(&base).unwrap()).unwrap();
    assert_eq!(back, base);
}

#[test]
fn changes_are_described_in_a_few_words() {
    let old = side(
            "tier_zero = ['A', 'B']\n[[suppress]]\nrule = 'PW-011'\nreason = 'r'\n[[zone]]\nname = 'Servers'\ngroups = ['G']\n",
        );
    let new = side(
            "tier_zero = ['a', 'C']\n[rules]\nstale_days = 30\n[[suppress]]\nrule = 'PW-011'\nreason = 'other'\n[[suppress.notes]]\ntext = 'n'\n[[suppress]]\nfingerprint = 'PW-004-1'\nreason = 'r'\n",
        );
    assert_eq!(
        describe(&old.table, &new.table),
        [
            "1 Tier Zero addition",
            "1 Tier Zero removal",
            "rule settings changed",
            "1 accepted risk added",
            "1 accepted risk changed",
            "1 note added",
            "1 zone removed",
        ]
    );
    let m = commit_message(&describe(&old.table, &old.table), &["rules"]);
    assert!(
        m.starts_with("pathwarden settings: environment details\n\nSections: rules\n"),
        "{m}"
    );
    assert!(m.contains(&format!("Pathwarden: {VERSION}")), "{m}");
}

#[test]
fn diffs_mark_what_each_side_changed() {
    let base = vec!["A".to_string(), "B".to_string()];
    let side = vec!["A".to_string(), "C".to_string()];
    let d = diff(&base, &side);
    let marks: Vec<(char, &str)> = d.iter().map(|l| (l.mark, l.text.as_str())).collect();
    assert_eq!(marks, [(' ', "A"), ('+', "C"), ('-', "B")]);
    let v = serde_json::to_value(side_value(
        "[[suppress]]\nrule = 'PW-011'\nreason = 'r'\nexpires = '2027-01-31'\n",
        "suppress",
    ))
    .unwrap();
    assert_eq!(
        section_lines("suppress", Some(&v)),
        ["every PW-011 finding: r (until 2027-01-31)"]
    );
}

fn side_value(text: &str, key: &str) -> toml::Value {
    side(text).table.get(key).cloned().unwrap()
}

#[test]
fn pack_paths_stay_in_the_packs_folder() {
    for ok in [
        "packs/acme.toml",
        "packs/sub/a-b_c.1.TOML",
        r"Packs\acme.toml",
    ] {
        assert!(pack_path(ok).is_ok(), "{ok}");
    }
    for bad in [
        "acme.toml",
        "a/b/c.toml",
        "../acme.toml",
        "/etc/acme.toml",
        "C:/acme.toml",
        r"C:\acme.toml",
        "packs/../../x.toml",
        "packs/.hidden/x.toml",
        "packs/sub./x.toml",
        "packs/sub /x.toml",
        "packs/CON.toml",
        "packs/nul/x.toml",
        "packs/com1.toml",
        "packs/x.txt",
        "packs/a b.toml",
        r"\\server\share\x.toml",
    ] {
        assert!(pack_path(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_push_never_writes_over_a_newer_settings_file() {
    // Read while the repository's file was this version's; a newer
    // Pathwarden's push lands before this one writes. The write itself
    // refuses, forced or not, past any refusal at the sync's level.
    let dir = std::env::temp_dir().join(format!("pw-push-newer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state");
    std::fs::create_dir_all(state.join("settings")).unwrap();
    let config_path = dir.join("pathwarden.toml");
    std::fs::write(&config_path, "tier_zero = [\"B\"]\n").unwrap();
    let repo = state.join(SETTINGS_FILE);
    std::fs::write(&repo, "tier_zero = [\"A\"]\n").unwrap();
    let store = Store::new(&crate::config::StateConfig::default(), Some(&state)).unwrap();
    let place = Place {
        store: &store,
        config_path: &config_path,
        pushes: true,
        env_name: None,
    };
    let r = read_all(&place).unwrap();
    assert!(r.status.unreadable.is_none());
    let newer = "format = 2\ntier_zero = [\"C\"]\n";
    std::fs::write(&repo, newer).unwrap();
    for forced in [true, false] {
        let e = push_local(
            &place,
            &r,
            &["tier_zero"],
            &[],
            forced,
            &mut Done::default(),
        )
        .unwrap_err();
        assert_eq!(format!("{e:#}"), NEWER_SETTINGS_WORDS, "{forced}");
        assert_eq!(std::fs::read_to_string(&repo).unwrap(), newer, "{forced}");
    }
    // environment.json the same.
    std::fs::write(&repo, "tier_zero = [\"A\"]\n").unwrap();
    let env = state.join(ENVIRONMENT_FILE);
    std::fs::write(&env, "{\"format\": 2}").unwrap();
    let e = push_local(&place, &r, &["tier_zero"], &[], true, &mut Done::default()).unwrap_err();
    assert!(
        format!("{e:#}").contains("was saved by a newer Pathwarden"),
        "{e:#}"
    );
    assert_eq!(std::fs::read_to_string(&env).unwrap(), "{\"format\": 2}");
    assert_eq!(
        std::fs::read_to_string(&repo).unwrap(),
        "tier_zero = [\"A\"]\n"
    );
    // A push that goes through writes last-change.json at format 1,
    // which reads back; one of a newer format isn't read.
    std::fs::remove_file(&env).unwrap();
    push_local(&place, &r, &["tier_zero"], &[], true, &mut Done::default()).unwrap();
    let last = state.join(LAST_CHANGE_FILE);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&last).unwrap()).unwrap();
    assert_eq!(v["format"], 1, "{v}");
    assert!(change_record_in(&store).is_some());
    for newer in [serde_json::json!(2), serde_json::json!("1")] {
        let mut v = v.clone();
        v["format"] = newer;
        std::fs::write(&last, v.to_string()).unwrap();
        assert!(change_record_in(&store).is_none(), "{v}");
    }
    let mut old = v.clone();
    old.as_object_mut().unwrap().remove("format");
    std::fs::write(&last, old.to_string()).unwrap();
    assert!(change_record_in(&store).is_some(), "before 0.2: format 1");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn newer_formats_are_not_applied() {
    // The repository's settings of a newer format: refused, whole.
    let e = repo_side("format = 2\ntier_zero = [\"A\"]\n").unwrap_err();
    assert_eq!(format!("{e:#}"), NEWER_SETTINGS_WORDS);
    // Not damaged: `--keep-local` never replaces it.
    assert!(!damaged(&e));
    // A format that isn't a whole number isn't read as 1.
    for text in ["format = \"2\"\n", "format = 1.0\n", "format = 0\n"] {
        assert!(repo_side(text).is_err_and(|e| is_newer_file(&e)), "{text}");
    }
    // Format 1 is this version's, and no note.
    let (side, notes) = repo_side("format = 1\ntier_zero = [\"A\"]\n").unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert!(side.get("tier_zero").is_some());
    // environment.json: written at format 1; read before it said one.
    let env: Environment = serde_json::from_str(r#"{"name":"Lab"}"#).unwrap();
    assert_eq!(env.format, 1);
    let e = Environment {
        format: ENVIRONMENT_FORMAT,
        ..Default::default()
    };
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["format"], 1);
}

#[test]
fn versions_compare_as_numbers() {
    assert!(newer("0.1.10", "0.1.9"));
    assert!(newer("0.2.0", "0.1.9"));
    assert!(!newer("0.1.7", "0.1.7"));
    assert!(!newer("0.1.6", "0.1.7"));
}

#[test]
fn repository_files_have_limits() {
    let big = format!("tier_zero = [\"{}\"]\n", "x".repeat(MAX_SETTINGS_BYTES));
    assert!(repo_side(&big).is_err());
    let mut many = String::from("[[mapping]]\npath = \"packs/a.toml\"\n");
    for i in 0..=MAX_MAPPING_FILES {
        many.push_str(&format!(
            "[[mapping_files]]\npath = \"packs/{i}.toml\"\ntext = \"\"\n"
        ));
    }
    assert!(repo_side(&many).is_err());
    // A pack no [[mapping]] names is left out; a section never shared
    // is named.
    let (s, notes) = repo_side(
            "[[mapping]]\npath = \"packs/a.toml\"\n[[mapping_files]]\npath = \"packs/b.toml\"\ntext = \"x\"\n[state]\nbackend = \"local\"\n",
        )
        .unwrap();
    let m = s.table["mapping"].as_array().unwrap()[0]
        .as_table()
        .unwrap();
    assert!(m.get("text").is_none());
    assert!(
        notes.iter().any(|n| n.contains("packs/b.toml")),
        "{notes:?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("never shared")),
        "{notes:?}"
    );
}
