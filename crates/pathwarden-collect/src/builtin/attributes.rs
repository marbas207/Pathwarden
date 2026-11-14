//! What the read asks the directory for: the attributes
//! RustHound-CE parses, instead of `*`.
//!
//! `*` also brings Exchange data, `thumbnailPhoto`, `userCertificate` and
//! the like, which the parser throws away, and LAPS password values, which
//! would land in the read on disk. [`PARSED`] is what RustHound-CE 2.5.30
//! reads from an entry (every `"name" =>` arm and every lookup of its
//! parser), plus what Pathwarden reads from the raw entries itself.
//! `--all-attributes` (`[collect] all_attributes`) asks for [`ALL`], as
//! before, for comparing the two.
//!
//! Two guards ([`tests`] and `attributes_tests.rs`): every attribute name
//! in the pinned RustHound-CE source is in [`PARSED`] or in [`NOT_ASKED`]
//! with a reason, and a collection with either list writes the same output.
//! **Run them again on every RustHound-CE bump.**

/// Everything, as RustHound-CE asks (`--all-attributes`).
pub(crate) const ALL: &[&str] = &[
    "*",
    "nTSecurityDescriptor",
    "msDS-User-Account-Control-Computed",
];

/// What RustHound-CE 2.5.30 and Pathwarden read from an entry. LDAP names
/// are case-insensitive; AD returns each as its schema spells it, which is
/// how they are written here.
pub(crate) const PARSED: &[&str] = &[
    // RustHound-CE's parser (`src/objects/*.rs`, `enums/ldaptype.rs`).
    "adminCount",
    "cACertificate",
    "certificateTemplates",
    "crossCertificatePair",
    "description",
    "displayName",
    "distinguishedName",
    "dNSHostName",
    "dSHeuristics",
    "flags",
    "gPCFileSysPath",
    "gPLink",
    "groupType",
    "homeDirectory",
    "isCriticalSystemObject",
    "isDeleted",
    "lastLogon",
    "lastLogonTimestamp",
    "lockoutDuration",
    "lockOutObservationWindow",
    "lockoutThreshold",
    "mail",
    "maxPwdAge",
    "member",
    "minPwdAge",
    "minPwdLength",
    "ms-DS-MachineAccountQuota",
    // `haslaps` comes from either expiration time as well as the password.
    "ms-Mcs-AdmPwdExpirationTime",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AllowedToDelegateTo",
    "msDS-Behavior-Version",
    "msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
    "msDS-GroupMSAMembership",
    "msDS-OIDToGroupLink",
    "msDS-SupportedEncryptionTypes",
    "msDS-User-Account-Control-Computed",
    "msLAPS-PasswordExpirationTime",
    "msPKI-Cert-Template-OID",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Certificate-Policy",
    "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag",
    "msPKI-RA-Application-Policies",
    "msPKI-RA-Policies",
    "msPKI-RA-Signature",
    "msPKI-Template-Schema-Version",
    "name",
    "nTSecurityDescriptor",
    "objectClass",
    "objectGUID",
    "objectSid",
    "operatingSystem",
    "pKIExpirationPeriod",
    "pKIExtendedKeyUsage",
    "pKIOverlapPeriod",
    "primaryGroupID",
    "profilePath",
    "pwdHistoryLength",
    "pwdLastSet",
    "pwdProperties",
    "sAMAccountName",
    "schemaIDGUID",
    "scriptPath",
    "securityIdentifier",
    "servicePrincipalName",
    "sIDHistory",
    "title",
    "trustAttributes",
    "trustDirection",
    "unicodePwd",
    "unixUserPassword",
    "userAccountControl",
    "userPassword",
    "whenCreated",
    // RustHound-CE's ou.rs matches it misspelt ("gPOtions"), so it never
    // matches today. Asked for by its real name so a fix keeps working.
    "gPOptions",
    // Pathwarden: the read's windows and resuming (`cache.rs`).
    "uSNChanged",
    // Pathwarden: SCCM's site objects, which RustHound-CE drops; kept in
    // the SYSVOL sidecar (`dirextras.rs`).
    "mSSMSSiteCode",
    "mSSMSMPName",
    "mSSMSDefaultMP",
    // Pathwarden: computers created through the machine account quota
    // (`dirextras.rs`).
    "mS-DS-CreatorSID",
];

/// Names in RustHound-CE's source that are not asked for, and why.
#[cfg(test)]
pub(crate) const NOT_ASKED: &[(&str, &str)] = &[
    (
        "ms-Mcs-AdmPwd",
        "a LAPS password: only logged and sets haslaps, which the expiration time sets too",
    ),
    (
        "msLAPS-Password",
        "a LAPS password: only logged and sets haslaps, which the expiration time sets too",
    ),
    (
        "msLAPS-EncryptedPassword",
        "a LAPS password: only logged and sets haslaps, which the expiration time sets too",
    ),
    (
        "userCertificate",
        "only parsed to log a certificate that does not decode: nothing in the output",
    ),
    (
        "msSFU30Password",
        "its arm's code is commented out: nothing in the output",
    ),
    (
        "profilepath",
        "a lower-case second arm in user.rs: AD sends profilePath, which is asked for",
    ),
    (
        "gPOtions",
        "misspelt in ou.rs: no such attribute; gPOptions is asked for instead",
    ),
];

/// What a read asks for: everything, or [`PARSED`].
pub(crate) fn asked(all: bool) -> &'static [&'static str] {
    if all {
        ALL
    } else {
        PARSED
    }
}

#[cfg(test)]
mod tests {
    //! Guard (a): every attribute name the pinned RustHound-CE source reads
    //! from an entry is asked for or on [`NOT_ASKED`]. It reads the vendored
    //! source (vendor/rusthound-ce) when Cargo.lock has it as a path
    //! dependency, else the source in the cargo registry, the version
    //! Cargo.lock pins. Re-run on every RustHound-CE bump. `PATHWARDEN_SKIP_RH_SOURCE=1` skips it where the
    //! registry source is not there (it fails otherwise).

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use super::*;

    /// Files whose `"…" =>` arms are not attribute names.
    const NOT_ENTRIES: &[(&str, &str)] = &[
        ("args.rs", "collection method names"),
        ("enums/forestlevel.rs", "functional level numbers"),
        (
            "enums/sid.rs",
            "well-known SIDs (the object type guess, in modules/ before 2.5.30)",
        ),
        ("modules/", "group names and SIDs from SYSVOL and SAMR"),
    ];

    /// The vendored RustHound-CE (`[patch.crates-io]`), if it is there.
    fn vendored_dir() -> Option<PathBuf> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/rusthound-ce/src");
        dir.join("objects").is_dir().then_some(dir)
    }

    /// The rusthound-ce version Cargo.lock pins.
    fn pinned_version() -> String {
        let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
        let text = std::fs::read_to_string(&lock)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock.display()));
        let mut lines = text.lines();
        while let Some(l) = lines.next() {
            if l.trim() == "name = \"rusthound-ce\"" {
                let v = lines.next().unwrap_or_default().trim();
                let v = v
                    .strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("no version after rusthound-ce in Cargo.lock: {v}"));
                let source = lines.next().unwrap_or_default();
                // A path dependency has no `source` line: the vendored copy.
                assert!(
                    source.contains("registry+")
                        || (!source.trim_start().starts_with("source") && vendored_dir().is_some()),
                    "rusthound-ce is neither from the registry nor vendored ({source}): \
                     check its source by hand"
                );
                return v.to_string();
            }
        }
        panic!("rusthound-ce is not in {}", lock.display());
    }

    /// `$CARGO_HOME/registry/src/<index>/rusthound-ce-<version>/src`.
    fn source_dir(version: &str) -> Option<PathBuf> {
        if let Some(dir) = vendored_dir() {
            return Some(dir);
        }
        let home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .or_else(|| std::env::var_os("HOME"))
                    .map(|h| PathBuf::from(h).join(".cargo"))
            })?;
        let name = format!("rusthound-ce-{version}");
        std::fs::read_dir(home.join("registry").join("src"))
            .ok()?
            .flatten()
            .map(|index| index.path().join(&name).join("src"))
            .find(|p| p.join("objects").is_dir())
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// The names of an arm's pattern (what comes before `=>`) when it is
    /// only quoted names and `_`, joined by `|`; `None` for anything else
    /// (a constant, a guard, a binding).
    fn plain_names(head: &str) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for part in head.trim().trim_start_matches('|').split('|') {
            let p = part.trim();
            if p == "_" {
                continue;
            }
            let inner = p.strip_prefix('"')?.strip_suffix('"')?;
            if inner.contains('"') || inner.is_empty() {
                return None;
            }
            out.push(inner.to_string());
        }
        Some(out)
    }

    /// Whether `t` (a trimmed line) opens a `match` on an attribute name:
    /// `match key.as_str() {`, `match key {`, ...
    fn opens_key_match(t: &str) -> bool {
        let Some(rest) = t.strip_prefix("match ") else {
            return false;
        };
        let rest = rest.trim_start_matches(['&', '*', '(']);
        t.ends_with('{')
            && rest
                .strip_prefix("key")
                .is_some_and(|after| !after.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    }

    /// The arms of every `match key` in `text`: the names of plain arms,
    /// and each arm the scan can't read as plain names (with its line).
    /// Arms are the lines at the block's first indentation; a pattern may
    /// run over several lines (`"a"` then `| "b" =>`).
    fn key_match_arms(text: &str) -> (Vec<String>, Vec<String>) {
        let lines: Vec<&str> = text.lines().collect();
        let indent = |l: &str| l.len() - l.trim_start().len();
        let (mut names, mut odd) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            if t.starts_with("//") || !opens_key_match(t) {
                i += 1;
                continue;
            }
            let at = indent(lines[i]);
            let mut arms = None;
            let mut pattern = String::new();
            let mut j = i + 1;
            while j < lines.len() {
                let (l, t) = (lines[j], lines[j].trim());
                j += 1;
                if t.is_empty() || t.starts_with("//") {
                    continue;
                }
                let here = indent(l);
                if here <= at && t.starts_with('}') {
                    break;
                }
                let arm = *arms.get_or_insert(here);
                if pattern.is_empty() && (here != arm || t.starts_with(['}', ')', ']'])) {
                    continue;
                }
                pattern.push_str(t);
                pattern.push(' ');
                if let Some((head, _)) = pattern.split_once("=>") {
                    match plain_names(head) {
                        Some(n) => names.extend(n),
                        None => odd.push(format!("line {j}: {}", head.trim())),
                    }
                    pattern.clear();
                }
            }
            i = j;
        }
        (names, odd)
    }

    /// Attribute names `line` reads: match arms (`"a" | "b" =>`, or
    /// `| "b" =>` ending a pattern begun above) and lookups
    /// (`result_attrs.get("a")`, `result_bin["a"]`, ...).
    fn names_in(line: &str) -> Vec<String> {
        let t = line.trim_start();
        if t.starts_with("//") {
            return Vec::new();
        }
        let mut out = Vec::new();
        if t.starts_with('"') || t.starts_with('|') {
            if let Some(names) = t.split_once("=>").and_then(|(head, _)| plain_names(head)) {
                out.extend(names);
            }
        }
        // Lookups on an entry's maps: `attrs` also finds `result_attrs`
        // and `bin_attrs`.
        for map in ["attrs", "result_bin"] {
            for call in [".get(\"", ".contains_key(\"", "[\""] {
                let pat = format!("{map}{call}");
                let mut from = 0;
                while let Some(i) = t[from..].find(&pat) {
                    let at = from + i + pat.len();
                    if let Some(end) = t[at..].find('"') {
                        out.push(t[at..at + end].to_string());
                    }
                    from = at;
                }
            }
        }
        let mut seen = BTreeSet::new();
        out.retain(|n| seen.insert(n.clone()));
        out
    }

    /// What the source reads: every attribute name, with the files it is
    /// in; the `match key` arms the scan can't read; and how many such
    /// matches it found.
    struct Scan {
        names: BTreeMap<String, BTreeSet<String>>,
        odd: Vec<String>,
        matches: usize,
    }

    fn scan(src: &Path) -> Scan {
        let mut files = Vec::new();
        rust_files(src, &mut files);
        let mut out = Scan {
            names: BTreeMap::new(),
            odd: Vec::new(),
            matches: 0,
        };
        for f in files {
            let rel = f
                .strip_prefix(src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if NOT_ENTRIES.iter().any(|(p, _)| rel.starts_with(p)) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let mut add = |n: String| {
                out.names.entry(n).or_default().insert(rel.clone());
            };
            for line in text.lines() {
                names_in(line).into_iter().for_each(&mut add);
            }
            let (names, odd) = key_match_arms(&text);
            names.into_iter().for_each(&mut add);
            out.odd
                .extend(odd.into_iter().map(|o| format!("{rel} {o}")));
            out.matches += text
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.starts_with("//") && opens_key_match(t)
                })
                .count();
        }
        out
    }

    #[test]
    fn every_attribute_rusthound_ce_reads_is_asked_for() {
        if std::env::var_os("PATHWARDEN_SKIP_RH_SOURCE").is_some_and(|v| v == "1") {
            eprintln!("PATHWARDEN_SKIP_RH_SOURCE=1: the RustHound-CE source is not checked");
            return;
        }
        let version = pinned_version();
        let src = source_dir(&version).unwrap_or_else(|| {
            panic!(
                "the source of rusthound-ce {version} is not in the cargo registry \
                 (CARGO_HOME or ~/.cargo): run `cargo fetch`, or set \
                 PATHWARDEN_SKIP_RH_SOURCE=1 to skip this check"
            )
        });
        let Scan {
            names,
            odd,
            matches,
        } = scan(&src);
        // Sanity: the scan finds the parser at all.
        for n in [
            "sAMAccountName",
            "objectClass",
            "schemaIDGUID",
            "ms-Mcs-AdmPwd",
        ] {
            assert!(names.contains_key(n), "{n} not found in {}", src.display());
        }
        assert!(matches >= 20, "only {matches} `match key` blocks found");
        // An arm that isn't plain quoted names (a constant, a guard) could
        // name an attribute the scan misses: read it by hand, then teach
        // the scan.
        assert!(
            odd.is_empty(),
            "rusthound-ce {version} has `match key` arms the scan can't read: {odd:#?}"
        );
        // Exact case: AD sends each name as the schema spells it, and the
        // parser compares exactly.
        let asked = |n: &str| PARSED.contains(&n);
        let excluded = |n: &str| NOT_ASKED.iter().any(|(a, _)| *a == n);
        let missing: Vec<String> = names
            .iter()
            .filter(|(n, _)| !asked(n) && !excluded(n))
            .map(|(n, files)| {
                format!(
                    "{n} ({})",
                    files.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            })
            .collect();
        assert!(
            missing.is_empty(),
            "rusthound-ce {version} reads attributes the read does not ask for: {}. Add each to \
             PARSED, or to NOT_ASKED with the reason",
            missing.join("; ")
        );
        // An exclusion no longer in the source goes.
        for (n, _) in NOT_ASKED {
            assert!(
                names.contains_key(*n),
                "{n} is no longer in rusthound-ce {version}: remove it from NOT_ASKED"
            );
        }
    }

    #[test]
    fn the_scan_reads_arms_and_lookups() {
        assert_eq!(names_in(r#"                "name" => {"#), ["name"]);
        assert_eq!(
            names_in(r#"  "msDS-AllowedToDelegateTo"  => {"#),
            ["msDS-AllowedToDelegateTo"]
        );
        assert_eq!(names_in(r#" "a" | "b" => x,"#), ["a", "b"]);
        assert_eq!(
            names_in(r#"if let Some(c) = result_attrs.get("objectClass") {"#),
            ["objectClass"]
        );
        assert_eq!(
            names_in(r#"&result_attrs["name"][0].yellow(), &result_attrs["ms-Mcs-AdmPwd"][0]"#),
            ["name", "ms-Mcs-AdmPwd"]
        );
        assert!(names_in(r#"// "member" => {"#).is_empty());
        assert!(
            names_in(r#"    //    //if result_attrs["operatingSystem"].len() > 0 {"#).is_empty()
        );
        assert!(names_in(r#"let s = "x".to_string(); // => no"#).is_empty());
        assert_eq!(names_in(r#"    | "c" => {"#), ["c"]);
        assert!(names_in(r#" "a" if x => {"#).is_empty());
    }

    #[test]
    fn the_scan_reads_match_key_blocks_and_flags_what_it_cannot() {
        let text = r#"
        for (key, value) in &attrs {
            match key.as_str() {
                "name" => {
                    let x = match y {
                        Q => 1,
                    };
                }
                "a"
                | "b" => f(
                    1,
                ),
                // "commented" => {}
                NAME_CONST => {}
                "guarded" if value.is_empty() => {}
                "c" | "d" => {}
                _ => {}
            }
        }
        match other {
            CONST => 1,
        }
        "#;
        let (names, odd) = key_match_arms(text);
        assert_eq!(names, ["name", "a", "b", "c", "d"]);
        assert_eq!(odd.len(), 2, "{odd:?}");
        assert!(
            odd[0].contains("NAME_CONST") && odd[1].contains("guarded"),
            "{odd:?}"
        );
        assert!(opens_key_match("match key.as_str() {"));
        assert!(opens_key_match("match &key[..] {"));
        assert!(!opens_key_match("match keys.len() {"));
        assert!(!opens_key_match("match range_high(&key) {"));
    }

    #[test]
    fn the_list_has_no_duplicates_and_no_laps_values() {
        let mut seen = BTreeSet::new();
        for a in PARSED {
            assert!(seen.insert(a.to_ascii_lowercase()), "{a} twice");
            assert!(!a.contains('*'), "{a}");
        }
        for (n, why) in NOT_ASKED {
            assert!(!PARSED.contains(n), "{n} is asked for");
            assert!(!why.is_empty());
        }
        for laps in [
            "ms-Mcs-AdmPwd",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
        ] {
            assert!(!PARSED.iter().any(|a| a.eq_ignore_ascii_case(laps)));
        }
        assert_eq!(asked(true), ALL);
        assert_eq!(asked(false), PARSED);
    }
}
