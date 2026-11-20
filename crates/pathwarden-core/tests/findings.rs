//! Rules and remediation planning against `testdata/forest` (see forest.rs for
//! the planted paths) and `testdata/broad`, where Domain Users is nested into
//! the builtin Administrators group.

use std::collections::BTreeMap;
use std::path::PathBuf;

use pathwarden_core::config::Config;
use pathwarden_core::findings::{self, Category, Context, Finding, RuleSettings, Severity};
use pathwarden_core::model::EdgeKind;
use pathwarden_core::remediation;
use pathwarden_core::{load, AdGraph, IngestStats, LoadOptions};

/// 2026-10-08, so age-based rules are deterministic.
const NOW: i64 = 1_791_417_600;

fn load_dir(name: &str) -> (AdGraph, IngestStats) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    load(&[dir], &LoadOptions::default()).expect("fixture loads")
}

/// Rule logic with the rules' own severities.
fn run(g: &AdGraph, stats: &IngestStats) -> Vec<Finding> {
    run_with(g, stats, false)
}

fn run_with(g: &AdGraph, stats: &IngestStats, severity_from_exposure: bool) -> Vec<Finding> {
    let settings = RuleSettings {
        now: NOW,
        severity_from_exposure,
        ..RuleSettings::default()
    };
    findings::evaluate(&Context::new(g, &stats.trusts, &settings), &[])
}

fn by_rule(findings: &[Finding]) -> BTreeMap<&'static str, Vec<&Finding>> {
    let mut out: BTreeMap<&'static str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        out.entry(f.rule).or_default().push(f);
    }
    out
}

fn affected(f: &Finding) -> Vec<&str> {
    f.affected.iter().map(|a| a.name.as_str()).collect()
}

#[test]
fn forest_findings() {
    let (g, stats) = load_dir("forest");
    let all = run(&g, &stats);
    let rules = by_rule(&all);
    let one = |rule: &str| -> &Finding {
        let list = rules
            .get(rule)
            .unwrap_or_else(|| panic!("{rule} did not fire"));
        assert_eq!(
            list.len(),
            1,
            "{rule}: {:?}",
            list.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        list[0]
    };

    assert!(
        !rules.contains_key("PW-001"),
        "no broad group reaches Tier Zero here"
    );

    let f = one("PW-002");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(affected(f), ["SVC_SYNC@CONTOSO.LOCAL", "CONTOSO.LOCAL"]);

    let f = one("PW-003");
    assert_eq!(
        f.title,
        "CAROL@CHILD.CONTOSO.LOCAL has GenericAll on CHILD_DA@CHILD.CONTOSO.LOCAL"
    );
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.remediation.contains("inherited")
            && f.remediation.contains("TIER0 ADMINS@CHILD.CONTOSO.LOCAL"),
        "inherited ACEs point at the defining container: {}",
        f.remediation
    );

    let f = one("PW-004");
    assert_eq!(
        affected(f),
        ["DA_ALICE@CONTOSO.LOCAL", "SRV01.CONTOSO.LOCAL"]
    );

    let f = one("PW-005");
    assert_eq!(affected(f), ["APP01.CONTOSO.LOCAL", "CONTOSO.LOCAL"]);
    assert_eq!(
        f.path.as_ref().unwrap().steps[0].edge,
        EdgeKind::CoerceToTgt
    );

    let f = one("PW-006");
    assert_eq!(
        (affected(f), f.severity),
        (vec!["SVC_SQL@CONTOSO.LOCAL"], Severity::High)
    );
    assert!(f.path.is_some());

    let f = one("PW-007");
    assert_eq!(
        (affected(f), f.severity),
        (vec!["BOB@CONTOSO.LOCAL"], Severity::Medium)
    );

    // Protected Users membership exempts DA_ALICE; krbtgt is never listed.
    let pw008 = &rules["PW-008"];
    assert_eq!(pw008.len(), 2);
    let contoso = pw008
        .iter()
        .find(|f| f.domain.as_deref() == Some("CONTOSO.LOCAL"))
        .unwrap();
    assert_eq!(affected(contoso), ["ADMINISTRATOR@CONTOSO.LOCAL"]);

    assert_eq!(affected(one("PW-009")), ["ADMINISTRATOR@CONTOSO.LOCAL"]);
    assert_eq!(affected(one("PW-010")), ["ADMINISTRATOR@CONTOSO.LOCAL"]);

    let mut laps = affected(one("PW-011"));
    laps.sort_unstable();
    assert_eq!(
        laps,
        ["APP01.CONTOSO.LOCAL", "SRV01.CONTOSO.LOCAL"],
        "DCs are excluded"
    );

    assert_eq!(
        one("PW-012").title,
        "Trust CONTOSO.LOCAL → FABRIKAM.COM has SID filtering relaxed"
    );
    assert_eq!(affected(one("PW-013")), ["JDOE@CONTOSO.LOCAL"]);
    assert_eq!(affected(one("PW-014")), ["KRBTGT@CONTOSO.LOCAL"]);

    // Most severe first.
    assert!(all.windows(2).all(|w| w[0].severity >= w[1].severity));
}

#[test]
fn fingerprints_are_stable() {
    let (g, stats) = load_dir("forest");
    let first: Vec<String> = run(&g, &stats).into_iter().map(|f| f.fingerprint).collect();
    let second: Vec<String> = run(&g, &stats).into_iter().map(|f| f.fingerprint).collect();
    assert_eq!(first, second);
    let unique: std::collections::HashSet<_> = first.iter().collect();
    assert_eq!(unique.len(), first.len(), "fingerprints must be unique");
    // Pinned: changing this breaks de-duplication of tickets already filed.
    assert_eq!(
        findings::fingerprint(
            "PW-002",
            &["S-1-5-21-1000-1000-1000-1106", "S-1-5-21-1000-1000-1000"]
        ),
        "PW-002-1687c02cf56323ac"
    );
}

#[test]
fn disabled_rules_and_suppressions() {
    let (g, stats) = load_dir("forest");
    let config = Config::parse(
        r#"
        [rules]
        disabled = ["PW-011"]
        [[suppress]]
        fingerprint = "PW-002-1687c02cf56323ac"
        reason = "Entra Connect account, managed as Tier Zero"
        [[suppress]]
        rule = "PW-013"
        reason = "expired acceptance"
        expires = "2026-01-01"
        "#,
    )
    .unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..config.settings()
    };
    let mut all = findings::evaluate(
        &Context::new(&g, &stats.trusts, &settings),
        &config.rules.disabled,
    );
    config.apply_suppressions(&mut all, NOW);
    let rules = by_rule(&all);
    assert!(!rules.contains_key("PW-011"));
    assert_eq!(
        rules["PW-002"][0].suppressed.as_deref(),
        Some("Entra Connect account, managed as Tier Zero")
    );
    assert!(
        rules["PW-013"][0].suppressed.is_none(),
        "expired suppressions no longer apply"
    );
}

#[test]
fn forest_remediation_plan_removes_all_exposure() {
    let (g, _) = load_dir("forest");
    let plan = remediation::plan(&g, &pathwarden_core::analysis::Relevance::new(&g, NOW, 90));
    assert_eq!(plan.exposed_before, 6);
    assert_eq!(plan.exposed_after, 0);
    let mut fixes: Vec<(String, EdgeKind)> = plan
        .fixes
        .iter()
        .map(|f| (f.from.clone(), f.edges[0]))
        .collect();
    fixes.sort();
    assert_eq!(
        fixes,
        [
            ("APP01.CONTOSO.LOCAL".to_string(), EdgeKind::CoerceToTgt),
            (
                "CAROL@CHILD.CONTOSO.LOCAL".to_string(),
                EdgeKind::GenericAll
            ),
            ("SRV01.CONTOSO.LOCAL".to_string(), EdgeKind::HasSession),
            ("SVC_SYNC@CONTOSO.LOCAL".to_string(), EdgeKind::DcSync),
        ]
    );
    assert_eq!(plan.total_cost, 6);
}

#[test]
fn domain_users_nested_into_administrators() {
    let (g, stats) = load_dir("broad");
    let alice = g.find("ALICE")[0];
    assert!(
        !g.node(alice).tier_zero,
        "broad group nesting must not make everyone Tier Zero"
    );

    let all = run(&g, &stats);
    let f = all
        .iter()
        .find(|f| f.rule == "PW-001")
        .expect("PW-001 fires");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(affected(f), ["DOMAIN USERS@BROAD.LOCAL"]);
    // The fix covers every relationship to the first step's object.
    assert!(
        f.remediation.starts_with(
            "Break the path where it starts. Remove DOMAIN USERS@BROAD.LOCAL from the group "
        ),
        "{}",
        f.remediation
    );

    // Users cannot leave Domain Users, so the fix is the nesting itself.
    let plan = remediation::plan(&g, &pathwarden_core::analysis::Relevance::new(&g, NOW, 90));
    assert_eq!((plan.exposed_before, plan.exposed_after), (2, 0));
    assert_eq!(plan.fixes.len(), 1);
    assert_eq!(plan.fixes[0].from, "DOMAIN USERS@BROAD.LOCAL");
    assert_eq!(plan.fixes[0].edges[0], EdgeKind::MemberOf);
}

#[test]
fn exposure_drives_attack_path_severity() {
    let (g, stats) = load_dir("forest");
    let all = run_with(&g, &stats, true);
    let rule = |id: &str| all.iter().find(|f| f.rule == id).unwrap();

    // Population: the enabled non-Tier Zero users and computers of the
    // finding's own domain (the forest has 8; one is in the child domain).
    let dcsync = rule("PW-002");
    let e = dcsync.exposure.clone().unwrap();
    assert_eq!((e.principals, e.population), (1, 7), "only SVC_SYNC itself");
    assert_eq!(
        e.scope.as_deref(),
        dcsync
            .domain
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref()
    );
    // Low exposure, but DCSync is direct control of the domain: never below High.
    assert_eq!(dcsync.severity, Severity::High);
    assert_eq!(dcsync.rule_severity, Severity::Critical);

    // Anyone can request a service ticket.
    let roast = rule("PW-006");
    assert_eq!(roast.exposure.clone().unwrap().principals, 7);
    assert_eq!(roast.severity, Severity::Critical);

    // DA_ALICE's session on SRV01 is reachable from SRV01, SVC_SQL and JDOE.
    let session = rule("PW-004");
    assert_eq!(session.exposure.clone().unwrap().principals, 3);
    assert_eq!(session.category, Category::AttackPath);

    // BOB has no path anywhere: AS-REP roasting him is hygiene, rule severity.
    let asrep = rule("PW-007");
    assert_eq!(asrep.category, Category::Hygiene);
    assert!(asrep.exposure.is_none());
    assert_eq!(asrep.severity, Severity::Medium);

    assert_eq!(rule("PW-011").category, Category::Hygiene);
}

#[test]
fn remote_logon_to_a_dc_is_hygiene_not_a_path() {
    let (g, stats) = load_dir("forest");
    let all = run_with(&g, &stats, true);
    // BOB is in Remote Desktop Users on DC01: reported once, as hygiene...
    let rdp: Vec<&Finding> = all.iter().filter(|f| f.rule == "PW-023").collect();
    assert_eq!(rdp.len(), 1);
    assert_eq!(affected(rdp[0])[0], "BOB@CONTOSO.LOCAL");
    assert_eq!(rdp[0].category, Category::Hygiene);
    assert_eq!(rdp[0].severity, Severity::High);
    // ...and not as a path to Tier Zero or control of DC01.
    assert!(!all.iter().any(
        |f| matches!(f.rule, "PW-001" | "PW-003") && affected(f).contains(&"BOB@CONTOSO.LOCAL")
    ));
    let plan = remediation::plan(&g, &pathwarden_core::analysis::Relevance::new(&g, NOW, 90));
    assert!(plan
        .fixes
        .iter()
        .all(|f| !f.edges.contains(&EdgeKind::CanRdp)));
}

/// PW-006 skips managed service accounts, whose passwords are 240 random
/// bytes the domain rotates: a gMSA as SharpHound writes it (`gmsa`), an
/// sMSA as SharpHound writes it (`msa`) and a gMSA as RustHound-CE and the
/// built-in collector write it (no flag, userAccountControl 0x1000). Service
/// users with an SPN stay reported, whichever collector shape. All are put
/// in Domain Admins, so each would be a Critical finding. A second users
/// file repeats some accounts in the other collector's shape, as when a
/// SharpHound and a RustHound-CE collection of one domain are loaded
/// together: the merged records keep the flag.
#[test]
fn managed_service_accounts_are_not_kerberoastable() {
    use serde_json::{json, Value};
    let accounts: [(&str, &str, Value); 7] = [
        ("1301", "GMSA_WEB$", json!({ "gmsa": true })),
        ("1302", "SMSA_APP$", json!({ "msa": true })),
        ("1303", "GMSA_RH$", json!({ "useraccountcontrol": 4096 })),
        ("1304", "SVC_WEB", json!({ "gmsa": false, "msa": false })),
        ("1305", "SVC_RH", json!({ "useraccountcontrol": 66048 })),
        ("1306", "GMSA_MIX$", json!({ "gmsa": true })),
        ("1307", "GMSA_MIX2$", json!({ "useraccountcontrol": 4096 })),
    ];
    // The same objects in the other shape, in a file read after the first.
    let duplicates: [(&str, Value); 4] = [
        ("1306", json!({ "useraccountcontrol": 4096 })),
        ("1307", json!({ "gmsa": true })),
        ("1301", json!({ "useraccountcontrol": 4096 })),
        ("1304", json!({ "useraccountcontrol": 66048 })),
    ];
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let dir = std::env::temp_dir().join(format!("pw-pw006-msa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let data = doc["data"].as_array_mut().unwrap();
        for (rid, sam, extra) in &accounts {
            let sid = format!("S-1-5-21-1000-1000-1000-{rid}");
            if name.ends_with("_users.json") {
                let mut props = json!({
                    "name": format!("{sam}@CONTOSO.LOCAL"),
                    "domain": "CONTOSO.LOCAL",
                    "domainsid": "S-1-5-21-1000-1000-1000",
                    "enabled": true,
                    "hasspn": true,
                    "serviceprincipalnames": [format!("HTTP/{}", sam.trim_end_matches('$'))],
                });
                for (k, v) in extra.as_object().unwrap() {
                    props[k] = v.clone();
                }
                data.push(json!({
                    "ObjectIdentifier": sid, "Properties": props, "Aces": [], "IsDeleted": false
                }));
            } else if name.ends_with("_groups.json") {
                let da = data
                    .iter_mut()
                    .find(|o| o["ObjectIdentifier"] == "S-1-5-21-1000-1000-1000-512")
                    .unwrap();
                da["Members"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "ObjectIdentifier": sid, "ObjectType": "User" }));
            }
        }
        let count = data.len();
        if let Some(n) = doc["meta"].get_mut("count") {
            *n = json!(count);
        }
        std::fs::write(dir.join(&name), serde_json::to_vec(&doc).unwrap()).unwrap();
        if name.ends_with("_users.json") {
            let data: Vec<Value> = duplicates
                .iter()
                .map(|(rid, props)| {
                    let mut props = props.clone();
                    props["domain"] = json!("CONTOSO.LOCAL");
                    json!({
                        "ObjectIdentifier": format!("S-1-5-21-1000-1000-1000-{rid}"),
                        "Properties": props, "Aces": [], "IsDeleted": false
                    })
                })
                .collect();
            let mut extra = doc.clone();
            extra["data"] = json!(data);
            if let Some(n) = extra["meta"].get_mut("count") {
                *n = json!(duplicates.len());
            }
            std::fs::write(
                dir.join("zz_rusthound_users.json"),
                serde_json::to_vec(&extra).unwrap(),
            )
            .unwrap();
        }
    }
    let loaded = load(std::slice::from_ref(&dir), &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    let (g, stats) = loaded.expect("loads");
    let roastable: Vec<String> = run(&g, &stats)
        .iter()
        .filter(|f| f.rule == "PW-006")
        .flat_map(|f| f.affected.iter().map(|a| a.name.clone()))
        .collect();
    for (rid, sam, _) in &accounts {
        let name = format!("{sam}@CONTOSO.LOCAL");
        let managed = sam.ends_with('$');
        assert_eq!(roastable.contains(&name), !managed, "{name}: {roastable:?}");
        let ix = g.lookup(&format!("S-1-5-21-1000-1000-1000-{rid}")).unwrap();
        assert_eq!(
            g.node(ix).props.managedpassword == Some(true),
            managed,
            "{name}"
        );
    }
    assert!(roastable.contains(&"SVC_SQL@CONTOSO.LOCAL".to_string()));
}

/// PW-011 skips standalone managed service accounts, which are typed as
/// computers but have no interactive local administrator, so LAPS doesn't
/// apply. It recognises them from SharpHound's `msa` flag, and in RustHound-CE
/// or built-in collections (no flag) from the Managed Service Accounts
/// container; a real computer without LAPS is still reported. All have
/// `haslaps` false, so without the exclusion each would be a finding.
#[test]
fn standalone_msas_are_not_reported_as_missing_laps() {
    use serde_json::{json, Value};
    // (RID, name, distinguishedName, collector-specific props, whether an sMSA).
    let computers: [(&str, &str, &str, Value, bool); 3] = [
        // RustHound-CE / built-in: an sMSA typed as a computer, no `msa`
        // flag, in the Managed Service Accounts container, UAC 0x1000.
        (
            "1401",
            "SMSA_RH$@CONTOSO.LOCAL",
            "CN=SMSA_RH,CN=MANAGED SERVICE ACCOUNTS,DC=CONTOSO,DC=LOCAL",
            json!({ "useraccountcontrol": 4096 }),
            true,
        ),
        // SharpHound: an sMSA with the `msa` flag (its DN is elsewhere, so
        // only the flag marks it).
        (
            "1402",
            "SMSA_SH$@CONTOSO.LOCAL",
            "CN=SMSA_SH,OU=SERVERS,DC=CONTOSO,DC=LOCAL",
            json!({ "msa": true }),
            true,
        ),
        // A real computer without LAPS, not in the container and no flag:
        // still reported.
        (
            "1403",
            "NOLAPS01.CONTOSO.LOCAL",
            "CN=NOLAPS01,OU=SERVERS,DC=CONTOSO,DC=LOCAL",
            json!({ "useraccountcontrol": 4096 }),
            false,
        ),
    ];
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let dir = std::env::temp_dir().join(format!("pw-pw011-smsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if name.ends_with("_computers.json") {
            let data = doc["data"].as_array_mut().unwrap();
            for (rid, cn, dn, extra, _) in &computers {
                let mut props = json!({
                    "name": cn,
                    "domain": "CONTOSO.LOCAL",
                    "domainsid": "S-1-5-21-1000-1000-1000",
                    "distinguishedname": dn,
                    "enabled": true,
                    "haslaps": false,
                });
                for (k, v) in extra.as_object().unwrap() {
                    props[k] = v.clone();
                }
                data.push(json!({
                    "ObjectIdentifier": format!("S-1-5-21-1000-1000-1000-{rid}"),
                    "Properties": props, "Aces": [], "IsDeleted": false
                }));
            }
            let count = data.len();
            if let Some(n) = doc["meta"].get_mut("count") {
                *n = json!(count);
            }
        }
        std::fs::write(dir.join(&name), serde_json::to_vec(&doc).unwrap()).unwrap();
    }
    let loaded = load(std::slice::from_ref(&dir), &LoadOptions::default());
    let _ = std::fs::remove_dir_all(&dir);
    let (g, stats) = loaded.expect("loads");
    let flagged: Vec<String> = run(&g, &stats)
        .iter()
        .filter(|f| f.rule == "PW-011")
        .flat_map(|f| f.affected.iter().map(|a| a.name.clone()))
        .collect();
    for (rid, cn, _, _, is_msa) in &computers {
        let ix = g.lookup(&format!("S-1-5-21-1000-1000-1000-{rid}")).unwrap();
        assert_eq!(g.node(ix).kind, pathwarden_core::model::NodeKind::Computer);
        assert_eq!(
            g.node(ix).props.managedpassword == Some(true),
            *is_msa,
            "{cn}"
        );
        // An sMSA must not be reported; the real computer must be.
        assert_eq!(
            flagged.contains(&cn.to_string()),
            !is_msa,
            "{cn}: {flagged:?}"
        );
    }
}

/// The rules the findings state doesn't date objects for
/// ([`findings::KEYED_RULES`]) list only what their fingerprint is made of,
/// in every fixture: their objects can't change under one fingerprint.
#[test]
fn keyed_rules_list_only_their_key() {
    use pathwarden_core::zones;
    let config = Config::parse(
        r#"
        [[zone]]
        name = "App servers"
        members = ["SRV01.CONTOSO.LOCAL", "APP01.CONTOSO.LOCAL"]

        [[zone]]
        name = "Workstations"
        ous = ["WORKSTATIONS@CONTOSO.LOCAL"]
        "#,
    )
    .unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for name in ["forest", "broad", "adcs", "mgmt", "hostile"] {
        let (g, stats) = load_dir(name);
        let zs = zones::resolve(&g, &config.zones);
        let all = findings::evaluate(
            &Context::new(&g, &stats.trusts, &settings).with_zones(&zs),
            &[],
        );
        for f in all
            .iter()
            .filter(|f| findings::KEYED_RULES.contains(&f.rule))
        {
            assert!(f.objects_are_its_key(), "{name}: {} {}", f.rule, f.title);
            *seen.entry(f.rule).or_default() += 1;
        }
        // A rule that lists more than its key is dated.
        assert!(all
            .iter()
            .filter(|f| f.rule == "PW-004")
            .all(|f| !f.objects_are_its_key()));
    }
    assert!(
        seen.contains_key("PW-002") && seen.contains_key("PW-022"),
        "{seen:?}"
    );
}

/// PW-012 on a forest trust's `SidFilteringEnabled` flag alone says
/// it can't tell, as the Forest view does; where the trust attributes show
/// SID history enabled, or an external trust is not quarantined, it stays
/// firm.
#[test]
fn pw012_says_unknown_on_a_forest_trusts_flag_alone() {
    use pathwarden_core::forest::{COLLECT_TRUST_ATTRIBUTES, FOREST_FLAG_UNKNOWN};
    use pathwarden_core::ingest::TrustInfo;
    let trust = |kind: &str, attrs: Option<u64>| TrustInfo {
        source: "A.LOCAL".into(),
        target: "B.LOCAL".into(),
        trust_type: kind.into(),
        direction: "Bidirectional".into(),
        transitive: true,
        sid_filtering: false,
        selective_auth: attrs.map(|a| a & 0x10 != 0),
        source_sid: "S-1-5-21-1-1-1".into(),
        target_sid: "S-1-5-21-2-2-2".into(),
        trust_attributes: attrs,
    };
    let g = AdGraph::new();
    let settings = RuleSettings::default();
    let pw012 = |t: TrustInfo| {
        let trusts = [t];
        let mut all = findings::evaluate(&Context::new(&g, &trusts, &settings), &[]);
        assert_eq!(all.len(), 1, "PW-012 still fires");
        all.remove(0)
    };

    // SharpHound 2.3: a forest trust, no attributes.
    let f = pw012(trust("Forest", None));
    assert_eq!(f.rule, "PW-012");
    assert_eq!(f.severity, findings::PW012_FLAG_ONLY_SEVERITY);
    // The user's call; the impact is forest-wide and unknown.
    assert_eq!(findings::PW012_FLAG_ONLY_SEVERITY, Severity::High);
    assert_eq!(
        f.title,
        "Trust A.LOCAL → B.LOCAL: SID filtering unknown (the collected data doesn't say)"
    );
    // A.LOCAL's record of a two-way trust: A.LOCAL trusts B.LOCAL, so the
    // check and the fix are on A.LOCAL's side; the bit is tested, as
    // Get-ADTrust prints the attributes in decimal.
    assert!(
        f.remediation.contains(
            "on a domain controller of A.LOCAL run `(Get-ADTrust -Filter \"Target -eq 'B.LOCAL'\").TrustAttributes -band 0x40`"
        ),
        "{}",
        f.remediation
    );
    assert!(f
        .remediation
        .contains("`netdom trust A.LOCAL /domain:B.LOCAL /enablesidhistory:no`"));
    assert!(f
        .summary
        .contains("compromises B.LOCAL can forge SID history A.LOCAL accepts"));
    assert!(!f.summary.contains("to know."), "{}", f.summary);
    assert!(f.summary.contains(FOREST_FLAG_UNKNOWN), "{}", f.summary);
    assert!(
        f.summary.contains("SID history may be forgeable"),
        "{}",
        f.summary
    );
    assert!(
        f.summary.contains(COLLECT_TRUST_ATTRIBUTES),
        "{}",
        f.summary
    );
    assert!(!f.summary.contains("does not filter SIDs"), "{}", f.summary);
    assert!(f.remediation.contains(COLLECT_TRUST_ATTRIBUTES));
    assert!(f.remediation.contains("/enablesidhistory:no"));
    // The same fingerprint as the firm finding, so suppressions carry over.
    assert_eq!(
        f.fingerprint,
        pw012(trust("Forest", Some(0x48))).fingerprint
    );

    // RustHound-CE: SID history enabled (TREAT_AS_EXTERNAL) is known.
    let f = pw012(trust("Forest", Some(0x48)));
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.title,
        "Trust A.LOCAL → B.LOCAL lets SID history through (SID filtering relaxed)"
    );
    // What MS-PAC 4.1.2.2 says passes: RIDs of 1000 and up, never the
    // privileged groups; it must not claim filtering is off.
    let firm = |f: &Finding| {
        assert!(!f.summary.contains("does not filter SIDs"), "{}", f.summary);
        assert!(!f.summary.contains("privileged access"), "{}", f.summary);
        assert!(
            f.summary
                .contains("filters only the built-in and privileged SIDs (RIDs under 1000)"),
            "{}",
            f.summary
        );
        assert!(
            f.summary.contains(
                "can forge SID history A.LOCAL accepts for its accounts and groups with RIDs of \
                 1000 and above, and gains what those hold directly or through domain-local groups"
            ),
            "{}",
            f.summary
        );
        assert!(
            f.summary
                .ends_with("Domain Admins and Enterprise Admins are still filtered."),
            "{}",
            f.summary
        );
    };
    firm(&f);

    // An external trust: the flag is quarantine itself, so it tells.
    for attrs in [None, Some(0)] {
        let f = pw012(trust("External", attrs));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Trust A.LOCAL → B.LOCAL has SID filtering relaxed");
        firm(&f);
        assert!(f.remediation.contains("/quarantine:yes"));
    }

    // An inbound record: B.LOCAL trusts A.LOCAL, so the trusting side, its
    // DC and the netdom line are B.LOCAL's. The title and fingerprint stay
    // the record's own.
    let inbound = |kind: &str, attrs: Option<u64>| TrustInfo {
        direction: "Inbound".into(),
        ..trust(kind, attrs)
    };
    let f = pw012(inbound("Forest", None));
    assert_eq!(f.severity, findings::PW012_FLAG_ONLY_SEVERITY);
    assert!(
        f.title.starts_with("Trust A.LOCAL → B.LOCAL: "),
        "{}",
        f.title
    );
    assert!(
        f.remediation.contains(
            "on a domain controller of B.LOCAL run `(Get-ADTrust -Filter \"Target -eq 'A.LOCAL'\").TrustAttributes -band 0x40`"
        ),
        "{}",
        f.remediation
    );
    assert!(f
        .remediation
        .contains("`netdom trust B.LOCAL /domain:A.LOCAL /enablesidhistory:no`"));
    assert!(f
        .summary
        .contains("compromises A.LOCAL can forge SID history B.LOCAL accepts"));
    let f = pw012(inbound("Forest", Some(0x48)));
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.remediation
            .contains("`netdom trust B.LOCAL /domain:A.LOCAL /enablesidhistory:no`"),
        "{}",
        f.remediation
    );
    let f = pw012(inbound("External", None));
    assert!(
        f.remediation
            .contains("`netdom trust B.LOCAL /domain:A.LOCAL /quarantine:yes`"),
        "{}",
        f.remediation
    );
}

/// What each finding rests on of sessions and local groups (what a Quick
/// run can't tell fixed): reach-based rules both; PW-004 sessions; PW-023
/// local groups; the rest the edges of their sample path (an ACL, a
/// DCSync right or unconstrained delegation: nothing).
#[test]
fn findings_say_what_they_rest_on() {
    use pathwarden_core::posture::Untargeted;
    for dir in ["forest", "broad"] {
        let (g, stats) = load_dir(dir);
        for f in run(&g, &stats) {
            let path = f
                .path
                .iter()
                .flat_map(|p| p.steps.iter().map(|s| Untargeted::of_edge(s.edge)))
                .fold(Untargeted::default(), Untargeted::or);
            match f.rule {
                "PW-001" | "PW-006" | "PW-032" => {
                    assert_eq!(f.rests_on, Untargeted::BOTH, "{}", f.title)
                }
                "PW-004" => assert!(f.rests_on.sessions, "{}", f.title),
                "PW-023" => assert!(f.rests_on.local_groups, "{}", f.title),
                "PW-002" | "PW-005" => assert!(f.rests_on.none(), "{}", f.title),
                // The rest: at least the edges of the sample path (and of
                // the evidence, which the API doesn't show).
                _ => assert_eq!(f.rests_on.or(path), f.rests_on, "{}", f.title),
            }
        }
    }
}

/// A name holding a line break (AD allows one in many names) is read on
/// one line: it can't add a line of its own ("Status: approved") to the
/// remediation that quotes it, nor to a ticket or export made from it.
#[test]
fn a_name_with_a_line_break_stays_on_one_line() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let dir = std::env::temp_dir().join(format!("pw-one-line-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let name = r#""name": "CAROL@CHILD.CONTOSO.LOCAL""#;
    for e in std::fs::read_dir(&src).unwrap().flatten() {
        let mut text = std::fs::read_to_string(e.path()).unwrap();
        if e.file_name() == "contoso_users.json" {
            assert!(text.contains(name));
            text = text.replace(
                name,
                r#""name": "CAROL@CHILD.CONTOSO.LOCAL\r\nStatus: approved\u2028Resolution: done""#,
            );
        }
        std::fs::write(dir.join(e.file_name()), text).unwrap();
    }
    let (g, stats) =
        load(std::slice::from_ref(&dir), &LoadOptions::default()).expect("fixture loads");
    let findings = run(&g, &stats);
    let quoting: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.remediation.to_uppercase().contains("STATUS: APPROVED"))
        .collect();
    assert!(!quoting.is_empty(), "CAROL is named in a remediation");
    for f in &findings {
        for text in [&f.remediation, &f.summary, &f.title] {
            let upper = text.to_uppercase();
            for bad in ["\nSTATUS", "\rSTATUS", "\u{2028}", "\nRESOLUTION"] {
                assert!(!upper.contains(bad), "{}: {text:?}", f.rule);
            }
        }
    }
    assert!(quoting.iter().any(|f| f
        .remediation
        .to_uppercase()
        .contains("CAROL@CHILD.CONTOSO.LOCAL  STATUS: APPROVED RESOLUTION")));
    let _ = std::fs::remove_dir_all(&dir);
}
