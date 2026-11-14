//! Posture numbers for `testdata/forest` (see forest.rs for its layout).

use std::path::PathBuf;

use pathwarden_core::findings::{self, Context, RuleSettings};
use pathwarden_core::{load, posture, LoadOptions};

/// 2026-10-08.
const NOW: i64 = 1_791_417_600;

#[test]
fn forest_posture() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(&Context::new(&g, &stats.trusts, &settings), &[]);
    let p = posture::compute(&g, &all, &[], &settings);

    // JDOE, SVC_SQL, SVC_SYNC, CAROL, SRV01, APP01 reach Tier Zero; BOB and WS01 do not.
    assert_eq!((p.tier_zero.exposed, p.tier_zero.population), (6, 8));
    // Findings lead to DA_ALICE, CONTOSO.LOCAL and CHILD_DA.
    assert_eq!(p.tier_zero.objects_with_findings, 3);
    let score = p.tier_zero.protection_score.unwrap();
    let expected = 100.0 * (p.tier_zero.objects - 3) as f64 / p.tier_zero.objects as f64;
    assert!((score - expected).abs() < 1e-9);
    // Said as objects and a share.
    let words = posture::protected_words(p.tier_zero.objects, 3);
    assert_eq!(
        words,
        format!(
            "{} of {} objects ({})",
            p.tier_zero.objects - 3,
            p.tier_zero.objects,
            posture::share_percent(expected)
        )
    );

    // PW-023: BOB can RDP to DC01, which is hygiene and adds no exposure.
    assert_eq!((p.findings.attack_path, p.findings.hygiene), (5, 10));
    assert_eq!(p.findings.suppressed, 0);

    // No logon times in the fixture: every enabled computer counts. APP01
    // reports no local group collection. DC01 counts for sessions, not for
    // local groups.
    let c = &p.completeness;
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].domain, "CONTOSO.LOCAL");
    assert!(!c[0].active_only);
    assert_eq!(
        (
            c[0].sessions_collected,
            c[0].computers,
            c[0].local_groups_collected,
            c[0].member_computers
        ),
        (4, 4, 2, 3)
    );
    assert!(c[0].is_low(), "local groups 2/3");
}

/// Completeness for the forest fixture, its computers file changed by `edit`.
fn completeness_with(
    tag: &str,
    edit: impl Fn(&mut Vec<serde_json::Value>),
) -> posture::Completeness {
    completeness_methods(tag, 0, edit)
}

/// [`completeness_with`], the computers file saying SharpHound collection
/// methods `methods` (0: RustHound-CE and the built-in collector say none).
fn completeness_methods(
    tag: &str,
    methods: u64,
    edit: impl Fn(&mut Vec<serde_json::Value>),
) -> posture::Completeness {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let dir = std::env::temp_dir().join(format!("pathwarden-compl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
        if doc["meta"]["type"] == "computers" {
            doc["meta"]["methods"] = methods.into();
            let data = doc["data"].as_array_mut().unwrap();
            edit(data);
            let n = data.len();
            doc["meta"]["count"] = n.into();
        }
        std::fs::write(
            dir.join(path.file_name().unwrap()),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
    }
    let (g, _) = load(&[&dir], &LoadOptions::default()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    let mut c = posture::completeness(&g, NOW);
    assert_eq!(c.len(), 1);
    c.remove(0)
}

fn name(c: &serde_json::Value) -> &str {
    c["Properties"]["name"].as_str().unwrap()
}

#[test]
fn domain_controllers_are_left_out_of_local_groups() {
    // The GOAD essos case: the DC's local groups not read (they are the
    // domain's BUILTIN groups), every member computer read.
    let c = completeness_with("members", |data| {
        let read = data
            .iter()
            .find(|c| name(c) == "SRV01.CONTOSO.LOCAL")
            .unwrap()["LocalGroups"]
            .clone();
        for c in data.iter_mut() {
            if name(c) == "DC01.CONTOSO.LOCAL" {
                c["LocalGroups"] = serde_json::json!([]);
            } else {
                c["LocalGroups"] = read.clone();
            }
        }
    });
    assert_eq!((c.sessions_collected, c.computers), (4, 4));
    assert_eq!((c.local_groups_collected, c.member_computers), (3, 3));
    assert_eq!(c.local_groups_percent, 100.0);
    assert!(c.local_groups_apply());
    assert!(!c.is_low());
}

#[test]
fn domain_with_only_domain_controllers_has_no_local_groups_basis() {
    // The GOAD sevenkingdoms case: one DC, its local groups not read.
    let c = completeness_with("dconly", |data| {
        data.retain(|c| name(c) == "DC01.CONTOSO.LOCAL");
        data[0]["LocalGroups"] = serde_json::json!([]);
    });
    assert_eq!((c.sessions_collected, c.computers), (1, 1));
    assert_eq!((c.member_computers, c.enabled_member_computers), (0, 0));
    assert!(!c.local_groups_apply());
    assert_eq!(c.local_groups_na(), Some("domain controllers only"));
    assert!(!c.is_low(), "nothing to read is not incomplete");

    // The JSON keeps its fields and adds member_computers.
    let json = serde_json::to_value(&c).unwrap();
    for field in [
        "domain",
        "computers",
        "member_computers",
        "active_only",
        "sessions_collected",
        "local_groups_collected",
        "sessions_percent",
        "local_groups_percent",
    ] {
        assert!(json.get(field).is_some(), "{field}");
    }
}

/// Every computer's session lists left as a collection that never asked
/// for them leaves them: not collected, with `reason` (the built-in Quick
/// collection's, or none as RustHound-CE writes it), and no local groups.
fn not_asked(data: &mut [serde_json::Value], reason: Option<&str>) {
    for c in data {
        for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
            c[k] = serde_json::json!({"Results": [], "Collected": false, "FailureReason": reason});
        }
        c["LocalGroups"] = serde_json::json!([]);
        c.as_object_mut().unwrap().remove("LocalAdmins");
    }
}

#[test]
fn a_quick_collection_is_not_targeted_not_short() {
    // The built-in Quick (DC only) collection.
    let c = completeness_with("quick", |data| {
        not_asked(data, Some(pathwarden_core::ingest::NOT_CONTACTED))
    });
    assert!(!c.sessions_targeted && !c.local_groups_targeted, "{c:?}");
    assert_eq!(c.sessions_collected, 0);
    assert!(!c.is_low(), "nothing was asked, so nothing is short");
    let u = posture::Untargeted::of(&c);
    assert!(u.sessions && u.local_groups);
    assert_eq!(u.words(), Some("sessions and local groups"));
    assert_eq!(
        u.posture_line().unwrap(),
        "Not targeted: this collection read the directory only, so paths through logged-on \
         sessions and local administrator rights are not in this run."
    );
    assert_eq!(
        u.summary_note().unwrap(),
        "Note: Sessions and local groups were not targeted in this collection. Paths through \
         logged-on sessions and local administrator rights are not in this run."
    );
    // The JSON adds the two fields, and an older posture without them
    // reads as targeted.
    let mut json = serde_json::to_value(&c).unwrap();
    assert_eq!(json["sessions_targeted"], false);
    assert_eq!(json["local_groups_targeted"], false);
    let o = json.as_object_mut().unwrap();
    o.remove("sessions_targeted");
    o.remove("local_groups_targeted");
    let old: posture::Completeness = serde_json::from_value(json).unwrap();
    assert!(old.sessions_targeted && old.local_groups_targeted);
    assert!(old.is_low());

    // RustHound-CE run on its own with DCOnly (2.5.26 and later): lists
    // not collected, no reason.
    let c = completeness_with("rh-dconly", |data| not_asked(data, None));
    assert!(!c.sessions_targeted && !c.local_groups_targeted);
    assert!(!c.is_low());
}

#[test]
fn a_full_collection_that_reached_nobody_is_short() {
    // Asked, refused: every list says why. Still 0% and a warning.
    let c = completeness_with("unreached", |data| {
        not_asked(data, Some("not collected: port 445 closed"))
    });
    assert!(c.sessions_targeted && c.local_groups_targeted, "{c:?}");
    assert_eq!(c.sessions_collected, 0);
    assert!(c.is_low());
    assert!(!posture::Untargeted::of(&c).any());
    // One list reached on one computer is enough to count as asked.
    let c = completeness_with("one-reached", |data| {
        not_asked(data, None);
        data[1]["Sessions"]["Collected"] = true.into();
    });
    assert!(c.sessions_targeted && c.local_groups_targeted);
    assert!(c.is_low());
}

/// Computers the built-in collector skipped (no Kerberos name, replies
/// not signed) count as not collected, and one line says how many and why.
#[test]
fn skipped_computers_are_counted_with_their_reason() {
    use pathwarden_core::ingest::{SKIP_NO_KERBEROS_NAME, SKIP_UNSIGNED};
    let c = completeness_with("skipped", |data| {
        for (i, c) in data.iter_mut().enumerate() {
            let host = name(c).to_string();
            let why = match i {
                1 => format!("{host}: skipped: {SKIP_NO_KERBEROS_NAME} (no SPN cifs/{host})"),
                2 => format!(
                    "{host}: skipped: {SKIP_UNSIGNED} (SMB2 TREE_CONNECT answered without a \
                     valid signature)"
                ),
                _ => continue,
            };
            for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                c[k] = serde_json::json!({"Results": [], "Collected": false, "FailureReason": why});
            }
        }
    });
    assert_eq!((c.skipped_no_kerberos, c.skipped_unsigned), (1, 1), "{c:?}");
    assert_eq!(c.sessions_collected, c.computers - 2);
    assert_eq!(
        c.skipped_words().unwrap(),
        "2 computers were skipped and count as not collected: 1 has no Kerberos name, 1 didn't \
         sign its replies."
    );
    // Nothing skipped: no line, and the JSON keeps no new fields.
    let none = completeness_with("not-skipped", |_| {});
    assert_eq!(none.skipped_words(), None);
    let json = serde_json::to_value(&none).unwrap();
    assert!(json.get("skipped_no_kerberos").is_none());
}

#[test]
fn skipped_words_for_one_and_many() {
    let base = || {
        let mut c = completeness_with("words", |_| {});
        c.skipped_no_kerberos = 0;
        c.skipped_unsigned = 0;
        c
    };
    let mut c = base();
    c.skipped_no_kerberos = 1;
    assert_eq!(
        c.skipped_words().unwrap(),
        "1 computer was skipped and counts as not collected: it has no Kerberos name."
    );
    let mut c = base();
    c.skipped_no_kerberos = 14;
    c.skipped_unsigned = 2;
    assert_eq!(
        c.skipped_words().unwrap(),
        "16 computers were skipped and count as not collected: 14 have no Kerberos name, 2 \
         didn't sign their replies."
    );
    // Skipped computers that weren't active aren't in the percentages,
    // but the line still names them, as the collection's warning does.
    c.skipped_not_counted = 1;
    assert_eq!(
        c.skipped_words().unwrap(),
        "16 computers were skipped: 14 have no Kerberos name, 2 didn't sign their replies. 15 \
         count as not collected; the other one isn't active, so it isn't in the numbers above."
    );
    c.skipped_not_counted = 3;
    assert_eq!(
        c.skipped_words().unwrap(),
        "16 computers were skipped: 14 have no Kerberos name, 2 didn't sign their replies. 13 \
         count as not collected; the other 3 aren't active, so they aren't in the numbers above."
    );
    let mut c = base();
    c.skipped_bad_reply = 2;
    assert_eq!(
        c.skipped_words().unwrap(),
        "2 computers were skipped and count as not collected: 2 answered with replies to other \
         requests."
    );
    c.skipped_bad_reply = 1;
    assert_eq!(
        c.skipped_words().unwrap(),
        "1 computer was skipped and counts as not collected: its replies didn't answer \
         Pathwarden's requests."
    );
    let mut c = base();
    c.skipped_rc4_trust = 1;
    assert_eq!(
        c.skipped_words().unwrap(),
        "1 computer was skipped and counts as not collected: the trust to its domain allows \
         only RC4."
    );
    c.skipped_no_kerberos = 2;
    assert_eq!(
        c.skipped_words().unwrap(),
        "3 computers were skipped and count as not collected: 2 have no Kerberos name, 1 is \
         behind a trust that allows only RC4."
    );
    let mut c = base();
    c.skipped_no_kerberos = 1;
    c.skipped_not_counted = 1;
    assert_eq!(
        c.skipped_words().unwrap(),
        "1 computer was skipped: it has no Kerberos name. It isn't active, so it isn't in the \
         numbers above."
    );
}

/// An enabled computer that was skipped but never logged on (the lab's
/// ADIDNS look-alike): the line names it, the percentages leave it out.
#[test]
fn a_skipped_inactive_computer_is_named_not_counted() {
    use pathwarden_core::ingest::SKIP_NO_KERBEROS_NAME;
    let c = completeness_with("skipped-inactive", |data| {
        for c in data.iter_mut() {
            c["Properties"]["lastlogontimestamp"] = (NOW - 86_400).into();
        }
        let mut rogue = data[1].clone();
        rogue["ObjectIdentifier"] = "S-1-5-21-1000-1000-1000-4999".into();
        rogue["Properties"]["name"] = "PWROGUE.CONTOSO.LOCAL".into();
        rogue["Properties"]["lastlogontimestamp"] = (-1).into();
        let why = format!("PWROGUE.CONTOSO.LOCAL: skipped: {SKIP_NO_KERBEROS_NAME} (no SPN)");
        for k in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
            rogue[k] = serde_json::json!({"Results": [], "Collected": false, "FailureReason": why});
        }
        data.push(rogue);
    });
    assert!(c.active_only, "{c:?}");
    assert_eq!(c.skipped_no_kerberos, 1, "{c:?}");
    assert_eq!(c.skipped_not_counted, 1);
    assert!(c
        .skipped_words()
        .unwrap()
        .contains("isn't in the numbers above"));
}

#[test]
fn sharphound_methods_say_what_was_targeted() {
    // DCOnly: Group, GPOLocalGroup, Trusts, ACL, Container, ObjectProps.
    let dc_only = 1 | 1 << 2 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 9;
    let c = completeness_methods("sh-dconly", dc_only, |data| not_asked(data, None));
    assert!(!c.sessions_targeted && !c.local_groups_targeted, "{c:?}");
    assert!(!c.is_low());
    // Session (and LoggedOn, the loops): sessions only.
    for bit in [3, 4, 10, 11] {
        let c = completeness_methods("sh-session", dc_only | 1 << bit, |data| {
            not_asked(data, None)
        });
        assert!(c.sessions_targeted && !c.local_groups_targeted, "bit {bit}");
        assert!(c.is_low(), "sessions asked and not read");
        let u = posture::Untargeted::of(&c);
        assert_eq!(u.chip().unwrap(), "local groups not targeted");
    }
    // LocalAdmin, RDP, DCOM or PSRemote: local groups only.
    for bit in [1, 8, 12, 14] {
        let c = completeness_methods("sh-lg", dc_only | 1 << bit, |_| {});
        assert!(!c.sessions_targeted && c.local_groups_targeted, "bit {bit}");
        assert_eq!(
            posture::Untargeted::of(&c).posture_line().unwrap(),
            "Not targeted: this collection did not read sessions, so paths through logged-on \
             sessions are not in this run."
        );
    }
    // Default: both, whatever the lists say.
    let default = dc_only | 1 << 1 | 1 << 3 | 1 << 8 | 1 << 12 | 1 << 14;
    let c = completeness_methods("sh-default", default, |data| not_asked(data, None));
    assert!(c.sessions_targeted && c.local_groups_targeted);
    assert!(c.is_low());
}

#[test]
fn privilege_zones() {
    use pathwarden_core::config::Config;
    use pathwarden_core::remediation;
    use pathwarden_core::zones;

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let (g, stats) = load(&[dir], &LoadOptions::default()).unwrap();
    let config = Config::parse(
        r#"
        [[zone]]
        name = "App servers"
        members = ["SRV01.CONTOSO.LOCAL", "APP01.CONTOSO.LOCAL", "NOPE.CONTOSO.LOCAL"]

        [[zone]]
        name = "Helpdesk"
        groups = ["HELPDESK@CONTOSO.LOCAL"]

        [[zone]]
        name = "Workstations"
        ous = ["WORKSTATIONS@CONTOSO.LOCAL"]
        "#,
    )
    .unwrap();
    let zs = zones::resolve(&g, &config.zones);
    let names = |z: &zones::Zone| {
        let mut v: Vec<String> = z
            .members
            .iter()
            .map(|&ix| g.node(ix).name.clone())
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        names(&zs[0]),
        ["APP01.CONTOSO.LOCAL", "SRV01.CONTOSO.LOCAL"]
    );
    assert_eq!(zs[0].unresolved, ["member NOPE.CONTOSO.LOCAL"]);
    assert_eq!(
        names(&zs[1]),
        ["HELPDESK@CONTOSO.LOCAL", "JDOE@CONTOSO.LOCAL"]
    );
    assert_eq!(
        names(&zs[2]),
        [
            "WORKSTATION POLICY@CONTOSO.LOCAL",
            "WORKSTATIONS@CONTOSO.LOCAL",
            "WS01.CONTOSO.LOCAL"
        ]
    );

    let settings = RuleSettings {
        now: NOW,
        ..RuleSettings::default()
    };
    let all = findings::evaluate(
        &Context::new(&g, &stats.trusts, &settings).with_zones(&zs),
        &[],
    );
    let pw022: Vec<&str> = all
        .iter()
        .filter(|f| f.rule == "PW-022")
        .map(|f| f.title.as_str())
        .collect();
    assert!(pw022
        .contains(&"SVC_SQL@CONTOSO.LOCAL has AdminTo on SRV01.CONTOSO.LOCAL (zone App servers)"));
    // Authenticated Users can edit the GPO linked to the Workstations OU.
    assert!(pw022.contains(
        &"AUTHENTICATED USERS@CONTOSO.LOCAL has GenericWrite on WORKSTATION POLICY@CONTOSO.LOCAL (zone Workstations)"
    ), "{pw022:?}");

    let p = posture::compute(&g, &all, &zs, &settings);
    let app = &p.zones[0];
    // Outside the zone: JDOE, SVC_SQL, BOB, SVC_SYNC, CAROL, WS01. JDOE and SVC_SQL
    // reach SRV01; SVC_SYNC and CAROL reach Tier Zero, which controls the zone.
    assert_eq!((app.exposed, app.population), (4, 6));
    assert_eq!(app.objects_with_findings, 1, "SRV01");

    let plan = remediation::plan_to(
        &g,
        &zs[0].targets(&g),
        &pathwarden_core::analysis::Relevance::from_settings(&g, &settings),
    );
    assert_eq!(plan.exposed_after, 0);
    assert_eq!(plan.exposed_before, 4);
}

#[test]
fn member_computers_that_are_not_active_are_not_domain_controllers_only() {
    // A lab whose member servers have been off for weeks: only the DC is
    // active, so local groups have no basis, but the domain has members.
    let c = completeness_with("inactive", |data| {
        for c in data.iter_mut() {
            let days = if name(c) == "DC01.CONTOSO.LOCAL" {
                1
            } else {
                30
            };
            c["Properties"]["lastlogontimestamp"] = (NOW - days * 86_400).into();
        }
    });
    assert!(c.active_only);
    assert_eq!((c.computers, c.member_computers), (1, 0));
    assert_eq!(c.enabled_member_computers, 3);
    assert_eq!(c.local_groups_na(), Some("no active member computers"));
    assert!(!c.is_low());
}

#[test]
fn read_only_domain_controllers_are_left_out_of_local_groups() {
    // SRV01 as a RODC: primary group Read-only Domain Controllers (RID 521),
    // not IsDC. Its local groups are not read.
    let c = completeness_with("rodc", |data| {
        for c in data.iter_mut() {
            if name(c) == "SRV01.CONTOSO.LOCAL" {
                c["PrimaryGroupSID"] = "S-1-5-21-1000-1000-1000-521".into();
                c["LocalGroups"] = serde_json::json!([]);
            }
        }
    });
    assert_eq!(c.computers, 4);
    // WS01 and APP01; APP01's local groups were not read.
    assert_eq!((c.local_groups_collected, c.member_computers), (1, 2));
    assert_eq!(c.enabled_member_computers, 2);
}

/// The protected share reads as objects and a percentage, never a score,
/// and "n/a" without objects.
#[test]
fn protected_share_in_words() {
    assert_eq!(posture::protected_words(59, 1), "58 of 59 objects (98.31%)");
    assert_eq!(posture::protected_words(1, 0), "1 of 1 object (100%)");
    assert_eq!(posture::protected_words(0, 0), "n/a");
    assert_eq!(posture::protected_count(1, 1), "1 of 1 object");
}
