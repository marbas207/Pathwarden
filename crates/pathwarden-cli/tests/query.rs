//! `pathwarden query` path results: printed hop by hop as
//! `pathwarden path` prints them, the same in `--json`, owned objects, and
//! plain refusals and caps.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-query-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pathwarden"))
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("LOCALAPPDATA", dir.join("appdata"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_str(&ok(out)).unwrap()
}

const KERBEROASTABLE_TO_DA: &str = "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Group)) \
     WHERE s.hasspn = true AND s.enabled = true AND t.objectid ENDS WITH '-512' RETURN p LIMIT 1000";

#[test]
fn paths_print_as_pathwarden_path_prints_them() {
    let dir = scratch("paths");
    let out = json(&pw(
        &dir,
        &["query", KERBEROASTABLE_TO_DA, "-i", "demo:", "--json"],
    ));
    let rows = out["rows"].as_array().unwrap();
    let paths = out["paths"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert_eq!(rows.len(), paths.len());
    let text = ok(&pw(&dir, &["query", KERBEROASTABLE_TO_DA, "-i", "demo:"]));
    assert!(text.starts_with(&format!("{} path", paths.len())), "{text}");
    for (row, path) in rows.iter().zip(paths).take(3) {
        let cell = &row[0];
        assert_eq!(cell["entity"], "path");
        let nodes = cell["nodes"].as_array().unwrap();
        let (from, to) = (
            nodes[0].as_str().unwrap(),
            nodes[nodes.len() - 1].as_str().unwrap(),
        );
        assert_eq!(
            cell["relationships"].as_array().unwrap().len(),
            path["steps"].as_array().unwrap().len()
        );
        // The same path, the same JSON, as `pathwarden path`.
        let want = json(&pw(
            &dir,
            &["path", "--from", from, "--to", to, "-i", "demo:", "--json"],
        ));
        assert_eq!(path["steps"], want["steps"], "{from} -> {to}");
        assert_eq!(path["source"], want["source"]);
        assert_eq!(path["target"], want["target"]);
        // And the same lines.
        let lines = ok(&pw(
            &dir,
            &["path", "--from", from, "--to", to, "-i", "demo:"],
        ));
        assert!(text.contains(&lines), "{lines}");
    }
}

#[test]
fn owned_objects_and_what_no_path_says() {
    let dir = scratch("owned");
    let q = "MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p LIMIT 1000";
    // Nothing marked: a note, and no paths.
    let out = pw(&dir, &["query", q, "-i", "demo:"]);
    assert_eq!(ok(&out).trim(), "0 paths");
    assert!(String::from_utf8_lossy(&out.stderr).contains("No object is marked as owned"));
    // A service account that is a Domain Admin.
    let first = json(&pw(
        &dir,
        &["query", KERBEROASTABLE_TO_DA, "-i", "demo:", "--json"],
    ));
    let owned = first["rows"][0][0]["nodes"][0]
        .as_str()
        .unwrap()
        .to_string();
    let out = json(&pw(
        &dir,
        &["query", q, "--owned", &owned, "-i", "demo:", "--json"],
    ));
    let paths = out["paths"].as_array().unwrap();
    assert!(!paths.is_empty());
    assert!(out["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r[0]["nodes"][0] == owned.as_str()));
    // An object that isn't there is an error, not an empty answer.
    let out = pw(
        &dir,
        &["query", q, "--owned", "NO SUCH OBJECT", "-i", "demo:"],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("No object matches"));
}

/// `<-` paths print turned around, running with their relationships, as
/// `pathwarden path` would; undirected ones print as matched, a step
/// against its relationship drawn `<-[...]-` and marked in `--json`.
#[test]
fn left_and_undirected_paths_print_their_direction() {
    let dir = scratch("direction");
    let left = "MATCH p=(g:Group)<-[:MemberOf*1..]-(u:User) WHERE g.name = 'DOMAIN ADMINS@SCALE.LOCAL' RETURN p LIMIT 5";
    let text = ok(&pw(&dir, &["query", left, "-i", "demo:"]));
    assert!(text.starts_with("5 paths"), "{text}");
    assert!(
        text.contains("-[MemberOf]-> DOMAIN ADMINS@SCALE.LOCAL (Group)"),
        "{text}"
    );
    assert!(!text.contains("<-["), "{text}");
    let out = json(&pw(&dir, &["query", left, "-i", "demo:", "--json"]));
    for p in out["paths"].as_array().unwrap() {
        assert_eq!(p["target"], "DOMAIN ADMINS@SCALE.LOCAL");
        assert!(p["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.get("backward").is_none()));
    }
    let undirected = "MATCH p=(g:Group)-[:MemberOf*1..2]-(u:User) WHERE g.name = 'DOMAIN ADMINS@SCALE.LOCAL' RETURN p LIMIT 5";
    let text = ok(&pw(&dir, &["query", undirected, "-i", "demo:"]));
    assert!(text.contains("<-[MemberOf]-"), "{text}");
    let out = json(&pw(&dir, &["query", undirected, "-i", "demo:", "--json"]));
    for p in out["paths"].as_array().unwrap() {
        assert_eq!(p["source"], "DOMAIN ADMINS@SCALE.LOCAL");
        // It ends at a member: the last step runs against MemberOf.
        let steps = p["steps"].as_array().unwrap();
        assert_eq!(steps[steps.len() - 1]["backward"], true);
    }
}

#[test]
fn hop_limits_and_ambiguous_owned_objects_are_refused() {
    let dir = scratch("limits");
    for (q, want) in [
        (
            "MATCH p=(a:User)-[:MemberOf*..30]->(b) RETURN p",
            "follows at most 25 relationships, not 30",
        ),
        (
            "MATCH p=(a:User)-[:MemberOf*100000..]-(b) RETURN p",
            "follows at most 25 relationships, not 100000",
        ),
        (
            "MATCH p=(a:User)-[:MemberOf*..25]->(b)-[:MemberOf*..25]->(c)-[:AdminTo]->(d) RETURN p",
            "at most 50 relationships in all, not 51",
        ),
    ] {
        let out = pw(&dir, &["query", q, "-i", "demo:"]);
        assert!(!out.status.success(), "{q}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(want), "{q}: {err}");
    }
    let forest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/forest");
    let out = pw(
        &dir,
        &[
            "query",
            "MATCH (n:Tag_Owned) RETURN n",
            "--owned",
            "ADMINISTRATOR",
            "-i",
            forest.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("'ADMINISTRATOR' is ambiguous"), "{err}");
}

#[test]
fn refusals_and_caps_are_plain() {
    let dir = scratch("refusals");
    let broad = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/broad");
    let broad = broad.to_str().unwrap();
    let out = pw(
        &dir,
        &["query", "MATCH (n:User) WITH n RETURN n", "-i", broad],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("query not supported: WITH is not supported yet"),
        "{err}"
    );
    let out = ok(&pw(
        &dir,
        &[
            "query",
            "MATCH p=(n:User)-[:AD_ATTACK_PATHS*]->(m) RETURN p",
            "-i",
            "demo:",
            "--limit",
            "10",
        ],
    ));
    assert!(
        out.contains("Stopped at the 10-row cap: there are more rows."),
        "{out}"
    );
    assert!(out.trim_end().ends_with("Raise --limit for more."), "{out}");
    let out = ok(&pw(
        &dir,
        &["query", "MATCH (n:Group) RETURN n", "-i", broad],
    ));
    assert!(!out.contains("Stopped"), "{out}");
}

/// A saved run answers as the collector data does (the app's Query tab),
/// and `pathwarden owned` keeps the marks its queries see as Tag_Owned.
#[test]
fn a_saved_run_and_kept_owned_marks() {
    let dir = scratch("saved");
    let ws = dir.join("ws");
    let ws = ws.to_str().unwrap();
    ok(&pw(
        &dir,
        &["run", "--save", "--workspace", ws, "-i", "demo:"],
    ));
    let at = ["--env", "SCALE.LOCAL", "--workspace", ws];
    let with = |args: &[&str]| -> Vec<String> {
        args.iter()
            .chain(at.iter())
            .map(|s| s.to_string())
            .collect()
    };
    let run = |args: Vec<String>| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        pw(&dir, &refs)
    };
    // The same paths, step for step, as from the collector data.
    let saved = json(&run(with(&["query", KERBEROASTABLE_TO_DA, "--json"])));
    let full = json(&pw(
        &dir,
        &["query", KERBEROASTABLE_TO_DA, "-i", "demo:", "--json"],
    ));
    assert!(saved["run"]["id"].is_string());
    assert_eq!(saved["paths"], full["paths"]);
    assert!(!saved["paths"].as_array().unwrap().is_empty());

    // Marks: none, then two, used by queries on the environment's runs.
    assert_eq!(
        ok(&run(with(&["owned", "list"]))).trim(),
        "No object is marked as owned."
    );
    let out = ok(&run(with(&[
        "owned",
        "add",
        "SVC-00045@SCALE.LOCAL",
        "SVC-00040@SCALE.LOCAL",
    ])));
    assert!(
        out.contains("Marked as owned: SVC-00045@SCALE.LOCAL (User)."),
        "{out}"
    );
    assert!(
        out.trim_end().ends_with("2 objects are marked as owned."),
        "{out}"
    );
    let listed = json(&run(with(&["owned", "list", "--json"])));
    assert_eq!(listed.as_array().unwrap().len(), 2);
    let q = "MATCH p=shortestPath((s:Tag_Owned)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero)) WHERE s<>t RETURN p";
    let out = json(&run(with(&["query", q, "--json"])));
    let starts: std::collections::BTreeSet<String> = out["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["source"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        starts,
        ["SVC-00040@SCALE.LOCAL", "SVC-00045@SCALE.LOCAL"]
            .into_iter()
            .map(String::from)
            .collect()
    );
    // -i with --env uses the kept marks too.
    let out = json(&pw(
        &dir,
        &[
            "query",
            q,
            "-i",
            "demo:",
            "--env",
            "SCALE.LOCAL",
            "--workspace",
            ws,
            "--json",
        ],
    ));
    let starts_i: std::collections::BTreeSet<String> = out["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["source"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(starts_i, starts);
    let out = ok(&run(with(&["owned", "remove", "SVC-00045@SCALE.LOCAL"])));
    assert!(
        out.trim_end().ends_with("1 object is marked as owned."),
        "{out}"
    );
    let out = run(with(&["owned", "remove", "SVC-00045@SCALE.LOCAL"]));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("isn't marked as owned"));

    // A newer Pathwarden's marks: refused to change, and queries run
    // without them and say why, as the app does.
    let newer =
        "owned.json was saved by a newer Pathwarden. Update Pathwarden to change the owned marks.";
    std::fs::write(
        PathBuf::from(ws).join("owned.json"),
        r#"{"version": 9, "marks": {}}"#,
    )
    .unwrap();
    for args in [
        vec!["owned", "list"],
        vec!["owned", "add", "SVC-00040@SCALE.LOCAL"],
    ] {
        let out = run(with(&args));
        assert!(!out.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(newer),
            "{args:?}"
        );
    }
    let out = run(with(&["query", q]));
    let text = ok(&out);
    assert_eq!(text.trim(), "0 paths");
    assert!(String::from_utf8_lossy(&out.stderr).contains(newer));
}

/// Prepared queries: listed, run by name or GUID prefix, printed to
/// edit; hidden ones refused by name with why.
#[test]
fn prepared_queries_list_run_and_refuse() {
    let dir = scratch("prepared");
    let list = json(&pw(&dir, &["query", "--list-prepared", "--json"]));
    let queries = list["queries"].as_array().unwrap();
    assert!(queries.len() > 50, "{}", queries.len());
    assert_eq!(list["library"]["tag"], "queries-2026-08-20");
    let text = ok(&pw(&dir, &["query", "--list-prepared"]));
    assert!(
        text.starts_with("BloodHound Query Library \u{a9} 2025 SpecterOps. MIT License."),
        "{text}"
    );
    assert!(text.contains("Principals with DCSync privileges"));
    assert!(!text.contains("not supported"));

    // By name in any case, and by GUID prefix: the same answer.
    // The examples, picked by what the shipped lists say about them.
    use pathwarden_core::prepared::{library, Prepared, Unsupported};
    let pick =
        |f: &dyn Fn(&Prepared) -> bool| library().all.iter().find(|q| f(q)).expect("an example");
    let offered = pick(&|q| q.supported && !q.edit_first && q.returns == "paths");
    let by_name = json(&pw(
        &dir,
        &[
            "query",
            "--prepared",
            &offered.name.to_lowercase(),
            "-i",
            "demo:",
            "--json",
        ],
    ));
    assert_eq!(by_name["prepared"]["guid"], offered.guid.as_str());
    let by_guid = json(&pw(
        &dir,
        &[
            "query",
            "--prepared",
            &offered.guid[..8],
            "-i",
            "demo:",
            "--json",
        ],
    ));
    // The same rows (their order can differ from one load to the next).
    let sorted = |v: &serde_json::Value| {
        let mut r: Vec<String> = v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect();
        r.sort();
        r
    };
    assert_eq!(sorted(&by_name), sorted(&by_guid));
    let text = ok(&pw(
        &dir,
        &["query", "--prepared", &offered.guid[..8], "-i", "demo:"],
    ));
    assert!(
        text.starts_with(&format!(
            "{}\nBloodHound Query Library, revision",
            offered.name
        )),
        "{text}"
    );

    // Hidden, for either reason: refused by name, with why.
    for hidden in [
        pick(&|q| matches!(q.unsupported, Some(Unsupported::Cypher(_)))),
        pick(&|q| matches!(q.unsupported, Some(Unsupported::Fields(_)))),
    ] {
        let out = pw(&dir, &["query", "--prepared", &hidden.name, "-i", "demo:"]);
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        let want = format!("isn't offered. {}", hidden.reason.as_deref().unwrap());
        assert!(err.contains(&want), "{err}");
        // --show-prepared prints the Cypher, offered or not.
        let cypher = ok(&pw(&dir, &["query", "--show-prepared", &hidden.guid]));
        assert_eq!(cypher.trim_end(), hidden.query.trim_end());
    }
}
