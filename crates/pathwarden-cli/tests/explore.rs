//! Explore from the command line: `pathwarden reach`, `search` and
//! `zones suggest` answer what the app's Explore page answers for the same
//! data, read the way the app reads a saved run.

use std::path::{Path, PathBuf};
use std::process::Command;

use pathwarden_core::explore::answers::Explorer;
use pathwarden_core::explore::ExploreGraph;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_str(&ok(out)).unwrap()
}

#[test]
fn explore_answers_match_the_app() {
    let dir = std::env::temp_dir().join(format!("pathwarden-cli-explore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    let input = forest.to_str().unwrap();

    // The same data analyzed and saved as the app saves it.
    ok(&run(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", input],
    ));
    let root = dir.join("ws");
    let ws = pathwarden_ui::workspace::Workspace::open(&root).unwrap();
    let saved = ws.all_runs();
    assert_eq!(saved.len(), 1);
    let summary = &saved[0];
    let run_dir = ws.for_run(summary).run_dir(&summary.id).unwrap();
    let g = pathwarden_ui::run_data::graph(&run_dir).unwrap();
    let bytes =
        pathwarden_ui::run_data::read_gz(&run_dir.join(pathwarden_ui::explore_ui::GRAPH_FILE))
            .unwrap();
    let x = ExploreGraph::decode(&bytes).unwrap();
    let ex = Explorer::new(&g, &x);

    // Search, as the page's box finds objects.
    let cli = json(&run(&dir, &["search", "alice", "-i", input, "--json"]));
    let app = serde_json::to_value(ex.search("alice", &[], 20)).unwrap();
    assert_eq!(cli["results"], app);
    let da = app
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "DA_ALICE@CONTOSO.LOCAL")
        .expect("found")["ix"]
        .as_u64()
        .unwrap() as u32;
    let only_users = json(&run(
        &dir,
        &["search", "contoso", "-i", input, "--kind", "user", "--json"],
    ));
    assert!(only_users["results"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["kind"] == "User"));
    let out = run(&dir, &["search", "x", "-i", input, "--kind", "planet"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Unknown object kind 'planet'"));

    // Who can reach DA_ALICE: the page's first page, and one class.
    let list = ex.reach_list(da);
    let cli = json(&run(
        &dir,
        &["reach", "DA_ALICE@CONTOSO.LOCAL", "-i", input, "--json"],
    ));
    assert_eq!(
        cli,
        serde_json::to_value(ex.reach_page(da, &list, None, 0, 25)).unwrap()
    );
    assert!(cli["total"].as_u64().unwrap() > 0, "{cli}");
    let cli = json(&run(
        &dir,
        &[
            "reach",
            "DA_ALICE@CONTOSO.LOCAL",
            "-i",
            input,
            "--class",
            "unprivileged",
            "--top",
            "1",
            "--json",
        ],
    ));
    assert_eq!(
        cli,
        serde_json::to_value(ex.reach_page(da, &list, Some(0), 0, 1)).unwrap()
    );
    let text = ok(&run(
        &dir,
        &["reach", "DA_ALICE@CONTOSO.LOCAL", "-i", input],
    ));
    assert!(
        text.starts_with("Who can reach DA_ALICE@CONTOSO.LOCAL (User) [Tier Zero]"),
        "{text}"
    );
    assert!(
        text.contains(&pathwarden_core::explore::answers::reach_summary(
            list.len()
        )),
        "{text}"
    );
    assert!(
        text.contains("Unprivileged users and computers · "),
        "{text}"
    );
    assert!(text.contains("JDOE@CONTOSO.LOCAL (User)"), "{text}");
    let out = run(&dir, &["reach", "NOBODY@NOWHERE", "-i", input]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No object matches"));

    // Suggested zones, with the headline counts of the run's posture.
    let tree = x.tier_zero_tree();
    let app = ex.suggestions(&tree, Some((summary.exposed, summary.relevant_pop())));
    let cli = json(&run(&dir, &["zones", "suggest", "-i", input, "--json"]));
    assert_eq!(cli, serde_json::to_value(&app).unwrap());
    assert_eq!(cli["heuristics"].as_array().unwrap().len(), 3);
    let text = ok(&run(&dir, &["zones", "suggest", "-i", input]));
    assert!(
        text.starts_with("Suggested zones\nCandidates for Tier 1"),
        "{text}"
    );
    assert!(text.contains("Privileged sign-ins · "), "{text}");
    assert!(text.contains("SRV01.CONTOSO.LOCAL (Computer)"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Without -i, `reach` and `search` answer from a run saved in the
/// workspace (`--run`, or `--env`'s latest), as its Explore page does:
/// the same answers as with -i on the data it was analyzed from, with a
/// `run` field naming the run.
#[test]
fn reach_and_search_on_a_saved_run() {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-explore-saved-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    let input = forest.to_str().unwrap();
    ok(&run(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", input],
    ));
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join("ws")).unwrap();
    let summary = ws.all_runs().remove(0);
    let env = ws.for_run(&summary).env_name();
    let run_id = summary.run_id();

    let saved: [&[&str]; 2] = [
        &["--run", &run_id, "--workspace", "ws"],
        &["--env", &env, "--workspace", "ws"],
    ];
    for how in saved {
        for (args, data) in [
            (
                vec!["search", "contoso", "--json"],
                vec!["search", "contoso", "-i", input, "--json"],
            ),
            (
                vec!["search", "alice", "--kind", "user", "--json"],
                vec!["search", "alice", "--kind", "user", "-i", input, "--json"],
            ),
            (
                vec!["reach", "DA_ALICE@CONTOSO.LOCAL", "--json"],
                vec!["reach", "DA_ALICE@CONTOSO.LOCAL", "-i", input, "--json"],
            ),
            (
                vec![
                    "reach",
                    "DA_ALICE@CONTOSO.LOCAL",
                    "--class",
                    "unprivileged",
                    "--top",
                    "2",
                    "--json",
                ],
                vec![
                    "reach",
                    "DA_ALICE@CONTOSO.LOCAL",
                    "--class",
                    "unprivileged",
                    "--top",
                    "2",
                    "-i",
                    input,
                    "--json",
                ],
            ),
            // Explore's Path between and Suggested zones, on the run.
            (
                vec!["path", "--from", "JDOE@CONTOSO.LOCAL", "--json"],
                vec![
                    "path",
                    "--from",
                    "JDOE@CONTOSO.LOCAL",
                    "-i",
                    input,
                    "--json",
                ],
            ),
            (
                vec!["zones", "suggest", "--json"],
                vec!["zones", "suggest", "-i", input, "--json"],
            ),
        ] {
            let mut a = args.clone();
            a.extend_from_slice(how);
            let mut saved = json(&run(&dir, &a));
            let answered = saved.as_object_mut().unwrap().remove("run").unwrap();
            assert_eq!(answered["id"], run_id.as_str(), "{a:?}");
            assert_eq!(answered["at"], summary.created_at, "{a:?}");
            assert_eq!(saved, json(&run(&dir, &data)), "{a:?}");
        }
        let mut a = vec!["reach", "DA_ALICE@CONTOSO.LOCAL"];
        a.extend_from_slice(how);
        let out = run(&dir, &a);
        let text = ok(&out);
        // --env chose the run: stderr says which one.
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            err.contains(&format!("From run {run_id} (")),
            how[0] == "--env",
            "{err}"
        );
        assert!(
            text.starts_with("Who can reach DA_ALICE@CONTOSO.LOCAL (User) [Tier Zero]"),
            "{text}"
        );
    }

    // Neither -i nor a saved run; an unknown run; -i with --run.
    let out = run(&dir, &["search", "alice"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--run ID or --env NAME"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(
        &dir,
        &[
            "search",
            "alice",
            "--run",
            "20200101T000000Z",
            "--workspace",
            "ws",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No saved run"));
    let out = run(&dir, &["search", "alice", "--run", &run_id, "-i", input]);
    assert_eq!(out.status.code(), Some(2));
    // Settings a saved run doesn't take are refused, not ignored.
    for extra in [
        &["--run", &run_id, "-c", "nonexist.toml"][..],
        &["--run", &run_id, "--tier-zero", "foo"],
        &["--env", &env, "--tier-zero", "foo"],
    ] {
        let mut a = vec!["search", "alice", "--workspace", "ws"];
        a.extend_from_slice(extra);
        let out = run(&dir, &a);
        assert_eq!(out.status.code(), Some(2), "{a:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("cannot be used with") || err.contains("go with -i"),
            "{a:?}: {err}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// When the latest run of --env can't be explored (its graph is gone),
/// an older run answers, and the answer says so: a warning, the run on
/// stderr and in `--json`.
#[test]
fn an_older_run_answers_and_says_so() {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-explore-older-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    let input = forest.to_str().unwrap();
    for _ in 0..2 {
        ok(&run(
            &dir,
            &["run", "--save", "--workspace", "ws", "-i", input],
        ));
    }
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join("ws")).unwrap();
    let runs = ws.all_runs();
    assert_eq!(runs.len(), 2);
    let (newest, older) = (&runs[0], &runs[1]);
    let env = ws.for_run(newest).env_name();
    std::fs::remove_file(ws.run_dir(&newest.id).unwrap().join("graph.bin.gz")).unwrap();

    let out = run(
        &dir,
        &["search", "alice", "--env", &env, "--workspace", "ws"],
    );
    let text = ok(&out);
    assert!(text.contains("DA_ALICE@CONTOSO.LOCAL"), "{text}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "The latest run of {env}, {}, can't be explored",
            newest.run_id()
        )),
        "{err}"
    );
    assert!(err.contains("--run ID picks a run"), "{err}");
    assert!(
        err.contains(&format!("From run {} (", older.run_id())),
        "{err}"
    );
    let out = run(
        &dir,
        &[
            "search",
            "alice",
            "--env",
            &env,
            "--workspace",
            "ws",
            "--json",
        ],
    );
    let v = json(&out);
    assert_eq!(v["run"]["id"], older.run_id().as_str());
    assert!(String::from_utf8_lossy(&out.stderr).contains("can't be explored"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The test forest with a right across its trust: CAROL of
/// CHILD.CONTOSO.LOCAL in CONTOSO's HELPDESK group. Written under `dir`.
fn with_crossing(dir: &Path) -> PathBuf {
    let out = dir.join("forest");
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(repo("testdata/forest")).unwrap() {
        let p = e.unwrap().path();
        std::fs::copy(&p, out.join(p.file_name().unwrap())).unwrap();
    }
    let groups = out.join("contoso_groups.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&groups).unwrap()).unwrap();
    let helpdesk = v["data"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|g| g["ObjectIdentifier"] == "S-1-5-21-1000-1000-1000-1150")
        .unwrap();
    helpdesk["Members"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "ObjectIdentifier": "S-1-5-21-2000-2000-2000-1202",
            "ObjectType": "User"
        }));
    std::fs::write(&groups, v.to_string()).unwrap();
    out
}

/// `summary` on a saved run (`--run`, or `--env`'s latest) gives the
/// forest map the app's API returns, the one `summary -i` and the analysis
/// build from the same data; a run saved before the map was kept says to
/// analyze it again.
#[test]
fn summary_on_a_saved_run() {
    let dir = std::env::temp_dir().join(format!(
        "pathwarden-cli-summary-saved-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = with_crossing(&dir);
    let input = forest.to_str().unwrap();
    ok(&run(
        &dir,
        &["run", "--save", "--workspace", "ws", "-i", input],
    ));
    let ws = pathwarden_ui::workspace::Workspace::open(dir.join("ws")).unwrap();
    let summary = ws.all_runs().remove(0);
    let env = ws.for_run(&summary).env_name();
    let run_id = summary.run_id();

    let config = pathwarden_core::config::Config::default();
    let analysis =
        pathwarden_core::analyze::run(std::slice::from_ref(&forest), &config, &[], &mut |_| {})
            .unwrap();
    let expected = serde_json::to_value(analysis.forest_map().document()).unwrap();
    let from_data = json(&run(&dir, &["summary", "-i", input, "--json"]));
    assert_eq!(from_data["forest"], expected);
    for how in [["--run", &run_id], ["--env", &env]] {
        let mut args = vec!["summary", "--workspace", "ws", "--json"];
        args.extend(how);
        let v = json(&run(&dir, &args));
        assert_eq!(v["forest"], expected, "{how:?}");
        assert_eq!(v["run"]["id"], run_id.as_str());
        args.retain(|a| *a != "--json");
        let text = ok(&run(&dir, &args));
        assert!(text.contains("Forests (2, 3 domains)"), "{text}");
        assert!(
            text.contains(
                "Objects of CHILD.CONTOSO.LOCAL hold in CONTOSO.LOCAL: 1 group membership"
            ),
            "{text}"
        );
        assert!(!text.contains("CAROL@"), "listed only with --rights");
        // --rights lists what each crossing counts, from the saved run.
        args.push("--rights");
        let listed = ok(&run(&dir, &args));
        assert!(
            listed.contains("CAROL@CHILD.CONTOSO.LOCAL MemberOf HELPDESK@CONTOSO.LOCAL"),
            "{listed}"
        );
    }

    // Saved before crossings listed their rights: --rights says so.
    let graph = ws.run_dir(&summary.id).unwrap().join("graph.bin.gz");
    let mut older = analysis.forest_map();
    for t in &mut older.trusts {
        for c in &mut t.crossing {
            c.rights.clear();
        }
    }
    let mut bytes = Vec::new();
    pathwarden_core::explore::encode_with_forest_to(&mut bytes, &analysis, &older).unwrap();
    pathwarden_ui::run_data::write_gz(&graph, &bytes).unwrap();
    let text = ok(&run(
        &dir,
        &["summary", "--run", &run_id, "--workspace", "ws", "--rights"],
    ));
    assert!(
        text.contains("Not listed: this run was analyzed before Pathwarden listed them"),
        "{text}"
    );

    // Saved before the map was kept.
    let bare =
        pathwarden_core::explore::encode(&analysis.graph, &analysis.findings, &analysis.zones);
    pathwarden_ui::run_data::write_gz(&graph, &bare).unwrap();
    let out = run(&dir, &["summary", "--run", &run_id, "--workspace", "ws"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(pathwarden_core::forest::NOT_KEPT),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
