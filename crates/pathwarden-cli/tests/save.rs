//! Saving runs to environments from the command line, as the app does
//! (`run --save`, `collect --save`), run labels (`--label`, `pathwarden
//! label`), and the "something's off" stop that saves nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pathwarden")
}

fn repo(path: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
        .to_string_lossy()
        .into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pathwarden-save-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pw(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("PATHWARDEN_SCHEDULED")
        .args(args)
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The runs saved in the workspace: (folder, summary).
fn runs(ws: &Path) -> Vec<(String, serde_json::Value)> {
    let mut out: Vec<(String, serde_json::Value)> = std::fs::read_dir(ws.join("runs"))
        .map(|d| {
            d.flatten()
                .map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    (name, read_json(&e.path().join("summary.json")))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Every file under `dir`, with its contents, to show nothing changed.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// `-i run:ID` reads the collection a saved run kept, with other
/// files, into a new run that records how it was collected, as the app's
/// "Add files and analyze again"; `runs show` says how, or why not.
#[test]
fn run_reads_a_runs_kept_collection_with_other_files() {
    let dir = scratch("add-data");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    // A collection kept on this computer.
    let kept = dir.join("kept");
    std::fs::create_dir_all(&kept).unwrap();
    for e in std::fs::read_dir(repo("testdata/opengraph/ad"))
        .unwrap()
        .flatten()
    {
        std::fs::copy(e.path(), kept.join(e.file_name())).unwrap();
    }
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &kept.to_string_lossy(),
            "--save",
            "--workspace",
            &w,
        ],
    ));
    let (id, mut first) = runs(&ws).remove(0);
    // As the Collect wizard saves it, with the collection kept.
    first["source"] = "Collected from corp.local (Full, built-in)".into();
    first["collection"] = serde_json::json!({
        "method": "builtin", "scope": "all", "domain": "corp.local",
        "kept": kept.to_string_lossy(),
    });
    let summary = ws.join("runs").join(&id).join("summary.json");
    std::fs::write(&summary, serde_json::to_string_pretty(&first).unwrap()).unwrap();

    let shown = ok(&pw(&dir, &["runs", "show", &id, "--workspace", &w]));
    assert!(shown.contains("  Add other data\n"), "{shown}");
    assert!(
        shown.contains(&format!(
            "`pathwarden run -i run:{id} -i FILE --save` analyzes this run's collection again with AzureHound, OpenGraph or SharpHound files, as a new run."
        )),
        "{shown}"
    );
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["runs", "show", &id, "--workspace", &w, "--json"],
    )))
    .unwrap();
    assert_eq!(json["add_data"]["possible"], true);
    assert_eq!(json["add_data"]["input"], format!("run:{id}"));

    let taskhound = repo("testdata/opengraph/taskhound/taskhound.json");
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &format!("run:{id}"),
            "-i",
            &taskhound,
            "--save",
            "--workspace",
            &w,
        ],
    ));
    let saved = runs(&ws);
    assert_eq!(saved.len(), 2);
    let (_, second) = saved.iter().find(|(f, _)| *f != id).unwrap();
    assert_eq!(
        second["source"],
        "Collected from corp.local (Full, built-in), with taskhound.json"
    );
    for k in ["method", "scope", "domain", "kept"] {
        assert_eq!(second["collection"][k], first["collection"][k], "{k}");
    }
    assert!(kept.is_dir(), "the kept collection stays");

    // Not kept: -i says so for any command; Run details says it in the
    // app's words.
    first["collection"]["kept"] = serde_json::Value::Null;
    std::fs::write(&summary, serde_json::to_string_pretty(&first).unwrap()).unwrap();
    let out = pw(
        &dir,
        &[
            "run",
            "-i",
            &format!("run:{id}"),
            "-i",
            &taskhound,
            "--save",
            "--workspace",
            &w,
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "run:{id}: its raw collection wasn't kept, so -i can't read it."
        )),
        "{err}"
    );
    let shown = ok(&pw(&dir, &["runs", "show", &id, "--workspace", &w]));
    assert!(
        shown.contains("    The collection wasn't kept, so there is nothing to add to."),
        "{shown}"
    );
    // A run that isn't there.
    let out = pw(
        &dir,
        &[
            "report",
            "-i",
            "run:20990101-000000-000000",
            "--env",
            "x",
            "--workspace",
            &w,
        ],
    );
    assert!(!out.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_save_puts_runs_in_environments_by_domain() {
    let dir = scratch("run");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let forest = repo("testdata/forest");

    // No environment has the domains: a new one, named after them (the
    // workspace is made on the first --save).
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--save",
            "--workspace",
            &w,
            "--label",
            "pre-change baseline",
            "--report",
            "copy.html",
        ],
    ));
    assert!(
        out.contains("Saving to a new environment CONTOSO.LOCAL +1")
            && out.contains("label \"pre-change baseline\""),
        "{out}"
    );
    let saved = runs(&ws);
    assert_eq!(saved.len(), 1);
    let s = &saved[0].1;
    assert_eq!(s["label"], "pre-change baseline");
    assert_eq!(s["assigned"], "new");
    let history = s["history"]["run_id"].as_str().unwrap().to_string();
    // The history point carries the label too.
    let point = read_json(
        &ws.join("pathwarden-state/history")
            .join(format!("{}.json", history.replace(':', ""))),
    );
    assert_eq!(point["label"], "pre-change baseline");
    assert_eq!(point["recorded_by"], "cli");
    let copy = std::fs::read_to_string(dir.join("copy.html")).unwrap();
    assert!(copy.contains(
        "<title>Pathwarden report: pre-change baseline (CHILD.CONTOSO.LOCAL, CONTOSO.LOCAL)</title>"
    ));
    // The stored report has no label: it is added when shown.
    let stored =
        std::fs::read_to_string(ws.join("runs").join(&saved[0].0).join("report.html")).unwrap();
    assert!(!stored.contains("pre-change baseline"));

    // The same domains: that environment, with no question.
    let out = ok(&pw(
        &dir,
        &["run", "-i", &forest, "--save", "--workspace", &w],
    ));
    assert!(
        out.contains("Saving to CONTOSO.LOCAL +1 (it lists"),
        "{out}"
    );
    // Run IDs sort by second, then at random: find the new run by name.
    let first = saved[0].0.clone();
    let second = runs(&ws).into_iter().find(|r| r.0 != first).unwrap();
    assert_eq!(second.1["assigned"], "domains");

    // --new-env makes one; a name already taken, or an unknown --env, is
    // an error that saves nothing.
    let sdprop = repo("testdata/sdprop");
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &sdprop,
            "--save",
            "--workspace",
            &w,
            "--new-env",
            "Lab",
        ],
    ));
    assert!(
        out.contains("Saving to a new environment Lab (made for this run)"),
        "{out}"
    );
    let reg = read_json(&ws.join("environments.json"));
    let lab = reg["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "Lab")
        .unwrap()
        .clone();
    assert!(!lab["domains"].as_array().unwrap().is_empty(), "{lab}");
    let before = snapshot(&ws);
    for args in [
        &["--new-env", "lab"][..],
        &["--env", "Nope"],
        &["--label", &"x".repeat(61)],
    ] {
        let mut all = vec!["run", "-i", &sdprop, "--save", "--workspace", &w];
        all.extend_from_slice(args);
        let out = pw(&dir, &all);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.starts_with("error:"), "{err}");
    }
    let err = String::from_utf8_lossy(
        &pw(
            &dir,
            &[
                "run",
                "-i",
                &sdprop,
                "--save",
                "--workspace",
                &w,
                "--env",
                "Nope",
            ],
        )
        .stderr,
    )
    .into_owned();
    assert!(
        err.contains("(there is: CONTOSO.LOCAL +1, Lab)") && err.contains("--new-env"),
        "{err}"
    );
    assert_eq!(snapshot(&ws), before, "nothing saved");
    // --env picks an existing environment by the name it shows.
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &sdprop,
            "--save",
            "--workspace",
            &w,
            "--env",
            "lab",
        ],
    ));
    assert!(out.contains("Saving to Lab (chosen)"), "{out}");
    // --new-env needs --save; --save and --state don't go together.
    for args in [
        &["run", "-i", &sdprop, "--new-env", "X"][..],
        &["run", "-i", &sdprop, "--save", "--state", "st"],
    ] {
        assert_eq!(pw(&dir, args).status.code(), Some(2), "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Something's off (a known domain plus a new one, or two environments):
/// exit status 2, the reason and the values to use, and nothing written.
#[test]
fn something_off_stops_and_saves_nothing() {
    let dir = scratch("ask");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    // GOAD lab has ESSOS.LOCAL.
    let essos = [
        "testdata/rusthound/20261011195626_essos-local_domains.json",
        "testdata/rusthound/20261011195626_essos-local_users.json",
    ]
    .map(repo);
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &essos[0],
            "-i",
            &essos[1],
            "--save",
            "--workspace",
            &w,
            "--new-env",
            "GOAD lab",
        ],
    ));
    // ESSOS.LOCAL and SEVENKINGDOMS.LOCAL: ESSOS.LOCAL is GOAD lab's and no
    // environment has SEVENKINGDOMS.LOCAL, so the run joins GOAD lab and
    // its list takes the new domain.
    let both = repo("testdata/rusthound");
    let out = ok(&pw(
        &dir,
        &["run", "-i", &both, "--save", "--workspace", &w],
    ));
    assert!(
        out.contains("Saving to GOAD lab (it has the other domains; the new ones join it)"),
        "{out}"
    );

    // `collect --save` stops the same way, before collecting: ESSOS.LOCAL
    // listed by two environments.
    let reg_path = ws.join("environments.json");
    let mut reg = read_json(&reg_path);
    reg["environments"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"id": "prod", "name": "Production", "domains": ["ESSOS.LOCAL"]}));
    std::fs::write(&reg_path, reg.to_string()).unwrap();
    let before = snapshot(&ws);
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "essos.local",
            "-o",
            "out",
            "--save",
            "--workspace",
            &w,
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("ESSOS.LOCAL matches GOAD lab and Production.")
            && err.contains("--env Production"),
        "{err}"
    );
    assert!(!dir.join("out").exists(), "nothing collected");
    assert_eq!(snapshot(&ws), before, "nothing saved");
    // Picking GOAD lab for both domains lists SEVENKINGDOMS.LOCAL there.
    let mut reg = read_json(&reg_path);
    reg["environments"].as_array_mut().unwrap().pop();
    std::fs::write(&reg_path, reg.to_string()).unwrap();
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &both,
            "--save",
            "--workspace",
            &w,
            "--env",
            "GOAD lab",
        ],
    ));
    assert!(out.contains("Saving to GOAD lab (chosen)"), "{out}");
    let reg = read_json(&reg_path);
    let goad = reg["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "GOAD lab")
        .unwrap()
        .clone();
    assert_eq!(
        goad["domains"],
        serde_json::json!(["ESSOS.LOCAL", "SEVENKINGDOMS.LOCAL"])
    );
    // Flags of --save need it.
    assert_eq!(
        pw(
            &dir,
            &["collect", "-d", "x.local", "-o", "o", "--label", "x"]
        )
        .status
        .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `collect` with several domains, here with a stand-in SharpHound
/// that fails for one: asks first (`--yes` where nothing can answer), each
/// domain into its own folder, a table of how each went, exit status 3
/// when some weren't collected; `--save` saves the others as one run, with
/// each domain's outcome; `--trusted` adds the domains the last run says
/// this account can read.
#[cfg(windows)]
#[test]
fn collect_several_domains() {
    let dir = scratch("several");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let script = dir.join("SharpHound.cmd");
    let zip = repo("demo/20261001020000_PathwardenDemo.zip").replace('/', "\\");
    let lines = [
        "@echo off".to_string(),
        ":args".into(),
        r#"if "%~1"=="" goto run"#.into(),
        r#"if "%~1"=="--outputdirectory" set "OUT=%~2""#.into(),
        r#"if "%~1"=="--domain" set "DOM=%~2""#.into(),
        "shift".into(),
        "goto args".into(),
        ":run".into(),
        r#"if /i "%DOM%"=="broken.invalid" exit /b 1"#.into(),
        format!(r#"copy /y "{zip}" "%OUT%\20261001020000_BloodHound.zip" >nul"#),
    ];
    std::fs::write(&script, lines.join("\r\n") + "\r\n").unwrap();
    let s = script.to_string_lossy().into_owned();
    let args = |extra: &[&str]| -> Vec<String> {
        let mut a: Vec<String> = [
            "collect",
            "-d",
            "pathwarden.demo",
            "--domain",
            "broken.invalid",
            "--sharphound",
            &s,
            "-q",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        a.extend(extra.iter().map(|x| x.to_string()));
        a
    };
    let run = |a: Vec<String>| {
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        pw(&dir, &refs)
    };
    // Nothing can answer the question: --yes is needed, nothing collected.
    let out = run(args(&["-o", "out0"]));
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Only collect from domains you are authorized to assess."),
        "{err}"
    );
    assert!(err.contains("Pass --yes"), "{err}");
    assert!(!dir.join("out0").exists());

    // With --yes: one collected, one not, exit status 3.
    let out = run(args(&["-o", "out", "--yes"]));
    assert_eq!(out.status.code(), Some(3));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Collected 1 of 2 domains"), "{text}");
    assert!(text.contains("BROKEN.INVALID   not collected:"), "{text}");
    assert!(dir
        .join("out/pathwarden.demo/20261001020000_BloodHound.zip")
        .is_file());
    assert!(!dir
        .join("out/broken.invalid")
        .join("20261001020000_BloodHound.zip")
        .exists());

    // --save: the domains collected, saved as one run with each outcome.
    let out = run(args(&["-o", "out2", "--yes", "--save", "--workspace", &w]));
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = runs(&ws);
    assert_eq!(saved.len(), 1);
    let summary = &saved[0].1;
    assert_eq!(
        summary["source"],
        "Collected from pathwarden.demo and 1 trusted domain"
    );
    let doms = summary["collection"]["domains"].as_array().unwrap();
    assert_eq!(doms.len(), 2);
    assert_eq!(doms[0]["domain"], "PATHWARDEN.DEMO");
    assert_eq!(doms[0]["collected"], true);
    assert_eq!(doms[1]["collected"], false);

    // --trusted: the readable trusted domains of the domain's last run.
    let data = repo("testdata/trusts");
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &data,
            "--save",
            "--workspace",
            &w,
            "--new-env",
            "Contoso",
        ],
    ));
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "contoso.local",
            "--trusted",
            "--workspace",
            &w,
            "--sharphound",
            &s,
            "-o",
            "out3",
            "--yes",
            "-q",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let text = ok(&out);
    // Only the child domain: the others' own trust records, which say
    // whether they use selective authentication, aren't in the run (lab
    // item 53).
    assert!(text.contains("Collected 2 of 2 domains"), "{text}");
    assert!(text.contains("CHILD.CONTOSO.LOCAL"), "{text}");
    for d in ["FABRIKAM.COM", "TAILSPIN.COM", "WINGTIP.COM"] {
        assert!(!text.contains(d), "{d}: {text}");
        assert!(
            err.contains(&format!(
                "{d} left out: Your account may not be allowed to sign in there. Name it \
                 with --domain to try."
            )),
            "{d}: {err}"
        );
    }
    assert!(!text.contains("NORTHWIND.COM"), "{text}");
    assert!(!err.contains("NORTHWIND.COM"), "{err}");

    // --server DOMAIN=HOST: that domain's collector is given that host.
    let checked = dir.join("SharpHoundDc.cmd");
    let lines = [
        "@echo off".to_string(),
        ":args".into(),
        r#"if "%~1"=="" goto run"#.into(),
        r#"if "%~1"=="--outputdirectory" set "OUT=%~2""#.into(),
        r#"if "%~1"=="--domain" set "DOM=%~2""#.into(),
        r#"if "%~1"=="--domaincontroller" set "DC=%~2""#.into(),
        "shift".into(),
        "goto args".into(),
        ":run".into(),
        r#"if /i "%DOM%"=="fabrikam.com" if /i not "%DC%"=="dc07.fabrikam.com" exit /b 1"#.into(),
        format!(r#"copy /y "{zip}" "%OUT%\20261001020000_BloodHound.zip" >nul"#),
    ];
    std::fs::write(&checked, lines.join("\r\n") + "\r\n").unwrap();
    let c = checked.to_string_lossy().into_owned();
    let several = |server: &str, out: &str| {
        pw(
            &dir,
            &[
                "collect",
                "-d",
                "pathwarden.demo",
                "-d",
                "fabrikam.com",
                "--server",
                server,
                "--sharphound",
                &c,
                "-o",
                out,
                "--yes",
                "-q",
            ],
        )
    };
    let text = ok(&several("FABRIKAM.COM=dc07.fabrikam.com", "out5"));
    assert!(text.contains("Collected 2 of 2 domains"), "{text}");
    let out = several("fabrikam.com=dc01.fabrikam.com", "out6");
    assert_eq!(out.status.code(), Some(3));
    // A domain the run doesn't collect: an error before anything runs.
    let out = several("tailspin.com=dc01.tailspin.com", "out7");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tailspin.com, which this run doesn't"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.join("out7").exists());
    // A domain no run has collected: say so.
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "other.local",
            "--trusted",
            "--workspace",
            &w,
            "--sharphound",
            &s,
            "-o",
            "out4",
            "--yes",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No run of other.local"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `collect --save` collects (here with a stand-in SharpHound), analyzes and
/// saves the run like the Collect wizard, with how it was collected.
#[cfg(windows)]
#[test]
fn collect_save_collects_analyzes_and_saves() {
    let dir = scratch("collect");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let script = dir.join("SharpHound.cmd");
    let zip = repo("demo/20261001020000_PathwardenDemo.zip").replace('/', "\\");
    let lines = [
        "@echo off".to_string(),
        ":args".into(),
        r#"if "%~1"=="" goto run"#.into(),
        r#"if "%~1"=="--outputdirectory" set "OUT=%~2""#.into(),
        "shift".into(),
        "goto args".into(),
        ":run".into(),
        format!(r#"copy /y "{zip}" "%OUT%\20261001020000_BloodHound.zip" >nul"#),
    ];
    std::fs::write(&script, lines.join("\r\n") + "\r\n").unwrap();
    let s = script.to_string_lossy().into_owned();
    let out = ok(&pw(
        &dir,
        &[
            "collect",
            "-d",
            "scale.local",
            "--sharphound",
            &s,
            "-o",
            "out",
            "--save",
            "--workspace",
            &w,
            "--label",
            "first look",
            "-q",
        ],
    ));
    assert!(
        out.contains("Saving to a new environment SCALE.LOCAL"),
        "{out}"
    );
    assert!(!out.contains("Analyze it with"), "{out}");
    let saved = runs(&ws);
    assert_eq!(saved.len(), 1);
    let s = &saved[0].1;
    assert_eq!(s["label"], "first look");
    assert_eq!(s["source"], "Collected from scale.local");
    assert_eq!(s["collection"]["method"], "sharphound");
    assert_eq!(s["collection"]["domain"], "scale.local");
    // The collection stays where it was asked to go.
    assert!(dir
        .join("out")
        .join("20261001020000_BloodHound.zip")
        .is_file());

    // Something's off only once collected (the data's domain is on two
    // lists, the one given is new): no run is saved, the collection stays,
    // and the stop says how to save it without collecting again.
    let reg_path = ws.join("environments.json");
    let mut reg = read_json(&reg_path);
    reg["environments"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"id": "other", "name": "Other", "domains": ["SCALE.LOCAL"]}));
    std::fs::write(&reg_path, reg.to_string()).unwrap();
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "elsewhere.local",
            "--sharphound",
            &script.to_string_lossy(),
            "-o",
            "out2",
            "--save",
            "--workspace",
            &w,
            "--label",
            "second look",
            "-q",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    // The command to save it repeats --workspace and --label.
    assert!(
        err.contains("The collection stays in out2")
            && err.contains(&format!(
                "`pathwarden run -i out2 --save --workspace \"{w}\" --label \"second look\"`"
            ))
            && err.contains("No run was saved."),
        "{err}"
    );
    assert_eq!(runs(&ws).len(), 1);
    assert!(dir
        .join("out2")
        .join("20261001020000_BloodHound.zip")
        .is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `pathwarden env list` and `env rename`, as the Environments page; a
/// registry that can't be read stops every change, and stays as it was.
#[test]
fn env_list_rename_and_a_broken_registry() {
    let dir = scratch("envcmd");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let forest = repo("testdata/forest");
    ok(&pw(
        &dir,
        &["run", "-i", &forest, "--save", "--workspace", &w],
    ));
    let list = ok(&pw(&dir, &["env", "list", "--workspace", &w]));
    assert!(
        list.contains("CONTOSO.LOCAL +1 (current)  ID default")
            && list.contains("1 run · domains: CHILD.CONTOSO.LOCAL, CONTOSO.LOCAL"),
        "{list}"
    );
    let out = ok(&pw(
        &dir,
        &[
            "env",
            "rename",
            "contoso.local +1",
            "Production",
            "--workspace",
            &w,
        ],
    ));
    assert!(
        out.contains("Renamed CONTOSO.LOCAL +1 to Production"),
        "{out}"
    );
    let json: serde_json::Value = serde_json::from_str(&ok(&pw(
        &dir,
        &["env", "list", "--json", "--workspace", &w],
    )))
    .unwrap();
    assert_eq!(json[0]["name"], "Production");
    assert_eq!(json[0]["runs"], 1);
    // The UI's checks: empty, too long, a control character, unknown.
    for (env, name) in [
        ("Production", ""),
        ("Production", &"x".repeat(61)[..]),
        ("Production", "a\u{7}b"),
        ("Nope", "X"),
    ] {
        let out = pw(&dir, &["env", "rename", env, name, "--workspace", &w]);
        assert_eq!(out.status.code(), Some(2), "{env} {name:?}");
    }
    // Broken registry: exit status 2, the file untouched, nothing saved.
    std::fs::write(ws.join("environments.json"), "{broken").unwrap();
    for args in [
        &["env", "rename", "default", "X", "--workspace", &w][..],
        &["env", "list", "--workspace", &w],
        &[
            "run",
            "-i",
            &repo("testdata/sdprop"),
            "--save",
            "--workspace",
            &w,
        ],
    ] {
        let out = pw(&dir, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("can't be read"),
            "{args:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(ws.join("environments.json")).unwrap(),
        "{broken"
    );
    assert_eq!(runs(&ws).len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `pathwarden env remove`, as the Environments page removes one: the same
/// summary first; not on a terminal it needs `--yes`; everything moves to
/// environments/removed, nothing is deleted; the first environment too.
#[test]
fn env_remove_asks_then_moves_everything_aside() {
    let dir = scratch("envremove");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let forest = repo("testdata/forest");
    ok(&pw(
        &dir,
        &["run", "-i", &forest, "--save", "--workspace", &w],
    ));
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--save",
            "--new-env",
            "Lab",
            "--workspace",
            &w,
        ],
    ));
    assert_eq!(runs(&ws).len(), 2);
    // Not on a terminal, without --yes: the summary, then a stop.
    let out = pw(&dir, &["env", "remove", "Lab", "--workspace", &w]);
    assert_eq!(out.status.code(), Some(2));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("Remove Lab?"), "{said}");
    assert!(
        said.contains("- Goes: 1 run with its report and its settings, run history and labels ("),
        "{said}"
    );
    assert!(said.contains("task Pathwarden-lab"), "{said}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("pass --yes"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(runs(&ws).len(), 2, "nothing removed");
    // Unknown names list the environments.
    let out = pw(&dir, &["env", "remove", "Nope", "--yes", "--workspace", &w]);
    assert_eq!(out.status.code(), Some(2));
    // With --yes.
    let out = ok(&pw(
        &dir,
        &["env", "remove", "lab", "--yes", "--workspace", &w],
    ));
    assert!(out.contains("Removed Lab: 1 run and its files ("), "{out}");
    assert!(out.contains("RESTORE.txt"), "{out}");
    assert_eq!(runs(&ws).len(), 1);
    assert!(!ws.join("environments/lab").exists());
    let removed: Vec<_> = std::fs::read_dir(ws.join("environments/removed"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(removed.len(), 1);
    assert!(removed[0].path().join("runs").is_dir());
    assert!(removed[0].path().join("env/pathwarden-state").is_dir());
    // The first environment (the workspace folder itself) goes too.
    let out = ok(&pw(
        &dir,
        &[
            "env",
            "remove",
            "CONTOSO.LOCAL +1",
            "--yes",
            "--workspace",
            &w,
        ],
    ));
    assert!(out.contains("It is the first environment"), "{out}");
    assert!(out.contains("Now showing No environment yet."), "{out}");
    assert!(runs(&ws).is_empty());
    assert!(!ws.join("pathwarden-state").exists());
    let list = ok(&pw(&dir, &["env", "list", "--workspace", &w]));
    assert!(list.starts_with("No environment yet"), "{list}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `env remove --state DIR` plans as `pathwarden ui --state DIR` would: the
/// first environment's history there stays (and is said to).
#[test]
fn env_remove_plans_with_the_uis_state_folder() {
    let dir = scratch("envremove-state");
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let state = dir.join("elsewhere");
    std::fs::create_dir_all(&state).unwrap();
    let s = state.to_string_lossy().into_owned();
    ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &repo("testdata/forest"),
            "--save",
            "--workspace",
            &w,
        ],
    ));
    let plan = |extra: &[&str]| {
        let mut args = vec!["env", "remove", "default", "--workspace", &w];
        args.extend_from_slice(extra);
        let out = pw(&dir, &args);
        assert_eq!(out.status.code(), Some(2), "not on a terminal, no --yes");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let with = plan(&["--state", &s]);
    assert!(
        with.contains("Its run history in") && with.contains("elsewhere"),
        "{with}"
    );
    let without = plan(&[]);
    assert!(!without.contains("Its run history in"), "{without}");
    let out = ok(&pw(
        &dir,
        &[
            "env",
            "remove",
            "default",
            "--state",
            &s,
            "--yes",
            "--workspace",
            &w,
        ],
    ));
    assert!(out.contains("Removed "), "{out}");
    assert!(state.is_dir(), "the --state folder is untouched");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Labels without the UI workspace (`run --label`, `retest --record
/// --label`) go in the history point; `pathwarden label` sets one later.
#[test]
fn labels_on_recorded_runs() {
    let dir = scratch("labels");
    let forest = repo("testdata/forest");
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--state",
            "st",
            "--label",
            "nightly baseline",
        ],
    ));
    assert!(out.contains("label \"nightly baseline\""), "{out}");
    // Findings still open: status 1, and the run is recorded.
    let out = pw(
        &dir,
        &[
            "retest",
            "-i",
            &forest,
            "--state",
            "st",
            "--record",
            "--no-push",
            "--label",
            "after fix",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let hist = ok(&pw(&dir, &["history", "--state", "st"]));
    assert!(
        hist.contains("nightly baseline") && hist.contains("after fix"),
        "{hist}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&ok(&pw(&dir, &["history", "--state", "st", "--json"]))).unwrap();
    assert_eq!(json[0]["label"], "nightly baseline");
    assert_eq!(json[1]["label"], "after fix");
    // A label with a control character is refused.
    let out = pw(
        &dir,
        &["run", "-i", &forest, "--state", "st", "--label", "a\u{7}b"],
    );
    assert_eq!(out.status.code(), Some(2));

    // In the UI workspace: a run recorded with `run --env` gets a label
    // later, kept beside the history (which is never rewritten).
    let ws = dir.join("ws");
    let w = ws.to_string_lossy().into_owned();
    let out = ok(&pw(
        &dir,
        &[
            "run",
            "-i",
            &forest,
            "--save",
            "--workspace",
            &w,
            "--new-env",
            "Lab",
        ],
    ));
    assert!(out.contains("Lab"), "{out}");
    let run_out = ok(&pw(
        &dir,
        &["run", "-i", &forest, "--env", "Lab", "--workspace", &w],
    ));
    let run_id = run_out
        .lines()
        .find_map(|l| l.strip_prefix("Run "))
        .unwrap()
        .trim()
        .to_string();
    let out = ok(&pw(
        &dir,
        &[
            "label",
            &run_id,
            "scheduled check",
            "--env",
            "Lab",
            "--workspace",
            &w,
        ],
    ));
    assert!(out.contains("\"scheduled check\""), "{out}");
    let hist = ok(&pw(&dir, &["history", "--env", "Lab", "--workspace", &w]));
    assert!(hist.contains("scheduled check"), "{hist}");
    let point_files: Vec<_> = std::fs::read_dir(ws.join("pathwarden-state/history"))
        .unwrap()
        .flatten()
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(point_files.iter().all(|t| !t.contains("scheduled check")));
    // A saved run, by its history ID: its summary changes; then cleared.
    let saved = runs(&ws);
    let id = saved[0].1["history"]["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    ok(&pw(&dir, &["label", &id, "first", "--workspace", &w]));
    assert_eq!(runs(&ws)[0].1["label"], "first");
    ok(&pw(&dir, &["label", &id, "--clear", "--workspace", &w]));
    assert!(runs(&ws)[0].1.get("label").is_none());
    // An unknown run is an error.
    assert_eq!(
        pw(&dir, &["label", "20200101T000000Z", "x", "--workspace", &w])
            .status
            .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--sharphound`: a bare file name (a lookup in the current folder)
/// is refused; a path with a folder in it, as scheduled tasks from before
/// 0.3 give `.\SharpHound.exe`, is resolved to its full path; and a SharpHound
/// that isn't signed by SpecterOps gets one warning, naming that path, and
/// still runs.
#[cfg(windows)]
#[test]
fn collect_sharphound_resolves_its_path_and_warns_when_unsigned() {
    let dir = scratch("unsigned");
    let script = dir.join("SharpHound.cmd");
    let zip = repo("demo/20261001020000_PathwardenDemo.zip").replace('/', "\\");
    let lines = [
        "@echo off".to_string(),
        ":args".into(),
        r#"if "%~1"=="" goto run"#.into(),
        r#"if "%~1"=="--outputdirectory" set "OUT=%~2""#.into(),
        "shift".into(),
        "goto args".into(),
        ":run".into(),
        format!(r#"copy /y "{zip}" "%OUT%\20261001020000_BloodHound.zip" >nul"#),
    ];
    std::fs::write(&script, lines.join("\r\n") + "\r\n").unwrap();

    // In the current folder, named without a path: refused, nothing run.
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "scale.local",
            "--sharphound",
            "SharpHound.cmd",
            "-o",
            "out1",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("give its full path"), "{err}");
    assert!(!dir
        .join("out1")
        .join("20261001020000_BloodHound.zip")
        .exists());

    // From the current folder, with `.\`: its full path in the warning,
    // then the collection.
    let s = script.to_string_lossy().into_owned();
    let out = pw(
        &dir,
        &[
            "collect",
            "-d",
            "scale.local",
            "--sharphound",
            r".\SharpHound.cmd",
            "-o",
            "out2",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains(&format!(
            "Warning: {s} isn't signed by SpecterOps. Run it only if you trust where it came from."
        )),
        "{err}"
    );
    assert_eq!(
        err.matches("isn't signed by SpecterOps").count(),
        1,
        "{err}"
    );
    assert!(dir
        .join("out2")
        .join("20261001020000_BloodHound.zip")
        .is_file());
    let _ = std::fs::remove_dir_all(&dir);
}
