//! `pathwarden history storage|import|keep-local`: the app's History
//! storage page from the terminal, through the page's own code and words.

use std::path::{Path, PathBuf};
use std::process::Command;

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
        .env("PATHWARDEN_LOCK_WAIT", "0")
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

fn err(out: &std::process::Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn show(dir: &Path) -> serde_json::Value {
    serde_json::from_str(&ok(&run(
        dir,
        &["history", "storage", "show", "--workspace", "ws", "--json"],
    )))
    .unwrap()
}

#[test]
fn storage_import_and_keep_local_from_the_terminal() {
    let dir = std::env::temp_dir().join(format!("pathwarden-cli-storage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let forest = repo("testdata/forest");
    let input = forest.to_str().unwrap();
    let save = |dir: &Path| {
        // Run IDs carry the second they were made in.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        ok(&run(
            dir,
            &["run", "--save", "--workspace", "ws", "-i", input],
        ));
    };

    // One run recorded; two saved while another run held the history's
    // lock, so they are local only.
    save(&dir);
    let state = dir.join("ws").join("pathwarden-state");
    let lock = state.join(".pathwarden.lock");
    std::fs::write(&lock, "host test pid 1 token x\n").unwrap();
    save(&dir);
    save(&dir);
    std::fs::remove_file(&lock).unwrap();

    let text = ok(&run(
        &dir,
        &["history", "storage", "show", "--workspace", "ws"],
    ));
    assert!(
        text.contains("A folder: ") && !text.contains("A folder: `"),
        "{text}"
    );
    // The page's labels, word for word.
    use pathwarden_ui::history_ui::label;
    for l in [label::WHERE, label::SET_BY, label::RECORDED, label::RECORDS] {
        assert!(text.contains(&format!("  {l}  ")), "{l}: {text}");
    }
    assert!(
        text.contains("The default: nothing is set in pathwarden.toml"),
        "{text}"
    );
    assert!(text.contains("1 run, the latest"), "{text}");
    assert!(text.contains("Runs kept on this computer only"), "{text}");
    assert!(
        text.contains("2 can be added in order, oldest first"),
        "{text}"
    );
    let v = show(&dir);
    assert_eq!(v["kind"], "folder");
    assert_eq!(v["origin"], "default");
    assert_eq!(v["runs"], 1);
    let importable = v["not_in_history"]["importable"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(importable.len(), 2, "{v}");
    let first = importable[0]["id"].as_str().unwrap().to_string();

    // Keep the first local only; a run that isn't offered is refused.
    let e = err(&run(
        &dir,
        &["history", "keep-local", "nope", "--workspace", "ws"],
    ));
    assert!(e.contains("isn't a run of environment"), "{e}");
    let text = ok(&run(
        &dir,
        &["history", "keep-local", &first, "--workspace", "ws"],
    ));
    assert!(text.contains("Kept 1 run local only: it stays"), "{text}");
    let v = show(&dir);
    assert_eq!(
        v["not_in_history"]["importable"].as_array().unwrap().len(),
        1
    );
    assert_eq!(v["not_in_history"]["kept_local"], 1);

    // Import the other, as the page's button does.
    let text = ok(&run(&dir, &["history", "import", "--workspace", "ws"]));
    assert!(
        text.contains("Imported 1 run into the run history"),
        "{text}"
    );
    let (points, _) = pathwarden_core::history::load(&state).unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(points[1].recorded_by.as_deref(), Some("import"));
    let text = ok(&run(&dir, &["history", "import", "--workspace", "ws"]));
    assert!(text.starts_with("Nothing to import"), "{text}");
    let text = ok(&run(&dir, &["history", "keep-local", "--workspace", "ws"]));
    assert!(text.starts_with("Nothing to keep local"), "{text}");

    // An analysis older than the history's latest run can't be imported:
    // keep-local says so, and the JSON lists it for keep-local to take.
    std::fs::write(
        &lock,
        "host test pid 1 token x
",
    )
    .unwrap();
    save(&dir);
    std::fs::remove_file(&lock).unwrap();
    save(&dir);
    let v = show(&dir);
    let old = v["not_in_history"]["too_old"].as_array().unwrap().clone();
    assert_eq!(old.len(), 1, "{v}");
    assert!(old[0]["created_at"].is_i64(), "{v}");
    let old = old[0]["id"].as_str().unwrap().to_string();
    let text = ok(&run(&dir, &["history", "keep-local", "--workspace", "ws"]));
    assert!(
        text.contains("1 older run from before the history's latest run"),
        "{text}"
    );
    assert!(
        !text.contains("every analysis in the app is in the history"),
        "{text}"
    );
    ok(&run(
        &dir,
        &["history", "keep-local", &old, "--workspace", "ws"],
    ));
    let v = show(&dir);
    assert_eq!(v["not_in_history"]["too_old"].as_array().unwrap().len(), 0);

    // Where to keep it: through the page's checks and messages.
    let text = ok(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--folder",
            "shared",
            "--workspace",
            "ws",
        ],
    ));
    assert!(text.contains("A folder: `"), "{text}");
    let v = show(&dir);
    assert_eq!(v["origin"], "config");
    assert!(v["dir"].as_str().unwrap().ends_with("shared"), "{v}");
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            "https://someone:secret@git.example.invalid/state.git",
            "--workspace",
            "ws",
        ],
    ));
    assert!(
        e.contains("Don't put a password or token in the repository URL"),
        "{e}"
    );
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--folder",
            "x",
            "--no-push",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("go with --git"), "{e}");
    let text = ok(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            "https://git.example.invalid/state.git",
            "--branch",
            "trunk",
            "--no-push",
            "--names",
            "--workspace",
            "ws",
        ],
    ));
    assert!(text.contains("branch `trunk`"), "{text}");
    assert!(text.contains("Kept on this computer only"), "{text}");
    let v = show(&dir);
    assert_eq!(v["kind"], "git");
    assert_eq!(v["branch"], "trunk");
    assert_eq!(
        (v["push"].as_bool(), v["include_names"].as_bool()),
        (Some(false), Some(true))
    );
    // The folder given before stays the checkout.
    assert!(v["dir"].as_str().unwrap().ends_with("shared"), "{v}");
    // Options alone keep the history where it is. Names are kept at every
    // level; full runs and settings need --yes.
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--no-names",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("no longer available"), "{e}");
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--keep",
            "full",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("--yes") && e.contains("accepted risks"), "{e}");
    // A history that isn't encrypted: encrypt it, or keep it plain on
    // purpose.
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--keep",
            "full",
            "--yes",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("Choose whether to encrypt"), "{e}");
    assert_eq!(show(&dir)["keep"].as_str(), Some("names"));
    for (args, keep) in [
        (&["--keep", "full", "--no-encrypt", "--yes"][..], "full"),
        (&["--names"][..], "names"),
    ] {
        let mut a = vec!["history", "storage", "set"];
        a.extend(args);
        a.extend(["--workspace", "ws"]);
        ok(&run(&dir, &a));
        let v = show(&dir);
        assert_eq!(
            (v["kind"].as_str(), v["branch"].as_str()),
            (Some("git"), Some("trunk"))
        );
        assert_eq!(v["include_names"].as_bool(), Some(true), "{v}");
        assert_eq!(v["keep"].as_str(), Some(keep), "{v}");
        assert_eq!(v["push"].as_bool(), Some(false), "{v}");
    }
    ok(&run(
        &dir,
        &["history", "storage", "set", "--push", "--workspace", "ws"],
    ));
    assert_eq!(show(&dir)["push"].as_bool(), Some(true));
    ok(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--no-push",
            "--workspace",
            "ws",
        ],
    ));
    let e = err(&run(
        &dir,
        &["history", "storage", "set", "--workspace", "ws"],
    ));
    assert!(e.contains("Nothing to change"), "{e}");
    // Nothing can be imported while this computer only reads the history.
    let e = err(&run(&dir, &["history", "import", "--workspace", "ws"]));
    assert!(e.contains(pathwarden_ui::history_ui::NO_PUSH_IMPORT), "{e}");
    // A folder has nothing to pull.
    ok(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--folder",
            "pathwarden-state",
            "--workspace",
            "ws",
        ],
    ));
    let e = err(&run(
        &dir,
        &["history", "storage", "pull", "--workspace", "ws"],
    ));
    assert!(e.contains("is a folder, not a git repository"), "{e}");
    ok(&run(
        &dir,
        &["history", "storage", "set", "--names", "--workspace", "ws"],
    ));
    assert_eq!(show(&dir)["kind"], "folder");
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--no-push",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("go with --git"), "{e}");
    // A git checkout can't take over the folder history it replaces.
    let e = err(&run(
        &dir,
        &[
            "history",
            "storage",
            "set",
            "--git",
            "https://git.example.invalid/state.git",
            "--workspace",
            "ws",
        ],
    ));
    assert!(e.contains("is not a git working copy"), "{e}");
    assert!(e.contains("--folder DIR"), "{e}");
    assert_eq!(show(&dir)["kind"], "folder", "not saved");
    // The history's own options don't mix with these.
    let e = err(&run(&dir, &["history", "--last", "2", "import"]));
    assert!(e.contains("cannot be used with"), "{e}");

    let _ = std::fs::remove_dir_all(&dir);
}
