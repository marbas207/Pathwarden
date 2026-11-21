use super::*;

#[test]
fn names_get_a_number_when_taken() {
    let taken = vec!["Lab".to_string(), "lab 2".to_string()];
    assert_eq!(free_name("Lab", &taken, 60), "Lab 3");
    assert_eq!(free_name("Prod", &taken, 60), "Prod");
    assert_eq!(free_name("  ", &[], 60), "Shared history");
    let long = "x".repeat(60);
    let name = free_name(&long, std::slice::from_ref(&long), 60);
    assert_eq!(name.chars().count(), 60);
    assert!(name.ends_with(" 2"));
}

#[test]
fn shared_folders_are_looked_at_too() {
    let dir = std::env::temp_dir().join(format!("pw-cx-folder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let none = dir.join("none");
    assert_eq!(
        probe(&Where::Folder(none.clone()), &dir).unwrap_err(),
        Problem::NoFolder
    );
    std::fs::create_dir_all(&none).unwrap();
    assert_eq!(
        probe(&Where::Folder(none.clone()), &dir).unwrap_err(),
        Problem::Empty { git: false }
    );
    std::fs::write(none.join("notes.txt"), "x").unwrap();
    assert_eq!(
        probe(&Where::Folder(none.clone()), &dir).unwrap_err(),
        Problem::NotHistory { git: false }
    );
    let h = dir.join("history");
    std::fs::create_dir_all(h.join("history")).unwrap();
    std::fs::write(h.join("findings.json"), r#"{"version": 1, "findings": {}}"#).unwrap();
    std::fs::write(h.join("history/20261026T235100.000Z.json"), "{}").unwrap();
    let found = probe(&Where::Folder(h.clone()), &dir).unwrap();
    assert!(!found.encrypted);
    assert_eq!(found.keep, Keep::Names);
    assert_eq!(found.runs, 1);
    assert!(found.latest.is_some());
    std::fs::write(
        h.join("findings.json"),
        r#"{"version": 999, "findings": {}}"#,
    )
    .unwrap();
    assert_eq!(
        probe(&Where::Folder(h), &dir).unwrap_err(),
        Problem::Newer { version: None }
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_user_name_in_the_url_is_fine_a_token_is_not() {
    let dir = std::env::temp_dir().join(format!("pw-cx-url-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let git = |url: &str| Where::Git {
        url: url.into(),
        branch: None,
    };
    // A user name (Azure DevOps' own form) is looked at: here a local
    // port nothing listens on, so it can't be reached, but it isn't
    // refused for its URL.
    let p = probe(&git("https://org@127.0.0.1:9/org/p/_git/r"), &dir).unwrap_err();
    assert_ne!(p.key(), "bad_url", "{p}");
    for secret in [
        "https://user:pw@127.0.0.1:9/x.git".to_string(),
        "https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@127.0.0.1:9/x.git".to_string(),
        format!(
            "https://{}@127.0.0.1:9/x.git",
            "a1b2c3d4e5".repeat(5) + "zz"
        ),
    ] {
        let p = probe(&git(&secret), &dir).unwrap_err();
        assert_eq!(p, Problem::BadUrl(PASSWORD_IN_URL.into()), "{secret}");
        assert!(!p.sentence().contains("ghp_"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sign_in_and_reach_are_told_apart() {
    let failed = |m: &str| -> anyhow::Error {
        store::GitFailed {
            code: Some(128),
            message: m.into(),
        }
        .into()
    };
    assert_eq!(
        classify(&failed(
            "git ls-remote failed: remote: HTTP Basic: Access denied"
        ))
        .key(),
        "sign_in"
    );
    assert_eq!(
            classify(&failed("git ls-remote failed: fatal: unable to access 'https://git.example.com/x.git/': Could not resolve host: git.example.com")).key(),
            "unreachable"
        );
    assert_eq!(
            classify(&failed("git ls-remote failed: fatal: 'C:/Temp/probe-124012/x.git' does not appear to be a git repository")).key(),
            "unreachable"
        );
    assert_eq!(
            classify(&failed("git ls-remote failed: fatal: unable to access 'https://h/x.git/': The requested URL returned error: 403")).key(),
            "sign_in"
        );
    let said = "git fetch failed: fatal: could not read Password for 'https://github.com': terminal prompts disabled";
    assert!(is_sign_in(said));
    assert!(!is_sign_in(
        "fatal: unable to access 'https://h/': Could not resolve host: h"
    ));
    // A local file another program holds is no sign-in, nor is a
    // status code in a path.
    assert!(!is_sign_in(
            "git pull failed: fatal: Unable to create 'C:/ws/gitstate/.git/index.lock': Permission denied"
        ));
    assert!(!is_sign_in(
            "git fetch failed: fatal: 'C:\\shares\\403\\history.git' does not appear to be a git repository"
        ));
    assert!(!is_sign_in(
        "fatal: unable to access 'https://h/team/401/x.git/': Could not resolve host: h"
    ));
    // ssh's and the remote's own are.
    assert!(is_sign_in(
            "git fetch failed: git@github.com: Permission denied (publickey).\nfatal: Could not read from remote repository."
        ));
    assert!(is_sign_in(
            "git push failed: remote: Permission to team/history.git denied to someone.\nfatal: unable to access 'https://github.com/team/history.git/': The requested URL returned error: 403"
        ));
    // Azure DevOps, ssh's password prompts, HTTP/2.
    assert!(is_sign_in(
            "remote: TF401019: The Git repository with name or identifier history does not exist or you do not have permissions for the operation you are attempting."
        ));
    assert!(is_sign_in("git@host: Permission denied, please try again."));
    assert!(is_sign_in(
        "git@host: Permission denied (publickey,keyboard-interactive)."
    ));
    assert!(is_sign_in("< HTTP/2 401"));
    assert!(is_sign_in("< HTTP/2 403"));
    assert!(cancelled("fatal: A task was canceled."));
    // Not signed in, or refused: the account git gave wasn't let in.
    assert!(!refused(said));
    assert!(refused("remote: HTTP Basic: Access denied"));
    assert_eq!(
        classify(&failed(
            "git ls-remote failed: remote: HTTP Basic: Access denied"
        ))
        .lead(),
        REFUSED
    );
    // A refusal is no question of a helper.
    assert!(!no_helper("remote: HTTP Basic: Access denied", None));
    // Cancelled: Git Credential Manager's words, not a repository's name.
    assert!(cancelled("fatal: User canceled the authentication prompt."));
    assert!(!cancelled(
        "fatal: unable to access 'https://h/team/cancelled-orders.git/': Could not resolve host: h"
    ));
    assert!(cancelled(
        "fatal: User cancelled the authentication prompt."
    ));
    assert!(!cancelled(said));
    assert_eq!(
        Problem::SignIn {
            detail: said.into(),
            no_helper: true,
            refused: false,
        }
        .sentence(),
        "This computer isn't signed in to the repository. Git can't ask you to sign in. \
             Install Git for Windows (it includes Git Credential Manager), then look again."
    );
}

#[test]
fn run_ids_give_their_time() {
    assert_eq!(
        run_time("20261026T235100.000Z").map(crate::time::format_unix),
        Some("2026-10-26 23:51".to_string())
    );
    assert_eq!(run_time("nonsense"), None);
}

#[test]
fn sentences_are_complete() {
    for p in [
        Problem::Unreachable {
            detail: String::new(),
        },
        Problem::SignIn {
            detail: String::new(),
            no_helper: false,
            refused: false,
        },
        Problem::SignIn {
            detail: String::new(),
            no_helper: true,
            refused: false,
        },
        Problem::SignIn {
            detail: String::new(),
            no_helper: false,
            refused: true,
        },
        Problem::NoBranch {
            branch: "lab".into(),
            branches: vec!["main".into(), "archive".into()],
        },
        Problem::NotHistory { git: true },
        Problem::Empty { git: true },
        Problem::Newer {
            version: Some("0.2.3".into()),
        },
        Problem::NoFolder,
        Problem::BadDefaultBranch,
    ] {
        let s = p.sentence();
        assert!(s.ends_with('.'), "{s}");
        assert!(!s.contains('`'), "{s}");
    }
    assert_eq!(
        Problem::NoBranch {
            branch: "lab".into(),
            branches: vec!["archive".into(), "main".into()],
        }
        .sentence(),
        "The repository has no branch named lab. Its branches are archive and main."
    );
    assert_eq!(
        settings_words("[tier_zero]\nmembers = [\"x\"]\n[rules]\nx = 1\n[[zone]]\nname = \"a\"\n"),
        "Tier Zero additions, rule settings and zones. No accepted risks yet."
    );
    assert_eq!(
        settings_words("[[suppress]]\nrule = \"PW-1\"\n"),
        "1 accepted risk."
    );
}
