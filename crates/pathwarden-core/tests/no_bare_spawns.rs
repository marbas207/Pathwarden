//! Every program Pathwarden starts comes from `pathwarden_core::spawn`
//! (`quiet`, or `detached` for the browser), which on Windows keeps a
//! console program from opening a console window of its own once
//! Pathwarden has let go of its console (a double-click). A bare
//! `Command::new` anywhere in the workspace's sources, or a
//! `tokio::process` command, would flash a window: this test names it.
//!
//! Integration tests (`crates/*/tests`) are not checked: they run under
//! `cargo test`'s console, never from Explorer.

use std::path::{Path, PathBuf};

/// The one file allowed to make a `Command` itself.
const ALLOWED: &[&str] = &["crates/pathwarden-core/src/spawn.rs"];

const FORBIDDEN: &[&str] = &["Command::new", "tokio::process"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn every_spawn_goes_through_the_quiet_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let crates = root.join("crates");
    let mut files = Vec::new();
    for c in std::fs::read_dir(&crates).expect("crates folder").flatten() {
        rust_files(&c.path().join("src"), &mut files);
        let build = c.path().join("build.rs");
        if build.is_file() {
            files.push(build);
        }
    }
    assert!(
        files.len() > 50,
        "found the workspace's sources ({} files)",
        files.len()
    );
    let mut bad = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if FORBIDDEN.iter().any(|w| line.contains(w)) {
                bad.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "start programs with pathwarden_core::spawn::quiet (or spawn::detached for \
         a browser window), never Command::new: a console program started without \
         CREATE_NO_WINDOW flashes a console window once Pathwarden has freed its \
         console (see crates/pathwarden-core/src/spawn.rs):\n{}",
        bad.join("\n")
    );
}
