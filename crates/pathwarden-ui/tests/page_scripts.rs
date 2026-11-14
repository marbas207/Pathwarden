//! The page scripts' parts that work without the server (`zipDomains`,
//! the where/ask state machine, the Collect page's progress view,
//! Explore's bundles and edge styles): `tests/js/app.test.mjs`,
//! `tests/js/collect.test.mjs` and `tests/js/explore.test.mjs`, run with Node
//! when it is installed and has what the tests use (`File` and
//! `DecompressionStream("deflate-raw")`: Node 20.12 or later), skipped
//! with a note when it hasn't.

use std::path::PathBuf;
use std::process::Command;

/// What the tests need from Node, tried rather than read off the version.
const NEEDS: &str = "new File([], 'x'); new DecompressionStream('deflate-raw');";

#[test]
fn page_scripts_pass_their_node_tests() {
    let version = match Command::new("node").arg("--version").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            eprintln!("node not found: the page script tests (tests/js) were skipped");
            return;
        }
    };
    let able = Command::new("node")
        .args(["-e", NEEDS])
        .output()
        .is_ok_and(|o| o.status.success());
    if !able {
        eprintln!(
            "node {version} lacks File or DecompressionStream(\"deflate-raw\") (Node 20.12 or later has both): the page script tests were skipped"
        );
        return;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/js");
    let out = Command::new("node")
        .arg("--test")
        .arg(dir.join("app.test.mjs"))
        .arg(dir.join("collect.test.mjs"))
        .arg(dir.join("explore.test.mjs"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
