//! The built-in demo: `pathwarden demo`, and `-i demo:` on any command that
//! reads collector data.
//!
//! The demo collection (a made-up company) is built into the binary, the same
//! one the UI's "Try the demo" uses, so it works with nothing but the
//! executable. It is written to a fresh private folder in the temp directory
//! for the analysis to read, and removed when the command ends.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use pathwarden_ui::server::{DEMO_NAME, DEMO_ZIP};

/// The input that stands for the built-in demo collection.
pub const INPUT: &str = "demo:";

/// The demo collection written to disk; the folder is removed on drop.
pub struct DemoData {
    dir: PathBuf,
    pub zip: PathBuf,
}

impl Drop for DemoData {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Writes the demo collection to a new folder in the temp directory. The
/// file keeps its collector name, which carries the collection time.
pub fn unpack() -> Result<DemoData> {
    let dir = fresh_temp_dir("pathwarden-demo")?;
    let zip = dir.join(DEMO_NAME);
    let data = DemoData { dir, zip };
    std::fs::write(&data.zip, DEMO_ZIP)
        .with_context(|| format!("writing the demo collection to {}", data.zip.display()))?;
    Ok(data)
}

/// Replaces every `demo:` among `inputs` with the unpacked demo collection.
/// Returns the unpacked data (keep it alive while the inputs are read), or
/// `None` when no input asked for the demo.
pub fn resolve(inputs: &mut [PathBuf]) -> Result<Option<DemoData>> {
    if !inputs.iter().any(|p| is_demo(p)) {
        return Ok(None);
    }
    let data = unpack()?;
    for p in inputs.iter_mut().filter(|p| is_demo(p)) {
        p.clone_from(&data.zip);
    }
    Ok(Some(data))
}

fn is_demo(p: &Path) -> bool {
    p.as_os_str().eq_ignore_ascii_case(INPUT)
}

/// A new, empty folder in the temp directory that did not exist before (so
/// nothing another user planted there is read or overwritten), private to
/// this account on Unix.
pub fn fresh_temp_dir(prefix: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let mut last = None;
    for attempt in 0..16u32 {
        let dir = base.join(format!(
            "{prefix}-{}-{:08x}",
            std::process::id(),
            nanos.wrapping_add(attempt.wrapping_mul(0x9E37_79B9))
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => {
                return Err(e).with_context(|| format!("creating a folder in {}", base.display()))
            }
        }
    }
    Err(last.expect("at least one attempt"))
        .with_context(|| format!("creating a folder in {}", base.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_the_demo_input_and_cleans_up() {
        let mut inputs = vec![PathBuf::from("a.zip"), PathBuf::from("DEMO:")];
        let data = resolve(&mut inputs).unwrap().expect("demo requested");
        assert_eq!(inputs[0], PathBuf::from("a.zip"));
        assert_eq!(inputs[1], data.zip);
        assert_eq!(std::fs::read(&data.zip).unwrap().len(), DEMO_ZIP.len());
        let dir = data.dir.clone();
        drop(data);
        assert!(!dir.exists());

        let mut plain = vec![PathBuf::from("demo")];
        assert!(
            resolve(&mut plain).unwrap().is_none(),
            "a folder named demo is not the demo"
        );
    }
}
