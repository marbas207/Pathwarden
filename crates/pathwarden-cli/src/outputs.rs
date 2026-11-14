//! Output plugins: separate programs that receive the run's event document
//! (`pathwarden.event.v1`) on stdin and their settings as JSON in
//! `PATHWARDEN_OUTPUT_SETTINGS`.
//!
//! Finding, checking and running a plugin lives in
//! [`pathwarden_core::plugins`] (the local UI's "Test" button uses it too);
//! this prints what the plugin said, tagged with its name.

use anstream::println;
use anyhow::{bail, Result};
use pathwarden_core::config::OutputConfig;
use pathwarden_core::plugins;

pub fn run(output: &OutputConfig, event_json: &str) -> Result<()> {
    let ran = plugins::run(output, event_json, None)?;
    let tag = crate::ui::VIOLET;
    for line in ran.lines() {
        // Plugin output can relay what other systems said (ticket numbers, errors).
        println!(
            "  {tag}[{}]{tag:#} {}",
            crate::ui::safe(&output.plugin),
            crate::ui::safe(&line)
        );
    }
    if !ran.status.success() {
        bail!("exited with {}", ran.status);
    }
    Ok(())
}
