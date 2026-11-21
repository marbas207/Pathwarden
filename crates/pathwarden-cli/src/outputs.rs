//! Output plugins: separate programs that receive the run's event document
//! (`pathwarden.event.v1`) on stdin and their settings as JSON in
//! `PATHWARDEN_OUTPUT_SETTINGS`.
//!
//! Finding, checking and running a plugin lives in
//! [`pathwarden_core::plugins`] (the local UI's "Test" button uses it too);
//! this prints what the plugin said, tagged with its name, and reads what
//! it reported in its result file ([`pathwarden_core::output_result`]).

use anstream::println;
use anyhow::{bail, Result};
use pathwarden_core::config::OutputConfig;
use pathwarden_core::output_result::{self, Reported};
use pathwarden_core::plugins;

/// Runs `output` on the event. What it reported in its result file, when
/// it wrote one and exited well; a result that can't be read is a
/// warning line, never a failed plugin.
pub fn run(output: &OutputConfig, event_json: &str) -> Result<Option<Reported>> {
    let run = plugins::run_reporting(output, event_json)?;
    let tag = crate::ui::VIOLET;
    for line in run.ran.lines() {
        // Plugin output can relay what other systems said (ticket numbers, errors).
        println!(
            "  {tag}[{}]{tag:#} {}",
            crate::ui::safe(&output.plugin),
            crate::ui::safe(&line)
        );
    }
    if !run.ran.status.success() {
        bail!("exited with {}", run.ran.status);
    }
    let (reported, warning) = output_result::read_result(output, run.result);
    if let Some(w) = warning {
        let warn = crate::ui::severity(pathwarden_core::findings::Severity::Medium);
        anstream::eprintln!(
            "  {warn}Plugin {}:{warn:#} {}",
            crate::ui::safe(&output.plugin),
            crate::ui::safe_text(&w)
        );
    }
    Ok(reported)
}
