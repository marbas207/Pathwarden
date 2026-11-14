//! Pathwarden findings in formats other tools import:
//!
//! - [`sarif`]: SARIF 2.1.0 (OASIS), for SARIF viewers and vulnerability
//!   platforms. Rules come with their step-by-step guide as help text, the
//!   finding fingerprint is a partial fingerprint, accepted risks are
//!   suppressions.
//! - [`defectdojo`]: DefectDojo's "Generic Findings Import" JSON, with the
//!   fingerprint as `unique_id_from_tool` so a reimport deduplicates and
//!   closes findings that are gone.
//!
//! Both read a [`Doc`]: the findings of one run, from an event document
//! (`pathwarden.event.v1`, what `pathwarden run --event` writes) or built by
//! the caller from a fresh analysis. This crate does not depend on the
//! analysis engine; it only knows the event format, which only ever grows.

#![forbid(unsafe_code)]

pub mod defectdojo;
mod doc;
pub mod sarif;

pub use doc::{Affected, Doc, Exposure, Finding, Path, Step};

/// Where Pathwarden lives, for `informationUri` and help links.
pub const HOMEPAGE: &str = "https://github.com/marbas207/Pathwarden";

/// The formats findings export to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// SARIF 2.1.0 (OASIS).
    Sarif,
    /// DefectDojo "Generic Findings Import" JSON.
    Defectdojo,
}

impl Format {
    /// The file extension: `sarif` or `json`.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Sarif => "sarif",
            Format::Defectdojo => "json",
        }
    }
}

/// The export file's text, as `pathwarden export` writes it (pretty JSON
/// and a final newline).
pub fn text(doc: &Doc, format: Format) -> anyhow::Result<String> {
    let value = match format {
        Format::Sarif => sarif::sarif(doc),
        Format::Defectdojo => defectdojo::defectdojo(doc),
    };
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    Ok(text)
}

/// `YYYY-MM-DD` for a Unix time (UTC), without a date library.
pub fn date(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time (UTC).
pub fn timestamp(unix: i64) -> String {
    let secs = unix.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date(unix),
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(timestamp(1_791_512_129), "2026-10-09T02:15:29Z");
        assert_eq!(date(-1), "1969-12-31");
    }
}
