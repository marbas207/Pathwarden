//! Terminal presentation: the banner (drawn in `logo`), brand colors and
//! severity styles.
//!
//! All output goes through `anstream`, which drops color codes when stdout is
//! not a terminal (pipes, files, `--json` consumers) or `NO_COLOR` is set, and
//! turns on escape-code support in Windows consoles. `CLICOLOR_FORCE=1` forces
//! color on.

use anstyle::{AnsiColor, Color, RgbColor, Style};
use clap::builder::Styles;
use pathwarden_core::findings::Severity;

pub const VIOLET: Style = Style::new().fg_color(Some(Color::Rgb(RgbColor(0x9D, 0x5C, 0xFF))));
pub const GREEN: Style = Style::new().fg_color(Some(Color::Rgb(RgbColor(0x7C, 0xE4, 0x6B))));
pub const BOLD: Style = Style::new().bold();
pub const DIM: Style = Style::new().dimmed();

/// The Crown W banner over the help, chosen for this terminal (see
/// [`crate::logo`]).
pub fn banner() -> String {
    crate::logo::banner()
}

/// Brand colors for clap's help output.
pub fn help_styles() -> Styles {
    Styles::styled()
        .header(VIOLET.bold())
        .usage(VIOLET.bold())
        .literal(GREEN.bold())
        .placeholder(DIM)
}

/// Standard terminal colors (not RGB) so severities stay readable on any theme.
pub fn severity(s: Severity) -> Style {
    let fg = |c: AnsiColor| Style::new().fg_color(Some(Color::Ansi(c)));
    match s {
        Severity::Critical => fg(AnsiColor::BrightRed).bold(),
        Severity::High => fg(AnsiColor::Red),
        Severity::Medium => fg(AnsiColor::Yellow),
        Severity::Low => fg(AnsiColor::Cyan),
        Severity::Info => DIM,
    }
}

/// Directory-controlled text (names, titles, plugin output) made safe for a
/// terminal: control characters and bidi controls are shown escaped, so an
/// AD name can't recolor, erase or forge output. Use it for every value
/// that did not come from Pathwarden itself.
pub fn safe(s: &str) -> std::borrow::Cow<'_, str> {
    pathwarden_core::text::terminal_safe(s)
}

/// [`safe`] for text of several lines (finding summaries and fixes).
pub fn safe_text(s: &str) -> std::borrow::Cow<'_, str> {
    pathwarden_core::text::terminal_safe_text(s)
}
