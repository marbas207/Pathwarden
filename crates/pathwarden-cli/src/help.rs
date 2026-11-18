//! The top-level help: commands grouped by what you're doing, a "start here"
//! line, and the exit codes, in 80 columns.
//!
//! clap lists subcommands in one flat block, so the top-level help uses a
//! template with the groups written in; each command's one-line description
//! still comes from its doc comment.

use clap::Command;

use crate::ui;

/// The help is laid out for this many columns.
pub const WIDTH: usize = 80;

/// Every command, by group, in the order listed. A test checks that each
/// command appears exactly once.
pub const GROUPS: &[(&str, &[&str])] = &[
    ("Getting started", &["demo", "ui", "report"]),
    ("Collect", &["collect", "diagnose"]),
    (
        "Analyze",
        &[
            "posture",
            "findings",
            "plan",
            "path",
            "reach",
            "search",
            "exposure",
            "choke-points",
            "tier-zero",
            "summary",
            "query",
            "owned",
        ],
    ),
    (
        "Track & retest",
        &["retest", "history", "runs", "changes", "label", "evidence"],
    ),
    (
        "Configure & automate",
        &[
            "run", "env", "config", "zones", "mappings", "plugins", "action", "schedule", "export",
            "rules", "guide",
        ],
    ),
];

const FOOTER: &str = "\
New here? `pathwarden demo` writes a sample report; `pathwarden ui` opens the
app. Any command that reads data also takes `-i demo:`.

Exit status (every command): 0 OK, 1 findings at or above --fail-on (or
still open after a retest), 2 error (usage or runtime), 3 can't tell.
`pathwarden <command> --help` gives the details.";

/// Applies the grouped help to the top-level command.
pub fn apply(cmd: Command) -> Command {
    let groups = render_groups(&cmd);
    let h = ui::VIOLET.bold();
    let template = format!(
        "{{before-help}}{{about-with-newline}}\n\
         {{usage-heading}} {{usage}}\n\n\
         {groups}\
         {h}Options:{h:#}\n{{options}}{{after-help}}"
    );
    cmd.help_template(template).after_help(FOOTER)
}

/// One style for every command's help: each description is a
/// sentence with its closing period (clap's derive drops the period of a
/// one-line doc comment), and a default reads "(default: X)" at the end of
/// its description, not clap's "[default: X]"; an empty default isn't
/// shown at all.
pub fn polish(cmd: Command) -> Command {
    let cmd = match cmd.get_about().map(|a| a.to_string()) {
        Some(a) if needs_period(&a) => cmd.about(format!("{a}.")),
        _ => cmd,
    };
    let cmd = cmd.mut_args(|a| {
        let defaults: Vec<String> =
            if a.get_action().takes_values() && !a.is_hide_default_value_set() {
                a.get_default_values()
                    .iter()
                    .map(|v| v.to_string_lossy().into_owned())
                    .collect()
            } else {
                Vec::new()
            };
        let shown = defaults.join(", ");
        let finish = |text: String| -> String {
            let text = text.trim_end().to_string();
            let text = if shown.is_empty() {
                text
            } else {
                format!("{} (default: {shown})", text.trim_end_matches('.'))
            };
            if needs_period(&text) {
                format!("{text}.")
            } else {
                text
            }
        };
        let help = a.get_help().map(|h| finish(h.to_string()));
        let long = a.get_long_help().map(|h| finish(h.to_string()));
        let mut a = a;
        if let Some(h) = help {
            a = a.help(h);
        }
        if let Some(h) = long {
            a = a.long_help(h);
        }
        if !defaults.is_empty() && (a.get_help().is_some() || a.get_long_help().is_some()) {
            a = a.hide_default_value(true);
        }
        a
    });
    cmd.mut_subcommands(polish)
}

/// Whether `text` lacks its closing period.
fn needs_period(text: &str) -> bool {
    let t = text.trim_end();
    !t.is_empty() && !t.ends_with(['.', '!', '?', ':'])
}

fn render_groups(cmd: &Command) -> String {
    let (h, lit) = (ui::VIOLET.bold(), ui::GREEN.bold());
    let name_width = GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|n| n.len())
        .max()
        .unwrap_or(0);
    let indent = 2 + name_width + 2;
    let mut out = String::new();
    for (title, names) in GROUPS {
        out.push_str(&format!("{h}{title}:{h:#}\n"));
        for name in *names {
            let about = cmd
                .find_subcommand(name)
                .and_then(|s| s.get_about())
                .map(|a| a.to_string())
                .unwrap_or_default();
            let mut lines = wrap(&about, WIDTH - indent).into_iter();
            let first = lines.next().unwrap_or_default();
            out.push_str(&format!("  {lit}{name:<name_width$}{lit:#}  {first}\n"));
            for line in lines {
                out.push_str(&format!("{:indent$}{line}\n", ""));
            }
        }
        out.push('\n');
    }
    out
}

/// Word wrap to `width` columns (words longer than that stay whole).
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_at_word_boundaries() {
        assert_eq!(wrap("aa bb cc", 5), ["aa bb", "cc"]);
        assert_eq!(wrap("", 5), Vec::<String>::new());
        assert_eq!(wrap("toolongword x", 4), ["toolongword", "x"]);
    }
}
