//! The Crown W in the terminal: the banner over the help and the one-line
//! header of `pathwarden ui` and `pathwarden demo`.
//!
//! The mark is line art: one zig-zag node path (box-drawing diagonals, flat
//! `▁` valley floors) with violet end nodes, a green jewel on top and a solid
//! band, the path shaded violet to green as in the brand files. What is
//! drawn depends on the terminal:
//!
//! - **Hero** (80 columns or more): the mark with the name, the tagline and
//!   the version beside it, 6 lines.
//! - **Compact** (narrower): a jewel and the name on one line, the tagline
//!   under it.
//! - **ASCII**: the same shapes in 7-bit ASCII (`o / \ _ =`) when the terminal
//!   can't be trusted with Unicode, or color is off (`NO_COLOR`, `TERM=dumb`).
//! - **Nothing** when stdout is not a terminal (pipes, logs, `--json`
//!   consumers): the help starts with one plain line naming the program.
//!
//! Colors are truecolor where the terminal says so (`COLORTERM`, Windows
//! Terminal, VS Code, iTerm2...), the 256-color palette for `*-256color`
//! terminals, and the 16 standard colors otherwise. `NO_COLOR`, `CLICOLOR=0`
//! and `CLICOLOR_FORCE` are honored as everywhere else in the CLI.

use std::io::IsTerminal;

/// The mark, 19 columns by 6 lines.
pub const MARK: [&str; 6] = [
    "         ●         ",
    "●       ╱ ╲       ●",
    " ╲     ╱   ╲     ╱ ",
    "  ╲   ╱     ╲   ╱  ",
    "   ╲▁╱       ╲▁╱   ",
    "  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ",
];

/// The mark in 7-bit ASCII, on the same grid.
pub const MARK_ASCII: [&str; 6] = [
    "         o         ",
    "o       / \\       o",
    " \\     /   \\     / ",
    "  \\   /     \\   /  ",
    "   \\_/       \\_/   ",
    "  ===============  ",
];

const MARK_COLS: usize = 19;
/// Columns the hero needs: indent, mark, gap and the longest text line.
pub const HERO_COLS: usize = 80;
const INDENT: &str = "  ";
const GAP: &str = "    ";

pub const NAME: &str = "Pathwarden";
pub const TAGLINE: &str = "Defend every path to privilege.";
const ABOUT: &str = "attack path management for AD and Entra";

type Rgb = (u8, u8, u8);
const VIOLET: Rgb = (0x9D, 0x5C, 0xFF);
const GREEN: Rgb = (0x7C, 0xE4, 0x6B);

/// How many colors the terminal shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    None,
    Ansi16,
    Ansi256,
    True,
}

/// What the banner may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Whether to draw a logo at all (stdout is a terminal, or color is
    /// forced).
    pub show: bool,
    pub depth: Depth,
    pub unicode: bool,
    pub width: usize,
}

/// Which logo [`Caps`] select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// One plain line, no art (not a terminal).
    Plain,
    Hero,
    Compact,
    HeroAscii,
    CompactAscii,
}

impl Caps {
    pub fn variant(&self) -> Variant {
        let wide = self.width >= HERO_COLS;
        match (self.show, self.unicode, wide) {
            (false, _, _) => Variant::Plain,
            (true, true, true) => Variant::Hero,
            (true, true, false) => Variant::Compact,
            (true, false, true) => Variant::HeroAscii,
            (true, false, false) => Variant::CompactAscii,
        }
    }
}

/// The environment variables the choice depends on.
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub no_color: bool,
    /// `CLICOLOR=0`.
    pub clicolor_off: bool,
    pub clicolor_force: bool,
    pub colorterm: String,
    pub term: String,
    pub term_program: String,
    /// Windows Terminal (`WT_SESSION`).
    pub wt_session: bool,
    /// ConEmu / Cmder with ANSI on (`ConEmuANSI=ON`).
    pub conemu: bool,
    /// `LC_ALL`, else `LC_CTYPE`, else `LANG`.
    pub locale: String,
    pub columns: Option<usize>,
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

impl Env {
    pub fn read() -> Env {
        let set = |name: &str| !var(name).is_empty();
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .map(|n| var(n))
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        Env {
            no_color: set("NO_COLOR"),
            clicolor_off: var("CLICOLOR") == "0",
            clicolor_force: set("CLICOLOR_FORCE") && var("CLICOLOR_FORCE") != "0",
            colorterm: var("COLORTERM"),
            term: var("TERM"),
            term_program: var("TERM_PROGRAM"),
            wt_session: set("WT_SESSION"),
            conemu: var("ConEmuANSI").eq_ignore_ascii_case("on"),
            locale,
            columns: var("COLUMNS").trim().parse().ok().filter(|&c| c > 0),
        }
    }
}

/// The terminal stdout writes to.
#[derive(Clone, Copy, Debug)]
pub struct Terminal {
    pub tty: bool,
    pub width: Option<usize>,
    pub windows: bool,
    /// Windows only: escape sequences are on in this console.
    pub vt: bool,
}

impl Terminal {
    pub fn stdout() -> Terminal {
        let tty = std::io::stdout().is_terminal();
        let width = terminal_size::terminal_size().map(|(w, _)| w.0 as usize);
        let windows = cfg!(windows);
        // Turning on escape sequences is what tells a Windows 10+ console
        // from an older one; anstream does the same for every colored line.
        let vt = !windows || (tty && anstyle_query::windows::enable_ansi_colors().unwrap_or(false));
        Terminal {
            tty,
            width,
            windows,
            vt,
        }
    }
}

/// Terminals that draw truecolor and box drawing well whatever `TERM` says.
const MODERN: &[&str] = &[
    "vscode",
    "iTerm.app",
    "WezTerm",
    "ghostty",
    "Hyper",
    "Tabby",
    "rio",
];

fn utf8_locale(locale: &str) -> bool {
    let l = locale.to_ascii_lowercase();
    l.contains("utf-8") || l.contains("utf8")
}

/// Chooses what the banner may use.
pub fn caps(env: &Env, t: &Terminal) -> Caps {
    let show = t.tty || env.clicolor_force;
    let modern = env.wt_session || MODERN.contains(&env.term_program.as_str());
    let dumb = env.term == "dumb";
    let off = env.no_color || (env.clicolor_off && !env.clicolor_force);
    let depth = if !show || off || dumb || (t.windows && !t.vt && !env.clicolor_force) {
        Depth::None
    } else if matches!(env.colorterm.as_str(), "truecolor" | "24bit") || modern {
        Depth::True
    } else if env.term.contains("256color") {
        Depth::Ansi256
    } else if t.windows && env.term.is_empty() {
        // A Windows 10+ console with escape sequences on draws 24-bit color.
        Depth::True
    } else if env.term.is_empty() {
        Depth::None
    } else {
        Depth::Ansi16
    };
    // Unicode art needs a font with box drawing: Windows Terminal, ConEmu
    // and the modern terminals have one; the classic Windows console's
    // Consolas lacks `▁`, so it gets ASCII. Elsewhere a UTF-8 locale is the
    // signal; the Linux text console (TERM=linux) has too few glyphs. The
    // plain variant is for no color too (NO_COLOR, dumb terminals, logs).
    let unicode_font = if t.windows {
        modern || env.conemu || (!env.term.is_empty() && utf8_locale(&env.locale))
    } else {
        modern || utf8_locale(&env.locale)
    };
    let unicode = depth != Depth::None && unicode_font && env.term != "linux";
    let width = t.width.or(env.columns).unwrap_or(HERO_COLS);
    Caps {
        show,
        depth,
        unicode,
        width,
    }
}

/// What this process's stdout may use.
pub fn detect() -> Caps {
    caps(&Env::read(), &Terminal::stdout())
}

// ------------------------------------------------------------------ colors

const RESET: &str = "\x1b[0m";

/// The brand gradient at `t` (0 at an end node, 1 at the jewel), with the
/// brand file's stops: violet to 22%, green from 90%.
fn gradient(t: f32) -> Rgb {
    let k = ((t - 0.22) / (0.90 - 0.22)).clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * k).round() as u8;
    (
        mix(VIOLET.0, GREEN.0),
        mix(VIOLET.1, GREEN.1),
        mix(VIOLET.2, GREEN.2),
    )
}

/// The nearest color of the xterm 256-color palette (cube or grey ramp).
pub fn ansi256((r, g, b): Rgb) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let level = |v: u8| {
        (0..6)
            .min_by_key(|&i| (LEVELS[i] as i32 - v as i32).abs())
            .unwrap_or(0)
    };
    let dist = |c: Rgb| {
        let d = |a: u8, b: u8| (a as i32 - b as i32).pow(2);
        d(c.0, r) + d(c.1, g) + d(c.2, b)
    };
    let (ri, gi, bi) = (level(r), level(g), level(b));
    let cube = (LEVELS[ri], LEVELS[gi], LEVELS[bi]);
    let avg = (r as i32 + g as i32 + b as i32) / 3;
    let gi_ = ((avg - 8).max(0) / 10).min(23) as u8;
    let grey_v = 8 + gi_ * 10;
    if dist((grey_v, grey_v, grey_v)) < dist(cube) {
        232 + gi_
    } else {
        16 + 36 * ri as u8 + 6 * gi as u8 + bi as u8
    }
}

/// A foreground color: `t` is the place on the gradient, used for the 16
/// colors (violet half bright magenta, green half bright green).
fn fg(depth: Depth, c: Rgb, t: f32) -> String {
    match depth {
        Depth::None => String::new(),
        Depth::True => format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2),
        Depth::Ansi256 => format!("\x1b[38;5;{}m", ansi256(c)),
        Depth::Ansi16 => (if t < 0.5 { "\x1b[95m" } else { "\x1b[92m" }).to_string(),
    }
}

fn styled(depth: Depth, code: &str, s: &str) -> String {
    if depth == Depth::None {
        s.to_string()
    } else {
        format!("\x1b[{code}m{s}{RESET}")
    }
}

/// One line of the mark, colored: end nodes violet, the jewel green, the
/// band in the terminal's own text color (so it shows on light themes too),
/// the path shaded along its length.
fn mark_line(row: usize, line: &str, depth: Depth) -> String {
    let mid = MARK_COLS as f32 / 2.0;
    let mut out = String::new();
    for (x, ch) in line.chars().enumerate() {
        if ch == ' ' || depth == Depth::None {
            out.push(ch);
            continue;
        }
        let band = row == MARK.len() - 1;
        if band {
            out.push(ch);
            continue;
        }
        let jewel = row == 0;
        let node = matches!(ch, '●' | 'o') && !jewel;
        let (c, t) = if jewel {
            (GREEN, 1.0)
        } else if node {
            (VIOLET, 0.0)
        } else {
            let t = 1.0 - ((x as f32 + 0.5) - mid).abs() / mid;
            (gradient(t), t)
        };
        out.push_str(&fg(depth, c, t));
        out.push(ch);
        out.push_str(RESET);
    }
    out
}

/// "Pathwarden" shaded violet to green, bold.
fn name(depth: Depth) -> String {
    if depth == Depth::None {
        return NAME.to_string();
    }
    let n = NAME.len() as f32 - 1.0;
    let mut out = String::from("\x1b[1m");
    for (i, ch) in NAME.chars().enumerate() {
        // Start past the flat violet stop so every letter shifts a little.
        let t = 0.22 + 0.68 * i as f32 / n;
        out.push_str(&fg(depth, gradient(t), t));
        out.push(ch);
    }
    out.push_str(RESET);
    out
}

fn version_line(caps: &Caps) -> String {
    let dot = if caps.unicode { "·" } else { "-" };
    styled(
        caps.depth,
        "2",
        &format!("v{} {dot} {ABOUT}", env!("CARGO_PKG_VERSION")),
    )
}

/// The banner for these capabilities (no trailing newline).
pub fn render(caps: &Caps) -> String {
    let d = caps.depth;
    match caps.variant() {
        Variant::Plain => format!("{NAME} {}: {TAGLINE}", env!("CARGO_PKG_VERSION")),
        Variant::Hero | Variant::HeroAscii => {
            let art = if caps.unicode { &MARK } else { &MARK_ASCII };
            let text = [
                String::new(),
                String::new(),
                name(d),
                TAGLINE.to_string(),
                String::new(),
                version_line(caps),
            ];
            let lines: Vec<String> = art
                .iter()
                .enumerate()
                .map(|(row, line)| {
                    let t = &text[row];
                    let l = format!("{INDENT}{}", mark_line(row, line, d));
                    if t.is_empty() {
                        l.trim_end().to_string()
                    } else {
                        format!("{l}{GAP}{t}")
                    }
                })
                .collect();
            format!("\n{}", lines.join("\n"))
        }
        Variant::Compact | Variant::CompactAscii => {
            format!("{}\n{INDENT}{TAGLINE}", header_line(caps))
        }
    }
}

/// One line: the jewel, the name and the version, plus the tagline when
/// it fits.
pub fn header_line(caps: &Caps) -> String {
    let d = caps.depth;
    let jewel = if caps.unicode { "●" } else { "o" };
    let jewel = if d == Depth::None {
        jewel.to_string()
    } else {
        format!("{}{jewel}{RESET}", fg(d, GREEN, 1.0))
    };
    let version = styled(d, "2", &format!("v{}", env!("CARGO_PKG_VERSION")));
    format!("{jewel} {} {version}", name(d))
}

/// The banner for this terminal.
pub fn banner() -> String {
    render(&detect())
}

/// The one-line header for commands that start something (`ui`, `demo`),
/// or `None` when stdout is not a terminal.
pub fn header() -> Option<String> {
    let caps = detect();
    if !caps.show {
        return None;
    }
    let dot = if caps.unicode { "·" } else { "-" };
    let line = header_line(&caps);
    // "● Pathwarden v0.0.0 · Defend every path to privilege."
    let full = 2 + NAME.len() + 2 + env!("CARGO_PKG_VERSION").len() + 3 + TAGLINE.len();
    Some(if caps.width > full {
        format!("{line} {dot} {TAGLINE}")
    } else {
        line
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(tty: bool, width: usize, windows: bool) -> Terminal {
        Terminal {
            tty,
            width: Some(width),
            windows,
            vt: true,
        }
    }

    fn utf8() -> Env {
        Env {
            term: "xterm-256color".into(),
            locale: "en_US.UTF-8".into(),
            ..Env::default()
        }
    }

    /// Visible width: escape sequences removed, characters counted.
    fn visible(s: &str) -> usize {
        let mut n = 0;
        let mut esc = false;
        for ch in s.chars() {
            match (esc, ch) {
                (false, '\x1b') => esc = true,
                (true, 'm') => esc = false,
                (true, _) => {}
                (false, _) => n += 1,
            }
        }
        n
    }

    #[test]
    fn the_marks_share_one_grid() {
        for (u, a) in MARK.iter().zip(MARK_ASCII) {
            assert_eq!(u.chars().count(), MARK_COLS);
            assert_eq!(a.len(), MARK_COLS);
            // Same shape: blank where the other is blank.
            for (cu, ca) in u.chars().zip(a.chars()) {
                assert_eq!(cu == ' ', ca == ' ', "{u:?} / {a:?}");
            }
        }
    }

    #[test]
    fn depth_follows_the_environment() {
        let t = term(true, 120, false);
        assert_eq!(caps(&utf8(), &t).depth, Depth::Ansi256);
        let e = Env {
            colorterm: "truecolor".into(),
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::True);
        let e = Env {
            term: "xterm".into(),
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::Ansi16);
        let e = Env {
            no_color: true,
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::None);
        let e = Env {
            clicolor_off: true,
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::None);
        let e = Env {
            term: "dumb".into(),
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::None);
        // Windows Terminal and VS Code draw truecolor whatever TERM says.
        let e = Env {
            wt_session: true,
            ..Env::default()
        };
        assert_eq!(caps(&e, &term(true, 120, true)).depth, Depth::True);
        let e = Env {
            term_program: "vscode".into(),
            term: "xterm".into(),
            ..utf8()
        };
        assert_eq!(caps(&e, &t).depth, Depth::True);
        // A Windows console without escape sequences: no color.
        let old = Terminal {
            vt: false,
            ..term(true, 120, true)
        };
        assert_eq!(caps(&Env::default(), &old).depth, Depth::None);
    }

    #[test]
    fn variant_follows_terminal_unicode_and_width() {
        let t = term(true, 120, false);
        let tc = Env {
            colorterm: "truecolor".into(),
            ..utf8()
        };
        assert_eq!(caps(&tc, &t).variant(), Variant::Hero);
        assert_eq!(
            caps(&tc, &term(true, 79, false)).variant(),
            Variant::Compact
        );
        assert_eq!(caps(&tc, &term(true, 80, false)).variant(), Variant::Hero);
        // Not a terminal: no art, unless color is forced.
        assert_eq!(
            caps(&tc, &term(false, 120, false)).variant(),
            Variant::Plain
        );
        let forced = Env {
            clicolor_force: true,
            ..tc.clone()
        };
        assert_eq!(
            caps(&forced, &term(false, 120, false)).variant(),
            Variant::Hero
        );
        // No UTF-8 locale, the Linux console, NO_COLOR: ASCII.
        let c = Env {
            locale: "C".into(),
            ..tc.clone()
        };
        assert_eq!(caps(&c, &t).variant(), Variant::HeroAscii);
        let linux = Env {
            term: "linux".into(),
            ..utf8()
        };
        assert_eq!(caps(&linux, &t).variant(), Variant::HeroAscii);
        let nc = Env {
            no_color: true,
            ..tc.clone()
        };
        assert_eq!(caps(&nc, &t).variant(), Variant::HeroAscii);
        assert_eq!(
            caps(&nc, &term(true, 60, false)).variant(),
            Variant::CompactAscii
        );
        // Windows: Windows Terminal gets Unicode, the classic console ASCII.
        let wt = Env {
            wt_session: true,
            ..Env::default()
        };
        assert_eq!(caps(&wt, &term(true, 120, true)).variant(), Variant::Hero);
        assert_eq!(
            caps(&Env::default(), &term(true, 120, true)).variant(),
            Variant::HeroAscii
        );
        // Width: the terminal's, else COLUMNS, else 80.
        let cols = Env {
            columns: Some(60),
            clicolor_force: true,
            ..tc.clone()
        };
        let piped = Terminal {
            width: None,
            ..term(false, 0, false)
        };
        assert_eq!(caps(&cols, &piped).variant(), Variant::Compact);
    }

    #[test]
    fn ascii_fallback_is_plain_seven_bit_and_reads_as_the_crown() {
        let c = Caps {
            show: true,
            depth: Depth::None,
            unicode: false,
            width: 100,
        };
        let out = render(&c);
        assert!(out.is_ascii(), "{out}");
        assert!(!out.contains('\x1b'), "{out}");
        for piece in [
            "o       / \\       o",
            "\\_/       \\_/",
            "===============",
            NAME,
            TAGLINE,
        ] {
            assert!(out.contains(piece), "{piece} in\n{out}");
        }
        let compact = render(&Caps { width: 60, ..c });
        assert!(
            compact.is_ascii() && compact.starts_with("o Pathwarden v"),
            "{compact}"
        );
        assert!(compact.contains(TAGLINE));
    }

    #[test]
    fn every_variant_fits_its_width_and_size() {
        for depth in [Depth::None, Depth::Ansi16, Depth::Ansi256, Depth::True] {
            for unicode in [true, false] {
                for width in [HERO_COLS, 60] {
                    let c = Caps {
                        show: true,
                        depth,
                        unicode,
                        width,
                    };
                    let out = render(&c);
                    let lines: Vec<&str> = out.lines().collect();
                    for l in &lines {
                        assert!(visible(l) <= width, "{} > {width}: {l:?}", visible(l));
                    }
                    if width == HERO_COLS {
                        assert!((6..=9).contains(&lines.len()), "{out}");
                    } else {
                        assert!(lines.len() <= 2, "{out}");
                    }
                    assert_eq!(out.contains('\x1b'), depth != Depth::None);
                }
            }
        }
    }

    #[test]
    fn colors_match_the_depth() {
        let c = Caps {
            show: true,
            depth: Depth::True,
            unicode: true,
            width: 100,
        };
        let out = render(&c);
        assert!(out.contains("\x1b[38;2;157;92;255m●"), "violet end node");
        assert!(out.contains("\x1b[38;2;124;228;107m●"), "green jewel");
        let out = render(&Caps {
            depth: Depth::Ansi256,
            ..c
        });
        assert!(out.contains("\x1b[38;5;") && !out.contains("38;2;"));
        let out = render(&Caps {
            depth: Depth::Ansi16,
            ..c
        });
        assert!(out.contains("\x1b[95m●") && out.contains("\x1b[92m●"));
        assert!(!out.contains("38;5;") && !out.contains("38;2;"));
    }

    #[test]
    fn ansi256_picks_near_colors() {
        assert_eq!(ansi256((0, 0, 0)), 16);
        assert_eq!(ansi256((255, 255, 255)), 231);
        assert_eq!(ansi256((0x9D, 0x5C, 0xFF)), 16 + 36 * 3 + 6 + 5);
        assert_eq!(ansi256((128, 128, 128)), 244);
    }
}
