//! Live progress on stderr for `collect` and the analysis commands.
//!
//! On a terminal, a status of one to three lines is redrawn in place about
//! eight times a second: the step ("2/5"), a bar, the percentage, the elapsed
//! time and the time left, then (for collections) counts by type. Log lines
//! print above it. Elsewhere (pipes, files, CI logs) it prints a plain line
//! when the step changes and every few seconds, or nothing at all.
//!
//! The built-in collector (RustHound-CE) draws its own `indicatif` spinner
//! when stderr is a terminal. While Pathwarden draws its status, the
//! process's stderr points at the null device ([`Redirect`]) so that spinner
//! stays hidden, and the status goes to the real terminal through a handle
//! kept aside ([`ErrOut`]).

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anstyle::Style;
use pathwarden_collect::progress::{bytes, clock, thousands};
use pathwarden_collect::{Status, Step, Tracker};
use pathwarden_core::analyze::{self, Phase};

use crate::ui;

// ------------------------------------------------------------------ output

/// Where the status is written: the process's stderr, or the terminal it
/// had before [`Redirect`] pointed stderr elsewhere.
pub enum ErrOut {
    Std,
    #[cfg(windows)]
    Console(isize),
    #[cfg(unix)]
    Fd(std::fs::File),
    /// Captured text, for tests.
    #[cfg(test)]
    Buffer(Arc<Mutex<Vec<u8>>>),
}

impl ErrOut {
    fn write_str(&mut self, s: &str) {
        match self {
            ErrOut::Std => {
                let mut e = std::io::stderr().lock();
                let _ = e.write_all(s.as_bytes());
                let _ = e.flush();
            }
            #[cfg(windows)]
            ErrOut::Console(h) => win::write(*h, s),
            #[cfg(unix)]
            ErrOut::Fd(f) => {
                let _ = f.write_all(s.as_bytes());
                let _ = f.flush();
            }
            #[cfg(test)]
            ErrOut::Buffer(b) => b.lock().unwrap().extend_from_slice(s.as_bytes()),
        }
    }

    /// Whether plain lines written here may use typographic glyphs
    /// ([`glyphs_allowed`]).
    fn glyphs(&self) -> bool {
        match self {
            ErrOut::Std => glyphs_allowed(
                std::io::stderr().is_terminal(),
                std::env::var("PATHWARDEN_UTF8").ok().as_deref(),
                utf8_console_code_page(),
            ),
            // Only kept aside when it is a terminal.
            #[cfg(windows)]
            ErrOut::Console(_) => true,
            #[cfg(unix)]
            ErrOut::Fd(_) => true,
            #[cfg(test)]
            ErrOut::Buffer(_) => true,
        }
    }
}

/// Whether text for stderr may use typographic glyphs ("…", "·").
///
/// They are UTF-8. A Windows console shows them whatever its code page: the
/// standard library and [`win::write`] hand it UTF-16. A pipe or a file gets
/// the bytes, and whoever reads them on Windows often decodes them in the
/// console's code page instead (Windows PowerShell 5.1 with `2>&1` or
/// `2> file`, `Get-Content` of a log): "estimating…" came out as
/// "estimatingΓÇª" or "estimatingâ€¦". So on Windows, a stderr that is not a
/// console gets ASCII ("...") unless the console's output code page is
/// UTF-8 (65001). `PATHWARDEN_UTF8=1` or `=0` decides instead, on any
/// system. Elsewhere, UTF-8 as before.
fn glyphs_allowed(console: bool, env: Option<&str>, utf8_code_page: bool) -> bool {
    match env.map(str::trim) {
        Some("1") => true,
        Some("0") => false,
        _ => !cfg!(windows) || console || utf8_code_page,
    }
}

/// Whether this process's console decodes output as UTF-8 (false without a
/// console, e.g. in a scheduled task).
fn utf8_console_code_page() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: no arguments; returns 0 when there is no console.
        unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() == 65001 }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// `text` with the status's typographic glyphs in ASCII, for a stream that
/// may be read in a legacy code page ([`glyphs_allowed`]). Every other
/// character is left as it is.
pub fn ascii_glyphs(text: &str) -> std::borrow::Cow<'_, str> {
    fn ascii(c: char) -> Option<&'static str> {
        Some(match c {
            '\u{2026}' => "...",
            '\u{00b7}' | '\u{2013}' | '\u{2014}' | '\u{2591}' => "-",
            '\u{2192}' => "->",
            '\u{2713}' => "ok",
            '\u{2588}' => "#",
            '\u{258c}' | '\u{2580}' | '\u{2590}' | '\u{2584}' => "|",
            _ => return None,
        })
    }
    if !text.chars().any(|c| ascii(c).is_some()) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match ascii(c) {
            Some(a) => out.push_str(a),
            None => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Points this process's stderr at the null device until dropped.
pub struct Redirect {
    #[cfg(windows)]
    _null: std::fs::File,
}

/// The stderr a live [`Redirect`] replaced (a handle on Windows, a saved
/// descriptor on Unix). Taken by whichever restores it first: the guard's
/// drop, or the panic hook, so a panic message is not lost in the null
/// device.
static REPLACED: std::sync::Mutex<Option<isize>> = std::sync::Mutex::new(None);

fn restore_replaced() {
    let replaced = REPLACED.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(_original) = replaced {
        #[cfg(windows)]
        win::restore(_original);
        #[cfg(unix)]
        unix::restore(_original as i32);
    }
}

/// Puts stderr back before the default panic message is written.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_replaced();
            previous(info);
        }));
    });
}

impl Redirect {
    /// Redirects stderr and returns the guard plus a writer to the original
    /// stderr. `None` if that isn't possible (then nothing changed).
    pub fn stderr_to_null() -> Option<(Redirect, ErrOut)> {
        if REPLACED.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            return None; // one at a time
        }
        #[cfg(windows)]
        let redirected = win::redirect();
        #[cfg(unix)]
        let redirected = unix::redirect();
        #[cfg(not(any(windows, unix)))]
        let redirected: Option<(Redirect, ErrOut, isize)> = None;
        let (guard, out, original) = redirected?;
        *REPLACED.lock().unwrap_or_else(|e| e.into_inner()) = Some(original);
        install_panic_hook();
        Some((guard, out))
    }
}

impl Drop for Redirect {
    fn drop(&mut self) {
        restore_replaced();
    }
}

#[cfg(windows)]
mod win {
    use super::{ErrOut, Redirect};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, SetStdHandle, WriteConsoleW,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE,
    };

    pub(super) fn redirect() -> Option<(Redirect, ErrOut, isize)> {
        let null = std::fs::OpenOptions::new().write(true).open("NUL").ok()?;
        // SAFETY: plain Win32 calls on the process's own standard handles.
        unsafe {
            let original = GetStdHandle(STD_ERROR_HANDLE);
            if original.is_null() || original as isize == -1 {
                return None;
            }
            let mut mode = 0;
            if GetConsoleMode(original, &mut mode) != 0 {
                SetConsoleMode(original, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
            if SetStdHandle(STD_ERROR_HANDLE, null.as_raw_handle() as _) == 0 {
                return None;
            }
            Some((
                Redirect { _null: null },
                ErrOut::Console(original as isize),
                original as isize,
            ))
        }
    }

    pub(super) fn restore(original: isize) {
        // SAFETY: puts back the handle `redirect` replaced.
        unsafe {
            SetStdHandle(STD_ERROR_HANDLE, original as _);
        }
    }

    /// Writes to the console as UTF-16 (any code page), or as bytes to a
    /// pipe or file.
    pub(super) fn write(handle: isize, s: &str) {
        let h = handle as _;
        // SAFETY: `h` is the process's original stderr, which stays open.
        unsafe {
            let mut mode = 0;
            if GetConsoleMode(h, &mut mode) != 0 {
                let wide: Vec<u16> = s.encode_utf16().collect();
                let mut written = 0;
                WriteConsoleW(
                    h,
                    wide.as_ptr().cast(),
                    wide.len() as u32,
                    &mut written,
                    std::ptr::null(),
                );
            } else {
                use std::io::Write;
                use std::os::windows::io::FromRawHandle;
                let mut f = std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(h));
                let _ = f.write_all(s.as_bytes());
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::{ErrOut, Redirect};
    use std::os::fd::FromRawFd;

    pub(super) fn redirect() -> Option<(Redirect, ErrOut, isize)> {
        // SAFETY: dup/open/dup2 on this process's own descriptors.
        unsafe {
            let saved = libc::dup(2);
            if saved < 0 {
                return None;
            }
            let ours = libc::dup(saved);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
            if ours < 0 || null < 0 || libc::dup2(null, 2) < 0 {
                libc::close(saved);
                if ours >= 0 {
                    libc::close(ours);
                }
                if null >= 0 {
                    libc::close(null);
                }
                return None;
            }
            libc::close(null);
            Some((
                Redirect {},
                ErrOut::Fd(std::fs::File::from_raw_fd(ours)),
                saved as isize,
            ))
        }
    }

    pub(super) fn restore(saved: i32) {
        // SAFETY: puts back the descriptor `redirect` saved.
        unsafe {
            libc::dup2(saved, 2);
            libc::close(saved);
        }
    }
}

// -------------------------------------------------------------------- live

/// How progress is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Redrawn in place on a terminal.
    Live,
    /// A plain line on step changes and every so often.
    Plain(Duration),
    /// Nothing.
    Off,
}

/// Where the status comes from.
enum Source {
    /// Pushed by the collector a few times a second.
    Pushed(Option<(Status, Instant)>),
    /// Kept here (analysis): sampled on every redraw.
    Tracked(Tracker),
}

struct Shared {
    out: ErrOut,
    mode: Mode,
    color: bool,
    /// Plain lines may use "…" (else "..."; see [`glyphs_allowed`]).
    glyphs: bool,
    width: usize,
    /// What the job is ("Collecting contoso.local", "Analyzing").
    title: String,
    /// Show the second and third lines (units, counts by type).
    details: bool,
    source: Source,
    /// Lines of status on screen.
    drawn: usize,
    frame: usize,
    last_plain: Option<Instant>,
    last_plain_step: usize,
}

/// A live progress display. Updates come from the job's thread; a ticker
/// thread redraws (on a terminal) or prints plain lines when due.
pub struct Live {
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
}

const TICK: Duration = Duration::from_millis(120);
const SPINNER: [&str; 4] = ["\u{258c}", "\u{2580}", "\u{2590}", "\u{2584}"];
const BAR_CELLS: usize = 24;

impl Live {
    fn start(out: ErrOut, mode: Mode, title: String, details: bool, source: Source) -> Live {
        let color = mode == Mode::Live && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        let glyphs = out.glyphs();
        let shared = Arc::new(Mutex::new(Shared {
            out,
            mode,
            color,
            glyphs,
            width: terminal_width(),
            title,
            details,
            source,
            drawn: 0,
            frame: 0,
            last_plain: None,
            last_plain_step: 0,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let ticker = (mode != Mode::Off).then(|| {
            let (shared, stop) = (shared.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(mut s) = shared.lock() {
                        s.frame += 1;
                        s.refresh();
                    }
                    std::thread::sleep(TICK);
                }
            })
        });
        Live {
            shared,
            stop,
            ticker,
        }
    }

    fn with(&self, f: impl FnOnce(&mut Shared)) {
        if let Ok(mut s) = self.shared.lock() {
            f(&mut s);
        }
    }

    /// A new status from the collector.
    pub fn status(&self, status: Status) {
        self.with(|s| {
            let step_changed = match &s.source {
                Source::Pushed(Some((old, _))) => old.step != status.step,
                _ => true,
            };
            s.source = Source::Pushed(Some((status, Instant::now())));
            if step_changed {
                s.refresh();
            }
        });
    }

    /// Changes the tracked status (analysis).
    pub fn track(&self, f: impl FnOnce(&mut Tracker)) {
        self.with(|s| {
            if let Source::Tracked(t) = &mut s.source {
                let before = t.current();
                f(t);
                if t.current() != before {
                    s.refresh();
                }
            }
        });
    }

    /// A new title ("Collecting fabrikam.com (2 of 3)").
    pub fn title(&self, title: String) {
        self.with(|s| {
            s.title = title;
            s.refresh();
        });
    }

    /// A line printed above the status (or plainly).
    pub fn log(&self, line: &str) {
        self.with(|s| {
            if s.mode == Mode::Off {
                return;
            }
            let mut text = s.clear_text();
            text.push_str(line.trim_end());
            text.push('\n');
            s.out.write_str(&text);
            s.drawn = 0;
            if s.mode == Mode::Live {
                s.draw();
            }
        });
    }

    /// Stops and removes the status (a terminal is left as it was).
    pub fn finish(mut self) {
        self.end();
    }

    fn end(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
        self.with(|s| {
            let text = s.clear_text();
            s.out.write_str(&text);
            s.drawn = 0;
        });
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if self.ticker.is_some() {
            self.end();
        }
    }
}

/// `PATHWARDEN_PROGRESS=live|plain|off` overrides the choice (`live` draws
/// even when stderr is not a terminal, e.g. to record it).
fn forced_mode() -> Option<Mode> {
    match std::env::var("PATHWARDEN_PROGRESS").ok()?.trim() {
        "live" => Some(Mode::Live),
        "plain" => Some(Mode::Plain(Duration::from_secs(10))),
        "off" => Some(Mode::Off),
        _ => None,
    }
}

fn terminal_width() -> usize {
    if let Some(cols) = std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
    {
        return cols.clamp(40, 240);
    }
    terminal_size::terminal_size_of(std::io::stderr())
        .or_else(terminal_size::terminal_size)
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(100)
        .clamp(40, 240)
}

impl Shared {
    fn current(&mut self) -> Option<Status> {
        match &mut self.source {
            Source::Pushed(None) => None,
            Source::Pushed(Some((st, at))) => {
                let mut st = st.clone();
                // The clock keeps going between updates.
                let since = at.elapsed().as_secs();
                st.elapsed_secs += since;
                st.eta_secs = st.eta_secs.map(|e| e.saturating_sub(since));
                Some(st)
            }
            Source::Tracked(t) => Some(t.status()),
        }
    }

    fn refresh(&mut self) {
        match self.mode {
            Mode::Live => self.draw(),
            Mode::Plain(every) => {
                let Some(st) = self.current() else { return };
                let due = self.last_plain.is_none_or(|t| t.elapsed() >= every)
                    || st.step != self.last_plain_step;
                if due {
                    let mut line = plain_line(&self.title, &st);
                    if !self.glyphs {
                        line = ascii_glyphs(&line).into_owned();
                    }
                    self.out.write_str(&format!("{line}\n"));
                    self.last_plain = Some(Instant::now());
                    self.last_plain_step = st.step;
                }
            }
            Mode::Off => {}
        }
    }

    /// Moves to the start of the status and erases it.
    fn clear_text(&self) -> String {
        if self.mode != Mode::Live || self.drawn == 0 {
            return String::new();
        }
        let mut t = String::new();
        if self.drawn > 1 {
            t.push_str(&format!("\x1b[{}A", self.drawn - 1));
        }
        t.push_str("\r\x1b[J");
        t
    }

    fn draw(&mut self) {
        let Some(st) = self.current() else { return };
        let lines = live_lines(
            &self.title,
            &st,
            self.frame,
            self.width,
            self.details,
            self.color,
        );
        let mut text = self.clear_text();
        text.push_str(&lines.join("\n"));
        self.out.write_str(&text);
        self.drawn = lines.len();
    }
}

// ------------------------------------------------------------------ format

/// Text pieces with a style, cut to a width and rendered.
struct Line {
    parts: Vec<(String, Style)>,
}

impl Line {
    fn new() -> Self {
        Line { parts: Vec::new() }
    }

    fn push(&mut self, text: impl Into<String>, style: Style) -> &mut Self {
        self.parts.push((text.into(), style));
        self
    }

    fn render(&self, width: usize, color: bool) -> String {
        let mut left = width.saturating_sub(1);
        let mut out = String::new();
        for (text, style) in &self.parts {
            if left == 0 {
                break;
            }
            let piece: String = text.chars().take(left).collect();
            left -= piece.chars().count();
            if color && *style != Style::new() {
                out.push_str(&format!("{style}{piece}{style:#}"));
            } else {
                out.push_str(&piece);
            }
        }
        out
    }
}

fn eta_short(st: &Status) -> String {
    match st.eta_secs {
        _ if st.finished => "done".into(),
        None => "estimating\u{2026}".into(),
        Some(0) => "almost done".into(),
        Some(s) => format!("{} left", clock(s)),
    }
}

/// The terminal status: one line, then units and counts when `details`.
pub fn live_lines(
    title: &str,
    st: &Status,
    frame: usize,
    width: usize,
    details: bool,
    color: bool,
) -> Vec<String> {
    let dim = ui::DIM;
    let mut first = Line::new();
    first
        .push(SPINNER[frame % SPINNER.len()], ui::VIOLET)
        .push(format!(" {title} "), ui::BOLD)
        .push(format!("{}/{} ", st.step, st.steps), dim)
        .push(format!("{:<28}", st.phase), Style::new());
    let filled = ((st.percent / 100.0) * BAR_CELLS as f64).round() as usize;
    let filled = filled.min(BAR_CELLS);
    first
        .push("\u{2588}".repeat(filled), ui::VIOLET)
        .push("\u{2591}".repeat(BAR_CELLS - filled), dim)
        .push(
            if percent_known(st) {
                format!(" {:>3.0}%", st.percent.floor())
            } else {
                "   ?%".to_string()
            },
            ui::BOLD,
        )
        .push(format!("  {}", clock(st.elapsed_secs)), Style::new())
        .push(format!("  {}", eta_short(st)), dim);
    let mut lines = vec![first.render(width, color)];
    if !details {
        return lines;
    }
    let mut second = Line::new();
    let mut words = Vec::new();
    if let Some(d) = &st.detail {
        words.push(d.clone());
    }
    if let Some(u) = st.units_words() {
        words.push(u);
    }
    if let Some(r) = st.rate.filter(|r| *r >= 1.0) {
        if st.unit == "bytes" {
            words.push(format!("{}/s", bytes(r as u64)));
        } else {
            words.push(format!("{}/s", thousands(r as u64)));
        }
    }
    // A read in parts: its streams, as the app shows them.
    if let Some(p) = &st.parts {
        words.push(p.streams_words());
    }
    if !words.is_empty() {
        second.push(format!("  {}", words.join(" \u{00b7} ")), dim);
        lines.push(second.render(width, color));
    }
    let counts = counts_words(&st.objects, &st.expected);
    if !counts.is_empty() {
        let mut third = Line::new();
        third.push("  ", Style::new());
        for (i, (kind, n)) in counts.iter().enumerate() {
            if i > 0 {
                third.push("  ", Style::new());
            }
            third
                .push(kind.clone(), dim)
                .push(format!(" {n}"), Style::new());
        }
        lines.push(third.render(width, color));
    }
    lines
}

/// `[("users", "8,123 of ~15,000"), ...]`, most common types first. These
/// are entries read so far: containers and other entries mostly drop out in
/// processing, so they are left out until the written counts.
fn counts_words(
    objects: &BTreeMap<String, u64>,
    expected: &BTreeMap<String, u64>,
) -> Vec<(String, String)> {
    const ORDER: [&str; 7] = [
        "users",
        "computers",
        "groups",
        "ous",
        "gpos",
        "containers",
        "domains",
    ];
    let mut kinds: Vec<&String> = objects
        .keys()
        .chain(expected.keys())
        .filter(|k| !matches!(k.as_str(), "other" | "containers"))
        .collect();
    kinds.sort_by_key(|k| {
        (
            ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()),
            k.as_str() == "other",
            k.to_string(),
        )
    });
    kinds.dedup();
    kinds
        .into_iter()
        .map(|k| {
            let n = objects.get(k).copied().unwrap_or(0);
            let words = match expected.get(k) {
                Some(&e) if e >= n => format!("{} of ~{}", thousands(n), thousands(e)),
                _ => thousands(n),
            };
            (k.clone(), words)
        })
        .collect()
}

/// Whether the overall percentage means something: not while a step counts
/// without knowing its total (SharpHound when the domain could not be
/// counted first), where it would sit still.
fn percent_known(st: &Status) -> bool {
    st.finished || st.step_percent.is_some() || st.done == 0
}

/// One line for logs: `Collecting contoso.local [2/5] Reading the
/// directory: 15,870 of about 29,400 objects, 4 streams, 54%, 2:13 elapsed,
/// 1:50 left`.
pub fn plain_line(title: &str, st: &Status) -> String {
    let mut parts = Vec::new();
    if let Some(u) = st.units_words() {
        parts.push(u);
    }
    if let Some(p) = &st.parts {
        parts.push(p.streams_words());
    }
    if percent_known(st) {
        parts.push(format!("{:.0}%", st.percent.floor()));
    }
    parts.push(format!("{} elapsed", clock(st.elapsed_secs)));
    parts.push(eta_short(st));
    format!(
        "{title} [{}/{}] {}: {}",
        st.step,
        st.steps,
        st.phase,
        parts.join(", ")
    )
}

// ----------------------------------------------------------------- collect

/// A disk too full for the read, or a read that stopped and can be resumed,
/// with what the command line can do about it.
pub(crate) fn no_space_hint(e: anyhow::Error) -> anyhow::Error {
    if let Some(n) = e.downcast_ref::<pathwarden_collect::NoSpace>() {
        return anyhow::anyhow!("{n} Free some space, or pass --no-cache to read into memory.");
    }
    if let Some(s) = e.downcast_ref::<pathwarden_collect::ReadStopped>() {
        return anyhow::anyhow!("{s} Run the same command with --resume to continue it.");
    }
    e
}

/// What `collect` says before it starts about the reads of the run's
/// domains that stopped: each one that can be resumed, and whether it
/// is (`resume`) or starts over.
pub(crate) fn resume_notes(
    req: &pathwarden_collect::CollectRequest,
    trusted: &[String],
    resume: bool,
    now: i64,
) -> Vec<String> {
    let Some(cache) = &req.cache else {
        return Vec::new();
    };
    let mut domains: Vec<&str> = Vec::new();
    for d in std::iter::once(&req.domain).chain(trusted) {
        let d = d.trim().trim_end_matches('.');
        if !d.is_empty() && !domains.iter().any(|o| o.eq_ignore_ascii_case(d)) {
            domains.push(d);
        }
    }
    domains
        .into_iter()
        .filter_map(
            |d| match pathwarden_collect::stopped_read(cache, d, &req.auth) {
                Some(s) if resume => Some(format!(
                    "Resuming the read of {} that stopped at {}% ({}).",
                    s.domain,
                    s.percent,
                    s.ago(now)
                )),
                Some(s) => Some(format!(
                    "An earlier read of {} stopped at {}% ({}); starting over. Pass --resume to \
                     continue it.",
                    s.domain,
                    s.percent,
                    s.ago(now)
                )),
                None if resume => Some(format!(
                    "No stopped read of {d} to resume; starting from the beginning."
                )),
                None => None,
            },
        )
        .collect()
}

/// A domain of a collection started, done or failed, in the job's log.
fn log_domain(e: &pathwarden_collect::DomainEvent) {
    use pathwarden_collect::DomainState;
    let d = e.domain.to_ascii_uppercase();
    pathwarden_core::logs::note(&match &e.state {
        DomainState::Started => format!("domain {d} ({} of {}) started", e.index + 1, e.total),
        DomainState::Done { seconds, .. } => format!("domain {d} done in {seconds} s"),
        DomainState::Failed { reason, .. } => format!("domain {d} failed: {reason}"),
    });
}

/// What [`collect`] collected.
pub struct Collected {
    /// The files written, ready to analyze.
    pub files: Vec<std::path::PathBuf>,
    /// How it was collected, for a saved run (`collect --save`).
    pub info: pathwarden_ui::workspace::CollectionInfo,
    /// Where the time went, for the saved run's `timings.json`.
    pub timings: Option<pathwarden_core::diagnostics::CollectionTimings>,
    /// Domains of the run that weren't collected.
    pub failed: usize,
}

/// `pathwarden collect`: runs the collection with live progress, then
/// prints what was collected. `trusted`: more domains to collect in the
/// same run, after the `--domain`s. With `save`, the next step is
/// saving the run (`collect --save`), so it doesn't say to analyze it.
/// Every domain failing is an error; some failing is in `failed`. `ws` is
/// the workspace environment the run is saved to: the built-in collector
/// keeps each domain's read there (the default workspace without one), as
/// the app does.
pub fn collect(
    args: pathwarden_collect::CollectArgs,
    trusted: Vec<String>,
    save: bool,
    ws: Option<&pathwarden_ui::workspace::Workspace>,
) -> anyhow::Result<Collected> {
    use pathwarden_collect::{DomainState, Method, Progress, Verbosity};

    let verbosity = args.verbosity();
    let no_cache = args.no_cache;
    let resume = args.resume;
    let mut also = args.trusted();
    also.extend(trusted);
    // A domain controller named for a domain the run doesn't collect:
    // stopped before the password prompt.
    let (_, servers) = pathwarden_collect::parse_servers(&args.server, args.first_domain())?;
    // One named for the account's own domain is kept for its ticket.
    if let Some(d) = pathwarden_collect::unused_servers(args.first_domain(), &servers, &also)
        .iter()
        .find(|d| !pathwarden_collect::names_account_domain(args.user.as_deref(), d))
    {
        anyhow::bail!(
            "--server names a domain controller for {d}, which this run doesn't collect as a \
             trusted domain"
        );
    }
    // Prompts for the password (if any) before the display starts.
    let mut req = args.into_request()?;
    if req.method == Method::Builtin {
        // `--all-attributes`, or `[collect] all_attributes` as in the app.
        req.all_attributes = req.all_attributes || pathwarden_ui::collect::all_attributes(ws);
        // `--read-streams`, else `[collect] read_streams` as in the app.
        req.read_streams = req
            .read_streams
            .or_else(|| pathwarden_ui::collect::read_streams(ws));
    }
    if req.method == Method::Builtin && !no_cache {
        req.cache = match ws {
            Some(ws) => Some(pathwarden_ui::collect::read_cache(ws, &req.domain)),
            None => pathwarden_ui::collect::default_read_cache(&req.domain),
        };
        if let Some(c) = req.cache.as_mut() {
            c.resume = resume;
            // Reads that can't be resumed any more go first.
            pathwarden_collect::sweep_stopped_reads(&c.root);
        }
    }
    if verbosity != Verbosity::Quiet {
        for note in resume_notes(&req, &also, resume, pathwarden_core::analyze::now()) {
            anstream::eprintln!("{}", ui::safe(&note));
        }
        // SharpHound that isn't SpecterOps', as the Collect page's
        // check says it: it still runs.
        if let Some(w) = pathwarden_collect::signature::request_warning(&req) {
            let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
            anstream::eprintln!("{warn}Warning:{warn:#} {}", ui::safe(&w));
        }
    }
    let mut info = pathwarden_ui::collect::collection_info(&req);
    let tty = std::io::stderr().is_terminal();
    let mode = match verbosity {
        Verbosity::Quiet => Mode::Off,
        _ => forced_mode().unwrap_or(if tty {
            Mode::Live
        } else {
            Mode::Plain(Duration::from_secs(10))
        }),
    };
    let redirect = if mode == Mode::Live && tty && req.method == Method::Builtin {
        Redirect::stderr_to_null()
    } else {
        None
    };
    let (guard, out) = match redirect {
        Some((g, o)) => (Some(g), o),
        None => (None, ErrOut::Std),
    };
    let title = format!("Collecting {}", req.domain.trim());
    let live = Live::start(out, mode, title, true, Source::Pushed(None));
    let started = Instant::now();
    let cancel = AtomicBool::new(false);
    let warn = ui::severity(pathwarden_core::findings::Severity::Medium);
    let result = pathwarden_collect::collect_domains(
        &req,
        &also,
        &mut |p| match p {
            Progress::Status(s) => live.status(*s),
            Progress::Log(line) => {
                pathwarden_core::logs::note(&line);
                // `[timing]` lines exist only with PATHWARDEN_TIMINGS=1:
                // asked for, so shown without -v.
                let important = line.starts_with("error:")
                    || line.starts_with("warning:")
                    || line.starts_with("[timing]");
                if verbosity == Verbosity::Verbose || (important && verbosity == Verbosity::Normal)
                {
                    live.log(&line);
                }
            }
            // Several domains: which one, and the ones that fail.
            Progress::Domain(e) => {
                log_domain(&e);
                match e.state {
                    DomainState::Started => live.title(format!(
                        "Collecting {} ({} of {})",
                        e.domain,
                        e.index + 1,
                        e.total
                    )),
                    DomainState::Done { .. } => {}
                    DomainState::Failed { reason, .. } => {
                        if verbosity != Verbosity::Verbose {
                            live.log(&format!(
                                "{warn}{}:{warn:#} {reason} Skipped.",
                                e.domain.to_ascii_uppercase()
                            ))
                        }
                    }
                }
            }
            Progress::Phase(s) => pathwarden_core::logs::note(&format!("step: {s}")),
            Progress::Objects { .. } => {}
        },
        &cancel,
    );
    live.finish();
    drop(guard);
    let mut results = result.map_err(no_space_hint)?;
    // Nothing collected: the (first) domain's own error.
    if results.iter().all(|r| r.outcome.is_err()) {
        return Err(no_space_hint(results.remove(0).outcome.unwrap_err()));
    }
    let names = pathwarden_ui::collect::account_names(&req);
    pathwarden_ui::collect::record_domains(&mut info, &results, &names);
    let outcome = pathwarden_collect::merged(&results);
    // As the app records it: a domain controller read over plain LDAP
    // after its LDAPS failed makes the run plain LDAP.
    if outcome.plain_ldap {
        info.ldaps = false;
    }
    let several = results.len() > 1;
    let failed = results.iter().filter(|r| r.outcome.is_err()).count();

    let (g, bold) = (ui::GREEN, ui::BOLD);
    let how = match (&req.method, req.scope) {
        (Method::Builtin, pathwarden_collect::Scope::All) => "built-in collector, full",
        (Method::Builtin, _) => "built-in collector, DC only",
        (Method::External { kind, .. }, scope) => match (kind, scope) {
            (pathwarden_collect::ExternalKind::SharpHound, pathwarden_collect::Scope::DcOnly) => {
                "SharpHound, DC only"
            }
            (pathwarden_collect::ExternalKind::SharpHound, _) => "SharpHound, full",
            (_, pathwarden_collect::Scope::DcOnly) => "RustHound-CE, DC only",
            _ => "RustHound-CE, full",
        },
    };
    if several {
        anstream::println!(
            "{g}Collected{g:#} {bold}{} of {} domains{bold:#} in {} ({how})",
            results.len() - failed,
            results.len(),
            clock(started.elapsed().as_secs())
        );
        // Each domain and how it went.
        let width = results
            .iter()
            .map(|r| r.domain.chars().count())
            .max()
            .unwrap_or(0);
        for r in &results {
            let name = r.domain.to_ascii_uppercase();
            let pad = " ".repeat(width - r.domain.chars().count());
            match r.table_reason() {
                None => anstream::println!(
                    "  {}{pad}  {:>9} objects  {}",
                    ui::safe(&name),
                    pathwarden_core::report::num(r.objects()),
                    clock(r.elapsed.as_secs())
                ),
                Some(reason) => anstream::println!(
                    "  {}{pad}  {warn}not collected:{warn:#} {}",
                    ui::safe(&name),
                    ui::safe(&reason)
                ),
            }
        }
        // A trusted domain's certificate wasn't accepted: no
        // controller was found in its domain (none, none answering, or only
        // names outside it), or the one named doesn't match. Naming it is
        // the way on; the check stays on.
        if results.iter().skip(1).any(|r| r.certificate_failed()) {
            eprintln!(
                "When no domain controller is found in a trusted domain, or its name is outside \
                 the domain, name it by its full name with --server DOMAIN=HOST."
            );
        }
    } else {
        anstream::println!(
            "{g}Collected{g:#} {bold}{}{bold:#} in {} ({how})",
            req.domain.trim(),
            clock(started.elapsed().as_secs())
        );
    }
    let objects: BTreeMap<String, u64> = pathwarden_collect::summarize_outputs(&outcome.files)
        .into_iter()
        .map(|(k, v)| (k, v as u64))
        .collect();
    if !objects.is_empty() {
        let counts: Vec<String> = counts_words(&objects, &BTreeMap::new())
            .into_iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        anstream::println!("  {}", counts.join("   "));
    }
    for f in &outcome.files {
        let size = std::fs::metadata(f)
            .map(|m| bytes(m.len()))
            .unwrap_or_default();
        anstream::println!("  Output: {} ({size})", f.display());
    }
    anstream::println!("  Computers: {}", pathwarden_collect::computers_words(&req));
    for w in &outcome.warnings {
        anstream::eprintln!("{warn}Warning:{warn:#} {w}");
    }
    for r in results.iter().filter(|r| r.outcome.is_err()) {
        if let Some((reason, detail)) = r.failure() {
            anstream::eprintln!(
                "{warn}Warning:{warn:#} {} wasn't collected: {reason} {}",
                r.domain.to_ascii_uppercase(),
                ui::safe(&detail)
            );
        }
    }
    if failed > 0 {
        anstream::eprintln!(
            "Attack paths through the {} not collected are missing from this run.",
            if failed == 1 { "domain" } else { "domains" }
        );
    }
    if save {
        anstream::println!(
            "This is a full map of the directory; store it as carefully as the domain itself."
        );
    } else {
        anstream::println!(
            "This is a full map of the directory; store it as carefully as the domain itself.\n\
             Analyze it with: pathwarden report -i {}",
            crate::shell::quoted_path(&req.output_dir)
        );
    }
    info.warnings = outcome.warnings.clone();
    info.kept = Some(req.output_dir.display().to_string());
    info.read_started = outcome.read_started;
    Ok(Collected {
        files: outcome.files,
        info,
        timings: outcome.timings,
        failed,
    })
}

// ---------------------------------------------------------------- analysis

/// The analysis phases a command goes through.
#[derive(Debug, Clone, Copy)]
pub enum Through {
    /// Loading only (summary, tier-zero, exposure, ...).
    Load,
    /// Loading and the rules (findings, posture).
    Rules,
    /// Rules and the remediation plan (run).
    Plan,
    /// Everything, including the HTML report (report, run --report).
    Report,
}

fn analysis_steps(through: Through) -> Vec<Step> {
    // Shares measured on a 500k-computer forest (PATHWARDEN_TIMINGS=1).
    let mut steps = vec![
        Step::new("reading", "Reading data", 82.0),
        Step::new("graph", "Building the graph", 4.0),
    ];
    if matches!(through, Through::Rules | Through::Plan | Through::Report) {
        steps.push(Step::new("rules", "Running the rules", 7.0));
    }
    if matches!(through, Through::Plan | Through::Report) {
        steps.push(Step::new(
            "remediation",
            "Planning the remediation path",
            6.0,
        ));
    }
    if matches!(through, Through::Report) {
        steps.push(Step::new("report", "Writing the report", 1.0));
    }
    steps
}

/// The title while `pathwarden demo` records the demo's earlier runs, as
/// the app's Analyze page says it: "Building the demo's earlier runs (2 of
/// 4)", `done` of them recorded so far ([`pathwarden_ui::demo_runs`]).
pub fn demo_earlier_title(done: usize) -> String {
    use pathwarden_ui::demo_runs::{count_words, BUILDING};
    format!("{BUILDING} ({})", count_words(done))
}

/// Progress of an analysis command, shown on a terminal (or, with `-v`,
/// as plain lines elsewhere). Implements [`analyze::Progress`].
pub struct Analysis {
    live: Option<Live>,
    /// Warnings held until the status is gone.
    notes: Vec<String>,
}

impl Analysis {
    pub fn new(through: Through, verbose: bool) -> Analysis {
        Self::titled(through, verbose, "Analyzing")
    }

    /// [`Analysis::new`] with another title than "Analyzing".
    pub fn titled(through: Through, verbose: bool, title: &str) -> Analysis {
        let mode = if let Some(m) = forced_mode() {
            m
        } else if std::io::stderr().is_terminal() {
            Mode::Live
        } else if verbose {
            Mode::Plain(Duration::from_secs(5))
        } else {
            Mode::Off
        };
        Self::with_mode(through, mode, ErrOut::Std, title)
    }

    fn with_mode(through: Through, mode: Mode, out: ErrOut, title: &str) -> Analysis {
        let live = (mode != Mode::Off).then(|| {
            Live::start(
                out,
                mode,
                title.into(),
                true,
                Source::Tracked(Tracker::new(analysis_steps(through))),
            )
        });
        if let Some(live) = &live {
            live.with(|s| s.refresh());
        }
        Analysis {
            live,
            notes: Vec::new(),
        }
    }

    /// Removes the status before the command prints its results, then
    /// prints the warnings held back.
    pub fn done(&mut self) {
        if let Some(live) = self.live.take() {
            live.finish();
        }
        for n in self.notes.drain(..) {
            anstream::eprintln!("{n}");
        }
    }

    /// A warning for stderr: printed now, or once the status is gone.
    pub fn note(&mut self, text: String) {
        if self.live.is_some() {
            self.notes.push(text);
        } else {
            anstream::eprintln!("{text}");
        }
    }
}

impl Drop for Analysis {
    fn drop(&mut self) {
        self.done();
    }
}

impl analyze::Progress for Analysis {
    fn phase(&mut self, phase: Phase) {
        if let Some(live) = &self.live {
            live.track(|t| {
                t.enter(phase.as_str());
                if phase == Phase::Reading {
                    t.unit("bytes");
                }
            });
        }
    }

    fn bytes(&mut self, read: u64, total: u64) {
        if let Some(live) = &self.live {
            live.track(|t| {
                if t.current() == "reading" {
                    t.unit("bytes");
                    t.units(read, Some(total));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic while stderr points at the null device puts it back before
    /// the panic message is written, instead of losing the message.
    #[test]
    fn a_panic_restores_stderr_first() {
        let Some((guard, _out)) = Redirect::stderr_to_null() else {
            return;
        };
        let replaced = || REPLACED.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        assert!(replaced());
        assert!(Redirect::stderr_to_null().is_none(), "one at a time");
        let _ = std::thread::spawn(|| panic!("boom")).join();
        assert!(!replaced(), "the panic hook restored stderr");
        drop(guard); // nothing left to restore, and no double close
        assert!(!replaced());
    }

    fn status() -> Status {
        let mut objects = BTreeMap::new();
        objects.insert("users".to_string(), 8123);
        objects.insert("computers".to_string(), 4511);
        objects.insert("other".to_string(), 33);
        let mut expected = BTreeMap::new();
        expected.insert("users".to_string(), 15000);
        Status {
            key: "read".into(),
            step: 2,
            steps: 5,
            phase: "Reading the directory".into(),
            detail: Some("DC=contoso,DC=local".into()),
            done: 12667,
            total: Some(29400),
            unit: "objects".into(),
            rate: Some(312.4),
            objects,
            expected,
            percent: 41.26,
            step_percent: Some(43.1),
            eta_secs: Some(125),
            elapsed_secs: 83,
            finished: false,
            parts: None,
        }
    }

    #[test]
    fn plain_lines_for_logs() {
        assert_eq!(
            plain_line("Collecting contoso.local", &status()),
            "Collecting contoso.local [2/5] Reading the directory: 12,667 of about 29,400 \
             objects, 41%, 1:23 elapsed, 2:05 left"
        );
        // A read in parts: its streams, as the app shows them.
        let mut st = status();
        st.parts = Some(pathwarden_collect::progress::ReadParts {
            streams: 4,
            parts: 68,
            done: 41,
        });
        assert_eq!(
            plain_line("Collecting contoso.local", &st),
            "Collecting contoso.local [2/5] Reading the directory: 12,667 of about 29,400 \
             objects, 4 streams, 41%, 1:23 elapsed, 2:05 left"
        );
        let lines = live_lines("Collecting contoso.local", &st, 0, 100, true, false);
        assert!(
            lines[1].contains("12,667 of about 29,400 objects \u{00b7} 312/s \u{00b7} 4 streams"),
            "{lines:#?}"
        );
        st.parts = Some(pathwarden_collect::progress::ReadParts {
            streams: 1,
            parts: 68,
            done: 41,
        });
        assert!(plain_line("x", &st).contains("objects, 1 stream, 41%"));
        let mut st = status();
        st.eta_secs = None;
        st.total = None;
        assert!(
            plain_line("x", &st).ends_with("12,667 objects, 41%, 1:23 elapsed, estimating\u{2026}")
        );
    }

    #[test]
    fn live_lines_fit_the_width() {
        let lines = live_lines("Collecting contoso.local", &status(), 0, 80, true, false);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.chars().count() < 80), "{lines:#?}");
        assert!(lines[0].contains("2/5 Reading the directory"));
        assert!(lines[1].contains("12,667 of about 29,400 objects \u{00b7} 312/s"));
        assert!(lines[2].starts_with("  users 8,123 of ~15,000  computers 4,511"));
        assert!(!lines[2].contains("other"), "{}", lines[2]);
        let wide = live_lines("Collecting contoso.local", &status(), 1, 200, false, false);
        assert_eq!(wide.len(), 1);
        assert!(wide[0].contains(" 41%  1:23  2:05 left"), "{}", wide[0]);
        // Colors only when asked.
        assert!(!wide[0].contains('\x1b'));
        assert!(live_lines("x", &status(), 0, 200, false, true)[0].contains('\x1b'));
    }

    /// Not a terminal: a plain line on each step change and when due, and
    /// log lines as they come; nothing is redrawn.
    #[test]
    fn plain_mode_prints_lines() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let live = Live::start(
            ErrOut::Buffer(buf.clone()),
            Mode::Plain(Duration::from_secs(3600)),
            "Collecting contoso.local".into(),
            true,
            Source::Pushed(None),
        );
        let mut st = status();
        st.step = 1;
        st.phase = "Connecting and signing in".into();
        live.status(st);
        live.status(status());
        live.status(status()); // same step: not due yet
        live.log("warning: something");
        live.finish();
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("Collecting contoso.local [1/5] Connecting and signing in:"));
        assert!(lines[1].starts_with("Collecting contoso.local [2/5] Reading the directory:"));
        assert_eq!(lines[2], "warning: something");
        assert!(!text.contains('\x1b'));
    }

    /// A plain line for a stream read in a legacy code page is ASCII:
    /// "estimating..." rather than UTF-8 that Windows PowerShell 5.1 shows as
    /// "estimatingΓÇª". Log lines (names from the directory) are untouched.
    #[test]
    fn plain_mode_falls_back_to_ascii() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let live = Live::start(
            ErrOut::Buffer(buf.clone()),
            Mode::Plain(Duration::from_secs(3600)),
            "Collecting contoso.local".into(),
            true,
            Source::Pushed(None),
        );
        live.with(|s| s.glyphs = false);
        let mut st = status();
        st.eta_secs = None;
        live.status(st);
        live.log("Reading CN=Élodie Dupré\u{2026},DC=contoso,DC=local");
        live.finish();
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].ends_with("1:23 elapsed, estimating..."), "{text}");
        assert!(lines[0].is_ascii(), "{text}");
        assert_eq!(
            lines[1],
            "Reading CN=Élodie Dupré\u{2026},DC=contoso,DC=local"
        );
    }

    #[test]
    fn ascii_glyphs_only_change_the_decoration() {
        assert_eq!(ascii_glyphs("estimating\u{2026}"), "estimating...");
        assert_eq!(
            ascii_glyphs("\u{258c} a \u{00b7} b \u{2014} c \u{2192} d \u{2713} \u{2588}\u{2591}"),
            "| a - b - c -> d ok #-"
        );
        let names = "Élodie 管理者 Dupré";
        assert!(matches!(ascii_glyphs(names), std::borrow::Cow::Borrowed(n) if n == names));
    }

    #[test]
    fn glyphs_follow_the_stream_and_code_page() {
        // A console takes UTF-16, so any code page shows them.
        assert!(glyphs_allowed(true, None, false));
        // A pipe or file: UTF-8 bytes. On Windows, only when the console
        // reads UTF-8; elsewhere as before.
        assert_eq!(glyphs_allowed(false, None, false), !cfg!(windows));
        assert!(glyphs_allowed(false, None, true));
        // PATHWARDEN_UTF8 decides.
        assert!(glyphs_allowed(false, Some("1"), false));
        assert!(!glyphs_allowed(true, Some(" 0 "), true));
        assert_eq!(glyphs_allowed(false, Some("yes"), false), !cfg!(windows));
    }

    #[test]
    fn off_prints_nothing() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut a = Analysis::with_mode(
            Through::Report,
            Mode::Off,
            ErrOut::Buffer(buf.clone()),
            "Analyzing",
        );
        analyze::Progress::phase(&mut a, Phase::Reading);
        a.done();
        assert!(buf.lock().unwrap().is_empty());
    }

    /// The analysis display on real data: phases and bytes from the loader.
    #[test]
    fn analysis_reports_bytes_and_phases() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut a = Analysis::with_mode(
            Through::Load,
            Mode::Plain(Duration::ZERO),
            ErrOut::Buffer(buf.clone()),
            "Analyzing",
        );
        let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo");
        pathwarden_core::load_with_progress(&[demo], &Default::default(), &mut a).unwrap();
        a.done();
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(text.contains("Analyzing [1/2] Reading data:"), "{text}");
        assert!(
            text.contains("Analyzing [2/2] Building the graph"),
            "{text}"
        );
    }

    /// `pathwarden demo` says it is building the demo's earlier runs, and
    /// how many are recorded, as the app does.
    #[test]
    fn the_demo_says_it_builds_its_earlier_runs() {
        assert_eq!(
            demo_earlier_title(2),
            "Building the demo's earlier runs (2 of 4)"
        );
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut a = Analysis::with_mode(
            Through::Plan,
            Mode::Plain(Duration::ZERO),
            ErrOut::Buffer(buf.clone()),
            &demo_earlier_title(1),
        );
        analyze::Progress::phase(&mut a, Phase::Graph);
        a.done();
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            text.contains("Building the demo's earlier runs (1 of 4) [2/4] Building the graph"),
            "{text}"
        );
    }
}
