//! Running output plugins: separate programs that receive the run's event
//! document (`pathwarden.event.v1`) on stdin and their settings as JSON in
//! `PATHWARDEN_OUTPUT_SETTINGS`. Shared by `pathwarden run` and the local UI's
//! "Test with the latest run".
//!
//! A plugin is `pathwarden-output-<name>` next to the pathwarden executable
//! (or in a `plugins` folder beside it), or the program given as `command`:
//! an absolute path, or a known interpreter such as `powershell` or `python`.
//! Plugins never come from the working directory or PATH, so nobody can plant
//! one there. An interpreter named without a path is looked up on PATH, but
//! only in folders that only administrators can change (System32, Program
//! Files, root-owned folders such as `/usr/bin`); see [`resolve_interpreter`].
//! A plugin starts in a private folder of its own ([`work_dir`]), never the
//! folder Pathwarden was started in, and a script named in `command` must be
//! given by its full path ([`check_args`]): nothing is ever picked up from the
//! working directory. They get a minimal environment plus the variables their
//! own settings name (`password_env = "..."`), never one of Pathwarden's own
//! secrets ([`crate::keystore::SECRET_ENV`]), and a timeout
//! (`timeout_seconds`, default 10 minutes).
//!
//! Finding actions ([`crate::actions`]) run the same way: found as
//! `pathwarden-action-<name>` or by their `command`, with the same checks,
//! environment and folder, through [`run_streaming`], which hands over each
//! line of stdout as it arrives and can be stopped ([`CancelHandle`]).

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{ActionConfig, OutputConfig};

pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Interpreters `command` may name without a full path.
pub const INTERPRETERS: &[&str] = &[
    "powershell",
    "pwsh",
    "python",
    "python3",
    "bash",
    "sh",
    "node",
    "cmd",
];

/// Environment variables every plugin gets (matched case-insensitively).
/// The proxy variables are passed so a plugin reaches its service the way
/// this computer does. `SSL_CERT_FILE` and `SSL_CERT_DIR` are not: they
/// would replace the system's trusted certificates for the plugins shipped
/// with Pathwarden. A plugin that needs one names it in a `*_env` setting.
const BASE_ENV: &[&str] = &[
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
];

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The plugin could not be found, or `command` is not allowed.
    #[error("{0}")]
    Setup(String),
    #[error("starting output plugin {plugin}: {detail}")]
    Start { plugin: String, detail: String },
    #[error("timed out after {0} s and was stopped (set timeout_seconds to change the limit)")]
    Timeout(u64),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// What a plugin printed and how it exited.
#[derive(Debug)]
pub struct PluginRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl PluginRun {
    /// Non-empty lines of stdout, then stderr.
    pub fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&self.stderr).lines())
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// Folders plugins are loaded from: beside the executable, and its `plugins`.
pub fn plugin_dirs() -> Vec<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .map(|d| vec![d.clone(), d.join("plugins")])
        .unwrap_or_default()
}

/// Warnings for the folders Pathwarden runs programs from, for the start
/// of a run: the folder holding the pathwarden executable (on
/// Linux, its install folder) and its `plugins` folder, when someone other
/// than this account (and Administrators and SYSTEM, or root) can change
/// them. Anyone who can could put a plugin there, or replace Pathwarden
/// itself, and it would run as this account. Empty when both are private
/// or their permissions can't be read.
pub fn folder_warnings() -> Vec<String> {
    folder_warnings_for(&plugin_dirs())
}

/// [`folder_warnings`] for these folders (beside the executable, then
/// `plugins`). A folder that doesn't exist is left out.
pub fn folder_warnings_for(dirs: &[PathBuf]) -> Vec<String> {
    dirs.iter()
        .filter(|d| d.is_dir())
        .filter_map(|d| {
            let writers: Vec<String> = crate::perms::others_with_access(d)
                .into_iter()
                .filter(|a| a.write)
                .map(|a| a.who)
                .collect();
            (!writers.is_empty()).then(|| {
                let what = if d.file_name().is_some_and(|n| n == "plugins") {
                    "Pathwarden's plugins folder"
                } else {
                    "The folder Pathwarden runs from"
                };
                format!(
                    "{what}, {}, can be changed by {}: whatever they put there runs as this \
                     account. Let only administrators change it.",
                    d.display(),
                    writers.join(", ")
                )
            })
        })
        .collect()
}

/// The local files a `command` runs: its program (an interpreter as found
/// on PATH) and every argument that names an existing file by its full
/// path (the script an interpreter runs, `-File C:\x\teams.ps1`). Network
/// paths are never looked at.
pub(crate) fn command_files(argv: &[String]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(program) = argv.first() {
        if is_interpreter(program) {
            out.extend(resolve_interpreter(program));
        } else if !is_remote_path(program) && Path::new(program).is_absolute() {
            out.push(PathBuf::from(program));
        }
    }
    for a in argv.iter().skip(1).filter(|a| !reaches_network(a)) {
        for p in arg_paths(a) {
            let p = p.trim().trim_matches('"').trim();
            if p.is_empty() || is_url(p) || is_remote_path(p) {
                continue;
            }
            let path = Path::new(p);
            if path.is_absolute() && path.is_file() {
                out.push(path.to_path_buf());
            }
        }
    }
    out.dedup();
    out
}

/// Who besides this account (Administrators and SYSTEM, or root) can
/// change a file `command` runs, or the folder holding it: whatever they
/// put there would run as this account. One line per file, empty when
/// none can.
pub fn command_writers(argv: &[String]) -> Vec<String> {
    command_files(argv)
        .into_iter()
        .filter_map(|f| {
            let mut who: Vec<String> = Vec::new();
            for target in std::iter::once(f.as_path()).chain(f.parent()) {
                for a in crate::perms::others_with_access(target) {
                    if a.write && !who.contains(&a.who) {
                        who.push(a.who);
                    }
                }
            }
            (!who.is_empty())
                .then(|| format!("{} can be changed by {}", f.display(), who.join(", ")))
        })
        .collect()
}

/// [`command_writers`] for every output with a `command`, for the start
/// of a run: a scheduled run refuses such a plugin ([`command_for`]).
pub fn command_warnings(outputs: &[OutputConfig]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|o| o.command.as_ref().map(|c| (o, c)))
        .flat_map(|(o, c)| {
            command_writers(c).into_iter().map(move |w| {
                format!(
                    "Plugin {}: {w}; whatever they put there runs as this account. Let only \
                     administrators change it.",
                    o.plugin
                )
            })
        })
        .collect()
}

/// What a program is for, which names its file: an output plugin
/// (`pathwarden-output-<name>`) or a finding action
/// (`pathwarden-action-<name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Output,
    Action,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::Output => "pathwarden-output-",
            Kind::Action => "pathwarden-action-",
        }
    }
}

/// The program file for plugin `name`: `pathwarden-output-<name>(.exe)`.
pub fn program_name(name: &str) -> String {
    program_name_of(Kind::Output, name)
}

/// The program file of a `kind` plugin `name`.
pub fn program_name_of(kind: Kind, name: &str) -> String {
    format!("{}{name}{}", kind.prefix(), std::env::consts::EXE_SUFFIX)
}

/// Finds `pathwarden-output-<name>`.
pub fn locate(name: &str) -> Option<PathBuf> {
    locate_of(Kind::Output, name)
}

/// Finds the `kind` plugin `name` beside pathwarden or in its `plugins`
/// folder.
pub fn locate_of(kind: Kind, name: &str) -> Option<PathBuf> {
    let file = program_name_of(kind, name);
    plugin_dirs()
        .into_iter()
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// Whether `p` (as typed: quotes and spaces are ignored) names a network or
/// device path: `\\server\share`, `//server/share`, `\\?\`, `\\.\`, `\??\`
/// or a `file:` URL. Check this *before* touching the file system: even
/// looking at `\\server\x` makes Windows connect to that server and sign in
/// as the user (NTLM).
pub fn is_network_path(p: &str) -> bool {
    let p = p.trim().trim_matches('"').trim();
    let mut c = p.chars();
    matches!((c.next(), c.next()), (Some('\\' | '/'), Some('\\' | '/')))
        || p.starts_with(r"\??\")
        || p.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("file:"))
}

/// Whether `p` (as typed) is on a drive letter mapped to a network share
/// (`Z:\x` on Windows): it is read from that server. A local drive, a
/// letter that isn't mapped, or any other path is not.
#[allow(unsafe_code)]
pub fn is_network_drive(p: &str) -> bool {
    let p = p.trim().trim_matches('"').trim();
    let b = p.as_bytes();
    if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        const DRIVE_REMOTE: u32 = 4;
        let root: Vec<u16> = format!("{}:\\", b[0] as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: `root` is NUL-terminated and outlives the call, which
        // only reads it (the drive's type comes from the system's table of
        // drives: no server is contacted).
        unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_REMOTE }
    }
    #[cfg(not(windows))]
    false
}

/// [`is_network_path`] or [`is_network_drive`]: a path that is read from
/// another computer.
pub fn is_remote_path(p: &str) -> bool {
    is_network_path(p) || is_network_drive(p)
}

/// The parts of a `command` argument that may be a path: the argument,
/// and the value of `--x=value` or of `-File:value`.
fn arg_paths(arg: &str) -> Vec<&str> {
    let mut parts = vec![arg];
    match arg.split_once('=') {
        Some((_, v)) => parts.push(v),
        None if arg.starts_with('-') => {
            if let Some((_, v)) = arg.split_once(':') {
                parts.push(v);
            }
        }
        None => {}
    }
    parts
}

/// Whether `s` starts with a URL scheme other than `file` (`https:`,
/// `ldaps:`): what follows is an address, not a path.
fn is_url(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut c = scheme.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic())
        && c.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        && scheme.len() > 1
        && !scheme.eq_ignore_ascii_case("file")
        && rest.starts_with("//")
}

/// Whether a `command` argument reaches another computer: a network path
/// or a mapped network drive on its own, as the value of `-File=\\srv\x`,
/// `--x=//srv/x` or `-File:Z:\x`, or with `\\` or `//` anywhere in it
/// outside a URL such as `https://…`.
pub fn reaches_network(arg: &str) -> bool {
    if arg.contains(r"\\") {
        return true;
    }
    let parts = arg_paths(arg);
    if parts.iter().any(|p| is_remote_path(p)) {
        return true;
    }
    // `//` outside the start of a URL.
    let mut rest = arg;
    while let Some(i) = rest.find("//") {
        let before = &rest[..i];
        let start = before
            .rfind(['=', ' ', ',', ';', '"', '\''])
            .map_or(0, |j| j + 1);
        if !is_url(&rest[start..]) {
            return true;
        }
        rest = &rest[i + 2..];
    }
    false
}

/// File name endings of scripts an interpreter runs.
const SCRIPT_EXTENSIONS: &[&str] = &[
    ".ps1", ".psm1", ".py", ".pyw", ".sh", ".bash", ".js", ".mjs", ".cjs", ".cmd", ".bat", ".vbs",
    ".rb", ".pl",
];

/// The relative path a `command` argument names, if it names one: a script
/// (`teams.ps1`, `scripts/teams.py`) or a path starting with `.` (`.\x`,
/// `../x`). Plugins start in their own folder ([`work_dir`]), so such a
/// path would not be found, and must not be looked up anywhere else.
pub fn relative_path_in(arg: &str) -> Option<&str> {
    // The value of `--x=value` or `-File:value`, else the argument.
    let value = match arg.split_once('=') {
        Some((_, v)) => v,
        None if arg.starts_with('-') => arg.split_once(':').map_or(arg, |(_, v)| v),
        None => arg,
    };
    let p = value.trim().trim_matches('"').trim();
    if p.is_empty() || is_url(p) || Path::new(p).is_absolute() || is_remote_path(p) {
        return None;
    }
    let lower = p.to_ascii_lowercase();
    let relative = SCRIPT_EXTENSIONS.iter().any(|x| lower.ends_with(x))
        || p.starts_with("./")
        || p.starts_with(".\\")
        || p.starts_with("../")
        || p.starts_with("..\\");
    relative.then_some(p)
}

/// The checks on a `command`'s arguments, when it is saved and again each
/// time the plugin runs: no network path or mapped network drive (even
/// looking at one signs in to that server as this account), and no script
/// by a relative path.
pub fn check_args(args: &[String]) -> Result<(), String> {
    if let Some(p) = args.iter().find(|a| reaches_network(a)) {
        return Err(format!(
            "{p} is a network path. Copy the program or script to this computer and give its local path: even checking a network path makes Windows sign in to that server as you."
        ));
    }
    if let Some(p) = args.iter().find_map(|a| relative_path_in(a)) {
        return Err(format!(
            "{p} is a relative path. Plugins start in a folder of their own, not the current one: give the script's full path, like {}.",
            if cfg!(windows) {
                r"C:\Pathwarden\scripts\teams.ps1"
            } else {
                "/opt/pathwarden/scripts/teams.sh"
            }
        ));
    }
    Ok(())
}

/// The folder every plugin starts in: private to this account (created so
/// when missing; refused when someone else can open it), and never the
/// folder Pathwarden was started from, so a plugin or its interpreter
/// finds nothing there that someone else put.
/// `%LOCALAPPDATA%\Pathwarden\plugin-work` on Windows,
/// `$XDG_STATE_HOME/pathwarden/plugin-work` (or
/// `~/.local/state/pathwarden/plugin-work`) elsewhere, or the temporary
/// folder's `pathwarden-plugin-work` without those. Debug builds use a
/// folder of the temporary folder, so tests never write this account's
/// data.
pub fn work_dir() -> Result<PathBuf, PluginError> {
    let dir = work_dir_in(&work_base());
    let made = match crate::perms::create_private_dir(&dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            return Err(PluginError::Setup(format!(
                "creating the folder plugins start in, {}: {e}",
                dir.display()
            )))
        }
    };
    if !made && !crate::perms::is_private_dir(&dir) {
        return Err(PluginError::Setup(format!(
            "The folder plugins start in, {}, isn't private to this account: someone else could put a program or script there. Remove it and Pathwarden creates it again.",
            dir.display()
        )));
    }
    Ok(dir)
}

fn work_dir_in(base: &Path) -> PathBuf {
    base.join(if cfg!(debug_assertions) {
        format!("pathwarden-test-plugin-work-{}", std::process::id())
    } else {
        "plugin-work".to_string()
    })
}

/// Where [`work_dir`] goes; its parents are created.
fn work_base() -> PathBuf {
    let tmp = std::env::temp_dir();
    if cfg!(debug_assertions) {
        return tmp;
    }
    let var = |n: &str| {
        std::env::var_os(n)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let base = if cfg!(windows) {
        var("LOCALAPPDATA").map(|d| d.join("Pathwarden"))
    } else {
        var("XDG_STATE_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".local").join("state")))
            .map(|d| d.join("pathwarden"))
    };
    match base {
        Some(b) if std::fs::create_dir_all(&b).is_ok() => b,
        _ => tmp,
    }
}

pub fn is_interpreter(program: &str) -> bool {
    let name = program.to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    !program.contains(['/', '\\']) && INTERPRETERS.contains(&name)
}

/// The Windows folder and the Program Files folders, as the system knows
/// them (not as the environment says).
#[cfg(windows)]
#[allow(unsafe_code)]
fn system_folders() -> Vec<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_Windows, SHGetKnownFolderPath,
    };
    let mut out = Vec::new();
    for id in [
        FOLDERID_Windows,
        FOLDERID_ProgramFiles,
        FOLDERID_ProgramFilesX86,
    ] {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: `id` outlives the call; the path the system allocates is
        // read up to its NUL and freed with CoTaskMemFree on every path.
        unsafe {
            let hr = SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut p);
            if hr >= 0 && !p.is_null() {
                let mut n = 0;
                while *p.add(n) != 0 {
                    n += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                out.push(PathBuf::from(s));
            }
            if !p.is_null() {
                CoTaskMemFree(p as *const core::ffi::c_void);
            }
        }
    }
    out
}

/// Whether a PATH folder is one only administrators can change, so an
/// interpreter found there can't have been planted by an ordinary user.
///
/// - Windows: under the Windows folder or a Program Files folder (as the
///   system knows them, [`system_folders`]), and nobody but this account,
///   Administrators and SYSTEM may change it.
/// - Unix: the folder and every folder above it are owned by root and not
///   writable by group or others.
fn trusted_dir(dir: &Path) -> bool {
    if !dir.is_absolute()
        || dir
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    #[cfg(windows)]
    {
        if is_remote_path(&dir.to_string_lossy()) {
            return false;
        }
        let norm = |p: &Path| {
            let s = p.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
            s.trim_end_matches('\\').to_string()
        };
        let d = norm(dir);
        let under = system_folders()
            .iter()
            .map(|r| norm(r))
            .filter(|r| r.len() > 3)
            .any(|r| d == r || d.starts_with(&format!("{r}\\")));
        under
            && crate::perms::others_with_access(dir)
                .iter()
                .all(|a| !a.write)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        dir.ancestors()
            .all(|d| std::fs::metadata(d).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// The full path of an interpreter named without one (`powershell`,
/// `python`, ...): the first match on PATH in a folder only administrators
/// can change ([`trusted_dir`]). A copy in a folder an ordinary user can
/// write to is never used, so nobody can plant one.
pub fn resolve_interpreter(program: &str) -> Option<PathBuf> {
    if !is_interpreter(program) {
        return None;
    }
    let lower = program.to_ascii_lowercase();
    let name = lower.strip_suffix(".exe").unwrap_or(&lower);
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| trusted_dir(d))
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// `command`'s program must be an absolute local path or a known
/// interpreter: never a network or device path, nor one on a mapped
/// network drive (checked before the file system is touched, which would
/// sign in to that server).
pub fn check_program(program: &str) -> Result<(), String> {
    if is_remote_path(program) {
        return Err(format!(
            "command {program:?} is a network or device path; give a program on this computer"
        ));
    }
    if Path::new(program).is_absolute() || is_interpreter(program) {
        Ok(())
    } else {
        Err(format!(
            "command {program:?} must be an absolute path or one of: {} \
             (plugins are never looked up in the working directory or on PATH)",
            INTERPRETERS.join(", ")
        ))
    }
}

/// Whether `name` can be an environment variable name.
pub fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= 128
}

pub fn command_for(output: &OutputConfig) -> Result<Command, PluginError> {
    command_of(Kind::Output, &output.plugin, output.command.as_deref())
}

/// The program of an `[[action]]` block, found and checked as an output
/// plugin's is ([`command_for`]).
pub fn command_for_action(action: &ActionConfig) -> Result<Command, PluginError> {
    let plugin = action.plugin.as_deref().unwrap_or(&action.name);
    command_of(Kind::Action, plugin, action.command.as_deref())
}

/// The local files an `[[action]]` block runs: its plugin program, or
/// the program and scripts its `command` names ([`command_files`]).
pub fn action_files(action: &ActionConfig) -> Vec<PathBuf> {
    match &action.command {
        Some(argv) => command_files(argv),
        None => action
            .plugin
            .as_deref()
            .and_then(|p| locate_of(Kind::Action, p))
            .into_iter()
            .collect(),
    }
}

fn command_of(
    kind: Kind,
    plugin: &str,
    command: Option<&[String]>,
) -> Result<Command, PluginError> {
    match command {
        Some(argv) => {
            let program = argv
                .first()
                .ok_or_else(|| PluginError::Setup("command is empty".into()))?;
            check_program(program).map_err(PluginError::Setup)?;
            // Again at each run, not only when saved: the file may have
            // been edited by hand.
            check_args(&argv[1..]).map_err(PluginError::Setup)?;
            // A scheduled run, which nobody watches, never runs a program
            // or script someone else could have changed.
            if crate::store::unattended() {
                let writers = command_writers(argv);
                if !writers.is_empty() {
                    return Err(PluginError::Setup(format!(
                        "refusing to run it from a scheduled run: {}. Let only administrators \
                         change these.",
                        writers.join("; ")
                    )));
                }
            }
            let mut c = if is_interpreter(program) {
                let full = resolve_interpreter(program).ok_or_else(|| {
                    PluginError::Setup(format!(
                        "{program} was not found in a system folder on PATH (one only \
                         administrators can change, such as System32, Program Files or /usr/bin); \
                         give its full path in command"
                    ))
                })?;
                crate::spawn::quiet(full)
            } else {
                crate::spawn::quiet(program)
            };
            c.args(&argv[1..]);
            Ok(c)
        }
        None => match locate_of(kind, plugin) {
            Some(path) => Ok(crate::spawn::quiet(path)),
            None => Err(PluginError::Setup(format!(
                "{}{plugin} not found next to pathwarden or in the plugins folder beside it ({})",
                kind.prefix(),
                plugin_dirs()
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        },
    }
}

pub fn timeout_of(output: &OutputConfig) -> Duration {
    let secs = output
        .settings
        .get("timeout_seconds")
        .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
        .max(1);
    Duration::from_secs(secs)
}

/// Names of the environment variables the plugin's settings point at
/// (every string value of a key ending in `_env`).
pub fn named_env(output: &OutputConfig) -> Vec<String> {
    named_env_in(&output.settings)
}

/// [`named_env`] of any program's settings (an output's, an action's).
pub fn named_env_in(settings: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    settings
        .iter()
        .filter(|(k, _)| k.ends_with("_env"))
        .filter_map(|(_, v)| v.as_str().map(str::to_owned))
        .filter(|v| !v.is_empty())
        // The history's passphrase never goes to a plugin.
        .filter(|v| !crate::keystore::is_secret_env(v))
        .collect()
}

fn apply_env(cmd: &mut Command, output: &OutputConfig) {
    apply_env_in(cmd, &output.settings);
}

/// The cleared environment, the base list and the variables `settings`
/// name ([`named_env_in`]).
pub(crate) fn apply_env_in(
    cmd: &mut Command,
    settings: &serde_json::Map<String, serde_json::Value>,
) {
    let named: Vec<String> = named_env_in(settings)
        .into_iter()
        .map(|n| n.to_ascii_uppercase())
        .collect();
    cmd.env_clear();
    for (key, value) in std::env::vars_os() {
        let upper = key.to_string_lossy().to_ascii_uppercase();
        if BASE_ENV.contains(&upper.as_str()) || named.contains(&upper) {
            if named.contains(&upper) {
                // Never in a log line ([`crate::redact::log_line`]).
                crate::redact::register_secret(&value.to_string_lossy());
            }
            cmd.env(key, value);
        }
    }
    // Windows: a program the plugin starts by name is not looked for in
    // its current folder first (cmd.exe, CreateProcess and PowerShell
    // honour this).
    if cfg!(windows) {
        cmd.env("NoDefaultCurrentDirectoryInExePath", "1");
    }
}

/// How much of a plugin's stdout, and of its stderr, is kept.
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// Reads `r` to the end, keeping the first `limit` bytes and a note if
/// there was more. The rest is read and dropped, so the plugin never blocks
/// on a full pipe.
fn read_capped(mut r: impl Read, limit: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = r.by_ref().take(limit as u64).read_to_end(&mut buf);
    let extra = std::io::copy(&mut r, &mut std::io::sink()).unwrap_or(0);
    if extra > 0 {
        let note = format!(
            "\n[pathwarden: output truncated after {} MiB; {extra} more bytes dropped]\n",
            limit / (1024 * 1024)
        );
        buf.extend_from_slice(note.as_bytes());
    }
    buf
}

fn read_all(r: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || read_capped(r, MAX_OUTPUT))
}

/// Runs one plugin with the event on stdin and returns what it printed.
/// `max_time` caps the plugin's own `timeout_seconds` (the UI's test button
/// does not wait ten minutes). A non-zero exit is returned, not an error.
pub fn run(
    output: &OutputConfig,
    event_json: &str,
    max_time: Option<Duration>,
) -> Result<PluginRun, PluginError> {
    let mut cmd = command_for(output)?;
    apply_env(&mut cmd, output);
    cmd.current_dir(work_dir()?);
    let settings = serde_json::to_string(&output.settings)
        .map_err(|e| PluginError::Setup(format!("settings: {e}")))?;
    crate::proc_tree::prepare(&mut cmd);
    let mut child = cmd
        .env("PATHWARDEN_OUTPUT_SETTINGS", settings)
        .env("PATHWARDEN_OUTPUT_NAME", &output.plugin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PluginError::Start {
            plugin: output.plugin.clone(),
            detail: e.to_string(),
        })?;
    let tree = crate::proc_tree::Tree::attach(&child);

    // Feed stdin and drain stdout/stderr concurrently: a plugin that writes a
    // lot before reading would otherwise deadlock against us.
    let stdin = child.stdin.take();
    let event = event_json.to_owned();
    let writer = thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            // A plugin may exit without reading everything; that is its business.
            let _ = stdin.write_all(event.as_bytes());
        }
    });
    let stdout = read_all(child.stdout.take().expect("piped stdout"));
    let stderr = read_all(child.stderr.take().expect("piped stderr"));

    let mut timeout = timeout_of(output);
    if let Some(max) = max_time {
        timeout = timeout.min(max);
    }
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > timeout {
            // The whole tree: a grandchild must not outlive the timeout.
            tree.kill();
            let _ = child.kill();
            let _ = child.wait();
            // The reader threads finish when the pipes close; they are not
            // joined so a process that escaped the tree cannot hang the run.
            return Err(PluginError::Timeout(timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(50));
    };
    // Anything the plugin left running would hold its pipes open.
    tree.kill();
    let _ = writer.join();
    Ok(PluginRun {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// The most progress lines [`run_streaming`] keeps (the latest ones).
pub const MAX_PROGRESS_LINES: usize = 200;
/// The longest progress line kept, in characters; the rest is cut.
pub const MAX_LINE_CHARS: usize = 500;

/// Stops a program [`run_streaming`] runs, and every process it started,
/// from another thread (a Cancel button). Clones share one switch.
#[derive(Debug, Clone, Default)]
pub struct CancelHandle(Arc<AtomicBool>);

impl CancelHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the run to stop: it kills the process tree within 50 ms and
    /// returns with [`Stopped::Cancelled`].
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Why [`run_streaming`] stopped a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// It ran past its time limit (seconds).
    TimedOut(u64),
    /// Its [`CancelHandle`] was used.
    Cancelled,
}

/// What a program [`run_streaming`] ran printed and how it ended.
#[derive(Debug)]
pub struct Streamed {
    /// How it exited; `None` when it was stopped.
    pub status: Option<ExitStatus>,
    /// Why it was stopped; `None` when it exited by itself.
    pub stopped: Option<Stopped>,
    /// Its stdout lines, the latest [`MAX_PROGRESS_LINES`], each cut to
    /// [`MAX_LINE_CHARS`] and without control characters; empty lines are
    /// left out.
    pub lines: Vec<String>,
    /// Its stderr, capped at [`MAX_OUTPUT`]: what it wrote before it was
    /// stopped too.
    pub stderr: Vec<u8>,
}

/// How long the readers get, once the program has ended or was stopped,
/// to hand over what it wrote. A process that escaped the tree and holds
/// the pipes open can't hold the run up for longer.
const DRAIN_TIME: Duration = Duration::from_secs(2);

/// One stdout line as kept: control and bidi characters dropped, cut to
/// [`MAX_LINE_CHARS`]. `None` when nothing is left.
fn progress_line(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let line: String = text
        .chars()
        .filter(|c| !c.is_control() && !crate::text::is_bidi_control(*c))
        .take(MAX_LINE_CHARS)
        .collect();
    let line = line.trim();
    (!line.is_empty()).then(|| line.to_string())
}

/// Reads stdout line by line into `tx`, up to [`MAX_OUTPUT`] bytes; the
/// rest is read and dropped, so the program never blocks on a full pipe.
fn read_lines(r: impl Read + Send + 'static, tx: mpsc::Sender<String>) {
    thread::spawn(move || {
        let mut all = std::io::BufReader::new(r);
        let mut capped = (&mut all).take(MAX_OUTPUT as u64);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match capped.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Some(line) = progress_line(&buf) {
                        let _ = tx.send(line);
                    }
                }
            }
        }
        let _ = std::io::copy(&mut all, &mut std::io::sink());
    });
}

/// stderr as it is read, and whether its pipe has closed.
type SharedOutput = (Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>);

/// Reads stderr into a buffer shared as it grows, up to [`MAX_OUTPUT`]
/// bytes and a note if there was more, so what was read is there even if
/// the pipe never closes.
fn read_shared(mut r: impl Read + Send + 'static) -> SharedOutput {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let (b, d) = (buf.clone(), done.clone());
    thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        let mut extra: u64 = 0;
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut b = b.lock().unwrap_or_else(|e| e.into_inner());
                    let room = MAX_OUTPUT.saturating_sub(b.len());
                    b.extend_from_slice(&chunk[..n.min(room)]);
                    extra += n.saturating_sub(room) as u64;
                }
            }
        }
        if extra > 0 {
            let note = format!(
                "\n[pathwarden: output truncated after {} MiB; {extra} more bytes dropped]\n",
                MAX_OUTPUT / (1024 * 1024)
            );
            b.lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(note.as_bytes());
        }
        d.store(true, Ordering::SeqCst);
    });
    (buf, done)
}

/// Runs a program as [`run`] does (its process tree stopped at
/// `timeout`), with `input` on stdin and `cmd` set up by the caller
/// (environment, folder), and hands each stdout line to `on_line` as it
/// arrives, on this thread. `cancel` stops it at any time. A non-zero
/// exit, a timeout and a cancel are returned ([`Streamed::stopped`]), with
/// what it printed until then; `Err` only when it can't be started.
/// `label` names it in errors.
pub fn run_streaming(
    mut cmd: Command,
    label: &str,
    input: &str,
    timeout: Duration,
    on_line: &mut dyn FnMut(&str),
    cancel: &CancelHandle,
) -> Result<Streamed, PluginError> {
    crate::proc_tree::prepare(&mut cmd);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PluginError::Start {
            plugin: label.to_string(),
            detail: e.to_string(),
        })?;
    let tree = crate::proc_tree::Tree::attach(&child);
    let stdin = child.stdin.take();
    let text = input.to_owned();
    thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            // A program may exit without reading everything.
            let _ = stdin.write_all(text.as_bytes());
        }
    });
    let (tx, rx) = mpsc::channel();
    read_lines(child.stdout.take().expect("piped stdout"), tx);
    let (stderr, stderr_done) = read_shared(child.stderr.take().expect("piped stderr"));
    let mut kept: VecDeque<String> = VecDeque::new();
    let mut take = |line: String, kept: &mut VecDeque<String>| {
        on_line(&line);
        if kept.len() == MAX_PROGRESS_LINES {
            kept.pop_front();
        }
        kept.push_back(line);
    };
    let started = Instant::now();
    let (status, stopped) = loop {
        let stop = if cancel.is_cancelled() {
            Some(Stopped::Cancelled)
        } else if started.elapsed() > timeout {
            Some(Stopped::TimedOut(timeout.as_secs()))
        } else {
            None
        };
        if let Some(why) = stop {
            // The whole tree: a grandchild must not outlive it.
            tree.kill();
            let _ = child.kill();
            let _ = child.wait();
            break (None, Some(why));
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                take(line, &mut kept);
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // stdout closed but the program may run on: wait without spinning.
            Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(Duration::from_millis(50)),
        }
        if let Some(status) = child.try_wait()? {
            break (Some(status), None);
        }
    };
    // Anything the program left running would hold its pipes open.
    tree.kill();
    // What it wrote, for at most DRAIN_TIME: the readers are not waited
    // for past that, so a process that escaped the tree can't hang the run.
    let deadline = Instant::now() + DRAIN_TIME;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left.min(Duration::from_millis(50))) {
            Ok(line) => take(line, &mut kept),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) if left.is_zero() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    while !stderr_done.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let stderr = stderr.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(Streamed {
        status,
        stopped,
        lines: kept.into(),
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(json: &str) -> OutputConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn interpreters_and_absolute_paths_only() {
        assert!(is_interpreter("powershell"));
        assert!(is_interpreter("PowerShell.exe"));
        assert!(is_interpreter("python3"));
        assert!(!is_interpreter("notepad"));
        assert!(!is_interpreter(".\\powershell"));
        assert!(!is_interpreter("plugins/powershell"));
        let o = output(r#"{"plugin":"x","command":["teams-alert.exe"]}"#);
        let e = command_for(&o).unwrap_err().to_string();
        assert!(e.contains("absolute path"), "{e}");
    }

    /// A network or device path is never a plugin's program, and is
    /// refused before the file system is touched.
    #[test]
    fn network_programs_are_refused() {
        for p in [
            r"\\fabrikam\share\alert.exe",
            "//fabrikam/share/alert.exe",
            r"\\?\UNC\fabrikam\share\alert.exe",
            r"\\.\pipe\x",
            "file://fabrikam/share/alert.exe",
            r#""\\fabrikam\share\alert.exe""#,
        ] {
            let e = check_program(p).unwrap_err();
            assert!(e.contains("network or device path"), "{p}: {e}");
        }
        let abs = if cfg!(windows) {
            r"C:\Tools\alert.exe"
        } else {
            "/opt/tools/alert"
        };
        assert!(check_program(abs).is_ok());
        assert!(check_program("powershell").is_ok());
        let o = output(r#"{"plugin":"x","command":["\\\\fabrikam\\share\\alert.exe"]}"#);
        let e = command_for(&o).unwrap_err().to_string();
        assert!(e.contains("network or device path"), "{e}");
    }

    /// A network path anywhere in an argument, a mapped network drive, or
    /// a script by a relative path is refused, at save and at each run
    ///; URLs and absolute paths are fine.
    #[test]
    fn arguments_are_checked() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            r"\\srv\s\x.ps1",
            r"-File=\\srv\s\x.ps1",
            r"-File:\\srv\s\x.ps1",
            "--script=//srv/s/x.ps1",
            "-File://srv/s/x.ps1",
            "x//srv/y",
            "--x=file://srv/s",
            "--x=https://ok.example/a,//srv/s",
        ] {
            let e = check_args(&args(&["-NoProfile", bad])).unwrap_err();
            assert!(e.contains("network path"), "{bad}: {e}");
        }
        for rel in [
            "teams.ps1",
            r".\teams.ps1",
            "./alert",
            r"..\x",
            "scripts/teams.py",
            "-File=teams.ps1",
            "-File:teams.ps1",
        ] {
            let e = check_args(&args(&["-File", rel])).unwrap_err();
            assert!(e.contains("is a relative path"), "{rel}: {e}");
            assert!(e.contains("full path"), "{rel}: {e}");
        }
        let abs = if cfg!(windows) {
            r"C:\Pathwarden\teams.ps1"
        } else {
            "/opt/pathwarden/teams.sh"
        };
        let file_colon = format!("-File:{abs}");
        let file_eq = format!("--script={abs}");
        assert!(check_args(&args(&[
            "-NoProfile",
            "-File",
            abs,
            &file_colon,
            &file_eq,
            "--url=https://hooks.example.com/x?a=b",
            "-c",
            "print(1)",
        ]))
        .is_ok());
        // At each run too, not only when the page saves it.
        let o: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "x", "command": ["powershell", "-File", "teams.ps1"]
        }))
        .unwrap();
        let e = command_for(&o).unwrap_err().to_string();
        assert!(e.contains("is a relative path"), "{e}");
    }

    /// A plugin starts in a private folder of its own, not the current
    /// one, and on Windows a program it names isn't looked for in
    /// that folder first.
    #[test]
    fn plugins_start_in_their_own_folder() {
        let dir = work_dir().unwrap();
        assert!(crate::perms::is_private_dir(&dir), "{}", dir.display());
        assert_ne!(
            std::fs::canonicalize(&dir).unwrap(),
            std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
        );
        // Asked again: the same folder.
        assert_eq!(work_dir().unwrap(), dir);
        let command = if cfg!(windows) {
            serde_json::json!([
                "cmd",
                "/d",
                "/c",
                "cd",
                "&",
                "echo",
                "%NoDefaultCurrentDirectoryInExePath%"
            ])
        } else {
            serde_json::json!(["sh", "-c", "pwd"])
        };
        let o: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "where", "command": command
        }))
        .unwrap();
        let ran = run(&o, "{}", None).unwrap();
        let lines = ran.lines();
        let shown = std::fs::canonicalize(lines[0].trim()).unwrap();
        assert_eq!(shown, std::fs::canonicalize(&dir).unwrap(), "{lines:?}");
        if cfg!(windows) {
            assert_eq!(lines[1].trim(), "1", "{lines:?}");
        }
    }

    /// A folder for plugins to start in that someone else may open is
    /// refused, not used.
    #[test]
    fn a_shared_work_folder_is_refused() {
        let base = std::env::temp_dir().join(format!("pw-work-base-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = work_dir_in(&base);
        crate::perms::create_private_dir(&dir).unwrap();
        assert!(crate::perms::is_private_dir(&dir));
        #[cfg(windows)]
        {
            let ok = crate::spawn::quiet("icacls")
                .arg(&dir)
                .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(ok);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        assert!(!crate::perms::is_private_dir(&dir));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A program or plugins folder others can change is named at the
    /// start of a run; a private one, or one that isn't there, is
    /// not.
    #[test]
    fn folders_others_can_change_are_named() {
        let base = std::env::temp_dir().join(format!("pw-plugin-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let bin = base.join("bin");
        let plugins = bin.join("plugins");
        std::fs::create_dir_all(&base).unwrap();
        crate::perms::create_private_dir(&bin).unwrap();
        crate::perms::create_private_dir(&plugins).unwrap();
        let dirs = [bin.clone(), plugins.clone()];
        assert!(folder_warnings_for(&dirs).is_empty());
        assert!(folder_warnings_for(&[base.join("missing")]).is_empty());
        // Every user may change the plugins folder.
        #[cfg(windows)]
        {
            let ok = crate::spawn::quiet("icacls")
                .arg(&plugins)
                .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(ok);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let w = folder_warnings_for(&dirs);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].starts_with("Pathwarden's plugins folder, "), "{w:?}");
        assert!(w[0].contains(&plugins.display().to_string()), "{w:?}");
        assert!(
            w[0].ends_with("Let only administrators change it."),
            "{w:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The script a `command` names is checked like the program: a script
    /// whose folder Users may change is named, with who; a missing file, a
    /// URL or a network path is never looked at.
    #[cfg(windows)]
    #[test]
    fn scripts_others_can_change_are_named() {
        let dir = std::env::temp_dir().join(format!("pw-script-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("teams.ps1");
        std::fs::write(&script, "x").unwrap();
        let out = crate::spawn::quiet("icacls")
            .arg(&dir)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M", "/Q"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let s = script.display().to_string();
        let argv = |args: &[&str]| -> Vec<String> {
            std::iter::once("powershell")
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect()
        };
        let (colon, eq) = (format!("-File:{s}"), format!("--script={s}"));
        for args in [
            vec!["-File", s.as_str()],
            vec![colon.as_str()],
            vec![eq.as_str()],
        ] {
            let w = command_writers(&argv(&args));
            assert!(
                w.iter().any(|l| l.starts_with(&s) && l.contains("Users")),
                "{args:?}: {w:?}"
            );
        }
        let missing = dir.join("gone.ps1").display().to_string();
        assert!(!command_writers(&argv(&["-File", &missing]))
            .iter()
            .any(|l| l.contains("gone.ps1")));
        assert!(
            !command_writers(&argv(&[r"\\server\share\x.ps1", "https://example.com/x"]))
                .iter()
                .any(|l| l.contains("server") || l.contains("example"))
        );
        let outputs = vec![OutputConfig {
            plugin: "teams".into(),
            command: Some(argv(&["-File", &s])),
            settings: Default::default(),
        }];
        let warnings = command_warnings(&outputs);
        assert!(
            warnings
                .iter()
                .any(|w| w.starts_with("Plugin teams: ") && w.contains(&s)),
            "{warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interpreters_come_from_system_folders_only() {
        // The system shell is found where the system keeps it.
        let shell = if cfg!(windows) { "cmd" } else { "sh" };
        let found = resolve_interpreter(shell).expect("system shell");
        assert!(found.is_absolute(), "{}", found.display());
        assert!(resolve_interpreter("notepad").is_none());
        // A folder anyone can write to (the temp folder) is not trusted,
        // nor is a relative one.
        assert!(!trusted_dir(&std::env::temp_dir()));
        assert!(!trusted_dir(Path::new("bin")));
        if cfg!(windows) {
            let root = std::env::var_os("SystemRoot").unwrap();
            assert!(trusted_dir(&Path::new(&root).join("System32")));
            assert!(!trusted_dir(&Path::new(&root).join("..").join("Users")));
        } else {
            assert!(trusted_dir(Path::new("/usr/bin")) || trusted_dir(Path::new("/bin")));
        }
    }

    #[test]
    fn settings_drive_timeout_and_env_names() {
        let o = output(
            r#"{"plugin":"x","timeout_seconds":2,"password_env":"SN_PW","token_env":"","color":"x"}"#,
        );
        assert_eq!(timeout_of(&o), Duration::from_secs(2));
        assert_eq!(named_env(&o), ["SN_PW"]);
        // Pathwarden's own secrets never go to a plugin: the
        // history's passphrases, the signing key, the collection password.
        let o = output(
            r#"{"plugin":"x","a_env":"PATHWARDEN_HISTORY_PASSPHRASE","b_env":"pathwarden_history_new_passphrase","c_env":"OK","d_env":"PATHWARDEN_EVIDENCE_KEY","e_env":"Pathwarden_Collect_Password"}"#,
        );
        assert_eq!(named_env(&o), ["OK"]);
        assert_eq!(
            timeout_of(&output(r#"{"plugin":"x"}"#)),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn output_is_capped_with_a_note() {
        let small = read_capped(&b"hello"[..], 8);
        assert_eq!(small, b"hello");
        let big = vec![b'x'; 3 * 1024 * 1024 + 10];
        let kept = read_capped(&big[..], 1024 * 1024);
        let text = String::from_utf8_lossy(&kept);
        assert!(text.starts_with(&"x".repeat(1024 * 1024)));
        assert!(
            text.ends_with("truncated after 1 MiB; 2097162 more bytes dropped]\n"),
            "{}",
            &text[1024 * 1024..]
        );
    }

    /// A process the plugin starts dies with it at the timeout.
    #[test]
    fn timeout_stops_the_whole_process_tree() {
        let dir = std::env::temp_dir().join(format!("pw-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("grandchild-was-here");
        let m = marker.to_string_lossy().replace('\'', "''");
        let command = if cfg!(windows) {
            let inner = format!("Start-Sleep -Seconds 5; Set-Content -LiteralPath ''{m}'' x");
            serde_json::json!([
                "powershell",
                "-NoProfile",
                "-Command",
                format!(
                    "Start-Process -WindowStyle Hidden powershell -ArgumentList \
                     '-NoProfile','-Command','{inner}'; Start-Sleep -Seconds 60"
                )
            ])
        } else {
            serde_json::json!(["sh", "-c", format!("(sleep 5; touch '{m}') & sleep 60")])
        };
        let o: OutputConfig = serde_json::from_value(serde_json::json!({
            "plugin": "tree", "timeout_seconds": 2, "command": command
        }))
        .unwrap();
        let started = Instant::now();
        let err = run(&o, "{}", None).unwrap_err();
        assert!(matches!(err, PluginError::Timeout(2)), "{err}");
        assert!(started.elapsed() < Duration::from_secs(20));
        thread::sleep(Duration::from_secs(8));
        assert!(!marker.exists(), "the grandchild outlived the timeout");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_names() {
        assert!(valid_env_name("PATHWARDEN_SN_USER"));
        assert!(valid_env_name("_x1"));
        assert!(!valid_env_name("1X"));
        assert!(!valid_env_name("A-B"));
        assert!(!valid_env_name(""));
        assert!(!valid_env_name("A B"));
    }
}
