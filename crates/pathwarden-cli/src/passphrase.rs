//! Reading a history passphrase: typed without echo at a terminal (twice
//! for a new one), one line from stdin when it is piped, or an environment
//! variable (`--from-env`).

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Context, Result};
use pathwarden_core::crypt::{self, ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// A new passphrase: from `env_var` when given, else typed twice at a
/// terminal, else the first line of stdin. Checked for length.
pub(crate) fn new(env_var: Option<&str>, prompt: &str) -> Result<SecretString> {
    let p = match env_var {
        Some(var) => from_env(var)?,
        None if std::io::stdin().is_terminal() => {
            let first = hidden(&format!("{prompt}: "))?;
            crypt::check_passphrase(&first).map_err(anyhow::Error::msg)?;
            let again = hidden("Type it again: ")?;
            if first.expose_secret() != again.expose_secret() {
                bail!("the two passphrases differ; nothing was changed");
            }
            first
        }
        None => line()?,
    };
    crypt::check_passphrase(&p).map_err(anyhow::Error::msg)?;
    Ok(p)
}

/// A passphrase typed once at a terminal; `None` when stdin isn't one.
pub(crate) fn ask(prompt: &str) -> Result<Option<SecretString>> {
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    hidden(&format!("{prompt}: ")).map(Some)
}

/// `--from-env`: [`keystore::ENV_VAR`] or [`keystore::NEW_ENV_VAR`], as
/// `main` took them from the environment ([`keystore::take_env`]).
pub(crate) fn from_env(var: &str) -> Result<SecretString> {
    use pathwarden_core::keystore;
    let value = if var == keystore::NEW_ENV_VAR {
        keystore::new_from_env()?
    } else {
        keystore::from_env()?
    };
    value.ok_or_else(|| anyhow::anyhow!("--from-env: {var} is not set"))
}

/// A buffer for one typed or piped line, zeroed when dropped, and large
/// enough that reading never moves it (leaving a copy behind).
fn line_buffer() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(4 * crypt::MAX_PASSPHRASE))
}

/// The first line of stdin, without its line ending.
fn line() -> Result<SecretString> {
    let mut s = line_buffer();
    std::io::stdin()
        .lock()
        .read_line(&mut s)
        .context("reading the passphrase from stdin")?;
    let trimmed = s.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        bail!(
            "no passphrase: type it at a terminal, pipe it in on one line, or use --from-env with {}",
            pathwarden_core::keystore::ENV_VAR
        );
    }
    Ok(crypt::secret_from(trimmed))
}

/// Reads a line from the terminal with echo off.
fn hidden(prompt: &str) -> Result<SecretString> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let _echo = EchoOff::new();
    let mut s = line_buffer();
    let read = std::io::stdin().lock().read_line(&mut s);
    drop(_echo);
    eprintln!();
    read.context("reading the passphrase")?;
    Ok(crypt::secret_from(s.trim_end_matches(['\r', '\n'])))
}

/// Terminal echo turned off until dropped.
struct EchoOff {
    #[cfg(windows)]
    restore: Option<(windows_sys::Win32::Foundation::HANDLE, u32)>,
    #[cfg(unix)]
    restore: Option<libc::termios>,
}

impl EchoOff {
    #[cfg(windows)]
    fn new() -> Self {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
        };
        // SAFETY: a handle of this process; the mode is restored on drop.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            if GetConsoleMode(h, &mut mode) == 0 {
                return EchoOff { restore: None };
            }
            if SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) == 0 {
                return EchoOff { restore: None };
            }
            EchoOff {
                restore: Some((h, mode)),
            }
        }
    }

    #[cfg(unix)]
    fn new() -> Self {
        // SAFETY: termios of stdin, restored on drop.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return EchoOff { restore: None };
            }
            let saved = t;
            t.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(0, libc::TCSANOW, &t) != 0 {
                return EchoOff { restore: None };
            }
            EchoOff {
                restore: Some(saved),
            }
        }
    }

    #[cfg(not(any(windows, unix)))]
    fn new() -> Self {
        EchoOff {}
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some((h, mode)) = self.restore.take() {
            // SAFETY: the handle and mode read in `new`.
            unsafe {
                windows_sys::Win32::System::Console::SetConsoleMode(h, mode);
            }
        }
        #[cfg(unix)]
        if let Some(t) = self.restore.take() {
            // SAFETY: the termios read in `new`.
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
}
