//! Values in the commands the CLI suggests (`pathwarden run -i ... --save`),
//! quoted so they paste into the shell unchanged. On Windows the shell is
//! taken to be PowerShell: cmd and Git Bash users get single quotes cmd
//! doesn't read, which is accepted.

use std::path::Path;

/// Characters the shell would expand or read inside double quotes. On
/// Windows that includes the curly quotes PowerShell takes as quotes (and
/// the curly single quotes, so [`single_quoted`] doubles them); outside
/// Windows, the backslash.
#[cfg(windows)]
const SPECIAL: &[char] = &[
    '$', '`', '"', '!', '\u{201C}', '\u{201D}', '\u{201E}', '\u{2018}', '\u{2019}', '\u{201A}',
    '\u{201B}',
];
#[cfg(not(windows))]
const SPECIAL: &[char] = &['$', '`', '"', '!', '\\'];

/// A command-line value, quoted when it needs to be. Bare when it is plain
/// (and doesn't start with `@`, splatting in PowerShell, or `-`); in single
/// quotes, which PowerShell and POSIX shells take literally, when it has a
/// [`SPECIAL`] character; else in double quotes, with backslashes before
/// the closing one doubled (as in `".\out\\"`). That doubling is for
/// Windows PowerShell 5.1 and cmd, which hand the value on as typed;
/// PowerShell 7.3+ keeps the doubled backslash, harmless in a path.
pub(crate) fn quoted(s: &str) -> String {
    if !s.is_empty()
        && !s.starts_with(['@', '-'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
    {
        return s.to_string();
    }
    if s.contains(SPECIAL) {
        return single_quoted(s);
    }
    format!("\"{s}{}\"", "\\".repeat(trailing_backslashes(s)))
}

/// [`quoted`] for a path.
pub(crate) fn quoted_path(p: &Path) -> String {
    quoted(&p.display().to_string())
}

fn trailing_backslashes(s: &str) -> usize {
    s.len() - s.trim_end_matches('\\').len()
}

/// Single quotes for PowerShell: a single quote inside, straight or curly,
/// is doubled. Windows PowerShell 5.1 hands a value with a space to the
/// program in double quotes, so backslashes at its end are doubled then.
/// An embedded `"` doesn't survive 5.1 (the program gets `say hi` for
/// `'say "hi"'`); 7.3+ passes it on.
#[cfg(windows)]
fn single_quoted(s: &str) -> String {
    let mut body = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        body.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            body.push(c);
        }
    }
    if s.contains(char::is_whitespace) {
        body.push_str(&"\\".repeat(trailing_backslashes(s)));
    }
    format!("'{body}'")
}

/// Single quotes for a POSIX shell: a `'` inside closes them, is escaped
/// and opens them again (`'\''`).
#[cfg(not(windows))]
fn single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::quoted;

    /// Values the shell would mangle in double quotes, and what it should
    /// read back.
    const TRICKY: &[&str] = &[
        "CONTOSO.LOCAL",
        "second look",
        "$HOME",
        "a `b` $(c)",
        "it's",
        "it's $5",
        "it\u{2019}s $5",
        r#"say "hi""#,
        "say \u{201C}hi\u{201D}",
        "hi!",
        "@all",
        "-x",
        r"C:\runs\a b",
        "",
    ];

    #[test]
    fn quoted_values_survive_the_shell() {
        assert_eq!(quoted("CONTOSO.LOCAL"), "CONTOSO.LOCAL");
        assert_eq!(quoted("a@b.c"), "a@b.c");
        assert_eq!(quoted("@all"), r#""@all""#);
        assert_eq!(quoted("-x"), r#""-x""#);
        assert_eq!(quoted("second look"), r#""second look""#);
        assert_eq!(quoted("it's"), r#""it's""#);
        assert_eq!(quoted(""), r#""""#);
        if cfg!(windows) {
            assert_eq!(quoted(r"C:\runs\a b"), r#""C:\runs\a b""#);
            // A trailing backslash would escape the closing quote.
            assert_eq!(quoted(r".\out2\"), r#"".\out2\\""#);
            assert_eq!(quoted("$HOME"), "'$HOME'");
            assert_eq!(quoted("a`b"), "'a`b'");
            assert_eq!(quoted("it's $5"), "'it''s $5'");
            assert_eq!(quoted("it\u{2019}s $5"), "'it\u{2019}\u{2019}s $5'");
            assert_eq!(quoted("it\u{2019}s"), "'it\u{2019}\u{2019}s'");
            assert_eq!(quoted(r#"say "hi""#), r#"'say "hi"'"#);
            assert_eq!(quoted("say \u{201C}hi\u{201D}"), "'say \u{201C}hi\u{201D}'");
            assert_eq!(quoted("hi!"), "'hi!'");
            // Windows PowerShell 5.1 passes this one on in double quotes.
            assert_eq!(quoted(r"C:\a $b\"), r"'C:\a $b\\'");
            assert_eq!(quoted(r".\$out\"), r"'.\$out\'");
        } else {
            assert_eq!(quoted(r"C:\runs\a b"), r"'C:\runs\a b'");
            assert_eq!(quoted(r".\out2\"), r"'.\out2\'");
            assert_eq!(quoted("$HOME"), "'$HOME'");
            assert_eq!(quoted("a`b"), "'a`b'");
            assert_eq!(quoted("it's $5"), r"'it'\''s $5'");
            assert_eq!(quoted(r#"say "hi""#), r#"'say "hi"'"#);
            assert_eq!(quoted("hi!"), "'hi!'");
            assert_eq!(quoted(r#"a\"b"#), r#"'a\"b'"#);
        }
    }

    /// PowerShell parses each value back unchanged (as a function's
    /// argument: what reaches a program can differ, see `single_quoted`).
    #[cfg(windows)]
    #[test]
    fn powershell_parses_quoted_values_back() {
        let mut script = String::from(
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
             function a { [Console]::Out.Write($args[0] + [char]1) }",
        );
        for s in TRICKY {
            script.push_str(&format!("; a {}", quoted(s)));
        }
        let out = pathwarden_core::spawn::quiet("powershell.exe")
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("powershell runs");
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8(out.stdout).expect("UTF-8");
        let back: Vec<&str> = text.trim_start_matches('\u{feff}').split('\u{1}').collect();
        assert_eq!(back[..back.len() - 1], *TRICKY);
    }

    /// A POSIX shell reads each value back unchanged.
    #[cfg(unix)]
    #[test]
    fn sh_reads_quoted_values_back() {
        let more = [r".\out2\", r#"a\"b"#, r"\\server\share x"];
        for s in TRICKY.iter().chain(&more) {
            let out = pathwarden_core::spawn::quiet("sh")
                .args(["-c", &format!("printf %s {}", quoted(s))])
                .output()
                .expect("sh runs");
            assert!(out.status.success(), "{s}: {out:?}");
            assert_eq!(String::from_utf8_lossy(&out.stdout), *s);
        }
    }
}
