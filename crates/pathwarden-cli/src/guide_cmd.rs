//! `pathwarden guide RULE`: a rule's remediation guide, the one the report
//! links each finding to. The guides are Markdown; the terminal gets them
//! as plain text (headings in bold, no `#`, `**` or backticks, paragraphs
//! wrapped), `--markdown` the source, `--json` both.

use anstream::print;
use anyhow::{bail, Result};

use crate::{emit_json, help, ui};

pub(crate) fn guide(rule: &str, markdown: bool, json: bool) -> Result<()> {
    let Some(text) = pathwarden_core::guides::guide(rule) else {
        bail!("No guide for '{rule}'. See `pathwarden rules`.");
    };
    if json {
        return emit_json(&serde_json::json!({
            "rule": rule.trim().to_ascii_uppercase(),
            "markdown": text,
            "text": plain(text, false),
        }));
    }
    if markdown {
        print!("{text}");
    } else {
        print!("{}", plain(text, true));
    }
    Ok(())
}

/// `**bold**` and `` `code` `` as plain words.
fn inline(s: &str) -> String {
    s.replace("**", "").replace('`', "")
}

/// A list item's marker ("- ", "1. ") and the rest, if `line` is one.
fn list_item(line: &str) -> Option<(&str, &str)> {
    if let Some(rest) = line.strip_prefix("- ") {
        return Some(("- ", rest));
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    (digits > 0 && line[digits..].starts_with(". "))
        .then(|| (&line[..digits + 2], &line[digits + 2..]))
}

/// The guide `md` as terminal text, headings in bold when `styled`.
fn plain(md: &str, styled: bool) -> String {
    let width = help::WIDTH;
    let mut out = String::new();
    // The words of the paragraph or list item being gathered, and the
    // item's marker.
    let mut words = String::new();
    let mut marker: Option<String> = None;
    let flush = |out: &mut String, words: &mut String, marker: &mut Option<String>| {
        if words.is_empty() {
            return;
        }
        let text = inline(words.trim());
        match marker.take() {
            Some(m) => {
                let indent = " ".repeat(m.len() + 2);
                for (i, l) in help::wrap(&text, width - indent.len()).iter().enumerate() {
                    if i == 0 {
                        out.push_str(&format!("  {m}{l}\n"));
                    } else {
                        out.push_str(&format!("{indent}{l}\n"));
                    }
                }
            }
            None => {
                for l in help::wrap(&text, width) {
                    out.push_str(&l);
                    out.push('\n');
                }
            }
        }
        words.clear();
    };
    // The marker's length of the list item the lines are under.
    let mut item: Option<usize> = None;
    for line in md.lines() {
        let trimmed = line.trim_end();
        let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
        if hashes > 0 && trimmed[hashes..].starts_with(' ') {
            flush(&mut out, &mut words, &mut marker);
            item = None;
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            let title = inline(trimmed[hashes..].trim());
            if styled {
                let b = ui::BOLD;
                out.push_str(&format!("{b}{title}{b:#}\n"));
            } else {
                out.push_str(&title);
                out.push('\n');
            }
            continue;
        }
        if trimmed.trim().is_empty() {
            flush(&mut out, &mut words, &mut marker);
            item = None;
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            continue;
        }
        // "**Category:** Attack path": a line of its own.
        if trimmed.starts_with("**") {
            flush(&mut out, &mut words, &mut marker);
            words.push_str(trimmed);
            flush(&mut out, &mut words, &mut marker);
            continue;
        }
        if let Some((m, rest)) = list_item(trimmed) {
            flush(&mut out, &mut words, &mut marker);
            marker = Some(m.to_string());
            item = Some(m.len());
            words.push_str(rest);
            continue;
        }
        let indented = line.starts_with("  ");
        if !indented {
            item = None;
        }
        // An indented line under a list item that is code (a command):
        // kept whole on a line of its own.
        if indented && trimmed.trim_start().starts_with('`') {
            flush(&mut out, &mut words, &mut marker);
            let indent = " ".repeat(item.map_or(2, |n| n + 2));
            out.push_str(&format!("{indent}{}\n", inline(trimmed.trim())));
            continue;
        }
        // More of the item after its command: at the item's indent.
        if indented && words.is_empty() {
            if let Some(n) = item {
                marker = Some(" ".repeat(n));
            }
        }
        if !words.is_empty() {
            words.push(' ');
        }
        words.push_str(trimmed.trim());
    }
    flush(&mut out, &mut words, &mut marker);
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_reads_as_plain_text() {
        let md = "# PW-015: AD CS ESC1\n\n**Category:** Attack path\n**Typical owner:** PKI\n\n\
## What this finding means\nA template lets `requesters` choose\nany name.\n\n\
## Fix\n- Find who uses it:\n  `certutil -view -restrict \"CertificateTemplate=X\"`\n\
- Check **autoenrollment**.\n1. Open certtmpl.msc.\n";
        let text = plain(md, false);
        assert!(
            !text.contains('#') && !text.contains("**") && !text.contains('`'),
            "{text}"
        );
        assert!(text.starts_with("PW-015: AD CS ESC1\n\nCategory: Attack path\nTypical owner: PKI\n\nWhat this finding means\nA template lets requesters choose any name.\n"), "{text}");
        assert!(text.contains("  - Find who uses it:\n    certutil -view -restrict \"CertificateTemplate=X\"\n  - Check autoenrollment.\n  1. Open certtmpl.msc.\n"), "{text}");
        for guide in pathwarden_core::guides::ALL {
            let text = plain(pathwarden_core::guides::guide(guide).unwrap(), false);
            assert!(!text.contains("**") && !text.contains("\n#"), "{guide}");
        }
    }
}
