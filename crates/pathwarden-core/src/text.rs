//! Making directory-controlled text safe to display.
//!
//! Names, descriptions, GPO and template names come from Active Directory
//! (or from whoever wrote a collection), so they can hold terminal control
//! sequences (ESC, CSI, `\r`, C1 controls) that recolor, erase or forge
//! output lines, and Unicode bidi controls (U+202E and friends) that make
//! a name read differently from what it is. These helpers render such
//! characters visibly, as `\u{202e}`, so nothing is hidden and nothing is
//! lost.
//!
//! Also [`count`], for the counts in finding titles and messages.

use std::borrow::Cow;
use std::fmt::Write;

/// Unicode bidirectional formatting characters: embeddings and overrides
/// (U+202A–U+202E), isolates (U+2066–U+2069), and the implicit marks
/// (U+200E, U+200F, U+061C).
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

fn escape_where(s: &str, unsafe_char: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !s.chars().any(&unsafe_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if unsafe_char(c) {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// For one line of terminal or log output: every control character (C0
/// including ESC, `\r` and `\n`, DEL, C1 including CSI U+009B) and every
/// bidi control is shown escaped.
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    escape_where(s, |c| {
        c.is_control() || is_bidi_control(c) || matches!(c, '\u{2028}' | '\u{2029}')
    })
}

/// Whether `c` breaks a line: line feed, carriage return, vertical tab,
/// form feed, next line (U+0085), and the Unicode line and paragraph
/// separators. What a name may not hold once it is read ([`one_line`]).
/// Other control characters stay, for [`terminal_safe`] to show escaped.
pub fn breaks_line(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// `s` on one line: every line break ([`breaks_line`]) becomes a space.
/// Applied to directory names and domains as they are read, so a name
/// can't add a line of its own to a remediation, a ticket or an export
/// that quotes it.
pub fn one_line(s: &str) -> Cow<'_, str> {
    if !s.chars().any(breaks_line) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| if breaks_line(c) { ' ' } else { c })
            .collect(),
    )
}

/// [`terminal_safe`] for text of several lines: `\n` and `\t` are kept.
/// The Unicode line and paragraph separators (U+2028, U+2029) are shown
/// escaped too: a terminal would start a line nothing indents.
pub fn terminal_safe_text(s: &str) -> Cow<'_, str> {
    escape_where(s, |c| {
        (c.is_control() && c != '\n' && c != '\t')
            || is_bidi_control(c)
            || matches!(c, '\u{2028}' | '\u{2029}')
    })
}

/// A value for an HTML attribute that the page sends back as it is (an
/// input's value, a `data-value`): `& < > " '` escaped and nothing else,
/// so a bidi control in a name comes back unchanged. Text shown on the
/// page uses an escape that shows bidi controls instead.
pub fn html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// JSON for an HTML attribute (`data-…="…"`), read back with JSON.parse:
/// bidi controls are written as JSON escapes (`\u202e`), so the JSON stays
/// valid and no character in it reorders the page's source.
pub fn json_attr(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if is_bidi_control(c) {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    html_attr(&out)
}

/// For HTML or other rich text, where control characters are harmless once
/// escaped but bidi controls still reorder what is shown: bidi controls are
/// shown escaped, everything else is left alone (escape HTML separately).
pub fn bidi_safe(s: &str) -> Cow<'_, str> {
    escape_where(s, is_bidi_control)
}

#[cfg(test)]
mod attr_tests {
    use super::*;

    #[test]
    fn attributes_keep_values_and_json_stays_json() {
        assert_eq!(
            html_attr("A\u{202e}<\"'&>"),
            "A\u{202e}&lt;&quot;&#39;&amp;&gt;"
        );
        let v = serde_json::json!({"zone": "T1 \u{202e}x"});
        let attr = json_attr(&v.to_string());
        assert!(!attr.contains('\u{202e}') && attr.contains(r"\u202e"));
        let back = attr.replace("&quot;", "\"");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&back).unwrap(), v);
        assert_eq!(terminal_safe_text("a\u{2028}b\nc"), "a\\u{2028}b\nc");
    }
}

/// A count with thousands separators: 1169537 -> "1,169,537".
pub fn num(n: usize) -> String {
    crate::report::num(n)
}

/// A count and its noun, singular or plural, with thousands separators:
/// "1 account", "1,230 accounts". Instead of "account(s)".
pub fn count(n: usize, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        crate::report::num(n),
        if n == 1 { one } else { many }
    )
}

/// "A", "A and B", "A, B and C".
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_borrowed() {
        assert!(matches!(
            terminal_safe("JDOE@CONTOSO.LOCAL"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(bidi_safe("ÉLODIE — 管理者"), Cow::Borrowed(_)));
    }

    #[test]
    fn terminal_controls_are_escaped() {
        let evil = "A\u{1b}[31mB\u{1b}]0;title\u{7}C\rD\u{9b}2KE\u{7f}F\nG";
        let safe = terminal_safe(evil);
        assert!(!safe.chars().any(|c| c.is_control()), "{safe}");
        assert_eq!(
            safe,
            "A\\u{1b}[31mB\\u{1b}]0;title\\u{7}C\\u{d}D\\u{9b}2KE\\u{7f}F\\u{a}G"
        );
        assert_eq!(terminal_safe_text("a\nb\tc\rd"), "a\nb\tc\\u{d}d");
    }

    #[test]
    fn bidi_controls_are_shown() {
        let spoof = "ADMIN\u{202E}TXT.EXE\u{2066}x\u{2069}";
        assert_eq!(bidi_safe(spoof), "ADMIN\\u{202e}TXT.EXE\\u{2066}x\\u{2069}");
        assert_eq!(terminal_safe(spoof), bidi_safe(spoof));
        for c in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{2067}', '\u{2068}',
        ] {
            assert!(is_bidi_control(c));
        }
        // Control characters are left to the HTML escaper.
        assert_eq!(bidi_safe("a\u{1b}b"), "a\u{1b}b");
    }
}
