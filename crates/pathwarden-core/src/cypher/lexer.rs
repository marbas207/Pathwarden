//! A hand-rolled tokeniser for the spike Cypher subset. No external crates, per
//! the project's dependency-light rule.
//!
//! Positions are character indices into the source, used for friendly parse
//! errors ("expected ')' at position 17"). Keywords are not distinguished here:
//! Cypher keywords are case-insensitive, so the parser matches identifiers
//! against keyword text itself.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Colon,
    Comma,
    Dot,
    Pipe,
    Star,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    Dash,
    /// `=~`: lexed only to refuse it clearly.
    RegexMatch,
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    /// 9223372036854775808: valid only negated, as `i64::MIN`.
    IntMinMagnitude,
    Eof,
}

impl Tok {
    /// A short label for error messages.
    pub fn describe(&self) -> String {
        match self {
            Tok::LParen => "'('".into(),
            Tok::RParen => "')'".into(),
            Tok::LBracket => "'['".into(),
            Tok::RBracket => "']'".into(),
            Tok::LBrace => "'{'".into(),
            Tok::RBrace => "'}'".into(),
            Tok::Colon => "':'".into(),
            Tok::Comma => "','".into(),
            Tok::Dot => "'.'".into(),
            Tok::Pipe => "'|'".into(),
            Tok::Star => "'*'".into(),
            Tok::Eq => "'='".into(),
            Tok::Neq => "'<>'".into(),
            Tok::Lt => "'<'".into(),
            Tok::Gt => "'>'".into(),
            Tok::Lte => "'<='".into(),
            Tok::Gte => "'>='".into(),
            Tok::Dash => "'-'".into(),
            Tok::RegexMatch => "'=~'".into(),
            Tok::Ident(s) => format!("identifier '{s}'"),
            Tok::Str(_) => "string".into(),
            Tok::Int(_) => "integer".into(),
            Tok::Float(_) => "number".into(),
            Tok::IntMinMagnitude => "integer".into(),
            Tok::Eof => "end of query".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub pos: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub pos: usize,
    pub msg: String,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&super::sentence(&format!(
            "{} (position {})",
            self.msg, self.pos
        )))
    }
}

/// Tokenises the whole query, always ending with [`Tok::Eof`].
pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Comments, as BloodHound's query library writes them.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let open = i;
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            if i >= chars.len() {
                return Err(LexError {
                    pos: open,
                    msg: "unterminated comment".into(),
                });
            }
            i += 2;
            continue;
        }
        let start = i;
        let single = |t: Tok| Some(t);
        let tok =
            match c {
                '(' => single(Tok::LParen),
                ')' => single(Tok::RParen),
                '[' => single(Tok::LBracket),
                ']' => single(Tok::RBracket),
                '{' => single(Tok::LBrace),
                '}' => single(Tok::RBrace),
                ':' => single(Tok::Colon),
                ',' => single(Tok::Comma),
                '.' => single(Tok::Dot),
                '|' => single(Tok::Pipe),
                '*' => single(Tok::Star),
                '-' => single(Tok::Dash),
                '=' if chars.get(i + 1) == Some(&'~') => {
                    i += 1;
                    single(Tok::RegexMatch)
                }
                '=' => single(Tok::Eq),
                '$' => return Err(LexError {
                    pos: start,
                    msg: "query parameters ($name) are not supported; write the value in the query"
                        .into(),
                }),
                // A quoted name: `my label`.
                '`' => {
                    let Some(len) = chars[i + 1..].iter().position(|&c| c == '`') else {
                        return Err(LexError {
                            pos: start,
                            msg: "unterminated `quoted name`".into(),
                        });
                    };
                    if len == 0 {
                        return Err(LexError {
                            pos: start,
                            msg: "an empty `quoted name`".into(),
                        });
                    }
                    let word: String = chars[i + 1..i + 1 + len].iter().collect();
                    i += len + 2;
                    out.push(Token {
                        tok: Tok::Ident(word),
                        pos: start,
                    });
                    continue;
                }
                '<' => {
                    if chars.get(i + 1) == Some(&'=') {
                        i += 1;
                        single(Tok::Lte)
                    } else if chars.get(i + 1) == Some(&'>') {
                        i += 1;
                        single(Tok::Neq)
                    } else {
                        single(Tok::Lt)
                    }
                }
                '>' => {
                    if chars.get(i + 1) == Some(&'=') {
                        i += 1;
                        single(Tok::Gte)
                    } else {
                        single(Tok::Gt)
                    }
                }
                '"' | '\'' => {
                    let (s, next) = lex_string(&chars, i, c)?;
                    i = next;
                    out.push(Token {
                        tok: Tok::Str(s),
                        pos: start,
                    });
                    continue;
                }
                c if c.is_ascii_digit() => {
                    let (t, next) = lex_number(&chars, i)?;
                    i = next;
                    out.push(Token { tok: t, pos: start });
                    continue;
                }
                c if c.is_alphabetic() || c == '_' => {
                    let mut j = i;
                    while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                        j += 1;
                    }
                    let word: String = chars[i..j].iter().collect();
                    i = j;
                    out.push(Token {
                        tok: Tok::Ident(word),
                        pos: start,
                    });
                    continue;
                }
                other => {
                    return Err(LexError {
                        pos: start,
                        msg: format!("unexpected character '{other}'"),
                    })
                }
            };
        i += 1;
        if let Some(t) = tok {
            out.push(Token { tok: t, pos: start });
        }
    }
    out.push(Token {
        tok: Tok::Eof,
        pos: chars.len(),
    });
    Ok(out)
}

/// Reads a quoted string starting at the opening quote `quote` (index `i`),
/// honouring `\\`, `\"`, `\'`, `\n`, `\t`, `\r` escapes. Returns the content and
/// the index just past the closing quote.
fn lex_string(chars: &[char], i: usize, quote: char) -> Result<(String, usize), LexError> {
    let mut s = String::new();
    let mut j = i + 1;
    while j < chars.len() {
        let c = chars[j];
        if c == '\\' {
            let Some(&esc) = chars.get(j + 1) else {
                return Err(LexError {
                    pos: j,
                    msg: "unterminated escape in string".into(),
                });
            };
            s.push(match esc {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                '\'' => '\'',
                '"' => '"',
                other => other,
            });
            j += 2;
            continue;
        }
        if c == quote {
            return Ok((s, j + 1));
        }
        s.push(c);
        j += 1;
    }
    Err(LexError {
        pos: i,
        msg: "unterminated string literal".into(),
    })
}

/// Reads an integer or float starting at `i`. Returns the token and the index
/// just past it.
fn lex_number(chars: &[char], i: usize) -> Result<(Tok, usize), LexError> {
    let mut j = i;
    let mut is_float = false;
    while j < chars.len() && chars[j].is_ascii_digit() {
        j += 1;
    }
    // A single '.' followed by a digit makes it a float; '.' alone stays a Dot
    // token (so `n.name` still lexes its property access).
    if chars.get(j) == Some(&'.') && chars.get(j + 1).is_some_and(|c| c.is_ascii_digit()) {
        is_float = true;
        j += 1;
        while j < chars.len() && chars[j].is_ascii_digit() {
            j += 1;
        }
    }
    // An exponent: 1e3, 1.8e19, 2E-5.
    if matches!(chars.get(j), Some('e' | 'E')) {
        let digits_at = match chars.get(j + 1) {
            Some('+' | '-') => j + 2,
            _ => j + 1,
        };
        if chars.get(digits_at).is_some_and(|c| c.is_ascii_digit()) {
            is_float = true;
            j = digits_at;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
        }
    }
    let text: String = chars[i..j].iter().collect();
    let tok = if is_float {
        let f: f64 = text.parse().map_err(|_| LexError {
            pos: i,
            msg: format!("invalid number '{text}'"),
        })?;
        if !f.is_finite() {
            return Err(LexError {
                pos: i,
                msg: format!("number '{text}' is too large"),
            });
        }
        Tok::Float(f)
    } else if text == "9223372036854775808" {
        Tok::IntMinMagnitude
    } else {
        Tok::Int(text.parse().map_err(|_| LexError {
            pos: i,
            msg: format!("integer '{text}' is too large"),
        })?)
    };
    Ok((tok, j))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn lexes_a_node_pattern() {
        assert_eq!(
            kinds("MATCH (n:Group) RETURN n"),
            vec![
                Tok::Ident("MATCH".into()),
                Tok::LParen,
                Tok::Ident("n".into()),
                Tok::Colon,
                Tok::Ident("Group".into()),
                Tok::RParen,
                Tok::Ident("RETURN".into()),
                Tok::Ident("n".into()),
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn lexes_relationship_arrows() {
        // Direction is assembled by the parser from Dash/Lt/Gt tokens.
        assert_eq!(
            kinds("(a)-[:MemberOf]->(b)"),
            vec![
                Tok::LParen,
                Tok::Ident("a".into()),
                Tok::RParen,
                Tok::Dash,
                Tok::LBracket,
                Tok::Colon,
                Tok::Ident("MemberOf".into()),
                Tok::RBracket,
                Tok::Dash,
                Tok::Gt,
                Tok::LParen,
                Tok::Ident("b".into()),
                Tok::RParen,
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn lexes_comparison_and_string() {
        assert_eq!(
            kinds(r#"WHERE n.name = "A\"B" AND x <> 1"#),
            vec![
                Tok::Ident("WHERE".into()),
                Tok::Ident("n".into()),
                Tok::Dot,
                Tok::Ident("name".into()),
                Tok::Eq,
                Tok::Str("A\"B".into()),
                Tok::Ident("AND".into()),
                Tok::Ident("x".into()),
                Tok::Neq,
                Tok::Int(1),
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn exponents_and_the_largest_magnitude() {
        assert_eq!(kinds("1.8e19"), vec![Tok::Float(1.8e19), Tok::Eof]);
        assert_eq!(kinds("2E-5"), vec![Tok::Float(2e-5), Tok::Eof]);
        assert_eq!(kinds("1e+3"), vec![Tok::Float(1000.0), Tok::Eof]);
        // `e` without digits is not an exponent.
        assert_eq!(
            kinds("1e"),
            vec![Tok::Int(1), Tok::Ident("e".into()), Tok::Eof]
        );
        assert_eq!(
            kinds("9223372036854775808"),
            vec![Tok::IntMinMagnitude, Tok::Eof]
        );
        assert!(lex("9223372036854775809").is_err());
        assert!(lex("1e400").is_err());
    }

    #[test]
    fn number_vs_property_dot() {
        assert_eq!(kinds("3.5"), vec![Tok::Float(3.5), Tok::Eof]);
        // The dot after an identifier is property access, not a float.
        assert_eq!(
            kinds("n.pwdlastset"),
            vec![
                Tok::Ident("n".into()),
                Tok::Dot,
                Tok::Ident("pwdlastset".into()),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn comments_are_skipped() {
        assert_eq!(
            kinds("RETURN // a comment\n n /* and\n another */ LIMIT"),
            vec![
                Tok::Ident("RETURN".into()),
                Tok::Ident("n".into()),
                Tok::Ident("LIMIT".into()),
                Tok::Eof
            ]
        );
        assert!(lex("n /* never closed").is_err());
        // Not a comment: a lone slash.
        assert!(lex("a / b").is_err());
    }

    #[test]
    fn ranges_regex_and_quoted_names() {
        assert_eq!(
            kinds("*1..3"),
            vec![
                Tok::Star,
                Tok::Int(1),
                Tok::Dot,
                Tok::Dot,
                Tok::Int(3),
                Tok::Eof
            ]
        );
        assert_eq!(kinds("=~"), vec![Tok::RegexMatch, Tok::Eof]);
        assert_eq!(kinds("`a b`"), vec![Tok::Ident("a b".into()), Tok::Eof]);
        assert!(lex("$name").is_err());
        assert!(lex("``").is_err());
    }

    #[test]
    fn rejects_unterminated_string() {
        let err = lex("\"oops").unwrap_err();
        assert!(err.msg.contains("unterminated"));
    }
}
