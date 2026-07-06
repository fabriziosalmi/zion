//! Tolerant nginx configuration parser (ADR-0011).
//!
//! Lexer semantics are modeled on nginx's `ngx_conf_read_token` as specified
//! by nginxinc/crossplane: whitespace-separated words, `;` terminator, `{`/`}`
//! block delimiters, single/double-quoted strings with backslash escapes, `#`
//! comments only where a new token may start, `$var` passed through untouched.
//! There is deliberately no directive whitelist — the parser accepts any
//! directive name; deciding what Zion supports is the mapper's job, so the
//! parser never has to reject a real-world config for using a module we've
//! never heard of.
//!
//! `*_by_lua_block { … }` bodies are skipped with a raw balanced-brace scan
//! that is aware of Lua quotes and `--` line comments (Lua long-bracket
//! strings are not handled; the block is unsupported downstream either way).

use std::fmt;

/// One parsed directive: `name arg1 arg2;` or `name args { children }`.
#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    /// `Some` when the directive opened a `{ … }` block (possibly empty).
    pub block: Option<Vec<Directive>>,
    /// 1-based line of the directive name in its source.
    pub line: u32,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: u32,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

fn err(line: u32, msg: impl Into<String>) -> ParseError {
    ParseError {
        line,
        msg: msg.into(),
    }
}

/// Parse an nginx config source into a directive tree. `include` directives
/// are returned as plain directives — resolution against the filesystem is
/// the caller's concern (see `resolve_includes` in the import driver).
pub fn parse(src: &str) -> Result<Vec<Directive>, ParseError> {
    let mut lx = Lexer::new(src);
    let items = parse_block(&mut lx, 0)?;
    Ok(items)
}

// ── Tokens ──────────────────────────────────────────────────────────────

enum Tok {
    Word(String),
    Open,
    Close,
    Semi,
    Eof,
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: u32,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            chars: src.chars().peekable(),
            line: 1,
        }
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next();
        if c == Some('\n') {
            self.line += 1;
        }
        c
    }

    /// Skip whitespace and comments. A `#` starts a comment only here — i.e.
    /// only where a new token may start — matching nginx: `foo#bar` is one word.
    fn skip_trivia(&mut self) {
        loop {
            match self.chars.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('#') => {
                    while let Some(c) = self.bump() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    /// Next token. Returns the token and the line it started on.
    fn next_tok(&mut self) -> Result<(Tok, u32), ParseError> {
        self.skip_trivia();
        let line = self.line;
        let c = match self.chars.peek() {
            None => return Ok((Tok::Eof, line)),
            Some(c) => *c,
        };
        match c {
            '{' => {
                self.bump();
                Ok((Tok::Open, line))
            }
            '}' => {
                self.bump();
                Ok((Tok::Close, line))
            }
            ';' => {
                self.bump();
                Ok((Tok::Semi, line))
            }
            '\'' | '"' => {
                self.bump();
                let word = self.quoted_word(c, line)?;
                Ok((Tok::Word(word), line))
            }
            _ => {
                let word = self.bare_word();
                Ok((Tok::Word(word), line))
            }
        }
    }

    /// Quoted string: `\` escapes the quote character and itself; any other
    /// `\x` sequence is preserved verbatim (nginx does not process escapes
    /// beyond un-quoting — `$` interpolation is per-directive runtime behavior).
    fn quoted_word(&mut self, quote: char, start_line: u32) -> Result<String, ParseError> {
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(err(start_line, "unterminated quoted string")),
                Some('\\') => match self.bump() {
                    None => return Err(err(start_line, "unterminated quoted string")),
                    Some(c) if c == quote || c == '\\' => out.push(c),
                    Some(c) => {
                        out.push('\\');
                        out.push(c);
                    }
                },
                Some(c) if c == quote => return Ok(out),
                Some(c) => out.push(c),
            }
        }
    }

    /// Unquoted word: runs until whitespace or a structural character.
    /// `#` does NOT terminate a word (comments start only at token starts);
    /// `\x` keeps both characters, matching crossplane's lexer. A `${…}`
    /// variable expansion is part of the word — nginx's lexer treats the
    /// brace-form variable as word content, not as a block delimiter
    /// (`return 301 https://example.com${request_uri};` is one arg).
    fn bare_word(&mut self) -> String {
        let mut out = String::new();
        loop {
            match self.chars.peek() {
                None => return out,
                Some(c) if c.is_whitespace() => return out,
                Some('{') | Some('}') | Some(';') => return out,
                Some('\\') => {
                    self.bump();
                    out.push('\\');
                    if let Some(c) = self.bump() {
                        out.push(c);
                    }
                }
                Some('$') => {
                    self.bump();
                    out.push('$');
                    if self.chars.peek() == Some(&'{') {
                        // Consume the brace-form variable through its `}`.
                        while let Some(c) = self.bump() {
                            out.push(c);
                            if c == '}' {
                                break;
                            }
                        }
                    }
                }
                Some(_) => {
                    // Unwrap is safe: peek() just returned Some.
                    out.push(self.bump().unwrap());
                }
            }
        }
    }

    /// Raw scan for `*_by_lua_block { … }` bodies: the opening `{` has been
    /// consumed; consume up to and including the balanced closing `}`.
    /// Lua single/double-quoted strings and `--` line comments are skipped so
    /// braces inside them don't unbalance the scan. Lua long-bracket strings
    /// (`[[…]]`) are not handled — documented limitation; the block is
    /// reported unsupported by the mapper regardless.
    fn skip_lua_block(&mut self, start_line: u32) -> Result<(), ParseError> {
        let mut depth: u32 = 1;
        while depth > 0 {
            match self.bump() {
                None => return Err(err(start_line, "unterminated *_by_lua_block (missing `}`)")),
                Some('{') => depth += 1,
                Some('}') => depth -= 1,
                Some(q @ '\'') | Some(q @ '"') => loop {
                    match self.bump() {
                        None => return Err(err(start_line, "unterminated string in lua block")),
                        Some('\\') => {
                            self.bump();
                        }
                        Some(c) if c == q => break,
                        Some(_) => {}
                    }
                },
                Some('-') => {
                    // `--` starts a Lua line comment (outside strings).
                    if self.chars.peek() == Some(&'-') {
                        while let Some(c) = self.bump() {
                            if c == '\n' {
                                break;
                            }
                        }
                    }
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

// ── Parser ──────────────────────────────────────────────────────────────

fn parse_block(lx: &mut Lexer<'_>, depth: u32) -> Result<Vec<Directive>, ParseError> {
    // A directive tree deeper than this is not a real nginx config.
    const MAX_DEPTH: u32 = 64;
    if depth > MAX_DEPTH {
        return Err(err(lx.line, "blocks nested too deeply"));
    }

    let mut items = Vec::new();
    loop {
        let (tok, line) = lx.next_tok()?;
        let name = match tok {
            Tok::Eof => {
                if depth > 0 {
                    return Err(err(line, "unexpected end of file, expecting `}`"));
                }
                return Ok(items);
            }
            Tok::Close => {
                if depth == 0 {
                    return Err(err(line, "unexpected `}`"));
                }
                return Ok(items);
            }
            Tok::Semi => return Err(err(line, "unexpected `;`")),
            Tok::Open => return Err(err(line, "unexpected `{`")),
            Tok::Word(w) => w,
        };

        // Collect args until `;` (simple directive) or `{` (block).
        let mut args = Vec::new();
        loop {
            let (tok, tline) = lx.next_tok()?;
            match tok {
                Tok::Word(w) => args.push(w),
                Tok::Semi => {
                    items.push(Directive {
                        name,
                        args,
                        block: None,
                        line,
                    });
                    break;
                }
                Tok::Open => {
                    let block = if name.ends_with("_by_lua_block") {
                        lx.skip_lua_block(tline)?;
                        Vec::new()
                    } else {
                        parse_block(lx, depth + 1)?
                    };
                    items.push(Directive {
                        name,
                        args,
                        block: Some(block),
                        line,
                    });
                    break;
                }
                Tok::Close => {
                    return Err(err(
                        tline,
                        format!("unexpected `}}` in directive \"{name}\" (missing `;`?)"),
                    ))
                }
                Tok::Eof => {
                    return Err(err(
                        tline,
                        format!("unexpected end of file in directive \"{name}\" (missing `;`?)"),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> Directive {
        let mut v = parse(src).expect("parse");
        assert_eq!(v.len(), 1, "expected exactly one directive");
        v.remove(0)
    }

    #[test]
    fn simple_directive() {
        let d = one("proxy_pass http://127.0.0.1:8080;");
        assert_eq!(d.name, "proxy_pass");
        assert_eq!(d.args, vec!["http://127.0.0.1:8080"]);
        assert!(d.block.is_none());
        assert_eq!(d.line, 1);
    }

    #[test]
    fn block_directive_and_nesting() {
        let d = one("server {\n  listen 80;\n  location / {\n    proxy_pass http://b;\n  }\n}");
        assert_eq!(d.name, "server");
        let kids = d.block.expect("block");
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].name, "listen");
        assert_eq!(kids[1].name, "location");
        assert_eq!(kids[1].args, vec!["/"]);
        assert_eq!(kids[1].line, 3);
        let inner = kids[1].block.as_ref().expect("location block");
        assert_eq!(inner[0].name, "proxy_pass");
    }

    #[test]
    fn brace_adjacent_to_word() {
        // nginx accepts `server{` — `{` terminates the bare word.
        let d = one("server{listen 80;}");
        assert_eq!(d.name, "server");
        assert_eq!(d.block.expect("block")[0].args, vec!["80"]);
    }

    #[test]
    fn comments_only_at_token_start() {
        let v = parse("# full line\nroot /var/www#notcomment; # trailing\n").expect("parse");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].args, vec!["/var/www#notcomment"]);
    }

    #[test]
    fn quoted_strings_with_escapes() {
        let d = one(r#"log_format main '$remote_addr "quoted \' arg"';"#);
        assert_eq!(d.args, vec!["main", r#"$remote_addr "quoted ' arg""#]);
        // Non-quote escapes are preserved verbatim.
        let d = one(r#"location ~ "^/user/(\d{4,8})$" { }"#);
        assert_eq!(d.args, vec!["~", r"^/user/(\d{4,8})$"]);
        assert!(d.block.is_some());
    }

    #[test]
    fn dollar_vars_pass_through() {
        let d = one("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
        assert_eq!(d.args[1], "$proxy_add_x_forwarded_for");
    }

    #[test]
    fn brace_form_variables_stay_in_the_word() {
        // nginx lexes `${name}` as word content, not a block open (a common
        // idiom in redirects and proxy_pass targets).
        let d = one("return 301 https://example.com${request_uri};");
        assert_eq!(d.args, vec!["301", "https://example.com${request_uri}"]);
        let d = one("set $x a${b}c;");
        assert_eq!(d.args, vec!["$x", "a${b}c"]);
        let d = one("proxy_pass http://backend${suffix};");
        assert_eq!(d.args, vec!["http://backend${suffix}"]);
        // Unterminated `${` must not panic; the parse simply errors.
        assert!(parse("x a${b;").is_err());
    }

    #[test]
    fn empty_block() {
        let d = one("events { }");
        assert_eq!(d.block.expect("block").len(), 0);
    }

    #[test]
    fn unknown_directives_are_fine() {
        // Tolerance is the point: third-party module directives must parse.
        let v = parse("more_set_headers 'X-Custom: 1';\nbrotli on;\n").expect("parse");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "more_set_headers");
        assert_eq!(v[1].name, "brotli");
    }

    #[test]
    fn lua_block_with_braces_in_strings() {
        let src =
            "content_by_lua_block { local s = \"}\" -- also a } here\n ngx.say('{') } listen 80;";
        let v = parse(src).expect("parse");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "content_by_lua_block");
        assert_eq!(v[0].block.as_ref().expect("raw block").len(), 0);
        assert_eq!(v[1].name, "listen");
    }

    #[test]
    fn error_unterminated_quote() {
        let e = parse("server_name \"unterminated;").expect_err("must fail");
        assert!(e.msg.contains("unterminated"), "{e}");
    }

    #[test]
    fn error_unbalanced_braces() {
        assert!(parse("server { listen 80;").is_err());
        assert!(parse("}").is_err());
        let e = parse("server { listen 80; } }").expect_err("must fail");
        assert!(e.msg.contains("unexpected `}`"), "{e}");
    }

    #[test]
    fn error_missing_semicolon() {
        let e = parse("server { listen 80 }").expect_err("must fail");
        assert!(e.msg.contains("missing `;`"), "{e}");
    }

    #[test]
    fn error_stray_semicolon() {
        assert!(parse(";").is_err());
    }

    #[test]
    fn line_numbers_track_newlines() {
        let v = parse("\n\nlisten 80;\nserver_name a;\n").expect("parse");
        assert_eq!(v[0].line, 3);
        assert_eq!(v[1].line, 4);
    }

    #[test]
    fn crlf_input() {
        let v = parse("listen 80;\r\nserver_name a.example.com;\r\n").expect("parse");
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].line, 2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The parser must never panic — arbitrary input may fail with a
        /// ParseError, never crash (ADR-0011 tolerance contract).
        #[test]
        fn parser_never_panics(src in "\\PC*") {
            let _ = parse(&src);
        }

        /// Bias the generator toward structural characters to stress
        /// nesting/quoting paths harder than uniform strings would.
        #[test]
        fn parser_never_panics_structural(src in "[{};#'\"\\\\a b\n$*_]{0,64}") {
            let _ = parse(&src);
        }

        /// A well-formed simple directive always round-trips its args.
        #[test]
        fn simple_directive_roundtrip(
            name in "[a-z_]{1,12}",
            args in proptest::collection::vec("[a-zA-Z0-9_./:$-]{1,8}", 0..4),
        ) {
            let src = format!("{} {};", name, args.join(" "));
            let v = parse(&src).expect("well-formed directive must parse");
            prop_assert_eq!(v.len(), 1);
            prop_assert_eq!(&v[0].name, &name);
            prop_assert_eq!(&v[0].args, &args);
        }
    }
}
