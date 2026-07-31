//! Docker Compose reader — a *declared subset* of YAML (ADR-0012).
//!
//! `zion import traefik` needs three things out of a compose file, and only
//! three: the service names (a Traefik router's upstream host IS the compose
//! service name), each service's `labels`, and the `command` of the Traefik
//! service itself (its static entrypoint/ACME flags live there). Everything
//! else — networks, volumes, healthchecks, deploy blocks — is noise.
//!
//! So this is not a YAML parser and must never be mistaken for one. It is an
//! indentation-directed scan over the block-style subset compose files
//! actually use, and it **refuses** every construct it cannot honour rather
//! than guessing: anchors, aliases, merge keys, multi-document streams, tab
//! indentation. Refusing with a line number is the house contract (ADR-0011,
//! honesty over completeness) — a silently mis-parsed label would become a
//! silently wrong route, which is precisely the failure mode the import
//! report exists to prevent.
//!
//! Supported node shapes, exhaustively:
//!   - block mappings          `key: value` / `key:` + indented children
//!   - block sequences         `- item`
//!   - flow sequences of scalars  `key: [a, b, "c d"]`  (compose uses these
//!     for `command:` and for the `ports: []` / `labels: []` empty-override
//!     idiom, so they are not optional)
//!   - single/double-quoted and plain scalars, with YAML comment rules

use std::fmt;

// ── Model ───────────────────────────────────────────────────────────────

/// One `key=value` label, however it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub key: String,
    pub value: String,
    /// 1-based line of the label in the source.
    pub line: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Service {
    pub name: String,
    /// 1-based line of the service key.
    pub line: u32,
    pub image: Option<String>,
    /// `command:` normalized to a token list. A shell-form string stays a
    /// single element — splitting it would be a guess.
    pub command: Vec<String>,
    pub labels: Vec<Label>,
}

#[derive(Debug, Clone, Default)]
pub struct ComposeFile {
    pub services: Vec<Service>,
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

fn err<T>(line: u32, msg: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError {
        line,
        msg: msg.into(),
    })
}

// ── Line model ──────────────────────────────────────────────────────────

/// A significant source line: indentation depth, trimmed content, 1-based number.
#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
    no: u32,
}

/// Guard against pathological inputs: a compose file with more significant
/// lines than this is not a compose file.
const MAX_LINES: usize = 200_000;

/// Split into significant lines, rejecting what the subset cannot honour.
fn scan(src: &str) -> Result<Vec<Line>, ParseError> {
    let mut out = Vec::new();
    let mut seen_content = false;
    for (i, raw) in src.lines().enumerate() {
        let no = (i + 1) as u32;
        if out.len() >= MAX_LINES {
            return err(no, "input exceeds the compose line budget (200000)");
        }
        // Strip a trailing CR so CRLF files behave like LF ones.
        let raw = raw.strip_suffix('\r').unwrap_or(raw);

        let indent = raw.len() - raw.trim_start_matches([' ', '\t']).len();
        if raw[..indent].contains('\t') {
            return err(no, "tab indentation — YAML forbids tabs; use spaces");
        }
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if text == "---" || text == "..." {
            // A leading document start is idiomatic and harmless; a second
            // document means content we would silently drop.
            if seen_content {
                return err(
                    no,
                    "multi-document YAML stream — split the documents and \
                     import them one at a time",
                );
            }
            continue;
        }
        seen_content = true;
        if let Some(bad) = merge_key(text) {
            return err(no, bad);
        }
        out.push(Line {
            indent,
            text: text.to_string(),
            no,
        });
    }
    Ok(out)
}

/// Reject YAML merge keys (`<<: *base`) wherever they appear — the subset has
/// no inheritance, so honouring them would mean dropping the merged keys.
fn merge_key(text: &str) -> Option<&'static str> {
    let body = text.strip_prefix("- ").unwrap_or(text);
    if body.starts_with("<<:") || body.trim_end() == "<<" {
        return Some("YAML merge key (`<<`) — the compose subset has no inheritance");
    }
    None
}

/// Reject an anchor/alias at the point a node value starts. Checked only
/// here, never on whole lines: `&&` inside a Traefik rule is a legitimate
/// value, and a blanket scan for `&` would reject every real router rule.
fn reject_anchor(value: &str, line: u32) -> Result<(), ParseError> {
    let mut chars = value.chars();
    let sigil = match chars.next() {
        Some(c @ ('&' | '*')) => c,
        _ => return Ok(()),
    };
    // `&name` / `*name` — an anchor name is non-empty and alphanumeric-ish.
    // `&&`, `*`, `**` and friends are values, not anchors.
    let name: String = chars
        .clone()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if name.is_empty() {
        return Ok(());
    }
    let kind = if sigil == '&' { "anchor" } else { "alias" };
    err(
        line,
        format!(
            "YAML {kind} (`{sigil}{name}`) — the compose subset does not \
             resolve anchors; inline the value"
        ),
    )
}

// ── Tree walk ───────────────────────────────────────────────────────────

/// Slice of lines strictly more indented than `lines[i]`, i.e. its children.
fn children(lines: &[Line], i: usize) -> &[Line] {
    let base = lines[i].indent;
    let start = i + 1;
    let mut end = start;
    while end < lines.len() && lines[end].indent > base {
        end += 1;
    }
    &lines[start..end]
}

/// Index of the next sibling of `lines[i]` (i.e. skip its whole subtree).
fn next_sibling(lines: &[Line], i: usize) -> usize {
    i + 1 + children(lines, i).len()
}

/// Split `key: rest` on the first `:` that terminates a key. Quoted keys are
/// not used by compose for service names or labels, so a `:` inside a quoted
/// key is out of subset; a `:` inside the *value* is common (`image: a:1`)
/// and is preserved because only the first one splits.
fn split_key(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            let after = &text[i + 1..];
            // A key terminator is `:` at end of line or followed by space.
            if after.is_empty() || after.starts_with(' ') {
                return Some((text[..i].trim(), after.trim()));
            }
        }
        i += 1;
    }
    None
}

/// Parse a compose source into the subset model.
pub fn parse(src: &str) -> Result<ComposeFile, ParseError> {
    let lines = scan(src)?;
    let mut file = ComposeFile::default();

    // Top level: the shallowest indent present. Compose puts `services:` at
    // column 0, but tolerate a uniformly indented document.
    let top = match lines.first() {
        Some(l) => l.indent,
        None => return Ok(file),
    };
    let mut i = 0;
    while i < lines.len() {
        if lines[i].indent != top {
            // Only reachable on a malformed dedent; skip defensively rather
            // than mis-attributing the line to the wrong parent.
            i += 1;
            continue;
        }
        let (key, rest) = match split_key(&lines[i].text) {
            Some(kv) => kv,
            None => {
                i = next_sibling(&lines, i);
                continue;
            }
        };
        if key == "services" {
            if !rest.is_empty() {
                return err(lines[i].no, "`services:` must open a block mapping");
            }
            parse_services(children(&lines, i), &mut file)?;
        }
        i = next_sibling(&lines, i);
    }
    Ok(file)
}

fn parse_services(lines: &[Line], file: &mut ComposeFile) -> Result<(), ParseError> {
    if lines.is_empty() {
        return Ok(());
    }
    let level = lines[0].indent;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].indent != level {
            i += 1;
            continue;
        }
        let (name, rest) = match split_key(&lines[i].text) {
            Some(kv) => kv,
            None => {
                i = next_sibling(lines, i);
                continue;
            }
        };
        reject_anchor(rest, lines[i].no)?;
        let mut svc = Service {
            name: unquote(name, lines[i].no)?,
            line: lines[i].no,
            ..Service::default()
        };
        parse_service_body(children(lines, i), &mut svc)?;
        file.services.push(svc);
        i = next_sibling(lines, i);
    }
    Ok(())
}

fn parse_service_body(lines: &[Line], svc: &mut Service) -> Result<(), ParseError> {
    if lines.is_empty() {
        return Ok(());
    }
    let level = lines[0].indent;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].indent != level {
            i += 1;
            continue;
        }
        let (key, rest) = match split_key(&lines[i].text) {
            Some(kv) => kv,
            None => {
                i = next_sibling(lines, i);
                continue;
            }
        };
        let no = lines[i].no;
        match key {
            "image" => {
                reject_anchor(rest, no)?;
                if !rest.is_empty() {
                    svc.image = Some(unquote(rest, no)?);
                }
            }
            "command" | "entrypoint" => {
                // `entrypoint` matters for the same reason `command` does:
                // some stacks put the Traefik static flags there.
                svc.command = parse_string_list(lines, i, rest)?;
            }
            "labels" => {
                let items = parse_labels(lines, i, rest)?;
                svc.labels.extend(items);
            }
            _ => {}
        }
        i = next_sibling(lines, i);
    }
    Ok(())
}

/// A `key:` whose value is a scalar, a flow sequence, or a block sequence.
fn parse_string_list(lines: &[Line], i: usize, rest: &str) -> Result<Vec<String>, ParseError> {
    let no = lines[i].no;
    reject_anchor(rest, no)?;
    if !rest.is_empty() {
        return if rest.starts_with('[') {
            parse_flow_seq(rest, no)
        } else {
            // Shell form: one opaque token. Splitting on spaces would be a
            // guess about quoting we are not entitled to make.
            Ok(vec![unquote(rest, no)?])
        };
    }
    let kids = children(lines, i);
    let mut out = Vec::with_capacity(kids.len());
    for k in kids {
        let item = match k.text.strip_prefix("- ") {
            Some(v) => v.trim(),
            None if k.text == "-" => continue,
            // A block mapping under `command:` is out of subset; ignore
            // rather than fail — it cannot be a Traefik flag.
            None => continue,
        };
        reject_anchor(item, k.no)?;
        out.push(unquote(item, k.no)?);
    }
    Ok(out)
}

/// `labels:` in either form — a sequence of `k=v` strings, or a mapping.
fn parse_labels(lines: &[Line], i: usize, rest: &str) -> Result<Vec<Label>, ParseError> {
    let no = lines[i].no;
    reject_anchor(rest, no)?;
    if !rest.is_empty() {
        // `labels: []` — the empty-override idiom.
        let items = parse_flow_seq(rest, no)?;
        return Ok(items.into_iter().map(|s| split_label(&s, no)).collect());
    }
    let kids = children(lines, i);
    let mut out = Vec::with_capacity(kids.len());
    for k in kids {
        if let Some(item) = k.text.strip_prefix("- ") {
            let item = item.trim();
            reject_anchor(item, k.no)?;
            out.push(split_label(&unquote(item, k.no)?, k.no));
        } else if k.text == "-" {
            continue;
        } else if let Some((key, val)) = split_key(&k.text) {
            reject_anchor(val, k.no)?;
            out.push(Label {
                key: unquote(key, k.no)?,
                value: unquote(val, k.no)?,
                line: k.no,
            });
        }
    }
    Ok(out)
}

/// Split a `key=value` label. A label with no `=` keeps an empty value and is
/// left for the mapper to report — the reader does not judge label content.
fn split_label(s: &str, line: u32) -> Label {
    match s.split_once('=') {
        Some((k, v)) => Label {
            key: k.trim().to_string(),
            value: v.to_string(),
            line,
        },
        None => Label {
            key: s.trim().to_string(),
            value: String::new(),
            line,
        },
    }
}

/// `[a, b, "c, d"]` → the scalars, quote-aware.
fn parse_flow_seq(s: &str, line: u32) -> Result<Vec<String>, ParseError> {
    let body = match s.strip_prefix('[') {
        Some(b) => b,
        None => return err(line, "expected a flow sequence starting with `[`"),
    };
    let body = match body.rfind(']') {
        Some(p) => &body[..p],
        None => return err(line, "unterminated flow sequence — missing `]`"),
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' && q == '"' {
                    if let Some(n) = chars.next() {
                        cur.push(unescape(n));
                    }
                } else if c == q {
                    // `''` inside a single-quoted scalar is a literal quote.
                    if q == '\'' && chars.peek() == Some(&'\'') {
                        chars.next();
                        cur.push('\'');
                    } else {
                        quote = None;
                    }
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                ',' => {
                    out.push(cur.trim().to_string());
                    cur = String::new();
                }
                '[' | '{' => {
                    return err(line, "nested flow collections are out of subset");
                }
                _ => cur.push(c),
            },
        }
    }
    if quote.is_some() {
        return err(line, "unterminated quoted string in flow sequence");
    }
    let tail = cur.trim();
    if !tail.is_empty() || !out.is_empty() {
        // A trailing empty element only appears after a trailing comma, which
        // YAML permits and which carries no item.
        if !tail.is_empty() {
            out.push(tail.to_string());
        }
    }
    Ok(out)
}

/// Unquote a scalar and apply YAML's comment rule: on a plain (unquoted)
/// scalar, ` #` starts a comment; inside quotes it does not.
fn unquote(s: &str, line: u32) -> Result<String, ParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(String::new());
    }
    let bytes = s.as_bytes();
    let q = bytes[0];
    if q == b'"' || q == b'\'' {
        let quote = q as char;
        let mut out = String::with_capacity(s.len());
        let mut chars = s[1..].chars().peekable();
        let mut closed = false;
        while let Some(c) = chars.next() {
            if c == '\\' && quote == '"' {
                match chars.next() {
                    Some(n) => out.push(unescape(n)),
                    None => break,
                }
            } else if c == quote {
                if quote == '\'' && chars.peek() == Some(&'\'') {
                    chars.next();
                    out.push('\'');
                } else {
                    closed = true;
                    break;
                }
            } else {
                out.push(c);
            }
        }
        if !closed {
            return err(line, "unterminated quoted string");
        }
        return Ok(out);
    }
    // Plain scalar: strip a trailing comment introduced by whitespace + `#`.
    let cut = s
        .char_indices()
        .find(|(i, c)| *c == '#' && *i > 0 && s.as_bytes()[i - 1].is_ascii_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    Ok(s[..cut].trim().to_string())
}

fn unescape(c: char) -> char {
    match c {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '0' => '\0',
        other => other,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn svc<'a>(f: &'a ComposeFile, name: &str) -> &'a Service {
        f.services
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no service {name}"))
    }

    #[test]
    fn labels_in_list_form() {
        // cheap-api / rainlogs shape: quoted list items.
        let src = "\
services:
  api:
    build: .
    labels:
      - \"traefik.enable=true\"
      - \"traefik.http.routers.api.rule=Host(`api.example.com`)\"
      - \"traefik.http.services.api.loadbalancer.server.port=8000\"
";
        let f = parse(src).expect("parse");
        let api = svc(&f, "api");
        assert_eq!(api.labels.len(), 3);
        assert_eq!(api.labels[0].key, "traefik.enable");
        assert_eq!(api.labels[0].value, "true");
        assert_eq!(
            api.labels[1].value, "Host(`api.example.com`)",
            "backticks must survive"
        );
        assert_eq!(api.labels[1].line, 6);
    }

    #[test]
    fn labels_unquoted_list_form() {
        // certmate-ng shape: bare list items, no quotes.
        let src = "\
services:
  frontend:
    labels:
      - traefik.enable=true
      - traefik.http.routers.fe.rule=Host(`${PUBLIC_FQDN}`)
";
        let f = parse(src).expect("parse");
        let fe = svc(&f, "frontend");
        assert_eq!(fe.labels[1].value, "Host(`${PUBLIC_FQDN}`)");
    }

    #[test]
    fn labels_in_map_form() {
        let src = "\
services:
  api:
    labels:
      traefik.enable: \"true\"
      traefik.http.routers.api.rule: Host(`a.test`)
";
        let f = parse(src).expect("parse");
        let api = svc(&f, "api");
        assert_eq!(api.labels.len(), 2);
        assert_eq!(api.labels[0].key, "traefik.enable");
        assert_eq!(api.labels[0].value, "true");
        assert_eq!(api.labels[1].value, "Host(`a.test`)");
    }

    #[test]
    fn double_ampersand_in_a_rule_is_a_value_not_an_anchor() {
        // The regression that a naive anchor scan would cause: every real
        // Traefik rule combining matchers would be rejected.
        let src = "\
services:
  api:
    labels:
      - traefik.http.routers.api.rule=Host(`a.test`) && PathPrefix(`/api`)
";
        let f = parse(src).expect("parse");
        assert_eq!(
            svc(&f, "api").labels[0].value,
            "Host(`a.test`) && PathPrefix(`/api`)"
        );
    }

    #[test]
    fn command_block_sequence() {
        let src = "\
services:
  traefik:
    image: traefik:v3.3
    command:
      - \"--providers.docker=true\"
      - \"--entrypoints.web.address=:80\"
";
        let f = parse(src).expect("parse");
        let t = svc(&f, "traefik");
        assert_eq!(t.image.as_deref(), Some("traefik:v3.3"));
        assert_eq!(t.command.len(), 2);
        assert_eq!(t.command[1], "--entrypoints.web.address=:80");
    }

    #[test]
    fn command_flow_sequence() {
        // certmate-ng disables nginx with an inline flow sequence.
        let src = "\
services:
  nginx:
    command: [\"sh\", \"-c\", \"echo nginx disabled, sleep infinity\"]
    ports: []
";
        let f = parse(src).expect("parse");
        let n = svc(&f, "nginx");
        assert_eq!(n.command.len(), 3);
        assert_eq!(n.command[2], "echo nginx disabled, sleep infinity");
    }

    #[test]
    fn image_with_a_tag_or_digest_keeps_its_colons() {
        let src = "\
services:
  t:
    image: traefik:v3@sha256:6b9cbca6fac42ab0075f5437d8dc1685cfd188626d8d515839ea94f8b6271c42
";
        let f = parse(src).expect("parse");
        assert!(svc(&f, "t").image.as_deref().unwrap().contains("@sha256:"));
    }

    #[test]
    fn nested_blocks_do_not_leak_into_the_parent_service() {
        // `deploy.resources.limits` and healthchecks must not be read as
        // service keys, and must not swallow the following service.
        let src = "\
services:
  a:
    image: a:1
    deploy:
      resources:
        limits:
          memory: 128M
    labels:
      - x=1
  b:
    image: b:1
    labels:
      - y=2
";
        let f = parse(src).expect("parse");
        assert_eq!(f.services.len(), 2);
        assert_eq!(svc(&f, "a").labels.len(), 1);
        assert_eq!(svc(&f, "b").labels[0].key, "y");
        assert_eq!(svc(&f, "b").image.as_deref(), Some("b:1"));
    }

    #[test]
    fn top_level_keys_other_than_services_are_ignored() {
        let src = "\
version: \"3.8\"
networks:
  frontend:
    driver: bridge
services:
  a:
    labels:
      - x=1
volumes:
  data:
";
        let f = parse(src).expect("parse");
        assert_eq!(f.services.len(), 1);
        assert_eq!(svc(&f, "a").labels[0].key, "x");
    }

    #[test]
    fn comments_are_stripped_outside_quotes_only() {
        let src = "\
services:
  a:
    # a full-line comment
    image: nginx:alpine  # trailing comment
    labels:
      - \"traefik.http.routers.a.rule=Host(`a.test`) # not a comment\"
";
        let f = parse(src).expect("parse");
        assert_eq!(svc(&f, "a").image.as_deref(), Some("nginx:alpine"));
        assert!(svc(&f, "a").labels[0].value.contains("# not a comment"));
    }

    #[test]
    fn label_without_equals_keeps_an_empty_value() {
        let src = "services:\n  a:\n    labels:\n      - traefik.enable\n";
        let f = parse(src).expect("parse");
        assert_eq!(svc(&f, "a").labels[0].key, "traefik.enable");
        assert_eq!(svc(&f, "a").labels[0].value, "");
    }

    #[test]
    fn crlf_input() {
        let src = "services:\r\n  a:\r\n    labels:\r\n      - x=1\r\n";
        let f = parse(src).expect("parse");
        assert_eq!(svc(&f, "a").labels[0].value, "1");
    }

    #[test]
    fn empty_and_serviceless_files() {
        assert_eq!(parse("").expect("parse").services.len(), 0);
        assert_eq!(parse("version: \"3\"\n").expect("parse").services.len(), 0);
    }

    // ── Refusals: each one would otherwise become a silently wrong route ──

    #[test]
    fn rejects_anchors_and_aliases() {
        let anchor = "services:\n  a: &base\n    image: x\n  b: *base\n";
        let e = parse(anchor).expect_err("must fail");
        assert!(e.msg.contains("anchor"), "{e}");
        assert_eq!(e.line, 2);

        let alias = "services:\n  a:\n    image: *ref\n";
        let e = parse(alias).expect_err("must fail");
        assert!(e.msg.contains("alias"), "{e}");
    }

    #[test]
    fn rejects_merge_keys() {
        let src = "services:\n  a:\n    <<: *base\n    image: x\n";
        let e = parse(src).expect_err("must fail");
        assert!(e.msg.contains("merge key"), "{e}");
        assert_eq!(e.line, 3);
    }

    #[test]
    fn rejects_tab_indentation() {
        let src = "services:\n\ta:\n\t\timage: x\n";
        let e = parse(src).expect_err("must fail");
        assert!(e.msg.contains("tab"), "{e}");
        assert_eq!(e.line, 2);
    }

    #[test]
    fn rejects_multi_document_streams() {
        let src = "services:\n  a:\n    image: x\n---\nservices:\n  b:\n    image: y\n";
        let e = parse(src).expect_err("must fail");
        assert!(e.msg.contains("multi-document"), "{e}");
    }

    #[test]
    fn leading_document_marker_is_fine() {
        let src = "---\nservices:\n  a:\n    labels:\n      - x=1\n";
        assert_eq!(parse(src).expect("parse").services.len(), 1);
    }

    #[test]
    fn rejects_unterminated_quotes() {
        let src = "services:\n  a:\n    image: \"nginx\n";
        let e = parse(src).expect_err("must fail");
        assert!(e.msg.contains("unterminated"), "{e}");
    }

    #[test]
    fn rejects_nested_flow_collections() {
        let src = "services:\n  a:\n    command: [\"sh\", [\"-c\"]]\n";
        assert!(parse(src).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The reader must never panic — arbitrary input may fail with a
        /// ParseError, never crash (ADR-0011 tolerance contract).
        #[test]
        fn reader_never_panics(src in "\\PC*") {
            let _ = parse(&src);
        }

        /// Bias toward YAML structural characters to stress the indentation,
        /// quoting and flow-sequence paths harder than uniform text would.
        #[test]
        fn reader_never_panics_structural(src in "[ \n:#'\"\\\\&*<>\\-\\[\\],a1]{0,96}") {
            let _ = parse(&src);
        }

        /// A well-formed list-form label always round-trips key and value.
        #[test]
        fn label_roundtrip(
            key in "[a-z][a-z0-9.]{0,24}",
            value in "[a-zA-Z0-9_./:`() -]{0,32}",
        ) {
            let src = format!("services:\n  s:\n    labels:\n      - \"{key}={value}\"\n");
            let f = parse(&src).expect("well-formed compose must parse");
            let s = f.services.iter().find(|x| x.name == "s").expect("service s");
            prop_assert_eq!(s.labels.len(), 1);
            prop_assert_eq!(&s.labels[0].key, &key);
            prop_assert_eq!(&s.labels[0].value, &value);
        }
    }
}
