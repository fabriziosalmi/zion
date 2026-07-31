//! Caddyfile → `ZionDoc` (ADR-0013, third front-end of `zion import`).
//!
//! Third front-end on the neutral seam established by ADR-0011/0012: this
//! module owns a tolerant Caddyfile reader and a mapper that builds the *same*
//! `ZionDoc` the nginx and Traefik paths emit; rendering, self-validation and
//! reporting are unchanged.
//!
//! Unlike the Traefik front-end (which reads container labels via the compose
//! reader), a Caddyfile has its own grammar, so this file carries a hand-rolled
//! lexer + structural parser in the `nginx.rs` tradition: std-only, tolerant
//! (no directive whitelist — deciding what Zion supports is the mapper's job),
//! line-preserving, and `ParseError { line, msg }` on genuinely malformed input.
//!
//! ## The tokenizer's one subtlety
//!
//! `{` is a block opener OR the start of a placeholder token (`{$DOMAIN}`,
//! `{$DOMAIN:localhost}`, `{http.request.host}`). A naive brace scan would read
//! a site address of `{$DOMAIN:localhost}` as "open an empty block". We
//! disambiguate at the point a token starts: a `{` immediately followed by a
//! non-blank is a placeholder word read to its matching `}`; a `{` followed by
//! whitespace / newline / `}` / EOF is a block opener.
//!
//! ## Honesty over completeness (ADR-0011)
//!
//! The interesting result, verified against real Caddyfiles, is that the
//! `header` block almost evaporates: Zion already injects the same security
//! headers, so they land in `auto`. `root`/`file_server` (Zion serves nothing
//! from disk), `handle_path` (no path rewriting) and `respond` (no static
//! responses) are the product edge and map to `unsupported`. `tls`/ACME follows
//! the Traefik front-end: a placeholder cert + a `partial` finding, with native
//! `[tls.acme]` emission deferred.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use super::map::{AcmeOut, RouteOut, UpstreamOut, ZionDoc};
use super::{emit, Conversion, ConvertError, Finding, Status};

/// Placeholder cert paths (mirrors the nginx/Traefik convention): schema
/// validation does not require the files to exist, so a TLS route validates
/// and `:443` binds; the operator supplies the real cert (or `[tls.acme]`).
const PLACEHOLDER_CERT: &str = "/etc/ssl/zion/zion.crt";
const PLACEHOLDER_KEY: &str = "/etc/ssl/zion/zion.key";

/// Convert a Caddyfile into a validated zion.toml. `base_dir` locates the
/// adjacent `.env`; `cli_vars` are `--var KEY=VALUE` overrides (for `{$VAR}`).
pub(super) fn convert(
    src: &str,
    base_dir: Option<&Path>,
    cli_vars: &[(String, String)],
    cli_acme_email: Option<&str>,
) -> Result<Conversion, ConvertError> {
    let file = parse(src).map_err(|e| ConvertError::Parse(e.to_string()))?;
    let env = Env::load(base_dir, cli_vars);

    let mut findings = Vec::new();
    let doc = build(&file, &env, cli_acme_email, &mut findings);
    findings.sort_by_key(|f| f.line);

    if doc.routes.is_empty() {
        return Err(ConvertError::NoRoutes(findings));
    }

    let toml = emit::render(&doc, "caddy");
    emit::self_validate(&toml).map_err(|e| {
        ConvertError::Internal(format!(
            "emitted config failed self-validation — this is an importer bug, \
             please report it: {e}"
        ))
    })?;
    Ok(Conversion { toml, findings })
}

// ── Parse tree ────────────────────────────────────────────────────────────

/// One Caddyfile directive: `name args… { block }`. `block` is `Some` (even if
/// empty) when the directive opened a `{ … }`.
#[derive(Debug, Clone)]
struct Node {
    name: String,
    args: Vec<String>,
    block: Option<Vec<Node>>,
    line: u32,
}

#[derive(Debug, Default)]
struct Caddyfile {
    /// Global options block (leading `{ … }`), if any.
    global: Vec<Node>,
    /// Snippet definitions `(name) { … }`, resolved by `import name`.
    snippets: BTreeMap<String, Vec<Node>>,
    sites: Vec<Site>,
}

#[derive(Debug)]
struct Site {
    addresses: Vec<String>,
    body: Vec<Node>,
    line: u32,
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

fn perr(line: u32, msg: impl Into<String>) -> ParseError {
    ParseError {
        line,
        msg: msg.into(),
    }
}

// ── Lexer ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Tok {
    Word(String),
    Open,
    Close,
    Eof,
}

#[derive(PartialEq)]
enum Kind {
    Word,
    Open,
    Close,
    Eof,
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: u32,
    pending: Option<(Tok, u32)>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            chars: src.chars().peekable(),
            line: 1,
            pending: None,
        }
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next();
        if c == Some('\n') {
            self.line += 1;
        }
        c
    }

    /// Whitespace and `#` comments (a comment only starts where a token may).
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

    fn fill(&mut self) -> Result<(), ParseError> {
        if self.pending.is_none() {
            self.pending = Some(self.lex_one()?);
        }
        Ok(())
    }

    fn peek_kind(&mut self) -> Result<(Kind, u32), ParseError> {
        self.fill()?;
        let (tok, line) = self.pending.as_ref().unwrap();
        let kind = match tok {
            Tok::Word(_) => Kind::Word,
            Tok::Open => Kind::Open,
            Tok::Close => Kind::Close,
            Tok::Eof => Kind::Eof,
        };
        Ok((kind, *line))
    }

    fn next_tok(&mut self) -> Result<(Tok, u32), ParseError> {
        self.fill()?;
        Ok(self.pending.take().unwrap())
    }

    fn lex_one(&mut self) -> Result<(Tok, u32), ParseError> {
        self.skip_trivia();
        let line = self.line;
        let c = match self.chars.peek() {
            None => return Ok((Tok::Eof, line)),
            Some(c) => *c,
        };
        match c {
            '}' => {
                self.bump();
                Ok((Tok::Close, line))
            }
            '{' => {
                self.bump();
                // Placeholder token vs block opener: a `{` immediately followed
                // by a non-blank (`$`, a letter, …) is `{…}` read to its `}`.
                match self.chars.peek() {
                    Some(ch) if !ch.is_whitespace() && *ch != '}' => {
                        let mut s = String::from("{");
                        loop {
                            match self.bump() {
                                Some('}') => {
                                    s.push('}');
                                    break;
                                }
                                Some(ch) => s.push(ch),
                                None => return Err(perr(line, "unterminated `{…}` placeholder")),
                            }
                        }
                        Ok((Tok::Word(s), line))
                    }
                    _ => Ok((Tok::Open, line)),
                }
            }
            '"' => self.read_quoted('"', line),
            '`' => self.read_quoted('`', line),
            _ => Ok((Tok::Word(self.read_bare()), line)),
        }
    }

    /// Quoted (`"`) or raw (`` ` ``) string. `"` honors `\"` / `\\`; the raw
    /// form is verbatim to the closing backtick.
    fn read_quoted(&mut self, quote: char, line: u32) -> Result<(Tok, u32), ParseError> {
        self.bump(); // opening quote
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err(perr(line, "unterminated quoted string")),
                Some(c) if c == quote => break,
                Some('\\') if quote == '"' => match self.bump() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some(other) => {
                        s.push('\\');
                        s.push(other);
                    }
                    None => return Err(perr(line, "unterminated escape in quoted string")),
                },
                Some(c) => s.push(c),
            }
        }
        Ok((Tok::Word(s), line))
    }

    /// A bare word: runs to whitespace or a structural `{` / `}`. An embedded
    /// `{$…}` placeholder at word start is handled in `lex_one`; mid-word braces
    /// terminate the word (rare in practice).
    fn read_bare(&mut self) -> String {
        let mut s = String::new();
        while let Some(&c) = self.chars.peek() {
            if c.is_whitespace() || c == '{' || c == '}' || c == '"' || c == '`' {
                break;
            }
            s.push(c);
            self.bump();
        }
        s
    }
}

// ── Parser ────────────────────────────────────────────────────────────────

fn parse(src: &str) -> Result<Caddyfile, ParseError> {
    let mut lx = Lexer::new(src);
    let mut file = Caddyfile::default();

    // A leading `{` (before any site) is the global options block.
    if let (Kind::Open, _) = lx.peek_kind()? {
        lx.next_tok()?;
        file.global = parse_block(&mut lx, 0)?;
    }

    loop {
        match lx.peek_kind()? {
            (Kind::Eof, _) => break,
            (Kind::Close, line) => return Err(perr(line, "unexpected `}`")),
            (Kind::Open, line) => {
                return Err(perr(
                    line,
                    "unexpected `{` (global options must be the first block)",
                ))
            }
            (Kind::Word, head_line) => {
                // Address / snippet-name tokens run until the opening `{`.
                let mut heads = Vec::new();
                while let (Kind::Word, _) = lx.peek_kind()? {
                    if let (Tok::Word(w), _) = lx.next_tok()? {
                        heads.push(w);
                    }
                }
                match lx.peek_kind()? {
                    (Kind::Open, _) => {
                        lx.next_tok()?;
                        let body = parse_block(&mut lx, 0)?;
                        if heads.len() == 1
                            && heads[0].starts_with('(')
                            && heads[0].ends_with(')')
                            && heads[0].len() >= 2
                        {
                            let name = heads[0][1..heads[0].len() - 1].to_string();
                            file.snippets.insert(name, body);
                        } else {
                            let addresses = heads
                                .iter()
                                .flat_map(|h| h.split(','))
                                .map(|a| a.trim().to_string())
                                .filter(|a| !a.is_empty())
                                .collect();
                            file.sites.push(Site {
                                addresses,
                                body,
                                line: head_line,
                            });
                        }
                    }
                    (_, line) => {
                        return Err(perr(
                            line,
                            "expected `{` to open a site block after the address",
                        ))
                    }
                }
            }
        }
    }
    Ok(file)
}

/// Parse directives until the matching `}` (which it consumes). `depth` bounds
/// block nesting so a pathological `a {`×N input errors with a line number
/// instead of overflowing the stack.
fn parse_block(lx: &mut Lexer, depth: u32) -> Result<Vec<Node>, ParseError> {
    const MAX_NEST_DEPTH: u32 = 64;
    if depth > MAX_NEST_DEPTH {
        return Err(perr(lx.peek_kind()?.1, "blocks nested too deeply"));
    }
    let mut nodes = Vec::new();
    loop {
        match lx.peek_kind()? {
            (Kind::Close, _) => {
                lx.next_tok()?;
                break;
            }
            (Kind::Eof, line) => return Err(perr(line, "unexpected end of input — unclosed `{`")),
            (Kind::Open, line) => return Err(perr(line, "unexpected `{` with no directive")),
            (Kind::Word, line) => {
                let name = match lx.next_tok()? {
                    (Tok::Word(w), _) => w,
                    _ => unreachable!(),
                };
                // Arguments are the tokens on the directive's own line.
                let mut args = Vec::new();
                loop {
                    match lx.peek_kind()? {
                        (Kind::Word, l) if l == line => {
                            if let (Tok::Word(w), _) = lx.next_tok()? {
                                args.push(w);
                            }
                        }
                        _ => break,
                    }
                }
                // An immediately-following `{` opens this directive's block.
                let block = match lx.peek_kind()? {
                    (Kind::Open, _) => {
                        lx.next_tok()?;
                        Some(parse_block(lx, depth + 1)?)
                    }
                    _ => None,
                };
                nodes.push(Node {
                    name,
                    args,
                    block,
                    line,
                });
            }
        }
    }
    Ok(nodes)
}

// ── Environment placeholders (`{$VAR}` / `{$VAR:default}`) ─────────────────

struct Env {
    map: BTreeMap<String, String>,
}

impl Env {
    fn load(base_dir: Option<&Path>, cli_vars: &[(String, String)]) -> Self {
        let mut map = BTreeMap::new();
        if let Some(dir) = base_dir {
            if let Ok(content) = std::fs::read_to_string(dir.join(".env")) {
                for raw in content.lines() {
                    let line = raw.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let line = line.strip_prefix("export ").unwrap_or(line);
                    if let Some((k, v)) = line.split_once('=') {
                        map.insert(k.trim().to_string(), unquote(v.trim()).to_string());
                    }
                }
            }
        }
        for (k, v) in cli_vars {
            map.insert(k.clone(), v.clone());
        }
        Env { map }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.map
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// Expand every `{$VAR}` / `{$VAR:default}` in `raw`. Non-env placeholders
/// (`{http.request.host}`) are left literal. An unresolved required `{$VAR}`
/// becomes a named `unsupported` finding and returns `None`.
fn resolve(
    raw: &str,
    env: &Env,
    line: u32,
    ctx: &str,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    let mut ok = true;
    while let Some(pos) = rest.find("{$") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        match after.find('}') {
            Some(end) => {
                let inner = &after[..end];
                let (name, default) = match inner.split_once(':') {
                    Some((n, d)) => (n, Some(d)),
                    None => (inner, None),
                };
                match env.get(name) {
                    Some(v) => out.push_str(v),
                    None => {
                        match default {
                            Some(d) => out.push_str(d),
                            None => {
                                findings.push(Finding::new(
                                Status::Unsupported,
                                line,
                                format!("{ctx}: {{${name}}}"),
                                format!("unresolved variable — pass `--var {name}=…` or set it in .env"),
                            ));
                                ok = false;
                            }
                        }
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str("{$");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    if ok {
        Some(out)
    } else {
        None
    }
}

fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// ── Mapper ────────────────────────────────────────────────────────────────

fn build(
    file: &Caddyfile,
    env: &Env,
    cli_acme_email: Option<&str>,
    findings: &mut Vec<Finding>,
) -> ZionDoc {
    let mut doc = ZionDoc {
        listen_http: "0.0.0.0:80".to_string(),
        listen_https: "0.0.0.0:443".to_string(),
        rate_limit: None,
        max_conn_per_ip: None,
        trusted_proxies: Vec::new(),
        tls_cert: PLACEHOLDER_CERT.to_string(),
        tls_key: PLACEHOLDER_KEY.to_string(),
        tls_min12: false,
        sni: Vec::new(),
        acme: None,
        waf_body_mb: None,
        upstreams: Vec::new(),
        routes: Vec::new(),
    };

    let mut acme_email: Option<String> = None;
    for node in &file.global {
        apply_global(node, &mut acme_email, findings);
    }

    let mut seen_upstreams: BTreeSet<String> = BTreeSet::new();
    for site in &file.sites {
        let hosts = resolve_hosts(site, env, findings);
        let body = expand_imports(&site.body, &file.snippets);
        map_site(
            &body,
            &hosts,
            env,
            &acme_email,
            cli_acme_email,
            &mut doc,
            &mut seen_upstreams,
            findings,
        );
    }
    doc
}

fn apply_global(node: &Node, acme_email: &mut Option<String>, findings: &mut Vec<Finding>) {
    match node.name.as_str() {
        "email" => {
            if let Some(e) = node.args.first() {
                *acme_email = Some(e.clone());
            }
        }
        "auto_https" => findings.push(Finding::new(
            Status::Auto,
            node.line,
            "auto_https",
            "TLS/HTTPS behavior is driven by Zion's [tls] block, not a global toggle",
        )),
        "admin" | "debug" | "log" | "order" | "grace_period" | "storage" => {
            findings.push(Finding::new(
                Status::Auto,
                node.line,
                node.name.clone(),
                "global option — no routing effect",
            ))
        }
        "servers" => findings.push(Finding::new(
            Status::Partial,
            node.line,
            "servers",
            "global server tuning (timeouts, protocols) has only partial Zion knobs",
        )),
        other => findings.push(Finding::new(
            Status::Unsupported,
            node.line,
            other.to_string(),
            "unrecognized global option",
        )),
    }
}

/// Resolve a site's addresses into hosts, folding `:80` / `:443` bare-port
/// addresses into hostless routes. Invalid / unresolved addresses are findings.
fn resolve_hosts(site: &Site, env: &Env, findings: &mut Vec<Finding>) -> Vec<String> {
    let mut hosts = Vec::new();
    for addr in &site.addresses {
        let Some(resolved) = resolve(addr, env, site.line, "site address", findings) else {
            continue; // finding already recorded
        };
        // Strip an optional scheme and a trailing :port.
        let no_scheme = resolved
            .strip_prefix("https://")
            .or_else(|| resolved.strip_prefix("http://"))
            .unwrap_or(&resolved);
        let host = no_scheme.split('/').next().unwrap_or(no_scheme);
        let host = match host.rsplit_once(':') {
            // `:443` / `host:8080` → drop the port; a bare `:port` leaves nothing.
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        if host.is_empty() || host == "*" {
            // `:80`, `:443`, `*` → hostless (Zion's shared/default layer).
            continue;
        }
        if host.contains('{') || host.contains('}') {
            findings.push(Finding::new(
                Status::Unsupported,
                site.line,
                "site address",
                format!("runtime placeholder in host `{host}` cannot be a static route host"),
            ));
            continue;
        }
        hosts.push(host.to_string());
    }
    // Dedupe (e.g. `example.com, example.com:443`) preserving order — duplicate
    // ACME domains / route hosts otherwise leak into the emitted config.
    let mut seen = std::collections::BTreeSet::new();
    hosts.retain(|h| seen.insert(h.clone()));
    hosts
}

/// Inline `import <snippet>` directives (one level; unknown names are left as a
/// node so the mapper reports them).
fn expand_imports(body: &[Node], snippets: &BTreeMap<String, Vec<Node>>) -> Vec<Node> {
    let mut out = Vec::new();
    for node in body {
        if node.name == "import" && node.block.is_none() {
            if let Some(name) = node.args.first() {
                if let Some(expanded) = snippets.get(name) {
                    out.extend(expanded.iter().cloned());
                    continue;
                }
            }
        }
        out.push(node.clone());
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn map_site(
    body: &[Node],
    hosts: &[String],
    env: &Env,
    acme_email: &Option<String>,
    cli_acme_email: Option<&str>,
    doc: &mut ZionDoc,
    seen_upstreams: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    // A site with `root <dir>` + `file_server` serves files from disk
    // (ADR-0015); it may coexist with proxy handlers as a static fallback.
    let static_spec = detect_static(body);

    // Pass 1: site-level directives (headers, tls, encode, …). The site-level
    // header block yields a CSP that applies to every route unless a handler
    // overrides it.
    let mut site_csp: Option<String> = None;
    for node in body {
        match node.name.as_str() {
            "header" => {
                if let Some(csp) = map_header(node, findings) {
                    site_csp = Some(csp);
                }
            }
            "tls" => map_tls(node, doc, findings),
            "encode" => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                "encode",
                "Zion does not compress responses — the backend should",
            )),
            "log" => findings.push(Finding::new(
                Status::Auto,
                node.line,
                "log",
                "structured JSON logging to stdout is built in",
            )),
            "root" | "file_server" => {
                if static_spec.is_some() {
                    findings.push(Finding::new(
                        Status::Convert,
                        node.line,
                        node.name.clone(),
                        "→ mode=static — files served from disk (ADR-0015)",
                    ));
                } else {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        node.line,
                        node.name.clone(),
                        "static serving needs both `root <dir>` and `file_server`",
                    ));
                }
            }
            "try_files" => {
                let spa = static_spec.as_ref().map(|s| s.1).unwrap_or(false);
                findings.push(Finding::new(
                    if spa { Status::Convert } else { Status::Unsupported },
                    node.line,
                    "try_files",
                    "SPA fallback (`… /index.html`) → spa_fallback; other try_files forms are unsupported",
                ));
            }
            "respond" => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                "respond",
                "Zion has no static-response directive",
            )),
            "redir" => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                "redir",
                "explicit redirects have no Zion equivalent (HTTP→HTTPS is built in)",
            )),
            "handle_path" => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                "handle_path",
                "path rewriting (prefix stripping) has no Zion equivalent",
            )),
            // Route-bearing directives are handled in pass 2.
            "handle" | "reverse_proxy" | "route" => {}
            other if other.starts_with('@') => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                other.to_string(),
                "named matchers are not converted (v0)",
            )),
            other => findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                other.to_string(),
                "no Zion equivalent — review manually",
            )),
        }
    }

    // Pass 2: build routes from handle / reverse_proxy directives.
    for node in body {
        match node.name.as_str() {
            "handle" | "route" => map_handle(
                node,
                hosts,
                site_csp.as_deref(),
                env,
                doc,
                seen_upstreams,
                findings,
            ),
            "reverse_proxy" => map_reverse_proxy(
                node,
                hosts,
                site_csp.as_deref(),
                env,
                doc,
                seen_upstreams,
                findings,
            ),
            _ => {}
        }
    }

    // A static site/route (root + file_server) becomes a catch-all mode=static
    // route, emitted AFTER the proxy routes so a more-specific handler wins.
    if let Some((dir, spa)) = static_spec {
        let route_hosts = if hosts.is_empty() {
            None
        } else {
            Some(hosts.to_vec())
        };
        // F2: a bare `handle` / `reverse_proxy` may already own the catch-all at
        // this (path, hosts); matchit rejects a duplicate route, so drop the
        // static fallback (the proxy handler covers everything in Caddy too).
        let collides = doc
            .routes
            .iter()
            .any(|r| r.serve_dir.is_none() && r.path == "/{*rest}" && r.hosts == route_hosts);
        if collides {
            findings.push(Finding::new(
                Status::Partial,
                0,
                "file_server",
                "a catch-all proxy handler already covers this site — the static file_server fallback is dropped (unreachable behind it)",
            ));
        } else {
            // F9: a hostless static catch-all lands in Zion's SHARED default
            // layer (unlike Caddy, where a `:port` block does not apply to a
            // host with its own site) — so it would serve files under EVERY
            // authority. Flag it loudly.
            if route_hosts.is_none() {
                findings.push(Finding::new(
                    Status::Partial,
                    0,
                    "file_server (hostless)",
                    "a hostless static site becomes a shared fallback across ALL hosts in Zion; scope it to a host, or a request to another host with no match will be served these files",
                ));
            }
            doc.routes.push(RouteOut {
                path: "/{*rest}".to_string(),
                hosts: route_hosts,
                upstream: String::new(),
                websocket: false,
                csp: site_csp.clone(),
                waf: false,
                serve_dir: Some(dir),
                spa_fallback: spa,
                annotations: Vec::new(),
            });
        }
    }

    apply_site_acme(body, hosts, acme_email, cli_acme_email, doc, findings);
}

/// A site's `root <dir>` + `file_server` → `(serve_dir, spa_fallback)`, or
/// `None` if it serves no files. `try_files … /index.html` sets the SPA flag.
fn detect_static(body: &[Node]) -> Option<(String, bool)> {
    if !body.iter().any(|n| n.name == "file_server") {
        return None;
    }
    let dir = body.iter().find(|n| n.name == "root")?.args.last()?.clone();
    // The last `root` arg must be a real directory, not a matcher (`root *`,
    // `root @m /d`) or empty — otherwise there is no serve dir to convert.
    if dir.is_empty() || dir == "*" || dir.starts_with('@') || dir.contains('*') {
        return None;
    }
    let spa = body
        .iter()
        .any(|n| n.name == "try_files" && n.args.iter().any(|a| a.contains("index.html")));
    Some((dir, spa))
}

/// Map a `header` block. Security headers Zion already injects → `auto`;
/// `Content-Security-Policy` → returned as a route/site CSP (convert);
/// HSTS → `partial` (Zion's value is fixed); the rest → `unsupported`.
fn map_header(node: &Node, findings: &mut Vec<Finding>) -> Option<String> {
    // Fields come either as a block or as inline `header Field value` args.
    let fields: Vec<(String, u32)> = match &node.block {
        Some(block) => block.iter().map(|n| (n.name.clone(), n.line)).collect(),
        None => node
            .args
            .first()
            .map(|f| vec![(f.clone(), node.line)])
            .unwrap_or_default(),
    };
    // Capture Content-Security-Policy from EITHER the block form
    // (`header { Content-Security-Policy "…" }`) or the inline one-liner
    // (`header Content-Security-Policy "…"`) — the inline form was silently lost.
    let mut csp = None;
    match &node.block {
        Some(block) => {
            for n in block {
                if n.name.eq_ignore_ascii_case("Content-Security-Policy") {
                    csp = n.args.first().cloned();
                }
            }
        }
        None => {
            if node
                .args
                .first()
                .is_some_and(|f| f.eq_ignore_ascii_case("Content-Security-Policy"))
            {
                csp = node.args.get(1).cloned();
            }
        }
    }
    for (field, line) in fields {
        let f = field.trim_start_matches('-');
        let (status, detail): (Status, &str) = match () {
            _ if field.starts_with('-') => (Status::Auto, "Zion already strips this header"),
            _ if f.eq_ignore_ascii_case("X-Content-Type-Options")
                || f.eq_ignore_ascii_case("X-Frame-Options")
                || f.eq_ignore_ascii_case("Referrer-Policy")
                || f.eq_ignore_ascii_case("Permissions-Policy") =>
            {
                (Status::Auto, "Zion injects this security header built-in")
            }
            _ if f.eq_ignore_ascii_case("Strict-Transport-Security") => (
                Status::Partial,
                "Zion sets HSTS built-in with a fixed max-age (63072000; not configurable)",
            ),
            _ if f.eq_ignore_ascii_case("Content-Security-Policy") => {
                continue; // handled as a route CSP, not a finding
            }
            _ if f.eq_ignore_ascii_case("X-XSS-Protection") => (
                Status::Unsupported,
                "Zion does not set X-XSS-Protection (a no-op on modern browsers)",
            ),
            _ => (Status::Unsupported, "no generic header-manipulation target"),
        };
        findings.push(Finding::new(status, line, format!("header {f}"), detail));
    }
    csp
}

/// `tls email` / `tls { … }` / `tls internal` → placeholder cert + `partial`
/// (ACME deferred). `tls <cert> <key>` (explicit files) → convert.
fn map_tls(node: &Node, doc: &mut ZionDoc, findings: &mut Vec<Finding>) {
    // Explicit cert + key files → a real cert.
    if is_explicit_cert(node) {
        doc.tls_cert = node.args[0].clone();
        doc.tls_key = node.args[1].clone();
        findings.push(Finding::new(
            Status::Convert,
            node.line,
            "tls <cert> <key>",
            "explicit certificate files → [tls] cert_path/key_path",
        ));
        return;
    }
    // `protocols tls1.2 …` inside the block → min version.
    if let Some(block) = &node.block {
        for n in block {
            if n.name == "protocols" && n.args.iter().any(|p| p.contains("1.2")) {
                doc.tls_min12 = true;
                findings.push(Finding::new(
                    Status::Convert,
                    n.line,
                    "tls.protocols",
                    "tls.min_version = \"1.2\"",
                ));
            }
        }
    }
    // ACME-managed TLS (`tls <email>` / `internal` / bare) is decided at the
    // site level in `apply_site_acme`, which can see the site hosts.
}

/// A crude e-mail shape check — has an `@`, no path separator, a dotted domain.
/// Distinguishes `ops@example.com` from a cert path like `/etc/ssl/git@h.crt`.
fn looks_like_email(s: &str) -> bool {
    match s.split_once('@') {
        Some((user, domain)) => !user.is_empty() && !s.contains('/') && domain.contains('.'),
        None => false,
    }
}

fn is_explicit_cert(node: &Node) -> bool {
    node.args.len() == 2
        && !looks_like_email(&node.args[0])
        && node.args[0] != "internal"
        && node.args[1] != "internal"
}

/// Decide automatic HTTPS for a site: emit `[tls.acme]` when the site uses
/// ACME-managed TLS (a `tls` directive that isn't explicit cert files, or the
/// operator opting in with `--acme-email`) and a contact e-mail is known.
fn apply_site_acme(
    body: &[Node],
    hosts: &[String],
    global_email: &Option<String>,
    cli_acme_email: Option<&str>,
    doc: &mut ZionDoc,
    findings: &mut Vec<Finding>,
) {
    let tls_node = body.iter().find(|n| n.name == "tls");
    if tls_node.map(is_explicit_cert).unwrap_or(false) {
        return; // a real cert, not ACME (map_tls handled it)
    }
    if tls_node.is_none() && cli_acme_email.is_none() {
        return; // no ACME intent — the operator supplies TLS
    }
    let public: Vec<String> = hosts
        .iter()
        .filter(|h| *h != "localhost" && h.parse::<std::net::IpAddr>().is_err())
        .cloned()
        .collect();
    if public.is_empty() {
        return; // localhost / IP only — no public cert
    }
    let line = tls_node.map(|n| n.line).unwrap_or(0);
    let email = tls_node
        .and_then(|n| n.args.iter().find(|a| looks_like_email(a)).cloned())
        .or_else(|| cli_acme_email.map(String::from))
        .or_else(|| global_email.clone())
        .filter(|e| looks_like_email(e));
    match email {
        Some(email) => {
            findings.push(Finding::new(
                Status::Convert,
                line,
                "tls (ACME)",
                format!(
                    "automatic HTTPS → [tls.acme] (email = \"{email}\") for {}",
                    public.join(", ")
                ),
            ));
            match &mut doc.acme {
                Some(acme) => {
                    for h in &public {
                        if !acme.domains.contains(h) {
                            acme.domains.push(h.clone());
                        }
                    }
                }
                None => {
                    doc.acme = Some(AcmeOut {
                        email,
                        domains: public,
                    })
                }
            }
        }
        None => findings.push(Finding::new(
            Status::Partial,
            line,
            "tls (ACME)",
            "Caddy auto-HTTPS → placeholder cert. Pass `--acme-email you@example.com` to emit \
             [tls.acme], or point [tls] at an existing certificate manager's cert"
                .to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn map_handle(
    node: &Node,
    hosts: &[String],
    site_csp: Option<&str>,
    env: &Env,
    doc: &mut ZionDoc,
    seen_upstreams: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    // `handle [matcher] { … }`. A named matcher we cannot convert.
    let matcher = node.args.first().map(String::as_str);
    if let Some(m) = matcher {
        if m.starts_with('@') {
            findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                format!("handle {m}"),
                "named matchers are not converted (v0)",
            ));
            return;
        }
    }
    let path = matcher_to_path(matcher);

    let Some(block) = &node.block else {
        findings.push(Finding::new(
            Status::Unsupported,
            node.line,
            "handle",
            "handle without a block does nothing convertible",
        ));
        return;
    };

    // A handler that serves files or responds statically is the product edge.
    if let Some(bad) = block
        .iter()
        .find(|n| matches!(n.name.as_str(), "root" | "file_server" | "respond"))
    {
        findings.push(Finding::new(
            Status::Unsupported,
            bad.line,
            format!("handle → {}", bad.name),
            "this handler serves no upstream (static/respond) — route dropped",
        ));
        return;
    }

    // CSP from a nested header block overrides the site-level CSP.
    let mut route_csp = site_csp.map(str::to_string);
    for n in block {
        if n.name == "header" {
            if let Some(csp) = map_header(n, findings) {
                route_csp = Some(csp);
            }
        }
    }

    let Some(rp) = block.iter().find(|n| n.name == "reverse_proxy") else {
        findings.push(Finding::new(
            Status::Unsupported,
            node.line,
            "handle",
            "no reverse_proxy in this handler — nothing to route to",
        ));
        return;
    };

    push_route(
        rp,
        &path,
        hosts,
        route_csp.as_deref(),
        env,
        doc,
        seen_upstreams,
        findings,
    );
}

#[allow(clippy::too_many_arguments)]
fn map_reverse_proxy(
    node: &Node,
    hosts: &[String],
    site_csp: Option<&str>,
    env: &Env,
    doc: &mut ZionDoc,
    seen_upstreams: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    // Bare `reverse_proxy [matcher] upstream…` directly in a site.
    let matcher = node
        .args
        .first()
        .filter(|a| a.starts_with('/') || a.starts_with('@') || *a == "*")
        .map(String::as_str);
    if let Some(m) = matcher {
        if m.starts_with('@') {
            findings.push(Finding::new(
                Status::Unsupported,
                node.line,
                format!("reverse_proxy {m}"),
                "named matchers are not converted (v0)",
            ));
            return;
        }
    }
    let path = matcher_to_path(matcher);
    push_route(
        node,
        &path,
        hosts,
        site_csp,
        env,
        doc,
        seen_upstreams,
        findings,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_route(
    rp: &Node,
    path: &str,
    hosts: &[String],
    csp: Option<&str>,
    env: &Env,
    doc: &mut ZionDoc,
    seen_upstreams: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    // Upstreams are the reverse_proxy args that are not the leading matcher.
    let targets: Vec<&String> = rp
        .args
        .iter()
        .filter(|a| !a.starts_with('/') && !a.starts_with('@') && *a != "*")
        .collect();
    if targets.is_empty() {
        findings.push(Finding::new(
            Status::Unsupported,
            rp.line,
            "reverse_proxy",
            "no upstream address — cannot build an upstream",
        ));
        return;
    }

    let mut urls = Vec::new();
    for t in &targets {
        let Some(resolved) = resolve(t, env, rp.line, "reverse_proxy", findings) else {
            return; // unresolved variable already recorded
        };
        urls.push(to_url(&resolved));
    }

    // Name the upstream after the first target's host.
    let up_name = sanitize_name(host_of(&urls[0]));
    if seen_upstreams.insert(up_name.clone()) {
        doc.upstreams.push(UpstreamOut {
            name: up_name.clone(),
            urls,
            connect_timeout_ms: None,
            keepalive: None,
        });
    }

    findings.push(Finding::new(
        Status::Convert,
        rp.line,
        "reverse_proxy",
        format!("→ route {path} upstream '{up_name}'"),
    ));
    doc.routes.push(RouteOut {
        path: path.to_string(),
        hosts: if hosts.is_empty() {
            None
        } else {
            Some(hosts.to_vec())
        },
        upstream: up_name,
        websocket: false,
        csp: csp.map(str::to_string),
        waf: false,
        serve_dir: None,
        spa_fallback: false,
        annotations: Vec::new(),
    });
}

// ── Small helpers ─────────────────────────────────────────────────────────

/// A Caddy path matcher → a Zion route path. `/api/*` → `/api/{*rest}`;
/// `/exact` → `/exact`; none / `*` → `/{*rest}`.
fn matcher_to_path(matcher: Option<&str>) -> String {
    match matcher {
        None | Some("*") => "/{*rest}".to_string(),
        Some(m) if m.ends_with('*') => {
            let base = m.trim_end_matches('*').trim_end_matches('/');
            if base.is_empty() {
                "/{*rest}".to_string()
            } else {
                format!("{base}/{{*rest}}")
            }
        }
        Some(m) => m.to_string(),
    }
}

fn to_url(target: &str) -> String {
    if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    }
}

fn host_of(url: &str) -> &str {
    let no_scheme = url.split("://").last().unwrap_or(url);
    let hostport = no_scheme.split('/').next().unwrap_or(no_scheme);
    hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport)
}

fn sanitize_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "upstream".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env {
            map: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn convert_str(src: &str, vars: &[(&str, &str)]) -> Result<Conversion, ConvertError> {
        let cli: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        convert(src, None, &cli, None)
    }

    // ── lexer / parser ──

    #[test]
    fn placeholder_is_a_word_not_a_brace() {
        // The critical disambiguation: `{$DOMAIN:localhost}` is one token.
        let f = parse("{$DOMAIN:localhost} {\n  reverse_proxy api:8000\n}").unwrap();
        assert_eq!(f.sites.len(), 1);
        assert_eq!(
            f.sites[0].addresses,
            vec!["{$DOMAIN:localhost}".to_string()]
        );
        assert_eq!(f.sites[0].body.len(), 1);
        assert_eq!(f.sites[0].body[0].name, "reverse_proxy");
    }

    #[test]
    fn global_block_then_site() {
        let f = parse("{\n  email a@b.com\n}\nexample.com {\n  reverse_proxy app:80\n}").unwrap();
        assert_eq!(f.global.len(), 1);
        assert_eq!(f.global[0].name, "email");
        assert_eq!(f.sites.len(), 1);
        assert_eq!(f.sites[0].addresses, vec!["example.com".to_string()]);
    }

    #[test]
    fn nested_blocks_and_quoted_values() {
        let f = parse(
            "example.com {\n  handle /api/* {\n    reverse_proxy api:8000\n    header {\n      Content-Security-Policy \"default-src 'none'\"\n    }\n  }\n}",
        )
        .unwrap();
        let handle = &f.sites[0].body[0];
        assert_eq!(handle.name, "handle");
        assert_eq!(handle.args, vec!["/api/*".to_string()]);
        let inner = handle.block.as_ref().unwrap();
        assert_eq!(inner[0].name, "reverse_proxy");
        let header = &inner[1];
        assert_eq!(
            header.block.as_ref().unwrap()[0].name,
            "Content-Security-Policy"
        );
        assert_eq!(
            header.block.as_ref().unwrap()[0].args,
            vec!["default-src 'none'".to_string()]
        );
    }

    #[test]
    fn snippet_is_captured_not_a_site() {
        let f = parse("(sec) {\n  header X-Frame-Options DENY\n}\nexample.com {\n  import sec\n  reverse_proxy app:80\n}").unwrap();
        assert!(f.snippets.contains_key("sec"));
        assert_eq!(f.sites.len(), 1);
    }

    #[test]
    fn unterminated_block_is_a_parse_error() {
        let e = parse("example.com {\n  reverse_proxy app:80\n").unwrap_err();
        assert!(e.msg.contains("unclosed") || e.msg.contains("end of input"));
    }

    #[test]
    fn comments_are_skipped() {
        let f =
            parse("# top comment\nexample.com {\n  reverse_proxy app:80  # trailing\n}").unwrap();
        assert_eq!(f.sites[0].body.len(), 1);
    }

    // ── mapping ──

    #[test]
    fn matcher_paths() {
        assert_eq!(matcher_to_path(None), "/{*rest}");
        assert_eq!(matcher_to_path(Some("*")), "/{*rest}");
        assert_eq!(matcher_to_path(Some("/api/*")), "/api/{*rest}");
        assert_eq!(matcher_to_path(Some("/health")), "/health");
    }

    #[test]
    fn resolve_default_and_unresolved() {
        let e = env(&[("SET", "v")]);
        let mut f = Vec::new();
        assert_eq!(resolve("{$SET}", &e, 1, "x", &mut f).as_deref(), Some("v"));
        assert_eq!(
            resolve("{$UNSET:def}", &e, 1, "x", &mut f).as_deref(),
            Some("def")
        );
        assert_eq!(resolve("{$MISSING}", &e, 9, "site address", &mut f), None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 9);
        assert!(f[0].detail.contains("--var MISSING="));
    }

    const NIS2_SHAPE: &str = r#"
{$DOMAIN:localhost} {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options    "nosniff"
        X-Frame-Options           "DENY"
        Referrer-Policy           "strict-origin-when-cross-origin"
        X-XSS-Protection          "1; mode=block"
        Permissions-Policy        "geolocation=(), camera=()"
        -Server
    }
    handle /api/* {
        reverse_proxy api:8000
        header {
            Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
        }
    }
    handle {
        reverse_proxy web:3000
        header {
            Content-Security-Policy "default-src 'self'"
        }
    }
    encode gzip zstd
    log {
        output stdout
        format json
    }
}
"#;

    #[test]
    fn nis2_shape_converts_both_routes() {
        let c = convert_str(NIS2_SHAPE, &[]).expect("should convert");
        // Two upstreams, two routes, host defaulted to localhost.
        assert!(c.toml.contains("[upstream.api]") && c.toml.contains("http://api:8000"));
        assert!(c.toml.contains("[upstream.web]") && c.toml.contains("http://web:3000"));
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert!(c.toml.contains("hosts = [\"localhost\"]"));
        // per-handler CSP became route csp
        assert!(c.toml.contains("default-src 'none'"));
        assert!(c.toml.contains("default-src 'self'"));
        // the source header is honest
        assert!(c.toml.contains("zion import caddy"));
        // header block evaporated to auto; HSTS is partial; XSS + encode unsupported
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Partial
                && f.directive.contains("Strict-Transport-Security")));
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Unsupported && f.directive.contains("X-XSS-Protection")));
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Unsupported && f.directive == "encode"));
    }

    #[test]
    fn tls_email_emits_acme() {
        let src = "example.com {\n  reverse_proxy app:8080\n  tls ops@example.com\n}";
        let c = convert_str(src, &[]).expect("convert");
        let tls = c
            .findings
            .iter()
            .find(|f| f.directive == "tls (ACME)")
            .expect("acme finding");
        assert_eq!(tls.status, Status::Convert);
        assert!(c.toml.contains("[tls.acme]"));
        assert!(c.toml.contains("email = \"ops@example.com\""));
        assert!(c.toml.contains("domains = [\"example.com\"]"));
        // The bootstrap cert stays so :443 binds before issuance.
        assert!(c.toml.contains("cert_path = \"/etc/ssl/zion/zion.crt\""));
    }

    #[test]
    fn acme_email_flag_opts_in_without_a_tls_directive() {
        // The nis2 swap case: implicit auto-HTTPS, no e-mail in the Caddyfile;
        // --acme-email supplies it and we emit a real [tls.acme].
        let src = "app.example.com {\n  reverse_proxy web:3000\n}";
        let c = convert(src, None, &[], Some("ops@example.com")).expect("convert");
        assert!(c.toml.contains("[tls.acme]"));
        assert!(c.toml.contains("email = \"ops@example.com\""));
        assert!(c.toml.contains("domains = [\"app.example.com\"]"));
    }

    #[test]
    fn explicit_cert_files_convert() {
        let src = "example.com {\n  reverse_proxy app:8080\n  tls /etc/ssl/a.crt /etc/ssl/a.key\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c.toml.contains("cert_path = \"/etc/ssl/a.crt\""));
        assert!(c.toml.contains("key_path = \"/etc/ssl/a.key\""));
    }

    #[test]
    fn static_site_converts_to_mode_static() {
        let src = "example.com {\n  root * /var/www\n  file_server\n}";
        let c = convert_str(src, &[]).expect("static site should convert");
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/var/www\""));
        assert!(c.toml.contains("path = \"/{*rest}\""));
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Convert && f.directive == "file_server"));
    }

    #[test]
    fn hybrid_static_plus_proxy() {
        // The Tier B shape: an API proxied, everything else served from disk
        // with an SPA fallback.
        let src = "example.com {\n  handle /api/* {\n    reverse_proxy api:8000\n  }\n  root * /srv\n  file_server\n  try_files {path} /index.html\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c.toml.contains("[upstream.api]") && c.toml.contains("http://api:8000"));
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/srv\""));
        assert!(c.toml.contains("spa_fallback = true"));
    }

    // ── adversarial-review regressions (draconian, one per finding) ──

    #[test]
    fn deeply_nested_blocks_error_not_stack_overflow() {
        // F1: a pathological nest must return Err, never overflow the stack
        // (if it overflowed, this test process would abort).
        let src = "a {\n".repeat(500);
        assert!(parse(&src).is_err());
    }

    #[test]
    fn catchall_proxy_plus_file_server_does_not_double_route() {
        // F2: a bare `handle` (catch-all proxy) + `file_server` must NOT emit two
        // `/{*rest}` routes (matchit rejects the dup → self_validate would fail).
        let src = "example.com {\n  handle {\n    reverse_proxy web:3000\n  }\n  root * /srv\n  file_server\n}";
        let c = convert_str(src, &[]).expect("should convert, not internal-error");
        assert_eq!(c.toml.matches("path = \"/{*rest}\"").count(), 1);
        assert!(c.toml.contains("http://web:3000") && !c.toml.contains("mode = \"static\""));
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Partial && f.directive == "file_server"));
    }

    #[test]
    fn inline_header_csp_is_captured() {
        // F3: the one-liner `header CSP "…"` form must set route.csp.
        let src = "example.com {\n  header Content-Security-Policy \"default-src 'self'\"\n  reverse_proxy app:80\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c.toml.contains("csp = \"default-src 'self'\""));
    }

    #[test]
    fn cert_path_containing_at_is_not_an_acme_email() {
        // F4: a cert path with '@' must be explicit cert files, never ACME.
        let src = "example.com {\n  reverse_proxy app:80\n  tls /etc/ssl/git@host.crt /etc/ssl/git@host.key\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c.toml.contains("cert_path = \"/etc/ssl/git@host.crt\""));
        assert!(!c.toml.contains("[tls.acme]"));
    }

    #[test]
    fn no_acme_without_a_real_email() {
        // F5: `tls internal` (no e-mail anywhere) must not emit [tls.acme].
        let src = "example.com {\n  reverse_proxy app:80\n  tls internal\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(!c.toml.contains("[tls.acme]"));
    }

    #[test]
    fn duplicate_site_addresses_are_deduped() {
        // F6: `example.com, example.com:443` → one host, not two.
        let src = "example.com, example.com:443 {\n  reverse_proxy app:80\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c.toml.contains("hosts = [\"example.com\"]"));
        assert!(!c.toml.contains("\"example.com\", \"example.com\""));
    }

    #[test]
    fn root_matcher_without_a_dir_is_not_static() {
        // F8: `root *` (matcher, no dir) must not become serve_dir="*".
        let src = "example.com {\n  root *\n  file_server\n}";
        match convert_str(src, &[]) {
            Ok(c) => assert!(!c.toml.contains("serve_dir = \"*\"")),
            Err(ConvertError::NoRoutes(f)) => {
                assert!(f.iter().any(|x| x.status == Status::Unsupported))
            }
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }

    #[test]
    fn hostless_static_site_is_flagged() {
        // F9: a hostless static site becomes a shared cross-host fallback.
        let src = ":443 {\n  root * /var/www\n  file_server\n}";
        let c = convert_str(src, &[]).expect("convert");
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Partial && f.directive.contains("hostless")));
    }

    #[test]
    fn snippet_import_is_inlined() {
        let src = "(sec) {\n  header X-Frame-Options DENY\n}\nexample.com {\n  import sec\n  reverse_proxy app:8080\n}";
        let c = convert_str(src, &[]).expect("convert");
        // X-Frame-Options from the snippet → auto finding
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Auto && f.directive.contains("X-Frame-Options")));
        assert!(c.toml.contains("http://app:8080"));
    }

    #[test]
    fn unresolved_domain_without_default_refuses() {
        let src = "{$PUBLIC} {\n  reverse_proxy app:8080\n}";
        match convert_str(src, &[]) {
            Err(ConvertError::NoRoutes(f)) => {
                assert!(f.iter().any(|x| x.detail.contains("PUBLIC")))
            }
            // A hostless route could still emit; assert the finding exists instead.
            Ok(c) => assert!(c.findings.iter().any(|x| x.detail.contains("PUBLIC"))),
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }

    #[test]
    fn var_resolves_the_domain() {
        let src = "{$PUBLIC} {\n  reverse_proxy app:8080\n}";
        let c = convert_str(src, &[("PUBLIC", "app.example.com")]).expect("convert");
        assert!(c.toml.contains("hosts = [\"app.example.com\"]"));
    }

    // ── golden corpus (anonymized fleet shapes) ──

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/import/caddy")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    #[test]
    fn golden_security_headers() {
        let c = convert(&fixture("security-headers.caddy"), None, &[], None).expect("convert");
        assert!(c.toml.contains("[upstream.api]") && c.toml.contains("http://api:8000"));
        assert!(c.toml.contains("[upstream.web]") && c.toml.contains("http://web:3000"));
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert!(c.toml.contains("hosts = [\"localhost\"]"));
        assert!(c
            .toml
            .contains("csp = \"default-src 'none'; frame-ancestors 'none'\""));
        // The header block evaporates: XFO / XCTO / Referrer / Permissions → auto.
        assert!(
            c.findings
                .iter()
                .filter(|f| f.status == Status::Auto && f.directive.starts_with("header"))
                .count()
                >= 4
        );
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Partial
                && f.directive.contains("Strict-Transport-Security")));
    }

    #[test]
    fn golden_tls_acme_emits_acme() {
        let c = convert(&fixture("tls-acme.caddy"), None, &[], None).expect("convert");
        assert!(c.toml.contains("http://backend:8080"));
        assert!(c.toml.contains("hosts = [\"app.example.com\"]"));
        let tls = c
            .findings
            .iter()
            .find(|f| f.directive == "tls (ACME)")
            .expect("acme finding");
        assert_eq!(tls.status, Status::Convert);
        assert!(c.toml.contains("[tls.acme]"));
        assert!(c.toml.contains("email = \"ops@example.com\""));
        assert!(c.toml.contains("domains = [\"app.example.com\"]"));
    }

    #[test]
    fn golden_snippet_import() {
        let c = convert(&fixture("snippet-import.caddy"), None, &[], None).expect("convert");
        assert!(c.toml.contains("http://api:9000"));
        assert!(c.toml.contains("http://site:3000"));
        assert!(c.toml.contains("hosts = [\"example.com\"]"));
        // The snippet's X-Frame-Options is inlined → auto finding.
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Auto && f.directive.contains("X-Frame-Options")));
    }

    #[test]
    fn golden_static_edge_converts() {
        let c = convert(&fixture("static-edge.caddy"), None, &[], None)
            .expect("static site converts to mode=static");
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/srv/www\""));
        // `encode` is still unsupported (Zion does not compress).
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Unsupported && f.directive == "encode"));
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    proptest! {
        // The reader tolerates arbitrary input: it may return Err, but never panics.
        #[test]
        fn reader_never_panics(s in ".*") {
            let _ = super::parse(&s);
        }

        #[test]
        fn reader_never_panics_structural(
            s in prop::collection::vec(
                prop_oneof![Just("{"), Just("}"), Just("example.com"), Just("reverse_proxy"),
                            Just("app:80"), Just("{$X}"), Just("{$X:d}"), Just("\n"), Just(" "),
                            Just("header"), Just("\""), Just("#c\n")],
                0..64,
            ).prop_map(|v| v.concat())
        ) {
            let _ = super::parse(&s);
        }
    }
}
