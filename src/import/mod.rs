//! `zion import` — convert foreign proxy configs into a validated zion.toml
//! (ADR-0011). Always available, like `zion suggest`: deterministic systems
//! code with zero extra dependencies, and the same self-validation contract —
//! nothing is ever emitted that the config parser would reject.
//!
//! The governing principle is honesty over completeness: every input
//! directive lands in exactly one finding bucket (convert / partial / auto /
//! unsupported), and anything Zion cannot express faithfully is flagged
//! loudly instead of silently mistranslated.

mod emit;
mod map;
mod model;
mod nginx;

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cli::ImportOpts;
use nginx::Directive;

// ── Findings ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Faithfully converted.
    Convert,
    /// Converted with a stated semantic delta.
    Partial,
    /// Zion does it built-in; the directive is dropped with this note.
    Auto,
    /// No faithful Zion equivalent — needs a human decision.
    Unsupported,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Convert => "convert",
            Status::Partial => "partial",
            Status::Auto => "auto",
            Status::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub status: Status,
    pub line: u32,
    pub directive: String,
    pub detail: String,
}

impl Finding {
    fn new(
        status: Status,
        line: u32,
        directive: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            status,
            line,
            directive: directive.into(),
            detail: detail.into(),
        }
    }

    fn unsupported_directive(d: &Directive) -> Self {
        Finding::new(
            Status::Unsupported,
            d.line,
            &d.name,
            "no Zion equivalent — review manually",
        )
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>5}  {:<11}  {:<22}  {}",
            self.line,
            self.status.label(),
            self.directive,
            self.detail
        )
    }
}

// ── Conversion pipeline ─────────────────────────────────────────────────

pub(crate) struct Conversion {
    pub toml: String,
    pub findings: Vec<Finding>,
}

pub(crate) enum ConvertError {
    /// Input could not be parsed (with file/line context).
    Parse(String),
    /// Parsed fine, but nothing was convertible; findings explain why.
    NoRoutes(Vec<Finding>),
    /// The emitted config failed self-validation — an importer bug.
    Internal(String),
}

/// Convert nginx config source. `base_dir` anchors `include` resolution;
/// pass `None` to leave includes unresolved (they become findings).
pub(crate) fn convert(src: &str, base_dir: Option<&Path>) -> Result<Conversion, ConvertError> {
    let ast = nginx::parse(src).map_err(|e| ConvertError::Parse(e.to_string()))?;
    let ast = match base_dir {
        Some(dir) => resolve_includes(ast, dir, 0).map_err(ConvertError::Parse)?,
        None => ast,
    };
    let mut findings = Vec::new();
    let model = model::extract(ast, &mut findings);
    let doc = map::map_model(&model, &mut findings);
    findings.sort_by_key(|f| f.line);
    if doc.routes.is_empty() {
        return Err(ConvertError::NoRoutes(findings));
    }
    let toml = emit::render(&doc);
    emit::self_validate(&toml).map_err(|e| {
        ConvertError::Internal(format!(
            "emitted config failed self-validation — this is an importer bug, \
             please report it: {e}"
        ))
    })?;
    Ok(Conversion { toml, findings })
}

/// Splice resolved `include` directives in place, guarded on depth AND on the
/// total number of spliced directives — depth alone would let a wide include
/// fan-out (each file including many others) amplify a small input into
/// unbounded memory. An include that cannot be resolved is left in the tree —
/// the mapper turns it into an unsupported finding instead of aborting the
/// whole import.
fn resolve_includes(
    items: Vec<Directive>,
    base: &Path,
    depth: u32,
) -> Result<Vec<Directive>, String> {
    let mut budget: usize = 100_000;
    resolve_includes_inner(items, base, depth, &mut budget)
}

fn resolve_includes_inner(
    items: Vec<Directive>,
    base: &Path,
    depth: u32,
    budget: &mut usize,
) -> Result<Vec<Directive>, String> {
    const MAX_INCLUDE_DEPTH: u32 = 16;
    if depth > MAX_INCLUDE_DEPTH {
        return Err("includes nested too deeply (cycle?)".to_string());
    }
    let mut out = Vec::with_capacity(items.len());
    for mut d in items {
        if d.name == "include" && d.block.is_none() && d.args.len() == 1 {
            match included_files(&d.args[0], base) {
                Some(files) if !files.is_empty() => {
                    for file in files {
                        let src = std::fs::read_to_string(&file)
                            .map_err(|e| format!("include {}: {e}", file.display()))?;
                        let sub = nginx::parse(&src)
                            .map_err(|e| format!("include {}: {e}", file.display()))?;
                        *budget = budget.checked_sub(sub.len()).ok_or_else(|| {
                            "include expansion exceeds the directive budget \
                             (100000) — refusing to continue"
                                .to_string()
                        })?;
                        let sub_base = file.parent().unwrap_or(base).to_path_buf();
                        out.extend(resolve_includes_inner(sub, &sub_base, depth + 1, budget)?);
                    }
                    continue;
                }
                _ => {
                    // Unresolved — keep for an honest finding downstream.
                    out.push(d);
                    continue;
                }
            }
        }
        if let Some(block) = d.block.take() {
            d.block = Some(resolve_includes_inner(block, base, depth, budget)?);
        }
        out.push(d);
    }
    Ok(out)
}

/// Resolve an include pattern relative to `base`. Only a `*` wildcard in the
/// final path component is supported (the common `conf.d/*.conf` shape);
/// matches are sorted, as nginx does.
fn included_files(pattern: &str, base: &Path) -> Option<Vec<PathBuf>> {
    let full = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base.join(pattern)
    };
    let name = full.file_name()?.to_str()?.to_string();
    if !name.contains('*') {
        return if full.is_file() {
            Some(vec![full])
        } else {
            None
        };
    }
    let dir = full.parent()?;
    let entries = std::fs::read_dir(dir).ok()?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| wildcard_match(&name, n))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();
    Some(files)
}

/// Simple `*` glob on a single path component.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = name;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(pos) => rest = &rest[pos + part.len()..],
                None => return false,
            }
        }
    }
    // Pattern ends with `*` (or was all `*`s): any remainder matches.
    parts.last().map(|p| p.is_empty()).unwrap_or(false) || rest.is_empty()
}

// ── CLI entry point ─────────────────────────────────────────────────────

/// Exit codes: 0 converted; 1 fatal (bad usage, unreadable/unparseable input,
/// internal self-validation failure — nothing emitted); 2 `--strict` and at
/// least one partial/unsupported finding exists.
pub fn run(opts: ImportOpts) -> i32 {
    match opts.source.as_str() {
        "nginx" => {}
        "" => {
            eprintln!(
                "usage: zion import nginx <path|-> [-o zion.toml] [--report file] [--strict]"
            );
            return 1;
        }
        other => {
            eprintln!("zion import: unsupported source '{other}' (supported: nginx)");
            return 1;
        }
    }
    let input = match &opts.input {
        Some(p) => p.clone(),
        None => {
            eprintln!("zion import nginx: missing input path (use `-` for stdin)");
            return 1;
        }
    };
    let (src, base_dir) = if input == "-" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("zion import: cannot read stdin: {e}");
            return 1;
        }
        (buf, std::env::current_dir().ok())
    } else {
        match std::fs::read_to_string(&input) {
            Ok(s) => {
                let base = Path::new(&input)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .filter(|p| !p.as_os_str().is_empty());
                (s, base)
            }
            Err(e) => {
                eprintln!("zion import: cannot read {input}: {e}");
                return 1;
            }
        }
    };

    let conversion = match convert(&src, base_dir.as_deref()) {
        Ok(c) => c,
        Err(ConvertError::Parse(e)) => {
            eprintln!("zion import: {input}: {e}");
            return 1;
        }
        Err(ConvertError::NoRoutes(findings)) => {
            eprint!("{}", report_text(&findings, true));
            eprintln!("zion import: no convertible routes — nothing emitted");
            return 1;
        }
        Err(ConvertError::Internal(e)) => {
            eprintln!("::error:: internal: {e}");
            return 1;
        }
    };

    // The report file is written BEFORE the config is emitted so that exit 1
    // keeps its contract: fatal means nothing was emitted.
    if let Some(path) = &opts.report {
        if let Err(e) = std::fs::write(path, report_text(&conversion.findings, true)) {
            eprintln!("zion import: cannot write report {path}: {e} — nothing emitted");
            return 1;
        }
    }

    match &opts.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &conversion.toml) {
                eprintln!("zion import: cannot write {path}: {e}");
                return 1;
            }
            eprintln!("wrote {path}");
        }
        None => print!("{}", conversion.toml),
    }

    // Findings that need eyes go to stderr; the full log went to --report.
    eprint!("{}", report_text(&conversion.findings, false));

    let needs_eyes = conversion
        .findings
        .iter()
        .any(|f| matches!(f.status, Status::Partial | Status::Unsupported));
    if opts.strict && needs_eyes {
        eprintln!("--strict: partial/unsupported findings present");
        return 2;
    }
    0
}

/// Render the findings report. `full` includes convert/auto entries; the
/// stderr variant shows only what needs a human (partial/unsupported) plus
/// the counts.
fn report_text(findings: &[Finding], full: bool) -> String {
    let count = |s: Status| findings.iter().filter(|f| f.status == s).count();
    let mut out = String::new();
    out.push_str(&format!(
        "zion import nginx: {} findings — {} convert, {} partial, {} auto, {} unsupported\n",
        findings.len(),
        count(Status::Convert),
        count(Status::Partial),
        count(Status::Auto),
        count(Status::Unsupported),
    ));
    let shown: Vec<&Finding> = findings
        .iter()
        .filter(|f| full || matches!(f.status, Status::Partial | Status::Unsupported))
        .collect();
    if !shown.is_empty() {
        out.push_str(&format!(
            "{:>5}  {:<11}  {:<22}  {}\n",
            "line", "status", "directive", "detail"
        ));
        for f in shown {
            out.push_str(&format!("{f}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/import/nginx")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    fn convert_fixture(name: &str) -> Conversion {
        match convert(&fixture(name), None) {
            Ok(c) => c,
            Err(ConvertError::Parse(e)) => panic!("{name}: parse error: {e}"),
            Err(ConvertError::NoRoutes(f)) => {
                panic!("{name}: no routes; findings:\n{}", report_text(&f, true))
            }
            Err(ConvertError::Internal(e)) => panic!("{name}: internal: {e}"),
        }
    }

    fn has_finding(c: &Conversion, status: Status, directive: &str, needle: &str) -> bool {
        c.findings
            .iter()
            .any(|f| f.status == status && f.directive == directive && f.detail.contains(needle))
    }

    /// The corpus is the executable spec: every fixture must convert into a
    /// TOML that passed schema + semantic + router self-validation (enforced
    /// inside `convert`), and the corpus must stay at exactly the documented
    /// size so additions come with expectations in the README.
    #[test]
    fn golden_corpus_all_convert() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import/nginx");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("corpus dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".conf"))
            .collect();
        names.sort();
        assert_eq!(
            names.len(),
            10,
            "corpus size changed — update the README table"
        );
        for name in names {
            let c = convert_fixture(&name);
            assert!(
                c.toml.contains("[[route]]"),
                "{name}: emitted config has no routes"
            );
        }
    }

    #[test]
    fn corpus_01_nextjs_websocket_and_host_delta() {
        let c = convert_fixture("01-nextjs.conf");
        assert!(c.toml.contains("hosts = [\"app.example.com\"]"));
        assert!(c.toml.contains("mode = \"websocket\""));
        assert!(c.toml.contains("url = \"http://localhost:3000\""));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_set_header",
            "Host"
        ));
        assert!(has_finding(
            &c,
            Status::Auto,
            "proxy_set_header",
            "X-Real-IP"
        ));
        // Plain-HTTP vhost: placeholder certs + stated TLS-termination delta.
        assert!(c.toml.contains("/etc/ssl/zion/zion.crt"));
        assert!(has_finding(&c, Status::Partial, "server", "plain-HTTP"));
    }

    #[test]
    fn corpus_02_wordpress_body_cap_and_timeouts() {
        let c = convert_fixture("02-wordpress.conf");
        assert!(c.toml.contains("max_body_mb = 64"));
        assert!(c.toml.contains("waf_profile = \"imported\""));
        assert!(c.toml.contains("waf_shadow = true"));
        assert!(c.toml.contains("connect_timeout_ms = 75000"));
        assert!(c
            .toml
            .contains("hosts = [\"blog.example.com\", \"www.blog.example.com\"]"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_read_timeout",
            "connect"
        ));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_buffering",
            "sse_stream"
        ));
        // The regex dotfile-deny location is skipped, loudly.
        assert!(has_finding(&c, Status::Unsupported, "location", "regex"));
    }

    #[test]
    fn corpus_03_api_gateway_routes_and_global_rate() {
        let c = convert_fixture("03-api-gateway.conf");
        assert!(c.toml.contains("path = \"/healthz\""));
        assert!(c.toml.contains("path = \"/v1/users/{*rest}\""));
        assert!(c.toml.contains("path = \"/v1/orders/{*rest}\""));
        assert!(c.toml.contains("path = \"/v1/{*rest}\""));
        assert!(c.toml.contains("rate_limit_rps = 20"));
        assert!(has_finding(&c, Status::Partial, "limit_req", "GLOBALLY"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "add_header",
            "X-Gateway"
        ));
    }

    #[test]
    fn corpus_04_static_spa_honesty() {
        let c = convert_fixture("04-static-plus-proxy.conf");
        // Only /api converts; the URI part of its proxy_pass is dropped loudly.
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert_eq!(c.toml.matches("[[route]]").count(), 1);
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_pass",
            "URI part"
        ));
        assert!(c.toml.contains("# UNSUPPORTED: proxy_pass URI part"));
        assert!(has_finding(&c, Status::Unsupported, "try_files", "files"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "location",
            "no convertible proxy target"
        ));
    }

    #[test]
    fn corpus_05_multi_vhost_shared_layer() {
        let c = convert_fixture("05-multi-vhost.conf");
        assert!(c.toml.contains("hosts = [\"alpha.example.com\"]"));
        assert!(c.toml.contains("hosts = [\"beta.example.com\"]"));
        // The default_server `_` catch-all becomes a hostless shared route.
        let routes: Vec<&str> = c.toml.split("[[route]]").skip(1).collect();
        assert_eq!(routes.len(), 3);
        assert!(!routes[2].contains("hosts ="), "catch-all must be hostless");
    }

    #[test]
    fn corpus_06_upstream_pool() {
        let c = convert_fixture("06-upstream-lb.conf");
        assert!(c.toml.contains("[upstream.backend_pool]"));
        assert!(c.toml.contains("urls = [\"http://10.0.2.11:8080\", \"http://10.0.2.12:8080\", \"http://10.0.2.13:8080\"]"));
        assert!(c.toml.contains("keepalive = 32"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "least_conn",
            "load balancing"
        ));
        assert!(has_finding(&c, Status::Unsupported, "server", "weight=3"));
        assert!(has_finding(&c, Status::Unsupported, "server", "backup"));
    }

    #[test]
    fn corpus_07_tls_termination() {
        let c = convert_fixture("07-tls-termination.conf");
        assert!(c
            .toml
            .contains("cert_path = \"/etc/letsencrypt/live/secure.example.com/fullchain.pem\""));
        assert!(c.toml.contains("min_version = \"1.2\""));
        assert!(c.toml.contains("url = \"https://10.0.3.10:8443\""));
        assert!(has_finding(&c, Status::Auto, "server", "redirect"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "ssl_ciphers",
            "rustls"
        ));
        assert!(has_finding(&c, Status::Unsupported, "proxy_ssl_verify", ""));
        assert!(has_finding(
            &c,
            Status::Auto,
            "add_header",
            "Strict-Transport-Security"
        ));
    }

    #[test]
    fn corpus_08_wildcard_default_cert() {
        let c = convert_fixture("08-wildcard-vhost.conf");
        // The wildcard cert must be the DEFAULT (Zion SNI is exact-match).
        assert!(c
            .toml
            .contains("cert_path = \"/etc/ssl/wildcard.tenants.example.com.crt\""));
        assert!(c.toml.contains("hosts = [\"*.tenants.example.com\"]"));
        assert!(c.toml.contains("hosts = [\"tenants.example.com\"]"));
        assert!(has_finding(
            &c,
            Status::Convert,
            "ssl_certificate",
            "default"
        ));
    }

    #[test]
    fn corpus_09_cdn_origin() {
        let c = convert_fixture("09-behind-cdn.conf");
        assert!(c.toml.contains(
            "trusted_proxies = [\"173.245.48.0/20\", \"103.21.244.0/22\", \"2400:cb00::/32\"]"
        ));
        assert!(c.toml.contains("max_connections_per_ip = 20"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "real_ip_header",
            "CF-Connecting-IP"
        ));
        assert!(has_finding(&c, Status::Unsupported, "gzip", ""));
    }

    #[test]
    fn corpus_10_gnarly_survives() {
        let c = convert_fixture("10-gnarly.conf");
        // Only /okay/ converts; everything else is loud, nothing crashed.
        assert_eq!(c.toml.matches("[[route]]").count(), 1);
        assert!(c.toml.contains("path = \"/okay/{*rest}\""));
        assert!(has_finding(&c, Status::Unsupported, "map", ""));
        assert!(has_finding(&c, Status::Unsupported, "if", ""));
        assert!(has_finding(&c, Status::Unsupported, "rewrite", ""));
        assert!(has_finding(&c, Status::Unsupported, "location", "regex"));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_pass",
            "variable"
        ));
        assert!(has_finding(&c, Status::Unsupported, "auth_basic", "JWT"));
    }

    #[test]
    fn include_resolution_and_wildcards() {
        let dir = std::env::temp_dir().join(format!("zion-import-test-{}", std::process::id()));
        let sub = dir.join("conf.d");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(
            sub.join("a.conf"),
            "server { listen 80; location / { proxy_pass http://127.0.0.1:9001; } }",
        )
        .unwrap();
        std::fs::write(sub.join("b.conf"), "server { listen 80; server_name b.example.com; location = /b { proxy_pass http://127.0.0.1:9002; } }").unwrap();
        std::fs::write(sub.join("notes.txt"), "not nginx").unwrap();
        let src = "include conf.d/*.conf;";
        let c = convert(src, Some(&dir))
            .ok()
            .expect("convert with includes");
        assert!(c.toml.contains("http://127.0.0.1:9001"));
        assert!(c.toml.contains("http://127.0.0.1:9002"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unresolved_include_is_a_finding_not_an_abort() {
        let c = convert(
            "include /nonexistent/mime.types;\nserver { listen 80; location / { proxy_pass http://127.0.0.1:9001; } }",
            Some(Path::new("/")),
        )
        .ok()
        .expect("must still convert");
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "include",
            "review manually"
        ));
    }

    #[test]
    fn wildcard_matcher() {
        assert!(wildcard_match("*.conf", "site.conf"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*b*.conf", "aXbY.conf"));
        assert!(!wildcard_match("*.conf", "site.confx"));
        assert!(!wildcard_match("a*.conf", "b.conf"));
    }

    // ── Regression tests for the adversarial-review findings ────────────

    fn ok(src: &str) -> Conversion {
        match convert(src, None) {
            Ok(c) => c,
            Err(ConvertError::Parse(e)) => panic!("parse error: {e}"),
            Err(ConvertError::NoRoutes(f)) => {
                panic!("no routes; findings:\n{}", report_text(&f, true))
            }
            Err(ConvertError::Internal(e)) => panic!("internal: {e}"),
        }
    }

    #[test]
    fn server_level_websocket_idiom_is_inherited() {
        // nginx inherits proxy_set_header into locations with none of their
        // own — the idiom at server level must actually flip the route mode.
        let c = ok("server { listen 80; server_name ws.example.com; \
             proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; \
             location / { proxy_pass http://127.0.0.1:3000; } }");
        assert!(c.toml.contains("mode = \"websocket\""));
    }

    #[test]
    fn location_set_header_blocks_inheritance() {
        // Replace-not-merge: a location with its OWN proxy_set_header set
        // inherits nothing — no websocket mode from the server level.
        let c = ok("server { listen 80; \
             proxy_set_header Upgrade $http_upgrade; \
             location / { proxy_set_header X-Real-IP $remote_addr; proxy_pass http://127.0.0.1:3000; } }");
        assert!(!c.toml.contains("mode = \"websocket\""));
    }

    #[test]
    fn add_header_inheritance_is_replace_not_merge() {
        let c = ok("server { listen 80; \
             add_header Content-Security-Policy \"default-src 'self'\"; \
             location /a/ { proxy_pass http://127.0.0.1:1; } \
             location /b/ { add_header X-Other v; proxy_pass http://127.0.0.1:2; } }");
        let routes: Vec<&str> = c.toml.split("[[route]]").skip(1).collect();
        assert!(
            routes[0].contains("csp = "),
            "location /a/ inherits the server CSP"
        );
        assert!(
            !routes[1].contains("csp = "),
            "location /b/ declares its own add_header — inherits nothing"
        );
    }

    #[test]
    fn location_connect_timeout_overrides_server() {
        let c = ok("server { listen 80; proxy_connect_timeout 30s; \
             location / { proxy_connect_timeout 5s; proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("connect_timeout_ms = 5000"));
        assert!(!c.toml.contains("connect_timeout_ms = 30000"));
    }

    #[test]
    fn cross_host_redirect_is_not_dropped_as_auto() {
        // A domain-migration redirect is NOT Zion's built-in same-host
        // redirect; the server must be kept and its `return` flagged.
        let c = ok("server { listen 80; server_name old.example.com; \
             return 301 https://new.example.com$request_uri; } \
             server { listen 80; server_name a.example.com; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(&c, Status::Unsupported, "return", ""));
        assert!(!c
            .findings
            .iter()
            .any(|f| f.status == Status::Auto && f.directive == "server"));
    }

    #[test]
    fn same_host_302_redirect_dropped_with_code_delta() {
        let c = ok(
            "server { listen 80; return 302 https://$host$request_uri; } \
             server { listen 443 ssl; server_name s.example.com; \
             ssl_certificate /c.pem; ssl_certificate_key /k.pem; \
             location / { proxy_pass http://127.0.0.1:1; } }",
        );
        assert!(has_finding(&c, Status::Partial, "server", "301"));
    }

    #[test]
    fn legacy_ssl_on_marks_listeners_tls() {
        let c = ok("server { listen 443; ssl on; server_name s.example.com; \
             ssl_certificate /c.pem; ssl_certificate_key /k.pem; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("listen_https = \"0.0.0.0:443\""));
        assert!(has_finding(&c, Status::Convert, "ssl", "legacy"));
        assert!(
            !has_finding(&c, Status::Partial, "server", "plain-HTTP"),
            "an `ssl on` server is not plain HTTP"
        );
    }

    #[test]
    fn unix_socket_targets_are_loud_not_garbage() {
        let c = ok(
            "upstream app { server unix:/run/php.sock; server 127.0.0.1:9000; } \
             server { listen 80; \
             location / { proxy_pass http://app; } \
             location /direct/ { proxy_pass http://unix:/run/gunicorn.sock; } }",
        );
        assert!(
            !c.toml.contains("unix"),
            "no unix pseudo-URL may be emitted"
        );
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "server",
            "unix domain socket"
        ));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_pass",
            "unix domain socket"
        ));
    }

    #[test]
    fn default_vhost_scope_widening_is_stated() {
        let c = ok("server { listen 80; server_name a.example.com; \
             location / { proxy_pass http://127.0.0.1:1; } } \
             server { listen 80 default_server; server_name _; \
             location /admin/ { proxy_pass http://127.0.0.1:2; } }");
        assert!(has_finding(
            &c,
            Status::Partial,
            "server",
            "path-miss fallback"
        ));
    }

    #[test]
    fn duplicate_host_across_servers_is_flagged() {
        let c = ok("server { listen 80; server_name a.example.com; \
             location / { proxy_pass http://127.0.0.1:1; } } \
             server { listen 80; server_name a.example.com; \
             location /x/ { proxy_pass http://127.0.0.1:2; } }");
        assert!(has_finding(
            &c,
            Status::Partial,
            "server_name",
            "more than one server block"
        ));
    }

    #[test]
    fn incomplete_cert_pair_is_flagged() {
        let c = ok("server { listen 443 ssl; server_name s.example.com; \
             ssl_certificate /only-cert.pem; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "ssl_certificate",
            "incomplete pair"
        ));
        assert!(
            c.toml.contains("/etc/ssl/zion/zion.crt"),
            "placeholder used"
        );
    }

    #[test]
    fn invalid_cidr_is_flagged_not_emitted() {
        let c = ok("server { listen 80; set_real_ip_from not-a-cidr; \
             set_real_ip_from 10.0.0.0/8; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "set_real_ip_from",
            "not-a-cidr"
        ));
        assert!(c.toml.contains("trusted_proxies = [\"10.0.0.0/8\"]"));
    }

    #[test]
    fn unused_conn_zone_gets_a_finding() {
        let c = ok("limit_conn_zone $binary_remote_addr zone=unusedz:10m; \
             server { listen 80; location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(&c, Status::Auto, "limit_conn_zone", "unusedz"));
    }

    #[test]
    fn ssl_protocols_one_finding_per_directive() {
        // Legacy-only: floor to 1.2 and say so, in ONE finding.
        let c = ok("server { listen 443 ssl; server_name s.example.com; \
             ssl_certificate /c.pem; ssl_certificate_key /k.pem; \
             ssl_protocols TLSv1 TLSv1.1; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("min_version = \"1.2\""));
        assert_eq!(
            c.findings
                .iter()
                .filter(|f| f.directive == "ssl_protocols")
                .count(),
            1
        );
        // 1.3-only: Zion's default, convert.
        let c = ok("server { listen 443 ssl; ssl_protocols TLSv1.3; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(&c, Status::Convert, "ssl_protocols", "default"));
        // Nothing Zion can speak: loud, and --strict-visible.
        let c = ok("server { listen 443 ssl; ssl_protocols SSLv3; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "ssl_protocols",
            "SSLv3"
        ));
    }

    #[test]
    fn happy_path_core_directives_are_accounted() {
        let c = ok("server { listen 443 ssl; server_name h.example.com; \
             ssl_certificate /c.pem; ssl_certificate_key /k.pem; \
             location = /health { proxy_pass http://127.0.0.1:1; } }");
        for directive in [
            "listen",
            "server_name",
            "proxy_pass",
            "ssl_certificate",
            "location",
        ] {
            assert!(
                c.findings.iter().any(|f| f.directive == directive),
                "{directive} must land in a finding bucket"
            );
        }
    }

    #[test]
    fn http_level_mappable_directive_gets_truthful_detail() {
        let c = ok("http { client_max_body_size 64m; \
             server { listen 80; location / { proxy_pass http://127.0.0.1:1; } } }");
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "client_max_body_size",
            "move it into the server block"
        ));
        assert!(
            !c.toml.contains("max_body_mb"),
            "http-level cap must not half-apply"
        );
    }

    #[test]
    fn no_routes_is_an_error_with_findings() {
        match convert("server { listen 80; }", None) {
            Err(ConvertError::NoRoutes(_)) => {}
            _ => panic!("expected NoRoutes"),
        }
    }

    #[test]
    fn parse_error_surfaces() {
        match convert("server { listen 80", None) {
            Err(ConvertError::Parse(e)) => assert!(e.contains("line"), "{e}"),
            _ => panic!("expected Parse error"),
        }
    }
}
