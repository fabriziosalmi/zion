//! `zion import` — convert foreign proxy configs into a validated zion.toml
//! (ADR-0011). Always available, like `zion suggest`: deterministic systems
//! code with zero extra dependencies, and the same self-validation contract —
//! nothing is ever emitted that the config parser would reject.
//!
//! The governing principle is honesty over completeness: every input
//! directive lands in exactly one finding bucket (convert / partial / auto /
//! unsupported), and anything Zion cannot express faithfully is flagged
//! loudly instead of silently mistranslated.

mod caddy;
mod compose;
mod emit;
mod map;
mod model;
mod nginx;
mod traefik;

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

#[derive(Debug)]
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
    let toml = emit::render(&doc, "nginx");
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
    let source = opts.source.as_str();
    match source {
        "nginx" | "traefik" | "caddy" => {}
        "" => {
            eprintln!(
                "usage: zion import <nginx|traefik|caddy> <path|-> [-o zion.toml] [--report file] [--strict] [--var KEY=VALUE]... [--acme-email EMAIL]"
            );
            return 1;
        }
        other => {
            eprintln!(
                "zion import: unsupported source '{other}' (supported: nginx, traefik, caddy)"
            );
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

    let converted = match source {
        "traefik" => traefik::convert(
            &src,
            base_dir.as_deref(),
            &opts.vars,
            opts.acme_email.as_deref(),
        ),
        "caddy" => caddy::convert(
            &src,
            base_dir.as_deref(),
            &opts.vars,
            opts.acme_email.as_deref(),
        ),
        _ => convert(&src, base_dir.as_deref()),
    };
    let conversion = match converted {
        Ok(c) => c,
        Err(ConvertError::Parse(e)) => {
            eprintln!("zion import: {input}: {e}");
            return 1;
        }
        Err(ConvertError::NoRoutes(findings)) => {
            eprint!("{}", report_text(&findings, true, source));
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
        if let Err(e) = std::fs::write(path, report_text(&conversion.findings, true, source)) {
            eprintln!("zion import: cannot write report {path}: {e} — nothing emitted");
            return 1;
        }
    }

    match &opts.output {
        Some(path) => {
            // Atomic replace: `-o` is routinely pointed at the live zion.toml when
            // migrating a proxy, exactly when a torn write hurts most.
            if let Err(e) = crate::atomic_file::write_atomic_config(
                std::path::Path::new(path),
                conversion.toml.as_bytes(),
            ) {
                eprintln!("zion import: cannot write {path}: {e}");
                return 1;
            }
            eprintln!("wrote {path}");
        }
        None => print!("{}", conversion.toml),
    }

    // Findings that need eyes go to stderr; the full log went to --report.
    eprint!("{}", report_text(&conversion.findings, false, source));

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
fn report_text(findings: &[Finding], full: bool, source: &str) -> String {
    let count = |s: Status| findings.iter().filter(|f| f.status == s).count();
    let mut out = String::new();
    out.push_str(&format!(
        "zion import {source}: {} findings — {} convert, {} partial, {} auto, {} unsupported\n",
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
                panic!(
                    "{name}: no routes; findings:\n{}",
                    report_text(&f, true, "nginx")
                )
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
        // `proxy_set_header Host $host` → the upstream forwards the client's Host, and is
        // probed with the vhost's name (#485)
        assert!(has_finding(
            &c,
            Status::Convert,
            "proxy_set_header",
            "Host $host"
        ));
        assert!(c.toml.contains("preserve_host = true"), "{}", c.toml);
        assert!(
            c.toml.contains("health_host = \"app.example.com\""),
            "{}",
            c.toml
        );
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
        // proxy_read_timeout → request_timeout_ms, with the semantic delta stated.
        assert!(c.toml.contains("request_timeout_ms = 300000"), "{}", c.toml);
        assert!(has_finding(
            &c,
            Status::Partial,
            "proxy_read_timeout",
            "request_timeout_ms = 300000"
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
        // `location = /healthz` would be a dead route (zion answers /healthz itself): it is
        // dropped and reported, not emitted
        assert!(!c.toml.contains("path = \"/healthz\""), "{}", c.toml);
        assert!(has_finding(
            &c,
            Status::Partial,
            "location",
            "/healthz itself"
        ));
        assert!(has_finding(
            &c,
            Status::Partial,
            "location",
            "route dropped"
        ));
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
        // The SPA `location /` (inherited `root` + `try_files … /index.html`)
        // now converts to a mode=static catch-all (ADR-0015); /api still proxies.
        assert_eq!(c.toml.matches("[[route]]").count(), 2);
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/var/www/spa/dist\""));
        assert!(c.toml.contains("spa_fallback = true"));
        // try_files CONVERTS now — it is no longer an unsupported product edge.
        assert!(has_finding(&c, Status::Convert, "try_files", "mode=static"));
        // The /api proxy_pass URI part is still dropped loudly.
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_pass",
            "URI part"
        ));
        assert!(c.toml.contains("# UNSUPPORTED: proxy_pass URI part"));
        // `/assets/` carries only expires/access_log (no static signal, no
        // proxy) — still skipped; the catch-all serves it at runtime.
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "location",
            "no convertible proxy target"
        ));
    }

    // ── 3a-nginx: root/try_files/index/alias → mode=static (ADR-0015) ────────
    // Draconian, deterministic matrix. `conv_ok` converts an inline server and
    // returns the single static route it produced (asserting there is exactly
    // one), so each test pins serve_dir/spa_fallback exactly.

    fn conv_ok(src: &str) -> Conversion {
        convert(src, None).unwrap_or_else(|e| panic!("convert failed: {e:?}"))
    }

    #[test]
    fn static_spa_catch_all_from_inherited_root() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /var/www/app;\n  \
             location / { try_files $uri $uri/ /index.html; }\n}",
        );
        assert!(c.toml.contains("path = \"/{*rest}\""));
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/var/www/app\""));
        assert!(c.toml.contains("spa_fallback = true"));
        assert!(has_finding(&c, Status::Convert, "try_files", "mode=static"));
    }

    #[test]
    fn static_try_files_404_has_no_spa_fallback() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /srv;\n  \
             location / { try_files $uri =404; }\n}",
        );
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/srv\""));
        assert!(!c.toml.contains("spa_fallback"));
    }

    #[test]
    fn static_subpath_root_joins_the_location_prefix() {
        // nginx `root` appends the whole URI; Zion strips the route prefix — so
        // serve_dir must be root + prefix to serve the same files.
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location /assets/ { root /srv/app; try_files $uri =404; }\n}",
        );
        assert!(c.toml.contains("path = \"/assets/{*rest}\""));
        assert!(c.toml.contains("serve_dir = \"/srv/app/assets\""));
    }

    #[test]
    fn static_alias_maps_to_serve_dir_directly() {
        // `alias` already strips the prefix (like Zion), so serve_dir = alias.
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location /dl/ { alias /data/files/; }\n}",
        );
        assert!(c.toml.contains("path = \"/dl/{*rest}\""));
        assert!(c.toml.contains("serve_dir = \"/data/files\""));
        assert!(has_finding(&c, Status::Convert, "alias", "mode=static"));
    }

    #[test]
    fn static_local_root_overrides_inherited() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /inherited;\n  \
             location / { root /local; try_files $uri /index.html; }\n}",
        );
        assert!(c.toml.contains("serve_dir = \"/local\""));
        assert!(!c.toml.contains("/inherited"));
    }

    #[test]
    fn static_unresolved_root_variable_is_unsupported() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location / { root /www/$host; try_files $uri /index.html; }\n  \
             location /api/ { proxy_pass http://127.0.0.1:9000; }\n}",
        );
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "root",
            "unresolved variable"
        ));
        assert!(!c.toml.contains("mode = \"static\""));
        // the proxy route still converts
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
    }

    #[test]
    fn static_named_fallback_is_partial_without_spa() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /srv;\n  \
             location / { try_files $uri $uri/ @app; }\n}",
        );
        assert!(c.toml.contains("mode = \"static\""));
        assert!(!c.toml.contains("spa_fallback"));
        assert!(has_finding(
            &c,
            Status::Partial,
            "try_files",
            "named location"
        ));
    }

    #[test]
    fn static_custom_index_is_partial() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location / { root /srv; index main.html; }\n}",
        );
        assert!(c.toml.contains("mode = \"static\""));
        assert!(!c.toml.contains("spa_fallback"));
        assert!(has_finding(&c, Status::Partial, "index", "index.html"));
    }

    #[test]
    fn static_autoindex_is_partial() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location /files/ { root /srv; autoindex on; }\n}",
        );
        assert!(c.toml.contains("path = \"/files/{*rest}\""));
        assert!(has_finding(
            &c,
            Status::Partial,
            "autoindex",
            "directory listing"
        ));
    }

    #[test]
    fn static_exact_match_location_is_unsupported() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location = /favicon.ico { root /srv; }\n  \
             location /api/ { proxy_pass http://127.0.0.1:9000; }\n}",
        );
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "location",
            "exact-match static"
        ));
        assert!(!c.toml.contains("mode = \"static\""));
    }

    #[test]
    fn static_server_root_unused_by_proxy_only_is_reported() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /never/served;\n  \
             location / { proxy_pass http://127.0.0.1:9000; }\n}",
        );
        assert!(!c.toml.contains("mode = \"static\""));
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "root",
            "no static location uses it"
        ));
    }

    #[test]
    fn static_and_proxy_coexist_in_one_server() {
        let c = conv_ok(
            "server {\n  server_name a.test;\n  root /var/www/app;\n  \
             location / { try_files $uri /index.html; }\n  \
             location /api/ { proxy_pass http://127.0.0.1:9000; }\n}",
        );
        assert_eq!(c.toml.matches("[[route]]").count(), 2);
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        assert!(c.toml.contains("upstream = \"127_0_0_1_9000\""));
    }

    #[test]
    fn static_directory_serving_without_try_files() {
        // Just `root` (+ no try_files): Zion serves index.html for the dir.
        let c = conv_ok(
            "server {\n  server_name a.test;\n  \
             location / { root /srv/site; }\n}",
        );
        assert!(c.toml.contains("mode = \"static\""));
        assert!(c.toml.contains("serve_dir = \"/srv/site\""));
        assert!(!c.toml.contains("spa_fallback"));
        assert!(has_finding(&c, Status::Convert, "root", "mode=static"));
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
        let c = convert(src, Some(&dir)).expect("convert with includes");
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
                panic!("no routes; findings:\n{}", report_text(&f, true, "nginx"))
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
    fn proxy_read_timeout_becomes_request_timeout_ms() {
        // Location overrides server, like the connect timeout.
        let c = ok("server { listen 80; proxy_read_timeout 60s; \
             location / { proxy_read_timeout 120s; proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("request_timeout_ms = 120000"), "{}", c.toml);
        assert!(!c.toml.contains("request_timeout_ms = 60000"));
        // Partial, not convert: the finding states where the two differ.
        assert!(has_finding(
            &c,
            Status::Partial,
            "proxy_read_timeout",
            "between two reads"
        ));
        // Server level alone is inherited.
        let c = ok("server { listen 80; proxy_read_timeout 45s; \
             location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("request_timeout_ms = 45000"), "{}", c.toml);
        // Without the directive nothing is emitted: the default applies.
        let c = ok("server { listen 80; location / { proxy_pass http://127.0.0.1:1; } }");
        assert!(!c.toml.contains("request_timeout_ms"));
    }

    #[test]
    fn a_read_timeout_zion_cannot_express_is_not_emitted() {
        // 0 and anything past the 1 h connection cap are refused by the config: the importer
        // must say so instead of emitting a config that fails its own validation.
        for bad in ["0", "2h", "soon"] {
            let c = ok(&format!(
                "server {{ listen 80; location / {{ proxy_read_timeout {bad}; \
                 proxy_pass http://127.0.0.1:1; }} }}"
            ));
            assert!(!c.toml.contains("request_timeout_ms"), "{bad}: {}", c.toml);
            assert!(
                has_finding(
                    &c,
                    Status::Unsupported,
                    "proxy_read_timeout",
                    "default 30 s"
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn proxy_send_timeout_points_at_request_timeout_ms() {
        let c = ok("server { listen 80; location / { proxy_send_timeout 90s; \
             proxy_pass http://127.0.0.1:1; } }");
        assert!(
            !c.toml.contains("request_timeout_ms"),
            "nothing is invented from it"
        );
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_send_timeout",
            "request_timeout_ms"
        ));
    }

    #[test]
    fn two_locations_on_one_upstream_keep_the_first_read_timeout() {
        let c = ok("server { listen 80; \
             location /a/ { proxy_read_timeout 10s; proxy_pass http://127.0.0.1:1; } \
             location /b/ { proxy_read_timeout 99s; proxy_pass http://127.0.0.1:1; } }");
        assert!(c.toml.contains("request_timeout_ms = 10000"), "{}", c.toml);
        assert!(!c.toml.contains("request_timeout_ms = 99000"));
        // The one that is not applied is named, not dropped in silence.
        assert!(has_finding(
            &c,
            Status::Partial,
            "proxy_read_timeout",
            "request_timeout_ms = 10000 kept (the first), 99000 not applied"
        ));
        // Same for the connect timeout, which shares the mechanism.
        let c = ok("server { listen 80; \
             location /a/ { proxy_connect_timeout 1s; proxy_pass http://127.0.0.1:1; } \
             location /b/ { proxy_connect_timeout 9s; proxy_pass http://127.0.0.1:1; } }");
        assert!(has_finding(
            &c,
            Status::Partial,
            "proxy_connect_timeout",
            "connect_timeout_ms = 1000 kept (the first), 9000 not applied"
        ));
        // Equal values are not a conflict.
        let c = ok("server { listen 80; \
             location /a/ { proxy_read_timeout 10s; proxy_pass http://127.0.0.1:1; } \
             location /b/ { proxy_read_timeout 10s; proxy_pass http://127.0.0.1:1; } }");
        assert!(!has_finding(
            &c,
            Status::Partial,
            "proxy_read_timeout",
            "not applied"
        ));
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

    // ── IP access rules (allow / deny) — #483 ──────────────────────────────

    fn conv(src: &str) -> Conversion {
        match convert(src, None) {
            Ok(c) => c,
            Err(e) => panic!("convert failed: {e:?}"),
        }
    }

    /// The `[[route]]` block whose `path = "<path>"`, as text.
    fn route_block<'a>(toml: &'a str, path: &str) -> &'a str {
        let needle = format!("path = \"{path}\"");
        let at = toml
            .find(&needle)
            .unwrap_or_else(|| panic!("no route {path} in:\n{toml}"));
        let start = toml[..at].rfind("[[route]]").expect("route header");
        let end = toml[at..].find("\n\n").map_or(toml.len(), |e| at + e);
        &toml[start..end]
    }

    fn server(locations: &str, server_rules: &str) -> String {
        format!(
            "events {{}}\nhttp {{\n  upstream app {{ server 10.1.2.3:8000; }}\n  server {{\n    \
             listen 80;\n    server_name api.example.com;\n    {server_rules}\n    \
             location / {{ proxy_pass http://app; }}\n    {locations}\n  }}\n}}\n"
        )
    }

    /// The `[upstream.<name>]` block, as text.
    fn upstream_block<'a>(toml: &'a str, name: &str) -> &'a str {
        let needle = format!("[upstream.{name}]\n");
        let start = toml
            .find(&needle)
            .unwrap_or_else(|| panic!("no upstream {name} in:\n{toml}"));
        let end = toml[start..].find("\n\n").map_or(toml.len(), |e| start + e);
        &toml[start..end]
    }

    #[test]
    fn proxy_set_header_host_maps_to_preserve_host() {
        for (value, preserve) in [
            ("$http_host", true),
            ("$host", true),
            ("$proxy_host", false),
        ] {
            let c = conv(&server("", &format!("proxy_set_header Host {value};")));
            let up = upstream_block(&c.toml, "app");
            assert_eq!(
                up.contains("preserve_host = true"),
                preserve,
                "{value}: {up}"
            );
            if preserve {
                assert!(up.contains("health_host = \"api.example.com\""), "{up}");
                assert!(has_finding(
                    &c,
                    Status::Convert,
                    "proxy_set_header",
                    "preserve_host"
                ));
            } else {
                assert!(has_finding(
                    &c,
                    Status::Auto,
                    "proxy_set_header",
                    "$proxy_host"
                ));
            }
        }
        // a fixed Host is not something Zion can send
        let c = conv(&server("", "proxy_set_header Host backend.internal;"));
        assert!(!c.toml.contains("preserve_host"), "{}", c.toml);
        assert!(has_finding(
            &c,
            Status::Unsupported,
            "proxy_set_header",
            "backend.internal"
        ));
    }

    #[test]
    fn a_location_with_its_own_headers_does_not_inherit_the_host_and_splits_the_upstream() {
        // nginx replace-not-merge: /ws sets headers of its own, none of them Host, so it
        // sends the upstream's address while / forwards the client's Host
        let c = conv(&server(
            "location /ws { proxy_set_header Upgrade $http_upgrade; proxy_pass http://app; }",
            "proxy_set_header Host $host;",
        ));
        assert!(
            route_block(&c.toml, "/{*rest}").contains("upstream = \"app_host\""),
            "{}",
            c.toml
        );
        assert!(
            route_block(&c.toml, "/ws/{*rest}").contains("upstream = \"app\""),
            "{}",
            c.toml
        );
        assert!(upstream_block(&c.toml, "app_host").contains("preserve_host = true"));
        assert!(!upstream_block(&c.toml, "app").contains("preserve_host"));
        assert!(
            upstream_block(&c.toml, "app_host").contains("url = \"http://10.1.2.3:8000\""),
            "the copy keeps the endpoints"
        );
        assert!(has_finding(&c, Status::Convert, "upstream app", "app_host"));
    }

    #[test]
    fn health_host_is_a_concrete_name_or_reported_missing() {
        let wild = "events {}\nhttp {\n  upstream app { server 10.1.2.3:8000; }\n  server {\n    \
                    listen 80;\n    server_name *.example.com;\n    proxy_set_header Host $host;\n    \
                    location / { proxy_pass http://app; }\n  }\n}\n";
        let c = conv(wild);
        let up = upstream_block(&c.toml, "app");
        assert!(
            up.contains("preserve_host = true") && !up.contains("health_host"),
            "{up}"
        );
        assert!(has_finding(
            &c,
            Status::Convert,
            "upstream app",
            "set health_host"
        ));
    }

    #[test]
    fn finding_texts_have_no_runs_of_spaces() {
        // a `\` line continuation lost in an edit leaves the next line's indentation inside the
        // string ("…/metrics                      is not reachable"): catch it for every finding
        let c = conv(&server(
            "location /metrics { proxy_pass http://app; } \
             location /a { allow 10.0.0.0/8; deny all; proxy_pass http://app; } \
             location /b { allow 203.0.113.0/24; deny all; proxy_pass http://app; } \
             location /c { deny 198.51.100.7; allow all; proxy_pass http://app; } \
             location /d { deny all; proxy_pass http://app; }",
            "",
        ));
        for f in &c.findings {
            assert!(!f.detail.contains("  "), "double space in: {:?}", f.detail);
        }
    }

    #[test]
    fn private_only_allow_then_deny_all_becomes_internal_only() {
        // the certmate-ng shape: RFC 1918 ranges + loopback, then deny all
        let c = conv(&server(
            "location /admin { allow 10.0.0.0/8; allow 172.16.0.0/12; allow 192.168.0.0/16; \
             allow 127.0.0.1; deny all; proxy_pass http://app; }",
            "",
        ));
        let r = route_block(&c.toml, "/admin/{*rest}");
        assert!(r.contains("internal_only = true"), "{r}");
        assert!(
            has_finding(&c, Status::Convert, "allow", "internal_only"),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
        // the catch-all next to it stays open
        assert!(!route_block(&c.toml, "/{*rest}").contains("internal_only"));
    }

    #[test]
    fn a_narrower_internal_allow_list_is_partial_and_says_how_to_narrow() {
        let c = conv(&server(
            "location /ops { allow 10.0.0.0/8; deny all; proxy_pass http://app; }",
            "",
        ));
        assert!(route_block(&c.toml, "/ops/{*rest}").contains("internal_only = true"));
        assert!(
            has_finding(
                &c,
                Status::Partial,
                "allow",
                "admits ALL of Zion's internal networks"
            ) && has_finding(
                &c,
                Status::Partial,
                "allow",
                "internal_networks = [\"10.0.0.0/8\"]"
            ),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
        assert!(
            !has_finding(&c, Status::Convert, "allow", "internal_only"),
            "not claimed as faithful"
        );
    }

    #[test]
    fn an_allow_list_with_public_addresses_fails_closed() {
        let c = conv(&server(
            "location /partner { allow 10.0.0.0/8; allow 203.0.113.0/24; deny all; proxy_pass http://app; }",
            "",
        ));
        assert!(
            route_block(&c.toml, "/partner/{*rest}").contains("internal_only = true"),
            "never an open route"
        );
        assert!(
            has_finding(&c, Status::Partial, "allow", "203.0.113.0/24")
                && has_finding(&c, Status::Partial, "allow", "internal_networks"),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
    }

    #[test]
    fn a_cidr_that_only_starts_inside_an_internal_network_fails_closed() {
        // 10.0.0.0/7 = 10.0.0.0-11.255.255.255: half of it is public
        let c = conv(&server(
            "location /x { allow 10.0.0.0/7; deny all; proxy_pass http://app; }",
            "",
        ));
        assert!(route_block(&c.toml, "/x/{*rest}").contains("internal_only = true"));
        assert!(
            has_finding(&c, Status::Partial, "allow", "10.0.0.0/7"),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
    }

    #[test]
    fn a_block_list_stays_open_and_is_reported() {
        let c = conv(&server(
            "location /blog { deny 198.51.100.7; allow all; proxy_pass http://app; }",
            "",
        ));
        assert!(!route_block(&c.toml, "/blog/{*rest}").contains("internal_only"));
        assert!(
            has_finding(&c, Status::Unsupported, "deny", "198.51.100.7"),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
    }

    #[test]
    fn deny_all_alone_is_closed_to_the_outside() {
        let c = conv(&server(
            "location /secret { deny all; proxy_pass http://app; }",
            "",
        ));
        assert!(route_block(&c.toml, "/secret/{*rest}").contains("internal_only = true"));
        assert!(
            has_finding(&c, Status::Partial, "deny", "internal networks"),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
    }

    #[test]
    fn server_rules_are_inherited_unless_the_location_has_its_own() {
        let c = conv(&server(
            "location /inherits { proxy_pass http://app; } \
             location /opens { allow all; proxy_pass http://app; }",
            "allow 10.0.0.0/8; deny all;",
        ));
        assert!(route_block(&c.toml, "/inherits/{*rest}").contains("internal_only = true"));
        assert!(
            route_block(&c.toml, "/{*rest}").contains("internal_only = true"),
            "location / inherits too"
        );
        assert!(
            !route_block(&c.toml, "/opens/{*rest}").contains("internal_only"),
            "replace, not merge"
        );
    }

    #[test]
    fn a_static_location_keeps_its_restriction() {
        let c = conv(&server(
            "location /files/ { allow 192.168.0.0/16; deny all; root /srv/www; }",
            "",
        ));
        let r = route_block(&c.toml, "/files/{*rest}");
        assert!(
            r.contains("serve_dir") && r.contains("internal_only = true"),
            "{r}"
        );
    }

    #[test]
    fn a_route_on_a_built_in_endpoint_is_reported() {
        let c = conv(&server("location /metrics { proxy_pass http://app; }", ""));
        assert!(
            has_finding(
                &c,
                Status::Partial,
                "location",
                "Zion answers /metrics itself"
            ),
            "{}",
            report_text(&c.findings, true, "nginx")
        );
        // an ordinary path is not flagged
        let c = conv(&server("location /api { proxy_pass http://app; }", ""));
        assert!(!c
            .findings
            .iter()
            .any(|f| f.detail.contains("answers") && f.detail.contains("itself")));
    }
}
