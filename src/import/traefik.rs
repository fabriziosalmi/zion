//! Traefik (Docker-provider compose labels) → `ZionDoc` (ADR-0012, stage 2).
//!
//! Second front-end of `zion import`, sharing the nginx path's neutral seam:
//! this module only *builds* a [`ZionDoc`] and a list of [`Finding`]s; the
//! rendering, self-validation and reporting live in `emit`/`mod` and are not
//! touched. The one shared change is that `emit::render` now takes the source
//! name so the generated header is honest about where the config came from.
//!
//! It is deliberately NOT a Traefik configuration engine. Traefik's dynamic
//! configuration for the Docker provider is expressed as container labels, and
//! its static configuration as CLI flags on the Traefik service's `command`.
//! We read exactly the label families the real fleet uses and refuse — loudly,
//! as an `unsupported` finding — on anything else, per ADR-0011's honesty
//! contract. A silently mis-mapped label becomes a silently wrong route, which
//! is the whole failure mode the findings report exists to prevent.
//!
//! ## The finding that matters most
//!
//! `--providers.docker=true` maps to `auto`, but it is the single biggest
//! semantic delta of the whole migration and is written first in the report:
//! Zion has no service discovery, so the routes are *frozen at import time*. A
//! container added to the compose stack later is not exposed until the import
//! is re-run. Everything else is detail next to that.
//!
//! ## The environment-variable precondition
//!
//! `zion.toml` does not expand `${VAR}`. Real compose files write
//! `` Host(`${DOMAIN:-localhost}`) `` and `--certificatesresolvers.le.acme.email=${ACME_EMAIL}`,
//! so an unresolved variable surviving to emission would fail `self_validate`
//! and surface as an "importer bug" — the worst possible message for the most
//! mundane cause. Variables are therefore resolved at import time from a `.env`
//! next to the compose file plus `--var KEY=VALUE`; an unresolved variable is a
//! named `unsupported` finding, never an invented value and never a crash.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::map::{RouteOut, UpstreamOut, ZionDoc};
use super::{compose, emit, Conversion, ConvertError, Finding, Status};

/// Placeholder cert paths, mirroring the nginx path's convention (map.rs):
/// schema validation does not require the files to exist, so a TLS route
/// validates and `:443` binds; the operator supplies the real cert (or
/// `[tls.acme]`). Kept local so the nginx mapper stays untouched.
const PLACEHOLDER_CERT: &str = "/etc/ssl/zion/zion.crt";
const PLACEHOLDER_KEY: &str = "/etc/ssl/zion/zion.key";

/// Convert a Traefik-labelled docker-compose file into a validated zion.toml.
///
/// `base_dir` locates the adjacent `.env` (compose convention); `cli_vars`
/// are `--var KEY=VALUE` overrides that win over `.env`.
pub(super) fn convert(
    src: &str,
    base_dir: Option<&Path>,
    cli_vars: &[(String, String)],
) -> Result<Conversion, ConvertError> {
    let file = compose::parse(src)
        .map_err(|e| ConvertError::Parse(format!("line {}: {}", e.line, e.msg)))?;
    let env = Env::load(base_dir, cli_vars);

    let mut findings = Vec::new();
    let doc = build(&file, &env, &mut findings);
    findings.sort_by_key(|f| f.line);

    if doc.routes.is_empty() {
        return Err(ConvertError::NoRoutes(findings));
    }

    let toml = emit::render(&doc, "traefik");
    emit::self_validate(&toml).map_err(|e| {
        ConvertError::Internal(format!(
            "emitted config failed self-validation — this is an importer bug, \
             please report it: {e}"
        ))
    })?;
    Ok(Conversion { toml, findings })
}

// ── Environment-variable resolution ───────────────────────────────────────

/// Resolved variables: `.env` values overlaid by `--var` overrides.
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
                        map.insert(k.trim().to_string(), strip_quotes(v.trim()).to_string());
                    }
                }
            }
        }
        // --var wins over .env.
        for (k, v) in cli_vars {
            map.insert(k.clone(), v.clone());
        }
        Env { map }
    }

    /// Expand a single `${...}` body: `NAME`, `NAME:-default`, `NAME-default`,
    /// `NAME:?msg`, `NAME?msg`. Returns `None` when the variable is required
    /// (plain or `:?`) but unset/empty — the caller turns that into a finding.
    fn expand(&self, spec: &str) -> Option<String> {
        let name_end = spec
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(spec.len());
        let name = &spec[..name_end];
        let rest = &spec[name_end..];
        let set = self.map.get(name).filter(|v| !v.is_empty()).cloned();
        if rest.is_empty() {
            return set;
        }
        if let Some(default) = rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-')) {
            return Some(set.unwrap_or_else(|| default.to_string()));
        }
        if rest.starts_with(":?") || rest.starts_with('?') {
            return set; // required; None → finding
        }
        // `:+` and anything exotic: best-effort, treat as the bare value.
        set
    }
}

/// The `NAME` part of a `${...}` body, for the finding message.
fn var_name(spec: &str) -> &str {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(spec.len());
    &spec[..end]
}

/// Interpolate every `${...}` in `raw`. On an unresolved variable, push one
/// `unsupported` finding (named, with the input line) and return `None` so the
/// caller drops the route rather than emitting a wrong one.
fn interpolate(
    raw: &str,
    env: &Env,
    line: u32,
    ctx: &str,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut ok = true;
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut inner = String::new();
            let mut closed = false;
            for d in chars.by_ref() {
                if d == '}' {
                    closed = true;
                    break;
                }
                inner.push(d);
            }
            if !closed {
                // Unterminated `${` — leave literal rather than guess.
                out.push_str("${");
                out.push_str(&inner);
                continue;
            }
            match env.expand(&inner) {
                Some(v) => out.push_str(&v),
                None => {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        line,
                        format!("{ctx}: ${{{inner}}}"),
                        format!(
                            "unresolved variable — pass `--var {n}=…` or set it in .env",
                            n = var_name(&inner)
                        ),
                    ));
                    ok = false;
                }
            }
            continue;
        }
        out.push(c);
    }
    if ok {
        Some(out)
    } else {
        None
    }
}

/// Soft interpolation for non-routing static flags (e.g. the ACME e-mail used
/// only in a finding message): unresolved variables are left literal instead
/// of failing the import.
fn interpolate_soft(raw: &str, env: &Env) -> String {
    let mut dropped = Vec::new();
    interpolate(raw, env, 0, "", &mut dropped).unwrap_or_else(|| raw.to_string())
}

fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// ── Build ─────────────────────────────────────────────────────────────────

#[derive(Default)]
struct StaticCfg {
    acme_email: Option<String>,
}

fn build(file: &compose::ComposeFile, env: &Env, findings: &mut Vec<Finding>) -> ZionDoc {
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
        waf_body_mb: None,
        upstreams: Vec::new(),
        routes: Vec::new(),
    };

    let statics = parse_static(file, env, &mut doc, findings);

    let mut seen_upstreams: BTreeSet<String> = BTreeSet::new();
    for svc in &file.services {
        if is_traefik_service(svc) {
            continue;
        }
        let routing = collect_routing(svc, findings);
        if routing.enable != Some(true) {
            // Matches `--providers.docker.exposedbydefault=false`: only
            // explicitly-enabled containers are routed.
            continue;
        }
        for (rname, r) in &routing.routers {
            build_route(
                svc,
                rname,
                r,
                &routing,
                &statics,
                env,
                &mut doc,
                &mut seen_upstreams,
                findings,
            );
        }
    }
    doc
}

/// Parse the Traefik service's static CLI flags (its compose `command`).
fn parse_static(
    file: &compose::ComposeFile,
    env: &Env,
    doc: &mut ZionDoc,
    findings: &mut Vec<Finding>,
) -> StaticCfg {
    let mut cfg = StaticCfg::default();
    let Some(svc) = file.services.iter().find(|s| is_traefik_service(s)) else {
        return cfg;
    };
    let mut logged_log = false;
    let mut logged_redirect = false;
    for flag in &svc.command {
        let flag = flag.trim_start_matches('-');
        let (key, val) = match flag.split_once('=') {
            Some((k, v)) => (k, v),
            None => (flag, ""),
        };
        match key {
            "providers.docker" if val == "true" => findings.push(Finding::new(
                Status::Auto,
                svc.line,
                "--providers.docker",
                "Zion has no service discovery — routes are frozen at import time; a \
                 container added to the stack later is not exposed until you re-run the import",
            )),
            "providers.docker.exposedbydefault" => findings.push(Finding::new(
                Status::Auto,
                svc.line,
                "--providers.docker.exposedbydefault",
                "only services with `traefik.enable=true` are imported",
            )),
            "api.insecure" | "api.dashboard" if val == "true" => findings.push(Finding::new(
                Status::Unsupported,
                svc.line,
                format!("--{key}"),
                "Zion has no admin dashboard — drop it",
            )),
            _ if key.starts_with("entrypoints.") && key.ends_with(".address") => {
                apply_entrypoint(key, val, doc);
            }
            _ if !logged_redirect
                && key.starts_with("entrypoints.")
                && key.contains(".redirections.") =>
            {
                findings.push(Finding::new(
                    Status::Auto,
                    svc.line,
                    "--entrypoints.*.redirections",
                    "HTTP→HTTPS redirect is built in when TLS is configured",
                ));
                logged_redirect = true;
            }
            _ if key.starts_with("certificatesresolvers.") && key.ends_with(".acme.email") => {
                cfg.acme_email = Some(interpolate_soft(val, env));
            }
            _ if !logged_log && (key.starts_with("log.") || key == "log") => {
                findings.push(Finding::new(
                    Status::Auto,
                    svc.line,
                    "--log",
                    "structured JSON logging to stdout is built in",
                ));
                logged_log = true;
            }
            _ => {} // Operational flags with no routing meaning are ignored.
        }
    }
    cfg
}

/// Map `--entrypoints.<name>.address=:PORT` onto Zion's two listeners by the
/// ubiquitous `web`/`websecure` convention.
fn apply_entrypoint(key: &str, val: &str, doc: &mut ZionDoc) {
    let name = key
        .trim_start_matches("entrypoints.")
        .trim_end_matches(".address");
    let addr = if let Some(port) = val.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        val.to_string()
    };
    match name {
        "web" => doc.listen_http = addr,
        "websecure" => doc.listen_https = addr,
        _ => {} // Non-standard entrypoint names: leave the defaults.
    }
}

// ── Dynamic labels ────────────────────────────────────────────────────────

#[derive(Default)]
struct Routing {
    enable: Option<bool>,
    routers: BTreeMap<String, Router>,
    /// Traefik-service-name → (port, line).
    ports: BTreeMap<String, (String, u32)>,
}

#[derive(Default)]
struct Router {
    rule: Option<(String, u32)>,
    tls: bool,
    tls_line: u32,
    certresolver: Option<(String, u32)>,
    service: Option<String>,
}

fn collect_routing(svc: &compose::Service, findings: &mut Vec<Finding>) -> Routing {
    let mut r = Routing::default();
    for label in &svc.labels {
        let line = label.line;
        let Some(rest) = label.key.strip_prefix("traefik.") else {
            continue; // not a Traefik label
        };
        if rest == "enable" {
            r.enable = Some(label.value == "true");
        } else if let Some(spec) = rest.strip_prefix("http.routers.") {
            let Some((name, prop)) = spec.split_once('.') else {
                continue;
            };
            let router = r.routers.entry(name.to_string()).or_default();
            match prop {
                "rule" => router.rule = Some((label.value.clone(), line)),
                "tls" => {
                    router.tls = label.value == "true";
                    router.tls_line = line;
                }
                "tls.certresolver" => router.certresolver = Some((label.value.clone(), line)),
                "service" => router.service = Some(label.value.clone()),
                "entrypoints" => {} // Zion serves both listeners; informational only.
                "middlewares" => findings.push(Finding::new(
                    Status::Partial,
                    line,
                    format!("routers.{name}.middlewares"),
                    "middleware chain referenced — see the per-middleware findings; \
                     rate-limit maps to the global [server], strip-prefix is unsupported",
                )),
                other => findings.push(Finding::new(
                    Status::Unsupported,
                    line,
                    format!("routers.{name}.{other}"),
                    "unrecognised router property",
                )),
            }
        } else if let Some(spec) = rest.strip_prefix("http.services.") {
            if let Some((name, prop)) = spec.split_once('.') {
                if prop == "loadbalancer.server.port" {
                    r.ports
                        .insert(name.to_string(), (label.value.clone(), line));
                } else {
                    findings.push(Finding::new(
                        Status::Partial,
                        line,
                        format!("services.{name}.{prop}"),
                        "only loadbalancer.server.port is converted",
                    ));
                }
            }
        } else if let Some(spec) = rest.strip_prefix("http.middlewares.") {
            let kind = spec.split('.').nth(1).unwrap_or("");
            let (status, detail) = match kind {
                "ratelimit" => (
                    Status::Partial,
                    "per-route rate limit → Zion only has a global [server].rate_limit_rps",
                ),
                "stripprefix" | "stripprefixregex" => {
                    (Status::Unsupported, "path rewriting has no Zion equivalent")
                }
                _ => (Status::Unsupported, "middleware has no Zion equivalent"),
            };
            findings.push(Finding::new(
                status,
                line,
                format!("middlewares.{}", spec.split('.').next().unwrap_or(spec)),
                detail,
            ));
        } else if rest.starts_with("tcp.") || rest.starts_with("udp.") {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                "tcp/udp router",
                "Zion is an L7 proxy — L4 routing is out of scope",
            ));
        }
        // Other `traefik.*` keys (docker.network, etc.) are operational: ignored.
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn build_route(
    svc: &compose::Service,
    rname: &str,
    router: &Router,
    routing: &Routing,
    statics: &StaticCfg,
    env: &Env,
    doc: &mut ZionDoc,
    seen_upstreams: &mut BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    let Some((rule_raw, rule_line)) = &router.rule else {
        findings.push(Finding::new(
            Status::Unsupported,
            svc.line,
            format!("routers.{rname}"),
            "router has no rule — nothing to match on",
        ));
        return;
    };
    let rule_line = *rule_line;

    let Some(parsed) = parse_rule(rule_raw, rule_line, env, findings) else {
        return; // findings already recorded; drop the route
    };

    if parsed.acme_challenge {
        findings.push(Finding::new(
            Status::Auto,
            rule_line,
            format!("routers.{rname}"),
            "ACME HTTP-01 challenge is answered in memory by Zion before routing — router dropped",
        ));
        return;
    }

    let Some(port) = resolve_port(routing, rname, router, env, findings) else {
        findings.push(Finding::new(
            Status::Unsupported,
            svc.line,
            format!("routers.{rname}"),
            format!(
                "no `loadbalancer.server.port` for service '{}' — cannot build an upstream",
                svc.name
            ),
        ));
        return;
    };

    let up_name = sanitize_name(&svc.name);
    if seen_upstreams.insert(up_name.clone()) {
        doc.upstreams.push(UpstreamOut {
            name: up_name.clone(),
            urls: vec![format!("http://{}:{}", svc.name, port)],
            connect_timeout_ms: None,
            keepalive: None,
        });
    }

    // TLS is a listener concern in Zion; a placeholder cert lets :443 bind.
    if let Some((resolver, cl)) = &router.certresolver {
        let email = statics.acme_email.as_deref().unwrap_or("you@example.com");
        findings.push(Finding::new(
            Status::Partial,
            *cl,
            format!("routers.{rname}.tls.certresolver={resolver}"),
            format!(
                "Traefik ACME → Zion emits a placeholder cert. For automatic HTTPS add \
                 [tls.acme] (email = \"{email}\", domains = the route hosts) or run `zion init`; \
                 if the origin is a certificate manager, point [tls] at its cert instead"
            ),
        ));
    } else if router.tls {
        findings.push(Finding::new(
            Status::Partial,
            router.tls_line,
            format!("routers.{rname}.tls=true"),
            "TLS enabled at the entrypoint — Zion emits a placeholder cert; set [tls] \
             cert_path/key_path or [tls.acme], or run `zion init`",
        ));
    }

    let path = to_zion_path(&parsed.path);
    findings.push(Finding::new(
        Status::Convert,
        rule_line,
        format!("routers.{rname}"),
        format!("→ route {path} upstream '{up_name}'"),
    ));
    doc.routes.push(RouteOut {
        path,
        hosts: if parsed.hosts.is_empty() {
            None
        } else {
            Some(parsed.hosts)
        },
        upstream: up_name,
        websocket: false,
        csp: None,
        waf: false,
        annotations: Vec::new(),
    });
}

/// Resolve the upstream port for a router: its `.service` override, else the
/// service named after the router, else the container's sole port.
fn resolve_port(
    routing: &Routing,
    rname: &str,
    router: &Router,
    env: &Env,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let key = router.service.clone().unwrap_or_else(|| rname.to_string());
    let (raw, line) = routing.ports.get(&key).or_else(|| {
        if routing.ports.len() == 1 {
            routing.ports.values().next()
        } else {
            None
        }
    })?;
    interpolate(raw, env, *line, "loadbalancer.server.port", findings)
}

// ── Rule parsing ──────────────────────────────────────────────────────────

enum PathKind {
    CatchAll,
    Prefix(String),
    Exact(String),
}

struct RuleParse {
    hosts: Vec<String>,
    path: PathKind,
    acme_challenge: bool,
}

/// Parse a Traefik router rule into hosts + a single path matcher. Only
/// `Host`, `PathPrefix` and `Path` (combined with `&&`/`||`) are understood;
/// any other matcher (regex, `Query`, `Header`, `HostRegexp`, …) drops the
/// whole route with an `unsupported` finding rather than converting it wrong.
fn parse_rule(rule: &str, line: u32, env: &Env, findings: &mut Vec<Finding>) -> Option<RuleParse> {
    let mut hosts = Vec::new();
    let mut path = PathKind::CatchAll;
    let mut acme_challenge = false;

    // Combinators only join matchers in the target corpus; splitting on them is
    // sufficient (no nested boolean groups appear in real fleet rules).
    let normalized = rule.replace("&&", "\u{1}").replace("||", "\u{1}");
    for token in normalized.split('\u{1}') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some((func, args)) = parse_matcher(token) else {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                format!("rule: {token}"),
                "unsupported Traefik matcher — only Host/PathPrefix/Path convert",
            ));
            return None;
        };
        match func.as_str() {
            "Host" | "HostSNI" => {
                for a in args {
                    hosts.push(interpolate(&a, env, line, "rule: Host", findings)?);
                }
            }
            "PathPrefix" => {
                let p = interpolate(args.first()?, env, line, "rule: PathPrefix", findings)?;
                if p.contains("/.well-known/acme-challenge") {
                    acme_challenge = true;
                }
                path = PathKind::Prefix(p);
            }
            "Path" => {
                path = PathKind::Exact(interpolate(
                    args.first()?,
                    env,
                    line,
                    "rule: Path",
                    findings,
                )?);
            }
            other => {
                findings.push(Finding::new(
                    Status::Unsupported,
                    line,
                    format!("rule: {other}(…)"),
                    "unsupported Traefik matcher — only Host/PathPrefix/Path convert",
                ));
                return None;
            }
        }
    }
    Some(RuleParse {
        hosts,
        path,
        acme_challenge,
    })
}

/// Split `Func(`a`, `b`)` into the function name and its backtick/quote-stripped
/// arguments. Returns `None` on anything that is not a `name(...)` call.
fn parse_matcher(token: &str) -> Option<(String, Vec<String>)> {
    let open = token.find('(')?;
    if !token.ends_with(')') {
        return None;
    }
    let func = token[..open].trim().to_string();
    if func.is_empty() || !func.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let inner = &token[open + 1..token.len() - 1];
    let args = inner
        .split(',')
        .map(|a| {
            a.trim()
                .trim_matches('`')
                .trim_matches('"')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();
    Some((func, args))
}

fn to_zion_path(p: &PathKind) -> String {
    match p {
        PathKind::CatchAll => "/{*rest}".to_string(),
        PathKind::Prefix(s) => {
            let base = if s == "/" {
                ""
            } else {
                s.trim_end_matches('/')
            };
            format!("{base}/{{*rest}}")
        }
        PathKind::Exact(s) => s.clone(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn is_traefik_service(svc: &compose::Service) -> bool {
    let Some(image) = &svc.image else {
        return false;
    };
    let repo = image
        .split(['@', ':'])
        .next()
        .unwrap_or(image)
        .rsplit('/')
        .next()
        .unwrap_or("");
    repo == "traefik"
}

/// A Zion upstream name keys a `[upstream.NAME]` table, so a dot would nest it.
/// Compose service names are almost always clean; flatten the rest.
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
        convert(src, None, &cli)
    }

    // ── variable resolution ──

    #[test]
    fn expand_plain_default_and_required() {
        let e = env(&[("SET", "v")]);
        assert_eq!(e.expand("SET"), Some("v".to_string()));
        assert_eq!(e.expand("UNSET"), None);
        assert_eq!(e.expand("UNSET:-fallback"), Some("fallback".to_string()));
        assert_eq!(e.expand("SET:-fallback"), Some("v".to_string()));
        assert_eq!(e.expand("UNSET:?must be set"), None);
        assert_eq!(e.expand("UNSET-bare"), Some("bare".to_string()));
    }

    #[test]
    fn interpolate_reports_unresolved_with_name_and_line() {
        let e = env(&[]);
        let mut f = Vec::new();
        assert_eq!(
            interpolate("a.${MISSING}.b", &e, 42, "rule: Host", &mut f),
            None
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].status, Status::Unsupported);
        assert_eq!(f[0].line, 42);
        assert!(f[0].detail.contains("--var MISSING="));
    }

    #[test]
    fn interpolate_embeds_resolved_value() {
        let e = env(&[("DOMAIN", "example.com")]);
        let mut f = Vec::new();
        assert_eq!(
            interpolate("api.${DOMAIN}", &e, 1, "x", &mut f),
            Some("api.example.com".to_string())
        );
        assert!(f.is_empty());
    }

    // ── rule parsing ──

    fn hosts_of(rule: &str, e: &Env) -> Option<Vec<String>> {
        let mut f = Vec::new();
        parse_rule(rule, 1, e, &mut f).map(|p| p.hosts)
    }

    #[test]
    fn host_or_host_collects_both() {
        let got = hosts_of("Host(`a.io`) || Host(`b.io`)", &env(&[]));
        assert_eq!(got, Some(vec!["a.io".to_string(), "b.io".to_string()]));
    }

    #[test]
    fn host_and_pathprefix_splits_host_from_path() {
        let mut f = Vec::new();
        let p = parse_rule("Host(`a.io`) && PathPrefix(`/api`)", 1, &env(&[]), &mut f).unwrap();
        assert_eq!(p.hosts, vec!["a.io".to_string()]);
        assert_eq!(to_zion_path(&p.path), "/api/{*rest}");
    }

    #[test]
    fn pathprefix_alone_has_no_host() {
        let mut f = Vec::new();
        let p = parse_rule("PathPrefix(`/api`)", 1, &env(&[]), &mut f).unwrap();
        assert!(p.hosts.is_empty());
        assert_eq!(to_zion_path(&p.path), "/api/{*rest}");
    }

    #[test]
    fn path_is_exact() {
        let mut f = Vec::new();
        let p = parse_rule("Path(`/health`)", 1, &env(&[]), &mut f).unwrap();
        assert_eq!(to_zion_path(&p.path), "/health");
    }

    #[test]
    fn unsupported_matcher_drops_the_route() {
        let mut f = Vec::new();
        assert!(parse_rule("Host(`a`) && Query(`x=1`)", 7, &env(&[]), &mut f).is_none());
        assert!(f
            .iter()
            .any(|x| x.status == Status::Unsupported && x.line == 7));
    }

    #[test]
    fn acme_challenge_router_is_flagged() {
        let mut f = Vec::new();
        let p = parse_rule(
            "Host(`a.io`) && PathPrefix(`/.well-known/acme-challenge`)",
            1,
            &env(&[]),
            &mut f,
        )
        .unwrap();
        assert!(p.acme_challenge);
    }

    #[test]
    fn host_variable_resolves_from_var() {
        let got = hosts_of("Host(`${DOMAIN:-localhost}`)", &env(&[]));
        assert_eq!(got, Some(vec!["localhost".to_string()]));
        let got = hosts_of(
            "Host(`${DOMAIN:-localhost}`)",
            &env(&[("DOMAIN", "prod.io")]),
        );
        assert_eq!(got, Some(vec!["prod.io".to_string()]));
    }

    // ── end to end ──

    const HTTP_ONLY: &str = r#"
services:
  traefik:
    image: traefik:v3.3
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
  api:
    image: myapi:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=Host(`a.io`) || Host(`b.io`)"
      - "traefik.http.routers.api.entrypoints=web"
      - "traefik.http.services.api.loadbalancer.server.port=8000"
"#;

    #[test]
    fn http_only_stack_converts_and_validates() {
        let c = convert_str(HTTP_ONLY, &[]).expect("should convert");
        assert!(c.toml.contains("[upstream.api]"));
        assert!(c.toml.contains("http://api:8000"));
        assert!(c.toml.contains("hosts = [\"a.io\", \"b.io\"]"));
        assert!(c.toml.contains("upstream = \"api\""));
        // finding-titolo present
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Auto && f.directive.contains("providers.docker")));
        // header names the source
        assert!(c.toml.contains("zion import traefik"));
    }

    #[test]
    fn unresolved_host_variable_yields_no_routes() {
        // No --var, no .env: ${PUBLIC_FQDN} cannot resolve → the only route is
        // dropped → NoRoutes with a named finding.
        let src = HTTP_ONLY.replace("Host(`a.io`) || Host(`b.io`)", "Host(`${PUBLIC_FQDN}`)");
        match convert_str(&src, &[]) {
            Err(ConvertError::NoRoutes(f)) => {
                assert!(f
                    .iter()
                    .any(|x| x.status == Status::Unsupported && x.detail.contains("PUBLIC_FQDN")));
            }
            other => panic!("expected NoRoutes, got {:?}", other.map(|c| c.toml)),
        }
    }

    #[test]
    fn var_override_resolves_the_host() {
        let src = HTTP_ONLY.replace("Host(`a.io`) || Host(`b.io`)", "Host(`${PUBLIC_FQDN}`)");
        let c = convert_str(&src, &[("PUBLIC_FQDN", "app.example.com")]).expect("should convert");
        assert!(c.toml.contains("hosts = [\"app.example.com\"]"));
    }

    #[test]
    fn tls_certresolver_is_partial_not_silent() {
        let src = r#"
services:
  traefik:
    image: traefik:v3.3
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.le.acme.email=ops@example.com"
  fe:
    image: myfe:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.fe.rule=Host(`app.io`)"
      - "traefik.http.routers.fe.entrypoints=websecure"
      - "traefik.http.routers.fe.tls.certresolver=le"
      - "traefik.http.services.fe.loadbalancer.server.port=3000"
"#;
        let c = convert_str(src, &[]).expect("should convert");
        let tls = c
            .findings
            .iter()
            .find(|f| f.directive.contains("certresolver"))
            .expect("certresolver finding");
        assert_eq!(tls.status, Status::Partial);
        assert!(tls.detail.contains("ops@example.com"));
        assert!(c.toml.contains("http://fe:3000"));
    }

    #[test]
    fn service_without_enable_is_skipped() {
        let src = HTTP_ONLY.replace("\"traefik.enable=true\"", "\"traefik.enable=false\"");
        // The only routed service is now disabled → nothing to emit.
        assert!(matches!(
            convert_str(&src, &[]),
            Err(ConvertError::NoRoutes(_))
        ));
    }

    // ── golden corpus (anonymized fleet shapes) ──

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/import/traefik")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    #[test]
    fn golden_http_only() {
        let c = convert(&fixture("http-only.yml"), None, &[]).expect("convert");
        assert!(c.toml.contains("[upstream.app]"));
        assert!(c.toml.contains("http://app:8000"));
        assert!(c
            .toml
            .contains("hosts = [\"a.example.com\", \"b.example.com\"]"));
        assert!(c.toml.contains("# Generated by `zion import traefik`"));
    }

    #[test]
    fn golden_tls_default_host_defaults_and_tls_is_partial() {
        let c = convert(&fixture("tls-default.yml"), None, &[]).expect("convert");
        assert!(c.toml.contains("http://web:8080"));
        assert!(c.toml.contains("hosts = [\"localhost\"]"));
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Partial && f.directive.contains("tls=true")));
        // The two redirection flags collapse to a single auto finding.
        assert_eq!(
            c.findings
                .iter()
                .filter(|f| f.directive.contains("redirections"))
                .count(),
            1
        );
    }

    #[test]
    fn golden_acme_converts_with_vars() {
        let vars = [
            ("PUBLIC_FQDN".to_string(), "app.example.com".to_string()),
            ("ACME_EMAIL".to_string(), "ops@example.com".to_string()),
        ];
        let c = convert(&fixture("acme-certresolver.yml"), None, &vars).expect("convert");
        assert!(c.toml.contains("[upstream.frontend]") && c.toml.contains("http://frontend:3000"));
        assert!(c.toml.contains("[upstream.backend]") && c.toml.contains("http://backend:8000"));
        assert!(c.toml.contains("path = \"/api/{*rest}\""));
        // certresolver → partial, twice, echoing the discovered ACME email.
        let partials: Vec<_> = c
            .findings
            .iter()
            .filter(|f| f.directive.contains("certresolver"))
            .collect();
        assert_eq!(partials.len(), 2);
        assert!(partials
            .iter()
            .all(|f| f.status == Status::Partial && f.detail.contains("ops@example.com")));
        // the /.well-known/acme-challenge router is dropped as `auto`.
        assert!(c
            .findings
            .iter()
            .any(|f| f.status == Status::Auto && f.directive.contains("api-acme")));
    }

    #[test]
    fn golden_acme_without_vars_refuses() {
        match convert(&fixture("acme-certresolver.yml"), None, &[]) {
            Err(ConvertError::NoRoutes(f)) => {
                assert!(f.iter().any(|x| x.detail.contains("PUBLIC_FQDN")))
            }
            other => panic!("expected NoRoutes, got {:?}", other.map(|c| c.toml)),
        }
    }

    #[test]
    fn golden_label_without_service_refuses() {
        match convert(&fixture("label-without-service.yml"), None, &[]) {
            Err(ConvertError::NoRoutes(f)) => {
                assert!(f.iter().any(|x| x.status == Status::Unsupported
                    && x.detail.contains("loadbalancer.server.port")))
            }
            other => panic!("expected NoRoutes, got {:?}", other.map(|c| c.toml)),
        }
    }

    #[test]
    fn dot_env_next_to_file_is_read() {
        // `.env` is read from base_dir (compose convention). Write a throwaway
        // stack + `.env` to a temp dir and confirm the host resolves from it.
        let dir = std::env::temp_dir().join(format!("zion-traefik-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let compose = HTTP_ONLY.replace("Host(`a.io`) || Host(`b.io`)", "Host(`${SITE}`)");
        std::fs::write(dir.join(".env"), "SITE=env.example.com\n").unwrap();
        let c = convert(&compose, Some(dir.as_path()), &[]).expect("convert via .env");
        assert!(c.toml.contains("hosts = [\"env.example.com\"]"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
