//! nginx model → Zion document (ADR-0011 stage 3).
//!
//! Implements the normative mapping contract from ADR-0011: every directive
//! ends in exactly one finding bucket (convert / partial / auto /
//! unsupported), and anything Zion cannot express faithfully becomes a loud
//! finding — never a best-effort guess. The emitted `ZionDoc` is pure data;
//! rendering and self-validation live in `emit`.

use std::collections::HashMap;

use super::model::{LocMod, Location, NginxModel, Pool, Server};
use super::nginx::Directive;
use super::{Finding, Status};

// ── Output document ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ZionDoc {
    pub listen_http: String,
    pub listen_https: String,
    pub rate_limit: Option<(u32, u64)>,
    pub max_conn_per_ip: Option<u32>,
    pub trusted_proxies: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub tls_min12: bool,
    pub sni: Vec<SniOut>,
    /// Emit a `[tls.acme]` block for automatic HTTPS. The bootstrap cert stays
    /// in `tls_cert`/`tls_key`; populated by the Traefik/Caddy front-ends when
    /// the source uses ACME and a contact e-mail is known.
    pub acme: Option<AcmeOut>,
    pub waf_body_mb: Option<u64>,
    pub upstreams: Vec<UpstreamOut>,
    pub routes: Vec<RouteOut>,
}

#[derive(Debug)]
pub struct SniOut {
    pub server_name: String,
    pub cert: String,
    pub key: String,
}

#[derive(Debug)]
pub struct AcmeOut {
    pub email: String,
    pub domains: Vec<String>,
}

#[derive(Debug)]
pub struct UpstreamOut {
    pub name: String,
    pub urls: Vec<String>,
    pub connect_timeout_ms: Option<u64>,
    pub keepalive: Option<u64>,
}

#[derive(Debug)]
pub struct RouteOut {
    pub path: String,
    pub hosts: Option<Vec<String>>,
    pub upstream: String,
    pub websocket: bool,
    pub csp: Option<String>,
    /// Attach the shared `imported` WAF profile (body cap) in shadow mode.
    pub waf: bool,
    /// `mode = "static"` serve directory (ADR-0015). When `Some`, the route
    /// serves files from disk instead of proxying and `upstream` is ignored.
    pub serve_dir: Option<String>,
    /// SPA fallback for a static route (serve `index.html` on a miss).
    pub spa_fallback: bool,
    /// Rendered as `# UNSUPPORTED: …` comment lines above the route.
    pub annotations: Vec<String>,
}

/// Placeholder cert paths, following the `zion suggest` convention: schema
/// validation does not require the files to exist; the operator fills them in.
const PLACEHOLDER_CERT: &str = "/etc/ssl/zion/zion.crt";
const PLACEHOLDER_KEY: &str = "/etc/ssl/zion/zion.key";

// ── Entry point ─────────────────────────────────────────────────────────

pub fn map_model(model: &NginxModel, findings: &mut Vec<Finding>) -> ZionDoc {
    let mut doc = ZionDoc {
        listen_http: String::new(),
        listen_https: String::new(),
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

    // 1. Classify servers: drop the canonical :80→https redirect pair member,
    //    resolve hosts, apply the all-names-invalid hijack guard.
    let mut kept: Vec<(&Server, Option<Vec<String>>)> = Vec::new();
    for server in &model.servers {
        match redirect_server_kind(server) {
            RedirectKind::SameHost301 => {
                findings.push(Finding::new(
                    Status::Auto,
                    server.line,
                    "server",
                    "http→https same-host redirect server — built into Zion's :80 \
                     handler; dropped",
                ));
                continue;
            }
            RedirectKind::SameHostOtherCode => {
                findings.push(Finding::new(
                    Status::Partial,
                    server.line,
                    "server",
                    "http→https same-host redirect server dropped — note nginx used \
                     302/307/308, Zion's built-in redirect is a 301",
                ));
                continue;
            }
            RedirectKind::No => {}
        }
        match server_hosts(server, findings) {
            HostsOutcome::Skip => continue,
            HostsOutcome::Shared => kept.push((server, None)),
            HostsOutcome::Hosts(h) => {
                // default_server on a NAMED server: nginx sends unmatched
                // hosts here; in Zion they fall to the shared layer instead.
                if let Some(l) = server.listens.iter().find(|l| l.default_server) {
                    findings.push(Finding::new(
                        Status::Partial,
                        l.line,
                        "listen",
                        "default_server on a named server — unmatched hosts fall \
                         through to Zion's shared (hostless) routes, not to this server",
                    ));
                }
                kept.push((server, Some(h)));
            }
        }
    }

    // 1b. Scope deltas the hostless-as-shared mapping cannot avoid — state
    //     them loudly (ADR-0011 honesty contract).
    let has_named = kept.iter().any(|(_, h)| h.is_some());
    for (s, h) in &kept {
        if h.is_none() && has_named && !s.locations.is_empty() {
            findings.push(Finding::new(
                Status::Partial,
                s.line,
                "server",
                "default-vhost routes become hostless SHARED routes: nginx served \
                 them only for unmatched Hosts, but Zion's shared layer is also the \
                 path-miss fallback under every named host — internal endpoints \
                 parked here become reachable via all hostnames; review",
            ));
        }
    }
    // The same host in several server blocks: nginx sends ALL of that host's
    // traffic to the first block; Zion merges the route sets.
    {
        let mut seen_hosts: Vec<&str> = Vec::new();
        let mut flagged: Vec<&str> = Vec::new();
        for (s, h) in &kept {
            for host in h.as_deref().unwrap_or(&[]) {
                if seen_hosts.contains(&host.as_str()) {
                    if !flagged.contains(&host.as_str()) {
                        flagged.push(host);
                        findings.push(Finding::new(
                            Status::Partial,
                            s.line,
                            "server_name",
                            format!(
                                "host '{host}' appears in more than one server block — \
                                 nginx routes all its traffic to the first block only; \
                                 Zion merges the blocks' routes under this host"
                            ),
                        ));
                    }
                } else {
                    seen_hosts.push(host);
                }
            }
        }
    }

    // 2. Plain-HTTP servers: Zion always terminates TLS — one global finding.
    let plain: Vec<u32> = kept
        .iter()
        .filter(|(s, _)| !server_is_tls(s))
        .map(|(s, _)| s.line)
        .collect();
    if !plain.is_empty() {
        findings.push(Finding::new(
            Status::Partial,
            plain[0],
            "server",
            format!(
                "{} plain-HTTP server(s) (line {}): Zion always terminates TLS — \
                 port 80 serves only the redirect to HTTPS; review the synthesized \
                 certificate paths before deploying",
                plain.len(),
                plain
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        ));
    }

    map_listens(&kept, &mut doc, findings);
    map_tls(&kept, &mut doc, findings);

    // 3. Upstream registry: named pools + upstreams synthesized from direct
    //    proxy_pass authorities, deduplicated by URL.
    let mut reg = UpstreamReg::new(&model.pools);

    // 4. Servers → routes, collecting global aggregates on the way.
    let mut agg = Aggregates::default();
    for (server, hosts) in &kept {
        map_server(
            server,
            hosts.as_deref(),
            &mut doc,
            &mut reg,
            &mut agg,
            findings,
            model,
        );
    }

    finish_aggregates(&agg, model, &mut doc, findings);
    doc.upstreams = reg.finish(model, findings);
    doc
}

// ── Server classification ───────────────────────────────────────────────

/// Legacy `ssl on;` (nginx < 1.15) marks every listener of the server as TLS.
fn ssl_on(server: &Server) -> bool {
    server
        .directives
        .iter()
        .any(|d| d.name == "ssl" && d.args.first().map(String::as_str) == Some("on"))
}

/// TLS server = any `listen … ssl` flag, or the legacy server-level `ssl on;`.
fn server_is_tls(server: &Server) -> bool {
    server.listens.iter().any(|l| l.ssl) || ssl_on(server)
}

enum RedirectKind {
    /// `return 301 https://$host$request_uri` (or `$server_name`/`$http_host`)
    /// on a plain server with no locations — exactly Zion's built-in behavior.
    SameHost301,
    /// Same shape but 302/307/308 — droppable, with the code delta stated.
    SameHostOtherCode,
    No,
}

/// The canonical redirect pair member. The target must be a SAME-HOST
/// redirect: a cross-host target (`https://new.example.com$request_uri`, a
/// domain migration) is NOT equivalent to Zion's :80 handler, which redirects
/// to the original request host — those servers are kept so their `return`
/// surfaces as an unsupported finding instead of being silently rewritten
/// into a self-redirect.
fn redirect_server_kind(server: &Server) -> RedirectKind {
    if server_is_tls(server) || !server.locations.is_empty() {
        return RedirectKind::No;
    }
    const SAME_HOST_TARGETS: [&str; 3] = [
        "https://$host$request_uri",
        "https://$server_name$request_uri",
        "https://$http_host$request_uri",
    ];
    for d in &server.directives {
        if d.name != "return" {
            continue;
        }
        let code = d.args.first().map(String::as_str);
        let target = d.args.get(1).map(String::as_str).unwrap_or("");
        if SAME_HOST_TARGETS.contains(&target) {
            match code {
                Some("301") => return RedirectKind::SameHost301,
                Some("302") | Some("307") | Some("308") => return RedirectKind::SameHostOtherCode,
                _ => {}
            }
        }
    }
    RedirectKind::No
}

enum HostsOutcome {
    Shared,
    Hosts(Vec<String>),
    Skip,
}

/// Map `server_name` forms per ADR-0011: exact and `*.domain` convert,
/// `.domain` expands to apex + wildcard, `_`/empty mean the shared layer, and
/// regex or embedded-wildcard names are dropped. A server whose names ALL
/// dropped is skipped entirely: emitting its routes hostless would hijack the
/// shared layer.
fn server_hosts(server: &Server, findings: &mut Vec<Finding>) -> HostsOutcome {
    if server.names.is_empty() {
        return HostsOutcome::Shared;
    }
    let line = server.names_line;
    let mut hosts: Vec<String> = Vec::new();
    let mut catchall = false;
    let mut dropped = 0usize;
    for raw in &server.names {
        let name = raw.to_ascii_lowercase();
        if name == "_" || name.is_empty() {
            catchall = true;
            continue;
        }
        if name.starts_with('~') {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                "server_name",
                format!("regex server_name '{raw}' — Zion hosts are exact or `*.domain`"),
            ));
            dropped += 1;
            continue;
        }
        if let Some(domain) = name.strip_prefix("*.") {
            if valid_bare_host(domain) {
                hosts.push(name.clone());
            } else {
                findings.push(bad_name(line, raw));
                dropped += 1;
            }
            continue;
        }
        if let Some(domain) = name.strip_prefix('.') {
            // nginx `.example.com` = apex AND all subdomains.
            if valid_bare_host(domain) {
                findings.push(Finding::new(
                    Status::Convert,
                    line,
                    "server_name",
                    format!("'.{domain}' expanded to '{domain}' + '*.{domain}'"),
                ));
                hosts.push(domain.to_string());
                hosts.push(format!("*.{domain}"));
            } else {
                findings.push(bad_name(line, raw));
                dropped += 1;
            }
            continue;
        }
        if valid_bare_host(&name) {
            hosts.push(name);
        } else {
            findings.push(bad_name(line, raw));
            dropped += 1;
        }
    }
    hosts.dedup();
    if hosts.is_empty() {
        if catchall {
            return HostsOutcome::Shared;
        }
        if dropped > 0 {
            findings.push(Finding::new(
                Status::Unsupported,
                server.line,
                "server",
                format!(
                    "every server_name was unconvertible — the whole server block \
                     ({} listen(s), {} location(s) and their directives) is skipped: \
                     emitting its routes hostless would capture traffic for all hosts",
                    server.listens.len(),
                    server.locations.len(),
                ),
            ));
            return HostsOutcome::Skip;
        }
        return HostsOutcome::Shared;
    }
    if catchall {
        findings.push(Finding::new(
            Status::Partial,
            line,
            "server_name",
            "'_' listed together with real names — the catch-all part is dropped; \
             unmatched hosts fall through to Zion's shared layer",
        ));
    }
    findings.push(Finding::new(
        Status::Convert,
        line,
        "server_name",
        format!("hosts = [{}]", hosts.join(", ")),
    ));
    HostsOutcome::Hosts(hosts)
}

fn bad_name(line: u32, raw: &str) -> Finding {
    Finding::new(
        Status::Unsupported,
        line,
        "server_name",
        format!("'{raw}' is not a bare hostname or `*.domain` wildcard"),
    )
}

/// Conservative bare-hostname check mirroring `config::validate_host_entry`'s
/// domain: lowercase letters/digits/dots/hyphens, no empty labels. (The final
/// gate is `validate_semantics` on the emitted config; this filter exists so
/// junk input becomes an honest finding instead of an internal-bug abort.)
fn valid_bare_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

// ── Listen mapping ──────────────────────────────────────────────────────

fn map_listens(
    kept: &[(&Server, Option<Vec<String>>)],
    doc: &mut ZionDoc,
    findings: &mut Vec<Finding>,
) {
    let mut http_port: Option<u16> = None;
    let mut https_port: Option<u16> = None;
    for (server, _) in kept {
        // Legacy `ssl on;` upgrades every listener of this server to TLS.
        let forced_tls = ssl_on(server);
        for l in &server.listens {
            let tls = l.ssl || forced_tls;
            let (host_part, port) = match split_listen(&l.addr, tls) {
                Some(hp) => hp,
                None => {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        l.line,
                        "listen",
                        format!("cannot map listen address '{}'", l.addr),
                    ));
                    continue;
                }
            };
            if let Some(h) = host_part {
                if h != "0.0.0.0" && h != "*" && h != "[::]" {
                    findings.push(Finding::new(
                        Status::Partial,
                        l.line,
                        "listen",
                        format!("nginx bound to {h}; Zion listens on 0.0.0.0 — narrow with a firewall if needed"),
                    ));
                }
            }
            let (slot, label) = if tls {
                (&mut https_port, "https")
            } else {
                (&mut http_port, "http")
            };
            match slot {
                None => {
                    *slot = Some(port);
                    findings.push(Finding::new(
                        Status::Convert,
                        l.line,
                        "listen",
                        format!("server.listen_{label} = \"0.0.0.0:{port}\""),
                    ));
                }
                Some(p) if *p == port => findings.push(Finding::new(
                    Status::Convert,
                    l.line,
                    "listen",
                    format!("port {port} (already mapped)"),
                )),
                Some(p) => findings.push(Finding::new(
                    Status::Unsupported,
                    l.line,
                    "listen",
                    format!(
                        "Zion has a single {} listener (:{p} already taken) — port {port} not mapped",
                        if tls { "HTTPS" } else { "HTTP" }
                    ),
                )),
            }
            for flag in &l.flags {
                let f = flag.as_str();
                if f == "http2" {
                    findings.push(Finding::new(
                        Status::Auto,
                        l.line,
                        "listen",
                        "http2 — negotiated via ALPN by default",
                    ));
                } else if f == "reuseport"
                    || f == "deferred"
                    || f.starts_with("backlog=")
                    || f.starts_with("so_keepalive=")
                    || f.starts_with("fastopen=")
                {
                    findings.push(Finding::new(
                        Status::Auto,
                        l.line,
                        "listen",
                        format!("{f} — Zion tunes its own listener"),
                    ));
                } else {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        l.line,
                        "listen",
                        format!("flag '{f}' not mapped"),
                    ));
                }
            }
        }
    }
    doc.listen_http = format!("0.0.0.0:{}", http_port.unwrap_or(80));
    doc.listen_https = format!("0.0.0.0:{}", https_port.unwrap_or(443));
}

/// `80` → (None, 80) · `1.2.3.4:8080` → (Some host, 8080) · `[::]:443` →
/// (Some "[::]", 443) · bare address → default port by context.
fn split_listen(addr: &str, ssl: bool) -> Option<(Option<String>, u16)> {
    if addr.starts_with("unix:") {
        return None;
    }
    if let Ok(port) = addr.parse::<u16>() {
        return Some((None, port));
    }
    let default_port = if ssl { 443 } else { 80 };
    if let Some(rest) = addr.strip_prefix('[') {
        // IPv6 literal: [::]:443 or [::]
        let end = rest.find(']')?;
        let host = format!("[{}]", &rest[..end]);
        let after = &rest[end + 1..];
        if let Some(p) = after.strip_prefix(':') {
            return Some((Some(host), p.parse().ok()?));
        }
        return Some((Some(host), default_port));
    }
    match addr.rfind(':') {
        Some(i) => {
            let port = addr[i + 1..].parse().ok()?;
            Some((Some(addr[..i].to_string()), port))
        }
        None => Some((Some(addr.to_string()), default_port)),
    }
}

// ── TLS mapping ─────────────────────────────────────────────────────────

fn map_tls(
    kept: &[(&Server, Option<Vec<String>>)],
    doc: &mut ZionDoc,
    findings: &mut Vec<Finding>,
) {
    struct CertEntry {
        cert: String,
        key: String,
        line: u32,
        exact: Vec<String>,
        wildcard: Vec<String>,
    }
    let mut entries: Vec<CertEntry> = Vec::new();

    for (server, hosts) in kept {
        let mut cert = None;
        let mut key = None;
        let mut line = server.line;
        for d in &server.directives {
            match d.name.as_str() {
                "ssl_certificate" => {
                    if cert.is_some() {
                        findings.push(Finding::new(
                            Status::Partial,
                            d.line,
                            "ssl_certificate",
                            "multiple certificate pairs (RSA+ECDSA dual-cert?) — first pair kept",
                        ));
                    } else if let Some(p) = d.args.first() {
                        cert = Some(p.clone());
                        line = d.line;
                    }
                }
                "ssl_certificate_key" => {
                    if key.is_none() {
                        key = d.args.first().cloned();
                    }
                }
                "ssl_protocols" => {
                    // Exactly ONE finding per directive (report contract).
                    let protos: Vec<&str> = d.args.iter().map(String::as_str).collect();
                    let legacy = protos.iter().any(|p| *p == "TLSv1" || *p == "TLSv1.1");
                    let v12 = protos.contains(&"TLSv1.2");
                    let v13 = protos.contains(&"TLSv1.3");
                    if legacy {
                        // Floor as low as Zion goes so 1.2 clients keep working.
                        doc.tls_min12 = true;
                        findings.push(Finding::new(
                            Status::Partial,
                            d.line,
                            "ssl_protocols",
                            "TLS 1.0/1.1 requested — Zion's floor is 1.2; emitted \
                             min_version = \"1.2\"",
                        ));
                    } else if v12 {
                        doc.tls_min12 = true;
                        findings.push(Finding::new(
                            Status::Convert,
                            d.line,
                            "ssl_protocols",
                            "tls.min_version = \"1.2\"",
                        ));
                    } else if v13 {
                        findings.push(Finding::new(
                            Status::Convert,
                            d.line,
                            "ssl_protocols",
                            "TLS 1.3-only is Zion's default",
                        ));
                    } else {
                        findings.push(Finding::new(
                            Status::Unsupported,
                            d.line,
                            "ssl_protocols",
                            format!(
                                "no supported protocol in [{}] — Zion emits its \
                                 default (TLS 1.3)",
                                protos.join(", ")
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
        match (cert, key) {
            (Some(cert), Some(key)) => {
                let mut exact = Vec::new();
                let mut wildcard = Vec::new();
                for h in hosts.as_deref().unwrap_or(&[]) {
                    if h.starts_with("*.") {
                        wildcard.push(h.clone());
                    } else {
                        exact.push(h.clone());
                    }
                }
                entries.push(CertEntry {
                    cert,
                    key,
                    line,
                    exact,
                    wildcard,
                });
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => findings.push(Finding::new(
                Status::Unsupported,
                line,
                "ssl_certificate",
                "ssl_certificate without ssl_certificate_key (or vice versa) — \
                 incomplete pair ignored; placeholder paths emitted",
            )),
        }
    }

    if entries.is_empty() {
        // Placeholders already set; the plain-HTTP finding covers the why.
        return;
    }

    // Default cert: prefer a wildcard-serving pair (Zion's SNI table is
    // exact-match, so a wildcard cert only works as the default fallback);
    // otherwise the first pair seen.
    let default_idx = entries
        .iter()
        .position(|e| !e.wildcard.is_empty())
        .unwrap_or(0);
    doc.tls_cert = entries[default_idx].cert.clone();
    doc.tls_key = entries[default_idx].key.clone();
    findings.push(Finding::new(
        Status::Convert,
        entries[default_idx].line,
        "ssl_certificate",
        "default [tls] certificate pair (ssl_certificate + ssl_certificate_key)",
    ));

    let default_cert = doc.tls_cert.clone();
    let mut seen_names: Vec<String> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        for w in &e.wildcard {
            if e.cert == default_cert {
                findings.push(Finding::new(
                    Status::Convert,
                    e.line,
                    "ssl_certificate",
                    format!(
                        "wildcard '{w}' served by the default certificate (Zion's SNI \
                         table is exact-match; the default is the fallback)"
                    ),
                ));
            } else {
                findings.push(Finding::new(
                    Status::Unsupported,
                    e.line,
                    "ssl_certificate",
                    format!(
                        "a second wildcard certificate ('{w}') cannot be expressed — \
                         Zion's SNI table is exact-match with a single default fallback"
                    ),
                ));
            }
        }
        if i == default_idx && e.exact.is_empty() {
            continue;
        }
        for name in &e.exact {
            if seen_names.contains(name) {
                findings.push(Finding::new(
                    Status::Partial,
                    e.line,
                    "ssl_certificate",
                    format!("duplicate SNI entry for '{name}' — first kept"),
                ));
                continue;
            }
            seen_names.push(name.clone());
            if e.cert == default_cert && i == default_idx {
                continue; // covered by the default cert
            }
            doc.sni.push(SniOut {
                server_name: name.clone(),
                cert: e.cert.clone(),
                key: e.key.clone(),
            });
            findings.push(Finding::new(
                Status::Convert,
                e.line,
                "ssl_certificate",
                format!("[[tls.sni]] entry for '{name}'"),
            ));
        }
    }
}

// ── Upstream registry ───────────────────────────────────────────────────

struct UpstreamReg<'a> {
    pools: &'a [Pool],
    /// pool name → (scheme, connect_timeout_ms, used)
    pool_state: HashMap<String, (String, Option<u64>, bool)>,
    /// url → sanitized name (direct proxy_pass targets)
    synth: Vec<(String, String, Option<u64>)>,
}

impl<'a> UpstreamReg<'a> {
    fn new(pools: &'a [Pool]) -> Self {
        UpstreamReg {
            pools,
            pool_state: HashMap::new(),
            synth: Vec::new(),
        }
    }

    /// Resolve a proxy_pass target to an upstream name, creating a synthesized
    /// single-URL upstream when the target is a plain authority.
    fn resolve(
        &mut self,
        scheme: &str,
        target: &str,
        timeout_ms: Option<u64>,
        line: u32,
        findings: &mut Vec<Finding>,
    ) -> String {
        if self.pools.iter().any(|p| p.name == target) {
            let entry = self
                .pool_state
                .entry(target.to_string())
                .or_insert_with(|| (scheme.to_string(), timeout_ms, true));
            if entry.0 != scheme {
                findings.push(Finding::new(
                    Status::Partial,
                    line,
                    "proxy_pass",
                    format!(
                        "pool '{target}' referenced with both http and https — {} kept",
                        entry.0
                    ),
                ));
            }
            if entry.1.is_none() {
                entry.1 = timeout_ms;
            }
            return sanitize_name(target);
        }
        let url = format!("{scheme}://{target}");
        if let Some((_, name, existing_timeout)) = self.synth.iter_mut().find(|(u, _, _)| *u == url)
        {
            if existing_timeout.is_none() {
                *existing_timeout = timeout_ms;
            }
            return name.clone();
        }
        let mut name = sanitize_name(target);
        while self.name_taken(&name) {
            name.push('_');
        }
        self.synth.push((url, name.clone(), timeout_ms));
        name
    }

    fn name_taken(&self, name: &str) -> bool {
        self.synth.iter().any(|(_, n, _)| n == name)
            || self.pools.iter().any(|p| sanitize_name(&p.name) == name)
    }

    /// Emit upstream sections: pools first (input order), synthesized after.
    fn finish(self, _model: &NginxModel, findings: &mut Vec<Finding>) -> Vec<UpstreamOut> {
        let mut out = Vec::new();
        for pool in self.pools {
            let (scheme, timeout, used) = self
                .pool_state
                .get(&pool.name)
                .cloned()
                .unwrap_or_else(|| ("http".to_string(), None, false));
            if !used {
                findings.push(Finding::new(
                    Status::Auto,
                    pool.line,
                    "upstream",
                    format!(
                        "pool '{}' is not referenced by any converted route",
                        pool.name
                    ),
                ));
            }
            let mut urls = Vec::new();
            for s in &pool.servers {
                if s.addr.starts_with("unix:") {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        s.line,
                        "server",
                        format!(
                            "unix domain socket member '{}' — Zion upstreams are \
                             TCP http(s) only; member omitted",
                            s.addr
                        ),
                    ));
                    continue;
                }
                let mut down = false;
                for flag in &s.flags {
                    match flag.as_str() {
                        "down" => down = true,
                        "backup" => findings.push(Finding::new(
                            Status::Unsupported,
                            s.line,
                            "server",
                            format!(
                                "'{}' is a backup — Zion's health-gated LB has no \
                                 primary/backup tiers; included as a regular member",
                                s.addr
                            ),
                        )),
                        f => findings.push(Finding::new(
                            Status::Unsupported,
                            s.line,
                            "server",
                            format!(
                                "flag '{f}' on '{}' — Zion's LB is fixed \
                                 (health-gated lowest-latency)",
                                s.addr
                            ),
                        )),
                    }
                }
                if down {
                    findings.push(Finding::new(
                        Status::Convert,
                        s.line,
                        "server",
                        format!("'{}' marked down — omitted", s.addr),
                    ));
                } else {
                    urls.push(format!("{scheme}://{}", s.addr));
                }
            }
            for extra in &pool.extras {
                match extra.name.as_str() {
                    "least_conn" | "ip_hash" | "hash" | "random" | "sticky" => {
                        findings.push(Finding::new(
                            Status::Unsupported,
                            extra.line,
                            &extra.name,
                            "Zion's load balancing is fixed: healthiest member, lowest \
                             EWMA latency (no strategy knob)",
                        ))
                    }
                    _ => findings.push(Finding::unsupported_directive(extra)),
                }
            }
            if pool.keepalive.is_some() {
                findings.push(Finding::new(
                    Status::Convert,
                    pool.line,
                    "keepalive",
                    "upstream keepalive pool size",
                ));
            }
            if urls.is_empty() {
                findings.push(Finding::new(
                    Status::Unsupported,
                    pool.line,
                    "upstream",
                    format!("pool '{}' has no usable members — omitted", pool.name),
                ));
                continue;
            }
            out.push(UpstreamOut {
                name: sanitize_name(&pool.name),
                urls,
                connect_timeout_ms: timeout,
                keepalive: pool.keepalive,
            });
        }
        for (url, name, timeout) in self.synth {
            out.push(UpstreamOut {
                name,
                urls: vec![url],
                connect_timeout_ms: timeout,
                keepalive: None,
            });
        }
        out
    }
}

/// TOML-bare-key-safe upstream name.
fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ── Per-server mapping ──────────────────────────────────────────────────

/// Global aggregates that nginx scopes per-location but Zion holds globally.
#[derive(Default)]
struct Aggregates {
    /// Distinct (rps, window) demanded by limit_req references.
    rates: Vec<(u32, u64, u32)>,
    /// Distinct per-IP connection caps demanded by limit_conn references.
    conns: Vec<(u32, u32)>,
    /// req/conn zone names actually referenced.
    used_zones: Vec<String>,
}

/// Server-level state locations may inherit. nginx inheritance for the
/// header-array directives (`proxy_set_header`, `add_header`) is
/// REPLACE-not-merge: a location that declares any of its own inherits none
/// of the server's — the `has_*` flags carry that rule to `map_location`.
struct ServerCtx {
    csp: Option<String>,
    has_add_header: bool,
    websocket: bool,
    has_set_header: bool,
    hdr_annotations: Vec<String>,
    waf: bool,
    connect_ms: Option<u64>,
    /// Inherited docroot (`root <dir>`) that static locations serve from
    /// (ADR-0015). nginx inheritance is replace-not-merge, but a location's own
    /// `root`/`alias` simply overrides this at the location level.
    root: Option<String>,
    root_line: u32,
    /// Inherited `index`. Zion serves `index.html` for directory requests, so a
    /// non-default index becomes a partial finding when a static route uses it.
    index: Option<String>,
}

/// Classify a static location's `try_files` fallback (its last argument) into
/// `(spa_fallback, optional partial note)`. Zion's SPA fallback always serves
/// the docroot's `index.html`, so a fallback to a *different* file converts with
/// a note, a `=CODE` fallback means no SPA, and a named-location (`@name`)
/// fallback is not modeled.
fn classify_try_files(args: &[String]) -> (bool, Option<String>) {
    match args.last() {
        None => (
            false,
            Some("try_files has no fallback argument".to_string()),
        ),
        Some(last) if last.starts_with('=') => (false, None),
        Some(last) if last.starts_with('@') => (
            false,
            Some(format!(
                "try_files fallback to named location '{last}' is not modeled — \
                 no SPA fallback set"
            )),
        ),
        Some(last) if last == "/index.html" => (true, None),
        Some(last) => (
            true,
            Some(format!(
                "Zion's SPA fallback serves the docroot '/index.html', not '{last}'"
            )),
        ),
    }
}

fn map_server(
    server: &Server,
    hosts: Option<&[String]>,
    doc: &mut ZionDoc,
    reg: &mut UpstreamReg<'_>,
    agg: &mut Aggregates,
    findings: &mut Vec<Finding>,
    model: &NginxModel,
) {
    let mut ctx = ServerCtx {
        csp: None,
        has_add_header: false,
        websocket: false,
        has_set_header: false,
        hdr_annotations: Vec::new(),
        waf: false,
        connect_ms: None,
        root: None,
        root_line: 0,
        index: None,
    };

    for d in &server.directives {
        match d.name.as_str() {
            // Consumed by map_tls / redirect_server_kind.
            "ssl_certificate" | "ssl_certificate_key" | "ssl_protocols" => {}
            "client_max_body_size" => map_body_size(d, doc, &mut ctx.waf, findings),
            "set_real_ip_from" => match d.args.first() {
                Some(cidr) if valid_cidr(cidr) => {
                    if !doc.trusted_proxies.contains(cidr) {
                        doc.trusted_proxies.push(cidr.clone());
                    }
                    findings.push(Finding::new(
                        Status::Convert,
                        d.line,
                        "set_real_ip_from",
                        "server.trusted_proxies",
                    ));
                }
                Some(other) => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "set_real_ip_from",
                    format!(
                        "'{other}' is not an IP address or CIDR — not emitted \
                         (Zion would silently ignore it at runtime)"
                    ),
                )),
                None => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "set_real_ip_from",
                    "missing address",
                )),
            },
            "real_ip_header" => {
                let hdr = d.args.first().map(String::as_str).unwrap_or("");
                if hdr.eq_ignore_ascii_case("x-forwarded-for") {
                    findings.push(Finding::new(
                        Status::Convert,
                        d.line,
                        "real_ip_header",
                        "X-Forwarded-For from trusted proxies is Zion's default \
                         client-IP resolution",
                    ));
                } else {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "real_ip_header",
                        format!("'{hdr}' — Zion resolves the client IP from X-Forwarded-For only"),
                    ));
                }
            }
            "limit_req" => map_limit_req(d, agg, model, findings),
            "limit_conn" => map_limit_conn(d, agg, model, findings),
            "add_header" => {
                ctx.has_add_header = true;
                map_add_header(d, &mut ctx.csp, findings);
            }
            "proxy_set_header" => {
                // Inherited by locations that declare none of their own —
                // including the websocket idiom and the Host behavior note.
                ctx.has_set_header = true;
                classify_set_header(d, &mut ctx.websocket, &mut ctx.hdr_annotations, findings);
            }
            "proxy_connect_timeout" => {
                map_connect_timeout(d, &mut ctx.connect_ms, findings);
            }
            "ssl" => {
                if d.args.first().map(String::as_str) == Some("on") {
                    findings.push(Finding::new(
                        Status::Convert,
                        d.line,
                        "ssl",
                        "legacy `ssl on` — this server's listeners are treated as TLS",
                    ));
                } else {
                    findings.push(Finding::unsupported_directive(d));
                }
            }
            "ssl_ciphers"
            | "ssl_prefer_server_ciphers"
            | "ssl_session_cache"
            | "ssl_session_timeout"
            | "ssl_session_tickets"
            | "ssl_stapling"
            | "ssl_stapling_verify"
            | "ssl_trusted_certificate"
            | "ssl_dhparam"
            | "ssl_ecdh_curve" => {
                findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    &d.name,
                    "rustls owns cipher and session policy",
                ));
            }
            "auth_basic" | "auth_basic_user_file" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                &d.name,
                "Zion auth profiles are JWT/OIDC, not basic auth",
            )),
            // Inherited docroot context for static locations (ADR-0015). No
            // finding here: it is consumed by a static location below, or
            // reported as unused after the location loop.
            "root" => match d.args.last() {
                Some(dir) if !dir.is_empty() && !dir.contains('$') => {
                    ctx.root = Some(dir.clone());
                    ctx.root_line = d.line;
                }
                Some(_) => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "root",
                    "docroot contains an unresolved variable — not emitted",
                )),
                None => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "root",
                    "missing docroot path",
                )),
            },
            "index" => ctx.index = d.args.first().cloned(),
            "try_files" => findings.push(Finding::new(
                Status::Partial,
                d.line,
                "try_files",
                "server-level try_files is not modeled — move it into a `location` \
                 to convert it to mode=static",
            )),
            "alias" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "alias",
                "server-level alias has no location prefix to serve",
            )),
            "autoindex" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "autoindex",
                "no directory listing — Zion serves index.html or 404",
            )),
            _ => findings.push(Finding::unsupported_directive(d)),
        }
    }

    // Static locations consume the inherited `ctx.root`; a docroot that none of
    // them used is silently ignored by Zion — say so (ADR-0011 honesty).
    let route_start = doc.routes.len();
    for loc in &server.locations {
        map_location(loc, hosts, &ctx, doc, reg, agg, findings, model);
    }
    if let Some(dir) = &ctx.root {
        let used_static = doc.routes[route_start..]
            .iter()
            .any(|r| r.serve_dir.is_some());
        if !used_static {
            findings.push(Finding::new(
                Status::Unsupported,
                ctx.root_line,
                "root",
                format!("docroot '{dir}' set but no static location uses it — ignored"),
            ));
        }
    }
}

// ── Location → route ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn map_location(
    loc: &Location,
    hosts: Option<&[String]>,
    ctx: &ServerCtx,
    doc: &mut ZionDoc,
    reg: &mut UpstreamReg<'_>,
    agg: &mut Aggregates,
    findings: &mut Vec<Finding>,
    model: &NginxModel,
) {
    if loc.modifier == LocMod::Regex {
        findings.push(Finding::new(
            Status::Unsupported,
            loc.line,
            "location",
            format!(
                "regex location '{}' — Zion routes on literal paths and \
                 catch-alls only; write it as a prefix route by hand",
                loc.pattern
            ),
        ));
        return;
    }

    let mut annotations: Vec<String> = Vec::new();
    let mut proxy: Option<(String, String, Option<String>, u32)> = None; // scheme, target, uri part, line
                                                                         // Location-scoped header state — inherits from the server ONLY when the
                                                                         // location declares no directive of that family (nginx replace-not-merge).
    let mut loc_ws = false;
    let mut loc_has_set_header = false;
    let mut loc_hdr_annotations: Vec<String> = Vec::new();
    let mut loc_csp: Option<String> = None;
    let mut loc_has_add_header = false;
    let mut loc_connect: Option<u64> = None;
    let mut route_waf = ctx.waf;
    let mut static_only = Vec::new();
    // Static-serving state (ADR-0015): a location with one of these and no
    // proxy_pass becomes a mode=static route.
    let mut loc_root: Option<String> = None;
    let mut loc_alias: Option<String> = None;
    let mut loc_index: Option<String> = None;
    let mut loc_try_files: Option<(Vec<String>, u32)> = None;
    let mut loc_autoindex: Option<u32> = None;
    let mut static_bad: Option<(u32, &'static str)> = None; // unresolved/empty root|alias

    for d in &loc.directives {
        match d.name.as_str() {
            "proxy_pass" => match d.args.first() {
                Some(url) if url.contains('$') => {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "proxy_pass",
                        format!("variable target '{url}' — Zion upstreams are static"),
                    ));
                }
                Some(url) if is_unix_target(url) => {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "proxy_pass",
                        format!(
                            "unix domain socket target '{url}' — Zion upstreams \
                             are TCP http(s) only; route skipped"
                        ),
                    ));
                }
                Some(url) => match split_proxy_pass(url) {
                    Some((scheme, target, uri)) => proxy = Some((scheme, target, uri, d.line)),
                    None => findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "proxy_pass",
                        format!("cannot parse target '{url}'"),
                    )),
                },
                None => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "proxy_pass",
                    "missing target",
                )),
            },
            "proxy_set_header" => {
                loc_has_set_header = true;
                classify_set_header(d, &mut loc_ws, &mut loc_hdr_annotations, findings)
            }
            "proxy_http_version" => findings.push(Finding::new(
                Status::Auto,
                d.line,
                "proxy_http_version",
                "backend protocol is managed by Zion",
            )),
            "proxy_connect_timeout" => map_connect_timeout(d, &mut loc_connect, findings),
            "proxy_read_timeout"
            | "proxy_send_timeout"
            | "send_timeout"
            | "client_body_timeout"
            | "keepalive_timeout" => {
                findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    &d.name,
                    "only the upstream connect timeout is configurable in Zion",
                ));
            }
            "proxy_buffering" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "proxy_buffering",
                "no buffering knob — for SSE endpoints use `mode = \"sse_stream\"`",
            )),
            "add_header" => {
                loc_has_add_header = true;
                map_add_header(d, &mut loc_csp, findings);
            }
            "limit_req" => map_limit_req(d, agg, model, findings),
            "limit_conn" => map_limit_conn(d, agg, model, findings),
            "client_max_body_size" => {
                // Location-scoped cap: contributes to the shared imported profile.
                map_body_size(d, doc, &mut route_waf, findings);
            }
            // Static-serving directives: parsed into locals and resolved after
            // the loop (a mode=static route if there is no proxy target).
            "root" => {
                static_only.push(d.line);
                match d.args.last() {
                    Some(dir) if !dir.is_empty() && !dir.contains('$') => {
                        loc_root = Some(dir.clone())
                    }
                    _ => static_bad = Some((d.line, "root")),
                }
            }
            "alias" => {
                static_only.push(d.line);
                match d.args.last() {
                    Some(dir) if !dir.is_empty() && !dir.contains('$') => {
                        loc_alias = Some(dir.clone())
                    }
                    _ => static_bad = Some((d.line, "alias")),
                }
            }
            "try_files" => {
                static_only.push(d.line);
                loc_try_files = Some((d.args.clone(), d.line));
            }
            "index" => {
                static_only.push(d.line);
                loc_index = d.args.first().cloned();
            }
            "autoindex" => {
                static_only.push(d.line);
                loc_autoindex = Some(d.line);
            }
            "expires" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "expires",
                "no Cache-Control injection — set it on the backend",
            )),
            "error_page" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "error_page",
                "custom error pages are not configurable",
            )),
            "access_log" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "access_log",
                "structured access logging is configured globally via [access_log]",
            )),
            "auth_basic" | "auth_basic_user_file" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                &d.name,
                "Zion auth profiles are JWT/OIDC, not basic auth",
            )),
            "deny" | "allow" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                &d.name,
                "no per-route IP allow/deny lists (`internal_only` covers \
                 RFC1918/loopback-only routes)",
            )),
            "if" => findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "if",
                "no conditional engine by design",
            )),
            "proxy_ssl_verify" | "proxy_ssl_name" | "proxy_ssl_server_name" => {
                findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    &d.name,
                    "upstream TLS verification is not tunable per route",
                ));
            }
            _ => findings.push(Finding::unsupported_directive(d)),
        }
    }

    // ── Static location → mode=static (ADR-0015) ────────────────────────────
    // No proxy target, but an explicit static signal: serve files from disk.
    // nginx `root` appends the whole request URI while Zion strips the route
    // prefix, so `serve_dir = root joined with the location prefix` reproduces
    // the same on-disk path; `alias` already strips the prefix, so it maps to
    // `serve_dir` directly.
    let has_static_signal = loc_try_files.is_some()
        || loc_root.is_some()
        || loc_alias.is_some()
        || loc_index.is_some()
        || loc_autoindex.is_some();
    if proxy.is_none() && has_static_signal {
        if let Some((line, kind)) = static_bad {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                kind,
                "docroot is empty or contains an unresolved variable — not emitted",
            ));
            return;
        }
        if loc.modifier == LocMod::Exact {
            findings.push(Finding::new(
                Status::Unsupported,
                loc.line,
                "location",
                format!(
                    "exact-match static location '{}' is not converted — write it as \
                     a prefix `mode=static` route by hand",
                    loc.pattern
                ),
            ));
            return;
        }
        let path = match location_path(loc, findings) {
            Some(p) => p,
            None => return,
        };
        // serve_dir: `alias` maps directly; `root` (own or inherited) joins the
        // location prefix.
        let serve_dir = if let Some(alias) = &loc_alias {
            alias.trim_end_matches('/').to_string()
        } else if let Some(root) = loc_root.as_ref().or(ctx.root.as_ref()) {
            let root = root.trim_end_matches('/');
            let prefix = loc.pattern.trim_matches('/');
            if prefix.is_empty() {
                root.to_string()
            } else {
                format!("{root}/{prefix}")
            }
        } else {
            findings.push(Finding::new(
                Status::Unsupported,
                loc.line,
                "location",
                format!(
                    "'{}': static location without a resolvable `root` or `alias` — skipped",
                    loc.pattern
                ),
            ));
            return;
        };
        let (spa_fallback, tf_note) = match &loc_try_files {
            Some((args, _)) => classify_try_files(args),
            None => (false, None),
        };
        // Same collision guard as the proxy path: a duplicate (host, path) would
        // abort matchit at boot.
        let route_hosts: Option<Vec<String>> = hosts.map(|h| h.to_vec());
        let collision = doc.routes.iter().any(|r| {
            r.path == path
                && match (&r.hosts, &route_hosts) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.iter().any(|h| b.contains(h)),
                    _ => false,
                }
        });
        if collision {
            findings.push(Finding::new(
                Status::Unsupported,
                loc.line,
                "location",
                format!(
                    "'{}': duplicate path '{path}' for the same host — skipped",
                    loc.pattern
                ),
            ));
            return;
        }
        let signal = if loc_alias.is_some() {
            "alias"
        } else if loc_try_files.is_some() {
            "try_files"
        } else {
            "root"
        };
        findings.push(Finding::new(
            Status::Convert,
            loc.line,
            signal,
            format!(
                "route '{path}' → mode=static, serve_dir '{serve_dir}'{}",
                if spa_fallback { " + spa_fallback" } else { "" }
            ),
        ));
        if let Some(note) = tf_note {
            let line = loc_try_files.as_ref().map(|(_, l)| *l).unwrap_or(loc.line);
            findings.push(Finding::new(Status::Partial, line, "try_files", note));
        }
        if let Some(idx) = &loc_index {
            if idx != "index.html" {
                findings.push(Finding::new(
                    Status::Partial,
                    loc.line,
                    "index",
                    format!(
                        "Zion serves 'index.html' for directory requests; custom index \
                         '{idx}' is not honored"
                    ),
                ));
            }
        }
        if let Some(line) = loc_autoindex {
            findings.push(Finding::new(
                Status::Partial,
                line,
                "autoindex",
                "no directory listing — Zion serves index.html or 404",
            ));
        }
        // CSP inheritance follows the same replace-not-merge rule as the proxy path.
        let mut csp = if loc_has_add_header {
            loc_csp.clone()
        } else {
            ctx.csp.clone()
        };
        if let Some(v) = &csp {
            if hyper::header::HeaderValue::from_str(v).is_err() {
                findings.push(Finding::new(
                    Status::Unsupported,
                    loc.line,
                    "add_header",
                    "Content-Security-Policy value is not a valid header value — dropped",
                ));
                csp = None;
            }
        }
        doc.routes.push(RouteOut {
            path,
            hosts: route_hosts,
            upstream: String::new(),
            websocket: false,
            csp,
            waf: false,
            serve_dir: Some(serve_dir),
            spa_fallback,
            annotations: Vec::new(),
        });
        return;
    }

    let (scheme, target, uri, pline) = match proxy {
        Some(p) => p,
        None => {
            findings.push(Finding::new(
                Status::Unsupported,
                loc.line,
                "location",
                format!("'{}': no convertible proxy target — skipped", loc.pattern),
            ));
            return;
        }
    };

    // Compute the route path only now that we know a route will exist, so a
    // skipped location never gets a contradictory "converted path" finding.
    let path = match location_path(loc, findings) {
        Some(p) => p,
        None => return,
    };

    // Resolve inheritance (nginx replace-not-merge): a location with its own
    // proxy_set_header/add_header set inherits nothing from the server's.
    let websocket = if loc_has_set_header {
        loc_ws
    } else {
        ctx.websocket
    };
    let mut hdr_annotations = if loc_has_set_header {
        loc_hdr_annotations
    } else {
        ctx.hdr_annotations.clone()
    };
    annotations.append(&mut hdr_annotations);
    let mut csp = if loc_has_add_header {
        loc_csp
    } else {
        ctx.csp.clone()
    };
    // Timeouts: the location-level value overrides the server-level one.
    let connect_ms = loc_connect.or(ctx.connect_ms);

    if let Some(uri) = uri {
        // Replacing `/` with `/` under `location /` is the identity — fine.
        let noop = uri == "/" && loc.modifier == LocMod::Prefix && loc.pattern == "/";
        if !noop {
            findings.push(Finding::new(
                Status::Unsupported,
                pline,
                "proxy_pass",
                format!(
                    "URI part '{uri}' — Zion forwards the original request path \
                     unchanged (no prefix strip/replace); upstream kept authority-only"
                ),
            ));
            annotations.push(format!(
                "proxy_pass URI part '{uri}' dropped: Zion forwards the original \
                 request path unchanged"
            ));
        }
    }

    // Same (host, path) twice would fail matchit's insert at boot; catch it
    // here so it is an honest finding instead of a self-validation abort.
    let route_hosts: Option<Vec<String>> = hosts.map(|h| h.to_vec());
    let collision = doc.routes.iter().any(|r| {
        r.path == path
            && match (&r.hosts, &route_hosts) {
                (None, None) => true,
                (Some(a), Some(b)) => a.iter().any(|h| b.contains(h)),
                _ => false,
            }
    });
    if collision {
        findings.push(Finding::new(
            Status::Unsupported,
            loc.line,
            "location",
            format!(
                "'{}': duplicate path '{path}' for the same host — skipped",
                loc.pattern
            ),
        ));
        return;
    }

    if let Some(v) = &csp {
        if hyper::header::HeaderValue::from_str(v).is_err() {
            findings.push(Finding::new(
                Status::Unsupported,
                loc.line,
                "add_header",
                "Content-Security-Policy value is not a valid header value — dropped",
            ));
            csp = None;
        }
    }

    let upstream = reg.resolve(&scheme, &target, connect_ms, pline, findings);
    findings.push(Finding::new(
        Status::Convert,
        pline,
        "proxy_pass",
        format!("route '{path}' → upstream '{upstream}'"),
    ));
    if !static_only.is_empty() {
        annotations.push(
            "this location also served static content in nginx — that part needs a \
             separate static host"
                .to_string(),
        );
    }
    doc.routes.push(RouteOut {
        path,
        hosts: route_hosts,
        upstream,
        websocket,
        csp,
        waf: route_waf,
        serve_dir: None,
        spa_fallback: false,
        annotations,
    });
}

/// Location pattern → matchit path (ADR-0011): exact as-is, `/` → `/{*rest}`,
/// trailing-slash prefixes convert cleanly, bare prefixes carry the
/// string-prefix divergence as a partial finding.
fn location_path(loc: &Location, findings: &mut Vec<Finding>) -> Option<String> {
    let pat = &loc.pattern;
    if !pat.starts_with('/') {
        findings.push(Finding::new(
            Status::Unsupported,
            loc.line,
            "location",
            format!("pattern '{pat}' does not start with '/'"),
        ));
        return None;
    }
    if pat.contains('{') || pat.contains('}') || pat.contains('*') || pat.contains(':') {
        findings.push(Finding::new(
            Status::Unsupported,
            loc.line,
            "location",
            format!("pattern '{pat}' contains characters reserved by Zion's router"),
        ));
        return None;
    }
    if loc.modifier == LocMod::Exact {
        findings.push(Finding::new(
            Status::Convert,
            loc.line,
            "location",
            format!("exact route '{pat}'"),
        ));
        return Some(pat.clone());
    }
    if loc.modifier == LocMod::PrefixPriority {
        findings.push(Finding::new(
            Status::Partial,
            loc.line,
            "location",
            "'^~' treated as a plain prefix (Zion has no regex tier to suppress)",
        ));
    }
    if pat == "/" {
        findings.push(Finding::new(
            Status::Convert,
            loc.line,
            "location",
            "catch-all route '/{*rest}'",
        ));
        return Some("/{*rest}".to_string());
    }
    let base = pat.trim_end_matches('/');
    if base.is_empty() {
        // e.g. `location //` — degenerate; treat as root.
        return Some("/{*rest}".to_string());
    }
    let path = format!("{base}/{{*rest}}");
    if pat.ends_with('/') {
        findings.push(Finding::new(
            Status::Convert,
            loc.line,
            "location",
            format!("prefix route '{path}' (Zion also matches the bare '{base}')"),
        ));
    } else {
        findings.push(Finding::new(
            Status::Partial,
            loc.line,
            "location",
            format!(
                "prefix route '{path}' — nginx's string-prefix '{pat}' also matched \
                 e.g. '{pat}xyz'; Zion matches on path segments"
            ),
        ));
    }
    Some(path)
}

/// nginx's unix-socket target syntax: `proxy_pass http://unix:/path[:/uri]`.
/// Zion upstreams are TCP-only, so these must be loud findings — a naive
/// split would emit a "valid" http URL whose hostname is literally `unix`.
fn is_unix_target(url: &str) -> bool {
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .map(|rest| rest.starts_with("unix:"))
        .unwrap_or(false)
}

/// `http://host[:port][/uri]` → (scheme, authority, Some(uri) if present).
fn split_proxy_pass(url: &str) -> Option<(String, String, Option<String>)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else {
        return None;
    };
    if rest.is_empty() {
        return None;
    }
    match rest.find('/') {
        Some(0) => None,
        Some(i) => Some((
            scheme.to_string(),
            rest[..i].to_string(),
            Some(rest[i..].to_string()),
        )),
        None => Some((scheme.to_string(), rest.to_string(), None)),
    }
}

// ── Shared directive mappers ────────────────────────────────────────────

fn map_body_size(d: &Directive, doc: &mut ZionDoc, waf: &mut bool, findings: &mut Vec<Finding>) {
    let raw = match d.args.first() {
        Some(a) => a,
        None => return,
    };
    match parse_size_mb(raw) {
        Some(0) => findings.push(Finding::new(
            Status::Auto,
            d.line,
            "client_max_body_size",
            "0 = unlimited — Zion has no body cap unless a WAF profile sets one",
        )),
        Some(mb) => {
            *waf = true;
            let prev = doc.waf_body_mb;
            doc.waf_body_mb = Some(prev.map_or(mb, |p| p.max(mb)));
            let mut detail = format!(
                "{raw} → [waf_profile.imported] max_body_mb = {mb}, attached in shadow \
                 mode (logs, doesn't block) — the cap is enforced by the WAF path, \
                 which nginx didn't run; flip waf_shadow to false to enforce"
            );
            if let Some(p) = prev {
                if p != mb {
                    detail.push_str(&format!(
                        " (differs from an earlier cap of {p} MB — the larger value wins)"
                    ));
                }
            }
            findings.push(Finding::new(
                Status::Partial,
                d.line,
                "client_max_body_size",
                detail,
            ));
        }
        None => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "client_max_body_size",
            format!("cannot parse size '{raw}'"),
        )),
    }
}

fn map_limit_req(
    d: &Directive,
    agg: &mut Aggregates,
    model: &NginxModel,
    findings: &mut Vec<Finding>,
) {
    let zone = d
        .args
        .iter()
        .find_map(|a| a.strip_prefix("zone="))
        .unwrap_or("");
    match model.req_zones.iter().find(|z| z.name == zone) {
        Some(z) if z.key == "$binary_remote_addr" || z.key == "$remote_addr" => {
            agg.used_zones.push(zone.to_string());
            agg.rates.push((z.rps, z.window_secs, d.line));
        }
        Some(z) => {
            agg.used_zones.push(zone.to_string());
            findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "limit_req",
                format!(
                    "zone '{zone}' keys on '{}' — Zion rate-limits per client IP only",
                    z.key
                ),
            ));
        }
        None => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "limit_req",
            format!("zone '{zone}' is not defined"),
        )),
    }
}

fn map_limit_conn(
    d: &Directive,
    agg: &mut Aggregates,
    model: &NginxModel,
    findings: &mut Vec<Finding>,
) {
    let (zone, n) = match (d.args.first(), d.args.get(1)) {
        (Some(z), Some(n)) => (z.as_str(), n.parse::<u32>().ok()),
        _ => (d.args.first().map(String::as_str).unwrap_or(""), None),
    };
    let known = model.conn_zones.iter().find(|z| z.name == zone);
    match (known, n) {
        (Some(z), Some(n)) if z.key == "$binary_remote_addr" || z.key == "$remote_addr" => {
            agg.used_zones.push(zone.to_string());
            agg.conns.push((n, d.line));
        }
        (Some(z), _) if z.key != "$binary_remote_addr" && z.key != "$remote_addr" => {
            agg.used_zones.push(zone.to_string());
            findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "limit_conn",
                format!(
                    "zone '{zone}' keys on '{}' — Zion caps connections per client IP only",
                    z.key
                ),
            ));
        }
        _ => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "limit_conn",
            "could not resolve zone / count",
        )),
    }
}

/// The five headers Zion injects unconditionally on every response.
const AUTO_HEADERS: [&str; 5] = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
];

fn map_add_header(d: &Directive, csp: &mut Option<String>, findings: &mut Vec<Finding>) {
    let name = d.args.first().map(String::as_str).unwrap_or("");
    let lower = name.to_ascii_lowercase();
    if lower == "content-security-policy" {
        if let Some(v) = d.args.get(1) {
            *csp = Some(v.clone());
            findings.push(Finding::new(
                Status::Convert,
                d.line,
                "add_header",
                "route csp",
            ));
            return;
        }
    }
    if AUTO_HEADERS.contains(&lower.as_str()) {
        findings.push(Finding::new(
            Status::Auto,
            d.line,
            "add_header",
            format!(
                "{name} — Zion injects this header on every response; a differing \
                 value cannot be honored"
            ),
        ));
        return;
    }
    findings.push(Finding::new(
        Status::Unsupported,
        d.line,
        "add_header",
        format!("{name} — no generic response-header injection"),
    ));
}

/// Classify a `proxy_set_header`: forwarding hygiene headers are automatic,
/// the websocket idiom flips the route mode, `Host` is a stated behavior
/// delta, anything else is unsupported.
fn classify_set_header(
    d: &Directive,
    websocket: &mut bool,
    annotations: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    let name = d.args.first().map(String::as_str).unwrap_or("");
    let value = d.args.get(1).map(String::as_str).unwrap_or("");
    match name.to_ascii_lowercase().as_str() {
        "x-real-ip" | "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" => {
            findings.push(Finding::new(
                Status::Auto,
                d.line,
                "proxy_set_header",
                format!("{name} — Zion sets forwarding headers unconditionally"),
            ));
        }
        "upgrade" => {
            *websocket = true;
            findings.push(Finding::new(
                Status::Convert,
                d.line,
                "proxy_set_header",
                "websocket upgrade idiom → mode = \"websocket\"",
            ));
        }
        "connection" => {
            findings.push(Finding::new(
                Status::Auto,
                d.line,
                "proxy_set_header",
                "Connection — hop-by-hop headers are managed by Zion",
            ));
        }
        "host" => {
            findings.push(Finding::new(
                Status::Unsupported,
                d.line,
                "proxy_set_header",
                format!(
                    "Host {value} — Zion re-derives Host from the upstream authority; \
                     the original host reaches the backend as X-Forwarded-Host"
                ),
            ));
            annotations.push(
                "proxy_set_header Host: backend sees the upstream authority as Host; \
                 original host arrives in X-Forwarded-Host"
                    .to_string(),
            );
        }
        _ => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "proxy_set_header",
            format!("{name} — no generic request-header injection"),
        )),
    }
}

fn map_connect_timeout(d: &Directive, slot: &mut Option<u64>, findings: &mut Vec<Finding>) {
    let raw = d.args.first().map(String::as_str).unwrap_or("");
    match parse_time_ms(raw) {
        Some(ms) => {
            if slot.is_none() {
                *slot = Some(ms);
            }
            findings.push(Finding::new(
                Status::Convert,
                d.line,
                "proxy_connect_timeout",
                format!("connect_timeout_ms = {ms}"),
            ));
        }
        None => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "proxy_connect_timeout",
            format!("cannot parse time '{raw}'"),
        )),
    }
}

// ── Aggregation ─────────────────────────────────────────────────────────

fn finish_aggregates(
    agg: &Aggregates,
    model: &NginxModel,
    doc: &mut ZionDoc,
    findings: &mut Vec<Finding>,
) {
    let mut rates: Vec<(u32, u64)> = agg.rates.iter().map(|(r, w, _)| (*r, *w)).collect();
    rates.sort_unstable();
    rates.dedup();
    match rates.len() {
        0 => {}
        1 => {
            doc.rate_limit = Some(rates[0]);
            findings.push(Finding::new(
                Status::Partial,
                agg.rates[0].2,
                "limit_req",
                format!(
                    "{} req / {}s applied GLOBALLY — nginx scoped it per-location; \
                     burst/nodelay are not mapped",
                    rates[0].0, rates[0].1
                ),
            ));
        }
        _ => {
            for (rps, window, line) in &agg.rates {
                findings.push(Finding::new(
                    Status::Unsupported,
                    *line,
                    "limit_req",
                    format!(
                        "{rps} req / {window}s — multiple distinct rate policies exist \
                         and Zion has one global per-IP limit; none applied"
                    ),
                ));
            }
        }
    }

    let mut conns: Vec<u32> = agg.conns.iter().map(|(n, _)| *n).collect();
    conns.sort_unstable();
    conns.dedup();
    match conns.len() {
        0 => {}
        1 => {
            doc.max_conn_per_ip = Some(conns[0]);
            findings.push(Finding::new(
                Status::Partial,
                agg.conns[0].1,
                "limit_conn",
                format!(
                    "{} connections per IP applied GLOBALLY — nginx scoped it per-location",
                    conns[0]
                ),
            ));
        }
        _ => {
            for (n, line) in &agg.conns {
                findings.push(Finding::new(
                    Status::Unsupported,
                    *line,
                    "limit_conn",
                    format!(
                        "{n} per IP — multiple distinct caps exist and Zion has one \
                         global per-IP cap; none applied"
                    ),
                ));
            }
        }
    }

    for z in &model.req_zones {
        if !agg.used_zones.contains(&z.name) {
            findings.push(Finding::new(
                Status::Auto,
                z.line,
                "limit_req_zone",
                format!("zone '{}' is never referenced — dropped", z.name),
            ));
        }
    }
    for z in &model.conn_zones {
        if !agg.used_zones.contains(&z.name) {
            findings.push(Finding::new(
                Status::Auto,
                z.line,
                "limit_conn_zone",
                format!("zone '{}' is never referenced — dropped", z.name),
            ));
        }
    }
}

// ── Unit parsers ────────────────────────────────────────────────────────

/// A `set_real_ip_from` value must be an IP address or CIDR — Zion parses
/// `trusted_proxies` leniently at boot (invalid entries are skipped), so an
/// unvalidated pass-through would become a silent runtime drop.
fn valid_cidr(s: &str) -> bool {
    let (ip, prefix) = match s.split_once('/') {
        Some((i, p)) => (i, Some(p)),
        None => (s, None),
    };
    let addr: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match prefix {
        None => true,
        Some(p) => p
            .parse::<u8>()
            .map(|n| n <= if addr.is_ipv4() { 32 } else { 128 })
            .unwrap_or(false),
    }
}

/// nginx size → megabytes, rounding up. `0` means unlimited (caller decides).
fn parse_size_mb(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let (num, mult_to_bytes): (&str, u64) = match raw.chars().last() {
        Some('k') | Some('K') => (&raw[..raw.len() - 1], 1024),
        Some('m') | Some('M') => (&raw[..raw.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&raw[..raw.len() - 1], 1024 * 1024 * 1024),
        Some(c) if c.is_ascii_digit() => (raw, 1),
        _ => return None,
    };
    let n: u64 = num.parse().ok()?;
    if n == 0 {
        return Some(0);
    }
    let bytes = n.checked_mul(mult_to_bytes)?;
    Some(bytes.div_ceil(1024 * 1024).max(1))
}

/// nginx time → milliseconds. Single unit only (`75s`, `500ms`, `2m`); a bare
/// number means seconds for the timeout directives we map.
fn parse_time_ms(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if let Some(n) = raw.strip_suffix("ms") {
        return n.parse::<u64>().ok();
    }
    let (num, mult): (&str, u64) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1000),
        Some('m') => (&raw[..raw.len() - 1], 60_000),
        Some('h') => (&raw[..raw.len() - 1], 3_600_000),
        Some(c) if c.is_ascii_digit() => (raw, 1000),
        _ => return None,
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size_mb("64m"), Some(64));
        assert_eq!(parse_size_mb("1g"), Some(1024));
        assert_eq!(parse_size_mb("512k"), Some(1));
        assert_eq!(parse_size_mb("100"), Some(1));
        assert_eq!(parse_size_mb("0"), Some(0));
        assert_eq!(parse_size_mb("abc"), None);
    }

    #[test]
    fn time_parsing() {
        assert_eq!(parse_time_ms("75s"), Some(75_000));
        assert_eq!(parse_time_ms("500ms"), Some(500));
        assert_eq!(parse_time_ms("2m"), Some(120_000));
        assert_eq!(parse_time_ms("30"), Some(30_000));
        assert_eq!(parse_time_ms("1m30s"), None);
    }

    #[test]
    fn proxy_pass_splitting() {
        assert_eq!(
            split_proxy_pass("http://localhost:3000"),
            Some(("http".into(), "localhost:3000".into(), None))
        );
        assert_eq!(
            split_proxy_pass("https://10.0.3.10:8443"),
            Some(("https".into(), "10.0.3.10:8443".into(), None))
        );
        assert_eq!(
            split_proxy_pass("http://b/"),
            Some(("http".into(), "b".into(), Some("/".into())))
        );
        assert_eq!(
            split_proxy_pass("http://b/prefix/x"),
            Some(("http".into(), "b".into(), Some("/prefix/x".into())))
        );
        assert_eq!(split_proxy_pass("ftp://b"), None);
        assert_eq!(split_proxy_pass("http://"), None);
    }

    #[test]
    fn listen_splitting() {
        assert_eq!(split_listen("80", false), Some((None, 80)));
        assert_eq!(
            split_listen("1.2.3.4:8080", false),
            Some((Some("1.2.3.4".into()), 8080))
        );
        assert_eq!(
            split_listen("[::]:443", true),
            Some((Some("[::]".into()), 443))
        );
        assert_eq!(
            split_listen("1.2.3.4", true),
            Some((Some("1.2.3.4".into()), 443))
        );
        assert_eq!(split_listen("unix:/run/x.sock", false), None);
    }

    #[test]
    fn name_sanitizing() {
        assert_eq!(sanitize_name("users-svc:8001"), "users-svc_8001");
        assert_eq!(sanitize_name("127.0.0.1:80"), "127_0_0_1_80");
        assert_eq!(sanitize_name("backend_pool"), "backend_pool");
    }

    #[test]
    fn bare_host_validation() {
        assert!(valid_bare_host("example.com"));
        assert!(valid_bare_host("a-b.example.co.uk"));
        assert!(!valid_bare_host("Example.com")); // caller lowercases first
        assert!(!valid_bare_host("exa mple.com"));
        assert!(!valid_bare_host(""));
        assert!(!valid_bare_host(".example.com"));
        assert!(!valid_bare_host("example..com"));
    }
}
