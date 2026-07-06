//! Proxy-oriented intermediate model extracted from the nginx directive tree
//! (ADR-0011 stage 2). Normalizes nginx's context rules (top-level vs `http{}`
//! vs `server{}` vs `location{}`) into flat structs the mapper can reason
//! about, and files a finding for every context it deliberately walks past.

use super::nginx::Directive;
use super::{Finding, Status};

/// Everything the mapper needs, flattened out of the directive tree.
#[derive(Debug, Default)]
pub struct NginxModel {
    pub servers: Vec<Server>,
    pub pools: Vec<Pool>,
    /// `limit_req_zone` definitions: name → (key, rate_rps, window_secs).
    pub req_zones: Vec<ReqZone>,
    /// `limit_conn_zone` definitions: name → key.
    pub conn_zones: Vec<ConnZone>,
}

#[derive(Debug)]
pub struct ReqZone {
    pub name: String,
    pub key: String,
    pub rps: u32,
    pub window_secs: u64,
    pub line: u32,
}

#[derive(Debug)]
pub struct ConnZone {
    pub name: String,
    pub key: String,
    pub line: u32,
}

#[derive(Debug)]
pub struct Pool {
    pub name: String,
    pub servers: Vec<PoolServer>,
    pub keepalive: Option<u64>,
    /// Anything else inside `upstream{}` (`least_conn`, `zone`, …), kept for findings.
    pub extras: Vec<Directive>,
    pub line: u32,
}

#[derive(Debug)]
pub struct PoolServer {
    pub addr: String,
    pub flags: Vec<String>,
    pub line: u32,
}

#[derive(Debug)]
pub struct Server {
    pub line: u32,
    pub listens: Vec<Listen>,
    /// `server_name` args in order of appearance (may span several directives).
    pub names: Vec<String>,
    pub names_line: u32,
    pub locations: Vec<Location>,
    /// Server-level directives other than listen/server_name/location.
    pub directives: Vec<Directive>,
}

#[derive(Debug)]
pub struct Listen {
    /// The address part of the listen spec (first arg), e.g. `80`, `[::]:443`.
    pub addr: String,
    pub ssl: bool,
    pub default_server: bool,
    /// Non-address flags other than ssl/default_server (http2, reuseport, …).
    pub flags: Vec<String>,
    pub line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocMod {
    /// `location /p`
    Prefix,
    /// `location = /p`
    Exact,
    /// `location ~ regex` / `location ~* regex`
    Regex,
    /// `location ^~ /p` — prefix that suppresses regex matching.
    PrefixPriority,
}

#[derive(Debug)]
pub struct Location {
    pub line: u32,
    pub modifier: LocMod,
    pub pattern: String,
    pub directives: Vec<Directive>,
}

/// Walk the parsed tree and build the model. Every directive the walk skips
/// on purpose gets a finding — nothing is silently ignored (ADR-0011 report
/// contract: every input directive lands in exactly one bucket).
pub fn extract(ast: Vec<Directive>, findings: &mut Vec<Finding>) -> NginxModel {
    let mut model = NginxModel::default();
    walk_top(ast, &mut model, findings);
    model
}

/// Top level and `http{}` share the same interesting children; nginx snippets
/// in the wild come both as full configs (`http { server { … } }`) and as
/// conf.d fragments (bare `server { … }`), so accept both shapes.
fn walk_top(items: Vec<Directive>, model: &mut NginxModel, findings: &mut Vec<Finding>) {
    for d in items {
        match d.name.as_str() {
            "http" => {
                if let Some(block) = d.block {
                    walk_top(block, model, findings);
                } else {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "http",
                        "expected a block",
                    ));
                }
            }
            "server" => match d.block {
                Some(block) => model.servers.push(extract_server(block, d.line, findings)),
                None => findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    "server",
                    "expected a block",
                )),
            },
            "upstream" => extract_pool(d, model, findings),
            "limit_req_zone" => extract_req_zone(&d, model, findings),
            "limit_conn_zone" => extract_conn_zone(&d, model, findings),
            // nginx process management — Zion runs its own runtime; nothing to carry over.
            "events"
            | "worker_processes"
            | "worker_rlimit_nofile"
            | "user"
            | "pid"
            | "daemon"
            | "master_process" => {
                findings.push(Finding::new(
                    Status::Auto,
                    d.line,
                    &d.name,
                    "nginx process management — Zion manages its own runtime",
                ));
            }
            // Directives the mapper DOES support inside server{}/location{} —
            // nginx inherits them from http{} downward, but v0 does not model
            // that inheritance, so be truthful about why they're dropped
            // instead of claiming they have no Zion equivalent.
            "client_max_body_size"
            | "proxy_connect_timeout"
            | "proxy_set_header"
            | "add_header"
            | "limit_req"
            | "limit_conn"
            | "set_real_ip_from"
            | "real_ip_header"
            | "ssl_certificate"
            | "ssl_certificate_key"
            | "ssl_protocols"
            | "proxy_http_version" => {
                findings.push(Finding::new(
                    Status::Unsupported,
                    d.line,
                    &d.name,
                    "supported inside server{} — http-level inheritance is not \
                     implemented; move it into the server block(s)",
                ));
            }
            _ => findings.push(Finding::unsupported_directive(&d)),
        }
    }
}

fn extract_server(block: Vec<Directive>, line: u32, findings: &mut Vec<Finding>) -> Server {
    let mut server = Server {
        line,
        listens: Vec::new(),
        names: Vec::new(),
        names_line: line,
        locations: Vec::new(),
        directives: Vec::new(),
    };
    for d in block {
        match d.name.as_str() {
            "listen" => {
                if d.args.is_empty() {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        d.line,
                        "listen",
                        "missing address",
                    ));
                    continue;
                }
                let mut ssl = false;
                let mut default_server = false;
                let mut flags = Vec::new();
                for flag in &d.args[1..] {
                    match flag.as_str() {
                        "ssl" => ssl = true,
                        "default_server" | "default" => default_server = true,
                        other => flags.push(other.to_string()),
                    }
                }
                server.listens.push(Listen {
                    addr: d.args[0].clone(),
                    ssl,
                    default_server,
                    flags,
                    line: d.line,
                });
            }
            "server_name" => {
                server.names_line = d.line;
                server.names.extend(d.args.iter().cloned());
            }
            "location" => extract_location(d, &mut server, findings),
            _ => server.directives.push(d),
        }
    }
    server
}

fn extract_location(d: Directive, server: &mut Server, findings: &mut Vec<Finding>) {
    let line = d.line;
    let block = match d.block {
        Some(b) => b,
        None => {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                "location",
                "expected a block",
            ));
            return;
        }
    };
    let (modifier, pattern) = match d.args.len() {
        1 => (LocMod::Prefix, d.args[0].clone()),
        2 => {
            let m = match d.args[0].as_str() {
                "=" => LocMod::Exact,
                "~" | "~*" => LocMod::Regex,
                "^~" => LocMod::PrefixPriority,
                other => {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        line,
                        "location",
                        format!("unknown modifier '{other}'"),
                    ));
                    return;
                }
            };
            (m, d.args[1].clone())
        }
        _ => {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                "location",
                "expected `location [modifier] <pattern> { … }`",
            ));
            return;
        }
    };
    // Nested locations are legal nginx but rare; v0 keeps them out of scope.
    let mut directives = Vec::new();
    for child in block {
        if child.name == "location" {
            findings.push(Finding::new(
                Status::Unsupported,
                child.line,
                "location",
                "nested locations are not supported — flatten them",
            ));
        } else {
            directives.push(child);
        }
    }
    server.locations.push(Location {
        line,
        modifier,
        pattern,
        directives,
    });
}

fn extract_pool(d: Directive, model: &mut NginxModel, findings: &mut Vec<Finding>) {
    let line = d.line;
    let (name, block) = match (d.args.first(), d.block) {
        (Some(n), Some(b)) => (n.clone(), b),
        _ => {
            findings.push(Finding::new(
                Status::Unsupported,
                line,
                "upstream",
                "expected `upstream <name> { … }`",
            ));
            return;
        }
    };
    let mut pool = Pool {
        name,
        servers: Vec::new(),
        keepalive: None,
        extras: Vec::new(),
        line,
    };
    for child in block {
        match child.name.as_str() {
            "server" if !child.args.is_empty() => pool.servers.push(PoolServer {
                addr: child.args[0].clone(),
                flags: child.args[1..].to_vec(),
                line: child.line,
            }),
            "keepalive" => {
                pool.keepalive = child.args.first().and_then(|a| a.parse().ok());
                if pool.keepalive.is_none() {
                    findings.push(Finding::new(
                        Status::Unsupported,
                        child.line,
                        "keepalive",
                        "could not parse connection count",
                    ));
                }
            }
            _ => pool.extras.push(child),
        }
    }
    model.pools.push(pool);
}

/// `limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;`
fn extract_req_zone(d: &Directive, model: &mut NginxModel, findings: &mut Vec<Finding>) {
    let mut key = String::new();
    let mut name = None;
    let mut rate = None;
    for arg in &d.args {
        if let Some(z) = arg.strip_prefix("zone=") {
            name = Some(z.split(':').next().unwrap_or(z).to_string());
        } else if let Some(r) = arg.strip_prefix("rate=") {
            rate = parse_rate(r);
        } else if arg.starts_with('$') {
            key = arg.clone();
        }
    }
    match (name, rate) {
        (Some(name), Some((rps, window_secs))) => model.req_zones.push(ReqZone {
            name,
            key,
            rps,
            window_secs,
            line: d.line,
        }),
        _ => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "limit_req_zone",
            "could not parse zone name / rate",
        )),
    }
}

/// `limit_conn_zone $binary_remote_addr zone=peraddr:10m;`
fn extract_conn_zone(d: &Directive, model: &mut NginxModel, findings: &mut Vec<Finding>) {
    let mut key = String::new();
    let mut name = None;
    for arg in &d.args {
        if let Some(z) = arg.strip_prefix("zone=") {
            name = Some(z.split(':').next().unwrap_or(z).to_string());
        } else if arg.starts_with('$') {
            key = arg.clone();
        }
    }
    match name {
        Some(name) => model.conn_zones.push(ConnZone {
            name,
            key,
            line: d.line,
        }),
        None => findings.push(Finding::new(
            Status::Unsupported,
            d.line,
            "limit_conn_zone",
            "could not parse zone name",
        )),
    }
}

/// nginx rate spec: `20r/s` or `5r/m` → (requests, window seconds).
fn parse_rate(spec: &str) -> Option<(u32, u64)> {
    if let Some(n) = spec.strip_suffix("r/s") {
        return n.parse().ok().map(|rps| (rps, 1));
    }
    if let Some(n) = spec.strip_suffix("r/m") {
        return n.parse().ok().map(|rpm| (rpm, 60));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_of(src: &str) -> (NginxModel, Vec<Finding>) {
        let ast = super::super::nginx::parse(src).expect("parse");
        let mut findings = Vec::new();
        let model = extract(ast, &mut findings);
        (model, findings)
    }

    #[test]
    fn server_inside_and_outside_http_block() {
        let (m, _) = model_of("http { server { listen 80; } }\nserver { listen 81; }");
        assert_eq!(m.servers.len(), 2);
    }

    #[test]
    fn listen_flags_parsed() {
        let (m, _) = model_of("server { listen 443 ssl http2 default_server; }");
        let l = &m.servers[0].listens[0];
        assert_eq!(l.addr, "443");
        assert!(l.ssl);
        assert!(l.default_server);
        assert_eq!(l.flags, vec!["http2"]);
    }

    #[test]
    fn location_modifiers() {
        let (m, _) = model_of(
            "server { location / {} location = /x {} location ~ ^/r$ {} location ^~ /p {} }",
        );
        let locs = &m.servers[0].locations;
        assert_eq!(locs[0].modifier, LocMod::Prefix);
        assert_eq!(locs[1].modifier, LocMod::Exact);
        assert_eq!(locs[1].pattern, "/x");
        assert_eq!(locs[2].modifier, LocMod::Regex);
        assert_eq!(locs[3].modifier, LocMod::PrefixPriority);
    }

    #[test]
    fn upstream_pool_extraction() {
        let (m, _) = model_of(
            "upstream be { least_conn; server 10.0.0.1:80 weight=3; server 10.0.0.2:80; keepalive 16; }",
        );
        let p = &m.pools[0];
        assert_eq!(p.name, "be");
        assert_eq!(p.servers.len(), 2);
        assert_eq!(p.servers[0].flags, vec!["weight=3"]);
        assert_eq!(p.keepalive, Some(16));
        assert_eq!(p.extras[0].name, "least_conn");
    }

    #[test]
    fn zones_parsed() {
        let (m, _) = model_of(
            "limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;\n\
             limit_conn_zone $binary_remote_addr zone=peraddr:10m;",
        );
        assert_eq!(m.req_zones[0].name, "api");
        assert_eq!(m.req_zones[0].rps, 20);
        assert_eq!(m.req_zones[0].window_secs, 1);
        assert_eq!(m.req_zones[0].key, "$binary_remote_addr");
        assert_eq!(m.conn_zones[0].name, "peraddr");
    }

    #[test]
    fn rate_per_minute() {
        assert_eq!(parse_rate("30r/m"), Some((30, 60)));
        assert_eq!(parse_rate("10r/s"), Some((10, 1)));
        assert_eq!(parse_rate("bogus"), None);
    }

    #[test]
    fn unknown_top_level_directive_gets_finding() {
        let (_, findings) = model_of("stream { }");
        assert!(findings
            .iter()
            .any(|f| f.status == Status::Unsupported && f.directive == "stream"));
    }

    #[test]
    fn nested_location_flagged() {
        let (m, findings) = model_of("server { location / { location /x { } } }");
        assert_eq!(m.servers[0].locations.len(), 1);
        assert!(findings.iter().any(|f| f.detail.contains("nested")));
    }
}
